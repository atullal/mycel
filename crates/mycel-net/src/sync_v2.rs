//! Sync v2 over the node protocol: the driver for `mycel_sync::reconcile`
//! on a [`StreamKind::SyncV2`] bi-stream, plus what the node keeps for it
//! (per-peer session records, budgets, peers that only speak v1).
//!
//! The session is sans-IO; this file only moves its frames. A reader loop
//! and a writer loop run on the stream at once, and neither waits for the
//! other, so flow control can't deadlock while both sides stream chunks.
//! The replica is locked only around each call into the session or the
//! ingest of one frame, never across an await (as with v1).
//!
//! Policy stays here, exactly as in v1: the membership gate, invites and
//! `Removed` proofs; and the per-peer limits, none of which depends on the
//! peer acknowledging anything: sessions per (peer, space) that find a
//! difference (a burst of 32, then 4 per second, `Busy` beyond; an idle
//! check with equal digests costs one cached hash and is not counted),
//! bytes sent per (peer, space) (one
//! full catch-up, then 1 MiB/min; the session aborts with `Budget` and
//! resumes later, keeping what arrived), and phase-2 sessions per peer
//! (6 per hour).
//!
//! **Negotiation (local stand-in, marked for integration).** The capability
//! hello lives on the parallel `v2/wire-versioning` branch. Until it is
//! merged, a client simply tries `SyncV2`: a build that doesn't know the
//! stream kind drops it (the stream ends before any answer) or, with the
//! versioning branch, resets it with `STREAM_REFUSED`. Either, on a
//! connection that is still up, or an explicit `Unsupported` verdict, makes
//! the client fall back to v1 and remember that peer for
//! [`V1_REMEMBERED`]. A `Busy` answer, an `Abort` or a broken connection
//! never cause fallback. Integration: replace the try-and-remember with
//! `PeerState::protocol` carrying `Caps::SYNC_V2`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use mycel_crypto::{Hash32, SignPk};
use mycel_sync::reconcile::{self, AbortReason, Config, Msg, Outcome, PeerRecord, Session, SyncSet, Verdict};
use mycel_sync::{Envelope, EnvelopeId, Replica};
use mycel_trust::{SignedOp, SpaceId};
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::wire::{StreamKind, recv_bounded, send_len};
use crate::{Inner, NetEvent, SyncStats, accept_invite, open_bi, pooled, resources};

type V2Msg = Msg<SignedOp, Envelope>;

/// The reset code a build that knows stream kinds but not this one uses
/// (`version::STREAM_REFUSED` on the `v2/wire-versioning` branch; the same
/// value, to be replaced by that constant at integration).
pub(crate) const STREAM_REFUSED: u32 = 0x6d79_0001;
/// How long a peer that refused `SyncV2` is synced with v1 before v2 is
/// tried again (it may have been updated).
pub const V1_REMEMBERED: Duration = Duration::from_secs(30 * 60);
/// Memory for session records, all peers and spaces together.
const RECORDS_BYTES: usize = 8 * 1024 * 1024;
const SESSION_BURST: f64 = 32.0;
const SESSIONS_PER_SEC: f64 = 4.0;
const BYTES_PER_SEC: f64 = 1024.0 * 1024.0 / 60.0;
const PHASE2_PER_HOUR: usize = 6;
/// Consecutive `Ops` frames are ingested together (one membership
/// resolution) up to this many bytes.
const OPS_BUFFER: usize = 8 * 1024 * 1024;

/// What the node keeps for Sync v2.
#[derive(Default)]
pub(crate) struct V2 {
    records: Mutex<Records>,
    v1_only: Mutex<HashMap<SignPk, Instant>>,
    buckets: Mutex<HashMap<(SignPk, SpaceId), Buckets>>,
    phase2: Mutex<HashMap<SignPk, VecDeque<Instant>>>,
    /// Peers that recently opened a session to us, per space: they chose us
    /// as a neighbour, so we push to them too (symmetric overlay edges).
    inbound: Mutex<HashMap<SpaceId, HashMap<SignPk, Instant>>>,
    totals: Mutex<V2Totals>,
}

/// Counters for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2Totals {
    /// Sessions run as client and as server.
    pub client_sessions: u64,
    pub server_sessions: u64,
    /// Client attempts that fell back to v1 (the peer refused `SyncV2`).
    pub fallbacks: u64,
    /// Sessions that ended in one round trip (`InSync`/`Unchanged`).
    pub idle: u64,
    /// Sessions that needed phase 2.
    pub phase2: u64,
    /// Bytes on v2 streams (frames, both roles).
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    /// `Busy` answers given and received.
    pub busy_sent: u64,
    pub busy_received: u64,
}

#[derive(Default)]
struct Records {
    map: HashMap<(SignPk, SpaceId), (PeerRecord, u64)>,
    bytes: usize,
    clock: u64,
}

impl Records {
    fn get(&mut self, key: &(SignPk, SpaceId)) -> Option<PeerRecord> {
        self.clock += 1;
        let clock = self.clock;
        self.map.get_mut(key).map(|(r, used)| {
            *used = clock;
            r.clone()
        })
    }

    fn put(&mut self, key: (SignPk, SpaceId), rec: PeerRecord) {
        self.clock += 1;
        if let Some((old, _)) = self.map.remove(&key) {
            self.bytes -= old.size();
        }
        self.bytes += rec.size();
        self.map.insert(key, (rec, self.clock));
        while self.bytes > RECORDS_BYTES && self.map.len() > 1 {
            let Some(oldest) = self.map.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| *k) else { break };
            if let Some((old, _)) = self.map.remove(&oldest) {
                self.bytes -= old.size();
            }
        }
    }
}

/// Token buckets for one (peer, space). The byte bucket holds one full
/// catch-up of our set: when the set grows, the growth is added once.
struct Buckets {
    sessions: f64,
    bytes: f64,
    cap: f64,
    at: Instant,
}

impl Buckets {
    fn new(byte_cap: f64) -> Self {
        Buckets { sessions: SESSION_BURST, bytes: byte_cap, cap: byte_cap, at: Instant::now() }
    }

    fn refill(&mut self, byte_cap: f64) {
        let dt = self.at.elapsed().as_secs_f64();
        self.at = Instant::now();
        self.sessions = (self.sessions + dt * SESSIONS_PER_SEC).min(SESSION_BURST);
        if byte_cap > self.cap {
            self.bytes += byte_cap - self.cap;
            self.cap = byte_cap;
        }
        self.bytes = (self.bytes + dt * BYTES_PER_SEC).min(self.cap);
    }
}

impl V2 {
    pub(crate) fn totals(&self) -> V2Totals {
        *self.totals.lock()
    }

    pub(crate) fn is_v1_only(&self, peer: &SignPk) -> bool {
        let mut v1 = self.v1_only.lock();
        match v1.get(peer) {
            Some(t) if t.elapsed() < V1_REMEMBERED => true,
            Some(_) => {
                v1.remove(peer);
                false
            }
            None => false,
        }
    }

    pub(crate) fn v1_only_peers(&self) -> Vec<SignPk> {
        self.v1_only.lock().iter().filter(|(_, t)| t.elapsed() < V1_REMEMBERED).map(|(p, _)| *p).collect()
    }

    fn mark_v1_only(&self, peer: SignPk) {
        self.v1_only.lock().insert(peer, Instant::now());
        self.totals.lock().fallbacks += 1;
    }

    /// Peers that opened a session to us in `space` in the last 30 minutes
    /// (at most `max`, most recent first). Periodic rounds, at most 10 min
    /// apart, renew the edge.
    pub(crate) fn inbound(&self, space: &SpaceId, max: usize) -> Vec<SignPk> {
        let mut all = self.inbound.lock();
        let Some(map) = all.get_mut(space) else { return Vec::new() };
        map.retain(|_, t| t.elapsed() < Duration::from_secs(1800));
        let mut v: Vec<(SignPk, Instant)> = map.iter().map(|(p, t)| (*p, *t)).collect();
        v.sort_by_key(|(_, t)| std::cmp::Reverse(*t));
        v.into_iter().take(max).map(|(p, _)| p).collect()
    }

    fn note_inbound(&self, space: SpaceId, peer: SignPk) {
        let mut all = self.inbound.lock();
        let map = all.entry(space).or_default();
        map.insert(peer, Instant::now());
        if map.len() > 64
            && let Some(oldest) = map.iter().min_by_key(|(_, t)| **t).map(|(p, _)| *p)
        {
            map.remove(&oldest);
        }
    }

    /// Session limit: `Err(retry after ms)` when over it.
    fn take_session(&self, peer: SignPk, space: SpaceId, byte_cap: f64) -> std::result::Result<(), u32> {
        let mut b = self.buckets.lock();
        let bucket = b.entry((peer, space)).or_insert_with(|| Buckets::new(byte_cap));
        bucket.refill(byte_cap);
        if bucket.sessions >= 1.0 {
            bucket.sessions -= 1.0;
            Ok(())
        } else {
            Err((((1.0 - bucket.sessions) / SESSIONS_PER_SEC) * 1000.0).ceil() as u32)
        }
    }

    fn byte_budget(&self, peer: SignPk, space: SpaceId, byte_cap: f64) -> u64 {
        let mut b = self.buckets.lock();
        let bucket = b.entry((peer, space)).or_insert_with(|| Buckets::new(byte_cap));
        bucket.refill(byte_cap);
        bucket.bytes.max(0.0) as u64
    }

    fn spend(&self, peer: SignPk, space: SpaceId, bytes: u64) {
        if let Some(b) = self.buckets.lock().get_mut(&(peer, space)) {
            b.bytes -= bytes as f64;
        }
    }

    fn phase2_allowed(&self, peer: SignPk) -> bool {
        let mut p = self.phase2.lock();
        let q = p.entry(peer).or_default();
        while q.front().is_some_and(|t| t.elapsed() > Duration::from_secs(3600)) {
            q.pop_front();
        }
        q.len() < PHASE2_PER_HOUR
    }

    fn charge_phase2(&self, peer: SignPk) {
        self.phase2.lock().entry(peer).or_default().push_back(Instant::now());
    }
}

/// One full catch-up of our set (ops estimated at 8 KiB each), then the
/// refill rate.
fn byte_cap(r: &Replica) -> f64 {
    1.1 * (r.stored_bytes() as f64 + r.op_count() as f64 * 8192.0) + 1024.0 * 1024.0
}

fn config(inner: &Inner, peer: SignPk, space: SpaceId, r: &Replica) -> Config {
    Config {
        send_budget: inner.v2.byte_budget(peer, space, byte_cap(r)),
        allow_phase2: inner.v2.phase2_allowed(peer),
        ..Config::default()
    }
}

/// Did the peer refuse the stream kind (a build without Sync v2)? Only on
/// a connection that is still up: the stream ended before any answer, or
/// was reset or stopped with code 0 or [`STREAM_REFUSED`].
fn refused(err: &anyhow::Error, conn: &Connection) -> bool {
    use iroh::endpoint::{ReadError, ReadExactError, VarInt, WriteError};
    if conn.close_reason().is_some() {
        return false;
    }
    let codes = [VarInt::from_u32(0), VarInt::from_u32(STREAM_REFUSED)];
    let is_refusal = |e: &(dyn std::error::Error + 'static)| {
        matches!(e.downcast_ref::<ReadExactError>(), Some(ReadExactError::FinishedEarly(0)))
            || matches!(e.downcast_ref::<ReadExactError>(), Some(ReadExactError::ReadError(ReadError::Reset(c))) if codes.contains(c))
            || matches!(e.downcast_ref::<ReadError>(), Some(ReadError::Reset(c)) if codes.contains(c))
            || matches!(e.downcast_ref::<WriteError>(), Some(WriteError::Stopped(c)) if codes.contains(c))
    };
    err.chain().any(|e| {
        is_refusal(e) || e.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).is_some_and(|e| is_refusal(e))
    })
}

/// Refuse a `SyncV2` stream as a build without it would (with the
/// versioning branch's code).
pub(crate) fn refuse_stream(tx: &mut SendStream, rx: &mut RecvStream) {
    let code = iroh::endpoint::VarInt::from_u32(STREAM_REFUSED);
    rx.stop(code).ok();
    tx.reset(code).ok();
}

/// What a finished session did.
struct Done {
    stats: SyncStats,
    outcome: Option<Outcome>,
}

// ─────────────────────────────── client ───────────────────────────────

/// One Sync v2 session with `peer` as the client. `Ok(None)`: the peer
/// doesn't speak Sync v2 (run v1; it is remembered).
pub(crate) async fn sync(
    inner: &Arc<Inner>,
    peer: SignPk,
    space: SpaceId,
    trust_peer: bool,
    eager: bool,
) -> Result<Option<SyncStats>> {
    if !inner.with_space(&space, |r| trust_peer || r.is_member(&peer))? {
        bail!("peer is not a member of this space");
    }
    let res = crate::on_conn!(inner, &peer, |conn| exchange(inner, &conn, peer, space, eager));
    match res {
        Ok(None) => {
            inner.v2.mark_v1_only(peer);
            Ok(None)
        }
        other => other,
    }
}

async fn exchange(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    space: SpaceId,
    eager: bool,
) -> Result<Option<SyncStats>> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::SyncV2).await?;
    let record = inner.v2.records.lock().get(&(peer, space));
    let new_session = |invite: Option<Vec<SignedOp>>| {
        inner.with_space(&space, |r| {
            let cfg = config(inner, peer, space, r);
            Session::<Replica>::open(r, cfg, mycel_crypto::random(), record.clone(), eager, invite)
        })
    };
    let mut session = new_session(None)?;
    let mut invited = false;
    let first = loop {
        let mut sent = 0;
        while let Some(m) = inner.with_space(&space, |r| session.poll_send(r))? {
            match send_len(&mut tx, &m).await {
                Ok(n) => sent += n,
                Err(e) if refused(&e, conn) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        let wait = resources::reply_timeout(sent);
        let msg = match recv_bounded::<V2Msg>(&mut rx, wait, reconcile::MAX_FRAME, &inner.reply_frames(&peer)).await {
            Ok((m, _permit)) => m,
            Err(e) if refused(&e, conn) => return Ok(None),
            Err(e) => return Err(e),
        };
        match msg {
            Msg::Status(Verdict::NeedInvite) if !invited => {
                invited = true;
                let ops = inner.with_space(&space, |r| r.all_ops())?;
                session = new_session(Some(ops))?;
            }
            Msg::Status(Verdict::Removed { ops }) => {
                let res = inner.with_space(&space, |r| r.ingest_batch(ops, vec![]))?;
                if res.changed() {
                    inner.emit(NetEvent::SpaceChanged { space });
                }
                bail!("peer denied sync (we were removed from this space)")
            }
            Msg::Status(Verdict::Denied) => bail!("peer denied sync (we are not a member)"),
            Msg::Status(Verdict::Unsupported { .. }) => return Ok(None),
            Msg::Status(Verdict::Busy { retry_after_ms }) => {
                inner.v2.totals.lock().busy_received += 1;
                bail!("peer busy (retry in {retry_after_ms} ms)")
            }
            other => break other,
        }
    };
    let done = drive(inner, peer, space, session, Some(first), tx, rx, true).await?;
    inner.note_path(peer, conn);
    finish(inner, peer, done)
}

fn finish(inner: &Arc<Inner>, peer: SignPk, done: Done) -> Result<Option<SyncStats>> {
    match done.outcome {
        Some(Outcome::Aborted { reason, by_peer }) => {
            bail!("sync aborted ({reason:?}, by {})", if by_peer { "peer" } else { "us" })
        }
        Some(Outcome::Refused(why)) => bail!("sync refused: {why:?}"),
        None => bail!("sync ended early"),
        Some(_) => {
            inner.mark_ok(peer);
            Ok(Some(done.stats))
        }
    }
}

// ─────────────────────────────── server ───────────────────────────────

pub(crate) async fn serve(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    if !inner.sync_v2 {
        refuse_stream(&mut tx, &mut rx);
        return Ok(());
    }
    let max = reconcile::MAX_FRAME;
    let (mut msg, mut _permit) =
        recv_bounded::<V2Msg>(&mut rx, resources::FIRST_FRAME, max, &inner.frames(&peer)).await?;
    loop {
        let Msg::Open(mut open) = msg else { bail!("expected Open") };
        let space = open.space;
        if !inner.spaces.lock().contains_key(&space) {
            match open.invite.take() {
                None => {
                    let n = send_len(&mut tx, &V2Msg::Status(Verdict::NeedInvite)).await?;
                    (msg, _permit) =
                        recv_bounded(&mut rx, resources::reply_timeout(n), max, &inner.frames(&peer)).await?;
                    continue;
                }
                Some(ops) => {
                    if !accept_invite(inner, peer, space, ops) {
                        send_len(&mut tx, &V2Msg::Status(Verdict::Denied)).await?;
                        tx.finish()?;
                        return Ok(());
                    }
                }
            }
        }
        open.invite = None;
        // Membership gate: only current members (any role) may sync.
        let record = inner.v2.records.lock().get(&(peer, space));
        let gate = inner.with_space(&space, |r| {
            if r.is_member(&peer) {
                let cap = byte_cap(r);
                let idle = open.digest == r.digest();
                match if idle { Ok(()) } else { inner.v2.take_session(peer, space, cap) } {
                    Ok(()) => Ok(Session::accept(r, config(inner, peer, space, r), open, record)),
                    Err(retry_after_ms) => Err(Box::new(Verdict::Busy { retry_after_ms })),
                }
            } else {
                let proof = r.revocation_proof(&peer);
                Err(Box::new(if proof.is_empty() { Verdict::Denied } else { Verdict::Removed { ops: proof } }))
            }
        })?;
        let session = match gate {
            Ok(s) => s,
            Err(v) => {
                if matches!(*v, Verdict::Busy { .. }) {
                    inner.v2.totals.lock().busy_sent += 1;
                }
                send_len(&mut tx, &V2Msg::Status(*v)).await?;
                tx.finish()?;
                return Ok(());
            }
        };
        inner.v2.note_inbound(space, peer);
        drop(_permit);
        let done = drive(inner, peer, space, session, None, tx, rx, false).await?;
        inner.note_path(peer, conn);
        finish(inner, peer, done)?;
        return Ok(());
    }
}

// ─────────────────────────────── both ───────────────────────────────

/// Run a session to its end on `tx`/`rx`. `first`: a frame already read
/// (the client's `Status`).
#[allow(clippy::too_many_arguments)]
async fn drive(
    inner: &Arc<Inner>,
    peer: SignPk,
    space: SpaceId,
    session: Session<Replica>,
    first: Option<V2Msg>,
    mut tx: SendStream,
    mut rx: RecvStream,
    client: bool,
) -> Result<Done> {
    let shared = Arc::new(Mutex::new(session));
    let notify = Arc::new(Notify::new());
    let received = Arc::new(Mutex::new(SyncStats::default()));
    let frames = if client { inner.reply_frames(&peer) } else { inner.frames(&peer) };
    let reader = {
        let (shared, notify, received) = (shared.clone(), notify.clone(), received.clone());
        async move {
            let mut ops: Vec<SignedOp> = Vec::new();
            let mut ops_bytes = 0;
            if let Some(m) = first {
                process(inner, peer, space, &shared, m, &mut ops, &mut ops_bytes, &received)?;
                notify.notify_one();
            }
            loop {
                if shared.lock().outcome().is_some() {
                    break;
                }
                let wait = resources::reply_timeout(0);
                let msg = match recv_bounded::<V2Msg>(&mut rx, wait, reconcile::MAX_FRAME, &frames).await {
                    Ok((m, _permit)) => m,
                    Err(_) if shared.lock().outcome().is_some() => break,
                    Err(e) => {
                        notify.notify_one();
                        return Err(e);
                    }
                };
                let res = process(inner, peer, space, &shared, msg, &mut ops, &mut ops_bytes, &received);
                notify.notify_one();
                res?;
            }
            if !ops.is_empty() {
                ingest(inner, peer, space, &shared, std::mem::take(&mut ops), Vec::new(), &received);
            }
            notify.notify_one();
            Ok::<_, anyhow::Error>(())
        }
    };
    let writer = {
        let (shared, notify) = (shared.clone(), notify.clone());
        async move {
            loop {
                let frame = inner.with_space(&space, |r| shared.lock().poll_send(r)).unwrap_or_else(|_| {
                    shared.lock().abort(AbortReason::Gone);
                    None
                });
                match frame {
                    Some(m) => {
                        send_len(&mut tx, &m).await?;
                    }
                    None if shared.lock().is_done() => break,
                    None => {
                        // Woken by the reader after every frame; the timeout
                        // only bounds a wait on a peer that went silent.
                        if tokio::time::timeout(resources::IDLE_TIMEOUT, notify.notified()).await.is_err()
                            && !shared.lock().is_done()
                        {
                            continue;
                        }
                    }
                }
            }
            tx.finish()?;
            Ok::<_, anyhow::Error>(())
        }
    };
    let res = tokio::try_join!(reader, writer);
    let s = shared.lock();
    let stats = s.stats();
    {
        let mut t = inner.v2.totals.lock();
        if client {
            t.client_sessions += 1
        } else {
            t.server_sessions += 1
        }
        t.sent_bytes += stats.sent_bytes;
        t.recv_bytes += stats.recv_bytes;
        if matches!(s.outcome(), Some(Outcome::InSync | Outcome::Unchanged)) {
            t.idle += 1;
        }
        if stats.phase >= 2 {
            t.phase2 += 1;
        }
    }
    inner.v2.spend(peer, space, stats.sent_data_bytes);
    if stats.phase >= 2 {
        inner.v2.charge_phase2(peer);
    }
    if let Some(rec) = s.record() {
        inner.v2.records.lock().put((peer, space), rec.clone());
    }
    let outcome = s.outcome().cloned();
    drop(s);
    if matches!(outcome, Some(Outcome::InSync | Outcome::Unchanged | Outcome::Converged { .. })) {
        // The peer verified it holds our opening set: our latest writes are
        // delivered to it (delivery ticks without a per-envelope pass).
        let me = inner.keys.sign_pk();
        let _ = inner.with_space(&space, |r| {
            let recent = r.recent_envelopes(&me, 64);
            r.note_holder(peer, &recent);
        });
        inner.emit(NetEvent::SpaceChanged { space });
    }
    let stats = *received.lock();
    if moved(&stats) {
        inner.schedule(space);
    }
    res?;
    Ok(Done { stats, outcome })
}

/// Hand one frame to the session and ingest what it carried.
#[allow(clippy::too_many_arguments)]
fn process(
    inner: &Arc<Inner>,
    peer: SignPk,
    space: SpaceId,
    shared: &Arc<Mutex<Session<Replica>>>,
    msg: V2Msg,
    ops: &mut Vec<SignedOp>,
    ops_bytes: &mut usize,
    received: &Arc<Mutex<SyncStats>>,
) -> Result<()> {
    let is_ops = matches!(msg, Msg::Ops(_));
    if !is_ops && !ops.is_empty() {
        // Every frame before a non-`Ops` one is ingested before the session
        // sees it (a `SendsDone` must find them in the replica).
        ingest(inner, peer, space, shared, std::mem::take(ops), Vec::new(), received);
        *ops_bytes = 0;
    }
    let items = inner.with_space(&space, |r| shared.lock().on_msg(r, msg))?;
    let items = match items {
        Ok(items) => items,
        Err(e) => {
            shared.lock().abort(AbortReason::Protocol);
            return Err(anyhow!("sync v2 protocol error from peer: {e}"));
        }
    };
    if is_ops {
        *ops_bytes += items.ops.iter().map(reconcile::encoded_len).sum::<usize>();
        ops.extend(items.ops);
        if *ops_bytes >= OPS_BUFFER {
            ingest(inner, peer, space, shared, std::mem::take(ops), Vec::new(), received);
            *ops_bytes = 0;
        }
    } else if !items.is_empty() {
        ingest(inner, peer, space, shared, items.ops, items.envelopes, received);
    }
    Ok(())
}

fn ingest(
    inner: &Arc<Inner>,
    peer: SignPk,
    space: SpaceId,
    shared: &Arc<Mutex<Session<Replica>>>,
    ops: Vec<SignedOp>,
    envelopes: Vec<Envelope>,
    received: &Arc<Mutex<SyncStats>>,
) {
    let res = inner.with_space(&space, |r| {
        let op_ids: Vec<Hash32> = ops.iter().map(|o| o.id()).filter(|id| !r.holds_op(id)).collect();
        let all_ids: Vec<EnvelopeId> = envelopes.iter().map(|e| e.id()).collect();
        let env_ids: Vec<EnvelopeId> = all_ids.iter().filter(|id| !r.has_envelope(id)).copied().collect();
        let (res, refused) = r.ingest_batch_refused(ops, envelopes);
        let gained = reconcile::gained(r, &op_ids, &env_ids);
        // the peer holds what it sent us
        r.note_holder(peer, &all_ids);
        shared.lock().ingested(gained, &refused);
        res
    });
    let Ok(res) = res else { return };
    if res.changed() {
        {
            let mut s = received.lock();
            s.ops += res.ops;
            s.envelopes += res.envelopes;
        }
        // The app sees each chunk as it lands; forwarding to other members
        // waits for the end of the session (one round, not one per chunk).
        inner.emit(NetEvent::SpaceChanged { space });
        if res.ops > 0 {
            inner.loss_signal(space);
        }
    }
}

/// Did a session bring anything (a sign of loss for a periodic one)?
pub(crate) fn moved(stats: &SyncStats) -> bool {
    stats.ops + stats.envelopes > 0
}
