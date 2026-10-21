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
//! peer acknowledging anything: one session at a time per (peer, space),
//! in either role (two devices that open to each other at once: the lower
//! key's session runs, the other gets `Busy`), and at most
//! [`MAX_SERVED_PER_PEER`] served per peer across spaces; sessions per
//! (peer, space) that find a difference (a burst of 32, then 4 per second,
//! `Busy` beyond; an idle check with equal digests costs one hash over
//! cached op tips and boundary and is not counted); bytes sent per (peer,
//! space) (one full catch-up, then 1 MiB/min, charged for what was written
//! to the stream; the session aborts with `Budget` and resumes later,
//! keeping what arrived); phase-2 sessions per peer (6 per hour, reserved
//! when a session starts and refunded if it didn't need phase 2); and the
//! peer's frontier a session buffers (at least 65,536 authors, more if we
//! know more). The byte budget follows our set as it grows, during a
//! session too. A `Busy` answer is never a failure: [`crate::Node::sync_with`]
//! waits and runs its own session after the crossing one.
//!
//! **Liveness.** A session has no total deadline (a catch-up over
//! Bluetooth takes minutes) and no per-frame reply deadline either: the
//! side that streams hears nothing back until it is done. It fails only
//! when the peer stays silent for a reply timeout after both its last
//! frame and the time what we wrote takes to drain at the slowest planned
//! rate (QUIC accepts up to a stream window of it at once), or when a frame
//! already started stalls. Once the session reached a successful outcome, errors
//! on the stream's tail (the peer stopping its side first) don't count.
//!
//! **Negotiation (local stand-in, marked for integration).** The capability
//! hello lives on the parallel `v2/wire-versioning` branch. Until it is
//! merged, a client simply tries `SyncV2`: a build that doesn't know the
//! stream kind drops it (the stream ends before any answer) or, with the
//! versioning branch, resets it with `STREAM_REFUSED`. Either, on a
//! connection that is still up, or an explicit `Unsupported` verdict, makes
//! the client fall back to v1 and remember that peer for
//! [`V1_REMEMBERED`]. A `STREAM_REFUSED` reset or `Unsupported` is
//! remembered at once; a bare end of stream (code 0, which a v2 server that
//! failed could also cause, though it resets with [`SYNC_V2_FAILED`]) only
//! on the second time in a row, and falls back for that session alone
//! before then. A `Busy` answer, an `Abort` or a broken connection never
//! cause fallback. Integration: replace the try-and-remember with
//! `PeerState::protocol` carrying `Caps::SYNC_V2`.

use std::collections::{HashMap, VecDeque};
use std::fmt;
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
/// The reset code of a v2 server that failed after accepting the stream
/// (not a refusal: the client doesn't fall back).
pub(crate) const SYNC_V2_FAILED: u32 = 0x6d79_0002;
/// Sessions served to one peer at once, all spaces together.
pub const MAX_SERVED_PER_PEER: usize = 4;
/// How long a client waits for a session the peer is serving it in the
/// same space to end before running its own.
const WAIT_FOR_SERVED: Duration = Duration::from_secs(30);
/// How long a peer that refused `SyncV2` is synced with v1 before v2 is
/// tried again (it may have been updated).
pub const V1_REMEMBERED: Duration = Duration::from_secs(30 * 60);
/// Memory for session records, all peers and spaces together.
const RECORDS_BYTES: usize = 8 * 1024 * 1024;
const SESSION_BURST: f64 = 32.0;
const SESSIONS_PER_SEC: f64 = 4.0;
const BYTES_PER_SEC: f64 = 1024.0 * 1024.0 / 60.0;
const PHASE2_PER_HOUR: usize = 6;
/// The largest `Open` (an invite) or opening `Status` (a `Removed` proof)
/// accepted: both carry the whole membership history, so they get v1's
/// frame limit (64 MiB: about 1,900 removals in a 300-reader group, at
/// about 115 B of rotation lockbox per reader per removal), not a session
/// frame's 1.1 MiB (about 33 such removals). Like v1's `Hello`, an
/// `Open` from a device we share no space with is charged to the stranger
/// frame budget. Every later frame is a session frame
/// ([`reconcile::MAX_FRAME`]).
const OPENING_FRAME: usize = crate::wire::MAX_FRAME;
/// Frontier chunks a client may have sent after an eager `Open` (at most a
/// full frontier at the largest cap), skipped after `NeedInvite`.
const MAX_SKIPPED_FRONTIER: usize = 1024;
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
    /// Sessions running per (peer, space): (as client, as server).
    active: Mutex<HashMap<(SignPk, SpaceId), (bool, bool)>>,
    /// Ambiguous refusals (a bare end of stream) in a row, per peer.
    refusals: Mutex<HashMap<SignPk, u8>>,
    totals: Mutex<V2Totals>,
}

/// Counters for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2Totals {
    /// Sessions run as client and as server.
    pub client_sessions: u64,
    pub server_sessions: u64,
    /// Client attempts that fell back to v1 (the peer refused `SyncV2`),
    /// and peers remembered as v1-only (v2 not tried for [`V1_REMEMBERED`]).
    pub fallbacks: u64,
    pub remembered_v1: u64,
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
    /// Sessions that ended without a successful outcome (aborted, broken,
    /// stalled, refused or unconverged), both roles.
    pub failed: u64,
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
        self.totals.lock().remembered_v1 += 1;
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

    /// Reserve a phase-2 session (refunded with [`Self::refund_phase2`] if
    /// the session didn't need it): concurrent sessions can't all take the
    /// last one.
    fn take_phase2(&self, peer: SignPk) -> Option<Instant> {
        let mut p = self.phase2.lock();
        let q = p.entry(peer).or_default();
        while q.front().is_some_and(|t| t.elapsed() > Duration::from_secs(3600)) {
            q.pop_front();
        }
        (q.len() < PHASE2_PER_HOUR).then(|| {
            let now = Instant::now();
            q.push_back(now);
            now
        })
    }

    fn refund_phase2(&self, peer: SignPk, stamp: Instant) {
        if let Some(q) = self.phase2.lock().get_mut(&peer)
            && let Some(i) = q.iter().rposition(|t| *t == stamp)
        {
            q.remove(i);
        }
    }

    /// Start a client session with `peer` in `space`, unless it is serving
    /// us one there right now.
    fn begin_client(&self, peer: SignPk, space: SpaceId) -> Option<ActiveGuard<'_>> {
        let mut a = self.active.lock();
        let e = a.entry((peer, space)).or_default();
        if e.1 || e.0 {
            return None;
        }
        e.0 = true;
        Some(ActiveGuard { v2: self, key: (peer, space), client: true })
    }

    /// Start serving `peer` in `space`: not while serving it there already
    /// or more than [`MAX_SERVED_PER_PEER`] spaces at once, and not while our
    /// own session to it there runs, if our key is the lower one (the two
    /// sides decide the same way, so exactly one session survives).
    fn begin_server(&self, me: SignPk, peer: SignPk, space: SpaceId) -> Option<ActiveGuard<'_>> {
        let mut a = self.active.lock();
        let served = a.iter().filter(|((p, _), (_, srv))| *p == peer && *srv).count();
        let e = a.entry((peer, space)).or_default();
        if e.1 || (e.0 && me < peer) || served >= MAX_SERVED_PER_PEER {
            return None;
        }
        e.1 = true;
        Some(ActiveGuard { v2: self, key: (peer, space), client: false })
    }

    /// Count an ambiguous refusal; true when it should be remembered.
    fn note_refusal(&self, peer: SignPk) -> bool {
        let mut r = self.refusals.lock();
        let n = r.entry(peer).or_default();
        *n += 1;
        if *n >= 2 {
            r.remove(&peer);
            true
        } else {
            false
        }
    }
}

/// A running session in [`V2::active`]; cleared when dropped.
struct ActiveGuard<'a> {
    v2: &'a V2,
    key: (SignPk, SpaceId),
    client: bool,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let mut a = self.v2.active.lock();
        if let Some(e) = a.get_mut(&self.key) {
            if self.client {
                e.0 = false;
            } else {
                e.1 = false;
            }
            if !e.0 && !e.1 {
                a.remove(&self.key);
            }
        }
    }
}

/// The peer answered `Busy`, or is already syncing this space with us: not
/// a failure (no backoff, no store-and-forward bundle).
#[derive(Debug)]
pub(crate) struct PeerBusy(pub u32);

impl PeerBusy {
    /// When to try again (the peer's hint, within [200 ms, 5 s]).
    pub(crate) fn retry_after(&self) -> Duration {
        Duration::from_millis(u64::from(self.0).clamp(200, 5000))
    }
}

impl fmt::Display for PeerBusy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer busy (retry in {} ms)", self.0)
    }
}

impl std::error::Error for PeerBusy {}

/// One full catch-up of our set (ops estimated at 8 KiB each), then the
/// refill rate.
fn byte_cap(r: &Replica) -> f64 {
    1.1 * (r.stored_bytes() as f64 + r.op_count() as f64 * 8192.0) + 1024.0 * 1024.0
}

fn config(inner: &Inner, peer: SignPk, space: SpaceId, r: &Replica, allow_phase2: bool) -> Config {
    // The peer's frontier, buffered whole: at least 65,536 authors (a fresh
    // device knows almost none, a long-lived peer lists every author that
    // ever wrote), more if we know more (see `Config::for_known`).
    let known = r.index().entries().len().max(r.members().len());
    Config { send_budget: inner.v2.byte_budget(peer, space, byte_cap(r)), allow_phase2, ..Config::for_known(known) }
}

/// Did the peer refuse the stream kind (a build without Sync v2)? Only on
/// a connection that is still up, on the opening exchange. `Some(true)`:
/// explicitly (reset or stopped with [`STREAM_REFUSED`]); `Some(false)`:
/// ambiguously (the stream ended before any answer, or code 0).
fn refused(err: &anyhow::Error, conn: &Connection) -> Option<bool> {
    use iroh::endpoint::{ReadError, ReadExactError, VarInt, WriteError};
    if conn.close_reason().is_some() {
        return None;
    }
    let code = |e: &(dyn std::error::Error + 'static)| -> Option<VarInt> {
        match e.downcast_ref::<ReadExactError>() {
            Some(ReadExactError::FinishedEarly(0)) => return Some(VarInt::from_u32(0)),
            Some(ReadExactError::ReadError(ReadError::Reset(c))) => return Some(*c),
            _ => {}
        }
        if let Some(ReadError::Reset(c)) = e.downcast_ref::<ReadError>() {
            return Some(*c);
        }
        if let Some(WriteError::Stopped(c)) = e.downcast_ref::<WriteError>() {
            return Some(*c);
        }
        None
    };
    let found = err.chain().find_map(|e| {
        code(e).or_else(|| {
            let io = e.downcast_ref::<std::io::Error>()?;
            // A read that hit the end of the stream (tokio's `read_exact`:
            // "early eof"): the peer finished its side, code 0.
            io.get_ref()
                .and_then(|inner| code(inner))
                .or_else(|| (io.kind() == std::io::ErrorKind::UnexpectedEof).then(|| VarInt::from_u32(0)))
        })
    })?;
    if found == VarInt::from_u32(STREAM_REFUSED) {
        Some(true)
    } else if found == VarInt::from_u32(0) {
        Some(false)
    } else {
        None
    }
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
/// doesn't speak Sync v2 (run v1; remembered once it is clear). A
/// [`PeerBusy`] error: the peer is syncing this space with us already, or
/// is over its limits.
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
    // One session per (peer, space): wait out one it is serving us (it
    // carries our pinned set both ways; ours then sends what came after).
    let waited = Instant::now();
    let _active = loop {
        if let Some(g) = inner.v2.begin_client(peer, space) {
            break g;
        }
        if waited.elapsed() > WAIT_FOR_SERVED {
            return Err(PeerBusy(1000).into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let res = crate::on_conn!(inner, &peer, |conn| exchange(inner, &conn, peer, space, eager));
    match res {
        Ok(Exchange::Refused { explicit }) => {
            inner.v2.totals.lock().fallbacks += 1;
            if explicit || inner.v2.note_refusal(peer) {
                inner.v2.mark_v1_only(peer);
            }
            Ok(None)
        }
        Ok(Exchange::Done(stats)) => {
            inner.v2.refusals.lock().remove(&peer);
            Ok(Some(stats))
        }
        Err(e) => Err(e),
    }
}

enum Exchange {
    Done(SyncStats),
    /// The peer refused the stream kind (see [`refused`]).
    Refused {
        explicit: bool,
    },
}

async fn exchange(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    space: SpaceId,
    eager: bool,
) -> Result<Exchange> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::SyncV2).await?;
    let record = inner.v2.records.lock().get(&(peer, space));
    let phase2 = inner.v2.take_phase2(peer);
    let res = exchange_on(inner, conn, peer, space, eager, record, phase2, &mut tx, &mut rx).await;
    if let Some(stamp) = phase2
        && !matches!(&res, Ok(Exchange::Done(_)))
    {
        // (a session that ran refunds in `drive`)
        inner.v2.refund_phase2(peer, stamp);
    }
    res
}

#[allow(clippy::too_many_arguments)]
async fn exchange_on(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    space: SpaceId,
    eager: bool,
    record: Option<PeerRecord>,
    phase2: Option<Instant>,
    tx: &mut SendStream,
    rx: &mut RecvStream,
) -> Result<Exchange> {
    let new_session = |invite: Option<Vec<SignedOp>>| {
        inner.with_space(&space, |r| {
            let cfg = config(inner, peer, space, r, phase2.is_some());
            Session::<Replica>::open(r, cfg, mycel_crypto::random(), record.clone(), eager, invite)
        })
    };
    let mut session = new_session(None)?;
    let mut invited = false;
    let first = loop {
        let mut sent = 0;
        while let Some(m) = inner.with_space(&space, |r| session.poll_send(r))? {
            match send_len(tx, &m).await {
                Ok(n) => sent += n,
                Err(e) => match refused(&e, conn) {
                    Some(explicit) => return Ok(Exchange::Refused { explicit }),
                    None => return Err(e),
                },
            }
        }
        let wait = resources::reply_timeout(sent);
        // The answer to `Open` may carry a `Removed` proof: the whole
        // membership history, as large as v1 allows (see `OPENING_FRAME`).
        let msg = match recv_bounded::<V2Msg>(rx, wait, OPENING_FRAME, &inner.reply_frames(&peer)).await {
            Ok((m, _permit)) => m,
            Err(e) => match refused(&e, conn) {
                Some(explicit) => return Ok(Exchange::Refused { explicit }),
                None => return Err(e),
            },
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
            Msg::Status(Verdict::Unsupported { .. }) => return Ok(Exchange::Refused { explicit: true }),
            Msg::Status(Verdict::Busy { retry_after_ms }) => {
                inner.v2.totals.lock().busy_received += 1;
                return Err(PeerBusy(retry_after_ms).into());
            }
            other => break other,
        }
    };
    let done = drive(inner, peer, space, session, Some(first), tx, rx, true, phase2).await?;
    inner.note_path(peer, conn);
    Ok(Exchange::Done(finish(inner, peer, done)?))
}

fn finish(inner: &Arc<Inner>, peer: SignPk, done: Done) -> Result<SyncStats> {
    match done.outcome {
        Some(Outcome::Aborted { reason, by_peer }) => {
            bail!("sync aborted ({reason:?}, by {})", if by_peer { "peer" } else { "us" })
        }
        Some(Outcome::Refused(why)) => bail!("sync refused: {why:?}"),
        None => bail!("sync ended early"),
        Some(_) => {
            inner.mark_ok(peer);
            Ok(done.stats)
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
        // Exactly what a build before Sync v2 does: an error on the unknown
        // stream kind, dropping both halves (the opener sees the stream end,
        // code 0), not the explicit refusal of later builds.
        drop((tx, rx));
        bail!("unknown stream kind {}", StreamKind::SyncV2 as u8);
    }
    let res = serve_on(inner, conn, peer, &mut tx, &mut rx).await;
    if res.is_err() {
        // Never a bare end of stream: the client must not take a failure
        // for a build without v2.
        let code = iroh::endpoint::VarInt::from_u32(SYNC_V2_FAILED);
        rx.stop(code).ok();
        tx.reset(code).ok();
    }
    res
}

async fn serve_on(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    tx: &mut SendStream,
    rx: &mut RecvStream,
) -> Result<()> {
    // `Open` may carry an invite: the whole membership history (see
    // `OPENING_FRAME`).
    let max = OPENING_FRAME;
    let (mut msg, mut _permit) = recv_bounded::<V2Msg>(rx, resources::FIRST_FRAME, max, &inner.frames(&peer)).await?;
    let mut asked_invite = false;
    loop {
        let Msg::Open(mut open) = msg else { bail!("expected Open") };
        let space = open.space;
        if !inner.spaces.lock().contains_key(&space) {
            match open.invite.take() {
                None if !asked_invite => {
                    asked_invite = true;
                    let n = send_len(tx, &V2Msg::Status(Verdict::NeedInvite)).await?;
                    let wait = resources::reply_timeout(n);
                    // A client that sent its frontier eagerly sent the rest
                    // of it after `Open` before reading our answer: skip it
                    // (bounded) until the `Open` that carries the invite.
                    let mut skipped = 0;
                    loop {
                        (msg, _permit) = recv_bounded(rx, wait, max, &inner.frames(&peer)).await?;
                        if !matches!(msg, Msg::Frontier(_)) {
                            break;
                        }
                        skipped += 1;
                        if skipped > MAX_SKIPPED_FRONTIER {
                            bail!("too many frontier chunks before the invite");
                        }
                    }
                    continue;
                }
                None => {
                    send_len(tx, &V2Msg::Status(Verdict::Denied)).await?;
                    tx.finish()?;
                    return Ok(());
                }
                Some(ops) => {
                    if !accept_invite(inner, peer, space, ops) {
                        send_len(tx, &V2Msg::Status(Verdict::Denied)).await?;
                        tx.finish()?;
                        return Ok(());
                    }
                }
            }
        }
        open.invite = None;
        let me = inner.keys.sign_pk();
        let active = inner.v2.begin_server(me, peer, space);
        let phase2 = if active.is_some() { inner.v2.take_phase2(peer) } else { None };
        // Membership gate: only current members (any role) may sync.
        let record = inner.v2.records.lock().get(&(peer, space));
        let gate = inner.with_space(&space, |r| {
            if r.is_member(&peer) {
                if active.is_none() {
                    return Err(Box::new(Verdict::Busy { retry_after_ms: 1000 }));
                }
                let cap = byte_cap(r);
                let idle = open.digest == r.digest();
                match if idle { Ok(()) } else { inner.v2.take_session(peer, space, cap) } {
                    Ok(()) => Ok(Session::accept(r, config(inner, peer, space, r, phase2.is_some()), open, record)),
                    Err(retry_after_ms) => Err(Box::new(Verdict::Busy { retry_after_ms })),
                }
            } else {
                let proof = r.revocation_proof(&peer);
                Err(Box::new(if proof.is_empty() { Verdict::Denied } else { Verdict::Removed { ops: proof } }))
            }
        });
        let gate = match gate {
            Ok(g) => g,
            Err(e) => {
                if let Some(stamp) = phase2 {
                    inner.v2.refund_phase2(peer, stamp);
                }
                return Err(e);
            }
        };
        let session = match gate {
            Ok(s) => s,
            Err(v) => {
                if let Some(stamp) = phase2 {
                    inner.v2.refund_phase2(peer, stamp);
                }
                if matches!(*v, Verdict::Busy { .. }) {
                    inner.v2.totals.lock().busy_sent += 1;
                }
                send_len(tx, &V2Msg::Status(*v)).await?;
                tx.finish()?;
                return Ok(());
            }
        };
        inner.v2.note_inbound(space, peer);
        drop(_permit);
        let done = drive(inner, peer, space, session, None, tx, rx, false, phase2).await?;
        drop(active);
        inner.note_path(peer, conn);
        finish(inner, peer, done)?;
        return Ok(());
    }
}

// ─────────────────────────────── both ───────────────────────────────

/// When the peer last sent a frame, and when what we wrote will have been
/// delivered at the slowest planned rate (see the module docs, "Liveness").
struct Progress {
    heard: Instant,
    drained: Instant,
}

impl Progress {
    /// We wrote `n` bytes: they queue behind what is still undelivered
    /// (at most a stream window of it).
    fn wrote(&mut self, n: usize) {
        let now = Instant::now();
        let per = Duration::from_secs_f64(n as f64 / resources::SLOWEST_RATE as f64);
        let most = now + Duration::from_secs(resources::MAX_UNDELIVERED / resources::SLOWEST_RATE);
        self.drained = (self.drained.max(now) + per).min(most);
    }
}

/// Completes once the peer has been silent for a reply timeout after the
/// later of its last frame and the delivery of what we wrote.
async fn stalled(p: &Mutex<Progress>) {
    loop {
        let deadline = {
            let p = p.lock();
            p.heard.max(p.drained) + resources::REPLY_TIMEOUT
        };
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline.into()).await;
    }
}

/// Run a session to its end on `tx`/`rx`. `first`: a frame already read
/// (the client's `Status`). `phase2`: the reserved phase-2 slot, refunded
/// if the session didn't use it.
#[allow(clippy::too_many_arguments)]
async fn drive(
    inner: &Arc<Inner>,
    peer: SignPk,
    space: SpaceId,
    session: Session<Replica>,
    first: Option<V2Msg>,
    tx: &mut SendStream,
    rx: &mut RecvStream,
    client: bool,
    phase2: Option<Instant>,
) -> Result<Done> {
    let shared = Arc::new(Mutex::new(session));
    let notify = Notify::new();
    let received = Arc::new(Mutex::new(SyncStats::default()));
    let progress = Mutex::new(Progress { heard: Instant::now(), drained: Instant::now() });
    // Data bytes written to the stream (what the byte budget is charged).
    let written_data = Mutex::new(0u64);
    let frames = if client { inner.reply_frames(&peer) } else { inner.frames(&peer) };
    // The reader borrows `rx`, which outlives both loops: dropping it as
    // soon as the outcome is known would stop the peer's last writes.
    let reader = async {
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
            // No reply deadline of its own (see "Liveness"); a frame
            // already started must keep arriving (`IDLE_TIMEOUT`).
            let got = tokio::select! {
                r = recv_bounded::<V2Msg>(rx, Duration::from_secs(86_400), reconcile::MAX_FRAME, &frames) => r,
                _ = stalled(&progress) => Err(anyhow!("sync stalled: nothing moved either way")),
            };
            let msg = match got {
                Ok((m, _permit)) => m,
                Err(_) if shared.lock().outcome().is_some() => break,
                Err(e) => {
                    notify.notify_one();
                    return Err(e);
                }
            };
            progress.lock().heard = Instant::now();
            let res = process(inner, peer, space, &shared, msg, &mut ops, &mut ops_bytes, &received);
            notify.notify_one();
            res?;
        }
        if !ops.is_empty() {
            ingest(inner, peer, space, &shared, std::mem::take(&mut ops), Vec::new(), &received);
        }
        notify.notify_one();
        Ok::<_, anyhow::Error>(())
    };
    let writer = async {
        loop {
            let frame = inner
                .with_space(&space, |r| {
                    let mut s = shared.lock();
                    // The budget follows our set: it may have grown since the
                    // session opened (a write, or what this very session
                    // brought while both sides stream), and a budget fixed
                    // at the start aborted catch-ups halfway.
                    s.raise_send_budget(inner.v2.byte_budget(peer, space, byte_cap(r)));
                    s.poll_send(r)
                })
                .unwrap_or_else(|_| {
                    shared.lock().abort(AbortReason::Gone);
                    None
                });
            match frame {
                Some(m) => {
                    let data = matches!(m, Msg::Ops(_) | Msg::Chunk(_));
                    let n = send_len(tx, &m).await?;
                    if data {
                        *written_data.lock() += n as u64;
                    }
                    progress.lock().wrote(n);
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
    };
    // The writer ends only once the session is done and everything owed is
    // sent: nothing more is needed from the peer then, so a peer that never
    // finishes its side can't hold the session (or a sync slot) open.
    tokio::pin!(reader, writer);
    let res = tokio::select! {
        r = &mut reader => match r {
            Ok(()) => (&mut writer).await,
            Err(e) => Err(e),
        },
        w = &mut writer => match w {
            Ok(()) => Ok(()),
            // The peer may have stopped our stream once it had our `Close`:
            // its own `Close` may still be on the way, so read on (the
            // reader ends on the outcome, an error, or a stall).
            Err(e) => {
                let _ = (&mut reader).await;
                Err(e)
            }
        },
    };
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
        if !matches!(s.outcome(), Some(Outcome::InSync | Outcome::Unchanged | Outcome::Converged { .. })) {
            t.failed += 1;
        }
    }
    inner.v2.spend(peer, space, *written_data.lock());
    if let Some(stamp) = phase2
        && stats.phase < 2
    {
        inner.v2.refund_phase2(peer, stamp);
    }
    if let Some(rec) = s.record() {
        inner.v2.records.lock().put((peer, space), rec.clone());
    }
    let outcome = s.outcome().cloned();
    let me = inner.keys.sign_pk();
    let delivered_to = s.peer_holds_my_opening_set().then(|| s.opening_top(&me));
    drop(s);
    if let Some(top) = delivered_to {
        // The peer verified it holds our opening set: our latest writes up
        // to its pinned top are delivered (ticks without a per-envelope
        // pass; writes made during the session wait for the next one).
        let _ = inner.with_space(&space, |r| {
            let recent: Vec<EnvelopeId> = r
                .recent_envelopes(&me, 64)
                .into_iter()
                .filter(|id| top.is_some_and(|t| r.index().seq(id).is_some_and(|s| s <= t)))
                .collect();
            r.note_holder(peer, &recent);
        });
        inner.emit(NetEvent::SpaceChanged { space });
    }
    let stats = *received.lock();
    if moved(&stats) {
        inner.schedule(space);
    }
    // A session that reached a successful outcome succeeded, whatever
    // happened to the stream's tail afterwards (the peer may stop reading
    // its side as soon as it has our `Close`).
    if !matches!(outcome, Some(Outcome::InSync | Outcome::Unchanged | Outcome::Converged { .. })) {
        res?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_session_per_peer_and_space_in_either_role() {
        let v2 = V2::default();
        let (lo, hi) = (SignPk([1; 32]), SignPk([2; 32]));
        let space = Hash32([5; 32]);
        // I am `lo` with a session open to `hi`: `hi`'s crossing open is
        // refused (the lower key's session wins) ...
        let c = v2.begin_client(hi, space).unwrap();
        assert!(v2.begin_server(lo, hi, space).is_none());
        drop(c);
        // ... and as `hi`, `lo`'s open is served (ours will get `Busy`).
        let c = v2.begin_client(lo, space).unwrap();
        let s = v2.begin_server(hi, lo, space).unwrap();
        assert!(v2.begin_server(hi, lo, space).is_none(), "one served per (peer, space)");
        drop((c, s));
        // A client waits while the peer is served in that space.
        let s = v2.begin_server(hi, lo, space).unwrap();
        assert!(v2.begin_client(lo, space).is_none());
        drop(s);
        assert!(v2.active.lock().is_empty());
        // At most MAX_SERVED_PER_PEER spaces served to one peer at once.
        let held: Vec<_> =
            (0..MAX_SERVED_PER_PEER as u8).map(|i| v2.begin_server(hi, lo, Hash32([i; 32])).unwrap()).collect();
        assert!(v2.begin_server(hi, lo, Hash32([99; 32])).is_none());
        drop(held);
        assert!(v2.begin_server(hi, lo, Hash32([99; 32])).is_some());
    }

    #[test]
    fn phase2_slots_are_reserved_up_front_and_refunded() {
        let v2 = V2::default();
        let peer = SignPk([3; 32]);
        let stamps: Vec<Instant> = (0..PHASE2_PER_HOUR).map(|_| v2.take_phase2(peer).unwrap()).collect();
        assert!(v2.take_phase2(peer).is_none(), "concurrent sessions can't all take the last slot");
        v2.refund_phase2(peer, stamps[2]);
        assert!(v2.take_phase2(peer).is_some());
    }

    #[test]
    fn an_ambiguous_refusal_is_remembered_only_the_second_time() {
        let v2 = V2::default();
        let peer = SignPk([4; 32]);
        assert!(!v2.note_refusal(peer));
        assert!(v2.note_refusal(peer));
        assert!(!v2.note_refusal(peer), "counting starts again");
    }
}
