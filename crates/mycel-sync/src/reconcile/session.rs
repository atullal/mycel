//! The Sync v2 session state machine (sans-IO).
//!
//! The driver (node or simulator) feeds every frame from the peer to
//! [`Session::on_msg`], ingests the items it returns (into the replica,
//! which validates each one) and reports back with [`Session::ingested`],
//! and sends whatever [`Session::poll_send`] yields until it returns
//! `None`. Reading and writing are independent: a side never waits for the
//! peer before sending what it owes, so flow control cannot deadlock.
//!
//! Phases (each side keeps its own copy of the state; both reach the same
//! decisions because they follow from the frames both have seen):
//!
//! 1. Frontier: each side plans its sends from the peer's opening frontier
//!    and streams them, then `SendsDone{1}`. On the peer's `SendsDone{1}` it
//!    checks coverage and sends `Close{1}`. Both `All`: converged.
//! 2. Placement: runs whose coverage phase 1 couldn't decide (a fork whose
//!    other branch the side doesn't hold) are probed and sent; op sends
//!    deferred in phase 1 are made. Then `SendsDone{2}` and `Close{2}`.
//!
//! Otherwise the session ends `Unconverged`, and the driver tries another
//! partner later. Every amount of work is bounded per session (frames,
//! probes, bytes) whatever the peer says.

use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use mycel_crypto::{Hash32, SignPk};
use mycel_trust::{OpId, SpaceId};

use super::msg::{AbortReason, AuthorEntry, Coverage, Digest, Frontier, Msg, Open, RecordName, Run, Scope, Verdict};
use super::{
    CHUNK_BYTES, ChainIndex, FEATURES, FRONTIER_CHUNK_AUTHORS, MAX_OP_TIPS, MAX_RUNS_INLINE, PROBE_POINTS, Summary,
    SyncSet, VERSION, encoded_len, frame_len,
};
use crate::EnvelopeId;

/// Which end of the stream this side is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Per-session limits. None of them depends on the peer acknowledging
/// anything.
#[derive(Clone, Debug)]
pub struct Config {
    /// Target size of data frames.
    pub chunk_bytes: usize,
    /// Most authors, and runs in all, accepted in the peer's frontier
    /// (what a session buffers of it).
    pub max_frontier_authors: usize,
    pub max_frontier_runs: usize,
    /// Placement work per session: (my run, peer run) pairs compared
    /// (honest authors need one per run, normally one), and index steps
    /// for authors with more than [`MAX_RUNS_INLINE`] runs (an equivocation
    /// flood). Past either cap the rest waits for a later session (whose
    /// rotated order reaches it), so no peer or author can make a session
    /// slow.
    pub max_place_pairs: usize,
    pub max_flood_steps: usize,
    /// Data bytes this side may send in this session (the driver's per-peer
    /// byte budget); beyond it the session aborts with `Budget`.
    pub send_budget: u64,
    /// Data bytes accepted from the peer in this session.
    pub recv_budget: u64,
    /// May this session run phase 2 (the driver's per-peer phase-2 budget)?
    pub allow_phase2: bool,
    /// Runs probed per session, and rounds per run.
    pub max_probe_runs: usize,
    pub max_probe_rounds: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            chunk_bytes: CHUNK_BYTES,
            max_frontier_authors: 1 << 16,
            max_frontier_runs: 1 << 18,
            max_place_pairs: 1 << 17,
            max_flood_steps: 1 << 20,
            send_budget: u64::MAX,
            recv_budget: 4 << 30,
            allow_phase2: true,
            max_probe_runs: 64,
            max_probe_rounds: 8,
        }
    }
}

/// Why a session ended without syncing (from the server's `Status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    NeedInvite,
    Denied,
    Removed,
    Unsupported,
    Busy { retry_after_ms: u32 },
}

/// How a session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Equal digests at the start.
    InSync,
    /// Neither side changed since a quiet converged session both remember.
    Unchanged,
    /// Each side now holds the other's opening set. `moved`: items were
    /// received in this session.
    Converged { phase: u8, moved: bool },
    /// Coverage still failed after the last phase.
    Unconverged { phase: u8, ops: bool, authors: Vec<SignPk> },
    /// The server refused (see `Status`).
    Refused(Refusal),
    /// The session stopped: `by_peer` if the peer sent `Abort`.
    Aborted { reason: AbortReason, by_peer: bool },
}

/// A protocol violation by the peer. The driver sends `Abort{Protocol}` and
/// drops the stream; nothing the peer sent so far is lost (it was ingested
/// and validated item by item).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("unexpected {0} message")]
    Unexpected(&'static str),
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

/// Items received in one frame, for the driver to ingest.
#[derive(Debug)]
pub struct Received<O, E> {
    pub ops: Vec<O>,
    pub envelopes: Vec<E>,
}

impl<O, E> Default for Received<O, E> {
    fn default() -> Self {
        Received { ops: Vec::new(), envelopes: Vec::new() }
    }
}

impl<O, E> Received<O, E> {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.envelopes.is_empty()
    }
}

/// What a side remembers about a peer after a converged session (SSB EBT's
/// remembered clocks, with digests): the next session's frontiers are
/// deltas against these, and `Unchanged` answers idle checks between peers
/// whose sets differ for good. One-sided: neither side needs the other to
/// have stored anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// The two `Close` digests, client's first.
    pub name: RecordName,
    /// My opening summary, which the peer verified it covers.
    pub mine: Summary,
    /// The peer's opening summary, which I verified I cover.
    pub peer: Summary,
    /// Both sides' closing sets were their opening sets plus what the other
    /// sent.
    pub quiet: bool,
    pub my_close: Digest,
    pub peer_close: Digest,
    /// Ids the peer refused for reasons intrinsic to the item: not offered
    /// to it again.
    pub refused: Arc<HashSet<EnvelopeId>>,
    /// Ids I refused from the peer: they count as covered.
    pub i_refused: Arc<HashSet<EnvelopeId>>,
}

impl PeerRecord {
    /// Rough memory footprint, for the driver's cap.
    pub fn size(&self) -> usize {
        let entries =
            |s: &Summary| s.authors.values().map(|e| 40 + e.runs.len() * 48).sum::<usize>() + s.ops.len() * 32;
        let shared = Arc::ptr_eq(&self.mine.authors, &self.peer.authors);
        128 + entries(&self.mine)
            + if shared { 0 } else { entries(&self.peer) }
            + (self.refused.len() + self.i_refused.len()) * 32
    }
}

/// Bytes and frames, both directions (postcard plus the 4-byte length).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub sent_frames: u64,
    pub recv_frames: u64,
    pub sent_data_bytes: u64,
    pub recv_data_bytes: u64,
    pub items_out: u64,
    pub items_in: u64,
    pub phase: u8,
    pub probes_sent: u64,
}

/// Envelopes owed along one branch, sent in ascending seq.
struct Job {
    ids: Vec<EnvelopeId>,
    next: usize,
}

/// Jobs interleaved by proportional round-robin: the next envelope comes
/// from the job whose sent fraction is lowest, which approximates global
/// time order without timestamps.
#[derive(Default)]
struct Jobs {
    jobs: Vec<Job>,
    heap: BinaryHeap<std::cmp::Reverse<(u64, usize)>>,
}

impl Jobs {
    fn push(&mut self, ids: Vec<EnvelopeId>) {
        if ids.is_empty() {
            return;
        }
        self.heap.push(std::cmp::Reverse((0, self.jobs.len())));
        self.jobs.push(Job { ids, next: 0 });
    }

    fn pop(&mut self) -> Option<EnvelopeId> {
        let std::cmp::Reverse((_, j)) = self.heap.pop()?;
        let job = &mut self.jobs[j];
        let id = job.ids[job.next];
        job.next += 1;
        if job.next < job.ids.len() {
            let frac = ((job.next as u128) << 32) / job.ids.len() as u128;
            self.heap.push(std::cmp::Reverse((frac as u64, j)));
        } else {
            job.ids = Vec::new();
        }
        Some(id)
    }
}

/// A run being placed by probing (phase 2).
struct Probe {
    run: Run,
    author: SignPk,
    /// Highest seq known held by the peer, if any.
    held: Option<u64>,
    /// Lowest seq known not held (above `held`).
    unheld: u64,
    rounds: u8,
    /// Points of the probe in flight.
    asked: Vec<(u64, EnvelopeId)>,
    /// Seq intervals of the run the peer is known to hold.
    covered: Vec<(u64, u64)>,
}

/// An incoming frontier being assembled from chunks.
struct FrontierRx {
    delta_of: Option<RecordName>,
    ops: Option<Vec<OpId>>,
    authors: Vec<AuthorEntry>,
    runs: usize,
    done: bool,
}

#[derive(Clone)]
struct CloseInfo {
    coverage: Coverage,
    digest: Digest,
    quiet: bool,
    phase2: bool,
}

/// One Sync v2 session (see the module docs).
pub struct Session<S: SyncSet> {
    role: Role,
    cfg: Config,
    space: SpaceId,
    /// The client's nonce: varies the order flooded authors are placed in.
    nonce: [u8; 16],
    /// The record the frontiers of this session are deltas against.
    record: Option<PeerRecord>,
    refused_by_peer: HashSet<EnvelopeId>,
    /// Continuation chunks of a client delta the server couldn't use.
    discard: Option<RecordName>,
    mine: Summary,
    my_digest: Digest,
    count_open: u64,
    peer: Option<Summary>,
    rx: Option<FrontierRx>,
    outbox: VecDeque<Msg<S::Op, S::Env>>,
    ops_q: VecDeque<OpId>,
    jobs: Jobs,
    /// Envelopes queued (or skipped as refused), each with the lowest seq
    /// down to which its branch is queued too.
    queued: HashMap<EnvelopeId, u64>,
    queued_ops: HashSet<OpId>,
    /// 0 until both frontiers are known, then 1 or 2.
    phase: u8,
    planned: bool,
    /// Placement stopped at the work cap: what this side owes isn't all
    /// queued, so the session's record isn't quiet.
    incomplete: bool,
    probes: BTreeMap<EnvelopeId, Probe>,
    probes_answered: usize,
    sends_done: bool,
    peer_sends_done: bool,
    my_close: Option<CloseInfo>,
    peer_close: Option<CloseInfo>,
    refused_here: Vec<EnvelopeId>,
    ingested_new: u64,
    status_seen: bool,
    outcome: Option<Outcome>,
    record_out: Option<PeerRecord>,
    stats: SessionStats,
}

impl<S: SyncSet> Session<S> {
    fn new(role: Role, set: &S, cfg: Config, nonce: [u8; 16], record: Option<PeerRecord>) -> Self {
        let refused_by_peer = record.as_ref().map(|r| (*r.refused).clone()).unwrap_or_default();
        Session {
            role,
            cfg,
            space: set.space(),
            nonce,
            record,
            refused_by_peer,
            discard: None,
            mine: set.summary(),
            my_digest: set.digest(),
            count_open: set.count(),
            peer: None,
            rx: None,
            outbox: VecDeque::new(),
            ops_q: VecDeque::new(),
            jobs: Jobs::default(),
            queued: HashMap::new(),
            queued_ops: HashSet::new(),
            phase: 0,
            planned: false,
            incomplete: false,
            probes: BTreeMap::new(),
            probes_answered: 0,
            sends_done: false,
            peer_sends_done: false,
            my_close: None,
            peer_close: None,
            refused_here: Vec::new(),
            ingested_new: 0,
            status_seen: false,
            outcome: None,
            record_out: None,
            stats: SessionStats::default(),
        }
    }

    /// Start a session as the client. `record`: the last converged session
    /// with this server, if remembered. `eager`: send the frontier now even
    /// without a record (a local write: saves a round trip). `invite`: the
    /// membership ops, after the server answered `NeedInvite`.
    pub fn open(
        set: &S,
        cfg: Config,
        nonce: [u8; 16],
        record: Option<PeerRecord>,
        eager: bool,
        invite: Option<Vec<S::Op>>,
    ) -> Self {
        let mut s = Self::new(Role::Client, set, cfg, nonce, record);
        let mut chunks = match &s.record {
            Some(r) => s.mine.chunks(Some((&r.mine, r.name))),
            None if eager => s.mine.chunks(None),
            None => Vec::new(),
        };
        let first = (!chunks.is_empty()).then(|| chunks.remove(0));
        let open = Open {
            version: VERSION,
            features: FEATURES,
            space: s.space,
            nonce,
            digest: s.my_digest,
            memory: s.record.as_ref().map(|r| r.name),
            scope: Scope::Full,
            frontier: first,
            invite,
        };
        s.outbox.push_back(Msg::Open(open));
        s.outbox.extend(chunks.into_iter().map(Msg::Frontier));
        s
    }

    /// Answer a client's `Open` (after the driver's membership gate).
    /// `record`: what this server remembers about the client.
    pub fn accept(set: &S, cfg: Config, open: Open<S::Op>, record: Option<PeerRecord>) -> Self {
        let mut s = Self::new(Role::Server, set, cfg, open.nonce, record);
        s.stats.recv_frames += 1;
        s.stats.recv_bytes += frame_len(&Msg::<S::Op, S::Env>::Open(open.clone())) as u64;
        s.status_seen = true;
        if open.version != VERSION || open.features & !FEATURES != 0 || open.space != s.space {
            s.finish_with(Verdict::Unsupported { version: VERSION, features: FEATURES }, Refusal::Unsupported);
            return s;
        }
        let rec = s.record.clone().filter(|r| Some(r.name) == open.memory);
        if open.digest == s.my_digest {
            s.record_out = Some(s.refreshed_record());
            s.outbox.push_back(Msg::Status(Verdict::InSync { digest: s.my_digest }));
            s.outcome = Some(Outcome::InSync);
            return s;
        }
        if let Some(r) = &rec
            && r.quiet
            && r.my_close == s.my_digest
            && r.peer_close == open.digest
        {
            s.outbox.push_back(Msg::Status(Verdict::Unchanged { digest: s.my_digest }));
            s.outcome = Some(Outcome::Unchanged);
            return s;
        }
        // Can we use the client's frontier?
        let mut need_full = true;
        if let Some(f) = open.frontier {
            let usable = match f.delta_of {
                None => true,
                Some(name) => rec.as_ref().is_some_and(|r| r.name == name),
            };
            if usable {
                need_full = false;
                if s.on_frontier_chunk(f).is_err() {
                    need_full = true;
                    s.rx = None;
                }
            }
        }
        // The record is a usable delta base only if the client named it.
        if need_full {
            s.discard = open.memory;
        }
        s.record = rec;
        let mut chunks = match &s.record {
            Some(r) => s.mine.chunks(Some((&r.mine, r.name))),
            None => s.mine.chunks(None),
        };
        let first = chunks.remove(0);
        s.outbox.push_back(Msg::Status(Verdict::Diff { digest: s.my_digest, frontier: first, need_full }));
        s.outbox.extend(chunks.into_iter().map(Msg::Frontier));
        s.phase = 1;
        s.stats.phase = 1;
        if need_full {
            s.rx = None;
        }
        s.try_start(set);
        s
    }

    fn finish_with(&mut self, v: Verdict<S::Op>, why: Refusal) {
        self.outbox.push_back(Msg::Status(v));
        self.outcome = Some(Outcome::Refused(why));
    }

    /// A record naming the current, equal sets (after `InSync`): both sides
    /// derive the same one without exchanging anything.
    fn refreshed_record(&self) -> PeerRecord {
        PeerRecord {
            name: (self.my_digest, self.my_digest),
            mine: self.mine.clone(),
            peer: self.mine.clone(),
            quiet: true,
            my_close: self.my_digest,
            peer_close: self.my_digest,
            refused: self.record.as_ref().map(|r| r.refused.clone()).unwrap_or_default(),
            i_refused: self.record.as_ref().map(|r| r.i_refused.clone()).unwrap_or_default(),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// How the session ended, once it has.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// Finished, with nothing left to send.
    pub fn is_done(&self) -> bool {
        self.outcome.is_some() && self.outbox.is_empty()
    }

    /// What to remember about the peer after this session, if anything new.
    pub fn record(&self) -> Option<&PeerRecord> {
        self.record_out.as_ref()
    }

    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// The highest seq of `author` in my opening set (what a peer that
    /// verified my set holds of that chain at least).
    pub fn opening_top(&self, author: &SignPk) -> Option<u64> {
        self.mine.top(author)
    }

    /// Did the peer verify that it holds my whole opening set? (`InSync`
    /// on equal digests, `Unchanged`, or `Converged`; not an `InSync` whose
    /// digest no longer matched my pinned set.)
    pub fn peer_holds_my_opening_set(&self) -> bool {
        match &self.outcome {
            Some(Outcome::InSync) => self.record_out.is_some(),
            Some(Outcome::Unchanged | Outcome::Converged { .. }) => true,
            _ => false,
        }
    }

    /// The driver ingested the items of the last frame: `new` of them were
    /// new to the set, and these envelope ids were refused for reasons
    /// intrinsic to the item (they will never be accepted).
    pub fn ingested(&mut self, new: u64, refused: &[EnvelopeId]) {
        self.ingested_new += new;
        for id in refused {
            if self.refused_here.len() < 4096 {
                self.refused_here.push(*id);
            }
        }
    }

    /// Stop now (the driver's budget ran out, or it is shutting down).
    pub fn abort(&mut self, reason: AbortReason) {
        if self.outcome.is_none() {
            self.outbox.push_back(Msg::Abort { reason });
            self.outcome = Some(Outcome::Aborted { reason, by_peer: false });
        }
    }

    /// The next frame to send, if any.
    pub fn poll_send(&mut self, set: &S) -> Option<Msg<S::Op, S::Env>> {
        let msg = self.next_frame(set)?;
        let len = frame_len(&msg) as u64;
        self.stats.sent_bytes += len;
        self.stats.sent_frames += 1;
        match &msg {
            Msg::Ops(v) => {
                self.stats.items_out += v.len() as u64;
                self.stats.sent_data_bytes += len;
            }
            Msg::Chunk(v) => {
                self.stats.items_out += v.len() as u64;
                self.stats.sent_data_bytes += len;
            }
            Msg::Probe { .. } => self.stats.probes_sent += 1,
            _ => {}
        }
        if self.stats.sent_data_bytes > self.cfg.send_budget {
            self.abort(AbortReason::Budget);
        }
        Some(msg)
    }

    fn next_frame(&mut self, set: &S) -> Option<Msg<S::Op, S::Env>> {
        if let Some(m) = self.outbox.pop_front() {
            return Some(m);
        }
        if self.outcome.is_some() || !self.planned || self.sends_done {
            return None;
        }
        if let Some(frame) = self.data_frame(set) {
            return Some(frame);
        }
        if !self.probes.is_empty() {
            return None; // waiting for probe replies
        }
        self.sends_done = true;
        let phase = self.phase;
        self.check_phase_end(set);
        // (a phase change may have queued frames; they follow SendsDone)
        Some(Msg::SendsDone { phase })
    }

    fn data_frame(&mut self, set: &S) -> Option<Msg<S::Op, S::Env>> {
        let budget = self.cfg.chunk_bytes;
        if !self.ops_q.is_empty() {
            let mut ops = Vec::new();
            let mut bytes = 0;
            while let Some(id) = self.ops_q.front().copied() {
                let Some(op) = set.op(&id) else {
                    self.ops_q.pop_front();
                    continue;
                };
                let len = encoded_len(&op);
                if !ops.is_empty() && bytes + len > budget {
                    break;
                }
                self.ops_q.pop_front();
                bytes += len;
                ops.push(op);
            }
            if !ops.is_empty() {
                return Some(Msg::Ops(ops));
            }
        }
        let mut envs = Vec::new();
        let mut bytes = 0;
        while bytes < budget {
            let Some(id) = self.jobs.pop() else { break };
            if let Some(env) = set.env(&id) {
                bytes += encoded_len(&env);
                envs.push(env);
            }
        }
        (!envs.is_empty()).then_some(Msg::Chunk(envs))
    }

    /// A frame from the peer. Returns the items to ingest.
    pub fn on_msg(&mut self, set: &S, msg: Msg<S::Op, S::Env>) -> Result<Received<S::Op, S::Env>, SessionError> {
        let len = frame_len(&msg) as u64;
        self.stats.recv_bytes += len;
        self.stats.recv_frames += 1;
        if self.outcome.is_some() {
            return Ok(Received::default());
        }
        match msg {
            Msg::Open(_) => Err(SessionError::Unexpected("Open")),
            Msg::Status(v) => {
                if self.role != Role::Client || self.status_seen {
                    return Err(SessionError::Unexpected("Status"));
                }
                self.status_seen = true;
                self.on_status(set, v)?;
                Ok(Received::default())
            }
            Msg::Frontier(f) => {
                if self.phase != 1 || self.peer.is_some() {
                    return Err(SessionError::Unexpected("Frontier"));
                }
                if self.rx.is_none() && f.delta_of.is_some() && f.delta_of == self.discard {
                    return Ok(Received::default()); // the rest of a delta we couldn't use
                }
                self.on_frontier_chunk(f)?;
                self.try_start(set);
                Ok(Received::default())
            }
            Msg::Ops(ops) => {
                self.data_allowed(len)?;
                self.stats.items_in += ops.len() as u64;
                Ok(Received { ops, envelopes: Vec::new() })
            }
            Msg::Chunk(envelopes) => {
                self.data_allowed(len)?;
                self.stats.items_in += envelopes.len() as u64;
                Ok(Received { ops: Vec::new(), envelopes })
            }
            Msg::Probe { author, run, points } => {
                if self.phase != 2 {
                    return Err(SessionError::Unexpected("Probe"));
                }
                if points.len() > PROBE_POINTS {
                    return Err(SessionError::Limit("probe points"));
                }
                self.probes_answered += 1;
                if self.probes_answered > self.cfg.max_probe_runs * (self.cfg.max_probe_rounds as usize + 1) {
                    return Err(SessionError::Limit("probes"));
                }
                let mut held = 0u16;
                let mut bottoms = Vec::new();
                for (i, (_, id)) in points.iter().enumerate() {
                    if let Some(b) = set.index().bottom(id) {
                        held |= 1 << i;
                        bottoms.push(b);
                    }
                }
                self.outbox.push_back(Msg::ProbeReply { author, run, held, bottoms });
                Ok(Received::default())
            }
            Msg::ProbeReply { author, run, held, bottoms } => {
                if bottoms.len() > PROBE_POINTS {
                    return Err(SessionError::Limit("probe reply"));
                }
                self.on_probe_reply(set, author, run, held, bottoms)?;
                Ok(Received::default())
            }
            Msg::SendsDone { phase } => {
                if phase != self.phase || self.peer_sends_done || self.peer.is_none() {
                    return Err(SessionError::Unexpected("SendsDone"));
                }
                self.peer_sends_done = true;
                let coverage = self.coverage(set);
                let quiet = set.count().saturating_sub(self.count_open) == self.ingested_new && !self.incomplete;
                let phase2 = self.cfg.allow_phase2;
                let refused: Vec<EnvelopeId> = self.refused_here.iter().take(64).copied().collect();
                let digest = set.digest();
                self.my_close = Some(CloseInfo { coverage: coverage.clone(), digest, quiet, phase2 });
                self.outbox.push_back(Msg::Close { phase, coverage, refused, digest, quiet, phase2 });
                self.check_phase_end(set);
                Ok(Received::default())
            }
            Msg::Close { phase, coverage, refused, digest, quiet, phase2 } => {
                if phase != self.phase || self.peer_close.is_some() || self.peer.is_none() {
                    return Err(SessionError::Unexpected("Close"));
                }
                if refused.len() > 64 {
                    return Err(SessionError::Limit("refused ids"));
                }
                if let Coverage::Missing { authors, .. } = &coverage
                    && authors.len() > self.mine.authors.len()
                {
                    return Err(SessionError::Malformed("coverage names unknown authors"));
                }
                self.refused_by_peer.extend(refused);
                self.peer_close = Some(CloseInfo { coverage, digest, quiet, phase2 });
                self.check_phase_end(set);
                Ok(Received::default())
            }
            Msg::Abort { reason } => {
                self.outcome = Some(Outcome::Aborted { reason, by_peer: true });
                Ok(Received::default())
            }
        }
    }

    fn data_allowed(&mut self, len: u64) -> Result<(), SessionError> {
        if self.phase == 0 {
            return Err(SessionError::Unexpected("data before the frontiers"));
        }
        self.stats.recv_data_bytes += len;
        if self.stats.recv_data_bytes > self.cfg.recv_budget {
            return Err(SessionError::Limit("received data"));
        }
        Ok(())
    }

    fn on_status(&mut self, set: &S, v: Verdict<S::Op>) -> Result<(), SessionError> {
        match v {
            Verdict::InSync { digest } => {
                if digest != self.my_digest {
                    // Our set changed after Open (a concurrent arrival): fine,
                    // but the refreshed record would name the wrong set.
                    self.outcome = Some(Outcome::InSync);
                    return Ok(());
                }
                self.record_out = Some(self.refreshed_record());
                self.outcome = Some(Outcome::InSync);
            }
            Verdict::Unchanged { .. } => self.outcome = Some(Outcome::Unchanged),
            Verdict::Diff { frontier, need_full, .. } => {
                self.phase = 1;
                self.stats.phase = 1;
                if frontier.delta_of.is_some() && frontier.delta_of != self.record.as_ref().map(|r| r.name) {
                    return Err(SessionError::Malformed("delta against a record we didn't name"));
                }
                if need_full {
                    // Our delta (or nothing) wasn't usable: send everything.
                    self.outbox.extend(self.mine.chunks(None).into_iter().map(Msg::Frontier));
                }
                self.on_frontier_chunk(frontier)?;
                self.try_start(set);
            }
            Verdict::NeedInvite => self.outcome = Some(Outcome::Refused(Refusal::NeedInvite)),
            Verdict::Denied => self.outcome = Some(Outcome::Refused(Refusal::Denied)),
            Verdict::Removed { .. } => self.outcome = Some(Outcome::Refused(Refusal::Removed)),
            Verdict::Unsupported { .. } => self.outcome = Some(Outcome::Refused(Refusal::Unsupported)),
            Verdict::Busy { retry_after_ms } => self.outcome = Some(Outcome::Refused(Refusal::Busy { retry_after_ms })),
        }
        Ok(())
    }

    fn on_frontier_chunk(&mut self, f: Frontier) -> Result<(), SessionError> {
        let rx = self.rx.get_or_insert_with(|| FrontierRx {
            delta_of: f.delta_of,
            ops: None,
            authors: Vec::new(),
            runs: 0,
            done: false,
        });
        if rx.done || rx.delta_of != f.delta_of {
            return Err(SessionError::Malformed("frontier chunks"));
        }
        if let Some(ops) = f.ops {
            if rx.ops.is_some() || ops.len() > MAX_OP_TIPS {
                return Err(SessionError::Limit("op tips"));
            }
            rx.ops = Some(ops);
        }
        if f.authors.len() > FRONTIER_CHUNK_AUTHORS
            || rx.authors.len() + f.authors.len() > self.cfg.max_frontier_authors
        {
            return Err(SessionError::Limit("frontier authors"));
        }
        if f.authors.iter().any(|e| e.runs.len() > MAX_RUNS_INLINE || e.runs.is_empty()) {
            return Err(SessionError::Limit("runs per author"));
        }
        if f.authors.iter().any(|e| e.runs.iter().any(|r| r.bottom > r.top)) {
            return Err(SessionError::Malformed("run bottom above its top"));
        }
        rx.runs += f.authors.iter().map(|e| e.runs.len()).sum::<usize>();
        if rx.runs > self.cfg.max_frontier_runs {
            return Err(SessionError::Limit("frontier runs"));
        }
        rx.authors.extend(f.authors);
        rx.done = !f.more;
        if rx.done {
            self.resolve_frontier()?;
        }
        Ok(())
    }

    /// The assembled frontier, applied to its base.
    fn resolve_frontier(&mut self) -> Result<(), SessionError> {
        let Some(rx) = self.rx.as_mut() else { return Ok(()) };
        let (ops, mut authors) = match rx.delta_of {
            None => (rx.ops.take().ok_or(SessionError::Malformed("full frontier without op tips"))?, BTreeMap::new()),
            Some(name) => {
                let base = match &self.record {
                    Some(r) if r.name == name => &r.peer,
                    _ => return Err(SessionError::Malformed("delta against an unknown record")),
                };
                (rx.ops.take().unwrap_or_else(|| base.ops.clone()), (*base.authors).clone())
            }
        };
        for e in std::mem::take(&mut rx.authors) {
            authors.insert(e.author, e);
        }
        if authors.len() > self.cfg.max_frontier_authors {
            return Err(SessionError::Limit("frontier authors"));
        }
        self.peer = Some(Summary { ops, authors: Arc::new(authors) });
        Ok(())
    }

    /// Both frontiers known: plan phase 1.
    fn try_start(&mut self, set: &S) {
        if self.phase == 1 && !self.planned && self.peer.is_some() && self.outcome.is_none() {
            self.plan(set);
        }
    }

    /// Compute what this side owes for the current phase.
    fn plan(&mut self, set: &S) {
        self.planned = true;
        let Some(peer) = self.peer.clone() else { return };
        let idx = set.index();
        // Ops: those not in the past of the peer's tips that I hold. When I
        // lack some tips (concurrent membership changes on both sides) this
        // over-sends what lies in their past, a superset bounded by the op
        // count (ops are small and rare), but it never waits for phase 2.
        let held: Vec<OpId> = peer.ops.iter().filter(|t| set.holds_op(t)).copied().collect();
        for id in set.ops_after(&held) {
            if self.queued_ops.insert(id) {
                self.ops_q.push_back(id);
            }
        }
        let empty = AuthorEntry { author: SignPk([0; 32]), runs: Vec::new(), truncated: None };
        let mine = idx.entries();
        let mut undecided = Vec::new();
        let mut pairs = self.cfg.max_place_pairs;
        let mut flood_work = self.cfg.max_flood_steps;
        for (author, entry) in mine.iter() {
            let theirs = peer.authors.get(author).unwrap_or(&empty);
            if entry.truncated.is_some() && entry.truncated == theirs.truncated {
                continue; // the same chains, committed to in full
            }
            let runs = match entry.truncated {
                None => entry.runs.clone(),
                Some(_) => {
                    // A flood: start at a point that varies per session and
                    // phase, so a capped placement reaches every run in time.
                    let mut all = idx.runs(author);
                    let h =
                        Hash32::digest("mycel/v2/sync-rotate", &[&self.nonce[..], &author.0, &[self.phase]].concat());
                    let at = (u64::from_le_bytes(h.0[..8].try_into().unwrap_or_default()) % all.len().max(1) as u64)
                        as usize;
                    all.rotate_left(at);
                    all
                }
            };
            let exact: HashMap<EnvelopeId, u64> = theirs.runs.iter().map(|p| (p.head, p.bottom)).collect();
            let mut owed = Vec::new();
            if entry.truncated.is_some() || theirs.truncated.is_some() {
                self.plan_flood(idx, &runs, theirs, &exact, &mut flood_work, &mut owed);
            } else {
                for r in runs {
                    if exact.get(&r.head).is_some_and(|b| *b <= r.bottom) {
                        continue; // the peer holds this run
                    }
                    // (at most MAX_RUNS_INLINE² pairs per author here)
                    let cost = theirs.runs.len();
                    if cost > pairs {
                        self.incomplete = true;
                        break;
                    }
                    pairs -= cost;
                    match self.uncovered(set, &r, theirs, None) {
                        Some(intervals) => {
                            for (lo, hi) in intervals {
                                self.queue_branch(idx, &r.head, lo, hi, &mut owed);
                            }
                        }
                        None => undecided.push((*author, r)),
                    }
                }
            }
            // One job per author in ascending seq, so a fork's envelopes
            // never overtake the prefix the receiver's window waits for.
            owed.sort_unstable();
            self.jobs.push(owed.into_iter().map(|(_, id)| id).collect());
        }
        if self.phase == 2 {
            for (author, run) in undecided {
                if self.probes.len() >= self.cfg.max_probe_runs {
                    break;
                }
                self.start_probe(set, author, run, &peer);
            }
        }
    }

    /// Place a flooded author's runs (more than [`MAX_RUNS_INLINE`] heads on
    /// either side) in time linear in what the peer's listed heads cover,
    /// not in pairs of runs. Each envelope on the branch of a listed peer
    /// head I hold is marked once with the lowest bottom the peer holds it
    /// down to; each of my runs then walks down to its first marked
    /// envelope. Peer heads I don't hold are ignored rather than probed
    /// (probing reaches only a few of many runs per session): this may
    /// over-send the part of a run the peer holds below such a head, never
    /// under-send. Stops at `work` steps; the rest waits for a later
    /// session, whose rotated run order reaches it.
    fn plan_flood(
        &mut self,
        idx: &ChainIndex,
        runs: &[Run],
        theirs: &AuthorEntry,
        exact: &HashMap<EnvelopeId, u64>,
        work: &mut usize,
        owed: &mut Vec<(u64, EnvelopeId)>,
    ) {
        let mut marks: HashMap<EnvelopeId, u64> = HashMap::new();
        for p in theirs.runs.iter().filter(|p| idx.holds(&p.head)) {
            let mut cur = Some(p.head);
            while let Some(id) = cur {
                if marks.get(&id).is_some_and(|b| *b <= p.bottom) {
                    break;
                }
                if *work == 0 {
                    self.incomplete = true;
                    return;
                }
                *work -= 1;
                let b = marks.get(&id).map_or(p.bottom, |b| (*b).min(p.bottom));
                marks.insert(id, b);
                if idx.seq(&id).is_none_or(|s| s <= p.bottom) {
                    break;
                }
                cur = idx.parent(&id);
            }
        }
        for r in runs {
            if exact.get(&r.head).is_some_and(|b| *b <= r.bottom) {
                continue;
            }
            // Walk down to the first envelope the peer holds (each envelope
            // is walked about once: queued stretches are skipped).
            let mut cur = Some(r.head);
            let mut seq = r.top;
            let mut met = None;
            while let Some(id) = cur {
                if let Some(b) = marks.get(&id) {
                    met = Some((seq, *b));
                    break;
                }
                // Queued already, down to `floor`: skip that stretch.
                if let Some(floor) = self.queued.get(&id).copied() {
                    if floor <= r.bottom {
                        break;
                    }
                    seq = floor - 1;
                    cur = idx.branch_id_at(&id, seq);
                    continue;
                }
                if *work == 0 {
                    self.incomplete = true;
                    return;
                }
                *work -= 1;
                if seq <= r.bottom {
                    break;
                }
                seq -= 1;
                cur = idx.parent(&id);
            }
            let (above, below) = match met {
                Some((m, b)) => (m + 1, b),
                None => (r.bottom, r.bottom),
            };
            self.queue_branch(idx, &r.head, above, r.top, owed);
            if below > r.bottom {
                self.queue_branch(idx, &r.head, r.bottom, below - 1, owed);
            }
        }
    }

    /// Queue the envelopes of the branch ending at `head` in `lo..=hi`
    /// (into `out` as (seq, id)), skipping the ones already queued: the walk
    /// stops at an envelope whose branch is queued down to `lo`, so each
    /// envelope is visited about once however many runs share it.
    fn queue_branch(
        &mut self,
        idx: &ChainIndex,
        head: &EnvelopeId,
        lo: u64,
        hi: u64,
        out: &mut Vec<(u64, EnvelopeId)>,
    ) {
        if lo > hi {
            return;
        }
        let mut seq = hi;
        let mut cur = idx.branch_id_at(head, hi);
        while let Some(id) = cur {
            if let Some(floor) = self.queued.get(&id).copied() {
                if floor <= lo {
                    break;
                }
                seq = floor - 1;
                cur = idx.branch_id_at(&id, seq);
                continue;
            }
            self.queued.insert(id, lo);
            if !self.refused_by_peer.contains(&id) {
                out.push((seq, id));
            }
            if seq <= lo {
                break;
            }
            seq -= 1;
            cur = idx.parent(&id);
        }
    }

    /// The seq intervals of my run `r` that the peer's entry shows it lacks,
    /// or `None` if the entry can't decide (a peer head I don't hold that
    /// overlaps the run). `probed`: after probing, the intervals of `r` the
    /// peer is known to hold (empty for a flood); peer heads I don't hold
    /// then add nothing.
    fn uncovered(
        &self,
        set: &S,
        r: &Run,
        theirs: &AuthorEntry,
        probed: Option<&[(u64, u64)]>,
    ) -> Option<Vec<(u64, u64)>> {
        let idx = set.index();
        let mut covered: Vec<(u64, u64)> = probed.map(|c| c.to_vec()).unwrap_or_default();
        for p in &theirs.runs {
            if p.head == r.head {
                covered.push((p.bottom.max(r.bottom), r.top));
            } else if idx.holds(&p.head) {
                let lo = p.bottom.max(r.bottom);
                if idx.is_ancestor(&p.head, &r.head) {
                    covered.push((lo, p.top));
                } else if let Some(f) = idx.fork_point(&p.head, &r.head)
                    && f >= lo
                {
                    covered.push((lo, f));
                }
            } else if p.top >= r.bottom && probed.is_none() {
                return None;
            }
        }
        covered.sort_unstable();
        let mut out = Vec::new();
        let mut next = r.bottom;
        for (lo, hi) in covered {
            let lo = lo.max(r.bottom);
            if lo > next {
                out.push((next, lo - 1));
            }
            next = next.max(hi.saturating_add(1));
        }
        if next <= r.top {
            out.push((next, r.top));
        }
        Some(out)
    }

    /// Do I cover the peer's opening frontier?
    fn coverage(&self, set: &S) -> Coverage {
        let Some(peer) = &self.peer else { return Coverage::All };
        let idx = set.index();
        let ops = peer.ops.iter().any(|t| !set.holds_op(t));
        let mut refused: HashSet<&EnvelopeId> = self.refused_here.iter().collect();
        if let Some(r) = &self.record {
            refused.extend(r.i_refused.iter());
        }
        let authors: Vec<SignPk> = peer
            .authors
            .values()
            .filter(|e| {
                e.runs.iter().any(|p| {
                    let held = idx.bottom(&p.head).is_some_and(|b| b <= p.bottom)
                        || idx.gap_below(&p.head).is_some_and(|m| refused.contains(&m));
                    !held && !refused.contains(&p.head)
                })
            })
            .map(|e| e.author)
            .collect();
        if !ops && authors.is_empty() { Coverage::All } else { Coverage::Missing { ops, authors } }
    }

    fn check_phase_end(&mut self, set: &S) {
        if !(self.sends_done && self.peer_sends_done) || self.outcome.is_some() {
            return;
        }
        let (Some(mine), Some(theirs)) = (self.my_close.clone(), self.peer_close.clone()) else { return };
        let all = mine.coverage == Coverage::All && theirs.coverage == Coverage::All;
        if all {
            self.outcome = Some(Outcome::Converged { phase: self.phase, moved: self.ingested_new > 0 });
            let name = match self.role {
                Role::Client => (mine.digest, theirs.digest),
                Role::Server => (theirs.digest, mine.digest),
            };
            let mut refused: HashSet<EnvelopeId> =
                self.record.as_ref().map(|r| (*r.refused).clone()).unwrap_or_default();
            refused.extend(self.refused_by_peer.iter().copied());
            if refused.len() > 4096 {
                refused = refused.into_iter().take(4096).collect();
            }
            let mut i_refused: HashSet<EnvelopeId> =
                self.record.as_ref().map(|r| (*r.i_refused).clone()).unwrap_or_default();
            i_refused.extend(self.refused_here.iter().copied());
            if i_refused.len() > 4096 {
                i_refused = i_refused.into_iter().take(4096).collect();
            }
            self.record_out = self.peer.clone().map(|peer| PeerRecord {
                name,
                mine: self.mine.clone(),
                peer,
                quiet: mine.quiet && theirs.quiet,
                my_close: mine.digest,
                peer_close: theirs.digest,
                refused: Arc::new(refused),
                i_refused: Arc::new(i_refused),
            });
            return;
        }
        if self.phase == 1 && mine.phase2 && theirs.phase2 {
            self.phase = 2;
            self.stats.phase = 2;
            self.sends_done = false;
            self.peer_sends_done = false;
            self.my_close = None;
            self.peer_close = None;
            self.plan(set);
            return;
        }
        let (ops, mut authors) = match mine.coverage {
            Coverage::All => (false, Vec::new()),
            Coverage::Missing { ops, authors } => (ops, authors),
        };
        if let Coverage::Missing { ops: o, authors: a } = theirs.coverage {
            authors.extend(a);
            authors.sort();
            authors.dedup();
            self.outcome = Some(Outcome::Unconverged { phase: self.phase, ops: ops || o, authors });
        } else {
            self.outcome = Some(Outcome::Unconverged { phase: self.phase, ops, authors });
        }
    }

    // ───────────── phase 2: probing ─────────────

    fn start_probe(&mut self, set: &S, author: SignPk, run: Run, peer: &Summary) {
        let top = peer.top(&author).unwrap_or(0).min(run.top).max(run.bottom);
        let mut p =
            Probe { run, author, held: None, unheld: top + 1, rounds: 0, asked: Vec::new(), covered: Vec::new() };
        // Gallop down from the tip: top, top-1, top-2, top-4, ... and the bottom.
        let mut seqs = Vec::new();
        let mut step = 1u64;
        let mut s = top;
        loop {
            seqs.push(s);
            if s == run.bottom || seqs.len() == PROBE_POINTS - 1 {
                break;
            }
            s = s.saturating_sub(step).max(run.bottom);
            step = step.saturating_mul(2);
        }
        if *seqs.last().unwrap_or(&run.bottom) != run.bottom {
            seqs.push(run.bottom);
        }
        self.ask(set, &mut p, seqs);
        self.probes.insert(run.head, p);
    }

    fn ask(&mut self, set: &S, p: &mut Probe, seqs: Vec<u64>) {
        let idx = set.index();
        p.asked = seqs.into_iter().filter_map(|s| idx.branch_id_at(&p.run.head, s).map(|id| (s, id))).collect();
        p.rounds += 1;
        self.outbox.push_back(Msg::Probe { author: p.author, run: p.run.head, points: p.asked.clone() });
    }

    fn on_probe_reply(
        &mut self,
        set: &S,
        author: SignPk,
        run: EnvelopeId,
        held: u16,
        bottoms: Vec<u64>,
    ) -> Result<(), SessionError> {
        let Some(mut p) = self.probes.remove(&run) else {
            return Err(SessionError::Unexpected("ProbeReply"));
        };
        if p.author != author || p.asked.is_empty() {
            return Err(SessionError::Unexpected("ProbeReply"));
        }
        let held = held & (((1u32 << p.asked.len()) - 1) as u16);
        if bottoms.len() != held.count_ones() as usize {
            return Err(SessionError::Malformed("probe reply bottoms"));
        }
        let mut bottoms = bottoms.into_iter();
        for (i, (s, _)) in p.asked.iter().enumerate() {
            if held & (1 << i) != 0 {
                // The peer holds my branch from its bottom of this id up to it
                // (the id commits to the chain below it).
                let b = bottoms.next().unwrap_or(*s).min(*s);
                p.covered.push((b, *s));
                p.held = Some(p.held.map_or(*s, |h| h.max(*s)));
            }
        }
        for (i, (s, _)) in p.asked.iter().enumerate() {
            if held & (1 << i) == 0 && p.held.is_none_or(|h| *s > h) {
                p.unheld = p.unheld.min(*s);
            }
        }
        p.asked.clear();
        let lo = p.held.map_or(p.run.bottom, |h| h + 1);
        let placed = match p.held {
            None => p.unheld <= p.run.bottom,
            Some(h) => h + 1 >= p.unheld,
        };
        if !placed && p.rounds < self.cfg.max_probe_rounds && lo < p.unheld {
            // Bisect between the highest held and the lowest unheld seq.
            let hi = p.unheld - 1;
            let n = (hi - lo + 1).min(PROBE_POINTS as u64);
            let seqs: Vec<u64> = (0..n).map(|i| lo + i * (hi - lo + 1) / n).collect();
            self.ask(set, &mut p, seqs);
            self.probes.insert(run, p);
            return Ok(());
        }
        // Placed: send the run minus what the peer is known to hold (from
        // the probes, and from its heads that I hold).
        let empty = AuthorEntry { author, runs: Vec::new(), truncated: None };
        let peer = self.peer.clone().unwrap_or_default();
        let theirs = peer.authors.get(&author).unwrap_or(&empty);
        let intervals = self.uncovered(set, &p.run, theirs, Some(&p.covered)).unwrap_or_default();
        let mut owed = Vec::new();
        for (lo, hi) in intervals {
            self.queue_branch(set.index(), &p.run.head, lo, hi, &mut owed);
        }
        owed.sort_unstable();
        self.jobs.push(owed.into_iter().map(|(_, id)| id).collect());
        Ok(())
    }
}
