//! A synthetic [`SyncSet`] (no signatures, no encryption) and an in-memory
//! driver for two sessions, for tests, benchmarks and the simulator.
//!
//! Model items are encoded with postcard like real ones, and envelopes can
//! carry a body padded to a realistic size, so byte counts are comparable
//! to a replica's. Authorisation is modelled by an allow-list of authors:
//! items from other authors are refused on ingest, as `Replica` refuses
//! envelopes from keys never added to the space.

use std::collections::{HashMap, HashSet};

use mycel_crypto::{Hash32, SignPk};
use mycel_trust::{OpId, SpaceId};
use serde::{Deserialize, Serialize};

use super::{ChainIndex, Config, Msg, Outcome, PeerRecord, Received, Session, SessionStats, SyncSet};
use crate::EnvelopeId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelOp {
    pub parents: Vec<OpId>,
    pub nonce: u64,
}

impl ModelOp {
    pub fn id(&self) -> OpId {
        Hash32::digest("mycel/model/op", &postcard::to_allocvec(self).unwrap_or_default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEnv {
    pub author: SignPk,
    pub seq: u64,
    pub prev: Option<EnvelopeId>,
    /// Distinguishes forks at the same seq.
    pub branch: u32,
    pub body: Vec<u8>,
}

impl ModelEnv {
    pub fn id(&self) -> EnvelopeId {
        Hash32::digest("mycel/model/env", &postcard::to_allocvec(self).unwrap_or_default())
    }
}

/// See the module docs.
pub struct ModelSet {
    pub space: SpaceId,
    ops: HashMap<OpId, ModelOp>,
    /// Resolved ops, parents first.
    order: Vec<OpId>,
    pending_ops: HashMap<OpId, ModelOp>,
    envs: HashMap<EnvelopeId, ModelEnv>,
    index: ChainIndex,
    /// Authors whose envelopes are accepted (`None`: everyone).
    pub allowed: Option<HashSet<SignPk>>,
    /// Envelopes refused for reasons intrinsic to them (as an over-limit or
    /// undecodable item is): reported to the session as refused.
    pub refuse: HashSet<EnvelopeId>,
}

impl ModelSet {
    pub fn new(space: SpaceId) -> Self {
        let mut s = ModelSet {
            space,
            ops: HashMap::new(),
            order: Vec::new(),
            pending_ops: HashMap::new(),
            envs: HashMap::new(),
            index: ChainIndex::default(),
            allowed: None,
            refuse: HashSet::new(),
        };
        s.insert_op(ModelOp { parents: Vec::new(), nonce: 0 });
        s
    }

    /// Add an op: resolved if every parent is, pending otherwise. Returns
    /// true if it was new.
    pub fn insert_op(&mut self, op: ModelOp) -> bool {
        let id = op.id();
        if self.ops.contains_key(&id) || self.pending_ops.contains_key(&id) {
            return false;
        }
        if op.parents.iter().all(|p| self.ops.contains_key(p)) {
            self.ops.insert(id, op);
            self.order.push(id);
            loop {
                let ready: Vec<OpId> = self
                    .pending_ops
                    .iter()
                    .filter(|(_, o)| o.parents.iter().all(|p| self.ops.contains_key(p)))
                    .map(|(id, _)| *id)
                    .collect();
                if ready.is_empty() {
                    break;
                }
                for r in ready {
                    let o = self.pending_ops.remove(&r).unwrap_or_else(|| unreachable!());
                    self.ops.insert(r, o);
                    self.order.push(r);
                }
            }
        } else {
            self.pending_ops.insert(id, op);
        }
        true
    }

    /// Add an envelope if its author is allowed and it is within the
    /// window. `Ok(true)`: new; `Ok(false)`: already held.
    pub fn insert_env(&mut self, env: ModelEnv) -> Result<bool, &'static str> {
        if self.allowed.as_ref().is_some_and(|a| !a.contains(&env.author)) {
            return Err("author not allowed");
        }
        if self.refuse.contains(&env.id()) {
            return Err("refused");
        }
        if !self.index.within_window(&env.author, env.seq) {
            return Err("beyond the window");
        }
        let id = env.id();
        if self.envs.contains_key(&id) {
            return Ok(false);
        }
        self.index.insert(id, env.author, env.seq, env.prev);
        self.envs.insert(id, env);
        Ok(true)
    }

    /// Append `n` envelopes to `author`'s chain (its highest branch-0 head),
    /// each with a `body_len`-byte body.
    pub fn append(&mut self, author: SignPk, n: u64, body_len: usize) -> Vec<EnvelopeId> {
        let (mut seq, mut prev) = match self.index.recent(&author, 1).first() {
            Some(id) => (self.envs[id].seq + 1, Some(*id)),
            None => (0, None),
        };
        let mut out = Vec::new();
        for _ in 0..n {
            let env = ModelEnv { author, seq, prev, branch: 0, body: vec![0x5a; body_len] };
            let id = env.id();
            self.insert_env(env).expect("own chain within the window");
            out.push(id);
            prev = Some(id);
            seq += 1;
        }
        out
    }

    /// Write a branch of `n` envelopes on top of `base` (an envelope of
    /// `author`, or `None` for a chain from seq 0), tagged `branch`.
    pub fn fork(&mut self, author: SignPk, base: Option<EnvelopeId>, n: u64, branch: u32) -> Vec<EnvelopeId> {
        let first = base.map_or(0, |b| self.envs[&b].seq + 1);
        let mut prev = base;
        let mut out = Vec::new();
        for seq in first..first + n {
            let env = ModelEnv { author, seq, prev, branch, body: vec![branch as u8; 16] };
            let id = env.id();
            let _ = self.insert_env(env);
            out.push(id);
            prev = Some(id);
        }
        out
    }

    pub fn env_ids(&self) -> HashSet<EnvelopeId> {
        self.envs.keys().copied().collect()
    }

    pub fn op_ids(&self) -> HashSet<OpId> {
        self.ops.keys().copied().collect()
    }

    pub fn envelope(&self, id: &EnvelopeId) -> Option<&ModelEnv> {
        self.envs.get(id)
    }

    /// Every envelope and resolved op, for building another set.
    pub fn all(&self) -> (Vec<ModelOp>, Vec<ModelEnv>) {
        (self.order.iter().map(|id| self.ops[id].clone()).collect(), self.envs.values().cloned().collect())
    }

    pub fn tip_op(&self) -> OpId {
        *self.order.last().unwrap_or(&self.space)
    }
}

impl SyncSet for ModelSet {
    type Op = ModelOp;
    type Env = ModelEnv;

    fn space(&self) -> SpaceId {
        self.space
    }

    fn index(&self) -> &ChainIndex {
        &self.index
    }

    fn op_tips(&self) -> Vec<OpId> {
        let parents: HashSet<&OpId> = self.ops.values().flat_map(|o| o.parents.iter()).collect();
        let mut tips: Vec<OpId> = self.ops.keys().filter(|id| !parents.contains(id)).copied().collect();
        tips.sort();
        tips
    }

    fn holds_op(&self, id: &OpId) -> bool {
        self.ops.contains_key(id)
    }

    fn ops_after(&self, heads: &[OpId]) -> Vec<OpId> {
        let mut past: HashSet<OpId> = HashSet::new();
        let mut stack: Vec<OpId> = heads.to_vec();
        while let Some(id) = stack.pop() {
            if past.insert(id)
                && let Some(op) = self.ops.get(&id)
            {
                stack.extend(op.parents.iter().copied());
            }
        }
        self.order.iter().filter(|id| !past.contains(id)).copied().collect()
    }

    fn op_count(&self) -> u64 {
        self.ops.len() as u64
    }

    fn op(&self, id: &OpId) -> Option<ModelOp> {
        self.ops.get(id).cloned()
    }

    fn env(&self, id: &EnvelopeId) -> Option<ModelEnv> {
        self.envs.get(id).cloned()
    }
}

/// A set a driver can ingest received items into.
pub trait Apply: SyncSet {
    /// Ingest; returns (received items new to the set, envelope ids refused
    /// for good). Items the set gains as a side effect (a pending op whose
    /// parent arrived) are not counted: they make the session not quiet.
    fn apply(&mut self, items: Received<Self::Op, Self::Env>) -> (u64, Vec<EnvelopeId>);
}

impl Apply for ModelSet {
    fn apply(&mut self, items: Received<ModelOp, ModelEnv>) -> (u64, Vec<EnvelopeId>) {
        let ops: Vec<OpId> = items.ops.iter().map(|o| o.id()).filter(|id| !self.holds_op(id)).collect();
        let env_ids: Vec<EnvelopeId> =
            items.envelopes.iter().map(|e| e.id()).filter(|id| !self.index.holds(id)).collect();
        for op in items.ops {
            self.insert_op(op);
        }
        let mut envs = items.envelopes;
        envs.sort_by_key(|e| (e.author, e.seq));
        let mut refused = Vec::new();
        for env in envs {
            let id = env.id();
            if let Err("refused") = self.insert_env(env) {
                refused.push(id);
            }
        }
        (super::gained(self, &ops, &env_ids), refused)
    }
}

impl Apply for crate::Replica {
    fn apply(&mut self, items: Received<mycel_trust::SignedOp, crate::Envelope>) -> (u64, Vec<EnvelopeId>) {
        let ops: Vec<OpId> = items.ops.iter().map(|o| o.id()).filter(|id| !self.holds_op(id)).collect();
        let env_ids: Vec<EnvelopeId> =
            items.envelopes.iter().map(|e| e.id()).filter(|id| !self.index.holds(id)).collect();
        let (_, refused) = self.ingest_batch_refused(items.ops, items.envelopes);
        (super::gained(self, &ops, &env_ids), refused)
    }
}

/// The result of [`run_pair`].
#[derive(Debug)]
pub struct PairRun {
    pub client: Outcome,
    pub server: Outcome,
    pub client_stats: SessionStats,
    pub server_stats: SessionStats,
    /// One-way flights until both sides were done (a round trip is two).
    pub flights: u32,
    /// Flights until the first data frame reached the client.
    pub first_data_flight: Option<u32>,
    pub client_record: Option<PeerRecord>,
    pub server_record: Option<PeerRecord>,
}

impl PairRun {
    /// Bytes on the stream, both directions.
    pub fn bytes(&self) -> u64 {
        self.client_stats.sent_bytes + self.server_stats.sent_bytes
    }

    pub fn round_trips(&self) -> f64 {
        self.flights as f64 / 2.0
    }
}

/// Run one session between `client` and `server` in memory. Each flight
/// delivers everything each side has queued to the other at once (both
/// directions in parallel, as on a real link), so `flights` counts one-way
/// latencies. `between` runs after every flight (to inject concurrent
/// arrivals); the whole exchange stops after `max_flights`.
pub fn run_pair<S: Apply>(
    client: &mut S,
    server: &mut S,
    records: (Option<PeerRecord>, Option<PeerRecord>),
    cfg: Config,
    eager: bool,
    mut between: impl FnMut(u32, &mut S, &mut S),
) -> PairRun {
    let mut c = Session::open(client, cfg.clone(), [7; 16], records.0, eager, None);
    let mut s: Option<Session<S>> = None;
    let mut flights = 0;
    let mut first_data = None;
    let mut to_server: Vec<Msg<S::Op, S::Env>> = Vec::new();
    loop {
        while let Some(m) = c.poll_send(client) {
            to_server.push(m);
        }
        let mut to_client = Vec::new();
        if let Some(s) = s.as_mut() {
            while let Some(m) = s.poll_send(server) {
                to_client.push(m);
            }
        }
        let server_done = s.as_ref().is_some_and(|s| s.is_done());
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
        if c.is_done() && server_done && to_server.is_empty() && to_client.is_empty() {
            break;
        }
        flights += 1;
        if flights > 10_000 {
            break;
        }
        for m in std::mem::take(&mut to_server) {
            match (&mut s, m) {
                (None, Msg::Open(open)) => s = Some(Session::accept(server, cfg.clone(), open, records.1.clone())),
                (Some(sess), m) => match sess.on_msg(server, m) {
                    Ok(items) => {
                        let (new, refused) = server.apply(items);
                        sess.ingested(new, &refused);
                    }
                    Err(_) => sess.abort(super::AbortReason::Protocol),
                },
                (None, _) => {}
            }
        }
        for m in to_client {
            let data = matches!(m, Msg::Ops(_) | Msg::Chunk(_));
            match c.on_msg(client, m) {
                Ok(items) => {
                    if data && first_data.is_none() {
                        first_data = Some(flights);
                    }
                    let (new, refused) = client.apply(items);
                    c.ingested(new, &refused);
                }
                Err(_) => c.abort(super::AbortReason::Protocol),
            }
        }
        between(flights, client, server);
    }
    let (server_outcome, server_stats, server_record) = match &s {
        Some(s) => (s.outcome().cloned(), s.stats(), s.record().cloned()),
        None => (None, SessionStats::default(), None),
    };
    PairRun {
        client: c.outcome().cloned().unwrap_or(Outcome::Aborted { reason: super::AbortReason::Gone, by_peer: false }),
        server: server_outcome.unwrap_or(Outcome::Aborted { reason: super::AbortReason::Gone, by_peer: false }),
        client_stats: c.stats(),
        server_stats,
        flights,
        first_data_flight: first_data,
        client_record: c.record().cloned(),
        server_record,
    }
}
