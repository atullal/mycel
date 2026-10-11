//! Mycel data & sync v0 (docs/TRUST.md §7): signed, encrypted envelopes,
//! validated without decryption, materialized into **Docs** (Automerge) and
//! **Feeds** (append-only, causally ordered entries).
//!
//! A [`Replica`] is one device's view of one Space: the membership graph, the
//! device's keyring, every envelope it holds, and the streams it can decrypt.
//! Keepers run the same `Replica` with the Relay role: they validate and store
//! envelopes but hold no keys, so they never materialize anything.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use automerge::{ActorId, AutoCommit};
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, Sig, SignPk, random};
use mycel_trust::{EpochId, Inserted, Keyring, OpId, Role, SignedOp, SpaceGraph, SpaceId};
use serde::{Deserialize, Serialize};

pub use automerge;
pub use mycel_trust;

mod bounded_change;
mod change_resources;

pub type EnvelopeId = Hash32;

const CTX_ENV_SIG: &str = "mycel/v0/envelope";
const CTX_ENV_ID: &str = "mycel/v0/envelope-id";
const CTX_CONTENT_AAD: &str = "mycel/v0/content";

/// Envelopes carry small changes; large data goes through blobs.
pub const MAX_ENVELOPE_CIPHERTEXT: usize = 1024 * 1024;
/// Maximum serialized Automerge change size after decompression, including
/// its framing. All document writers and readers enforce this same limit.
pub const MAX_DOC_CHANGE_BYTES: usize = 1024 * 1024;
/// Interoperability limits for column encoding expansion within one change.
/// Larger edits must be split into multiple changes, even if highly compressible.
pub const MAX_DOC_CHANGE_OPS: usize = 65_536;
/// Shared count of logical column cells plus entries declared by group counts.
pub const MAX_DOC_COLUMN_VALUES: usize = 1_048_576;
/// Shared byte count of strings after expanding string-column runs.
pub const MAX_DOC_COLUMN_STRING_BYTES: usize = 1024 * 1024;
/// Max membership heads an envelope may reference (DoS hardening).
pub const MAX_AUTH_HEADS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("trust: {0}")]
    Trust(#[from] mycel_trust::TrustError),
    #[error("crypto: {0}")]
    Crypto(#[from] mycel_crypto::CryptoError),
    #[error("automerge: {0}")]
    Automerge(#[from] automerge::AutomergeError),
    #[error("envelope belongs to a different space")]
    WrongSpace,
    #[error("envelope too large")]
    TooLarge,
    #[error("encoding error")]
    Encoding,
    #[error("not allowed: {0}")]
    NotAllowed(&'static str),
}

pub type Result<T> = std::result::Result<T, SyncError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StreamKind {
    Doc,
    Feed,
}

/// A Doc or Feed inside a Space.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamId {
    pub kind: StreamKind,
    pub id: [u8; 16],
}

impl StreamId {
    pub fn new_doc() -> Self {
        StreamId { kind: StreamKind::Doc, id: random() }
    }
    pub fn new_feed() -> Self {
        StreamId { kind: StreamKind::Feed, id: random() }
    }
    /// A well-known stream derived from a name (e.g. a chat's "messages" feed).
    pub fn named(kind: StreamKind, name: &str) -> Self {
        let h = Hash32::digest("mycel/v0/named-stream", name.as_bytes());
        StreamId { kind, id: h.0[..16].try_into().unwrap() }
    }
}

impl std::fmt::Debug for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}:{:02x}{:02x}{:02x}", self.kind, self.id[0], self.id[1], self.id[2])
    }
}

/// Kept for API compatibility with phase 0: a doc stream id.
pub type DocId = StreamId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub space: SpaceId,
    pub stream: StreamId,
    pub author: SignPk,
    /// Per-author hash chain within the space.
    pub author_seq: u64,
    pub author_prev: Option<EnvelopeId>,
    /// Membership heads the author saw when writing.
    pub auth_heads: Vec<OpId>,
    pub epoch: EpochId,
    pub nonce: [u8; 24],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub sig: Sig,
}

/// Plaintext of a Feed envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// Feed entries the author had seen (causal order).
    pub deps: Vec<EnvelopeId>,
    /// Author's wall clock, ms since epoch. Display/tie-break only.
    pub ts_ms: u64,
    pub body: Vec<u8>,
}

/// A decrypted, valid feed entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedItem {
    pub id: EnvelopeId,
    pub author: SignPk,
    /// The author's role as of the membership state they wrote against.
    pub author_role: Role,
    pub ts_ms: u64,
    pub deps: Vec<EnvelopeId>,
    pub body: Vec<u8>,
}

fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).expect("encodes")
}

fn content_aad(header: &Header) -> Vec<u8> {
    [CTX_CONTENT_AAD.as_bytes(), &encode(header)].concat()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Envelope {
    pub fn id(&self) -> EnvelopeId {
        Hash32::digest(CTX_ENV_ID, &encode(self))
    }

    pub fn verify_sig(&self) -> Result<()> {
        self.header.author.verify(
            CTX_ENV_SIG,
            &[&encode(&self.header), &self.ciphertext],
            &self.sig,
        )?;
        Ok(())
    }
}

/// Why an envelope is (not yet) part of its stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Valid,
    Pending(&'static str),
    Invalid(&'static str),
}

/// L4 rules hook: decides whether a decrypted feed entry is acceptable.
/// Must be deterministic (same inputs → same answer on every peer); the
/// inputs are all derived from the envelope and its causal past.
pub trait FeedValidator: Send + Sync {
    fn validate(&self, stream: &StreamId, author: &SignPk, author_role: Role, body: &[u8]) -> bool;
}

/// Durable storage for a replica's inputs. Everything else is derived.
pub trait Store: Send + Sync {
    fn put_op(&self, space: &SpaceId, op: &SignedOp);
    fn put_envelope(&self, space: &SpaceId, env: &Envelope);
}

/// What a batch ingest changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ingested {
    pub ops: usize,
    pub envelopes: usize,
    pub rejected: usize,
}

impl Ingested {
    pub fn changed(&self) -> bool {
        self.ops + self.envelopes > 0
    }
}

struct DocState {
    doc: AutoCommit,
    applied: BTreeSet<EnvelopeId>,
    /// (actor, seq) → (change hash, envelope) — to detect equivocation.
    seqs: HashMap<(Vec<u8>, u64), (automerge::ChangeHash, EnvelopeId)>,
}

#[derive(Default)]
struct FeedState {
    items: HashMap<EnvelopeId, FeedItem>,
    order: Option<Vec<EnvelopeId>>,
}

impl FeedState {
    /// Deterministic causal order: Kahn over known deps, ties by (ts, id).
    fn ordered(&mut self) -> &[EnvelopeId] {
        if self.order.is_none() {
            let mut indeg: HashMap<EnvelopeId, usize> = HashMap::new();
            let mut children: HashMap<EnvelopeId, Vec<EnvelopeId>> = HashMap::new();
            for (id, item) in &self.items {
                let known: HashSet<&EnvelopeId> =
                    item.deps.iter().filter(|d| self.items.contains_key(d)).collect();
                indeg.insert(*id, known.len());
                for d in known {
                    children.entry(*d).or_default().push(*id);
                }
            }
            let key = |id: &EnvelopeId| (self.items[id].ts_ms, *id);
            let mut ready: BTreeSet<(u64, EnvelopeId)> =
                indeg.iter().filter(|(_, d)| **d == 0).map(|(id, _)| key(id)).collect();
            let mut order = Vec::with_capacity(self.items.len());
            while let Some((_, id)) = ready.pop_first() {
                order.push(id);
                for c in children.get(&id).into_iter().flatten() {
                    let d = indeg.get_mut(c).unwrap();
                    *d -= 1;
                    if *d == 0 {
                        ready.insert(key(c));
                    }
                }
            }
            self.order = Some(order);
        }
        self.order.as_deref().unwrap()
    }

    fn heads(&self) -> Vec<EnvelopeId> {
        let referenced: HashSet<&EnvelopeId> = self.items.values().flat_map(|i| &i.deps).collect();
        let mut heads: Vec<EnvelopeId> =
            self.items.keys().filter(|id| !referenced.contains(id)).copied().collect();
        heads.sort();
        heads
    }
}

/// One device's replica of one Space.
pub struct Replica {
    me: Arc<DeviceKeys>,
    graph: SpaceGraph,
    ring: Keyring,
    envelopes: HashMap<EnvelopeId, Envelope>,
    /// author → seq → envelope ids (more than one = equivocation)
    chains: HashMap<SignPk, BTreeMap<u64, Vec<EnvelopeId>>>,
    status: HashMap<EnvelopeId, Status>,
    /// Valid envelopes per stream (whether or not we can decrypt them).
    valid_by_stream: HashMap<StreamId, BTreeSet<EnvelopeId>>,
    docs: HashMap<StreamId, DocState>,
    feeds: HashMap<StreamId, FeedState>,
    /// Which peers are known to hold which envelopes (from sync inventories).
    holders: HashMap<EnvelopeId, BTreeSet<SignPk>>,
    store: Option<Arc<dyn Store>>,
    validator: Option<Arc<dyn FeedValidator>>,
    /// Valid envelopes whose decrypted content the rules rejected.
    rule_rejected: HashSet<EnvelopeId>,
    /// Doc changes excluded because their author equivocated (two different
    /// changes with the same actor+seq): the lowest envelope id wins, everywhere.
    equivocated: HashSet<EnvelopeId>,
    /// Payloads rejected during the current document rebuild. Deferred inputs
    /// stay only in the existing valid_by_stream index, never in Automerge.
    doc_rejected: HashSet<EnvelopeId>,
}

impl Replica {
    /// Found a new Space.
    pub fn create(me: Arc<DeviceKeys>, store: Option<Arc<dyn Store>>) -> Result<(Self, SignedOp)> {
        let (graph, genesis, epoch, key) = SpaceGraph::create(&me)?;
        let mut ring = Keyring::default();
        ring.insert(epoch, key);
        let r = Self::from_parts(me, graph, ring, store);
        r.persist_op(&genesis);
        Ok((r, genesis))
    }

    /// Join (or relay) an existing Space given its genesis op.
    pub fn join(me: Arc<DeviceKeys>, genesis: SignedOp, store: Option<Arc<dyn Store>>) -> Result<Self> {
        let graph = SpaceGraph::from_genesis(genesis.clone())?;
        let mut r = Self::from_parts(me, graph, Keyring::default(), store);
        r.graph.unlock(&r.me, &mut r.ring);
        r.persist_op(&genesis);
        Ok(r)
    }

    /// Rebuild a replica from stored inputs (nothing is re-persisted).
    pub fn restore(
        me: Arc<DeviceKeys>,
        genesis: SignedOp,
        ops: Vec<SignedOp>,
        envelopes: Vec<Envelope>,
        store: Option<Arc<dyn Store>>,
    ) -> Result<Self> {
        let graph = SpaceGraph::from_genesis(genesis)?;
        let mut r = Self::from_parts(me, graph, Keyring::default(), None);
        r.ingest_batch(ops, envelopes);
        r.graph.unlock(&r.me, &mut r.ring);
        r.full_refresh();
        r.store = store;
        Ok(r)
    }

    fn from_parts(
        me: Arc<DeviceKeys>,
        graph: SpaceGraph,
        ring: Keyring,
        store: Option<Arc<dyn Store>>,
    ) -> Self {
        Replica {
            me,
            graph,
            ring,
            envelopes: HashMap::new(),
            chains: HashMap::new(),
            status: HashMap::new(),
            valid_by_stream: HashMap::new(),
            docs: HashMap::new(),
            feeds: HashMap::new(),
            holders: HashMap::new(),
            store,
            validator: None,
            rule_rejected: HashSet::new(),
            equivocated: HashSet::new(),
            doc_rejected: HashSet::new(),
        }
    }

    /// Install (or replace) the L4 rules for feed entries; re-derives feeds.
    pub fn set_feed_validator(&mut self, v: Option<Arc<dyn FeedValidator>>) {
        self.validator = v;
        self.rule_rejected.clear();
        self.feeds.clear();
        let ids: Vec<EnvelopeId> = self
            .status
            .iter()
            .filter(|(_, s)| **s == Status::Valid)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.materialize(&id);
        }
    }

    /// Entries that were cryptographically valid but rejected by the rules.
    pub fn rule_rejected(&self) -> usize {
        self.rule_rejected.len()
    }

    fn persist_op(&self, op: &SignedOp) {
        if let Some(s) = &self.store {
            s.put_op(&self.space_id(), op);
        }
    }

    fn persist_envelope(&self, env: &Envelope) {
        if let Some(s) = &self.store {
            s.put_envelope(&self.space_id(), env);
        }
    }

    pub fn me(&self) -> &Arc<DeviceKeys> {
        &self.me
    }

    pub fn space_id(&self) -> SpaceId {
        self.graph.space_id()
    }

    pub fn graph(&self) -> &SpaceGraph {
        &self.graph
    }

    pub fn my_role(&self) -> Option<Role> {
        self.graph.state().role(&self.me.sign_pk())
    }

    /// Is `pk` currently allowed to sync this space with us (any role, incl. Relay)?
    pub fn is_member(&self, pk: &SignPk) -> bool {
        self.graph.state().members.contains_key(pk)
    }

    /// Current members.
    pub fn members(&self) -> Vec<(MemberKeys, Role)> {
        self.graph
            .state()
            .members
            .values()
            .map(|m| (m.keys, m.role))
            .collect()
    }

    // ───────────── network-facing ─────────────

    pub fn op_ids(&self) -> Vec<OpId> {
        self.graph.op_ids()
    }

    pub fn op(&self, id: &OpId) -> Option<&SignedOp> {
        self.graph.get(id)
    }

    pub fn all_ops(&self) -> Vec<SignedOp> {
        self.graph.op_ids().iter().filter_map(|i| self.graph.get(i).cloned()).collect()
    }

    /// Winning revocations of `pk` plus every op in their causal past — what a
    /// removed member needs to learn it was removed (nothing after that).
    pub fn revocation_proof(&self, pk: &SignPk) -> Vec<SignedOp> {
        let revs: Vec<OpId> = self.graph.revocations_of(pk).into_iter().map(|(id, _)| id).collect();
        if revs.is_empty() {
            return vec![];
        }
        self.graph
            .resolution()
            .order
            .iter()
            .filter(|id| self.graph.in_past(id, &revs))
            .filter_map(|id| self.graph.get(id).cloned())
            .collect()
    }

    pub fn envelope_ids(&self) -> Vec<EnvelopeId> {
        self.envelopes.keys().copied().collect()
    }

    pub fn has_envelope(&self, id: &EnvelopeId) -> bool {
        self.envelopes.contains_key(id)
    }

    pub fn envelope(&self, id: &EnvelopeId) -> Option<&Envelope> {
        self.envelopes.get(id)
    }

    /// Record that `peer` holds these envelopes (from its sync inventory).
    pub fn note_holder(&mut self, peer: SignPk, ids: &[EnvelopeId]) {
        for id in ids {
            if self.envelopes.contains_key(id) {
                self.holders.entry(*id).or_default().insert(peer);
            }
        }
    }

    pub fn holders(&self, id: &EnvelopeId) -> BTreeSet<SignPk> {
        self.holders.get(id).cloned().unwrap_or_default()
    }

    /// Ingest a membership op from anyone. Returns true if it was new.
    pub fn ingest_op(&mut self, op: SignedOp) -> Result<bool> {
        let id = op.id();
        let new = self.graph.insert(op)? == Inserted::New;
        if let Some(op) = self.graph.get(&id) {
            // Persist pending ops too: they become valid once parents arrive.
            self.persist_op(&op.clone());
        }
        if new {
            self.graph.unlock(&self.me, &mut self.ring);
            self.full_refresh();
        }
        Ok(new)
    }

    /// Ingest an envelope from anyone. Signature, space and size are checked
    /// here; validity is decided by [`Replica::status`].
    pub fn ingest_envelope(&mut self, env: Envelope) -> Result<bool> {
        let Some(id) = self.stage_envelope(env)? else {
            return Ok(false);
        };
        self.incremental(&[id]);
        Ok(true)
    }

    fn stage_envelope(&mut self, env: Envelope) -> Result<Option<EnvelopeId>> {
        if env.header.space != self.space_id() {
            return Err(SyncError::WrongSpace);
        }
        if env.ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT {
            return Err(SyncError::TooLarge);
        }
        if env.header.auth_heads.len() > MAX_AUTH_HEADS {
            return Err(SyncError::NotAllowed("too many auth heads"));
        }
        let id = env.id();
        if self.envelopes.contains_key(&id) {
            return Ok(None);
        }
        // DoS guard: never store envelopes from keys this space never added.
        // (Re-fetched on a later sync if the Add simply hasn't arrived yet.)
        if !self.graph.ever_named(&env.header.author) {
            return Err(SyncError::NotAllowed("author was never added to this space"));
        }
        env.verify_sig()?;
        self.persist_envelope(&env);
        self.chains
            .entry(env.header.author)
            .or_default()
            .entry(env.header.author_seq)
            .or_default()
            .push(id);
        self.envelopes.insert(id, env);
        Ok(Some(id))
    }

    /// Ingest many items at once (one graph resolution, one refresh).
    pub fn ingest_batch(&mut self, ops: Vec<SignedOp>, envelopes: Vec<Envelope>) -> Ingested {
        let mut out = Ingested::default();
        if !ops.is_empty() {
            let ids: Vec<OpId> = ops.iter().map(|o| o.id()).collect();
            let known: HashSet<OpId> = ids.iter().filter(|i| self.graph.contains(i)).copied().collect();
            let (added, rejected) = self.graph.insert_many(ops);
            out.ops = added.len();
            out.rejected += rejected;
            for id in ids.iter().filter(|i| !known.contains(i)) {
                if let Some(op) = self.graph.get(id) {
                    self.persist_op(&op.clone());
                }
            }
        }
        let mut new_envs = Vec::new();
        for env in envelopes {
            match self.stage_envelope(env) {
                Ok(Some(id)) => new_envs.push(id),
                Ok(None) => {}
                Err(_) => out.rejected += 1,
            }
        }
        out.envelopes = new_envs.len();
        if out.ops > 0 {
            self.graph.unlock(&self.me, &mut self.ring);
            self.full_refresh();
        } else if !new_envs.is_empty() {
            self.incremental(&new_envs);
        }
        out
    }

    // ───────────── validation (no decryption) ─────────────

    pub fn status(&self, id: &EnvelopeId) -> Status {
        self.status
            .get(id)
            .cloned()
            .unwrap_or(Status::Pending("unknown envelope"))
    }

    fn compute_status(&self, id: &EnvelopeId) -> Status {
        let Some(env) = self.envelopes.get(id) else {
            return Status::Pending("unknown envelope");
        };
        let h = &env.header;
        if !self.graph.knows_all(&h.auth_heads) {
            return Status::Pending("missing membership ops");
        }
        let st = self.graph.state_at(&h.auth_heads);
        if !st.role(&h.author).is_some_and(Role::can_write) {
            return Status::Invalid("author not a writer at auth_heads");
        }
        if !st
            .epoch(&h.epoch)
            .is_some_and(|e| e.recipients.contains(&h.author))
        {
            return Status::Invalid("author not a recipient of epoch");
        }
        match (h.author_seq, &h.author_prev) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Status::Invalid("broken author chain"),
            (seq, Some(prev)) => match self.envelopes.get(prev) {
                None => return Status::Pending("missing previous envelope"),
                Some(p) if p.header.author != h.author || p.header.author_seq.checked_add(1) != Some(seq) => {
                    return Status::Invalid("broken author chain");
                }
                Some(_) => {}
            },
        }
        // Cutoff rule: revocations the author didn't acknowledge bound their chain.
        for (rev, cutoff) in self.graph.revocations_of(&h.author) {
            if self.graph.in_past(&rev, &h.auth_heads) {
                continue;
            }
            let Some(cutoff) = cutoff else {
                return Status::Invalid("written after revocation");
            };
            match self.chain_contains(&cutoff, id) {
                Some(true) => {}
                Some(false) => return Status::Invalid("beyond revocation cutoff"),
                None => return Status::Pending("missing cutoff envelope"),
            }
        }
        Status::Valid
    }

    /// Is `target` on the author chain ending at `tip`? `None` if the chain has gaps.
    fn chain_contains(&self, tip: &EnvelopeId, target: &EnvelopeId) -> Option<bool> {
        let mut cur = *tip;
        loop {
            if cur == *target {
                return Some(true);
            }
            let env = self.envelopes.get(&cur)?;
            match env.header.author_prev {
                Some(prev) => cur = prev,
                None => return Some(false),
            }
        }
    }

    // ───────────── materialization ─────────────

    /// Membership changed: re-evaluate everything; rebuild streams that lost envelopes.
    fn full_refresh(&mut self) {
        let ids: Vec<EnvelopeId> = self.envelopes.keys().copied().collect();
        self.status = ids.iter().map(|id| (*id, self.compute_status(id))).collect();
        let mut by_stream: HashMap<StreamId, BTreeSet<EnvelopeId>> = HashMap::new();
        for (id, st) in &self.status {
            if *st == Status::Valid {
                by_stream
                    .entry(self.envelopes[id].header.stream)
                    .or_default()
                    .insert(*id);
            }
        }
        let streams: BTreeSet<StreamId> = by_stream
            .keys()
            .chain(self.valid_by_stream.keys())
            .copied()
            .collect();
        for stream in streams {
            let valid = by_stream.remove(&stream).unwrap_or_default();
            let lost = self
                .valid_by_stream
                .get(&stream)
                .is_some_and(|old| !old.is_subset(&valid));
            if lost {
                self.docs.remove(&stream);
                self.feeds.remove(&stream);
                self.clear_equivocation(stream);
            }
            self.valid_by_stream.insert(stream, valid.clone());
            self.clear_doc_rejections(stream);
            if stream.kind == StreamKind::Doc {
                self.refresh_doc(stream);
            } else {
                for id in valid {
                    self.materialize(&id);
                }
            }
        }
    }

    /// New envelopes arrived: evaluate them and anything pending that they may unblock.
    fn incremental(&mut self, new: &[EnvelopeId]) {
        let mut todo: Vec<EnvelopeId> = new.to_vec();
        todo.extend(
            self.status
                .iter()
                .filter(|(_, s)| matches!(s, Status::Pending(_)))
                .map(|(id, _)| *id),
        );
        loop {
            let mut progressed = false;
            let mut still = Vec::new();
            for id in todo {
                let st = self.compute_status(&id);
                let was_valid = self.status.get(&id) == Some(&Status::Valid);
                if st == Status::Valid && !was_valid {
                    let stream = self.envelopes[&id].header.stream;
                    self.valid_by_stream.entry(stream).or_default().insert(id);
                    self.status.insert(id, st);
                    self.materialize(&id);
                    progressed = true;
                } else {
                    if matches!(st, Status::Pending(_)) {
                        still.push(id);
                    }
                    self.status.insert(id, st);
                }
            }
            if !progressed || still.is_empty() {
                break;
            }
            todo = still;
        }
    }

    /// Apply one valid envelope to its stream, if we can decrypt it.
    fn materialize(&mut self, id: &EnvelopeId) {
        let env = &self.envelopes[id];
        let stream = env.header.stream;
        if stream.kind == StreamKind::Doc {
            self.refresh_doc(stream);
            return;
        }
        let Some(key) = self.ring.get(&env.header.epoch) else {
            return; // opaque (e.g. we are a keeper, or joined after this epoch)
        };
        let Ok(plain) = key.open(&env.header.nonce, &content_aad(&env.header), &env.ciphertext)
        else {
            return;
        };
        match stream.kind {
            StreamKind::Doc => unreachable!("documents use refresh_doc"),
            StreamKind::Feed => {
                if self.feeds.get(&stream).is_some_and(|f| f.items.contains_key(id)) {
                    return;
                }
                let Ok(entry) = postcard::from_bytes::<FeedEntry>(&plain) else {
                    return;
                };
                let role = self
                    .graph
                    .state_at(&env.header.auth_heads)
                    .role(&env.header.author)
                    .unwrap_or(Role::Relay);
                if let Some(v) = &self.validator
                    && !v.validate(&stream, &env.header.author, role, &entry.body)
                {
                    self.rule_rejected.insert(*id);
                    return;
                }
                let item = FeedItem {
                    id: *id,
                    author: env.header.author,
                    author_role: role,
                    ts_ms: entry.ts_ms,
                    deps: entry.deps,
                    body: entry.body,
                };
                let feed = self.feeds.entry(stream).or_default();
                feed.items.insert(*id, item);
                feed.order = None;
            }
        }
    }

    /// Re-derive one document, including payload rejection and fork decisions.
    fn rebuild_doc(&mut self, stream: StreamId) {
        self.docs.remove(&stream);
        self.clear_doc_rejections(stream);
        self.refresh_doc(stream);
    }

    fn clear_doc_rejections(&mut self, stream: StreamId) {
        self.doc_rejected.retain(|id| self.envelopes[id].header.stream != stream);
    }

    /// The encrypted input index is also the deferred backlog. Do not allocate
    /// another queue, retain parsed changes, or copy the entire ID set on retry.
    fn doc_batch(&self, stream: StreamId, after: Option<EnvelopeId>) -> Vec<EnvelopeId> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.valid_by_stream.get(&stream).map(|ids| {
            ids.range((after.map(Excluded).unwrap_or(Unbounded), Unbounded))
                .take(256).copied().collect()
        }).unwrap_or_default()
    }

    fn doc_change(&self, id: &EnvelopeId) -> std::result::Result<Option<automerge::Change>, ()> {
        let env = &self.envelopes[id];
        let Some(key) = self.ring.get(&env.header.epoch) else { return Ok(None); };
        let plain = key.open(&env.header.nonce, &content_aad(&env.header), &env.ciphertext).map_err(|_| ())?;
        let change = bounded_change::parse(&plain).map_err(|_| ())?;
        if change.actor_id().to_bytes() != env.header.author.0 { return Err(()); }
        Ok(Some(change))
    }

    /// Select canonical forks before retrying dependencies. A lower-ID fork
    /// may depend on a later-ID change; selecting only already-applied forks
    /// would repeatedly rebuild against its higher-ID competitor.
    fn refresh_doc(&mut self, stream: StreamId) {
        loop {
            self.clear_equivocation(stream);
            let mut winners = HashMap::new();
            let mut after = None;
            loop {
                let batch = self.doc_batch(stream, after);
                if batch.is_empty() { break; }
                after = batch.last().copied();
                for id in batch {
                    if self.doc_rejected.contains(&id) { continue; }
                    let change = match self.doc_change(&id) {
                        Ok(Some(change)) => change,
                        Ok(None) => continue,
                        Err(()) => { self.doc_rejected.insert(id); continue; }
                    };
                    let key = (change.actor_id().to_bytes().to_vec(), change.seq());
                    let winner = winners.entry(key).or_insert(change.hash());
                    if *winner != change.hash() { self.equivocated.insert(id); }
                }
            }
            drop(winners);
            // Any newly selected fork invalidates its old materialization and
            // all descendants. Recompute from the same encrypted input set.
            if self.docs.get(&stream).is_some_and(|state| state.applied.iter().any(|id| {
                self.equivocated.contains(id) || self.doc_rejected.contains(id)
            })) {
                self.docs.remove(&stream);
            }
            // No recursion and no upstream dependency queue: retry the stored
            // IDs only while changes actually apply. A failed candidate is
            // rejected, then fork selection is recomputed to permit fallback.
            let rejected_before = self.doc_rejected.len();
            loop {
                let mut progressed = false;
                let mut after = None;
                loop {
                    let batch = self.doc_batch(stream, after);
                    if batch.is_empty() { break; }
                    after = batch.last().copied();
                    for id in batch { progressed |= self.apply_ready_doc(&id); }
                }
                if self.doc_rejected.len() != rejected_before { break; }
                if !progressed { return; }
            }
        }
    }

    /// Apply only when every dependency is present in the materialized doc.
    /// Missing-dependency changes remain encrypted in the existing input index.
    fn apply_ready_doc(&mut self, id: &EnvelopeId) -> bool {
        let stream = self.envelopes[id].header.stream;
        if self.equivocated.contains(id) || self.doc_rejected.contains(id)
            || self.docs.get(&stream).is_some_and(|s| s.applied.contains(id)) {
            return false;
        }
        let change = match self.doc_change(id) {
            Ok(Some(change)) => change,
            Ok(None) => return false,
            Err(()) => { self.doc_rejected.insert(*id); return false; }
        };
        let state = self.docs.get(&stream);
        if change.deps().iter().any(|dep| state.is_none_or(|s| automerge::ReadDoc::get_change_by_hash(&s.doc, dep).is_none())) {
            return false;
        }
        if !Self::causal_metadata_valid(state, &change) {
            self.doc_rejected.insert(*id);
            return false;
        }
        let key = (change.actor_id().to_bytes().to_vec(), change.seq());
        let hash = change.hash();
        let canonical = state.and_then(|s| s.seqs.get(&key))
            .map(|(_, other)| (*id).min(*other)).unwrap_or(*id);
        let actor = ActorId::from(self.me.sign_pk().0.to_vec());
        let mut candidate = state.map(|s| s.doc.clone())
            .unwrap_or_else(|| AutoCommit::new().with_actor(actor));
        // Validate semantics using only declared causal history. Applying to
        // the full local doc first could accept undeclared actor/object refs
        // merely because concurrent changes happened to arrive earlier.
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(mut causal) = candidate.fork_at(change.deps()) else { return false; };
            if causal.apply_changes([change.clone()]).is_err()
                || causal.get_change_by_hash(&hash).is_none() {
                return false;
            }
            // Only a causally valid change can enter the full document. Errors
            // and panics discard both temporary docs and their bookkeeping.
            candidate.apply_changes([change]).is_ok()
                && candidate.get_change_by_hash(&hash).is_some()
        }));
        if !matches!(applied, Ok(true)) {
            self.doc_rejected.insert(*id);
            return false;
        }
        let state = match self.docs.entry(stream) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let state = entry.into_mut();
                state.doc = candidate;
                state
            }
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(DocState {
                doc: candidate, applied: BTreeSet::new(), seqs: HashMap::new(),
            }),
        };
        state.seqs.insert(key, (hash, canonical));
        state.applied.insert(*id);
        true
    }

    /// Automerge's actor sequence is consecutive within declared ancestry;
    /// operation counters are Lamport counters, so gaps are allowed but no
    /// counter may overlap causal history. The upstream graph stores u32 ends.
    fn causal_metadata_valid(state: Option<&DocState>, change: &automerge::Change) -> bool {
        let end = |c: &automerge::Change| {
            let start = c.start_op().get();
            let last = start.checked_add(c.len() as u64)?.checked_sub(1)?;
            (start <= u32::MAX as u64 && last <= u32::MAX as u64).then_some(last)
        };
        if end(change).is_none() { return false; }
        let mut seen = HashSet::new();
        let mut todo = Vec::new();
        for dep in change.deps() {
            if seen.insert(*dep) { todo.push(*dep); }
        }
        let mut previous_seq = 0u64;
        let mut previous_counter = 0u64;
        while let Some(hash) = todo.pop() {
            let Some(prior) = state.and_then(|s| automerge::ReadDoc::get_change_by_hash(&s.doc, &hash)) else {
                return false;
            };
            if prior.actor_id() == change.actor_id() { previous_seq = previous_seq.max(prior.seq()); }
            let Some(last) = end(&prior) else { return false; };
            previous_counter = previous_counter.max(last);
            for dep in prior.deps() {
                if seen.insert(*dep) { todo.push(*dep); }
            }
        }
        previous_seq.checked_add(1) == Some(change.seq())
            && change.start_op().get() > previous_counter
    }

    fn clear_equivocation(&mut self, stream: StreamId) {
        self.equivocated.retain(|id| self.envelopes[id].header.stream != stream);
    }

    // ───────────── app-facing ─────────────

    pub fn new_doc_id() -> StreamId {
        StreamId::new_doc()
    }

    pub fn doc(&self, doc: &StreamId) -> Option<&AutoCommit> {
        self.docs.get(doc).map(|d| &d.doc)
    }

    pub fn doc_json(&self, doc: &StreamId) -> serde_json::Value {
        match self.docs.get(doc) {
            Some(d) => serde_json::to_value(automerge::AutoSerde::from(&d.doc)).unwrap_or_default(),
            None => serde_json::Value::Null,
        }
    }

    pub fn doc_ids(&self) -> Vec<StreamId> {
        self.docs.keys().copied().collect()
    }

    /// Feed entries in deterministic causal order.
    pub fn feed(&mut self, feed: &StreamId) -> Vec<FeedItem> {
        match self.feeds.get_mut(feed) {
            Some(f) => {
                let order = f.ordered().to_vec();
                order.iter().map(|id| f.items[id].clone()).collect()
            }
            None => Vec::new(),
        }
    }

    pub fn feed_len(&self, feed: &StreamId) -> usize {
        self.feeds.get(feed).map_or(0, |f| f.items.len())
    }

    /// Ensure there's a usable epoch for writing (rotating if needed).
    fn write_epoch(&mut self) -> Result<(Vec<SignedOp>, EpochId)> {
        match self.graph.state().write_epoch() {
            Some(e) if self.ring.get(&e).is_some() => Ok((vec![], e)),
            _ => {
                // TRUST.md §6: no usable epoch → rotate first (needs Writer).
                let (op, epoch, key) = self.graph.rotate(&self.me)?;
                self.ring.insert(epoch, key);
                self.ingest_op(op.clone())?;
                Ok((vec![op], epoch))
            }
        }
    }

    fn seal(&mut self, stream: StreamId, epoch: EpochId, plaintext: &[u8]) -> Result<Envelope> {
        let (seq, prev) = self.my_chain_tip();
        let header = Header {
            space: self.space_id(),
            stream,
            author: self.me.sign_pk(),
            author_seq: seq,
            author_prev: prev,
            auth_heads: self.graph.heads(),
            epoch,
            nonce: random(),
        };
        let key = self.ring.get(&epoch).expect("epoch key present");
        let ciphertext = key.seal(&header.nonce, &content_aad(&header), plaintext)?;
        if ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT {
            return Err(SyncError::TooLarge);
        }
        let sig = self.me.sign(CTX_ENV_SIG, &[&encode(&header), &ciphertext]);
        Ok(Envelope { header, ciphertext, sig })
    }

    /// Edit a document locally. Returns any ops (a self-healing rotation) and
    /// the envelope to broadcast.
    ///
    /// The local role isn't pre-checked: a Reader's change is produced and
    /// signed like any other, and every honest peer — including ourselves —
    /// rejects it. Apps should check `my_role()` first for UX.
    pub fn change(
        &mut self,
        doc: StreamId,
        edit: impl FnOnce(&mut AutoCommit) -> std::result::Result<(), automerge::AutomergeError>,
    ) -> Result<(Vec<SignedOp>, Option<Envelope>)> {
        debug_assert_eq!(doc.kind, StreamKind::Doc);
        let (ops, epoch) = self.write_epoch()?;
        let actor = ActorId::from(self.me.sign_pk().0.to_vec());
        let state = self.docs.entry(doc).or_insert_with(|| DocState {
            doc: AutoCommit::new().with_actor(actor),
            applied: BTreeSet::new(),
            seqs: HashMap::new(),
        });
        edit(&mut state.doc)?;
        state.doc.commit();
        let Some(mut change) = state.doc.get_last_local_change() else {
            return Ok((ops, None));
        };
        if let Err(err) = bounded_change::validate(change.raw_bytes()) {
            self.rebuild_doc(doc);
            return Err(err);
        }
        if !Self::causal_metadata_valid(self.docs.get(&doc), &change) {
            self.rebuild_doc(doc);
            return Err(SyncError::Encoding);
        }
        let plaintext = change.bytes().to_vec();
        let env = match self.seal(doc, epoch, &plaintext) {
            Ok(env) => env,
            Err(err) => {
                self.rebuild_doc(doc);
                return Err(err);
            }
        };
        let id = env.id();
        if let Err(err) = self.ingest_envelope(env.clone()) {
            self.rebuild_doc(doc);
            return Err(err);
        }
        if self.status(&id) != Status::Valid
            || !self.docs.get(&doc).is_some_and(|state| state.applied.contains(&id)) {
            // Roll the local doc back to the valid set.
            self.rebuild_doc(doc);
        }
        Ok((ops, Some(env)))
    }

    /// Append an entry to a feed. Returns any ops and the envelope to broadcast.
    pub fn append(&mut self, feed: StreamId, body: Vec<u8>) -> Result<(Vec<SignedOp>, Envelope)> {
        debug_assert_eq!(feed.kind, StreamKind::Feed);
        let (ops, epoch) = self.write_epoch()?;
        let deps = self.feeds.get(&feed).map(|f| f.heads()).unwrap_or_default();
        let entry = FeedEntry { deps, ts_ms: now_ms(), body };
        let env = self.seal(feed, epoch, &encode(&entry))?;
        self.ingest_envelope(env.clone())?;
        Ok((ops, env))
    }

    fn my_chain_tip(&self) -> (u64, Option<EnvelopeId>) {
        match self
            .chains
            .get(&self.me.sign_pk())
            .and_then(|c| c.iter().next_back())
        {
            Some((seq, ids)) => (seq + 1, ids.first().copied()),
            None => (0, None),
        }
    }

    /// Latest envelope we've seen from `pk` (used as a revocation cutoff).
    pub fn latest_from(&self, pk: &SignPk) -> Option<EnvelopeId> {
        self.chains
            .get(pk)
            .and_then(|c| c.iter().next_back())
            .and_then(|(_, ids)| ids.first().copied())
    }

    // ───────────── membership (admin) ─────────────

    pub fn add_member(&mut self, member: MemberKeys, role: Role) -> Result<SignedOp> {
        let op = self.graph.add_member(&self.me, &self.ring, member, role)?;
        self.ingest_op(op.clone())?;
        Ok(op)
    }

    pub fn remove_member(&mut self, member: SignPk) -> Result<SignedOp> {
        let cutoff = self.latest_from(&member);
        let (op, epoch, key) = self.graph.remove_member(&self.me, member, cutoff)?;
        self.ring.insert(epoch, key);
        self.ingest_op(op.clone())?;
        Ok(op)
    }

    pub fn leave(&mut self) -> Result<SignedOp> {
        let cutoff = self.latest_from(&self.me.sign_pk());
        let op = self.graph.leave(&self.me, cutoff)?;
        self.ingest_op(op.clone())?;
        Ok(op)
    }

    pub fn set_role(&mut self, member: SignPk, role: Role) -> Result<SignedOp> {
        let cutoff = self.latest_from(&member);
        let (op, new_key) = self.graph.set_role(&self.me, member, role, cutoff)?;
        if let Some((epoch, key)) = new_key {
            self.ring.insert(epoch, key);
        }
        self.ingest_op(op.clone())?;
        Ok(op)
    }

    /// Envelopes that are valid but that we can't decrypt (e.g. relays).
    pub fn opaque_count(&self) -> usize {
        self.status
            .iter()
            .filter(|(id, s)| {
                **s == Status::Valid && self.ring.get(&self.envelopes[*id].header.epoch).is_none()
            })
            .count()
    }

    /// Encrypt a small ephemeral payload (typing, presence) under the current
    /// epoch. Returns (epoch, nonce, ciphertext).
    pub fn seal_ephemeral(&self, aad: &[u8], plaintext: &[u8]) -> Option<(EpochId, [u8; 24], Vec<u8>)> {
        let epoch = self.graph.state().write_epoch()?;
        let key = self.ring.get(&epoch)?;
        let nonce = random();
        let ct = key.seal(&nonce, aad, plaintext).ok()?;
        Some((epoch, nonce, ct))
    }

    pub fn open_ephemeral(&self, epoch: &EpochId, nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        self.ring.get(epoch)?.open(nonce, aad, ct).ok()
    }
}

#[cfg(test)]
mod tests;

