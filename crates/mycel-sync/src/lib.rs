//! Mycel data & sync v0 (docs/TRUST.md §7): signed, encrypted envelopes,
//! validated without decryption, materialized into **Docs** (Automerge) and
//! **Feeds** (append-only, causally ordered entries).
//!
//! A [`Replica`] is one device's view of one Space: the membership graph, the
//! device's keyring, every envelope it holds, and the streams it can decrypt.
//! Keepers run the same `Replica` with the Relay role: they validate and store
//! envelopes but hold no keys, so they never materialize anything.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use automerge::{ActorId, AutoCommit, Change, ChangeHash};
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, Sig, SignPk, random};
use mycel_trust::{EpochId, Inserted, Keyring, OpId, Role, SignedOp, SpaceGraph, SpaceId};
use serde::{Deserialize, Serialize};

pub use automerge;
pub use mycel_trust;

mod bounded_change;
mod change_ops;
mod change_resources;
mod doc_index;
pub mod reconcile;

pub type EnvelopeId = Hash32;

const CTX_ENV_SIG: &str = "mycel/v0/envelope";
const CTX_ENV_ID: &str = "mycel/v0/envelope-id";
const CTX_CONTENT_AAD: &str = "mycel/v0/content";

/// Envelopes carry small changes; large data goes through blobs.
pub const MAX_ENVELOPE_CIPHERTEXT: usize = 1024 * 1024;

// Document change limits. Readers accept up to the `MAX_DOC_*` bounds; writers
// stay within the much smaller `MAX_LOCAL_CHANGE_*` bounds and split larger
// edits into several changes, so what they write is accepted by every
// released version while what older versions wrote stays readable.
//
// Decompression is bounded by `MAX_DOC_CHANGE_BYTES` (DEFLATE itself cannot
// exceed ~1032x). Run-length and group expansion is bounded relative to the
// encoded change: up to 64 logical values (or string bytes) per byte of
// change body, at least a quarter of the cap (deleting a long run encodes in
// a few bytes) and never more than the cap. A single change therefore costs
// at most ~1M operations / 16M logical values to parse and apply, whatever
// its size on the wire.

/// Maximum serialized Automerge change after decompression, framing included.
pub const MAX_DOC_CHANGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum operations in one received change.
pub const MAX_DOC_CHANGE_OPS: usize = 1 << 20;
/// Cap on logical column cells plus entries declared by group counts.
pub const MAX_DOC_COLUMN_VALUES: usize = 16 << 20;
/// Cap on string bytes after expanding string-column runs.
pub const MAX_DOC_COLUMN_STRING_BYTES: usize = 16 * 1024 * 1024;
/// Local edits are written as changes of at most this many serialized bytes
/// (well inside one envelope even if incompressible)...
pub const MAX_LOCAL_CHANGE_BYTES: usize = 512 * 1024;
/// ...and at most this many operations each.
pub const MAX_LOCAL_CHANGE_OPS: usize = 65_536;
/// Validated changes are handed to Automerge in batches of about this many
/// operations, bounding the memory one apply call needs.
const APPLY_BATCH_OPS: usize = 1 << 20;
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
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Envelope {
    pub fn id(&self) -> EnvelopeId {
        Hash32::digest(CTX_ENV_ID, &encode(self))
    }

    pub fn verify_sig(&self) -> Result<()> {
        self.header.author.verify(CTX_ENV_SIG, &[&encode(&self.header), &self.ciphertext], &self.sig)?;
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

/// A materialized document: the Automerge doc, the causal index of the changes
/// in it, and the envelopes those changes came from.
struct DocState {
    doc: AutoCommit,
    index: doc_index::Index,
    applied: BTreeSet<EnvelopeId>,
}

impl DocState {
    fn new(actor: ActorId) -> Self {
        DocState { doc: AutoCommit::new().with_actor(actor), index: Default::default(), applied: BTreeSet::new() }
    }
}

/// An author's (actor, seq) slot in a document.
type Slot = (ActorId, u64);

/// Decrypted, well-formed changes of one document, applied or not. Waiting
/// changes stay encrypted in the envelope store; only this metadata is kept.
#[derive(Default)]
struct DocInputs {
    known: HashMap<EnvelopeId, Known>,
    /// Candidates per slot. More than one change hash is equivocation: the
    /// lowest envelope id wins on every replica.
    slots: HashMap<Slot, BTreeMap<EnvelopeId, ChangeHash>>,
    /// Missing dependency → envelopes waiting for it.
    waiting: HashMap<ChangeHash, Vec<EnvelopeId>>,
}

struct Known {
    hash: ChangeHash,
    slot: Slot,
    /// Distinct dependencies not yet in the document.
    missing: usize,
}

impl DocInputs {
    fn winner(&self, slot: &Slot) -> Option<ChangeHash> {
        self.slots.get(slot).and_then(|c| c.first_key_value()).map(|(_, h)| *h)
    }
}

enum DocFlow {
    Done,
    /// The document must be re-derived from its inputs.
    Rebuild,
}

/// A reader's position in one feed: which incarnation of it, and how much of
/// it the reader has applied (see [`Replica::feed_changes`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedCursor {
    instance: u64,
    version: u64,
    len: usize,
}

/// What changed in a feed since a [`FeedCursor`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedChanges {
    /// The first position (in causal order) that differs from what the
    /// reader applied: everything before it is unchanged. The reader's length
    /// when entries were only appended; 0 when the feed was rebuilt.
    pub from: usize,
    /// The feed from `from` on, in causal order.
    pub items: Vec<FeedItem>,
    pub cursor: FeedCursor,
}

/// Feed incarnations: a feed rebuilt from scratch (it lost entries, or the
/// rules changed) is a new one, and its readers start over.
static FEED_INSTANCES: AtomicU64 = AtomicU64::new(1);

/// Recent changes remembered per feed, for readers catching up.
const FEED_CHANGES_KEPT: usize = 4096;
/// A new entry is placed in the order directly only if it lands among the
/// newest this many; otherwise (a long-offline branch, a parent arriving
/// after its children) the order is recomputed once, when next read, so a
/// sync batch in any order costs one sort rather than one per entry.
const FEED_PLACE_WITHIN: usize = 1024;

struct FeedState {
    instance: u64,
    items: HashMap<EnvelopeId, FeedItem>,
    /// Deterministic causal order (Kahn over known deps, ties by (ts, id)),
    /// maintained as entries arrive rather than recomputed.
    order: Vec<EnvelopeId>,
    position: HashMap<EnvelopeId, usize>,
    /// Missing dep → entries that listed it. Its arrival can reorder them.
    waiting: HashMap<EnvelopeId, Vec<EnvelopeId>>,
    /// Every dep listed by an entry; heads are the entries not among them.
    referenced: HashSet<EnvelopeId>,
    heads: BTreeSet<EnvelopeId>,
    /// Entries arrived that `order` doesn't place yet (see `FEED_PLACE_WITHIN`).
    unsorted: bool,
    /// One more per inserted entry.
    version: u64,
    /// (version, first position that changed), oldest first.
    changes: VecDeque<(u64, usize)>,
    /// Changes up to this version may have been forgotten.
    forgotten: u64,
}

impl Default for FeedState {
    fn default() -> Self {
        FeedState {
            instance: FEED_INSTANCES.fetch_add(1, Ordering::Relaxed),
            items: HashMap::new(),
            order: Vec::new(),
            position: HashMap::new(),
            waiting: HashMap::new(),
            referenced: HashSet::new(),
            heads: BTreeSet::new(),
            unsorted: false,
            version: 0,
            changes: VecDeque::new(),
            forgotten: 0,
        }
    }
}

impl FeedState {
    fn key(&self, id: &EnvelopeId) -> (u64, EnvelopeId) {
        (self.items[id].ts_ms, *id)
    }

    /// Add an entry where the deterministic order puts it. Usually O(1): a
    /// new entry follows its deps, and Kahn's choices up to them can't
    /// change; from there it goes before the first entry with a greater
    /// (ts, id). An entry that others already listed as a dep can reorder
    /// them, and one far from the end would shift much of the order: both
    /// leave the order to be recomputed once, when next read.
    fn insert(&mut self, item: FeedItem) {
        let id = item.id;
        let key = (item.ts_ms, id);
        for dep in &item.deps {
            self.referenced.insert(*dep);
            self.heads.remove(dep);
            if !self.items.contains_key(dep) {
                self.waiting.entry(*dep).or_default().push(id);
            }
        }
        if !self.referenced.contains(&id) {
            self.heads.insert(id);
        }
        let after = item.deps.iter().filter_map(|d| self.position.get(d)).max().map_or(0, |p| p + 1);
        self.items.insert(id, item);
        self.version += 1;
        let waited = self.waiting.remove(&id).is_some();
        if self.unsorted || waited || self.order.len() - after.min(self.order.len()) > FEED_PLACE_WITHIN {
            self.unsorted = true;
            return;
        }
        let at = (after..self.order.len()).find(|&i| self.key(&self.order[i]) > key).unwrap_or(self.order.len());
        self.order.insert(at, id);
        for (i, entry) in self.order[at..].iter().enumerate() {
            self.position.insert(*entry, at + i);
        }
        self.record(at);
    }

    fn record(&mut self, at: usize) {
        self.changes.push_back((self.version, at));
        if self.changes.len() > FEED_CHANGES_KEPT
            && let Some((version, _)) = self.changes.pop_front()
        {
            self.forgotten = version;
        }
    }

    /// The order, recomputed first if entries arrived it doesn't place.
    fn sorted(&mut self) -> &[EnvelopeId] {
        if self.unsorted {
            self.unsorted = false;
            let first = self.reorder();
            self.record(first);
        }
        &self.order
    }

    /// Recompute the order from scratch; the first position that moved.
    fn reorder(&mut self) -> usize {
        let mut indeg: HashMap<EnvelopeId, usize> = HashMap::new();
        let mut children: HashMap<EnvelopeId, Vec<EnvelopeId>> = HashMap::new();
        for (id, item) in &self.items {
            let known: HashSet<&EnvelopeId> = item.deps.iter().filter(|d| self.items.contains_key(d)).collect();
            indeg.insert(*id, known.len());
            for d in known {
                children.entry(*d).or_default().push(*id);
            }
        }
        let mut ready: BTreeSet<(u64, EnvelopeId)> =
            indeg.iter().filter(|(_, d)| **d == 0).map(|(id, _)| self.key(id)).collect();
        let mut order = Vec::with_capacity(self.items.len());
        while let Some((_, id)) = ready.pop_first() {
            order.push(id);
            for c in children.get(&id).into_iter().flatten() {
                let d = indeg.get_mut(c).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.insert(self.key(c));
                }
            }
        }
        let first = self.order.iter().zip(&order).take_while(|(a, b)| a == b).count();
        self.position = order.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        self.order = order;
        first
    }

    fn heads(&self) -> Vec<EnvelopeId> {
        self.heads.iter().copied().collect()
    }

    fn changes_since(&mut self, since: FeedCursor) -> FeedChanges {
        self.sorted();
        let cursor = FeedCursor { instance: self.instance, version: self.version, len: self.order.len() };
        let from = if since.instance != self.instance || since.version > self.version || since.version < self.forgotten
        {
            0
        } else {
            self.changes
                .iter()
                .filter(|(v, _)| *v > since.version)
                .map(|(_, at)| *at)
                .fold(since.len, usize::min)
                .min(self.order.len())
        };
        let items = self.order[from..].iter().map(|id| self.items[id].clone()).collect();
        FeedChanges { from, items, cursor }
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
    /// Valid envelopes whose document payload is invalid: undecryptable with
    /// the right key, malformed, written under another actor, or inconsistent
    /// with its declared history. A property of the payload, so permanent.
    doc_rejected: HashSet<EnvelopeId>,
    doc_inputs: HashMap<StreamId, DocInputs>,
    /// Envelopes whose status is Pending (re-checked when new inputs arrive).
    pending: HashSet<EnvelopeId>,
    /// The envelope chains held, for Sync v2 (`reconcile`).
    index: reconcile::ChainIndex,
    /// Sync v2's op tips, with the op count they were computed at (ops are
    /// never removed, so an equal count means the same op set).
    op_tips: std::sync::Mutex<Option<(usize, Vec<OpId>)>>,
    /// Encoded bytes of the envelopes held (for per-peer sync budgets).
    stored_bytes: u64,
    #[cfg(test)]
    stats: std::cell::Cell<DocStats>,
}

/// Work counters for the scaling tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct DocStats {
    opens: usize,
    applies: usize,
    rebuilds: usize,
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

    fn from_parts(me: Arc<DeviceKeys>, graph: SpaceGraph, ring: Keyring, store: Option<Arc<dyn Store>>) -> Self {
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
            doc_inputs: HashMap::new(),
            pending: HashSet::new(),
            index: reconcile::ChainIndex::default(),
            op_tips: std::sync::Mutex::new(None),
            stored_bytes: 0,
            #[cfg(test)]
            stats: Default::default(),
        }
    }

    /// Install (or replace) the L4 rules for feed entries; re-derives feeds.
    pub fn set_feed_validator(&mut self, v: Option<Arc<dyn FeedValidator>>) {
        self.validator = v;
        self.rule_rejected.clear();
        self.feeds.clear();
        let ids: Vec<EnvelopeId> = self
            .valid_by_stream
            .iter()
            .filter(|(stream, _)| stream.kind == StreamKind::Feed)
            .flat_map(|(_, ids)| ids.iter().copied())
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
        self.graph.state().members.values().map(|m| (m.keys, m.role)).collect()
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

    /// Encoded bytes of every envelope held.
    pub fn stored_bytes(&self) -> u64 {
        self.stored_bytes
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
        // Admission rule A3: at most `reconcile::WINDOW` seqs beyond the
        // author's chain held from its start (re-offered once the prefix
        // arrives; senders go in ascending seq, so honest data never waits).
        if !self.index.within_window(&env.header.author, env.header.author_seq) {
            return Err(SyncError::NotAllowed("beyond the author's chain window"));
        }
        env.verify_sig()?;
        self.persist_envelope(&env);
        self.chains.entry(env.header.author).or_default().entry(env.header.author_seq).or_default().push(id);
        self.index.insert(id, env.header.author, env.header.author_seq, env.header.author_prev);
        self.stored_bytes += reconcile::encoded_len(&env) as u64;
        self.envelopes.insert(id, env);
        Ok(Some(id))
    }

    /// Ingest many items at once (one graph resolution, one refresh).
    pub fn ingest_batch(&mut self, ops: Vec<SignedOp>, envelopes: Vec<Envelope>) -> Ingested {
        self.ingest_batch_refused(ops, envelopes).0
    }

    /// [`Replica::ingest_batch`], also returning the ids of envelopes refused
    /// for reasons intrinsic to the envelope (bad signature, too large,
    /// another space): they will never be accepted, whatever else arrives.
    /// Envelopes are staged in (author, seq) order, so a batch in any order
    /// extends chains from their start (admission rule A3).
    pub fn ingest_batch_refused(
        &mut self,
        ops: Vec<SignedOp>,
        mut envelopes: Vec<Envelope>,
    ) -> (Ingested, Vec<EnvelopeId>) {
        envelopes.sort_by_key(|e| (e.header.author, e.header.author_seq));
        let mut refused = Vec::new();
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
            let id = env.id();
            match self.stage_envelope(env) {
                Ok(Some(id)) => new_envs.push(id),
                Ok(None) => {}
                Err(e) => {
                    out.rejected += 1;
                    if !matches!(e, SyncError::NotAllowed(m) if m != "too many auth heads") {
                        refused.push(id);
                    }
                }
            }
        }
        out.envelopes = new_envs.len();
        if out.ops > 0 {
            self.graph.unlock(&self.me, &mut self.ring);
            self.full_refresh();
        } else if !new_envs.is_empty() {
            self.incremental(&new_envs);
        }
        (out, refused)
    }

    // ───────────── validation (no decryption) ─────────────

    pub fn status(&self, id: &EnvelopeId) -> Status {
        self.status.get(id).cloned().unwrap_or(Status::Pending("unknown envelope"))
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
        if !st.epoch(&h.epoch).is_some_and(|e| e.recipients.contains(&h.author)) {
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

    /// Membership changed: re-evaluate every envelope's status, then touch
    /// only what that can change — envelopes that became valid or decryptable,
    /// and documents that lost a change they had applied (or a fork candidate).
    fn full_refresh(&mut self) {
        let ids: Vec<EnvelopeId> = self.envelopes.keys().copied().collect();
        self.status = ids.iter().map(|id| (*id, self.compute_status(id))).collect();
        self.pending = self.status.iter().filter(|(_, s)| matches!(s, Status::Pending(_))).map(|(id, _)| *id).collect();
        let mut by_stream: HashMap<StreamId, BTreeSet<EnvelopeId>> = HashMap::new();
        for (id, st) in &self.status {
            if *st == Status::Valid {
                by_stream.entry(self.envelopes[id].header.stream).or_default().insert(*id);
            }
        }
        let streams: BTreeSet<StreamId> = by_stream.keys().chain(self.valid_by_stream.keys()).copied().collect();
        for stream in streams {
            let valid = by_stream.remove(&stream).unwrap_or_default();
            let old = self.valid_by_stream.insert(stream, valid).unwrap_or_default();
            let valid = &self.valid_by_stream[&stream];
            let lost: Vec<EnvelopeId> = old.difference(valid).copied().collect();
            if stream.kind == StreamKind::Feed {
                if !lost.is_empty() {
                    self.feeds.remove(&stream);
                }
                let ids: Vec<EnvelopeId> = valid.iter().copied().collect();
                for id in ids {
                    self.materialize(&id);
                }
                continue;
            }
            if lost.iter().any(|id| self.doc_input_matters(stream, id)) {
                self.rebuild_doc(stream);
                continue;
            }
            if let Some(inputs) = self.doc_inputs.get_mut(&stream) {
                for id in &lost {
                    if let Some(known) = inputs.known.remove(id)
                        && let Some(candidates) = inputs.slots.get_mut(&known.slot)
                    {
                        candidates.remove(id);
                        if candidates.is_empty() {
                            inputs.slots.remove(&known.slot);
                        }
                    }
                }
            }
            // Newly valid, or valid but previously undecryptable.
            let fresh: Vec<EnvelopeId> = valid
                .iter()
                .filter(|id| {
                    !self.doc_rejected.contains(id)
                        && !self.doc_inputs.get(&stream).is_some_and(|i| i.known.contains_key(id))
                        && self.ring.get(&self.envelopes[id].header.epoch).is_some()
                })
                .copied()
                .collect();
            if !fresh.is_empty() {
                self.process_doc(stream, fresh);
            }
        }
    }

    /// Would losing envelope `id` change `stream`'s materialization?
    fn doc_input_matters(&self, stream: StreamId, id: &EnvelopeId) -> bool {
        if self.docs.get(&stream).is_some_and(|d| d.applied.contains(id)) {
            return true;
        }
        self.doc_inputs.get(&stream).is_some_and(|inputs| {
            inputs.known.get(id).and_then(|k| inputs.slots.get(&k.slot)).is_some_and(|candidates| candidates.len() > 1)
        })
    }

    /// New envelopes arrived: evaluate them and anything pending that they may unblock.
    fn incremental(&mut self, new: &[EnvelopeId]) {
        // New envelopes have no status yet, so they are never in `pending`.
        let mut todo: Vec<EnvelopeId> = new.to_vec();
        todo.extend(self.pending.iter().copied());
        let mut docs: BTreeMap<StreamId, Vec<EnvelopeId>> = BTreeMap::new();
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
                    self.pending.remove(&id);
                    if stream.kind == StreamKind::Doc {
                        docs.entry(stream).or_default().push(id);
                    } else {
                        self.materialize(&id);
                    }
                    progressed = true;
                } else {
                    if matches!(st, Status::Pending(_)) {
                        self.pending.insert(id);
                        still.push(id);
                    } else {
                        self.pending.remove(&id);
                    }
                    self.status.insert(id, st);
                }
            }
            if !progressed || still.is_empty() {
                break;
            }
            todo = still;
        }
        // Each touched document is refreshed once for the whole batch.
        for (stream, ids) in docs {
            self.process_doc(stream, ids);
        }
    }

    /// Apply one valid feed entry, if we can decrypt it.
    fn materialize(&mut self, id: &EnvelopeId) {
        let env = &self.envelopes[id];
        let stream = env.header.stream;
        if stream.kind == StreamKind::Doc {
            self.process_doc(stream, vec![*id]);
            return;
        }
        if self.rule_rejected.contains(id) || self.feeds.get(&stream).is_some_and(|f| f.items.contains_key(id)) {
            return;
        }
        let Some(key) = self.ring.get(&env.header.epoch) else {
            return; // opaque (e.g. we are a keeper, or joined after this epoch)
        };
        let Ok(plain) = key.open(&env.header.nonce, &content_aad(&env.header), &env.ciphertext) else {
            return;
        };
        let Ok(entry) = postcard::from_bytes::<FeedEntry>(&plain) else {
            return;
        };
        let role = self.graph.state_at(&env.header.auth_heads).role(&env.header.author).unwrap_or(Role::Relay);
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
        self.feeds.entry(stream).or_default().insert(item);
    }

    /// Re-derive one document from its valid envelopes.
    fn rebuild_doc(&mut self, stream: StreamId) {
        let ids: Vec<EnvelopeId> =
            self.valid_by_stream.get(&stream).map(|ids| ids.iter().copied().collect()).unwrap_or_default();
        self.reset_doc(stream);
        self.process_doc(stream, ids);
    }

    fn reset_doc(&mut self, stream: StreamId) {
        #[cfg(test)]
        self.stats.set(DocStats { rebuilds: self.stats.get().rebuilds + 1, ..self.stats.get() });
        self.docs.remove(&stream);
        if let Some(inputs) = self.doc_inputs.remove(&stream) {
            for id in inputs.known.keys() {
                self.equivocated.remove(id);
            }
        }
    }

    fn doc_change(&self, id: &EnvelopeId) -> std::result::Result<Option<Change>, ()> {
        let env = &self.envelopes[id];
        let Some(key) = self.ring.get(&env.header.epoch) else {
            return Ok(None);
        };
        #[cfg(test)]
        self.stats.set(DocStats { opens: self.stats.get().opens + 1, ..self.stats.get() });
        let plain = key.open(&env.header.nonce, &content_aad(&env.header), &env.ciphertext).map_err(|_| ())?;
        let change = bounded_change::parse(&plain).map_err(|_| ())?;
        if change.actor_id().to_bytes() != env.header.author.0 {
            return Err(());
        }
        Ok(Some(change))
    }

    /// Bring a document up to date with newly valid (or newly decryptable)
    /// envelopes `ids`. Each envelope is decrypted and parsed once to learn
    /// its slot and dependencies, and once more when it can be applied; a
    /// change is validated once, against its declared history. Documents are
    /// rebuilt from scratch at most once per call (when a lower-id fork
    /// displaces an applied change), plus once per change that Automerge
    /// fails on after passing validation.
    fn process_doc(&mut self, stream: StreamId, mut ids: Vec<EnvelopeId>) {
        loop {
            let actor = ActorId::from(self.me.sign_pk().0.to_vec());
            let mut state = self.docs.remove(&stream).unwrap_or_else(|| DocState::new(actor));
            let mut inputs = self.doc_inputs.remove(&stream).unwrap_or_default();
            match self.doc_pass(&mut state, &mut inputs, ids) {
                DocFlow::Done => {
                    debug_assert_eq!(state.doc.get_heads().into_iter().collect::<HashSet<_>>(), state.index.heads());
                    if !state.index.is_empty() {
                        self.docs.insert(stream, state);
                    }
                    self.doc_inputs.insert(stream, inputs);
                    return;
                }
                DocFlow::Rebuild => {
                    #[cfg(test)]
                    self.stats.set(DocStats { rebuilds: self.stats.get().rebuilds + 1, ..self.stats.get() });
                    for id in inputs.known.keys() {
                        self.equivocated.remove(id);
                    }
                    ids =
                        self.valid_by_stream.get(&stream).map(|ids| ids.iter().copied().collect()).unwrap_or_default();
                }
            }
        }
    }

    fn doc_pass(&mut self, state: &mut DocState, inputs: &mut DocInputs, mut ids: Vec<EnvelopeId>) -> DocFlow {
        ids.sort_unstable();
        ids.dedup();
        // 1. Learn every new change's slot and dependencies, so fork selection
        //    sees the whole batch before anything is applied.
        let mut rebuild = false;
        let mut work = Vec::new();
        for id in ids {
            if self.doc_rejected.contains(&id) || inputs.known.contains_key(&id) {
                continue;
            }
            let change = match self.doc_change(&id) {
                Ok(Some(change)) => change,
                Ok(None) => continue,
                Err(()) => {
                    self.doc_rejected.insert(id);
                    continue;
                }
            };
            let slot = (change.actor_id().clone(), change.seq());
            let hash = change.hash();
            let before = inputs.winner(&slot);
            inputs.slots.entry(slot.clone()).or_default().insert(id, hash);
            // A lower-id fork of an applied change replaces it and everything
            // built on it: re-derive the document once, after this batch.
            rebuild |= before.is_some_and(|b| Some(b) != inputs.winner(&slot) && state.index.contains(&b));
            let mut missing: Vec<ChangeHash> =
                change.deps().iter().filter(|d| !state.index.contains(d)).copied().collect();
            missing.sort_unstable();
            missing.dedup();
            for dep in &missing {
                inputs.waiting.entry(*dep).or_default().push(id);
            }
            inputs.known.insert(id, Known { hash, slot: slot.clone(), missing: missing.len() });
            self.mark_forks(inputs, &slot);
            work.push(id);
        }
        if rebuild {
            return DocFlow::Rebuild;
        }
        // 2. Validate whatever is ready against the causal index, waking
        //    dependents as their dependencies are admitted.
        let mut batch: Vec<(EnvelopeId, Change)> = Vec::new();
        let mut batch_ops = 0;
        work.reverse();
        while let Some(id) = work.pop() {
            let Some(known) = inputs.known.get(&id) else { continue };
            let hash = known.hash;
            if state.index.contains(&hash) {
                state.applied.insert(id);
                continue;
            }
            if known.missing > 0 || inputs.winner(&known.slot) != Some(hash) {
                continue;
            }
            let admitted = match self.doc_change(&id) {
                Ok(Some(change)) => state.index.admit(&change).map(|a| (a, change)),
                _ => None,
            };
            let Some((admitted, change)) = admitted else {
                self.reject_doc_input(inputs, id, &mut work);
                continue;
            };
            state.index.insert(admitted);
            for (other, h) in &inputs.slots[&inputs.known[&id].slot] {
                if *h == hash {
                    state.applied.insert(*other);
                }
            }
            for waiter in inputs.waiting.remove(&hash).unwrap_or_default() {
                if let Some(k) = inputs.known.get_mut(&waiter) {
                    k.missing -= 1;
                    if k.missing == 0 {
                        work.push(waiter);
                    }
                }
            }
            batch_ops += change.len();
            batch.push((id, change));
            // 3. Hand validated changes to Automerge in bounded batches.
            if batch_ops >= APPLY_BATCH_OPS && !self.apply_doc_batch(state, std::mem::take(&mut batch)) {
                return DocFlow::Rebuild;
            }
            if batch.is_empty() {
                batch_ops = 0;
            }
        }
        if !batch.is_empty() && !self.apply_doc_batch(state, batch) {
            return DocFlow::Rebuild;
        }
        DocFlow::Done
    }

    /// Apply validated changes to a copy of the document (copies share
    /// storage, so this is cheap) and keep it only if everything applied.
    /// Validation makes failure an Automerge bug; if it happens anyway, find
    /// the changes Automerge cannot apply, reject them, and report that the
    /// document must be re-derived.
    fn apply_doc_batch(&mut self, state: &mut DocState, batch: Vec<(EnvelopeId, Change)>) -> bool {
        fn apply(doc: &AutoCommit, changes: Vec<Change>) -> Option<AutoCommit> {
            let mut candidate = doc.clone();
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                candidate.apply_changes(changes).is_ok() && candidate.get_missing_deps(&[]).is_empty()
            }));
            matches!(ok, Ok(true)).then_some(candidate)
        }
        #[cfg(test)]
        self.stats.set(DocStats { applies: self.stats.get().applies + 1, ..self.stats.get() });
        if let Some(doc) = apply(&state.doc, batch.iter().map(|(_, c)| c.clone()).collect()) {
            state.doc = doc;
            return true;
        }
        let mut doc = state.doc.clone();
        let mut failed = HashSet::new();
        for (id, change) in batch {
            if change.deps().iter().any(|d| failed.contains(d)) {
                failed.insert(change.hash());
                continue;
            }
            let hash = change.hash();
            match apply(&doc, vec![change]) {
                Some(next) => doc = next,
                None => {
                    failed.insert(hash);
                    self.doc_rejected.insert(id);
                }
            }
        }
        false
    }

    /// `id`'s change is invalid: reject every envelope carrying it, and let
    /// the next fork in its slot (if any) take its place.
    fn reject_doc_input(&mut self, inputs: &mut DocInputs, id: EnvelopeId, work: &mut Vec<EnvelopeId>) {
        let Some(known) = inputs.known.remove(&id) else { return };
        let slot = known.slot;
        let before = inputs.winner(&slot);
        let mut carriers = vec![id];
        if let Some(candidates) = inputs.slots.get_mut(&slot) {
            candidates.retain(|other, h| {
                let same = *h == known.hash;
                if same {
                    carriers.push(*other);
                }
                !same
            });
            if candidates.is_empty() {
                inputs.slots.remove(&slot);
            }
        }
        for carrier in carriers {
            inputs.known.remove(&carrier);
            self.equivocated.remove(&carrier);
            self.doc_rejected.insert(carrier);
        }
        if let Some(winner) = inputs.winner(&slot).filter(|w| Some(*w) != before) {
            work.extend(inputs.slots[&slot].iter().filter(|(_, h)| **h == winner).map(|(id, _)| *id));
        }
        self.mark_forks(inputs, &slot);
    }

    /// Record which candidates of `slot` lose to its lowest-id envelope.
    fn mark_forks(&mut self, inputs: &DocInputs, slot: &Slot) {
        let Some(candidates) = inputs.slots.get(slot) else { return };
        let winner = inputs.winner(slot);
        for (id, hash) in candidates {
            if Some(*hash) == winner {
                self.equivocated.remove(id);
            } else {
                self.equivocated.insert(*id);
            }
        }
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
        self.feed_changes(feed, FeedCursor::default()).items
    }

    /// What changed in a feed since `since` (`FeedCursor::default()`: all of
    /// it), and the cursor to pass next time. Costs O(what changed): a new
    /// entry usually lands at the end, so a reader applies just that.
    pub fn feed_changes(&mut self, feed: &StreamId, since: FeedCursor) -> FeedChanges {
        match self.feeds.get_mut(feed) {
            Some(f) => f.changes_since(since),
            None => FeedChanges::default(),
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
        self.seal_at(stream, epoch, plaintext, seq, prev)
    }

    fn seal_at(
        &self,
        stream: StreamId,
        epoch: EpochId,
        plaintext: &[u8],
        author_seq: u64,
        author_prev: Option<EnvelopeId>,
    ) -> Result<Envelope> {
        let header = Header {
            space: self.space_id(),
            stream,
            author: self.me.sign_pk(),
            author_seq,
            author_prev,
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
    /// An edit larger than one change may carry (`MAX_LOCAL_CHANGE_*`, e.g. a
    /// multi-megabyte paste) is written as several consecutive changes, each
    /// in its own envelope; all are stored and synced, and the last one is
    /// returned.
    ///
    /// The local role isn't pre-checked: a Reader's change is produced and
    /// signed like any other, and every honest peer — including ourselves —
    /// rejects it. Apps should check `my_role()` first for UX. A rejected or
    /// failed edit leaves the document as it was.
    pub fn change(
        &mut self,
        doc: StreamId,
        edit: impl FnOnce(&mut AutoCommit) -> std::result::Result<(), automerge::AutomergeError>,
    ) -> Result<(Vec<SignedOp>, Option<Envelope>)> {
        debug_assert_eq!(doc.kind, StreamKind::Doc);
        let (ops, epoch) = self.write_epoch()?;
        let actor = ActorId::from(self.me.sign_pk().0.to_vec());
        let mut state = self.docs.remove(&doc).unwrap_or_else(|| DocState::new(actor));
        // Copies share storage: keeping one to roll back to is cheap.
        let snapshot = state.doc.clone();
        let checkpoint = state.index.checkpoint();
        let sealed = Self::commit_local(&mut state, &snapshot, edit).and_then(|mut parts| {
            let (mut seq, mut prev) = self.my_chain_tip();
            let mut envelopes = Vec::with_capacity(parts.len());
            for part in &mut parts {
                let env = self.seal_at(doc, epoch, &part.bytes(), seq, prev)?;
                seq += 1;
                prev = Some(env.id());
                envelopes.push(env);
            }
            Ok((parts, envelopes))
        });
        let (parts, mut envelopes) = match sealed {
            Ok(sealed) => sealed,
            Err(err) => {
                state.doc = snapshot;
                state.index.rollback(checkpoint);
                self.put_doc(doc, state);
                return Err(err);
            }
        };
        let mut staged = Vec::new();
        let mut error = None;
        for env in &envelopes {
            match self.stage_envelope(env.clone()) {
                Ok(Some(id)) => staged.push(id),
                Ok(None) => {}
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        // The change is already in the local document (Automerge applied it
        // while editing, and the index validated it once): keep it if its
        // envelopes are valid, otherwise roll back to the valid set.
        let keep = error.is_none()
            && staged.len() == parts.len()
            && staged.iter().all(|id| self.compute_status(id) == Status::Valid);
        if keep {
            let inputs = self.doc_inputs.entry(doc).or_default();
            for (id, part) in staged.iter().zip(&parts) {
                let slot = (part.actor_id().clone(), part.seq());
                inputs.slots.entry(slot.clone()).or_default().insert(*id, part.hash());
                inputs.known.insert(*id, Known { hash: part.hash(), slot, missing: 0 });
                state.applied.insert(*id);
            }
            let forked = parts.iter().any(|p| inputs.winner(&(p.actor_id().clone(), p.seq())) != Some(p.hash()));
            self.put_doc(doc, state);
            if forked {
                // Another envelope already holds one of our slots (e.g. this
                // key wrote from a restored device): keep the canonical fork.
                self.rebuild_doc(doc);
            }
        } else {
            state.doc = snapshot;
            state.index.rollback(checkpoint);
            self.put_doc(doc, state);
        }
        self.incremental(&staged);
        match error {
            Some(err) => Err(err),
            None => Ok((ops, envelopes.pop())),
        }
    }

    fn put_doc(&mut self, doc: StreamId, state: DocState) {
        if !state.index.is_empty() {
            self.docs.insert(doc, state);
        }
    }

    /// Run `edit`, commit it, and validate the result as one change, or as
    /// several when it is too large for one. Returns the committed changes,
    /// already part of `state` (index included).
    fn commit_local(
        state: &mut DocState,
        before: &AutoCommit,
        edit: impl FnOnce(&mut AutoCommit) -> std::result::Result<(), automerge::AutomergeError>,
    ) -> Result<Vec<Change>> {
        edit(&mut state.doc)?;
        let Some(hash) = state.doc.commit() else { return Ok(Vec::new()) };
        let change = state.doc.get_last_local_change().filter(|c| c.hash() == hash).ok_or(SyncError::Encoding)?;
        let parts = if bounded_change::within(change.raw_bytes(), &change_resources::WRITE).is_ok() {
            vec![change]
        } else {
            let parts = split_change(&change)?;
            let mut doc = before.clone();
            let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                doc.apply_changes(parts.clone()).is_ok() && doc.get_missing_deps(&[]).is_empty()
            }));
            if !matches!(applied, Ok(true)) {
                return Err(SyncError::Encoding);
            }
            state.doc = doc;
            parts
        };
        for part in &parts {
            let admitted = state.index.admit(part).ok_or(SyncError::Encoding)?;
            state.index.insert(admitted);
        }
        Ok(parts)
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
        match self.chains.get(&self.me.sign_pk()).and_then(|c| c.iter().next_back()) {
            Some((seq, ids)) => (seq + 1, ids.first().copied()),
            None => (0, None),
        }
    }

    /// Latest envelope we've seen from `pk` (used as a revocation cutoff).
    pub fn latest_from(&self, pk: &SignPk) -> Option<EnvelopeId> {
        self.chains.get(pk).and_then(|c| c.iter().next_back()).and_then(|(_, ids)| ids.first().copied())
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
            .filter(|(id, s)| **s == Status::Valid && self.ring.get(&self.envelopes[*id].header.epoch).is_none())
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

/// Split one local change into consecutive changes within the write limits.
/// Operation ids are preserved (each part starts where the previous ended and
/// depends on it), so references between operations stay valid; Automerge's
/// own encoder produces each part.
fn split_change(change: &Change) -> Result<Vec<Change>> {
    let mut template = change.decode();
    let ops = std::mem::take(&mut template.operations);
    let estimate = |op: &automerge::legacy::Op| {
        let value = match &op.action {
            automerge::legacy::OpType::Put(automerge::ScalarValue::Str(s)) => s.len(),
            automerge::legacy::OpType::Put(automerge::ScalarValue::Bytes(b)) => b.len(),
            _ => 8,
        };
        let key = match &op.key {
            automerge::legacy::Key::Map(k) => k.len(),
            _ => 0,
        };
        2 + value + key
    };
    let mut parts: Vec<Change> = Vec::new();
    let (mut start, mut seq, mut start_op) = (0, template.seq, template.start_op.get());
    let mut deps = template.deps.clone();
    while start < ops.len() {
        let mut end = start;
        let mut bytes = 0;
        while end < ops.len() && end - start < MAX_LOCAL_CHANGE_OPS {
            bytes += estimate(&ops[end]);
            if bytes > MAX_LOCAL_CHANGE_BYTES / 2 && end > start {
                break;
            }
            end += 1;
        }
        let part = loop {
            let first = parts.is_empty();
            let candidate = Change::from(automerge::ExpandedChange {
                operations: ops[start..end].to_vec(),
                actor_id: template.actor_id.clone(),
                hash: None,
                seq,
                start_op: std::num::NonZeroU64::new(start_op).ok_or(SyncError::Encoding)?,
                time: template.time,
                message: if first { template.message.clone() } else { None },
                deps: deps.clone(),
                extra_bytes: if first { template.extra_bytes.clone() } else { Vec::new() },
                author: if first { template.author.clone() } else { None },
            });
            if bounded_change::within(candidate.raw_bytes(), &change_resources::WRITE).is_ok() {
                break candidate;
            }
            if end - start == 1 {
                return Err(SyncError::TooLarge); // one operation too large: use a blob
            }
            end = start + (end - start) / 2;
        };
        deps = vec![part.hash()];
        seq += 1;
        start_op += (end - start) as u64;
        start = end;
        parts.push(part);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests;
