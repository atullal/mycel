//! Mycel data & sync v0 (docs/TRUST.md §7): signed, encrypted envelopes of
//! Automerge changes, validated without decryption, materialized into docs.
//!
//! A [`Replica`] is one device's view of one Space: the membership graph, the
//! device's keyring, every envelope it holds, and the documents it can decrypt.
//! Keepers run the same `Replica` with the Relay role: they validate and store
//! envelopes but hold no keys, so they never materialize documents.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use automerge::{ActorId, AutoCommit, Change};
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, Sig, SignPk, random};
use mycel_trust::{EpochId, Inserted, Keyring, OpId, Role, SignedOp, SpaceGraph, SpaceId};
use serde::{Deserialize, Serialize};

pub use automerge;
pub use mycel_trust;

pub type EnvelopeId = Hash32;

const CTX_ENV_SIG: &str = "mycel/v0/envelope";
const CTX_ENV_ID: &str = "mycel/v0/envelope-id";
const CTX_CONTENT_AAD: &str = "mycel/v0/content";

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
    #[error("encoding error")]
    Encoding,
    #[error("not allowed: {0}")]
    NotAllowed(&'static str),
    #[error("unknown document")]
    UnknownDoc,
}

pub type Result<T> = std::result::Result<T, SyncError>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DocId(pub [u8; 16]);

impl std::fmt::Debug for DocId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "doc:{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub space: SpaceId,
    pub doc: DocId,
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

fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).expect("encodes")
}

fn content_aad(header: &Header) -> Vec<u8> {
    [CTX_CONTENT_AAD.as_bytes(), &encode(header)].concat()
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

/// Why an envelope is (not yet) part of the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Valid,
    Pending(&'static str),
    Invalid(&'static str),
}

struct DocState {
    doc: AutoCommit,
    applied: BTreeSet<EnvelopeId>,
}

/// One device's replica of one Space.
pub struct Replica {
    me: Arc<DeviceKeys>,
    graph: SpaceGraph,
    ring: Keyring,
    envelopes: HashMap<EnvelopeId, Envelope>,
    /// author → seq → envelope ids (more than one = equivocation)
    chains: HashMap<SignPk, BTreeMap<u64, Vec<EnvelopeId>>>,
    docs: HashMap<DocId, DocState>,
}

impl Replica {
    /// Found a new Space.
    pub fn create(me: Arc<DeviceKeys>) -> Result<(Self, SignedOp)> {
        let (graph, genesis, epoch, key) = SpaceGraph::create(&me)?;
        let mut ring = Keyring::default();
        ring.insert(epoch, key);
        Ok((Self::from_parts(me, graph, ring), genesis))
    }

    /// Join (or relay) an existing Space given its genesis op.
    pub fn join(me: Arc<DeviceKeys>, genesis: SignedOp) -> Result<Self> {
        let graph = SpaceGraph::from_genesis(genesis)?;
        Ok(Self::from_parts(me, graph, Keyring::default()))
    }

    fn from_parts(me: Arc<DeviceKeys>, graph: SpaceGraph, ring: Keyring) -> Self {
        Replica {
            me,
            graph,
            ring,
            envelopes: HashMap::new(),
            chains: HashMap::new(),
            docs: HashMap::new(),
        }
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

    // ───────────── network-facing ─────────────

    pub fn op_ids(&self) -> Vec<OpId> {
        self.graph.op_ids()
    }

    pub fn op(&self, id: &OpId) -> Option<&SignedOp> {
        self.graph.get(id)
    }

    pub fn envelope_ids(&self) -> Vec<EnvelopeId> {
        self.envelopes.keys().copied().collect()
    }

    pub fn envelope(&self, id: &EnvelopeId) -> Option<&Envelope> {
        self.envelopes.get(id)
    }

    /// Ingest a membership op from anyone. Returns true if it was new.
    pub fn ingest_op(&mut self, op: SignedOp) -> Result<bool> {
        let new = self.graph.insert(op)? == Inserted::New;
        if new {
            self.graph.unlock(&self.me, &mut self.ring);
            // Membership changed: validity of any envelope may have changed.
            self.refresh_all();
        }
        Ok(new)
    }

    /// Ingest an envelope from anyone. Only signature + space are checked here;
    /// validity is re-evaluated on every refresh so all peers converge.
    pub fn ingest_envelope(&mut self, env: Envelope) -> Result<bool> {
        if env.header.space != self.space_id() {
            return Err(SyncError::WrongSpace);
        }
        let id = env.id();
        if self.envelopes.contains_key(&id) {
            return Ok(false);
        }
        env.verify_sig()?;
        self.chains
            .entry(env.header.author)
            .or_default()
            .entry(env.header.author_seq)
            .or_default()
            .push(id);
        self.envelopes.insert(id, env);
        self.refresh_all();
        Ok(true)
    }

    // ───────────── validation (no decryption) ─────────────

    pub fn status(&self, id: &EnvelopeId) -> Status {
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
                Some(p) if p.header.author != h.author || p.header.author_seq + 1 != seq => {
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

    fn refresh_all(&mut self) {
        let mut by_doc: HashMap<DocId, BTreeSet<EnvelopeId>> = HashMap::new();
        for (id, env) in &self.envelopes {
            if self.status(id) == Status::Valid && self.ring.get(&env.header.epoch).is_some() {
                by_doc.entry(env.header.doc).or_default().insert(*id);
            }
        }
        let docs: BTreeSet<DocId> = by_doc.keys().chain(self.docs.keys()).copied().collect();
        for doc in docs {
            let valid = by_doc.remove(&doc).unwrap_or_default();
            self.refresh_doc(doc, valid);
        }
    }

    fn decrypt(&self, id: &EnvelopeId) -> Option<Change> {
        let env = self.envelopes.get(id)?;
        let key = self.ring.get(&env.header.epoch)?;
        let plain = key
            .open(&env.header.nonce, &content_aad(&env.header), &env.ciphertext)
            .ok()?;
        let change = Change::from_bytes(plain).ok()?;
        // An author may only write under their own actor id.
        (change.actor_id().to_bytes() == env.header.author.0).then_some(change)
    }

    fn refresh_doc(&mut self, doc: DocId, valid: BTreeSet<EnvelopeId>) {
        let actor = ActorId::from(self.me.sign_pk().0.to_vec());
        let rebuild = self
            .docs
            .get(&doc)
            .is_none_or(|d| !d.applied.is_subset(&valid));
        let mut state = if rebuild {
            DocState {
                doc: AutoCommit::new().with_actor(actor),
                applied: BTreeSet::new(),
            }
        } else {
            self.docs.remove(&doc).unwrap()
        };
        let mut batch = Vec::new();
        for id in valid.difference(&state.applied.clone()) {
            // Undecryptable envelopes and forged actors are never applied.
            if let Some(change) = self.decrypt(id) {
                batch.push(change);
                state.applied.insert(*id);
            }
        }
        if !batch.is_empty() {
            // Automerge queues changes whose deps haven't arrived yet.
            let _ = state.doc.apply_changes(batch);
        }
        self.docs.insert(doc, state);
    }

    // ───────────── app-facing ─────────────

    pub fn new_doc_id() -> DocId {
        DocId(random())
    }

    pub fn doc(&self, doc: &DocId) -> Option<&AutoCommit> {
        self.docs.get(doc).map(|d| &d.doc)
    }

    pub fn doc_json(&self, doc: &DocId) -> serde_json::Value {
        match self.docs.get(doc) {
            Some(d) => serde_json::to_value(automerge::AutoSerde::from(&d.doc)).unwrap_or_default(),
            None => serde_json::Value::Null,
        }
    }

    pub fn doc_ids(&self) -> Vec<DocId> {
        self.docs.keys().copied().collect()
    }

    /// Edit a document locally. Returns the ops (a self-healing rotation, if
    /// needed) and the envelope to broadcast.
    ///
    /// This does not check the local role: a Reader's change is produced and
    /// signed like any other, and every honest peer — including ourselves —
    /// rejects it. Apps should check `my_role()` first for UX.
    pub fn change(
        &mut self,
        doc: DocId,
        edit: impl FnOnce(&mut AutoCommit) -> std::result::Result<(), automerge::AutomergeError>,
    ) -> Result<(Vec<SignedOp>, Option<Envelope>)> {
        let mut ops = Vec::new();
        let epoch = match self.graph.state().write_epoch() {
            Some(e) if self.ring.get(&e).is_some() => e,
            _ => {
                // TRUST.md §6: no usable epoch → rotate first (needs Writer).
                let (op, epoch, key) = self.graph.rotate(&self.me)?;
                self.ring.insert(epoch, key);
                self.ingest_op(op.clone())?;
                ops.push(op);
                epoch
            }
        };
        let actor = ActorId::from(self.me.sign_pk().0.to_vec());
        let state = self.docs.entry(doc).or_insert_with(|| DocState {
            doc: AutoCommit::new().with_actor(actor),
            applied: BTreeSet::new(),
        });
        edit(&mut state.doc)?;
        state.doc.commit();
        let Some(mut change) = state.doc.get_last_local_change() else {
            return Ok((ops, None));
        };
        let plaintext = change.bytes().to_vec();
        let (seq, prev) = self.my_chain_tip();
        let header = Header {
            space: self.space_id(),
            doc,
            author: self.me.sign_pk(),
            author_seq: seq,
            author_prev: prev,
            auth_heads: self.graph.heads(),
            epoch,
            nonce: random(),
        };
        let key = self.ring.get(&epoch).expect("epoch key present");
        let ciphertext = key.seal(&header.nonce, &content_aad(&header), &plaintext)?;
        let sig = self
            .me
            .sign(CTX_ENV_SIG, &[&encode(&header), &ciphertext]);
        let env = Envelope {
            header,
            ciphertext,
            sig,
        };
        // Our own change goes through the same validation path as anyone else's.
        // Mark it applied (it already is, locally) only if it validates.
        let id = env.id();
        self.ingest_envelope(env.clone())?;
        if self.status(&id) != Status::Valid {
            // Roll the local doc back to the valid set.
            self.docs.remove(&doc);
            self.refresh_all();
        }
        Ok((ops, Some(env)))
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
        self.envelopes
            .iter()
            .filter(|(id, e)| {
                self.status(id) == Status::Valid && self.ring.get(&e.header.epoch).is_none()
            })
            .count()
    }
}

#[cfg(test)]
mod tests;
