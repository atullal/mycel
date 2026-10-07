//! Mycel trust layer v0 (docs/TRUST.md §3–§6).
//!
//! A Space is a DAG of signed membership ops. Every peer resolves the DAG with
//! the same deterministic algorithm, so peers holding the same ops agree on
//! membership, roles and encryption epochs.

mod bitset;
mod resolve;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use mycel_crypto::{
    CryptoError, DeviceKeys, Hash32, Lockbox, MemberKeys, Sig, SignPk, SymKey,
    random_u64, seal_lockbox,
};
use serde::{Deserialize, Serialize};

pub use resolve::Resolution;

pub type OpId = Hash32;
pub type SpaceId = Hash32;

const CTX_OP_SIG: &str = "mycel/v0/op";

/// Resource limits (DoS hardening). Generous for real groups.
pub const MAX_PARENTS: usize = 64;
pub const MAX_MEMBERS: usize = 1024;
pub const MAX_PENDING: usize = 4096;
const STATE_CACHE_MAX: usize = 1024;
const CTX_OP_ID: &str = "mycel/v0/op-id";
const CTX_LOCKBOX: &str = "mycel/v0/lockbox";
const CTX_KEYRING: &str = "mycel/v0/keyring";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("encoding error")]
    Encoding,
    #[error("op belongs to a different space")]
    WrongSpace,
    #[error("malformed op: {0}")]
    Malformed(&'static str),
    #[error("not authorized: {0}")]
    NotAuthorized(&'static str),
}

pub type Result<T> = std::result::Result<T, TrustError>;

/// 128-bit epoch identifier, derived from the key commitment so two rotations
/// can only share an id if they share the key (no epoch-id collisions).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EpochId(pub [u8; 16]);

impl EpochId {
    pub fn for_commitment(c: &Hash32) -> Self {
        let h = Hash32::digest("mycel/v0/epoch-id", &c.0);
        EpochId(h.0[..16].try_into().unwrap())
    }
}

impl std::fmt::Debug for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch:{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Keepers: store and forward ciphertext, never hold keys.
    Relay,
    Reader,
    Writer,
    Admin,
}

impl Role {
    pub fn can_read(self) -> bool {
        self >= Role::Reader
    }
    pub fn can_write(self) -> bool {
        self >= Role::Writer
    }
    pub fn is_admin(self) -> bool {
        self == Role::Admin
    }
}

/// A fresh epoch key sealed to every recipient (sorted by recipient key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    pub epoch: EpochId,
    pub commitment: Hash32,
    pub lockboxes: Vec<(SignPk, Lockbox)>,
}

/// Marks a capability-reducing op (TRUST.md §5 step 3, §7 rule 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Latest envelope by the revoked member that the revoker had seen.
    pub cutoff: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Genesis {
        founder: MemberKeys,
        rotation: Rotation,
    },
    Add {
        member: MemberKeys,
        role: Role,
        /// All epoch keys the adder could see, sealed to the new member (readers only).
        keyring: Option<Lockbox>,
    },
    SetRole {
        member: SignPk,
        role: Role,
        /// Must be `Some` iff this is a downgrade.
        revocation: Option<Revocation>,
        /// Required iff the member loses read access.
        rotation: Option<Rotation>,
    },
    Remove {
        member: SignPk,
        revocation: Revocation,
        rotation: Rotation,
    },
    Rotate {
        rotation: Rotation,
    },
    /// The author leaves voluntarily. No rotation (the leaver must not pick
    /// the next key): no epoch then matches the remaining readers, so the next
    /// writer rotates automatically (TRUST.md §6). It is a revocation of the
    /// author with `cutoff` = their own last envelope, so whoever holds the
    /// device afterwards can't keep posting with backdated `auth_heads`.
    Leave { cutoff: Option<Hash32> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    pub space: Option<SpaceId>,
    pub parents: Vec<OpId>,
    pub author: SignPk,
    pub nonce: u64,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOp {
    pub op: Op,
    pub sig: Sig,
}

impl SignedOp {
    pub fn sign(keys: &DeviceKeys, op: Op) -> Self {
        let body = postcard::to_allocvec(&op).expect("op encodes");
        let sig = keys.sign(CTX_OP_SIG, &[&body]);
        SignedOp { op, sig }
    }

    pub fn id(&self) -> OpId {
        Hash32::digest(CTX_OP_ID, &postcard::to_allocvec(self).expect("op encodes"))
    }

    /// Signature + structural checks that need no graph context.
    pub fn verify_standalone(&self) -> Result<()> {
        let body = postcard::to_allocvec(&self.op).map_err(|_| TrustError::Encoding)?;
        self.op.author.verify(CTX_OP_SIG, &[&body], &self.sig)?;
        if self.op.parents.len() > MAX_PARENTS {
            return Err(TrustError::Malformed("too many parents"));
        }
        let mut parents = self.op.parents.clone();
        parents.sort();
        parents.dedup();
        if parents.len() != self.op.parents.len() {
            return Err(TrustError::Malformed("duplicate parents"));
        }
        let check_rotation = |r: &Rotation| -> Result<()> {
            if r.epoch != EpochId::for_commitment(&r.commitment) {
                return Err(TrustError::Malformed("epoch id must derive from commitment"));
            }
            if r.lockboxes.len() > MAX_MEMBERS {
                return Err(TrustError::Malformed("too many lockboxes"));
            }
            let sorted = r.lockboxes.windows(2).all(|w| w[0].0 < w[1].0);
            if !sorted {
                return Err(TrustError::Malformed("lockboxes must be sorted and unique"));
            }
            Ok(())
        };
        match &self.op.action {
            Action::Genesis { founder, rotation } => {
                if self.op.space.is_some() || !self.op.parents.is_empty() {
                    return Err(TrustError::Malformed("genesis has no space and no parents"));
                }
                if founder.sign_pk != self.op.author {
                    return Err(TrustError::Malformed("genesis author must be founder"));
                }
                founder.verify_binding()?;
                check_rotation(rotation)?;
            }
            other => {
                if self.op.space.is_none() || self.op.parents.is_empty() {
                    return Err(TrustError::Malformed("non-genesis op needs space and parents"));
                }
                match other {
                    Action::Add { member, role, keyring } => {
                        member.verify_binding()?;
                        if role.can_read() != keyring.is_some() {
                            return Err(TrustError::Malformed("keyring iff reader"));
                        }
                    }
                    Action::SetRole { rotation: Some(r), .. }
                    | Action::Remove { rotation: r, .. }
                    | Action::Rotate { rotation: r } => check_rotation(r)?,
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// HPKE `info` for an epoch lockbox: binds epoch and recipient.
fn lockbox_info(epoch: &EpochId, recipient: &SignPk) -> Vec<u8> {
    [CTX_LOCKBOX.as_bytes(), &epoch.0, &recipient.0].concat()
}

fn keyring_info(space: &SpaceId, nonce: u64, recipient: &SignPk) -> Vec<u8> {
    [
        CTX_KEYRING.as_bytes(),
        &space.0,
        &nonce.to_le_bytes(),
        &recipient.0,
    ]
    .concat()
}

/// Generate a new epoch key sealed to exactly `recipients`.
pub fn new_rotation<'a>(
    recipients: impl IntoIterator<Item = &'a MemberKeys>,
) -> Result<(Rotation, SymKey)> {
    let key = SymKey::generate();
    let epoch = EpochId::for_commitment(&key.commitment());
    let mut lockboxes = recipients
        .into_iter()
        .map(|m| {
            let lb = seal_lockbox(&m.kex_pk, &lockbox_info(&epoch, &m.sign_pk), &key.0)?;
            Ok((m.sign_pk, lb))
        })
        .collect::<Result<Vec<_>>>()?;
    lockboxes.sort_by_key(|(pk, _)| *pk);
    Ok((
        Rotation {
            epoch,
            commitment: key.commitment(),
            lockboxes,
        },
        key,
    ))
}

// ─────────────────────────── membership state ───────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub keys: MemberKeys,
    pub role: Role,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub id: EpochId,
    pub commitment: Hash32,
    pub created_by: OpId,
    pub recipients: BTreeSet<SignPk>,
}

/// Membership + epochs after replaying a set of valid ops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberState {
    pub members: BTreeMap<SignPk, Member>,
    /// In creation (topological) order.
    pub epochs: Vec<Epoch>,
}

impl MemberState {
    pub fn role(&self, pk: &SignPk) -> Option<Role> {
        self.members.get(pk).map(|m| m.role)
    }

    pub fn readers(&self) -> BTreeSet<SignPk> {
        self.members
            .iter()
            .filter(|(_, m)| m.role.can_read())
            .map(|(pk, _)| *pk)
            .collect()
    }

    pub fn epoch(&self, id: &EpochId) -> Option<&Epoch> {
        self.epochs.iter().find(|e| &e.id == id)
    }

    /// TRUST.md §6: the latest epoch whose recipients are exactly the current readers.
    pub fn write_epoch(&self) -> Option<EpochId> {
        let readers = self.readers();
        self.epochs
            .iter()
            .rev()
            .find(|e| e.recipients == readers)
            .map(|e| e.id)
    }

    fn admin_count(&self) -> usize {
        self.members.values().filter(|m| m.role.is_admin()).count()
    }
}

// ─────────────────────────────── keyring ───────────────────────────────

/// Local, secret: the epoch keys this device has unlocked.
#[derive(Default)]
pub struct Keyring {
    keys: HashMap<EpochId, SymKey>,
}

impl Keyring {
    pub fn get(&self, epoch: &EpochId) -> Option<&SymKey> {
        self.keys.get(epoch)
    }
    pub fn insert(&mut self, epoch: EpochId, key: SymKey) {
        self.keys.insert(epoch, key);
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ───────────────────────────── space graph ─────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Inserted {
    New,
    Duplicate,
    /// Stored, but waits for missing parents.
    Pending,
}

/// The membership DAG of one Space plus its cached resolution.
pub struct SpaceGraph {
    space: SpaceId,
    ops: HashMap<OpId, SignedOp>,
    pending: HashMap<OpId, SignedOp>,
    res: Resolution,
    state_cache: Mutex<HashMap<Vec<OpId>, MemberState>>,
}

impl SpaceGraph {
    /// Create a new Space. Returns the graph, the genesis op and the epoch-0 key.
    pub fn create(founder: &DeviceKeys) -> Result<(Self, SignedOp, EpochId, SymKey)> {
        let me = founder.public();
        let (rotation, key) = new_rotation([&me])?;
        let epoch = rotation.epoch;
        let genesis = SignedOp::sign(
            founder,
            Op {
                space: None,
                parents: vec![],
                author: me.sign_pk,
                nonce: random_u64(),
                action: Action::Genesis {
                    founder: me,
                    rotation,
                },
            },
        );
        let graph = Self::from_genesis(genesis.clone())?;
        Ok((graph, genesis, epoch, key))
    }

    pub fn from_genesis(genesis: SignedOp) -> Result<Self> {
        genesis.verify_standalone()?;
        if !matches!(genesis.op.action, Action::Genesis { .. }) {
            return Err(TrustError::Malformed("first op must be genesis"));
        }
        let space = genesis.id();
        let mut ops = HashMap::new();
        ops.insert(space, genesis);
        let res = resolve::resolve(&ops);
        Ok(SpaceGraph {
            space,
            ops,
            pending: HashMap::new(),
            res,
            state_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn space_id(&self) -> SpaceId {
        self.space
    }

    pub fn contains(&self, id: &OpId) -> bool {
        self.ops.contains_key(id) || self.pending.contains_key(id)
    }

    pub fn op_ids(&self) -> Vec<OpId> {
        self.ops.keys().chain(self.pending.keys()).copied().collect()
    }

    pub fn get(&self, id: &OpId) -> Option<&SignedOp> {
        self.ops.get(id).or_else(|| self.pending.get(id))
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Verify and add an op received from anyone. Validity (authorization) is
    /// decided by resolution, not here: invalid-but-well-formed ops are kept so
    /// that every peer converges on the same DAG.
    pub fn insert(&mut self, op: SignedOp) -> Result<Inserted> {
        let id = op.id();
        if self.contains(&id) {
            return Ok(Inserted::Duplicate);
        }
        self.stage(op)?;
        let promoted = self.promote_pending();
        if promoted.contains(&id) {
            self.reresolve();
            Ok(Inserted::New)
        } else {
            Ok(Inserted::Pending)
        }
    }

    /// Insert many ops, resolving the graph once. Bad ops are skipped and
    /// reported; returns (ids that became part of the graph, rejected count).
    pub fn insert_many(&mut self, ops: impl IntoIterator<Item = SignedOp>) -> (Vec<OpId>, usize) {
        let mut rejected = 0;
        for op in ops {
            if self.contains(&op.id()) {
                continue;
            }
            if self.stage(op).is_err() {
                rejected += 1;
            }
        }
        let promoted: Vec<OpId> = self.promote_pending().into_iter().collect();
        if !promoted.is_empty() {
            self.reresolve();
        }
        (promoted, rejected)
    }

    fn stage(&mut self, op: SignedOp) -> Result<()> {
        op.verify_standalone()?;
        if op.op.space != Some(self.space) {
            return Err(TrustError::WrongSpace);
        }
        // DoS guard: only keys that some known op ever added may author ops.
        // (An op that arrives before its author's Add is simply re-fetched on
        // a later sync, so this doesn't affect convergence.)
        if !self.ever_named(&op.op.author) {
            return Err(TrustError::NotAuthorized("author was never added to this space"));
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(TrustError::Malformed("too many pending ops"));
        }
        self.pending.insert(op.id(), op);
        Ok(())
    }

    /// Has any known op (valid or not) named `pk` as founder or added member?
    pub fn ever_named(&self, pk: &SignPk) -> bool {
        self.ops.values().chain(self.pending.values()).any(|o| match &o.op.action {
            Action::Genesis { founder, .. } => founder.sign_pk == *pk,
            Action::Add { member, .. } => member.sign_pk == *pk,
            _ => false,
        })
    }

    fn reresolve(&mut self) {
        self.res = resolve::resolve(&self.ops);
        self.state_cache.lock().unwrap().clear();
    }

    fn promote_pending(&mut self) -> HashSet<OpId> {
        let mut promoted = HashSet::new();
        loop {
            let ready: Vec<OpId> = self
                .pending
                .iter()
                .filter(|(_, o)| o.op.parents.iter().all(|p| self.ops.contains_key(p)))
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                return promoted;
            }
            for id in ready {
                let op = self.pending.remove(&id).unwrap();
                self.ops.insert(id, op);
                promoted.insert(id);
            }
        }
    }

    /// Ops (valid or not) that no other known op names as a parent.
    pub fn heads(&self) -> Vec<OpId> {
        let parents: HashSet<&OpId> = self.ops.values().flat_map(|o| &o.op.parents).collect();
        let mut heads: Vec<OpId> = self
            .ops
            .keys()
            .filter(|id| !parents.contains(id))
            .copied()
            .collect();
        heads.sort();
        heads
    }

    pub fn resolution(&self) -> &Resolution {
        &self.res
    }

    pub fn is_valid(&self, id: &OpId) -> bool {
        self.res.is_valid(id)
    }

    /// Current membership state.
    pub fn state(&self) -> &MemberState {
        &self.res.state
    }

    /// True iff every op in `heads` is known (not pending, not missing).
    pub fn knows_all(&self, heads: &[OpId]) -> bool {
        heads.iter().all(|h| self.ops.contains_key(h))
    }

    /// Membership as of `heads` (TRUST.md: "what the author could prove").
    /// Panics if a head is unknown; check `knows_all` first.
    pub fn state_at(&self, heads: &[OpId]) -> MemberState {
        let mut key = heads.to_vec();
        key.sort();
        key.dedup();
        if let Some(s) = self.state_cache.lock().unwrap().get(&key) {
            return s.clone();
        }
        let st = self.res.state_at(&self.ops, &key);
        let mut cache = self.state_cache.lock().unwrap();
        if cache.len() >= STATE_CACHE_MAX {
            cache.clear();
        }
        cache.insert(key, st.clone());
        st
    }

    /// Is op `a` in the causal past of (or equal to one of) `heads`?
    pub fn in_past(&self, a: &OpId, heads: &[OpId]) -> bool {
        self.res.in_past(a, heads)
    }

    /// Winning revocations targeting `pk`: (op id, cutoff).
    pub fn revocations_of(&self, pk: &SignPk) -> Vec<(OpId, Option<Hash32>)> {
        self.res
            .winners
            .iter()
            .filter_map(|id| {
                let op = &self.ops[id].op;
                match &op.action {
                    Action::Remove { member, revocation, .. }
                    | Action::SetRole {
                        member,
                        revocation: Some(revocation),
                        ..
                    } if member == pk => Some((*id, revocation.cutoff)),
                    Action::Leave { cutoff } if op.author == *pk => Some((*id, *cutoff)),
                    _ => None,
                }
            })
            .collect()
    }

    // ───────────── keys ─────────────

    /// Unseal every lockbox addressed to `me` in valid ops into `keyring`,
    /// checking each key against its public commitment. Returns how many keys
    /// were newly added.
    pub fn unlock(&self, me: &DeviceKeys, keyring: &mut Keyring) -> usize {
        let my_pk = me.sign_pk();
        let commitments: HashMap<EpochId, Hash32> = self
            .res
            .state
            .epochs
            .iter()
            .map(|e| (e.id, e.commitment))
            .collect();
        let mut added = 0;
        for id in &self.res.order {
            if !self.res.is_valid(id) {
                continue;
            }
            let op = &self.ops[id].op;
            let mut try_insert = |epoch: EpochId, key: SymKey| {
                if keyring.get(&epoch).is_none()
                    && commitments.get(&epoch) == Some(&key.commitment())
                {
                    keyring.insert(epoch, key);
                    added += 1;
                }
            };
            match &op.action {
                Action::Genesis { rotation, .. }
                | Action::SetRole {
                    rotation: Some(rotation),
                    ..
                }
                | Action::Remove { rotation, .. }
                | Action::Rotate { rotation } => {
                    if let Some((_, lb)) = rotation.lockboxes.iter().find(|(pk, _)| *pk == my_pk)
                        && let Ok(bytes) = me.open_lockbox(&lockbox_info(&rotation.epoch, &my_pk), lb)
                        && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
                        && SymKey(arr).commitment() == rotation.commitment
                    {
                        try_insert(rotation.epoch, SymKey(arr));
                    }
                }
                Action::Add {
                    member,
                    keyring: Some(lb),
                    ..
                } if member.sign_pk == my_pk => {
                    if let Ok(bytes) =
                        me.open_lockbox(&keyring_info(&self.space, op.nonce, &my_pk), lb)
                        && let Ok(entries) = postcard::from_bytes::<Vec<(EpochId, SymKey)>>(&bytes)
                    {
                        for (epoch, key) in entries {
                            try_insert(epoch, key);
                        }
                    }
                }
                _ => {}
            }
        }
        added
    }

    // ───────────── authoring helpers ─────────────

    fn author_op(&self, me: &DeviceKeys, action: Action) -> SignedOp {
        SignedOp::sign(
            me,
            Op {
                space: Some(self.space),
                parents: self.heads(),
                author: me.sign_pk(),
                nonce: random_u64(),
                action,
            },
        )
    }

    fn require_role(&self, me: &DeviceKeys, ok: impl Fn(Role) -> bool) -> Result<()> {
        match self.state().role(&me.sign_pk()) {
            Some(r) if ok(r) => Ok(()),
            _ => Err(TrustError::NotAuthorized("insufficient role")),
        }
    }

    fn rotation_for(&self, readers: &BTreeSet<SignPk>) -> Result<(Rotation, SymKey)> {
        let st = self.state();
        new_rotation(readers.iter().map(|pk| &st.members[pk].keys))
    }

    /// Admin: add a member. Readers receive every epoch key in `keyring`.
    pub fn add_member(
        &self,
        me: &DeviceKeys,
        keyring: &Keyring,
        member: MemberKeys,
        role: Role,
    ) -> Result<SignedOp> {
        self.require_role(me, Role::is_admin)?;
        member.verify_binding()?;
        if self.state().members.contains_key(&member.sign_pk) {
            return Err(TrustError::Malformed("already a member"));
        }
        let nonce = random_u64();
        let sealed = if role.can_read() {
            let entries: Vec<(EpochId, SymKey)> = self
                .state()
                .epochs
                .iter()
                .filter_map(|e| keyring.get(&e.id).map(|k| (e.id, k.clone())))
                .collect();
            let bytes = postcard::to_allocvec(&entries).map_err(|_| TrustError::Encoding)?;
            Some(seal_lockbox(
                &member.kex_pk,
                &keyring_info(&self.space, nonce, &member.sign_pk),
                &bytes,
            )?)
        } else {
            None
        };
        let mut op = self.author_op(
            me,
            Action::Add {
                member,
                role,
                keyring: sealed,
            },
        );
        // re-sign with the nonce the keyring was bound to
        op.op.nonce = nonce;
        Ok(SignedOp::sign(me, op.op))
    }

    /// Admin: remove a member, rotating to a fresh epoch for remaining readers.
    pub fn remove_member(
        &self,
        me: &DeviceKeys,
        member: SignPk,
        cutoff: Option<Hash32>,
    ) -> Result<(SignedOp, EpochId, SymKey)> {
        self.require_role(me, Role::is_admin)?;
        if !self.state().members.contains_key(&member) {
            return Err(TrustError::Malformed("not a member"));
        }
        let mut readers = self.state().readers();
        readers.remove(&member);
        let (rotation, key) = self.rotation_for(&readers)?;
        let epoch = rotation.epoch;
        let op = self.author_op(
            me,
            Action::Remove {
                member,
                revocation: Revocation { cutoff },
                rotation,
            },
        );
        Ok((op, epoch, key))
    }

    /// Admin: change a member's role. Downgrades carry a revocation; losing
    /// read access forces a rotation (returned as `Some((epoch, key))`).
    pub fn set_role(
        &self,
        me: &DeviceKeys,
        member: SignPk,
        role: Role,
        cutoff: Option<Hash32>,
    ) -> Result<(SignedOp, Option<(EpochId, SymKey)>)> {
        self.require_role(me, Role::is_admin)?;
        let prior = self
            .state()
            .role(&member)
            .ok_or(TrustError::Malformed("not a member"))?;
        if prior == role {
            return Err(TrustError::Malformed("role unchanged"));
        }
        let revocation = (role < prior).then_some(Revocation { cutoff });
        let (rotation, new_key) = if prior.can_read() && !role.can_read() {
            let mut readers = self.state().readers();
            readers.remove(&member);
            let (r, k) = self.rotation_for(&readers)?;
            let e = r.epoch;
            (Some(r), Some((e, k)))
        } else {
            (None, None)
        };
        let op = self.author_op(
            me,
            Action::SetRole {
                member,
                role,
                revocation,
                rotation,
            },
        );
        Ok((op, new_key))
    }

    /// Any member: leave the space.
    pub fn leave(&self, me: &DeviceKeys, cutoff: Option<Hash32>) -> Result<SignedOp> {
        if self.state().role(&me.sign_pk()).is_none() {
            return Err(TrustError::NotAuthorized("not a member"));
        }
        Ok(self.author_op(me, Action::Leave { cutoff }))
    }

    /// Writer+: rotate to a fresh epoch for exactly the current readers.
    pub fn rotate(&self, me: &DeviceKeys) -> Result<(SignedOp, EpochId, SymKey)> {
        self.require_role(me, Role::can_write)?;
        let (rotation, key) = self.rotation_for(&self.state().readers())?;
        let epoch = rotation.epoch;
        Ok((self.author_op(me, Action::Rotate { rotation }), epoch, key))
    }
}

#[cfg(test)]
mod tests;
