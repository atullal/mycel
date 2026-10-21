//! Deterministic, incremental resolution of the membership DAG (TRUST.md §5).
//!
//! The result is defined by the from-scratch algorithm in `oracle.rs`
//! (topological order, seniority, revocation winners, concurrent
//! invalidation, authorization replay, repeated while a winner fails). This
//! module computes exactly the same result, but updates it as ops arrive
//! instead of rebuilding it:
//!
//! - **Ancestry** comes from a chain cover index (`reach.rs`), not an n × n
//!   bitset.
//! - **Causal states.** `state(valid ∩ past(op))` is never replayed from
//!   genesis. The resolver keeps, for every round of the winners loop (and
//!   for "authorized ignoring concurrency", which fixes seniority), the state
//!   at the current valid heads. Each has an undo log, so it can be rewound
//!   to an earlier cut.
//! - **Cuts.** After each update the resolver records a cut: the ops known
//!   so far, their valid heads `F` and the log lengths. A new op can be
//!   resolved against cut `u` when it descends from all of `F_u`, every op in
//!   its past outside `past(F_u)` and outside the region is invalid in every
//!   round, (for a revocation) no op by its target that is concurrent with
//!   it, arrived before `u` and could change result (valid in some round,
//!   or winning ahead of it) exists, and it does not change the seniority of
//!   anyone with revocations before `u`. Then nothing before the cut can
//!   change: ops interact only through ancestry, seniority, and a revocation
//!   and the concurrent ops of its target. Only the **region** (ops that
//!   arrived after `u`) is re-resolved, every round, from the states rewound
//!   to `u`: the subgraph concurrent with the conflict and what follows it.
//! - **Loose ops.** Every region op descends from `F_u`, so an older op can
//!   be concurrent with it only if it is outside `past(F_u)`. Each cut keeps
//!   those that are valid or win in some round (normally none: they are the
//!   remains of a conflict), and only they are searched for concurrent
//!   revocations, so the cost does not grow with history.
//! - **Fast path.** An op that descends from the valid heads and conflicts
//!   with nothing is the whole region of the newest cut: it is checked
//!   against the head states in place, O(op) per round (plus, for an `Add`
//!   of a reader, one recipient insert per epoch they lack, as the state
//!   records: all of them for a new member, the ones since for a member
//!   added back).
//! - **Revocation checks.** Steps 3 and 4 ask whether an op is concurrent
//!   with a winning revocation of its author. A region walk indexes each
//!   target's winners by topological index (`target_winners`) and scans
//!   outward from the op only until a winner whose earlier (or later)
//!   winners all lie in its own past (or future), so a member revoked many
//!   times over a long history does not make a full recompute quadratic.
//! - **Causal states share their logs.** A region walk branches and merges
//!   role states along the DAG; their undo logs are shared lists, so a
//!   branch copies the role state (bounded by the member count), never the
//!   history.
//!
//! The winners loop is path dependent (a winner that fails in round k is
//! dropped for good, and what failed depends on the round's transient
//! states), so the resolver stores every round, not just the last one: one
//! validity and one winner flag per op per round, and one head state per
//! round. Rounds beyond the first appear only when a revocation winner fails.
//!
//! Tests replay random concurrent histories through both resolvers and
//! require identical results (`diff_tests.rs`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use mycel_crypto::SignPk;

use crate::reach::Reach;
use crate::{Action, Epoch, EpochId, Member, MemberState, OpId, Role, Rotation, SignedOp};

/// What applying an op did to one member's role, for undo.
#[derive(Clone, Copy, Debug)]
enum Prev {
    /// The op changed nothing (a rotation, or a role change of a non-member).
    Same,
    /// The member's role before the op (`None` = not a member).
    Role(Option<Role>),
}

#[derive(Clone, Copy, Debug)]
struct RoleUndo {
    slot: u32,
    prev: Prev,
}

/// The part of a membership state that authorization reads.
#[derive(Clone, Debug, Default)]
struct RoleState {
    roles: BTreeMap<SignPk, Role>,
    readers: BTreeSet<SignPk>,
    admins: usize,
}

impl RoleState {
    fn role(&self, pk: &SignPk) -> Option<Role> {
        self.roles.get(pk).copied()
    }

    fn set(&mut self, pk: SignPk, role: Option<Role>) -> Option<Role> {
        let prev = match role {
            Some(r) => self.roles.insert(pk, r),
            None => self.roles.remove(&pk),
        };
        if prev.is_some_and(Role::is_admin) {
            self.admins -= 1;
        }
        if role.is_some_and(Role::is_admin) {
            self.admins += 1;
        }
        if role.is_some_and(Role::can_read) {
            self.readers.insert(pk);
        } else {
            self.readers.remove(&pk);
        }
        prev
    }
}

/// A role state plus the log of the region ops applied to it, newest first
/// (a causal state inside a region walk). The log is a shared list, so
/// branching or merging a state copies only the role state, never the
/// history: a full recompute of a long concurrent history stays linear.
#[derive(Clone, Debug, Default)]
struct PState {
    st: RoleState,
    log: Log,
}

type Log = Option<Rc<LogNode>>;

#[derive(Debug)]
struct LogNode {
    u: RoleUndo,
    prev: Log,
}

impl PState {
    fn push(&mut self, u: RoleUndo) {
        self.log = Some(Rc::new(LogNode { u, prev: self.log.take() }));
    }
}

impl Drop for LogNode {
    /// Unlink iteratively: a long list would overflow the stack dropping
    /// recursively.
    fn drop(&mut self) {
        let mut next = self.prev.take();
        while let Some(rc) = next {
            match Rc::try_unwrap(rc) {
                Ok(mut node) => next = node.prev.take(),
                Err(_) => break,
            }
        }
    }
}

/// One round of the winners loop (TRUST.md §5 steps 3–6), or round 0:
/// authorization ignoring concurrency, which fixes seniority.
#[derive(Clone, Debug, Default)]
struct Round {
    /// Per op: valid in this round.
    valid: Vec<bool>,
    /// Per op: a revocation that wins this round (always false in round 0).
    win: Vec<bool>,
    /// Winners that failed authorization this round (dropped from then on),
    /// by slot.
    fails: Vec<u32>,
    /// State of the round's valid ops in the past of the valid heads.
    st: RoleState,
    log: Vec<RoleUndo>,
}

#[derive(Clone, Debug)]
enum FullUndo {
    Member(SignPk, Option<Member>),
    Epoch,
    /// A reader `Add` (slot) gave the member the keys of the epochs in its
    /// past; the member's previous keyring. Undo recomputes which epochs
    /// that was (among those past the previous `covered`) instead of storing
    /// them.
    Keyring(SignPk, u32, Keyring),
}

/// What a member's reader `Add`s gave them, in a full state.
#[derive(Clone, Debug, Default)]
struct Keyring {
    /// The causally maximal reader `Add`s of the member. The member is a
    /// recipient of an epoch iff its rotation names them or the epoch is in
    /// the past of one of these.
    frontier: Vec<u32>,
    /// The member is a recipient of every epoch before this index of
    /// `state.epochs`, so the next `Add` of them starts there: a member
    /// removed and added back pays for the epochs since, not for all
    /// history.
    covered: u32,
}

/// What updating a full membership state needs beside it.
#[derive(Clone, Debug, Default)]
struct Aux {
    /// Per epoch in `state.epochs`: slot of the op that created it.
    creators: Vec<u32>,
    /// Per member who was added as a reader: their keyring in the state.
    keyrings: HashMap<SignPk, Keyring>,
}

/// A point the resolver can rewind to (see the module docs).
#[derive(Clone, Debug)]
struct Cut {
    /// Ops at or above this slot form the region.
    slot: u32,
    /// Valid heads (slots) when the cut was made.
    frontier: Vec<u32>,
    /// Log length of round 0, 1, … (rounds added later share the last).
    lens: Vec<usize>,
    full_len: usize,
    /// Ops before `slot` outside the past of `frontier` that are valid in
    /// some round or win in some round (normally none). Every region op
    /// descends from the frontier, so only older ops outside its past can be
    /// concurrent with it, and an op invalid and losing in every round
    /// cannot be changed by a revocation (`affected_by`) nor revoke anything
    /// (the pools hold winners only).
    loose: Vec<u32>,
}

/// Revocations that can be concurrent with the ops being resolved, by target.
type Pool = HashMap<SignPk, Vec<u32>>;

/// One target's winning revocations (see `Resolution::winners_by_target`).
struct TargetWinners {
    ws: Vec<u32>,
    closed: Vec<bool>,
    open: Vec<bool>,
}

/// Static facts about an op.
#[derive(Clone, Debug)]
struct Meta {
    parents: Vec<u32>,
    author: SignPk,
    /// Member a revocation revokes (TRUST.md §5 step 3).
    target: Option<SignPk>,
    /// Member a Genesis or Add names (seniority).
    names: Option<SignPk>,
    /// Member whose role the op changes when applied.
    touches: Option<SignPk>,
}

/// Result of resolving the DAG: topological order, validity, winners and
/// current state, maintained incrementally as ops are added.
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    /// Every op in topological order, ties broken by op id.
    pub order: Vec<OpId>,
    /// Membership after replaying every valid op in `order`.
    pub state: MemberState,
    pub(crate) heads: Vec<OpId>,
    ids: Vec<OpId>,
    slot: HashMap<OpId, u32>,
    meta: Vec<Meta>,
    /// Per slot: index in `order`.
    pos: Vec<u32>,
    /// Per index in `order`: slot.
    at: Vec<u32>,
    reach: Reach,
    by_author: HashMap<SignPk, Vec<u32>>,
    cands_by_target: HashMap<SignPk, Vec<u32>>,
    cands_by_author: HashMap<SignPk, u32>,
    epoch_ops: HashMap<EpochId, Vec<u32>>,
    /// First (in `order`) op valid in round 0 that names each key.
    seniority: HashMap<SignPk, u32>,
    pre: Round,
    rounds: Vec<Round>,
    full_log: Vec<FullUndo>,
    aux: Aux,
    head_slots: Vec<u32>,
    cuts: Vec<Cut>,
    /// Per slot: 0, or the slot of the cut recorded after the op was last
    /// resolved if the op was then invalid in every round and each of its
    /// parents was in the past of that cut's frontier or itself marked. The
    /// op and its invalid ancestors outside every later frontier's past are
    /// then all invalid, so `outside_past_invalid` stops at it: a long chain
    /// of invalid ops is walked once, not on every insert built on it.
    dead: Vec<u32>,
    /// Updates that took the fast path / re-resolved a region / everything.
    pub(crate) stats: Stats,
    /// Ops visited by `outside_past_invalid`, summed (tests).
    #[cfg(test)]
    pub(crate) searched: std::cell::Cell<u64>,
}

/// Counters for tests and benchmarks.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Stats {
    pub(crate) fast: u64,
    pub(crate) region: u64,
    pub(crate) full: u64,
    /// Region ops re-resolved, summed over updates.
    pub(crate) region_ops: u64,
}

fn revocation_target(op: &SignedOp) -> Option<SignPk> {
    match &op.op.action {
        Action::Remove { member, .. } => Some(*member),
        Action::SetRole { member, revocation: Some(_), .. } => Some(*member),
        Action::Leave { .. } => Some(op.op.author),
        _ => None,
    }
}

fn touches(op: &SignedOp) -> Option<SignPk> {
    match &op.op.action {
        Action::Genesis { founder, .. } => Some(founder.sign_pk),
        Action::Add { member, .. } => Some(member.sign_pk),
        Action::SetRole { member, .. } | Action::Remove { member, .. } => Some(*member),
        Action::Leave { .. } => Some(op.op.author),
        Action::Rotate { .. } => None,
    }
}

fn rotation_of(op: &SignedOp) -> Option<&Rotation> {
    match &op.op.action {
        Action::Genesis { rotation, .. }
        | Action::SetRole { rotation: Some(rotation), .. }
        | Action::Remove { rotation, .. }
        | Action::Rotate { rotation } => Some(rotation),
        _ => None,
    }
}

fn recipients(r: &Rotation) -> BTreeSet<SignPk> {
    r.lockboxes.iter().map(|(pk, _)| *pk).collect()
}

/// Readers after `member` changes to `role` (`None` = leaves the space).
fn readers_after(st: &RoleState, member: &SignPk, role: Option<Role>) -> BTreeSet<SignPk> {
    let mut readers = st.readers.clone();
    if role.is_some_and(Role::can_read) {
        readers.insert(*member);
    } else {
        readers.remove(member);
    }
    readers
}

/// Admins after `member` changes to `role` (`None` = leaves the space).
fn admins_after(st: &RoleState, member: &SignPk, role: Option<Role>) -> usize {
    let before = st.role(member).is_some_and(Role::is_admin);
    let after = role.is_some_and(Role::is_admin);
    st.admins + usize::from(after) - usize::from(before)
}

/// TRUST.md §4 authorization of `op` (at topological index `idx`) in state
/// `st`; `fresh(e)` says whether no op in the state created epoch `e`.
fn authorized(op: &SignedOp, idx: u32, st: &RoleState, fresh: impl Fn(&EpochId) -> bool) -> bool {
    let author_role = st.role(&op.op.author);
    let is_admin = author_role.is_some_and(Role::is_admin);
    match &op.op.action {
        Action::Genesis { founder, rotation } => idx == 0 && recipients(rotation) == BTreeSet::from([founder.sign_pk]),
        Action::Add { member, .. } => is_admin && !st.roles.contains_key(&member.sign_pk),
        Action::SetRole { member, role, revocation, rotation } => {
            let Some(prior) = st.role(member) else {
                return false;
            };
            let loses_read = prior.can_read() && !role.can_read();
            is_admin
                && *role != prior
                && revocation.is_some() == (*role < prior)
                && rotation.is_some() == loses_read
                && rotation
                    .as_ref()
                    .is_none_or(|r| fresh(&r.epoch) && recipients(r) == readers_after(st, member, Some(*role)))
                && admins_after(st, member, Some(*role)) > 0
        }
        Action::Remove { member, rotation, .. } => {
            st.roles.contains_key(member)
                && is_admin
                && fresh(&rotation.epoch)
                && recipients(rotation) == readers_after(st, member, None)
                && admins_after(st, member, None) > 0
        }
        Action::Rotate { rotation } => {
            author_role.is_some_and(Role::can_write) && fresh(&rotation.epoch) && recipients(rotation) == st.readers
        }
        Action::Leave { .. } => author_role.is_some() && admins_after(st, &op.op.author, None) > 0,
    }
}

fn apply_role(st: &mut RoleState, op: &SignedOp) -> Prev {
    match &op.op.action {
        Action::Genesis { founder, .. } => Prev::Role(st.set(founder.sign_pk, Some(Role::Admin))),
        Action::Add { member, role, .. } => Prev::Role(st.set(member.sign_pk, Some(*role))),
        Action::SetRole { member, role, .. } => {
            if st.roles.contains_key(member) {
                Prev::Role(st.set(*member, Some(*role)))
            } else {
                Prev::Same
            }
        }
        Action::Remove { member, .. } => Prev::Role(st.set(*member, None)),
        Action::Rotate { .. } => Prev::Same,
        Action::Leave { .. } => Prev::Role(st.set(op.op.author, None)),
    }
}

/// Candidate order (TRUST.md §5 step 3): author seniority, then topological index.
type Key = (u32, u32);

impl Resolution {
    /// Resolve a DAG holding only `genesis`.
    pub(crate) fn new(ops: &HashMap<OpId, SignedOp>, genesis: OpId) -> Self {
        let mut res = Resolution {
            cuts: vec![Cut { slot: 0, frontier: vec![], lens: vec![0], full_len: 0, loose: vec![] }],
            ..Default::default()
        };
        res.add(ops, &[genesis]);
        res
    }

    pub fn is_valid(&self, id: &OpId) -> bool {
        self.slot.get(id).is_some_and(|&s| self.final_round().valid[s as usize])
    }

    /// Is `a` in the causal past of (or equal to one of) `heads`?
    pub fn in_past(&self, a: &OpId, heads: &[OpId]) -> bool {
        let Some(&a) = self.slot.get(a) else {
            return false;
        };
        heads.iter().any(|h| self.slot.get(h).is_some_and(|&h| self.le(a, h)))
    }

    /// Winning revocations, in candidate order (TRUST.md §5 step 3).
    pub fn winners(&self) -> Vec<OpId> {
        let fin = self.final_round();
        let mut w: Vec<u32> =
            self.cands_by_target.values().flatten().copied().filter(|&c| fin.win[c as usize]).collect();
        w.sort_by_key(|&c| self.key(c));
        w.into_iter().map(|c| self.ids[c as usize]).collect()
    }

    /// Winning revocations of `pk`, in candidate order.
    pub(crate) fn winners_against(&self, pk: &SignPk) -> Vec<OpId> {
        let fin = self.final_round();
        let mut w: Vec<u32> =
            self.cands_by_target.get(pk).into_iter().flatten().copied().filter(|&c| fin.win[c as usize]).collect();
        w.sort_by_key(|&c| self.key(c));
        w.into_iter().map(|c| self.ids[c as usize]).collect()
    }

    /// Membership as of `heads`: every valid op in their past, replayed in order.
    pub(crate) fn state_at(&self, ops: &HashMap<OpId, SignedOp>, heads: &[OpId]) -> MemberState {
        let mut seen = vec![false; self.ids.len()];
        let mut stack: Vec<u32> = heads.iter().map(|h| self.slot[h]).collect();
        let mut set = Vec::new();
        let fin = self.final_round();
        while let Some(s) = stack.pop() {
            if std::mem::replace(&mut seen[s as usize], true) {
                continue;
            }
            if fin.valid[s as usize] {
                set.push(s);
            }
            stack.extend(self.meta[s as usize].parents.iter().copied().filter(|&p| !seen[p as usize]));
        }
        set.sort_by_key(|&s| self.pos[s as usize]);
        let mut st = MemberState::default();
        let mut aux = Aux::default();
        for s in set {
            self.apply_full(&mut st, &mut aux, None, ops, s, 0);
        }
        st
    }

    #[cfg(feature = "oracle")]
    #[doc(hidden)]
    pub fn debug_sizes(&self) -> String {
        format!(
            "reach [{}], cuts {} loose {}, full_log {}, round logs {}, epochs {} recipients {}, keyrings {}",
            self.reach.debug_sizes(),
            self.cuts.len(),
            self.cuts.iter().map(|c| c.loose.len()).sum::<usize>(),
            self.full_log.len(),
            std::iter::once(&self.pre).chain(&self.rounds).map(|r| r.log.len()).sum::<usize>(),
            self.state.epochs.len(),
            self.state.epochs.iter().map(|e| e.recipients.len()).sum::<usize>(),
            self.aux.keyrings.values().map(|k| k.frontier.len()).sum::<usize>(),
        )
    }

    /// Rounds of the winners loop kept (tests and the benchmark).
    #[cfg(any(test, feature = "oracle"))]
    #[doc(hidden)]
    pub fn rounds(&self) -> usize {
        self.rounds.len()
    }

    /// Cuts kept (tests).
    #[cfg(test)]
    pub(crate) fn cuts(&self) -> usize {
        self.cuts.len()
    }

    fn final_round(&self) -> &Round {
        self.rounds.last().expect("resolved at least once")
    }

    fn le(&self, a: u32, b: u32) -> bool {
        a == b || (self.pos[a as usize] < self.pos[b as usize] && self.reach.le(a, b))
    }

    fn concurrent(&self, a: u32, b: u32) -> bool {
        a != b && !self.le(a, b) && !self.le(b, a)
    }

    fn rank(&self, pk: &SignPk) -> u32 {
        self.seniority.get(pk).map_or(u32::MAX, |&s| self.pos[s as usize])
    }

    fn key(&self, c: u32) -> Key {
        (self.rank(&self.meta[c as usize].author), self.pos[c as usize])
    }

    // ─────────────────────────── adding ops ───────────────────────────

    /// Add ops whose parents are all known (`new` in any order) and update
    /// the resolution.
    pub(crate) fn add(&mut self, ops: &HashMap<OpId, SignedOp>, new: &[OpId]) {
        let first = self.ids.len() as u32;
        for id in topo_sorted(ops, new) {
            self.push_op(ops, id);
        }
        let n = self.ids.len() as u32;
        if n == first {
            return;
        }
        let ci = (first..n).map(|s| self.choose_cut(s)).min().unwrap();
        let top = ci + 1 == self.cuts.len() && self.cuts[ci].slot == first;
        if n == first + 1 && top && !self.rounds.is_empty() && fast_path_enabled() {
            if self.fast(ops, first) {
                return;
            }
            self.recompute(ops, 0, first);
            return;
        }
        self.recompute(ops, ci, first);
    }

    fn push_op(&mut self, ops: &HashMap<OpId, SignedOp>, id: OpId) {
        let op = &ops[&id];
        let slot = self.ids.len() as u32;
        let parents: Vec<u32> = op.op.parents.iter().map(|p| self.slot[p]).collect();
        // Kahn's algorithm with the smallest id first places a new sink at the
        // first step after its parents where it is smaller than the op the
        // old order took (TRUST.md §5 step 1).
        let mut p = parents.iter().map(|&q| self.pos[q as usize] as usize + 1).max().unwrap_or(0);
        while p < self.order.len() && self.order[p] < id {
            p += 1;
        }
        self.order.insert(p, id);
        self.at.insert(p, slot);
        self.pos.push(p as u32);
        for j in p + 1..self.at.len() {
            self.pos[self.at[j] as usize] = j as u32;
        }
        let r = self.reach.push(&parents);
        debug_assert_eq!(r, slot);
        let target = revocation_target(op);
        let meta = Meta { parents, author: op.op.author, target, names: crate::names(op), touches: touches(op) };
        self.by_author.entry(meta.author).or_default().push(slot);
        if let Some(t) = target {
            self.cands_by_target.entry(t).or_default().push(slot);
            *self.cands_by_author.entry(meta.author).or_default() += 1;
        }
        if let Some(r) = rotation_of(op) {
            self.epoch_ops.entry(r.epoch).or_default().push(slot);
        }
        self.meta.push(meta);
        self.dead.push(0);
        self.ids.push(id);
        self.slot.insert(id, slot);
        for r in std::iter::once(&mut self.pre).chain(&mut self.rounds) {
            r.valid.push(false);
            r.win.push(false);
        }
    }

    /// The newest cut new op `x` can be re-resolved from (module docs).
    fn choose_cut(&self, x: u32) -> usize {
        let target = self.meta[x as usize].target;
        for ci in (1..self.cuts.len()).rev() {
            let cut = &self.cuts[ci];
            if !cut.frontier.iter().all(|&f| self.le(f, x)) {
                continue;
            }
            // An op by the revoked member, before the cut and concurrent
            // with `x` (`x` descends from the frontier, so it is loose),
            // whose result `x` can change.
            let partner = target.is_some_and(|t| self.has_partner(&cut.loose, t, x));
            if !partner && self.outside_past_invalid(x, cut) {
                return ci;
            }
        }
        0
    }

    /// Is there a loose op by `t`, concurrent with its revocation `x`, whose
    /// result `x` can change (`affected_by`)? (`x` descends from the cut's
    /// frontier, so a loose op not in its past is concurrent with it.)
    fn has_partner(&self, loose: &[u32], t: SignPk, x: u32) -> bool {
        loose.iter().any(|&y| self.meta[y as usize].author == t && !self.le(y, x) && self.affected_by(y, x))
    }

    /// Can a revocation `x` of `y`'s author, concurrent with `y`, change
    /// `y`'s result? Only by excluding it (step 4) where it is valid, or by
    /// beating it (step 3) where it wins. An op invalid in every round that
    /// never wins, or wins only ahead of `x`, keeps its result: so old
    /// dangling ops of a revoked member do not pull every later revocation
    /// of them back to before their time.
    fn affected_by(&self, y: u32, x: u32) -> bool {
        let y_ = y as usize;
        self.rounds.iter().any(|r| r.valid[y_]) || (self.rounds.iter().any(|r| r.win[y_]) && self.key(x) < self.key(y))
    }

    /// Is every op in `x`'s past that is outside the cut's past and outside
    /// its region invalid in every round? Ops marked `dead` by this cut or an
    /// older one end the search: cut frontiers only move forward (each
    /// descends from the whole previous one), so what lay in the past of the
    /// frontier that marked them lies in the past of this one.
    fn outside_past_invalid(&self, x: u32, cut: &Cut) -> bool {
        let mut stack: Vec<u32> = self.meta[x as usize].parents.clone();
        let mut seen = std::collections::HashSet::new();
        while let Some(y) = stack.pop() {
            let dead = self.dead[y as usize];
            if y >= cut.slot
                || (dead != 0 && dead <= cut.slot)
                || !seen.insert(y)
                || cut.frontier.iter().any(|&f| self.le(y, f))
            {
                continue;
            }
            #[cfg(test)]
            self.searched.set(self.searched.get() + 1);
            let y_ = y as usize;
            if self.pre.valid[y_] || self.rounds.iter().any(|r| r.valid[y_]) {
                return false;
            }
            stack.extend_from_slice(&self.meta[y_].parents);
        }
        true
    }

    /// Fast path: one new op, which is the whole region of the newest cut.
    /// Returns false when a seniority change forces a full recompute.
    fn fast(&mut self, ops: &HashMap<OpId, SignedOp>, x: u32) -> bool {
        let xu = x as usize;
        let op = &ops[&self.ids[xu]];
        let idx = self.pos[xu];
        // Round 0.
        let pre_ok = authorized(op, idx, &self.pre.st, |e| self.fresh_epoch(x, e, |j| self.pre.valid[j as usize]));
        if pre_ok && !self.note_seniority(x, x) {
            return false;
        }
        self.pre.valid[xu] = pre_ok;
        // Rounds 1…
        let k_old = self.rounds.len();
        let k_pre = self.prefix_rounds(x);
        let pool = self.pool(&self.cuts[self.cuts.len() - 1].loose, x..x + 1);
        let mut res: Vec<(bool, bool)> = Vec::new(); // (valid, win) per round
        let mut removed = false;
        let mut k = 1;
        loop {
            let r = &self.rounds[k.min(k_old) - 1];
            let win_at = |w: u32| r.win[w as usize];
            let win = self.meta[xu].target.is_some() && !removed && !self.loses(x, &pool, |w| w != x && win_at(w));
            let excl = self.excluded(x, &pool, win_at);
            let valid =
                !excl && authorized(op, idx, &r.st, |e| self.fresh_epoch(x, e, |j| j != x && r.valid[j as usize]));
            res.push((valid, win));
            let failed = win && !valid;
            if failed {
                removed = true;
            }
            if k >= k_pre && !failed {
                break;
            }
            k += 1;
        }
        let k_new = res.len();
        self.resize_rounds(k_new);
        let fin_valid = res[k_new - 1].0;
        for (k, &(valid, win)) in res.iter().enumerate() {
            let r = &mut self.rounds[k];
            r.valid[xu] = valid;
            r.win[xu] = win;
            if win && !valid {
                r.fails.push(x);
            }
        }
        if fin_valid {
            self.head_slots = vec![x];
            self.heads = vec![self.ids[xu]];
            if pre_ok {
                let prev = apply_role(&mut self.pre.st, op);
                self.pre.log.push(RoleUndo { slot: x, prev });
            }
            for (k, &(valid, _)) in res.iter().enumerate() {
                if valid {
                    let r = &mut self.rounds[k];
                    let prev = apply_role(&mut r.st, op);
                    r.log.push(RoleUndo { slot: x, prev });
                }
            }
            self.push_full(ops, x, x);
        }
        self.stats.fast += 1;
        self.push_cut(x);
        true
    }

    /// Record `x` as a new op valid in round 0; returns false if that moves
    /// the seniority of a key whose revocations sit before the cut at `from`
    /// (their candidate order would change outside the region).
    fn note_seniority(&mut self, x: u32, from: u32) -> bool {
        let Some(pk) = self.meta[x as usize].names else {
            return true;
        };
        match self.seniority.get(&pk) {
            Some(&s) if self.pos[s as usize] < self.pos[x as usize] => true,
            _ => {
                let affected = self.cands_by_author.contains_key(&pk)
                    && self.by_author[&pk].iter().any(|&c| c < from && self.meta[c as usize].target.is_some());
                self.seniority.insert(pk, x);
                !affected
            }
        }
    }

    /// 1 + the last round in which an op before `from` failed.
    fn prefix_rounds(&self, from: u32) -> usize {
        self.rounds.iter().rposition(|r| r.fails.first().is_some_and(|&f| f < from)).map_or(1, |k| k + 2)
    }

    /// The revocations that can be concurrent with ops in `region` (which
    /// descend from the frontier of the cut whose loose ops are `loose`):
    /// those in the region and the loose ones. Any other revocation is in
    /// the frontier's past, so in the past of every region op.
    fn pool(&self, loose: &[u32], region: std::ops::Range<u32>) -> Pool {
        let mut pool = Pool::new();
        for c in loose.iter().copied().chain(region) {
            if let Some(t) = self.meta[c as usize].target {
                pool.entry(t).or_default().push(c);
            }
        }
        pool
    }

    /// Does candidate `r` lose to an earlier-ordered concurrent winner that
    /// revokes its author (TRUST.md §5 step 3)?
    fn loses(&self, r: u32, pool: &Pool, win_at: impl Fn(u32) -> bool) -> bool {
        let kr = self.key(r);
        pool.get(&self.meta[r as usize].author)
            .into_iter()
            .flatten()
            .any(|&w| win_at(w) && self.key(w) < kr && self.concurrent(w, r))
    }

    /// Is `i` concurrent with a winner revoking its author (step 4)?
    fn excluded(&self, i: u32, pool: &Pool, win_at: impl Fn(u32) -> bool) -> bool {
        pool.get(&self.meta[i as usize].author).into_iter().flatten().any(|&w| win_at(w) && self.concurrent(w, i))
    }

    /// The winners in `pool` (per `win_at`) by target, for
    /// `revoked_concurrently`.
    fn winners_by_target(&self, pool: &Pool, win_at: impl Fn(u32) -> bool) -> HashMap<SignPk, TargetWinners> {
        pool.iter()
            .filter_map(|(t, cands)| {
                let ws: Vec<u32> = cands.iter().copied().filter(|&w| win_at(w)).collect();
                (!ws.is_empty()).then(|| (*t, self.target_winners(ws)))
            })
            .collect()
    }

    /// Winning revocations of one target, sorted by topological index, with
    /// two flags per winner: every earlier winner is in its past (`closed`),
    /// every later one in its future (`open`).
    fn target_winners(&self, mut ws: Vec<u32>) -> TargetWinners {
        ws.sort_by_key(|&w| self.pos[w as usize]);
        let n = ws.len();
        let mut closed = vec![true; n];
        for j in 1..n {
            for k in (0..j).rev() {
                if !self.le(ws[k], ws[j]) {
                    closed[j] = false;
                    break;
                }
                if closed[k] {
                    break;
                }
            }
        }
        let mut open = vec![true; n];
        for j in (0..n.saturating_sub(1)).rev() {
            for k in j + 1..n {
                if !self.le(ws[j], ws[k]) {
                    open[j] = false;
                    break;
                }
                if open[k] {
                    break;
                }
            }
        }
        TargetWinners { ws, closed, open }
    }

    /// `excluded` over `winners_by_target`.
    fn revoked_concurrently(&self, i: u32, winners: &HashMap<SignPk, TargetWinners>) -> bool {
        winners.get(&self.meta[i as usize].author).is_some_and(|tw| self.concurrent_with_any(i, tw))
    }

    /// Is `i` concurrent with one of `tw`'s winners? Scans outward from
    /// `i`'s place in the topological order and stops at a winner in `i`'s
    /// past (future) whose earlier (later) winners are all in its own, so a
    /// member revoked many times over a long history costs a few checks per
    /// op, not one per revocation.
    fn concurrent_with_any(&self, i: u32, tw: &TargetWinners) -> bool {
        let p = tw.ws.partition_point(|&w| self.pos[w as usize] < self.pos[i as usize]);
        for k in (0..p).rev() {
            if !self.le(tw.ws[k], i) {
                return true;
            }
            if tw.closed[k] {
                break;
            }
        }
        for k in p..tw.ws.len() {
            let w = tw.ws[k];
            if w == i {
                continue;
            }
            if !self.le(i, w) {
                return true;
            }
            if tw.open[k] {
                break;
            }
        }
        false
    }

    /// Step 3 for the region's candidates `cands` (in candidate order), as
    /// `loses` decides it one by one, without rescanning every revocation of
    /// the author for each candidate. Candidates come in groups of equal
    /// author seniority; the winners against an author from more senior
    /// authors are all decided before the group starts, so they are indexed
    /// once per group (`target_winners`); winners of equal seniority (a
    /// `Leave`, or authors with no seniority) are checked one by one.
    fn decide_winners(
        &self,
        cands: &[u32],
        pool: &Pool,
        from: u32,
        skip: impl Fn(u32) -> bool,
        prefix_win: impl Fn(u32) -> bool,
        rwin: &mut [bool],
    ) {
        let mut i = 0;
        while i < cands.len() {
            let rank = self.rank(&self.meta[cands[i] as usize].author);
            let end = cands[i..]
                .iter()
                .position(|&c| self.rank(&self.meta[c as usize].author) != rank)
                .map_or(cands.len(), |d| i + d);
            let mut groups: HashMap<SignPk, (TargetWinners, Vec<u32>)> = HashMap::new();
            for &c in &cands[i..end] {
                if skip(c) {
                    continue;
                }
                let author = self.meta[c as usize].author;
                let win_at = |w: u32, rwin: &[bool]| if w >= from { rwin[(w - from) as usize] } else { prefix_win(w) };
                let (senior, same) = groups.entry(author).or_insert_with(|| {
                    let all = pool.get(&author).map_or(&[][..], Vec::as_slice);
                    let senior = all
                        .iter()
                        .copied()
                        .filter(|&w| self.rank(&self.meta[w as usize].author) < rank && win_at(w, rwin))
                        .collect();
                    let same =
                        all.iter().copied().filter(|&w| self.rank(&self.meta[w as usize].author) == rank).collect();
                    (self.target_winners(senior), same)
                });
                let kc = self.key(c);
                let lost = self.concurrent_with_any(c, senior)
                    || same.iter().any(|&w| win_at(w, rwin) && self.key(w) < kc && self.concurrent(w, c));
                rwin[(c - from) as usize] = !lost;
            }
            i = end;
        }
    }

    /// No op valid (per `valid`) in `i`'s past created epoch `e`.
    fn fresh_epoch(&self, i: u32, e: &EpochId, valid: impl Fn(u32) -> bool) -> bool {
        self.epoch_ops.get(e).into_iter().flatten().all(|&j| j == i || !valid(j) || !self.le(j, i))
    }

    /// Make exactly `k` rounds. New rounds copy the last one, whose ops are
    /// at their fixed point (the loop stopped there).
    fn resize_rounds(&mut self, k: usize) {
        while self.rounds.len() < k {
            let mut last = self.rounds.last().cloned().unwrap_or_else(|| Round {
                valid: vec![false; self.ids.len()],
                win: vec![false; self.ids.len()],
                ..Default::default()
            });
            last.fails.clear();
            self.rounds.push(last);
        }
        self.rounds.truncate(k);
    }

    /// Record a cut after re-resolving the region from slot `from`, which
    /// started at the newest cut.
    fn push_cut(&mut self, from: u32) {
        let lens = std::iter::once(&self.pre).chain(&self.rounds).map(|r| r.log.len()).collect();
        let n = self.ids.len() as u32;
        let prev = &self.cuts[self.cuts.len() - 1].loose;
        let loose = prev
            .iter()
            .copied()
            .chain(from..n)
            .filter(|&y| {
                let y_ = y as usize;
                self.rounds.iter().any(|r| r.valid[y_] || r.win[y_]) && !self.head_slots.iter().any(|&h| self.le(y, h))
            })
            .collect();
        // Mark the region's dead ops (see `dead`), parents first.
        for y in from..n {
            let y_ = y as usize;
            let invalid = !self.pre.valid[y_] && !self.rounds.iter().any(|r| r.valid[y_]);
            let closed = invalid
                && self.meta[y_]
                    .parents
                    .iter()
                    .all(|&p| self.dead[p as usize] != 0 || self.head_slots.iter().any(|&h| self.le(p, h)));
            self.dead[y_] = if closed { n } else { 0 };
        }
        self.cuts.push(Cut { slot: n, frontier: self.head_slots.clone(), lens, full_len: self.full_log.len(), loose });
        self.thin_cuts();
    }

    /// Drop cuts until each gap between kept cuts (in slots) is at most the
    /// age of the younger one, or was a single update. Any subset of valid
    /// cuts is valid; a sparser one only means a larger region for an op
    /// that lags behind. With this rule an op whose parents arrived `lag`
    /// slots ago finds a cut less than `2 · lag` slots back (plus the size
    /// of the update that made it), and the cuts kept are O(log n): stepping
    /// two cuts back at least doubles the age. Cut 0 (re-resolve
    /// everything) and the newest cut (the fast path's) always stay.
    fn thin_cuts(&mut self) {
        let n = self.ids.len() as u32;
        let mut last = self.cuts[0].slot;
        let mut keep = vec![true];
        for w in self.cuts.windows(2).skip(1) {
            let (here, next) = (w[0].slot, w[1].slot);
            let drop = next - last <= n - next;
            if !drop {
                last = here;
            }
            keep.push(!drop);
        }
        let mut keep = keep.into_iter();
        self.cuts.retain(|_| keep.next().unwrap_or(true));
    }

    /// Rewind every round's head state and the full state to cut `ci`.
    fn rewind(&mut self, ops: &HashMap<OpId, SignedOp>, ci: usize) {
        let cut = self.cuts[ci].clone();
        let last = *cut.lens.last().unwrap();
        for (k, r) in std::iter::once(&mut self.pre).chain(&mut self.rounds).enumerate() {
            let len = cut.lens.get(k).copied().unwrap_or(last);
            while r.log.len() > len {
                let u = r.log.pop().unwrap();
                undo_role(&mut r.st, &self.meta, u);
            }
        }
        while self.full_log.len() > cut.full_len {
            match self.full_log.pop().unwrap() {
                FullUndo::Member(pk, prev) => {
                    match prev {
                        Some(m) => self.state.members.insert(pk, m),
                        None => self.state.members.remove(&pk),
                    };
                }
                FullUndo::Epoch => {
                    self.state.epochs.pop();
                    self.aux.creators.pop();
                }
                FullUndo::Keyring(pk, s, prev) => {
                    // Later epochs are already undone: drop the member from
                    // the epochs this add covered and nothing else covers.
                    let mut epochs = std::mem::take(&mut self.state.epochs);
                    let skip = prev.covered as usize;
                    for (e, &c) in epochs.iter_mut().zip(&self.aux.creators).skip(skip) {
                        let named = || {
                            rotation_of(&ops[&self.ids[c as usize]])
                                .is_some_and(|r| r.lockboxes.binary_search_by_key(&pk, |(k, _)| *k).is_ok())
                        };
                        if c != s
                            && e.recipients.contains(&pk)
                            && self.le(c, s)
                            && !named()
                            && !prev.frontier.iter().any(|&a| self.le(c, a))
                        {
                            e.recipients.remove(&pk);
                        }
                    }
                    self.state.epochs = epochs;
                    if prev.frontier.is_empty() {
                        self.aux.keyrings.remove(&pk);
                    } else {
                        self.aux.keyrings.insert(pk, prev);
                    }
                }
            }
        }
    }

    /// Re-resolve the region of cut `ci` (all ops at or above its slot), every
    /// round; ops at or above `first` are new. Cut 0 re-resolves everything.
    fn recompute(&mut self, ops: &HashMap<OpId, SignedOp>, ci: usize, first: u32) {
        if ci == 0 {
            self.seniority.clear();
            self.stats.full += 1;
        } else {
            self.stats.region += 1;
        }
        self.rewind(ops, ci);
        self.cuts.truncate(ci + 1);
        let from = self.cuts[ci].slot;
        let frontier = self.cuts[ci].frontier.clone();
        let n = self.ids.len() as u32;
        let rn = (n - from) as usize;
        self.stats.region_ops += rn as u64;
        let mut region: Vec<u32> = (from..n).collect();
        region.sort_by_key(|&s| self.pos[s as usize]);
        // Region children of each region op, to free causal states early.
        let mut children = vec![0u32; rn];
        for &s in &region {
            for &p in &self.meta[s as usize].parents {
                if p >= from {
                    children[(p - from) as usize] += 1;
                }
            }
        }
        let mut walk = Walk { from, children, mark: vec![0; rn], stamp: 0 };

        // Round 0: authorization ignoring concurrency, for new ops (old ops'
        // results depend only on their past, so they never change).
        let pre_from = if ci == 0 { 0 } else { first };
        {
            let base = self.pre.st.clone();
            let mut rvalid: Vec<bool> = region_slice(&self.pre.valid, from);
            let mut abort = false;
            self.walk(ops, &mut walk, &region, &base, &mut rvalid, |res, i, st, rvalid| {
                if i < pre_from {
                    return rvalid[(i - from) as usize];
                }
                let op = &ops[&res.ids[i as usize]];
                authorized(op, res.pos[i as usize], st, |e| {
                    res.fresh_epoch(i, e, |j| {
                        if j >= from { rvalid[(j - from) as usize] } else { res.pre.valid[j as usize] }
                    })
                })
            });
            for (o, &v) in rvalid.iter().enumerate() {
                self.pre.valid[from as usize + o] = v;
            }
            // Seniority from new valid naming ops, in topological order.
            let mut ranked = Vec::new();
            for &s in &region {
                if (s >= pre_from) && self.pre.valid[s as usize] {
                    abort |= !self.note_seniority(s, from);
                    ranked.extend(self.meta[s as usize].names);
                }
            }
            // `choose_cut` checked the region's candidates against the cut's
            // loose ops with their authors' old ranks. A candidate whose
            // author was just ranked (or moved up) can now sort ahead of a
            // loose op of its target that won a round, and so change that
            // op's result: the cut no longer holds. (Rare: it takes a valid
            // `Add` and a revocation by the added member in one update.)
            if !abort && ci != 0 && !ranked.is_empty() {
                let loose = &self.cuts[ci].loose;
                abort = region.iter().any(|&c| {
                    let m = &self.meta[c as usize];
                    m.target.is_some_and(|t| ranked.contains(&m.author) && self.has_partner(loose, t, c))
                });
            }
            if abort && ci != 0 {
                // Undo nothing else: the full recompute rebuilds everything.
                return self.recompute(ops, 0, first);
            }
        }

        // Rounds 1…: winners, exclusion, authorization, until no winner fails.
        let k_old = self.rounds.len();
        let k_pre = if ci == 0 { 1 } else { self.prefix_rounds(from) };
        let mut cands: Vec<u32> = region.iter().copied().filter(|&s| self.meta[s as usize].target.is_some()).collect();
        cands.sort_by_key(|&c| self.key(c));
        let pool = self.pool(&self.cuts[ci].loose, from..n);
        let mut removed = vec![usize::MAX; rn];
        let mut results: Vec<(Vec<bool>, Vec<bool>, Vec<u32>)> = Vec::new();
        let mut k = 1;
        loop {
            let pk = k.min(k_old).max(1) - 1;
            let mut rwin = vec![false; rn];
            self.decide_winners(
                &cands,
                &pool,
                from,
                |c| removed[(c - from) as usize] <= k,
                |w| self.prefix_win(pk, w),
                &mut rwin,
            );
            let base = if k_old == 0 { RoleState::default() } else { self.rounds[pk].st.clone() };
            let mut rvalid = vec![false; rn];
            {
                let rwin = &rwin;
                let win_at = |w: u32| if w >= from { rwin[(w - from) as usize] } else { self.prefix_win(pk, w) };
                let winners = self.winners_by_target(&pool, win_at);
                self.walk(ops, &mut walk, &region, &base, &mut rvalid, |res, i, st, rvalid| {
                    if res.revoked_concurrently(i, &winners) {
                        return false;
                    }
                    let op = &ops[&res.ids[i as usize]];
                    authorized(op, res.pos[i as usize], st, |e| {
                        res.fresh_epoch(i, e, |j| {
                            if j >= from { rvalid[(j - from) as usize] } else { res.prefix_valid(pk, j) }
                        })
                    })
                });
            }
            let mut fails: Vec<u32> = cands
                .iter()
                .copied()
                .filter(|&c| {
                    let co = (c - from) as usize;
                    rwin[co] && !rvalid[co]
                })
                .collect();
            fails.sort_unstable();
            for &f in &fails {
                removed[(f - from) as usize] = k + 1;
            }
            let done = k >= k_pre && fails.is_empty();
            results.push((rvalid, rwin, fails));
            if done {
                break;
            }
            k += 1;
        }

        // Write the rounds back.
        let k_new = results.len();
        self.resize_rounds(k_new);
        for (k, (rvalid, rwin, fails)) in results.into_iter().enumerate() {
            let r = &mut self.rounds[k];
            r.valid[from as usize..].copy_from_slice(&rvalid);
            r.win[from as usize..].copy_from_slice(&rwin);
            let keep = r.fails.partition_point(|&f| f < from);
            r.fails.truncate(keep);
            r.fails.extend(fails);
        }

        // New valid heads: the maximal valid region ops (each descends from
        // the whole cut frontier), or the frontier if none is valid.
        let fin = self.rounds.len() - 1;
        let mut heads: Vec<u32> = Vec::new();
        for &s in &region {
            if self.rounds[fin].valid[s as usize] {
                heads.retain(|&h| !self.le(h, s));
                heads.push(s);
            }
        }
        if heads.is_empty() {
            heads = frontier;
        }
        let below: Vec<bool> = region.iter().map(|&s| heads.iter().any(|&h| self.le(s, h))).collect();

        // Head states: each round's valid region ops in the heads' past.
        for k in 0..=self.rounds.len() {
            let mut r = std::mem::take(if k == 0 { &mut self.pre } else { &mut self.rounds[k - 1] });
            for (o, &s) in region.iter().enumerate() {
                if below[o] && r.valid[s as usize] {
                    let prev = apply_role(&mut r.st, &ops[&self.ids[s as usize]]);
                    r.log.push(RoleUndo { slot: s, prev });
                }
            }
            *(if k == 0 { &mut self.pre } else { &mut self.rounds[k - 1] }) = r;
        }
        for &s in &region {
            if self.rounds[fin].valid[s as usize] {
                self.push_full(ops, s, from);
            }
        }
        self.heads = heads.iter().map(|&h| self.ids[h as usize]).collect();
        self.heads.sort();
        self.head_slots = heads;
        self.push_cut(from);
    }

    fn prefix_win(&self, k: usize, w: u32) -> bool {
        self.rounds.get(k).is_some_and(|r| r.win[w as usize])
    }

    fn prefix_valid(&self, k: usize, j: u32) -> bool {
        self.rounds.get(k).is_some_and(|r| r.valid[j as usize])
    }

    /// Walk the region in topological order, deciding each op's validity
    /// with `decide(self, op, causal state, validity so far)`. The causal
    /// state of an op is `base` (the round's state at the cut) plus its valid
    /// region ancestors, replayed in topological order: inherited from a
    /// single region parent, or merged from several by rewinding one parent's
    /// state to the first op it lacks and replaying from there.
    fn walk(
        &self,
        ops: &HashMap<OpId, SignedOp>,
        w: &mut Walk,
        region: &[u32],
        base: &RoleState,
        rvalid: &mut [bool],
        decide: impl Fn(&Self, u32, &RoleState, &[bool]) -> bool,
    ) {
        let from = w.from;
        let base = Rc::new(PState { st: base.clone(), log: None });
        let mut post: Vec<Option<Rc<PState>>> = vec![None; region.len()];
        let mut left = w.children.clone();
        for &i in region {
            let rp: Vec<u32> = self.meta[i as usize].parents.iter().copied().filter(|&p| p >= from).collect();
            let cst = match rp.as_slice() {
                [] => base.clone(),
                [p] => post[(p - from) as usize].clone().expect("parent state kept until its last child"),
                _ => self.merge(ops, w, &post, &rp, rvalid),
            };
            for &p in &rp {
                let po = (p - from) as usize;
                left[po] -= 1;
                if left[po] == 0 {
                    post[po] = None;
                }
            }
            let io = (i - from) as usize;
            let v = decide(self, i, &cst.st, rvalid);
            rvalid[io] = v;
            if left[io] > 0 {
                let mut st = cst;
                if v {
                    let m = Rc::make_mut(&mut st);
                    let prev = apply_role(&mut m.st, &ops[&self.ids[i as usize]]);
                    m.push(RoleUndo { slot: i, prev });
                }
                post[io] = Some(st);
            }
        }
    }

    /// Causal state of a region op with several region parents `rp`.
    fn merge(
        &self,
        ops: &HashMap<OpId, SignedOp>,
        w: &mut Walk,
        post: &[Option<Rc<PState>>],
        rp: &[u32],
        rvalid: &[bool],
    ) -> Rc<PState> {
        let from = w.from;
        let p1 = *rp.iter().max_by_key(|&&p| self.pos[p as usize]).unwrap();
        let first = post[(p1 - from) as usize].clone().expect("parent state kept until its last child");
        // Valid region ancestors not in p1's past.
        w.stamp += 1;
        let mut side = Vec::new();
        let mut stack: Vec<u32> = rp.iter().copied().filter(|&p| p != p1).collect();
        while let Some(y) = stack.pop() {
            if y < from {
                continue;
            }
            let yo = (y - from) as usize;
            if w.mark[yo] == w.stamp || self.le(y, p1) {
                continue;
            }
            w.mark[yo] = w.stamp;
            if rvalid[yo] {
                side.push(y);
            }
            stack.extend_from_slice(&self.meta[y as usize].parents);
        }
        if side.is_empty() {
            return first;
        }
        let q = side.iter().map(|&s| self.pos[s as usize]).min().unwrap();
        let mut st = (*first).clone();
        let mut redo = side;
        while let Some(node) = st.log.clone().filter(|n| self.pos[n.u.slot as usize] >= q) {
            let u = node.u;
            st.log = node.prev.clone();
            undo_role(&mut st.st, &self.meta, u);
            redo.push(u.slot);
        }
        redo.sort_by_key(|&s| self.pos[s as usize]);
        for s in redo {
            let prev = apply_role(&mut st.st, &ops[&self.ids[s as usize]]);
            st.push(RoleUndo { slot: s, prev });
        }
        Rc::new(st)
    }

    /// Apply valid op `s` to the full state (TRUST.md §5 step 7), logging
    /// undo. Every valid op before slot `from` is in `s`'s past.
    fn push_full(&mut self, ops: &HashMap<OpId, SignedOp>, s: u32, from: u32) {
        let mut state = std::mem::take(&mut self.state);
        let mut aux = std::mem::take(&mut self.aux);
        let mut log = std::mem::take(&mut self.full_log);
        self.apply_full(&mut state, &mut aux, Some(&mut log), ops, s, from);
        self.state = state;
        self.aux = aux;
        self.full_log = log;
    }

    fn apply_full(
        &self,
        st: &mut MemberState,
        aux: &mut Aux,
        log: Option<&mut Vec<FullUndo>>,
        ops: &HashMap<OpId, SignedOp>,
        s: u32,
        from: u32,
    ) {
        let id = self.ids[s as usize];
        let op = &ops[&id].op;
        let mut undo = Vec::new();
        let Aux { creators, keyrings } = aux;
        let mut push_epoch = |st: &mut MemberState, undo: &mut Vec<FullUndo>, r: &Rotation| {
            st.epochs.push(Epoch { id: r.epoch, commitment: r.commitment, created_by: id, recipients: recipients(r) });
            creators.push(s);
            undo.push(FullUndo::Epoch);
        };
        match &op.action {
            Action::Genesis { founder, rotation } => {
                let prev = st.members.insert(founder.sign_pk, Member { keys: *founder, role: Role::Admin });
                undo.push(FullUndo::Member(founder.sign_pk, prev));
                push_epoch(st, &mut undo, rotation);
            }
            Action::Add { member, role, .. } => {
                let prev = st.members.insert(member.sign_pk, Member { keys: *member, role: *role });
                undo.push(FullUndo::Member(member.sign_pk, prev));
                if role.can_read() {
                    // The keyring covers exactly the epochs in the adder's
                    // causal past. Those before `covered` already have the
                    // member; `covered` moves up to the first one left out.
                    let kr = keyrings.entry(member.sign_pk).or_default();
                    let prev = kr.clone();
                    let mut covered = None;
                    let skip = prev.covered as usize;
                    for (i, (epoch, &c)) in st.epochs.iter_mut().zip(creators.iter()).enumerate().skip(skip) {
                        if c != s && (c < from || self.le(c, s)) {
                            epoch.recipients.insert(member.sign_pk);
                        } else if covered.is_none() && !epoch.recipients.contains(&member.sign_pk) {
                            covered = Some(i as u32);
                        }
                    }
                    kr.covered = covered.unwrap_or(st.epochs.len() as u32);
                    kr.frontier.retain(|&a| !self.le(a, s));
                    kr.frontier.push(s);
                    undo.push(FullUndo::Keyring(member.sign_pk, s, prev));
                }
            }
            Action::SetRole { member, role, rotation, .. } => {
                if let Some(m) = st.members.get_mut(member) {
                    let prev = m.clone();
                    m.role = *role;
                    undo.push(FullUndo::Member(*member, Some(prev)));
                }
                if let Some(r) = rotation {
                    push_epoch(st, &mut undo, r);
                }
            }
            Action::Remove { member, rotation, .. } => {
                let prev = st.members.remove(member);
                undo.push(FullUndo::Member(*member, prev));
                push_epoch(st, &mut undo, rotation);
            }
            Action::Rotate { rotation } => push_epoch(st, &mut undo, rotation),
            Action::Leave { .. } => {
                let prev = st.members.remove(&op.author);
                undo.push(FullUndo::Member(op.author, prev));
            }
        }
        if let Some(log) = log {
            log.extend(undo);
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Tests turn the fast path off to check the general path against it.
    pub(crate) static FAST_PATH: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

#[cfg(test)]
fn fast_path_enabled() -> bool {
    FAST_PATH.get()
}

#[cfg(not(test))]
fn fast_path_enabled() -> bool {
    true
}

/// Scratch shared by the region walks of one recompute.
struct Walk {
    from: u32,
    children: Vec<u32>,
    mark: Vec<u32>,
    stamp: u32,
}

fn region_slice(v: &[bool], from: u32) -> Vec<bool> {
    v[from as usize..].to_vec()
}

fn undo_role(st: &mut RoleState, meta: &[Meta], u: RoleUndo) {
    if let Prev::Role(prev) = u.prev {
        let pk = meta[u.slot as usize].touches.expect("an op that changed a role touches a member");
        st.set(pk, prev);
    }
}

/// `new` ordered so that parents come first (each op's parents are already
/// known or earlier in the list).
fn topo_sorted(ops: &HashMap<OpId, SignedOp>, new: &[OpId]) -> Vec<OpId> {
    let set: std::collections::HashSet<OpId> = new.iter().copied().collect();
    let mut indegree: HashMap<OpId, usize> = HashMap::new();
    let mut children: HashMap<OpId, Vec<OpId>> = HashMap::new();
    for id in new {
        let ps: Vec<OpId> = ops[id].op.parents.iter().copied().filter(|p| set.contains(p)).collect();
        indegree.insert(*id, ps.len());
        for p in ps {
            children.entry(p).or_default().push(*id);
        }
    }
    let mut ready: BTreeSet<OpId> = indegree.iter().filter(|(_, d)| **d == 0).map(|(id, _)| *id).collect();
    let mut out = Vec::with_capacity(new.len());
    while let Some(id) = ready.pop_first() {
        out.push(id);
        for c in children.get(&id).into_iter().flatten() {
            let d = indegree.get_mut(c).unwrap();
            *d -= 1;
            if *d == 0 {
                ready.insert(*c);
            }
        }
    }
    out
}
