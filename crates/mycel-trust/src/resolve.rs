//! Deterministic resolution of the membership DAG (TRUST.md §5).

use std::collections::{BTreeSet, HashMap};

use mycel_crypto::SignPk;

use crate::bitset::BitSet;
use crate::{Action, Epoch, Member, MemberState, OpId, Role, Rotation, SignedOp};

/// Result of resolving a DAG: topo order, ancestry, validity and current state.
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    pub order: Vec<OpId>,
    index: HashMap<OpId, usize>,
    /// Strict ancestors of each op, by topo index.
    anc: Vec<BitSet>,
    valid: BitSet,
    pub(crate) heads: Vec<OpId>,
    /// Winning revocation ops.
    pub winners: Vec<OpId>,
    pub state: MemberState,
}

impl Resolution {
    pub fn is_valid(&self, id: &OpId) -> bool {
        self.index.get(id).is_some_and(|&i| self.valid.get(i))
    }

    pub fn in_past(&self, a: &OpId, heads: &[OpId]) -> bool {
        let Some(&ai) = self.index.get(a) else {
            return false;
        };
        heads.iter().any(|h| self.index.get(h).is_some_and(|&hi| hi == ai || self.anc[hi].get(ai)))
    }

    pub(crate) fn state_at(&self, ops: &HashMap<OpId, SignedOp>, heads: &[OpId]) -> MemberState {
        let mut set = BitSet::new(self.order.len());
        for h in heads {
            let hi = self.index[h];
            set.set(hi);
            set.union_with(&self.anc[hi]);
        }
        let set = set.intersect(&self.valid);
        replay(ops, &self.order, &self.index, &self.anc, &set)
    }
}

fn concurrent(anc: &[BitSet], a: usize, b: usize) -> bool {
    a != b && !anc[a].get(b) && !anc[b].get(a)
}

fn revocation_target(op: &SignedOp) -> Option<SignPk> {
    match &op.op.action {
        Action::Remove { member, .. } => Some(*member),
        Action::SetRole { member, revocation: Some(_), .. } => Some(*member),
        Action::Leave { .. } => Some(op.op.author),
        _ => None,
    }
}

pub(crate) fn resolve(ops: &HashMap<OpId, SignedOp>) -> Resolution {
    // 1. Topological order, ties broken by op id.
    let mut children: HashMap<OpId, Vec<OpId>> = HashMap::new();
    let mut indegree: HashMap<OpId, usize> = HashMap::new();
    for (id, op) in ops {
        indegree.insert(*id, op.op.parents.len());
        for p in &op.op.parents {
            children.entry(*p).or_default().push(*id);
        }
    }
    let mut ready: BTreeSet<OpId> = indegree.iter().filter(|(_, d)| **d == 0).map(|(id, _)| *id).collect();
    let mut order = Vec::with_capacity(ops.len());
    while let Some(id) = ready.pop_first() {
        order.push(id);
        for c in children.get(&id).into_iter().flatten() {
            let d = indegree.get_mut(c).unwrap();
            *d -= 1;
            if *d == 0 {
                ready.insert(*c);
            }
        }
    }
    let n = order.len();
    let index: HashMap<OpId, usize> = order.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let mut anc: Vec<BitSet> = Vec::with_capacity(n);
    for id in &order {
        let mut set = BitSet::new(n);
        for p in &ops[id].op.parents {
            let pi = index[p];
            set.set(pi);
            set.union_with(&anc[pi]);
        }
        anc.push(set);
    }
    let op_at = |i: usize| &ops[&order[i]];
    let author: Vec<SignPk> = (0..n).map(|i| op_at(i).op.author).collect();
    let target: Vec<Option<SignPk>> = (0..n).map(|i| revocation_target(op_at(i))).collect();
    let mut by_author: HashMap<SignPk, Vec<usize>> = HashMap::new();
    for (i, pk) in author.iter().enumerate() {
        by_author.entry(*pk).or_default().push(i);
    }

    // 2. Seniority from ops that pass authorization ignoring concurrency.
    let pre_valid = validate(ops, &order, &index, &anc, &BitSet::new(n));
    let mut seniority: HashMap<SignPk, usize> = HashMap::new();
    for i in pre_valid.iter() {
        match &op_at(i).op.action {
            Action::Genesis { founder, .. } => {
                seniority.entry(founder.sign_pk).or_insert(i);
            }
            Action::Add { member, .. } => {
                seniority.entry(member.sign_pk).or_insert(i);
            }
            _ => {}
        }
    }
    let rank = |pk: &SignPk| seniority.get(pk).copied().unwrap_or(usize::MAX);

    let mut candidates: Vec<usize> = (0..n).filter(|&i| target[i].is_some()).collect();
    candidates.sort_by_key(|&i| (rank(&author[i]), i));

    loop {
        // 3. Revocation winners in seniority order.
        let mut winners: Vec<usize> = Vec::new();
        let mut won_against: HashMap<SignPk, Vec<usize>> = HashMap::new();
        for &r in &candidates {
            let loses = won_against.get(&author[r]).is_some_and(|ws| ws.iter().any(|&w| concurrent(&anc, w, r)));
            if !loses {
                winners.push(r);
                won_against.entry(target[r].unwrap()).or_default().push(r);
            }
        }
        // 4. Ops by a revoked member, concurrent with the winning revocation, are invalid.
        let mut excluded = BitSet::new(n);
        for &w in &winners {
            for &i in by_author.get(&target[w].unwrap()).into_iter().flatten() {
                if concurrent(&anc, i, w) {
                    excluded.set(i);
                }
            }
        }
        // 5. Authorization replay.
        let valid = validate(ops, &order, &index, &anc, &excluded);
        // 6. Winners that turned out unauthorized lose their candidacy; retry.
        let failed: Vec<usize> = winners.iter().copied().filter(|&w| !valid.get(w)).collect();
        if failed.is_empty() {
            let state = replay(ops, &order, &index, &anc, &valid);
            let mut covered = BitSet::new(n);
            for i in valid.iter() {
                covered.union_with(&anc[i]);
            }
            let mut heads: Vec<_> = valid.iter().filter(|&i| !covered.get(i)).map(|i| order[i]).collect();
            heads.sort();
            return Resolution {
                winners: winners.iter().map(|&w| order[w]).collect(),
                order,
                index,
                anc,
                valid,
                heads,
                state,
            };
        }
        candidates.retain(|c| !failed.contains(c));
    }
}

/// Walk ops in topo order; each op is valid iff its author was authorized in
/// the state built from valid ops in its causal past.
///
/// `running` is the state of every valid op so far. When an op's causal past
/// already contains all of them (any linear stretch of history, e.g. one
/// admin's sequence of changes) that state is used directly, so such history
/// resolves in linear time. Otherwise the op's own past is replayed.
fn validate(
    ops: &HashMap<OpId, SignedOp>,
    order: &[OpId],
    index: &HashMap<OpId, usize>,
    anc: &[BitSet],
    excluded: &BitSet,
) -> BitSet {
    let n = order.len();
    let mut valid = BitSet::new(n);
    let mut running = MemberState::default();
    for i in 0..n {
        if excluded.get(i) {
            continue;
        }
        let ok = if anc[i].contains_all(&valid) {
            authorized(&ops[&order[i]], i, &running)
        } else {
            let st = replay(ops, order, index, anc, &anc[i].intersect(&valid));
            authorized(&ops[&order[i]], i, &st)
        };
        if ok {
            valid.set(i);
            apply(&mut running, ops, order, index, anc, i);
        }
    }
    valid
}

fn recipients(r: &Rotation) -> BTreeSet<SignPk> {
    r.lockboxes.iter().map(|(pk, _)| *pk).collect()
}

fn fresh_epoch(st: &MemberState, r: &Rotation) -> bool {
    st.epoch(&r.epoch).is_none()
}

/// Readers after `member` changes to `role` (`None` = leaves the space).
fn readers_after(st: &MemberState, member: &SignPk, role: Option<Role>) -> BTreeSet<SignPk> {
    let mut readers = st.readers();
    if role.is_some_and(Role::can_read) {
        readers.insert(*member);
    } else {
        readers.remove(member);
    }
    readers
}

/// Admins after `member` changes to `role` (`None` = leaves the space).
fn admins_after(st: &MemberState, member: &SignPk, role: Option<Role>) -> usize {
    let before = st.role(member).is_some_and(Role::is_admin);
    let after = role.is_some_and(Role::is_admin);
    st.admin_count() + usize::from(after) - usize::from(before)
}

fn authorized(op: &SignedOp, idx: usize, st: &MemberState) -> bool {
    let author_role = st.role(&op.op.author);
    let is_admin = author_role.is_some_and(Role::is_admin);
    match &op.op.action {
        Action::Genesis { founder, rotation } => idx == 0 && recipients(rotation) == BTreeSet::from([founder.sign_pk]),
        Action::Add { member, .. } => is_admin && !st.members.contains_key(&member.sign_pk),
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
                    .is_none_or(|r| fresh_epoch(st, r) && recipients(r) == readers_after(st, member, Some(*role)))
                && admins_after(st, member, Some(*role)) > 0
        }
        Action::Remove { member, rotation, .. } => {
            st.members.contains_key(member)
                && is_admin
                && fresh_epoch(st, rotation)
                && recipients(rotation) == readers_after(st, member, None)
                && admins_after(st, member, None) > 0
        }
        Action::Rotate { rotation } => {
            author_role.is_some_and(Role::can_write)
                && fresh_epoch(st, rotation)
                && recipients(rotation) == st.readers()
        }
        Action::Leave { .. } => author_role.is_some() && admins_after(st, &op.op.author, None) > 0,
    }
}

fn push_epoch(st: &mut MemberState, r: &Rotation, created_by: OpId) {
    st.epochs.push(Epoch { id: r.epoch, commitment: r.commitment, created_by, recipients: recipients(r) });
}

/// Build state by applying the ops in `set` in topo order.
fn replay(
    ops: &HashMap<OpId, SignedOp>,
    order: &[OpId],
    index: &HashMap<OpId, usize>,
    anc: &[BitSet],
    set: &BitSet,
) -> MemberState {
    let mut st = MemberState::default();
    for i in set.iter() {
        apply(&mut st, ops, order, index, anc, i);
    }
    st
}

/// Apply the op at topo index `i` to `st`.
fn apply(
    st: &mut MemberState,
    ops: &HashMap<OpId, SignedOp>,
    order: &[OpId],
    index: &HashMap<OpId, usize>,
    anc: &[BitSet],
    i: usize,
) {
    let index_of = |id: &OpId| index.get(id).copied();
    let id = order[i];
    let op = &ops[&id].op;
    match &op.action {
        Action::Genesis { founder, rotation } => {
            st.members.insert(founder.sign_pk, Member { keys: *founder, role: Role::Admin });
            push_epoch(st, rotation, id);
        }
        Action::Add { member, role, .. } => {
            st.members.insert(member.sign_pk, Member { keys: *member, role: *role });
            if role.can_read() {
                // The keyring covers exactly the epochs in the adder's causal past.
                for e in st.epochs.iter_mut() {
                    if index_of(&e.created_by).is_some_and(|ei| anc[i].get(ei)) {
                        e.recipients.insert(member.sign_pk);
                    }
                }
            }
        }
        Action::SetRole { member, role, rotation, .. } => {
            if let Some(m) = st.members.get_mut(member) {
                m.role = *role;
            }
            if let Some(r) = rotation {
                push_epoch(st, r, id);
            }
        }
        Action::Remove { member, rotation, .. } => {
            st.members.remove(member);
            push_epoch(st, rotation, id);
        }
        Action::Rotate { rotation } => push_epoch(st, rotation, id),
        Action::Leave { .. } => {
            st.members.remove(&op.author);
        }
    }
}
