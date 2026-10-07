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
        heads.iter().any(|h| {
            self.index
                .get(h)
                .is_some_and(|&hi| hi == ai || self.anc[hi].get(ai))
        })
    }

    pub(crate) fn state_at(&self, ops: &HashMap<OpId, SignedOp>, heads: &[OpId]) -> MemberState {
        let mut set = BitSet::new(self.order.len());
        for h in heads {
            let hi = self.index[h];
            set.set(hi);
            set.union_with(&self.anc[hi]);
        }
        let set = set.intersect(&self.valid);
        replay(ops, &self.order, &self.anc, &set)
    }
}

fn concurrent(anc: &[BitSet], a: usize, b: usize) -> bool {
    a != b && !anc[a].get(b) && !anc[b].get(a)
}

fn revocation_target(op: &SignedOp) -> Option<SignPk> {
    match &op.op.action {
        Action::Remove { member, .. } => Some(*member),
        Action::SetRole {
            member,
            revocation: Some(_),
            ..
        } => Some(*member),
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
    let mut ready: BTreeSet<OpId> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| *id)
        .collect();
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

    // 2. Seniority from ops that pass authorization ignoring concurrency.
    let pre_valid = validate(ops, &order, &anc, &BitSet::new(n));
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

    let mut candidates: Vec<usize> = (0..n)
        .filter(|&i| revocation_target(op_at(i)).is_some())
        .collect();
    candidates.sort_by_key(|&i| (rank(&op_at(i).op.author), i));

    loop {
        // 3. Revocation winners in seniority order.
        let mut winners: Vec<usize> = Vec::new();
        for &r in &candidates {
            let author = op_at(r).op.author;
            let loses = winners.iter().any(|&w| {
                revocation_target(op_at(w)) == Some(author) && concurrent(&anc, w, r)
            });
            if !loses {
                winners.push(r);
            }
        }
        // 4. Ops by a revoked member, concurrent with the winning revocation, are invalid.
        let mut excluded = BitSet::new(n);
        for &w in &winners {
            let target = revocation_target(op_at(w)).unwrap();
            for i in 0..n {
                if op_at(i).op.author == target && concurrent(&anc, i, w) {
                    excluded.set(i);
                }
            }
        }
        // 5. Authorization replay.
        let valid = validate(ops, &order, &anc, &excluded);
        // 6. Winners that turned out unauthorized lose their candidacy; retry.
        let failed: Vec<usize> = winners.iter().copied().filter(|&w| !valid.get(w)).collect();
        if failed.is_empty() {
            let state = replay(ops, &order, &anc, &valid);
            return Resolution {
                winners: winners.iter().map(|&w| order[w]).collect(),
                order,
                index,
                anc,
                valid,
                state,
            };
        }
        candidates.retain(|c| !failed.contains(c));
    }
}

/// Walk ops in topo order; each op is valid iff its author was authorized in
/// the state built from valid ops in its causal past.
fn validate(
    ops: &HashMap<OpId, SignedOp>,
    order: &[OpId],
    anc: &[BitSet],
    excluded: &BitSet,
) -> BitSet {
    let n = order.len();
    let mut valid = BitSet::new(n);
    for i in 0..n {
        if excluded.get(i) {
            continue;
        }
        let past = anc[i].intersect(&valid);
        let st = replay(ops, order, anc, &past);
        if authorized(&ops[&order[i]], i, &st) {
            valid.set(i);
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

fn authorized(op: &SignedOp, idx: usize, st: &MemberState) -> bool {
    let author_role = st.role(&op.op.author);
    let is_admin = author_role.is_some_and(Role::is_admin);
    match &op.op.action {
        Action::Genesis { founder, rotation } => {
            idx == 0 && recipients(rotation) == BTreeSet::from([founder.sign_pk])
        }
        Action::Add { member, .. } => is_admin && !st.members.contains_key(&member.sign_pk),
        Action::SetRole {
            member,
            role,
            revocation,
            rotation,
        } => {
            let Some(prior) = st.role(member) else {
                return false;
            };
            let loses_read = prior.can_read() && !role.can_read();
            let mut after = st.clone();
            after.members.get_mut(member).unwrap().role = *role;
            is_admin
                && *role != prior
                && revocation.is_some() == (*role < prior)
                && rotation.is_some() == loses_read
                && rotation
                    .as_ref()
                    .is_none_or(|r| fresh_epoch(st, r) && recipients(r) == after.readers())
                && after.admin_count() > 0
        }
        Action::Remove {
            member, rotation, ..
        } => {
            if !st.members.contains_key(member) {
                return false;
            }
            let mut after = st.clone();
            after.members.remove(member);
            is_admin
                && fresh_epoch(st, rotation)
                && recipients(rotation) == after.readers()
                && after.admin_count() > 0
        }
        Action::Rotate { rotation } => {
            author_role.is_some_and(Role::can_write)
                && fresh_epoch(st, rotation)
                && recipients(rotation) == st.readers()
        }
    }
}

fn push_epoch(st: &mut MemberState, r: &Rotation, created_by: OpId) {
    st.epochs.push(Epoch {
        id: r.epoch,
        commitment: r.commitment,
        created_by,
        recipients: recipients(r),
    });
}

/// Build state by applying the ops in `set` in topo order.
fn replay(
    ops: &HashMap<OpId, SignedOp>,
    order: &[OpId],
    anc: &[BitSet],
    set: &BitSet,
) -> MemberState {
    let index: HashMap<&OpId, usize> = order.iter().enumerate().map(|(i, id)| (id, i)).collect();
    let index_of = |id: &OpId| index.get(id).copied();
    let mut st = MemberState::default();
    for i in set.iter() {
        let id = order[i];
        let op = &ops[&id].op;
        match &op.action {
            Action::Genesis { founder, rotation } => {
                st.members.insert(
                    founder.sign_pk,
                    Member {
                        keys: *founder,
                        role: Role::Admin,
                    },
                );
                push_epoch(&mut st, rotation, id);
            }
            Action::Add { member, role, .. } => {
                st.members.insert(
                    member.sign_pk,
                    Member {
                        keys: *member,
                        role: *role,
                    },
                );
                if role.can_read() {
                    // The keyring covers exactly the epochs in the adder's causal past.
                    for e in st.epochs.iter_mut() {
                        if index_of(&e.created_by).is_some_and(|ei| anc[i].get(ei)) {
                            e.recipients.insert(member.sign_pk);
                        }
                    }
                }
            }
            Action::SetRole {
                member,
                role,
                rotation,
                ..
            } => {
                if let Some(m) = st.members.get_mut(member) {
                    m.role = *role;
                }
                if let Some(r) = rotation {
                    push_epoch(&mut st, r, id);
                }
            }
            Action::Remove {
                member, rotation, ..
            } => {
                st.members.remove(member);
                push_epoch(&mut st, rotation, id);
            }
            Action::Rotate { rotation } => push_epoch(&mut st, rotation, id),
        }
    }
    st
}
