//! Differential tests: the incremental resolver (`resolve.rs`) against the
//! from-scratch oracle (`oracle.rs`) on random concurrent histories.
//!
//! A history is built by a few replicas that author ops from their own
//! (partial) view and sync with each other: concurrent adds, removals and
//! role changes, revocation storms and cycles of mutual revocation,
//! equivocating authors (two ops on the same parents), reused epochs, stale
//! recipients, ops by revoked or never-authorized members and parents deep in
//! the past. Every graph, after every insert, must match `resolve_full` of
//! its ops exactly: order, validity, heads, winners, state, `state_at`,
//! `in_past` and `revocations_of`. A fresh observer then receives all ops in
//! a random order (out of order, in batches, with duplicates), once with the
//! fast path and once without.
//!
//! `PROPTEST_CASES=<n>` scales every property up for a longer fuzz run.

use std::collections::{BTreeSet, HashSet};

use mycel_crypto::{DeviceKeys, Hash32, Lockbox, SignPk};
use proptest::prelude::*;

use crate::oracle::{FullResolution, resolve_full};
use crate::resolve::FAST_PATH;
use crate::{Action, EpochId, Inserted, Op, OpId, Revocation, Role, Rotation, SignedOp, SpaceGraph};

const KEYS: usize = 7;
const REPLICAS: usize = 4;

/// One step of a random history. Fields are reduced modulo what they index.
#[derive(Clone, Debug)]
enum Cmd {
    /// A replica authors one op.
    Author { replica: u8, author: u8, kind: u8, member: u8, role: u8, parents: u8, flaw: u8 },
    /// An author equivocates: two different ops on the same parents.
    Fork { replica: u8, author: u8, member: u8 },
    /// `to` receives what `from` has: all of it in causal order, or a random
    /// part in random order (some of it parked as pending).
    Sync { from: u8, to: u8, part: u8, seed: u64 },
    /// An admin (or anyone) adds a member and the member at once revokes
    /// someone; another replica receives both in one update: a batch, or
    /// promoted together from the pending pool once their parents arrive.
    /// The new member's seniority then moves inside the update.
    AddRevoke { replica: u8, admin: u8, member: u8, victim: u8, to: u8, kind: u8, parents: u8 },
    /// A key, often a removed member, sends a few pairwise-concurrent
    /// revocations (leaves or removals) on one base.
    Spam { replica: u8, author: u8, victim: u8, count: u8, parents: u8, leave: bool },
}

fn cmd(storm: bool) -> impl Strategy<Value = Cmd> {
    let author = (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
        move |(replica, author, kind, member, role, parents, flaw)| {
            // Storms: mostly revocations (removals, downgrades, leaves).
            let kind = if storm && kind % 4 != 0 { 1 + kind % 3 } else { kind };
            Cmd::Author { replica, author, kind, member, role, parents, flaw }
        },
    );
    let fork = (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(replica, author, member)| Cmd::Fork {
        replica,
        author,
        member,
    });
    let sync = (any::<u8>(), any::<u8>(), any::<u8>(), any::<u64>()).prop_map(|(from, to, part, seed)| Cmd::Sync {
        from,
        to,
        part,
        seed,
    });
    let add_revoke = (any::<[u8; 7]>()).prop_map(|[replica, admin, member, victim, to, kind, parents]| {
        Cmd::AddRevoke { replica, admin, member, victim, to, kind, parents }
    });
    let spam = (any::<[u8; 5]>(), any::<bool>()).prop_map(|([replica, author, victim, count, parents], leave)| {
        Cmd::Spam { replica, author, victim, count, parents, leave }
    });
    prop_oneof![6 => author, 1 => fork, 3 => sync, 1 => add_revoke, 1 => spam]
}

/// splitmix64: deterministic shuffles and picks from a proptest seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i + 1));
        }
    }
}

struct World {
    keys: Vec<DeviceKeys>,
    genesis: SignedOp,
    replicas: Vec<SpaceGraph>,
    /// Every op authored so far, in authoring order.
    all: Vec<SignedOp>,
    nonce: u64,
}

impl World {
    fn new(storm: bool) -> Self {
        let keys: Vec<DeviceKeys> = (0..KEYS).map(|i| DeviceKeys::from_seed([i as u8 + 1; 32])).collect();
        let (g, genesis, _, _) = SpaceGraph::create(&keys[0]).unwrap();
        let replicas = (0..REPLICAS).map(|_| SpaceGraph::from_genesis(genesis.clone()).unwrap()).collect();
        let mut w = World { keys, genesis, replicas, all: Vec::new(), nonce: 0 };
        drop(g);
        if storm {
            // Everyone is an admin before the partitions start revoking.
            for m in 1..KEYS {
                let op = w.op(0, w.replicas[0].heads(), w.add(m, Role::Admin));
                w.deliver(0, op);
            }
            for r in 1..REPLICAS {
                w.sync(0, r, 0, 0);
            }
        }
        w
    }

    fn pk(&self, i: usize) -> SignPk {
        self.keys[i].sign_pk()
    }

    fn op(&mut self, author: usize, parents: Vec<OpId>, action: Action) -> SignedOp {
        self.nonce += 1;
        let op = Op { space: Some(self.genesis.id()), parents, author: self.pk(author), nonce: self.nonce, action };
        SignedOp::sign(&self.keys[author], op)
    }

    fn add(&self, member: usize, role: Role) -> Action {
        let keyring = role.can_read().then(|| Lockbox { enc: vec![1], ct: vec![2] });
        Action::Add { member: self.keys[member].public(), role, keyring }
    }

    /// A rotation to `recipients`; a flawed one reuses a known epoch.
    fn rotation(&mut self, recipients: BTreeSet<SignPk>, reuse: Option<Rotation>) -> Rotation {
        if let Some(r) = reuse {
            return Rotation { lockboxes: recipients.into_iter().map(fake_box).collect(), ..r };
        }
        self.nonce += 1;
        let commitment = Hash32::digest("mycel/test/commitment", &self.nonce.to_le_bytes());
        Rotation {
            epoch: EpochId::for_commitment(&commitment),
            commitment,
            lockboxes: recipients.into_iter().map(fake_box).collect(),
        }
    }

    fn known_rotation(&self, r: usize, pick: u8) -> Option<Rotation> {
        let g = &self.replicas[r];
        let rots: Vec<Rotation> =
            g.resolution().order.iter().filter_map(|id| rotation_of(g.get(id).unwrap())).collect();
        (!rots.is_empty()).then(|| rots[pick as usize % rots.len()].clone())
    }

    fn parents(&self, r: usize, mode: u8, rng: &mut Rng) -> Vec<OpId> {
        let g = &self.replicas[r];
        let order = &g.resolution().order;
        let mut ps = match mode % 10 {
            0..=5 => g.heads(),
            6 => vec![order[rng.below(order.len())]],
            7 => {
                // The valid heads plus an old op (an ancestor of a head).
                let mut ps = g.heads();
                ps.push(order[rng.below(order.len())]);
                ps
            }
            8 => {
                // Every sink, valid or not.
                order
                    .iter()
                    .copied()
                    .filter(|id| !order.iter().any(|c| g.get(c).unwrap().op.parents.contains(id)))
                    .collect()
            }
            _ => (0..1 + rng.below(3)).map(|_| order[rng.below(order.len())]).collect(),
        };
        ps.sort();
        ps.dedup();
        ps
    }

    fn author(&mut self, c: &Cmd) {
        let Cmd::Author { replica, author, kind, member, role, parents, flaw } = *c else { unreachable!() };
        let r = replica as usize % REPLICAS;
        let st = self.replicas[r].state().clone();
        // Mostly current members (so most ops are valid); sometimes anyone.
        let members: Vec<usize> = (0..KEYS).filter(|&i| st.members.contains_key(&self.pk(i))).collect();
        let a = if flaw % 5 != 0 && !members.is_empty() {
            members[author as usize % members.len()]
        } else {
            author as usize % KEYS
        };
        let mut m = member as usize % KEYS;
        let mut role = [Role::Relay, Role::Reader, Role::Writer, Role::Admin][role as usize % 4];
        // Bias toward the keyring's undo paths: add back as a reader someone
        // who is not a member now (often a removed reader), and revoke whoever
        // added someone last, so that the re-add gets invalidated.
        match kind % 6 {
            0 if flaw % 4 == 0 => {
                let out: Vec<usize> = (0..KEYS).filter(|&i| !st.members.contains_key(&self.pk(i))).collect();
                if !out.is_empty() {
                    m = out[member as usize % out.len()];
                    role = Role::Reader;
                }
            }
            1 if flaw % 4 == 3 => m = self.last_adder(r).unwrap_or(m),
            _ => {}
        }
        let mpk = self.pk(m);
        let mut rng = Rng(u64::from(parents) << 32 | u64::from(flaw) << 8 | u64::from(kind));
        let ps = self.parents(r, parents, &mut rng);
        let reuse = if flaw % 11 == 1 { self.known_rotation(r, member) } else { None };
        let mut readers = st.readers();
        let action = match kind % 6 {
            0 => self.add(m, role),
            1 => {
                readers.remove(&mpk);
                let rotation = self.rotation(stale(readers, flaw, &self.pk(a)), reuse);
                Action::Remove { member: mpk, revocation: Revocation { cutoff: None }, rotation }
            }
            2 => {
                let prior = st.role(&mpk).unwrap_or(Role::Admin);
                let role =
                    if flaw % 3 == 0 { role } else { [Role::Relay, Role::Reader, Role::Writer][role as usize % 3] };
                let revocation = (role < prior || flaw % 13 == 2).then_some(Revocation { cutoff: None });
                let rotation = (prior.can_read() && !role.can_read()).then(|| {
                    readers.remove(&mpk);
                    self.rotation(stale(readers, flaw, &self.pk(a)), reuse)
                });
                Action::SetRole { member: mpk, role, revocation, rotation }
            }
            3 => Action::Leave { cutoff: None },
            4 => Action::Rotate { rotation: self.rotation(stale(readers, flaw, &self.pk(a)), reuse) },
            _ => {
                let up = [Role::Reader, Role::Writer, Role::Admin][role as usize % 3];
                Action::SetRole { member: mpk, role: up, revocation: None, rotation: None }
            }
        };
        let op = self.op(a, ps, action);
        self.deliver(r, op);
    }

    /// Author of the newest valid `Add` replica `r` knows.
    fn last_adder(&self, r: usize) -> Option<usize> {
        let g = &self.replicas[r];
        let id = g
            .resolution()
            .order
            .iter()
            .rev()
            .find(|id| g.is_valid(id) && matches!(g.get(id).unwrap().op.action, Action::Add { .. }))?;
        let author = g.get(id).unwrap().op.author;
        (0..KEYS).find(|&i| self.pk(i) == author)
    }

    fn fork(&mut self, c: &Cmd) {
        let Cmd::Fork { replica, author, member } = *c else { unreachable!() };
        let r = replica as usize % REPLICAS;
        let st = self.replicas[r].state().clone();
        let members: Vec<usize> = (0..KEYS).filter(|&i| st.members.contains_key(&self.pk(i))).collect();
        if members.is_empty() {
            return;
        }
        let a = members[author as usize % members.len()];
        let m = members[member as usize % members.len()];
        let heads = self.replicas[r].heads();
        let mut readers = st.readers();
        let rot1 = self.rotation(readers.clone(), None);
        let first = self.op(a, heads.clone(), Action::Rotate { rotation: rot1 });
        readers.remove(&self.pk(m));
        let rot2 = self.rotation(readers, None);
        let second = self.op(
            a,
            heads,
            Action::Remove { member: self.pk(m), revocation: Revocation { cutoff: None }, rotation: rot2 },
        );
        self.deliver(r, first);
        self.deliver(r, second);
    }

    fn add_revoke(&mut self, c: &Cmd) {
        let Cmd::AddRevoke { replica, admin, member, victim, to, kind, parents } = *c else { unreachable!() };
        let (r, to) = (replica as usize % REPLICAS, to as usize % REPLICAS);
        let st = self.replicas[r].state().clone();
        let admins: Vec<usize> = (0..KEYS).filter(|&i| st.role(&self.pk(i)).is_some_and(Role::is_admin)).collect();
        let a = if kind % 4 != 0 && !admins.is_empty() {
            admins[admin as usize % admins.len()]
        } else {
            admin as usize % KEYS
        };
        let (m, v) = (member as usize % KEYS, victim as usize % KEYS);
        let mut rng = Rng(u64::from(parents) << 16 | u64::from(kind));
        let ps = self.parents(r, parents, &mut rng);
        let x = self.op(a, ps, self.add(m, Role::Admin));
        let mut readers = st.readers();
        readers.insert(self.pk(m));
        readers.remove(&self.pk(v));
        let action = match kind % 3 {
            0 => {
                let rotation = self.rotation(readers, None);
                Action::Remove { member: self.pk(v), revocation: Revocation { cutoff: None }, rotation }
            }
            1 => Action::SetRole {
                member: self.pk(v),
                role: Role::Relay,
                revocation: Some(Revocation { cutoff: None }),
                rotation: Some(self.rotation(readers, None)),
            },
            _ => Action::Leave { cutoff: None },
        };
        let y = self.op(m, vec![x.id()], action);
        self.deliver(r, x.clone());
        self.deliver(r, y.clone());
        let known = |w: &Self, id: OpId| w.all.iter().any(|o| o.id() == id);
        if to != r && known(self, x.id()) && known(self, y.id()) {
            self.replicas[to].insert_many([x, y]);
            check(&self.replicas[to]);
        }
    }

    fn spam(&mut self, c: &Cmd) {
        let Cmd::Spam { replica, author, victim, count, parents, leave } = *c else { unreachable!() };
        let r = replica as usize % REPLICAS;
        let (a, v) = (author as usize % KEYS, victim as usize % KEYS);
        let mut rng = Rng(u64::from(parents) << 8 | u64::from(count));
        let ps = self.parents(r, parents, &mut rng);
        let readers = self.replicas[r].state().readers();
        for _ in 0..2 + count % 5 {
            let action = if leave {
                Action::Leave { cutoff: None }
            } else {
                let rotation = self.rotation(readers.clone(), None);
                Action::Remove { member: self.pk(v), revocation: Revocation { cutoff: None }, rotation }
            };
            let op = self.op(a, ps.clone(), action);
            self.deliver(r, op);
        }
    }

    /// Insert an op authored at replica `r` (rejected ops are dropped).
    fn deliver(&mut self, r: usize, op: SignedOp) {
        if self.replicas[r].insert(op.clone()).is_ok() {
            self.all.push(op);
            check(&self.replicas[r]);
        }
    }

    fn sync(&mut self, from: usize, to: usize, part: u8, seed: u64) {
        let src = &self.replicas[from];
        let mut ops: Vec<SignedOp> = src.op_ids().iter().filter_map(|id| src.get(id).cloned()).collect();
        let mut rng = Rng(seed);
        if !part.is_multiple_of(3) {
            rng.shuffle(&mut ops);
            ops.truncate(1 + rng.below(ops.len()));
        }
        let dst = &mut self.replicas[to];
        if part.is_multiple_of(2) {
            dst.insert_many(ops);
        } else {
            for op in ops {
                let _ = dst.insert(op);
            }
        }
        check(dst);
    }

    fn run(&mut self, cmds: &[Cmd]) {
        for c in cmds {
            match c {
                Cmd::Author { .. } => self.author(c),
                Cmd::Fork { .. } => self.fork(c),
                Cmd::AddRevoke { .. } => self.add_revoke(c),
                Cmd::Spam { .. } => self.spam(c),
                Cmd::Sync { from, to, part, seed } => {
                    let (from, to) = (*from as usize % REPLICAS, *to as usize % REPLICAS);
                    if from != to {
                        self.sync(from, to, *part, *seed);
                    }
                }
            }
        }
    }

    /// A fresh peer receives every op in a random order, in random batches,
    /// with duplicates; checked after every step. Returns its final graph.
    fn observe(&self, seed: u64) -> SpaceGraph {
        let mut rng = Rng(seed);
        let mut ops = self.all.clone();
        let dups: Vec<SignedOp> = (0..ops.len() / 4).map(|_| ops[rng.below(ops.len())].clone()).collect();
        ops.extend(dups);
        rng.shuffle(&mut ops);
        let mut g = SpaceGraph::from_genesis(self.genesis.clone()).unwrap();
        let mut i = 0;
        while i < ops.len() {
            let n = if rng.below(3) == 0 { 1 + rng.below(6) } else { 1 };
            let batch: Vec<SignedOp> = ops[i..(i + n).min(ops.len())].to_vec();
            i += n;
            if batch.len() == 1 {
                let _ = g.insert(batch.into_iter().next().unwrap());
            } else {
                g.insert_many(batch);
            }
            check(&g);
        }
        // An op whose author's Add had not arrived yet was dropped at the
        // door; a later sync delivers it again.
        loop {
            let before = g.len();
            for op in &self.all {
                if g.insert(op.clone()).is_ok_and(|r| r != Inserted::Duplicate) {
                    check(&g);
                }
            }
            if g.len() == before {
                return g;
            }
        }
    }
}

fn rotation_of(op: &SignedOp) -> Option<Rotation> {
    match &op.op.action {
        Action::Genesis { rotation, .. }
        | Action::SetRole { rotation: Some(rotation), .. }
        | Action::Remove { rotation, .. }
        | Action::Rotate { rotation } => Some(rotation.clone()),
        _ => None,
    }
}

fn fake_box(pk: SignPk) -> (SignPk, Lockbox) {
    (pk, Lockbox { enc: vec![3], ct: vec![4] })
}

/// Correct recipients, or (for some flaws) stale ones: one reader missing,
/// or the author added although they are no reader.
fn stale(mut readers: BTreeSet<SignPk>, flaw: u8, author: &SignPk) -> BTreeSet<SignPk> {
    match flaw % 9 {
        3 => {
            if let Some(&first) = readers.iter().next() {
                readers.remove(&first);
            }
        }
        4 => {
            readers.insert(*author);
        }
        _ => {}
    }
    readers
}

/// The graph's incremental resolution must equal the oracle's, in every
/// observable respect.
fn check(g: &SpaceGraph) {
    let full = resolve_full(&g.ops);
    let res = g.resolution();
    assert_eq!(res.order, full.order, "order");
    for id in &full.order {
        assert_eq!(res.is_valid(id), full.is_valid(id), "validity of {id:?}");
    }
    assert_eq!(res.heads, full.heads, "valid heads");
    assert_eq!(res.winners(), full.winners, "revocation winners");
    assert_eq!(res.state, full.state, "state");
    for i in 0..KEYS {
        let pk = DeviceKeys::from_seed([i as u8 + 1; 32]).sign_pk();
        assert_eq!(g.revocations_of(&pk), oracle_revocations(g, &full, &pk), "revocations_of");
    }
    // Causal states and ancestry for a sample of head sets.
    let n = full.order.len();
    let step = (n / 12).max(1);
    for i in (0..n).step_by(step) {
        let a = full.order[i];
        let b = full.order[(i * 7 + 3) % n];
        let mut heads = vec![a, b];
        heads.sort();
        heads.dedup();
        assert_eq!(res.state_at(&g.ops, &heads), full.state_at(&g.ops, &heads), "state_at {heads:?}");
        for h in &full.order {
            assert_eq!(res.in_past(h, &[a]), full.in_past(h, &[a]), "in_past");
        }
    }
}

/// `SpaceGraph::revocations_of` as written before the incremental resolver,
/// over the oracle's winners.
fn oracle_revocations(g: &SpaceGraph, full: &FullResolution, pk: &SignPk) -> Vec<(OpId, Option<Hash32>)> {
    full.winners
        .iter()
        .filter_map(|id| {
            let op = &g.ops[id].op;
            match &op.action {
                Action::Remove { member, revocation, .. }
                | Action::SetRole { member, revocation: Some(revocation), .. }
                    if member == pk =>
                {
                    Some((*id, revocation.cutoff))
                }
                Action::Leave { cutoff } if op.author == *pk => Some((*id, *cutoff)),
                _ => None,
            }
        })
        .collect()
}

/// `PROPTEST_CASES` overrides the per-property default case count.
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn with_fast_path<T>(on: bool, f: impl FnOnce() -> T) -> T {
    let was = FAST_PATH.get();
    FAST_PATH.set(on);
    let out = f();
    FAST_PATH.set(was);
    out
}

fn property(storm: bool, cmds: &[Cmd], seed: u64) {
    let mut w = World::new(storm);
    w.run(cmds);
    let a = w.observe(seed);
    let b = with_fast_path(false, || w.observe(seed ^ 0x5eed));
    assert_eq!(a.resolution().order, b.resolution().order);
    assert_eq!(a.state(), b.state());
    // Every replica converges once it has everything. (A sync refuses an op
    // that sorts before the only op naming its author, as a peer would; the
    // next sync delivers it.)
    let ids: HashSet<OpId> = a.resolution().order.iter().copied().collect();
    for _ in 0..3 * REPLICAS {
        if w.replicas.iter().all(|g| g.len() == ids.len()) {
            break;
        }
        for r in 0..REPLICAS {
            w.sync(r, (r + 1) % REPLICAS, 0, 0);
        }
    }
    for g in &w.replicas {
        let got: HashSet<OpId> = g.resolution().order.iter().copied().collect();
        assert_eq!(got, ids);
        assert_eq!(g.state(), a.state());
        assert_eq!(g.heads(), a.heads());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(400)))]

    #[test]
    fn incremental_matches_oracle(cmds in prop::collection::vec(cmd(false), 1..40), seed in any::<u64>()) {
        property(false, &cmds, seed);
    }

    #[test]
    fn incremental_matches_oracle_in_revocation_storms(
        cmds in prop::collection::vec(cmd(true), 1..40),
        seed in any::<u64>(),
    ) {
        property(true, &cmds, seed);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(100)))]

    /// Longer histories, where cuts thin out and regions reach far back.
    #[test]
    fn incremental_matches_oracle_on_long_histories(
        cmds in prop::collection::vec(cmd(false), 60..140),
        seed in any::<u64>(),
    ) {
        property(false, &cmds, seed);
    }
}

#[test]
fn linear_history_takes_the_fast_path() {
    let w = World::new(true);
    let g = &w.replicas[0];
    let stats = g.resolution().stats;
    // Genesis resolves in full; every Add after it extends the heads.
    assert_eq!(stats.full, 1, "{stats:?}");
    assert_eq!(stats.fast, (KEYS - 1) as u64, "{stats:?}");
    assert_eq!(stats.region, 0, "{stats:?}");
}

#[test]
fn concurrency_re_resolves_only_the_concurrent_region() {
    // Two partitions each extend a long shared history; merging re-resolves
    // only what arrived after the fork, not the shared prefix.
    let mut w = World::new(true);
    for _ in 0..40 {
        w.run(&[Cmd::Author { replica: 0, author: 0, kind: 4, member: 0, role: 0, parents: 0, flaw: 2 }]);
    }
    w.sync(0, 1, 0, 0);
    let before = w.replicas[1].resolution().stats;
    w.run(&[
        Cmd::Author { replica: 0, author: 1, kind: 1, member: 2, role: 0, parents: 0, flaw: 2 },
        Cmd::Author { replica: 1, author: 2, kind: 1, member: 1, role: 0, parents: 0, flaw: 2 },
    ]);
    w.sync(0, 1, 0, 0);
    let after = w.replicas[1].resolution().stats;
    assert_eq!(after.full, before.full, "no full recompute: {after:?}");
    assert!(after.region > before.region, "{after:?}");
    let shared = w.replicas[0].len() as u64 - 1;
    assert!(after.region_ops - before.region_ops <= 3, "region of {} ops out of {shared}", after.region_ops);
}

/// A reader removed and added back, again and again, with rotations in
/// between and a concurrent add from another replica: each add hands them
/// every epoch in its past again, including the ones that left them out.
/// (The resolver skips the epochs they already hold.)
#[test]
fn removed_and_re_added_reader_gets_every_epoch_again() {
    let mut w = World::new(false);
    let admin = |kind, member, parents| Cmd::Author { replica: 0, author: 0, kind, member, role: 1, parents, flaw: 2 };
    for round in 0..6u8 {
        w.run(&[admin(0, 3, 0), admin(4, 0, 0), admin(4, 0, 7), admin(1, 3, 0), admin(4, 0, 0)]);
        if round % 2 == 1 {
            // Replica 1 re-adds them concurrently with replica 0's rotation.
            w.sync(0, 1, 0, 0);
            w.run(&[
                Cmd::Author { replica: 1, author: 0, kind: 0, member: 3, role: 1, parents: 0, flaw: 2 },
                admin(4, 0, 0),
            ]);
            w.sync(1, 0, 0, 0);
        }
    }
    // Replica 1's add made them a member again: remove them once more and
    // add them back on top of everything.
    w.run(&[admin(1, 3, 0), admin(0, 3, 0)]);
    let g = &w.replicas[0];
    assert_eq!(g.state().role(&w.pk(3)), Some(Role::Reader));
    assert!(g.state().epochs.len() > 20);
    assert!(g.state().epochs.iter().all(|e| e.recipients.contains(&w.pk(3))));
}

/// Regression: a revocation cycle (a removes b, b removes c, c removes a, all
/// concurrent) where the senior winner's revocation makes another winner
/// unauthorized, so the winners loop runs more than one round.
#[test]
fn mutual_revocation_cycle_matches_oracle() {
    let mut w = World::new(true);
    for r in 0..3u8 {
        let (a, m) = (1 + r, 1 + (r + 1) % 3);
        w.run(&[Cmd::Author { replica: r, author: a, kind: 1, member: m, role: 0, parents: 0, flaw: 2 }]);
    }
    // The cycle's authors index current members, so look the keys up again.
    w.run(&[
        Cmd::Sync { from: 0, to: 3, part: 0, seed: 0 },
        Cmd::Sync { from: 1, to: 3, part: 0, seed: 0 },
        Cmd::Sync { from: 2, to: 3, part: 0, seed: 0 },
    ]);
    check(&w.replicas[3]);
}

#[test]
#[ignore]
fn coverage_report() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    for storm in [false, true] {
        let mut runner = TestRunner::default();
        let (mut multi, mut fast, mut region, mut full, mut region_ops, mut ops, mut valid, mut winners, mut maxr) =
            (0, 0, 0, 0, 0, 0, 0, 0, 0);
        let cases = 200;
        for _ in 0..cases {
            let cmds = prop::collection::vec(cmd(storm), 1..40).new_tree(&mut runner).unwrap().current();
            let mut w = World::new(storm);
            w.run(&cmds);
            let g = w.observe(runner.rng().next_u64());
            let r = g.resolution();
            let st = r.stats;
            multi += usize::from(r.rounds() > 1);
            maxr = maxr.max(r.rounds());
            fast += st.fast;
            region += st.region;
            full += st.full;
            region_ops += st.region_ops;
            ops += r.order.len();
            valid += r.order.iter().filter(|id| r.is_valid(id)).count();
            winners += r.winners().len();
        }
        eprintln!(
            "storm={storm}: cases {cases}, multi-round {multi}, max rounds {maxr}, ops {ops}, valid {valid}, winners {winners}, fast {fast}, region {region}, full {full}, region ops {region_ops}"
        );
    }
}

/// Regression for the cut rule "every op in the new op's past outside the
/// cut's past is invalid in every round": `z` (B promotes D, concurrent with
/// A removing B) is excluded in every round of the winners loop but valid
/// in round 0, and `x` (D adds K, on top of both) is valid in round 0 only
/// through `z`. Round 0 fixes seniority, so `x` makes K senior to M, which
/// decides the later mutual removal of K and M. Resolving `x` against the
/// newest cut (frontier {w}) would leave `z` out of its round-0 state.
#[test]
fn round_zero_state_includes_ops_excluded_later() {
    let mut w = World::new(false);
    let (a, b, d, k, m) = (0, 1, 2, 3, 4);
    let mut seq = Vec::new();
    let g = w.genesis.id();
    let add_b = w.op(a, vec![g], w.add(b, Role::Admin));
    let add_d = w.op(a, vec![add_b.id()], w.add(d, Role::Writer));
    let readers = |w: &World, ks: &[usize]| ks.iter().map(|&i| w.pk(i)).collect::<BTreeSet<_>>();
    let rot = w.rotation(readers(&w, &[a, d]), None);
    let rm_b = w.op(
        a,
        vec![add_d.id()],
        Action::Remove { member: w.pk(b), revocation: Revocation { cutoff: None }, rotation: rot },
    );
    let z = w.op(
        b,
        vec![add_d.id()],
        Action::SetRole { member: w.pk(d), role: Role::Admin, revocation: None, rotation: None },
    );
    let mut px = vec![rm_b.id(), z.id()];
    px.sort();
    let x = w.op(d, px, w.add(k, Role::Admin));
    let add_m = w.op(a, vec![x.id()], w.add(m, Role::Admin));
    let y = w.op(a, vec![add_m.id()], w.add(k, Role::Admin));
    let rot_k = w.rotation(readers(&w, &[a, d, k]), None);
    let k_rm_m = w.op(
        k,
        vec![y.id()],
        Action::Remove { member: w.pk(m), revocation: Revocation { cutoff: None }, rotation: rot_k },
    );
    let rot_m = w.rotation(readers(&w, &[a, d, m]), None);
    let m_rm_k = w.op(
        m,
        vec![y.id()],
        Action::Remove { member: w.pk(k), revocation: Revocation { cutoff: None }, rotation: rot_m },
    );
    seq.extend([add_b, add_d, rm_b, z.clone(), x.clone(), add_m, y, k_rm_m.clone(), m_rm_k.clone()]);
    for fast in [true, false] {
        with_fast_path(fast, || {
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in &seq {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert!(!g.is_valid(&z.id()) && !g.is_valid(&x.id()));
            // K is senior (named first by `x`, valid in round 0), so K's
            // removal of M wins the mutual removal.
            assert!(g.is_valid(&k_rm_m.id()) && !g.is_valid(&m_rm_k.id()));
            assert!(g.state().role(&w.pk(m)).is_none());
            assert_eq!(g.state().role(&w.pk(k)), Some(Role::Admin));
        });
    }
}

/// Regression for the seniority rule of the cut: a new op that becomes the
/// first op (in topological order) naming a key whose revocations sit
/// before the cut moves those revocations in the candidate order, so the
/// whole history is re-resolved.
///
/// B is being removed by the founder A (who wins), and concurrently B
/// removes A (`r`) and adds K and M (`s_k`, `s_m`, with ids high enough to
/// sort last). Those ops are excluded from every round of the winners loop
/// but are valid in round 0, so they fix seniority: M before K. A then adds
/// K and M on the main line, after `r` (so in round 0, where A is removed,
/// those adds are invalid), and K and M remove each other: M, the senior,
/// wins. Finally C adds K (`x`, invalid except in round 0) and sorts before
/// `s_k` and `s_m`: K becomes the senior, and K's removal of M wins instead.
#[test]
fn seniority_change_before_the_cut_re_resolves_everything() {
    let mut w = World::new(false);
    let (a, b, c, k, m) = (0, 1, 2, 3, 4);
    let readers = |w: &World, ks: &[usize]| ks.iter().map(|&i| w.pk(i)).collect::<BTreeSet<_>>();
    let remove = |w: &mut World, by: usize, who: usize, rest: &[usize], parents: Vec<OpId>| {
        let rotation = w.rotation(readers(w, rest), None);
        let action = Action::Remove { member: w.pk(who), revocation: Revocation { cutoff: None }, rotation };
        w.op(by, parents, action)
    };
    let g = w.genesis.id();
    let add_b = w.op(a, vec![g], w.add(b, Role::Admin));
    let add_c = w.op(a, vec![add_b.id()], w.add(c, Role::Admin));
    let rm_b = remove(&mut w, a, b, &[a, c], vec![add_c.id()]);
    let r = remove(&mut w, b, a, &[b, c], vec![add_c.id()]);
    // Late-sorting concurrent adds by B: s_m < s_k, both above every other id.
    let grind = |w: &mut World, member: usize, high: bool| loop {
        let op = w.op(b, vec![add_c.id()], w.add(member, Role::Admin));
        let id = op.id().0;
        if id[0] == 0xff && (id[1] >= 0x80) == high {
            return op;
        }
    };
    let s_k = grind(&mut w, k, true);
    let s_m = grind(&mut w, m, false);
    let mut p = vec![rm_b.id(), r.id()];
    p.sort();
    let add_k = w.op(a, p, w.add(k, Role::Admin));
    let add_m = w.op(a, vec![add_k.id()], w.add(m, Role::Admin));
    let k_rm_m = remove(&mut w, k, m, &[a, c, k], vec![add_m.id()]);
    let m_rm_k = remove(&mut w, m, k, &[a, c, m], vec![add_m.id()]);
    let x = w.op(c, vec![m_rm_k.id()], w.add(k, Role::Admin));
    let seq = [add_b, add_c, rm_b, r, s_k.clone(), s_m.clone(), add_k, add_m, k_rm_m.clone(), m_rm_k.clone()];
    for fast in [true, false] {
        with_fast_path(fast, || {
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in &seq {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert!(g.is_valid(&m_rm_k.id()) && !g.is_valid(&k_rm_m.id()), "M is senior at first");
            let full_before = g.resolution().stats.full;
            assert_eq!(g.insert(x.clone()).unwrap(), Inserted::New);
            check(&g);
            let order = &g.resolution().order;
            let pos = |id: OpId| order.iter().position(|o| *o == id).unwrap();
            assert!(pos(x.id()) < pos(s_m.id()) && pos(s_m.id()) < pos(s_k.id()), "the scenario's order");
            assert!(g.is_valid(&k_rm_m.id()) && !g.is_valid(&m_rm_k.id()), "x makes K the senior");
            assert_eq!(g.resolution().stats.full, full_before + 1, "re-resolved from scratch");
        });
    }
}

/// Regression (a branch no random history reached): undoing a reader's
/// re-add keeps them in the epochs an earlier add of theirs still covers,
/// even past that add's `covered` mark. A adds B (admin) and C (writer); C's
/// rotation `r1` and A's `r2` both sit on that add, and `r1` sorts first.
/// `a1` adds M as a reader on `r2` (so M gets `r2`'s epoch, but `covered`
/// stops before `r1`'s). `rm` removes M on both, `a2` adds M back, and `x`
/// (B removes A, concurrent with `a2`) invalidates the re-add: M must stay
/// a recipient of `r2`'s epoch.
#[test]
fn undoing_a_re_add_keeps_the_epochs_of_an_earlier_add() {
    let mut w = World::new(false);
    let (a, b, c, m) = (0, 1, 2, 3);
    let readers = |w: &World, ks: &[usize]| ks.iter().map(|&i| w.pk(i)).collect::<BTreeSet<_>>();
    let g = w.genesis.id();
    let add_b = w.op(a, vec![g], w.add(b, Role::Admin));
    let add_c = w.op(a, vec![add_b.id()], w.add(c, Role::Writer));
    let rot = w.rotation(readers(&w, &[a, b, c]), None);
    let r2 = w.op(a, vec![add_c.id()], Action::Rotate { rotation: rot });
    let r1 = loop {
        let rot = w.rotation(readers(&w, &[a, b, c]), None);
        let r1 = w.op(c, vec![add_c.id()], Action::Rotate { rotation: rot });
        if r1.id() < r2.id() {
            break r1;
        }
    };
    let a1 = w.op(a, vec![r2.id()], w.add(m, Role::Reader));
    let mut p = vec![r1.id(), a1.id()];
    p.sort();
    let rot = w.rotation(readers(&w, &[a, b, c]), None);
    let rm = w.op(a, p, Action::Remove { member: w.pk(m), revocation: Revocation { cutoff: None }, rotation: rot });
    let a2 = w.op(a, vec![rm.id()], w.add(m, Role::Reader));
    let rot = w.rotation(readers(&w, &[b, c]), None);
    let x = w.op(
        b,
        vec![rm.id()],
        Action::Remove { member: w.pk(a), revocation: Revocation { cutoff: None }, rotation: rot },
    );
    let seq = [add_b, add_c, r2.clone(), a1.clone(), r1, rm.clone(), a2.clone(), x.clone()];
    for fast in [true, false] {
        with_fast_path(fast, || {
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in &seq {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert!(g.is_valid(&x.id()) && !g.is_valid(&a2.id()) && g.is_valid(&a1.id()));
            let e2 = g.state().epochs.iter().find(|e| e.created_by == r2.id()).unwrap();
            assert!(e2.recipients.contains(&w.pk(m)), "M keeps the epoch its first add gave it");
        });
    }
}

/// Regression (cut thinning): an op whose parents lie `lag` updates back
/// re-resolves fewer than about `2 · lag` ops, and O(log n) cuts are kept.
/// The old rule halved every old cut each 16 updates, whatever its age, so
/// after warm-up an op lagging more than about 100 updates fell back to the
/// cut after genesis and re-resolved the whole history.
#[test]
fn lagging_op_re_resolves_at_most_twice_its_lag() {
    let mut w = World::new(false);
    let (a, b) = (0, 1);
    let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
    let op = w.op(a, g.heads(), w.add(b, Role::Admin));
    g.insert(op).unwrap();
    let readers: BTreeSet<SignPk> = [w.pk(a), w.pk(b)].into();
    let mut line = Vec::new();
    for _ in 0..45_000 {
        let rotation = w.rotation(readers.clone(), None);
        let op = w.op(a, g.heads(), Action::Rotate { rotation });
        line.push(op.id());
        g.insert(op).unwrap();
    }
    let n = g.len() as f64;
    let cuts = g.resolution().cuts();
    assert!(cuts as f64 <= 2.0 * n.log2() + 4.0, "{cuts} cuts at {n} ops");
    // Smallest lag first: each re-resolution drops the cuts after the one
    // it used, and a smaller lag's cut is newer than a larger one's.
    for lag in [1usize, 200, 2_000, 20_000] {
        let before = g.resolution().stats;
        let rotation = w.rotation(readers.clone(), None);
        let op = w.op(b, vec![line[line.len() - 1 - lag]], Action::Rotate { rotation });
        let id = op.id();
        g.insert(op).unwrap();
        assert!(g.is_valid(&id));
        let after = g.resolution().stats;
        let region = after.region_ops - before.region_ops;
        assert_eq!(after.full, before.full, "lag {lag}");
        assert!(region <= 2 * lag as u64 + 4, "lag {lag}: re-resolved {region} ops of {n}");
    }
}

/// Regression: a removed member writes a long chain of invalid ops, then
/// ops on the valid heads plus the chain's tip. The chain lies outside every
/// cut's past, and each insert used to search all of it again (quadratic in
/// the attacker's ops); invalid ops are now marked once (`dead`), so each
/// insert visits a few ops. A short version is checked against the oracle.
#[test]
fn dead_chain_is_searched_once() {
    for (len, oracle) in [(30usize, true), (3_000, false)] {
        for fast in [true, false] {
            with_fast_path(fast, || {
                let mut w = World::new(false);
                let (a, b) = (0, 1);
                let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
                let op = w.op(a, g.heads(), w.add(b, Role::Admin));
                g.insert(op).unwrap();
                let rotation = w.rotation([w.pk(a)].into(), None);
                let action = Action::Remove { member: w.pk(b), revocation: Revocation { cutoff: None }, rotation };
                let op = w.op(a, g.heads(), action);
                let mut tip = op.id();
                g.insert(op).unwrap();
                let searched = g.resolution().searched.get();
                for _ in 0..len {
                    let rotation = w.rotation([w.pk(a)].into(), None);
                    let op = w.op(b, vec![tip], Action::Rotate { rotation });
                    tip = op.id();
                    g.insert(op).unwrap();
                    if oracle {
                        check(&g);
                    }
                }
                let build = g.resolution().searched.get() - searched;
                assert!(build <= 2 * len as u64 + 10, "building the chain searched {build} ops");
                // By the removed member (invalid) and by the admin (valid,
                // so the heads move on).
                for author in [b, b, a, b, a] {
                    for _ in 0..20 {
                        let searched = g.resolution().searched.get();
                        let rotation = w.rotation([w.pk(a)].into(), None);
                        let mut ps = g.heads();
                        ps.push(tip);
                        ps.sort();
                        ps.dedup();
                        let op = w.op(author, ps, Action::Rotate { rotation });
                        let id = op.id();
                        g.insert(op).unwrap();
                        assert_eq!(g.is_valid(&id), author == a);
                        let per = g.resolution().searched.get() - searched;
                        assert!(per <= 4, "one insert on a {len}-op dead chain searched {per} ops");
                        if oracle {
                            check(&g);
                        }
                    }
                }
            });
        }
    }
}

/// Pins a known cost of the specification (TRUST.md §10): a removed
/// member's pairwise-concurrent `Leave`s are all revocation candidates; each
/// round the earliest wins, beats the rest and then fails authorization, so
/// the winners loop runs once per `Leave`, and the resolver keeps each
/// round. Regression: the rounds differ only in which `Leave` wins, so they
/// share one head state and store flags only for the `Leave`s; each round
/// used to copy every op's flags and the whole undo log, and every later
/// insert paid for every round (O(k²) for k `Leave`s, forever).
#[test]
fn concurrent_leaves_by_a_removed_member_add_one_round_each() {
    const LEAVES: usize = 30;
    for fast in [true, false] {
        with_fast_path(fast, || {
            let mut w = World::new(false);
            let (a, b) = (0, 1);
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            let op = w.op(a, g.heads(), w.add(b, Role::Admin));
            g.insert(op).unwrap();
            let rotation = w.rotation([w.pk(a)].into(), None);
            let action = Action::Remove { member: w.pk(b), revocation: Revocation { cutoff: None }, rotation };
            let op = w.op(a, g.heads(), action);
            g.insert(op).unwrap();
            let base = g.heads();
            for _ in 0..LEAVES {
                let op = w.op(b, base.clone(), Action::Leave { cutoff: None });
                g.insert(op).unwrap();
                check(&g);
            }
            assert_eq!(g.resolution().rounds(), LEAVES + 1);
            assert_eq!(g.resolution().round_sizes(), (1, LEAVES));
            for _ in 0..5 {
                let before = g.resolution().stats;
                let rotation = w.rotation([w.pk(a)].into(), None);
                let op = w.op(a, g.heads(), Action::Rotate { rotation });
                g.insert(op).unwrap();
                check(&g);
                if fast {
                    assert_eq!(g.resolution().stats.fast, before.fast + 1);
                }
            }
            assert_eq!(g.resolution().round_sizes(), (1, LEAVES));
        });
    }
}

/// The ops of `seniority_flip_in_one_update`: A adds B and C (admins); A
/// removes C (`ra`) concurrently with C removing B (`rc`); B adds T as a
/// reader on `rc` (`a_t`: invalid in round 0, valid once `rc` loses); A
/// rotates on both (`m`); T removes P (`z`, on `a_t`): T is a member with no
/// seniority and P is no member, so `z` wins round 1 and then fails. Then A
/// adds P as an admin on `m` (`x`) and P removes T (`y`, on `x`). Returns
/// (history up to `z`, `m`, `z`, `x`, `y`), with `z` before `y` in the
/// topological order.
fn seniority_flip_ops() -> (World, Vec<SignedOp>, SignedOp, SignedOp, SignedOp, SignedOp) {
    let remove = |w: &mut World, by: usize, who: usize, rest: &[usize], parents: Vec<OpId>| {
        let rotation = w.rotation(rest.iter().map(|&i| w.pk(i)).collect(), None);
        let action = Action::Remove { member: w.pk(who), revocation: Revocation { cutoff: None }, rotation };
        w.op(by, parents, action)
    };
    for attempt in 0.. {
        let mut w = World::new(false);
        w.nonce = attempt * 1000;
        let (a, b, c, t, p) = (0, 1, 2, 3, 4);
        let g0 = w.genesis.id();
        let add_b = w.op(a, vec![g0], w.add(b, Role::Admin));
        let add_c = w.op(a, vec![add_b.id()], w.add(c, Role::Admin));
        let ra = remove(&mut w, a, c, &[a, b], vec![add_c.id()]);
        let rc = remove(&mut w, c, b, &[a, c], vec![add_c.id()]);
        let a_t = w.op(b, vec![rc.id()], w.add(t, Role::Reader));
        let mut ps = vec![ra.id(), a_t.id()];
        ps.sort();
        let rotation = w.rotation([w.pk(a), w.pk(b), w.pk(t)].into(), None);
        let m = w.op(a, ps, Action::Rotate { rotation });
        let z = remove(&mut w, t, p, &[a], vec![a_t.id()]);
        let x = w.op(a, vec![m.id()], w.add(p, Role::Admin));
        let y = remove(&mut w, p, t, &[a, b, p], vec![x.id()]);
        let history = vec![add_b, add_c, ra, rc, a_t];
        let all: HashSet<OpId> = history.iter().chain([&m, &z, &x, &y]).map(SignedOp::id).collect();
        let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
        g.insert_many(history.iter().chain([&m, &z, &x, &y]).cloned());
        assert_eq!(g.len(), all.len() + 1);
        let order = &g.resolution().order;
        let pos = |id: OpId| order.iter().position(|o| *o == id).unwrap();
        if pos(z.id()) < pos(y.id()) {
            return (w, history, m, z, x, y);
        }
    }
    unreachable!()
}

/// Regression (seniority moved inside one update): `x` gives P seniority and
/// `y` (P removes T) arrives in the same update, by a batch or by promotion
/// from the pending pool. The cut was chosen with P unranked, so `y` sorted
/// after the loose failed winner `z` (T removes P, concurrent with `y`) and
/// could not change it; once round 0 ranks P, `y` sorts first and beats `z`.
/// Resolving from that cut kept `z` as a stale round-1 winner and dropped
/// `y`, unlike the oracle (and unlike inserting the ops one at a time).
#[test]
fn seniority_flip_in_one_update() {
    let (w, history, m, z, x, y) = seniority_flip_ops();
    for fast in [true, false] {
        with_fast_path(fast, || {
            // Batched.
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in history.iter().chain([&m, &z]) {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert!(!g.is_valid(&z.id()) && g.is_valid(&m.id()));
            let (added, rejected) = g.insert_many([x.clone(), y.clone()]);
            assert_eq!((added.len(), rejected), (2, 0));
            check(&g);
            assert!(g.is_valid(&y.id()), "P (ranked by x) beats T's failed removal of P");
            let batched = g.state().clone();
            // Promoted from the pending pool: x and y wait for m.
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in history.iter().chain([&z]) {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert_eq!(g.insert(x.clone()).unwrap(), Inserted::Pending);
            assert_eq!(g.insert(y.clone()).unwrap(), Inserted::Pending);
            assert_eq!(g.insert(m.clone()).unwrap(), Inserted::New);
            check(&g);
            assert_eq!(g.state(), &batched);
            // One at a time.
            let mut g = SpaceGraph::from_genesis(w.genesis.clone()).unwrap();
            for op in history.iter().chain([&m, &z, &x, &y]) {
                assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
                check(&g);
            }
            assert_eq!(g.state(), &batched);
        });
    }
}
