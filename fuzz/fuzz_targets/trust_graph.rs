//! Membership (`mycel-trust`): a DAG of validly signed ops by the space's
//! members and by keys it never added, with any parents, roles, removals,
//! rotations (to any set of recipients) and departures, concurrent or not.
//! Signatures pass, so the fuzzer reaches resolution, not the signature
//! check. Raw ops from the wire are mixed in.
//!
//! Property, beyond not panicking: convergence. The same ops inserted one
//! at a time in the order made, and in a different order in one batch (each
//! re-offered until nothing more is taken, as repeated syncs would), give
//! the same resolution: valid set, heads and member state.
#![no_main]

use std::collections::BTreeMap;
use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{DeviceKeys, Hash32, Lockbox, MemberKeys};
use mycel_trust::{Action, Op, OpId, Revocation, Role, Rotation, SignedOp, SpaceGraph, new_rotation};

const KEYS: usize = 5;

struct Setup {
    keys: Vec<DeviceKeys>,
    genesis: SignedOp,
    /// A rotation to each subset of the keys (bit i: key i), made once:
    /// rotations hold fresh random keys, and inputs must replay exactly.
    rotations: Vec<Rotation>,
    /// A keyring lockbox for added readers (its contents don't matter here).
    keyring: Lockbox,
}

static SETUP: LazyLock<Setup> = LazyLock::new(|| {
    let keys: Vec<DeviceKeys> = (0..KEYS).map(|i| DeviceKeys::from_seed([i as u8 + 1; 32])).collect();
    let (_, genesis, _, _) = SpaceGraph::create(&keys[0]).expect("a space");
    let public: Vec<MemberKeys> = keys.iter().map(DeviceKeys::public).collect();
    let rotations = (0..1u32 << KEYS)
        .map(|set| {
            let to = public.iter().enumerate().filter(|(i, _)| set & (1 << i) != 0).map(|(_, m)| m);
            new_rotation(to).expect("a rotation").0
        })
        .collect();
    let keyring = mycel_crypto::seal_lockbox(&public[0].kex_pk, b"fuzz", b"").expect("seals");
    Setup { keys, genesis, rotations, keyring }
});

#[derive(Arbitrary, Debug, Clone, Copy)]
enum R {
    Admin,
    Writer,
    Reader,
    Relay,
}

impl From<R> for Role {
    fn from(r: R) -> Role {
        match r {
            R::Admin => Role::Admin,
            R::Writer => Role::Writer,
            R::Reader => Role::Reader,
            R::Relay => Role::Relay,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum A {
    Add { member: u8, role: R },
    SetRole { member: u8, role: R, revoke: bool, rotate: Option<u8> },
    Remove { member: u8, rotate: u8 },
    Rotate { to: u8 },
    Leave,
}

#[derive(Arbitrary, Debug)]
enum Step {
    Op { author: u8, parents: Vec<u8>, nonce: u64, action: A },
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    steps: Vec<Step>,
    /// How the second graph receives the ops: rotated by this much, reversed.
    rotate: u8,
}

fn summary(g: &SpaceGraph, ids: &[OpId]) -> String {
    let mut heads = g.heads();
    heads.sort();
    let valid: Vec<bool> = ids.iter().map(|id| g.is_valid(id)).collect();
    let members: BTreeMap<_, _> = g.state().members.iter().map(|(k, v)| (*k, format!("{v:?}"))).collect();
    format!("{heads:?}\n{valid:?}\n{members:?}\n{:?}", g.state().write_epoch())
}

fuzz_target!(|input: Input| {
    let s = &*SETUP;
    let space = s.genesis.id();
    let mut ops: Vec<SignedOp> = vec![];
    let mut ids: Vec<OpId> = vec![space];
    for step in input.steps.into_iter().take(32) {
        let op = match step {
            Step::Raw(bytes) => match postcard::from_bytes::<SignedOp>(&bytes) {
                Ok(op) => op,
                Err(_) => continue,
            },
            Step::Op { author, parents, nonce, action } => {
                let me = &s.keys[usize::from(author) % KEYS];
                let mut parents: Vec<OpId> = parents.iter().map(|p| ids[usize::from(*p) % ids.len()]).collect();
                parents.sort();
                parents.dedup();
                if parents.is_empty() {
                    parents.push(*ids.last().unwrap());
                }
                let key = |m: u8| &s.keys[usize::from(m) % KEYS];
                let rotation = |set: u8| s.rotations[usize::from(set) % s.rotations.len()].clone();
                let action = match action {
                    A::Add { member, role } => {
                        let role = Role::from(role);
                        let member = key(member).public();
                        let keyring = role.can_read().then(|| s.keyring.clone());
                        Action::Add { member, role, keyring }
                    }
                    A::SetRole { member, role, revoke, rotate } => Action::SetRole {
                        member: key(member).sign_pk(),
                        role: role.into(),
                        revocation: revoke.then_some(Revocation { cutoff: None }),
                        rotation: rotate.map(rotation),
                    },
                    A::Remove { member, rotate } => Action::Remove {
                        member: key(member).sign_pk(),
                        revocation: Revocation { cutoff: Some(Hash32([member; 32])) },
                        rotation: rotation(rotate),
                    },
                    A::Rotate { to } => Action::Rotate { rotation: rotation(to) },
                    A::Leave => Action::Leave { cutoff: None },
                };
                SignedOp::sign(me, Op { space: Some(space), parents, author: me.sign_pk(), nonce, action })
            }
        };
        ids.push(op.id());
        ops.push(op);
    }
    // In order, one at a time, re-offering what was refused until nothing changes.
    let mut one = SpaceGraph::from_genesis(s.genesis.clone()).expect("genesis");
    let mut two = SpaceGraph::from_genesis(s.genesis.clone()).expect("genesis");
    // (counting pending ops too: an op taken as pending names its author's
    // key, which lets that author's earlier ops in on the next offer)
    loop {
        let before = one.op_ids().len();
        for op in &ops {
            let _ = one.insert(op.clone());
        }
        if one.op_ids().len() == before {
            break;
        }
    }
    let mut other = ops.clone();
    other.reverse();
    if !other.is_empty() {
        let k = usize::from(input.rotate) % other.len();
        other.rotate_left(k);
    }
    loop {
        let before = two.op_ids().len();
        two.insert_many(other.clone());
        if two.op_ids().len() == before {
            break;
        }
    }
    assert_eq!(one.len(), two.len(), "different op sets");
    assert_eq!(summary(&one, &ids), summary(&two, &ids), "membership diverged");
    // Every query over the resolved graph answers.
    let heads = one.heads();
    let st = one.state_at(&heads);
    for k in &s.keys {
        let _ = st.role(&k.sign_pk());
        let _ = one.revocations_of(&k.sign_pk());
    }
    for id in &ids {
        let _ = one.in_past(id, &heads);
    }
});
