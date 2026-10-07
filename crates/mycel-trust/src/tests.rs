use super::*;

struct Peer {
    keys: DeviceKeys,
    ring: Keyring,
}

impl Peer {
    fn new() -> Self {
        Peer {
            keys: DeviceKeys::generate(),
            ring: Keyring::default(),
        }
    }
    fn pk(&self) -> SignPk {
        self.keys.sign_pk()
    }
}

/// Founder creates a space; returns (graph, founder).
fn space() -> (SpaceGraph, Peer) {
    let mut a = Peer::new();
    let (g, _, epoch, key) = SpaceGraph::create(&a.keys).unwrap();
    a.ring.insert(epoch, key);
    (g, a)
}

fn add(g: &mut SpaceGraph, admin: &Peer, who: &Peer, role: Role) -> SignedOp {
    let op = g.add_member(&admin.keys, &admin.ring, who.keys.public(), role).unwrap();
    assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
    op
}

/// Replica: a second graph that has received the same ops.
fn replica(g: &SpaceGraph) -> SpaceGraph {
    let space = g.space_id();
    let mut r = SpaceGraph::from_genesis(g.get(&space).unwrap().clone()).unwrap();
    for id in &g.resolution().order {
        if *id != space {
            r.insert(g.get(id).unwrap().clone()).unwrap();
        }
    }
    r
}

#[test]
fn roles_and_key_distribution() {
    let (mut g, a) = space();
    let mut w = Peer::new();
    let mut r = Peer::new();
    let mut k = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    add(&mut g, &a, &r, Role::Reader);
    add(&mut g, &a, &k, Role::Relay);

    assert_eq!(g.state().role(&w.pk()), Some(Role::Writer));
    assert_eq!(g.state().role(&k.pk()), Some(Role::Relay));
    assert_eq!(g.unlock(&w.keys, &mut w.ring), 1);
    assert_eq!(g.unlock(&r.keys, &mut r.ring), 1);
    assert_eq!(g.unlock(&k.keys, &mut k.ring), 0, "relays never get keys");

    // epoch 0 is still usable: new readers received it via keyring
    let e = g.state().write_epoch().unwrap();
    assert!(w.ring.get(&e).is_some() && r.ring.get(&e).is_some());
}

#[test]
fn non_admin_ops_are_invalid() {
    let (mut g, a) = space();
    let w = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    let outsider = Peer::new();

    // The writer hand-crafts an Add (the helper would refuse).
    let forged = SignedOp::sign(
        &w.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: w.pk(),
            nonce: 1,
            action: Action::Add {
                member: outsider.keys.public(),
                role: Role::Relay,
                keyring: None,
            },
        },
    );
    assert_eq!(g.insert(forged.clone()).unwrap(), Inserted::New);
    assert!(!g.is_valid(&forged.id()));
    assert!(g.state().role(&outsider.pk()).is_none());
}

#[test]
fn tampered_and_foreign_ops_rejected() {
    let (mut g, a) = space();
    let w = Peer::new();
    let mut op = g.add_member(&a.keys, &a.ring, w.keys.public(), Role::Writer).unwrap();
    op.op.nonce ^= 1;
    assert!(matches!(g.insert(op), Err(TrustError::Crypto(_))));

    let (g2, b) = space();
    let other = g2.add_member(&b.keys, &b.ring, w.keys.public(), Role::Writer).unwrap();
    assert_eq!(g.insert(other), Err(TrustError::WrongSpace));
}

#[test]
fn pending_until_parents_arrive() {
    let (mut g, a) = space();
    let mut r = replica(&g);
    let w = Peer::new();
    let x = Peer::new();
    let op1 = add(&mut g, &a, &w, Role::Writer);
    let op2 = add(&mut g, &a, &x, Role::Writer);
    assert_eq!(r.insert(op2.clone()).unwrap(), Inserted::Pending);
    assert!(r.state().role(&x.pk()).is_none());
    assert_eq!(r.insert(op1).unwrap(), Inserted::New);
    assert_eq!(r.state().role(&x.pk()), Some(Role::Writer));
    assert_eq!(r.insert(op2).unwrap(), Inserted::Duplicate);
}

#[test]
fn remove_rotates_and_excludes() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    let mut c = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    add(&mut g, &a, &c, Role::Reader);
    let old = g.state().write_epoch().unwrap();

    let (op, epoch, key) = g.remove_member(&a.keys, b.pk(), None).unwrap();
    a.ring.insert(epoch, key);
    g.insert(op).unwrap();

    assert!(g.state().role(&b.pk()).is_none());
    let new = g.state().write_epoch().unwrap();
    assert_ne!(old, new);
    g.unlock(&b.keys, &mut b.ring);
    g.unlock(&c.keys, &mut c.ring);
    assert!(b.ring.get(&new).is_none(), "removed member can't read new epoch");
    assert!(c.ring.get(&new).is_some());
}

#[test]
fn revoked_members_concurrent_ops_are_invalid() {
    let (mut g, a) = space();
    let b = Peer::new();
    add(&mut g, &a, &b, Role::Admin);
    let mut gb = replica(&g);
    let victim = Peer::new();

    // Partition: A removes B; concurrently B adds `victim`.
    let (rm, _, _) = g.remove_member(&a.keys, b.pk(), None).unwrap();
    g.insert(rm.clone()).unwrap();
    let b_add = gb
        .add_member(&b.keys, &Keyring::default(), victim.keys.public(), Role::Writer)
        .unwrap();
    gb.insert(b_add.clone()).unwrap();
    assert_eq!(gb.state().role(&victim.pk()), Some(Role::Writer));

    // Heal both ways.
    g.insert(b_add.clone()).unwrap();
    gb.insert(rm.clone()).unwrap();
    for graph in [&g, &gb] {
        assert!(graph.is_valid(&rm.id()));
        assert!(!graph.is_valid(&b_add.id()), "removal wins over concurrent op");
        assert!(graph.state().role(&victim.pk()).is_none());
        assert!(graph.state().role(&b.pk()).is_none());
    }
}

#[test]
fn mutual_removal_senior_admin_wins() {
    let (mut g, a) = space();
    let b = Peer::new();
    add(&mut g, &a, &b, Role::Admin);
    let mut gb = replica(&g);

    let (a_rm_b, _, _) = g.remove_member(&a.keys, b.pk(), None).unwrap();
    let (b_rm_a, _, _) = gb.remove_member(&b.keys, a.pk(), None).unwrap();
    g.insert(a_rm_b.clone()).unwrap();
    gb.insert(b_rm_a.clone()).unwrap();
    g.insert(b_rm_a.clone()).unwrap();
    gb.insert(a_rm_b.clone()).unwrap();

    for graph in [&g, &gb] {
        assert!(graph.is_valid(&a_rm_b.id()));
        assert!(!graph.is_valid(&b_rm_a.id()));
        assert_eq!(graph.state().role(&a.pk()), Some(Role::Admin));
        assert!(graph.state().role(&b.pk()).is_none());
    }
}

#[test]
fn convergence_independent_of_delivery_order() {
    // Build a messy concurrent history on 3 replicas, deliver in different orders.
    let (mut g0, a) = space();
    let b = Peer::new();
    let c = Peer::new();
    let d = Peer::new();
    let e = Peer::new();
    add(&mut g0, &a, &b, Role::Admin);
    add(&mut g0, &a, &c, Role::Writer);
    let mut g1 = replica(&g0);
    let mut g2 = replica(&g0);

    let o1 = g0.add_member(&a.keys, &a.ring, d.keys.public(), Role::Reader).unwrap();
    g0.insert(o1.clone()).unwrap();
    let (o2, _, _) = g1.remove_member(&b.keys, c.pk(), None).unwrap();
    g1.insert(o2.clone()).unwrap();
    let (o3, _, _) = g2.rotate(&c.keys).unwrap();
    g2.insert(o3.clone()).unwrap();
    let o4 = g2.add_member(&a.keys, &a.ring, e.keys.public(), Role::Writer).unwrap();
    g2.insert(o4.clone()).unwrap();
    let (o5, _) = g0.set_role(&a.keys, b.pk(), Role::Writer, None).unwrap();
    g0.insert(o5.clone()).unwrap();

    let all = [o1, o2, o3, o4, o5];
    let orders: [&[usize]; 3] = [&[0, 1, 2, 3, 4], &[4, 3, 2, 1, 0], &[2, 4, 0, 3, 1]];
    let mut results = vec![];
    for (g, ord) in [&mut g0, &mut g1, &mut g2].into_iter().zip(orders) {
        for &i in ord {
            g.insert(all[i].clone()).unwrap();
        }
        let valid: Vec<bool> = all.iter().map(|o| g.is_valid(&o.id())).collect();
        results.push((g.state().clone(), valid, g.heads()));
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
    // a (senior) demoted b concurrently with b removing c: the demotion wins,
    // so b's removal of c is invalid and c's rotation stays valid.
    assert_eq!(results[0].1, vec![true, false, true, true, true]);
    assert_eq!(results[0].0.role(&b.pk()), Some(Role::Writer));
    assert_eq!(results[0].0.role(&c.pk()), Some(Role::Writer));
}

#[test]
fn rotation_must_match_readers_exactly() {
    let (mut g, a) = space();
    let b = Peer::new();
    let leak = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    // Rotation that also seals to an outsider.
    let members = [a.keys.public(), b.keys.public(), leak.keys.public()];
    let (rotation, _) = new_rotation(members.iter()).unwrap();
    let op = SignedOp::sign(
        &a.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: a.pk(),
            nonce: 7,
            action: Action::Rotate { rotation },
        },
    );
    g.insert(op.clone()).unwrap();
    assert!(!g.is_valid(&op.id()));
}

#[test]
fn readers_cannot_rotate_and_last_admin_stays() {
    let (mut g, a) = space();
    let r = Peer::new();
    add(&mut g, &a, &r, Role::Reader);
    assert!(g.rotate(&r.keys).is_err());
    // Founder demoting themselves would leave no admin.
    let (op, _) = g.set_role(&a.keys, a.pk(), Role::Writer, None).unwrap();
    g.insert(op.clone()).unwrap();
    assert!(!g.is_valid(&op.id()));
    assert_eq!(g.state().role(&a.pk()), Some(Role::Admin));
}

#[test]
fn bad_commitment_key_is_not_accepted() {
    let (mut g, a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    // Rotator gives b a different key than the commitment advertises.
    let (mut rotation, _) = new_rotation([a.keys.public(), b.keys.public()].iter()).unwrap();
    let wrong = SymKey::generate();
    let idx = rotation.lockboxes.iter().position(|(pk, _)| *pk == b.pk()).unwrap();
    rotation.lockboxes[idx].1 = mycel_crypto::seal_lockbox(
        &b.keys.public().kex_pk,
        &lockbox_info(&rotation.epoch, &b.pk()),
        &wrong.0,
    )
    .unwrap();
    let epoch = rotation.epoch;
    let op = SignedOp::sign(
        &a.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: a.pk(),
            nonce: 9,
            action: Action::Rotate { rotation },
        },
    );
    g.insert(op).unwrap();
    g.unlock(&b.keys, &mut b.ring);
    assert!(b.ring.get(&epoch).is_none(), "mismatched key rejected");
}

#[test]
fn concurrent_add_and_remove_self_heals_via_rotation() {
    let (mut g, mut a) = space();
    let b = Peer::new();
    let c = Peer::new();
    add(&mut g, &a, &b, Role::Admin);
    add(&mut g, &a, &c, Role::Writer);
    let gb = replica(&g);
    let d = Peer::new();

    // A adds D; concurrently B removes C (rotation excludes C, but doesn't know D).
    let add_d = g.add_member(&a.keys, &a.ring, d.keys.public(), Role::Reader).unwrap();
    g.insert(add_d.clone()).unwrap();
    let (rm_c, _, _) = gb.remove_member(&b.keys, c.pk(), None).unwrap();
    g.insert(rm_c).unwrap();

    // No epoch matches {a, b, d} exactly: epoch0 includes C, the new one lacks D.
    assert_eq!(g.state().write_epoch(), None);
    g.unlock(&a.keys, &mut a.ring);
    let (rot, epoch, _) = g.rotate(&a.keys).unwrap();
    g.insert(rot).unwrap();
    assert_eq!(g.state().write_epoch(), Some(epoch));
}

#[test]
fn concurrent_revocation_by_unauthorized_author_does_not_win() {
    // A writer forges a Remove of the admin; it must not knock out the admin's ops.
    let (mut g, a) = space();
    let w = Peer::new();
    let x = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    let mut gw = replica(&g);
    let readers = g.state().readers();
    let mut after = readers.clone();
    after.remove(&a.pk());
    let st = g.state().clone();
    let (rotation, _) = new_rotation(after.iter().map(|pk| &st.members[pk].keys)).unwrap();
    let forged = SignedOp::sign(
        &w.keys,
        Op {
            space: Some(g.space_id()),
            parents: gw.heads(),
            author: w.pk(),
            nonce: 3,
            action: Action::Remove {
                member: a.pk(),
                revocation: Revocation { cutoff: None },
                rotation,
            },
        },
    );
    gw.insert(forged.clone()).unwrap();
    let a_add = add(&mut g, &a, &x, Role::Reader);
    g.insert(forged.clone()).unwrap();
    assert!(!g.is_valid(&forged.id()));
    assert!(g.is_valid(&a_add.id()), "admin's concurrent op survives");
    assert_eq!(g.state().role(&x.pk()), Some(Role::Reader));
}

#[test]
fn insert_many_matches_sequential_inserts() {
    let (mut g, a) = space();
    let peers: Vec<Peer> = (0..5).map(|_| Peer::new()).collect();
    for p in &peers {
        add(&mut g, &a, p, Role::Writer);
    }
    let space = g.space_id();
    let mut b = SpaceGraph::from_genesis(g.get(&space).unwrap().clone()).unwrap();
    // reversed order: everything goes pending, then resolves once
    let ops: Vec<SignedOp> = g.resolution().order.iter().rev()
        .filter(|id| **id != space)
        .map(|id| g.get(id).unwrap().clone())
        .collect();
    let (added, rejected) = b.insert_many(ops);
    assert_eq!((added.len(), rejected), (5, 0));
    assert_eq!(b.state(), g.state());
}
