use super::*;

struct Peer {
    keys: DeviceKeys,
    ring: Keyring,
}

impl Peer {
    fn new() -> Self {
        Peer { keys: DeviceKeys::generate(), ring: Keyring::default() }
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
            action: Action::Add { member: outsider.keys.public(), role: Role::Relay, keyring: None },
        },
    );
    assert_eq!(g.insert(forged.clone()).unwrap(), Inserted::New);
    assert!(!g.is_valid(&forged.id()));
    assert!(g.state().role(&outsider.pk()).is_none());
}

/// A hand-crafted `Add` by `by` (no role check), on `g`'s heads.
fn forged_add(g: &SpaceGraph, by: &Peer, who: &Peer, role: Role, nonce: u64) -> SignedOp {
    SignedOp::sign(
        &by.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: by.pk(),
            nonce,
            action: Action::Add { member: who.keys.public(), role, keyring: None },
        },
    )
}

#[test]
fn only_keys_added_by_an_ever_admin_are_named() {
    // Admission rule A2: a writer, reader or relay can't mint authors (each
    // minted key could store envelopes and grow every sync frontier).
    let (mut g, a) = space();
    let w = Peer::new();
    let r = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    add(&mut g, &a, &r, Role::Reader);
    for (i, by) in [&w, &r].into_iter().enumerate() {
        let minted = Peer::new();
        let op = forged_add(&g, by, &minted, Role::Relay, i as u64);
        assert_eq!(g.insert(op).unwrap(), Inserted::New, "kept: peers converge on the DAG");
        assert!(!g.ever_named(&minted.pk()));
        // So the minted key can't author ops (or store envelopes).
        let own = forged_add(&g, &minted, &Peer::new(), Role::Relay, 9);
        assert!(matches!(g.insert(own), Err(TrustError::NotAuthorized(_))));
    }
    assert!(g.ever_named(&w.pk()) && g.ever_named(&r.pk()));
}

#[test]
fn named_keys_do_not_depend_on_arrival_order() {
    // The writer adds a key while still a writer (an invalid op); the
    // founder concurrently promotes the writer to admin. Ever-admin counts,
    // so the key is named on every replica, whichever op arrived first.
    let (mut g, a) = space();
    let w = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    let base = replica(&g);
    let x = Peer::new();
    let by_writer = forged_add(&g, &w, &x, Role::Relay, 1);
    let (promote, _) = g.set_role(&a.keys, w.pk(), Role::Admin, None).unwrap();
    for order in [[&by_writer, &promote], [&promote, &by_writer]] {
        let mut r = replica(&base);
        for op in order {
            r.insert(op.clone()).unwrap();
        }
        assert!(r.ever_named(&x.pk()));
    }
    // A pending Add names no one until it is resolvable.
    let mut r = replica(&base);
    let y = Peer::new();
    let mut h = replica(&base);
    h.insert(promote.clone()).unwrap();
    let add_y = forged_add(&h, &w, &y, Role::Relay, 2);
    assert_eq!(r.insert(add_y).unwrap(), Inserted::Pending);
    assert!(!r.ever_named(&y.pk()));
    r.insert(promote).unwrap();
    assert!(r.ever_named(&y.pk()));
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
    let b_add = gb.add_member(&b.keys, &Keyring::default(), victim.keys.public(), Role::Writer).unwrap();
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
    rotation.lockboxes[idx].1 =
        mycel_crypto::seal_lockbox(&b.keys.public().kex_pk, &lockbox_info(&rotation.epoch, &b.pk()), &wrong.0).unwrap();
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
            action: Action::Remove { member: a.pk(), revocation: Revocation { cutoff: None }, rotation },
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
    let ops: Vec<SignedOp> =
        g.resolution().order.iter().rev().filter(|id| **id != space).map(|id| g.get(id).unwrap().clone()).collect();
    let (added, rejected) = b.insert_many(ops);
    assert_eq!((added.len(), rejected), (5, 0));
    assert_eq!(b.state(), g.state());
}

#[test]
fn leave_forces_rotation_without_leaver() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    g.unlock(&b.keys, &mut b.ring);
    let leave = g.leave(&b.keys, None).unwrap();
    g.insert(leave.clone()).unwrap();
    assert!(g.is_valid(&leave.id()));
    assert!(g.state().role(&b.pk()).is_none());
    assert_eq!(g.state().write_epoch(), None, "old epoch includes the leaver");
    g.unlock(&a.keys, &mut a.ring);
    let (rot, epoch, _) = g.rotate(&a.keys).unwrap();
    g.insert(rot).unwrap();
    g.unlock(&b.keys, &mut b.ring);
    assert!(b.ring.get(&epoch).is_none(), "leaver can't read new epoch");
    // the last admin can't leave
    let stuck = g.leave(&a.keys, None).unwrap();
    g.insert(stuck.clone()).unwrap();
    assert!(!g.is_valid(&stuck.id()));
}

#[test]
fn epoch_ids_cannot_be_reused_with_a_different_key() {
    let (mut g, a) = space();
    let w = Peer::new();
    add(&mut g, &a, &w, Role::Writer);
    let (honest, _) = new_rotation([a.keys.public(), w.keys.public()].iter()).unwrap();
    // Attacker copies the honest epoch id but uses its own key/commitment.
    let (mut evil, _) = new_rotation([a.keys.public(), w.keys.public()].iter()).unwrap();
    evil.epoch = honest.epoch;
    let op = SignedOp::sign(
        &w.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: w.pk(),
            nonce: 5,
            action: Action::Rotate { rotation: evil },
        },
    );
    assert_eq!(g.insert(op), Err(TrustError::Malformed("epoch id must derive from commitment")));
}

#[test]
fn ops_from_never_added_keys_are_dropped_at_the_door() {
    let (mut g, _a) = space();
    let outsider = Peer::new();
    let junk = SignedOp::sign(
        &outsider.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: outsider.pk(),
            nonce: 1,
            action: Action::Leave { cutoff: None },
        },
    );
    assert!(matches!(g.insert(junk), Err(TrustError::NotAuthorized(_))));
    assert_eq!(g.op_ids().len(), 1, "nothing stored");
}

fn relay_add(g: &SpaceGraph, author: &Peer, member: &Peer, parents: Vec<OpId>, nonce: u64) -> SignedOp {
    SignedOp::sign(
        &author.keys,
        Op {
            space: Some(g.space_id()),
            parents,
            author: author.pk(),
            nonce,
            action: Action::Add { member: member.keys.public(), role: Role::Relay, keyring: None },
        },
    )
}

#[test]
fn unauthorized_fanout_cannot_block_admin_removal() {
    let (mut g, a) = space();
    let reader = Peer::new();
    let target = Peer::new();
    let admitted = add(&mut g, &a, &reader, Role::Reader);
    let junk: Vec<_> = (0..65).map(|n| relay_add(&g, &reader, &target, vec![admitted.id()], n)).collect();
    let (added, rejected) = g.insert_many(junk);
    assert_eq!((added.len(), rejected), (65, 0));
    assert_eq!(g.heads(), vec![admitted.id()]);
    let (remove, _, _) = g.remove_member(&a.keys, reader.pk(), None).unwrap();
    g.insert(remove.clone()).unwrap();
    assert!(g.is_valid(&remove.id()));
    assert_eq!(g.heads(), vec![remove.id()]);
}

#[test]
fn valid_frontier_keeps_ancestry_through_invalid_ops() {
    let (mut g, a) = space();
    let reader = Peer::new();
    let target = Peer::new();
    let admitted = add(&mut g, &a, &reader, Role::Reader);
    let invalid = relay_add(&g, &reader, &target, vec![admitted.id()], 1);
    g.insert(invalid.clone()).unwrap();
    let valid = relay_add(&g, &a, &target, vec![invalid.id()], 2);
    g.insert(valid.clone()).unwrap();
    let invalid_child = relay_add(&g, &reader, &target, vec![valid.id()], 3);
    g.insert(invalid_child).unwrap();
    assert_eq!(g.heads(), vec![valid.id()]);
    assert!(g.in_past(&admitted.id(), &g.heads()));
    assert!(g.in_past(&invalid.id(), &g.heads()));
    assert_eq!(g.state_at(&g.heads()), *g.state());
    let (remove, _, _) = g.remove_member(&a.keys, reader.pk(), None).unwrap();
    g.insert(remove.clone()).unwrap();
    let after_revocation = relay_add(&g, &reader, &target, vec![remove.id()], 4);
    g.insert(after_revocation).unwrap();
    assert_eq!(g.heads(), vec![remove.id()]);
    assert_eq!(g.revocations_of(&reader.pk()), vec![(remove.id(), None)]);
}

#[test]
fn genuinely_concurrent_valid_frontier_is_never_truncated() {
    let (mut g, a) = space();
    let target = Peer::new();
    let ops: Vec<_> = (0..65).map(|n| relay_add(&g, &a, &target, g.heads(), n)).collect();
    let (added, rejected) = g.insert_many(ops);
    assert_eq!((added.len(), rejected), (65, 0));
    assert_eq!(g.heads().len(), 65);
    assert!(g.heads().iter().all(|id| g.is_valid(id)));
}

fn missing_parent_op(g: &SpaceGraph, author: &Peer, nonce: u64) -> SignedOp {
    SignedOp::sign(
        &author.keys,
        Op {
            space: Some(g.space_id()),
            parents: vec![Hash32([0x37; 32])],
            author: author.pk(),
            nonce,
            action: Action::Leave { cutoff: None },
        },
    )
}

#[test]
fn pending_quota_is_per_author_and_does_not_block_ready_ops() {
    let (mut g, a) = space();
    let reader = Peer::new();
    add(&mut g, &a, &reader, Role::Reader);
    for n in 0..MAX_PENDING_PER_AUTHOR as u64 {
        assert_eq!(g.insert(missing_parent_op(&g, &reader, n)).unwrap(), Inserted::Pending);
    }
    assert!(g.insert(missing_parent_op(&g, &reader, MAX_PENDING_PER_AUTHOR as u64)).is_err());
    assert_eq!(g.insert(missing_parent_op(&g, &a, 0)).unwrap(), Inserted::Pending);
    let leave = g.leave(&reader.keys, None).unwrap();
    assert_eq!(g.insert(leave.clone()).unwrap(), Inserted::New);
    assert!(g.is_valid(&leave.id()));
}

#[test]
fn full_pending_pool_allows_admin_ops_and_bulk_resolution() {
    let (mut g, a) = space();
    let authors: Vec<_> = (0..MAX_PENDING / MAX_PENDING_PER_AUTHOR).map(|_| Peer::new()).collect();
    for author in &authors {
        add(&mut g, &a, author, Role::Relay);
    }
    let pending: Vec<_> = authors
        .iter()
        .flat_map(|author| {
            (0..MAX_PENDING_PER_AUTHOR as u64).map(|n| missing_parent_op(&g, author, n)).collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(g.insert_many(pending), (vec![], 0));
    assert_eq!(g.pending.len(), MAX_PENDING);
    let first = Peer::new();
    let second = Peer::new();
    let parent = relay_add(&g, &a, &first, g.heads(), 10);
    let child = relay_add(&g, &a, &second, vec![parent.id()], 11);
    let (added, rejected) = g.insert_many([parent.clone(), child.clone()]);
    assert_eq!(rejected, 0);
    assert_eq!(added.len(), 2);
    assert!(g.is_valid(&parent.id()) && g.is_valid(&child.id()));
    let (remove, _, _) = g.remove_member(&a.keys, authors[0].pk(), None).unwrap();
    assert_eq!(g.insert(remove.clone()).unwrap(), Inserted::New);
    assert!(g.is_valid(&remove.id()));
}

#[test]
fn bulk_parent_arrival_releases_pending_quota_before_next_admission() {
    let (mut g, a) = space();
    let reader = Peer::new();
    let relay = Peer::new();
    add(&mut g, &a, &reader, Role::Reader);
    let parent = relay_add(&g, &a, &relay, g.heads(), 1);
    let pending: Vec<_> = (0..MAX_PENDING_PER_AUTHOR as u64)
        .map(|nonce| {
            SignedOp::sign(
                &reader.keys,
                Op {
                    space: Some(g.space_id()),
                    parents: vec![parent.id()],
                    author: reader.pk(),
                    nonce,
                    action: Action::Leave { cutoff: None },
                },
            )
        })
        .collect();
    assert_eq!(g.insert_many(pending), (vec![], 0));
    let next_pending = missing_parent_op(&g, &reader, MAX_PENDING_PER_AUTHOR as u64);
    let (added, rejected) = g.insert_many([parent, next_pending.clone()]);
    assert_eq!(rejected, 0);
    assert_eq!(added.len(), MAX_PENDING_PER_AUTHOR + 1);
    assert_eq!(g.pending.len(), 1);
    assert!(g.pending.contains_key(&next_pending.id()));
}

/// One admin's long history: `n` ops chained one after another, alternating
/// adding a keeper, rotating, and removing that keeper again.
fn long_admin_history(g: &SpaceGraph, admin: &Peer, n: usize) -> Vec<SignedOp> {
    let mut parent = g.space_id();
    let mut keeper = None;
    (0..n as u64)
        .map(|nonce| {
            let action = match (nonce % 3, keeper.take()) {
                (0, _) => {
                    let k = DeviceKeys::generate().public();
                    keeper = Some(k.sign_pk);
                    Action::Add { member: k, role: Role::Relay, keyring: None }
                }
                (1, k) => {
                    keeper = k;
                    Action::Rotate { rotation: new_rotation([&admin.keys.public()]).unwrap().0 }
                }
                (_, k) => Action::Remove {
                    member: k.unwrap(),
                    revocation: Revocation { cutoff: None },
                    rotation: new_rotation([&admin.keys.public()]).unwrap().0,
                },
            };
            let op = SignedOp::sign(
                &admin.keys,
                Op { space: Some(g.space_id()), parents: vec![parent], author: admin.pk(), nonce, action },
            );
            parent = op.id();
            op
        })
        .collect()
}

#[test]
fn new_member_receives_a_long_admin_history_in_one_exchange() {
    const N: usize = 10_000;
    let (mut g, a) = space();
    let history = long_admin_history(&g, &a, N);
    let (added, rejected) = g.insert_many(history.clone());
    assert_eq!((added.len(), rejected), (N, 0));
    assert!(history.iter().all(|op| g.is_valid(&op.id())));

    // What a peer sends: every op it knows, in its op_ids() order.
    let sent: Vec<SignedOp> = g.op_ids().iter().map(|id| g.get(id).unwrap().clone()).collect();
    let mut joiner = SpaceGraph::from_genesis(g.get(&g.space_id()).unwrap().clone()).unwrap();
    let (added, rejected) = joiner.insert_many(sent);
    assert_eq!((added.len(), rejected), (N, 0), "one exchange delivers everything");
    assert!(joiner.pending.is_empty());
    assert_eq!(joiner.state(), g.state());
    assert_eq!(joiner.heads(), g.heads());

    // Newest-first, ops park behind missing parents until the per-author
    // quota drops the rest: unordered delivery needs several rounds.
    let mut reversed: Vec<SignedOp> = history[..2 * MAX_PENDING_PER_AUTHOR].to_vec();
    reversed.reverse();
    let mut late = SpaceGraph::from_genesis(g.get(&g.space_id()).unwrap().clone()).unwrap();
    let (_, rejected) = late.insert_many(reversed);
    assert!(rejected > 0, "unordered delivery needs more rounds");
}
