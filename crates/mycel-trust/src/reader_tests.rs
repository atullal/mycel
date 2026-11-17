//! Reader keys (TRUST.md §6): published in the graph, sealed to from then
//! on, and never derived from a device's seed.

use super::*;

struct Peer {
    keys: DeviceKeys,
    /// Reader keys this device holds, oldest first.
    readers: Vec<KexSecret>,
    ring: Keyring,
}

impl Peer {
    fn new() -> Self {
        Peer { keys: DeviceKeys::generate(), readers: vec![], ring: Keyring::default() }
    }

    fn pk(&self) -> SignPk {
        self.keys.sign_pk()
    }

    /// Publish a fresh reader key in `g`.
    fn rekey(&mut self, g: &mut SpaceGraph, lost_previous: bool) -> SignedOp {
        let secret = KexSecret::generate();
        let op = g.publish_reader_key(&self.keys, secret.public().clone(), lost_previous).unwrap();
        self.readers.push(secret);
        assert_eq!(g.insert(op.clone()).unwrap(), Inserted::New);
        op
    }

    fn unlock(&mut self, g: &SpaceGraph) -> usize {
        g.unlock_with(&self.keys, &self.readers, &mut self.ring)
    }
}

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

fn rotate(g: &mut SpaceGraph, by: &mut Peer) -> EpochId {
    let (op, epoch, key) = g.rotate(&by.keys).unwrap();
    by.ring.insert(epoch, key);
    assert_eq!(g.insert(op).unwrap(), Inserted::New);
    epoch
}

/// A second graph that has received `ops` after the genesis.
fn graph_with(g: &SpaceGraph, ops: &[&SignedOp]) -> SpaceGraph {
    let space = g.space_id();
    let mut r = SpaceGraph::from_genesis(g.get(&space).unwrap().clone()).unwrap();
    r.insert_many(ops.iter().map(|o| (*o).clone()));
    r
}

/// The device a thief has: the same seed, and nothing the device stored.
fn from_seed_alone(p: &Peer) -> Peer {
    Peer { keys: DeviceKeys::from_seed(p.keys.seed()), readers: vec![], ring: Keyring::default() }
}

#[test]
fn lockboxes_go_to_the_reader_key_once_one_is_published() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    assert!(g.state().members[&b.pk()].reader.is_none());
    assert_eq!(g.state().members[&b.pk()].seal_key(), &b.keys.public().kex_pk, "no reader key yet: the kex key");

    b.rekey(&mut g, false);
    let published = g.state().members[&b.pk()].reader.clone().unwrap();
    assert_eq!(&published.key, b.readers[0].public());
    assert_eq!(g.state().members[&b.pk()].seal_key(), b.readers[0].public());
    assert!(published.lost_before.is_none());

    let e = rotate(&mut g, &mut a);
    // B opens it with the reader key...
    assert_eq!(b.unlock(&g), 2, "the first epoch (from the keyring) and the new one");
    assert!(b.ring.get(&e).is_some());
    // ...and not with what its seed gives
    let mut seed_only = from_seed_alone(&b);
    seed_only.unlock(&g);
    assert!(seed_only.ring.get(&e).is_none(), "the device key alone doesn't open it");
    assert_eq!(seed_only.ring.len(), 1, "only what was sealed before B had a reader key");
}

/// The property the reader keys are for: once a device has deleted a
/// reader key, what was sealed to it is closed to everyone, the device
/// included; a keyring kept from before still has the key.
#[test]
fn a_deleted_reader_key_closes_its_lockboxes_and_a_kept_keyring_stays_whole() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    b.rekey(&mut g, false);
    let e1 = rotate(&mut g, &mut a);
    b.unlock(&g);
    let kept_key = b.ring.get(&e1).unwrap().clone();

    // B moves to a second reader key and later deletes the first
    b.rekey(&mut g, false);
    let e2 = rotate(&mut g, &mut a);
    b.unlock(&g);
    b.readers.remove(0);

    // B after a restart, with its stored keyring: nothing to re-open
    let mut restarted =
        Peer { keys: DeviceKeys::from_seed(b.keys.seed()), readers: b.readers.clone(), ring: Keyring::default() };
    restarted.ring.insert(e1, kept_key);
    restarted.unlock(&g);
    assert!(restarted.ring.get(&e1).is_some() && restarted.ring.get(&e2).is_some());

    // B after a restart without it: the first key's epoch is gone for good
    let mut without =
        Peer { keys: DeviceKeys::from_seed(b.keys.seed()), readers: b.readers.clone(), ring: Keyring::default() };
    without.unlock(&g);
    assert!(without.ring.get(&e1).is_none(), "sealed to a key that no longer exists");
    assert!(without.ring.get(&e2).is_some());

    // and a thief with B's seed and every op ever published gets neither
    let mut thief = from_seed_alone(&b);
    thief.unlock(&g);
    assert!(thief.ring.get(&e1).is_none() && thief.ring.get(&e2).is_none());
}

/// Someone who hasn't seen a reader's new key seals to the old one, which
/// the reader still holds: nothing is lost while both are kept.
#[test]
fn a_sealer_behind_on_reader_keys_is_still_understood() {
    let (mut g, a) = space();
    let mut b = Peer::new();
    let add_b = add(&mut g, &a, &b, Role::Writer);
    let k1 = b.rekey(&mut g, false);
    // A's device stops hearing from B here
    let mut a_view = graph_with(&g, &[&add_b, &k1]);
    b.rekey(&mut g, false);
    let (rot, epoch, _) = a_view.rotate(&a.keys).unwrap();
    a_view.insert(rot.clone()).unwrap();
    assert_eq!(a_view.state().members[&b.pk()].seal_key(), b.readers[0].public());
    // the two views meet
    g.insert(rot).unwrap();
    b.unlock(&g);
    assert!(b.ring.get(&epoch).is_some(), "opened with the earlier reader key");
    // once B has deleted that key, the same lockbox is closed to it
    b.readers.remove(0);
    b.ring = Keyring::default();
    b.unlock(&g);
    assert!(b.ring.get(&epoch).is_none());
}

/// Two devices publish and rotate at once, in every order of arrival:
/// every peer ends with the same reader keys and the same epochs.
#[test]
fn concurrent_reader_keys_and_rotations_converge() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    let mut c = Peer::new();
    let add_b = add(&mut g, &a, &b, Role::Writer);
    let add_c = add(&mut g, &a, &c, Role::Reader);
    let base = [&add_b, &add_c];

    // each on its own copy of the graph, unaware of the others
    let (mut ga, mut gb, mut gc) = (graph_with(&g, &base), graph_with(&g, &base), graph_with(&g, &base));
    let ka = a.rekey(&mut ga, false);
    let (rot_a, ..) = ga.rotate(&a.keys).unwrap();
    ga.insert(rot_a.clone()).unwrap();
    let kb1 = b.rekey(&mut gb, false);
    let kb2 = b.rekey(&mut gb, false);
    let (rot_b, ..) = gb.rotate(&b.keys).unwrap();
    gb.insert(rot_b.clone()).unwrap();
    let kc = c.rekey(&mut gc, false);

    let ops = [&ka, &rot_a, &kb1, &kb2, &rot_b, &kc];
    let mut orders: Vec<Vec<&SignedOp>> = vec![ops.to_vec(), ops.iter().rev().copied().collect()];
    orders.push(vec![&rot_b, &kc, &rot_a, &kb2, &ka, &kb1]);
    let mut states = vec![];
    for order in &orders {
        let mut r = graph_with(&g, &base);
        r.insert_many(order.iter().map(|o| (*o).clone()));
        assert_eq!(r.len(), 3 + ops.len(), "every op is in");
        assert!(ops.iter().all(|o| r.is_valid(&o.id())));
        states.push(r.state().clone());
    }
    assert!(states.windows(2).all(|w| w[0] == w[1]), "same state whatever the order");
    let st = &states[0];
    assert_eq!(st.members[&a.pk()].seal_key(), a.readers[0].public());
    assert_eq!(st.members[&b.pk()].seal_key(), b.readers[1].public(), "B's later key");
    assert_eq!(st.members[&c.pk()].seal_key(), c.readers[0].public());
    // and everyone opens both concurrent epochs, each sealed to what its
    // author knew: reader keys for its own, kex keys for the others
    let mut merged = graph_with(&g, &base);
    merged.insert_many(ops.iter().map(|o| (*o).clone()));
    for p in [&mut a, &mut b, &mut c] {
        p.ring = Keyring::default();
        p.unlock(&merged);
        assert_eq!(p.ring.len(), merged.state().epochs.len());
    }
}

#[test]
fn who_may_publish_a_reader_key() {
    let (mut g, mut a) = space();
    let mut reader = Peer::new();
    let keeper = Peer::new();
    let stranger = Peer::new();
    add(&mut g, &a, &reader, Role::Reader);
    add(&mut g, &a, &keeper, Role::Relay);
    // a reader may, though it can author nothing else but leaving
    reader.rekey(&mut g, false);
    assert!(g.state().members[&reader.pk()].reader.is_some());
    // a keeper holds no keys: refused when authoring, invalid if forced
    let key = KexSecret::generate().public().clone();
    assert!(g.publish_reader_key(&keeper.keys, key.clone(), false).is_err());
    let forced = SignedOp::sign(
        &keeper.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: keeper.pk(),
            nonce: 1,
            action: Action::ReaderKey { key: key.clone(), lost_previous: false },
        },
    );
    let id = forced.id();
    g.insert(forced).unwrap();
    assert!(!g.is_valid(&id));
    assert!(g.state().members[&keeper.pk()].reader.is_none());
    // someone never added: not even stored
    let outside = SignedOp::sign(
        &stranger.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: stranger.pk(),
            nonce: 1,
            action: Action::ReaderKey { key, lost_previous: false },
        },
    );
    assert!(g.insert(outside).is_err());
    // a removed member's key no longer counts, and it can't publish another
    let (rm, epoch, k) = g.remove_member(&a.keys, reader.pk(), None).unwrap();
    a.ring.insert(epoch, k);
    g.insert(rm).unwrap();
    assert!(g.publish_reader_key(&reader.keys, KexSecret::generate().public().clone(), false).is_err());
}

/// A reader key that X-Wing wouldn't accept can't get into the graph: every
/// later rotation would fail to seal to it.
#[test]
fn a_malformed_reader_key_is_refused() {
    let (mut g, a) = space();
    let b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    // the right length, but not an ML-KEM key
    let junk: KexPk =
        postcard::from_bytes(&postcard::to_allocvec(&Bytes(&[0xff; mycel_crypto::KEX_PK_LEN])).unwrap()).unwrap();
    assert!(g.publish_reader_key(&b.keys, junk.clone(), false).is_err());
    let forced = SignedOp::sign(
        &b.keys,
        Op {
            space: Some(g.space_id()),
            parents: g.heads(),
            author: b.pk(),
            nonce: 1,
            action: Action::ReaderKey { key: junk, lost_previous: false },
        },
    );
    assert!(matches!(forced.verify_standalone(), Err(TrustError::Crypto(CryptoError::BadPublicKey))));
    assert!(g.insert(forced).is_err());
    assert!(g.rotate(&a.keys).is_ok(), "rotations still seal");
}

struct Bytes<'a>(&'a [u8]);
impl serde::Serialize for Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

/// Losing read access drops the reader key: a member that reads again
/// later is sealed to its kex key until it publishes a new one.
#[test]
fn a_member_that_stops_reading_starts_afresh() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Reader);
    b.rekey(&mut g, false);
    let (down, key) = g.set_role(&a.keys, b.pk(), Role::Relay, None).unwrap();
    let (epoch, k) = key.unwrap();
    a.ring.insert(epoch, k);
    g.insert(down).unwrap();
    assert!(g.state().members[&b.pk()].reader.is_none());
    let (up, _) = g.set_role(&a.keys, b.pk(), Role::Reader, None).unwrap();
    g.insert(up).unwrap();
    assert_eq!(g.state().members[&b.pk()].seal_key(), &b.keys.public().kex_pk);
    // the next epoch is one B opens with what every device has
    let e = rotate(&mut g, &mut a);
    b.readers.clear();
    b.unlock(&g);
    assert!(b.ring.get(&e).is_some());
}

/// A reader that says it lost its earlier keys marks the epochs sealed
/// before that as closed to it, until someone rotates having seen it.
#[test]
fn an_epoch_sealed_before_a_reader_lost_its_keys_is_closed_until_rotated() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    b.rekey(&mut g, false);
    let e1 = rotate(&mut g, &mut a);
    assert!(!g.epoch_closed_to_a_reader(&e1));
    // an ordinary change of key closes nothing: B keeps the earlier one
    b.rekey(&mut g, false);
    assert!(!g.epoch_closed_to_a_reader(&e1));

    // B loses everything it stored, and says so with its next key
    b.readers.clear();
    let lost = b.rekey(&mut g, true);
    assert_eq!(g.state().members[&b.pk()].reader.as_ref().unwrap().lost_before, Some(lost.id()));
    assert!(g.epoch_closed_to_a_reader(&e1), "sealed to a key B no longer has");
    assert_eq!(g.state().write_epoch(), Some(e1), "still valid to write under: moving on is the writer's call");

    let e2 = rotate(&mut g, &mut a);
    assert!(!g.epoch_closed_to_a_reader(&e2), "its author had seen B's new key");
    b.ring = Keyring::default();
    b.unlock(&g);
    assert!(b.ring.get(&e2).is_some());
    // a later ordinary key keeps the mark where it was
    b.rekey(&mut g, false);
    assert_eq!(g.state().members[&b.pk()].reader.as_ref().unwrap().lost_before, Some(lost.id()));
    assert!(g.epoch_closed_to_a_reader(&e1) && !g.epoch_closed_to_a_reader(&e2));
}

/// A writer that hasn't heard of the loss seals to the lost key: once the
/// two views meet, everyone sees that its epoch is closed to the reader.
#[test]
fn a_rotation_by_a_writer_behind_on_a_loss_is_closed_too() {
    let (mut g, a) = space();
    let mut b = Peer::new();
    let add_b = add(&mut g, &a, &b, Role::Writer);
    let k1 = b.rekey(&mut g, false);
    let mut a_view = graph_with(&g, &[&add_b, &k1]);
    // B loses its keys while A is out of touch, and A rotates meanwhile
    b.readers.clear();
    b.rekey(&mut g, true);
    let (rot, epoch, _) = a_view.rotate(&a.keys).unwrap();
    a_view.insert(rot.clone()).unwrap();
    assert!(!a_view.epoch_closed_to_a_reader(&epoch), "A doesn't know yet");
    g.insert(rot).unwrap();
    assert_eq!(g.state().write_epoch(), Some(epoch));
    assert!(g.epoch_closed_to_a_reader(&epoch));
    b.unlock(&g);
    assert!(b.ring.get(&epoch).is_none(), "and B indeed can't open it");
}

/// The join window: what a member is given when it is added is sealed to
/// its kex key, because it has published no reader key in the space yet.
#[test]
fn what_a_member_is_given_on_joining_is_sealed_to_its_kex_key() {
    let (mut g, mut a) = space();
    a.rekey(&mut g, false);
    let before = rotate(&mut g, &mut a);
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Reader);
    let mut seed_only = from_seed_alone(&b);
    assert_eq!(seed_only.unlock(&g), 2, "the keyring: every epoch up to the join");
    assert!(seed_only.ring.get(&before).is_some());
    // from B's first reader key on, new epochs are out of the seed's reach
    b.rekey(&mut g, false);
    let after = rotate(&mut g, &mut a);
    let mut seed_only = from_seed_alone(&b);
    seed_only.unlock(&g);
    assert!(seed_only.ring.get(&after).is_none());
    b.unlock(&g);
    assert!(b.ring.get(&after).is_some());
}

/// Bringing a keyring up to date skips what it already holds: no lockbox is
/// opened twice (which is what lets a stored keyring outlive reader keys).
#[test]
fn unlock_adds_only_what_is_missing() {
    let (mut g, mut a) = space();
    let mut b = Peer::new();
    add(&mut g, &a, &b, Role::Writer);
    b.rekey(&mut g, false);
    for _ in 0..3 {
        rotate(&mut g, &mut a);
    }
    assert_eq!(b.unlock(&g), 4);
    assert_eq!(b.unlock(&g), 0);
    rotate(&mut g, &mut a);
    assert_eq!(b.unlock(&g), 1);
    // with the reader keys gone, the keyring it kept is still complete
    b.readers.clear();
    assert_eq!(b.unlock(&g), 0);
    assert_eq!(b.ring.len(), g.state().epochs.len());
}
