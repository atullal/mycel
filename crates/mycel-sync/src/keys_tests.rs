//! The key schedule (`keys.rs`): reader keys published, replaced and
//! deleted on this device's clock, the keyring kept across restarts, and
//! epochs rotated by age.

use super::*;
use crate::tests::MemStore;

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

fn dev() -> Arc<DeviceKeys> {
    Arc::new(DeviceKeys::generate())
}

type Time = Arc<AtomicU64>;

/// A clock for a test to move, starting at the real time: a replica reads
/// the real clock until it is handed this one.
fn start() -> Time {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Arc::new(AtomicU64::new(now))
}

fn clock(t: &Time) -> Clock {
    let t = t.clone();
    Arc::new(move || t.load(Ordering::Relaxed))
}

/// Turn the key schedule on, on a clock the test moves.
fn schedule(r: &mut Replica, t: &Time) {
    r.set_key_clock(clock(t));
    r.set_key_policy(Some(KeyPolicy::default()));
}

/// Let `hours` pass with these devices running: the clock moves in steps
/// too short to count as downtime, and each device does its upkeep.
fn run(t: &Time, devices: &mut [&mut Replica], hours: u64) {
    let mut left = hours;
    while left > 0 {
        let step = left.min(4);
        t.fetch_add(step * HOUR, Ordering::Relaxed);
        left -= step;
        for r in devices.iter_mut() {
            r.key_upkeep();
        }
    }
}

/// Full two-way sync of ops, then envelopes.
fn sync(a: &mut Replica, b: &mut Replica) {
    for _ in 0..3 {
        let (ops_a, ops_b) = (a.all_ops(), b.all_ops());
        b.ingest_batch(ops_a, vec![]);
        a.ingest_batch(ops_b, vec![]);
    }
    let envs =
        |r: &Replica| -> Vec<Envelope> { r.envelope_ids().iter().map(|i| r.envelope(i).unwrap().clone()).collect() };
    let (ea, eb) = (envs(a), envs(b));
    b.ingest_batch(vec![], ea);
    a.ingest_batch(vec![], eb);
}

/// A founder and a writer, synced, both on the schedule and the same clock.
/// The writer keeps its data in `store`.
fn pair(store: Option<Arc<MemStore>>) -> (Replica, Replica, Arc<DeviceKeys>, SignedOp, Time) {
    let t: Time = start();
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    schedule(&mut a, &t);
    let bk = dev();
    let store = store.map(|s| s as Arc<dyn Store>);
    let mut b = Replica::join(bk.clone(), genesis.clone(), store).unwrap();
    schedule(&mut b, &t);
    a.add_member(bk.public(), Role::Writer).unwrap();
    sync(&mut a, &mut b);
    (a, b, bk, genesis, t)
}

fn reader_key_of(r: &Replica, pk: &SignPk) -> Option<mycel_trust::ReaderKey> {
    r.graph().state().members[pk].reader.clone()
}

fn bodies(r: &mut Replica, feed: &StreamId) -> Vec<String> {
    r.feed(feed).iter().map(|e| String::from_utf8_lossy(&e.body).into_owned()).collect()
}

/// What `store` holds, as a restart would read it back.
fn restart(store: &MemStore, keys: Arc<DeviceKeys>, genesis: &SignedOp, with_secrets: bool) -> Replica {
    let ops: Vec<SignedOp> = store.ops.lock().unwrap().iter().filter(|o| o.id() != genesis.id()).cloned().collect();
    let envs = store.envs.lock().unwrap().clone();
    let secrets = store.secrets.lock().unwrap().clone().filter(|_| with_secrets);
    Replica::restore_with_secrets(keys, genesis.clone(), ops, envs, secrets.as_deref(), None).unwrap()
}

#[test]
fn a_replica_publishes_nothing_until_its_schedule_is_on() {
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis, None).unwrap();
    a.add_member(bk.public(), Role::Writer).unwrap();
    sync(&mut a, &mut b);
    // an invitation that nobody accepted yet: B's device says nothing
    assert_eq!(b.all_ops().len(), 2);
    assert!(b.key_upkeep().is_none());
    assert!(reader_key_of(&b, &bk.sign_pk()).is_none());
    assert_eq!(b.reader_keys_held(), 0);
    // accepted: the device's first reader key goes out
    let op = b.set_key_policy(Some(KeyPolicy::default())).expect("a reader key");
    assert!(matches!(op.op.action, mycel_trust::Action::ReaderKey { lost_previous: false, .. }));
    assert_eq!(reader_key_of(&b, &bk.sign_pk()).unwrap().op, op.id());
    assert_eq!(b.reader_keys_held(), 1);
    // and nothing more while it is fresh
    assert!(b.key_upkeep().is_none());
    assert!(b.set_key_policy(Some(KeyPolicy::default())).is_none());
}

#[test]
fn reader_keys_are_replaced_on_schedule_and_deleted_after_the_retention() {
    let (mut a, mut b, bk, _, t) = pair(None);
    let first = reader_key_of(&b, &bk.sign_pk()).unwrap();
    assert_eq!(reader_key_of(&a, &bk.sign_pk()).as_ref(), Some(&first), "A seals to it");

    // six days: still the same key
    run(&t, &mut [&mut a, &mut b], 6 * 24);
    assert_eq!(reader_key_of(&b, &bk.sign_pk()).unwrap(), first);
    // the seventh: a new one, and the old one kept
    run(&t, &mut [&mut a, &mut b], 24);
    let second = reader_key_of(&b, &bk.sign_pk()).unwrap();
    assert_ne!(second.key, first.key);
    assert!(second.lost_before.is_none());
    assert_eq!(b.reader_keys_held(), 2);
    sync(&mut a, &mut b);
    assert_eq!(reader_key_of(&a, &bk.sign_pk()).unwrap(), second);

    // 29 days of running later the first is still there, and three more
    // have come; a day later the first is gone
    run(&t, &mut [&mut a, &mut b], 29 * 24);
    assert_eq!(b.reader_keys_held(), 6, "the current one and five replaced");
    run(&t, &mut [&mut a, &mut b], 24);
    assert_eq!(b.reader_keys_held(), 5, "the first was deleted");
    // steady state: a key lives 7 days in use and 30 more kept
    run(&t, &mut [&mut a, &mut b], 60 * 24);
    assert!(b.reader_keys_held() <= 6, "{}", b.reader_keys_held());
}

/// What the reader keys are for. A's rotation is sealed to B's reader key,
/// so the seed doesn't open it; once B has deleted that key, the lockbox is
/// closed for good, and B still reads its history from the keyring it kept.
#[test]
fn a_deleted_reader_key_closes_old_lockboxes_and_the_stored_keyring_still_reads_history() {
    let store = Arc::new(MemStore::default());
    let (mut a, mut b, bk, genesis, t) = pair(Some(store.clone()));
    let feed = StreamId::new_feed();
    // day 2: the first epoch is old, so A's write rotates, sealing to
    // B's reader key
    run(&t, &mut [&mut a, &mut b], 48);
    let (ops, _) = a.append(feed, b"under B's first reader key".to_vec()).unwrap();
    assert!(ops.iter().any(|o| matches!(o.op.action, mycel_trust::Action::Rotate { .. })), "a timed rotation");
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["under B's first reader key"]);
    let old_epoch = b.graph().state().write_epoch().unwrap();

    // B's key is replaced on day 7 and deleted 30 running days later
    run(&t, &mut [&mut a, &mut b], 45 * 24);
    sync(&mut a, &mut b);
    a.append(feed, b"much later".to_vec()).unwrap();
    sync(&mut a, &mut b);
    assert_ne!(b.graph().state().write_epoch().unwrap(), old_epoch);

    // a restart with what B stored: all of it is read
    let mut restored = restart(&store, bk.clone(), &genesis, true);
    assert_eq!(bodies(&mut restored, &feed), ["under B's first reader key", "much later"]);
    assert_eq!(restored.opaque_count(), 0);
    assert_eq!(restored.reader_keys_held(), b.reader_keys_held());

    // the same device without its stored secrets: the old epoch's lockbox
    // was sealed to a key that is gone, so the old message can't be read
    let mut bare = restart(&store, bk.clone(), &genesis, false);
    assert!(bare.opaque_count() >= 1);
    assert!(!bodies(&mut bare, &feed).contains(&"under B's first reader key".to_string()));

    // and a thief with B's seed and everything a keeper stores (every op,
    // every envelope) reads neither message
    let thief = Arc::new(DeviceKeys::from_seed(bk.seed()));
    let ops: Vec<SignedOp> = a.all_ops().into_iter().filter(|o| o.id() != genesis.id()).collect();
    let envs: Vec<Envelope> = a.envelope_ids().iter().map(|i| a.envelope(i).unwrap().clone()).collect();
    let mut stolen = Replica::restore(thief, genesis.clone(), ops, envs, None).unwrap();
    assert!(bodies(&mut stolen, &feed).is_empty(), "{:?}", bodies(&mut stolen, &feed));
    assert_eq!(stolen.opaque_count(), 2);
}

/// The founder's side of a restart: its own reader key, the members it
/// added and what they wrote come back as they were, and it keeps writing.
#[test]
fn a_founder_restarts_with_its_secrets() {
    let store = Arc::new(MemStore::default());
    let t = start();
    let ak = dev();
    let (mut a, genesis) = Replica::create(ak.clone(), Some(store.clone() as Arc<dyn Store>)).unwrap();
    schedule(&mut a, &t);
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis.clone(), None).unwrap();
    schedule(&mut b, &t);
    a.add_member(bk.public(), Role::Writer).unwrap();
    let feed = StreamId::new_feed();
    a.append(feed, b"from a".to_vec()).unwrap();
    sync(&mut a, &mut b);
    b.append(feed, b"from b".to_vec()).unwrap();
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut a, &feed), ["from a", "from b"]);
    let (state, held) = (a.graph().state().clone(), a.reader_keys_held());
    drop(a);

    let mut a = restart(&store, ak.clone(), &genesis, true);
    assert_eq!(a.graph().state(), &state);
    assert_eq!(bodies(&mut a, &feed), ["from a", "from b"]);
    assert_eq!((a.opaque_count(), a.reader_keys_held()), (0, held));
    // back on its schedule: the key it has is still good, nothing goes out
    a.set_key_clock(clock(&t));
    assert!(a.set_key_policy(Some(KeyPolicy::default())).is_none());
    a.append(feed, b"after the restart".to_vec()).unwrap();
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["from a", "from b", "after the restart"]);
}

/// A store hands ops back in no particular order. Members now author ops
/// (their reader keys), and the graph refuses an op whose author it hasn't
/// seen added: a restore must still take every op, whatever the order.
#[test]
fn a_restore_takes_stored_ops_in_any_order() {
    let (mut a, mut b, _, genesis, t) = pair(None);
    let ck = dev();
    let mut c = Replica::join(ck.clone(), genesis.clone(), None).unwrap();
    schedule(&mut c, &t);
    a.add_member(ck.public(), Role::Writer).unwrap();
    sync(&mut a, &mut c);
    sync(&mut a, &mut b);
    let feed = StreamId::new_feed();
    for (i, r) in [&mut a, &mut b, &mut c].into_iter().enumerate() {
        r.append(feed, format!("from {i}").into_bytes()).unwrap();
    }
    run(&t, &mut [&mut a, &mut b, &mut c], 8 * 24);
    sync(&mut a, &mut b);
    sync(&mut a, &mut c);
    sync(&mut a, &mut b);
    c.append(feed, b"last".to_vec()).unwrap();
    sync(&mut a, &mut c);
    let want = bodies(&mut a, &feed);
    assert_eq!(want.len(), 4);
    let ops: Vec<SignedOp> = a.all_ops().into_iter().filter(|o| o.id() != genesis.id()).collect();
    assert!(ops.iter().filter(|o| matches!(o.op.action, mycel_trust::Action::ReaderKey { .. })).count() >= 6);
    let envs: Vec<Envelope> = a.envelope_ids().iter().map(|i| a.envelope(i).unwrap().clone()).collect();
    let secrets = a.sealed_secrets().unwrap();

    let mut reversed = ops.clone();
    reversed.reverse();
    let mut by_id = ops.clone();
    by_id.sort_by_key(SignedOp::id);
    // with the genesis and a duplicate thrown in, as a careless store might
    let mut padded = by_id.clone();
    padded.insert(0, genesis.clone());
    padded.push(ops[0].clone());
    for (name, order) in [("as authored", ops), ("reversed", reversed), ("by id", by_id), ("padded", padded)] {
        let mut r =
            Replica::restore_with_secrets(a.me().clone(), genesis.clone(), order, envs.clone(), Some(&secrets), None)
                .unwrap();
        assert_eq!(r.graph().state(), a.graph().state(), "{name}");
        assert_eq!(r.all_ops().len(), a.all_ops().len(), "{name}: every op is back");
        assert_eq!(bodies(&mut r, &feed), want, "{name}");
        assert_eq!(r.opaque_count(), 0, "{name}");
    }
    // an op whose parent was never stored waits, and the rest is unaffected
    let mut orphaned: Vec<SignedOp> = a.all_ops().into_iter().filter(|o| o.id() != genesis.id()).collect();
    let dropped = orphaned.remove(0);
    orphaned.reverse();
    let r = Replica::restore_with_secrets(a.me().clone(), genesis.clone(), orphaned, vec![], None, None).unwrap();
    assert!(r.op(&dropped.id()).is_none());
    assert!(r.all_ops().len() > 1);
}

/// What is stored is sealed to the device and the space: another device's
/// seed, or the same secrets offered for another space, give nothing.
#[test]
fn stored_secrets_open_only_for_their_device_and_space() {
    let store = Arc::new(MemStore::default());
    let (mut a, mut b, bk, genesis, t) = pair(Some(store.clone()));
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 48);
    a.append(feed, b"secret".to_vec()).unwrap();
    sync(&mut a, &mut b);
    let sealed = store.secrets.lock().unwrap().clone().expect("secrets were stored");
    // not readable as stored: no key material in the clear
    let seeds = b.reader_seeds_for_test();
    assert!(!seeds.is_empty());
    assert!(seeds.iter().all(|seed| !sealed.windows(32).any(|w| w == seed)));

    let ops: Vec<SignedOp> = store.ops.lock().unwrap().iter().filter(|o| o.id() != genesis.id()).cloned().collect();
    let envs = store.envs.lock().unwrap().clone();
    // another device's seed
    let mut other =
        Replica::restore_with_secrets(dev(), genesis.clone(), ops.clone(), envs.clone(), Some(&sealed), None).unwrap();
    assert_eq!(other.reader_keys_held(), 0);
    assert!(bodies(&mut other, &feed).is_empty());
    // a damaged record: ignored, not half-read
    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let damaged = Replica::restore_with_secrets(bk.clone(), genesis.clone(), ops, envs, Some(&bad), None).unwrap();
    assert_eq!(damaged.reader_keys_held(), 0);
    // B's own secrets offered for another space B founded
    let (mut elsewhere, _) = Replica::create(bk.clone(), None).unwrap();
    elsewhere.load_secrets(&sealed);
    assert_eq!(elsewhere.reader_keys_held(), 0);
}

/// A reader key is published only once its private half is stored: what
/// others then seal to it could be opened with nothing else.
#[test]
fn a_reader_key_is_stored_before_it_is_published() {
    let store = Arc::new(MemStore::default());
    store.fail_secrets.store(true, Ordering::Relaxed);
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis, Some(store.clone() as Arc<dyn Store>)).unwrap();
    a.add_member(bk.public(), Role::Writer).unwrap();
    sync(&mut a, &mut b);
    // the store refuses: nothing goes out, and nothing is kept
    assert!(b.set_key_policy(Some(KeyPolicy::default())).is_none());
    assert!(reader_key_of(&b, &bk.sign_pk()).is_none());
    assert_eq!(b.reader_keys_held(), 0);
    assert_eq!(b.all_ops().len(), 2);
    // B still works, on its kex key
    let feed = StreamId::new_feed();
    b.append(feed, b"still here".to_vec()).unwrap();
    // the store recovers: the next upkeep publishes, after a durable write
    store.fail_secrets.store(false, Ordering::Relaxed);
    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 0);
    assert!(b.key_upkeep().is_some());
    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
    assert_eq!(b.reader_keys_held(), 1);
    assert!(store.secrets.lock().unwrap().is_some());
}

/// A writer leaves an epoch once it has held its key for a day, plus its
/// own share of jitter; whoever is due first rotates, and the others find
/// a fresh epoch.
#[test]
fn epochs_rotate_by_age_with_jitter() {
    let (mut a, mut b, _, _, t) = pair(None);
    let feed = StreamId::new_feed();
    let wrote_rotation =
        |ops: &[SignedOp]| ops.iter().any(|o| matches!(o.op.action, mycel_trust::Action::Rotate { .. }));

    // within the day: no rotation, whoever writes
    let first = a.graph().state().write_epoch().unwrap();
    run(&t, &mut [&mut a, &mut b], 23);
    assert!(!wrote_rotation(&a.append(feed, b"a1".to_vec()).unwrap().0));
    assert!(!wrote_rotation(&b.append(feed, b"b1".to_vec()).unwrap().0));
    sync(&mut a, &mut b);
    assert_eq!(a.graph().state().write_epoch(), Some(first));

    // a day and a quarter on, both are due whatever their jitter: the first
    // to write rotates, the other writes under the new epoch
    run(&t, &mut [&mut a, &mut b], 8);
    assert!(a.should_rotate(&first) && b.should_rotate(&first));
    assert!(wrote_rotation(&b.append(feed, b"b2".to_vec()).unwrap().0));
    sync(&mut a, &mut b);
    let second = a.graph().state().write_epoch().unwrap();
    assert_ne!(second, first);
    assert!(!wrote_rotation(&a.append(feed, b"a2".to_vec()).unwrap().0));
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut a, &feed), bodies(&mut b, &feed));
    assert_eq!(bodies(&mut a, &feed).len(), 4);

    // the jitter: each device is due somewhere in [a day, a day and a
    // quarter], at its own moment for each epoch
    let start = t.load(Ordering::Relaxed);
    let due_at = |r: &Replica| {
        let due = (0..=31 * 60).find(|m| {
            t.store(start + m * 60, Ordering::Relaxed);
            r.should_rotate(&second)
        });
        t.store(start, Ordering::Relaxed);
        due.expect("due within 31 hours")
    };
    for d in [due_at(&a), due_at(&b)] {
        assert!((24 * 60..=30 * 60).contains(&d), "due after {d} minutes");
    }
    // spread over the quarter, and fixed for a given device and epoch
    let (period, epoch) = (DAY, EpochId([7; 16]));
    let jitters: BTreeSet<u64> = (0..64u8).map(|i| keys::rotation_jitter(&SignPk([i; 32]), &epoch, period)).collect();
    assert!(jitters.iter().all(|j| *j <= period / 4));
    assert!(jitters.len() > 56, "{} distinct jitters of 64", jitters.len());
    assert!(jitters.iter().any(|j| *j < period / 16) && jitters.iter().any(|j| *j > period * 3 / 16));
    let me = SignPk([1; 32]);
    assert_eq!(keys::rotation_jitter(&me, &epoch, period), keys::rotation_jitter(&me, &epoch, period));
    assert_ne!(keys::rotation_jitter(&me, &epoch, period), keys::rotation_jitter(&me, &EpochId([8; 16]), period));
    assert_eq!(keys::rotation_jitter(&me, &epoch, 0), 0);
}

/// Both rotate at once, each unaware of the other: two epochs for a moment,
/// one write epoch after they meet, and both read everything.
#[test]
fn concurrent_timed_rotations_converge() {
    let (mut a, mut b, _, _, t) = pair(None);
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 32);
    a.append(feed, b"from a".to_vec()).unwrap();
    b.append(feed, b"from b".to_vec()).unwrap();
    assert_ne!(a.graph().state().write_epoch(), b.graph().state().write_epoch());
    sync(&mut a, &mut b);
    assert_eq!(a.graph().state().write_epoch(), b.graph().state().write_epoch());
    assert_eq!(a.graph().state(), b.graph().state());
    let mut got = bodies(&mut a, &feed);
    got.sort();
    assert_eq!(got, ["from a", "from b"]);
    assert_eq!(bodies(&mut a, &feed), bodies(&mut b, &feed));
    assert_eq!((a.opaque_count(), b.opaque_count()), (0, 0));
}

/// A doesn't hear of B's new reader key and seals a rotation to the one
/// before. Inside the retention B still holds it and reads on.
#[test]
fn a_member_behind_on_a_reader_key_is_understood_inside_the_retention() {
    let (mut a, mut b, bk, _, t) = pair(None);
    let feed = StreamId::new_feed();
    let first = reader_key_of(&b, &bk.sign_pk()).unwrap();
    // B moves on alone for 20 days: two new reader keys A never hears of
    run(&t, &mut [&mut b], 20 * 24);
    assert_ne!(reader_key_of(&b, &bk.sign_pk()).unwrap().key, first.key);
    assert_eq!(reader_key_of(&a, &bk.sign_pk()).unwrap(), first, "A is behind");
    // A, offline all that time, writes: its timed rotation seals to B's first key
    a.set_key_clock(clock(&t));
    let (ops, _) = a.append(feed, b"sealed to the key before".to_vec()).unwrap();
    assert!(!ops.is_empty());
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["sealed to the key before"]);
    assert_eq!(b.opaque_count(), 0);
}

/// The same, but A stays away past the retention: B has deleted the key A
/// seals to, can't read that epoch, and says so with its next reader key.
/// The next writer then leaves the epoch, and B reads on from there.
#[test]
fn past_the_retention_a_closed_epoch_is_left_at_the_next_write() {
    let (mut a, mut b, bk, _, t) = pair(None);
    let feed = StreamId::new_feed();
    let first = reader_key_of(&b, &bk.sign_pk()).unwrap();
    run(&t, &mut [&mut b], 45 * 24);
    assert_eq!(reader_key_of(&a, &bk.sign_pk()).unwrap(), first);
    a.append(feed, b"written while away".to_vec()).unwrap();
    let closed = a.graph().state().write_epoch().unwrap();
    sync(&mut a, &mut b);

    // B can't read it, and published a key that says its earlier ones are gone
    assert_eq!(b.opaque_count(), 1);
    assert!(bodies(&mut b, &feed).is_empty());
    let now = reader_key_of(&b, &bk.sign_pk()).unwrap();
    assert!(now.lost_before.is_some());
    assert!(a.graph().epoch_closed_to_a_reader(&closed), "A learns it from the graph");
    // once is enough: B doesn't publish again while the graph says so
    assert!(b.key_upkeep().is_none());

    // A's next write leaves the closed epoch
    let (ops, _) = a.append(feed, b"after the reunion".to_vec()).unwrap();
    assert!(ops.iter().any(|o| matches!(o.op.action, mycel_trust::Action::Rotate { .. })));
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["after the reunion"]);
    assert!(!a.graph().epoch_closed_to_a_reader(&a.graph().state().write_epoch().unwrap()));
    // and B writes under it too
    b.append(feed, b"back".to_vec()).unwrap();
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut a, &feed), ["written while away", "after the reunion", "back"]);
}

/// A device that was switched off doesn't delete its replaced keys on
/// waking: the time it missed is time in which nothing could reach it.
#[test]
fn time_switched_off_does_not_age_replaced_keys() {
    let (mut a, mut b, bk, _, t) = pair(None);
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 7 * 24);
    sync(&mut a, &mut b);
    assert_eq!(b.reader_keys_held(), 2);
    let second = reader_key_of(&b, &bk.sign_pk()).unwrap();
    // A (alone, behind on nothing yet) rotates on day 8, sealed to B's second key
    run(&t, &mut [&mut a], 24);
    a.append(feed, b"while B was off".to_vec()).unwrap();
    // B is off for 90 days, far past the retention
    t.fetch_add(90 * DAY, Ordering::Relaxed);
    // on waking it replaces its (old) current key, and deletes none
    assert!(b.key_upkeep().is_some());
    assert_eq!(b.reader_keys_held(), 3);
    assert_ne!(reader_key_of(&b, &bk.sign_pk()).unwrap().key, second.key);
    // so what was sealed while it was off still opens
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["while B was off"]);
    // from here the retention runs again: 30 days of running delete the
    // two keys that were already replaced
    run(&t, &mut [&mut a, &mut b], 29 * 24);
    assert!(b.reader_keys_held() >= 3);
    run(&t, &mut [&mut a, &mut b], 2 * 24);
    assert!(b.reader_keys_held() < 7, "{}", b.reader_keys_held());
}

/// A clock set back doesn't delete anything early, republish, or rotate.
#[test]
fn a_clock_set_back_changes_nothing() {
    let (mut a, mut b, bk, _, t) = pair(None);
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 8 * 24);
    sync(&mut a, &mut b);
    a.append(feed, b"x".to_vec()).unwrap();
    sync(&mut a, &mut b);
    let (held, key, epoch, ops) =
        (b.reader_keys_held(), reader_key_of(&b, &bk.sign_pk()), b.graph().state().write_epoch(), b.all_ops().len());
    t.fetch_sub(400 * DAY, Ordering::Relaxed);
    assert!(b.key_upkeep().is_none());
    let (wrote, _) = b.append(feed, b"y".to_vec()).unwrap();
    assert!(wrote.is_empty());
    assert_eq!(
        (b.reader_keys_held(), reader_key_of(&b, &bk.sign_pk()), b.graph().state().write_epoch(), b.all_ops().len()),
        (held, key, epoch, ops)
    );
}

/// A device whose stored secrets are gone (a wiped or rolled-back
/// database) finds a reader key in the graph that it doesn't hold: it
/// publishes a new one at once, marked as having lost the earlier ones.
#[test]
fn a_device_that_lost_its_secrets_says_so_and_is_sealed_to_again() {
    let store = Arc::new(MemStore::default());
    let (mut a, mut b, bk, genesis, t) = pair(Some(store.clone()));
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 48);
    a.append(feed, b"before the loss".to_vec()).unwrap();
    sync(&mut a, &mut b);
    drop(b);

    let mut b = restart(&store, bk.clone(), &genesis, false);
    assert!(bodies(&mut b, &feed).is_empty(), "sealed to a reader key that went with the database");
    schedule(&mut b, &t);
    let key = reader_key_of(&b, &bk.sign_pk()).unwrap();
    assert_eq!(key.lost_before, Some(key.op), "its new key says the earlier ones are lost");
    sync(&mut a, &mut b);
    let (ops, _) = a.append(feed, b"after the loss".to_vec()).unwrap();
    assert!(ops.iter().any(|o| matches!(o.op.action, mycel_trust::Action::Rotate { .. })), "A leaves the closed epoch");
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut b, &feed), ["after the loss"]);
}

/// Keepers hold no keys: the schedule gives them nothing to do, and they
/// keep storing and serving what they can't read.
#[test]
fn keepers_are_unaffected() {
    let store = Arc::new(MemStore::default());
    let t: Time = start();
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    schedule(&mut a, &t);
    let kk = dev();
    let mut keeper = Replica::join(kk.clone(), genesis.clone(), Some(store.clone() as Arc<dyn Store>)).unwrap();
    schedule(&mut keeper, &t);
    a.add_member(kk.public(), Role::Relay).unwrap();
    sync(&mut a, &mut keeper);
    let feed = StreamId::new_feed();
    for day in 0..40 {
        run(&t, &mut [&mut a, &mut keeper], 24);
        a.append(feed, format!("day {day}").into_bytes()).unwrap();
        sync(&mut a, &mut keeper);
    }
    assert!(reader_key_of(&keeper, &kk.sign_pk()).is_none());
    assert_eq!(keeper.reader_keys_held(), 0);
    assert!(keeper.all_ops().iter().all(|o| o.op.author != kk.sign_pk()), "a keeper authors nothing");
    assert_eq!(keeper.opaque_count(), 40, "all of it stored, none of it read");
    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 0);
    // and it serves a member that comes back with nothing but its secrets
    let restored = restart(&store, kk, &genesis, true);
    assert_eq!(restored.opaque_count(), 40);
    assert_eq!(restored.graph().state(), a.graph().state());
}

/// A member added later is given the earlier epochs sealed to its kex key
/// (it has no reader key in the space yet), publishes its first reader key
/// on arriving, and is sealed to that from the next rotation on.
#[test]
fn a_new_member_moves_from_its_kex_key_to_a_reader_key() {
    let (mut a, mut b, _, genesis, t) = pair(None);
    let feed = StreamId::new_feed();
    run(&t, &mut [&mut a, &mut b], 48);
    a.append(feed, b"before C".to_vec()).unwrap();
    let ck = dev();
    let mut c = Replica::join(ck.clone(), genesis.clone(), None).unwrap();
    schedule(&mut c, &t);
    a.add_member(ck.public(), Role::Writer).unwrap();
    sync(&mut a, &mut c);
    sync(&mut a, &mut b);
    assert_eq!(bodies(&mut c, &feed), ["before C"], "history, from the keyring");
    assert!(reader_key_of(&a, &ck.sign_pk()).is_some(), "C's first reader key reached A");
    // the seed alone opens what C was given on joining...
    let all = |r: &Replica| -> (Vec<SignedOp>, Vec<Envelope>) {
        (
            r.all_ops().into_iter().filter(|o| o.id() != genesis.id()).collect(),
            r.envelope_ids().iter().map(|i| r.envelope(i).unwrap().clone()).collect(),
        )
    };
    let (ops, envs) = all(&a);
    let mut seed_only =
        Replica::restore(Arc::new(DeviceKeys::from_seed(ck.seed())), genesis.clone(), ops, envs, None).unwrap();
    assert_eq!(bodies(&mut seed_only, &feed), ["before C"]);
    // ...and nothing from the first rotation after C's reader key
    run(&t, &mut [&mut a, &mut b, &mut c], 32);
    a.append(feed, b"after C's reader key".to_vec()).unwrap();
    sync(&mut a, &mut c);
    assert_eq!(bodies(&mut c, &feed), ["before C", "after C's reader key"]);
    let (ops, envs) = all(&a);
    let mut seed_only = Replica::restore(Arc::new(DeviceKeys::from_seed(ck.seed())), genesis, ops, envs, None).unwrap();
    assert_eq!(bodies(&mut seed_only, &feed), ["before C"]);
    assert_eq!(seed_only.opaque_count(), 1);
}
