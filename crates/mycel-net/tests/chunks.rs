//! Chunked files over real QUIC: the push policy, resuming, fetching from
//! every holder, files that outlive their sender in a stranger's cache, the
//! cache's budget, and storing a shared file once.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::chunked::{self, Mode, SealedFile};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::chunks::{CacheTier, MemHolders};
use mycel_net::{EAGER_PUSH_MAX, NetMode, Node, NodeOptions, Progress};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;

const MIB: usize = 1024 * 1024;

async fn node_with(keys: Arc<DeviceKeys>, name: &str) -> (Node, PathBuf) {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    let dir = std::env::temp_dir().join(format!("mycel-test-chunks-{:016x}", mycel_crypto::random_u64()));
    opts.blob_dir = Some(dir.clone());
    (Node::spawn(keys, opts).await.unwrap(), dir)
}

async fn node(name: &str) -> (Node, PathBuf) {
    node_with(Arc::new(DeviceKeys::generate()), name).await
}

fn introduce(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
}

/// Deterministic, incompressible-looking bytes (xorshift).
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Seal `data` into `node`'s store, kept for `owner`.
fn seal(node: &Node, data: &[u8], owner: Hash32, mode: &Mode, hints: &[SignPk]) -> SealedFile {
    let store = node.chunk_store().unwrap();
    let mut session = store.begin_seal();
    let hints: Vec<[u8; 32]> = hints.iter().map(|h| h.0).collect();
    let f = chunked::seal_file(mode, &hints, &mut &data[..], |id, b| session.put(id, b), |_| {}).unwrap();
    session.finish(f.root, owner);
    f
}

/// Decrypt the file from `node`'s store.
fn open(node: &Node, f: &SealedFile) -> Vec<u8> {
    let store = node.chunk_store().unwrap();
    let mut out = Vec::new();
    chunked::open_file(&f.root, &f.key, f.len, |id| store.read(id), &mut out, |_| {}).unwrap();
    out
}

async fn eventually_complete(what: &str, nodes: &[&Node], root: Hash32) {
    for _ in 0..1200 {
        let mut all = true;
        for n in nodes {
            all &= n.file_complete(root).await;
        }
        if all {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..1200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

type Seen = Arc<Mutex<Vec<(u64, u64)>>>;

fn recorder() -> (Progress, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    (Arc::new(move |d, t| s.lock().push((d, t))), seen)
}

/// A space of `owner` with `members` in it, known to all of them.
async fn space_of(owner: &Node, members: &[(&Node, Role)]) -> SpaceId {
    let (space, genesis) = owner.create_space().unwrap();
    for (m, role) in members {
        owner.with_space(&space, |r| r.add_member(m.keys().public(), *role)).unwrap().unwrap();
    }
    for (m, _) in members {
        m.join_space(genesis.clone()).unwrap();
        m.sync_with(owner.id(), space, true).await.unwrap();
    }
    space
}

#[tokio::test(flavor = "multi_thread")]
async fn files_follow_the_push_policy_resume_and_come_from_every_holder() {
    let (alice, alice_dir) = node("alice").await;
    let (bob, bob_dir) = node("bob").await;
    let (carol, carol_dir) = node("carol").await;
    let (keeper, keeper_dir) = node("keeper").await;
    introduce(&[&alice, &bob, &carol, &keeper]);
    let space = space_of(&alice, &[(&bob, Role::Writer), (&carol, Role::Writer), (&keeper, Role::Relay)]).await;

    // A small file: pushed to everyone right away, and kept for the space.
    let small = pseudo_random(2 * MIB + 7, 1);
    let f = seal(&alice, &small, space, &Mode::private(), &[]);
    alice.add_file(space, f.root, vec![]).await.unwrap();
    eventually_complete("small file pushed to every member", &[&bob, &carol, &keeper], f.root).await;
    assert_eq!(open(&bob, &f), small);
    for n in [&bob, &carol, &keeper] {
        let store = n.chunk_store().unwrap();
        assert!(store.is_pinned(&f.root, Some(&space)));
        assert_eq!(store.stats().cache_bytes, 0, "a conversation's file uses none of the donated budget");
    }
    eventually("each got the file once", || alice.chunk_bytes_pushed() == 3 * f.sealed_len).await;

    // A big file: only the keeper gets it without asking.
    let big = pseudo_random(40 * MIB, 2);
    let g = seal(&alice, &big, space, &Mode::private(), &[]);
    assert!(g.sealed_len > EAGER_PUSH_MAX);
    alice.add_file(space, g.root, vec![]).await.unwrap();
    eventually_complete("the keeper holds the big file", &[&keeper], g.root).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!bob.file_complete(g.root).await, "big files aren't pushed to members");
    assert!(!bob.chunk_store().unwrap().has(&g.root));

    // Bob starts downloading and is interrupted part way.
    let bob = Arc::new(bob);
    let (progress, seen) = recorder();
    let task = {
        let (bob, key) = (bob.clone(), g.key.clone());
        tokio::spawn(async move { bob.fetch_file(space, g.root, g.len, Some(key), progress).await })
    };
    eventually("download under way", || seen.lock().last().is_some_and(|(d, _)| *d >= 12 * MIB as u64)).await;
    task.abort();
    let _ = task.await;
    let before = seen.lock().last().unwrap().0;
    assert!(before < g.sealed_len, "interrupted part way ({before})");
    assert!(!bob.file_complete(g.root).await);

    // ... and resumes where it stopped: the nodes it has are not fetched again.
    let served = alice.chunk_bytes_served() + keeper.chunk_bytes_served();
    let (progress, seen) = recorder();
    bob.fetch_file(space, g.root, g.len, Some(g.key.clone()), progress).await.unwrap();
    let first = seen.lock()[0];
    assert!(first.0 >= before && first.1 == g.sealed_len, "resumed from {first:?}, had {before}");
    assert_eq!(seen.lock().last().unwrap(), &(g.sealed_len, g.sealed_len));
    assert_eq!(open(&bob, &g), big);
    let resumed = alice.chunk_bytes_served() + keeper.chunk_bytes_served() - served;
    assert!(resumed <= g.sealed_len - first.0 + 4 * MIB as u64, "{resumed} bytes fetched to finish from {first:?}");
    // pieces came from the sender and the keeper at once
    assert!(alice.chunk_bytes_served() > 0 && keeper.chunk_bytes_served() > 0);

    // Alice goes offline: Carol gets it from whoever else has it.
    alice.shutdown().await.unwrap();
    carol.fetch_file(space, g.root, g.len, None, Arc::new(|_, _| {})).await.unwrap();
    assert_eq!(open(&carol, &g), big);
    assert!(bob.chunk_bytes_served() > 0, "a member that downloaded the file serves it too");

    for n in [&*bob, &carol, &keeper] {
        n.shutdown().await.unwrap();
    }
    for d in [alice_dir, bob_dir, carol_dir, keeper_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// The recipient is away when the file is sent, and the sender is gone when
/// the recipient returns: the file waits in the cache of a device that is in
/// neither's conversation and can't read it.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_outlives_its_sender_in_a_strangers_cache() {
    let holders = MemHolders::new();
    let (sender, sender_dir) = node("sender").await;
    let (cache, cache_dir) = node("cache").await;
    let recipient_keys = Arc::new(DeviceKeys::generate());
    let (recipient, recipient_dir) = node_with(recipient_keys.clone(), "recipient").await;
    introduce(&[&sender, &recipient]);
    let space = space_of(&sender, &[(&recipient, Role::Writer)]).await;
    recipient.shutdown().await.unwrap();
    drop(recipient);

    cache.set_holders(Arc::new(holders.clone()));
    sender.add_peer_addr(cache.addr());
    let data = pseudo_random(3 * MIB + 5, 3);
    let f = seal(&sender, &data, space, &Mode::private(), &[cache.id()]);
    sender.add_file(space, f.root, vec![cache.id()]).await.unwrap();
    eventually_complete("the cache holds the file for the recipient", &[&cache], f.root).await;
    eventually("the cache says so", || holders.holders(&f.root) == vec![cache.id()]).await;
    let cached = cache.chunk_store().unwrap();
    assert!(!cached.is_pinned(&f.root, None), "held inside the donated budget, not kept for good");
    assert_eq!(cached.stats().cache_bytes, f.sealed_len);
    assert_eq!(sender.chunk_bytes_pushed(), f.sealed_len);
    sender.shutdown().await.unwrap();

    // The recipient comes back (a new process, the same keys): nobody in the
    // conversation is there, so it looks up who holds the file.
    let (recipient, recipient_dir2) = node_with(recipient_keys, "recipient").await;
    recipient.set_holders(Arc::new(holders.clone()));
    recipient.add_peer_addr(cache.addr());
    let (progress, seen) = recorder();
    recipient.fetch_file(space, f.root, f.len, Some(f.key.clone()), progress).await.unwrap();
    assert_eq!(open(&recipient, &f), data);
    assert_eq!(seen.lock().last().unwrap(), &(f.sealed_len, f.sealed_len));
    assert_eq!(holders.lookups(), vec![f.root]);
    eventually("the cache served all of it", || cache.chunk_bytes_served() == f.sealed_len).await;
    assert!(recipient.chunk_store().unwrap().is_pinned(&f.root, Some(&space)));
    // what was asked for is worth more to the cache than what never is
    let leaf = cached.tree(&f.root).nodes.iter().find(|n| !n.2).unwrap().0;
    eventually("the request counts", || cached.cached_score(&leaf).unwrap() >= 0.99).await;

    for n in [&cache, &recipient] {
        n.shutdown().await.unwrap();
    }
    for d in [sender_dir, cache_dir, recipient_dir, recipient_dir2] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A sender that names nobody still finds a holder among its contacts.
#[tokio::test(flavor = "multi_thread")]
async fn replicas_go_to_contacts_when_a_member_is_away() {
    let (sender, sender_dir) = node("sender").await;
    let (friend, friend_dir) = node("friend").await;
    let (other, other_dir) = node("other").await;
    let (away, away_dir) = node("away").await;
    introduce(&[&sender, &away]);
    let space = space_of(&sender, &[(&away, Role::Writer)]).await;
    away.shutdown().await.unwrap();
    sender.add_peer_addr(friend.addr());
    sender.add_peer_addr(other.addr());
    // one contact refuses, the next takes it
    other.set_cache_policy(Arc::new(|_| CacheTier::Refuse));
    let (o, fr) = (other.id(), friend.id());
    sender.set_replica_candidates(Arc::new(move || vec![o, fr]));
    let data = pseudo_random(MIB + 1, 4);
    let f = seal(&sender, &data, space, &Mode::private(), &[]);
    sender.add_file(space, f.root, vec![]).await.unwrap();
    eventually_complete("a contact holds the file", &[&friend], f.root).await;
    assert!(!other.file_complete(f.root).await);
    assert_eq!(other.chunk_store().unwrap().stats().cache_nodes, 0);
    for n in [&sender, &friend, &other] {
        n.shutdown().await.unwrap();
    }
    for d in [sender_dir, friend_dir, other_dir, away_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn caches_take_only_what_their_budget_allows() {
    let (sender, sender_dir) = node("sender").await;
    let (cache, cache_dir) = node("cache").await;
    sender.add_peer_addr(cache.addr());
    let owner = Hash32([1; 32]);
    let f = seal(&sender, &pseudo_random(3 * MIB, 5), owner, &Mode::private(), &[]);
    let store = cache.chunk_store().unwrap();

    // a device that donates nothing holds nothing
    cache.set_cache_budget(0);
    assert!(sender.push_file(cache.id(), None, f.root).await.is_err());
    // a stranger may fill a sixteenth of the budget: 3 MiB needs 48 MiB
    cache.set_cache_budget(32 * MIB as u64);
    assert!(sender.push_file(cache.id(), None, f.root).await.is_err());
    assert_eq!(store.stats().cache_nodes, 0, "a refused file leaves nothing behind");
    assert_eq!(sender.chunk_bytes_pushed(), 0);
    cache.set_cache_budget(64 * MIB as u64);
    sender.push_file(cache.id(), None, f.root).await.unwrap();
    assert!(cache.file_complete(f.root).await);
    assert_eq!(store.stats().cache_bytes, f.sealed_len);
    // again: it is all there, nothing is sent
    sender.push_file(cache.id(), None, f.root).await.unwrap();
    assert_eq!(sender.chunk_bytes_pushed(), f.sealed_len);

    // the same stranger's next file no longer fits its share ...
    let g = seal(&sender, &pseudo_random(3 * MIB, 6), owner, &Mode::private(), &[]);
    assert!(sender.push_file(cache.id(), None, g.root).await.is_err());
    assert!(!store.has(&g.root));
    // ... a contact's does
    cache.set_cache_policy(Arc::new(|_| CacheTier::Contact));
    sender.push_file(cache.id(), None, g.root).await.unwrap();
    assert!(cache.file_complete(g.root).await);
    // and nothing is taken from a device the app refuses
    cache.set_cache_policy(Arc::new(|_| CacheTier::Refuse));
    let h = seal(&sender, &pseudo_random(MIB, 7), owner, &Mode::private(), &[]);
    assert!(sender.push_file(cache.id(), None, h.root).await.is_err());
    assert!(store.stats().cache_bytes <= 64 * MIB as u64);

    // Room runs out: a contact's new file displaces what nobody asked for,
    // never a file kept for a conversation.
    cache.set_cache_policy(Arc::new(|_| CacheTier::Contact));
    let kept = seal(&cache, &pseudo_random(2 * MIB, 8), owner, &Mode::private(), &[]);
    cache.set_cache_budget(7 * MIB as u64);
    assert!(cache.file_complete(f.root).await && cache.file_complete(g.root).await);
    // make the cached nodes old enough to rank below a fresh arrival
    let big = seal(&sender, &pseudo_random(5 * MIB, 9), owner, &Mode::private(), &[]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    sender.push_file(cache.id(), None, big.root).await.unwrap();
    assert!(cache.file_complete(big.root).await);
    assert!(!(cache.file_complete(f.root).await && cache.file_complete(g.root).await), "older files made room");
    assert!(cache.file_complete(kept.root).await, "a pinned file is never evicted");
    assert!(store.stats().cache_bytes <= 7 * MIB as u64);

    for n in [&sender, &cache] {
        n.shutdown().await.unwrap();
    }
    for d in [sender_dir, cache_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// The same public file sent by two people in two conversations is one set
/// of nodes: stored once, and not sent to a device that has it.
#[tokio::test(flavor = "multi_thread")]
async fn a_public_file_is_stored_and_sent_once() {
    let (alice, alice_dir) = node("alice").await;
    let (bob, bob_dir) = node("bob").await;
    let (carol, carol_dir) = node("carol").await;
    introduce(&[&alice, &bob, &carol]);
    let with_alice = space_of(&alice, &[(&carol, Role::Writer)]).await;
    let with_bob = space_of(&bob, &[(&carol, Role::Writer)]).await;

    let data = pseudo_random(5 * MIB + 3, 10);
    let from_alice = seal(&alice, &data, with_alice, &Mode::Public, &[]);
    let from_bob = seal(&bob, &data, with_bob, &Mode::Public, &[]);
    assert_eq!(from_alice, from_bob, "the same content is the same reference, whoever seals it");

    alice.add_file(with_alice, from_alice.root, vec![]).await.unwrap();
    eventually_complete("carol has the file from alice", &[&carol], from_alice.root).await;
    let store = carol.chunk_store().unwrap();
    let nodes = store.stats().pinned_nodes;
    eventually("alice sent it once", || alice.chunk_bytes_pushed() == from_alice.sealed_len).await;

    // Bob sends the same file: Carol keeps it for his conversation too,
    // and not a byte of it travels.
    bob.add_file(with_bob, from_bob.root, vec![]).await.unwrap();
    eventually("carol keeps it for bob's conversation", || store.is_pinned(&from_bob.root, Some(&with_bob))).await;
    assert!(store.is_pinned(&from_alice.root, Some(&with_alice)));
    assert_eq!(store.stats().pinned_nodes, nodes, "one copy for both conversations");
    assert_eq!(bob.chunk_bytes_pushed(), 0);
    assert_eq!(open(&carol, &from_bob), data);

    // A private file is different every time it is sealed ...
    let p1 = seal(&alice, &data, with_alice, &Mode::private(), &[]);
    let p2 = seal(&alice, &data, with_alice, &Mode::private(), &[]);
    assert_ne!(p1.root, p2.root);
    let (t1, t2) = (alice.chunk_store().unwrap().tree(&p1.root), alice.chunk_store().unwrap().tree(&p2.root));
    assert!(t1.nodes.iter().all(|a| t2.nodes.iter().all(|b| a.0 != b.0)), "two private copies share no node");
    // ... but forwarding one reuses its reference: nothing new to store or send.
    alice.add_file(with_alice, p1.root, vec![]).await.unwrap();
    eventually_complete("carol has the private file", &[&carol], p1.root).await;
    let pushed = carol.chunk_bytes_pushed();
    carol.add_file(with_bob, p1.root, vec![]).await.unwrap();
    eventually_complete("bob has the forwarded file", &[&bob], p1.root).await;
    eventually("sent once, to the one who lacked it", || carol.chunk_bytes_pushed() - pushed == p1.sealed_len).await;
    assert_eq!(open(&bob, &p1), data);

    for n in [&alice, &bob, &carol] {
        n.shutdown().await.unwrap();
    }
    for d in [alice_dir, bob_dir, carol_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
