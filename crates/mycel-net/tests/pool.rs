//! Connection reuse: every sync, card fetch and ephemeral message to a peer
//! is a new QUIC stream on one pooled connection (one handshake), and a
//! peer that restarts is simply redialed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::{NetEvent, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

async fn node(keys: Arc<DeviceKeys>, name: &str, port: u16) -> Node {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.port = port;
    Node::spawn(keys, opts).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn syncs_reuse_one_connection_and_redial_after_restart() {
    let alice_keys = Arc::new(DeviceKeys::generate());
    let alice = node(alice_keys.clone(), "alice", 0).await;
    let bob = node(Arc::new(DeviceKeys::generate()), "bob", 0).await;
    bob.add_peer_addr(alice.addr());
    alice.add_peer_addr(bob.addr());

    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    let t = Instant::now();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    let first = t.elapsed();

    // N consecutive syncs, each carrying a change.
    const N: usize = 20;
    let doc = Replica::new_doc_id();
    let mut later = Duration::ZERO;
    for i in 0..N {
        alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "n", i as i64))).unwrap().unwrap();
        let t = Instant::now();
        bob.sync_with(alice.id(), space, false).await.unwrap();
        later += t.elapsed();
        // (bob's own background push may have fetched it a moment earlier)
        assert_eq!(
            bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
            json!({"n": i}),
            "sync {i} carried the change"
        );
    }
    eprintln!("first sync (with handshake) {first:?}, then {:?} per sync on the pooled connection", later / N as u32);
    // Card and ephemeral messages ride the same connection.
    assert_eq!(bob.fetch_card(alice.id()).await.unwrap().name, "alice");
    let mut events = alice.subscribe();
    bob.send_ephemeral(space, b"typing".to_vec()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(NetEvent::Ephemeral { data, .. }) = events.recv().await
                && data == b"typing"
            {
                break;
            }
        }
    })
    .await
    .expect("ephemeral message arrived");

    let (b, a) = (bob.connection_counts(), alice.connection_counts());
    eprintln!("bob dialed {}, alice accepted {}", b.dialed, a.accepted);
    assert_eq!(b.dialed, 1, "bob dialed alice once for {} exchanges", N + 3);
    assert_eq!(a.accepted, 1, "alice accepted one connection from bob");

    // Alice restarts (same key, same port). Her shutdown closes bob's
    // pooled connection; the next sync dials the new process.
    let port = alice.addr().ip_addrs().next().unwrap().port();
    alice.shutdown().await.unwrap();
    drop(alice);
    let mut restarted = None;
    for _ in 0..50 {
        let mut opts = NodeOptions::new(NetMode::Local, "alice again");
        opts.port = port;
        if let Ok(n) = Node::spawn(alice_keys.clone(), opts).await {
            restarted = Some(n);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await; // socket still closing
    }
    let alice = restarted.expect("alice restarted on her old port");
    let t = Instant::now();
    // The new process doesn't have the space: the sync re-invites it.
    bob.sync_with(alice.id(), space, false).await.unwrap();
    eprintln!("sync after restart took {:?}", t.elapsed());
    assert!(alice.space_ids().contains(&space), "restarted alice got the space back from bob");
    assert_eq!(bob.connection_counts().dialed, 2, "one redial after the restart");
    for _ in 0..5 {
        bob.sync_with(alice.id(), space, false).await.unwrap();
    }
    assert_eq!(bob.connection_counts().dialed, 2, "and that connection is reused again");
    // An idle connection is closed (normally after POOL_IDLE), then redialed on use.
    bob.close_idle_connections(Duration::ZERO);
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.connection_counts().dialed, 3, "idle connection closed, then redialed");
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Many exchanges at once on the one connection: chats are one space each
/// and a device syncs up to 16 at a time, a download takes several streams.
/// None is refused: past QUIC's stream limit (64) the rest wait for their
/// turn, and the peer isn't marked as failing.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_exchanges_on_one_connection_all_complete() {
    let alice = node(Arc::new(DeviceKeys::generate()), "alice", 0).await;
    let bob = Arc::new(node(Arc::new(DeviceKeys::generate()), "bob", 0).await);
    bob.add_peer_addr(alice.addr());
    alice.add_peer_addr(bob.addr());
    const SPACES: usize = 40;
    let mut spaces = Vec::new();
    for _ in 0..SPACES {
        let (space, genesis) = alice.create_space().unwrap();
        alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
        bob.join_space(genesis).unwrap();
        spaces.push(space);
    }
    let alice_id = alice.id();
    let mut syncs = tokio::task::JoinSet::new();
    for space in spaces {
        let bob = bob.clone();
        syncs.spawn(async move { bob.sync_with(alice_id, space, true).await });
    }
    // and more streams than QUIC lets a peer have open at once
    const CARDS: usize = 100;
    for _ in 0..CARDS {
        let bob = bob.clone();
        syncs.spawn(async move { bob.fetch_card(alice_id).await.map(|_| Default::default()) });
    }
    let mut done = 0;
    while let Some(res) = syncs.join_next().await {
        res.unwrap().expect("every exchange completes");
        done += 1;
    }
    assert_eq!(done, SPACES + CARDS);
    assert_eq!(bob.connection_counts().dialed, 1, "all on one connection");
    assert_eq!(bob.peers()[&alice_id].failures, 0);
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Regression: a phone's background catch-up synced conversations one after
/// another, and every conversation with a sleeping member waited out a
/// connect timeout before the next began; concurrent syncs to that member
/// then queued behind one another's dials. A 25 s iOS refresh reached about
/// three conversations. Now everything starts at once and a failed dial
/// answers every sync waiting for it: one sleeping member in six
/// conversations costs about one connect timeout in all, and a reachable
/// member in the last conversation still gets the news.
#[tokio::test(flavor = "multi_thread")]
async fn a_sleeping_member_costs_one_connect_timeout_not_one_per_conversation() {
    let alice = node(Arc::new(DeviceKeys::generate()), "alice", 0).await;
    let bob = node(Arc::new(DeviceKeys::generate()), "bob", 0).await;
    let asleep = node(Arc::new(DeviceKeys::generate()), "asleep", 0).await;
    alice.add_peer_addr(bob.addr());
    bob.add_peer_addr(alice.addr());
    alice.add_peer_addr(asleep.addr());
    let asleep_keys = asleep.keys().public();
    asleep.shutdown().await.unwrap();
    drop(asleep);

    const SPACES: usize = 6;
    let mut spaces = Vec::new();
    for _ in 0..SPACES {
        let (space, genesis) = alice.create_space().unwrap();
        alice.with_space(&space, |r| r.add_member(asleep_keys, Role::Writer)).unwrap().unwrap();
        spaces.push((space, genesis));
    }
    // Bob is only in the last one.
    let (last, genesis) = spaces.last().cloned().unwrap();
    alice.with_space(&last, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), last, true).await.unwrap();
    let doc = Replica::new_doc_id();
    alice.with_space(&last, |r| r.change(doc, |d| d.put(ROOT, "news", "while you slept"))).unwrap().unwrap();

    let t = Instant::now();
    alice.sync_everything().await;
    let took = t.elapsed();
    eprintln!("synced {SPACES} conversations with one sleeping member in {took:?}");
    assert_eq!(bob.with_space(&last, |r| r.doc_json(&doc)).unwrap(), json!({"news": "while you slept"}));
    // The connect timeout is 6 s; one per conversation would be 36 s.
    assert!(took < Duration::from_secs(10), "took {took:?}");
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Regression: a sync with a member that was running already (here the one
/// a new address starts) made `sync_everything` return at once, before
/// anything arrived. A phone's background catch-up then reported "synced in
/// 0.2 s" and went back to sleep with the message still on its way
/// (mycel-host's windowless catch-up test failed 2 runs in 60). On a
/// single-threaded runtime the address's sync is always the one running.
#[tokio::test(flavor = "current_thread")]
async fn sync_everything_waits_for_a_sync_already_running() {
    let alice = node(Arc::new(DeviceKeys::generate()), "alice", 0).await;
    let bob = node(Arc::new(DeviceKeys::generate()), "bob", 0).await;
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    // Bob has the membership (as after an earlier sync), not Alice's address.
    let ops = alice.with_space(&space, |r| r.all_ops()).unwrap();
    bob.with_space(&space, |r| r.ingest_batch(ops, vec![])).unwrap();
    assert!(bob.with_space(&space, |r| r.my_role()).unwrap().is_some());
    let doc = Replica::new_doc_id();
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "news", "while you slept"))).unwrap().unwrap();

    // Bob learns Alice's address (which starts a sync with her) and catches up.
    bob.add_peer_addr(alice.addr());
    bob.sync_everything().await;
    assert_eq!(
        bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
        json!({"news": "while you slept"}),
        "sync_everything returned before the sync it joined delivered"
    );

    // `sync_all` (one space) waits the same way.
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "news", "and then"))).unwrap().unwrap();
    bob.add_peer_addr(alice.addr());
    bob.sync_all(space).await;
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"news": "and then"}));
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}
