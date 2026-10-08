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
        assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"n": i}), "sync {i} carried the change");
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

