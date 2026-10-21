//! Sync v2 between real nodes over QUIC: idle cost, fallback to v1 for
//! builds without it, bounded fan-out in a larger group, and a long
//! catch-up over a slow emulated radio link.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_sync::{StreamId, StreamKind};
use mycel_trust::Role;

async fn node(name: &str, sync_v2: bool) -> Node {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.sync_v2 = sync_v2;
    Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap()
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

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn feed() -> StreamId {
    StreamId::named(StreamKind::Feed, "chat")
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_pair_syncs_and_an_idle_check_is_one_small_exchange() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    alice
        .with_space(&space, |r| {
            for i in 0..200u32 {
                r.append(feed(), i.to_le_bytes().to_vec())?;
            }
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();
    // (bob's own background session may have fetched some of them first)
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 200);
    // Let background forwarding settle, then measure one idle check.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = bob.sync_v2_totals();
    let stats = bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(stats.envelopes, 0);
    let after = bob.sync_v2_totals();
    let bytes = (after.sent_bytes + after.recv_bytes) - (before.sent_bytes + before.recv_bytes);
    eprintln!("idle v2 session: {bytes} bytes on the stream (200 envelopes held)");
    assert!(bytes < 400, "idle check costs O(1): {bytes} bytes");
    assert_eq!(after.idle, before.idle + 1);
    assert_eq!(after.fallbacks, 0);
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_build_without_v2_is_synced_with_v1_and_remembered() {
    let alice = node("alice", true).await;
    let old = node("old", false).await;
    introduce(&[&alice, &old]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(old.keys().public(), Role::Writer)).unwrap().unwrap();
    old.join_space(genesis).unwrap();
    alice.with_space(&space, |r| r.append(feed(), b"hi".to_vec())).unwrap().unwrap();
    alice.sync_with(old.id(), space, false).await.unwrap();
    assert_eq!(old.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 1);
    assert_eq!(alice.sync_v2_totals().fallbacks, 1, "the refused stream fell back to v1");
    alice.with_space(&space, |r| r.append(feed(), b"again".to_vec())).unwrap().unwrap();
    alice.sync_with(old.id(), space, false).await.unwrap();
    assert_eq!(old.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 2);
    assert_eq!(alice.sync_v2_totals().fallbacks, 1, "remembered: v2 not tried again");
    // The old build syncs with v1 as a client, and a v2 node serves it.
    old.with_space(&space, |r| r.append(feed(), b"from old".to_vec())).unwrap().unwrap();
    old.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(alice.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 3);
    assert_eq!(old.sync_v2_totals().client_sessions, 0);
    alice.shutdown().await.unwrap();
    old.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_reaches_a_larger_group_with_bounded_fanout() {
    const N: usize = 10;
    let mut nodes = Vec::new();
    for i in 0..N {
        nodes.push(node(&format!("n{i}"), true).await);
    }
    introduce(&nodes.iter().collect::<Vec<_>>());
    let (space, genesis) = nodes[0].create_space().unwrap();
    for n in &nodes[1..] {
        nodes[0].with_space(&space, |r| r.add_member(n.keys().public(), Role::Writer)).unwrap().unwrap();
        n.join_space(genesis.clone()).unwrap();
    }
    nodes[0].changed(space);
    eventually("everyone learns the membership", || {
        nodes.iter().all(|n| n.with_space(&space, |r| r.members().len()).unwrap() == N)
    })
    .await;
    // The first periodic round (within ~2 s) tells each view member that
    // it was chosen, so pushes flow both ways along every edge.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let sessions = |nodes: &[Node]| nodes.iter().map(|n| n.sync_v2_totals().client_sessions).sum::<u64>();
    let before = sessions(&nodes);
    let author = &nodes[3];
    author.with_space(&space, |r| r.append(feed(), b"to everyone".to_vec())).unwrap().unwrap();
    author.changed(space);
    eventually("every member gets the message", || {
        nodes.iter().all(|n| n.with_space(&space, |r| r.feed_len(&feed())).unwrap() == 1)
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let used = sessions(&nodes) - before;
    eprintln!("one message in a {N}-member group: {used} sessions (v1 epidemic: ~{})", (N - 1) * N);
    // The author reaches everyone directly; forwarders use their bounded
    // view, so a message costs O(members) sessions, not O(members²).
    assert!(used < ((N - 1) * (N - 1)) as u64, "{used} sessions");
    for n in nodes {
        n.shutdown().await.unwrap();
    }
}

async fn link_node(name: &str, net: &MemNet) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = false;
    opts.links = vec![net.link(keys.sign_pk()) as Arc<dyn Link>];
    Node::spawn(keys, opts).await.unwrap()
}

/// Review regression: the streaming side heard nothing back for more than
/// a reply timeout (60 s) and aborted its own session; a converged session
/// whose peer stopped the stream first was reported as failed; and both
/// directions streamed the same items at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_catch_up_longer_than_a_reply_timeout_completes_over_a_slow_link() {
    let bt = MemNet::new(0, PathKind::Bluetooth);
    let alice = link_node("alice", &bt).await;
    let bob = link_node("bob", &bt).await;
    eventually("the link comes up", || alice.peers().get(&bob.id()).is_some_and(|p| p.online())).await;
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    const N: u32 = 2_500;
    alice
        .with_space(&space, |r| {
            for i in 0..N {
                let mut body = vec![0u8; 900];
                body[..4].copy_from_slice(&i.to_le_bytes());
                r.append(feed(), body)?;
            }
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();
    // 25 kB/s: about 100 s of one-way streaming for one session. Bob joins
    // and catches up (its explicit sync, or a background one: one session
    // per pair runs, the other waits or gets `Busy`).
    bt.set_rate_limit(Some(25_000));
    let t = Instant::now();
    bob.join_space(genesis).unwrap();
    let res = bob.sync_with(alice.id(), space, true).await;
    while bob.with_space(&space, |r| r.feed_len(&feed())).unwrap() < N as usize
        && t.elapsed() < Duration::from_secs(400)
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let took = t.elapsed();
    // (alice's side ends when bob's `Close` reaches it)
    eventually("alice's side of the session ends", || alice.sync_v2_totals().server_sessions >= 1).await;
    let (a, b) = (alice.sync_v2_totals(), bob.sync_v2_totals());
    let held = bob.with_space(&space, |r| r.feed_len(&feed())).unwrap();
    eprintln!("slow catch-up: explicit {res:?}; bob holds {held}/{N} after {took:?}; alice {a:?}; bob {b:?}");
    assert_eq!(held, N as usize);
    assert!(took > Duration::from_secs(60), "the transfer must outlast a reply timeout to test anything");
    assert_eq!(a.failed + b.failed, 0, "no session failed");
    // Each item crossed about once (no parallel duplicate session).
    assert!(a.sent_bytes < 3 * N as u64 * 1_100 / 2, "{} bytes for {N} envelopes", a.sent_bytes);
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}
