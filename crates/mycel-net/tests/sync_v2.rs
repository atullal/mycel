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

/// A node with `sync_v2 = false` behaves exactly as a build before Sync v2:
/// the unknown stream kind is an error and both halves are dropped (the
/// opener sees the stream end with code 0), which is ambiguous (a failing
/// v2 server could cause it too), so the first time falls back for that
/// session only and the second in a row is remembered.
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
    let t = alice.sync_v2_totals();
    assert!(t.fallbacks >= 1, "the dropped stream fell back to v1: {t:?}");
    alice.with_space(&space, |r| r.append(feed(), b"again".to_vec())).unwrap().unwrap();
    alice.sync_with(old.id(), space, false).await.unwrap();
    assert_eq!(old.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 2);
    let t = alice.sync_v2_totals();
    assert_eq!(t.remembered_v1, 1, "remembered on the second ambiguous refusal: {t:?}");
    assert_eq!(t.client_sessions, 0, "no v2 session ran");
    alice.with_space(&space, |r| r.append(feed(), b"third".to_vec())).unwrap().unwrap();
    alice.sync_with(old.id(), space, false).await.unwrap();
    assert_eq!(old.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 3);
    assert_eq!(alice.sync_v2_totals().fallbacks, t.fallbacks, "remembered: v2 not tried again");
    // The old build syncs with v1 as a client, and a v2 node serves it.
    old.with_space(&space, |r| r.append(feed(), b"from old".to_vec())).unwrap().unwrap();
    old.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(alice.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 4);
    assert_eq!(old.sync_v2_totals().client_sessions, 0);
    alice.shutdown().await.unwrap();
    old.shutdown().await.unwrap();
}

/// A stream kind this build doesn't know (a newer build's) is reset at once
/// with `STREAM_REFUSED`, so the opener can fall back without a timeout.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_stream_kind_is_refused_at_once() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let conn = alice.connect(bob.id(), mycel_net::wire::ALPN).await.unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[0xEE, 0, 0, 0, 0]).await.unwrap();
    let mut buf = [0u8; 1];
    let t = Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(10), rx.read_exact(&mut buf)).await.unwrap().unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(5));
    let refused = mycel_net::iroh::endpoint::VarInt::from_u32(0x6d79_0001);
    match err {
        mycel_net::iroh::endpoint::ReadExactError::ReadError(mycel_net::iroh::endpoint::ReadError::Reset(c)) => {
            assert_eq!(c, refused)
        }
        other => panic!("expected a STREAM_REFUSED reset, got {other:?}"),
    }
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Review regression: when a background session crossed an explicit one,
/// `sync_with` returned "peer busy" and put a healthy peer into backoff.
/// Both sides now sync explicitly at the same moment, twenty times.
#[tokio::test(flavor = "multi_thread")]
async fn explicit_syncs_that_cross_both_succeed() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    for i in 0..20u32 {
        for n in [&alice, &bob] {
            n.with_space(&space, |r| r.append(feed(), i.to_le_bytes().to_vec())).unwrap().unwrap();
            n.changed(space);
        }
        let (a, b) = tokio::join!(alice.sync_with(bob.id(), space, false), bob.sync_with(alice.id(), space, false));
        a.unwrap();
        b.unwrap();
        // Each explicit session ran after the other ended: both hold both
        // sides' writes.
        let want = 2 * (i as usize + 1);
        assert_eq!(alice.with_space(&space, |r| r.feed_len(&feed())).unwrap(), want);
        assert_eq!(bob.with_space(&space, |r| r.feed_len(&feed())).unwrap(), want);
    }
    for (n, other) in [(&alice, &bob), (&bob, &alice)] {
        let p = n.peers().get(&other.id()).cloned().unwrap();
        assert_eq!(p.failures, 0, "Busy put a healthy peer into backoff");
    }
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Review regression: no test streamed both ways at once over real QUIC.
/// Each side holds more than a stream window (8 MiB) the other lacks, and
/// both sync explicitly at the same moment (plus their background pushes).
#[tokio::test(flavor = "multi_thread")]
async fn a_two_way_catch_up_streams_both_directions_at_once() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    const N: u32 = 10_000;
    for (tag, n) in [(0u8, &alice), (1u8, &bob)] {
        n.with_space(&space, |r| {
            for i in 0..N {
                let mut body = vec![tag; 1_000];
                body[..4].copy_from_slice(&i.to_le_bytes());
                r.append(feed(), body)?;
            }
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();
    }
    let payload = alice.with_space(&space, |r| r.stored_bytes()).unwrap();
    let (a0, b0) = (alice.sync_v2_totals(), bob.sync_v2_totals());
    let t = Instant::now();
    alice.changed(space);
    bob.changed(space);
    let (ra, rb) = tokio::join!(alice.sync_with(bob.id(), space, false), bob.sync_with(alice.id(), space, false));
    let took = t.elapsed();
    ra.unwrap();
    rb.unwrap();
    for n in [&alice, &bob] {
        assert_eq!(n.with_space(&space, |r| r.feed_len(&feed())).unwrap(), 2 * N as usize);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (a, b) = (alice.sync_v2_totals(), bob.sync_v2_totals());
    let (a_sent, b_sent) = (a.sent_bytes - a0.sent_bytes, b.sent_bytes - b0.sent_bytes);
    eprintln!(
        "two-way catch-up: {took:?}; payload {payload} B per side; alice sent {a_sent} B, bob sent {b_sent} B; \
         alice {a:?}; bob {b:?}"
    );
    assert_eq!(a.failed + b.failed, 0, "no session failed");
    for sent in [a_sent, b_sent] {
        assert!(sent as f64 <= 1.1 * payload as f64, "{sent} B sent for {payload} B of payload");
    }
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
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

/// Review regression: invites and `Removed` proofs carry the whole
/// membership history in one frame, and v2 capped it at a session frame
/// (1.1 MiB, v1: 64 MiB), so every invite into a churned group failed with
/// no fallback, and a removed member never learned it was removed. Here
/// 300 writers and 40 removals make about 1.4 MB of membership ops.
#[tokio::test(flavor = "multi_thread")]
async fn invites_and_removal_proofs_larger_than_a_session_frame() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, _genesis) = alice.create_space().unwrap();
    let others: Vec<DeviceKeys> = (0..300).map(|_| DeviceKeys::generate()).collect();
    alice
        .with_space(&space, |r| {
            for k in &others {
                r.add_member(k.public(), Role::Writer)?;
            }
            for k in &others[..40] {
                r.remove_member(k.sign_pk())?;
            }
            r.add_member(bob.keys().public(), Role::Writer)?;
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();
    let history: usize = alice
        .with_space(&space, |r| r.all_ops().iter().map(|o| postcard::to_allocvec(o).unwrap().len()).sum())
        .unwrap();
    assert!(history > 1_200_000, "{history} B of membership ops");
    // Bob doesn't hold the space: alice's session gets `NeedInvite` and
    // sends the invite.
    alice.sync_with(bob.id(), space, false).await.unwrap();
    assert!(bob.space_ids().contains(&space), "bob joined");
    assert_eq!(bob.with_space(&space, |r| r.my_role()).unwrap(), Some(Role::Writer));
    // Bob is removed; his next session is refused with the proof.
    alice.with_space(&space, |r| r.remove_member(bob.id())).unwrap().unwrap();
    let err = bob.sync_with(alice.id(), space, false).await.unwrap_err();
    assert!(err.to_string().contains("removed"), "{err}");
    assert_eq!(bob.with_space(&space, |r| r.my_role()).unwrap(), None, "bob learned it was removed");
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Review regression: a client that sends its frontier eagerly (a local
/// write since the last periodic round) to a device that lacks the space
/// sent the frontier's continuation chunks (more than 256 authors) before
/// reading `NeedInvite`, and the server took the next chunk for the new
/// `Open` and failed the session.
#[tokio::test(flavor = "multi_thread")]
async fn an_eager_frontier_over_many_authors_then_need_invite() {
    let alice = node("alice", true).await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    let authors: Vec<Arc<DeviceKeys>> = (0..300).map(|_| Arc::new(DeviceKeys::generate())).collect();
    let ops = alice
        .with_space(&space, |r| {
            for k in &authors {
                r.add_member(k.public(), Role::Writer)?;
            }
            anyhow::Ok(r.all_ops())
        })
        .unwrap()
        .unwrap();
    let mut envelopes = Vec::new();
    for k in &authors {
        let mut r = mycel_sync::Replica::join(k.clone(), genesis.clone(), None).unwrap();
        r.ingest_batch(ops.clone(), vec![]);
        envelopes.push(r.append(feed(), b"hello".to_vec()).unwrap().1);
    }
    let held = alice.with_space(&space, |r| r.ingest_batch(vec![], envelopes).envelopes).unwrap();
    assert_eq!(held, 300);
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    alice.changed(space);
    alice.sync_with(bob.id(), space, false).await.unwrap();
    assert!(bob.space_ids().contains(&space), "bob joined");
    eventually("bob holds every author's envelope", || bob.with_space(&space, |r| r.feed_len(&feed())).unwrap() == 300)
        .await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}
