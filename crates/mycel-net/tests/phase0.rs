//! End-to-end tests: real Iroh QUIC endpoints on this machine.

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::{NetEvent, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica, Status, StreamId, StreamKind,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

async fn node_with(mode: NetMode, name: &str) -> Node {
    let mut opts = NodeOptions::new(mode, name);
    let dir = std::env::temp_dir().join(format!("mycel-test-blobs-{}", mycel_crypto::random_u64()));
    opts.blob_dir = Some(dir);
    Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap()
}

/// Local-mode nodes that all know each other's addresses.
async fn mesh(n: usize) -> Vec<Node> {
    let mut nodes = Vec::new();
    for i in 0..n {
        nodes.push(node_with(NetMode::Local, &format!("n{i}")).await);
    }
    for a in &nodes {
        for b in &nodes {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
    nodes
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn phase0_end_to_end() {
    let mut nodes = mesh(5).await;
    let eve = nodes.pop().unwrap();
    let keeper = nodes.pop().unwrap();
    let carol = nodes.pop().unwrap();
    let bob = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();

    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(bob.keys().public(), Role::Writer)?;
            r.add_member(carol.keys().public(), Role::Reader)?;
            r.add_member(keeper.keys().public(), Role::Relay)
        })
        .unwrap()
        .unwrap();
    for n in [&bob, &carol, &keeper] {
        n.join_space(genesis.clone()).unwrap();
        n.sync_with(alice.id(), space, true).await.unwrap();
        assert!(n.with_space(&space, |r| r.my_role().is_some()).unwrap());
    }

    let doc = Replica::new_doc_id();
    bob.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "Mayor resigns")))
        .unwrap()
        .unwrap();
    bob.sync_with(keeper.id(), space, false).await.unwrap();
    keeper
        .with_space(&space, |r| {
            assert_eq!(r.opaque_count(), 1);
            assert_eq!(r.doc_json(&doc), serde_json::Value::Null);
        })
        .unwrap();
    carol.sync_with(keeper.id(), space, false).await.unwrap();
    assert_eq!(
        carol.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
        json!({"headline": "Mayor resigns"})
    );

    let (_, env) = carol
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "FAKE")))
        .unwrap()
        .unwrap();
    let env_id = env.unwrap().id();
    carol.sync_with(keeper.id(), space, false).await.unwrap();
    alice.sync_with(keeper.id(), space, false).await.unwrap();
    alice
        .with_space(&space, |r| {
            assert!(matches!(r.status(&env_id), Status::Invalid(_)));
            assert_eq!(r.doc_json(&doc), json!({"headline": "Mayor resigns"}));
        })
        .unwrap();

    eve.join_space(genesis.clone()).unwrap();
    let err = eve.sync_with(alice.id(), space, true).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");

    alice.with_space(&space, |r| r.remove_member(bob.id())).unwrap().unwrap();
    alice
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "source", "confidential")))
        .unwrap()
        .unwrap();
    alice.sync_with(keeper.id(), space, false).await.unwrap();
    let err = bob.sync_with(keeper.id(), space, false).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");
    carol.sync_with(keeper.id(), space, false).await.unwrap();
    assert_eq!(
        carol.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
        json!({"headline": "Mayor resigns", "source": "confidential"})
    );

    for n in [alice, bob, carol, keeper, eve] {
        n.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_and_live_sync_without_manual_calls() {
    let mut nodes = mesh(3).await;
    let carol = nodes.pop().unwrap();
    let bob = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();
    let mut bob_events = bob.subscribe();

    let (space, _) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(bob.keys().public(), Role::Writer)?;
            r.add_member(carol.keys().public(), Role::Writer)
        })
        .unwrap()
        .unwrap();
    let feed = StreamId::named(StreamKind::Feed, "messages");
    alice
        .with_space(&space, |r| r.append(feed, b"welcome".to_vec()))
        .unwrap()
        .unwrap();
    alice.changed(space); // the scheduler pushes the space (invite) to bob & carol

    eventually("bob accepts invite", || bob.space_ids().contains(&space)).await;
    let added = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(NetEvent::SpaceAdded { space: s, from }) = bob_events.recv().await {
                return (s, from);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(added, (space, alice.id()));
    eventually("bob has welcome", || {
        bob.with_space(&space, |r| r.feed_len(&feed)).unwrap() == 1
    })
    .await;

    // Bob replies; carol gets it with no explicit sync calls.
    bob.with_space(&space, |r| r.append(feed, b"hi from bob".to_vec())).unwrap().unwrap();
    bob.changed(space);
    eventually("carol sees bob", || {
        carol.space_ids().contains(&space)
            && carol.with_space(&space, |r| r.feed_len(&feed)).unwrap() == 2
    })
    .await;
    // delivery tracking: bob learns that carol and alice hold his message
    let bob_msg = bob.with_space(&space, |r| r.feed(&feed)[1].id).unwrap();
    eventually("holders known", || {
        bob.with_space(&space, |r| r.holders(&bob_msg).len()).unwrap() == 2
    })
    .await;

    for n in [alice, bob, carol] {
        n.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_policy_can_refuse() {
    let mut nodes = Vec::new();
    for name in ["alice", "mallory-target"] {
        let mut opts = NodeOptions::new(NetMode::Local, name);
        if name != "alice" {
            opts.invite_policy = Arc::new(|_, _| false);
        }
        nodes.push(Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap());
    }
    let target = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();
    alice.add_peer_addr(target.addr());
    let (space, _) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| r.add_member(target.keys().public(), Role::Writer))
        .unwrap()
        .unwrap();
    let err = alice.sync_with(target.id(), space, false).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");
    assert!(target.space_ids().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn cards_ephemeral_and_blobs() {
    let mut nodes = mesh(3).await;
    let keeper = nodes.pop().unwrap();
    let bob = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();

    let card = alice.fetch_card(bob.id()).await.unwrap();
    assert_eq!(card.name, "n1");
    assert_eq!(card.keys, bob.keys().public());

    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(card.keys, Role::Writer)?;
            r.add_member(keeper.keys().public(), Role::Relay)
        })
        .unwrap()
        .unwrap();
    bob.join_space(genesis.clone()).unwrap();
    keeper.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    keeper.sync_with(alice.id(), space, true).await.unwrap();

    // typing indicator
    let mut ev = bob.subscribe();
    alice.send_ephemeral(space, b"typing".to_vec()).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(NetEvent::Ephemeral { from, data, .. }) = ev.recv().await {
                return (from, data);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got, (alice.id(), b"typing".to_vec()));

    // blob: alice uploads, it's pushed to bob and keeper; a fresh fetch works
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let hash = alice.put_blob(space, payload.clone()).await.unwrap();
    eventually("keeper stored blob", || keeper.blob_path(&space, &hash).is_some()).await;
    let path = bob.fetch_blob(space, hash).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), payload);

    for n in [alice, bob, keeper] {
        n.shutdown().await.unwrap();
    }
}

/// Real mDNS on this machine: no manual addresses, no relays, no internet.
#[tokio::test(flavor = "multi_thread")]
async fn lan_discovery_via_mdns() {
    let alice = node_with(NetMode::Lan, "alice-lan").await;
    let bob = node_with(NetMode::Lan, "bob-lan").await;
    eventually("alice sees bob nearby", || {
        alice.peers().get(&bob.id()).is_some_and(|p| p.nearby && p.name.as_deref() == Some("bob-lan"))
    })
    .await;
    let card = alice.fetch_card(bob.id()).await.unwrap();
    let (space, _) = alice.create_space().unwrap();
    let feed = StreamId::new_feed();
    alice
        .with_space(&space, |r| {
            r.add_member(card.keys, Role::Writer)?;
            r.append(feed, b"over the LAN".to_vec())
        })
        .unwrap()
        .unwrap();
    alice.changed(space);
    eventually("bob got message over LAN", || {
        bob.space_ids().contains(&space)
            && bob.with_space(&space, |r| r.feed_len(&feed)).unwrap() == 1
    })
    .await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// A device joining a space syncs first with whoever invited it, before it
/// knows from the space's history that they are a member. Their answer is
/// that whole history, and comes in however big (here 10 MiB): what we
/// asked a device for isn't held to the small budget of devices we share
/// no space with.
#[tokio::test(flavor = "multi_thread")]
async fn first_sync_with_an_inviter_brings_a_large_history() {
    let mut nodes = mesh(3).await;
    let bob = nodes.pop().unwrap();
    let carol = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();
    let (space, genesis) = alice.create_space().unwrap();
    let feed = StreamId::new_feed();
    alice
        .with_space(&space, |r| {
            r.add_member(carol.keys().public(), Role::Writer)?;
            r.add_member(bob.keys().public(), Role::Writer)?;
            for i in 0..160u8 {
                r.append(feed, vec![i; 64 * 1024])?;
            }
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();
    carol.join_space(genesis.clone()).unwrap();
    carol.sync_with(alice.id(), space, true).await.unwrap();
    alice.shutdown().await.unwrap();
    // Bob knows only the genesis: Carol isn't a member yet in his copy
    bob.join_space(genesis).unwrap();
    assert!(!bob.with_space(&space, |r| r.is_member(&carol.id())).unwrap());
    let stats = bob.sync_with(carol.id(), space, true).await.unwrap();
    assert_eq!(stats.envelopes, 160);
    carol.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// Ephemeral channels carry what apps share live: a typing flag, but also
/// cursors in a document or a game's state, kilobytes at a time. A device
/// set to take less drops bigger ones unread (and won't send them).
#[tokio::test(flavor = "multi_thread")]
async fn ephemeral_messages_carry_live_state() {
    let mut small = NodeOptions::new(NetMode::Local, "small");
    small.max_ephemeral = 1024;
    let carol = Node::spawn(Arc::new(DeviceKeys::generate()), small).await.unwrap();
    let mut nodes = mesh(2).await;
    let bob = nodes.pop().unwrap();
    let alice = nodes.pop().unwrap();
    for n in [&alice, &bob] {
        n.add_peer_addr(carol.addr());
        carol.add_peer_addr(n.addr());
    }
    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(bob.keys().public(), Role::Writer)?;
            r.add_member(carol.keys().public(), Role::Writer)
        })
        .unwrap()
        .unwrap();
    for n in [&bob, &carol] {
        n.join_space(genesis.clone()).unwrap();
        n.sync_with(alice.id(), space, true).await.unwrap();
    }
    let received = |node: &Node| {
        let mut events = node.subscribe();
        async move {
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(NetEvent::Ephemeral { data, .. }) = events.recv().await {
                        got.push(data.len());
                    }
                }
            })
            .await;
            got
        }
    };
    let (at_bob, at_carol) = (received(&bob), received(&carol));
    let state: Vec<u8> = (0..48 * 1024).map(|i| i as u8).collect();
    alice.send_ephemeral(space, state).unwrap();
    alice.send_ephemeral(space, vec![1; 512]).unwrap();
    let (at_bob, at_carol) = tokio::join!(at_bob, at_carol);
    assert_eq!(at_bob.iter().copied().collect::<std::collections::BTreeSet<_>>(), [512, 48 * 1024].into());
    assert_eq!(at_carol, vec![512], "carol drops what is bigger than she takes");
    assert!(carol.send_ephemeral(space, vec![0; 1025]).is_err());
    for n in [alice, bob, carol] {
        n.shutdown().await.unwrap();
    }
}
