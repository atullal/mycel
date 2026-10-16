//! Two nodes in one process, IP transports off, find each other through the
//! link's Bonjour service and sync a document both ways over its UDP flows.
//!
//! Needs a Mac with Bonjour (mDNSResponder) reachable, so it is `#[ignore]`d
//! by default:
//!
//! ```text
//! cargo test -p mycel-link-awdl -- --ignored
//! ```
#![cfg(target_os = "macos")]

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::{NetMode, Node, NodeOptions, PathKind};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn node(name: &str, any_interface: bool) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Lan, name);
    opts.ip = false;
    opts.links = vec![mycel_link_awdl::link_with(keys.sign_pk(), name, any_interface)];
    Node::spawn(keys, opts).await.unwrap()
}

async fn sync_both_ways(any_interface: bool) {
    let alice = node("alice", any_interface).await;
    let bob = node("bob", any_interface).await;
    eventually("both discover each other over the link", || {
        alice.peers().get(&bob.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))
            && bob.peers().get(&alice.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))
    })
    .await;
    assert_eq!(alice.peers()[&bob.id()].name.as_deref(), Some("bob"), "name from the TXT record");

    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();

    let doc = Replica::new_doc_id();
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "a", "from alice"))).unwrap().unwrap();
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"a": "from alice"}));

    bob.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "b", "from bob"))).unwrap().unwrap();
    alice.sync_with(bob.id(), space, false).await.unwrap();
    assert_eq!(alice.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"a": "from alice", "b": "from bob"}));
    assert_eq!(alice.peers()[&bob.id()].via, Some(PathKind::PeerWifi));
    assert!(alice.link_status()[0].active, "{:?}", alice.link_status());

    // bob leaves: alice's link reports him gone (service removed / flow silent)
    let bob_id = bob.id();
    bob.shutdown().await.unwrap();
    drop(bob);
    eventually("alice loses bob", || alice.peers().get(&bob_id).is_none_or(|p| !p.links.contains(&PathKind::PeerWifi)))
        .await;
    assert_eq!(alice.link_status()[0].peers, 0);
    alice.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Bonjour on a Mac"]
async fn bonjour_link_any_interface() {
    sync_both_ways(true).await;
}

/// AWDL-only mode on one Mac: Bonjour resolves the other service onto this
/// Mac's own awdl0 address, which still passes the peer-to-peer check.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Bonjour and Wi-Fi switched on"]
async fn bonjour_link_awdl_only() {
    sync_both_ways(false).await;
}
