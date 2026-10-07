//! Phase 0 end-to-end: real Iroh QUIC endpoints on localhost.

use std::sync::Arc;

use mycel_crypto::DeviceKeys;
use mycel_net::{NetMode, Node};
use mycel_sync::{Replica, Status, automerge::{ROOT, transaction::Transactable}};
use mycel_trust::Role;
use serde_json::json;

async fn node() -> Node {
    Node::spawn(Arc::new(DeviceKeys::generate()), NetMode::Local)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn phase0_end_to_end() {
    let (alice, bob, carol, keeper, eve) = (node().await, node().await, node().await, node().await, node().await);

    // Alice founds a space and invites everyone (invite = genesis + alice's address).
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
        n.sync_with(alice.addr(), space, true).await.unwrap();
        assert!(n.with_space(&space, |r| r.my_role().is_some()).unwrap());
    }

    // Bob writes and pushes to the keeper only.
    let doc = Replica::new_doc_id();
    bob.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "Mayor resigns")))
        .unwrap()
        .unwrap();
    bob.sync_with(keeper.addr(), space, false).await.unwrap();

    // Keeper holds it, validates it, but can't read it.
    keeper
        .with_space(&space, |r| {
            assert_eq!(r.opaque_count(), 1);
            assert_eq!(r.doc_json(&doc), serde_json::Value::Null);
        })
        .unwrap();

    // Carol (reader) gets it via the keeper, never talking to Bob.
    carol.sync_with(keeper.addr(), space, false).await.unwrap();
    assert_eq!(
        carol.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
        json!({"headline": "Mayor resigns"})
    );

    // Carol tries to write: rejected locally and by everyone she syncs with.
    let (_, env) = carol
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "FAKE")))
        .unwrap()
        .unwrap();
    let env_id = env.unwrap().id();
    carol.sync_with(keeper.addr(), space, false).await.unwrap();
    alice.sync_with(keeper.addr(), space, false).await.unwrap();
    alice
        .with_space(&space, |r| {
            assert!(matches!(r.status(&env_id), Status::Invalid(_)));
            assert_eq!(r.doc_json(&doc), json!({"headline": "Mayor resigns"}));
        })
        .unwrap();

    // Eve (not a member) is refused at the door.
    eve.join_space(genesis.clone()).unwrap();
    let err = eve.sync_with(alice.addr(), space, true).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");

    // Alice removes Bob and pushes to the keeper.
    alice
        .with_space(&space, |r| r.remove_member(bob.id()))
        .unwrap()
        .unwrap();
    alice
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "source", "confidential")))
        .unwrap()
        .unwrap();
    alice.sync_with(keeper.addr(), space, false).await.unwrap();

    // The keeper now refuses Bob.
    let err = bob.sync_with(keeper.addr(), space, false).await.unwrap_err();
    assert!(err.to_string().contains("denied"), "{err}");

    // Even if Bob gets the data some other way (a stale peer), he can't read the new epoch.
    let stale = alice.with_space(&space, |r| {
        let ops: Vec<_> = r.op_ids().iter().map(|i| r.op(i).unwrap().clone()).collect();
        let envs: Vec<_> = r.envelope_ids().iter().map(|i| r.envelope(i).unwrap().clone()).collect();
        (ops, envs)
    }).unwrap();
    bob.with_space(&space, |r| {
        for op in stale.0 { r.ingest_op(op).unwrap(); }
        for e in stale.1 { r.ingest_envelope(e).unwrap(); }
        assert_eq!(r.my_role(), None);
        assert_eq!(r.doc_json(&doc), json!({"headline": "Mayor resigns"}), "no 'source' for bob");
    }).unwrap();

    carol.sync_with(keeper.addr(), space, false).await.unwrap();
    assert_eq!(
        carol.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
        json!({"headline": "Mayor resigns", "source": "confidential"})
    );

    for n in [alice, bob, carol, keeper, eve] {
        n.shutdown().await.unwrap();
    }
}
