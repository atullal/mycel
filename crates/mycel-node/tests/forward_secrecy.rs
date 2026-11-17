//! Reader keys and the stored keyring through the whole runtime (TRUST.md
//! §6): real storage, real QUIC.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_node::api::NetworkMode;
use mycel_node::crypto::{DeviceKeys, SignPk};
use mycel_node::store::DbStore;
use mycel_node::sync::Replica;
use mycel_node::trust::{Action, SpaceId};
use mycel_node::{Runtime, RuntimeOptions};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mycel-fs-{name}-{}", mycel_node::crypto::random_u64()))
}

async fn open(dir: &std::path::Path, name: &str, keeper: bool) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.to_path_buf(),
        mode: NetworkMode::Local,
        name: Some(name.into()),
        default_name: None,
        keeper,
        port: 0,
    })
    .await
    .unwrap()
}

fn connect_all(rts: &[&Arc<Runtime>]) {
    for a in rts {
        for b in rts {
            if a.profile().id != b.profile().id {
                a.node().add_peer_addr(b.node().addr());
            }
        }
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn space_of(id: &str) -> SpaceId {
    let bytes: Vec<u8> = (0..id.len()).step_by(2).map(|i| u8::from_str_radix(&id[i..i + 2], 16).unwrap()).collect();
    mycel_node::crypto::Hash32(bytes.try_into().unwrap())
}

fn pk_of(rt: &Runtime) -> SignPk {
    rt.node().id()
}

/// Has `who` a reader key in `space`, as `rt` sees the graph?
fn has_reader_key(rt: &Runtime, space: &SpaceId, who: &SignPk) -> bool {
    rt.node()
        .with_space(space, |r| r.graph().state().members.get(who).is_some_and(|m| m.reader.is_some()))
        .unwrap_or(false)
}

/// Ops in `space` authored by `who`, as `rt` sees the graph.
fn ops_by(rt: &Runtime, space: &SpaceId, who: &SignPk) -> usize {
    rt.node().with_space(space, |r| r.all_ops().iter().filter(|o| o.op.author == *who).count()).unwrap_or(0)
}

fn texts(rt: &Runtime, conv: &str) -> Vec<String> {
    rt.messages(conv.to_string(), None, None).unwrap().into_iter().map(|m| m.body).collect()
}

/// The founder publishes a reader key when it makes the conversation, the
/// other side when it accepts it: not before. A request nobody answered
/// gets nothing signed back from this device.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_gets_no_reader_key_until_it_is_accepted() {
    let alice = open(&tmp("req-a"), "Alice", false).await;
    let bob = open(&tmp("req-b"), "Bob", false).await;
    connect_all(&[&alice, &bob]);
    // Bob doesn't know Alice: her conversation is a request
    let b = alice.add_contact(bob.profile().contact_code_full).unwrap();
    let conv = alice.create_conversation(None, vec![b.id]).unwrap();
    alice.send_message(conv.id.clone(), "hello?".into(), None, vec![]).await.unwrap();
    let space = space_of(&conv.id);
    let (a_pk, b_pk) = (pk_of(&alice), pk_of(&bob));
    assert!(has_reader_key(&alice, &space, &a_pk), "the founder's, from the start");
    eventually("bob has the request", || bob.conversations().iter().any(|c| c.id == conv.id && c.request)).await;
    // give anything Bob's device might say time to arrive: nothing does
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(ops_by(&bob, &space, &b_pk), 0, "an unanswered request gets nothing signed");
    assert_eq!(ops_by(&alice, &space, &b_pk), 0);
    assert!(!has_reader_key(&alice, &space, &b_pk));

    bob.accept_request(conv.id.clone()).unwrap();
    eventually("bob's reader key reached alice", || has_reader_key(&alice, &space, &b_pk)).await;
    assert!(has_reader_key(&bob, &space, &b_pk));
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// A contact's conversation is taken part in at once: the reader key goes
/// out on arrival.
#[tokio::test(flavor = "multi_thread")]
async fn a_contacts_conversation_gets_a_reader_key_on_arrival() {
    let alice = open(&tmp("con-a"), "Alice", false).await;
    let bob = open(&tmp("con-b"), "Bob", false).await;
    connect_all(&[&alice, &bob]);
    bob.add_contact(alice.profile().contact_code_full).unwrap();
    let b = alice.add_contact(bob.profile().contact_code_full).unwrap();
    let conv = alice.create_conversation(None, vec![b.id]).unwrap();
    let space = space_of(&conv.id);
    eventually("bob's reader key reached alice", || has_reader_key(&alice, &space, &pk_of(&bob))).await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// The keyring and the reader keys survive a restart (they are no longer
/// re-derived from the device key), sealed: the database holds them under
/// a key derived from the identity, so the same database is useless to
/// another identity.
#[tokio::test(flavor = "multi_thread")]
async fn the_keyring_survives_a_restart_and_is_sealed_to_the_identity() {
    let (da, db) = (tmp("rs-a"), tmp("rs-b"));
    let alice = open(&da, "Alice", false).await;
    let bob = open(&db, "Bob", false).await;
    connect_all(&[&alice, &bob]);
    bob.add_contact(alice.profile().contact_code_full).unwrap();
    let b = alice.add_contact(bob.profile().contact_code_full).unwrap();
    let conv = alice.create_conversation(None, vec![b.id]).unwrap();
    let space = space_of(&conv.id);
    let b_pk = pk_of(&bob);
    eventually("bob's reader key reached alice", || has_reader_key(&alice, &space, &b_pk)).await;
    // Two days on by Alice's clock, her next write rotates: an epoch sealed
    // to both reader keys, which the device keys alone don't open.
    let first_epoch = alice.node().with_space(&space, |r| r.graph().state().write_epoch()).unwrap();
    alice
        .node()
        .with_space(&space, |r| {
            r.set_key_clock(Arc::new(|| {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
                now.as_secs() + 2 * 24 * 3600
            }))
        })
        .unwrap();
    alice.send_message(conv.id.clone(), "one".into(), None, vec![]).await.unwrap();
    let epoch = alice.node().with_space(&space, |r| r.graph().state().write_epoch()).unwrap();
    assert_ne!(epoch, first_epoch, "a timed rotation");
    eventually("bob reads it", || texts(&bob, &conv.id).contains(&"one".to_string())).await;
    assert_eq!(bob.node().with_space(&space, |r| r.reader_keys_held()).unwrap(), 1);
    let bobs_ops = ops_by(&bob, &space, &b_pk);
    bob.shutdown().await.unwrap();
    drop(bob);

    // what Bob's database holds for the space: a sealed record
    let store = DbStore::open(db.join("mycel.redb")).unwrap();
    let sealed = store.space_secrets(&space).unwrap().expect("the space's secrets are stored");
    let (spaces, _) = store.load_spaces().unwrap();
    let (ops, envs) = spaces.get(&space).cloned().unwrap();
    store.close().unwrap();
    drop(store);
    let genesis = ops.iter().find(|o| o.id() == space).cloned().unwrap();
    let rest: Vec<_> = ops.into_iter().filter(|o| o.id() != space).collect();
    assert!(rest.iter().any(|o| o.op.author == b_pk && matches!(o.op.action, Action::ReaderKey { .. })));
    // another identity with Bob's whole database gets no reader key out of it
    let stranger = Arc::new(DeviceKeys::generate());
    let other =
        Replica::restore_with_secrets(stranger, genesis.clone(), rest.clone(), envs.clone(), Some(&sealed), None)
            .unwrap();
    assert_eq!(other.reader_keys_held(), 0);
    // and Bob's identity without that record can't open the rotated epoch:
    // its lockbox was sealed to the reader key, not to the device key
    let bob_keys = Arc::new(DeviceKeys::from_seed(std::fs::read(db.join("identity.key")).unwrap().try_into().unwrap()));
    assert_eq!(bob_keys.sign_pk(), b_pk);
    let bare = Replica::restore_with_secrets(bob_keys, genesis, rest, envs, None, None).unwrap();
    assert!(bare.opaque_count() >= 1, "the message under the rotated epoch stays closed");

    // Bob again: everything is there, and he keeps the same reader key
    let bob = open(&db, "Bob", false).await;
    assert!(texts(&bob, &conv.id).contains(&"one".to_string()));
    assert_eq!(bob.node().with_space(&space, |r| r.reader_keys_held()).unwrap(), 1);
    assert_eq!(ops_by(&bob, &space, &b_pk), bobs_ops, "no new reader key at restart");
    connect_all(&[&alice, &bob]);
    alice.send_message(conv.id.clone(), "two".into(), None, vec![]).await.unwrap();
    eventually("bob reads on", || texts(&bob, &conv.id).contains(&"two".to_string())).await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// A keeper stores a conversation it can't read, with the reader keys in
/// it like any other op, and serves it to a member that was away.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_carries_reader_keys_it_has_no_use_for() {
    let alice = open(&tmp("kp-a"), "Alice", false).await;
    let bob_dir = tmp("kp-b");
    let bob = open(&bob_dir, "Bob", false).await;
    let keeper = open(&tmp("kp-k"), "Keeper", true).await;
    connect_all(&[&alice, &bob, &keeper]);
    bob.add_contact(alice.profile().contact_code_full).unwrap();
    let b = alice.add_contact(bob.profile().contact_code_full).unwrap();
    let k = alice.add_contact(keeper.profile().contact_code_full).unwrap();
    let conv = alice.create_conversation(None, vec![b.id]).unwrap();
    let space = space_of(&conv.id);
    let (b_pk, k_pk) = (pk_of(&bob), pk_of(&keeper));
    alice.add_keeper(conv.id.clone(), k.id).unwrap();
    eventually("bob's reader key reached the keeper", || has_reader_key(&keeper, &space, &b_pk)).await;
    assert_eq!(ops_by(&keeper, &space, &k_pk), 0, "a keeper publishes none");
    assert!(!has_reader_key(&alice, &space, &k_pk));
    // Bob goes away; Alice writes; Alice goes away; Bob gets it from the keeper
    bob.shutdown().await.unwrap();
    drop(bob);
    let held = |rt: &Runtime| rt.node().with_space(&space, |r| r.envelope_ids().len()).unwrap_or(0);
    eventually("the keeper has caught up with alice", || held(&keeper) == held(&alice)).await;
    alice.send_message(conv.id.clone(), "for later".into(), None, vec![]).await.unwrap();
    eventually("the keeper holds it", || held(&keeper) == held(&alice)).await;
    assert_eq!(keeper.node().with_space(&space, |r| r.opaque_count()).unwrap(), held(&keeper), "and reads none of it");
    alice.shutdown().await.unwrap();
    drop(alice);
    let bob = open(&bob_dir, "Bob", false).await;
    connect_all(&[&bob, &keeper]);
    eventually("bob reads it from the keeper", || texts(&bob, &conv.id).contains(&"for later".to_string())).await;
    bob.shutdown().await.unwrap();
    keeper.shutdown().await.unwrap();
}
