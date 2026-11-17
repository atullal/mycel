//! Contact codes end to end: the short code (the device key; its lockbox key
//! is fetched from the device) and the full code (everything in it).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_node::api::NetworkMode;
use mycel_node::{ContactCode, Runtime, RuntimeOptions, parse_contact_code};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mycel-codes-{name}-{}", mycel_node::crypto::random_u64()))
}

async fn open(dir: &std::path::Path, name: &str) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.to_path_buf(),
        mode: NetworkMode::Local,
        name: Some(name.into()),
        default_name: None,
        keeper: false,
        port: 0,
    })
    .await
    .unwrap()
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

/// The code a profile shows is the short one: small enough for a QR code,
/// with no lockbox key in it. The full one holds the card.
#[tokio::test(flavor = "multi_thread")]
async fn a_profile_has_a_short_code_and_a_full_one() {
    let bob = open(&tmp("forms"), "Bob").await;
    let p = bob.profile();
    assert!(p.contact_code.len() < 300, "{} characters: {}", p.contact_code.len(), p.contact_code);
    assert!(p.contact_code_full.len() > 1_600, "{} characters", p.contact_code_full.len());
    let (short, short_hints) = parse_contact_code(&p.contact_code).unwrap();
    let (full, full_hints) = parse_contact_code(&p.contact_code_full).unwrap();
    assert!(matches!(short, ContactCode::Short(_)));
    assert!(matches!(full, ContactCode::Full(_)));
    assert_eq!(short.sign_pk(), full.sign_pk());
    assert_eq!((short.name(), full.name()), ("Bob", "Bob"));
    assert!(!short_hints.is_empty() && short_hints == full_hints, "both carry the address hints");
    bob.shutdown().await.unwrap();
}

/// Added from a short code, a contact is awaited until its device is
/// reached: then its signed card arrives, and it can be put in a
/// conversation. Nothing is sealed to it before.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_code_contact_gets_its_keys_from_the_device() {
    let alice = open(&tmp("sa"), "Alice").await;
    let bob = open(&tmp("sb"), "Bob").await;
    // Local mode: no discovery. The code's address hints are all Alice has.
    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    assert_eq!(b.name, "Bob");
    eventually("bob's card fetched", || alice.contacts().iter().any(|c| c.id == b.id && !c.awaiting_keys)).await;
    let conv = alice.create_conversation(None, vec![b.id.clone()]).unwrap();
    alice.send_message(conv.id.clone(), "found you by a short code".into(), None, vec![]).await.unwrap();
    eventually("bob has the conversation", || bob.conversations().iter().any(|c| c.id == conv.id)).await;
    bob.accept_request(conv.id.clone()).unwrap();
    eventually("bob reads it", || {
        bob.messages(conv.id.clone(), None, None).is_ok_and(|m| m.iter().any(|m| m.body == "found you by a short code"))
    })
    .await;
    // adding the same code again changes nothing
    let again = alice.add_contact(bob.profile().contact_code).unwrap();
    assert!(!again.awaiting_keys);
    assert_eq!(alice.contacts().len(), 1);
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// While the device can't be reached the contact is listed, counts as a
/// contact, and can't be put in a conversation; it survives a restart, and
/// the keys arrive once the device is up.
#[tokio::test(flavor = "multi_thread")]
async fn an_awaited_contact_waits_for_the_device_across_a_restart() {
    let (da, db) = (tmp("wa"), tmp("wb"));
    let bob = open(&db, "Bob").await;
    let code = bob.profile().contact_code;
    let bob_id = bob.profile().id;
    bob.shutdown().await.unwrap();
    drop(bob);

    let alice = open(&da, "Alice").await;
    let b = alice.add_contact(code).unwrap();
    assert!(b.awaiting_keys);
    assert_eq!((b.id.as_str(), b.name.as_str()), (bob_id.as_str(), "Bob"));
    let err = alice.create_conversation(None, vec![b.id.clone()]).unwrap_err();
    assert!(format!("{err:#}").contains("hasn't reached Bob's device"), "{err:#}");
    assert!(alice.conversations().is_empty(), "nothing was created");
    alice.shutdown().await.unwrap();
    drop(alice);

    let alice = open(&da, "Alice").await;
    let listed = alice.contacts();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].awaiting_keys && listed[0].name == "Bob", "{listed:?}");
    // Bob's device comes up, somewhere else: Alice learns where.
    let bob = open(&db, "Bob").await;
    alice.node().add_peer_addr(bob.node().addr());
    eventually("bob's card fetched after the restart", || alice.contacts().iter().any(|c| !c.awaiting_keys)).await;
    alice.create_conversation(None, vec![b.id.clone()]).unwrap();
    // and it is a contact with keys after another restart
    alice.shutdown().await.unwrap();
    drop(alice);
    let alice = open(&da, "Alice").await;
    assert!(alice.contacts().iter().any(|c| c.id == b.id && !c.awaiting_keys));
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

/// The full code needs no connection: the contact has its keys at once,
/// with the device switched off.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_code_needs_no_connection() {
    let bob = open(&tmp("fb"), "Bob").await;
    let code = bob.profile().contact_code_full;
    bob.shutdown().await.unwrap();
    drop(bob);
    let alice = open(&tmp("fa"), "Alice").await;
    let b = alice.add_contact(code).unwrap();
    assert!(!b.awaiting_keys);
    alice.create_conversation(None, vec![b.id]).unwrap();
    alice.shutdown().await.unwrap();
}

/// A contact still awaited who writes first isn't a stranger: its
/// conversation arrives as a conversation, not as a request, and its keys
/// come with it (they are in the conversation's signed membership).
#[tokio::test(flavor = "multi_thread")]
async fn an_awaited_contact_who_writes_first_is_a_contact() {
    let alice = open(&tmp("ia"), "Alice").await;
    let bob = open(&tmp("ib"), "Bob").await;
    // Alice knows Bob by a short code with no usable address: awaited.
    let short = bob.profile().contact_code;
    let without_hints = short.split('@').next().unwrap().to_string();
    let b = alice.add_contact(without_hints).unwrap();
    assert!(b.awaiting_keys);
    // Bob knows Alice in full, and where she is.
    let a = bob.add_contact(alice.profile().contact_code_full).unwrap();
    let conv = bob.create_conversation(None, vec![a.id]).unwrap();
    bob.send_message(conv.id.clone(), "me first".into(), None, vec![]).await.unwrap();
    eventually("alice has it as a conversation", || {
        alice.conversations().iter().any(|c| c.id == conv.id && !c.request)
    })
    .await;
    eventually("and bob's keys with it", || alice.contacts().iter().any(|c| c.id == b.id && !c.awaiting_keys)).await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_an_awaited_contact_forgets_it() {
    let bob = open(&tmp("rb"), "Bob").await;
    let code = bob.profile().contact_code;
    bob.shutdown().await.unwrap();
    drop(bob);
    let dir = tmp("ra");
    let alice = open(&dir, "Alice").await;
    let b = alice.add_contact(code).unwrap();
    alice.remove_contact(b.id).unwrap();
    assert!(alice.contacts().is_empty());
    // your own code, in either form, is refused
    assert!(alice.add_contact(alice.profile().contact_code).is_err());
    assert!(alice.add_contact(alice.profile().contact_code_full).is_err());
    alice.shutdown().await.unwrap();
    drop(alice);
    let alice = open(&dir, "Alice").await;
    assert!(alice.contacts().is_empty());
    alice.shutdown().await.unwrap();
}
