//! Runtime end-to-end: real storage, real QUIC, the full messaging API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_node::api::{Delivery, Event, NetworkMode};
use mycel_node::{Runtime, RuntimeOptions};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mycel-rt-{name}-{}", mycel_node::crypto::random_u64()))
}

async fn open(dir: &std::path::Path, name: &str, port: u16, keeper: bool) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.to_path_buf(),
        mode: NetworkMode::Local,
        name: Some(name.into()),
        keeper,
        port,
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

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn messaging_end_to_end() {
    let (da, db) = (tmp("alice"), tmp("bob"));
    let (pa, pb) = (free_port(), free_port());
    let alice = open(&da, "Alice", pa, false).await;
    let mut bob = open(&db, "Bob", pb, false).await;
    connect_all(&[&alice, &bob]);
    let mut bob_events = bob.subscribe();

    // exchange contact codes
    let bob_contact = alice.add_contact(bob.profile().contact_code).unwrap();
    assert_eq!(bob_contact.name, "Bob");
    assert!(alice.add_contact("garbage".into()).is_err());

    // DM
    let conv = alice.create_conversation(None, vec![bob_contact.id.clone()]).unwrap();
    assert!(conv.direct);
    assert_eq!(conv.title, "Bob");
    let m1 = alice.send_message(conv.id.clone(), "hi bob 👋".into(), None, vec![]).await.unwrap();
    assert!(m1.is_mine);

    eventually("bob gets the conversation", || bob.conversations().len() == 1).await;
    let added = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Event::ConversationAdded { conversation }) = bob_events.recv().await {
                return conversation;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(added, conv.id);
    eventually("bob sees message", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "hi bob 👋")
    })
    .await;
    // Alice isn't Bob's contact: it arrives as a message request.
    let bconv = bob.conversation(conv.id.clone()).unwrap();
    assert!(bconv.request);
    assert_eq!(bconv.invited_by.as_deref(), Some(alice.profile().id.as_str()));
    assert!(bob.contacts().is_empty(), "strangers are not auto-added");
    assert!(bob.send_message(conv.id.clone(), "x".into(), None, vec![]).await.is_err());
    let bconv = bob.accept_request(conv.id.clone()).unwrap();
    assert!(!bconv.request);
    assert_eq!(bconv.title, "Alice", "bob learns alice's name via Profile");
    assert_eq!(bconv.unread, 1);
    assert!(bob.contacts().iter().any(|c| c.name == "Alice"), "accepted → contact");

    // delivery → read
    eventually("delivered", || {
        alice.messages(conv.id.clone(), None, None).unwrap().last().unwrap().delivery >= Delivery::Delivered
    })
    .await;
    bob.mark_read(conv.id.clone()).unwrap();
    assert_eq!(bob.conversation(conv.id.clone()).unwrap().unread, 0);
    eventually("read", || {
        let msgs = alice.messages(conv.id.clone(), None, None).unwrap();
        msgs.iter().find(|m| m.id == m1.id).unwrap().delivery == Delivery::Read
    })
    .await;

    // reply, react, edit, delete
    let r = bob
        .send_message(conv.id.clone(), "hey alice".into(), Some(m1.id.clone()), vec![])
        .await
        .unwrap();
    assert_eq!(r.reply_to.as_deref(), Some(m1.id.as_str()));
    bob.toggle_reaction(conv.id.clone(), m1.id.clone(), "❤️".into()).unwrap();
    alice.edit_message(conv.id.clone(), m1.id.clone(), "hi bob! (edited)".into()).unwrap();
    assert!(bob.edit_message(conv.id.clone(), m1.id.clone(), "nope".into()).is_err());
    eventually("alice sees reply + reaction; bob sees edit", || {
        let am = alice.messages(conv.id.clone(), None, None).unwrap();
        let bm = bob.messages(conv.id.clone(), None, None).unwrap();
        am.len() == 2
            && am[0].reactions.iter().any(|r| r.emoji == "❤️")
            && bm[0].body == "hi bob! (edited)"
            && bm[0].edited
    })
    .await;
    bob.delete_message(conv.id.clone(), r.id.clone()).unwrap();
    eventually("delete propagates", || {
        alice.messages(conv.id.clone(), None, None).unwrap()[1].deleted
    })
    .await;

    // attachment
    let file = tmp("photo").with_extension("png");
    let content: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 256) as u8).collect();
    std::fs::write(&file, &content).unwrap();
    let sent = alice
        .send_message(conv.id.clone(), "pic".into(), None, vec![file.to_string_lossy().into()])
        .await
        .unwrap();
    assert_eq!(sent.attachments[0].mime, "image/png");
    assert!(sent.attachments[0].local_path.is_some());
    let blob = sent.attachments[0].blob.clone();
    eventually("bob sees attachment msg", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "pic")
    })
    .await;
    let path = bob.fetch_attachment(blob).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);

    // restart bob: everything persists
    let bob_id = bob.profile().id.clone();
    bob.shutdown().await.unwrap();
    drop(bob);
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob = open(&db, "Bob", pb, false).await;
    assert_eq!(bob.profile().id, bob_id, "same identity after restart");
    connect_all(&[&alice, &bob]);
    let msgs = bob.messages(conv.id.clone(), None, None).unwrap();
    assert_eq!(msgs.len(), 3);
    assert!(msgs[0].body.contains("edited"));
    assert!(bob.contacts().iter().any(|c| c.name == "Alice"));
    bob.send_message(conv.id.clone(), "back after restart".into(), None, vec![]).await.unwrap();
    eventually("alice gets post-restart message", || {
        alice.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "back after restart")
    })
    .await;

    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keeper_delivers_while_sender_is_offline() {
    let (da, db, dk) = (tmp("alice"), tmp("bob"), tmp("keeper"));
    let (pa, pb, pk) = (free_port(), free_port(), free_port());
    let alice = open(&da, "Alice", pa, false).await;
    let bob = open(&db, "Bob", pb, false).await;
    let keeper = open(&dk, "Keeper", pk, true).await;
    connect_all(&[&alice, &bob, &keeper]);

    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    let k = alice.add_contact(keeper.profile().contact_code).unwrap();
    let conv = alice.create_conversation(Some("Team".into()), vec![b.id.clone()]).unwrap();
    alice.add_keeper(conv.id.clone(), k.id.clone()).unwrap();
    eventually("bob joined", || bob.conversations().len() == 1).await;
    bob.accept_request(conv.id.clone()).unwrap();
    eventually("keeper joined", || keeper.node().space_ids().len() == 1).await;
    assert!(keeper.conversations().is_empty(), "keeper never shows conversations");

    // Bob goes offline. Alice writes, syncs to the keeper, then goes offline too.
    bob.shutdown().await.unwrap();
    drop(bob);
    alice.send_message(conv.id.clone(), "sent while you were away".into(), None, vec![]).await.unwrap();
    let space = keeper.node().space_ids()[0];
    eventually("keeper holds it (but can't read it)", || {
        keeper.node().with_space(&space, |r| r.opaque_count()).unwrap() >= 3
    })
    .await;
    alice.shutdown().await.unwrap();
    drop(alice);

    // Bob comes back: only the keeper is online.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bob = open(&db, "Bob", pb, false).await;
    connect_all(&[&bob, &keeper]);
    eventually("bob gets the message from the keeper", || {
        bob.messages(conv.id.clone(), None, None)
            .unwrap()
            .iter()
            .any(|m| m.body == "sent while you were away")
    })
    .await;
    bob.shutdown().await.unwrap();
    keeper.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn group_admin_removes_member() {
    let dirs: Vec<PathBuf> = ["a", "b", "c"].iter().map(|n| tmp(n)).collect();
    let alice = open(&dirs[0], "Alice", free_port(), false).await;
    let bob = open(&dirs[1], "Bob", free_port(), false).await;
    let carol = open(&dirs[2], "Carol", free_port(), false).await;
    connect_all(&[&alice, &bob, &carol]);
    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    let c = alice.add_contact(carol.profile().contact_code).unwrap();
    let conv = alice.create_conversation(Some("Trio".into()), vec![b.id.clone(), c.id.clone()]).unwrap();
    eventually("all joined", || bob.conversations().len() == 1 && carol.conversations().len() == 1).await;
    bob.accept_request(conv.id.clone()).unwrap();
    carol.accept_request(conv.id.clone()).unwrap();
    assert!(bob.rename_conversation(conv.id.clone(), "mine".into()).is_err(), "not admin");

    // L4: Bob (not admin) bypasses the API and appends a forged Meta op.
    // Every peer's WASM chat rules reject it; the title is unchanged.
    let space = alice.node().space_ids()[0];
    let forged = mycel_node::chat::ChatOp::Meta { title: Some("pwned".into()), direct: false };
    bob.node()
        .with_space(&space, |r| r.append(mycel_node::chat::messages_feed(), forged.encode()))
        .unwrap()
        .unwrap();
    bob.node().changed(space);
    eventually("alice's rules reject bob's forged op", || {
        alice.node().with_space(&space, |r| r.rule_rejected()).unwrap() == 1
    })
    .await;
    assert_eq!(alice.conversation(conv.id.clone()).unwrap().title, "Trio");
    assert_eq!(bob.node().with_space(&space, |r| r.rule_rejected()).unwrap(), 1);

    alice.remove_member(conv.id.clone(), c.id.clone()).unwrap();
    eventually("carol learns she was removed", || {
        !carol.conversation(conv.id.clone()).unwrap().active
    })
    .await;
    alice.send_message(conv.id.clone(), "carol can't see this".into(), None, vec![]).await.unwrap();
    eventually("bob sees it", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "carol can't see this")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!carol
        .messages(conv.id.clone(), None, None)
        .unwrap()
        .iter()
        .any(|m| m.body == "carol can't see this"));
    assert!(carol.send_message(conv.id.clone(), "hello?".into(), None, vec![]).await.is_err());
    for r in [alice, bob, carol] {
        r.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn declined_and_blocked_strangers_stay_out() {
    let (dm, dv) = (tmp("mallory"), tmp("victim"));
    let mallory = open(&dm, "Mallory", free_port(), false).await;
    let victim = open(&dv, "Victim", free_port(), false).await;
    connect_all(&[&mallory, &victim]);
    // Mallory only needs the victim's public card (e.g. from the LAN).
    let v = mallory.add_contact(victim.profile().contact_code).unwrap();
    let c1 = mallory.create_conversation(None, vec![v.id.clone()]).unwrap();
    mallory.send_message(c1.id.clone(), "click my file".into(), None, vec![]).await.unwrap();
    eventually("request arrives", || victim.conversations().iter().any(|c| c.request)).await;
    assert!(victim.contacts().is_empty());
    victim.decline_request(c1.id.clone(), true).unwrap();
    assert!(victim.conversations().is_empty(), "declined conversations are hidden");
    // A new attempt from the blocked key is refused at the network layer.
    let c2 = mallory.create_conversation(Some("again".into()), vec![v.id.clone()]).unwrap();
    let _ = mallory.node().sync_with(
        mycel_node::crypto::SignPk(<[u8; 32]>::try_from(hex_decode(&v.id)).unwrap()),
        hash_of(&c2.id),
        false,
    ).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(victim.conversations().is_empty());
    assert!(!victim.node().space_ids().contains(&hash_of(&c2.id)));
    mallory.shutdown().await.unwrap();
    victim.shutdown().await.unwrap();
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hash_of(s: &str) -> mycel_node::crypto::Hash32 {
    mycel_node::crypto::Hash32(<[u8; 32]>::try_from(hex_decode(s)).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn contact_code_address_hints_connect_without_discovery() {
    // Local mode: no mDNS, and we deliberately don't call connect_all.
    let alice = open(&tmp("ha"), "Alice", free_port(), false).await;
    let bob = open(&tmp("hb"), "Bob", free_port(), false).await;
    let code = bob.profile().contact_code;
    assert!(code.contains('@'), "code carries address hints: {code}");
    let b = alice.add_contact(code).unwrap();
    let conv = alice.create_conversation(None, vec![b.id.clone()]).unwrap();
    alice.send_message(conv.id.clone(), "found you by code".into(), None, vec![]).await.unwrap();
    eventually("bob reached via hints only", || {
        bob.conversations().iter().any(|c| c.id == conv.id)
    })
    .await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}
