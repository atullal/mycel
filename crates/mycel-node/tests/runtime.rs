//! Runtime end-to-end: real storage, real QUIC, the full messaging API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_node::api::{Delivery, Event, NetworkMode};
use mycel_node::{Runtime, RuntimeOptions};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mycel-rt-{name}-{}", mycel_node::crypto::random_u64()))
}

async fn open(dir: &PathBuf, name: &str, port: u16, keeper: bool) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.clone(),
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
    let bconv = bob.conversation(conv.id.clone()).unwrap();
    assert_eq!(bconv.title, "Alice", "bob learns alice's name via Profile");
    assert_eq!(bconv.unread, 1);
    // alice was auto-added to bob's contacts
    eventually("contact auto-added", || bob.contacts().iter().any(|c| c.name == "Alice")).await;

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
    assert!(bob.rename_conversation(conv.id.clone(), "mine".into()).is_err(), "not admin");

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
