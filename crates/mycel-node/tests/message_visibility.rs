//! Per-device deletion survives restarts without changing other peers' history.
use mycel_node::{Runtime, RuntimeOptions, api::NetworkMode};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "mycel-visibility-{name}-{}",
        mycel_node::crypto::random_u64()
    ))
}
async fn open(dir: &Path, name: &str) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.into(),
        mode: NetworkMode::Local,
        name: Some(name.into()),
        default_name: None,
        keeper: false,
        port: 0,
    })
    .await
    .unwrap()
}
fn connect(peers: &[&Arc<Runtime>]) {
    for a in peers {
        for b in peers {
            if a.profile().id != b.profile().id {
                a.node().add_peer_addr(b.node().addr());
            }
        }
    }
}
async fn eventually(mut ready: impl FnMut() -> bool) {
    for _ in 0..300 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("message visibility did not converge");
}

#[tokio::test(flavor = "multi_thread")]
async fn local_deletion_persists_and_author_deletion_clears_all_content_on_three_peers() {
    let (da, db, dc) = (tmp("alice"), tmp("bob"), tmp("carol"));
    let alice = open(&da, "Alice").await;
    let mut bob = open(&db, "Bob").await;
    let carol = open(&dc, "Carol").await;
    connect(&[&alice, &bob, &carol]);
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.profile().id != b.profile().id {
                a.add_contact(b.profile().contact_code).unwrap();
            }
        }
    }
    let conv = alice
        .create_conversation(
            Some("Visibility test".into()),
            vec![bob.profile().id, carol.profile().id],
        )
        .unwrap();
    let cid = conv.id;
    let text = alice
        .send_message(cid.clone(), "Older SEARCH text".into(), None, vec![])
        .await
        .unwrap();
    let mut all = vec![text.clone()];
    for (name, body) in [
        ("Search photo.png", "image caption"),
        ("Search report.txt", "document caption"),
        ("Search voice.m4a", ""),
    ] {
        let file = da.join(name);
        std::fs::write(&file, b"synthetic attachment fixture").unwrap();
        all.push(
            alice
                .send_message(
                    cid.clone(),
                    body.into(),
                    None,
                    vec![file.to_string_lossy().into_owned()],
                )
                .await
                .unwrap(),
        );
    }
    eventually(|| {
        [&bob, &carol].iter().all(|r| {
            r.messages(cid.clone(), None, None)
                .is_ok_and(|m| m.len() == 4)
        })
    })
    .await;
    assert_eq!(bob.conversation(cid.clone()).unwrap().unread, 4);
    for m in &all {
        assert!(
            bob.delete_message(cid.clone(), m.id.clone()).is_err(),
            "recipient must not delete author's {}",
            m.id
        );
    }
    // Hide the newest voice and image on Bob only, leaving full pages of visible history.
    bob.delete_message_local(cid.clone(), all[1].id.clone())
        .unwrap();
    bob.delete_message_local(cid.clone(), all[3].id.clone())
        .unwrap();
    let visible = bob.messages(cid.clone(), Some(2), None).unwrap();
    assert_eq!(
        visible.iter().map(|m| &m.id).collect::<Vec<_>>(),
        vec![&all[0].id, &all[2].id]
    );
    assert_eq!(
        bob.messages(cid.clone(), Some(1), Some(all[2].id.clone()))
            .unwrap()[0]
            .id,
        all[0].id
    );
    let summary = bob.conversation(cid.clone()).unwrap();
    assert_eq!(summary.last_message.unwrap().id, all[2].id);
    assert_eq!(summary.unread, 2);
    assert_eq!(
        bob.search_messages(cid.clone(), "SEARCH".into(), None)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        bob.search_messages(cid.clone(), "report SEARCH".into(), None)
            .unwrap()[0]
            .id,
        all[2].id
    );
    assert!(
        bob.search_messages(cid.clone(), "voice".into(), None)
            .unwrap()
            .is_empty()
    );
    assert!(
        bob.search_messages(cid.clone(), "   ".into(), None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(carol.messages(cid.clone(), None, None).unwrap().len(), 4);
    alice
        .edit_message(
            cid.clone(),
            all[1].id.clone(),
            "changed hidden caption".into(),
        )
        .unwrap();
    eventually(|| {
        carol
            .search_messages(cid.clone(), "changed".into(), None)
            .is_ok_and(|m| m.len() == 1)
    })
    .await;
    assert!(
        bob.search_messages(cid.clone(), "changed".into(), None)
            .unwrap()
            .is_empty()
    );
    bob.shutdown().await.unwrap();
    drop(bob);
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob = open(&db, "Bob").await;
    connect(&[&alice, &bob, &carol]);
    assert_eq!(bob.messages(cid.clone(), None, None).unwrap().len(), 2);
    assert_eq!(bob.conversation(cid.clone()).unwrap().unread, 2);
    bob.restore_message_local(cid.clone(), all[1].id.clone())
        .unwrap();
    assert_eq!(
        bob.search_messages(cid.clone(), "changed".into(), None)
            .unwrap()
            .len(),
        1
    );
    bob.delete_message_local(cid.clone(), all[1].id.clone())
        .unwrap();
    let next = alice
        .send_message(cid.clone(), "new sync".into(), None, vec![])
        .await
        .unwrap();
    eventually(|| {
        bob.messages(cid.clone(), None, None)
            .is_ok_and(|m| m.iter().any(|m| m.id == next.id))
    })
    .await;
    assert_eq!(
        bob.messages(cid.clone(), None, None).unwrap().len(),
        3,
        "new sync cannot resurrect locally hidden messages"
    );
    // All kinds use the same author-only tombstone, including attachment-only voice notes.
    for m in &all {
        bob.toggle_reaction(cid.clone(), m.id.clone(), "test".into())
            .unwrap();
        alice.delete_message(cid.clone(), m.id.clone()).unwrap();
    }
    eventually(|| {
        [&alice, &carol].iter().all(|r| {
            r.messages(cid.clone(), None, None).is_ok_and(|rows| {
                all.iter().all(|sent| {
                    rows.iter().any(|m| {
                        m.id == sent.id
                            && m.deleted
                            && m.body.is_empty()
                            && m.attachments.is_empty()
                            && m.reactions.is_empty()
                    })
                })
            })
        })
    })
    .await;
    bob.restore_message_local(cid.clone(), all[1].id.clone())
        .unwrap();
    bob.restore_message_local(cid.clone(), all[3].id.clone())
        .unwrap();
    eventually(|| {
        bob.messages(cid.clone(), None, None)
            .is_ok_and(|rows| rows.iter().filter(|m| m.deleted).count() == 4)
    })
    .await;
    assert!(
        bob.search_messages(cid.clone(), "search".into(), None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        bob.conversation(cid.clone())
            .unwrap()
            .last_message
            .unwrap()
            .id,
        next.id
    );
    assert!(
        bob.delete_message_local(cid.clone(), "ff".repeat(32))
            .is_err()
    );
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
    carol.shutdown().await.unwrap();
    drop(alice);
    drop(bob);
    drop(carol);
    for dir in [da, db, dc] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
