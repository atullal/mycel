//! Application consent must guard both unsolicited blob protocols and downloads.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mycel_net::wire::{self, BlobReq, BlobResp, StreamKind};
use mycel_node::api::NetworkMode;
use mycel_node::{Runtime, RuntimeOptions};

fn tmp(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "mycel-attachment-security-{label}-{}",
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

fn connect(a: &Runtime, b: &Runtime) {
    a.node().add_peer_addr(b.node().addr());
    b.node().add_peer_addr(a.node().addr());
}

async fn eventually(mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition did not become true");
}

/// Exercise the public QUIC protocol directly, including the pre-Offer legacy Put.
async fn push(
    sender: &Runtime,
    receiver: &Runtime,
    space: mycel_trust::SpaceId,
    bytes: &[u8],
    offer: bool,
) -> BlobResp {
    let conn = sender
        .node()
        .connect(receiver.node().id(), wire::ALPN)
        .await
        .unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
    let hash = wire::blob_hash(bytes);
    let len = bytes.len() as u64;
    let req = if offer {
        BlobReq::Offer { space, hash, len }
    } else {
        BlobReq::Put { space, hash, len }
    };
    wire::send(&mut tx, &req).await.unwrap();
    if offer {
        let response = wire::recv::<BlobResp>(&mut rx).await.unwrap();
        match response {
            BlobResp::SendFrom { offset } => tx.write_all(&bytes[offset as usize..]).await.unwrap(),
            other => return other,
        }
    } else {
        // A server that denies the legacy Put may answer and stop reading
        // before the bytes are written: the write can fail, the answer stands.
        let _ = tx.write_all(bytes).await;
    }
    let _ = tx.finish();
    wire::recv(&mut rx).await.unwrap()
}

fn no_files(dir: &Path) -> bool {
    !dir.exists()
        || std::fs::read_dir(dir).unwrap().all(|entry| {
            let path = entry.unwrap().path();
            path.is_dir() && no_files(&path)
        })
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_requests_reject_offer_put_and_download_across_restart() {
    let (alice_dir, bob_dir) = (tmp("sender"), tmp("recipient"));
    let alice = open(&alice_dir, "Sender").await;
    let mut bob = open(&bob_dir, "Recipient").await;
    connect(&alice, &bob);
    let contact = alice.add_contact(bob.profile().contact_code).unwrap();
    let conv = alice.create_conversation(None, vec![contact.id]).unwrap();
    eventually(|| {
        bob.conversations()
            .iter()
            .any(|c| c.id == conv.id && c.request)
    })
    .await;
    let space = bob.node().space_ids()[0];

    for offer in [true, false] {
        assert!(matches!(
            push(&alice, &bob, space, b"unaccepted arbitrary blob", offer).await,
            BlobResp::Denied
        ));
    }
    let source = alice_dir.join("synthetic.txt");
    std::fs::write(&source, b"synthetic attachment bytes").unwrap();
    let sent = alice
        .send_message(
            conv.id.clone(),
            "pending attachment".into(),
            None,
            vec![source.to_string_lossy().into()],
        )
        .await
        .unwrap();
    let blob = sent.attachments[0].blob.clone();
    eventually(|| {
        bob.messages(conv.id.clone(), None, None)
            .unwrap()
            .iter()
            .any(|m| !m.attachments.is_empty())
    })
    .await;
    assert!(
        bob.fetch_attachment(blob.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("accept this message request")
    );
    assert!(
        no_files(&bob_dir.join("blobs")),
        "denied pushes must create no blob or partial files"
    );
    assert!(
        no_files(&bob_dir.join("files")),
        "denied download must create no output"
    );

    bob.shutdown().await.unwrap();
    drop(bob);
    bob = open(&bob_dir, "Recipient").await;
    connect(&alice, &bob);
    assert!(bob.conversation(conv.id.clone()).unwrap().request);
    for offer in [true, false] {
        assert!(matches!(
            push(&alice, &bob, space, b"restart arbitrary blob", offer).await,
            BlobResp::Denied
        ));
    }
    assert!(bob.fetch_attachment(blob.clone()).await.is_err());
    assert!(
        no_files(&bob_dir.join("blobs")),
        "persisted pending request must deny writes after restart"
    );

    bob.accept_request(conv.id.clone()).unwrap();
    for (offer, bytes) in [
        (true, b"accepted offer".as_slice()),
        (false, b"accepted legacy put".as_slice()),
    ] {
        assert!(matches!(
            push(&alice, &bob, space, bytes, offer).await,
            BlobResp::Stored
        ));
        let path = bob
            .node()
            .blob_path(&space, &wire::blob_hash(bytes))
            .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    let output = bob.fetch_attachment(blob.clone()).await.unwrap();
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"synthetic attachment bytes"
    );
    std::fs::remove_file(output).unwrap();
    bob.leave_conversation(conv.id.clone()).unwrap();
    let historical = bob.fetch_attachment(blob).await.unwrap();
    assert_eq!(
        std::fs::read(historical).unwrap(),
        b"synthetic attachment bytes",
        "leaving keeps accepted local history downloadable"
    );

    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
    drop(alice);
    drop(bob);
    std::fs::remove_dir_all(alice_dir).unwrap();
    std::fs::remove_dir_all(bob_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn declined_requests_reject_pushes_across_restart() {
    let (alice_dir, bob_dir) = (tmp("declined-sender"), tmp("declined-recipient"));
    let alice = open(&alice_dir, "Sender").await;
    let mut bob = open(&bob_dir, "Recipient").await;
    connect(&alice, &bob);
    let contact = alice.add_contact(bob.profile().contact_code).unwrap();
    let conv = alice.create_conversation(None, vec![contact.id]).unwrap();
    eventually(|| {
        bob.conversations()
            .iter()
            .any(|c| c.id == conv.id && c.request)
    })
    .await;
    let space = bob.node().space_ids()[0];
    bob.decline_request(conv.id.clone(), true).unwrap();
    assert!(bob.conversations().is_empty());
    for offer in [true, false] {
        assert!(matches!(
            push(&alice, &bob, space, b"declined arbitrary blob", offer).await,
            BlobResp::Denied
        ));
    }
    assert!(no_files(&bob_dir.join("blobs")));
    bob.shutdown().await.unwrap();
    drop(bob);
    bob = open(&bob_dir, "Recipient").await;
    connect(&alice, &bob);
    assert!(bob.conversations().is_empty());
    for offer in [true, false] {
        assert!(matches!(
            push(&alice, &bob, space, b"declined restart blob", offer).await,
            BlobResp::Denied
        ));
    }
    assert!(no_files(&bob_dir.join("blobs")));
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
    drop(alice);
    drop(bob);
    std::fs::remove_dir_all(alice_dir).unwrap();
    std::fs::remove_dir_all(bob_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_invitation_proof_does_not_persist_pending_metadata() {
    let (alice_dir, bob_dir) = (tmp("invalid-sender"), tmp("invalid-recipient"));
    let alice = open(&alice_dir, "Sender").await;
    let bob = open(&bob_dir, "Recipient").await;
    connect(&alice, &bob);
    {
        let conn = alice
            .node()
            .connect(bob.node().id(), wire::ALPN)
            .await
            .unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        tx.write_all(&[StreamKind::Sync as u8]).await.unwrap();
        wire::send(
            &mut tx,
            &wire::SyncMsg::Hello {
                space: wire::blob_hash(b"invalid proof space"),
                inv: wire::Inventory::default(),
                invite: Some(vec![]),
            },
        )
        .await
        .unwrap();
        tx.finish().unwrap();
        assert!(matches!(
            wire::recv::<wire::SyncMsg>(&mut rx).await.unwrap(),
            wire::SyncMsg::Denied
        ));
    }
    assert!(bob.conversations().is_empty());
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
    drop(alice);
    drop(bob);
    let store = mycel_node::store::DbStore::open(bob_dir.join("mycel.redb")).unwrap();
    assert!(
        store.kv_get("requests").unwrap().is_none(),
        "unproved invitations must not invoke persistent policy"
    );
    store.close().unwrap();
    drop(store);
    std::fs::remove_dir_all(alice_dir).unwrap();
    std::fs::remove_dir_all(bob_dir).unwrap();
}
