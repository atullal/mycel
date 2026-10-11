//! Failed eager uploads cannot consume persistent staging or damage a user's resume.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::wire::{self, BlobReq, BlobResp, StreamKind};
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_trust::Role;

async fn node() -> (Node, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "mycel-push-security-{}",
        mycel_crypto::random_u64()
    ));
    let mut opts = NodeOptions::new(NetMode::Local, "synthetic test node");
    opts.blob_dir = Some(dir.clone());
    (
        Node::spawn(Arc::new(DeviceKeys::generate()), opts)
            .await
            .unwrap(),
        dir,
    )
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition did not become true");
}

fn stages(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".push.")
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_and_invalid_eager_pushes_clean_stages_and_preserve_download_resume() {
    let (alice, alice_dir) = node().await;
    let (bob, bob_dir) = node().await;
    alice.add_peer_addr(bob.addr());
    bob.add_peer_addr(alice.addr());
    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer))
        .unwrap()
        .unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    let hash = wire::blob_hash(b"expected complete blob");
    let dir = bob_dir.join(space.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let part = dir.join(format!("{hash}.part"));
    let ranges = part.with_extension("ranges");
    std::fs::write(&part, b"user download prefix").unwrap();
    std::fs::write(&ranges, b"user download ranges").unwrap();
    let conn = alice.connect(bob.id(), wire::ALPN).await.unwrap();

    for offer in [true, false] {
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
        let req = if offer {
            BlobReq::Offer {
                space,
                hash,
                len: 64,
            }
        } else {
            BlobReq::Put {
                space,
                hash,
                len: 64,
            }
        };
        wire::send(&mut tx, &req).await.unwrap();
        if offer {
            assert!(matches!(
                wire::recv::<BlobResp>(&mut rx).await.unwrap(),
                BlobResp::SendFrom { offset: 0 }
            ));
        }
        tx.write_all(b"short").await.unwrap();
        eventually(|| stages(&dir) == 1).await;
        tx.finish().unwrap();
        assert!(wire::recv::<BlobResp>(&mut rx).await.is_err());
        eventually(|| stages(&dir) == 0).await;
        assert_eq!(std::fs::read(&part).unwrap(), b"user download prefix");
        assert_eq!(std::fs::read(&ranges).unwrap(), b"user download ranges");
        assert!(bob.blob_path(&space, &hash).is_none());
    }
    // Full-length bad data must also discard its isolated stage.
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
    wire::send(
        &mut tx,
        &BlobReq::Offer {
            space,
            hash,
            len: 3,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        wire::recv::<BlobResp>(&mut rx).await.unwrap(),
        BlobResp::SendFrom { offset: 0 }
    ));
    tx.write_all(b"bad").await.unwrap();
    tx.finish().unwrap();
    assert!(wire::recv::<BlobResp>(&mut rx).await.is_err());
    eventually(|| stages(&dir) == 0).await;
    assert_eq!(std::fs::read(&part).unwrap(), b"user download prefix");
    assert_eq!(std::fs::read(&ranges).unwrap(), b"user download ranges");

    // Reset while waiting for bytes exercises cancellation/error cleanup too.
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
    wire::send(
        &mut tx,
        &BlobReq::Offer {
            space,
            hash,
            len: 100,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        wire::recv::<BlobResp>(&mut rx).await.unwrap(),
        BlobResp::SendFrom { offset: 0 }
    ));
    tx.reset(0u32.into()).unwrap();
    rx.stop(0u32.into()).unwrap();
    eventually(|| stages(&dir) == 0).await;

    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
    std::fs::remove_dir_all(alice_dir).ok();
    std::fs::remove_dir_all(bob_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keeper_push_retains_and_resumes_partial_bytes() {
    let (alice, alice_dir) = node().await;
    let (keeper, keeper_dir) = node().await;
    alice.add_peer_addr(keeper.addr());
    keeper.add_peer_addr(alice.addr());
    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(keeper.keys().public(), Role::Relay)
        })
        .unwrap()
        .unwrap();
    keeper.join_space(genesis).unwrap();
    keeper.sync_with(alice.id(), space, true).await.unwrap();
    let bytes = b"synthetic keeper resume bytes";
    let hash = wire::blob_hash(bytes);
    let conn = alice.connect(keeper.id(), wire::ALPN).await.unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
    wire::send(
        &mut tx,
        &BlobReq::Offer {
            space,
            hash,
            len: bytes.len() as u64,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        wire::recv::<BlobResp>(&mut rx).await.unwrap(),
        BlobResp::SendFrom { offset: 0 }
    ));
    tx.write_all(&bytes[..8]).await.unwrap();
    tx.finish().unwrap();
    assert!(wire::recv::<BlobResp>(&mut rx).await.is_err());
    let part = keeper_dir
        .join(space.to_string())
        .join(format!("{hash}.part"));
    assert_eq!(std::fs::read(&part).unwrap(), &bytes[..8]);

    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[StreamKind::Blob as u8]).await.unwrap();
    wire::send(
        &mut tx,
        &BlobReq::Offer {
            space,
            hash,
            len: bytes.len() as u64,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        wire::recv::<BlobResp>(&mut rx).await.unwrap(),
        BlobResp::SendFrom { offset: 8 }
    ));
    tx.write_all(&bytes[8..]).await.unwrap();
    tx.finish().unwrap();
    assert!(matches!(
        wire::recv::<BlobResp>(&mut rx).await.unwrap(),
        BlobResp::Stored
    ));
    assert_eq!(
        std::fs::read(keeper.blob_path(&space, &hash).unwrap()).unwrap(),
        bytes
    );
    assert!(!part.exists());
    alice.shutdown().await.unwrap();
    keeper.shutdown().await.unwrap();
    std::fs::remove_dir_all(alice_dir).ok();
    std::fs::remove_dir_all(keeper_dir).unwrap();
}
