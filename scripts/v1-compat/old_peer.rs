//! The pre-release side of the cross-build test (`run.sh`): copied into a
//! checkout of main `98d9b7b` as `crates/mycel-net/tests/v1_compat_peer.rs`
//! and run beside `crates/mycel-net/tests/v1_compat.rs` of the current
//! build. The two swap addresses and contact cards through files in
//! `MYCEL_V1_COMPAT_DIR` and talk over loopback.
//!
//! Script: the current build creates a space with this device in it,
//! writes to it and syncs it here; this device writes back and syncs it
//! there, and fetches the other's card. It uses only `98d9b7b`'s API, which
//! the `dev-2026-10-09-apps` release has too (`BASE=` in `run.sh`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::EndpointAddr;
use mycel_net::{ContactCard, NetMode, Node, NodeOptions};
use mycel_trust::SpaceId;

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("MYCEL_V1_COMPAT_DIR").expect("MYCEL_V1_COMPAT_DIR"))
}

fn put(dir: &Path, name: &str, value: &impl serde::Serialize) {
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(value).unwrap()).unwrap();
    std::fs::rename(tmp, dir.join(name)).unwrap();
}

async fn take<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> T {
    loop {
        if let Ok(b) = std::fs::read(dir.join(name)) {
            return serde_json::from_slice(&b).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by scripts/v1-compat/run.sh"]
async fn old_peer() {
    tokio::time::timeout(Duration::from_secs(120), run()).await.expect("the old peer's script timed out");
}

async fn run() {
    let dir = dir();
    let keys = Arc::new(DeviceKeys::generate());
    let node = Node::spawn(keys.clone(), NodeOptions::new(NetMode::Local, "old")).await.unwrap();
    put(&dir, "old.addr", &node.addr());
    put(&dir, "old.card", &ContactCard::new(&keys, "old"));
    let new: EndpointAddr = take(&dir, "new.addr").await;
    let new_id = mycel_crypto::SignPk(*new.id.as_bytes());
    node.add_peer_addr(new);

    // the space the new build pushed here, with its first entry
    let space: SpaceId = take(&dir, "space").await;
    while node.with_space(&space, |r| r.envelope_ids().len()).unwrap_or(0) < 1 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    node.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"from old".to_vec())).unwrap().unwrap();
    node.sync_with(new_id, space, false).await.unwrap();
    let card = node.fetch_card(new_id).await.unwrap();
    assert_eq!(card.keys.sign_pk, new_id);
    put(&dir, "old.done", &"ok");
    let _: String = take(&dir, "new.done").await;
    node.shutdown().await.unwrap();
    eprintln!("old peer (pre-release): synced a space both ways and fetched the card");
}
