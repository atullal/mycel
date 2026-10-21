//! This build against a real pre-release build (docs/PROTOCOL.md §5). The
//! other side is `scripts/v1-compat/old_peer.rs` compiled in a checkout of
//! main `98d9b7b`: `scripts/v1-compat/run.sh` builds it and runs both, which
//! swap addresses and cards through files in `MYCEL_V1_COMPAT_DIR` and talk
//! over loopback. Ignored in a plain `cargo test` (it needs the old peer).
//!
//! What it shows: the connection lands on wire version 1 with no
//! capabilities; a space created here syncs there with its first entry, the
//! old build's entry syncs back, and each fetches the other's card.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::{DeviceKeys, SignPk};
use mycel_net::iroh::EndpointAddr;
use mycel_net::version::{PeerProtocol, WIRE_V1};
use mycel_net::{ContactCard, NetMode, Node, NodeOptions};
use mycel_trust::Role;

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
#[ignore = "needs the pre-release peer: scripts/v1-compat/run.sh"]
async fn talks_to_a_pre_release_build() {
    tokio::time::timeout(Duration::from_secs(120), run()).await.expect("the new peer's script timed out");
}

async fn run() {
    let dir = PathBuf::from(std::env::var("MYCEL_V1_COMPAT_DIR").expect("MYCEL_V1_COMPAT_DIR"));
    let node = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "new")).await.unwrap();
    put(&dir, "new.addr", &node.addr());
    let old: EndpointAddr = take(&dir, "old.addr").await;
    let card: ContactCard = take(&dir, "old.card").await;
    card.verify().unwrap();
    let old_id = SignPk(*old.id.as_bytes());
    assert_eq!(card.keys.sign_pk, old_id);
    node.add_peer_addr(old);

    assert_eq!(node.negotiate(old_id).await.unwrap(), PeerProtocol::baseline(WIRE_V1), "version 1, no hello");
    let (space, _) = node.create_space().unwrap();
    node.with_space(&space, |r| r.add_member(card.keys, Role::Writer)).unwrap().unwrap();
    node.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"from new".to_vec())).unwrap().unwrap();
    node.sync_with(old_id, space, false).await.unwrap();
    put(&dir, "space", &space);

    let _: String = take(&dir, "old.done").await;
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    while node.with_space(&space, |r| r.envelope_ids().len()).unwrap() < 2 && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 2, "the old build's entry synced back");
    assert_eq!(node.fetch_card(old_id).await.unwrap().keys.sign_pk, old_id);
    put(&dir, "new.done", &"ok");
    node.shutdown().await.unwrap();
    eprintln!("new peer: version 1 with the pre-release build, space synced both ways, cards fetched");
}
