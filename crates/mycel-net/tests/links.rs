//! Links: devices with no IP connectivity at all reach each other over
//! non-IP links, pick the best one, and move a live connection to another
//! link when one dies. Uses in-memory links (`MemNet`) in place of radios.

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets, protocol::Router};
use mycel_net::link::{Link, MemNet, MycelPathSelector, PathKind};
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn link_node(name: &str, nets: &[&MemNet]) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = false;
    opts.links = nets.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    Node::spawn(keys, opts).await.unwrap()
}

/// No IP at all: two devices find each other on links, sync on the fastest
/// one, and keep syncing over Bluetooth once peer-to-peer Wi-Fi is cut.
#[tokio::test(flavor = "multi_thread")]
async fn sync_over_links_and_fall_back_to_bluetooth() {
    let wifi = MemNet::new(0, PathKind::PeerWifi);
    let bt = MemNet::new(0, PathKind::Bluetooth);
    let alice = link_node("alice", &[&wifi, &bt]).await;
    let bob = link_node("bob", &[&wifi, &bt]).await;

    eventually("bob seen on both links", || {
        alice.peers().get(&bob.id()).is_some_and(|p| p.links.len() == 2 && p.online())
    })
    .await;

    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer))
        .unwrap()
        .unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();

    let doc = Replica::new_doc_id();
    alice
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "over peer wifi")))
        .unwrap()
        .unwrap();
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"msg": "over peer wifi"}));
    assert_eq!(bob.peers()[&alice.id()].via, Some(PathKind::PeerWifi), "fastest link wins");

    wifi.cut();
    eventually("peer wifi gone", || {
        bob.peers().get(&alice.id()).is_some_and(|p| !p.links.contains(&PathKind::PeerWifi))
    })
    .await;
    alice
        .with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "over bluetooth")))
        .unwrap()
        .unwrap();
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"msg": "over bluetooth"}));
    assert_eq!(bob.peers()[&alice.id()].via, Some(PathKind::Bluetooth));
    assert!(alice.link_status().iter().any(|s| s.kind == PathKind::Bluetooth && s.active));
}

const ECHO: &[u8] = b"test/stream";

#[derive(Debug, Clone)]
struct Sink;

impl mycel_net::iroh::protocol::ProtocolHandler for Sink {
    async fn accept(
        &self,
        conn: mycel_net::iroh::endpoint::Connection,
    ) -> Result<(), mycel_net::iroh::protocol::AcceptError> {
        let (mut tx, mut rx) = conn.accept_bi().await?;
        let mut total = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = rx.read(&mut buf).await.map_err(mycel_net::iroh::protocol::AcceptError::from_err)? {
            total += n as u64;
        }
        tx.write_all(&total.to_le_bytes()).await.map_err(mycel_net::iroh::protocol::AcceptError::from_err)?;
        tx.finish()?;
        conn.closed().await;
        Ok(())
    }
}

/// One QUIC connection survives losing its path: a transfer that starts on
/// peer-to-peer Wi-Fi finishes over Bluetooth, without reconnecting.
#[tokio::test(flavor = "multi_thread")]
async fn live_connection_moves_to_another_link() {
    let wifi = MemNet::new(1, PathKind::PeerWifi);
    let bt = MemNet::new(1, PathKind::Bluetooth);
    let (ka, kb) = (DeviceKeys::generate(), DeviceKeys::generate());
    let ep = |k: &DeviceKeys| {
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&k.seed()))
            .relay_mode(mycel_net::iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .path_selector(Arc::new(MycelPathSelector))
            .transport_config(mycel_net::link::transport_config());
        for n in [&wifi, &bt] {
            b = b.add_custom_transport(n.link(k.sign_pk()).transport());
        }
        b
    };
    let a = ep(&ka).bind().await.unwrap();
    let b = ep(&kb).alpns(vec![ECHO.to_vec()]).bind().await.unwrap();
    let router = Router::builder(b.clone()).accept(ECHO, Sink).spawn();

    let to_b = EndpointAddr::from_parts(
        b.id(),
        [&wifi, &bt].map(|n| TransportAddr::Custom(n.addr_of(&kb.sign_pk()))),
    );
    let conn = a.connect(to_b, ECHO).await.unwrap();
    // the backup path opens alongside the first one
    for _ in 0..50 {
        if conn.paths().iter().count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(conn.paths().iter().count(), 2, "both links are open paths");
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let total: u64 = 4 * 1024 * 1024;
    let mut sent = 0u64;
    let mut cut = false;
    let mut cut_at = None;
    while sent < total {
        tx.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
        if !cut && sent >= total / 4 {
            let selected = conn.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()));
            assert_eq!(selected, Some(PathKind::PeerWifi), "starts on the fast link");
            wifi.cut();
            cut_at = Some(std::time::Instant::now());
            cut = true;
        }
    }
    tx.finish().unwrap();
    let got = tokio::time::timeout(Duration::from_secs(60), rx.read_to_end(8))
        .await
        .expect("transfer finished after the link was cut")
        .unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), total, "every byte arrived");
    eprintln!("failover + rest of transfer took {:?}", cut_at.unwrap().elapsed());
    let selected = conn.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()));
    assert_eq!(selected, Some(PathKind::Bluetooth), "finished on the backup link");
    conn.close(0u32.into(), b"done");
    router.shutdown().await.unwrap();
}
