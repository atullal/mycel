//! Links: devices with no IP connectivity at all reach each other over
//! non-IP links, pick the best one, and move a live connection to another
//! link when one dies. Uses in-memory links (`MemNet`) in place of radios.

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets, protocol::Router};
use mycel_net::link::transports::{PathSelection, PathSelectionContext, PathSelector};
use mycel_net::link::{Link, MemNet, MycelPathSelector, PathKind, path_in_use};
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

/// These tests time emulated radios (path choice, failover, timeouts): side
/// by side on a small machine they starve each other of CPU and timers (seen
/// on 4-core Windows runners), so they run one at a time.
static RADIOS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let _radios = RADIOS.lock().await;
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
    // Path choice needs an RTT sample on each path; a very short exchange
    // under load can finish before the fast path has one, so sync again
    // until it has settled.
    for _ in 0..20 {
        if bob.peers()[&alice.id()].via == Some(PathKind::PeerWifi) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        bob.sync_with(alice.id(), space, false).await.unwrap();
    }
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
    // The data moves to Bluetooth within a probe timeout of the cut; Iroh's
    // selection (what `via` reports) follows once the dead path has been
    // silent for a few seconds.
    for _ in 0..50 {
        if bob.peers()[&alice.id()].via == Some(PathKind::Bluetooth) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        bob.sync_with(alice.id(), space, false).await.unwrap();
    }
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
    let _radios = RADIOS.lock().await;
    let wifi = MemNet::new(1, PathKind::PeerWifi);
    let bt = MemNet::new(1, PathKind::Bluetooth);
    let (ka, kb) = (DeviceKeys::generate(), DeviceKeys::generate());
    let ep = |k: &DeviceKeys| {
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&k.seed()))
            .relay_mode(mycel_net::iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .path_selector(Arc::new(MycelPathSelector::default()))
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
    // The rest went over Bluetooth as soon as the Wi-Fi path stopped answering
    // (noq moves a dead path's data within a probe timeout); Iroh's selection
    // follows once that path has been silent for a few seconds.
    let selected = || conn.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()));
    for _ in 0..50 {
        if selected() == Some(PathKind::Bluetooth) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(selected(), Some(PathKind::Bluetooth), "finished on the backup link");
    conn.close(0u32.into(), b"done");
    router.shutdown().await.unwrap();
}

/// Selects a path only over one medium (to set which path each end selects).
#[derive(Debug)]
struct Only(PathKind);

impl PathSelector for Only {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(p) = ctx.paths().find(|p| PathKind::of(&TransportAddr::from(p.network_path().remote())) == self.0) {
            selection.set(&p);
        }
        selection
    }
}

/// Hands each connection it accepts to the test, and keeps it open.
#[derive(Debug, Clone)]
struct Accepted(tokio::sync::mpsc::UnboundedSender<mycel_net::iroh::endpoint::Connection>);

impl mycel_net::iroh::protocol::ProtocolHandler for Accepted {
    async fn accept(
        &self,
        conn: mycel_net::iroh::endpoint::Connection,
    ) -> Result<(), mycel_net::iroh::protocol::AcceptError> {
        let _ = self.0.send(conn.clone());
        conn.closed().await;
        Ok(())
    }
}

/// Each end selects its own path to the other, and only the end that dialed
/// a connection opens paths on it. So a connection the peer dialed may lack
/// the path our end selected, and then none of its paths is selected (in a
/// group call, a participant's path stayed unknown): `path_in_use` still
/// says which path it uses.
#[tokio::test(flavor = "multi_thread")]
async fn path_in_use_on_a_connection_the_peer_dialed() {
    let _radios = RADIOS.lock().await;
    let wifi = MemNet::new(1, PathKind::PeerWifi);
    let bt = MemNet::new(1, PathKind::Bluetooth);
    let (ka, kb) = (DeviceKeys::generate(), DeviceKeys::generate());
    let ep = |k: &DeviceKeys, only: PathKind| {
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&k.seed()))
            .relay_mode(mycel_net::iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .path_selector(Arc::new(Only(only)))
            .transport_config(mycel_net::link::transport_config())
            .alpns(vec![ECHO.to_vec()]);
        for n in [&wifi, &bt] {
            b = b.add_custom_transport(n.link(k.sign_pk()).transport());
        }
        b
    };
    // Alice's end selects Bluetooth, Bob's peer-to-peer Wi-Fi.
    let a = ep(&ka, PathKind::Bluetooth).bind().await.unwrap();
    let b = ep(&kb, PathKind::PeerWifi).bind().await.unwrap();
    let (a_tx, _a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, mut b_rx) = tokio::sync::mpsc::unbounded_channel();
    let routers = [
        Router::builder(a.clone()).accept(ECHO, Accepted(a_tx)).spawn(),
        Router::builder(b.clone()).accept(ECHO, Accepted(b_tx)).spawn(),
    ];
    let on = |n: &MemNet, k: &DeviceKeys, ep: &Endpoint| {
        EndpointAddr::from_parts(ep.id(), [TransportAddr::Custom(n.addr_of(&k.sign_pk()))])
    };
    let kind = |p: mycel_net::iroh::endpoint::Path<'_>| PathKind::of(p.remote_addr());
    let selected = |c: &mycel_net::iroh::endpoint::Connection| c.paths().iter().find(|p| p.is_selected()).map(kind);

    // Bob dials Alice over Wi-Fi: his end selects it.
    let b_to_a = b.connect(on(&wifi, &ka, &a), ECHO).await.unwrap();
    eventually("bob selects wi-fi", || selected(&b_to_a) == Some(PathKind::PeerWifi)).await;
    // Wi-Fi goes out of range (else Alice's end would open a Wi-Fi path on
    // her connection too), and Alice dials Bob over Bluetooth: her end
    // selects Bluetooth, his stays on Wi-Fi.
    wifi.cut();
    let a_to_b = a.connect(on(&bt, &kb, &b), ECHO).await.unwrap();
    eventually("alice selects bluetooth", || selected(&a_to_b) == Some(PathKind::Bluetooth)).await;
    let on_b = tokio::time::timeout(Duration::from_secs(10), b_rx.recv()).await.unwrap().unwrap();
    // traffic both ways on Alice's connection
    let (mut tx, mut rx) = a_to_b.open_bi().await.unwrap();
    tx.write_all(&[7u8; 4096]).await.unwrap();
    tx.finish().unwrap();
    let (mut btx, mut brx) = on_b.accept_bi().await.unwrap();
    assert_eq!(brx.read_to_end(1 << 16).await.unwrap().len(), 4096);
    btx.write_all(&[8u8; 4096]).await.unwrap();
    btx.finish().unwrap();
    assert_eq!(rx.read_to_end(1 << 16).await.unwrap().len(), 4096);

    // On Bob's end of Alice's connection there's only Bluetooth, and his end
    // selected Wi-Fi: no path there is selected.
    let paths = on_b.paths();
    let kinds: Vec<PathKind> = paths.iter().map(kind).collect();
    assert_eq!(kinds, vec![PathKind::Bluetooth], "alice's connection has only bluetooth");
    assert_eq!(selected(&on_b), None, "nothing on it is selected at bob's end");
    // ... yet it's plain which path it uses
    assert_eq!(path_in_use(&paths).map(kind), Some(PathKind::Bluetooth));
    assert_eq!(path_in_use(&a_to_b.paths()).map(kind), Some(PathKind::Bluetooth));

    for c in [&b_to_a, &a_to_b] {
        c.close(0u32.into(), b"done");
    }
    for r in routers {
        r.shutdown().await.unwrap();
    }
}
