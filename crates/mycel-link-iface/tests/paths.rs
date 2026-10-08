//! Each interface is its own QUIC path: two endpoints with only the
//! interface link (no IP transport) open one path per shared interface and
//! carry a bulk transfer. Prints the throughput.
//!
//! Loopback by default (nothing leaves the machine). `MYCEL_IFACE_TEST=lo0,en0`
//! uses those interfaces instead (with a private discovery group and port).

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_link_iface::classify::{Decision, Rules, classify};
use mycel_link_iface::{IfaceLink, Options, ifaces};
use mycel_net::iroh::endpoint::Connection;
use mycel_net::iroh::protocol::{AcceptError, ProtocolHandler, Router};
use mycel_net::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets};
use mycel_net::link::{CustomAddr, Link, LinkEvent, MycelPathSelector};
use mycel_net::PathKind;
use tokio::sync::mpsc;

const ALPN: &[u8] = b"test/iface";

#[derive(Debug, Clone)]
struct Sink;

impl ProtocolHandler for Sink {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
            let mut total = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            while let Some(n) = rx.read(&mut buf).await.map_err(AcceptError::from_err)? {
                total += n as u64;
            }
            tx.write_all(&total.to_le_bytes()).await.map_err(AcceptError::from_err)?;
            tx.finish()?;
        }
        Ok(())
    }
}

/// The interfaces to use, or `None` if this machine has none usable.
fn options(port: u16) -> Option<(Vec<String>, Options)> {
    let all = ifaces::list();
    let names: Vec<String> = match std::env::var("MYCEL_IFACE_TEST") {
        Ok(v) => v.split(',').map(|s| s.trim().to_string()).collect(),
        Err(_) => vec![all.iter().find(|i| i.loopback)?.name.clone()],
    };
    let rules = Rules { ip_covers_routable: false, loopback: true, only: Some(names.clone()), medium: vec![] };
    for n in &names {
        let i = all.iter().find(|i| i.name == *n)?;
        if let Decision::Skip(why) = classify(i, &rules) {
            eprintln!("SKIPPED: {n} is not usable here ({why})");
            return None;
        }
    }
    let group = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0x6d79, 0x7465, 0x7375);
    Some((names, Options { rules, group, port, wifi_direct: false }))
}

struct Side {
    ep: Endpoint,
    link: Arc<IfaceLink>,
    found: mpsc::UnboundedReceiver<LinkEvent>,
}

async fn side(opts: &Options, alpn: bool) -> Side {
    let keys = DeviceKeys::generate();
    let link = IfaceLink::new(keys.sign_pk(), "t", opts.clone());
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&keys.seed()))
        .relay_mode(mycel_net::iroh::RelayMode::Disabled)
        .clear_ip_transports()
        .path_selector(Arc::new(MycelPathSelector::default()))
        .transport_config(mycel_net::link::transport_config())
        .add_custom_transport(link.transport());
    if alpn {
        b = b.alpns(vec![ALPN.to_vec()]);
    }
    let ep = b.bind().await.unwrap();
    let (tx, found) = mpsc::unbounded_channel();
    link.start(tx).unwrap();
    Side { ep, link, found }
}

async fn transfer(conn: &Connection, total: u64) -> f64 {
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let chunk = vec![0x5au8; 256 * 1024];
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        tx.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
    }
    tx.finish().unwrap();
    let got = tokio::time::timeout(Duration::from_secs(120), rx.read_to_end(8)).await.expect("finished").unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), sent, "every byte arrived");
    sent as f64 / 1e6 / start.elapsed().as_secs_f64()
}

#[tokio::test(flavor = "multi_thread")]
async fn one_path_per_interface() {
    let port = 47_000 + (std::process::id() % 1000) as u16;
    let Some((names, opts)) = options(port) else { return };
    let mut a = side(&opts, false).await;
    let b = side(&opts, true).await;
    let router = Router::builder(b.ep.clone()).accept(ALPN, Sink).spawn();

    // b's address on every interface, from its beacons
    let mut addrs: Vec<CustomAddr> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while addrs.len() < names.len() && Instant::now() < deadline {
        if let Ok(Some(LinkEvent::Found { addr, .. })) = tokio::time::timeout(Duration::from_millis(200), a.found.recv()).await {
            addrs.push(addr);
        }
    }
    assert_eq!(addrs.len(), names.len(), "found on every interface: {:?}", a.link.peers());
    let to_b = EndpointAddr::from_parts(b.ep.id(), addrs.iter().cloned().map(TransportAddr::Custom));
    let conn = a.ep.connect(to_b, ALPN).await.unwrap();
    for _ in 0..100 {
        if conn.paths().iter().count() >= names.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let kinds: Vec<PathKind> = conn.paths().iter().map(|p| PathKind::of(p.remote_addr())).collect();
    eprintln!("paths over {names:?}: {kinds:?}");
    assert_eq!(conn.paths().iter().count(), names.len(), "one path per interface");

    let rate = transfer(&conn, 64 * 1024 * 1024).await;
    let per_path: Vec<String> = conn
        .paths()
        .iter()
        .map(|p| format!("{}: {:.1} MB", PathKind::of(p.remote_addr()).label(), p.stats().udp_tx.bytes as f64 / 1e6))
        .collect();
    eprintln!("64 MiB over the interface link: {rate:.1} MB/s [{}]", per_path.join(", "));
    assert!(rate > 1.0, "{rate:.1} MB/s");

    conn.close(0u32.into(), b"done");
    router.shutdown().await.unwrap();
}
