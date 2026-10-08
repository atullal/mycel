//! Bandwidth aggregation over QUIC multipath: with several comparable links
//! between two devices, one connection (one stream, even) sends on all of
//! them at once, and keeps going when one is cut. A very slow link
//! (Bluetooth) is never allowed to slow the fast one down.
//!
//! Uses rate-limited in-memory links (`MemNet`) in place of radios.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::iroh::protocol::{AcceptError, ProtocolHandler, Router};
use mycel_net::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets};
use mycel_net::link::{Link, MemNet, MycelPathSelector, PathKind};

const ALPN: &[u8] = b"test/aggregate";
const MB: u64 = 1_000_000;

/// Reads a stream to the end and answers with the byte count.
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

struct Pair {
    conn: Connection,
    router: Router,
    _a: Endpoint,
}

/// Two endpoints with no IP at all, joined only by `nets`.
async fn pair(nets: &[&MemNet]) -> Pair {
    let (ka, kb) = (DeviceKeys::generate(), DeviceKeys::generate());
    let ep = |k: &DeviceKeys| {
        let mut b = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&k.seed()))
            .relay_mode(mycel_net::iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .path_selector(Arc::new(MycelPathSelector::default()))
            .transport_config(mycel_net::link::transport_config());
        for n in nets {
            b = b.add_custom_transport(n.link(k.sign_pk()).transport());
        }
        b
    };
    let a = ep(&ka).bind().await.unwrap();
    let b = ep(&kb).alpns(vec![ALPN.to_vec()]).bind().await.unwrap();
    let router = Router::builder(b.clone()).accept(ALPN, Sink).spawn();
    let to_b = EndpointAddr::from_parts(b.id(), nets.iter().map(|n| TransportAddr::Custom(n.addr_of(&kb.sign_pk()))));
    let conn = a.connect(to_b, ALPN).await.unwrap();
    for _ in 0..100 {
        if conn.paths().iter().count() >= nets.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(conn.paths().iter().count(), nets.len(), "every link is an open path");
    // let both sides measure every path's RTT and run selection
    tokio::time::sleep(Duration::from_millis(2500)).await;
    Pair { conn, router, _a: a }
}

/// Bytes sent so far on each path, by kind of path.
fn sent_per_path(conn: &Connection) -> Vec<(PathKind, u64)> {
    conn.paths().iter().map(|p| (PathKind::of(p.remote_addr()), p.stats().udp_tx.bytes)).collect()
}

fn path_report(conn: &Connection) -> String {
    conn.paths()
        .iter()
        .map(|p| {
            let s = p.stats();
            format!(
                "{} rtt {:?} cwnd {} KB lost {:.1} MB",
                PathKind::of(p.remote_addr()).label(),
                s.rtt,
                s.cwnd / 1000,
                s.lost_bytes as f64 / MB as f64
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Send `total` bytes on one stream; `at` (fraction, action) runs once
/// that much has been written. Returns MB/s.
async fn transfer(conn: &Connection, total: u64, mut at: Option<(f64, Box<dyn FnOnce() + Send>)>) -> f64 {
    let before = sent_per_path(conn);
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let chunk = vec![0x5au8; 256 * 1024];
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        tx.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
        if let Some((f, _)) = &at
            && sent as f64 >= *f * total as f64
        {
            (at.take().unwrap().1)();
        }
    }
    tx.finish().unwrap();
    let got =
        tokio::time::timeout(Duration::from_secs(120), rx.read_to_end(8)).await.expect("transfer finished").unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), sent, "every byte arrived");
    let secs = start.elapsed().as_secs_f64();
    let after = sent_per_path(conn);
    let per_path: Vec<String> = after
        .iter()
        .enumerate()
        .map(|(i, (k, b))| {
            let b0 = before.get(i).map_or(0, |x| x.1);
            format!("{}: {:.1} MB", k.label(), (b - b0) as f64 / MB as f64)
        })
        .collect();
    let rate = sent as f64 / MB as f64 / secs;
    eprintln!("  {}", path_report(conn));
    eprintln!("  {:.1} MB in {secs:.2} s = {rate:.1} MB/s  [{}]", sent as f64 / MB as f64, per_path.join(", "));
    rate
}

fn link(n: u64, kind: PathKind, rate: u64, latency_ms: u64) -> MemNet {
    let net = MemNet::new(n, kind);
    net.set_rate_limit(Some(rate));
    net.set_latency(Duration::from_millis(latency_ms));
    net
}

const TOTAL: u64 = 40 * MB;

/// Two 10 MB/s links carry about twice what one does, on one stream.
#[tokio::test(flavor = "multi_thread")]
async fn two_links_add_up() {
    eprintln!("one 10 MB/s link:");
    let one = link(1, PathKind::PeerWifi, 10 * MB, 5);
    let p = pair(&[&one]).await;
    let single = transfer(&p.conn, TOTAL, None).await;
    p.router.shutdown().await.unwrap();

    eprintln!("two 10 MB/s links:");
    let (l1, l2) = (link(2, PathKind::PeerWifi, 10 * MB, 5), link(3, PathKind::PeerWifi, 10 * MB, 5));
    let p = pair(&[&l1, &l2]).await;
    let both = transfer(&p.conn, TOTAL, None).await;
    eprintln!("aggregate / single = {:.2}x", both / single);
    assert!(both > 1.6 * single, "two links: {both:.1} MB/s vs one: {single:.1} MB/s");
    let per = sent_per_path(&p.conn);
    assert!(per.iter().all(|(_, b)| *b > 5 * MB), "both links carried data: {per:?}");

    // Cut one link a quarter of the way in: the transfer still completes
    // (in-flight packets on the dead link are resent on the live one once
    // its path times out).
    eprintln!("two links, one cut at 25 %:");
    let cut = l1.clone();
    let start = Instant::now();
    transfer(&p.conn, TOTAL, Some((0.25, Box::new(move || cut.cut())))).await;
    eprintln!("  (with the cut: {:.1} s)", start.elapsed().as_secs_f64());
    p.router.shutdown().await.unwrap();
}

/// A fast link plus a very slow Bluetooth one: the slow one stays a backup,
/// so throughput is the fast link's own.
#[tokio::test(flavor = "multi_thread")]
async fn slow_bluetooth_never_slows_the_fast_link() {
    eprintln!("fast link alone:");
    let fast = link(4, PathKind::PeerWifi, 10 * MB, 5);
    let p = pair(&[&fast]).await;
    let alone = transfer(&p.conn, TOTAL / 2, None).await;
    p.router.shutdown().await.unwrap();

    eprintln!("fast link + 20 KB/s Bluetooth:");
    let fast = link(5, PathKind::PeerWifi, 10 * MB, 5);
    let bt = link(0, PathKind::Bluetooth, 20_000, 30);
    let p = pair(&[&fast, &bt]).await;
    let with_bt = transfer(&p.conn, TOTAL / 2, None).await;
    assert!(with_bt > 0.85 * alone, "with Bluetooth {with_bt:.1} MB/s vs alone {alone:.1} MB/s");
    p.router.shutdown().await.unwrap();

    // Same for a slow link that claims to be fast (peer-to-peer Wi-Fi at
    // 300 KB/s with 60 ms latency): its RTT keeps it out of the aggregate.
    eprintln!("fast link + slow 'peer Wi-Fi' (300 KB/s, 60 ms):");
    let fast = link(6, PathKind::PeerWifi, 10 * MB, 5);
    let slow = link(7, PathKind::PeerWifi, 300_000, 60);
    let p = pair(&[&fast, &slow]).await;
    let with_slow = transfer(&p.conn, TOTAL / 2, None).await;
    assert!(with_slow > 0.85 * alone, "with slow link {with_slow:.1} MB/s vs alone {alone:.1} MB/s");
    p.router.shutdown().await.unwrap();
}
