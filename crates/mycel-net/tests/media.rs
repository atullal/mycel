//! Any medium ranks itself: path selection has no per-radio rules, only a
//! prior guess per medium that measurements replace. A UWB link beats an
//! 802.15.4 one next to it, and a link whose prior is far too optimistic
//! loses the traffic once it is seen to deliver less than the alternative.
//!
//! Uses rate-limited in-memory links (`MemNet`) in place of radios.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::iroh::protocol::{AcceptError, ProtocolHandler, Router};
use mycel_net::iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets};
use mycel_net::link::{Link, MemNet, MycelPathSelector, PathKind};

const ALPN: &[u8] = b"test/media";
const KB: u64 = 1000;

#[derive(Debug, Clone)]
struct Sink;

impl ProtocolHandler for Sink {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
            let mut total = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
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
    _router: Router,
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
    tokio::time::sleep(Duration::from_millis(2500)).await;
    Pair { conn, _router: router, _a: a }
}

fn link(n: u64, kind: PathKind, rate: u64, latency_ms: u64) -> MemNet {
    let net = MemNet::new(n, kind);
    net.set_rate_limit(Some(rate));
    net.set_latency(Duration::from_millis(latency_ms));
    net
}

fn selected(conn: &Connection) -> Option<PathKind> {
    conn.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()))
}

/// Bytes sent on each medium so far.
fn sent(conn: &Connection, kind: PathKind) -> u64 {
    conn.paths().iter().filter(|p| PathKind::of(p.remote_addr()) == kind).map(|p| p.stats().udp_tx.bytes).sum()
}

/// Send `total` bytes on one stream and wait for the receiver's count.
async fn transfer(conn: &Connection, total: u64, timeout: Duration) -> Duration {
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let chunk = vec![0x5au8; 16 * 1024];
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        tx.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
    }
    tx.finish().unwrap();
    let got = tokio::time::timeout(timeout, rx.read_to_end(8)).await.expect("transfer finished").unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), sent, "every byte arrived");
    start.elapsed()
}

/// UWB (600 KB/s) next to 802.15.4 (15 KB/s): traffic goes over UWB, the
/// slow radio stays a backup, and carries on alone when UWB is cut.
#[tokio::test(flavor = "multi_thread")]
async fn uwb_beats_802154_and_falls_back_to_it() {
    let uwb = link(8, PathKind::Uwb, 600 * KB, 5);
    let lowpan = link(9, PathKind::Ieee802154, 15 * KB, 10);
    let p = pair(&[&uwb, &lowpan]).await;
    assert_eq!(selected(&p.conn), Some(PathKind::Uwb));
    let before = sent(&p.conn, PathKind::Ieee802154);
    let took = transfer(&p.conn, 1200 * KB, Duration::from_secs(30)).await;
    let on_lowpan = sent(&p.conn, PathKind::Ieee802154) - before;
    eprintln!("1.2 MB over UWB in {took:?}; {on_lowpan} B on 802.15.4");
    assert!(took < Duration::from_secs(6), "at UWB speed, not held back: {took:?}");
    assert!(on_lowpan < 60 * KB, "802.15.4 only carried probes: {on_lowpan} B");

    uwb.cut();
    let took = transfer(&p.conn, 40 * KB, Duration::from_secs(60)).await;
    eprintln!("40 KB over 802.15.4 after UWB was cut: {took:?}");
    assert_eq!(selected(&p.conn), Some(PathKind::Ieee802154));
}

/// A link whose medium promises 1 MB/s ("Other") but delivers 20 KB/s, next
/// to a Bluetooth-kind link that really does 400 KB/s: it starts on the
/// promising one, measures, and moves to the one that is actually faster.
#[tokio::test(flavor = "multi_thread")]
async fn measurements_override_a_wrong_prior() {
    let liar = link(10, PathKind::Other, 20 * KB, 5);
    let fast_bt = link(0, PathKind::Bluetooth, 400 * KB, 5);
    let p = pair(&[&liar, &fast_bt]).await;
    assert_eq!(selected(&p.conn), Some(PathKind::Other), "the prior picks first");
    let took = transfer(&p.conn, 1500 * KB, Duration::from_secs(90)).await;
    let (on_liar, on_bt) = (sent(&p.conn, PathKind::Other), sent(&p.conn, PathKind::Bluetooth));
    eprintln!("1.5 MB in {took:?}: {} KB on the slow link, {} KB on the fast one", on_liar / KB, on_bt / KB);
    assert_eq!(selected(&p.conn), Some(PathKind::Bluetooth), "moved to what measured faster");
    assert!(on_bt > on_liar, "most bytes on the faster link");
    // all of it at 20 KB/s would take 75 s
    assert!(took < Duration::from_secs(30), "{took:?}");
}
