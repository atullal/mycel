//! The driver's view of a hop connection (in-memory links, real QUIC).

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::presets;
use iroh::endpoint::transports::{PathSelection, PathSelectionContext, PathSelector};
use iroh::protocol::{AcceptError, ProtocolHandler, Router as Routes};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use mycel_crypto::DeviceKeys;

use super::{ALPN, Mesh, MeshOptions};
use crate::link::{Link, MemNet, PathKind, transport_config};

const PLAIN: &[u8] = b"test/plain";

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

/// Keeps connections open.
#[derive(Debug, Clone)]
struct Hold;

impl ProtocolHandler for Hold {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        conn.closed().await;
        Ok(())
    }
}

struct Device {
    keys: Arc<DeviceKeys>,
    ep: Endpoint,
    mesh: Mesh,
    _routes: Routes,
}

async fn device(keys: Arc<DeviceKeys>, only: PathKind, nets: &[&MemNet]) -> Device {
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&keys.seed()))
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .path_selector(Arc::new(Only(only)))
        .transport_config(transport_config())
        .alpns(vec![ALPN.to_vec(), PLAIN.to_vec()]);
    for n in nets {
        b = b.add_custom_transport(n.link(keys.sign_pk()).transport());
    }
    let ep = b.bind().await.unwrap();
    let mesh = Mesh::new(keys.clone(), "test", MeshOptions { store_and_forward: None, ..MeshOptions::default() });
    let routes = Routes::builder(ep.clone()).accept(ALPN, mesh.protocol()).accept(PLAIN, Hold).spawn();
    mesh.attach(ep.clone());
    Device { keys, ep, mesh, _routes: routes }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Each end selects its own path to the other, and only the end that dialed
/// a connection opens paths on it. So on a hop the neighbour dialed, the
/// path our end selected for them may be missing, and then no path there is
/// selected: the hop must still get a measured cost (else routing uses a
/// guess) and its congestion window (else relayed frames queue against the
/// minimum and drop).
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_the_neighbour_dialed_has_a_cost_and_a_window() {
    let wifi = MemNet::new(1, PathKind::PeerWifi);
    let bt = MemNet::new(1, PathKind::Bluetooth);
    let (k1, k2) = (Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()));
    // the lower key dials the hop: make that Alice
    let (ka, kb) = if k1.sign_pk() < k2.sign_pk() { (k1, k2) } else { (k2, k1) };
    // Alice's end selects Bluetooth, Bob's peer-to-peer Wi-Fi.
    let a = device(ka, PathKind::Bluetooth, &[&wifi, &bt]).await;
    let b = device(kb, PathKind::PeerWifi, &[&wifi, &bt]).await;
    let on = |n: &MemNet, d: &Device| {
        EndpointAddr::from_parts(d.ep.id(), [TransportAddr::Custom(n.addr_of(&d.keys.sign_pk()))])
    };
    let selected = |c: &iroh::endpoint::Connection| {
        c.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()))
    };

    // Bob reaches Alice over Wi-Fi first: his end selects it.
    let b_to_a = b.ep.connect(on(&wifi, &a), PLAIN).await.unwrap();
    eventually("bob selects wi-fi", || selected(&b_to_a) == Some(PathKind::PeerWifi)).await;
    // Wi-Fi goes out of range (else Alice's end would open a Wi-Fi path on
    // her connections too), and Alice reaches Bob over Bluetooth.
    wifi.cut();
    let a_to_b = a.ep.connect(on(&bt, &b), PLAIN).await.unwrap();
    eventually("alice selects bluetooth", || selected(&a_to_b) == Some(PathKind::Bluetooth)).await;

    // They're neighbours: Alice (the lower key) dials the hop, on Bluetooth.
    let (pa, pb) = (a.keys.sign_pk(), b.keys.sign_pk());
    a.mesh.set_direct(pb, true);
    b.mesh.set_direct(pa, true);
    eventually("the hop is up on both ends", || {
        a.mesh.connected_neighbours().contains(&pb) && b.mesh.connected_neighbours().contains(&pa)
    })
    .await;
    let hop = b.mesh.d.conn(&pa).unwrap();
    assert!(hop.side().is_server(), "alice dialed the hop");
    let kinds: Vec<PathKind> = hop.paths().iter().map(|p| PathKind::of(p.remote_addr())).collect();
    assert_eq!(kinds, vec![PathKind::Bluetooth], "the hop has only bluetooth");
    assert_eq!(selected(&hop), None, "bob's end selected wi-fi: nothing on the hop is selected");

    // Bob's end still measures the hop and knows its window.
    let mut costs = Vec::new();
    eventually("bob measures the hop", || {
        costs = b.mesh.d.hop_costs();
        costs.iter().any(|(pk, _)| *pk == pa)
    })
    .await;
    assert!(b.mesh.d.hops.lock().get(&pa).is_some_and(|h| h.path.is_some()), "the hop's path is remembered");
    let window = b.mesh.d.hop_window(&pa, &hop, None);
    assert!(window >= 1200, "bob's end knows the hop's congestion window ({window})");
    // ... as Alice's end, where the hop's path is selected, does
    assert!(a.mesh.d.hop_costs().iter().any(|(pk, _)| *pk == pb));
    let a_hop = a.mesh.d.conn(&pb).unwrap();
    assert!(a.mesh.d.hop_window(&pb, &a_hop, None) >= 1200);

    for c in [&b_to_a, &a_to_b] {
        c.close(0u32.into(), b"done");
    }
}

/// The queue management on a hop ([`super::Aqm`]), on a fake clock: a brief
/// or short queue gets no drops; a standing one gets its first drop after
/// an interval and then more, faster; a queue the drops don't drain (not
/// ours) is taken as the base instead of starving our traffic; and a slow
/// link is allowed a few packets' time of queue.
#[test]
fn hop_queue_management_drops_only_for_a_standing_queue() {
    use super::Aqm;
    let ms = Duration::from_millis;
    let t0 = Instant::now();
    let mut q = Aqm::new(t0);
    q.rate = 400_000.0; // 20 ms target, 100 ms interval
    assert!(!q.drop_now(ms(5), t0), "base 5 ms");
    // 15 ms of queue for a second, or 200 ms of it for half an interval
    assert!((1..=100).all(|i| !q.drop_now(ms(20), t0 + ms(10 * i))));
    assert!((1..=9).all(|i| !q.drop_now(ms(205), t0 + ms(1000 + 5 * i))));
    assert!(!q.drop_now(ms(10), t0 + ms(1050)));

    // 50 ms of queue that stays: a drop after an interval, then closer ones
    let start = t0 + ms(1100);
    let drops: Vec<u64> = (0..100).filter(|i| q.drop_now(ms(55), start + ms(5 * i))).map(|i| 5 * i).collect();
    assert_eq!(drops.first(), Some(&100), "{drops:?}");
    assert!(drops.len() >= 5, "{drops:?}");
    let gaps: Vec<u64> = drops.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.windows(2).all(|g| g[1] <= g[0]), "drops come faster: {drops:?}");

    // it doesn't drain: someone else's queue. After a second, no more drops
    // at that delay; it is the base now.
    let later = start + ms(1200);
    assert!((0..400).filter(|i| q.drop_now(ms(55), later + ms(5 * i))).count() <= 1);
    assert!(q.base.is_some_and(|b| b >= ms(50)), "{:?}", q.base);
    // ... and the base comes back down once it does drain
    assert!(!q.drop_now(ms(6), later + ms(2100)));
    assert_eq!(q.base, Some(ms(6)));

    // a burst that the drops do drain, a quarter every half second: they
    // go on until it's gone, and the base stays
    let mut d = Aqm::new(t0);
    d.rate = 400_000.0;
    assert!(!d.drop_now(ms(5), t0));
    let mut rtt = 300.0_f64;
    let mut dropped = 0;
    for i in 1..=600 {
        dropped += d.drop_now(Duration::from_secs_f64(rtt / 1000.0), t0 + ms(5 * i)) as u32;
        rtt = (rtt * 0.9971).max(5.0); // -25% per 100 steps (0.5 s)
    }
    assert!(dropped >= 10, "{dropped} drops");
    assert!(d.base.is_some_and(|b| b < ms(6)), "{:?}", d.base);

    // a 20 kB/s link: three packets' time of queue (180 ms) is fine
    let mut slow = Aqm::new(t0);
    slow.rate = 20_000.0;
    assert!(!slow.drop_now(ms(10), t0));
    assert!((1..=300).all(|i| !slow.drop_now(ms(160), t0 + ms(10 * i))));
}
