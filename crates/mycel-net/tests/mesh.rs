//! Mesh: devices with no direct link reach each other through others, hop
//! by hop, over in-memory links (`MemNet`, one per radio "edge") in place of
//! radios. Relays aren't members of anything and can't read what they carry.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::{ExtraProtocol, MeshOptions, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use parking_lot::Mutex;
use serde_json::json;
use tokio::sync::mpsc;

/// Tests that measure speed (fps, throughput, rates) run one at a time:
/// side by side they starve each other of CPU and the numbers mean nothing.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const BULK: &[u8] = b"test/mesh-bulk";

async fn eventually(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// A device on the given edges, no IP, mesh on. Serves [`BULK`]: reads a
/// stream to the end and answers with the byte count.
async fn device(name: &str, edges: &[&MemNet], mesh: MeshOptions) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = false;
    opts.links = edges.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    opts.mesh = Some(mesh);
    let (tx, mut rx) = mpsc::unbounded_channel::<Connection>();
    opts.extra_protocols.push(ExtraProtocol { alpn: BULK.to_vec(), incoming: tx });
    tokio::spawn(async move {
        while let Some(conn) = rx.recv().await {
            tokio::spawn(sink(conn));
        }
    });
    Node::spawn(keys, opts).await.unwrap()
}

async fn sink(conn: Connection) {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        let mut total = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        while let Ok(Some(n)) = rx.read(&mut buf).await {
            total += n as u64;
        }
        let _ = tx.write_all(&total.to_le_bytes()).await;
        let _ = tx.finish();
    }
}

fn fast() -> MeshOptions {
    MeshOptions { announce_every: Duration::from_millis(500), ..MeshOptions::default() }
}

fn edge(n: u64) -> MemNet {
    MemNet::new(n, PathKind::PeerWifi)
}

/// `from` can reach `to` through the mesh.
async fn mesh_route(from: &Node, to: &Node) {
    let id = to.id();
    eventually("a mesh route", 20, || from.peers().get(&id).is_some_and(|p| p.links.contains(&PathKind::Mesh))).await;
}

/// Send `bytes` on one stream; returns how long until the far end had them.
async fn push(conn: &Connection, bytes: u64) -> Duration {
    let t = Instant::now();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let chunk = vec![0x5au8; 64 * 1024];
    let mut sent = 0;
    while sent < bytes {
        let n = chunk.len().min((bytes - sent) as usize);
        tx.write_all(&chunk[..n]).await.unwrap();
        sent += n as u64;
    }
    tx.finish().unwrap();
    let got = tokio::time::timeout(Duration::from_secs(120), rx.read_to_end(8)).await.expect("transfer").unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), bytes);
    t.elapsed()
}

/// A and C aren't in range of each other; B is in range of both. They
/// connect and sync through B, which isn't a member and never sees the
/// plaintext.
#[tokio::test(flavor = "multi_thread")]
async fn line_a_b_c_syncs_through_a_non_member() {
    let (ab, bc) = (edge(0), edge(1));
    let a = device("alice", &[&ab], fast()).await;
    let b = device("bob", &[&ab, &bc], fast()).await;
    let c = device("carol", &[&bc], fast()).await;

    // everything B relays, to look for plaintext in
    let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
    let tap = seen.clone();
    b.mesh().unwrap().set_tap(Some(Arc::new(move |p: &[u8]| tap.lock().extend_from_slice(p))));

    mesh_route(&a, &c).await;
    mesh_route(&c, &a).await;
    assert!(!a.peers()[&c.id()].links.iter().any(|k| *k != PathKind::Mesh), "no direct path A–C");

    let (space, genesis) = a.create_space().unwrap();
    a.with_space(&space, |r| r.add_member(c.keys().public(), Role::Writer)).unwrap().unwrap();
    c.join_space(genesis).unwrap();
    let doc = Replica::new_doc_id();
    let secret = "the quick brown fox jumps over the lazy mesh relay";
    a.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", secret))).unwrap().unwrap();
    c.sync_with(a.id(), space, true).await.unwrap();
    assert_eq!(c.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({ "msg": secret }));

    let via = c.peers()[&a.id()].clone();
    assert_eq!(via.via, Some(PathKind::Mesh));
    let route = via.mesh.expect("mesh route info");
    assert_eq!(route.via, b.id());
    assert_eq!(route.hops, 2);
    assert_eq!(route.via_name.as_deref(), Some("bob"));

    // B relayed it, holds nothing of it, and saw only ciphertext
    let stats = b.mesh().unwrap().stats();
    assert!(stats.frames_relayed > 0 && stats.bytes_relayed > 1000, "{stats:?}");
    assert!(b.space_ids().is_empty(), "the relay is in no space");
    let relayed = seen.lock().clone();
    assert_eq!(relayed.len() as u64, stats.bytes_relayed);
    let needle = &secret.as_bytes()[..16];
    assert!(!relayed.windows(needle.len()).any(|w| w == needle), "plaintext crossed the relay");
}

/// A space shared by `a` and `c`, `c` holding a copy.
async fn shared(a: &Node, c: &Node) -> mycel_trust::SpaceId {
    mesh_route(c, a).await;
    let (space, genesis) = a.create_space().unwrap();
    a.with_space(&space, |r| r.add_member(c.keys().public(), Role::Writer)).unwrap().unwrap();
    c.join_space(genesis).unwrap();
    c.sync_with(a.id(), space, true).await.unwrap();
    space
}

/// A route that appears after a connection is up becomes a path on it:
/// Iroh looks a peer's addresses up only while it has no working path, so
/// the node hands it new ones (`Endpoint::add_remote_addrs`). Before that,
/// a second route found a moment after connecting was never used.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_found_later_joins_the_live_connection() {
    let (ab, bc, ad, dc) = (edge(20), edge(21), edge(22), edge(23));
    let a = device("a", &[&ab, &ad], fast()).await;
    let _b = device("b", &[&ab, &bc], fast()).await;
    let c = device("c", &[&bc, &dc], fast()).await;
    mesh_route(&a, &c).await;
    let conn = a.connect(c.id(), BULK).await.unwrap();
    push(&conn, 10_000).await;
    let mesh_paths =
        |conn: &Connection| conn.paths().iter().filter(|p| PathKind::of(p.remote_addr()) == PathKind::Mesh).count();
    assert_eq!(mesh_paths(&conn), 1, "one route so far: {}", path_report(&conn));

    // D comes into range of both: a second route, after the connection
    let _d = device("d", &[&ad, &dc], fast()).await;
    eventually("a path over the new route", 20, || mesh_paths(&conn) >= 2).await;
    push(&conn, 10_000).await;
}

fn path_report(conn: &Connection) -> String {
    conn.paths()
        .iter()
        .map(|p| {
            let s = p.stats();
            format!(
                "[{:?} sel={} rtt={:?} tx={}B lost={} cwnd={}]",
                PathKind::of(p.remote_addr()),
                p.is_selected(),
                p.rtt(),
                s.udp_tx.bytes,
                s.lost_packets,
                s.cwnd
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn write_and_sync(a: &Node, c: &Node, space: mycel_trust::SpaceId, text: &str) {
    let doc = Replica::new_doc_id();
    a.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", text))).unwrap().unwrap();
    c.sync_with(a.id(), space, false).await.unwrap();
    assert_eq!(c.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({ "msg": text }));
}

/// Two disjoint relays, A–B–C and A–D–C, each over its own rate-limited
/// links: one QUIC connection uses both routes at once (two mesh paths,
/// aggregated like direct links) and survives losing one relay mid-transfer.
#[tokio::test(flavor = "multi_thread")]
async fn two_routes_aggregate_and_fail_over() {
    let _measuring = MEASURING.lock().await;
    const RATE: u64 = 400_000;
    let rated = |n| {
        let e = edge(n);
        e.set_rate_limit(Some(RATE));
        e
    };

    // one route only: the baseline
    let (ab, bc) = (rated(0), rated(1));
    let a1 = device("a1", &[&ab], fast()).await;
    let _b1 = device("b1", &[&ab, &bc], fast()).await;
    let c1 = device("c1", &[&bc], fast()).await;
    mesh_route(&a1, &c1).await;
    let conn = a1.connect(c1.id(), BULK).await.unwrap();
    push(&conn, 200_000).await; // warm up
    let bytes = 2_000_000;
    let one = bytes as f64 / push(&conn, bytes).await.as_secs_f64();
    eprintln!("one route: {}", path_report(&conn));
    eprintln!("  a1 {:?}\n  b1 {:?}", a1.mesh().unwrap().stats(), _b1.mesh().unwrap().stats());
    conn.close(0u32.into(), b"");

    // two disjoint routes
    let (ab, bc, ad, dc) = (rated(2), rated(3), rated(4), rated(5));
    let a = device("a", &[&ab, &ad], fast()).await;
    let b = device("b", &[&ab, &bc], fast()).await;
    let d = device("d", &[&ad, &dc], fast()).await;
    let c = device("c", &[&bc, &dc], fast()).await;
    let cid = c.id();
    eventually("both routes known", 20, || {
        a.mesh().unwrap().reachable().contains(&cid)
            && a.link_status().iter().any(|s| s.kind == PathKind::Mesh && s.peers >= 1)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await; // both routes announced
    let conn = a.connect(c.id(), BULK).await.unwrap();
    eventually("a QUIC path per route", 20, || {
        conn.paths().iter().filter(|p| PathKind::of(p.remote_addr()) == PathKind::Mesh).count() >= 2
    })
    .await;
    push(&conn, 200_000).await;
    tokio::time::sleep(Duration::from_millis(1500)).await; // selection sees both RTTs
    let two = (2 * bytes) as f64 / push(&conn, 2 * bytes).await.as_secs_f64();
    let ratio = two / one;
    eprintln!("two routes: {}", path_report(&conn));
    eprintln!(
        "  a {:?}\n  b {:?}\n  d {:?}",
        a.mesh().unwrap().stats(),
        b.mesh().unwrap().stats(),
        d.mesh().unwrap().stats()
    );
    eprintln!("one route {:.0} kB/s, two routes {:.0} kB/s: {ratio:.2}x", one / 1e3, two / 1e3);
    assert!(ratio > 1.5, "two routes carry {ratio:.2}x one route");
    let (sb, sd) = (b.mesh().unwrap().stats(), d.mesh().unwrap().stats());
    assert!(sb.bytes_relayed > 500_000 && sd.bytes_relayed > 500_000, "both relays carried data: {sb:?} {sd:?}");

    // B goes away mid-transfer: the transfer finishes through D alone
    let conn2 = conn.clone();
    let transfer = tokio::spawn(async move { push(&conn2, 3_000_000).await });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let cut = Instant::now();
    b.shutdown().await.unwrap();
    ab.cut();
    bc.cut();
    let took = tokio::time::timeout(Duration::from_secs(60), transfer).await.expect("finishes without B").unwrap();
    let rest = cut.elapsed();
    eprintln!("lost relay B; the rest of the transfer took {rest:?} (whole: {took:?})");
    // ~2 MB left at one route's rate is ~6.5 s. A path that dies used to hold
    // what it carried, and the ACKs, for its idle timeout and more (5-20 s
    // stalls; vendor/noq-proto/MYCEL_PATCH.md §3).
    assert!(rest < Duration::from_secs(15), "the rest took {rest:?} after losing B");
    let space = shared(&a, &c).await;
    write_and_sync(&a, &c, space, "after B left").await;
    assert_eq!(c.peers()[&a.id()].mesh.as_ref().map(|m| m.via), Some(d.id()));
}

/// What got across a saturated A–B–C line while A pushed C a bulk transfer.
struct Saturated {
    /// Round trips of small exchanges between A and C meanwhile.
    small: Vec<Duration>,
    /// A lost its route to C at some point.
    route_lost: bool,
    /// Bulk bytes per second.
    bulk_rate: f64,
    /// The first hop's radio (A–B), which the bulk transfer saturates.
    radio: mycel_net::link::RadioStats,
}

async fn saturated_line(n0: u64, kind: PathKind, rate: u64, bulk: u64) -> Saturated {
    let edge = |n| {
        let e = MemNet::radio(n, kind);
        e.set_rate_limit(Some(rate));
        e
    };
    let (ab, bc) = (edge(n0), edge(n0 + 1));
    let a = device("a", &[&ab], fast()).await;
    let _b = device("b", &[&ab, &bc], fast()).await;
    let c = device("c", &[&bc], fast()).await;
    mesh_route(&a, &c).await;
    // the small exchanges have a connection of their own, over the same route
    let small = a.connect(c.id(), BULK).await.unwrap();
    push(&small, 1).await;
    let conn = a.connect(c.id(), BULK).await.unwrap();
    let transfer = tokio::spawn(async move { push(&conn, bulk).await });
    tokio::time::sleep(Duration::from_secs(2)).await; // the queues fill
    let cid = c.id();
    let mut rtts = Vec::new();
    let mut route_lost = false;
    while !transfer.is_finished() {
        rtts.push(push(&small, 1).await);
        route_lost |= !a.peers().get(&cid).is_some_and(|p| p.links.contains(&PathKind::Mesh));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let took = transfer.await.unwrap();
    rtts.sort();
    Saturated { small: rtts, route_lost, bulk_rate: bulk as f64 / took.as_secs_f64(), radio: ab.radio_stats() }
}

/// A bulk transfer saturates a two-hop route, on fast radios and on
/// Bluetooth-speed ones. The queues below the hops stay short, so the
/// small exchanges, announcements and acknowledgements sharing them don't
/// wait behind (and get dropped with) a full radio queue: on the fast
/// radios a small exchange crosses in tens of milliseconds where it took
/// half a second. The route stays up, and the bulk data still gets the
/// link.
#[tokio::test(flavor = "multi_thread")]
async fn control_traffic_crosses_a_saturated_hop() {
    let _measuring = MEASURING.lock().await;
    let ms = Duration::from_millis;
    // (name, radios, kind, rate, bulk bytes, small exchanges' median at most,
    // first radio's mean queueing at most, share of the rate for bulk at least)
    for (name, n0, kind, rate, bulk, max_median, max_wait, min_share) in [
        ("400 kB/s", 10, PathKind::PeerWifi, 400_000, 2_500_000, ms(150), ms(80), 0.6),
        ("Bluetooth, 20 kB/s", 12, PathKind::Bluetooth, 20_000, 120_000, ms(700), ms(250), 0.5),
    ] {
        let s = saturated_line(n0, kind, rate, bulk).await;
        let median = s.small[s.small.len() / 2];
        eprintln!(
            "{name}: bulk {:.0} B/s; {} small exchanges, median {median:?}, max {:?}; first radio: {} dropped, mean wait {:?}, max {:?}",
            s.bulk_rate,
            s.small.len(),
            s.small.last().unwrap(),
            s.radio.dropped,
            s.radio.mean_wait(),
            s.radio.max_wait
        );
        assert!(!s.route_lost, "{name}: the route went down under load");
        assert!(median < max_median, "{name}: small exchanges took {median:?} (median) across the saturated route");
        assert!(
            s.radio.mean_wait() < max_wait,
            "{name}: packets waited {:?} in the radio's queue",
            s.radio.mean_wait()
        );
        assert!(s.bulk_rate > rate as f64 * min_share, "{name}: bulk data got {:.0} B/s of {rate}", s.bulk_rate);
    }
}

/// A–B–C–D–E in a line: E is reachable from A four hops away, and each hop
/// adds little latency of its own.
#[tokio::test(flavor = "multi_thread")]
async fn five_device_line_latency_per_hop() {
    let _measuring = MEASURING.lock().await;
    let edges: Vec<MemNet> = (0..4).map(edge).collect();
    let mut nodes = Vec::new();
    for i in 0..5 {
        let mine: Vec<&MemNet> =
            edges.iter().enumerate().filter(|(e, _)| *e + 1 == i || *e == i).map(|(_, n)| n).collect();
        nodes.push(device(&format!("n{i}"), &mine, fast()).await);
    }
    let a = &nodes[0];
    for far in &nodes[2..] {
        mesh_route(a, far).await;
    }
    let mut rtts = Vec::new();
    for (hops, far) in nodes.iter().enumerate().skip(1) {
        let conn = a.connect(far.id(), BULK).await.unwrap();
        let mut best = Duration::MAX;
        for _ in 0..20 {
            best = best.min(push(&conn, 1).await);
        }
        rtts.push(best);
        if hops >= 2 {
            let route = a.peers()[&far.id()].mesh.clone().expect("mesh route");
            assert_eq!(route.via, nodes[1].id());
            assert_eq!(route.hops as usize, hops);
        }
        eprintln!("{hops} hop(s): best round trip {best:?}");
    }
    let per_hop = (rtts[3].as_secs_f64() - rtts[0].as_secs_f64()) / 3.0;
    eprintln!("each extra hop adds {:.2} ms to a round trip (in-memory links, no radio delay)", per_hop * 1e3);
    assert!(per_hop < 0.010, "relaying adds under 10 ms per hop");
}

/// A–B–C plus a longer A–D–X–C: when B leaves, traffic carries on over the
/// longer route.
#[tokio::test(flavor = "multi_thread")]
async fn route_heals_when_a_middle_device_leaves() {
    let e: Vec<MemNet> = (0..5).map(edge).collect();
    let a = device("a", &[&e[0], &e[2]], fast()).await;
    let b = device("b", &[&e[0], &e[1]], fast()).await;
    let c = device("c", &[&e[1], &e[4]], fast()).await;
    let d = device("d", &[&e[2], &e[3]], fast()).await;
    let _x = device("x", &[&e[3], &e[4]], fast()).await;
    mesh_route(&a, &c).await;
    let space = shared(&a, &c).await;
    write_and_sync(&a, &c, space, "via b").await;

    b.shutdown().await.unwrap();
    e[0].cut();
    e[1].cut();
    let t = Instant::now();
    let (cid, did) = (c.id(), d.id());
    eventually("route through d", 20, || {
        a.mesh().unwrap().reachable().contains(&cid) && a.mesh().unwrap().connected_neighbours() == vec![did]
    })
    .await;
    write_and_sync(&a, &c, space, "via d and x").await;
    eprintln!("healed in {:?}", t.elapsed());
    let route = c.peers()[&a.id()].mesh.clone().expect("mesh route");
    assert_eq!(route.hops, 3);
}

/// Six devices in a ring: announcements stay bounded (each passed on once,
/// never back), and traffic doesn't loop.
#[tokio::test(flavor = "multi_thread")]
async fn ring_has_no_storms_or_loops() {
    let _measuring = MEASURING.lock().await;
    const N: usize = 6;
    let e: Vec<MemNet> = (0..N as u64).map(edge).collect();
    let mut nodes = Vec::new();
    for i in 0..N {
        nodes.push(device(&format!("r{i}"), &[&e[i], &e[(i + N - 1) % N]], fast()).await);
    }
    for i in 0..N {
        for j in 0..N {
            let dist = (i + N - j) % N;
            if dist > 1 && dist < N - 1 {
                mesh_route(&nodes[i], &nodes[j]).await;
            }
        }
    }
    let before: Vec<u64> = nodes.iter().map(|n| n.mesh().unwrap().stats().announcements_sent).collect();
    let secs = 5.0;
    tokio::time::sleep(Duration::from_secs_f64(secs)).await;
    let periods = secs / fast().announce_every.as_secs_f64();
    // own: one per period to each of 2 neighbours; others': each of N-1
    // origins passed on once per period, to the 1 other neighbour
    let expected = periods * (2.0 + (N - 1) as f64);
    for (n, b) in nodes.iter().zip(before) {
        let sent = (n.mesh().unwrap().stats().announcements_sent - b) as f64;
        eprintln!("sent {sent} announcements in {secs} s (about {expected} expected)");
        assert!(sent <= expected * 1.5, "{sent} announcements in {secs}s (expected about {expected})");
    }

    // traffic to the far side of the ring arrives, and nothing loops
    let (a, far) = (&nodes[0], &nodes[3]);
    let space = shared(a, far).await;
    for i in 0..10 {
        write_and_sync(a, far, space, &format!("round {i}")).await;
    }
    assert_eq!(far.peers()[&a.id()].mesh.as_ref().map(|m| m.hops), Some(3));
    for n in &nodes {
        let s = n.mesh().unwrap().stats();
        assert_eq!(s.dropped_ttl, 0, "a frame went round in circles: {s:?}");
    }
}

/// A relay caps what it carries for others; one that doesn't relay at all
/// isn't routed through.
#[tokio::test(flavor = "multi_thread")]
async fn relay_budget_is_enforced() {
    let _measuring = MEASURING.lock().await;
    const BUDGET: u64 = 100_000;
    let (ab, bc) = (edge(0), edge(1));
    let a = device("a", &[&ab], fast()).await;
    let stingy = MeshOptions { relay_rate_per_neighbour: BUDGET, relay_rate_total: BUDGET * 4, ..fast() };
    let b = device("b", &[&ab, &bc], stingy).await;
    let c = device("c", &[&bc], fast()).await;
    mesh_route(&a, &c).await;
    let conn = a.connect(c.id(), BULK).await.unwrap();
    let before = b.mesh().unwrap().stats();
    let bytes = 500_000;
    let took = push(&conn, bytes).await;
    let after = b.mesh().unwrap().stats();
    let rate = (after.bytes_relayed - before.bytes_relayed) as f64 / took.as_secs_f64();
    eprintln!("{bytes} bytes through a {BUDGET} B/s relay took {took:?}: {rate:.0} B/s relayed");
    // one second of burst; the acks coming back have their own budget
    assert!(took.as_secs_f64() >= (bytes - BUDGET) as f64 / BUDGET as f64 * 0.8, "took {took:?}");
    assert!(rate <= BUDGET as f64 * 2.0 * 1.15, "relayed {rate:.0} B/s");
    assert!(after.dropped_budget > before.dropped_budget, "{after:?}");

    let (pq, qr) = (edge(2), edge(3));
    let p = device("p", &[&pq], fast()).await;
    let selfish = MeshOptions { relay: false, ..fast() };
    let _q = device("q", &[&pq, &qr], selfish).await;
    let r = device("r", &[&qr], fast()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!p.mesh().unwrap().reachable().contains(&r.id()), "nobody routes through a device that doesn't relay");
}

/// One relay reached over two links: the hop itself is a multipath QUIC
/// connection, so when the hop's fast link dies mid-transfer the relay keeps
/// carrying the traffic over its other link.
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_moves_between_its_links() {
    let wifi = MemNet::new(8, PathKind::PeerWifi);
    wifi.set_rate_limit(Some(1_000_000));
    let bt = MemNet::new(0, PathKind::Bluetooth);
    bt.set_rate_limit(Some(200_000));
    let bc = edge(9);
    let a = device("a", &[&wifi, &bt], fast()).await;
    let b = device("b", &[&wifi, &bt, &bc], fast()).await;
    let c = device("c", &[&bc], fast()).await;
    mesh_route(&a, &c).await;
    let bid = b.id();
    eventually("both links to the relay", 20, || a.peers().get(&bid).is_some_and(|p| p.links.len() == 2)).await;
    let space = shared(&a, &c).await;
    let conn = a.connect(c.id(), BULK).await.unwrap();
    push(&conn, 100_000).await;
    let transfer = tokio::spawn(async move { push(&conn, 1_500_000).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!transfer.is_finished(), "still going when the link is cut");
    wifi.cut();
    let took = tokio::time::timeout(Duration::from_secs(60), transfer).await.expect("finishes over bluetooth").unwrap();
    eprintln!("hop lost its peer-to-peer Wi-Fi mid-transfer; finished over Bluetooth in {took:?}");
    write_and_sync(&a, &c, space, "the hop is on bluetooth now").await;
    assert_eq!(c.peers()[&a.id()].mesh.as_ref().map(|m| m.via), Some(b.id()));
}

/// The mesh doesn't care what the hops are: here one is peer-to-peer Wi-Fi
/// and the next a (slow) Bluetooth link.
#[tokio::test(flavor = "multi_thread")]
async fn hops_over_peer_wifi_and_bluetooth() {
    let wifi = MemNet::new(7, PathKind::PeerWifi);
    let bt = MemNet::new(0, PathKind::Bluetooth);
    bt.set_rate_limit(Some(30_000));
    let a = device("a", &[&wifi], fast()).await;
    let b = device("b", &[&wifi, &bt], fast()).await;
    let c = device("c", &[&bt], fast()).await;
    assert!(b.link_status().iter().any(|s| s.kind == PathKind::Bluetooth));
    mesh_route(&a, &c).await;
    let space = shared(&a, &c).await;
    write_and_sync(&a, &c, space, "over wi-fi, then bluetooth").await;
    write_and_sync(&c, &a, space, "and back").await;
    assert_eq!(a.peers()[&c.id()].via, Some(PathKind::Mesh));
}
