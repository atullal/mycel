//! Beyond one mesh: Bluetooth-only devices on different "continents" reach
//! each other through gateways and the internet, end to end.
//!
//! In-process: the "internet" is loopback IP between devices that have it
//! (each knows the others' addresses, standing in for DNS); radios are
//! `MemNet`s; the global record directory is a shared `MemDirectory`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::mesh::directory::{self, Directory, MemDirectory};
use mycel_net::{ExtraProtocol, MeshOptions, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;
use tokio::sync::mpsc;

/// These tests time emulated radios (path choice, failover, timeouts): side
/// by side on a small machine they starve each other of CPU and timers (seen
/// on 4-core Windows runners), so they run one at a time.
static RADIOS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const BULK: &[u8] = b"test/global-bulk";

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

/// A Bluetooth "radio" between devices: ~100 KB/s, 10 ms each way.
fn ble(n: u64) -> MemNet {
    let m = MemNet::radio(n, PathKind::Bluetooth);
    m.set_rate_limit(Some(100_000));
    m.set_latency(Duration::from_millis(10));
    m
}

/// A device on the given radios; `internet`: it also has IP (a gateway, or
/// a device elsewhere on the internet).
async fn device(name: &str, radios: &[&MemNet], internet: bool, dir: &MemDirectory) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = internet;
    opts.links = radios.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    opts.mesh = Some(MeshOptions {
        announce_every: Duration::from_millis(500),
        internet: Some(internet),
        directory: Some(Arc::new(dir.clone())),
        ..MeshOptions::default()
    });
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

/// The internet devices learn each other's addresses (DNS, in real life).
fn internet(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
}

async fn has_record(dir: &MemDirectory, node: &Node) -> bool {
    match dir.get(node.id()).await {
        Some(b) => directory::open(&b, Some(&node.id())).is_some(),
        None => false,
    }
}

/// US: a Bluetooth-only phone three hops from its gateway. EU: a
/// Bluetooth-only phone behind another gateway. They sync a document live,
/// end to end, with nothing in between able to read it.
#[tokio::test(flavor = "multi_thread")]
async fn bluetooth_us_to_bluetooth_eu_through_two_gateways() {
    let _radios = RADIOS.lock().await;
    let dir = MemDirectory::new();
    let (e1, e2, e3, e4) = (ble(1), ble(2), ble(3), ble(4));
    let us = device("us-phone", &[&e1], false, &dir).await;
    let a = device("us-a", &[&e1, &e2], false, &dir).await;
    let b = device("us-b", &[&e2, &e3], false, &dir).await;
    let g_us = device("us-gateway", &[&e3], true, &dir).await;
    let g_eu = device("eu-gateway", &[&e4], true, &dir).await;
    let eu = device("eu-phone", &[&e4], false, &dir).await;
    internet(&[&g_us, &g_eu]);

    let t = Instant::now();
    for (who, n) in [("us-phone", &us), ("eu-phone", &eu)] {
        let mut ok = false;
        for _ in 0..200 {
            if has_record(&dir, n).await {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok, "{who} has a record");
    }
    eprintln!("records published after {:?} (directory holds {})", t.elapsed(), dir.len());
    let rec = directory::open(&dir.get(us.id()).await.unwrap(), None).unwrap();
    assert_eq!(rec.gateways.first().map(|(g, _)| *g), Some(g_us.id()), "the US phone is behind the US gateway");
    assert!(rec.gateways[0].1 > 0, "with its mesh cost");

    let (space, genesis) = us.create_space().unwrap();
    us.with_space(&space, |r| r.add_member(eu.keys().public(), Role::Writer)).unwrap().unwrap();
    eu.join_space(genesis).unwrap();
    let doc = Replica::new_doc_id();
    let secret = "hello Berlin, love Boston, over four Bluetooth hops";
    us.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", secret))).unwrap().unwrap();

    let t = Instant::now();
    eu.sync_with(us.id(), space, true).await.expect("live sync across the world");
    let first = t.elapsed();
    assert_eq!(eu.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({ "msg": secret }));
    // and back, on the warm connection
    let doc2 = Replica::new_doc_id();
    eu.with_space(&space, |r| r.change(doc2, |d| d.put(ROOT, "msg", "hallo zurück"))).unwrap().unwrap();
    let t = Instant::now();
    us.sync_with(eu.id(), space, false).await.unwrap();
    let second = t.elapsed();
    assert_eq!(us.with_space(&space, |r| r.doc_json(&doc2)).unwrap(), json!({ "msg": "hallo zurück" }));
    eprintln!("US<->EU sync: first {first:?} (lookups, dials, handshake), then {second:?}");

    let via = eu.peers()[&us.id()].clone();
    assert_eq!(via.via, Some(PathKind::Mesh));
    let route = via.mesh.expect("route info");
    assert!(route.gateway, "{route:?}");
    assert_eq!(route.via, g_eu.id(), "the EU phone leaves through its gateway");
    // what crossed which gateway, and the relays saw only ciphertext
    let (gu, ge) = (g_us.mesh().unwrap().stats(), g_eu.mesh().unwrap().stats());
    eprintln!(
        "US gateway: in {} out {}; EU gateway: in {} out {}",
        gu.gateway_in, gu.gateway_out, ge.gateway_in, ge.gateway_out
    );
    assert!(gu.gateway_in > 0 && gu.gateway_out > 0 && ge.gateway_in > 0 && ge.gateway_out > 0);
    assert!(a.mesh().unwrap().stats().frames_relayed > 0 && b.mesh().unwrap().stats().frames_relayed > 0);
    for relay in [&a, &b, &g_us, &g_eu] {
        assert!(relay.space_ids().is_empty(), "relays are in no space");
    }
    assert!(g_us.mesh().unwrap().records_published() > 0);
}

/// A Bluetooth-only device behind two gateways: an internet device's
/// connection to it uses both (two QUIC paths, one per gateway) and
/// survives losing one.
#[tokio::test(flavor = "multi_thread")]
async fn two_gateways_are_two_paths_and_fail_over() {
    let _radios = RADIOS.lock().await;
    let dir = MemDirectory::new();
    let (e1, e2) = (ble(5), ble(6));
    for e in [&e1, &e2] {
        e.set_rate_limit(Some(250_000));
    }
    let m = device("phone", &[&e1, &e2], false, &dir).await;
    let g1 = device("gateway-1", &[&e1], true, &dir).await;
    let g2 = device("gateway-2", &[&e2], true, &dir).await;
    let r = device("laptop-elsewhere", &[], true, &dir).await;
    internet(&[&g1, &g2, &r]);
    eventually("a record with both gateways", 20, || {
        let rt = tokio::runtime::Handle::current();
        let got = std::thread::scope(|s| s.spawn(|| rt.block_on(dir.get(m.id()))).join().unwrap());
        got.and_then(|b| directory::open(&b, None)).is_some_and(|r| r.gateways.len() == 2)
    })
    .await;

    let conn = r.connect(m.id(), BULK).await.expect("dial a Bluetooth-only device by key");
    eventually("a path through each gateway", 15, || {
        conn.paths().iter().filter(|p| PathKind::of(p.remote_addr()) == PathKind::Mesh).count() >= 2
    })
    .await;
    let total: u64 = 3 * 1024 * 1024;
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let t = Instant::now();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x42u8; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            tx.write_all(&chunk).await.unwrap();
            sent += chunk.len() as u64;
        }
        tx.finish().unwrap();
    });
    let mesh_tx = |c: &Connection| -> Vec<u64> {
        c.paths()
            .iter()
            .filter(|p| PathKind::of(p.remote_addr()) == PathKind::Mesh)
            .map(|p| p.stats().udp_tx.bytes)
            .collect()
    };
    eventually("half sent", 60, || mesh_tx(&conn).iter().sum::<u64>() >= total / 2).await;
    let per = mesh_tx(&conn);
    let half = t.elapsed();
    eprintln!("bytes per gateway path at half-way ({half:?}): {per:?}");
    assert!(per.iter().filter(|b| **b as f64 > total as f64 * 0.1).count() >= 2, "both gateways carry data: {per:?}");
    // which path goes through gateway 2 (it survives)
    let via_g2 = |c: &Connection| -> u64 {
        c.paths()
            .iter()
            .filter(|p| match p.remote_addr() {
                mycel_net::iroh::TransportAddr::Custom(a) => {
                    mycel_net::mesh::parse_mesh_addr(a).is_some_and(|(_, w)| w == g2.id())
                }
                _ => false,
            })
            .map(|p| p.stats().udp_tx.bytes)
            .sum()
    };
    e1.cut(); // gateway 1 out of range
    let cut_at = Instant::now();
    // the longest stretch with no new bytes on the surviving path
    let (mut last, mut last_change, mut longest) = (via_g2(&conn), Instant::now(), Duration::ZERO);
    let reader = tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(90), rx.read_to_end(8)).await });
    while !reader.is_finished() && cut_at.elapsed() < Duration::from_secs(90) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = via_g2(&conn);
        if now != last {
            longest = longest.max(last_change.elapsed());
            last = now;
            last_change = Instant::now();
        }
    }
    eprintln!(
        "failover: longest pause on the surviving gateway path after the cut: {longest:?} (no routing convergence needed)"
    );
    // bounded by the path idle timeout (5 s): data in flight on the dead
    // path leaves a hole that flow control waits on until loss detection
    assert!(longest < Duration::from_secs(5), "{longest:?}");
    writer.await.unwrap();
    let got = reader.await.unwrap().expect("finished").unwrap();
    assert_eq!(u64::from_le_bytes(got.try_into().unwrap()), total);
    let secs = t.elapsed().as_secs_f64();
    eprintln!(
        "3 MiB over two 250 KB/s gateway paths, one lost half-way: {secs:.1} s; first half at {:.0} KB/s (one path alone: 250)",
        total as f64 / 2.0 / half.as_secs_f64() / 1000.0
    );
    drop(g2);
}

/// A device with given keys (to name it in a space before it exists).
async fn device_with_keys(keys: Arc<DeviceKeys>, name: &str, radios: &[&MemNet], dir: &MemDirectory) -> Node {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = false;
    opts.links = radios.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    opts.mesh = Some(MeshOptions {
        announce_every: Duration::from_millis(500),
        internet: Some(false),
        directory: Some(Arc::new(dir.clone())),
        ..MeshOptions::default()
    });
    Node::spawn(keys, opts).await.unwrap()
}

/// No path ever exists between A and C. A mule walks from A's partition
/// to C's and the message goes with it: A's failed sync becomes a signed,
/// still-encrypted bundle; the mule carries it (it isn't a member and
/// can't read it); C applies it when the mule arrives, minutes later in
/// real life, seconds here. A short-lived bundle expires at the mule.
#[tokio::test(flavor = "multi_thread")]
async fn a_data_mule_carries_a_message_across_partitions() {
    let _radios = RADIOS.lock().await;
    let dir = MemDirectory::new();
    let (here, there) = (ble(7), ble(8));
    let a = device("a", &[&here], false, &dir).await;
    let mule = device("mule", &[&here, &there], false, &dir).await;
    let c_keys = Arc::new(DeviceKeys::generate());
    let c_id = c_keys.sign_pk();

    let (space, genesis) = a.create_space().unwrap();
    a.with_space(&space, |r| r.add_member(c_keys.public(), Role::Writer)).unwrap().unwrap();
    let doc = Replica::new_doc_id();
    a.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "carried by hand"))).unwrap().unwrap();
    // A's live sync to C fails (no path): it becomes a bundle
    a.changed(space);
    eventually("A makes a bundle for C", 30, || a.mesh().unwrap().dtn_stats().originated >= 1).await;
    // and a short-lived one, to see carriers drop expired bundles. Only
    // once A has a hop to the mule: before that it has no carrier, and a
    // bundle this short could expire at A before the next hand-off round
    eventually("A meets the mule", 20, || a.mesh().unwrap().connected_neighbours().contains(&mule.id())).await;
    let short =
        a.mesh().unwrap().send_bundle(c_id, bytes::Bytes::from_static(b"stale soon"), Duration::from_secs(5)).unwrap();
    eventually("the mule takes copies", 20, || {
        let s = mule.mesh().unwrap().dtn_stats();
        s.accepted >= 2
    })
    .await;
    assert!(mule.space_ids().is_empty(), "the mule is in no space");

    // the mule walks: out of A's range, into C's
    here.cut();
    eventually("the short-lived bundle expires at the carrier", 15, || {
        !mule.mesh().unwrap().holds_bundle(&short) && mule.mesh().unwrap().dtn_stats().expired >= 1
    })
    .await;
    let c = device_with_keys(c_keys, "c", &[&there], &dir).await;
    c.join_space(genesis).unwrap();
    let t = Instant::now();
    eventually("C has A's message", 30, || {
        c.with_space(&space, |r| r.doc_json(&doc)).ok() == Some(json!({ "msg": "carried by hand" }))
    })
    .await;
    eprintln!("mule: delivered {:?} after meeting C; mule stats {:?}", t.elapsed(), mule.mesh().unwrap().dtn_stats());
    // C's receipt clears the mule's copy
    eventually("the mule drops its delivered copy", 10, || mule.mesh().unwrap().dtn_stats().handed_on >= 1).await;
}

/// A contact with many bundles to pass on: all of them go over, a few at
/// a time (each one gets through whole), the next starting as soon as one
/// ends rather than at the next tick. None is turned away for having too
/// many streams open.
#[tokio::test(flavor = "multi_thread")]
async fn a_contact_hands_over_many_bundles() {
    let _radios = RADIOS.lock().await;
    let dir = MemDirectory::new();
    let here = ble(9);
    let a = device("a", &[&here], false, &dir).await;
    let mule = device("mule", &[&here], false, &dir).await;
    let c = DeviceKeys::generate().sign_pk();
    const N: u64 = 60;
    for i in 0..N {
        let payload = bytes::Bytes::from(vec![i as u8; 2048]);
        a.mesh().unwrap().send_bundle(c, payload, Duration::from_secs(600)).unwrap();
    }
    let t = Instant::now();
    eventually("the mule takes every bundle", 30, || mule.mesh().unwrap().dtn_stats().accepted >= N).await;
    eprintln!("{N} bundles handed over in {:?}; {:?}", t.elapsed(), mule.mesh().unwrap().dtn_stats());
    assert_eq!(mule.mesh().unwrap().dtn_stats().refused, 0);
}
