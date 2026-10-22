//! The `buggify!` sites, fired in a real exchange: three devices on two
//! emulated Bluetooth radios (A and C two hops apart, through a relay)
//! sync a document end to end and carry a bundle while every injection
//! site is on. Each site must fire at least once, and the exchange must
//! still get through: each injected path is one the code has to survive.
//!
//! Needs the `sim` feature: `cargo test -p mycel-net --features sim --test buggify`.
#![cfg(feature = "sim")]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::buggify::{self, Run};
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::mesh::directory::MemDirectory;
use mycel_net::{MeshOptions, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

/// Every site in the crate, as written at the call site.
const SITES: [&str; 6] = [
    "pool: dial fails spuriously",
    "pool: connection lost right after the dial",
    "mesh: hop queue full",
    "mesh: summary stream lost at the receiver",
    "mesh: summary stream fails to open",
    "mesh: timer fires late",
];

/// Labels: A, the relay, C.
const A: u64 = 0;
const RELAY: u64 = 1;
const C: u64 = 2;

/// A Bluetooth "radio": ~100 KB/s, 10 ms each way.
fn ble(n: u64) -> MemNet {
    let m = MemNet::radio(n, PathKind::Bluetooth);
    m.set_rate_limit(Some(100_000));
    m.set_latency(Duration::from_millis(10));
    m
}

async fn device(keys: Arc<DeviceKeys>, name: &str, radios: &[&MemNet], dir: &MemDirectory) -> Node {
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

/// A seed whose run takes each injected path early, so one short exchange
/// reaches them all: each dialing device's first dial fails, its second
/// hands out a connection that is already closed, and its third works; the
/// relay's first summary stream fails to open; each device loses the first
/// summary stream it receives. Every other draw is whatever the seed makes.
fn seed() -> u64 {
    let f = buggify::fires;
    let (dial, lost) = (SITES[0], SITES[1]);
    (1..u64::MAX)
        .find(|&s| {
            [A, C].iter().all(|&l| {
                f(s, dial, l, 0) && !f(s, dial, l, 1) && !f(s, dial, l, 2) && f(s, lost, l, 0) && !f(s, lost, l, 1)
            }) && f(s, SITES[4], RELAY, 0)
                && [A, RELAY, C].iter().all(|&l| f(s, SITES[3], l, 0))
        })
        .expect("some seed")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_site_fires_and_the_exchange_survives() {
    let run = Run::every_site(seed());
    let dir = MemDirectory::new();
    let (here, there) = (ble(31), ble(32));
    let keys: Vec<Arc<DeviceKeys>> = (0..3).map(|_| Arc::new(DeviceKeys::generate())).collect();
    for (label, k) in keys.iter().enumerate() {
        run.add(k.sign_pk().0, label as u64);
    }
    let a = device(keys[0].clone(), "a", &[&here], &dir).await;
    let relay = device(keys[1].clone(), "relay", &[&here, &there], &dir).await;
    let c = device(keys[2].clone(), "c", &[&there], &dir).await;

    let (space, genesis) = a.create_space().unwrap();
    a.with_space(&space, |r| r.add_member(keys[2].public(), Role::Writer)).unwrap().unwrap();
    c.join_space(genesis).unwrap();
    let doc = Replica::new_doc_id();
    // a bundle for a device that never shows up: the carriers summarise it
    // to each other for as long as the test runs
    let absent = DeviceKeys::generate().sign_pk();
    let until = Instant::now() + Duration::from_secs(90);
    let mut synced = 0u32;
    let mut i = 0u32;
    loop {
        i += 1;
        a.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "n", i as i64))).unwrap().unwrap();
        if let Some(m) = a.mesh() {
            let _ = m.send_bundle(absent, bytes::Bytes::from(vec![i as u8; 512]), Duration::from_secs(600));
        }
        if tokio::time::timeout(Duration::from_secs(10), a.sync_with(c.id(), space, false))
            .await
            .is_ok_and(|r| r.is_ok())
            && c.with_space(&space, |r| r.doc_json(&doc)).ok() == Some(json!({ "n": i }))
        {
            synced += 1;
        }
        let fired: BTreeSet<&str> = run.fired().keys().map(|p| p.trim_start_matches("mycel-buggify-site:")).collect();
        if synced >= 2 && SITES.iter().all(|s| fired.contains(s)) {
            break;
        }
        assert!(
            Instant::now() < until,
            "after {i} rounds ({synced} synced end to end), sites that never fired: {:?}; fired: {:?}",
            SITES.iter().filter(|s| !fired.contains(*s)).collect::<Vec<_>>(),
            run.fired()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!("{i} rounds, {synced} synced end to end; fired {:?}", run.fired());
    drop(relay);
}
