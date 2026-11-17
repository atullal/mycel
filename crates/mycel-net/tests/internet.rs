//! Against the real internet: n0's relay and DNS servers and the public
//! Mainline DHT. Ignored by default (they need the internet, and they
//! publish this computer's records under throwaway keys):
//!
//! ```sh
//! cargo test -p mycel-net --features dht --test internet -- --ignored --nocapture
//! ```
//!
//! The devices here don't relay and say the internet can't dial in to
//! them, so no IP address is published: only what Iroh's own publisher
//! always published (the relay server a device is connected to).

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::TransportAddr;
use mycel_net::{MeshOptions, NetMode, Node, NodeOptions, Services};

async fn device(name: &str, services: Services) -> Node {
    let mut opts = NodeOptions::new(NetMode::Internet, name);
    opts.services = services;
    opts.mesh = Some(MeshOptions { reachable: Some(false), internet_relay: false, ..MeshOptions::default() });
    Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap()
}

async fn eventually(what: &str, secs: u64, mut f: impl AsyncFnMut() -> bool) -> Duration {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if f().await {
            return start.elapsed();
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// With the default services, a device's own record (published by Mycel,
/// not by Iroh's publisher any more) reaches n0's DNS server, and another
/// device reads from it which relay server to dial.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "uses the internet: n0's relay and DNS servers and the public DHT"]
async fn a_record_reaches_the_default_services_and_resolves() {
    let a = device("internet-test-a", Services::default()).await;
    let b = device("internet-test-b", Services::default()).await;
    let took = eventually("b reads a's record, with a's relay server", 90, async || {
        b.published_record(a.id()).await.is_some_and(|r| r.addrs.iter().any(|x| matches!(x, TransportAddr::Relay(_))))
    })
    .await;
    let rec = b.published_record(a.id()).await.unwrap();
    eprintln!("a's record after {took:?}: {rec:?}");
    assert!(rec.addrs.iter().all(|x| matches!(x, TransportAddr::Relay(_))), "no IP address published");
    assert!(!rec.relay && rec.gateways.is_empty());
    for n in [&a, &b] {
        n.shutdown().await.unwrap();
    }
}

/// With no relay server and no DNS server, the DHT alone is joined, and
/// the device learns from it whether it is online.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "uses the internet: the public DHT"]
async fn the_dht_alone_is_joined() {
    let a = device("internet-test-c", Services::serverless()).await;
    let took = eventually("a has DHT nodes", 90, async || a.dht_status().await.is_some_and(|s| s.nodes > 0)).await;
    let status = a.dht_status().await.unwrap();
    eprintln!("on the DHT after {took:?}: {status:?}");
    let nodes = a.dht_nodes().await;
    assert!(!nodes.is_empty(), "nodes to remember for the next start");
    assert!(nodes.iter().all(|n| n.parse::<std::net::SocketAddrV4>().is_ok()), "{nodes:?}");
    eventually("the mesh sees it is online", 60, async || a.mesh().unwrap().has_internet()).await;
    a.shutdown().await.unwrap();
}
