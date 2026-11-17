//! Relays among the devices themselves: two devices behind routers reach
//! each other through a third device, with no relay server and no DNS
//! server, end to end.
//!
//! In-process: every device has loopback IP. "Behind a router" means nobody
//! is told its address and it publishes none, so only what it dials itself
//! reaches it. The global record directory is a shared `MemDirectory`
//! (standing in for the DHT).

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::mesh::directory::{self, Directory, MemDirectory, Record};
use mycel_net::{ExtraProtocol, MeshOptions, NetMode, Node, NodeOptions, PathKind};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;
use tokio::sync::mpsc;

const BULK: &[u8] = b"test/relay-bulk";

async fn eventually(what: &str, secs: u64, mut f: impl AsyncFnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// A device on the internet. `reachable`: the internet can dial in to it
/// (a public address); otherwise it is behind a router.
async fn device(name: &str, reachable: bool, dir: &MemDirectory, tune: impl FnOnce(&mut MeshOptions)) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    let mut mesh = MeshOptions {
        announce_every: Duration::from_millis(500),
        internet: Some(true),
        reachable: Some(reachable),
        directory: Some(Arc::new(dir.clone())),
        ..MeshOptions::default()
    };
    tune(&mut mesh);
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

/// Count what arrives on each stream and say how much.
async fn sink(conn: Connection) {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        let mut total = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(Some(n)) = rx.read(&mut buf).await {
            total += n as u64;
        }
        let _ = tx.write_all(&total.to_le_bytes()).await;
        let _ = tx.finish();
    }
}

async fn record(dir: &MemDirectory, node: &Node) -> Option<Record> {
    directory::read(&dir.get(node.id()).await?, Some(&node.id()))
}

/// Wait until `node`'s record names exactly these relays.
async fn behind(dir: &MemDirectory, node: &Node, relays: &[&Node]) {
    let mut want: Vec<_> = relays.iter().map(|r| r.id()).collect();
    want.sort();
    eventually(&format!("{}'s record names its relays", node.id().short()), 20, async || {
        record(dir, node).await.is_some_and(|r| {
            let mut got: Vec<_> = r.gateways.iter().map(|(k, _)| *k).collect();
            got.sort();
            got == want && r.addrs.is_empty()
        })
    })
    .await;
}

/// Alice and Bob are each behind a router; a third device, which the
/// internet can reach, relays. Each asks it, names it in its record, and
/// they sync a document through it. The relay is in no space and reads
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn two_devices_behind_routers_sync_through_a_relay() {
    let dir = MemDirectory::new();
    let relay = device("relay", true, &dir, |_| {}).await;
    let alice = device("alice", false, &dir, |_| {}).await;
    let bob = device("bob", false, &dir, |_| {}).await;

    // the relay says so in its record, with where to dial it
    eventually("the relay's record", 10, async || {
        record(&dir, &relay).await.is_some_and(|r| r.relay && !r.addrs.is_empty())
    })
    .await;
    assert!(relay.mesh().unwrap().relay_status().relaying);
    // a device behind a router says nothing until it has a relay: no address of its own
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(record(&dir, &alice).await.is_none() && record(&dir, &bob).await.is_none());

    // each is told of the relay (a contact's device, say), reads its record,
    // connects, asks, and names it in its own
    let t = Instant::now();
    for d in [&alice, &bob] {
        d.mesh().unwrap().set_relay_candidates(vec![relay.id()]);
    }
    behind(&dir, &alice, &[&relay]).await;
    behind(&dir, &bob, &[&relay]).await;
    eprintln!("both behind the relay after {:?}", t.elapsed());
    assert_eq!(relay.mesh().unwrap().relay_status().clients, 2);
    assert_eq!(alice.mesh().unwrap().relay_status().relays, vec![relay.id()]);

    // neither knows the other's address; they find each other by key
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    let doc = Replica::new_doc_id();
    let secret = "through a stranger's laptop, unread";
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", secret))).unwrap().unwrap();
    let t = Instant::now();
    bob.sync_with(alice.id(), space, true).await.expect("sync through the relay");
    eprintln!("first sync through the relay: {:?}", t.elapsed());
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({ "msg": secret }));
    // and back
    let doc2 = Replica::new_doc_id();
    bob.with_space(&space, |r| r.change(doc2, |d| d.put(ROOT, "msg", "and back"))).unwrap().unwrap();
    alice.sync_with(bob.id(), space, false).await.unwrap();
    assert_eq!(alice.with_space(&space, |r| r.doc_json(&doc2)).unwrap(), json!({ "msg": "and back" }));

    let stats = relay.mesh().unwrap().stats();
    eprintln!("the relay carried {} frames between internet hops", stats.relayed_internet);
    assert!(stats.relayed_internet > 0);
    assert!(relay.space_ids().is_empty(), "the relay is in no space");
    for n in [&alice, &bob, &relay] {
        n.shutdown().await.unwrap();
    }
}

/// A device that isn't reachable doesn't relay, a reachable one with
/// relaying switched off doesn't either, and one on mobile data neither: a
/// device behind a router asks none of them.
#[tokio::test(flavor = "multi_thread")]
async fn only_devices_that_say_they_relay_are_asked() {
    let dir = MemDirectory::new();
    let hidden = device("also-behind-a-router", false, &dir, |_| {}).await;
    let unwilling = device("reachable-but-not-relaying", true, &dir, |m| m.internet_relay = false).await;
    let metered = device("reachable-on-mobile-data", true, &dir, |m| m.metered = Some(true)).await;
    let alice = device("alice", false, &dir, |_| {}).await;
    // the reachable ones publish where to dial them, but not that they relay
    for n in [&unwilling, &metered] {
        eventually("a reachable device's record", 10, async || {
            record(&dir, n).await.is_some_and(|r| !r.relay && !r.addrs.is_empty())
        })
        .await;
        let st = n.mesh().unwrap().relay_status();
        assert!(!st.relaying, "{st:?}");
    }
    assert!(metered.mesh().unwrap().relay_status().metered);
    alice.mesh().unwrap().set_relay_candidates(vec![hidden.id(), unwilling.id(), metered.id()]);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(alice.mesh().unwrap().relay_status().relays.is_empty());
    assert!(record(&dir, &alice).await.is_none(), "nothing to say: no address, no relay");
    for n in [&unwilling, &metered, &hidden] {
        assert_eq!(n.mesh().unwrap().relay_status().clients, 0);
    }
    for n in [&alice, &hidden, &unwilling, &metered] {
        n.shutdown().await.unwrap();
    }
}

/// Bob knows only Alice, who is behind a router herself: he finds a relay
/// in her record and asks it too.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_is_learned_from_a_contacts_record() {
    let dir = MemDirectory::new();
    let relay = device("relay", true, &dir, |_| {}).await;
    let alice = device("alice", false, &dir, |_| {}).await;
    let bob = device("bob", false, &dir, |_| {}).await;
    eventually("the relay's record", 10, async || record(&dir, &relay).await.is_some_and(|r| r.relay)).await;
    alice.mesh().unwrap().set_relay_candidates(vec![relay.id()]);
    behind(&dir, &alice, &[&relay]).await;
    // Bob was never told of the relay
    bob.mesh().unwrap().set_relay_candidates(vec![alice.id()]);
    behind(&dir, &bob, &[&relay]).await;
    assert_eq!(relay.mesh().unwrap().relay_status().clients, 2);
    for n in [&alice, &bob, &relay] {
        n.shutdown().await.unwrap();
    }
}

/// A device behind two relays: a connection to it has a path through each,
/// finds a direct path once it is up (nobody was told either address: each
/// end learns the other's over the connection), and survives one relay
/// going away.
#[tokio::test(flavor = "multi_thread")]
async fn two_relays_are_two_paths_and_one_can_go() {
    let dir = MemDirectory::new();
    let r1 = device("relay-1", true, &dir, |_| {}).await;
    let r2 = device("relay-2", true, &dir, |_| {}).await;
    let alice = device("alice", false, &dir, |_| {}).await;
    let bob = device("bob", false, &dir, |_| {}).await;
    for r in [&r1, &r2] {
        eventually("a relay's record", 10, async || record(&dir, r).await.is_some_and(|x| x.relay)).await;
    }
    alice.mesh().unwrap().set_relay_candidates(vec![r1.id(), r2.id()]);
    behind(&dir, &alice, &[&r1, &r2]).await;

    let conn = bob.connect(alice.id(), BULK).await.expect("dial a device behind a router by key");
    eventually("a path through each relay", 15, async || {
        conn.paths().iter().filter(|p| PathKind::of(p.remote_addr()) == PathKind::Mesh).count() >= 2
    })
    .await;
    let send = async |n: usize| -> u64 {
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        tx.write_all(&vec![7u8; n]).await.unwrap();
        tx.finish().unwrap();
        let mut got = [0u8; 8];
        rx.read_exact(&mut got).await.unwrap();
        u64::from_le_bytes(got)
    };
    assert_eq!(send(200_000).await, 200_000);
    let kinds = |c: &Connection| c.paths().iter().map(|p| PathKind::of(p.remote_addr())).collect::<Vec<_>>();
    // the relays told Alice her address as they see it, Iroh offered it
    // over the connection, and Bob's end opened a direct path to it
    eventually("a direct path", 15, async || kinds(&conn).contains(&PathKind::Network)).await;
    eprintln!("paths after the first transfer: {:?}", kinds(&conn));
    // one relay goes: the connection carries on (over the other relay, or
    // the direct path)
    r1.shutdown().await.unwrap();
    let t = Instant::now();
    assert_eq!(tokio::time::timeout(Duration::from_secs(30), send(200_000)).await.expect("carried on"), 200_000);
    eprintln!("200 kB after losing a relay: {:?}; paths now: {:?}", t.elapsed(), kinds(&conn));
    assert!(r2.mesh().unwrap().stats().relayed_internet > 0);
    for n in [&alice, &bob, &r2] {
        n.shutdown().await.unwrap();
    }
}
