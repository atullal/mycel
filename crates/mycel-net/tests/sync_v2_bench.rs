//! Sync v2 costs between real nodes over loopback QUIC (docs/BENCHMARKS.md,
//! "Sync v2"). Ignored by default; run with
//!
//! ```text
//! cargo test -p mycel-net --test sync_v2_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Bytes are counted twice: frames on the sync and gossip streams (what the
//! protocol sends), and UDP bytes on the nodes' QUIC connections (QUIC
//! headers, acknowledgements, keep-alives and capability hellos included;
//! loopback, so no loss). Debug builds: times are indicative only.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_sync::{Replica, StreamId, StreamKind};
use mycel_trust::{Role, SpaceId};

async fn node(name: &str, sync_v2: bool) -> Node {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.sync_v2 = sync_v2;
    Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap()
}

async fn node_with(keys: Arc<DeviceKeys>, name: &str) -> Node {
    Node::spawn(keys, NodeOptions::new(NetMode::Local, name)).await.unwrap()
}

fn introduce(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..2400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn feed() -> StreamId {
    StreamId::named(StreamKind::Feed, "chat")
}

/// A chat message about as large as the design's measured one (351 B).
fn body(i: u32) -> Vec<u8> {
    let mut b = format!("message {i}: ").into_bytes();
    b.resize(45, b'.');
    b
}

fn append(n: &Node, space: &SpaceId, count: u32, from: u32) {
    n.with_space(space, |r| {
        for i in 0..count {
            r.append(feed(), body(from + i)).unwrap();
        }
    })
    .unwrap();
}

/// Stream and UDP bytes across `nodes`.
fn bytes(nodes: &[&Node]) -> (u64, u64) {
    nodes.iter().fold((0, 0), |(s, u), n| {
        let t = n.sync_v2_totals();
        let g = n.gossip_totals();
        (s + t.sent_bytes + g.sent_bytes, u + n.quic_udp_bytes().0)
    })
}

/// One explicit sync of `space` from `client` to `server`, measured.
async fn measure(label: &str, client: &Node, server: &Node, space: SpaceId) -> (u64, u64) {
    tokio::time::sleep(Duration::from_millis(300)).await; // let background work settle
    let before = bytes(&[client, server]);
    let t = Instant::now();
    let stats = client.sync_with(server.id(), space, false).await.unwrap();
    let took = t.elapsed();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = bytes(&[client, server]);
    let (s, u) = (after.0 - before.0, after.1 - before.1);
    println!("| {label} | {s} | {u} | {} | {took:.1?} |", stats.envelopes);
    (s, u)
}

async fn pair(sync_v2: bool, history: u32) -> (Node, Node, SpaceId) {
    let alice = node("alice", sync_v2).await;
    let bob = node("bob", sync_v2).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    append(&alice, &space, history, 0);
    bob.sync_with(alice.id(), space, true).await.unwrap();
    eventually("bob caught up", || bob.with_space(&space, |r| r.feed_len(&feed())).unwrap() == history as usize).await;
    (alice, bob, space)
}

/// Session costs: idle, one new envelope, 1,000 missing, a fresh join, and
/// a fork, for v2 and (where it applies) v1.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_sync_v2_sessions_over_quic() {
    const HISTORY: u32 = 2_000;
    println!("\nhistory: {HISTORY} chat envelopes (~350 B each)\n");
    println!("| case | stream B | UDP B (client) | envelopes received | time |");
    println!("|---|---|---|---|---|");
    for v2 in [true, false] {
        let tag = if v2 { "v2" } else { "v1" };
        let (alice, bob, space) = pair(v2, HISTORY).await;
        measure(&format!("{tag} idle"), &bob, &alice, space).await;
        // (written without `changed`: no gossip push, the session carries it)
        append(&alice, &space, 1, HISTORY);
        measure(&format!("{tag} 1 new"), &bob, &alice, space).await;
        append(&alice, &space, 1_000, HISTORY + 1);
        measure(&format!("{tag} 1k missing"), &bob, &alice, space).await;
        // A fresh member joins and catches up the whole history.
        let carol = node("carol", v2).await;
        introduce(&[&alice, &bob, &carol]);
        alice.with_space(&space, |r| r.add_member(carol.keys().public(), Role::Writer)).unwrap().unwrap();
        let genesis = alice.with_space(&space, |r| r.op(&space).unwrap().clone()).unwrap();
        carol.join_space(genesis).unwrap();
        measure(&format!("{tag} fresh join ({} envelopes)", HISTORY + 1_001), &carol, &alice, space).await;
        for n in [alice, bob, carol] {
            n.shutdown().await.unwrap();
        }
    }
    // Fork: alice's key also writes 100 envelopes on another branch from
    // seq 1,900 (a restore from backup reusing seqs); bob holds that branch,
    // alice holds hers (100 more on the original branch).
    let alice_keys = Arc::new(DeviceKeys::generate());
    let alice = node_with(alice_keys.clone(), "alice").await;
    let bob = node("bob", true).await;
    introduce(&[&alice, &bob]);
    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis.clone()).unwrap();
    append(&alice, &space, 1_900, 0);
    bob.sync_with(alice.id(), space, true).await.unwrap();
    let (ops, envs) = alice
        .with_space(&space, |r| {
            (r.all_ops(), r.envelope_ids().iter().map(|id| r.envelope(id).unwrap().clone()).collect::<Vec<_>>())
        })
        .unwrap();
    let mut restored = Replica::restore(alice_keys.clone(), genesis, ops, envs, None).unwrap();
    let branch: Vec<_> = (0..100).map(|i| restored.append(feed(), body(90_000 + i)).unwrap().1).collect();
    append(&alice, &space, 100, 1_900);
    bob.with_space(&space, |r| r.ingest_batch(vec![], branch)).unwrap();
    measure("v2 fork at seq 1,900 (100 envelopes each side)", &bob, &alice, space).await;
    let t = bob.sync_v2_totals();
    println!("\n(bob's sessions reaching phase 2: {})", t.phase2);
    for n in [alice, bob] {
        n.shutdown().await.unwrap();
    }
}

/// Dissemination: what one new message costs a whole group (all nodes'
/// gossip and session bytes, and UDP bytes), after the tree has formed.
/// Group sizes from `GROUP_SIZES` (default "10,50").
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_dissemination_over_quic() {
    /// Group bytes (stream, UDP), payload copies, sessions, time to all.
    type Row = (u64, u64, u64, u64, Duration);
    let sizes: Vec<usize> = std::env::var("GROUP_SIZES")
        .unwrap_or_else(|_| "10,50".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    println!(
        "\n| members | stream B per message (group) | per member | UDP B per message (group) | payload copies | sessions | time to all |"
    );
    println!("|---|---|---|---|---|---|---|");
    for n in sizes {
        let mut nodes = Vec::new();
        for i in 0..n {
            nodes.push(node(&format!("m{i}"), true).await);
        }
        introduce(&nodes.iter().collect::<Vec<_>>());
        let (space, genesis) = nodes[0].create_space().unwrap();
        nodes[0]
            .with_space(&space, |r| {
                for m in &nodes[1..] {
                    r.add_member(m.keys().public(), Role::Writer).unwrap();
                }
            })
            .unwrap();
        for m in &nodes[1..] {
            m.join_space(genesis.clone()).unwrap();
            m.sync_with(nodes[0].id(), space, false).await.unwrap();
        }
        eventually("membership everywhere", || {
            nodes.iter().all(|m| m.with_space(&space, |r| r.members().len()).unwrap() == n)
        })
        .await;
        eventually("views formed", || nodes.iter().all(|m| m.gossip_neighbours(&space).len() >= 2.min(n - 1))).await;
        let all: Vec<&Node> = nodes.iter().collect();
        let mut rows: Vec<Row> = Vec::new();
        for k in 0..6usize {
            let author = &nodes[(k * 7) % n];
            tokio::time::sleep(Duration::from_millis(500)).await;
            let before = bytes(&all);
            let copies0: u64 = nodes.iter().map(|m| m.gossip_stats().items_received).sum();
            let sessions0: u64 = nodes.iter().map(|m| m.sync_v2_totals().client_sessions).sum();
            let t = Instant::now();
            author.with_space(&space, |r| r.append(feed(), body(k as u32))).unwrap().unwrap();
            author.changed(space);
            eventually("everyone has it", || {
                nodes.iter().all(|m| m.with_space(&space, |r| r.feed_len(&feed())).unwrap() == k + 1)
            })
            .await;
            let took = t.elapsed();
            tokio::time::sleep(Duration::from_millis(1500)).await; // lazy announcements, prunes
            let after = bytes(&all);
            let copies = nodes.iter().map(|m| m.gossip_stats().items_received).sum::<u64>() - copies0;
            let sessions = nodes.iter().map(|m| m.sync_v2_totals().client_sessions).sum::<u64>() - sessions0;
            rows.push((after.0 - before.0, after.1 - before.1, copies, sessions, took));
        }
        // The first messages form the tree (prunes); report the last three.
        let tail = &rows[3..];
        let avg = |f: &dyn Fn(&Row) -> f64| tail.iter().map(f).sum::<f64>() / tail.len() as f64;
        let s = avg(&|r| r.0 as f64);
        let u = avg(&|r| r.1 as f64);
        let c = avg(&|r| r.2 as f64);
        let ss = avg(&|r| r.3 as f64);
        let t = avg(&|r| r.4.as_secs_f64() * 1000.0);
        println!("| {n} | {s:.0} | {:.0} | {u:.0} | {c:.1} | {ss:.1} | {t:.0} ms |", s / n as f64);
        println!("<!-- {n}: warm-up rows {:?} -->", &rows[..3].iter().map(|r| (r.0, r.2, r.3)).collect::<Vec<_>>());
        for m in nodes {
            m.shutdown().await.unwrap();
        }
    }
}
