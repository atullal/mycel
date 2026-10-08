//! Multi-source blob download: three members hold a blob, a fourth fetches
//! disjoint ranges from all of them at once (each range its own QUIC stream
//! on the pooled connection to that member). One source dies half way; its
//! ranges go to the others and the hash still checks out.
//!
//! Each source reaches the downloader over its own rate-limited in-memory
//! link, as if each had its own uplink.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::{DeviceKeys, Hash32};
use mycel_net::link::{Link, MemNet};
use mycel_net::{NetMode, Node, NodeOptions, PathKind, Progress, blob_digest};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;

const MIB: usize = 1024 * 1024;
const MB: f64 = 1_000_000.0;

async fn link_node(name: &str, nets: &[&MemNet]) -> (Node, PathBuf) {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = false;
    opts.links = nets.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    let dir = std::env::temp_dir().join(format!("mycel-test-multi-{}", mycel_crypto::random_u64()));
    opts.blob_dir = Some(dir.clone());
    (Node::spawn(keys, opts).await.unwrap(), dir)
}

fn shaped(n: u64, rate: u64) -> MemNet {
    let net = MemNet::new(n, PathKind::PeerWifi);
    net.set_rate_limit(Some(rate));
    net.set_latency(Duration::from_millis(5));
    net
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

async fn add_file_blob(node: &Node, space: SpaceId, bytes: &[u8]) -> Hash32 {
    let staged = node.blob_staging_path().unwrap();
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    let mut f = std::fs::File::create(&staged).unwrap();
    let mut d = blob_digest();
    for chunk in bytes.chunks(MIB) {
        f.write_all(chunk).unwrap();
        d.update(chunk);
    }
    drop(f);
    let hash = d.finalize();
    node.add_blob(space, &staged, hash).await.unwrap();
    hash
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..1200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn download_from_three_sources_and_survive_losing_one() {
    const RATE: u64 = 4_000_000; // each source's own 4 MB/s link
    // Setup network (fast, unlimited) joins the three sources; each source
    // has its own slow link to the downloader (and one more for a baseline).
    let setup = MemNet::new(0, PathKind::PeerWifi);
    let (l1, l2, l3, l4) = (shaped(1, RATE), shaped(2, RATE), shaped(3, RATE), shaped(4, RATE));
    let (a, a_dir) = link_node("a", &[&setup, &l1, &l4]).await;
    let (b, b_dir) = link_node("b", &[&setup, &l2]).await;
    let (c, c_dir) = link_node("c", &[&setup, &l3]).await;
    let (d, d_dir) = link_node("d", &[&l1, &l2, &l3]).await;
    let (e, e_dir) = link_node("e", &[&l4]).await; // baseline: only reaches a

    eventually("everyone sees their links", || {
        d.peers().len() >= 3 && b.peers().contains_key(&a.id()) && c.peers().contains_key(&a.id())
    })
    .await;

    let (space, genesis) = a.create_space().unwrap();
    a.with_space(&space, |r| {
        for n in [&b, &c, &d, &e] {
            r.add_member(n.keys().public(), Role::Writer)?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .unwrap()
    .unwrap();
    for n in [&b, &c, &d, &e] {
        n.join_space(genesis.clone()).unwrap();
        n.sync_with(a.id(), space, true).await.unwrap();
    }

    // A 24 MiB blob (above the eager-push size: fetched on demand).
    let big = pseudo_random(24 * MIB, 7);
    let hash = add_file_blob(&a, space, &big).await;
    b.fetch_blob(space, hash).await.unwrap();
    c.fetch_blob(space, hash).await.unwrap();

    // Baseline: one source over one link.
    let t = Instant::now();
    let path = e.fetch_blob(space, hash).await.unwrap();
    let single = big.len() as f64 / MB / t.elapsed().as_secs_f64();
    assert_eq!(std::fs::read(&path).unwrap(), big);
    eprintln!("one source:    {single:.1} MB/s");

    // Three sources; c is shut down a third of the way in.
    let served_before = [a.blob_bytes_served(), b.blob_bytes_served(), c.blob_bytes_served()];
    let seen: Arc<Mutex<u64>> = Arc::default();
    let s = seen.clone();
    let progress: Progress = Arc::new(move |done, _| *s.lock() = done);
    let d = Arc::new(d);
    let dd = d.clone();
    let t = Instant::now();
    let task = tokio::spawn(async move { dd.fetch_blob_with_progress(space, hash, progress).await });
    eventually("a third downloaded", || *seen.lock() >= big.len() as u64 / 3).await;
    let at_cut = t.elapsed();
    let c_served = c.blob_bytes_served() - served_before[2];
    c.shutdown().await.unwrap();
    let path = task.await.unwrap().map_err(|e| format!("{e:#}")).expect("download finished without c");
    let secs = t.elapsed().as_secs_f64();
    let served: Vec<f64> = [&a, &b]
        .iter()
        .zip(served_before)
        .map(|(n, before)| (n.blob_bytes_served() - before) as f64 / MB)
        .collect();
    eprintln!(
        "three sources: first third in {at_cut:?} ({:.1} MB/s); whole file in {secs:.2} s; \
         served a {:.1} MB, b {:.1} MB, c {:.1} MB (then shut down)",
        big.len() as f64 / 3.0 / MB / at_cut.as_secs_f64(),
        served[0],
        served[1],
        c_served as f64 / MB
    );
    assert_eq!(std::fs::read(&path).unwrap(), big, "hash-checked and byte-exact");
    assert!(served.iter().all(|s| *s > 2.0) && c_served > 2 * MIB as u64, "every source served pieces");
    let multi = big.len() as f64 / 3.0 / MB / at_cut.as_secs_f64();
    assert!(multi > 1.6 * single, "three sources {multi:.1} MB/s vs one {single:.1} MB/s");

    for n in [&a, &b, &*d, &e] {
        n.shutdown().await.unwrap();
    }
    for dir in [a_dir, b_dir, c_dir, d_dir, e_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
