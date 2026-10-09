//! Regression (vendor/iroh/MYCEL_PATCH.md §5): paths that can't be opened
//! yet are queued for a retry once each, not once per connection.
//!
//! A device reachable on more links than a connection has path IDs, with
//! several connections to it (Mycel's pooled one plus a call, say): every
//! retry used to re-queue each unopened address once per connection, so the
//! queue tripled every 333 ms. In the walking-crowd simulation that was tens
//! of GB within minutes. Its own test binary: it watches the process's memory.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::{ExtraProtocol, NetMode, Node, NodeOptions};
use tokio::sync::mpsc;

/// More links than a connection's 8 path IDs.
const RADIOS: u64 = 16;
const ALPNS: [&[u8]; 3] = [b"mycel-test/a", b"mycel-test/b", b"mycel-test/c"];

/// Physical footprint (macOS) or resident size (elsewhere), in MB.
fn memory_mb() -> f64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: proc_pid_rusage fills a rusage_info_v2 for RUSAGE_INFO_V2.
        let ok = unsafe {
            libc::proc_pid_rusage(
                std::process::id() as libc::c_int,
                libc::RUSAGE_INFO_V2,
                &mut info as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
            )
        } == 0;
        if ok {
            return info.ri_phys_footprint as f64 / (1024.0 * 1024.0);
        }
    }
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<f64>().ok())
        .map_or(0.0, |pages| pages * 4096.0 / (1024.0 * 1024.0))
}

async fn node(name: &str, radios: &[MemNet], extra: Vec<ExtraProtocol>) -> Node {
    let keys = Arc::new(DeviceKeys::generate());
    let mut o = NodeOptions::new(NetMode::Local, name);
    o.ip = false;
    o.links = radios.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    o.extra_protocols = extra;
    Node::spawn(keys, o).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unopened_paths_are_queued_once() {
    let radios: Vec<MemNet> = (0..RADIOS).map(|n| MemNet::radio(n, PathKind::PeerWifi)).collect();
    let mut extra = Vec::new();
    let mut accepted = Vec::new();
    for alpn in ALPNS {
        let (tx, rx) = mpsc::unbounded_channel();
        extra.push(ExtraProtocol { alpn: alpn.to_vec(), incoming: tx });
        accepted.push(rx);
    }
    let bob = node("bob", &radios, extra).await;
    let alice = node("alice", &radios, Vec::new()).await;
    let start = Instant::now();
    while alice.peers().get(&bob.id()).is_none_or(|p| !p.online()) {
        assert!(start.elapsed() < Duration::from_secs(20), "bob never showed up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // every radio has announced itself
    tokio::time::sleep(Duration::from_secs(1)).await;

    let base = memory_mb();
    // three more connections to bob, each wanting a path on all 16 links
    let mut conns = Vec::new();
    for alpn in ALPNS {
        conns.push(alice.connect(bob.id(), alpn).await.unwrap());
    }
    let mut peak = 0.0f64;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let grew = memory_mb() - base;
        peak = peak.max(grew);
        // with the bug: ~50 MB in 10 s here, growing (tens of GB in the
        // walking-crowd simulation); fixed: ~2 MB
        assert!(grew < 20.0, "memory grew {grew:.0} MB in {:?} with {} connections", t.elapsed(), conns.len());
    }
    eprintln!("memory growth over 10 s: peak {peak:.1} MB");
    drop(conns);
}
