//! Feasibility probe: N real nodes on an emulated BLE grid with the mesh on.
//! Prints memory and CPU per node and route coverage.
//!
//! cargo run --release -p mycel-sim --example probe -- 50 [paused]

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_net::emu::{EmuNet, Medium, Pos};
use mycel_net::link::{Link, PathKind};
use mycel_net::{MeshOptions, NetMode, Node, NodeOptions};

fn rss_mb() -> f64 {
    let out =
        std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().unwrap_or(0.0) / 1024.0
}

fn cpu_s() -> f64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    u.ru_utime.tv_sec as f64
        + u.ru_utime.tv_usec as f64 / 1e6
        + u.ru_stime.tv_sec as f64
        + u.ru_stime.tv_usec as f64 / 1e6
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let paused = args.iter().any(|a| a == "paused");
    let mut rt = tokio::runtime::Builder::new_multi_thread();
    rt.enable_all();
    let rt = if paused {
        tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap()
    } else {
        rt.build().unwrap()
    };
    rt.block_on(async move {
        let base = rss_mb();
        let mut m = Medium::ideal(PathKind::Bluetooth);
        m.range = 30.0;
        m.rate = Some(50_000);
        m.latency = mycel_net::emu::Latency::Fixed(Duration::from_millis(15));
        let net = EmuNet::new(0, m, 7);
        let side = (n as f64).sqrt().ceil() as usize;
        let mut nodes = Vec::new();
        let t0 = std::time::Instant::now();
        for i in 0..n {
            let keys = Arc::new(DeviceKeys::generate());
            let pos = Pos::new((i % side) as f64 * 20.0, (i / side) as f64 * 20.0);
            let mut o = NodeOptions::new(NetMode::Local, format!("n{i}"));
            o.ip = false;
            o.links = vec![net.link(keys.sign_pk(), pos) as Arc<dyn Link>];
            o.mesh = Some(MeshOptions::default());
            nodes.push(Node::spawn(keys, o).await.unwrap());
        }
        let spawn = t0.elapsed();
        let after_spawn = rss_mb();
        let (c0, w0) = (cpu_s(), std::time::Instant::now());
        tokio::time::sleep(Duration::from_secs(30)).await;
        let (c1, w1) = (cpu_s(), w0.elapsed());
        let rss = rss_mb();
        let reach: usize = nodes.iter().map(|x| x.mesh().unwrap().reachable().len()).sum();
        let neigh: usize = nodes.iter().map(|x| x.mesh().unwrap().connected_neighbours().len()).sum();
        let st = net.stats();
        let ms = nodes.iter().map(|x| x.mesh().unwrap().stats()).fold((0, 0, 0, 0), |a, s| {
            (a.0 + s.announcements_received, a.1 + s.announcements_limited, a.2 + s.dropped_queue, a.3 + s.announcements_sent)
        });
        println!("mesh: announcements sent {} received {} rate-limited {} hop-queue drops {}", ms.3, ms.0, ms.1, ms.2);
        println!(
            "n={n} paused={paused} spawn={spawn:?} rss: base {base:.0} MB, after spawn {after_spawn:.0}, after 30 s {rss:.0} MB ({:.2} MB/node); \
             cpu {:.1}% of a core over {w1:?} wall ({:.2}% per node); avg neighbours {:.1}; reach {:.1}% of pairs; packets {} dropped q{} r{}",
            (rss - base) / n as f64,
            100.0 * (c1 - c0) / w1.as_secs_f64(),
            100.0 * (c1 - c0) / w1.as_secs_f64() / n as f64,
            neigh as f64 / n as f64,
            100.0 * reach as f64 / (n * (n - 1)) as f64,
            st.packets_sent,
            st.dropped_queue,
            st.dropped_range,
        );
    });
}
