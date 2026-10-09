//! Memory over time for walking devices (SIMULATION.md §4, the `shutdown`
//! finding): N real nodes on Bluetooth (+ AWDL on half), walking at 1.4 m/s
//! in a 250 m square, or standing still. Prints RSS, live tokio tasks and
//! the emulator's counters every 15 s, to tell growth in the node from
//! growth in the emulator.
//!
//! cargo run --release -p mycel-sim --example mem_walk -- 12 180 [still]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mycel_net::emu::Pos;
use mycel_net::MeshOptions;
use mycel_sim::models::{Env, Tech};
use mycel_sim::tier1::{DevOpts, Lab, block_on, net, resources};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(12);
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(180);
    let still = args.iter().any(|a| a == "still");
    block_on(async move {
        let (rss0, _) = resources();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, 1));
        let awdl = lab.add_medium(net(1, Tech::Awdl, Env::Outdoor, 1));
        let (w, h) = (250.0, 250.0);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move |lo: f64, hi: f64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            lo + (hi - lo) * (seed >> 11) as f64 / (1u64 << 53) as f64
        };
        for i in 0..n {
            let p = Pos::new(rnd(0.0, w), rnd(0.0, h));
            let mut at = vec![(&ble, p)];
            if i % 2 == 0 {
                at.push((&awdl, p));
            }
            lab.device(&format!("walker{i}"), &at, DevOpts { mesh: Some(MeshOptions::default()), ..Default::default() }).await;
        }
        let (rss1, _) = resources();
        println!("n={n} still={still}: rss {rss0:.0} MB before, {rss1:.0} MB after spawning");
        let keys: Vec<_> = lab.devs.iter().map(|d| d.node.id()).collect();
        let nets = vec![ble.clone(), awdl.clone()];
        let t0 = Instant::now();
        let mut target: HashMap<_, Pos> = HashMap::new();
        let mut next_report = Duration::from_secs(15);
        while t0.elapsed() < Duration::from_secs(secs) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if !still {
                for k in &keys {
                    let Some(p) = nets[0].pos(k) else { continue };
                    let t = *target.entry(*k).or_insert_with(|| Pos::new(rnd(0.0, w), rnd(0.0, h)));
                    let d = p.dist(&t);
                    let np = if d <= 1.4 {
                        target.remove(k);
                        t
                    } else {
                        Pos::new(p.x + (t.x - p.x) * 1.4 / d, p.y + (t.y - p.y) * 1.4 / d)
                    };
                    for m in &nets {
                        m.set_pos(k, np);
                    }
                }
                for m in &nets {
                    m.refresh();
                }
            }
            if t0.elapsed() >= next_report {
                next_report += Duration::from_secs(15);
                let (rss, _) = resources();
                let tasks = tokio::runtime::Handle::current().metrics().num_alive_tasks();
                let s = ble.stats();
                let neigh: usize = lab.devs.iter().filter_map(|d| d.node.mesh()).map(|m| m.connected_neighbours().len()).sum();
                let ms = lab.devs.iter().filter_map(|d| d.node.mesh()).map(|m| m.stats()).fold((0u64, 0u64), |a, s| (a.0 + s.announcements_sent, a.1 + s.dropped_queue));
                println!(
                    "t={:>4}s rss {rss:>6.0} MB ({:>5.1} MB/node over spawn)  tasks {tasks:>6}  ble pkts {} delivered {} q-drop {} range-drop {}  neighbours {:.1}/node  ann sent {} hop-q drops {}",
                    t0.elapsed().as_secs(),
                    (rss - rss1) / n as f64,
                    s.packets_sent,
                    s.packets_delivered,
                    s.dropped_queue,
                    s.dropped_range,
                    neigh as f64 / n as f64,
                    ms.0,
                    ms.1,
                );
            }
        }
        lab.shutdown().await;
    });
}
