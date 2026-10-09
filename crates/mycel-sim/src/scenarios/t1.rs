//! Tier-1 scenarios: real Mycel nodes over emulated radios and wires, in
//! real time. Messages are real sync, calls real calls with test tones.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_net::MeshOptions;
use mycel_net::emu::{EmuNet, Medium, PairShape, Pos};
use mycel_net::link::PathKind;
use parking_lot::Mutex;
use serde_json::json;

use super::{Opts, Scenario};
use crate::models::{Access, Env, Nat, Tech};
use crate::report::{ScenarioResult, fmt};
use crate::stats::{Rng, Summary};
use crate::tier1::{self, CallOutcome, Delivery, DevOpts, Lab, Uplink, block_on, grid, internet, net, relays, resources, summarize};

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario { name: "cafe", title: "Café: one Wi-Fi access point, phones and laptops", tier: 1, run: cafe },
        Scenario { name: "office", title: "Office: Ethernet + Wi-Fi on two floors", tier: 1, run: office },
        Scenario { name: "apartment-80211s", title: "Apartment building on an 802.11s Wi-Fi mesh", tier: 1, run: apartment },
        Scenario { name: "conference", title: "Conference hall: dense BLE and AWDL, no Wi-Fi", tier: 1, run: conference },
        Scenario { name: "city-block", title: "City block, no internet: an 8+ hop Bluetooth chain", tier: 1, run: city_block },
        Scenario { name: "shutdown", title: "Internet shutdown: mesh only, people walking", tier: 1, run: shutdown },
        Scenario { name: "disaster-live", title: "Disaster: two camps and a mule (member vs stranger)", tier: 1, run: disaster_live },
        Scenario { name: "rural-line", title: "Rural line: houses 120 m apart on Wi-Fi Direct and BLE", tier: 1, run: rural_line },
        Scenario { name: "us-eu-live", title: "US to Europe with real nodes: BLE → gateway → internet → gateway → BLE", tier: 1, run: us_eu_live },
        Scenario { name: "nat-relay", title: "NAT types, relay paths, relay outage and failover", tier: 1, run: nat_relay },
        Scenario { name: "adversarial-live", title: "A black-hole relay and an announcement storm", tier: 1, run: adversarial_live },
        Scenario { name: "multipath", title: "Several radios between two devices, aggregated", tier: 1, run: multipath },
        Scenario { name: "mixed-room", title: "UWB, Ethernet, Wi-Fi Direct and BLE in one room: ranking", tier: 1, run: mixed_room },
        Scenario { name: "scale-ceiling", title: "How many real nodes this machine runs", tier: 1, run: scale_ceiling },
    ]
}

/// The mesh as the app runs it (default settings).
fn mesh() -> Option<MeshOptions> {
    Some(MeshOptions::default())
}

/// Deliveries, latency and optimality objectives, and a headline.
fn judge(r: &mut ScenarioResult, label: &str, ds: &[Delivery], min_delivery: f64, max_p95: f64) -> (f64, Summary, Summary) {
    let (ratio, lat, opt) = summarize(ds);
    r.at_least(&format!("{label}: delivery"), 100.0 * ratio, 100.0 * min_delivery, "%");
    r.at_most(&format!("{label}: latency p95"), if lat.n == 0 { f64::INFINITY } else { lat.p95 }, max_p95, "s");
    r.headline(format!(
        "{label}: {:.0}% delivered, p50 {} s, p95 {} s, optimality p50/p95/p99 {}/{}/{}×",
        100.0 * ratio,
        fmt(lat.p50),
        fmt(lat.p95),
        fmt(opt.p50),
        fmt(opt.p95),
        fmt(opt.p99)
    ));
    (ratio, lat, opt)
}

fn judge_call(r: &mut ScenarioResult, label: &str, c: &CallOutcome, max_setup: f64, max_loss: f32) {
    r.at_most(&format!("{label}: call setup"), c.setup.map_or(f64::INFINITY, |d| d.as_secs_f64()), max_setup, "s");
    r.check(&format!("{label}: the callee hears the caller's tone"), c.heard_ok, if c.heard_ok { "yes".to_string() } else { format!("no ({:?})", c.error) });
    r.at_most(&format!("{label}: audio loss"), c.loss_pct as f64, max_loss as f64, "%");
    r.headline(format!(
        "{label}: setup {} s, loss {:.1}%, latency {} ms, path {:?}",
        c.setup.map_or("∞".into(), |d| fmt(d.as_secs_f64())),
        c.loss_pct,
        c.latency_ms,
        c.path
    ));
}

/// Conversations between `pairs`, `k` messages each (waits `gap` between).
async fn probe(lab: &mut Lab, pairs: &[(usize, usize)], k: usize, gap: Duration, deadline: Duration) -> (Vec<Delivery>, usize) {
    let mut out = Vec::new();
    let mut failed_setup = 0;
    for &(a, b) in pairs {
        let Ok(c) = lab.conversation(&[a, b]).await else {
            failed_setup += 1;
            for _ in 0..k {
                out.push(Delivery { from: a, to: b, latency: None, optimal: lab.optimal(a, b, 600) });
            }
            continue;
        };
        for _ in 0..k {
            out.extend(lab.message(c, a, &[b], deadline).await);
            tokio::time::sleep(gap).await;
        }
    }
    (out, failed_setup)
}

fn pairs(rng: &mut Rng, n: usize, k: usize) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    while v.len() < k {
        let (a, b) = (rng.below(n), rng.below(n));
        if a != b {
            v.push((a, b));
        }
    }
    v
}

fn finish(r: &mut ScenarioResult, t0: Instant, n: usize, rss0: f64, cpu0: f64) {
    let (rss, cpu) = resources();
    let wall = t0.elapsed().as_secs_f64();
    r.note(format!(
        "{n} real nodes; memory +{:.0} MB ({:.1} MB per node); CPU {:.0}% of a core on average over {:.0} s",
        rss - rss0,
        (rss - rss0) / n.max(1) as f64,
        100.0 * (cpu - cpu0) / wall,
        wall
    ));
}

// ───────────────────────────── café ─────────────────────────────

fn cafe(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("cafe", "Café: one Wi-Fi access point, phones and laptops", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let wifi = lab.add_medium(net(0, Tech::WifiAp, Env::Indoor, o.seed));
        let ble = lab.add_medium(net(1, Tech::Ble, Env::Indoor, o.seed));
        let awdl = lab.add_medium(net(2, Tech::Awdl, Env::Indoor, o.seed));
        let n = o.n(20, 6);
        for i in 0..n {
            let p = grid(i, n, 15.0, 10.0);
            let mut at = vec![(&wifi, p), (&ble, p)];
            if i % 2 == 0 {
                at.push((&awdl, p)); // iPhones and Macs
            }
            let tone = (i < 2).then_some(440.0 + 220.0 * i as f32);
            lab.device(&format!("cafe{i}"), &at, DevOpts { tone, ..Default::default() }).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut rng = Rng::new(o.seed);
        let ps = pairs(&mut rng, n, (n / 2).max(3));
        let (ds, _) = probe(&mut lab, &ps, o.n(5, 3), Duration::from_millis(200), Duration::from_secs(20)).await;
        judge(&mut r, "messages", &ds, 1.0, 1.0);
        let c = lab.conversation(&[0, 1]).await;
        let call = match c {
            Ok(c) => lab.call(c, 0, 1, Duration::from_secs(3)).await,
            Err(e) => CallOutcome { error: Some(e.to_string()), ..Default::default() },
        };
        judge_call(&mut r, "call", &call, 3.0, 2.0);
        r.note("Optimality: the fastest path on a café's Wi-Fi is a few milliseconds; a Mycel message is a sync exchange (a few round trips, then the 5 ms poll here), so 5–20× on a LAN is the protocol, not routing.");
        finish(&mut r, t0, n, rss0, cpu0);
        r.metrics = json!({"wifi": wifi.stats().packets_sent, "ble": ble.stats().packets_sent, "awdl": awdl.stats().packets_sent});
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── office ─────────────────────────────

fn office(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("office", "Office: Ethernet + Wi-Fi on two floors", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let eth = lab.add_medium(net(0, Tech::Ethernet, Env::Indoor, o.seed));
        let f1 = lab.add_medium(net(1, Tech::WifiAp, Env::Indoor, o.seed));
        let f2 = lab.add_medium(net(2, Tech::WifiAp, Env::Indoor, o.seed));
        // the routed office LAN across floors (Wi-Fi ↔ switch ↔ Wi-Fi)
        let mut lanm = Medium::ideal(PathKind::Network);
        lanm.label = "Office LAN (routed)";
        lanm.latency = mycel_net::emu::Latency::Fixed(Duration::from_millis(4));
        lanm.jitter = Duration::from_millis(3);
        lanm.rate = Some(20_000_000);
        let lan = lab.add_medium(EmuNet::new(3, lanm, o.seed));
        let ble = lab.add_medium(net(4, Tech::Ble, Env::Indoor, o.seed));
        let per = o.n(4, 2);
        let mut desks = Vec::new();
        let mut laptops = Vec::new();
        for i in 0..per {
            let p = Pos::new(i as f64 * 5.0, 0.0);
            desks.push(lab.device(&format!("desk{i}"), &[(&eth, p), (&lan, p)], DevOpts::default()).await);
        }
        for (floor, wf) in [(0, &f1), (1, &f2)] {
            for i in 0..per {
                let p = Pos::new(i as f64 * 6.0, floor as f64 * 100.0);
                laptops.push(lab.device(&format!("f{floor}laptop{i}"), &[(wf, p), (&lan, p), (&ble, p)], DevOpts::default()).await);
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut ps = vec![(desks[0], desks[per - 1])];
        ps.push((laptops[0], laptops[per])); // across floors
        ps.push((laptops[0], laptops[1])); // same floor
        ps.push((desks[0], laptops[per])); // desk to the other floor
        let (ds, _) = probe(&mut lab, &ps, o.n(5, 3), Duration::from_millis(200), Duration::from_secs(20)).await;
        judge(&mut r, "messages", &ds, 1.0, 1.0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let via = lab.devs[desks[0]].via(&lab.devs[desks[per - 1]]);
        r.check("desk to desk goes over Ethernet", via == Some(PathKind::Ethernet), format!("{via:?}"));
        let via2 = lab.devs[laptops[0]].via(&lab.devs[laptops[per]]);
        r.check("across floors goes over the office LAN", via2 == Some(PathKind::Network), format!("{via2:?}"));
        finish(&mut r, t0, lab.devs.len(), rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── apartment (802.11s) ─────────────────────────────

fn apartment(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("apartment-80211s", "Apartment building on an 802.11s Wi-Fi mesh", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        // the 802.11s mesh spans the building at layer 2; each 25 m is one more Wi-Fi hop
        let mut m = Tech::WifiMesh.medium(Env::Indoor);
        m.range = f64::INFINITY;
        m.shared_channel = false;
        let wm = lab.add_medium(EmuNet::new(0, m, o.seed));
        let n = o.n(8, 4);
        for i in 0..n {
            lab.device(&format!("flat{i}"), &[(&wm, Pos::new(i as f64 * 25.0, 0.0))], DevOpts { bulk: true, ..Default::default() }).await;
        }
        let pos: HashMap<mycel_crypto::SignPk, f64> = lab.devs.iter().enumerate().map(|(i, d)| (d.node.id(), i as f64 * 25.0)).collect();
        wm.set_pair(Some(Arc::new(move |a, b| {
            let hops = ((pos.get(a)? - pos.get(b)?).abs() / 25.0).ceil().max(1.0);
            Some(PairShape { latency: Duration::from_millis(3 * (hops as u64 - 1)), rate_div: hops.min(4.0) })
        })));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let ps = vec![(0, 1), (0, n - 1)];
        let (ds, _) = probe(&mut lab, &ps, o.n(5, 3), Duration::from_millis(200), Duration::from_secs(20)).await;
        judge(&mut r, "messages", &ds, 1.0, 1.0);
        let bytes = (o.n(8, 2) as u64) << 20;
        let near = lab.bulk(0, 1, bytes, Duration::from_secs(60)).await;
        let far = lab.bulk(0, n - 1, bytes, Duration::from_secs(60)).await;
        let rate = |d: Option<Duration>| d.map_or(0.0, |d| bytes as f64 / d.as_secs_f64() / 1e6);
        r.at_least("throughput to the next flat", rate(near), 3.0, "MB/s");
        r.check("the far end is slower (more 802.11s hops)", rate(far) < rate(near), format!("{:.1} vs {:.1} MB/s", rate(far), rate(near)));
        r.headline(format!("bulk: next flat {:.1} MB/s, {} flats away {:.1} MB/s", rate(near), n - 1, rate(far)));
        finish(&mut r, t0, n, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── conference ─────────────────────────────

fn conference(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("conference", "Conference hall: dense BLE and AWDL, no Wi-Fi", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Crowd, o.seed));
        let awdl = lab.add_medium(net(1, Tech::Awdl, Env::Crowd, o.seed));
        let n = o.n(300, 24);
        let (w, h) = if n > 100 { (60.0, 40.0) } else { (40.0, 25.0) };
        for i in 0..n {
            let p = grid(i, n, w, h);
            let mut at = vec![(&ble, p)];
            if i % 2 == 0 {
                at.push((&awdl, p));
            }
            lab.device(&format!("seat{i}"), &at, DevOpts { mesh: mesh(), ..Default::default() }).await;
        }
        let spawned = t0.elapsed();
        tokio::time::sleep(Duration::from_secs(8)).await;
        let mut rng = Rng::new(o.seed);
        let ps = pairs(&mut rng, n, o.n(20, 5));
        let (ds, _) = probe(&mut lab, &ps, 2, Duration::from_millis(200), Duration::from_secs(30)).await;
        judge(&mut r, "messages", &ds, 0.95, 3.0);
        let hop: u64 = lab.devs.iter().filter_map(|d| d.node.mesh().map(|m| m.stats().hop_connections)).sum();
        let deg = ble.neighbours(&lab.devs[0].node.id()).len() + awdl.neighbours(&lab.devs[0].node.id()).len();
        r.note(format!("Spawned in {:.1} s; a seat hears ~{deg} devices; {hop} mesh hop connections in total ({:.1} per device).", spawned.as_secs_f64(), hop as f64 / n as f64));
        let bs = ble.stats();
        let drops = bs.dropped_queue as f64 / bs.packets_sent.max(1) as f64;
        if drops > 0.1 && !r.slos.iter().all(|x| x.pass) {
            r.expect_fail("FINDING (docs/SIMULATION.md §4, fixed 15): with MYCEL_SIM_BLE_QUEUE=radio (one 250 ms queue for the whole radio, not one 16 KiB queue per peer as the real BLE link has), bursts to one peer drop everyone's packets (~23%); the slowest of 10 messages then waits for retransmissions");
        }
        r.note(format!("Bluetooth medium: {} packets sent, {} dropped at full transmit queues ({:.1}%).", bs.packets_sent, bs.dropped_queue, 100.0 * bs.dropped_queue as f64 / bs.packets_sent.max(1) as f64));
        r.note("Each device opens hop connections to at most 6 devices in range (its own pseudo-random pick, so they spread out); others open theirs to it, ~11 in all here. Real BLE radios hold ~10 connections.");
        finish(&mut r, t0, n, rss0, cpu0);
        r.metrics = json!({"hop_connections": hop, "ble_packets": ble.stats().packets_sent, "awdl_packets": awdl.stats().packets_sent, "ble_queue_drops": ble.stats().dropped_queue});
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── city block ─────────────────────────────

fn city_block(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("city-block", "City block, no internet: an 8+ hop Bluetooth chain", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
        // 10 phones 40 m apart: each hears only its neighbours (60 m range)
        let n = 10;
        for i in 0..n {
            lab.device(&format!("p{i}"), &[(&ble, Pos::new(i as f64 * 40.0, 0.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
        let (d8, _) = probe(&mut lab, &[(0, 8)], o.n(3, 2), Duration::from_millis(300), Duration::from_secs(30)).await;
        judge(&mut r, "8 hops", &d8, 1.0, 5.0);
        let (d9, _) = probe(&mut lab, &[(0, 9)], 1, Duration::from_millis(300), Duration::from_secs(20)).await;
        let ok9 = d9.iter().any(|d| d.latency.is_some());
        r.headline(format!("9 hops: {}", if ok9 { "delivered" } else { "not delivered" }));
        r.note("The mesh's TTL (max_hops = 10) bounds a chain at 10 radio hops (routes follow the cheapest path, which can be a hop or two longer than the fewest): devices further apart need a gateway or store-and-forward.");
        finish(&mut r, t0, n, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── shutdown ─────────────────────────────

/// Move devices on radio media every second (random waypoint).
fn walkers(lab: &Lab, who: Vec<usize>, w: f64, h: f64, speed: f64, seed: u64) -> tokio::task::JoinHandle<()> {
    let nets: Vec<EmuNet> = lab.media.iter().filter(|m| m.medium().discoverable).cloned().collect();
    let keys: Vec<mycel_crypto::SignPk> = who.iter().map(|i| lab.devs[*i].node.id()).collect();
    tokio::spawn(async move {
        let mut rng = Rng::new(seed);
        let mut target: HashMap<mycel_crypto::SignPk, Pos> = HashMap::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            for k in &keys {
                let Some(p) = nets[0].pos(k) else { continue };
                let t = *target.entry(*k).or_insert_with(|| Pos::new(rng.range(0.0, w), rng.range(0.0, h)));
                let d = p.dist(&t);
                let np = if d <= speed {
                    target.remove(k);
                    t
                } else {
                    Pos::new(p.x + (t.x - p.x) * speed / d, p.y + (t.y - p.y) * speed / d)
                };
                for n in &nets {
                    n.set_pos(k, np);
                }
            }
            for n in &nets {
                n.refresh();
            }
        }
    })
}

fn shutdown(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("shutdown", "Internet shutdown: mesh only, people walking", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
        let awdl = lab.add_medium(net(1, Tech::Awdl, Env::Outdoor, o.seed));
        let n = o.n(30, 12);
        let (w, h) = (250.0, 250.0);
        let mut rng = Rng::new(o.seed);
        for i in 0..n {
            let p = Pos::new(rng.range(0.0, w), rng.range(0.0, h));
            let mut at = vec![(&ble, p)];
            if i % 2 == 0 {
                at.push((&awdl, p));
            }
            let tone = (i < 2).then_some(500.0 + 200.0 * i as f32);
            lab.device(&format!("walker{i}"), &at, DevOpts { mesh: mesh(), tone, ..Default::default() }).await;
        }
        let mover = walkers(&lab, (0..n).collect(), w, h, 1.4, o.seed);
        tokio::time::sleep(Duration::from_secs(8)).await;
        let ps = pairs(&mut rng, n, o.n(10, 4));
        let (ds, failed) = probe(&mut lab, &ps, 2, Duration::from_secs(1), Duration::from_secs(20)).await;
        // live mesh only: devices in different clusters can't talk until they meet
        let feasible: Vec<Delivery> = ds.iter().copied().filter(|d| d.optimal.is_some() || d.latency.is_some()).collect();
        judge(&mut r, "messages (connected at the time)", &feasible, 0.8, 10.0);
        r.note(format!("{} of {} pairs couldn't even start a conversation (in different clusters at the time); {} messages had no path at all.", failed, ps.len(), ds.len() - feasible.len()));
        let call = match lab.conversation(&[0, 1]).await {
            Ok(c) => lab.call(c, 0, 1, Duration::from_secs(3)).await,
            Err(e) => CallOutcome { error: Some(e.to_string()), ..Default::default() },
        };
        r.headline(format!("call between two walkers: setup {:?}, heard {}, loss {:.1}%, path {:?}, {:?}", call.setup, call.heard_ok, call.loss_pct, call.path, call.error));
        mover.abort();
        finish(&mut r, t0, n, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── disaster (live) ─────────────────────────────

fn disaster_live(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("disaster-live", "Disaster: two camps and a mule (member vs stranger)", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
        let wd = lab.add_medium(net(1, Tech::WifiDirect, Env::Outdoor, o.seed));
        // camps 400 m apart: out of reach of every radio
        let a = lab.device("campA", &[(&ble, Pos::new(0.0, 0.0)), (&wd, Pos::new(0.0, 0.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        let b = lab.device("campB", &[(&ble, Pos::new(400.0, 0.0)), (&wd, Pos::new(400.0, 0.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        let member = lab.device("mule-member", &[(&ble, Pos::new(10.0, 5.0)), (&wd, Pos::new(10.0, 5.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        let stranger = lab.device("mule-stranger", &[(&ble, Pos::new(10.0, -5.0)), (&wd, Pos::new(10.0, -5.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        // the conversations need to exist first: create them while everyone is together
        for (n, x) in [(&ble, 400.0), (&wd, 400.0)] {
            n.set_pos(&lab.devs[b].node.id(), Pos::new(20.0, 0.0));
            let _ = x;
        }
        ble.refresh();
        wd.refresh();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let with_mule = lab.conversation(&[a, b, member]).await;
        let without = lab.conversation(&[a, b]).await;
        for n in [&ble, &wd] {
            n.set_pos(&lab.devs[b].node.id(), Pos::new(400.0, 0.0));
            n.refresh();
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (Ok(cm), Ok(cs)) = (with_mule, without) else {
            r.check("conversations created", false, "couldn't set up");
            return;
        };
        // both write while the camps are apart; the mules then walk from A to B (5 m/s)
        let k1 = lab.message(cm, a, &[b], Duration::from_millis(1)).await;
        let k2 = lab.message(cs, a, &[b], Duration::from_millis(1)).await;
        let _ = (k1, k2);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let t_walk = Instant::now();
        let mules = [lab.devs[member].node.id(), lab.devs[stranger].node.id()];
        let nets = [ble.clone(), wd.clone()];
        let linger = std::env::var("MYCEL_SIM_LINGER").ok().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        let mover = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(linger)).await;
            for step in 0..=80 {
                let x = 10.0 + step as f64 * 5.0;
                for n in &nets {
                    for (i, m) in mules.iter().enumerate() {
                        n.set_pos(m, Pos::new(x.min(395.0), if i == 0 { 5.0 } else { -5.0 }));
                    }
                    n.refresh();
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let deadline = Duration::from_secs(o.n(300, 240) as u64);
        let seen = |space, doc, key: &str| {
            lab.devs[b].node.with_space(&space, |rr| rr.doc_json(&doc)).ok().is_some_and(|v: serde_json::Value| v.get(key).is_some())
        };
        let (mut got_m, mut got_s) = (None, None);
        while t_walk.elapsed() < deadline && (got_m.is_none() || got_s.is_none()) {
            if got_m.is_none() && seen(cm.space, cm.doc, "m1") {
                got_m = Some(t_walk.elapsed());
            }
            if got_s.is_none() && seen(cs.space, cs.doc, "m2") {
                got_s = Some(t_walk.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        mover.abort();
        for d in &lab.devs {
            if let Some(m) = d.node.mesh() {
                r.note(format!("{} carrier: {:?}", d.name, m.dtn_stats()));
            }
        }
        r.at_most("a mule who is a member carries it (CRDT sync)", got_m.map_or(f64::INFINITY, |d| d.as_secs_f64()), 100.0, "s");
        r.at_most("a stranger mule carries it (store-and-forward)", got_s.map_or(f64::INFINITY, |d| d.as_secs_f64()), 200.0, "s");
        r.headline(format!("member mule: {}; stranger mule: {}", got_m.map_or("never".into(), |d| format!("{:.0} s", d.as_secs_f64())), got_s.map_or("never".into(), |d| format!("{:.0} s", d.as_secs_f64()))));
        r.note("Members carry what they're members of: the mule syncs camp A's change when it's in range and hands it to camp B when it arrives (~80 s walk). A stranger can only carry a store-and-forward bundle: camp A offers one when its sync with camp B isn't through within 10 s (the stale connection to B would only time out after 60 s, when the mules are long gone), the stranger takes copies (Spray-and-Focus: it is as good a carrier as camp A), and hands one to camp B on arrival.");
        finish(&mut r, t0, lab.devs.len(), rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── rural line ─────────────────────────────

fn rural_line(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("rural-line", "Rural line: houses 120 m apart on Wi-Fi Direct and BLE", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let wd = lab.add_medium(net(0, Tech::WifiDirect, Env::Outdoor, o.seed));
        let ble = lab.add_medium(net(1, Tech::Ble, Env::Outdoor, o.seed));
        let n = 6;
        let mut rng = Rng::new(o.seed);
        let mut x = 0.0;
        for i in 0..n {
            let p = Pos::new(x, 0.0);
            lab.device(&format!("house{i}"), &[(&wd, p), (&ble, p)], DevOpts { mesh: mesh(), bulk: true, ..Default::default() }).await;
            x += rng.range(100.0, 140.0);
        }
        tokio::time::sleep(Duration::from_secs(8)).await;
        let (ds, _) = probe(&mut lab, &[(0, n - 1), (0, 1)], o.n(4, 2), Duration::from_millis(300), Duration::from_secs(30)).await;
        judge(&mut r, "messages", &ds, 1.0, 3.0);
        let bytes = (o.n(4, 1) as u64) << 20;
        let near = lab.bulk(0, 1, bytes, Duration::from_secs(60)).await;
        let far = lab.bulk(0, n - 1, bytes, Duration::from_secs(120)).await;
        let rate = |d: Option<Duration>| d.map_or(0.0, |d| bytes as f64 / d.as_secs_f64() / 1e6);
        r.at_least("end-to-end throughput over 5 Wi-Fi Direct hops", rate(far), 0.5, "MB/s");
        r.headline(format!("bulk: next house {:.1} MB/s, 5 hops {:.2} MB/s", rate(near), rate(far)));
        finish(&mut r, t0, n, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── US → EU (live) ─────────────────────────────

fn us_eu_live(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("us-eu-live", "US to Europe with real nodes: BLE → gateway → internet → gateway → BLE", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble_us = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
        let ble_eu = lab.add_medium(net(1, Tech::Ble, Env::Outdoor, o.seed));
        let ups: Arc<Mutex<HashMap<mycel_crypto::SignPk, Uplink>>> = Arc::default();
        let inet = lab.add_medium(internet(2, o.seed, ups.clone()));
        let rel = lab.add_medium(relays(3, o.seed, ups.clone()));
        let gw_mesh = |up: bool| Some(MeshOptions { announce_every: Duration::from_millis(1000), internet: Some(up), ..MeshOptions::default() });
        // New York: a BLE-only phone 3 hops from an LTE phone
        let src = lab.device("ny-phone", &[(&ble_us, Pos::new(0.0, 0.0))], DevOpts { mesh: gw_mesh(false), tone: Some(440.0), ..Default::default() }).await;
        for i in 1..3 {
            lab.device(&format!("ny-relay{i}"), &[(&ble_us, Pos::new(i as f64 * 50.0, 0.0))], DevOpts { mesh: gw_mesh(false), ..Default::default() }).await;
        }
        let ny = (40.71, -74.01);
        let gw_us = lab
            .device("ny-gateway", &[(&ble_us, Pos::new(150.0, 0.0)), (&inet, Pos::new(ny.0, ny.1)), (&rel, Pos::new(ny.0, ny.1))], DevOpts { mesh: gw_mesh(true), ..Default::default() })
            .await;
        ups.lock().insert(lab.devs[gw_us].node.id(), Uplink { latlon: ny, access: Access::Lte, nat: Nat::Hard });
        // London: a home gateway and a BLE-only phone
        let ld = (51.51, -0.13);
        let gw_eu = lab
            .device("london-gateway", &[(&ble_eu, Pos::new(0.0, 0.0)), (&inet, Pos::new(ld.0, ld.1)), (&rel, Pos::new(ld.0, ld.1))], DevOpts { mesh: gw_mesh(true), ..Default::default() })
            .await;
        ups.lock().insert(lab.devs[gw_eu].node.id(), Uplink { latlon: ld, access: Access::Fibre, nat: Nat::Easy });
        let dst = lab.device("london-phone", &[(&ble_eu, Pos::new(40.0, 0.0))], DevOpts { mesh: gw_mesh(false), tone: Some(660.0), ..Default::default() }).await;
        inet.set_pair(None);
        let _ = inet;
        lab.introduce(gw_us, gw_eu);
        tokio::time::sleep(Duration::from_secs(8)).await;
        let conv = tokio::time::timeout(Duration::from_secs(60), lab.conversation(&[src, dst])).await;
        match conv {
            Ok(Ok(c)) => {
                let mut ds = Vec::new();
                for _ in 0..o.n(5, 3) {
                    ds.extend(lab.message(c, src, &[dst], Duration::from_secs(30)).await);
                }
                judge(&mut r, "messages", &ds, 1.0, 5.0);
                let call = lab.call(c, src, dst, Duration::from_secs(3)).await;
                judge_call(&mut r, "call", &call, 5.0, 5.0);
            }
            other => {
                r.check("a conversation between the two BLE-only phones", false, format!("{:?}", other.map(|x| x.map(|_| ()))));
            }
        }
        r.note("Tier 2 runs the same path with GLOBAL's routing core (`us-eu`); here every hop is real QUIC over emulated Bluetooth, internet and relays.");
        finish(&mut r, t0, lab.devs.len(), rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── NAT and relays ─────────────────────────────

fn nat_relay(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("nat-relay", "NAT types, relay paths, relay outage and failover", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ups: Arc<Mutex<HashMap<mycel_crypto::SignPk, Uplink>>> = Arc::default();
        let inet = lab.add_medium(internet(0, o.seed, ups.clone()));
        let primary = lab.add_medium(relays(1, o.seed, ups.clone()));
        let backup = lab.add_medium(relays(2, o.seed ^ 7, ups.clone()));
        let people = [
            ("ny-lte", (40.71, -74.01), Access::Lte, Nat::Hard),
            ("ny-home", (40.73, -73.99), Access::Cable, Nat::Easy),
            ("london-5g", (51.51, -0.13), Access::FiveG, Nat::Hard),
            ("london-office", (51.52, -0.10), Access::Fibre, Nat::Open),
            ("tokyo-home", (35.68, 139.69), Access::Fibre, Nat::Easy),
            ("sf-lte", (37.77, -122.42), Access::Lte, Nat::Hard),
        ];
        for (name, ll, acc, nat) in people {
            let p = Pos::new(ll.0, ll.1);
            let i = lab.device(name, &[(&inet, p), (&primary, p), (&backup, p)], DevOpts::default()).await;
            ups.lock().insert(lab.devs[i].node.id(), Uplink { latlon: ll, access: acc, nat });
        }
        let n = people.len();
        for a in 0..n {
            for b in a + 1..n {
                lab.introduce(a, b);
            }
        }
        let all: Vec<(usize, usize)> = (0..n).flat_map(|a| (a + 1..n).map(move |b| (a, b))).collect();
        let mut convs = Vec::new();
        for &(a, b) in &all {
            convs.push(lab.conversation(&[a, b]).await.ok());
        }
        let mut ds = Vec::new();
        for (i, &(a, b)) in all.iter().enumerate() {
            if let Some(c) = convs[i] {
                ds.extend(lab.message(c, a, &[b], Duration::from_secs(20)).await);
            } else {
                ds.push(Delivery { from: a, to: b, latency: None, optimal: None });
            }
        }
        judge(&mut r, "messages", &ds, 1.0, 2.0);
        // who went direct, who through a relay
        let mut wrong = Vec::new();
        for &(a, b) in &all {
            let direct = Nat::direct(people[a].3, people[b].3);
            let via = lab.devs[a].via(&lab.devs[b]);
            let ok = if direct { via == Some(PathKind::Network) } else { via == Some(PathKind::Relay) };
            if !ok {
                wrong.push(format!("{}–{}: {via:?} (direct possible: {direct})", people[a].0, people[b].0));
            }
        }
        r.check("NAT-blocked pairs use a relay, others go direct", wrong.is_empty(), if wrong.is_empty() { "all as expected".into() } else { wrong.join("; ") });
        // the primary relays go down
        primary.set_medium_up(false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut ds2 = Vec::new();
        for (i, &(a, b)) in all.iter().enumerate() {
            if let Some(c) = convs[i] {
                ds2.extend(lab.message(c, a, &[b], Duration::from_secs(30)).await);
            }
        }
        judge(&mut r, "during the relay outage", &ds2, 1.0, 10.0);
        finish(&mut r, t0, n, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── adversarial (live) ─────────────────────────────

fn adversarial_live(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("adversarial-live", "A black-hole relay and an announcement storm", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
        // A at the left, C at the right, 100 m apart; two relays in between
        let a = lab.device("alice", &[(&ble, Pos::new(0.0, 0.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        let hole = MeshOptions { relay_rate_total: 0, relay_rate_per_neighbour: 0, ..mesh().expect("mesh") };
        lab.device("blackhole", &[(&ble, Pos::new(50.0, 10.0))], DevOpts { mesh: Some(hole), ..Default::default() }).await;
        lab.device("honest", &[(&ble, Pos::new(50.0, -10.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        let storm = MeshOptions { announce_every: Duration::from_millis(10), ..mesh().expect("mesh") };
        lab.device("storm", &[(&ble, Pos::new(20.0, 30.0))], DevOpts { mesh: Some(storm), ..Default::default() }).await;
        let c = lab.device("carol", &[(&ble, Pos::new(100.0, 0.0))], DevOpts { mesh: mesh(), ..Default::default() }).await;
        tokio::time::sleep(Duration::from_secs(8)).await;
        let (ds, _) = probe(&mut lab, &[(a, c)], o.n(6, 3), Duration::from_millis(500), Duration::from_secs(30)).await;
        judge(&mut r, "messages past a black hole and a storm", &ds, 1.0, 5.0);
        let limited: u64 = lab.devs.iter().filter_map(|d| d.node.mesh().map(|m| m.stats().announcements_limited)).sum();
        let storm_sent = lab.devs[3].node.mesh().map_or(0, |m| m.stats().announcements_sent);
        r.note(format!("The storm device (announce_every = 10 ms) sent {storm_sent} announcements; neighbours rate-limited {limited}. The node announces from a 10 ms tick, so a settings change can't exceed the 100/s per-neighbour limit; a real storm needs a modified binary, which tier 2's `adversarial` models (and its announcements are limited)."));
        finish(&mut r, t0, lab.devs.len(), rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── multipath ─────────────────────────────

fn multipath(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("multipath", "Several radios between two devices, aggregated", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        // three comparable links, each held to 3 MB/s so aggregation is visible
        let mut media = Vec::new();
        for (slot, tech) in [(0, Tech::Awdl), (1, Tech::WifiDirect), (2, Tech::Ethernet)] {
            let mut m = tech.medium(Env::Indoor);
            m.rate = Some(3_000_000);
            m.jitter = Duration::from_millis(1);
            m.shared_channel = false;
            m.max_queue = Duration::from_millis(100);
            media.push(lab.add_medium(EmuNet::new(slot, m, o.seed)));
        }
        let p = Pos::new(0.0, 0.0);
        let at: Vec<(&EmuNet, Pos)> = media.iter().map(|m| (m, p)).collect();
        let a = lab.device("laptopA", &at, DevOpts { bulk: true, ..Default::default() }).await;
        let b = lab.device("laptopB", &at, DevOpts { bulk: true, ..Default::default() }).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let bytes = (o.n(24, 12) as u64) << 20;
        let all = lab.bulk(a, b, bytes, Duration::from_secs(120)).await;
        media[1].set_medium_up(false);
        media[2].set_medium_up(false);
        tokio::time::sleep(Duration::from_secs(6)).await;
        let one = lab.bulk(a, b, bytes, Duration::from_secs(120)).await;
        let rate = |d: Option<Duration>| d.map_or(0.0, |d| bytes as f64 / d.as_secs_f64() / 1e6);
        let gain = rate(all) / rate(one).max(1e-9);
        r.at_least("three links vs one", gain, 1.8, "×");
        r.headline(format!("3 links {:.1} MB/s, 1 link {:.1} MB/s ({:.2}×)", rate(all), rate(one), gain));
        finish(&mut r, t0, 2, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── mixed room ─────────────────────────────

fn mixed_room(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("mixed-room", "UWB, Ethernet, Wi-Fi Direct and BLE in one room: ranking", 1, o.seed, o.scale);
    block_on(async {
        let (rss0, cpu0) = resources();
        let t0 = Instant::now();
        let mut lab = Lab::new();
        let order = [(0, Tech::Ethernet), (1, Tech::WifiDirect), (2, Tech::Uwb), (3, Tech::Ble)];
        let media: Vec<EmuNet> = order.iter().map(|(s, t)| lab.add_medium(net(*s, *t, Env::Indoor, o.seed))).collect();
        let at: Vec<(&EmuNet, Pos)> = media.iter().map(|m| (m, Pos::new(0.0, 0.0))).collect();
        let a = lab.device("deskA", &at, DevOpts::default()).await;
        let b = lab.device("deskB", &at, DevOpts::default()).await;
        let c = lab.conversation(&[a, b]).await;
        let Ok(c) = c else {
            r.check("conversation", false, "couldn't set up");
            return;
        };
        let mut steps = Vec::new();
        for (i, (_, tech)) in order.iter().enumerate() {
            // traffic so paths get measured, then look at the chosen one
            let mut via = None;
            for _ in 0..30 {
                let _ = lab.message(c, a, &[b], Duration::from_secs(10)).await;
                via = lab.devs[a].via(&lab.devs[b]);
                if via == Some(tech.kind()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            r.check(&format!("with {} available, the path is {}", order[i..].iter().map(|x| x.1.label()).collect::<Vec<_>>().join(", "), tech.label()), via == Some(tech.kind()), format!("{via:?}"));
            steps.push(format!("{}→{:?}", tech.label(), via));
            media[i].set_medium_up(false);
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        r.headline(steps.join(", "));
        finish(&mut r, t0, 2, rss0, cpu0);
        lab.shutdown().await;
    });
    r
}

// ───────────────────────────── scale ceiling ─────────────────────────────

fn scale_ceiling(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("scale-ceiling", "How many real nodes this machine runs", 1, o.seed, o.scale);
    let sizes: Vec<usize> = if o.scale >= 1.0 { vec![50, 100, 200, 500] } else { vec![o.n(50, 20)] };
    let mut rows = Vec::new();
    for n in sizes {
        block_on(async {
            let (rss0, cpu0) = resources();
            let t0 = Instant::now();
            let mut lab = Lab::new();
            let ble = lab.add_medium(net(0, Tech::Ble, Env::Outdoor, o.seed));
            let side = (n as f64).sqrt().ceil() as usize;
            for i in 0..n {
                let p = Pos::new((i % side) as f64 * 40.0, (i / side) as f64 * 40.0);
                lab.device(&format!("n{i}"), &[(&ble, p)], DevOpts { mesh: mesh(), ..Default::default() }).await;
            }
            let spawn = t0.elapsed();
            let (rss1, _) = resources();
            let (_, cpu1) = resources();
            let w0 = Instant::now();
            tokio::time::sleep(Duration::from_secs(20)).await;
            let (rss2, cpu2) = resources();
            let cpu_pct = 100.0 * (cpu2 - cpu1) / w0.elapsed().as_secs_f64();
            let reach: usize = lab.devs.iter().filter_map(|d| d.node.mesh().map(|m| m.reachable().len())).sum();
            let line = format!(
                "N={n}: spawned in {:.1} s; {:.1} MB per node; {:.0}% of a core in total ({:.2}% per node); mesh routes to {:.0}% of others",
                spawn.as_secs_f64(),
                (rss2 - rss0) / n as f64,
                cpu_pct,
                cpu_pct / n as f64,
                100.0 * reach as f64 / (n * (n - 1)) as f64
            );
            r.note(line.clone());
            r.headline(format!("N={n}: {:.1} MB, {:.2}% CPU per node", (rss2 - rss0) / n as f64, cpu_pct / n as f64));
            rows.push(json!({"n": n, "spawn_s": spawn.as_secs_f64(), "mb_per_node": (rss2 - rss0) / n as f64, "cpu_pct": cpu_pct, "rss_after_spawn": rss1 - rss0, "cpu0": cpu0}));
            r.at_most(&format!("N={n}: memory per node"), (rss2 - rss0) / n as f64, 10.0, "MB");
            lab.shutdown().await;
        });
    }
    r.metrics = serde_json::Value::Array(rows);
    let _ = tier1::grid;
    r
}
