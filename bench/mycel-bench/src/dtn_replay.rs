//! Replays a contact trace and a message workload (`bench/traces`) through
//! Mycel's store-and-forward carrier (`mycel_net::mesh::dtn::Carrier`), on
//! the same inputs The ONE replays, and prints ONE-style message statistics.
//!
//! What runs is Mycel's real carrier code. What this file models around it:
//!
//! - **Links, exactly as The ONE's `ActiveRouter` does**: a contact is a link
//!   of `--speed` bytes/s. A device takes part in one transfer at a time (as
//!   sender or receiver). A transfer completes after `size / speed` if the
//!   contact lasts that long, else it's aborted. Completions are applied at
//!   their exact time, before a contact goes down (The ONE updates every
//!   host at every event). Deliveries go first.
//! - **The router's live routes** (`Router::toward`): a breadth-first search
//!   over the contacts up right now (plus the gateways' internet clique), up
//!   to `max_hops`. That's the route Mycel's router converges to within ~1 s
//!   of a change (docs/ROUTING.md); contacts here last minutes. A device
//!   without the internet that can reach a gateway sends bundles it has no
//!   route for toward the nearest one (the default route).
//! - **The driver** (`mesh/mod.rs`): `encounter` when a contact comes up,
//!   summaries on a new contact and every 5 s, `plan` every second.
//!
//! `--carrier fixed --fixes own,free,expiry,resume,spray,evict,inet` runs the
//! experimental copy in `carrier_fixed.rs` instead, with the proposed fixes
//! switched on one at a time (docs/BENCHMARKS.md §6). `resume` is modelled
//! here: an interrupted transfer keeps the bytes that arrived, and the next
//! transfer of that bundle to that device only sends the rest.
//!
//! Besides ONE's statistics it prints transfers by reason, the carriers'
//! counters and `refused_by` (why receivers refused); `--latencies` writes
//! every message's latency, for "delivered within" comparisons.
//!
//! Usage:
//!   dtn-replay --contacts c.csv --messages m.csv [--gateways 0-16]
//!              [--speed 250000] [--buffer 5000000] [--ttl-min 300]
//!              [--copies 4] [--end <s>] [--label name]
//!              [--carrier real|fixed] [--fixes all,spray,evict,inet,...]
//!              [--latencies out.csv] [--step-ms 1000]

use std::collections::{BTreeSet, HashMap, VecDeque};

use bytes::Bytes;
use mycel_crypto::{Hash32, Sig, SignPk};
use mycel_net::mesh::core::{Time, Toward};
use mycel_net::mesh::dtn::{self, Accepted, Bundle, DtnConfig, DtnStats, Receipt, Why};

mod carrier_fixed;
use carrier_fixed::Fixes;

/// Payload bytes: bundles only need the right length.
static ZERO: [u8; 4 << 20] = [0; 4 << 20];
const SUMMARY_EVERY: Time = 5_000;

fn key(i: usize) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&(i as u32).to_be_bytes());
    k[31] = 0x42;
    SignPk(k)
}

fn idx(k: &SignPk) -> usize {
    u32::from_be_bytes(k.0[..4].try_into().unwrap()) as usize
}

struct Args {
    contacts: String,
    messages: String,
    gateways: BTreeSet<usize>,
    speed: u64,
    buffer: u64,
    ttl_ms: Time,
    copies: u8,
    end: Option<f64>,
    max_hops: usize,
    label: String,
    fixed: bool,
    fixes: Fixes,
    latencies: Option<String>,
    /// How often the carrier plans (the real driver: every second).
    step: Time,
}

/// The carrier API the replay drives: the real one, or the patched copy.
trait Carry {
    type Summary;
    fn has_any(&self) -> bool;
    fn set_internet(&mut self, on: bool);
    fn encounter(&mut self, peer: SignPk, now: Time);
    fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str>;
    fn accept(&mut self, from: SignPk, b: Bundle, copies: u8, now: Time) -> Accepted;
    fn summary(&self, now: Time) -> Self::Summary;
    fn on_summary(&mut self, from: SignPk, s: Self::Summary, now: Time);
    fn add_receipt(&mut self, r: Receipt);
    fn plan(&mut self, now: Time, toward: impl FnMut(&SignPk) -> Toward, nbs: &[SignPk]) -> Vec<dtn::Transfer>;
    fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, refused: bool, now: Time);
    fn tick(&mut self, now: Time);
    fn bundle(&self, id: &Hash32) -> Option<&Bundle>;
    fn stats(&self) -> DtnStats;
}

impl Carry for dtn::Carrier {
    type Summary = dtn::Summary;
    fn has_any(&self) -> bool {
        !self.held().is_empty()
    }
    fn set_internet(&mut self, on: bool) {
        dtn::Carrier::set_internet(self, on)
    }
    fn encounter(&mut self, peer: SignPk, now: Time) {
        dtn::Carrier::encounter(self, peer, now)
    }
    fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str> {
        dtn::Carrier::originate(self, b, now)
    }
    fn accept(&mut self, from: SignPk, b: Bundle, copies: u8, now: Time) -> Accepted {
        dtn::Carrier::accept(self, from, b, copies, now, |_| true)
    }
    fn summary(&self, now: Time) -> dtn::Summary {
        dtn::Carrier::summary(self, now)
    }
    fn on_summary(&mut self, from: SignPk, s: dtn::Summary, now: Time) {
        dtn::Carrier::on_summary(self, from, s, now, |_| true)
    }
    fn add_receipt(&mut self, r: Receipt) {
        dtn::Carrier::add_receipt(self, r)
    }
    fn plan(&mut self, now: Time, toward: impl FnMut(&SignPk) -> Toward, nbs: &[SignPk]) -> Vec<dtn::Transfer> {
        dtn::Carrier::plan(self, now, toward, nbs)
    }
    fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, _refused: bool, now: Time) {
        dtn::Carrier::transferred(self, to, id, copies, ok, now)
    }
    fn tick(&mut self, now: Time) {
        dtn::Carrier::tick(self, now)
    }
    fn bundle(&self, id: &Hash32) -> Option<&Bundle> {
        dtn::Carrier::bundle(self, id)
    }
    fn stats(&self) -> DtnStats {
        dtn::Carrier::stats(self)
    }
}

impl Carry for carrier_fixed::Carrier {
    type Summary = carrier_fixed::FixedSummary;
    fn has_any(&self) -> bool {
        carrier_fixed::Carrier::has_any(self)
    }
    fn set_internet(&mut self, on: bool) {
        carrier_fixed::Carrier::set_internet(self, on)
    }
    fn encounter(&mut self, peer: SignPk, now: Time) {
        carrier_fixed::Carrier::encounter(self, peer, now)
    }
    fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str> {
        carrier_fixed::Carrier::originate(self, b, now)
    }
    fn accept(&mut self, from: SignPk, b: Bundle, copies: u8, now: Time) -> Accepted {
        carrier_fixed::Carrier::accept(self, from, b, copies, now)
    }
    fn summary(&self, now: Time) -> carrier_fixed::FixedSummary {
        carrier_fixed::Carrier::summary(self, now)
    }
    fn on_summary(&mut self, from: SignPk, s: carrier_fixed::FixedSummary, now: Time) {
        carrier_fixed::Carrier::on_summary(self, from, s, now)
    }
    fn add_receipt(&mut self, r: Receipt) {
        carrier_fixed::Carrier::add_receipt(self, r)
    }
    fn plan(&mut self, now: Time, toward: impl FnMut(&SignPk) -> Toward, nbs: &[SignPk]) -> Vec<dtn::Transfer> {
        carrier_fixed::Carrier::plan(self, now, toward, nbs)
    }
    fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, refused: bool, now: Time) {
        carrier_fixed::Carrier::transferred(self, to, id, copies, ok, refused, now)
    }
    fn tick(&mut self, now: Time) {
        carrier_fixed::Carrier::tick(self, now)
    }
    fn bundle(&self, id: &Hash32) -> Option<&Bundle> {
        carrier_fixed::Carrier::bundle(self, id)
    }
    fn stats(&self) -> DtnStats {
        carrier_fixed::Carrier::stats(self)
    }
}

fn parse_ranges(s: &str) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => out.extend(a.parse::<usize>().unwrap()..=b.parse::<usize>().unwrap()),
            None => {
                out.insert(part.parse().unwrap());
            }
        }
    }
    out
}

fn args() -> Args {
    let mut a = Args {
        contacts: String::new(),
        messages: String::new(),
        gateways: BTreeSet::new(),
        speed: 250_000,
        buffer: 5_000_000,
        ttl_ms: 300 * 60_000,
        copies: 4,
        end: None,
        max_hops: 8,
        label: "mycel".into(),
        fixed: false,
        fixes: Fixes::default(),
        latencies: None,
        step: 1_000,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut v = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--contacts" => a.contacts = v(),
            "--messages" => a.messages = v(),
            "--gateways" => a.gateways = parse_ranges(&v()),
            "--speed" => a.speed = v().parse().unwrap(),
            "--buffer" => a.buffer = v().parse().unwrap(),
            "--ttl-min" => a.ttl_ms = v().parse::<u64>().unwrap() * 60_000,
            "--copies" => a.copies = v().parse().unwrap(),
            "--end" => a.end = Some(v().parse().unwrap()),
            "--max-hops" => a.max_hops = v().parse().unwrap(),
            "--label" => a.label = v(),
            "--carrier" => {
                a.fixed = match v().as_str() {
                    "real" => false,
                    "fixed" => true,
                    other => panic!("--carrier real|fixed, not {other}"),
                }
            }
            "--fixes" => a.fixes = Fixes::parse(&v()),
            "--latencies" => a.latencies = Some(v()),
            "--step-ms" => a.step = v().parse().unwrap(),
            other => panic!("unknown flag {other}"),
        }
    }
    assert!(!a.contacts.is_empty() && !a.messages.is_empty(), "--contacts and --messages are required");
    a
}

fn ms(s: &str) -> Time {
    (s.parse::<f64>().unwrap() * 1000.0).round() as Time
}

/// A contact going up or down: (time, up, a, b).
type ContactEvent = (Time, bool, usize, usize);

/// Contact events (downs before ups at the same instant), devices, end.
fn read_contacts(path: &str, gateways: &BTreeSet<usize>) -> (Vec<ContactEvent>, usize, Time) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut ev = Vec::new();
    let (mut n, mut end) = (0, 0);
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        let (s, e, a, b) = (ms(f[0]), ms(f[1]), f[2].parse().unwrap(), f[3].parse().unwrap());
        n = n.max(a + 1).max(b + 1);
        end = end.max(e);
        if gateways.contains(&a) && gateways.contains(&b) {
            continue; // always connected over the internet
        }
        ev.push((s, true, a, b));
        ev.push((e, false, a, b));
    }
    ev.sort_by_key(|&(t, up, a, b)| (t, up, a, b));
    (ev, n, end)
}

struct Msg {
    at: Time,
    src: usize,
    dst: usize,
    size: usize,
}

fn read_messages(path: &str) -> Vec<Msg> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .skip(1)
        .map(|line| {
            let f: Vec<&str> = line.split(',').collect();
            Msg { at: ms(f[0]), src: f[2].parse().unwrap(), dst: f[3].parse().unwrap(), size: f[4].parse().unwrap() }
        })
        .collect()
}

fn bundle_id(k: usize) -> Hash32 {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(k as u64).to_be_bytes());
    b[31] = 0xb0;
    Hash32(b)
}

struct Transfer {
    from: usize,
    to: usize,
    id: Hash32,
    copies: u8,
    started: Time,
    done_at: Time,
}

#[derive(Default)]
struct Counters {
    started: u64,
    relayed: u64,
    aborted: u64,
    refused: u64,
    refused_why: std::collections::BTreeMap<&'static str, u64>,
    by_why: [u64; 4],
}

struct Sim<C: Carry> {
    a: Args,
    n: usize,
    nodes: Vec<C>,
    adj: Vec<BTreeSet<usize>>,
    internet: Vec<bool>,
    busy: Vec<bool>,
    active: Vec<Transfer>,
    last_summary: HashMap<(usize, usize), Time>,
    /// id → (message index, created)
    meta: HashMap<Hash32, (usize, Time)>,
    delivered: HashMap<Hash32, (Time, u32)>,
    hops: HashMap<(usize, Hash32), u32>,
    /// Bytes of a bundle a device already has from interrupted transfers
    /// (the `resume` fix).
    partial: HashMap<(usize, Hash32), u64>,
    c: Counters,
}

impl<C: Carry> Sim<C> {
    fn neighbours(&self, i: usize) -> Vec<usize> {
        let mut v: Vec<usize> = self.adj[i].iter().copied().collect();
        if self.internet[i] {
            v.extend(self.a.gateways.iter().copied().filter(|g| *g != i && !self.adj[i].contains(g)));
        }
        v
    }

    /// First hops from `i` toward every device reachable now, and toward the
    /// nearest gateway.
    fn routes_from(&self, i: usize) -> (Vec<Option<usize>>, Option<usize>) {
        let mut first: Vec<Option<usize>> = vec![None; self.n];
        let mut depth = vec![usize::MAX; self.n];
        let mut q = VecDeque::new();
        depth[i] = 0;
        q.push_back(i);
        let mut nearest_gw = None;
        while let Some(x) = q.pop_front() {
            if x != i && self.internet[x] && nearest_gw.is_none() {
                nearest_gw = first[x];
            }
            if depth[x] >= self.a.max_hops {
                continue;
            }
            for y in self.neighbours(x) {
                if depth[y] == usize::MAX {
                    depth[y] = depth[x] + 1;
                    first[y] = if x == i { Some(y) } else { first[x] };
                    q.push_back(y);
                }
            }
        }
        (first, if self.internet[i] { None } else { nearest_gw })
    }

    fn contact(&mut self, t: Time, up: bool, a: usize, b: usize) {
        if up {
            self.adj[a].insert(b);
            self.adj[b].insert(a);
            self.nodes[a].encounter(key(b), t);
            self.nodes[b].encounter(key(a), t);
        } else {
            self.adj[a].remove(&b);
            self.adj[b].remove(&a);
            self.last_summary.remove(&(a, b));
            self.last_summary.remove(&(b, a));
            let (mut keep, mut cut) = (Vec::new(), Vec::new());
            for tr in self.active.drain(..) {
                if (tr.from == a && tr.to == b) || (tr.from == b && tr.to == a) {
                    cut.push(tr);
                } else {
                    keep.push(tr);
                }
            }
            self.active = keep;
            for tr in cut {
                self.busy[tr.from] = false;
                self.busy[tr.to] = false;
                if self.a.fixes.resume {
                    let got = t.saturating_sub(tr.started) * self.a.speed / 1000;
                    *self.partial.entry((tr.to, tr.id)).or_default() += got;
                }
                self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, false, false, t);
                self.c.aborted += 1;
            }
        }
    }

    fn complete(&mut self, t: Time) {
        let (done, rest): (Vec<Transfer>, Vec<Transfer>) = self.active.drain(..).partition(|tr| tr.done_at <= t);
        self.active = rest;
        for tr in done {
            self.busy[tr.from] = false;
            self.busy[tr.to] = false;
            let Some(b) = self.nodes[tr.from].bundle(&tr.id).cloned() else {
                // expired or cleared by a receipt mid-transfer
                self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, false, false, t);
                continue;
            };
            self.partial.remove(&(tr.to, tr.id));
            let h = self.hops.get(&(tr.from, tr.id)).copied().unwrap_or(0) + 1;
            let mut refused = false;
            let ok = match self.nodes[tr.to].accept(key(tr.from), b, tr.copies, t) {
                Accepted::ForMe(b) => {
                    self.delivered.entry(b.id).or_insert((t, h));
                    self.nodes[tr.to].add_receipt(Receipt { id: b.id, dst: b.dst, sig: Sig([0; 64]) });
                    true
                }
                Accepted::Stored => {
                    self.hops.insert((tr.to, tr.id), h);
                    true
                }
                Accepted::Duplicate => true,
                Accepted::Refused(why) => {
                    self.c.refused += 1;
                    *self.c.refused_why.entry(why).or_default() += 1;
                    refused = true;
                    false
                }
            };
            if ok {
                self.c.relayed += 1;
            }
            self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, ok, refused, t);
        }
    }

    fn summaries(&mut self, t: Time) {
        for i in 0..self.n {
            for j in self.neighbours(i) {
                let due = self.last_summary.get(&(i, j)).is_none_or(|at| t.saturating_sub(*at) >= SUMMARY_EVERY);
                if due {
                    let s = self.nodes[i].summary(t);
                    self.nodes[j].on_summary(key(i), s, t);
                    self.last_summary.insert((i, j), t);
                }
            }
        }
    }

    fn plan(&mut self, t: Time) {
        for i in 0..self.n {
            if self.busy[i] || !self.nodes[i].has_any() {
                continue;
            }
            let nbs = self.neighbours(i);
            if nbs.is_empty() {
                continue;
            }
            let keys: Vec<SignPk> = nbs.iter().map(|j| key(*j)).collect();
            let (first, gw) = self.routes_from(i);
            let plan = self.nodes[i].plan(
                t,
                |dst| match first.get(idx(dst)).copied().flatten().or(gw) {
                    Some(n) => Toward::Hop(key(n)),
                    None => Toward::Nowhere,
                },
                &keys,
            );
            let rank = |w: Why| match w {
                Why::Deliver => 0,
                Why::Route => 1,
                Why::Gradient => 2,
                Why::Spray => 3,
            };
            let pick = plan
                .iter()
                .enumerate()
                .filter(|(_, tr)| !self.busy[idx(&tr.to)])
                .min_by_key(|(k, tr)| (rank(tr.why), *k))
                .map(|(k, _)| k);
            for (k, tr) in plan.into_iter().enumerate() {
                if Some(k) != pick {
                    self.nodes[i].transferred(tr.to, tr.id, tr.copies, false, false, t);
                    continue;
                }
                let to = idx(&tr.to);
                let size = self.nodes[i].bundle(&tr.id).map_or(0, |b| b.payload.len()) as u64;
                let have = self.partial.get(&(to, tr.id)).copied().unwrap_or(0).min(size);
                let dur = ((size - have) * 1000).div_ceil(self.a.speed).max(1);
                self.busy[i] = true;
                self.busy[to] = true;
                self.c.started += 1;
                self.c.by_why[rank(tr.why)] += 1;
                self.active.push(Transfer { from: i, to, id: tr.id, copies: tr.copies, started: t, done_at: t + dur });
            }
        }
    }
}

fn main() {
    let a = args();
    if a.fixed {
        let fixes = a.fixes;
        run(a, |me, cfg| carrier_fixed::Carrier::new(me, cfg, fixes));
    } else {
        run(a, dtn::Carrier::new);
    }
}

fn run<C: Carry>(a: Args, make: impl Fn(SignPk, DtnConfig) -> C) {
    let (events, n_trace, trace_end) = read_contacts(&a.contacts, &a.gateways);
    let msgs = read_messages(&a.messages);
    let n = n_trace.max(msgs.iter().map(|m| m.src.max(m.dst) + 1).max().unwrap_or(0));
    let end = a.end.map_or(trace_end, |s| (s * 1000.0) as Time);
    let cfg = DtnConfig {
        capacity: a.buffer,
        max_bundle: ZERO.len(),
        per_source: a.buffer,
        max_lifetime: 7 * 24 * 3_600_000,
        copies: a.copies,
        carry: true,
    };
    let mut sim = Sim {
        n,
        nodes: (0..n).map(|i| make(key(i), cfg.clone())).collect(),
        adj: vec![BTreeSet::new(); n],
        internet: (0..n).map(|i| a.gateways.contains(&i)).collect(),
        busy: vec![false; n],
        active: Vec::new(),
        last_summary: HashMap::new(),
        meta: HashMap::new(),
        delivered: HashMap::new(),
        hops: HashMap::new(),
        partial: HashMap::new(),
        c: Counters::default(),
        a,
    };
    for i in 0..n {
        let on = sim.internet[i];
        sim.nodes[i].set_internet(on);
    }
    let (mut ei, mut mi) = (0, 0);
    let mut t: Time = 0;
    let wall = std::time::Instant::now();
    while t <= end {
        while ei < events.len() && events[ei].0 <= t {
            let (et, up, x, y) = events[ei];
            // Transfers finish at their own time, not at the next step: a
            // 40 ms transfer on a contact that ends half a second later
            // completes (The ONE finalizes transfers at every event too).
            sim.complete(et);
            sim.contact(et, up, x, y);
            ei += 1;
        }
        while mi < msgs.len() && msgs[mi].at <= t {
            let m = &msgs[mi];
            let id = bundle_id(mi);
            let b = Bundle {
                id,
                src: key(m.src),
                dst: key(m.dst),
                created: m.at,
                lifetime: sim.a.ttl_ms,
                payload: Bytes::from_static(&ZERO[..m.size.min(ZERO.len())]),
                sig: Sig([0; 64]),
            };
            sim.meta.insert(id, (mi, m.at));
            sim.nodes[m.src].originate(b, t).expect("originate");
            mi += 1;
        }
        sim.complete(t);
        sim.summaries(t);
        for c in &mut sim.nodes {
            c.tick(t);
        }
        sim.plan(t);
        t += sim.a.step;
    }

    // ONE MessageStatsReport semantics: delivered within the TTL, latency
    // from creation, overhead = (relayed - delivered) / delivered.
    let created = msgs.len();
    let mut lat = Vec::new();
    let mut hops = Vec::new();
    let mut late = 0;
    for (id, (at, h)) in &sim.delivered {
        let (_, made) = sim.meta[id];
        if at - made <= sim.a.ttl_ms {
            lat.push((at - made) as f64 / 1000.0);
            hops.push(*h as f64);
        } else {
            late += 1;
        }
    }
    if let Some(path) = &sim.a.latencies {
        // every created message: its creation time and latency (empty if it
        // wasn't delivered within the TTL), for comparisons over all messages
        let mut out = String::from("msg,created_s,latency_s\n");
        let mut by_msg: Vec<(usize, Time, Option<f64>)> = sim
            .meta
            .iter()
            .map(|(id, (mi, made))| {
                let l = sim.delivered.get(id).map(|(at, _)| at - made).filter(|l| *l <= sim.a.ttl_ms);
                (*mi, *made, l.map(|l| l as f64 / 1000.0))
            })
            .collect();
        by_msg.sort_by_key(|x| x.0);
        for (mi, made, l) in by_msg {
            out += &format!("{mi},{:.1},{}\n", made as f64 / 1000.0, l.map_or(String::new(), |l| format!("{l:.1}")));
        }
        std::fs::write(path, out).unwrap();
    }
    lat.sort_by(f64::total_cmp);
    hops.sort_by(f64::total_cmp);
    let delivered = lat.len();
    let mean = |v: &[f64]| if v.is_empty() { f64::NAN } else { v.iter().sum::<f64>() / v.len() as f64 };
    let med = |v: &[f64]| if v.is_empty() { f64::NAN } else { v[v.len() / 2] };
    let stats = sim.nodes.iter().fold([0u64; 4], |mut acc, c| {
        let s = c.stats();
        acc[0] += s.expired;
        acc[1] += s.cleared_by_receipt;
        acc[2] += s.refused;
        acc[3] += s.accepted;
        acc
    });
    println!("Message stats for scenario {}", sim.a.label);
    println!("sim_time: {:.4}", end as f64 / 1000.0);
    println!("created: {created}");
    println!("started: {}", sim.c.started);
    println!("relayed: {}", sim.c.relayed);
    println!("aborted: {}", sim.c.aborted);
    println!("refused: {}", sim.c.refused);
    println!("delivered: {delivered}");
    println!("delivered_after_ttl: {late}");
    println!("delivery_prob: {:.4}", delivered as f64 / created as f64);
    println!(
        "overhead_ratio: {:.4}",
        if delivered == 0 { f64::NAN } else { (sim.c.relayed as f64 - delivered as f64) / delivered as f64 }
    );
    println!("latency_avg: {:.4}", mean(&lat));
    println!("latency_med: {:.4}", med(&lat));
    println!("hopcount_avg: {:.4}", mean(&hops));
    println!("hopcount_med: {}", med(&hops));
    println!(
        "transfers_by_reason: deliver {} route {} gradient {} spray {}",
        sim.c.by_why[0], sim.c.by_why[1], sim.c.by_why[2], sim.c.by_why[3]
    );
    println!("carrier: expired {} cleared_by_receipt {} refused {} accepted {}", stats[0], stats[1], stats[2], stats[3]);
    println!("refused_by: {:?}", sim.c.refused_why);
    eprintln!("({} devices, {} contact events, {:.1} s)", n, events.len(), wall.elapsed().as_secs_f64());
}
