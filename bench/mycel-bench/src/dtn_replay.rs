//! Replays a contact trace and a message workload (`bench/traces`) through
//! Mycel's store-and-forward carrier (`mycel_net::mesh::dtn::Carrier`), on
//! the same inputs The ONE replays, and prints ONE-style message statistics.
//!
//! What runs is Mycel's real carrier code. What this file models around it:
//!
//! - **Links, exactly as The ONE's `ActiveRouter` does**: a contact is a link
//!   of `--speed` bytes/s. A device takes part in one transfer at a time (as
//!   sender or receiver). A transfer completes after `size / speed` if the
//!   contact lasts that long, else it's cut. Completions are applied at
//!   their exact time, before a contact goes down (The ONE updates every
//!   host at every event). Deliveries go first.
//! - **The router's live routes** (`Router::toward`): a breadth-first search
//!   over the contacts up right now (plus the gateways' internet clique), up
//!   to `max_hops`. That's the route Mycel's router converges to within ~1 s
//!   of a change (docs/ROUTING.md); contacts here last minutes. A device
//!   without the internet that can reach a gateway sends bundles it has no
//!   route for toward the nearest one (the default route).
//! - **The driver** (`mesh/mod.rs`): `encounter` when a contact comes up,
//!   summaries on a new contact and every 5 s, `plan` every second. Each
//!   bundle is **offered** first and the payload sent only if the receiver
//!   takes it, as the node does; an offer costs no link time here (a round
//!   trip, against seconds of payload). A device tries its planned
//!   transfers in order until one is taken.
//! - **Resume**: a cut transfer leaves its bytes with the receiver
//!   (`Carrier::keep_partial`), and the next offer of that bundle, from
//!   anyone, sends only the rest. `--no-resume` turns that off (The ONE's
//!   routers can't resume).
//!
//! `--knobs spray=focus,gradient=both,...` sets carrier knobs
//! (`DtnConfig::tune`); `--copies N` gives every bundle N copies whatever
//! its size.
//!
//! Besides ONE's statistics it prints transfers by reason, offers, the
//! carriers' counters and `refused_by` (why receivers refused); `--latencies`
//! writes every message's latency, for "delivered within" comparisons.
//!
//! Usage:
//!   dtn-replay --contacts c.csv --messages m.csv [--gateways 0-16]
//!              [--speed 250000] [--buffer 5000000] [--ttl-min 300]
//!              [--copies N] [--knobs k=v,...] [--no-resume] [--end <s>]
//!              [--label name] [--latencies out.csv] [--step-ms 1000]

use std::collections::{BTreeSet, HashMap, VecDeque};

use bytes::Bytes;
use mycel_crypto::{Hash32, Sig, SignPk};
use mycel_net::mesh::core::{Time, Toward};
use mycel_net::mesh::dtn::{Accepted, Answer, Bundle, Carrier, DtnConfig, Offer, Receipt, Why};

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
    copies: Option<u8>,
    knobs: String,
    resume: bool,
    end: Option<f64>,
    max_hops: usize,
    label: String,
    latencies: Option<String>,
    /// How often the carrier plans (the real driver: every second).
    step: Time,
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
        copies: None,
        knobs: String::new(),
        resume: true,
        end: None,
        max_hops: 8,
        label: "mycel".into(),
        latencies: None,
        step: 1_000,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--no-resume" {
            a.resume = false;
            continue;
        }
        let mut v = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--contacts" => a.contacts = v(),
            "--messages" => a.messages = v(),
            "--gateways" => a.gateways = parse_ranges(&v()),
            "--speed" => a.speed = v().parse().unwrap(),
            "--buffer" => a.buffer = v().parse().unwrap(),
            "--ttl-min" => a.ttl_ms = v().parse::<u64>().unwrap() * 60_000,
            "--copies" => a.copies = Some(v().parse().unwrap()),
            "--knobs" => a.knobs = v(),
            "--end" => a.end = Some(v().parse().unwrap()),
            "--max-hops" => a.max_hops = v().parse().unwrap(),
            "--label" => a.label = v(),
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
    src: SignPk,
    copies: u8,
    /// Bytes the receiver had before this transfer (a resume).
    have: u64,
    size: u64,
    started: Time,
    done_at: Time,
}

#[derive(Default)]
struct Counters {
    started: u64,
    relayed: u64,
    aborted: u64,
    offers: u64,
    refused: u64,
    duplicates: u64,
    refused_why: std::collections::BTreeMap<&'static str, u64>,
    by_why: [u64; 4],
}

/// Who is in contact with whom right now, and who has the internet.
struct Net {
    adj: Vec<BTreeSet<usize>>,
    internet: Vec<bool>,
}

struct Sim {
    a: Args,
    n: usize,
    nodes: Vec<Carrier>,
    net: Net,
    busy: Vec<bool>,
    active: Vec<Transfer>,
    last_summary: HashMap<(usize, usize), Time>,
    /// id → (message index, created)
    meta: HashMap<Hash32, (usize, Time)>,
    delivered: HashMap<Hash32, (Time, u32)>,
    hops: HashMap<(usize, Hash32), u32>,
    c: Counters,
}

fn rank(w: Why) -> usize {
    match w {
        Why::Deliver => 0,
        Why::Route => 1,
        Why::Gradient => 2,
        Why::Spray => 3,
    }
}

impl Sim {
    fn neighbours(&self, i: usize) -> Vec<usize> {
        let mut v: Vec<usize> = self.net.adj[i].iter().copied().collect();
        if self.net.internet[i] {
            v.extend(self.a.gateways.iter().copied().filter(|g| *g != i && !self.net.adj[i].contains(g)));
        }
        v
    }

    /// First hops from `i` toward every device reachable now, and toward the
    /// nearest gateway.
    fn routes_from(net: &Net, a: &Args, i: usize) -> (Vec<Option<usize>>, Option<usize>) {
        let n = net.adj.len();
        let mut first: Vec<Option<usize>> = vec![None; n];
        let mut depth = vec![usize::MAX; n];
        let mut q = VecDeque::new();
        depth[i] = 0;
        q.push_back(i);
        let mut nearest_gw = None;
        while let Some(x) = q.pop_front() {
            if x != i && net.internet[x] && nearest_gw.is_none() {
                nearest_gw = first[x];
            }
            if depth[x] >= a.max_hops {
                continue;
            }
            let gws = net.internet[x].then_some(&a.gateways).into_iter().flatten();
            for &y in net.adj[x].iter().chain(gws) {
                if depth[y] == usize::MAX {
                    depth[y] = depth[x] + 1;
                    first[y] = if x == i { Some(y) } else { first[x] };
                    q.push_back(y);
                }
            }
        }
        (first, if net.internet[i] { None } else { nearest_gw })
    }

    fn refuse(&mut self, from: usize, to: usize, id: Hash32, why: &'static str, t: Time) {
        self.c.refused += 1;
        *self.c.refused_why.entry(why).or_default() += 1;
        self.nodes[from].refused(key(to), id, why == "store full", t);
    }

    fn contact(&mut self, t: Time, up: bool, a: usize, b: usize) {
        if up {
            self.net.adj[a].insert(b);
            self.net.adj[b].insert(a);
            self.nodes[a].encounter(key(b), t);
            self.nodes[b].encounter(key(a), t);
        } else {
            self.net.adj[a].remove(&b);
            self.net.adj[b].remove(&a);
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
                if self.a.resume {
                    // what arrived stays with the receiver, as on the node
                    let got = (tr.have + t.saturating_sub(tr.started) * self.a.speed / 1000).min(tr.size);
                    if got > tr.have {
                        self.nodes[tr.to].keep_partial(tr.id, tr.src, Bytes::from_static(&ZERO[..got as usize]), t);
                    }
                }
                self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, false, t);
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
                self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, false, t);
                continue;
            };
            let h = self.hops.get(&(tr.from, tr.id)).copied().unwrap_or(0) + 1;
            match self.nodes[tr.to].accept(key(tr.from), b, tr.copies, t, |_| true) {
                Accepted::ForMe(b) => {
                    self.delivered.entry(b.id).or_insert((t, h));
                    self.nodes[tr.to].add_receipt(Receipt { id: b.id, dst: b.dst, sig: Sig([0; 64]) });
                }
                Accepted::Stored => {
                    self.hops.insert((tr.to, tr.id), h);
                }
                Accepted::Duplicate => {}
                Accepted::Refused(why) => {
                    // room went between the offer and the end of the payload
                    self.refuse(tr.from, tr.to, tr.id, why, t);
                    continue;
                }
            }
            self.c.relayed += 1;
            self.nodes[tr.from].transferred(key(tr.to), tr.id, tr.copies, true, t);
        }
    }

    fn summaries(&mut self, t: Time) {
        for i in 0..self.n {
            // one summary per device per step, to every neighbour it's due for
            let mut s = None;
            for j in self.neighbours(i) {
                let due = self.last_summary.get(&(i, j)).is_none_or(|at| t.saturating_sub(*at) >= SUMMARY_EVERY);
                if due {
                    let s = s.get_or_insert_with(|| self.nodes[i].summary(t)).clone();
                    self.nodes[j].on_summary(key(i), s, t, |_| true);
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
            // nothing can start (and planning changes nothing) if every neighbour is busy
            if nbs.iter().all(|j| self.busy[*j]) {
                continue;
            }
            let keys: Vec<SignPk> = nbs.iter().map(|j| key(*j)).collect();
            // routes only if a bundle needs them (most are for a neighbour, or none)
            let mut routes = None;
            let mut plan = {
                let (net, a, routes) = (&self.net, &self.a, &mut routes);
                self.nodes[i].plan(
                    t,
                    |dst| {
                        let (first, gw) = routes.get_or_insert_with(|| Sim::routes_from(net, a, i));
                        match first.get(idx(dst)).copied().flatten().or(*gw) {
                            Some(n) => Toward::Hop(key(n)),
                            None => Toward::Nowhere,
                        }
                    },
                    &keys,
                )
            };
            plan.sort_by_key(|tr| rank(tr.why));
            // offer in order until one is taken; the rest wait for the next plan
            let mut started = false;
            for tr in plan {
                let to = idx(&tr.to);
                if started || self.busy[to] {
                    self.nodes[i].transferred(tr.to, tr.id, tr.copies, false, t);
                    continue;
                }
                let Some(b) = self.nodes[i].bundle(&tr.id) else { continue };
                let offer = Offer::of(b, tr.copies);
                self.c.offers += 1;
                match self.nodes[to].offered(key(i), &offer, t, |_| true) {
                    Answer::Refuse(why) => self.refuse(i, to, tr.id, why, t),
                    Answer::Duplicate => {
                        self.c.duplicates += 1;
                        self.nodes[i].transferred(tr.to, tr.id, tr.copies, true, t);
                    }
                    Answer::Take { from } => {
                        let from = if self.a.resume { from } else { 0 };
                        let dur = ((offer.size - from) * 1000).div_ceil(self.a.speed).max(1);
                        self.busy[i] = true;
                        self.busy[to] = true;
                        self.c.started += 1;
                        self.c.by_why[rank(tr.why)] += 1;
                        self.active.push(Transfer {
                            from: i,
                            to,
                            id: tr.id,
                            src: offer.src,
                            copies: tr.copies,
                            have: from,
                            size: offer.size,
                            started: t,
                            done_at: t + dur,
                        });
                        started = true;
                    }
                }
            }
        }
    }
}

fn main() {
    let a = args();
    let (events, n_trace, trace_end) = read_contacts(&a.contacts, &a.gateways);
    let msgs = read_messages(&a.messages);
    let n = n_trace.max(msgs.iter().map(|m| m.src.max(m.dst) + 1).max().unwrap_or(0));
    let end = a.end.map_or(trace_end, |s| (s * 1000.0) as Time);
    let mut cfg = DtnConfig {
        capacity: a.buffer,
        max_bundle: ZERO.len(),
        per_source: a.buffer,
        max_lifetime: 7 * 24 * 3_600_000,
        ..DtnConfig::default()
    };
    if let Some(c) = a.copies {
        cfg.copies = c;
        cfg.copies_small = c;
    }
    cfg.tune(&a.knobs).unwrap_or_else(|e| panic!("--knobs: {e}"));
    eprintln!("carrier: {cfg:?}, resume {}", a.resume);
    let mut sim = Sim {
        n,
        nodes: (0..n).map(|i| Carrier::new(key(i), cfg.clone())).collect(),
        net: Net { adj: vec![BTreeSet::new(); n], internet: (0..n).map(|i| a.gateways.contains(&i)).collect() },
        busy: vec![false; n],
        active: Vec::new(),
        last_summary: HashMap::new(),
        meta: HashMap::new(),
        delivered: HashMap::new(),
        hops: HashMap::new(),
        c: Counters::default(),
        a,
    };
    for i in 0..n {
        let on = sim.net.internet[i];
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
            // `created` on the carriers' clock (they keep no wall-clock offset)
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
    let stats = sim.nodes.iter().fold([0u64; 6], |mut acc, c| {
        let s = c.stats();
        acc[0] += s.expired;
        acc[1] += s.cleared_by_receipt;
        acc[2] += s.refused;
        acc[3] += s.accepted;
        acc[4] += s.evicted;
        acc[5] += s.resumed;
        acc
    });
    println!("Message stats for scenario {}", sim.a.label);
    println!("sim_time: {:.4}", end as f64 / 1000.0);
    println!("created: {created}");
    println!("started: {}", sim.c.started);
    println!("relayed: {}", sim.c.relayed);
    println!("aborted: {}", sim.c.aborted);
    println!("offers: {}", sim.c.offers);
    println!("refused: {}", sim.c.refused);
    println!("duplicates: {}", sim.c.duplicates);
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
    println!(
        "carrier: expired {} cleared_by_receipt {} refused {} accepted {} evicted {} resumed {}",
        stats[0], stats[1], stats[2], stats[3], stats[4], stats[5]
    );
    println!("refused_by: {:?}", sim.c.refused_why);
    eprintln!("({} devices, {} contact events, {:.1} s)", n, events.len(), wall.elapsed().as_secs_f64());
}
