//! Checks the shortcut `dtn-replay` takes for live routes (a breadth-first
//! search over the contacts up now) against Mycel's real router
//! (`mesh::core::Router`) running on the same contact trace.
//!
//! Every second it compares, for every ordered pair of devices: is there a
//! multi-hop path now (ground truth), and does the router's chain of next
//! hops lead there over links that are up now? It reports how often the
//! router agrees, and how often it holds a stale route.
//!
//! Usage: route-check <contacts.csv> <start s> <duration s>

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use mycel_crypto::{Sig, SignPk};
use mycel_net::mesh::core::{Announce, Config, Out, Router, SeqReq, Time};

const WALL: u64 = 1_700_000_000_000;
const STEP: Time = 5;
const HOP_DELAY: Time = 5;
const MAX_HOPS: usize = 8;

fn key(i: usize) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&(i as u32).to_be_bytes());
    k[31] = 0x7c;
    SignPk(k)
}

enum Msg {
    Ann(Announce),
    Req(SeqReq),
}

struct Net {
    nodes: Vec<Router>,
    index: HashMap<SignPk, usize>,
    up: HashSet<(usize, usize)>,
    adj: Vec<HashSet<usize>>,
    now: Time,
    queue: BinaryHeap<Reverse<(Time, u64, usize, usize)>>,
    msgs: HashMap<u64, Msg>,
    next: u64,
}

impl Net {
    fn effects(&mut self, i: usize) {
        let mut outs = Vec::new();
        self.nodes[i].drain(&mut outs);
        for o in outs {
            let (to, m) = match o {
                Out::Announce { to, ann } => (to, Msg::Ann(ann)),
                Out::SeqReq { to, req } => (to, Msg::Req(req)),
                _ => continue,
            };
            if let Some(&j) = self.index.get(&to) {
                let id = self.next;
                self.next += 1;
                self.msgs.insert(id, m);
                self.queue.push(Reverse((self.now + HOP_DELAY, id, i, j)));
            }
        }
    }

    fn link(&mut self, a: usize, b: usize, up: bool) {
        let now = self.now;
        if up {
            if !self.up.insert((a.min(b), a.max(b))) {
                return;
            }
            self.adj[a].insert(b);
            self.adj[b].insert(a);
            for (x, y) in [(a, b), (b, a)] {
                self.nodes[x].set_direct(key(y), true, now);
                self.nodes[x].hop_up(key(y), now);
            }
        } else {
            if !self.up.remove(&(a.min(b), a.max(b))) {
                return;
            }
            self.adj[a].remove(&b);
            self.adj[b].remove(&a);
            for (x, y) in [(a, b), (b, a)] {
                self.nodes[x].hop_down(key(y), now);
                self.nodes[x].set_direct(key(y), false, now);
            }
        }
        self.effects(a);
        self.effects(b);
    }

    fn step(&mut self) {
        self.now += STEP;
        while let Some(Reverse((at, id, from, to))) = self.queue.peek().copied() {
            if at > self.now {
                break;
            }
            self.queue.pop();
            let m = self.msgs.remove(&id).unwrap();
            if !self.up.contains(&(from.min(to), from.max(to))) {
                continue;
            }
            let now = self.now;
            match m {
                Msg::Ann(a) => self.nodes[to].on_announce(key(from), a, now, WALL + now, |_| true),
                Msg::Req(r) => self.nodes[to].on_seqreq(key(from), r, now),
            }
            self.effects(to);
        }
        if self.now.is_multiple_of(10) {
            for i in 0..self.nodes.len() {
                let now = self.now;
                let r = &mut self.nodes[i];
                if r.announce_due(now) {
                    let o = r.next_announce(WALL + now);
                    r.originate(
                        Announce {
                            hops: 0,
                            cost: 0,
                            origin: r.me(),
                            seq: o.seq,
                            flags: o.flags,
                            scope: o.scope,
                            uplink: o.uplink,
                            name: Arc::from(""),
                            sig: Sig([0; 64]),
                        },
                        now,
                    );
                }
                r.tick(now);
                self.effects(i);
            }
        }
    }

    fn hops_from(&self, i: usize) -> Vec<usize> {
        let mut d = vec![usize::MAX; self.nodes.len()];
        d[i] = 0;
        let mut q = VecDeque::from([i]);
        while let Some(x) = q.pop_front() {
            if d[x] >= MAX_HOPS {
                continue;
            }
            for &y in &self.adj[x] {
                if d[y] == usize::MAX {
                    d[y] = d[x] + 1;
                    q.push_back(y);
                }
            }
        }
        d
    }

    /// Following the router's next hops from `i` reaches `j` over links up now.
    fn router_reaches(&self, i: usize, j: usize) -> bool {
        let (mut at, dst) = (i, key(j));
        for _ in 0..2 * MAX_HOPS {
            let Some(n) = self.nodes[at].next_hop_local(&dst, self.now) else { return false };
            let n = self.index[&n];
            if !self.up.contains(&(at.min(n), at.max(n))) {
                return false;
            }
            if n == j {
                return true;
            }
            at = n;
        }
        false
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (path, start, dur) = (&a[0], a[1].parse::<f64>().unwrap(), a[2].parse::<f64>().unwrap());
    let text = std::fs::read_to_string(path).unwrap();
    let mut ev: Vec<(Time, bool, usize, usize)> = Vec::new();
    let mut n = 0;
    let (t0, t1) = ((start * 1000.0) as Time, ((start + dur) * 1000.0) as Time);
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        let (s, e) = ((f[0].parse::<f64>().unwrap() * 1000.0) as Time, (f[1].parse::<f64>().unwrap() * 1000.0) as Time);
        let (x, y): (usize, usize) = (f[2].parse().unwrap(), f[3].parse().unwrap());
        n = n.max(x + 1).max(y + 1);
        if e < t0 || s > t1 {
            continue;
        }
        ev.push((s.saturating_sub(t0), true, x, y));
        ev.push((e.saturating_sub(t0), false, x, y));
    }
    ev.sort_by_key(|&(t, up, x, y)| (t, up, x, y));
    let nodes: Vec<Router> = (0..n).map(|i| Router::new(key(i), Config { seed: i as u64 + 1, ..Config::default() })).collect();
    let mut net = Net {
        index: nodes.iter().enumerate().map(|(i, r)| (r.me(), i)).collect(),
        nodes,
        up: HashSet::new(),
        adj: vec![HashSet::new(); n],
        now: 0,
        queue: BinaryHeap::new(),
        msgs: HashMap::new(),
        next: 0,
    };
    let (mut k, end) = (0, t1 - t0);
    let (mut truth, mut agree, mut stale, mut direct) = (0u64, 0u64, 0u64, 0u64);
    let warmup = 10_000;
    while net.now < end {
        net.step();
        while k < ev.len() && ev[k].0 <= net.now {
            let (_, up, x, y) = ev[k];
            net.link(x, y, up);
            k += 1;
        }
        if net.now >= warmup && net.now.is_multiple_of(1_000) {
            for i in 0..n {
                let d = net.hops_from(i);
                for (j, &dj) in d.iter().enumerate() {
                    if j == i {
                        continue;
                    }
                    if dj == 1 {
                        direct += 1;
                    } else if dj != usize::MAX {
                        truth += 1;
                        if net.router_reaches(i, j) {
                            agree += 1;
                        }
                    } else if net.nodes[i].next_hop_local(&key(j), net.now).is_some() {
                        stale += 1;
                    }
                }
            }
        }
    }
    let samples = (end - warmup) / 1000;
    println!(
        "devices {n}, {samples} one-second samples: multi-hop paths present {truth}, router follows a working route on {agree} ({:.2} %); \
         router holds a route to an unreachable device {stale} times ({:.2} per sample); direct pairs {direct}",
        100.0 * agree as f64 / truth.max(1) as f64,
        stale as f64 / samples.max(1) as f64
    );
}
