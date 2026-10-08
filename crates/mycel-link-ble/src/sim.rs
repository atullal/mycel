//! Deterministic simulation: several connection state machines ([`Core`])
//! against a model of CoreBluetooth as observed between two real Macs, over
//! hours of simulated time with faults injected every minute or so.
//!
//! The radio model is deliberately pessimistic:
//! - scanning reports each peripheral **once per scan session** (duplicates
//!   filtered); only a rescan reports it again;
//! - a connect to a **stale** peripheral (the node's address rotated since)
//!   never completes, and a few connects to fresh ones hang too;
//! - both devices share **one radio link**: a connect while the link is up
//!   completes at once, and (with `harsh_cancel`) cancelling our side of a
//!   connected link tears the whole link down, the peer's channels included;
//! - faults: the link drops (supervision timeout), a channel is closed by the
//!   stack, a channel goes silent (detected by the keepalive), a node's
//!   address rotates.
//!
//! Measured: time to first link, every Lost → Found gap, duplicate channels
//! that outlive the grace period, and whether both ends route over the same
//! channel.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use mycel_crypto::SignPk;

use crate::core::{ChanId, Cmd, Core, DUPLICATE_GRACE, Input, Pid};
use crate::hub::SILENT_AFTER;
use crate::wire::GattInfo;

#[derive(Clone, Copy, Debug)]
struct Opts {
    nodes: usize,
    duration: Duration,
    /// Mean seconds between faults (uniform in [mean/2, mean*3/2]).
    fault_every: u64,
    /// Chance a connect to a fresh peripheral hangs anyway.
    hang: f64,
    harsh_cancel: bool,
    rotate: bool,
    seed: u64,
}

#[derive(Debug)]
enum Ev {
    In(usize, Input),
    Tick(usize),
    Discover { scanner: usize, target: usize, session: u64 },
    ConnectDone { n: usize, pid: Pid, attempt: u64 },
    InfoDone { n: usize, pid: Pid },
    OpenDone { n: usize, pid: Pid },
    Hello { pair: u64, to_dialer: bool },
    Fault,
    Sample,
}

#[derive(Debug, PartialEq, Eq)]
enum Ref {
    Pending(u64),
    Connected,
}

#[derive(Debug)]
struct Pair {
    /// (node, channel id) at the dialing and accepting ends.
    dialer: (usize, ChanId),
    acceptor: (usize, ChanId),
    via: (usize, Pid),
    alive: bool,
    opened: Duration,
}

struct Node {
    core: Core,
    key: SignPk,
    epoch: u32,
    session: u64,
    reported: HashSet<Pid>,
    routes: HashMap<SignPk, ChanId>,
    /// Per peer key: `Some(t)` = unlinked since t; absent = never linked.
    lost_since: HashMap<SignPk, Option<Duration>>,
}

#[derive(Default, Debug)]
struct Stats {
    first_link: Vec<Duration>,
    gaps: Vec<Duration>,
    worst_gap_at: Duration,
    founds: usize,
    losts: usize,
    faults: usize,
    dup_samples: usize,
    disagree_samples: usize,
    samples: usize,
}

struct Sim {
    o: Opts,
    t0: Instant,
    now: Duration,
    q: BinaryHeap<Reverse<(Duration, u64)>>,
    evs: HashMap<u64, Ev>,
    seq: u64,
    rng: u64,
    nodes: Vec<Node>,
    refs: HashMap<(usize, Pid), Ref>,
    pairs: HashMap<u64, Pair>,
    ends: HashMap<(usize, ChanId), u64>,
    next_chan: ChanId,
    next_pair: u64,
    attempts: u64,
    st: Stats,
}

fn pid_of(n: usize, epoch: u32) -> Pid {
    format!("N{n}-{epoch}")
}

fn target(pid: &str) -> usize {
    pid[1..].split('-').next().unwrap().parse().unwrap()
}

fn epoch(pid: &str) -> u32 {
    pid.split('-').nth(1).unwrap().parse().unwrap()
}

fn ms(x: u64) -> Duration {
    Duration::from_millis(x)
}

impl Sim {
    fn new(o: Opts) -> Sim {
        let t0 = Instant::now();
        let mut sim = Sim {
            o,
            t0,
            now: Duration::ZERO,
            q: BinaryHeap::new(),
            evs: HashMap::new(),
            seq: 0,
            rng: o.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            nodes: Vec::new(),
            refs: HashMap::new(),
            pairs: HashMap::new(),
            ends: HashMap::new(),
            next_chan: 1,
            next_pair: 1,
            attempts: 0,
            st: Stats::default(),
        };
        for _ in 0..o.nodes {
            let mut kb = [0u8; 32];
            for b in kb.iter_mut() {
                *b = sim.rand() as u8;
            }
            let key = SignPk(kb);
            let mut core = Core::new(key, t0);
            core.seed(sim.rand());
            sim.nodes.push(Node {
                core,
                key,
                epoch: 0,
                session: 0,
                reported: HashSet::new(),
                routes: HashMap::new(),
                lost_since: HashMap::new(),
            });
        }
        for n in 0..o.nodes {
            let off = ms(sim.uniform(0, 999));
            sim.at(off, Ev::Tick(n));
            for t in 0..o.nodes {
                if t != n {
                    let d = ms(sim.uniform(100, 1000));
                    sim.at(d, Ev::Discover { scanner: n, target: t, session: 0 });
                }
            }
        }
        let first = Duration::from_secs(sim.uniform(o.fault_every / 2, o.fault_every * 3 / 2));
        sim.at(first, Ev::Fault);
        sim.at(Duration::from_secs(1), Ev::Sample);
        sim
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn uniform(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.rand() % (hi - lo + 1)
    }

    fn chance(&mut self, p: f64) -> bool {
        (self.rand() % 1_000_000) as f64 / 1_000_000.0 < p
    }

    fn at(&mut self, after: Duration, ev: Ev) {
        self.seq += 1;
        self.q.push(Reverse((self.now + after, self.seq)));
        self.evs.insert(self.seq, ev);
    }

    fn run(&mut self) {
        while let Some(Reverse((t, id))) = self.q.pop() {
            if t > self.o.duration {
                break;
            }
            self.now = t;
            let ev = self.evs.remove(&id).expect("event");
            self.step(ev);
        }
    }

    fn link_up(&self, a: usize, b: usize) -> bool {
        self.refs
            .iter()
            .any(|((owner, pid), r)| *r == Ref::Connected && ((*owner == a && target(pid) == b) || (*owner == b && target(pid) == a)))
    }

    fn input(&mut self, n: usize, i: Input) {
        let now = self.t0 + self.now;
        let cmds = self.nodes[n].core.handle(now, i);
        for c in cmds {
            self.exec(n, c);
        }
    }

    /// The radio link between `a` and `b` is gone: every connection and
    /// channel between them ends.
    fn drop_link(&mut self, a: usize, b: usize) {
        let refs: Vec<(usize, Pid)> = self
            .refs
            .iter()
            .filter(|((owner, pid), r)| {
                **r == Ref::Connected && ((*owner == a && target(pid) == b) || (*owner == b && target(pid) == a))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for (owner, pid) in refs {
            self.refs.remove(&(owner, pid.clone()));
            let d = ms(self.uniform(0, 300));
            self.at(d, Ev::In(owner, Input::Disconnected(pid)));
        }
        let pairs: Vec<u64> = self
            .pairs
            .iter()
            .filter(|(_, p)| p.alive && ({ p.dialer.0 == a && p.acceptor.0 == b } || { p.dialer.0 == b && p.acceptor.0 == a }))
            .map(|(id, _)| *id)
            .collect();
        for id in pairs {
            self.kill_pair(id, true, true);
        }
    }

    /// End a channel; tell the ends that didn't close it themselves.
    fn kill_pair(&mut self, id: u64, tell_dialer: bool, tell_acceptor: bool) {
        let Some(p) = self.pairs.get_mut(&id) else { return };
        if !p.alive {
            return;
        }
        p.alive = false;
        let (d, a) = (p.dialer, p.acceptor);
        for (end, tell) in [(d, tell_dialer), (a, tell_acceptor)] {
            if tell {
                let delay = ms(self.uniform(10, 300));
                self.at(delay, Ev::In(end.0, Input::ChannelClosed(end.1)));
            }
        }
    }

    fn exec(&mut self, n: usize, cmd: Cmd) {
        match cmd {
            Cmd::Connect(pid) => {
                let o = target(&pid);
                self.attempts += 1;
                let att = self.attempts;
                self.refs.insert((n, pid.clone()), Ref::Pending(att));
                if epoch(&pid) != self.nodes[o].epoch {
                    return; // stale peripheral: never completes
                }
                let delay = if self.link_up(n, o) {
                    ms(50)
                } else if self.chance(self.o.hang) {
                    return;
                } else {
                    ms(self.uniform(300, 2000))
                };
                self.at(delay, Ev::ConnectDone { n, pid, attempt: att });
            }
            Cmd::Disconnect(pid) => {
                if self.refs.remove(&(n, pid.clone())) == Some(Ref::Connected) {
                    let o = target(&pid);
                    if self.o.harsh_cancel || !self.link_up(n, o) {
                        self.drop_link(n, o);
                    } else {
                        let ours: Vec<u64> =
                            self.pairs.iter().filter(|(_, p)| p.alive && p.via == (n, pid.clone())).map(|(i, _)| *i).collect();
                        for id in ours {
                            self.kill_pair(id, true, true);
                        }
                    }
                    self.at(ms(50), Ev::In(n, Input::Disconnected(pid)));
                }
            }
            Cmd::Forget(pid) => {
                if matches!(self.refs.get(&(n, pid.clone())), Some(Ref::Pending(_))) {
                    self.refs.remove(&(n, pid));
                }
            }
            Cmd::ReadInfo(pid) => {
                if self.refs.get(&(n, pid.clone())) == Some(&Ref::Connected) {
                    let d = ms(self.uniform(200, 800));
                    self.at(d, Ev::InfoDone { n, pid });
                }
            }
            Cmd::OpenChannel(pid, _) => {
                if self.refs.get(&(n, pid.clone())) == Some(&Ref::Connected) {
                    let d = ms(self.uniform(200, 600));
                    self.at(d, Ev::OpenDone { n, pid });
                } else {
                    self.at(ms(50), Ev::In(n, Input::OpenFailed(pid)));
                }
            }
            Cmd::CloseChannel(c) => {
                if let Some(&id) = self.ends.get(&(n, c)) {
                    let we_dialed = self.pairs[&id].dialer == (n, c);
                    self.kill_pair(id, !we_dialed, we_dialed);
                }
            }
            Cmd::Rescan => {
                let node = &mut self.nodes[n];
                node.session += 1;
                node.reported.clear();
                let session = node.session;
                for t in 0..self.o.nodes {
                    if t != n {
                        let d = ms(self.uniform(100, 1000));
                        self.at(d, Ev::Discover { scanner: n, target: t, session });
                    }
                }
            }
            Cmd::Route { key, chan } => {
                self.nodes[n].routes.insert(key, chan);
            }
            Cmd::Unroute { key } => {
                self.nodes[n].routes.remove(&key);
            }
            Cmd::Found { key, .. } => {
                self.st.founds += 1;
                let now = self.now;
                match self.nodes[n].lost_since.insert(key, None) {
                    None => self.st.first_link.push(now),
                    Some(Some(t)) => {
                        let gap = now - t;
                        if self.st.gaps.iter().all(|g| *g < gap) {
                            self.st.worst_gap_at = t;
                        }
                        self.st.gaps.push(gap);
                    }
                    Some(None) => panic!("Found twice without Lost"),
                }
            }
            Cmd::Lost { key } => {
                self.st.losts += 1;
                let now = self.now;
                assert_eq!(self.nodes[n].lost_since.insert(key, Some(now)), Some(None), "Lost without Found");
            }
        }
    }

    fn step(&mut self, ev: Ev) {
        match ev {
            Ev::In(n, i) => self.input(n, i),
            Ev::Tick(n) => {
                self.input(n, Input::Tick);
                self.at(Duration::from_secs(1), Ev::Tick(n));
            }
            Ev::Discover { scanner, target, session } => {
                let pid = pid_of(target, self.nodes[target].epoch);
                let node = &mut self.nodes[scanner];
                if node.session == session && node.reported.insert(pid.clone()) {
                    self.input(scanner, Input::Discovered(pid));
                }
            }
            Ev::ConnectDone { n, pid, attempt } => {
                if self.refs.get(&(n, pid.clone())) == Some(&Ref::Pending(attempt)) {
                    self.refs.insert((n, pid.clone()), Ref::Connected);
                    self.input(n, Input::Connected(pid));
                }
            }
            Ev::InfoDone { n, pid } => {
                if self.refs.get(&(n, pid.clone())) != Some(&Ref::Connected) {
                    return;
                }
                if self.chance(0.03) {
                    return self.input(n, Input::InfoFailed(pid));
                }
                let o = target(&pid);
                let info = GattInfo { psm: 0x80 + o as u16, key: self.nodes[o].key, name: format!("n{o}") };
                self.input(n, Input::Info(pid, info));
            }
            Ev::OpenDone { n, pid } => {
                if self.refs.get(&(n, pid.clone())) != Some(&Ref::Connected) || self.chance(0.03) {
                    return self.input(n, Input::OpenFailed(pid));
                }
                let o = target(&pid);
                let (cd, ca) = (self.next_chan, self.next_chan + 1);
                self.next_chan += 2;
                let id = self.next_pair;
                self.next_pair += 1;
                self.pairs.insert(
                    id,
                    Pair { dialer: (n, cd), acceptor: (o, ca), via: (n, pid.clone()), alive: true, opened: self.now },
                );
                self.ends.insert((n, cd), id);
                self.ends.insert((o, ca), id);
                self.input(n, Input::ChannelOpened { chan: cd, pid: Some(pid) });
                self.input(o, Input::ChannelOpened { chan: ca, pid: None });
                for to_dialer in [true, false] {
                    let d = ms(self.uniform(30, 150));
                    self.at(d, Ev::Hello { pair: id, to_dialer });
                }
            }
            Ev::Hello { pair, to_dialer } => {
                let Some(p) = self.pairs.get(&pair) else { return };
                if !p.alive {
                    return;
                }
                let (to, from) = if to_dialer { (p.dialer, p.acceptor.0) } else { (p.acceptor, p.dialer.0) };
                let key = self.nodes[from].key;
                self.input(to.0, Input::Hello { chan: to.1, key, name: format!("n{from}") });
            }
            Ev::Fault => {
                self.fault();
                let next = Duration::from_secs(self.uniform(self.o.fault_every / 2, self.o.fault_every * 3 / 2));
                self.at(next, Ev::Fault);
            }
            Ev::Sample => {
                self.sample();
                self.at(Duration::from_secs(1), Ev::Sample);
            }
        }
    }

    fn fault(&mut self) {
        let a = self.uniform(0, self.o.nodes as u64 - 1) as usize;
        let mut b = self.uniform(0, self.o.nodes as u64 - 2) as usize;
        if b >= a {
            b += 1;
        }
        let alive: Vec<u64> = {
            let mut v: Vec<u64> = self
                .pairs
                .iter()
                .filter(|(_, p)| p.alive && ((p.dialer.0, p.acceptor.0) == (a, b) || (p.dialer.0, p.acceptor.0) == (b, a)))
                .map(|(i, _)| *i)
                .collect();
            v.sort();
            v
        };
        self.st.faults += 1;
        match self.uniform(0, 99) {
            // the radio link drops (supervision timeout)
            0..35 => self.drop_link(a, b),
            // the stack closes a channel under us (both ends see it end)
            35..60 => {
                if let Some(&id) = alive.first() {
                    self.kill_pair(id, true, true);
                }
            }
            // a channel goes silent; each end's keepalive notices
            60..80 => {
                if let Some(&id) = alive.first() {
                    let p = self.pairs.get_mut(&id).expect("pair");
                    p.alive = false;
                    let ends = [p.dialer, p.acceptor];
                    for e in ends {
                        let d = SILENT_AFTER + ms(self.uniform(0, 1000));
                        self.at(d, Ev::In(e.0, Input::ChannelClosed(e.1)));
                    }
                }
            }
            // a node's address rotates: new identifier, old one goes stale
            _ if self.o.rotate => {
                self.nodes[a].epoch += 1;
                for s in 0..self.o.nodes {
                    if s != a {
                        let session = self.nodes[s].session;
                        let d = ms(self.uniform(100, 1000));
                        self.at(d, Ev::Discover { scanner: s, target: a, session });
                    }
                }
            }
            _ => self.drop_link(a, b),
        }
    }

    /// Every second: at most one long-lived channel per pair; both ends of
    /// each linked pair route over the same channel once settled.
    fn sample(&mut self) {
        self.st.samples += 1;
        for a in 0..self.o.nodes {
            for b in (a + 1)..self.o.nodes {
                let old = self
                    .pairs
                    .values()
                    .filter(|p| {
                        p.alive
                            && ((p.dialer.0, p.acceptor.0) == (a, b) || (p.dialer.0, p.acceptor.0) == (b, a))
                            && self.now - p.opened > DUPLICATE_GRACE + Duration::from_secs(3)
                    })
                    .count();
                if old > 1 {
                    self.st.dup_samples += 1;
                }
                let (ka, kb) = (self.nodes[a].key, self.nodes[b].key);
                if let (Some(&ca), Some(&cb)) = (self.nodes[a].routes.get(&kb), self.nodes[b].routes.get(&ka)) {
                    let (pa, pb) = (self.ends.get(&(a, ca)), self.ends.get(&(b, cb)));
                    let settled = pa.is_some_and(|id| self.now - self.pairs[id].opened > Duration::from_secs(3));
                    if settled && pa != pb {
                        self.st.disagree_samples += 1;
                    }
                }
            }
        }
    }

    fn report(&self) -> String {
        let mut g = self.st.gaps.clone();
        g.sort();
        let pct = |p: f64| g.get(((g.len() as f64 * p) as usize).min(g.len().saturating_sub(1))).copied().unwrap_or_default();
        format!(
            "{:?}: faults {} lost {} found {} | first link max {:.1?} | gaps n={} p50 {:.1?} p95 {:.1?} p99 {:.1?} max {:.1?} (lost at {:.0?}) | dup samples {} disagree {} / {}",
            self.o,
            self.st.faults,
            self.st.losts,
            self.st.founds,
            self.st.first_link.iter().max().copied().unwrap_or_default(),
            g.len(),
            pct(0.5),
            pct(0.95),
            pct(0.99),
            g.last().copied().unwrap_or_default(),
            self.st.worst_gap_at,
            self.st.dup_samples,
            self.st.disagree_samples,
            self.st.samples,
        )
    }

    /// Every pair of nodes is linked right now (both directions).
    fn all_linked(&self) -> bool {
        self.nodes.iter().all(|n| n.lost_since.len() == self.o.nodes - 1 && n.lost_since.values().all(|v| v.is_none()))
    }
}

fn base(seed: u64) -> Opts {
    Opts {
        nodes: 2,
        duration: Duration::from_secs(6 * 3600),
        fault_every: 60,
        hang: 0.02,
        harsh_cancel: true,
        rotate: true,
        seed,
    }
}

fn check(sim: &Sim, max_gap: Duration) {
    let r = sim.report();
    eprintln!("{r}");
    let st = &sim.st;
    assert_eq!(st.first_link.len(), sim.o.nodes * (sim.o.nodes - 1), "everyone linked: {r}");
    assert!(st.first_link.iter().all(|t| *t <= Duration::from_secs(10)), "first link within 10 s: {r}");
    let mut g = st.gaps.clone();
    g.sort();
    let p99 = g[(g.len() * 99 / 100).min(g.len() - 1)];
    assert!(p99 <= Duration::from_secs(10), "99% of reconnects within 10 s: {r}");
    assert!(g.last().copied().unwrap_or_default() <= max_gap, "no long silent gap: {r}");
    // a fault takes down at most one link per side; no extra flapping
    assert!(st.losts <= st.faults * 2 + 2, "no flapping: {r}");
    assert_eq!(st.dup_samples, 0, "duplicate channels never outlive the grace period: {r}");
    assert!(st.disagree_samples * 200 <= st.samples, "both ends use the same channel: {r}");
    assert!(sim.all_linked() || sim.now > sim.o.duration, "linked at the end: {r}");
}

#[test]
fn two_macs_stay_linked_for_hours_through_faults() {
    for seed in 1..=4 {
        let mut sim = Sim::new(base(seed));
        sim.run();
        check(&sim, Duration::from_secs(20));
        assert!(sim.st.gaps.len() > 100, "faults really hit the link: {}", sim.report());
    }
}

#[test]
fn gentle_cancel_and_no_hangs_reconnect_within_ten_seconds() {
    for seed in 10..=12 {
        let mut sim = Sim::new(Opts { harsh_cancel: false, hang: 0.0, ..base(seed) });
        sim.run();
        check(&sim, Duration::from_secs(12));
    }
}

#[test]
fn three_devices_all_pairs_stay_linked() {
    for seed in 20..=21 {
        let mut sim = Sim::new(Opts { nodes: 3, duration: Duration::from_secs(2 * 3600), fault_every: 40, ..base(seed) });
        sim.run();
        check(&sim, Duration::from_secs(20));
    }
}

#[test]
fn stale_handles_everywhere_still_link_quickly() {
    // Every connect to a fresh peripheral hangs half the time: links still
    // come up, just slower; nothing gets stuck.
    let mut sim = Sim::new(Opts { hang: 0.5, duration: Duration::from_secs(3600), ..base(30) });
    sim.run();
    eprintln!("{}", sim.report());
    let mut g = sim.st.gaps.clone();
    g.sort();
    assert!(g.len() > 20);
    assert!(g[g.len() / 2] <= Duration::from_secs(10), "{}", sim.report());
    assert!(*g.last().unwrap() <= Duration::from_secs(60), "{}", sim.report());
    assert_eq!(sim.st.dup_samples, 0);
}
