//! The router on a virtual clock: a tiny deterministic network simulator
//! (per-hop delay, an "internet" any two internet devices can dial, a
//! record directory), functional tests, and convergence measurements.
//! Run with `--nocapture` to see the numbers.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use super::*;

pub(crate) fn key(i: u32) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k[31] = 0xa5;
    SignPk(k)
}

const WALL: u64 = 1_700_000_000_000;

#[derive(Clone, Debug)]
enum Msg {
    Ann(Announce),
    Req(SeqReq),
    Frame(Frame),
}

/// A message in flight: (due, order, from, to, message id).
type Due = (Time, u64, usize, usize, u64);

/// Routers joined by links with a fixed one-way delay. Signatures are
/// always valid (they're tested in `wire.rs`).
pub(crate) struct Net {
    pub nodes: Vec<Router>,
    index: BTreeMap<SignPk, usize>,
    links: BTreeSet<(usize, usize)>,
    pub now: Time,
    delay: Time,
    queue: BinaryHeap<Reverse<Due>>,
    msgs: BTreeMap<u64, Msg>,
    next_msg: u64,
    pub delivered: Vec<(usize, SignPk, Bytes)>,
    pub records: Vec<(usize, Vec<(SignPk, u32)>)>,
    /// Frames seen per node, to catch a frame visiting a node twice.
    seen: BTreeSet<(usize, SignPk, u32)>,
    pub frame_loops: u64,
    pub sent: Vec<u64>,
}

impl Net {
    pub fn new(n: usize, cfg: impl Fn(usize) -> Config) -> Net {
        let nodes: Vec<Router> = (0..n).map(|i| Router::new(key(i as u32 + 1), cfg(i))).collect();
        let index = nodes.iter().enumerate().map(|(i, r)| (r.me(), i)).collect();
        Net {
            nodes,
            index,
            links: BTreeSet::new(),
            now: 0,
            delay: 5,
            queue: BinaryHeap::new(),
            msgs: BTreeMap::new(),
            next_msg: 0,
            delivered: vec![],
            records: vec![],
            seen: BTreeSet::new(),
            frame_loops: 0,
            sent: vec![0; n],
        }
    }

    pub fn fast(n: usize) -> Net {
        Net::new(n, |i| Config { announce_every: 500, seed: i as u64 + 1, ..Config::default() })
    }

    pub fn k(&self, i: usize) -> SignPk {
        self.nodes[i].me()
    }

    pub fn link(&mut self, a: usize, b: usize) {
        self.links.insert((a.min(b), a.max(b)));
        let (ka, kb, now) = (self.k(a), self.k(b), self.now);
        self.nodes[a].set_direct(kb, true, now);
        self.nodes[b].set_direct(ka, true, now);
        self.nodes[a].hop_up(kb, now);
        self.nodes[b].hop_up(ka, now);
    }

    pub fn cut(&mut self, a: usize, b: usize) {
        self.links.remove(&(a.min(b), a.max(b)));
        let (ka, kb, now) = (self.k(a), self.k(b), self.now);
        self.nodes[a].hop_down(kb, now);
        self.nodes[b].hop_down(ka, now);
        self.nodes[a].set_direct(kb, false, now);
        self.nodes[b].set_direct(ka, false, now);
    }

    fn post(&mut self, from: usize, to: usize, m: Msg) {
        let id = self.next_msg;
        self.next_msg += 1;
        self.msgs.insert(id, m);
        self.queue.push(Reverse((self.now + self.delay, id, from, to, id)));
    }

    fn connected(&self, a: usize, b: usize) -> bool {
        self.links.contains(&(a.min(b), a.max(b)))
            || (self.nodes[a].internet() && self.nodes[b].internet())
    }

    /// Carry out node `i`'s effects.
    fn effects(&mut self, i: usize) {
        let mut outs = Vec::new();
        self.nodes[i].drain(&mut outs);
        let (me, now) = (self.k(i), self.now);
        for o in outs {
            match o {
                Out::Announce { to, ann } => {
                    self.sent[i] += 1;
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Ann(ann));
                    }
                }
                Out::SeqReq { to, req } => {
                    self.sent[i] += 1;
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Req(req));
                    }
                }
                Out::Frame { to, frame, .. } => {
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Frame(frame));
                    }
                }
                Out::Deliver { src, payload, .. } => self.delivered.push((i, src, payload)),
                Out::Control { .. } => {}
                Out::Dial(peer) => match self.index.get(&peer).copied() {
                    Some(j) if self.nodes[j].internet() && self.nodes[i].internet() => {
                        self.nodes[i].hop_up(peer, now);
                        self.nodes[j].hop_up(me, now);
                        self.effects(j);
                    }
                    _ => self.nodes[i].dial_failed(peer, now),
                },
                Out::Hangup(peer) => {
                    if let Some(&j) = self.index.get(&peer) {
                        self.nodes[i].hop_down(peer, now);
                        self.nodes[j].hop_down(me, now);
                    }
                }
                Out::Resolve(peer) => {
                    let gws = self
                        .records
                        .iter()
                        .rev()
                        .find(|(n, _)| self.nodes[*n].me() == peer)
                        .map(|(_, g)| g.clone());
                    self.nodes[i].on_resolved(peer, gws, now);
                    self.effects(i);
                }
                Out::PublishReach { gateways } => self.records.push((i, gateways)),
                Out::RouteUp { .. } | Out::RouteDown { .. } => {}
            }
        }
    }

    /// Deliver every message due by `now`.
    fn pump(&mut self) {
        while let Some(Reverse((at, _, from, to, id))) = self.queue.peek().copied() {
            if at > self.now {
                break;
            }
            self.queue.pop();
            let m = self.msgs.remove(&id).expect("message");
            if !self.connected(from, to) {
                continue; // the link went away in flight
            }
            let (f, now) = (self.k(from), self.now);
            match m {
                Msg::Ann(a) => self.nodes[to].on_announce(f, a, now, WALL + now, |_| true),
                Msg::Req(r) => self.nodes[to].on_seqreq(f, r, now),
                Msg::Frame(fr) => {
                    if !self.seen.insert((to, fr.src, fr.id)) {
                        self.frame_loops += 1;
                    }
                    self.nodes[to].on_frame(f, fr, now)
                }
            }
            self.effects(to);
        }
    }

    pub fn step(&mut self) {
        self.now += 5;
        self.pump();
        if self.now.is_multiple_of(10) {
            for i in 0..self.nodes.len() {
                let now = self.now;
                let r = &mut self.nodes[i];
                if r.announce_due(now) {
                    let o = r.next_announce(WALL + now);
                    let a = Announce {
                        hops: 0,
                        cost: 0,
                        origin: r.me(),
                        seq: o.seq,
                        flags: o.flags,
                        scope: o.scope,
                        uplink: o.uplink,
                        name: Arc::from(""),
                        sig: Sig([0; 64]),
                    };
                    r.originate(a, now);
                }
                r.tick(now);
                self.effects(i);
            }
        }
    }

    pub fn run(&mut self, ms: Time) {
        let end = self.now + ms;
        while self.now < end {
            self.step();
        }
    }

    /// Run until `f` holds (checked every step); the time it took.
    pub fn until(&mut self, limit: Time, mut f: impl FnMut(&Net) -> bool) -> Option<Time> {
        let start = self.now;
        while self.now < start + limit {
            if f(self) {
                return Some(self.now - start);
            }
            self.step();
        }
        f(self).then(|| self.now - start)
    }

    pub fn send(&mut self, from: usize, to: usize, via: usize, data: &'static [u8]) {
        let (dst, wp, now) = (self.k(to), self.k(via), self.now);
        self.nodes[from].send(dst, wp, Bytes::from_static(data), false, now);
        self.effects(from);
        self.run(200);
    }

    /// Follow best next hops from every node toward `dst`: any cycle is a
    /// routing loop.
    pub fn loops_toward(&self, dst: usize) -> usize {
        let d = self.k(dst);
        let mut loops = 0;
        for start in 0..self.nodes.len() {
            let mut at = start;
            let mut visited = BTreeSet::new();
            while at != dst {
                if !visited.insert(at) {
                    loops += 1;
                    break;
                }
                match self.nodes[at].next_hop_local(&d, self.now) {
                    Some(n) => at = self.index[&n],
                    None => break,
                }
            }
        }
        loops
    }

    pub fn has_route(&self, from: usize, to: usize) -> bool {
        self.nodes[from].next_hop_local(&self.k(to), self.now).is_some()
    }
}

/// A random geometric graph: `n` devices in a square, linked within `range`.
fn geometric(n: usize, side: f64, range: f64, seed: u64) -> Vec<(usize, usize)> {
    let mut x = seed | 1;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % 1_000_000) as f64 / 1_000_000.0
    };
    let pos: Vec<(f64, f64)> = (0..n).map(|_| (rnd() * side, rnd() * side)).collect();
    let mut edges = vec![];
    for a in 0..n {
        for b in a + 1..n {
            let (dx, dy) = (pos[a].0 - pos[b].0, pos[a].1 - pos[b].1);
            if (dx * dx + dy * dy).sqrt() <= range {
                edges.push((a, b));
            }
        }
    }
    // keep it connected: chain the components in index order
    let mut comp: Vec<usize> = (0..n).collect();
    fn find(c: &mut Vec<usize>, i: usize) -> usize {
        if c[i] != i {
            let r = find(c, c[i]);
            c[i] = r;
        }
        c[i]
    }
    for (a, b) in &edges {
        let (ra, rb) = (find(&mut comp, *a), find(&mut comp, *b));
        comp[ra] = rb;
    }
    for i in 1..n {
        let (ra, rb) = (find(&mut comp, i - 1), find(&mut comp, i));
        if ra != rb {
            edges.push((i - 1, i));
            comp[ra] = rb;
        }
    }
    edges
}

// ───────────────────────────── behaviour ─────────────────────────────

#[test]
fn a_line_routes_hop_by_hop() {
    let mut net = Net::fast(4);
    for i in 0..3 {
        net.link(i, i + 1);
    }
    net.run(3_000);
    assert_eq!(net.nodes[0].next_hop_local(&net.k(3), net.now), Some(net.k(1)));
    assert_eq!(net.nodes[0].route_hops(&net.k(3), &net.k(1)), Some(3));
    net.send(0, 3, 1, b"hello");
    assert_eq!(net.delivered, vec![(3, net.k(0), Bytes::from_static(b"hello"))]);
    assert_eq!(net.nodes[1].stats().frames_relayed, 1);
    assert_eq!(net.nodes[2].stats().frames_relayed, 1);
}

#[test]
fn forged_stale_and_flooding_announcements_are_rejected() {
    let ann = |origin, seq| Announce {
        hops: 0,
        cost: 0,
        origin,
        seq,
        flags: 0,
        scope: 8,
        uplink: 0,
        name: Arc::from(""),
        sig: Sig([0; 64]),
    };
    let mut r = Router::new(key(1), Config::default());
    let n = key(2);
    r.set_direct(n, true, 0);
    r.hop_up(n, 0);
    let victim = key(9);
    r.on_announce(n, ann(victim, WALL), 0, WALL, |_| false);
    assert_eq!(r.stats().announcements_forged, 1);
    assert!(r.origins.is_empty());
    r.on_announce(n, ann(victim, WALL - 3_600_000), 0, WALL, |_| true);
    assert_eq!(r.stats().announcements_stale, 1);
    r.on_announce(n, ann(victim, WALL), 0, WALL, |_| true);
    assert!(r.origins.contains_key(&victim));
    for i in 0..1000 {
        r.on_announce(n, ann(victim, WALL + i), 0, WALL, |_| true);
    }
    assert!(r.stats().announcements_limited >= 1000 - OGM_RATE as u64 * 4, "{:?}", r.stats());
    // and nothing at all is learnt over an internet hop
    let far = key(3);
    r.hop_up(far, 0);
    r.on_announce(far, ann(key(10), WALL), 10_000, WALL, |_| true);
    assert!(!r.origins.contains_key(&key(10)));
}

#[test]
fn fragments_reassemble_at_the_destination() {
    let mut r = Router::new(key(1), Config::default());
    let src = key(2);
    let packet: Vec<u8> = (0..1200u32).map(|i| i as u8).collect();
    for (off, chunk) in [(600usize, &packet[600..]), (0, &packet[..600])] {
        let f = Frame {
            ttl: 8,
            reached: true,
            control: false,
            dst: key(1),
            src,
            waypoint: src,
            id: 7,
            offset: off as u16,
            total: 1200,
            payload: Bytes::copy_from_slice(chunk),
        };
        r.route(f, Some(src), 0);
    }
    let mut outs = Vec::new();
    r.drain(&mut outs);
    assert!(matches!(&outs[..], [Out::Deliver { payload, .. }] if payload[..] == packet[..]));
}

/// A Bluetooth-only device with a gateway two hops away publishes a record
/// naming it; an internet device reads the record and reaches it through
/// that gateway; replies take the default route back out.
#[test]
fn records_gateways_and_the_default_route() {
    // 0 —(ble)— 1 —(ble)— 2 [internet]          3 [internet]
    let mut net = Net::fast(4);
    net.link(0, 1);
    net.link(1, 2);
    net.nodes[2].set_internet(true);
    net.nodes[3].set_internet(true);
    net.run(3_000);
    let (m, g, r) = (net.k(0), net.k(2), net.k(3));
    assert!(net.nodes[0].is_gateway(&g));
    let (who, gws) = net.records.last().cloned().expect("a record");
    assert_eq!((who, gws.iter().map(|(k, _)| *k).collect::<Vec<_>>()), (0, vec![g]));
    assert!(gws[0].1 > 0, "with its mesh cost");
    assert_eq!(net.nodes[0].my_gateways(), &[g]);
    net.send(3, 0, 2, b"to M");
    assert_eq!(net.delivered.last().map(|(i, s, _)| (*i, *s)), Some((0, r)));
    assert_eq!(net.nodes[2].stats().gateway_in, 1);
    net.send(0, 3, 2, b"to R");
    assert_eq!(net.delivered.last().map(|(i, s, _)| (*i, *s)), Some((3, m)));
    assert_eq!(net.nodes[2].stats().gateway_out, 1);
    // to someone M has no route to, through a non-gateway waypoint: the
    // default route still finds the gateway, which dials out
    net.send(0, 3, 1, b"default route");
    assert_eq!(
        net.delivered.last().map(|(i, _, p)| (*i, p.clone())),
        Some((3, Bytes::from_static(b"default route")))
    );
}

/// Two meshes, each with its gateway, each with a Bluetooth-only device
/// three hops behind it: the US device reaches the EU device live,
/// end to end, through both gateways and the internet.
#[test]
fn us_to_eu_through_two_gateways() {
    // US: 0 — 1 — 2 — 3 [gw]      EU: 4 [gw] — 5 — 6 — 7
    let mut net = Net::fast(8);
    for (a, b) in [(0, 1), (1, 2), (2, 3), (4, 5), (5, 6), (6, 7)] {
        net.link(a, b);
    }
    net.nodes[3].set_internet(true);
    net.nodes[4].set_internet(true);
    let t = net.until(10_000, |n| n.records.iter().any(|(i, _)| *i == 0) && n.records.iter().any(|(i, _)| *i == 7));
    eprintln!("both records published after {t:?} ms");
    assert!(t.is_some());
    // the US device's packet: waypoint = its gateway
    let start = net.now;
    net.send(0, 7, 3, b"hello from the US");
    let got = net.delivered.iter().find(|(i, _, p)| *i == 7 && &p[..] == b"hello from the US");
    assert!(got.is_some(), "{:?}", net.nodes[3].stats());
    // the reply, via the US gateway as waypoint, out through the EU gateway
    net.send(7, 0, 3, b"hello from the EU");
    assert!(net.delivered.iter().any(|(i, _, p)| *i == 0 && &p[..] == b"hello from the EU"));
    eprintln!("round trip done within {} ms of virtual time", net.now - start);
    assert_eq!(net.nodes[3].stats().gateway_out, 1);
    assert_eq!(net.nodes[4].stats().gateway_in, 1);
    assert_eq!(net.nodes[4].stats().gateway_out, 1);
    assert_eq!(net.nodes[3].stats().gateway_in, 1);
}

/// The gateway with the lowest *total* cost wins: one 4 hops away with a
/// fast uplink beats the neighbour on a slow one.
#[test]
fn gateway_choice_by_total_cost() {
    // 0 — 1 [gw, slow uplink]       0 — 2 — 3 — 4 — 5 [gw, fast uplink]
    let mut net = Net::fast(6);
    for (a, b) in [(0, 1), (0, 2), (2, 3), (3, 4), (4, 5)] {
        net.link(a, b);
    }
    for (g, up) in [(1, 20_000), (5, 50)] {
        net.nodes[g].set_internet(true);
        net.nodes[g].set_uplink(up);
    }
    net.run(4_000);
    let gws = net.nodes[0].gateways_with_cost(net.now);
    assert_eq!(gws.first().map(|(g, _)| *g), Some(net.k(5)), "{gws:?}");
    // and the default route follows it
    let r = key(9_999);
    let (k2, now) = (net.k(2), net.now);
    net.nodes[0].send(r, k2, Bytes::from_static(b"x"), false, now);
    let mut outs = vec![];
    net.nodes[0].drain(&mut outs);
    assert!(outs.iter().any(|o| matches!(o, Out::Frame { to, .. } if *to == k2)));
    // a slow gateway that gets faster wins it back
    net.nodes[1].set_uplink(10);
    net.run(4_000);
    assert_eq!(net.nodes[0].gateways(net.now).first(), Some(&net.k(1)));
}

/// Gateways don't relay internet → internet.
#[test]
fn no_open_proxy() {
    let mut net = Net::fast(3);
    for i in 0..3 {
        net.nodes[i].set_internet(true);
    }
    net.run(1_000);
    net.send(0, 2, 1, b"proxy?");
    assert!(net.delivered.is_empty());
    assert!(net.nodes[1].stats().dropped_no_route >= 1);
}

#[test]
fn frames_wait_for_a_lookup_and_a_dial_bounded() {
    let mut r = Router::new(key(1), Config::default());
    r.set_internet(true);
    for i in 0..40u8 {
        r.send(key(50), key(50), Bytes::from(vec![i]), false, 0);
    }
    let mut outs = Vec::new();
    r.drain(&mut outs);
    assert_eq!(outs.iter().filter(|o| matches!(o, Out::Resolve(_))).count(), 1, "one lookup");
    assert_eq!(r.stats().dropped_pending, 8, "32 wait");
    r.on_resolved(key(50), None, 10);
    r.drain(&mut outs);
    assert!(outs.iter().any(|o| matches!(o, Out::Dial(k) if *k == key(50))));
    r.hop_up(key(50), 20);
    outs.clear();
    r.drain(&mut outs);
    assert_eq!(outs.iter().filter(|o| matches!(o, Out::Frame { .. })).count(), 32);
    r.tick(20 + INTERNET_IDLE + 1);
    outs.clear();
    r.drain(&mut outs);
    assert!(outs.iter().any(|o| matches!(o, Out::Hangup(k) if *k == key(50))));
}

/// A failed dial isn't retried on every packet: it backs off (doubling),
/// and meanwhile `toward` says the internet doesn't reach the target, so a
/// carrier holding a bundle for it can look for a mesh carrier instead.
#[test]
fn failed_dials_back_off() {
    let mut r = Router::new(key(1), Config::default());
    r.set_internet(true);
    let dials = |r: &mut Router| {
        let mut outs = Vec::new();
        r.drain(&mut outs);
        outs.iter().filter(|o| matches!(o, Out::Dial(k) if *k == key(50))).count()
    };
    r.send(key(50), key(50), Bytes::from_static(b"x"), false, 0);
    r.on_resolved(key(50), None, 10); // no record: dial it directly
    assert_eq!(dials(&mut r), 1);
    r.dial_failed(key(50), 100);
    for t in [200, 500, 1_000, 2_000] {
        r.send(key(50), key(50), Bytes::from_static(b"x"), false, t);
        assert_eq!(r.toward(&key(50), t), Toward::Unreachable);
    }
    assert_eq!(dials(&mut r), 0, "backing off for 2 s");
    assert!(r.stats().dropped_backoff >= 4);
    r.send(key(50), key(50), Bytes::from_static(b"x"), false, 2_200);
    assert_eq!(dials(&mut r), 1, "then once more");
    r.dial_failed(key(50), 2_300);
    r.send(key(50), key(50), Bytes::from_static(b"x"), false, 5_000);
    assert_eq!(dials(&mut r), 0, "now 4 s");
    r.send(key(50), key(50), Bytes::from_static(b"x"), false, 6_400);
    assert_eq!(dials(&mut r), 1);
    // a connection that works clears it
    r.hop_up(key(50), 6_500);
    r.hop_down(key(50), 7_000);
    r.send(key(50), key(50), Bytes::from_static(b"x"), false, 7_100);
    assert_eq!(dials(&mut r), 1);
}

#[test]
fn relay_budgets_hold() {
    let cfg = Config { relay_rate_per_neighbour: 1000, relay_rate_total: 1500, ..Config::default() };
    let mut r = Router::new(key(1), cfg);
    for k in [key(2), key(3)] {
        r.set_direct(k, true, 0);
        r.hop_up(k, 0);
    }
    let f = |dst: SignPk, src: SignPk| Frame {
        ttl: 8,
        reached: true,
        control: false,
        dst,
        src,
        waypoint: key(1),
        id: 0,
        offset: 0,
        total: 400,
        payload: Bytes::from(vec![0; 400]),
    };
    for _ in 0..5 {
        r.on_frame(key(2), f(key(3), key(2)), 0);
    }
    assert_eq!(r.stats().frames_relayed, 2, "1000 B/s per neighbour");
    assert_eq!(r.stats().dropped_budget, 3);
    assert!(r.admit_record(key(9), 0));
    assert!(!r.admit_record(key(9), 1_000), "one record per origin per 10 s");
    assert!(r.admit_record(key(9), RECORD_MIN_GAP));
}

// ───────────────────────────── convergence ─────────────────────────────

/// Two lines of 6 joined by a new link: how long until every device has a
/// route to every device on the other side (near ones within a period,
/// far ones within the fisheye's full-scope period).
#[test]
fn convergence_time_to_learn_new_routes() {
    let mut net = Net::fast(12);
    for i in 0..5 {
        net.link(i, i + 1);
        net.link(6 + i, 7 + i);
    }
    net.run(5_000);
    net.link(5, 6);
    // every pair within the 8-hop scope
    let all = |n: &Net| (0..6).all(|a| (6..12).filter(|b| b - a <= 8).all(|b| n.has_route(a, b) && n.has_route(b, a)));
    let near = |n: &Net| n.has_route(4, 6) && n.has_route(6, 4);
    let start = net.now;
    let mut t_near = None;
    let t_all = net.until(20_000, |n| {
        if t_near.is_none() && near(n) {
            t_near = Some(n.now - start);
        }
        all(n)
    });
    eprintln!(
        "learn: 2-hop neighbours across the new link after {t_near:?} ms; all routes up to 8 hops after {t_all:?} ms (period 500 ms)"
    );
    assert!(t_all.is_some_and(|t| t <= 4 * 500 * 2), "{t_all:?}");
}

/// A link in the middle of a line dies: with retractions, nobody keeps
/// using the dead route; there is no alternative, so it stops at once.
#[test]
fn convergence_dead_route_stops_being_used() {
    let mut net = Net::fast(8);
    for i in 0..7 {
        net.link(i, i + 1);
    }
    net.run(5_000);
    assert!(net.has_route(0, 7));
    net.cut(3, 4);
    let t = net.until(10_000, |n| (0..4).all(|a| (4..8).all(|b| !n.has_route(a, b))));
    eprintln!("dead route: no device uses it after {t:?} ms (one-way hop delay 5 ms; timeout would be 1750–7000 ms)");
    assert!(t.is_some_and(|t| t <= 100), "{t:?}");
    assert_eq!(net.nodes[0].stats().announcements_forged, 0);
    assert!(net.nodes.iter().map(|r| r.stats().retractions_sent).sum::<u64>() > 0);
}

/// A ring loses one link: every pair finds the way round the other side,
/// with zero loops at any instant during convergence.
#[test]
fn convergence_heals_around_a_ring_without_loops() {
    const N: usize = 9; // cut, it's a line of 8 hops: within scope
    let mut net = Net::fast(N);
    for i in 0..N {
        net.link(i, (i + 1) % N);
    }
    net.run(6_000);
    for d in 0..N {
        assert_eq!(net.loops_toward(d), 0);
    }
    net.cut(0, 1);
    let mut loops = 0;
    let t = net.until(20_000, |n| {
        loops += (0..N).map(|d| n.loops_toward(d)).sum::<usize>();
        (0..N).all(|a| (0..N).all(|b| a == b || n.has_route(a, b)))
    });
    if t.is_none() {
        for a in 0..N {
            let missing: Vec<usize> = (0..N).filter(|b| *b != a && !net.has_route(a, *b)).collect();
            eprintln!("  {a} has no route to {missing:?}");
        }
    }
    let reqs: u64 = net.nodes.iter().map(|r| r.stats().seqreqs_sent).sum();
    eprintln!("ring heal: every pair routed again after {t:?} ms, {loops} loops seen, {reqs} seqno requests");
    assert_eq!(loops, 0);
    assert!(t.is_some_and(|t| t <= 3_000), "{t:?}");
}

/// Random meshes with links appearing and vanishing all the time, packets
/// flowing: no frame ever visits a device twice, and no best-route cycle
/// ever exists.
#[test]
fn churn_never_loops() {
    const N: usize = 30;
    let edges = geometric(N, 100.0, 30.0, 7);
    let mut net = Net::fast(N);
    for (a, b) in &edges {
        net.link(*a, *b);
    }
    net.run(5_000);
    let mut x: u64 = 99;
    let mut rnd = |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m as u64) as usize
    };
    let mut route_loops = 0;
    let mut down: Vec<(usize, usize)> = vec![];
    for round in 0..60 {
        // flap a link
        if round % 2 == 0 {
            let (a, b) = edges[rnd(edges.len())];
            if !down.contains(&(a, b)) {
                net.cut(a, b);
                down.push((a, b));
            }
        } else if !down.is_empty() {
            let (a, b) = down.remove(rnd(down.len()));
            net.link(a, b);
        }
        // traffic between random pairs that have a route
        for _ in 0..5 {
            let (s, d) = (rnd(N), rnd(N));
            if s != d && let Some(via) = net.nodes[s].next_hop_local(&net.k(d), net.now) {
                let (dst, now) = (net.k(d), net.now);
                if !net.nodes[s].is_neighbour(&dst) {
                    net.nodes[s].send(dst, via, Bytes::from_static(b"p"), false, now);
                    net.effects(s);
                }
            }
        }
        for _ in 0..40 {
            net.step();
            route_loops += (0..N).map(|d| net.loops_toward(d)).sum::<usize>();
        }
    }
    let delivered = net.delivered.len();
    eprintln!("churn: 60 link flaps, {delivered} packets delivered, {} frame loops, {route_loops} route loops", net.frame_loops);
    assert_eq!(net.frame_loops, 0);
    assert_eq!(route_loops, 0);
    assert!(delivered > 100);
}

/// Announcements each device sends per second, against mesh size, with
/// fisheye and flood reduction on and off (random geometric graphs).
fn overhead(sizes: &[(usize, f64)]) {
    let mut rows = vec![];
    for &(n, range) in sizes {
        let edges = geometric(n, 100.0, range, n as u64);
        let mut per = vec![];
        for scoped in [false, true] {
            let mut net = Net::new(n, |i| Config {
                announce_every: 500,
                seed: i as u64 + 1,
                fisheye: scoped,
                flood_reduction: scoped,
                ..Config::default()
            });
            for (a, b) in &edges {
                net.link(*a, *b);
            }
            net.run(3_000);
            let before: u64 = net.sent.iter().sum();
            net.run(4_000);
            let after: u64 = net.sent.iter().sum();
            per.push((after - before) as f64 / n as f64 / 4.0);
        }
        let degree = edges.len() as f64 * 2.0 / n as f64;
        rows.push((n, degree, per[0], per[1]));
    }
    for (n, d, flat, scoped) in &rows {
        eprintln!(
            "overhead n={n:>3} mean degree {d:>4.1}: {flat:>6.1} msgs/s per device flat, {scoped:>6.1} with fisheye + flood reduction ({:.0}% less)",
            100.0 * (1.0 - scoped / flat)
        );
        assert!(scoped < flat);
    }
}

#[test]
fn overhead_per_device_against_mesh_size() {
    overhead(&[(25, 30.0), (50, 22.0), (100, 16.0)]);
}

/// The same at 200 and 400 devices (slow in a debug build).
#[test]
#[ignore]
fn overhead_per_device_large_meshes() {
    overhead(&[(200, 11.5), (400, 8.2)]);
}
