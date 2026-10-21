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
    /// Plausible liars, as tier 2's: they relay announcements claiming to
    /// be one hop from every origin, as cheaply as an honest relay could
    /// say it, and swallow the packets that this attracts.
    pub liars: BTreeSet<usize>,
    /// With real keys ([`Net::signed`]): every signature is made and
    /// checked for real (Ed25519, `wire.rs`).
    pub keys: Option<Vec<mycel_crypto::DeviceKeys>>,
    /// Devices whose hops take route attestations (`ROUTE_ATTEST`), when
    /// both ends do.
    pub attesting: BTreeSet<usize>,
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
            liars: BTreeSet::new(),
            keys: None,
            attesting: BTreeSet::new(),
        }
    }

    /// [`Net::new`] with real keys and signatures, every device attesting.
    pub fn signed(n: usize, cfg: impl Fn(usize) -> Config) -> Net {
        let keys: Vec<mycel_crypto::DeviceKeys> =
            (0..n).map(|i| mycel_crypto::DeviceKeys::from_seed([i as u8 + 1; 32])).collect();
        let mut net = Net::new(n, &cfg);
        net.nodes = keys.iter().enumerate().map(|(i, k)| Router::new(k.sign_pk(), cfg(i))).collect();
        net.index = net.nodes.iter().enumerate().map(|(i, r)| (r.me(), i)).collect();
        net.keys = Some(keys);
        net.attesting = (0..n).collect();
        net
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
        let both = self.attesting.contains(&a) && self.attesting.contains(&b);
        self.nodes[a].set_attests(kb, Some(both), now);
        self.nodes[b].set_attests(ka, Some(both), now);
        self.nodes[a].hop_up(kb, now);
        self.nodes[b].hop_up(ka, now);
    }

    /// [`Net::link`], then measure the hop at `cost` both ways (in that
    /// order, as the node does).
    pub fn link_cost(&mut self, a: usize, b: usize, cost: u32) {
        self.link(a, b);
        let (ka, kb) = (self.k(a), self.k(b));
        self.nodes[a].set_cost(kb, cost);
        self.nodes[b].set_cost(ka, cost);
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
        self.links.contains(&(a.min(b), a.max(b))) || (self.nodes[a].internet() && self.nodes[b].internet())
    }

    /// Carry out node `i`'s effects.
    fn effects(&mut self, i: usize) {
        let mut outs = Vec::new();
        self.nodes[i].drain(&mut outs);
        let (me, now) = (self.k(i), self.now);
        for o in outs {
            match o {
                Out::Announce { to, mut ann } => {
                    if let Some(keys) = &self.keys {
                        ann = crate::mesh::wire::sign_hop(&keys[i], ann, &to);
                    }
                    if self.liars.contains(&i) && ann.origin != me && ann.cost != INFINITY {
                        // (unattested: no chain backs this)
                        (ann.hops, ann.cost, ann.chain, ann.sign_link) = (1, 1 + HOP_PENALTY, None, None);
                    }
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
                Out::Frame { to, frame, relayed } => {
                    if relayed && self.liars.contains(&i) {
                        continue; // swallowed
                    }
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
                    let gws =
                        self.records.iter().rev().find(|(n, _)| self.nodes[*n].me() == peer).map(|(_, g)| g.clone());
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
                Msg::Ann(a) => {
                    if self.keys.is_some() {
                        self.nodes[to].on_announce(f, a, now, WALL + now, crate::mesh::wire::verify)
                    } else {
                        self.nodes[to].on_announce(f, a, now, WALL + now, |_| true)
                    }
                }
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
                    if let Some(keys) = &self.keys {
                        r.originate(crate::mesh::wire::sign_announce(&keys[i], o, ""), now);
                        r.tick(now);
                        self.effects(i);
                        continue;
                    }
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
                        chain: None,
                        sign_link: None,
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

    /// Following next hops from `from` reaches `to`.
    pub fn routed(&self, from: usize, to: usize) -> bool {
        let mut at = from;
        for _ in 0..16 {
            match self.nodes[at].next_hop_local(&self.k(to), self.now) {
                Some(n) if self.index[&n] == to => return true,
                Some(n) => at = self.index[&n],
                None => return false,
            }
        }
        false
    }

    /// Radio hops between two devices (breadth-first over the links).
    pub fn hops(&self, from: usize, to: usize) -> Option<usize> {
        let mut dist = vec![usize::MAX; self.nodes.len()];
        let mut q = std::collections::VecDeque::from([from]);
        dist[from] = 0;
        while let Some(u) = q.pop_front() {
            for &(a, b) in &self.links {
                let v = if a == u {
                    b
                } else if b == u {
                    a
                } else {
                    continue;
                };
                if dist[v] == usize::MAX {
                    dist[v] = dist[u] + 1;
                    q.push_back(v);
                }
            }
        }
        (dist[to] != usize::MAX).then_some(dist[to])
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
    // relayed by a neighbour: one hop, as an honest relay sends it
    let ann = |origin, seq| Announce {
        hops: 1,
        cost: 100,
        origin,
        seq,
        flags: 0,
        scope: 8,
        uplink: 0,
        name: Arc::from(""),
        sig: Sig([0; 64]),
                        chain: None,
                        sign_link: None,
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
            ext: 0,
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
    assert_eq!(net.delivered.last().map(|(i, _, p)| (*i, p.clone())), Some((3, Bytes::from_static(b"default route"))));
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

/// A black hole claims every device is right next to it: relayed
/// announcements at no cost (or as the origin itself). No honest relay can
/// send that (each hop adds at least `MIN_HOP_COST`), so the neighbour is
/// distrusted: the routes it gave go, the routes it relays are ignored for
/// a while, and it stays reachable itself. A plausible claim, or a
/// retraction, is never blamed.
#[test]
fn a_neighbour_relaying_impossible_routes_is_not_routed_through() {
    let ann = |origin, seq, hops, cost| Announce {
        hops,
        cost,
        origin,
        seq,
        flags: 0,
        scope: 8,
        uplink: 0,
        name: Arc::from(""),
        sig: Sig([0; 64]),
                        chain: None,
                        sign_link: None,
    };
    let (honest, liar, o, p, q) = (key(2), key(3), key(9), key(10), key(11));
    let mut r = Router::new(key(1), Config::default());
    for n in [honest, liar] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        r.set_cost(n, 100);
    }
    let ok = |_: Check<'_>| true;
    r.on_announce(honest, ann(o, WALL, 2, 400), 10, WALL, ok);
    r.on_announce(liar, ann(liar, WALL, 0, 0), 10, WALL, ok);
    r.on_announce(liar, ann(q, WALL, 1, 50), 10, WALL, ok);
    r.tick(20);
    assert_eq!(r.next_hop_local(&o, 20), Some(honest));
    assert_eq!(r.next_hop_local(&q, 20), Some(liar), "plausible: believed");
    // a retraction may carry no hops: never blamed
    r.on_announce(honest, Announce { cost: INFINITY, ..ann(p, WALL, 0, 0) }, 30, WALL, ok);
    assert_eq!(r.stats().neighbours_distrusted, 0);
    // "o is right here": impossible two hops out at no cost
    r.on_announce(liar, ann(o, WALL + 1, 2, 0), 40, WALL, ok);
    assert_eq!(r.stats().neighbours_distrusted, 1);
    r.tick(50);
    assert_eq!(r.next_hop_local(&o, 50), Some(honest));
    assert_eq!(r.next_hop_local(&q, 50), None, "what it gave before goes too");
    // what it relays now is ignored, even if plausible; it stays reachable itself
    r.on_announce(liar, ann(p, WALL + 2, 1, 50), 60, WALL, ok);
    r.on_announce(liar, ann(liar, WALL + 3, 0, 0), 60, WALL, ok);
    r.tick(70);
    assert_eq!(r.next_hop_local(&p, 70), None);
    assert_eq!(r.route_hops(&liar, &liar), Some(1));
    // as the origin, claiming no hops from somewhere else: impossible too
    let mut r2 = Router::new(key(1), Config::default());
    r2.set_direct(liar, true, 0);
    r2.hop_up(liar, 0);
    r2.on_announce(liar, ann(o, WALL, 0, 0), 10, WALL, ok);
    assert_eq!(r2.stats().neighbours_distrusted, 1);
    // after a while it gets another chance
    let later = 40 + DISTRUST + 1;
    r.tick(later);
    r.on_announce(liar, ann(p, WALL + later, 1, 50), later, WALL + later, ok);
    r.tick(later + 10);
    assert_eq!(r.next_hop_local(&p, later + 10), Some(liar));
}

/// A black hole that lies plausibly can't be refuted from announcements,
/// but the destination's acknowledgements don't come back through it: two
/// timeouts in a row with nothing acknowledged through one next hop, and the
/// source takes the next route for that destination. One acknowledgement in
/// between clears the count (a slow or lossy link isn't dropped), and the
/// suspicion runs out.
#[test]
fn unacknowledged_packets_move_a_destination_off_its_next_hop() {
    let ann = |origin, seq, hops, cost| Announce {
        hops,
        cost,
        origin,
        seq,
        flags: 0,
        scope: 8,
        uplink: 0,
        name: Arc::from(""),
        sig: Sig([0; 64]),
                        chain: None,
                        sign_link: None,
    };
    let (liar, honest, d) = (key(2), key(3), key(9));
    // the rule itself (the defences that refine it are tested below)
    let mut r = Router::new(key(1), Config { defences: Defences::NONE, ..Config::default() });
    for n in [liar, honest] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        r.set_cost(n, 100);
    }
    let ok = |_: Check<'_>| true;
    r.on_announce(liar, ann(d, WALL, 1, 21), 10, WALL, ok);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, ok);
    r.tick(20);
    let send = |r: &mut Router, t: Time| {
        r.send(d, key(1), Bytes::from_static(b"x"), false, t);
        outcome(r).2
    };
    assert_eq!(send(&mut r, 100), vec![liar], "the cheapest claim wins");
    r.feedback(d, false, 1_100);
    r.feedback(d, true, 1_500); // an ack: the count starts again
    r.feedback(d, false, 2_100);
    assert_eq!(send(&mut r, 2_200), vec![liar], "one timeout at a time is a slow link");
    r.feedback(d, false, 4_200);
    assert_eq!(r.stats().hops_suspected, 1);
    assert_eq!(send(&mut r, 4_300), vec![honest]);
    // the honest route works; nothing more is suspected
    r.feedback(d, true, 4_400);
    r.feedback(d, false, 6_000);
    assert_eq!(send(&mut r, 6_100), vec![honest]);
    // every route suspected: still the best (dropping can't deliver)
    r.feedback(d, false, 9_000);
    assert_eq!(r.stats().hops_suspected, 2);
    assert_eq!(send(&mut r, 9_100), vec![liar]);
    // suspicion runs out
    let later = 9_000 + SUSPECT_FOR + 1;
    r.on_announce(liar, ann(d, WALL + later, 1, 21), later, WALL + later, ok);
    r.tick(later + 10);
    assert_eq!(send(&mut r, later + 20), vec![liar]);
}

/// The node's evidence comes per QUIC path: `mesh(d, via)` silent while
/// we send on it. Two such silences, long enough for the route, and the
/// route offered for `d` moves to another first hop (RouteDown, RouteUp);
/// a path that isn't a mesh route through a neighbour isn't judged.
#[test]
fn a_silent_path_moves_the_offered_route() {
    let ann = |origin, seq, hops, cost| Announce {
        hops,
        cost,
        origin,
        seq,
        flags: 0,
        scope: 8,
        uplink: 0,
        name: Arc::from(""),
        sig: Sig([0; 64]),
                        chain: None,
                        sign_link: None,
    };
    let (liar, honest, d, stranger) = (key(2), key(3), key(9), key(7));
    let mut r = Router::new(key(1), Config { routes: 1, defences: Defences::NONE, ..Config::default() });
    for n in [liar, honest] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        r.set_cost(n, 100);
    }
    let ok = |_: Check<'_>| true;
    r.on_announce(liar, ann(d, WALL, 1, 21), 10, WALL, ok);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, ok);
    r.tick(20);
    assert_eq!(r.offered(&d), vec![liar]);
    assert!(!r.path_feedback(d, stranger, Some(100), 3_100), "not a route of ours");
    assert!(r.path_feedback(d, liar, Some(100), 3_100));
    r.path_feedback(d, liar, None, 3_200); // it answered: start again
    r.path_feedback(d, liar, Some(4_000), 7_000);
    r.tick(7_010);
    assert_eq!(r.offered(&d), vec![liar], "one silence isn't enough");
    r.path_feedback(d, liar, Some(4_000), 9_000); // it closed, still silent
    let mut outs = Vec::new();
    r.drain(&mut outs);
    // we advertised the cheap route, so the other is infeasible: a fresh
    // seqno is asked for (not through the suspect) ...
    assert!(outs.iter().any(|o| matches!(o, Out::SeqReq { to, req } if *to == honest && req.origin == d)));
    assert!(!outs.iter().any(|o| matches!(o, Out::SeqReq { to, .. } if *to == liar)));
    // ... and once it comes, the route moves
    r.on_announce(honest, ann(d, WALL + 9_005, 3, 500), 9_005, WALL + 9_005, ok);
    r.tick(9_010);
    r.drain(&mut outs);
    assert_eq!(r.offered(&d), vec![honest]);
    assert!(outs.iter().any(|o| matches!(o, Out::RouteDown { dst, via } if *dst == d && *via == liar)));
    assert!(outs.iter().any(|o| matches!(o, Out::RouteUp { dst, via, .. } if *dst == d && *via == honest)));
    // when the suspicion runs out, the cheaper route is offered again
    let later = 9_000 + SUSPECT_FOR + 1;
    r.on_announce(liar, ann(d, WALL + later, 1, 21), later, WALL + later, ok);
    r.on_announce(honest, ann(d, WALL + later, 3, 500), later, WALL + later, ok);
    r.tick(later + 10);
    assert_eq!(r.offered(&d), vec![liar]);
}

/// What a router did with one packet of ours: (dials, lookups, frames sent to).
fn outcome(r: &mut Router) -> (Vec<SignPk>, usize, Vec<SignPk>) {
    let mut outs = Vec::new();
    r.drain(&mut outs);
    let dials = outs.iter().filter_map(|o| if let Out::Dial(k) = o { Some(*k) } else { None }).collect();
    let resolves = outs.iter().filter(|o| matches!(o, Out::Resolve(_))).count();
    let frames = outs.iter().filter_map(|o| if let Out::Frame { to, .. } = o { Some(*to) } else { None }).collect();
    (dials, resolves, frames)
}

/// A gateway carrying our traffic to a device behind it is kept: the
/// record's other gateways, not tried yet, are costed like the one we have
/// measured (they sit in the same mesh), not as a flat guess far below any
/// measured internet hop. Before, each packet after the first measurement
/// dialled the other gateway and waited for it.
#[test]
fn a_working_gateway_is_kept_over_untried_ones() {
    let (t, g1, g2) = (key(50), key(60), key(61));
    let mut r = Router::new(key(1), Config::default());
    r.set_internet(true);
    r.send(t, key(1), Bytes::from_static(b"1"), false, 0);
    assert_eq!(outcome(&mut r).1, 1, "a lookup");
    r.on_resolved(t, Some(vec![(g1, 300), (g2, 300)]), 150);
    let (dials, _, _) = outcome(&mut r);
    assert_eq!(dials, vec![g1], "equal cost: the first");
    r.hop_up(g1, 300);
    r.set_cost(g1, 3_000); // a 150 ms round trip and the time to move 64 KiB
    assert_eq!(outcome(&mut r).2, vec![g1], "the waiting frame goes");
    r.send(t, key(1), Bytes::from_static(b"2"), false, 1_000);
    assert_eq!(outcome(&mut r), (vec![], 0, vec![g1]), "no dial to the other gateway");
    // one that is clearly closer to the target is still worth a dial
    r.on_resolved(t, Some(vec![(g1, 3_000), (g2, 300)]), 2_000);
    r.send(t, key(1), Bytes::from_static(b"3"), false, 2_000);
    assert_eq!(outcome(&mut r).0, vec![g2]);
}

/// A looked-up record goes out of date after a minute. Traffic through a
/// gateway of it that is up doesn't wait for the new lookup (it used to
/// stall on every expiry); a gateway that isn't up isn't dialled from an
/// out-of-date record; and a record long out of date is looked up first.
#[test]
fn an_out_of_date_record_keeps_a_working_gateway_while_it_is_looked_up() {
    let (t, g1, g2) = (key(50), key(60), key(61));
    let mut r = Router::new(key(1), Config::default());
    r.set_internet(true);
    r.send(t, key(1), Bytes::from_static(b"1"), false, 0);
    r.on_resolved(t, Some(vec![(g1, 300), (g2, 300)]), 100);
    r.hop_up(g1, 200);
    r.set_cost(g1, 3_000);
    outcome(&mut r);
    let stale = 100 + REACH_TTL + 1;
    r.tick(stale);
    r.send(t, key(1), Bytes::from_static(b"2"), false, stale);
    assert_eq!(outcome(&mut r), (vec![], 1, vec![g1]), "sent at once, looked up again");
    r.send(t, key(1), Bytes::from_static(b"3"), false, stale + 10);
    assert_eq!(outcome(&mut r), (vec![], 0, vec![g1]), "one lookup at a time");
    r.on_resolved(t, Some(vec![(g2, 100), (g1, 300)]), stale + 200);
    outcome(&mut r);
    // without a hop up, an out-of-date record waits for its lookup
    r.hop_down(g1, stale + 300);
    let later = stale + 200 + REACH_TTL + 1;
    r.tick(later);
    r.send(t, key(1), Bytes::from_static(b"4"), false, later);
    assert_eq!(outcome(&mut r), (vec![], 1, vec![]), "no dial from an out-of-date record");
    r.on_resolved(t, Some(vec![(g2, 100), (g1, 300)]), later + 100);
    assert_eq!(outcome(&mut r).0, vec![g2], "then the fresh one's best");
    // long out of date: forgotten, looked up before anything moves
    r.hop_up(g2, later + 200);
    outcome(&mut r);
    let gone = later + 100 + REACH_TTL + REACH_STALE + 1;
    r.tick(gone);
    r.send(t, key(1), Bytes::from_static(b"5"), false, gone);
    assert_eq!(outcome(&mut r), (vec![], 1, vec![]));
}

/// Data-frame flags a later version assigns are relayed unchanged (wire
/// version 2: docs/PROTOCOL.md §3.5), so marking frames end to end needs
/// no relay upgrade.
#[test]
fn relays_carry_unknown_frame_flags_unchanged() {
    let mut r = Router::new(key(1), Config::default());
    for k in [key(2), key(3)] {
        r.set_direct(k, true, 0);
        r.hop_up(k, 0);
    }
    let f = Frame {
        ttl: 8,
        reached: true,
        control: false,
        ext: 0x40,
        dst: key(3),
        src: key(2),
        waypoint: key(1),
        id: 0,
        offset: 0,
        total: 3,
        payload: Bytes::from_static(b"abc"),
    };
    r.on_frame(key(2), f, 0);
    let mut outs = Vec::new();
    r.drain(&mut outs);
    let relayed: Vec<&Frame> =
        outs.iter().filter_map(|o| if let Out::Frame { frame, .. } = o { Some(frame) } else { None }).collect();
    assert_eq!(relayed.len(), 1, "{outs:?}");
    assert_eq!(relayed[0].ext, 0x40);
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
        ext: 0,
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

/// Babel-like timing (16 s periods): a device meeting a mesh learns its
/// neighbours' routes from the greeting and announces itself to the full
/// scope at once, so nobody waits for a period.
#[test]
fn new_neighbours_are_greeted_and_lone_devices_announce_fully() {
    for greet in [Greet::Near, Greet::Own] {
        let mut net =
            Net::new(7, |i| Config { announce_every: 16_000, greet, seed: i as u64 + 1, ..Config::default() });
        for i in 0..5 {
            net.link(i, i + 1);
        }
        // node 6 is alone for a while: its announcements reach nobody, and
        // the latest ones are near-scope (fisheye)
        net.run(100_000);
        assert!(net.has_route(0, 5) && net.has_route(5, 0));
        net.link(6, 5);
        let start = net.now;
        let (mut t_far, mut t_near) = (None, None);
        net.until(16_000, |n| {
            if t_far.is_none() && n.has_route(0, 6) {
                t_far = Some(n.now - start);
            }
            if t_near.is_none() && n.has_route(6, 4) {
                t_near = Some(n.now - start);
            }
            t_far.is_some() && t_near.is_some()
        });
        eprintln!(
            "greet {greet:?}: 5 hops away learns the newcomer in {t_far:?} ms, the newcomer learns 2 hops away in {t_near:?} ms"
        );
        assert!(t_far.is_some_and(|t| t <= 600), "a lone device's first neighbour: full scope at once ({t_far:?})");
        match greet {
            Greet::Near => assert!(t_near.is_some_and(|t| t <= 100), "{t_near:?}"),
            _ => assert!(t_near.is_none_or(|t| t > 1_000), "without a greeting it waits for a period ({t_near:?})"),
        }
        assert_eq!(net.loops_toward(6), 0);
        assert_eq!(net.loops_toward(0), 0);
    }
}

/// A device announcing every 10 ms (a storm) reaches its neighbours; relays
/// pass on at most one of its seqnos per 250 ms.
#[test]
fn an_announcement_storm_stops_at_the_first_relays() {
    let mut net = Net::new(3, |i| Config { announce_every: 16_000, seed: i as u64 + 1, ..Config::default() });
    net.link(0, 1);
    net.link(1, 2);
    net.run(1_000);
    let received = |n: &Net| n.nodes[2].stats().announcements_received;
    let before = received(&net);
    for _ in 0..200 {
        let now = net.now;
        let r = &mut net.nodes[0];
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
                        chain: None,
                        sign_link: None,
        };
        r.originate(a, now);
        net.effects(0);
        net.run(10);
    }
    net.run(200);
    let through = received(&net) - before;
    eprintln!("storm: 200 announcements in 2 s, {through} reached 2 hops away");
    assert!(through <= 10, "{through}");
    assert!(net.nodes[1].stats().announcements_limited > 0);
    assert!(net.has_route(2, 0), "the storming device stays reachable");
}

/// Over unicast hops, the broadcast-style flood reduction (skip a
/// rebroadcast after hearing 3 equal copies) leaves devices out: those
/// copies reached their senders' neighbours, not ours. Off by default.
#[test]
fn flood_reduction_is_off_and_floods_reach_everyone() {
    assert!(!Config::default().flood_reduction);
    let edges = geometric(60, 100.0, 24.0, 7);
    let coverage = |reduction: bool| {
        let mut net = Net::new(60, |i| Config {
            announce_every: 500,
            flood_reduction: reduction,
            seed: i as u64 + 1,
            ..Config::default()
        });
        for (a, b) in &edges {
            net.link(*a, *b);
        }
        net.run(3_000);
        let mut ok = 0;
        let mut all = 0;
        for a in 0..60 {
            for b in 0..60 {
                if a != b && net.hops(a, b).is_some_and(|h| h <= 6) {
                    all += 1;
                    ok += net.routed(a, b) as usize;
                }
            }
        }
        ok as f64 / all as f64
    };
    let (off, on) = (coverage(false), coverage(true));
    eprintln!("pairs within 8 hops routed after 3 s: reduction off {:.1}%, on {:.1}%", 100.0 * off, 100.0 * on);
    assert!(off >= 0.99, "{off}");
    assert!(off >= on);
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
            if s != d
                && let Some(via) = net.nodes[s].next_hop_local(&net.k(d), net.now)
            {
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
    eprintln!(
        "churn: 60 link flaps, {delivered} packets delivered, {} frame loops, {route_loops} route loops",
        net.frame_loops
    );
    assert_eq!(net.frame_loops, 0);
    assert_eq!(route_loops, 0);
    assert!(delivered > 100);
    // honest relays never send a route the plausibility check refuses
    assert!(net.nodes.iter().all(|r| r.stats().neighbours_distrusted == 0 && r.stats().announcements_implausible == 0));
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

#[test]
fn security_verified_cache_binds_every_signed_field() {
    use crate::mesh::wire::{sign_announce, verify, verify_announce};
    let owner = mycel_crypto::DeviceKeys::generate();
    for field in 0..7 {
        let mut router = Router::new(key(1), Config::default());
        let neighbour = key(2);
        router.set_direct(neighbour, true, 0);
        router.hop_up(neighbour, 0);
        let mut ann = sign_announce(&owner, Origination { seq: WALL, flags: 0, scope: 8, uplink: 0 }, "original");
        ann.cost = INFINITY;
        router.on_announce(neighbour, ann.clone(), 0, WALL, verify);
        // relayed: one hop (hops and cost aren't signed)
        ann.hops = 1;
        ann.cost = 100;
        match field {
            0 => ann.name = Arc::from("forged"),
            1 => ann.flags = F_GATEWAY,
            2 => ann.scope = 7,
            3 => ann.uplink = 1,
            4 => ann.sig.0[0] ^= 1,
            5 => ann.seq += 1,
            _ => ann.origin = mycel_crypto::DeviceKeys::generate().sign_pk(),
        }
        assert!(!verify_announce(&ann));
        let origin = ann.origin;
        router.on_announce(neighbour, ann, 1, WALL, verify);
        assert!(router.origin_name(&origin).is_none(), "field {field} bypassed verification");
        assert_eq!(router.stats().announcements_forged, 1);
    }
}

#[test]
fn security_verified_cache_allows_forwarded_hops_and_cost() {
    use crate::mesh::wire::{sign_announce, verify, verify_announce};
    let owner = mycel_crypto::DeviceKeys::generate();
    let mut router = Router::new(key(1), Config::default());
    let neighbour = key(2);
    router.set_direct(neighbour, true, 0);
    router.hop_up(neighbour, 0);
    let mut ann = sign_announce(&owner, Origination { seq: WALL, flags: 0, scope: 8, uplink: 0 }, "original");
    ann.cost = INFINITY;
    router.on_announce(neighbour, ann.clone(), 0, WALL, verify);
    ann.cost = 123;
    ann.hops = 2;
    assert!(verify_announce(&ann));
    router.on_announce(neighbour, ann, 1, WALL, |_| panic!("same signed announcement reverified"));
    assert_eq!(router.origin_name(&owner.sign_pk()).as_deref(), Some("original"));
}

#[test]
fn security_verified_cache_stays_bounded_and_can_be_disabled() {
    use crate::mesh::wire::{sign_announce, verify};
    for limit in [0, 1, 2] {
        let owner = mycel_crypto::DeviceKeys::generate();
        let mut router = Router::new(key(1), Config { verified_max: limit, ..Config::default() });
        let neighbour = key(2);
        router.set_direct(neighbour, true, 0);
        router.hop_up(neighbour, 0);
        for i in 0..5 {
            let mut ann =
                sign_announce(&owner, Origination { seq: WALL + i, flags: 0, scope: 8, uplink: 0 }, "original");
            ann.hops = 1;
            ann.cost = 100;
            router.on_announce(neighbour, ann, i, WALL, verify);
            assert!(router.verified.len() <= limit);
        }
    }
}

// ───────────────────────────── defences ─────────────────────────────

fn ann(origin: SignPk, seq: u64, hops: u8, cost: u32) -> Announce {
    Announce { hops, cost, origin, seq, flags: 0, scope: 8, uplink: 0, name: Arc::from(""), sig: Sig([0; 64]), chain: None, sign_link: None }
}

/// A source that doesn't relay (so nothing it advertises narrows which
/// routes are feasible), with these neighbours up at time 0, measured at
/// 10 ms, and only these defences.
fn source(neighbours: &[SignPk], defences: Defences) -> Router {
    let mut r = Router::new(key(1), Config { relay: false, defences, ..Config::default() });
    for n in neighbours {
        r.set_direct(*n, true, 0);
        r.hop_up(*n, 0);
        r.set_cost(*n, 100);
    }
    r
}

/// Where a packet of ours to `d` goes now.
fn sent_to(r: &mut Router, d: SignPk, t: Time) -> Vec<SignPk> {
    r.send(d, key(1), Bytes::from_static(b"x"), false, t);
    outcome(r).2
}

/// Two timeouts through `d`'s next hop, far enough apart to suspect it.
fn suspect(r: &mut Router, d: SignPk, t: Time) {
    sent_to(r, d, t);
    r.feedback(d, false, t + 1_000);
    r.feedback(d, false, t + 4_000);
}

/// [`suspect`], then the next packet takes another route and is
/// acknowledged through it: `d` is alive, the suspect was silent. Where
/// that packet went.
fn suspect_then_ack(r: &mut Router, d: SignPk, t: Time) -> Vec<SignPk> {
    suspect(r, d, t);
    let to = sent_to(r, d, t + 4_100);
    r.feedback(d, true, t + 4_200);
    to
}

/// A relay suspected for three destinations, each of which then
/// acknowledged through another hop, is avoided for every destination (and
/// not before: two could be bad luck), but stays reachable itself.
/// Destinations that merely went silent (offline: no acknowledgement
/// through anyone) count for nothing until one comes; a relay that carried
/// acknowledgements for more destinations than it is suspected for is not
/// shunned (a busy honest relay collects the most false suspicions).
#[test]
fn a_hop_suspected_for_several_live_destinations_is_avoided_for_all() {
    let (liar, honest) = (key(2), key(3));
    let ds: Vec<SignPk> = (10..15).map(key).collect();
    let only = Defences { aggregate: true, ..Defences::NONE };
    let routes = |r: &mut Router, hop: SignPk, ds: &[SignPk]| {
        for d in ds {
            r.on_announce(hop, ann(*d, WALL, 1, 21), 10, WALL, |_| true);
            r.on_announce(honest, ann(*d, WALL, 3, 500), 10, WALL, |_| true);
        }
    };
    let mut r = source(&[liar, honest], only);
    routes(&mut r, liar, &ds);
    assert_eq!(suspect_then_ack(&mut r, ds[0], 100), vec![honest]);
    suspect_then_ack(&mut r, ds[1], 5_000);
    assert_eq!(r.stats().hops_suspected, 2);
    assert_eq!(sent_to(&mut r, ds[3], 9_500), vec![liar], "two suspicions aren't enough");
    suspect_then_ack(&mut r, ds[2], 10_000);
    assert_eq!(r.stats().hops_shunned, 1);
    assert_eq!(sent_to(&mut r, ds[3], 14_500), vec![honest]);
    assert_eq!(sent_to(&mut r, ds[4], 14_600), vec![honest]);
    assert_eq!(r.next_hop_local(&liar, 14_700), Some(liar), "still reachable itself");
    // silent destinations (offline, perhaps) count once they acknowledge
    // through someone else, not before
    let mut r = source(&[liar, honest], only);
    routes(&mut r, liar, &ds);
    for (i, d) in ds[..4].iter().enumerate() {
        suspect(&mut r, *d, 100 + 5_000 * i as Time);
    }
    assert_eq!(r.stats().hops_suspected, 4);
    assert_eq!(r.stats().hops_shunned, 0);
    assert_eq!(sent_to(&mut r, ds[4], 20_000), vec![liar]);
    for (i, d) in ds[..3].iter().enumerate() {
        assert_eq!(sent_to(&mut r, *d, 21_000 + i as Time), vec![honest]);
        r.feedback(*d, true, 21_500 + i as Time);
    }
    assert_eq!(r.stats().hops_shunned, 1, "alive after all");
    assert_eq!(sent_to(&mut r, ds[4], 22_000), vec![honest]);
    // without the defence, only the suspected destinations move
    let mut plain = source(&[liar, honest], Defences::NONE);
    routes(&mut plain, liar, &ds);
    for (i, d) in ds[..3].iter().enumerate() {
        suspect_then_ack(&mut plain, *d, 100 + 5_000 * i as Time);
    }
    assert_eq!(sent_to(&mut plain, ds[3], 14_500), vec![liar]);
    // a relay that delivers for more destinations than it fails isn't shunned
    let busy = key(4);
    let mut r = source(&[busy, honest], only);
    let more: Vec<SignPk> = (20..27).map(key).collect();
    routes(&mut r, busy, &ds);
    routes(&mut r, busy, &more);
    for (i, d) in more.iter().enumerate() {
        sent_to(&mut r, *d, 50 + i as Time);
        r.feedback(*d, true, 60 + i as Time);
    }
    for (i, d) in ds[..4].iter().enumerate() {
        suspect_then_ack(&mut r, *d, 100 + 5_000 * i as Time);
    }
    assert_eq!(r.stats().hops_suspected, 4);
    assert_eq!(r.stats().hops_shunned, 0);
    assert_eq!(sent_to(&mut r, ds[4], 20_000), vec![busy]);
}

/// Shunning a relay asks for fresh seqnos only for our destinations that
/// went through it lately (the latest first), and at most `SHUN_SEQREQS`
/// requests in all, however many destinations we ever sent to. Before,
/// every destination ever sent through it asked every other neighbour.
#[test]
fn shunning_asks_around_within_a_bound() {
    let (liar, honest) = (key(2), key(3));
    let mut nbs = vec![liar, honest];
    nbs.extend((4..10).map(key));
    let mut r = source(&nbs, Defences { aggregate: true, ..Defences::NONE });
    let ds: Vec<SignPk> = (10..13).map(key).collect();
    let old: Vec<SignPk> = (100..250).map(key).collect();
    let recent: Vec<SignPk> = (300..450).map(key).collect();
    // only the liar offers routes to `old` and `recent`
    let offer = |r: &mut Router, t: Time| {
        for d in ds.iter().chain(&old).chain(&recent) {
            r.on_announce(liar, ann(*d, WALL + t, 1, 21), t, WALL + t, |_| true);
        }
        for d in &ds {
            r.on_announce(honest, ann(*d, WALL + t, 3, 500), t, WALL + t, |_| true);
        }
    };
    offer(&mut r, 10);
    for (i, d) in old.iter().enumerate() {
        assert_eq!(sent_to(&mut r, *d, 1_000 + i as Time), vec![liar]);
    }
    let t = 1_000 + SUSPECT_FOR + 1_000;
    offer(&mut r, t);
    for (i, d) in recent.iter().enumerate() {
        sent_to(&mut r, *d, t + 100 + i as Time);
    }
    suspect_then_ack(&mut r, ds[0], t + 1_000);
    suspect_then_ack(&mut r, ds[1], t + 6_000);
    suspect(&mut r, ds[2], t + 11_000);
    assert_eq!(sent_to(&mut r, ds[2], t + 15_100), vec![honest]);
    let before = r.stats().seqreqs_sent;
    r.feedback(ds[2], true, t + 15_200);
    assert_eq!(r.stats().hops_shunned, 1);
    let mut outs = Vec::new();
    r.drain(&mut outs);
    let asked: Vec<SignPk> = outs
        .iter()
        .filter_map(|o| match o {
            Out::SeqReq { req, .. } => Some(req.origin),
            _ => None,
        })
        .collect();
    assert_eq!(r.stats().seqreqs_sent - before, asked.len() as u64);
    assert_eq!(asked.len(), SHUN_SEQREQS, "7 neighbours each for 150 destinations, without the bound");
    assert!(asked.iter().all(|d| recent.contains(d)), "only the recent destinations");
    assert!(asked.contains(recent.last().expect("some")), "the latest first");
}

/// A much cheaper route that one neighbour suddenly claims, and no other
/// backs, ranks behind the route already in use for a while: when it
/// appears, and when a neighbour that offered a plausible, costlier route
/// drops its cost to it (waiting first doesn't get a liar past it). Backed
/// by a second neighbour, acknowledged through, or after the hold-down, it
/// takes over. A route already the cheapest that gets cheaper, or the
/// destination itself come into range, is never held.
#[test]
fn a_sudden_uncorroborated_shortcut_waits_before_displacing_the_incumbent() {
    let (honest, liar, other, d) = (key(2), key(3), key(4), key(9));
    let only = Defences { corroborate: true, ..Defences::NONE };
    let mut r = source(&[honest, liar, other], only);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 100), vec![honest]);
    r.on_announce(liar, ann(d, WALL, 1, 21), 1_000, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 1_100), vec![honest], "held down");
    assert_eq!(sent_to(&mut r, d, 1_000 + HOLD_DOWN - 1), vec![honest]);
    assert_eq!(sent_to(&mut r, d, 1_000 + HOLD_DOWN), vec![liar], "the hold-down ran out");
    // plausible and costlier first; a sudden shortcut once the hold-down
    // (were it counted from then) would have run out: held from the drop
    let mut r = source(&[honest, liar, other], only);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    r.on_announce(liar, ann(d, WALL, 4, 900), 1_000, WALL, |_| true);
    let t = 1_000 + HOLD_DOWN + 1_000;
    r.on_announce(liar, ann(d, WALL, 4, 900), t - 500, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, t - 400), vec![honest]);
    r.on_announce(liar, ann(d, WALL, 1, 21), t, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, t + 100), vec![honest], "held from when it fell");
    assert_eq!(sent_to(&mut r, d, t + HOLD_DOWN - 1), vec![honest]);
    // a liar that keeps lying wins then (it is a delay, not a verdict):
    // what it can't fake is acknowledgements (`Router::feedback`)
    assert_eq!(sent_to(&mut r, d, t + HOLD_DOWN), vec![liar]);
    // a second neighbour's route within the factor backs it at once
    let mut r = source(&[honest, liar, other], only);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    r.on_announce(liar, ann(d, WALL, 1, 21), 1_000, WALL, |_| true);
    r.on_announce(other, ann(d, WALL, 2, 100), 1_500, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 1_600), vec![liar]);
    // so does an acknowledgement from the destination through it lately
    let both = Defences { aggregate: true, ..only };
    let mut r = source(&[honest, liar], both);
    r.on_announce(liar, ann(d, WALL, 2, 300), 10, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 100), vec![liar]);
    r.feedback(d, true, 200);
    r.on_announce(honest, ann(d, WALL, 3, 500), 300, WALL, |_| true);
    r.on_announce(liar, ann(d, WALL, 4, 900), 400, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 500), vec![honest]);
    r.on_announce(liar, ann(d, WALL, 1, 21), 1_000, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 1_100), vec![liar], "acknowledged through it lately");
    // no incumbent (both new): nothing to hold for
    let mut r = source(&[honest, liar], only);
    r.on_announce(liar, ann(d, WALL, 1, 21), 10, WALL, |_| true);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 100), vec![liar]);
    // the cheapest route getting cheaper isn't a sudden shortcut
    let mut r = source(&[honest, other], only);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    r.on_announce(other, ann(d, WALL, 2, 300), 1_000, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 1_100), vec![other]);
    r.on_announce(other, ann(d, WALL, 1, 21), 2_000, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 2_100), vec![other]);
    // nor is the destination itself, come into range: what we use (and
    // advertise) is its own 1-hop route, not the incumbent's 4 hops
    let mut r = source(&[honest, d], only);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    r.on_announce(d, ann(d, WALL, 0, 0), 1_000, WALL, |_| true);
    assert_eq!(r.best_route(&d, 1_100).map(|(n, v)| (n, v.hops)), Some((d, 1)));
    // without the defence: at once
    let mut r = source(&[honest, liar], Defences::NONE);
    r.on_announce(honest, ann(d, WALL, 3, 500), 10, WALL, |_| true);
    r.on_announce(liar, ann(d, WALL, 1, 21), 1_000, WALL, |_| true);
    assert_eq!(sent_to(&mut r, d, 1_100), vec![liar]);
}

/// Routes through relays outside our spaces rank costlier, those through
/// members don't; with no spaces nobody is preferred. What we advertise is
/// the route we chose, at its own cost.
#[test]
fn relays_far_from_our_spaces_rank_costlier() {
    let (stranger, member, d) = (key(2), key(3), key(9));
    let only = Defences { affinity: true, ..Defences::NONE };
    let setup = |r: &mut Router| {
        r.on_announce(stranger, ann(d, WALL, 2, 280), 10, WALL, |_| true); // 400 through it
        r.on_announce(member, ann(d, WALL, 2, 380), 10, WALL, |_| true); // 500
    };
    let mut r = source(&[stranger, member], only);
    setup(&mut r);
    assert_eq!(sent_to(&mut r, d, 100), vec![stranger], "no spaces: no preference");
    r.set_affinity([(member, 1)]);
    assert_eq!(sent_to(&mut r, d, 200), vec![member]);
    // two steps away it counts half as much, still more than 400 → 500
    r.set_affinity([(member, 1), (stranger, 2)]);
    assert_eq!(sent_to(&mut r, d, 300), vec![member]);
    let mut plain = source(&[stranger, member], Defences::NONE);
    setup(&mut plain);
    plain.set_affinity([(member, 1)]);
    assert_eq!(sent_to(&mut plain, d, 100), vec![stranger]);
    // a smaller step: unknown counts 1.2×, 480 beats 500
    let mut mild = source(&[stranger, member], only);
    mild.cfg.affinity_step = 10;
    setup(&mut mild);
    mild.set_affinity([(member, 1)]);
    assert_eq!(sent_to(&mut mild, d, 100), vec![stranger]);
    // relaying: the announcement passed on carries the chosen route's cost
    let third = key(4);
    let mut r = Router::new(key(1), Config { defences: only, ..Config::default() });
    for n in [stranger, member, third] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        r.set_cost(n, 100);
    }
    r.set_affinity([(member, 1), (third, 1)]);
    let mut outs = Vec::new();
    r.drain(&mut outs);
    outs.clear();
    setup(&mut r);
    r.tick(100);
    r.drain(&mut outs);
    let to_third: Vec<u32> = outs
        .iter()
        .filter_map(|o| match o {
            Out::Announce { to, ann } if *to == third && ann.origin == d => Some(ann.cost),
            _ => None,
        })
        .collect();
    assert_eq!(to_third, vec![500]);
}

/// Relayed announcements to a slow hop take at most 2% of its capacity
/// (after a burst of what it accepts at once); the rest wait, fewest hops first, and go
/// out as they stand when sent: a route lost meanwhile isn't advertised
/// late, one that got cheaper goes at its new cost (and sets our
/// feasibility distance, as any advertisement), and retractions never wait.
#[test]
fn relayed_announcements_are_paced_to_the_hop_nearest_first() {
    let (from, also, ble) = (key(2), key(4), key(3));
    let defences = Defences { budget: true, ..Defences::NONE };
    let mut r = Router::new(key(1), Config { defences, ..Config::default() });
    for n in [from, also, ble] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        // BLE: 64 KiB in 1.67 s, so ~786 B/s for control
        r.set_cost(n, if n == ble { 16_680 } else { 100 });
    }
    let mut outs = Vec::new();
    r.drain(&mut outs);
    outs.clear();
    // once the Wi-Fi hops' budgets have grown from the unmeasured one
    let t0 = 2_000;
    // 600 routes, from two neighbours (each may send 400 at once)
    let origins: Vec<SignPk> = (100..700).map(key).collect();
    let by = |i: usize| if i.is_multiple_of(2) { from } else { also };
    for (i, o) in origins.iter().enumerate() {
        let hops = 1 + (i % 3) as u8;
        r.on_announce(by(i), ann(*o, WALL, hops, 100 * hops as u32), t0 + 10, WALL, |_| true);
    }
    let to_ble = |outs: &mut Vec<Out>| {
        let v: Vec<(SignPk, u8, u32)> = outs
            .iter()
            .filter_map(|o| match o {
                Out::Announce { to, ann } if *to == ble => Some((ann.origin, ann.hops, ann.cost)),
                _ => None,
            })
            .collect();
        outs.clear();
        v
    };
    r.tick(t0 + 100);
    r.drain(&mut outs);
    let first = to_ble(&mut outs).len();
    // a burst of what it accepts from one neighbour at once
    assert_eq!(first, 400);
    assert_eq!(r.stats().announcements_deferred, 200);
    let waiting = |r: &Router, hops: u8| {
        origins.iter().copied().find(|o| r.nbs[&ble].ctl_q.iter().any(|a| a.origin == *o && a.hops == hops))
    };
    // one waiting is lost meanwhile: never sent; its retraction is at once
    let lost = waiting(&r, 2).expect("something waits");
    let i = origins.iter().position(|o| *o == lost).expect("one of ours");
    r.on_announce(by(i), Announce { cost: INFINITY, ..ann(lost, WALL, 1, 0) }, t0 + 200, WALL, |_| true);
    r.drain(&mut outs);
    assert!(to_ble(&mut outs).iter().any(|(o, _, c)| *o == lost && *c == INFINITY));
    // one far route waiting gets cheaper through the other neighbour
    let cheaper = waiting(&r, 4).expect("a far one waits");
    let i = origins.iter().position(|o| *o == cheaper).expect("one of ours");
    let other = if by(i) == from { also } else { from };
    r.on_announce(other, ann(cheaper, WALL, 1, 100), t0 + 300, WALL, |_| true);
    assert_eq!(r.origins[&cheaper].fd, Some((WALL, 420)), "advertised to the other neighbour");
    // then ~786 B/s (6.7 a second), fewest hops first
    let mut later = vec![];
    for k in 1..=3 {
        r.tick(t0 + 100 + k * 1_000);
        r.drain(&mut outs);
        later.extend(to_ble(&mut outs));
    }
    assert!((19..=21).contains(&later.len()), "{} in 3 s", later.len());
    assert!(later.windows(2).all(|w| w[0].1 <= w[1].1), "nearest first");
    // (the near routes expire meanwhile: their retractions don't count)
    for k in 4..=40 {
        if k % 20 == 0 {
            // kept fresh (it is near: it would expire before its turn)
            r.on_announce(other, ann(cheaper, WALL, 1, 100), t0 + k * 1_000, WALL, |_| true);
        }
        r.tick(t0 + 100 + k * 1_000);
        r.drain(&mut outs);
        later.extend(to_ble(&mut outs).into_iter().filter(|(.., c)| *c != INFINITY));
    }
    assert_eq!(later.len(), 199, "all but the lost one");
    assert!(!later.iter().any(|(o, ..)| *o == lost));
    assert_eq!(r.stats().announcements_shed, 1);
    assert!(later.contains(&(cheaper, 2, 220)), "as it stands when sent");
    assert_eq!(r.origins[&cheaper].fd, Some((WALL, 220)), "what we advertised");
}

/// A new neighbour is greeted with our table before its hop is measured:
/// the greeting is paced as for the slowest radio until then, so a big
/// table doesn't go out at once over Bluetooth: what the neighbour accepts
/// at once (more would be thrown away), then 2% of the link. A fast hop,
/// once measured, is never sent more than its receiver accepts either.
#[test]
fn a_greeting_to_an_unmeasured_hop_is_paced() {
    let from = key(2);
    let defences = Defences { budget: true, ..Defences::NONE };
    let mut r = Router::new(key(1), Config { defences, ..Config::default() });
    r.set_direct(from, true, 0);
    r.hop_up(from, 0);
    r.set_cost(from, 100);
    let origins: Vec<SignPk> = (100..2_100).map(key).collect();
    for (i, o) in origins.iter().enumerate() {
        // within its announcement rate
        r.on_announce(from, ann(*o, WALL, 2, 200), 10 * i as Time, WALL, |_| true);
    }
    r.tick(21_000);
    let mut outs = Vec::new();
    r.drain(&mut outs);
    assert_eq!(r.stats().announcements_limited, 0);
    let greeted = |r: &mut Router, to: SignPk, outs: &mut Vec<Out>| {
        r.drain(outs);
        let n = outs.iter().filter(|o| matches!(o, Out::Announce { to: t, .. } if *t == to)).count();
        outs.clear();
        n
    };
    // the node's order: up (and greeted), then measured
    let ble = key(3);
    r.set_direct(ble, true, 21_000);
    r.hop_up(ble, 21_000);
    r.set_cost(ble, 16_680);
    // 400 announcements, 47 kB (not 2,000, 234 kB: 6 s of a BLE link) ...
    assert_eq!(greeted(&mut r, ble, &mut outs), 400);
    assert_eq!(r.stats().announcements_deferred, 2_000 - 400);
    // ... then ~790 B/s, 6.7 a second
    r.tick(22_000);
    assert!((6..=7).contains(&greeted(&mut r, ble, &mut outs)));
    let wifi = key(4);
    let t = 21_000 + GREET_GAP;
    r.set_direct(wifi, true, t);
    r.hop_up(wifi, t);
    r.set_cost(wifi, 100);
    assert_eq!(greeted(&mut r, wifi, &mut outs), 400);
    // measured fast: 100 a second, what it accepts from us (2% of the
    // link would be ~1,100)
    r.tick(t + 1_000);
    assert_eq!(greeted(&mut r, wifi, &mut outs), 100);
}

/// Answering a seqno request is an advertisement like any other: it sets
/// our feasibility distance (Babel, RFC 8966 §3.7.3), or a costlier route
/// we accepted later could loop through the neighbour we told.
#[test]
fn a_seqno_answer_sets_the_feasibility_distance() {
    let (a, b, o) = (key(2), key(3), key(9));
    let mut r = Router::new(key(1), Config { defences: Defences::NONE, ..Config::default() });
    for n in [a, b] {
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        r.set_cost(n, 100);
    }
    r.on_announce(a, ann(o, WALL, 3, 900), 10, WALL, |_| true);
    r.tick(1_000);
    assert_eq!(r.origins[&o].fd, Some((WALL, 1_020)), "passed on to b");
    // cheaper through b, at the same seqno: not passed on again ...
    r.on_announce(b, ann(o, WALL, 1, 100), 1_100, WALL, |_| true);
    r.tick(2_000);
    let mut outs = Vec::new();
    r.drain(&mut outs);
    outs.clear();
    // ... but told to a, which asks
    r.on_seqreq(a, SeqReq { origin: o, seq: WALL, hops: 4 }, 2_100);
    r.drain(&mut outs);
    assert!(
        outs.iter().any(|x| matches!(x, Out::Announce { to, ann } if *to == a && ann.origin == o && ann.cost == 220))
    );
    assert_eq!(r.origins[&o].fd, Some((WALL, 220)));
}

/// [`Net::loops_toward`] among honest devices: a walk stops at a liar,
/// whose own lies may well send packets round (it swallows them).
fn honest_loops(net: &Net, dst: usize) -> usize {
    let d = net.k(dst);
    let mut loops = 0;
    for start in (0..net.nodes.len()).filter(|i| !net.liars.contains(i)) {
        let (mut at, mut visited) = (start, BTreeSet::new());
        while at != dst && !net.liars.contains(&at) {
            if !visited.insert(at) {
                loops += 1;
                break;
            }
            match net.nodes[at].next_hop_local(&d, net.now) {
                Some(n) => at = net.index[&n],
                None => break,
            }
        }
    }
    loops
}

/// Usable routes held down right now ([`Defences::corroborate`]).
fn held_routes(r: &Router, now: Time) -> usize {
    r.origins
        .values()
        .map(|o| o.via.iter().filter(|(n, v)| r.usable(o, n, v, now) && r.held_down(o, n, v, now).is_some()).count())
        .sum()
}

/// Loop freedom with every defence at work, through link flaps: plausible
/// liars that attract routes and swallow packets, feedback from what
/// arrived (timeouts suspect hops, acknowledgements through others get
/// them shunned), sudden shortcuts held down as liars' links come back,
/// announcements paced on Bluetooth hops, and membership tables that
/// reorder routes. Each defence's own counter must move, so the coverage
/// can't quietly go away.
#[test]
fn churn_never_loops_with_every_defence() {
    const N: usize = 30;
    let edges = geometric(N, 100.0, 30.0, 11);
    let mut net = Net::new(N, |i| Config {
        announce_every: 500,
        seed: i as u64 + 1,
        defences: Defences::ALL,
        ..Config::default()
    });
    let mut x: u64 = 7;
    let mut rnd = move |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m as u64) as usize
    };
    net.liars = [4, 13, 21].into_iter().collect();
    for i in 0..N {
        let members: Vec<(SignPk, u8)> = (0..6).map(|_| (net.k(rnd(N)), 1 + rnd(3) as u8)).collect();
        net.nodes[i].set_affinity(members);
    }
    // a quarter of the hops slow (64 KiB in 1.2 s: at this test's 500 ms
    // period their control budget is tighter than a Bluetooth hop's at the
    // real 16 s), the rest Wi-Fi
    let cost = |(a, b): (usize, usize)| if (a + b).is_multiple_of(4) { 12_000 } else { 100 };
    for e in &edges {
        net.link_cost(e.0, e.1, cost(*e));
    }
    net.run(5_000);
    let honest: Vec<usize> = (0..N).filter(|i| !net.liars.contains(i)).collect();
    // sources next to a liar, with other ways out, each messaging contacts
    // 3 hops or more away again and again
    let around = |i: usize| -> Vec<usize> {
        edges
            .iter()
            .filter_map(|&(a, b)| {
                if a == i {
                    Some(b)
                } else if b == i {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    };
    let mut sources: Vec<usize> = net
        .liars
        .iter()
        .flat_map(|l| around(*l).into_iter().filter(|s| !net.liars.contains(s) && around(*s).len() >= 3).take(2))
        .collect();
    sources.sort_unstable();
    sources.dedup();
    let contacts: Vec<Vec<usize>> = sources
        .iter()
        .map(|s| honest.iter().copied().filter(|d| net.hops(*s, *d).is_some_and(|h| h >= 3)).take(5).collect())
        .collect();
    assert!(sources.len() >= 3 && contacts.iter().all(|c| c.len() >= 4), "{sources:?}");
    let (mut route_loops, mut held, mut msg) = (0, 0, 0u64);
    let mut waiting: Vec<(usize, usize, Bytes, Time)> = vec![];
    let mut down: Vec<(usize, usize)> = vec![];
    for round in 0..240 {
        if round % 4 == 0 {
            let (a, b) = edges[rnd(edges.len())];
            if !down.contains(&(a, b)) {
                net.cut(a, b);
                down.push((a, b));
            }
        } else if round % 4 == 2 && !down.is_empty() {
            let e = down.remove(rnd(down.len()));
            net.link_cost(e.0, e.1, cost(e));
        }
        // end-to-end feedback: arrived within 300 ms, or a timeout
        let now = net.now;
        let (done, rest): (Vec<_>, Vec<_>) = waiting.into_iter().partition(|w| now >= w.3 + 300);
        waiting = rest;
        for (s, d, p, _) in done {
            let arrived = net.delivered.iter().any(|(i, _, q)| *i == d && *q == p);
            let dst = net.k(d);
            net.nodes[s].feedback(dst, arrived, now);
            net.effects(s);
        }
        for (&s, d) in sources.iter().zip(&contacts).flat_map(|(s, c)| c.iter().map(move |d| (s, *d))) {
            let (dst, me) = (net.k(d), net.k(s));
            if !net.nodes[s].is_neighbour(&dst) {
                msg += 1;
                let p = Bytes::from(msg.to_be_bytes().to_vec());
                net.nodes[s].send(dst, me, p.clone(), false, now);
                net.effects(s);
                waiting.push((s, d, p, now));
            }
        }
        for _ in 0..40 {
            net.step();
            route_loops += honest.iter().map(|d| honest_loops(&net, *d)).sum::<usize>();
        }
        held += net.nodes.iter().map(|r| held_routes(r, net.now)).sum::<usize>();
    }
    let total = |f: fn(&Stats) -> u64| net.nodes.iter().map(|r| f(&r.stats())).sum::<u64>();
    let (suspected, shunned, deferred) =
        (total(|s| s.hops_suspected), total(|s| s.hops_shunned), total(|s| s.announcements_deferred));
    eprintln!(
        "churn, every defence: {} of {msg} delivered, {} frame loops, {route_loops} route loops, \
         {suspected} suspected, {shunned} shunned, {held} held down, {deferred} deferred",
        net.delivered.len(),
        net.frame_loops
    );
    assert_eq!(net.frame_loops, 0);
    assert_eq!(route_loops, 0);
    assert!(net.delivered.len() as u64 > msg / 2);
    assert!(suspected > 0 && shunned > 0, "suspicion and aggregation at work");
    assert!(held > 0, "hold-down at work");
    assert!(deferred > 0, "control budget at work");
}

/// The defences on by default (affinity costs route length everywhere, so
/// it is opt-in), and the knobs the simulator measures them with.
#[test]
fn defences_default_and_knobs() {
    assert_eq!(Config::default().defences, Defences { affinity: false, ..Defences::ALL });
    let mut c = Config::default();
    c.tune("defences=none,affinity=on,affinity_step=10").unwrap();
    assert_eq!(c.defences, Defences { affinity: true, ..Defences::NONE });
    assert_eq!(c.affinity_step, 10);
    c.tune("defences=default").unwrap();
    assert_eq!(c.defences, Defences::DEFAULT);
    assert!(c.tune("affinity_step=far").is_err());
    assert!(c.tune("jitter=on").is_err(), "dropped defences have no knob");
}

/// Found by fuzzing (`fuzz/fuzz_targets/mesh_router.rs`): smoothing a hop
/// cost multiplied it by 7 in `u32`, which overflowed above `u32::MAX / 7`
/// (costs are in 0.1 ms units: about 61,000 s, 17 hours, per 64 KiB; the
/// driver's `mesh::hop_cost` would need round trips of about 1,100 s at the
/// minimum window to measure that). Debug builds panicked; release builds
/// wrapped to a near-zero cost, making the slowest hop the cheapest. No real
/// link gets there, but the driver can technically report up to its cap of
/// `u32::MAX / 2`. A later run found the same for a cost above that cap plus
/// the per-hop penalty: costs are now capped where the driver caps them,
/// and the penalty saturates.
#[test]
fn smoothing_a_very_slow_hop_cost_does_not_overflow() {
    let mut r = Router::new(key(1), Config::default());
    let n = key(2);
    r.set_direct(n, true, 0);
    r.hop_up(n, 0);
    let slow = u32::MAX / 2; // the driver's cap (`mesh::hop_cost`)
    r.set_cost(n, slow);
    r.set_cost(n, slow);
    assert_eq!(r.nbs[&n].cost, slow);
    r.set_cost(n, 100);
    assert!(r.nbs[&n].cost > slow / 2, "one fast sample doesn't make a slow hop cheap");
    let before = r.nbs[&n].cost;
    r.set_cost(n, u32::MAX);
    assert!(r.nbs[&n].cost > before && r.nbs[&n].cost <= slow, "capped as the driver caps it");
    assert!(r.nbs[&n].hop_cost() > r.nbs[&n].cost, "the hop penalty still adds");
    r.nbs.get_mut(&n).unwrap().cost = u32::MAX;
    assert_eq!(r.nbs[&n].hop_cost(), u32::MAX, "and saturates");
}
