//! The Mycel routing model, as a sans-IO [`Router`].
//!
//! [`Cfg::main`] models the mesh on main today (`mycel-net/src/mesh.rs`):
//! signed originator announcements flooded every 2 s with a TTL of 8,
//! rebroadcast once per sequence number after 10–50 ms of jitter, split
//! horizon, 100 announcements/s per neighbour, cost = measured hop delay +
//! 2 ms per hop, routes valid for a few periods. It never crosses the
//! internet (a mesh neighbour is a device found on a link) and has no
//! store-and-forward for strangers: a message with no route is dropped.
//!
//! [`Cfg::global`] is the stand-in for the GLOBAL routing work (until its
//! sans-IO core is wired in, see docs/SIMULATION.md): the same announcements,
//! plus
//! - gateways (devices with internet) announce their uplink, so every
//!   device knows the cost to its nearby gateways *for this message's size*
//!   (latency + size/rate per hop, store-and-forward) and picks the gateway
//!   by total cost, not distance;
//! - gateways publish reachability records ("D is reachable via me at cost
//!   c") to a directory; the sender's gateway looks D up and crosses the
//!   internet to D's best gateway, which carries it the last hops;
//! - partial routes: a message advances as far as the route goes and waits
//!   there in custody, retried on every new link and table change;
//! - gradient DTN: held messages flow, with a small copy budget, to
//!   neighbours with a lower expected delay to the internet (0 on the
//!   internet; else the cost to the best gateway; else the time since the
//!   device last had a gateway, so mules that visit gateways attract them);
//! - far-side mailboxes: D's gateway holds what arrives while D is away,
//!   and drains it when D's announcements come back;
//! - delivery receipts back to the sender;
//! - k routes: the sender also sends a copy along its second-best route.

use super::engine::{Cx, DirRecord, MS, MsgId, NodeId, Over, Router, SEC, Techs, Time};
use crate::stats::{Map, Set};

/// Reference size for routing-table costs (one QUIC packet).
const REF: u32 = 1200;
/// Added per hop (mesh.rs HOP_PENALTY: 20 × 0.1 ms).
const HOP_PENALTY: Time = 2 * MS;
const OGM_SIZE: u32 = 120;
const HDR: u32 = 64;
const RECEIPT_SIZE: u32 = 100;
const NEVER: Time = Time::MAX / 4;
/// A route this old still points the way toward a break (partial routes).
const STALE_ROUTE: Time = 30 * 60 * SEC;
/// Directory records are kept this long: an offline device's last gateway
/// keeps its mailbox.
const RECORD_TTL: Time = 24 * 60 * 60 * SEC;

/// A cost that scales with message size: `lat + size × inv`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Cost {
    /// µs of latency.
    pub lat: Time,
    /// µs per byte (sum of 1/rate over store-and-forward hops).
    pub inv: f64,
}

impl Cost {
    pub fn at(&self, size: u32) -> Time {
        self.lat + (self.inv * size as f64) as Time
    }

    fn plus(&self, o: Cost) -> Cost {
        Cost { lat: self.lat + o.lat, inv: self.inv + o.inv }
    }
}

/// An adversary's behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Role {
    #[default]
    Honest,
    /// Claims zero-cost routes to everyone, then drops what it gets.
    BlackHole,
    /// A black hole that lies plausibly: claims to be one hop from everyone
    /// at the least cost an honest relay could report, then drops what it
    /// gets, packets and store-and-forward bundles alike (tier-2 GLOBAL core
    /// only).
    Liar,
    /// A liar that extends the cheapest chain it was sent, by one hop and
    /// the least cost an honest hop adds (2.1 ms), understating only its
    /// own link, and drops everything (tier-2 GLOBAL core only). Without
    /// attestations it can say anything, this included; it is the most a
    /// signed per-hop chain *without* cost binding would let it say. With
    /// the attested router (`attest=on`) it signs its own hop over that lie,
    /// and honest devices refuse the chain (its upstream signed a costlier
    /// link) and distrust it (docs/SIMULATION.md §4, open 15).
    ChainLiar,
    /// A liar held to cost-bound attestations (the attested router): it
    /// advertises the least its chain allows, its upstream's cost plus the
    /// link that upstream measured to it, signs the least link to the
    /// receiver (who takes the costlier end), and drops everything. On the
    /// simulator's symmetric links that is what an honest relay says, so it
    /// is an honest dropper with the router's real chains (tier-2 GLOBAL
    /// core only).
    AttestedLiar,
    /// Announces honestly and drops everything (packets and bundles): all
    /// that is left of a liar once announcements can't lie at all (route
    /// attestations that also carry each upstream's measured cost to the
    /// next hop, so not even its own link can be understated). The real
    /// world's "believable liar": a relay that truly is close, and drops.
    Dropper,
    /// A grey hole: announces honestly, and drops half of the messages it
    /// relays, chosen per message ([`Role::swallows`]: every packet and
    /// acknowledgement of a chosen message, and its bundle), forwarding
    /// the rest. Some traffic through it is acknowledged, so the
    /// end-to-end defence sees mixed evidence (tier-2 GLOBAL core only).
    GreyHole,
    /// Announces every 10 ms.
    Storm,
    /// Re-sends announcements it heard long ago.
    Replayer,
}

impl Role {
    /// It rewrites attested announcements it sends, signing its own hop
    /// over the lie (so its core sends every chain whole,
    /// `Config::chain_reuse` off).
    pub fn signs_lies(self) -> bool {
        matches!(self, Role::ChainLiar | Role::AttestedLiar)
    }

    /// It drops what it is given to relay (packets, and with the GLOBAL
    /// core bundles too).
    pub fn drops(self) -> bool {
        matches!(
            self,
            Role::BlackHole | Role::Liar | Role::ChainLiar | Role::AttestedLiar | Role::Dropper | Role::GreyHole
        )
    }

    /// It drops traffic of message `msg` that it relays (`None`: traffic
    /// that belongs to no message). A [`Role::GreyHole`] drops the half of
    /// messages whose id hashes odd (Fibonacci hashing, so neighbouring ids
    /// don't alternate); every other dropper, everything.
    pub fn swallows(self, msg: Option<u32>) -> bool {
        match self {
            Role::GreyHole => msg.is_some_and(|m| m.wrapping_mul(0x9e37_79b1) >> 31 == 1),
            r => r.drops(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cfg {
    pub name: &'static str,
    pub ogm_every: Time,
    pub ttl: u8,
    /// Announcements accepted per neighbour per second.
    pub ogm_rate: f64,
    pub use_internet: bool,
    pub custody: bool,
    pub gradient: bool,
    /// Copy budget for gradient DTN.
    pub copies: u8,
    pub mailbox: bool,
    pub receipts: bool,
    /// Routes used at the sender (1 = best only, 2 = also the second best).
    pub k_routes: usize,
    /// Baseline: the sender holds a message until a complete route exists;
    /// nobody else stores it.
    pub sender_holds: bool,
    pub record_every: Time,
    /// Retry held messages this often.
    pub retry_every: Time,
}

impl Cfg {
    /// Today's mesh on main.
    pub fn main() -> Cfg {
        Cfg {
            name: "main (mesh.rs today)",
            ogm_every: 2 * SEC,
            ttl: 8,
            ogm_rate: 100.0,
            use_internet: false,
            custody: false,
            gradient: false,
            copies: 1,
            mailbox: false,
            receipts: false,
            k_routes: 1,
            sender_holds: false,
            record_every: 30 * SEC,
            retry_every: SEC,
        }
    }

    /// The stand-in for GLOBAL: gateways, total-cost choice, custody,
    /// gradient DTN, mailboxes, receipts, 2 routes.
    pub fn global() -> Cfg {
        Cfg {
            name: "global (stand-in model)",
            use_internet: true,
            custody: true,
            gradient: true,
            copies: 4,
            mailbox: true,
            receipts: true,
            k_routes: 2,
            ..Cfg::main()
        }
    }

    /// Baseline for partial routes: the sender waits for a whole route.
    pub fn sender_holds() -> Cfg {
        Cfg { name: "sender holds until a route", custody: false, gradient: false, sender_holds: true, ..Cfg::global() }
    }

    /// For 100k devices: slower announcements, smaller scope.
    pub fn scaled(mut self, ogm_every: Time, ttl: u8) -> Cfg {
        self.ogm_every = ogm_every;
        self.ttl = ttl;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Toward `dst` (or a gateway) over the mesh.
    Mesh,
    /// Crossed the internet: at or toward the destination's gateway.
    FarSide,
}

#[derive(Clone, Debug)]
pub struct Data {
    msg: MsgId,
    src: NodeId,
    dst: NodeId,
    size: u32,
    ttl: u8,
    stage: Stage,
    /// Copy tokens (gradient DTN).
    copies: u8,
    receipt: bool,
}

#[derive(Clone, Debug)]
pub enum Frame {
    Ogm { origin: NodeId, seq: u32, hops: u8, cost: Cost, gw: Option<Cost>, gc: Time, li: Option<Time> },
    Data(Data),
}

#[derive(Clone, Copy, Debug)]
struct Route {
    seq: u32,
    cost: Cost,
    via: NodeId,
    hops: u8,
    /// The origin is a gateway with this uplink cost.
    gw: Option<Cost>,
    at: Time,
    rebroadcast: u32,
    alt: Option<(NodeId, Cost)>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Nb {
    hop: Cost,
    /// Its cost to a gateway it has a route to, as it last said.
    gc: Time,
    /// The last time it (or anyone it heard from) had a way to the internet.
    li: Option<Time>,
    window: Time,
    count: f64,
}

/// Counters for the scenario reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct MycelStats {
    pub ogm_limited: u64,
    pub ogm_stale: u64,
    pub dropped_no_route: u64,
    pub dropped_ttl: u64,
    pub dropped_blackhole: u64,
    pub held: u64,
    pub mailbox_drained: u64,
}

pub struct Mycel {
    cfg: std::rc::Rc<Cfg>,
    role: Role,
    me: NodeId,
    seq: u32,
    table: Map<NodeId, Route>,
    nbrs: Map<NodeId, Nb>,
    store: Vec<Data>,
    seen: Set<(MsgId, bool)>,
    given: Set<(MsgId, NodeId)>,
    /// dst → (its gateway, when looked up)
    dircache: Map<NodeId, (NodeId, Time)>,
    lookups: Map<NodeId, Vec<Data>>,
    /// The freshest time this device knows of a way to the internet
    /// (its own, or heard from neighbours: timestamps can't count to infinity).
    li: Option<Time>,
    old_ogms: Vec<Frame>,
    /// Who handed us each message (don't send it straight back).
    came_from: Map<MsgId, NodeId>,
    pub stats: MycelStats,
}

const T_OGM: u64 = 1 << 40;
const T_REBROADCAST: u64 = 2 << 40;
const T_RETRY: u64 = 3 << 40;
const T_RECORDS: u64 = 4 << 40;
const T_LOOKUP: u64 = 5 << 40;

impl Mycel {
    pub fn new(me: NodeId, cfg: std::rc::Rc<Cfg>, role: Role) -> Mycel {
        Mycel {
            cfg,
            role,
            me,
            seq: 0,
            table: Map::default(),
            nbrs: Map::default(),
            store: Vec::new(),
            seen: Set::default(),
            given: Set::default(),
            dircache: Map::default(),
            lookups: Map::default(),
            li: None,
            old_ogms: Vec::new(),
            came_from: Map::default(),
            stats: MycelStats::default(),
        }
    }

    /// Messages held here (custody, mailbox): (message, copies).
    pub fn held(&self) -> Vec<(MsgId, u8)> {
        self.store.iter().map(|d| (d.msg, d.copies)).collect()
    }

    /// The neighbour this device would send `dst`'s traffic to now.
    pub fn next_hop(&self, dst: NodeId, now: Time) -> Option<NodeId> {
        self.fresh(dst, now).map(|r| r.via)
    }

    pub fn routes(&self) -> usize {
        self.table.len()
    }

    pub fn has_route(&self, dst: NodeId, now: Time) -> bool {
        self.fresh(dst, now).is_some()
    }

    fn valid_for(&self) -> Time {
        3 * self.cfg.ogm_every + SEC
    }

    fn fresh(&self, dst: NodeId, now: Time) -> Option<&Route> {
        self.table.get(&dst).filter(|r| now.saturating_sub(r.at) <= self.valid_for() && self.nbrs.contains_key(&r.via))
    }

    fn hop_cost(techs: Techs) -> Cost {
        let t = techs.best(REF).expect("a radio");
        Cost { lat: t.latency().as_micros() as Time + HOP_PENALTY, inv: 1e6 / t.rate() as f64 }
    }

    fn uplink_cost(cx: &Cx<Frame>) -> Option<Cost> {
        cx.access().map(|a| Cost { lat: a.latency().as_micros() as Time, inv: 1e6 / a.uplink() as f64 })
    }

    /// Cost to the internet through a gateway this device has a route to
    /// (0 on the internet), or NEVER.
    fn gc(&self, cx: &Cx<Frame>) -> Time {
        if cx.has_inet() {
            return 0;
        }
        let now = cx.now();
        self.table
            .iter()
            .filter(|(d, r)| r.gw.is_some() && self.fresh(**d, now).is_some())
            .map(|(_, r)| r.cost.plus(r.gw.unwrap_or_default()).at(REF))
            .min()
            .unwrap_or(NEVER)
    }

    /// Note a way to the internet now, if there is one.
    fn touch_li(&mut self, cx: &Cx<Frame>) {
        if self.gc(cx) < NEVER {
            self.li = Some(cx.now());
        }
    }

    /// Expected delay to the internet (the DTN gradient): the gateway cost
    /// if there's a route, else how long ago the last known way out was.
    fn metric(gc: Time, li: Option<Time>, now: Time) -> Time {
        if gc < NEVER { gc } else { li.map_or(NEVER, |t| now.saturating_sub(t) + 10 * SEC) }
    }

    fn send_ogm_all(&mut self, cx: &mut Cx<Frame>, f: &Frame, except: Option<NodeId>) {
        for (nb, _) in cx.neighbours() {
            if Some(nb) != except {
                cx.send_radio(nb, f.clone(), OGM_SIZE, true, None);
            }
        }
    }

    fn originate(&mut self, cx: &mut Cx<Frame>) {
        if !cx.online() {
            return;
        }
        self.seq += 1;
        let gw = if self.cfg.use_internet && cx.has_inet() { Self::uplink_cost(cx) } else { None };
        self.touch_li(cx);
        let f = Frame::Ogm {
            origin: self.me,
            seq: self.seq,
            hops: 0,
            cost: Cost::default(),
            gw,
            gc: self.gc(cx),
            li: self.li,
        };
        self.send_ogm_all(cx, &f, None);
        if self.role == Role::Replayer && self.old_ogms.len() > 20 {
            let old: Vec<Frame> = self.old_ogms.drain(..10).collect();
            for f in old {
                self.send_ogm_all(cx, &f, None);
            }
        }
    }

    fn on_ogm(&mut self, cx: &mut Cx<Frame>, from: NodeId, f: Frame) {
        let Frame::Ogm { origin, seq, hops, cost, gw, gc, li } = f.clone() else { return };
        let now = cx.now();
        // per-neighbour rate limit
        let rate = self.cfg.ogm_rate;
        let Some(nb) = self.nbrs.get_mut(&from) else { return };
        if now.saturating_sub(nb.window) >= SEC {
            nb.window = now;
            nb.count = 0.0;
        }
        nb.count += 1.0;
        if nb.count > rate {
            self.stats.ogm_limited += 1;
            return;
        }
        nb.gc = gc;
        nb.li = li;
        let hop = nb.hop;
        if li > self.li {
            self.li = li;
        }
        if self.role == Role::Replayer && self.old_ogms.len() < 200 {
            self.old_ogms.push(f);
        }
        if origin == self.me {
            return;
        }
        if gw.is_some() {
            self.li = Some(now);
        }
        let c = cost.plus(hop);
        let hops = hops.saturating_add(1);
        let ttl = self.cfg.ttl;
        match self.table.get_mut(&origin) {
            Some(r) if seq < r.seq => {
                self.stats.ogm_stale += 1;
                return;
            }
            Some(r) if seq == r.seq => {
                if c.at(REF) < r.cost.at(REF) {
                    if r.via != from {
                        r.alt = Some((r.via, r.cost));
                    }
                    r.via = from;
                    r.cost = c;
                    r.hops = hops;
                } else if r.via != from && r.alt.is_none_or(|a| c.at(REF) < a.1.at(REF)) {
                    r.alt = Some((from, c));
                }
                return;
            }
            Some(r) => {
                let alt = if r.via != from { Some((r.via, r.cost)) } else { r.alt };
                *r = Route { seq, cost: c, via: from, hops, gw, at: now, rebroadcast: r.rebroadcast, alt };
            }
            None => {
                self.table
                    .insert(origin, Route { seq, cost: c, via: from, hops, gw, at: now, rebroadcast: 0, alt: None });
            }
        }
        if hops < ttl {
            let j = 10 * MS + (cx.rng().f64() * 40.0 * MS as f64) as Time;
            cx.set_timer(j, T_REBROADCAST | origin as u64);
        }
        // someone we hold messages for (or a way out) may be reachable now
        if gw.is_some() || self.store.iter().any(|d| d.dst == origin) {
            self.retry(cx);
        }
    }

    fn rebroadcast(&mut self, cx: &mut Cx<Frame>, origin: NodeId) {
        self.touch_li(cx);
        let (gc, li) = (self.gc(cx), self.li);
        let Some(r) = self.table.get_mut(&origin) else { return };
        if r.rebroadcast == r.seq {
            return;
        }
        r.rebroadcast = r.seq;
        let cost = if self.role == Role::BlackHole { Cost::default() } else { r.cost };
        let f = Frame::Ogm { origin, seq: r.seq, hops: r.hops, cost, gw: r.gw, gc, li };
        let via = r.via;
        self.send_ogm_all(cx, &f, Some(via));
    }

    /// Hand a message on, or keep it.
    fn route(&mut self, cx: &mut Cx<Frame>, mut d: Data, at_source: bool) {
        let now = cx.now();
        if d.dst == self.me {
            cx.delivered(d.msg);
            if d.receipt {
                cx.receipt(d.msg);
            } else if self.cfg.receipts || cx.msg(d.msg).echo {
                let r = Data {
                    msg: d.msg,
                    src: self.me,
                    dst: d.src,
                    size: RECEIPT_SIZE,
                    ttl: 32,
                    stage: Stage::Mesh,
                    copies: 1,
                    receipt: true,
                };
                self.route(cx, r, true);
            }
            return;
        }
        if self.role == Role::BlackHole && !at_source {
            self.stats.dropped_blackhole += 1;
            return;
        }
        if d.ttl == 0 {
            self.stats.dropped_ttl += 1;
            return;
        }
        // 1. a mesh route to the destination
        if let Some(r) = self.fresh(d.dst, now).copied() {
            d.ttl -= 1;
            let via = r.via;
            let size = d.size + HDR;
            let control = d.receipt;
            cx.send_radio(via, Frame::Data(d.clone()), size, control, Some(d.msg));
            if at_source
                && self.cfg.k_routes > 1
                && !d.receipt
                && let Some((alt, _)) = r.alt
                && alt != via
                && self.nbrs.contains_key(&alt)
            {
                cx.copied(d.msg);
                cx.send_radio(alt, Frame::Data(d), size, control, None);
            }
            return;
        }
        // 1b. partial route: follow the last known route as far as it goes
        if self.cfg.custody
            && d.stage == Stage::Mesh
            && let Some(r) = self.table.get(&d.dst).copied()
            && now.saturating_sub(r.at) <= STALE_ROUTE
            && self.nbrs.contains_key(&r.via)
            && self.came_from.get(&d.msg).is_none_or(|f| *f != r.via)
        {
            d.ttl -= 1;
            let size = d.size + HDR;
            let control = d.receipt;
            cx.send_radio(r.via, Frame::Data(d.clone()), size, control, Some(d.msg));
            return;
        }
        if self.cfg.use_internet {
            // 2. we're on the internet: cross it to the destination's gateway
            if cx.has_inet() {
                if d.stage == Stage::FarSide {
                    // we are its gateway and don't see it now: mailbox
                    return self.hold(cx, d);
                }
                if let Some(&(gw, at)) = self.dircache.get(&d.dst)
                    && now - at < 3 * self.cfg.record_every
                    && gw != self.me
                {
                    d.stage = Stage::FarSide;
                    let size = d.size + HDR;
                    let control = d.receipt;
                    cx.send_inet(gw, Frame::Data(d.clone()), size, control, Some(d.msg));
                    return;
                }
                let first = !self.lookups.contains_key(&d.dst);
                self.lookups.entry(d.dst).or_default().push(d.clone());
                if first {
                    cx.dir_get(d.dst, T_LOOKUP | d.dst as u64);
                }
                return;
            }
            // 3. toward the gateway with the lowest total cost for this size
            if d.stage == Stage::Mesh
                && let Some(gw) = self.best_gateway(now, d.size + HDR)
                && !(self.cfg.sender_holds && at_source && !self.far_side_known(d.dst, now))
            {
                let via = self.table[&gw].via;
                d.ttl -= 1;
                let size = d.size + HDR;
                let control = d.receipt;
                cx.send_radio(via, Frame::Data(d.clone()), size, control, Some(d.msg));
                return;
            }
        }
        // 4. no way on now
        if (self.cfg.custody || d.stage == Stage::FarSide && self.cfg.mailbox) || (self.cfg.sender_holds && at_source) {
            self.hold(cx, d);
        } else {
            self.stats.dropped_no_route += 1;
        }
    }

    /// Whether the far side looks reachable (sender-holds baseline): a
    /// fresh directory answer for `dst`, or none needed.
    fn far_side_known(&self, dst: NodeId, now: Time) -> bool {
        self.dircache.get(&dst).is_some_and(|(_, at)| now - at < self.cfg.record_every)
    }

    fn best_gateway(&self, now: Time, size: u32) -> Option<NodeId> {
        self.table
            .iter()
            .filter(|(d, r)| r.gw.is_some() && self.fresh(**d, now).is_some())
            .min_by_key(|(_, r)| r.cost.plus(r.gw.unwrap_or_default()).at(size))
            .map(|(d, _)| *d)
    }

    fn hold(&mut self, cx: &mut Cx<Frame>, d: Data) {
        self.stats.held += 1;
        if self.store.iter().any(|x| x.msg == d.msg && x.receipt == d.receipt) {
            return;
        }
        let first = self.store.is_empty();
        self.store.push(d);
        cx.note_stored(self.store.len());
        if first {
            let every = self.cfg.retry_every;
            cx.set_timer(every, T_RETRY);
        }
    }

    /// Try every held message again; spread DTN copies down the gradient.
    fn retry(&mut self, cx: &mut Cx<Frame>) {
        if !cx.online() {
            return;
        }
        let now = cx.now();
        let held = std::mem::take(&mut self.store);
        for d in held {
            let mailbox = d.stage == Stage::FarSide;
            let routable = self.fresh(d.dst, now).is_some()
                || (self.cfg.use_internet && !mailbox && (cx.has_inet() || self.best_gateway(now, d.size).is_some()));
            let holds_ok = !self.cfg.sender_holds
                || d.src != self.me
                || self.fresh(d.dst, now).is_some()
                || self.far_side_known(d.dst, now)
                || cx.has_inet();
            if routable && holds_ok {
                if mailbox && self.fresh(d.dst, now).is_some() {
                    self.stats.mailbox_drained += 1;
                }
                let src = d.src == self.me;
                self.route(cx, d, src);
                continue;
            }
            if mailbox && cx.has_inet() {
                // re-look up: the destination may be behind another gateway now
                if let Some(&(gw, at)) = self.dircache.get(&d.dst)
                    && gw != self.me
                    && now - at < self.cfg.record_every
                {
                    let size = d.size + HDR;
                    let control = d.receipt;
                    cx.send_inet(gw, Frame::Data(d.clone()), size, control, Some(d.msg));
                    continue;
                }
            }
            let mut d = d;
            if self.cfg.gradient && !mailbox {
                self.touch_li(cx);
                let mine = Self::metric(self.gc(cx), self.li, now);
                for (nb, techs) in cx.neighbours() {
                    if d.copies == 0 {
                        break;
                    }
                    let Some(n) = self.nbrs.get(&nb) else { continue };
                    let m = Self::metric(n.gc, n.li, now);
                    let theirs = m.saturating_add(Self::hop_cost(techs).at(d.size));
                    if m >= NEVER || theirs >= mine.saturating_mul(9) / 10 || self.given.contains(&(d.msg, nb)) {
                        continue;
                    }
                    self.given.insert((d.msg, nb));
                    let give = if d.copies > 1 { d.copies / 2 } else { 1 };
                    let mut c = d.clone();
                    c.copies = give;
                    let size = c.size + HDR;
                    let control = c.receipt;
                    // handing on the last copy moves it; only a split makes one
                    if d.copies > 1 {
                        cx.copied(d.msg);
                    }
                    cx.handed(d.msg);
                    cx.send_radio(nb, Frame::Data(c), size, control, Some(d.msg));
                    d.copies -= give;
                }
                if d.copies == 0 {
                    continue; // custody handed on
                }
            }
            self.store.push(d);
        }
        if !self.store.is_empty() {
            let every = self.cfg.retry_every;
            cx.set_timer(every, T_RETRY);
        }
    }

    fn publish_records(&mut self, cx: &mut Cx<Frame>) {
        if !cx.has_inet() {
            return;
        }
        let now = cx.now();
        cx.dir_put(DirRecord { subject: self.me, gateway: self.me, cost: 0, at: now });
        let subjects: Vec<(NodeId, Time)> = self
            .table
            .iter()
            .filter(|(d, r)| r.gw.is_none() && self.fresh(**d, now).is_some())
            .map(|(d, r)| (*d, r.cost.at(REF)))
            .collect();
        for (s, c) in subjects {
            cx.dir_put(DirRecord { subject: s, gateway: self.me, cost: c, at: now });
        }
    }
}

impl Router for Mycel {
    type Frame = Frame;

    fn size(f: &Frame) -> u32 {
        match f {
            Frame::Ogm { .. } => OGM_SIZE,
            Frame::Data(d) => d.size + HDR,
        }
    }

    fn is_control(f: &Frame) -> bool {
        matches!(f, Frame::Ogm { .. }) || matches!(f, Frame::Data(d) if d.receipt)
    }

    fn msg_of(f: &Frame) -> Option<MsgId> {
        match f {
            Frame::Data(d) => Some(d.msg),
            _ => None,
        }
    }

    fn on_start(&mut self, cx: &mut Cx<Frame>) {
        let every = if self.role == Role::Storm { 10 * MS } else { self.cfg.ogm_every };
        let j = (cx.rng().f64() * every as f64) as Time;
        cx.set_timer(j + 1, T_OGM);
        if self.cfg.use_internet && cx.has_inet() {
            self.li = Some(0);
            let r = (cx.rng().f64() * self.cfg.record_every as f64) as Time;
            cx.set_timer(self.cfg.ogm_every * 2 + r, T_RECORDS);
        }
    }

    fn on_link(&mut self, cx: &mut Cx<Frame>, nb: NodeId, techs: Techs, up: bool) {
        if up {
            let e = self.nbrs.entry(nb).or_insert(Nb { gc: NEVER, ..Nb::default() });
            e.hop = Self::hop_cost(techs);
            if !self.store.is_empty() {
                self.retry(cx);
            }
        } else {
            self.nbrs.remove(&nb);
        }
    }

    fn on_inet(&mut self, cx: &mut Cx<Frame>, up: bool) {
        if up {
            self.li = Some(cx.now());
            if !self.store.is_empty() {
                self.retry(cx);
            }
        }
    }

    fn on_frame(&mut self, cx: &mut Cx<Frame>, from: NodeId, _over: Over, f: Frame) {
        if !cx.online() {
            return;
        }
        match f {
            Frame::Ogm { .. } => self.on_ogm(cx, from, f),
            Frame::Data(d) => {
                if !self.seen.insert((d.msg, d.receipt)) && d.dst != self.me {
                    return;
                }
                if !d.receipt {
                    self.came_from.insert(d.msg, from);
                }
                self.route(cx, d, false);
            }
        }
    }

    fn on_timer(&mut self, cx: &mut Cx<Frame>, token: u64) {
        let kind = token & !((1 << 40) - 1);
        let arg = (token & ((1 << 40) - 1)) as NodeId;
        match kind {
            T_OGM => {
                self.originate(cx);
                let every = if self.role == Role::Storm { 10 * MS } else { self.cfg.ogm_every };
                let j = (cx.rng().f64() * every as f64 * 0.1) as Time;
                cx.set_timer(every - every / 20 + j, T_OGM);
            }
            T_REBROADCAST => self.rebroadcast(cx, arg),
            T_RETRY => self.retry(cx),
            T_RECORDS => {
                self.publish_records(cx);
                let every = self.cfg.record_every;
                cx.set_timer(every, T_RECORDS);
            }
            _ => {}
        }
    }

    fn on_send(&mut self, cx: &mut Cx<Frame>, msg: MsgId, dst: NodeId, size: u32) {
        let d =
            Data { msg, src: self.me, dst, size, ttl: 32, stage: Stage::Mesh, copies: self.cfg.copies, receipt: false };
        cx.copied(msg);
        self.seen.insert((msg, false));
        self.route(cx, d, true);
    }

    fn on_dir(&mut self, cx: &mut Cx<Frame>, token: u64, recs: Vec<DirRecord>) {
        let dst = (token & ((1 << 40) - 1)) as NodeId;
        let now = cx.now();
        let waiting = self.lookups.remove(&dst).unwrap_or_default();
        // live records (refreshed lately) cheapest first, then the last
        // gateway of a device that went away (its mailbox)
        let live = 3 * self.cfg.record_every;
        let mut recs: Vec<DirRecord> =
            recs.into_iter().filter(|r| r.gateway != self.me && now.saturating_sub(r.at) <= RECORD_TTL).collect();
        recs.sort_by_key(|r| (now.saturating_sub(r.at) > live, r.cost, std::cmp::Reverse(r.at)));
        let Some(best) = recs.first().copied() else {
            for d in waiting {
                if self.cfg.mailbox || self.cfg.custody || self.cfg.sender_holds {
                    self.hold(cx, d);
                }
            }
            return;
        };
        self.dircache.insert(dst, (best.gateway, now));
        let second = recs.iter().find(|r| r.gateway != best.gateway).copied();
        for mut d in waiting {
            d.stage = Stage::FarSide;
            let size = d.size + HDR;
            let control = d.receipt;
            cx.send_inet(best.gateway, Frame::Data(d.clone()), size, control, Some(d.msg));
            if self.cfg.k_routes > 1
                && let Some(s) = second
            {
                cx.copied(d.msg);
                cx.send_inet(s.gateway, Frame::Data(d), size, control, None);
            }
        }
    }

    fn on_online(&mut self, cx: &mut Cx<Frame>, online: bool) {
        if online && !self.store.is_empty() {
            self.retry(cx);
        }
    }

    fn on_undelivered(&mut self, cx: &mut Cx<Frame>, _to: NodeId, f: Frame) {
        // custody isn't handed over until the next hop has it: take it back
        if let Frame::Data(d) = f
            && (self.cfg.custody || self.cfg.mailbox)
        {
            self.hold(cx, d);
        }
    }
}
