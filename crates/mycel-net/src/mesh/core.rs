//! The mesh router as a pure state machine: no I/O, no clock, no tokio, no
//! cryptography. Every input carries the time; every effect comes back as an
//! [`Out`] for the caller to carry out. The real driver (`mesh/mod.rs`) wraps
//! it around QUIC hop connections; a simulator can drive 100k of them with a
//! virtual clock and stubbed signatures, deterministically (the only
//! randomness is a seeded xorshift, the maps hash with FNV).
//!
//! # What it does
//!
//! - **Local routes** (B.A.T.M.A.N.-style originator messages): every device
//!   floods a signed [`Announce`] to its *direct* neighbours (a link or the
//!   LAN); each device rebroadcasts the best copy of each sequence number
//!   once, after a short jitter, adding the hop's measured cost, never back
//!   where it came from. A route to X leaves through the neighbour that
//!   delivered X's cheapest fresh announcement; up to `routes` of them
//!   (through distinct neighbours) are offered to QUIC as separate paths.
//! - **Gateways**: a device with the internet that relays for others sets
//!   [`F_GATEWAY`] in its (signed) announcements. A device *without* the
//!   internet keeps a **default route**: traffic for anyone it has no route
//!   to goes to its nearest gateway. It also picks up to `gateways` of them
//!   and asks the driver to publish a *reachability record* ("reach me via
//!   G1, G2") in a global directory ([`Out::PublishReach`]).
//! - **Internet hops**: a device with the internet resolves unknown targets
//!   ([`Out::Resolve`] → [`Router::on_resolved`]): a target behind gateways is
//!   reached by dialing one of them ([`Out::Dial`]), anyone else directly.
//!   Frames wait (bounded) while that happens. Internet hops carry no
//!   announcements (meshes don't merge across the internet) and are hung up
//!   when idle. A gateway never relays internet → internet.
//! - **Budgets**: transit is capped per neighbour and in total, traffic
//!   crossing between the internet and the mesh separately; announcements
//!   are rate-limited per neighbour.
//!
//! # API (for drivers and simulators)
//!
//! ```text
//! Router::new(me, Config) -> Router
//!   inputs                                         (all take `now: Time`, ms)
//!   set_internet(bool)            this device can reach the wider world
//!   set_direct(peer, bool, now)   peer is (not) in direct range (link / LAN)
//!   hop_up(peer, now)             a hop connection to peer is up (direct or internet)
//!   hop_down(peer, now)           ... is gone
//!   dial_failed(peer, now)        an Out::Dial didn't work
//!   set_cost(peer, units)         measured hop cost, 0.1 ms units (smoothed RTT)
//!   announce_due(now) -> bool     time to originate: then
//!     originate(Announce, now)      with seq = next_seq(wall), flags = own_flags(),
//!                                   signed by the caller
//!   on_announce(from, Announce, now, wall, verify)   verify: FnOnce(&Announce) -> bool,
//!                                   called only for unseen (origin, seq) pairs
//!   send(dst, waypoint, payload, control, now)       a packet of ours
//!   on_frame(from, Frame, now)    a frame from a neighbour
//!   on_resolved(target, Option<Vec<gateway>>, now)   answer to Out::Resolve
//!   admit_record(origin, now) -> bool                a gateway may publish this record
//!   tick(now)                     every ~20 ms: rebroadcasts, expiry, route
//!                                 changes, gateway choice, idle hang-ups
//!   drain(&mut Vec<Out>)          take the effects (in order)
//!   queries: route_info, reachable, gateways, my_gateways, next_hop_local,
//!            is_neighbour, neighbours, origin_name, stats
//! ```
//!
//! A frame is `(dst, src, waypoint)` plus a TTL: it travels toward the
//! waypoint (the source's choice of first relay or gateway, which is what
//! makes each route a distinct QUIC path), then toward `dst`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use bytes::Bytes;
use mycel_crypto::{Sig, SignPk};

/// Milliseconds on a monotonic clock (virtual in a simulator).
pub type Time = u64;

/// Announcement flag: this device relays between the mesh and the internet.
pub const F_GATEWAY: u8 = 1;

/// Cost units are 0.1 ms; each hop adds this on top of its RTT, so among
/// equally fast routes the shorter wins.
pub const HOP_PENALTY: u32 = 20;
/// A neighbour's hop cost before its RTT is measured.
pub const DEFAULT_COST: u32 = 100;
/// Routes much costlier than the best one aren't worth a QUIC path.
const ROUTE_COST_FACTOR: u32 = 4;
const ROUTE_COST_SLACK: u32 = 300;
/// A route already in use counts as this much cheaper (no flapping).
const STICKY_PERCENT: u32 = 80;
/// Each neighbour may send us this many announcements per second (burst 4×).
const OGM_RATE: f64 = 100.0;
/// Announcements more than this far from our wall clock are ignored (replays).
pub const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
const REASM_TIMEOUT: Time = 2_000;
const REASM_MAX: usize = 256;
const VERIFIED_MAX: usize = 4096;
/// Frames waiting for a lookup or an internet dial: per key, keys, and how long.
const PENDING_FRAMES: usize = 32;
const PENDING_KEYS: usize = 256;
const PENDING_TIMEOUT: Time = 8_000;
/// How long a looked-up record (or the absence of one) is trusted.
const REACH_TTL: Time = 60_000;
const NO_RECORD_TTL: Time = 20_000;
/// An internet hop nobody used for this long is hung up.
pub const INTERNET_IDLE: Time = 60_000;
/// A dial that hasn't come back after this long has failed.
const DIAL_GIVE_UP: Time = 15_000;
/// A mesh-only device republishes its record this often (and when its
/// gateways change, at most every [`REACH_MIN_GAP`]).
pub const REACH_REFRESH: Time = 10 * 60_000;
const REACH_MIN_GAP: Time = 5_000;
/// A gateway publishes one origin's record at most this often.
pub const RECORD_MIN_GAP: Time = 10_000;

/// FNV-1a: deterministic iteration order (a simulator replays exactly).
#[derive(Default, Clone, Copy)]
pub struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 { 0xcbf2_9ce4_8422_2325 } else { self.0 };
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        self.0 = h;
    }
}

pub type Map<K, V> = HashMap<K, V, BuildHasherDefault<Fnv>>;
type Set<K> = HashSet<K, BuildHasherDefault<Fnv>>;

/// How a device takes part.
#[derive(Clone, Debug)]
pub struct Config {
    /// Forward other devices' traffic (it stays unreadable to us).
    pub relay: bool,
    /// Bytes per second relayed for traffic arriving from one neighbour.
    pub relay_rate_per_neighbour: u64,
    /// Bytes per second relayed in total.
    pub relay_rate_total: u64,
    /// Routes (QUIC paths, through distinct neighbours) kept per destination.
    pub routes: usize,
    /// Hops a frame or an announcement may travel.
    pub max_hops: u8,
    /// How often this device announces itself (ms).
    pub announce_every: Time,
    /// With the internet: relay between it and the mesh for others.
    pub gateway: bool,
    /// Bytes per second crossing between the internet and the mesh.
    pub gateway_rate: u64,
    /// Without the internet: gateways to publish in our record (1–3).
    pub gateways: usize,
    /// Internet hop connections open at once.
    pub max_internet_hops: usize,
    /// Reachability records a gateway publishes for others.
    pub max_records: usize,
    /// Seed for jitter (deterministic simulations).
    pub seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            relay: true,
            relay_rate_per_neighbour: 1 << 20,
            relay_rate_total: 4 << 20,
            routes: 3,
            max_hops: 8,
            announce_every: 2_000,
            gateway: true,
            gateway_rate: 2 << 20,
            gateways: 2,
            max_internet_hops: 256,
            max_records: 1024,
            seed: 0x6d79_6365_6c21,
        }
    }
}

/// An originator announcement. `origin`, `seq`, `flags` and `name` are
/// signed by the origin; `hops` and `cost` are filled in on the way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    pub hops: u8,
    pub cost: u32,
    pub origin: SignPk,
    pub seq: u64,
    pub flags: u8,
    pub name: Arc<str>,
    pub sig: Sig,
}

/// One packet (or a fragment of one) on its way to `dst`.
#[derive(Clone, Debug)]
pub struct Frame {
    pub ttl: u8,
    /// The waypoint has been passed; now heading for `dst`.
    pub reached: bool,
    /// For the router at `dst` (e.g. a record to publish), not for QUIC.
    pub control: bool,
    pub dst: SignPk,
    pub src: SignPk,
    pub waypoint: SignPk,
    /// Per-source packet number (fragments share it).
    pub id: u32,
    /// Where `payload` starts in the whole packet, and the packet's length.
    pub offset: u16,
    pub total: u16,
    pub payload: Bytes,
}

/// Something for the driver to do.
#[derive(Clone, Debug)]
pub enum Out {
    /// Send `ann` to neighbour `to`.
    Announce { to: SignPk, ann: Announce },
    /// Send `frame` to neighbour `to`. `relayed`: transit for others.
    Frame { to: SignPk, frame: Frame, relayed: bool },
    /// A whole QUIC packet for us, from `src` (answer via `waypoint`).
    Deliver { src: SignPk, waypoint: SignPk, payload: Bytes },
    /// A whole control message for us.
    Control { from: SignPk, payload: Bytes },
    /// Open an internet hop connection to `peer` (then `hop_up` or `dial_failed`).
    Dial(SignPk),
    /// Close the idle internet hop to `peer` (then `hop_down`).
    Hangup(SignPk),
    /// Look up `peer`'s reachability record (then `on_resolved`).
    Resolve(SignPk),
    /// We have no internet: publish a record naming these gateways.
    PublishReach { gateways: Vec<SignPk> },
    /// A mesh route to `dst` leaving through `via` appeared...
    RouteUp { dst: SignPk, via: SignPk, name: Arc<str> },
    /// ... or went away.
    RouteDown { dst: SignPk, via: SignPk },
}

/// Counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub announcements_sent: u64,
    pub announcements_received: u64,
    /// Bad signature, or claiming to be from us.
    pub announcements_forged: u64,
    /// Too far from our clock, or older than what we have.
    pub announcements_stale: u64,
    /// Over a neighbour's announcement rate.
    pub announcements_limited: u64,
    pub frames_sent: u64,
    pub frames_delivered: u64,
    /// Transit frames forwarded for others, and their bytes.
    pub frames_relayed: u64,
    pub bytes_relayed: u64,
    /// Transit frames from the internet into the mesh, and out of it.
    pub gateway_in: u64,
    pub gateway_out: u64,
    pub resolves: u64,
    pub dials: u64,
    pub records_refused: u64,
    pub dropped_budget: u64,
    pub dropped_ttl: u64,
    pub dropped_no_route: u64,
    pub dropped_queue: u64,
    pub dropped_too_big: u64,
    pub dropped_not_relaying: u64,
    pub dropped_pending: u64,
    pub hop_connections: u64,
}

/// Bytes-per-second token bucket (burst = one second) on the caller's clock.
#[derive(Clone, Debug)]
pub struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Time,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Bucket { rate, burst, tokens: burst, at: 0 }
    }

    pub fn take(&mut self, n: f64, now: Time) -> bool {
        self.tokens = (self.tokens + now.saturating_sub(self.at) as f64 / 1000.0 * self.rate).min(self.burst);
        self.at = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

struct Nb {
    /// In range on a link or the LAN (else an internet hop, when up).
    direct: bool,
    /// A hop connection is up.
    up: bool,
    /// Hop cost (0.1 ms units, smoothed RTT); 0 = not measured yet.
    cost: u32,
    budget: Bucket,
    ogm_budget: Bucket,
    last_used: Time,
}

impl Nb {
    fn new(cfg: &Config, now: Time) -> Self {
        let rate = cfg.relay_rate_per_neighbour as f64;
        let mut budget = Bucket::new(rate, rate);
        budget.at = now;
        let mut ogm_budget = Bucket::new(OGM_RATE, OGM_RATE * 4.0);
        ogm_budget.at = now;
        Nb { direct: false, up: false, cost: 0, budget, ogm_budget, last_used: now }
    }

    fn hop_cost(&self) -> u32 {
        (if self.cost == 0 { DEFAULT_COST } else { self.cost }) + HOP_PENALTY
    }

    fn internet(&self) -> bool {
        self.up && !self.direct
    }
}

/// What we heard about one origin through one neighbour.
#[derive(Clone, Copy, Debug)]
struct Via {
    seq: u64,
    cost: u32,
    hops: u8,
    at: Time,
}

struct Origin {
    newest: u64,
    /// The newest announcement itself (passed on with our cost added).
    latest: Announce,
    via: Vec<(SignPk, Via)>,
    /// Newest sequence number we have passed on.
    forwarded: u64,
    /// When to pass on the newest one.
    pending: Option<Time>,
}

struct Reasm {
    buf: Vec<u8>,
    got: usize,
    at: Time,
    waypoint: SignPk,
    control: bool,
}

struct Reach {
    /// Empty: no record (reach the target itself over the internet).
    gateways: Vec<SignPk>,
    until: Time,
}

struct Pending {
    frames: VecDeque<(Frame, Option<SignPk>)>,
    since: Time,
}

enum Next {
    Via(SignPk),
    /// Queue under this key (a lookup or a dial is under way).
    Wait(SignPk),
    Drop,
}

/// One device's router. See the module docs.
pub struct Router {
    me: SignPk,
    cfg: Config,
    internet: bool,
    rng: u64,
    nbs: BTreeMap<SignPk, Nb>,
    origins: Map<SignPk, Origin>,
    /// Waypoints offered to QUIC per destination.
    published: Map<SignPk, Vec<SignPk>>,
    reasm: Map<(SignPk, u32), Reasm>,
    verified: Set<(SignPk, u64)>,
    total_budget: Bucket,
    gateway_budget: Bucket,
    reach: Map<SignPk, Reach>,
    resolving: Set<SignPk>,
    dialing: Map<SignPk, Time>,
    pending: Map<SignPk, Pending>,
    my_gateways: Vec<SignPk>,
    reach_due: Time,
    last_reach: Option<Time>,
    /// Gateway side: when we last accepted each origin's record.
    records: Map<SignPk, Time>,
    own: Option<Announce>,
    seq: u64,
    next_announce: Time,
    next_id: u32,
    stats: Stats,
    out: Vec<Out>,
}

impl Router {
    pub fn new(me: SignPk, cfg: Config) -> Router {
        let total = cfg.relay_rate_total as f64;
        let gw = cfg.gateway_rate as f64;
        let rng = cfg.seed ^ u64::from_le_bytes(me.0[..8].try_into().unwrap_or([7; 8])) | 1;
        Router {
            me,
            internet: false,
            rng,
            nbs: BTreeMap::new(),
            origins: Map::default(),
            published: Map::default(),
            reasm: Map::default(),
            verified: Set::default(),
            total_budget: Bucket::new(total, total),
            gateway_budget: Bucket::new(gw, gw),
            reach: Map::default(),
            resolving: Set::default(),
            dialing: Map::default(),
            pending: Map::default(),
            my_gateways: Vec::new(),
            reach_due: 0,
            last_reach: None,
            records: Map::default(),
            own: None,
            seq: 0,
            next_announce: 0,
            next_id: 0,
            stats: Stats::default(),
            out: Vec::new(),
            cfg,
        }
    }

    pub fn me(&self) -> SignPk {
        self.me
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Sequence numbers live this long (announcement periods) ...
    fn window(&self) -> u64 {
        self.cfg.announce_every * 3
    }

    /// ... and a route without a fresh announcement dies after this.
    fn route_timeout(&self) -> Time {
        self.cfg.announce_every * 7 / 2
    }

    /// Take the effects produced so far, in order.
    pub fn drain(&mut self, buf: &mut Vec<Out>) {
        if buf.is_empty() {
            std::mem::swap(buf, &mut self.out);
        } else {
            buf.append(&mut self.out);
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    // ───────────── neighbours and the internet ─────────────

    /// Whether this device reaches the wider world (IP beyond the mesh).
    pub fn set_internet(&mut self, on: bool) {
        self.internet = on;
    }

    pub fn internet(&self) -> bool {
        self.internet
    }

    /// The flags our announcements carry.
    pub fn own_flags(&self) -> u8 {
        if self.internet && self.cfg.gateway && self.cfg.relay { F_GATEWAY } else { 0 }
    }

    pub fn set_direct(&mut self, peer: SignPk, direct: bool, now: Time) {
        if peer == self.me {
            return;
        }
        if direct {
            let cfg = &self.cfg;
            self.nbs.entry(peer).or_insert_with(|| Nb::new(cfg, now)).direct = true;
            // a peer in range is reached directly, never through gateways
            self.reach.remove(&peer);
        } else if let Some(n) = self.nbs.get_mut(&peer) {
            n.direct = false;
            if !n.up {
                self.nbs.remove(&peer);
            }
        }
    }

    pub fn hop_up(&mut self, peer: SignPk, now: Time) {
        if peer == self.me {
            return;
        }
        let cfg = &self.cfg;
        let n = self.nbs.entry(peer).or_insert_with(|| Nb::new(cfg, now));
        n.up = true;
        n.last_used = now;
        let direct = n.direct;
        self.stats.hop_connections += 1;
        self.dialing.remove(&peer);
        if direct && let Some(a) = self.own.clone() {
            self.stats.announcements_sent += 1;
            self.out.push(Out::Announce { to: peer, ann: a });
        }
        self.release(peer, now);
    }

    pub fn hop_down(&mut self, peer: SignPk, _now: Time) {
        let Some(n) = self.nbs.get_mut(&peer) else { return };
        n.up = false;
        if !n.direct {
            self.nbs.remove(&peer);
        }
        for o in self.origins.values_mut() {
            o.via.retain(|(k, _)| *k != peer);
        }
        if let Some(p) = self.pending.remove(&peer) {
            self.stats.dropped_pending += p.frames.len() as u64;
        }
    }

    pub fn dial_failed(&mut self, peer: SignPk, _now: Time) {
        self.dialing.remove(&peer);
        if let Some(p) = self.pending.remove(&peer) {
            self.stats.dropped_pending += p.frames.len() as u64;
        }
    }

    /// Measured hop cost in 0.1 ms units (smoothed here).
    pub fn set_cost(&mut self, peer: SignPk, units: u32) {
        if let Some(n) = self.nbs.get_mut(&peer) {
            let units = units.max(1);
            n.cost = if n.cost == 0 { units } else { (n.cost * 7 + units) / 8 };
        }
    }

    /// A neighbour we have a hop connection to, or one in range.
    pub fn is_neighbour(&self, pk: &SignPk) -> bool {
        self.nbs.get(pk).is_some_and(|n| n.direct || n.up)
    }

    fn is_internet_hop(&self, pk: &SignPk) -> bool {
        self.nbs.get(pk).is_some_and(Nb::internet)
    }

    /// Neighbours with a hop connection up: (key, direct).
    pub fn neighbours(&self) -> Vec<(SignPk, bool)> {
        self.nbs.iter().filter(|(_, n)| n.up).map(|(k, n)| (*k, n.direct)).collect()
    }

    // ───────────── announcements ─────────────

    pub fn announce_due(&self, now: Time) -> bool {
        now >= self.next_announce
    }

    /// The sequence number for our next announcement: wall-clock ms, so a
    /// restarted device's announcements are newer than its old ones.
    pub fn next_seq(&mut self, wall: u64) -> u64 {
        self.seq = wall.max(self.seq + 1);
        self.seq
    }

    /// Send our own (signed) announcement to every direct neighbour.
    pub fn originate(&mut self, ann: Announce, now: Time) {
        let every = self.cfg.announce_every;
        let jitter = self.rand() % (every / 4 + 1);
        self.next_announce = now + every - every / 8 + jitter;
        for (pk, n) in &self.nbs {
            if n.up && n.direct {
                self.stats.announcements_sent += 1;
                self.out.push(Out::Announce { to: *pk, ann: ann.clone() });
            }
        }
        self.own = Some(ann);
    }

    /// An announcement from a neighbour. `verify` checks the origin's
    /// signature; it runs once per (origin, seq), after the cheap checks.
    pub fn on_announce(
        &mut self,
        from: SignPk,
        a: Announce,
        now: Time,
        wall: u64,
        verify: impl FnOnce(&Announce) -> bool,
    ) {
        let window = self.window();
        let jitter = 10 + self.rand() % 40;
        let Some(n) = self.nbs.get_mut(&from) else { return };
        if !n.direct {
            return; // internet hops carry no routing: meshes don't merge
        }
        if !n.ogm_budget.take(1.0, now) {
            self.stats.announcements_limited += 1;
            return;
        }
        let hop_cost = n.hop_cost();
        self.stats.announcements_received += 1;
        if a.origin == self.me {
            return; // our own, echoed back
        }
        if a.seq > wall + MAX_CLOCK_SKEW_MS || a.seq + MAX_CLOCK_SKEW_MS < wall {
            self.stats.announcements_stale += 1;
            return;
        }
        if self.origins.get(&a.origin).is_some_and(|o| a.seq + window < o.newest) {
            self.stats.announcements_stale += 1;
            return;
        }
        if !self.verified.contains(&(a.origin, a.seq)) {
            if !verify(&a) {
                self.stats.announcements_forged += 1;
                return;
            }
            if self.verified.len() >= VERIFIED_MAX {
                self.verified.clear();
            }
            self.verified.insert((a.origin, a.seq));
        }
        let hops = a.hops.saturating_add(1);
        if hops > self.cfg.max_hops {
            return;
        }
        let cost = a.cost.saturating_add(hop_cost);
        let (relay, max_hops) = (self.cfg.relay, self.cfg.max_hops);
        let seq = a.seq;
        let o = self.origins.entry(a.origin).or_insert_with(|| Origin {
            newest: 0,
            latest: a.clone(),
            via: Vec::new(),
            forwarded: 0,
            pending: None,
        });
        if seq > o.newest {
            o.newest = seq;
            o.latest = a;
        }
        let via = Via { seq, cost, hops, at: now };
        match o.via.iter_mut().find(|(k, _)| *k == from) {
            Some((_, v)) => *v = via,
            None => o.via.push((from, via)),
        }
        if relay && seq == o.newest && seq > o.forwarded && o.pending.is_none() && hops < max_hops {
            // wait a little to hear the cheapest copy, and desynchronize
            o.pending = Some(now + jitter);
        }
    }

    /// Pass on announcements whose jitter has run out: once per sequence
    /// number, with our best cost, to direct neighbours, not back where it
    /// came from.
    fn flush_announcements(&mut self, now: Time) {
        let due: Vec<SignPk> =
            self.origins.iter().filter(|(_, o)| o.pending.is_some_and(|t| t <= now)).map(|(k, _)| *k).collect();
        for origin in due {
            let Some(o) = self.origins.get_mut(&origin) else { continue };
            o.pending = None;
            let newest = o.newest;
            let best = o.via.iter().filter(|(_, v)| v.seq == newest).min_by_key(|(n, v)| (v.cost, n.0)).copied();
            let Some((from, via)) = best else { continue };
            o.forwarded = newest;
            let mut a = o.latest.clone();
            a.hops = via.hops;
            a.cost = via.cost;
            for (pk, n) in &self.nbs {
                if *pk == from || *pk == origin || !(n.up && n.direct) {
                    continue;
                }
                self.stats.announcements_sent += 1;
                self.out.push(Out::Announce { to: *pk, ann: a.clone() });
            }
        }
    }

    // ───────────── routes ─────────────

    /// Fresh routes to `origin` through direct neighbours: (neighbour, via),
    /// cheapest first.
    fn routes(&self, origin: &SignPk, now: Time) -> Vec<(SignPk, Via)> {
        let Some(o) = self.origins.get(origin) else { return Vec::new() };
        let (window, timeout) = (self.window(), self.route_timeout());
        let mut v: Vec<(SignPk, Via)> = o
            .via
            .iter()
            .filter(|(n, via)| {
                via.seq + window >= o.newest
                    && now.saturating_sub(via.at) < timeout
                    && self.nbs.get(n).is_some_and(|n| n.up && n.direct)
            })
            .copied()
            .collect();
        v.sort_by_key(|(n, via)| (via.cost, n.0));
        v
    }

    /// The neighbour toward `dst` inside the mesh (no gateways, no internet).
    pub fn next_hop_local(&self, dst: &SignPk, now: Time) -> Option<SignPk> {
        if self.nbs.get(dst).is_some_and(|n| n.up) {
            return Some(*dst);
        }
        self.routes(dst, now).first().map(|(n, _)| *n)
    }

    /// Gateways reachable through the mesh: (gateway, cost, first hop), cheapest first.
    fn gateway_routes(&self, now: Time) -> Vec<(SignPk, u32, SignPk)> {
        let mut v: Vec<(SignPk, u32, SignPk)> = self
            .origins
            .iter()
            .filter(|(_, o)| o.latest.flags & F_GATEWAY != 0)
            .filter_map(|(g, _)| self.routes(g, now).first().map(|(n, via)| (*g, via.cost, *n)))
            .collect();
        v.sort_by_key(|(g, c, _)| (*c, g.0));
        v
    }

    /// Gateways we'd publish in our record: the cheapest, through distinct
    /// first hops where possible, at most `gateways` of them.
    pub fn gateways(&self, now: Time) -> Vec<SignPk> {
        let all = self.gateway_routes(now);
        let want = self.cfg.gateways.max(1);
        let mut pick: Vec<SignPk> = Vec::new();
        let mut hops: Vec<SignPk> = Vec::new();
        for (g, _, first) in &all {
            if pick.len() < want && !hops.contains(first) {
                pick.push(*g);
                hops.push(*first);
            }
        }
        for (g, _, _) in &all {
            if pick.len() < want && !pick.contains(g) {
                pick.push(*g);
            }
        }
        pick
    }

    /// The gateways our current record names (none while we have the internet).
    pub fn my_gateways(&self) -> &[SignPk] {
        &self.my_gateways
    }

    /// Devices reachable through the mesh (local routes) right now.
    pub fn reachable(&self) -> Vec<SignPk> {
        self.published.keys().copied().collect()
    }

    pub fn origin_name(&self, pk: &SignPk) -> Option<Arc<str>> {
        self.origins.get(pk).map(|o| o.latest.name.clone()).filter(|n| !n.is_empty())
    }

    pub fn is_gateway(&self, pk: &SignPk) -> bool {
        self.origins.get(pk).is_some_and(|o| o.latest.flags & F_GATEWAY != 0)
    }

    /// Hops to `dst` leaving through `via` (a local route), or `None`.
    pub fn route_hops(&self, dst: &SignPk, via: &SignPk) -> Option<u8> {
        self.origins.get(dst)?.via.iter().find(|(k, _)| k == via).map(|(_, v)| v.hops)
    }

    /// Recompute the routes offered per destination; report the changes.
    fn publish(&mut self, now: Time) {
        let mut want: Map<SignPk, Vec<SignPk>> = Map::default();
        for origin in self.origins.keys() {
            if *origin == self.me || self.is_neighbour(origin) {
                continue;
            }
            let current = self.published.get(origin);
            let mut routes = self.routes(origin, now);
            let Some(best) = routes.first().map(|(_, v)| v.cost) else { continue };
            let limit = best.saturating_mul(ROUTE_COST_FACTOR).saturating_add(ROUTE_COST_SLACK);
            routes.retain(|(_, v)| v.cost <= limit);
            let sticky = |n: &SignPk, c: u32| {
                if current.is_some_and(|ws| ws.contains(n)) { (c as u64 * STICKY_PERCENT as u64 / 100) as u32 } else { c }
            };
            routes.sort_by_key(|(n, v)| (sticky(n, v.cost), n.0));
            routes.truncate(self.cfg.routes.max(1));
            want.insert(*origin, routes.into_iter().map(|(n, _)| n).collect());
        }
        let mut downs: Vec<(SignPk, SignPk)> = Vec::new();
        for (dst, ws) in &self.published {
            let keep = want.get(dst);
            for w in ws {
                if keep.is_none_or(|k| !k.contains(w)) {
                    downs.push((*dst, *w));
                }
            }
        }
        downs.sort_by_key(|(d, w)| (d.0, w.0));
        for (dst, via) in downs {
            self.out.push(Out::RouteDown { dst, via });
        }
        let mut ups: Vec<(SignPk, SignPk)> = Vec::new();
        for (dst, ws) in &want {
            let had = self.published.get(dst);
            for w in ws {
                if had.is_none_or(|h| !h.contains(w)) {
                    ups.push((*dst, *w));
                }
            }
        }
        ups.sort_by_key(|(d, w)| (d.0, w.0));
        for (dst, via) in ups {
            let name = self.origins.get(&dst).map(|o| o.latest.name.clone()).unwrap_or_else(|| Arc::from(""));
            self.out.push(Out::RouteUp { dst, via, name });
        }
        self.published = want;
    }

    // ───────────── data ─────────────

    /// A packet of ours for `dst`, through `waypoint`. Data never goes to
    /// a neighbour through the mesh (a direct path always wins; this also
    /// keeps hop connections off the mesh); control messages may.
    pub fn send(&mut self, dst: SignPk, waypoint: SignPk, payload: Bytes, control: bool, now: Time) -> bool {
        if !control && self.is_neighbour(&dst) {
            self.stats.dropped_no_route += 1;
            return false;
        }
        let f = Frame {
            ttl: self.cfg.max_hops,
            reached: false,
            control,
            dst,
            src: self.me,
            waypoint,
            id: self.next_id,
            offset: 0,
            total: payload.len().min(u16::MAX as usize) as u16,
            payload,
        };
        self.next_id = self.next_id.wrapping_add(1);
        self.stats.frames_sent += 1;
        self.route(f, None, now);
        true
    }

    /// A frame from neighbour `from`.
    pub fn on_frame(&mut self, from: SignPk, f: Frame, now: Time) {
        if let Some(n) = self.nbs.get_mut(&from) {
            n.last_used = now;
        }
        self.route(f, Some(from), now);
    }

    /// Deliver, pass `f` one hop on, or park it while a lookup or dial
    /// runs. `from`: the neighbour it came from (`None`: ours).
    fn route(&mut self, mut f: Frame, from: Option<SignPk>, now: Time) {
        if !f.reached && f.waypoint == self.me {
            f.reached = true;
        }
        if f.dst == self.me {
            self.deliver(f, now);
            return;
        }
        if f.src == self.me && from.is_some() {
            self.stats.dropped_no_route += 1; // our own packet came back: a loop
            return;
        }
        if from.is_some() {
            if !self.cfg.relay {
                self.stats.dropped_not_relaying += 1;
                return;
            }
            if f.ttl <= 1 {
                self.stats.dropped_ttl += 1;
                return;
            }
        }
        let target = if f.reached { f.dst } else { f.waypoint };
        match self.next_hop(&target, from.as_ref(), now) {
            Next::Via(next) => self.forward(f, from, next, now),
            Next::Wait(key) => self.park(key, f, from, now),
            Next::Drop => self.stats.dropped_no_route += 1,
        }
    }

    fn next_hop(&mut self, target: &SignPk, from: Option<&SignPk>, now: Time) -> Next {
        // 1. a neighbour (direct, or an internet hop already up)
        if Some(target) != from && self.nbs.get(target).is_some_and(|n| n.up) {
            return Next::Via(*target);
        }
        // 2. a mesh route
        if let Some((n, _)) = self.routes(target, now).into_iter().find(|(n, _)| Some(n) != from) {
            return Next::Via(n);
        }
        let from_internet = from.is_some_and(|f| self.is_internet_hop(f));
        if self.internet {
            // 3. over the internet: never internet → internet for others,
            // and mesh → internet only as a gateway
            if from_internet || (from.is_some() && !self.cfg.gateway) {
                return Next::Drop;
            }
            if self.nbs.get(target).is_some_and(|n| n.direct) {
                return Next::Drop; // in range but no hop connection yet
            }
            match self.reach.get(target) {
                Some(r) if r.until > now => {
                    if r.gateways.is_empty() {
                        return self.dial_or_wait(*target, now);
                    }
                    let gws: Vec<SignPk> =
                        r.gateways.iter().filter(|g| **g != self.me && Some(*g) != from).copied().collect();
                    if let Some(g) = gws.iter().find(|g| self.nbs.get(g).is_some_and(|n| n.up)) {
                        return Next::Via(*g);
                    }
                    match gws.first() {
                        Some(g) => self.dial_or_wait(*g, now),
                        None => Next::Drop,
                    }
                }
                _ => {
                    if self.resolving.insert(*target) {
                        self.stats.resolves += 1;
                        self.out.push(Out::Resolve(*target));
                    }
                    Next::Wait(*target)
                }
            }
        } else {
            // 4. no internet: the default route, to the nearest gateway
            match self.gateway_routes(now).into_iter().find(|(g, _, n)| Some(n) != from && Some(g) != from) {
                Some((_, _, first)) => Next::Via(first),
                None => Next::Drop,
            }
        }
    }

    fn dial_or_wait(&mut self, peer: SignPk, now: Time) -> Next {
        if self.nbs.get(&peer).is_some_and(|n| n.up) {
            return Next::Via(peer);
        }
        if !self.dialing.contains_key(&peer) {
            let open = self.nbs.values().filter(|n| n.internet()).count() + self.dialing.len();
            if open >= self.cfg.max_internet_hops {
                return Next::Drop;
            }
            self.dialing.insert(peer, now);
            self.stats.dials += 1;
            self.out.push(Out::Dial(peer));
        }
        Next::Wait(peer)
    }

    fn park(&mut self, key: SignPk, f: Frame, from: Option<SignPk>, now: Time) {
        if !self.pending.contains_key(&key) && self.pending.len() >= PENDING_KEYS {
            self.stats.dropped_pending += 1;
            return;
        }
        let p = self.pending.entry(key).or_insert_with(|| Pending { frames: VecDeque::new(), since: now });
        if p.frames.len() >= PENDING_FRAMES {
            p.frames.pop_front(); // the oldest is likeliest retransmitted already
            self.stats.dropped_pending += 1;
        }
        p.frames.push_back((f, from));
    }

    /// Route again what waited on `key`.
    fn release(&mut self, key: SignPk, now: Time) {
        let Some(p) = self.pending.remove(&key) else { return };
        for (f, from) in p.frames {
            self.route(f, from, now);
        }
    }

    fn forward(&mut self, mut f: Frame, from: Option<SignPk>, next: SignPk, now: Time) {
        if let Some(from) = from {
            f.ttl -= 1;
            let len = f.payload.len() as f64;
            let neighbour_ok = self.nbs.get_mut(&from).is_some_and(|n| n.budget.take(len, now));
            if !neighbour_ok || !self.total_budget.take(len, now) {
                self.stats.dropped_budget += 1;
                return;
            }
            let (from_inet, to_inet) = (self.is_internet_hop(&from), self.is_internet_hop(&next));
            if from_inet != to_inet {
                if !self.gateway_budget.take(len, now) {
                    self.stats.dropped_budget += 1;
                    return;
                }
                if to_inet {
                    self.stats.gateway_out += 1;
                } else {
                    self.stats.gateway_in += 1;
                }
            }
            self.stats.frames_relayed += 1;
            self.stats.bytes_relayed += f.payload.len() as u64;
        }
        if let Some(n) = self.nbs.get_mut(&next) {
            n.last_used = now;
        }
        self.out.push(Out::Frame { to: next, frame: f, relayed: from.is_some() });
    }

    fn deliver(&mut self, f: Frame, now: Time) {
        if f.offset == 0 && f.payload.len() == f.total as usize {
            self.stats.frames_delivered += 1;
            self.out.push(if f.control {
                Out::Control { from: f.src, payload: f.payload }
            } else {
                Out::Deliver { src: f.src, waypoint: f.waypoint, payload: f.payload }
            });
            return;
        }
        let key = (f.src, f.id);
        if !self.reasm.contains_key(&key) && self.reasm.len() >= REASM_MAX {
            return;
        }
        let r = self.reasm.entry(key).or_insert_with(|| Reasm {
            buf: vec![0; f.total as usize],
            got: 0,
            at: now,
            waypoint: f.waypoint,
            control: f.control,
        });
        let at = f.offset as usize;
        if r.buf.len() != f.total as usize || at + f.payload.len() > r.buf.len() {
            return;
        }
        r.buf[at..at + f.payload.len()].copy_from_slice(&f.payload);
        r.got += f.payload.len();
        if r.got >= r.buf.len()
            && let Some(r) = self.reasm.remove(&key)
        {
            self.stats.frames_delivered += 1;
            let payload = Bytes::from(r.buf);
            self.out.push(if r.control {
                Out::Control { from: f.src, payload }
            } else {
                Out::Deliver { src: f.src, waypoint: r.waypoint, payload }
            });
        }
    }

    // ───────────── reachability records ─────────────

    /// The answer to [`Out::Resolve`]: `Some(gateways)` if `target` has a
    /// record (it is behind them), `None` if it has none (dial it directly).
    pub fn on_resolved(&mut self, target: SignPk, gateways: Option<Vec<SignPk>>, now: Time) {
        self.resolving.remove(&target);
        let found = gateways.as_ref().is_some_and(|g| !g.is_empty());
        let mut gws = gateways.unwrap_or_default();
        gws.retain(|g| *g != target);
        gws.truncate(8);
        let ttl = if found { REACH_TTL } else { NO_RECORD_TTL };
        self.reach.insert(target, Reach { gateways: gws, until: now + ttl });
        self.release(target, now);
    }

    /// Whether a gateway should publish `origin`'s record now: at most one
    /// per origin every [`RECORD_MIN_GAP`], at most `max_records` origins.
    pub fn admit_record(&mut self, origin: SignPk, now: Time) -> bool {
        let ok = match self.records.get(&origin) {
            Some(t) => now.saturating_sub(*t) >= RECORD_MIN_GAP,
            None => self.records.len() < self.cfg.max_records,
        };
        if ok {
            self.records.insert(origin, now);
        } else {
            self.stats.records_refused += 1;
        }
        ok
    }

    // ───────────── housekeeping ─────────────

    pub fn tick(&mut self, now: Time) {
        self.flush_announcements(now);
        let timeout = self.route_timeout();
        self.origins.retain(|_, o| {
            o.via.retain(|(_, v)| now.saturating_sub(v.at) < timeout);
            !o.via.is_empty()
        });
        self.reasm.retain(|_, r| now.saturating_sub(r.at) < REASM_TIMEOUT);
        let mut expired = 0;
        self.pending.retain(|_, p| {
            let keep = now.saturating_sub(p.since) < PENDING_TIMEOUT;
            if !keep {
                expired += p.frames.len() as u64;
            }
            keep
        });
        self.stats.dropped_pending += expired;
        self.reach.retain(|_, r| r.until > now);
        let gave_up: Vec<SignPk> =
            self.dialing.iter().filter(|(_, t)| now.saturating_sub(**t) >= DIAL_GIVE_UP).map(|(k, _)| *k).collect();
        for pk in gave_up {
            self.dial_failed(pk, now);
        }
        for (pk, n) in self.nbs.iter_mut() {
            if n.internet() && now.saturating_sub(n.last_used) >= INTERNET_IDLE {
                n.last_used = now; // once; the driver reports the hop down
                self.out.push(Out::Hangup(*pk));
            }
        }
        self.records.retain(|_, t| now.saturating_sub(*t) < REACH_REFRESH * 2);
        self.publish(now);
        self.choose_gateways(now);
    }

    /// Without the internet: keep a record naming our gateways published.
    fn choose_gateways(&mut self, now: Time) {
        if self.internet {
            self.my_gateways.clear();
            return;
        }
        let mut g = self.gateways(now);
        g.sort();
        let changed = g != self.my_gateways;
        let gap_ok = self.last_reach.is_none_or(|t| now.saturating_sub(t) >= REACH_MIN_GAP);
        if !g.is_empty() && gap_ok && (changed || now >= self.reach_due) {
            self.out.push(Out::PublishReach { gateways: g.clone() });
            self.last_reach = Some(now);
            self.reach_due = now + REACH_REFRESH;
            self.my_gateways = g;
        } else if g.is_empty() {
            self.my_gateways.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> SignPk {
        let mut k = [0u8; 32];
        k[0] = i;
        k[31] = i.wrapping_mul(37);
        SignPk(k)
    }

    fn ann(origin: SignPk, seq: u64, flags: u8) -> Announce {
        Announce { hops: 0, cost: 0, origin, seq, flags, name: Arc::from(""), sig: Sig([0; 64]) }
    }

    const WALL: u64 = 1_700_000_000_000;

    /// Routers wired by instant, lossless hops; signatures always valid.
    struct Net {
        nodes: Vec<Router>,
        now: Time,
        delivered: Vec<(usize, SignPk, Bytes)>,
        published: Vec<(usize, Vec<SignPk>)>,
    }

    impl Net {
        fn new(n: usize, edges: &[(usize, usize)], internet: &[usize]) -> Net {
            let mut nodes: Vec<Router> = (0..n)
                .map(|i| Router::new(key(i as u8 + 1), Config { announce_every: 500, seed: i as u64 + 1, ..Config::default() }))
                .collect();
            for i in internet {
                nodes[*i].set_internet(true);
            }
            let mut net = Net { nodes, now: 0, delivered: vec![], published: vec![] };
            for (a, b) in edges {
                net.link(*a, *b);
            }
            net
        }

        fn idx(&self, k: &SignPk) -> Option<usize> {
            self.nodes.iter().position(|r| r.me() == *k)
        }

        fn link(&mut self, a: usize, b: usize) {
            let (ka, kb) = (self.nodes[a].me(), self.nodes[b].me());
            let now = self.now;
            self.nodes[a].set_direct(kb, true, now);
            self.nodes[b].set_direct(ka, true, now);
            self.nodes[a].hop_up(kb, now);
            self.nodes[b].hop_up(ka, now);
        }

        /// Deliver everything queued, repeatedly, at the current time.
        fn settle(&mut self) {
            for _ in 0..1000 {
                let mut work = Vec::new();
                for i in 0..self.nodes.len() {
                    let mut outs = Vec::new();
                    self.nodes[i].drain(&mut outs);
                    work.extend(outs.into_iter().map(|o| (i, o)));
                }
                if work.is_empty() {
                    return;
                }
                for (i, o) in work {
                    let me = self.nodes[i].me();
                    let now = self.now;
                    match o {
                        Out::Announce { to, ann } => {
                            if let Some(j) = self.idx(&to) {
                                self.nodes[j].on_announce(me, ann, now, WALL + now, |_| true);
                            }
                        }
                        Out::Frame { to, frame, .. } => {
                            if let Some(j) = self.idx(&to) {
                                self.nodes[j].on_frame(me, frame, now);
                            }
                        }
                        Out::Deliver { src, payload, .. } => self.delivered.push((i, src, payload)),
                        Out::Control { .. } => {}
                        Out::Dial(peer) => {
                            // the internet: any two internet nodes connect
                            match self.idx(&peer) {
                                Some(j) if self.nodes[j].internet() => {
                                    self.nodes[i].hop_up(peer, now);
                                    self.nodes[j].hop_up(me, now);
                                }
                                _ => self.nodes[i].dial_failed(peer, now),
                            }
                        }
                        Out::Hangup(peer) => {
                            if let Some(j) = self.idx(&peer) {
                                self.nodes[i].hop_down(peer, now);
                                self.nodes[j].hop_down(me, now);
                            }
                        }
                        Out::Resolve(peer) => {
                            let record = self.published.iter().rev().find(|(n, _)| self.nodes[*n].me() == peer);
                            let gws = record.map(|(_, g)| g.clone());
                            self.nodes[i].on_resolved(peer, gws, now);
                        }
                        Out::PublishReach { gateways } => self.published.push((i, gateways)),
                        Out::RouteUp { .. } | Out::RouteDown { .. } => {}
                    }
                }
            }
            panic!("no quiescence");
        }

        fn run(&mut self, ms: Time) {
            let end = self.now + ms;
            while self.now < end {
                self.now += 10;
                for i in 0..self.nodes.len() {
                    let now = self.now;
                    let r = &mut self.nodes[i];
                    if r.announce_due(now) {
                        let seq = r.next_seq(WALL + now);
                        let a = ann(r.me(), seq, r.own_flags());
                        r.originate(a, now);
                    }
                    r.tick(now);
                }
                self.settle();
            }
        }

        fn send(&mut self, from: usize, to: usize, via: usize, data: &'static [u8]) {
            let (dst, wp) = (self.nodes[to].me(), self.nodes[via].me());
            let now = self.now;
            self.nodes[from].send(dst, wp, Bytes::from_static(data), false, now);
            self.settle();
        }
    }

    #[test]
    fn a_line_routes_hop_by_hop() {
        let mut net = Net::new(4, &[(0, 1), (1, 2), (2, 3)], &[]);
        net.run(3_000);
        assert_eq!(net.nodes[0].next_hop_local(&net.nodes[3].me(), net.now), Some(net.nodes[1].me()));
        assert_eq!(net.nodes[0].route_hops(&net.nodes[3].me(), &net.nodes[1].me()), Some(3));
        net.send(0, 3, 1, b"hello");
        assert_eq!(net.delivered, vec![(3, net.nodes[0].me(), Bytes::from_static(b"hello"))]);
        assert_eq!(net.nodes[1].stats().frames_relayed, 1);
        assert_eq!(net.nodes[2].stats().frames_relayed, 1);
    }

    #[test]
    fn forged_stale_and_flooding_announcements_are_rejected() {
        let mut r = Router::new(key(1), Config::default());
        let n = key(2);
        r.set_direct(n, true, 0);
        r.hop_up(n, 0);
        let victim = key(9);
        r.on_announce(n, ann(victim, WALL, 0), 0, WALL, |_| false);
        assert_eq!(r.stats().announcements_forged, 1);
        assert!(r.origins.is_empty());
        r.on_announce(n, ann(victim, WALL - 3_600_000, 0), 0, WALL, |_| true);
        assert_eq!(r.stats().announcements_stale, 1);
        r.on_announce(n, ann(victim, WALL, 0), 0, WALL, |_| true);
        assert!(r.origins.contains_key(&victim));
        for i in 0..1000 {
            r.on_announce(n, ann(victim, WALL + i, 0), 0, WALL, |_| true);
        }
        assert!(r.stats().announcements_limited >= 1000 - OGM_RATE as u64 * 4, "{:?}", r.stats());
        // and nothing at all is learnt over an internet hop
        let far = key(3);
        r.hop_up(far, 0);
        r.on_announce(far, ann(key(10), WALL, 0), 10_000, WALL, |_| true);
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

    /// A Bluetooth-only device with a gateway two hops away publishes a
    /// record naming it; an internet device reads the record and reaches it
    /// through that gateway; replies take the default route back.
    #[test]
    fn records_gateways_and_the_default_route() {
        // 0 —(ble)— 1 —(ble)— 2 [internet]          3 [internet]
        let mut net = Net::new(4, &[(0, 1), (1, 2)], &[2, 3]);
        net.run(3_000);
        let (m, g, r) = (net.nodes[0].me(), net.nodes[2].me(), net.nodes[3].me());
        assert!(net.nodes[0].is_gateway(&g));
        assert_eq!(net.published.last().map(|(i, gw)| (*i, gw.clone())), Some((0, vec![g])));
        assert_eq!(net.nodes[0].my_gateways(), &[g]);
        // the internet device: mesh(M via G)
        net.send(3, 0, 2, b"to M");
        assert_eq!(net.delivered.last().map(|(i, s, _)| (*i, *s)), Some((0, r)));
        assert_eq!(net.nodes[2].stats().gateway_in, 1);
        // M answers via G: the default route takes it out
        net.send(0, 3, 2, b"to R");
        assert_eq!(net.delivered.last().map(|(i, s, _)| (*i, *s)), Some((3, m)));
        assert_eq!(net.nodes[2].stats().gateway_out, 1);
        // M sending to someone it has no route to, through its neighbour:
        // the default route still finds the gateway, which dials out
        net.send(0, 3, 1, b"default route");
        assert_eq!(
            net.delivered.last().map(|(i, _, p)| (*i, p.clone())),
            Some((3, Bytes::from_static(b"default route")))
        );
    }

    /// Gateways don't relay internet → internet.
    #[test]
    fn no_open_proxy() {
        let mut net = Net::new(3, &[], &[0, 1, 2]);
        net.run(1_000);
        // 0 asks 1 to carry a packet to 2 (waypoint 1, then dst 2)
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
        // idle internet hops are hung up
        r.tick(20 + INTERNET_IDLE + 1);
        outs.clear();
        r.drain(&mut outs);
        assert!(outs.iter().any(|o| matches!(o, Out::Hangup(k) if *k == key(50))));
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
}
