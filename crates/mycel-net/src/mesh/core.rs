//! The mesh router as a pure state machine: no I/O, no clock, no tokio, no
//! cryptography. Every input carries the time; every effect comes back as an
//! [`Out`] for the caller to carry out. The real driver (`mesh/mod.rs`) wraps
//! it around QUIC hop connections; a simulator can drive 100k of them with a
//! virtual clock and stubbed signatures, deterministically (the only
//! randomness is a seeded xorshift; maps hash with FNV).
//!
//! Design record: `docs/ROUTING.md`.
//!
//! # What it does
//!
//! - **Local routes**: distance vector over signed originator announcements
//!   (B.A.T.M.A.N.), made loop-free *during* convergence by Babel's
//!   feasibility condition, with retractions and seqno requests on loss,
//!   and Babel's timing: a long period (16 s), with what changes sent at
//!   once (retractions, seqno requests, a lone device's first neighbour)
//!   and a new neighbour greeted with our routes. Fisheye scoping: 2 hops
//!   every period, the full scope every 8th. Up to `routes` routes per
//!   destination (distinct first hops) are offered to QUIC as separate
//!   paths.
//! - **Gateways**: a device with the internet that relays for others sets
//!   [`F_GATEWAY`] and its uplink cost in its (signed) announcements. A
//!   device *without* the internet keeps a **default route** to the gateway
//!   with the lowest *total* cost (mesh + uplink) and asks the driver to
//!   publish a reachability record naming its best gateways with their mesh
//!   cost ([`Out::PublishReach`]).
//! - **Internet hops**: a device with the internet resolves targets it has
//!   no route to ([`Out::Resolve`] → [`Router::on_resolved`]). One behind
//!   gateways is reached through the gateway with the lowest record cost +
//!   internet hop cost ([`Out::Dial`] if not connected; one not measured
//!   yet costs what a measured one of the same record does, and one up
//!   wins ties); anyone else directly. Frames wait (bounded) meanwhile. A
//!   record a minute old is looked up again, while a hop up to one of its
//!   gateways keeps carrying the traffic. Internet hops carry no
//!   routing (meshes don't merge across the internet), idle ones are hung
//!   up, and nothing is relayed internet → internet.
//! - **Budgets**: transit per neighbour and in total, the mesh ↔ internet
//!   crossing separately, announcements per neighbour.
//! - **Lying neighbours**: a relayed announcement no honest relay can send
//!   (zero hops, or less cost than its hops add) gets its sender distrusted
//!   for a while: the routes through it go, and the routes it relays are
//!   ignored.
//! - **Signed route attestations** (`ROUTE_ATTEST`, [`Config::attest`]):
//!   with neighbours that take them, each hop signs what it advertises, who
//!   it sends to and its measured cost to them ([`Hop`]); a relay can't
//!   claim a shorter chain or a cheaper link than the device upstream of it
//!   signed, and a chain that tries gets its sender distrusted. Routes
//!   without a chain rank behind attested ones. Hops sign an epoch of the
//!   origin's clock ([`ATTEST_EPOCH`]), so a refresh within it travels
//!   without its chain when the receiver holds it ([`Announce::same`]).
//!
//! # API (for drivers and simulators)
//!
//! ```text
//! Router::new(me, Config) -> Router
//!   inputs                                      (`now: Time` = monotonic ms)
//!   set_internet(bool)            this device reaches the wider world
//!   set_uplink(units)             its internet cost (0.1 ms units), announced
//!   set_direct(peer, bool, now)   peer is (not) in direct range (link / LAN)
//!   hop_up(peer, now)             a hop connection to peer is up (direct or internet)
//!   hop_down(peer, now)           ... is gone
//!   dial_failed(peer, now)        an Out::Dial didn't work
//!   set_attests(peer, Option<bool>, now)   its hop hello has ROUTE_ATTEST (None: on the way)
//!   set_cost(peer, units)         measured hop cost, 0.1 ms units
//!   announce_due(now) -> bool     time to originate: then
//!     next_announce(wall) -> Origination { seq, flags, scope, uplink }
//!     originate(Announce, now)      the caller signs those fields
//!   on_announce(from, Announce, now, wall, verify)   verify: FnMut(Check) -> bool,
//!                                 run once per unseen (origin, seq) and per
//!                                 unseen attestation hop
//!   (an Out::Announce with `sign_link` set: the caller signs our hop for its
//!    receiver and pushes it onto the chain, `Announce::signed_by`; one with
//!    `same` set goes attested without its chain)
//!   on_seqreq(from, SeqReq, now)  a neighbour wants a fresh seqno of an origin
//!                                 (or, one it was sent, its chain again)
//!   send(dst, waypoint, payload, control, now) -> bool    a packet of ours
//!   on_frame(from, Frame, now)    a frame from a neighbour
//!   on_resolved(target, Option<Vec<(gateway, cost)>>, now)   answer to Out::Resolve
//!   admit_record(origin, now) -> bool             a gateway may publish this record
//!   tick(now)                     every ~10–20 ms: rebroadcasts, expiry, route
//!                                 changes, gateway choice, idle hang-ups
//!   drain(&mut Vec<Out>)          take the effects (in order)
//!   queries: toward (next hop for custody transfer), route_hops, reachable,
//!            gateways, gateways_with_cost, my_gateways, next_hop_local,
//!            is_neighbour, is_gateway, neighbours, origin_name, stats
//! ```
//!
//! A frame is `(dst, src, waypoint)` plus a TTL: it travels toward the
//! waypoint (the source's choice of first relay or gateway, which is what
//! makes each route a distinct QUIC path), then toward `dst`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use bytes::Bytes;
use mycel_crypto::{Digest, Hash32, Sig, SignPk};

/// Milliseconds on a monotonic clock (virtual in a simulator).
pub type Time = u64;

/// Announcement flag: this device relays between the mesh and the internet.
pub const F_GATEWAY: u8 = 1;
/// The cost of a retraction ("I no longer have a route").
pub const INFINITY: u32 = u32::MAX;

/// Cost units are 0.1 ms; each hop adds this on top of its measured cost,
/// so among equally fast routes the shorter wins.
pub const HOP_PENALTY: u32 = 20;
/// A neighbour's hop cost before it is measured.
pub const DEFAULT_COST: u32 = 100;
/// The least a route's cost grows per hop: the hop's measured cost (at
/// least 1) and [`HOP_PENALTY`]. A relayed announcement claiming less than
/// this per hop (or no hops at all) came from a liar: honest relays can't
/// produce it.
const MIN_HOP_COST: u32 = 1 + HOP_PENALTY;
/// A neighbour caught sending such an announcement is not routed through
/// for this long (and at most this many are remembered).
const DISTRUST: Time = 10 * 60_000;
const DISTRUST_MAX: usize = 256;
/// End-to-end feedback ([`Router::feedback`]): after this many
/// retransmission timeouts in a row with nothing acknowledged, the next hop
/// our packets to a destination took is suspected for that destination ...
const SUSPECT_STRIKES: u8 = 2;
/// ... and only once the silence has lasted this long plus twice the
/// route's cost (the time to move 64 KiB along it): a slow route, or one
/// busy with a big transfer, gets longer before it is blamed.
const SUSPECT_SILENCE: Time = 1_500;
/// ... and avoided for it this long (another route is used, or none).
const SUSPECT_FOR: Time = 2 * 60_000;
/// Destinations followed for feedback, and suspects kept per destination.
const FEEDBACK_MAX: usize = 1024;
const SUSPECTS_PER_DST: usize = 4;
/// Cross-destination aggregation ([`Defences::aggregate`]): a next hop
/// suspected for this many distinct destinations at once, each of which
/// then acknowledged through another hop (so it was alive, and the silence
/// was the suspect's), and for more of them than it carried
/// acknowledgements for lately, is avoided for every destination for
/// [`SUSPECT_FOR`]. A high bar on purpose: a well-connected relay carries
/// many destinations, so it also collects the most false suspicions (BGP
/// route-flap damping's lesson, RFC 7196) ...
const AGGREGATE_MIN: usize = 3;
/// ... counting at most this many destinations it carried
/// acknowledgements for (enough to outvote [`AGGREGATE_MIN`] and more) ...
const VOUCHED_PER_HOP: usize = 8;
/// ... and once avoided, fresh seqnos are asked for (at most this many
/// requests in all) for our destinations that went through it within
/// [`SUSPECT_FOR`]: the traffic that has to move, not everyone ever sent to.
const SHUN_SEQREQS: usize = 32;
/// Corroboration hold-down ([`Defences::corroborate`]): a route one
/// neighbour suddenly claims at less than 1/this of the incumbent's cost
/// (an older route through another neighbour), with no other neighbour's
/// route within this factor of it, ranks just behind the incumbent ...
const CORROBORATE_FACTOR: u64 = 2;
/// ... for this long after its claim became that cheap (it appeared, or it
/// fell from no cheaper than the others' to that): two announcement
/// periods, time for a real shortcut to be heard through a second
/// neighbour. An acknowledgement from the destination through the hop ends
/// it early; the destination itself, next to us, is never held.
const HOLD_DOWN: Time = 32_000;
/// Trust-graph preference ([`Defences::affinity`]): by default a route
/// ranks this many percent costlier per step its next hop is from us in the
/// membership graph of our spaces beyond a co-member (distance 1) ...
pub const AFFINITY_STEP: u16 = 50;
/// ... a relay we know nothing about counting as this far.
pub const AFFINITY_UNKNOWN: u8 = 3;
/// Control budget ([`Defences::budget`], after Reticulum's announce cap):
/// relayed announcements to a neighbour take at most this share of the
/// hop's capacity (estimated from its cost: the time to move 64 KiB) ...
const CONTROL_SHARE: f64 = 0.02;
/// ... and never more than the neighbour accepts from one neighbour
/// ([`OGM_RATE`] a second, 4 s of it at once: beyond that it throws them
/// away), which is also the burst (a greeting's table, a full-scope period,
/// a crowd switching on at once: 400 announcements, 1.2 s of a Bluetooth
/// hop; smaller, at a cold start far routes waited behind the near ones'
/// refreshes). Past the budget they queue, fewest hops first, at most
/// this many per neighbour (the farthest make way).
const CONTROL_QUEUE: usize = 1024;
/// A hop not measured yet is budgeted as the slowest radio (Bluetooth LE
/// at ~40 kB/s: 64 KiB in 1.6 s) until it is: a new neighbour is greeted
/// before its first measurement, and a whole table sent unpaced would fill
/// a slow link for seconds (and mostly be thrown away).
const UNMEASURED_CONTROL_COST: u32 = 16_384;
/// Bytes of an announcement on the wire without its name (`wire.rs`).
const ANN_BYTES: usize = 117;
/// An internet hop's cost before it is measured (100 ms).
pub const DEFAULT_INTERNET_COST: u32 = 1_000;
/// Routes much costlier than the best one aren't worth a QUIC path.
const ROUTE_COST_FACTOR: u32 = 4;
const ROUTE_COST_SLACK: u32 = 300;
/// A route already in use counts as this much cheaper (no flapping).
const STICKY_PERCENT: u32 = 80;
/// Each neighbour may send us this many announcements per second (burst 4×).
const OGM_RATE: f64 = 100.0;
/// Announcements more than this far from our wall clock are ignored (replays).
pub const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
/// Fisheye: every period an origin announces to this many hops ...
pub const NEAR_SCOPE: u8 = 2;
/// ... and to its full scope every this many periods (far routes refresh,
/// and expire, this much slower; [`Config::far_every`]).
pub const FAR_EVERY: u64 = 8;
/// Flood reduction (off by default: it assumes broadcast radios): with
/// this many direct neighbours or more ...
const DENSE: usize = 8;
/// ... skip a rebroadcast that this many neighbours already made as well.
const REDUNDANT: usize = 3;
/// A device greets one new neighbour with its routes at most this often;
/// the others wait their turn and then get only what they haven't heard
/// meanwhile. In a crowd everyone meets 15 devices at once, and one table
/// is enough to join.
const GREET_GAP: Time = 4_000;
/// Seqno requests per origin at most this often; how far they travel.
const SEQREQ_GAP: Time = 1_000;
const SEQREQ_HOPS: u8 = 8;
/// An origin answers a seqno request at most this often.
const FORCED_GAP: Time = 500;
/// A relay floods one origin's new seqnos at most this often: a storming
/// device reaches its neighbours, not the mesh. (Origins announce every
/// ~16 s, or on request at most every [`FORCED_GAP`].)
const ORIGIN_GAP: Time = 250;
const REASM_TIMEOUT: Time = 2_000;
const REASM_MAX: usize = 256;
const VERIFIED_MAX: usize = 4096;
/// Signed route attestations ([`Config::attest`], `docs/ROUTING.md` §6 item
/// 13): a route that came without a verified chain ranks behind every
/// usable attested route to the same destination, as a fallback (the
/// downgrade policy of `ROUTE_ATTEST`, `docs/PROTOCOL.md` §6). A relay that
/// stops attesting loses its routes instead of keeping them. (Above any
/// cost: costs are `u32`.)
const UNATTESTED_RANK: u64 = 1 << 34;
/// Signature checks a neighbour's attested announcements may cost us per
/// second (burst 4×): a chain costs one check per hop not seen before, and
/// a neighbour inventing long chains of fresh keys would otherwise cost up
/// to [`MAX_CHAIN`] checks per announcement. Honest copies mostly repeat
/// a cached prefix (`docs/ROUTING.md` §6, item 13, measured there).
const VERIFY_RATE: f64 = 4.0 * OGM_RATE;
/// The longest attestation chain accepted (and decoded).
pub const MAX_CHAIN: usize = 16;
/// A new neighbour whose capability hello hasn't arrived yet is greeted
/// once it does (so the greeting can be attested), or after this long.
const HELLO_WAIT: Time = 1_000;
/// How long one attestation hop stays good (ms of the origin's seqno, which
/// is its clock): each hop signs the epoch of the announcement, not its
/// seqno, so the origin's refreshes within an epoch travel without their
/// chain when the receiver holds it already ([`Announce::same`]). It is
/// also how stale a chain a relay can replay: a route it had up to this
/// long ago, never a cheaper link than its upstream measured. Four of
/// Babel's 16 s periods.
pub const ATTEST_EPOCH: u64 = 64_000;
/// A relay re-signs its hop for a neighbour within an epoch only when the
/// chain below it changed, or its cost or its link fell by more than
/// 1/this (it may advertise up to that much over its cost meanwhile:
/// measured costs jitter, and each change would cost a chain).
const RESIGN_FRACTION: u32 = 8;
/// Changed origins remembered before `tick` redoes all of them instead.
const DIRTY_MAX: usize = 1024;
/// Frames waiting for a lookup or an internet dial: per key, keys, and how long.
const PENDING_FRAMES: usize = 32;
const PENDING_KEYS: usize = 256;
const PENDING_TIMEOUT: Time = 8_000;
/// How long a looked-up record (or the absence of one) is trusted.
const REACH_TTL: Time = 60_000;
const NO_RECORD_TTL: Time = 20_000;
/// After that, for this long, a record is looked up again on use while a
/// hop to one of its gateways that is up keeps carrying the traffic.
const REACH_STALE: Time = 60_000;
/// An internet hop nobody used for this long is hung up.
pub const INTERNET_IDLE: Time = 60_000;
/// A dial that hasn't come back after this long has failed.
const DIAL_GIVE_UP: Time = 15_000;
/// After a failed dial, the peer isn't dialled again for this long,
/// doubling with each failure up to the maximum.
const DIAL_BACKOFF_MIN: Time = 2_000;
const DIAL_BACKOFF_MAX: Time = 60_000;
/// A device without the internet republishes its record this often (and
/// when its gateways change, at most every `REACH_MIN_GAP`).
pub const REACH_REFRESH: Time = 10 * 60_000;
/// Records are valid this long (the origin refreshes well before).
pub const REACH_LIFETIME: Time = 30 * 60_000;
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
pub type Set<K> = HashSet<K, BuildHasherDefault<Fnv>>;

/// What a new direct neighbour is told at once, besides our own
/// announcement. Babel sends a new neighbour a full update instead of
/// letting it wait for the next periodic one; with long periods that is
/// what keeps discovery fast when devices meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Greet {
    /// Only our own announcement.
    Own,
    /// Our routes to direct neighbours (2 hops for it) and to gateways.
    Near,
    /// Every route it may hear (each within its announcement's scope).
    All,
}

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
    /// Hops a frame or an announcement may travel. Routes follow the
    /// cheapest path, which can be a hop or two longer than the fewest
    /// hops: 10 covers devices 8 radio hops away.
    pub max_hops: u8,
    /// How often this device announces itself (ms). Routes don't depend on
    /// it to notice a lost link (hop connections time out in seconds and
    /// trigger retractions), only to refresh: Babel's 16 s.
    pub announce_every: Time,
    /// Fisheye scoping (off: every announcement floods the full scope).
    pub fisheye: bool,
    /// With fisheye: announce to the full scope every this many periods
    /// (far routes refresh, and expire, this much slower).
    pub far_every: u64,
    /// What a new direct neighbour is sent at once.
    pub greet: Greet,
    /// Flood reduction in dense neighbourhoods: skip a rebroadcast heard 3
    /// times. Made for broadcast radios, where those 3 copies reached our
    /// neighbours too; over unicast hops they reached theirs, and devices
    /// get left out (docs/SIMULATION.md §4, finding 1). Off by default.
    pub flood_reduction: bool,
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
    /// Announcements remembered as checked (a 32-byte digest of everything
    /// signed and the signature: not the hops and cost filled in on the
    /// way). A simulator with stubbed signatures keeps this small: it is
    /// most of a router's memory.
    pub verified_max: usize,
    /// Seed for jitter (deterministic simulations).
    pub seed: u64,
    /// Routing defences that need no wire change ([`Defences`]) ...
    pub defences: Defences,
    /// ... and how much costlier, in percent, a route through a relay
    /// ranks per step it is from our spaces ([`Defences::affinity`]).
    pub affinity_step: u16,
    /// Signed route attestations with each hop's measured cost bound in
    /// (`ROUTE_ATTEST`, `docs/ROUTING.md` §6 item 13): send them to
    /// neighbours that have it ([`Router::set_attests`]), check the ones we
    /// get, and rank routes without one behind those with.
    pub attest: bool,
    /// With `attest`: send a neighbour that holds our chain for an origin
    /// (this epoch, [`ATTEST_EPOCH`]) the origin's refreshes without it
    /// ([`Announce::same`]). Off: every copy carries its chain (what the
    /// simulator's liars do, re-signing each lie).
    pub chain_reuse: bool,
}

/// Defences against lying relays that need no wire change
/// (`docs/ROUTING.md` §6, item 15). Each can be turned off on its own
/// (`Config::tune`), which is how the simulator measures them one at a
/// time. None of them changes which routes are feasible or what an
/// advertisement says about its route (its own hops and cost): they rank
/// feasible routes (all loop-free, Babel), and so choose which one we use
/// and advertise, decide when evidence counts, or pace what we send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Defences {
    /// A next hop suspected for several destinations is avoided for all.
    pub aggregate: bool,
    /// A sudden, much cheaper route claimed by one neighbour alone waits
    /// before it displaces the incumbent.
    pub corroborate: bool,
    /// Routes through relays far from our spaces' members rank costlier
    /// ([`Router::set_affinity`]). Off by default: in the simulator it
    /// bought delivery under plausible liars with longer routes everywhere
    /// else (`docs/ROUTING.md` §6, item 15).
    pub affinity: bool,
    /// Relayed announcements are paced to a share of each hop's capacity.
    pub budget: bool,
}

impl Defences {
    pub const ALL: Defences = Defences { aggregate: true, corroborate: true, affinity: true, budget: true };
    pub const NONE: Defences = Defences { aggregate: false, corroborate: false, affinity: false, budget: false };
    /// What the simulator showed helps without costing elsewhere.
    pub const DEFAULT: Defences = Defences { affinity: false, ..Defences::ALL };
}

impl Default for Defences {
    fn default() -> Self {
        Defences::DEFAULT
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            relay: true,
            relay_rate_per_neighbour: 1 << 20,
            relay_rate_total: 4 << 20,
            routes: 3,
            max_hops: 10,
            announce_every: 16_000,
            fisheye: true,
            far_every: FAR_EVERY,
            greet: Greet::All,
            flood_reduction: false,
            gateway: true,
            gateway_rate: 2 << 20,
            gateways: 2,
            max_internet_hops: 256,
            max_records: 1024,
            verified_max: VERIFIED_MAX,
            seed: 0x6d79_6365_6c21,
            defences: Defences::default(),
            affinity_step: AFFINITY_STEP,
            attest: true,
            chain_reuse: true,
        }
    }
}

impl Config {
    /// Settings from `key=value` pairs, for simulations and benchmarks:
    /// `every` (ms), `far` (periods), `hops`, `greet` (own, near, all), `fisheye`
    /// and `reduction` (on, off); the defences ([`Defences`]) all at once,
    /// `defences` (all, default, none), or one by one: `aggregate`, `corroborate`,
    /// `affinity`, `budget` (on, off); `affinity_step` (percent); `attest`
    /// (on, off: signed route attestations); `reuse` (on, off: refreshes
    /// without their chain, [`Config::chain_reuse`]); `verified` (signature
    /// cache size).
    pub fn tune(&mut self, s: &str) -> Result<(), String> {
        let on = |kv: &str, v: &str| match v {
            "on" => Ok(true),
            "off" => Ok(false),
            _ => Err(format!("{kv}: on or off")),
        };
        for kv in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("{kv}: expected key=value"))?;
            match (k, v) {
                ("every", n) => self.announce_every = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                ("far", n) => self.far_every = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                ("hops", n) => self.max_hops = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                ("greet", "own") => self.greet = Greet::Own,
                ("greet", "near") => self.greet = Greet::Near,
                ("greet", "all") => self.greet = Greet::All,
                ("fisheye", v) => self.fisheye = on(kv, v)?,
                ("reduction", v) => self.flood_reduction = on(kv, v)?,
                ("defences", "all") => self.defences = Defences::ALL,
                ("defences", "default") => self.defences = Defences::DEFAULT,
                ("defences", "none") => self.defences = Defences::NONE,
                ("aggregate", v) => self.defences.aggregate = on(kv, v)?,
                ("corroborate", v) => self.defences.corroborate = on(kv, v)?,
                ("affinity", v) => self.defences.affinity = on(kv, v)?,
                ("affinity_step", v) => self.affinity_step = v.parse().map_err(|_| format!("{kv}: not a number"))?,
                ("budget", v) => self.defences.budget = on(kv, v)?,
                ("attest", v) => self.attest = on(kv, v)?,
                ("reuse", v) => self.chain_reuse = on(kv, v)?,
                ("verified", n) => self.verified_max = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                _ => return Err(format!("{kv}: unknown knob")),
            }
        }
        Ok(())
    }
}

/// An originator announcement. `origin`, `seq`, `flags`, `scope`, `uplink`
/// and `name` are signed by the origin; `hops` and `cost` are filled in on
/// the way (`cost` = [`INFINITY`]: a retraction), and with `ROUTE_ATTEST`
/// signed by each hop too (`chain`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    pub hops: u8,
    pub cost: u32,
    pub origin: SignPk,
    pub seq: u64,
    pub flags: u8,
    /// Hops this announcement may travel (fisheye).
    pub scope: u8,
    /// A gateway's internet cost (0.1 ms units).
    pub uplink: u32,
    pub name: Arc<str>,
    /// The origin's signature over everything but `hops` and `cost`.
    pub sig: Sig,
    /// Signed route attestation (`ROUTE_ATTEST`), newest hop first: `None`,
    /// unattested. In an announcement received from neighbour `n` at `hops`
    /// = h it holds the hops at positions 0 (the origin) to h − 1, the last
    /// naming `n`, and, if we may pass it on, `n`'s own at position h naming
    /// us ([`Hop`]).
    pub chain: Option<Arc<Hop>>,
    /// Outgoing only: our own hop is still to be signed by the caller (the
    /// router holds no keys), naming the receiver, with this link cost: a
    /// [`Hop`] at position `hops` advertising `cost`, pushed onto `chain`
    /// ([`Announce::signed_by`]).
    pub sign_link: Option<u32>,
    /// Attested by the chain its sender last sent us for this origin, in
    /// this announcement's epoch ([`ATTEST_EPOCH`]), which travels again
    /// only when something in it changed (`chain` is then `None`). Its
    /// receiver checks the claim against that chain as it held it: the
    /// sender may advertise more than its hop signed, never less.
    pub same: bool,
}

impl Announce {
    /// With the hop the caller signed for it ([`Announce::sign_link`]).
    pub fn signed_by(mut self, signer: SignPk, sig: Sig) -> Announce {
        if let Some(link) = self.sign_link.take() {
            let prev = self.chain.take();
            self.chain = Some(Arc::new(Hop { signer, cost: self.cost, link, sig, prev }));
        }
        self
    }

    /// The hops of its chain.
    pub fn chain_len(&self) -> usize {
        self.chain.as_ref().map_or(0, |c| c.len())
    }

    /// It goes attested: with a chain, a hop to sign, or [`Announce::same`].
    pub fn attested(&self) -> bool {
        self.chain.is_some() || self.sign_link.is_some() || self.same
    }
}

/// One hop of a route attestation (`ROUTE_ATTEST`, `docs/ROUTING.md` §6
/// item 13). The device at position `pos` of a route (0: the origin) signs
/// the origin, the announcement's epoch ([`attest_epoch`]), `pos`, the cost
/// it advertises, the neighbour it sends to, and its own measured cost to
/// that neighbour ([`hop_signed`]). The origin's own signature covers the
/// rest (the seqno among it). The next hop may advertise no less than
/// `cost + link`: no device can claim a cheaper link than the device
/// upstream of it measured, nor a shorter chain than it was sent (the
/// origin signs for its real neighbours), nor reuse a hop naming someone
/// else.
///
/// A persistent list, newest hop first: the copies a relay sends its
/// neighbours share all but their own last hop.
#[derive(Debug, PartialEq, Eq)]
pub struct Hop {
    pub signer: SignPk,
    /// What the signer advertised (0 for the origin).
    pub cost: u32,
    /// Its measured cost to the next hop, [`HOP_PENALTY`] included.
    pub link: u32,
    pub sig: Sig,
    pub prev: Option<Arc<Hop>>,
}

impl Hop {
    /// Hops in the chain ending here.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Never: a chain has at least this hop.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// This hop, then the ones before it (toward the origin).
    pub fn iter(&self) -> impl Iterator<Item = &Hop> {
        std::iter::successors(Some(self), |h| h.prev.as_deref())
    }
}

/// A signature the router asks its caller to check: it holds no keys and
/// does no signature cryptography (`wire::verify` checks Ed25519; a
/// simulator answers from a stub).
#[derive(Clone, Copy, Debug)]
pub enum Check<'a> {
    /// The origin's signature over everything but `hops` and `cost`.
    Origin(&'a Announce),
    /// Hop `pos` of the announcement's chain, naming `next`: the hop after
    /// it, or the receiver.
    Hop { ann: &'a Announce, hop: &'a Hop, pos: u8, next: SignPk },
}

/// The attestation epoch of `origin`'s seqno `seq` ([`ATTEST_EPOCH`]), each
/// origin's epochs offset by its key so that not every chain in a mesh is
/// re-signed at once.
pub fn attest_epoch(origin: &SignPk, seq: u64) -> u64 {
    let offset = u64::from_be_bytes(origin.0[..8].try_into().unwrap_or_default()) % ATTEST_EPOCH;
    seq.saturating_add(offset) / ATTEST_EPOCH
}

/// What hop `pos` of an attestation signs (after its context string,
/// `wire.rs`): the origin, the epoch, `pos`, the cost the hop advertises,
/// the neighbour it names and its measured cost to it.
pub fn hop_signed(origin: &SignPk, epoch: u64, pos: u8, cost: u32, next: &SignPk, link: u32) -> [u8; 81] {
    let mut m = [0u8; 81];
    m[..32].copy_from_slice(&origin.0);
    m[32..40].copy_from_slice(&epoch.to_be_bytes());
    m[40] = pos;
    m[41..45].copy_from_slice(&cost.to_be_bytes());
    m[45..77].copy_from_slice(&next.0);
    m[77..].copy_from_slice(&link.to_be_bytes());
    m
}

/// What `hop`, at position `pos` of `ann`'s chain and naming `next`, signed.
pub fn hop_message(ann: &Announce, hop: &Hop, pos: u8, next: &SignPk) -> [u8; 81] {
    hop_signed(&ann.origin, attest_epoch(&ann.origin, ann.seq), pos, hop.cost, next, hop.link)
}

/// What our own hop on `a` signs for `to` ([`Announce::sign_link`]).
pub fn own_hop_message(a: &Announce, to: &SignPk, link: u32) -> [u8; 81] {
    hop_signed(&a.origin, attest_epoch(&a.origin, a.seq), a.hops, a.cost, to, link)
}

/// The signature cache's key for a checked hop: what it signed and the
/// signature, so any change is checked again. (Hops sign an epoch, not a
/// seqno: the origin's refreshes within it hit the cache.)
fn hop_id(ann: &Announce, pos: u8, hop: &Hop, next: &SignPk) -> Hash32 {
    static KEYED: std::sync::LazyLock<Digest> = std::sync::LazyLock::new(|| Digest::new("mycel/v0/mesh-verified-hop"));
    let mut d = KEYED.clone();
    d.update(&hop.signer.0).update(&hop_message(ann, hop, pos, next)).update(&hop.sig.0);
    d.finalize()
}

/// What checking a chain found.
enum Verdict {
    /// Every hop checks out: the link cost its sender measured to us, if it
    /// signed its own hop.
    Attested(u32),
    /// A claim no honest chain carries: a hop advertising less than the
    /// hop upstream of it plus the link that one measured, a bad
    /// signature, or a malformed chain. Its sender lied.
    Lie,
    /// Over the sender's signature budget: dropped, not judged.
    Limited,
    /// A path through us (or through one device twice): a loop, not a lie.
    Loop,
}

/// Insert into a map kept at most [`FEEDBACK_MAX`] long (an arbitrary entry
/// makes way: these are hints, rebuilt by the next packets).
fn bounded_insert<V>(m: &mut Map<SignPk, V>, k: SignPk, v: V) {
    if m.len() >= FEEDBACK_MAX
        && !m.contains_key(&k)
        && let Some(old) = m.keys().next().copied()
    {
        m.remove(&old);
    }
    m.insert(k, v);
}

/// A relayed announcement (not a retraction) whose hops and cost no honest
/// relay can produce: each hop adds one hop and at least [`MIN_HOP_COST`],
/// and only the origin itself sends zero hops.
fn implausible(from: &SignPk, a: &Announce) -> bool {
    a.cost != INFINITY && *from != a.origin && (a.hops == 0 || a.cost < MIN_HOP_COST.saturating_mul(a.hops as u32))
}

/// What the signature cache keeps of a checked announcement: a digest of
/// every signed field and of the signature itself, so a change to any of
/// them is checked again; the hops and cost filled in on the way are left
/// out. 32 bytes, where the fields (with the name) are about three times
/// that.
fn verified_id(a: &Announce) -> Hash32 {
    static KEYED: std::sync::LazyLock<Digest> =
        std::sync::LazyLock::new(|| Digest::new("mycel/v0/mesh-verified-announce"));
    let mut d = KEYED.clone();
    d.update(&a.origin.0)
        .update(&a.seq.to_be_bytes())
        .update(&[a.flags, a.scope])
        .update(&a.uplink.to_be_bytes())
        .update(&(a.name.len() as u64).to_be_bytes())
        .update(a.name.as_bytes())
        .update(&a.sig.0);
    d.finalize()
}

/// The fields of our next announcement, for the caller to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origination {
    pub seq: u64,
    pub flags: u8,
    pub scope: u8,
    pub uplink: u32,
}

/// "I need an announcement of `origin` newer than `seq`."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqReq {
    pub origin: SignPk,
    pub seq: u64,
    pub hops: u8,
}

/// One packet (or a fragment of one) on its way to `dst`.
#[derive(Clone, Debug)]
pub struct Frame {
    pub ttl: u8,
    /// The waypoint has been passed; now heading for `dst`.
    pub reached: bool,
    /// For the router at `dst` (e.g. a record to publish), not for QUIC.
    pub control: bool,
    /// Flag bits this build doesn't assign (`wire::F_EXTENSIONS`): carried
    /// unchanged to the destination, which ignores them.
    pub ext: u8,
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
    /// Send a seqno request to neighbour `to`.
    SeqReq { to: SignPk, req: SeqReq },
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
    /// We have no internet: publish a record naming these gateways, each
    /// with our mesh cost to it.
    PublishReach { gateways: Vec<(SignPk, u32)> },
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
    /// Over a neighbour's announcement rate, or an origin's flood rate.
    pub announcements_limited: u64,
    /// With a cost no honest relay can send (a route through it is a lie),
    /// or from a neighbour distrusted for one.
    pub announcements_implausible: u64,
    /// Neighbours caught lying about routes (not routed through for a while).
    pub neighbours_distrusted: u64,
    /// Next hops suspected for a destination after our packets to it went
    /// unacknowledged through them ([`Router::feedback`]).
    pub hops_suspected: u64,
    /// Next hops avoided for every destination after suspicions for
    /// several ([`Defences::aggregate`]).
    pub hops_shunned: u64,
    /// Relayed announcements that waited for their hop's control budget
    /// ([`Defences::budget`]), and those dropped from a full queue or
    /// replaced there by a newer one.
    pub announcements_deferred: u64,
    pub announcements_shed: u64,
    /// Rebroadcasts skipped as redundant (flood reduction).
    pub announcements_suppressed: u64,
    /// Announcements accepted with a verified attestation chain ...
    pub announcements_attested: u64,
    /// ... signatures checked (the origin's and each hop's), and those the
    /// cache spared ...
    pub signatures_checked: u64,
    pub signatures_cached: u64,
    /// ... and chains refused as lies (their senders are distrusted).
    pub chains_refused: u64,
    /// Refreshes attested by the chain we held from their sender
    /// ([`Announce::same`]), those we didn't hold one for (taken
    /// unattested, the chain asked for again), and refreshes we sent
    /// without their chain.
    pub chains_reused: u64,
    pub chains_unheld: u64,
    pub chains_elided: u64,
    /// Routes withdrawn at once on a loss, and fresh-seqno requests sent.
    pub retractions_sent: u64,
    pub seqreqs_sent: u64,
    /// Routes refused by the feasibility condition (would risk a loop).
    pub infeasible: u64,
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
    /// Frames dropped because their next hop's dial failed recently.
    pub dropped_backoff: u64,
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
    /// Hop cost (0.1 ms units, smoothed); 0 = not measured yet.
    cost: u32,
    budget: Bucket,
    ogm_budget: Bucket,
    last_used: Time,
    /// Relayed announcements to it: their budget ([`Defences::budget`]) and
    /// those waiting for it.
    ctl: Bucket,
    ctl_q: Vec<Announce>,
    /// Whether it takes signed route attestations (`ROUTE_ATTEST`).
    attests: Attests,
    /// Signature checks its attested announcements may still cost us (and
    /// chains it asks us to sign again).
    verify_budget: Bucket,
    /// Which of our hop connections to it this is: what it holds of the
    /// chains we sent ([`Sent`]) went with the last one.
    session: u64,
}

/// The attested announcement we last sent a neighbour for an origin, which
/// it holds ([`Announce::same`]): refreshes go without the chain while
/// nothing in it would change.
#[derive(Clone, Debug)]
struct Sent {
    session: u64,
    epoch: u64,
    /// The chain we extended (`None`: our own announcement) ...
    base: Option<Arc<Hop>>,
    /// ... the cost we advertised, and the link our hop signed (`None`: we
    /// signed no hop of our own, it won't pass it on).
    cost: u32,
    link: Option<u32>,
}

/// A neighbour's `ROUTE_ATTEST` capability, as its hop hello said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attests {
    No,
    /// Its hello is on the way (since then): its greeting waits for it.
    Pending(Time),
    Yes,
}

impl Nb {
    fn new(cfg: &Config, now: Time) -> Self {
        let rate = cfg.relay_rate_per_neighbour as f64;
        let mut budget = Bucket::new(rate, rate);
        budget.at = now;
        let mut ogm_budget = Bucket::new(OGM_RATE, OGM_RATE * 4.0);
        ogm_budget.at = now;
        let mut ctl = Self::control_bucket(0);
        ctl.at = now;
        let mut verify_budget = Bucket::new(VERIFY_RATE, VERIFY_RATE * 4.0);
        verify_budget.at = now;
        Nb {
            direct: false,
            up: false,
            cost: 0,
            budget,
            ogm_budget,
            last_used: now,
            ctl,
            ctl_q: Vec::new(),
            attests: Attests::No,
            verify_budget,
            session: 0,
        }
    }

    /// Its greeting waits for its capability hello.
    fn hello_pending(&self, now: Time) -> bool {
        matches!(self.attests, Attests::Pending(t) if now < t + HELLO_WAIT)
    }

    fn hop_cost(&self) -> u32 {
        (if self.cost == 0 { DEFAULT_COST } else { self.cost }).saturating_add(HOP_PENALTY)
    }

    /// The control budget for a hop of this cost: its cost is the time to
    /// move 64 KiB over it (and its round trip), so its capacity is about
    /// 64 KiB / cost. Unmeasured (0): as the slowest radio. The burst, and
    /// the cap on the rate, are what the neighbour accepts from us.
    fn control_bucket(cost: u32) -> Bucket {
        let cost = if cost == 0 { UNMEASURED_CONTROL_COST } else { cost };
        // (in bytes of unattested announcements: attested ones, larger,
        // take more of it, `wire::wire_len`)
        let accepted = OGM_RATE * ANN_BYTES as f64;
        let rate = (CONTROL_SHARE * 65_536.0 * 10_000.0 / cost as f64).min(accepted);
        Bucket::new(rate, accepted * 4.0)
    }

    fn internet(&self) -> bool {
        self.up && !self.direct
    }
}

/// What we heard about one origin through one neighbour.
#[derive(Clone, Copy, Debug)]
struct Via {
    seq: u64,
    /// The neighbour's advertised cost (for the feasibility condition) ...
    adv: u32,
    /// ... and ours through it.
    cost: u32,
    hops: u8,
    at: Time,
    /// When this neighbour's claim became a sudden shortcut
    /// ([`Defences::corroborate`]): under 1/[`CORROBORATE_FACTOR`] of every
    /// other usable route's cost, when it first gave us a route to the
    /// origin (since it last lost it) or when its cost fell to that from no
    /// cheaper than all of them. `None`: it never did.
    since: Option<Time>,
    /// It came with a verified attestation chain (kept in
    /// [`Origin::chains`]).
    attested: bool,
}

struct Origin {
    newest: u64,
    /// The newest announcement itself (passed on with our cost added),
    /// without its chain.
    latest: Announce,
    via: Vec<(SignPk, Via)>,
    /// The attestation chain each attested route came with, by neighbour,
    /// and its epoch (what we extend when we advertise it).
    chains: Vec<(SignPk, Arc<Hop>, u64)>,
    /// What each neighbour holds of the chains we sent it ([`Sent`]).
    sent: Vec<(SignPk, Sent)>,
    /// The epoch (+ 1) in which we last asked a neighbour for a chain it
    /// sent a refresh of without our holding it.
    chain_asked: u64,
    /// Newest sequence number we have passed on (or decided not to), and
    /// when we last did.
    forwarded: u64,
    flooded: Option<Time>,
    /// When to pass on the newest one.
    pending: Option<Time>,
    /// Feasibility distance: the (seq, cost) we last advertised.
    fd: Option<(u64, u32)>,
    /// Neighbours we heard the newest seq from, with their advertised cost.
    heard: Vec<(SignPk, u32)>,
    /// We told our neighbours we have no route (until a feasible one returns).
    retracted: bool,
    last_req: Option<Time>,
    /// The seqno request we last forwarded: (seq, hops left), to forward
    /// each once (again only if a later copy can travel further).
    req_forwarded: (u64, u8),
    /// Last announcement heard; the entry (and its feasibility distance)
    /// outlives its routes until [`Router::gc_after`], as in Babel.
    seen: Time,
}

impl Origin {
    fn feasible(&self, v: &Via) -> bool {
        match self.fd {
            None => true,
            Some((s, c)) => v.seq > s || (v.seq == s && v.adv < c),
        }
    }

    /// The chain the route through `n` came with.
    fn chain_of(&self, n: &SignPk) -> Option<&Arc<Hop>> {
        self.chains.iter().find(|(k, ..)| k == n).map(|(_, c, _)| c)
    }

    fn set_chain(&mut self, n: SignPk, chain: Option<(Arc<Hop>, u64)>) {
        self.chains.retain(|(k, ..)| *k != n);
        if let Some((c, epoch)) = chain {
            self.chains.push((n, c, epoch));
        }
    }

    /// Forget the chains of routes that are gone.
    fn prune_chains(&mut self) {
        let via = &self.via;
        self.chains.retain(|(k, ..)| via.iter().any(|(n, _)| n == k));
    }
}

/// The chain we hold from `from` that attests `a`, a refresh it sent without
/// one ([`Announce::same`]): of `a`'s epoch, as long as `a`'s hops, ending
/// with `from`'s own hop or naming `from`, and claiming no less than that
/// allows (the sender may advertise more than its hop signed, never less).
fn held_chain(chains: &[(SignPk, Arc<Hop>, u64)], from: &SignPk, a: &Announce) -> Option<Arc<Hop>> {
    let (_, c, epoch) = chains.iter().find(|(k, ..)| k == from)?;
    let h = a.hops as usize;
    let n = c.len();
    let fits = if n == h + 1 {
        c.signer == *from && a.cost >= c.cost
    } else {
        n == h && h > 0 && u64::from(a.cost) >= u64::from(c.cost) + u64::from(c.link)
    };
    (*epoch == attest_epoch(&a.origin, a.seq) && fits).then(|| c.clone())
}

struct Reasm {
    buf: Vec<u8>,
    got: usize,
    at: Time,
    waypoint: SignPk,
    control: bool,
}

struct Reach {
    /// (gateway, its mesh cost to the target). Empty: no record, reach the
    /// target itself over the internet.
    gateways: Vec<(SignPk, u32)>,
    /// Trusted until then; kept [`REACH_STALE`] longer (see `next_hop`).
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
    /// The peer to dial failed recently (backing off).
    Unreachable,
}

/// Where data for a destination can go *now* (custody transfer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toward {
    /// Hand it to this neighbour (a mesh hop, or an internet hop that is up).
    Hop(SignPk),
    /// A lookup or a dial is under way; ask again shortly.
    Soon,
    /// No forward progress possible right now.
    Nowhere,
    /// Not over the internet either: it has no reachability record and
    /// dialling it failed (it isn't on the internet). Only the mesh, or
    /// someone carrying it there, can get it there.
    Unreachable,
}

/// Gateways to publish: with our mesh cost to each, and their sorted keys.
type GatewayPick = (Vec<(SignPk, u32)>, Vec<SignPk>);

/// One device's router. See the module docs.
pub struct Router {
    me: SignPk,
    cfg: Config,
    internet: bool,
    uplink: u32,
    rng: u64,
    nbs: BTreeMap<SignPk, Nb>,
    origins: Map<SignPk, Origin>,
    /// Waypoints offered to QUIC per destination.
    published: Map<SignPk, Vec<SignPk>>,
    reasm: Map<(SignPk, u32), Reasm>,
    verified: Set<Hash32>,
    total_budget: Bucket,
    gateway_budget: Bucket,
    reach: Map<SignPk, Reach>,
    resolving: Set<SignPk>,
    dialing: Map<SignPk, Time>,
    pending: Map<SignPk, Pending>,
    /// Peers whose dial failed: (not before, current backoff).
    backoff: Map<SignPk, (Time, Time)>,
    my_gateways: Vec<SignPk>,
    reach_due: Time,
    last_reach: Option<Time>,
    /// Gateway side: when we last accepted each origin's record.
    records: Map<SignPk, Time>,
    /// Neighbours caught lying about routes, until when we ignore the
    /// routes they relay.
    distrusted: Map<SignPk, Time>,
    /// The next hop our own packets to each destination last took, and
    /// when, for [`Router::feedback`] ...
    sent_via: Map<SignPk, (SignPk, Time)>,
    /// ... timeouts in a row with nothing acknowledged through it, since
    /// when ...
    strikes: Map<SignPk, (SignPk, u8, Time)>,
    /// ... and the next hops suspected for a destination, until when.
    suspects: Map<SignPk, Vec<(SignPk, Time)>>,
    /// Next hops avoided for every destination, until when
    /// ([`Defences::aggregate`]) ...
    shunned: Map<SignPk, Time>,
    /// ... the destinations each carried acknowledgements for lately ...
    vouched: Map<SignPk, Vec<(SignPk, Time)>>,
    /// ... and the hop each destination last acknowledged through, and
    /// when (evidence it was alive while another hop was silent).
    acked_via: Map<SignPk, (SignPk, Time)>,
    /// Neighbours' distance from us in our spaces' membership graph
    /// ([`Router::set_affinity`]).
    affinity: Map<SignPk, u8>,
    /// Neighbours with announcements waiting for their control budget.
    ctl_waiting: Vec<SignPk>,
    own: Option<Announce>,
    /// What each neighbour holds of our own announcement's chain ([`Sent`]).
    own_sent: Vec<(SignPk, Sent)>,
    /// Hop connections counted, for [`Nb::session`].
    sessions: u64,
    seq: u64,
    originated: u64,
    next_announce: Time,
    last_forced: Option<Time>,
    last_greet: Option<Time>,
    /// New direct neighbours waiting to be greeted, in order.
    greet_q: VecDeque<SignPk>,
    force_full: bool,
    next_id: u32,
    stats: Stats,
    out: Vec<Out>,
    // Incremental housekeeping: `tick` runs every 10–20 ms, so it only
    // revisits what changed. Each is exact (the same result as a full scan
    // every tick), never a sampling.
    /// Origins whose pending rebroadcast is due at that time (stale entries
    /// are skipped when popped).
    flush_q: BinaryHeap<Reverse<(Time, SignPk)>>,
    /// No route expires before this (a lower bound; exact after a scan).
    next_expiry: Time,
    /// No origin can be forgotten before this unless `gc_check` is set.
    next_gc: Time,
    gc_check: bool,
    /// Nothing in `reasm`, `pending`, `reach`, `dialing`, `records` or the
    /// idle internet hops times out before this (a lower bound).
    next_sweep: Time,
    /// Origins whose routes may have changed since the last `publish`.
    dirty: Vec<SignPk>,
    all_dirty: bool,
    /// `gateway_routes` kept per gateway: (total, mesh, first hop), for the
    /// origins not in `gw_dirty`; valid while no route can have expired
    /// (`next_expiry`).
    gw_table: Map<SignPk, (u32, u32, SignPk)>,
    gw_dirty: Vec<SignPk>,
    gw_all_dirty: bool,
    /// `gw_table` sorted as `gateway_routes` sorts (None: rebuild).
    gw_sorted: Option<Vec<(SignPk, u32, u32, SignPk)>>,
    /// What `choose_gateways` picks from `gw_sorted`.
    gw_pick: Option<GatewayPick>,
}

impl Router {
    pub fn new(me: SignPk, cfg: Config) -> Router {
        let total = cfg.relay_rate_total as f64;
        let gw = cfg.gateway_rate as f64;
        let rng = (cfg.seed ^ u64::from_le_bytes(me.0[..8].try_into().unwrap_or([7; 8]))) | 1;
        Router {
            me,
            internet: false,
            uplink: 0,
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
            backoff: Map::default(),
            my_gateways: Vec::new(),
            reach_due: 0,
            last_reach: None,
            records: Map::default(),
            distrusted: Map::default(),
            sent_via: Map::default(),
            strikes: Map::default(),
            suspects: Map::default(),
            shunned: Map::default(),
            vouched: Map::default(),
            acked_via: Map::default(),
            affinity: Map::default(),
            ctl_waiting: Vec::new(),
            own: None,
            own_sent: Vec::new(),
            sessions: 0,
            seq: 0,
            originated: 0,
            next_announce: 0,
            last_forced: None,
            last_greet: None,
            greet_q: VecDeque::new(),
            force_full: false,
            next_id: 0,
            stats: Stats::default(),
            out: Vec::new(),
            flush_q: BinaryHeap::new(),
            next_expiry: 0,
            next_gc: 0,
            gc_check: false,
            next_sweep: Time::MAX,
            dirty: Vec::new(),
            all_dirty: true,
            gw_table: Map::default(),
            gw_dirty: Vec::new(),
            gw_all_dirty: true,
            gw_sorted: None,
            gw_pick: None,
            cfg,
        }
    }

    /// `origin`'s routes (or its gateway status) may have changed.
    fn touch(&mut self, origin: SignPk) {
        // past a bound, redoing everything is as cheap (and the lists of a
        // device that never asks for gateways don't grow)
        if !self.all_dirty {
            if self.dirty.len() >= DIRTY_MAX {
                self.all_dirty = true;
                self.dirty.clear();
            } else {
                self.dirty.push(origin);
            }
        }
        if !self.gw_all_dirty {
            if self.gw_dirty.len() >= DIRTY_MAX {
                self.gw_all_dirty = true;
                self.gw_dirty.clear();
            } else {
                self.gw_dirty.push(origin);
            }
        }
    }

    /// A direct neighbour changed: any route may have.
    fn touch_all(&mut self) {
        self.all_dirty = true;
        self.dirty.clear();
        self.gw_all_dirty = true;
        self.gw_dirty.clear();
    }

    /// When a route heard at `at` over `hops` expires.
    fn expires(&self, at: Time, hops: u8) -> Time {
        at + self.cfg.announce_every * 7 / 2 * self.scale(hops)
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

    /// Far routes (beyond the near scope) refresh, and expire, this much slower.
    fn scale(&self, hops: u8) -> u64 {
        if self.cfg.fisheye && hops > NEAR_SCOPE { self.cfg.far_every.max(1) } else { 1 }
    }

    /// How long an origin without routes is remembered (its feasibility
    /// distance keeps stale announcements from forming loops meanwhile).
    fn gc_after(&self) -> Time {
        self.cfg.announce_every * 3 * self.cfg.far_every.max(1) * 2
    }

    /// A via's seqno is recent enough, and it was heard recently enough.
    fn fresh(&self, o: &Origin, v: &Via, now: Time) -> bool {
        let k = self.scale(v.hops);
        v.seq + self.cfg.announce_every * 3 * k >= o.newest
            && now.saturating_sub(v.at) < self.cfg.announce_every * 7 / 2 * k
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

    /// Our internet cost (measured by the driver), announced as a gateway.
    pub fn set_uplink(&mut self, units: u32) {
        self.uplink = units;
    }

    /// How far devices are from us in the membership graph of our spaces
    /// (1: a member of a space we are in), for [`Defences::affinity`]: a
    /// route ranks [`Config::affinity_step`] percent costlier per step its
    /// next hop is beyond 1, and one through a device not listed as if it were
    /// [`AFFINITY_UNKNOWN`] away. An empty table (no spaces) prefers nobody.
    /// Whanau's and SybilLimit's argument: what an attacker can then do is
    /// bounded by the members who vouch for its devices, not by how many it
    /// runs. It only ranks feasible routes, and so which route we
    /// advertise, never its content (its hops and cost are its own).
    /// Returns whether the table changed.
    pub fn set_affinity(&mut self, table: impl IntoIterator<Item = (SignPk, u8)>) -> bool {
        let table: Map<SignPk, u8> =
            table.into_iter().filter(|(k, _)| *k != self.me).map(|(k, d)| (k, d.max(1))).collect();
        if table == self.affinity {
            return false;
        }
        self.affinity = table;
        self.touch_all();
        true
    }

    /// `peer`'s distance in the table [`Router::set_affinity`] last set.
    pub fn affinity(&self, peer: &SignPk) -> Option<u8> {
        self.affinity.get(peer).copied()
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
            self.touch_all();
        } else if let Some(n) = self.nbs.get_mut(&peer) {
            n.direct = false;
            if !n.up {
                self.nbs.remove(&peer);
            } else {
                // an internet hop now: it may go idle
                self.next_sweep = self.next_sweep.min(n.last_used + INTERNET_IDLE);
            }
            self.touch_all();
            self.lost_neighbour(peer, now);
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
        // a new connection: it holds none of the chains we sent before
        self.sessions += 1;
        n.session = self.sessions;
        let direct = n.direct;
        self.next_sweep = self.next_sweep.min(now + INTERNET_IDLE);
        if direct {
            self.touch_all();
        } else {
            self.touch(peer); // it is a neighbour now
        }
        self.stats.hop_connections += 1;
        self.dialing.remove(&peer);
        self.backoff.remove(&peer);
        if direct {
            if self.direct_up().all(|k| k == peer) {
                // our first neighbour: announce to the full scope now (what
                // we announced alone reached nobody)
                self.next_announce = self.next_announce.min(now);
                self.force_full = true;
            } else if let Some(a) = self.own_for(&peer) {
                self.push_announce(peer, a);
            }
            if self.cfg.greet != Greet::Own && self.cfg.relay && !self.greet_q.contains(&peer) {
                self.greet_q.push_back(peer);
            }
            self.greet_next(now);
        }
        self.release(peer, now);
    }

    /// Greet the next new neighbour waiting, if [`GREET_GAP`] has passed
    /// since the last greeting that told anyone anything.
    fn greet_next(&mut self, now: Time) {
        while self.last_greet.is_none_or(|t| now.saturating_sub(t) >= GREET_GAP) {
            // the first one ready: its capability hello came (or won't),
            // so the greeting can be attested if it takes that
            let ready = self.greet_q.iter().position(|p| self.nbs.get(p).is_none_or(|n| !n.hello_pending(now)));
            let Some(peer) = ready.and_then(|i| self.greet_q.remove(i)) else { return };
            if self.nbs.get(&peer).is_some_and(|n| n.up && n.direct) && self.greet(peer, now) > 0 {
                self.last_greet = Some(now);
            }
        }
    }

    /// Whether `peer` takes signed route attestations (`ROUTE_ATTEST` in
    /// both hop hellos): `None` while its hello is on the way (its greeting
    /// then waits for it, at most [`HELLO_WAIT`]). Without
    /// [`Config::attest`] nobody is sent any. A neighbour that turns out to
    /// take them gets our own announcement again, attested.
    pub fn set_attests(&mut self, peer: SignPk, attests: Option<bool>, now: Time) {
        if peer == self.me {
            return;
        }
        let cfg = &self.cfg;
        let n = self.nbs.entry(peer).or_insert_with(|| Nb::new(cfg, now));
        let before = n.attests;
        n.attests = match attests {
            Some(true) if self.cfg.attest => Attests::Yes,
            None if self.cfg.attest => Attests::Pending(now),
            _ => Attests::No,
        };
        if n.attests == Attests::Yes
            && before != Attests::Yes
            && n.up
            && n.direct
            && let Some(a) = self.own_for(&peer)
        {
            self.push_announce(peer, a);
        }
    }

    /// Whether `peer` takes signed route attestations.
    pub fn attests(&self, peer: &SignPk) -> bool {
        self.nbs.get(peer).is_some_and(|n| n.attests == Attests::Yes)
    }

    /// Our own announcement for `peer`: with our first hop to sign for it
    /// if it takes attestations.
    fn own_for(&self, peer: &SignPk) -> Option<Announce> {
        let mut a = self.own.clone()?;
        if let Some(n) = self.nbs.get(peer).filter(|n| n.attests == Attests::Yes) {
            a.sign_link = Some(n.hop_cost());
        }
        Some(a)
    }

    /// What we tell `to` of `origin` through our route `(n, via)` (at the
    /// newest seqno, as every caller checks): attested if `to` takes
    /// attestations and our route came with a chain we can extend (with our
    /// own hop for the caller to sign if `to` may pass it on; else the chain
    /// alone, which still bounds our claim); otherwise unattested (also when
    /// the chain would no longer fit in a datagram every hop carries).
    fn advert(&self, o: &Origin, n: &SignPk, via: &Via, to: &SignPk) -> Option<Announce> {
        let a = Announce { hops: via.hops, cost: via.cost, ..o.latest.clone() };
        let attesting = self.nbs.get(to).filter(|t| t.attests == Attests::Yes);
        if let Some(t) = attesting
            && via.attested
            && let Some(c) = o.chain_of(n).filter(|c| c.len() == via.hops as usize)
        {
            let own = via.hops.saturating_add(1) < o.latest.scope.min(self.cfg.max_hops);
            let attested = Announce { chain: Some(c.clone()), sign_link: own.then(|| t.hop_cost()), ..a.clone() };
            if super::wire::wire_len(&attested) < super::wire::MIN_QUIC_MTU {
                return Some(attested);
            }
        }
        Some(a)
    }

    /// Tell a new direct neighbour our current routes ([`Config::greet`])
    /// that it hasn't sent us itself, as a periodic rebroadcast would:
    /// newest seqno, our cost, within each announcement's scope. What is
    /// new to it travels on from there; what its other neighbours already
    /// have stops at it (it has forwarded that seqno). Advertising updates
    /// our feasibility distances, as in `flush_announcements`. Returns the
    /// routes sent.
    fn greet(&mut self, peer: SignPk, now: Time) -> usize {
        let mut sent = 0;
        let mut keys: Vec<SignPk> = self.origins.keys().filter(|k| **k != peer).copied().collect();
        keys.sort();
        for origin in keys {
            // never back where it came from
            let Some((n, via)) = self.best_route(&origin, now).filter(|(n, _)| *n != peer) else { continue };
            let max_hops = self.cfg.max_hops;
            let near = self.cfg.greet == Greet::Near;
            let Some(o) = self.origins.get(&origin) else { continue };
            let gateway = o.latest.flags & F_GATEWAY != 0;
            if via.seq != o.newest
                || via.hops >= o.latest.scope.min(max_hops)
                || (near && via.hops >= NEAR_SCOPE && !gateway)
                || o.heard.iter().any(|(k, _)| *k == peer)
            {
                continue;
            }
            let Some(a) = self.origins.get(&origin).and_then(|o| self.advert(o, &n, &via, &peer)) else { continue };
            let Some(o) = self.origins.get_mut(&origin) else { continue };
            o.fd = match o.fd {
                Some((s, c)) if s == o.newest => Some((s, c.min(via.cost))),
                _ => Some((o.newest, via.cost)),
            };
            o.retracted = false;
            self.send_announce(peer, a, now);
            sent += 1;
        }
        sent
    }

    pub fn hop_down(&mut self, peer: SignPk, now: Time) {
        let Some(n) = self.nbs.get_mut(&peer) else { return };
        n.up = false;
        n.ctl_q.clear();
        let direct = n.direct;
        if !direct {
            self.nbs.remove(&peer);
            self.touch(peer);
        } else {
            self.touch_all();
        }
        if let Some(p) = self.pending.remove(&peer) {
            self.stats.dropped_pending += p.frames.len() as u64;
        }
        self.lost_neighbour(peer, now);
    }

    /// Routes through `peer` are gone: retract (triggered update) whatever
    /// that leaves us without, and ask for fresh seqnos.
    fn lost_neighbour(&mut self, peer: SignPk, now: Time) {
        self.drop_routes_via(peer, false, now);
    }

    /// Forget the routes through `peer` (`but_its_own`: except the route to
    /// `peer` itself), then retract and ask for fresh seqnos as needed.
    fn drop_routes_via(&mut self, peer: SignPk, but_its_own: bool, now: Time) {
        let affected: Vec<SignPk> = self
            .origins
            .iter_mut()
            .filter(|(k, _)| !(but_its_own && **k == peer))
            .filter_map(|(k, o)| {
                let before = o.via.len();
                o.via.retain(|(n, _)| *n != peer);
                o.prune_chains();
                (o.via.len() != before).then_some(*k)
            })
            .collect();
        let mut affected = affected;
        affected.sort();
        if !affected.is_empty() {
            self.gc_check = true;
        }
        for origin in affected {
            self.touch(origin);
            self.after_loss(origin, Some(peer), now);
        }
    }

    pub fn dial_failed(&mut self, peer: SignPk, now: Time) {
        self.dialing.remove(&peer);
        if let Some(p) = self.pending.remove(&peer) {
            self.stats.dropped_pending += p.frames.len() as u64;
        }
        // don't hammer it: back off, doubling
        let wait = self.backoff.get(&peer).map_or(DIAL_BACKOFF_MIN, |(_, w)| (w * 2).min(DIAL_BACKOFF_MAX));
        self.backoff.insert(peer, (now + wait, wait));
        self.next_sweep = self.next_sweep.min(now + wait + DIAL_BACKOFF_MAX);
    }

    /// Measured hop cost in 0.1 ms units (smoothed here).
    pub fn set_cost(&mut self, peer: SignPk, units: u32) {
        if let Some(n) = self.nbs.get_mut(&peer) {
            // (at most the driver's cap, `mesh::hop_cost`, which leaves room
            // to add penalties; and in u64: a slow hop's cost times 7 can
            // exceed u32)
            let units = units.clamp(1, u32::MAX / 2);
            n.cost = if n.cost == 0 { units } else { ((u64::from(n.cost) * 7 + u64::from(units)) / 8) as u32 };
            // the control budget follows the hop's capacity
            n.ctl.rate = Nb::control_bucket(n.cost).rate;
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

    fn direct_up(&self) -> impl Iterator<Item = SignPk> + '_ {
        self.nbs.iter().filter(|(_, n)| n.up && n.direct).map(|(k, _)| *k)
    }

    // ───────────── announcements ─────────────

    pub fn announce_due(&self, now: Time) -> bool {
        now >= self.next_announce
    }

    /// The fields of our next announcement: a seqno (wall-clock ms,
    /// strictly increasing: a restarted device's announcements are newer
    /// than its old ones with nothing stored), our flags, the fisheye scope
    /// and our uplink cost.
    pub fn next_announce(&mut self, wall: u64) -> Origination {
        self.seq = wall.max(self.seq + 1);
        let full = !self.cfg.fisheye || self.originated.is_multiple_of(self.cfg.far_every.max(1)) || self.force_full;
        self.force_full = false;
        self.originated += 1;
        let scope = if full { self.cfg.max_hops } else { NEAR_SCOPE.min(self.cfg.max_hops) };
        let gateway = self.internet && self.cfg.gateway && self.cfg.relay;
        Origination {
            seq: self.seq,
            flags: if gateway { F_GATEWAY } else { 0 },
            scope,
            uplink: if gateway { self.uplink } else { 0 },
        }
    }

    /// Send our own (signed) announcement to every direct neighbour.
    pub fn originate(&mut self, ann: Announce, now: Time) {
        let every = self.cfg.announce_every;
        let jitter = self.rand() % (every / 4 + 1);
        self.next_announce = now + every - every / 8 + jitter;
        self.own = Some(Announce { chain: None, sign_link: None, same: false, ..ann });
        for pk in self.direct_up().collect::<Vec<_>>() {
            let Some(a) = self.own_for(&pk) else { continue };
            self.push_announce(pk, a);
        }
    }

    /// An announcement from a neighbour. `verify` checks a signature (the
    /// origin's, or a hop's of an attestation chain); it runs once per
    /// signed identity, after the cheap checks, and with a chain only for
    /// hops not checked before, within the neighbour's budget.
    pub fn on_announce(
        &mut self,
        from: SignPk,
        mut a: Announce,
        now: Time,
        wall: u64,
        mut verify: impl FnMut(Check<'_>) -> bool,
    ) {
        let jitter = 10 + self.rand() % 40;
        if a.origin != from && self.distrusted.get(&from).is_some_and(|t| now < *t) {
            self.stats.announcements_implausible += 1;
            // its route counts for nothing, but it has this seqno: don't
            // send it back (a cost no route can match: never "redundant")
            if let Some(o) = self.origins.get_mut(&a.origin)
                && a.seq == o.newest
                && a.cost != INFINITY
                && !o.heard.iter().any(|(k, _)| *k == from)
            {
                o.heard.push((from, INFINITY));
            }
            return;
        }
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
        let far_window = self.cfg.announce_every * 3 * self.cfg.far_every.max(1);
        if self.origins.get(&a.origin).is_some_and(|o| a.seq + far_window < o.newest) {
            self.stats.announcements_stale += 1;
            return;
        }
        if implausible(&from, &a) {
            self.distrust(from, now);
            return;
        }
        a.sign_link = None;
        let attest = self.cfg.attest && a.cost != INFINITY;
        let same = std::mem::take(&mut a.same) && attest;
        let sent = a.chain.take().filter(|_| attest);
        // a refresh without its chain: attested by the one we hold from its
        // sender, checked when it came (else taken unattested, and the
        // chain asked for again, below)
        let held = if same { self.origins.get(&a.origin).and_then(|o| held_chain(&o.chains, &from, &a)) } else { None };
        // the link cost its sender measured to us, if it signed for us
        let mut link = held.as_ref().map_or(0, |c| if c.len() > a.hops as usize { c.link } else { 0 });
        if let Some(c) = &sent {
            match self.check_chain(from, &a, c, &mut verify, now) {
                Verdict::Attested(l) => link = l,
                Verdict::Lie => {
                    self.stats.chains_refused += 1;
                    self.distrust(from, now);
                    return;
                }
                Verdict::Limited => {
                    self.stats.announcements_limited += 1;
                    return;
                }
                Verdict::Loop => return,
            }
        }
        // the origin's own signature: what binds the seqno (hops sign only
        // its epoch), attested or not
        if !self.check_origin(&a, &mut verify) {
            self.stats.announcements_forged += 1;
            if sent.is_some() {
                // it vouched for the chain it sent along
                self.stats.chains_refused += 1;
                self.distrust(from, now);
            }
            return;
        }
        let unheld = same && held.is_none();
        if held.is_some() {
            self.stats.chains_reused += 1;
        } else if unheld {
            self.stats.chains_unheld += 1;
        }
        let chain = sent.or(held);
        if a.cost == INFINITY {
            self.on_retraction(from, a.origin, a.seq, now);
            return;
        }
        let hops = a.hops.saturating_add(1);
        if hops > self.cfg.max_hops {
            return;
        }
        if chain.is_some() {
            self.stats.announcements_attested += 1;
        }
        // with its hop signed, our link costs what the costlier end measured:
        // a sender can't make us advertise less than it saw (bilateral)
        let cost = a.cost.saturating_add(hop_cost.max(link));
        let relay = self.cfg.relay;
        let forward_scope = a.scope.min(self.cfg.max_hops);
        let (seq, adv) = (a.seq, a.cost);
        let origin = a.origin;
        // [`Defences::corroborate`]: a claim much cheaper than every other
        // route is a sudden shortcut when it appears, and when it falls to
        // that from no cheaper than all of them (else a liar would first
        // offer a plausible route, wait, then drop its cost)
        let sudden = self.cfg.defences.corroborate
            && self.origins.get(&origin).is_some_and(|o| {
                let others =
                    o.via.iter().filter(|(k, w)| *k != from && self.usable(o, k, w, now)).map(|(_, w)| w.cost).min();
                let Some(c) = others else { return false };
                let was_cheapest = o.via.iter().any(|(k, old)| *k == from && old.cost < c);
                !was_cheapest && cost as u64 * CORROBORATE_FACTOR < c as u64
            });
        // before the update: it may stop being a gateway
        self.touch(origin);
        let expires = self.expires(now, hops);
        self.next_expiry = self.next_expiry.min(expires);
        let o = self.origins.entry(a.origin).or_insert_with(|| Origin {
            newest: 0,
            latest: a.clone(),
            via: Vec::new(),
            chains: Vec::new(),
            sent: Vec::new(),
            chain_asked: 0,
            forwarded: 0,
            flooded: None,
            pending: None,
            fd: None,
            heard: Vec::new(),
            retracted: false,
            last_req: None,
            req_forwarded: (0, 0),
            seen: now,
        });
        o.seen = now;
        if seq > o.newest {
            o.newest = seq;
            o.latest = a;
            o.heard.clear();
        }
        if seq == o.newest && !o.heard.iter().any(|(k, _)| *k == from) {
            o.heard.push((from, adv));
        }
        let attested = chain.is_some();
        let mut via = Via { seq, adv, cost, hops, at: now, since: sudden.then_some(now), attested };
        if !o.feasible(&via) {
            self.stats.infeasible += 1;
        }
        match o.via.iter_mut().find(|(k, _)| *k == from) {
            Some((_, v)) => {
                if !sudden {
                    via.since = v.since;
                }
                *v = via;
            }
            None => o.via.push((from, via)),
        }
        let epoch = attest_epoch(&origin, seq);
        o.set_chain(from, chain.map(|c| (c, epoch)));
        // a refresh whose chain we lack: asked for once an epoch (its sender
        // answers a request for a seqno it sent with its chain again)
        let ask = unheld && seq == o.newest && o.chain_asked != epoch + 1;
        if ask {
            o.chain_asked = epoch + 1;
        }
        if o.feasible(&via) {
            o.retracted = false;
        }
        if relay && seq == o.newest && seq > o.forwarded && o.pending.is_none() && hops < forward_scope {
            if o.flooded.is_some_and(|t| now.saturating_sub(t) < ORIGIN_GAP) {
                // an announcement storm: the route stands, the flood stops here
                o.forwarded = seq;
                self.stats.announcements_limited += 1;
            } else {
                // wait a little to hear the cheapest copy (and other relays'),
                // and desynchronize
                o.pending = Some(now + jitter);
                self.flush_q.push(Reverse((now + jitter, origin)));
            }
        }
        // after: it may have become one
        self.touch(origin);
        if ask {
            self.stats.seqreqs_sent += 1;
            self.out.push(Out::SeqReq { to: from, req: SeqReq { origin, seq, hops: 1 } });
        }
    }

    /// The origin's signature on `a`, checked once per signed identity.
    fn check_origin(&mut self, a: &Announce, verify: &mut impl FnMut(Check<'_>) -> bool) -> bool {
        let verified = verified_id(a);
        if self.verified.contains(&verified) {
            self.stats.signatures_cached += 1;
            return true;
        }
        self.stats.signatures_checked += 1;
        if !verify(Check::Origin(a)) {
            return false;
        }
        self.remember(verified);
        true
    }

    /// A signature checked: don't check it again (while the cache lasts).
    fn remember(&mut self, id: Hash32) {
        if self.verified.len() >= self.cfg.verified_max {
            self.verified.clear();
        }
        if self.cfg.verified_max > 0 {
            self.verified.insert(id);
        }
    }

    /// An attested announcement's chain, from neighbour `from` (see
    /// [`Announce::chain`] and [`Hop`]). Structure first, then what each hop
    /// may advertise, then the signatures of hops not checked before (those
    /// a copy through another neighbour shared are cached), within
    /// `from`'s budget. Everything a chain claims was checked by every
    /// honest device it passed (each checks the whole chain), so whatever
    /// fails here is its sender's doing: [`Verdict::Lie`].
    fn check_chain(
        &mut self,
        from: SignPk,
        a: &Announce,
        chain: &Arc<Hop>,
        verify: &mut impl FnMut(Check<'_>) -> bool,
        now: Time,
    ) -> Verdict {
        let h = a.hops as usize;
        let mut hops: Vec<&Hop> = chain.iter().take(MAX_CHAIN + 1).collect();
        if hops.len() > MAX_CHAIN {
            return Verdict::Lie;
        }
        hops.reverse(); // the origin first: position = index
        let n = hops.len();
        // with its sender's own hop (position h, naming us), or without it
        // (we may not pass it on; the last hop names the sender)
        let own = n == h + 1;
        if !(own || (n == h && h > 0)) {
            return Verdict::Lie;
        }
        if hops[0].signer != a.origin
            || hops[0].cost != 0
            || (own && (hops[h].signer != from || hops[h].cost != a.cost))
        {
            return Verdict::Lie;
        }
        // a path through us is a loop (a neighbour may answer a seqno
        // request with a route through the asker); through its sender or
        // one device twice, no honest chain goes
        let ends = if own { n - 1 } else { n };
        for j in 0..n {
            let k = hops[j].signer;
            if k == self.me {
                return Verdict::Loop;
            }
            if (j < ends && k == from) || hops[..j].iter().any(|x| x.signer == k) {
                return Verdict::Lie;
            }
        }
        // no hop advertises less than the hop before it plus the link that
        // one measured, and no link is cheaper than an honest hop's least
        for j in 0..n {
            if hops[j].link < MIN_HOP_COST {
                return Verdict::Lie;
            }
            let after = match hops.get(j + 1) {
                Some(next) => next.cost,
                None if own => continue, // its link to us: our cost, not a claim
                None => a.cost,
            };
            if (after as u64) < hops[j].cost as u64 + hops[j].link as u64 {
                return Verdict::Lie;
            }
        }
        for j in 0..n {
            let next = match hops.get(j + 1) {
                Some(x) => x.signer,
                None if own => self.me,
                None => from,
            };
            let id = hop_id(a, j as u8, hops[j], &next);
            if self.verified.contains(&id) {
                self.stats.signatures_cached += 1;
                continue;
            }
            if !self.nbs.get_mut(&from).is_some_and(|nb| nb.verify_budget.take(1.0, now)) {
                return Verdict::Limited;
            }
            self.stats.signatures_checked += 1;
            if !verify(Check::Hop { ann: a, hop: hops[j], pos: j as u8, next }) {
                self.stats.announcements_forged += 1;
                return Verdict::Lie;
            }
            self.remember(id);
        }
        Verdict::Attested(if own { hops[h].link } else { 0 })
    }

    /// `peer` sent a route no honest relay could have: a black hole
    /// pulling traffic toward itself (it costs nothing to claim "every
    /// device is right next to me", and announcements' hops and cost aren't
    /// signed). Its routes to others go at once, as if it had left
    /// (retractions and seqno requests restore the others), and the routes
    /// it relays are ignored for [`DISTRUST`]. It stays reachable itself:
    /// its own announcements are signed by it and come over its own
    /// authenticated hop connection, which is also why only a direct
    /// neighbour can be blamed.
    fn distrust(&mut self, peer: SignPk, now: Time) {
        self.stats.announcements_implausible += 1;
        if self.distrusted.len() >= DISTRUST_MAX {
            self.distrusted.retain(|_, t| now < *t);
            if self.distrusted.len() >= DISTRUST_MAX
                && let Some(k) = self.distrusted.iter().min_by_key(|(k, t)| (**t, k.0)).map(|(k, _)| *k)
            {
                self.distrusted.remove(&k);
            }
        }
        self.distrusted.insert(peer, now + DISTRUST);
        self.stats.neighbours_distrusted += 1;
        self.next_sweep = self.next_sweep.min(now + DISTRUST);
        self.drop_routes_via(peer, true, now);
    }

    /// `from` no longer routes to `origin` (as of `seq`).
    fn on_retraction(&mut self, from: SignPk, origin: SignPk, seq: u64, now: Time) {
        let Some(o) = self.origins.get_mut(&origin) else { return };
        let before = o.via.len();
        o.via.retain(|(n, v)| !(*n == from && v.seq <= seq));
        o.prune_chains();
        if o.via.len() != before {
            self.gc_check |= o.via.is_empty();
            self.touch(origin);
            self.after_loss(origin, Some(from), now);
        }
    }

    /// We lost a route to `origin`: if no feasible one is left, tell our
    /// neighbours at once (retraction) and ask for a fresh seqno, which
    /// makes the remaining (or new) routes feasible again.
    fn after_loss(&mut self, origin: SignPk, except: Option<SignPk>, now: Time) {
        let feasible_left = {
            let Some(o) = self.origins.get(&origin) else { return };
            o.via.iter().any(|(n, v)| o.feasible(v) && self.fresh(o, v, now) && self.nbs.get(n).is_some_and(|n| n.up))
        };
        if feasible_left {
            return;
        }
        let targets: Vec<SignPk> = self.direct_up().filter(|k| Some(*k) != except && *k != origin).collect();
        let Some(o) = self.origins.get_mut(&origin) else { return };
        if o.fd.is_some() && !o.retracted {
            // (never attested: it only takes away our own route, and what
            // its receivers held of our chains goes with it)
            let mut a = o.latest.clone();
            o.retracted = true;
            o.sent.clear();
            a.cost = INFINITY;
            for t in &targets {
                self.stats.retractions_sent += 1;
                self.out.push(Out::Announce { to: *t, ann: a.clone() });
            }
        }
        if o.last_req.is_none_or(|t| now.saturating_sub(t) >= SEQREQ_GAP) {
            o.last_req = Some(now);
            let req = SeqReq { origin, seq: o.newest + 1, hops: SEQREQ_HOPS };
            for t in targets {
                self.stats.seqreqs_sent += 1;
                self.out.push(Out::SeqReq { to: t, req });
            }
        }
    }

    /// A neighbour asks for an announcement of `req.origin` at least as
    /// new as `req.seq`.
    pub fn on_seqreq(&mut self, from: SignPk, req: SeqReq, now: Time) {
        if !self.nbs.get(&from).is_some_and(|n| n.direct && n.up) {
            return;
        }
        if req.origin == self.me {
            // the one we sent it last, asked for once more: its chain (our
            // hop) didn't arrive (`Announce::same`), so ours again to it
            // alone (a request for a seqno it lacks, `seq` + 1, carries on
            // below and reaches everyone)
            if req.hops == 1 && self.own.as_ref().is_some_and(|a| req.seq == a.seq) {
                if self.nbs.get_mut(&from).is_some_and(|n| n.verify_budget.take(1.0, now)) {
                    self.own_sent.retain(|(k, _)| *k != from);
                }
                if let Some(a) = self.own_for(&from) {
                    self.push_announce(from, a);
                }
                return;
            }
            if self.last_forced.is_none_or(|t| now.saturating_sub(t) >= FORCED_GAP) {
                self.last_forced = Some(now);
                self.next_announce = now; // answer with a fresh one ...
                self.force_full = true; // ... that reaches the requester
            }
            return;
        }
        let best = self.best_route(&req.origin, now);
        let advert =
            best.and_then(|(n, via)| self.origins.get(&req.origin).and_then(|o| self.advert(o, &n, &via, &from)));
        let Some(o) = self.origins.get_mut(&req.origin) else { return };
        if o.newest >= req.seq
            && let Some((_, via)) = best
            && via.seq == o.newest
            && let Some(a) = advert
        {
            // we have it: send our current advertisement back, which (as
            // any advertisement) sets our feasibility distance (Babel,
            // RFC 8966 §3.7.3)
            o.fd = match o.fd {
                Some((s, c)) if s == o.newest => Some((s, c.min(via.cost))),
                _ => Some((o.newest, via.cost)),
            };
            o.retracted = false;
            // with its chain, if it asked for one it lacks (within its
            // signature budget: each costs us a signature)
            if self.nbs.get_mut(&from).is_some_and(|n| n.verify_budget.take(1.0, now)) {
                o.sent.retain(|(k, _)| *k != from);
            }
            self.push_announce(from, a);
            self.touch(req.origin); // its feasibility distance may have changed
            return;
        }
        if req.hops > 1 && (req.seq, req.hops) > o.req_forwarded {
            o.req_forwarded = (req.seq, req.hops);
            // toward the origin: along any route we still know
            let next = o
                .via
                .iter()
                .filter(|(n, _)| *n != from && self.nbs.get(n).is_some_and(|n| n.up && n.direct))
                .min_by_key(|(n, v)| (v.cost, n.0))
                .map(|(n, _)| *n);
            if let Some(n) = next {
                self.stats.seqreqs_sent += 1;
                self.out.push(Out::SeqReq { to: n, req: SeqReq { hops: req.hops - 1, ..req } });
            }
        }
    }

    /// Pass on announcements whose jitter has run out: once per sequence
    /// number, with our best cost, to direct neighbours that don't have it
    /// yet (not back where it came from); not at all in a dense
    /// neighbourhood where enough others already did.
    fn flush_announcements(&mut self, now: Time) {
        let mut due: Vec<SignPk> = Vec::new();
        while let Some(&Reverse((t, k))) = self.flush_q.peek() {
            if t > now {
                break;
            }
            self.flush_q.pop();
            if self.origins.get(&k).is_some_and(|o| o.pending.is_some_and(|t| t <= now)) {
                due.push(k);
            }
        }
        if due.is_empty() {
            return;
        }
        due.sort();
        due.dedup();
        let direct: Vec<SignPk> = self.direct_up().collect();
        let dense = self.cfg.flood_reduction && direct.len() >= DENSE;
        for origin in due {
            let best = self.best_route(&origin, now);
            self.touch(origin); // its feasibility distance may change
            let Some(o) = self.origins.get_mut(&origin) else { continue };
            o.pending = None;
            self.gc_check |= o.via.is_empty();
            let newest = o.newest;
            o.forwarded = newest;
            o.flooded = Some(now);
            let Some((n, via)) = best.filter(|(_, v)| v.seq == newest) else { continue };
            if dense && o.heard.iter().filter(|(_, adv)| *adv <= via.cost).count() >= REDUNDANT {
                self.stats.announcements_suppressed += 1;
                continue;
            }
            // Babel: the feasibility distance is the best we advertised
            o.fd = match o.fd {
                Some((s, c)) if s == newest => Some((s, c.min(via.cost))),
                _ => Some((newest, via.cost)),
            };
            o.retracted = false;
            let targets: Vec<SignPk> =
                direct.iter().filter(|pk| **pk != origin && !o.heard.iter().any(|(k, _)| k == *pk)).copied().collect();
            for pk in targets {
                // (each its own: attested or not, and our hop names it)
                let Some(a) = self.origins.get(&origin).and_then(|o| self.advert(o, &n, &via, &pk)) else { continue };
                self.send_announce(pk, a, now);
            }
        }
    }

    /// Push an announcement for `to`: an attested one it holds the chain of
    /// goes without it ([`Router::elided`]); what it holds is noted.
    fn push_announce(&mut self, to: SignPk, a: Announce) {
        let a = self.elided(&to, &a).unwrap_or(a);
        self.note_sent(&to, &a);
        self.stats.announcements_sent += 1;
        self.out.push(Out::Announce { to, ann: a });
    }

    /// `a` without its chain ([`Announce::same`]), if `to` holds the chain
    /// we last sent it for the origin and ours wouldn't change: the same
    /// connection and epoch, the same chain under our hop, our hop's link
    /// no more than 1/[`RESIGN_FRACTION`] below what we signed, and our
    /// cost not below what we signed by more (it goes as signed then: a
    /// receiver takes no less).
    fn elided(&self, to: &SignPk, a: &Announce) -> Option<Announce> {
        if !self.cfg.chain_reuse || a.same || !a.attested() {
            return None;
        }
        let nb = self.nbs.get(to)?;
        let sent = if a.origin == self.me { &self.own_sent } else { &self.origins.get(&a.origin)?.sent };
        let (_, s) = sent.iter().find(|(k, _)| k == to)?;
        let base = match (&s.base, &a.chain) {
            (None, None) => true,
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            _ => false,
        };
        let link = match (s.link, a.sign_link) {
            (None, None) => true,
            (Some(signed), Some(l)) => l >= signed - signed / RESIGN_FRACTION,
            _ => false,
        };
        let cost = a.cost.saturating_add(a.cost / RESIGN_FRACTION) >= s.cost;
        (s.session == nb.session && s.epoch == attest_epoch(&a.origin, a.seq) && base && link && cost)
            .then(|| Announce { cost: a.cost.max(s.cost), chain: None, sign_link: None, same: true, ..a.clone() })
    }

    /// Note what `to` will hold once it has `a`: an attested announcement's
    /// chain (until it changes), or, after an unattested one, nothing.
    fn note_sent(&mut self, to: &SignPk, a: &Announce) {
        if a.same {
            self.stats.chains_elided += 1;
            return;
        }
        let Some(session) = self.nbs.get(to).map(|n| n.session) else { return };
        let me = self.me;
        let sent = if a.origin == me {
            &mut self.own_sent
        } else {
            let Some(o) = self.origins.get_mut(&a.origin) else { return };
            &mut o.sent
        };
        sent.retain(|(k, _)| k != to);
        if a.attested() && a.cost != INFINITY {
            let epoch = attest_epoch(&a.origin, a.seq);
            sent.push((*to, Sent { session, epoch, base: a.chain.clone(), cost: a.cost, link: a.sign_link }));
        }
        // (neighbours gone, or reconnected since: dropped now and then)
        if sent.len() > 32 {
            let nbs = &self.nbs;
            sent.retain(|(k, s)| nbs.get(k).is_some_and(|n| n.session == s.session));
        }
    }

    /// Send a relayed announcement to neighbour `to`: within its control
    /// budget ([`Defences::budget`]), or queued for it. Waiting
    /// announcements go fewest hops first (they reach the most, and near
    /// routes refresh every period); one waiting for the same origin is
    /// replaced; a full queue drops the farthest.
    fn send_announce(&mut self, to: SignPk, a: Announce, now: Time) {
        if !self.cfg.defences.budget || a.cost == INFINITY {
            self.push_announce(to, a);
            return;
        }
        let size = super::wire::wire_len(self.elided(&to, &a).as_ref().unwrap_or(&a)) as f64;
        let Some(n) = self.nbs.get_mut(&to) else { return };
        if n.ctl_q.is_empty() && n.ctl.take(size, now) {
            self.push_announce(to, a);
            return;
        }
        self.stats.announcements_deferred += 1;
        if let Some(w) = n.ctl_q.iter_mut().find(|w| w.origin == a.origin) {
            *w = a;
            self.stats.announcements_shed += 1;
        } else {
            if n.ctl_q.len() >= CONTROL_QUEUE
                && let Some(far) = n.ctl_q.iter().enumerate().max_by_key(|(_, w)| w.hops).map(|(i, _)| i)
            {
                n.ctl_q.swap_remove(far);
                self.stats.announcements_shed += 1;
            }
            n.ctl_q.push(a);
        }
        if !self.ctl_waiting.contains(&to) {
            self.ctl_waiting.push(to);
        }
    }

    /// Send what waited for control budget and fits now, as it stands now:
    /// with our current route's hops and cost, and not at all if we no
    /// longer have a route at the newest seqno (or only through `to`), so a
    /// route lost meanwhile is never advertised late.
    fn flush_control(&mut self, now: Time) {
        if self.ctl_waiting.is_empty() {
            return;
        }
        let mut waiting = std::mem::take(&mut self.ctl_waiting);
        waiting.sort();
        for to in waiting {
            let Some(n) = self.nbs.get_mut(&to) else { continue };
            let mut q = std::mem::take(&mut n.ctl_q);
            if !n.up {
                continue;
            }
            // fewest hops first; popped from the end
            q.sort_by_key(|a| (Reverse(a.hops), a.origin));
            while let Some(a) = q.last() {
                let origin = a.origin;
                let fresh = self.best_route(&origin, now).filter(|(k, _)| *k != to).and_then(|(n, via)| {
                    let o = self.origins.get(&origin)?;
                    let ok = via.seq == o.newest
                        && via.hops < o.latest.scope.min(self.cfg.max_hops)
                        && !o.heard.iter().any(|(k, _)| *k == to);
                    if ok { self.advert(o, &n, &via, &to) } else { None }
                });
                let Some(fresh) = fresh else {
                    q.pop();
                    self.stats.announcements_shed += 1;
                    continue;
                };
                let size = super::wire::wire_len(self.elided(&to, &fresh).as_ref().unwrap_or(&fresh)) as f64;
                if !self.nbs.get_mut(&to).is_some_and(|n| n.ctl.take(size, now)) {
                    break;
                }
                q.pop();
                if let Some(o) = self.origins.get_mut(&origin) {
                    // Babel: the feasibility distance is the best we advertised
                    o.fd = match o.fd {
                        Some((s, c)) if s == fresh.seq => Some((s, c.min(fresh.cost))),
                        _ => Some((fresh.seq, fresh.cost)),
                    };
                }
                self.push_announce(to, fresh);
            }
            if let Some(n) = self.nbs.get_mut(&to)
                && !q.is_empty()
            {
                n.ctl_q = q;
                self.ctl_waiting.push(to);
            }
        }
    }

    // ───────────── routes ─────────────

    /// A route through `n` that can carry traffic now: feasible, fresh,
    /// through a direct neighbour whose hop is up.
    fn usable(&self, o: &Origin, n: &SignPk, v: &Via, now: Time) -> bool {
        o.feasible(v) && self.fresh(o, v, now) && self.nbs.get(n).is_some_and(|n| n.up && n.direct)
    }

    /// What a route through `n` is chosen by: its cost, with what the
    /// defences add. It only orders feasible routes, every one of them
    /// loop-free (Babel); what we advertise is the chosen route's own cost.
    fn rank(&self, o: &Origin, n: &SignPk, v: &Via, now: Time) -> u64 {
        let mut r = self.base_rank(o, n, v, now);
        if self.cfg.defences.corroborate
            && let Some(incumbent) = self.held_down(o, n, v, now)
        {
            r = r.max(incumbent + 1);
        }
        r
    }

    /// [`Self::rank`] before the hold-down: the cost, costlier through a
    /// relay far from our spaces ([`Defences::affinity`]), and behind every
    /// usable attested route if it has no chain ([`UNATTESTED_RANK`]).
    fn base_rank(&self, o: &Origin, n: &SignPk, v: &Via, now: Time) -> u64 {
        let unattested =
            self.cfg.attest && !v.attested && o.via.iter().any(|(k, w)| w.attested && self.usable(o, k, w, now));
        self.affine(n, v.cost) + if unattested { UNATTESTED_RANK } else { 0 }
    }

    /// `cost` through next hop `n`, costlier the farther `n` is from our
    /// spaces' members ([`Defences::affinity`]).
    fn affine(&self, n: &SignPk, cost: u32) -> u64 {
        if !self.cfg.defences.affinity || self.affinity.is_empty() {
            return cost as u64;
        }
        let far = self.affinity.get(n).copied().unwrap_or(AFFINITY_UNKNOWN).clamp(1, AFFINITY_UNKNOWN) as u64;
        cost as u64 * (100 + self.cfg.affinity_step as u64 * (far - 1)) / 100
    }

    /// [`Defences::corroborate`]: if the route through `n` became a sudden
    /// shortcut less than [`HOLD_DOWN`] ago and nobody else backs it yet (an
    /// older usable route through another neighbour costs over
    /// [`CORROBORATE_FACTOR`] times as much, and no other neighbour's route
    /// is within that factor of it), the incumbent's rank, which it then
    /// ranks just behind.
    ///
    /// Never the destination itself, next to us (its own announcement over
    /// its own authenticated hop; nobody else can claim 0 hops), nor a hop
    /// that carried an acknowledgement from it lately (kept with
    /// [`Defences::aggregate`]; evidence that beats a second opinion), nor
    /// an attested route: its chain proves the shortcut, each link's cost
    /// signed by the device upstream of it.
    fn held_down(&self, o: &Origin, n: &SignPk, v: &Via, now: Time) -> Option<u64> {
        let since = v.since.filter(|t| now.saturating_sub(*t) < HOLD_DOWN)?;
        if v.attested
            || *n == o.latest.origin
            || self.vouched.get(n).is_some_and(|d| d.iter().any(|(k, t)| *k == o.latest.origin && now < *t))
        {
            return None;
        }
        let cheap = v.cost as u64 * CORROBORATE_FACTOR;
        let mut incumbent: Option<u64> = None;
        for (k, w) in &o.via {
            if k == n || !self.usable(o, k, w, now) {
                continue;
            }
            if w.cost as u64 <= cheap {
                return None; // corroborated
            }
            if w.since.is_none_or(|t| t < since) {
                let r = self.base_rank(o, k, w, now);
                incumbent = Some(incumbent.map_or(r, |i| i.min(r)));
            }
        }
        incumbent
    }

    /// `hop` is suspected for `dst`: for it, or for every destination
    /// ([`Defences::aggregate`]; never as the destination itself).
    fn suspected(&self, dst: &SignPk, hop: &SignPk, now: Time) -> bool {
        self.suspects.get(dst).is_some_and(|v| v.iter().any(|(k, until)| k == hop && now < *until))
            || (self.cfg.defences.aggregate && hop != dst && self.shunned.get(hop).is_some_and(|t| now < *t))
    }

    /// Fresh, feasible routes to `origin` through direct neighbours:
    /// (neighbour, via), best first.
    fn routes(&self, origin: &SignPk, now: Time) -> Vec<(SignPk, Via)> {
        let Some(o) = self.origins.get(origin) else { return Vec::new() };
        let mut v: Vec<(SignPk, u64, Via)> = o
            .via
            .iter()
            .filter(|(n, via)| self.usable(o, n, via, now))
            .map(|(n, via)| (*n, self.rank(o, n, via, now), *via))
            .collect();
        v.sort_by_key(|(n, rank, _)| (*rank, n.0));
        v.into_iter().map(|(n, _, via)| (n, via)).collect()
    }

    /// The best route to `origin` among those `ok` accepts, without building
    /// the list.
    fn best_where(&self, origin: &SignPk, now: Time, ok: impl Fn(&SignPk, &Via) -> bool) -> Option<(SignPk, Via)> {
        let o = self.origins.get(origin)?;
        o.via
            .iter()
            .filter(|(n, via)| ok(n, via) && self.usable(o, n, via, now))
            .min_by_key(|(n, via)| (self.rank(o, n, via, now), n.0))
            .copied()
    }

    /// The best of [`Self::routes`] not through `except`.
    fn best_route_except(&self, origin: &SignPk, except: Option<&SignPk>, now: Time) -> Option<(SignPk, Via)> {
        self.best_where(origin, now, |n, _| Some(n) != except)
    }

    fn best_route(&self, origin: &SignPk, now: Time) -> Option<(SignPk, Via)> {
        self.best_route_except(origin, None, now)
    }

    /// `hop` is a direct neighbour that announced a route to `dst` (not `dst`
    /// itself).
    fn is_route_via(&self, dst: &SignPk, hop: &SignPk) -> bool {
        hop != dst && self.origins.get(dst).is_some_and(|o| o.via.iter().any(|(k, _)| k == hop))
    }

    /// The cheapest route to `dst` not through `except` nor a hop suspected
    /// for it. Any feasible route is loop-free (Babel), not only the best,
    /// so taking the next one when the best is suspected keeps that.
    fn best_unsuspected_route(&self, dst: &SignPk, except: Option<&SignPk>, now: Time) -> Option<(SignPk, Via)> {
        self.best_where(dst, now, |n, _| Some(n) != except && !self.suspected(dst, n, now))
    }

    /// End-to-end feedback from the transport about our own packets to
    /// `dst`: a whole retransmission timeout went by with nothing
    /// acknowledged (`acked = false`), or an acknowledgement came back
    /// (`true`). The driver sees the acknowledgements (relays can't: they're
    /// inside the end-to-end encryption), and its timeout follows the
    /// measured round trip, so a slow path isn't mistaken for a dead one.
    ///
    /// After `SUSPECT_STRIKES` timeouts in a row through the same next
    /// hop, over at least `SUSPECT_SILENCE` plus twice the route's cost,
    /// that hop is suspected for `dst` for `SUSPECT_FOR`: our packets (and
    /// those we relay to `dst`) take the next feasible route; with none
    /// left, still the best (dropping can't deliver, and suspicion can be
    /// wrong), while the store-and-forward carrier spreads the bundle
    /// (`Carrier::doubt`). Custody hand-offs aren't steered by it: in a
    /// network of brief contacts that cost more than it saved
    /// (docs/SIMULATION.md §4, fixed 21). A black hole that lies plausibly
    /// pulls in routes nothing in an announcement can refute; what it can't
    /// fake is the destination's acknowledgements. A lost packet on a slow
    /// link doesn't count: one acknowledgement clears the strikes.
    ///
    /// Returns whether the timeout counted against a mesh route (then the
    /// store-and-forward carrier shouldn't trust that route with every copy
    /// of a bundle either: `Carrier::doubt`).
    pub fn feedback(&mut self, dst: SignPk, acked: bool, now: Time) -> bool {
        if acked {
            self.strikes.remove(&dst);
            if let Some((hop, _)) = self.sent_via.get(&dst).copied() {
                self.vouch(hop, dst, now);
            }
            return false;
        }
        let Some((hop, _)) = self.sent_via.get(&dst).copied() else { return false };
        self.strike(dst, hop, now, now)
    }

    /// `hop` carried an acknowledgement from `dst` ([`Defences::aggregate`]:
    /// evidence for it against suspicions for other destinations).
    fn vouch(&mut self, hop: SignPk, dst: SignPk, now: Time) {
        if !self.cfg.defences.aggregate {
            return;
        }
        let mut v = self.vouched.remove(&hop).unwrap_or_default();
        v.retain(|(k, t)| *k != dst && now < *t);
        if v.len() >= VOUCHED_PER_HOP {
            v.remove(0);
        }
        v.push((dst, now + SUSPECT_FOR));
        bounded_insert(&mut self.vouched, hop, v);
        // the destination is alive: a silence through another hop suspected
        // for it now counts against that hop
        bounded_insert(&mut self.acked_via, dst, (hop, now));
        let others: Vec<SignPk> = self
            .suspects
            .get(&dst)
            .map(|v| v.iter().filter(|(k, t)| *k != hop && now < *t).map(|(k, _)| *k).collect())
            .unwrap_or_default();
        for k in others {
            self.aggregate(k, now);
        }
    }

    /// The same evidence from the node's QUIC connections, one path at a
    /// time: our path to `dst` through first hop `via` (the mesh address
    /// `mesh(dst, via)`) has had no authenticated packet back since
    /// `silent_since` while we kept sending on it (`Some`), or carries them
    /// (`None`). Only packets QUIC decrypted count, so a relay can't fake
    /// either: it can only drop. A path that says so (two silences, as for
    /// [`Router::feedback`]) is suspected for `dst`, and the routes offered
    /// for it ([`Out::RouteUp`]) move to the next route. Returns whether it
    /// counted against a mesh route.
    pub fn path_feedback(&mut self, dst: SignPk, via: SignPk, silent_since: Option<Time>, now: Time) -> bool {
        match silent_since {
            None => {
                if self.strikes.get(&dst).is_some_and(|(h, ..)| *h == via) {
                    self.strikes.remove(&dst);
                }
                if self.is_route_via(&dst, &via) {
                    self.vouch(via, dst, now);
                }
                false
            }
            Some(since) => self.strike(dst, via, since, now),
        }
    }

    /// A timeout through `hop` toward `dst`, silent since `since`.
    fn strike(&mut self, dst: SignPk, hop: SignPk, since: Time, now: Time) -> bool {
        // only a mesh route that still claims to reach it is judged: a link
        // that broke, or a destination behind a gateway or the internet
        // (perhaps offline), says nothing about the hop
        if !self.is_route_via(&dst, &hop) || !self.nbs.get(&hop).is_some_and(|n| n.up && n.direct) {
            self.strikes.remove(&dst);
            return false;
        }
        let (n, since) = match self.strikes.get(&dst) {
            Some((h, n, first)) if *h == hop => (n.saturating_add(1), since.min(*first)),
            _ => (1, since),
        };
        let cost =
            self.origins.get(&dst).and_then(|o| o.via.iter().find(|(k, _)| *k == hop)).map_or(0, |(_, v)| v.cost);
        let silence = SUSPECT_SILENCE + 2 * cost as Time / 10;
        if n < SUSPECT_STRIKES || now.saturating_sub(since) < silence {
            bounded_insert(&mut self.strikes, dst, (hop, n, since));
            return true;
        }
        self.strikes.remove(&dst);
        if !self.suspects.contains_key(&dst) && self.suspects.len() >= FEEDBACK_MAX {
            self.suspects.retain(|_, v| v.iter().any(|(_, t)| now < *t));
            if self.suspects.len() >= FEEDBACK_MAX
                && let Some(k) = self.suspects.keys().next().copied()
            {
                self.suspects.remove(&k);
            }
        }
        let v = self.suspects.entry(dst).or_default();
        v.retain(|(k, t)| *k != hop && now < *t);
        if v.len() >= SUSPECTS_PER_DST {
            v.remove(0);
        }
        v.push((hop, now + SUSPECT_FOR));
        self.stats.hops_suspected += 1;
        self.next_sweep = self.next_sweep.min(now + SUSPECT_FOR);
        self.touch(dst); // the routes offered for it change
        self.ask_around(dst, hop, usize::MAX, now);
        if self.cfg.defences.aggregate {
            self.aggregate(hop, now);
        }
        true
    }

    /// The routes to `dst` other than through `hop` may be infeasible: we
    /// advertised the cheap one (Babel's feasibility distance). If none is
    /// left, a fresh seqno from the origin makes them usable, as after a
    /// loss: ask for it, not through `hop`, of at most `limit` neighbours
    /// (those that offered a route to it first, cheapest first). Returns
    /// the requests sent.
    fn ask_around(&mut self, dst: SignPk, hop: SignPk, limit: usize, now: Time) -> usize {
        if limit == 0 || self.best_unsuspected_route(&dst, None, now).is_some() {
            return 0;
        }
        let mut targets: Vec<SignPk> = self.direct_up().filter(|k| *k != hop && *k != dst).collect();
        if targets.len() > limit {
            let o = self.origins.get(&dst);
            let cost =
                |k: &SignPk| o.and_then(|o| o.via.iter().find(|(n, _)| n == k)).map_or(u32::MAX, |(_, v)| v.cost);
            targets.sort_by_key(|k| (cost(k), k.0));
            targets.truncate(limit);
        }
        let Some(o) = self.origins.get_mut(&dst) else { return 0 };
        if o.last_req.is_some_and(|t| now.saturating_sub(t) < SEQREQ_GAP) {
            return 0;
        }
        o.last_req = Some(now);
        let req = SeqReq { origin: dst, seq: o.newest + 1, hops: SEQREQ_HOPS };
        for t in &targets {
            self.stats.seqreqs_sent += 1;
            self.out.push(Out::SeqReq { to: *t, req });
        }
        targets.len()
    }

    /// [`Defences::aggregate`]: `hop` was just suspected for a destination,
    /// or a destination it is suspected for acknowledged through another.
    /// Suspected now for at least [`AGGREGATE_MIN`] distinct destinations
    /// that acknowledged through another hop since (alive: not merely
    /// offline), and for more than it carried acknowledgements for lately,
    /// it is avoided for every destination (but itself) for
    /// [`SUSPECT_FOR`]. Only our own evidence counts (no one else's
    /// accusations), and a relay that delivers for most of what it carries
    /// is never shunned for the rest. What it can't tell: whether the hop
    /// or someone past it drops (an honest relay in front of a liar is
    /// blamed too, as for one destination).
    fn aggregate(&mut self, hop: SignPk, now: Time) {
        if self.shunned.get(&hop).is_some_and(|t| now < *t) {
            return;
        }
        let acked_since = |d: &SignPk, until: Time| {
            self.acked_via.get(d).is_some_and(|(via, at)| *via != hop && *at + SUSPECT_FOR >= until)
        };
        let bad: Vec<SignPk> = self
            .suspects
            .iter()
            .filter(|(d, v)| v.iter().any(|(k, t)| *k == hop && now < *t && acked_since(d, *t)))
            .map(|(d, _)| *d)
            .collect();
        let good = self.vouched.get(&hop).map_or(0, |v| v.iter().filter(|(d, t)| now < *t && !bad.contains(d)).count());
        if bad.len() < AGGREGATE_MIN || bad.len() <= good {
            return;
        }
        bounded_insert(&mut self.shunned, hop, now + SUSPECT_FOR);
        self.stats.hops_shunned += 1;
        self.next_sweep = self.next_sweep.min(now + SUSPECT_FOR);
        self.touch_all();
        // our own recent destinations through it may need a fresh seqno too,
        // the latest first, within a bound
        let mut mine: Vec<(Time, SignPk)> = self
            .sent_via
            .iter()
            .filter(|(d, (h, at))| *h == hop && **d != hop && now.saturating_sub(*at) < SUSPECT_FOR)
            .map(|(d, (_, at))| (*at, *d))
            .collect();
        mine.sort_by_key(|(at, d)| (Reverse(*at), *d));
        let mut left = SHUN_SEQREQS;
        for (_, dst) in mine {
            left -= self.ask_around(dst, hop, left, now);
        }
    }

    /// The neighbour toward `dst` inside the mesh (no gateways, no internet).
    pub fn next_hop_local(&self, dst: &SignPk, now: Time) -> Option<SignPk> {
        if self.nbs.get(dst).is_some_and(|n| n.up) {
            return Some(*dst);
        }
        self.best_route(dst, now).map(|(n, _)| n)
    }

    /// Gateways reachable through the mesh: (gateway, total cost = mesh +
    /// uplink, mesh cost, first hop), cheapest total first.
    fn gateway_routes(&self, now: Time) -> Vec<(SignPk, u32, u32, SignPk)> {
        let mut v: Vec<(SignPk, u32, u32, SignPk)> =
            self.origins.keys().filter_map(|g| self.gateway_route(g, now).map(|(t, m, n)| (*g, t, m, n))).collect();
        v.sort_by_key(|(g, total, _, _)| (*total, g.0));
        v
    }

    /// `g`'s entry in [`Self::gateway_routes`]: (total, mesh, first hop).
    fn gateway_route(&self, g: &SignPk, now: Time) -> Option<(u32, u32, SignPk)> {
        let o = self.origins.get(g).filter(|o| o.latest.flags & F_GATEWAY != 0)?;
        self.best_route(g, now).map(|(n, via)| (via.cost.saturating_add(o.latest.uplink), via.cost, n))
    }

    /// [`Self::gateway_routes`], reusing the last answer while it holds:
    /// no gateway's routes changed and no route can have expired since.
    fn gateway_routes_cached(&mut self, now: Time) -> &[(SignPk, u32, u32, SignPk)] {
        if now >= self.next_expiry || self.gw_all_dirty {
            // a route may have gone stale since the table was made: redo it all
            self.gw_all_dirty = false;
            self.gw_dirty.clear();
            self.gw_table = self.origins.keys().filter_map(|g| self.gateway_route(g, now).map(|r| (*g, r))).collect();
            self.gw_sorted = None;
            self.gw_pick = None;
        } else if !self.gw_dirty.is_empty() {
            let mut dirty = std::mem::take(&mut self.gw_dirty);
            dirty.sort();
            dirty.dedup();
            for g in &dirty {
                let new = self.gateway_route(g, now);
                if new != self.gw_table.get(g).copied() {
                    match new {
                        Some(r) => self.gw_table.insert(*g, r),
                        None => self.gw_table.remove(g),
                    };
                    self.gw_sorted = None;
                    self.gw_pick = None;
                }
            }
            self.gw_dirty = dirty;
            self.gw_dirty.clear();
        }
        if self.gw_sorted.is_none() {
            let mut v: Vec<(SignPk, u32, u32, SignPk)> =
                self.gw_table.iter().map(|(g, (t, m, n))| (*g, *t, *m, *n)).collect();
            v.sort_by_key(|(g, total, _, _)| (*total, g.0));
            self.gw_sorted = Some(v);
        }
        self.gw_sorted.as_deref().unwrap_or_default()
    }

    /// Gateways we'd publish in our record, with our mesh cost to each: the
    /// cheapest by total cost, through distinct first hops where possible,
    /// at most `gateways` of them.
    pub fn gateways_with_cost(&self, now: Time) -> Vec<(SignPk, u32)> {
        let all = self.gateway_routes(now);
        Self::pick_gateways(&all, self.cfg.gateways)
    }

    fn pick_gateways(all: &[(SignPk, u32, u32, SignPk)], gateways: usize) -> Vec<(SignPk, u32)> {
        let want = gateways.max(1);
        let mut pick: Vec<(SignPk, u32)> = Vec::new();
        let mut hops: Vec<SignPk> = Vec::new();
        for (g, _, mesh, first) in all {
            if pick.len() < want && !hops.contains(first) {
                pick.push((*g, *mesh));
                hops.push(*first);
            }
        }
        for (g, _, mesh, _) in all {
            if pick.len() < want && !pick.iter().any(|(k, _)| k == g) {
                pick.push((*g, *mesh));
            }
        }
        pick
    }

    /// Our best gateways, cheapest total first (the waypoints for anyone
    /// we have no route to, while we have no internet).
    pub fn gateways(&self, now: Time) -> Vec<SignPk> {
        self.gateways_with_cost(now).into_iter().map(|(g, _)| g).collect()
    }

    /// The gateways our current record names (none while we have the internet).
    pub fn my_gateways(&self) -> &[SignPk] {
        &self.my_gateways
    }

    /// Devices reachable through the mesh (local routes) right now.
    pub fn reachable(&self) -> Vec<SignPk> {
        let mut v: Vec<SignPk> = self.published.keys().copied().collect();
        v.sort();
        v
    }

    pub fn origin_name(&self, pk: &SignPk) -> Option<Arc<str>> {
        self.origins.get(pk).map(|o| o.latest.name.clone()).filter(|n| !n.is_empty())
    }

    pub fn is_gateway(&self, pk: &SignPk) -> bool {
        self.origins.get(pk).is_some_and(|o| o.latest.flags & F_GATEWAY != 0)
    }

    /// The first hops of the routes to `dst` offered as QUIC paths now.
    pub fn offered(&self, dst: &SignPk) -> Vec<SignPk> {
        self.published.get(dst).cloned().unwrap_or_default()
    }

    /// Hops to `dst` leaving through `via` (a local route), or `None`.
    pub fn route_hops(&self, dst: &SignPk, via: &SignPk) -> Option<u8> {
        self.origins.get(dst)?.via.iter().find(|(k, _)| k == via).map(|(_, v)| v.hops)
    }

    /// The routes offered for `origin` now, given what was offered before
    /// (`None`: none). Idempotent: with nothing changed, the answer is what
    /// is already offered (incumbents only get cheaper), so `publish` only
    /// revisits origins that changed.
    fn offer(&self, origin: &SignPk, now: Time) -> Option<Vec<SignPk>> {
        if *origin == self.me || self.is_neighbour(origin) {
            return None;
        }
        let current = self.published.get(origin);
        let o = self.origins.get(origin)?;
        let mut routes: Vec<(SignPk, u64)> =
            self.routes(origin, now).into_iter().map(|(n, v)| (n, self.rank(o, &n, &v, now))).collect();
        // not through a hop suspected for it, while another route remains
        if routes.iter().any(|(n, _)| !self.suspected(origin, n, now)) {
            routes.retain(|(n, _)| !self.suspected(origin, n, now));
        }
        let best = routes.first().map(|(_, r)| *r)?;
        let limit = best.saturating_mul(ROUTE_COST_FACTOR as u64).saturating_add(ROUTE_COST_SLACK as u64);
        routes.retain(|(_, r)| *r <= limit);
        let sticky = |n: &SignPk, r: u64| {
            if current.is_some_and(|ws| ws.contains(n)) { r * STICKY_PERCENT as u64 / 100 } else { r }
        };
        routes.sort_by_key(|(n, r)| (sticky(n, *r), n.0));
        routes.truncate(self.cfg.routes.max(1));
        Some(routes.into_iter().map(|(n, _)| n).collect())
    }

    /// Recompute the routes offered per destination; report the changes.
    fn publish(&mut self, now: Time) {
        let mut keys: Vec<SignPk> = if self.all_dirty {
            self.origins.keys().chain(self.published.keys()).copied().collect()
        } else {
            std::mem::take(&mut self.dirty)
        };
        self.all_dirty = false;
        self.dirty.clear();
        if keys.is_empty() {
            return;
        }
        keys.sort();
        keys.dedup();
        let mut downs: Vec<(SignPk, SignPk)> = Vec::new();
        let mut ups: Vec<(SignPk, SignPk)> = Vec::new();
        for dst in keys {
            let want = self.offer(&dst, now);
            let had = self.published.get(&dst);
            for w in had.into_iter().flatten() {
                if want.as_ref().is_none_or(|k| !k.contains(w)) {
                    downs.push((dst, *w));
                }
            }
            for w in want.iter().flatten() {
                if had.is_none_or(|h| !h.contains(w)) {
                    ups.push((dst, *w));
                }
            }
            match want {
                Some(w) => {
                    self.published.insert(dst, w);
                }
                None => {
                    self.published.remove(&dst);
                }
            }
        }
        downs.sort();
        for (dst, via) in downs {
            self.out.push(Out::RouteDown { dst, via });
        }
        ups.sort();
        for (dst, via) in ups {
            let name = self.origins.get(&dst).map(|o| o.latest.name.clone()).unwrap_or_else(|| Arc::from(""));
            self.out.push(Out::RouteUp { dst, via, name });
        }
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
            ttl: self.cfg.max_hops.saturating_mul(2).saturating_add(2),
            reached: false,
            control,
            ext: 0,
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
        match self.next_hop(&target, from.as_ref(), true, now) {
            Next::Via(next) => {
                // ours, along a mesh route: what `feedback` judges
                if from.is_none() && !f.control && self.is_route_via(&target, &next) {
                    bounded_insert(&mut self.sent_via, target, (next, now));
                }
                self.forward(f, from, next, now)
            }
            Next::Wait(key) => self.park(key, f, from, now),
            Next::Drop | Next::Unreachable => self.stats.dropped_no_route += 1,
        }
    }

    /// `avoid`: steer clear of next hops suspected for `target` (packets,
    /// not custody: [`Router::feedback`]).
    fn next_hop(&mut self, target: &SignPk, from: Option<&SignPk>, avoid: bool, now: Time) -> Next {
        // 1. a neighbour (direct, or an internet hop already up)
        if Some(target) != from && self.nbs.get(target).is_some_and(|n| n.up) {
            return Next::Via(*target);
        }
        // 2. a mesh route, not through a hop suspected for the target if
        // there is another (if every one is, the best: dropping can't
        // deliver, and suspicion can be wrong)
        let unsuspected = if avoid { self.best_unsuspected_route(target, from, now) } else { None };
        if let Some((n, _)) = unsuspected.or_else(|| self.best_route_except(target, from, now)) {
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
                    match self.record_gateway(&r.gateways, from, false) {
                        // its gateway backing off: hold on, it has a way in
                        Some(g) => match self.dial_or_wait(g, now) {
                            Next::Unreachable => Next::Drop,
                            n => n,
                        },
                        None => Next::Drop,
                    }
                }
                Some(r) if r.until.saturating_add(REACH_STALE) > now => {
                    // Out of date: look it up again, and meanwhile keep
                    // using a hop to one of its gateways that is up (it was
                    // working a moment ago; a stale record never starts a
                    // dial). Traffic through a gateway doesn't stall for a
                    // lookup every REACH_TTL.
                    let up = self.record_gateway(&r.gateways, from, true);
                    self.resolve(*target);
                    match up {
                        Some(g) => Next::Via(g),
                        None => Next::Wait(*target),
                    }
                }
                _ => {
                    self.resolve(*target);
                    Next::Wait(*target)
                }
            }
        } else {
            // 4. no internet: the default route, to the gateway with the
            // lowest total cost
            let first = self
                .gateway_routes_cached(now)
                .iter()
                .find(|(g, _, _, n)| Some(n) != from && Some(g) != from)
                .map(|r| r.3);
            match first {
                Some(first) => Next::Via(first),
                None => Next::Drop,
            }
        }
    }

    /// Look `target`'s record up, unless a lookup is under way.
    fn resolve(&mut self, target: SignPk) {
        if self.resolving.insert(target) {
            self.stats.resolves += 1;
            self.out.push(Out::Resolve(target));
        }
    }

    /// Which of a record's gateways to go through: the lowest record cost
    /// (its mesh cost to the target) + internet hop cost (`only_up`: among
    /// those we have a hop up to).
    ///
    /// The gateways of one record sit in one mesh around the target, so the
    /// internet between us and each of them is about the same. A hop not
    /// measured yet (or not up) is costed as the cheapest measured hop to
    /// one of them, and only without any as [`DEFAULT_INTERNET_COST`]: a
    /// measured cost includes the round trip *and* the time to move 64 KiB,
    /// so a flat guess would make every gateway we haven't tried look
    /// cheaper than the one carrying our traffic, and each one in turn
    /// would be dialled while that traffic waits. On equal cost, a hop that
    /// is up wins: no dial.
    fn record_gateway(&self, gateways: &[(SignPk, u32)], from: Option<&SignPk>, only_up: bool) -> Option<SignPk> {
        let measured = |g: &SignPk| self.nbs.get(g).filter(|n| n.up && n.cost > 0).map(Nb::hop_cost);
        let known = gateways.iter().filter(|(g, _)| self.is_internet_hop(g)).filter_map(|(g, _)| measured(g)).min();
        gateways
            .iter()
            .filter(|(g, _)| *g != self.me && Some(g) != from)
            .filter_map(|(g, c)| {
                let up = self.nbs.get(g).is_some_and(|n| n.up);
                if only_up && !up {
                    return None;
                }
                let hop = measured(g).or(known).unwrap_or(DEFAULT_INTERNET_COST);
                Some((c.saturating_add(hop), !up, *g))
            })
            .min()
            .map(|(_, _, g)| g)
    }

    /// Where data for `dst` can be handed on *now*, hop by hop (custody
    /// transfer of store-and-forward bundles): the same choice as for
    /// packets, may start a lookup or a dial.
    pub fn toward(&mut self, dst: &SignPk, now: Time) -> Toward {
        if *dst == self.me {
            return Toward::Nowhere;
        }
        match self.next_hop(dst, None, false, now) {
            Next::Via(n) => Toward::Hop(n),
            Next::Wait(_) => Toward::Soon,
            Next::Drop => Toward::Nowhere,
            Next::Unreachable => Toward::Unreachable,
        }
    }

    fn dial_or_wait(&mut self, peer: SignPk, now: Time) -> Next {
        if self.nbs.get(&peer).is_some_and(|n| n.up) {
            return Next::Via(peer);
        }
        if self.backoff.get(&peer).is_some_and(|(at, _)| now < *at) {
            self.stats.dropped_backoff += 1;
            return Next::Unreachable;
        }
        if !self.dialing.contains_key(&peer) {
            let open = self.nbs.values().filter(|n| n.internet()).count() + self.dialing.len();
            if open >= self.cfg.max_internet_hops {
                return Next::Drop;
            }
            self.dialing.insert(peer, now);
            self.next_sweep = self.next_sweep.min(now + DIAL_GIVE_UP);
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
        self.next_sweep = self.next_sweep.min(now + PENDING_TIMEOUT);
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
        self.next_sweep = self.next_sweep.min(now + REASM_TIMEOUT);
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
    /// record (it is behind those gateways, at that mesh cost), `None` if it
    /// has none (dial it directly).
    pub fn on_resolved(&mut self, target: SignPk, gateways: Option<Vec<(SignPk, u32)>>, now: Time) {
        self.resolving.remove(&target);
        let found = gateways.as_ref().is_some_and(|g| !g.is_empty());
        let mut gws = gateways.unwrap_or_default();
        gws.retain(|(g, _)| *g != target);
        gws.truncate(8);
        let ttl = if found { REACH_TTL } else { NO_RECORD_TTL };
        self.reach.insert(target, Reach { gateways: gws, until: now + ttl });
        self.next_sweep = self.next_sweep.min(now + ttl + REACH_STALE);
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
            self.next_sweep = self.next_sweep.min(now + REACH_REFRESH * 2);
        } else {
            self.stats.records_refused += 1;
        }
        ok
    }

    // ───────────── housekeeping ─────────────

    pub fn tick(&mut self, now: Time) {
        self.flush_announcements(now);
        self.flush_control(now);
        if !self.greet_q.is_empty() {
            self.greet_next(now);
        }
        // routes that went silent: forget them, retracting what that costs us
        if now >= self.next_expiry {
            let mut silent: Vec<SignPk> = Vec::new();
            let timeout = self.cfg.announce_every * 7 / 2;
            let fisheye = self.cfg.fisheye;
            let far_every = self.cfg.far_every.max(1);
            let mut next = Time::MAX;
            for (k, o) in self.origins.iter_mut() {
                let before = o.via.len();
                o.via.retain(|(_, v)| {
                    let scale = if fisheye && v.hops > NEAR_SCOPE { far_every } else { 1 };
                    let keep = now.saturating_sub(v.at) < timeout * scale;
                    if keep {
                        next = next.min(v.at + timeout * scale);
                    }
                    keep
                });
                if o.via.len() != before {
                    o.prune_chains();
                    silent.push(*k);
                    self.gc_check |= o.via.is_empty();
                }
            }
            self.next_expiry = next;
            silent.sort();
            for k in silent {
                self.touch(k);
                self.after_loss(k, None, now);
            }
        }
        let gc = self.gc_after();
        if self.gc_check || now >= self.next_gc {
            let mut gone: Vec<SignPk> = Vec::new();
            self.origins.retain(|k, o| {
                let keep = !o.via.is_empty() || o.pending.is_some() || now.saturating_sub(o.seen) < gc;
                if !keep {
                    gone.push(*k);
                }
                keep
            });
            for k in gone {
                self.touch(k);
            }
            self.next_gc = self
                .origins
                .values()
                .filter(|o| o.via.is_empty() && o.pending.is_none())
                .map(|o| o.seen + gc)
                .min()
                .unwrap_or(Time::MAX);
            self.gc_check = false;
        }
        if now >= self.next_sweep {
            self.sweep(now);
        }
        self.publish(now);
        self.choose_gateways(now);
    }

    /// Time-outs: half-assembled frames, parked frames, lookup answers,
    /// dials, records, idle internet hops. Then the next time one is due.
    fn sweep(&mut self, now: Time) {
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
        self.reach.retain(|_, r| r.until + REACH_STALE > now);
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
        self.distrusted.retain(|_, t| now < *t);
        let mut lapsed = Vec::new();
        self.suspects.retain(|k, v| {
            let before = v.len();
            v.retain(|(_, t)| now < *t);
            if v.len() != before {
                lapsed.push(*k);
            }
            !v.is_empty()
        });
        for k in lapsed {
            self.touch(k); // its routes may be offered again
        }
        let shunned = self.shunned.len();
        self.shunned.retain(|_, t| now < *t);
        if self.shunned.len() != shunned {
            self.touch_all(); // routes through it may be used again
        }
        self.vouched.retain(|_, v| {
            v.retain(|(_, t)| now < *t);
            !v.is_empty()
        });
        self.acked_via.retain(|_, (_, at)| now.saturating_sub(*at) < SUSPECT_FOR);
        // a long-quiet peer starts again from the minimum backoff
        self.backoff.retain(|_, (at, _)| now < *at + DIAL_BACKOFF_MAX);
        let mut next = Time::MAX;
        next = self.reasm.values().map(|r| r.at + REASM_TIMEOUT).fold(next, Time::min);
        next = self.pending.values().map(|p| p.since + PENDING_TIMEOUT).fold(next, Time::min);
        next = self.reach.values().map(|r| r.until + REACH_STALE).fold(next, Time::min);
        next = self.dialing.values().map(|t| t + DIAL_GIVE_UP).fold(next, Time::min);
        next = self.records.values().map(|t| t + REACH_REFRESH * 2).fold(next, Time::min);
        next = self.distrusted.values().copied().fold(next, Time::min);
        next = self.suspects.values().flatten().map(|(_, t)| *t).fold(next, Time::min);
        next = self.shunned.values().copied().fold(next, Time::min);
        next = self.backoff.values().map(|(at, _)| at + DIAL_BACKOFF_MAX).fold(next, Time::min);
        next = self.nbs.values().filter(|n| n.internet()).map(|n| n.last_used + INTERNET_IDLE).fold(next, Time::min);
        self.next_sweep = next;
    }

    /// Without the internet: keep a record naming our gateways published.
    fn choose_gateways(&mut self, now: Time) {
        if self.internet {
            self.my_gateways.clear();
            return;
        }
        self.gateway_pick(now);
        let Some((with_cost, g)) = &self.gw_pick else { return };
        let changed = *g != self.my_gateways;
        let gap_ok = self.last_reach.is_none_or(|t| now.saturating_sub(t) >= REACH_MIN_GAP);
        if !g.is_empty() && gap_ok && (changed || now >= self.reach_due) {
            let (with_cost, g) = (with_cost.clone(), g.clone());
            self.out.push(Out::PublishReach { gateways: with_cost });
            self.last_reach = Some(now);
            self.reach_due = now + REACH_REFRESH;
            self.my_gateways = g;
        } else if g.is_empty() {
            self.my_gateways.clear();
        }
    }

    /// The gateways to publish (with cost, and their sorted keys).
    fn gateway_pick(&mut self, now: Time) -> (&Vec<(SignPk, u32)>, &Vec<SignPk>) {
        self.gateway_routes_cached(now);
        if self.gw_pick.is_none() {
            let with_cost = Self::pick_gateways(self.gw_sorted.as_deref().unwrap_or_default(), self.cfg.gateways);
            let mut g: Vec<SignPk> = with_cost.iter().map(|(k, _)| *k).collect();
            g.sort();
            self.gw_pick = Some((with_cost, g));
        }
        let (w, g) = self.gw_pick.as_ref().expect("just made");
        (w, g)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod attest_tests;
