//! Store-and-forward ("delay-tolerant") carrying, as a pure state machine
//! like [`super::core`]: no I/O, no clock, no crypto (signatures are checked
//! through closures). Design record: `docs/ROUTING.md` §7; measurements:
//! `docs/BENCHMARKS.md` §6 and `docs/SIMULATION.md`.
//!
//! A **bundle** is an already-signed, already-encrypted batch of Mycel
//! envelopes for one destination key, with a lifetime, signed by its source.
//! Carriers learn the destination key, size and timing, never content.
//!
//! What a carrier does with a bundle, in order of preference:
//! 1. **Live or partial route**: the router knows a next hop toward the
//!    destination right now (a mesh route, the default route to a gateway,
//!    an internet hop to the destination's gateway): hand it on, with
//!    custody. Every step that exists now is taken now; the device at the
//!    break holds it.
//! 2. **Spray and gradient** ([`Spray`], [`Gradient`]): no next hop. While
//!    it holds copies to spare, half of them go to the likeliest neighbour
//!    without one (binary Spray-and-Wait steered by *delivery
//!    predictability*, PRoPHET, RFC 6693). A single copy moves, with
//!    custody, only to a neighbour with a clearly better predictability for
//!    **the internet** (a virtual destination: devices with the internet
//!    have P = 1), so it climbs toward connectivity instead of wandering.
//!    If a device with the internet finds the destination isn't on it (no
//!    reachability record, and dialling it failed), the internet doesn't
//!    count for that bundle: it moves by predictability for the destination.
//!    A device with the internet doesn't spray: it is where copies should
//!    end up (a mailbox).
//!
//! Small bundles get more copies than big ones ([`DtnConfig::copies_for`]).
//!
//! A device with the internet that holds a bundle for a destination behind
//! itself (it is one of the destination's gateways) is its **mailbox**: it
//! keeps it until the destination appears on its mesh. The destination
//! signs a **receipt**; receipts spread in summaries and every carrier
//! drops its copy.
//!
//! **Room.** What a device carries for others is bounded in total and per
//! source; its own bundles don't count. A full store drops the carried
//! bundles that expire soonest (the same source's first if that source is
//! over its share) for one that expires later, and refuses one that would
//! expire sooner. A bundle expires at its source's `created + lifetime`,
//! not a fresh lifetime per hop. Summaries say how much room is left and
//! what could make way, so neighbours don't offer what would be refused.
//!
//! **Summaries** ([`Carrier::summaries`]) tell each neighbour what it
//! needs, when it changes: what we hold (so it isn't offered again), new
//! receipts, our room, and the predictabilities the configured gradient
//! uses. With [`Gradient::Internet`] that is our predictability for the
//! internet, plus, for the destinations a neighbour holds bundles for
//! that the internet can't reach (its summary `wants` them), ours for
//! those. A neighbour gets everything at first contact, what changed at
//! most every [`SUMMARY_GAP`], and everything held every [`SUMMARY_FULL`]
//! (so it learns what we dropped). Nothing changes, nothing is sent
//! (docs/SIMULATION.md §4).
//!
//! **Offers.** A bundle is offered before it is sent ([`Offer`] →
//! [`Answer`]): a refusal costs a round trip, not the payload. A transfer
//! cut short leaves its bytes with the receiver ([`Carrier::keep_partial`])
//! for a few minutes, and the next offer of that bundle, from anyone (the id
//! is the hash of its content), resumes where it stopped.
//!
//! # API
//!
//! ```text
//! Carrier::new(me, DtnConfig)
//!   set_internet(bool)
//!   set_clock(now, wall_ms)                   bundles' `created` is a wall clock
//!   encounter(peer, now)                      a neighbour came into range (P rises)
//!   originate(Bundle, now) -> Result           a bundle of ours
//!   offered(from, &Offer, now, verify) -> Answer   before the payload
//!   keep_partial(id, src, bytes, now)          a transfer to us was cut short
//!   partial(id) -> Option<&Bytes>              what arrived of it so far
//!   accept(from, Bundle, copies, now, verify)  the whole bundle -> Accepted
//!   summaries(now, neighbours) -> Vec<(peer, Summary)>   what to tell whom now
//!   new_contact(peer)                          a new hop connection: tell it everything
//!   summary(now) -> Summary                    everything, to anyone
//!   on_summary(from, Summary, now, verify_receipt)
//!   add_receipt(Receipt)                       we were the destination
//!   plan(now, toward, neighbours) -> Vec<Transfer>   what to offer to whom now
//!   transferred(to, id, copies, ok, now)       the outcome of a Transfer
//!   refused(to, id, full, now)                 the offer was refused
//!   tick(now)                                  expiry and ageing
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use bytes::Bytes;
use mycel_crypto::{Hash32, Sig, SignPk};

use super::core::{Time, Toward};

/// Maps keyed by bundle ids and device keys: hashes and public keys, so
/// already uniform. A word-at-a-time hash; FNV byte by byte was most of
/// the time `plan` and `on_summary` took over thousands of bundles.
type Map<K, V> = HashMap<K, V, BuildHasherDefault<WordHash>>;
type Set<K> = HashSet<K, BuildHasherDefault<WordHash>>;

#[derive(Default)]
struct WordHash(u64);

impl Hasher for WordHash {
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
    }

    fn finish(&self) -> u64 {
        // mix the high bits down: tables index by the low ones
        let x = (self.0 ^ (self.0 >> 32)).wrapping_mul(0xd6e8_feb8_6659_fd93);
        x ^ (x >> 32)
    }
}

/// How long a destination stays doubted ([`Carrier::doubt`]), and how many
/// are remembered.
const DOUBT_FOR: Time = 10 * 60_000;
const DOUBTED_MAX: usize = 1024;

/// The virtual destination "the internet" in predictability tables.
pub const INTERNET: SignPk = SignPk([0xff; 32]);

/// PRoPHET (RFC 6693) parameters: the rise on an encounter, transitivity
/// damping, ageing per minute.
const P_ENCOUNTER: f64 = 0.7;
const BETA: f64 = 0.9;
const GAMMA_PER_MIN: f64 = 0.98;
/// Forward along the gradient only to a clearly better neighbour.
const MARGIN: f64 = 0.05;
/// What a summary carries at most.
const SUMMARY_IDS: usize = 512;
const SUMMARY_RECEIPTS: usize = 256;
const SUMMARY_PREDS: usize = 64;
const SUMMARY_EVICTABLE: usize = 32;
const SUMMARY_WANTS: usize = 16;
/// What changed goes to a neighbour at most this often (ms)...
pub const SUMMARY_GAP: Time = 2_000;
/// ...and everything we hold this often, for it to drop what we no longer do.
pub const SUMMARY_FULL: Time = 60_000;
const RECEIPTS_MAX: usize = 4096;
/// A transfer in flight to a neighbour is not repeated meanwhile.
const IN_FLIGHT: Time = 30_000;
/// A neighbour's summary is forgotten this long after we last heard from it
/// (neighbours in range send one every few seconds; a phone in a crowd
/// meets thousands of devices a day).
const NB_FORGET: Time = 10 * 60_000;
/// The bytes of a cut-short transfer are kept this long for a resume.
const PARTIAL_KEEP: Time = 5 * 60_000;
/// Forgetting (stale partial transfers, negligible predictabilities,
/// neighbours long gone) runs at most this often.
const HOUSEKEEP: Time = 10_000;
/// Bundles this small get [`DtnConfig::copies_small`] copies; this big and
/// bigger, [`DtnConfig::copies`]; in between, geometrically fewer.
const SMALL: usize = 16 << 10;
const LARGE: usize = 256 << 10;

/// How copies spread when no live route exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spray {
    /// While it has copies to spare, half go to the likeliest neighbour
    /// without one, better than us or not, before the gradient is
    /// consulted; the gradient moves single copies (binary Spray-and-Wait
    /// steered by predictability).
    First,
    /// The gradient first; with no clearly better neighbour, copies to
    /// spare go to the likeliest neighbour, better or not.
    Fallback,
    /// Spray-and-Focus (Spyropoulos et al., 2007): the gradient first;
    /// with no clearly better neighbour, copies to spare go to the
    /// likeliest neighbour that is no worse a carrier than us.
    Focus,
}

/// What a carrier's predictability measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gradient {
    /// Reaching the internet (the destination itself once the internet has
    /// proved not to lead there).
    Internet,
    /// The better of reaching the destination and reaching the internet.
    Both,
    /// Reaching the destination (classic PRoPHET).
    Destination,
    /// Nothing: copies move by spraying and live routes only.
    Off,
}

#[derive(Clone, Debug)]
pub struct DtnConfig {
    /// Bytes held for others in total.
    pub capacity: u64,
    /// The largest bundle accepted.
    pub max_bundle: usize,
    /// Bytes held for one source.
    pub per_source: u64,
    /// The longest lifetime honoured (ms).
    pub max_lifetime: Time,
    /// Copies a big bundle (256 KiB or more) starts with (Spray-and-Wait's L).
    pub copies: u8,
    /// Copies a small one (16 KiB or less) starts with: small bundles are
    /// cheap to copy, and chat needs the spread.
    pub copies_small: u8,
    pub spray: Spray,
    pub gradient: Gradient,
    /// The gradient discounts a neighbour by how few more bundles of this
    /// size its free room takes (fewer than `ROOM_HEADROOM`): a full
    /// gateway draws bundles it can only hold briefly. On by default: it
    /// takes The ONE's Helsinki with tram gateways (heavy) from 37.2% to
    /// 52.7% and changes nothing elsewhere (docs/BENCHMARKS.md §6.5).
    pub room_aware: bool,
    /// Carry bundles for others at all.
    pub carry: bool,
}

impl Default for DtnConfig {
    fn default() -> Self {
        DtnConfig {
            capacity: 64 << 20,
            max_bundle: 256 << 10,
            per_source: 4 << 20,
            max_lifetime: 7 * 24 * 3600 * 1000,
            copies: 4,
            copies_small: 32,
            spray: Spray::First,
            gradient: Gradient::Internet,
            room_aware: true,
            carry: true,
        }
    }
}

impl DtnConfig {
    /// Copies a new bundle of `size` bytes starts with.
    pub fn copies_for(&self, size: usize) -> u8 {
        let lo = self.copies.max(1);
        let hi = self.copies_small.max(lo);
        if size <= SMALL {
            return hi;
        }
        if size >= LARGE {
            return lo;
        }
        let x = (size as f64 / SMALL as f64).ln() / (LARGE as f64 / SMALL as f64).ln();
        (hi as f64 * (lo as f64 / hi as f64).powf(x)).round().clamp(lo as f64, hi as f64) as u8
    }

    /// Set knobs from `key=value,...` (`spray=first|fallback|focus`,
    /// `gradient=internet|both|destination|off`, `copies=N`,
    /// `copies_small=N`, `room=on|off`), for experiments.
    pub fn tune(&mut self, s: &str) -> Result<(), String> {
        for kv in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("{kv}: expected key=value"))?;
            match (k, v) {
                ("spray", "first") => self.spray = Spray::First,
                ("spray", "fallback") => self.spray = Spray::Fallback,
                ("spray", "focus") => self.spray = Spray::Focus,
                ("gradient", "internet") => self.gradient = Gradient::Internet,
                ("gradient", "both") => self.gradient = Gradient::Both,
                ("gradient", "destination") => self.gradient = Gradient::Destination,
                ("gradient", "off") => self.gradient = Gradient::Off,
                ("copies", n) => self.copies = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                ("copies_small", n) => self.copies_small = n.parse().map_err(|e| format!("{kv}: {e}"))?,
                ("room", "on") => self.room_aware = true,
                ("room", "off") => self.room_aware = false,
                _ => return Err(format!("{kv}: unknown knob")),
            }
        }
        Ok(())
    }
}

/// A bundle. `id` = H(src, dst, payload) (the same data is the same
/// bundle); `sig` is the source's over `(id, created, lifetime)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub id: Hash32,
    pub src: SignPk,
    pub dst: SignPk,
    /// Wall-clock ms at the source.
    pub created: u64,
    /// ms after `created` it is worth delivering.
    pub lifetime: u64,
    pub payload: Bytes,
    pub sig: Sig,
}

/// A bundle offered before its payload: everything but the bytes. The
/// signature covers `(id, created, lifetime)`; the id is checked against
/// the payload once it has arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub id: Hash32,
    pub src: SignPk,
    pub dst: SignPk,
    pub size: u64,
    pub created: u64,
    pub lifetime: u64,
    pub copies: u8,
    pub sig: Sig,
}

impl Offer {
    pub fn of(b: &Bundle, copies: u8) -> Offer {
        Offer {
            id: b.id,
            src: b.src,
            dst: b.dst,
            size: b.payload.len() as u64,
            created: b.created,
            lifetime: b.lifetime,
            copies,
            sig: b.sig,
        }
    }
}

/// The answer to an [`Offer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Send the payload from byte `from` (the bytes before it arrived
    /// earlier).
    Take {
        from: u64,
    },
    /// Already held (the copies offered are added to ours), delivered, or
    /// receipted: nothing to send.
    Duplicate,
    Refuse(&'static str),
}

/// "I, `dst`, have bundle `id`", signed by `dst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub id: Hash32,
    pub dst: SignPk,
    pub sig: Sig,
}

/// What a carrier tells its neighbours.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    /// `ids` are everything it holds (they replace what we knew), not only
    /// what it took since its last summary to us.
    pub full: bool,
    /// Bundles it holds (so nobody sends them again).
    pub ids: Vec<Hash32>,
    /// Receipts it hasn't told us of yet.
    pub receipts: Vec<Receipt>,
    /// The delivery predictabilities its gradient uses (including
    /// [`INTERNET`]); they replace its last ones.
    pub preds: Vec<(SignPk, f32)>,
    /// Bytes it still has room for, for others.
    pub free: u64,
    /// What could make way: its soonest-expiring carried bundles, as
    /// (ms until they expire, size). Only a bundle expiring later can push
    /// them out.
    pub evictable: Vec<(u64, u64)>,
    /// Destinations it holds bundles for that the internet doesn't lead
    /// to: it asks for our predictabilities for them.
    pub wants: Vec<SignPk>,
}

/// Hand `copies` copies of bundle `id` to `to` (custody if it is all of them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub to: SignPk,
    pub id: Hash32,
    pub copies: u8,
    pub why: Why,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The destination itself.
    Deliver,
    /// The next hop of a live (or partial) route.
    Route,
    /// A neighbour with better delivery predictability.
    Gradient,
    /// Copies to spare, to a likely neighbour.
    Spray,
}

/// What happened to a bundle handed to us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// For us: deliver it (and sign a receipt).
    ForMe(Bundle),
    Stored,
    /// Already held, already delivered, or receipted.
    Duplicate,
    Refused(&'static str),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DtnStats {
    pub originated: u64,
    pub accepted: u64,
    pub delivered: u64,
    pub handed_on: u64,
    pub expired: u64,
    pub cleared_by_receipt: u64,
    /// Offers and bundles refused.
    pub refused: u64,
    /// Carried bundles dropped to make room for fresher ones.
    pub evicted: u64,
    /// Offers answered from a byte already received (resumed transfers).
    pub resumed: u64,
}

struct Held {
    b: Bundle,
    copies: u8,
    /// Expiry on our clock.
    until: Time,
    /// Who handed it to us: gradient and spray never send it back.
    from: Option<SignPk>,
    /// `Carrier::rev` when we took it (what a summary says is new).
    rev: u64,
    /// Neighbours we gave copies of our own bundle to: each gets one share
    /// (they may pass it on and forget it, but it went that way).
    given: Vec<SignPk>,
}

/// What we last told a neighbour, and when.
#[derive(Clone, Copy, Debug)]
struct Sent {
    at: Time,
    full_at: Time,
    rev: u64,
    receipts: u64,
    /// `Carrier::fingerprint` of its predictabilities and our wants.
    fp: u64,
}

/// The room a neighbour last said it had, less what we sent it since.
#[derive(Clone, Debug, Default)]
struct Room {
    free: u64,
    /// (expiry on our clock, size), soonest first.
    evictable: Vec<(Time, u64)>,
}

impl Room {
    /// Room for a bundle of `size` that expires at `until`.
    fn fits(&self, size: u64, until: Time) -> bool {
        self.free + self.evictable.iter().filter(|(u, _)| *u < until).map(|(_, s)| s).sum::<u64>() >= size
    }

    /// How much a neighbour this full counts for a bundle of `size`: 1 with
    /// room for [`ROOM_HEADROOM`] more, less below that.
    fn weight(&self, size: u64) -> f64 {
        (self.free as f64 / (ROOM_HEADROOM * size.max(1)) as f64).min(1.0)
    }

    fn take(&mut self, size: u64) {
        let f = self.free.min(size);
        self.free -= f;
        let mut need = size - f;
        while need > 0 && !self.evictable.is_empty() {
            need = need.saturating_sub(self.evictable.remove(0).1);
        }
    }
}

/// See [`DtnConfig::room_aware`].
const ROOM_HEADROOM: u64 = 4;

/// What a neighbour told us, for one plan.
struct Nb<'a> {
    k: SignPk,
    has: Option<&'a Set<Hash32>>,
    refused: Option<&'a Set<Hash32>>,
    room: Option<&'a Room>,
    pred: Option<&'a NbPreds>,
}

/// A neighbour's utility for `dst` by `gradient`, from its predictability
/// table, counting the internet only if it leads to `dst` (`inet`).
/// A neighbour's predictabilities from its last summary, sorted by key: a
/// device remembers one per neighbour, and at 64 entries a sorted `Vec` is
/// half the size of a hash map (docs/SIMULATION.md §4).
type NbPreds = Vec<(SignPk, f32)>;

fn nb_p(t: &NbPreds, x: &SignPk) -> f64 {
    t.binary_search_by(|(k, _)| k.cmp(x)).map_or(0.0, |i| t[i].1 as f64)
}

fn utility_in(gradient: Gradient, table: Option<&NbPreds>, dst: &SignPk, inet: bool) -> f64 {
    table.map_or(0.0, |t| {
        let d = || nb_p(t, dst);
        let i = || if inet { nb_p(t, &INTERNET) } else { 0.0 };
        match gradient {
            Gradient::Internet if inet => i(),
            Gradient::Internet | Gradient::Destination => d(),
            Gradient::Both => d().max(i()),
            Gradient::Off => 0.0,
        }
    })
}

/// The first bytes of a bundle whose transfer to us was cut short.
struct Partial {
    src: SignPk,
    bytes: Bytes,
    at: Time,
}

/// One device's store-and-forward carrier.
pub struct Carrier {
    me: SignPk,
    cfg: DtnConfig,
    internet: bool,
    /// Our wall clock minus our clock (ms): `created` is the source's wall clock.
    wall_offset: i64,
    held: BTreeMap<Hash32, Held>,
    /// What we hold by expiry, soonest first.
    expiry: BTreeSet<(Time, Hash32)>,
    used: u64,
    by_source: Map<SignPk, u64>,
    /// Our delivery predictabilities and when each was last aged.
    pred: Map<SignPk, (f64, Time)>,
    /// Neighbours' last summaries: their predictabilities, ids and room.
    nb_pred: Map<SignPk, NbPreds>,
    nb_has: Map<SignPk, Set<Hash32>>,
    nb_room: Map<SignPk, Room>,
    /// Bundles a neighbour refused, not offered again before its next summary.
    nb_refused: Map<SignPk, Set<Hash32>>,
    /// When each neighbour last told us anything (for forgetting).
    nb_heard: Map<SignPk, Time>,
    receipts: Map<Hash32, Receipt>,
    /// Receipts in the order we learnt them, numbered.
    receipt_order: VecDeque<(u64, Hash32)>,
    receipt_seq: u64,
    /// Bumped whenever what we hold changes.
    rev: u64,
    /// What we last told each neighbour.
    sent: Map<SignPk, Sent>,
    /// Destinations of bundles we hold that the internet doesn't lead to.
    wanted: Vec<SignPk>,
    /// What each neighbour asked our predictabilities for.
    nb_wants: Map<SignPk, Vec<SignPk>>,
    /// Offers under way: bundle -> (to, since, copies). Their copies aren't
    /// ours to give again meanwhile (a transfer can take seconds).
    in_flight: Map<Hash32, Vec<(SignPk, Time, u8)>>,
    /// Destinations whose live route just failed (`doubt`), until when.
    doubted: Map<SignPk, Time>,
    partial: Map<Hash32, Partial>,
    partial_used: u64,
    housekept: Option<Time>,
    stats: DtnStats,
}

impl Carrier {
    pub fn new(me: SignPk, cfg: DtnConfig) -> Carrier {
        Carrier {
            me,
            cfg,
            internet: false,
            wall_offset: 0,
            held: BTreeMap::new(),
            expiry: BTreeSet::new(),
            used: 0,
            by_source: Map::default(),
            pred: Map::default(),
            nb_pred: Map::default(),
            nb_has: Map::default(),
            nb_room: Map::default(),
            nb_refused: Map::default(),
            nb_heard: Map::default(),
            receipts: Map::default(),
            receipt_order: VecDeque::new(),
            receipt_seq: 0,
            rev: 0,
            sent: Map::default(),
            wanted: Vec::new(),
            nb_wants: Map::default(),
            in_flight: Map::default(),
            doubted: Map::default(),
            partial: Map::default(),
            partial_used: 0,
            housekept: None,
            stats: DtnStats::default(),
        }
    }

    pub fn stats(&self) -> DtnStats {
        self.stats
    }

    pub fn config(&self) -> &DtnConfig {
        &self.cfg
    }

    pub fn held(&self) -> Vec<Hash32> {
        self.held.keys().copied().collect()
    }

    pub fn holds(&self, id: &Hash32) -> bool {
        self.held.contains_key(id)
    }

    pub fn has_any(&self) -> bool {
        !self.held.is_empty()
    }

    pub fn set_internet(&mut self, on: bool) {
        if self.internet != on {
            self.rev += 1;
        }
        self.internet = on;
    }

    /// Our wall clock reads `wall_ms` at `now` (bundles' `created` and
    /// lifetimes are on their source's wall clock). Without it, `created`
    /// is taken to be on our clock.
    pub fn set_clock(&mut self, now: Time, wall_ms: u64) {
        self.wall_offset = wall_ms as i64 - now as i64;
    }

    /// When a bundle stops being worth carrying, on our clock: at its
    /// source's `created + lifetime`, and no later than its lifetime (and
    /// `max_lifetime`) from now, whatever the source's clock says.
    fn until(&self, created: u64, lifetime: u64, now: Time) -> Option<Time> {
        let cap = now as i128 + lifetime.min(self.cfg.max_lifetime) as i128;
        let end = created as i128 + lifetime as i128 - self.wall_offset as i128;
        let until = end.min(cap);
        (until > now as i128).then_some(until as Time)
    }

    // ───────────── PRoPHET ─────────────

    /// Our delivery predictability for `x`, aged to `now`.
    pub fn p(&self, x: &SignPk, now: Time) -> f64 {
        if *x == INTERNET && self.internet {
            return 1.0;
        }
        self.pred.get(x).map_or(0.0, |(p, at)| p * GAMMA_PER_MIN.powf(now.saturating_sub(*at) as f64 / 60_000.0))
    }

    fn set_p(&mut self, x: SignPk, p: f64, now: Time) {
        self.pred.insert(x, (p.clamp(0.0, 1.0), now));
    }

    /// We are in range of `peer`: P(peer) = P + (1 − P)·P_enc.
    pub fn encounter(&mut self, peer: SignPk, now: Time) {
        let p = self.p(&peer, now);
        self.set_p(peer, p + (1.0 - p) * P_ENCOUNTER, now);
    }

    /// How good a carrier we are for `dst` by the configured [`Gradient`],
    /// counting the internet only if it leads to `dst` (`inet`).
    fn utility(&self, dst: &SignPk, inet: bool, now: Time) -> f64 {
        let d = || self.p(dst, now);
        let i = || if inet { self.p(&INTERNET, now) } else { 0.0 };
        match self.cfg.gradient {
            Gradient::Internet if inet => i(),
            Gradient::Internet | Gradient::Destination => d(),
            Gradient::Both => d().max(i()),
            Gradient::Off => 0.0,
        }
    }

    // ───────────── bundles in ─────────────

    /// A bundle of ours, to carry with as many copies as its size gets.
    pub fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str> {
        if self.held.contains_key(&b.id) || self.receipts.contains_key(&b.id) {
            return Ok(());
        }
        let copies = self.cfg.copies_for(b.payload.len());
        self.store(b, copies, now, None)?;
        self.stats.originated += 1;
        Ok(())
    }

    /// `from` offers a bundle; `verify` checks the source's signature over
    /// the offer. Taking it means room for it now; the payload follows.
    pub fn offered(&mut self, from: SignPk, o: &Offer, now: Time, verify: impl FnOnce(&Offer) -> bool) -> Answer {
        self.nb_has.entry(from).or_default().insert(o.id);
        self.nb_heard.insert(from, now);
        if self.receipts.contains_key(&o.id) {
            return Answer::Duplicate;
        }
        if let Some(h) = self.held.get_mut(&o.id) {
            h.copies = h.copies.saturating_add(o.copies);
            return Answer::Duplicate;
        }
        if !verify(o) {
            self.stats.refused += 1;
            return Answer::Refuse("bad signature");
        }
        if o.dst != self.me
            && let Err(why) = self.admit(o.src, o.size, o.created, o.lifetime, now)
        {
            self.stats.refused += 1;
            return Answer::Refuse(why);
        }
        let from = self.partial.get(&o.id).map_or(0, |p| p.bytes.len() as u64).min(o.size);
        if from > 0 {
            self.stats.resumed += 1;
        }
        Answer::Take { from }
    }

    /// Bundle `id` from `src` arrived only as far as `bytes` (its first
    /// bytes): keep them a few minutes for the next offer to resume from.
    /// Bounded in total (a quarter of `capacity`) and per source (two
    /// bundles' worth); the oldest go first.
    pub fn keep_partial(&mut self, id: Hash32, src: SignPk, bytes: Bytes, now: Time) {
        if bytes.is_empty() || self.held.contains_key(&id) || self.receipts.contains_key(&id) {
            return;
        }
        if self.partial.get(&id).is_some_and(|p| p.bytes.len() >= bytes.len()) {
            return;
        }
        self.drop_partial(&id);
        let n = bytes.len() as u64;
        let (total, per_source) = (self.cfg.capacity / 4, 2 * self.cfg.max_bundle as u64);
        if n > total.min(per_source) {
            return;
        }
        let mut old: Vec<(Time, Hash32, SignPk, u64)> =
            self.partial.iter().map(|(k, p)| (p.at, *k, p.src, p.bytes.len() as u64)).collect();
        old.sort_unstable();
        let mut src_used: u64 = old.iter().filter(|x| x.2 == src).map(|x| x.3).sum();
        for (_, k, s, len) in old {
            let (all_over, src_over) = (self.partial_used + n > total, src_used + n > per_source);
            if !all_over && !src_over {
                break;
            }
            if all_over || s == src {
                self.drop_partial(&k);
                if s == src {
                    src_used -= len;
                }
            }
        }
        self.partial_used += n;
        self.partial.insert(id, Partial { src, bytes, at: now });
    }

    /// What arrived of bundle `id` in transfers cut short.
    pub fn partial(&self, id: &Hash32) -> Option<&Bytes> {
        self.partial.get(id).map(|p| &p.bytes)
    }

    fn drop_partial(&mut self, id: &Hash32) {
        if let Some(p) = self.partial.remove(id) {
            self.partial_used -= p.bytes.len() as u64;
        }
    }

    /// A bundle handed to us by `from` with `copies` copies. `verify`
    /// checks the source's signature.
    pub fn accept(
        &mut self,
        from: SignPk,
        b: Bundle,
        copies: u8,
        now: Time,
        verify: impl FnOnce(&Bundle) -> bool,
    ) -> Accepted {
        self.nb_has.entry(from).or_default().insert(b.id);
        self.nb_heard.insert(from, now);
        if self.receipts.contains_key(&b.id) {
            return Accepted::Duplicate;
        }
        if let Some(h) = self.held.get_mut(&b.id) {
            h.copies = h.copies.saturating_add(copies);
            return Accepted::Duplicate;
        }
        if !verify(&b) {
            self.stats.refused += 1;
            return Accepted::Refused("bad signature");
        }
        self.drop_partial(&b.id);
        if b.dst == self.me {
            self.stats.delivered += 1;
            return Accepted::ForMe(b);
        }
        if !self.cfg.carry {
            self.stats.refused += 1;
            return Accepted::Refused("not carrying");
        }
        match self.store(b, copies.max(1), now, Some(from)) {
            Ok(()) => {
                self.stats.accepted += 1;
                Accepted::Stored
            }
            Err(why) => {
                self.stats.refused += 1;
                Accepted::Refused(why)
            }
        }
    }

    /// Whether we would carry a bundle of `size` from `src` for another
    /// device: its expiry, and which carried bundles would make way.
    fn admit(
        &self,
        src: SignPk,
        size: u64,
        created: u64,
        lifetime: u64,
        now: Time,
    ) -> Result<(Time, Vec<Hash32>), &'static str> {
        if !self.cfg.carry {
            return Err("not carrying");
        }
        if size > self.cfg.max_bundle as u64 {
            return Err("too big");
        }
        let until = self.until(created, lifetime, now).ok_or("expired")?;
        Ok((until, self.room_for(src, size, until)?))
    }

    /// The carried bundles (never our own) to drop for one of `size` from
    /// `src` expiring at `until`: only ones that expire before it, soonest
    /// first, the same source's first while it is over its share
    /// (drop-oldest: Lindgren & Phanse, 2006). An error, dropping nothing,
    /// if that doesn't make room.
    fn room_for(&self, src: SignPk, size: u64, until: Time) -> Result<Vec<Hash32>, &'static str> {
        let mut src_used = self.by_source.get(&src).copied().unwrap_or(0);
        let mut used = self.used;
        let share = |s: u64| s + size <= self.cfg.per_source;
        let all = |u: u64| u + size <= self.cfg.capacity;
        if share(src_used) && all(used) {
            return Ok(Vec::new());
        }
        let older: Vec<(Time, Hash32, u64, SignPk)> = self
            .expiry
            .iter()
            .take_while(|(u, _)| *u < until)
            .filter_map(|(u, id)| {
                let h = self.held.get(id).filter(|h| h.from.is_some())?;
                Some((*u, *id, h.b.payload.len() as u64, h.b.src))
            })
            .collect();
        let mut out = Vec::new();
        for (_, id, n, _) in older.iter().filter(|x| x.3 == src) {
            if share(src_used) {
                break;
            }
            out.push(*id);
            src_used -= n;
            used -= n;
        }
        if !share(src_used) {
            return Err("source over its share");
        }
        let gone: Set<Hash32> = out.iter().copied().collect();
        for (_, id, n, _) in older.iter().filter(|x| !gone.contains(&x.1)) {
            if all(used) {
                break;
            }
            out.push(*id);
            used -= n;
        }
        if !all(used) {
            return Err("store full");
        }
        Ok(out)
    }

    fn store(&mut self, b: Bundle, copies: u8, now: Time, from: Option<SignPk>) -> Result<(), &'static str> {
        let size = b.payload.len() as u64;
        if b.payload.len() > self.cfg.max_bundle {
            return Err("too big");
        }
        let until = self.until(b.created, b.lifetime, now).ok_or("expired")?;
        // `capacity` and `per_source` bound what we carry for others; our
        // own bundles are the user's own messages
        if from.is_some() {
            let victims = self.room_for(b.src, size, until)?;
            for v in &victims {
                self.drop_held(v);
            }
            self.stats.evicted += victims.len() as u64;
            self.used += size;
            *self.by_source.entry(b.src).or_default() += size;
        }
        self.drop_partial(&b.id);
        self.expiry.insert((until, b.id));
        self.rev += 1;
        self.held.insert(b.id, Held { b, copies, until, from, rev: self.rev, given: Vec::new() });
        Ok(())
    }

    fn drop_held(&mut self, id: &Hash32) {
        let Some(h) = self.held.remove(id) else { return };
        self.rev += 1;
        self.expiry.remove(&(h.until, *id));
        if h.from.is_some() {
            let size = h.b.payload.len() as u64;
            self.used = self.used.saturating_sub(size);
            if let Some(s) = self.by_source.get_mut(&h.b.src) {
                *s = s.saturating_sub(size);
            }
        }
    }

    /// The bundle itself, to send in a [`Transfer`].
    pub fn bundle(&self, id: &Hash32) -> Option<&Bundle> {
        self.held.get(id).map(|h| &h.b)
    }

    // ───────────── receipts and summaries ─────────────

    /// We delivered `r.id` to ourselves (we are `r.dst`), or learnt of it.
    pub fn add_receipt(&mut self, r: Receipt) {
        if self.held.contains_key(&r.id) {
            self.drop_held(&r.id);
            self.stats.cleared_by_receipt += 1;
        }
        self.drop_partial(&r.id);
        if self.receipts.insert(r.id, r).is_none() {
            self.receipt_seq += 1;
            self.receipt_order.push_back((self.receipt_seq, r.id));
            while self.receipt_order.len() > RECEIPTS_MAX {
                if let Some((_, old)) = self.receipt_order.pop_front() {
                    self.receipts.remove(&old);
                }
            }
        }
    }

    /// Everything, to anyone (no neighbour's wants answered).
    pub fn summary(&self, now: Time) -> Summary {
        self.build(None, true, None, now)
    }

    /// `peer` is a new contact (a hop connection just came up): the next
    /// [`Carrier::summaries`] tells it everything.
    pub fn new_contact(&mut self, peer: SignPk) {
        self.sent.remove(&peer);
    }

    /// The summaries due now: everything for a neighbour we haven't told
    /// anything yet and, every [`SUMMARY_FULL`], for the others; what
    /// changed since our last one, at most every [`SUMMARY_GAP`]; nothing
    /// if nothing did.
    pub fn summaries(&mut self, now: Time, neighbours: &[SignPk]) -> Vec<(SignPk, Summary)> {
        let mut out = Vec::new();
        for k in neighbours {
            let last = self.sent.get(k).copied();
            let fp = self.fingerprint(k, now);
            let full = match last {
                None => true,
                Some(s) if now.saturating_sub(s.full_at) >= SUMMARY_FULL => true,
                Some(s)
                    if now.saturating_sub(s.at) >= SUMMARY_GAP
                        && (s.rev != self.rev || s.receipts != self.receipt_seq || s.fp != fp) =>
                {
                    false
                }
                Some(_) => continue,
            };
            out.push((*k, self.build(Some(k), full, last, now)));
            let full_at = match last {
                Some(s) if !full => s.full_at,
                _ => now,
            };
            self.sent.insert(*k, Sent { at: now, full_at, rev: self.rev, receipts: self.receipt_seq, fp });
        }
        out
    }

    /// The predictabilities our gradient uses, for neighbour `nb`. A
    /// gradient that follows destinations, and any `full` summary, gets the
    /// most useful [`SUMMARY_PREDS`] (the internet's among them: PRoPHET's
    /// transitivity carries them hop by hop, and [`Gradient::Internet`]
    /// falls back on destinations the internet doesn't lead to). Between
    /// full summaries, [`Gradient::Internet`] sends only the internet's, and
    /// ours for the destinations `nb` asked for. No gradient, none.
    fn preds_for(&self, nb: Option<&SignPk>, full: bool, now: Time) -> Vec<(SignPk, f32)> {
        let all = || self.pred.keys().copied().chain(std::iter::once(INTERNET));
        let mut preds: Vec<(SignPk, f32)> = match self.cfg.gradient {
            Gradient::Off => return Vec::new(),
            Gradient::Internet if !full => std::iter::once(INTERNET).map(|k| (k, self.p(&k, now) as f32)).collect(),
            _ => all().map(|k| (k, self.p(&k, now) as f32)).collect(),
        };
        preds.retain(|(_, p)| *p > 0.01);
        preds.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        preds.dedup_by_key(|(k, _)| *k);
        preds.truncate(SUMMARY_PREDS);
        // and what `nb` asked for, whatever its rank
        if self.cfg.gradient == Gradient::Internet
            && let Some(w) = nb.and_then(|k| self.nb_wants.get(k))
        {
            for k in w {
                let p = self.p(k, now) as f32;
                if p > 0.01 && !preds.iter().any(|(x, _)| x == k) {
                    preds.push((*k, p));
                }
            }
        }
        preds
    }

    /// What `nb` would hear from us besides bundles and receipts: our
    /// predictabilities for it, to a twentieth (they age by the minute;
    /// a summary per drift would be noise), and what we want.
    fn fingerprint(&self, nb: &SignPk, now: Time) -> u64 {
        let mut h = WordHash::default();
        for (k, p) in self.preds_for(Some(nb), false, now) {
            h.write(&k.0);
            h.write(&[(p * 20.0).round() as u8]);
        }
        h.write(&[0xfe]);
        for k in &self.wanted {
            h.write(&k.0);
        }
        h.finish()
    }

    /// A summary for `nb` (`None`: anyone): everything held, and the latest
    /// receipts, if `full`; else what we took and learnt since `last`.
    fn build(&self, nb: Option<&SignPk>, full: bool, last: Option<Sent>, now: Time) -> Summary {
        let ids = match last {
            Some(l) if !full => {
                self.held.iter().filter(|(_, h)| h.rev > l.rev).map(|(k, _)| *k).take(SUMMARY_IDS).collect()
            }
            _ => self.held.keys().rev().take(SUMMARY_IDS).copied().collect(),
        };
        // receipts it hasn't heard from us (a summary that may not have
        // arrived resets this: `new_contact`)
        let since = last.map_or(0, |l| l.receipts);
        let receipts = self
            .receipt_order
            .iter()
            .rev()
            .take_while(|(n, _)| *n > since)
            .take(SUMMARY_RECEIPTS)
            .filter_map(|(_, id)| self.receipts.get(id))
            .copied()
            .collect();
        let (free, evictable) = if self.cfg.carry {
            let mut v: Vec<(u64, u64)> = self
                .held
                .values()
                .filter(|h| h.from.is_some())
                .map(|h| (h.until.saturating_sub(now), h.b.payload.len() as u64))
                .collect();
            if v.len() > SUMMARY_EVICTABLE {
                v.select_nth_unstable(SUMMARY_EVICTABLE);
                v.truncate(SUMMARY_EVICTABLE);
            }
            v.sort_unstable();
            (self.cfg.capacity.saturating_sub(self.used), v)
        } else {
            (0, Vec::new())
        };
        Summary {
            full,
            ids,
            receipts,
            preds: self.preds_for(nb, full, now),
            free,
            evictable,
            wants: self.wanted.clone(),
        }
    }

    /// A neighbour's summary: what it holds and has room for, receipts
    /// (checked by `verify_receipt`), and its predictabilities (PRoPHET
    /// transitivity).
    pub fn on_summary(
        &mut self,
        from: SignPk,
        s: Summary,
        now: Time,
        mut verify_receipt: impl FnMut(&Receipt) -> bool,
    ) {
        let ids = s.ids.iter().copied().take(SUMMARY_IDS);
        if s.full && s.ids.len() < SUMMARY_IDS {
            self.nb_has.insert(from, ids.collect());
        } else {
            // what it took since, or a full list that is only part of what
            // it holds: add to what we knew
            self.nb_has.entry(from).or_default().extend(ids);
        }
        if s.wants.is_empty() {
            self.nb_wants.remove(&from);
        } else {
            let mut w: Vec<SignPk> = s.wants.iter().copied().take(SUMMARY_WANTS).collect();
            w.sort();
            w.dedup();
            self.nb_wants.insert(from, w);
        }
        self.nb_heard.insert(from, now);
        self.nb_refused.remove(&from);
        let mut evictable: Vec<(Time, u64)> =
            s.evictable.iter().take(SUMMARY_EVICTABLE).map(|(left, size)| (now.saturating_add(*left), *size)).collect();
        evictable.sort_unstable();
        self.nb_room.insert(from, Room { free: s.free, evictable });
        for r in s.receipts.into_iter().take(SUMMARY_RECEIPTS) {
            if !self.receipts.contains_key(&r.id) && verify_receipt(&r) {
                self.add_receipt(r);
            }
        }
        let p_from = self.p(&from, now);
        let full = s.full;
        let mut table: NbPreds = Vec::with_capacity(s.preds.len().min(SUMMARY_PREDS + SUMMARY_WANTS));
        for (x, px) in s.preds.into_iter().take(SUMMARY_PREDS + SUMMARY_WANTS) {
            // (`clamp` keeps a NaN: one would outrank every real
            // predictability where candidates are ranked by `total_cmp`)
            let px = if px.is_nan() { 0.0 } else { (px as f64).clamp(0.0, 1.0) };
            table.push((x, px as f32));
            if x == self.me {
                continue;
            }
            // transitivity: P(x) = max(P(x), P(from)·P_from(x)·β)
            let via = p_from * px * BETA;
            if via > self.p(&x, now) {
                self.set_p(x, via, now);
            }
        }
        // between full summaries, what it sends updates what we knew
        if !full && let Some(old) = self.nb_pred.get(&from) {
            let mut merged = old.clone();
            merged.extend(table);
            table = merged;
        }
        // sorted for lookups; of repeated keys the last counts
        table.reverse();
        table.sort_by_key(|x| x.0);
        table.dedup_by_key(|(k, _)| *k);
        self.nb_pred.insert(from, table);
    }

    // ───────────── bundles out ─────────────

    /// What to offer to whom right now. `toward(dst)` is the router's next
    /// hop for live and partial routes; `neighbours` are those with a hop
    /// connection up.
    pub fn plan(
        &mut self,
        now: Time,
        mut toward: impl FnMut(&SignPk) -> Toward,
        neighbours: &[SignPk],
    ) -> Vec<Transfer> {
        self.in_flight.retain(|_, v| {
            v.retain(|x| now.saturating_sub(x.1) < IN_FLIGHT);
            !v.is_empty()
        });
        // what each neighbour told us, looked up once (this runs every
        // second over everything held)
        let nbs: Vec<Nb> = neighbours
            .iter()
            .map(|k| Nb {
                k: *k,
                has: self.nb_has.get(k),
                refused: self.nb_refused.get(k),
                room: self.nb_room.get(k),
                pred: self.nb_pred.get(k),
            })
            .collect();
        let flying = !self.in_flight.is_empty();
        self.doubted.retain(|_, t| now < *t);
        let doubted = (!self.doubted.is_empty()).then_some(&self.doubted);
        let mut out = Vec::new();
        let mut unreachable = Vec::new();
        for (id, h) in &self.held {
            let (dst, giver, size, until) = (h.b.dst, h.from, h.b.payload.len() as u64, h.until);
            let flight = if flying { self.in_flight.get(id) } else { None };
            // the copies not already on their way somewhere
            let copies = h.copies.saturating_sub(flight.map_or(0, |v| v.iter().map(|x| x.2).sum()));
            if copies == 0 {
                continue;
            }
            let sending = |to: &SignPk| flight.is_some_and(|v| v.iter().any(|x| x.0 == *to));
            // in flight, already there, refused, or no room for it (the
            // destination always takes its own)
            let busy = |n: &Nb| {
                sending(&n.k)
                    || n.has.is_some_and(|s| s.contains(id))
                    || n.refused.is_some_and(|s| s.contains(id))
                    || (n.k != dst && n.room.is_some_and(|r| !r.fits(size, until)))
            };
            // a candidate: not busy, and not who gave it to us
            let free = |n: &&Nb| !busy(n) && giver != Some(n.k);
            // 1. the destination itself, or the next hop of a live route
            let pick = if let Some(n) = nbs.iter().find(|n| n.k == dst) {
                (!busy(n)).then_some((dst, copies, Why::Deliver))
            } else {
                let t = toward(&dst);
                if t == Toward::Unreachable {
                    unreachable.push(dst);
                }
                match t {
                    Toward::Hop(n) => {
                        let busy = match nbs.iter().find(|x| x.k == n) {
                            Some(x) => busy(x),
                            None => {
                                sending(&n)
                                    || self.nb_has.get(&n).is_some_and(|s| s.contains(id))
                                    || self.nb_refused.get(&n).is_some_and(|s| s.contains(id))
                            }
                        };
                        // Our own bundle, and our live packets to its
                        // destination just went unacknowledged along a mesh
                        // route (`doubt`): the route may be what failed (a
                        // black hole on it takes custody and drops
                        // everything). Half its copies go along the route,
                        // the rest to other neighbours, the likeliest first,
                        // one share each, and the last stays with us.
                        let split = h.b.src == self.me && copies > 1 && doubted.is_some_and(|d| d.contains_key(&dst));
                        let busy = busy || (split && h.given.contains(&n));
                        if !busy {
                            Some((n, if split { copies / 2 } else { copies }, Why::Route))
                        } else if split && !self.internet {
                            let room_aware = self.cfg.room_aware;
                            nbs.iter()
                                .filter(free)
                                .filter(|x| x.k != n && !h.given.contains(&x.k))
                                .map(|x| {
                                    let u = utility_in(self.cfg.gradient, x.pred, &dst, true);
                                    let w = if room_aware { x.room.map_or(1.0, |r| r.weight(size)) } else { 1.0 };
                                    (u * w, x.k)
                                })
                                .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
                                .map(|(_, k)| (k, copies / 2, Why::Spray))
                        } else {
                            None
                        }
                    }
                    Toward::Soon => None, // a lookup or dial is under way: wait for it
                    _ if !nbs.iter().any(|n| free(&n)) => None,
                    t @ (Toward::Nowhere | Toward::Unreachable) => {
                        // the internet leads there unless it has just proved not to
                        let inet = t == Toward::Nowhere;
                        let mine = self.utility(&dst, inet, now);
                        // the likeliest neighbour without it at least `min` useful
                        let room_aware = self.cfg.room_aware;
                        let best = |min: f64, strict: bool| {
                            nbs.iter()
                                .filter(free)
                                .map(|n| {
                                    let u = utility_in(self.cfg.gradient, n.pred, &dst, inet);
                                    let w = if room_aware { n.room.map_or(1.0, |r| r.weight(size)) } else { 1.0 };
                                    (u * w, n.k)
                                })
                                .filter(|(u, _)| if strict { *u > min } else { *u >= min })
                                .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
                                .map(|(_, n)| n)
                        };
                        // 2. copies to spare spread; a mailbox keeps them
                        let spare = copies > 1 && !(self.internet && inet);
                        let spray = |min: f64| best(min, false).map(|n| (n, copies / 2, Why::Spray));
                        // 3. the gradient: a clearly better neighbour
                        let gradient = || {
                            (self.cfg.gradient != Gradient::Off)
                                .then(|| best(mine + MARGIN, true))
                                .flatten()
                                .map(|n| (n, if copies > 1 { copies / 2 } else { 1 }, Why::Gradient))
                        };
                        match self.cfg.spray {
                            Spray::First if spare => spray(f64::NEG_INFINITY),
                            _ => gradient().or_else(|| match self.cfg.spray {
                                _ if !spare => None,
                                Spray::Focus => spray(mine - MARGIN),
                                Spray::Fallback | Spray::First => spray(f64::NEG_INFINITY),
                            }),
                        }
                    }
                }
            };
            if let Some((to, give, why)) = pick {
                out.push(Transfer { to, id: *id, copies: give.max(1), why });
            }
        }
        for t in &out {
            self.in_flight.entry(t.id).or_default().push((t.to, now, t.copies));
        }
        // what we ask neighbours' predictabilities for (with the other
        // gradients they send them all)
        if self.cfg.gradient == Gradient::Internet {
            unreachable.sort();
            unreachable.dedup();
            unreachable.truncate(SUMMARY_WANTS);
        } else {
            unreachable.clear();
        }
        self.wanted = unreachable;
        // deliveries first, then live routes, the gradient, spraying: a
        // contact may end before everything is through
        out.sort_by_key(|t| t.why as u8);
        out
    }

    /// The offer of `id` to `to` is over, one way or another.
    fn landed(&mut self, id: &Hash32, to: &SignPk) {
        if let Some(v) = self.in_flight.get_mut(id) {
            v.retain(|x| x.0 != *to);
            if v.is_empty() {
                self.in_flight.remove(id);
            }
        }
    }

    /// Our live packets to `dst` just went unacknowledged along a mesh
    /// route (the router's `feedback` says so): for a while, our own
    /// bundles for `dst` don't trust a live route with all their copies.
    pub fn doubt(&mut self, dst: SignPk, now: Time) {
        if !self.doubted.contains_key(&dst) && self.doubted.len() >= DOUBTED_MAX {
            self.doubted.retain(|_, t| now < *t);
            if self.doubted.len() >= DOUBTED_MAX
                && let Some(k) = self.doubted.keys().next().copied()
            {
                self.doubted.remove(&k);
            }
        }
        self.doubted.insert(dst, now + DOUBT_FOR);
    }

    /// `to` took (`ok`) or didn't take `copies` copies of `id`.
    pub fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, now: Time) {
        self.landed(&id, &to);
        if !ok {
            return;
        }
        self.nb_has.entry(to).or_default().insert(id);
        self.nb_heard.insert(to, now);
        let gone = match self.held.get_mut(&id) {
            Some(h) if h.b.dst == to => true, // delivered
            Some(h) => {
                if let Some(r) = self.nb_room.get_mut(&to) {
                    r.take(h.b.payload.len() as u64);
                }
                if h.b.src == self.me && !h.given.contains(&to) {
                    h.given.push(to);
                }
                h.copies = h.copies.saturating_sub(copies);
                h.copies == 0
            }
            None => false,
        };
        if gone {
            self.drop_held(&id);
        }
        self.stats.handed_on += 1;
    }

    /// `to` refused our offer of `id`, for lack of room if `full`. Neither
    /// it (nor, if full, anything else bar deliveries) is offered to `to`
    /// again before its next summary.
    pub fn refused(&mut self, to: SignPk, id: Hash32, full: bool, now: Time) {
        self.landed(&id, &to);
        self.nb_heard.insert(to, now);
        self.nb_refused.entry(to).or_default().insert(id);
        if full {
            self.nb_room.insert(to, Room::default());
        }
    }

    pub fn tick(&mut self, now: Time) {
        while let Some(&(until, id)) = self.expiry.first()
            && until <= now
        {
            self.drop_held(&id);
            self.stats.expired += 1;
        }
        if self.housekept.is_some_and(|t| now.saturating_sub(t) < HOUSEKEEP) {
            return;
        }
        self.housekept = Some(now);
        let stale: Vec<Hash32> =
            self.partial.iter().filter(|(_, p)| now.saturating_sub(p.at) >= PARTIAL_KEEP).map(|(k, _)| *k).collect();
        for id in stale {
            self.drop_partial(&id);
        }
        self.sent.retain(|_, x| now.saturating_sub(x.at) < NB_FORGET);
        // forget negligible predictabilities
        self.pred.retain(|_, (p, at)| *p * GAMMA_PER_MIN.powf(now.saturating_sub(*at) as f64 / 60_000.0) > 0.001);
        // and what neighbours long gone told us
        let gone: Vec<SignPk> =
            self.nb_heard.iter().filter(|(_, t)| now.saturating_sub(**t) >= NB_FORGET).map(|(k, _)| *k).collect();
        for k in gone {
            self.nb_heard.remove(&k);
            self.nb_wants.remove(&k);
            self.nb_pred.remove(&k);
            self.nb_has.remove(&k);
            self.nb_room.remove(&k);
            self.nb_refused.remove(&k);
        }
    }

    /// Neighbours whose summaries we remember.
    pub fn remembered(&self) -> usize {
        self.nb_pred.len().max(self.nb_has.len())
    }
}

#[cfg(test)]
mod tests;
