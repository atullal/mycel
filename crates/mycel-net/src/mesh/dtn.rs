//! Store-and-forward ("delay-tolerant") carrying, as a pure state machine
//! like [`super::core`]: no I/O, no clock, no crypto (signatures are checked
//! through closures). Design record: `docs/ROUTING.md` §7.
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
//! 2. **Gradient**: no next hop: give it (or half its copies) to a
//!    neighbour with a clearly better *delivery predictability* (PRoPHET,
//!    RFC 6693) for the destination or for **the internet** (a virtual
//!    destination: devices with the internet have P = 1), so data climbs
//!    toward connectivity instead of wandering.
//!    If a device with the internet finds the destination isn't on it (no
//!    reachability record, and dialling it failed), the internet doesn't
//!    count for that bundle: it moves by predictability for the
//!    destination alone, and the device may spray it.
//! 3. **Spray-and-Focus** (Spyropoulos et al., 2007): while it holds more
//!    than one copy, hand half to the neighbour with the best predictability
//!    that has none, even one no better than itself: an equally placed
//!    passer-by may be the one walking to the destination. A single copy
//!    moves only along the gradient. A device with the internet doesn't
//!    spray: it is where copies should end up (a mailbox).
//!
//! A device with the internet that holds a bundle for a destination behind
//! itself (it is one of the destination's gateways) is its **mailbox**: it
//! keeps it until the destination appears on its mesh. The destination
//! signs a **receipt**; receipts spread in summaries and every carrier
//! drops its copy.
//!
//! # API
//!
//! ```text
//! Carrier::new(me, DtnConfig)
//!   set_internet(bool)
//!   encounter(peer, now)                      a neighbour came into range (P rises)
//!   originate(Bundle, now) -> Result           a bundle of ours
//!   accept(from, Bundle, copies, now, verify)  one handed to us -> Accepted
//!   summary(now) -> Summary                    what to tell neighbours
//!   on_summary(from, Summary, now, verify_receipt)
//!   add_receipt(Receipt)                       we were the destination
//!   plan(now, toward, neighbours) -> Vec<Transfer>   what to hand to whom now
//!   transferred(to, id, copies, ok, now)       the outcome of a Transfer
//!   tick(now)                                  expiry and ageing
//! ```

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use mycel_crypto::{Hash32, Sig, SignPk};

use super::core::{Map, Set, Time, Toward};

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
const RECEIPTS_MAX: usize = 4096;
/// A transfer in flight to a neighbour is not repeated meanwhile.
const IN_FLIGHT: Time = 30_000;
/// A neighbour's summary is forgotten this long after we last heard from it
/// (neighbours in range send one every few seconds; a phone in a crowd
/// meets thousands of devices a day).
const NB_FORGET: Time = 10 * 60_000;

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
    /// Copies a new bundle starts with (Spray-and-Wait's L).
    pub copies: u8,
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
            carry: true,
        }
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
    /// Bundles it holds (so nobody sends them again).
    pub ids: Vec<Hash32>,
    pub receipts: Vec<Receipt>,
    /// Its delivery predictabilities (including [`INTERNET`]).
    pub preds: Vec<(SignPk, f32)>,
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
    /// Spray-and-Wait, nobody knowing better.
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
    pub refused: u64,
    /// Carried bundles dropped to make room for fresher ones.
    pub evicted: u64,
}

struct Held {
    b: Bundle,
    copies: u8,
    /// Expiry on our clock.
    until: Time,
    /// Who handed it to us: gradient and spray never send it back.
    from: Option<SignPk>,
}

/// One device's store-and-forward carrier.
pub struct Carrier {
    me: SignPk,
    cfg: DtnConfig,
    internet: bool,
    held: BTreeMap<Hash32, Held>,
    used: u64,
    by_source: Map<SignPk, u64>,
    /// Our delivery predictabilities and when each was last aged.
    pred: Map<SignPk, (f64, Time)>,
    /// Neighbours' last summaries: their predictabilities and ids.
    nb_pred: Map<SignPk, Map<SignPk, f64>>,
    nb_has: Map<SignPk, Set<Hash32>>,
    /// When each neighbour last told us anything (for forgetting).
    nb_heard: Map<SignPk, Time>,
    receipts: Map<Hash32, Receipt>,
    receipt_order: VecDeque<Hash32>,
    in_flight: Map<(Hash32, SignPk), Time>,
    stats: DtnStats,
}

impl Carrier {
    pub fn new(me: SignPk, cfg: DtnConfig) -> Carrier {
        Carrier {
            me,
            cfg,
            internet: false,
            held: BTreeMap::new(),
            used: 0,
            by_source: Map::default(),
            pred: Map::default(),
            nb_pred: Map::default(),
            nb_has: Map::default(),
            nb_heard: Map::default(),
            receipts: Map::default(),
            receipt_order: VecDeque::new(),
            in_flight: Map::default(),
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

    pub fn set_internet(&mut self, on: bool) {
        self.internet = on;
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

    /// How good a carrier is for `dst`: reaching the destination, or the
    /// internet (from where it crosses to the destination's gateways).
    fn utility(&self, dst: &SignPk, now: Time) -> f64 {
        self.p(dst, now).max(self.p(&INTERNET, now))
    }

    /// A neighbour's utility for `dst`, counting its way to the internet
    /// only if the internet leads to `dst` (`inet`).
    fn nb_utility(&self, nb: &SignPk, dst: &SignPk, inet: bool) -> f64 {
        self.nb_pred.get(nb).map_or(0.0, |t| {
            let d = t.get(dst).copied().unwrap_or(0.0);
            let i = if inet { t.get(&INTERNET).copied().unwrap_or(0.0) } else { 0.0 };
            d.max(i)
        })
    }

    // ───────────── bundles in ─────────────

    /// A bundle of ours, to carry with `copies` copies.
    pub fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str> {
        if self.held.contains_key(&b.id) || self.receipts.contains_key(&b.id) {
            return Ok(());
        }
        let copies = self.cfg.copies.max(1);
        self.store(b, copies, now, None)?;
        self.stats.originated += 1;
        Ok(())
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

    fn store(&mut self, b: Bundle, copies: u8, now: Time, from: Option<SignPk>) -> Result<(), &'static str> {
        let ours = from.is_none();
        let size = b.payload.len() as u64;
        if b.payload.len() > self.cfg.max_bundle {
            return Err("too big");
        }
        let lifetime = b.lifetime.min(self.cfg.max_lifetime);
        if lifetime == 0 {
            return Err("expired");
        }
        if !ours {
            if self.by_source.get(&b.src).copied().unwrap_or(0) + size > self.cfg.per_source {
                return Err("source over its share");
            }
            if self.used + size > self.cfg.capacity && !self.make_room(size, now + lifetime) {
                return Err("store full");
            }
        }
        // `capacity` and `per_source` bound what we carry for others; our
        // own bundles are the user's own messages
        if !ours {
            self.used += size;
            *self.by_source.entry(b.src).or_default() += size;
        }
        self.held.insert(b.id, Held { b, copies, until: now + lifetime, from });
        Ok(())
    }

    /// Full: drop carried bundles (never our own) that expire before one
    /// expiring at `until`, soonest first, if that frees `size` bytes
    /// (drop-oldest: Lindgren & Phanse, 2006). Nothing is dropped otherwise.
    fn make_room(&mut self, size: u64, until: Time) -> bool {
        let mut older: Vec<(Time, Hash32, u64)> = self
            .held
            .iter()
            .filter(|(_, h)| h.from.is_some() && h.until < until)
            .map(|(id, h)| (h.until, *id, h.b.payload.len() as u64))
            .collect();
        let need = (self.used + size).saturating_sub(self.cfg.capacity);
        if older.iter().map(|x| x.2).sum::<u64>() < need {
            return false;
        }
        older.sort();
        let mut freed = 0;
        for (_, id, n) in older {
            if freed >= need {
                break;
            }
            self.drop_held(&id);
            self.stats.evicted += 1;
            freed += n;
        }
        true
    }

    fn drop_held(&mut self, id: &Hash32) {
        if let Some(h) = self.held.remove(id)
            && h.from.is_some()
        {
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
        if self.receipts.insert(r.id, r).is_none() {
            self.receipt_order.push_back(r.id);
            while self.receipt_order.len() > RECEIPTS_MAX {
                if let Some(old) = self.receipt_order.pop_front() {
                    self.receipts.remove(&old);
                }
            }
        }
    }

    pub fn summary(&self, now: Time) -> Summary {
        let mut preds: Vec<(SignPk, f32)> = self
            .pred
            .keys()
            .map(|k| (*k, self.p(k, now) as f32))
            .chain(std::iter::once((INTERNET, self.p(&INTERNET, now) as f32)))
            .filter(|(_, p)| *p > 0.01)
            .collect();
        preds.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        preds.dedup_by_key(|(k, _)| *k);
        preds.truncate(SUMMARY_PREDS);
        Summary {
            ids: self.held.keys().rev().take(SUMMARY_IDS).copied().collect(),
            receipts: self.receipt_order.iter().rev().take(SUMMARY_RECEIPTS).filter_map(|id| self.receipts.get(id)).copied().collect(),
            preds,
        }
    }

    /// A neighbour's summary: what it holds, receipts (checked by
    /// `verify_receipt`), and its predictabilities (PRoPHET transitivity).
    pub fn on_summary(&mut self, from: SignPk, s: Summary, now: Time, mut verify_receipt: impl FnMut(&Receipt) -> bool) {
        self.nb_has.insert(from, s.ids.iter().copied().take(SUMMARY_IDS).collect());
        self.nb_heard.insert(from, now);
        for r in s.receipts.into_iter().take(SUMMARY_RECEIPTS) {
            if !self.receipts.contains_key(&r.id) && verify_receipt(&r) {
                self.add_receipt(r);
            }
        }
        let p_from = self.p(&from, now);
        let mut table: Map<SignPk, f64> = Map::default();
        for (x, px) in s.preds.into_iter().take(SUMMARY_PREDS) {
            let px = (px as f64).clamp(0.0, 1.0);
            table.insert(x, px);
            if x == self.me {
                continue;
            }
            // transitivity: P(x) = max(P(x), P(from)·P_from(x)·β)
            let via = p_from * px * BETA;
            if via > self.p(&x, now) {
                self.set_p(x, via, now);
            }
        }
        self.nb_pred.insert(from, table);
    }

    // ───────────── bundles out ─────────────

    /// What to hand to whom right now. `toward(dst)` is the router's next
    /// hop for live and partial routes; `neighbours` are those with a hop
    /// connection up.
    pub fn plan(&mut self, now: Time, mut toward: impl FnMut(&SignPk) -> Toward, neighbours: &[SignPk]) -> Vec<Transfer> {
        self.in_flight.retain(|_, t| now.saturating_sub(*t) < IN_FLIGHT);
        let mut out = Vec::new();
        let ids: Vec<Hash32> = self.held.keys().copied().collect();
        for id in ids {
            let (dst, copies, giver) = {
                let h = &self.held[&id];
                (h.b.dst, h.copies, h.from)
            };
            let busy = |c: &Carrier, to: &SignPk| {
                c.in_flight.contains_key(&(id, *to)) || c.nb_has.get(to).is_some_and(|s| s.contains(&id))
            };
            let back = |to: &SignPk| giver == Some(*to);
            // 1. the destination itself, or the next hop of a live route
            let pick = if neighbours.contains(&dst) {
                Some((dst, copies, Why::Deliver))
            } else {
                match toward(&dst) {
                    Toward::Hop(n) => Some((n, copies, Why::Route)),
                    Toward::Soon => None, // a lookup or dial is under way: wait for it
                    t @ (Toward::Nowhere | Toward::Unreachable) => {
                        // the internet leads there unless it has just proved not to
                        let inet = t == Toward::Nowhere;
                        // 2. the gradient: a clearly better neighbour
                        let mine = if inet { self.utility(&dst, now) } else { self.p(&dst, now) };
                        let best = neighbours
                            .iter()
                            .filter(|n| !busy(self, n) && !back(n))
                            .map(|n| (self.nb_utility(n, &dst, inet), *n))
                            .filter(|(u, _)| *u > mine + MARGIN)
                            .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)));
                        match best {
                            Some((_, n)) => Some((n, if copies > 1 { copies / 2 } else { 1 }, Why::Gradient)),
                            None if copies > 1 && (!self.internet || !inet) => {
                                // 3. spray: half the copies to the likeliest neighbour
                                // without it that is no worse a carrier than us
                                neighbours
                                    .iter()
                                    .filter(|n| !busy(self, n) && !back(n))
                                    .map(|n| (self.nb_utility(n, &dst, inet), *n))
                                    .filter(|(u, _)| *u + MARGIN >= mine)
                                    .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
                                    .map(|(_, n)| (n, copies / 2, Why::Spray))
                            }
                            None => None,
                        }
                    }
                }
            };
            if let Some((to, give, why)) = pick
                && !busy(self, &to)
            {
                self.in_flight.insert((id, to), now);
                out.push(Transfer { to, id, copies: give.max(1), why });
            }
        }
        // deliveries first, then live routes, the gradient, spraying: a
        // contact may end before everything is through
        out.sort_by_key(|t| t.why as u8);
        out
    }

    /// `to` took (`ok`) or didn't take `copies` copies of `id`.
    pub fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, now: Time) {
        self.in_flight.remove(&(id, to));
        if !ok {
            return;
        }
        self.nb_has.entry(to).or_default().insert(id);
        self.nb_heard.insert(to, now);
        let gone = match self.held.get_mut(&id) {
            Some(h) if h.b.dst == to => true, // delivered
            Some(h) => {
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

    pub fn tick(&mut self, now: Time) {
        let dead: Vec<Hash32> = self.held.iter().filter(|(_, h)| h.until <= now).map(|(k, _)| *k).collect();
        for id in dead {
            self.drop_held(&id);
            self.stats.expired += 1;
        }
        // forget negligible predictabilities
        self.pred.retain(|_, (p, at)| *p * GAMMA_PER_MIN.powf(now.saturating_sub(*at) as f64 / 60_000.0) > 0.001);
        // and what neighbours long gone told us
        let gone: Vec<SignPk> = self.nb_heard.iter().filter(|(_, t)| now.saturating_sub(**t) >= NB_FORGET).map(|(k, _)| *k).collect();
        for k in gone {
            self.nb_heard.remove(&k);
            self.nb_pred.remove(&k);
            self.nb_has.remove(&k);
        }
    }

    /// Neighbours whose summaries we remember.
    pub fn remembered(&self) -> usize {
        self.nb_pred.len().max(self.nb_has.len())
    }
}

#[cfg(test)]
mod tests;
