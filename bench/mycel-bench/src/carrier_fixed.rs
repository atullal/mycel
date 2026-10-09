//! An experimental copy of `mycel_net::mesh::dtn::Carrier` with the fixes
//! proposed in docs/BENCHMARKS.md §6, each behind a switch, so `dtn-replay
//! --carrier fixed --fixes ...` can measure them one at a time on the same
//! traces. Everything not listed below is the real carrier's logic unchanged.
//!
//! - `own`: our own bundles don't use the space we lend to others. The real
//!   carrier counts them in `used`, so a device with a backlog of its own
//!   messages refuses every bundle it is offered.
//! - `free`: summaries say how much room is left, nothing is sent to a
//!   neighbour (other than the destination) that has no room for it, and a
//!   refusal marks the neighbour full until its next summary. The real
//!   carrier learns of a refusal only after the whole payload has crossed the
//!   link, then offers the same bundle again a second later.
//! - `expiry`: a carried bundle expires at `created + lifetime`. The real
//!   carrier restarts the lifetime at every hop (`now + lifetime`).
//! - `resume`: an interrupted transfer keeps the bytes that arrived (BPv7
//!   reactive fragmentation; Mycel's file transfers already resume). This one
//!   is modelled in `dtn_replay.rs`, not here.
//! - `spray`: while a bundle has more than one copy, hand half of them to
//!   the most useful neighbour that lacks it, better than us or not
//!   (binary Spray-and-Wait, steered by the gradient). The gradient then
//!   moves single copies only. The real carrier sprays only when it knows
//!   nothing at all (`mine == 0`), which after a few encounters is almost
//!   never.
//! - `evict`: when the store is full, drop the carried bundles (never our
//!   own) that expire soonest to make room for one that expires later, as
//!   The ONE's routers drop their oldest. The real carrier refuses instead,
//!   so its store fills with old bundles and fresh ones stop spreading.
//!   Summaries list the soonest-expiring carried bundles so senders know
//!   what a bundle could displace.
//! - `fallback`: spray (half the copies to the most useful neighbour that
//!   lacks it) whenever no neighbour is clearly better, not only when we
//!   know nothing (`mine == 0`). The gradient keeps priority where it is
//!   informative; Spray-and-Wait takes over where it isn't.
//! - `inet`: the gradient climbs toward the internet only (P of
//!   [`INTERNET`]); predictability for the destination itself is ignored.
//! - `nograd` (diagnostic, not a proposal): no gradient at all; with
//!   `spray` this is binary Spray-and-Wait plus Mycel's live routes.
//!
//! `all` = `own,free,expiry,resume`.

use std::collections::{BTreeMap, VecDeque};

use mycel_crypto::{Hash32, SignPk};
use mycel_net::mesh::core::{Map, Set, Time, Toward};
use mycel_net::mesh::dtn::{Accepted, Bundle, DtnConfig, DtnStats, INTERNET, Receipt, Summary, Transfer, Why};

const P_ENCOUNTER: f64 = 0.7;
const BETA: f64 = 0.9;
const GAMMA_PER_MIN: f64 = 0.98;
const MARGIN: f64 = 0.05;
const SUMMARY_IDS: usize = 512;
const SUMMARY_RECEIPTS: usize = 256;
const SUMMARY_PREDS: usize = 64;
const RECEIPTS_MAX: usize = 4096;
const IN_FLIGHT: Time = 30_000;

#[derive(Clone, Copy, Debug, Default)]
pub struct Fixes {
    pub own: bool,
    pub free: bool,
    pub expiry: bool,
    pub resume: bool,
    pub spray: bool,
    pub nograd: bool,
    pub evict: bool,
    pub inet: bool,
    pub fallback: bool,
}

impl Fixes {
    pub fn parse(s: &str) -> Fixes {
        let mut f = Fixes::default();
        for x in s.split(',').filter(|x| !x.is_empty()) {
            match x {
                "own" => f.own = true,
                "free" => f.free = true,
                "expiry" => f.expiry = true,
                "resume" => f.resume = true,
                "spray" => f.spray = true,
                "nograd" => f.nograd = true,
                "evict" => f.evict = true,
                "inet" => f.inet = true,
                "fallback" => f.fallback = true,
                "all" => f = Fixes { own: true, free: true, expiry: true, resume: true, ..f },
                other => panic!("unknown fix {other}"),
            }
        }
        f
    }
}

/// A summary plus the room left (the `free` fix) and, with `evict`, what
/// could make way: the soonest-expiring bundles carried for others, as
/// (expiry, size). Only a bundle that expires later can push them out.
#[derive(Clone, Debug, Default)]
pub struct FixedSummary {
    pub s: Summary,
    pub free: u64,
    pub evictable: Vec<(Time, u64)>,
}

const SUMMARY_EVICTABLE: usize = 32;

#[derive(Clone, Default)]
struct Room {
    free: u64,
    evictable: Vec<(Time, u64)>,
}

impl Room {
    /// Room for a bundle of `size` that expires at `until`.
    fn fits(&self, size: u64, until: Time) -> bool {
        self.free + self.evictable.iter().filter(|(u, _)| *u < until).map(|(_, s)| s).sum::<u64>() >= size
    }
}

struct Held {
    b: Bundle,
    copies: u8,
    until: Time,
    from: Option<SignPk>,
}

pub struct Carrier {
    me: SignPk,
    cfg: DtnConfig,
    fixes: Fixes,
    internet: bool,
    held: BTreeMap<Hash32, Held>,
    /// Bytes held for others (and our own, without the `own` fix).
    used: u64,
    by_source: Map<SignPk, u64>,
    pred: Map<SignPk, (f64, Time)>,
    nb_pred: Map<SignPk, Map<SignPk, f64>>,
    nb_has: Map<SignPk, Set<Hash32>>,
    /// Room each neighbour last said it had, less what we sent it since.
    nb_room: Map<SignPk, Room>,
    receipts: Map<Hash32, Receipt>,
    receipt_order: VecDeque<Hash32>,
    in_flight: Map<(Hash32, SignPk), Time>,
    stats: DtnStats,
}

impl Carrier {
    pub fn new(me: SignPk, cfg: DtnConfig, fixes: Fixes) -> Carrier {
        Carrier {
            me,
            cfg,
            fixes,
            internet: false,
            held: BTreeMap::new(),
            used: 0,
            by_source: Map::default(),
            pred: Map::default(),
            nb_pred: Map::default(),
            nb_has: Map::default(),
            nb_room: Map::default(),
            receipts: Map::default(),
            receipt_order: VecDeque::new(),
            in_flight: Map::default(),
            stats: DtnStats::default(),
        }
    }

    pub fn stats(&self) -> DtnStats {
        self.stats
    }

    pub fn has_any(&self) -> bool {
        !self.held.is_empty()
    }

    pub fn set_internet(&mut self, on: bool) {
        self.internet = on;
    }

    pub fn p(&self, x: &SignPk, now: Time) -> f64 {
        if *x == INTERNET && self.internet {
            return 1.0;
        }
        self.pred.get(x).map_or(0.0, |(p, at)| p * GAMMA_PER_MIN.powf(now.saturating_sub(*at) as f64 / 60_000.0))
    }

    fn set_p(&mut self, x: SignPk, p: f64, now: Time) {
        self.pred.insert(x, (p.clamp(0.0, 1.0), now));
    }

    pub fn encounter(&mut self, peer: SignPk, now: Time) {
        let p = self.p(&peer, now);
        self.set_p(peer, p + (1.0 - p) * P_ENCOUNTER, now);
    }

    fn utility(&self, dst: &SignPk, now: Time) -> f64 {
        let d = if self.fixes.inet { 0.0 } else { self.p(dst, now) };
        d.max(self.p(&INTERNET, now))
    }

    fn nb_utility(&self, nb: &SignPk, dst: &SignPk) -> f64 {
        let inet = self.fixes.inet;
        self.nb_pred.get(nb).map_or(0.0, |t| {
            let d = if inet { 0.0 } else { t.get(dst).copied().unwrap_or(0.0) };
            let i = t.get(&INTERNET).copied().unwrap_or(0.0);
            d.max(i)
        })
    }

    pub fn originate(&mut self, b: Bundle, now: Time) -> Result<(), &'static str> {
        if self.held.contains_key(&b.id) || self.receipts.contains_key(&b.id) {
            return Ok(());
        }
        let copies = self.cfg.copies.max(1);
        self.store(b, copies, now, None)?;
        self.stats.originated += 1;
        Ok(())
    }

    /// `now` doubles as the wall clock (`created` is on the same clock here).
    pub fn accept(&mut self, from: SignPk, b: Bundle, copies: u8, now: Time) -> Accepted {
        self.nb_has.entry(from).or_default().insert(b.id);
        if self.receipts.contains_key(&b.id) {
            return Accepted::Duplicate;
        }
        if let Some(h) = self.held.get_mut(&b.id) {
            h.copies = h.copies.saturating_add(copies);
            return Accepted::Duplicate;
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

    fn counts(&self, ours: bool) -> bool {
        !(ours && self.fixes.own)
    }

    fn store(&mut self, b: Bundle, copies: u8, now: Time, from: Option<SignPk>) -> Result<(), &'static str> {
        let ours = from.is_none();
        let size = b.payload.len() as u64;
        if b.payload.len() > self.cfg.max_bundle {
            return Err("too big");
        }
        let lifetime = b.lifetime.min(self.cfg.max_lifetime);
        let until = if self.fixes.expiry { b.created.saturating_add(lifetime).min(now + lifetime) } else { now + lifetime };
        if until <= now {
            return Err("expired");
        }
        if !ours {
            let share = |c: &Carrier| c.by_source.get(&b.src).copied().unwrap_or(0) + size > c.cfg.per_source;
            // `evict`: make way by dropping carried bundles that expire
            // sooner, the same source's first if it is over its share
            while self.fixes.evict && (self.used + size > self.cfg.capacity || share(self)) {
                let same = share(self);
                let victim = self
                    .held
                    .iter()
                    .filter(|(_, h)| h.from.is_some() && h.until < until && (!same || h.b.src == b.src))
                    .min_by_key(|(_, h)| h.until)
                    .map(|(k, _)| *k);
                let Some(v) = victim else { break };
                self.drop_held(&v);
            }
            if self.used + size > self.cfg.capacity {
                return Err("store full");
            }
            if share(self) {
                return Err("source over its share");
            }
        }
        if self.counts(ours) {
            self.used += size;
            *self.by_source.entry(b.src).or_default() += size;
        }
        self.held.insert(b.id, Held { b, copies, until, from });
        Ok(())
    }

    fn drop_held(&mut self, id: &Hash32) {
        if let Some(h) = self.held.remove(id)
            && self.counts(h.from.is_none())
        {
            let size = h.b.payload.len() as u64;
            self.used = self.used.saturating_sub(size);
            if let Some(s) = self.by_source.get_mut(&h.b.src) {
                *s = s.saturating_sub(size);
            }
        }
    }

    pub fn bundle(&self, id: &Hash32) -> Option<&Bundle> {
        self.held.get(id).map(|h| &h.b)
    }

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

    pub fn summary(&self, now: Time) -> FixedSummary {
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
        FixedSummary {
            s: Summary {
                ids: self.held.keys().rev().take(SUMMARY_IDS).copied().collect(),
                receipts: self
                    .receipt_order
                    .iter()
                    .rev()
                    .take(SUMMARY_RECEIPTS)
                    .filter_map(|id| self.receipts.get(id))
                    .copied()
                    .collect(),
                preds,
            },
            free: self.cfg.capacity.saturating_sub(self.used),
            evictable: if self.fixes.evict {
                let mut v: Vec<(Time, u64)> =
                    self.held.values().filter(|h| h.from.is_some()).map(|h| (h.until, h.b.payload.len() as u64)).collect();
                v.sort_unstable();
                v.truncate(SUMMARY_EVICTABLE);
                v
            } else {
                Vec::new()
            },
        }
    }

    pub fn on_summary(&mut self, from: SignPk, fs: FixedSummary, now: Time) {
        let s = fs.s;
        self.nb_room.insert(from, Room { free: fs.free, evictable: fs.evictable });
        self.nb_has.insert(from, s.ids.iter().copied().take(SUMMARY_IDS).collect());
        for r in s.receipts.into_iter().take(SUMMARY_RECEIPTS) {
            if !self.receipts.contains_key(&r.id) {
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
            let via = p_from * px * BETA;
            if via > self.p(&x, now) {
                self.set_p(x, via, now);
            }
        }
        self.nb_pred.insert(from, table);
    }

    pub fn plan(&mut self, now: Time, mut toward: impl FnMut(&SignPk) -> Toward, neighbours: &[SignPk]) -> Vec<Transfer> {
        self.in_flight.retain(|_, t| now.saturating_sub(*t) < IN_FLIGHT);
        let mut out = Vec::new();
        let ids: Vec<Hash32> = self.held.keys().copied().collect();
        for id in ids {
            let (dst, copies, giver, size, until) = {
                let h = &self.held[&id];
                (h.b.dst, h.copies, h.from, h.b.payload.len() as u64, h.until)
            };
            let check_room = self.fixes.free;
            let no_room = |r: &Room| !r.fits(size, until);
            let busy = |c: &Carrier, to: &SignPk| {
                c.in_flight.contains_key(&(id, *to))
                    || c.nb_has.get(to).is_some_and(|s| s.contains(&id))
                    || (check_room && *to != dst && c.nb_room.get(to).is_some_and(no_room))
            };
            let back = |to: &SignPk| giver == Some(*to);
            let pick = if neighbours.contains(&dst) {
                Some((dst, copies, Why::Deliver))
            } else {
                match toward(&dst) {
                    Toward::Hop(n) => Some((n, copies, Why::Route)),
                    Toward::Soon => None,
                    Toward::Nowhere if self.fixes.spray && copies > 1 => neighbours
                        .iter()
                        .filter(|n| !busy(self, n) && !back(n))
                        .map(|n| (self.nb_utility(n, &dst), *n))
                        .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
                        .map(|(_, n)| (n, copies / 2, Why::Spray)),
                    Toward::Nowhere if self.fixes.nograd => None,
                    Toward::Nowhere => {
                        let mine = self.utility(&dst, now);
                        let best = neighbours
                            .iter()
                            .filter(|n| !busy(self, n) && !back(n))
                            .map(|n| (self.nb_utility(n, &dst), *n))
                            .filter(|(u, _)| *u > mine + MARGIN)
                            .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)));
                        match best {
                            Some((_, n)) => Some((n, if copies > 1 { copies / 2 } else { 1 }, Why::Gradient)),
                            None if copies > 1 && self.fixes.fallback => neighbours
                                .iter()
                                .filter(|n| !busy(self, n) && !back(n))
                                .map(|n| (self.nb_utility(n, &dst), *n))
                                .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
                                .map(|(_, n)| (n, copies / 2, Why::Spray)),
                            None if copies > 1 && mine == 0.0 => neighbours
                                .iter()
                                .find(|n| !busy(self, n) && !back(n))
                                .map(|n| (*n, copies / 2, Why::Spray)),
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
        out
    }

    /// `refused`: the neighbour answered "no room" (the `free` fix then
    /// treats it as full until its next summary).
    pub fn transferred(&mut self, to: SignPk, id: Hash32, copies: u8, ok: bool, refused: bool, _now: Time) {
        self.in_flight.remove(&(id, to));
        if !ok {
            if refused && self.fixes.free {
                self.nb_room.insert(to, Room::default());
            }
            return;
        }
        self.nb_has.entry(to).or_default().insert(id);
        let size = self.held.get(&id).map_or(0, |h| h.b.payload.len() as u64);
        let gone = match self.held.get_mut(&id) {
            Some(h) if h.b.dst == to => true,
            Some(h) => {
                if let Some(r) = self.nb_room.get_mut(&to) {
                    r.free = r.free.saturating_sub(size);
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

    pub fn tick(&mut self, now: Time) {
        let dead: Vec<Hash32> = self.held.iter().filter(|(_, h)| h.until <= now).map(|(k, _)| *k).collect();
        for id in dead {
            self.drop_held(&id);
            self.stats.expired += 1;
        }
        self.pred.retain(|_, (p, at)| *p * GAMMA_PER_MIN.powf(now.saturating_sub(*at) as f64 / 60_000.0) > 0.001);
    }
}
