//! Offline delivery through the internet (docs/OFFLINE_DELIVERY.md) in
//! virtual time: internet-only devices that come and go, direct messages
//! between people, and what delivers them.
//!
//! - **Keepers only** (before custody): a message goes live when the sender
//!   and the recipient are online at once (the sender retries within a
//!   minute), or through a keeper of the conversation, if it has one
//!   (an always-on device; [`Cfg::dm_keeper`] of direct chats have one).
//! - **Custodians**: also, when the live attempt fails, a sealed parcel goes
//!   to up to 3 custodians, chosen by the real
//!   [`mycel_net::custody::select`] from the build's tiers (the sender's
//!   keepers, devices sharing a group with the recipient, then the
//!   custodians XOR-closest to the recipient, online or not: a dial to an
//!   offline one fails and uses up one of the 8 attempts), stored under the
//!   real [`mycel_net::custody::Vault`] limits. How the recipient then gets
//!   it follows the build, per tier:
//!   - a co-member custodian: the next time both are online (the recipient
//!     syncs its groups on coming back, and a custodian pushes to a device
//!     that connects to it);
//!   - any custodian: the custodian's own pushes, at the build's backoff
//!     (now, then 2, 4, 8 ... minutes, at most an hour apart), each landing
//!     only if both are online at that moment;
//!   - a volunteer among the 8 closest to the recipient's key: also the
//!     recipient's own "anything for me?" every 30 minutes (at a random
//!     phase per device), landing only if both are online then.
//!
//!   The recipient's receipt clears every copy.
//!
//! No radios: every device is internet-only, so store-and-forward carriers
//! (the mesh) can't help, the case the bug report describes. Assumptions
//! that favour custody are marked: the XOR lookups (sender's and
//! recipient's) are converged, finding the true closest custodians; a dial
//! to an online device finds it at once; and a person's always-on device is
//! a keeper of their chats (the build's first tier is the sender's
//! keepers; a laptop is not one, so laptops only volunteer).

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use mycel_crypto::{Hash32, SignPk};
use mycel_net::custody::{self, Deposit, Depositor, Origin, Parcel, Vault, VaultConfig};

use crate::stats::{Rng, Summary};
use crate::tier2::{HOUR, MIN, SEC, Time};

/// The world and workload.
#[derive(Clone, Debug)]
pub struct Cfg {
    pub people: usize,
    /// Time zones (hours from UTC); people are placed in blocks along the
    /// ring groups are drawn from, so most groups share a zone and some
    /// straddle two.
    pub zones: Vec<i64>,
    /// Local hours a phone is used (awake), and a laptop.
    pub phone_hours: (i64, i64),
    pub laptop_hours: (i64, i64),
    /// Mean online and offline spells of a phone while awake (s).
    pub phone_on_s: f64,
    pub phone_off_s: f64,
    /// A second device (a laptop), with its own spells: ~30% online.
    pub laptop_share: f64,
    pub laptop_on_s: f64,
    pub laptop_off_s: f64,
    /// People with an always-on device (a keeper, a desktop at home).
    pub always_on_share: f64,
    /// Direct chats with a keeper (the always-on device of one side, added
    /// to the chat): the only offline path before custody.
    pub dm_keeper: f64,
    /// Phones that don't keep custody (battery saver, metered network).
    pub phone_refuses: f64,
    /// Groups per person and their size.
    pub groups_per_person: usize,
    pub group_size: usize,
    /// Messages per person, sent over the first `send_window`.
    pub msgs_per_person: usize,
    /// Of them, to someone sharing no group (a contact from elsewhere).
    pub stranger_share: f64,
    pub send_window: Time,
    /// Delivered within this long counts.
    pub deadline: Time,
    pub copies: usize,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            people: 2000,
            zones: vec![-5, 1, 5, 9],
            phone_hours: (7, 23),
            laptop_hours: (9, 18),
            phone_on_s: 15.0 * 60.0,
            phone_off_s: 45.0 * 60.0,
            laptop_share: 0.5,
            laptop_on_s: 2.0 * 3600.0,
            laptop_off_s: 2.0 * 3600.0,
            always_on_share: 0.05,
            dm_keeper: 0.1,
            phone_refuses: 0.3,
            groups_per_person: 2,
            group_size: 6,
            msgs_per_person: 5,
            stranger_share: 0.1,
            send_window: 24 * HOUR,
            deadline: 24 * HOUR,
            copies: custody::DEFAULT_COPIES,
        }
    }
}

/// What delivers messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    KeepersOnly,
    Custodians,
}

/// One run's numbers.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub sent: usize,
    /// Sent while the recipient was offline (the case at issue).
    pub offline_at_send: usize,
    pub delivered: usize,
    pub delivered_offline_case: usize,
    /// Seconds from send to delivery (delivered ones).
    pub latency_s: Vec<f64>,
    /// The same, for messages sent while the recipient was offline.
    pub offline_latency_s: Vec<f64>,
    /// Messages sent while the recipient was offline that some custodian took.
    pub carried: usize,
    /// Custodians per carried message.
    pub custodians_per_carried: f64,
    /// The largest store any custodian reached (bytes).
    pub peak_custodian_bytes: u64,
    /// Deposits refused by custodians' limits.
    pub refused: u64,
}

impl Outcome {
    pub fn ratio(&self) -> f64 {
        self.delivered as f64 / self.sent.max(1) as f64
    }

    pub fn offline_ratio(&self) -> f64 {
        self.delivered_offline_case as f64 / self.offline_at_send.max(1) as f64
    }

    pub fn latency(&self) -> Summary {
        Summary::of(&self.latency_s)
    }
}

/// Online spells of one device, sorted, non-overlapping, `[start, end)`.
type Spells = Vec<(Time, Time)>;

fn spells(rng: &mut Rng, on_s: f64, off_s: f64, until: Time) -> Spells {
    let exp = |rng: &mut Rng, mean: f64| (-(1.0 - rng.f64()).ln() * mean * SEC as f64) as Time;
    let mut out = Vec::new();
    // start in a random phase of the cycle
    let mut on = rng.chance(on_s / (on_s + off_s));
    let mut t: Time = 0;
    while t < until {
        let len = exp(rng, if on { on_s } else { off_s }).max(SEC);
        if on {
            out.push((t, (t + len).min(until)));
        }
        t += len;
        on = !on;
    }
    out
}

/// `s` cut to the local hours `[wake, sleep)` of time zone `tz` each day.
fn awake(s: Spells, tz: i64, (wake, sleep): (i64, i64), until: Time) -> Spells {
    let day = 24 * HOUR;
    let mut windows = Vec::new();
    // local wake time of day d, in sim time (sim time 0 = 00:00 UTC)
    let mut d: i64 = -1;
    loop {
        let start = d * day as i64 + (wake - tz) * HOUR as i64;
        let end = d * day as i64 + (sleep - tz) * HOUR as i64;
        if start >= until as i64 {
            break;
        }
        if end > 0 {
            windows.push((start.max(0) as Time, (end as Time).min(until)));
        }
        d += 1;
    }
    let mut out = Vec::new();
    for (a, b) in s {
        for (wa, wb) in &windows {
            let (lo, hi) = (a.max(*wa), b.min(*wb));
            if lo < hi {
                out.push((lo, hi));
            }
        }
    }
    out.sort_unstable();
    out
}

fn always(until: Time) -> Spells {
    vec![(0, until)]
}

fn online(s: &Spells, t: Time) -> bool {
    let i = s.partition_point(|x| x.1 <= t);
    s.get(i).is_some_and(|x| x.0 <= t)
}

/// The first time at or after `t` that `s` is online.
fn next_on(s: &Spells, t: Time) -> Option<Time> {
    let i = s.partition_point(|x| x.1 <= t);
    s.get(i).map(|x| x.0.max(t))
}

/// The build's delivery retries after a custodian takes a parcel (s): one
/// within a tick, then after 2, 4, 8 ... minutes, at most an hour apart
/// (`CustodyOptions::retry`, `retry_max`).
fn push_times(at: Time, until: Time) -> impl Iterator<Item = Time> {
    let mut t = at + 5 * SEC;
    let mut wait = 60 * SEC;
    std::iter::from_fn(move || {
        if t >= until {
            return None;
        }
        let now = t;
        wait = (wait * 2).min(HOUR);
        t += wait;
        Some(now)
    })
}

/// The recipient's periodic fetch from the custodians closest to its key
/// (`CustodyOptions::fetch_every`), from `at` on, at `phase` in the period.
fn fetch_times(at: Time, phase: Time, until: Time) -> impl Iterator<Item = Time> {
    let first = at + (phase + FETCH_EVERY - at % FETCH_EVERY) % FETCH_EVERY;
    (0..).map(move |k| first + k * FETCH_EVERY).take_while(move |t| *t < until)
}

const FETCH_EVERY: Time = 30 * MIN;

/// The first of `times` at which both are online.
fn both_on(a: &Spells, b: &Spells, times: impl Iterator<Item = Time>) -> Option<Time> {
    times.into_iter().find(|t| online(a, *t) && online(b, *t))
}

/// The first time at or after `t` that both are online.
fn overlap(a: &Spells, b: &Spells, t: Time) -> Option<Time> {
    let (mut i, mut j) = (a.partition_point(|x| x.1 <= t), b.partition_point(|x| x.1 <= t));
    while i < a.len() && j < b.len() {
        let lo = a[i].0.max(b[j].0).max(t);
        let hi = a[i].1.min(b[j].1);
        if lo < hi {
            return Some(lo);
        }
        if a[i].1 <= b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    None
}

struct Device {
    key: SignPk,
    spells: Spells,
    serves: bool,
    /// Where in the fetch period its periodic fetch falls.
    phase: Time,
}

struct Person {
    phone: usize,
    always_on: Option<usize>,
    groups: Vec<usize>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    /// A message is due: (message index).
    Send(usize),
    /// Message delivered: clear its parcel everywhere.
    Delivered(usize),
}

fn secret_of(i: usize) -> [u8; 32] {
    Hash32::digest("mycel-sim/custody-secret", &(i as u64).to_le_bytes()).0
}

fn opt_min(a: Option<Time>, b: Option<Time>) -> Option<Time> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Run one world for `seed` in `mode`.
pub fn run(cfg: &Cfg, seed: u64, mode: Mode) -> Outcome {
    let mut rng = Rng::new(seed ^ 0x0ff1_1e00);
    let until = cfg.send_window + cfg.deadline + HOUR;
    let mut devices: Vec<Device> = Vec::new();
    let key = |rng: &mut Rng| {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&rng.u64().to_le_bytes());
        }
        SignPk(k)
    };
    let mut people: Vec<Person> = Vec::new();
    for i in 0..cfg.people {
        let tz = cfg.zones[i * cfg.zones.len().max(1) / cfg.people.max(1)];
        let phone = devices.len();
        let on = spells(&mut rng, cfg.phone_on_s, cfg.phone_off_s, until);
        let phase = |rng: &mut Rng| (rng.f64() * FETCH_EVERY as f64) as Time;
        devices.push(Device {
            key: key(&mut rng),
            spells: awake(on, tz, cfg.phone_hours, until),
            serves: !rng.chance(cfg.phone_refuses),
            phase: phase(&mut rng),
        });
        if rng.chance(cfg.laptop_share) {
            // (a device of its own: Mycel has no multi-device identity, so a
            // laptop is no "own device" tier; it can volunteer)
            let on = spells(&mut rng, cfg.laptop_on_s, cfg.laptop_off_s, until);
            let spells = awake(on, tz, cfg.laptop_hours, until);
            devices.push(Device { key: key(&mut rng), spells, serves: true, phase: phase(&mut rng) });
        }
        let mut always_on = None;
        if rng.chance(cfg.always_on_share) {
            always_on = Some(devices.len());
            devices.push(Device { key: key(&mut rng), spells: always(until), serves: true, phase: phase(&mut rng) });
        }
        people.push(Person { phone, always_on, groups: Vec::new() });
    }
    // groups: communities of neighbours on a ring, so groups overlap
    let n_groups = (cfg.people * cfg.groups_per_person / cfg.group_size).max(1);
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for _ in 0..n_groups {
        let centre = rng.below(cfg.people);
        let mut g: Vec<usize> = Vec::new();
        while g.len() < cfg.group_size.min(cfg.people) {
            let off = rng.below(4 * cfg.group_size) as isize - 2 * cfg.group_size as isize;
            let p = (centre as isize + off).rem_euclid(cfg.people as isize) as usize;
            if !g.contains(&p) {
                g.push(p);
            }
        }
        for p in &g {
            people[*p].groups.push(groups.len());
        }
        groups.push(g);
    }
    // messages: (time, from, to, keeper of the chat)
    let mut msgs: Vec<(Time, usize, usize, Option<usize>)> = Vec::new();
    for from in 0..cfg.people {
        for _ in 0..cfg.msgs_per_person {
            let mates: Vec<usize> =
                people[from].groups.iter().flat_map(|g| groups[*g].iter().copied()).filter(|p| *p != from).collect();
            let to = if mates.is_empty() || rng.chance(cfg.stranger_share) {
                let mut to = rng.below(cfg.people);
                if to == from {
                    to = (to + 1) % cfg.people;
                }
                to
            } else {
                mates[rng.below(mates.len())]
            };
            // people write while they're on their phone
            let open: Vec<(Time, Time)> = devices[people[from].phone]
                .spells
                .iter()
                .filter(|x| x.0 < cfg.send_window)
                .map(|x| (x.0, x.1.min(cfg.send_window)))
                .collect();
            if open.is_empty() {
                continue;
            }
            let (a, b) = open[rng.below(open.len())];
            let t = a + ((b - a) as f64 * rng.f64()) as Time;
            // a keeper: one side's always-on device, if it has one
            let keeper = if rng.chance(cfg.dm_keeper) { people[from].always_on.or(people[to].always_on) } else { None };
            msgs.push((t, from, to, keeper));
        }
    }
    msgs.sort_by_key(|m| m.0);

    let mut vaults: Vec<Option<Vault>> = (0..devices.len()).map(|_| None).collect();
    let vault_cfg = VaultConfig { stamp_bits: 0, ..Default::default() };
    let mut out = Outcome { sent: msgs.len(), ..Default::default() };
    let _ = &out;
    let mut parcels: Vec<Vec<(usize, Hash32)>> = vec![Vec::new(); msgs.len()];
    let mut queue: BinaryHeap<Reverse<(Time, Ev)>> =
        msgs.iter().enumerate().map(|(i, m)| Reverse((m.0, Ev::Send(i)))).collect();
    let mut custodians_total = 0usize;
    // the custodians XOR-closest to each recipient (a converged lookup:
    // the sender's and the recipient's agree), online or not
    let mut closest: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    let index: std::collections::HashMap<SignPk, usize> = devices.iter().enumerate().map(|(j, d)| (d.key, j)).collect();
    const T0_MS: u64 = 1_800_000_000_000;
    let retry = |rng: &mut Rng| (rng.f64() * 60.0 * SEC as f64) as Time;
    while let Some(Reverse((now, ev))) = queue.pop() {
        match ev {
            Ev::Send(i) => {
                let (t, from, to, keeper) = msgs[i];
                let (src, dst) = (people[from].phone, people[to].phone);
                let offline = !online(&devices[dst].spells, t);
                if offline {
                    out.offline_at_send += 1;
                }
                // live: whenever both are online (sender's retries within a minute)
                let mut best = overlap(&devices[src].spells, &devices[dst].spells, t)
                    .map(|x| if x == t { x + 100 * crate::tier2::MS } else { x + retry(&mut rng) });
                // a keeper of the chat gets it when the sender is online, the
                // recipient when both it and the keeper are
                if let Some(k) = keeper
                    && let Some(at_keeper) = overlap(&devices[src].spells, &devices[k].spells, t)
                    && let Some(x) = overlap(&devices[k].spells, &devices[dst].spells, at_keeper)
                {
                    best = Some(best.map_or(x + SEC, |b| b.min(x + SEC)));
                }
                // the sender's first live attempt (now, or when it is next
                // online) fails after ~10 s if the recipient is away: custody
                let attempt = next_on(&devices[src].spells, t).filter(|a| !online(&devices[dst].spells, *a));
                if mode == Mode::Custodians
                    && let Some(attempt) = attempt
                {
                    let at = attempt + 10 * SEC;
                    let me = devices[src].key;
                    let dkey = devices[dst].key;
                    // the build's first tier: the sender's keepers (assumed:
                    // its always-on device, if it has one)
                    let own: Vec<SignPk> = people[from].always_on.iter().map(|d| devices[*d].key).collect();
                    let shares: Vec<SignPk> = people[from]
                        .groups
                        .iter()
                        .filter(|g| groups[**g].contains(&to))
                        .flat_map(|g| groups[*g].iter().map(|p| people[*p].phone))
                        // (co-members' hellos say whether they keep custody)
                        .filter(|d| devices[*d].serves)
                        .map(|d| devices[d].key)
                        .collect();
                    let near = closest.entry(dst).or_insert_with(|| {
                        let mut serving: Vec<([u8; 32], usize)> = devices
                            .iter()
                            .enumerate()
                            .filter(|(j, d)| d.serves && *j != dst)
                            .map(|(j, d)| (custody::distance(&dkey, &d.key), j))
                            .collect();
                        serving.sort_unstable();
                        serving.into_iter().take(custody::FIND_MAX + 1).map(|(_, j)| j).collect()
                    });
                    let volunteers: Vec<SignPk> =
                        near.iter().filter(|j| **j != src).take(custody::FIND_MAX).map(|j| devices[*j].key).collect();
                    // what the recipient's periodic fetch asks: what its lookup names
                    let asked: Vec<usize> = near.iter().copied().take(custody::FIND_MAX).collect();
                    let by_key = |k: &SignPk| index.get(k).copied();
                    let is_on = |k: &SignPk| by_key(k).is_some_and(|j| online(&devices[j].spells, at));
                    let picked = custody::select(&dkey, &me, &own, &shares, &volunteers, &is_on, custody::MAX_ATTEMPTS);
                    let parcel = Parcel {
                        version: custody::PARCEL_V1,
                        dst: dkey,
                        created: T0_MS + at / 1000,
                        lifetime: custody::DEFAULT_LIFETIME_MS,
                        release: custody::release_hash(&secret_of(i)),
                        sealed: vec![0; 1500 + (i % 7) * 40],
                    };
                    let id = parcel.id();
                    let mut tiers = Vec::new();
                    for (k, tier) in picked {
                        if parcels[i].len() >= cfg.copies {
                            break;
                        }
                        let Some(j) = by_key(&k) else { continue };
                        if !online(&devices[j].spells, at) {
                            continue; // the dial fails
                        }
                        let v = vaults[j].get_or_insert_with(|| {
                            Vault::new(VaultConfig { serve: devices[j].serves, ..vault_cfg.clone() })
                        });
                        v.tick(T0_MS + at / 1000);
                        // (a volunteer shares no space with the sender: a stranger's share)
                        let mut ip = [0u8; 16];
                        ip[..8].copy_from_slice(&(from as u64).to_le_bytes());
                        let known = tier != custody::Tier::Volunteer;
                        let d = Depositor { key: me, origin: Origin::Ip(ip), known };
                        match v.deposit(&d, parcel.clone(), 0, &k, T0_MS + at / 1000) {
                            Deposit::Stored | Deposit::Duplicate => {
                                parcels[i].push((j, id));
                                tiers.push(tier);
                                out.peak_custodian_bytes = out.peak_custodian_bytes.max(v.used().0);
                            }
                            Deposit::Refused(_) => out.refused += 1,
                        }
                    }
                    if !parcels[i].is_empty() {
                        out.carried += 1;
                        custodians_total += parcels[i].len();
                    }
                    for ((j, _), tier) in parcels[i].iter().zip(&tiers) {
                        let (cs, ds) = (&devices[*j].spells, &devices[dst].spells);
                        // the custodian's pushes, at its backoff
                        let mut x = both_on(cs, ds, push_times(at, until));
                        // a co-member: the recipient syncs with it on coming back
                        if *tier == custody::Tier::Shares {
                            x = opt_min(x, overlap(cs, ds, at).map(|t| t + SEC));
                        }
                        // one of the closest to its key: its periodic fetch
                        if asked.contains(j) {
                            x = opt_min(x, both_on(cs, ds, fetch_times(at, devices[dst].phase, until)));
                        }
                        best = opt_min(best, x.map(|t| t + SEC));
                    }
                }
                if let Some(x) = best
                    && x - t <= cfg.deadline
                {
                    out.delivered += 1;
                    if offline {
                        out.delivered_offline_case += 1;
                    }
                    out.latency_s.push((x - t) as f64 / SEC as f64);
                    if offline {
                        out.offline_latency_s.push((x - t) as f64 / SEC as f64);
                    }
                    queue.push(Reverse((x, Ev::Delivered(i))));
                }
            }
            Ev::Delivered(i) => {
                // the recipient's receipt clears every copy
                let dst = people[msgs[i].2].phone;
                // (signatures aren't modelled: the release secret drops it)
                let _ = dst;
                for (j, id) in std::mem::take(&mut parcels[i]) {
                    if let Some(v) = vaults[j].as_mut() {
                        v.release(&id, &secret_of(i));
                        v.tick(T0_MS + now / 1000);
                    }
                }
            }
        }
    }
    let _ = MIN;
    out.custodians_per_carried = custodians_total as f64 / out.carried.max(1) as f64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_and_online() {
        let a = vec![(0, 10), (20, 30)];
        let b = vec![(5, 6), (25, 40)];
        assert!(online(&a, 0) && !online(&a, 10) && online(&a, 29));
        assert_eq!(overlap(&a, &b, 0), Some(5));
        assert_eq!(overlap(&a, &b, 6), Some(25));
        assert_eq!(overlap(&a, &b, 31), None);
    }

    #[test]
    fn pushes_back_off_and_fetches_follow_their_phase() {
        let p: Vec<Time> = push_times(0, 4 * HOUR).collect();
        assert_eq!(p[..6], [5 * SEC, 125 * SEC, 365 * SEC, 845 * SEC, 1805 * SEC, 3725 * SEC]);
        assert!(p.windows(2).all(|w| w[1] - w[0] <= HOUR));
        let f: Vec<Time> = fetch_times(40 * MIN, 5 * MIN, 2 * HOUR).collect();
        assert_eq!(f, vec![65 * MIN, 95 * MIN]);
        let a = vec![(0, 10 * MIN), (60 * MIN, 70 * MIN)];
        let b = vec![(0, HOUR + 7 * MIN)];
        assert_eq!(both_on(&a, &b, push_times(0, HOUR)), Some(5 * SEC));
        assert_eq!(both_on(&a, &b, push_times(11 * MIN, 2 * HOUR)), None);
    }

    #[test]
    fn custody_beats_keepers_only_on_a_small_world() {
        let cfg = Cfg { people: 60, ..Default::default() };
        let base = run(&cfg, 7, Mode::KeepersOnly);
        let cust = run(&cfg, 7, Mode::Custodians);
        assert_eq!(base.sent, cust.sent);
        assert!(cust.delivered >= base.delivered, "{} vs {}", cust.delivered, base.delivered);
        assert!(cust.carried > 0);
        // deterministic
        assert_eq!(run(&cfg, 7, Mode::Custodians).delivered, cust.delivered);
    }
}
