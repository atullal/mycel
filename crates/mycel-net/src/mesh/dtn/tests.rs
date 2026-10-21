//! Carriers on a contact trace: who is in range of whom changes each step;
//! a scripted router (`routes`) stands in for live mesh and internet paths.
//! Run with `--nocapture` for the numbers.

use super::*;

fn key(i: u32) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k[31] = 0x5a;
    SignPk(k)
}

fn bundle(src: SignPk, dst: SignPk, n: u8, lifetime: u64) -> Bundle {
    let mut idb = [0u8; 32];
    idb[0] = n;
    idb[1..5].copy_from_slice(&src.0[..4]);
    idb[5..9].copy_from_slice(&dst.0[..4]);
    Bundle { id: Hash32(idb), src, dst, created: 0, lifetime, payload: Bytes::from(vec![n; 1000]), sig: Sig([0; 64]) }
}

struct World {
    nodes: Vec<Carrier>,
    /// Who is in range of whom this step.
    contacts: Vec<Vec<usize>>,
    /// Live next hops: (at, dst) -> next.
    routes: Map<(usize, usize), usize>,
    now: Time,
    delivered: Vec<(usize, Hash32, Time)>,
    transfers: Vec<(usize, usize, Why)>,
    /// Offers refused.
    refusals: usize,
}

impl World {
    fn new(n: usize, cfg: impl Fn(usize) -> DtnConfig) -> World {
        World {
            nodes: (0..n).map(|i| Carrier::new(key(i as u32), cfg(i))).collect(),
            contacts: vec![vec![]; n],
            routes: Map::default(),
            now: 0,
            delivered: vec![],
            transfers: vec![],
            refusals: 0,
        }
    }

    fn idx(&self, k: &SignPk) -> usize {
        u32::from_be_bytes(k.0[..4].try_into().unwrap()) as usize
    }

    fn meet(&mut self, a: usize, b: usize) {
        if !self.contacts[a].contains(&b) {
            self.contacts[a].push(b);
            self.contacts[b].push(a);
        }
    }

    fn apart(&mut self) {
        for c in &mut self.contacts {
            c.clear();
        }
    }

    /// One step: encounters, summaries, plans, transfers.
    fn step(&mut self, dt: Time) {
        self.now += dt;
        let now = self.now;
        let n = self.nodes.len();
        for i in 0..n {
            for j in self.contacts[i].clone() {
                self.nodes[i].encounter(key(j as u32), now);
            }
        }
        for i in 0..n {
            for j in self.contacts[i].clone() {
                let s = self.nodes[j].summary(now);
                self.nodes[i].on_summary(key(j as u32), s, now, |_| true);
            }
        }
        for i in 0..n {
            let nbs: Vec<SignPk> = self.contacts[i].iter().map(|j| key(*j as u32)).collect();
            let routes = &self.routes;
            let plan = self.nodes[i].plan(
                now,
                |dst| {
                    let d = u32::from_be_bytes(dst.0[..4].try_into().unwrap()) as usize;
                    match routes.get(&(i, d)) {
                        Some(next) => Toward::Hop(key(*next as u32)),
                        None => Toward::Nowhere,
                    }
                },
                &nbs,
            );
            for t in plan {
                let j = self.idx(&t.to);
                let reachable = self.contacts[i].contains(&j) || self.routes.values().any(|v| *v == j);
                let b = self.nodes[i].bundle(&t.id).cloned();
                self.transfers.push((i, j, t.why));
                let (true, Some(b)) = (reachable, b) else {
                    self.nodes[i].transferred(t.to, t.id, t.copies, false, now);
                    continue;
                };
                // offered first, as the node does; the payload only if taken
                match self.nodes[j].offered(key(i as u32), &Offer::of(&b, t.copies), now, |_| true) {
                    Answer::Refuse(why) => {
                        self.refusals += 1;
                        self.nodes[i].refused(t.to, t.id, why == "store full", now);
                        continue;
                    }
                    Answer::Duplicate => {
                        self.nodes[i].transferred(t.to, t.id, t.copies, true, now);
                        continue;
                    }
                    Answer::Take { .. } => {}
                }
                let ok = match self.nodes[j].accept(key(i as u32), b, t.copies, now, |_| true) {
                    Accepted::ForMe(b) => {
                        self.delivered.push((j, b.id, now));
                        let r = Receipt { id: b.id, dst: b.dst, sig: Sig([0; 64]) };
                        self.nodes[j].add_receipt(r);
                        true
                    }
                    Accepted::Stored | Accepted::Duplicate => true,
                    Accepted::Refused(_) => false,
                };
                self.nodes[i].transferred(t.to, t.id, t.copies, ok, now);
            }
        }
        for c in &mut self.nodes {
            c.tick(now);
        }
    }
}

/// Live as far as it goes, then custody at the break, then the rest when
/// the next segment appears, without the source.
#[test]
fn partial_route_then_custody_then_delivery() {
    // S=0 — A=1 — B=2 [gateway: next segment is the internet to G2=3]; D=4 behind G2
    let mut w = World::new(5, |_| DtnConfig::default());
    let (s, a, b, g2, d) = (0, 1, 2, 3, 4);
    w.meet(s, a);
    w.meet(a, b);
    // the live part of the route: S → A → B (default route to the gateway)
    w.routes.insert((s, d), a);
    w.routes.insert((a, d), b);
    let x = bundle(key(s as u32), key(d as u32), 1, 3_600_000);
    w.nodes[s].originate(x.clone(), 0).unwrap();
    for _ in 0..3 {
        w.step(100);
    }
    assert!(w.nodes[b].holds(&x.id), "the bundle reached the break point");
    assert!(!w.nodes[s].holds(&x.id) && !w.nodes[a].holds(&x.id), "custody moved: nobody behind keeps it");
    // the source leaves; the internet segment comes back: B → G2
    w.apart();
    w.step(60_000);
    assert!(w.nodes[b].holds(&x.id), "held at the break meanwhile");
    w.routes.insert((b, d), g2);
    w.step(100);
    assert!(w.nodes[g2].holds(&x.id), "on to the destination's gateway (its mailbox)");
    // the destination appears on its gateway's mesh
    w.meet(g2, d);
    w.step(100);
    assert_eq!(w.delivered.iter().map(|(n, id, _)| (*n, *id)).collect::<Vec<_>>(), vec![(d, x.id)]);
    assert!(w.transfers.iter().all(|(_, _, why)| matches!(why, Why::Route | Why::Deliver)));
}

/// A mailbox: an internet device holding a bundle for someone behind it
/// keeps it until they show up.
#[test]
fn mailbox_until_the_destination_appears() {
    let mut w = World::new(3, |_| DtnConfig::default());
    w.nodes[0].set_internet(true);
    let x = bundle(key(9), key(2), 2, 3_600_000);
    assert_eq!(w.nodes[0].accept(key(1), x.clone(), 1, 0, |_| true), Accepted::Stored);
    w.meet(0, 1); // a neighbour who isn't the destination, and knows nothing
    for _ in 0..10 {
        w.step(60_000);
    }
    assert!(w.nodes[0].holds(&x.id), "a gateway's mailbox doesn't wander off");
    w.apart();
    w.meet(0, 2);
    w.step(1_000);
    assert_eq!(w.delivered.len(), 1);
    assert!(!w.nodes[0].holds(&x.id));
}

/// Camps A and B split after everyone met; a passer-by beside A ranks
/// the same as A for B. With copies to spare, A sprays half to it anyway
/// (Spray-and-Focus), and the passer-by delivers when it reaches B. (Spraying
/// only when nobody knew anything left the bundle stuck at A.)
#[test]
fn a_passer_by_as_good_as_the_holder_gets_a_copy() {
    let mut w = World::new(3, |_| DtnConfig::default());
    let (a, mule, b) = (0, 1, 2);
    w.meet(a, b);
    w.meet(mule, b);
    w.meet(a, mule);
    w.step(1_000);
    w.apart();
    w.meet(a, mule);
    let x = bundle(key(a as u32), key(b as u32), 4, 3_600_000);
    w.nodes[a].originate(x.clone(), w.now).unwrap();
    let (pa, pm) =
        (w.nodes[a].utility(&key(b as u32), true, w.now), w.nodes[mule].utility(&key(b as u32), true, w.now));
    assert!((pa - pm).abs() < MARGIN, "equally placed: {pa} vs {pm}");
    w.step(1_000);
    assert!(w.nodes[mule].holds(&x.id), "the passer-by carries a copy");
    assert!(w.transfers.contains(&(a, mule, Why::Spray)));
    w.apart();
    w.meet(mule, b);
    w.step(60_000);
    assert_eq!(w.delivered.iter().map(|d| (d.0, d.1)).collect::<Vec<_>>(), vec![(b, x.id)]);
}

/// What a neighbour told us is forgotten once it has been gone a while,
/// so a phone meeting thousands of devices doesn't keep thousands of tables.
#[test]
fn neighbours_long_gone_are_forgotten() {
    let mut w = World::new(40, |_| DtnConfig::default());
    for j in 1..40 {
        w.apart();
        w.meet(0, j);
        w.step(1_000);
    }
    assert_eq!(w.nodes[0].remembered(), 39);
    w.apart();
    w.meet(0, 1);
    for _ in 0..11 {
        w.step(60_000);
    }
    assert_eq!(w.nodes[0].remembered(), 1, "only the neighbour still in range");
}

/// A full store makes room for a fresher bundle by dropping the carried
/// one nearest its expiry; never our own, and never for an older one.
#[test]
fn a_full_store_drops_the_oldest_carried_bundle() {
    let cfg = DtnConfig { capacity: 2000, per_source: 2000, ..DtnConfig::default() };
    let mut c = Carrier::new(key(0), cfg);
    let mine = bundle(key(0), key(9), 1, 100_000);
    c.originate(mine.clone(), 0).unwrap();
    let old = bundle(key(1), key(9), 2, 50_000);
    let mid = bundle(key(2), key(9), 3, 80_000);
    assert_eq!(c.accept(key(1), old.clone(), 1, 0, |_| true), Accepted::Stored);
    assert_eq!(c.accept(key(2), mid.clone(), 1, 0, |_| true), Accepted::Stored);
    // full (2 × 1000 carried; our own doesn't count): a later expiry replaces `old`
    let fresh = bundle(key(3), key(9), 4, 90_000);
    assert_eq!(c.accept(key(3), fresh.clone(), 1, 0, |_| true), Accepted::Stored);
    assert!(!c.holds(&old.id) && c.holds(&mid.id) && c.holds(&fresh.id) && c.holds(&mine.id));
    assert_eq!(c.stats().evicted, 1);
    // one expiring sooner than everything carried is refused instead
    let stale = bundle(key(4), key(9), 5, 10_000);
    assert_eq!(c.accept(key(4), stale.clone(), 1, 0, |_| true), Accepted::Refused("store full"));
    assert!(c.holds(&mid.id) && c.holds(&fresh.id));
}

/// A mailbox with copies to spare still keeps them (it doesn't spray).
#[test]
fn a_mailbox_does_not_spray() {
    let mut w = World::new(3, |_| DtnConfig::default());
    w.nodes[0].set_internet(true);
    let x = bundle(key(0), key(2), 5, 3_600_000);
    w.nodes[0].originate(x.clone(), 0).unwrap();
    w.meet(0, 1);
    for _ in 0..5 {
        w.step(60_000);
    }
    assert!(!w.nodes[1].holds(&x.id));
}

/// Once the destination has it, its signed receipt spreads and every
/// carrier drops its copy.
#[test]
fn receipts_clear_carrier_copies() {
    let mut w = World::new(5, |_| DtnConfig::default());
    let x = bundle(key(0), key(4), 3, 3_600_000);
    for c in 1..4 {
        w.nodes[c].accept(key(0), x.clone(), 1, 0, |_| true);
    }
    // carrier 3 meets the destination and delivers
    w.meet(3, 4);
    w.step(100);
    assert_eq!(w.delivered.len(), 1);
    assert!(w.nodes[1].holds(&x.id) && w.nodes[2].holds(&x.id));
    // the receipt travels in summaries: 4 → 2 → 1 (no transfers involved)
    let s4 = w.nodes[4].summary(w.now);
    assert_eq!(s4.receipts.len(), 1);
    w.nodes[2].on_summary(key(4), s4, w.now, |_| true);
    let s2 = w.nodes[2].summary(w.now);
    w.nodes[1].on_summary(key(2), s2, w.now, |_| true);
    assert!(!w.nodes[1].holds(&x.id) && !w.nodes[2].holds(&x.id), "copies cleared");
    let cleared: u64 = w.nodes.iter().map(|c| c.stats().cleared_by_receipt).sum();
    assert_eq!(cleared, 2);
    // a forged receipt clears nothing
    let y = bundle(key(0), key(4), 4, 3_600_000);
    w.nodes[1].accept(key(0), y.clone(), 1, 0, |_| true);
    let fake = Summary { receipts: vec![Receipt { id: y.id, dst: y.dst, sig: Sig([1; 64]) }], ..Summary::default() };
    w.nodes[1].on_summary(key(3), fake, w.now, |_| false);
    assert!(w.nodes[1].holds(&y.id));
    // and a cleared bundle isn't taken again
    assert_eq!(w.nodes[1].accept(key(0), x, 1, 0, |_| true), Accepted::Duplicate);
}

#[test]
fn budgets_signatures_and_lifetimes() {
    let cfg = DtnConfig { capacity: 5_000, per_source: 3_000, max_bundle: 1_500, ..DtnConfig::default() };
    let mut c = Carrier::new(key(1), cfg);
    let (s1, s2) = (key(10), key(11));
    assert_eq!(c.accept(key(2), bundle(s1, key(3), 1, 1_000), 1, 0, |_| false), Accepted::Refused("bad signature"));
    let mut big = bundle(s1, key(3), 2, 1_000);
    big.payload = Bytes::from(vec![0; 2_000]);
    assert_eq!(c.accept(key(2), big, 1, 0, |_| true), Accepted::Refused("too big"));
    for n in 3..6 {
        let r = c.accept(key(2), bundle(s1, key(3), n, 1_000), 1, 0, |_| true);
        assert_eq!(r, if n < 6 && n - 3 < 3 { Accepted::Stored } else { r.clone() });
    }
    assert_eq!(
        c.accept(key(2), bundle(s1, key(3), 7, 1_000), 1, 0, |_| true),
        Accepted::Refused("source over its share")
    );
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 8, 1_000), 1, 0, |_| true), Accepted::Stored);
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 9, 1_000), 1, 0, |_| true), Accepted::Stored);
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 10, 1_000), 1, 0, |_| true), Accepted::Refused("store full"));
    c.tick(1_001);
    assert!(c.held().is_empty(), "lifetimes run out");
    assert_eq!(c.stats().expired, 5);
}

/// Partitioned clusters in a chain, the first with internet devices; a message from the
/// farthest cluster for someone beyond the internet. Spray-first with the
/// gradient toward the internet for single copies, against plain binary
/// Spray-and-Wait with the same 4 copies, over many random traces: mean
/// delay until a copy reaches a device with the internet.
#[test]
fn gradient_beats_spray_and_wait() {
    const CLUSTERS: usize = 4;
    const PER: usize = 10;
    const N: usize = CLUSTERS * PER;
    let run = |gradient: bool, seed: u64| -> Option<Time> {
        // 4 copies sprayed first either way; the gradient (or not) moves single copies
        let cfg = DtnConfig {
            copies: 4,
            copies_small: 4,
            gradient: if gradient { Gradient::Internet } else { Gradient::Off },
            ..DtnConfig::default()
        };
        let mut w = World::new(N + 1, |_| cfg.clone());
        let far = key(N as u32); // the destination, beyond the internet
        for i in 0..2 {
            w.nodes[i].set_internet(true); // two devices in cluster 0
        }
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut rnd = |m: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % m as u64) as usize
        };
        // warm-up: an hour of contacts so predictabilities form
        let contacts = |w: &mut World, rnd: &mut dyn FnMut(usize) -> usize| {
            w.apart();
            for c in 0..CLUSTERS {
                for _ in 0..PER / 2 {
                    let (a, b) = (c * PER + rnd(PER), c * PER + rnd(PER));
                    if a != b {
                        w.meet(a, b);
                    }
                }
            }
            // a few travellers visit an adjacent cluster (clusters in a
            // chain: 3 — 2 — 1 — 0, the internet in 0)
            for _ in 0..2 {
                let a = rnd(N);
                let here = a / PER;
                let there = if here == 0 {
                    1
                } else if here == CLUSTERS - 1 || rnd(2) == 0 {
                    here - 1
                } else {
                    here + 1
                };
                let b = there * PER + rnd(PER);
                w.meet(a, b);
            }
        };
        for _ in 0..60 {
            contacts(&mut w, &mut rnd);
            w.step(60_000);
        }
        let src = (CLUSTERS - 1) * PER + rnd(PER);
        let mut b = bundle(key(src as u32), far, 77, 24 * 3_600_000);
        b.created = w.now;
        let start = w.now;
        w.nodes[src].originate(b.clone(), w.now).unwrap();
        for _ in 0..12 * 60 {
            contacts(&mut w, &mut rnd);
            if !gradient {
                // unused with the gradient off; dropping them only saves time
                for c in &mut w.nodes {
                    c.pred.clear();
                    c.nb_pred.clear();
                }
            }
            w.step(60_000);
            if (0..2).any(|i| w.nodes[i].holds(&b.id)) {
                return Some(w.now - start);
            }
        }
        None
    };
    let mut rows = vec![];
    for gradient in [true, false] {
        let mut delays = vec![];
        for seed in 1..=40 {
            delays.push(run(gradient, seed).map(|t| t as f64 / 60_000.0).unwrap_or(12.0 * 60.0));
        }
        delays.sort_by(f64::total_cmp);
        let mean = delays.iter().sum::<f64>() / delays.len() as f64;
        rows.push((gradient, mean, delays[delays.len() / 2]));
    }
    for (g, mean, median) in &rows {
        eprintln!(
            "{}: mean {mean:.0} min, median {median:.0} min to reach the internet (40 traces)",
            if *g { "spray, then the gradient toward the internet" } else { "Spray-and-Wait (L = 4)" }
        );
    }
    assert!(rows[0].1 < rows[1].1, "gradient beats spray on mean delay: {rows:?}");
}

/// A carried bundle expires at its source's `created + lifetime`, not a
/// fresh lifetime at every hop; a source clock ahead of ours can't stretch it.
#[test]
fn lifetimes_run_from_creation_not_per_hop() {
    let mut c = Carrier::new(key(1), DtnConfig::default());
    // our wall clock reads 1_000_000 at our time 0
    c.set_clock(0, 1_000_000);
    let mut b = bundle(key(2), key(3), 1, 60_000);
    b.created = 1_000_000 - 50_000; // made 50 s ago: 10 s left
    assert_eq!(c.accept(key(2), b.clone(), 1, 0, |_| true), Accepted::Stored);
    c.tick(9_999);
    assert!(c.holds(&b.id));
    c.tick(10_000);
    assert!(!c.holds(&b.id), "expired 60 s after creation, not 60 s after it reached us");
    // already past its lifetime: refused, before any payload
    let mut old = bundle(key(2), key(3), 2, 60_000);
    old.created = 1_000_000 - 70_000;
    assert_eq!(c.offered(key(2), &Offer::of(&old, 1), 0, |_| true), Answer::Refuse("expired"));
    // a source clock an hour ahead: still at most its lifetime from now
    let mut ahead = bundle(key(2), key(3), 3, 60_000);
    ahead.created = 1_000_000 + 3_600_000;
    assert_eq!(c.accept(key(2), ahead.clone(), 1, 0, |_| true), Accepted::Stored);
    c.tick(60_000);
    assert!(!c.holds(&ahead.id));
}

/// Offers are answered before any payload: a full store refuses (and the
/// sender stops offering it anything until its next summary), a bundle
/// already held is a duplicate that still takes the copies, and the
/// destination always takes its own.
#[test]
fn offers_are_refused_before_the_payload() {
    let cfg = DtnConfig { capacity: 2_000, per_source: 2_000, ..DtnConfig::default() };
    let mut w = World::new(3, |_| cfg.clone());
    let (s, r, d) = (0, 1, 2);
    // the relay is full of bundles that outlive anything the source sends
    for n in 0..2 {
        let x = bundle(key(9), key(8), 100 + n, 7_200_000);
        assert_eq!(w.nodes[r].accept(key(9), x, 1, 0, |_| true), Accepted::Stored);
    }
    let x = bundle(key(s as u32), key(d as u32), 1, 3_600_000);
    let o = Offer::of(&x, 2);
    assert_eq!(w.nodes[r].offered(key(s as u32), &o, 0, |_| true), Answer::Refuse("store full"));
    assert!(!w.nodes[r].holds(&x.id), "nothing stored");
    // through the planner: refused once, then not offered again
    w.nodes[s].originate(x.clone(), 0).unwrap();
    w.meet(s, r);
    w.step(1_000);
    let offers = |w: &World| w.transfers.iter().filter(|t| (t.0, t.1) == (s, r)).count();
    assert_eq!(w.refusals, 0, "its summary said it was full, so nothing was offered");
    assert_eq!(offers(&w), 0);
    // a bundle it holds already: duplicate, copies added
    let y = bundle(key(9), key(8), 100, 7_200_000);
    assert_eq!(w.nodes[r].offered(key(s as u32), &Offer::of(&y, 3), 0, |_| true), Answer::Duplicate);
    // the destination takes its own whatever its room
    let mut c = Carrier::new(key(d as u32), DtnConfig { capacity: 0, carry: false, ..DtnConfig::default() });
    assert_eq!(c.offered(key(s as u32), &o, 0, |_| true), Answer::Take { from: 0 });
    // and a bad signature is refused up front
    assert_eq!(c.offered(key(s as u32), &o, 0, |_| false), Answer::Refuse("bad signature"));
}

/// Without a summary yet, an offer is refused; the refusal marks the
/// neighbour full until it says otherwise.
#[test]
fn a_refusal_marks_the_neighbour_full_until_its_next_summary() {
    let mut c = Carrier::new(key(0), DtnConfig::default());
    let x = bundle(key(0), key(5), 1, 3_600_000);
    let y = bundle(key(0), key(6), 2, 3_600_000);
    c.originate(x.clone(), 0).unwrap();
    c.originate(y.clone(), 0).unwrap();
    let nb = [key(1)];
    let plan = c.plan(0, |_| Toward::Nowhere, &nb);
    assert_eq!(plan.len(), 2, "both offered (sprayed)");
    c.refused(key(1), x.id, true, 0);
    c.transferred(key(1), y.id, 1, false, 0);
    assert!(c.plan(1_000, |_| Toward::Nowhere, &nb).is_empty(), "full: nothing offered");
    // its summary says it has room again
    let room = Summary { free: 1 << 20, ..Summary::default() };
    c.on_summary(key(1), room, 2_000, |_| true);
    assert_eq!(c.plan(2_000, |_| Toward::Nowhere, &nb).len(), 2);
}

/// Found while writing the `dtn` fuzz target: summaries carry `f32`
/// predictabilities, and `f64::clamp` keeps a NaN. A neighbour reporting
/// NaN then outranked every real predictability wherever candidates are
/// ranked with `total_cmp` (the spread of a doubted route's copies). What a
/// neighbour reports is a probability, or nothing.
#[test]
fn a_reported_nan_predictability_counts_as_zero() {
    let mut c = Carrier::new(key(1), DtnConfig::default());
    let (liar, x) = (key(2), key(9));
    let s = Summary {
        full: true,
        preds: vec![(x, f32::NAN), (INTERNET, f32::INFINITY), (key(10), -1.0)],
        ..Summary::default()
    };
    c.on_summary(liar, s, 0, |_| true);
    let table = &c.nb_pred[&liar];
    assert!(table.iter().all(|(_, p)| (0.0..=1.0).contains(p)), "{table:?}");
    assert_eq!(table.iter().find(|(k, _)| *k == x).map(|(_, p)| *p), Some(0.0));
    assert_eq!(table.iter().find(|(k, _)| *k == INTERNET).map(|(_, p)| *p), Some(1.0));
    assert!(c.p(&x, 0).is_finite());
}

/// One hostile neighbour can't grow what we remember without bound: partial
/// summaries full of new destinations and bundle ids, and offers of bundles
/// nobody holds, while the link stays up (found in review: 1,000 summaries
/// of 64 new keys left 64,000 entries for the neighbour and 64,001 of our
/// own). Its latest summary always counts in full, and the likeliest of our
/// own predictabilities survive the trim.
#[test]
fn a_neighbour_cannot_grow_what_we_remember_without_bound() {
    let mut c = Carrier::new(key(1), DtnConfig::default());
    let (liar, friend) = (key(2), key(3));
    c.encounter(liar, 0);
    c.encounter(friend, 0);
    let mut n = 1_000u32;
    let mut fresh = |count: usize| -> Vec<SignPk> {
        (0..count)
            .map(|_| {
                n += 1;
                key(n)
            })
            .collect()
    };
    let id = |i: u32, j: u32| {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_be_bytes());
        h[4..8].copy_from_slice(&j.to_be_bytes());
        Hash32(h)
    };
    let mut last = Vec::new();
    for i in 0..1_000u32 {
        let now = Time::from(i);
        last = fresh(SUMMARY_PREDS + SUMMARY_WANTS);
        let s = Summary {
            full: false,
            ids: (0..SUMMARY_IDS as u32).map(|j| id(i, j)).collect(),
            preds: last.iter().map(|k| (*k, 1.0)).collect(),
            ..Summary::default()
        };
        c.on_summary(liar, s, now, |_| true);
        let b = bundle(liar, key(4), 1, 3_600_000);
        let o = Offer { id: id(i, u32::MAX), ..Offer::of(&b, 1) };
        let _ = c.offered(liar, &o, now, |_| false);
        let (pred, nb_pred, nb_has) = c.table_sizes();
        assert!(pred <= PRED_MAX + PRED_MAX / 4, "{pred} predictabilities after {i} summaries");
        assert!(nb_pred <= NB_PREDS_MAX, "{nb_pred} remembered for one neighbour");
        assert!(nb_has <= NB_HAS_MAX, "{nb_has} ids remembered for one neighbour");
        c.check_bounds().unwrap();
    }
    let now = 1_000;
    c.tick(now);
    let table = &c.nb_pred[&liar];
    assert_eq!(table.len(), NB_PREDS_MAX);
    assert!(last.iter().all(|k| table.binary_search_by(|(x, _)| x.cmp(k)).is_ok()), "the latest summary counts");
    assert!(c.table_sizes().0 <= PRED_MAX + PRED_MAX / 4);
    assert!(c.unheld_ids_of(&liar) <= NB_HAS_MAX);
    // the neighbours we met ourselves outrank anything learnt through them
    assert!(c.p(&liar, now) > 0.69 && c.p(&friend, now) > 0.69);
}

/// Trimming our predictabilities forgets the least likely first, and the
/// same ones on every device.
#[test]
fn trimming_predictabilities_forgets_the_least_likely() {
    let mut c = Carrier::new(key(1), DtnConfig::default());
    let total = PRED_MAX + PRED_MAX / 4;
    for i in 0..total as u32 {
        c.set_p(key(10 + i), f64::from(i + 1) / total as f64, 0);
    }
    assert_eq!(c.table_sizes().0, total);
    c.set_p(key(5), 1.0, 0);
    assert_eq!(c.table_sizes().0, PRED_MAX);
    assert_eq!(c.p(&key(5), 0), 1.0);
    // the cut fell below everything kept
    let lowest_kept = (total + 1 - PRED_MAX) as u32;
    assert_eq!(c.p(&key(10 + lowest_kept - 1), 0), 0.0);
    assert!(c.p(&key(10 + lowest_kept), 0) > 0.0);
}

/// A transfer cut short keeps its bytes with the receiver; the next offer
/// of that bundle, from anyone, resumes where it stopped. Kept bytes are
/// bounded and expire.
#[test]
fn cut_transfers_resume() {
    let cfg = DtnConfig { capacity: 8_000, max_bundle: 2_000, ..DtnConfig::default() };
    let mut c = Carrier::new(key(1), cfg);
    let x = bundle(key(2), key(3), 1, 3_600_000);
    assert_eq!(c.offered(key(4), &Offer::of(&x, 1), 0, |_| true), Answer::Take { from: 0 });
    c.keep_partial(x.id, x.src, x.payload.slice(..600), 0);
    // another neighbour with the same bundle: the rest only
    assert_eq!(c.offered(key(5), &Offer::of(&x, 1), 1_000, |_| true), Answer::Take { from: 600 });
    assert_eq!(c.partial(&x.id).map(|p| p.len()), Some(600));
    assert_eq!(c.stats().resumed, 1);
    assert_eq!(c.accept(key(5), x.clone(), 1, 1_000, |_| true), Accepted::Stored);
    assert!(c.partial(&x.id).is_none(), "complete: the partial copy goes");
    // bounded: a quarter of capacity (2,000 bytes) in all, oldest first
    let ys: Vec<Bundle> = (10..14).map(|n| bundle(key(7), key(3), n, 3_600_000)).collect();
    for (k, y) in ys.iter().enumerate() {
        c.keep_partial(y.id, key(20 + k as u32), y.payload.slice(..900), k as Time);
    }
    let kept: Vec<bool> = ys.iter().map(|y| c.partial(&y.id).is_some()).collect();
    assert_eq!(kept, vec![false, false, true, true]);
    // and kept a few minutes only
    c.tick(5 * 60_000 + 3);
    assert!(ys.iter().all(|y| c.partial(&y.id).is_none()));
}

/// A source over its share makes way with its own older bundles first,
/// rather than being refused or pushing out other sources'.
#[test]
fn a_source_over_its_share_makes_way_with_its_own() {
    let cfg = DtnConfig { capacity: 10_000, per_source: 2_000, ..DtnConfig::default() };
    let mut c = Carrier::new(key(0), cfg);
    let other = bundle(key(2), key(9), 1, 10_000);
    let a1 = bundle(key(1), key(9), 2, 20_000);
    let a2 = bundle(key(1), key(9), 3, 30_000);
    for b in [&other, &a1, &a2] {
        assert_eq!(c.accept(key(5), b.clone(), 1, 0, |_| true), Accepted::Stored);
    }
    let a3 = bundle(key(1), key(9), 4, 40_000);
    assert_eq!(c.accept(key(5), a3.clone(), 1, 0, |_| true), Accepted::Stored);
    assert!(!c.holds(&a1.id) && c.holds(&a2.id) && c.holds(&a3.id) && c.holds(&other.id));
    // one expiring before all of its own is still refused
    let a0 = bundle(key(1), key(9), 5, 5_000);
    assert_eq!(c.accept(key(5), a0, 1, 0, |_| true), Accepted::Refused("source over its share"));
}

/// Small bundles get more copies than big ones.
#[test]
fn copies_by_size() {
    let cfg = DtnConfig::default();
    assert_eq!(cfg.copies_for(200), 32);
    assert_eq!(cfg.copies_for(16 << 10), 32);
    assert_eq!(cfg.copies_for(256 << 10), 4);
    assert_eq!(cfg.copies_for(1 << 20), 4);
    let mid: Vec<u8> = [32 << 10, 64 << 10, 128 << 10].iter().map(|s| cfg.copies_for(*s)).collect();
    assert!(mid.windows(2).all(|w| w[0] > w[1]) && mid[0] < 32 && mid[2] > 4, "{mid:?}");
    let mut c = Carrier::new(key(0), cfg);
    let x = bundle(key(0), key(1), 1, 60_000);
    c.originate(x.clone(), 0).unwrap();
    let plan = c.plan(0, |_| Toward::Nowhere, &[key(2)]);
    assert_eq!(plan[0].copies, 16, "half of 32 sprayed");
}

/// Spray modes: spray-first gives copies to a neighbour worse than us;
/// Spray-and-Focus only to one no worse; `tune` sets them.
#[test]
fn spray_modes() {
    let run = |knobs: &str| {
        let mut cfg = DtnConfig::default();
        cfg.tune(knobs).unwrap();
        let mut w = World::new(3, |_| cfg.clone());
        let (a, worse, b) = (0, 1, 2);
        // a has met b (the destination); `worse` never has
        w.meet(a, b);
        w.step(1_000);
        w.apart();
        w.meet(a, worse);
        let x = bundle(key(a as u32), key(b as u32), 1, 3_600_000);
        w.nodes[a].originate(x.clone(), w.now).unwrap();
        w.step(1_000);
        w.nodes[worse].holds(&x.id)
    };
    assert!(run("spray=first,gradient=destination"));
    assert!(run("spray=fallback,gradient=destination"));
    assert!(!run("spray=focus,gradient=destination"));
    assert!(DtnConfig::default().tune("spray=sideways").is_err());
}

/// Copies on their way to one neighbour (an offer or transfer can take
/// seconds) aren't planned again for another: a single copy in custody
/// doesn't become two.
#[test]
fn copies_in_flight_are_not_given_twice() {
    let cfg = DtnConfig { copies: 4, copies_small: 4, ..DtnConfig::default() };
    let mut c = Carrier::new(key(0), cfg);
    let x = bundle(key(0), key(9), 1, 3_600_000);
    c.originate(x.clone(), 0).unwrap();
    let first = c.plan(0, |_| Toward::Nowhere, &[key(1)]);
    assert_eq!(first.iter().map(|t| (t.to, t.copies)).collect::<Vec<_>>(), vec![(key(1), 2)]);
    // still under way: of the 2 left, 1 for the next neighbour
    let second = c.plan(1_000, |_| Toward::Nowhere, &[key(1), key(2)]);
    assert_eq!(second.iter().map(|t| (t.to, t.copies)).collect::<Vec<_>>(), vec![(key(2), 1)]);
    // the last copy is ours to keep while the others are in flight
    assert!(c.plan(2_000, |_| Toward::Nowhere, &[key(1), key(2), key(3)]).is_empty());
    // custody: a route hop takes every free copy, and nothing is left meanwhile
    let mut c = Carrier::new(key(0), DtnConfig::default());
    c.accept(key(5), x.clone(), 1, 0, |_| true);
    assert_eq!(c.plan(0, |_| Toward::Hop(key(1)), &[key(1)]).len(), 1);
    assert!(c.plan(1_000, |_| Toward::Hop(key(2)), &[key(1), key(2)]).is_empty(), "one copy, already under way");
    c.transferred(key(1), x.id, 1, false, 2_000);
    assert_eq!(c.plan(2_000, |_| Toward::Hop(key(2)), &[key(2)]).len(), 1, "free again once that failed");
}

/// `room=on`: of two neighbours equally close to the internet, the
/// gradient prefers the one with room for several more bundles like this
/// over one that could take only this one (Helsinki's tram gateways,
/// docs/BENCHMARKS.md §6.5).
#[test]
fn room_aware_gradient_prefers_room() {
    let pick = |knobs: &str| {
        let mut cfg = DtnConfig { copies: 1, copies_small: 1, ..DtnConfig::default() };
        cfg.tune(knobs).unwrap();
        let mut c = Carrier::new(key(0), cfg);
        let x = bundle(key(0), key(9), 1, 3_600_000);
        c.originate(x, 0).unwrap();
        for (nb, free) in [(1u32, 1_000u64), (2, 1_000_000)] {
            let s = Summary { preds: vec![(INTERNET, 1.0)], free, ..Summary::default() };
            c.on_summary(key(nb), s, 0, |_| true);
        }
        // key(1) wins ties on key order, so only room can make it key(2)
        let plan = c.plan(1_000, |_| Toward::Nowhere, &[key(1), key(2)]);
        assert_eq!(plan.len(), 1);
        plan[0].to
    };
    assert_eq!(pick("room=off"), key(1));
    assert_eq!(pick("room=on"), key(2));
    assert!(DtnConfig::default().room_aware);
}

/// Summaries say what changed, when it changed: everything at first
/// contact, then only bundles taken since, nothing while nothing changes,
/// everything held every `SUMMARY_FULL`. With the internet gradient,
/// destination predictabilities travel only in full summaries (for
/// PRoPHET's transitivity); deltas carry the internet's (at 2,000 devices,
/// 64 predictabilities to every neighbour every 10 s were 8 kB/s per device).
#[test]
fn summaries_say_what_changed_and_only_what_the_gradient_uses() {
    let mut c = Carrier::new(key(0), DtnConfig::default());
    for p in 1..=5 {
        c.encounter(key(p), 0);
    }
    let nb = [key(9)];
    let s = c.summaries(0, &nb);
    assert_eq!(s.len(), 1);
    assert!(s[0].1.full);
    assert_eq!(s[0].1.preds.len(), 5, "a full summary: destinations too");
    assert!(c.summaries(5_000, &nb).is_empty(), "nothing changed, nothing to say");
    c.encounter(key(6), 5_000);
    assert!(c.summaries(5_000, &nb).is_empty(), "a destination's predictability waits for the next full summary");
    let (x, y) = (bundle(key(0), key(5), 1, 3_600_000), bundle(key(0), key(6), 2, 3_600_000));
    c.originate(x.clone(), 5_000).unwrap();
    let s = c.summaries(5_000, &nb);
    assert_eq!((s[0].1.full, s[0].1.ids.clone()), (false, vec![x.id]), "only what is new");
    assert!(s[0].1.preds.iter().all(|(k, _)| *k == INTERNET), "{:?}", s[0].1.preds);
    c.originate(y.clone(), 5_500).unwrap();
    assert!(c.summaries(6_000, &nb).is_empty(), "at most every SUMMARY_GAP");
    let s = c.summaries(5_000 + SUMMARY_GAP, &nb);
    assert_eq!(s[0].1.ids, vec![y.id]);
    let s = c.summaries(SUMMARY_FULL, &nb);
    assert!(s[0].1.full && s[0].1.ids.len() == 2, "everything, every SUMMARY_FULL");
    c.new_contact(key(9));
    assert!(c.summaries(SUMMARY_FULL + 1, &nb)[0].1.full, "a new hop connection hears everything");
    // the other side: a full summary replaces what we knew, a delta adds
    let mut d = Carrier::new(key(9), DtnConfig::default());
    d.on_summary(key(0), Summary { full: true, ids: vec![x.id], ..Summary::default() }, 0, |_| true);
    d.on_summary(key(0), Summary { ids: vec![y.id], ..Summary::default() }, 1, |_| true);
    assert_eq!(d.nb_has[&key(0)].len(), 2);
    d.on_summary(key(0), Summary { full: true, ids: vec![y.id], ..Summary::default() }, 2, |_| true);
    assert_eq!(d.nb_has[&key(0)].len(), 1);
}

/// With the internet gradient, a carrier holding a bundle the internet
/// can't deliver asks neighbours for their predictability for its
/// destination (`wants`); their next summary answers, and the single copy
/// moves to the one that has met the destination.
#[test]
fn wants_bring_destination_predictabilities() {
    let (a, b, dst) = (key(1), key(2), key(7));
    let mut ca = Carrier::new(a, DtnConfig::default());
    let mut cb = Carrier::new(b, DtnConfig::default());
    // they meet; then b meets the destination (its full summary is past)
    let (_, first) = cb.summaries(0, &[a]).pop().expect("first contact");
    ca.on_summary(b, first, 0, |_| true);
    cb.encounter(dst, 0);
    assert!(cb.summaries(SUMMARY_GAP, &[a]).is_empty(), "nobody asked: it waits for the next full summary");
    let x = bundle(key(3), dst, 1, 3_600_000);
    assert_eq!(ca.accept(key(3), x, 1, 0, |_| true), Accepted::Stored);
    assert!(ca.plan(0, |_| Toward::Unreachable, &[b]).is_empty(), "nobody known better yet");
    let (_, sa) = ca.summaries(0, &[b]).pop().expect("first contact");
    assert_eq!(sa.wants, vec![dst]);
    cb.on_summary(a, sa, 0, |_| true);
    let (_, sb) = cb.summaries(2 * SUMMARY_GAP, &[a]).pop().expect("a want is news");
    assert!(!sb.full && sb.preds.iter().any(|(k, p)| *k == dst && *p > 0.5), "{sb:?}");
    ca.on_summary(b, sb, 2 * SUMMARY_GAP, |_| true);
    let plan = ca.plan(2 * SUMMARY_GAP, |_| Toward::Unreachable, &[b]);
    assert_eq!(plan.iter().map(|t| (t.to, t.why)).collect::<Vec<_>>(), vec![(b, Why::Gradient)]);
}

/// When our live packets to the destination just went unacknowledged along
/// a mesh route (`doubt`), our own bundle doesn't follow that route with
/// every copy: a black hole on it would take custody and drop them all.
/// Half go along the route, the rest to other neighbours, one share each,
/// and the last stays with us. Without that evidence, custody moves whole.
#[test]
fn a_doubted_route_gets_one_share_of_our_bundle() {
    for doubt in [false, true] {
        let mut w = World::new(5, |_| DtnConfig::default());
        let (s, a, b, c, d) = (0, 1, 2, 3, 4);
        for n in [a, b, c] {
            w.meet(s, n);
        }
        w.routes.insert((s, d), a);
        let x = bundle(key(s as u32), key(d as u32), 1, 3_600_000);
        w.nodes[s].originate(x.clone(), 0).unwrap();
        if doubt {
            w.nodes[s].doubt(key(d as u32), 0);
        }
        for _ in 0..6 {
            w.step(100);
        }
        let from_s: Vec<(usize, Why)> = w.transfers.iter().filter(|t| t.0 == s).map(|t| (t.1, t.2)).collect();
        if doubt {
            assert_eq!(from_s.iter().filter(|t| t.0 == a).count(), 1, "one share along the route: {from_s:?}");
            assert!(from_s.contains(&(a, Why::Route)));
            assert!(from_s.contains(&(b, Why::Spray)) && from_s.contains(&(c, Why::Spray)), "{from_s:?}");
            assert!(w.nodes[s].holds(&x.id), "the last copy stays");
        } else {
            assert_eq!(from_s, vec![(a, Why::Route)]);
            assert!(!w.nodes[s].holds(&x.id), "custody moved whole");
        }
    }
}
