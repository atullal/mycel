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
    Bundle {
        id: Hash32(idb),
        src,
        dst,
        created: 0,
        lifetime,
        payload: Bytes::from(vec![n; 1000]),
        sig: Sig([0; 64]),
    }
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
                let ok = match (reachable, b) {
                    (true, Some(b)) => match self.nodes[j].accept(key(i as u32), b, t.copies, now, |_| true) {
                        Accepted::ForMe(b) => {
                            self.delivered.push((j, b.id, now));
                            let r = Receipt { id: b.id, dst: b.dst, sig: Sig([0; 64]) };
                            self.nodes[j].add_receipt(r);
                            true
                        }
                        Accepted::Stored | Accepted::Duplicate => true,
                        Accepted::Refused(_) => false,
                    },
                    _ => false,
                };
                self.transfers.push((i, j, t.why));
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
    let (pa, pm) = (w.nodes[a].utility(&key(b as u32), w.now), w.nodes[mule].utility(&key(b as u32), w.now));
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
    assert_eq!(c.accept(key(2), bundle(s1, key(3), 7, 1_000), 1, 0, |_| true), Accepted::Refused("source over its share"));
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 8, 1_000), 1, 0, |_| true), Accepted::Stored);
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 9, 1_000), 1, 0, |_| true), Accepted::Stored);
    assert_eq!(c.accept(key(2), bundle(s2, key(3), 10, 1_000), 1, 0, |_| true), Accepted::Refused("store full"));
    c.tick(1_001);
    assert!(c.held().is_empty(), "lifetimes run out");
    assert_eq!(c.stats().expired, 5);
}

/// Partitioned clusters in a chain, the first with internet devices; a message from the
/// farthest cluster for someone beyond the internet. Gradient routing
/// (PRoPHET toward the internet) against Spray-and-Wait with the same 4
/// copies, over many random traces: mean delay until a copy reaches a
/// device with the internet.
#[test]
fn gradient_beats_spray_and_wait() {
    const CLUSTERS: usize = 4;
    const PER: usize = 10;
    const N: usize = CLUSTERS * PER;
    let run = |gradient: bool, seed: u64| -> Option<Time> {
        let mut w = World::new(N + 1, |_| DtnConfig::default());
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
                let there = if here == 0 { 1 } else if here == CLUSTERS - 1 || rnd(2) == 0 { here - 1 } else { here + 1 };
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
        if !gradient {
            // Spray-and-Wait: no predictabilities at all
            for c in &mut w.nodes {
                c.pred.clear();
            }
        }
        w.nodes[src].originate(b.clone(), w.now).unwrap();
        for _ in 0..24 * 60 {
            contacts(&mut w, &mut rnd);
            if !gradient {
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
            delays.push(run(gradient, seed).map(|t| t as f64 / 60_000.0).unwrap_or(24.0 * 60.0));
        }
        delays.sort_by(f64::total_cmp);
        let mean = delays.iter().sum::<f64>() / delays.len() as f64;
        rows.push((gradient, mean, delays[delays.len() / 2]));
    }
    for (g, mean, median) in &rows {
        eprintln!(
            "{}: mean {mean:.0} min, median {median:.0} min to reach the internet (40 traces)",
            if *g { "gradient (PRoPHET toward the internet)" } else { "Spray-and-Wait (L = 4)" }
        );
    }
    assert!(rows[0].1 < rows[1].1, "gradient beats spray on mean delay: {rows:?}");
}
