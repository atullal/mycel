//! Signed route attestations (`ROUTE_ATTEST`, `docs/ROUTING.md` §6 item
//! 13), with real Ed25519 signatures (`wire.rs`): what a lying relay can't
//! get past a receiver (a cheaper link than its upstream measured, a
//! forged, replayed, truncated or re-addressed chain), the downgrade policy
//! in mixed meshes, the signature cache and the per-neighbour budget.

use mycel_crypto::DeviceKeys;

use super::tests::Net;
use super::*;
use crate::mesh::wire::{self, sign_announce, sign_hop};

const WALL: u64 = 1_700_000_000_000;

fn dk(i: u8) -> DeviceKeys {
    DeviceKeys::from_seed([i; 32])
}

/// `origin`'s announcement (seqno `seq`, `scope`) as relayed honestly along
/// `relays` and sent by the last of them (or the origin) to `to`. `links[j]`
/// is the link cost the hop at position j measured to the next one (the
/// last to `to`); each relay advertises its upstream's cost plus that
/// upstream's link.
fn relayed(origin: &DeviceKeys, relays: &[&DeviceKeys], to: SignPk, links: &[u32], seq: u64, scope: u8) -> Announce {
    assert_eq!(links.len(), relays.len() + 1);
    let next = |j: usize| relays.get(j).map_or(to, |k| k.sign_pk());
    let mut a = sign_announce(origin, Origination { seq, flags: 0, scope, uplink: 0 }, "o");
    a.sign_link = Some(links[0]);
    a = sign_hop(origin, a, &next(0));
    for (j, r) in relays.iter().enumerate() {
        a.hops = j as u8 + 1;
        a.cost += links[j];
        a.sign_link = Some(links[j + 1]);
        a = sign_hop(r, a, &next(j + 1));
    }
    a
}

/// A router for `me` with attesting neighbours `nbs`, each measured at
/// `cost`.
fn router(me: &DeviceKeys, nbs: &[SignPk], cost: u32) -> Router {
    let mut r = Router::new(me.sign_pk(), Config::default());
    for n in nbs {
        r.set_direct(*n, true, 0);
        r.set_attests(*n, Some(true), 0);
        r.hop_up(*n, 0);
        r.set_cost(*n, cost);
    }
    r
}

/// The first seqno from [`WALL`] on that starts one of `origin`'s epochs
/// for announcements of `scope`.
fn epoch_start(origin: &SignPk, scope: u8) -> u64 {
    let e = attest_epoch(origin, WALL, scope);
    let len = if scope <= NEAR_SCOPE { ATTEST_EPOCH } else { FAR_ATTEST_EPOCH };
    let next = (WALL..WALL + len + 1).step_by(1_000).find(|s| attest_epoch(origin, *s, scope) > e).expect("within one");
    (next - 1_000..=next).find(|s| attest_epoch(origin, *s, scope) > e).expect("within a second")
}

fn via(r: &Router, origin: &SignPk, n: &SignPk) -> Option<Via> {
    r.origins.get(origin)?.via.iter().find(|(k, _)| k == n).map(|(_, v)| *v)
}

#[test]
fn an_honest_chain_is_accepted_and_binds_the_costlier_end_of_each_link() {
    let (o, u, l, me) = (dk(1), dk(2), dk(3), dk(4));
    let mut r = router(&me, &[l.sign_pk()], 100);
    // O measured 300 to U, U 5,000 to L (a slow link), L 21 to us
    let a = relayed(&o, &[&u, &l], me.sign_pk(), &[300, 5_000, MIN_HOP_COST], WALL, 8);
    assert_eq!(a.chain_len(), 3);
    assert_eq!(a.cost, 5_300);
    r.on_announce(l.sign_pk(), a, 0, WALL, wire::verify);
    let s = r.stats();
    assert_eq!((s.announcements_attested, s.chains_refused, s.neighbours_distrusted), (1, 0, 0));
    assert_eq!(s.signatures_checked, 4, "three hops and the origin's signature");
    let v = via(&r, &o.sign_pk(), &l.sign_pk()).expect("a route");
    assert!(v.attested && v.hops == 3);
    // L said its link to us costs 21; we measured 100 (+20): ours counts
    assert_eq!(v.cost, 5_300 + 120);
    // ... and where L measured more than we did, L's
    let mut r = router(&me, &[l.sign_pk()], 100);
    let a = relayed(&o, &[&u, &l], me.sign_pk(), &[300, 5_000, 4_000], WALL, 8);
    r.on_announce(l.sign_pk(), a, 0, WALL, wire::verify);
    assert_eq!(via(&r, &o.sign_pk(), &l.sign_pk()).map(|v| v.cost), Some(5_300 + 4_000));
}

#[test]
fn a_relay_cannot_claim_a_cheaper_link_than_its_upstream_measured() {
    let (o, u, l, me) = (dk(1), dk(2), dk(3), dk(4));
    // U measured its link to L at 5,000; L claims the 2.1 ms floor for it
    // (the chain-extending lie), signing its own hop honestly otherwise
    let mut a = relayed(&o, &[&u], l.sign_pk(), &[300, 5_000], WALL, 8);
    a.hops = 2;
    a.cost = 300 + MIN_HOP_COST;
    a.sign_link = Some(200);
    let lie = sign_hop(&l, a, &me.sign_pk());
    let mut r = router(&me, &[l.sign_pk()], 100);
    r.on_announce(l.sign_pk(), lie.clone(), 0, WALL, wire::verify);
    let s = r.stats();
    assert_eq!((s.chains_refused, s.neighbours_distrusted, s.announcements_attested), (1, 1, 0));
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_none());
    // one unit under the bound is as much a lie
    let mut a = relayed(&o, &[&u], l.sign_pk(), &[300, 5_000], WALL, 8);
    (a.hops, a.cost, a.sign_link) = (2, 5_299, Some(200));
    let mut r = router(&me, &[l.sign_pk()], 100);
    r.on_announce(l.sign_pk(), sign_hop(&l, a, &me.sign_pk()), 0, WALL, wire::verify);
    assert_eq!(r.stats().chains_refused, 1);
    // stripped of its chain, the lie is an unattested route: kept, but
    // ranked behind any attested one (below)
    let mut r = router(&me, &[l.sign_pk()], 100);
    r.on_announce(l.sign_pk(), Announce { chain: None, ..lie }, 0, WALL, wire::verify);
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_some_and(|v| !v.attested));
}

#[test]
fn understating_its_own_link_to_us_buys_a_relay_nothing() {
    let (o, l, me) = (dk(1), dk(3), dk(4));
    let mut r = router(&me, &[l.sign_pk()], 3_000);
    let a = relayed(&o, &[&l], me.sign_pk(), &[300, MIN_HOP_COST], WALL, 8);
    r.on_announce(l.sign_pk(), a, 0, WALL, wire::verify);
    assert_eq!(via(&r, &o.sign_pk(), &l.sign_pk()).map(|v| v.cost), Some(300 + 3_020));
    // and a link claimed under any honest hop's least is a lie
    let mut a = relayed(&o, &[], l.sign_pk(), &[300], WALL, 8);
    (a.hops, a.cost, a.sign_link) = (1, 300, Some(MIN_HOP_COST - 1));
    let mut r = router(&me, &[l.sign_pk()], 100);
    r.on_announce(l.sign_pk(), sign_hop(&l, a, &me.sign_pk()), 0, WALL, wire::verify);
    assert_eq!(r.stats().chains_refused, 1);
}

#[test]
fn forged_replayed_truncated_and_readdressed_chains_are_refused() {
    let (o, a1, b, x, me) = (dk(1), dk(2), dk(3), dk(5), dk(4));
    let honest = relayed(&o, &[&a1, &b], me.sign_pk(), &[300, 400, 500], WALL, 8);
    let refused = |ann: Announce| {
        let mut r = router(&me, &[b.sign_pk()], 100);
        let wall = ann.seq;
        r.on_announce(b.sign_pk(), ann, 0, wall, wire::verify);
        let s = r.stats();
        (s.chains_refused, s.neighbours_distrusted, s.announcements_attested)
    };
    assert_eq!(refused(honest.clone()), (0, 0, 1));
    // a hop's signature altered (the middle one)
    let hops: Vec<&Hop> = honest.chain.as_ref().unwrap().iter().collect();
    let forged = {
        let origin_hop = hops[2];
        let mut mid = Hop { prev: origin_hop.prev.clone(), ..clone_hop(hops[1]) };
        mid.prev = Some(Arc::new(clone_hop(origin_hop)));
        mid.sig.0[7] ^= 1;
        Arc::new(Hop { prev: Some(Arc::new(mid)), ..clone_hop(hops[0]) })
    };
    assert_eq!(refused(Announce { chain: Some(forged), ..honest.clone() }), (1, 1, 0));
    // a hop's cost raised after signing (to make room below it)
    let raised = {
        let mut mid = clone_hop(hops[1]);
        mid.cost += 50;
        mid.prev = Some(Arc::new(clone_hop(hops[2])));
        Arc::new(Hop { prev: Some(Arc::new(mid)), ..clone_hop(hops[0]) })
    };
    assert_eq!(refused(Announce { chain: Some(raised), ..honest.clone() }), (1, 1, 0));
    // under a newer seqno than the origin signed
    assert_eq!(refused(Announce { seq: WALL + 1, ..honest.clone() }), (1, 1, 0));
    // replayed onto the origin's next announcement: within the epoch every
    // hop signed, it attests that one too (a route B had this epoch, never
    // a cheaper link than A measured); an epoch later, nothing
    let s0 = epoch_start(&o.sign_pk(), 8);
    let first = relayed(&o, &[&a1, &b], me.sign_pk(), &[300, 400, 500], s0, 8);
    let next = sign_announce(&o, Origination { seq: s0 + 16_000, flags: 0, scope: 8, uplink: 0 }, "o");
    let replay = Announce { chain: first.chain.clone(), hops: first.hops, cost: first.cost, ..next };
    assert_eq!(refused(replay), (0, 0, 1));
    let later = sign_announce(&o, Origination { seq: s0 + FAR_ATTEST_EPOCH, flags: 0, scope: 8, uplink: 0 }, "o");
    let replay = Announce { chain: first.chain.clone(), hops: first.hops, cost: first.cost, ..later };
    assert_eq!(refused(replay), (1, 1, 0), "an epoch later");
    // the origin's fields changed (a far scope claimed for a near one)
    assert_eq!(refused(Announce { scope: 10, ..honest.clone() }), (1, 1, 0));
    // truncated: A's hop dropped, B claiming to be one hop from O (O's hop
    // named A, not B)
    let truncated = {
        let own = Hop { cost: 300, prev: Some(Arc::new(clone_hop(hops[2]))), ..clone_hop(hops[0]) };
        Announce { hops: 1, cost: 300, chain: Some(Arc::new(own)), ..honest.clone() }
    };
    assert_eq!(refused(truncated), (1, 1, 0));
    // ... or keeping its hop count with a hop missing
    let short = Announce {
        chain: Some(Arc::new(Hop { prev: Some(Arc::new(clone_hop(hops[2]))), ..clone_hop(hops[0]) })),
        ..honest.clone()
    };
    assert_eq!(refused(short), (1, 1, 0));
    // re-addressed: B passes on the copy A signed for X, as its own
    let for_x = relayed(&o, &[&a1], x.sign_pk(), &[300, 400], WALL, 8);
    assert_eq!(refused(for_x.clone()), (1, 1, 0), "the last hop isn't the sender's");
    let mut stolen = for_x;
    (stolen.hops, stolen.cost, stolen.sign_link) = (2, 700, Some(500));
    let stolen = sign_hop(&b, stolen, &me.sign_pk());
    assert_eq!(refused(stolen), (1, 1, 0), "A's hop names X, not B");
    // a chain B was sent for us, replayed by someone else
    let mut r = router(&me, &[x.sign_pk()], 100);
    r.on_announce(x.sign_pk(), honest.clone(), 0, WALL, wire::verify);
    assert_eq!(r.stats().chains_refused, 1);
    // a path through us is a loop, not a lie
    let through_us = relayed(&o, &[&me, &b], me.sign_pk(), &[300, 400, 500], WALL, 8);
    let mut r = router(&me, &[b.sign_pk()], 100);
    r.on_announce(b.sign_pk(), through_us, 0, WALL, wire::verify);
    let s = r.stats();
    assert_eq!((s.chains_refused, s.neighbours_distrusted, s.announcements_attested), (0, 0, 0));
    assert!(via(&r, &o.sign_pk(), &b.sign_pk()).is_none());
}

fn clone_hop(h: &Hop) -> Hop {
    Hop { signer: h.signer, cost: h.cost, link: h.link, sig: h.sig, prev: h.prev.clone() }
}

#[test]
fn an_attested_route_needs_no_hop_of_its_sender_at_the_edge_of_its_scope() {
    let (o, l, me) = (dk(1), dk(3), dk(4));
    // near scope (2): we are its last hop, so L sends its chain without
    // its own hop (O's names L, which bounds what L may claim)
    let mut a = relayed(&o, &[], l.sign_pk(), &[300], WALL, NEAR_SCOPE);
    (a.hops, a.cost) = (1, 300);
    let bytes = wire::encode_attested(vec![a.clone()], 1200).0;
    let back = wire::decode_attested(&bytes[0], &l.sign_pk());
    assert_eq!(back, vec![a.clone()]);
    assert_eq!(wire::wire_len(&a), bytes[0].len() - 1);
    assert_eq!(wire::wire_len(&a), wire::wire_len(&Announce { chain: None, ..a.clone() }) + 68, "O's hop over v1");
    let mut r = router(&me, &[l.sign_pk()], 100);
    r.on_announce(l.sign_pk(), back[0].clone(), 0, WALL, wire::verify);
    assert_eq!(r.stats().announcements_attested, 1);
    assert_eq!(r.stats().signatures_checked, 2, "O's hop and O's own signature");
    // it isn't passed on (scope), and has nothing to retract with
    r.tick(100);
    let mut out = Vec::new();
    r.drain(&mut out);
    assert!(!out.iter().any(|o| matches!(o, Out::Announce { ann, .. } if ann.origin == a.origin)));
}

#[test]
fn copies_through_other_neighbours_share_the_checked_prefix() {
    let (o, u, n1, n2, me) = (dk(1), dk(2), dk(3), dk(5), dk(4));
    let mut r = router(&me, &[n1.sign_pk(), n2.sign_pk()], 100);
    let mut checks = 0;
    let mut count = |c: Check<'_>| {
        checks += 1;
        wire::verify(c)
    };
    // U's hop differs per receiver (it names n1 or n2); O's doesn't
    r.on_announce(n1.sign_pk(), relayed(&o, &[&u, &n1], me.sign_pk(), &[300, 400, 500], WALL, 8), 0, WALL, &mut count);
    r.on_announce(n2.sign_pk(), relayed(&o, &[&u, &n2], me.sign_pk(), &[300, 450, 500], WALL, 8), 1, WALL, &mut count);
    let s = r.stats();
    assert_eq!(s.announcements_attested, 2);
    assert_eq!(checks, 4 + 2, "the second copy: U's and n2's hops only");
    assert_eq!(s.signatures_cached, 2, "O's hop and O's own signature");
}

#[test]
fn signature_checks_are_budgeted_per_neighbour() {
    let (n, me) = (dk(3), dk(4));
    let mut r = router(&me, &[n.sign_pk()], 100);
    let mut checks = 0u64;
    // fresh keys every time: nothing to cache, all valid (a stub)
    for i in 0..400u32 {
        let fake = |j: u32| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            k[4..8].copy_from_slice(&j.to_be_bytes());
            k[31] = 0x5a;
            SignPk(k)
        };
        let origin = fake(99);
        let mut chain = Arc::new(Hop { signer: origin, cost: 0, link: 100, sig: Sig([1; 64]), prev: None });
        for j in 1..8u32 {
            chain = Arc::new(Hop { signer: fake(j), cost: 100 * j, link: 100, sig: Sig([1; 64]), prev: Some(chain) });
        }
        chain = Arc::new(Hop { signer: n.sign_pk(), cost: 800, link: 100, sig: Sig([1; 64]), prev: Some(chain) });
        let a = Announce {
            hops: 8,
            cost: 800,
            origin,
            seq: WALL,
            flags: 0,
            scope: 10,
            uplink: 0,
            name: Arc::from(""),
            sig: Sig([1; 64]),
            chain: Some(chain),
            sign_link: None,
            same: false,
        };
        r.on_announce(n.sign_pk(), a, 0, WALL, |_| {
            checks += 1;
            true
        });
    }
    // 400 announcements × 9 hops, at once: the burst is 4 s of the rate
    let burst = (VERIFY_RATE * 4.0) as u64;
    let s = r.stats();
    assert!(checks <= burst + 400, "{checks} checks (origin signatures aren't budgeted: one each)");
    assert!(s.announcements_limited > 0 && s.announcements_attested < 400, "{s:?}");
    assert_eq!(s.chains_refused, 0, "over budget is not a lie");
}

#[test]
fn a_neighbour_is_greeted_once_its_hello_says_how() {
    let (n, m, me) = (dk(3), dk(5), dk(4));
    let mut r = router(&me, &[m.sign_pk()], 100);
    let o = dk(1);
    r.on_announce(m.sign_pk(), relayed(&o, &[&m], me.sign_pk(), &[300, 400], WALL, 8), 0, WALL, wire::verify);
    r.tick(100);
    r.drain(&mut Vec::new());
    r.set_direct(n.sign_pk(), true, 5_000);
    r.set_attests(n.sign_pk(), None, 5_000);
    r.hop_up(n.sign_pk(), 5_000);
    r.tick(5_010);
    let mut out = Vec::new();
    r.drain(&mut out);
    let greeted = |out: &[Out]| {
        out.iter()
            .filter_map(|x| match x {
                Out::Announce { to, ann } if *to == n.sign_pk() && ann.origin == o.sign_pk() => Some(ann.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert!(greeted(&out).is_empty(), "waits for the hello");
    r.set_attests(n.sign_pk(), Some(true), 5_100);
    r.tick(5_110);
    let mut out = Vec::new();
    r.drain(&mut out);
    let g = greeted(&out);
    assert_eq!(g.len(), 1);
    assert!(g[0].chain_len() == 2 && g[0].sign_link.is_some(), "attested, with our hop to sign");
    // a hello that never comes: greeted unattested after the wait
    let (p, q) = (dk(6), dk(7));
    let mut r = router(&q, &[m.sign_pk()], 100);
    r.on_announce(m.sign_pk(), relayed(&o, &[&m], q.sign_pk(), &[300, 400], WALL, 8), 0, WALL, wire::verify);
    r.tick(100);
    r.drain(&mut Vec::new());
    r.set_direct(p.sign_pk(), true, 5_000);
    r.set_attests(p.sign_pk(), None, 5_000);
    r.hop_up(p.sign_pk(), 5_000);
    r.tick(5_000 + HELLO_WAIT);
    let mut out = Vec::new();
    r.drain(&mut out);
    let late: Vec<&Announce> = out
        .iter()
        .filter_map(|x| match x {
            Out::Announce { to, ann } if *to == p.sign_pk() && ann.origin == o.sign_pk() => Some(ann),
            _ => None,
        })
        .collect();
    assert!(late.len() == 1 && late[0].chain.is_none() && late[0].sign_link.is_none());
}

/// Settle a signed network.
fn settled(net: &mut Net) {
    net.run(4_000);
}

#[test]
fn attested_routes_converge_with_real_signatures() {
    let mut net = Net::signed(6, |i| Config { announce_every: 500, seed: i as u64 + 1, ..Config::default() });
    for i in 0..5 {
        net.link_cost(i, i + 1, 300);
    }
    settled(&mut net);
    for a in 0..6 {
        for b in 0..6 {
            assert!(a == b || net.routed(a, b), "{a} → {b}");
        }
    }
    let s = net.nodes[5].stats();
    assert!(s.announcements_attested > 0 && s.chains_refused == 0 && s.announcements_forged == 0, "{s:?}");
    let v = via(&net.nodes[5], &net.k(0), &net.k(4)).expect("route");
    assert!(v.attested && v.hops == 5);
    assert_eq!(net.loops_toward(0), 0);
    net.send(5, 0, 4, b"over five attested hops");
    assert!(net.delivered.iter().any(|(i, _, p)| *i == 0 && &p[..] == b"over five attested hops"));
}

#[test]
fn mixed_meshes_route_through_hops_that_dont_attest_but_prefer_those_that_do() {
    // 0 — 1 — 3 (1 doesn't attest: a version 1 device, or a liar that stopped)
    // 0 — 2 — 3 (attests, but costlier)
    let mut net = Net::signed(4, |i| Config { announce_every: 500, seed: i as u64 + 1, ..Config::default() });
    net.attesting.remove(&1);
    net.link_cost(0, 1, 200);
    net.link_cost(1, 3, 200);
    net.link_cost(0, 2, 900);
    net.link_cost(2, 3, 900);
    settled(&mut net);
    // everyone reaches everyone, the device that doesn't attest included
    for a in 0..4 {
        for b in 0..4 {
            assert!(a == b || net.routed(a, b), "{a} → {b}");
        }
    }
    let r3 = &net.nodes[3];
    let (via1, via2) = (via(r3, &net.k(0), &net.k(1)).unwrap(), via(r3, &net.k(0), &net.k(2)).unwrap());
    assert!(!via1.attested && via2.attested && via1.cost < via2.cost);
    assert_eq!(r3.next_hop_local(&net.k(0), net.now), Some(net.k(2)), "the attested route, though costlier");
    assert_eq!(r3.offered(&net.k(0)), vec![net.k(2)], "the other one isn't offered as a path");
    // with the attested one gone, the other carries the traffic
    net.cut(0, 2);
    net.run(2_000);
    assert_eq!(net.nodes[3].next_hop_local(&net.k(0), net.now), Some(net.k(1)));
    net.send(3, 0, 1, b"through a hop that doesn't attest");
    assert!(net.delivered.iter().any(|(i, _, p)| *i == 0 && &p[..] == b"through a hop that doesn't attest"));
    let s: Vec<Stats> = net.nodes.iter().map(Router::stats).collect();
    assert!(s.iter().all(|s| s.chains_refused == 0 && s.announcements_forged == 0), "{s:?}");
}

#[test]
fn a_one_hop_liar_that_drops_its_chain_attracts_nothing_attested_nodes_can_avoid() {
    // 0 — 1 (liar) — 4, and 0 — 2 — 3 — 4: the liar claims to be one hop
    // from 0 at the floor, unattested
    let topo = |attest: bool| {
        let mut net =
            Net::signed(5, |i| Config { announce_every: 500, seed: i as u64 + 1, attest, ..Config::default() });
        net.liars.insert(1);
        for (a, b) in [(0, 1), (1, 4), (0, 2), (2, 3), (3, 4)] {
            net.link_cost(a, b, 300);
        }
        settled(&mut net);
        net.nodes[4].next_hop_local(&net.k(0), net.now)
    };
    let attested = topo(true);
    assert_ne!(attested, None);
    assert_ne!(attested, Some(Net::signed(5, |_| Config::default()).k(1)), "attested: around the liar");
    let unattested = topo(false);
    assert_eq!(unattested, Some(Net::signed(5, |_| Config::default()).k(1)), "without: through it");
}

// ─────────────── refreshes without their chain (`Announce::same`) ───────────────

/// The announcements `r` has for `to` of `origin`, after a tick.
fn sent_to(r: &mut Router, to: SignPk, origin: SignPk, now: Time) -> Vec<Announce> {
    r.tick(now);
    let mut out = Vec::new();
    r.drain(&mut out);
    out.into_iter()
        .filter_map(|x| match x {
            Out::Announce { to: t, ann } if t == to && ann.origin == origin => Some(ann),
            _ => None,
        })
        .collect()
}

/// A neighbour's copy of `full`'s origin at seqno `seq`, without its chain.
fn refresh(o: &DeviceKeys, full: &Announce, seq: u64) -> Announce {
    let next = sign_announce(o, Origination { seq, flags: 0, scope: full.scope, uplink: 0 }, "o");
    Announce { hops: full.hops, cost: full.cost, same: true, ..next }
}

#[test]
fn a_refresh_within_the_epoch_is_attested_by_the_chain_its_sender_sent() {
    let (o, u, l, x, me) = (dk(1), dk(2), dk(3), dk(5), dk(4));
    let s0 = epoch_start(&o.sign_pk(), 8);
    let mut r = router(&me, &[l.sign_pk(), x.sign_pk()], 100);
    let full = relayed(&o, &[&u, &l], me.sign_pk(), &[300, 400, 500], s0, 8);
    r.on_announce(l.sign_pk(), full.clone(), 0, s0, wire::verify);
    let mut checks = 0;
    let mut count = |c: Check<'_>| {
        checks += 1;
        wire::verify(c)
    };
    // the next seqno, a refresh without its chain: one signature, the origin's
    r.on_announce(l.sign_pk(), refresh(&o, &full, s0 + 16_000), 16_000, s0 + 16_000, &mut count);
    assert_eq!(checks, 1);
    let v = via(&r, &o.sign_pk(), &l.sign_pk()).expect("a route");
    assert!(v.attested && v.seq == s0 + 16_000 && v.cost == full.cost + 500);
    // advertising more than its hop signed is fine (its cost rose) ...
    let up = Announce { cost: full.cost + 50, ..refresh(&o, &full, s0 + 32_000) };
    r.on_announce(l.sign_pk(), up, 32_000, s0 + 32_000, wire::verify);
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_some_and(|v| v.attested && v.cost == full.cost + 50 + 500));
    let s = r.stats();
    assert_eq!((s.chains_reused, s.chains_unheld, s.chains_refused), (2, 0, 0));
    // ... less is not: no chain says so (unattested, not a lie: the chain
    // that would have said so may have been lost)
    let down = Announce { cost: full.cost - 1, ..refresh(&o, &full, s0 + 48_000) };
    r.on_announce(l.sign_pk(), down, 48_000, s0 + 48_000, wire::verify);
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_some_and(|v| !v.attested));
    let s = r.stats();
    assert_eq!((s.chains_reused, s.chains_unheld, s.neighbours_distrusted), (2, 1, 0));
    // ... and the chain is asked for again, of its sender only, once
    let mut out = Vec::new();
    r.drain(&mut out);
    let asked: Vec<_> =
        out.iter().filter_map(|x| if let Out::SeqReq { to, req } = x { Some((*to, *req)) } else { None }).collect();
    assert_eq!(asked, vec![(l.sign_pk(), SeqReq { origin: o.sign_pk(), seq: s0 + 48_000, hops: 1 })]);
    // a neighbour that sent us no chain can't refresh one: X's claim is
    // unattested (L's chain names L, and us through L)
    r.on_announce(x.sign_pk(), refresh(&o, &full, s0 + 48_000), 48_000, s0 + 48_000, wire::verify);
    assert!(via(&r, &o.sign_pk(), &x.sign_pk()).is_some_and(|v| !v.attested));
}

#[test]
fn a_refresh_an_epoch_later_needs_its_chain_again() {
    let (o, l, me) = (dk(1), dk(3), dk(4));
    let s0 = epoch_start(&o.sign_pk(), 8);
    let mut r = router(&me, &[l.sign_pk()], 100);
    let full = relayed(&o, &[&l], me.sign_pk(), &[300, 400], s0, 8);
    r.on_announce(l.sign_pk(), full.clone(), 0, s0, wire::verify);
    let later = s0 + FAR_ATTEST_EPOCH;
    r.on_announce(l.sign_pk(), refresh(&o, &full, later), 1_000, later, wire::verify);
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_some_and(|v| !v.attested && v.seq == later));
    assert_eq!(r.stats().chains_unheld, 1);
    // its sender answers with the chain re-signed for the new epoch
    let again = relayed(&o, &[&l], me.sign_pk(), &[300, 400], later, 8);
    r.on_announce(l.sign_pk(), again, 1_100, later, wire::verify);
    assert!(via(&r, &o.sign_pk(), &l.sign_pk()).is_some_and(|v| v.attested));
}

#[test]
fn a_relay_sends_its_chain_again_only_when_its_claim_needs_it() {
    let (o, u, me, y) = (dk(1), dk(2), dk(4), dk(6));
    let s0 = epoch_start(&o.sign_pk(), 8);
    let mut r = router(&me, &[u.sign_pk(), y.sign_pk()], 100);
    r.drain(&mut Vec::new());
    let full = |seq: u64, link: u32| relayed(&o, &[&u], me.sign_pk(), &[300, link], seq, 8);
    let clock = std::cell::Cell::new(0);
    let step = |r: &mut Router, a: Announce, seq: u64| {
        clock.set(clock.get() + 1_000);
        let t = clock.get();
        r.on_announce(u.sign_pk(), a, t, seq, wire::verify);
        let got = sent_to(r, y.sign_pk(), o.sign_pk(), t + 100);
        assert_eq!(got.len(), 1, "{got:?}");
        got.into_iter().next().unwrap()
    };
    let a = step(&mut r, full(s0, 400), s0);
    assert!(a.chain_len() == 2 && a.sign_link.is_some() && !a.same, "the chain, our hop to sign");
    // a refresh with nothing changed: without it
    let f = full(s0, 400);
    let b = step(&mut r, refresh(&o, &f, s0 + 1_000), s0 + 1_000);
    assert!(b.same && b.chain.is_none() && b.sign_link.is_none() && b.cost == a.cost);
    assert_eq!(wire::wire_len(&b), wire::wire_len(&Announce { same: false, ..b.clone() }));
    // the chain under ours changed and our cost rose (U measured its link
    // anew): the chain Y holds still bounds what we claim
    let c = step(&mut r, full(s0 + 2_000, 450), s0 + 2_000);
    assert!(c.same && c.cost == a.cost + 50);
    // a refresh whose cost fell well under what our hop signed: re-signed
    let d = step(&mut r, full(s0 + 3_000, 300), s0 + 3_000);
    assert!(!d.same && d.chain_len() == 2 && d.cost == a.cost - 100);
    // ... a little under: the same, as signed
    let d = step(&mut r, full(s0 + 3_500, 290), s0 + 3_500);
    assert!(d.same && d.cost == a.cost - 100, "{d:?}");
    // Y's connection again: it holds nothing of ours, so its greeting
    // carries the chain (and the next refresh goes without it again)
    let t = clock.get();
    r.hop_down(y.sign_pk(), t + 200);
    r.hop_up(y.sign_pk(), t + 300);
    let mut out = Vec::new();
    r.drain(&mut out);
    let greeting: Vec<&Announce> = out
        .iter()
        .filter_map(|x| match x {
            Out::Announce { to, ann } if *to == y.sign_pk() && ann.origin == o.sign_pk() => Some(ann),
            _ => None,
        })
        .collect();
    assert!(greeting.len() == 1 && !greeting[0].same && greeting[0].chain_len() == 2, "{greeting:?}");
    let e = step(&mut r, refresh(&o, &full(s0, 290), s0 + 4_000), s0 + 4_000);
    assert!(e.same);
    // Y asks for the chain of a refresh it got: re-sent, to Y alone
    let f2 = step(&mut r, refresh(&o, &full(s0, 290), s0 + 5_000), s0 + 5_000);
    assert!(f2.same);
    r.on_seqreq(y.sign_pk(), SeqReq { origin: o.sign_pk(), seq: s0 + 5_000, hops: 1 }, clock.get() + 400);
    let mut out = Vec::new();
    r.drain(&mut out);
    let answers: Vec<&Announce> =
        out.iter().filter_map(|x| if let Out::Announce { ann, .. } = x { Some(ann) } else { None }).collect();
    assert!(answers.len() == 1 && !answers[0].same && answers[0].chain_len() == 2);
    // an epoch later: everything again
    let g = step(&mut r, full(s0 + FAR_ATTEST_EPOCH, 290), s0 + FAR_ATTEST_EPOCH);
    assert!(!g.same);
    let s = r.stats();
    assert_eq!(s.chains_elided, 5);
}

#[test]
fn an_origin_sends_its_own_hop_once_an_epoch_and_again_when_asked() {
    let (me, y, z) = (dk(4), dk(6), dk(7));
    let mut r = router(&me, &[y.sign_pk(), z.sign_pk()], 100);
    let s0 = epoch_start(&me.sign_pk(), 2);
    let own = |r: &mut Router, seq: u64, now: Time| {
        r.originate(sign_announce(&me, Origination { seq, flags: 0, scope: 2, uplink: 0 }, ""), now);
        sent_to(r, y.sign_pk(), me.sign_pk(), now)
    };
    let a = own(&mut r, s0, 20_000);
    assert!(a.len() == 1 && a[0].sign_link.is_some() && !a[0].same);
    let b = own(&mut r, s0 + 16_000, 36_000);
    assert!(b.len() == 1 && b[0].same && b[0].sign_link.is_none());
    // Y lost it: asked for that seqno, we send ours again, to Y only (not
    // a fresh announcement to everyone)
    r.on_seqreq(y.sign_pk(), SeqReq { origin: me.sign_pk(), seq: s0 + 16_000, hops: 1 }, 36_500);
    let mut out = Vec::new();
    r.drain(&mut out);
    let to: Vec<SignPk> =
        out.iter().filter_map(|x| if let Out::Announce { to, .. } = x { Some(*to) } else { None }).collect();
    assert_eq!(to, vec![y.sign_pk()]);
    assert!(matches!(&out[0], Out::Announce { ann, .. } if ann.sign_link.is_some() && ann.seq == s0 + 16_000));
    let c = own(&mut r, s0 + ATTEST_EPOCH, 90_000);
    assert!(c.len() == 1 && !c[0].same, "a new epoch");
}

#[test]
fn refreshes_keep_a_signed_mesh_attested_and_cost_fewer_bytes() {
    let run = |attest: bool, reuse: bool| {
        let cfg = |i: usize| Config {
            announce_every: 500,
            seed: i as u64 + 1,
            attest,
            chain_reuse: reuse,
            ..Config::default()
        };
        let mut net = Net::signed(6, cfg);
        for i in 0..5 {
            net.link_cost(i, i + 1, 300);
        }
        net.run(20_000);
        for a in 0..6 {
            for b in 0..6 {
                assert!(a == b || net.routed(a, b), "{a} → {b}");
            }
        }
        let v = via(&net.nodes[5], &net.k(0), &net.k(4)).expect("route");
        assert!(v.attested == attest && v.hops == 5, "reuse {reuse}: {v:?}");
        let s: Vec<Stats> = net.nodes.iter().map(Router::stats).collect();
        assert!(s.iter().all(|s| s.chains_refused == 0 && s.announcements_forged == 0), "{s:?}");
        let sum = |f: fn(&Stats) -> u64| s.iter().map(f).sum::<u64>();
        let bytes: u64 = net.ann_bytes.iter().sum();
        (
            sum(|s| s.chains_elided),
            sum(|s| s.chains_reused),
            sum(|s| s.chains_unheld),
            sum(|s| s.signatures_checked),
            bytes,
        )
    };
    let (elided, reused, unheld, checked, bytes) = run(true, true);
    let (elided_off, _, _, checked_off, bytes_off) = run(true, false);
    let (.., plain) = run(false, false);
    // (every refresh sent without its chain was attested by the one held,
    // but for a few still in flight when the run ends)
    assert!(elided > 0 && reused <= elided && elided - reused <= 10 && unheld == 0, "{elided} {reused} {unheld}");
    assert_eq!(elided_off, 0);
    // hops sign an epoch: copies of a chain repeat within it, so the cache
    // spares as many checks either way; what reuse saves is bytes
    assert!(checked <= checked_off, "signature checks {checked} with reuse, {checked_off} without");
    // (measured: 31% over unattested with reuse, 77% without; five hops
    // in a line, refreshes every 500 ms)
    let (over, over_off) = (bytes - plain, bytes_off - plain);
    assert!(over * 2 < over_off, "attestation bytes {over} with reuse, {over_off} without, over {plain}");
}

// ─────────────── chains only where they may be used (`Config::chain_pull`) ───────────────

#[test]
fn a_neighbour_whose_attested_route_beats_ours_gets_it_without_the_chain() {
    // O — U — me, and Y, Z our other neighbours
    let (o, u, v, me, y, z) = (dk(1), dk(2), dk(8), dk(4), dk(6), dk(7));
    let s0 = epoch_start(&o.sign_pk(), 8);
    let mut r = router(&me, &[u.sign_pk(), y.sign_pk(), z.sign_pk()], 100);
    r.drain(&mut Vec::new());
    // Y has an attested route of its own (O — V — Y), no costlier than ours
    // through U plus our link to Y; Z told us of one without a chain
    r.on_announce(y.sign_pk(), relayed(&o, &[&v, &y], me.sign_pk(), &[300, 400, 500], s0, 8), 10, s0, wire::verify);
    let zs = Announce { chain: None, ..relayed(&o, &[&v, &z], me.sign_pk(), &[300, 400, 500], s0, 8) };
    r.on_announce(z.sign_pk(), zs, 20, s0, wire::verify);
    assert!(via(&r, &o.sign_pk(), &z.sign_pk()).is_some_and(|v| !v.attested));
    r.tick(1_000);
    r.drain(&mut Vec::new());
    // the next seqno through U: ours costs 300 + 400 (+ our hop to Y)
    let seq = s0 + 1_000;
    r.on_announce(u.sign_pk(), relayed(&o, &[&u], me.sign_pk(), &[300, 400], seq, 8), 2_000, seq, wire::verify);
    r.tick(2_100);
    let mut out = Vec::new();
    r.drain(&mut out);
    let to = |n: &DeviceKeys| -> Vec<Announce> {
        out.iter()
            .filter_map(|x| match x {
                Out::Announce { to, ann } if *to == n.sign_pk() && ann.origin == o.sign_pk() => Some(ann.clone()),
                _ => None,
            })
            .collect()
    };
    let (ty, tz) = (to(&y), to(&z));
    assert!(ty.len() == 1 && ty[0].same && ty[0].chain.is_none() && ty[0].sign_link.is_none(), "{ty:?}");
    assert_eq!(wire::wire_len(&ty[0]), wire::wire_len(&Announce { same: false, ..ty[0].clone() }));
    // Z's route came unattested: held to it, Z needs ours with its chain
    assert!(tz.len() == 1 && !tz[0].same && tz[0].chain_len() == 2 && tz[0].sign_link.is_some(), "{tz:?}");
    assert_eq!(r.stats().chains_withheld, 1);
    // Y asks after all (its own route went): the chain, to Y alone
    r.on_seqreq(y.sign_pk(), SeqReq { origin: o.sign_pk(), seq, hops: 1 }, 2_200);
    let mut out = Vec::new();
    r.drain(&mut out);
    let answers: Vec<(SignPk, &Announce)> =
        out.iter().filter_map(|x| if let Out::Announce { to, ann } = x { Some((*to, ann)) } else { None }).collect();
    assert!(answers.len() == 1 && answers[0].0 == y.sign_pk(), "{answers:?}");
    assert!(!answers[0].1.same && answers[0].1.chain_len() == 2 && answers[0].1.sign_link.is_some());
    // with pull off, Y gets the chain at once
    let mut r = router(&me, &[u.sign_pk(), y.sign_pk()], 100);
    r.cfg.chain_pull = false;
    r.on_announce(y.sign_pk(), relayed(&o, &[&v, &y], me.sign_pk(), &[300, 400, 500], s0, 8), 10, s0, wire::verify);
    r.tick(1_000);
    r.drain(&mut Vec::new());
    r.on_announce(u.sign_pk(), relayed(&o, &[&u], me.sign_pk(), &[300, 400], seq, 8), 2_000, seq, wire::verify);
    let got = sent_to(&mut r, y.sign_pk(), o.sign_pk(), 2_100);
    assert!(got.len() == 1 && !got[0].same && got[0].chain_len() == 2, "{got:?}");
}

#[test]
fn a_chain_we_lack_is_asked_for_only_when_its_route_would_be_our_best() {
    let (o, a, b, c, me) = (dk(1), dk(2), dk(3), dk(5), dk(4));
    let s0 = epoch_start(&o.sign_pk(), 8);
    let mut r = router(&me, &[a.sign_pk(), b.sign_pk(), c.sign_pk()], 100);
    // attested through A: 300 + 400, and our hop
    r.on_announce(a.sign_pk(), relayed(&o, &[&a], me.sign_pk(), &[300, 400], s0, 8), 0, s0, wire::verify);
    r.drain(&mut Vec::new());
    let unheld = |seq: u64, hops: u8, cost: u32| Announce {
        hops,
        cost,
        same: true,
        ..sign_announce(&o, Origination { seq, flags: 0, scope: 8, uplink: 0 }, "o")
    };
    let asked = |r: &mut Router| -> Vec<(SignPk, SeqReq)> {
        let mut out = Vec::new();
        r.drain(&mut out);
        out.into_iter().filter_map(|x| if let Out::SeqReq { to, req } = x { Some((to, req)) } else { None }).collect()
    };
    // a costlier refresh from B whose chain we don't hold: taken
    // unattested, not asked for (A's attested route beats it anyway)
    r.on_announce(b.sign_pk(), unheld(s0 + 1_000, 3, 2_000), 1_000, s0 + 1_000, wire::verify);
    assert!(via(&r, &o.sign_pk(), &b.sign_pk()).is_some_and(|v| !v.attested));
    assert_eq!(asked(&mut r), vec![]);
    // a cheaper one from C: asked for, of C alone
    r.on_announce(c.sign_pk(), unheld(s0 + 2_000, 1, 300), 2_000, s0 + 2_000, wire::verify);
    assert_eq!(asked(&mut r), vec![(c.sign_pk(), SeqReq { origin: o.sign_pk(), seq: s0 + 2_000, hops: 1 })]);
    // ... once an epoch
    r.on_announce(c.sign_pk(), unheld(s0 + 3_000, 1, 300), 3_000, s0 + 3_000, wire::verify);
    assert_eq!(asked(&mut r), vec![]);
    let s = r.stats();
    assert_eq!((s.chains_unheld, s.chains_asked, s.neighbours_distrusted), (3, 1, 0));
}
