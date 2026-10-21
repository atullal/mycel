//! Dissemination on model sets: an in-memory network of devices, each with
//! a [`Disseminator`], delivering every message within one 10 ms step and
//! running a real Sync v2 session for every pull.

use std::collections::{BTreeSet, HashSet, VecDeque};

use mycel_crypto::{Hash32, SignPk};

use super::gossip::*;
use super::model::*;
use super::*;

fn pk(i: u16) -> SignPk {
    let mut k = [0u8; 32];
    k[..2].copy_from_slice(&i.to_le_bytes());
    k[31] = 1;
    SignPk(k)
}

fn space() -> mycel_trust::SpaceId {
    Hash32([9; 32])
}

type D = Disseminator<ModelOp, ModelEnv>;

struct Net {
    keys: Vec<SignPk>,
    sets: Vec<ModelSet>,
    ds: Vec<D>,
    now: u64,
    /// Envelope payload copies each device received by push.
    copies: Vec<u64>,
    sessions: u64,
    session_bytes: u64,
    gossip_bytes: u64,
    /// Devices whose incoming pushes are dropped (a lossy path).
    deaf: HashSet<usize>,
}

impl Net {
    fn new(n: u16, members: impl Fn(usize, &SignPk) -> Member) -> Net {
        let keys: Vec<SignPk> = (0..n).map(pk).collect();
        let mut sets = Vec::new();
        let mut ds = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            sets.push(ModelSet::new(space()));
            let mut d = D::new(*k, GossipConfig::default());
            let ms: Vec<Member> = keys.iter().filter(|p| *p != k).map(|p| members(i, p)).collect();
            d.set_members(sets.last().unwrap(), &ms, 0);
            ds.push(d);
        }
        let n = keys.len();
        Net {
            keys,
            sets,
            ds,
            now: 0,
            copies: vec![0; n],
            sessions: 0,
            session_bytes: 0,
            gossip_bytes: 0,
            deaf: HashSet::new(),
        }
    }

    fn ix(&self, k: &SignPk) -> usize {
        self.keys.iter().position(|p| p == k).unwrap()
    }

    /// One step: every device's actions, then every message delivered.
    fn step(&mut self) -> bool {
        let mut mail: VecDeque<(usize, usize, GossipMsg<ModelOp, ModelEnv>)> = VecDeque::new();
        let mut pulls = Vec::new();
        for i in 0..self.ds.len() {
            while let Some(a) = self.ds[i].poll(self.now) {
                match a {
                    Action::Send { to, msg } => {
                        self.gossip_bytes += frame_len(&msg) as u64;
                        mail.push_back((i, self.ix(&to), msg));
                    }
                    Action::Pull { peer, .. } => pulls.push((i, self.ix(&peer))),
                }
            }
        }
        let busy = !mail.is_empty() || !pulls.is_empty();
        for (from, to, msg) in mail {
            if self.deaf.contains(&to) && matches!(msg, GossipMsg::Push { .. }) {
                continue;
            }
            let fk = self.keys[from];
            let pushed = self.ds[to].on_msg(&self.sets[to], fk, msg, self.now).expect("valid gossip");
            if pushed.pushed {
                let n = pushed.envelopes.len();
                self.copies[to] += n as u64;
                let (new, _) = self.sets[to].apply(Received { ops: pushed.ops, envelopes: pushed.envelopes });
                let now = self.now;
                self.ds[to].after_push(&self.sets[to], fk, n, new, now);
            }
        }
        for (c, s) in pulls {
            self.session(c, s);
        }
        busy
    }

    fn session(&mut self, c: usize, s: usize) {
        let (a, b) = if c < s {
            let (l, r) = self.sets.split_at_mut(s);
            (&mut l[c], &mut r[0])
        } else {
            let (l, r) = self.sets.split_at_mut(c);
            (&mut r[0], &mut l[s])
        };
        let run = run_pair(a, b, (None, None), Config::default(), false, |_, _, _| {});
        self.sessions += 1;
        self.session_bytes += run.bytes();
        let now = self.now;
        let (kc, ks) = (self.keys[c], self.keys[s]);
        self.ds[c].on_changed(&self.sets[c], Some(ks), now);
        self.ds[s].on_changed(&self.sets[s], Some(kc), now);
    }

    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.step();
            self.now += 10;
        }
    }

    fn write(&mut self, i: usize, n: u64, body: usize) -> Vec<EnvelopeId> {
        let k = self.keys[i];
        let ids = self.sets[i].append(k, n, body);
        let now = self.now;
        self.ds[i].on_changed(&self.sets[i], None, now);
        ids
    }

    fn holders(&self, id: &EnvelopeId) -> usize {
        self.sets.iter().filter(|s| s.index().holds(id)).count()
    }
}

fn internet(_: usize, p: &SignPk) -> Member {
    Member { key: *p, class: PathClass::Internet, reachable: true, gossip: true, slow: false }
}

#[test]
fn a_write_reaches_a_12_member_group_with_few_copies_after_warm_up() {
    let mut net = Net::new(12, internet);
    net.run(500);
    // Warm-up: the first messages prune redundant eager edges.
    for round in 0..5 {
        let ids = net.write(round % 12, 1, 300);
        net.run(4_000);
        assert_eq!(net.holders(&ids[0]), 12, "warm-up message {round}");
    }
    let before: u64 = net.copies.iter().sum();
    let sessions = net.sessions;
    let ids = net.write(7, 1, 300);
    net.run(4_000);
    assert_eq!(net.holders(&ids[0]), 12);
    let copies = net.copies.iter().sum::<u64>() - before;
    eprintln!("12 members: {copies} payload copies for 11 receivers, {} sessions", net.sessions - sessions);
    // Design §13.3: ≤ 1.5 payload copies per member after warm-up.
    assert!(copies as f64 <= 1.5 * 11.0, "{copies} copies");
}

#[test]
fn groups_of_six_or_fewer_are_a_full_mesh() {
    let net = Net::new(6, internet);
    for d in &net.ds {
        assert_eq!(d.neighbours(&space()).len(), 5);
    }
}

#[test]
fn larger_groups_have_bounded_degree_and_a_connected_overlay() {
    for n in [10u16, 50, 200] {
        let mut net = Net::new(n, internet);
        net.run(200);
        let mut max = 0;
        for d in &net.ds {
            let deg = d.neighbours(&space()).len();
            max = max.max(deg);
            assert!(deg >= 2, "every device keeps edges it initiated");
        }
        assert!(max <= MAX_DEGREE, "{n} members: degree {max}");
        // Connected: a search over neighbour edges reaches everyone.
        let mut seen = BTreeSet::from([0usize]);
        let mut stack = vec![0usize];
        while let Some(i) = stack.pop() {
            for (p, _) in net.ds[i].neighbours(&space()) {
                let j = net.ix(&p);
                if seen.insert(j) {
                    stack.push(j);
                }
            }
        }
        assert_eq!(seen.len(), n as usize, "{n} members: overlay connected");
        // Edges are symmetric once grafts were answered.
        for (i, d) in net.ds.iter().enumerate() {
            for (p, _) in d.neighbours(&space()) {
                assert!(net.ds[net.ix(&p)].is_neighbour(&space(), &net.keys[i]), "asymmetric edge");
            }
        }
    }
}

/// Three radio clusters whose members see each other directly and the rest
/// only over the internet: locality edges stay inside clusters, but the
/// random edges join them (design §8.1, `clustered-no-keepers`).
#[test]
fn clusters_are_joined_by_random_edges() {
    let cluster = |i: usize| i % 3;
    let mut net = Net::new(30, |i, p| {
        let j = p.0[0] as usize + 256 * p.0[1] as usize;
        let class = if cluster(i) == cluster(j) { PathClass::Direct } else { PathClass::Mesh };
        Member { key: *p, class, reachable: true, gossip: true, slow: class != PathClass::Direct }
    });
    net.run(200);
    let ids = net.write(4, 1, 200);
    net.run(10_000);
    assert_eq!(net.holders(&ids[0]), 30, "every cluster got it");
}

#[test]
fn a_duplicate_push_prunes_the_edge_to_lazy() {
    let mut net = Net::new(3, internet);
    net.run(100);
    let ids = net.write(0, 1, 100);
    net.run(2_000);
    assert_eq!(net.holders(&ids[0]), 3);
    // 1 and 2 both got it from 0 and forwarded it to each other: each push
    // between them was a duplicate, so that edge is lazy now.
    let lazy = |a: usize, b: usize| net.ds[a].neighbours(&space()).iter().any(|(p, eager)| *p == net.keys[b] && !eager);
    assert!(lazy(1, 2) || lazy(2, 1), "{:?} {:?}", net.ds[1].neighbours(&space()), net.ds[2].neighbours(&space()));
    assert!(net.ds.iter().map(|d| d.stats().prunes_sent).sum::<u64>() >= 1);
}

/// A device that misses pushes (a lossy path) still gets every item: lazy
/// neighbours' announcements time out, it grafts and pulls with a session.
#[test]
fn a_missed_push_is_repaired_by_ihave_graft_and_pull() {
    let mut net = Net::new(8, internet);
    net.run(200);
    for _ in 0..3 {
        net.write(0, 1, 100);
        net.run(2_000);
    }
    net.deaf.insert(5);
    let ids = net.write(1, 1, 100);
    net.run(6_000);
    assert_eq!(net.holders(&ids[0]), 8, "the deaf device pulled it");
    assert!(net.ds[5].stats().pulls >= 1);
}

/// Too much for a push (a catch-up brought hundreds of items): announced to
/// everyone instead, and neighbours pull it in sessions.
#[test]
fn a_large_change_is_announced_and_pulled() {
    let mut net = Net::new(4, internet);
    net.run(100);
    let ids = net.write(0, 500, 300);
    net.run(5_000);
    assert!(ids.iter().all(|id| net.holders(id) == 4));
    assert!(net.sessions >= 1);
    assert_eq!(net.ds[0].stats().push_items_sent, 0, "nothing pushed: {:?}", net.ds[0].stats());
}

#[test]
fn a_graft_beyond_the_degree_cap_is_dropped_with_alternatives() {
    let keys: Vec<SignPk> = (0..20).map(pk).collect();
    let mut d = D::new(keys[0], GossipConfig::default());
    let members: Vec<Member> = keys[1..].iter().map(|p| internet(0, p)).collect();
    let set = ModelSet::new(space());
    d.set_members(&set, &members, 0);
    while d.poll(0).is_some() {}
    for p in &keys[1..] {
        d.on_msg(&set, *p, GossipMsg::Graft { space: space() }, 0).unwrap();
    }
    assert_eq!(d.neighbours(&space()).len(), MAX_DEGREE);
    let mut drops = 0;
    while let Some(a) = d.poll(0) {
        if let Action::Send { msg: GossipMsg::Prune { drop: true, alternatives, .. }, .. } = a {
            assert!(!alternatives.is_empty() && alternatives.len() <= MAX_ALTERNATIVES);
            drops += 1;
        }
    }
    assert_eq!(drops, 19 - MAX_DEGREE);
}

/// Byte-fair forwarding: one author floods a slow link, another writes a
/// little; the second author's items leave within the first rounds, not
/// behind the whole flood.
#[test]
fn a_flooding_author_cannot_starve_others_on_a_slow_link() {
    let keys: Vec<SignPk> = (0..2).map(pk).collect();
    let mut d = D::new(keys[0], GossipConfig::default());
    let slow = Member { key: keys[1], class: PathClass::Direct, reachable: true, gossip: true, slow: true };
    let mut set = ModelSet::new(space());
    d.set_members(&set, &[slow], 0);
    while d.poll(0).is_some() {}
    let (flood, quiet) = (pk(100), pk(101));
    // 60 items of ~250 B from the flooder, written one push at a time.
    for _ in 0..60 {
        set.append(flood, 1, 250);
        d.on_changed(&set, None, 0);
    }
    let q = set.append(quiet, 3, 250);
    d.on_changed(&set, None, 0);
    let mut order = Vec::new();
    let mut now = 0;
    while order.len() < 63 && now < 60_000 {
        while let Some(a) = d.poll(now) {
            if let Action::Send { msg: GossipMsg::Push { items, .. }, .. } = a {
                order.extend(items.iter().map(|e| e.author));
            }
        }
        now += 50;
    }
    let first_quiet = order.iter().position(|a| *a == quiet).expect("the quiet author's items left");
    let last_quiet = order.iter().rposition(|a| *a == quiet).unwrap();
    eprintln!("quiet author's items at positions {first_quiet}..={last_quiet} of {}", order.len());
    assert!(last_quiet < 12, "fair share: {order:?}");
    let _ = q;
}

#[test]
fn have_removes_queued_items_and_later_ones() {
    let keys: Vec<SignPk> = (0..2).map(pk).collect();
    let mut d = D::new(keys[0], GossipConfig { slow_rate: 1.0, burst: 1.0, ..Default::default() });
    let slow = Member { key: keys[1], class: PathClass::Direct, reachable: true, gossip: true, slow: true };
    let mut set = ModelSet::new(space());
    d.set_members(&set, &[slow], 0);
    while d.poll(0).is_some() {}
    let ids = set.append(pk(50), 2, 2000);
    d.on_changed(&set, None, 0);
    let set_b = ModelSet::new(space());
    let _ = set_b;
    d.on_msg(&set, keys[1], GossipMsg::Have { space: space(), ids: ids.clone() }, 0).unwrap();
    assert!(d.stats().skipped_by_have >= 2, "{:?}", d.stats());
    let mut pushed = 0;
    for t in 0..100 {
        while let Some(a) = d.poll(t * 1000) {
            if matches!(a, Action::Send { msg: GossipMsg::Push { .. }, .. }) {
                pushed += 1;
            }
        }
    }
    assert_eq!(pushed, 0);
}

/// A device that receives a new large item tells its other eager neighbours
/// before forwarding (IDONTWANT).
#[test]
fn a_new_large_item_is_announced_with_have_before_forwarding() {
    let mut net = Net::new(4, internet);
    net.run(100);
    let ids = net.write(0, 1, 4000);
    net.run(2_000);
    assert_eq!(net.holders(&ids[0]), 4);
    assert!(net.ds[1..].iter().map(|d| d.stats().haves_sent).sum::<u64>() >= 1);
}

#[test]
fn messages_over_their_limits_are_refused() {
    let keys: Vec<SignPk> = (0..2).map(pk).collect();
    let mut d = D::new(keys[0], GossipConfig::default());
    let set = ModelSet::new(space());
    d.set_members(&set, &[internet(0, &keys[1])], 0);
    let ids = vec![Hash32([1; 32]); MAX_HAVE_IDS + 1];
    assert_eq!(d.on_msg(&set, keys[1], GossipMsg::Have { space: space(), ids }, 0), Err(GossipError::TooLarge));
    let other = Hash32([3; 32]);
    assert_eq!(d.on_msg(&set, keys[1], GossipMsg::Graft { space: other }, 0), Err(GossipError::WrongSpace));
}

#[test]
fn seen_notes_ride_on_messages_once_per_neighbour() {
    let mut net = Net::new(3, internet);
    net.run(100);
    assert!(net.ds[0].carry_seen(&space(), vec![7; 100]));
    assert!(!net.ds[0].carry_seen(&space(), vec![7; 100]), "known already");
    let (k0, k1) = (net.keys[0], net.keys[1]);
    net.sets[0].append(k0, 1, 10);
    net.ds[0].on_changed(&net.sets[0], None, 0);
    let mut carried = 0;
    let mut t = 0;
    while t < 2000 {
        while let Some(a) = net.ds[0].poll(t) {
            if let Action::Send { to, msg: GossipMsg::Push { seen, .. } | GossipMsg::IHave { seen, .. } } = a
                && to == k1
            {
                carried += seen.len();
            }
        }
        t += 10;
    }
    assert_eq!(carried, 1);
}

/// Dissemination cost on model sets (real postcard sizes, no transport
/// overhead): gossip frame bytes and payload copies for one 351-byte
/// message in 10/50/200-member groups after warm-up (docs/BENCHMARKS.md
/// §8). `cargo test -p mycel-sync --lib bench_gossip -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_gossip_dissemination_cost() {
    println!("| members | gossip B per message (group) | per member | payload copies | pulls (sessions) |");
    println!("|---|---|---|---|---|");
    for n in [10u16, 50, 200] {
        let mut net = Net::new(n, internet);
        net.run(500);
        for w in 0..8 {
            net.write(w % n as usize, 1, 300);
            net.run(3_000);
        }
        let (b0, c0, s0) = (net.gossip_bytes, net.copies.iter().sum::<u64>(), net.sessions);
        const K: u64 = 5;
        for k in 0..K {
            let ids = net.write((k as usize * 13) % n as usize, 1, 300);
            net.run(3_000);
            assert_eq!(net.holders(&ids[0]), n as usize);
        }
        let b = (net.gossip_bytes - b0) / K;
        let c = (net.copies.iter().sum::<u64>() - c0) as f64 / K as f64;
        let s = (net.sessions - s0) as f64 / K as f64;
        println!("| {n} | {b} | {} | {c:.1} | {s:.1} |", b / u64::from(n));
    }
}
