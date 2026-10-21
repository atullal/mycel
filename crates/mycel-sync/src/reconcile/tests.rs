use std::collections::HashSet;

use mycel_crypto::{Hash32, SignPk};

use super::model::*;
use super::*;

fn pk(i: u8) -> SignPk {
    SignPk([i; 32])
}

fn space() -> mycel_trust::SpaceId {
    Hash32([9; 32])
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn copy(s: &ModelSet) -> ModelSet {
    let mut c = ModelSet::new(s.space);
    let (ops, envs) = s.all();
    for op in ops {
        c.insert_op(op);
    }
    c.apply(Received { ops: Vec::new(), envelopes: envs });
    c
}

fn sync(a: &mut ModelSet, b: &mut ModelSet) -> PairRun {
    run_pair(a, b, (None, None), Config::default(), false, |_, _, _| {})
}

fn sync_with(a: &mut ModelSet, b: &mut ModelSet, records: (Option<PeerRecord>, Option<PeerRecord>)) -> PairRun {
    run_pair(a, b, records, Config::default(), false, |_, _, _| {})
}

fn assert_equal(a: &ModelSet, b: &ModelSet) {
    assert_eq!(a.env_ids(), b.env_ids(), "envelope sets differ");
    assert_eq!(a.op_ids(), b.op_ids(), "op sets differ");
    assert_eq!(a.digest(), b.digest(), "equal sets, different digests");
}

fn converged(run: &PairRun) -> u8 {
    match (&run.client, &run.server) {
        (Outcome::Converged { phase: a, .. }, Outcome::Converged { phase: b, .. }) => {
            assert_eq!(a, b);
            *a
        }
        (Outcome::InSync, Outcome::InSync) => 0,
        other => panic!("not converged: {other:?}"),
    }
}

/// A set with `authors` chains of `len` envelopes each.
fn history(authors: u8, len: u64, body: usize) -> ModelSet {
    let mut s = ModelSet::new(space());
    for a in 1..=authors {
        s.append(pk(a), len, body);
    }
    s
}

// ───────────── the common cases ─────────────

#[test]
fn idle_session_is_one_round_trip_and_constant_size() {
    for len in [10, 1000] {
        let mut a = history(5, len, 300);
        let mut b = copy(&a);
        let run = sync(&mut a, &mut b);
        assert_eq!(run.client, Outcome::InSync);
        assert_eq!(run.flights, 2, "one round trip");
        assert!(run.bytes() < 300, "idle costs O(1): {} bytes", run.bytes());
    }
}

#[test]
fn one_new_envelope_moves_in_one_phase() {
    let mut a = history(5, 100, 300);
    let mut b = copy(&a);
    let first = sync(&mut a, &mut b);
    assert_eq!(first.client, Outcome::InSync);
    a.append(pk(1), 1, 300);
    let run = sync_with(&mut a, &mut b, (first.client_record, first.server_record));
    assert_eq!(converged(&run), 1);
    assert_equal(&a, &b);
    assert!(run.flights <= 4, "{} flights", run.flights);
    // With a remembered record, only the changed author's entry is sent.
    assert!(run.bytes() < 1500, "{} bytes", run.bytes());
    assert_eq!(run.server_stats.items_in, 1);
}

#[test]
fn records_make_the_next_idle_check_one_round_trip() {
    let mut a = history(3, 20, 100);
    let mut b = history(3, 10, 100);
    let run = sync(&mut a, &mut b);
    converged(&run);
    let again = sync_with(&mut a, &mut b, (run.client_record, run.server_record));
    assert_eq!(again.client, Outcome::InSync);
    assert_eq!(again.flights, 2);
}

#[test]
fn catch_up_sends_only_what_is_missing() {
    let mut server = history(10, 1000, 300);
    let mut client = copy(&server);
    for a in 1..=10 {
        server.append(pk(a), 100, 300);
    }
    let run = sync(&mut client, &mut server);
    assert_eq!(converged(&run), 1);
    assert_equal(&client, &server);
    assert_eq!(run.client_stats.items_in, 1000);
    let control = run.bytes() - run.server_stats.sent_data_bytes - run.client_stats.sent_data_bytes;
    assert!(control < 4000, "control bytes {control}");
    // No record: the server asks for the client's frontier (2.5 RTT).
    assert_eq!(run.flights, 5);
    // Back online with a record: the frontier rides in `Open` (2 RTT), and
    // data starts after one.
    let mut client2 = copy(&server);
    let rec = sync(&mut client2, &mut server);
    for a in 1..=10 {
        server.append(pk(a), 100, 300);
    }
    let run = sync_with(&mut client2, &mut server, (rec.client_record, rec.server_record));
    assert_eq!(converged(&run), 1);
    assert_eq!(run.flights, 4);
    assert_eq!(run.first_data_flight, Some(2));
    assert_equal(&client2, &server);
}

#[test]
fn both_sides_missing_different_things_converge_to_the_union() {
    let mut a = history(4, 50, 50);
    let mut b = copy(&a);
    a.append(pk(1), 10, 50);
    a.append(pk(9), 5, 50);
    b.append(pk(2), 7, 50);
    b.append(pk(10), 3, 50);
    let tip = a.tip_op();
    a.insert_op(ModelOp { parents: vec![tip], nonce: 1 });
    b.insert_op(ModelOp { parents: vec![tip], nonce: 2 });
    let run = sync(&mut a, &mut b);
    assert!(converged(&run) <= 2);
    assert_equal(&a, &b);
}

#[test]
fn more_than_256_authors_are_chunked() {
    let mut a = ModelSet::new(space());
    for i in 0..600u32 {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_le_bytes());
        a.append(SignPk(k), 2, 10);
    }
    let mut b = ModelSet::new(space());
    let run = sync(&mut b, &mut a);
    assert_eq!(converged(&run), 1);
    assert_equal(&a, &b);
    let mut c = ModelSet::new(space());
    let run = run_pair(&mut a, &mut c, (None, None), Config::default(), true, |_, _, _| {});
    assert_eq!(converged(&run), 1);
    assert_equal(&a, &c);
}

#[test]
fn gaps_fill_from_either_side() {
    let full = history(1, 30, 20);
    let ids: Vec<_> =
        (0..30).map(|s| full.index().branch_id_at(&full.index().runs(&pk(1))[0].head, s).unwrap()).collect();
    let mut a = ModelSet::new(space());
    let mut b = ModelSet::new(space());
    for (s, id) in ids.iter().enumerate() {
        let env = full.envelope(id).unwrap().clone();
        if !(10..20).contains(&s) {
            a.insert_env(env.clone()).unwrap();
        }
        if s < 25 {
            b.insert_env(env).unwrap();
        }
    }
    assert_eq!(a.index().runs(&pk(1)).len(), 2, "a has a gap");
    let run = sync(&mut a, &mut b);
    assert!(converged(&run) <= 2);
    assert_equal(&a, &b);
    assert_eq!(a.env_ids().len(), 30);
}

// ───────────── forks and equivocation ─────────────

/// One author's chain of `common` envelopes, then branch 1 (`x` more) at
/// one side and branch 2 (`y` more) at the other.
fn forked(common: u64, x: u64, y: u64) -> (ModelSet, ModelSet) {
    let mut a = history(2, 5, 20);
    let base = a.fork(pk(7), None, common, 0).last().copied();
    let mut b = copy(&a);
    a.fork(pk(7), base, x, 1);
    b.fork(pk(7), base, y, 2);
    (a, b)
}

#[test]
fn forks_converge_at_the_start_middle_and_tip() {
    for (common, x, y) in [(0, 5, 5), (1, 3, 9), (500, 400, 7), (5000, 300, 100), (99, 1, 1)] {
        let (mut a, mut b) = forked(common, x, y);
        let run = sync(&mut a, &mut b);
        let phase = converged(&run);
        assert!(phase <= 2, "fork at {common}: phase {phase}");
        assert_equal(&a, &b);
        // Probing costs O(log distance) rounds, not O(distance).
        assert!(run.flights <= 16, "fork at {common}: {} flights", run.flights);
        // Afterwards, a forked author costs what an unforked one does.
        a.fork(pk(7), a.index().runs(&pk(7)).first().map(|r| r.head), 1, 3);
        let next = sync_with(&mut a, &mut b, (run.client_record, run.server_record));
        assert_eq!(converged(&next), 1, "fork at {common}: the next session stays in phase 1");
        assert_equal(&a, &b);
    }
}

#[test]
fn a_side_holding_both_branches_places_the_fork_in_phase_1() {
    let (mut a, mut b) = forked(200, 10, 10);
    let mut c = copy(&a);
    let run = sync(&mut c, &mut b); // c now holds both branches
    converged(&run);
    a.append(pk(1), 1, 20);
    let run = sync(&mut c, &mut a);
    assert_eq!(converged(&run), 1);
    assert_equal(&a, &c);
}

#[test]
fn three_way_fork_and_seq_reuse_at_the_tip() {
    let mut a = history(1, 3, 20);
    let base = a.fork(pk(7), None, 50, 0).last().copied();
    let mut b = copy(&a);
    let mut c = copy(&a);
    a.fork(pk(7), base, 3, 1);
    b.fork(pk(7), base, 3, 2);
    c.fork(pk(7), base, 1, 3); // a restored device reusing one seq
    let r1 = sync(&mut a, &mut b);
    assert!(converged(&r1) <= 2);
    let r2 = sync(&mut c, &mut b);
    assert!(converged(&r2) <= 2);
    let r3 = sync(&mut a, &mut c);
    assert!(converged(&r3) <= 2);
    assert_equal(&a, &b);
    assert_equal(&a, &c);
    assert_eq!(a.index().runs(&pk(7)).len(), 3);
}

#[test]
fn an_equivocation_flood_beyond_the_listed_runs_still_converges() {
    let mut a = history(1, 3, 20);
    let base = a.fork(pk(7), None, 10, 0).last().copied();
    for branch in 1..=(MAX_RUNS_INLINE as u32 + 20) {
        a.fork(pk(7), base, 1, branch);
    }
    let mut b = ModelSet::new(space());
    let run = sync(&mut b, &mut a);
    assert!(converged(&run) <= 2);
    assert_equal(&a, &b);
}

// ───────────── concurrency, memory, refusals ─────────────

#[test]
fn items_arriving_during_a_session_do_not_escalate() {
    let mut a = history(5, 200, 100);
    let mut b = copy(&a);
    a.append(pk(1), 50, 100);
    b.append(pk(2), 50, 100);
    let run = run_pair(&mut a, &mut b, (None, None), Config::default(), false, |flight, a, b| {
        // Gossip delivers new items to both sides while they stream.
        if flight < 6 {
            a.append(pk(3), 1, 100);
            b.append(pk(4), 1, 100);
        }
    });
    assert_eq!(converged(&run), 1, "concurrent arrivals stay in phase 1");
    // Each side covers the other's *opening* set; the next session takes the rest.
    let again = sync_with(&mut a, &mut b, (run.client_record, run.server_record));
    assert!(converged(&again) <= 1);
    assert_equal(&a, &b);
}

#[test]
fn sets_that_differ_by_a_refused_item_settle_into_unchanged() {
    let mut a = history(2, 10, 20);
    let mut b = copy(&a);
    let bad = a.append(pk(1), 1, 20)[0];
    b.refuse.insert(bad);
    let run = sync(&mut a, &mut b);
    assert_eq!(converged(&run), 1, "a refused item counts as covered");
    assert!(!b.env_ids().contains(&bad));
    let again = sync_with(&mut a, &mut b, (run.client_record.clone(), run.server_record.clone()));
    assert_eq!(again.client, Outcome::Unchanged);
    assert_eq!(again.flights, 2);
    // The refused item is not offered to that peer again.
    b.append(pk(2), 1, 20);
    let third = sync_with(&mut a, &mut b, (run.client_record, run.server_record));
    converged(&third);
    assert_eq!(third.client_stats.items_out, 0);
}

#[test]
fn a_lost_record_costs_one_full_frontier() {
    let mut a = history(3, 20, 20);
    let mut b = history(3, 10, 20);
    let run = sync(&mut a, &mut b);
    converged(&run);
    a.append(pk(1), 1, 20);
    // The server forgot; the client still names the record.
    let again = sync_with(&mut a, &mut b, (run.client_record, None));
    assert_eq!(converged(&again), 1);
    assert_equal(&a, &b);
}

#[test]
fn a_broken_session_resumes_where_it_stopped() {
    let mut server = history(4, 500, 300);
    let mut client = ModelSet::new(space());
    let cfg = Config { chunk_bytes: 16 * 1024, ..Config::default() };
    // Cut the session after a few flights: what arrived is kept.
    let mut c = Session::open(&client, cfg.clone(), [1; 16], None, false, None);
    let open = match c.poll_send(&client) {
        Some(Msg::Open(o)) => o,
        other => panic!("{other:?}"),
    };
    let mut s = Session::accept(&server, cfg.clone(), open, None);
    for _ in 0..3 {
        let mut to_client = Vec::new();
        while let Some(m) = s.poll_send(&server) {
            to_client.push(m);
        }
        let mut to_server = Vec::new();
        for m in to_client.into_iter().take(4) {
            let items = c.on_msg(&client, m).unwrap();
            let (new, refused) = client.apply(items);
            c.ingested(new, &refused);
        }
        while let Some(m) = c.poll_send(&client) {
            to_server.push(m);
        }
        for m in to_server {
            let items = s.on_msg(&server, m).unwrap();
            let (new, refused) = server.apply(items);
            s.ingested(new, &refused);
        }
    }
    let got = client.env_ids().len();
    assert!(got > 0 && got < 2000, "partial progress: {got}");
    let run = sync(&mut client, &mut server);
    assert_eq!(converged(&run), 1);
    assert_equal(&client, &server);
    assert_eq!(run.client_stats.items_in as usize, 2000 - got, "nothing is sent twice");
}

// ───────────── property tests ─────────────

/// Random histories: authors with chains, forks, and items from authors
/// nobody allows; delivered to random subsets.
fn random_world(seed: u64) -> (ModelSet, HashSet<SignPk>) {
    let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut all = ModelSet::new(space());
    let mut allowed = HashSet::new();
    let authors = 1 + xorshift(&mut rng) % 6;
    for a in 1..=authors as u8 {
        let len = xorshift(&mut rng) % 40;
        let ids = all.fork(pk(a), None, len, 0);
        if a % 5 != 0 {
            allowed.insert(pk(a));
        }
        // Forks (equivocation or seq reuse) at random points.
        for branch in 1..=(xorshift(&mut rng) % 3) as u32 {
            if ids.is_empty() {
                break;
            }
            let at = ids[(xorshift(&mut rng) % ids.len() as u64) as usize];
            all.fork(pk(a), Some(at), 1 + xorshift(&mut rng) % 10, branch);
        }
    }
    for n in 0..xorshift(&mut rng) % 5 {
        let tips = all.op_tips();
        let parent = tips[(xorshift(&mut rng) % tips.len() as u64) as usize];
        all.insert_op(ModelOp { parents: vec![parent], nonce: 100 + n });
    }
    (all, allowed)
}

fn subset(all: &ModelSet, allowed: &HashSet<SignPk>, rng: &mut u64, keep: u64, junk: bool) -> ModelSet {
    let mut s = ModelSet::new(space());
    let (ops, envs) = all.all();
    for op in ops {
        if xorshift(rng) % 100 < keep {
            s.insert_op(op);
        }
    }
    let mut envs: Vec<ModelEnv> = envs
        .into_iter()
        .filter(|e| junk || allowed.contains(&e.author))
        .filter(|_| xorshift(rng) % 100 < keep)
        .collect();
    envs.sort_by_key(|e| (e.author, e.seq));
    for e in envs {
        s.insert_env(e).unwrap();
    }
    s.allowed = Some(allowed.clone());
    s
}

#[test]
fn property_two_replicas_converge_to_the_union_with_authorisation_enforced() {
    for seed in 0..300u64 {
        let (all, allowed) = random_world(seed);
        let mut rng = seed + 17;
        // Every fourth world, side `a` also holds items of authors that
        // nobody may write (an attacker's junk).
        let junk = seed % 4 == 0;
        let mut a = subset(&all, &allowed, &mut rng, 30 + seed % 60, junk);
        let mut b = subset(&all, &allowed, &mut rng, 30 + (seed * 7) % 60, false);
        let b_before = b.env_ids();
        let union: HashSet<_> = a.env_ids().union(&b_before).copied().collect();
        let run = sync(&mut a, &mut b);
        match (&run.client, &run.server) {
            (Outcome::Converged { phase, .. }, Outcome::Converged { .. }) => assert!(*phase <= 2, "seed {seed}"),
            (Outcome::InSync, Outcome::InSync) => {}
            (Outcome::Unconverged { authors, .. }, Outcome::Unconverged { .. }) => {
                assert!(junk, "seed {seed}: honest peers didn't converge");
                assert!(authors.iter().all(|x| !allowed.contains(x)), "seed {seed}: {authors:?}");
            }
            other => panic!("seed {seed}: {other:?}"),
        }
        for id in &union {
            let author = all.envelope(id).unwrap().author;
            if allowed.contains(&author) {
                assert!(a.env_ids().contains(id) && b.env_ids().contains(id), "seed {seed}: allowed item lost");
            } else {
                assert!(!b.env_ids().contains(id), "seed {seed}: unauthorised item admitted");
            }
        }
        // Each side now holds the other's *opening* set; ops that left the
        // pending pool during the session (their parents arrived) go in the
        // next one.
        let mut records = (run.client_record, run.server_record);
        for _ in 0..2 {
            let again = sync_with(&mut a, &mut b, records);
            records = (again.client_record, again.server_record);
        }
        assert_eq!(a.op_ids(), b.op_ids(), "seed {seed}");
        if !junk {
            assert_equal(&a, &b);
            // A converged pair answers the next check in one round trip.
            let again = sync_with(&mut a, &mut b, records);
            assert_eq!(again.client, Outcome::InSync, "seed {seed}");
            assert_eq!(again.flights, 2);
        }
    }
}

#[test]
fn property_pairwise_sessions_among_peers_reach_one_set() {
    for seed in 0..60u64 {
        let (all, _) = random_world(seed);
        let everyone: HashSet<SignPk> = (1..=10).map(pk).collect();
        let mut rng = seed ^ 0xabcdef;
        let n = 3 + (seed % 3) as usize;
        let mut peers: Vec<ModelSet> = (0..n).map(|_| subset(&all, &everyone, &mut rng, 40, false)).collect();
        for _ in 0..(n * n) {
            let i = (xorshift(&mut rng) % n as u64) as usize;
            let j = (xorshift(&mut rng) % n as u64) as usize;
            if i == j {
                continue;
            }
            let (lo, hi) = (i.min(j), i.max(j));
            let (left, right) = peers.split_at_mut(hi);
            let run = sync(&mut left[lo], &mut right[0]);
            assert!(matches!(run.client, Outcome::InSync | Outcome::Converged { .. }), "seed {seed}: {:?}", run.client);
        }
        // A final round-robin pass reaches everyone.
        for _ in 0..2 {
            for i in 0..n - 1 {
                let (left, right) = peers.split_at_mut(i + 1);
                sync(&mut left[i], &mut right[0]);
            }
        }
        for p in &peers[1..] {
            assert_equal(&peers[0], p);
        }
    }
}

// ───────────── the index ─────────────

#[test]
fn incremental_index_matches_a_rebuild_in_any_insertion_order() {
    for seed in 1..80u64 {
        let (all, _) = random_world(seed);
        let (_, mut envs) = all.all();
        let mut rng = seed;
        for i in (1..envs.len()).rev() {
            envs.swap(i, (xorshift(&mut rng) % (i as u64 + 1)) as usize);
        }
        let mut shuffled = ChainIndex::default();
        for e in &envs {
            shuffled.insert(e.id(), e.author, e.seq, e.prev);
        }
        assert_eq!(shuffled.boundary(), all.index().boundary(), "seed {seed}");
        assert_eq!(shuffled.entries(), all.index().entries(), "seed {seed}");
        for e in &envs {
            let id = e.id();
            assert_eq!(shuffled.bottom(&id), all.index().bottom(&id));
            assert!(shuffled.is_ancestor(&id, &id));
            if let Some(p) = e.prev.filter(|p| shuffled.holds(p)) {
                assert!(shuffled.is_ancestor(&p, &id));
                assert!(!shuffled.is_ancestor(&id, &p));
            }
        }
    }
}

#[test]
fn equal_heads_with_different_gaps_have_different_digests() {
    let full = history(1, 10, 10);
    let head = full.index().runs(&pk(1))[0].head;
    let mk = |skip: u64| {
        let mut s = ModelSet::new(space());
        for seq in 0..10 {
            if seq != skip {
                let id = full.index().branch_id_at(&head, seq).unwrap();
                s.insert_env(full.envelope(&id).unwrap().clone()).unwrap();
            }
        }
        s
    };
    let (a, b) = (mk(3), mk(5));
    assert_eq!(a.index().runs(&pk(1))[0].head, b.index().runs(&pk(1))[0].head);
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn the_window_refuses_far_ahead_envelopes_until_the_prefix_arrives() {
    let full = history(1, WINDOW + 10, 1);
    let head = full.index().runs(&pk(1))[0].head;
    let at = |s| full.envelope(&full.index().branch_id_at(&head, s).unwrap()).unwrap().clone();
    let mut s = ModelSet::new(space());
    assert!(s.insert_env(at(WINDOW - 1)).is_ok());
    assert!(s.insert_env(at(WINDOW + 5)).is_err());
    s.insert_env(at(0)).unwrap();
    s.insert_env(at(1)).unwrap();
    assert_eq!(s.index().reach(&pk(1)), 2);
    assert!(s.insert_env(at(WINDOW + 1)).is_ok());
    assert!(s.insert_env(at(WINDOW + 5)).is_err());
    // A session delivers in ascending seq per author: the window never bites.
    let mut empty = ModelSet::new(space());
    let mut full = full;
    let run = sync(&mut empty, &mut full);
    assert_eq!(converged(&run), 1);
    assert_equal(&empty, &full);
}

#[test]
fn fork_point_and_branch_ids_follow_the_right_branch() {
    let mut s = history(1, 1, 1);
    let base = s.fork(pk(7), None, 100, 0);
    let x = s.fork(pk(7), Some(base[40]), 30, 1);
    let y = s.fork(pk(7), Some(base[60]), 5, 2);
    let idx = s.index();
    assert_eq!(idx.fork_point(x.last().unwrap(), y.last().unwrap()), Some(40));
    assert_eq!(idx.fork_point(x.last().unwrap(), base.last().unwrap()), Some(40));
    assert_eq!(idx.fork_point(y.last().unwrap(), base.last().unwrap()), Some(60));
    assert_eq!(idx.branch_id_at(x.last().unwrap(), 41), Some(x[0]));
    assert_eq!(idx.branch_id_at(x.last().unwrap(), 10), Some(base[10]));
    assert_eq!(idx.branch_id_at(y.last().unwrap(), 61), Some(y[0]));
    assert_eq!(idx.branch_ids(y.last().unwrap(), 59, 62), vec![base[59], base[60], y[0], y[1]]);
    assert!(idx.is_ancestor(&base[40], x.last().unwrap()));
    assert!(!idx.is_ancestor(&base[41], x.last().unwrap()));
    assert_eq!(idx.runs(&pk(7)).len(), 3);
}

// ───────────── adversarial peers ─────────────

/// A server session that has just accepted `client`'s open, plus the client.
fn accepted(client: &ModelSet, server: &ModelSet, cfg: Config) -> (Session<ModelSet>, Session<ModelSet>) {
    let mut c = Session::open(client, cfg.clone(), [1; 16], None, true, None);
    let Some(Msg::Open(open)) = c.poll_send(client) else { panic!("open") };
    let s = Session::accept(server, cfg, open, None);
    (c, s)
}

#[test]
fn malformed_and_out_of_order_frames_are_refused() {
    let a = history(2, 10, 10);
    let b = history(2, 5, 10);
    let run = |msgs: Vec<Msg<ModelOp, ModelEnv>>| {
        let (_, mut s) = accepted(&a, &b, Config::default());
        let mut res = Ok(());
        for m in msgs {
            if let Err(e) = s.on_msg(&b, m) {
                res = Err(e);
                break;
            }
        }
        res
    };
    let probe = |n: usize| Msg::Probe { author: pk(1), run: Hash32([1; 32]), points: vec![(0, Hash32([2; 32])); n] };
    assert!(run(vec![probe(3)]).is_err(), "probe outside phase 2");
    assert!(run(vec![Msg::SendsDone { phase: 1 }, Msg::SendsDone { phase: 1 }]).is_err(), "duplicate SendsDone");
    assert!(run(vec![Msg::SendsDone { phase: 2 }]).is_err(), "wrong phase");
    assert!(
        run(vec![Msg::ProbeReply { author: pk(1), run: Hash32([1; 32]), held: 1, bottoms: vec![0] }]).is_err(),
        "unasked reply"
    );
    assert!(run(vec![Msg::Status(Verdict::Denied)]).is_err(), "status to a server");
    let close = |n: usize| Msg::Close {
        phase: 1,
        coverage: Coverage::All,
        refused: vec![Hash32([0; 32]); n],
        digest: [0; 32],
        quiet: true,
        phase2: true,
    };
    assert!(run(vec![close(65)]).is_err(), "too many refused ids");
    assert!(run(vec![close(1), close(1)]).is_err(), "duplicate Close");
    // Frontier abuse, on a server that asked for the full frontier.
    let fresh = ModelSet::new(space());
    let bad_entry = |runs: Vec<Run>| AuthorEntry { author: pk(1), runs, truncated: false };
    for (what, entry) in [
        ("too many runs", bad_entry(vec![Run { top: 1, head: Hash32([3; 32]), bottom: 0 }; MAX_RUNS_INLINE + 1])),
        ("bottom above top", bad_entry(vec![Run { top: 1, head: Hash32([3; 32]), bottom: 5 }])),
        ("no runs", bad_entry(Vec::new())),
    ] {
        let mut c = Session::open(&fresh, Config::default(), [1; 16], None, false, None);
        let Some(Msg::Open(open)) = c.poll_send(&fresh) else { panic!() };
        let mut s = Session::accept(&b, Config::default(), open, None);
        let f = Frontier { delta_of: None, ops: Some(vec![]), authors: vec![entry], more: false };
        assert!(s.on_msg(&b, Msg::Frontier(f)).is_err(), "{what}");
    }
    // A client must not get data before its Status.
    let mut c = Session::open(&fresh, Config::default(), [1; 16], None, false, None);
    let _ = c.poll_send(&fresh);
    assert!(c.on_msg(&fresh, Msg::Chunk(vec![])).is_err());
}

#[test]
fn oversized_frontiers_and_data_floods_hit_limits() {
    let a = ModelSet::new(space());
    let b = history(1, 3, 10);
    let cfg = Config { max_frontier_authors: 300, recv_budget: 10_000, ..Config::default() };
    let mut c = Session::open(&a, cfg.clone(), [1; 16], None, false, None);
    let Some(Msg::Open(open)) = c.poll_send(&a) else { panic!() };
    let mut s = Session::accept(&b, cfg.clone(), open, None);
    let entry = |i: u32| {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_le_bytes());
        AuthorEntry { author: SignPk(k), runs: vec![Run { top: 0, head: Hash32(k), bottom: 0 }], truncated: false }
    };
    let chunk = |from: u32, more: bool| Frontier {
        delta_of: None,
        ops: if from == 0 { Some(vec![]) } else { None },
        authors: (from..from + 200).map(entry).collect(),
        more,
    };
    s.on_msg(&b, Msg::Frontier(chunk(0, true))).unwrap();
    assert_eq!(s.on_msg(&b, Msg::Frontier(chunk(200, true))).err(), Some(SessionError::Limit("frontier authors")));
    // Data beyond the receive budget.
    let (_, mut s) = accepted(&a, &b, cfg);
    let env = ModelEnv { author: pk(1), seq: 0, prev: None, branch: 0, body: vec![0; 4000] };
    let mut res = Ok(Received::default());
    for _ in 0..4 {
        res = s.on_msg(&b, Msg::Chunk(vec![env.clone()]));
    }
    assert_eq!(res.err(), Some(SessionError::Limit("received data")));
}

#[test]
fn probe_floods_are_bounded() {
    let (mut a, mut b) = forked(100, 10, 10);
    let cfg = Config { max_probe_runs: 2, max_probe_rounds: 2, ..Config::default() };
    // Drive a real session into phase 2, then flood probes.
    let mut c = Session::open(&a, cfg.clone(), [1; 16], None, true, None);
    let Some(Msg::Open(open)) = c.poll_send(&a) else { panic!() };
    let mut s = Session::accept(&b, cfg, open, None);
    for _ in 0..20 {
        let mut to_c = Vec::new();
        while let Some(m) = s.poll_send(&b) {
            to_c.push(m);
        }
        for m in to_c {
            let items = c.on_msg(&a, m).unwrap();
            let (n, r) = a.apply(items);
            c.ingested(n, &r);
        }
        let mut to_s = Vec::new();
        while let Some(m) = c.poll_send(&a) {
            to_s.push(m);
        }
        for m in to_s {
            let items = s.on_msg(&b, m).unwrap();
            let (n, r) = b.apply(items);
            s.ingested(n, &r);
        }
        if s.stats().phase == 2 {
            break;
        }
    }
    assert_eq!(s.stats().phase, 2);
    let probe = Msg::Probe { author: pk(7), run: Hash32([1; 32]), points: vec![(0, Hash32([2; 32])); 16] };
    let mut errors = 0;
    for _ in 0..20 {
        if s.on_msg(&b, probe.clone()).is_err() {
            errors += 1;
        }
    }
    assert!(errors > 0, "probe flood never refused");
    let too_many = Msg::Probe { author: pk(7), run: Hash32([1; 32]), points: vec![(0, Hash32([2; 32])); 17] };
    assert!(s.on_msg(&b, too_many).is_err());
}

#[test]
fn a_peer_lying_about_its_frontier_only_hurts_itself() {
    // Claims to hold more (a head it doesn't have): it receives less, the
    // honest side loses nothing and does bounded work.
    let mut honest = history(2, 20, 10);
    let liar = history(2, 5, 10);
    let mut c = Session::open(&liar, Config::default(), [1; 16], None, false, None);
    let Some(Msg::Open(mut open)) = c.poll_send(&liar) else { panic!() };
    let mut entries = (*honest.summary().authors).clone();
    for e in entries.values_mut() {
        e.runs[0].top += 1000;
        e.runs[0].head = Hash32([0xee; 32]);
    }
    open.frontier = Some(Frontier {
        delta_of: None,
        ops: Some(honest.op_tips()),
        authors: entries.into_values().collect(),
        more: false,
    });
    let before = honest.env_ids();
    let mut s = Session::accept(&honest, Config { max_probe_runs: 4, ..Config::default() }, open, None);
    let mut frames = 0;
    while let Some(m) = s.poll_send(&honest) {
        frames += 1;
        assert!(!matches!(m, Msg::Chunk(_)), "nothing is sent to a peer claiming to be ahead");
    }
    assert!(frames < 10);
    // A lying Close (Missing for everything) leads to bounded phase 2 then Unconverged.
    s.on_msg(&honest, Msg::SendsDone { phase: 1 }).unwrap();
    let lie = Msg::Close {
        phase: 1,
        coverage: Coverage::Missing { ops: true, authors: vec![pk(1), pk(2)] },
        refused: vec![],
        digest: [0; 32],
        quiet: true,
        phase2: true,
    };
    s.on_msg(&honest, lie).unwrap();
    let mut probes = 0;
    while let Some(m) = s.poll_send(&honest) {
        if matches!(m, Msg::Probe { .. }) {
            probes += 1;
        }
    }
    assert!(probes <= 4, "{probes} probes");
    let _ = honest.apply(Received::default());
    assert_eq!(honest.env_ids(), before);
}

#[test]
fn the_send_budget_aborts_the_session_and_progress_is_kept() {
    let mut server = history(2, 300, 1000);
    let mut client = ModelSet::new(space());
    let cfg = Config { send_budget: 100_000, chunk_bytes: 16 * 1024, ..Config::default() };
    let run = run_pair(&mut client, &mut server, (None, None), cfg, false, |_, _, _| {});
    assert!(matches!(run.server, Outcome::Aborted { reason: AbortReason::Budget, by_peer: false }), "{:?}", run.server);
    assert!(matches!(run.client, Outcome::Aborted { reason: AbortReason::Budget, by_peer: true }), "{:?}", run.client);
    let got = client.env_ids().len();
    assert!(got > 50 && got < 600, "{got}");
    assert!(run.server_stats.sent_data_bytes < 140_000);
}

#[test]
fn version_and_feature_mismatches_are_refused_explicitly() {
    let a = history(1, 2, 2);
    let mut c = Session::open(&a, Config::default(), [1; 16], None, false, None);
    let Some(Msg::Open(mut open)) = c.poll_send(&a) else { panic!() };
    open.version = 2;
    let mut s = Session::accept(&a, Config::default(), open.clone(), None);
    assert!(matches!(s.poll_send(&a), Some(Msg::Status(Verdict::Unsupported { version: 1, .. }))));
    open.version = 1;
    open.features = 1 << 5;
    let mut s = Session::accept(&a, Config::default(), open, None);
    assert!(matches!(s.poll_send(&a), Some(Msg::Status(Verdict::Unsupported { .. }))));
    // The client reports the refusal (the driver decides about fallback).
    c.on_msg(&a, Msg::Status(Verdict::Busy { retry_after_ms: 500 })).unwrap();
    assert_eq!(c.outcome(), Some(&Outcome::Refused(Refusal::Busy { retry_after_ms: 500 })));
}

#[test]
fn proportional_round_robin_interleaves_authors() {
    let mut server = ModelSet::new(space());
    server.append(pk(1), 100, 50);
    server.append(pk(2), 10, 50);
    let client = ModelSet::new(space());
    let mut c = Session::open(&client, Config::default(), [1; 16], None, true, None);
    let Some(Msg::Open(open)) = c.poll_send(&client) else { panic!() };
    let mut s = Session::accept(&server, Config::default(), open, None);
    let mut order = Vec::new();
    while let Some(m) = s.poll_send(&server) {
        if let Msg::Chunk(envs) = m {
            order.extend(envs.into_iter().map(|e| (e.author, e.seq)));
        }
    }
    assert_eq!(order.len(), 110);
    // Per author ascending.
    for a in [pk(1), pk(2)] {
        let seqs: Vec<u64> = order.iter().filter(|(x, _)| *x == a).map(|(_, s)| *s).collect();
        assert!(seqs.windows(2).all(|w| w[0] + 1 == w[1]));
    }
    // Author 2's ten envelopes are spread over the stream, not bunched.
    let first_half = order[..55].iter().filter(|(a, _)| *a == pk(2)).count();
    assert!((4..=6).contains(&first_half), "{first_half}");
}

// ───────────── real replicas ─────────────

mod replicas {
    use std::collections::HashSet;
    use std::sync::Arc;

    use mycel_crypto::DeviceKeys;
    use mycel_trust::Role;

    use super::super::model::*;
    use super::super::*;
    use super::converged;
    use crate::{Envelope, FeedEntry, Replica, StreamId, encode};

    fn dev() -> Arc<DeviceKeys> {
        Arc::new(DeviceKeys::generate())
    }

    fn rsync(a: &mut Replica, b: &mut Replica) -> PairRun {
        run_pair(a, b, (None, None), Config::default(), false, |_, _, _| {})
    }

    fn ids(r: &Replica) -> HashSet<EnvelopeId> {
        r.envelope_ids().into_iter().collect()
    }

    /// A founder, a writer and a reader, each with their own replica, all
    /// knowing the membership.
    fn group() -> (Replica, Replica, Replica) {
        let (mut a, genesis) = Replica::create(dev(), None).unwrap();
        let (wk, rk) = (dev(), dev());
        a.add_member(wk.public(), Role::Writer).unwrap();
        a.add_member(rk.public(), Role::Reader).unwrap();
        let mut w = Replica::join(wk, genesis.clone(), None).unwrap();
        let mut r = Replica::join(rk, genesis, None).unwrap();
        w.ingest_batch(a.all_ops(), vec![]);
        r.ingest_batch(a.all_ops(), vec![]);
        (a, w, r)
    }

    #[test]
    fn replicas_converge_and_every_item_is_still_validated() {
        let (mut a, mut w, mut r) = group();
        let feed = StreamId::named(crate::StreamKind::Feed, "chat");
        for i in 0..20u8 {
            a.append(feed, vec![i]).unwrap();
            w.append(feed, vec![100 + i]).unwrap();
        }
        // A reader's write is signed and stored, but invalid everywhere.
        let bad = r.append(feed, b"reader".to_vec()).unwrap().1;
        let run = rsync(&mut a, &mut w);
        assert_eq!(converged(&run), 1);
        let run = rsync(&mut r, &mut a);
        assert!(converged(&run) <= 2);
        let run = rsync(&mut w, &mut r);
        assert!(converged(&run) <= 2);
        assert_eq!(ids(&a), ids(&w));
        assert_eq!(ids(&a), ids(&r));
        assert_eq!(a.feed(&feed), w.feed(&feed));
        assert_eq!(a.feed_len(&feed), 40);
        assert!(matches!(w.status(&bad.id()), crate::Status::Invalid(_)));
        assert_eq!(a.digest(), w.digest());
        // Idle: one round trip.
        let again = rsync(&mut a, &mut w);
        assert_eq!(again.client, Outcome::InSync);
        assert_eq!(again.flights, 2);
    }

    #[test]
    fn forged_and_outsider_items_in_a_chunk_are_refused() {
        let (mut a, mut w, _) = group();
        let feed = StreamId::named(crate::StreamKind::Feed, "chat");
        let good = a.append(feed, b"hello".to_vec()).unwrap().1;
        let mut tampered = good.clone();
        tampered.ciphertext[0] ^= 1;
        let (mut eve, _) = Replica::create(dev(), None).unwrap();
        let outsider = eve.append(feed, b"spam".to_vec()).unwrap().1;
        let mut c = Session::open(&w, Config::default(), [1; 16], None, true, None);
        let Some(Msg::Open(open)) = c.poll_send(&w) else { panic!() };
        let mut s = Session::accept(&a, Config::default(), open, None);
        while let Some(m) = s.poll_send(&a) {
            if let Ok(items) = c.on_msg(&w, m) {
                let (n, refused) = w.apply(items);
                c.ingested(n, &refused);
            }
        }
        // A malicious server appends forged items to an honest stream.
        let forged = c.on_msg(&w, Msg::Chunk(vec![tampered.clone(), outsider.clone()]));
        let (n, refused) = w.apply(forged.unwrap_or_default());
        assert_eq!(n, 0);
        assert!(refused.contains(&tampered.id()), "a bad signature is refused for good");
        assert!(!w.has_envelope(&tampered.id()) && !w.has_envelope(&outsider.id()));
        assert!(w.has_envelope(&good.id()));
    }

    #[test]
    fn equivocating_author_branches_reach_every_peer() {
        let (mut a, mut w, reader) = group();
        let feed = StreamId::named(crate::StreamKind::Feed, "chat");
        for i in 0..5u8 {
            w.append(feed, vec![i]).unwrap();
        }
        let run = rsync(&mut a, &mut w);
        converged(&run);
        // The writer signs two different envelopes at the next seq (a
        // restored device, or an attacker) and gives one to each peer.
        let epoch = w.graph.state().write_epoch().unwrap();
        let (seq, prev) = w.my_chain_tip();
        let fork = |body: &[u8]| -> Envelope {
            let entry = FeedEntry { deps: vec![], ts_ms: 1, body: body.to_vec() };
            w.seal_at(feed, epoch, &encode(&entry), seq, prev).unwrap()
        };
        let (e1, e2) = (fork(b"one"), fork(b"two"));
        let mut b = reader;
        b.ingest_batch(a.all_ops(), a.envelope_ids().iter().map(|i| a.envelope(i).unwrap().clone()).collect());
        a.ingest_envelope(e1.clone()).unwrap();
        b.ingest_envelope(e2.clone()).unwrap();
        let run = rsync(&mut a, &mut b);
        assert!(converged(&run) <= 2);
        assert!(a.has_envelope(&e2.id()) && b.has_envelope(&e1.id()));
        assert_eq!(ids(&a), ids(&b));
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.feed(&feed), b.feed(&feed), "documents agree");
    }
}

// ───────────── benchmarks ─────────────

mod bench {
    use std::time::Instant;

    use mycel_crypto::{Hash32, SignPk};
    use serde::Serialize;

    use super::super::model::*;
    use super::super::*;
    use super::{copy, pk, space, sync_with};

    /// v1's sync messages (mycel-net `wire::SyncMsg`), mirrored field for
    /// field so postcard sizes are exact: variant tags, length prefixes, ids.
    #[derive(Serialize)]
    struct Inv {
        ops: Vec<Hash32>,
        envelopes: Vec<Hash32>,
    }

    #[derive(Serialize)]
    struct Data<'a> {
        ops: Vec<&'a ModelOp>,
        envelopes: Vec<&'a ModelEnv>,
    }

    #[allow(dead_code)]
    #[derive(Serialize)]
    enum V1<'a> {
        Hello { space: Hash32, inv: Inv, invite: Option<Vec<ModelOp>> },
        Denied,
        Removed { ops: Vec<ModelOp> },
        NeedInvite,
        Accept { inv: Inv, want: Inv },
        DataAndWant { data: Data<'a>, want: Inv },
        Data { data: Data<'a> },
    }

    fn inv(s: &ModelSet) -> Inv {
        Inv { ops: s.op_ids().into_iter().collect(), envelopes: s.env_ids().into_iter().collect() }
    }

    fn want(of: &ModelSet, from: &ModelSet) -> Inv {
        let (have_ops, have_envs) = (of.op_ids(), of.env_ids());
        Inv {
            ops: from.op_ids().into_iter().filter(|i| !have_ops.contains(i)).collect(),
            envelopes: from.env_ids().into_iter().filter(|i| !have_envs.contains(i)).collect(),
        }
    }

    fn data<'a>(s: &'a ModelSet, w: &Inv) -> Data<'a> {
        Data { ops: Vec::new(), envelopes: w.envelopes.iter().filter_map(|id| s.envelope(id)).collect() }
    }

    /// Bytes of one v1 session (client, server): Hello, Accept, DataAndWant, Data.
    fn v1_bytes(client: &ModelSet, server: &ModelSet) -> u64 {
        let c_want = want(client, server);
        let s_want = want(server, client);
        let msgs = [
            frame_len(&V1::Hello { space: space(), inv: inv(client), invite: None }),
            frame_len(&V1::Accept { inv: inv(server), want: want(server, client) }),
            frame_len(&V1::DataAndWant { data: data(client, &s_want), want: want(client, server) }),
            frame_len(&V1::Data { data: data(server, &c_want) }),
        ];
        msgs.iter().sum::<usize>() as u64
    }

    /// A model envelope body that makes an envelope encode to ~351 bytes,
    /// the measured mean of a chat envelope.
    fn body_for_351() -> usize {
        let probe = ModelEnv { author: pk(1), seq: 5000, prev: Some(Hash32([1; 32])), branch: 0, body: vec![0; 279] };
        279 + 351 - encoded_len(&probe).min(351)
    }

    fn world(authors: u32, per: u64) -> ModelSet {
        let body = body_for_351();
        let mut s = ModelSet::new(space());
        for a in 0..authors {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&a.to_le_bytes());
            s.append(SignPk(k), per, body);
        }
        s
    }

    fn author(a: u32) -> SignPk {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&a.to_le_bytes());
        SignPk(k)
    }

    fn row(name: &str, v1: u64, run: &PairRun, took: std::time::Duration) {
        let data = run.client_stats.sent_data_bytes + run.server_stats.sent_data_bytes;
        let control = run.bytes() - data;
        println!(
            "| {name} | {v1} B, 2 RTT | {} B ({} control + {} data), {} RTT, first data after {} | {:?} | {:.1?} |",
            run.bytes(),
            control,
            data,
            run.round_trips(),
            run.first_data_flight.map_or("-".to_string(), |f| format!("{:.1} RTT", f as f64 / 2.0)),
            (&run.client, run.client_stats.phase),
            took,
        );
    }

    /// `cargo test --release -p mycel-sync bench_sync_v2 -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_sync_v2() {
        const AUTHORS: u32 = 50;
        println!("envelope size: {} B", encoded_len(&world(1, 1).all().1[0]));
        println!("| scenario | v1 | v2 | v2 outcome | v2 CPU (both sides) |");
        println!("|---|---|---|---|---|");
        let server = world(AUTHORS, 200); // 10k envelopes
        // Idle, first contact (no record) and steady state (record).
        let mut s = copy(&server);
        let mut c = copy(&server);
        let v1 = v1_bytes(&c, &s);
        let t = Instant::now();
        let run = sync_with(&mut c, &mut s, (None, None));
        row("idle, 10k envelopes", v1, &run, t.elapsed());
        let records = (run.client_record.clone(), run.server_record.clone());
        // One new envelope (steady state: both remember the last session).
        c.append(author(7), 1, body_for_351());
        let v1 = v1_bytes(&c, &s);
        let t = Instant::now();
        let run = sync_with(&mut c, &mut s, records);
        row("1 new envelope, record", v1, &run, t.elapsed());
        // One new envelope, first contact (full 50-author frontier).
        let mut c2 = copy(&server);
        let mut s2 = copy(&server);
        c2.append(author(7), 1, body_for_351());
        let v1 = v1_bytes(&c2, &s2);
        let t = Instant::now();
        let run = sync_with(&mut c2, &mut s2, (None, None));
        row("1 new envelope, first contact", v1, &run, t.elapsed());
        // 1k missing: back online after 1,000 messages (20 per author).
        let mut c3 = copy(&server);
        let mut s3 = copy(&server);
        let rec = sync_with(&mut c3, &mut s3, (None, None));
        for a in 0..AUTHORS {
            s3.append(author(a), 20, body_for_351());
        }
        let v1 = v1_bytes(&c3, &s3);
        let t = Instant::now();
        let run = sync_with(&mut c3, &mut s3, (rec.client_record, rec.server_record));
        row("1k missing (of 11k), record", v1, &run, t.elapsed());
        let mut c4 = copy(&server);
        let mut s4 = copy(&s3);
        let v1 = v1_bytes(&c4, &s4);
        let t = Instant::now();
        let run = sync_with(&mut c4, &mut s4, (None, None));
        row("1k missing (of 11k), first contact", v1, &run, t.elapsed());
        // Fresh join of 100k envelopes.
        let mut big = world(AUTHORS, 2000);
        let mut fresh = ModelSet::new(space());
        let v1 = v1_bytes(&fresh, &big);
        let t = Instant::now();
        let run = sync_with(&mut fresh, &mut big, (None, None));
        row("fresh join, 100k envelopes", v1, &run, t.elapsed());
        assert_eq!(fresh.env_ids().len(), 100_000);
        println!(
            "fresh join over 40 kB/s Bluetooth (estimate from bytes): v1 {:.0} s with nothing usable until the end; v2 {:.0} s, first 64 KiB chunk after {:.1} s",
            v1 as f64 / 40_000.0,
            run.bytes() as f64 / 40_000.0,
            (CHUNK_BYTES as f64) / 40_000.0
        );
        // Fork repair: fork at seq 5,000; one side 5,000 more on its branch,
        // the other 100 on its own.
        let mut a = world(2, 10);
        let base = a.fork(author(99), None, 5000, 0).last().copied();
        let mut b = copy(&a);
        let rec = sync_with(&mut a, &mut b, (None, None));
        a.fork(author(99), base, 5000, 1);
        b.fork(author(99), base, 100, 2);
        let v1 = v1_bytes(&a, &b);
        let t = Instant::now();
        let run = sync_with(&mut a, &mut b, (rec.client_record, rec.server_record));
        row("fork at 5,000 (+5,000 vs +100)", v1, &run, t.elapsed());
        println!("probes sent: {} + {}", run.client_stats.probes_sent, run.server_stats.probes_sent);
        // Index and digest costs at scale.
        let t = Instant::now();
        let big = world(AUTHORS, 2000);
        println!("build 100k-envelope model set (index maintained on insert): {:.1?}", t.elapsed());
        let t = Instant::now();
        let d = big.digest();
        println!("digest of 100k envelopes / 50 authors, cold: {:.1?}", t.elapsed());
        let t = Instant::now();
        assert_eq!(big.digest(), d);
        println!("digest, cached: {:.1?}", t.elapsed());
    }
}
