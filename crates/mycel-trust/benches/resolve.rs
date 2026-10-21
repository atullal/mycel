//! Membership resolution cost, incremental resolver against the from-scratch
//! oracle (TRUST.md §5, BENCHMARKS.md §7).
//!
//! `cargo bench -p mycel-trust --features oracle --bench resolve --profile replay -- [sizes] [--oracle-max N] [--oracle-storm-max N]`
//!
//! Two histories, each built live by inserting one op at a time into a
//! `SpaceGraph`, the way ops arrive in production:
//!
//! - **linear**: one admin's run of rotations, each on the previous op.
//! - **storm**: rounds of a revocation cycle. Four admins each remove the
//!   next one concurrently (a removes b, b removes c, c removes d, d removes
//!   a), a fifth member rotates concurrently, then a surviving admin re-adds
//!   whoever was removed and the next round starts. Every round has several
//!   winners, losers and ops invalidated by a concurrent revocation, and
//!   leaves dead ends nobody builds on. (No winner fails authorization
//!   here, so the winners loop runs once; repeated rounds are covered by the
//!   differential tests.)
//!
//! Reported per history size: mean and worst `insert` time over the whole
//! build and over its last 10%; the signature check inside `insert`, measured
//! separately so the resolution share is visible; one bulk `insert_many` of
//! the whole history into a fresh graph (a new member's first sync); and the
//! heap the graph holds, with the peak during the build. "Before" is the
//! oracle: one `resolve_full` of the same ops is what every insert cost
//! before the incremental resolver (it rebuilt everything), and its peak heap
//! on top of the ops. The oracle is skipped above `--oracle-max` ops for the
//! linear history and `--oracle-storm-max` for the storm (default 10,000
//! each): it is O(n²) in memory, and in time for the storm.
//!
//! Lockboxes are dummies: resolution checks who they are for, never opens
//! them, and real HPKE sealing would only slow the history generation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mycel_crypto::{DeviceKeys, Hash32, Lockbox, SignPk};
use mycel_trust::oracle::resolve_full;
use mycel_trust::{Action, EpochId, Op, OpId, Revocation, Role, Rotation, SignedOp, SpaceGraph};

/// Counts live heap bytes and their peak.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator, only counting sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            grew(new - l.size());
        } else {
            LIVE.fetch_sub(l.size() - new, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn reset_peak() -> usize {
    let l = live();
    PEAK.store(l, Ordering::Relaxed);
    l
}

fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

struct Gen {
    keys: Vec<DeviceKeys>,
    g: SpaceGraph,
    genesis: SignedOp,
    ops: Vec<SignedOp>,
    nonce: u64,
    insert: Vec<Duration>,
    peak: usize,
}

impl Gen {
    fn new(members: usize) -> Self {
        let keys: Vec<DeviceKeys> = (0..members).map(|i| DeviceKeys::from_seed([i as u8 + 1; 32])).collect();
        let (g, genesis, _, _) = SpaceGraph::create(&keys[0]).unwrap();
        Gen { keys, g, genesis, ops: Vec::new(), nonce: 0, insert: Vec::new(), peak: 0 }
    }

    fn pk(&self, i: usize) -> SignPk {
        self.keys[i].sign_pk()
    }

    fn sign(&mut self, author: usize, parents: Vec<OpId>, action: Action) -> SignedOp {
        self.nonce += 1;
        let op = Op { space: Some(self.g.space_id()), parents, author: self.pk(author), nonce: self.nonce, action };
        SignedOp::sign(&self.keys[author], op)
    }

    fn rotation(&mut self, recipients: BTreeSet<SignPk>) -> Rotation {
        self.nonce += 1;
        let commitment = Hash32::digest("mycel/bench/commitment", &self.nonce.to_le_bytes());
        Rotation {
            epoch: EpochId::for_commitment(&commitment),
            commitment,
            lockboxes: recipients.into_iter().map(|pk| (pk, Lockbox { enc: vec![0; 32], ct: vec![0; 48] })).collect(),
        }
    }

    fn add(&mut self, author: usize, member: usize, role: Role) -> SignedOp {
        let keyring = role.can_read().then(|| Lockbox { enc: vec![0; 32], ct: vec![0; 64] });
        let action = Action::Add { member: self.keys[member].public(), role, keyring };
        self.sign(author, self.g.heads(), action)
    }

    fn insert(&mut self, op: SignedOp) {
        let t = Instant::now();
        self.g.insert(op.clone()).unwrap();
        self.insert.push(t.elapsed());
        self.peak = self.peak.max(peak());
        self.ops.push(op);
    }

    fn admins(&self) -> Vec<usize> {
        let st = self.g.state();
        (0..self.keys.len()).filter(|&i| st.role(&self.pk(i)).is_some_and(Role::is_admin)).collect()
    }
}

fn linear(n: usize) -> Gen {
    let mut gen_ = Gen::new(4);
    for (m, role) in [(1, Role::Admin), (2, Role::Writer), (3, Role::Reader)] {
        let op = gen_.add(0, m, role);
        gen_.insert(op);
    }
    while gen_.ops.len() + 1 < n {
        let readers = gen_.g.state().readers();
        let rotation = gen_.rotation(readers);
        let op = gen_.sign(0, gen_.g.heads(), Action::Rotate { rotation });
        gen_.insert(op);
    }
    gen_
}

fn storm(n: usize) -> Gen {
    const MEMBERS: usize = 12;
    let mut gen_ = Gen::new(MEMBERS);
    for m in 1..MEMBERS {
        let op = gen_.add(0, m, Role::Admin);
        gen_.insert(op);
    }
    let mut round = 0usize;
    while gen_.ops.len() + 1 < n {
        let admins = gen_.admins();
        let heads = gen_.g.heads();
        let readers = gen_.g.state().readers();
        // Four admins in a removal cycle, offset each round (never all of
        // them, so a remover always survives), plus a concurrent rotation.
        let k = admins.len();
        let ring: Vec<usize> = (0..4).map(|j| admins[(round + j * 2) % k]).collect();
        let mut batch = Vec::new();
        for j in 0..4 {
            let (a, m) = (ring[j], ring[(j + 1) % 4]);
            if a == m {
                continue;
            }
            let mut rest = readers.clone();
            rest.remove(&gen_.pk(m));
            let rotation = gen_.rotation(rest);
            let action = Action::Remove { member: gen_.pk(m), revocation: Revocation { cutoff: None }, rotation };
            batch.push(gen_.sign(a, heads.clone(), action));
        }
        let rotator = admins[(round + 1) % k];
        let rotation = gen_.rotation(readers);
        batch.push(gen_.sign(rotator, heads.clone(), Action::Rotate { rotation }));
        for op in batch {
            gen_.insert(op);
        }
        // A surviving admin re-adds everyone removed.
        let back = gen_.admins()[0];
        let gone: Vec<usize> = (0..MEMBERS).filter(|&m| gen_.g.state().role(&gen_.pk(m)).is_none()).collect();
        for m in gone {
            if gen_.ops.len() + 1 < n {
                let op = gen_.add(back, m, Role::Admin);
                gen_.insert(op);
            }
        }
        round += 1;
    }
    gen_
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn mib(b: usize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn report(name: &str, n: usize, oracle_max: usize, oracle_storm_max: usize) {
    let oracle_max = if name == "linear" { oracle_max } else { oracle_storm_max };
    let base = reset_peak();
    let build = Instant::now();
    let mut gen_ = if name == "linear" { linear(n) } else { storm(n) };
    let build = build.elapsed();
    let held = live() - base;
    let peak_build = gen_.peak - base;
    let total = gen_.ops.len() + 1;
    // The ops themselves, as the graph stores them, and the bench's own
    // copy (inside `held` too): what is left is the resolver's bookkeeping
    // and the membership state.
    let before = live();
    let copy: HashMap<OpId, SignedOp> = gen_.ops.iter().map(|op| (op.id(), op.clone())).collect();
    let ops_heap = live() - before;
    drop(copy);
    let before = live();
    let list = gen_.ops.clone();
    let list_heap = live() - before + (gen_.ops.capacity() - gen_.ops.len()) * std::mem::size_of::<SignedOp>();
    drop(list);
    let graph = held - list_heap;

    let ins = &gen_.insert;
    let mean = |s: &[Duration]| us(s.iter().sum::<Duration>()) / s.len() as f64;
    let tail = &ins[ins.len() * 9 / 10..];
    let worst_tail = tail.iter().max().copied().unwrap_or_default();

    // The signature check `insert` does first, alone.
    let t = Instant::now();
    for op in &gen_.ops {
        op.verify_standalone().unwrap();
    }
    let verify = us(t.elapsed()) / gen_.ops.len() as f64;

    // A new member's first sync: the whole history in one call.
    let mut fresh = SpaceGraph::from_genesis(gen_.genesis.clone()).unwrap();
    let t = Instant::now();
    let (added, rejected) = fresh.insert_many(gen_.ops.iter().cloned());
    let bulk = t.elapsed();
    assert_eq!((added.len(), rejected), (gen_.ops.len(), 0));
    assert_eq!(fresh.state(), gen_.g.state());

    let valid = gen_.g.resolution().order.iter().filter(|id| gen_.g.is_valid(id)).count();
    let winners = gen_.g.resolution().winners().len();
    eprintln!("{name} n={total}: rounds kept {}; {}", gen_.g.resolution().rounds(), gen_.g.resolution().debug_sizes());
    println!(
        "{name} n={total}: valid {valid}, winners {winners}; build {:.2} s; insert mean {:.1} us (last 10%: mean {:.1} us, worst {:.1} us), of which signature check {:.1} us; bulk insert_many {:.1} ms ({:.1} us/op); graph heap {:.1} MiB (ops {:.1} MiB, the rest {:.1} MiB), peak during build {:.1} MiB",
        build.as_secs_f64(),
        mean(ins),
        mean(tail),
        us(worst_tail),
        verify,
        bulk.as_secs_f64() * 1e3,
        us(bulk) / total as f64,
        mib(graph),
        mib(ops_heap),
        mib(graph - ops_heap),
        mib(peak_build - list_heap),
    );
    drop(fresh);

    if total <= oracle_max {
        let mut ops: HashMap<OpId, SignedOp> = gen_.ops.drain(..).map(|op| (op.id(), op)).collect();
        ops.insert(gen_.genesis.id(), gen_.genesis.clone());
        let reps = if total <= 2_000 { 5 } else { 1 };
        let base = reset_peak();
        let t = Instant::now();
        let mut full = None;
        for _ in 0..reps {
            full = Some(resolve_full(&ops));
        }
        let per = t.elapsed() / reps;
        let full = full.unwrap();
        assert_eq!(&full.state, gen_.g.state(), "oracle and incremental agree");
        println!(
            "{name} n={total}: before (resolve_full per insert) {:.1} ms; peak heap of one resolution {:.1} MiB",
            per.as_secs_f64() * 1e3,
            mib(peak() - base),
        );
    }
}

fn main() {
    let mut sizes = Vec::new();
    let mut oracle_max = 10_000;
    let mut oracle_storm_max = 10_000;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--oracle-max" => oracle_max = args.next().and_then(|v| v.parse().ok()).expect("--oracle-max N"),
            "--oracle-storm-max" => {
                oracle_storm_max = args.next().and_then(|v| v.parse().ok()).expect("--oracle-storm-max N")
            }
            "--bench" => {}
            s => sizes.push(s.parse::<usize>().expect("history sizes in ops")),
        }
    }
    if sizes.is_empty() {
        sizes = vec![1_000, 10_000, 100_000];
    }
    for &n in &sizes {
        for name in ["linear", "storm"] {
            report(name, n, oracle_max, oracle_storm_max);
        }
    }
}
