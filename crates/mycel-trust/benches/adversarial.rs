//! Membership resolution under adversarial and lagging histories (TRUST.md
//! §5 and §10, BENCHMARKS.md §7).
//!
//! `cargo bench -p mycel-trust --features oracle --bench adversarial --profile replay -- [ops] [leaves]`
//!
//! Each scenario starts from one admin's linear history of `ops` rotations
//! (default 10,000) in which the founder added member 1 as an admin and then
//! removed them:
//!
//! - **old-parent**: the removed member sends rotations whose parent is
//!   their own `Add`, from before their removal. Each is invalid (concurrent
//!   with the removal) but lies older than every cut the resolver keeps, so
//!   it re-resolves the whole history.
//! - **leaves**: the removed member sends `leaves` (default 500) pairwise
//!   concurrent `Leave`s on the current heads. Each is a revocation
//!   candidate that wins one round of the winners loop and then fails, so
//!   the loop runs `leaves + 1` rounds (TRUST.md §5 step 6). Reported: the
//!   cost of inserting the `Leave`s, then of 200 honest admin inserts, and
//!   the heap the graph grew by.
//! - **lagging**: an honest admin device that was offline since the start
//!   sends one (valid) op on an old head.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use mycel_crypto::{DeviceKeys, Hash32, Lockbox, SignPk};
use mycel_trust::{Action, EpochId, Op, OpId, Revocation, Role, Rotation, SignedOp, SpaceGraph};

/// Counts live heap bytes.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator, only counting sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            LIVE.fetch_add(new - l.size(), Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - new, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

struct History {
    keys: Vec<DeviceKeys>,
    g: SpaceGraph,
    nonce: u64,
    /// The founder's `Add` of member 1, before their removal.
    add: OpId,
}

impl History {
    /// One admin's linear history of `n` ops: add member 1, remove them,
    /// then rotations.
    fn new(n: usize) -> Self {
        let keys: Vec<DeviceKeys> = (0..2).map(|i| DeviceKeys::from_seed([i as u8 + 1; 32])).collect();
        let (g, _, _, _) = SpaceGraph::create(&keys[0]).unwrap();
        let add = g.heads()[0];
        let mut h = History { keys, g, nonce: 0, add };
        let keyring = Some(Lockbox { enc: vec![1], ct: vec![2] });
        let op = h.sign(0, h.g.heads(), Action::Add { member: h.keys[1].public(), role: Role::Admin, keyring });
        h.add = op.id();
        h.g.insert(op).unwrap();
        let rotation = h.rotation([h.pk(0)].into());
        let action = Action::Remove { member: h.pk(1), revocation: Revocation { cutoff: None }, rotation };
        let op = h.sign(0, h.g.heads(), action);
        h.g.insert(op).unwrap();
        while h.g.len() < n {
            let op = h.admin_op();
            h.g.insert(op).unwrap();
        }
        h
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
            lockboxes: recipients.into_iter().map(|pk| (pk, Lockbox { enc: vec![0], ct: vec![0] })).collect(),
        }
    }

    /// The founder rotates on the current heads.
    fn admin_op(&mut self) -> SignedOp {
        let rotation = self.rotation([self.pk(0)].into());
        self.sign(0, self.g.heads(), Action::Rotate { rotation })
    }

    /// Insert `op`; milliseconds taken.
    fn time(&mut self, op: SignedOp) -> f64 {
        let t = Instant::now();
        self.g.insert(op).unwrap();
        t.elapsed().as_secs_f64() * 1e3
    }
}

fn median(mut ts: Vec<f64>) -> (f64, f64) {
    ts.sort_by(f64::total_cmp);
    (ts[ts.len() / 2], ts[ts.len() - 1])
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with("--")).collect();
    let n: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(10_000);
    let leaves: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(500);

    let mut h = History::new(n);
    let op = h.admin_op();
    let honest = h.time(op);
    let ts: Vec<f64> = (0..10)
        .map(|_| {
            let rotation = h.rotation([h.pk(0), h.pk(1)].into());
            let op = h.sign(1, vec![h.add], Action::Rotate { rotation });
            let id = op.id();
            let t = h.time(op);
            assert!(!h.g.is_valid(&id));
            t
        })
        .collect();
    let (med, max) = median(ts);
    println!(
        "old-parent  n={n}: honest head insert {honest:.3} ms; removed member's op on their old Add: median {med:.2} ms, max {max:.2} ms"
    );

    let mut h = History::new(n);
    let base = h.g.heads();
    let heap = LIVE.load(Ordering::Relaxed);
    let t = Instant::now();
    let mut worst: f64 = 0.0;
    for _ in 0..leaves {
        let op = h.sign(1, base.clone(), Action::Leave { cutoff: None });
        worst = worst.max(h.time(op));
    }
    let total = t.elapsed().as_secs_f64();
    let grew = LIVE.load(Ordering::Relaxed).saturating_sub(heap);
    let ts: Vec<f64> = (0..200)
        .map(|_| {
            let op = h.admin_op();
            h.time(op)
        })
        .collect();
    let (med, max) = median(ts);
    println!(
        "leaves      n={n}: {leaves} concurrent Leaves, {} rounds: inserting them {total:.1} s (worst {worst:.1} ms), heap +{:.1} MiB; honest insert after: median {med:.3} ms, max {max:.3} ms",
        h.g.resolution().rounds(),
        mib(grew),
    );

    let mut h = History::new(n);
    let rotation = h.rotation([h.pk(0), h.pk(1)].into());
    let op = h.sign(0, vec![h.add], Action::Rotate { rotation });
    let id = op.id();
    let t = h.time(op);
    assert!(h.g.is_valid(&id));
    println!("lagging     n={n}: honest admin op on the second op of the history: {t:.2} ms");
}
