//! Counter-based random streams keyed by `(seed, purpose, entity, k)`.
//!
//! Every random draw in tier 2 is a stateless function of four numbers:
//! the run's seed, what the draw is for ([`Purpose`]), whose it is (a
//! device, a directed link, a message: the *entity*) and that entity's own
//! event index `k` (the k-th frame on link a→b, the k-th draw of router
//! d). There is no global draw count, so a protocol change alters *which*
//! events happen, but every event that happens in both candidates sees the
//! same draw: common random numbers (CRN, Law, *Simulation Modeling and
//! Analysis*, ch. 11). Var(A − B) = Var(A) + Var(B) − 2 Cov(A, B), and CRN
//! makes the covariance large; `mycel-sim crn` measures how large.
//!
//! The generator is Philox4×32-10 (Salmon, Moraes, Dror and Shaw,
//! "Parallel random numbers: as easy as 1, 2, 3", SC 2011): a 10-round
//! keyed bijection on 128-bit counters that passes TestU01's BigCrush with
//! any key and any counter pattern, and is checked here against the
//! authors' published known-answer vectors (Random123 `kat_vectors`). It
//! is a statistical generator for simulation, not a cryptographic one.
//! The key is (seed, purpose) mixed by SplitMix64's finaliser; the counter
//! is (entity, k). Purposes are disjoint keys, entities and indices are
//! disjoint counters, so no two (purpose, entity, k) ever share a block.
//! This is ns-3's advice to give every run non-overlapping substreams
//! (ns-3 manual, "Random Variables"), keyed per entity so they cannot
//! shift.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::stats::mix64;

/// Shifts every endogenous key (0: none). Only `mycel-sim crn` sets it, to
/// run candidates on the same exogenous world with independent protocol
/// draws; it is process-wide, so it is set between batches of runs, never
/// during one.
static ENDOGENOUS_SALT: AtomicU64 = AtomicU64::new(0);

/// Give the endogenous streams of every run started from now on salt `s`
/// (0 restores them). For the CRN measurement only.
pub fn set_endogenous_salt(s: u64) {
    ENDOGENOUS_SALT.store(s, Ordering::SeqCst);
}

/// Philox4×32's multipliers and Weyl key increments (Salmon et al. 2011,
/// Table 2; Random123 `philox.h`).
const M0: u32 = 0xD251_1F53;
const M1: u32 = 0xCD9E_8D57;
const W0: u32 = 0x9E37_79B9;
const W1: u32 = 0xBB67_AE85;

/// Philox4×32 with 10 rounds: one 128-bit block for counter `ctr` under
/// `key`. Pure and stateless.
pub fn philox4x32_10(ctr: [u32; 4], key: [u32; 2]) -> [u32; 4] {
    let (mut c, mut k) = (ctr, key);
    for round in 0..10 {
        if round > 0 {
            k = [k[0].wrapping_add(W0), k[1].wrapping_add(W1)];
        }
        let p0 = u64::from(M0) * u64::from(c[0]);
        let p1 = u64::from(M1) * u64::from(c[2]);
        let (hi0, lo0) = ((p0 >> 32) as u32, p0 as u32);
        let (hi1, lo1) = ((p1 >> 32) as u32, p1 as u32);
        c = [hi1 ^ c[1] ^ k[0], lo1, hi0 ^ c[3] ^ k[1], lo0];
    }
    c
}

/// What a draw is for. Exogenous purposes drive the world, which no
/// protocol decision may move (hashed and compared across candidates);
/// endogenous ones drive models that depend on traffic and protocol state,
/// and pair candidates by CRN. Purposes marked *reserved* belong to later
/// work packages (docs/SIMULATION.md §1, "World and streams") and draw
/// nothing yet; their keys are fixed now so that adding them later moves
/// no other stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum Purpose {
    // ── exogenous ──
    /// Where walking devices go (per device, k-th waypoint draw).
    Mobility = 1,
    /// Log-normal shadowing field (reserved: WP7).
    Shadowing = 2,
    /// Tapped-delay-line channel realisations (reserved: WP7).
    ChannelTaps = 3,
    /// User screen sessions and charging (reserved: WP9).
    Sessions = 4,
    /// Internet, relay and DHT outages (reserved: WP10).
    InetOutages = 5,
    /// Censorship windows (reserved: WP10).
    Censorship = 6,
    /// Which devices are adversaries, and in which role (per role, k-th pick).
    Adversary = 7,
    /// Who wants to send what to whom, when (per message, k-th draw).
    Workload = 8,
    /// Who switches off and on when (per device or per minute, k-th draw).
    Churn = 9,
    // ── endogenous ──
    /// Frame reception (reserved: WP7; per (tx, rx), k-th frame).
    FrameRx = 0x101,
    /// MAC backoff (reserved: WP8; per device, k-th backoff).
    MacBackoff = 0x102,
    /// Link-setup outcomes (reserved: WP8; per pair, k-th attempt).
    LinkSetup = 0x103,
    /// OS wakes and jetsam (reserved: WP9; per device, k-th decision).
    OsWake = 0x104,
    /// Relay and cell queueing (reserved: WP10; per relay or cell, k-th arrival).
    Queueing = 0x105,
    /// What a router draws through `Cx::rng` (per router, k-th draw).
    Router = 0x106,
    /// A routing core's own generator seed (per device, draw 0): the core
    /// steps its own xorshift from there.
    RouterCore = 0x107,
    /// Radio jitter (per directed link (tx, rx), k-th frame on it).
    RadioJitter = 0x108,
}

impl Purpose {
    /// Whether the draw belongs to the exogenous world.
    pub fn is_exogenous(self) -> bool {
        (self as u16) < 0x100
    }
}

/// The entity of a directed link a → b.
pub fn link(a: u32, b: u32) -> u64 {
    (u64::from(a) << 32) | u64::from(b)
}

/// A Philox key: one purpose of one seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key([u32; 2]);

impl Key {
    pub fn new(seed: u64, p: Purpose) -> Key {
        let salt = if p.is_exogenous() { 0 } else { ENDOGENOUS_SALT.load(Ordering::Relaxed) };
        let seed = if salt == 0 { seed } else { seed ^ mix64(salt ^ 0x5a17) };
        // distinct seeds give distinct keys for one purpose (mix64 is a
        // bijection); across purposes a collision has odds of 2^-64 a pair
        let k = mix64(seed ^ mix64((p as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x6d79_6365_6c5f_7277));
        Key([k as u32, (k >> 32) as u32])
    }

    /// The 128-bit block for draw `k` of `entity`, as two words.
    pub fn block(self, entity: u64, k: u64) -> [u64; 2] {
        let c = philox4x32_10([k as u32, (k >> 32) as u32, entity as u32, (entity >> 32) as u32], self.0);
        [u64::from(c[0]) | (u64::from(c[1]) << 32), u64::from(c[2]) | (u64::from(c[3]) << 32)]
    }

    /// Draw `k` of `entity`: 64 random bits.
    pub fn u64(self, entity: u64, k: u64) -> u64 {
        self.block(entity, k)[0]
    }

    /// Draw `k` of `entity`, uniform in [0, 1).
    pub fn f64(self, entity: u64, k: u64) -> f64 {
        unit(self.u64(entity, k))
    }

    /// The stream of `entity`, from its draw 0.
    pub fn stream(self, entity: u64) -> Substream {
        Substream { key: self, entity, k: 0, spare: None }
    }
}

fn unit(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// The streams of one run: a [`Key`] per [`Purpose`] on demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Streams {
    pub seed: u64,
}

impl Streams {
    pub fn new(seed: u64) -> Streams {
        Streams { seed }
    }

    pub fn key(self, p: Purpose) -> Key {
        Key::new(self.seed, p)
    }

    /// `entity`'s stream for `p`, from its draw 0.
    pub fn stream(self, p: Purpose, entity: u64) -> Substream {
        self.key(p).stream(entity)
    }

    /// Draw `k` of `entity` for `p`, stateless.
    pub fn u64(self, p: Purpose, entity: u64, k: u64) -> u64 {
        self.key(p).u64(entity, k)
    }
}

/// One entity's stream: draw k is a pure function of (seed, purpose,
/// entity, k) (draws 2j and 2j + 1 are the two words of Philox block j),
/// and the stream only counts k. The same interface as
/// [`crate::stats::Rng`], so routers and scenario code use either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Substream {
    key: Key,
    entity: u64,
    /// The next block's index.
    k: u64,
    /// The second word of the last block, not yet drawn.
    spare: Option<u64>,
}

impl Substream {
    /// How many 64-bit draws this entity has made.
    pub fn draws(&self) -> u64 {
        2 * self.k - u64::from(self.spare.is_some())
    }

    /// Draw 2j and 2j + 1 are the two words of block j.
    pub fn u64(&mut self) -> u64 {
        if let Some(x) = self.spare.take() {
            return x;
        }
        let [a, b] = self.key.block(self.entity, self.k);
        self.k += 1;
        self.spare = Some(b);
        a
    }

    /// Uniform in [0, 1).
    pub fn f64(&mut self) -> f64 {
        unit(self.u64())
    }

    /// Uniform in [lo, hi).
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f64()
    }

    /// Uniform index below `n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.u64() % n as u64) as usize
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.f64() < p
    }

    /// Standard normal (Box–Muller over two draws).
    pub fn normal(&mut self) -> f64 {
        let u = self.f64().max(1e-12);
        let v = self.f64();
        (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn philox_matches_random123_known_answers() {
        // Random123 tests/kat_vectors, "philox4x32 10": counter, key, result
        let kat: [([u32; 4], [u32; 2], [u32; 4]); 3] = [
            ([0; 4], [0; 2], [0x6627_e8d5, 0xe169_c58d, 0xbc57_ac4c, 0x9b00_dbd8]),
            ([u32::MAX; 4], [u32::MAX; 2], [0x408f_276d, 0x41c8_3b0e, 0xa20b_c7c6, 0x6d54_51fd]),
            (
                [0x243f_6a88, 0x85a3_08d3, 0x1319_8a2e, 0x0370_7344],
                [0xa409_3822, 0x299f_31d0],
                [0xd16c_fe09, 0x94fd_cceb, 0x5001_e420, 0x2412_6ea1],
            ),
        ];
        for (ctr, key, want) in kat {
            assert_eq!(philox4x32_10(ctr, key), want);
        }
    }

    #[test]
    fn draws_are_stateless_and_keyed() {
        let s = Streams::new(7);
        let mut a = s.stream(Purpose::Router, 3);
        let first: Vec<u64> = (0..5).map(|_| a.u64()).collect();
        // the k-th draw is the same however it is reached
        assert_eq!(first[4], s.key(Purpose::Router).block(3, 2)[0]);
        assert_eq!(first[3], s.key(Purpose::Router).block(3, 1)[1]);
        assert_eq!(a.draws(), 5);
        // another entity, purpose or seed: unrelated
        assert_ne!(first[0], s.u64(Purpose::Router, 4, 0));
        assert_ne!(first[0], s.u64(Purpose::Mobility, 3, 0));
        assert_ne!(first[0], Streams::new(8).u64(Purpose::Router, 3, 0));
        // links are directed
        assert_ne!(link(1, 2), link(2, 1));
        assert!(Purpose::Workload.is_exogenous() && !Purpose::RadioJitter.is_exogenous());
    }

    #[test]
    fn uniform_enough() {
        // a coarse sanity check (Philox itself passes BigCrush): 64 bins of
        // 64,000 draws over many entities, chi-square under 2× its dof
        let key = Streams::new(1).key(Purpose::RadioJitter);
        let mut bins = [0u32; 64];
        for e in 0..1000u64 {
            for k in 0..64 {
                bins[(key.f64(e, k) * 64.0) as usize] += 1;
            }
        }
        let exp = 1000.0;
        let chi2: f64 = bins.iter().map(|b| (f64::from(*b) - exp).powi(2) / exp).sum();
        assert!(chi2 < 126.0, "chi-square {chi2}");
    }
}
