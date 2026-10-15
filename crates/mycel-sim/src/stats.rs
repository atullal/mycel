//! Seeded randomness and summary statistics.

use serde::{Deserialize, Serialize};

/// Hash maps and sets with a fixed hasher: the same inserts iterate in the
/// same order on every run, so seeded simulations are reproducible.
pub type Map<K, V> =
    std::collections::HashMap<K, V, std::hash::BuildHasherDefault<std::collections::hash_map::DefaultHasher>>;
pub type Set<K> =
    std::collections::HashSet<K, std::hash::BuildHasherDefault<std::collections::hash_map::DefaultHasher>>;

/// SplitMix64: tiny, fast, seeded; every run with the same seed is the same.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    pub fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn f64(&mut self) -> f64 {
        (self.u64() >> 11) as f64 / (1u64 << 53) as f64
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

    /// Standard normal (Box–Muller).
    pub fn normal(&mut self) -> f64 {
        let u = self.f64().max(1e-12);
        let v = self.f64();
        (-2.0 * u.ln()).sqrt() * (std::f64::consts::TAU * v).cos()
    }

    pub fn fork(&mut self) -> Rng {
        Rng(self.u64())
    }
}

/// p50/p95/p99 and friends of a sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub n: usize,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

impl Summary {
    pub fn of(xs: &[f64]) -> Summary {
        if xs.is_empty() {
            return Summary::default();
        }
        let mut v: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return Summary::default();
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let q = |p: f64| v[((p * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)];
        Summary {
            n: v.len(),
            mean: v.iter().sum::<f64>() / v.len() as f64,
            p50: q(0.50),
            p95: q(0.95),
            p99: q(0.99),
            max: *v.last().expect("non-empty"),
        }
    }
}

/// Jain's fairness index: 1 = perfectly even, 1/n = one does everything.
pub fn jain(xs: &[f64]) -> f64 {
    let s: f64 = xs.iter().sum();
    let s2: f64 = xs.iter().map(|x| x * x).sum();
    if s2 == 0.0 { 1.0 } else { s * s / (xs.len() as f64 * s2) }
}

/// The largest share of the total carried by one element.
pub fn max_share(xs: &[f64]) -> f64 {
    let s: f64 = xs.iter().sum();
    if s == 0.0 { 0.0 } else { xs.iter().copied().fold(0.0, f64::max) / s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let xs: Vec<f64> = (1..=100).map(f64::from).collect();
        let s = Summary::of(&xs);
        assert_eq!((s.p50, s.p95, s.p99, s.max), (51.0, 95.0, 99.0, 100.0));
        assert!((jain(&[1.0, 1.0, 1.0]) - 1.0).abs() < 1e-9);
        assert!((jain(&[1.0, 0.0, 0.0, 0.0]) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn seeded() {
        let (mut a, mut b) = (Rng::new(5), Rng::new(5));
        assert_eq!((0..10).map(|_| a.u64()).collect::<Vec<_>>(), (0..10).map(|_| b.u64()).collect::<Vec<_>>());
    }
}
