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
        mix64(self.0)
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

/// SplitMix64's output function (Stafford's variant 13): a bijection on
/// `u64` with full avalanche, so nearby inputs give unrelated outputs.
pub fn mix64(x: u64) -> u64 {
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The independent random streams of one seed. A scenario draws its world
/// and workload from `Rng::new(seed ^ tag)` streams; what the protocols do
/// (radio jitter, the routers' own randomness) comes from these, so the
/// world's draws never line up with the protocol's. (They used to be the
/// same sequence: `Rng::new(seed)` for a mesh's positions and for the
/// engine's jitter and the routers' start phases.)
///
/// This is ns-3's substream rule ("the only way to guarantee that two
/// streams do not overlap is to use the substream capability") applied to
/// SplitMix64: each stream starts from [`mix64`] of (seed, stream), and two
/// SplitMix64 sequences of length L overlap only if their starts are
/// within L Weyl steps, a chance of about 2L / 2^64 per pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// The engine: radio jitter, and what routers draw through `Cx::rng`.
    Protocol = 1,
    /// Each routing core's own generator (one sub-stream per device).
    Routers = 2,
    /// Who sends what when, where the scenario's world stream (or trace)
    /// already draws from `Rng::new(seed)`.
    Workload = 3,
}

/// The seed of stream `s` of `seed`.
pub fn stream_seed(seed: u64, s: Stream) -> u64 {
    mix64(seed ^ mix64((s as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
}

/// The seed of replication `run` of base seed `base` (ns-3's fixed seed
/// with an advancing run number). Replications of one base never repeat a
/// seed ([`mix64`] is a bijection), and their seeds are unrelated to the
/// small seeds (1, 2, 3...) thresholds were first tuned on.
pub fn run_seed(base: u64, run: u64) -> u64 {
    mix64(base ^ mix64(run ^ 0x7275_6e5f_696e_6478))
}

/// The seeds of replications `0..k` of `base`.
pub fn run_seeds(base: u64, k: usize) -> Vec<u64> {
    (0..k as u64).map(|r| run_seed(base, r)).collect()
}

/// Wilson's score interval for `k` successes in `n` trials, at the normal
/// quantile `z` (1.96: 95%). It keeps its coverage near 0 and 1 and for
/// small n, where the textbook p ± z·√(p(1−p)/n) collapses to a point.
pub fn wilson(k: usize, n: usize, z: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let (n, p) = (n as f64, k as f64 / n as f64);
    let z2 = z * z;
    let centre = (p + z2 / (2.0 * n)) / (1.0 + z2 / n);
    let half = z / (1.0 + z2 / n) * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

/// P(B ≤ j) for B ~ Binomial(n, p), for every j in 0..=n (in log space, so
/// n in the tens of thousands doesn't underflow).
pub fn binomial_cdf(n: usize, p: f64) -> Vec<f64> {
    if p <= 0.0 {
        return vec![1.0; n + 1];
    }
    if p >= 1.0 {
        let mut v = vec![0.0; n + 1];
        v[n] = 1.0;
        return v;
    }
    let (lp, lq) = (p.ln(), (1.0 - p).ln());
    let mut log_pmf = n as f64 * lq;
    let mut acc = 0.0;
    let mut out = Vec::with_capacity(n + 1);
    for j in 0..=n {
        if j > 0 {
            log_pmf += ((n - j + 1) as f64).ln() - (j as f64).ln() + lp - lq;
        }
        acc += log_pmf.exp();
        out.push(acc.min(1.0));
    }
    out
}

/// The chance that a build whose seeds each pass with probability `p0`
/// passes on fewer than `m` of `k` seeds: the gate's false-alarm rate.
pub fn spurious_fail(k: usize, m: usize, p0: f64) -> f64 {
    if m == 0 {
        return 0.0;
    }
    binomial_cdf(k, p0)[(m - 1).min(k)]
}

/// The exact distribution-free interval for quantile `q` of a sorted
/// sample, from its order statistics: [X(l), X(u)] covers the quantile with
/// probability P(l ≤ B < u), B ~ Binomial(n, q), with tails of at most
/// (1 − `conf`) / 2 each. `None` on a side means no order statistic is far
/// enough out: the sample is too small to bound it there (p99 needs
/// n ≥ 299 for any 95% interval at all).
pub fn quantile_ci(sorted: &[f64], q: f64, conf: f64) -> (Option<f64>, Option<f64>) {
    let n = sorted.len();
    if n == 0 {
        return (None, None);
    }
    let cdf = binomial_cdf(n, q);
    let tail = (1.0 - conf) / 2.0;
    // lower: the largest rank l (1-based) with P(B ≤ l − 1) ≤ tail
    let lo = (1..=n).take_while(|l| cdf[l - 1] <= tail).last().map(|l| sorted[l - 1]);
    // upper: the smallest rank u with P(B ≤ u − 1) ≥ 1 − tail
    let hi = (1..=n).find(|u| cdf[u - 1] >= 1.0 - tail).map(|u| sorted[u - 1]);
    (lo, hi)
}

/// Pooled samples smaller than this report no p99: its 95% interval
/// reaches the few largest samples (at n = 400 it runs from about the 9th
/// largest to the maximum, so "p99" is any of the nine worst), and first
/// leaves them at about this size (54th to 29th largest).
pub const P99_MIN_N: usize = 4000;

/// The tail of a sample of ratios (achieved / fastest feasible), in
/// numbers that can carry a verdict at a few hundred samples: p95 with
/// its exact interval, the mean of the worst 5% (CVaR₉₅, the expected
/// shortfall: it moves with every tail sample, not with one order
/// statistic), and how many are over 10× and over 30×, with Wilson
/// intervals on the share. p99 only for samples of [`P99_MIN_N`] or more.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Tail {
    pub n: usize,
    pub p50: f64,
    pub p95: f64,
    /// Exact 95% interval for p95 (`None`: unbounded on that side).
    pub p95_ci: (Option<f64>, Option<f64>),
    /// Mean of the worst ⌈5%⌉ samples.
    pub cvar95: f64,
    pub over_10: usize,
    /// Wilson 95% interval for the share over 10×.
    pub over_10_ci: (f64, f64),
    pub over_30: usize,
    pub over_30_ci: (f64, f64),
    /// Only when `n` ≥ [`P99_MIN_N`].
    pub p99: Option<f64>,
    /// Exact 95% interval for p99, with it.
    #[serde(default)]
    pub p99_ci: Option<(Option<f64>, Option<f64>)>,
    pub max: f64,
}

impl Tail {
    pub fn of(xs: &[f64]) -> Tail {
        let mut v: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return Tail::default();
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let n = v.len();
        let q = |p: f64| v[((p * (n - 1) as f64).round() as usize).min(n - 1)];
        let worst = n.div_ceil(20);
        let over = |x: f64| v.iter().filter(|r| **r > x).count();
        let (over_10, over_30) = (over(10.0), over(30.0));
        Tail {
            n,
            p50: q(0.50),
            p95: q(0.95),
            p95_ci: quantile_ci(&v, 0.95, 0.95),
            cvar95: v[n - worst..].iter().sum::<f64>() / worst as f64,
            over_10,
            over_10_ci: wilson(over_10, n, 1.96),
            over_30,
            over_30_ci: wilson(over_30, n, 1.96),
            p99: (n >= P99_MIN_N).then(|| q(0.99)),
            p99_ci: (n >= P99_MIN_N).then(|| quantile_ci(&v, 0.99, 0.95)),
            max: v[n - 1],
        }
    }

    /// One line: "p50 1.22×, p95 7.55× [6.90–8.41], CVaR95 21.3×, > 10×: 14
    /// (2.1–5.8%), > 30×: 4 (0.4–2.5%) of 400".
    pub fn line(&self) -> String {
        use crate::report::fmt;
        let ci = |c: (Option<f64>, Option<f64>)| {
            format!("{}–{}", c.0.map_or_else(|| "?".into(), fmt), c.1.map_or_else(|| "∞".into(), fmt))
        };
        let share = |c: (f64, f64)| format!("{:.1}–{:.1}%", 100.0 * c.0, 100.0 * c.1);
        let mut s = format!(
            "p50 {}×, p95 {}× [{}], CVaR95 {}×, > 10×: {} ({}), > 30×: {} ({}) of {}",
            fmt(self.p50),
            fmt(self.p95),
            ci(self.p95_ci),
            fmt(self.cvar95),
            self.over_10,
            share(self.over_10_ci),
            self.over_30,
            share(self.over_30_ci),
            self.n
        );
        if let Some(p99) = self.p99 {
            s.push_str(&format!(", p99 {}× [{}]", fmt(p99), self.p99_ci.map_or_else(|| "?".into(), ci)));
        }
        s
    }
}

/// p50/p95/p99 and friends of a sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub n: usize,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    /// Not written out for optimality ratios below [`P99_MIN_N`].
    #[serde(default)]
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
    fn streams_and_runs_are_distinct_and_reproducible() {
        let s = [Stream::Protocol, Stream::Routers, Stream::Workload];
        let seeds: Vec<u64> = s.iter().map(|x| stream_seed(1, *x)).collect();
        assert!(seeds.iter().all(|x| *x != 1));
        assert_eq!(seeds.iter().collect::<Set<_>>().len(), 3);
        assert_eq!(stream_seed(7, Stream::Protocol), stream_seed(7, Stream::Protocol));
        let runs = run_seeds(1, 100);
        assert_eq!(runs.iter().collect::<Set<_>>().len(), 100);
        assert!(runs.iter().all(|r| *r > 1_000), "unrelated to the small hand-picked seeds");
        assert_eq!(runs, run_seeds(1, 100));
        assert_ne!(run_seeds(2, 3), run_seeds(1, 3));
        // the protocol stream no longer repeats the world's `Rng::new(seed)`
        let (mut world, mut proto) = (Rng::new(1), Rng::new(stream_seed(1, Stream::Protocol)));
        assert_ne!((0..4).map(|_| world.u64()).collect::<Vec<_>>(), (0..4).map(|_| proto.u64()).collect::<Vec<_>>());
    }

    #[test]
    fn wilson_matches_published_values() {
        // 380/400 → [92.4%, 96.7%] (computed in the research notes)
        let (lo, hi) = wilson(380, 400, 1.96);
        assert!((lo - 0.924).abs() < 0.001 && (hi - 0.967).abs() < 0.001, "{lo} {hi}");
        // all passing still leaves room below 1
        let (lo, hi) = wilson(10, 10, 1.96);
        assert!(lo > 0.65 && lo < 0.75 && hi == 1.0, "{lo} {hi}");
        assert_eq!(wilson(0, 0, 1.96), (0.0, 1.0));
    }

    #[test]
    fn binomial_gate_rates() {
        // ≥ 8 of 10 with a per-seed pass rate of 0.95 fails spuriously ~1.2%
        let f = spurious_fail(10, 8, 0.95);
        assert!((f - 0.0115).abs() < 0.0005, "{f}");
        // three passing seeds bound the failure rate only at 63%: a build
        // failing 63% of seeds passes all three with probability 0.37³ ≈ 0.05
        assert!((binomial_cdf(3, 0.63)[0] - 0.05).abs() < 0.002);
        let c = binomial_cdf(4000, 0.99);
        assert!((c[4000] - 1.0).abs() < 1e-9 && c[3900] < 1e-6, "no underflow at large n");
    }

    #[test]
    fn quantile_intervals_need_enough_samples() {
        let v: Vec<f64> = (1..=400).map(f64::from).collect();
        // p99 at n = 400: from about the 9th largest to the maximum or beyond
        let (lo, hi) = quantile_ci(&v, 0.99, 0.95);
        assert!(lo.is_some_and(|x| (390.0..=393.0).contains(&x)), "{lo:?}");
        assert!(hi.is_none_or(|x| x >= 399.0), "{hi:?}");
        // p95 at n = 400 sits well inside: about the 29th to the 12th largest
        let (lo, hi) = quantile_ci(&v, 0.95, 0.95);
        assert!(lo.is_some_and(|x| (369.0..=374.0).contains(&x)), "{lo:?}");
        assert!(hi.is_some_and(|x| (387.0..=391.0).contains(&x)), "{hi:?}");
        // under 299 samples p99 has no upper bound at all
        let small: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(quantile_ci(&small, 0.99, 0.95).1, None);
    }

    #[test]
    fn tail_metrics() {
        // 400 ratios: 380 at 1×, 15 at 20×, 5 at 50×
        let mut xs = vec![1.0; 380];
        xs.extend(std::iter::repeat_n(20.0, 15));
        xs.extend(std::iter::repeat_n(50.0, 5));
        let t = Tail::of(&xs);
        assert_eq!((t.n, t.over_10, t.over_30), (400, 20, 5));
        // the worst 5% are the 20 samples over 10×: (15·20 + 5·50) / 20
        assert!((t.cvar95 - 27.5).abs() < 1e-9);
        assert_eq!(t.p99, None, "p99 needs a pooled sample of 4000");
        assert_eq!(t.max, 50.0);
        assert_eq!(Tail::of(&vec![2.0; P99_MIN_N]).p99, Some(2.0));
        assert!(t.line().contains("CVaR95 27.5×"), "{}", t.line());
    }

    #[test]
    fn seeded() {
        let (mut a, mut b) = (Rng::new(5), Rng::new(5));
        assert_eq!((0..10).map(|_| a.u64()).collect::<Vec<_>>(), (0..10).map(|_| b.u64()).collect::<Vec<_>>());
    }
}
