//! Replications: each scenario on many seeds, and verdicts one seed can't
//! give (docs/SIMULATION.md §1, "Seeds and verdicts").
//!
//! A seed is a replication, never a tuning target. Seeds come from a base
//! and a run index ([`run_seeds`], ns-3's fixed seed with an advancing run
//! number), and each seed's protocol randomness is a stream apart from its
//! world ([`crate::world::streams`]). Two kinds of objective, two rules:
//!
//! - **Invariants** (no loops, no route through a black hole after the
//!   defence, convergence at all; [`crate::report::Slo::invariant`]) hold
//!   on every seed: one failure fails the gate.
//! - **Quality** objectives (delivery, latency, optimality) pass on at
//!   least m of k seeds. With k = 10 and m = 8, a build whose seeds each
//!   pass with probability 0.95 fails the gate 1.2% of the time
//!   ([`crate::stats::spurious_fail`]); three seeds that all pass bound a
//!   seed's failure rate only below 63%.
//! - A **known gap** (a scenario expected to fail) is judged the other way
//!   round: its invariants on every seed, and its quality objectives must
//!   still fail on more than k − m seeds. Once they pass on m or more the
//!   expectation is stale and the verdict fails, naming those seeds; fewer
//!   are reported ("gap closed on j of k") without failing.
//!
//! Thresholds are calibrated on [`CALIBRATION_BASE`]'s seeds, never on the
//! gate's ([`GATE_BASE`]), and a nightly soak runs fresh bases: every
//! failing seed it prints replays exactly (`--seed`), to be pinned
//! ([`PINNED`]) once its cause is fixed.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::report::{ScenarioResult, Status, fmt};
use crate::scenarios::{self, Candidate, Opts};
use crate::stats::{P99_MIN_N, Tail, run_seeds, wilson};

/// Base of the seeds CI gates on (`mycel-sim ci --seed 1000 --runs 10`).
pub const GATE_BASE: u64 = 1000;
/// Base of the seeds thresholds are calibrated on, never gated on
/// (`mycel-sim ci --seed 2000 --runs 30`).
pub const CALIBRATION_BASE: u64 = 2000;
/// Seeds per scenario in the gate...
pub const GATE_SEEDS: usize = 10;
/// ... and how many of them each quality objective must pass on.
pub const GATE_MIN_PASS: usize = 8;

/// The tier-2 scenarios CI gates, at their CI sizes.
pub const CI_SUITE: &[(&str, f64)] = &[
    ("us-eu", 0.1),
    ("gateway-choice", 0.1),
    ("partial-route", 0.1),
    ("mailbox", 0.1),
    ("flood-hop-limit", 0.2),
    ("trace-replay", 0.05),
    ("adversarial", 0.1),
    ("routing-convergence", 0.1),
    ("disaster-dtn", 0.1),
];

/// The nightly soak's: the gate's, the heavier ones, and the liar ceiling
/// at a size where liars cost delivery (225 phones; at CI size the formats
/// can't be told apart: docs/SIMULATION.md §4, open 15). It is a known gap
/// there, so the soak guards its invariant and flags the day it passes.
pub const SOAK_SUITE: &[(&str, f64)] = &[
    ("us-eu", 0.1),
    ("gateway-choice", 0.1),
    ("partial-route", 0.1),
    ("mailbox", 0.1),
    ("flood-hop-limit", 0.2),
    ("trace-replay", 0.05),
    ("adversarial", 0.1),
    ("routing-convergence", 0.1),
    ("disaster-dtn", 0.1),
    ("liar-ceiling", 0.75),
    ("flood-scaling", 0.1),
    ("global-scale", 0.01),
    ("churn", 0.05),
];

/// Seeds that once failed, kept as regressions: (scenario, scale, seed).
/// Every objective must pass on each.
pub const PINNED: &[(&str, f64, u64)] = &[
    // the hop-limit shape check compared different broadcasts at each
    // limit; on today's streams this seed guards the paired criterion, and
    // the scenario's own invariant ("every hop limit sends the same
    // broadcasts") guards the pairing (docs/SIMULATION.md §4, fixed 24)
    ("flood-hop-limit", 0.2, 3),
    // one 12-message world "failed" at 6 of 8 and 9 of 12 delivered: now a
    // mean of 20 worlds of 48 messages each (fixed 25)
    ("disaster-dtn", 0.1, 2),
    ("disaster-dtn", 0.1, 3),
];

/// The default for "at least m of k seeds": 80%, rounded up (8 of 10).
pub fn min_pass(k: usize) -> usize {
    (k * 4).div_ceil(5)
}

/// Run `name` at `scale` on every seed (tier 2 in parallel; tier 1 one
/// after another, since it measures the wall clock).
pub fn replicate(name: &str, scale: f64, seeds: &[u64], candidate: Candidate) -> Vec<ScenarioResult> {
    let s = scenarios::find(name).unwrap_or_else(|| panic!("no scenario {name}"));
    let one = |seed: &u64| {
        let t = std::time::Instant::now();
        let mut r = (s.run)(Opts { seed: *seed, scale, candidate });
        r.wall_s = t.elapsed().as_secs_f64();
        r.finish();
        r
    };
    if s.tier == 2 { seeds.par_iter().map(one).collect() } else { seeds.iter().map(one).collect() }
}

/// Run each [`PINNED`] seed once (they're cheap and few): every objective
/// must pass. What failed, each with the command that replays it.
pub fn check_pinned(candidate: Candidate) -> Vec<String> {
    PINNED
        .iter()
        .filter_map(|(name, scale, seed)| {
            let s = scenarios::find(name).unwrap_or_else(|| panic!("no scenario {name}"));
            let mut r = (s.run)(Opts { seed: *seed, scale: *scale, candidate });
            r.finish();
            if matches!(r.status, Status::Pass | Status::ExpectedFail) {
                return None;
            }
            let missed: Vec<String> =
                r.failed_slos().iter().map(|f| format!("{}: {} (target {})", f.name, f.actual, f.target)).collect();
            Some(format!(
                "pinned {name} seed {seed}: {}; replay: cargo run --release -p mycel-sim -- {name} --scale {scale} --seed {seed}",
                missed.join("; ")
            ))
        })
        .collect()
}

/// One objective across the seeds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spread {
    pub name: String,
    pub target: String,
    pub invariant: bool,
    pub passes: usize,
    pub seeds: usize,
    /// Per-seed values, where the objective has a number.
    pub values: Vec<f64>,
}

impl Spread {
    /// "9/10 (Wilson 60–98%), values min / median / max".
    pub fn line(&self) -> String {
        let (lo, hi) = wilson(self.passes, self.seeds, 1.96);
        let mut s = format!(
            "{}{} ({}): {}/{} seeds pass (per-seed pass rate {:.0}–{:.0}%)",
            if self.invariant { "[invariant] " } else { "" },
            self.name,
            self.target,
            self.passes,
            self.seeds,
            100.0 * lo,
            100.0 * hi
        );
        if !self.values.is_empty() {
            let mut v = self.values.clone();
            v.sort_by(|a, b| a.total_cmp(b));
            let q = |p: f64| v[((p * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)];
            s.push_str(&format!(
                "; min {}, p10 {}, median {}, p90 {}, max {}",
                fmt(v[0]),
                fmt(q(0.1)),
                fmt(q(0.5)),
                fmt(q(0.9)),
                fmt(v[v.len() - 1])
            ));
        }
        s
    }
}

/// A scenario's replications judged: invariants on every seed, quality on
/// at least `min_pass` of them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verdict {
    pub name: String,
    pub scale: f64,
    pub seeds: Vec<u64>,
    pub min_pass: usize,
    /// Seeds on which every quality objective passed.
    pub quality_passes: usize,
    /// (seed, objective: actual vs target) for each quality miss. For a
    /// known gap these are the gap itself, not failing seeds.
    pub quality_misses: Vec<(u64, String)>,
    /// Why the scenario is expected to fail, if it is (a known gap).
    #[serde(default)]
    pub known_gap: Option<String>,
    /// (seed, what passed) for each seed of a known gap on which every
    /// quality objective passed: the gap closed there.
    #[serde(default)]
    pub unexpected_passes: Vec<(u64, String)>,
    /// (seed, objective: actual vs target) for each invariant broken.
    pub invariant_failures: Vec<(u64, String)>,
    pub spread: Vec<Spread>,
    /// The candidate's optimality ratios of every seed, pooled: the tail
    /// one seed's few hundred messages can't give (p99 from
    /// [`P99_MIN_N`] messages on).
    pub pooled: Option<Tail>,
    pub pass: bool,
    pub wall_s: f64,
}

/// Judge `results` (one scenario, one result per seed).
pub fn verdict(results: &[ScenarioResult], min_pass: usize) -> Verdict {
    let first = results.first();
    let mut v = Verdict {
        name: first.map_or_else(String::new, |r| r.name.clone()),
        scale: first.map_or(0.0, |r| r.scale),
        seeds: results.iter().map(|r| r.seed).collect(),
        min_pass,
        quality_passes: 0,
        quality_misses: Vec::new(),
        known_gap: results.iter().find_map(|r| r.expected_fail.clone()),
        unexpected_passes: Vec::new(),
        invariant_failures: Vec::new(),
        spread: Vec::new(),
        pooled: None,
        pass: false,
        wall_s: results.iter().map(|r| r.wall_s).sum(),
    };
    let ratios: Vec<f64> = results.iter().flat_map(|r| r.optimality.iter().copied()).collect();
    v.pooled = (!ratios.is_empty()).then(|| Tail::of(&ratios));
    for r in results {
        let mut quality_ok = true;
        for s in r.slos.iter().filter(|s| !s.pass) {
            let what = format!("{}: {} (target {})", s.name, s.actual, s.target);
            // an expected failure (a known gap) covers quality, never an
            // invariant ([`ScenarioResult::finish`])
            if s.invariant {
                v.invariant_failures.push((r.seed, what));
            } else {
                quality_ok = false;
                v.quality_misses.push((r.seed, what));
            }
        }
        v.quality_passes += quality_ok as usize;
        if quality_ok && r.expected_fail.is_some() {
            let what: Vec<String> =
                r.slos.iter().filter(|s| !s.invariant).map(|s| format!("{} {}", s.name, s.actual)).collect();
            v.unexpected_passes.push((r.seed, format!("passed although expected to fail: {}", what.join("; "))));
        }
        for s in &r.slos {
            let i = match v.spread.iter().position(|x| x.name == s.name) {
                Some(i) => i,
                None => {
                    v.spread.push(Spread {
                        name: s.name.clone(),
                        target: s.target.clone(),
                        invariant: s.invariant,
                        passes: 0,
                        seeds: 0,
                        values: Vec::new(),
                    });
                    v.spread.len() - 1
                }
            };
            let x = &mut v.spread[i];
            x.seeds += 1;
            x.passes += s.pass as usize;
            x.values.extend(s.value.filter(|v| v.is_finite()));
        }
    }
    v.pass = v.invariant_failures.is_empty() && v.quality_ok();
    v
}

impl Verdict {
    /// The command that replays one seed exactly.
    pub fn repro(&self, seed: u64) -> String {
        format!("cargo run --release -p mycel-sim -- {} --scale {} --seed {seed}", self.name, self.scale)
    }

    /// Quality as the gate judges it: passes on at least `min_pass` seeds;
    /// for a known gap, on fewer (from `min_pass` on it has closed).
    fn quality_ok(&self) -> bool {
        if self.known_gap.is_some() {
            self.quality_passes < self.min_pass
        } else {
            self.quality_passes >= self.min_pass
        }
    }

    /// The seeds to blame, each once, in order: every seed that broke an
    /// invariant and, when the verdict fails on quality, the seeds that
    /// made it fail (quality misses; for a known gap, the seeds where it
    /// closed). What a seed may miss within m of k isn't here
    /// ([`Verdict::missed_within_slack`]), nor a known gap's own misses.
    pub fn failing_seeds(&self) -> Vec<u64> {
        let on_quality = !self.quality_ok();
        let blamed = |s: &u64| {
            self.invariant_failures.iter().any(|(x, _)| x == s)
                || (on_quality
                    && if self.known_gap.is_some() {
                        self.unexpected_passes.iter().any(|(x, _)| x == s)
                    } else {
                        self.quality_misses.iter().any(|(x, _)| x == s)
                    })
        };
        self.seeds.iter().copied().filter(blamed).collect()
    }

    /// Seeds that missed a quality objective without failing the verdict
    /// (the m-of-k slack), each once, in order. With fixed gate seeds and a
    /// deterministic tier 2, such a seed misses on every run: it uses up
    /// slack until the code changes.
    pub fn missed_within_slack(&self) -> Vec<u64> {
        if self.known_gap.is_some() {
            return Vec::new();
        }
        let failing = self.failing_seeds();
        self.seeds
            .iter()
            .copied()
            .filter(|s| !failing.contains(s) && self.quality_misses.iter().any(|(x, _)| x == s))
            .collect()
    }

    pub fn markdown(&self) -> String {
        let quality = match &self.known_gap {
            None => format!(
                "quality: {} of {} seeds pass (gate ≥ {})",
                self.quality_passes,
                self.seeds.len(),
                self.min_pass
            ),
            Some(why) => format!(
                "known gap ({why}): closed on {} of {} seeds (a stale expectation from {})",
                self.quality_passes,
                self.seeds.len(),
                self.min_pass
            ),
        };
        let mut s = format!(
            "### `{}` at scale {} on {} seeds: {}\n\n{quality}; invariants broken: {}; {:.0} s of runs\n",
            self.name,
            self.scale,
            self.seeds.len(),
            if self.pass { "✅ pass" } else { "❌ FAIL" },
            self.invariant_failures.len(),
            self.wall_s
        );
        for x in &self.spread {
            s.push_str(&format!("\n- {}", x.line()));
        }
        if let Some(t) = &self.pooled {
            s.push_str(&format!("\n- optimality, pooled over the seeds: {}", t.line()));
            if t.p99.is_none() {
                s.push_str(&format!(" (p99 from {P99_MIN_N} messages)"));
            }
        }
        for (seed, what) in &self.invariant_failures {
            s.push_str(&format!("\n- ❌ invariant, seed {seed}: {what}\n  replay: `{}`", self.repro(*seed)));
        }
        let kind = if self.known_gap.is_some() { "known-gap miss" } else { "quality miss" };
        for (seed, what) in &self.quality_misses {
            s.push_str(&format!("\n- {kind}, seed {seed}: {what}\n  replay: `{}`", self.repro(*seed)));
        }
        for (seed, what) in &self.unexpected_passes {
            s.push_str(&format!("\n- ⚠️ gap closed, seed {seed}: {what}\n  replay: `{}`", self.repro(*seed)));
        }
        s.push('\n');
        s
    }
}

/// The gate's seeds.
pub fn gate_seeds() -> Vec<u64> {
    run_seeds(GATE_BASE, GATE_SEEDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ScenarioResult;

    fn result(seed: u64, quality: bool, invariant: bool) -> ScenarioResult {
        let mut r = ScenarioResult::new("x", "x", 2, seed, 0.1);
        r.at_least("delivery", if quality { 95.0 } else { 80.0 }, 90.0, "%");
        r.at_most("loops", if invariant { 0.0 } else { 1.0 }, 0.0, "").invariant();
        r.optimality = (0..400).map(|i| 1.0 + f64::from(i) / 100.0).collect();
        r.finish();
        r
    }

    #[test]
    fn quality_is_m_of_k_and_invariants_zero_tolerance() {
        let mut rs: Vec<ScenarioResult> = (0..10).map(|s| result(s, s >= 2, true)).collect();
        let v = verdict(&rs, 8);
        assert!(v.pass, "8 of 10 pass");
        assert_eq!((v.quality_passes, v.missed_within_slack()), (8, vec![0, 1]));
        assert!(v.failing_seeds().is_empty(), "within the slack");
        assert_eq!(v.spread[0].values.len(), 10);
        assert_eq!(v.pooled.as_ref().map(|t| t.n), Some(4000), "400 ratios per seed, pooled");
        assert!(v.pooled.as_ref().is_some_and(|t| t.p99.is_some()) && v.markdown().contains("p99"));
        rs[5] = result(5, true, false);
        let v = verdict(&rs, 8);
        assert!(!v.pass, "one broken invariant fails the gate");
        assert_eq!(v.invariant_failures.len(), 1);
        assert!(v.markdown().contains("--seed 5"), "{}", v.markdown());
        rs[5] = result(5, false, true);
        assert!(!verdict(&rs, 8).pass, "7 of 10");
        // a known gap excuses quality, never an invariant
        let mut gap = result(3, false, false);
        gap.expect_fail("a known gap");
        gap.finish();
        assert_eq!(gap.status, Status::Fail);
        let v = verdict(&[gap], 1);
        assert!(!v.pass && v.invariant_failures.len() == 1 && v.quality_passes == 0, "{v:?}");
        assert_eq!(v.failing_seeds(), vec![3]);
    }

    /// Ten seeds of a known gap, the gap closed on the seeds in `closed`.
    fn gap(closed: &[u64]) -> Vec<ScenarioResult> {
        (0..10)
            .map(|s| {
                let mut r = result(s, closed.contains(&s), true);
                r.expect_fail("a known gap");
                r.finish();
                r
            })
            .collect()
    }

    #[test]
    fn a_known_gaps_own_misses_are_not_seeds_to_pin() {
        let v = verdict(&gap(&[]), 8);
        assert!(v.pass && v.quality_misses.len() == 10, "{v:?}");
        assert!(v.failing_seeds().is_empty() && v.missed_within_slack().is_empty(), "the gap, not a regression");
        assert!(v.markdown().contains("known-gap miss") && !v.markdown().contains("quality miss"));
    }

    #[test]
    fn a_known_gap_that_closes_is_named_seed_by_seed() {
        // closed on a few seeds: reported, not failed
        let v = verdict(&gap(&[4, 7]), 8);
        assert!(v.pass && v.failing_seeds().is_empty(), "{v:?}");
        assert_eq!(v.unexpected_passes.iter().map(|x| x.0).collect::<Vec<_>>(), vec![4, 7]);
        assert!(v.markdown().contains("gap closed, seed 4") && v.markdown().contains("closed on 2 of 10"));
        // closed on m of k: the expectation is stale, and the seeds are named
        let closed = [0, 1, 2, 3, 4, 5, 6, 7];
        let v = verdict(&gap(&closed), 8);
        assert!(!v.pass);
        assert_eq!(v.failing_seeds(), closed.to_vec());
        // one seed, as `mycel-sim <scenario>` judges it: an unexpected pass fails
        let v = verdict(&gap(&[0])[..1], 1);
        assert!(!v.pass && v.failing_seeds() == vec![0], "{v:?}");
    }

    #[test]
    fn a_miss_within_the_slack_is_not_a_failing_seed() {
        let rs: Vec<ScenarioResult> = (0..10).map(|s| result(s, s != 6, true)).collect();
        let v = verdict(&rs, 8);
        assert!(v.pass && v.failing_seeds().is_empty(), "{v:?}");
        assert_eq!(v.missed_within_slack(), vec![6]);
        // over the slack, every missing seed is to blame
        let rs: Vec<ScenarioResult> = (0..10).map(|s| result(s, s > 2, true)).collect();
        let v = verdict(&rs, 8);
        assert!(!v.pass && v.failing_seeds() == vec![0, 1, 2] && v.missed_within_slack().is_empty());
    }

    #[test]
    fn suites_name_real_scenarios() {
        for (name, _) in CI_SUITE.iter().chain(SOAK_SUITE) {
            assert!(scenarios::find(name).is_some_and(|s| s.tier == 2), "{name}");
        }
        for (name, _, _) in PINNED {
            assert!(scenarios::find(name).is_some(), "{name}");
        }
        assert_eq!(min_pass(10), 8);
        assert_eq!(gate_seeds().len(), GATE_SEEDS);
        let cal = run_seeds(CALIBRATION_BASE, 30);
        assert!(gate_seeds().iter().all(|s| !cal.contains(s)), "calibration seeds are never gated on");
    }
}
