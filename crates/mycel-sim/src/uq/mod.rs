//! Uncertainty quantification for verdicts (sim-fidelity WP19): is a
//! verdict robust over what we do not know, and which unknowns does it
//! hinge on?
//!
//! A [`study`] takes an [`Experiment`] (a scenario whose metric depends on
//! uncertain parameters) and a threshold, and runs, in order:
//!
//! 1. the **nominal** point, replicated over the seeds;
//! 2. a **space-filling sample** of the joint region ([`params::Region`]:
//!    priors and copula correlations), scrambled Sobol points
//!    ([`sample::sobol`]), each a replicated experiment on the *same* seeds
//!    (common random numbers across points, so differences between points
//!    are not seed noise). The **robust-pass fraction** is the share of
//!    points that pass, with a Wilson 95% interval; points are drawn from
//!    the prior, so it is the prior-weighted pass probability;
//! 3. **Morris screening** ([`morris`]), r(k + 1) more replicated runs:
//!    the ranking of parameters by μ*;
//! 4. a **Gaussian-process emulator** ([`surrogate::Gp`]) fitted on the
//!    space-filling runs, checked by leave-one-out and on the Morris runs
//!    as a held-out set;
//! 5. **Sobol first-order and total indices** on the emulator
//!    ([`sobol::indices`]) with bootstrap intervals;
//! 6. a **worst-case search** on the emulator ([`search::cma_es`], several
//!    starts), then the point found **confirmed with replicated runs** on
//!    fresh seeds. The verdict is called robust only if every sampled
//!    point and the confirmed worst case pass, and the report says the
//!    worst case was found by search, not proven.
//!
//! Three-corner (pessimistic/nominal/optimistic) sweeps are not used as a
//! gate: independent corners stack into a jointly implausible world and
//! miss interior and interaction worst cases (sim-fidelity §8, item 11).

pub mod morris;
pub mod params;
pub mod sample;
pub mod search;
pub mod sobol;
pub mod surrogate;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::report::fmt;
use crate::stats::{Rng, wilson};
use params::Region;

/// A scenario metric as a function of uncertain parameters.
pub trait Experiment: Sync {
    fn name(&self) -> String;
    fn region(&self) -> &Region;
    /// The metric's name and unit, for reports ("delivery (of feasible) %").
    fn metric(&self) -> String;
    /// One replication: the metric at parameter values `x` (in the
    /// region's order and units) on `seed`.
    fn run(&self, x: &[f64], seed: u64) -> f64;
}

/// How much to run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    /// Space-filling points (a power of two keeps the Sobol net property).
    pub points: usize,
    /// Seeds every point is replicated on (the same at every point).
    pub seeds: Vec<u64>,
    /// Morris trajectories (0 = no screening).
    pub morris_r: usize,
    pub threshold: f64,
    /// The metric passes at or above the threshold (delivery), or at or
    /// below it (latency).
    pub higher_is_better: bool,
    /// Fresh seeds for confirming the worst case.
    pub confirm_seeds: Vec<u64>,
    /// Base rows for the Sobol indices on the emulator.
    pub sobol_n: usize,
    pub boots: usize,
    /// Seeds the design's scrambling, trajectories and searches.
    pub seed: u64,
}

/// One replicated point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Point {
    /// Prior quantiles (joint), the emulator's inputs.
    pub q: Vec<f64>,
    /// Parameter values.
    pub x: Vec<f64>,
    /// The metric on each seed.
    pub values: Vec<f64>,
    pub mean: f64,
    pub pass: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmulatorReport {
    pub loo: surrogate::Loo,
    /// RMSE on the Morris runs, which the emulator was not fitted on.
    pub holdout_rmse: Option<f64>,
    pub holdout_n: usize,
    /// (parameter, fitted length scale on its prior-quantile axis).
    pub length: Vec<(String, f64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Worst {
    pub q: Vec<f64>,
    pub x: Vec<f64>,
    /// What the emulator predicted there.
    pub predicted: f64,
    /// The confirmation runs (fresh seeds).
    pub confirmed: Vec<f64>,
    pub confirmed_mean: f64,
    pub pass: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Study {
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub higher_is_better: bool,
    pub region: Region,
    pub plan: Plan,
    pub nominal: Point,
    pub points: Vec<Point>,
    /// (passing points, points, Wilson 95% interval of the pass share).
    pub robust_pass: (usize, usize, (f64, f64)),
    pub morris: Vec<morris::Effect>,
    pub emulator: Option<EmulatorReport>,
    pub sobol: Vec<sobol::Index>,
    /// The worst sampled point.
    pub worst_sampled: Option<Point>,
    /// The worst point the search found on the emulator, confirmed.
    pub worst_searched: Option<Worst>,
    /// Every sampled point and the confirmed worst case pass.
    pub robust: bool,
    pub runs: usize,
    pub wall_s: f64,
}

impl Plan {
    fn passes(&self, v: f64) -> bool {
        v.is_finite() && if self.higher_is_better { v >= self.threshold } else { v <= self.threshold }
    }
}

fn mean(v: &[f64]) -> f64 {
    let f: Vec<f64> = v.iter().copied().filter(|x| x.is_finite()).collect();
    if f.len() < v.len() || f.is_empty() { f64::NAN } else { f.iter().sum::<f64>() / f.len() as f64 }
}

/// Run every (x, seed) job in parallel; values in job order.
fn run_all(e: &dyn Experiment, jobs: &[(Vec<f64>, u64)]) -> Vec<f64> {
    jobs.par_iter().map(|(x, s)| e.run(x, *s)).collect()
}

/// Replicate each point on `seeds`.
fn replicate(e: &dyn Experiment, plan: &Plan, qs: &[Vec<f64>], xs: &[Vec<f64>], seeds: &[u64]) -> Vec<Point> {
    let jobs: Vec<(Vec<f64>, u64)> = xs.iter().flat_map(|x| seeds.iter().map(move |s| (x.clone(), *s))).collect();
    let vals = run_all(e, &jobs);
    qs.iter()
        .zip(xs)
        .zip(vals.chunks(seeds.len().max(1)))
        .map(|((q, x), v)| {
            let m = mean(v);
            Point { q: q.clone(), x: x.clone(), values: v.to_vec(), mean: m, pass: plan.passes(m) }
        })
        .collect()
}

/// Run the whole study (module docs).
pub fn study(e: &dyn Experiment, plan: &Plan) -> anyhow::Result<Study> {
    let t = std::time::Instant::now();
    let region = e.region().clone();
    let k = region.dims();
    anyhow::ensure!(k >= 1, "a study needs at least one uncertain parameter");
    anyhow::ensure!(!plan.seeds.is_empty() && plan.points >= 4, "a study needs seeds and at least 4 points");
    let names: Vec<String> = region.params.iter().map(|p| p.name.clone()).collect();
    let mut runs = 0;
    // 1. nominal
    let xn = region.nominal();
    let qn: Vec<f64> = region.params.iter().zip(&xn).map(|(p, x)| p.unit_of(*x)).collect();
    let nominal = replicate(e, plan, std::slice::from_ref(&qn), std::slice::from_ref(&xn), &plan.seeds).remove(0);
    runs += plan.seeds.len();
    // 2. space-filling sample of the joint region
    let qs: Vec<Vec<f64>> = sample::sobol(plan.points, k, plan.seed).iter().map(|u| region.joint(u)).collect();
    let xs: Vec<Vec<f64>> = qs.iter().map(|q| region.values(q)).collect();
    let points = replicate(e, plan, &qs, &xs, &plan.seeds);
    runs += points.len() * plan.seeds.len();
    let passing = points.iter().filter(|p| p.pass).count();
    let robust_pass = (passing, points.len(), wilson(passing, points.len(), 1.96));
    // 3. Morris on independent marginals
    let mut rng = Rng::new(plan.seed ^ 0x6d6f_7272_6973);
    let (morris, held_out) = if plan.morris_r > 0 {
        let trajs = morris::trajectories(k, plan.morris_r, &mut rng);
        let tq: Vec<Vec<f64>> = trajs.iter().flat_map(|t| t.points.clone()).collect();
        let tx: Vec<Vec<f64>> = tq.iter().map(|q| region.values(q)).collect();
        let tp = replicate(e, plan, &tq, &tx, &plan.seeds);
        runs += tp.len() * plan.seeds.len();
        let y: Vec<Vec<f64>> = tp.chunks(k + 1).map(|c| c.iter().map(|p| p.mean).collect()).collect();
        (morris::effects(&trajs, &y, &names, &mut rng), tp)
    } else {
        (Vec::new(), Vec::new())
    };
    // 4. emulator on the space-filling runs
    let fit: Vec<&Point> = points.iter().filter(|p| p.mean.is_finite()).collect();
    let gp = if fit.len() >= 4 {
        let xq: Vec<Vec<f64>> = fit.iter().map(|p| p.q.clone()).collect();
        let y: Vec<f64> = fit.iter().map(|p| p.mean).collect();
        surrogate::Gp::fit(&xq, &y).ok()
    } else {
        None
    };
    let emulator = gp.as_ref().map(|g| {
        let ho: Vec<&Point> = held_out.iter().filter(|p| p.mean.is_finite()).collect();
        let holdout_rmse = (!ho.is_empty())
            .then(|| (ho.iter().map(|p| (g.mean(&p.q) - p.mean).powi(2)).sum::<f64>() / ho.len() as f64).sqrt());
        EmulatorReport {
            loo: g.loo(),
            holdout_rmse,
            holdout_n: ho.len(),
            length: names.iter().cloned().zip(g.length.iter().copied()).collect(),
        }
    });
    // 5. Sobol indices on the emulator
    let sobol = match &gp {
        Some(g) => sobol::indices(&|q: &[f64]| g.mean(q), &names, plan.sobol_n, plan.boots, &mut rng),
        None => Vec::new(),
    };
    // 6. worst case: on the emulator, then confirmed
    let worst_sampled = points
        .iter()
        .filter(|p| p.mean.is_finite())
        .min_by(|a, b| {
            let s = if plan.higher_is_better { 1.0 } else { -1.0 };
            (s * a.mean).total_cmp(&(s * b.mean))
        })
        .cloned()
        .or_else(|| points.iter().find(|p| !p.mean.is_finite()).cloned());
    let worst_searched = match &gp {
        Some(g) => {
            let sign = if plan.higher_is_better { 1.0 } else { -1.0 };
            let obj = |q: &[f64]| sign * g.mean(q);
            // start from the worst sampled points and the centre
            let mut starts: Vec<Vec<f64>> = {
                let mut v: Vec<&Point> = fit.clone();
                v.sort_by(|a, b| (sign * a.mean).total_cmp(&(sign * b.mean)));
                v.iter().take(3).map(|p| p.q.clone()).collect()
            };
            starts.push(vec![0.5; k]);
            let best = starts
                .iter()
                .map(|s| search::cma_es(&obj, s, 0.25, 1500 * k.max(2), &mut rng))
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .expect("starts");
            let q = best.0;
            let x = region.values(&q);
            let confirmed = run_all(e, &plan.confirm_seeds.iter().map(|s| (x.clone(), *s)).collect::<Vec<_>>());
            runs += confirmed.len();
            let m = mean(&confirmed);
            Some(Worst { predicted: g.mean(&q), q, x, pass: plan.passes(m), confirmed_mean: m, confirmed })
        }
        None => None,
    };
    let robust = nominal.pass && passing == points.len() && worst_searched.as_ref().is_none_or(|w| w.pass);
    Ok(Study {
        name: e.name(),
        metric: e.metric(),
        threshold: plan.threshold,
        higher_is_better: plan.higher_is_better,
        region,
        plan: plan.clone(),
        nominal,
        points,
        robust_pass,
        morris,
        emulator,
        sobol,
        worst_sampled,
        worst_searched,
        robust,
        runs,
        wall_s: t.elapsed().as_secs_f64(),
    })
}

impl Study {
    /// "12/16 (Wilson 49–92%)".
    pub fn robust_pass_label(&self) -> String {
        let (k, n, (lo, hi)) = self.robust_pass;
        format!("{k}/{n} of the region pass (Wilson 95% {:.0}–{:.0}%)", 100.0 * lo, 100.0 * hi)
    }

    /// The parameters the verdict depends on: total Sobol index ≥ 0.1, by
    /// rank; Morris's ranking where there is no emulator.
    pub fn hinges_on(&self) -> Vec<String> {
        if self.sobol.is_empty() {
            return self.morris.iter().take(2).map(|e| e.name.clone()).collect();
        }
        self.sobol.iter().filter(|i| i.total >= 0.1).map(|i| i.name.clone()).collect()
    }

    pub fn markdown(&self) -> String {
        let cmp = if self.higher_is_better { "≥" } else { "≤" };
        let xs = |x: &[f64]| -> String {
            self.region
                .params
                .iter()
                .zip(x)
                .map(|(p, v)| format!("{} {}", p.name, fmt(*v)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut s = format!(
            "## Robustness of `{}`: {} {cmp} {}\n\nVerdict: **{}**. {}. Worst case found by search on the emulator and confirmed with {} fresh seeds (a search, not a proof). {} replicated runs, {:.0} s wall.\n\n",
            self.name,
            self.metric,
            fmt(self.threshold),
            if self.robust { "robust over the region" } else { "not robust over the region" },
            self.robust_pass_label(),
            self.plan.confirm_seeds.len(),
            self.runs,
            self.wall_s
        );
        s.push_str(&format!("Region ({}):\n\n{}\n", self.region.label(), self.region.describe()));
        s.push_str(&format!(
            "Nominal ({}): {} on {} seeds ({}).\n\n",
            xs(&self.nominal.x),
            fmt(self.nominal.mean),
            self.nominal.values.len(),
            if self.nominal.pass { "pass" } else { "fail" }
        ));
        if let Some(w) = &self.worst_sampled {
            s.push_str(&format!("Worst sampled point: {} at {}.\n\n", fmt(w.mean), xs(&w.x)));
        }
        if let Some(w) = &self.worst_searched {
            s.push_str(&format!(
                "Worst case searched: emulator predicted {}, confirmed {} ({}) at {}.\n\n",
                fmt(w.predicted),
                fmt(w.confirmed_mean),
                if w.pass { "pass" } else { "fail" },
                xs(&w.x)
            ));
        }
        if !self.morris.is_empty() {
            s.push_str("Morris screening (μ* with 95% bootstrap interval, σ):\n\n| Parameter | μ* | interval | μ | σ |\n|---|---:|---|---:|---:|\n");
            for e in &self.morris {
                s.push_str(&format!(
                    "| `{}` | {} | {}–{} | {} | {} |\n",
                    e.name,
                    fmt(e.mu_star),
                    fmt(e.mu_star_ci.0),
                    fmt(e.mu_star_ci.1),
                    fmt(e.mu),
                    fmt(e.sigma)
                ));
            }
            s.push('\n');
        }
        if let Some(em) = &self.emulator {
            s.push_str(&format!(
                "Emulator (GP, Matérn 5/2 ARD) on {} points: leave-one-out RMSE {}, Q² {:.2}, 95% coverage {:.0}%{}.\n\n",
                em.loo.n,
                fmt(em.loo.rmse),
                em.loo.q2,
                100.0 * em.loo.coverage95,
                em.holdout_rmse
                    .map_or(String::new(), |r| format!("; held-out RMSE on {} Morris runs {}", em.holdout_n, fmt(r)))
            ));
        }
        if !self.sobol.is_empty() {
            s.push_str("Sobol indices on the emulator (95% bootstrap intervals):\n\n| Parameter | first order | total |\n|---|---|---|\n");
            for i in &self.sobol {
                s.push_str(&format!(
                    "| `{}` | {} [{} – {}] | {} [{} – {}] |\n",
                    i.name,
                    fmt(i.first),
                    fmt(i.first_ci.0),
                    fmt(i.first_ci.1),
                    fmt(i.total),
                    fmt(i.total_ci.0),
                    fmt(i.total_ci.1)
                ));
            }
            s.push('\n');
        }
        let h = self.hinges_on();
        s.push_str(&format!(
            "Hinges on: {}.\n",
            if h.is_empty() { "no single parameter (all total indices < 0.1)".to_string() } else { h.join(", ") }
        ));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use params::{Dist, Param};

    /// A toy experiment: y = 100 − 30 a² − 5 b + noise(seed), c inert.
    struct Toy(Region);

    impl Experiment for Toy {
        fn name(&self) -> String {
            "toy".into()
        }
        fn region(&self) -> &Region {
            &self.0
        }
        fn metric(&self) -> String {
            "y".into()
        }
        fn run(&self, x: &[f64], seed: u64) -> f64 {
            let mut r = Rng::new(seed);
            100.0 - 30.0 * x[0] * x[0] - 5.0 * x[1] + 0.5 * r.normal()
        }
    }

    fn toy() -> Toy {
        let p = |n: &str| Param {
            name: n.into(),
            lo: 0.0,
            hi: 1.0,
            nominal: 0.2,
            dist: Dist::Uniform,
            unit: String::new(),
            source: "test".into(),
        };
        Toy(Region::new(vec![p("a"), p("b"), p("c")], Vec::new()).unwrap())
    }

    fn plan(threshold: f64) -> Plan {
        Plan {
            points: 32,
            seeds: vec![1, 2, 3],
            morris_r: 8,
            threshold,
            higher_is_better: true,
            confirm_seeds: vec![11, 12, 13, 14],
            sobol_n: 2048,
            boots: 50,
            seed: 7,
        }
    }

    #[test]
    fn a_study_finds_what_the_metric_hinges_on_and_its_worst_case() {
        let s = study(&toy(), &plan(60.0)).unwrap();
        assert!(s.robust, "worst case is 65, above 60: {}", s.markdown());
        assert_eq!(s.morris[0].name, "a");
        assert_eq!(s.sobol[0].name, "a");
        assert!(s.hinges_on().contains(&"a".to_string()) && !s.hinges_on().contains(&"c".to_string()));
        let w = s.worst_searched.as_ref().unwrap();
        assert!(w.x[0] > 0.9 && w.x[1] > 0.8, "worst at a, b high: {:?}", w.x);
        assert!((w.confirmed_mean - 65.0).abs() < 1.5, "{}", w.confirmed_mean);
        assert_eq!(s.runs, 3 + 32 * 3 + 8 * 4 * 3 + 4);
        // a threshold the corner misses: not robust, though most of the region passes
        let s = study(&toy(), &plan(72.0)).unwrap();
        assert!(!s.robust && s.robust_pass.0 > s.robust_pass.1 / 2, "{}", s.robust_pass_label());
        assert!(s.markdown().contains("not robust"));
    }
}
