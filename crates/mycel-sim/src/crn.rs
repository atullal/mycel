//! `mycel-sim crn`: what common random numbers buy when comparing two
//! routing models (docs/SIMULATION.md §1, "World and streams").
//!
//! Each scenario runs the candidate (A) beside a reference model (B) on
//! one world. The difference A − B of a metric is sampled three ways over
//! `k` seeds:
//!
//! - **CRN**: A and B on the same seed: the same exogenous world and the
//!   same endogenous draws (the paired comparison every scenario makes);
//! - **same world**: A on seed i, B on seed i with its endogenous streams
//!   salted ([`crate::world::streams::set_endogenous_salt`]): the world is
//!   shared, the protocol draws are independent;
//! - **independent**: A on seed i, B on seed k + i: nothing shared.
//!
//! Var(A − B) = Var(A) + Var(B) − 2 Cov(A, B): the ratio of the
//! independent variance to the CRN variance is the factor by which pairing
//! cuts the seeds a comparison needs for the same precision (Law,
//! *Simulation Modeling and Analysis*, ch. 11).

use serde::{Deserialize, Serialize};

use crate::report::ScenarioResult;
use crate::scenarios::Candidate;
use crate::seeds::replicate;
use crate::stats::run_seeds;
use crate::world::streams::set_endogenous_salt;

/// The scenarios measured by default, each with its reference model.
pub const DEFAULT: &[(&str, f64, &str)] = &[
    ("churn", 0.05, "main (mesh before GLOBAL)"),
    ("disaster-dtn", 0.1, "epidemic"),
    ("trace-replay", 0.05, "epidemic"),
];

/// The metrics compared.
const METRICS: &[(&str, &str)] =
    &[("delivery (% of feasible)", "delivery"), ("latency p50 (s)", "p50"), ("latency p95 (s)", "p95")];

/// One scenario and metric: the variance of A − B under each sampling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub scenario: String,
    pub scale: f64,
    pub a: String,
    pub b: String,
    pub metric: String,
    pub n: usize,
    pub mean_diff: f64,
    pub var_crn: f64,
    pub var_same_world: f64,
    pub var_independent: f64,
}

impl Row {
    /// How many times fewer seeds CRN needs than independent sampling.
    pub fn reduction(&self) -> f64 {
        self.var_independent / self.var_crn
    }
}

/// A metric of a model in a scenario's result, if it ran.
fn metric(r: &ScenarioResult, model: &str, key: &str) -> Option<f64> {
    let runs = r.metrics.as_array()?;
    let m = runs.iter().map(|x| &x["metrics"]).find(|m| m["model"] == model)?;
    let v = match key {
        "delivery" => 100.0 * m["delivery_ratio"].as_f64()?,
        "p50" => m["latency_s"]["p50"].as_f64()?,
        _ => m["latency_s"]["p95"].as_f64()?,
    };
    v.is_finite().then_some(v)
}

fn variance(xs: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0)
}

/// Measure `name` at `scale` on `k` seeds from `base`, A = the GLOBAL
/// core + DTN, B = `b`.
pub fn measure(name: &str, scale: f64, b: &str, base: u64, k: usize) -> Vec<Row> {
    let a = crate::scenarios::t2::Model::of(Candidate::Global).name();
    let seeds = run_seeds(base, 2 * k);
    let (same, other) = seeds.split_at(k);
    set_endogenous_salt(0);
    let paired = replicate(name, scale, same, Candidate::Global);
    let independent = replicate(name, scale, other, Candidate::Global);
    set_endogenous_salt(1);
    let salted = replicate(name, scale, same, Candidate::Global);
    set_endogenous_salt(0);
    METRICS
        .iter()
        .filter_map(|(label, key)| {
            let mut d = (Vec::new(), Vec::new(), Vec::new());
            for i in 0..k {
                let (Some(ai), Some(bi), Some(bw), Some(bx)) = (
                    metric(&paired[i], &a, key),
                    metric(&paired[i], b, key),
                    metric(&salted[i], b, key),
                    metric(&independent[i], b, key),
                ) else {
                    continue;
                };
                d.0.push(ai - bi);
                d.1.push(ai - bw);
                d.2.push(ai - bx);
            }
            (d.0.len() >= 3).then(|| Row {
                scenario: name.into(),
                scale,
                a: a.clone(),
                b: b.into(),
                metric: (*label).into(),
                n: d.0.len(),
                mean_diff: d.0.iter().sum::<f64>() / d.0.len() as f64,
                var_crn: variance(&d.0),
                var_same_world: variance(&d.1),
                var_independent: variance(&d.2),
            })
        })
        .collect()
}

/// The rows as a Markdown table.
pub fn markdown(rows: &[Row]) -> String {
    let mut s = String::from(
        "| Scenario (scale) | A − B | Metric | n | mean A − B | Var CRN | Var same world | Var independent | independent / CRN |\n|---|---|---|---:|---:|---:|---:|---:|---:|\n",
    );
    for r in rows {
        s.push_str(&format!(
            "| `{}` ({}) | {} − {} | {} | {} | {:.4} | {:.4} | {:.4} | {:.4} | {} |\n",
            r.scenario,
            r.scale,
            r.a,
            r.b,
            r.metric,
            r.n,
            r.mean_diff,
            r.var_crn,
            r.var_same_world,
            r.var_independent,
            if r.var_crn > 0.0 { format!("{:.1}×", r.reduction()) } else { "∞ (no CRN variance)".into() }
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_variance() {
        assert!((variance(&[1.0, 2.0, 3.0, 4.0]) - 5.0 / 3.0).abs() < 1e-12);
    }
}
