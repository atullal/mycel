//! Variance-based (Sobol') sensitivity indices, estimated by Monte Carlo
//! with the Saltelli design (A. Saltelli et al., "Variance based
//! sensitivity analysis of model output. Design and estimator for the
//! total sensitivity index", Comput. Phys. Commun. 181, 2010):
//!
//! - first order Sᵢ = V[E(Y | Xᵢ)] / V(Y), estimator (Saltelli 2010, table
//!   2 (b)): (1/N) Σ f(B)ⱼ (f(A_Bⁱ)ⱼ − f(A)ⱼ) / V;
//! - total STᵢ = E[V(Y | X₋ᵢ)] / V(Y), Jansen's estimator (Jansen 1999,
//!   table 2 (f)): (1/2N) Σ (f(A)ⱼ − f(A_Bⁱ)ⱼ)² / V;
//!
//! with A, B independent N × k uniform matrices and A_Bⁱ = A with column i
//! from B: N(k + 2) evaluations. Every output is first centred on the mean
//! of f(A) and f(B): the first-order estimator is unbiased under a constant
//! shift of f, but its variance grows with the square of the output's mean
//! (about (mean / sd)²-fold: some 300-fold for a delivery ratio near 90
//! with a spread of 5; regression test below). Centring
//! the pairs of evaluations is what Sobol' and Myshetskaya (2007) found
//! most effective (A. B. Owen, "Better estimation of small Sobol'
//! sensitivity indices", ACM TOMACS 23, 2013, §2). Intervals are percentile bootstraps over
//! the N rows. Inputs are independent uniforms on [0, 1]^k: Sobol indices
//! are defined for independent inputs. Applied to the emulator, which is
//! cheap, the intervals cover the Monte Carlo error of the indices on the
//! emulator's mean, not the emulator's own error (its leave-one-out error
//! is reported beside them).

use serde::{Deserialize, Serialize};

use crate::stats::Rng;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Index {
    pub factor: usize,
    pub name: String,
    pub first: f64,
    pub first_ci: (f64, f64),
    pub total: f64,
    pub total_ci: (f64, f64),
}

/// Indices of `f` over [0, 1]^k with `n` base rows and `boots` bootstrap
/// resamples, ranked by total index (largest first).
pub fn indices(f: &dyn Fn(&[f64]) -> f64, names: &[String], n: usize, boots: usize, rng: &mut Rng) -> Vec<Index> {
    let k = names.len();
    let a: Vec<Vec<f64>> = (0..n).map(|_| (0..k).map(|_| rng.f64()).collect()).collect();
    let b: Vec<Vec<f64>> = (0..n).map(|_| (0..k).map(|_| rng.f64()).collect()).collect();
    let fa: Vec<f64> = a.iter().map(|x| f(x)).collect();
    let fb: Vec<f64> = b.iter().map(|x| f(x)).collect();
    // centre every output (module docs)
    let centre = (fa.iter().sum::<f64>() + fb.iter().sum::<f64>()) / (2 * n).max(1) as f64;
    let fa: Vec<f64> = fa.iter().map(|v| v - centre).collect();
    let fb: Vec<f64> = fb.iter().map(|v| v - centre).collect();
    let fab: Vec<Vec<f64>> = (0..k)
        .map(|i| {
            a.iter()
                .zip(&b)
                .map(|(ra, rb)| {
                    let mut x = ra.clone();
                    x[i] = rb[i];
                    f(&x) - centre
                })
                .collect()
        })
        .collect();
    // (first, total) on a resample of rows
    let estimate = |rows: &[usize]| -> Vec<(f64, f64)> {
        let m = rows.len() as f64;
        let all: Vec<f64> = rows.iter().flat_map(|j| [fa[*j], fb[*j]]).collect();
        let mean = all.iter().sum::<f64>() / all.len() as f64;
        let var = (all.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / all.len() as f64).max(1e-300);
        (0..k)
            .map(|i| {
                let s1 = rows.iter().map(|j| fb[*j] * (fab[i][*j] - fa[*j])).sum::<f64>() / m / var;
                let st = rows.iter().map(|j| (fa[*j] - fab[i][*j]).powi(2)).sum::<f64>() / (2.0 * m) / var;
                (s1, st)
            })
            .collect()
    };
    let all: Vec<usize> = (0..n).collect();
    let point = estimate(&all);
    let mut bs: Vec<Vec<(f64, f64)>> = Vec::with_capacity(boots);
    for _ in 0..boots {
        let rows: Vec<usize> = (0..n).map(|_| rng.below(n)).collect();
        bs.push(estimate(&rows));
    }
    let ci = |vals: &mut Vec<f64>| -> (f64, f64) {
        vals.sort_by(f64::total_cmp);
        if vals.is_empty() {
            return (f64::NAN, f64::NAN);
        }
        let q = |p: f64| vals[((p * (vals.len() - 1) as f64).round() as usize).min(vals.len() - 1)];
        (q(0.025), q(0.975))
    };
    let mut out: Vec<Index> = (0..k)
        .map(|i| {
            let mut f1: Vec<f64> = bs.iter().map(|e| e[i].0).collect();
            let mut ft: Vec<f64> = bs.iter().map(|e| e[i].1).collect();
            Index {
                factor: i,
                name: names[i].clone(),
                first: point[i].0,
                first_ci: ci(&mut f1),
                total: point[i].1,
                total_ci: ci(&mut ft),
            }
        })
        .collect();
    out.sort_by(|x, y| y.total.total_cmp(&x.total));
    out
}

/// The Ishigami function on [0, 1]³ mapped to [−π, π]³, a = 7, b = 0.1
/// (Ishigami & Homma 1990), the standard check for Sobol estimators.
pub fn ishigami(u: &[f64]) -> f64 {
    let x: Vec<f64> = u.iter().map(|v| std::f64::consts::PI * (2.0 * v - 1.0)).collect();
    x[0].sin() + 7.0 * x[1].sin().powi(2) + 0.1 * x[2].powi(4) * x[0].sin()
}

/// Ishigami's analytic indices (a = 7, b = 0.1): (S₁, S₂, S₃), (ST₁, ST₂, ST₃).
pub const ISHIGAMI_FIRST: [f64; 3] = [0.3139, 0.4424, 0.0];
pub const ISHIGAMI_TOTAL: [f64; 3] = [0.5576, 0.4424, 0.2437];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uq::sample::sobol;
    use crate::uq::surrogate::Gp;

    fn names() -> Vec<String> {
        (1..=3).map(|i| format!("x{i}")).collect()
    }

    #[test]
    fn ishigami_indices_match_the_analytic_values() {
        let mut rng = Rng::new(2026);
        let idx = indices(&ishigami, &names(), 1 << 14, 200, &mut rng);
        for e in &idx {
            let (s1, st) = (ISHIGAMI_FIRST[e.factor], ISHIGAMI_TOTAL[e.factor]);
            assert!((e.first - s1).abs() < 0.03, "S{} {} vs {s1}", e.factor + 1, e.first);
            assert!((e.total - st).abs() < 0.03, "ST{} {} vs {st}", e.factor + 1, e.total);
            assert!(e.first_ci.0 <= e.first_ci.1 && e.total_ci.0 <= e.total && e.total <= e.total_ci.1);
            assert!(
                e.first_ci.0 - 0.01 <= s1 && s1 <= e.first_ci.1 + 0.01,
                "S{} interval {:?}",
                e.factor + 1,
                e.first_ci
            );
        }
        assert_eq!(idx[0].name, "x1", "x1 has the largest total index");
    }

    /// Regression: a metric far from zero (a delivery ratio near 90 %)
    /// must not widen the intervals. Before outputs were centred, the
    /// Ishigami function plus 1000 at 4,096 rows gave S₁ = −3.8 ± 8.7
    /// (95%) against 0.28 ± 0.045 without the offset (computed with the
    /// same design).
    #[test]
    fn a_large_mean_does_not_widen_the_intervals() {
        let shifted = |u: &[f64]| 1000.0 + ishigami(u);
        let (mut r1, mut r2) = (Rng::new(77), Rng::new(77));
        let plain = indices(&ishigami, &names(), 1 << 12, 100, &mut r1);
        let far = indices(&shifted, &names(), 1 << 12, 100, &mut r2);
        for (p, f) in plain.iter().zip(&far) {
            assert_eq!(p.factor, f.factor);
            assert!((p.first - f.first).abs() < 1e-6 && (p.total - f.total).abs() < 1e-6, "{p:?} vs {f:?}");
            let width = f.first_ci.1 - f.first_ci.0;
            assert!(width < 0.15, "S{} interval {:?}", f.factor + 1, f.first_ci);
            assert!((f.first - ISHIGAMI_FIRST[f.factor]).abs() < 0.06, "S{} {}", f.factor + 1, f.first);
        }
    }

    /// The emulator route the studies use: fit a GP on 256 space-filling
    /// runs, take the indices on its mean. Looser, since the GP carries its
    /// own error (reported as leave-one-out).
    #[test]
    fn ishigami_indices_through_the_emulator() {
        let x = sobol(256, 3, 5);
        let y: Vec<f64> = x.iter().map(|p| ishigami(p)).collect();
        let gp = Gp::fit(&x, &y).unwrap();
        let loo = gp.loo();
        assert!(loo.q2 > 0.95, "{loo:?}");
        let mut rng = Rng::new(9);
        let idx = indices(&|p: &[f64]| gp.mean(p), &names(), 1 << 13, 100, &mut rng);
        for e in &idx {
            assert!((e.first - ISHIGAMI_FIRST[e.factor]).abs() < 0.06, "S{} {}", e.factor + 1, e.first);
            assert!((e.total - ISHIGAMI_TOTAL[e.factor]).abs() < 0.06, "ST{} {}", e.factor + 1, e.total);
        }
    }
}
