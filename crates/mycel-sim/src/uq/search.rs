//! Optimisers: Nelder–Mead for emulator hyperparameters, and a
//! separable CMA-ES for the worst-case search inside the uncertainty
//! region.
//!
//! - Nelder–Mead (Nelder & Mead, Comput. J. 7, 1965) with the standard
//!   coefficients (reflection 1, expansion 2, contraction ½, shrink ½).
//! - sep-CMA-ES (R. Ros and N. Hansen, "A simple modification in CMA-ES
//!   achieving linear time and space complexity", PPSN 2008): CMA-ES with a
//!   diagonal covariance, default strategy parameters from N. Hansen, "The
//!   CMA Evolution Strategy: A Tutorial" (arXiv:1604.00772, table 1), the
//!   rank-one and rank-μ rates scaled by (k + 2)/3 as Ros & Hansen give.
//!   The box [0, 1]^k is handled by evaluating the clamped point and adding
//!   a quadratic penalty for the distance outside, a common and simple
//!   boundary treatment (Hansen's tutorial, appendix B).
//!
//! The worst case is searched on the emulator, which is cheap, and then
//! confirmed with full replicated runs ([`super::study`]): a point found by
//! search, not a proven worst case.

use crate::stats::Rng;

/// Minimise `f` from `start` with initial simplex step `step`; at most
/// `max_evals` evaluations. Returns (argmin, min).
pub fn nelder_mead(f: &dyn Fn(&[f64]) -> f64, start: &[f64], step: f64, max_evals: usize) -> (Vec<f64>, f64) {
    let k = start.len();
    let mut simplex: Vec<(Vec<f64>, f64)> = Vec::with_capacity(k + 1);
    simplex.push((start.to_vec(), f(start)));
    for i in 0..k {
        let mut p = start.to_vec();
        p[i] += step;
        let v = f(&p);
        simplex.push((p, v));
    }
    let mut evals = k + 1;
    let sort = |s: &mut Vec<(Vec<f64>, f64)>| s.sort_by(|a, b| a.1.total_cmp(&b.1));
    while evals < max_evals {
        sort(&mut simplex);
        let spread = simplex[k].1 - simplex[0].1;
        if spread.abs() < 1e-10 && evals > 4 * (k + 1) {
            break;
        }
        let centroid: Vec<f64> = (0..k).map(|d| simplex[..k].iter().map(|p| p.0[d]).sum::<f64>() / k as f64).collect();
        let along =
            |t: f64| -> Vec<f64> { (0..k).map(|d| centroid[d] + t * (simplex[k].0[d] - centroid[d])).collect() };
        let xr = along(-1.0);
        let fr = f(&xr);
        evals += 1;
        if fr < simplex[0].1 {
            let xe = along(-2.0);
            let fe = f(&xe);
            evals += 1;
            simplex[k] = if fe < fr { (xe, fe) } else { (xr, fr) };
        } else if fr < simplex[k - 1].1 {
            simplex[k] = (xr, fr);
        } else {
            let (xc, fc) = if fr < simplex[k].1 {
                let x = along(-0.5);
                let v = f(&x);
                (x, v)
            } else {
                let x = along(0.5);
                let v = f(&x);
                (x, v)
            };
            evals += 1;
            if fc < simplex[k].1.min(fr) {
                simplex[k] = (xc, fc);
            } else {
                let best = simplex[0].0.clone();
                for p in simplex.iter_mut().skip(1) {
                    let x: Vec<f64> = p.0.iter().zip(&best).map(|(a, b)| b + 0.5 * (a - b)).collect();
                    let v = f(&x);
                    *p = (x, v);
                }
                evals += k;
            }
        }
    }
    sort(&mut simplex);
    simplex.swap_remove(0)
}

/// Minimise `f` over [0, 1]^k by sep-CMA-ES from `start` with step size
/// `sigma`, at most `max_evals` evaluations. Returns (argmin, min), the
/// argmin inside the box.
pub fn cma_es(
    f: &dyn Fn(&[f64]) -> f64,
    start: &[f64],
    sigma: f64,
    max_evals: usize,
    rng: &mut Rng,
) -> (Vec<f64>, f64) {
    let k = start.len();
    let kf = k as f64;
    let lambda = 4 + (3.0 * kf.ln()).floor() as usize;
    let mu = lambda / 2;
    let raw: Vec<f64> = (0..mu).map(|i| (mu as f64 + 0.5).ln() - ((i + 1) as f64).ln()).collect();
    let wsum: f64 = raw.iter().sum();
    let w: Vec<f64> = raw.iter().map(|x| x / wsum).collect();
    let mueff = 1.0 / w.iter().map(|x| x * x).sum::<f64>();
    let cs = (mueff + 2.0) / (kf + mueff + 5.0);
    let ds = 1.0 + 2.0 * (((mueff - 1.0) / (kf + 1.0)).sqrt() - 1.0).max(0.0) + cs;
    let cc = (4.0 + mueff / kf) / (kf + 4.0 + 2.0 * mueff / kf);
    let sep = (kf + 2.0) / 3.0;
    let c1 = (sep * 2.0 / ((kf + 1.3).powi(2) + mueff)).min(1.0);
    let cmu = (sep * 2.0 * (mueff - 2.0 + 1.0 / mueff) / ((kf + 2.0).powi(2) + mueff)).min(1.0 - c1);
    let chi = kf.sqrt() * (1.0 - 1.0 / (4.0 * kf) + 1.0 / (21.0 * kf * kf));
    let penalised = |x: &[f64]| -> f64 {
        let inside: Vec<f64> = x.iter().map(|v| v.clamp(0.0, 1.0)).collect();
        let out: f64 = x.iter().zip(&inside).map(|(a, b)| (a - b).powi(2)).sum();
        f(&inside) + 1e3 * out
    };
    let mut m = start.to_vec();
    let mut s = sigma;
    let mut c: Vec<f64> = vec![1.0; k];
    let (mut ps, mut pc) = (vec![0.0; k], vec![0.0; k]);
    let mut best = (m.iter().map(|v| v.clamp(0.0, 1.0)).collect::<Vec<f64>>(), penalised(&m));
    let mut evals = 1;
    let mut generation = 0u32;
    while evals + lambda <= max_evals {
        generation += 1;
        let d: Vec<f64> = c.iter().map(|v| v.sqrt()).collect();
        let mut pop: Vec<(Vec<f64>, Vec<f64>, f64)> = (0..lambda)
            .map(|_| {
                let z: Vec<f64> = (0..k).map(|_| rng.normal()).collect();
                let y: Vec<f64> = z.iter().zip(&d).map(|(a, b)| a * b).collect();
                let x: Vec<f64> = m.iter().zip(&y).map(|(a, b)| a + s * b).collect();
                let v = penalised(&x);
                (y, x, v)
            })
            .collect();
        evals += lambda;
        pop.sort_by(|a, b| a.2.total_cmp(&b.2));
        if pop[0].2 < best.1 {
            best = (pop[0].1.iter().map(|v| v.clamp(0.0, 1.0)).collect(), pop[0].2);
        }
        let yw: Vec<f64> = (0..k).map(|j| (0..mu).map(|i| w[i] * pop[i].0[j]).sum()).collect();
        for j in 0..k {
            m[j] += s * yw[j];
        }
        let a = (cs * (2.0 - cs) * mueff).sqrt();
        for j in 0..k {
            ps[j] = (1.0 - cs) * ps[j] + a * yw[j] / d[j];
        }
        let psn = ps.iter().map(|x| x * x).sum::<f64>().sqrt();
        let hs = psn / (1.0 - (1.0 - cs).powi(2 * generation as i32)).sqrt() < (1.4 + 2.0 / (kf + 1.0)) * chi;
        let b = if hs { (cc * (2.0 - cc) * mueff).sqrt() } else { 0.0 };
        for j in 0..k {
            pc[j] = (1.0 - cc) * pc[j] + b * yw[j];
            let rank_mu: f64 = (0..mu).map(|i| w[i] * pop[i].0[j].powi(2)).sum();
            c[j] = ((1.0 - c1 - cmu) * c[j] + c1 * pc[j] * pc[j] + cmu * rank_mu).max(1e-20);
        }
        s *= ((cs / ds) * (psn / chi - 1.0)).exp();
        if s * d.iter().cloned().fold(0.0, f64::max) < 1e-9 {
            break;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nelder_mead_finds_the_rosenbrock_minimum() {
        let f = |x: &[f64]| (1.0 - x[0]).powi(2) + 100.0 * (x[1] - x[0] * x[0]).powi(2);
        let (x, v) = nelder_mead(&f, &[-1.2, 1.0], 0.5, 4000);
        assert!(v < 1e-6 && (x[0] - 1.0).abs() < 1e-2 && (x[1] - 1.0).abs() < 2e-2, "{x:?} {v}");
    }

    #[test]
    fn cma_es_finds_interior_and_boundary_minima() {
        let mut rng = Rng::new(1);
        let f = |x: &[f64]| x.iter().enumerate().map(|(i, v)| (v - 0.2 - 0.1 * i as f64).powi(2)).sum::<f64>();
        let (x, v) = cma_es(&f, &[0.5; 5], 0.3, 4000, &mut rng);
        assert!(v < 1e-8, "{x:?} {v}");
        // the minimum of a slope is the corner, which must be reached from inside
        let g = |x: &[f64]| x[0] - x[1] + 0.5 * x[2];
        let (x, v) = cma_es(&g, &[0.5; 3], 0.3, 3000, &mut rng);
        assert!((v + 1.0).abs() < 1e-3 && x[0] < 1e-3 && x[1] > 1.0 - 1e-3 && x[2] < 1e-3, "{x:?} {v}");
        // a multimodal function: the global minimum of a Rastrigin in 2-D
        let r = |x: &[f64]| {
            x.iter()
                .map(|v| (10.0 * v - 3.0).powi(2) - 10.0 * (std::f64::consts::TAU * (10.0 * v - 3.0)).cos())
                .sum::<f64>()
                + 20.0
        };
        let best = (0..6).map(|_| cma_es(&r, &[0.5, 0.5], 0.3, 3000, &mut rng)).min_by(|a, b| a.1.total_cmp(&b.1));
        let (x, v) = best.unwrap();
        assert!(v < 1e-3, "{x:?} {v}");
    }
}
