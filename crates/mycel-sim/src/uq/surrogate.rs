//! A Gaussian-process emulator of a scenario metric over the unit cube
//! (C. E. Rasmussen and C. K. I. Williams, *Gaussian Processes for Machine
//! Learning*, MIT Press 2006; equation numbers below are theirs).
//!
//! - Kernel: Matérn ν = 5/2 with one length scale per input (ARD) (eq.
//!   4.17), plus a noise term: a seed-averaged simulation output is noisy,
//!   and an interpolating emulator would chase that noise.
//! - Outputs are standardised; hyperparameters (log length scales, log
//!   signal and noise variances) maximise the log marginal likelihood
//!   (eq. 2.30) by Nelder–Mead from several starts ([`super::search`]).
//! - Leave-one-out predictions in closed form from the inverse covariance
//!   (eq. 5.12): μ₋ᵢ = yᵢ − [K⁻¹y]ᵢ / [K⁻¹]ᵢᵢ, σ²₋ᵢ = 1 / [K⁻¹]ᵢᵢ.
//!   Reported as RMSE and Q² = 1 − Σ(yᵢ − μ₋ᵢ)² / Σ(yᵢ − ȳ)², with the
//!   share of points whose LOO 95% interval holds them (calibration).

use serde::{Deserialize, Serialize};

use super::params::cholesky;
use super::search::nelder_mead;

#[derive(Clone, Debug)]
pub struct Gp {
    x: Vec<Vec<f64>>,
    /// L, the lower Cholesky factor of K + σₙ²I (standardised units).
    l: Vec<Vec<f64>>,
    /// (K + σₙ²I)⁻¹ y (standardised).
    alpha: Vec<f64>,
    /// The standardised outputs.
    ys: Vec<f64>,
    pub length: Vec<f64>,
    pub signal_var: f64,
    pub noise_var: f64,
    y_mean: f64,
    y_sd: f64,
    pub log_likelihood: f64,
}

/// Leave-one-out diagnostics, in the metric's own units.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Loo {
    pub n: usize,
    pub rmse: f64,
    /// 1 − SSE / SST: the share of the output's variance the emulator
    /// predicts for points it was not fitted on.
    pub q2: f64,
    /// Share of points inside their own LOO 95% predictive interval.
    pub coverage95: f64,
}

fn matern52(a: &[f64], b: &[f64], length: &[f64], var: f64) -> f64 {
    let r2: f64 = a.iter().zip(b).zip(length).map(|((x, y), l)| ((x - y) / l).powi(2)).sum();
    let r = (5.0 * r2).sqrt();
    var * (1.0 + r + r * r / 3.0) * (-r).exp()
}

fn solve_lower(l: &[Vec<f64>], b: &[f64]) -> Vec<f64> {
    let n = b.len();
    let mut x = vec![0.0; n];
    for i in 0..n {
        let s: f64 = (0..i).map(|k| l[i][k] * x[k]).sum();
        x[i] = (b[i] - s) / l[i][i];
    }
    x
}

fn solve_upper_t(l: &[Vec<f64>], b: &[f64]) -> Vec<f64> {
    // solve Lᵀ x = b
    let n = b.len();
    let mut x = vec![0.0; n];
    for i in (0..n).rev() {
        let s: f64 = (i + 1..n).map(|k| l[k][i] * x[k]).sum();
        x[i] = (b[i] - s) / l[i][i];
    }
    x
}

/// (L, α, log marginal likelihood) for hyperparameters on standardised y.
fn factor(x: &[Vec<f64>], y: &[f64], length: &[f64], sf2: f64, sn2: f64) -> Option<(Vec<Vec<f64>>, Vec<f64>, f64)> {
    let n = x.len();
    let mut k = vec![vec![0.0; n]; n];
    for i in 0..n {
        for j in 0..=i {
            let v = matern52(&x[i], &x[j], length, sf2);
            k[i][j] = v;
            k[j][i] = v;
        }
        k[i][i] += sn2 + 1e-10;
    }
    let l = cholesky(&k)?;
    let alpha = solve_upper_t(&l, &solve_lower(&l, y));
    let fit: f64 = y.iter().zip(&alpha).map(|(a, b)| a * b).sum();
    let logdet: f64 = (0..n).map(|i| l[i][i].ln()).sum();
    let lml = -0.5 * fit - logdet - 0.5 * n as f64 * (std::f64::consts::TAU).ln();
    Some((l, alpha, lml))
}

impl Gp {
    /// Fit on inputs in [0, 1]^k and outputs `y` (finite).
    pub fn fit(x: &[Vec<f64>], y: &[f64]) -> anyhow::Result<Gp> {
        anyhow::ensure!(x.len() == y.len() && x.len() >= 3, "a surrogate needs at least 3 points");
        anyhow::ensure!(y.iter().all(|v| v.is_finite()), "surrogate outputs must be finite");
        let k = x[0].len();
        let n = y.len() as f64;
        let y_mean = y.iter().sum::<f64>() / n;
        let y_sd = (y.iter().map(|v| (v - y_mean).powi(2)).sum::<f64>() / n).sqrt().max(1e-9);
        let ys: Vec<f64> = y.iter().map(|v| (v - y_mean) / y_sd).collect();
        // θ = (log ℓ₁..ℓₖ, log σf², log σn²), each clamped to a sane box
        let bounds = |i: usize| -> (f64, f64) {
            if i < k {
                (0.03f64.ln(), 20f64.ln())
            } else if i == k {
                (0.05f64.ln(), 20f64.ln())
            } else {
                (1e-6f64.ln(), 1f64.ln())
            }
        };
        let clamp = |t: &[f64]| -> Vec<f64> {
            t.iter()
                .enumerate()
                .map(|(i, v)| {
                    let (lo, hi) = bounds(i);
                    v.clamp(lo, hi)
                })
                .collect()
        };
        let neg_lml = |t: &[f64]| -> f64 {
            let t = clamp(t);
            let length: Vec<f64> = t[..k].iter().map(|v| v.exp()).collect();
            match factor(x, &ys, &length, t[k].exp(), t[k + 1].exp()) {
                Some((_, _, lml)) => -lml,
                None => f64::INFINITY,
            }
        };
        let mut best: Option<(Vec<f64>, f64)> = None;
        for (l0, n0) in [(0.3f64, 0.01f64), (1.0, 0.1), (0.1, 0.001)] {
            let mut start = vec![l0.ln(); k];
            start.push(0.0);
            start.push(n0.ln());
            let (t, v) = nelder_mead(&neg_lml, &start, 0.7, 400 * (k + 2));
            if best.as_ref().is_none_or(|b| v < b.1) {
                best = Some((clamp(&t), v));
            }
        }
        let (t, _) = best.expect("three starts");
        let length: Vec<f64> = t[..k].iter().map(|v| v.exp()).collect();
        let (sf2, sn2) = (t[k].exp(), t[k + 1].exp());
        let (l, alpha, lml) =
            factor(x, &ys, &length, sf2, sn2).ok_or_else(|| anyhow::anyhow!("covariance not positive definite"))?;
        Ok(Gp {
            x: x.to_vec(),
            l,
            alpha,
            ys,
            length,
            signal_var: sf2,
            noise_var: sn2,
            y_mean,
            y_sd,
            log_likelihood: lml,
        })
    }

    /// Predictive mean and standard deviation of the latent function at `p`.
    pub fn predict(&self, p: &[f64]) -> (f64, f64) {
        let ks: Vec<f64> = self.x.iter().map(|xi| matern52(xi, p, &self.length, self.signal_var)).collect();
        let mean: f64 = ks.iter().zip(&self.alpha).map(|(a, b)| a * b).sum();
        let v = solve_lower(&self.l, &ks);
        let var = (self.signal_var - v.iter().map(|x| x * x).sum::<f64>()).max(0.0);
        (self.y_mean + self.y_sd * mean, self.y_sd * var.sqrt())
    }

    /// The predictive mean alone.
    pub fn mean(&self, p: &[f64]) -> f64 {
        self.predict(p).0
    }

    /// Leave-one-out diagnostics (eq. 5.12).
    pub fn loo(&self) -> Loo {
        let n = self.x.len();
        // K⁻¹ = L⁻ᵀ L⁻¹, column by column
        let mut diag = vec![0.0; n];
        for (j, d) in diag.iter_mut().enumerate() {
            let mut e = vec![0.0; n];
            e[j] = 1.0;
            let col = solve_upper_t(&self.l, &solve_lower(&self.l, &e));
            *d = col[j];
        }
        // yᵢ − μ₋ᵢ, standardised
        let res: Vec<f64> = self.alpha.iter().zip(&diag).map(|(a, d)| a / d).collect();
        let y = &self.ys;
        let mean = y.iter().sum::<f64>() / n as f64;
        let sse: f64 = res.iter().map(|r| r * r).sum();
        let sst: f64 = y.iter().map(|v| (v - mean).powi(2)).sum::<f64>().max(1e-12);
        let covered = res.iter().zip(&diag).filter(|(r, d)| r.abs() <= 1.96 / d.sqrt()).count();
        Loo { n, rmse: self.y_sd * (sse / n as f64).sqrt(), q2: 1.0 - sse / sst, coverage95: covered as f64 / n as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uq::sample::sobol;

    #[test]
    fn emulates_a_smooth_function_and_reports_its_own_error() {
        let f = |x: &[f64]| (3.0 * x[0]).sin() + x[1] * x[1] + 0.0 * x[2];
        let x = sobol(64, 3, 1);
        let y: Vec<f64> = x.iter().map(|p| f(p)).collect();
        let gp = Gp::fit(&x, &y).unwrap();
        let test = sobol(200, 3, 99);
        let rmse = (test.iter().map(|p| (gp.mean(p) - f(p)).powi(2)).sum::<f64>() / 200.0).sqrt();
        assert!(rmse < 0.03, "held-out rmse {rmse}");
        let loo = gp.loo();
        assert!(loo.q2 > 0.98 && loo.rmse < 0.05, "{loo:?}");
        // the irrelevant input gets a long length scale
        assert!(gp.length[2] > 3.0 * gp.length[0], "{:?}", gp.length);
        let (m, sd) = gp.predict(&x[5]);
        assert!((m - y[5]).abs() < 0.01 && sd < 0.05);
    }

    #[test]
    fn noisy_outputs_get_a_noise_term() {
        let mut rng = crate::stats::Rng::new(4);
        let x = sobol(64, 1, 2);
        let y: Vec<f64> = x.iter().map(|p| 2.0 * p[0] + 0.2 * rng.normal()).collect();
        let gp = Gp::fit(&x, &y).unwrap();
        assert!(gp.noise_var > 0.01, "noise variance {} (standardised)", gp.noise_var);
        let err = (gp.mean(&[0.5]) - 1.0).abs();
        assert!(err < 0.15, "{err}");
        let loo = gp.loo();
        assert!(loo.coverage95 > 0.85, "{loo:?}");
    }
}
