//! Uncertain parameters and their joint region (sim-fidelity WP19).
//!
//! Each parameter has a range and a prior (uniform, log-uniform or
//! integer-uniform), a nominal value and a source. Parameters known to move
//! together are joined by a Gaussian copula with a rank correlation, so a
//! sample of the region is a sample of *jointly plausible* worlds, not of
//! independent corners (three independent pessimistic corners stack into a
//! world nobody believes in). The catalogue of named parameters, with the
//! source of every range, is [`builtin`].

use serde::{Deserialize, Serialize};

use super::sample::{norm_cdf, norm_quantile};

/// The prior of one parameter over its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dist {
    Uniform,
    /// Uniform in log space: for scale parameters spanning a factor of
    /// several (range multipliers, pause times, battery life).
    LogUniform,
    /// Integers `lo..=hi`, each equally likely.
    Int,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub lo: f64,
    pub hi: f64,
    pub nominal: f64,
    pub dist: Dist,
    pub unit: String,
    /// Where the range comes from, or "(estimate)".
    pub source: String,
}

impl Param {
    /// The value at quantile `u` in [0, 1] of the prior.
    pub fn at(&self, u: f64) -> f64 {
        let u = u.clamp(0.0, 1.0);
        match self.dist {
            Dist::Uniform => self.lo + u * (self.hi - self.lo),
            Dist::LogUniform => (self.lo.ln() + u * (self.hi.ln() - self.lo.ln())).exp().clamp(self.lo, self.hi),
            Dist::Int => {
                let k = (self.hi - self.lo + 1.0).max(1.0);
                (self.lo + (u * k).floor()).min(self.hi)
            }
        }
    }

    /// The prior quantile of value `x` (the inverse of [`Param::at`]).
    pub fn unit_of(&self, x: f64) -> f64 {
        let u = match self.dist {
            Dist::Uniform => (x - self.lo) / (self.hi - self.lo),
            Dist::LogUniform => (x.ln() - self.lo.ln()) / (self.hi.ln() - self.lo.ln()),
            Dist::Int => (x - self.lo + 0.5) / (self.hi - self.lo + 1.0),
        };
        if u.is_finite() { u.clamp(0.0, 1.0) } else { 0.5 }
    }

    fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.lo.is_finite() && self.hi.is_finite() && self.lo < self.hi, "{}: lo < hi", self.name);
        anyhow::ensure!(self.dist != Dist::LogUniform || self.lo > 0.0, "{}: log-uniform needs lo > 0", self.name);
        anyhow::ensure!(
            (self.lo..=self.hi).contains(&self.nominal),
            "{}: nominal {} outside [{}, {}]",
            self.name,
            self.nominal,
            self.lo,
            self.hi
        );
        Ok(())
    }
}

/// The joint uncertainty region: the parameters and their correlations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Region {
    pub params: Vec<Param>,
    /// (a, b, ρ): Spearman rank correlation between parameters a and b,
    /// imposed by a Gaussian copula.
    pub corr: Vec<(usize, usize, f64)>,
    /// Lower Cholesky factor of the copula's normal correlation matrix.
    #[serde(skip)]
    chol: Option<Vec<Vec<f64>>>,
}

impl Region {
    pub fn new(params: Vec<Param>, corr: Vec<(usize, usize, f64)>) -> anyhow::Result<Region> {
        for p in &params {
            p.check()?;
        }
        let k = params.len();
        let chol = if corr.is_empty() {
            None
        } else {
            let mut c = vec![vec![0.0; k]; k];
            for (i, row) in c.iter_mut().enumerate() {
                row[i] = 1.0;
            }
            for &(a, b, rho) in &corr {
                anyhow::ensure!(a < k && b < k && a != b, "correlation between unknown parameters");
                anyhow::ensure!(rho.abs() < 1.0, "correlation {rho} must be inside (−1, 1)");
                // Spearman ρ_s → the normal copula's Pearson r = 2 sin(π ρ_s / 6)
                let r = 2.0 * (std::f64::consts::PI * rho / 6.0).sin();
                c[a][b] = r;
                c[b][a] = r;
            }
            Some(cholesky(&c).ok_or_else(|| anyhow::anyhow!("correlations are not jointly possible"))?)
        };
        Ok(Region { params, corr, chol })
    }

    pub fn dims(&self) -> usize {
        self.params.len()
    }

    /// Independent uniforms → correlated prior quantiles (the copula).
    pub fn joint(&self, u: &[f64]) -> Vec<f64> {
        let Some(l) = &self.chol else { return u.to_vec() };
        let z: Vec<f64> = u.iter().map(|x| norm_quantile(*x)).collect();
        l.iter().map(|row| norm_cdf(row.iter().zip(&z).map(|(a, b)| a * b).sum())).collect()
    }

    /// Values for prior quantiles `q` (already joint).
    pub fn values(&self, q: &[f64]) -> Vec<f64> {
        self.params.iter().zip(q).map(|(p, u)| p.at(*u)).collect()
    }

    pub fn nominal(&self) -> Vec<f64> {
        self.params.iter().map(|p| p.nominal).collect()
    }

    pub fn index(&self, name: &str) -> Option<usize> {
        self.params.iter().position(|p| p.name == name)
    }

    /// One line per parameter, for reports.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        for p in &self.params {
            s.push_str(&format!(
                "- `{}` {:?} [{} – {}] {} (nominal {}): {}\n",
                p.name, p.dist, p.lo, p.hi, p.unit, p.nominal, p.source
            ));
        }
        for (a, b, rho) in &self.corr {
            s.push_str(&format!(
                "- rank correlation {rho} between `{}` and `{}` (Gaussian copula)\n",
                self.params[*a].name, self.params[*b].name
            ));
        }
        s
    }

    /// A short label: "range_mult × adoption × speed (3-D, 1 correlation)".
    pub fn label(&self) -> String {
        let names: Vec<&str> = self.params.iter().map(|p| p.name.as_str()).collect();
        format!(
            "{} ({}-D{})",
            names.join(" × "),
            names.len(),
            if self.corr.is_empty() { String::new() } else { format!(", {} correlated", self.corr.len()) }
        )
    }
}

/// Cholesky factor of a symmetric positive-definite matrix, or `None`.
pub fn cholesky(a: &[Vec<f64>]) -> Option<Vec<Vec<f64>>> {
    let n = a.len();
    let mut l = vec![vec![0.0; n]; n];
    for i in 0..n {
        for j in 0..=i {
            let s: f64 = (0..j).map(|k| l[i][k] * l[j][k]).sum();
            if i == j {
                let d = a[i][i] - s;
                if d <= 0.0 {
                    return None;
                }
                l[i][j] = d.sqrt();
            } else {
                l[i][j] = (a[i][j] - s) / l[j][j];
            }
        }
    }
    Some(l)
}

/// A named parameter of the catalogue, with its default range, prior and
/// source. A scenario gives the nominal (its own world's value) and may
/// narrow or widen the range; `None` for an unknown name.
///
/// Every range is either cited or marked **(estimate)**: none is
/// calibrated on Mycel's own devices yet (WP14), so a verdict's robustness
/// over these ranges is robustness over today's ignorance, not a
/// calibrated error bar.
pub fn builtin(name: &str) -> Option<Param> {
    let p = |lo: f64, hi: f64, nominal: f64, dist: Dist, unit: &str, source: &str| Param {
        name: name.to_string(),
        lo,
        hi,
        nominal,
        dist,
        unit: unit.to_string(),
        source: source.to_string(),
    };
    Some(match name {
        // A ±6 dB error in the link budget at path-loss exponent 3 moves
        // range by 10^(±6/30) = ×0.63 … ×1.58 (computed). ±6 dB covers the
        // per-handset transmit/receive offsets of the GAEN calibration
        // table (several dB per model) plus environment uncertainty; a body
        // turning round the phone swings RSSI by ~20 dB (Leith & Farrell,
        // arXiv 2006.06822), a fast effect the disc averages out.
        "range_mult" => p(
            0.63,
            1.58,
            1.0,
            Dist::LogUniform,
            "× range",
            "±6 dB link budget at path-loss exponent 3 (computed); GAEN per-model RSSI offsets; Leith & Farrell 2020 (estimate of the span)",
        ),
        "adoption" => p(
            0.02,
            1.0,
            0.1,
            Dist::LogUniform,
            "share of people",
            "share of people present running Mycel: unknown before launch (estimate); mesh connectivity is a percolation problem in it",
        ),
        "inet_share" => p(
            0.0,
            1.0,
            0.5,
            Dist::Uniform,
            "share of devices",
            "share of Mycel devices with working internet; GSMA Mobile Economy 2024 adoption by region for the nominal",
        ),
        "nat_hard" => p(
            0.3,
            0.94,
            0.7,
            Dist::Uniform,
            "share of cellular",
            "cellular devices behind endpoint-dependent NAT: 94% of mobile networks ran CGNAT in 2016 (Richter et al., dated); libp2p DCUtR 70% ± 7% success (Trautwein et al. 2025); iroh ~90% direct (n0 docs, anecdotal)",
        ),
        "max_neighbours" => p(
            6.0,
            15.0,
            8.0,
            Dist::Int,
            "connections",
            "BLE connections per phone: Android ~7 (BTA_GATTC_CONN_MAX, Nordic DevZone); iOS 6–15 reported, undocumented (Apple forums 78857)",
        ),
        "walk_speed" => p(
            0.5,
            1.6,
            1.2,
            Dist::Uniform,
            "m/s",
            "pedestrian speed: comfortable gait 1.27–1.46 m/s (Bohannon 1997); crowds slow to 0.3–1 m/s at 2–5 people/m² (Weidmann 1993; G. K. Still)",
        ),
        "pause_s" => p(
            30.0,
            1800.0,
            300.0,
            Dist::LogUniform,
            "s",
            "pause between walks: heavy-tailed in human traces (SLAW, Lee et al. 2009); span (estimate)",
        ),
        "msg_rate" => p(
            0.5,
            2.0,
            1.0,
            Dist::LogUniform,
            "× workload",
            "messages per device-hour relative to the scenario's (estimate; WP16 replaces it with a fitted workload)",
        ),
        "adversary_share" => p(
            0.0,
            0.1,
            0.03,
            Dist::Uniform,
            "share of devices",
            "share of devices that are attackers: infiltrators at 1–5% (design catalogue #9); up to 10% (estimate)",
        ),
        "battery_median_h" => p(
            3.0,
            24.0,
            8.0,
            Dist::LogUniform,
            "h",
            "median hours until a phone dies with radios on and no charging (estimate; WP9 replaces it with an energy model)",
        ),
        "ios_share" => p(
            0.15,
            0.6,
            0.3,
            Dist::Uniform,
            "share of phones",
            "iPhones (AWDL rather than Wi-Fi Direct): ~28% worldwide, ~55% in the US (StatCounter mobile OS share 2025)",
        ),
        "ble_only_share" => {
            p(0.0, 0.4, 0.1, Dist::Uniform, "share of phones", "phones with peer Wi-Fi off or missing (estimate)")
        }
        "churn_per_min" => p(
            0.0,
            0.3,
            0.05,
            Dist::Uniform,
            "share per minute",
            "share of devices switching off (and the last minute's back on) each minute (estimate)",
        ),
        "mule_share" => p(
            0.02,
            0.3,
            0.1,
            Dist::LogUniform,
            "share of devices",
            "devices that walk between clusters (responders, traders, commuters) (estimate)",
        ),
        _ => return None,
    })
}

/// The names [`builtin`] knows.
pub const BUILTIN: &[&str] = &[
    "range_mult",
    "adoption",
    "inet_share",
    "nat_hard",
    "max_neighbours",
    "walk_speed",
    "pause_s",
    "msg_rate",
    "adversary_share",
    "battery_median_h",
    "ios_share",
    "ble_only_share",
    "churn_per_min",
    "mule_share",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_is_valid_and_sourced() {
        for n in BUILTIN {
            let p = builtin(n).expect("listed");
            p.check().expect("valid");
            assert!(!p.source.is_empty(), "{n} has a source");
            for u in [0.0, 0.3, 1.0] {
                let x = p.at(u);
                assert!((p.lo..=p.hi).contains(&x), "{n} at {u}: {x}");
            }
            let back = p.at(p.unit_of(p.nominal));
            assert!((back - p.nominal).abs() < 1e-9 * p.nominal.abs().max(1.0) || p.dist == Dist::Int, "{n}");
        }
        assert!(builtin("no such").is_none());
    }

    #[test]
    fn the_copula_imposes_the_rank_correlation() {
        let a = builtin("battery_median_h").unwrap();
        let b = builtin("msg_rate").unwrap();
        let r = Region::new(vec![a, b], vec![(0, 1, -0.6)]).unwrap();
        let pts = super::super::sample::sobol(4096, 2, 9);
        let q: Vec<Vec<f64>> = pts.iter().map(|u| r.joint(u)).collect();
        // Spearman ρ of the quantiles themselves (they are ranks already)
        let n = q.len() as f64;
        let mean = |i: usize| q.iter().map(|x| x[i]).sum::<f64>() / n;
        let (m0, m1) = (mean(0), mean(1));
        let cov = q.iter().map(|x| (x[0] - m0) * (x[1] - m1)).sum::<f64>() / n;
        let sd = |i: usize, m: f64| (q.iter().map(|x| (x[i] - m).powi(2)).sum::<f64>() / n).sqrt();
        let rho = cov / (sd(0, m0) * sd(1, m1));
        assert!((rho + 0.6).abs() < 0.03, "{rho}");
        // the marginals stay uniform
        assert!((m0 - 0.5).abs() < 0.01 && (m1 - 0.5).abs() < 0.01);
        assert!(Region::new(vec![builtin("adoption").unwrap()], vec![(0, 0, 0.5)]).is_err());
    }

    #[test]
    fn int_parameters_cover_each_value() {
        let p = builtin("max_neighbours").unwrap();
        let vals: std::collections::BTreeSet<i64> = (0..100).map(|i| p.at(f64::from(i) / 99.0) as i64).collect();
        assert_eq!(vals.into_iter().collect::<Vec<_>>(), (6..=15).collect::<Vec<_>>());
    }
}
