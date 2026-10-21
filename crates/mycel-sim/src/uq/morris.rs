//! Morris elementary-effects screening (M. D. Morris, "Factorial sampling
//! plans for preliminary computational experiments", Technometrics 33,
//! 1991), with the μ* measure of F. Campolongo, J. Cariboni and A.
//! Saltelli ("An effective screening design for sensitivity analysis of
//! large models", Environ. Model. Softw. 22, 2007).
//!
//! r trajectories of k + 1 points each on a p-level grid of the unit cube;
//! along a trajectory one factor at a time moves by Δ = p / (2(p − 1)).
//! The elementary effect of factor i is the change in output over ±Δ.
//! μ* (the mean of |EE|) ranks importance; σ (their spread) flags
//! interactions or non-linearity. It costs r(k + 1) runs, against
//! N(k + 2) for Sobol indices, and drops the factors not worth an emulator.
//!
//! A simulation is noisy: even an inert factor gets |EE| > 0 from seed
//! noise. [`noise_floors`] estimates, per factor, the μ* that seed noise
//! alone would give, from the spread over seeds of each elementary effect
//! (paired on the same seeds, so common random numbers count). A factor
//! whose μ* interval does not clear its floor is not distinguishable from
//! noise at this many seeds.

use serde::{Deserialize, Serialize};

use crate::stats::Rng;

/// Grid levels (p); Δ = p / (2(p − 1)) = 2/3 on the unit interval.
pub const LEVELS: usize = 4;

/// One trajectory: k + 1 points, and which factor moved (and by how much)
/// between point j and j + 1.
#[derive(Clone, Debug)]
pub struct Trajectory {
    pub points: Vec<Vec<f64>>,
    /// (factor, signed step) for each of the k moves.
    pub moves: Vec<(usize, f64)>,
}

/// `r` random trajectories in `k` dimensions.
pub fn trajectories(k: usize, r: usize, rng: &mut Rng) -> Vec<Trajectory> {
    let p = LEVELS as f64;
    let delta = p / (2.0 * (p - 1.0));
    (0..r)
        .map(|_| {
            let mut x: Vec<f64> = (0..k).map(|_| rng.below(LEVELS) as f64 / (p - 1.0)).collect();
            let mut order: Vec<usize> = (0..k).collect();
            for i in (1..k).rev() {
                order.swap(i, rng.below(i + 1));
            }
            let mut points = vec![x.clone()];
            let mut moves = Vec::with_capacity(k);
            for i in order {
                // step up if it stays inside, else down (each grid level
                // admits exactly one of the two with p = 4)
                let step = if x[i] + delta <= 1.0 + 1e-12 { delta } else { -delta };
                x[i] = (x[i] + step).clamp(0.0, 1.0);
                points.push(x.clone());
                moves.push((i, step));
            }
            Trajectory { points, moves }
        })
        .collect()
}

/// One factor's screening result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Effect {
    pub factor: usize,
    pub name: String,
    /// Mean |EE| (Campolongo's μ*): importance.
    pub mu_star: f64,
    /// 95% bootstrap interval of μ* over trajectories.
    pub mu_star_ci: (f64, f64),
    /// Mean EE (signed): the direction, when monotone.
    pub mu: f64,
    /// Standard deviation of EE: interaction or non-linearity.
    pub sigma: f64,
    /// The μ* seed noise alone would give ([`noise_floors`]; 0 if not
    /// estimated).
    #[serde(default)]
    pub noise_floor: f64,
}

impl Effect {
    /// μ*'s interval clears the noise floor.
    pub fn above_noise(&self) -> bool {
        self.mu_star_ci.0 > self.noise_floor
    }
}

/// Effects from the outputs `y[t][j]` at each trajectory's points, ranked
/// by μ* (largest first).
pub fn effects(trajs: &[Trajectory], y: &[Vec<f64>], names: &[String], rng: &mut Rng) -> Vec<Effect> {
    let k = names.len();
    // ee[i] = elementary effects of factor i, one per trajectory
    let mut ee: Vec<Vec<f64>> = vec![Vec::new(); k];
    for (t, ys) in trajs.iter().zip(y) {
        for (j, (i, step)) in t.moves.iter().enumerate() {
            let d = (ys[j + 1] - ys[j]) / step;
            if d.is_finite() {
                ee[*i].push(d);
            }
        }
    }
    let mut out: Vec<Effect> = ee
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let n = e.len().max(1) as f64;
            let mu = e.iter().sum::<f64>() / n;
            let mu_star = e.iter().map(|x| x.abs()).sum::<f64>() / n;
            let sigma =
                if e.len() > 1 { (e.iter().map(|x| (x - mu).powi(2)).sum::<f64>() / (n - 1.0)).sqrt() } else { 0.0 };
            let mut boots: Vec<f64> = (0..500)
                .map(|_| {
                    if e.is_empty() {
                        return 0.0;
                    }
                    (0..e.len()).map(|_| e[rng.below(e.len())].abs()).sum::<f64>() / n
                })
                .collect();
            boots.sort_by(f64::total_cmp);
            let ci = (boots[12], boots[487]);
            Effect { factor: i, name: names[i].clone(), mu_star, mu_star_ci: ci, mu, sigma, noise_floor: 0.0 }
        })
        .collect();
    out.sort_by(|a, b| b.mu_star.total_cmp(&a.mu_star));
    out
}

/// Per factor, the μ* that seed noise alone would give: for each
/// elementary effect, the standard error of its mean over seeds (from the
/// per-seed effects, `values[t][j][s]` = trajectory t, point j, seed s),
/// times E|Z| = √(2/π) for a normal Z, averaged over the factor's effects.
/// With fewer than two seeds there is no estimate (0).
pub fn noise_floors(trajs: &[Trajectory], values: &[Vec<Vec<f64>>], k: usize) -> Vec<f64> {
    let mut sum = vec![0.0; k];
    let mut cnt = vec![0usize; k];
    for (t, ys) in trajs.iter().zip(values) {
        for (j, (i, step)) in t.moves.iter().enumerate() {
            let d: Vec<f64> =
                ys[j].iter().zip(&ys[j + 1]).map(|(a, b)| (b - a) / step).filter(|v| v.is_finite()).collect();
            if d.len() < 2 {
                continue;
            }
            let n = d.len() as f64;
            let m = d.iter().sum::<f64>() / n;
            let sd = (d.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (n - 1.0)).sqrt();
            sum[*i] += sd / n.sqrt() * (2.0 / std::f64::consts::PI).sqrt();
            cnt[*i] += 1;
        }
    }
    sum.iter().zip(&cnt).map(|(s, c)| if *c == 0 { 0.0 } else { s / *c as f64 }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trajectories_move_one_factor_at_a_time_on_the_grid() {
        let mut rng = Rng::new(5);
        for t in trajectories(4, 20, &mut rng) {
            assert_eq!(t.points.len(), 5);
            let mut moved: Vec<usize> = t.moves.iter().map(|m| m.0).collect();
            moved.sort_unstable();
            assert_eq!(moved, vec![0, 1, 2, 3], "each factor moves once");
            for (j, (i, step)) in t.moves.iter().enumerate() {
                for d in 0..4 {
                    let diff = t.points[j + 1][d] - t.points[j][d];
                    if d == *i {
                        assert!((diff - step).abs() < 1e-12 && (step.abs() - 2.0 / 3.0).abs() < 1e-12);
                    } else {
                        assert_eq!(diff, 0.0);
                    }
                }
                assert!(t.points[j + 1].iter().all(|x| (0.0..=1.0).contains(x)));
            }
        }
    }

    #[test]
    fn effects_rank_a_known_function() {
        // y = 5 x0 + 1 x1 − 3 x2 + 0 x3 + 4 x0 x1: x0 matters most (μ* 5 + 4·E[x1]),
        // x3 not at all, x1's effect depends on x0 (σ > 0)
        let f = |x: &[f64]| 5.0 * x[0] + x[1] - 3.0 * x[2] + 4.0 * x[0] * x[1];
        let mut rng = Rng::new(11);
        let trajs = trajectories(4, 40, &mut rng);
        let y: Vec<Vec<f64>> = trajs.iter().map(|t| t.points.iter().map(|p| f(p)).collect()).collect();
        let names: Vec<String> = (0..4).map(|i| format!("x{i}")).collect();
        let e = effects(&trajs, &y, &names, &mut rng);
        assert_eq!(e[0].name, "x0");
        assert_eq!(e[3].name, "x3");
        assert_eq!(e[3].mu_star, 0.0);
        let x2 = e.iter().find(|x| x.name == "x2").unwrap();
        assert!((x2.mu_star - 3.0).abs() < 1e-9 && (x2.mu + 3.0).abs() < 1e-9 && x2.sigma < 1e-9, "{x2:?}");
        let x1 = e.iter().find(|x| x.name == "x1").unwrap();
        assert!(x1.sigma > 0.5, "interaction shows as spread: {x1:?}");
        assert!(e[0].mu_star_ci.0 <= e[0].mu_star && e[0].mu_star <= e[0].mu_star_ci.1);
    }

    /// y = 4 x0 + noise (sd 3 per seed, 4 seeds): x0 clears the noise
    /// floor, the inert x1 does not, and the floor is near its expected
    /// value E|mean of 4 differences| / Δ = √2·3/2 · √(2/π) / (2/3) ≈ 2.5.
    #[test]
    fn the_noise_floor_separates_a_real_effect_from_seed_noise() {
        let mut rng = Rng::new(21);
        let trajs = trajectories(2, 30, &mut rng);
        let seeds = 4;
        let values: Vec<Vec<Vec<f64>>> = trajs
            .iter()
            .map(|t| t.points.iter().map(|p| (0..seeds).map(|_| 4.0 * p[0] + 3.0 * rng.normal()).collect()).collect())
            .collect();
        let y: Vec<Vec<f64>> =
            values.iter().map(|t| t.iter().map(|v| v.iter().sum::<f64>() / seeds as f64).collect()).collect();
        let names = vec!["x0".to_string(), "x1".to_string()];
        let mut e = effects(&trajs, &y, &names, &mut rng);
        let floors = noise_floors(&trajs, &values, 2);
        for x in &mut e {
            x.noise_floor = floors[x.factor];
        }
        let x0 = e.iter().find(|x| x.name == "x0").unwrap();
        let x1 = e.iter().find(|x| x.name == "x1").unwrap();
        assert!(x0.above_noise(), "{x0:?}");
        assert!(!x1.above_noise(), "{x1:?}");
        for f in floors {
            assert!((f - 2.5).abs() < 0.6, "floor {f}");
        }
    }
}
