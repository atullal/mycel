//! Space-filling samples of the unit cube: scrambled Sobol points and Latin
//! hypercubes, and the normal distribution functions the Gaussian copula
//! needs ([`super::params::Region`]).
//!
//! - **Sobol sequence** (Sobol', 1967), generated in Gray-code order
//!   (Antonov & Saleev, 1979) from the Joe–Kuo direction numbers
//!   `new-joe-kuo-6.21201` (S. Joe and F. Y. Kuo, "Constructing Sobol
//!   sequences with better two-dimensional projections", SIAM J. Sci.
//!   Comput. 30, 2008; table at <https://web.maths.unsw.edu.au/~fkuo/sobol/>,
//!   rows d = 2..25 copied verbatim, checked 2026-10-21). 25 dimensions.
//! - **Owen scrambling** (nested uniform scrambling, Owen 1995), in the
//!   hash-based form of B. Burley, "Practical Hash-based Owen Scrambling",
//!   JCGT 9(4), 2020: reverse the bits, apply the Laine–Karras permutation
//!   with a per-dimension seed, reverse back. It keeps the (t, m, s)-net
//!   property, so the first 2^m points still put one point in every
//!   elementary interval of volume 2^−m that the unscrambled net does, and
//!   it makes the points random, so replicated designs give error bars.
//! - **Latin hypercube** (McKay, Beckman & Conover, Technometrics 1979).

use crate::stats::{Rng, mix64};

/// Joe–Kuo `new-joe-kuo-6.21201`, d = 2..25: (s, a, m_1..m_s).
const JOE_KUO: [(u32, u32, &[u32]); 24] = [
    (1, 0, &[1]),
    (2, 1, &[1, 3]),
    (3, 1, &[1, 3, 1]),
    (3, 2, &[1, 1, 1]),
    (4, 1, &[1, 1, 3, 3]),
    (4, 4, &[1, 3, 5, 13]),
    (5, 2, &[1, 1, 5, 5, 17]),
    (5, 4, &[1, 1, 5, 5, 5]),
    (5, 7, &[1, 1, 7, 11, 19]),
    (5, 11, &[1, 1, 5, 1, 1]),
    (5, 13, &[1, 1, 1, 3, 11]),
    (5, 14, &[1, 3, 5, 5, 31]),
    (6, 1, &[1, 3, 3, 9, 7, 49]),
    (6, 13, &[1, 1, 1, 15, 21, 21]),
    (6, 16, &[1, 3, 1, 13, 27, 49]),
    (6, 19, &[1, 1, 1, 15, 7, 5]),
    (6, 22, &[1, 3, 1, 15, 13, 25]),
    (6, 25, &[1, 1, 5, 5, 19, 61]),
    (7, 1, &[1, 3, 7, 11, 23, 15, 103]),
    (7, 4, &[1, 3, 7, 13, 13, 15, 69]),
    (7, 7, &[1, 1, 3, 13, 7, 35, 63]),
    (7, 8, &[1, 3, 5, 9, 1, 25, 53]),
    (7, 14, &[1, 3, 1, 13, 9, 35, 107]),
    (7, 19, &[1, 3, 1, 5, 27, 61, 31]),
];

/// Dimensions the Sobol generator supports.
pub const SOBOL_MAX_DIMS: usize = JOE_KUO.len() + 1;

/// 32 direction numbers (as left-aligned 32-bit integers) per dimension.
fn directions(dims: usize) -> Vec<[u32; 32]> {
    assert!(dims <= SOBOL_MAX_DIMS, "Sobol: at most {SOBOL_MAX_DIMS} dimensions, asked for {dims}");
    let mut out = Vec::with_capacity(dims);
    // dimension 1: v_k = 2^(32 − k)
    let mut first = [0u32; 32];
    for (k, v) in first.iter_mut().enumerate() {
        *v = 1u32 << (31 - k);
    }
    out.push(first);
    for &(s, a, m) in JOE_KUO.iter().take(dims.saturating_sub(1)) {
        let s = s as usize;
        let mut v = [0u32; 32];
        for k in 0..32 {
            if k < s {
                v[k] = m[k] << (31 - k);
            } else {
                // v_k = a_1 v_{k−1} ⊕ … ⊕ a_{s−1} v_{k−s+1} ⊕ v_{k−s} ⊕ (v_{k−s} >> s)
                let mut x = v[k - s] ^ (v[k - s] >> s);
                for i in 1..s {
                    if (a >> (s - 1 - i)) & 1 == 1 {
                        x ^= v[k - i];
                    }
                }
                v[k] = x;
            }
        }
        out.push(v);
    }
    out
}

/// The first `n` Sobol points in `dims` dimensions, as 32-bit integers
/// (Gray-code order; the first point is the origin).
fn sobol_bits(n: usize, dims: usize) -> Vec<Vec<u32>> {
    let v = directions(dims);
    let mut x = vec![0u32; dims];
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(x.clone());
        // the lowest zero bit of i picks the direction number to flip in
        let c = (!(i as u64)).trailing_zeros() as usize;
        if c < 32 {
            for (xd, vd) in x.iter_mut().zip(&v) {
                *xd ^= vd[c];
            }
        }
    }
    out
}

/// Burley's Laine–Karras permutation (JCGT 2020, listing 2).
fn laine_karras(mut x: u32, seed: u32) -> u32 {
    x = x.wrapping_add(seed);
    x ^= x.wrapping_mul(0x6c50_b47c);
    x ^= x.wrapping_mul(0xb82f_1e52);
    x ^= x.wrapping_mul(0xc7af_e638);
    x ^= x.wrapping_mul(0x8d22_f6e6);
    x
}

/// Nested uniform (Owen) scrambling of one coordinate.
fn owen(x: u32, seed: u32) -> u32 {
    laine_karras(x.reverse_bits(), seed).reverse_bits()
}

/// `n` scrambled Sobol points in `[0, 1)^dims` (each coordinate in the
/// open interval: the centre of its 2^−32 cell). Use a power of two for
/// `n`: the net property holds for the first 2^m points.
pub fn sobol(n: usize, dims: usize, seed: u64) -> Vec<Vec<f64>> {
    let seeds: Vec<u32> = (0..dims).map(|d| (mix64(seed ^ mix64(d as u64 + 1)) >> 32) as u32).collect();
    sobol_bits(n, dims)
        .into_iter()
        .map(|p| p.iter().zip(&seeds).map(|(x, s)| (f64::from(owen(*x, *s)) + 0.5) / 4_294_967_296.0).collect())
        .collect()
}

/// The unscrambled Sobol points (for tests against published values).
pub fn sobol_plain(n: usize, dims: usize) -> Vec<Vec<f64>> {
    sobol_bits(n, dims).into_iter().map(|p| p.iter().map(|x| f64::from(*x) / 4_294_967_296.0).collect()).collect()
}

/// A Latin hypercube of `n` points in `[0, 1)^dims`: each coordinate has
/// exactly one point in each of the `n` equal strata, jittered within it.
pub fn latin_hypercube(n: usize, dims: usize, rng: &mut Rng) -> Vec<Vec<f64>> {
    let mut pts = vec![vec![0.0; dims]; n];
    for d in 0..dims {
        let mut perm: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            perm.swap(i, rng.below(i + 1));
        }
        for (p, k) in pts.iter_mut().zip(perm) {
            p[d] = (k as f64 + rng.f64()) / n as f64;
        }
    }
    pts
}

/// The standard normal CDF Φ, from erfc by the Chebyshev fit `erfcc` of
/// Numerical Recipes in C, 2nd ed., §6.2 (fractional error below 1.2e−7
/// everywhere).
pub fn norm_cdf(x: f64) -> f64 {
    0.5 * erfc(-x / std::f64::consts::SQRT_2)
}

fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t
        * (-z * z - 1.265_512_23
            + t * (1.000_023_68
                + t * (0.374_091_96
                    + t * (0.096_784_18
                        + t * (-0.186_288_06
                            + t * (0.278_868_07
                                + t * (-1.135_203_98
                                    + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
            .exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

/// The standard normal quantile Φ⁻¹(p) for p in (0, 1): P. J. Acklam's
/// rational approximation (relative error below 1.15e−9), clamped to
/// p in [1e−12, 1 − 1e−12].
pub fn norm_quantile(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] =
        [7.784_695_709_041_462e-3, 3.224_671_290_700_398e-1, 2.445_134_137_142_996, 3.754_408_661_907_416];
    let p = p.clamp(1e-12, 1.0 - 1e-12);
    let lo = 0.02425;
    if p < lo {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - lo {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sobol_matches_the_published_first_points() {
        // dimension 1 is the van der Corput sequence; dimension 2's first
        // points (Joe–Kuo d = 2: s = 1, m = 1) are 0, 0.5, 0.25, 0.75, ...
        let p = sobol_plain(8, 3);
        let d1: Vec<f64> = p.iter().map(|x| x[0]).collect();
        let d2: Vec<f64> = p.iter().map(|x| x[1]).collect();
        let d3: Vec<f64> = p.iter().map(|x| x[2]).collect();
        assert_eq!(d1, [0.0, 0.5, 0.75, 0.25, 0.375, 0.875, 0.625, 0.125]);
        assert_eq!(d2, [0.0, 0.5, 0.25, 0.75, 0.375, 0.875, 0.125, 0.625]);
        assert_eq!(d3, [0.0, 0.5, 0.25, 0.75, 0.625, 0.125, 0.875, 0.375]);
    }

    /// Every one of the first 2^m points sits in its own cell of each
    /// 1-D projection, and dimensions 1 and 2 form a (0, m, 2)-net:
    /// every 2^−a × 2^−(m−a) box holds exactly one point. Scrambling keeps both.
    #[test]
    fn scrambled_points_keep_the_net_property() {
        let m = 7;
        let n = 1 << m;
        for pts in [sobol_plain(n, SOBOL_MAX_DIMS), sobol(n, SOBOL_MAX_DIMS, 42)] {
            for d in 0..SOBOL_MAX_DIMS {
                let mut seen = vec![false; n];
                for p in &pts {
                    assert!((0.0..1.0).contains(&p[d]));
                    let c = (p[d] * n as f64) as usize;
                    assert!(!seen[c], "dimension {d}: two points in stratum {c}");
                    seen[c] = true;
                }
            }
            for a in 0..=m {
                let (bx, by) = (1usize << a, 1usize << (m - a));
                let mut seen = vec![false; n];
                for p in &pts {
                    let c = (p[0] * bx as f64) as usize * by + (p[1] * by as f64) as usize;
                    assert!(!seen[c], "box {a}: two points");
                    seen[c] = true;
                }
            }
        }
        assert_ne!(sobol(8, 2, 1), sobol(8, 2, 2), "scrambling depends on the seed");
        assert_eq!(sobol(8, 2, 1), sobol(8, 2, 1), "and is reproducible");
    }

    #[test]
    fn sobol_integrates_better_than_chance() {
        // ∫ Π (|4x − 2| + 1)/2 over [0,1]^5 = 1 (Sobol's g-function, a = 1)
        let g = |x: &[f64]| x.iter().map(|v| ((4.0 * v - 2.0).abs() + 1.0) / 2.0).product::<f64>();
        let pts = sobol(4096, 5, 7);
        let est = pts.iter().map(|p| g(p)).sum::<f64>() / pts.len() as f64;
        assert!((est - 1.0).abs() < 0.005, "{est}");
    }

    #[test]
    fn latin_hypercube_stratifies_each_coordinate() {
        let mut rng = Rng::new(3);
        let pts = latin_hypercube(50, 4, &mut rng);
        for d in 0..4 {
            let mut cells: Vec<usize> = pts.iter().map(|p| (p[d] * 50.0) as usize).collect();
            cells.sort_unstable();
            assert_eq!(cells, (0..50).collect::<Vec<_>>());
        }
    }

    #[test]
    fn normal_functions_invert_each_other() {
        for p in [1e-6, 0.01, 0.024, 0.2, 0.5, 0.8, 0.976, 0.999] {
            let x = norm_quantile(p);
            assert!((norm_cdf(x) - p).abs() < 1e-6 * p, "{p} {x}");
        }
        assert!((norm_quantile(0.975) - 1.959_964).abs() < 1e-5);
        assert!((norm_cdf(1.0) - 0.841_344_7).abs() < 1e-6);
    }
}
