//! Audio measurements: level meters and tone detection (tests, diagnostics).

/// Meter level in 0..1 for a block of samples: RMS mapped from -60..0 dBFS.
pub fn meter(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let rms = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
    if rms <= 1e-6 {
        return 0.0;
    }
    let db = 20.0 * rms.log10();
    ((db + 60.0) / 60.0).clamp(0.0, 1.0)
}

/// Frequency of the dominant tone, from rising zero crossings (with linear
/// interpolation between samples). `None` for silence or noise-like input.
pub fn estimate_frequency(samples: &[f32], rate: u32) -> Option<f32> {
    let peak = samples.iter().fold(0f32, |m, s| m.max(s.abs()));
    if peak < 1e-3 {
        return None;
    }
    // hysteresis: ignore tiny wiggles around zero
    let hyst = peak * 0.05;
    let mut armed = false;
    let mut first: Option<f32> = None;
    let mut last = 0f32;
    let mut count = 0usize;
    for i in 1..samples.len() {
        let (a, b) = (samples[i - 1], samples[i]);
        if b < -hyst {
            armed = true;
        }
        if armed && a <= 0.0 && b > 0.0 {
            let t = (i - 1) as f32 + a / (a - b);
            if first.is_none() {
                first = Some(t);
            } else {
                count += 1;
            }
            last = t;
            armed = false;
        }
    }
    let first = first?;
    if count < 2 || last <= first {
        return None;
    }
    Some(count as f32 * rate as f32 / (last - first))
}

/// Power of `freq` in `samples` (Goertzel), normalized by length.
pub fn goertzel(samples: &[f32], freq: f32, rate: u32) -> f32 {
    let w = 2.0 * std::f32::consts::PI * freq / rate as f32;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0f32, 0f32);
    for &x in samples {
        let s = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    power / (samples.len().max(1) as f32).powi(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_and_meter() {
        let rate = 48_000;
        let tone: Vec<f32> = (0..rate)
            .map(|i| 0.3 * (2.0 * std::f32::consts::PI * 523.25 * i as f32 / rate as f32).sin())
            .collect();
        let f = estimate_frequency(&tone, rate).unwrap();
        assert!((f - 523.25).abs() < 0.5, "{f}");
        assert!(goertzel(&tone, 523.25, rate) > 100.0 * goertzel(&tone, 800.0, rate));
        assert!(meter(&tone) > 0.7 && meter(&tone) < 0.9);
        assert_eq!(meter(&[0.0; 100]), 0.0);
        assert_eq!(estimate_frequency(&[0.0; 1000], rate), None);
    }
}
