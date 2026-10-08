//! Streaming sample-rate conversion between a device's rate (often 44.1 or
//! 48 kHz) and the call's 48 kHz. Cubic (Catmull-Rom) interpolation: cheap,
//! no buffering beyond 4 samples, and clean enough for speech.

pub struct Resampler {
    /// Input samples per output sample.
    step: f64,
    /// Position of the next output sample, relative to `hist[1]`.
    pos: f64,
    /// The last four input samples (hist[3] newest).
    hist: [f32; 4],
    /// Input samples still needed before the window is full.
    warmup: usize,
}

impl Resampler {
    pub fn new(from_rate: u32, to_rate: u32) -> Resampler {
        Resampler { step: from_rate as f64 / to_rate as f64, pos: 0.0, hist: [0.0; 4], warmup: 2 }
    }

    pub fn is_passthrough(&self) -> bool {
        self.step == 1.0
    }

    /// Convert `input`, appending the output to `out`.
    pub fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if self.is_passthrough() {
            out.extend_from_slice(input);
            return;
        }
        for &x in input {
            self.hist = [self.hist[1], self.hist[2], self.hist[3], x];
            if self.warmup > 0 {
                self.warmup -= 1;
                continue;
            }
            // emit every output sample that falls between hist[1] and hist[2]
            while self.pos < 1.0 {
                out.push(cubic(&self.hist, self.pos as f32));
                self.pos += self.step;
            }
            self.pos -= 1.0;
        }
    }
}

fn cubic(h: &[f32; 4], t: f32) -> f32 {
    let (p0, p1, p2, p3) = (h[0], h[1], h[2], h[3]);
    let a = -0.5 * p0 + 1.5 * p1 - 1.5 * p2 + 0.5 * p3;
    let b = p0 - 2.5 * p1 + 2.0 * p2 - 0.5 * p3;
    let c = -0.5 * p0 + 0.5 * p2;
    ((a * t + b) * t + c) * t + p1
}

/// Mix interleaved frames of `channels` down to mono.
pub fn to_mono(interleaved: &[f32], channels: usize, out: &mut Vec<f32>) {
    if channels <= 1 {
        out.extend_from_slice(interleaved);
        return;
    }
    let scale = 1.0 / channels as f32;
    out.extend(interleaved.chunks_exact(channels).map(|f| f.iter().sum::<f32>() * scale));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::estimate_frequency;

    fn tone(freq: f32, rate: u32, secs: f32) -> Vec<f32> {
        (0..(rate as f32 * secs) as usize)
            .map(|i| 0.5 * (2.0 * std::f32::consts::PI * freq * i as f32 / rate as f32).sin())
            .collect()
    }

    #[test]
    fn keeps_pitch_and_length_across_rates() {
        for (from, to) in [(44_100, 48_000), (48_000, 44_100), (16_000, 48_000), (48_000, 48_000)] {
            let input = tone(700.0, from, 1.0);
            let mut r = Resampler::new(from, to);
            let mut out = Vec::new();
            // feed in odd-sized chunks, like a device would
            for chunk in input.chunks(437) {
                r.process(chunk, &mut out);
            }
            let expect = to as usize;
            assert!(out.len().abs_diff(expect) <= 8, "{from}->{to}: {} samples", out.len());
            let f = estimate_frequency(&out, to).unwrap();
            assert!((f - 700.0).abs() < 2.0, "{from}->{to}: {f} Hz");
            assert!(out.iter().all(|s| s.abs() < 0.6), "no overshoot");
        }
    }

    #[test]
    fn stereo_to_mono() {
        let mut out = Vec::new();
        to_mono(&[1.0, 0.0, 0.5, 0.5], 2, &mut out);
        assert_eq!(out, vec![0.5, 0.5]);
    }
}
