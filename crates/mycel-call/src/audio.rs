//! Audio I/O behind a trait, so calls run on real devices, Apple's voice
//! processing (echo cancellation), or test sources and sinks.
//!
//! Every backend speaks mono f32 at 48 kHz through two lock-free ring
//! buffers: it pushes what the microphone hears into `mic` and pulls what to
//! play from `speaker` (playing silence when it runs dry). Backends resample
//! to and from their device's rate themselves.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;

use crate::codec::SAMPLE_RATE;
use crate::level::estimate_frequency;
use crate::resample::{Resampler, to_mono};

/// The two ends a backend gets when a call starts.
pub struct AudioPorts {
    /// Push captured samples here.
    pub mic: rtrb::Producer<f32>,
    /// Pull samples to play from here.
    pub speaker: rtrb::Consumer<f32>,
}

/// Keeps a backend running; dropping it stops capture and playback.
pub struct AudioHandle(#[allow(dead_code)] Box<dyn Send>);

impl AudioHandle {
    pub fn new(inner: impl Send + 'static) -> AudioHandle {
        AudioHandle(Box::new(inner))
    }
}

/// Diagnostics a backend can offer (test audio measures what it hears).
#[derive(Clone, Debug, Default)]
pub struct AudioDiag {
    pub heard_tone_hz: Option<f32>,
    pub measured_round_trip_ms: Option<f32>,
}

pub trait AudioIo: Send + Sync + 'static {
    /// Shown in call stats ("Voice processing", "Test tone 440 Hz").
    fn describe(&self) -> String;
    /// Whether this backend cancels the far end's echo.
    fn echo_cancellation(&self) -> bool {
        false
    }
    /// Make sure we may use the microphone, asking the user if the OS hasn't
    /// yet. Blocking (it may wait for the user); errors say what to do.
    fn prepare(&self) -> Result<()> {
        Ok(())
    }
    /// Start capture and playback.
    fn open(&self, ports: AudioPorts) -> Result<AudioHandle>;
    fn diagnostics(&self) -> AudioDiag {
        AudioDiag::default()
    }
}

#[cfg(target_os = "macos")]
pub const MIC_DENIED: &str = "Mycel isn't allowed to use the microphone. Allow it in System Settings > Privacy & Security > Microphone, then call again.";
#[cfg(target_os = "ios")]
pub const MIC_DENIED: &str = "Mycel isn't allowed to use the microphone. Turn it on in Settings > Mycel, then call again.";
#[cfg(target_os = "android")]
pub const MIC_DENIED: &str = "Mycel isn't allowed to use the microphone. Allow it in Settings > Apps > Mycel > Permissions, then call again.";
#[cfg(windows)]
pub const MIC_DENIED: &str = "Mycel isn't allowed to use the microphone. Allow it in Settings > Privacy & security > Microphone, then call again.";
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android", windows)))]
pub const MIC_DENIED: &str = "Mycel can't use the microphone. Check that one is connected and that Mycel may use it, then call again.";

/// The audio backend for this device. `MYCEL_AUDIO` picks it:
/// - unset / `auto`: Apple voice processing with echo cancellation on macOS,
///   iOS and iPadOS (falling back to plain devices), the phone's call audio
///   with echo cancellation on Android, plain devices elsewhere
/// - `device`: plain default input/output devices (no echo cancellation)
/// - `test` / `test:<hz>`: a sine tone in, nothing played (headless testing)
/// - `test:bursts[:<hz>]`: tone bursts in; measures the echo coming back
/// - `test:echo`: plays nothing, sends back whatever it hears (a loopback peer)
pub fn default_audio() -> Arc<dyn AudioIo> {
    let want = std::env::var("MYCEL_AUDIO").unwrap_or_default().trim().to_ascii_lowercase();
    if let Some(rest) = want.strip_prefix("test") {
        let rest = rest.trim_start_matches(':');
        let mut parts = rest.split(':');
        return match parts.next().unwrap_or("") {
            "echo" => Arc::new(TestAudio::new(TestSource::Echo)),
            "bursts" => {
                let hz = parts.next().and_then(|h| h.parse().ok()).unwrap_or(1000.0);
                Arc::new(TestAudio::new(TestSource::Bursts { hz, on_ms: 100, period_ms: 500 }))
            }
            hz => Arc::new(TestAudio::new(TestSource::Sine { hz: hz.parse().unwrap_or(440.0), amp: 0.5 })),
        };
    }
    if want == "device" || want == "cpal" {
        return Arc::new(DeviceAudio);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Arc::new(crate::mac::VoiceProcessingAudio)
    }
    #[cfg(target_os = "android")]
    {
        Arc::new(crate::android::VoiceCallAudio)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    {
        Arc::new(DeviceAudio)
    }
}

// ─────────────────────────────── test audio ───────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum TestSource {
    Silence,
    Sine { hz: f32, amp: f32 },
    /// `on_ms` of tone every `period_ms`, for latency measurement.
    Bursts { hz: f32, on_ms: u32, period_ms: u32 },
    /// Send back what we hear (a remote loopback).
    Echo,
}

/// What a test backend heard (its "speaker").
#[derive(Default)]
pub struct Recording {
    /// When the first recorded sample was played.
    pub start: Option<Instant>,
    pub samples: Vec<f32>,
}

/// Software audio paced by the wall clock in 10 ms ticks, like a device with
/// a 10 ms buffer: the source goes into the call, what the call plays is
/// recorded.
pub struct TestAudio {
    source: TestSource,
    /// Keep at most this much recording (oldest dropped).
    keep: usize,
    recording: Arc<Mutex<Recording>>,
    /// When the current source started (sample 0 of the source).
    source_start: Arc<Mutex<Option<Instant>>>,
}

const TICK: Duration = Duration::from_millis(10);
const TICK_SAMPLES: usize = (SAMPLE_RATE / 100) as usize;

impl TestAudio {
    pub fn new(source: TestSource) -> TestAudio {
        TestAudio {
            source,
            keep: SAMPLE_RATE as usize * 30,
            recording: Arc::default(),
            source_start: Arc::default(),
        }
    }

    pub fn source(&self) -> TestSource {
        self.source
    }

    /// Everything played so far (up to the last 30 s).
    pub fn recording(&self) -> Arc<Mutex<Recording>> {
        self.recording.clone()
    }

    pub fn source_start(&self) -> Option<Instant> {
        *self.source_start.lock()
    }

    fn sample(source: TestSource, i: u64) -> f32 {
        let t = i as f32 / SAMPLE_RATE as f32;
        match source {
            TestSource::Silence | TestSource::Echo => 0.0,
            TestSource::Sine { hz, amp } => amp * (2.0 * std::f32::consts::PI * hz * t).sin(),
            TestSource::Bursts { hz, on_ms, period_ms } => {
                let ms = (i * 1000 / SAMPLE_RATE as u64) % period_ms as u64;
                if ms < on_ms as u64 { 0.5 * (2.0 * std::f32::consts::PI * hz * t).sin() } else { 0.0 }
            }
        }
    }

    /// Onset times (seconds from the recording's start) of tone bursts in
    /// `samples`, found with a 5 ms energy envelope.
    pub fn onsets(samples: &[f32]) -> Vec<f64> {
        let win = (SAMPLE_RATE / 200) as usize;
        let mut out = Vec::new();
        let mut on = false;
        let mut quiet = 0usize;
        for (k, w) in samples.chunks(win).enumerate() {
            let rms = (w.iter().map(|s| s * s).sum::<f32>() / w.len() as f32).sqrt();
            if !on && rms > 0.08 {
                on = true;
                quiet = 0;
                out.push((k * win) as f64 / SAMPLE_RATE as f64);
            } else if on && rms < 0.02 {
                quiet += 1;
                if quiet >= 8 {
                    on = false;
                }
            } else {
                quiet = 0;
            }
        }
        out
    }

    /// For `Bursts`: mean delay from each burst we sent to the next onset we
    /// heard back (the far side running `Echo`).
    fn round_trip_ms(&self) -> Option<f32> {
        let TestSource::Bursts { period_ms, .. } = self.source else { return None };
        let src = self.source_start()?;
        let rec = self.recording.lock();
        let rec_start = rec.start?;
        let offset = rec_start.saturating_duration_since(src).as_secs_f64();
        let period = period_ms as f64 / 1000.0;
        let delays: Vec<f64> = TestAudio::onsets(&rec.samples)
            .into_iter()
            .map(|t| t + offset)
            .map(|t| t - (t / period).floor() * period)
            .collect();
        if delays.len() < 2 {
            return None;
        }
        // skip the first (start-up); median of the rest
        let mut d: Vec<f64> = delays[1..].to_vec();
        d.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Some((d[d.len() / 2] * 1000.0) as f32)
    }
}

impl AudioIo for TestAudio {
    fn describe(&self) -> String {
        match self.source {
            TestSource::Silence => "Test audio (silence)".into(),
            TestSource::Sine { hz, .. } => format!("Test tone {hz} Hz"),
            TestSource::Bursts { hz, .. } => format!("Test tone bursts {hz} Hz"),
            TestSource::Echo => "Test echo".into(),
        }
    }

    fn open(&self, mut ports: AudioPorts) -> Result<AudioHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let (source, keep, recording) = (self.source, self.keep, self.recording.clone());
        *recording.lock() = Recording::default();
        let source_start = self.source_start.clone();
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("mycel-test-audio".into()).spawn(move || {
            let start = Instant::now();
            *source_start.lock() = Some(start);
            let mut produced: u64 = 0;
            let mut echo: Vec<f32> = Vec::new();
            let mut tick: u32 = 0;
            while !flag.load(Ordering::Relaxed) {
                tick += 1;
                let due = start + TICK * tick;
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
                // "speaker": play one tick's worth
                let mut played = vec![0f32; TICK_SAMPLES];
                let _ = ports.speaker.pop_partial_slice(&mut played);
                {
                    let mut rec = recording.lock();
                    rec.start.get_or_insert(due);
                    rec.samples.extend_from_slice(&played);
                    if rec.samples.len() > keep {
                        let cut = rec.samples.len() - keep;
                        rec.samples.drain(..cut);
                        rec.start = rec.start.map(|s| s + Duration::from_secs_f64(cut as f64 / SAMPLE_RATE as f64));
                    }
                }
                // "microphone": one tick of the source (or what we just heard)
                let mic: Vec<f32> = match source {
                    TestSource::Echo => {
                        echo.extend_from_slice(&played);
                        echo.drain(..TICK_SAMPLES.min(echo.len())).collect()
                    }
                    _ => (0..TICK_SAMPLES as u64).map(|i| TestAudio::sample(source, produced + i)).collect(),
                };
                produced += TICK_SAMPLES as u64;
                let _ = ports.mic.push_partial_slice(&mic);
            }
        })?;
        Ok(AudioHandle::new(StopOnDrop { stop, thread: Some(thread) }))
    }

    fn diagnostics(&self) -> AudioDiag {
        let heard = {
            let rec = self.recording.lock();
            let last = SAMPLE_RATE as usize;
            let tail = &rec.samples[rec.samples.len().saturating_sub(last)..];
            estimate_frequency(tail, SAMPLE_RATE)
        };
        AudioDiag { heard_tone_hz: heard, measured_round_trip_ms: self.round_trip_ms() }
    }
}

struct StopOnDrop {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ───────────────────────────── device audio (cpal) ─────────────────────────────

/// The default input and output devices through `cpal` (CoreAudio on
/// macOS). No echo cancellation: use headphones, or the voice-processing
/// backend on macOS.
pub struct DeviceAudio;

impl AudioIo for DeviceAudio {
    fn describe(&self) -> String {
        "Default microphone and speakers".into()
    }

    fn prepare(&self) -> Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        crate::mac::ensure_mic_permission()?;
        Ok(())
    }

    fn open(&self, ports: AudioPorts) -> Result<AudioHandle> {
        // cpal streams aren't Send everywhere: own them on their own thread.
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("mycel-audio".into()).spawn(move || {
            match cpal_streams(ports) {
                Ok(streams) => {
                    let _ = ready_tx.send(Ok(()));
                    while !flag.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    drop(streams);
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        })?;
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(AudioHandle::new(StopOnDrop { stop, thread: Some(thread) })),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow!("the audio devices didn't start")),
        }
    }
}

fn cpal_streams(mut ports: AudioPorts) -> Result<(cpal::Stream, cpal::Stream)> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let host = cpal::default_host();
    let input = host.default_input_device().context("no microphone found")?;
    let output = host.default_output_device().context("no speakers or headphones found")?;
    let in_cfg = input.default_input_config().context("the microphone can't be opened")?;
    let out_cfg = output.default_output_config().context("the speakers can't be opened")?;
    if in_cfg.sample_format() != cpal::SampleFormat::F32 || out_cfg.sample_format() != cpal::SampleFormat::F32 {
        bail!("unsupported audio sample format (need 32-bit float)");
    }
    let in_ch = in_cfg.channels() as usize;
    let out_ch = out_cfg.channels() as usize;
    let mut up = Resampler::new(in_cfg.sample_rate().0, SAMPLE_RATE);
    let mut down = Resampler::new(SAMPLE_RATE, out_cfg.sample_rate().0);
    let out_ratio = out_cfg.sample_rate().0 as f64 / SAMPLE_RATE as f64;

    let mut mono = Vec::new();
    let mut resampled = Vec::new();
    let on_err = |e| eprintln!("[mycel] audio stream error: {e}");
    let in_stream = input.build_input_stream(
        &in_cfg.config(),
        move |data: &[f32], _| {
            mono.clear();
            resampled.clear();
            to_mono(data, in_ch, &mut mono);
            up.process(&mono, &mut resampled);
            let _ = ports.mic.push_partial_slice(&resampled);
        },
        on_err,
        None,
    )?;
    let mut pending: Vec<f32> = Vec::new();
    let mut from_call = Vec::new();
    let out_stream = output.build_output_stream(
        &out_cfg.config(),
        move |data: &mut [f32], _| {
            let frames = data.len() / out_ch;
            // pull enough 48 kHz audio for this many device frames
            let need = ((frames.saturating_sub(pending.len())) as f64 / out_ratio).ceil() as usize + 2;
            from_call.resize(need, 0.0);
            let got = ports.speaker.pop_partial_slice(&mut from_call).0.len();
            from_call.truncate(got);
            down.process(&from_call, &mut pending);
            for (i, frame) in data.chunks_exact_mut(out_ch).enumerate() {
                let s = pending.get(i).copied().unwrap_or(0.0);
                frame.fill(s);
            }
            let used = frames.min(pending.len());
            pending.drain(..used);
        },
        on_err,
        None,
    )?;
    in_stream.play()?;
    out_stream.play()?;
    Ok((in_stream, out_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_paces_in_real_time_and_records() {
        let audio = TestAudio::new(TestSource::Sine { hz: 440.0, amp: 0.5 });
        let (mic_tx, mut mic_rx) = rtrb::RingBuffer::new(48_000);
        let (mut spk_tx, spk_rx) = rtrb::RingBuffer::new(48_000);
        // something to "play": 0.2 s of 300 Hz
        for i in 0..9_600 {
            let _ = spk_tx.push(0.4 * (2.0 * std::f32::consts::PI * 300.0 * i as f32 / 48_000.0).sin());
        }
        let h = audio.open(AudioPorts { mic: mic_tx, speaker: spk_rx }).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(h);
        let got = mic_rx.slots();
        assert!((12_000..17_500).contains(&got), "~0.3 s of mic audio, got {got}");
        let mut mic = vec![0f32; got];
        mic_rx.pop_entire_slice(&mut mic).unwrap();
        assert!((estimate_frequency(&mic, 48_000).unwrap() - 440.0).abs() < 2.0);
        let rec = audio.recording();
        let rec = rec.lock();
        assert!((estimate_frequency(&rec.samples[..9_600], 48_000).unwrap() - 300.0).abs() < 2.0);
    }

    #[test]
    fn burst_onsets_are_found() {
        let src = TestSource::Bursts { hz: 1000.0, on_ms: 100, period_ms: 500 };
        let samples: Vec<f32> = (0..96_000u64).map(|i| TestAudio::sample(src, i)).collect();
        let on = TestAudio::onsets(&samples);
        assert_eq!(on.len(), 4);
        for (k, t) in on.iter().enumerate() {
            assert!((t - k as f64 * 0.5).abs() < 0.006, "{on:?}");
        }
    }
}
