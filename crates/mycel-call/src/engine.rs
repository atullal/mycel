//! A call's media: microphone → Opus → every peer, and every peer → jitter
//! buffer → Opus decoder → mix → speaker.
//!
//! One [`Media`] per call owns the audio device and two real-time threads:
//! the send thread (paced by the capture clock) encodes each 20 ms frame
//! once per bitrate tier in use and sends it to every joined peer; the play
//! thread (paced by the playback clock) pulls one frame from each peer's
//! jitter buffer, decodes it with that peer's decoder and mixes the result.
//!
//! Each peer is a [`LegMedia`]: its QUIC connection, jitter buffer, decoder,
//! send bitrate and receive tasks. Legs come and go while the call runs
//! (people join late and leave early). A 1:1 call is simply one leg.
//!
//! Frames start with a one-byte track kind ([`crate::frame::KIND_AUDIO`]).
//! Datagrams and unidirectional streams of any other kind are handed to the
//! call's [`TrackSink`] untouched; that is where video plugs in.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use mycel_crypto::SignPk;
use mycel_net::iroh::endpoint::{Connection, RecvStream, SendDatagramError};
use mycel_video::realtime;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::audio::{AudioHandle, AudioIo, AudioPorts};
use crate::codec::{Decoder, Encoder, FRAME_MS, FRAME_SAMPLES, MAX_PACKET, SAMPLE_RATE};
use crate::frame::{AudioFrame, FLAG_MUTED, KIND_AUDIO, StreamDeframer};
use crate::jitter::{JitterBuffer, JitterStats, Playout};
use crate::level::meter;
use crate::proto::CallId;

/// One audio frame.
const FRAME: Duration = Duration::from_millis(FRAME_MS as u64);

/// Keep at least this much decoded audio queued for the speaker (~25 ms).
const PLAYOUT_FILL: usize = FRAME_SAMPLES * 5 / 4;
/// ... and at most this much (100 ms), however big the device's bursts.
const MAX_PLAYOUT_FILL: usize = FRAME_SAMPLES * 5;
/// If the mic backs up (a stall), drop audio beyond this so we stay live.
const MIC_BACKLOG: usize = FRAME_SAMPLES * 4;
const MIC_RING: usize = SAMPLE_RATE as usize;
const SPEAKER_RING: usize = SAMPLE_RATE as usize / 2;
/// Opus bitrates we actually encode at. Each peer's bitrate (from its path
/// and loss) is rounded down to one of these, so a call encodes each frame
/// at most this many times however many people are in it.
pub const TIERS: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 32_000];

pub fn tier(bitrate: u32) -> u32 {
    TIERS.iter().rev().copied().find(|t| *t <= bitrate).unwrap_or(TIERS[0])
}

fn f32_load(a: &AtomicU32) -> f32 {
    f32::from_bits(a.load(Ordering::Relaxed))
}

fn f32_store(a: &AtomicU32, v: f32) {
    a.store(v.to_bits(), Ordering::Relaxed)
}

/// Where tracks other than audio go (video). Called from network tasks;
/// implementations must not block.
pub trait TrackSink: Send + Sync + 'static {
    /// A peer's media connection joined the call: send your track on it.
    fn leg_added(&self, _call: &CallId, _peer: &SignPk, _conn: &Connection) {}
    /// A peer left (or its connection was replaced).
    fn leg_removed(&self, _call: &CallId, _peer: &SignPk) {}
    /// A datagram whose first byte (`kind`) isn't audio.
    fn datagram(&self, _call: &CallId, _peer: &SignPk, _kind: u8, _data: Bytes) {}
    /// A unidirectional stream whose first byte (`kind`, already read) isn't audio.
    fn stream(&self, _call: &CallId, _peer: &SignPk, _kind: u8, _stream: RecvStream) {}
}

/// One peer's half of the media.
pub struct LegMedia {
    pub peer: SignPk,
    conn: Connection,
    /// Opus bitrate for what we send this peer (one of [`TIERS`]).
    pub bitrate: AtomicU32,
    /// Expected loss (percent) for Opus FEC.
    pub fec_loss: AtomicU32,
    pub frames_sent: AtomicU64,
    pub remote_muted: AtomicBool,
    /// Frames go on a stream: this path can't carry datagrams.
    pub stream_mode: AtomicBool,
    jitter: Mutex<JitterBuffer>,
    decoder: Mutex<Decoder>,
    /// Level of what this peer says, 0..1.
    level: AtomicU32,
    last_rx: Mutex<Option<Instant>>,
    stream_tx: mpsc::UnboundedSender<Bytes>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl LegMedia {
    pub fn jitter_stats(&self) -> JitterStats {
        self.jitter.lock().stats()
    }

    pub fn level(&self) -> f32 {
        f32_load(&self.level)
    }

    /// Time since the last frame arrived (`None` if none yet).
    pub fn since_last_frame(&self) -> Option<Duration> {
        self.last_rx.lock().map(|t| t.elapsed())
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn receive_frame(&self, f: AudioFrame) {
        let now = Instant::now();
        self.remote_muted.store(f.muted(), Ordering::Relaxed);
        *self.last_rx.lock() = Some(now);
        self.jitter.lock().push(f.seq, f.payload, now);
    }

    /// Send one encoded frame (from the send thread).
    fn send(&self, frame: &AudioFrame) -> bool {
        if !self.stream_mode.load(Ordering::Relaxed) {
            match self.conn.send_datagram(frame.encode()) {
                Ok(()) => {
                    self.frames_sent.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(SendDatagramError::ConnectionLost(_)) => return false,
                Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
                    self.stream_mode.store(true, Ordering::Relaxed);
                }
                // too big for this path right now: send this one on the stream
                Err(SendDatagramError::TooLarge) => {}
            }
        }
        if self.stream_tx.send(frame.encode_for_stream()).is_err() {
            return false;
        }
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn stop(&self) {
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }
}

/// State shared between a call's media threads and the call.
pub struct MediaShared {
    pub muted: AtomicBool,
    mic_level: AtomicU32,
    /// Level of the mix we play.
    out_level: AtomicU32,
    legs: RwLock<Vec<Arc<LegMedia>>>,
    stop: AtomicBool,
}

impl MediaShared {
    pub fn mic_level(&self) -> f32 {
        f32_load(&self.mic_level)
    }

    pub fn out_level(&self) -> f32 {
        f32_load(&self.out_level)
    }

    pub fn leg(&self, peer: &SignPk) -> Option<Arc<LegMedia>> {
        self.legs.read().iter().find(|l| l.peer == *peer).cloned()
    }

    pub fn legs(&self) -> Vec<Arc<LegMedia>> {
        self.legs.read().clone()
    }
}

pub struct Media {
    call: CallId,
    shared: Arc<MediaShared>,
    rt: tokio::runtime::Handle,
    sink: Option<Arc<dyn TrackSink>>,
    _audio: AudioHandle,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Media {
    /// Open the audio device and start the send and play threads (no peers yet).
    pub fn start(
        call: CallId,
        audio: &dyn AudioIo,
        muted: bool,
        sink: Option<Arc<dyn TrackSink>>,
        rt: tokio::runtime::Handle,
    ) -> Result<Media> {
        let (mic_tx, mut mic_rx) = rtrb::RingBuffer::new(MIC_RING);
        let (mut spk_tx, spk_rx) = rtrb::RingBuffer::new(SPEAKER_RING);
        let shared = Arc::new(MediaShared {
            muted: AtomicBool::new(muted),
            mic_level: AtomicU32::new(0),
            out_level: AtomicU32::new(0),
            legs: RwLock::new(Vec::new()),
            stop: AtomicBool::new(false),
        });
        let handle = audio.open(AudioPorts { mic: mic_tx, speaker: spk_rx })?;

        let mut threads = Vec::new();
        // send: capture-clocked; one encoder per bitrate tier in use
        {
            let shared = shared.clone();
            threads.push(std::thread::Builder::new().name("mycel-call-send".into()).spawn(move || {
                // wakes every 2 ms; encodes a 20 ms frame once per tier in use
                realtime::promote_current_thread(FRAME, Duration::from_millis(4));
                let mut pcm = vec![0f32; FRAME_SAMPLES];
                let mut out = [0u8; MAX_PACKET];
                let mut encoders: BTreeMap<u32, Encoder> = BTreeMap::new();
                let mut seq: u32 = 0;
                while !shared.stop.load(Ordering::Relaxed) {
                    if mic_rx.slots() < FRAME_SAMPLES {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    while mic_rx.slots() > MIC_BACKLOG {
                        let _ = mic_rx.pop_entire_slice(&mut pcm);
                    }
                    if mic_rx.pop_entire_slice(&mut pcm).is_err() {
                        continue;
                    }
                    let muted = shared.muted.load(Ordering::Relaxed);
                    if muted {
                        pcm.fill(0.0);
                    }
                    f32_store(&shared.mic_level, if muted { 0.0 } else { meter(&pcm) });
                    let legs = shared.legs();
                    // tier → (FEC loss, peers)
                    let mut by_tier: BTreeMap<u32, (u32, Vec<&Arc<LegMedia>>)> = BTreeMap::new();
                    for l in &legs {
                        let e = by_tier.entry(tier(l.bitrate.load(Ordering::Relaxed))).or_default();
                        e.0 = e.0.max(l.fec_loss.load(Ordering::Relaxed));
                        e.1.push(l);
                    }
                    encoders.retain(|t, _| by_tier.contains_key(t));
                    let timestamp = seq.wrapping_mul(FRAME_SAMPLES as u32);
                    for (t, (loss, peers)) in by_tier {
                        let enc = match encoders.entry(t) {
                            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                            std::collections::btree_map::Entry::Vacant(v) => match Encoder::new(t) {
                                Ok(e) => v.insert(e),
                                Err(_) => continue,
                            },
                        };
                        let _ = enc.set_expected_loss(loss as u8);
                        let Ok(n) = enc.encode(&pcm, &mut out) else { continue };
                        let frame = AudioFrame {
                            seq,
                            timestamp,
                            flags: if muted { FLAG_MUTED } else { 0 },
                            payload: Bytes::copy_from_slice(&out[..n]),
                        };
                        for l in peers {
                            l.send(&frame);
                        }
                    }
                    seq = seq.wrapping_add(1);
                }
            })?);
        }
        // play: playback-clocked; decode each peer and mix
        {
            let shared = shared.clone();
            threads.push(std::thread::Builder::new().name("mycel-call-play".into()).spawn(move || {
                // wakes every 3 ms; decodes and mixes a frame per peer
                realtime::promote_current_thread(FRAME, Duration::from_millis(3));
                let mut pcm = vec![0f32; FRAME_SAMPLES];
                let mut mix = vec![0f32; FRAME_SAMPLES];
                let mut cushion = Cushion::default();
                while !shared.stop.load(Ordering::Relaxed) {
                    let queued = SPEAKER_RING - spk_tx.slots();
                    if queued >= cushion.observe(queued) {
                        std::thread::sleep(Duration::from_millis(3));
                        continue;
                    }
                    mix.fill(0.0);
                    for leg in shared.legs() {
                        let next = leg.jitter.lock().pop();
                        let mut decoder = leg.decoder.lock();
                        let ok = match next {
                            Playout::Frame(p) => {
                                decoder.decode(&p, &mut pcm).is_ok() || decoder.conceal(&mut pcm).is_ok()
                            }
                            Playout::Lost { fec: Some(p) } => {
                                decoder.recover(&p, &mut pcm).is_ok() || decoder.conceal(&mut pcm).is_ok()
                            }
                            Playout::Lost { fec: None } => decoder.conceal(&mut pcm).is_ok(),
                            Playout::Silence => false,
                        };
                        drop(decoder);
                        if !ok {
                            f32_store(&leg.level, 0.0);
                            continue;
                        }
                        f32_store(&leg.level, meter(&pcm));
                        for (m, s) in mix.iter_mut().zip(&pcm) {
                            *m += s;
                        }
                    }
                    limit(&mut mix);
                    f32_store(&shared.out_level, meter(&mix));
                    let _ = spk_tx.push_partial_slice(&mix);
                    cushion.refilled(SPEAKER_RING - spk_tx.slots());
                }
            })?);
        }
        Ok(Media { call, shared, rt, sink, _audio: handle, threads })
    }

    pub fn shared(&self) -> &Arc<MediaShared> {
        &self.shared
    }

    /// Start exchanging audio with `peer` over `conn` (replacing any
    /// previous connection to them).
    pub fn add_leg(&self, peer: SignPk, conn: Connection, bitrate: u32, force_stream: bool) -> Arc<LegMedia> {
        self.remove_leg(&peer);
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<Bytes>();
        let leg = Arc::new(LegMedia {
            peer,
            conn: conn.clone(),
            bitrate: AtomicU32::new(tier(bitrate)),
            fec_loss: AtomicU32::new(5),
            frames_sent: AtomicU64::new(0),
            remote_muted: AtomicBool::new(false),
            stream_mode: AtomicBool::new(force_stream || conn.max_datagram_size().is_none()),
            jitter: Mutex::new(JitterBuffer::for_calls()),
            decoder: Mutex::new(Decoder::new().expect("opus decoder")),
            level: AtomicU32::new(0),
            last_rx: Mutex::new(None),
            stream_tx,
            tasks: Mutex::new(Vec::new()),
        });
        let mut tasks = Vec::new();
        // stream fallback: frames queued here go out on one uni stream
        // that starts with the track kind
        {
            let conn = conn.clone();
            tasks.push(self.rt.spawn(async move {
                let Some(first) = stream_rx.recv().await else { return };
                let Ok(mut tx) = conn.open_uni().await else { return };
                if tx.write_all(&[KIND_AUDIO]).await.is_err() || tx.write_all(&first).await.is_err() {
                    return;
                }
                while let Some(b) = stream_rx.recv().await {
                    if tx.write_all(&b).await.is_err() {
                        return;
                    }
                }
            }));
        }
        // receive: datagrams, demultiplexed by track kind
        {
            let (conn, leg, sink, call) = (conn.clone(), leg.clone(), self.sink.clone(), self.call);
            tasks.push(self.rt.spawn(async move {
                while let Ok(d) = conn.read_datagram().await {
                    match d.first() {
                        Some(&KIND_AUDIO) => {
                            if let Ok(f) = AudioFrame::decode(d) {
                                leg.receive_frame(f);
                            }
                        }
                        Some(&kind) => {
                            if let Some(s) = &sink {
                                s.datagram(&call, &leg.peer, kind, d);
                            }
                        }
                        None => {}
                    }
                }
            }));
        }
        // receive: unidirectional streams (audio fallback, or other tracks)
        {
            let (conn, leg, sink, call) = (conn.clone(), leg.clone(), self.sink.clone(), self.call);
            tasks.push(self.rt.spawn(async move {
                while let Ok(mut rx) = conn.accept_uni().await {
                    let mut kind = [0u8; 1];
                    if rx.read_exact(&mut kind).await.is_err() {
                        continue;
                    }
                    if kind[0] != KIND_AUDIO {
                        if let Some(s) = &sink {
                            s.stream(&call, &leg.peer, kind[0], rx);
                        }
                        continue;
                    }
                    let leg = leg.clone();
                    tokio::spawn(async move {
                        let mut de = StreamDeframer::default();
                        let mut buf = vec![0u8; 4096];
                        while let Ok(Some(n)) = rx.read(&mut buf).await {
                            de.push(&buf[..n]);
                            while let Ok(Some(f)) = de.next_frame() {
                                leg.receive_frame(f);
                            }
                        }
                    });
                }
            }));
        }
        *leg.tasks.lock() = tasks;
        self.shared.legs.write().push(leg.clone());
        if let Some(s) = &self.sink {
            s.leg_added(&self.call, &peer, &conn);
        }
        leg
    }

    /// Stop exchanging audio with `peer`.
    pub fn remove_leg(&self, peer: &SignPk) {
        let gone: Vec<Arc<LegMedia>> = {
            let mut legs = self.shared.legs.write();
            let (gone, keep): (Vec<_>, Vec<_>) = legs.drain(..).partition(|l| l.peer == *peer);
            *legs = keep;
            gone
        };
        for l in &gone {
            l.stop();
        }
        if !gone.is_empty()
            && let Some(s) = &self.sink
        {
            s.leg_removed(&self.call, peer);
        }
    }
}

/// How much decoded audio the play thread keeps queued for the speaker.
///
/// The device takes audio in bursts of its buffer size: ~10 ms from Core
/// Audio, a few ms from AAudio, but 20–40 ms or more from some Bluetooth
/// headsets and Linux sound servers. A burst bigger than what's queued is
/// played partly as silence, and every such gap delays the rest of the
/// call's audio (the jitter buffer then has to trim it back out). So the
/// play thread keeps the largest recent burst queued, plus a quarter frame
/// of margin: between [`PLAYOUT_FILL`] (25 ms) and [`MAX_PLAYOUT_FILL`]
/// (100 ms). A burst is what the device took between two looks at the
/// queue, so a play thread that wakes late counts too, which is right: the
/// queue has to cover that as well. The peak halves after ~1.5 s of
/// smaller bursts, so one hiccup doesn't add delay for the rest of the call.
#[derive(Debug, Default)]
struct Cushion {
    /// Samples queued after the last refill.
    after_refill: usize,
    /// Largest recent burst, samples (decaying).
    peak: f32,
}

impl Cushion {
    /// Per look at the queue (every ~3 ms): a half-life of ~1.5 s.
    const DECAY: f32 = 0.9985;

    /// Note how much is queued now; returns how much should be.
    fn observe(&mut self, queued: usize) -> usize {
        let taken = self.after_refill.saturating_sub(queued);
        self.after_refill = queued;
        self.peak = (self.peak * Self::DECAY).max(taken as f32);
        self.target()
    }

    fn refilled(&mut self, queued: usize) {
        self.after_refill = queued;
    }

    fn target(&self) -> usize {
        (self.peak as usize + FRAME_SAMPLES / 4).clamp(PLAYOUT_FILL, MAX_PLAYOUT_FILL)
    }
}

/// Keep the mix within -1..1: scale the frame down if several voices add up
/// past full scale (no clipping, no distortion at normal levels).
fn limit(mix: &mut [f32]) {
    let peak = mix.iter().fold(0f32, |m, s| m.max(s.abs()));
    if peak > 0.98 {
        let g = 0.98 / peak;
        for s in mix.iter_mut() {
            *s *= g;
        }
    }
}

impl Drop for Media {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        let peers: Vec<SignPk> = self.shared.legs().iter().map(|l| l.peer).collect();
        for p in peers {
            self.remove_leg(&p);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_round_down() {
        assert_eq!(tier(32_000), 32_000);
        assert_eq!(tier(31_999), 24_000);
        assert_eq!(tier(12_000), 12_000);
        assert_eq!(tier(9_000), 8_000);
        assert_eq!(tier(1_000), 8_000);
        assert_eq!(tier(100_000), 32_000);
    }

    /// Run a play thread against a device that takes `burst` samples every
    /// `every` looks; returns the cushion's target and how often the
    /// device found the queue short.
    fn drive(cushion: &mut Cushion, burst: usize, every: usize, looks: usize) -> (usize, usize) {
        let mut queued = cushion.after_refill;
        let mut short = 0;
        for n in 0..=looks {
            // (n = 0: the play thread fills the queue before the device starts)
            if n > 0 && n % every == 0 {
                if queued < burst {
                    short += 1;
                }
                // the device can't take more than is queued: the rest is silence
                queued = queued.saturating_sub(burst);
            }
            while queued < cushion.observe(queued) {
                queued += FRAME_SAMPLES;
                cushion.refilled(queued);
            }
        }
        (cushion.target(), short)
    }

    #[test]
    fn cushion_covers_the_device_bursts() {
        // Core Audio's ~10 ms: the 25 ms floor
        let mut c = Cushion::default();
        let (target, short) = drive(&mut c, 480, 3, 3_000);
        assert_eq!(target, PLAYOUT_FILL);
        assert_eq!(short, 0);
        // a 40 ms Bluetooth burst: the old fixed 25 ms ran short every time
        let mut c = Cushion::default();
        let (target, short) = drive(&mut c, 1_920, 13, 3_000);
        // (the peak decays a little between bursts, staying above one)
        assert!((1_920..=1_920 + FRAME_SAMPLES / 4).contains(&target), "{target}");
        assert_eq!(short, 0);
        // a 60 ms burst: short for the first few bursts, then covered
        let mut c = Cushion::default();
        let (target, short) = drive(&mut c, 2_880, 20, 3_000);
        assert!((2_880..=2_880 + FRAME_SAMPLES / 4).contains(&target), "{target}");
        assert!(short <= 3, "short {short} times");
        // never more than 100 ms, whatever the device does
        let mut c = Cushion::default();
        let (target, _) = drive(&mut c, 48_000 / 4, 50, 1_000);
        assert_eq!(target, MAX_PLAYOUT_FILL);
    }

    #[test]
    fn cushion_shrinks_back_after_a_hiccup() {
        let mut c = Cushion::default();
        drive(&mut c, 3_000, 1, 5);
        assert!(c.target() > 3_000, "{c:?}");
        // ~3 s of 10 ms bursts afterwards
        let (target, short) = drive(&mut c, 480, 3, 1_000);
        assert_eq!(target, PLAYOUT_FILL);
        assert_eq!(short, 0);
    }

    #[test]
    fn limiter_only_acts_on_overload() {
        let mut quiet = vec![0.5, -0.4, 0.1];
        limit(&mut quiet);
        assert_eq!(quiet, vec![0.5, -0.4, 0.1]);
        let mut loud = vec![1.5, -0.75, 0.3];
        limit(&mut loud);
        assert!((loud[0] - 0.98).abs() < 1e-6 && (loud[1] + 0.49).abs() < 1e-6);
    }
}
