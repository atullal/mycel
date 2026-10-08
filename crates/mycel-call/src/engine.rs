//! One call's media: microphone → Opus → QUIC datagrams, and datagrams →
//! jitter buffer → Opus (with loss concealment / FEC) → speaker.
//!
//! Two plain threads do the real-time work (encoding paced by the capture
//! clock, decoding paced by the playback clock), and two async tasks receive
//! frames (datagrams, or the stream fallback). They share [`MediaShared`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use mycel_net::iroh::endpoint::{Connection, SendDatagramError};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::audio::{AudioHandle, AudioIo, AudioPorts};
use crate::codec::{Decoder, Encoder, FRAME_SAMPLES, MAX_PACKET, SAMPLE_RATE};
use crate::frame::{AudioFrame, FLAG_MUTED, StreamDeframer};
use crate::jitter::{JitterBuffer, JitterStats, Playout};
use crate::level::meter;

/// Keep this much decoded audio queued for the speaker (~25 ms).
const PLAYOUT_FILL: usize = FRAME_SAMPLES * 5 / 4;
/// If the mic backs up (a stall), drop audio beyond this so we stay live.
const MIC_BACKLOG: usize = FRAME_SAMPLES * 4;
const MIC_RING: usize = SAMPLE_RATE as usize;
const SPEAKER_RING: usize = SAMPLE_RATE as usize / 2;

fn f32_load(a: &AtomicU32) -> f32 {
    f32::from_bits(a.load(Ordering::Relaxed))
}

fn f32_store(a: &AtomicU32, v: f32) {
    a.store(v.to_bits(), Ordering::Relaxed)
}

/// State shared between a call's media threads/tasks and the call driver.
pub struct MediaShared {
    pub muted: AtomicBool,
    /// Opus target bitrate (bits/s), set by the bitrate controller.
    pub bitrate: AtomicU32,
    /// Expected loss (percent) for Opus FEC.
    pub fec_loss: AtomicU32,
    mic_level: AtomicU32,
    out_level: AtomicU32,
    pub frames_sent: AtomicU64,
    pub remote_muted: AtomicBool,
    /// Frames go on a stream: the path can't carry datagrams.
    pub stream_mode: AtomicBool,
    pub jitter: Mutex<JitterBuffer>,
    last_rx: Mutex<Option<Instant>>,
    stop: AtomicBool,
}

impl MediaShared {
    pub fn mic_level(&self) -> f32 {
        f32_load(&self.mic_level)
    }

    pub fn out_level(&self) -> f32 {
        f32_load(&self.out_level)
    }

    pub fn jitter_stats(&self) -> JitterStats {
        self.jitter.lock().stats()
    }

    /// Time since the last frame arrived (`None` if none yet).
    pub fn since_last_frame(&self) -> Option<Duration> {
        self.last_rx.lock().map(|t| t.elapsed())
    }
}

pub struct Media {
    shared: Arc<MediaShared>,
    _audio: AudioHandle,
    threads: Vec<std::thread::JoinHandle<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Media {
    /// Open the audio device and start sending and receiving on `conn`.
    pub fn start(
        conn: Connection,
        audio: &dyn AudioIo,
        bitrate: u32,
        muted: bool,
        force_stream: bool,
        rt: tokio::runtime::Handle,
    ) -> Result<Media> {
        let (mic_tx, mut mic_rx) = rtrb::RingBuffer::new(MIC_RING);
        let (mut spk_tx, spk_rx) = rtrb::RingBuffer::new(SPEAKER_RING);
        let shared = Arc::new(MediaShared {
            muted: AtomicBool::new(muted),
            bitrate: AtomicU32::new(bitrate),
            fec_loss: AtomicU32::new(5),
            mic_level: AtomicU32::new(0),
            out_level: AtomicU32::new(0),
            frames_sent: AtomicU64::new(0),
            remote_muted: AtomicBool::new(false),
            stream_mode: AtomicBool::new(force_stream || conn.max_datagram_size().is_none()),
            jitter: Mutex::new(JitterBuffer::for_calls()),
            last_rx: Mutex::new(None),
            stop: AtomicBool::new(false),
        });
        let mut encoder = Encoder::new(bitrate)?;
        let mut decoder = Decoder::new()?;
        let handle = audio.open(AudioPorts { mic: mic_tx, speaker: spk_rx })?;

        // stream fallback: frames queued here go out on one uni stream
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<Bytes>();
        let mut tasks = Vec::new();
        {
            let conn = conn.clone();
            tasks.push(rt.spawn(async move {
                let Some(first) = stream_rx.recv().await else { return };
                let Ok(mut tx) = conn.open_uni().await else { return };
                if tx.write_all(&first).await.is_err() {
                    return;
                }
                while let Some(b) = stream_rx.recv().await {
                    if tx.write_all(&b).await.is_err() {
                        return;
                    }
                }
            }));
        }
        // receive: datagrams
        {
            let (conn, shared) = (conn.clone(), shared.clone());
            tasks.push(rt.spawn(async move {
                while let Ok(d) = conn.read_datagram().await {
                    receive(&shared, d);
                }
            }));
        }
        // receive: stream fallback
        {
            let (conn, shared) = (conn.clone(), shared.clone());
            tasks.push(rt.spawn(async move {
                while let Ok(mut rx) = conn.accept_uni().await {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let mut de = StreamDeframer::default();
                        let mut buf = vec![0u8; 4096];
                        while let Ok(Some(n)) = rx.read(&mut buf).await {
                            de.push(&buf[..n]);
                            while let Ok(Some(f)) = de.next_frame() {
                                receive_frame(&shared, f);
                            }
                        }
                    });
                }
            }));
        }

        let mut threads = Vec::new();
        // send: capture-clocked
        {
            let shared = shared.clone();
            threads.push(std::thread::Builder::new().name("mycel-call-send".into()).spawn(move || {
                let mut pcm = vec![0f32; FRAME_SAMPLES];
                let mut out = [0u8; MAX_PACKET];
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
                    let _ = encoder.set_bitrate(shared.bitrate.load(Ordering::Relaxed));
                    let _ = encoder.set_expected_loss(shared.fec_loss.load(Ordering::Relaxed) as u8);
                    let Ok(n) = encoder.encode(&pcm, &mut out) else { continue };
                    let frame = AudioFrame {
                        seq,
                        timestamp: seq.wrapping_mul(FRAME_SAMPLES as u32),
                        flags: if muted { FLAG_MUTED } else { 0 },
                        payload: Bytes::copy_from_slice(&out[..n]),
                    };
                    seq = seq.wrapping_add(1);
                    if !shared.stream_mode.load(Ordering::Relaxed) {
                        match conn.send_datagram(frame.encode()) {
                            Ok(()) => {
                                shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            Err(SendDatagramError::ConnectionLost(_)) => break,
                            Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
                                shared.stream_mode.store(true, Ordering::Relaxed);
                            }
                            // too big for this path right now: send this one on the stream
                            Err(SendDatagramError::TooLarge) => {}
                        }
                    }
                    if stream_tx.send(frame.encode_for_stream()).is_err() {
                        break;
                    }
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                }
            })?);
        }
        // play: playback-clocked
        {
            let shared = shared.clone();
            threads.push(std::thread::Builder::new().name("mycel-call-play".into()).spawn(move || {
                let mut pcm = vec![0f32; FRAME_SAMPLES];
                while !shared.stop.load(Ordering::Relaxed) {
                    let queued = SPEAKER_RING - spk_tx.slots();
                    if queued >= PLAYOUT_FILL {
                        std::thread::sleep(Duration::from_millis(3));
                        continue;
                    }
                    let next = shared.jitter.lock().pop();
                    let ok = match next {
                        Playout::Frame(p) => decoder.decode(&p, &mut pcm).is_ok() || decoder.conceal(&mut pcm).is_ok(),
                        Playout::Lost { fec: Some(p) } => {
                            decoder.recover(&p, &mut pcm).is_ok() || decoder.conceal(&mut pcm).is_ok()
                        }
                        Playout::Lost { fec: None } => decoder.conceal(&mut pcm).is_ok(),
                        Playout::Silence => false,
                    };
                    if !ok {
                        pcm.fill(0.0);
                    }
                    f32_store(&shared.out_level, meter(&pcm));
                    let _ = spk_tx.push_partial_slice(&pcm);
                }
            })?);
        }
        Ok(Media { shared, _audio: handle, threads, tasks })
    }

    pub fn shared(&self) -> &Arc<MediaShared> {
        &self.shared
    }
}

fn receive(shared: &MediaShared, d: Bytes) {
    if let Ok(f) = AudioFrame::decode(d) {
        receive_frame(shared, f);
    }
}

fn receive_frame(shared: &MediaShared, f: AudioFrame) {
    let now = Instant::now();
    shared.remote_muted.store(f.muted(), Ordering::Relaxed);
    *shared.last_rx.lock() = Some(now);
    shared.jitter.lock().push(f.seq, f.payload, now);
}

impl Drop for Media {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for t in &self.tasks {
            t.abort();
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}
