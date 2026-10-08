//! One call's video, both directions, on the call's QUIC connection.
//!
//! - **Send**: the source (camera or test pattern) hands pictures to the
//!   encoder thread, which asks the [`RateController`] whether to encode
//!   each one, encodes it with VideoToolbox at the current quality, shows
//!   it as self-view, and queues it for the sender task. The sender opens a
//!   stream per frame (lower priority than anything else on the
//!   connection; audio datagrams always go first), and a watcher per frame
//!   reports when QUIC has it fully acknowledged, which drives the rate
//!   controller. Frames that are made obsolete by a newer keyframe, or stuck
//!   for over [`STALE`], have their streams reset so QUIC stops
//!   retransmitting them.
//! - **Receive**: each frame stream is read whole, put back in order by
//!   [`Reorder`], and handed to the app (which decodes it). A frame that
//!   can't arrive any more makes the receiver ask for a keyframe.
//! - **Control**: one stream per direction carries keyframe requests and
//!   camera on/off / paused state.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use bytes::Bytes;
use mycel_net::PathKind;
use mycel_net::iroh::endpoint::{Connection, ReadError, ReadExactError, RecvStream, SendStream};
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::platform::H264Encoder;
use crate::rate::{Admit, Quality, RateController};
use crate::receiver::Reorder;
use crate::source::{Picture, SourceHandle, VideoSource, wall_us};
use crate::wire::{
    CtrlDeframer, EncodedFrame, FRAME_HEADER_LEN, KIND_CTRL, KIND_FRAME, MAX_FRAME, STREAM_HEADER_LEN, UiFrame,
    UiSource, VideoCtrl, ctrl_stream_header, stream_kind,
};

/// Give up on a frame QUIC hasn't delivered after this long.
pub const STALE: Duration = Duration::from_millis(1500);
/// Video streams yield to everything else on the connection.
const FRAME_PRIORITY: i32 = -10;
const CTRL_PRIORITY: i32 = 5;
/// Self-view while the path can't carry video.
const PREVIEW: Quality = Quality::new(424, 240, 15);
const TICK: Duration = Duration::from_millis(50);
/// Remote video stopped arriving: show it as frozen, not live.
const RECV_IDLE: Duration = Duration::from_secs(2);

/// The state of our camera.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CameraState {
    #[default]
    Off,
    Starting,
    On,
    /// Not allowed (see `error`).
    Denied,
    /// Couldn't start (see `error`).
    Failed,
}

/// Live video numbers for a call (JSON: camelCase).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoInfo {
    pub camera: CameraState,
    /// Why the camera is denied or failed, and what to do.
    pub error: Option<String>,
    /// Our video is going out.
    pub sending: bool,
    /// Our video is paused because the path can't carry it (Bluetooth).
    pub paused: bool,
    /// The other side has its camera on.
    pub remote_camera: bool,
    /// The other side's video is paused (slow connection).
    pub remote_paused: bool,
    /// Their frames are arriving.
    pub receiving: bool,
    pub send_width: u32,
    pub send_height: u32,
    /// Frames per second we sent over the last second.
    pub send_fps: f32,
    /// Target video bitrate (bits/s).
    pub bitrate: u32,
    /// What we actually sent over the last second (bits/s).
    pub sent_bitrate: u32,
    /// How long our frames wait in queues beyond the RTT (smoothed).
    pub queue_ms: u32,
    pub recv_width: u32,
    pub recv_height: u32,
    pub recv_fps: f32,
    /// Capture on their side to arrival here, decodable (their clock vs
    /// ours: approximate across devices).
    pub latency_ms: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    /// Pictures not sent because the path was backed up.
    pub frames_skipped: u64,
    pub keyframes_sent: u64,
    /// Keyframes we asked for (after losing frames).
    pub keyframe_requests: u64,
    /// What captures our video.
    pub source: String,
    /// Which encoder ("H.264 hardware", "H.264 low-latency", ...).
    pub encoder: String,
}

/// A frame from encoding until it's acknowledged (or given up on).
struct Outstanding {
    queued: Instant,
    bytes: usize,
    /// Once it's been handed to QUIC: the stream, and when.
    stream: Option<SendStream>,
    handed: Option<Instant>,
}

impl Outstanding {
    fn give_up(mut self, seq: u32) {
        if let Some(s) = self.stream.as_mut() {
            let _ = s.reset(reset_code(seq));
        }
    }
}

/// Frame bytes are handed to QUIC at this multiple of the target bitrate,
/// so a keyframe doesn't land on the bottleneck all at once (where audio
/// would queue behind it).
const PACING: f64 = 2.0;

/// How much of a frame to hand QUIC at a time. On a slow path every video
/// packet holds up the audio packets behind it (a full 1200-byte packet is
/// 16 ms at 600 kbit/s), which shows up as audio jitter and a deeper jitter
/// buffer; smaller pieces there keep audio's wait to a few ms, at some
/// header overhead. Fast paths get full packets.
fn pace_chunk(target_bps: u32) -> usize {
    if let Some(n) = std::env::var("MYCEL_VIDEO_CHUNK").ok().and_then(|v| v.parse().ok()) {
        return n;
    }
    // ~4 ms of the target rate's worth, 200..1200 bytes
    ((target_bps as f64 / 8.0 * 0.004) as usize).clamp(200, 1200)
}

#[derive(Default)]
struct Window {
    start: Option<Instant>,
    count: u32,
    fps: f32,
}

impl Window {
    fn tick(&mut self, now: Instant) {
        let s = *self.start.get_or_insert(now);
        self.count += 1;
        let span = now.duration_since(s);
        if span >= Duration::from_secs(1) {
            self.fps = self.count as f32 / span.as_secs_f32();
            self.start = Some(now);
            self.count = 0;
        }
    }

    fn fps(&self, now: Instant) -> f32 {
        match self.start {
            Some(s) if now.duration_since(s) > Duration::from_secs(2) => 0.0,
            _ => self.fps,
        }
    }
}

#[derive(Default)]
struct SendSide {
    window: Window,
    frames: u64,
    keyframes: u64,
    skipped: u64,
    /// Sequence number of our newest keyframe.
    last_key: Option<u32>,
    size: (u32, u32),
    encoder: String,
}

#[derive(Default)]
struct RecvSide {
    window: Window,
    frames: u64,
    last: Option<Instant>,
    size: (u32, u32),
    latency_ms: Option<f32>,
    remote_camera: bool,
    remote_paused: bool,
}

/// The latest picture, for the encoder thread (older ones are dropped).
#[derive(Default)]
struct Latest {
    pic: Mutex<Option<Picture>>,
    ready: Condvar,
}

struct Shared {
    conn: Connection,
    me: [u8; 32],
    peer: [u8; 32],
    ui: broadcast::Sender<UiFrame>,
    ctl: Mutex<RateController>,
    rtt: Mutex<Duration>,
    force_key: AtomicBool,
    outstanding: Mutex<BTreeMap<u32, Outstanding>>,
    send: Mutex<SendSide>,
    recv: Mutex<RecvSide>,
    reorder: Mutex<Reorder>,
    camera: Mutex<(CameraState, Option<String>)>,
    source_desc: Mutex<String>,
    latest: Latest,
    ctrl_tx: mpsc::UnboundedSender<VideoCtrl>,
    stop: AtomicBool,
    /// Bumped when the camera turns on or off (the encoder restarts cleanly).
    generation: AtomicU64,
    /// Tests: give up on every n-th frame as if it got stuck.
    test_drop_every: std::sync::atomic::AtomicU32,
}

impl Shared {
    /// The backlog: bytes not yet handed to QUIC, and how long the oldest
    /// frame QUIC has is going unacknowledged.
    fn queued(&self, now: Instant) -> (u64, Option<Duration>) {
        let o = self.outstanding.lock();
        let bytes = o.values().filter(|f| f.handed.is_none()).map(|f| f.bytes as u64).sum();
        let oldest = o.values().filter_map(|f| f.handed).map(|t| now.duration_since(t)).max();
        (bytes, oldest)
    }

    fn sending_state(&self) -> VideoCtrl {
        let camera = self.camera.lock().0 == CameraState::On;
        VideoCtrl::State { camera, paused: self.ctl.lock().paused() }
    }

    fn deliver(&self, frames: Vec<EncodedFrame>, now: Instant) {
        if frames.is_empty() {
            return;
        }
        let mut r = self.recv.lock();
        for f in frames {
            r.window.tick(now);
            r.frames += 1;
            r.last = Some(now);
            r.size = (f.width as u32, f.height as u32);
            let lat = wall_us().saturating_sub(f.capture_us) as f32 / 1000.0;
            if lat < 60_000.0 {
                r.latency_ms = Some(match r.latency_ms {
                    None => lat,
                    Some(l) => l * 0.9 + lat * 0.1,
                });
            }
            let _ = self.ui.send(UiFrame { source: UiSource::Remote, peer: self.peer, frame: f });
        }
    }
}

/// A call's video. Dropping it stops everything.
pub struct VideoTrack {
    shared: Arc<Shared>,
    source: Arc<dyn VideoSource>,
    running: Mutex<Option<SourceHandle>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    encoder: Option<std::thread::JoinHandle<()>>,
    rt: tokio::runtime::Handle,
}

pub struct TrackOptions {
    /// Our device key and the other side's (UI frames say whose they are).
    pub me: [u8; 32],
    pub peer: [u8; 32],
    pub path: Option<PathKind>,
}

impl VideoTrack {
    /// Start receiving on `conn` (and sending once the camera is on).
    pub fn start(
        conn: Connection,
        source: Arc<dyn VideoSource>,
        ui: broadcast::Sender<UiFrame>,
        opts: TrackOptions,
        rt: tokio::runtime::Handle,
    ) -> VideoTrack {
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            conn: conn.clone(),
            me: opts.me,
            peer: opts.peer,
            ui,
            ctl: Mutex::new(RateController::new(opts.path)),
            rtt: Mutex::new(Duration::from_millis(50)),
            force_key: AtomicBool::new(true),
            outstanding: Mutex::default(),
            send: Mutex::default(),
            recv: Mutex::default(),
            reorder: Mutex::default(),
            camera: Mutex::default(),
            source_desc: Mutex::new(source.describe()),
            latest: Latest::default(),
            ctrl_tx,
            stop: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            test_drop_every: Default::default(),
        });
        let (frame_tx, frame_rx) = mpsc::unbounded_channel::<EncodedFrame>();
        let tasks = vec![
            rt.spawn(write_ctrl(shared.clone(), ctrl_rx)),
            rt.spawn(accept(shared.clone())),
            rt.spawn(send_frames(shared.clone(), frame_rx)),
            rt.spawn(tick(shared.clone())),
        ];
        let enc_shared = shared.clone();
        let encoder = std::thread::Builder::new()
            .name("mycel-video-encode".into())
            .spawn(move || encode_loop(enc_shared, frame_tx))
            .ok();
        let _ = shared.ctrl_tx.send(shared.sending_state());
        VideoTrack { shared, source, running: Mutex::new(None), tasks, encoder, rt }
    }

    /// Turn our camera on or off. Turning it on may ask for permission
    /// (blocking until the user answers), so call it off the async runtime.
    pub fn set_camera(&self, on: bool) -> Result<()> {
        let sh = &self.shared;
        if !on {
            self.running.lock().take();
            *sh.camera.lock() = (CameraState::Off, None);
            sh.generation.fetch_add(1, Ordering::SeqCst);
            sh.latest.pic.lock().take();
            let _ = sh.ctrl_tx.send(sh.sending_state());
            return Ok(());
        }
        if self.running.lock().is_some() {
            return Ok(());
        }
        *sh.camera.lock() = (CameraState::Starting, None);
        let result = self.source.prepare().and_then(|()| {
            let target = Arc::downgrade(sh);
            self.source.start(Arc::new(move |pic: Picture| {
                if let Some(sh) = target.upgrade() {
                    *sh.latest.pic.lock() = Some(pic);
                    sh.latest.ready.notify_one();
                }
            }))
        });
        match result {
            Ok(handle) => {
                *self.running.lock() = Some(handle);
                *sh.camera.lock() = (CameraState::On, None);
                sh.generation.fetch_add(1, Ordering::SeqCst);
                sh.force_key.store(true, Ordering::SeqCst);
                let _ = sh.ctrl_tx.send(sh.sending_state());
                Ok(())
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let denied = msg.contains("isn't allowed");
                *sh.camera.lock() = (if denied { CameraState::Denied } else { CameraState::Failed }, Some(msg));
                let _ = sh.ctrl_tx.send(sh.sending_state());
                Err(e)
            }
        }
    }

    /// Tests: reset every `every`-th delta frame's stream mid-way, as the
    /// sender does with frames stuck too long (0 = off).
    #[doc(hidden)]
    pub fn drop_frames_for_test(&self, every: u32) {
        self.shared.test_drop_every.store(every, Ordering::SeqCst);
    }

    pub fn camera_on(&self) -> bool {
        self.running.lock().is_some()
    }

    /// Ask the other side for a keyframe (e.g. the app's decoder was reset).
    pub fn request_keyframe(&self) {
        let _ = self.shared.ctrl_tx.send(VideoCtrl::KeyframeRequest { missing: u32::MAX });
    }

    /// Re-send our next frame as a keyframe (a new viewer of the self-view).
    pub fn force_keyframe(&self) {
        self.shared.force_key.store(true, Ordering::SeqCst);
    }

    pub fn info(&self) -> VideoInfo {
        let sh = &self.shared;
        let now = Instant::now();
        let (camera, error) = sh.camera.lock().clone();
        let ctl = sh.ctl.lock();
        let s = sh.send.lock();
        let r = sh.recv.lock();
        let ro = sh.reorder.lock();
        let receiving = r.last.is_some_and(|t| now.duration_since(t) < RECV_IDLE);
        VideoInfo {
            camera,
            error,
            sending: camera == CameraState::On && !ctl.paused(),
            paused: camera == CameraState::On && ctl.paused(),
            remote_camera: r.remote_camera,
            remote_paused: r.remote_paused,
            receiving,
            send_width: s.size.0,
            send_height: s.size.1,
            send_fps: s.window.fps(now),
            bitrate: if camera == CameraState::On && !ctl.paused() { ctl.bitrate() } else { 0 },
            sent_bitrate: if s.window.fps(now) > 0.0 { ctl.sent_rate() } else { 0 },
            queue_ms: ctl.queue_delay().map(|d| d.as_millis() as u32).unwrap_or(0),
            recv_width: r.size.0,
            recv_height: r.size.1,
            recv_fps: if receiving { r.window.fps(now) } else { 0.0 },
            latency_ms: r.latency_ms.map(|l| l as u32).unwrap_or(0),
            frames_sent: s.frames,
            frames_received: r.frames,
            frames_skipped: s.skipped,
            keyframes_sent: s.keyframes,
            keyframe_requests: ro.stats.keyframe_requests,
            source: sh.source_desc.lock().clone(),
            encoder: s.encoder.clone(),
        }
    }
}

impl Drop for VideoTrack {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.running.lock().take();
        self.shared.latest.ready.notify_all();
        for t in &self.tasks {
            t.abort();
        }
        if let Some(t) = self.encoder.take() {
            let _ = t.join();
        }
        let _ = &self.rt;
    }
}

// ─────────────────────────────── send ───────────────────────────────

/// A frame's stream is reset with its sequence number + 1 as the error
/// code, so the receiver knows which frame is gone even when the reset
/// overtakes the frame's first bytes.
fn reset_code(seq: u32) -> mycel_net::iroh::endpoint::VarInt {
    (seq as u64 + 1).try_into().expect("fits a varint")
}

fn reset_seq(e: &ReadError) -> Option<u32> {
    match e {
        ReadError::Reset(code) => u64::from(*code).checked_sub(1).map(|s| s as u32),
        _ => None,
    }
}

fn encode_loop(sh: Arc<Shared>, out: mpsc::UnboundedSender<EncodedFrame>) {
    let mut encoder: Option<(H264Encoder, Quality, u32)> = None;
    let mut generation = u64::MAX;
    let mut seq: u32 = 0;
    let mut preview_next = Instant::now();
    while !sh.stop.load(Ordering::SeqCst) {
        let pic = {
            let mut slot = sh.latest.pic.lock();
            if slot.is_none() {
                sh.latest.ready.wait_for(&mut slot, Duration::from_millis(100));
            }
            slot.take()
        };
        let Some(pic) = pic else { continue };
        let now = Instant::now();
        let g = sh.generation.load(Ordering::SeqCst);
        if g != generation {
            generation = g;
            encoder = None; // camera restarted: start clean with a keyframe
        }
        let rtt = *sh.rtt.lock();
        let (queued, oldest) = sh.queued(now);
        let (paused, verdict, quality, bitrate) = {
            let mut ctl = sh.ctl.lock();
            let paused = ctl.paused();
            let v = if paused { Admit::Congested } else { ctl.admit(now, queued, oldest, rtt) };
            (paused, v, ctl.quality(), ctl.bitrate())
        };
        // what to encode for: the path, or just the self-view while paused
        let (quality, bitrate, send) = match verdict {
            Admit::Send => (quality, bitrate, true),
            Admit::NotYet => continue,
            _ if paused => {
                if now < preview_next {
                    continue;
                }
                preview_next = now + Duration::from_secs_f64(1.0 / PREVIEW.fps as f64);
                (PREVIEW, 250_000, false)
            }
            Admit::Backlog | Admit::Congested => {
                sh.send.lock().skipped += 1;
                continue;
            }
        };
        let fresh = match &encoder {
            Some((_, q, _)) if q.width == quality.width && q.height == quality.height => false,
            _ => {
                match H264Encoder::new(quality.width, quality.height, quality.fps, bitrate) {
                    Ok(e) => {
                        sh.send.lock().encoder = e.describe();
                        encoder = Some((e, quality, bitrate));
                    }
                    Err(e) => {
                        eprintln!("[video] {e:#}");
                        *sh.camera.lock() = (CameraState::Failed, Some(format!("{e:#}")));
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                }
                true
            }
        };
        let (enc, q, b) = encoder.as_mut().expect("encoder");
        if *b != bitrate {
            enc.set_bitrate(bitrate);
            *b = bitrate;
        }
        *q = quality;
        // (always take the flag: a fresh encoder's first frame is a keyframe
        // anyway, and a stale flag would make the next one a second keyframe)
        let asked = send && sh.force_key.swap(false, Ordering::SeqCst);
        let force = fresh || asked;
        let mut frame = match enc.encode(&pic.buf, pic.capture_us as i64, force) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("[video] {e:#}");
                encoder = None;
                continue;
            }
        };
        frame.capture_us = pic.capture_us;
        if frame.keyframe && std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!(
                "[video {:?}] keyframe {} B {}x{} (fresh {fresh}, forced {force}, send {send})",
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 100_000,
                frame.data.len(),
                frame.width,
                frame.height
            );
        }
        if send {
            frame.seq = seq;
            seq = seq.wrapping_add(1);
        }
        let _ = sh.ui.send(UiFrame { source: UiSource::Local, peer: sh.me, frame: frame.clone() });
        if !send {
            continue;
        }
        {
            let mut s = sh.send.lock();
            s.window.tick(now);
            s.frames += 1;
            s.size = (frame.width as u32, frame.height as u32);
            if frame.keyframe {
                s.keyframes += 1;
                s.last_key = Some(frame.seq);
            }
        }
        sh.ctl.lock().on_sent(now, frame.data.len());
        {
            let mut o = sh.outstanding.lock();
            if frame.keyframe {
                // a keyframe makes every earlier frame moot: stop sending them
                let older: Vec<u32> = o.range(..frame.seq).map(|(s, _)| *s).collect();
                for s in older {
                    if let Some(f) = o.remove(&s) {
                        f.give_up(s);
                    }
                }
            }
            o.insert(frame.seq, Outstanding { queued: now, bytes: frame.data.len(), stream: None, handed: None });
        }
        if out.send(frame).is_err() {
            return;
        }
    }
}

/// Open a stream per frame, in order, pace its bytes out, and watch it
/// until it's acknowledged.
async fn send_frames(sh: Arc<Shared>, mut rx: mpsc::UnboundedReceiver<EncodedFrame>) {
    while let Some(f) = rx.recv().await {
        let (seq, key) = (f.seq, f.keyframe);
        if !sh.outstanding.lock().contains_key(&seq) {
            continue; // given up on before it went out (a newer keyframe, or stuck)
        }
        let wire = f.encode();
        if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!("[video {:?}] send #{seq} key={key} {} B {}x{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 100_000, wire.len(), f.width, f.height);
        }
        let Ok((mut tx, rx_half)) = sh.conn.open_bi().await else { return };
        // we never read their half of a frame stream
        drop(rx_half);
        let _ = tx.set_priority(FRAME_PRIORITY);
        let every = sh.test_drop_every.load(Ordering::Relaxed);
        if every > 0 && !key && seq % every == 0 {
            let _ = tx.write_all(&wire[..wire.len() / 2]).await;
            let _ = tx.reset(reset_code(seq));
            sh.outstanding.lock().remove(&seq);
            continue;
        }
        let target = sh.ctl.lock().bitrate();
        let pace_bps = (target.max(100_000) as f64 * PACING).max(1.0);
        let chunk_len = pace_chunk(target);
        let start = tokio::time::Instant::now();
        let mut written = 0usize;
        let mut ok = true;
        for chunk in wire.chunks(chunk_len) {
            if tx.write_all(chunk).await.is_err() {
                ok = false;
                break;
            }
            written += chunk.len();
            let due = start + Duration::from_secs_f64(written as f64 * 8.0 / pace_bps);
            if written < wire.len() && due > tokio::time::Instant::now() {
                tokio::time::sleep_until(due).await;
            }
            // given up on mid-way (stuck, or a newer keyframe)?
            if !sh.outstanding.lock().contains_key(&seq) {
                let _ = tx.reset(reset_code(seq));
                ok = false;
                break;
            }
        }
        if !ok {
            sh.outstanding.lock().remove(&seq);
            continue;
        }
        let _ = tx.finish();
        // queueing is measured from here: the pacing above is ours, not the path's
        let handed = Instant::now();
        let stopped = tx.stopped();
        match sh.outstanding.lock().get_mut(&seq) {
            Some(o) => {
                o.stream = Some(tx);
                o.handed = Some(handed);
            }
            None => {
                let _ = tx.reset(reset_code(seq));
                continue;
            }
        }
        let sh2 = sh.clone();
        tokio::spawn(async move {
            let r = stopped.await;
            let Some(f) = sh2.outstanding.lock().remove(&seq) else { return };
            if matches!(r, Ok(None)) {
                let rtt = *sh2.rtt.lock();
                sh2.ctl.lock().on_acked(Instant::now(), handed.elapsed(), rtt, f.bytes);
            }
        });
    }
}

async fn write_ctrl(sh: Arc<Shared>, mut rx: mpsc::UnboundedReceiver<VideoCtrl>) {
    let Ok((mut tx, rx_half)) = sh.conn.open_bi().await else { return };
    drop(rx_half);
    let _ = tx.set_priority(CTRL_PRIORITY);
    if tx.write_all(&ctrl_stream_header()).await.is_err() {
        return;
    }
    while let Some(m) = rx.recv().await {
        if tx.write_all(&m.encode()).await.is_err() {
            return;
        }
    }
}

/// Every [`TICK`]: follow the path, adapt the rate, give up on stale
/// frames, and nudge the other side for keyframes.
async fn tick(sh: Arc<Shared>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut was_paused = sh.ctl.lock().paused();
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let (path, rtt) = match sh.conn.paths().iter().find(|p| p.is_selected()) {
            Some(p) => (Some(PathKind::of(p.remote_addr())), p.rtt()),
            None => (None, Duration::ZERO),
        };
        if !rtt.is_zero() {
            *sh.rtt.lock() = rtt;
        }
        let (changed, paused) = {
            let mut ctl = sh.ctl.lock();
            if path.is_some() {
                ctl.set_path(path, now);
            }
            (ctl.tick(now, rtt), ctl.paused())
        };
        if changed.is_some() {
            sh.force_key.store(true, Ordering::SeqCst);
        }
        if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() && sh.send.lock().frames > 0 {
            static LAST: Mutex<Option<Instant>> = Mutex::new(None);
            let mut l = LAST.lock();
            if l.is_none_or(|t| now.duration_since(t) > Duration::from_secs(1)) {
                *l = Some(now);
                eprintln!("[video] {}", sh.ctl.lock().debug_line());
            }
        }
        if paused != was_paused {
            was_paused = paused;
            sh.force_key.store(true, Ordering::SeqCst);
            let _ = sh.ctrl_tx.send(sh.sending_state());
        }
        // frames stuck too long: give up on them and start over from a keyframe
        {
            let mut o = sh.outstanding.lock();
            let stale: Vec<u32> = o.iter().filter(|(_, f)| now.duration_since(f.queued) > STALE).map(|(s, _)| *s).collect();
            if !stale.is_empty() {
                for s in stale {
                    if let Some(f) = o.remove(&s) {
                        f.give_up(s);
                    }
                }
                sh.force_key.store(true, Ordering::SeqCst);
            }
        }
        let (frames, ask, missing) = {
            let mut r = sh.reorder.lock();
            let (frames, ask) = r.tick(now);
            (frames, ask, r.missing())
        };
        sh.deliver(frames, now);
        if ask {
            let _ = sh.ctrl_tx.send(VideoCtrl::KeyframeRequest { missing });
        }
    }
}

// ─────────────────────────────── receive ───────────────────────────────

async fn accept(sh: Arc<Shared>) {
    while let Ok((tx, rx)) = sh.conn.accept_bi().await {
        drop(tx); // we never answer on a video stream
        let sh = sh.clone();
        tokio::spawn(async move {
            if let Err(e) = read_stream(&sh, rx).await
                && std::env::var_os("MYCEL_VIDEO_DEBUG").is_some()
            {
                eprintln!("[video] stream: {e:#}");
            }
        });
    }
}

async fn read_stream(sh: &Shared, mut rx: RecvStream) -> Result<()> {
    let mut head = [0u8; STREAM_HEADER_LEN];
    if let Err(e) = rx.read_exact(&mut head).await {
        if let ReadExactError::ReadError(e) = &e
            && let Some(seq) = reset_seq(e)
        {
            frame_lost(sh, seq);
        }
        return Err(e.into());
    }
    match stream_kind(&head)? {
        KIND_FRAME => read_frame(sh, rx).await,
        KIND_CTRL => read_ctrl(sh, rx).await,
        _ => Ok(()),
    }
}

/// The sender gave up on frame `seq`: if the decoder needed it, ask for a
/// keyframe right away.
fn frame_lost(sh: &Shared, seq: u32) {
    let now = Instant::now();
    let (frames, ask, missing) = {
        let mut r = sh.reorder.lock();
        let frames = r.lost(seq, now);
        let (more, ask) = r.tick(now);
        (frames.into_iter().chain(more).collect::<Vec<_>>(), ask, r.missing())
    };
    sh.deliver(frames, now);
    if ask {
        let _ = sh.ctrl_tx.send(VideoCtrl::KeyframeRequest { missing });
    }
}

async fn read_frame(sh: &Shared, mut rx: RecvStream) -> Result<()> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    if let Err(e) = rx.read_exact(&mut header).await {
        if let ReadExactError::ReadError(e) = &e
            && let Some(seq) = reset_seq(e)
        {
            frame_lost(sh, seq);
        }
        return Err(e.into());
    }
    let seq = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let rest = match rx.read_to_end(MAX_FRAME).await {
        Ok(b) => b,
        Err(e) => {
            // the sender gave up on this frame (reset) or the connection broke
            frame_lost(sh, seq);
            return Err(e.into());
        }
    };
    let mut all = Vec::with_capacity(FRAME_HEADER_LEN + rest.len());
    all.extend_from_slice(&header);
    all.extend_from_slice(&rest);
    let f = EncodedFrame::decode(Bytes::from(all))?;
    ensure!(f.seq == seq, "sequence changed");
    let now = Instant::now();
    let frames = sh.reorder.lock().push(f, now);
    sh.deliver(frames, now);
    Ok(())
}

async fn read_ctrl(sh: &Shared, mut rx: RecvStream) -> Result<()> {
    let mut de = CtrlDeframer::default();
    let mut buf = vec![0u8; 1024];
    loop {
        let n = match rx.read(&mut buf).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(ReadError::ConnectionLost(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        de.push(&buf[..n]);
        while let Some(m) = de.next_msg()? {
            match m {
                VideoCtrl::KeyframeRequest { missing } => {
                    // a keyframe after the missing frame is already on its way
                    let covered = sh.send.lock().last_key.is_some_and(|k| k >= missing);
                    if !covered {
                        sh.force_key.store(true, Ordering::SeqCst);
                    }
                }
                VideoCtrl::State { camera, paused } => {
                    let mut r = sh.recv.lock();
                    r.remote_camera = camera;
                    r.remote_paused = paused;
                }
            }
        }
    }
}
