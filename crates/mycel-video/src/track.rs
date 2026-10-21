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
use mycel_net::iroh::endpoint::{Connection, ReadError, ReadExactError, RecvStream, SendDatagramError, SendStream};
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::platform::H264Encoder;
use crate::rate::{Admit, Quality, RateController};
use crate::receiver::Reorder;
use crate::source::{Picture, wall_us};
use crate::wire::{
    CtrlDeframer, EncodedFrame, FRAME_HEADER_LEN, KIND_CTRL, KIND_FRAME, MAX_FRAME, UiFrame, UiSource, VideoCtrl,
    ctrl_stream_header,
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
    fn give_up(mut self, seq: u32, ctrl: &mpsc::UnboundedSender<VideoCtrl>) {
        if let Some(s) = self.stream.as_mut() {
            let _ = s.reset(reset_code(seq));
            let _ = ctrl.send(VideoCtrl::Dropped { seq });
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

/// Pictures for the encoder thread: only the latest (older ones are
/// dropped), or for a source that encodes itself (the web view) a few in
/// order, since a dropped encoded frame costs a keyframe.
#[derive(Default)]
struct Latest {
    pic: Mutex<std::collections::VecDeque<Picture>>,
    ready: Condvar,
}

struct Shared {
    conn: Connection,
    /// [`TrackOptions::call_version`].
    call_version: u16,
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
    /// Our camera is on: send to this peer.
    camera_on: AtomicBool,
    /// This track also feeds the self-view (one track per call does).
    self_view: AtomicBool,
    /// The encoder couldn't start.
    encoder_error: Mutex<Option<String>>,
    latest: Latest,
    ctrl_tx: mpsc::UnboundedSender<VideoCtrl>,
    stop: AtomicBool,
    /// Bumped when the camera turns on or off (the encoder restarts cleanly).
    generation: AtomicU64,
    /// Tests: give up on every n-th frame as if it got stuck.
    test_drop_every: std::sync::atomic::AtomicU32,
}

impl Shared {
    /// Make the next frame a keyframe (`MYCEL_VIDEO_DEBUG` says why).
    fn force_keyframe(&self, why: &str) {
        if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!("[video] keyframe wanted: {why}");
        }
        self.force_key.store(true, Ordering::SeqCst);
    }

    /// The backlog: bytes not yet handed to QUIC, and how long the oldest
    /// frame QUIC has is going unacknowledged.
    fn queued(&self, now: Instant) -> (u64, Option<Duration>) {
        let o = self.outstanding.lock();
        let bytes = o.values().filter(|f| f.handed.is_none()).map(|f| f.bytes as u64).sum();
        let oldest = o.values().filter_map(|f| f.handed).map(|t| now.duration_since(t)).max();
        (bytes, oldest)
    }

    fn sending_state(&self) -> VideoCtrl {
        let camera = self.camera_on.load(Ordering::SeqCst);
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

/// Our video to one other device and theirs to us, on the connection to
/// them. Pictures come from [`crate::VideoCall`] (one camera, a track per
/// peer). Dropping it stops everything.
pub struct VideoTrack {
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    encoder: Option<std::thread::JoinHandle<()>>,
    rt: tokio::runtime::Handle,
}

pub struct TrackOptions {
    /// Our device key and the other side's (UI frames say whose they are).
    pub me: [u8; 32],
    pub peer: [u8; 32],
    pub path: Option<PathKind>,
    /// The call protocol version of the leg `conn` is (mycel-call's
    /// `proto::leg_version`). A control message newer than it
    /// ([`VideoCtrl::since`]) is not sent: on a version 1 leg the peer may
    /// be a pre-release build, which ends the control stream on a variant
    /// it doesn't have.
    pub call_version: u16,
}

/// One direction-pair of video with one peer, for stats and the UI.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerVideo {
    /// Our video is going out to them.
    pub sending: bool,
    /// Our video to them is paused: the path can't carry it.
    pub paused: bool,
    /// They have their camera on.
    pub remote_camera: bool,
    /// Their video is paused on their side (slow connection).
    pub remote_paused: bool,
    /// Their frames are arriving.
    pub receiving: bool,
    pub send_width: u32,
    pub send_height: u32,
    pub send_fps: f32,
    pub bitrate: u32,
    pub sent_bitrate: u32,
    pub queue_ms: u32,
    pub recv_width: u32,
    pub recv_height: u32,
    pub recv_fps: f32,
    pub latency_ms: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub frames_skipped: u64,
    pub keyframes_sent: u64,
    pub keyframe_requests: u64,
    pub encoder: String,
}

impl VideoTrack {
    /// Start video with one peer on `conn`: receive whatever streams are
    /// handed to [`VideoTrack::accept_stream`], send once the camera is on.
    pub fn start(
        conn: Connection,
        ui: broadcast::Sender<UiFrame>,
        opts: TrackOptions,
        rt: tokio::runtime::Handle,
    ) -> VideoTrack {
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            conn: conn.clone(),
            call_version: opts.call_version,
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
            camera_on: AtomicBool::new(false),
            self_view: AtomicBool::new(false),
            encoder_error: Mutex::new(None),
            latest: Latest::default(),
            ctrl_tx,
            stop: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            test_drop_every: Default::default(),
        });
        let (frame_tx, frame_rx) = mpsc::unbounded_channel::<EncodedFrame>();
        let tasks = vec![
            rt.spawn(write_ctrl(shared.clone(), ctrl_rx)),
            rt.spawn(send_frames(shared.clone(), frame_rx)),
            rt.spawn(tick(shared.clone())),
        ];
        let enc_shared = shared.clone();
        let encoder = std::thread::Builder::new()
            .name("mycel-video-encode".into())
            .spawn(move || encode_loop(enc_shared, frame_tx))
            .ok();
        let _ = shared.ctrl_tx.send(shared.sending_state());
        VideoTrack { shared, tasks, encoder, rt }
    }

    /// A video stream from this peer (its kind byte already read).
    pub fn accept_stream(&self, kind: u8, rx: RecvStream) {
        let sh = self.shared.clone();
        self.rt.spawn(async move {
            if let Err(e) = read_stream(&sh, kind, rx).await
                && std::env::var_os("MYCEL_VIDEO_DEBUG").is_some()
            {
                eprintln!("[video] stream: {e:#}");
            }
        });
    }

    /// A video datagram from this peer (kind byte included).
    pub fn accept_datagram(&self, d: &[u8]) {
        let _ = read_ctrl_datagram(&self.shared, d);
    }

    /// Standalone use (no call engine): accept this connection's streams
    /// and datagrams ourselves, routing video kinds to this track.
    pub fn serve(&self) {
        let sh = self.shared.clone();
        let conn = sh.conn.clone();
        {
            let (sh, conn) = (sh.clone(), conn.clone());
            self.rt.spawn(async move {
                while let Ok(d) = conn.read_datagram().await {
                    let _ = read_ctrl_datagram(&sh, &d);
                }
            });
        }
        let rt = self.rt.clone();
        self.rt.spawn(async move {
            while let Ok(mut rx) = conn.accept_uni().await {
                let sh = sh.clone();
                rt.spawn(async move {
                    let mut kind = [0u8; 1];
                    if rx.read_exact(&mut kind).await.is_ok() && crate::wire::is_video_kind(kind[0]) {
                        let _ = read_stream(&sh, kind[0], rx).await;
                    }
                });
            }
        });
    }

    /// A picture from the camera (the newest wins; older unencoded ones drop).
    pub fn push(&self, pic: Picture) {
        if !self.shared.camera_on.load(Ordering::Relaxed) {
            return;
        }
        {
            let mut q = self.shared.latest.pic.lock();
            let keep = if crate::platform::SOURCE_PACED { 8 } else { 1 };
            while q.len() >= keep {
                q.pop_front();
            }
            q.push_back(pic);
        }
        self.shared.latest.ready.notify_one();
    }

    /// Our camera turned on or off: start or stop sending, and tell them.
    pub fn set_camera(&self, on: bool) {
        let sh = &self.shared;
        if sh.camera_on.swap(on, Ordering::SeqCst) == on {
            return;
        }
        sh.generation.fetch_add(1, Ordering::SeqCst);
        sh.latest.pic.lock().clear();
        if on {
            sh.force_keyframe("camera on");
        }
        let _ = sh.ctrl_tx.send(sh.sending_state());
    }

    /// Also show what we encode for this peer as our self-view.
    pub fn set_self_view(&self, on: bool) {
        if !self.shared.self_view.swap(on, Ordering::SeqCst) && on {
            self.shared.force_keyframe("self-view on");
        }
    }

    /// Ask the other side for a keyframe (e.g. the app's decoder was reset).
    pub fn request_keyframe(&self) {
        let _ = self.shared.ctrl_tx.send(VideoCtrl::KeyframeRequest { missing: u32::MAX });
    }

    /// Re-send our next frame as a keyframe (a new viewer of the self-view).
    pub fn force_keyframe(&self) {
        self.shared.force_keyframe("the app asked");
    }

    /// Tests: reset every `every`-th delta frame's stream mid-way, as the
    /// sender does with frames stuck too long (0 = off).
    #[doc(hidden)]
    pub fn drop_frames_for_test(&self, every: u32) {
        self.shared.test_drop_every.store(every, Ordering::SeqCst);
    }

    /// The encoder couldn't start (why).
    pub fn encoder_error(&self) -> Option<String> {
        self.shared.encoder_error.lock().clone()
    }

    pub fn info(&self) -> PeerVideo {
        let sh = &self.shared;
        let now = Instant::now();
        let on = sh.camera_on.load(Ordering::SeqCst);
        let ctl = sh.ctl.lock();
        let s = sh.send.lock();
        let r = sh.recv.lock();
        let ro = sh.reorder.lock();
        let receiving = r.last.is_some_and(|t| now.duration_since(t) < RECV_IDLE);
        let sending = on && !ctl.paused();
        PeerVideo {
            sending,
            paused: on && ctl.paused(),
            remote_camera: r.remote_camera,
            remote_paused: r.remote_paused,
            receiving,
            send_width: if sending { s.size.0 } else { 0 },
            send_height: if sending { s.size.1 } else { 0 },
            send_fps: if sending { s.window.fps(now) } else { 0.0 },
            bitrate: if sending { ctl.bitrate() } else { 0 },
            sent_bitrate: if sending && s.window.fps(now) > 0.0 { ctl.sent_rate() } else { 0 },
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
            encoder: s.encoder.clone(),
        }
    }
}

impl Drop for VideoTrack {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.latest.ready.notify_all();
        for t in &self.tasks {
            t.abort();
        }
        if let Some(t) = self.encoder.take() {
            let _ = t.join();
        }
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

/// Fit the camera into the quality budget without stretching its pixels.
/// Portrait cameras receive a portrait budget; H.264 requires even sizes.
fn fitted_quality(width: u32, height: u32, budget: Quality) -> Quality {
    let (width, height) = (width.max(2), height.max(2));
    let (bw, bh) = if height > width { (budget.height, budget.width) } else { (budget.width, budget.height) };
    let even = |n: u32| (n & !1).max(2);
    let (w, h) = if width <= bw && height <= bh {
        (even(width), even(height))
    } else if u64::from(width) * u64::from(bh) >= u64::from(height) * u64::from(bw) {
        let w = even(bw);
        (w, even((u64::from(height) * u64::from(w) / u64::from(width)) as u32))
    } else {
        let h = even(bh);
        (even((u64::from(width) * u64::from(h) / u64::from(height)) as u32), h)
    };
    Quality::new(w, h, budget.fps)
}

fn encode_loop(sh: Arc<Shared>, out: mpsc::UnboundedSender<EncodedFrame>) {
    let mut encoder: Option<(H264Encoder, Quality, u32)> = None;
    let mut generation = u64::MAX;
    let mut seq: u32 = 0;
    let mut preview_next = Instant::now();
    while !sh.stop.load(Ordering::SeqCst) {
        let pic = {
            let mut slot = sh.latest.pic.lock();
            if slot.is_empty() {
                sh.latest.ready.wait_for(&mut slot, Duration::from_millis(100));
            }
            slot.pop_front()
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
            // A source that encodes at the target frame rate itself (the web
            // view) is already paced; skipping its frame would cost a keyframe.
            Admit::NotYet if crate::platform::SOURCE_PACED => (quality, bitrate, true),
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
        // Browser capture fits its own source before encoding. Native
        // VideoToolbox scales directly into these dimensions, so fit here.
        // A camera rotation changes the size and creates a fresh keyframe.
        let quality =
            if crate::platform::SOURCE_PACED { quality } else { fitted_quality(pic.width, pic.height, quality) };
        let reuse = match &mut encoder {
            Some((_, q, _)) if q.width == quality.width && q.height == quality.height => true,
            // A source that encodes itself (the web view) just gets new
            // targets: a new encoder here would cost it a keyframe.
            Some((e, _, _)) if crate::platform::SOURCE_PACED => {
                e.retarget(quality.width, quality.height, quality.fps);
                true
            }
            _ => false,
        };
        let fresh = match reuse {
            true => false,
            false => {
                match H264Encoder::new(quality.width, quality.height, quality.fps, bitrate) {
                    Ok(e) => {
                        sh.send.lock().encoder = e.describe();
                        encoder = Some((e, quality, bitrate));
                    }
                    Err(e) => {
                        eprintln!("[video] {e:#}");
                        *sh.encoder_error.lock() = Some(format!("{e:#}"));
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
        if sh.self_view.load(Ordering::Relaxed) {
            let _ = sh.ui.send(UiFrame { source: UiSource::Local, peer: sh.me, frame: frame.clone() });
        }
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
                        f.give_up(s, &sh.ctrl_tx);
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
            eprintln!(
                "[video {:?}] send #{seq} key={key} {} B {}x{}",
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 100_000,
                wire.len(),
                f.width,
                f.height
            );
        }
        let Ok(mut tx) = sh.conn.open_uni().await else { return };
        let _ = tx.set_priority(FRAME_PRIORITY);
        let every = sh.test_drop_every.load(Ordering::Relaxed);
        if every > 0 && !key && seq % every == 0 {
            let _ = tx.write_all(&wire[..wire.len() / 2]).await;
            let _ = tx.reset(reset_code(seq));
            let _ = sh.ctrl_tx.send(VideoCtrl::Dropped { seq });
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
                let _ = sh.ctrl_tx.send(VideoCtrl::Dropped { seq });
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
                sh2.ctl.lock().on_acked(Instant::now(), f.bytes);
            }
        });
    }
}

/// Control messages go as datagrams (kind byte, then the message): they're
/// small and repeated where it matters (state every second, keyframe
/// requests until answered), and unlike a stream they can't get stuck
/// behind video data QUIC is still recovering after a path change. A path
/// that can't carry datagrams gets them on a control stream instead.
async fn write_ctrl(sh: Arc<Shared>, mut rx: mpsc::UnboundedReceiver<VideoCtrl>) {
    let mut stream: Option<SendStream> = None;
    while let Some(m) = rx.recv().await {
        if m.since() > sh.call_version {
            continue;
        }
        let body = m.encode();
        if stream.is_none() {
            let mut d = Vec::with_capacity(1 + body.len());
            d.push(KIND_CTRL);
            d.extend_from_slice(&body);
            match sh.conn.send_datagram(Bytes::from(d)) {
                Ok(()) => continue,
                Err(SendDatagramError::ConnectionLost(_)) => return,
                Err(_) => {}
            }
        }
        if stream.is_none() {
            let Ok(mut tx) = sh.conn.open_uni().await else { return };
            let _ = tx.set_priority(CTRL_PRIORITY);
            if tx.write_all(&ctrl_stream_header()).await.is_err() {
                return;
            }
            stream = Some(tx);
        }
        if let Some(tx) = stream.as_mut()
            && tx.write_all(&body).await.is_err()
        {
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
    let mut ticks: u64 = 0;
    loop {
        ticker.tick().await;
        ticks += 1;
        let now = Instant::now();
        let (path, rtt) = match mycel_net::path_in_use(&sh.conn.paths()) {
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
            ctl.on_rtt(now, rtt);
            (ctl.tick(now, rtt), ctl.paused())
        };
        // (a source that encodes itself sends a keyframe when its size really
        // changes; the quality steps above it don't need one)
        if changed.is_some() && !crate::platform::SOURCE_PACED {
            sh.force_keyframe("quality changed");
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
            sh.force_keyframe(if paused { "paused" } else { "resumed" });
            let _ = sh.ctrl_tx.send(sh.sending_state());
        } else if ticks.is_multiple_of(20) {
            // and once a second anyway (a few bytes): whatever the other
            // side missed (a replaced connection, a late track) heals itself
            let _ = sh.ctrl_tx.send(sh.sending_state());
        }
        // frames stuck too long: give up on them and start over from a keyframe
        {
            let mut o = sh.outstanding.lock();
            let stale: Vec<u32> =
                o.iter().filter(|(_, f)| now.duration_since(f.queued) > STALE).map(|(s, _)| *s).collect();
            if !stale.is_empty() {
                for s in stale {
                    if let Some(f) = o.remove(&s) {
                        f.give_up(s, &sh.ctrl_tx);
                    }
                }
                sh.force_keyframe("frames stuck");
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

async fn read_stream(sh: &Shared, kind: u8, rx: RecvStream) -> Result<()> {
    match kind {
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
            on_ctrl(sh, m);
        }
    }
}

/// A control datagram (kind byte, then one message).
fn read_ctrl_datagram(sh: &Shared, d: &[u8]) -> Result<()> {
    ensure!(d.first() == Some(&KIND_CTRL), "not a video control datagram");
    let mut de = CtrlDeframer::default();
    de.push(&d[1..]);
    while let Some(m) = de.next_msg()? {
        on_ctrl(sh, m);
    }
    Ok(())
}

fn on_ctrl(sh: &Shared, m: VideoCtrl) {
    match m {
        VideoCtrl::KeyframeRequest { missing } => {
            // a keyframe after the missing frame is already on its way
            let covered = sh.send.lock().last_key.is_some_and(|k| k >= missing);
            if !covered {
                sh.force_keyframe("they asked");
            }
        }
        VideoCtrl::Dropped { seq } => frame_lost(sh, seq),
        VideoCtrl::State { camera, paused } => {
            let mut r = sh.recv.lock();
            r.remote_camera = camera;
            r.remote_paused = paused;
        }
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;

    #[test]
    fn camera_shape_survives_portrait_landscape_and_rotation() {
        let budget = Quality::new(1280, 720, 30);
        assert_eq!(fitted_quality(1920, 1080, budget), budget);
        assert_eq!(fitted_quality(1080, 1920, budget), Quality::new(720, 1280, 30));
        assert_eq!(fitted_quality(1920, 1440, budget), Quality::new(960, 720, 30));
        assert_eq!(fitted_quality(1440, 1920, budget), Quality::new(720, 960, 30));
        assert_ne!(fitted_quality(1080, 1920, budget), fitted_quality(1920, 1080, budget));
    }

    #[test]
    fn dimensions_stay_even_and_within_every_quality_budget() {
        for (_, budget) in crate::rate::LADDER {
            for (w, h) in [(4031, 3023), (3023, 4031), (121, 89), (89, 121)] {
                let fitted = fitted_quality(w, h, budget);
                assert_eq!(fitted.width % 2, 0);
                assert_eq!(fitted.height % 2, 0);
                assert!(fitted.width <= w && fitted.height <= h);
                assert!(fitted.pixels() <= budget.pixels());
                let shape_error = (fitted.width as f64 / fitted.height as f64 - w as f64 / h as f64).abs();
                assert!(
                    shape_error <= 2.0 * (1.0 + w as f64 / h as f64) / fitted.height as f64,
                    "{w}x{h} => {fitted:?}"
                );
            }
        }
    }
}
