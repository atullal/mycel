//! Places, answers and runs calls (see `proto.rs` for the wire protocol).
//!
//! Each call is one task (its "driver") that owns the control stream and
//! feeds the [`CallState`] machine; the app talks to it through commands.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::{Hash32, SignPk};
use mycel_net::PathKind;
use mycel_net::iroh::endpoint::{Connection, RecvStream, SendStream};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, oneshot};

use crate::api::{CallInfo, CallPhase, CallStats, Direction};
use crate::audio::{AudioIo, default_audio};
use crate::bitrate::{BitrateController, Observation};
use crate::engine::Media;
use crate::proto::{self, CallId, Ctrl, VERSION, call_id};
use crate::state::{CallState, Effect, Input, LiveCall, RING_TIMEOUT, RingDecision, on_ring};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What a call needs from the node it runs on.
pub trait CallHost: Send + Sync + 'static {
    fn me(&self) -> SignPk;
    /// Whom a call in this conversation goes to (direct conversations only).
    fn callee(&self, space: &Hash32) -> Result<SignPk>;
    /// May `peer` call us about `space`? (both current members, and it isn't
    /// a message request we haven't accepted)
    fn may_call(&self, space: &Hash32, peer: &SignPk) -> bool;
    fn name_of(&self, peer: &SignPk) -> String;
    /// Dial `peer`'s device for ALPN `mycel/call/0`.
    fn connect(&self, peer: SignPk) -> BoxFuture<Result<Connection>>;
    /// A call connection is working (marks the peer online, notes the path).
    fn note_connection(&self, _peer: &SignPk, _conn: &Connection) {}
    fn emit(&self, event: CallEvent);
}

#[derive(Clone, Debug)]
pub enum CallEvent {
    /// Someone is calling us: ring.
    Incoming(CallInfo),
    /// Anything about a call changed (state, path, levels ~10×/s while active).
    Updated(CallInfo),
}

enum Cmd {
    Accept(oneshot::Sender<()>),
    Decline,
    HangUp,
    Mute(bool),
    /// We both called at once and their call wins: drop ours.
    Replaced,
}

/// How long an ended call stays visible in `status()`.
const LINGER: Duration = Duration::from_secs(10);
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Nothing heard for this long in an active call: it's gone.
const MEDIA_TIMEOUT: Duration = Duration::from_secs(30);
/// At most this many incoming calls being set up at once.
const MAX_PENDING: usize = 8;
const TICK: Duration = Duration::from_millis(100);

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn selected_path(conn: &Connection) -> (Option<PathKind>, Duration) {
    match conn.paths().iter().find(|p| p.is_selected()) {
        Some(p) => (Some(PathKind::of(p.remote_addr())), p.rtt()),
        None => (None, Duration::ZERO),
    }
}

struct Call {
    id: CallId,
    space: Hash32,
    peer: SignPk,
    peer_name: String,
    started_at: u64,
    connected_at: Mutex<Option<u64>>,
    state: Mutex<CallState>,
    cmd: mpsc::UnboundedSender<Cmd>,
    media: Mutex<Option<Media>>,
    muted: AtomicBool,
    path: Mutex<Option<PathKind>>,
    rtt_ms: AtomicU32,
    /// Loss the other side reports for what we send (0..1).
    remote_loss: Mutex<f32>,
    bitrate: AtomicU32,
    error: Mutex<Option<String>>,
}

struct Mgr {
    host: Arc<dyn CallHost>,
    audio: RwLock<Arc<dyn AudioIo>>,
    calls: Mutex<HashMap<CallId, Arc<Call>>>,
    /// Our call to (peer, space) lost a glare: auto-answer theirs.
    expecting: Mutex<HashMap<(SignPk, Hash32), Instant>>,
    ring_timeout: Mutex<Duration>,
    force_stream: AtomicBool,
    pending: AtomicUsize,
}

/// Live 1:1 calls over the node's endpoint.
#[derive(Clone)]
pub struct CallManager {
    inner: Arc<Mgr>,
}

impl CallManager {
    pub fn new(host: Arc<dyn CallHost>) -> CallManager {
        CallManager {
            inner: Arc::new(Mgr {
                host,
                audio: RwLock::new(default_audio()),
                calls: Mutex::default(),
                expecting: Mutex::default(),
                ring_timeout: Mutex::new(RING_TIMEOUT),
                force_stream: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
            }),
        }
    }

    /// Swap the audio backend (tests, headless runs).
    pub fn set_audio(&self, audio: Arc<dyn AudioIo>) {
        *self.inner.audio.write() = audio;
    }

    pub fn audio(&self) -> Arc<dyn AudioIo> {
        self.inner.audio.read().clone()
    }

    pub fn set_ring_timeout(&self, d: Duration) {
        *self.inner.ring_timeout.lock() = d;
    }

    /// Send audio on a stream even where datagrams work (tests the fallback).
    pub fn force_stream(&self, on: bool) {
        self.inner.force_stream.store(on, Ordering::Relaxed);
    }

    /// Answer incoming call connections (from `ExtraProtocol::incoming`).
    pub fn serve(&self, mut incoming: mpsc::UnboundedReceiver<Connection>) -> tokio::task::JoinHandle<()> {
        let mgr = self.inner.clone();
        tokio::spawn(async move {
            while let Some(conn) = incoming.recv().await {
                if mgr.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING {
                    mgr.pending.fetch_sub(1, Ordering::SeqCst);
                    conn.close(1u32.into(), b"busy");
                    continue;
                }
                let mgr = mgr.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(&mgr, conn).await {
                        eprintln!("[mycel] incoming call refused: {e:#}");
                    }
                });
            }
        })
    }

    /// Calls we know about: live ones, plus ones that ended in the last few seconds.
    pub fn status(&self) -> Vec<CallInfo> {
        let calls: Vec<Arc<Call>> = self.inner.calls.lock().values().cloned().collect();
        let mut out: Vec<CallInfo> = calls.iter().map(|c| info(&self.inner, c)).collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.started_at));
        out
    }

    fn find(&self, id: &str) -> Result<Arc<Call>> {
        let calls = self.inner.calls.lock();
        calls
            .values()
            .find(|c| hex(&c.id.0) == id.trim().to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| anyhow!("no such call"))
    }

    /// Call the other person in a direct conversation.
    pub async fn start(&self, space: Hash32) -> Result<CallInfo> {
        let mgr = &self.inner;
        let peer = mgr.host.callee(&space)?;
        // they're already calling us here: just answer
        let ringing = live_calls(mgr).into_iter().find(|c| {
            c.peer == peer && c.space == space && {
                let st = c.state.lock();
                st.dir == Direction::Incoming && st.phase == CallPhase::Ringing
            }
        });
        if let Some(c) = ringing {
            return self.accept(&hex(&c.id.0)).await;
        }
        if !live_calls(mgr).is_empty() {
            bail!("You're already in a call.");
        }
        prepare_audio(mgr).await?;
        let nonce: [u8; 16] = mycel_crypto::random();
        let me = mgr.host.me();
        let id = call_id(&space, &me, &nonce);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let call = Arc::new(Call {
            id,
            space,
            peer,
            peer_name: mgr.host.name_of(&peer),
            started_at: wall_ms(),
            connected_at: Mutex::new(None),
            state: Mutex::new(CallState::outgoing(Instant::now(), *mgr.ring_timeout.lock())),
            cmd: cmd_tx,
            media: Mutex::new(None),
            muted: AtomicBool::new(false),
            path: Mutex::new(None),
            rtt_ms: AtomicU32::new(0),
            remote_loss: Mutex::new(0.0),
            bitrate: AtomicU32::new(0),
            error: Mutex::new(None),
        });
        mgr.calls.lock().insert(id, call.clone());
        let first = info(mgr, &call);
        mgr.host.emit(CallEvent::Updated(first.clone()));
        let m = mgr.clone();
        tokio::spawn(async move { run_outgoing(m, call, nonce, cmd_rx).await });
        Ok(first)
    }

    /// Answer a ringing incoming call.
    pub async fn accept(&self, id: &str) -> Result<CallInfo> {
        let call = self.find(id)?;
        {
            let st = call.state.lock();
            if st.dir != Direction::Incoming || st.phase != CallPhase::Ringing {
                bail!("This call isn't ringing any more.");
            }
        }
        // Another call in progress? Hang it up first (answering means switching).
        for other in live_calls(&self.inner) {
            if other.id != call.id {
                let _ = other.cmd.send(Cmd::HangUp);
            }
        }
        prepare_audio(&self.inner).await?;
        let (tx, rx) = oneshot::channel();
        call.cmd.send(Cmd::Accept(tx)).map_err(|_| anyhow!("This call already ended."))?;
        let _ = tokio::time::timeout(Duration::from_secs(2), rx).await;
        Ok(info(&self.inner, &call))
    }

    pub fn decline(&self, id: &str) -> Result<()> {
        let call = self.find(id)?;
        let _ = call.cmd.send(Cmd::Decline);
        Ok(())
    }

    /// Hang up (or cancel an outgoing call that's still ringing).
    pub fn end(&self, id: &str) -> Result<()> {
        let call = self.find(id)?;
        let _ = call.cmd.send(Cmd::HangUp);
        Ok(())
    }

    pub fn set_muted(&self, id: &str, muted: bool) -> Result<CallInfo> {
        let call = self.find(id)?;
        call.muted.store(muted, Ordering::Relaxed);
        if let Some(m) = call.media.lock().as_ref() {
            m.shared().muted.store(muted, Ordering::Relaxed);
        }
        let _ = call.cmd.send(Cmd::Mute(muted));
        let i = info(&self.inner, &call);
        self.inner.host.emit(CallEvent::Updated(i.clone()));
        Ok(i)
    }

    /// Hang up everything (app quitting).
    pub async fn shutdown(&self) {
        let live = live_calls(&self.inner);
        for c in &live {
            let _ = c.cmd.send(Cmd::HangUp);
        }
        if !live.is_empty() {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

fn live_calls(mgr: &Mgr) -> Vec<Arc<Call>> {
    mgr.calls.lock().values().filter(|c| c.state.lock().is_live()).cloned().collect()
}

async fn prepare_audio(mgr: &Mgr) -> Result<()> {
    let audio = mgr.audio.read().clone();
    tokio::task::spawn_blocking(move || audio.prepare()).await.context("audio check failed")?
}

fn info(mgr: &Mgr, c: &Call) -> CallInfo {
    let now = Instant::now();
    let st = c.state.lock().clone();
    let audio = mgr.audio.read().clone();
    let media = c.media.lock();
    let shared = media.as_ref().map(|m| m.shared().clone());
    drop(media);
    let mut stats = CallStats {
        rtt_ms: c.rtt_ms.load(Ordering::Relaxed),
        loss_pct: *c.remote_loss.lock() * 100.0,
        audio_device: audio.describe(),
        ..Default::default()
    };
    let (mut level, mut remote_level, mut remote_muted) = (0.0, 0.0, false);
    if let Some(s) = &shared {
        let js = s.jitter_stats();
        stats.jitter_ms = js.jitter_ms;
        stats.buffer_ms = js.depth_ms;
        stats.frames_sent = s.frames_sent.load(Ordering::Relaxed);
        stats.frames_received = js.received;
        stats.frames_lost = js.lost;
        stats.frames_late = js.late;
        stats.transport = if s.stream_mode.load(Ordering::Relaxed) { "stream" } else { "datagram" }.into();
        // one way + jitter buffer + one frame + device/playout buffering (~35 ms)
        stats.latency_ms = stats.rtt_ms / 2 + js.depth_ms.max(js.target_ms) + 20 + 35;
        let d = audio.diagnostics();
        stats.heard_tone_hz = d.heard_tone_hz;
        stats.measured_round_trip_ms = d.measured_round_trip_ms;
        if st.phase == CallPhase::Active {
            level = s.mic_level();
            remote_level = s.out_level();
            remote_muted = s.remote_muted.load(Ordering::Relaxed);
        }
    }
    CallInfo {
        id: hex(&c.id.0),
        conversation: c.space.to_string(),
        peer: hex(&c.peer.0),
        peer_name: c.peer_name.clone(),
        direction: st.dir,
        state: st.phase,
        end_reason: st.end,
        error: c.error.lock().clone(),
        started_at: c.started_at,
        connected_at: *c.connected_at.lock(),
        duration_ms: st.duration(now).as_millis() as u64,
        path: *c.path.lock(),
        bitrate: c.bitrate.load(Ordering::Relaxed),
        muted: c.muted.load(Ordering::Relaxed),
        remote_muted,
        level,
        remote_level,
        echo_cancellation: audio.echo_cancellation(),
        stats,
    }
}

// ─────────────────────────────── outgoing ───────────────────────────────

async fn run_outgoing(mgr: Arc<Mgr>, call: Arc<Call>, nonce: [u8; 16], mut cmd_rx: mpsc::UnboundedReceiver<Cmd>) {
    let dial = mgr.host.connect(call.peer);
    tokio::pin!(dial);
    let conn = loop {
        tokio::select! {
            r = &mut dial => break r,
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Mute(_)) => continue,
                _ => {
                    // hung up while still dialing
                    call.state.lock().apply(Input::LocalHangUp, Instant::now());
                    finish(&mgr, &call, None).await;
                    return;
                }
            }
        }
    };
    let conn = match conn {
        Ok(c) => c,
        Err(e) => {
            *call.error.lock() = Some(format!("{e:#}"));
            call.state.lock().apply(Input::Unreachable, Instant::now());
            finish(&mgr, &call, None).await;
            return;
        }
    };
    let streams = async {
        let (mut tx, rx) = conn.open_bi().await?;
        proto::send(&mut tx, &Ctrl::Ring { version: VERSION, space: call.space, nonce, call: call.id }).await?;
        anyhow::Ok((tx, rx))
    };
    match tokio::time::timeout(HANDSHAKE, streams).await {
        Ok(Ok((tx, rx))) => drive(mgr, call, conn, tx, rx, cmd_rx).await,
        other => {
            let msg = match other {
                Ok(Err(e)) => format!("{e:#}"),
                _ => "timed out".into(),
            };
            *call.error.lock() = Some(msg);
            call.state.lock().apply(Input::Unreachable, Instant::now());
            finish(&mgr, &call, Some(&conn)).await;
        }
    }
}

// ─────────────────────────────── incoming ───────────────────────────────

struct PendingGuard<'a>(&'a AtomicUsize);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn refuse(conn: &Connection, mut tx: SendStream, msg: Ctrl) {
    let _ = proto::send(&mut tx, &msg).await;
    let _ = tx.finish();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
}

async fn handle_incoming(mgr: &Arc<Mgr>, conn: Connection) -> Result<()> {
    let guard = PendingGuard(&mgr.pending);
    let peer = SignPk(*conn.remote_id().as_bytes());
    let (mut tx, mut rx) = tokio::time::timeout(HANDSHAKE, conn.accept_bi()).await.context("no ring")??;
    let msg = tokio::time::timeout(HANDSHAKE, proto::recv(&mut rx)).await.context("no ring")??;
    let Some(Ctrl::Ring { version: _, space, nonce, call: id }) = msg else {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("expected a ring");
    };
    // The call is bound to the conversation and to the authenticated caller.
    if id != call_id(&space, &peer, &nonce) {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("call id doesn't match");
    }
    if !mgr.host.may_call(&space, &peer) {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("{} isn't allowed to call about that conversation", peer.short());
    }
    if mgr.calls.lock().contains_key(&id) {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("duplicate call");
    }
    let live: Vec<LiveCall> = live_calls(mgr)
        .iter()
        .map(|c| LiveCall { id: c.id, peer: c.peer, space: c.space, dir: c.state.lock().dir })
        .collect();
    let expecting = {
        let mut e = mgr.expecting.lock();
        e.retain(|_, t| t.elapsed() < Duration::from_secs(15));
        e.remove(&(peer, space)).is_some()
    };
    let decision = on_ring(&mgr.host.me(), &peer, &space, &live, expecting);
    let auto = match decision {
        RingDecision::Busy => {
            refuse(&conn, tx, Ctrl::Busy).await;
            return Ok(());
        }
        RingDecision::Glare => {
            refuse(&conn, tx, Ctrl::Glare).await;
            return Ok(());
        }
        RingDecision::AutoAccept { replaces } => {
            if let Some(old) = replaces.and_then(|r| mgr.calls.lock().get(&r).cloned()) {
                let _ = old.cmd.send(Cmd::Replaced);
            }
            true
        }
        RingDecision::Ring => false,
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let call = Arc::new(Call {
        id,
        space,
        peer,
        peer_name: mgr.host.name_of(&peer),
        started_at: wall_ms(),
        connected_at: Mutex::new(None),
        state: Mutex::new(CallState::incoming(Instant::now(), *mgr.ring_timeout.lock())),
        cmd: cmd_tx.clone(),
        media: Mutex::new(None),
        muted: AtomicBool::new(false),
        path: Mutex::new(None),
        rtt_ms: AtomicU32::new(0),
        remote_loss: Mutex::new(0.0),
        bitrate: AtomicU32::new(0),
        error: Mutex::new(None),
    });
    mgr.calls.lock().insert(id, call.clone());
    proto::send(&mut tx, &Ctrl::Ringing).await?;
    *call.path.lock() = selected_path(&conn).0;
    mgr.host.note_connection(&peer, &conn);
    drop(guard);
    if auto {
        let (ack, _) = oneshot::channel();
        let _ = cmd_tx.send(Cmd::Accept(ack));
        mgr.host.emit(CallEvent::Updated(info(mgr, &call)));
    } else {
        mgr.host.emit(CallEvent::Incoming(info(mgr, &call)));
    }
    drive(mgr.clone(), call, conn, tx, rx, cmd_rx).await;
    Ok(())
}

// ─────────────────────────────── the driver ───────────────────────────────

enum Event {
    Cmd(Option<Cmd>),
    Remote(Option<Result<Ctrl>>),
    Timeout,
    Closed,
    Tick,
}

async fn drive(
    mgr: Arc<Mgr>,
    call: Arc<Call>,
    conn: Connection,
    mut tx: SendStream,
    mut rx: RecvStream,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) {
    // control messages from the other side, read on their own task
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Option<Result<Ctrl>>>();
    let reader = tokio::spawn(async move {
        loop {
            match proto::recv(&mut rx).await {
                Ok(Some(m)) => {
                    if in_tx.send(Some(Ok(m))).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = in_tx.send(None);
                    return;
                }
                Err(e) => {
                    let _ = in_tx.send(Some(Err(e)));
                    return;
                }
            }
        }
    });
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    let mut controller: Option<BitrateController> = None;
    let mut last_report = (0u64, 0u64);
    let mut accept_ack: Option<oneshot::Sender<()>> = None;

    loop {
        let deadline = call.state.lock().deadline();
        let ev = tokio::select! {
            c = cmd_rx.recv() => Event::Cmd(c),
            m = in_rx.recv() => Event::Remote(m.flatten()),
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None => std::future::pending().await,
                }
            } => Event::Timeout,
            _ = conn.closed() => Event::Closed,
            _ = ticker.tick() => Event::Tick,
        };
        let now = Instant::now();
        let before = call.state.lock().phase;
        let input = match ev {
            Event::Cmd(None) => Some(Input::LocalHangUp),
            Event::Cmd(Some(Cmd::Accept(ack))) => {
                accept_ack = Some(ack);
                Some(Input::LocalAccept)
            }
            Event::Cmd(Some(Cmd::Decline)) => Some(Input::LocalDecline),
            Event::Cmd(Some(Cmd::HangUp)) => Some(Input::LocalHangUp),
            Event::Cmd(Some(Cmd::Replaced)) => Some(Input::RemoteGlare),
            Event::Cmd(Some(Cmd::Mute(m))) => {
                if before == CallPhase::Active {
                    let _ = proto::send(&mut tx, &Ctrl::Mute { muted: m }).await;
                }
                None
            }
            Event::Remote(None) => Some(Input::ConnectionLost),
            Event::Remote(Some(Err(e))) => {
                *call.error.lock() = Some(format!("{e:#}"));
                Some(Input::ConnectionLost)
            }
            Event::Remote(Some(Ok(msg))) => match msg {
                Ctrl::Ringing => Some(Input::RemoteRinging),
                Ctrl::Accept => Some(Input::RemoteAccepted),
                Ctrl::Decline => Some(Input::RemoteDeclined),
                Ctrl::Busy => Some(Input::RemoteBusy),
                Ctrl::Glare => {
                    mgr.expecting.lock().insert((call.peer, call.space), now);
                    Some(Input::RemoteGlare)
                }
                Ctrl::Denied => {
                    *call.error.lock() = Some("They can't take calls in this conversation.".into());
                    Some(Input::Failed)
                }
                Ctrl::Started => Some(Input::RemoteStarted),
                Ctrl::HangUp => Some(Input::RemoteHangUp),
                Ctrl::Mute { .. } => None, // also carried in every audio frame
                Ctrl::Report { loss_ppm, .. } => {
                    *call.remote_loss.lock() = (loss_ppm as f32 / 1e6).clamp(0.0, 1.0);
                    None
                }
                Ctrl::Ring { .. } => None,
            },
            Event::Timeout => Some(Input::Timeout),
            Event::Closed => Some(Input::ConnectionLost),
            Event::Tick => {
                ticks += 1;
                if before == CallPhase::Active {
                    on_tick(&mgr, &call, &conn, &mut tx, ticks, &mut controller, &mut last_report).await
                } else {
                    None
                }
            }
        };
        let Some(input) = input else { continue };
        let effects = call.state.lock().apply(input, now);
        let mut closing = false;
        for fx in effects {
            match fx {
                Effect::Send(msg) => {
                    let _ = proto::send(&mut tx, &msg).await;
                }
                Effect::StartMedia => {
                    if let Err(e) = start_media(&mgr, &call, &conn).await {
                        *call.error.lock() = Some(format!("{e:#}"));
                        let fx = call.state.lock().apply(Input::Failed, Instant::now());
                        for f in fx {
                            if let Effect::Send(m) = f {
                                let _ = proto::send(&mut tx, &m).await;
                            }
                        }
                        closing = true;
                    }
                }
                Effect::Close => closing = true,
            }
        }
        if let Some(ack) = accept_ack.take() {
            let _ = ack.send(());
        }
        let after = call.state.lock().phase;
        if after != before && !closing {
            mgr.host.emit(CallEvent::Updated(info(&mgr, &call)));
        }
        if closing || after == CallPhase::Ended {
            break;
        }
    }
    reader.abort();
    let _ = tx.finish();
    finish(&mgr, &call, Some(&conn)).await;
}

async fn start_media(mgr: &Arc<Mgr>, call: &Arc<Call>, conn: &Connection) -> Result<()> {
    let audio = mgr.audio.read().clone();
    let (path, rtt) = selected_path(conn);
    let bitrate = BitrateController::new(path).bitrate();
    let (conn2, muted, force) = (conn.clone(), call.muted.load(Ordering::Relaxed), mgr.force_stream.load(Ordering::Relaxed));
    let rt = tokio::runtime::Handle::current();
    let media = tokio::task::spawn_blocking(move || Media::start(conn2, &*audio, bitrate, muted, force, rt))
        .await
        .context("audio failed to start")??;
    *call.media.lock() = Some(media);
    *call.connected_at.lock() = Some(wall_ms());
    *call.path.lock() = path;
    call.bitrate.store(bitrate, Ordering::Relaxed);
    call.rtt_ms.store(rtt.as_millis() as u32, Ordering::Relaxed);
    Ok(())
}

/// Every 100 ms while talking: levels to the UI; every second: path, RTT,
/// bitrate, and a receiver report to the other side.
async fn on_tick(
    mgr: &Arc<Mgr>,
    call: &Arc<Call>,
    conn: &Connection,
    tx: &mut SendStream,
    ticks: u64,
    controller: &mut Option<BitrateController>,
    last_report: &mut (u64, u64),
) -> Option<Input> {
    let shared = call.media.lock().as_ref().map(|m| m.shared().clone())?;
    if ticks.is_multiple_of(10) {
        let now = Instant::now();
        let (path, rtt) = selected_path(conn);
        if std::env::var_os("MYCEL_CALL_DEBUG").is_some() {
            let paths: Vec<String> = conn
                .paths()
                .iter()
                .map(|p| {
                    let st = p.stats();
                    format!(
                        "{:?}#{:?}{} rtt={:?} tx={} rx={} lost={}",
                        PathKind::of(p.remote_addr()),
                        p.id(),
                        if p.is_selected() { "*" } else { "" },
                        st.rtt,
                        st.udp_tx.datagrams,
                        st.udp_rx.datagrams,
                        st.lost_packets
                    )
                })
                .collect();
            eprintln!("[call {}] {:?} paths: {}", call.peer.short(), call.state.lock().dir, paths.join(", "));
        }
        let old_path = {
            let mut p = call.path.lock();
            let old = *p;
            if path.is_some() {
                *p = path;
            }
            old
        };
        call.rtt_ms.store(rtt.as_millis() as u32, Ordering::Relaxed);
        let ctl = controller.get_or_insert_with(|| BitrateController::new(path));
        let loss = *call.remote_loss.lock();
        if let Some(b) = ctl.update(now, Observation { path, loss, rtt }) {
            shared.bitrate.store(b, Ordering::Relaxed);
        }
        call.bitrate.store(ctl.bitrate(), Ordering::Relaxed);
        shared.fec_loss.store(BitrateController::fec_loss_percent(loss) as u32, Ordering::Relaxed);
        // what we received of theirs, last interval
        let js = shared.jitter_stats();
        let (played, lost) = (js.played - last_report.0.min(js.played), js.lost - last_report.1.min(js.lost));
        *last_report = (js.played, js.lost);
        let loss_ppm = (lost * 1_000_000).checked_div(played + lost).unwrap_or(0) as u32;
        let _ = proto::send(
            tx,
            &Ctrl::Report { loss_ppm, jitter_ms: js.jitter_ms as u16, bitrate: ctl.bitrate() },
        )
        .await;
        if old_path != path {
            mgr.host.note_connection(&call.peer, conn);
        }
        if shared.since_last_frame().is_some_and(|d| d > MEDIA_TIMEOUT) {
            return Some(Input::ConnectionLost);
        }
    }
    mgr.host.emit(CallEvent::Updated(info(mgr, call)));
    None
}

/// The call is over: stop audio, close the connection, tell the app, and
/// forget it after a while.
async fn finish(mgr: &Arc<Mgr>, call: &Arc<Call>, conn: Option<&Connection>) {
    let media = call.media.lock().take();
    if let Some(m) = media {
        let _ = tokio::task::spawn_blocking(move || drop(m)).await;
    }
    mgr.host.emit(CallEvent::Updated(info(mgr, call)));
    if let Some(conn) = conn {
        // let the last control message get there, then close
        let _ = tokio::time::timeout(Duration::from_millis(500), conn.closed()).await;
        conn.close(0u32.into(), b"bye");
    }
    let (mgr, id) = (mgr.clone(), call.id);
    tokio::spawn(async move {
        tokio::time::sleep(LINGER).await;
        mgr.calls.lock().remove(&id);
    });
}
