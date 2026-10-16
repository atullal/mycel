//! Places, answers and runs calls (see `proto.rs` for the wire protocol).
//!
//! Each call is one task that owns everything about it: one [`Leg`] per
//! other device (its QUIC connection, control stream and state) and, while
//! we're in the call, the [`Media`] engine with one [`LegMedia`] per peer
//! we talk to. Network tasks and the app talk to it through events, so all
//! the call's state changes happen in one place, in order.
//!
//! Legs read their control stream on a reader task and write it from a
//! writer task fed by a channel, so sending a control message never blocks
//! the call.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::{Hash32, SignPk};
use mycel_net::PathKind;
use mycel_net::iroh::endpoint::{Connection, RecvStream, SendStream};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, oneshot};

use crate::api::{CallInfo, CallPhase, CallStats, Direction, EndReason, Participant, ParticipantState};
use crate::audio::{AudioIo, default_audio};
use crate::bitrate::{BitrateController, Observation};
use crate::engine::{LegMedia, Media, TrackSink, tier};
use crate::proto::{self, CallId, CallRef, Ctrl, MAX_PARTICIPANTS, VERSION};
use crate::state::{CALLEE_RING_SLACK, LiveCall, RING_TIMEOUT, RingDecision, SETUP_TIMEOUT, on_ring};
use crate::video::VideoHub;
use mycel_video::{UiFrame, VideoSource};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What a call needs from the node it runs on.
pub trait CallHost: Send + Sync + 'static {
    fn me(&self) -> SignPk;
    /// Whom a call in this conversation rings: the other current members
    /// (not keepers). An error says why no call can be placed there.
    fn members(&self, space: &Hash32) -> Result<Vec<SignPk>>;
    /// May `peer` call us, or join a call with us, about `space`? (both
    /// current members, and it isn't a message request we haven't accepted)
    fn may_call(&self, space: &Hash32, peer: &SignPk) -> bool;
    fn name_of(&self, peer: &SignPk) -> String;
    /// The conversation's name, for group calls.
    fn title(&self, _space: &Hash32) -> Option<String> {
        None
    }
    /// Dial `peer`'s device for ALPN `mycel/call/1`.
    fn connect(&self, peer: SignPk) -> BoxFuture<Result<Connection>>;
    /// A call connection is working (marks the peer online, notes the path).
    fn note_connection(&self, _peer: &SignPk, _conn: &Connection) {}
    fn emit(&self, event: CallEvent);
}

#[derive(Clone, Debug)]
pub enum CallEvent {
    /// Someone is calling us: ring.
    Incoming(CallInfo),
    /// Anything about a call changed (state, people, path; levels ~10×/s while active).
    Updated(CallInfo),
}

/// How long an ended call stays visible in `status()`.
const LINGER: Duration = Duration::from_secs(10);
const HANDSHAKE: Duration = Duration::from_secs(15);
/// Nothing heard from a peer for this long: they're gone.
const MEDIA_TIMEOUT: Duration = Duration::from_secs(30);
/// At most this many incoming call connections being set up at once.
const MAX_PENDING: usize = 16;
/// A call rings at most this many members.
pub const MAX_RING: usize = 31;
const TICK: Duration = Duration::from_millis(100);
/// Someone who just left isn't dialed again because a stale roster still
/// lists them (they dial us themselves if they rejoin).
const LEFT_GRACE: Duration = Duration::from_secs(10);
/// How long after our call lost a glare their ring is answered at once.
const EXPECTING: Duration = Duration::from_secs(15);
/// A peer we couldn't reach is tried again after this long.
const RETRY: Duration = Duration::from_secs(3);
/// Level above which someone counts as speaking.
const SPEAKING: f32 = 0.3;

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The path a call connection is using and its RTT, whichever end dialed
/// it (see [`mycel_net::path_in_use`]).
pub fn selected_path(conn: &Connection) -> (Option<PathKind>, Duration) {
    match mycel_net::path_in_use(&conn.paths()) {
        Some(p) => (Some(PathKind::of(p.remote_addr())), p.rtt()),
        None => (None, Duration::ZERO),
    }
}

// ─────────────────────────────── legs ───────────────────────────────

/// Why we dialed a leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    Ring,
    Join,
    Watch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegState {
    /// Connecting to them; our first message isn't answered yet.
    Dialing(Why),
    /// We rang them; their device rings.
    Ringing,
    /// Our way into a call we're not in: they rang us, or we watch the call
    /// through them.
    Anchor,
    /// We answered on our anchor; waiting for `Started`.
    Accepting,
    /// Talking.
    Joined,
    /// We're in the call; they aren't (declined or missed) but keep hearing
    /// who's in it.
    Watcher(ParticipantState),
    /// Over.
    Done(ParticipantState),
}

struct Leg {
    serial: u64,
    state: LegState,
    conn: Option<Connection>,
    out: mpsc::UnboundedSender<Ctrl>,
    /// The dial task (aborted if the leg is abandoned while dialing).
    dial: Option<tokio::task::AbortHandle>,
    media: Option<Arc<LegMedia>>,
    controller: Option<BitrateController>,
    remote_loss: f32,
    last_report: (u64, u64),
    path: Option<PathKind>,
    rtt_ms: u32,
    joined_at: Option<Instant>,
    done_at: Option<Instant>,
    remote_muted: bool,
    /// Who they last told us is in the call.
    roster: BTreeSet<SignPk>,
    /// The roster we last sent them.
    sent_roster: Option<Vec<SignPk>>,
}

impl Leg {
    fn new(serial: u64, state: LegState, conn: Option<Connection>, out: mpsc::UnboundedSender<Ctrl>) -> Leg {
        Leg {
            serial,
            state,
            conn,
            out,
            dial: None,
            media: None,
            controller: None,
            remote_loss: 0.0,
            last_report: (0, 0),
            path: None,
            rtt_ms: 0,
            joined_at: None,
            done_at: None,
            remote_muted: false,
            roster: BTreeSet::new(),
            sent_roster: None,
        }
    }

    fn send(&self, msg: Ctrl) {
        let _ = self.out.send(msg);
    }

    fn live(&self) -> bool {
        !matches!(self.state, LegState::Done(_))
    }

    /// Abandon it now (replaced, or lost a glare): no goodbye.
    fn abandon(&mut self) {
        if let Some(d) = self.dial.take() {
            d.abort();
        }
        if let Some(c) = &self.conn {
            c.close(0u32.into(), b"replaced");
        }
    }
}

// ─────────────────────────────── calls ───────────────────────────────

enum Cmd {
    Accept(oneshot::Sender<Result<()>>),
    Decline,
    HangUp,
    Mute(bool),
    /// Another call in this conversation won: drop this one.
    Replaced,
}

enum Ev {
    Cmd(Cmd),
    /// Our dial went through: connected, first message sent.
    Dialed {
        peer: SignPk,
        serial: u64,
        conn: Connection,
    },
    /// A leg someone dialed to us for this call (`Join` or `Watch`).
    Incoming {
        peer: SignPk,
        serial: u64,
        conn: Connection,
        out: mpsc::UnboundedSender<Ctrl>,
        first: Ctrl,
    },
    Msg {
        peer: SignPk,
        serial: u64,
        msg: Ctrl,
    },
    /// The leg's control stream or connection ended (or the dial failed).
    Gone {
        peer: SignPk,
        serial: u64,
        error: Option<String>,
    },
    Timeout,
    Tick,
}

struct Core {
    phase: CallPhase,
    end: Option<EndReason>,
    /// While joinable: how we came to not be in it.
    lobby: Option<EndReason>,
    error: Option<String>,
    deadline: Option<Instant>,
    active_at: Option<Instant>,
    ended_at: Option<Instant>,
    connected_at: Option<u64>,
    legs: BTreeMap<SignPk, Leg>,
    /// Peers who left recently (not dialed again off a stale roster).
    left: HashMap<SignPk, Instant>,
    /// Since when we've known a peer is in the call without talking to them.
    missing: HashMap<SignPk, Instant>,
    ever_joined: bool,
    /// Why the last person we talked to went away.
    last_leave: Option<EndReason>,
    /// A peer refused us (`Denied`).
    denied: bool,
    media: Option<Media>,
    accept_ack: Option<oneshot::Sender<Result<()>>>,
}

struct Call {
    cref: CallRef,
    /// We started it.
    initiated: bool,
    group: bool,
    dir: Direction,
    title: Option<String>,
    /// 1:1: the other person; group: the initiator.
    peer: SignPk,
    started_at: u64,
    tx: mpsc::UnboundedSender<Ev>,
    muted: AtomicBool,
    names: Mutex<HashMap<SignPk, String>>,
    core: Mutex<Core>,
}

impl Call {
    fn id(&self) -> CallId {
        self.cref.call
    }

    fn send(&self, ev: Ev) {
        let _ = self.tx.send(ev);
    }

    fn name(&self, mgr: &Mgr, peer: &SignPk) -> String {
        if let Some(n) = self.names.lock().get(peer) {
            return n.clone();
        }
        let n = mgr.host.name_of(peer);
        self.names.lock().insert(*peer, n.clone());
        n
    }
}

struct Mgr {
    host: Arc<dyn CallHost>,
    audio: RwLock<Arc<dyn AudioIo>>,
    sink: RwLock<Option<Arc<dyn TrackSink>>>,
    /// Video in calls (the default track sink).
    video: Arc<VideoHub>,
    calls: Mutex<HashMap<CallId, Arc<Call>>>,
    /// Held while deciding what a ring or a press of "call" does and
    /// creating the call that comes of it, so each sees the other's call:
    /// a ring and a press in the same conversation (glare) can't both miss
    /// each other, whatever the timing.
    placing: Mutex<()>,
    /// Our call in (initiator, space) lost a glare: answer theirs at once.
    expecting: Mutex<HashMap<(SignPk, Hash32), Instant>>,
    ring_timeout: Mutex<Duration>,
    force_stream: AtomicBool,
    pending: AtomicUsize,
    serial: AtomicU64,
}

impl Mgr {
    fn me(&self) -> SignPk {
        self.host.me()
    }

    fn next_serial(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::Relaxed)
    }
}

/// Live calls (1:1 and group) over the node's endpoint.
#[derive(Clone)]
pub struct CallManager {
    inner: Arc<Mgr>,
}

impl CallManager {
    pub fn new(host: Arc<dyn CallHost>) -> CallManager {
        let video = Arc::new(VideoHub::new(host.me()));
        CallManager {
            inner: Arc::new(Mgr {
                host,
                audio: RwLock::new(default_audio()),
                sink: RwLock::new(Some(video.clone() as Arc<dyn TrackSink>)),
                video,
                calls: Mutex::default(),
                placing: Mutex::default(),
                expecting: Mutex::default(),
                ring_timeout: Mutex::new(RING_TIMEOUT),
                force_stream: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
                serial: AtomicU64::new(1),
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

    /// Swap the video source (tests, headless runs).
    pub fn set_video_source(&self, source: Arc<dyn VideoSource>) {
        self.inner.video.set_source(source);
    }

    /// Encoded video frames to show: every call's remote video (one stream
    /// per person) and our self-view (see `mycel_video::UiFrame`).
    pub fn video_frames(&self) -> tokio::sync::broadcast::Receiver<UiFrame> {
        self.inner.video.frames()
    }

    /// Turn our camera on or off in a call (before it's answered too). The
    /// first time, this may wait for the user to answer the system's
    /// camera prompt. If the camera can't start the call goes on without
    /// it: `video.camera` and `video.error` say why.
    pub async fn set_camera(&self, id: &str, on: bool) -> Result<CallInfo> {
        let call = self.find(id)?;
        if call.core.lock().phase == CallPhase::Ended {
            bail!("This call already ended.");
        }
        let (hub, cid) = (self.inner.video.clone(), call.id());
        let r =
            tokio::task::spawn_blocking(move || hub.set_camera(&cid, on)).await.context("camera failed to start")?;
        let i = info(&self.inner, &call);
        self.inner.host.emit(CallEvent::Updated(i.clone()));
        r.map(|()| i)
    }

    /// The app's video decoders lost their place (or just started): get
    /// fresh keyframes for the self-view (`source` "local"), from the others
    /// ("remote"), or both (`None`). Asking only where needed matters: a
    /// keyframe is several times a frame's size.
    pub fn video_keyframe(&self, id: &str, source: Option<&str>) -> Result<()> {
        let call = self.find(id)?;
        let (local, remote) = match source {
            Some("local") => (true, false),
            Some("remote") => (false, true),
            _ => (true, true),
        };
        self.inner.video.keyframes(&call.id(), local, remote);
        Ok(())
    }

    /// Where tracks other than audio (video) go; set before calls start
    /// (replaces the built-in video).
    pub fn set_track_sink(&self, sink: Arc<dyn TrackSink>) {
        *self.inner.sink.write() = Some(sink);
    }

    /// The connections to everyone we're talking to in a call (to send
    /// other tracks on; each datagram / stream starts with its track kind).
    pub fn connections(&self, id: &str) -> Vec<(SignPk, Connection)> {
        let Ok(call) = self.find(id) else { return vec![] };
        let core = call.core.lock();
        core.legs
            .iter()
            .filter(|(_, l)| l.state == LegState::Joined)
            .filter_map(|(p, l)| Some((*p, l.conn.clone()?)))
            .collect()
    }

    /// What names a call (diagnostics and tests).
    pub fn call_ref(&self, id: &str) -> Option<CallRef> {
        self.find(id).ok().map(|c| c.cref)
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
            .find(|c| hex(&c.id().0) == id.trim().to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| anyhow!("no such call"))
    }

    /// Call the conversation: the other person, or everyone in a group.
    pub async fn start(&self, space: Hash32) -> Result<CallInfo> {
        let mgr = &self.inner;
        let members = mgr.host.members(&space)?;
        if let Some(id) = waiting_call(mgr, &space)? {
            return self.accept(&id).await;
        }
        if members.len() > MAX_RING {
            bail!("This group is too big for calls (at most {} people can be rung).", MAX_RING + 1);
        }
        // This may wait for the user (microphone permission), or a loaded
        // machine for a while: a ring may come in meanwhile (they're
        // calling us too), so look again before placing ours.
        prepare_audio(mgr).await?;
        let placed = {
            let _placing = mgr.placing.lock();
            match waiting_call(mgr, &space)? {
                Some(id) => Err(id),
                None => Ok(place_call(mgr, space, members)),
            }
        };
        let call = match placed {
            Ok(call) => call,
            Err(id) => return self.accept(&id).await,
        };
        let first = info(mgr, &call);
        mgr.host.emit(CallEvent::Updated(first.clone()));
        Ok(first)
    }

    /// Answer a ringing call, or join a group call that's going on.
    pub async fn accept(&self, id: &str) -> Result<CallInfo> {
        let call = self.find(id)?;
        if !matches!(call.core.lock().phase, CallPhase::Ringing | CallPhase::Joinable)
            || call.dir != Direction::Incoming
        {
            bail!("This call isn't ringing any more.");
        }
        // Another call in progress? Hang it up first (answering means switching).
        for other in live_calls(&self.inner) {
            if other.id() != call.id() && engaged(&other) {
                other.send(Ev::Cmd(Cmd::HangUp));
            }
        }
        prepare_audio(&self.inner).await?;
        let (tx, rx) = oneshot::channel();
        call.send(Ev::Cmd(Cmd::Accept(tx)));
        if let Ok(Ok(Err(e))) = tokio::time::timeout(Duration::from_secs(2), rx).await {
            return Err(e);
        }
        Ok(info(&self.inner, &call))
    }

    pub fn decline(&self, id: &str) -> Result<()> {
        self.find(id)?.send(Ev::Cmd(Cmd::Decline));
        Ok(())
    }

    /// Leave (or cancel a call that hasn't been answered). A group call goes
    /// on for the others.
    pub fn end(&self, id: &str) -> Result<()> {
        self.find(id)?.send(Ev::Cmd(Cmd::HangUp));
        Ok(())
    }

    pub fn set_muted(&self, id: &str, muted: bool) -> Result<CallInfo> {
        let call = self.find(id)?;
        call.muted.store(muted, Ordering::Relaxed);
        if let Some(m) = call.core.lock().media.as_ref() {
            m.shared().muted.store(muted, Ordering::Relaxed);
        }
        call.send(Ev::Cmd(Cmd::Mute(muted)));
        let i = info(&self.inner, &call);
        self.inner.host.emit(CallEvent::Updated(i.clone()));
        Ok(i)
    }

    /// Hang up everything (app quitting).
    pub async fn shutdown(&self) {
        let live = live_calls(&self.inner);
        for c in &live {
            c.send(Ev::Cmd(Cmd::HangUp));
        }
        if !live.is_empty() {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

fn live_calls(mgr: &Mgr) -> Vec<Arc<Call>> {
    mgr.calls.lock().values().filter(|c| c.core.lock().phase != CallPhase::Ended).cloned().collect()
}

/// In it, or calling out: other calls get `Busy`.
fn engaged(c: &Call) -> bool {
    let phase = c.core.lock().phase;
    match phase {
        CallPhase::Active | CallPhase::Connecting => true,
        CallPhase::Ringing => c.dir == Direction::Outgoing,
        CallPhase::Joinable | CallPhase::Ended => false,
    }
}

/// Before placing a call in `space`: a call there already ringing us, or
/// going on without us, to answer or join instead (its id). An error if
/// we're in another call.
fn waiting_call(mgr: &Mgr, space: &Hash32) -> Result<Option<String>> {
    let live = live_calls(mgr);
    let waiting = live.iter().find(|c| {
        c.cref.space == *space
            && c.dir == Direction::Incoming
            && matches!(c.core.lock().phase, CallPhase::Ringing | CallPhase::Joinable)
    });
    if let Some(c) = waiting {
        return Ok(Some(hex(&c.id().0)));
    }
    if live.iter().any(|c| engaged(c)) {
        bail!("You're already in a call.");
    }
    Ok(None)
}

/// Our new call in `space`, ringing `members` (hold `Mgr::placing`).
fn place_call(mgr: &Arc<Mgr>, space: Hash32, members: Vec<SignPk>) -> Arc<Call> {
    let me = mgr.me();
    let cref = CallRef::new(space, me, mycel_crypto::random());
    let group = members.len() > 1;
    let peer = if group { me } else { members[0] };
    let call = new_call(mgr, cref, group, Direction::Outgoing, peer, CallPhase::Connecting);
    {
        let mut core = call.core.lock();
        let timeout = *mgr.ring_timeout.lock();
        // a group call ends once every ring is over (each member's own
        // ring timeout answers `Decline{missed}`); this is a backstop
        core.deadline = Some(Instant::now() + if group { timeout + CALLEE_RING_SLACK * 2 } else { timeout });
        for m in members {
            let leg = dial(mgr, &call, m, Why::Ring, Ctrl::Ring { version: VERSION, call: cref, group });
            core.legs.insert(m, leg);
        }
    }
    call
}

async fn prepare_audio(mgr: &Mgr) -> Result<()> {
    let audio = mgr.audio.read().clone();
    tokio::task::spawn_blocking(move || audio.prepare()).await.context("audio check failed")?
}

fn new_call(mgr: &Arc<Mgr>, cref: CallRef, group: bool, dir: Direction, peer: SignPk, phase: CallPhase) -> Arc<Call> {
    let (tx, rx) = mpsc::unbounded_channel();
    let call = Arc::new(Call {
        cref,
        initiated: cref.initiator == mgr.me(),
        group,
        dir,
        title: if group { mgr.host.title(&cref.space) } else { None },
        peer,
        started_at: wall_ms(),
        tx,
        muted: AtomicBool::new(false),
        names: Mutex::default(),
        core: Mutex::new(Core {
            phase,
            end: None,
            lobby: None,
            error: None,
            deadline: None,
            active_at: None,
            ended_at: None,
            connected_at: None,
            legs: BTreeMap::new(),
            left: HashMap::new(),
            missing: HashMap::new(),
            ever_joined: false,
            last_leave: None,
            denied: false,
            media: None,
            accept_ack: None,
        }),
    });
    mgr.calls.lock().insert(cref.call, call.clone());
    tokio::spawn(run(mgr.clone(), call.clone(), rx));
    call
}

// ─────────────────────────────── leg I/O ───────────────────────────────

/// Dial `peer` for this call; the leg exists (and queues messages) at once.
fn dial(mgr: &Arc<Mgr>, call: &Arc<Call>, peer: SignPk, why: Why, first: Ctrl) -> Leg {
    let serial = mgr.next_serial();
    let (out, out_rx) = mpsc::unbounded_channel();
    let (host, ev) = (mgr.host.clone(), call.tx.clone());
    let task = tokio::spawn(async move {
        let setup = async {
            let conn = host.connect(peer).await?;
            let (mut tx, rx) = conn.open_bi().await?;
            proto::send(&mut tx, &first).await?;
            anyhow::Ok((conn, tx, rx))
        };
        match tokio::time::timeout(HANDSHAKE, setup).await {
            Ok(Ok((conn, tx, rx))) => {
                // the leg has its connection before any answer on it is
                // handled (a `Started` handled first would join a leg
                // without a connection: no path, no media)
                let _ = ev.send(Ev::Dialed { peer, serial, conn: conn.clone() });
                spawn_reader(ev.clone(), peer, serial, rx, conn);
                write_loop(tx, out_rx).await;
            }
            other => {
                let error = match other {
                    Ok(Err(e)) => format!("{e:#}"),
                    _ => "timed out".into(),
                };
                let _ = ev.send(Ev::Gone { peer, serial, error: Some(error) });
            }
        }
    });
    let mut leg = Leg::new(serial, LegState::Dialing(why), None, out);
    leg.dial = Some(task.abort_handle());
    leg
}

async fn write_loop(mut tx: SendStream, mut out: mpsc::UnboundedReceiver<Ctrl>) {
    while let Some(m) = out.recv().await {
        if proto::send(&mut tx, &m).await.is_err() {
            return;
        }
    }
    let _ = tx.finish();
}

fn spawn_reader(ev: mpsc::UnboundedSender<Ev>, peer: SignPk, serial: u64, mut rx: RecvStream, conn: Connection) {
    tokio::spawn(async move {
        let error = loop {
            tokio::select! {
                m = proto::recv(&mut rx) => match m {
                    Ok(Some(msg)) => {
                        if ev.send(Ev::Msg { peer, serial, msg }).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break None,
                    Err(e) => break Some(format!("{e:#}")),
                },
                _ = conn.closed() => break Some("connection closed".to_string()),
            }
        };
        let _ = ev.send(Ev::Gone { peer, serial, error });
    });
}

/// A leg someone else dialed: its writer, reader, and the sender to queue messages on.
fn attach_incoming(
    ev: &mpsc::UnboundedSender<Ev>,
    peer: SignPk,
    serial: u64,
    conn: &Connection,
    tx: SendStream,
    rx: RecvStream,
) -> mpsc::UnboundedSender<Ctrl> {
    let (out, out_rx) = mpsc::unbounded_channel();
    tokio::spawn(write_loop(tx, out_rx));
    spawn_reader(ev.clone(), peer, serial, rx, conn.clone());
    out
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
    let (tx, mut rx) = tokio::time::timeout(HANDSHAKE, conn.accept_bi()).await.context("no call message")??;
    let first = tokio::time::timeout(HANDSHAKE, proto::recv(&mut rx)).await.context("no call message")??;
    let cref = match &first {
        Some(Ctrl::Ring { call, .. } | Ctrl::Join { call, .. } | Ctrl::Watch { call, .. }) => *call,
        _ => {
            refuse(&conn, tx, Ctrl::Denied).await;
            bail!("expected a ring, join or watch");
        }
    };
    // Bound to the conversation and, for a ring, to the authenticated caller.
    let ring = matches!(first, Some(Ctrl::Ring { .. }));
    if !cref.is_valid() || (ring && cref.initiator != peer) {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("call id doesn't match");
    }
    if !mgr.host.may_call(&cref.space, &peer) {
        refuse(&conn, tx, Ctrl::Denied).await;
        bail!("{} isn't allowed to call about that conversation", peer.short());
    }
    let Some(Ctrl::Ring { group, .. }) = first else {
        // Join / Watch: only for a call we're in; the call decides the rest
        let call = mgr.calls.lock().get(&cref.call).cloned();
        let Some(call) = call.filter(|c| in_call(c, c.core.lock().phase)) else {
            refuse(&conn, tx, Ctrl::Denied).await;
            bail!("not in that call");
        };
        let serial = mgr.next_serial();
        let out = attach_incoming(&call.tx, peer, serial, &conn, tx, rx);
        call.send(Ev::Incoming { peer, serial, conn, out, first: first.expect("checked above") });
        drop(guard);
        return Ok(());
    };
    // decided, and the call set up, with no call placed here in between
    // (see `Mgr::placing`)
    let rung = {
        let _placing = mgr.placing.lock();
        let live: Vec<LiveCall> =
            live_calls(mgr).iter().map(|c| LiveCall { call: c.cref, dir: c.dir, phase: c.core.lock().phase }).collect();
        let expecting = {
            let mut e = mgr.expecting.lock();
            e.retain(|_, t| t.elapsed() < EXPECTING);
            e.remove(&(peer, cref.space)).is_some()
        };
        let auto = match on_ring(&mgr.me(), &peer, &cref, &live, expecting) {
            RingDecision::Busy => Err(Ctrl::Busy),
            RingDecision::Glare => Err(Ctrl::Glare),
            RingDecision::Existing(call) => Err(Ctrl::Existing { call }),
            RingDecision::Duplicate => Err(Ctrl::Denied),
            RingDecision::AutoAccept { replaces } => {
                if let Some(old) = replaces.and_then(|r| mgr.calls.lock().get(&r).cloned()) {
                    old.send(Ev::Cmd(Cmd::Replaced));
                }
                Ok(true)
            }
            RingDecision::Ring => Ok(false),
        };
        match auto {
            Ok(auto) => Ok((ring_here(mgr, cref, group, peer, &conn, tx, rx), auto)),
            Err(msg) => Err((msg, tx)),
        }
    };
    let (call, auto) = match rung {
        Ok(rung) => rung,
        Err((msg, tx)) => {
            let duplicate = msg == Ctrl::Denied;
            refuse(&conn, tx, msg).await;
            if duplicate {
                bail!("duplicate call");
            }
            return Ok(());
        }
    };
    mgr.host.note_connection(&peer, &conn);
    drop(guard);
    if auto {
        let (ack, _) = oneshot::channel();
        call.send(Ev::Cmd(Cmd::Accept(ack)));
        mgr.host.emit(CallEvent::Updated(info(mgr, &call)));
    } else {
        mgr.host.emit(CallEvent::Incoming(info(mgr, &call)));
    }
    Ok(())
}

/// A call ringing us (or answered at once), with its anchor leg in place
/// before anyone can answer it (hold `Mgr::placing`).
fn ring_here(
    mgr: &Arc<Mgr>,
    cref: CallRef,
    group: bool,
    peer: SignPk,
    conn: &Connection,
    tx: SendStream,
    rx: RecvStream,
) -> Arc<Call> {
    let call = new_call(mgr, cref, group, Direction::Incoming, peer, CallPhase::Ringing);
    let serial = mgr.next_serial();
    let out = attach_incoming(&call.tx, peer, serial, conn, tx, rx);
    let _ = out.send(Ctrl::Ringing);
    let mut core = call.core.lock();
    core.deadline = Some(Instant::now() + *mgr.ring_timeout.lock() + CALLEE_RING_SLACK);
    let mut leg = Leg::new(serial, LegState::Anchor, Some(conn.clone()), out);
    leg.path = selected_path(conn).0;
    core.legs.insert(peer, leg);
    drop(core);
    call
}

// ─────────────────────────────── the call task ───────────────────────────────

/// Things to do once the call's lock is released.
#[derive(Default)]
struct After {
    start_media: bool,
    /// Our ring was answered with "there's a call already": join it.
    join_existing: Option<(CallRef, SignPk)>,
    /// Our call lost a glare to this peer's.
    lost_glare: Option<SignPk>,
}

/// We're in the call (or, as its initiator, calling out): we count in
/// rosters and take `Join`s.
fn in_call(call: &Call, phase: CallPhase) -> bool {
    phase == CallPhase::Active || (call.initiated && matches!(phase, CallPhase::Connecting | CallPhase::Ringing))
}

async fn run(mgr: Arc<Mgr>, call: Arc<Call>, mut rx: mpsc::UnboundedReceiver<Ev>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    loop {
        let deadline = call.core.lock().deadline;
        let ev = tokio::select! {
            e = rx.recv() => match e { Some(e) => e, None => return },
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None => std::future::pending().await,
                }
            } => Ev::Timeout,
            _ = ticker.tick() => Ev::Tick,
        };
        let tick = matches!(ev, Ev::Tick);
        if tick {
            ticks += 1;
        }
        let mut after = After::default();
        let (changed, ended) = {
            let mut core = call.core.lock();
            let before = (core.phase, core.legs.values().map(|l| l.state).collect::<Vec<_>>());
            if tick {
                on_tick(&mgr, &call, &mut core, ticks);
            } else {
                handle(&mgr, &call, &mut core, ev, &mut after);
            }
            if core.phase != CallPhase::Ended {
                mesh(&mgr, &call, &mut core);
                check_end(&call, &mut core);
            }
            if core.phase != CallPhase::Ended {
                send_rosters(&mgr, &call, &mut core);
            }
            let now = (core.phase, core.legs.values().map(|l| l.state).collect::<Vec<_>>());
            (before != now || !tick || core.phase == CallPhase::Active, core.phase == CallPhase::Ended)
        };
        if after.start_media && !ended {
            start_media(&mgr, &call).await;
        }
        if let Some((cref, via)) = after.join_existing {
            join_existing(&mgr, cref, via);
        }
        if let Some(peer) = after.lost_glare {
            lost_glare(&mgr, &call, peer);
        }
        if ended {
            finish(&mgr, &call).await;
            return;
        }
        if changed {
            mgr.host.emit(CallEvent::Updated(info(&mgr, &call)));
        }
    }
}

/// Our side of the call ends: say goodbye on every leg.
fn end(core: &mut Core, reason: EndReason) {
    if core.phase == CallPhase::Ended {
        return;
    }
    core.phase = CallPhase::Ended;
    core.end = Some(reason);
    core.ended_at = Some(Instant::now());
    core.deadline = None;
    for leg in core.legs.values_mut() {
        if leg.live() {
            if matches!(leg.state, LegState::Dialing(_)) {
                leg.abandon();
            } else {
                leg.send(Ctrl::HangUp);
            }
        }
    }
    if let Some(ack) = core.accept_ack.take() {
        let _ = ack.send(Ok(()));
    }
}

fn set_active(core: &mut Core) {
    if core.phase != CallPhase::Active {
        core.phase = CallPhase::Active;
        core.active_at.get_or_insert_with(Instant::now);
        core.connected_at.get_or_insert_with(wall_ms);
        core.deadline = None;
        core.lobby = None;
    }
}

/// Start talking with `peer` on its leg.
fn leg_joined(mgr: &Mgr, core: &mut Core, peer: SignPk, after: &mut After) {
    set_active(core);
    core.ever_joined = true;
    core.left.remove(&peer);
    let force = mgr.force_stream.load(Ordering::Relaxed);
    let Some(leg) = core.legs.get_mut(&peer) else { return };
    leg.state = LegState::Joined;
    leg.joined_at = Some(Instant::now());
    if let Some(conn) = &leg.conn {
        let (path, rtt) = selected_path(conn);
        leg.path = path;
        leg.rtt_ms = rtt.as_millis() as u32;
        mgr.host.note_connection(&peer, conn);
    }
    if let (Some(media), Some(conn)) = (core.media.as_ref(), leg.conn.clone()) {
        let bitrate = BitrateController::new(leg.path).bitrate();
        leg.media = Some(media.add_leg(peer, conn, bitrate, force));
    } else {
        after.start_media = true;
    }
    if let Some(ack) = core.accept_ack.take() {
        let _ = ack.send(Ok(()));
    }
}

/// The leg to `peer` is over.
fn leg_done(core: &mut Core, peer: &SignPk, state: ParticipantState) {
    let Some(leg) = core.legs.get_mut(peer) else { return };
    if leg.state == LegState::Joined {
        if let Some(m) = &core.media {
            m.remove_leg(peer);
        }
        leg.media = None;
    }
    leg.state = LegState::Done(state);
    leg.done_at = Some(Instant::now());
    leg.roster.clear();
}

/// Whoever we know is in the call (not us).
fn known_roster(core: &Core, me: &SignPk) -> BTreeSet<SignPk> {
    let mut out: BTreeSet<SignPk> = BTreeSet::new();
    for (p, leg) in &core.legs {
        if leg.state == LegState::Joined {
            out.insert(*p);
        }
        if leg.live() {
            out.extend(leg.roster.iter().copied());
        }
    }
    out.remove(me);
    out.retain(|p| {
        core.legs.get(p).is_some_and(|l| l.state == LegState::Joined)
            || core.left.get(p).is_none_or(|t| t.elapsed() > LEFT_GRACE)
    });
    out
}

fn handle(mgr: &Arc<Mgr>, call: &Arc<Call>, core: &mut Core, ev: Ev, after: &mut After) {
    match ev {
        Ev::Tick => {}
        Ev::Timeout => match core.phase {
            CallPhase::Ringing if call.dir == Direction::Incoming => {
                // it rang out
                if let Some(anchor) = anchor_mut(core) {
                    anchor.send(Ctrl::Decline { missed: true });
                }
                lobby_or_end(call, core, EndReason::Missed);
            }
            CallPhase::Connecting | CallPhase::Ringing if call.initiated && !core.ever_joined => {
                end(core, EndReason::NoAnswer)
            }
            CallPhase::Connecting => end(core, EndReason::ConnectionLost),
            _ => core.deadline = None,
        },
        Ev::Cmd(cmd) => match cmd {
            Cmd::Accept(ack) => {
                if !matches!(core.phase, CallPhase::Ringing | CallPhase::Joinable) {
                    let _ = ack.send(Err(anyhow!("This call isn't ringing any more.")));
                    return;
                }
                let Some(anchor) = anchor_mut(core) else {
                    let _ = ack.send(Err(anyhow!("Reconnecting to the call; try again in a moment.")));
                    return;
                };
                anchor.send(Ctrl::Accept);
                anchor.state = LegState::Accepting;
                core.phase = CallPhase::Connecting;
                core.deadline = Some(Instant::now() + SETUP_TIMEOUT);
                core.accept_ack = Some(ack);
            }
            Cmd::Decline => decline(call, core),
            Cmd::HangUp => match core.phase {
                CallPhase::Ringing if call.dir == Direction::Incoming => decline(call, core),
                CallPhase::Joinable => {
                    let reason = core.lobby.unwrap_or(EndReason::Declined);
                    end(core, reason)
                }
                _ => end(core, EndReason::HungUp),
            },
            Cmd::Mute(muted) => {
                for leg in core.legs.values().filter(|l| l.state == LegState::Joined) {
                    leg.send(Ctrl::Mute { muted });
                }
            }
            Cmd::Replaced => end(core, EndReason::Replaced),
        },
        Ev::Dialed { peer, serial, conn } => {
            let Some(leg) = core.legs.get_mut(&peer).filter(|l| l.serial == serial) else {
                conn.close(0u32.into(), b"gone");
                return;
            };
            leg.dial = None;
            leg.path = selected_path(&conn).0;
            mgr.host.note_connection(&peer, &conn);
            leg.conn = Some(conn);
            if leg.state == LegState::Dialing(Why::Watch) {
                leg.state = LegState::Anchor;
            }
        }
        Ev::Incoming { peer, serial, conn, out, first } => {
            on_incoming_leg(mgr, call, core, peer, serial, conn, out, first, after)
        }
        Ev::Msg { peer, serial, msg } => {
            if core.legs.get(&peer).is_none_or(|l| l.serial != serial) {
                return; // from a leg that's been replaced
            }
            on_msg(mgr, call, core, peer, msg, after);
        }
        Ev::Gone { peer, serial, error } => {
            let Some(leg) = core.legs.get(&peer).filter(|l| l.serial == serial) else { return };
            let state = leg.state;
            match state {
                LegState::Done(_) => {}
                LegState::Joined => {
                    core.last_leave = Some(EndReason::ConnectionLost);
                    leg_done(core, &peer, ParticipantState::Left);
                }
                LegState::Watcher(_) => {
                    core.legs.remove(&peer);
                }
                LegState::Anchor | LegState::Accepting | LegState::Dialing(Why::Watch) => {
                    reanchor(mgr, call, core, peer);
                    leg_done(core, &peer, ParticipantState::Left);
                }
                LegState::Dialing(_) | LegState::Ringing => {
                    if core.error.is_none() {
                        core.error = error;
                    }
                    leg_done(core, &peer, ParticipantState::Unavailable);
                }
            }
        }
    }
}

fn anchor_mut(core: &mut Core) -> Option<&mut Leg> {
    core.legs.values_mut().find(|l| l.state == LegState::Anchor)
}

/// The user said no (or let it ring out): a group call stays joinable while
/// it goes on; a 1:1 call is over.
fn decline(call: &Call, core: &mut Core) {
    if let Some(anchor) = anchor_mut(core) {
        anchor.send(Ctrl::Decline { missed: false });
    }
    lobby_or_end(call, core, EndReason::Declined);
}

fn lobby_or_end(call: &Call, core: &mut Core, reason: EndReason) {
    if call.group {
        core.phase = CallPhase::Joinable;
        core.lobby = Some(reason);
        core.deadline = None;
    } else {
        end(core, reason);
    }
}

/// Our way into the call (`gone`) is going away: watch it through someone
/// else who's in it (as `gone` last told us), or, if nobody is, it's over
/// for us. Call before marking `gone`'s leg done (its roster is the hint).
fn reanchor(mgr: &Arc<Mgr>, call: &Arc<Call>, core: &mut Core, gone: SignPk) {
    let me = mgr.me();
    let mut candidates: BTreeSet<SignPk> = core.legs.values().flat_map(|l| l.roster.iter().copied()).collect();
    candidates.retain(|p| {
        *p != me
            && *p != gone
            && core.legs.get(p).is_none_or(|l| !matches!(l.state, LegState::Done(_)))
            && core.left.get(p).is_none_or(|t| t.elapsed() > LEFT_GRACE)
    });
    let joining = core.phase == CallPhase::Connecting;
    if call.group
        && let Some(next) = candidates.into_iter().next()
    {
        let (why, first) = if joining {
            (Why::Join, Ctrl::Join { version: VERSION, call: call.cref })
        } else {
            (Why::Watch, Ctrl::Watch { version: VERSION, call: call.cref })
        };
        if let Some(old) = core.legs.get_mut(&next) {
            old.abandon();
        }
        let leg = dial(mgr, call, next, why, first);
        core.legs.insert(next, leg);
        return;
    }
    match core.phase {
        CallPhase::Ringing => end(core, EndReason::Missed),
        CallPhase::Joinable => {
            let reason = core.lobby.unwrap_or(EndReason::Missed);
            end(core, reason)
        }
        CallPhase::Connecting => end(core, EndReason::RemoteHungUp),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn on_incoming_leg(
    mgr: &Arc<Mgr>,
    call: &Arc<Call>,
    core: &mut Core,
    peer: SignPk,
    serial: u64,
    conn: Connection,
    out: mpsc::UnboundedSender<Ctrl>,
    first: Ctrl,
    after: &mut After,
) {
    let me = mgr.me();
    let refuse = |msg: Ctrl| {
        let _ = out.send(msg);
        let c = conn.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(3), c.closed()).await;
            c.close(0u32.into(), b"refused");
        });
    };
    if !in_call(call, core.phase) {
        refuse(Ctrl::Denied);
        return;
    }
    let existing = core.legs.get(&peer).map(|l| l.state);
    match first {
        Ctrl::Join { .. } => {
            if existing == Some(LegState::Dialing(Why::Join)) && me < peer {
                // we're dialing them too: the leg the lower key dialed wins
                refuse(Ctrl::Glare);
                return;
            }
            let healthy = core.legs.get(&peer).is_some_and(|l| {
                l.state == LegState::Joined
                    && l.media.as_ref().and_then(|m| m.since_last_frame()).is_some_and(|d| d < Duration::from_secs(2))
            });
            if healthy {
                // we're already talking (a stale dial of theirs): keep it
                refuse(Ctrl::Glare);
                return;
            }
            let joined = core.legs.values().filter(|l| l.state == LegState::Joined).count();
            if existing != Some(LegState::Joined) && joined + 1 >= MAX_PARTICIPANTS {
                refuse(Ctrl::Full);
                return;
            }
            if let Some(mut old) = core.legs.remove(&peer) {
                if old.state == LegState::Joined
                    && let Some(m) = &core.media
                {
                    m.remove_leg(&peer);
                }
                old.abandon();
            }
            let _ = out.send(Ctrl::Started);
            core.legs.insert(peer, Leg::new(serial, LegState::Joined, Some(conn), out));
            leg_joined(mgr, core, peer, after);
        }
        Ctrl::Watch { .. } => {
            let was = match existing {
                Some(LegState::Watcher(s) | LegState::Done(s)) => s,
                _ => ParticipantState::Declined,
            };
            if let Some(mut old) = core.legs.remove(&peer) {
                old.abandon();
            }
            core.legs.insert(peer, Leg::new(serial, LegState::Watcher(was), Some(conn), out));
        }
        _ => refuse(Ctrl::Denied),
    }
}

fn on_msg(mgr: &Arc<Mgr>, call: &Arc<Call>, core: &mut Core, peer: SignPk, msg: Ctrl, after: &mut After) {
    let me = mgr.me();
    let Some(state) = core.legs.get(&peer).map(|l| l.state) else { return };
    match msg {
        Ctrl::Ringing => {
            if state == LegState::Dialing(Why::Ring) {
                core.legs.get_mut(&peer).expect("leg").state = LegState::Ringing;
                if core.phase == CallPhase::Connecting && call.dir == Direction::Outgoing {
                    core.phase = CallPhase::Ringing;
                }
            }
        }
        Ctrl::Accept => {
            if !matches!(state, LegState::Ringing | LegState::Watcher(_)) || !in_call(call, core.phase) {
                return;
            }
            // still a member? (they may have been removed since it rang)
            if !mgr.host.may_call(&call.cref.space, &peer) {
                core.legs.get_mut(&peer).expect("leg").send(Ctrl::Denied);
                leg_done(core, &peer, ParticipantState::Unavailable);
                return;
            }
            let joined = core.legs.values().filter(|l| l.state == LegState::Joined).count();
            let leg = core.legs.get_mut(&peer).expect("leg");
            if joined + 1 >= MAX_PARTICIPANTS {
                leg.send(Ctrl::Full);
                return;
            }
            leg.send(Ctrl::Started);
            leg_joined(mgr, core, peer, after);
        }
        Ctrl::Started => {
            if matches!(state, LegState::Accepting | LegState::Dialing(Why::Join)) {
                leg_joined(mgr, core, peer, after);
            }
        }
        Ctrl::Decline { missed } => {
            if matches!(state, LegState::Ringing | LegState::Dialing(Why::Ring)) {
                let s = if missed { ParticipantState::Missed } else { ParticipantState::Declined };
                if call.group {
                    core.legs.get_mut(&peer).expect("leg").state = LegState::Watcher(s);
                } else {
                    leg_done(core, &peer, s);
                }
            }
        }
        Ctrl::Busy => leg_done(core, &peer, ParticipantState::Busy),
        Ctrl::Glare => match state {
            LegState::Dialing(Why::Join) => {
                // they're dialing us too (their leg wins), or already talking
                // to us: drop ours, and don't dial them again for a while
                core.legs.get_mut(&peer).expect("leg").abandon();
                leg_done(core, &peer, ParticipantState::Connecting);
            }
            _ if !core.ever_joined => {
                // their call in this conversation wins: drop ours, take theirs
                // (expected before ours ends, so their ring is answered
                // whenever it comes)
                mgr.expecting.lock().insert((peer, call.cref.space), Instant::now());
                end(core, EndReason::Replaced);
                after.lost_glare = Some(peer);
            }
            _ => leg_done(core, &peer, ParticipantState::Unavailable),
        },
        Ctrl::Existing { call: other } => {
            if !core.ever_joined && other.is_valid() && other.space == call.cref.space {
                after.join_existing = Some((other, peer));
                end(core, EndReason::Replaced);
            } else {
                leg_done(core, &peer, ParticipantState::Busy);
            }
        }
        Ctrl::Denied => {
            core.denied = true;
            if core.error.is_none() && !call.group {
                core.error = Some("They can't take calls in this conversation.".into());
            }
            if matches!(state, LegState::Anchor | LegState::Accepting | LegState::Dialing(Why::Watch)) {
                reanchor(mgr, call, core, peer);
            }
            leg_done(core, &peer, ParticipantState::Unavailable);
        }
        Ctrl::Full => {
            leg_done(core, &peer, ParticipantState::Unavailable);
            if !in_call(call, core.phase) || core.phase == CallPhase::Connecting {
                end(core, EndReason::Full);
            }
        }
        Ctrl::HangUp => match state {
            LegState::Joined => {
                core.last_leave = Some(EndReason::RemoteHungUp);
                core.left.insert(peer, Instant::now());
                leg_done(core, &peer, ParticipantState::Left);
            }
            LegState::Watcher(_) => {
                core.legs.remove(&peer);
            }
            LegState::Anchor | LegState::Accepting | LegState::Dialing(Why::Watch) => {
                reanchor(mgr, call, core, peer);
                leg_done(core, &peer, ParticipantState::Left);
            }
            LegState::Ringing | LegState::Dialing(_) => leg_done(core, &peer, ParticipantState::Unavailable),
            LegState::Done(_) => {}
        },
        Ctrl::Mute { muted } => {
            core.legs.get_mut(&peer).expect("leg").remote_muted = muted;
        }
        Ctrl::Report { loss_ppm, .. } => {
            core.legs.get_mut(&peer).expect("leg").remote_loss = (loss_ppm as f32 / 1e6).clamp(0.0, 1.0);
        }
        Ctrl::Roster { joined } => {
            let leg = core.legs.get_mut(&peer).expect("leg");
            leg.roster = joined.into_iter().filter(|p| *p != me).take(MAX_PARTICIPANTS * 2).collect();
        }
        Ctrl::Ring { .. } | Ctrl::Join { .. } | Ctrl::Watch { .. } => {}
    }
}

/// While we're in the call: connect to everyone in it we aren't talking
/// to. Of two people not yet connected, the lower key dials (so they don't
/// dial each other at once); the other one dials too if that hasn't
/// happened after a while (it may not be able to reach us).
fn mesh(mgr: &Arc<Mgr>, call: &Arc<Call>, core: &mut Core) {
    if core.phase != CallPhase::Active {
        core.missing.clear();
        return;
    }
    let me = mgr.me();
    let now = Instant::now();
    let joined = core.legs.values().filter(|l| l.state == LegState::Joined).count();
    let roster = known_roster(core, &me);
    core.missing.retain(|p, _| roster.contains(p));
    for p in roster {
        let free = core
            .legs
            .get(&p)
            .is_none_or(|l| matches!(l.state, LegState::Done(_)) && l.done_at.is_none_or(|t| t.elapsed() > RETRY));
        if !free {
            core.missing.remove(&p);
            continue;
        }
        let since = *core.missing.entry(p).or_insert(now);
        if joined + 1 >= MAX_PARTICIPANTS || (me > p && now.duration_since(since) < RETRY) {
            continue;
        }
        core.missing.remove(&p);
        let leg = dial(mgr, call, p, Why::Join, Ctrl::Join { version: VERSION, call: call.cref });
        core.legs.insert(p, leg);
    }
}

/// Over when nobody's left to talk to and nobody's still being reached.
fn check_end(call: &Call, core: &mut Core) {
    // in it, or on our way in (calling out, answering, joining)
    let ours = in_call(call, core.phase) || core.phase == CallPhase::Connecting;
    if !ours {
        return;
    }
    let pending = core
        .legs
        .values()
        .any(|l| matches!(l.state, LegState::Dialing(_) | LegState::Ringing | LegState::Joined | LegState::Accepting));
    if pending {
        return;
    }
    let reason = if core.ever_joined {
        core.last_leave.unwrap_or(EndReason::RemoteHungUp)
    } else {
        let states: Vec<ParticipantState> = core
            .legs
            .values()
            .filter_map(|l| match l.state {
                LegState::Watcher(s) | LegState::Done(s) => Some(s),
                _ => None,
            })
            .collect();
        let any = |s: ParticipantState| states.contains(&s);
        if any(ParticipantState::Declined) {
            EndReason::RemoteDeclined
        } else if any(ParticipantState::Missed) {
            EndReason::NoAnswer
        } else if any(ParticipantState::Busy) {
            EndReason::Busy
        } else if core.denied {
            if core.error.is_none() {
                core.error = Some("You're not allowed in this call.".into());
            }
            EndReason::Failed
        } else {
            EndReason::Unavailable
        }
    };
    end(core, reason);
}

/// Tell every leg who's in the call, when that changed.
fn send_rosters(mgr: &Mgr, call: &Call, core: &mut Core) {
    let me = mgr.me();
    let mut joined: Vec<SignPk> =
        core.legs.iter().filter(|(_, l)| l.state == LegState::Joined).map(|(p, _)| *p).collect();
    if in_call(call, core.phase) {
        joined.push(me);
    }
    joined.sort();
    for leg in core.legs.values_mut() {
        if leg.live() && leg.sent_roster.as_ref() != Some(&joined) {
            leg.send(Ctrl::Roster { joined: joined.clone() });
            leg.sent_roster = Some(joined.clone());
        }
    }
}

/// Every 100 ms; every second while talking: each leg's path, RTT and
/// bitrate, and a receiver report to each peer.
fn on_tick(mgr: &Arc<Mgr>, call: &Arc<Call>, core: &mut Core, ticks: u64) {
    if core.phase != CallPhase::Active || !ticks.is_multiple_of(10) {
        return;
    }
    let now = Instant::now();
    let debug = std::env::var_os("MYCEL_CALL_DEBUG").is_some();
    let mut lost = Vec::new();
    for (peer, leg) in core.legs.iter_mut().filter(|(_, l)| l.state == LegState::Joined) {
        let (Some(conn), Some(media)) = (leg.conn.clone(), leg.media.clone()) else { continue };
        let (path, rtt) = selected_path(&conn);
        if debug {
            eprintln!("[call {}] {} via {:?} rtt {:?}", hex(&call.id().0[..4]), peer.short(), path, rtt);
        }
        let old_path = leg.path;
        if path.is_some() {
            leg.path = path;
        }
        leg.rtt_ms = rtt.as_millis() as u32;
        let ctl = leg.controller.get_or_insert_with(|| BitrateController::new(path));
        ctl.update(now, Observation { path, loss: leg.remote_loss, rtt });
        let bitrate = ctl.bitrate();
        media.bitrate.store(tier(bitrate), Ordering::Relaxed);
        media.fec_loss.store(BitrateController::fec_loss_percent(leg.remote_loss) as u32, Ordering::Relaxed);
        // what we received of theirs, last interval
        let js = media.jitter_stats();
        let (played, missing) =
            (js.played - leg.last_report.0.min(js.played), js.lost - leg.last_report.1.min(js.lost));
        leg.last_report = (js.played, js.lost);
        let loss_ppm = (missing * 1_000_000).checked_div(played + missing).unwrap_or(0) as u32;
        leg.send(Ctrl::Report { loss_ppm, jitter_ms: js.jitter_ms as u16, bitrate });
        if old_path != path {
            mgr.host.note_connection(peer, &conn);
        }
        if media.since_last_frame().is_some_and(|d| d > MEDIA_TIMEOUT)
            || (media.since_last_frame().is_none() && leg.joined_at.is_some_and(|t| t.elapsed() > MEDIA_TIMEOUT))
        {
            lost.push(*peer);
        }
    }
    for p in lost {
        core.last_leave = Some(EndReason::ConnectionLost);
        leg_done(core, &p, ParticipantState::Left);
    }
    // someone removed from the conversation is out of its call too
    let removed: Vec<SignPk> = core
        .legs
        .iter()
        .filter(|(_, l)| matches!(l.state, LegState::Joined | LegState::Watcher(_)))
        .map(|(p, _)| *p)
        .filter(|p| !mgr.host.may_call(&call.cref.space, p))
        .collect();
    for p in removed {
        if let Some(leg) = core.legs.get(&p) {
            leg.send(Ctrl::Denied);
        }
        leg_done(core, &p, ParticipantState::Left);
    }
}

async fn start_media(mgr: &Arc<Mgr>, call: &Arc<Call>) {
    if call.core.lock().media.is_some() {
        return;
    }
    let audio = mgr.audio.read().clone();
    let sink = mgr.sink.read().clone();
    let (id, muted) = (call.id(), call.muted.load(Ordering::Relaxed));
    let rt = tokio::runtime::Handle::current();
    let started = tokio::task::spawn_blocking(move || Media::start(id, &*audio, muted, sink, rt))
        .await
        .context("audio failed to start")
        .and_then(|r| r);
    let unused = {
        let mut core = call.core.lock();
        match started {
            Ok(media) if core.phase != CallPhase::Ended => {
                let force = mgr.force_stream.load(Ordering::Relaxed);
                for (peer, leg) in core.legs.iter_mut().filter(|(_, l)| l.state == LegState::Joined) {
                    if let Some(conn) = leg.conn.clone() {
                        let bitrate = BitrateController::new(leg.path).bitrate();
                        leg.media = Some(media.add_leg(*peer, conn, bitrate, force));
                    }
                }
                core.media = Some(media);
                None
            }
            Ok(media) => Some(media),
            Err(e) => {
                core.error = Some(format!("{e:#}"));
                end(&mut core, EndReason::Failed);
                None
            }
        }
    };
    if let Some(media) = unused {
        let _ = tokio::task::spawn_blocking(move || drop(media)).await;
    }
}

/// Our ring found a call already going on in the conversation: join that one.
fn join_existing(mgr: &Arc<Mgr>, cref: CallRef, via: SignPk) {
    let _placing = mgr.placing.lock();
    if mgr.calls.lock().contains_key(&cref.call) {
        return;
    }
    let group = mgr.host.members(&cref.space).map(|m| m.len() > 1).unwrap_or(true);
    let call = new_call(mgr, cref, group, Direction::Outgoing, cref.initiator, CallPhase::Connecting);
    let mut core = call.core.lock();
    core.deadline = Some(Instant::now() + SETUP_TIMEOUT);
    let leg = dial(mgr, &call, via, Why::Join, Ctrl::Join { version: VERSION, call: cref });
    core.legs.insert(via, leg);
}

/// Our call lost a glare to `peer`'s. If their ring already came (and was
/// answered at once, replacing ours), the expectation is used up: drop it,
/// or a later call of theirs would be answered without ringing.
fn lost_glare(mgr: &Arc<Mgr>, call: &Call, peer: SignPk) {
    let _placing = mgr.placing.lock();
    let space = call.cref.space;
    let theirs = live_calls(mgr)
        .iter()
        .any(|c| c.cref.space == space && c.cref.initiator == peer && c.dir == Direction::Incoming);
    if theirs {
        mgr.expecting.lock().remove(&(peer, space));
    }
}

/// The call is over: stop audio, tell the app, close the connections, and
/// forget it after a while.
async fn finish(mgr: &Arc<Mgr>, call: &Arc<Call>) {
    let (media, conns) = {
        let mut core = call.core.lock();
        let conns: Vec<Connection> = core.legs.values().filter_map(|l| l.conn.clone()).collect();
        // dropping the legs ends their writers (after the last messages)
        for leg in core.legs.values_mut() {
            leg.media = None;
        }
        (core.media.take(), conns)
    };
    let video = mgr.video.end(&call.id());
    if media.is_some() || video.is_some() {
        let _ = tokio::task::spawn_blocking(move || {
            drop(media);
            if let Some(stop) = video {
                stop();
            }
        })
        .await;
    }
    mgr.host.emit(CallEvent::Updated(info(mgr, call)));
    for conn in conns {
        tokio::spawn(async move {
            // let the last control message get there, then close
            let _ = tokio::time::timeout(Duration::from_millis(500), conn.closed()).await;
            conn.close(0u32.into(), b"bye");
        });
    }
    let (mgr, id) = (mgr.clone(), call.id());
    tokio::spawn(async move {
        tokio::time::sleep(LINGER).await;
        let gone = mgr.calls.lock().remove(&id);
        if let Some(c) = gone {
            c.core.lock().legs.clear();
        }
    });
}

// ─────────────────────────────── status ───────────────────────────────

fn participant_state(leg: Option<&Leg>, in_roster: bool, me_in: bool) -> Option<ParticipantState> {
    use ParticipantState as P;
    let joined_or = |s: P| if in_roster { if me_in { P::Connecting } else { P::Joined } } else { s };
    Some(match leg.map(|l| l.state) {
        Some(LegState::Joined) => P::Joined,
        Some(LegState::Dialing(Why::Join)) => P::Connecting,
        Some(LegState::Dialing(Why::Ring) | LegState::Ringing) => P::Ringing,
        Some(LegState::Watcher(s) | LegState::Done(s)) => joined_or(s),
        Some(LegState::Anchor | LegState::Accepting | LegState::Dialing(Why::Watch)) => joined_or(P::Left),
        None if in_roster => joined_or(P::Left),
        None => return None,
    })
}

fn info(mgr: &Mgr, c: &Call) -> CallInfo {
    let now = Instant::now();
    let me = mgr.me();
    let audio = mgr.audio.read().clone();
    // copy what we need out of the lock (names are looked up after)
    struct Row {
        id: SignPk,
        state: ParticipantState,
        muted: bool,
        level: f32,
        path: Option<PathKind>,
        bitrate: u32,
        rtt_ms: u32,
        loss_pct: f32,
        joined_at: Option<Instant>,
        media: Option<Arc<LegMedia>>,
    }
    let (phase, end_reason, error, connected_at, duration, rows, joined_count, shared, path) = {
        let core = c.core.lock();
        let me_in = in_call(c, core.phase);
        let roster = known_roster(&core, &me);
        let mut ids: BTreeSet<SignPk> = core.legs.keys().copied().collect();
        ids.extend(roster.iter().copied());
        let mut rows = Vec::new();
        for id in ids {
            let leg = core.legs.get(&id);
            let Some(state) = participant_state(leg, roster.contains(&id), me_in) else { continue };
            let media = leg.and_then(|l| l.media.clone());
            rows.push(Row {
                id,
                state,
                muted: leg.is_some_and(|l| l.remote_muted)
                    || media.as_ref().is_some_and(|m| m.remote_muted.load(Ordering::Relaxed)),
                level: media.as_ref().map(|m| m.level()).unwrap_or(0.0),
                path: leg.and_then(|l| l.path.or_else(|| l.conn.as_ref().and_then(|c| selected_path(c).0))),
                bitrate: media.as_ref().map(|m| m.bitrate.load(Ordering::Relaxed)).unwrap_or(0),
                rtt_ms: leg.map(|l| l.rtt_ms).unwrap_or(0),
                loss_pct: leg.map(|l| l.remote_loss * 100.0).unwrap_or(0.0),
                joined_at: leg.and_then(|l| l.joined_at),
                media,
            });
        }
        let joined_count = roster.len() as u32 + u32::from(me_in);
        let duration = match core.active_at {
            Some(a) => core.ended_at.unwrap_or(now).saturating_duration_since(a),
            None => Duration::ZERO,
        };
        // the leg that stands for "the call" in 1:1 terms: the first we
        // talked to, else whichever leg there is
        let path = core
            .legs
            .values()
            .filter(|l| l.state == LegState::Joined)
            .min_by_key(|l| l.joined_at)
            .or_else(|| core.legs.values().find(|l| l.live()))
            .and_then(|l| l.path);
        (
            core.phase,
            core.end,
            core.error.clone(),
            core.connected_at,
            duration,
            rows,
            joined_count,
            core.media.as_ref().map(|m| m.shared().clone()),
            path,
        )
    };
    let mut participants: Vec<Participant> = rows
        .iter()
        .map(|r| Participant {
            id: hex(&r.id.0),
            name: c.name(mgr, &r.id),
            state: r.state,
            muted: r.muted,
            level: r.level,
            speaking: r.state == ParticipantState::Joined && !r.muted && r.level > SPEAKING,
            path: r.path,
            bitrate: r.bitrate,
            rtt_ms: r.rtt_ms,
            loss_pct: r.loss_pct,
            video: mgr.video.peer(&c.id(), &r.id),
        })
        .collect();
    let rank = |s: ParticipantState| match s {
        ParticipantState::Joined => 0,
        ParticipantState::Connecting => 1,
        ParticipantState::Ringing => 2,
        _ => 3,
    };
    participants.sort_by(|a, b| rank(a.state).cmp(&rank(b.state)).then_with(|| a.name.cmp(&b.name)));
    let active_speaker =
        participants.iter().filter(|p| p.speaking).max_by(|a, b| a.level.total_cmp(&b.level)).map(|p| p.id.clone());
    let primary = rows.iter().filter(|r| r.media.is_some()).min_by_key(|r| r.joined_at);

    let mut stats = CallStats { audio_device: audio.describe(), ..Default::default() };
    let (mut level, mut remote_level, mut remote_muted, mut bitrate) = (0.0, 0.0, false, 0);
    if let Some(r) = primary {
        let m = r.media.as_ref().expect("filtered");
        let js = m.jitter_stats();
        stats.rtt_ms = r.rtt_ms;
        stats.loss_pct = r.loss_pct;
        stats.jitter_ms = js.jitter_ms;
        stats.buffer_ms = js.depth_ms;
        stats.frames_sent = m.frames_sent.load(Ordering::Relaxed);
        stats.frames_received = js.received;
        stats.frames_lost = js.lost;
        stats.frames_late = js.late;
        stats.transport = if m.stream_mode.load(Ordering::Relaxed) { "stream" } else { "datagram" }.into();
        // one way + jitter buffer + one frame + device/playout buffering (~35 ms)
        stats.latency_ms = stats.rtt_ms / 2 + js.depth_ms.max(js.target_ms) + 20 + 35;
        bitrate = r.bitrate;
        remote_muted = r.muted;
    }
    if let Some(s) = &shared {
        let d = audio.diagnostics();
        stats.heard_tone_hz = d.heard_tone_hz;
        stats.measured_round_trip_ms = d.measured_round_trip_ms;
        if phase == CallPhase::Active {
            level = s.mic_level();
            remote_level = s.out_level();
        }
    }
    CallInfo {
        id: hex(&c.id().0),
        conversation: c.cref.space.to_string(),
        group: c.group,
        title: c.title.clone(),
        peer: hex(&c.peer.0),
        peer_name: if c.peer == me { "You".into() } else { c.name(mgr, &c.peer) },
        direction: c.dir,
        state: phase,
        end_reason,
        error,
        started_at: c.started_at,
        connected_at,
        duration_ms: duration.as_millis() as u64,
        participants,
        joined_count,
        active_speaker,
        path,
        bitrate,
        muted: c.muted.load(Ordering::Relaxed),
        remote_muted,
        level,
        remote_level,
        echo_cancellation: audio.echo_cancellation(),
        stats,
        video: mgr.video.info(&c.id(), phase != CallPhase::Ended),
    }
}
