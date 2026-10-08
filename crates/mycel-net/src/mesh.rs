//! Mesh: multi-hop relaying between devices that have no direct link.
//!
//! A and C are out of each other's radio range but both are near B: A's QUIC
//! packets for C travel A → B → C, and B never needs to be a member of
//! anything A and C share. It can't read them either: what it forwards are
//! the QUIC packets of A's connection *to C*, encrypted end to end with keys
//! only A and C hold. No server, no coordinator: every device is a router.
//!
//! **Link-agnostic.** A hop is a QUIC connection (ALPN [`ALPN`]) between two
//! neighbours, so it runs over whatever direct paths they have: same
//! network, peer-to-peer Wi-Fi, Bluetooth, or any link added later. That
//! hop connection is itself multipath: a relay uses the best of its links to
//! the next device, and moves when one dies. Mesh frames are QUIC datagrams
//! on it (unreliable and unordered, like IP: the end-to-end QUIC connection
//! does loss recovery and congestion control).
//!
//! **To Iroh the mesh is one more custom transport** ([`TRANSPORT_MESH`],
//! `PathKind::Mesh`). An address names a destination *and a waypoint*: the
//! neighbour the packet leaves through, which also routes the replies
//! (`mesh(C, via B)`). Each route to C is a distinct address, so Iroh opens
//! one QUIC path per route, each with its own RTT, congestion window and
//! failover, and the path selector aggregates comparable routes exactly as it
//! does direct links. Up to [`MeshOptions::routes`] routes (through distinct
//! neighbours) are kept per destination.
//!
//! **Routing** is a distance-vector protocol in the style of B.A.T.M.A.N.
//! (originator messages): every device periodically floods a small
//! *announcement* (origin key, sequence number, name) signed with its device
//! key; each device rebroadcasts each announcement once (the best copy it
//! heard, after a short jitter) with the path cost added, never back to
//! where its best copy came from (split horizon). A device routes to C via
//! the neighbour that delivered C's cheapest fresh announcement. The cost of
//! a hop is the hop connection's *measured* RTT plus a small per-hop penalty:
//! no link types are hard-coded, so new hardware ranks itself. Forged
//! announcements are rejected (the origin's signature), stale ones expire
//! (sequence numbers are milliseconds since the epoch; a device's routes die
//! a few announcement periods after it goes silent).
//!
//! **Loops and storms**: a TTL on every frame, split horizon for data and
//! announcements, each announcement rebroadcast at most once per sequence
//! number, and announcements rate-limited per neighbour.
//!
//! **Relaying for others** is on by default and capped per neighbour and in
//! total ([`MeshOptions`]); a device can turn it off and still use the mesh.
//!
//! A direct path always beats the mesh: a device with a direct link to C
//! gets no mesh addresses for C, and the mesh refuses to carry packets to a
//! neighbour. That also guarantees hop connections never run over the mesh
//! themselves.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::Connection;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use mycel_crypto::{DeviceKeys, Sig, SignPk};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::link::{CustomAddr, Link, LinkEvent, LinkStatus, PathKind, TRANSPORT_MESH, n0_watcher, noq_udp};

/// Hop connections between neighbours.
pub const ALPN: &[u8] = b"mycel/mesh/0";

/// Sees each payload a device relays (tests).
pub type Tap = Arc<dyn Fn(&[u8]) + Send + Sync>;

const OGM_CTX: &str = "mycel/v0/mesh-announce";
const T_OGM: u8 = 1;
const T_DATA: u8 = 2;
/// Data frame header: type, ttl, flags, dst, src, waypoint, id, offset, total.
const DATA_HDR: usize = 3 + 32 * 3 + 4 + 2 + 2;
const F_REACHED: u8 = 1;
/// QUIC's minimum MTU, and the largest packet the mesh carries: bigger ones
/// (MTU probes) are dropped, so end-to-end connections stay at 1200 bytes.
/// A hop's own MTU varies (it falls back to 1200 after loss); a 1200-byte
/// packet always gets through, whole or in two fragments, where a larger
/// one would be lost for good until the end-to-end path re-learnt its MTU.
const MIN_QUIC_MTU: usize = 1200;
const MAX_NAME: usize = 32;
/// Announcements more than this far from our clock are ignored (replays).
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
/// Cost units are 0.1 ms; each hop adds this on top of its RTT, so among
/// equally fast routes the shorter wins.
const HOP_PENALTY: u32 = 20;
/// A neighbour's hop cost before its RTT is measured.
const DEFAULT_COST: u32 = 100;
/// Routes much costlier than the best one aren't worth a QUIC path.
const ROUTE_COST_FACTOR: u32 = 4;
const ROUTE_COST_SLACK: u32 = 300;
/// A route already in use counts as this much cheaper (no flapping).
const STICKY_PERCENT: u32 = 80;
/// Each neighbour may send us this many announcements per second (burst 4×).
const OGM_RATE: f64 = 100.0;
const REASM_TIMEOUT: Duration = Duration::from_secs(2);
const REASM_MAX: usize = 256;
const INBOX: usize = 4096;
/// Datagrams queued on a hop (waiting for its congestion window) beyond
/// 1/[QUEUE_CWND_DIV] of that window, or this many bytes if more, are dropped
/// from the tail. A short queue keeps relayed traffic's delay down and lets
/// the end-to-end connection see congestion early (1/4 and a full window
/// were measured too: more variable throughput across two routes).
const MIN_QUEUE: usize = 16 * 1024;
const QUEUE_CWND_DIV: usize = 8;
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
/// The higher key dials only if the lower one hasn't after this long.
const DIAL_DEFER: Duration = Duration::from_secs(2);

/// How a device takes part in the mesh.
#[derive(Clone, Debug)]
pub struct MeshOptions {
    /// Forward other devices' traffic (it stays unreadable to us). Off: we
    /// still reach others through the mesh, but nobody routes through us.
    pub relay: bool,
    /// Bytes per second relayed for traffic arriving from one neighbour.
    pub relay_rate_per_neighbour: u64,
    /// Bytes per second relayed in total.
    pub relay_rate_total: u64,
    /// Routes (QUIC paths, through distinct neighbours) kept per destination.
    pub routes: usize,
    /// Hops a frame or an announcement may travel.
    pub max_hops: u8,
    /// How often this device announces itself.
    pub announce_every: Duration,
}

impl Default for MeshOptions {
    fn default() -> Self {
        MeshOptions {
            relay: true,
            relay_rate_per_neighbour: 1 << 20,
            relay_rate_total: 4 << 20,
            routes: 3,
            max_hops: 8,
            announce_every: Duration::from_secs(2),
        }
    }
}

/// How a peer is reached through the mesh, for the Network panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshRoute {
    /// The neighbour the route leaves through.
    pub via: SignPk,
    pub via_name: Option<String>,
    /// Hops to the destination (2 = one device in between).
    pub hops: u8,
}

/// Counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeshStats {
    pub announcements_sent: u64,
    pub announcements_received: u64,
    /// Bad signature, or claiming to be from us.
    pub announcements_forged: u64,
    /// Too far from our clock, or older than what we have.
    pub announcements_stale: u64,
    /// Over a neighbour's announcement rate.
    pub announcements_limited: u64,
    pub frames_sent: u64,
    pub frames_delivered: u64,
    /// Transit frames forwarded for others, and their bytes.
    pub frames_relayed: u64,
    pub bytes_relayed: u64,
    pub dropped_budget: u64,
    pub dropped_ttl: u64,
    pub dropped_no_route: u64,
    pub dropped_queue: u64,
    pub dropped_too_big: u64,
    pub dropped_not_relaying: u64,
    pub hop_connections: u64,
}

#[derive(Default)]
struct Counters {
    announcements_sent: AtomicU64,
    announcements_received: AtomicU64,
    announcements_forged: AtomicU64,
    announcements_stale: AtomicU64,
    announcements_limited: AtomicU64,
    frames_sent: AtomicU64,
    frames_delivered: AtomicU64,
    frames_relayed: AtomicU64,
    bytes_relayed: AtomicU64,
    dropped_budget: AtomicU64,
    dropped_ttl: AtomicU64,
    dropped_no_route: AtomicU64,
    dropped_queue: AtomicU64,
    dropped_too_big: AtomicU64,
    dropped_not_relaying: AtomicU64,
    hop_connections: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// A device's mesh address for `dst`, leaving through (and answered via)
/// `waypoint`.
pub fn mesh_addr(dst: &SignPk, waypoint: &SignPk) -> CustomAddr {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&dst.0);
    data[32..].copy_from_slice(&waypoint.0);
    CustomAddr::from_parts(TRANSPORT_MESH, &data)
}

/// `(destination, waypoint)` of a mesh address.
pub fn parse_mesh_addr(a: &CustomAddr) -> Option<(SignPk, SignPk)> {
    if a.id() != TRANSPORT_MESH || a.data().len() != 64 {
        return None;
    }
    let d = a.data();
    Some((SignPk(d[..32].try_into().ok()?), SignPk(d[32..].try_into().ok()?)))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn to_sign_pk(id: &iroh::EndpointId) -> SignPk {
    SignPk(*id.as_bytes())
}

/// Bytes-per-second token bucket (burst = one second).
#[derive(Debug)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: f64, burst: f64) -> Self {
        Bucket { rate, burst, tokens: burst, at: Instant::now() }
    }

    fn take(&mut self, n: f64, now: Instant) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * self.rate).min(self.burst);
        self.at = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────── wire ───────────────────────────────

/// An originator announcement. `origin`, `seq` and `name` are signed by the
/// origin; `hops` and `cost` are filled in by each device that passes it on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Announce {
    hops: u8,
    cost: u32,
    origin: SignPk,
    seq: u64,
    name: String,
    sig: Sig,
}

impl Announce {
    fn signed(keys: &DeviceKeys, seq: u64, name: &str) -> Announce {
        let name = truncate(name, MAX_NAME);
        let origin = keys.sign_pk();
        let sig = keys.sign(OGM_CTX, &[&origin.0, &seq.to_be_bytes(), name.as_bytes()]);
        Announce { hops: 0, cost: 0, origin, seq, name, sig }
    }

    fn verify(&self) -> bool {
        self.origin
            .verify(OGM_CTX, &[&self.origin.0, &self.seq.to_be_bytes(), self.name.as_bytes()], &self.sig)
            .is_ok()
    }

    fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(1 + 1 + 4 + 32 + 8 + 1 + self.name.len() + 64);
        b.put_u8(T_OGM);
        b.put_u8(self.hops);
        b.put_u32(self.cost);
        b.put_slice(&self.origin.0);
        b.put_u64(self.seq);
        b.put_u8(self.name.len() as u8);
        b.put_slice(self.name.as_bytes());
        b.put_slice(&self.sig.0);
        b.freeze()
    }

    fn decode(b: &[u8]) -> Option<Announce> {
        if b.len() < 1 + 1 + 4 + 32 + 8 + 1 + 64 || b[0] != T_OGM {
            return None;
        }
        let hops = b[1];
        let cost = u32::from_be_bytes(b[2..6].try_into().ok()?);
        let origin = SignPk(b[6..38].try_into().ok()?);
        let seq = u64::from_be_bytes(b[38..46].try_into().ok()?);
        let n = b[46] as usize;
        if n > MAX_NAME || b.len() != 47 + n + 64 {
            return None;
        }
        let name = String::from_utf8(b[47..47 + n].to_vec()).ok()?;
        let sig = Sig(b[47 + n..].try_into().ok()?);
        Some(Announce { hops, cost, origin, seq, name, sig })
    }
}

fn truncate(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// One QUIC packet (or a fragment of one) on its way to `dst`.
#[derive(Clone, Debug)]
struct Frame {
    ttl: u8,
    /// The waypoint has been passed; now heading for `dst`.
    reached: bool,
    dst: SignPk,
    src: SignPk,
    waypoint: SignPk,
    /// Per-source packet number (fragments share it).
    id: u32,
    /// Where `payload` starts in the whole packet, and the packet's length.
    offset: u16,
    total: u16,
    payload: Bytes,
}

impl Frame {
    fn header(&self, offset: u16, b: &mut BytesMut) {
        b.put_u8(T_DATA);
        b.put_u8(self.ttl);
        b.put_u8(if self.reached { F_REACHED } else { 0 });
        b.put_slice(&self.dst.0);
        b.put_slice(&self.src.0);
        b.put_slice(&self.waypoint.0);
        b.put_u32(self.id);
        b.put_u16(offset);
        b.put_u16(self.total);
    }

    /// Encoded datagrams of at most `max` bytes each, or `None` if it
    /// can't (or shouldn't) be split to fit.
    fn encode(&self, max: usize) -> Option<Vec<Bytes>> {
        let room = max.checked_sub(DATA_HDR)?;
        if self.payload.len() <= room {
            let mut b = BytesMut::with_capacity(DATA_HDR + self.payload.len());
            self.header(self.offset, &mut b);
            b.put_slice(&self.payload);
            return Some(vec![b.freeze()]);
        }
        if self.total as usize > MIN_QUIC_MTU || room < 64 {
            return None;
        }
        Some(
            self.payload
                .chunks(room)
                .enumerate()
                .map(|(i, chunk)| {
                    let mut b = BytesMut::with_capacity(DATA_HDR + chunk.len());
                    self.header(self.offset + (i * room) as u16, &mut b);
                    b.put_slice(chunk);
                    b.freeze()
                })
                .collect(),
        )
    }

    fn decode(b: Bytes) -> Option<Frame> {
        if b.len() < DATA_HDR || b[0] != T_DATA {
            return None;
        }
        let pk = |at: usize| -> Option<SignPk> { Some(SignPk(b[at..at + 32].try_into().ok()?)) };
        let frame = Frame {
            ttl: b[1],
            reached: b[2] & F_REACHED != 0,
            dst: pk(3)?,
            src: pk(35)?,
            waypoint: pk(67)?,
            id: u32::from_be_bytes(b[99..103].try_into().ok()?),
            offset: u16::from_be_bytes(b[103..105].try_into().ok()?),
            total: u16::from_be_bytes(b[105..107].try_into().ok()?),
            payload: b.slice(DATA_HDR..),
        };
        (frame.offset as usize + frame.payload.len() <= frame.total as usize).then_some(frame)
    }
}

// ─────────────────────────────── state ───────────────────────────────

struct Neighbour {
    /// Seen directly (a link or the LAN), as opposed to only connected.
    direct: bool,
    direct_since: Instant,
    conn: Option<Connection>,
    /// Largest datagram buffer space seen = the buffer's size.
    dgram_cap: usize,
    /// Hop cost (0.1 ms units, smoothed RTT).
    cost: u32,
    budget: Bucket,
    ogm_budget: Bucket,
    dialing: bool,
    next_dial: Instant,
    failures: u32,
}

impl Neighbour {
    fn new(opts: &MeshOptions, now: Instant) -> Self {
        let rate = opts.relay_rate_per_neighbour as f64;
        Neighbour {
            direct: false,
            direct_since: now,
            conn: None,
            dgram_cap: 0,
            cost: 0,
            budget: Bucket::new(rate, rate),
            ogm_budget: Bucket::new(OGM_RATE, OGM_RATE * 4.0),
            dialing: false,
            next_dial: now,
            failures: 0,
        }
    }

    fn live(&self) -> Option<&Connection> {
        self.conn.as_ref().filter(|c| c.close_reason().is_none())
    }

    fn hop_cost(&self) -> u32 {
        (if self.cost == 0 { DEFAULT_COST } else { self.cost }) + HOP_PENALTY
    }
}

/// What we heard about one origin through one neighbour.
#[derive(Clone, Copy, Debug)]
struct Via {
    seq: u64,
    cost: u32,
    hops: u8,
    at: Instant,
}

struct Origin {
    newest: u64,
    /// The newest announcement itself (forwarded with our cost added).
    latest: Announce,
    via: HashMap<SignPk, Via>,
    /// Newest sequence number we have passed on.
    forwarded: u64,
    /// When to pass on the newest one.
    pending: Option<Instant>,
}

struct Reasm {
    buf: Vec<u8>,
    got: usize,
    at: Instant,
    waypoint: SignPk,
}

struct State {
    neighbours: HashMap<SignPk, Neighbour>,
    origins: HashMap<SignPk, Origin>,
    /// Waypoints we gave Iroh for each destination.
    published: HashMap<SignPk, Vec<SignPk>>,
    reasm: HashMap<(SignPk, u32), Reasm>,
    verified: HashSet<(SignPk, u64)>,
    total_budget: Bucket,
}

impl State {
    fn is_neighbour(&self, pk: &SignPk) -> bool {
        self.neighbours.get(pk).is_some_and(|n| n.direct || n.live().is_some())
    }

    /// Fresh routes to `origin`: (neighbour, via), cheapest first.
    fn routes(&self, origin: &SignPk, window: u64, timeout: Duration, now: Instant) -> Vec<(SignPk, Via)> {
        let Some(o) = self.origins.get(origin) else { return Vec::new() };
        let mut v: Vec<(SignPk, Via)> = o
            .via
            .iter()
            .filter(|(n, via)| {
                via.seq + window >= o.newest
                    && now.duration_since(via.at) < timeout
                    && self.neighbours.get(*n).is_some_and(|n| n.live().is_some())
            })
            .map(|(n, via)| (*n, *via))
            .collect();
        v.sort_by_key(|(n, via)| (via.cost, n.0));
        v
    }
}

struct Core {
    keys: Arc<DeviceKeys>,
    me: SignPk,
    opts: MeshOptions,
    name: Mutex<String>,
    st: Mutex<State>,
    endpoint: std::sync::OnceLock<Endpoint>,
    events: std::sync::OnceLock<mpsc::UnboundedSender<LinkEvent>>,
    inbox: mpsc::Sender<(Bytes, CustomAddr)>,
    inbox_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(Bytes, CustomAddr)>>>,
    counters: Counters,
    next_id: AtomicU32,
    seq: AtomicU64,
    stopped: AtomicBool,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    tap: Mutex<Option<Tap>>,
}

impl Core {
    /// Sequence numbers live this long (announcement periods) ...
    fn window_ms(&self) -> u64 {
        self.opts.announce_every.as_millis() as u64 * 3
    }

    /// ... and a route without a fresh announcement dies after this.
    fn route_timeout(&self) -> Duration {
        self.opts.announce_every * 7 / 2
    }

    /// Remember a task so `stop` can end it (dropping finished ones).
    fn keep(&self, task: tokio::task::JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
    }

    fn send_event(&self, ev: LinkEvent) {
        if let Some(tx) = self.events.get() {
            let _ = tx.send(ev);
        }
    }

    // ───────────── neighbours ─────────────

    fn set_direct(self: &Arc<Self>, peer: SignPk, direct: bool) {
        if peer == self.me {
            return;
        }
        let now = Instant::now();
        {
            let mut st = self.st.lock();
            let opts = &self.opts;
            if direct {
                let n = st.neighbours.entry(peer).or_insert_with(|| Neighbour::new(opts, now));
                if !n.direct {
                    n.direct = true;
                    n.direct_since = now;
                    n.next_dial = now;
                    n.failures = 0;
                }
            } else if let Some(n) = st.neighbours.get_mut(&peer) {
                n.direct = false;
                if n.live().is_none() {
                    st.neighbours.remove(&peer);
                }
            }
        }
        self.publish();
    }

    /// A hop connection is up (dialed or accepted).
    fn add_conn(self: &Arc<Self>, conn: Connection) {
        let peer = to_sign_pk(&conn.remote_id());
        if peer == self.me {
            return;
        }
        let now = Instant::now();
        {
            let mut st = self.st.lock();
            let n = st.neighbours.entry(peer).or_insert_with(|| Neighbour::new(&self.opts, now));
            if let Some(old) = n.live() {
                // Both dialed at once: keep the connection the lower key
                // opened (both sides agree on which that is).
                if self.lower_dialed(old) || !self.lower_dialed(&conn) {
                    conn.close(0u32.into(), b"duplicate");
                    return;
                }
                old.close(0u32.into(), b"duplicate");
            }
            n.conn = Some(conn.clone());
            n.dgram_cap = conn.datagram_send_buffer_space();
            n.failures = 0;
        }
        bump(&self.counters.hop_connections);
        self.publish(); // a neighbour gets no mesh addresses
        self.announce_to(&peer);
        let me = self.clone();
        let task = tokio::spawn(async move {
            while let Ok(d) = conn.read_datagram().await {
                if me.stopped.load(Ordering::Relaxed) {
                    break;
                }
                me.on_datagram(peer, d);
            }
            me.conn_closed(peer, &conn);
        });
        self.keep(task);
    }

    fn lower_dialed(&self, conn: &Connection) -> bool {
        let peer = to_sign_pk(&conn.remote_id());
        let we_dialed = conn.side().is_client();
        we_dialed == (self.me < peer)
    }

    fn conn_closed(self: &Arc<Self>, peer: SignPk, conn: &Connection) {
        {
            let mut st = self.st.lock();
            let Some(n) = st.neighbours.get_mut(&peer) else { return };
            if n.conn.as_ref().is_none_or(|c| c.stable_id() != conn.stable_id()) {
                return; // a replaced duplicate
            }
            n.conn = None;
            n.failures += 1;
            n.next_dial = Instant::now() + Duration::from_secs((1u64 << n.failures.min(5)).min(30));
            if !n.direct {
                st.neighbours.remove(&peer);
            }
            for o in st.origins.values_mut() {
                o.via.remove(&peer);
            }
        }
        self.publish();
    }

    /// Dial direct neighbours we have no hop connection to.
    fn dial_missing(self: &Arc<Self>) {
        let Some(ep) = self.endpoint.get().cloned() else { return };
        let now = Instant::now();
        let mut todo = Vec::new();
        {
            let mut st = self.st.lock();
            for (pk, n) in st.neighbours.iter_mut() {
                let ours = self.me < *pk || now.duration_since(n.direct_since) >= DIAL_DEFER;
                if n.direct && n.live().is_none() && !n.dialing && now >= n.next_dial && ours {
                    n.dialing = true;
                    todo.push(*pk);
                }
            }
        }
        for pk in todo {
            let (me, ep) = (self.clone(), ep.clone());
            let task = tokio::spawn(async move {
                let res = match iroh::PublicKey::from_bytes(&pk.0) {
                    Ok(id) => tokio::time::timeout(DIAL_TIMEOUT, ep.connect(EndpointAddr::new(id), ALPN)).await.ok(),
                    Err(_) => None,
                };
                let ok = matches!(res, Some(Ok(_)));
                {
                    let mut st = me.st.lock();
                    if let Some(n) = st.neighbours.get_mut(&pk) {
                        n.dialing = false;
                        if !ok {
                            n.failures += 1;
                            n.next_dial = Instant::now() + Duration::from_secs((1u64 << n.failures.min(5)).min(30));
                        }
                    }
                }
                if let Some(Ok(conn)) = res {
                    me.add_conn(conn);
                }
            });
            self.keep(task);
        }
    }

    /// Hop cost: each hop connection's measured RTT, smoothed.
    fn measure(&self) {
        let mut st = self.st.lock();
        for n in st.neighbours.values_mut() {
            let Some(conn) = n.live() else { continue };
            let rtt = conn.paths().iter().find(|p| p.is_selected()).map(|p| p.rtt());
            let Some(rtt) = rtt.filter(|r| !r.is_zero()) else { continue };
            let units = (rtt.as_micros() / 100).clamp(1, u32::MAX as u128 / 2) as u32;
            n.cost = if n.cost == 0 { units } else { (n.cost * 7 + units) / 8 };
        }
    }

    // ───────────── announcements ─────────────

    fn own_announce(&self) -> Announce {
        let seq = loop {
            let last = self.seq.load(Ordering::SeqCst);
            let next = now_ms().max(last + 1);
            if self.seq.compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                break next;
            }
        };
        Announce::signed(&self.keys, seq, &self.name.lock())
    }

    fn announce_all(&self) {
        let a = self.own_announce().encode();
        let conns: Vec<Connection> = self.st.lock().neighbours.values().filter_map(|n| n.live().cloned()).collect();
        for c in conns {
            if c.send_datagram(a.clone()).is_ok() {
                bump(&self.counters.announcements_sent);
            }
        }
    }

    fn announce_to(&self, peer: &SignPk) {
        let a = self.own_announce().encode();
        let conn = self.st.lock().neighbours.get(peer).and_then(|n| n.live().cloned());
        if let Some(c) = conn
            && c.send_datagram(a).is_ok()
        {
            bump(&self.counters.announcements_sent);
        }
    }

    fn on_announce(&self, from: SignPk, a: Announce) {
        let now = Instant::now();
        let mut st = self.st.lock();
        let Some(n) = st.neighbours.get_mut(&from) else { return };
        if !n.ogm_budget.take(1.0, now) {
            bump(&self.counters.announcements_limited);
            return;
        }
        let hop_cost = n.hop_cost();
        bump(&self.counters.announcements_received);
        if a.origin == self.me {
            return; // our own, echoed back
        }
        let clock = now_ms();
        if a.seq > clock + MAX_CLOCK_SKEW_MS || a.seq + MAX_CLOCK_SKEW_MS < clock {
            bump(&self.counters.announcements_stale);
            return;
        }
        let window = self.window_ms();
        if st.origins.get(&a.origin).is_some_and(|o| a.seq + window < o.newest) {
            bump(&self.counters.announcements_stale);
            return;
        }
        if !st.verified.contains(&(a.origin, a.seq)) {
            if !a.verify() {
                bump(&self.counters.announcements_forged);
                return;
            }
            if st.verified.len() > 4096 {
                st.verified.clear();
            }
            st.verified.insert((a.origin, a.seq));
        }
        let hops = a.hops.saturating_add(1);
        if hops > self.opts.max_hops {
            return;
        }
        let cost = a.cost.saturating_add(hop_cost);
        let relay = self.opts.relay;
        let max_hops = self.opts.max_hops;
        let o = st.origins.entry(a.origin).or_insert_with(|| Origin {
            newest: 0,
            latest: a.clone(),
            via: HashMap::new(),
            forwarded: 0,
            pending: None,
        });
        if a.seq > o.newest {
            o.newest = a.seq;
            o.latest = a.clone();
        }
        o.via.insert(from, Via { seq: a.seq, cost, hops, at: now });
        if relay && a.seq == o.newest && a.seq > o.forwarded && o.pending.is_none() && hops < max_hops {
            // wait a little to hear the cheapest copy, and desynchronize
            let jitter = 10 + mycel_crypto::random_u64() % 40;
            o.pending = Some(now + Duration::from_millis(jitter));
        }
    }

    /// Pass on the announcements whose jitter has run out: once per
    /// sequence number, with our best cost, not back where it came from.
    fn flush_announcements(&self) {
        let now = Instant::now();
        let mut out: Vec<(Connection, Bytes)> = Vec::new();
        {
            let mut st = self.st.lock();
            let due: Vec<SignPk> = st
                .origins
                .iter()
                .filter(|(_, o)| o.pending.is_some_and(|t| t <= now))
                .map(|(k, _)| *k)
                .collect();
            for origin in due {
                let Some(o) = st.origins.get_mut(&origin) else { continue };
                o.pending = None;
                let newest = o.newest;
                let best = o
                    .via
                    .iter()
                    .filter(|(_, v)| v.seq == newest)
                    .min_by_key(|(n, v)| (v.cost, n.0))
                    .map(|(n, v)| (*n, *v));
                let Some((from, via)) = best else { continue };
                o.forwarded = newest;
                let mut a = o.latest.clone();
                a.hops = via.hops;
                a.cost = via.cost;
                let bytes = a.encode();
                for (pk, n) in &st.neighbours {
                    if *pk == from || *pk == origin {
                        continue;
                    }
                    if let Some(c) = n.live() {
                        out.push((c.clone(), bytes.clone()));
                    }
                }
            }
        }
        for (c, b) in out {
            if c.send_datagram(b).is_ok() {
                bump(&self.counters.announcements_sent);
            }
        }
    }

    fn expire(&self) {
        let now = Instant::now();
        let timeout = self.route_timeout();
        let mut st = self.st.lock();
        st.origins.retain(|_, o| {
            o.via.retain(|_, v| now.duration_since(v.at) < timeout);
            !o.via.is_empty()
        });
        st.reasm.retain(|_, r| now.duration_since(r.at) < REASM_TIMEOUT);
    }

    /// Tell Iroh which mesh addresses each destination has: up to
    /// `routes`, through distinct neighbours, none for neighbours.
    fn publish(&self) {
        let now = Instant::now();
        let mut events = Vec::new();
        {
            let mut st = self.st.lock();
            let mut want: HashMap<SignPk, Vec<SignPk>> = HashMap::new();
            for origin in st.origins.keys() {
                if *origin == self.me || st.is_neighbour(origin) {
                    continue;
                }
                let current = st.published.get(origin);
                let mut routes = st.routes(origin, self.window_ms(), self.route_timeout(), now);
                let Some(best) = routes.first().map(|(_, v)| v.cost) else { continue };
                let limit = best.saturating_mul(ROUTE_COST_FACTOR).saturating_add(ROUTE_COST_SLACK);
                routes.retain(|(_, v)| v.cost <= limit);
                let sticky = |n: &SignPk, c: u32| {
                    if current.is_some_and(|ws| ws.contains(n)) { (c as u64 * STICKY_PERCENT as u64 / 100) as u32 } else { c }
                };
                routes.sort_by_key(|(n, v)| (sticky(n, v.cost), n.0));
                routes.truncate(self.opts.routes.max(1));
                want.insert(*origin, routes.into_iter().map(|(n, _)| n).collect());
            }
            for (dst, ws) in &st.published {
                let keep = want.get(dst);
                for w in ws {
                    if keep.is_none_or(|k| !k.contains(w)) {
                        events.push(LinkEvent::Lost { peer: *dst, addr: mesh_addr(dst, w) });
                    }
                }
            }
            for (dst, ws) in &want {
                let had = st.published.get(dst);
                let name = st.origins.get(dst).map(|o| o.latest.name.clone()).filter(|n| !n.is_empty());
                for w in ws {
                    if had.is_none_or(|h| !h.contains(w)) {
                        events.push(LinkEvent::Found { peer: *dst, addr: mesh_addr(dst, w), name: name.clone() });
                    }
                }
            }
            st.published = want;
        }
        for e in events {
            self.send_event(e);
        }
    }

    // ───────────── data ─────────────

    fn on_datagram(self: &Arc<Self>, from: SignPk, d: Bytes) {
        match d.first() {
            Some(&T_OGM) => {
                if let Some(a) = Announce::decode(&d) {
                    self.on_announce(from, a);
                }
            }
            Some(&T_DATA) => {
                if let Some(f) = Frame::decode(d) {
                    let mut st = self.st.lock();
                    self.route(&mut st, f, Some(from));
                }
            }
            _ => {}
        }
    }

    /// A QUIC packet from our endpoint for `dst`, through `waypoint`.
    fn send_local(&self, dst: SignPk, waypoint: SignPk, packet: &[u8]) {
        if packet.len() > MIN_QUIC_MTU {
            bump(&self.counters.dropped_too_big);
            return;
        }
        let mut st = self.st.lock();
        // A direct path always wins; this also keeps hop connections (which
        // only exist between neighbours) off the mesh.
        if st.is_neighbour(&dst) {
            bump(&self.counters.dropped_no_route);
            return;
        }
        let f = Frame {
            ttl: self.opts.max_hops,
            reached: false,
            dst,
            src: self.me,
            waypoint,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            offset: 0,
            total: packet.len() as u16,
            payload: Bytes::copy_from_slice(packet),
        };
        bump(&self.counters.frames_sent);
        self.route(&mut st, f, None);
    }

    /// Deliver, or pass `f` one hop on. `from` is the neighbour it came
    /// from (`None`: we are the source).
    fn route(&self, st: &mut State, mut f: Frame, from: Option<SignPk>) {
        if !f.reached && f.waypoint == self.me {
            f.reached = true;
        }
        if f.dst == self.me {
            self.deliver(st, f);
            return;
        }
        if f.src == self.me && from.is_some() {
            return; // our own packet came back: a loop
        }
        let target = if f.reached { f.dst } else { f.waypoint };
        let next = self.next_hop(st, &target, from.as_ref());
        let Some(next) = next else {
            bump(&self.counters.dropped_no_route);
            return;
        };
        let now = Instant::now();
        if let Some(from) = from {
            if !self.opts.relay {
                bump(&self.counters.dropped_not_relaying);
                return;
            }
            if f.ttl <= 1 {
                bump(&self.counters.dropped_ttl);
                return;
            }
            f.ttl -= 1;
            let len = f.payload.len() as f64;
            let neighbour_ok = st.neighbours.get_mut(&from).is_some_and(|n| n.budget.take(len, now));
            if !neighbour_ok || !st.total_budget.take(len, now) {
                bump(&self.counters.dropped_budget);
                return;
            }
            bump(&self.counters.frames_relayed);
            self.counters.bytes_relayed.fetch_add(f.payload.len() as u64, Ordering::Relaxed);
            if let Some(tap) = self.tap.lock().clone() {
                tap(&f.payload);
            }
        }
        let Some(n) = st.neighbours.get_mut(&next) else { return };
        let Some(conn) = n.live().cloned() else { return };
        let Some(max) = conn.max_datagram_size() else {
            bump(&self.counters.dropped_too_big);
            return;
        };
        let Some(datagrams) = f.encode(max) else {
            bump(&self.counters.dropped_too_big);
            return;
        };
        // Tail-drop beyond a fraction of the hop's congestion window queued,
        // so a slow hop doesn't build seconds of delay.
        let space = conn.datagram_send_buffer_space();
        n.dgram_cap = n.dgram_cap.max(space);
        let queued = n.dgram_cap - space;
        let cwnd = conn
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .and_then(|p| conn.congestion_state(p.id()))
            .map_or(0, |c| c.window() as usize);
        let bytes: usize = datagrams.iter().map(|d| d.len()).sum();
        if queued + bytes > (cwnd / QUEUE_CWND_DIV).max(MIN_QUEUE) {
            bump(&self.counters.dropped_queue);
            return;
        }
        for d in datagrams {
            if conn.send_datagram(d).is_err() {
                bump(&self.counters.dropped_queue);
            }
        }
    }

    /// The neighbour to send toward `target` through: `target` itself if
    /// it is one, else the start of the cheapest fresh route (never back
    /// where the frame came from).
    fn next_hop(&self, st: &State, target: &SignPk, from: Option<&SignPk>) -> Option<SignPk> {
        if Some(target) != from && st.neighbours.get(target).is_some_and(|n| n.live().is_some()) {
            return Some(*target);
        }
        st.routes(target, self.window_ms(), self.route_timeout(), Instant::now())
            .into_iter()
            .map(|(n, _)| n)
            .find(|n| Some(n) != from)
    }

    fn deliver(&self, st: &mut State, f: Frame) {
        let from = mesh_addr(&f.src, &f.waypoint);
        if f.offset == 0 && f.payload.len() == f.total as usize {
            bump(&self.counters.frames_delivered);
            let _ = self.inbox.try_send((f.payload, from));
            return;
        }
        let key = (f.src, f.id);
        if !st.reasm.contains_key(&key) && st.reasm.len() >= REASM_MAX {
            return;
        }
        let r = st.reasm.entry(key).or_insert_with(|| Reasm {
            buf: vec![0; f.total as usize],
            got: 0,
            at: Instant::now(),
            waypoint: f.waypoint,
        });
        if r.buf.len() != f.total as usize {
            return;
        }
        let at = f.offset as usize;
        r.buf[at..at + f.payload.len()].copy_from_slice(&f.payload);
        r.got += f.payload.len();
        if r.got >= r.buf.len()
            && let Some(r) = st.reasm.remove(&key)
        {
            bump(&self.counters.frames_delivered);
            let _ = self.inbox.try_send((Bytes::from(r.buf), mesh_addr(&f.src, &r.waypoint)));
        }
    }

    fn stats(&self) -> MeshStats {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        MeshStats {
            announcements_sent: g(&c.announcements_sent),
            announcements_received: g(&c.announcements_received),
            announcements_forged: g(&c.announcements_forged),
            announcements_stale: g(&c.announcements_stale),
            announcements_limited: g(&c.announcements_limited),
            frames_sent: g(&c.frames_sent),
            frames_delivered: g(&c.frames_delivered),
            frames_relayed: g(&c.frames_relayed),
            bytes_relayed: g(&c.bytes_relayed),
            dropped_budget: g(&c.dropped_budget),
            dropped_ttl: g(&c.dropped_ttl),
            dropped_no_route: g(&c.dropped_no_route),
            dropped_queue: g(&c.dropped_queue),
            dropped_too_big: g(&c.dropped_too_big),
            dropped_not_relaying: g(&c.dropped_not_relaying),
            hop_connections: g(&c.hop_connections),
        }
    }
}

/// Background work: announce, pass announcements on, dial, measure, expire
/// and keep Iroh's mesh addresses current.
async fn run(core: Arc<Core>) {
    let tick = Duration::from_millis(20);
    let mut next_announce = Instant::now();
    let mut next_slow = Instant::now();
    loop {
        tokio::time::sleep(tick).await;
        if core.stopped.load(Ordering::Relaxed) {
            return;
        }
        core.flush_announcements();
        let now = Instant::now();
        if now >= next_announce {
            core.announce_all();
            let every = core.opts.announce_every;
            let jitter = mycel_crypto::random_u64() % (every.as_millis() as u64 / 4 + 1);
            next_announce = now + every - every / 8 + Duration::from_millis(jitter);
        }
        if now >= next_slow {
            next_slow = now + Duration::from_millis(250);
            core.dial_missing();
            core.measure();
            core.expire();
            core.publish();
        }
    }
}

// ─────────────────────────────── public API ───────────────────────────────

/// This device's mesh router. A [`Link`] to the node: its transport carries
/// QUIC packets to devices with no direct path, and it reports them (and
/// their routes) like any link reports peers.
#[derive(Clone)]
pub struct Mesh {
    core: Arc<Core>,
}

impl std::fmt::Debug for Mesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mesh({})", self.core.me.short())
    }
}

impl Mesh {
    pub fn new(keys: Arc<DeviceKeys>, name: &str, opts: MeshOptions) -> Mesh {
        let (inbox, rx) = mpsc::channel(INBOX);
        let total = opts.relay_rate_total as f64;
        let core = Arc::new(Core {
            me: keys.sign_pk(),
            keys,
            name: Mutex::new(name.to_string()),
            st: Mutex::new(State {
                neighbours: HashMap::new(),
                origins: HashMap::new(),
                published: HashMap::new(),
                reasm: HashMap::new(),
                verified: HashSet::new(),
                total_budget: Bucket::new(total, total),
            }),
            opts,
            endpoint: Default::default(),
            events: Default::default(),
            inbox,
            inbox_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            counters: Counters::default(),
            next_id: AtomicU32::new(0),
            seq: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            tasks: Mutex::default(),
            tap: Mutex::default(),
        });
        Mesh { core }
    }

    /// Start routing on `endpoint` (which must serve [`ALPN`] with
    /// [`Mesh::protocol`]).
    pub fn attach(&self, endpoint: Endpoint) {
        if self.core.endpoint.set(endpoint).is_ok() {
            let task = tokio::spawn(run(self.core.clone()));
            self.core.keep(task);
        }
    }

    /// The handler for incoming hop connections.
    pub fn protocol(&self) -> MeshProtocol {
        MeshProtocol { core: self.core.clone() }
    }

    /// `peer` is (or no longer is) reachable directly: on a link or the LAN.
    pub fn set_direct(&self, peer: SignPk, direct: bool) {
        self.core.set_direct(peer, direct);
    }

    /// The route behind a mesh address (`mesh(dst, via)`), if we have one.
    pub fn route_info(&self, addr: &CustomAddr) -> Option<MeshRoute> {
        let (dst, via) = parse_mesh_addr(addr)?;
        let st = self.core.st.lock();
        let hops = st.origins.get(&dst).and_then(|o| o.via.get(&via)).map(|v| v.hops)?;
        let via_name = st.origins.get(&via).map(|o| o.latest.name.clone()).filter(|n| !n.is_empty());
        Some(MeshRoute { via, via_name, hops })
    }

    /// Devices reachable only through the mesh right now.
    pub fn reachable(&self) -> Vec<SignPk> {
        self.core.st.lock().published.keys().copied().collect()
    }

    /// Neighbours with a hop connection up.
    pub fn connected_neighbours(&self) -> Vec<SignPk> {
        let st = self.core.st.lock();
        st.neighbours.iter().filter(|(_, n)| n.live().is_some()).map(|(k, _)| *k).collect()
    }

    pub fn stats(&self) -> MeshStats {
        self.core.stats()
    }

    /// Tests: see every payload this device relays for others.
    pub fn set_tap(&self, tap: Option<Tap>) {
        *self.core.tap.lock() = tap;
    }
}

impl Link for Mesh {
    fn kind(&self) -> PathKind {
        PathKind::Mesh
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(MeshTransport { core: self.core.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        let _ = self.core.events.set(events);
        Ok(())
    }

    fn set_name(&self, name: &str) {
        *self.core.name.lock() = name.to_string();
    }

    fn status(&self) -> LinkStatus {
        let st = self.core.st.lock();
        let neighbours = st.neighbours.values().filter(|n| n.live().is_some()).count();
        LinkStatus {
            kind: PathKind::Mesh,
            active: self.core.endpoint.get().is_some() && !self.core.stopped.load(Ordering::Relaxed),
            detail: Some(match (neighbours, self.core.opts.relay) {
                (0, _) => "No Mycel devices nearby to relay through".into(),
                (n, true) => format!("{n} nearby, relaying for others"),
                (n, false) => format!("{n} nearby, not relaying for others"),
            }),
            peers: st.published.len(),
        }
    }

    fn stop(&self) {
        self.core.stopped.store(true, Ordering::SeqCst);
        for t in self.core.tasks.lock().drain(..) {
            t.abort();
        }
        let mut st = self.core.st.lock();
        for n in st.neighbours.values() {
            if let Some(c) = n.live() {
                c.close(0u32.into(), b"bye");
            }
        }
        st.neighbours.clear();
    }
}

/// Accepts hop connections from neighbours (anyone nearby: relaying needs
/// no membership; budgets bound what they can make us carry).
#[derive(Clone)]
pub struct MeshProtocol {
    core: Arc<Core>,
}

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshProtocol")
    }
}

impl ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let closed = conn.clone();
        self.core.add_conn(conn);
        closed.closed().await;
        Ok(())
    }
}

// ───────────────────────────── Iroh transport ─────────────────────────────

#[derive(Debug)]
struct MeshTransport {
    core: Arc<Core>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshCore({})", self.me.short())
    }
}

impl CustomTransport for MeshTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self
            .core
            .inbox_rx
            .clone()
            .try_lock_owned()
            .map_err(|_| io::Error::other("mesh already bound"))?;
        let local = mesh_addr(&self.core.me, &self.core.me);
        Ok(Box::new(MeshEndpoint {
            core: self.core.clone(),
            addrs: n0_watcher::Watchable::new(vec![local.clone()]),
            local,
            rx,
        }))
    }
}

struct MeshEndpoint {
    core: Arc<Core>,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    local: CustomAddr,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<(Bytes, CustomAddr)>>,
}

impl std::fmt::Debug for MeshEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshEndpoint")
    }
}

impl CustomEndpoint for MeshEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(MeshSender { core: self.core.clone() })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len();
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut packets = Vec::with_capacity(n);
        match self.rx.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("mesh closed"))),
            Poll::Ready(_) => {}
        }
        let mut count = 0;
        for (data, from) in packets {
            if bufs[count].len() < data.len() {
                continue;
            }
            bufs[count][..data.len()].copy_from_slice(&data);
            metas[count].len = data.len();
            metas[count].stride = data.len();
            recv_infos[count] = RecvInfo::new(from, Some(self.local.clone()));
            count += 1;
        }
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }
}

#[derive(Debug)]
struct MeshSender {
    core: Arc<Core>,
}

impl CustomSender for MeshSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TRANSPORT_MESH
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some((to, waypoint)) = parse_mesh_addr(dst) else {
            return Poll::Ready(Err(io::Error::other("not a mesh address")));
        };
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for packet in transmit.contents.chunks(seg) {
            self.core.send_local(to, waypoint, packet);
        }
        // Like UDP: sent means handed on, not delivered.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(opts: MeshOptions) -> (Arc<DeviceKeys>, Mesh) {
        let keys = Arc::new(DeviceKeys::generate());
        (keys.clone(), Mesh::new(keys, "me", opts))
    }

    #[test]
    fn announcements_round_trip_and_verify() {
        let k = DeviceKeys::generate();
        let mut a = Announce::signed(&k, now_ms(), "Atul’s MacBook Pro with a long name");
        assert!(a.name.len() <= MAX_NAME);
        a.hops = 3;
        a.cost = 1234;
        let b = Announce::decode(&a.encode()).unwrap();
        assert_eq!(a, b);
        assert!(b.verify(), "hops and cost are not signed: relays fill them in");
    }

    #[test]
    fn forged_announcements_are_rejected() {
        let (_, mesh) = core(MeshOptions::default());
        let c = &mesh.core;
        let neighbour = DeviceKeys::generate().sign_pk();
        c.st.lock().neighbours.insert(neighbour, Neighbour::new(&c.opts, Instant::now()));

        // a route to `victim`, signed by someone else
        let victim = DeviceKeys::generate();
        let liar = DeviceKeys::generate();
        let mut forged = Announce::signed(&liar, now_ms(), "victim");
        forged.origin = victim.sign_pk();
        c.on_announce(neighbour, forged);
        assert_eq!(mesh.stats().announcements_forged, 1);
        assert!(c.st.lock().origins.is_empty());

        // claiming a different name than the origin signed
        let mut renamed = Announce::signed(&victim, now_ms(), "victim");
        renamed.name = "evil".into();
        c.on_announce(neighbour, renamed);
        assert_eq!(mesh.stats().announcements_forged, 2);

        // a replay from long ago
        let old = Announce::signed(&victim, now_ms() - 3_600_000, "victim");
        c.on_announce(neighbour, old);
        assert_eq!(mesh.stats().announcements_stale, 1);
        assert!(c.st.lock().origins.is_empty());

        // the genuine one is taken
        c.on_announce(neighbour, Announce::signed(&victim, now_ms(), "victim"));
        assert!(c.st.lock().origins.contains_key(&victim.sign_pk()));
    }

    #[test]
    fn announcements_from_one_neighbour_are_rate_limited() {
        let (_, mesh) = core(MeshOptions::default());
        let c = &mesh.core;
        let neighbour = DeviceKeys::generate().sign_pk();
        c.st.lock().neighbours.insert(neighbour, Neighbour::new(&c.opts, Instant::now()));
        let origin = DeviceKeys::generate();
        let base = now_ms();
        for i in 0..1000 {
            c.on_announce(neighbour, Announce::signed(&origin, base + i, "x"));
        }
        let s = mesh.stats();
        assert!(s.announcements_limited >= 1000 - (OGM_RATE as u64 * 4) - 50, "{s:?}");
    }

    #[test]
    fn frames_fragment_and_reassemble() {
        let (keys, mesh) = core(MeshOptions::default());
        let me = keys.sign_pk();
        let src = DeviceKeys::generate().sign_pk();
        let packet: Vec<u8> = (0..1200u32).map(|i| i as u8).collect();
        let f = Frame {
            ttl: 8,
            reached: true,
            dst: me,
            src,
            waypoint: src,
            id: 7,
            offset: 0,
            total: packet.len() as u16,
            payload: Bytes::from(packet.clone()),
        };
        // a hop that only carries 500-byte datagrams
        let parts = f.encode(500).unwrap();
        assert_eq!(parts.len(), 4);
        // a relay with an even smaller hop splits a fragment again
        let second = Frame::decode(parts[1].clone()).unwrap().encode(300).unwrap();
        assert!(second.len() > 1);
        let mut st = mesh.core.st.lock();
        for d in [&parts[0], &parts[2], &parts[3]].into_iter().cloned().chain(second) {
            mesh.core.deliver(&mut st, Frame::decode(d).unwrap());
        }
        drop(st);
        let (got, from) = mesh.core.inbox_rx.try_lock().unwrap().try_recv().unwrap();
        assert_eq!(&got[..], &packet[..]);
        assert_eq!(parse_mesh_addr(&from), Some((src, src)));
        // bigger than QUIC's minimum and too big for the hop: dropped, not split
        let big = Frame { total: 1400, payload: Bytes::from(vec![0u8; 1400]), ..f };
        assert!(big.encode(1200).is_none());
    }

    #[test]
    fn mesh_addresses_round_trip() {
        let (a, b) = (DeviceKeys::generate().sign_pk(), DeviceKeys::generate().sign_pk());
        let addr = mesh_addr(&a, &b);
        assert_eq!(PathKind::of_custom(addr.id()), PathKind::Mesh);
        assert_eq!(parse_mesh_addr(&addr), Some((a, b)));
    }

    #[test]
    fn bucket_caps_the_rate() {
        let mut b = Bucket::new(1000.0, 1000.0);
        let t = Instant::now();
        assert!(b.take(1000.0, t));
        assert!(!b.take(1.0, t));
        assert!(b.take(500.0, t + Duration::from_millis(500)));
        assert!(!b.take(100.0, t + Duration::from_millis(500)));
    }
}
