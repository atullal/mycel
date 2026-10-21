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
//! neighbour (or gateway) the packet goes through, which also routes the
//! replies (`mesh(C, via B)`). Each route to C is a distinct address, so Iroh
//! opens one QUIC path per route, each with its own RTT, congestion window
//! and failover, and the path selector aggregates comparable routes exactly
//! as it does direct links. Up to [`MeshOptions::routes`] routes (through
//! distinct neighbours) are kept per destination.
//!
//! **Routing** lives in [`core`], a pure state machine (B.A.T.M.A.N.-style
//! signed announcements, distance vector over measured hop RTTs); this module
//! is its driver: hop connections, datagrams, signatures, clocks.
//!
//! **Beyond radio range** (see `docs/ARCHITECTURE.md`, "Global routing"): a
//! device with the internet is a *gateway* for the mesh around it. A device
//! without the internet publishes a signed record "reach me via gateways G1,
//! G2" in a global directory (pkarr: the n0 DNS relay Iroh already uses,
//! and a DHT-backed pkarr relay), through those gateways. Anyone on the
//! internet looks the record up and gets one mesh address per gateway; a
//! device without the internet sends anything it has no route for to its
//! nearest gateway. So a Bluetooth-only phone in the US and one in Europe
//! talk end to end: BLE hops → gateway → the internet → gateway → BLE hops,
//! one QUIC connection, several gateways as several paths.
//!
//! A direct path always beats the mesh: a device with a direct link to C
//! gets no mesh addresses for C, and the mesh refuses to carry packets to a
//! neighbour. That also guarantees hop connections never run over the mesh
//! themselves.

pub mod core;
pub mod directory;
pub mod dtn;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod v1_vectors;
mod watch;
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use iroh::endpoint::{ConnectOptions, Connection, PathId};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub use self::core::Stats as MeshStats;
use self::core::{Config, Out, Router, Time};
use self::wire::{MIN_QUIC_MTU, T_DATA, T_OGM, T_OGMS, T_SEQREQ};
pub use self::wire::{mesh_addr, parse_mesh_addr};
use crate::link::{
    CustomAddr, Link, LinkEvent, LinkStatus, PathKind, TRANSPORT_MESH, n0_watcher, noq_udp, path_in_use,
};
use crate::version::{
    AlpnTable, Hello, PeerProtocol, Protocol, WIRE_V1, WIRE_V2, WireVersion, alpn_table_ok, alpns_in, version_in,
};

/// Hop connections between neighbours (and internet hops to gateways), wire
/// version 2: version 1 plus a capability hello from each side of a hop,
/// versioned bundle offers, and data-frame flags carried end to end (see
/// docs/PROTOCOL.md). Dials offer every version the device speaks
/// ([`alpns`]).
pub const ALPN: &[u8] = ALPN_V2;
/// The mesh, wire version 2.
pub const ALPN_V2: &[u8] = b"mycel/mesh/2";
/// The mesh as pre-release builds speak it (wire version 1).
pub const ALPN_V1: &[u8] = b"mycel/mesh/1";

/// The mesh's ALPN for each wire version (see [`AlpnTable`]).
pub const ALPNS: AlpnTable = [(WIRE_V1, ALPN_V1), (WIRE_V2, ALPN_V2)];
const _: () = assert!(alpn_table_ok(&ALPNS), "one mesh ALPN per wire version, each its own");

/// The mesh's ALPNs for wire versions `newest` down to the oldest
/// supported, newest first.
pub fn alpns(newest: WireVersion) -> Vec<&'static [u8]> {
    alpns_in(&ALPNS, newest)
}

/// The mesh wire version a hop connection runs: the one its handshake
/// chose (1 for an ALPN that isn't ours, which a hop never has).
fn hop_version(conn: &Connection) -> WireVersion {
    version_of(conn.alpn()).unwrap_or(WIRE_V1)
}

/// The wire version a negotiated mesh ALPN stands for.
pub fn version_of(alpn: &[u8]) -> Option<WireVersion> {
    version_in(&ALPNS, alpn)
}

/// Sees each payload a device relays (tests).
pub type Tap = Arc<dyn Fn(&[u8]) + Send + Sync>;

const INBOX: usize = 4096;
/// Datagrams queued on a hop (waiting for its congestion window) beyond
/// 1/[QUEUE_CWND_DIV] of that window, or this many bytes if more, are dropped
/// from the tail. A short queue keeps relayed traffic's delay down and lets
/// the end-to-end connection see congestion early (1/4 and a full window
/// were measured too: more variable throughput across two routes).
const MIN_QUEUE: usize = 16 * 1024;
const QUEUE_CWND_DIV: usize = 8;
/// Active queue management on each hop ([`Aqm`]): the queueing delay
/// allowed below QUIC is the time to send this many full packets at the
/// rate the hop delivers (on 20 kB/s Bluetooth-speed radios, 2 took
/// another 6% of bulk data's throughput, and 5 left small exchanges
/// waiting a third longer) ...
const AQM_PACKETS: f64 = 3.0;
/// ... but at least this (radio jitter isn't a queue; Wi-Fi drivers' own
/// AQM uses 20 ms) and at most this.
const AQM_TARGET_MIN: Duration = Duration::from_millis(20);
const AQM_TARGET_MAX: Duration = Duration::from_millis(250);
/// The delay must stay above target this long before a frame is dropped
/// (CoDel's interval: about an end-to-end round trip, so the senders have
/// time to slow down on the first drop); on slow links, twice the target
/// plus the base RTT if that is longer, and never shorter than the hop's
/// RTT now.
const AQM_INTERVAL: Duration = Duration::from_millis(100);
/// Frames this size or smaller are never dropped by it: acknowledgements,
/// voice, small messages. Dropping them would empty no queue.
const AQM_SMALL: usize = 400;
/// The base RTT may drift up this much per second (a link that got slower).
const AQM_BASE_DRIFT: f64 = 0.01;
/// Dropping for this long (or 8 intervals) without the RTT falling: the
/// queue isn't ours to drain, so stop.
const AQM_GIVE_UP: Duration = Duration::from_secs(1);
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
/// The higher key dials only if the lower one hasn't after this long.
const DIAL_DEFER: Duration = Duration::from_secs(2);
/// Control message kinds (mesh frames for the router at the destination).
const CTRL_REACH: u8 = 1;
const RECORD_CACHE: Duration = Duration::from_secs(60);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);

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
    /// With the internet: be a gateway between it and the mesh for others.
    pub gateway: bool,
    /// Bytes per second crossing between the internet and the mesh.
    pub gateway_rate: u64,
    /// Without the internet: how many gateways to publish in our record.
    pub gateways: usize,
    /// Whether this device reaches the internet; `None`: it does while
    /// connected to its home relay.
    pub internet: Option<bool>,
    /// Where reachability records are published and looked up (see
    /// [`directory`]); the node sets the real one ([`Mesh::set_directory`]).
    pub directory: Option<Arc<dyn directory::Directory>>,
    /// Store-and-forward ([`dtn`]): carry bundles for others and send ours
    /// through carriers when no live path exists; `None` = off.
    pub store_and_forward: Option<dtn::DtnConfig>,
    /// Hop connections we open to devices in range, at most (others open
    /// theirs to us: about twice this in all, in a crowd). A Bluetooth radio holds ~10
    /// connections, and each costs keep-alives and a share of every
    /// announcement; in a crowd, a few well-spread neighbours route as well
    /// as all of them (docs/SIMULATION.md §4, finding 1).
    pub max_neighbours: usize,
    /// The newest wire version offered on hops and the capabilities
    /// advertised to neighbours (a node sets it from its own
    /// `NodeOptions::protocol`).
    pub protocol: Protocol,
    /// Routing defences that need no wire change ([`core::Defences`]; the
    /// trust-graph relay preference is off by default).
    pub defences: core::Defences,
}

impl Default for MeshOptions {
    fn default() -> Self {
        let c = Config::default();
        MeshOptions {
            relay: c.relay,
            relay_rate_per_neighbour: c.relay_rate_per_neighbour,
            relay_rate_total: c.relay_rate_total,
            routes: c.routes,
            max_hops: c.max_hops,
            announce_every: Duration::from_millis(c.announce_every),
            gateway: c.gateway,
            gateway_rate: c.gateway_rate,
            gateways: c.gateways,
            internet: None,
            directory: None,
            store_and_forward: Some(dtn::DtnConfig::default()),
            max_neighbours: 6,
            protocol: Protocol::default(),
            defences: c.defences,
        }
    }
}

impl MeshOptions {
    fn config(&self) -> Config {
        Config {
            relay: self.relay,
            relay_rate_per_neighbour: self.relay_rate_per_neighbour,
            relay_rate_total: self.relay_rate_total,
            routes: self.routes,
            max_hops: self.max_hops,
            announce_every: self.announce_every.as_millis() as Time,
            gateway: self.gateway,
            gateway_rate: self.gateway_rate,
            gateways: self.gateways,
            defences: self.defences,
            seed: mycel_crypto::random_u64(),
            ..Config::default()
        }
    }
}

/// How a peer is reached through the mesh, for the Network panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshRoute {
    /// The neighbour (or gateway) the route goes through.
    pub via: SignPk,
    pub via_name: Option<String>,
    /// Hops to the destination (2 = one device in between; 0 = unknown,
    /// beyond a gateway).
    pub hops: u8,
    /// Through a gateway and the internet.
    #[serde(default)]
    pub gateway: bool,
}

/// The path a hop connection uses, and its RTT. Not just the selected one:
/// on a hop the neighbour dialed, the path our end selected for them may be
/// missing, and then none is selected (see [`path_in_use`]).
fn hop_path(conn: &Connection) -> Option<(PathId, Duration)> {
    let paths = conn.paths();
    path_in_use(&paths).map(|p| (p.id(), p.rtt()))
}

/// A hop's cost in 0.1 ms units: its RTT plus the time to move 64 KiB at
/// the rate its congestion window allows (cwnd per RTT), so a slow radio
/// with a low RTT doesn't look better than a fast one with a higher RTT.
fn hop_cost(conn: &Connection, path: PathId, rtt: Duration) -> Option<u32> {
    if rtt.is_zero() {
        return None;
    }
    let cwnd = conn.congestion_state(path).map_or(0, |c| c.window()).max(1200) as f64;
    let secs = rtt.as_secs_f64() * (1.0 + 65_536.0 / cwnd);
    Some((secs * 10_000.0).clamp(1.0, (u32::MAX / 2) as f64) as u32)
}

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// A stable pseudo-random order of `peer` for `me` (FNV-1a over both keys).
fn rank(me: &SignPk, peer: &SignPk) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in me.0.iter().chain(peer.0.iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn to_sign_pk(id: &iroh::EndpointId) -> SignPk {
    SignPk(*id.as_bytes())
}

/// A record looked up: (gateways with cost, when).
type Looked = (Vec<(SignPk, u32)>, Instant);

/// The I/O side of one neighbour.
struct Hop {
    /// Seen directly (a link or the LAN), as opposed to only connected.
    direct: bool,
    direct_since: Instant,
    conn: Option<Connection>,
    /// The path `conn` uses, as last looked up (each `measure`, or when it
    /// closed): frames go out without a look at every path.
    path: Option<PathId>,
    /// Largest datagram buffer space seen = the buffer's size.
    dgram_cap: usize,
    /// Keeps the queue below the hop short.
    aqm: Aqm,
    dialing: bool,
    /// We opened it (it counts toward `max_neighbours`).
    dialed_by_us: bool,
    next_dial: Instant,
    failures: u32,
    /// What was agreed on `conn`: its wire version, then capabilities once
    /// the neighbour's hello has arrived.
    protocol: Option<PeerProtocol>,
}

impl Hop {
    fn new(now: Instant) -> Self {
        Hop {
            direct: false,
            direct_since: now,
            conn: None,
            path: None,
            dgram_cap: 0,
            aqm: Aqm::new(now),
            dialing: false,
            dialed_by_us: false,
            next_dial: now,
            failures: 0,
            protocol: None,
        }
    }

    fn live(&self) -> Option<&Connection> {
        self.conn.as_ref().filter(|c| c.close_reason().is_none())
    }
}

/// Active queue management for the data a hop carries (CoDel, RFC 8289,
/// with the hop's RTT standing in for the time packets wait).
///
/// A hop connection's congestion controller keeps sending until a buffer
/// *below* QUIC overflows: a radio's send queue, a Bluetooth controller's,
/// a busy relay's socket. That queue is first in, first out, and everything
/// on the hop waits in it: the announcements and sequence-number requests
/// that keep routes alive, the acknowledgements of the connections the hop
/// carries, keep-alives. On a saturated hop they waited as long as the data
/// (on the 400 kB/s test radios, 170 ms on average, the full 250 ms queue
/// at worst) and were dropped with it, and the end-to-end connections over
/// it ran at RTTs of 300–600 ms, so they took seconds to recover from a
/// loss. QUIC can't put control ahead of data in a queue it doesn't own.
///
/// So the driver keeps that queue short, as a router's AQM does: when the
/// hop's RTT has stayed more than a target above its base for an interval,
/// it drops a data frame, and then more often while it stays there. The
/// end-to-end connections slow down on the loss before the queue below
/// fills, and control traffic waits at most about the target (20 ms on
/// fast radios, a few packets' time on slow ones). Control frames,
/// announcements and small packets (acknowledgements, voice) are never
/// dropped this way. Only hops to devices in range have it: an internet
/// hop's queues belong to the internet, shared with everyone else's
/// traffic. And when dropping doesn't drain a queue (someone else's
/// traffic fills it, or the link got slower), it stops and takes that
/// delay as the new base, rather than starve our traffic.
#[derive(Debug)]
struct Aqm {
    /// The path these figures are for (a hop moving to another link starts
    /// over).
    path: Option<PathId>,
    /// The hop's RTT with an empty queue: the lowest seen, drifting up.
    base: Option<Duration>,
    base_at: Instant,
    /// Bytes per second the hop delivered (its busiest recent sample,
    /// decaying slowly), and the counter it was last sampled from.
    rate: f64,
    delivered: u64,
    sampled: Instant,
    /// Since when the delay has been above target.
    above_since: Option<Instant>,
    dropping: bool,
    /// When dropping last made progress (the RTT fell by a quarter from
    /// its peak), and the RTT since then at its highest.
    progress_at: Instant,
    progress_rtt: Duration,
    drop_next: Instant,
    count: u32,
    last_count: u32,
}

impl Aqm {
    fn new(now: Instant) -> Self {
        Aqm {
            path: None,
            base: None,
            base_at: now,
            rate: 0.0,
            delivered: 0,
            sampled: now,
            above_since: None,
            dropping: false,
            progress_at: now,
            progress_rtt: Duration::ZERO,
            drop_next: now,
            count: 0,
            last_count: 0,
        }
    }

    /// Follow the hop's path: figures for another path don't apply.
    fn on_path(&mut self, path: Option<PathId>, now: Instant) {
        if self.path != path {
            *self = Aqm::new(now);
            self.path = path;
        }
    }

    /// The path delivered `delivered` bytes so far (sent − lost): sample
    /// its rate. A busier sample replaces the estimate; quieter ones lower
    /// it slowly, so a burst after a pause is judged by what the hop can
    /// carry, not by how idle it was.
    fn sample_rate(&mut self, delivered: u64, now: Instant) {
        let dt = now.duration_since(self.sampled).as_secs_f64();
        if delivered < self.delivered {
            self.delivered = delivered;
        }
        if dt >= 0.2 {
            let r = (delivered - self.delivered) as f64 / dt;
            self.rate = if r > self.rate { r } else { 0.97 * self.rate + 0.03 * r };
            (self.delivered, self.sampled) = (delivered, now);
        }
    }

    /// The RTT the hop has now: update the base.
    fn sample_rtt(&mut self, rtt: Duration, now: Instant) -> Duration {
        let dt = now.duration_since(self.base_at).as_secs_f64();
        self.base_at = now;
        let base = match self.base {
            Some(b) => b.mul_f64(1.0 + AQM_BASE_DRIFT * dt).min(rtt),
            None => rtt,
        };
        self.base = Some(base);
        base
    }

    /// Queueing delay allowed: a few packets' worth at the hop's rate.
    fn target(&self) -> Duration {
        if self.rate <= 0.0 {
            return AQM_TARGET_MAX;
        }
        Duration::from_secs_f64(AQM_PACKETS * MIN_QUIC_MTU as f64 / self.rate).clamp(AQM_TARGET_MIN, AQM_TARGET_MAX)
    }

    /// Whether to drop a data frame now, the hop's smoothed RTT being `rtt`.
    fn drop_now(&mut self, rtt: Duration, now: Instant) -> bool {
        let base = self.sample_rtt(rtt, now);
        let target = self.target();
        // (an end-to-end round trip through this hop takes at least the
        // hop's own RTT: the senders can't react to a drop any faster)
        let interval = AQM_INTERVAL.max(2 * target + base).max(rtt);
        if rtt.saturating_sub(base) < target {
            self.above_since = None;
            self.dropping = false;
            return false;
        }
        if self.dropping {
            if rtt < self.progress_rtt.mul_f64(0.75) {
                (self.progress_at, self.progress_rtt) = (now, rtt);
            } else if rtt > self.progress_rtt {
                self.progress_rtt = rtt; // still rising: progress is from its peak
            } else if now.duration_since(self.progress_at) > AQM_GIVE_UP.max(8 * interval) {
                // Dropping didn't drain it: the queue isn't (only) ours,
                // other traffic shares the link, or the link got slower.
                // Take this delay as the hop's base; the lowest RTT seen
                // brings the base back down once the queue does drain.
                self.base = Some(rtt);
                self.dropping = false;
                self.above_since = None;
                return false;
            }
            if now < self.drop_next {
                return false;
            }
            if self.drop_next + interval < now {
                self.drop_next = now; // a lull: no burst of drops to catch up
            }
            self.count += 1;
            self.drop_next += interval.div_f64((self.count as f64).sqrt());
            return true;
        }
        let since = *self.above_since.get_or_insert(now);
        if now.duration_since(since) < interval {
            return false;
        }
        // Above target for a whole interval: start dropping, faster at
        // once if we were dropping a moment ago (the queue came back).
        self.dropping = true;
        (self.progress_at, self.progress_rtt) = (now, rtt);
        let delta = self.count.saturating_sub(self.last_count);
        self.count = if delta > 1 && now.saturating_duration_since(self.drop_next) < 16 * interval { delta } else { 1 };
        self.last_count = self.count;
        self.drop_next = now + interval.div_f64((self.count as f64).sqrt());
        true
    }
}

struct Driver {
    keys: Arc<DeviceKeys>,
    me: SignPk,
    opts: MeshOptions,
    name: Mutex<String>,
    router: Mutex<Router>,
    hops: Mutex<HashMap<SignPk, Hop>>,
    base: Instant,
    endpoint: std::sync::OnceLock<Endpoint>,
    events: std::sync::OnceLock<mpsc::UnboundedSender<LinkEvent>>,
    inbox: mpsc::Sender<(Bytes, CustomAddr)>,
    inbox_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(Bytes, CustomAddr)>>>,
    stopped: AtomicBool,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    tap: Mutex<Option<Tap>>,
    dropped_queue: std::sync::atomic::AtomicU64,
    dropped_too_big: std::sync::atomic::AtomicU64,
    /// Uplink cost override (tests, or a known slow link).
    uplink: Mutex<Option<u32>>,
    directory: Mutex<Option<Arc<dyn directory::Directory>>>,
    /// Records looked up: target -> (gateways with cost, when). Shared with
    /// the address lookup.
    records: Mutex<HashMap<SignPk, Looked>>,
    records_published: std::sync::atomic::AtomicU64,
    carrier: Option<Mutex<dtn::Carrier>>,
    /// Where bundles for us go (the node ingests them).
    bundle_sink: Mutex<Option<mpsc::UnboundedSender<(SignPk, u16, Bytes)>>>,
    /// Bundles being handed to each neighbour now ([`SENDS_PER_NEIGHBOUR`]).
    sending: Mutex<HashMap<SignPk, HashSet<Hash32>>>,
    /// One of them ended: plan the next without waiting for the tick.
    dtn_due: AtomicBool,
    /// Memory for what neighbours send us (`resources.rs`).
    frames: crate::resources::Frames,
    /// End-to-end connections whose mesh paths are watched (`watch.rs`).
    watched: Mutex<HashSet<usize>>,
    /// Tests: relay nothing to or from this device (a black hole).
    black_hole: Mutex<Option<SignPk>>,
}

/// A bundle being handed to a neighbour; ending lets the next one start.
struct SendSlot {
    d: Arc<Driver>,
    to: SignPk,
    id: Hash32,
}

impl Drop for SendSlot {
    fn drop(&mut self) {
        let mut sending = self.d.sending.lock();
        if let Some(ids) = sending.get_mut(&self.to) {
            ids.remove(&self.id);
            if ids.is_empty() {
                sending.remove(&self.to);
            }
        }
        self.d.dtn_due.store(true, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshDriver({})", self.me.short())
    }
}

impl Driver {
    fn now(&self) -> Time {
        self.base.elapsed().as_millis() as Time
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

    /// Run `f` on the router, then carry out what it asked for (outside
    /// the router's lock).
    fn with_router<R>(self: &Arc<Self>, f: impl FnOnce(&mut Router, Time) -> R) -> R {
        let mut outs = Vec::new();
        let r = {
            let mut rt = self.router.lock();
            let now = self.now();
            let r = f(&mut rt, now);
            rt.drain(&mut outs);
            r
        };
        if !outs.is_empty() {
            self.exec(outs);
        }
        r
    }

    fn conn(&self, peer: &SignPk) -> Option<Connection> {
        self.hops.lock().get(peer).and_then(|h| h.live().cloned())
    }

    /// Dial a hop connection, offering every mesh version we speak.
    async fn dial_hop(&self, ep: &Endpoint, peer: SignPk) -> Option<Connection> {
        let id = iroh::PublicKey::from_bytes(&peer.0).ok()?;
        let offered = alpns(self.opts.protocol.version);
        let (first, rest) = offered.split_first()?;
        let options = ConnectOptions::new().with_additional_alpns(rest.iter().map(|a| a.to_vec()).collect());
        let connect = async { ep.connect_with_opts(EndpointAddr::new(id), first, options).await.ok()?.await.ok() };
        tokio::time::timeout(DIAL_TIMEOUT, connect).await.ok().flatten()
    }

    fn exec(self: &Arc<Self>, outs: Vec<Out>) {
        // announcements go out batched per neighbour, after the rest
        let mut anns: Vec<(SignPk, Vec<core::Announce>)> = Vec::new();
        for o in outs {
            match o {
                Out::Announce { to, ann } => match anns.iter_mut().find(|(k, _)| *k == to) {
                    Some((_, v)) => v.push(ann),
                    None => anns.push((to, vec![ann])),
                },
                Out::SeqReq { to, req } => {
                    if let Some(c) = self.conn(&to) {
                        let _ = c.send_datagram(wire::encode_seqreq(&req));
                    }
                }
                Out::Frame { to, frame, relayed } => {
                    if relayed && self.black_hole.lock().is_some_and(|b| b == frame.dst || b == frame.src) {
                        continue;
                    }
                    if relayed && let Some(tap) = self.tap.lock().clone() {
                        tap(&frame.payload);
                    }
                    self.send_frame(&to, &frame);
                }
                Out::Deliver { src, waypoint, payload } => {
                    let _ = self.inbox.try_send((payload, mesh_addr(&src, &waypoint)));
                }
                Out::Control { from, payload } => self.on_control(from, payload),
                Out::Dial(peer) => self.dial_internet(peer),
                Out::Hangup(peer) => {
                    if let Some(c) = self.conn(&peer) {
                        c.close(0u32.into(), b"idle");
                    }
                }
                Out::Resolve(peer) => self.resolve(peer),
                Out::PublishReach { gateways } => self.publish_reach(gateways),
                Out::RouteUp { dst, via, name } => {
                    let name = (!name.is_empty()).then(|| name.to_string());
                    self.send_event(LinkEvent::Found { peer: dst, addr: mesh_addr(&dst, &via), name });
                }
                Out::RouteDown { dst, via } => {
                    self.send_event(LinkEvent::Lost { peer: dst, addr: mesh_addr(&dst, &via) });
                }
            }
        }
        for (to, v) in anns {
            let Some(c) = self.conn(&to) else { continue };
            let max = c.max_datagram_size().unwrap_or(MIN_QUIC_MTU);
            for d in wire::encode_announcements(&v, max) {
                let _ = c.send_datagram(d);
            }
        }
    }

    /// Put a frame on a hop connection: split to the hop's datagram size,
    /// tail-dropped if the hop is already backed up, and data dropped now
    /// and then while the queue below the hop stands too long ([`Aqm`]).
    fn send_frame(&self, to: &SignPk, f: &core::Frame) {
        let mut hops = self.hops.lock();
        let Some(h) = hops.get_mut(to) else { return };
        let Some(conn) = h.live().cloned() else { return };
        let Some(max) = conn.max_datagram_size() else {
            self.dropped_too_big.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(datagrams) = wire::encode_frame(f, max) else {
            self.dropped_too_big.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // Tail-drop beyond a fraction of the hop's congestion window queued,
        // so a slow hop doesn't build seconds of delay.
        let space = conn.datagram_send_buffer_space();
        h.dgram_cap = h.dgram_cap.max(space);
        let queued = h.dgram_cap - space;
        let path = h.path;
        drop(hops);
        let cwnd = self.hop_window(to, &conn, path);
        let bytes: usize = datagrams.iter().map(|d| d.len()).sum();
        if queued + bytes > (cwnd / QUEUE_CWND_DIV).max(MIN_QUEUE) {
            self.dropped_queue.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !f.control && f.payload.len() > AQM_SMALL && self.aqm_drops(to, &conn) {
            self.dropped_queue.fetch_add(1, Ordering::Relaxed);
            return;
        }
        for d in datagrams {
            if conn.send_datagram(d).is_err() {
                self.dropped_queue.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The congestion window of the path the hop to `to` uses: the one
    /// remembered, or, on a new hop or once that path closed, the one in
    /// use now (remembered for the next frames).
    fn hop_window(&self, to: &SignPk, conn: &Connection, path: Option<PathId>) -> usize {
        let window = |id: PathId| conn.congestion_state(id).map(|c| c.window() as usize);
        if let Some(w) = path.and_then(window) {
            return w;
        }
        let used = hop_path(conn).map(|(id, _)| id);
        if let Some(h) = self.hops.lock().get_mut(to)
            && h.live().is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            h.path = used;
        }
        used.and_then(window).unwrap_or(0)
    }

    /// Whether the hop's queue calls for dropping a data frame now ([`Aqm`]).
    fn aqm_drops(&self, to: &SignPk, conn: &Connection) -> bool {
        let mut hops = self.hops.lock();
        let Some(h) = hops.get_mut(to) else { return false };
        if h.live().is_none_or(|c| c.stable_id() != conn.stable_id()) {
            return false;
        }
        if !h.direct {
            return false; // an internet hop: its queues are the internet's
        }
        let Some(path) = h.path else { return false };
        let Some(rtt) = conn.rtt(path).filter(|r| !r.is_zero()) else { return false };
        let now = Instant::now();
        h.aqm.on_path(Some(path), now);
        h.aqm.drop_now(rtt, now)
    }

    // ───────────── neighbours ─────────────

    fn set_direct(self: &Arc<Self>, peer: SignPk, direct: bool) {
        if peer == self.me {
            return;
        }
        let now = Instant::now();
        {
            let mut hops = self.hops.lock();
            if direct {
                let h = hops.entry(peer).or_insert_with(|| Hop::new(now));
                if !h.direct {
                    h.direct = true;
                    h.direct_since = now;
                    h.next_dial = now;
                    h.failures = 0;
                }
            } else if let Some(h) = hops.get_mut(&peer) {
                h.direct = false;
                if h.live().is_none() {
                    hops.remove(&peer);
                }
            }
        }
        self.with_router(|r, now| {
            r.set_direct(peer, direct, now);
            r.tick(now); // a neighbour gets no mesh addresses
        });
    }

    /// A hop connection is up (dialed or accepted).
    fn add_conn(self: &Arc<Self>, conn: Connection) {
        let peer = to_sign_pk(&conn.remote_id());
        if peer == self.me {
            return;
        }
        {
            let mut hops = self.hops.lock();
            let h = hops.entry(peer).or_insert_with(|| Hop::new(Instant::now()));
            if let Some(old) = h.live() {
                // Both dialed at once: keep the connection the lower key
                // opened (both sides agree on which that is).
                if self.lower_dialed(old) || !self.lower_dialed(&conn) {
                    conn.close(0u32.into(), b"duplicate");
                    return;
                }
                old.close(0u32.into(), b"duplicate");
            }
            h.conn = Some(conn.clone());
            h.path = None;
            h.aqm = Aqm::new(Instant::now());
            h.dialed_by_us = conn.side().is_client();
            h.dgram_cap = conn.datagram_send_buffer_space();
            h.failures = 0;
            h.protocol = Some(PeerProtocol::baseline(hop_version(&conn)));
        }
        self.send_hello(&conn);
        let direct = self.hops.lock().get(&peer).is_some_and(|h| h.direct);
        self.with_router(|r, now| {
            r.hop_up(peer, now);
            r.tick(now);
        });
        if let Some(c) = &self.carrier
            && direct
        {
            c.lock().encounter(peer, self.now());
        }
        if let Some(c) = &self.carrier {
            c.lock().new_contact(peer); // tell it what we hold, soon
        }
        self.keep(tokio::spawn(self.clone().serve_streams(peer, conn.clone())));
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
            let mut hops = self.hops.lock();
            let Some(h) = hops.get_mut(&peer) else { return };
            if h.conn.as_ref().is_none_or(|c| c.stable_id() != conn.stable_id()) {
                return; // a replaced duplicate
            }
            h.conn = None;
            h.failures += 1;
            h.next_dial = Instant::now() + Duration::from_secs((1u64 << h.failures.min(5)).min(30));
            if !h.direct {
                hops.remove(&peer);
            }
        }
        self.with_router(|r, now| {
            r.hop_down(peer, now);
            r.tick(now);
        });
    }

    /// Dial direct neighbours we have no hop connection to.
    fn dial_missing(self: &Arc<Self>) {
        let Some(ep) = self.endpoint.get().cloned() else { return };
        let now = Instant::now();
        let mut todo = Vec::new();
        {
            let mut hops = self.hops.lock();
            // at most `max_neighbours` we dialed: each device prefers its own
            // pseudo-random subset of those in range, so the hops spread out
            let mut ours_up =
                hops.values().filter(|h| h.direct && h.dialed_by_us && (h.live().is_some() || h.dialing)).count();
            let mut want: Vec<(u64, SignPk)> = hops
                .iter()
                .filter(|(pk, h)| {
                    let ours = self.me < **pk || now.duration_since(h.direct_since) >= DIAL_DEFER;
                    h.direct && h.live().is_none() && !h.dialing && now >= h.next_dial && ours
                })
                .map(|(pk, _)| (rank(&self.me, pk), *pk))
                .collect();
            want.sort_unstable();
            for (_, pk) in want {
                if ours_up >= self.opts.max_neighbours.max(1) {
                    break;
                }
                if let Some(h) = hops.get_mut(&pk) {
                    h.dialing = true;
                    h.dialed_by_us = true;
                    ours_up += 1;
                    todo.push(pk);
                }
            }
        }
        for pk in todo {
            let (me, ep) = (self.clone(), ep.clone());
            let task = tokio::spawn(async move {
                let res = me.dial_hop(&ep, pk).await;
                let ok = res.is_some();
                {
                    let mut hops = me.hops.lock();
                    if let Some(h) = hops.get_mut(&pk) {
                        h.dialing = false;
                        h.dialed_by_us = ok;
                        if !ok {
                            h.failures += 1;
                            h.next_dial = Instant::now() + Duration::from_secs((1u64 << h.failures.min(5)).min(30));
                        }
                    }
                }
                if let Some(conn) = res {
                    me.add_conn(conn);
                }
            });
            self.keep(task);
        }
    }

    /// An internet hop the router asked for: to a gateway, or to a device
    /// that is itself on the internet.
    fn dial_internet(self: &Arc<Self>, peer: SignPk) {
        let Some(ep) = self.endpoint.get().cloned() else {
            self.with_router(|r, now| r.dial_failed(peer, now));
            return;
        };
        let me = self.clone();
        let task = tokio::spawn(async move {
            match me.dial_hop(&ep, peer).await {
                Some(conn) => me.add_conn(conn),
                None => me.with_router(|r, now| r.dial_failed(peer, now)),
            }
        });
        self.keep(task);
    }

    /// Each hop's cost, measured on the path its connection uses now (which
    /// `send_frame` then uses too).
    fn hop_costs(&self) -> Vec<(SignPk, u32)> {
        let mut hops = self.hops.lock();
        let mut costs = Vec::new();
        let now = Instant::now();
        for (pk, h) in hops.iter_mut() {
            let Some(conn) = h.live().cloned() else { continue };
            // (path, RTT, bytes delivered)
            let used = path_in_use(&conn.paths()).map(|p| {
                let s = p.stats();
                (p.id(), s.rtt, s.udp_tx.bytes.saturating_sub(s.lost_bytes))
            });
            h.path = used.map(|(id, ..)| id);
            h.aqm.on_path(h.path, now);
            if let Some((.., delivered)) = used {
                h.aqm.sample_rate(delivered, now);
            }
            if let Some(cost) = used.and_then(|(id, rtt, _)| hop_cost(&conn, id, rtt)) {
                costs.push((*pk, cost));
            }
        }
        costs
    }

    /// Hop cost: each hop connection's measured RTT.
    fn measure(self: &Arc<Self>) {
        let costs = self.hop_costs();
        self.with_router(|r, _| {
            for (pk, c) in costs {
                r.set_cost(pk, c);
            }
        });
    }

    fn on_datagram(self: &Arc<Self>, from: SignPk, d: Bytes) {
        match d.first() {
            Some(&T_OGM) => {
                if let Some(a) = wire::decode_announce(&d) {
                    let wall = wall_ms();
                    self.with_router(|r, now| r.on_announce(from, a, now, wall, wire::verify_announce));
                }
            }
            Some(&T_OGMS) => {
                let anns = wire::decode_announces(&d);
                if !anns.is_empty() {
                    let wall = wall_ms();
                    self.with_router(|r, now| {
                        for a in anns {
                            r.on_announce(from, a, now, wall, wire::verify_announce);
                        }
                    });
                }
            }
            Some(&T_DATA) => {
                if let Some(f) = wire::decode_frame(d) {
                    self.with_router(|r, now| r.on_frame(from, f, now));
                }
            }
            Some(&T_SEQREQ) => {
                if let Some(q) = wire::decode_seqreq(&d) {
                    self.with_router(|r, now| r.on_seqreq(from, q, now));
                }
            }
            _ => {}
        }
    }

    /// A QUIC packet from our endpoint for `dst`, through `waypoint`.
    fn send_local(self: &Arc<Self>, dst: SignPk, waypoint: SignPk, packet: &[u8]) {
        if packet.len() > MIN_QUIC_MTU {
            self.dropped_too_big.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let payload = Bytes::copy_from_slice(packet);
        self.with_router(|r, now| r.send(dst, waypoint, payload, false, now));
    }

    // ───────────── beyond the mesh ─────────────

    fn directory(&self) -> Option<Arc<dyn directory::Directory>> {
        self.directory.lock().clone()
    }

    /// A control message for us: a record to publish, as a gateway.
    fn on_control(self: &Arc<Self>, _from: SignPk, payload: Bytes) {
        if payload.first() != Some(&CTRL_REACH) {
            return;
        }
        let record = payload.slice(1..);
        // signed by its owner; it must name us as one of its gateways
        let Some(reach) = directory::open(&record, None) else { return };
        if !reach.gateways.iter().any(|(g, _)| *g == self.me) {
            return;
        }
        if !self.with_router(|r, now| r.internet() && r.admit_record(reach.node, now)) {
            return;
        }
        let Some(dir) = self.directory() else { return };
        let me = self.clone();
        self.keep(tokio::spawn(async move {
            if dir.put(record).await.is_ok() {
                me.records_published.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    /// Look `peer` up: behind gateways (a record), or not (dial it).
    fn resolve(self: &Arc<Self>, peer: SignPk) {
        let Some(dir) = self.directory() else {
            self.with_router(|r, now| r.on_resolved(peer, None, now));
            return;
        };
        let me = self.clone();
        self.keep(tokio::spawn(async move {
            let gws = me.lookup(&dir, peer).await;
            me.with_router(|r, now| r.on_resolved(peer, gws, now));
        }));
    }

    /// The gateways `peer`'s record names (cached a minute), or `None`.
    async fn lookup(&self, dir: &Arc<dyn directory::Directory>, peer: SignPk) -> Option<Vec<(SignPk, u32)>> {
        if let Some((g, at)) = self.records.lock().get(&peer)
            && at.elapsed() < RECORD_CACHE
        {
            return (!g.is_empty()).then(|| g.clone());
        }
        let found = tokio::time::timeout(LOOKUP_TIMEOUT, dir.get(peer))
            .await
            .ok()
            .flatten()
            .and_then(|b| directory::open(&b, Some(&peer)))
            .map(|r| r.gateways);
        self.records.lock().insert(peer, (found.clone().unwrap_or_default(), Instant::now()));
        found.filter(|g| !g.is_empty())
    }

    /// Without the internet: sign a record naming our gateways and hand it
    /// to each of them to publish.
    fn publish_reach(self: &Arc<Self>, gateways: Vec<(SignPk, u32)>) {
        let Ok(record) = directory::seal(&self.keys, &gateways) else { return };
        let mut payload = Vec::with_capacity(1 + record.len());
        payload.push(CTRL_REACH);
        payload.extend_from_slice(&record);
        let payload = Bytes::from(payload);
        self.with_router(|r, now| {
            for (g, _) in &gateways {
                r.send(*g, *g, payload.clone(), true, now);
            }
        });
    }

    /// Mesh addresses for `peer` beyond our own mesh: through our gateways
    /// if we have no internet, through its gateways if it has a record.
    async fn gateway_addrs(self: Arc<Self>, peer: SignPk) -> Vec<CustomAddr> {
        let (local, internet, mine) = {
            let r = self.router.lock();
            let now = self.now();
            let local = r.is_neighbour(&peer) || r.next_hop_local(&peer, now).is_some();
            (local, r.internet(), r.gateways(now))
        };
        if local || peer == self.me {
            return Vec::new(); // a link or a mesh route has it
        }
        if !internet {
            return mine.iter().take(self.opts.routes.max(1)).map(|g| mesh_addr(&peer, g)).collect();
        }
        let Some(dir) = self.directory() else { return Vec::new() };
        let Some(mut gws) = self.lookup(&dir, peer).await else { return Vec::new() };
        gws.sort_by_key(|(g, c)| (*c, g.0));
        gws.into_iter().filter(|(g, _)| *g != self.me).take(3).map(|(g, _)| mesh_addr(&peer, &g)).collect()
    }

    // ───────────── store and forward ─────────────

    /// Streams a neighbour opens on the hop connection: summaries and
    /// bundles (datagrams carry routing and packets). QUIC's stream limits
    /// make a neighbour with too many open wait for its turn.
    async fn serve_streams(self: Arc<Self>, peer: SignPk, conn: Connection) {
        loop {
            tokio::select! {
                bi = conn.accept_bi() => {
                    let Ok((tx, rx)) = bi else { break };
                    let me = self.clone();
                    tokio::spawn(async move {
                        let _ = me.on_bundle_stream(peer, tx, rx).await;
                    });
                }
                uni = conn.accept_uni() => {
                    let Ok(rx) = uni else { break };
                    let me = self.clone();
                    tokio::spawn(async move {
                        let _ = me.on_summary_stream(peer, rx).await;
                    });
                }
            }
        }
    }

    /// Our capability hello on a new hop connection (version 2 and later):
    /// a uni-stream of its own, beside everything else.
    fn send_hello(self: &Arc<Self>, conn: &Connection) {
        if version_of(conn.alpn()).is_none_or(|v| v < WIRE_V2) {
            return;
        }
        let mut msg = vec![K_HELLO];
        msg.extend_from_slice(&Hello::ours(self.opts.protocol.caps).encode());
        let conn = conn.clone();
        self.keep(tokio::spawn(async move {
            let open = crate::resources::within(crate::resources::REPLY_TIMEOUT, "no stream", conn.open_uni());
            if let Ok(mut tx) = open.await {
                tx.set_priority(1).ok();
                if crate::resources::write_all(&mut tx, &msg).await.is_ok() {
                    tx.finish().ok();
                }
            }
        }));
    }

    /// A neighbour's capability hello: what both of us have on this hop.
    fn on_hello(&self, from: SignPk, body: &[u8]) -> Result<()> {
        let theirs = Hello::decode(body)?;
        let mut hops = self.hops.lock();
        let Some(h) = hops.get_mut(&from) else { return Ok(()) };
        if let Some(p) = h.protocol.filter(|p| p.version >= WIRE_V2) {
            h.protocol = Some(PeerProtocol::agreed(p.version, self.opts.protocol.caps, theirs.caps));
        }
        Ok(())
    }

    async fn on_summary_stream(self: Arc<Self>, from: SignPk, mut rx: iroh::endpoint::RecvStream) -> Result<()> {
        // (it ends with the stream: no length first)
        let permit = self.frames.peer(&from).admit(MAX_SUMMARY).await?;
        let idle = crate::resources::IDLE_TIMEOUT;
        let (bytes, _permit) = crate::resources::read_body(&mut rx, MAX_SUMMARY, true, permit, idle).await?;
        let body = match bytes.split_first() {
            Some((&K_SUMMARY, body)) => body,
            Some((&K_HELLO, body)) => return self.on_hello(from, body),
            // a kind from a newer neighbour: nothing it needs answered
            _ => return Ok(()),
        };
        let s = decode_summary(body)?;
        let now = self.now();
        if let Some(c) = &self.carrier {
            c.lock().on_summary(from, s, now, verify_receipt);
        }
        Ok(())
    }

    /// A neighbour offers a bundle: answer before any payload crosses
    /// the link, then take the payload (from where an earlier transfer was
    /// cut, if one was).
    async fn on_bundle_stream(
        self: Arc<Self>,
        from: SignPk,
        mut tx: iroh::endpoint::SendStream,
        mut rx: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let Some(c) = &self.carrier else { return Ok(()) };
        let frames = self.frames.peer(&from);
        let (head, _head_permit) = read_frame(&mut rx, MAX_OFFER, crate::resources::FIRST_FRAME, &frames).await?;
        let Some(o) = decode_offer(&head)? else { return Ok(()) };
        if !o.format.checkable() {
            // a header we can't check is one we won't carry (a payload kind
            // we don't know is fine: carriers never read payloads)
            write_frame(&mut tx, &crate::wire::encode_bounded(&WireAnswer::Refuse(false), 64)?).await?;
            tx.finish()?;
            return Err(crate::version::VersionError::Unsupported {
                what: "bundle",
                version: o.format.version.into(),
                newest: dtn::BUNDLE_VERSION.into(),
            }
            .into());
        }
        let answer = {
            let mut c = c.lock();
            c.set_clock(self.now(), wall_ms());
            c.offered(from, &o, self.now(), verify_offer)
        };
        // Room for the payload before asking for it: the neighbour's share
        // for all of it, the pool for what is in memory (the partial kept
        // from before, then what arrives).
        let want = usize::try_from(o.size)?;
        let permit = match answer {
            dtn::Answer::Take { .. } => Some(frames.admit(want).await?),
            _ => None,
        };
        write_frame(&mut tx, &crate::wire::encode_bounded(&WireAnswer::from(answer), 64)?).await?;
        let (dtn::Answer::Take { from: at }, Some(mut permit)) = (answer, permit) else {
            tx.finish()?;
            return Ok(());
        };
        permit.hold(at as usize).await?;
        // the payload from `at`: keep what arrives even if the link drops
        let mut payload = c.lock().partial(&o.id).map_or_else(Vec::new, |p| p[..p.len().min(at as usize)].to_vec());
        if payload.len() as u64 != at {
            return Ok(()); // dropped meanwhile: the next offer starts over
        }
        let idle = crate::resources::IDLE_TIMEOUT;
        let cut = loop {
            let deadline = permit.deadline(payload.len() - at as usize, idle);
            let n = want.saturating_sub(payload.len()).clamp(1, 64 * 1024);
            match tokio::time::timeout_at(deadline, rx.read_chunk(n)).await {
                Ok(Ok(Some(chunk))) if payload.len() + chunk.len() <= want => {
                    let need = payload.len() + chunk.len();
                    if payload.capacity() < need {
                        let target = need.next_power_of_two().min(want);
                        if permit.hold(target).await.is_err() {
                            break true;
                        }
                        payload.reserve_exact(target - payload.len());
                    }
                    payload.extend_from_slice(&chunk)
                }
                Ok(Ok(Some(_))) => return Ok(()), // more than offered: not that bundle
                Ok(Ok(None)) => break false,
                Ok(Err(_)) | Err(_) => break true,
            }
        };
        if cut || payload.len() < want {
            if payload.len() as u64 > at {
                c.lock().keep_partial(o.id, o.src, Bytes::from(payload), self.now());
            }
            return Ok(());
        }
        let b = dtn::Bundle {
            format: o.format,
            id: o.id,
            src: o.src,
            dst: o.dst,
            created: o.created,
            lifetime: o.lifetime,
            payload: Bytes::from(payload),
            sig: o.sig,
        };
        let now = self.now();
        let got = c.lock().accept(from, b, o.copies, now, verify_bundle);
        let ok = !matches!(got, dtn::Accepted::Refused(_));
        let verdict: [u8; BUNDLE_VERDICT_LEN] = [ok as u8];
        crate::resources::write_all(&mut tx, &verdict).await?;
        tx.finish()?;
        if let dtn::Accepted::ForMe(b) = got {
            let sig = self.keys.sign(RECEIPT_CTX, &[&b.id.0]);
            c.lock().add_receipt(dtn::Receipt { id: b.id, dst: self.me, sig });
            if let Some(sink) = self.bundle_sink.lock().as_ref() {
                let _ = sink.send((b.src, b.format.kind, b.payload));
            }
        }
        Ok(())
    }

    /// Summaries to neighbours, then hand on what can move now.
    fn dtn_tick(self: &Arc<Self>) {
        let Some(c) = &self.carrier else { return };
        let now = self.now();
        let internet = self.router.lock().internet();
        let neighbours: Vec<SignPk> = self.router.lock().neighbours().into_iter().map(|(k, _)| k).collect();
        {
            let mut c = c.lock();
            c.set_internet(internet);
            c.set_clock(now, wall_ms());
        }
        // summaries: everything to a new neighbour, then what changes
        let due = c.lock().summaries(now, &neighbours);
        for (k, s) in due {
            let Ok(body) = encode_summary(s) else { continue };
            let Some(conn) = self.conn(&k) else { continue };
            let mut msg = vec![K_SUMMARY];
            msg.extend_from_slice(&body);
            let me = self.clone();
            self.keep(tokio::spawn(async move {
                // (opening waits while the neighbour has as many streams from us as it allows)
                let open = crate::resources::within(crate::resources::REPLY_TIMEOUT, "no stream", conn.open_uni());
                let sent = match open.await {
                    Ok(mut tx) => crate::resources::write_all(&mut tx, &msg).await.is_ok() && tx.finish().is_ok(),
                    Err(_) => false,
                };
                // it may have heard nothing: tell it everything next time
                if !sent && let Some(c) = &me.carrier {
                    c.lock().new_contact(k);
                }
            }));
        }
        // what can move now: live/partial routes, gradient, spray
        let plan = {
            let mut carrier = c.lock();
            carrier.tick(now);
            let router = &self.router;
            let mut outs = Vec::new();
            let plan = carrier.plan(
                now,
                |dst| {
                    let mut r = router.lock();
                    let t = r.toward(dst, now);
                    r.drain(&mut outs);
                    t
                },
                &neighbours,
            );
            drop(carrier);
            if !outs.is_empty() {
                self.exec(outs);
            }
            plan
        };
        // (deliveries first: the plan is in order of importance)
        for t in plan {
            let slot = {
                let mut sending = self.sending.lock();
                let ids = sending.entry(t.to).or_default();
                if ids.contains(&t.id) {
                    continue; // still on its way there (a slow link)
                }
                (ids.len() < SENDS_PER_NEIGHBOUR && ids.insert(t.id)).then(|| SendSlot {
                    d: self.clone(),
                    to: t.to,
                    id: t.id,
                })
            };
            let Some(slot) = slot else {
                // its turn comes when one of those ends
                c.lock().transferred(t.to, t.id, t.copies, false, now);
                continue;
            };
            let Some(b) = c.lock().bundle(&t.id).cloned() else { continue };
            let Some(conn) = self.conn(&t.to) else {
                c.lock().transferred(t.to, t.id, t.copies, false, now);
                continue;
            };
            let me = self.clone();
            // (from the connection itself: a hop replaced since `conn` was
            // read can't pair this connection with another's version)
            let version = hop_version(&conn);
            self.keep(tokio::spawn(async move {
                let _slot = slot;
                let frames = me.frames.peer(&t.to);
                let sent = send_bundle(&conn, version, &b, t.copies, &frames).await.unwrap_or(Sent::Failed);
                if let Some(c) = &me.carrier {
                    let mut c = c.lock();
                    match sent {
                        Sent::Took => c.transferred(t.to, t.id, t.copies, true, me.now()),
                        Sent::Failed => c.transferred(t.to, t.id, t.copies, false, me.now()),
                        Sent::Refused(full) => c.refused(t.to, t.id, full, me.now()),
                    }
                }
            }));
        }
    }

    /// Carry `payload` to `dst` whenever it can get there.
    fn send_bundle(
        &self,
        dst: SignPk,
        format: dtn::BundleFormat,
        payload: Bytes,
        lifetime: Duration,
    ) -> Option<Hash32> {
        let c = self.carrier.as_ref()?;
        if !format.checkable() {
            return None;
        }
        let id = bundle_id_of(format, &self.me, &dst, &payload);
        let created = wall_ms();
        let lifetime = lifetime.as_millis() as u64;
        let sig = sign_bundle(&self.keys, format, &id, created, lifetime);
        let b = dtn::Bundle { format, id, src: self.me, dst, created, lifetime, payload, sig };
        c.lock().originate(b, self.now()).ok()?;
        Some(id)
    }

    fn stats(&self) -> MeshStats {
        let mut s = self.router.lock().stats();
        s.dropped_queue += self.dropped_queue.load(Ordering::Relaxed);
        s.dropped_too_big += self.dropped_too_big.load(Ordering::Relaxed);
        s
    }

    /// Our internet cost as a gateway (0.1 ms units): set, or the mean cost
    /// of our internet hops, or a guess until there are any.
    fn uplink_cost(&self) -> u32 {
        if let Some(u) = *self.uplink.lock() {
            return u;
        }
        let rtts: Vec<u32> = {
            let hops = self.hops.lock();
            hops.values()
                .filter(|h| !h.direct)
                .filter_map(|h| {
                    let conn = h.live()?;
                    let (path, rtt) = hop_path(conn)?;
                    hop_cost(conn, path, rtt)
                })
                .collect()
        };
        if rtts.is_empty() { core::DEFAULT_INTERNET_COST / 2 } else { rtts.iter().sum::<u32>() / rtts.len() as u32 }
    }

    fn internet_now(&self) -> bool {
        match self.opts.internet {
            Some(on) => on,
            None => self.endpoint.get().is_some_and(|ep| {
                use n0_watcher::Watcher;
                ep.home_relay_status().get().iter().any(|s| s.is_connected())
            }),
        }
    }
}

/// Background work: announce, pass announcements on, dial, measure, expire
/// and keep Iroh's mesh addresses current.
async fn run(d: Arc<Driver>) {
    let tick = Duration::from_millis(20);
    let mut next_slow = Instant::now();
    let mut next_dtn = Instant::now();
    let mut last_dtn = Instant::now();
    loop {
        tokio::time::sleep(tick).await;
        if d.stopped.load(Ordering::Relaxed) {
            return;
        }
        let slow = Instant::now() >= next_slow;
        let internet = slow.then(|| d.internet_now());
        let uplink = slow.then(|| d.uplink_cost());
        let name = d.name.lock().clone();
        let keys = d.keys.clone();
        d.with_router(|r, now| {
            if let Some(on) = internet {
                r.set_internet(on);
            }
            if let Some(u) = uplink {
                r.set_uplink(u);
            }
            if r.announce_due(now) {
                let o = r.next_announce(wall_ms());
                r.originate(wire::sign_announce(&keys, o, &name), now);
            }
            r.tick(now);
        });
        if slow {
            next_slow = Instant::now() + Duration::from_millis(250);
            d.dial_missing();
            d.measure();
        }
        let soon = d.dtn_due.load(Ordering::Relaxed) && last_dtn.elapsed() >= DTN_SOON;
        if soon || Instant::now() >= next_dtn {
            d.dtn_due.store(false, Ordering::Relaxed);
            last_dtn = Instant::now();
            next_dtn = last_dtn + DTN_EVERY;
            d.dtn_tick();
        }
    }
}

// ─────────────────────────────── public API ───────────────────────────────

/// This device's mesh router. A [`Link`] to the node: its transport carries
/// QUIC packets to devices with no direct path, and it reports them (and
/// their routes) like any link reports peers.
#[derive(Clone)]
pub struct Mesh {
    d: Arc<Driver>,
}

impl std::fmt::Debug for Mesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mesh({})", self.d.me.short())
    }
}

impl Mesh {
    pub fn new(keys: Arc<DeviceKeys>, name: &str, opts: MeshOptions) -> Mesh {
        let (inbox, rx) = mpsc::channel(INBOX);
        let me = keys.sign_pk();
        let directory = opts.directory.clone();
        let carrier = opts.store_and_forward.clone().map(|c| {
            let mut c = dtn::Carrier::new(me, c);
            c.set_clock(0, wall_ms());
            Mutex::new(c)
        });
        let mut router = Router::new(me, opts.config());
        router.set_internet(opts.internet.unwrap_or(false));
        let d = Arc::new(Driver {
            me,
            keys,
            name: Mutex::new(name.to_string()),
            router: Mutex::new(router),
            hops: Mutex::default(),
            base: Instant::now(),
            opts,
            endpoint: Default::default(),
            events: Default::default(),
            inbox,
            inbox_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            stopped: AtomicBool::new(false),
            tasks: Mutex::default(),
            tap: Mutex::default(),
            dropped_queue: Default::default(),
            dropped_too_big: Default::default(),
            uplink: Mutex::default(),
            directory: Mutex::new(directory),
            records: Mutex::default(),
            records_published: Default::default(),
            carrier,
            bundle_sink: Mutex::default(),
            sending: Mutex::default(),
            dtn_due: AtomicBool::new(false),
            frames: crate::resources::Frames::neighbours(),
            watched: Mutex::default(),
            black_hole: Mutex::default(),
        });
        Mesh { d }
    }

    /// Start routing on `endpoint` (which must serve [`ALPN`] with
    /// [`Mesh::protocol`]).
    pub fn attach(&self, endpoint: Endpoint) {
        if self.d.endpoint.set(endpoint).is_ok() {
            let task = tokio::spawn(run(self.d.clone()));
            self.d.keep(task);
        }
    }

    /// The handler for incoming hop connections.
    pub fn protocol(&self) -> MeshProtocol {
        MeshProtocol { d: self.d.clone() }
    }

    /// `peer` is (or no longer is) reachable directly: on a link or the LAN.
    pub fn set_direct(&self, peer: SignPk, direct: bool) {
        self.d.set_direct(peer, direct);
    }

    /// The route behind a mesh address (`mesh(dst, via)`), if we have one.
    pub fn route_info(&self, addr: &CustomAddr) -> Option<MeshRoute> {
        let (dst, via) = parse_mesh_addr(addr)?;
        let r = self.d.router.lock();
        let via_name = r.origin_name(&via).map(|n| n.to_string());
        match r.route_hops(&dst, &via) {
            Some(hops) => Some(MeshRoute { via, via_name, hops, gateway: false }),
            None => Some(MeshRoute { via, via_name, hops: 0, gateway: true }),
        }
    }

    /// Devices reachable only through the mesh right now.
    pub fn reachable(&self) -> Vec<SignPk> {
        self.d.router.lock().reachable()
    }

    /// Neighbours with a hop connection up.
    pub fn connected_neighbours(&self) -> Vec<SignPk> {
        self.d.router.lock().neighbours().into_iter().map(|(k, _)| k).collect()
    }

    pub fn stats(&self) -> MeshStats {
        self.d.stats()
    }

    /// Carry `payload` to `dst` through others when it can't go live:
    /// along any live part of the way, toward the internet, to its
    /// gateways' mailboxes. `None` if store-and-forward is off.
    pub fn send_bundle(&self, dst: SignPk, payload: Bytes, lifetime: Duration) -> Option<Hash32> {
        self.d.send_bundle(dst, dtn::BundleFormat::V1, payload, lifetime)
    }

    /// [`Mesh::send_bundle`] in another format: a version 2 bundle names its
    /// payload kind, and carriers older than version 2 don't take it (so
    /// it travels only through carriers that speak version 2). `None` also
    /// for a format this build can't sign.
    pub fn send_bundle_as(
        &self,
        dst: SignPk,
        format: dtn::BundleFormat,
        payload: Bytes,
        lifetime: Duration,
    ) -> Option<Hash32> {
        self.d.send_bundle(dst, format, payload, lifetime)
    }

    /// Where bundles for us go: `(source, payload kind, payload)`.
    pub fn set_bundle_sink(&self, tx: mpsc::UnboundedSender<(SignPk, u16, Bytes)>) {
        *self.d.bundle_sink.lock() = Some(tx);
    }

    /// What was agreed with a neighbour on our hop connection to it: the
    /// wire version, and the capabilities once its hello has arrived.
    pub fn neighbour_protocol(&self, peer: &SignPk) -> Option<PeerProtocol> {
        self.d.hops.lock().get(peer).filter(|h| h.live().is_some()).and_then(|h| h.protocol)
    }

    pub fn dtn_stats(&self) -> dtn::DtnStats {
        self.d.carrier.as_ref().map(|c| c.lock().stats()).unwrap_or_default()
    }

    /// Whether this device holds bundle `id` (for others or its own).
    pub fn holds_bundle(&self, id: &Hash32) -> bool {
        self.d.carrier.as_ref().is_some_and(|c| c.lock().holds(id))
    }

    /// Where records are published and looked up (the node sets the pkarr
    /// relay and DHT directory once its endpoint exists).
    pub fn set_directory(&self, dir: Arc<dyn directory::Directory>) {
        *self.d.directory.lock() = Some(dir);
    }

    /// The address lookup to add to the endpoint: mesh addresses through
    /// gateways for devices beyond our mesh.
    pub fn address_lookup(&self) -> MeshLookup {
        MeshLookup { d: self.d.clone() }
    }

    /// The gateways our record names (empty while we have the internet).
    pub fn my_gateways(&self) -> Vec<SignPk> {
        self.d.router.lock().my_gateways().to_vec()
    }

    /// Whether the mesh currently thinks we reach the internet.
    pub fn has_internet(&self) -> bool {
        self.d.router.lock().internet()
    }

    /// Records this device published for others, as a gateway.
    pub fn records_published(&self) -> u64 {
        self.d.records_published.load(Ordering::Relaxed)
    }

    /// Fix this device's announced internet cost (0.1 ms units) instead of
    /// measuring it (tests; a metered or satellite uplink).
    pub fn set_uplink(&self, units: Option<u32>) {
        *self.d.uplink.lock() = units;
    }

    /// How far devices are from us in our spaces' membership graph (1: a
    /// member of a space we are in): routes through relays farther away, or
    /// not listed, rank costlier (`Router::set_affinity`). Nothing about it
    /// is sent.
    pub fn set_affinity(&self, table: impl IntoIterator<Item = (SignPk, u8)>) {
        self.d.with_router(|r, now| {
            if r.set_affinity(table) {
                r.tick(now); // the routes we offer may change
            }
        });
    }

    /// Whether routes are ranked by [`Mesh::set_affinity`]'s table
    /// ([`MeshOptions::defences`]); if not, there is no need to build it.
    pub fn uses_affinity(&self) -> bool {
        self.d.router.lock().config().defences.affinity
    }

    /// `peer`'s distance as [`Mesh::set_affinity`] last set it.
    pub fn affinity(&self, peer: &SignPk) -> Option<u8> {
        self.d.router.lock().affinity(peer)
    }

    /// Tests: see every payload this device relays for others.
    pub fn set_tap(&self, tap: Option<Tap>) {
        *self.d.tap.lock() = tap;
    }
}

impl Link for Mesh {
    fn kind(&self) -> PathKind {
        PathKind::Mesh
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(MeshTransport { d: self.d.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        let _ = self.d.events.set(events);
        Ok(())
    }

    fn set_name(&self, name: &str) {
        *self.d.name.lock() = name.to_string();
    }

    fn status(&self) -> LinkStatus {
        let r = self.d.router.lock();
        let neighbours = r.neighbours().iter().filter(|(_, direct)| *direct).count();
        let relay = r.config().relay;
        let gateway = r.my_gateways().first().map(|g| r.origin_name(g).map_or_else(|| g.short(), |n| n.to_string()));
        let mut detail = match (neighbours, relay) {
            (0, _) => "No Mycel devices nearby to relay through".to_string(),
            (n, true) => format!("{n} nearby, relaying for others"),
            (n, false) => format!("{n} nearby, not relaying for others"),
        };
        if let Some(g) = gateway {
            detail.push_str(&format!("; internet via {g}"));
        } else if r.internet() && neighbours > 0 && relay {
            detail.push_str("; a gateway for them");
        }
        LinkStatus {
            kind: PathKind::Mesh,
            label: None,
            active: self.d.endpoint.get().is_some() && !self.d.stopped.load(Ordering::Relaxed),
            detail: Some(detail),
            peers: r.reachable().len(),
        }
    }

    fn stop(&self) {
        self.d.stopped.store(true, Ordering::SeqCst);
        for t in self.d.tasks.lock().drain(..) {
            t.abort();
        }
        let mut hops = self.d.hops.lock();
        for h in hops.values() {
            if let Some(c) = h.live() {
                c.close(0u32.into(), b"bye");
            }
        }
        hops.clear();
    }
}

/// Accepts hop connections from neighbours (anyone nearby: relaying needs
/// no membership; budgets bound what they can make us carry).
#[derive(Clone)]
pub struct MeshProtocol {
    d: Arc<Driver>,
}

impl std::fmt::Debug for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshProtocol")
    }
}

impl ProtocolHandler for MeshProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let closed = conn.clone();
        self.d.add_conn(conn);
        closed.closed().await;
        Ok(())
    }
}

// ───────────────────────────── store and forward ─────────────────────────────

/// Bundle ids and signatures, version 1 (the context predates versioning).
const BUNDLE_CTX: &str = "mycel/v0/dtn-bundle";
/// Version 2 signatures (over the format too) and ids (over the kind too).
const BUNDLE_V2_CTX: &str = "mycel/v2/dtn-bundle";
const BUNDLE_V2_ID_CTX: &str = "mycel/v2/dtn-bundle-id";
const RECEIPT_CTX: &str = "mycel/v0/dtn-receipt";
/// Uni-stream kinds (first byte): a summary; a capability hello (v2).
const K_SUMMARY: u8 = 1;
const K_HELLO: u8 = 2;
/// Bi-stream kinds: a bundle offer; a versioned one (v2 hops).
const K_OFFER: u8 = 3;
const K_OFFER_V2: u8 = 4;
const MAX_SUMMARY: usize = 256 * 1024;
const MAX_OFFER: usize = 1024;
const DTN_EVERY: Duration = Duration::from_secs(1);
/// ... or this soon after a transfer ended, to start the next one.
const DTN_SOON: Duration = Duration::from_millis(100);
/// Bundles handed to one neighbour at once. More would only share its link:
/// over a slow radio, bundles sent a few at a time get through whole before
/// the contact ends, where all at once each would get a part. (QUIC's stream
/// limit would only make the rest wait, unplanned work for nobody.)
const SENDS_PER_NEIGHBOUR: usize = 8;

/// A bundle offered before its payload.
#[derive(Serialize, Deserialize)]
struct WireOffer {
    id: Hash32,
    src: SignPk,
    dst: SignPk,
    size: u64,
    created: u64,
    lifetime: u64,
    sig: mycel_crypto::Sig,
    copies: u8,
}

/// What a [`K_OFFER_V2`] offer adds in front of the offer itself.
#[derive(Serialize, Deserialize)]
struct WireFormat {
    version: u8,
    kind: u16,
}

#[derive(Serialize, Deserialize)]
enum WireAnswer {
    Take(u64),
    Duplicate,
    /// Refused; `true` if for lack of room.
    Refuse(bool),
}

impl From<dtn::Answer> for WireAnswer {
    fn from(a: dtn::Answer) -> Self {
        match a {
            dtn::Answer::Take { from } => WireAnswer::Take(from),
            dtn::Answer::Duplicate => WireAnswer::Duplicate,
            dtn::Answer::Refuse(why) => WireAnswer::Refuse(why == "store full"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WireSummary {
    /// `ids` are all it holds (else: what it took since its last summary).
    full: bool,
    ids: Vec<Hash32>,
    receipts: Vec<(Hash32, SignPk, mycel_crypto::Sig)>,
    preds: Vec<(SignPk, f32)>,
    free: u64,
    /// (ms until it expires, size) of what could make way.
    evictable: Vec<(u64, u64)>,
    /// Destinations it asks our predictabilities for.
    wants: Vec<SignPk>,
}

/// A neighbour's summary stream, after its kind byte.
pub(crate) fn decode_summary(body: &[u8]) -> Result<dtn::Summary> {
    let w: WireSummary = postcard::from_bytes(body)?;
    Ok(dtn::Summary {
        full: w.full,
        ids: w.ids,
        receipts: w.receipts.into_iter().map(|(id, dst, sig)| dtn::Receipt { id, dst, sig }).collect(),
        preds: w.preds,
        free: w.free,
        evictable: w.evictable,
        wants: w.wants,
    })
}

/// [`WireSummary`] borrowed from a [`dtn::Summary`], for encoding: the
/// same fields in the same order, so the same bytes.
#[derive(Serialize)]
struct WireSummaryRef<'a> {
    full: bool,
    ids: &'a [Hash32],
    receipts: WireReceipts<'a>,
    preds: &'a [(SignPk, f32)],
    free: u64,
    evictable: &'a [(u64, u64)],
    wants: &'a [SignPk],
}

/// Receipts as [`WireSummary`] has them: `(id, dst, sig)` tuples.
struct WireReceipts<'a>(&'a [dtn::Receipt]);

impl Serialize for WireReceipts<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter().map(|r| (r.id, r.dst, r.sig)))
    }
}

impl<'a> WireSummaryRef<'a> {
    fn of(s: &'a dtn::Summary) -> Self {
        WireSummaryRef {
            full: s.full,
            ids: &s.ids,
            receipts: WireReceipts(&s.receipts),
            preds: &s.preds,
            free: s.free,
            evictable: &s.evictable,
            wants: &s.wants,
        }
    }
}

/// Our summary for a neighbour, without its kind byte.
pub(crate) fn encode_summary(s: dtn::Summary) -> Result<Vec<u8>> {
    crate::wire::encode_bounded(&WireSummaryRef::of(&s), MAX_SUMMARY - 1)
}

// What the store-and-forward exchanges put on their streams, measured with
// the encoders above but without allocating: the tier-2 simulator
// (`mycel-sim`) charges these, so a format change shows up in its byte
// counts.

/// The bytes before a [`write_frame`] frame's body (its length, `u32`).
pub const STREAM_FRAME_PREFIX: usize = 4;
/// The carrier's one-byte verdict after a bundle's payload ("took it").
pub const BUNDLE_VERDICT_LEN: usize = 1;

/// A summary's uni-stream: its kind byte and the summary; `None` if it is
/// too large to send (the node then sends none).
pub fn summary_stream_len(s: &dtn::Summary) -> Option<usize> {
    crate::wire::encoded_size(&WireSummaryRef::of(s), MAX_SUMMARY - 1).ok().map(|n| 1 + n)
}

/// An offer's first frame on its bi-stream, length prefix included, on a
/// hop of wire `version`; `None` if that hop can't take the bundle (see
/// [`encode_offer`]).
pub fn offer_stream_len(version: WireVersion, o: &dtn::Offer) -> Option<usize> {
    encode_offer(version, o).ok().flatten().map(|m| STREAM_FRAME_PREFIX + m.len())
}

/// The answer's frame back on the offer's stream, length prefix included.
pub fn answer_stream_len(a: dtn::Answer) -> usize {
    let body = crate::wire::encoded_size(&WireAnswer::from(a), 64).expect("an answer is a few bytes");
    STREAM_FRAME_PREFIX + body
}

/// Our offer `o` on a hop of wire `version` (its first frame's body, kind
/// byte included); `None` if that hop can't take the bundle (a version 1
/// hop only takes version 1 bundles: it would take any other as a version
/// 1 bundle and find the signature bad).
pub(crate) fn encode_offer(version: WireVersion, o: &dtn::Offer) -> Result<Option<Vec<u8>>> {
    let offer = WireOffer {
        id: o.id,
        src: o.src,
        dst: o.dst,
        size: o.size,
        created: o.created,
        lifetime: o.lifetime,
        sig: o.sig,
        copies: o.copies,
    };
    Ok(Some(if version >= WIRE_V2 {
        let format = WireFormat { version: o.format.version, kind: o.format.kind };
        let mut msg = vec![K_OFFER_V2];
        msg.extend_from_slice(&crate::wire::encode_bounded(&(format, offer), MAX_OFFER - 1)?);
        msg
    } else if o.format == dtn::BundleFormat::V1 {
        let mut msg = vec![K_OFFER];
        msg.extend_from_slice(&crate::wire::encode_bounded(&offer, MAX_OFFER - 1)?);
        msg
    } else {
        return Ok(None);
    }))
}

/// A neighbour's bundle offer (its first frame, kind byte included), in
/// the format it names (a version 1 offer is of a version 1 bundle);
/// `None` for an offer kind this build doesn't know (left unanswered).
/// The format may be one this build can't check: the caller refuses it.
pub(crate) fn decode_offer(head: &[u8]) -> Result<Option<dtn::Offer>> {
    let (format, w) = match head.split_first() {
        Some((&K_OFFER, body)) => (dtn::BundleFormat::V1, postcard::from_bytes::<WireOffer>(body)?),
        Some((&K_OFFER_V2, body)) => {
            let (f, w): (WireFormat, WireOffer) = postcard::from_bytes(body)?;
            (dtn::BundleFormat { version: f.version, kind: f.kind }, w)
        }
        _ => return Ok(None),
    };
    Ok(Some(dtn::Offer {
        format,
        id: w.id,
        src: w.src,
        dst: w.dst,
        size: w.size,
        created: w.created,
        lifetime: w.lifetime,
        copies: w.copies,
        sig: w.sig,
    }))
}

/// A neighbour's answer to our offer: `Ok(Some(from))` to send the payload
/// from byte `from`, `Ok(None)` if it has the bundle, `Err(full)` if refused
/// (`true` for lack of room).
pub(crate) fn decode_answer(body: &[u8]) -> Result<std::result::Result<Option<u64>, bool>> {
    Ok(match postcard::from_bytes::<WireAnswer>(body)? {
        WireAnswer::Take(at) => Ok(Some(at)),
        WireAnswer::Duplicate => Ok(None),
        WireAnswer::Refuse(full) => Err(full),
    })
}

/// A bundle's id: the same data for the same destination is the same bundle
/// (a version 1 bundle: what [`Mesh::send_bundle`] sends).
pub fn bundle_id(src: &SignPk, dst: &SignPk, payload: &[u8]) -> Hash32 {
    bundle_id_of(dtn::BundleFormat::V1, src, dst, payload)
}

/// A bundle's id in `format`: version 2 ids also cover the payload kind,
/// so the same bytes as another kind are another bundle.
pub fn bundle_id_of(format: dtn::BundleFormat, src: &SignPk, dst: &SignPk, payload: &[u8]) -> Hash32 {
    let mut h = if format.version == dtn::BUNDLE_V1 {
        mycel_crypto::Digest::new(BUNDLE_CTX)
    } else {
        let mut h = mycel_crypto::Digest::new(BUNDLE_V2_ID_CTX);
        h.update(&format.kind.to_be_bytes());
        h
    };
    h.update(&src.0).update(&dst.0).update(payload);
    h.finalize()
}

/// The signature context of a bundle header in `format`, and what is
/// signed before `(id, created, lifetime)`: nothing in version 1, the
/// version and kind in version 2. (Only for formats that are checkable.)
fn bundle_signed(format: dtn::BundleFormat) -> (&'static str, Vec<u8>) {
    if format.version == dtn::BUNDLE_V1 {
        (BUNDLE_CTX, Vec::new())
    } else {
        let k = format.kind.to_be_bytes();
        (BUNDLE_V2_CTX, vec![format.version, k[0], k[1]])
    }
}

/// Sign a bundle header in `format`'s rules (one this build can check).
fn sign_bundle(
    keys: &DeviceKeys,
    format: dtn::BundleFormat,
    id: &Hash32,
    created: u64,
    lifetime: u64,
) -> mycel_crypto::Sig {
    let (ctx, head) = bundle_signed(format);
    keys.sign(ctx, &[&head, &id.0, &created.to_be_bytes(), &lifetime.to_be_bytes()])
}

/// The source's signature over a bundle header, in its format's rules.
fn bundle_sig_ok(
    format: dtn::BundleFormat,
    src: &SignPk,
    id: &Hash32,
    created: u64,
    lifetime: u64,
    sig: &mycel_crypto::Sig,
) -> bool {
    if !format.checkable() {
        return false;
    }
    let (ctx, head) = bundle_signed(format);
    src.verify(ctx, &[&head, &id.0, &created.to_be_bytes(), &lifetime.to_be_bytes()], sig).is_ok()
}

fn verify_bundle(b: &dtn::Bundle) -> bool {
    b.format.checkable()
        && b.id == bundle_id_of(b.format, &b.src, &b.dst, &b.payload)
        && bundle_sig_ok(b.format, &b.src, &b.id, b.created, b.lifetime, &b.sig)
        && b.created.saturating_add(b.lifetime) > wall_ms()
}

fn verify_receipt(r: &dtn::Receipt) -> bool {
    r.dst.verify(RECEIPT_CTX, &[&r.id.0], &r.sig).is_ok()
}

fn verify_offer(o: &dtn::Offer) -> bool {
    bundle_sig_ok(o.format, &o.src, &o.id, o.created, o.lifetime, &o.sig)
        && o.created.saturating_add(o.lifetime) > wall_ms()
}

/// How handing a bundle on went.
enum Sent {
    /// The neighbour has it (or had it).
    Took,
    /// It didn't get there (the link, a timeout): try again later.
    Failed,
    /// The neighbour said no; `true` if for lack of room.
    Refused(bool),
}

/// Hand a bundle over a hop connection of wire `version`: offer it, and
/// send the payload (the rest of it, if an earlier transfer was cut) only
/// if it is wanted. A version 1 hop only takes version 1 bundles.
async fn send_bundle(
    conn: &Connection,
    version: WireVersion,
    b: &dtn::Bundle,
    copies: u8,
    frames: &crate::resources::PeerFrames,
) -> Result<Sent> {
    let Some(msg) = encode_offer(version, &dtn::Offer::of(b, copies))? else {
        // (it would take it as a version 1 bundle and find the signature bad)
        return Ok(Sent::Refused(false));
    };
    // (waits while the neighbour has as many streams from us as it allows)
    let (mut tx, mut rx) =
        crate::resources::within(crate::resources::REPLY_TIMEOUT, "no stream", conn.open_bi()).await?;
    write_frame(&mut tx, &msg).await?;
    let (answer, _answer_permit) =
        read_frame(&mut rx, 64, crate::resources::reply_timeout(4 + msg.len()), frames).await?;
    let at = match decode_answer(&answer)? {
        Ok(None) => return Ok(Sent::Took),
        Err(full) => return Ok(Sent::Refused(full)),
        // (a 32-bit device must not truncate an offset beyond the payload)
        Ok(Some(at)) => usize::try_from(at).unwrap_or(usize::MAX).min(b.payload.len()),
    };
    crate::resources::write_all(&mut tx, &b.payload[at..]).await?;
    tx.finish()?;
    // The payload written may still be queued for a slow link.
    let wait = crate::resources::reply_timeout(b.payload.len() - at);
    let ack = crate::resources::within(wait, "no receipt", rx.read_to_end(1)).await?;
    Ok(if ack.first() == Some(&1) { Sent::Took } else { Sent::Refused(false) })
}

/// A length-prefixed frame on a stream that goes on after it.
async fn write_frame(tx: &mut iroh::endpoint::SendStream, body: &[u8]) -> Result<()> {
    anyhow::ensure!(body.len() <= crate::wire::MAX_FRAME, "frame too large");
    let prefix: [u8; STREAM_FRAME_PREFIX] = (body.len() as u32).to_be_bytes();
    crate::resources::write_all(tx, &prefix).await?;
    crate::resources::write_all(tx, body).await?;
    Ok(())
}

/// `wait`: for its first bytes (see [`crate::wire::recv_held`]).
async fn read_frame(
    rx: &mut iroh::endpoint::RecvStream,
    max: usize,
    wait: Duration,
    frames: &crate::resources::PeerFrames,
) -> Result<(Vec<u8>, crate::resources::FramePermit)> {
    let mut len = [0u8; 4];
    crate::resources::within(wait, "no answer", rx.read_exact(&mut len)).await?;
    let len = u32::from_be_bytes(len) as usize;
    anyhow::ensure!(len <= max, "frame of {len} bytes");
    let permit = frames.admit(len).await?;
    crate::resources::read_body(rx, len, false, permit, crate::resources::IDLE_TIMEOUT).await
}

/// An Iroh address lookup: for a device beyond our mesh, one mesh address
/// per gateway (`mesh(dst, via G)`), each its own QUIC path.
#[derive(Clone)]
pub struct MeshLookup {
    d: Arc<Driver>,
}

impl std::fmt::Debug for MeshLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MeshLookup")
    }
}

impl iroh::address_lookup::AddressLookup for MeshLookup {
    fn resolve(
        &self,
        endpoint_id: iroh::EndpointId,
    ) -> Option<n0_future::boxed::BoxStream<Result<iroh::address_lookup::Item, iroh::address_lookup::Error>>> {
        use n0_future::StreamExt;
        let d = self.d.clone();
        let peer = to_sign_pk(&endpoint_id);
        let stream = n0_future::stream::once_future(async move {
            let addrs = d.gateway_addrs(peer).await;
            (!addrs.is_empty()).then(|| {
                let data = iroh::endpoint_info::EndpointData::new(
                    addrs.into_iter().map(iroh::TransportAddr::Custom).collect(),
                );
                Ok(iroh::address_lookup::Item::new(
                    iroh::endpoint_info::EndpointInfo::from_parts(endpoint_id, data),
                    "mycel-mesh",
                    None,
                ))
            })
        })
        .filter_map(|x| x);
        Some(Box::pin(stream))
    }
}

// ───────────────────────────── Iroh transport ─────────────────────────────

#[derive(Debug)]
struct MeshTransport {
    d: Arc<Driver>,
}

impl CustomTransport for MeshTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.d.inbox_rx.clone().try_lock_owned().map_err(|_| io::Error::other("mesh already bound"))?;
        let local = mesh_addr(&self.d.me, &self.d.me);
        Ok(Box::new(MeshEndpoint {
            d: self.d.clone(),
            addrs: n0_watcher::Watchable::new(vec![local.clone()]),
            local,
            rx,
        }))
    }
}

struct MeshEndpoint {
    d: Arc<Driver>,
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
        Arc::new(MeshSender { d: self.d.clone() })
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
    d: Arc<Driver>,
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
            self.d.send_local(to, waypoint, packet);
        }
        // Like UDP: sent means handed on, not delivered.
        Poll::Ready(Ok(()))
    }
}
