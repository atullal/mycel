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
pub mod wire;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use mycel_crypto::{DeviceKeys, SignPk};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use self::core::{Config, Out, Router, Time};
pub use self::core::Stats as MeshStats;
pub use self::wire::{mesh_addr, parse_mesh_addr};
use self::wire::{MIN_QUIC_MTU, T_DATA, T_OGM};
use crate::link::{CustomAddr, Link, LinkEvent, LinkStatus, PathKind, TRANSPORT_MESH, n0_watcher, noq_udp};

/// Hop connections between neighbours (and internet hops to gateways).
pub const ALPN: &[u8] = b"mycel/mesh/1";

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
    /// With the internet: be a gateway between it and the mesh for others.
    pub gateway: bool,
    /// Bytes per second crossing between the internet and the mesh.
    pub gateway_rate: u64,
    /// Without the internet: how many gateways to publish in our record.
    pub gateways: usize,
    /// Whether this device reaches the internet; `None`: it does while
    /// connected to its home relay.
    pub internet: Option<bool>,
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

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn to_sign_pk(id: &iroh::EndpointId) -> SignPk {
    SignPk(*id.as_bytes())
}

/// The I/O side of one neighbour.
struct Hop {
    /// Seen directly (a link or the LAN), as opposed to only connected.
    direct: bool,
    direct_since: Instant,
    conn: Option<Connection>,
    /// Largest datagram buffer space seen = the buffer's size.
    dgram_cap: usize,
    dialing: bool,
    next_dial: Instant,
    failures: u32,
}

impl Hop {
    fn new(now: Instant) -> Self {
        Hop { direct: false, direct_since: now, conn: None, dgram_cap: 0, dialing: false, next_dial: now, failures: 0 }
    }

    fn live(&self) -> Option<&Connection> {
        self.conn.as_ref().filter(|c| c.close_reason().is_none())
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

    fn exec(self: &Arc<Self>, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Announce { to, ann } => {
                    if let Some(c) = self.conn(&to) {
                        let _ = c.send_datagram(wire::encode_announce(&ann));
                    }
                }
                Out::Frame { to, frame, relayed } => {
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
    }

    /// Put a frame on a hop connection: split to the hop's datagram size,
    /// tail-dropped if the hop is already backed up.
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
        drop(hops);
        let cwnd = conn
            .paths()
            .iter()
            .find(|p| p.is_selected())
            .and_then(|p| conn.congestion_state(p.id()))
            .map_or(0, |c| c.window() as usize);
        let bytes: usize = datagrams.iter().map(|d| d.len()).sum();
        if queued + bytes > (cwnd / QUEUE_CWND_DIV).max(MIN_QUEUE) {
            self.dropped_queue.fetch_add(1, Ordering::Relaxed);
            return;
        }
        for d in datagrams {
            if conn.send_datagram(d).is_err() {
                self.dropped_queue.fetch_add(1, Ordering::Relaxed);
            }
        }
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
            h.dgram_cap = conn.datagram_send_buffer_space();
            h.failures = 0;
        }
        self.with_router(|r, now| {
            r.hop_up(peer, now);
            r.tick(now);
        });
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
            for (pk, h) in hops.iter_mut() {
                let ours = self.me < *pk || now.duration_since(h.direct_since) >= DIAL_DEFER;
                if h.direct && h.live().is_none() && !h.dialing && now >= h.next_dial && ours {
                    h.dialing = true;
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
                    let mut hops = me.hops.lock();
                    if let Some(h) = hops.get_mut(&pk) {
                        h.dialing = false;
                        if !ok {
                            h.failures += 1;
                            h.next_dial = Instant::now() + Duration::from_secs((1u64 << h.failures.min(5)).min(30));
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

    /// An internet hop the router asked for: to a gateway, or to a device
    /// that is itself on the internet.
    fn dial_internet(self: &Arc<Self>, peer: SignPk) {
        let Some(ep) = self.endpoint.get().cloned() else {
            self.with_router(|r, now| r.dial_failed(peer, now));
            return;
        };
        let me = self.clone();
        let task = tokio::spawn(async move {
            let res = match iroh::PublicKey::from_bytes(&peer.0) {
                Ok(id) => tokio::time::timeout(DIAL_TIMEOUT, ep.connect(EndpointAddr::new(id), ALPN)).await.ok(),
                Err(_) => None,
            };
            match res {
                Some(Ok(conn)) => me.add_conn(conn),
                _ => me.with_router(|r, now| r.dial_failed(peer, now)),
            }
        });
        self.keep(task);
    }

    /// Hop cost: each hop connection's measured RTT.
    fn measure(self: &Arc<Self>) {
        let costs: Vec<(SignPk, u32)> = {
            let hops = self.hops.lock();
            hops.iter()
                .filter_map(|(pk, h)| {
                    let conn = h.live()?;
                    let rtt = conn.paths().iter().find(|p| p.is_selected()).map(|p| p.rtt())?;
                    (!rtt.is_zero()).then(|| (*pk, (rtt.as_micros() / 100).clamp(1, u32::MAX as u128 / 2) as u32))
                })
                .collect()
        };
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
            Some(&T_DATA) => {
                if let Some(f) = wire::decode_frame(d) {
                    self.with_router(|r, now| r.on_frame(from, f, now));
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

    fn on_control(self: &Arc<Self>, _from: SignPk, _payload: Bytes) {}

    fn resolve(self: &Arc<Self>, peer: SignPk) {
        // No directory: anyone we have no route to is dialed directly.
        self.with_router(|r, now| r.on_resolved(peer, None, now));
    }

    fn publish_reach(self: &Arc<Self>, _gateways: Vec<SignPk>) {}

    fn stats(&self) -> MeshStats {
        let mut s = self.router.lock().stats();
        s.dropped_queue += self.dropped_queue.load(Ordering::Relaxed);
        s.dropped_too_big += self.dropped_too_big.load(Ordering::Relaxed);
        s
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
    loop {
        tokio::time::sleep(tick).await;
        if d.stopped.load(Ordering::Relaxed) {
            return;
        }
        let slow = Instant::now() >= next_slow;
        let internet = slow.then(|| d.internet_now());
        let name = d.name.lock().clone();
        let keys = d.keys.clone();
        d.with_router(|r, now| {
            if let Some(on) = internet {
                r.set_internet(on);
            }
            if r.announce_due(now) {
                let seq = r.next_seq(wall_ms());
                let a = wire::sign_announce(&keys, seq, r.own_flags(), &name);
                r.originate(a, now);
            }
            r.tick(now);
        });
        if slow {
            next_slow = Instant::now() + Duration::from_millis(250);
            d.dial_missing();
            d.measure();
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
        LinkStatus {
            kind: PathKind::Mesh,
            label: None,
            active: self.d.endpoint.get().is_some() && !self.d.stopped.load(Ordering::Relaxed),
            detail: Some(match (neighbours, relay) {
                (0, _) => "No Mycel devices nearby to relay through".into(),
                (n, true) => format!("{n} nearby, relaying for others"),
                (n, false) => format!("{n} nearby, not relaying for others"),
            }),
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
