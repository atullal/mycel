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
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use self::core::{Config, Out, Router, Time};
pub use self::core::Stats as MeshStats;
pub use self::wire::{mesh_addr, parse_mesh_addr};
use self::wire::{MIN_QUIC_MTU, T_DATA, T_OGM, T_SEQREQ};
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

/// A hop's cost in 0.1 ms units: its RTT plus the time to move 64 KiB at
/// the rate its congestion window allows (cwnd per RTT), so a slow radio
/// with a low RTT doesn't look better than a fast one with a higher RTT.
fn hop_cost(conn: &Connection) -> Option<u32> {
    let paths = conn.paths();
    let path = paths.iter().find(|p| p.is_selected())?;
    let rtt = path.rtt();
    if rtt.is_zero() {
        return None;
    }
    let cwnd = conn.congestion_state(path.id()).map_or(0, |c| c.window()).max(1200) as f64;
    let secs = rtt.as_secs_f64() * (1.0 + 65_536.0 / cwnd);
    Some((secs * 10_000.0).clamp(1.0, (u32::MAX / 2) as f64) as u32)
}

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
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
    /// Uplink cost override (tests, or a known slow link).
    uplink: Mutex<Option<u32>>,
    directory: Mutex<Option<Arc<dyn directory::Directory>>>,
    /// Records looked up: target -> (gateways with cost, when). Shared with
    /// the address lookup.
    records: Mutex<HashMap<SignPk, Looked>>,
    records_published: std::sync::atomic::AtomicU64,
    carrier: Option<Mutex<dtn::Carrier>>,
    /// Where bundles for us go (the node ingests them).
    bundle_sink: Mutex<Option<mpsc::UnboundedSender<(SignPk, Bytes)>>>,
    last_summary: Mutex<HashMap<SignPk, Instant>>,
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
                Out::SeqReq { to, req } => {
                    if let Some(c) = self.conn(&to) {
                        let _ = c.send_datagram(wire::encode_seqreq(&req));
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
        self.last_summary.lock().remove(&peer); // tell it what we hold, soon
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
            hops.iter().filter_map(|(pk, h)| Some((*pk, hop_cost(h.live()?)?))).collect()
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
    /// bundles (datagrams carry routing and packets).
    async fn serve_streams(self: Arc<Self>, peer: SignPk, conn: Connection) {
        loop {
            tokio::select! {
                bi = conn.accept_bi() => {
                    let Ok((tx, rx)) = bi else { break };
                    let me = self.clone();
                    tokio::spawn(async move { let _ = me.on_bundle_stream(peer, tx, rx).await; });
                }
                uni = conn.accept_uni() => {
                    let Ok(rx) = uni else { break };
                    let me = self.clone();
                    tokio::spawn(async move { let _ = me.on_summary_stream(peer, rx).await; });
                }
            }
        }
    }

    async fn on_summary_stream(self: Arc<Self>, from: SignPk, mut rx: iroh::endpoint::RecvStream) -> Result<()> {
        let bytes = rx.read_to_end(MAX_SUMMARY).await?;
        let Some((&K_SUMMARY, body)) = bytes.split_first() else { return Ok(()) };
        let w: WireSummary = postcard::from_bytes(body)?;
        let s = dtn::Summary {
            ids: w.ids,
            receipts: w.receipts.into_iter().map(|(id, dst, sig)| dtn::Receipt { id, dst, sig }).collect(),
            preds: w.preds,
            free: w.free,
            evictable: w.evictable,
        };
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
        let head = read_frame(&mut rx, MAX_OFFER).await?;
        let Some((&K_OFFER, body)) = head.split_first() else { return Ok(()) };
        let w: WireOffer = postcard::from_bytes(body)?;
        let o = dtn::Offer {
            id: w.id,
            src: w.src,
            dst: w.dst,
            size: w.size,
            created: w.created,
            lifetime: w.lifetime,
            copies: w.copies,
            sig: w.sig,
        };
        let answer = {
            let mut c = c.lock();
            c.set_clock(self.now(), wall_ms());
            c.offered(from, &o, self.now(), verify_offer)
        };
        write_frame(&mut tx, &postcard::to_allocvec(&WireAnswer::from(answer))?).await?;
        let dtn::Answer::Take { from: at } = answer else {
            tx.finish()?;
            return Ok(());
        };
        // the payload from `at`: keep what arrives even if the link drops
        let mut payload = c.lock().partial(&o.id).map_or_else(Vec::new, |p| p.to_vec());
        payload.truncate(at as usize);
        if payload.len() as u64 != at {
            return Ok(()); // dropped meanwhile: the next offer starts over
        }
        let want = o.size as usize;
        let cut = loop {
            match rx.read_chunk(want.saturating_sub(payload.len()).max(1)).await {
                Ok(Some(chunk)) if payload.len() + chunk.len() <= want => payload.extend_from_slice(&chunk),
                Ok(Some(_)) => return Ok(()), // more than offered: not that bundle
                Ok(None) => break false,
                Err(_) => break true,
            }
        };
        if cut || payload.len() < want {
            if payload.len() as u64 > at {
                c.lock().keep_partial(o.id, o.src, Bytes::from(payload), self.now());
            }
            return Ok(());
        }
        let b = dtn::Bundle {
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
        tx.write_all(&[ok as u8]).await?;
        tx.finish()?;
        if let dtn::Accepted::ForMe(b) = got {
            let sig = self.keys.sign(RECEIPT_CTX, &[&b.id.0]);
            c.lock().add_receipt(dtn::Receipt { id: b.id, dst: self.me, sig });
            if let Some(sink) = self.bundle_sink.lock().as_ref() {
                let _ = sink.send((b.src, b.payload));
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
        // summaries: on a new neighbour at once, then every few seconds
        let due: Vec<SignPk> = {
            let mut last = self.last_summary.lock();
            last.retain(|k, _| neighbours.contains(k));
            neighbours
                .iter()
                .filter(|k| last.get(*k).is_none_or(|t| t.elapsed() >= SUMMARY_EVERY))
                .copied()
                .collect::<Vec<_>>()
                .into_iter()
                .inspect(|k| {
                    last.insert(*k, Instant::now());
                })
                .collect()
        };
        if !due.is_empty() {
            let s = c.lock().summary(now);
            let wire = WireSummary {
                ids: s.ids,
                receipts: s.receipts.into_iter().map(|r| (r.id, r.dst, r.sig)).collect(),
                preds: s.preds,
                free: s.free,
                evictable: s.evictable,
            };
            if let Ok(body) = postcard::to_allocvec(&wire) {
                let mut msg = vec![K_SUMMARY];
                msg.extend_from_slice(&body);
                let msg = Bytes::from(msg);
                for k in due {
                    let Some(conn) = self.conn(&k) else { continue };
                    let msg = msg.clone();
                    self.keep(tokio::spawn(async move {
                        if let Ok(mut tx) = conn.open_uni().await {
                            let _ = tx.write_all(&msg).await;
                            let _ = tx.finish();
                        }
                    }));
                }
            }
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
        for t in plan {
            let Some(b) = c.lock().bundle(&t.id).cloned() else { continue };
            let Some(conn) = self.conn(&t.to) else {
                c.lock().transferred(t.to, t.id, t.copies, false, now);
                continue;
            };
            let me = self.clone();
            self.keep(tokio::spawn(async move {
                let sent = send_bundle(&conn, &b, t.copies).await.unwrap_or(Sent::Failed);
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
    fn send_bundle(&self, dst: SignPk, payload: Bytes, lifetime: Duration) -> Option<Hash32> {
        let c = self.carrier.as_ref()?;
        let id = bundle_id(&self.me, &dst, &payload);
        let created = wall_ms();
        let lifetime = lifetime.as_millis() as u64;
        let sig = self.keys.sign(BUNDLE_CTX, &[&id.0, &created.to_be_bytes(), &lifetime.to_be_bytes()]);
        let b = dtn::Bundle { id, src: self.me, dst, created, lifetime, payload, sig };
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
            hops.values().filter(|h| !h.direct).filter_map(|h| hop_cost(h.live()?)).collect()
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
        if Instant::now() >= next_dtn {
            next_dtn = Instant::now() + DTN_EVERY;
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
            last_summary: Mutex::default(),
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
        self.d.send_bundle(dst, payload, lifetime)
    }

    /// Where bundles for us go: `(source, payload)`.
    pub fn set_bundle_sink(&self, tx: mpsc::UnboundedSender<(SignPk, Bytes)>) {
        *self.d.bundle_sink.lock() = Some(tx);
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

const BUNDLE_CTX: &str = "mycel/v0/dtn-bundle";
const RECEIPT_CTX: &str = "mycel/v0/dtn-receipt";
const K_SUMMARY: u8 = 1;
const K_OFFER: u8 = 3;
const MAX_SUMMARY: usize = 256 * 1024;
const MAX_OFFER: usize = 1024;
const SUMMARY_EVERY: Duration = Duration::from_secs(5);
const DTN_EVERY: Duration = Duration::from_secs(1);

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
    ids: Vec<Hash32>,
    receipts: Vec<(Hash32, SignPk, mycel_crypto::Sig)>,
    preds: Vec<(SignPk, f32)>,
    free: u64,
    /// (ms until it expires, size) of what could make way.
    evictable: Vec<(u64, u64)>,
}

/// A bundle's id: the same data for the same destination is the same bundle.
pub fn bundle_id(src: &SignPk, dst: &SignPk, payload: &[u8]) -> Hash32 {
    let mut h = mycel_crypto::Digest::new(BUNDLE_CTX);
    h.update(&src.0).update(&dst.0).update(payload);
    h.finalize()
}

fn verify_bundle(b: &dtn::Bundle) -> bool {
    b.id == bundle_id(&b.src, &b.dst, &b.payload)
        && b.src.verify(BUNDLE_CTX, &[&b.id.0, &b.created.to_be_bytes(), &b.lifetime.to_be_bytes()], &b.sig).is_ok()
        && b.created.saturating_add(b.lifetime) > wall_ms()
}

fn verify_receipt(r: &dtn::Receipt) -> bool {
    r.dst.verify(RECEIPT_CTX, &[&r.id.0], &r.sig).is_ok()
}

fn verify_offer(o: &dtn::Offer) -> bool {
    o.src.verify(BUNDLE_CTX, &[&o.id.0, &o.created.to_be_bytes(), &o.lifetime.to_be_bytes()], &o.sig).is_ok()
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

/// Hand a bundle over a hop connection: offer it, and send the payload
/// (the rest of it, if an earlier transfer was cut) only if it is wanted.
async fn send_bundle(conn: &Connection, b: &dtn::Bundle, copies: u8) -> Result<Sent> {
    let offer = WireOffer {
        id: b.id,
        src: b.src,
        dst: b.dst,
        size: b.payload.len() as u64,
        created: b.created,
        lifetime: b.lifetime,
        sig: b.sig,
        copies,
    };
    let mut msg = vec![K_OFFER];
    msg.extend_from_slice(&postcard::to_allocvec(&offer)?);
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_frame(&mut tx, &msg).await?;
    let answer = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut rx, 64)).await??;
    let at = match postcard::from_bytes::<WireAnswer>(&answer)? {
        WireAnswer::Duplicate => return Ok(Sent::Took),
        WireAnswer::Refuse(full) => return Ok(Sent::Refused(full)),
        WireAnswer::Take(at) => (at as usize).min(b.payload.len()),
    };
    tx.write_all(&b.payload[at..]).await?;
    tx.finish()?;
    let ack = tokio::time::timeout(Duration::from_secs(30), rx.read_to_end(1)).await??;
    Ok(if ack.first() == Some(&1) { Sent::Took } else { Sent::Refused(false) })
}

/// A length-prefixed frame on a stream that goes on after it.
async fn write_frame(tx: &mut iroh::endpoint::SendStream, body: &[u8]) -> Result<()> {
    tx.write_all(&(body.len() as u32).to_be_bytes()).await?;
    tx.write_all(body).await?;
    Ok(())
}

async fn read_frame(rx: &mut iroh::endpoint::RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    rx.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    anyhow::ensure!(len <= max, "frame of {len} bytes");
    let mut body = vec![0u8; len];
    rx.read_exact(&mut body).await?;
    Ok(body)
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
