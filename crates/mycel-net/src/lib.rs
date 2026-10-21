//! Mycel network layer (docs/TRUST.md §8): Spaces over Iroh, with live sync,
//! LAN discovery, invites, contact cards, ephemeral messages and blobs.
//!
//! The device's Ed25519 key *is* its Iroh endpoint id, so every QUIC
//! connection is authenticated to a device. On top of that, a device only
//! syncs a Space with its current members (any role, including Relay
//! keepers), and everything received is re-validated by the receiving
//! `Replica` — nothing is trusted because of who sent it.
//!
//! Connections: one protocol ([`wire::ALPN`], in every wire version the
//! node speaks: see [`version`] and docs/PROTOCOL.md), and a long-lived
//! connection per peer from a small connection pool (`pool.rs`; closed
//! after [`POOL_IDLE`] without use, redialed when it breaks). Every exchange
//! is a new QUIC stream on it, labelled by a [`wire::StreamKind`] byte; the
//! server accepts streams in a loop, and refuses a kind it doesn't know
//! with [`version::STREAM_REFUSED`]. QUIC does the multiplexing, flow
//! control and loss recovery; stream priorities send messages ahead of
//! file bytes. No handshake per sync, and the connection's extra paths
//! (links, other interfaces) stay open and measured. On wire version 2 the
//! dialer sends a capability hello ([`wire::StreamKind::Hello`]) on a
//! stream of its own, beside the exchange it dialed for: the two race, so
//! nothing may assume the hello arrives (or is answered) first, and a hello
//! that fails is tried again later on the same connection.
//!
//! Sync v2 (stream kind `SyncV2`, wire version 2 and later, `sync_v2.rs`
//! driving `mycel_sync::reconcile`): an idle check costs one round trip and
//! a few hundred bytes, a difference costs about what differs. It is used
//! with a peer whose hello agreed [`Caps::SYNC_V2`]; with any other peer,
//! or one that refuses the stream anyway, the opener uses v1 (stream kind
//! `Sync`), one bi-stream, strictly alternating so neither side can
//! deadlock on flow control:
//!
//! ```text
//! C → S  Hello{space, inv, invite?}
//! S → C  Denied | NeedInvite | Accept{inv, want}
//! C → S  DataAndWant{data, want}
//! S → C  Data{data}
//! ```
//!
//! Scheduling: after a change a device syncs the space with every member in
//! groups of up to [`FULL_MESH`] devices, and otherwise with a bounded view
//! (two nearby members, two chosen at random by rendezvous hash, and those
//! that recently chose it), forwarding what it learns the same way; so a
//! change costs O(members) sessions, not O(members²). Periodic
//! anti-entropy backs off from 15 s to 10 min while it finds nothing, and
//! returns to 15 s on signs of loss (a periodic session that moved items, a
//! membership change, a local write, a newly reachable peer).

mod blobs;
pub mod bundles;
pub mod emu;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
mod gossip;
pub mod link;
#[cfg(any(target_os = "macos", target_os = "ios", fuzzing))]
mod mdns_records;
pub mod mesh;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod native_mdns;
mod pool;
mod resources;
mod sync_v2;
pub mod version;
pub mod wire;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// parking_lot: no lock poisoning, so a panic can't wedge the whole node.
use parking_lot::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, PublicKey, SecretKey,
    address_lookup::{MemoryLookup, UserData},
    endpoint::{ConnectOptions, Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_sync::{EnvelopeId, FeedValidator, Replica, Store};
use mycel_trust::{Role, SignedOp, SpaceId};
use n0_future::StreamExt;
use pool::{Pool, PooledConn};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc};

pub use blobs::{EAGER_PUSH_MAX, MIN_FREE_SPACE, Progress, blob_digest, ensure_free_space, free_space, human_size};
pub use gossip::GossipTotals;
pub use iroh;
pub use link::{Link, LinkEvent, LinkStatus, PathKind, path_in_use};
pub use mesh::{Mesh, MeshOptions, MeshRoute, MeshStats, Tap};
pub use mycel_sync::reconcile::gossip::GossipStats;
pub use sync_v2::{V1_REMEMBERED, V1_SERVE_INTERVAL, V2Totals};
pub use version::{Caps, PeerProtocol, Protocol, VersionError, WireVersion};
use version::{Hello, STREAM_REFUSED, WIRE_V2};
use wire::*;
pub use wire::{ContactCard, MAX_EPHEMERAL};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// A pooled connection unused (no stream open from our side) this long is closed.
pub const POOL_IDLE: Duration = Duration::from_secs(60);
/// A sync not through by now is also handed to store-and-forward carriers
/// (the live attempt keeps going): a stale connection to a peer that moved
/// away only fails once the peer has had [`resources::REPLY_TIMEOUT`] to
/// answer, and a passer-by who could carry it may be gone by then.
const BUNDLE_AFTER: Duration = Duration::from_secs(10);
/// Bounds on how long a sync waits for a new connection's capability
/// hello before it uses v1 (see `hello_wait`).
const HELLO_WAIT_MIN: Duration = Duration::from_millis(750);
const HELLO_WAIT_MAX: Duration = Duration::from_secs(3);
/// How long [`Node::sync_with`] keeps retrying a peer that answers `Busy`.
pub const EXPLICIT_BUSY_WAIT: Duration = Duration::from_secs(300);
/// Background retries after `Busy` (see `sync_once`).
const BUSY_RETRIES: u32 = 3;
/// Periodic anti-entropy: the first interval, and the cap it backs off to
/// while periodic sessions find nothing.
const PERIODIC_SYNC: Duration = Duration::from_secs(15);
const PERIODIC_MAX: Duration = Duration::from_secs(600);
/// Groups up to this size sync every member after a change; larger ones a
/// bounded view (see the crate docs).
pub const FULL_MESH: usize = 6;
/// The bounded view: nearby members, random members, and at most this many
/// members that recently chose us.
const VIEW_NEARBY: usize = 2;
const VIEW_RANDOM: usize = 2;
const VIEW_INBOUND: usize = 8;
/// The author of a change pushes it to every member in groups up to this
/// size (one hop to everyone it can reach, O(members) sessions); larger
/// groups use the bounded view for the author too.
pub const AUTHOR_FULL: usize = 32;
/// Views are re-drawn this often.
const VIEW_EPOCH: Duration = Duration::from_secs(600);
/// How long shutting down waits for peers to acknowledge the close.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const ONLINE_WINDOW: Duration = Duration::from_secs(45);
/// Changes are pushed this long after they happen (coalescing a burst). Short:
/// a sync is one stream on a pooled connection, no handshake.
const DEBOUNCE: Duration = Duration::from_millis(5);
/// Store-and-forward bundles: the largest payload, and how long it is worth
/// delivering.
const MAX_BUNDLE_PAYLOAD: usize = 200 * 1024;
const BUNDLE_LIFETIME: Duration = Duration::from_secs(3 * 24 * 3600);
/// Max membership ops accepted in a pushed invite.
const MAX_INVITE_OPS: usize = 4096;

fn to_sign_pk(pk: &PublicKey) -> SignPk {
    SignPk(*pk.as_bytes())
}

pub(crate) fn to_endpoint_id(pk: &SignPk) -> Result<EndpointId> {
    Ok(PublicKey::from_bytes(&pk.0)?)
}

/// How the endpoint reaches the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    /// Loopback only, addresses added manually (tests).
    Local,
    /// Local network: direct addresses + mDNS discovery, no internet needed.
    Lan,
    /// LAN plus n0 relays, DNS discovery and hole punching.
    Internet,
}

/// Whether an authenticated member may push unsolicited blob bytes.
pub type BlobPushPolicy = Arc<dyn Fn(SignPk, SpaceId) -> bool + Send + Sync>;

/// Which pushed invites (spaces we didn't have) to accept.
pub type InvitePolicy = Arc<dyn Fn(&SignPk, &SpaceId) -> bool + Send + Sync>;

pub struct NodeOptions {
    pub mode: NetMode,
    /// Display name in the contact card and LAN advertisement.
    pub name: String,
    pub store: Option<Arc<dyn Store>>,
    /// Where blobs live. `None` disables blob storage.
    pub blob_dir: Option<PathBuf>,
    pub invite_policy: InvitePolicy,
    /// Additional consent gate for incoming Put/Offer, after membership.
    pub blob_push_policy: BlobPushPolicy,
    /// Accept invites that give us only the Relay role (keepers: yes;
    /// personal devices: no — otherwise anyone could use our disk).
    pub accept_relay_invites: bool,
    /// UDP port to bind (0 = random).
    pub port: u16,
    /// L4 rules applied to every feed entry in every space.
    pub feed_validator: Option<Arc<dyn FeedValidator>>,
    /// Extra non-IP paths (peer-to-peer Wi-Fi, Bluetooth...). Not in `Local` mode.
    pub links: Vec<Arc<dyn Link>>,
    /// Use IP at all (tests turn it off to force traffic onto links).
    pub ip: bool,
    /// More protocols on the same endpoint (e.g. live calls). Each gets the
    /// node's multipath connections, path selection and links for free.
    pub extra_protocols: Vec<ExtraProtocol>,
    /// Multi-hop relaying through nearby devices (`mesh.rs`); `None` = off.
    pub mesh: Option<MeshOptions>,
    /// The largest ephemeral payload sent or taken ([`MAX_EPHEMERAL`] by
    /// default; at most [`wire::MAX_FRAME`] less overhead). A device drops
    /// bigger ones unread, so an app that needs more raises it on every
    /// device. What is queued for the app (up to 1024 events) can hold
    /// that much per event.
    pub max_ephemeral: usize,
    /// The newest wire version offered and the capabilities advertised, on
    /// the node protocol and the mesh alike (docs/PROTOCOL.md). Default:
    /// everything this build speaks.
    pub protocol: Protocol,
    /// Speak Sync v2 (default). Off: behave as a build without it (don't
    /// advertise [`Caps::SYNC_V2`] even if `protocol` lists it, run only v1
    /// sessions, refuse `SyncV2` streams as an unknown kind, sync every
    /// member), for mixed groups in tests and v1 baselines. Off also turns
    /// gossip off.
    pub sync_v2: bool,
    /// Read receipts: share seen notes (which members hold which chains,
    /// sealed under the space's epoch key) so authors see "delivered to N"
    /// beyond the devices they synced with directly. Off by default.
    pub read_receipts: bool,
}

/// Another protocol served on the node's endpoint: incoming connections with
/// this ALPN are handed to `incoming`. The peer is authenticated (its key is
/// `Connection::remote_id`), but nothing else is checked: the receiver must
/// do its own authorization.
pub struct ExtraProtocol {
    pub alpn: Vec<u8>,
    pub incoming: mpsc::UnboundedSender<Connection>,
}

impl NodeOptions {
    pub fn new(mode: NetMode, name: impl Into<String>) -> Self {
        NodeOptions {
            mode,
            name: name.into(),
            store: None,
            blob_dir: None,
            invite_policy: Arc::new(|_, _| true),
            blob_push_policy: Arc::new(|_, _| true),
            accept_relay_invites: false,
            port: 0,
            feed_validator: None,
            links: Vec::new(),
            ip: true,
            extra_protocols: Vec::new(),
            mesh: None,
            max_ephemeral: MAX_EPHEMERAL,
            protocol: Protocol::default(),
            sync_v2: true,
            read_receipts: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// New ops/envelopes were ingested into a space (from sync or locally).
    SpaceChanged {
        space: SpaceId,
    },
    /// A space was pushed to us and accepted.
    SpaceAdded {
        space: SpaceId,
        from: SignPk,
    },
    Ephemeral {
        space: SpaceId,
        from: SignPk,
        data: Vec<u8>,
    },
    /// Directly discovered peer list or a peer's online status changed.
    PeersChanged,
    BlobStored {
        hash: Hash32,
    },
}

/// What one sync session transferred (counts of items *received*).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    pub ops: usize,
    pub envelopes: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PeerState {
    pub name: Option<String>,
    pub nearby: bool,
    pub last_ok: Option<Instant>,
    pub failures: u32,
    pub last_fail: Option<Instant>,
    /// Links (peer-to-peer Wi-Fi, Bluetooth) the peer is currently reachable on.
    pub links: BTreeSet<PathKind>,
    /// The path the last successful exchange actually used.
    pub via: Option<PathKind>,
    /// When `via` is the mesh: which neighbour it leaves through, how many hops.
    pub mesh: Option<MeshRoute>,
    /// The wire version and capabilities last agreed with the peer, on a
    /// connection either side dialed (`None`: none agreed yet).
    pub protocol: Option<PeerProtocol>,
}

impl PeerState {
    /// Currently discovered on the LAN or a direct device link. A mesh
    /// route or a recent successful exchange alone does not imply proximity.
    pub fn is_directly_discovered(&self) -> bool {
        self.nearby || self.links.iter().any(|kind| *kind != PathKind::Mesh)
    }

    pub fn online(&self) -> bool {
        self.nearby || !self.links.is_empty() || self.last_ok.is_some_and(|t| t.elapsed() < ONLINE_WINDOW)
    }

    /// Exponential backoff after failures: 2s, 4s, … capped at 60s.
    fn backing_off(&self) -> bool {
        match self.last_fail {
            Some(t) if self.failures > 0 => {
                let wait = Duration::from_secs((1u64 << self.failures.min(5)).min(60));
                t.elapsed() < wait
            }
            _ => false,
        }
    }
}

struct Inner {
    keys: Arc<DeviceKeys>,
    mode: NetMode,
    name: Mutex<String>,
    store: Option<Arc<dyn Store>>,
    blob_dir: Option<PathBuf>,
    invite_policy: InvitePolicy,
    blob_push_policy: BlobPushPolicy,
    accept_relay_invites: bool,
    feed_validator: Option<Arc<dyn FeedValidator>>,
    spaces: Mutex<HashMap<SpaceId, Replica>>,
    peers: Mutex<HashMap<SignPk, PeerState>>,
    /// Independent LAN discovery sources; loss of one cannot hide another.
    lan_sources: Mutex<HashMap<SignPk, BTreeSet<&'static str>>>,
    events: broadcast::Sender<NetEvent>,
    memory: MemoryLookup,
    /// Addresses learned from links, kept apart from contact-code hints so a
    /// lost link can drop exactly its own addresses.
    link_lookup: MemoryLookup,
    link_addrs: Mutex<HashMap<SignPk, HashSet<link::CustomAddr>>>,
    links: Vec<Arc<dyn Link>>,
    mesh: Option<Mesh>,
    endpoint: Endpoint,
    /// Spaces needing a push to all members; `None` key = everything (periodic).
    dirty: Mutex<HashSet<SpaceId>>,
    wake: Notify,
    /// Syncs running now; `true` = something changed meanwhile, run again.
    inflight: Mutex<HashMap<(SignPk, SpaceId), bool>>,
    sync_slots: Semaphore,
    /// Outgoing connections, one per peer, reused for every exchange.
    pool: Pool,
    /// Connections accepted from peers (each one is a QUIC handshake).
    accepted: AtomicU64,
    /// Blob bytes served to fetching members.
    blob_served: AtomicU64,
    /// Capability hellos answered (one per connection a v2 peer dials).
    hellos_served: AtomicU64,
    /// Capability hellos we sent that failed (see [`ConnectionCounts`]).
    hellos_failed: AtomicU64,
    /// Tests: refuse this many hellos we're sent, as a lossy path would.
    #[cfg(test)]
    drop_hellos: std::sync::atomic::AtomicU32,
    /// Tests: never answer hellos.
    #[cfg(test)]
    stall_hellos: std::sync::atomic::AtomicBool,
    /// The last store-and-forward bundle sent per (member, space).
    /// Store-and-forward state (`bundles.rs`).
    bundles: Mutex<bundles::Bundles>,
    /// The most recent connections (dialed and accepted), for byte counts.
    conns: Mutex<std::collections::VecDeque<Connection>>,
    /// See [`NodeOptions::max_ephemeral`].
    max_ephemeral: usize,
    /// Dissemination (`gossip.rs`).
    gossip: gossip::Gossip,
    read_receipts: bool,
    /// See [`NodeOptions::protocol`].
    protocol: Protocol,
    /// Memory for what devices send us: those we share a space with, and
    /// the rest (`resources.rs`).
    member_frames: resources::Frames,
    stranger_frames: resources::Frames,
    /// See [`NodeOptions::sync_v2`].
    sync_v2: bool,
    /// Spaces with a local write since the last periodic round (sessions
    /// then send the frontier in `Open`, saving a round trip).
    local_writes: Mutex<HashSet<SpaceId>>,
    /// Spaces with a local write not yet pushed (the author pushes to more
    /// members than a forwarder: see [`AUTHOR_FULL`]).
    dirty_local: Mutex<HashSet<SpaceId>>,
    v2: sync_v2::V2,
    /// Periodic anti-entropy schedule per space.
    periodic: Mutex<HashMap<SpaceId, Backoff>>,
}

/// Why a sync runs: only some outcomes are signs of loss for the backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// A local write or forwarded items (event-driven).
    Change,
    /// Periodic anti-entropy.
    Periodic,
    /// A peer became reachable.
    Discovery,
    /// The app asked.
    Manual,
}

/// Idle backoff for periodic anti-entropy in one space: the interval starts
/// at [`PERIODIC_SYNC`] and doubles each round up to [`PERIODIC_MAX`],
/// unless a sign of loss arrived since the last round, which brings it back
/// to the start. Rounds are jittered ±20% so devices don't synchronise.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Backoff {
    interval: Duration,
    next: Instant,
    reset: bool,
}

impl Backoff {
    /// The first round comes soon (within ~2 s): it also tells the members
    /// of our view that we chose them, so they push to us (symmetric edges).
    fn new(now: Instant, jitter: f64) -> Self {
        Backoff { interval: PERIODIC_SYNC / 2, next: now + (PERIODIC_SYNC / 8).mul_f64(jitter), reset: true }
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next
    }

    /// A round runs now; `jitter` in [0.8, 1.2].
    fn round(&mut self, now: Instant, jitter: f64) {
        self.interval = if self.reset { PERIODIC_SYNC } else { (self.interval * 2).min(PERIODIC_MAX) };
        self.reset = false;
        self.next = now + self.interval.mul_f64(jitter);
    }

    /// A sign of loss: the next round comes within the first interval.
    fn signal(&mut self, now: Instant) {
        self.reset = true;
        self.interval = PERIODIC_SYNC;
        self.next = self.next.min(now + PERIODIC_SYNC);
    }
}

fn jitter() -> f64 {
    (0.8 + (mycel_crypto::random_u64() % 4001) as f64 / 10_000.0).min(1.2)
}

/// How many QUIC connections (handshakes) a node has made.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCounts {
    /// Dialed by us (through the pool).
    pub dialed: u64,
    /// Accepted from peers.
    pub accepted: u64,
    /// Capability hellos we sent on dialed connections that failed (lost
    /// stream, timeout). Each is tried again later on the same connection,
    /// a few times; meanwhile that connection has no capabilities.
    pub hellos_failed: u64,
}

impl Inner {
    /// Let the mesh watch a connection's mesh paths (end-to-end evidence
    /// against relays that drop what they announce: `mesh/watch.rs`).
    fn watch(&self, conn: &Connection) {
        if let Some(m) = &self.mesh {
            m.watch(conn);
        }
        let mut conns = self.conns.lock();
        if !conns.iter().any(|c| c.stable_id() == conn.stable_id()) {
            conns.push_back(conn.clone());
            if conns.len() > 256 {
                conns.pop_front();
            }
        }
    }

    /// Tell the mesh who shares a space with us: relays it prefers
    /// (`Router::set_affinity`). Members of a space we are in are one step
    /// away; we don't know other devices' spaces, so everyone else counts as
    /// unknown. Nothing about it leaves this device. Nothing is built
    /// unless the mesh uses it ([`MeshOptions::defences`]).
    fn refresh_affinity(&self) {
        let Some(mesh) = self.mesh.as_ref().filter(|m| m.uses_affinity()) else { return };
        let me = self.keys.sign_pk();
        let near: HashSet<SignPk> = self
            .spaces
            .lock()
            .values()
            .filter(|r| r.my_role().is_some())
            .flat_map(|r| r.members().into_iter().map(|(k, _)| k.sign_pk))
            .filter(|k| *k != me)
            .collect();
        mesh.set_affinity(near.into_iter().map(|k| (k, 1)));
    }

    fn prepare(&self, r: &mut Replica) {
        if self.feed_validator.is_some() {
            r.set_feed_validator(self.feed_validator.clone());
        }
    }

    fn emit(&self, e: NetEvent) {
        let _ = self.events.send(e);
    }

    fn addr_of(&self, pk: &SignPk) -> Result<EndpointAddr> {
        Ok(EndpointAddr::new(to_endpoint_id(pk)?))
    }

    fn mark_ok(&self, pk: SignPk) {
        let was_online;
        {
            let mut peers = self.peers.lock();
            let p = peers.entry(pk).or_default();
            was_online = p.online();
            p.last_ok = Some(Instant::now());
            p.failures = 0;
            p.last_fail = None;
        }
        if !was_online {
            self.emit(NetEvent::PeersChanged);
        }
    }

    /// Recent successful exchanges age out without another network event.
    /// Clear the expired timestamp and publish the transition for UI watchers.
    fn expire_reachability(&self) {
        let mut changed = false;
        for peer in self.peers.lock().values_mut() {
            if peer.last_ok.is_some_and(|t| t.elapsed() >= ONLINE_WINDOW) {
                peer.last_ok = None;
                changed |= !peer.nearby && peer.links.is_empty();
            }
        }
        if changed {
            self.emit(NetEvent::PeersChanged);
        }
    }

    /// Remember which path a finished exchange used (for the Network panel).
    fn note_path(&self, pk: SignPk, conn: &Connection) {
        let Some(addr) = link::path_in_use(&conn.paths()).map(|p| p.remote_addr().clone()) else {
            return;
        };
        let via = Some(PathKind::of(&addr));
        let route = match (&addr, &self.mesh) {
            (iroh::TransportAddr::Custom(c), Some(m)) if via == Some(PathKind::Mesh) => m.route_info(c),
            _ => None,
        };
        let changed = {
            let mut peers = self.peers.lock();
            let p = peers.entry(pk).or_default();
            let changed = p.via != via || p.mesh != route;
            (p.via, p.mesh) = (via, route);
            changed
        };
        if changed {
            self.emit(NetEvent::PeersChanged);
        }
    }

    /// A link found or lost a peer: update the addresses Iroh may dial and
    /// sync shared spaces with a newly reachable peer. The medium comes from
    /// the address (one link can drive several: network interfaces).
    fn on_link_event(self: &Arc<Self>, ev: LinkEvent) {
        let (peer, newly, kind) = match ev {
            LinkEvent::Found { peer, addr, name } => {
                if peer == self.keys.sign_pk() {
                    return;
                }
                let kind = PathKind::of_custom_addr(&addr);
                if self.link_addrs.lock().entry(peer).or_default().insert(addr.clone()) {
                    self.open_on_live_connections(peer, addr);
                }
                let mut peers = self.peers.lock();
                let p = peers.entry(peer).or_default();
                let newly = p.links.insert(kind);
                if p.name.is_none() {
                    p.name = name;
                }
                p.failures = 0;
                (peer, newly, kind)
            }
            LinkEvent::Lost { peer, addr } => {
                let kind = PathKind::of_custom_addr(&addr);
                let mut map = self.link_addrs.lock();
                if let Some(set) = map.get_mut(&peer) {
                    set.remove(&addr);
                    let still = set.iter().any(|a| PathKind::of_custom_addr(a) == kind);
                    if set.is_empty() {
                        map.remove(&peer);
                    }
                    if !still && let Some(p) = self.peers.lock().get_mut(&peer) {
                        p.links.remove(&kind);
                    }
                }
                (peer, false, kind)
            }
        };
        self.publish_link_addrs(peer);
        if kind != PathKind::Mesh {
            self.update_direct(peer);
        }
        self.emit(NetEvent::PeersChanged);
        if newly {
            let shared: Vec<SpaceId> =
                self.spaces.lock().iter().filter(|(_, r)| r.is_member(&peer)).map(|(s, _)| *s).collect();
            for s in shared {
                self.loss_signal(s);
                tokio::spawn(sync_once(self.clone(), peer, s, Trigger::Discovery));
            }
        }
    }

    /// Tell the mesh whether `peer` has a direct path (a link or the LAN):
    /// neighbours relay for us, and get no mesh addresses themselves.
    fn update_direct(&self, peer: SignPk) {
        let Some(mesh) = &self.mesh else { return };
        let direct = self.peers.lock().get(&peer).is_some_and(PeerState::is_directly_discovered);
        mesh.set_direct(peer, direct);
    }

    /// A link or mesh route found after a connection to `peer` came up: Iroh
    /// looks addresses up only while it has no working path, so tell it, and
    /// it opens the new one as a path on the live connections (a second mesh
    /// route aggregates, a new radio is ready to fail over to).
    fn open_on_live_connections(&self, peer: SignPk, addr: link::CustomAddr) {
        let Ok(id) = to_endpoint_id(&peer) else { return };
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            endpoint.add_remote_addrs(EndpointAddr::from_parts(id, [iroh::TransportAddr::Custom(addr)])).await;
        });
    }

    fn publish_link_addrs(&self, peer: SignPk) {
        let Ok(id) = to_endpoint_id(&peer) else { return };
        let addrs: Vec<iroh::TransportAddr> = self
            .link_addrs
            .lock()
            .get(&peer)
            .map(|s| s.iter().cloned().map(iroh::TransportAddr::Custom).collect())
            .unwrap_or_default();
        if addrs.is_empty() {
            self.link_lookup.remove_endpoint_info(id);
        } else {
            self.link_lookup.set_endpoint_info(EndpointAddr::from_parts(id, addrs));
        }
    }

    fn mark_fail(&self, pk: SignPk) {
        let mut peers = self.peers.lock();
        let p = peers.entry(pk).or_default();
        p.failures = p.failures.saturating_add(1);
        p.last_fail = Some(Instant::now());
    }

    /// Remember what was agreed with `peer` on a connection we dialed
    /// (diagnostics, and formats sent without a connection:
    /// store-and-forward). We chose to dial it, so it may get an entry.
    fn note_protocol(&self, peer: SignPk, p: PeerProtocol) {
        self.peers.lock().entry(peer).or_default().protocol = Some(p);
    }

    /// The same, on a connection `peer` dialed: before any exchange, so
    /// anyone may have dialed (a fresh key costs nothing). Only a device we
    /// already track or share a space with is noted; a stranger gets no
    /// entry, which would never be removed. (Its connection still knows its
    /// version.)
    fn note_accepted_protocol(&self, peer: SignPk, p: PeerProtocol) {
        let member = self.spaces.lock().values().any(|r| r.is_member(&peer));
        let mut peers = self.peers.lock();
        match peers.get_mut(&peer) {
            Some(state) => state.protocol = Some(p),
            None if member => peers.entry(peer).or_default().protocol = Some(p),
            None => {}
        }
    }

    /// The memory budget for what `peer` sends us on a stream it opened: a
    /// share of the members' pool if we share a space with it (now: it may
    /// just have joined one), of the strangers' otherwise.
    fn frames(&self, peer: &SignPk) -> resources::PeerFrames {
        if self.spaces.lock().values().any(|r| r.is_member(peer)) {
            self.member_frames.peer(peer)
        } else {
            self.stranger_frames.peer(peer)
        }
    }

    /// ... and for its answers to us: we chose to ask it (a device we were
    /// just invited by may not be a member yet in our copy of the space, and
    /// its first answer is the space's whole history).
    fn reply_frames(&self, peer: &SignPk) -> resources::PeerFrames {
        self.member_frames.peer(peer)
    }

    fn with_space<R>(&self, space: &SpaceId, f: impl FnOnce(&mut Replica) -> R) -> Result<R> {
        let mut spaces = self.spaces.lock();
        let r = spaces.get_mut(space).ok_or_else(|| anyhow!("unknown space"))?;
        Ok(f(r))
    }

    fn schedule(&self, space: SpaceId) {
        self.dirty.lock().insert(space);
        self.wake.notify_one();
    }

    /// New items arrived in `space` (from any sync or a bundle): tell the
    /// app and forward them (epidemic: others may not reach the author). A
    /// membership change is also a sign of loss for the backoff.
    fn on_new_items(&self, space: SpaceId, membership: bool) {
        self.emit(NetEvent::SpaceChanged { space });
        if membership {
            self.loss_signal(space);
        }
        self.schedule(space);
    }

    /// Did we write to `space` locally since the last periodic round? Then
    /// a session sends its frontier in `Open` (saving a round trip) even
    /// without a record of the peer.
    fn dirty_since_last(&self, _peer: &SignPk, space: &SpaceId) -> bool {
        self.local_writes.lock().contains(space)
    }

    /// We just learned how to reach `peer` (an address hint): a sign of a
    /// reachability change. Sync the spaces we share with it now, without
    /// waiting out a failure backoff or the periodic schedule.
    fn peer_reachable(self: &Arc<Self>, peer: SignPk) {
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let shared: Vec<SpaceId> =
            self.spaces.lock().iter().filter(|(_, r)| r.is_member(&peer)).map(|(s, _)| *s).collect();
        if shared.is_empty() {
            return;
        }
        if let Some(p) = self.peers.lock().get_mut(&peer) {
            p.failures = 0;
        }
        for s in shared {
            self.loss_signal(s);
            rt.spawn(sync_once(self.clone(), peer, s, Trigger::Discovery));
        }
    }

    /// See [`Backoff::signal`].
    fn loss_signal(&self, space: SpaceId) {
        let now = Instant::now();
        let mut periodic = self.periodic.lock();
        periodic.entry(space).or_insert_with(|| Backoff::new(now, jitter())).signal(now);
        drop(periodic);
        self.wake.notify_one();
    }

    /// Who to sync `space` with after a change or in a periodic round
    /// (excluding us): every member in small groups and on builds without
    /// v2; otherwise the bounded view (see the crate docs).
    fn targets(
        &self,
        space: &SpaceId,
        r: &Replica,
        peers: &HashMap<SignPk, PeerState>,
        local: bool,
        trigger: Trigger,
    ) -> Vec<SignPk> {
        let me = self.keys.sign_pk();
        let mut members: Vec<SignPk> = r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|pk| *pk != me).collect();
        // Members gossip reaches get no session after a change (pushes carry
        // it), and only one of them a periodic anti-entropy session.
        let mut partner = None;
        if self.gossip_on() {
            let covered: HashSet<SignPk> =
                members.iter().filter(|p| self.gossip_covers(space, p, local.then_some(peers))).copied().collect();
            if !covered.is_empty() {
                members.retain(|p| !covered.contains(p));
                if trigger == Trigger::Periodic {
                    partner = self.gossip.d.lock().anti_entropy_partner(space, mycel_crypto::random_u64());
                }
                if members.is_empty() {
                    return partner.into_iter().collect();
                }
            }
        }
        let mut out = self.targets_of(space, peers, local, &members, &me);
        if let Some(p) = partner
            && !out.contains(&p)
        {
            out.push(p);
        }
        out
    }

    /// [`Inner::targets`] among `members` (those gossip doesn't reach).
    fn targets_of(
        &self,
        space: &SpaceId,
        peers: &HashMap<SignPk, PeerState>,
        local: bool,
        members: &[SignPk],
        me: &SignPk,
    ) -> Vec<SignPk> {
        let (members, me) = (members.to_vec(), *me);
        let full = if local { AUTHOR_FULL } else { FULL_MESH };
        if !self.sync_v2 || members.len() <= full {
            return members;
        }
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / VIEW_EPOCH.as_secs());
        let score =
            |p: &SignPk| Hash32::digest("mycel/v2/view", &[&space.0[..], &me.0, &p.0, &epoch.to_le_bytes()].concat());
        let mut ranked: Vec<(Hash32, SignPk)> = members.iter().map(|p| (score(p), *p)).collect();
        ranked.sort();
        let mut out: Vec<SignPk> = ranked
            .iter()
            .filter(|(_, p)| peers.get(p).is_some_and(PeerState::is_directly_discovered))
            .take(VIEW_NEARBY)
            .map(|(_, p)| *p)
            .collect();
        // Random edges (by rendezvous hash over the whole member list, so
        // physical clusters can't split the overlay), preferring members
        // with recent evidence of reachability: one that fails drops a
        // tier and the next by rank takes its place (HyParView's active
        // view), so offline picks can't cut a device off for an epoch.
        let tier = |p: &SignPk| match peers.get(p) {
            Some(s) if s.backing_off() => 2,
            Some(s) if s.online() => 0,
            _ => 1,
        };
        let random = pick_ranked(&ranked, &out, VIEW_RANDOM, tier);
        out.extend(random);
        for p in self.v2.inbound(space, VIEW_INBOUND) {
            if members.contains(&p) && !out.contains(&p) {
                out.push(p);
            }
        }
        // Members on builds without v2 still re-sync epidemically with
        // everyone; only the two members nearest each of them by
        // rendezvous hash push to it, so they hear of changes once.
        for v in self.v2.v1_only_peers() {
            if out.contains(&v) || !members.contains(&v) {
                continue;
            }
            let mut by: Vec<(Hash32, SignPk)> = members
                .iter()
                .chain(std::iter::once(&me))
                .filter(|m| **m != v)
                .map(|m| (Hash32::digest("mycel/v2/v1-designated", &[&space.0[..], &v.0, &m.0].concat()), *m))
                .collect();
            by.sort();
            if by.iter().take(2).any(|(_, m)| *m == me) {
                out.push(v);
            }
        }
        out
    }

    /// Blobs are stored per space: a member of one space can't fetch or fill
    /// another space's blobs.
    fn blob_path(&self, space: &SpaceId, hash: &Hash32) -> Option<PathBuf> {
        self.blob_dir.as_ref().map(|d| d.join(space.to_string()).join(hash.to_string()))
    }

    /// Apply received data; on change, notify the app and forward to other members.
    fn ingest(&self, space: &SpaceId, peer: SignPk, data: Data, sent: &[EnvelopeId]) -> SyncStats {
        let res = {
            let mut spaces = self.spaces.lock();
            let Some(r) = spaces.get_mut(space) else {
                return SyncStats::default();
            };
            let ids: Vec<EnvelopeId> = data.envelopes.iter().map(|e| e.id()).collect();
            let res = r.ingest_batch(data.ops, data.envelopes);
            // the peer holds what it sent us and what we sent it
            r.note_holder(peer, &ids);
            r.note_holder(peer, sent);
            res
        };
        if res.changed() {
            self.gossip_changed(space, Some(peer));
            self.on_new_items(*space, res.ops > 0);
        } else if !sent.is_empty() {
            // delivery status changed
            self.emit(NetEvent::SpaceChanged { space: *space });
        }
        SyncStats { ops: res.ops, envelopes: res.envelopes }
    }
}

fn inventory(r: &Replica) -> Inventory {
    Inventory { ops: r.op_ids(), envelopes: r.envelope_ids() }
}

fn missing(r: &Replica, theirs: &Inventory) -> Inventory {
    let ops: HashSet<_> = r.op_ids().into_iter().collect();
    Inventory {
        ops: theirs.ops.iter().filter(|i| !ops.contains(i)).copied().collect(),
        envelopes: theirs.envelopes.iter().filter(|i| !r.has_envelope(i)).copied().collect(),
    }
}

fn gather(r: &Replica, want: &Inventory, budget: usize) -> Result<Data> {
    // Retain references while measuring; reject the whole response before
    // cloning any ciphertext. Count the exact Vec length prefixes as well.
    let mut seen = HashSet::new();
    let mut ops = Vec::new();
    let mut envelopes = Vec::new();
    let mut remaining = budget;
    for id in &want.ops {
        if !seen.insert(*id) {
            continue;
        }
        if let Some(op) = r.op(id) {
            remaining = remaining
                .checked_sub(wire::encoded_size(op, remaining)?)
                .ok_or_else(|| anyhow!("sync response too large"))?;
            ops.push(op);
        }
    }
    seen.clear();
    for id in &want.envelopes {
        if !seen.insert(*id) {
            continue;
        }
        if let Some(envelope) = r.envelope(id) {
            remaining = remaining
                .checked_sub(wire::encoded_size(envelope, remaining)?)
                .ok_or_else(|| anyhow!("sync response too large"))?;
            envelopes.push(envelope);
        }
    }
    wire::encoded_size(&(ops.len(), envelopes.len()), remaining)?;
    Ok(Data { ops: ops.into_iter().cloned().collect(), envelopes: envelopes.into_iter().cloned().collect() })
}

// ─────────────────────────── protocol handlers ───────────────────────────

/// Hands incoming connections of an [`ExtraProtocol`] to its owner.
#[derive(Debug, Clone)]
struct Forward(mpsc::UnboundedSender<Connection>);

impl ProtocolHandler for Forward {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        self.0.send(conn).map_err(|_| AcceptError::from_boxed(anyhow!("protocol is not running").into()))
    }
}

#[derive(Clone)]
struct Handler {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handler(mycel)")
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        serve_conn(&self.inner, conn).await;
        Ok(())
    }
}

/// Serve every stream a peer opens on one connection, for as long as it
/// lives: each stream is one exchange, handled concurrently with the others.
/// How many it may have open at once is QUIC's per-connection stream limit
/// (`link::transport_config`): beyond it the peer waits for its turn.
async fn serve_conn(inner: &Arc<Inner>, conn: Connection) {
    inner.accepted.fetch_add(1, Ordering::Relaxed);
    inner.watch(&conn);
    let peer = to_sign_pk(&conn.remote_id());
    // (the router only hands us connections with one of our ALPNs)
    let Some(version) = wire::version_of(conn.alpn()) else { return };
    if version < WIRE_V2 {
        inner.note_accepted_protocol(peer, PeerProtocol::baseline(version));
    }
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let Ok((tx, rx)) = bi else { break };
                let (inner, conn) = (inner.clone(), conn.clone());
                tokio::spawn(async move {
                    let _ = serve_bi(&inner, &conn, version, peer, tx, rx).await;
                });
            }
            uni = conn.accept_uni() => {
                let Ok(rx) = uni else { break };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _ = serve_uni(&inner, version, peer, rx).await;
                });
            }
        }
    }
}

/// The kind byte a stream starts with. One this wire `version` doesn't
/// have is refused at once: both directions are stopped with
/// [`STREAM_REFUSED`], so the opener (an older or newer build) learns it
/// in one round trip instead of waiting for an answer that never comes.
async fn stream_kind(version: WireVersion, tx: Option<&mut SendStream>, rx: &mut RecvStream) -> Result<StreamKind> {
    let mut b = [0u8; 1];
    resources::first(rx.read_exact(&mut b)).await?;
    StreamKind::on(version, b[0]).ok_or_else(|| {
        let code = iroh::endpoint::VarInt::from_u32(STREAM_REFUSED);
        rx.stop(code).ok();
        if let Some(tx) = tx {
            tx.reset(code).ok();
        }
        VersionError::UnknownStreamKind(b[0]).into()
    })
}

async fn serve_bi(
    inner: &Arc<Inner>,
    conn: &Connection,
    version: WireVersion,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    let kind = stream_kind(version, Some(&mut tx), &mut rx).await?;
    tx.set_priority(kind.priority()).ok();
    match kind {
        // No total deadline: over a slow link a large sync takes minutes,
        // and each wait inside is bounded while bytes keep moving.
        StreamKind::Sync => serve_sync(inner, conn, peer, tx, rx).await,
        StreamKind::SyncV2 => sync_v2::serve(inner, conn, peer, tx, rx).await,
        StreamKind::Card => serve_card(inner, tx).await,
        StreamKind::Blob => blobs::serve(inner, peer, tx, rx).await,
        StreamKind::Hello => serve_hello(inner, version, peer, tx, rx).await,
        StreamKind::Ephemeral | StreamKind::Gossip => bail!("{kind:?} uses uni-streams"),
    }
}

async fn serve_uni(inner: &Arc<Inner>, version: WireVersion, peer: SignPk, mut rx: RecvStream) -> Result<()> {
    match stream_kind(version, None, &mut rx).await? {
        StreamKind::Ephemeral => serve_eph(inner, peer, rx).await,
        StreamKind::Gossip => gossip::serve(inner, peer, rx).await,
        other => bail!("{other:?} needs a bi-stream"),
    }
}

/// A dialer's capability hello: answer with ours. (Anyone may send one:
/// capabilities are public, and both hellos are a few bytes.)
async fn serve_hello(
    inner: &Arc<Inner>,
    version: WireVersion,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    let theirs = recv_hello(&mut rx, resources::FIRST_FRAME, &inner.frames(&peer)).await?;
    #[cfg(test)]
    if inner.drop_hellos.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
        tx.reset(0u32.into()).ok();
        bail!("test: hello dropped");
    }
    #[cfg(test)]
    if inner.stall_hellos.load(Ordering::SeqCst) {
        // (a hello that never gets an answer, as on a path that black-holes it)
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
    inner.hellos_served.fetch_add(1, Ordering::Relaxed);
    inner.note_accepted_protocol(peer, PeerProtocol::agreed(version, inner.protocol.caps, theirs.caps));
    send(&mut tx, &Hello::ours(inner.protocol.caps)).await?;
    tx.finish()?;
    Ok(())
}

async fn serve_sync(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    let (mut msg, mut msg_permit) = recv_held::<SyncMsg>(&mut rx, resources::FIRST_FRAME, &inner.frames(&peer)).await?;
    loop {
        let SyncMsg::Hello { space, inv, invite } = msg else {
            bail!("expected Hello");
        };
        let known = inner.spaces.lock().contains_key(&space);
        if !known {
            match invite {
                None => {
                    let len = send_len(&mut tx, &SyncMsg::NeedInvite).await?;
                    drop(inv);
                    drop(msg_permit);
                    (msg, msg_permit) = recv_held(&mut rx, resources::reply_timeout(len), &inner.frames(&peer)).await?;
                    continue;
                }
                Some(ops) => {
                    if !accept_invite(inner, peer, space, ops) {
                        return deny(tx).await;
                    }
                }
            }
        } else {
            drop(invite);
        }
        // Membership gate: only current members (any role) may sync.
        let reply = inner.with_space(&space, |r| {
            r.is_member(&peer).then(|| {
                r.note_holder(peer, &inv.envelopes);
                SyncMsg::Accept { inv: inventory(r), want: missing(r, &inv) }
            })
        })?;
        if reply.is_some()
            && inner.sync_v2
            && let Err(retry_ms) = inner.v2.allow_v1(peer, space)
        {
            // Mixed groups: one v1 session per (peer, space) per
            // `V1_SERVE_INTERVAL` (see `sync_v2::allow_v1`).
            let code = iroh::endpoint::VarInt::from_u32(sync_v2::SYNC_V1_LIMITED);
            tx.reset(code).ok();
            rx.stop(code).ok();
            bail!("v1 session refused: one per {:?} (retry in {retry_ms} ms)", sync_v2::V1_SERVE_INTERVAL);
        }
        let Some(reply) = reply else {
            let proof = inner.with_space(&space, |r| r.revocation_proof(&peer))?;
            if proof.is_empty() {
                return deny(tx).await;
            }
            send(&mut tx, &SyncMsg::Removed { ops: proof }).await?;
            tx.finish()?;
            return Ok(());
        };
        let len = send_len(&mut tx, &reply).await?;
        drop(reply);
        drop(inv);
        drop(msg_permit);
        // (a member now, if this was an invitation)
        let (msg, _data_permit) = recv_held(&mut rx, resources::reply_timeout(len), &inner.frames(&peer)).await?;
        let SyncMsg::DataAndWant { data, want } = msg else {
            bail!("expected DataAndWant");
        };
        let out = inner.with_space(&space, |r| gather(r, &want, MAX_FRAME - 1))??;
        let sent: Vec<EnvelopeId> = out.envelopes.iter().map(|e| e.id()).collect();
        send(&mut tx, &SyncMsg::Data { data: out }).await?;
        tx.finish()?;
        inner.ingest(&space, peer, data, &sent);
        inner.note_path(peer, conn);
        inner.mark_ok(peer);
        return Ok(());
    }
}

/// Tell the client no. (The connection stays up: finishing the stream
/// delivers the reply.)
async fn deny(mut tx: SendStream) -> Result<()> {
    send(&mut tx, &SyncMsg::Denied).await?;
    tx.finish()?;
    Ok(())
}

/// A space pushed to us: accept only if policy allows and the ops prove that
/// both we and the pusher are members.
fn accept_invite(inner: &Arc<Inner>, from: SignPk, space: SpaceId, ops: Vec<SignedOp>) -> bool {
    if ops.len() > MAX_INVITE_OPS {
        return false;
    }
    let Some(genesis) = ops.iter().find(|o| o.id() == space).cloned() else {
        return false;
    };
    let Ok(mut r) = Replica::join(inner.keys.clone(), genesis, None) else {
        return false;
    };
    r.ingest_batch(ops, vec![]);
    match r.my_role() {
        None => return false,
        Some(Role::Relay) if !inner.accept_relay_invites => return false,
        _ => {}
    }
    if !r.is_member(&from) {
        return false;
    }
    // Policies may durably record consent state: invoke only for a valid
    // invitation, before the membership itself is attached to storage.
    if !(inner.invite_policy)(&from, &space) {
        return false;
    }
    // Re-create with the store attached so everything is persisted.
    let all = r.all_ops();
    let Some(genesis) = all.iter().find(|o| o.id() == space).cloned() else {
        return false;
    };
    let Ok(mut r) = Replica::join(inner.keys.clone(), genesis, inner.store.clone()) else {
        return false;
    };
    inner.prepare(&mut r);
    r.ingest_batch(all, vec![]);
    inner.spaces.lock().entry(space).or_insert(r);
    inner.emit(NetEvent::SpaceAdded { space, from });
    true
}

/// Anyone may ask for our card (it's public and self-signed).
async fn serve_card(inner: &Arc<Inner>, mut tx: SendStream) -> Result<()> {
    let card = ContactCard::new(&inner.keys, &inner.name.lock().clone());
    send(&mut tx, &card).await?;
    tx.finish()?;
    Ok(())
}

async fn serve_eph(inner: &Arc<Inner>, peer: SignPk, mut rx: RecvStream) -> Result<()> {
    let (msg, _permit) = recv_ephemeral(&mut rx, &inner.frames(&peer), inner.max_ephemeral).await?;
    let data = inner.with_space(&msg.space, |r| {
        if !r.is_member(&peer) {
            return None;
        }
        r.open_ephemeral(&msg.epoch, &msg.nonce, &eph_aad(&msg.space, &peer.0), &msg.ciphertext)
    })?;
    if let Some(data) = data {
        inner.mark_ok(peer);
        inner.emit(NetEvent::Ephemeral { space: msg.space, from: peer, data });
    }
    Ok(())
}

// ─────────────────────────────── client side ───────────────────────────────

/// A fresh connection for another protocol ([`Node::connect_offering`]):
/// `alpns` newest first, the peer picks one.
async fn connect(inner: &Arc<Inner>, peer: &SignPk, alpns: &[&[u8]]) -> Result<Connection> {
    let addr = inner.addr_of(peer)?;
    let (first, rest) = alpns.split_first().ok_or_else(|| anyhow!("no protocol to offer"))?;
    let options = ConnectOptions::new().with_additional_alpns(rest.iter().map(|a| a.to_vec()).collect());
    let connect = async { anyhow::Ok(inner.endpoint.connect_with_opts(addr, first, options).await?.await?) };
    match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(c)) => {
            inner.watch(&c);
            Ok(c)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("connect timed out")),
    }
}

/// The pooled connection to `peer`, dialed if there is none. One that has
/// already closed is dropped from the pool and redialed.
pub(crate) async fn pooled(inner: &Arc<Inner>, peer: &SignPk) -> Result<PooledConn> {
    let c = inner.pool.get(peer).await?;
    inner.watch(&c);
    if c.claim_hello() {
        start_hello(inner, *peer, &c);
    }
    Ok(c)
}

/// A connection we just dialed (or whose last hello failed a while ago:
/// [`PooledConn::claim_hello`]): agree on capabilities, beside whatever
/// exchange it was dialed for (nothing waits for this unless it needs a
/// capability: [`PooledConn::protocol`]). Version 1 has no hello.
fn start_hello(inner: &Arc<Inner>, peer: SignPk, c: &PooledConn) {
    let version = c.version();
    if version < WIRE_V2 {
        let p = PeerProtocol::baseline(version);
        c.set_protocol(p);
        inner.note_protocol(peer, p);
        return;
    }
    let (inner, conn) = (inner.clone(), c.share());
    tokio::spawn(async move {
        let caps = inner.protocol.caps;
        let hello = async {
            let (mut tx, mut rx) = open_bi(&conn, StreamKind::Hello).await?;
            let len = send_len(&mut tx, &Hello::ours(caps)).await?;
            tx.finish()?;
            recv_hello(&mut rx, resources::reply_timeout(len), &inner.reply_frames(&peer)).await
        };
        match hello.await {
            Ok(theirs) => {
                let p = PeerProtocol::agreed(version, caps, theirs.caps);
                conn.set_protocol(p);
                inner.note_protocol(peer, p);
            }
            // (no capabilities until a later try succeeds)
            Err(_) => {
                inner.hellos_failed.fetch_add(1, Ordering::Relaxed);
                conn.hello_failed(PeerProtocol::baseline(version));
            }
        }
    });
}

/// Run one exchange (`$body`, a future using `$conn`) on the pooled
/// connection to `$peer`. If it fails because that connection died (the
/// peer restarted, moved networks...), drop it and try once more on a
/// freshly dialed one.
macro_rules! on_conn {
    ($inner:expr, $peer:expr, |$conn:ident| $body:expr) => {{
        let mut retried = false;
        loop {
            let $conn = match pooled($inner, $peer).await {
                Ok(c) => c,
                Err(e) => break Err(e),
            };
            match $body.await {
                Err(_) if !retried && $conn.close_reason().is_some() => {
                    retried = true;
                    drop($conn);
                    $inner.pool.forget($peer);
                }
                res => break res,
            }
        }
    }};
}
pub(crate) use on_conn;

/// Open a bi-stream of `kind` (labelled and prioritised). Waits while the
/// peer already has as many of our streams open as it allows.
pub(crate) async fn open_bi(conn: &Connection, kind: StreamKind) -> Result<(SendStream, RecvStream)> {
    open_bi_raw(conn, kind as u8, kind.priority()).await
}

/// [`open_bi`] with any kind byte (tests: kinds a peer doesn't know).
pub(crate) async fn open_bi_raw(conn: &Connection, kind: u8, priority: i32) -> Result<(SendStream, RecvStream)> {
    let (mut tx, rx) = resources::within(resources::REPLY_TIMEOUT, "no stream", conn.open_bi()).await?;
    tx.set_priority(priority).ok();
    tx.write_all(&[kind]).await.map_err(|e| version::refusal(e.into()))?;
    Ok((tx, rx))
}

async fn sync_session(inner: &Arc<Inner>, peer: SignPk, space: SpaceId, trust_peer: bool) -> Result<SyncStats> {
    if inner.sync_v2 && !inner.v2.is_v1_only(&peer) && peer_has_sync_v2(inner, peer).await? {
        let eager = inner.dirty_since_last(&peer, &space);
        if let Some(stats) = sync_v2::sync(inner, peer, space, trust_peer, eager).await? {
            return Ok(stats);
        }
        // The peer doesn't speak v2 (remembered): v1 below.
    }
    let hello =
        inner.with_space(&space, |r| (trust_peer || r.is_member(&peer)).then(|| (inventory(r), r.all_ops())))?;
    let (inv, ops) = hello.ok_or_else(|| anyhow!("peer is not a member of this space"))?;
    let res = on_conn!(inner, &peer, |conn| sync_exchange(inner, &conn, peer, space, inv.clone(), ops.clone()));
    // A v2 node limiting the v1 sessions it serves: as `Busy`, not a failure.
    match res {
        Err(e) if reset_with(&e, sync_v2::SYNC_V1_LIMITED) => {
            Err(sync_v2::PeerBusy(sync_v2::V1_SERVE_INTERVAL.as_millis() as u32).into())
        }
        res => res,
    }
}

/// Did `err` come from the peer resetting (or stopping) the stream with `code`?
fn reset_with(err: &anyhow::Error, code: u32) -> bool {
    use iroh::endpoint::{ReadError, ReadExactError, WriteError};
    let code = iroh::endpoint::VarInt::from_u32(code);
    err.chain().any(|e| {
        matches!(e.downcast_ref::<ReadError>(), Some(ReadError::Reset(c)) if *c == code)
            || matches!(e.downcast_ref::<ReadExactError>(), Some(ReadExactError::ReadError(ReadError::Reset(c))) if *c == code)
            || matches!(e.downcast_ref::<WriteError>(), Some(WriteError::Stopped(c)) if *c == code)
            || e.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).is_some_and(|inner| {
                matches!(inner.downcast_ref::<ReadError>(), Some(ReadError::Reset(c)) if *c == code)
                    || matches!(inner.downcast_ref::<ReadExactError>(), Some(ReadExactError::ReadError(ReadError::Reset(c))) if *c == code)
                    || matches!(inner.downcast_ref::<WriteError>(), Some(WriteError::Stopped(c)) if *c == code)
            })
    })
}

/// Whether `peer`'s hello agreed [`Caps::SYNC_V2`] on the pooled connection
/// (dialed if there is none). On a new connection this waits for its hello,
/// sent as soon as it was dialed, so normally one round trip, but only
/// [`hello_wait`]: a peer on wire version 1, or whose hello failed or is
/// late, gets v1 this time (a hung hello must not hold a sync for a whole
/// reply timeout).
async fn peer_has_sync_v2(inner: &Arc<Inner>, peer: SignPk) -> Result<bool> {
    let conn = pooled(inner, &peer).await?;
    let wait = hello_wait(&conn);
    Ok(conn.protocol(wait).await.supports(Caps::SYNC_V2))
}

/// How long a sync waits for the peer's hello: four round trips on the
/// path in use plus a margin, within [`HELLO_WAIT_MIN`, `HELLO_WAIT_MAX`]
/// (the hello is one round trip; a multi-hop Bluetooth path takes about
/// half a second per round trip).
pub(crate) fn hello_wait(conn: &Connection) -> Duration {
    let rtt = link::path_in_use(&conn.paths()).map(|p| p.rtt()).unwrap_or(HELLO_WAIT_MAX);
    (rtt * 4 + Duration::from_millis(250)).clamp(HELLO_WAIT_MIN, HELLO_WAIT_MAX)
}

/// One sync session on its own stream of `conn`.
async fn sync_exchange(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    space: SpaceId,
    inv: Inventory,
    ops: Vec<SignedOp>,
) -> Result<SyncStats> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Sync).await?;
    let len = send_len(&mut tx, &SyncMsg::Hello { space, inv: inv.clone(), invite: None }).await?;
    let (mut reply, mut reply_permit) =
        recv_held::<SyncMsg>(&mut rx, resources::reply_timeout(len), &inner.reply_frames(&peer)).await?;
    if matches!(reply, SyncMsg::NeedInvite) {
        let len = send_len(&mut tx, &SyncMsg::Hello { space, inv, invite: Some(ops) }).await?;
        drop(reply_permit);
        (reply, reply_permit) = recv_held(&mut rx, resources::reply_timeout(len), &inner.reply_frames(&peer)).await?;
    }
    let (their_inv, their_want) = match reply {
        SyncMsg::Accept { inv, want } => (inv, want),
        SyncMsg::Denied => bail!("peer denied sync (we are not a member)"),
        SyncMsg::Removed { ops } => {
            let res = inner.with_space(&space, |r| r.ingest_batch(ops, vec![]))?;
            if res.changed() {
                inner.emit(NetEvent::SpaceChanged { space });
            }
            bail!("peer denied sync (we were removed from this space)")
        }
        _ => bail!("unexpected sync reply"),
    };
    let out = inner.with_space(&space, |r| {
        r.note_holder(peer, &their_inv.envelopes);
        let want = missing(r, &their_inv);
        let overhead = wire::encoded_size(&want, MAX_FRAME - 1)? + 1;
        Ok::<_, anyhow::Error>(SyncMsg::DataAndWant { data: gather(r, &their_want, MAX_FRAME - overhead)?, want })
    })??;
    let sent: Vec<EnvelopeId> = match &out {
        SyncMsg::DataAndWant { data, .. } => data.envelopes.iter().map(|e| e.id()).collect(),
        _ => vec![],
    };
    let len = send_len(&mut tx, &out).await?;
    tx.finish()?;
    drop(out);
    drop(their_inv);
    drop(their_want);
    drop(reply_permit);
    let (msg, _data_permit) = recv_held(&mut rx, resources::reply_timeout(len), &inner.reply_frames(&peer)).await?;
    let SyncMsg::Data { data } = msg else {
        bail!("expected Data");
    };
    inner.note_path(peer, conn);
    Ok(inner.ingest(&space, peer, data, &sent))
}

async fn sync_once(inner: Arc<Inner>, peer: SignPk, space: SpaceId, trigger: Trigger) {
    {
        let mut inflight = inner.inflight.lock();
        if let Some(again) = inflight.get_mut(&(peer, space)) {
            // One is running: it may have missed this change, so it runs once more.
            *again = true;
            return;
        }
        inflight.insert((peer, space), false);
    }
    let _slot = inner.sync_slots.acquire().await;
    let mut busy_retries = 0;
    loop {
        // No total deadline (a large sync over Bluetooth takes minutes):
        // every wait inside is bounded, and a dead connection fails it.
        let session = sync_session(&inner, peer, space, false);
        tokio::pin!(session);
        let res = tokio::select! {
            r = &mut session => r,
            _ = tokio::time::sleep(BUNDLE_AFTER) => {
                inner.offer_bundle(peer, space);
                session.await
            }
        };
        // `Busy`: the peer is syncing this space with us already, or over
        // its limits. Not a failure: no backoff, no bundle. A crossing
        // session carries our set only as of its start, so try again a few
        // times even without a new change (cheap: an idle check or what came
        // after, once the crossing session has ended).
        if let Err(e) = &res
            && let Some(busy) = e.downcast_ref::<sync_v2::PeerBusy>()
        {
            let retry = busy.retry_after();
            if busy_retries < BUSY_RETRIES {
                busy_retries += 1;
                if let Some(a) = inner.inflight.lock().get_mut(&(peer, space)) {
                    *a = false;
                }
                tokio::time::sleep(retry).await;
                continue;
            }
            inner.inflight.lock().remove(&(peer, space));
            return;
        }
        let ok = res.is_ok();
        if let Ok(stats) = &res {
            inner.mark_ok(peer);
            // Live again: what was in flight by carriers is settled.
            inner.bundles.lock().delivered(&peer, &space);
            // A periodic session that found something means pushes are
            // being missed: back to the short interval.
            if trigger == Trigger::Periodic && sync_v2::moved(stats) {
                inner.loss_signal(space);
            }
        } else {
            inner.mark_fail(peer);
            inner.offer_bundle(peer, space);
        }
        let mut inflight = inner.inflight.lock();
        match inflight.get_mut(&(peer, space)) {
            Some(again) if *again && ok => *again = false,
            _ => {
                inflight.remove(&(peer, space));
                return;
            }
        }
    }
}

/// Push dirty spaces to their members (or the bounded view); run periodic
/// anti-entropy per space on its backoff schedule.
async fn scheduler(inner: Arc<Inner>) {
    loop {
        let wait = {
            let now = Instant::now();
            let periodic = inner.periodic.lock();
            periodic.values().map(|b| b.next.saturating_duration_since(now)).min().unwrap_or(PERIODIC_SYNC)
        };
        tokio::select! {
            _ = inner.wake.notified() => {}
            _ = tokio::time::sleep(wait.max(DEBOUNCE)) => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
        // membership may have changed (ours or another member's ops)
        inner.refresh_affinity();
        let explicit: HashSet<SpaceId> = std::mem::take(&mut *inner.dirty.lock());
        let local: HashSet<SpaceId> = std::mem::take(&mut *inner.dirty_local.lock());
        let now = Instant::now();
        let due: HashSet<SpaceId> = {
            let spaces: Vec<SpaceId> = inner.spaces.lock().keys().copied().collect();
            let mut periodic = inner.periodic.lock();
            periodic.retain(|s, _| spaces.contains(s));
            spaces
                .into_iter()
                .filter(|s| {
                    let b = periodic.entry(*s).or_insert_with(|| Backoff::new(now, jitter()));
                    let due = b.due(now);
                    if due {
                        b.round(now, jitter());
                        inner.local_writes.lock().remove(s);
                    }
                    due
                })
                .collect()
        };
        // Gossip views follow membership and reachability; seen notes (read
        // receipts) ride on gossip.
        {
            let mut spaces = inner.spaces.lock();
            let peers = inner.peers.lock();
            for (s, r) in spaces.iter_mut() {
                inner.gossip_view(r, &peers);
                if inner.read_receipts
                    && inner.gossip_on()
                    && let Some(note) = r.seen_note()
                {
                    inner.gossip.d.lock().carry_seen(s, note);
                }
            }
        }
        let targets: Vec<(SignPk, SpaceId, Trigger)> = {
            let spaces = inner.spaces.lock();
            let peers = inner.peers.lock();
            explicit
                .iter()
                .map(|s| (*s, Trigger::Change))
                .chain(due.iter().filter(|s| !explicit.contains(*s)).map(|s| (*s, Trigger::Periodic)))
                .filter_map(|(s, t)| spaces.get(&s).map(|r| (s, t, r)))
                // No longer a member: only push explicit local changes (e.g. our
                // own Leave op); periodic syncs would just be refused.
                .filter(|(s, _, r)| explicit.contains(s) || r.my_role().is_some())
                .flat_map(|(s, t, r)| {
                    let local = t == Trigger::Change && local.contains(&s);
                    inner.targets(&s, r, &peers, local, t).into_iter().map(move |pk| (pk, s, t)).collect::<Vec<_>>()
                })
                .filter(|(pk, _, _)| !peers.get(pk).is_some_and(|p| p.backing_off() && !p.nearby))
                .collect()
        };
        for (peer, space, trigger) in targets {
            tokio::spawn(sync_once(inner.clone(), peer, space, trigger));
        }
    }
}

/// Track nearby peers via mDNS and sync shared spaces when one appears.
async fn watch_mdns(inner: Arc<Inner>, mdns: MdnsAddressLookup) {
    let mut events = mdns.subscribe().await;
    while let Some(ev) = events.next().await {
        on_lan_discovery(&inner, "raw", ev);
    }
}

fn on_lan_discovery(inner: &Arc<Inner>, source: &'static str, ev: DiscoveryEvent) {
    match ev {
        DiscoveryEvent::Discovered { endpoint_info, .. } => {
            let pk = to_sign_pk(&endpoint_info.endpoint_id);
            if pk == inner.keys.sign_pk() {
                return;
            }

            let name =
                endpoint_info.data.user_data().and_then(|u| u.as_ref().strip_prefix("mycel:").map(str::to_string));
            let newly = {
                let mut sources = inner.lan_sources.lock();
                sources.entry(pk).or_default().insert(source);
                let mut peers = inner.peers.lock();
                let p = peers.entry(pk).or_default();
                let newly = !p.nearby || name.is_some() && p.name != name;
                p.nearby = true;
                if name.is_some() {
                    p.name = name;
                }
                p.failures = 0;
                newly
            };
            inner.update_direct(pk);
            if newly {
                inner.emit(NetEvent::PeersChanged);
                let shared: Vec<SpaceId> =
                    inner.spaces.lock().iter().filter(|(_, r)| r.is_member(&pk)).map(|(s, _)| *s).collect();
                for s in shared {
                    inner.loss_signal(s);
                    tokio::spawn(sync_once(inner.clone(), pk, s, Trigger::Discovery));
                }
            }
        }
        DiscoveryEvent::Expired { endpoint_id } => {
            let pk = to_sign_pk(&endpoint_id);
            let changed = {
                let mut sources = inner.lan_sources.lock();
                if let Some(s) = sources.get_mut(&pk) {
                    s.remove(source);
                }
                let nearby = sources.get(&pk).is_some_and(|s| !s.is_empty());
                if !nearby {
                    sources.remove(&pk);
                }
                if let Some(p) = inner.peers.lock().get_mut(&pk) {
                    let changed = p.nearby != nearby;
                    p.nearby = nearby;
                    changed
                } else {
                    false
                }
            };
            inner.update_direct(pk);
            if changed {
                inner.emit(NetEvent::PeersChanged);
            }
        }
        _ => {}
    }
}

fn lan_user_data(name: &str) -> Option<UserData> {
    let mut s = format!("mycel:{name}");
    while s.len() > UserData::MAX_LENGTH {
        s.pop();
    }
    UserData::try_from(s).ok()
}

// ─────────────────────────────────── Node ───────────────────────────────────

/// A running Mycel device: identity, Iroh endpoint and its Space replicas.
pub struct Node {
    inner: Arc<Inner>,
    router: Router,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Windows rounds sleeps and timeouts up to its 15.6 ms default timer tick,
/// which skews QUIC's pacing and loss timers, 20 ms call audio and the
/// emulated links' delays (tests ranked a 5 ms link below a slower one).
/// Ask for 1 ms, as browsers do for media; since Windows 10 2004 this only
/// affects this process. A no-op elsewhere.
pub fn fine_timers() {
    #[cfg(windows)]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: a plain winmm call. Never undone: it lasts as long as the process.
        ONCE.call_once(|| unsafe {
            windows_sys::Win32::Media::timeBeginPeriod(1);
        });
    }
}

impl Node {
    pub async fn spawn(keys: Arc<DeviceKeys>, opts: NodeOptions) -> Result<Self> {
        let me_pk = keys.sign_pk();
        fine_timers();
        // Same Ed25519 key for transport and for Mycel signatures (domain-separated).
        let secret = SecretKey::from_bytes(&keys.seed());
        let memory = MemoryLookup::new();
        // Every wire version we speak, newest (preferred) first: a peer
        // that only speaks an older one still gets that one.
        let node_alpns = wire::alpns(opts.protocol.version);
        let mesh_alpns = mesh::alpns(opts.protocol.version);
        let mut alpns: Vec<Vec<u8>> = node_alpns.iter().map(|a| a.to_vec()).collect();
        alpns.extend(opts.extra_protocols.iter().map(|p| p.alpn.clone()));
        let mesh = opts.mesh.clone().map(|o| {
            let o = MeshOptions { protocol: opts.protocol, ..o };
            Mesh::new(keys.clone(), &opts.name, o)
        });
        let mut links = opts.links;
        if let Some(m) = &mesh {
            alpns.extend(mesh_alpns.iter().map(|a| a.to_vec()));
            links.push(Arc::new(m.clone()));
        }
        let builder = match opts.mode {
            NetMode::Local => Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr(format!("127.0.0.1:{}", opts.port).as_str())?,
            NetMode::Lan => Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr(format!("0.0.0.0:{}", opts.port).as_str())?,
            NetMode::Internet => Endpoint::builder(presets::N0),
        };
        let mut builder = builder
            .secret_key(secret)
            .alpns(alpns)
            .path_selector(Arc::new(link::MycelPathSelector::default()))
            .transport_config(link::transport_config());
        if let Some(ud) = lan_user_data(&opts.name) {
            builder = builder.user_data_for_address_lookup(ud);
        }
        if !opts.ip {
            builder = builder.clear_ip_transports();
        }
        for l in &links {
            builder = builder.add_custom_transport(l.transport());
        }
        let endpoint = builder.bind().await?;
        if let Some(m) = &mesh {
            m.attach(endpoint.clone());
        }
        endpoint.address_lookup()?.add(memory.clone());
        let link_lookup = MemoryLookup::new();
        endpoint.address_lookup()?.add(link_lookup.clone());
        if let Some(m) = &mesh {
            // devices beyond our mesh: through gateways (theirs or ours)
            endpoint.address_lookup()?.add(m.address_lookup());
            if opts.mode == NetMode::Internet && opts.mesh.as_ref().is_some_and(|o| o.directory.is_none()) {
                match mesh::directory::PkarrDirectory::new(&endpoint, true) {
                    Ok(d) => m.set_directory(Arc::new(Arc::new(d))),
                    Err(e) => eprintln!("[mycel] no record directory: {e:#}"),
                }
            }
        }
        // LAN discovery (`_mycel._udp`): iroh's mDNS sends its own multicast,
        // which iOS allows only with Apple's multicast entitlement, so on iOS
        // the system's Bonjour responder discovers and advertises instead
        // (native_mdns.rs). Only one of the two runs, or they would claim the
        // same instance name. They interoperate: vendor/swarm-discovery.
        let native_lan = cfg!(target_os = "ios")
            || cfg!(target_os = "macos") && std::env::var_os("MYCEL_NATIVE_MDNS").is_some_and(|v| v == "1");
        let mdns = if opts.mode != NetMode::Local && !native_lan {
            let mdns = MdnsAddressLookup::builder().service_name("mycel").build(endpoint.id())?;
            endpoint.address_lookup()?.add(mdns.clone());
            Some(mdns)
        } else {
            None
        };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let native_mdns = if opts.mode != NetMode::Local && opts.ip && native_lan {
            let sockets = endpoint.bound_sockets();
            let port = sockets.iter().find(|a| a.is_ipv4()).or_else(|| sockets.first()).map_or(0, |a| a.port());
            match native_mdns::NativeMdns::start(endpoint.id(), port) {
                Ok((lookup, events)) => {
                    endpoint.address_lookup()?.add(lookup.clone());
                    Some((lookup, events))
                }
                Err(err) => {
                    eprintln!("[mycel] native Bonjour unavailable: {err}");
                    None
                }
            }
        } else {
            None
        };
        let (events, _) = broadcast::channel(1024);
        let pool = Pool::new(endpoint.clone(), opts.protocol.version);
        let inner = Arc::new(Inner {
            keys,
            mode: opts.mode,
            name: Mutex::new(opts.name),
            store: opts.store,
            blob_dir: opts.blob_dir,
            invite_policy: opts.invite_policy,
            blob_push_policy: opts.blob_push_policy,
            accept_relay_invites: opts.accept_relay_invites,
            feed_validator: opts.feed_validator,
            spaces: Mutex::default(),
            peers: Mutex::default(),
            lan_sources: Mutex::default(),
            events,
            memory,
            link_lookup,
            link_addrs: Mutex::default(),
            links,
            mesh: mesh.clone(),
            endpoint: endpoint.clone(),
            dirty: Mutex::default(),
            wake: Notify::new(),
            inflight: Mutex::default(),
            sync_slots: Semaphore::new(16),
            pool,
            accepted: AtomicU64::new(0),
            blob_served: AtomicU64::new(0),
            hellos_served: AtomicU64::new(0),
            hellos_failed: AtomicU64::new(0),
            #[cfg(test)]
            drop_hellos: Default::default(),
            #[cfg(test)]
            stall_hellos: Default::default(),
            bundles: Mutex::default(),
            conns: Mutex::default(),
            max_ephemeral: opts.max_ephemeral.min(wire::MAX_FRAME - wire::max_ephemeral_frame(0)),
            gossip: gossip::Gossip::new(me_pk, false),
            read_receipts: opts.read_receipts,
            // (a node without Sync v2 doesn't advertise it)
            protocol: if opts.sync_v2 {
                opts.protocol
            } else {
                Protocol {
                    caps: opts.protocol.caps.difference(Caps::SYNC_V2).difference(Caps::GOSSIP),
                    ..opts.protocol
                }
            },
            member_frames: resources::Frames::members(),
            stranger_frames: resources::Frames::strangers(),
            sync_v2: opts.sync_v2,
            local_writes: Mutex::default(),
            dirty_local: Mutex::default(),
            v2: sync_v2::V2::default(),
            periodic: Mutex::default(),
        });
        // (the router's order is the listener's preference: newest first)
        let mut router = Router::builder(endpoint);
        for alpn in node_alpns {
            router = router.accept(alpn, Handler { inner: inner.clone() });
        }
        for p in opts.extra_protocols {
            router = router.accept(p.alpn, Forward(p.incoming));
        }
        if let Some(m) = &mesh {
            for alpn in mesh_alpns {
                router = router.accept(alpn, m.protocol());
            }
        }
        let router = router.spawn();
        let mut tasks = vec![tokio::spawn(scheduler(inner.clone())), tokio::spawn(gossip::pump(inner.clone()))];
        let reaper = inner.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                reaper.pool.reap(POOL_IDLE);
                gossip::reap(&reaper);
                reaper.expire_reachability();
            }
        }));
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let Some((lookup, mut events)) = native_mdns {
            let native_inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                let _keep_alive = lookup;
                while let Some(ev) = events.recv().await {
                    on_lan_discovery(&native_inner, "native", ev);
                }
            }));
        }
        if let Some(mdns) = mdns {
            tasks.push(tokio::spawn(watch_mdns(inner.clone(), mdns)));
        }
        if let Some(m) = &inner.mesh {
            let (tx, mut rx) = mpsc::unbounded_channel::<(SignPk, u16, bytes::Bytes)>();
            m.set_bundle_sink(tx);
            let inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                while let Some((src, kind, payload)) = rx.recv().await {
                    let _ = inner.on_bundle(src, kind, &payload);
                }
            }));
        }
        for l in &inner.links {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let kind = l.kind();
            if let Err(e) = l.start(tx) {
                eprintln!("[mycel] {} unavailable: {e:#}", kind.label());
                continue;
            }
            let inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    inner.on_link_event(ev);
                }
            }));
        }
        Ok(Node { inner, router, tasks })
    }

    pub fn keys(&self) -> &Arc<DeviceKeys> {
        &self.inner.keys
    }

    pub fn id(&self) -> SignPk {
        self.inner.keys.sign_pk()
    }

    pub fn mode(&self) -> NetMode {
        self.inner.mode
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetEvent> {
        self.inner.events.subscribe()
    }

    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }

    /// Addresses other devices can reach us on (real interface IPs, not
    /// wildcard binds; loopback excluded unless that's all there is).
    pub fn local_addresses(&self) -> Vec<String> {
        let mut addrs: Vec<std::net::SocketAddr> = self.addr().ip_addrs().copied().collect();
        if addrs.iter().any(|a| !a.ip().is_loopback()) {
            addrs.retain(|a| !a.ip().is_loopback());
        }
        addrs.sort();
        addrs.dedup();
        addrs.iter().map(|a| a.to_string()).collect()
    }

    /// Remember direct addresses for a peer (from a contact code), so we can
    /// reach it even on networks where mDNS is blocked.
    pub fn add_peer_hints(&self, peer: SignPk, addrs: &[std::net::SocketAddr]) {
        if addrs.is_empty() {
            return;
        }
        if let Ok(id) = to_endpoint_id(&peer) {
            let mut a = EndpointAddr::new(id);
            for x in addrs {
                a = a.with_ip_addr(*x);
            }
            self.inner.memory.add_endpoint_info(a);
            self.inner.peer_reachable(peer);
        }
    }

    /// Tell the node how to reach a peer directly (tests / manual pairing).
    pub fn add_peer_addr(&self, addr: EndpointAddr) {
        let peer = to_sign_pk(&addr.id);
        self.inner.memory.add_endpoint_info(addr);
        self.inner.peer_reachable(peer);
    }

    /// The mesh router, if this node relays.
    pub fn mesh(&self) -> Option<&Mesh> {
        self.inner.mesh.as_ref()
    }

    /// Health of each link (peer-to-peer Wi-Fi, Bluetooth, each kind of
    /// network interface).
    pub fn link_status(&self) -> Vec<LinkStatus> {
        self.inner.links.iter().flat_map(|l| l.statuses()).collect()
    }

    pub fn set_name(&self, name: &str) {
        *self.inner.name.lock() = name.to_string();
        for l in &self.inner.links {
            l.set_name(name);
        }
        if self.inner.mode != NetMode::Local {
            self.router.endpoint().set_user_data_for_address_lookup(lan_user_data(name));
        }
    }

    pub fn card(&self) -> ContactCard {
        ContactCard::new(&self.inner.keys, &self.inner.name.lock())
    }

    pub fn peers(&self) -> HashMap<SignPk, PeerState> {
        self.inner.peers.lock().clone()
    }

    // ───────────── spaces ─────────────

    /// Found a new Space; returns its id and the genesis op.
    pub fn create_space(&self) -> Result<(SpaceId, SignedOp)> {
        let (mut r, genesis) = Replica::create(self.inner.keys.clone(), self.inner.store.clone())?;
        self.inner.prepare(&mut r);
        let id = r.space_id();
        self.inner.spaces.lock().insert(id, r);
        self.inner.refresh_affinity();
        Ok((id, genesis))
    }

    pub fn join_space(&self, genesis: SignedOp) -> Result<SpaceId> {
        let mut r = Replica::join(self.inner.keys.clone(), genesis, self.inner.store.clone())?;
        self.inner.prepare(&mut r);
        let id = r.space_id();
        self.inner.spaces.lock().entry(id).or_insert(r);
        self.inner.refresh_affinity();
        Ok(id)
    }

    /// Insert a restored replica (from storage at startup).
    pub fn insert_replica(&self, mut r: Replica) -> SpaceId {
        self.inner.prepare(&mut r);
        let id = r.space_id();
        self.inner.spaces.lock().insert(id, r);
        self.inner.refresh_affinity();
        id
    }

    pub fn space_ids(&self) -> Vec<SpaceId> {
        self.inner.spaces.lock().keys().copied().collect()
    }

    /// Run `f` against a Space replica (sync lock: no awaiting inside).
    pub fn with_space<R>(&self, space: &SpaceId, f: impl FnOnce(&mut Replica) -> R) -> Result<R> {
        self.inner.with_space(space, f)
    }

    /// Local change happened: push to members soon and notify the app.
    pub fn changed(&self, space: SpaceId) {
        self.inner.emit(NetEvent::SpaceChanged { space });
        // Pushed to gossip neighbours now; members gossip doesn't reach
        // get sessions from the scheduler.
        self.inner.gossip_changed(&space, None);
        self.inner.local_writes.lock().insert(space);
        self.inner.dirty_local.lock().insert(space);
        self.inner.loss_signal(space);
        self.inner.schedule(space);
    }

    /// UDP bytes sent and received on the node's recent connections (the
    /// last 256, open or closed): QUIC headers, acknowledgements and
    /// keep-alives included. For benchmarks.
    pub fn quic_udp_bytes(&self) -> (u64, u64) {
        self.inner
            .conns
            .lock()
            .iter()
            .map(|c| c.stats())
            .fold((0, 0), |(t, r), s| (t + s.udp_tx.bytes, r + s.udp_rx.bytes))
    }

    /// Gossip counters: messages and bytes on gossip streams, new items
    /// received by push, pulls (tests, benchmarks, the Network panel).
    pub fn gossip_totals(&self) -> GossipTotals {
        self.inner.gossip.totals()
    }

    /// The disseminator's own counters (pushes, announcements, prunes,
    /// duplicates).
    pub fn gossip_stats(&self) -> GossipStats {
        self.inner.gossip.stats()
    }

    /// Our gossip neighbours in `space`, with whether each edge is eager.
    pub fn gossip_neighbours(&self, space: &SpaceId) -> Vec<(SignPk, bool)> {
        self.inner.gossip.d.lock().neighbours(space)
    }

    /// Sync v2 counters (sessions, fallbacks, bytes): for tests and the
    /// Network panel.
    pub fn sync_v2_totals(&self) -> V2Totals {
        self.inner.v2.totals()
    }

    /// One full bidirectional sync of `space` with `peer`, now.
    ///
    /// `trust_peer` lets a freshly-invited device sync with its inviter before
    /// it has learned (via that very sync) that the inviter is a member.
    ///
    /// A peer that is syncing this space with us already (it opened to us at
    /// the same moment) or is over its session limits answers `Busy`: not a
    /// failure. This waits and runs its own session then (cheap once the
    /// crossing one has ended), for up to [`EXPLICIT_BUSY_WAIT`].
    pub async fn sync_with(&self, peer: SignPk, space: SpaceId, trust_peer: bool) -> Result<SyncStats> {
        let deadline = Instant::now() + EXPLICIT_BUSY_WAIT;
        loop {
            let res = sync_session(&self.inner, peer, space, trust_peer).await;
            if let Err(e) = &res
                && let Some(busy) = e.downcast_ref::<sync_v2::PeerBusy>()
            {
                let retry = busy.retry_after();
                if Instant::now() + retry < deadline {
                    tokio::time::sleep(retry).await;
                    continue;
                }
                // (no backoff: the peer is up)
                return res;
            }
            match &res {
                Ok(_) => self.inner.mark_ok(peer),
                Err(_) => self.inner.mark_fail(peer),
            }
            return res;
        }
    }

    /// Sync `space` with every member now and wait (best effort).
    pub async fn sync_all(&self, space: SpaceId) {
        let me = self.id();
        let members: Vec<SignPk> =
            self.with_space(&space, |r| r.members().into_iter().map(|(k, _)| k.sign_pk).collect()).unwrap_or_default();
        let mut set = tokio::task::JoinSet::new();
        for pk in members.into_iter().filter(|p| *p != me) {
            set.spawn(sync_once(self.inner.clone(), pk, space, Trigger::Manual));
        }
        while set.join_next().await.is_some() {}
    }

    /// Sync every space with every member now, all at once, and wait (best
    /// effort): a phone's background catch-up and pull-to-refresh.
    ///
    /// Every (space, member) sync starts together and the node's sync slots
    /// bound how many run, so a member who is asleep holds up only its own
    /// syncs, and each unreachable peer costs one connect timeout in all
    /// (the pool shares a failed dial with every sync waiting for it).
    /// Keepers and peers that are reachable right now go first; peers in
    /// failure backoff that aren't nearby are skipped, as the scheduler
    /// skips them.
    pub async fn sync_everything(&self) {
        let inner = &self.inner;
        let me = self.id();
        let mut targets: Vec<(u8, SignPk, SpaceId)> = {
            let spaces = inner.spaces.lock();
            let peers = inner.peers.lock();
            spaces
                .iter()
                .filter(|(_, r)| r.my_role().is_some())
                .flat_map(|(s, r)| r.members().into_iter().map(move |(k, role)| (k.sign_pk, role, *s)))
                .filter(|(pk, _, _)| *pk != me)
                .filter_map(|(pk, role, s)| {
                    let p = peers.get(&pk);
                    if p.is_some_and(|p| p.backing_off() && !p.nearby) {
                        return None;
                    }
                    let keeper = role == Role::Relay;
                    let reachable = p.is_some_and(PeerState::online);
                    Some((u8::from(!keeper) + u8::from(!reachable), pk, s))
                })
                .collect()
        };
        targets.sort_by_key(|(rank, _, _)| *rank);
        let mut set = tokio::task::JoinSet::new();
        for (_, pk, space) in targets {
            set.spawn(sync_once(inner.clone(), pk, space, Trigger::Manual));
        }
        while set.join_next().await.is_some() {}
    }

    /// Restrict every link to `peers` (`Some`: a phone's app went to the
    /// background, so a radio that would otherwise link with any device in
    /// range links only with these), or lift the restriction (`None`).
    /// See [`Link::restrict_to`].
    pub fn restrict_links(&self, peers: Option<&[SignPk]>) {
        for l in &self.inner.links {
            l.restrict_to(peers);
        }
    }

    /// Open a connection to a device for another protocol (see
    /// [`ExtraProtocol`]): dialed by key over every path the node knows
    /// (network, links, relay), with multipath failover.
    pub async fn connect(&self, peer: SignPk, alpn: &[u8]) -> Result<Connection> {
        self.connect_offering(peer, &[alpn]).await
    }

    /// [`Node::connect`] offering several versions of a protocol, newest
    /// (preferred) first: the peer's TLS picks the first of its own it was
    /// offered, which `Connection::alpn` then names. That is how a protocol
    /// served beside the node's gets versions too (docs/PROTOCOL.md §1).
    pub async fn connect_offering(&self, peer: SignPk, alpns: &[&[u8]]) -> Result<Connection> {
        let res = connect(&self.inner, &peer, alpns).await;
        match &res {
            Ok(c) => {
                self.inner.note_path(peer, c);
                self.inner.mark_ok(peer);
            }
            Err(_) => self.inner.mark_fail(peer),
        }
        res
    }

    /// What this node offers: its newest wire version and its capabilities.
    pub fn protocol(&self) -> Protocol {
        self.inner.protocol
    }

    /// The wire version and capabilities agreed with `peer`: on the pooled
    /// connection, dialed if there is none, after its hello (one round trip
    /// on a new connection; nothing on one already agreed). A capability is
    /// used with a peer only if [`PeerProtocol::supports`] it.
    pub async fn negotiate(&self, peer: SignPk) -> Result<PeerProtocol> {
        let conn = pooled(&self.inner, &peer).await?;
        Ok(conn.protocol(resources::REPLY_TIMEOUT).await)
    }

    /// QUIC connections (handshakes) this node has dialed and accepted.
    pub fn connection_counts(&self) -> ConnectionCounts {
        ConnectionCounts {
            dialed: self.inner.pool.dialed.load(Ordering::Relaxed),
            accepted: self.inner.accepted.load(Ordering::Relaxed),
            hellos_failed: self.inner.hellos_failed.load(Ordering::Relaxed),
        }
    }

    /// Close pooled connections unused for `idle` now (the node does this
    /// itself every few seconds with [`POOL_IDLE`]).
    pub fn close_idle_connections(&self, idle: Duration) {
        self.inner.pool.reap(idle);
    }

    /// A connection of another protocol finished an exchange with `peer`:
    /// count it as the peer being online, and remember the path it used.
    pub fn note_connection(&self, peer: SignPk, conn: &Connection) {
        self.inner.note_path(peer, conn);
        self.inner.mark_ok(peer);
    }

    // ───────────── cards, ephemeral, blobs ─────────────

    /// Fetch a device's self-signed contact card (anyone may ask).
    pub async fn fetch_card(&self, peer: SignPk) -> Result<ContactCard> {
        let inner = &self.inner;
        let card: ContactCard = on_conn!(inner, &peer, |conn| async {
            let (mut tx, mut rx) = open_bi(&conn, StreamKind::Card).await?;
            tx.finish()?;
            recv_small(&mut rx, resources::REPLY_TIMEOUT, &inner.reply_frames(&peer)).await
        })?;
        card.verify()?;
        if card.keys.sign_pk != peer {
            bail!("card does not belong to peer");
        }
        Ok(card)
    }

    /// Fire-and-forget an encrypted ephemeral message to online members.
    /// Payloads are limited to [`NodeOptions::max_ephemeral`] bytes.
    pub fn send_ephemeral(&self, space: SpaceId, data: Vec<u8>) -> Result<()> {
        anyhow::ensure!(data.len() <= self.inner.max_ephemeral, "ephemeral message too large");
        let me = self.id();
        let (msg, members) = self.with_space(&space, |r| {
            let sealed = r.seal_ephemeral(&eph_aad(&space, &me.0), &data);
            let members: Vec<SignPk> = r
                .members()
                .into_iter()
                .filter(|(_, role)| role.can_read())
                .map(|(k, _)| k.sign_pk)
                .filter(|pk| *pk != me)
                .collect();
            (sealed, members)
        })?;
        let (epoch, nonce, ciphertext) = msg.context("no usable epoch key")?;
        let msg = Arc::new(EphMsg { space, epoch, nonce, ciphertext });
        let online: HashSet<SignPk> = self.peers().into_iter().filter(|(_, p)| p.online()).map(|(pk, _)| pk).collect();
        for pk in members.into_iter().filter(|p| online.contains(p)) {
            let inner = self.inner.clone();
            let msg = msg.clone();
            tokio::spawn(async move {
                let _ = on_conn!(&inner, &pk, |conn| async {
                    let mut tx = resources::within(resources::REPLY_TIMEOUT, "no stream", conn.open_uni()).await?;
                    tx.set_priority(StreamKind::Ephemeral.priority()).ok();
                    tx.write_all(&[StreamKind::Ephemeral as u8]).await?;
                    send(&mut tx, &*msg).await?;
                    tx.finish()?;
                    tx.stopped().await?;
                    anyhow::Ok(())
                });
            });
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        for t in &self.tasks {
            t.abort();
        }
        for l in &self.inner.links {
            l.stop();
        }
        self.inner.pool.shutdown();
        // Closing sends every peer a CONNECTION_CLOSE at once, then waits
        // for them to acknowledge it, up to 3 probe timeouts per connection.
        // Over a slow radio, or to peers already gone, that is seconds:
        // don't hold up quitting for it.
        if let Ok(r) = tokio::time::timeout(SHUTDOWN_GRACE, self.router.shutdown()).await {
            r?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use link::{CustomAddr, TRANSPORT_BLUETOOTH, TRANSPORT_MESH, TRANSPORT_PEER_WIFI};

    #[test]
    fn periodic_backoff_doubles_to_its_cap_and_resets_on_loss() {
        let t0 = Instant::now();
        let mut b = Backoff::new(t0, 1.0);
        assert!(b.next - t0 <= Duration::from_secs(2), "the first round comes soon");
        let mut now = b.next;
        b.round(now, 1.0);
        assert_eq!(b.interval, PERIODIC_SYNC);
        let mut seen = Vec::new();
        for _ in 0..8 {
            now = b.next;
            b.round(now, 1.0);
            seen.push(b.interval.as_secs());
        }
        assert_eq!(seen, [30, 60, 120, 240, 480, 600, 600, 600]);
        // A sign of loss: the next round is within the first interval, and
        // the schedule starts over.
        let mid = now + Duration::from_secs(100);
        b.signal(mid);
        assert!(b.next <= mid + PERIODIC_SYNC);
        b.round(b.next, 1.0);
        assert_eq!(b.interval, PERIODIC_SYNC);
        b.round(b.next, 1.0);
        assert_eq!(b.interval, PERIODIC_SYNC * 2);
        for _ in 0..1000 {
            assert!((0.8..=1.2).contains(&jitter()));
        }
    }

    #[test]
    fn direct_discovery_excludes_mesh_and_recent_exchanges() {
        let mut state = PeerState { last_ok: Some(Instant::now()), ..Default::default() };
        assert!(state.online());
        assert!(!state.is_directly_discovered());
        state.links.insert(PathKind::Mesh);
        assert!(!state.is_directly_discovered());
        for kind in [PathKind::Bluetooth, PathKind::PeerWifi] {
            state.links.insert(kind);
            assert!(state.is_directly_discovered());
            state.links.remove(&kind);
            assert!(!state.is_directly_discovered());
        }
        state.nearby = true;
        assert!(state.is_directly_discovered());
    }

    #[tokio::test]
    async fn lan_discovery_sources_expire_independently() {
        let node = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "lan-source-test"))
            .await
            .unwrap();
        let peer = DeviceKeys::generate().sign_pk();
        let id = to_endpoint_id(&peer).unwrap();
        let found = || DiscoveryEvent::Discovered {
            endpoint_info: iroh::address_lookup::EndpointInfo::from_parts(id, Default::default()),
            last_updated: None,
        };
        let lost = || DiscoveryEvent::Expired { endpoint_id: id };
        on_lan_discovery(&node.inner, "native", found());
        on_lan_discovery(&node.inner, "raw", found());
        on_lan_discovery(&node.inner, "raw", lost());
        assert!(node.peers()[&peer].nearby);
        assert!(node.peers()[&peer].is_directly_discovered());
        on_lan_discovery(&node.inner, "native", lost());
        assert!(!node.peers()[&peer].nearby);
        assert!(!node.peers()[&peer].online());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn recent_reachability_expiry_emits_once_and_preserves_path_history() {
        let node = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "expiry-test"))
            .await
            .unwrap();
        let gone = DeviceKeys::generate().sign_pk();
        let live = DeviceKeys::generate().sign_pk();
        let old = Instant::now() - ONLINE_WINDOW - Duration::from_secs(1);
        node.inner
            .peers
            .lock()
            .insert(gone, PeerState { last_ok: Some(old), via: Some(PathKind::Relay), ..Default::default() });
        node.inner.peers.lock().insert(live, PeerState { last_ok: Some(old), nearby: true, ..Default::default() });
        let mut events = node.subscribe();
        node.inner.expire_reachability();
        assert!(matches!(events.try_recv(), Ok(NetEvent::PeersChanged)));
        assert!(!node.peers()[&gone].online());
        assert_eq!(node.peers()[&gone].via, Some(PathKind::Relay));
        assert!(node.peers()[&live].online());
        node.inner.expire_reachability();
        assert!(events.try_recv().is_err());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn direct_discovery_tracks_found_and_lost_link_addresses() {
        let node = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "discovery-test"))
            .await
            .unwrap();
        let peer = DeviceKeys::generate().sign_pk();
        let addr = |id, suffix| {
            let mut data = peer.0.to_vec();
            data.push(suffix);
            CustomAddr::from_parts(id, &data)
        };
        let mesh = addr(TRANSPORT_MESH, 0);
        let wifi1 = addr(TRANSPORT_PEER_WIFI, 1);
        let wifi2 = addr(TRANSPORT_PEER_WIFI, 2);
        let bluetooth = addr(TRANSPORT_BLUETOOTH, 0);
        let found =
            |addr| node.inner.on_link_event(LinkEvent::Found { peer, addr, name: Some("Nearby device".into()) });
        let lost = |addr| node.inner.on_link_event(LinkEvent::Lost { peer, addr });
        let state = || node.peers().remove(&peer).unwrap();
        found(mesh);
        node.inner.mark_ok(peer);
        assert!(state().online());
        assert!(!state().is_directly_discovered());
        found(wifi1.clone());
        found(wifi2.clone());
        found(bluetooth.clone());
        assert!(state().is_directly_discovered());
        assert!(!state().nearby, "direct radio discovery must not claim an mDNS/LAN path");
        lost(wifi1);
        assert!(state().links.contains(&PathKind::PeerWifi), "one Wi-Fi address remains");
        lost(wifi2);
        assert!(!state().links.contains(&PathKind::PeerWifi));
        assert!(state().is_directly_discovered(), "Bluetooth remains");
        lost(bluetooth);
        assert!(!state().is_directly_discovered(), "mesh and last_ok cannot retain proximity");
        assert!(state().online(), "a remote reachable peer can remain online");
        node.shutdown().await.unwrap();
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    use version::{WIRE_V1, WIRE_V2};

    async fn node(name: &str, protocol: Protocol) -> Node {
        let mut opts = NodeOptions::new(NetMode::Local, name);
        opts.protocol = protocol;
        Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap()
    }

    /// Two current devices agree on version 2 and on exactly the
    /// capabilities both have; bits one of them doesn't know are ignored.
    #[tokio::test]
    async fn current_devices_negotiate_version_2_and_common_capabilities() {
        let future = Caps::from_bits(1 << 40);
        let a = node("a", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 | Caps::ROUTE_ATTEST | future }).await;
        let b = node("b", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 }).await;
        // (b notes what a dialer agreed only for a device it shares a space with)
        let (space, _) = b.create_space().unwrap();
        b.with_space(&space, |r| r.add_member(a.keys().public(), Role::Writer)).unwrap().unwrap();
        a.add_peer_addr(b.addr());
        let p = a.negotiate(b.id()).await.unwrap();
        assert_eq!((p.version, p.caps), (WIRE_V2, Caps::SYNC_V2));
        assert!(p.supports(Caps::SYNC_V2) && !p.supports(Caps::ROUTE_ATTEST));
        assert_eq!(a.peers()[&b.id()].protocol, Some(p));
        // b agreed the same from a's hello, and set a's unknown bit aside
        let q = b.peers()[&a.id()].protocol.expect("b took a's hello");
        assert_eq!((q.version, q.caps), (WIRE_V2, Caps::SYNC_V2));
        assert!(q.advertised.contains(future) && q.advertised.contains(Caps::ROUTE_ATTEST));
        // agreed once per connection: asking again sends nothing
        assert_eq!(a.negotiate(b.id()).await.unwrap(), p);
        assert_eq!(a.connection_counts().dialed, 1);
        assert_eq!(b.inner.hellos_served.load(Ordering::Relaxed), 1, "one hello for the connection");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    /// A hello lost on the way (as on a flaky Bluetooth or multi-hop path)
    /// doesn't cost the connection its capabilities for good: it is
    /// counted, the connection has none for now, and a later use of the
    /// same connection tries again and agrees them. Tries are bounded.
    #[tokio::test]
    async fn a_failed_hello_is_retried_on_the_same_connection() {
        let a = node("a", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 }).await;
        let b = node("b", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 }).await;
        a.add_peer_addr(b.addr());
        b.inner.drop_hellos.store(1, Ordering::SeqCst);
        let p = a.negotiate(b.id()).await.unwrap();
        assert_eq!((p.version, p.caps), (WIRE_V2, Caps::NONE), "no capabilities while the hello failed");
        assert_eq!(a.connection_counts().hellos_failed, 1);
        // too soon to try again: still none, nothing sent
        assert_eq!(a.negotiate(b.id()).await.unwrap().caps, Caps::NONE);
        tokio::time::sleep(pool::HELLO_RETRY + Duration::from_millis(100)).await;
        let p = a.negotiate(b.id()).await.unwrap();
        assert_eq!((p.version, p.caps), (WIRE_V2, Caps::SYNC_V2), "agreed on the retry");
        assert_eq!(a.peers()[&b.id()].protocol, Some(p));
        let counts = a.connection_counts();
        assert_eq!((counts.dialed, counts.hellos_failed), (1, 1), "same connection, one failure");
        assert_eq!(b.inner.hellos_served.load(Ordering::Relaxed), 1);
        a.shutdown().await.unwrap();

        // every try lost: bounded, then the connection stays without
        let c = node("c", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 }).await;
        c.add_peer_addr(b.addr());
        b.inner.drop_hellos.store(u32::MAX, Ordering::SeqCst);
        for i in 0..pool::HELLO_TRIES + 2 {
            assert_eq!(c.negotiate(b.id()).await.unwrap().caps, Caps::NONE);
            tokio::time::sleep(pool::HELLO_RETRY * 2u32.pow(i.min(pool::HELLO_TRIES)) + Duration::from_millis(50))
                .await;
        }
        assert_eq!(c.connection_counts().hellos_failed, pool::HELLO_TRIES as u64);
        assert_eq!(c.connection_counts().dialed, 1);
        b.inner.drop_hellos.store(0, Ordering::SeqCst);
        c.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    /// Devices b has never dealt with (fresh keys cost nothing) dial it,
    /// on version 1 and with a hello on version 2: b answers them all but
    /// keeps no state about them, which nothing would ever remove. A member
    /// that dials is noted.
    #[tokio::test]
    async fn strangers_that_dial_leave_no_peer_state() {
        let b = node("b", Protocol::default()).await;
        for i in 0..8 {
            let version = if i % 2 == 0 { WIRE_V1 } else { WIRE_V2 };
            let s = node("stranger", Protocol { version, caps: Caps::SYNC_V2 }).await;
            s.add_peer_addr(b.addr());
            assert_eq!(s.fetch_card(b.id()).await.unwrap().keys.sign_pk, b.id());
            assert_eq!(s.negotiate(b.id()).await.unwrap().version, version);
            s.shutdown().await.unwrap();
        }
        assert_eq!(b.inner.hellos_served.load(Ordering::Relaxed), 4, "the version 2 strangers were answered");
        assert_eq!(b.connection_counts().accepted, 8);
        assert!(b.peers().is_empty(), "no state for strangers: {:?}", b.peers().keys().collect::<Vec<_>>());

        let m = node("member", Protocol { version: WIRE_V1, caps: Caps::NONE }).await;
        let (space, _) = b.create_space().unwrap();
        b.with_space(&space, |r| r.add_member(m.keys().public(), Role::Writer)).unwrap().unwrap();
        m.add_peer_addr(b.addr());
        m.negotiate(b.id()).await.unwrap();
        let noted = || b.peers().get(&m.id()).and_then(|p| p.protocol);
        let until = Instant::now() + Duration::from_secs(5);
        while noted().is_none() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(noted(), Some(PeerProtocol::baseline(WIRE_V1)));
        assert_eq!(b.peers().len(), 1);
        m.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    /// A pre-release device (version 1 only) and a current one still do
    /// everything they did together: version 1 is chosen in the handshake
    /// whoever dials, no hello is sent, no capability is used, and spaces
    /// sync both ways.
    #[tokio::test]
    async fn a_version_1_device_and_a_version_2_device_talk_version_1() {
        let new = node("new", Protocol { version: WIRE_V2, caps: Caps::SYNC_V2 }).await;
        let old = node("old", Protocol { version: WIRE_V1, caps: Caps::SYNC_V2 }).await;
        new.add_peer_addr(old.addr());
        old.add_peer_addr(new.addr());
        assert_eq!(new.negotiate(old.id()).await.unwrap(), PeerProtocol::baseline(WIRE_V1));
        assert_eq!(old.negotiate(new.id()).await.unwrap(), PeerProtocol::baseline(WIRE_V1));
        let (space, _) = new.create_space().unwrap();
        new.with_space(&space, |r| r.add_member(old.keys().public(), Role::Writer)).unwrap().unwrap();
        new.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"from new".to_vec())).unwrap().unwrap();
        new.sync_with(old.id(), space, false).await.unwrap();
        assert_eq!(old.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 1, "the invitation and its data");
        old.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"from old".to_vec())).unwrap().unwrap();
        old.sync_with(new.id(), space, false).await.unwrap();
        assert_eq!(new.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 2);
        assert_eq!(new.fetch_card(old.id()).await.unwrap().keys.sign_pk, old.id());
        assert_eq!(old.fetch_card(new.id()).await.unwrap().keys.sign_pk, new.id());
        new.shutdown().await.unwrap();
        old.shutdown().await.unwrap();
    }

    /// Sync v2 is chosen by capability: two current devices use it, and a
    /// device that refuses the stream all the same (here: a build without
    /// Sync v2, opened regardless of its hello) is synced with v1 and
    /// remembered as v1-only at once, since the refusal is explicit.
    #[tokio::test]
    async fn a_refused_sync_v2_falls_back_and_is_remembered() {
        let new = node("new", Protocol::default()).await;
        let mut opts = NodeOptions::new(NetMode::Local, "old");
        opts.sync_v2 = false;
        let old = Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap();
        let peer = node("peer", Protocol::default()).await;
        for (a, b) in [(&new, &old), (&old, &new), (&new, &peer), (&peer, &new)] {
            a.add_peer_addr(b.addr());
        }
        assert!(new.negotiate(peer.id()).await.unwrap().supports(Caps::SYNC_V2));
        assert!(!new.negotiate(old.id()).await.unwrap().supports(Caps::SYNC_V2));
        let (space, _) = new.create_space().unwrap();
        new.with_space(&space, |r| r.add_member(old.keys().public(), Role::Writer)).unwrap().unwrap();
        new.with_space(&space, |r| r.add_member(peer.keys().public(), Role::Writer)).unwrap().unwrap();
        new.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"hi".to_vec())).unwrap().unwrap();
        new.sync_with(peer.id(), space, false).await.unwrap();
        assert_eq!(peer.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 1);
        assert!(new.sync_v2_totals().client_sessions >= 1, "both have it: v2");
        // Opened despite the hello: refused, so nothing ran, and remembered.
        let ran = sync_v2::sync(&new.inner, old.id(), space, false, false).await.unwrap();
        assert!(ran.is_none());
        let t = new.sync_v2_totals();
        assert_eq!((t.fallbacks, t.remembered_v1), (1, 1), "{t:?}");
        assert!(new.inner.v2.is_v1_only(&old.id()));
        new.sync_with(old.id(), space, false).await.unwrap();
        assert_eq!(old.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 1, "v1: the invitation and its data");
        for n in [new, old, peer] {
            n.shutdown().await.unwrap();
        }
    }

    /// A hello that never gets an answer (a path that black-holes it) holds
    /// a sync on a fresh connection only for the short hello wait, not a
    /// whole reply timeout: the sync runs v1 and succeeds. Regression test
    /// for the integration finding that it waited `REPLY_TIMEOUT` (60 s).
    #[tokio::test]
    async fn a_hung_hello_falls_back_to_v1_quickly() {
        let a = node("a", Protocol::default()).await;
        let b = node("b", Protocol::default()).await;
        b.inner.stall_hellos.store(true, Ordering::SeqCst);
        a.add_peer_addr(b.addr());
        b.add_peer_addr(a.addr());
        let (space, _) = a.create_space().unwrap();
        a.with_space(&space, |r| r.add_member(b.keys().public(), Role::Writer)).unwrap().unwrap();
        a.with_space(&space, |r| r.append(mycel_sync::StreamId::new_feed(), b"hi".to_vec())).unwrap().unwrap();
        let started = Instant::now();
        a.sync_with(b.id(), space, false).await.unwrap();
        let took = started.elapsed();
        assert!(took < HELLO_WAIT_MAX + Duration::from_secs(2), "took {took:?}");
        assert_eq!(b.with_space(&space, |r| r.envelope_ids().len()).unwrap(), 1);
        assert_eq!(a.sync_v2_totals().client_sessions, 0, "no hello: v1");
        for n in [a, b] {
            n.shutdown().await.unwrap();
        }
    }

    /// A stream kind the device doesn't know (a newer build's) is refused
    /// at once with a typed error: never a timeout, never bytes read as
    /// something else; the connection carries on. A version 1 connection
    /// has no hello, so a hello on one is unknown too.
    #[tokio::test]
    async fn unknown_stream_kinds_are_refused_cleanly() {
        use iroh::endpoint::VarInt;
        let a = node("a", Protocol::default()).await;
        let b = node("b", Protocol::default()).await;
        a.add_peer_addr(b.addr());
        let conn = pooled(&a.inner, &b.id()).await.unwrap();
        let start = Instant::now();
        let (mut tx, mut rx) = open_bi_raw(&conn, 0xee, 1).await.unwrap();
        let _ = send(&mut tx, &42u32).await;
        let err = recv::<u32>(&mut rx).await.unwrap_err();
        assert_eq!(err.downcast_ref::<VersionError>(), Some(&VersionError::StreamRefused), "{err:#}");
        assert!(start.elapsed() < Duration::from_secs(5), "refused, not timed out");
        let mut uni = conn.open_uni().await.unwrap();
        uni.write_all(&[0xee, 1, 2, 3]).await.unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(5), uni.stopped()).await.unwrap().unwrap();
        assert_eq!(stopped, Some(VarInt::from_u32(STREAM_REFUSED)));
        assert_eq!(a.fetch_card(b.id()).await.unwrap().keys.sign_pk, b.id(), "the connection still works");
        drop(conn);

        let v1 = a.inner.endpoint.connect(b.addr(), wire::ALPN_V1).await.unwrap();
        assert_eq!(wire::version_of(v1.alpn()), Some(WIRE_V1));
        let (mut tx, mut rx) = open_bi(&v1, StreamKind::Hello).await.unwrap();
        let _ = send(&mut tx, &Hello::ours(Caps::NONE)).await;
        let err = recv::<Hello>(&mut rx).await.unwrap_err();
        assert_eq!(err.downcast_ref::<VersionError>(), Some(&VersionError::StreamRefused), "{err:#}");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    /// A node serves its versions newest first, so a dialer that offers
    /// several lands on the newest, on the node protocol and on mesh hops
    /// alike, even one listing the oldest first (TLS goes by the listener's
    /// order). A node registering an old version first would quietly put
    /// every current pair on it.
    #[tokio::test]
    async fn a_node_serves_its_newest_versions_first() {
        let a = node("a", Protocol::default()).await;
        let mut opts = NodeOptions::new(NetMode::Local, "b");
        opts.mesh = Some(MeshOptions::default());
        let b = Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap();
        for (table, newest) in [(&wire::ALPNS, wire::ALPN_V2), (&mesh::ALPNS, mesh::ALPN_V2)] {
            let oldest_first: Vec<&[u8]> = table.iter().map(|(_, a)| *a).collect();
            let (first, rest) = oldest_first.split_first().unwrap();
            let options = ConnectOptions::new().with_additional_alpns(rest.iter().map(|a| a.to_vec()).collect());
            let conn = a.inner.endpoint.connect_with_opts(b.addr(), first, options).await.unwrap().await.unwrap();
            assert_eq!(conn.alpn(), newest, "offered {oldest_first:?}");
            conn.close(0u32.into(), b"");
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    /// Store-and-forward v2 on a node: a plaintext identical to one in
    /// flight isn't sealed or sent again (sealing changes the bundle id
    /// every time), and at most `SOURCE_BUDGET` of our bundles are in
    /// flight across destinations.
    #[tokio::test]
    async fn bundles_are_deduplicated_on_the_plaintext_and_budgeted_per_source() {
        let mut opts = NodeOptions::new(NetMode::Local, "src");
        opts.mesh = Some(MeshOptions::default());
        let n = Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap();
        let (space, _) = n.create_space().unwrap();
        let peers: Vec<Arc<DeviceKeys>> = (0..24).map(|_| Arc::new(DeviceKeys::generate())).collect();
        n.with_space(&space, |r| {
            for p in &peers {
                r.add_member(p.public(), Role::Writer).unwrap();
            }
            let feed = mycel_sync::StreamId::new_feed();
            for i in 0..700 {
                r.append(feed, vec![i as u8; 200]).unwrap();
            }
        })
        .unwrap();
        n.inner.offer_bundle(peers[0].sign_pk(), space);
        n.inner.offer_bundle(peers[0].sign_pk(), space);
        {
            let b = n.inner.bundles.lock();
            assert_eq!(b.sent, 2, "the backlog is larger than a bundle: the second continues it");
        }
        // A destination whose backlog is all in flight gets nothing new; with
        // nothing new, the same plaintext isn't sent twice.
        let small = Arc::new(DeviceKeys::generate());
        let (space2, _) = n.create_space().unwrap();
        n.with_space(&space2, |r| r.add_member(small.public(), Role::Writer).unwrap()).unwrap();
        n.inner.offer_bundle(small.sign_pk(), space2);
        n.inner.offer_bundle(small.sign_pk(), space2);
        assert_eq!(n.inner.bundles.lock().sent, 3, "nothing new: no second bundle");
        for p in &peers[1..] {
            n.inner.offer_bundle(p.sign_pk(), space);
        }
        {
            let b = n.inner.bundles.lock();
            assert!(b.over_budget >= 1, "sent {} before the budget", b.sent);
            assert!(b.in_flight_bytes() <= bundles::SOURCE_BUDGET, "{} B in flight", b.in_flight_bytes());
        }
        n.shutdown().await.unwrap();
    }

    #[test]
    fn stream_kinds_per_version() {
        assert_eq!(StreamKind::on(WIRE_V2, 5), Some(StreamKind::Hello));
        assert_eq!(StreamKind::on(WIRE_V1, 5), None, "version 1 has no hello");
        assert_eq!(StreamKind::on(WIRE_V1, 1), Some(StreamKind::Sync));
        assert_eq!(StreamKind::on(WIRE_V2, 6), Some(StreamKind::SyncV2));
        assert_eq!(StreamKind::on(WIRE_V1, 6), None, "version 1 has no Sync v2");
        assert_eq!(StreamKind::on(WIRE_V2, 7), Some(StreamKind::Gossip));
        assert_eq!(StreamKind::on(WIRE_V1, 7), None, "version 1 has no gossip");
        assert!((8..=255).all(|b| StreamKind::on(WIRE_V2, b).is_none()) && StreamKind::on(WIRE_V2, 0).is_none());
        assert_eq!(wire::alpns(WIRE_V2), vec![wire::ALPN_V2, wire::ALPN_V1]);
        assert_eq!(wire::alpns(WIRE_V1), vec![wire::ALPN_V1]);
        assert_eq!(wire::version_of(b"mycel/node/3"), None);
    }

    /// Every supported version has one ALPN per protocol, its own: none
    /// shared between versions or protocols, and each maps back to its
    /// version. (A version added without its ALPNs doesn't build.)
    #[test]
    fn every_version_has_its_own_alpns() {
        use version::{MIN_WIRE_VERSION, WIRE_VERSION, alpn_table_ok};
        let mut seen: Vec<&[u8]> = Vec::new();
        for v in MIN_WIRE_VERSION..=WIRE_VERSION {
            let (node, mesh) =
                (wire::ALPNS[usize::from(v - MIN_WIRE_VERSION)], mesh::ALPNS[usize::from(v - MIN_WIRE_VERSION)]);
            assert_eq!((node.0, mesh.0), (v, v));
            assert_eq!(wire::version_of(node.1), Some(v));
            assert_eq!(mesh::version_of(mesh.1), Some(v));
            assert_eq!(wire::alpns(v)[0], node.1, "the newest offered first");
            assert_eq!(mesh::alpns(v)[0], mesh.1);
            assert!(!seen.contains(&node.1) && !seen.contains(&mesh.1) && node.1 != mesh.1);
            seen.extend([node.1, mesh.1]);
        }
        assert_eq!(wire::alpns(WIRE_VERSION).len(), usize::from(WIRE_VERSION - MIN_WIRE_VERSION) + 1);
        // what the compile-time check refuses
        assert!(!alpn_table_ok(&[(WIRE_V1, b"same"), (WIRE_V2, b"same")]), "two versions, one name");
        assert!(!alpn_table_ok(&[(WIRE_V2, b"a"), (WIRE_V1, b"b")]), "out of place");
        assert!(!alpn_table_ok(&[(WIRE_V1, b"a"), (WIRE_V2, b"")]), "no name");
    }

    /// A store-and-forward payload of a kind this build doesn't know is
    /// refused unread with a typed error (it was delivered: the mesh sent
    /// its receipt); a known kind that doesn't decode is an error, not a
    /// panic.
    #[tokio::test]
    async fn bundles_of_an_unknown_payload_kind_are_refused_unread() {
        let n = node("n", Protocol::default()).await;
        let src = DeviceKeys::generate().sign_pk();
        let err = n.inner.on_bundle(src, 999, b"from a newer build").unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<VersionError>(),
                Some(VersionError::Unsupported { what: "bundle payload kind", version: 999, .. })
            ),
            "{err:#}"
        );
        assert!(n.inner.on_bundle(src, mesh::dtn::KIND_SPACE_SYNC, &[0xff; 3]).is_err());
        n.shutdown().await.unwrap();
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn security_gather_deduplicates_requested_records() {
        let (r, genesis) = Replica::create(Arc::new(DeviceKeys::generate()), None).unwrap();
        let want = Inventory { ops: vec![genesis.id(); 1024], envelopes: vec![] };
        let data = gather(&r, &want, MAX_FRAME - 1).unwrap();
        assert_eq!(data.ops.len(), 1);
    }
}

#[cfg(test)]
mod security_gather_tests {
    use super::*;
    #[test]
    fn security_gather_envelope_duplicates_and_exact_budget() {
        let (mut r, genesis) = Replica::create(Arc::new(DeviceKeys::generate()), None).unwrap();
        let (_, env) = r.append(mycel_sync::StreamId::new_feed(), vec![42; 16 * 1024]).unwrap();
        let want = Inventory { ops: vec![genesis.id(); 1024], envelopes: vec![env.id(); 1024] };
        let expected = Data { ops: vec![genesis], envelopes: vec![env] };
        let size = wire::encoded_size(&expected, MAX_FRAME).unwrap();
        let actual = gather(&r, &want, size).unwrap();
        assert_eq!(actual.ops.len(), 1);
        assert_eq!(actual.envelopes.len(), 1);
        assert_eq!(wire::encoded_size(&actual, MAX_FRAME).unwrap(), size);
        assert!(gather(&r, &want, size - 1).is_err());
        assert!(gather(&r, &want, 128).is_err());
    }
}

#[cfg(test)]
mod security_exchange_tests {
    use super::*;

    #[tokio::test]
    async fn security_responder_deduplicates_want_over_real_quic() {
        let alice =
            Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "alice")).await.unwrap();
        let bob = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "bob")).await.unwrap();
        let (space, genesis) = bob.create_space().unwrap();
        bob.with_space(&space, |r| r.add_member(alice.keys().public(), Role::Writer)).unwrap().unwrap();
        let conn = alice.inner.endpoint.connect(bob.addr(), ALPN).await.unwrap();
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Sync).await.unwrap();
        send(&mut tx, &SyncMsg::Hello { space, inv: Inventory::default(), invite: None }).await.unwrap();
        assert!(matches!(recv::<SyncMsg>(&mut rx).await.unwrap(), SyncMsg::Accept { .. }));
        send(
            &mut tx,
            &SyncMsg::DataAndWant {
                data: Data::default(),
                want: Inventory { ops: vec![genesis.id(); 1024], envelopes: vec![] },
            },
        )
        .await
        .unwrap();
        let SyncMsg::Data { data } = recv(&mut rx).await.unwrap() else { panic!("expected data") };
        assert_eq!(data.ops.len(), 1);
        alice.shutdown().await.unwrap();
        bob.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn security_initiator_deduplicates_want_over_real_quic() {
        let alice =
            Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "alice")).await.unwrap();
        let remote_keys = DeviceKeys::generate();
        let remote = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&remote_keys.seed()))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let (space, genesis) = alice.create_space().unwrap();
        alice.with_space(&space, |r| r.add_member(remote_keys.public(), Role::Writer)).unwrap().unwrap();
        let id = genesis.id();
        let remote_task = {
            let remote = remote.clone();
            tokio::spawn(async move {
                let conn = remote.accept().await.unwrap().await.unwrap();
                let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
                assert_eq!(stream_kind(WIRE_V2, None, &mut rx).await.unwrap(), StreamKind::Sync);
                assert!(matches!(recv::<SyncMsg>(&mut rx).await.unwrap(), SyncMsg::Hello { .. }));
                send(
                    &mut tx,
                    &SyncMsg::Accept {
                        inv: Inventory::default(),
                        want: Inventory { ops: vec![id; 1024], envelopes: vec![] },
                    },
                )
                .await
                .unwrap();
                let SyncMsg::DataAndWant { data, .. } = recv(&mut rx).await.unwrap() else { panic!("expected data") };
                assert_eq!(data.ops.len(), 1);
                send(&mut tx, &SyncMsg::Data { data: Data::default() }).await.unwrap();
                tx.finish().unwrap();
                tx.stopped().await.unwrap();
            })
        };
        let conn = alice.inner.endpoint.connect(remote.addr(), ALPN).await.unwrap();
        let inv = alice.with_space(&space, |r| inventory(r)).unwrap();
        sync_exchange(&alice.inner, &conn, remote_keys.sign_pk(), space, inv, vec![]).await.unwrap();
        remote_task.await.unwrap();
        alice.shutdown().await.unwrap();
        remote.close().await;
    }
    #[tokio::test]
    async fn security_invite_policy_runs_only_after_validation() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opts = NodeOptions::new(NetMode::Local, "receiver");
        let observed = calls.clone();
        opts.invite_policy = Arc::new(move |_, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            false
        });
        let receiver = Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap();
        let sender = Arc::new(DeviceKeys::generate());
        let (mut replica, genesis) = Replica::create(sender.clone(), None).unwrap();
        let space = genesis.id();
        assert!(!accept_invite(&receiver.inner, sender.sign_pk(), space, vec![genesis]));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        replica.add_member(receiver.keys().public(), Role::Writer).unwrap();
        assert!(!accept_invite(&receiver.inner, sender.sign_pk(), space, replica.all_ops()));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!receiver.inner.spaces.lock().contains_key(&space));
        receiver.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn security_ephemeral_plaintext_boundary() {
        let node =
            Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, "ephemeral")).await.unwrap();
        let (space, _) = node.create_space().unwrap();
        assert!(node.send_ephemeral(space, vec![42; MAX_EPHEMERAL]).is_ok());
        assert!(node.send_ephemeral(space, vec![42; MAX_EPHEMERAL + 1]).is_err());
        node.shutdown().await.unwrap();
    }
}

/// `n` members of `ranked` (rendezvous order) not in `skip`: lowest `tier`
/// first (0 recently reachable, 1 unknown, 2 failing), by rank within a tier.
fn pick_ranked(ranked: &[(Hash32, SignPk)], skip: &[SignPk], n: usize, tier: impl Fn(&SignPk) -> u8) -> Vec<SignPk> {
    let mut picks: Vec<(u8, usize, SignPk)> =
        ranked.iter().enumerate().filter(|(_, (_, p))| !skip.contains(p)).map(|(i, (_, p))| (tier(p), i, *p)).collect();
    picks.sort_unstable();
    picks.into_iter().take(n).map(|(_, _, p)| p).collect()
}

#[cfg(test)]
mod view_tests {
    use super::*;

    #[test]
    fn view_replaces_unreachable_members_by_rank() {
        let ranked: Vec<(Hash32, SignPk)> = (0..10u8).map(|i| (Hash32([i; 32]), SignPk([i; 32]))).collect();
        let pk = |i: u8| SignPk([i; 32]);
        // Nothing known: the first two by rank.
        assert_eq!(pick_ranked(&ranked, &[], 2, |_| 1), vec![pk(0), pk(1)]);
        // The first two fail: the next two by rank replace them.
        let failing = |p: &SignPk| if p.0[0] < 2 { 2 } else { 1 };
        assert_eq!(pick_ranked(&ranked, &[], 2, failing), vec![pk(2), pk(3)]);
        // A recently reachable member is preferred over unknown ones.
        let seen = |p: &SignPk| if p.0[0] == 7 { 0 } else { 1 };
        assert_eq!(pick_ranked(&ranked, &[pk(0)], 2, seen), vec![pk(7), pk(1)]);
        // Everyone failing: still the best by rank (retried after backoff).
        assert_eq!(pick_ranked(&ranked, &[], 2, |_| 2), vec![pk(0), pk(1)]);
    }
}
