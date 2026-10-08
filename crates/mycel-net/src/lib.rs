//! Mycel network layer (docs/TRUST.md §8): Spaces over Iroh, with live sync,
//! LAN discovery, invites, contact cards, ephemeral messages and blobs.
//!
//! The device's Ed25519 key *is* its Iroh endpoint id, so every QUIC
//! connection is authenticated to a device. On top of that, a device only
//! syncs a Space with its current members (any role, including Relay
//! keepers), and everything received is re-validated by the receiving
//! `Replica` — nothing is trusted because of who sent it.
//!
//! Connections: one ALPN ([`wire::ALPN`]), and a long-lived connection per
//! peer from a small connection pool (`pool.rs`; closed after [`POOL_IDLE`]
//! without use, redialed when it breaks). Every exchange is a new QUIC stream on it, labelled by a
//! [`wire::StreamKind`] byte; the server accepts streams in a loop. QUIC does
//! the multiplexing, flow control and loss recovery; stream priorities send
//! messages ahead of file bytes. No handshake per sync, and the connection's
//! extra paths (links, other interfaces) stay open and measured.
//!
//! Sync protocol (stream kind `Sync`), one bi-stream, strictly alternating so
//! neither side can deadlock on flow control:
//!
//! ```text
//! C → S  Hello{space, inv, invite?}
//! S → C  Denied | NeedInvite | Accept{inv, want}
//! C → S  DataAndWant{data, want}
//! S → C  Data{data}
//! ```

mod blobs;
mod pool;
pub mod link;
pub mod mesh;
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
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use pool::{Pool, PooledConn};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_sync::{EnvelopeId, FeedValidator, Replica, Store};
use mycel_trust::{Role, SignedOp, SpaceId};
use n0_future::StreamExt;
use tokio::sync::{Notify, Semaphore, broadcast, mpsc};

pub use blobs::{EAGER_PUSH_MAX, MIN_FREE_SPACE, Progress, blob_digest, ensure_free_space, free_space, human_size};
pub use iroh;
pub use link::{Link, LinkEvent, LinkStatus, PathKind};
pub use mesh::{Mesh, MeshOptions, MeshRoute, MeshStats, Tap};
pub use wire::ContactCard;
use wire::*;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// A pooled connection unused (no stream open from our side) this long is closed.
pub const POOL_IDLE: Duration = Duration::from_secs(60);
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const PERIODIC_SYNC: Duration = Duration::from_secs(15);
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
            accept_relay_invites: false,
            port: 0,
            feed_validator: None,
            links: Vec::new(),
            ip: true,
            extra_protocols: Vec::new(),
            mesh: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// New ops/envelopes were ingested into a space (from sync or locally).
    SpaceChanged { space: SpaceId },
    /// A space was pushed to us and accepted.
    SpaceAdded { space: SpaceId, from: SignPk },
    Ephemeral { space: SpaceId, from: SignPk, data: Vec<u8> },
    /// Nearby (mDNS) peer list or a peer's online status changed.
    PeersChanged,
    BlobStored { hash: Hash32 },
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
}

impl PeerState {
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
    accept_relay_invites: bool,
    feed_validator: Option<Arc<dyn FeedValidator>>,
    spaces: Mutex<HashMap<SpaceId, Replica>>,
    peers: Mutex<HashMap<SignPk, PeerState>>,
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
    /// The last store-and-forward bundle sent per (member, space).
    bundled: Mutex<HashMap<(SignPk, SpaceId), Hash32>>,
}

/// How many QUIC connections (handshakes) a node has made.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCounts {
    /// Dialed by us (through the pool).
    pub dialed: u64,
    /// Accepted from peers.
    pub accepted: u64,
}

impl Inner {
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

    /// Remember which path a finished exchange used (for the Network panel).
    fn note_path(&self, pk: SignPk, conn: &Connection) {
        let Some(addr) = conn.paths().iter().find(|p| p.is_selected()).map(|p| p.remote_addr().clone()) else {
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
                self.link_addrs.lock().entry(peer).or_default().insert(addr);
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
            let shared: Vec<SpaceId> = self
                .spaces
                .lock()
                .iter()
                .filter(|(_, r)| r.is_member(&peer))
                .map(|(s, _)| *s)
                .collect();
            for s in shared {
                tokio::spawn(sync_once(self.clone(), peer, s));
            }
        }
    }

    /// Tell the mesh whether `peer` has a direct path (a link or the LAN):
    /// neighbours relay for us, and get no mesh addresses themselves.
    fn update_direct(&self, peer: SignPk) {
        let Some(mesh) = &self.mesh else { return };
        let direct = self
            .peers
            .lock()
            .get(&peer)
            .is_some_and(|p| p.nearby || p.links.iter().any(|k| *k != PathKind::Mesh));
        mesh.set_direct(peer, direct);
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

    fn with_space<R>(&self, space: &SpaceId, f: impl FnOnce(&mut Replica) -> R) -> Result<R> {
        let mut spaces = self.spaces.lock();
        let r = spaces.get_mut(space).ok_or_else(|| anyhow!("unknown space"))?;
        Ok(f(r))
    }

    /// `peer` (a member of `space`) can't be reached live: send what it may
    /// lack through store-and-forward carriers (no plaintext leaves us:
    /// envelopes are already signed and encrypted).
    fn offer_bundle(&self, peer: SignPk, space: SpaceId) {
        let Some(mesh) = &self.mesh else { return };
        let data = self
            .with_space(&space, |r| {
                if !r.is_member(&peer) {
                    return None;
                }
                let envelopes: Vec<_> = r
                    .envelope_ids()
                    .iter()
                    .filter(|id| !r.holders(id).contains(&peer))
                    .filter_map(|id| r.envelope(id).cloned())
                    .collect();
                (!envelopes.is_empty()).then(|| Data { ops: r.all_ops(), envelopes })
            })
            .ok()
            .flatten();
        let Some(mut data) = data else { return };
        let payload = loop {
            let Ok(p) = postcard::to_allocvec(&DtnPayload { space, data }) else { return };
            if p.len() <= MAX_BUNDLE_PAYLOAD {
                break p;
            }
            let Ok(DtnPayload { data: mut d, .. }) = postcard::from_bytes::<DtnPayload>(&p) else { return };
            if d.envelopes.pop().is_none() {
                return;
            }
            data = d;
        };
        let id = mesh::bundle_id(&self.keys.sign_pk(), &peer, &payload);
        if self.bundled.lock().insert((peer, space), id) == Some(id) {
            return; // already on its way
        }
        mesh.send_bundle(peer, payload.into(), BUNDLE_LIFETIME);
    }

    /// A bundle for us arrived through carriers: apply it like a sync from
    /// its (authenticated) source, if that source is a member.
    fn on_bundle(&self, src: SignPk, payload: &[u8]) {
        let Ok(DtnPayload { space, data }) = postcard::from_bytes::<DtnPayload>(payload) else { return };
        if !self.with_space(&space, |r| r.is_member(&src)).unwrap_or(false) {
            return;
        }
        self.ingest(&space, src, data, &[]);
    }

    fn schedule(&self, space: SpaceId) {
        self.dirty.lock().insert(space);
        self.wake.notify_one();
    }

    /// Blobs are stored per space: a member of one space can't fetch or fill
    /// another space's blobs.
    fn blob_path(&self, space: &SpaceId, hash: &Hash32) -> Option<PathBuf> {
        self.blob_dir
            .as_ref()
            .map(|d| d.join(space.to_string()).join(hash.to_string()))
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
            self.emit(NetEvent::SpaceChanged { space: *space });
            // Epidemic forwarding: others may not be reachable by the author.
            self.schedule(*space);
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

fn gather(r: &Replica, want: &Inventory) -> Data {
    Data {
        ops: want.ops.iter().filter_map(|i| r.op(i).cloned()).collect(),
        envelopes: want.envelopes.iter().filter_map(|i| r.envelope(i).cloned()).collect(),
    }
}

// ─────────────────────────── protocol handlers ───────────────────────────

/// Hands incoming connections of an [`ExtraProtocol`] to its owner.
#[derive(Debug, Clone)]
struct Forward(mpsc::UnboundedSender<Connection>);

impl ProtocolHandler for Forward {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        self.0
            .send(conn)
            .map_err(|_| AcceptError::from_boxed(anyhow!("protocol is not running").into()))
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
async fn serve_conn(inner: &Arc<Inner>, conn: Connection) {
    inner.accepted.fetch_add(1, Ordering::Relaxed);
    let peer = to_sign_pk(&conn.remote_id());
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let Ok((tx, rx)) = bi else { break };
                let (inner, conn) = (inner.clone(), conn.clone());
                tokio::spawn(async move {
                    let _ = serve_bi(&inner, &conn, peer, tx, rx).await;
                });
            }
            uni = conn.accept_uni() => {
                let Ok(rx) = uni else { break };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _ = serve_uni(&inner, peer, rx).await;
                });
            }
        }
    }
}

async fn stream_kind(rx: &mut RecvStream) -> Result<StreamKind> {
    let mut b = [0u8; 1];
    rx.read_exact(&mut b).await?;
    StreamKind::from_byte(b[0]).ok_or_else(|| anyhow!("unknown stream kind {}", b[0]))
}

async fn serve_bi(inner: &Arc<Inner>, conn: &Connection, peer: SignPk, tx: SendStream, mut rx: RecvStream) -> Result<()> {
    let kind = stream_kind(&mut rx).await?;
    tx.set_priority(kind.priority()).ok();
    match kind {
        StreamKind::Sync => serve_sync(inner, conn, peer, tx, rx).await,
        StreamKind::Card => serve_card(inner, tx).await,
        StreamKind::Blob => blobs::serve(inner, peer, tx, rx).await,
        StreamKind::Ephemeral => bail!("ephemeral messages use uni-streams"),
    }
}

async fn serve_uni(inner: &Arc<Inner>, peer: SignPk, mut rx: RecvStream) -> Result<()> {
    match stream_kind(&mut rx).await? {
        StreamKind::Ephemeral => serve_eph(inner, peer, rx).await,
        other => bail!("{other:?} needs a bi-stream"),
    }
}

async fn serve_sync(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    let mut msg: SyncMsg = recv(&mut rx).await?;
    loop {
        let SyncMsg::Hello { space, inv, invite } = msg else {
            bail!("expected Hello");
        };
        let known = inner.spaces.lock().contains_key(&space);
        if !known {
            match invite {
                None => {
                    send(&mut tx, &SyncMsg::NeedInvite).await?;
                    msg = recv(&mut rx).await?;
                    continue;
                }
                Some(ops) => {
                    if !accept_invite(inner, peer, space, ops) {
                        return deny(tx).await;
                    }
                }
            }
        }
        // Membership gate: only current members (any role) may sync.
        let reply = inner.with_space(&space, |r| {
            r.is_member(&peer).then(|| {
                r.note_holder(peer, &inv.envelopes);
                SyncMsg::Accept { inv: inventory(r), want: missing(r, &inv) }
            })
        })?;
        let Some(reply) = reply else {
            let proof = inner.with_space(&space, |r| r.revocation_proof(&peer))?;
            if proof.is_empty() {
                return deny(tx).await;
            }
            send(&mut tx, &SyncMsg::Removed { ops: proof }).await?;
            tx.finish()?;
            return Ok(());
        };
        send(&mut tx, &reply).await?;
        let SyncMsg::DataAndWant { data, want } = recv(&mut rx).await? else {
            bail!("expected DataAndWant");
        };
        let out = inner.with_space(&space, |r| gather(r, &want))?;
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
    if ops.len() > MAX_INVITE_OPS || !(inner.invite_policy)(&from, &space) {
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
    let msg: EphMsg = recv(&mut rx).await?;
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

/// A fresh connection for another protocol ([`Node::connect`]).
async fn connect(inner: &Arc<Inner>, peer: &SignPk, alpn: &[u8]) -> Result<Connection> {
    let addr = inner.addr_of(peer)?;
    match tokio::time::timeout(CONNECT_TIMEOUT, inner.endpoint.connect(addr, alpn)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("connect timed out")),
    }
}

/// The pooled connection to `peer`, dialed if there is none. One that has
/// already closed is dropped from the pool and redialed.
pub(crate) async fn pooled(inner: &Arc<Inner>, peer: &SignPk) -> Result<PooledConn> {
    inner.pool.get(peer).await
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

/// Open a bi-stream of `kind` (labelled and prioritised).
pub(crate) async fn open_bi(conn: &Connection, kind: StreamKind) -> Result<(SendStream, RecvStream)> {
    let (mut tx, rx) = conn.open_bi().await?;
    tx.set_priority(kind.priority()).ok();
    tx.write_all(&[kind as u8]).await?;
    Ok((tx, rx))
}

async fn sync_session(inner: &Arc<Inner>, peer: SignPk, space: SpaceId, trust_peer: bool) -> Result<SyncStats> {
    let hello = inner.with_space(&space, |r| {
        (trust_peer || r.is_member(&peer)).then(|| (inventory(r), r.all_ops()))
    })?;
    let (inv, ops) = hello.ok_or_else(|| anyhow!("peer is not a member of this space"))?;
    on_conn!(inner, &peer, |conn| sync_exchange(inner, &conn, peer, space, inv.clone(), ops.clone()))
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
    send(&mut tx, &SyncMsg::Hello { space, inv: inv.clone(), invite: None }).await?;
    let mut reply: SyncMsg = recv(&mut rx).await?;
    if matches!(reply, SyncMsg::NeedInvite) {
        send(&mut tx, &SyncMsg::Hello { space, inv, invite: Some(ops) }).await?;
        reply = recv(&mut rx).await?;
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
        other => bail!("unexpected reply: {other:?}"),
    };
    let out = inner.with_space(&space, |r| {
        r.note_holder(peer, &their_inv.envelopes);
        SyncMsg::DataAndWant { data: gather(r, &their_want), want: missing(r, &their_inv) }
    })?;
    let sent: Vec<EnvelopeId> = match &out {
        SyncMsg::DataAndWant { data, .. } => data.envelopes.iter().map(|e| e.id()).collect(),
        _ => vec![],
    };
    send(&mut tx, &out).await?;
    tx.finish()?;
    let SyncMsg::Data { data } = recv(&mut rx).await? else {
        bail!("expected Data");
    };
    inner.note_path(peer, conn);
    Ok(inner.ingest(&space, peer, data, &sent))
}

async fn sync_once(inner: Arc<Inner>, peer: SignPk, space: SpaceId) {
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
    loop {
        let res = tokio::time::timeout(SESSION_TIMEOUT, sync_session(&inner, peer, space, false)).await;
        let ok = matches!(res, Ok(Ok(_)));
        if ok {
            inner.mark_ok(peer);
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

/// Push dirty spaces to their members; periodically sync everything.
async fn scheduler(inner: Arc<Inner>) {
    let mut last_full = Instant::now();
    loop {
        tokio::select! {
            _ = inner.wake.notified() => {}
            _ = tokio::time::sleep(PERIODIC_SYNC) => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
        let periodic = last_full.elapsed() >= PERIODIC_SYNC;
        let explicit: HashSet<SpaceId> = std::mem::take(&mut *inner.dirty.lock());
        let mut dirty = explicit.clone();
        if periodic {
            last_full = Instant::now();
            dirty.extend(inner.spaces.lock().keys().copied());
        }
        let me = inner.keys.sign_pk();
        let targets: Vec<(SignPk, SpaceId)> = {
            let spaces = inner.spaces.lock();
            let peers = inner.peers.lock();
            dirty
                .iter()
                .filter_map(|s| spaces.get(s).map(|r| (s, r)))
                // No longer a member: only push explicit local changes (e.g. our
                // own Leave op); periodic syncs would just be refused.
                .filter(|(s, r)| explicit.contains(*s) || r.my_role().is_some())
                .flat_map(|(s, r)| {
                    r.members()
                        .into_iter()
                        .map(move |(k, _)| (k.sign_pk, *s))
                        .collect::<Vec<_>>()
                })
                .filter(|(pk, _)| *pk != me)
                .filter(|(pk, _)| !peers.get(pk).is_some_and(|p| p.backing_off() && !p.nearby))
                .collect()
        };
        for (peer, space) in targets {
            tokio::spawn(sync_once(inner.clone(), peer, space));
        }
    }
}

/// Track nearby peers via mDNS and sync shared spaces when one appears.
async fn watch_mdns(inner: Arc<Inner>, mdns: MdnsAddressLookup) {
    let mut events = mdns.subscribe().await;
    while let Some(ev) = events.next().await {
        match ev {
            DiscoveryEvent::Discovered { endpoint_info, .. } => {
                let pk = to_sign_pk(&endpoint_info.endpoint_id);
                if pk == inner.keys.sign_pk() {
                    continue;
                }
                let name = endpoint_info
                    .data
                    .user_data()
                    .and_then(|u| u.as_ref().strip_prefix("mycel:").map(str::to_string));
                let newly = {
                    let mut peers = inner.peers.lock();
                    let p = peers.entry(pk).or_default();
                    let newly = !p.nearby || p.name != name;
                    p.nearby = true;
                    p.name = name;
                    p.failures = 0;
                    newly
                };
                inner.update_direct(pk);
                if newly {
                    inner.emit(NetEvent::PeersChanged);
                    let shared: Vec<SpaceId> = inner
                        .spaces
                        .lock()
                        .iter()
                        .filter(|(_, r)| r.is_member(&pk))
                        .map(|(s, _)| *s)
                        .collect();
                    for s in shared {
                        tokio::spawn(sync_once(inner.clone(), pk, s));
                    }
                }
            }
            DiscoveryEvent::Expired { endpoint_id } => {
                let pk = to_sign_pk(&endpoint_id);
                if let Some(p) = inner.peers.lock().get_mut(&pk) {
                    p.nearby = false;
                }
                inner.update_direct(pk);
                inner.emit(NetEvent::PeersChanged);
            }
            _ => {}
        }
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

impl Node {
    pub async fn spawn(keys: Arc<DeviceKeys>, opts: NodeOptions) -> Result<Self> {
        // Same Ed25519 key for transport and for Mycel signatures (domain-separated).
        let secret = SecretKey::from_bytes(&keys.seed());
        let memory = MemoryLookup::new();
        let mut alpns: Vec<Vec<u8>> = vec![ALPN.to_vec()];
        alpns.extend(opts.extra_protocols.iter().map(|p| p.alpn.clone()));
        let mesh = opts.mesh.clone().map(|o| Mesh::new(keys.clone(), &opts.name, o));
        let mut links = opts.links;
        if let Some(m) = &mesh {
            alpns.push(mesh::ALPN.to_vec());
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
        let mdns = if opts.mode != NetMode::Local {
            let mdns = MdnsAddressLookup::builder()
                .service_name("mycel")
                .build(endpoint.id())?;
            endpoint.address_lookup()?.add(mdns.clone());
            Some(mdns)
        } else {
            None
        };
        let (events, _) = broadcast::channel(1024);
        let pool = Pool::new(endpoint.clone());
        let inner = Arc::new(Inner {
            keys,
            mode: opts.mode,
            name: Mutex::new(opts.name),
            store: opts.store,
            blob_dir: opts.blob_dir,
            invite_policy: opts.invite_policy,
            accept_relay_invites: opts.accept_relay_invites,
            feed_validator: opts.feed_validator,
            spaces: Mutex::default(),
            peers: Mutex::default(),
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
            bundled: Mutex::default(),
        });
        let mut router = Router::builder(endpoint).accept(ALPN, Handler { inner: inner.clone() });
        for p in opts.extra_protocols {
            router = router.accept(p.alpn, Forward(p.incoming));
        }
        if let Some(m) = &mesh {
            router = router.accept(mesh::ALPN, m.protocol());
        }
        let router = router.spawn();
        let mut tasks = vec![tokio::spawn(scheduler(inner.clone()))];
        let reaper = inner.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                reaper.pool.reap(POOL_IDLE);
            }
        }));
        if let Some(mdns) = mdns {
            tasks.push(tokio::spawn(watch_mdns(inner.clone(), mdns)));
        }
        if let Some(m) = &inner.mesh {
            let (tx, mut rx) = mpsc::unbounded_channel::<(SignPk, bytes::Bytes)>();
            m.set_bundle_sink(tx);
            let inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                while let Some((src, payload)) = rx.recv().await {
                    inner.on_bundle(src, &payload);
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
        }
    }

    /// Tell the node how to reach a peer directly (tests / manual pairing).
    pub fn add_peer_addr(&self, addr: EndpointAddr) {
        self.inner.memory.add_endpoint_info(addr);
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
            self.router
                .endpoint()
                .set_user_data_for_address_lookup(lan_user_data(name));
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
        Ok((id, genesis))
    }

    pub fn join_space(&self, genesis: SignedOp) -> Result<SpaceId> {
        let mut r = Replica::join(self.inner.keys.clone(), genesis, self.inner.store.clone())?;
        self.inner.prepare(&mut r);
        let id = r.space_id();
        self.inner.spaces.lock().entry(id).or_insert(r);
        Ok(id)
    }

    /// Insert a restored replica (from storage at startup).
    pub fn insert_replica(&self, mut r: Replica) -> SpaceId {
        self.inner.prepare(&mut r);
        let id = r.space_id();
        self.inner.spaces.lock().insert(id, r);
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
        self.inner.schedule(space);
    }

    /// One full bidirectional sync of `space` with `peer`, now.
    ///
    /// `trust_peer` lets a freshly-invited device sync with its inviter before
    /// it has learned (via that very sync) that the inviter is a member.
    pub async fn sync_with(&self, peer: SignPk, space: SpaceId, trust_peer: bool) -> Result<SyncStats> {
        let res = sync_session(&self.inner, peer, space, trust_peer).await;
        match &res {
            Ok(_) => self.inner.mark_ok(peer),
            Err(_) => self.inner.mark_fail(peer),
        }
        res
    }

    /// Sync `space` with every member now and wait (best effort).
    pub async fn sync_all(&self, space: SpaceId) {
        let me = self.id();
        let members: Vec<SignPk> = self
            .with_space(&space, |r| r.members().into_iter().map(|(k, _)| k.sign_pk).collect())
            .unwrap_or_default();
        let mut set = tokio::task::JoinSet::new();
        for pk in members.into_iter().filter(|p| *p != me) {
            set.spawn(sync_once(self.inner.clone(), pk, space));
        }
        while set.join_next().await.is_some() {}
    }

    /// Open a connection to a device for another protocol (see
    /// [`ExtraProtocol`]): dialed by key over every path the node knows
    /// (network, links, relay), with multipath failover.
    pub async fn connect(&self, peer: SignPk, alpn: &[u8]) -> Result<Connection> {
        let res = connect(&self.inner, &peer, alpn).await;
        match &res {
            Ok(c) => {
                self.inner.note_path(peer, c);
                self.inner.mark_ok(peer);
            }
            Err(_) => self.inner.mark_fail(peer),
        }
        res
    }

    /// QUIC connections (handshakes) this node has dialed and accepted.
    pub fn connection_counts(&self) -> ConnectionCounts {
        ConnectionCounts {
            dialed: self.inner.pool.dialed.load(Ordering::Relaxed),
            accepted: self.inner.accepted.load(Ordering::Relaxed),
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
            recv::<ContactCard>(&mut rx).await
        })?;
        card.verify()?;
        if card.keys.sign_pk != peer {
            bail!("card does not belong to peer");
        }
        Ok(card)
    }

    /// Fire-and-forget an encrypted ephemeral message to online members.
    pub fn send_ephemeral(&self, space: SpaceId, data: Vec<u8>) -> Result<()> {
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
        let online: HashSet<SignPk> = self
            .peers()
            .into_iter()
            .filter(|(_, p)| p.online())
            .map(|(pk, _)| pk)
            .collect();
        for pk in members.into_iter().filter(|p| online.contains(p)) {
            let inner = self.inner.clone();
            let msg = msg.clone();
            tokio::spawn(async move {
                let _ = on_conn!(&inner, &pk, |conn| async {
                    let mut tx = conn.open_uni().await?;
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
        self.router.shutdown().await?;
        Ok(())
    }
}
