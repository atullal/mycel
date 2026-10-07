//! Mycel network layer (docs/TRUST.md §8): Spaces over Iroh, with live sync,
//! LAN discovery, invites, contact cards, ephemeral messages and blobs.
//!
//! The device's Ed25519 key *is* its Iroh endpoint id, so every QUIC
//! connection is authenticated to a device. On top of that, a device only
//! syncs a Space with its current members (any role, including Relay
//! keepers), and everything received is re-validated by the receiving
//! `Replica` — nothing is trusted because of who sent it.
//!
//! Sync protocol (ALPN `mycel/sync/1`), one bi-stream, strictly alternating so
//! neither side can deadlock on flow control:
//!
//! ```text
//! C → S  Hello{space, inv, invite?}
//! S → C  Denied | NeedInvite | Accept{inv, want}
//! C → S  DataAndWant{data, want}
//! S → C  Data{data}
//! ```

pub mod wire;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, PublicKey, SecretKey,
    address_lookup::{MemoryLookup, UserData},
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_sync::{EnvelopeId, Replica, Store};
use mycel_trust::{SignedOp, SpaceId};
use n0_future::StreamExt;
use tokio::sync::{Notify, Semaphore, broadcast};

pub use iroh;
pub use wire::ContactCard;
use wire::*;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const PERIODIC_SYNC: Duration = Duration::from_secs(15);
const ONLINE_WINDOW: Duration = Duration::from_secs(45);
const DEBOUNCE: Duration = Duration::from_millis(80);

fn to_sign_pk(pk: &PublicKey) -> SignPk {
    SignPk(*pk.as_bytes())
}

fn to_endpoint_id(pk: &SignPk) -> Result<EndpointId> {
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
    /// UDP port to bind (0 = random).
    pub port: u16,
}

impl NodeOptions {
    pub fn new(mode: NetMode, name: impl Into<String>) -> Self {
        NodeOptions {
            mode,
            name: name.into(),
            store: None,
            blob_dir: None,
            invite_policy: Arc::new(|_, _| true),
            port: 0,
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
}

impl PeerState {
    pub fn online(&self) -> bool {
        self.nearby || self.last_ok.is_some_and(|t| t.elapsed() < ONLINE_WINDOW)
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
    spaces: Mutex<HashMap<SpaceId, Replica>>,
    peers: Mutex<HashMap<SignPk, PeerState>>,
    events: broadcast::Sender<NetEvent>,
    memory: MemoryLookup,
    endpoint: Endpoint,
    /// Spaces needing a push to all members; `None` key = everything (periodic).
    dirty: Mutex<HashSet<SpaceId>>,
    wake: Notify,
    inflight: Mutex<HashSet<(SignPk, SpaceId)>>,
    sync_slots: Semaphore,
}

impl Inner {
    fn emit(&self, e: NetEvent) {
        let _ = self.events.send(e);
    }

    fn addr_of(&self, pk: &SignPk) -> Result<EndpointAddr> {
        Ok(EndpointAddr::new(to_endpoint_id(pk)?))
    }

    fn mark_ok(&self, pk: SignPk) {
        let was_online;
        {
            let mut peers = self.peers.lock().unwrap();
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

    fn mark_fail(&self, pk: SignPk) {
        let mut peers = self.peers.lock().unwrap();
        let p = peers.entry(pk).or_default();
        p.failures = p.failures.saturating_add(1);
        p.last_fail = Some(Instant::now());
    }

    fn with_space<R>(&self, space: &SpaceId, f: impl FnOnce(&mut Replica) -> R) -> Result<R> {
        let mut spaces = self.spaces.lock().unwrap();
        let r = spaces.get_mut(space).ok_or_else(|| anyhow!("unknown space"))?;
        Ok(f(r))
    }

    fn schedule(&self, space: SpaceId) {
        self.dirty.lock().unwrap().insert(space);
        self.wake.notify_one();
    }

    fn blob_path(&self, hash: &Hash32) -> Option<PathBuf> {
        self.blob_dir.as_ref().map(|d| d.join(hash.to_string()))
    }

    /// Apply received data; on change, notify the app and forward to other members.
    fn ingest(&self, space: &SpaceId, peer: SignPk, data: Data, sent: &[EnvelopeId]) -> SyncStats {
        let res = {
            let mut spaces = self.spaces.lock().unwrap();
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

#[derive(Clone)]
struct Handler {
    inner: Arc<Inner>,
    alpn: &'static [u8],
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handler({})", String::from_utf8_lossy(self.alpn))
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        let res = match self.alpn {
            ALPN_SYNC => serve_sync(&self.inner, conn).await,
            ALPN_CARD => serve_card(&self.inner, conn).await,
            ALPN_EPH => serve_eph(&self.inner, conn).await,
            ALPN_BLOB => serve_blob(&self.inner, conn).await,
            _ => Err(anyhow!("unknown alpn")),
        };
        res.map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

async fn serve_sync(inner: &Arc<Inner>, conn: Connection) -> Result<()> {
    let peer = to_sign_pk(&conn.remote_id());
    let (mut tx, mut rx) = conn.accept_bi().await?;
    let mut msg: SyncMsg = recv(&mut rx).await?;
    loop {
        let SyncMsg::Hello { space, inv, invite } = msg else {
            bail!("expected Hello");
        };
        let known = inner.spaces.lock().unwrap().contains_key(&space);
        if !known {
            match invite {
                None => {
                    send(&mut tx, &SyncMsg::NeedInvite).await?;
                    msg = recv(&mut rx).await?;
                    continue;
                }
                Some(ops) => {
                    if !accept_invite(inner, peer, space, ops) {
                        send(&mut tx, &SyncMsg::Denied).await?;
                        tx.finish()?;
                        return Ok(());
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
            send(&mut tx, &SyncMsg::Denied).await?;
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
        inner.mark_ok(peer);
        conn.closed().await;
        return Ok(());
    }
}

/// A space pushed to us: accept only if policy allows and the ops prove that
/// both we and the pusher are members.
fn accept_invite(inner: &Arc<Inner>, from: SignPk, space: SpaceId, ops: Vec<SignedOp>) -> bool {
    if !(inner.invite_policy)(&from, &space) {
        return false;
    }
    let Some(genesis) = ops.iter().find(|o| o.id() == space).cloned() else {
        return false;
    };
    let Ok(mut r) = Replica::join(inner.keys.clone(), genesis, None) else {
        return false;
    };
    r.ingest_batch(ops, vec![]);
    if r.my_role().is_none() || !r.is_member(&from) {
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
    r.ingest_batch(all, vec![]);
    inner.spaces.lock().unwrap().entry(space).or_insert(r);
    inner.emit(NetEvent::SpaceAdded { space, from });
    true
}

async fn serve_card(inner: &Arc<Inner>, conn: Connection) -> Result<()> {
    let (mut tx, _rx) = conn.accept_bi().await?;
    let card = ContactCard::new(&inner.keys, &inner.name.lock().unwrap().clone());
    send(&mut tx, &card).await?;
    tx.finish()?;
    conn.closed().await;
    Ok(())
}

async fn serve_eph(inner: &Arc<Inner>, conn: Connection) -> Result<()> {
    let peer = to_sign_pk(&conn.remote_id());
    let mut rx = conn.accept_uni().await?;
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

async fn serve_blob(inner: &Arc<Inner>, conn: Connection) -> Result<()> {
    let peer = to_sign_pk(&conn.remote_id());
    let (mut tx, mut rx) = conn.accept_bi().await?;
    let req: BlobReq = recv(&mut rx).await?;
    let (space, hash) = match &req {
        BlobReq::Get { space, hash } | BlobReq::Put { space, hash, .. } => (*space, *hash),
    };
    let allowed = inner
        .spaces
        .lock()
        .unwrap()
        .get(&space)
        .is_some_and(|r| r.is_member(&peer));
    let path = inner.blob_path(&hash);
    match (req, allowed, path) {
        (_, false, _) | (_, _, None) => send(&mut tx, &BlobResp::Denied).await?,
        (BlobReq::Get { .. }, true, Some(path)) => match tokio::fs::read(&path).await {
            Ok(bytes) => {
                send(&mut tx, &BlobResp::Found { len: bytes.len() as u64 }).await?;
                tx.write_all(&bytes).await?;
            }
            Err(_) => send(&mut tx, &BlobResp::NotFound).await?,
        },
        (BlobReq::Put { len, .. }, true, Some(path)) => {
            if len > MAX_BLOB {
                bail!("blob too large");
            }
            let mut bytes = vec![0u8; len as usize];
            rx.read_exact(&mut bytes).await?;
            if blob_hash(&bytes) != hash {
                bail!("blob hash mismatch");
            }
            write_blob(&path, &bytes).await?;
            inner.emit(NetEvent::BlobStored { hash });
            send(&mut tx, &BlobResp::Stored).await?;
        }
    }
    tx.finish()?;
    conn.closed().await;
    Ok(())
}

async fn write_blob(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

// ─────────────────────────────── client side ───────────────────────────────

async fn connect(inner: &Arc<Inner>, peer: &SignPk, alpn: &[u8]) -> Result<Connection> {
    let addr = inner.addr_of(peer)?;
    match tokio::time::timeout(CONNECT_TIMEOUT, inner.endpoint.connect(addr, alpn)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("connect timed out")),
    }
}

async fn sync_session(inner: &Arc<Inner>, peer: SignPk, space: SpaceId, trust_peer: bool) -> Result<SyncStats> {
    let hello = inner.with_space(&space, |r| {
        (trust_peer || r.is_member(&peer)).then(|| (inventory(r), r.all_ops()))
    })?;
    let (inv, ops) = hello.ok_or_else(|| anyhow!("peer is not a member of this space"))?;
    let conn = connect(inner, &peer, ALPN_SYNC).await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    send(&mut tx, &SyncMsg::Hello { space, inv: inv.clone(), invite: None }).await?;
    let mut reply: SyncMsg = recv(&mut rx).await?;
    if matches!(reply, SyncMsg::NeedInvite) {
        send(&mut tx, &SyncMsg::Hello { space, inv, invite: Some(ops) }).await?;
        reply = recv(&mut rx).await?;
    }
    let (their_inv, their_want) = match reply {
        SyncMsg::Accept { inv, want } => (inv, want),
        SyncMsg::Denied => bail!("peer denied sync (we are not a member)"),
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
    conn.close(0u32.into(), b"done");
    Ok(inner.ingest(&space, peer, data, &sent))
}

async fn sync_once(inner: Arc<Inner>, peer: SignPk, space: SpaceId) {
    if !inner.inflight.lock().unwrap().insert((peer, space)) {
        return;
    }
    let _slot = inner.sync_slots.acquire().await;
    let res = tokio::time::timeout(SESSION_TIMEOUT, sync_session(&inner, peer, space, false)).await;
    inner.inflight.lock().unwrap().remove(&(peer, space));
    match res {
        Ok(Ok(_)) => inner.mark_ok(peer),
        _ => inner.mark_fail(peer),
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
        let mut dirty: HashSet<SpaceId> = std::mem::take(&mut *inner.dirty.lock().unwrap());
        if periodic {
            last_full = Instant::now();
            dirty.extend(inner.spaces.lock().unwrap().keys().copied());
        }
        let me = inner.keys.sign_pk();
        let targets: Vec<(SignPk, SpaceId)> = {
            let spaces = inner.spaces.lock().unwrap();
            let peers = inner.peers.lock().unwrap();
            dirty
                .iter()
                .filter_map(|s| spaces.get(s).map(|r| (s, r)))
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
                    let mut peers = inner.peers.lock().unwrap();
                    let p = peers.entry(pk).or_default();
                    let newly = !p.nearby || p.name != name;
                    p.nearby = true;
                    p.name = name;
                    p.failures = 0;
                    newly
                };
                if newly {
                    inner.emit(NetEvent::PeersChanged);
                    let shared: Vec<SpaceId> = inner
                        .spaces
                        .lock()
                        .unwrap()
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
                if let Some(p) = inner.peers.lock().unwrap().get_mut(&pk) {
                    p.nearby = false;
                }
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
        let alpns: Vec<Vec<u8>> = [ALPN_SYNC, ALPN_CARD, ALPN_EPH, ALPN_BLOB]
            .iter()
            .map(|a| a.to_vec())
            .collect();
        let builder = match opts.mode {
            NetMode::Local => Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr(format!("127.0.0.1:{}", opts.port).as_str())?,
            NetMode::Lan => Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr(format!("0.0.0.0:{}", opts.port).as_str())?,
            NetMode::Internet => Endpoint::builder(presets::N0),
        };
        let mut builder = builder.secret_key(secret).alpns(alpns);
        if let Some(ud) = lan_user_data(&opts.name) {
            builder = builder.user_data_for_address_lookup(ud);
        }
        let endpoint = builder.bind().await?;
        endpoint.address_lookup()?.add(memory.clone());
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
        let inner = Arc::new(Inner {
            keys,
            mode: opts.mode,
            name: Mutex::new(opts.name),
            store: opts.store,
            blob_dir: opts.blob_dir,
            invite_policy: opts.invite_policy,
            spaces: Mutex::default(),
            peers: Mutex::default(),
            events,
            memory,
            endpoint: endpoint.clone(),
            dirty: Mutex::default(),
            wake: Notify::new(),
            inflight: Mutex::default(),
            sync_slots: Semaphore::new(16),
        });
        let mut router = Router::builder(endpoint);
        for alpn in [ALPN_SYNC, ALPN_CARD, ALPN_EPH, ALPN_BLOB] {
            router = router.accept(alpn, Handler { inner: inner.clone(), alpn });
        }
        let router = router.spawn();
        let mut tasks = vec![tokio::spawn(scheduler(inner.clone()))];
        if let Some(mdns) = mdns {
            tasks.push(tokio::spawn(watch_mdns(inner.clone(), mdns)));
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

    pub fn local_addresses(&self) -> Vec<String> {
        self.router
            .endpoint()
            .bound_sockets()
            .iter()
            .map(|a| a.to_string())
            .collect()
    }

    /// Tell the node how to reach a peer directly (tests / manual pairing).
    pub fn add_peer_addr(&self, addr: EndpointAddr) {
        self.inner.memory.add_endpoint_info(addr);
    }

    pub fn set_name(&self, name: &str) {
        *self.inner.name.lock().unwrap() = name.to_string();
        if self.inner.mode != NetMode::Local {
            self.router
                .endpoint()
                .set_user_data_for_address_lookup(lan_user_data(name));
        }
    }

    pub fn card(&self) -> ContactCard {
        ContactCard::new(&self.inner.keys, &self.inner.name.lock().unwrap())
    }

    pub fn peers(&self) -> HashMap<SignPk, PeerState> {
        self.inner.peers.lock().unwrap().clone()
    }

    // ───────────── spaces ─────────────

    /// Found a new Space; returns its id and the genesis op.
    pub fn create_space(&self) -> Result<(SpaceId, SignedOp)> {
        let (r, genesis) = Replica::create(self.inner.keys.clone(), self.inner.store.clone())?;
        let id = r.space_id();
        self.inner.spaces.lock().unwrap().insert(id, r);
        Ok((id, genesis))
    }

    pub fn join_space(&self, genesis: SignedOp) -> Result<SpaceId> {
        let r = Replica::join(self.inner.keys.clone(), genesis, self.inner.store.clone())?;
        let id = r.space_id();
        self.inner.spaces.lock().unwrap().entry(id).or_insert(r);
        Ok(id)
    }

    /// Insert a restored replica (from storage at startup).
    pub fn insert_replica(&self, r: Replica) -> SpaceId {
        let id = r.space_id();
        self.inner.spaces.lock().unwrap().insert(id, r);
        id
    }

    pub fn space_ids(&self) -> Vec<SpaceId> {
        self.inner.spaces.lock().unwrap().keys().copied().collect()
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

    // ───────────── cards, ephemeral, blobs ─────────────

    /// Fetch a device's self-signed contact card (anyone may ask).
    pub async fn fetch_card(&self, peer: SignPk) -> Result<ContactCard> {
        let conn = connect(&self.inner, &peer, ALPN_CARD).await?;
        let (_tx, mut rx) = conn.open_bi().await?;
        let card: ContactCard = recv(&mut rx).await?;
        conn.close(0u32.into(), b"done");
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
                let Ok(conn) = connect(&inner, &pk, ALPN_EPH).await else {
                    return;
                };
                if let Ok(mut tx) = conn.open_uni().await
                    && send(&mut tx, &*msg).await.is_ok()
                    && tx.finish().is_ok()
                {
                    let _ = tx.stopped().await;
                }
                conn.close(0u32.into(), b"done");
            });
        }
        Ok(())
    }

    pub fn blob_path(&self, hash: &Hash32) -> Option<PathBuf> {
        self.inner.blob_path(hash).filter(|p| p.exists())
    }

    /// Store an (already encrypted) blob locally and push it to online
    /// members and keepers in the background. Returns its hash.
    pub async fn put_blob(&self, space: SpaceId, bytes: Vec<u8>) -> Result<Hash32> {
        if bytes.len() as u64 > MAX_BLOB {
            bail!("file too large (max {} MiB)", MAX_BLOB / 1024 / 1024);
        }
        let hash = blob_hash(&bytes);
        let path = self.inner.blob_path(&hash).context("blob storage disabled")?;
        write_blob(&path, &bytes).await?;
        let me = self.id();
        let members: Vec<SignPk> = self.with_space(&space, |r| {
            r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|p| *p != me).collect()
        })?;
        let bytes = Arc::new(bytes);
        for pk in members {
            let (inner, bytes) = (self.inner.clone(), bytes.clone());
            tokio::spawn(async move {
                let _ = push_blob(&inner, pk, space, hash, &bytes).await;
            });
        }
        Ok(hash)
    }

    /// Get a blob: local if present, otherwise from any member that has it.
    pub async fn fetch_blob(&self, space: SpaceId, hash: Hash32) -> Result<PathBuf> {
        if let Some(p) = self.blob_path(&hash) {
            return Ok(p);
        }
        let me = self.id();
        let mut members: Vec<SignPk> = self.with_space(&space, |r| {
            r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|p| *p != me).collect()
        })?;
        let peers = self.peers();
        members.sort_by_key(|pk| !peers.get(pk).is_some_and(|p| p.online()));
        for pk in members {
            if let Ok(bytes) = get_blob(&self.inner, pk, space, hash).await {
                let path = self.inner.blob_path(&hash).context("blob storage disabled")?;
                write_blob(&path, &bytes).await?;
                self.inner.emit(NetEvent::BlobStored { hash });
                return Ok(path);
            }
        }
        bail!("blob not available from any reachable member")
    }

    pub async fn shutdown(self) -> Result<()> {
        for t in &self.tasks {
            t.abort();
        }
        self.router.shutdown().await?;
        Ok(())
    }
}

async fn push_blob(inner: &Arc<Inner>, pk: SignPk, space: SpaceId, hash: Hash32, bytes: &[u8]) -> Result<()> {
    let conn = connect(inner, &pk, ALPN_BLOB).await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    send(&mut tx, &BlobReq::Put { space, hash, len: bytes.len() as u64 }).await?;
    tx.write_all(bytes).await?;
    tx.finish()?;
    let resp: BlobResp = recv(&mut rx).await?;
    conn.close(0u32.into(), b"done");
    match resp {
        BlobResp::Stored => Ok(()),
        other => bail!("push failed: {other:?}"),
    }
}

async fn get_blob(inner: &Arc<Inner>, pk: SignPk, space: SpaceId, hash: Hash32) -> Result<Vec<u8>> {
    let conn = connect(inner, &pk, ALPN_BLOB).await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    send(&mut tx, &BlobReq::Get { space, hash }).await?;
    tx.finish()?;
    let resp: BlobResp = recv(&mut rx).await?;
    let BlobResp::Found { len } = resp else {
        bail!("not found: {resp:?}");
    };
    if len > MAX_BLOB {
        bail!("blob too large");
    }
    let mut bytes = vec![0u8; len as usize];
    rx.read_exact(&mut bytes).await?;
    conn.close(0u32.into(), b"done");
    if blob_hash(&bytes) != hash {
        bail!("blob hash mismatch");
    }
    Ok(bytes)
}
