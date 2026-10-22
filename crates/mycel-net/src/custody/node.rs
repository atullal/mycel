//! The node's side of custody (see the module above and
//! docs/OFFLINE_DELIVERY.md): depositing parcels when a member can't be
//! reached, keeping others' parcels and delivering them, fetching our own,
//! and the `Custody` stream that carries all of it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use mycel_crypto::{Hash32, SignPk};
use mycel_trust::SpaceId;

use super::{
    DEFAULT_COPIES, DEFAULT_LIFETIME_MS, Deposit, Deposited, Depositor, Directory, FIND_MAX, LISTING_MAX, Limiter,
    MAX_ATTEMPTS, MAX_FIRST, MAX_MSG, Msg, Origin, Outbox, Parcel, ROUND_BYTES, Receipt, Refusal, Tier, Vault,
    VaultConfig, VaultStats, select,
};
use crate::wire::{self, Data, DtnPayload, StreamKind, recv_bounded, send, send_len};
use crate::{Caps, Inner, NetEvent, PeerProtocol, mesh, on_conn, open_bi, pooled, resources};

/// How a node takes part in custody ([`crate::NodeOptions::custody`]).
#[derive(Clone, Debug)]
pub struct CustodyOptions {
    /// Speak the custody protocol at all: deposit our parcels with
    /// custodians, fetch ours (capability [`Caps::CUSTODY`]). Keeping
    /// others' parcels is [`VaultConfig::serve`] (capability
    /// [`Caps::CUSTODIAN`]), which can also change at run time
    /// ([`crate::Node::set_custodian`]).
    pub enabled: bool,
    /// The custodian's limits (and whether it serves).
    pub vault: VaultConfig,
    /// Custodians each parcel goes to.
    pub copies: usize,
    /// How long a parcel is worth delivering (ms).
    pub lifetime_ms: u64,
    /// How soon after a failed delivery to a recipient a custodian tries
    /// again (doubling up to [`CustodyOptions::retry_max`]).
    pub retry: Duration,
    pub retry_max: Duration,
    /// How often a device asks its likely custodians for its mail, beyond
    /// asking each custodian it connects to.
    pub fetch_every: Duration,
}

impl Default for CustodyOptions {
    fn default() -> Self {
        CustodyOptions {
            enabled: true,
            vault: VaultConfig::default(),
            copies: DEFAULT_COPIES,
            lifetime_ms: DEFAULT_LIFETIME_MS,
            retry: Duration::from_secs(60),
            retry_max: Duration::from_secs(3600),
            fetch_every: Duration::from_secs(30 * 60),
        }
    }
}

/// What custody has done on this node (tests, diagnostics, the simulator).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustodyStats {
    /// Parcels sealed for members we couldn't reach.
    pub parcels_sealed: u64,
    /// Custodians that acknowledged one of our parcels.
    pub custody_acks: u64,
    /// Deposits refused (by reason) or failed (no connection).
    pub deposits_refused: u64,
    pub deposits_failed: u64,
    /// Parcels we received as their recipient, and how many opened.
    pub parcels_received: u64,
    pub parcels_opened: u64,
    /// Parcels we delivered as a custodian.
    pub parcels_delivered: u64,
    /// Fetches we made (as recipient) and served (as custodian).
    pub fetches: u64,
    pub fetches_served: u64,
    /// Parcels withdrawn at custodians after a live sync.
    pub released: u64,
    /// What the store holds and has done.
    pub vault: VaultStats,
    pub held_bytes: u64,
    pub held_parcels: usize,
    pub directory: usize,
}

/// Parcels remembered as received (re-offers are answered with a receipt).
const RECEIVED_MAX: usize = 8192;
/// A custodian is asked for our mail at most this often, unless it says
/// it has some.
const FETCH_GAP: Duration = Duration::from_secs(600);
/// Custodians remembered as recently asked.
const FETCHED_MAX: usize = 1024;
/// Deliveries started per custody tick.
const DELIVERIES_PER_TICK: usize = 4;
const TICK: Duration = Duration::from_secs(10);
/// Rounds one delivery runs at most.
const MAX_ROUNDS: usize = 64;

pub(crate) struct State {
    pub(crate) enabled: bool,
    pub(crate) vault: Vault,
    pub(crate) outbox: Outbox,
    pub(crate) directory: Directory,
    /// Our own other devices: custodians of first choice.
    pub(crate) own: Vec<SignPk>,
    pub(crate) copies: usize,
    pub(crate) lifetime_ms: u64,
    retry_first: Duration,
    retry_max: Duration,
    pub(crate) fetch_every: Duration,
    fetched: HashMap<SignPk, Instant>,
    delivering: HashSet<SignPk>,
    retry: HashMap<SignPk, (Instant, Duration)>,
    depositing: HashSet<(SignPk, SpaceId)>,
    received: HashSet<Hash32>,
    received_order: VecDeque<Hash32>,
    find_rate: Limiter<SignPk>,
    fetch_rate: Limiter<SignPk>,
    pub(crate) stats: CustodyStats,
}

impl State {
    pub(crate) fn new(me: SignPk, o: CustodyOptions) -> State {
        State {
            enabled: o.enabled,
            vault: Vault::new(VaultConfig { serve: o.enabled && o.vault.serve, ..o.vault }),
            outbox: Outbox::default(),
            directory: Directory::new(me),
            own: Vec::new(),
            copies: o.copies.max(1),
            lifetime_ms: o.lifetime_ms,
            retry_first: o.retry,
            retry_max: o.retry_max,
            fetch_every: o.fetch_every,
            fetched: HashMap::new(),
            delivering: HashSet::new(),
            retry: HashMap::new(),
            depositing: HashSet::new(),
            received: HashSet::new(),
            received_order: VecDeque::new(),
            find_rate: Limiter::new(16, 1_000),
            fetch_rate: Limiter::new(8, 5_000),
            stats: CustodyStats::default(),
        }
    }

    fn note_received(&mut self, id: Hash32) {
        if self.received.insert(id) {
            self.received_order.push_back(id);
            while self.received_order.len() > RECEIVED_MAX {
                if let Some(old) = self.received_order.pop_front() {
                    self.received.remove(&old);
                }
            }
        }
    }

    /// A delivery to `dst` failed: try again later, backing off.
    fn retry_later(&mut self, dst: SignPk) {
        let now = Instant::now();
        let wait = match self.retry.get(&dst) {
            Some((_, w)) => (*w * 2).min(self.retry_max),
            None => self.retry_first,
        };
        self.retry.insert(dst, (now + wait, wait));
    }
}

pub(crate) fn wall_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn origin_of(conn: &Connection) -> Origin {
    match crate::link::path_in_use(&conn.paths()).map(|p| p.remote_addr().clone()) {
        Some(iroh::TransportAddr::Ip(sa)) => Origin::of_ip(sa.ip()),
        Some(iroh::TransportAddr::Relay(_)) => Origin::Relay,
        _ => Origin::Link,
    }
}

impl Inner {
    /// The capabilities we advertise now: custody ones follow the settings.
    pub(crate) fn caps(&self) -> Caps {
        let c = self.custody.lock();
        let mut caps = self.protocol.caps;
        if !c.enabled {
            caps = caps.difference(Caps::CUSTODY.union(Caps::CUSTODIAN));
        } else if !c.vault.serving() {
            caps = caps.difference(Caps::CUSTODIAN);
        }
        caps
    }

    /// Whether `peer` shares a space with us (a known device).
    fn shares_space(&self, peer: &SignPk) -> bool {
        self.spaces.lock().values().any(|r| r.is_member(peer))
    }

    /// A connection to `peer` agreed `p`: learn whether it keeps custody,
    /// ask it for our mail, give it any it has waiting with us. `trusted`:
    /// we dialed it or share a space with it. A stranger that dials us gets
    /// its mail, but isn't asked for ours (that would let anyone make us
    /// open streams, and remember them).
    pub(crate) fn custody_on_protocol(self: &Arc<Self>, peer: SignPk, p: PeerProtocol, trusted: bool) {
        if !p.supports(Caps::CUSTODY) {
            return;
        }
        let (fetch, deliver) = {
            let mut c = self.custody.lock();
            let custodian = p.advertised.contains(Caps::CUSTODIAN);
            if custodian {
                c.directory.add(peer, wall_ms());
            } else {
                c.directory.remove(&peer);
            }
            let fetch = trusted && custodian && c.fetched.get(&peer).is_none_or(|t| t.elapsed() >= FETCH_GAP);
            if fetch {
                if c.fetched.len() >= FETCHED_MAX {
                    c.fetched.retain(|_, t| t.elapsed() < FETCH_GAP);
                }
                c.fetched.insert(peer, Instant::now());
            }
            (fetch, c.vault.has_mail(&peer) && !c.delivering.contains(&peer))
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        if fetch {
            rt.spawn(fetch_from(self.clone(), peer));
        }
        if deliver {
            rt.spawn(deliver_to(self.clone(), peer));
        }
    }

    /// `peer` (a member of `space`) can't be reached live: seal what it
    /// lacks and hand it to custodians (in the background).
    pub(crate) fn offer_custody(self: &Arc<Self>, peer: SignPk, space: SpaceId) {
        {
            let mut c = self.custody.lock();
            if !c.enabled || !c.depositing.insert((peer, space)) {
                return;
            }
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.custody.lock().depositing.remove(&(peer, space));
            return;
        };
        let inner = self.clone();
        rt.spawn(async move {
            let _ = deposit(&inner, peer, space).await;
            inner.custody.lock().depositing.remove(&(peer, space));
        });
    }

    /// We synced `space` with `peer` live: withdraw our parcels for it.
    pub(crate) fn custody_synced(self: &Arc<Self>, peer: SignPk, space: SpaceId) {
        let done = self.custody.lock().outbox.delivered(&peer, &space);
        if done.is_empty() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        for (id, d) in done {
            for c in d.custodians {
                rt.spawn(release_at(self.clone(), c, id, d.secret));
            }
        }
    }

    /// How many custodians and carriers hold a sealed copy of `item` (an
    /// envelope of ours), acknowledged: internet custodians by their
    /// answer, mesh carriers by taking the bundle.
    pub(crate) fn carried(&self, item: &Hash32) -> usize {
        let mut by = self.custody.lock().outbox.custodians_of(item);
        if let Some(m) = &self.mesh {
            let ids: Vec<Hash32> =
                self.bundle_items.lock().iter().filter(|(_, items)| items.contains(item)).map(|(id, _)| *id).collect();
            for id in ids {
                by.extend(m.bundle_carriers(&id));
            }
        }
        by.len()
    }

    /// Our devices of first choice as custodians.
    pub(crate) fn set_own_devices(&self, own: Vec<SignPk>) {
        let me = self.keys.sign_pk();
        self.custody.lock().own = own.into_iter().filter(|k| *k != me).collect();
    }

    /// Parcels arrived for us (from `from`, a custodian): open each, apply
    /// it like a sync from its sender, and sign a receipt. Returns the
    /// receipts and how many opened.
    fn receive_parcels(&self, from: SignPk, parcels: Vec<Parcel>) -> (Vec<Receipt>, usize) {
        let mut receipts = Vec::new();
        let mut opened = 0;
        for p in parcels {
            let id = p.id();
            if self.custody.lock().received.contains(&id) {
                receipts.push(Receipt::sign(&self.keys, id));
                continue;
            }
            self.custody.lock().stats.parcels_received += 1;
            let Ok(o) = super::open(&self.keys, &p) else { continue };
            opened += 1;
            // (an unknown payload kind is refused unread, but it was
            // delivered: the receipt stops the custodians keeping it)
            let _ = self.on_bundle(o.src, o.kind, &o.payload);
            let mut c = self.custody.lock();
            c.stats.parcels_opened += 1;
            c.note_received(id);
            receipts.push(Receipt::sign(&self.keys, id));
        }
        let _ = from;
        (receipts, opened)
    }
}

// ───────────────────────────── depositing ─────────────────────────────

/// A sealed parcel for `peer` with what it lacks of `space` that isn't in
/// custody already, registered (pending) in the outbox.
fn plan(inner: &Arc<Inner>, peer: SignPk, space: SpaceId) -> Option<(Hash32, Parcel)> {
    let covered = inner.custody.lock().outbox.covered(&peer, &space);
    let lifetime = inner.custody.lock().lifetime_ms;
    let picked = inner
        .with_space(&space, |r| {
            let keys = r.members().into_iter().find(|(k, _)| k.sign_pk == peer)?.0;
            let mut left = crate::MAX_BUNDLE_PAYLOAD;
            let mut ops = Vec::new();
            for op in r.all_ops() {
                if covered.contains(&op.id()) {
                    continue;
                }
                let n = wire::encoded_size(&op, usize::MAX).ok()?;
                if n > left {
                    return None; // ops alone don't fit: sync will have to do
                }
                left -= n;
                ops.push(op);
            }
            let mut envelopes = Vec::new();
            for id in r.envelope_ids() {
                if covered.contains(&id) || r.holders(&id).contains(&peer) {
                    continue;
                }
                let Some(env) = r.envelope(&id) else { continue };
                let n = wire::encoded_size(env, usize::MAX).ok()?;
                if n > left {
                    if left < 512 {
                        break;
                    }
                    continue;
                }
                left -= n;
                envelopes.push(env.clone());
            }
            (!envelopes.is_empty()).then_some((keys, ops, envelopes))
        })
        .ok()
        .flatten();
    let (keys, ops, envelopes) = picked?;
    let op_ids: Vec<Hash32> = ops.iter().map(|o| o.id()).collect();
    let env_ids: Vec<Hash32> = envelopes.iter().map(|e| e.id()).collect();
    let payload = postcard::to_allocvec(&DtnPayload { space, data: Data { ops, envelopes } }).ok()?;
    let now = super::node::wall_ms();
    let (parcel, secret) =
        super::seal(&inner.keys, peer, &keys.kex_pk, mesh::dtn::KIND_SPACE_SYNC, payload, lifetime, now).ok()?;
    let id = parcel.id();
    let mut c = inner.custody.lock();
    c.stats.parcels_sealed += 1;
    c.outbox.add(
        id,
        Deposited {
            dst: peer,
            space,
            envelopes: env_ids,
            ops: op_ids,
            secret,
            custodians: Vec::new(),
            until: parcel.expires(),
            pending: true,
        },
    );
    Some((id, parcel))
}

/// Who to try as custodians for `dst`, best first.
async fn candidates(inner: &Arc<Inner>, dst: SignPk) -> Vec<(SignPk, Tier)> {
    let me = inner.keys.sign_pk();
    let shares: Vec<SignPk> = inner
        .spaces
        .lock()
        .values()
        .filter(|r| r.is_member(&dst))
        .flat_map(|r| r.members().into_iter().map(|(k, _)| k.sign_pk))
        .collect();
    let own = inner.custody.lock().own.clone();
    let volunteers = find(inner, dst).await;
    let peers = inner.peers.lock().clone();
    let online = |k: &SignPk| peers.get(k).is_some_and(crate::PeerState::online);
    select(&dst, &me, &own, &shares, &volunteers, &online, MAX_ATTEMPTS)
}

/// `MYCEL_CUSTODY_DEBUG=1` logs deposits and deliveries.
fn debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("MYCEL_CUSTODY_DEBUG").is_some_and(|v| v == "1"))
}

async fn deposit(inner: &Arc<Inner>, peer: SignPk, space: SpaceId) -> Result<()> {
    let Some((id, parcel)) = plan(inner, peer, space) else { return Ok(()) };
    let want = inner.custody.lock().copies;
    let t0 = Instant::now();
    let picked = candidates(inner, peer).await;
    if debug() {
        eprintln!(
            "[custody] parcel {id:?} for {} ({} B): candidates {picked:?} in {:?}",
            peer.short(),
            parcel.size(),
            t0.elapsed()
        );
    }
    let mut queue: VecDeque<SignPk> = picked.into_iter().map(|(k, _)| k).collect();
    let parcel = Arc::new(parcel);
    let mut running = tokio::task::JoinSet::new();
    let mut acked = 0usize;
    loop {
        while running.len() + acked < want
            && let Some(c) = queue.pop_front()
        {
            let (inner, parcel) = (inner.clone(), parcel.clone());
            running.spawn(async move { (c, deposit_at(&inner, c, &parcel).await) });
        }
        let Some(Ok((c, res))) = running.join_next().await else { break };
        if debug() {
            eprintln!("[custody] deposit of {id:?} at {}: {res:?} after {:?}", c.short(), t0.elapsed());
        }
        match res {
            Ok(Deposit::Stored | Deposit::Duplicate) => {
                let news = {
                    let mut st = inner.custody.lock();
                    st.stats.custody_acks += 1;
                    st.outbox.ack(&id, c)
                };
                acked += 1;
                if news {
                    // the message's delivery state changed
                    inner.emit(NetEvent::SpaceChanged { space });
                }
            }
            Ok(Deposit::Refused(_)) => inner.custody.lock().stats.deposits_refused += 1,
            Err(_) => inner.custody.lock().stats.deposits_failed += 1,
        }
    }
    inner.custody.lock().outbox.settle(&id);
    Ok(())
}

/// Deposit `parcel` at custodian `c`: a proof of work if `c` shares no
/// space with us (it would ask a stranger for one).
pub(crate) async fn deposit_at(inner: &Arc<Inner>, c: SignPk, parcel: &Arc<Parcel>) -> Result<Deposit> {
    let id = parcel.id();
    let bits = inner.custody.lock().vault.config().stamp_bits;
    let mut stamp = 0;
    if !inner.shares_space(&c) {
        stamp = tokio::task::spawn_blocking(move || super::mint(&id, &c, bits)).await?;
    }
    let ans = deposit_once(inner, c, parcel, stamp).await?;
    if ans == Deposit::Refused(Refusal::NoStamp) && stamp == 0 {
        // it doesn't count us as known (yet)
        let stamp = tokio::task::spawn_blocking(move || super::mint(&id, &c, bits)).await?;
        return deposit_once(inner, c, parcel, stamp).await;
    }
    Ok(ans)
}

async fn custody_conn(inner: &Arc<Inner>, peer: &SignPk) -> Result<crate::pool::PooledConn> {
    let conn = pooled(inner, peer).await?;
    if !conn.protocol(resources::REPLY_TIMEOUT).await.supports(Caps::CUSTODY) {
        bail!(crate::VersionError::MissingCapability(Caps::CUSTODY));
    }
    Ok(conn)
}

async fn deposit_once(inner: &Arc<Inner>, c: SignPk, parcel: &Parcel, stamp: u64) -> Result<Deposit> {
    let _ = custody_conn(inner, &c).await?;
    on_conn!(inner, &c, |conn| async {
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Custody).await?;
        let len = send_len(&mut tx, &Msg::Deposit { parcel: parcel.clone(), stamp }).await?;
        tx.finish()?;
        let (ans, _) =
            recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), 1024, &inner.reply_frames(&c)).await?;
        match ans {
            Msg::Deposited(d) => Ok(d),
            _ => Err(anyhow!("unexpected custody answer")),
        }
    })
}

async fn release_at(inner: Arc<Inner>, c: SignPk, id: Hash32, secret: [u8; 32]) {
    let res: Result<bool> = async {
        let _ = custody_conn(&inner, &c).await?;
        on_conn!(&inner, &c, |conn| async {
            let (mut tx, mut rx) = open_bi(&conn, StreamKind::Custody).await?;
            let len = send_len(&mut tx, &Msg::Release { id, secret }).await?;
            tx.finish()?;
            match recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), 1024, &inner.reply_frames(&c)).await?.0 {
                Msg::Released { ok } => Ok(ok),
                _ => Err(anyhow!("unexpected custody answer")),
            }
        })
    }
    .await;
    if res.is_ok_and(|ok| ok) {
        inner.custody.lock().stats.released += 1;
    }
}

// ───────────────────────────── finding custodians ─────────────────────────────

/// Lookups ask this many custodians at once (Kademlia's α).
const ALPHA: usize = 3;

/// The custodians XOR-closest to `target` that we can find: those we know,
/// refined by asking the closest of them (two rounds of [`ALPHA`]), as an
/// iterative Kademlia lookup. Keys from answers are candidates only.
pub(crate) async fn find(inner: &Arc<Inner>, target: SignPk) -> Vec<SignPk> {
    let me = inner.keys.sign_pk();
    let mut known: Vec<SignPk> = inner.custody.lock().directory.closest(&target, FIND_MAX);
    let mut asked: HashSet<SignPk> = HashSet::new();
    for _round in 0..2 {
        let ask: Vec<SignPk> =
            known.iter().filter(|k| **k != target && **k != me && !asked.contains(*k)).take(ALPHA).copied().collect();
        if ask.is_empty() {
            break;
        }
        let mut set = tokio::task::JoinSet::new();
        for k in ask {
            asked.insert(k);
            let inner = inner.clone();
            set.spawn(async move { ask_find(&inner, k, target).await.unwrap_or_default() });
        }
        while let Some(Ok(found)) = set.join_next().await {
            for k in found {
                if k != me && !known.contains(&k) {
                    known.push(k);
                }
            }
        }
        known.sort_unstable_by_key(|k| super::distance(&target, k));
        known.truncate(FIND_MAX);
    }
    known
}

async fn ask_find(inner: &Arc<Inner>, c: SignPk, target: SignPk) -> Result<Vec<SignPk>> {
    let _ = custody_conn(inner, &c).await?;
    on_conn!(inner, &c, |conn| async {
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Custody).await?;
        let len = send_len(&mut tx, &Msg::Find { target }).await?;
        tx.finish()?;
        match recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), 2048, &inner.reply_frames(&c)).await?.0 {
            Msg::Found { mut custodians } => {
                custodians.truncate(FIND_MAX);
                Ok(custodians)
            }
            _ => Err(anyhow!("unexpected custody answer")),
        }
    })
}

// ───────────────────────────── delivering and fetching ─────────────────────────────

/// As a custodian: give `dst` what we hold for it.
pub(crate) async fn deliver_to(inner: Arc<Inner>, dst: SignPk) {
    if !inner.custody.lock().delivering.insert(dst) {
        return;
    }
    let res: Result<()> = async {
        let _ = custody_conn(&inner, &dst).await?;
        on_conn!(&inner, &dst, |conn| async {
            let (tx, rx) = open_bi(&conn, StreamKind::Custody).await?;
            push(&inner, dst, tx, rx).await
        })
    }
    .await;
    let mut c = inner.custody.lock();
    c.delivering.remove(&dst);
    if res.is_ok() && !c.vault.has_mail(&dst) {
        c.retry.remove(&dst);
    } else {
        c.retry_later(dst);
    }
}

/// As a recipient: ask custodian `c` for our mail.
pub(crate) async fn fetch_from(inner: Arc<Inner>, c: SignPk) {
    inner.custody.lock().stats.fetches += 1;
    let _: Result<()> = async {
        let _ = custody_conn(&inner, &c).await?;
        on_conn!(&inner, &c, |conn| async {
            let (mut tx, rx) = open_bi(&conn, StreamKind::Custody).await?;
            send(&mut tx, &Msg::Fetch).await?;
            take(&inner, c, tx, rx, None).await
        })
    }
    .await;
}

/// The custodian's half of a delivery to `dst` (pushed, or after its
/// `Fetch`): rounds of listing, the recipient's choice, parcels and
/// receipts, until nothing is left or a round makes no progress.
async fn push(inner: &Arc<Inner>, dst: SignPk, mut tx: SendStream, mut rx: RecvStream) -> Result<()> {
    for _ in 0..MAX_ROUNDS {
        let items = inner.custody.lock().vault.listing(&dst, LISTING_MAX);
        let len = send_len(&mut tx, &Msg::Listing { items: items.clone() }).await?;
        if items.is_empty() {
            break;
        }
        let (msg, _) =
            recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), MAX_MSG, &inner.reply_frames(&dst)).await?;
        let Msg::Take { want, receipts } = msg else { bail!("expected Take") };
        let mut progress = apply_receipts(inner, &dst, &receipts);
        let parcels = inner.custody.lock().vault.take(&dst, &want, ROUND_BYTES);
        let sent = parcels.len();
        let len = send_len(&mut tx, &Msg::Parcels { parcels }).await?;
        if sent > 0 {
            let (msg, _) =
                recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), MAX_MSG, &inner.reply_frames(&dst)).await?;
            let Msg::Receipts { receipts } = msg else { bail!("expected Receipts") };
            let n = apply_receipts(inner, &dst, &receipts);
            inner.custody.lock().stats.parcels_delivered += n as u64;
            progress += n;
        }
        if progress == 0 {
            send(&mut tx, &Msg::Listing { items: Vec::new() }).await?;
            break;
        }
    }
    tx.finish()?;
    Ok(())
}

fn apply_receipts(inner: &Arc<Inner>, dst: &SignPk, receipts: &[Receipt]) -> usize {
    let mut c = inner.custody.lock();
    receipts.iter().take(LISTING_MAX).filter(|r| c.vault.holds(&r.id) && c.vault.receipt(dst, r)).count()
}

/// The recipient's half: what custodian `from` lists, take what we lack.
/// `first`: a listing already read (a push).
async fn take(
    inner: &Arc<Inner>,
    from: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
    mut first: Option<Vec<(Hash32, u32)>>,
) -> Result<()> {
    let frames = inner.reply_frames(&from);
    for _ in 0..MAX_ROUNDS {
        let items = match first.take() {
            Some(items) => items,
            None => match recv_bounded::<Msg>(&mut rx, resources::REPLY_TIMEOUT, MAX_MSG, &frames).await?.0 {
                Msg::Listing { items } => items,
                _ => bail!("expected Listing"),
            },
        };
        if items.is_empty() || items.len() > LISTING_MAX {
            break;
        }
        let (mut want, mut receipts, mut budget) = (Vec::new(), Vec::new(), ROUND_BYTES);
        {
            let c = inner.custody.lock();
            for (id, size) in &items {
                if c.received.contains(id) {
                    receipts.push(Receipt::sign(&inner.keys, *id));
                } else if u64::from(*size) <= budget {
                    budget -= u64::from(*size);
                    want.push(*id);
                }
            }
        }
        let wanted: HashSet<Hash32> = want.iter().copied().collect();
        let len = send_len(&mut tx, &Msg::Take { want, receipts }).await?;
        let (msg, _permit) = recv_bounded::<Msg>(&mut rx, resources::reply_timeout(len), MAX_MSG, &frames).await?;
        let Msg::Parcels { parcels } = msg else { bail!("expected Parcels") };
        if parcels.is_empty() {
            continue;
        }
        // only what we asked for, and only ours
        let parcels: Vec<Parcel> = parcels.into_iter().filter(|p| wanted.contains(&p.id())).collect();
        let (receipts, opened) = inner.receive_parcels(from, parcels);
        send(&mut tx, &Msg::Receipts { receipts }).await?;
        if opened == 0 {
            break;
        }
    }
    let _ = tx.finish();
    Ok(())
}

// ───────────────────────────── serving ─────────────────────────────

/// A `Custody` stream a peer opened.
pub(crate) async fn serve(
    inner: &Arc<Inner>,
    conn: &Connection,
    peer: SignPk,
    mut tx: SendStream,
    mut rx: RecvStream,
) -> Result<()> {
    if !inner.custody.lock().enabled {
        let code = iroh::endpoint::VarInt::from_u32(crate::version::STREAM_REFUSED);
        rx.stop(code).ok();
        tx.reset(code).ok();
        return Err(crate::VersionError::UnknownStreamKind(StreamKind::Custody as u8).into());
    }
    let (msg, permit) = recv_bounded::<Msg>(&mut rx, resources::FIRST_FRAME, MAX_FIRST, &inner.frames(&peer)).await?;
    let now = wall_ms();
    match msg {
        Msg::Deposit { parcel, stamp } => {
            let d = Depositor { key: peer, origin: origin_of(conn), known: inner.shares_space(&peer) };
            let me = inner.keys.sign_pk();
            let ans = inner.custody.lock().vault.deposit(&d, parcel, stamp, &me, now);
            drop(permit);
            send(&mut tx, &Msg::Deposited(ans)).await?;
            tx.finish()?;
        }
        Msg::Fetch => {
            drop(permit);
            let ok = {
                let mut c = inner.custody.lock();
                c.stats.fetches_served += 1;
                c.fetch_rate.take(peer, now)
            };
            if !ok {
                send(&mut tx, &Msg::Listing { items: Vec::new() }).await?;
                tx.finish()?;
                return Ok(());
            }
            // (the connection is authenticated to `peer`: only its mail)
            inner.custody.lock().delivering.insert(peer);
            let res = push(inner, peer, tx, rx).await;
            let mut c = inner.custody.lock();
            c.delivering.remove(&peer);
            if !c.vault.has_mail(&peer) {
                c.retry.remove(&peer);
            }
            return res;
        }
        Msg::Listing { items } => {
            drop(permit);
            // a custodian delivering to us
            return take(inner, peer, tx, rx, Some(items)).await;
        }
        Msg::Release { id, secret } => {
            drop(permit);
            let ok = inner.custody.lock().vault.release(&id, &secret);
            send(&mut tx, &Msg::Released { ok }).await?;
            tx.finish()?;
        }
        Msg::Find { target } => {
            drop(permit);
            let custodians = {
                let mut c = inner.custody.lock();
                if c.find_rate.take(peer, now) {
                    let mut v = c.directory.closest(&target, FIND_MAX);
                    if c.vault.serving() {
                        v.push(inner.keys.sign_pk());
                        v.sort_unstable_by_key(|k| super::distance(&target, k));
                        v.truncate(FIND_MAX);
                    }
                    v
                } else {
                    Vec::new()
                }
            };
            send(&mut tx, &Msg::Found { custodians }).await?;
            tx.finish()?;
        }
        _ => bail!("unexpected custody message"),
    }
    Ok(())
}

// ───────────────────────────── housekeeping ─────────────────────────────

/// Expiry, delivery retries, and asking our likely custodians for our mail.
pub(crate) async fn run(inner: Arc<Inner>) {
    let mut next_fetch = Instant::now() + Duration::from_secs(5);
    loop {
        tokio::time::sleep(TICK).await;
        let now = wall_ms();
        let due: Vec<SignPk> = {
            let mut c = inner.custody.lock();
            if !c.enabled {
                continue;
            }
            c.vault.tick(now);
            c.outbox.expire(now);
            let at = Instant::now();
            let mut due: Vec<SignPk> = c
                .vault
                .recipients()
                .into_iter()
                .filter(|d| !c.delivering.contains(d))
                .filter(|d| c.retry.get(d).is_none_or(|(t, _)| *t <= at))
                .collect();
            due.truncate(DELIVERIES_PER_TICK);
            for d in &due {
                // (a first try is due now; after it, the schedule backs off)
                if !c.retry.contains_key(d) {
                    c.retry_later(*d);
                }
            }
            let held: Vec<SignPk> = c.retry.keys().copied().collect();
            for d in held {
                if !c.vault.has_mail(&d) {
                    c.retry.remove(&d);
                }
            }
            due
        };
        for d in due {
            tokio::spawn(deliver_to(inner.clone(), d));
        }
        if Instant::now() >= next_fetch {
            let every = inner.custody.lock().fetch_every;
            next_fetch = Instant::now() + every;
            tokio::spawn(fetch_mine(inner.clone()));
        }
    }
}

/// Ask the custodians closest to our own key (where senders put our mail
/// when they know nobody better) whether they have anything for us.
async fn fetch_mine(inner: Arc<Inner>) {
    let me = inner.keys.sign_pk();
    let copies = inner.custody.lock().copies;
    for c in find(&inner, me).await.into_iter().take(copies) {
        let go = {
            let mut st = inner.custody.lock();
            let go = st.fetched.get(&c).is_none_or(|t| t.elapsed() >= FETCH_GAP);
            if go {
                st.fetched.insert(c, Instant::now());
            }
            go
        };
        if go {
            tokio::spawn(fetch_from(inner.clone(), c));
        }
    }
}

impl Inner {
    pub(crate) fn custody_stats(&self) -> CustodyStats {
        let c = self.custody.lock();
        let mut s = c.stats.clone();
        s.vault = c.vault.stats();
        (s.held_bytes, s.held_parcels) = c.vault.used();
        s.directory = c.directory.len();
        s
    }
}
