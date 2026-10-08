//! Links: extra, non-IP paths between devices, carried as Iroh custom
//! transports (Apple peer-to-peer Wi-Fi, Bluetooth LE, ...).
//!
//! A link moves opaque QUIC packets between two devices and announces which
//! devices it can currently reach. Everything above it is unchanged: the same
//! QUIC connection, authenticated to the peer's key, end-to-end encrypted, and
//! with QUIC multipath one connection keeps every known path open and moves
//! between them when one dies (Wi-Fi network lost → peer-to-peer Wi-Fi →
//! Bluetooth). [`MycelPathSelector`] decides which path carries the traffic.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use iroh::TransportAddr;
use iroh::endpoint::transports::{
    Addr, CustomEndpoint, CustomSender, CustomTransport, FourTuple, PathSelection, PathSelectionContext,
    PathSelector, RecvInfo, Transmit,
};
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::mpsc;

pub use iroh::endpoint::transports;
pub use iroh_base::CustomAddr;
pub use n0_watcher;
pub use noq_udp;

/// Custom transport ids (Iroh `CustomAddr::id`). "myc" + a link number.
pub const TRANSPORT_PEER_WIFI: u64 = 0x6d79_6301;
pub const TRANSPORT_BLUETOOTH: u64 = 0x6d79_6302;
/// In-memory links for tests ([`MemNet`]) pick their own ids.
pub const TRANSPORT_TEST_BASE: u64 = 0x6d79_63f0;

/// What kind of path a packet travels on, for path selection and the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    /// Same Wi-Fi / Ethernet / cable network, or the open internet (direct IP).
    Network,
    /// Apple peer-to-peer Wi-Fi (AWDL, what AirDrop uses): no shared network needed.
    PeerWifi,
    /// Bluetooth LE: slow, short range, works with no Wi-Fi at all.
    Bluetooth,
    /// Through an internet relay server (end-to-end encrypted).
    Relay,
}

impl PathKind {
    pub fn of_custom(id: u64) -> PathKind {
        match id {
            TRANSPORT_BLUETOOTH => PathKind::Bluetooth,
            // test links pretend to be peer Wi-Fi unless they use the BT id
            _ => PathKind::PeerWifi,
        }
    }

    pub fn of(addr: &TransportAddr) -> PathKind {
        match addr {
            TransportAddr::Relay(_) => PathKind::Relay,
            TransportAddr::Custom(c) => PathKind::of_custom(c.id()),
            _ => PathKind::Network,
        }
    }

    fn of_addr(addr: &Addr) -> PathKind {
        match addr {
            Addr::Ip(_) => PathKind::Network,
            Addr::Relay(..) => PathKind::Relay,
            Addr::Custom(c) => PathKind::of_custom(c.id()),
        }
    }

    /// Lower is preferred. Fast local paths compete on RTT; the relay needs
    /// the internet and a third party; Bluetooth is the slowest, so it only
    /// carries traffic when nothing else works.
    fn tier(self) -> u8 {
        match self {
            PathKind::Network | PathKind::PeerWifi => 0,
            PathKind::Relay => 1,
            PathKind::Bluetooth => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PathKind::Network => "Network",
            PathKind::PeerWifi => "Peer-to-peer Wi-Fi",
            PathKind::Bluetooth => "Bluetooth",
            PathKind::Relay => "Internet relay",
        }
    }
}

/// A link's health, shown in the Network panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkStatus {
    pub kind: PathKind,
    /// Working: advertising and discovering.
    pub active: bool,
    /// Why it isn't working, in words a user can act on ("Bluetooth is off").
    pub detail: Option<String>,
    /// Devices currently reachable over this link.
    pub peers: usize,
}

/// What a link tells the node.
#[derive(Clone, Debug)]
pub enum LinkEvent {
    /// `peer` is reachable at `addr` on this link.
    Found { peer: SignPk, addr: CustomAddr, name: Option<String> },
    /// `addr` no longer works for `peer`.
    Lost { peer: SignPk, addr: CustomAddr },
}

/// A non-IP path between devices. Implementations live in their own crates
/// (`mycel-link-awdl`, `mycel-link-ble`); the node only sees this trait.
pub trait Link: Send + Sync + 'static {
    fn kind(&self) -> PathKind;
    /// The Iroh custom transport carrying QUIC packets over this link.
    fn transport(&self) -> Arc<dyn CustomTransport>;
    /// Start advertising and discovering. Called once, after the endpoint is
    /// bound; report peers on `events` for as long as the link runs.
    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()>;
    /// The display name changed (some links advertise it).
    fn set_name(&self, _name: &str) {}
    fn status(&self) -> LinkStatus;
    /// Stop advertising and release the radio.
    fn stop(&self) {}
}

// ───────────────────────────── path selection ─────────────────────────────

/// QUIC settings for multipath failover: every path is probed often enough
/// that a dead one (Wi-Fi network left, radio out of range) is noticed in a
/// few seconds instead of Iroh's default 15, and traffic moves to the next.
pub fn transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        .default_path_keep_alive_interval(Duration::from_millis(1500))
        .default_path_max_idle_timeout(Duration::from_secs(5))
        .build()
}

/// Within a tier, only switch when the new path is this much faster.
const RTT_SWITCH_MIN: Duration = Duration::from_millis(5);
/// Direct IPv6 gets the same small edge Iroh's default selector gives it.
const IPV6_ADVANTAGE: Duration = Duration::from_millis(3);

/// Picks the path for each connection: the fastest of the local paths
/// (network, peer-to-peer Wi-Fi), else the relay, else Bluetooth. Sticky
/// within a tier so jitter doesn't flap between paths; across tiers it moves
/// immediately (e.g. back from Bluetooth the moment Wi-Fi returns).
#[derive(Debug, Default)]
pub struct MycelPathSelector;

impl MycelPathSelector {
    fn key(path: &FourTuple, rtt: Duration) -> (u8, i128) {
        let remote = path.remote();
        let kind = PathKind::of_addr(&remote);
        let mut biased = rtt.as_nanos() as i128;
        if matches!(remote, Addr::Ip(a) if a.is_ipv6()) {
            biased -= IPV6_ADVANTAGE.as_nanos() as i128;
        }
        (kind.tier(), biased)
    }
}

impl PathSelector for MycelPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let current = ctx.current();
        let mut best = None;
        let mut best_key = None;
        let mut current_key: Option<(u8, i128)> = None;
        for p in ctx.paths() {
            let Some(stats) = p.stats() else { continue };
            let key = Self::key(p.network_path(), stats.rtt);
            if Some(p.network_path()) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best_key.is_none_or(|b| key < b) {
                best_key = Some(key);
                best = Some(p);
            }
        }
        let mut selection = PathSelection::none();
        let (Some(best), Some((tier, rtt))) = (best, best_key) else {
            return selection;
        };
        match current_key {
            None => selection.set(&best),
            Some((ct, _)) if ct != tier => selection.set(&best),
            Some((_, crtt)) if rtt + RTT_SWITCH_MIN.as_nanos() as i128 <= crtt => selection.set(&best),
            _ => {}
        }
        selection
    }
}

// ─────────────────────────── in-memory test links ───────────────────────────

#[derive(Debug)]
struct Packet {
    data: Bytes,
    from: CustomAddr,
}

#[derive(Default)]
struct MemNetInner {
    inboxes: HashMap<SignPk, mpsc::Sender<Packet>>,
    started: Vec<(SignPk, mpsc::UnboundedSender<LinkEvent>)>,
}

/// An in-memory "radio" shared by test nodes: every [`MemLink`] on the same
/// `MemNet` can reach every other, until [`MemNet::cut`] silences it. Lets
/// tests prove failover between links without real radios.
#[derive(Clone)]
pub struct MemNet {
    id: u64,
    kind: PathKind,
    down: Arc<AtomicBool>,
    inner: Arc<Mutex<MemNetInner>>,
}

impl MemNet {
    /// `n` (0..16) picks the transport id; `kind` is what it reports as.
    pub fn new(n: u64, kind: PathKind) -> MemNet {
        let id = if kind == PathKind::Bluetooth { TRANSPORT_BLUETOOTH } else { TRANSPORT_TEST_BASE + n };
        MemNet { id, kind, down: Arc::default(), inner: Arc::default() }
    }

    /// Drop every packet from now on (radio out of range).
    pub fn cut(&self) {
        self.down.store(true, Ordering::SeqCst);
        let inner = self.inner.lock();
        for (pk, _) in &inner.started {
            for (_, tx) in &inner.started {
                let _ = tx.send(LinkEvent::Lost { peer: *pk, addr: self.addr_of(pk) });
            }
        }
    }

    pub fn link(&self, me: SignPk) -> Arc<MemLink> {
        let (tx, rx) = mpsc::channel(4096);
        self.inner.lock().inboxes.insert(me, tx);
        Arc::new(MemLink { net: self.clone(), me, rx: Arc::new(tokio::sync::Mutex::new(rx)) })
    }

    /// The address `pk` has on this link.
    pub fn addr_of(&self, pk: &SignPk) -> CustomAddr {
        CustomAddr::from_parts(self.id, &pk.0)
    }

    fn parse(&self, a: &CustomAddr) -> Option<SignPk> {
        (a.id() == self.id).then(|| a.data().try_into().ok().map(SignPk)).flatten()
    }
}

pub struct MemLink {
    net: MemNet,
    me: SignPk,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for MemLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemLink({:x})", self.net.id)
    }
}

impl Link for MemLink {
    fn kind(&self) -> PathKind {
        self.net.kind
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(MemTransport { net: self.net.clone(), me: self.me, rx: self.rx.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        let mut inner = self.net.inner.lock();
        for (pk, tx) in &inner.started {
            let _ = events.send(LinkEvent::Found { peer: *pk, addr: self.net.addr_of(pk), name: None });
            let _ = tx.send(LinkEvent::Found { peer: self.me, addr: self.net.addr_of(&self.me), name: None });
        }
        inner.started.push((self.me, events));
        Ok(())
    }

    fn status(&self) -> LinkStatus {
        let up = !self.net.down.load(Ordering::SeqCst);
        LinkStatus {
            kind: self.net.kind,
            active: up,
            detail: None,
            peers: if up { self.net.inner.lock().started.len().saturating_sub(1) } else { 0 },
        }
    }
}

#[derive(Debug)]
struct MemTransport {
    net: MemNet,
    me: SignPk,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for MemNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemNet({:x})", self.id)
    }
}

impl CustomTransport for MemTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self
            .rx
            .clone()
            .try_lock_owned()
            .map_err(|_| io::Error::other("link already bound"))?;
        Ok(Box::new(MemEndpoint {
            net: self.net.clone(),
            me: self.me,
            addrs: n0_watcher::Watchable::new(vec![self.net.addr_of(&self.me)]),
            rx,
        }))
    }
}

struct MemEndpoint {
    net: MemNet,
    me: SignPk,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<Packet>>,
}

impl std::fmt::Debug for MemEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemEndpoint")
    }
}

impl CustomEndpoint for MemEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(MemSender { net: self.net.clone(), from: self.net.addr_of(&self.me) })
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
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("link closed"))),
            Poll::Ready(_) => {}
        }
        let local = self.net.addr_of(&self.me);
        let mut count = 0;
        for p in packets {
            if self.net.down.load(Ordering::SeqCst) || bufs[count].len() < p.data.len() {
                continue;
            }
            bufs[count][..p.data.len()].copy_from_slice(&p.data);
            metas[count].len = p.data.len();
            metas[count].stride = p.data.len();
            recv_infos[count] = RecvInfo::new(p.from, Some(local.clone()));
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
struct MemSender {
    net: MemNet,
    from: CustomAddr,
}

impl CustomSender for MemSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == self.net.id
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if self.net.down.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(())); // lost in the air
        }
        let Some(to) = self.net.parse(dst) else {
            return Poll::Ready(Err(io::Error::other("not a peer on this link")));
        };
        let Some(tx) = self.net.inner.lock().inboxes.get(&to).cloned() else {
            return Poll::Ready(Err(io::Error::other("unknown peer")));
        };
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for chunk in transmit.contents.chunks(seg) {
            // a full queue drops the packet, like a congested radio
            let _ = tx.try_send(Packet { data: Bytes::copy_from_slice(chunk), from: self.from.clone() });
        }
        Poll::Ready(Ok(()))
    }
}
