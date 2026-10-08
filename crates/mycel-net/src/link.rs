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
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use iroh::TransportAddr;
use iroh::endpoint::transports::{
    Addr, CustomEndpoint, CustomSender, CustomTransport, FourTuple, PathSelection, PathSelectionContext, PathSelectionData,
    PathSelector, RecvInfo, Transmit,
};
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub use iroh::endpoint::transports;
pub use iroh_base::CustomAddr;
pub use n0_watcher;
pub use noq_udp;

/// Custom transport ids (Iroh `CustomAddr::id`). "myc" + a link number.
pub const TRANSPORT_PEER_WIFI: u64 = 0x6d79_6301;
pub const TRANSPORT_BLUETOOTH: u64 = 0x6d79_6302;
/// Multi-hop mesh (`mesh.rs`): QUIC packets relayed by other devices.
pub const TRANSPORT_MESH: u64 = 0x6d79_6303;
/// In-memory links for tests ([`MemNet`]) pick their own ids.
pub const TRANSPORT_TEST_BASE: u64 = 0x6d79_63f0;

/// What kind of path a packet travels on, for path selection and the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Relayed hop by hop by other nearby devices, over whatever links they
    /// have (end-to-end encrypted; see `mesh.rs`).
    Mesh,
}

impl PathKind {
    pub fn of_custom(id: u64) -> PathKind {
        match id {
            TRANSPORT_BLUETOOTH => PathKind::Bluetooth,
            TRANSPORT_MESH => PathKind::Mesh,
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
    /// carries traffic when nothing else works. The mesh shares the relay's
    /// tier: both are someone else forwarding ciphertext, so measured RTT
    /// decides between them (and comparable ones aggregate). A mesh path
    /// never competes with a direct one: it only exists to devices with no
    /// direct link (`mesh.rs`).
    fn tier(self) -> u8 {
        match self {
            PathKind::Network | PathKind::PeerWifi => 0,
            PathKind::Relay | PathKind::Mesh => 1,
            PathKind::Bluetooth => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PathKind::Network => "Network",
            PathKind::PeerWifi => "Peer-to-peer Wi-Fi",
            PathKind::Bluetooth => "Bluetooth",
            PathKind::Relay => "Internet relay",
            PathKind::Mesh => "Mesh",
        }
    }
}

/// A link's health, shown in the Network panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// QUIC settings for multipath failover and aggregation: every path is
/// probed often enough that a dead one (Wi-Fi network left, radio out of
/// range) is noticed in a few seconds instead of Iroh's default 15, and
/// traffic moves to the next.
///
/// Flow-control windows are raised from noq's defaults (1.25 MB per stream,
/// sized for 100 Mbit/s at 100 ms) so one stream can fill several aggregated
/// paths even when a loaded radio queue adds a few hundred ms of RTT. The
/// connection-wide window caps what a peer can make us buffer.
pub fn transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        .default_path_keep_alive_interval(Duration::from_millis(1500))
        .default_path_max_idle_timeout(Duration::from_secs(5))
        .stream_receive_window(STREAM_WINDOW.into())
        .receive_window(CONN_WINDOW.into())
        .send_window(u64::from(CONN_WINDOW))
        .build()
}

/// Per-stream receive window: 8 MiB (≈ 40 MB/s at 200 ms RTT).
const STREAM_WINDOW: u32 = 8 * 1024 * 1024;
/// Whole-connection receive / send window.
const CONN_WINDOW: u32 = 32 * 1024 * 1024;

/// Within a tier, only switch when the new path is this much faster.
const RTT_SWITCH_MIN: Duration = Duration::from_millis(5);
/// Direct IPv6 gets the same small edge Iroh's default selector gives it.
const IPV6_ADVANTAGE: Duration = Duration::from_millis(3);
/// A path joins the aggregate only while its base RTT is within this factor
/// of the selected path's ...
const AGG_RTT_FACTOR: u32 = 3;
/// ... or within this much of it (on a LAN, 1 ms vs 4 ms is no reason to
/// leave a fast path idle: the reordering it causes is tiny).
const AGG_RTT_SLACK: Duration = Duration::from_millis(15);
/// A path that delivers less than 1/8 of what the selected path does while
/// both are busy is dropped from the aggregate for a while ...
const AGG_RATE_RATIO: f64 = 8.0;
/// ... (if the selected path moves at least this many bytes per second) ...
const AGG_BUSY: f64 = 1_000_000.0;
/// ... first for this long, doubling each time it is judged slow again.
const AGG_SLOW_PAUSE: Duration = Duration::from_secs(30);
const AGG_SLOW_PAUSE_MAX: Duration = Duration::from_secs(300);
/// Leaves the aggregate above this loss rate, rejoins below the lower one.
/// High, because congestion control itself causes loss on a full queue.
const AGG_LOSS_MAX: f64 = 0.25;
const AGG_LOSS_OK: f64 = 0.10;
/// Loss is judged over at least this many packets.
const AGG_LOSS_MIN_PACKETS: u64 = 200;
/// The base RTT may drift up this much per second (routes change).
const BASE_RTT_DRIFT: f64 = 0.01;
/// Every path is pinged each second from both ends (Iroh patch), so a path
/// that has received nothing for this long is dead (radio gone, network
/// left) even before its idle timeout closes it.
const STALE: Duration = Duration::from_secs(3);

/// What the selector remembers about a path between selections.
#[derive(Debug)]
struct PathHealth {
    /// Datagrams sent and lost at the last loss sample.
    sent: u64,
    lost: u64,
    /// Smoothed loss rate.
    loss: f64,
    lossy: bool,
    /// Lowest RTT seen, drifting up slowly: the path's own latency, without
    /// the queueing delay a busy path adds.
    base_rtt: Duration,
    /// Bytes acknowledged (sent − lost) at the last rate sample, and when.
    delivered: u64,
    at: Instant,
    /// Bytes per second over the last sample.
    rate: f64,
    /// It was Available after the last selection.
    aggregated: bool,
    slow_until: Option<Instant>,
    slow_pause: Duration,
    /// Datagrams received so far, and when that last went up.
    received: u64,
    heard: Instant,
    seen: Instant,
}

impl PathHealth {
    fn new(now: Instant, c: &Candidate<'_>) -> Self {
        PathHealth {
            sent: c.sent,
            lost: c.lost,
            loss: 0.0,
            lossy: false,
            base_rtt: c.rtt,
            delivered: c.delivered,
            at: now,
            rate: 0.0,
            aggregated: false,
            slow_until: None,
            slow_pause: AGG_SLOW_PAUSE,
            received: c.received,
            heard: now,
            seen: now,
        }
    }

    fn stale(&self, now: Instant) -> bool {
        now.duration_since(self.heard) > STALE
    }

    fn update(&mut self, now: Instant, c: &Candidate<'_>) {
        let dt = now.duration_since(self.seen).as_secs_f64();
        self.seen = now;
        // Counters are sums over connections; one closing makes them drop.
        if c.sent < self.sent || c.lost < self.lost || c.delivered < self.delivered {
            (self.sent, self.lost, self.delivered, self.at) = (c.sent, c.lost, c.delivered, now);
        }
        if c.received != self.received {
            (self.received, self.heard) = (c.received, now);
        }
        let drifted = self.base_rtt.mul_f64(1.0 + BASE_RTT_DRIFT * dt);
        self.base_rtt = drifted.min(c.rtt);
        let (ds, dl) = (c.sent - self.sent, c.lost - self.lost);
        if ds >= AGG_LOSS_MIN_PACKETS {
            self.loss = 0.5 * self.loss + 0.5 * (dl as f64 / ds as f64).min(1.0);
            (self.sent, self.lost) = (c.sent, c.lost);
        }
        if self.loss > AGG_LOSS_MAX {
            self.lossy = true;
        } else if self.loss < AGG_LOSS_OK {
            self.lossy = false;
        }
        let span = now.duration_since(self.at).as_secs_f64();
        if span >= 0.5 {
            self.rate = (c.delivered - self.delivered) as f64 / span;
            (self.delivered, self.at) = (c.delivered, now);
        }
    }
}

/// Picks the paths each connection sends on.
///
/// The *selected* path is the fastest of the local paths (network,
/// peer-to-peer Wi-Fi), else the relay, else Bluetooth. Sticky within a tier
/// so jitter doesn't flap between paths; across tiers it moves immediately
/// (e.g. back from Bluetooth the moment Wi-Fi returns).
///
/// Every other healthy path that is not much slower is marked *Available*
/// too (Mycel's Iroh patch, `PathSelection::also_use`); noq's multipath
/// scheduler then sends on all Available paths, each within its own
/// congestion window, so their bandwidth adds up. Iroh re-runs selection
/// every second. A path stays a Backup when it would hold the others back
/// (a stream's bytes are delivered in order, so a slow path delays the
/// fast one: head-of-line blocking):
/// - Bluetooth: always a backup unless it is the only path;
/// - base RTT (lowest seen) above `max(3 × selected, selected + 15 ms)`;
///   this also keeps the relay out on a LAN;
/// - delivering under 1/8 of the selected path's rate while that one is
///   busy: out for 30 s, doubling up to 5 min;
/// - more than 25 % packet loss (back in below 10 %);
/// - a second IP path out of the same local interface or to the same remote
///   address (IPv4 and IPv6 over one Wi-Fi are one radio). Distinct
///   interfaces (Ethernet, Thunderbolt bridge, Wi-Fi) each count.
///
/// A path that has received nothing for 3 s (every path is pinged each
/// second) is dead: it is not *selected* while another path lives, so Iroh
/// doesn't keep reopening it on other connections to the peer.
#[derive(Debug, Default)]
pub struct MycelPathSelector {
    health: Mutex<HashMap<FourTuple, PathHealth>>,
    ifaces: Mutex<Option<(Instant, HashMap<IpAddr, String>)>>,
}

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

    /// The local interface an IP path leaves through (its name, or the
    /// local IP itself when the OS doesn't say).
    fn interface_of(&self, local: Option<IpAddr>) -> Option<String> {
        let ip = local?;
        let mut cache = self.ifaces.lock();
        if cache.as_ref().is_none_or(|(t, _)| t.elapsed() > Duration::from_secs(5)) {
            *cache = Some((Instant::now(), interface_names()));
        }
        let names = &cache.as_ref().expect("just filled").1;
        Some(names.get(&ip).cloned().unwrap_or_else(|| ip.to_string()))
    }
}

/// One candidate path, its stats summed over the connections it is on.
struct Candidate<'a> {
    data: PathSelectionData<'a>,
    rtt: Duration,
    sent: u64,
    lost: u64,
    /// Bytes sent and not lost.
    delivered: u64,
    received: u64,
}

impl PathSelector for MycelPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        // The same path can be on several connections to the peer.
        let mut cands: Vec<Candidate<'_>> = Vec::new();
        for p in ctx.paths() {
            let Some(s) = p.stats() else { continue };
            let delivered = s.udp_tx.bytes.saturating_sub(s.lost_bytes);
            match cands.iter_mut().find(|c| c.data.network_path() == p.network_path()) {
                Some(c) => {
                    c.rtt = c.rtt.min(s.rtt);
                    c.sent += s.udp_tx.datagrams;
                    c.lost += s.lost_packets;
                    c.delivered += delivered;
                    c.received += s.udp_rx.datagrams;
                }
                None => cands.push(Candidate {
                    rtt: s.rtt,
                    sent: s.udp_tx.datagrams,
                    lost: s.lost_packets,
                    delivered,
                    received: s.udp_rx.datagrams,
                    data: p,
                }),
            }
        }
        let mut selection = PathSelection::none();
        let now = Instant::now();
        let mut health = self.health.lock();
        health.retain(|_, h| now.duration_since(h.seen) < Duration::from_secs(120));
        for c in &cands {
            match health.get_mut(c.data.network_path()) {
                Some(h) => h.update(now, c),
                None => {
                    health.insert(c.data.network_path().clone(), PathHealth::new(now, c));
                }
            }
        }
        // Dead paths (nothing received lately) are skipped while any path lives.
        let alive = |c: &&Candidate<'_>| health.get(c.data.network_path()).is_none_or(|h| !h.stale(now));
        let live: Vec<&Candidate<'_>> = cands.iter().filter(alive).collect();
        let pool: Vec<&Candidate<'_>> = if live.is_empty() { cands.iter().collect() } else { live };
        let current = pool.iter().copied().find(|c| Some(c.data.network_path()) == ctx.current());
        let Some(best) = pool.iter().copied().min_by_key(|c| Self::key(c.data.network_path(), c.rtt)) else {
            return selection;
        };
        let (tier, rtt) = Self::key(best.data.network_path(), best.rtt);
        let primary = match current.map(|c| (c, Self::key(c.data.network_path(), c.rtt))) {
            Some((c, (ct, crtt))) if ct == tier && rtt + (RTT_SWITCH_MIN.as_nanos() as i128) > crtt => c,
            _ => best,
        };
        selection.set(&primary.data);
        let primary_path = primary.data.network_path();
        let (p_base, p_rate) = health.get(primary_path).map_or((primary.rtt, 0.0), |h| (h.base_rtt, h.rate));

        // Aggregation: more Available paths next to the selected one.
        let aggregate = PathKind::of_addr(&primary_path.remote()) != PathKind::Bluetooth;
        let limit = (p_base * AGG_RTT_FACTOR).max(p_base + AGG_RTT_SLACK);
        let mut used_ifaces: Vec<String> = Vec::new();
        let mut used_remotes: Vec<IpAddr> = Vec::new();
        let mut distinct_ip = |path: &FourTuple| -> bool {
            let FourTuple::Ip { remote, local } = path else { return true };
            let iface = self.interface_of(*local);
            if used_remotes.contains(&remote.ip()) || iface.as_ref().is_some_and(|i| used_ifaces.contains(i)) {
                return false;
            }
            used_remotes.push(remote.ip());
            used_ifaces.extend(iface);
            true
        };
        distinct_ip(primary_path);
        let mut rest: Vec<&Candidate<'_>> = cands.iter().filter(|c| c.data.network_path() != primary_path).collect();
        rest.sort_by_key(|c| c.rtt);
        for c in rest {
            let path = c.data.network_path();
            let Some(h) = health.get_mut(path) else { continue };
            // Too slow while both were busy: pause it.
            if h.aggregated && p_rate >= AGG_BUSY && h.rate * AGG_RATE_RATIO < p_rate {
                h.slow_until = Some(now + h.slow_pause);
                h.slow_pause = (h.slow_pause * 2).min(AGG_SLOW_PAUSE_MAX);
            } else if h.aggregated && p_rate >= AGG_BUSY {
                h.slow_pause = AGG_SLOW_PAUSE;
            }
            // (A stale path keeps its status: demoting it before its idle
            // timeout closes it only delays resending what is in flight on it.)
            let ok = aggregate
                && PathKind::of_addr(&path.remote()) != PathKind::Bluetooth
                && h.base_rtt <= limit
                && !h.lossy
                && h.slow_until.is_none_or(|t| now >= t)
                && distinct_ip(path);
            h.aggregated = ok;
            if ok {
                selection.also_use(&c.data);
            }
        }
        if let Some(h) = health.get_mut(primary_path) {
            h.aggregated = true;
        }
        selection
    }
}

/// Local IP → interface name (`en0`, `bridge0`, `lo0`, ...).
#[cfg(unix)]
fn interface_names() -> HashMap<IpAddr, String> {
    let mut out = HashMap::new();
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list that we free with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return out;
    }
    let mut cur = addrs;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points to a sockaddr of the family it names.
        let ip = unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::from(u32::from_be(sa.sin_addr.s_addr).to_be_bytes())
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::from(sa.sin6_addr.s6_addr)
                }
                _ => continue,
            }
        };
        // SAFETY: ifa_name is a NUL-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        out.insert(ip, name.to_string_lossy().into_owned());
    }
    // SAFETY: frees the list allocated above.
    unsafe { libc::freeifaddrs(addrs) };
    out
}

#[cfg(not(unix))]
fn interface_names() -> HashMap<IpAddr, String> {
    HashMap::new()
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

/// Optional radio limits for a [`MemNet`] (default: none, instant delivery).
#[derive(Default)]
struct Shape {
    /// Bytes per second the "radio" carries; `None` = unlimited.
    rate: Option<u64>,
    /// One-way delay added to every packet.
    latency: Duration,
    /// When the radio finishes sending what is already queued.
    busy_until: Option<Instant>,
}

/// More queued than this and packets are dropped (a congested radio).
const MEM_MAX_QUEUE: Duration = Duration::from_millis(250);

/// An in-memory "radio" shared by test nodes: every [`MemLink`] on the same
/// `MemNet` can reach every other, until [`MemNet::cut`] silences it. Lets
/// tests prove failover between links without real radios.
#[derive(Clone)]
pub struct MemNet {
    id: u64,
    kind: PathKind,
    down: Arc<AtomicBool>,
    inner: Arc<Mutex<MemNetInner>>,
    shape: Arc<Mutex<Shape>>,
}

impl MemNet {
    /// `n` (0..16) picks the transport id; `kind` is what it reports as.
    pub fn new(n: u64, kind: PathKind) -> MemNet {
        let id = if kind == PathKind::Bluetooth { TRANSPORT_BLUETOOTH } else { TRANSPORT_TEST_BASE + n };
        MemNet { id, kind, down: Arc::default(), inner: Arc::default(), shape: Arc::default() }
    }

    /// Limit the link to `bytes_per_sec` (e.g. ~20 KB/s for Bluetooth LE),
    /// with a short send queue; `None` removes the limit.
    pub fn set_rate_limit(&self, bytes_per_sec: Option<u64>) {
        let mut s = self.shape.lock();
        s.rate = bytes_per_sec.filter(|r| *r > 0);
        s.busy_until = None;
    }

    /// Add a fixed one-way delay to every packet.
    pub fn set_latency(&self, latency: Duration) {
        self.shape.lock().latency = latency;
    }

    /// When a packet of `len` bytes sent now arrives: `Some(delay)`, or
    /// `None` if the send queue is full and it is dropped.
    fn schedule(&self, len: usize) -> Option<Duration> {
        let mut s = self.shape.lock();
        let Some(rate) = s.rate else { return Some(s.latency) };
        let now = Instant::now();
        let start = s.busy_until.filter(|b| *b > now).unwrap_or(now);
        if start - now > MEM_MAX_QUEUE {
            return None;
        }
        let done = start + Duration::from_secs_f64(len as f64 / rate as f64);
        s.busy_until = Some(done);
        Some(done - now + s.latency)
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
            let packet = Packet { data: Bytes::copy_from_slice(chunk), from: self.from.clone() };
            // a full queue drops the packet, like a congested radio
            match self.net.schedule(chunk.len()) {
                None => {}
                Some(d) if d.is_zero() => {
                    let _ = tx.try_send(packet);
                }
                Some(d) => match tokio::runtime::Handle::try_current() {
                    Ok(rt) => {
                        let (tx, down) = (tx.clone(), self.net.down.clone());
                        rt.spawn(async move {
                            tokio::time::sleep(d).await;
                            if !down.load(Ordering::SeqCst) {
                                let _ = tx.try_send(packet);
                            }
                        });
                    }
                    Err(_) => {
                        let _ = tx.try_send(packet);
                    }
                },
            }
        }
        Poll::Ready(Ok(()))
    }
}
