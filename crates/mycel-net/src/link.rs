//! Links: extra paths between devices, carried as Iroh custom transports
//! (Apple peer-to-peer Wi-Fi, Bluetooth LE, any other network interface such
//! as UWB / 802.15.4, Wi-Fi Direct or a cable, ...).
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
use iroh::endpoint::{Path, PathList};
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
/// Any network interface (`mycel-link-iface`): the address carries the
/// medium, see [`PathKind::of_custom_addr`].
pub const TRANSPORT_IFACE: u64 = 0x6d79_6320;
/// Multi-hop mesh (`mesh.rs`): QUIC packets relayed by other devices.
pub const TRANSPORT_MESH: u64 = 0x6d79_6303;
/// In-memory links for tests ([`MemNet`]) pick their own ids.
pub const TRANSPORT_TEST_BASE: u64 = 0x6d79_63f0;

/// The medium a path travels over, for the UI and as a starting guess for
/// path selection. Selection itself ranks paths by what they measure (RTT,
/// throughput), so a new kind of radio needs no special case: only a prior
/// ([`PathKind::prior_rate`]) until it has carried traffic.
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
    /// A Wi-Fi Direct (Wi-Fi P2P) group, e.g. a Linux `p2p-*` interface.
    WifiDirect,
    /// An ultra-wideband radio (IEEE 802.15.4z HRP).
    Uwb,
    /// A low-power IEEE 802.15.4 radio: Thread, 6LoWPAN.
    Ieee802154,
    /// A cable: Ethernet, Thunderbolt or USB bridge.
    Ethernet,
    /// Any other network interface (802.11s or ad-hoc Wi-Fi mesh, ...); the
    /// link's status names it.
    Other,
    /// Relayed hop by hop by other nearby Mycel devices, over whatever links
    /// they have (end-to-end encrypted; see `mesh.rs`).
    Mesh,
}

impl PathKind {
    /// Every kind, in a stable order (wire codes are indexes into this).
    pub const ALL: [PathKind; 10] = [
        PathKind::Network,
        PathKind::PeerWifi,
        PathKind::Bluetooth,
        PathKind::Relay,
        PathKind::WifiDirect,
        PathKind::Uwb,
        PathKind::Ieee802154,
        PathKind::Ethernet,
        PathKind::Other,
        PathKind::Mesh,
    ];

    /// One-byte code carried in link addresses.
    pub fn code(self) -> u8 {
        PathKind::ALL.iter().position(|k| *k == self).expect("listed") as u8
    }

    /// Unknown codes (a newer peer) read as [`PathKind::Other`].
    pub fn from_code(code: u8) -> PathKind {
        PathKind::ALL.get(code as usize).copied().unwrap_or(PathKind::Other)
    }

    pub fn of_custom(id: u64) -> PathKind {
        match id {
            TRANSPORT_BLUETOOTH => PathKind::Bluetooth,
            TRANSPORT_IFACE => PathKind::Other,
            TRANSPORT_MESH => PathKind::Mesh,
            // test links pretend to be peer Wi-Fi unless they use the BT id
            _ => PathKind::PeerWifi,
        }
    }

    /// The medium of a link address. Links whose transport carries several
    /// media (network interfaces, test links) put its code in the first
    /// byte (iface) or the byte after the node key (test links).
    pub fn of_custom_addr(addr: &CustomAddr) -> PathKind {
        match addr.id() {
            TRANSPORT_IFACE => addr.data().first().map_or(PathKind::Other, |c| PathKind::from_code(*c)),
            id if (TRANSPORT_TEST_BASE..TRANSPORT_TEST_BASE + 16).contains(&id) && addr.data().len() == 33 => {
                PathKind::from_code(addr.data()[32])
            }
            id => PathKind::of_custom(id),
        }
    }

    pub fn of(addr: &TransportAddr) -> PathKind {
        match addr {
            TransportAddr::Relay(_) => PathKind::Relay,
            TransportAddr::Custom(c) => PathKind::of_custom_addr(c),
            _ => PathKind::Network,
        }
    }

    fn of_addr(addr: &Addr) -> PathKind {
        match addr {
            Addr::Ip(_) => PathKind::Network,
            Addr::Relay(..) => PathKind::Relay,
            Addr::Custom(c) => PathKind::of_custom_addr(c),
        }
    }

    /// What this medium typically delivers, in bytes per second: path
    /// selection's guess until the path has been measured. Rough on purpose;
    /// measurements replace it (see [`MycelPathSelector`]).
    pub fn prior_rate(self) -> f64 {
        const KB: f64 = 1000.0;
        const MB: f64 = 1_000_000.0;
        match self {
            PathKind::Ethernet => 100.0 * MB,
            PathKind::Network => 50.0 * MB,
            PathKind::PeerWifi | PathKind::WifiDirect => 25.0 * MB,
            // a shared server on the internet
            PathKind::Relay => 2.0 * MB,
            PathKind::Other => 1.0 * MB,
            // 6.8 Mbit/s HRP UWB
            PathKind::Uwb => 600.0 * KB,
            // BLE L2CAP in practice
            PathKind::Bluetooth => 30.0 * KB,
            // 250 kbit/s, 6LoWPAN headers and mesh-under hops
            PathKind::Ieee802154 => 15.0 * KB,
            // at least two hops over links we don't know: below the relay
            // until measured. (A mesh path never competes with a direct one:
            // devices with a direct path get no mesh addresses.)
            PathKind::Mesh => 500.0 * KB,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PathKind::Network => "Network",
            PathKind::PeerWifi => "Peer-to-peer Wi-Fi",
            PathKind::Bluetooth => "Bluetooth",
            PathKind::Relay => "Internet relay",
            PathKind::WifiDirect => "Wi-Fi Direct",
            PathKind::Uwb => "UWB",
            PathKind::Ieee802154 => "Thread / 802.15.4",
            PathKind::Ethernet => "Cable",
            PathKind::Other => "Other link",
            PathKind::Mesh => "Mesh",
        }
    }
}

/// The path a connection is using: the one Iroh selected, else the open
/// path that has carried the most.
///
/// Iroh selects one path per peer, across all connections to that peer, and
/// marks it selected on each connection that has it. But each end selects on
/// its own (whichever path it measured first, until another is clearly
/// better), and only the end that dialed a connection opens paths on it. So
/// on a connection the peer dialed, the path we selected may not exist: no
/// path there is selected, and the connection sends on the paths it has.
pub fn path_in_use<'a>(paths: &'a PathList<'_>) -> Option<Path<'a>> {
    paths.iter().find(|p| p.is_selected()).or_else(|| {
        // the first of equals: a new connection's first path
        paths.iter().rev().max_by_key(|p| {
            let s = p.stats();
            s.udp_tx.bytes.saturating_add(s.udp_rx.bytes)
        })
    })
}

/// A link's health, shown in the Network panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkStatus {
    pub kind: PathKind,
    /// What exactly this is, when the kind alone doesn't say ("802.11s mesh
    /// on mesh0", "wpan0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
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
    /// One status per medium, for links that drive several (one per network
    /// interface kind).
    fn statuses(&self) -> Vec<LinkStatus> {
        vec![self.status()]
    }
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
///
/// The stream limits are how a peer is told to slow down: QUIC grants it
/// a new stream only as one of its open ones ends, so an exchange beyond
/// the limit waits on the peer's side for its turn instead of being
/// refused. Each connection (one per peer) has its own, so one peer's
/// streams never use up another's.
pub fn transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        .default_path_keep_alive_interval(Duration::from_millis(1500))
        .default_path_max_idle_timeout(Duration::from_secs(5))
        .stream_receive_window(STREAM_WINDOW.into())
        .receive_window(CONN_WINDOW.into())
        .send_window(u64::from(CONN_WINDOW))
        .max_concurrent_bidi_streams(STREAMS_BIDI.into())
        .max_concurrent_uni_streams(STREAMS_UNI.into())
        .build()
}

/// Per-stream receive window: 8 MiB (≈ 40 MB/s at 200 ms RTT).
pub(crate) const STREAM_WINDOW: u32 = 8 * 1024 * 1024;
/// Whole-connection receive / send window.
const CONN_WINDOW: u32 = 32 * 1024 * 1024;
/// Bi-streams a peer may have open on one connection at once: syncs (up
/// to 16 at a time), blob pieces (two per file it downloads from us) and
/// pushes, cards; DTN bundles on a mesh hop connection.
const STREAMS_BIDI: u32 = 64;
/// Uni-streams: ephemeral messages (presence, cursors, game state), DTN
/// summaries, and in calls one per video frame.
const STREAMS_UNI: u32 = 128;


/// Paths are ranked by the time a typical exchange of this many bytes takes
/// on them: RTT + size / throughput. Big enough that throughput matters (the
/// relay beats Bluetooth even when Bluetooth answers faster), small enough
/// that RTT still decides between fast paths.
const REF_BYTES: f64 = 64.0 * 1024.0;
/// Only switch when the new path is this much cheaper (no flapping on jitter).
const RTT_SWITCH_MIN: Duration = Duration::from_millis(5);
/// The RTT is above `2 × base + this` while a path is busy: its queue is
/// growing, so what it delivers now is what it can deliver.
const QUEUE_SLACK: Duration = Duration::from_millis(10);
/// ... judged only while it carries traffic (in use, and more than the
/// probes every path gets: an idle path's RTT says nothing about its rate).
const BUSY_MIN: f64 = 2_000.0;
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
    /// Estimated throughput: the medium's prior, raised by any faster
    /// sample, lowered towards what it delivers while its queue grows.
    capacity: f64,
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
            capacity: PathKind::of_addr(&c.data.network_path().remote()).prior_rate(),
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
            if self.rate > self.capacity {
                self.capacity = self.rate;
            } else if self.aggregated && self.rate >= BUSY_MIN && c.rtt > self.base_rtt * 2 + QUEUE_SLACK {
                // saturated: this is about all it carries
                self.capacity = 0.5 * (self.capacity + self.rate);
            }
        }
    }

    /// Time a [`REF_BYTES`] exchange takes on this path, in nanoseconds.
    /// While the path is busy with our traffic, its RTT mostly measures the
    /// queue we built, and the capacity already prices that in (it drops
    /// towards what a saturated path delivers): counting the queue again
    /// made a bulk transfer's own queue hand the selection to an idle,
    /// unmeasured path many times slower. So a busy path's RTT counts up to
    /// where it would be called saturated.
    fn cost(&self, rtt: Duration) -> i128 {
        let rtt = if self.rate >= BUSY_MIN { rtt.min(self.base_rtt * 2 + QUEUE_SLACK) } else { rtt };
        cost(rtt, self.capacity)
    }
}

fn cost(rtt: Duration, capacity: f64) -> i128 {
    rtt.as_nanos() as i128 + (REF_BYTES / capacity.max(1.0) * 1e9) as i128
}

/// Picks the paths each connection sends on.
///
/// The *selected* path is the one where a typical exchange (64 KiB) finishes
/// first: its RTT plus 64 KiB at its estimated throughput. The throughput
/// starts as the medium's prior ([`PathKind::prior_rate`]: cable > Wi-Fi >
/// relay > UWB > Bluetooth > 802.15.4) and follows what the path delivers,
/// so any radio ranks itself by what it measures. Sticky (a switch needs a
/// 5 ms gain) so jitter doesn't flap between paths, yet moving between very
/// different paths is immediate (back from Bluetooth the moment Wi-Fi returns).
///
/// Every other healthy path that is not much slower is marked *Available*
/// too (Mycel's Iroh patch, `PathSelection::also_use`); noq's multipath
/// scheduler then sends on all Available paths, each within its own
/// congestion window, so their bandwidth adds up. Iroh re-runs selection
/// every second. A path stays a Backup when it would hold the others back
/// (a stream's bytes are delivered in order, so a slow path delays the
/// fast one: head-of-line blocking):
/// - estimated throughput under 1/8 of the selected path's (Bluetooth or
///   802.15.4 next to Wi-Fi): only a backup unless it is the only path;
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
    /// Lower is better.
    fn key(path: &FourTuple, rtt: Duration, health: Option<&PathHealth>) -> i128 {
        let remote = path.remote();
        let mut c = match health {
            Some(h) => h.cost(rtt),
            None => cost(rtt, PathKind::of_addr(&remote).prior_rate()),
        };
        if matches!(remote, Addr::Ip(a) if a.is_ipv6()) {
            c -= IPV6_ADVANTAGE.as_nanos() as i128;
        }
        c
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
        let key = |c: &Candidate<'_>| Self::key(c.data.network_path(), c.rtt, health.get(c.data.network_path()));
        let Some(best) = pool.iter().copied().min_by_key(|c| key(c)) else {
            return selection;
        };
        let primary = match current {
            Some(c) if key(best) + (RTT_SWITCH_MIN.as_nanos() as i128) > key(c) => c,
            _ => best,
        };
        selection.set(&primary.data);
        if path_debug() {
            for c in &cands {
                let h = health.get(c.data.network_path());
                eprintln!(
                    "[path] {} rtt {:?} base {:?} rate {:.0} cap {:.0} cost {:.1} ms{}",
                    PathKind::of_addr(&c.data.network_path().remote()).label(),
                    c.rtt,
                    h.map(|h| h.base_rtt),
                    h.map_or(0.0, |h| h.rate),
                    h.map_or(0.0, |h| h.capacity),
                    key(c) as f64 / 1e6,
                    if c.data.network_path() == primary.data.network_path() { " *" } else { "" }
                );
            }
        }
        let primary_path = primary.data.network_path();
        let prior = |p: &FourTuple| PathKind::of_addr(&p.remote()).prior_rate();
        let (p_base, p_rate, p_cap) = health
            .get(primary_path)
            .map_or((primary.rtt, 0.0, prior(primary_path)), |h| (h.base_rtt, h.rate, h.capacity));

        // Aggregation: more Available paths next to the selected one.
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
            let ok = h.capacity * AGG_RATE_RATIO >= p_cap
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

/// `MYCEL_PATH_DEBUG=1`: log every path's estimates at each selection.
fn path_debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("MYCEL_PATH_DEBUG").is_ok_and(|v| v == "1"))
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
    /// (Bluetooth always uses the real Bluetooth transport id.)
    pub fn new(n: u64, kind: PathKind) -> MemNet {
        crate::fine_timers();
        let id = if kind == PathKind::Bluetooth { TRANSPORT_BLUETOOTH } else { TRANSPORT_TEST_BASE + n };
        MemNet { id, kind, down: Arc::default(), inner: Arc::default(), shape: Arc::default() }
    }

    /// A radio of `kind` on its own test transport id `n` (0..16), so one
    /// device can be on several radios of the same kind (multi-hop tests).
    pub fn radio(n: u64, kind: PathKind) -> MemNet {
        MemNet { id: TRANSPORT_TEST_BASE + n, kind, down: Arc::default(), inner: Arc::default(), shape: Arc::default() }
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

    /// Undo [`MemNet::cut`]: back in range.
    pub fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
        let inner = self.inner.lock();
        for (pk, _) in &inner.started {
            for (other, tx) in &inner.started {
                if other != pk {
                    let _ = tx.send(LinkEvent::Found { peer: *pk, addr: self.addr_of(pk), name: None });
                }
            }
        }
    }

    pub fn link(&self, me: SignPk) -> Arc<MemLink> {
        let (tx, rx) = mpsc::channel(4096);
        self.inner.lock().inboxes.insert(me, tx);
        Arc::new(MemLink { net: self.clone(), me, rx: Arc::new(tokio::sync::Mutex::new(rx)) })
    }

    /// The address `pk` has on this link: the key, then the medium's code
    /// (so [`PathKind::of_custom_addr`] knows what this link pretends to be).
    pub fn addr_of(&self, pk: &SignPk) -> CustomAddr {
        let mut data = pk.0.to_vec();
        data.push(self.kind.code());
        CustomAddr::from_parts(self.id, &data)
    }

    fn parse(&self, a: &CustomAddr) -> Option<SignPk> {
        (a.id() == self.id).then(|| a.data().get(..32)?.try_into().ok().map(SignPk)).flatten()
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
            label: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medium_codes_round_trip() {
        for k in PathKind::ALL {
            assert_eq!(PathKind::from_code(k.code()), k);
        }
        assert_eq!(PathKind::from_code(200), PathKind::Other, "a newer peer's medium");
    }

    #[test]
    fn medium_of_link_addresses() {
        let iface = |k: PathKind| CustomAddr::from_parts(TRANSPORT_IFACE, &[k.code(), 1, 2, 3]);
        assert_eq!(PathKind::of_custom_addr(&iface(PathKind::Uwb)), PathKind::Uwb);
        assert_eq!(PathKind::of_custom_addr(&iface(PathKind::WifiDirect)), PathKind::WifiDirect);
        assert_eq!(PathKind::of_custom_addr(&CustomAddr::from_parts(TRANSPORT_IFACE, &[])), PathKind::Other);
        assert_eq!(PathKind::of_custom_addr(&CustomAddr::from_parts(TRANSPORT_PEER_WIFI, &[0; 32])), PathKind::PeerWifi);
        assert_eq!(PathKind::of_custom_addr(&CustomAddr::from_parts(TRANSPORT_BLUETOOTH, &[0; 32])), PathKind::Bluetooth);
        let net = MemNet::new(3, PathKind::Ieee802154);
        let pk = SignPk([7; 32]);
        assert_eq!(PathKind::of_custom_addr(&net.addr_of(&pk)), PathKind::Ieee802154);
        assert_eq!(net.parse(&net.addr_of(&pk)), Some(pk));
    }

    #[test]
    fn priors_order_media_by_what_they_carry() {
        let ms = Duration::from_millis;
        // a 64 KiB exchange: the relay beats Bluetooth even with 5x its RTT
        assert!(cost(ms(100), PathKind::Relay.prior_rate()) < cost(ms(20), PathKind::Bluetooth.prior_rate()));
        assert!(cost(ms(10), PathKind::Uwb.prior_rate()) < cost(ms(10), PathKind::Ieee802154.prior_rate()));
        // between fast paths, RTT decides
        assert!(cost(ms(2), PathKind::PeerWifi.prior_rate()) < cost(ms(9), PathKind::Ethernet.prior_rate()));
        // labels for every medium
        assert!(PathKind::ALL.iter().all(|k| !k.label().is_empty()));
    }
}
