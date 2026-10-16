//! The catch-all link: every network interface the OS exposes becomes its
//! own path, whatever hardware is behind it.
//!
//! - A UWB or other IEEE 802.15.4 radio (Linux's ieee802154 stack with
//!   6LoWPAN: `lowpan0`; OpenThread: `wpan0`), a Wi-Fi Direct group
//!   (`p2p-wlan0-0`), an 802.11s / ad-hoc mesh, a Thunderbolt or USB cable
//!   between two computers, a second NIC: if it carries IPv6 it is a path.
//! - Discovery: each interface's socket sends a beacon (node key + name) to
//!   a link-local multicast group every second and listens for others'. A
//!   beacon's source address is where that peer's QUIC packets go.
//! - Paths: one UDP socket per interface, bound to its IPv6 link-local
//!   address, so packets leave by that interface and no other. Iroh sees each
//!   (interface, peer) as its own custom address, so QUIC multipath measures,
//!   aggregates and fails over between interfaces like any other paths, and
//!   a mesh can hop over them. The address carries the medium
//!   ([`mycel_net::PathKind`]), which the node and the UI read.
//! - Interfaces come and go (netlink / routing socket, plus a rescan every
//!   10 s); which ones count and as what is decided in [`classify`].
//!
//! On Linux it can also *make* Wi-Fi Direct links ([`Options::wifi_direct`],
//! the `wifi_direct` module): it finds Mycel devices over Wi-Fi P2P through
//! wpa_supplicant and forms groups with them, whose `p2p-*` interfaces then
//! become paths like any other.
//!
//! Interfaces that Iroh's own IP transport already reaches peers through (a
//! routable address on an ordinary NIC) are left to it, so a Wi-Fi radio
//! isn't driven twice; with only link-local addresses (a cable between two
//! Macs) they are this link's. [`Rules::ip_covers_routable`] = false hands it
//! every NIC (tests, or a node with no IP transport that wants them).

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use mycel_crypto::SignPk;
use mycel_net::PathKind;
use mycel_net::link::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use mycel_net::link::{CustomAddr, Link, LinkEvent, LinkStatus, n0_watcher, noq_udp};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub mod classify;
pub mod ifaces;
mod watch;
#[cfg(target_os = "linux")]
pub mod wifi_direct;
pub mod wire;

use classify::{Decision, IfaceInfo, Rules};
use wire::{Beacon, IfaceAddr};

/// Beacons go out this often on every interface.
pub const BEACON_EVERY: Duration = Duration::from_secs(1);
/// A peer not heard from for this long on an interface is gone from it.
pub const PEER_TIMEOUT: Duration = Duration::from_secs(5);
/// Re-enumerate interfaces at least this often (change notifications do it
/// sooner).
pub const RESCAN_EVERY: Duration = Duration::from_secs(10);
/// Inbound packets waiting for Iroh. Full = dropped (QUIC recovers).
const INBOUND_QUEUE: usize = 1024;

/// What this link drives.
#[derive(Clone, Debug)]
pub struct Options {
    /// Which interfaces count, and as what (see [`classify::classify`]).
    pub rules: Rules,
    /// Discovery's multicast group and port (tests pick their own so they
    /// don't see each other).
    pub group: Ipv6Addr,
    pub port: u16,
    /// Linux: form Wi-Fi Direct groups with nearby Mycel devices (through
    /// wpa_supplicant). Off unless asked for: it takes over the Wi-Fi
    /// radio's P2P side and hasn't been tried on real hardware yet.
    pub wifi_direct: bool,
}

impl Options {
    /// The defaults, plus `MYCEL_IFACES` / `MYCEL_IFACE_MEDIUM` from the
    /// environment. `ip`: Iroh's IP transport is on.
    pub fn new(ip: bool) -> Options {
        Options { rules: Rules::from_env(ip), group: wire::GROUP, port: wire::DISCOVERY_PORT, wifi_direct: false }
    }
}

/// The interface link for node `me`, advertising `name`. `ip`: whether the
/// node also uses Iroh's IP transport (then ordinary NICs are left to it).
pub fn link(me: SignPk, name: &str, ip: bool) -> Arc<dyn Link> {
    IfaceLink::new(me, name, Options::new(ip))
}

/// Like [`link`], with Wi-Fi Direct group forming on (Linux).
pub fn link_with_wifi_direct(me: SignPk, name: &str, ip: bool) -> Arc<dyn Link> {
    IfaceLink::new(me, name, Options { wifi_direct: true, ..Options::new(ip) })
}

#[derive(Debug)]
struct Packet {
    data: Bytes,
    from: CustomAddr,
    local: CustomAddr,
}

/// An interface we have a socket on.
struct Active {
    info: IfaceInfo,
    kind: PathKind,
    label: String,
    sock: Arc<UdpSocket>,
    local: IfaceAddr,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Active {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

struct Shared {
    me: SignPk,
    name: Mutex<String>,
    opts: Options,
    /// By interface index.
    active: Mutex<BTreeMap<u32, Active>>,
    /// The last enumeration, and what was decided for each interface.
    seen: Mutex<Vec<(IfaceInfo, Decision)>>,
    /// Peers heard on each interface: (interface, key) → (address, last beacon).
    peers: Mutex<HashMap<(u32, SignPk), (IfaceAddr, Instant)>>,
    events: Mutex<Option<mpsc::UnboundedSender<LinkEvent>>>,
    inbound: mpsc::Sender<Packet>,
    problem: Mutex<Option<String>>,
    stopped: AtomicBool,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Wi-Fi Direct group forming: what it is doing, and its task.
    wd_status: Arc<Mutex<Option<String>>>,
    wd_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub struct IfaceLink {
    shared: Arc<Shared>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl IfaceLink {
    pub fn new(me: SignPk, name: &str, opts: Options) -> Arc<IfaceLink> {
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        Arc::new(IfaceLink {
            shared: Arc::new(Shared {
                me,
                name: Mutex::new(name.to_string()),
                opts,
                active: Mutex::default(),
                seen: Mutex::default(),
                peers: Mutex::default(),
                events: Mutex::new(None),
                inbound: tx,
                problem: Mutex::new(None),
                stopped: AtomicBool::new(false),
                task: Mutex::new(None),
                wd_status: Arc::default(),
                wd_task: Mutex::new(None),
            }),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        })
    }

    /// Every interface from the last scan and what was decided for it.
    pub fn interfaces(&self) -> Vec<(IfaceInfo, Decision)> {
        self.shared.seen.lock().clone()
    }

    /// The interfaces in use: name, medium and our socket address on it.
    pub fn in_use(&self) -> Vec<(String, PathKind, SocketAddrV6)> {
        self.shared.active.lock().values().map(|a| (a.info.name.clone(), a.kind, a.local.socket())).collect()
    }

    /// Peers heard so far: key, medium, interface name.
    pub fn peers(&self) -> Vec<(SignPk, PathKind, String)> {
        let active = self.shared.active.lock();
        self.shared
            .peers
            .lock()
            .iter()
            .map(|((idx, k), (a, _))| {
                (*k, a.kind, active.get(idx).map_or_else(|| idx.to_string(), |x| x.info.name.clone()))
            })
            .collect()
    }
}

impl Link for IfaceLink {
    fn kind(&self) -> PathKind {
        PathKind::Other
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(IfaceTransport { shared: self.shared.clone(), rx: self.rx.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        *self.shared.events.lock() = Some(events);
        let rt = tokio::runtime::Handle::try_current().context("the interface link needs a Tokio runtime")?;
        let disco = discovery_socket(&self.shared.opts).context("can't listen for interface beacons")?;
        let shared = self.shared.clone();
        let task = rt.spawn(async move {
            let disco = match UdpSocket::from_std(disco) {
                Ok(s) => s,
                Err(e) => {
                    *shared.problem.lock() = Some(format!("Can't listen for nearby devices: {e}"));
                    return;
                }
            };
            run(shared, disco).await
        });
        *self.shared.task.lock() = Some(task);
        #[cfg(target_os = "linux")]
        if self.shared.opts.wifi_direct {
            let wd = rt.spawn(wifi_direct::run(self.shared.me, self.shared.wd_status.clone()));
            *self.shared.wd_task.lock() = Some(wd);
        }
        Ok(())
    }

    fn set_name(&self, name: &str) {
        *self.shared.name.lock() = name.to_string();
    }

    /// All media together (the node shows [`Link::statuses`]).
    fn status(&self) -> LinkStatus {
        let peers = self.shared.peers.lock().keys().map(|(_, k)| *k).collect::<std::collections::HashSet<_>>().len();
        let active = self.shared.active.lock();
        LinkStatus {
            kind: PathKind::Other,
            label: Some(active.values().map(|a| a.label.clone()).collect::<Vec<_>>().join(", ")),
            active: !active.is_empty(),
            detail: self.shared.problem.lock().clone(),
            peers,
        }
    }

    /// One row per medium in use: "UWB (lowpan0)", "Wi-Fi Direct (p2p-wlan0-0)".
    fn statuses(&self) -> Vec<LinkStatus> {
        let active = self.shared.active.lock();
        let peers = self.shared.peers.lock();
        let problem = self.shared.problem.lock().clone();
        let mut by_kind: BTreeMap<PathKind, (Vec<String>, std::collections::HashSet<SignPk>)> = BTreeMap::new();
        for (idx, a) in active.iter() {
            let e = by_kind.entry(a.kind).or_default();
            e.0.push(a.info.name.clone());
            e.1.extend(peers.keys().filter(|(i, _)| i == idx).map(|(_, k)| *k));
        }
        let mut out: Vec<LinkStatus> = by_kind
            .into_iter()
            .map(|(kind, (names, keys))| LinkStatus {
                kind,
                label: Some(names.join(", ")),
                active: true,
                detail: None,
                peers: keys.len(),
            })
            .collect();
        // Wi-Fi Direct still looking (or broken): say so until a group is up
        if !out.iter().any(|s| s.kind == PathKind::WifiDirect)
            && let Some(wd) = self.shared.wd_status.lock().clone()
        {
            let broken = wd.contains("unavailable");
            out.push(LinkStatus {
                kind: PathKind::WifiDirect,
                label: None,
                active: !broken,
                detail: Some(wd),
                peers: 0,
            });
        }
        if out.is_empty()
            && let Some(p) = problem
        {
            out.push(LinkStatus { kind: PathKind::Other, label: None, active: false, detail: Some(p), peers: 0 });
        }
        out
    }

    fn stop(&self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        for t in [self.shared.task.lock().take(), self.shared.wd_task.lock().take()].into_iter().flatten() {
            t.abort();
        }
        self.shared.active.lock().clear();
        *self.shared.events.lock() = None;
    }
}

impl Shared {
    fn emit(&self, ev: LinkEvent) {
        if let Some(tx) = &*self.events.lock() {
            let _ = tx.send(ev);
        }
    }

    /// Re-enumerate: open sockets on new interfaces, drop vanished ones (and
    /// the peers heard on them).
    fn rescan(self: &Arc<Self>, disco: &UdpSocket) {
        let now: Vec<(IfaceInfo, Decision)> = ifaces::list()
            .into_iter()
            .map(|i| {
                let d = classify::classify(&i, &self.opts.rules);
                (i, d)
            })
            .collect();
        let want: BTreeMap<u32, (IfaceInfo, PathKind, String)> = now
            .iter()
            .filter_map(|(i, d)| match d {
                Decision::Use { kind, label } => Some((i.index, (i.clone(), *kind, label.clone()))),
                Decision::Skip(_) => None,
            })
            .collect();
        *self.seen.lock() = now;
        let mut active = self.active.lock();
        let gone: Vec<u32> = active
            .iter()
            .filter(|(idx, a)| want.get(idx).is_none_or(|(i, k, _)| *i != a.info || *k != a.kind))
            .map(|(idx, _)| *idx)
            .collect();
        for idx in gone {
            if let Some(a) = active.remove(&idx) {
                log(format_args!("stopped using {} ({})", a.info.name, a.kind.label()));
                let _ = leave_group(disco, &self.opts.group, idx);
            }
            let lost: Vec<(SignPk, IfaceAddr)> = {
                let mut peers = self.peers.lock();
                let keys: Vec<(u32, SignPk)> = peers.keys().filter(|(i, _)| *i == idx).copied().collect();
                keys.into_iter().filter_map(|k| peers.remove(&k).map(|(a, _)| (k.1, a))).collect()
            };
            for (peer, addr) in lost {
                self.emit(LinkEvent::Lost { peer, addr: addr.to_custom() });
            }
        }
        for (idx, (info, kind, label)) in want {
            if active.contains_key(&idx) {
                continue;
            }
            match self.open(&info, kind) {
                Ok((sock, local)) => {
                    if let Err(e) = join_group(disco, &self.opts.group, idx) {
                        log(format_args!("{}: can't join the discovery group: {e}", info.name));
                    }
                    let reader = tokio::spawn(read_packets(self.clone(), sock.clone(), local));
                    log(format_args!("using {label} at {}", local.socket()));
                    active.insert(idx, Active { info, kind, label, sock, local, reader });
                }
                Err(e) => log(format_args!("{}: can't open a socket: {e}", info.name)),
            }
        }
    }

    /// A UDP socket on the interface's link-local address.
    fn open(&self, info: &IfaceInfo, kind: PathKind) -> io::Result<(Arc<UdpSocket>, IfaceAddr)> {
        let ip = info.link_local.ok_or_else(|| io::Error::other("no link-local address"))?;
        let scope = if ip.is_unicast_link_local() { info.index } else { 0 };
        let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_only_v6(true)?;
        s.set_nonblocking(true)?;
        bind_to_interface(&s, info)?;
        s.bind(&SockAddr::from(SocketAddrV6::new(ip, 0, 0, scope)))?;
        s.set_multicast_if_v6(info.index)?;
        s.set_multicast_loop_v6(true)?;
        let _ = s.set_recv_buffer_size(1 << 20);
        let _ = s.set_send_buffer_size(1 << 20);
        let port = match s.local_addr()?.as_socket() {
            Some(SocketAddr::V6(a)) => a.port(),
            _ => return Err(io::Error::other("not an IPv6 socket")),
        };
        let sock = UdpSocket::from_std(s.into())?;
        Ok((Arc::new(sock), IfaceAddr { kind, index: info.index, ip, port }))
    }

    /// Send a beacon on every interface; forget peers that went quiet.
    fn beacon(&self) {
        let b = Beacon { key: self.me, name: self.name.lock().clone() }.encode();
        for a in self.active.lock().values() {
            let to = SocketAddrV6::new(self.opts.group, self.opts.port, 0, a.info.index);
            let _ = a.sock.try_send_to(&b, to.into());
        }
        let now = Instant::now();
        let quiet: Vec<(SignPk, IfaceAddr)> = {
            let mut peers = self.peers.lock();
            let keys: Vec<(u32, SignPk)> =
                peers.iter().filter(|(_, (_, t))| now.duration_since(*t) > PEER_TIMEOUT).map(|(k, _)| *k).collect();
            keys.into_iter().filter_map(|k| peers.remove(&k).map(|(a, _)| (k.1, a))).collect()
        };
        for (peer, addr) in quiet {
            log(format_args!("lost {} on interface {}", short(&peer), addr.index));
            self.emit(LinkEvent::Lost { peer, addr: addr.to_custom() });
        }
    }

    /// A beacon arrived from `from` (its scope is the interface it came in on).
    fn on_beacon(&self, data: &[u8], from: SocketAddrV6) {
        let Some(b) = Beacon::decode(data) else { return };
        if b.key == self.me {
            return;
        }
        let index = match from.scope_id() {
            0 => match self.only_active() {
                Some(i) => i,
                None => return,
            },
            i => i,
        };
        let Some(kind) = self.active.lock().get(&index).map(|a| a.kind) else { return };
        let addr = IfaceAddr { kind, index, ip: *from.ip(), port: from.port() };
        let fresh = {
            let mut peers = self.peers.lock();
            let prev = peers.insert((index, b.key), (addr, Instant::now()));
            prev.map(|(a, _)| a) != Some(addr)
        };
        if fresh {
            log(format_args!("found {} \"{}\" on {} at {}", short(&b.key), b.name, kind.label(), addr.socket()));
            self.emit(LinkEvent::Found {
                peer: b.key,
                addr: addr.to_custom(),
                name: (!b.name.is_empty()).then_some(b.name),
            });
        }
    }

    /// The one interface in use, if there is exactly one.
    fn only_active(&self) -> Option<u32> {
        let a = self.active.lock();
        (a.len() == 1).then(|| *a.keys().next().expect("one"))
    }
}

/// Discovery, beacons, rescans.
async fn run(shared: Arc<Shared>, disco: UdpSocket) {
    let watcher = watch::Watcher::new().map_err(|e| log(format_args!("no interface change notifications: {e}"))).ok();
    shared.rescan(&disco);
    let mut beacon = tokio::time::interval(BEACON_EVERY);
    let mut rescan = tokio::time::interval(RESCAN_EVERY);
    rescan.reset();
    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = beacon.tick() => shared.beacon(),
            _ = rescan.tick() => shared.rescan(&disco),
            r = async { match &watcher { Some(w) => w.changed().await, None => std::future::pending().await } } => {
                if r.is_ok() {
                    // let the OS finish assigning addresses
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    shared.rescan(&disco);
                }
            }
            r = disco.recv_from(&mut buf) => match r {
                Ok((n, SocketAddr::V6(from))) => shared.on_beacon(&buf[..n], from),
                Ok(_) => {}
                Err(e) => {
                    log(format_args!("discovery socket: {e}"));
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
        }
        if shared.stopped.load(Ordering::SeqCst) {
            return;
        }
    }
}

/// QUIC packets from one interface's socket, to Iroh.
async fn read_packets(shared: Arc<Shared>, sock: Arc<UdpSocket>, local: IfaceAddr) {
    let mut buf = vec![0u8; 65_536];
    let local_addr = local.to_custom();
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, SocketAddr::V6(from))) => {
                let from = IfaceAddr { kind: local.kind, index: local.index, ip: *from.ip(), port: from.port() };
                let p = Packet {
                    data: Bytes::copy_from_slice(&buf[..n]),
                    from: from.to_custom(),
                    local: local_addr.clone(),
                };
                let _ = shared.inbound.try_send(p);
            }
            Ok(_) => {}
            // the interface went away; the next rescan drops this reader
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// The discovery socket: the group's port on every interface, shared with
/// other nodes on this machine.
fn discovery_socket(opts: &Options) -> io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SockAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, opts.port, 0, 0)))?;
    Ok(s.into())
}

fn join_group(disco: &UdpSocket, group: &Ipv6Addr, index: u32) -> io::Result<()> {
    match disco.join_multicast_v6(group, index) {
        // already joined (an interface that came back)
        Err(e) if e.raw_os_error() == Some(libc_eaddrinuse()) => Ok(()),
        r => r,
    }
}

fn leave_group(disco: &UdpSocket, group: &Ipv6Addr, index: u32) -> io::Result<()> {
    disco.leave_multicast_v6(group, index)
}

#[cfg(unix)]
fn libc_eaddrinuse() -> i32 {
    libc::EADDRINUSE
}

#[cfg(not(unix))]
fn libc_eaddrinuse() -> i32 {
    -1
}

/// Packets leave by this interface only (macOS: `IPV6_BOUND_IF`). On Linux
/// binding to the scoped link-local address does the same without the
/// privilege `SO_BINDTODEVICE` needs on older kernels.
fn bind_to_interface(s: &Socket, info: &IfaceInfo) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    s.bind_device_by_index_v6(std::num::NonZeroU32::new(info.index))?;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = (s, info);
    Ok(())
}

// ───────────────────────────── Iroh transport ─────────────────────────────

struct IfaceTransport {
    shared: Arc<Shared>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for IfaceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IfaceTransport")
    }
}

impl CustomTransport for IfaceTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.rx.clone().try_lock_owned().map_err(|_| io::Error::other("interface link already bound"))?;
        // Our addresses mean nothing elsewhere (they hold our interface
        // index): peers learn theirs from beacons, so none are published.
        Ok(Box::new(IfaceEndpoint { shared: self.shared.clone(), addrs: n0_watcher::Watchable::new(Vec::new()), rx }))
    }
}

struct IfaceEndpoint {
    shared: Arc<Shared>,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<Packet>>,
}

impl std::fmt::Debug for IfaceEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IfaceEndpoint")
    }
}

impl CustomEndpoint for IfaceEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(IfaceSender { shared: self.shared.clone() })
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
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("interface link closed"))),
            Poll::Ready(_) => {}
        }
        let mut count = 0;
        for p in packets {
            if bufs[count].len() < p.data.len() {
                continue;
            }
            bufs[count][..p.data.len()].copy_from_slice(&p.data);
            metas[count].len = p.data.len();
            metas[count].stride = p.data.len();
            recv_infos[count] = RecvInfo::new(p.from, Some(p.local));
            count += 1;
        }
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }
}

struct IfaceSender {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for IfaceSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IfaceSender")
    }
}

impl CustomSender for IfaceSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        IfaceAddr::from_custom(addr).is_some_and(|a| self.shared.active.lock().contains_key(&a.index))
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(to) = IfaceAddr::from_custom(dst) else {
            return Poll::Ready(Err(io::Error::other("not an interface address")));
        };
        let Some(sock) = self.shared.active.lock().get(&to.index).map(|a| a.sock.clone()) else {
            return Poll::Ready(Err(io::Error::other("interface gone")));
        };
        let dest = SocketAddr::V6(to.socket());
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for chunk in transmit.contents.chunks(seg) {
            // A full socket buffer or an oversized probe is a lost packet,
            // like on a busy radio: QUIC recovers.
            let _ = sock.try_send_to(chunk, dest);
        }
        Poll::Ready(Ok(()))
    }
}

// ───────────────────────────── logging ─────────────────────────────

/// `MYCEL_IFACE_LOG=1`: log interfaces taken or dropped and peers found.
fn log(args: std::fmt::Arguments) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ON.get_or_init(|| std::env::var("MYCEL_IFACE_LOG").is_ok_and(|v| v == "1")) {
        eprintln!("[iface] {args}");
    }
}

fn short(k: &SignPk) -> String {
    k.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}
