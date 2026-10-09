//! Emulated networks for simulations: real Mycel nodes over modelled radios
//! and wires, with positions, range, rate, delay, jitter, loss, half-duplex
//! airtime and devices coming and going.
//!
//! [`MemNet`](crate::link::MemNet) is one ideal "edge" everyone on it can
//! reach; an [`EmuNet`] is a *medium* (Bluetooth, peer-to-peer Wi-Fi, an
//! access point's LAN, the internet...) shared by many devices, each at a
//! position. Two devices hear each other on a radio medium when they're
//! within its range; a wired or internet medium reaches everyone attached
//! (optionally filtered, e.g. NAT). Packets are delayed by the time the
//! radio is busy (airtime at the medium's rate), the propagation or base
//! latency, and jitter, and lost at random or when the transmit queue is
//! full, like a congested radio.
//!
//! Order: jitter delays packets but never reorders a pair's packets (a radio
//! link is FIFO; reordering would read as loss to QUIC).
//!
//! Airtime model: a node's radio sends one packet at a time
//! (`busy_until`). On a half-duplex medium the receiver's radio is busy for
//! the same airtime, and on a `shared_channel` medium every device in range
//! of the sender is too (they hear it and must stay quiet: one collision
//! domain, roughly CSMA/CA). This reproduces the classic multi-hop result
//! that a chain of relays on one channel carries about a third of the
//! single-hop rate. Not modelled: collisions, hidden terminals, rate
//! adaptation, fading (loss is i.i.d.).
//!
//! Discovery: a *discoverable* medium reports neighbours to each node's
//! link (`LinkEvent::Found`/`Lost`), as Bluetooth, AWDL or mDNS do. The
//! internet isn't discoverable: nobody learns every device on the internet,
//! so its addresses are handed to nodes for their contacts
//! ([`EmuNet::addr_of`] + `Node::add_peer_addr`), as address lookup would.
//!
//! Positions are metres on a plane for radios. For a [`Latency::Geo`] medium
//! they are (latitude, longitude) in degrees, and the one-way delay is the
//! great-circle distance over fibre with path inflation.
//!
//! Time comes from `tokio::time`, so these networks also run under paused
//! (virtual) time.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::link::{CustomAddr, Link, LinkEvent, LinkStatus, PathKind, TRANSPORT_TEST_BASE, n0_watcher, noq_udp};

/// A position: metres (x, y) on a radio medium, or (lat, lon) degrees on a
/// [`Latency::Geo`] medium.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pos {
    pub x: f64,
    pub y: f64,
}

impl Pos {
    pub const fn new(x: f64, y: f64) -> Pos {
        Pos { x, y }
    }

    pub fn dist(&self, o: &Pos) -> f64 {
        ((self.x - o.x).powi(2) + (self.y - o.y).powi(2)).sqrt()
    }

    /// Great-circle distance in km between two (lat, lon) positions.
    pub fn km(&self, o: &Pos) -> f64 {
        let (la1, lo1, la2, lo2) = (self.x.to_radians(), self.y.to_radians(), o.x.to_radians(), o.y.to_radians());
        let h = ((la2 - la1) / 2.0).sin().powi(2) + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
        2.0 * 6371.0 * h.sqrt().asin()
    }
}

/// How long a packet takes to propagate, on top of airtime and jitter.
#[derive(Clone, Copy, Debug)]
pub enum Latency {
    Fixed(Duration),
    /// Positions are (lat, lon): `base` plus great-circle km × `us_per_km` ×
    /// `inflation` (fibre: ~5 µs/km; real routes ~1.5× the great circle).
    Geo { base: Duration, us_per_km: f64, inflation: f64 },
}

/// The physics of one medium.
#[derive(Clone, Debug)]
pub struct Medium {
    pub kind: PathKind,
    /// Display label (e.g. "802.11s mesh").
    pub label: &'static str,
    /// Bytes per second one radio sends at (PHY goodput), `None` = unlimited.
    pub rate: Option<u64>,
    pub latency: Latency,
    /// Extra uniform random delay, 0..jitter.
    pub jitter: Duration,
    /// Independent loss probability per packet.
    pub loss: f64,
    /// Radio range in metres; `f64::INFINITY` for wires and the internet.
    pub range: f64,
    /// The receiver's radio is busy while a packet arrives.
    pub half_duplex: bool,
    /// Everyone in range of a sender is busy while it sends.
    pub shared_channel: bool,
    /// A transmit queue longer than this drops packets.
    pub max_queue: Duration,
    /// Reports neighbours to the nodes' links (radios, LAN discovery).
    pub discoverable: bool,
}

impl Medium {
    /// An ideal medium of `kind`: no limits at all.
    pub fn ideal(kind: PathKind) -> Medium {
        Medium {
            kind,
            label: kind.label(),
            rate: None,
            latency: Latency::Fixed(Duration::ZERO),
            jitter: Duration::ZERO,
            loss: 0.0,
            range: f64::INFINITY,
            half_duplex: false,
            shared_channel: false,
            max_queue: Duration::from_millis(250),
            discoverable: true,
        }
    }
}

/// Counters for one medium.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmuStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_delivered: u64,
    pub dropped_range: u64,
    pub dropped_loss: u64,
    pub dropped_queue: u64,
    pub dropped_down: u64,
}

#[derive(Default)]
struct Counters {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_delivered: AtomicU64,
    dropped_range: AtomicU64,
    dropped_loss: AtomicU64,
    dropped_queue: AtomicU64,
    dropped_down: AtomicU64,
}

fn bump(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

#[derive(Debug)]
struct Packet {
    data: Bytes,
    from: CustomAddr,
}

struct Member {
    pos: Pos,
    up: bool,
    inbox: mpsc::Sender<Packet>,
    events: Option<mpsc::UnboundedSender<LinkEvent>>,
    /// Neighbours last reported to this member's link.
    told: HashSet<SignPk>,
    /// When this member's radio is free again.
    busy_until: Option<Instant>,
}

/// How one pair of devices fares on a medium, beyond range and the
/// medium's own physics: e.g. NAT rules (`None` = can't reach), access
/// latency (cellular, Wi-Fi to the router), or an 802.11s mesh that is
/// several Wi-Fi hops long (slower and later the more hops).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairShape {
    /// Added one-way delay.
    pub latency: Duration,
    /// Airtime is multiplied by this (2.0 = half the rate).
    pub rate_div: f64,
}

impl Default for PairShape {
    fn default() -> Self {
        PairShape { latency: Duration::ZERO, rate_div: 1.0 }
    }
}

/// Per-pair rules for a medium: `None` = these two can't reach each other.
pub type PairFn = Arc<dyn Fn(&SignPk, &SignPk) -> Option<PairShape> + Send + Sync>;

struct State {
    members: HashMap<SignPk, Member>,
    pair: Option<PairFn>,
    rng: u64,
    up: bool,
    /// When the last packet from a to b arrives: links are FIFO, so jitter
    /// delays packets but never reorders them.
    fifo: HashMap<(SignPk, SignPk), Instant>,
    /// One in-order delivery queue per (from, to).
    queues: HashMap<(SignPk, SignPk), mpsc::UnboundedSender<(Instant, Packet)>>,
}

impl State {
    fn rand(&mut self) -> f64 {
        // xorshift64*: fast, seeded, good enough for loss and jitter
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn hears(&self, medium: &Medium, a: &SignPk, b: &SignPk) -> bool {
        if a == b || !self.up {
            return false;
        }
        let (Some(ma), Some(mb)) = (self.members.get(a), self.members.get(b)) else { return false };
        if !ma.up || !mb.up {
            return false;
        }
        let in_range = match medium.latency {
            Latency::Geo { .. } => true,
            Latency::Fixed(_) => medium.range.is_infinite() || ma.pos.dist(&mb.pos) <= medium.range,
        };
        in_range && self.pair.as_ref().is_none_or(|f| f(a, b).is_some())
    }

    fn shape(&self, a: &SignPk, b: &SignPk) -> PairShape {
        self.pair.as_ref().and_then(|f| f(a, b)).unwrap_or_default()
    }
}

/// A shared medium. Clones share state.
#[derive(Clone)]
pub struct EmuNet {
    id: u64,
    medium: Arc<Medium>,
    st: Arc<Mutex<State>>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for EmuNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmuNet({}, {:x})", self.medium.label, self.id)
    }
}

impl EmuNet {
    /// `n` (0..16, distinct per world, shared with `MemNet` ids) picks the
    /// transport id; `seed` the loss and jitter sequence.
    pub fn new(n: u64, medium: Medium, seed: u64) -> EmuNet {
        assert!(n < 16, "transport slot");
        EmuNet {
            id: TRANSPORT_TEST_BASE + n,
            medium: Arc::new(medium),
            st: Arc::new(Mutex::new(State { members: HashMap::new(), pair: None, rng: seed | 1, up: true, fifo: HashMap::new(), queues: HashMap::new() })),
            counters: Arc::default(),
        }
    }

    pub fn medium(&self) -> &Medium {
        &self.medium
    }

    /// Attach a device at `pos`.
    pub fn link(&self, me: SignPk, pos: Pos) -> Arc<EmuLink> {
        let (tx, rx) = mpsc::channel(4096);
        self.st.lock().members.insert(
            me,
            Member { pos, up: true, inbox: tx, events: None, told: HashSet::new(), busy_until: None },
        );
        Arc::new(EmuLink { net: self.clone(), me, rx: Arc::new(tokio::sync::Mutex::new(rx)) })
    }

    /// Per-pair rules: who reaches whom (e.g. two symmetric NATs can't),
    /// and at what extra delay and rate.
    pub fn set_pair(&self, f: Option<PairFn>) {
        self.st.lock().pair = f;
        self.refresh();
    }

    /// Move a device; call [`EmuNet::refresh`] (once, after moving many).
    pub fn set_pos(&self, pk: &SignPk, pos: Pos) {
        if let Some(m) = self.st.lock().members.get_mut(pk) {
            m.pos = pos;
        }
    }

    pub fn pos(&self, pk: &SignPk) -> Option<Pos> {
        self.st.lock().members.get(pk).map(|m| m.pos)
    }

    /// Turn one device's radio on this medium on or off.
    pub fn set_up(&self, pk: &SignPk, up: bool) {
        if let Some(m) = self.st.lock().members.get_mut(pk) {
            m.up = up;
        }
        self.refresh();
    }

    /// The whole medium on or off (an outage).
    pub fn set_medium_up(&self, up: bool) {
        self.st.lock().up = up;
        self.refresh();
    }

    /// Re-evaluate who hears whom and tell the links what changed.
    pub fn refresh(&self) {
        if !self.medium.discoverable {
            return;
        }
        let mut st = self.st.lock();
        let keys: Vec<SignPk> = st.members.keys().copied().collect();
        let mut changes: Vec<(SignPk, Vec<SignPk>, Vec<SignPk>)> = Vec::new();
        for a in &keys {
            if st.members[a].events.is_none() {
                continue;
            }
            let now: HashSet<SignPk> = keys.iter().filter(|b| st.hears(&self.medium, a, b)).copied().collect();
            let told = &st.members[a].told;
            let found: Vec<SignPk> = now.difference(told).copied().collect();
            let lost: Vec<SignPk> = told.difference(&now).copied().collect();
            if !found.is_empty() || !lost.is_empty() {
                changes.push((*a, found, lost));
            }
        }
        for (a, found, lost) in changes {
            let m = st.members.get_mut(&a).expect("member");
            let Some(ev) = m.events.clone() else { continue };
            for b in found {
                m.told.insert(b);
                let _ = ev.send(LinkEvent::Found { peer: b, addr: self.addr_of(&b), name: None });
            }
            for b in lost {
                m.told.remove(&b);
                let _ = ev.send(LinkEvent::Lost { peer: b, addr: self.addr_of(&b) });
            }
        }
    }

    /// The per-pair rules' extra delay and rate divisor for `a` → `b`.
    pub fn pair_shape(&self, a: &SignPk, b: &SignPk) -> PairShape {
        self.st.lock().shape(a, b)
    }

    /// Who `pk` hears now.
    pub fn neighbours(&self, pk: &SignPk) -> Vec<SignPk> {
        let st = self.st.lock();
        st.members.keys().filter(|b| st.hears(&self.medium, pk, b)).copied().collect()
    }

    /// `pk`'s address on this medium (its key, then the medium's code).
    pub fn addr_of(&self, pk: &SignPk) -> CustomAddr {
        let mut data = pk.0.to_vec();
        data.push(self.medium.kind.code());
        CustomAddr::from_parts(self.id, &data)
    }

    fn parse(&self, a: &CustomAddr) -> Option<SignPk> {
        (a.id() == self.id).then(|| a.data().get(..32)?.try_into().ok().map(SignPk)).flatten()
    }

    pub fn stats(&self) -> EmuStats {
        let c = &self.counters;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        EmuStats {
            packets_sent: l(&c.packets_sent),
            bytes_sent: l(&c.bytes_sent),
            packets_delivered: l(&c.packets_delivered),
            dropped_range: l(&c.dropped_range),
            dropped_loss: l(&c.dropped_loss),
            dropped_queue: l(&c.dropped_queue),
            dropped_down: l(&c.dropped_down),
        }
    }

    /// Decide one packet's fate: where it goes and when it arrives.
    fn schedule(&self, from: &SignPk, to: &SignPk, len: usize) -> Option<(mpsc::Sender<Packet>, Duration)> {
        let m = &self.medium;
        let c = &self.counters;
        bump(&c.packets_sent, 1);
        bump(&c.bytes_sent, len as u64);
        let mut st = self.st.lock();
        if !st.up || !st.members.get(from).is_some_and(|x| x.up) || !st.members.get(to).is_some_and(|x| x.up) {
            bump(&c.dropped_down, 1);
            return None;
        }
        if !st.hears(m, from, to) {
            bump(&c.dropped_range, 1);
            return None;
        }
        let now = Instant::now();
        let shape = st.shape(from, to);
        let airtime = m.rate.map_or(Duration::ZERO, |r| Duration::from_secs_f64(len as f64 * shape.rate_div / r as f64));
        let mut start = now;
        if m.rate.is_some() {
            let busy = |k: &SignPk, st: &State| st.members.get(k).and_then(|x| x.busy_until).filter(|b| *b > now);
            if let Some(b) = busy(from, &st) {
                start = start.max(b);
            }
            if m.half_duplex
                && let Some(b) = busy(to, &st)
            {
                start = start.max(b);
            }
            if start - now > m.max_queue {
                bump(&c.dropped_queue, 1);
                return None;
            }
            let done = start + airtime;
            let mut occupied: Vec<SignPk> = vec![*from];
            if m.half_duplex {
                occupied.push(*to);
            }
            if m.shared_channel {
                let src = st.members[from].pos;
                occupied.extend(
                    st.members
                        .iter()
                        .filter(|(k, x)| *k != from && x.up && x.pos.dist(&src) <= m.range)
                        .map(|(k, _)| *k),
                );
            }
            for k in occupied {
                if let Some(x) = st.members.get_mut(&k) {
                    x.busy_until = Some(x.busy_until.map_or(done, |b| b.max(done)));
                }
            }
        }
        if m.loss > 0.0 && st.rand() < m.loss {
            bump(&c.dropped_loss, 1);
            return None;
        }
        let prop = match m.latency {
            Latency::Fixed(d) => d,
            Latency::Geo { base, us_per_km, inflation } => {
                let km = st.members[from].pos.km(&st.members[to].pos);
                base + Duration::from_secs_f64(km * us_per_km * inflation / 1e6)
            }
        };
        let jitter = if m.jitter.is_zero() { Duration::ZERO } else { m.jitter.mul_f64(st.rand()) };
        let inbox = st.members[to].inbox.clone();
        let mut arrive = start + airtime + prop + shape.latency + jitter;
        let last = st.fifo.entry((*from, *to)).or_insert(arrive);
        if *last > arrive {
            arrive = *last;
        }
        *last = arrive;
        Some((inbox, arrive - now))
    }

    fn deliver(&self, from: SignPk, to: SignPk, data: Bytes) {
        let Some((inbox, delay)) = self.schedule(&from, &to, data.len()) else { return };
        let packet = Packet { data, from: self.addr_of(&from) };
        if delay.is_zero() {
            if inbox.try_send(packet).is_ok() {
                bump(&self.counters.packets_delivered, 1);
            }
            return;
        }
        let at = Instant::now() + delay;
        let tx = {
            let mut st = self.st.lock();
            if let Some(tx) = st.queues.get(&(from, to)).filter(|t| !t.is_closed()) {
                tx.clone()
            } else {
                let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
                let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Packet)>();
                let net = self.clone();
                rt.spawn(async move {
                    // in order: each packet waits for its own arrival time
                    while let Some((at, packet)) = rx.recv().await {
                        tokio::time::sleep_until(at).await;
                        let ok = net.st.lock().hears(&net.medium, &from, &to);
                        if ok && inbox.try_send(packet).is_ok() {
                            bump(&net.counters.packets_delivered, 1);
                        } else {
                            bump(&net.counters.dropped_range, 1);
                        }
                    }
                });
                st.queues.insert((from, to), tx.clone());
                tx
            }
        };
        let _ = tx.send((at, packet));
    }
}

/// One device's attachment to an [`EmuNet`].
pub struct EmuLink {
    net: EmuNet,
    me: SignPk,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for EmuLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmuLink({})", self.net.medium.label)
    }
}

impl EmuLink {
    pub fn net(&self) -> &EmuNet {
        &self.net
    }
}

impl Link for EmuLink {
    fn kind(&self) -> PathKind {
        self.net.medium.kind
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(EmuTransport { net: self.net.clone(), me: self.me, rx: self.rx.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        if let Some(m) = self.net.st.lock().members.get_mut(&self.me) {
            m.events = Some(events);
        }
        self.net.refresh();
        Ok(())
    }

    fn status(&self) -> LinkStatus {
        let up = self.net.st.lock().members.get(&self.me).is_some_and(|m| m.up);
        LinkStatus {
            kind: self.net.medium.kind,
            label: Some(self.net.medium.label.to_string()),
            active: up,
            detail: None,
            peers: if up { self.net.neighbours(&self.me).len() } else { 0 },
        }
    }
}

#[derive(Debug)]
struct EmuTransport {
    net: EmuNet,
    me: SignPk,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl CustomTransport for EmuTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self.rx.clone().try_lock_owned().map_err(|_| io::Error::other("link already bound"))?;
        Ok(Box::new(EmuEndpoint {
            net: self.net.clone(),
            me: self.me,
            addrs: n0_watcher::Watchable::new(vec![self.net.addr_of(&self.me)]),
            rx,
        }))
    }
}

struct EmuEndpoint {
    net: EmuNet,
    me: SignPk,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<Packet>>,
}

impl std::fmt::Debug for EmuEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmuEndpoint")
    }
}

impl CustomEndpoint for EmuEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(EmuSender { net: self.net.clone(), me: self.me })
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
            if bufs[count].len() < p.data.len() {
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
struct EmuSender {
    net: EmuNet,
    me: SignPk,
}

impl CustomSender for EmuSender {
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
        let Some(to) = self.net.parse(dst) else {
            return Poll::Ready(Err(io::Error::other("not a peer on this medium")));
        };
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for chunk in transmit.contents.chunks(seg) {
            self.net.deliver(self.me, to, Bytes::copy_from_slice(chunk));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SignPk {
        SignPk([n; 32])
    }

    #[test]
    fn great_circle() {
        let nyc = Pos::new(40.71, -74.01);
        let london = Pos::new(51.51, -0.13);
        let km = nyc.km(&london);
        assert!((5500.0..5650.0).contains(&km), "{km}");
    }

    #[tokio::test(start_paused = true)]
    async fn range_and_discovery() {
        let mut m = Medium::ideal(PathKind::Bluetooth);
        m.range = 30.0;
        let net = EmuNet::new(0, m, 1);
        let (a, b, c) = (key(1), key(2), key(3));
        let la = net.link(a, Pos::new(0.0, 0.0));
        let _lb = net.link(b, Pos::new(20.0, 0.0));
        let _lc = net.link(c, Pos::new(45.0, 0.0));
        let (tx, mut rx) = mpsc::unbounded_channel();
        la.start(tx).unwrap();
        let mut found = vec![];
        while let Ok(LinkEvent::Found { peer, .. }) = rx.try_recv() {
            found.push(peer);
        }
        assert_eq!(found, vec![b], "c is out of a's range");
        net.set_pos(&c, Pos::new(10.0, 0.0));
        net.set_pos(&b, Pos::new(100.0, 0.0));
        net.refresh();
        let mut ev = vec![];
        while let Ok(e) = rx.try_recv() {
            ev.push(match e {
                LinkEvent::Found { peer, .. } => (true, peer),
                LinkEvent::Lost { peer, .. } => (false, peer),
            });
        }
        ev.sort();
        assert_eq!(ev, vec![(false, b), (true, c)]);
    }

    #[tokio::test(start_paused = true)]
    async fn airtime_and_shared_channel() {
        // 1000 B/s: a 100-byte packet takes 100 ms of airtime
        let mut m = Medium::ideal(PathKind::Other);
        m.rate = Some(1000);
        m.range = 50.0;
        m.shared_channel = true;
        m.max_queue = Duration::from_secs(10);
        let net = EmuNet::new(1, m, 1);
        let (a, b, c) = (key(1), key(2), key(3));
        for (k, x) in [(a, 0.0), (b, 40.0), (c, 80.0)] {
            net.link(k, Pos::new(x, 0.0));
        }
        let (_, d1) = net.schedule(&a, &b, 100).unwrap();
        assert_eq!(d1, Duration::from_millis(100));
        // b heard a's packet: its own send waits for the channel
        let (_, d2) = net.schedule(&b, &c, 100).unwrap();
        assert_eq!(d2, Duration::from_millis(200));
        // c is out of a's range but in b's: busy until b is done
        let (_, d3) = net.schedule(&c, &b, 100).unwrap();
        assert_eq!(d3, Duration::from_millis(300));
        assert!(net.schedule(&a, &c, 10).is_none(), "out of range");
    }

    #[tokio::test(start_paused = true)]
    async fn geo_latency_and_reach() {
        let mut m = Medium::ideal(PathKind::Network);
        m.discoverable = false;
        m.latency = Latency::Geo { base: Duration::from_millis(1), us_per_km: 5.0, inflation: 1.5 };
        let net = EmuNet::new(2, m, 1);
        let (ny, ld, sf) = (key(1), key(2), key(3));
        net.link(ny, Pos::new(40.71, -74.01));
        net.link(ld, Pos::new(51.51, -0.13));
        net.link(sf, Pos::new(37.77, -122.42));
        let (_, d) = net.schedule(&ny, &ld, 10).unwrap();
        // ~5570 km × 7.5 µs = ~42 ms one way, ~84 ms round trip
        assert!((40..46).contains(&d.as_millis()), "{d:?}");
        net.set_pair(Some(Arc::new(move |a, b| (!(*a == sf || *b == sf)).then(PairShape::default))));
        assert!(net.schedule(&ny, &sf, 10).is_none(), "NAT says no");
    }
}
