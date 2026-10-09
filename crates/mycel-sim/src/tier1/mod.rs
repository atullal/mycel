//! Tier 1: real Mycel nodes (iroh QUIC, multipath, the mesh, sync, calls
//! with test tones) over emulated networks ([`mycel_net::emu`]).
//!
//! A [`Lab`] holds media and devices. Messages are real Mycel sync: a change
//! to a shared document, timed until the recipient's replica shows it.
//! Calls are real `mycel-call` calls with sine-tone "microphones". Every
//! device is a full `Node` (its own QUIC endpoint and tasks), so a lab runs
//! in real time; this Mac handles a few hundred (see `scale-ceiling`).
//!
//! Optimality: for a static topology the lab computes the fastest path a
//! message could take (Dijkstra over who hears whom on each medium, each hop
//! costing latency + half the jitter + size/rate). Mycel sync needs a few
//! round trips (QUIC handshake on first contact, then the sync exchange), so
//! a ratio of 2–4× on a warm connection is the protocol, not the routing.

use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_call::audio::{AudioIo, TestAudio, TestSource};
use mycel_call::level::estimate_frequency;
use mycel_call::{ALPN_CALL, BoxFuture, CallEvent, CallHost, CallManager, CallPhase};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::emu::{EmuLink, EmuNet, Latency, Medium, PairShape, Pos};
use mycel_net::iroh::endpoint::Connection;
use mycel_net::iroh::{EndpointAddr, TransportAddr};
use mycel_net::link::{Link, PathKind};
use mycel_net::{ExtraProtocol, MeshOptions, NetMode, Node, NodeOptions};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::models::{Access, Env, FIBRE_US_PER_KM, Nat, PATH_INFLATION, Tech, backbone, km, nearest_relay};
use crate::stats::Summary;

/// Run a tier-1 scenario on its own multi-threaded runtime.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime").block_on(f)
}

/// A medium of `tech` in `env`, in transport slot `slot` (0..16).
pub fn net(slot: u64, tech: Tech, env: Env, seed: u64) -> EmuNet {
    EmuNet::new(slot, tech.medium(env), seed ^ slot)
}

/// Per-device internet properties for the internet and relay media.
#[derive(Clone, Copy, Debug)]
pub struct Uplink {
    pub latlon: (f64, f64),
    pub access: Access,
    pub nat: Nat,
}

/// The internet as a medium: everyone attached can reach everyone NAT
/// allows, with access latency on both ends and fibre latency between.
/// Not discoverable: contacts are introduced (`Lab::introduce`).
pub fn internet(slot: u64, seed: u64, ups: Arc<Mutex<HashMap<SignPk, Uplink>>>) -> EmuNet {
    let mut m = Medium::ideal(PathKind::Network);
    m.label = "Internet (direct)";
    m.discoverable = false;
    m.latency = Latency::Geo { base: Duration::ZERO, us_per_km: FIBRE_US_PER_KM, inflation: PATH_INFLATION };
    let n = EmuNet::new(slot, m, seed);
    n.set_pair(Some(Arc::new(move |a, b| {
        let u = ups.lock();
        let (ua, ub) = (u.get(a)?, u.get(b)?);
        Nat::direct(ua.nat, ub.nat).then(|| PairShape { latency: ua.access.latency() + ub.access.latency(), rate_div: 1.0 })
    })));
    n
}

/// Relays: client → nearest relay → peer's nearest relay → peer, for
/// everyone (NAT doesn't matter). Not discoverable.
pub fn relays(slot: u64, seed: u64, ups: Arc<Mutex<HashMap<SignPk, Uplink>>>) -> EmuNet {
    let mut m = Medium::ideal(PathKind::Relay);
    m.label = "Internet relay";
    m.discoverable = false;
    let n = EmuNet::new(slot, m, seed);
    n.set_pair(Some(Arc::new(move |a, b| {
        let u = ups.lock();
        let (ua, ub) = (u.get(a)?, u.get(b)?);
        let (ra, rb) = (nearest_relay(ua.latlon), nearest_relay(ub.latlon));
        let path = backbone(km(ua.latlon, ra)) + backbone(km(ra, rb)) + backbone(km(rb, ub.latlon));
        // relays forward in a few ms
        Some(PairShape { latency: ua.access.latency() + ub.access.latency() + path + Duration::from_millis(2), rate_div: 1.0 })
    })));
    n
}

/// What a device runs.
#[derive(Clone, Default)]
pub struct DevOpts {
    pub mesh: Option<MeshOptions>,
    /// A test-tone "microphone" at this frequency (and a call manager).
    pub tone: Option<f32>,
    /// Serve bulk transfers ([`Lab::bulk`]).
    pub bulk: bool,
}

/// Bulk transfers: read a stream to the end, answer with the byte count.
pub const ALPN_BULK: &[u8] = b"mycel-sim/bulk";

async fn sink(conn: Connection) {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        tokio::spawn(async move {
            let mut total = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            while let Ok(Some(n)) = rx.read(&mut buf).await {
                total += n as u64;
            }
            let _ = tx.write_all(&total.to_le_bytes()).await;
            let _ = tx.finish();
        });
    }
}

pub struct Dev {
    pub name: String,
    pub node: Arc<Node>,
    pub keys: Arc<DeviceKeys>,
    pub calls: Option<CallManager>,
    pub audio: Option<Arc<TestAudio>>,
    pub events: Arc<Mutex<Vec<CallEvent>>>,
    pub links: Vec<(EmuNet, Arc<EmuLink>)>,
}

impl Dev {
    pub fn hex(&self) -> String {
        self.node.id().0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn via(&self, other: &Dev) -> Option<PathKind> {
        self.node.peers().get(&other.node.id()).and_then(|p| p.via)
    }
}

struct Host {
    node: Arc<Node>,
    events: Arc<Mutex<Vec<CallEvent>>>,
}

impl CallHost for Host {
    fn me(&self) -> SignPk {
        self.node.id()
    }

    fn members(&self, space: &Hash32) -> anyhow::Result<Vec<SignPk>> {
        let me = self.node.id();
        let others: Vec<SignPk> = self.node.with_space(space, |r| {
            r.members().into_iter().filter(|(k, role)| k.sign_pk != me && *role != Role::Relay).map(|(k, _)| k.sign_pk).collect()
        })?;
        anyhow::ensure!(!others.is_empty(), "nobody else here");
        Ok(others)
    }

    fn may_call(&self, space: &Hash32, peer: &SignPk) -> bool {
        self.node.with_space(space, |r| r.is_member(peer) && r.my_role().is_some()).unwrap_or(false)
    }

    fn name_of(&self, peer: &SignPk) -> String {
        peer.short()
    }

    fn connect(&self, peer: SignPk) -> BoxFuture<anyhow::Result<Connection>> {
        let node = self.node.clone();
        Box::pin(async move { node.connect(peer, ALPN_CALL).await })
    }

    fn note_connection(&self, peer: &SignPk, conn: &Connection) {
        self.node.note_connection(*peer, conn);
    }

    fn emit(&self, event: CallEvent) {
        self.events.lock().push(event);
    }
}

/// A space and the document messages are written to.
#[derive(Clone, Copy, Debug)]
pub struct Conv {
    pub space: Hash32,
    pub doc: mycel_sync::DocId,
}

/// The outcome of one message.
#[derive(Clone, Copy, Debug)]
pub struct Delivery {
    pub from: usize,
    pub to: usize,
    pub latency: Option<Duration>,
    pub optimal: Option<Duration>,
}

/// The outcome of one call.
#[derive(Clone, Debug, Default)]
pub struct CallOutcome {
    pub setup: Option<Duration>,
    pub heard_ok: bool,
    pub loss_pct: f32,
    pub latency_ms: u32,
    pub path: Option<PathKind>,
    pub error: Option<String>,
}

/// `MYCEL_SIM_TRACE=1`: print what the lab is doing.
fn trace(what: std::fmt::Arguments) {
    if std::env::var("MYCEL_SIM_TRACE").is_ok() {
        eprintln!("[lab] {what}");
    }
}

pub struct Lab {
    pub devs: Vec<Dev>,
    pub media: Vec<EmuNet>,
    /// Reachability records for every mesh device: the lab's offline stand-in
    /// for the pkarr relay and the Mainline DHT.
    pub dir: mycel_net::mesh::directory::MemDirectory,
    seq: u64,
}

impl Default for Lab {
    fn default() -> Self {
        Self::new()
    }
}

impl Lab {
    pub fn new() -> Lab {
        Lab { devs: Vec::new(), media: Vec::new(), dir: Default::default(), seq: 0 }
    }

    pub fn add_medium(&mut self, n: EmuNet) -> EmuNet {
        self.media.push(n.clone());
        n
    }

    /// A device attached to `attach` (medium, position).
    pub async fn device(&mut self, name: &str, attach: &[(&EmuNet, Pos)], o: DevOpts) -> usize {
        let keys = Arc::new(DeviceKeys::generate());
        let mut opts = NodeOptions::new(NetMode::Local, name);
        opts.ip = false;
        let links: Vec<(EmuNet, Arc<EmuLink>)> = attach.iter().map(|(n, p)| ((*n).clone(), n.link(keys.sign_pk(), *p))).collect();
        opts.links = links.iter().map(|(_, l)| l.clone() as Arc<dyn Link>).collect();
        opts.mesh = o.mesh.clone().map(|mut m| {
            if m.directory.is_none() {
                m.directory = Some(Arc::new(self.dir.clone()));
            }
            m
        });
        let (tx, rx) = mpsc::unbounded_channel();
        if o.tone.is_some() {
            opts.extra_protocols.push(ExtraProtocol { alpn: ALPN_CALL.to_vec(), incoming: tx });
        }
        if o.bulk {
            let (btx, mut brx) = mpsc::unbounded_channel::<Connection>();
            opts.extra_protocols.push(ExtraProtocol { alpn: ALPN_BULK.to_vec(), incoming: btx });
            tokio::spawn(async move {
                while let Some(c) = brx.recv().await {
                    tokio::spawn(sink(c));
                }
            });
        }
        let node = Arc::new(Node::spawn(keys.clone(), opts).await.expect("node"));
        let events: Arc<Mutex<Vec<CallEvent>>> = Arc::default();
        let (calls, audio) = match o.tone {
            Some(hz) => {
                let calls = CallManager::new(Arc::new(Host { node: node.clone(), events: events.clone() }));
                let audio = Arc::new(TestAudio::new(TestSource::Sine { hz, amp: 0.5 }));
                calls.set_audio(audio.clone() as Arc<dyn AudioIo>);
                calls.serve(rx);
                (Some(calls), Some(audio))
            }
            None => (None, None),
        };
        self.devs.push(Dev { name: name.into(), node, keys, calls, audio, events, links });
        trace(format_args!("device {} = {name}", self.devs.len() - 1));
        self.devs.len() - 1
    }

    /// Tell `a` and `b` each other's addresses on non-discoverable media
    /// (the internet, relays): what address lookup does for contacts.
    pub fn introduce(&self, a: usize, b: usize) {
        for (x, y) in [(a, b), (b, a)] {
            let addrs: Vec<TransportAddr> = self.devs[y]
                .links
                .iter()
                .filter(|(n, _)| !n.medium().discoverable && self.devs[x].links.iter().any(|(m, _)| format!("{m:?}") == format!("{n:?}")))
                .map(|(n, _)| TransportAddr::Custom(n.addr_of(&self.devs[y].node.id())))
                .collect();
            if !addrs.is_empty() {
                self.devs[x].node.add_peer_addr(EndpointAddr::from_parts(self.devs[y].node.addr().id, addrs));
            }
        }
    }

    /// A conversation of `members` (the first creates it); waits for each
    /// to have it.
    pub async fn conversation(&self, members: &[usize]) -> anyhow::Result<Conv> {
        trace(format_args!("conversation {members:?}"));
        let owner = &self.devs[members[0]];
        let (space, genesis) = owner.node.create_space()?;
        for m in &members[1..] {
            owner.node.with_space(&space, |r| r.add_member(self.devs[*m].keys.public(), Role::Writer))??;
        }
        let doc = Replica::new_doc_id();
        owner.node.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "created", 1i64)))??;
        owner.node.changed(space);
        for m in &members[1..] {
            self.devs[*m].node.join_space(genesis.clone())?;
        }
        for m in &members[1..] {
            let node = self.devs[*m].node.clone();
            let oid = owner.node.id();
            let mut last = None;
            let until = Instant::now() + Duration::from_secs(45);
            while Instant::now() < until {
                match tokio::time::timeout(Duration::from_secs(10), node.sync_with(oid, space, true)).await {
                    Ok(Ok(_)) => {
                        last = None;
                        break;
                    }
                    Ok(Err(e)) => last = Some(e.to_string()),
                    Err(_) => last = Some("timed out".into()),
                }
                last.get_or_insert_with(|| "timed out".into());
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if let Some(e) = last {
                anyhow::bail!("{} couldn't join: {e}", self.devs[*m].name);
            }
        }
        Ok(Conv { space, doc })
    }

    /// `from` writes a message; time until each of `to` sees it (or `deadline`).
    pub async fn message(&mut self, c: Conv, from: usize, to: &[usize], deadline: Duration) -> Vec<Delivery> {
        self.seq += 1;
        trace(format_args!("message {} {from} -> {to:?}", self.seq));
        let key = format!("m{}", self.seq);
        let t0 = Instant::now();
        let k = key.clone();
        let _ = self.devs[from].node.with_space(&c.space, move |r| r.change(c.doc, |d| d.put(ROOT, k.as_str(), "hello")));
        // what the app does after a local change: push it to the members
        self.devs[from].node.changed(c.space);
        let mut handles = Vec::new();
        for &t in to {
            let node = self.devs[t].node.clone();
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let seen = node.with_space(&c.space, |r| r.doc_json(&c.doc)).ok().is_some_and(|v| v.get(&key).is_some());
                    if seen {
                        return Some(t0.elapsed());
                    }
                    if t0.elapsed() > deadline {
                        return None;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }));
        }
        let mut out = Vec::new();
        for (h, &t) in handles.into_iter().zip(to) {
            let latency = h.await.ok().flatten();
            trace(format_args!("  {from} -> {t}: {latency:?} via {:?}", self.devs[from].via(&self.devs[t])));
            let optimal = self.optimal(from, t, 600);
            out.push(Delivery { from, to: t, latency, optimal });
        }
        out
    }

    /// Call from `a` to `b` in `c`; listen for `listen`.
    pub async fn call(&self, c: Conv, a: usize, b: usize, listen: Duration) -> CallOutcome {
        let (Some(ca), Some(cb)) = (&self.devs[a].calls, &self.devs[b].calls) else {
            return CallOutcome { error: Some("no call manager".into()), ..Default::default() };
        };
        trace(format_args!("call {a} -> {b}"));
        let t0 = Instant::now();
        let out = match ca.start(c.space).await {
            Ok(o) => o,
            Err(e) => return CallOutcome { error: Some(e.to_string()), ..Default::default() },
        };
        // wait for the ring, answer
        let ring = loop {
            if let Some(r) = self.devs[b].events.lock().iter().rev().find_map(|e| match e {
                CallEvent::Incoming(i) if i.id == out.id => Some(i.clone()),
                _ => None,
            }) {
                break Some(r);
            }
            if t0.elapsed() > Duration::from_secs(20) {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let Some(ring) = ring else {
            let _ = ca.end(&out.id);
            return CallOutcome { error: Some("never rang".into()), ..Default::default() };
        };
        if let Err(e) = cb.accept(&ring.id).await {
            return CallOutcome { error: Some(e.to_string()), ..Default::default() };
        }
        let setup = loop {
            let both = ca.status().iter().any(|x| x.id == out.id && x.state == CallPhase::Active)
                && cb.status().iter().any(|x| x.id == out.id && x.state == CallPhase::Active);
            if both {
                break Some(t0.elapsed());
            }
            if t0.elapsed() > Duration::from_secs(30) {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        tokio::time::sleep(listen).await;
        let info = cb.status().into_iter().find(|x| x.id == out.id);
        let want = self.devs[a].audio.as_ref().and_then(|_| tone_of(&self.devs[a]));
        let heard = self.devs[b].audio.as_ref().and_then(|au| {
            let rec = au.recording();
            let rec = rec.lock();
            let tail = &rec.samples[rec.samples.len().saturating_sub(48_000)..];
            estimate_frequency(tail, 48_000)
        });
        let heard_ok = matches!((want, heard), (Some(w), Some(h)) if (w - h).abs() < 8.0);
        let _ = ca.end(&out.id);
        CallOutcome {
            setup,
            heard_ok,
            loss_pct: info.as_ref().map_or(100.0, |i| i.stats.loss_pct),
            latency_ms: info.as_ref().map_or(0, |i| i.stats.latency_ms),
            path: info.and_then(|i| i.path),
            error: None,
        }
    }

    /// Push `bytes` from `a` to `b` on one QUIC stream; how long it took.
    pub async fn bulk(&self, a: usize, b: usize, bytes: u64, deadline: Duration) -> Option<Duration> {
        let t0 = Instant::now();
        let work = async {
            let conn = self.devs[a].node.connect(self.devs[b].node.id(), ALPN_BULK).await.ok()?;
            let (mut tx, mut rx) = conn.open_bi().await.ok()?;
            let chunk = vec![0x5au8; 64 * 1024];
            let mut sent = 0u64;
            while sent < bytes {
                let n = chunk.len().min((bytes - sent) as usize);
                tx.write_all(&chunk[..n]).await.ok()?;
                sent += n as u64;
            }
            tx.finish().ok()?;
            let got = rx.read_to_end(8).await.ok()?;
            (u64::from_le_bytes(got.try_into().ok()?) == bytes).then(|| t0.elapsed())
        };
        tokio::time::timeout(deadline, work).await.ok().flatten()
    }

    /// The fastest a `size`-byte message could go from `a` to `b` now
    /// (ground truth over the emulated media), if they're connected.
    pub fn optimal(&self, a: usize, b: usize, size: usize) -> Option<Duration> {
        let n = self.devs.len();
        let ids: Vec<SignPk> = self.devs.iter().map(|d| d.node.id()).collect();
        let index: HashMap<SignPk, usize> = ids.iter().enumerate().map(|(i, k)| (*k, i)).collect();
        // edges: (to, cost µs) per medium
        let mut adj: Vec<Vec<(usize, u64)>> = vec![Vec::new(); n];
        for m in &self.media {
            let med = m.medium();
            for (i, k) in ids.iter().enumerate() {
                for nb in m.neighbours(k) {
                    let Some(&j) = index.get(&nb) else { continue };
                    let lat = match med.latency {
                        Latency::Fixed(d) => d,
                        Latency::Geo { base, us_per_km, inflation } => {
                            let (pa, pb) = (m.pos(k).unwrap_or_default(), m.pos(&nb).unwrap_or_default());
                            base + Duration::from_secs_f64(pa.km(&pb) * us_per_km * inflation / 1e6)
                        }
                    };
                    let shape = m.pair_shape(k, &nb);
                    let air = med.rate.map_or(0.0, |r| size as f64 * shape.rate_div / r as f64);
                    let us = (lat + shape.latency).as_micros() as u64 + med.jitter.as_micros() as u64 / 2 + (air * 1e6) as u64;
                    adj[i].push((j, us));
                }
            }
        }
        let mut dist = vec![u64::MAX; n];
        let mut pq = BinaryHeap::new();
        dist[a] = 0;
        pq.push(std::cmp::Reverse((0u64, a)));
        while let Some(std::cmp::Reverse((d, u))) = pq.pop() {
            if d > dist[u] {
                continue;
            }
            if u == b {
                return Some(Duration::from_micros(d));
            }
            for (v, w) in &adj[u] {
                if d + w < dist[*v] {
                    dist[*v] = d + w;
                    pq.push(std::cmp::Reverse((d + w, *v)));
                }
            }
        }
        None
    }

    pub async fn shutdown(self) {
        for d in self.devs {
            let _ = d.node.shutdown().await;
        }
    }
}

fn tone_of(d: &Dev) -> Option<f32> {
    let a = d.audio.as_ref()?;
    match a.source() {
        TestSource::Sine { hz, .. } => Some(hz),
        _ => None,
    }
}

/// Latency summary in seconds, delivery ratio and optimality of deliveries.
pub fn summarize(ds: &[Delivery]) -> (f64, Summary, Summary) {
    let lat: Vec<f64> = ds.iter().filter_map(|d| d.latency.map(|l| l.as_secs_f64())).collect();
    let opt: Vec<f64> = ds
        .iter()
        .filter_map(|d| Some(d.latency?.as_secs_f64() / d.optimal?.as_secs_f64().max(1e-4)))
        .collect();
    let ratio = if ds.is_empty() { 0.0 } else { lat.len() as f64 / ds.len() as f64 };
    (ratio, Summary::of(&lat), Summary::of(&opt))
}

/// Resident memory (MB) and CPU time (s) of this process.
pub fn resources() -> (f64, f64) {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output();
    let rss = out.ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<f64>().ok()).unwrap_or(0.0) / 1024.0;
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage fills the struct we pass.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let cpu = u.ru_utime.tv_sec as f64 + u.ru_utime.tv_usec as f64 / 1e6 + u.ru_stime.tv_sec as f64 + u.ru_stime.tv_usec as f64 / 1e6;
    (rss, cpu)
}

/// A position for a device `i` of `n` spread evenly on a `w` × `h` floor.
pub fn grid(i: usize, n: usize, w: f64, h: f64) -> Pos {
    let cols = ((n as f64 * w / h).sqrt().ceil() as usize).max(1);
    let rows = n.div_ceil(cols).max(1);
    Pos::new((i % cols) as f64 * w / cols as f64 + w / cols as f64 / 2.0, (i / cols) as f64 * h / rows as f64 + h / rows as f64 / 2.0)
}
