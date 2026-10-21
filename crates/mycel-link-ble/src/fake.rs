//! A fake radio for tests: runs the real state machine, framing, routing and
//! Iroh transport of several in-process links, with the CoreBluetooth calls
//! replaced by an in-memory "air". Proves everything above the radio.
//!
//! The air models what CoreBluetooth did between two real Macs: a scan
//! reports each peripheral once (until the next rescan); a connect to a stale
//! handle never completes; and both devices share one radio link, so
//! cancelling a connected peripheral tears down every channel between the two
//! devices, the peer's included (the pessimistic reading of the bluetoothd
//! logs). The deterministic long-run version of this is in `sim`.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use mycel_crypto::SignPk;
use parking_lot::Mutex;

use crate::core::{ChanId, Cmd, Input};
use crate::hub::{ChannelRx, Hub, PacketSink, Radio};
use crate::wire::{GattInfo, OutQueue, encode_hello};
use crate::{Backend, BleLink, OUT_QUEUE_BYTES};

enum Job {
    Input(usize, Input),
    Cmd(usize, Cmd),
    Bytes { to: usize, chan: ChanId, data: Bytes },
}

struct End {
    node: usize,
    chan: ChanId,
}

/// One L2CAP channel between two nodes.
struct Pair {
    dialer: End,
    acceptor: End,
}

#[derive(Default)]
struct AirInner {
    keys: Vec<(SignPk, String)>,
    hubs: HashMap<usize, Weak<Hub>>,
    rx: HashMap<(usize, ChanId), ChannelRx>,
    pairs: Vec<Pair>,
    next_chan: ChanId,
    cut: bool,
    /// BLE connections: (central, peripheral).
    conns: HashSet<(usize, usize)>,
    /// (central, peripheral): the central's handle is stale; connects hang
    /// until it drops the handle (Forget) and takes a fresh one.
    stale: HashSet<(usize, usize)>,
    /// Cancels that tore down a channel the *peer* had dialed.
    harsh_kills: usize,
}

pub struct Air {
    inner: Mutex<AirInner>,
    tx: std_mpsc::Sender<Job>,
    /// `Some(bytes/s)`: channels are rate-limited like a real radio, with the
    /// same bounded drop-when-full queue the macOS backend uses.
    rate: Option<usize>,
    slow: Mutex<Vec<Arc<SlowSink>>>,
}

/// A rate-limited channel end: frames queue (bounded, dropped when full) and
/// a radio thread moves `rate` bytes/s, in arbitrary chunks, to the peer.
struct SlowSink {
    tx: std_mpsc::Sender<Job>,
    to: usize,
    chan: ChanId,
    q: Mutex<OutQueue>,
}

impl PacketSink for SlowSink {
    fn send(&self, frame: Bytes) -> bool {
        self.q.lock().push(frame)
    }
}

fn pid(n: usize) -> String {
    format!("p{n}")
}

fn idx(pid: &str) -> usize {
    pid[1..].parse().unwrap()
}

struct FakeBackend {
    air: Arc<Air>,
    me: usize,
}

impl Backend for FakeBackend {
    fn start(&self, hub: Arc<Hub>) -> anyhow::Result<()> {
        hub.set_radio(Radio::On);
        let others: Vec<usize> = {
            let mut a = self.air.inner.lock();
            a.hubs.insert(self.me, Arc::downgrade(&hub));
            a.hubs.keys().copied().filter(|n| *n != self.me).collect()
        };
        for o in others {
            self.air.job(Job::Input(self.me, Input::Discovered(pid(o))));
            self.air.job(Job::Input(o, Input::Discovered(pid(self.me))));
        }
        Ok(())
    }
}

struct FakeSink {
    tx: std_mpsc::Sender<Job>,
    to: usize,
    chan: ChanId,
}

impl PacketSink for FakeSink {
    fn send(&self, frame: Bytes) -> bool {
        self.tx.send(Job::Bytes { to: self.to, chan: self.chan, data: frame }).is_ok()
    }
}

impl Air {
    pub fn new() -> Arc<Air> {
        Self::with_rate(None)
    }

    pub fn with_rate(rate: Option<usize>) -> Arc<Air> {
        let (tx, rx) = std_mpsc::channel();
        let air = Arc::new(Air { inner: Mutex::default(), tx, rate, slow: Mutex::default() });
        if let Some(rate) = rate {
            let weak = Arc::downgrade(&air);
            std::thread::spawn(move || {
                const SLICE: Duration = Duration::from_millis(5);
                loop {
                    std::thread::sleep(SLICE);
                    let Some(air) = weak.upgrade() else { return };
                    let sinks = air.slow.lock().clone();
                    for s in sinks {
                        let mut budget = rate * SLICE.as_millis() as usize / 1000;
                        let mut q = s.q.lock();
                        while budget > 0 {
                            let Some(chunk) = q.peek() else { break };
                            let n = chunk.len().min(budget);
                            let data = Bytes::copy_from_slice(&chunk[..n]);
                            q.advance(n);
                            budget -= n;
                            let _ = s.tx.send(Job::Bytes { to: s.to, chan: s.chan, data });
                        }
                    }
                }
            });
        }
        let weak = Arc::downgrade(&air);
        std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                let Some(air) = weak.upgrade() else { return };
                air.run(job);
            }
        });
        let weak = Arc::downgrade(&air);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(200));
                let Some(air) = weak.upgrade() else { return };
                let nodes: Vec<usize> = air.inner.lock().hubs.keys().copied().collect();
                for n in nodes {
                    air.job(Job::Input(n, Input::Tick));
                }
            }
        });
        air
    }

    pub fn link(self: &Arc<Self>, me: SignPk, name: &str) -> Arc<BleLink> {
        let n = {
            let mut a = self.inner.lock();
            a.keys.push((me, name.to_string()));
            a.keys.len() - 1
        };
        BleLink::new(me, Box::new(FakeBackend { air: self.clone(), me: n }))
    }

    /// Radio silence: every channel drops, nothing connects.
    pub fn cut(&self) {
        self.inner.lock().cut = true;
        self.drop_links();
    }

    /// Back in range: everyone sees everyone again.
    pub fn restore(&self) {
        let nodes: Vec<usize> = {
            let mut a = self.inner.lock();
            a.cut = false;
            a.hubs.keys().copied().collect()
        };
        for &n in &nodes {
            for &o in &nodes {
                if n != o {
                    self.job(Job::Input(n, Input::Discovered(pid(o))));
                }
            }
        }
    }

    pub fn channels(&self) -> usize {
        self.inner.lock().pairs.len()
    }

    /// Every handle any node has (or will get) for any other is stale.
    pub fn make_stale(&self, nodes: usize) {
        let mut a = self.inner.lock();
        for n in 0..nodes {
            for o in 0..nodes {
                if n != o {
                    a.stale.insert((n, o));
                }
            }
        }
    }

    /// The stack closes every channel (both ends see it end); connections stay.
    pub fn close_channels(&self) {
        self.close_where(|_| true);
    }

    /// The radio link between every pair drops (supervision timeout).
    pub fn drop_links(&self) {
        let conns: Vec<(usize, usize)> = std::mem::take(&mut self.inner.lock().conns).into_iter().collect();
        self.close_where(|_| true);
        for (n, o) in conns {
            self.job(Job::Input(n, Input::Disconnected(pid(o))));
        }
    }

    pub fn harsh_kills(&self) -> usize {
        self.inner.lock().harsh_kills
    }

    fn job(&self, j: Job) {
        let _ = self.tx.send(j);
    }

    fn hub(&self, n: usize) -> Option<Arc<Hub>> {
        self.inner.lock().hubs.get(&n).and_then(|w| w.upgrade())
    }

    fn input(&self, n: usize, i: Input) {
        let Some(hub) = self.hub(n) else { return };
        for c in hub.input(i) {
            self.job(Job::Cmd(n, c));
        }
    }

    fn close_end(&self, e: &End) {
        self.inner.lock().rx.remove(&(e.node, e.chan));
        if let Some(h) = self.hub(e.node) {
            h.remove_sink(e.chan);
        }
        self.job(Job::Input(e.node, Input::ChannelClosed(e.chan)));
    }

    fn close_where(&self, f: impl Fn(&Pair) -> bool) {
        let gone: Vec<Pair> = {
            let mut a = self.inner.lock();
            let (gone, keep) = std::mem::take(&mut a.pairs).into_iter().partition(|p| f(p));
            a.pairs = keep;
            gone
        };
        for p in gone {
            self.close_end(&p.dialer);
            self.close_end(&p.acceptor);
        }
    }

    fn run(&self, job: Job) {
        match job {
            Job::Input(n, i) => self.input(n, i),
            Job::Bytes { to, chan, data } => {
                let Some(hub) = self.hub(to) else { return };
                let mut a = self.inner.lock();
                let Some(rx) = a.rx.get_mut(&(to, chan)) else { return };
                let res = rx.on_bytes(&hub, chan, &data);
                drop(a);
                match res {
                    Ok(cmds) => cmds.into_iter().for_each(|c| self.job(Job::Cmd(to, c))),
                    Err(e) => panic!("bad stream: {e:?}"),
                }
            }
            Job::Cmd(n, cmd) => self.exec(n, cmd),
        }
    }

    fn exec(&self, n: usize, cmd: Cmd) {
        let cut = self.inner.lock().cut;
        match cmd {
            Cmd::Connect(p) if cut => self.job(Job::Input(n, Input::ConnectFailed(p))),
            Cmd::Connect(p) => {
                let o = idx(&p);
                let mut a = self.inner.lock();
                if a.stale.contains(&(n, o)) {
                    return; // never completes
                }
                a.conns.insert((n, o));
                drop(a);
                self.job(Job::Input(n, Input::Connected(p)));
            }
            Cmd::Forget(p) => {
                self.inner.lock().stale.remove(&(n, idx(&p)));
            }
            Cmd::ReadInfo(p) => {
                let (key, name) = self.inner.lock().keys[idx(&p)].clone();
                self.job(Job::Input(n, Input::Info(p, GattInfo { psm: 0x80, key, name })));
            }
            Cmd::OpenChannel(p, _) if !self.inner.lock().conns.contains(&(n, idx(&p))) => {
                self.job(Job::Input(n, Input::OpenFailed(p)))
            }
            Cmd::OpenChannel(p, _) => {
                let o = idx(&p);
                let (Some(hn), Some(ho)) = (self.hub(n), self.hub(o)) else { return };
                let (cn, co, kn, ko) = {
                    let mut a = self.inner.lock();
                    let cn = a.next_chan;
                    let co = a.next_chan + 1;
                    a.next_chan += 2;
                    a.rx.insert((n, cn), ChannelRx::default());
                    a.rx.insert((o, co), ChannelRx::default());
                    a.pairs.push(Pair { dialer: End { node: n, chan: cn }, acceptor: End { node: o, chan: co } });
                    (cn, co, a.keys[n].clone(), a.keys[o].clone())
                };
                self.job(Job::Input(n, Input::ChannelOpened { chan: cn, pid: Some(p) }));
                self.job(Job::Input(o, Input::ChannelOpened { chan: co, pid: None }));
                for (hub, chan, to, to_chan, me) in [(&hn, cn, o, co, kn), (&ho, co, n, cn, ko)] {
                    let hello = encode_hello(&me.0);
                    if self.rate.is_some() {
                        let mut q = OutQueue::new(OUT_QUEUE_BYTES);
                        q.push(hello);
                        let sink = Arc::new(SlowSink { tx: self.tx.clone(), to, chan: to_chan, q: Mutex::new(q) });
                        self.slow.lock().push(sink.clone());
                        hub.add_sink(chan, sink);
                    } else {
                        hub.add_sink(chan, Arc::new(FakeSink { tx: self.tx.clone(), to, chan: to_chan }));
                        self.job(Job::Bytes { to, chan: to_chan, data: hello });
                    }
                }
            }
            Cmd::CloseChannel(c) => self.close_where(|p| {
                (p.dialer.node == n && p.dialer.chan == c) || (p.acceptor.node == n && p.acceptor.chan == c)
            }),
            Cmd::Disconnect(p) => {
                let o = idx(&p);
                let (connected, theirs) = {
                    let mut a = self.inner.lock();
                    let connected = a.conns.remove(&(n, o));
                    let theirs = connected && a.conns.remove(&(o, n));
                    if connected && a.pairs.iter().any(|q| q.dialer.node == o && q.acceptor.node == n) {
                        a.harsh_kills += 1;
                    }
                    (connected, theirs)
                };
                if !connected {
                    return; // a pending connect: cancelled quietly
                }
                // One radio link between the two: it goes, with every channel on it.
                self.close_where(|q| {
                    (q.dialer.node, q.acceptor.node) == (n, o) || (q.dialer.node, q.acceptor.node) == (o, n)
                });
                self.job(Job::Input(n, Input::Disconnected(p)));
                if theirs {
                    self.job(Job::Input(o, Input::Disconnected(pid(n))));
                }
            }
            Cmd::Rescan if !cut => {
                let nodes: Vec<usize> = self.inner.lock().hubs.keys().copied().collect();
                for o in nodes.into_iter().filter(|o| *o != n) {
                    self.job(Job::Input(n, Input::Discovered(pid(o))));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycel_crypto::DeviceKeys;
    use mycel_net::link::{Link, PathKind};
    use mycel_net::{NetMode, Node, NodeOptions};
    use mycel_sync::{
        Replica,
        automerge::{ROOT, transaction::Transactable},
    };
    use mycel_trust::Role;
    use serde_json::json;

    async fn eventually(what: &str, f: impl FnMut() -> bool) {
        eventually_within(what, Duration::from_secs(10), f).await
    }

    async fn eventually_within(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
        for _ in 0..(limit.as_millis() / 50) {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    async fn node(air: &Arc<Air>, name: &str) -> (Node, Arc<BleLink>) {
        let keys = Arc::new(DeviceKeys::generate());
        let link = air.link(keys.sign_pk(), name);
        let mut opts = NodeOptions::new(NetMode::Local, name);
        opts.ip = false;
        opts.links = vec![link.clone() as Arc<dyn Link>];
        (Node::spawn(keys, opts).await.unwrap(), link)
    }

    /// Real QUIC between two nodes over the BLE link stack (framing, state
    /// machine, routing, transport) with a fake radio; one channel per pair;
    /// Lost when the radio goes quiet and relinked when it comes back.
    #[tokio::test(flavor = "multi_thread")]
    async fn nodes_sync_over_the_ble_stack() {
        let air = Air::new();
        let (alice, alice_link) = node(&air, "alice").await;
        let (bob, _bob_link) = node(&air, "bob").await;

        eventually("linked both ways", || {
            alice.peers().get(&bob.id()).is_some_and(|p| p.links.contains(&PathKind::Bluetooth))
                && bob.peers().get(&alice.id()).is_some_and(|p| p.links.contains(&PathKind::Bluetooth))
        })
        .await;
        eventually("exactly one channel for the pair", || air.channels() == 1).await;
        // Bluetooth never carries the name (the card does, encrypted).
        assert_eq!(alice.peers()[&bob.id()].name, None);
        assert_eq!(alice.fetch_card(bob.id()).await.unwrap().name, "bob");
        let st = alice_link.status();
        assert!(st.active && st.peers == 1 && st.detail.is_none(), "{st:?}");

        let (space, genesis) = alice.create_space().unwrap();
        alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
        bob.join_space(genesis).unwrap();
        bob.sync_with(alice.id(), space, true).await.unwrap();
        let doc = Replica::new_doc_id();
        alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "hi over bluetooth"))).unwrap().unwrap();
        bob.sync_with(alice.id(), space, false).await.unwrap();
        assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"msg": "hi over bluetooth"}));
        assert_eq!(bob.peers()[&alice.id()].via, Some(PathKind::Bluetooth));
        bob.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "reply", "hello back"))).unwrap().unwrap();
        alice.sync_with(bob.id(), space, false).await.unwrap();
        assert_eq!(
            alice.with_space(&space, |r| r.doc_json(&doc)).unwrap(),
            json!({"msg": "hi over bluetooth", "reply": "hello back"})
        );

        air.cut();
        eventually("lost", || alice.peers().get(&bob.id()).is_some_and(|p| p.links.is_empty())).await;
        assert_eq!(alice_link.status().peers, 0);

        air.restore();
        eventually("relinked", || {
            alice.peers().get(&bob.id()).is_some_and(|p| p.links.contains(&PathKind::Bluetooth))
                && bob.peers().get(&alice.id()).is_some_and(|p| p.links.contains(&PathKind::Bluetooth))
        })
        .await;
        alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "back in range"))).unwrap().unwrap();
        bob.sync_with(alice.id(), space, false).await.unwrap();
        assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap()["msg"], json!("back in range"));
        eventually("one channel", || air.channels() == 1).await;
        alice.shutdown().await.unwrap();
        bob.shutdown().await.unwrap();
    }

    /// QUIC over a radio as slow as BLE L2CAP, with the real bounded queue:
    /// a 128 KiB message arrives intact; reports goodput vs. the raw rate.
    #[tokio::test(flavor = "multi_thread")]
    async fn bulk_sync_over_a_slow_radio() {
        const RATE: usize = 40 * 1024; // bytes/s, a typical Mac-to-Mac L2CAP rate
        let air = Air::with_rate(Some(RATE));
        let (alice, _a) = node(&air, "alice").await;
        let (bob, _b) = node(&air, "bob").await;
        eventually("linked", || {
            alice.peers().get(&bob.id()).is_some_and(|p| !p.links.is_empty())
                && bob.peers().get(&alice.id()).is_some_and(|p| !p.links.is_empty())
        })
        .await;
        let (space, genesis) = alice.create_space().unwrap();
        alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
        bob.join_space(genesis).unwrap();
        bob.sync_with(alice.id(), space, true).await.unwrap();

        let doc = Replica::new_doc_id();
        let mut x = 0x2545_f491u32;
        let big: String = (0..128 * 1024)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (b'a' + (x % 26) as u8) as char
            })
            .collect();
        alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "big", big.as_str()))).unwrap().unwrap();
        let t = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(60), bob.sync_with(alice.id(), space, false))
            .await
            .expect("finished")
            .unwrap();
        let el = t.elapsed();
        assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap()["big"], json!(big));
        let goodput = big.len() as f64 / el.as_secs_f64();
        eprintln!(
            "128 KiB over a {} KiB/s radio: {:.2?} = {:.1} KiB/s goodput ({:.0}% of raw)",
            RATE / 1024,
            el,
            goodput / 1024.0,
            100.0 * goodput / RATE as f64
        );
        assert!(goodput > RATE as f64 * 0.3, "QUIC keeps a slow radio reasonably busy");
        alice.shutdown().await.unwrap();
        bob.shutdown().await.unwrap();
    }

    /// Three devices that all discover each other at once end up with one
    /// channel per pair.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_channel_per_pair() {
        let air = Air::new();
        let mut links = Vec::new();
        for n in 0..3 {
            let l = air.link(DeviceKeys::generate().sign_pk(), &format!("n{n}"));
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            l.start(tx).unwrap();
            links.push((l, rx));
        }
        eventually("all linked", || links.iter().all(|(l, _)| l.status().peers == 2)).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        eventually("one channel per pair", || air.channels() == 3).await;
        for (l, rx) in &mut links {
            let mut found = 0;
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    mycel_net::LinkEvent::Found { .. } => found += 1,
                    mycel_net::LinkEvent::Lost { .. } => panic!("no flapping"),
                }
            }
            assert_eq!(found, 2, "each peer found once ({:?})", l.hub);
        }
        assert_eq!(air.harsh_kills(), 0, "never cancelled a link carrying the peer's channel");
    }

    type Links = Vec<(Arc<BleLink>, tokio::sync::mpsc::UnboundedReceiver<mycel_net::LinkEvent>)>;

    fn start_links(air: &Arc<Air>, n: usize) -> Links {
        let links: Links = (0..n)
            .map(|i| {
                let l = air.link(DeviceKeys::generate().sign_pk(), &format!("n{i}"));
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                (l, tx, rx)
            })
            .map(|(l, tx, rx)| {
                l.start(tx).unwrap();
                (l, rx)
            })
            .collect();
        links
    }

    fn drain(links: &mut Links) -> (usize, usize) {
        let (mut found, mut lost) = (0, 0);
        for (_, rx) in links.iter_mut() {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    mycel_net::LinkEvent::Found { .. } => found += 1,
                    mycel_net::LinkEvent::Lost { .. } => lost += 1,
                }
            }
        }
        (found, lost)
    }

    /// Connects to stale handles never complete: after the connect timeout
    /// the handles are dropped, fresh ones come from a rescan, and the link
    /// comes up.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_handles_recover_via_fresh_discovery() {
        let air = Air::new();
        air.make_stale(2);
        let t = std::time::Instant::now();
        let links = start_links(&air, 2);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(links[0].0.status().peers, 0, "stale: nothing connects yet");
        let st = links[0].0.status();
        assert_eq!(st.detail.as_deref(), Some("Connecting to 1 device…"), "{st:?}");
        eventually_within("linked after the connect timeout", Duration::from_secs(25), || {
            links.iter().all(|(l, _)| l.status().peers == 1)
        })
        .await;
        let took = t.elapsed();
        eprintln!("linked through stale handles in {took:?}");
        assert!(took < crate::core::CONNECT_TIMEOUT + Duration::from_secs(10), "{took:?}");
        eventually("one channel", || air.channels() == 1).await;
        assert_eq!(links[0].0.status().detail, None);
    }

    /// Channels closed by the stack and radio links dropping, again and
    /// again: each time both sides are linked again within seconds, over
    /// exactly one channel, with one Lost and one Found per side.
    #[tokio::test(flavor = "multi_thread")]
    async fn drops_and_remote_closes_reconnect_within_seconds() {
        let air = Air::new();
        let mut links = start_links(&air, 2);
        eventually("linked", || links.iter().all(|(l, _)| l.status().peers == 1)).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(drain(&mut links), (2, 0));
        for round in 0..6 {
            let t = std::time::Instant::now();
            if round % 2 == 0 {
                air.close_channels()
            } else {
                air.drop_links()
            }
            // Count events rather than poll status: a reopen over the spare
            // connection can take only milliseconds.
            let (mut found, mut lost) = (0, 0);
            eventually("lost and relinked", || {
                let (f, l) = drain(&mut links);
                found += f;
                lost += l;
                lost >= 2 && found >= 2 && links.iter().all(|(l, _)| l.status().peers == 1)
            })
            .await;
            let took = t.elapsed();
            eprintln!("round {round}: relinked in {took:?}");
            assert!(took < Duration::from_secs(8), "round {round}: {took:?}");
            eventually("one channel", || air.channels() == 1).await;
            tokio::time::sleep(Duration::from_millis(2500)).await;
            assert_eq!(air.channels(), 1, "round {round}");
            let (f, l) = drain(&mut links);
            assert_eq!((found + f, lost + l), (2, 2), "one Lost and one Found per side, round {round}");
        }
        assert_eq!(air.harsh_kills(), 0);
    }

    /// A phone in the background (restricted to its friend's key) links
    /// with the friend but never reports a stranger in range, and links
    /// with the stranger again once it's back in the foreground.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_restricted_link_ignores_strangers_until_lifted() {
        let air = Air::new();
        let keys: Vec<SignPk> = (0..3).map(|_| DeviceKeys::generate().sign_pk()).collect();
        let (friend, stranger) = (keys[1], keys[2]);
        let mut links: Links = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let l = air.link(*k, &format!("n{i}"));
                if i == 0 {
                    l.restrict_to(Some(&[friend])); // before it hears anyone
                }
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                l.start(tx).unwrap();
                (l, rx)
            })
            .collect();
        eventually("linked with the friend", || links[0].0.status().peers == 1).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(links[0].0.status().peers, 1);
        while let Ok(ev) = links[0].1.try_recv() {
            if let mycel_net::LinkEvent::Found { peer, .. } = ev {
                assert_eq!(peer, friend, "only the friend is reported");
            }
        }
        links[0].0.restrict_to(None);
        eventually_within("linked with the stranger too", Duration::from_secs(20), || links[0].0.status().peers == 2)
            .await;
        let mut found_stranger = false;
        while let Ok(ev) = links[0].1.try_recv() {
            found_stranger |= matches!(ev, mycel_net::LinkEvent::Found { peer, .. } if peer == stranger);
        }
        assert!(found_stranger);
    }
}
