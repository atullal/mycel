//! BlueZ backend (Linux), through `bluer`, BlueZ's own Rust bindings.
//!
//! Same protocol as the macOS backend, so a Linux machine and a Mac link
//! with each other: the Mycel service UUID in the advertisement (local name
//! "Mycel"), a readable GATT characteristic with [`GattInfo`] (PSM, node key,
//! name), and an L2CAP connection-oriented channel at that PSM carrying the
//! framing in [`crate::wire`]. No pairing: the listening and dialing sockets
//! use `BT_SECURITY_LOW` (no encryption at the link layer; QUIC on top is
//! end-to-end encrypted), as macOS publishes its channel without encryption.
//!
//! One Tokio task drives the radio: it advertises, serves the GATT
//! characteristic, scans, accepts channels and runs the shared state machine
//! ([`crate::core`]) once a second; each radio command runs as its own task
//! and reports back through [`Hub::input`]. Each channel has a reader task
//! (frames → Iroh; closes the channel after [`SILENT_AFTER`] of silence) and
//! a writer task (the bounded [`OutQueue`], plus a ping every
//! [`PING_EVERY`]). If BlueZ goes away or the adapter is powered off,
//! everything is dropped and retried every few seconds.
//!
//! Permissions: BlueZ's D-Bus policy lets members of the `bluetooth` group
//! (or the active console user) advertise and register GATT services; L2CAP
//! sockets need no privilege.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use bluer::adv::Advertisement;
use bluer::gatt::local::{Application, Characteristic, CharacteristicRead, Service};
use bluer::l2cap::{Security, SecurityLevel, Socket, SocketAddr, Stream, StreamListener};
use bluer::{Adapter, AdapterEvent, AdapterProperty, Address, DeviceEvent, DeviceProperty, DiscoveryFilter, DiscoveryTransport, Uuid};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::core::{ChanId, Cmd, Input, Pid};
use crate::hub::{ChannelRx, Hub, PING_EVERY, PacketSink, Radio, SILENT_AFTER, short};
use crate::wire::{GattInfo, OutQueue, encode_hello, encode_ping};
use crate::{Backend, INFO_CHAR_UUID, OUT_QUEUE_BYTES, SERVICE_UUID, debug, info};

/// Pass each device's advertisements on at most this often.
const REPORT_EVERY: Duration = Duration::from_secs(1);
/// Retry BlueZ / the adapter this often while unavailable.
const RETRY: Duration = Duration::from_secs(5);
/// L2CAP connect and GATT read give up after this (the state machine has its
/// own, longer timeouts too).
const OP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Linux {
    driver: Mutex<Option<Arc<Driver>>>,
}

impl Linux {
    pub fn new() -> Linux {
        Linux { driver: Mutex::new(None) }
    }
}

impl Backend for Linux {
    fn start(&self, hub: Arc<Hub>) -> Result<()> {
        let rt = tokio::runtime::Handle::try_current().context("the Bluetooth link needs a Tokio runtime")?;
        hub.set_radio(Radio::Starting);
        let d = Arc::new(Driver {
            hub,
            stopped: AtomicBool::new(false),
            next_chan: AtomicU64::new(1),
            chans: Mutex::default(),
            reported: Mutex::default(),
            watching: Mutex::default(),
            adapter: Mutex::new(None),
            rescan: Notify::new(),
            main: Mutex::new(None),
        });
        let task = rt.spawn(d.clone().run());
        *d.main.lock() = Some(task);
        *self.driver.lock() = Some(d);
        Ok(())
    }

    fn stop(&self) {
        if let Some(d) = self.driver.lock().take() {
            d.stop();
        }
    }
}

/// One open channel's tasks.
struct Chan {
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Drop for Chan {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

struct Driver {
    hub: Arc<Hub>,
    stopped: AtomicBool,
    next_chan: AtomicU64,
    chans: Mutex<HashMap<ChanId, Chan>>,
    /// When each device was last passed on as discovered.
    reported: Mutex<HashMap<Pid, Instant>>,
    /// Devices whose connection we watch for drops.
    watching: Mutex<HashMap<Pid, JoinHandle<()>>>,
    adapter: Mutex<Option<Adapter>>,
    rescan: Notify,
    main: Mutex<Option<JoinHandle<()>>>,
}

impl Driver {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(t) = self.main.lock().take() {
            t.abort();
        }
        self.chans.lock().clear();
        for (_, w) in self.watching.lock().drain() {
            w.abort();
        }
        self.hub.set_radio(Radio::NotStarted);
    }

    fn input(self: &Arc<Self>, i: Input) {
        let cmds = self.hub.input(i);
        self.exec(cmds);
    }

    /// The radio is gone: drop every channel and peripheral.
    fn radio_down(self: &Arc<Self>) {
        let chans: Vec<ChanId> = self.chans.lock().keys().copied().collect();
        for c in chans {
            self.hub.remove_sink(c);
        }
        self.chans.lock().clear();
        for (_, w) in self.watching.lock().drain() {
            w.abort();
        }
        self.reported.lock().clear();
        *self.adapter.lock() = None;
        drop(self.hub.input(Input::RadioDown));
    }

    async fn run(self: Arc<Self>) {
        while !self.stopped.load(Ordering::SeqCst) {
            match self.clone().session().await {
                Ok(()) => info(format_args!("Bluetooth went away; restarting")),
                Err(e) => info(format_args!("Bluetooth unavailable: {e:#}")),
            }
            self.radio_down();
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Advertise, serve, scan and accept until the adapter goes away.
    async fn session(self: Arc<Self>) -> Result<()> {
        let session = match bluer::Session::new().await {
            Ok(s) => s,
            Err(e) => {
                self.hub.set_radio(Radio::Unavailable(format!("Can't reach the Bluetooth service (bluetoothd): {e}")));
                return Err(e.into());
            }
        };
        let adapter = match session.default_adapter().await {
            Ok(a) => a,
            Err(e) => {
                self.hub.set_radio(Radio::Unsupported);
                return Err(e.into());
            }
        };
        let mut adapter_events = adapter.events().await?;
        if !adapter.is_powered().await? {
            self.hub.set_radio(Radio::Off);
            info(format_args!("adapter {} is off", adapter.name()));
            while let Some(ev) = adapter_events.next().await {
                if matches!(ev, AdapterEvent::PropertyChanged(AdapterProperty::Powered(true))) {
                    break;
                }
            }
        }
        *self.adapter.lock() = Some(adapter.clone());

        // The L2CAP channel others open to us, at a PSM the kernel picks.
        let listener = listen(&adapter).await.context("can't open an L2CAP channel")?;
        let psm = listener.as_ref().local_addr()?.psm;
        info(format_args!("L2CAP channel published, psm {psm}"));
        let _gatt = adapter.serve_gatt_application(self.gatt_app(psm)).await.map_err(|e| {
            self.hub.set_problem(Some(format!("Couldn't publish the Mycel Bluetooth service: {e}")));
            e
        })?;
        let _adv = adapter
            .advertise(Advertisement {
                service_uuids: [service_uuid()].into_iter().collect(),
                local_name: Some("Mycel".into()),
                discoverable: Some(true),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                self.hub.set_problem(Some(format!("Couldn't advertise over Bluetooth: {e}")));
                e
            })?;
        info(format_args!("advertising as node {}", short(&self.hub.me)));
        self.hub.set_problem(None);
        self.hub.set_radio(Radio::On);

        adapter
            .set_discovery_filter(DiscoveryFilter {
                uuids: [service_uuid()].into_iter().collect(),
                transport: DiscoveryTransport::Le,
                duplicate_data: true,
                ..Default::default()
            })
            .await?;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            info(format_args!("scanning for Mycel devices"));
            let found = adapter.discover_devices_with_changes().await?;
            futures_util::pin_mut!(found);
            loop {
                tokio::select! {
                    _ = tick.tick() => self.input(Input::Tick),
                    ev = found.next() => match ev {
                        Some(AdapterEvent::DeviceAdded(addr)) => self.saw(&adapter, addr).await,
                        Some(_) => {}
                        None => break, // discovery stopped: start it again
                    },
                    a = listener.accept() => match a {
                        Ok((stream, from)) => {
                            info(format_args!("L2CAP channel accepted from {}", from.addr));
                            self.attach(stream, None);
                        }
                        Err(e) => info(format_args!("L2CAP accept failed: {e}")),
                    },
                    ev = adapter_events.next() => match ev {
                        Some(AdapterEvent::PropertyChanged(AdapterProperty::Powered(false))) | None => {
                            self.hub.set_radio(Radio::Off);
                            return Ok(());
                        }
                        _ => {}
                    },
                    _ = self.rescan.notified() => break,
                }
                if self.stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
            }
        }
    }

    /// The GATT service: one read-only characteristic with our PSM, key and
    /// current name.
    fn gatt_app(self: &Arc<Self>, psm: u16) -> Application {
        let hub = self.hub.clone();
        Application {
            services: vec![Service {
                uuid: service_uuid(),
                primary: true,
                characteristics: vec![Characteristic {
                    uuid: Uuid::from_str(INFO_CHAR_UUID).expect("valid UUID"),
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| {
                            let value = GattInfo { psm, key: hub.me, name: hub.name() }.encode();
                            async move { Ok(value) }.boxed()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Scanning reported a device (new, or a property such as RSSI changed,
    /// i.e. it advertised again).
    async fn saw(self: &Arc<Self>, adapter: &Adapter, addr: Address) {
        let pid: Pid = addr.to_string();
        {
            let now = Instant::now();
            let mut r = self.reported.lock();
            if r.get(&pid).is_some_and(|t| now.duration_since(*t) < REPORT_EVERY) {
                return;
            }
            r.insert(pid.clone(), now);
        }
        let Ok(dev) = adapter.device(addr) else { return };
        // BlueZ also reports devices it merely remembers: only ones heard
        // now (an RSSI) advertising the Mycel service count.
        let present = matches!(dev.rssi().await, Ok(Some(_)));
        let mycel = dev.uuids().await.ok().flatten().is_some_and(|u| u.contains(&service_uuid()));
        if present && mycel {
            debug(format_args!("advertisement from {pid}"));
            self.input(Input::Discovered(pid));
        }
    }

    /// Carry out the state machine's radio commands; each runs as its own
    /// task and reports back.
    fn exec(self: &Arc<Self>, cmds: Vec<Cmd>) {
        for c in cmds {
            let d = self.clone();
            match c {
                Cmd::Connect(pid) => {
                    tokio::spawn(async move {
                        let r = match d.device(&pid) {
                            Some(dev) => tokio::time::timeout(OP_TIMEOUT, dev.connect()).await.map_err(|_| None).and_then(|r| r.map_err(Some)),
                            None => Err(None),
                        };
                        match r {
                            Ok(()) => {
                                d.watch(&pid);
                                d.input(Input::Connected(pid));
                            }
                            Err(e) => {
                                info(format_args!("connect to {pid} failed: {}", e.map_or("timed out".into(), |e| e.to_string())));
                                d.input(Input::ConnectFailed(pid));
                            }
                        }
                    });
                }
                Cmd::Disconnect(pid) => {
                    tokio::spawn(async move {
                        if let Some(dev) = d.device(&pid) {
                            let _ = dev.disconnect().await;
                        }
                    });
                }
                Cmd::Forget(pid) => {
                    self.reported.lock().remove(&pid);
                    if let Some(w) = self.watching.lock().remove(&pid) {
                        w.abort();
                    }
                }
                Cmd::ReadInfo(pid) => {
                    tokio::spawn(async move {
                        let r = tokio::time::timeout(OP_TIMEOUT, d.read_info(&pid)).await;
                        match r {
                            Ok(Ok(i)) => d.input(Input::Info(pid, i)),
                            Ok(Err(e)) => {
                                info(format_args!("reading {pid}'s info failed: {e:#}"));
                                d.input(Input::InfoFailed(pid));
                            }
                            Err(_) => d.input(Input::InfoFailed(pid)),
                        }
                    });
                }
                Cmd::OpenChannel(pid, psm) => {
                    tokio::spawn(async move {
                        info(format_args!("opening L2CAP channel to {pid} (psm {psm})"));
                        match tokio::time::timeout(OP_TIMEOUT, d.open_channel(&pid, psm)).await {
                            Ok(Ok(stream)) => d.attach(stream, Some(pid)),
                            Ok(Err(e)) => {
                                info(format_args!("L2CAP open to {pid} failed: {e:#}"));
                                d.input(Input::OpenFailed(pid));
                            }
                            Err(_) => d.input(Input::OpenFailed(pid)),
                        }
                    });
                }
                Cmd::CloseChannel(chan) => {
                    self.hub.remove_sink(chan);
                    if self.chans.lock().remove(&chan).is_some() {
                        info(format_args!("L2CAP channel {chan} closed by us"));
                    }
                }
                Cmd::Rescan => self.rescan.notify_one(),
                other => debug(format_args!("unexpected command {other:?}")),
            }
        }
    }

    fn device(&self, pid: &Pid) -> Option<bluer::Device> {
        let addr = Address::from_str(pid).ok()?;
        self.adapter.lock().as_ref()?.device(addr).ok()
    }

    /// Report the BLE connection to `pid` ending.
    fn watch(self: &Arc<Self>, pid: &Pid) {
        let Some(dev) = self.device(pid) else { return };
        let (d, pid2) = (self.clone(), pid.clone());
        let task = tokio::spawn(async move {
            let Ok(events) = dev.events().await else { return };
            futures_util::pin_mut!(events);
            while let Some(ev) = events.next().await {
                if matches!(ev, DeviceEvent::PropertyChanged(DeviceProperty::Connected(false))) {
                    d.watching.lock().remove(&pid2);
                    d.input(Input::Disconnected(pid2));
                    return;
                }
            }
        });
        if let Some(old) = self.watching.lock().insert(pid.clone(), task) {
            old.abort();
        }
    }

    async fn read_info(&self, pid: &Pid) -> Result<GattInfo> {
        let dev = self.device(pid).context("no such device")?;
        let want = Uuid::from_str(INFO_CHAR_UUID).expect("valid UUID");
        // (waits for BlueZ to resolve the services)
        for s in dev.services().await? {
            if s.uuid().await? != service_uuid() {
                continue;
            }
            for c in s.characteristics().await? {
                if c.uuid().await? == want {
                    let v = c.read().await?;
                    return GattInfo::decode(&v).context("unreadable Mycel info");
                }
            }
        }
        anyhow::bail!("no Mycel service")
    }

    async fn open_channel(&self, pid: &Pid, psm: u16) -> Result<Stream> {
        let dev = self.device(pid).context("no such device")?;
        let addr = Address::from_str(pid)?;
        let ty = dev.address_type().await?;
        let socket = Socket::<Stream>::new_stream()?;
        socket.set_security(Security { level: SecurityLevel::Low, key_size: 0 })?;
        socket.bind(SocketAddr::any_le())?;
        Ok(socket.connect(SocketAddr::new(addr, ty, psm)).await?)
    }

    /// Carry a channel's traffic: hello first, then packets both ways.
    fn attach(self: &Arc<Self>, stream: Stream, pid: Option<Pid>) {
        let chan = self.next_chan.fetch_add(1, Ordering::Relaxed);
        let mut q = OutQueue::new(OUT_QUEUE_BYTES);
        q.push(encode_hello(&self.hub.me, &self.hub.name())); // always the first frame
        let q = Arc::new(Mutex::new(q));
        let wake = Arc::new(Notify::new());
        self.hub.add_sink(chan, Arc::new(Sink { q: q.clone(), wake: wake.clone() }));
        let (mut rh, mut wh) = stream.into_split();
        let d = self.clone();
        let reader = tokio::spawn(async move {
            let mut rx = ChannelRx::default();
            let mut buf = vec![0u8; 8192];
            let why = loop {
                match tokio::time::timeout(SILENT_AFTER, rh.read(&mut buf)).await {
                    Err(_) => break format!("silent: nothing received for {} s (dead link)", SILENT_AFTER.as_secs()),
                    Ok(Ok(0)) => break "closed by the peer (stream ended)".to_string(),
                    Ok(Err(e)) => break format!("read failed: {e}"),
                    Ok(Ok(n)) => match rx.on_bytes(&d.hub, chan, &buf[..n]) {
                        Ok(cmds) => d.exec(cmds),
                        Err(e) => break format!("garbage on the channel ({})", e.0),
                    },
                }
            };
            d.channel_died(chan, &why);
        });
        let d = self.clone();
        let writer = tokio::spawn(async move {
            let mut ping = tokio::time::interval(PING_EVERY);
            loop {
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = ping.tick() => {
                        q.lock().push(encode_ping());
                    }
                }
                loop {
                    let chunk = q.lock().peek().map(<[u8]>::to_vec);
                    let Some(chunk) = chunk else { break };
                    if let Err(e) = wh.write_all(&chunk).await {
                        d.channel_died(chan, &format!("write failed: {e}"));
                        return;
                    }
                    q.lock().advance(chunk.len());
                }
            }
        });
        self.chans.lock().insert(chan, Chan { reader, writer });
        info(format_args!("L2CAP channel {chan} open ({})", pid.as_deref().map_or("accepted".into(), |p| format!("dialed to {p}"))));
        self.input(Input::ChannelOpened { chan, pid });
    }

    /// The channel ended or broke: tell everyone.
    fn channel_died(self: &Arc<Self>, chan: ChanId, why: &str) {
        let Some(c) = self.chans.lock().remove(&chan) else { return };
        info(format_args!("L2CAP channel {chan} closed: {why}"));
        self.hub.remove_sink(chan);
        self.input(Input::ChannelClosed(chan));
        // (if this runs on one of the channel's own tasks, it ends right after)
        drop(c);
    }
}

/// Iroh's side of a channel: queue the frame, wake the writer.
struct Sink {
    q: Arc<Mutex<OutQueue>>,
    wake: Arc<Notify>,
}

impl PacketSink for Sink {
    fn send(&self, frame: Bytes) -> bool {
        let ok = self.q.lock().push(frame);
        if ok {
            self.wake.notify_one();
        }
        ok
    }
}

fn service_uuid() -> Uuid {
    Uuid::from_str(SERVICE_UUID).expect("valid UUID")
}

/// Listen for L2CAP channels on the adapter, without link-layer security
/// (no pairing).
async fn listen(adapter: &Adapter) -> Result<StreamListener> {
    let socket = Socket::<Stream>::new_stream()?;
    socket.set_security(Security { level: SecurityLevel::Low, key_size: 0 })?;
    socket.bind(SocketAddr::new(adapter.address().await?, adapter.address_type().await?, 0))?;
    Ok(socket.listen(4)?)
}
