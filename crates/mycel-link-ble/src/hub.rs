//! What every backend shares: the state machine, the routing table from node
//! key to channel, the inbound packet queue Iroh reads, and the radio state
//! for status reporting. Thread-safe; backends call in from their own
//! threads (CoreBluetooth's dispatch queue, the stream run loop).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mycel_crypto::SignPk;
use mycel_net::link::{CustomAddr, LinkEvent, TRANSPORT_BLUETOOTH};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::core::{ChanId, Cmd, Core, Input};
use crate::wire::{BadStream, Deframer, Frame};

/// Inbound packets waiting for Iroh. Full = dropped (QUIC recovers).
pub const INBOUND_QUEUE: usize = 512;
/// Send a ping on an otherwise quiet channel this often...
pub const PING_EVERY: Duration = Duration::from_secs(8);
/// ...and give up on a channel that has said nothing for this long.
pub const SILENT_AFTER: Duration = Duration::from_secs(30);

/// Where a channel's outgoing frames go (the platform's write side).
pub trait PacketSink: Send + Sync {
    /// Queue one frame; false if it was dropped (queue full / closed).
    fn send(&self, frame: Bytes) -> bool;
}

/// The radio's state, as far as status reporting cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Radio {
    NotStarted,
    Starting,
    /// The OS is asking the user whether we may use Bluetooth.
    AwaitingPermission,
    On,
    Off,
    /// Denied in Privacy & Security (or restricted by policy).
    Unauthorized,
    Unsupported,
    Resetting,
    /// Can't run at all; the text says why.
    Unavailable(String),
}

#[derive(Debug)]
pub struct Inbound {
    pub from: SignPk,
    pub data: Bytes,
}

#[derive(Default)]
struct Routes {
    by_key: HashMap<SignPk, ChanId>,
    sinks: HashMap<ChanId, Arc<dyn PacketSink>>,
}

pub struct Hub {
    pub me: SignPk,
    name: Mutex<String>,
    core: Mutex<Core>,
    routes: Mutex<Routes>,
    inbound: mpsc::Sender<Inbound>,
    events: Mutex<Option<mpsc::UnboundedSender<LinkEvent>>>,
    radio: Mutex<Radio>,
    /// Set by a backend when something specific went wrong (shown in status).
    problem: Mutex<Option<String>>,
}

pub fn addr_of(key: &SignPk) -> CustomAddr {
    CustomAddr::from_parts(TRANSPORT_BLUETOOTH, &key.0)
}

pub fn key_of(addr: &CustomAddr) -> Option<SignPk> {
    (addr.id() == TRANSPORT_BLUETOOTH).then(|| addr.data().try_into().ok().map(SignPk)).flatten()
}

impl Hub {
    pub fn new(me: SignPk, name: &str) -> (Arc<Hub>, mpsc::Receiver<Inbound>) {
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        let hub = Hub {
            me,
            name: Mutex::new(name.to_string()),
            core: Mutex::new(Core::new(me, Instant::now())),
            routes: Mutex::default(),
            inbound: tx,
            events: Mutex::new(None),
            radio: Mutex::new(Radio::NotStarted),
            problem: Mutex::new(None),
        };
        (Arc::new(hub), rx)
    }

    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    pub fn set_name(&self, name: &str) {
        *self.name.lock() = name.to_string();
    }

    pub fn set_events(&self, events: Option<mpsc::UnboundedSender<LinkEvent>>) {
        *self.events.lock() = events;
    }

    pub fn radio(&self) -> Radio {
        self.radio.lock().clone()
    }

    pub fn set_radio(&self, r: Radio) {
        *self.radio.lock() = r;
    }

    pub fn problem(&self) -> Option<String> {
        self.problem.lock().clone()
    }

    pub fn set_problem(&self, p: Option<String>) {
        *self.problem.lock() = p;
    }

    pub fn peers(&self) -> usize {
        self.core.lock().peers()
    }

    /// Feed the state machine. Routing and node events are handled here;
    /// the returned commands are for the radio.
    pub fn input(&self, i: Input) -> Vec<Cmd> {
        let tick = i == Input::Tick;
        if !tick {
            crate::debug(format_args!("in  {i:?}"));
        }
        let cmds = self.core.lock().handle(Instant::now(), i);
        if tick && !cmds.is_empty() {
            crate::debug(format_args!("in  Tick"));
        }
        let mut radio = Vec::new();
        for c in cmds {
            match c {
                Cmd::Route { key, chan } => {
                    self.routes.lock().by_key.insert(key, chan);
                }
                Cmd::Unroute { key } => {
                    self.routes.lock().by_key.remove(&key);
                }
                Cmd::Found { key, name } => {
                    crate::info(format_args!("linked to {} ({name})", short(&key)));
                    self.emit(LinkEvent::Found {
                        peer: key,
                        addr: addr_of(&key),
                        name: (!name.is_empty()).then_some(name),
                    });
                }
                Cmd::Lost { key } => {
                    crate::info(format_args!("lost {}", short(&key)));
                    self.emit(LinkEvent::Lost { peer: key, addr: addr_of(&key) });
                }
                other => {
                    crate::debug(format_args!("cmd {other:?}"));
                    radio.push(other)
                }
            }
        }
        radio
    }

    fn emit(&self, ev: LinkEvent) {
        if let Some(tx) = &*self.events.lock() {
            let _ = tx.send(ev);
        }
    }

    pub fn add_sink(&self, chan: ChanId, sink: Arc<dyn PacketSink>) {
        self.routes.lock().sinks.insert(chan, sink);
    }

    pub fn remove_sink(&self, chan: ChanId) {
        self.routes.lock().sinks.remove(&chan);
    }

    /// The sink currently carrying packets for `key`.
    pub fn route(&self, key: &SignPk) -> Option<Arc<dyn PacketSink>> {
        let r = self.routes.lock();
        r.by_key.get(key).and_then(|c| r.sinks.get(c)).cloned()
    }

    /// A QUIC packet arrived from `from`.
    pub fn deliver(&self, from: SignPk, data: Bytes) {
        let _ = self.inbound.try_send(Inbound { from, data });
    }
}

/// Short printable form of a node key.
pub fn short(k: &SignPk) -> String {
    k.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The receive side of one channel: reassembles frames, learns the peer from
/// the hello, hands packets to Iroh. Platform-independent.
pub struct ChannelRx {
    deframer: Deframer,
    key: Option<SignPk>,
    last_rx: Instant,
}

impl Default for ChannelRx {
    fn default() -> Self {
        ChannelRx { deframer: Deframer::default(), key: None, last_rx: Instant::now() }
    }
}

impl ChannelRx {
    /// Nothing arrived for [`SILENT_AFTER`]: the channel is dead.
    pub fn silent(&self, now: Instant) -> bool {
        now.duration_since(self.last_rx) >= SILENT_AFTER
    }

    /// Bytes read from the channel. Returns radio commands to run, or an
    /// error if the stream is garbage (close the channel).
    pub fn on_bytes(&mut self, hub: &Hub, chan: ChanId, data: &[u8]) -> Result<Vec<Cmd>, BadStream> {
        let mut cmds = Vec::new();
        self.last_rx = Instant::now();
        for f in self.deframer.push(data)? {
            match (f, self.key) {
                (Frame::Hello { key, name }, None) => {
                    self.key = Some(key);
                    cmds.extend(hub.input(Input::Hello { chan, key, name }));
                }
                (Frame::Hello { .. }, Some(_)) => return Err(BadStream("second hello")),
                (Frame::Packet(_), None) => return Err(BadStream("packet before hello")),
                (Frame::Packet(p), Some(k)) => hub.deliver(k, p),
                (Frame::Ping, _) => {}
            }
        }
        Ok(cmds)
    }
}
