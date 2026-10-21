//! The discrete-event engine: virtual time in microseconds, one event queue,
//! a sans-IO [`Router`] per device, radio geometry, the internet, and a
//! record of every contact so the [oracle](super::oracle) can compute the
//! fastest path that was physically possible for each message.
//!
//! What a frame costs: the sender's radio (or internet uplink) is busy for
//! `size / rate`, then the frame arrives after the medium's latency plus
//! jitter, if the link is still up. Hops are reliable (BLE, Wi-Fi and QUIC
//! all retransmit); collisions and shared-channel contention are not
//! modelled here (tier 1 models them), so tier-2 latencies are optimistic
//! under load.

use crate::stats::Map;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use serde::{Deserialize, Serialize};

use crate::models::{Access, Env, Nat, Tech, backbone, km, nearest_relay};
use crate::stats::{Rng, Stream, stream_seed};

/// Microseconds of virtual time.
pub type Time = u64;
pub type NodeId = u32;
pub type MsgId = u32;

pub const MS: Time = 1_000;
pub const SEC: Time = 1_000_000;
pub const MIN: Time = 60 * SEC;
pub const HOUR: Time = 60 * MIN;

/// A set of [`Tech`]s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Techs(pub u16);

impl Techs {
    pub const NONE: Techs = Techs(0);

    pub fn of(ts: &[Tech]) -> Techs {
        Techs(ts.iter().fold(0, |m, t| m | Self::bit(*t)))
    }

    fn bit(t: Tech) -> u16 {
        1 << Tech::ALL.iter().position(|x| *x == t).expect("listed")
    }

    pub fn has(self, t: Tech) -> bool {
        self.0 & Self::bit(t) != 0
    }

    pub fn and(self, o: Techs) -> Techs {
        Techs(self.0 & o.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = Tech> {
        Tech::ALL.into_iter().filter(move |t| self.has(*t))
    }

    /// The tech that moves `size` bytes soonest (latency + airtime).
    pub fn best(self, size: u32) -> Option<Tech> {
        self.iter().min_by_key(|t| hop_time(*t, size))
    }
}

/// Latency + airtime of one hop over `t` (no queueing, no jitter).
pub fn hop_time(t: Tech, size: u32) -> Time {
    t.latency().as_micros() as Time + (size as u64 * SEC) / t.rate()
}

/// A device's internet access.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Inet {
    pub access: Access,
    pub nat: Nat,
}

/// How a device moves.
#[derive(Clone, Debug, Default)]
pub enum Mobility {
    #[default]
    Static,
    /// Random waypoint inside `[0, w] × [0, h]` of its area: walk at
    /// `speed` m/s to a random point, pause, repeat.
    Waypoint { w: f64, h: f64, speed: f64, pause: Time },
    /// Scripted positions: at each time, jump (it's interpolated between).
    Path(Vec<(Time, (f64, f64))>),
}

/// One device, as the world generator describes it.
#[derive(Clone, Debug)]
pub struct NodeSpec {
    /// Radio neighbourhood: devices in different areas never hear each other.
    pub area: u32,
    /// Metres inside the area.
    pub xy: (f64, f64),
    pub radios: Techs,
    pub inet: Option<Inet>,
    pub mobility: Mobility,
    pub online: bool,
}

/// A radio area (a building, a block, a camp...) at a place on Earth.
#[derive(Clone, Debug)]
pub struct Area {
    pub latlon: (f64, f64),
    pub env: Env,
}

/// Where a frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    Radio(Tech),
    Inet,
}

/// A directory record: "`subject` is reachable via `gateway` at `cost`
/// (µs) as of `at`". Stand-in for reachability records published by key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirRecord {
    pub subject: NodeId,
    pub gateway: NodeId,
    pub cost: Time,
    pub at: Time,
}

/// Something a scenario makes happen at a time.
#[derive(Clone, Debug)]
pub enum Action {
    Online(NodeId, bool),
    Inet(NodeId, bool),
    Move(NodeId, (f64, f64)),
    /// A contact from a trace: `a` and `b` in range over these radios (or not).
    Contact(NodeId, NodeId, Techs, bool),
}

/// A sans-IO routing core: it reacts to events and acts only through [`Cx`].
/// The GLOBAL routing core plugs in here (see docs/SIMULATION.md).
pub trait Router {
    type Frame: Clone;
    /// Wire size of a frame in bytes.
    fn size(f: &Self::Frame) -> u32;
    /// Control traffic (announcements, summaries, receipts), as opposed to
    /// messages: counted as overhead.
    fn is_control(f: &Self::Frame) -> bool;
    /// The message a data frame carries, for relay accounting.
    fn msg_of(f: &Self::Frame) -> Option<MsgId>;

    fn on_start(&mut self, cx: &mut Cx<Self::Frame>);
    /// A radio neighbour appeared (`up`) or went away; `techs` = shared radios.
    fn on_link(&mut self, cx: &mut Cx<Self::Frame>, nb: NodeId, techs: Techs, up: bool);
    /// This device's own internet came or went (it also goes with `online`).
    fn on_inet(&mut self, _cx: &mut Cx<Self::Frame>, _up: bool) {}
    fn on_frame(&mut self, cx: &mut Cx<Self::Frame>, from: NodeId, over: Over, f: Self::Frame);
    fn on_timer(&mut self, cx: &mut Cx<Self::Frame>, token: u64);
    /// The app on this device sends `msg` of `size` bytes to `dst`.
    fn on_send(&mut self, cx: &mut Cx<Self::Frame>, msg: MsgId, dst: NodeId, size: u32);
    /// The answer to [`Cx::dir_get`].
    fn on_dir(&mut self, _cx: &mut Cx<Self::Frame>, _token: u64, _recs: Vec<DirRecord>) {}
    /// The answer to [`Cx::reach_get`]: `Some(gateways)` if the subject has a
    /// live reachability record, `None` if not (it is on the internet
    /// itself, or unknown: dial it directly).
    fn on_reach(&mut self, _cx: &mut Cx<Self::Frame>, _token: u64, _gateways: Option<Vec<(NodeId, u32)>>) {}
    /// The device was switched off or on (its state survives: storage).
    fn on_online(&mut self, _cx: &mut Cx<Self::Frame>, _online: bool) {}
    /// A frame this device sent didn't make it (the hop broke or the far
    /// end went away): link layers and QUIC know when a hop fails.
    fn on_undelivered(&mut self, _cx: &mut Cx<Self::Frame>, _to: NodeId, _f: Self::Frame) {}
}

enum Ev<F> {
    Frame { to: NodeId, from: NodeId, over: Over, f: F, link_since: Time },
    Timer { node: NodeId, token: u64 },
    Dir { node: NodeId, token: u64, subject: NodeId },
    Reach { node: NodeId, token: u64, subject: NodeId },
    Send { msg: MsgId },
    Mobility,
    Act(Action),
    Probe,
}

/// A message the app sent: when, from, to, how big, and what happened.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MsgRecord {
    pub src: NodeId,
    pub dst: NodeId,
    pub size: u32,
    pub sent: Time,
    pub delivered: Option<Time>,
    /// Copies of it that came to exist: the sender's, plus every replica a
    /// carrier made by handing on some of its copies and keeping the rest.
    /// Moving the only copy (custody) creates none.
    pub copies: u32,
    /// Times it was handed to another carrier (replicas and custody moves):
    /// transmissions between carriers, The ONE's "relayed".
    #[serde(default)]
    pub handoffs: u32,
    /// The fastest feasible arrival (filled by the oracle).
    pub optimal: Option<Time>,
    /// The oracle looked at it (all messages, or a sample).
    #[serde(default)]
    pub checked: bool,
    /// Receipt back at the sender.
    pub receipt: Option<Time>,
    /// Ask for an answer straight back (a call offer: setup = offer + answer).
    pub echo: bool,
}

/// Per-device counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeCounters {
    pub ctrl_frames: u64,
    pub ctrl_bytes: u64,
    pub data_frames: u64,
    pub data_bytes: u64,
    /// Data bytes sent for others' messages.
    pub relay_bytes: u64,
    pub dropped_link: u64,
    pub stored_peak: u64,
}

struct Node {
    spec: NodeSpec,
    online: bool,
    inet_up: bool,
    /// Current radio neighbours and the radios shared with each, and since when.
    nbrs: Map<NodeId, (Techs, Time)>,
    /// When each radio (by tech index) and the uplink are free again.
    busy: [Time; 10],
    wp_target: Option<(f64, f64)>,
    wp_wait_until: Time,
}

/// A contact: (from, to, radios); `to == Time::MAX` while it lasts.
pub type Window = (Time, Time, Techs);

/// A measurement taken every so often while the world runs.
type Probe<F> = (Time, Box<dyn FnMut(&WorldCore<F>, Time)>);

/// Contact plan: who could reach whom when (ground truth, for the oracle).
#[derive(Default)]
pub struct Contacts {
    /// (low id, high id) → [(from, to, radios)]; `to == Time::MAX` = still up.
    pub radio: Map<(NodeId, NodeId), Vec<Window>>,
    /// node → [(from, to)] with working internet.
    pub inet: Vec<Vec<(Time, Time)>>,
}

impl Contacts {
    fn open_radio(&mut self, a: NodeId, b: NodeId, t: Time, techs: Techs) {
        self.radio.entry((a.min(b), a.max(b))).or_default().push((t, Time::MAX, techs));
    }

    fn close_radio(&mut self, a: NodeId, b: NodeId, t: Time) {
        if let Some(v) = self.radio.get_mut(&(a.min(b), a.max(b)))
            && let Some(last) = v.last_mut()
            && last.1 == Time::MAX
        {
            last.1 = t;
        }
    }

    fn set_inet(&mut self, n: NodeId, up: bool, t: Time) {
        let v = &mut self.inet[n as usize];
        let open = v.last().is_some_and(|l| l.1 == Time::MAX);
        if up && !open {
            v.push((t, Time::MAX));
        } else if !up && open {
            v.last_mut().expect("open").1 = t;
        }
    }
}

/// What a router can see and do.
pub struct Cx<'a, F> {
    pub(crate) me: NodeId,
    pub(crate) now: Time,
    pub(crate) world: &'a mut WorldCore<F>,
}

/// Everything but the routers (so routers can borrow it mutably).
pub struct WorldCore<F> {
    nodes: Vec<Node>,
    pub areas: Vec<Area>,
    queue: BinaryHeap<Reverse<(Time, u64, usize)>>,
    events: Vec<Option<Ev<F>>>,
    free: Vec<usize>,
    seq: u64,
    /// Radio jitter and the routers' own randomness: the seed's protocol
    /// stream ([`Stream::Protocol`]), apart from every stream the scenario
    /// draws its world and workload from.
    pub rng: Rng,
    /// Where walking devices go: a stream of its own, so the world (who
    /// meets whom, when) is the same whatever the routers send.
    mob_rng: Rng,
    pub msgs: Vec<MsgRecord>,
    pub counters: Vec<NodeCounters>,
    pub contacts: Contacts,
    directory: Map<NodeId, Vec<DirRecord>>,
    /// Signed reachability records (pkarr-style): subject → (gateways with
    /// mesh cost, published at). The newest record wins.
    reach: Map<NodeId, (Vec<(NodeId, u32)>, Time)>,
    /// How long a reachability record lives.
    pub reach_lifetime: Time,
    /// Directory lookups that a poisoner answers (Sybil gateway).
    pub dir_poison: Option<NodeId>,
    pub mobility_step: Time,
    grid_cell: f64,
    grids: Vec<Map<(i64, i64), Vec<NodeId>>>,
    pub link_events: u64,
    pub events_run: u64,
    /// Events run by kind: frames, timers, lookups, sends, mobility, actions, probes.
    pub events_by_kind: [u64; 7],
    /// Max radio neighbours a device keeps (real radios cap connections).
    pub max_neighbours: usize,
    probes: Vec<Probe<F>>,
}

impl<F> Cx<'_, F> {
    pub fn now(&self) -> Time {
        self.now
    }

    pub fn me(&self) -> NodeId {
        self.me
    }

    pub fn rng(&mut self) -> &mut Rng {
        &mut self.world.rng
    }

    pub fn online(&self) -> bool {
        self.world.nodes[self.me as usize].online
    }

    /// This device has working internet now.
    pub fn has_inet(&self) -> bool {
        let n = &self.world.nodes[self.me as usize];
        n.online && n.inet_up
    }

    /// Its uplink, if it has one (gateways announce this).
    pub fn access(&self) -> Option<Access> {
        self.world.nodes[self.me as usize].spec.inet.map(|i| i.access)
    }

    /// Current radio neighbours.
    pub fn neighbours(&self) -> Vec<(NodeId, Techs)> {
        let mut v: Vec<(NodeId, Techs)> =
            self.world.nodes[self.me as usize].nbrs.iter().map(|(k, (t, _))| (*k, *t)).collect();
        v.sort_unstable_by_key(|x| x.0);
        v
    }

    pub fn radios_to(&self, nb: NodeId) -> Option<Techs> {
        self.world.nodes[self.me as usize].nbrs.get(&nb).map(|x| x.0)
    }

    /// Send over the best shared radio; `false` if `nb` isn't a neighbour.
    pub fn send_radio(&mut self, nb: NodeId, f: F, size: u32, control: bool, msg: Option<MsgId>) -> bool {
        let me = self.me;
        let Some(&(techs, since)) = self.world.nodes[me as usize].nbrs.get(&nb) else {
            self.world.counters[me as usize].dropped_link += 1;
            return false;
        };
        let Some(t) = techs.best(size) else { return false };
        let ti = Tech::ALL.iter().position(|x| *x == t).expect("listed");
        let now = self.now;
        let node = &mut self.world.nodes[me as usize];
        let start = node.busy[ti].max(now);
        let air = (size as u64 * SEC) / t.rate();
        node.busy[ti] = start + air;
        let jitter = (self.world.rng.f64() * t.jitter().as_micros() as f64) as Time;
        let at = start + air + t.latency().as_micros() as Time + jitter;
        self.account(size, control, msg);
        self.world.push(at, Ev::Frame { to: nb, from: me, over: Over::Radio(t), f, link_since: since });
        true
    }

    /// Send over the internet. Delivered only if both ends have internet
    /// when it arrives (the sender doesn't learn otherwise).
    pub fn send_inet(&mut self, dst: NodeId, f: F, size: u32, control: bool, msg: Option<MsgId>) -> bool {
        if !self.has_inet() {
            return false;
        }
        let me = self.me;
        let Some(delay) = self.world.inet_delay(me, dst) else { return false };
        let up = self.world.nodes[me as usize].spec.inet.expect("inet").access.uplink();
        let node = &mut self.world.nodes[me as usize];
        let start = node.busy[9].max(self.now);
        let air = (size as u64 * SEC) / up;
        node.busy[9] = start + air;
        self.account(size, control, msg);
        self.world.push(start + air + delay, Ev::Frame { to: dst, from: me, over: Over::Inet, f, link_since: 0 });
        true
    }

    fn account(&mut self, size: u32, control: bool, msg: Option<MsgId>) {
        let c = &mut self.world.counters[self.me as usize];
        if control {
            c.ctrl_frames += 1;
            c.ctrl_bytes += size as u64;
        } else {
            c.data_frames += 1;
            c.data_bytes += size as u64;
            if let Some(m) = msg
                && self.world.msgs.get(m as usize).is_some_and(|r| r.src != self.me)
            {
                c.relay_bytes += size as u64;
            }
        }
    }

    pub fn set_timer(&mut self, after: Time, token: u64) {
        let at = self.now + after.max(1);
        self.world.push(at, Ev::Timer { node: self.me, token });
    }

    /// The message reached its destination (this device).
    pub fn delivered(&mut self, msg: MsgId) {
        let now = self.now;
        if let Some(r) = self.world.msgs.get_mut(msg as usize)
            && r.dst == self.me
            && r.delivered.is_none()
        {
            r.delivered = Some(now);
        }
    }

    /// The sender learnt that `msg` was delivered.
    pub fn receipt(&mut self, msg: MsgId) {
        let now = self.now;
        if let Some(r) = self.world.msgs.get_mut(msg as usize)
            && r.src == self.me
            && r.receipt.is_none()
        {
            r.receipt = Some(now);
        }
    }

    /// One more copy of `msg` exists somewhere.
    pub fn copied(&mut self, msg: MsgId) {
        if let Some(r) = self.world.msgs.get_mut(msg as usize) {
            r.copies += 1;
        }
    }

    /// A carrier took `msg` from another (a replica or a custody move).
    pub fn handed(&mut self, msg: MsgId) {
        if let Some(r) = self.world.msgs.get_mut(msg as usize) {
            r.handoffs += 1;
        }
    }

    pub fn note_stored(&mut self, n: usize) {
        let c = &mut self.world.counters[self.me as usize];
        c.stored_peak = c.stored_peak.max(n as u64);
    }

    pub fn msg(&self, msg: MsgId) -> &MsgRecord {
        &self.world.msgs[msg as usize]
    }

    /// Publish a reachability record (needs internet).
    pub fn dir_put(&mut self, rec: DirRecord) {
        if !self.has_inet() {
            return;
        }
        let v = self.world.directory.entry(rec.subject).or_default();
        v.retain(|r| r.gateway != rec.gateway);
        v.push(rec);
        if v.len() > 8 {
            v.sort_by_key(|r| Reverse(r.at));
            v.truncate(8);
        }
    }

    /// Look up `subject`'s records; the answer comes back in `on_dir` after
    /// a DHT-like lookup time (needs internet).
    pub fn dir_get(&mut self, subject: NodeId, token: u64) -> bool {
        if !self.has_inet() {
            return false;
        }
        let acc = self.world.nodes[self.me as usize].spec.inet.expect("inet").access.latency().as_micros() as Time;
        // a few round trips across a DHT: ~3 RTTs of 50 ms plus our access
        let at = self.now + 2 * acc + 150 * MS;
        self.world.push(at, Ev::Dir { node: self.me, token, subject });
        true
    }
}

impl<F> Cx<'_, F> {
    /// One-way internet delay to `peer` now, if both are on the internet.
    pub fn inet_delay_to(&self, peer: NodeId) -> Option<Time> {
        self.world.inet_delay(self.me, peer)
    }

    /// Publish this device's reachability record (the gateways it sits
    /// behind). In reality it goes to those gateways as a mesh control
    /// message and they publish it to the DHT / relay; that takes well under
    /// a lookup's time, so it is immediate here.
    pub fn reach_put(&mut self, gateways: Vec<(NodeId, u32)>) {
        let now = self.now;
        self.world.reach.insert(self.me, (gateways, now));
    }

    /// Resolve `subject`'s reachability record (needs internet); the
    /// answer arrives in `on_reach` after a DHT-like lookup time.
    pub fn reach_get(&mut self, subject: NodeId, token: u64) -> bool {
        if !self.has_inet() {
            return false;
        }
        let acc = self.world.nodes[self.me as usize].spec.inet.expect("inet").access.latency().as_micros() as Time;
        let at = self.now + 2 * acc + 150 * MS;
        self.world.push(at, Ev::Reach { node: self.me, token, subject });
        true
    }
}

impl<F> WorldCore<F> {
    fn push(&mut self, at: Time, ev: Ev<F>) {
        let slot = match self.free.pop() {
            Some(i) => {
                self.events[i] = Some(ev);
                i
            }
            None => {
                self.events.push(Some(ev));
                self.events.len() - 1
            }
        };
        self.seq += 1;
        self.queue.push(Reverse((at, self.seq, slot)));
    }

    pub fn latlon(&self, n: NodeId) -> (f64, f64) {
        let node = &self.nodes[n as usize];
        let a = &self.areas[node.spec.area as usize];
        // metres → degrees around the area's origin
        let dlat = node.spec.xy.1 / 111_320.0;
        let dlon = node.spec.xy.0 / (111_320.0 * a.latlon.0.to_radians().cos().max(0.01));
        (a.latlon.0 + dlat, a.latlon.1 + dlon)
    }

    /// One-way internet delay a → b now, or `None` if b is unreachable.
    pub fn inet_delay(&self, a: NodeId, b: NodeId) -> Option<Time> {
        let (na, nb) = (&self.nodes[a as usize], &self.nodes[b as usize]);
        if !(na.online && na.inet_up && nb.online && nb.inet_up) {
            return None;
        }
        Some(inet_delay_static(self, a, b))
    }

    pub fn spec(&self, n: NodeId) -> &NodeSpec {
        &self.nodes[n as usize].spec
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn is_online(&self, n: NodeId) -> bool {
        self.nodes[n as usize].online
    }

    pub fn neighbours_of(&self, n: NodeId) -> Vec<NodeId> {
        self.nodes[n as usize].nbrs.keys().copied().collect()
    }

    pub fn degree(&self, n: NodeId) -> usize {
        self.nodes[n as usize].nbrs.len()
    }

    fn range(&self, n: NodeId, t: Tech) -> f64 {
        t.range(self.areas[self.nodes[n as usize].spec.area as usize].env)
    }

    /// Radios a and b share and are in range of, now.
    fn shared(&self, a: NodeId, b: NodeId) -> Techs {
        let (na, nb) = (&self.nodes[a as usize], &self.nodes[b as usize]);
        if na.spec.area != nb.spec.area || !na.online || !nb.online || a == b {
            return Techs::NONE;
        }
        let d = ((na.spec.xy.0 - nb.spec.xy.0).powi(2) + (na.spec.xy.1 - nb.spec.xy.1).powi(2)).sqrt();
        let mut m = 0u16;
        for t in na.spec.radios.and(nb.spec.radios).iter() {
            if t != Tech::Ethernet && d <= self.range(a, t) {
                m |= Techs::of(&[t]).0;
            }
        }
        // a cable / LAN: same area and both wired
        if na.spec.radios.and(nb.spec.radios).has(Tech::Ethernet) {
            m |= Techs::of(&[Tech::Ethernet]).0;
        }
        Techs(m)
    }

    fn cell(&self, xy: (f64, f64)) -> (i64, i64) {
        ((xy.0 / self.grid_cell).floor() as i64, (xy.1 / self.grid_cell).floor() as i64)
    }

    /// Devices near `n` that could be neighbours.
    fn candidates(&self, n: NodeId) -> Vec<NodeId> {
        let node = &self.nodes[n as usize];
        let grid = &self.grids[node.spec.area as usize];
        let wired = node.spec.radios.has(Tech::Ethernet);
        let (cx, cy) = self.cell(node.spec.xy);
        let mut out = Vec::new();
        for dx in -1..=1 {
            for dy in -1..=1 {
                if let Some(v) = grid.get(&(cx + dx, cy + dy)) {
                    out.extend(v.iter().copied().filter(|m| *m != n));
                }
            }
        }
        if wired {
            for v in grid.values() {
                for m in v {
                    if *m != n && self.nodes[*m as usize].spec.radios.has(Tech::Ethernet) && !out.contains(m) {
                        out.push(*m);
                    }
                }
            }
        }
        out
    }
}

fn inet_delay_static<F>(w: &WorldCore<F>, a: NodeId, b: NodeId) -> Time {
    let (ia, ib) = (w.nodes[a as usize].spec.inet.expect("inet"), w.nodes[b as usize].spec.inet.expect("inet"));
    let (pa, pb) = (w.latlon(a), w.latlon(b));
    let acc = ia.access.latency() + ib.access.latency();
    // one way between two points: measured (half the median RTT between the
    // nearest WonderNetwork servers) if MYCEL_PINGS is set, else fibre over the great circle
    let leg = |x: (f64, f64), y: (f64, f64)| match crate::latency::measured().and_then(|m| m.rtt_ms(x, y)) {
        Some(rtt) => std::time::Duration::from_secs_f64(rtt / 2000.0),
        None => backbone(km(x, y)),
    };
    let path = if Nat::direct(ia.nat, ib.nat) {
        leg(pa, pb)
    } else {
        let (ra, rb) = (nearest_relay(pa), nearest_relay(pb));
        leg(pa, ra) + leg(ra, rb) + leg(rb, pb)
    };
    (acc + path).as_micros() as Time
}

/// A whole simulated world: devices, their routers, and the clock.
pub struct Sim<R: Router> {
    pub core: WorldCore<R::Frame>,
    pub routers: Vec<R>,
    pub now: Time,
}

impl<R: Router> Sim<R> {
    /// Build the world; `make` creates each device's router.
    pub fn new(
        areas: Vec<Area>,
        specs: Vec<NodeSpec>,
        seed: u64,
        mut make: impl FnMut(NodeId, &NodeSpec) -> R,
    ) -> Self {
        let n = specs.len();
        let max_range = specs
            .iter()
            .flat_map(|s| s.radios.iter().filter(|t| *t != Tech::Ethernet).map(|t| t.range(areas[s.area as usize].env)))
            .fold(10.0, f64::max);
        let routers = specs.iter().enumerate().map(|(i, s)| make(i as NodeId, s)).collect();
        let nodes: Vec<Node> = specs
            .into_iter()
            .map(|spec| Node {
                online: spec.online,
                inet_up: spec.inet.is_some(),
                spec,
                nbrs: Map::default(),
                busy: [0; 10],
                wp_target: None,
                wp_wait_until: 0,
            })
            .collect();
        let mut core = WorldCore {
            nodes,
            grids: vec![Map::default(); areas.len()],
            areas,
            queue: BinaryHeap::new(),
            events: Vec::new(),
            free: Vec::new(),
            seq: 0,
            rng: Rng::new(stream_seed(seed, Stream::Protocol)),
            mob_rng: Rng::new(seed ^ 0x6d6f_6269_6c69_7479),
            msgs: Vec::new(),
            counters: vec![NodeCounters::default(); n],
            contacts: Contacts { radio: Map::default(), inet: vec![Vec::new(); n] },
            directory: Map::default(),
            reach: Map::default(),
            reach_lifetime: 30 * MIN,
            dir_poison: None,
            mobility_step: 5 * SEC,
            grid_cell: max_range,
            link_events: 0,
            events_run: 0,
            events_by_kind: [0; 7],
            max_neighbours: usize::MAX,
            probes: Vec::new(),
        };
        for i in 0..n {
            let c = core.cell(core.nodes[i].spec.xy);
            let area = core.nodes[i].spec.area as usize;
            core.grids[area].entry(c).or_default().push(i as NodeId);
        }
        Sim { core, routers, now: 0 }
    }

    /// Schedule the app sending a message.
    pub fn send_at(&mut self, at: Time, src: NodeId, dst: NodeId, size: u32) -> MsgId {
        let id = self.core.msgs.len() as MsgId;
        self.core.msgs.push(MsgRecord { src, dst, size, sent: at, ..Default::default() });
        self.core.push(at, Ev::Send { msg: id });
        id
    }

    /// A call offer: the callee answers at once; setup time = the receipt.
    pub fn call_at(&mut self, at: Time, src: NodeId, dst: NodeId) -> MsgId {
        let id = self.send_at(at, src, dst, 300);
        self.core.msgs[id as usize].echo = true;
        id
    }

    pub fn act_at(&mut self, at: Time, a: Action) {
        self.core.push(at, Ev::Act(a));
    }

    /// Call `f` every `every` from `every` on (measurements over time).
    pub fn probe_every(&mut self, every: Time, f: impl FnMut(&WorldCore<R::Frame>, Time) + 'static) {
        self.core.probes.push((every, Box::new(f)));
        let idx = self.core.probes.len() - 1;
        let _ = idx;
        self.core.push(every, Ev::Probe);
    }

    fn cx(&mut self, me: NodeId) -> (&mut R, Cx<'_, R::Frame>) {
        let now = self.now;
        let r = &mut self.routers[me as usize];
        (r, Cx { me, now, world: &mut self.core })
    }

    /// Start: initial links, internet, every router's `on_start`.
    pub fn start(&mut self) {
        let n = self.core.nodes.len();
        for i in 0..n as NodeId {
            if self.core.nodes[i as usize].online && self.core.nodes[i as usize].inet_up {
                self.core.contacts.set_inet(i, true, 0);
            }
        }
        for i in 0..n as NodeId {
            self.relink(i);
        }
        for i in 0..n as NodeId {
            let (r, mut cx) = self.cx(i);
            r.on_start(&mut cx);
        }
        if self.core.nodes.iter().any(|n| !matches!(n.spec.mobility, Mobility::Static)) {
            let step = self.core.mobility_step;
            self.core.push(step, Ev::Mobility);
        }
    }

    /// Recompute `n`'s radio neighbours; tell both sides about changes.
    fn relink(&mut self, n: NodeId) {
        let cands = self.core.candidates(n);
        let mut want: Vec<(NodeId, Techs, f64)> = cands
            .into_iter()
            .filter_map(|m| {
                let t = self.core.shared(n, m);
                if t.is_empty() {
                    return None;
                }
                let (a, b) = (&self.core.nodes[n as usize].spec.xy, &self.core.nodes[m as usize].spec.xy);
                Some((m, t, (a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)))
            })
            .collect();
        let cap = self.core.max_neighbours;
        if want.len() > cap {
            // keep the nearest (best signal), like a radio with few connection slots
            want.sort_by(|a, b| a.2.total_cmp(&b.2));
            want.truncate(cap);
        }
        let now = self.now;
        let old: Vec<(NodeId, Techs)> = self.core.nodes[n as usize].nbrs.iter().map(|(k, (t, _))| (*k, *t)).collect();
        let mut changes: Vec<(NodeId, Techs, bool)> = Vec::new();
        for (m, t) in &old {
            match want.iter().find(|w| w.0 == *m) {
                None => changes.push((*m, *t, false)),
                Some(w) if w.1 != *t => {
                    changes.push((*m, *t, false));
                    changes.push((*m, w.1, true));
                }
                _ => {}
            }
        }
        for (m, t, _) in &want {
            if !old.iter().any(|o| o.0 == *m) {
                // the other side must have room too
                let other = &self.core.nodes[*m as usize].nbrs;
                if other.len() >= cap && !other.contains_key(&n) {
                    continue;
                }
                changes.push((*m, *t, true));
            }
        }
        for (m, t, up) in changes {
            self.core.link_events += 1;
            if up {
                self.core.nodes[n as usize].nbrs.insert(m, (t, now));
                self.core.nodes[m as usize].nbrs.insert(n, (t, now));
                self.core.contacts.open_radio(n, m, now, t);
            } else {
                self.core.nodes[n as usize].nbrs.remove(&m);
                self.core.nodes[m as usize].nbrs.remove(&n);
                self.core.contacts.close_radio(n, m, now);
            }
            {
                let (r, mut cx) = self.cx(n);
                r.on_link(&mut cx, m, t, up);
            }
            let (r, mut cx) = self.cx(m);
            r.on_link(&mut cx, n, t, up);
        }
    }

    /// A link from a contact trace, regardless of geometry.
    fn force_link(&mut self, a: NodeId, b: NodeId, techs: Techs, up: bool) {
        if a == b || a as usize >= self.core.nodes.len() || b as usize >= self.core.nodes.len() {
            return;
        }
        let has = self.core.nodes[a as usize].nbrs.contains_key(&b);
        if has == up {
            return;
        }
        let now = self.now;
        self.core.link_events += 1;
        if up {
            self.core.nodes[a as usize].nbrs.insert(b, (techs, now));
            self.core.nodes[b as usize].nbrs.insert(a, (techs, now));
            self.core.contacts.open_radio(a, b, now, techs);
        } else {
            self.core.nodes[a as usize].nbrs.remove(&b);
            self.core.nodes[b as usize].nbrs.remove(&a);
            self.core.contacts.close_radio(a, b, now);
        }
        {
            let (r, mut cx) = self.cx(a);
            r.on_link(&mut cx, b, techs, up);
        }
        let (r, mut cx) = self.cx(b);
        r.on_link(&mut cx, a, techs, up);
    }

    fn set_online(&mut self, n: NodeId, on: bool) {
        if self.core.nodes[n as usize].online == on {
            return;
        }
        let had_inet = self.core.nodes[n as usize].online && self.core.nodes[n as usize].inet_up;
        self.core.nodes[n as usize].online = on;
        let now = self.now;
        let has_inet = on && self.core.nodes[n as usize].inet_up;
        if had_inet != has_inet {
            self.core.contacts.set_inet(n, has_inet, now);
        }
        {
            let (r, mut cx) = self.cx(n);
            r.on_online(&mut cx, on);
        }
        self.relink(n);
    }

    fn set_inet(&mut self, n: NodeId, up: bool) {
        if self.core.nodes[n as usize].spec.inet.is_none() {
            return;
        }
        let before = self.core.nodes[n as usize].online && self.core.nodes[n as usize].inet_up;
        self.core.nodes[n as usize].inet_up = up;
        let after = self.core.nodes[n as usize].online && up;
        if before != after {
            let now = self.now;
            self.core.contacts.set_inet(n, after, now);
            let (r, mut cx) = self.cx(n);
            r.on_inet(&mut cx, after);
        }
    }

    fn move_to(&mut self, n: NodeId, xy: (f64, f64)) {
        let old = self.core.cell(self.core.nodes[n as usize].spec.xy);
        let new = self.core.cell(xy);
        let area = self.core.nodes[n as usize].spec.area as usize;
        if old != new {
            if let Some(v) = self.core.grids[area].get_mut(&old) {
                v.retain(|m| *m != n);
            }
            self.core.grids[area].entry(new).or_default().push(n);
        }
        self.core.nodes[n as usize].spec.xy = xy;
    }

    fn mobility(&mut self) {
        let step = self.core.mobility_step;
        let now = self.now;
        let mut moved = Vec::new();
        for i in 0..self.core.nodes.len() {
            let mob = self.core.nodes[i].spec.mobility.clone();
            let xy = self.core.nodes[i].spec.xy;
            let next = match mob {
                Mobility::Static => continue,
                Mobility::Waypoint { w, h, speed, pause } => {
                    if self.core.nodes[i].wp_wait_until > now {
                        continue;
                    }
                    let target = match self.core.nodes[i].wp_target {
                        Some(t) => t,
                        None => {
                            let t = (self.core.mob_rng.range(0.0, w), self.core.mob_rng.range(0.0, h));
                            self.core.nodes[i].wp_target = Some(t);
                            t
                        }
                    };
                    let d = ((target.0 - xy.0).powi(2) + (target.1 - xy.1).powi(2)).sqrt();
                    let go = speed * step as f64 / SEC as f64;
                    if d <= go {
                        self.core.nodes[i].wp_target = None;
                        self.core.nodes[i].wp_wait_until = now + pause;
                        target
                    } else {
                        (xy.0 + (target.0 - xy.0) * go / d, xy.1 + (target.1 - xy.1) * go / d)
                    }
                }
                Mobility::Path(ref pts) => {
                    let Some(i1) = pts.iter().position(|p| p.0 > now) else {
                        let last = pts.last().map(|p| p.1).unwrap_or(xy);
                        if last == xy {
                            continue;
                        }
                        self.move_to(i as NodeId, last);
                        moved.push(i as NodeId);
                        continue;
                    };
                    if i1 == 0 {
                        pts[0].1
                    } else {
                        let (t0, a) = pts[i1 - 1];
                        let (t1, b) = pts[i1];
                        let f = (now - t0) as f64 / (t1 - t0).max(1) as f64;
                        (a.0 + (b.0 - a.0) * f, a.1 + (b.1 - a.1) * f)
                    }
                }
            };
            if next != xy {
                self.move_to(i as NodeId, next);
                moved.push(i as NodeId);
            }
        }
        for n in moved {
            self.relink(n);
        }
        self.core.push(now + step, Ev::Mobility);
    }

    /// Run until `until` (or the queue empties).
    pub fn run(&mut self, until: Time) {
        while let Some(Reverse((at, _, slot))) = self.core.queue.peek().copied() {
            if at > until {
                break;
            }
            self.core.queue.pop();
            let ev = self.core.events[slot].take().expect("event");
            self.core.free.push(slot);
            self.now = at;
            self.core.events_run += 1;
            self.core.events_by_kind[match &ev {
                Ev::Frame { .. } => 0,
                Ev::Timer { .. } => 1,
                Ev::Dir { .. } | Ev::Reach { .. } => 2,
                Ev::Send { .. } => 3,
                Ev::Mobility => 4,
                Ev::Act(_) => 5,
                Ev::Probe => 6,
            }] += 1;
            match ev {
                Ev::Frame { to, from, over, f, link_since } => {
                    let ok = match over {
                        // the link must still be the same one (not broken and remade)
                        Over::Radio(_) => {
                            self.core.nodes[to as usize].nbrs.get(&from).is_some_and(|x| x.1 <= link_since)
                        }
                        Over::Inet => self.core.nodes[to as usize].online && self.core.nodes[to as usize].inet_up,
                    };
                    if !ok {
                        self.core.counters[from as usize].dropped_link += 1;
                        let (r, mut cx) = self.cx(from);
                        r.on_undelivered(&mut cx, to, f);
                        continue;
                    }
                    let (r, mut cx) = self.cx(to);
                    r.on_frame(&mut cx, from, over, f);
                }
                Ev::Timer { node, token } => {
                    let (r, mut cx) = self.cx(node);
                    r.on_timer(&mut cx, token);
                }
                Ev::Dir { node, token, subject } => {
                    let mut recs = self.core.directory.get(&subject).cloned().unwrap_or_default();
                    if let Some(sybil) = self.core.dir_poison {
                        // a Sybil gateway claims everyone, cheaply and freshly
                        recs.push(DirRecord { subject, gateway: sybil, cost: 0, at: self.now });
                    }
                    let (r, mut cx) = self.cx(node);
                    r.on_dir(&mut cx, token, recs);
                }
                Ev::Reach { node, token, subject } => {
                    let s = &self.core.nodes[subject as usize];
                    let answer = if s.online && s.inet_up {
                        None // on the internet itself: its own record has its relay address
                    } else {
                        let life = self.core.reach_lifetime;
                        let mut rec = self
                            .core
                            .reach
                            .get(&subject)
                            .filter(|(_, at)| self.now.saturating_sub(*at) < life)
                            .map(|(g, _)| g.clone());
                        if let Some(sybil) = self.core.dir_poison {
                            rec.get_or_insert_with(Vec::new).insert(0, (sybil, 0));
                        }
                        rec
                    };
                    let (r, mut cx) = self.cx(node);
                    r.on_reach(&mut cx, token, answer);
                }
                Ev::Send { msg } => {
                    let (src, dst, size) = {
                        let m = &self.core.msgs[msg as usize];
                        (m.src, m.dst, m.size)
                    };
                    let (r, mut cx) = self.cx(src);
                    r.on_send(&mut cx, msg, dst, size);
                }
                Ev::Mobility => self.mobility(),
                Ev::Act(a) => match a {
                    Action::Online(n, on) => self.set_online(n, on),
                    Action::Inet(n, up) => self.set_inet(n, up),
                    Action::Move(n, xy) => {
                        self.move_to(n, xy);
                        self.relink(n);
                    }
                    Action::Contact(a, b, techs, up) => self.force_link(a, b, techs, up),
                },
                Ev::Probe => {
                    let now = self.now;
                    let mut probes = std::mem::take(&mut self.core.probes);
                    let mut next = Time::MAX;
                    for (every, f) in probes.iter_mut() {
                        if now.is_multiple_of(*every) {
                            f(&self.core, now);
                        }
                        next = next.min((now / *every + 1) * *every);
                    }
                    self.core.probes = probes;
                    if next != Time::MAX {
                        self.core.push(next, Ev::Probe);
                    }
                }
            }
        }
        self.now = self.now.max(until);
    }

    /// Close open contact intervals at the end (for the oracle).
    pub fn finish(&mut self) {
        let end = self.now;
        for v in self.core.contacts.radio.values_mut() {
            for c in v.iter_mut() {
                if c.1 == Time::MAX {
                    c.1 = end;
                }
            }
        }
        for v in self.core.contacts.inet.iter_mut() {
            for c in v.iter_mut() {
                if c.1 == Time::MAX {
                    c.1 = end;
                }
            }
        }
    }

    /// One-way internet delay a → b ignoring whether they're online now
    /// (the oracle checks the contact plan for that).
    pub fn inet_delay_any(&self, a: NodeId, b: NodeId) -> Time {
        inet_delay_static(&self.core, a, b)
    }
}
