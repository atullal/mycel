//! The BLE connection state machine (`mycel_link_ble::core::Core`) of two
//! devices under every interleaving of radio events.
//!
//! **World.** The radio is the model `crates/mycel-link-ble/src/sim.rs`
//! uses, itself what two real Macs showed (docs/TESTING.md): scanning
//! reports a peripheral once per scan session (only a rescan reports it
//! again); a connect completes, fails or hangs forever (a stale handle);
//! reading the GATT info and opening an L2CAP channel complete or fail;
//! a channel's two ends each get the other's hello; a channel we close
//! ourselves is not reported back to us, the other end sees it closed; our
//! own disconnect is reported back as `Disconnected`, and kills the
//! channels we dialed over it. Faults, each bounded: an outcome fails, a
//! connect hangs, the radio link drops (every connection and channel
//! between the two ends, with `Disconnected` and `ChannelClosed`), the
//! stack closes one channel. Jitter is off (`model_seed`), and the clock
//! jumps by [`BleModel::advances`], each followed by both devices' `Tick`.
//!
//! **Properties.**
//! - *Found/Lost alternate* (every state): a node is never reported found
//!   twice, nor lost without being found (what the node above relies on).
//! - *routes mirror the core* (every state): the `Route`/`Unroute`
//!   commands leave the platform routing exactly what the core's active
//!   table says, over a channel end that is open or whose close is still
//!   on its way to it.
//! - *relinks* (recovery from every reachable state): once faults stop,
//!   within a bounded fair run (events delivered, ticks every second) both
//!   devices route to each other over the two ends of one channel and no
//!   other channel is left open: no stuck state, no duplicate live link, and
//!   every Lost is followed by a Found while the peer advertises.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use mycel_crypto::SignPk;
use mycel_link_ble::core::{ChanId, Cmd, Core, Input, Pid};
use mycel_link_ble::wire::GattInfo;
use stateright::{Model, Property};

/// The model's clock origin; states hold offsets from it.
static T0: LazyLock<Instant> = LazyLock::new(Instant::now);

pub fn key(i: u8) -> SignPk {
    SignPk([0x10 + i; 32])
}

fn pid_of(target: u8) -> Pid {
    format!("p{target}")
}

fn target(pid: &str) -> u8 {
    pid[1..].parse().unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Budget {
    pub steps: u8,
    /// Outcomes that fail, and connects that hang.
    pub fails: u8,
    /// The radio link dropping, or the stack closing a channel.
    pub drops: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ev {
    Discover { scanner: u8, target: u8, session: u32 },
    ConnectDone { n: u8, pid: Pid, attempt: u32 },
    InfoDone { n: u8, pid: Pid },
    OpenDone { n: u8, pid: Pid },
    Hello { pair: u32, to_dialer: bool },
    Disconnected { n: u8, pid: Pid },
    ChannelClosed { n: u8, chan: ChanId },
    OpenFailed { n: u8, pid: Pid },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Ref {
    Pending(u32),
    Connected,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pair {
    dialer: (u8, ChanId),
    acceptor: (u8, ChanId),
    via: (u8, Pid),
    alive: bool,
}

#[derive(Clone)]
pub struct State {
    /// ms since the model's clock origin.
    pub now: u64,
    pub cores: Vec<Core>,
    refs: BTreeMap<(u8, Pid), Ref>,
    pairs: BTreeMap<u32, Pair>,
    ends: BTreeMap<(u8, ChanId), u32>,
    next_chan: ChanId,
    attempts: u32,
    sessions: Vec<u32>,
    reported: Vec<BTreeSet<Pid>>,
    pub events: Vec<Ev>,
    /// What the platform routes, per device (from `Route`/`Unroute`).
    routes: Vec<BTreeMap<SignPk, ChanId>>,
    /// Per device and peer: found (true) or lost (false) last.
    found: Vec<BTreeMap<SignPk, bool>>,
    /// A broken Found/Lost alternation, if one happened.
    pub broken: Option<String>,
    pub left: Budget,
}

impl State {
    fn text(&self) -> String {
        format!(
            "{}|{:?}|{:?}|{:?}|{:?}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            self.now,
            self.left,
            self.refs,
            self.pairs,
            self.ends,
            self.next_chan,
            self.attempts,
            self.sessions,
            self.reported,
            self.events,
            self.routes,
            self.found,
            self.broken,
            self.cores
        )
    }

    fn at(&self) -> Instant {
        *T0 + Duration::from_millis(self.now)
    }

    fn link_up(&self) -> bool {
        self.refs.values().any(|r| *r == Ref::Connected)
    }

    /// Both devices route to each other over the two ends of the one
    /// channel left open.
    pub fn settled(&self) -> bool {
        let alive: Vec<&Pair> = self.pairs.values().filter(|p| p.alive).collect();
        if alive.len() != 1 {
            return false;
        }
        let p = alive[0];
        let route = |n: u8| self.routes[n as usize].get(&key(1 - n)).copied();
        let end = |n: u8| if p.dialer.0 == n { p.dialer.1 } else { p.acceptor.1 };
        route(0) == Some(end(0)) && route(1) == Some(end(1))
    }

    pub fn routes_mirror(&self) -> bool {
        (0..2u8).all(|n| {
            let active: BTreeMap<SignPk, ChanId> = self.cores[n as usize].model_active().into_iter().collect();
            active == self.routes[n as usize]
                && active.values().all(|c| {
                    self.ends.get(&(n, *c)).is_some_and(|id| self.pairs[id].alive)
                        || self.events.contains(&Ev::ChannelClosed { n, chan: *c })
                })
        })
    }
}

impl Hash for State {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.text().hash(h);
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.text() == other.text()
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={}ms left={:?} refs={:?}", self.now, self.left, self.refs)?;
        for n in 0..2 {
            write!(
                f,
                "\n  d{n}: phases={:?} chans={:?} routes={:?}",
                self.cores[n].model_phases(),
                self.cores[n].model_chans().iter().map(|c| (c.0, c.2, c.3, c.4)).collect::<Vec<_>>(),
                self.routes[n].values().collect::<Vec<_>>()
            )?;
        }
        write!(f, "\n  pairs={:?}\n  events={:?}", self.pairs.values().collect::<Vec<_>>(), self.events)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Fire(usize),
    /// The event's operation fails (connect, read, open), or a connect hangs.
    Fail(usize),
    Hang(usize),
    LinkDrop,
    ChanDrop(u32),
    Advance(u64),
}

#[derive(Clone, Debug)]
pub struct BleModel {
    pub budget: Budget,
    pub advances: Vec<u64>,
    /// Cancelling our side of a connected link tears the whole link down
    /// (seen between two Macs; `sim.rs`'s `harsh_cancel`).
    pub harsh_cancel: bool,
    pub recovery_rounds: u32,
}

impl Default for BleModel {
    fn default() -> Self {
        BleModel {
            budget: Budget { steps: 1, fails: 1, drops: 1 },
            // the higher key's open delay (1.5 s), the duplicate grace
            // (5 s), the rescan period, setup timeout and largest backoff
            // (10 s)
            advances: vec![1_500, 5_000, 10_000],
            harsh_cancel: false,
            recovery_rounds: 120,
        }
    }
}

impl BleModel {
    pub fn bound(&self) -> String {
        format!(
            "2 devices, steps {:?} ms, budget {:?}, harsh cancel {}, recovery {} s",
            self.advances, self.budget, self.harsh_cancel, self.recovery_rounds
        )
    }

    pub fn start(&self) -> State {
        let _ = *T0;
        let cores = (0..2u8)
            .map(|i| {
                let mut c = Core::new(key(i), *T0);
                c.model_seed(1 + i as u64, Duration::ZERO);
                c
            })
            .collect();
        State {
            now: 0,
            cores,
            refs: BTreeMap::new(),
            pairs: BTreeMap::new(),
            ends: BTreeMap::new(),
            next_chan: 1,
            attempts: 0,
            sessions: vec![0, 0],
            reported: vec![BTreeSet::new(), BTreeSet::new()],
            // both start scanning
            events: vec![
                Ev::Discover { scanner: 0, target: 1, session: 0 },
                Ev::Discover { scanner: 1, target: 0, session: 0 },
            ],
            routes: vec![BTreeMap::new(), BTreeMap::new()],
            found: vec![BTreeMap::new(), BTreeMap::new()],
            broken: None,
            left: self.budget,
        }
    }

    fn input(&self, s: &mut State, n: u8, i: Input) {
        let now = s.at();
        let cmds = s.cores[n as usize].handle(now, i);
        for c in cmds {
            self.exec(s, n, c);
        }
    }

    fn kill_pair(s: &mut State, id: u32, tell_dialer: bool, tell_acceptor: bool) {
        let Some(p) = s.pairs.get_mut(&id) else { return };
        if !p.alive {
            return;
        }
        p.alive = false;
        let (d, a) = (p.dialer, p.acceptor);
        for (end, tell) in [(d, tell_dialer), (a, tell_acceptor)] {
            if tell {
                s.events.push(Ev::ChannelClosed { n: end.0, chan: end.1 });
            }
        }
    }

    fn drop_link(s: &mut State) {
        let refs: Vec<(u8, Pid)> =
            s.refs.iter().filter(|(_, r)| **r == Ref::Connected).map(|(k, _)| k.clone()).collect();
        for (owner, pid) in refs {
            s.refs.remove(&(owner, pid.clone()));
            s.events.push(Ev::Disconnected { n: owner, pid });
        }
        let ids: Vec<u32> = s.pairs.iter().filter(|(_, p)| p.alive).map(|(id, _)| *id).collect();
        for id in ids {
            Self::kill_pair(s, id, true, true);
        }
    }

    fn exec(&self, s: &mut State, n: u8, cmd: Cmd) {
        match cmd {
            Cmd::Connect(pid) => {
                s.attempts += 1;
                let attempt = s.attempts;
                s.refs.insert((n, pid.clone()), Ref::Pending(attempt));
                s.events.push(Ev::ConnectDone { n, pid, attempt });
            }
            Cmd::Disconnect(pid) => {
                if s.refs.remove(&(n, pid.clone())) == Some(Ref::Connected) {
                    if self.harsh_cancel || !s.link_up() {
                        Self::drop_link(s);
                    } else {
                        let ours: Vec<u32> = s
                            .pairs
                            .iter()
                            .filter(|(_, p)| p.alive && p.via == (n, pid.clone()))
                            .map(|(i, _)| *i)
                            .collect();
                        for id in ours {
                            Self::kill_pair(s, id, true, true);
                        }
                    }
                    s.events.push(Ev::Disconnected { n, pid });
                }
            }
            Cmd::Forget(pid) => {
                if matches!(s.refs.get(&(n, pid.clone())), Some(Ref::Pending(_))) {
                    s.refs.remove(&(n, pid));
                }
            }
            Cmd::ReadInfo(pid) => {
                if s.refs.get(&(n, pid.clone())) == Some(&Ref::Connected) {
                    s.events.push(Ev::InfoDone { n, pid });
                }
            }
            Cmd::OpenChannel(pid, _) => {
                if s.refs.get(&(n, pid.clone())) == Some(&Ref::Connected) {
                    s.events.push(Ev::OpenDone { n, pid });
                } else {
                    s.events.push(Ev::OpenFailed { n, pid });
                }
            }
            Cmd::CloseChannel(c) => {
                if let Some(&id) = s.ends.get(&(n, c)) {
                    let we_dialed = s.pairs[&id].dialer == (n, c);
                    Self::kill_pair(s, id, !we_dialed, we_dialed);
                }
            }
            Cmd::Rescan => {
                s.sessions[n as usize] += 1;
                s.reported[n as usize].clear();
                let session = s.sessions[n as usize];
                s.events.push(Ev::Discover { scanner: n, target: 1 - n, session });
            }
            Cmd::Route { key, chan } => {
                s.routes[n as usize].insert(key, chan);
            }
            Cmd::Unroute { key } => {
                s.routes[n as usize].remove(&key);
            }
            Cmd::Found { key, .. } => {
                if s.found[n as usize].insert(key, true) == Some(true) && s.broken.is_none() {
                    s.broken = Some(format!("d{n}: Found twice without Lost"));
                }
            }
            Cmd::Lost { key } => {
                if s.found[n as usize].insert(key, false) != Some(true) && s.broken.is_none() {
                    s.broken = Some(format!("d{n}: Lost without Found"));
                }
            }
        }
    }

    fn fire(&self, s: &mut State, ev: Ev) {
        match ev {
            Ev::Discover { scanner, target, session } => {
                let pid = pid_of(target);
                if s.sessions[scanner as usize] == session && s.reported[scanner as usize].insert(pid.clone()) {
                    self.input(s, scanner, Input::Discovered(pid));
                }
            }
            Ev::ConnectDone { n, pid, attempt } => {
                if s.refs.get(&(n, pid.clone())) == Some(&Ref::Pending(attempt)) {
                    s.refs.insert((n, pid.clone()), Ref::Connected);
                    self.input(s, n, Input::Connected(pid));
                }
            }
            Ev::InfoDone { n, pid } => {
                if s.refs.get(&(n, pid.clone())) != Some(&Ref::Connected) {
                    return;
                }
                let o = target(&pid);
                let info = GattInfo { psm: 0x80 + o as u16, key: key(o), name: format!("n{o}") };
                self.input(s, n, Input::Info(pid, info));
            }
            Ev::OpenDone { n, pid } => {
                if s.refs.get(&(n, pid.clone())) != Some(&Ref::Connected) {
                    return self.input(s, n, Input::OpenFailed(pid));
                }
                let o = target(&pid);
                let (cd, ca) = (s.next_chan, s.next_chan + 1);
                s.next_chan += 2;
                let id = s.pairs.len() as u32;
                s.pairs.insert(id, Pair { dialer: (n, cd), acceptor: (o, ca), via: (n, pid.clone()), alive: true });
                s.ends.insert((n, cd), id);
                s.ends.insert((o, ca), id);
                self.input(s, n, Input::ChannelOpened { chan: cd, pid: Some(pid) });
                self.input(s, o, Input::ChannelOpened { chan: ca, pid: None });
                s.events.push(Ev::Hello { pair: id, to_dialer: true });
                s.events.push(Ev::Hello { pair: id, to_dialer: false });
            }
            Ev::Hello { pair, to_dialer } => {
                let p = s.pairs[&pair].clone();
                if !p.alive {
                    return;
                }
                let (to, from) = if to_dialer { (p.dialer, p.acceptor) } else { (p.acceptor, p.dialer) };
                self.input(s, to.0, Input::Hello { chan: to.1, key: key(from.0), name: format!("n{}", from.0) });
            }
            Ev::Disconnected { n, pid } => self.input(s, n, Input::Disconnected(pid)),
            Ev::ChannelClosed { n, chan } => self.input(s, n, Input::ChannelClosed(chan)),
            Ev::OpenFailed { n, pid } => self.input(s, n, Input::OpenFailed(pid)),
        }
    }

    /// The failing outcome of an event, if it has one.
    fn fail(&self, s: &mut State, ev: Ev) {
        match ev {
            Ev::ConnectDone { n, pid, attempt } => {
                if s.refs.get(&(n, pid.clone())) == Some(&Ref::Pending(attempt)) {
                    s.refs.remove(&(n, pid.clone()));
                    self.input(s, n, Input::ConnectFailed(pid));
                }
            }
            Ev::InfoDone { n, pid } => {
                if s.refs.get(&(n, pid.clone())) == Some(&Ref::Connected) {
                    self.input(s, n, Input::InfoFailed(pid));
                }
            }
            Ev::OpenDone { n, pid } => self.input(s, n, Input::OpenFailed(pid)),
            other => self.fire(s, other),
        }
    }

    fn advance(&self, s: &mut State, dt: u64) {
        s.now += dt;
        for n in 0..2 {
            self.input(s, n, Input::Tick);
        }
    }

    fn settle(s: &mut State) {
        s.events.sort();
    }

    pub fn recovers(&self, s: &State) -> bool {
        let mut s = s.clone();
        for _ in 0..self.recovery_rounds {
            while !s.events.is_empty() {
                let ev = s.events.remove(0);
                self.fire(&mut s, ev);
            }
            if s.settled() {
                return true;
            }
            self.advance(&mut s, 1_000);
        }
        false
    }
}

impl Model for BleModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        vec![self.start()]
    }

    fn actions(&self, s: &State, out: &mut Vec<Action>) {
        for (i, ev) in s.events.iter().enumerate() {
            out.push(Action::Fire(i));
            if s.left.fails > 0 {
                match ev {
                    Ev::ConnectDone { .. } => {
                        out.push(Action::Fail(i));
                        out.push(Action::Hang(i));
                    }
                    Ev::InfoDone { .. } | Ev::OpenDone { .. } => out.push(Action::Fail(i)),
                    _ => {}
                }
            }
        }
        if s.left.drops > 0 {
            if s.link_up() {
                out.push(Action::LinkDrop);
            }
            for (id, p) in &s.pairs {
                if p.alive {
                    out.push(Action::ChanDrop(*id));
                }
            }
        }
        if s.left.steps > 0 {
            for &dt in &self.advances {
                out.push(Action::Advance(dt));
            }
        }
    }

    fn next_state(&self, last: &State, action: Action) -> Option<State> {
        let mut s = last.clone();
        match action {
            Action::Fire(i) => {
                let ev = s.events.remove(i);
                self.fire(&mut s, ev);
            }
            Action::Fail(i) => {
                s.left.fails -= 1;
                let ev = s.events.remove(i);
                self.fail(&mut s, ev);
            }
            Action::Hang(i) => {
                // the connect never completes; the handle stays pending
                s.left.fails -= 1;
                s.events.remove(i);
            }
            Action::LinkDrop => {
                s.left.drops -= 1;
                Self::drop_link(&mut s);
            }
            Action::ChanDrop(id) => {
                s.left.drops -= 1;
                Self::kill_pair(&mut s, id, true, true);
            }
            Action::Advance(dt) => {
                s.left.steps -= 1;
                self.advance(&mut s, dt);
            }
        }
        Self::settle(&mut s);
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("Found/Lost alternate", |_, s: &State| s.broken.is_none()),
            Property::always("routes mirror the core", |_, s: &State| s.routes_mirror()),
            Property::always("relinks", |m: &BleModel, s: &State| m.recovers(s)),
            Property::sometimes("linked", |_, s: &State| s.settled()),
        ]
    }
}
