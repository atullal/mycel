//! The mesh router (`mesh::core::Router`) under every interleaving of a
//! few devices.
//!
//! **World.** `n` routers with the default [`Config`], stubbed signatures
//! (every announcement verifies: signatures are not what loop freedom rests
//! on). Announcements and seqno requests are QUIC datagrams in the real
//! driver, so the network may lose, duplicate (bounded) and reorder them
//! freely. A hop connection going down drops what was in flight on it and
//! tells both ends (`hop_down`, `set_direct(false)`); one coming up tells
//! both (`set_direct(true)`, `hop_up`). Measured hop costs change by
//! `set_cost` on one end (measurements are per end). Time is one global
//! clock that jumps by [`RouterModel::advances`]; each jump runs the
//! driver's step: originate when due, then `tick`.
//!
//! **Start.** Either cold (links up, nothing heard) or warm: the same world
//! run fairly (every datagram delivered, time stepping 50 ms) until routes
//! have converged, which is where loops in distance-vector protocols come
//! from (a link breaking under converged routes, count to infinity).
//!
//! **Properties** (every reachable state):
//! - *loop-free*: for every origin, the graph of every usable route's next
//!   hop (what `next_hop_local` and packet forwarding choose among: Mycel
//!   forwards over any feasible route, not only the best) has no cycle;
//! - *feasible*: every usable route meets Babel's feasibility condition
//!   against its router's feasibility distance (RFC 8966 §3.5.1);
//! - *advertised ≥ FD*: every usable route's advertised (seqno, cost) is no
//!   better than its advertiser's current feasibility distance: the
//!   inductive invariant that, with *feasible*, makes loops impossible.

use std::collections::BTreeSet;
use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};

use mycel_crypto::{Sig, SignPk};
use mycel_net::mesh::core::{Announce, Config, Out, Router, SeqReq, Time};
use stateright::{Model, Property};

/// Wall clock at virtual time 0 (seqnos are wall-clock ms).
const WALL0: u64 = 1_800_000_000_000;

/// Device `i`'s key.
pub fn key(i: u8) -> SignPk {
    SignPk([i + 1; 32])
}

fn index(k: &SignPk) -> u8 {
    k.0[0] - 1
}

/// What may still happen (every action that adds behaviour spends one).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Budget {
    /// Clock jumps.
    pub steps: u8,
    /// Links going down or coming up.
    pub links: u8,
    /// Hop cost changes.
    pub costs: u8,
    /// Datagrams lost.
    pub losses: u8,
    /// Datagrams duplicated.
    pub dups: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Ann(Announce),
    Req(SeqReq),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Msg {
    pub from: u8,
    pub to: u8,
    pub body: Body,
}

#[derive(Clone)]
pub struct State {
    pub now: Time,
    pub routers: Vec<Router>,
    /// Links up, as (lower, higher).
    pub links: BTreeSet<(u8, u8)>,
    /// In flight, kept sorted (delivery picks any: datagrams reorder).
    pub net: Vec<Msg>,
    pub left: Budget,
}

impl State {
    fn text(&self) -> String {
        format!("{}|{:?}|{:?}|{:?}|{:?}", self.now, self.left, self.links, self.net, self.routers)
    }

    /// Usable next hops toward `origin` at router `i`.
    fn usable(&self, i: usize, origin: &SignPk) -> Vec<SignPk> {
        self.routers[i].model_usable(origin, self.now)
    }

    /// The first routing loop over usable routes, as the devices on it.
    pub fn find_loop(&self) -> Option<(u8, Vec<u8>)> {
        let n = self.routers.len();
        for o in 0..n as u8 {
            let origin = key(o);
            let edges: Vec<Vec<u8>> = (0..n)
                .map(|i| {
                    if i as u8 == o {
                        return Vec::new();
                    }
                    self.usable(i, &origin).iter().map(index).filter(|j| *j != o).collect()
                })
                .collect();
            // depth-first search for a back edge
            let mut colour = vec![0u8; n];
            let mut stack: Vec<u8> = Vec::new();
            fn visit(v: u8, e: &[Vec<u8>], c: &mut [u8], st: &mut Vec<u8>) -> Option<Vec<u8>> {
                c[v as usize] = 1;
                st.push(v);
                for &w in &e[v as usize] {
                    if c[w as usize] == 1 {
                        let at = st.iter().position(|x| *x == w).unwrap_or(0);
                        return Some(st[at..].to_vec());
                    }
                    if c[w as usize] == 0
                        && let Some(cy) = visit(w, e, c, st)
                    {
                        return Some(cy);
                    }
                }
                st.pop();
                c[v as usize] = 2;
                None
            }
            for v in 0..n as u8 {
                if colour[v as usize] == 0
                    && let Some(cy) = visit(v, &edges, &mut colour, &mut stack)
                {
                    return Some((o, cy));
                }
            }
        }
        None
    }

    /// Every usable route meets the feasibility condition at its router.
    pub fn feasible(&self) -> bool {
        let n = self.routers.len();
        (0..n).all(|i| {
            let r = &self.routers[i];
            r.model_origins().iter().all(|o| {
                let fd = r.model_fd(o);
                r.model_vias(o, self.now).iter().filter(|v| v.usable).all(|v| match fd {
                    None => true,
                    Some((s, c)) => v.seq > s || (v.seq == s && v.adv < c),
                })
            })
        })
    }

    /// Every usable route's advertisement is no better than its
    /// advertiser's feasibility distance now.
    pub fn advertised_bounded(&self) -> bool {
        let n = self.routers.len();
        (0..n).all(|i| {
            let r = &self.routers[i];
            r.model_origins().iter().all(|o| {
                r.model_vias(o, self.now).iter().filter(|v| v.usable && v.via != *o).all(|v| {
                    let j = index(&v.via) as usize;
                    match self.routers.get(j).and_then(|a| a.model_fd(o)) {
                        Some((s, c)) => s > v.seq || (s == v.seq && c <= v.adv),
                        None => false,
                    }
                })
            })
        })
    }

    /// Some device has no usable route to another it is connected to (a
    /// fault bit).
    pub fn some_route_missing(&self) -> bool {
        let n = self.routers.len();
        (0..n).any(|i| {
            (0..n).any(|o| {
                o != i
                    && self.connected(i as u8, o as u8)
                    && self.routers[i].next_hop_local(&key(o as u8), self.now).is_none()
            })
        })
    }

    fn connected(&self, a: u8, b: u8) -> bool {
        let mut seen = BTreeSet::from([a]);
        let mut todo = vec![a];
        while let Some(x) = todo.pop() {
            for &(p, q) in &self.links {
                let y = if p == x {
                    q
                } else if q == x {
                    p
                } else {
                    continue;
                };
                if seen.insert(y) {
                    todo.push(y);
                }
            }
        }
        seen.contains(&b)
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
    /// The routing view (a counterexample path prints one per step): each
    /// router's usable next hops and feasibility distance per origin.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} links={:?} in-flight={} left={:?}", self.now, self.links, self.net.len(), self.left)?;
        for (i, r) in self.routers.iter().enumerate() {
            write!(f, "\n  r{i}:")?;
            for o in r.model_origins() {
                let vias: Vec<String> = r
                    .model_vias(&o, self.now)
                    .iter()
                    .map(|v| {
                        format!("{}{}@{}/{}", if v.usable { "" } else { "~" }, index(&v.via), v.seq % 100_000, v.adv)
                    })
                    .collect();
                let fd = r.model_fd(&o).map(|(s, c)| format!("{}/{c}", s % 100_000));
                write!(f, " [o{} fd={} {}]", index(&o), fd.unwrap_or_else(|| "-".into()), vias.join(","))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Deliver(usize),
    Lose(usize),
    Dup(usize),
    Down(u8, u8),
    Up(u8, u8),
    /// `set_cost` at the first device for its hop to the second.
    Cost(u8, u8, u32),
    Advance(Time),
}

/// A bounded configuration of the router model.
#[derive(Clone, Debug)]
pub struct RouterModel {
    pub n: u8,
    /// Links up at the start.
    pub initial: Vec<(u8, u8)>,
    /// Links that may go down or come up.
    pub flappable: Vec<(u8, u8)>,
    /// Start from converged routes (else cold).
    pub warm: bool,
    pub budget: Budget,
    /// Clock jumps (ms).
    pub advances: Vec<Time>,
    /// Hop costs `Cost` may report (0.1 ms units).
    pub costs: Vec<u32>,
    pub cfg: Config,
    /// Plant the bug of the acceptance test ([`Router::model_plant_infeasible`]).
    pub planted: bool,
}

impl RouterModel {
    /// The default bound: `n` devices on `initial` links.
    pub fn new(n: u8, initial: &[(u8, u8)]) -> Self {
        RouterModel {
            n,
            initial: initial.to_vec(),
            flappable: initial.to_vec(),
            warm: true,
            budget: Budget { steps: 2, links: 1, costs: 1, losses: 1, dups: 0 },
            // a rebroadcast's jitter (10–50 ms); seqno-request and forced
            // announcement gaps (1 s, 0.5 s); a greeting gap (4 s); the
            // announcement period (16 s)
            advances: vec![60, 1_100, 4_100, 16_000],
            costs: vec![40, 2_000],
            cfg: Config::default(),
            planted: false,
        }
    }

    /// One line describing the bound, for reports.
    pub fn bound(&self) -> String {
        format!(
            "{} devices, links {:?} ({} flappable), {}, steps {:?}, budget {:?}{}",
            self.n,
            self.initial,
            self.flappable.len(),
            if self.warm { "warm" } else { "cold" },
            self.advances,
            self.budget,
            if self.planted { ", PLANTED BUG" } else { "" }
        )
    }

    fn link(a: u8, b: u8) -> (u8, u8) {
        (a.min(b), a.max(b))
    }

    /// Collect what router `i` wants sent, onto links that are up.
    fn collect(s: &mut State, i: u8) {
        let mut outs = Vec::new();
        s.routers[i as usize].drain(&mut outs);
        for o in outs {
            let (to, body) = match o {
                Out::Announce { to, ann } => (to, Body::Ann(ann)),
                Out::SeqReq { to, req } => (to, Body::Req(req)),
                _ => continue,
            };
            let to = index(&to);
            if s.links.contains(&Self::link(i, to)) {
                s.net.push(Msg { from: i, to, body });
            }
        }
    }

    fn settle(s: &mut State) {
        s.net.sort_by_cached_key(|m| format!("{m:?}"));
    }

    fn deliver(s: &mut State, m: Msg) {
        let (now, wall) = (s.now, WALL0 + s.now);
        let r = &mut s.routers[m.to as usize];
        match m.body {
            Body::Ann(a) => r.on_announce(key(m.from), a, now, wall, |_| true),
            Body::Req(q) => r.on_seqreq(key(m.from), q, now),
        }
        Self::collect(s, m.to);
    }

    /// The driver's step after the clock moved: originate when due, tick.
    fn step(s: &mut State) {
        let (now, wall) = (s.now, WALL0 + s.now);
        for i in 0..s.routers.len() {
            let r = &mut s.routers[i];
            if r.announce_due(now) {
                let o = r.next_announce(wall);
                let ann = Announce {
                    hops: 0,
                    cost: 0,
                    origin: r.me(),
                    seq: o.seq,
                    flags: o.flags,
                    scope: o.scope,
                    uplink: o.uplink,
                    name: "".into(),
                    sig: Sig([0; 64]),
                };
                r.originate(ann, now);
            }
            r.tick(now);
            Self::collect(s, i as u8);
        }
    }

    fn up(s: &mut State, a: u8, b: u8) {
        s.links.insert(Self::link(a, b));
        let now = s.now;
        for (x, y) in [(a, b), (b, a)] {
            let r = &mut s.routers[x as usize];
            r.set_direct(key(y), true, now);
            r.hop_up(key(y), now);
        }
        Self::collect(s, a);
        Self::collect(s, b);
    }

    fn down(s: &mut State, a: u8, b: u8) {
        s.links.remove(&Self::link(a, b));
        s.net.retain(|m| Self::link(m.from, m.to) != Self::link(a, b));
        let now = s.now;
        for (x, y) in [(a, b), (b, a)] {
            let r = &mut s.routers[x as usize];
            r.hop_down(key(y), now);
            r.set_direct(key(y), false, now);
        }
        Self::collect(s, a);
        Self::collect(s, b);
    }

    /// The start: links up and, if warm, converged by a fair run.
    pub fn start(&self) -> State {
        let routers = (0..self.n)
            .map(|i| {
                let mut r = Router::new(key(i), Config { seed: 0x6d63 + i as u64, ..self.cfg.clone() });
                r.model_plant_infeasible(self.planted);
                r
            })
            .collect();
        let mut s = State { now: 0, routers, links: BTreeSet::new(), net: Vec::new(), left: self.budget };
        for &(a, b) in &self.initial {
            Self::up(&mut s, a, b);
        }
        if self.warm {
            // 3 announcement periods, every datagram delivered
            while s.now < 3 * self.cfg.announce_every {
                while !s.net.is_empty() {
                    let m = s.net.remove(0);
                    Self::deliver(&mut s, m);
                }
                s.now += 50;
                Self::step(&mut s);
            }
            while !s.net.is_empty() {
                let m = s.net.remove(0);
                Self::deliver(&mut s, m);
            }
        }
        Self::settle(&mut s);
        s
    }
}

impl Model for RouterModel {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        vec![self.start()]
    }

    fn actions(&self, s: &State, out: &mut Vec<Action>) {
        for (i, m) in s.net.iter().enumerate() {
            // identical copies: deliver the first only (same successor)
            if s.net[..i].contains(m) {
                continue;
            }
            out.push(Action::Deliver(i));
            if s.left.losses > 0 {
                out.push(Action::Lose(i));
            }
            if s.left.dups > 0 {
                out.push(Action::Dup(i));
            }
        }
        if s.left.links > 0 {
            for &(a, b) in &self.flappable {
                if s.links.contains(&(a, b)) {
                    out.push(Action::Down(a, b));
                } else {
                    out.push(Action::Up(a, b));
                }
            }
        }
        if s.left.costs > 0 {
            for &(a, b) in s.links.iter() {
                for &c in &self.costs {
                    out.push(Action::Cost(a, b, c));
                    out.push(Action::Cost(b, a, c));
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
            Action::Deliver(i) => {
                let m = s.net.remove(i);
                Self::deliver(&mut s, m);
            }
            Action::Lose(i) => {
                s.net.remove(i);
                s.left.losses -= 1;
            }
            Action::Dup(i) => {
                let m = s.net[i].clone();
                s.net.push(m);
                s.left.dups -= 1;
            }
            Action::Down(a, b) => {
                s.left.links -= 1;
                Self::down(&mut s, a, b);
            }
            Action::Up(a, b) => {
                s.left.links -= 1;
                Self::up(&mut s, a, b);
            }
            Action::Cost(a, b, c) => {
                s.left.costs -= 1;
                s.routers[a as usize].set_cost(key(b), c);
            }
            Action::Advance(dt) => {
                s.left.steps -= 1;
                s.now += dt;
                Self::step(&mut s);
            }
        }
        Self::settle(&mut s);
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("loop-free", |_, s: &State| s.find_loop().is_none()),
            Property::always("feasible", |_, s: &State| s.feasible()),
            Property::always("advertised >= advertiser's FD", |_, s: &State| s.advertised_bounded()),
            // sanity: the faults do take routes away somewhere
            Property::sometimes("a connected route is missing", |_, s: &State| s.some_route_missing()),
        ]
    }
}
