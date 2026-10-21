//! The store-and-forward carrier (`mesh::dtn::Carrier`) under every
//! interleaving of a few devices carrying one bundle.
//!
//! **World.** Device 0 originates one small bundle for device `n − 1`.
//! Each carrier exchange runs on its own QUIC stream in the real driver
//! (`mesh/mod.rs`): summaries on uni-streams, a transfer as offer → answer
//! → payload → one-byte result on a bi-stream. Streams are reliable while
//! their connection lives, and independent of each other, so messages may
//! be delivered in any order. Faults, each bounded:
//! - a link goes down (everything in flight on it is gone; the sender's
//!   transfers on it fail, `transferred(.., false)`) or comes up (both ends
//!   call `new_contact` and `encounter`, as the driver does);
//! - a stream is lost while its connection survives (the receiver's read
//!   timed out on a stalled link, or a budget refused it); if it belonged
//!   to a transfer, the sender times out (`transferred(.., false)`), as
//!   `send_bundle` does on its reply timeout.
//!
//! Next hops come from an oracle (shortest path over the links up): the
//! router is checked on its own ([`crate::router`]). Every transfer outcome
//! is reported exactly as the driver reports it. Lifetimes are long and
//! room is ample, so expiry and eviction (both by design) never drop it.
//!
//! **Properties.**
//! - *custody* (every state): until the destination has the bundle, some
//!   carrier holds it. A bundle taken into custody is never lost.
//! - *receipts clear every copy* (checked as recovery from every
//!   reachable state): once faults stop and the links come back, within a
//!   bounded fair run the bundle is delivered and no carrier still holds
//!   it, the source included (what receipts are for, docs/ROUTING.md §7.4).
//!
//!   The plan's first wording, "the receipt reaches the source", is
//!   stronger than the design and does not hold: a source that has handed
//!   every copy on is never told (found by this model: one lost summary
//!   stream is enough, docs/TESTING.md). A source still holding a copy is
//!   a carrier like any other and is covered.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use mycel_crypto::{Hash32, Sig, SignPk};
use mycel_net::mesh::core::{Time, Toward};
use mycel_net::mesh::dtn::{
    Accepted, Answer, Bundle, BundleFormat, Carrier, DtnConfig, Offer, Receipt, SUMMARY_FULL, SUMMARY_GAP, Summary,
};
use stateright::{Model, Property};

const WALL0: u64 = 1_800_000_000_000;
/// The bundle every run carries.
pub const BUNDLE: Hash32 = Hash32([0xb0; 32]);

pub fn key(i: u8) -> SignPk {
    SignPk([0x40 + i; 32])
}

fn index(k: &SignPk) -> u8 {
    k.0[0] - 0x40
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Budget {
    pub steps: u8,
    pub links: u8,
    /// Streams lost while their connection lives.
    pub drops: u8,
}

/// One exchange on a stream, `from` → `to`.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Summary(Summary),
    /// The offer (the payload follows only if it is taken).
    Offer(Offer),
    /// The receiver's answer, back to the sender.
    Answer(Hash32, u8, Answer),
    Payload(Bundle, u8),
    /// The one-byte result, back to the sender.
    Result(Hash32, u8, bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Msg {
    pub from: u8,
    pub to: u8,
    pub body: Body,
}

impl Msg {
    /// The transfer this belongs to, as (sender, receiver, bundle).
    fn transfer(&self) -> Option<(u8, u8, Hash32)> {
        match &self.body {
            Body::Summary(_) => None,
            Body::Offer(o) => Some((self.from, self.to, o.id)),
            Body::Payload(b, _) => Some((self.from, self.to, b.id)),
            Body::Answer(id, ..) | Body::Result(id, ..) => Some((self.to, self.from, *id)),
        }
    }
}

#[derive(Clone)]
pub struct State {
    pub now: Time,
    pub carriers: Vec<Carrier>,
    pub links: BTreeSet<(u8, u8)>,
    pub net: Vec<Msg>,
    /// Transfers the sender is waiting on: (sender, receiver, bundle) →
    /// (copies, the payload it streams once the offer is taken: the
    /// driver clones the bundle before the stream opens).
    pub waiting: BTreeMap<(u8, u8, Hash32), (u8, Bundle)>,
    /// The destination has the bundle.
    pub delivered: bool,
    pub left: Budget,
}

impl State {
    fn text(&self) -> String {
        format!(
            "{}|{:?}|{:?}|{:?}|{:?}|{}|{:?}",
            self.now, self.left, self.links, self.net, self.waiting, self.delivered, self.carriers
        )
    }

    fn holders(&self) -> Vec<u8> {
        (0..self.carriers.len() as u8).filter(|i| self.carriers[*i as usize].holds(&BUNDLE)).collect()
    }

    pub fn custody(&self) -> bool {
        self.delivered || !self.holders().is_empty()
    }

    fn neighbours(&self, i: u8) -> Vec<SignPk> {
        self.links
            .iter()
            .filter_map(|&(a, b)| {
                if a == i {
                    Some(key(b))
                } else if b == i {
                    Some(key(a))
                } else {
                    None
                }
            })
            .collect()
    }

    /// The oracle router: the first hop of a shortest path over the links
    /// up (the lowest-numbered on ties).
    fn toward(&self, from: u8, dst: u8) -> Toward {
        let n = self.carriers.len();
        let mut prev = vec![u8::MAX; n];
        let mut seen = vec![false; n];
        seen[from as usize] = true;
        let mut q = std::collections::VecDeque::from([from]);
        while let Some(x) = q.pop_front() {
            for k in self.neighbours(x) {
                let y = index(&k);
                if !seen[y as usize] {
                    seen[y as usize] = true;
                    prev[y as usize] = x;
                    q.push_back(y);
                }
            }
        }
        if !seen[dst as usize] || dst == from {
            return Toward::Nowhere;
        }
        let mut y = dst;
        while prev[y as usize] != from {
            y = prev[y as usize];
        }
        Toward::Hop(key(y))
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
        let copies: Vec<String> = self
            .carriers
            .iter()
            .enumerate()
            .map(|(i, c)| {
                format!(
                    "c{i}: copies={:?} receipt={}",
                    c.model_copies(&BUNDLE),
                    if c.model_has_receipt(&BUNDLE) { "yes" } else { "no" }
                )
            })
            .collect();
        let net: Vec<String> = self
            .net
            .iter()
            .map(|m| {
                let what = match &m.body {
                    Body::Summary(s) => {
                        format!("summary(full={}, receipts={}, ids={})", s.full, s.receipts.len(), s.ids.len())
                    }
                    Body::Offer(o) => format!("offer(copies={})", o.copies),
                    Body::Answer(_, c, a) => format!("answer({a:?}, copies={c})"),
                    Body::Payload(_, c) => format!("payload(copies={c})"),
                    Body::Result(_, c, ok) => format!("result(ok={ok}, copies={c})"),
                };
                format!("{}→{} {what}", m.from, m.to)
            })
            .collect();
        write!(
            f,
            "t={} links={:?} delivered={} left={:?}\n  {}\n  in flight: {}",
            self.now,
            self.links,
            self.delivered,
            self.left,
            copies.join("; "),
            net.join("; ")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Deliver(usize),
    /// The stream is lost; its connection lives.
    Drop(usize),
    Down(u8, u8),
    Up(u8, u8),
    Advance(Time),
}

#[derive(Clone, Debug)]
pub struct CarrierModel {
    pub n: u8,
    pub initial: Vec<(u8, u8)>,
    pub flappable: Vec<(u8, u8)>,
    pub budget: Budget,
    pub advances: Vec<Time>,
    pub cfg: DtnConfig,
    /// Rounds of the fair run the receipt property allows after faults.
    pub recovery_rounds: u32,
    /// Start exploring from every state of the fault-free run, not only
    /// its first.
    pub nominal_prefix: bool,
}

impl CarrierModel {
    pub fn new(n: u8, initial: &[(u8, u8)]) -> Self {
        CarrierModel {
            n,
            initial: initial.to_vec(),
            flappable: initial.to_vec(),
            budget: Budget { steps: 2, links: 1, drops: 1 },
            // the summary gap (2 s); a full summary's period (60 s)
            advances: vec![SUMMARY_GAP + 100, SUMMARY_FULL],
            // two copies keep the state small and still exercise spraying
            cfg: DtnConfig { copies: 2, copies_small: 2, ..DtnConfig::default() },
            recovery_rounds: 80,
            nominal_prefix: true,
        }
    }

    pub fn bound(&self) -> String {
        format!(
            "{} devices, links {:?} ({} flappable), steps {:?}, budget {:?}, recovery {} rounds{}",
            self.n,
            self.initial,
            self.flappable.len(),
            self.advances,
            self.budget,
            self.recovery_rounds,
            if self.nominal_prefix { ", branching off every state of the fault-free run" } else { "" }
        )
    }

    fn link(a: u8, b: u8) -> (u8, u8) {
        (a.min(b), a.max(b))
    }

    fn dst(&self) -> u8 {
        self.n - 1
    }

    pub fn start(&self) -> State {
        let carriers: Vec<Carrier> = (0..self.n).map(|i| Carrier::new(key(i), self.cfg.clone())).collect();
        let mut s = State {
            now: 0,
            carriers,
            links: BTreeSet::new(),
            net: Vec::new(),
            waiting: BTreeMap::new(),
            delivered: false,
            left: self.budget,
        };
        for &(a, b) in &self.initial {
            Self::up(&mut s, a, b);
        }
        let b = Bundle {
            format: BundleFormat::v2(1),
            id: BUNDLE,
            src: key(0),
            dst: key(self.dst()),
            created: WALL0,
            lifetime: 24 * 3600 * 1000,
            payload: Bytes::from_static(&[7; 100]),
            sig: Sig([0; 64]),
        };
        let c = &mut s.carriers[0];
        c.set_clock(0, WALL0);
        c.originate(b, 0).expect("room for it");
        s
    }

    fn up(s: &mut State, a: u8, b: u8) {
        s.links.insert(Self::link(a, b));
        let now = s.now;
        for (x, y) in [(a, b), (b, a)] {
            let c = &mut s.carriers[x as usize];
            c.encounter(key(y), now);
            c.new_contact(key(y));
        }
    }

    fn down(s: &mut State, a: u8, b: u8) {
        let l = Self::link(a, b);
        s.links.remove(&l);
        s.net.retain(|m| Self::link(m.from, m.to) != l);
        let now = s.now;
        let failed: Vec<(u8, u8, Hash32)> =
            s.waiting.keys().filter(|(x, y, _)| Self::link(*x, *y) == l).copied().collect();
        for t in failed {
            Self::fail(s, t, now);
        }
    }

    /// The sender's transfer `t` ended without a result.
    fn fail(s: &mut State, t: (u8, u8, Hash32), now: Time) {
        if let Some((copies, _)) = s.waiting.remove(&t) {
            s.carriers[t.0 as usize].transferred(key(t.1), t.2, copies, false, now);
        }
    }

    fn settle(s: &mut State) {
        s.net.sort_by_cached_key(|m| format!("{m:?}"));
    }

    /// The driver's carrier step (`dtn_tick`) at every device.
    fn step(&self, s: &mut State) {
        let now = s.now;
        for i in 0..self.n {
            let nbs = s.neighbours(i);
            let toward: Vec<Toward> = (0..self.n).map(|d| s.toward(i, d)).collect();
            let c = &mut s.carriers[i as usize];
            c.set_clock(now, WALL0 + now);
            c.tick(now);
            for (k, sum) in c.summaries(now, &nbs) {
                s.net.push(Msg { from: i, to: index(&k), body: Body::Summary(sum) });
            }
            let c = &mut s.carriers[i as usize];
            let plan = c.plan(now, |dst| toward[index(dst) as usize], &nbs);
            for t in plan {
                let to = index(&t.to);
                let Some(b) = s.carriers[i as usize].bundle(&t.id).cloned() else { continue };
                if !s.links.contains(&Self::link(i, to)) || s.waiting.contains_key(&(i, to, t.id)) {
                    s.carriers[i as usize].transferred(t.to, t.id, t.copies, false, now);
                    continue;
                }
                s.net.push(Msg { from: i, to, body: Body::Offer(Offer::of(&b, t.copies)) });
                s.waiting.insert((i, to, t.id), (t.copies, b));
            }
        }
    }

    fn deliver(&self, s: &mut State, m: Msg) {
        let now = s.now;
        let to = m.to as usize;
        match m.body {
            Body::Summary(sum) => s.carriers[to].on_summary(key(m.from), sum, now, |_| true),
            Body::Offer(o) => {
                let c = &mut s.carriers[to];
                c.set_clock(now, WALL0 + now);
                let a = c.offered(key(m.from), &o, now, |_| true);
                s.net.push(Msg { from: m.to, to: m.from, body: Body::Answer(o.id, o.copies, a) });
            }
            Body::Answer(id, copies, a) => {
                let t = (m.to, m.from, id);
                match a {
                    Answer::Take { .. } => {
                        if let Some((c, b)) = s.waiting.get(&t) {
                            s.net.push(Msg { from: m.to, to: m.from, body: Body::Payload(b.clone(), *c) });
                        }
                    }
                    Answer::Duplicate => {
                        if s.waiting.remove(&t).is_some() {
                            s.carriers[m.to as usize].transferred(key(m.from), id, copies, true, now);
                        }
                    }
                    Answer::Refuse(_) => {
                        if s.waiting.remove(&t).is_some() {
                            s.carriers[m.to as usize].refused(key(m.from), id, false, now);
                        }
                    }
                }
            }
            Body::Payload(b, copies) => {
                let id = b.id;
                let got = s.carriers[to].accept(key(m.from), b, copies, now, |_| true);
                let ok = !matches!(got, Accepted::Refused(_));
                if let Accepted::ForMe(b) = got {
                    s.delivered = true;
                    s.carriers[to].add_receipt(Receipt { id: b.id, dst: key(m.to), sig: Sig([0; 64]) });
                }
                s.net.push(Msg { from: m.to, to: m.from, body: Body::Result(id, copies, ok) });
            }
            Body::Result(id, copies, ok) => {
                let t = (m.to, m.from, id);
                if s.waiting.remove(&t).is_some() {
                    let c = &mut s.carriers[m.to as usize];
                    if ok {
                        c.transferred(key(m.from), id, copies, true, now);
                    } else {
                        c.refused(key(m.from), id, false, now);
                    }
                }
            }
        }
    }

    /// Faults stop: links come back, then the fair run; whether the bundle
    /// ends delivered and held by nobody.
    pub fn recovers(&self, s: &State) -> bool {
        self.fair_run(s, |s| s.delivered && s.holders().is_empty())
    }

    /// The plan's first, stronger wording: the source ends with the receipt
    /// (it does not when it handed every copy on; see the module docs).
    pub fn source_told(&self, s: &State) -> bool {
        self.fair_run(s, |s| s.carriers[0].model_has_receipt(&BUNDLE))
    }

    /// Restore the initial links, then deliver everything and step the
    /// clock, round after round, until `done` (true) or the rounds run out.
    fn fair_run(&self, s: &State, done: impl Fn(&State) -> bool) -> bool {
        let mut s = s.clone();
        for &(a, b) in &self.initial {
            if !s.links.contains(&(a, b)) {
                Self::up(&mut s, a, b);
            }
        }
        for _ in 0..self.recovery_rounds {
            while !s.net.is_empty() {
                let m = s.net.remove(0);
                self.deliver(&mut s, m);
            }
            if done(&s) {
                return true;
            }
            s.now += SUMMARY_GAP + 100;
            self.step(&mut s);
        }
        false
    }
}

impl Model for CarrierModel {
    type State = State;
    type Action = Action;

    /// The start, and every state of the fault-free run from it (each
    /// after its step's messages are all delivered) until the receipt is
    /// home: exploration branches off the nominal run anywhere along it,
    /// so a small budget still reaches deep into a transfer.
    fn init_states(&self) -> Vec<State> {
        let mut s = self.start();
        let mut out = vec![s.clone()];
        for _ in 0..self.recovery_rounds {
            while !s.net.is_empty() {
                let m = s.net.remove(0);
                self.deliver(&mut s, m);
            }
            if s.delivered && s.holders().is_empty() {
                break;
            }
            s.now += SUMMARY_GAP + 100;
            self.step(&mut s);
            Self::settle(&mut s);
            if self.nominal_prefix {
                out.push(s.clone());
            }
        }
        out
    }

    fn actions(&self, s: &State, out: &mut Vec<Action>) {
        for i in 0..s.net.len() {
            out.push(Action::Deliver(i));
            if s.left.drops > 0 {
                out.push(Action::Drop(i));
            }
        }
        if s.left.links > 0 {
            for &(a, b) in &self.flappable {
                out.push(if s.links.contains(&(a, b)) { Action::Down(a, b) } else { Action::Up(a, b) });
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
                self.deliver(&mut s, m);
            }
            Action::Drop(i) => {
                s.left.drops -= 1;
                let m = s.net.remove(i);
                if let Some(t) = m.transfer() {
                    // the sender times out
                    let now = s.now;
                    Self::fail(&mut s, t, now);
                }
            }
            Action::Down(a, b) => {
                s.left.links -= 1;
                Self::down(&mut s, a, b);
            }
            Action::Up(a, b) => {
                s.left.links -= 1;
                Self::up(&mut s, a, b);
            }
            Action::Advance(dt) => {
                s.left.steps -= 1;
                s.now += dt;
                self.step(&mut s);
            }
        }
        Self::settle(&mut s);
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("custody", |_, s: &State| s.custody()),
            Property::always("receipts clear every copy", |m: &CarrierModel, s: &State| m.recovers(s)),
            Property::sometimes("delivered", |_, s: &State| s.delivered),
        ]
    }
}
