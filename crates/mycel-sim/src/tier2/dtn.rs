//! Baseline routers to compare Mycel's with, apples to apples:
//!
//! - **Epidemic** (Vahdat & Becker, 2000): on every contact, exchange
//!   summary vectors and copy every message the other side lacks. Fastest
//!   possible delivery for unlimited storage and bandwidth; huge overhead.
//! - **Binary Spray-and-Wait** (Spyropoulos, Psounis & Raghavendra, 2005):
//!   L copies; a holder with n > 1 gives n/2 to each device it meets that
//!   lacks it; with 1 left it waits to meet the destination.
//! - **PRoPHET** (Lindgren et al., 2003; RFC 6693), plain: delivery
//!   predictabilities rise on encounters, age, and are transitive; a copy goes
//!   to a neighbour with a higher predictability for the destination (GRTR).
//!   Parameters as The ONE's ProphetRouter (P_init 0.75, β 0.25, γ 0.98 per
//!   30 s), no internet gradient.
//! - **Managed flooding**, as Meshtastic and BitChat do: every message is
//!   broadcast with a hop limit; each device rebroadcasts a new message once,
//!   after a random delay, unless it hears it rebroadcast meanwhile
//!   (suppression); duplicates are dropped. No storage: live only.
//!
//! Every router has a buffer (bytes held for others) with FIFO drop and a
//! message TTL, as in The ONE, so buffer occupancy is comparable.
//!
//! Devices with internet are all in contact with each other (the internet
//! is one big contact); the store-and-forward baselines know which devices
//! have internet (given at construction) since they have no gateway
//! announcements.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::engine::{Cx, MS, MsgId, NodeId, Over, Router, SEC, Techs, Time};
use crate::stats::{Map, Set};

/// A broadcast (flooding reach measurements): every device "receives" it.
pub const BROADCAST: NodeId = NodeId::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Epidemic,
    SprayAndWait(u8),
    Prophet,
    /// Managed flooding: hop limit, rebroadcast window (ms), cancel after
    /// hearing this many duplicates during the window.
    Flood { hops: u8, window_ms: u64, suppress: u8 },
}

impl Kind {
    pub fn name(&self) -> String {
        match self {
            Kind::Epidemic => "epidemic".into(),
            Kind::SprayAndWait(l) => format!("spray-and-wait (L={l})"),
            Kind::Prophet => "PRoPHET".into(),
            Kind::Flood { hops, .. } => format!("managed flooding (hop limit {hops})"),
        }
    }
}

/// Settings shared by the baselines.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    /// Bytes held for others; the oldest is dropped when full.
    pub buffer: u64,
    /// A message is dropped this long after it was created.
    pub ttl: Time,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { buffer: 64 << 20, ttl: 24 * 3600 * SEC }
    }
}

/// Flooding measurements shared by every device of a run.
#[derive(Default)]
pub struct FloodStats {
    /// Who has received each message.
    pub reached: RefCell<Map<MsgId, Set<NodeId>>>,
    /// Rebroadcasts sent for each message, and how many of them reached a new device.
    pub rebroadcasts: RefCell<Map<MsgId, (u64, u64)>>,
}

#[derive(Clone, Debug)]
pub enum Frame {
    /// What I hold (and, for PRoPHET, my predictabilities).
    Summary(Rc<Vec<MsgId>>, Rc<Vec<(NodeId, f32)>>),
    Msg { msg: MsgId, dst: NodeId, size: u32, copies: u8, created: Time, hops: u8 },
}

struct Held {
    dst: NodeId,
    size: u32,
    copies: u8,
    created: Time,
    ours: bool,
}

pub struct Dtn {
    kind: Kind,
    opts: Opts,
    me: NodeId,
    held: Map<MsgId, Held>,
    order: VecDeque<MsgId>,
    used: u64,
    done: Set<MsgId>,
    nb_has: Map<NodeId, Set<MsgId>>,
    inet_peers: Rc<Vec<NodeId>>,
    // PRoPHET
    pred: Map<NodeId, (f64, Time)>,
    nb_pred: Map<NodeId, Map<NodeId, f64>>,
    // flooding: message → (when to rebroadcast, duplicates heard, frame)
    pending: Map<MsgId, (u8, Frame)>,
    flood: Rc<FloodStats>,
    pub buffer_peak: u64,
    pub buffer_area: f64,
    buffer_at: Time,
}

const P_INIT: f64 = 0.75;
const BETA: f64 = 0.25;
const GAMMA: f64 = 0.98;
const TIME_UNIT: Time = 30 * SEC;
const T_FLOOD: u64 = 1 << 40;

impl Dtn {
    pub fn new(me: NodeId, kind: Kind, inet_peers: Rc<Vec<NodeId>>) -> Dtn {
        Dtn::with(me, kind, Opts::default(), inet_peers, Rc::default())
    }

    pub fn with(me: NodeId, kind: Kind, opts: Opts, inet_peers: Rc<Vec<NodeId>>, flood: Rc<FloodStats>) -> Dtn {
        Dtn {
            kind,
            opts,
            me,
            held: Map::default(),
            order: VecDeque::new(),
            used: 0,
            done: Set::default(),
            nb_has: Map::default(),
            inet_peers,
            pred: Map::default(),
            nb_pred: Map::default(),
            pending: Map::default(),
            flood,
            buffer_peak: 0,
            buffer_area: 0.0,
            buffer_at: 0,
        }
    }

    fn note_buffer(&mut self, now: Time) {
        self.buffer_area += self.used as f64 * now.saturating_sub(self.buffer_at) as f64;
        self.buffer_at = now;
        self.buffer_peak = self.buffer_peak.max(self.used);
    }

    fn p(&self, x: NodeId, now: Time) -> f64 {
        self.pred.get(&x).map_or(0.0, |(p, at)| p * GAMMA.powf(now.saturating_sub(*at) as f64 / TIME_UNIT as f64))
    }

    fn summary(&self, now: Time) -> Frame {
        let mut v: Vec<MsgId> = self.held.keys().copied().chain(self.done.iter().copied()).collect();
        v.sort_unstable();
        let preds = if self.kind == Kind::Prophet {
            let mut p: Vec<(NodeId, f32)> = self.pred.keys().map(|k| (*k, self.p(*k, now) as f32)).filter(|(_, p)| *p > 0.01).collect();
            p.sort_unstable_by_key(|x| x.0);
            p
        } else {
            Vec::new()
        };
        Frame::Summary(Rc::new(v), Rc::new(preds))
    }

    fn expire(&mut self, now: Time) {
        let ttl = self.opts.ttl;
        let dead: Vec<MsgId> = self.held.iter().filter(|(_, h)| now.saturating_sub(h.created) >= ttl).map(|(k, _)| *k).collect();
        for id in dead {
            self.drop_msg(id);
        }
    }

    fn drop_msg(&mut self, id: MsgId) {
        if let Some(h) = self.held.remove(&id)
            && !h.ours
        {
            self.used = self.used.saturating_sub(h.size as u64);
        }
        self.order.retain(|x| *x != id);
    }

    fn keep(&mut self, cx: &mut Cx<Frame>, msg: MsgId, h: Held) {
        let size = h.size as u64;
        if !h.ours {
            // FIFO drop until it fits (The ONE's default policy)
            while self.used + size > self.opts.buffer {
                let Some(old) = self.order.iter().copied().find(|id| self.held.get(id).is_some_and(|x| !x.ours)) else { return };
                self.drop_msg(old);
            }
            self.used += size;
            // these baselines replicate (or spray a share): every hand-off
            // leaves the giver a copy, except spray-and-wait's final one to
            // the destination, which is a delivery
            cx.copied(msg);
            cx.handed(msg);
        }
        self.held.insert(msg, h);
        self.order.push_back(msg);
        cx.note_stored(self.held.len());
        self.note_buffer(cx.now());
    }

    /// Offer what `nb` lacks.
    fn push_to(&mut self, cx: &mut Cx<Frame>, nb: NodeId, over_inet: bool) {
        let now = cx.now();
        self.expire(now);
        let ids: Vec<MsgId> = self.order.iter().copied().collect();
        for id in ids {
            if self.nb_has.get(&nb).is_some_and(|h| h.contains(&id)) {
                continue;
            }
            let Some(h) = self.held.get(&id) else { continue };
            let give = match self.kind {
                Kind::Epidemic => 1,
                Kind::SprayAndWait(_) if h.dst == nb => h.copies.max(1),
                Kind::SprayAndWait(_) if h.copies > 1 => h.copies / 2,
                Kind::SprayAndWait(_) => continue,
                Kind::Prophet => {
                    let theirs = self.nb_pred.get(&nb).and_then(|t| t.get(&h.dst).copied()).unwrap_or(0.0);
                    if h.dst != nb && theirs <= self.p(h.dst, now) {
                        continue;
                    }
                    1
                }
                Kind::Flood { .. } => continue,
            };
            let (dst, size, created) = (h.dst, h.size, h.created);
            let f = Frame::Msg { msg: id, dst, size, copies: give, created, hops: 0 };
            let sent = if over_inet { cx.send_inet(nb, f, size + 64, false, Some(id)) } else { cx.send_radio(nb, f, size + 64, false, Some(id)) };
            if sent {
                self.nb_has.entry(nb).or_default().insert(id);
                if let Kind::SprayAndWait(_) = self.kind
                    && let Some(h) = self.held.get_mut(&id)
                {
                    h.copies = h.copies.saturating_sub(give);
                    if h.copies == 0 {
                        self.drop_msg(id);
                    }
                }
            }
        }
        self.note_buffer(now);
    }

    fn spread(&mut self, cx: &mut Cx<Frame>) {
        for (nb, _) in cx.neighbours() {
            self.push_to(cx, nb, false);
        }
        if cx.has_inet() {
            let peers = self.inet_peers.clone();
            for &p in peers.iter() {
                if p != self.me {
                    self.push_to(cx, p, true);
                }
            }
        }
    }

    fn encounter(&mut self, nb: NodeId, now: Time) {
        let p = self.p(nb, now);
        self.pred.insert(nb, (p + (1.0 - p) * P_INIT, now));
    }

    // ───────────── flooding ─────────────

    fn flood_receive(&mut self, cx: &mut Cx<Frame>, f: Frame) {
        let Frame::Msg { msg, dst, hops, .. } = f.clone() else { return };
        if let Some((heard, _)) = self.pending.get_mut(&msg) {
            *heard = heard.saturating_add(1);
            return;
        }
        if !self.done.insert(msg) {
            return; // duplicate
        }
        let me = self.me;
        let new = self.flood.reached.borrow_mut().entry(msg).or_default().insert(me);
        let _ = new;
        if dst == me {
            cx.delivered(msg);
            return;
        }
        let Kind::Flood { window_ms, .. } = self.kind else { return };
        if hops == 0 {
            return;
        }
        let delay = (cx.rng().f64() * (window_ms * MS) as f64) as Time;
        self.pending.insert(msg, (0, f));
        cx.set_timer(delay + 1, T_FLOOD | msg as u64);
    }

    fn flood_send(&mut self, cx: &mut Cx<Frame>, f: Frame, rebroadcast: bool) {
        let Frame::Msg { msg, size, .. } = f else { return };
        let before = self.flood.reached.borrow().get(&msg).map_or(0, |s| s.len());
        for (nb, _) in cx.neighbours() {
            cx.send_radio(nb, f.clone(), size + 64, false, Some(msg));
        }
        if rebroadcast {
            let mut r = self.flood.rebroadcasts.borrow_mut();
            let e = r.entry(msg).or_default();
            e.0 += 1;
            let _ = before;
        }
    }
}

impl Router for Dtn {
    type Frame = Frame;

    fn size(f: &Frame) -> u32 {
        match f {
            Frame::Summary(v, p) => 8 + 4 * v.len() as u32 + 8 * p.len() as u32,
            Frame::Msg { size, .. } => size + 64,
        }
    }

    fn is_control(f: &Frame) -> bool {
        matches!(f, Frame::Summary(..))
    }

    fn msg_of(f: &Frame) -> Option<MsgId> {
        match f {
            Frame::Msg { msg, .. } => Some(*msg),
            _ => None,
        }
    }

    fn on_start(&mut self, _cx: &mut Cx<Frame>) {}

    fn on_link(&mut self, cx: &mut Cx<Frame>, nb: NodeId, _techs: Techs, up: bool) {
        if matches!(self.kind, Kind::Flood { .. }) {
            return;
        }
        if up {
            let now = cx.now();
            self.encounter(nb, now);
            let s = self.summary(now);
            let size = Self::size(&s);
            cx.send_radio(nb, s, size, true, None);
        } else {
            self.nb_has.remove(&nb);
        }
    }

    fn on_frame(&mut self, cx: &mut Cx<Frame>, from: NodeId, over: Over, f: Frame) {
        if matches!(self.kind, Kind::Flood { .. }) {
            if let Frame::Msg { msg, dst, size, copies, created, hops } = f {
                let next = Frame::Msg { msg, dst, size, copies, created, hops: hops.saturating_sub(1) };
                self.flood_receive(cx, next);
            }
            return;
        }
        let now = cx.now();
        match f {
            Frame::Summary(ids, preds) => {
                self.nb_has.insert(from, ids.iter().copied().collect());
                if self.kind == Kind::Prophet {
                    // transitivity: P(x) = P(x) + (1 − P(x))·P(from)·P_from(x)·β
                    let p_from = self.p(from, now);
                    let mut t = Map::default();
                    for (x, px) in preds.iter() {
                        t.insert(*x, *px as f64);
                        if *x == self.me {
                            continue;
                        }
                        let p = self.p(*x, now);
                        let np = p + (1.0 - p) * p_from * *px as f64 * BETA;
                        if np > p {
                            self.pred.insert(*x, (np, now));
                        }
                    }
                    self.nb_pred.insert(from, t);
                }
                self.push_to(cx, from, over == Over::Inet);
            }
            Frame::Msg { msg, dst, size, copies, created, .. } => {
                self.nb_has.entry(from).or_default().insert(msg);
                if self.done.contains(&msg) || self.held.contains_key(&msg) {
                    if let Some(h) = self.held.get_mut(&msg) {
                        h.copies = h.copies.saturating_add(copies);
                    }
                    return;
                }
                if dst == self.me {
                    self.done.insert(msg);
                    cx.delivered(msg);
                    return;
                }
                if now.saturating_sub(created) >= self.opts.ttl {
                    return;
                }
                self.keep(cx, msg, Held { dst, size, copies, created, ours: false });
                self.spread(cx);
            }
        }
    }

    fn on_timer(&mut self, cx: &mut Cx<Frame>, token: u64) {
        if token & T_FLOOD != 0 {
            let msg = (token & 0xffff_ffff) as MsgId;
            let Some((heard, f)) = self.pending.remove(&msg) else { return };
            let Kind::Flood { suppress, .. } = self.kind else { return };
            if heard >= suppress {
                return; // others covered it
            }
            self.flood_send(cx, f, true);
        }
    }

    fn on_send(&mut self, cx: &mut Cx<Frame>, msg: MsgId, dst: NodeId, size: u32) {
        let now = cx.now();
        if let Kind::Flood { hops, .. } = self.kind {
            self.done.insert(msg);
            self.flood.reached.borrow_mut().entry(msg).or_default().insert(self.me);
            // `hops` = transmissions left, this one included
            let f = Frame::Msg { msg, dst, size, copies: 1, created: now, hops };
            self.flood_send(cx, f, false);
            return;
        }
        let copies = match self.kind {
            Kind::SprayAndWait(l) => l,
            _ => 1,
        };
        cx.copied(msg);
        self.keep(cx, msg, Held { dst, size, copies, created: now, ours: true });
        self.spread(cx);
    }

    fn on_inet(&mut self, cx: &mut Cx<Frame>, up: bool) {
        if up && !matches!(self.kind, Kind::Flood { .. }) {
            self.spread(cx);
        }
    }
}
