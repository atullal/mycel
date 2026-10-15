//! The GLOBAL routing core (`mycel_net::mesh::core`), driven by the
//! discrete-event engine: the real routing code, not a model of it.
//!
//! What the driver does (as `mesh/mod.rs` does over real sockets, and as
//! the core's own test harness does):
//! - **Time**: the core runs on milliseconds. It is ticked every 10 ms for
//!   60 ms after any input (rebroadcast jitter is 10–50 ms), and every
//!   `announce_every / 4` (at most 500 ms) for housekeeping and its own
//!   announcements.
//! - **Hops**: a radio neighbour is a direct hop (`set_direct` + `hop_up`,
//!   cost = 2 × latency + time to move 64 KiB, in 0.1 ms units). Internet
//!   hops are dialled (`Out::Dial`): a handshake over the modelled internet,
//!   then `hop_up` on both ends; `Out::Hangup` closes them.
//! - **Records**: `Out::PublishReach` puts the device's record in the
//!   directory; `Out::Resolve` looks one up (DHT-like delay).
//! - **Data**: an app message is split into packets of at most 1,200 bytes
//!   (QUIC's packets), sent with `Router::send`, or straight to the peer
//!   where a direct path exists: over the radio to a neighbour, or over the
//!   internet once two devices with the internet have a connection (the
//!   node's Iroh connection, pooled for [`mycel_net::POOL_IDLE`]; the
//!   first packet pays the lookup and the dial). Direct paths never use
//!   the mesh, and the core refuses data for a neighbour. The destination acks
//!   each complete message; the sender retransmits unacked messages with
//!   exponential backoff (1 s → 30 s, for 10 min), as QUIC and Mycel's sync
//!   would. The ack's arrival is the message's receipt (round trip).
//! - **Signatures** are always valid here (tested in `mesh/wire.rs`).
//! - **Loops**: a packet (source, id) arriving at the same device twice is
//!   counted as a loop.
//! - **Store-and-forward** (optional, `with_dtn`): GLOBAL's carrier
//!   (`mycel_net::mesh::dtn::Carrier`). As in the node, a message goes live
//!   first; if the live attempt fails (its first retransmission timeout
//!   passes with nothing acknowledged), it is also handed to the carrier as
//!   a bundle, which moves along live and partial routes (`Router::toward`)
//!   with custody, down the PRoPHET gradient toward the destination or the
//!   internet, or sprays. Carriers exchange summaries (held ids, receipts,
//!   room, predictabilities) when they meet and then when something changes
//!   (`Carrier::summaries`); the destination signs a receipt. Delivery is
//!   whichever arrives first.

use crate::stats::{Map, Set};
use std::cell::Cell;

use std::rc::Rc;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use mycel_crypto::Hash32;
use mycel_crypto::{Sig, SignPk};
use mycel_net::mesh::core::{self as mc, Announce, Config, Out, SeqReq};
use mycel_net::mesh::dtn::{Accepted, Answer, Bundle, Carrier, DtnConfig, Offer, Receipt, Summary as DtnSummary};

use super::engine::{Cx, MS, MsgId, NodeId, Over, Router, SEC, Techs, Time};
use super::mycel::Role;

const WALL_MS: u64 = 1_700_000_000_000;
const PACKET: u32 = 1200;
const PKT_HDR: usize = 1 + 4 + 2 + 2;
const TAG_DATA: u8 = 1;
const TAG_ACK: u8 = 2;
const HANDSHAKE: u32 = 1200;
/// [`mycel_net::POOL_IDLE`] in engine time.
const POOL_IDLE_US: Time = 60 * SEC;

/// A device's key in the simulation (deterministic from its id).
pub fn key(i: NodeId) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&(i + 1).to_be_bytes());
    k[31] = 0xa5;
    SignPk(k)
}

pub fn node(pk: &SignPk) -> NodeId {
    u32::from_be_bytes(pk.0[..4].try_into().expect("4 bytes")) - 1
}

#[derive(Clone, Debug)]
pub enum Frame {
    Ann(Announce),
    Req(SeqReq),
    Data(mc::Frame),
    /// A packet straight to a radio neighbour (not through the mesh).
    Direct(Bytes),
    Dial,
    DialAck,
    Hangup,
    /// Store-and-forward: a bundle offered before its payload, the
    /// answer, then the bundle with `copies` copies (custody if all).
    Offer(Offer),
    Answer {
        id: Hash32,
        copies: u8,
        answer: Answer,
    },
    Bundle(Bundle, u8),
    BundleAck {
        id: Hash32,
        copies: u8,
        ok: bool,
        stored: bool,
    },
    Summary(Rc<DtnSummary>),
}

/// Counters shared by every device of one run.
#[derive(Default)]
pub struct Shared {
    pub loops: Cell<u64>,
    pub routes_up: Cell<u64>,
    pub routes_down: Cell<u64>,
}

/// A message being sent, QUIC-style: per-packet acks, a congestion window
/// (10 packets, +1 per ack, halved on a timeout), an adaptive RTO.
struct Outgoing {
    dst: NodeId,
    size: u32,
    parts: u16,
    acked: Vec<bool>,
    left: u16,
    /// part → when sent
    inflight: Map<u16, Time>,
    cwnd: f64,
    srtt: Option<Time>,
    rto: Time,
    started: Time,
}

const INITIAL_WINDOW: f64 = 10.0;
const MAX_WINDOW: f64 = 512.0;

pub struct Global {
    pub core: mc::Router,
    pub role: Role,
    pk: SignPk,
    old: Vec<Announce>,
    name: Arc<str>,
    period: Time,
    burst_until: Time,
    burst_armed: bool,
    outbox: Map<MsgId, Outgoing>,
    inbox: Map<MsgId, Set<u16>>,
    done: Set<MsgId>,
    seen: Map<(SignPk, u32), Time>,
    shared: Rc<Shared>,
    buf: Vec<Out>,
    /// GLOBAL's store-and-forward carrier, if on.
    pub dtn: Option<Carrier>,
    /// Messages already handed to the carrier (once each, as the node does).
    bundled: Set<MsgId>,
    /// Lifetime given to our bundles.
    pub bundle_lifetime_ms: u64,
    /// Bytes held for others: peak and time-weighted sum (for the average).
    pub buffer_peak: u64,
    pub buffer_area: f64,
    /// Control bytes sent, by kind: routing (announcements, seqno
    /// requests), carrier (summaries, offers, answers, acks), dials, other.
    pub ctrl_by_kind: [u64; 4],
    /// Internet peers we have a connection to (the node's pooled QUIC
    /// connections) and when it last carried a packet.
    conns: Map<NodeId, Time>,
    buffer_at: Time,
    buffer_now: u64,
}

/// A bundle's id for message `msg` (the same message is the same bundle).
fn bundle_id(msg: MsgId, src: NodeId) -> Hash32 {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&msg.to_be_bytes());
    b[4..8].copy_from_slice(&src.to_be_bytes());
    b[31] = 0xb0;
    Hash32(b)
}

fn bundle_msg(id: &Hash32) -> MsgId {
    u32::from_be_bytes(id.0[..4].try_into().expect("4"))
}

const T_HOUSE: u64 = 1;
const T_BURST: u64 = 2;
const T_RETRY: u64 = 3;

/// Cost units (0.1 ms) of a hop: 2 × latency + the time to move 64 KiB.
fn units(latency_us: Time, rate: u64) -> u32 {
    let us = 2 * latency_us + 65_536 * SEC / rate.max(1);
    (us / 100).min(u32::MAX as u64 / 2) as u32
}

fn radio_units(techs: Techs) -> u32 {
    let t = techs.best(64 * 1024).expect("a radio");
    units(t.latency().as_micros() as Time, t.rate())
}

impl Global {
    pub fn new(me: NodeId, cfg: Config, shared: Rc<Shared>) -> Global {
        let period = (cfg.announce_every / 4).clamp(100, 500) * MS;
        Global {
            core: mc::Router::new(key(me), cfg),
            role: Role::Honest,
            pk: key(me),
            old: Vec::new(),
            name: Arc::from(format!("n{me}").as_str()),
            period,
            burst_until: 0,
            burst_armed: false,
            outbox: Map::default(),
            inbox: Map::default(),
            done: Set::default(),
            seen: Map::default(),
            shared,
            buf: Vec::new(),
            dtn: None,
            bundled: Set::default(),
            bundle_lifetime_ms: 24 * 3600 * 1000,
            buffer_peak: 0,
            buffer_area: 0.0,
            ctrl_by_kind: [0; 4],
            conns: Map::default(),
            buffer_at: 0,
            buffer_now: 0,
        }
    }

    /// Turn on store-and-forward.
    pub fn with_dtn(mut self, cfg: DtnConfig) -> Global {
        let mut c = Carrier::new(self.pk, cfg);
        // bundles' `created` is a wall clock: WALL_MS at our time 0
        c.set_clock(0, WALL_MS);
        self.dtn = Some(c);
        self
    }

    fn note_buffer(&mut self, cx: &Cx<Frame>) {
        let Some(c) = &self.dtn else { return };
        let bytes: u64 = c
            .held()
            .iter()
            .filter_map(|id| c.bundle(id))
            .filter(|b| b.src != self.pk)
            .map(|b| b.payload.len() as u64)
            .sum();
        let now = cx.now();
        self.buffer_area += self.buffer_now as f64 * now.saturating_sub(self.buffer_at) as f64;
        self.buffer_at = now;
        self.buffer_now = bytes;
        self.buffer_peak = self.buffer_peak.max(bytes);
    }

    /// Hand bundles on: whatever the carrier plans now.
    fn dtn_plan(&mut self, cx: &mut Cx<Frame>) {
        let now = Self::ms(cx);
        let Global { core, dtn, .. } = self;
        let Some(c) = dtn.as_mut() else { return };
        c.set_internet(cx.has_inet());
        let nbs: Vec<SignPk> = core.neighbours().into_iter().map(|(k, _)| k).collect();
        let plan = c.plan(now, |d| core.toward(d, now), &nbs);
        // offered first, as the node does: the payload follows a "take"
        let offers: Vec<(NodeId, Offer)> =
            plan.into_iter().filter_map(|t| c.bundle(&t.id).map(|b| (node(&t.to), Offer::of(b, t.copies)))).collect();
        for (to, o) in offers {
            let (id, copies) = (o.id, o.copies);
            if !self.send_to(cx, to, Frame::Offer(o), None) {
                let now = Self::ms(cx);
                if let Some(c) = self.dtn.as_mut() {
                    c.transferred(key(to), id, copies, false, now);
                }
            }
        }
        // the plan may have started lookups or dials
        self.effects(cx);
        self.note_buffer(cx);
    }

    /// Summaries due now (the carrier decides: everything to a new
    /// neighbour, then what changes). Every 10 s, neighbours still in range
    /// count as encounters again.
    fn dtn_summaries(&mut self, cx: &mut Cx<Frame>, encounters: bool) {
        let now = Self::ms(cx);
        let Some(c) = self.dtn.as_mut() else { return };
        let nbs: Vec<SignPk> = self.core.neighbours().into_iter().map(|(k, _)| k).collect();
        if encounters {
            for k in &nbs {
                c.encounter(*k, now);
            }
        }
        for (k, s) in c.summaries(now, &nbs) {
            if !self.send_to(cx, node(&k), Frame::Summary(Rc::new(s)), None)
                && let Some(c) = self.dtn.as_mut()
            {
                c.new_contact(k); // it heard nothing: tell it everything next time
            }
        }
    }

    fn originate_bundle(&mut self, cx: &mut Cx<Frame>, msg: MsgId, dst: NodeId, size: u32) {
        let now = Self::ms(cx);
        let lifetime = self.bundle_lifetime_ms;
        let pk = self.pk;
        let Some(c) = self.dtn.as_mut() else { return };
        let b = Bundle {
            id: bundle_id(msg, node(&pk)),
            src: pk,
            dst: key(dst),
            created: WALL_MS + now,
            lifetime,
            payload: Bytes::from(vec![0u8; size as usize]),
            sig: Sig([0; 64]),
        };
        if c.originate(b, now).is_ok() {
            self.dtn_plan(cx);
        }
    }

    fn ms(cx: &Cx<Frame>) -> mc::Time {
        cx.now() / MS
    }

    /// Ask for ticks every 10 ms for the next 60 ms.
    fn busy(&mut self, cx: &mut Cx<Frame>) {
        self.burst_until = cx.now() + 60 * MS;
        if !self.burst_armed {
            self.burst_armed = true;
            cx.set_timer(10 * MS, T_BURST);
        }
    }

    fn send_to(&mut self, cx: &mut Cx<Frame>, to: NodeId, f: Frame, msg: Option<MsgId>) -> bool {
        let size = Self::size(&f);
        let control = Self::is_control(&f);
        if control {
            let kind = match &f {
                Frame::Ann(_) | Frame::Req(_) => 0,
                Frame::Summary(_) | Frame::Offer(_) | Frame::Answer { .. } | Frame::BundleAck { .. } => 1,
                Frame::Dial | Frame::DialAck | Frame::Hangup => 2,
                _ => 3,
            };
            self.ctrl_by_kind[kind] += size as u64;
        }
        if cx.radios_to(to).is_some() {
            cx.send_radio(to, f, size, control, msg)
        } else {
            cx.send_inet(to, f, size, control, msg)
        }
    }

    fn inet_units(cx: &Cx<Frame>, peer: NodeId) -> u32 {
        let d = cx.inet_delay_to(peer).unwrap_or(100 * MS);
        let up = cx.access().map_or(1_000_000, |a| a.uplink());
        units(d, up)
    }

    /// Carry out what the core asked for.
    fn effects(&mut self, cx: &mut Cx<Frame>) {
        let mut outs = std::mem::take(&mut self.buf);
        self.core.drain(&mut outs);
        let now = Self::ms(cx);
        for o in outs.drain(..) {
            match o {
                Out::Announce { to, mut ann } => {
                    if self.role == Role::BlackHole && ann.origin != self.pk && ann.cost != mc::INFINITY {
                        ann.cost = 0; // "everyone is right here"
                    }
                    self.send_to(cx, node(&to), Frame::Ann(ann), None);
                }
                Out::SeqReq { to, req } => {
                    self.send_to(cx, node(&to), Frame::Req(req), None);
                }
                Out::Frame { to, frame, relayed } => {
                    if relayed && self.role == Role::BlackHole {
                        continue; // swallowed
                    }
                    let msg = packet_msg(&frame.payload);
                    self.send_to(cx, node(&to), Frame::Data(frame), msg);
                }
                Out::Deliver { src, payload, .. } => self.on_packet(cx, node(&src), payload),
                Out::Control { .. } => {}
                Out::Dial(peer) => {
                    let p = node(&peer);
                    if !cx.has_inet() || !cx.send_inet(p, Frame::Dial, HANDSHAKE, true, None) {
                        self.core.dial_failed(peer, now);
                    }
                }
                Out::Hangup(peer) => {
                    self.core.hop_down(peer, now);
                    cx.send_inet(node(&peer), Frame::Hangup, 50, true, None);
                }
                Out::Resolve(peer) => {
                    if !cx.reach_get(node(&peer), node(&peer) as u64) {
                        self.core.on_resolved(peer, None, now);
                    }
                }
                Out::PublishReach { gateways } => {
                    cx.reach_put(gateways.iter().map(|(g, c)| (node(g), *c)).collect());
                }
                Out::RouteUp { .. } => self.shared.routes_up.set(self.shared.routes_up.get() + 1),
                Out::RouteDown { .. } => self.shared.routes_down.set(self.shared.routes_down.get() + 1),
            }
        }
        self.buf = outs;
        // effects may have queued more (e.g. a resolve answered inline)
        let mut more = Vec::new();
        self.core.drain(&mut more);
        if !more.is_empty() {
            self.buf.extend(more);
            self.effects(cx);
        }
    }

    /// A whole packet for us.
    fn on_packet(&mut self, cx: &mut Cx<Frame>, src: NodeId, p: Bytes) {
        if p.len() < PKT_HDR {
            return;
        }
        let msg = u32::from_be_bytes(p[1..5].try_into().expect("4"));
        match p[0] {
            TAG_DATA => {
                let part = u16::from_be_bytes([p[5], p[6]]);
                let parts = u16::from_be_bytes([p[7], p[8]]);
                self.ack(cx, src, msg, part);
                if self.done.contains(&msg) {
                    return;
                }
                let got = self.inbox.entry(msg).or_default();
                got.insert(part);
                if got.len() >= parts as usize {
                    self.inbox.remove(&msg);
                    self.done.insert(msg);
                    cx.delivered(msg);
                }
            }
            TAG_ACK => {
                let part = u16::from_be_bytes([p[5], p[6]]);
                let now = cx.now();
                let Some(o) = self.outbox.get_mut(&msg) else { return };
                if let Some(sent) = o.inflight.remove(&part) {
                    let rtt = now.saturating_sub(sent);
                    let s = o.srtt.map_or(rtt, |s| (7 * s + rtt) / 8);
                    o.srtt = Some(s);
                    o.rto = (2 * s).clamp(200 * MS, 30 * SEC);
                }
                if (part as usize) < o.acked.len() && !o.acked[part as usize] {
                    o.acked[part as usize] = true;
                    o.left -= 1;
                    o.cwnd = (o.cwnd + 1.0).min(MAX_WINDOW);
                }
                if o.left == 0 {
                    self.outbox.remove(&msg);
                    cx.receipt(msg);
                } else {
                    self.transmit(cx, msg);
                }
            }
            _ => {}
        }
    }

    fn ack(&mut self, cx: &mut Cx<Frame>, to: NodeId, msg: MsgId, part: u16) {
        let p = packet(TAG_ACK, msg, part, 1, 40);
        self.send_packet(cx, to, p);
    }

    fn send_packet(&mut self, cx: &mut Cx<Frame>, dst: NodeId, p: Bytes) {
        let msg = packet_msg(&p);
        let size = p.len() as u32;
        if cx.radios_to(dst).is_some() {
            // a direct path: never through the mesh
            cx.send_radio(dst, Frame::Direct(p), size, false, msg);
            return;
        }
        let (now_us, pk) = (cx.now(), key(dst));
        // a connection to it over the internet: Iroh's own, direct (as in the
        // node; the core refuses data for a neighbour, and an internet hop
        // is one)
        if self.conn_warm(dst, now_us) || self.core.is_neighbour(&pk) {
            if cx.send_inet(dst, Frame::Direct(p.clone()), size + 20, false, msg) {
                self.conns.insert(dst, now_us);
                return;
            }
            self.conns.remove(&dst);
        }
        let now = Self::ms(cx);
        self.core.send(pk, self.pk, p, false, now);
        self.effects(cx);
        self.busy(cx);
    }

    /// We exchanged packets with `peer` over the internet within the
    /// node's connection-pool idle time ([`mycel_net::POOL_IDLE`]).
    fn conn_warm(&self, peer: NodeId, now_us: Time) -> bool {
        self.conns.get(&peer).is_some_and(|t| now_us.saturating_sub(*t) < POOL_IDLE_US)
    }

    /// Send what the window allows: parts not acked and not in flight.
    fn transmit(&mut self, cx: &mut Cx<Frame>, msg: MsgId) {
        let now = cx.now();
        let Some(o) = self.outbox.get_mut(&msg) else { return };
        let room = (o.cwnd as usize).saturating_sub(o.inflight.len());
        let body = PACKET - PKT_HDR as u32;
        let (dst, size, parts) = (o.dst, o.size, o.parts);
        let mut send = Vec::new();
        for i in 0..parts {
            if send.len() >= room {
                break;
            }
            if !o.acked[i as usize] && !o.inflight.contains_key(&i) {
                o.inflight.insert(i, now);
                send.push(i);
            }
        }
        for i in send {
            let len = if i + 1 == parts { size - i as u32 * body } else { body };
            let p = packet(TAG_DATA, msg, i, parts, len as usize + PKT_HDR);
            self.send_packet(cx, dst, p);
        }
    }

    pub fn loops(&self) -> u64 {
        self.shared.loops.get()
    }
}

fn packet(tag: u8, msg: MsgId, part: u16, parts: u16, len: usize) -> Bytes {
    let mut b = BytesMut::with_capacity(len.max(PKT_HDR));
    b.put_u8(tag);
    b.put_u32(msg);
    b.put_u16(part);
    b.put_u16(parts);
    b.resize(len.max(PKT_HDR), 0);
    b.freeze()
}

fn packet_msg(p: &Bytes) -> Option<MsgId> {
    (p.len() >= PKT_HDR && p[0] == TAG_DATA).then(|| u32::from_be_bytes(p[1..5].try_into().expect("4")))
}

impl Router for Global {
    type Frame = Frame;

    fn size(f: &Frame) -> u32 {
        match f {
            Frame::Ann(a) => (1 + 1 + 4 + 32 + 8 + 1 + 1 + 4 + 1 + a.name.len() + 64) as u32,
            Frame::Req(_) => 1 + 32 + 8 + 1,
            Frame::Data(d) => (mycel_net::mesh::wire::DATA_HDR + d.payload.len()) as u32,
            Frame::Direct(p) => p.len() as u32 + 20,
            Frame::Dial | Frame::DialAck => HANDSHAKE,
            Frame::Hangup => 50,
            Frame::Offer(_) => 200,
            Frame::Answer { .. } => 60,
            Frame::Bundle(b, _) => b.payload.len() as u32 + 80,
            Frame::BundleAck { .. } => 80,
            Frame::Summary(s) => {
                (16 + 32 * s.ids.len()
                    + 96 * s.receipts.len()
                    + 36 * s.preds.len()
                    + 16 * s.evictable.len()
                    + 32 * s.wants.len()) as u32
            }
        }
    }

    fn is_control(f: &Frame) -> bool {
        match f {
            Frame::Data(d) => d.control || d.payload.first() == Some(&TAG_ACK),
            Frame::Direct(p) => p.first() == Some(&TAG_ACK),
            Frame::Bundle(..) => false,
            _ => true,
        }
    }

    fn msg_of(f: &Frame) -> Option<MsgId> {
        match f {
            Frame::Data(d) => packet_msg(&d.payload),
            Frame::Direct(p) => packet_msg(p),
            Frame::Bundle(b, _) => Some(bundle_msg(&b.id)),
            _ => None,
        }
    }

    fn on_start(&mut self, cx: &mut Cx<Frame>) {
        self.core.set_internet(cx.has_inet());
        if let Some(a) = cx.access() {
            self.core.set_uplink(units(a.latency().as_micros() as Time, a.uplink()));
        }
        let phase = (cx.rng().f64() * self.period as f64) as Time;
        cx.set_timer(phase + 1, T_HOUSE);
    }

    fn on_link(&mut self, cx: &mut Cx<Frame>, nb: NodeId, techs: Techs, up: bool) {
        let (pk, now) = (key(nb), Self::ms(cx));
        if up {
            self.core.set_direct(pk, true, now);
            self.core.hop_up(pk, now);
            self.core.set_cost(pk, radio_units(techs));
            if let Some(c) = self.dtn.as_mut() {
                c.encounter(pk, now);
                c.new_contact(pk);
                for (k, s) in c.summaries(now, &[pk]) {
                    if !self.send_to(cx, node(&k), Frame::Summary(Rc::new(s)), None)
                        && let Some(c) = self.dtn.as_mut()
                    {
                        c.new_contact(k);
                    }
                }
            }
        } else {
            self.core.hop_down(pk, now);
            self.core.set_direct(pk, false, now);
        }
        self.effects(cx);
        self.busy(cx);
    }

    fn on_inet(&mut self, cx: &mut Cx<Frame>, up: bool) {
        self.core.set_internet(up);
        self.effects(cx);
        self.busy(cx);
        self.dtn_plan(cx);
    }

    fn on_frame(&mut self, cx: &mut Cx<Frame>, from: NodeId, over: Over, f: Frame) {
        if !cx.online() {
            return;
        }
        let (fpk, now) = (key(from), Self::ms(cx));
        match f {
            Frame::Ann(a) => {
                if self.role == Role::Replayer && self.old.len() < 200 {
                    self.old.push(a.clone());
                }
                self.core.on_announce(fpk, a, now, WALL_MS + now, |_| true)
            }
            Frame::Req(r) => self.core.on_seqreq(fpk, r, now),
            Frame::Data(d) => {
                let k = (d.src, d.id);
                if d.offset == 0 && self.seen.insert(k, cx.now()).is_some() {
                    self.shared.loops.set(self.shared.loops.get() + 1);
                }
                self.core.on_frame(fpk, d, now);
            }
            Frame::Direct(p) => {
                if matches!(over, Over::Inet) {
                    self.conns.insert(from, cx.now());
                }
                self.on_packet(cx, from, p)
            }
            Frame::Dial => {
                self.conns.insert(from, cx.now());
                self.core.hop_up(fpk, now);
                let c = Self::inet_units(cx, from);
                self.core.set_cost(fpk, c);
                cx.send_inet(from, Frame::DialAck, HANDSHAKE, true, None);
            }
            Frame::DialAck => {
                self.conns.insert(from, cx.now());
                self.core.hop_up(fpk, now);
                let c = Self::inet_units(cx, from);
                self.core.set_cost(fpk, c);
            }
            Frame::Hangup => self.core.hop_down(fpk, now),
            Frame::Bundle(b, copies) => {
                let id = b.id;
                let msg = bundle_msg(&id);
                let (ok, stored) = match self.dtn.as_mut().map(|c| c.accept(fpk, b, copies, now, |_| true)) {
                    Some(Accepted::ForMe(b)) => {
                        cx.delivered(msg);
                        if let Some(c) = self.dtn.as_mut() {
                            c.add_receipt(Receipt { id: b.id, dst: self.pk, sig: Sig([0; 64]) });
                        }
                        (true, false)
                    }
                    Some(Accepted::Stored) => {
                        cx.handed(msg);
                        (true, true)
                    }
                    Some(Accepted::Duplicate) => (true, false),
                    Some(Accepted::Refused(_)) | None => (false, false),
                };
                self.send_to(cx, from, Frame::BundleAck { id, copies, ok, stored }, None);
                self.dtn_plan(cx);
            }
            Frame::Offer(o) => {
                let answer =
                    self.dtn.as_mut().map_or(Answer::Refuse("not carrying"), |c| c.offered(fpk, &o, now, |_| true));
                self.send_to(cx, from, Frame::Answer { id: o.id, copies: o.copies, answer }, None);
            }
            Frame::Answer { id, copies, answer } => {
                let Some(c) = self.dtn.as_mut() else { return };
                match answer {
                    Answer::Take { .. } => match c.bundle(&id).cloned() {
                        // (frames arrive whole here: nothing to resume)
                        Some(b) => {
                            let msg = bundle_msg(&id);
                            if !self.send_to(cx, from, Frame::Bundle(b, copies), Some(msg))
                                && let Some(c) = self.dtn.as_mut()
                            {
                                c.transferred(fpk, id, copies, false, now);
                            }
                        }
                        None => c.transferred(fpk, id, copies, false, now),
                    },
                    Answer::Duplicate => c.transferred(fpk, id, copies, true, now),
                    Answer::Refuse(why) => c.refused(fpk, id, why == "store full", now),
                }
                self.note_buffer(cx);
            }
            Frame::BundleAck { id, copies, ok, stored } => {
                if let Some(c) = self.dtn.as_mut() {
                    c.transferred(fpk, id, copies, ok, now);
                    // a new replica only if we kept some copies; handing on
                    // the last one moves it (custody)
                    if stored && c.holds(&id) {
                        cx.copied(bundle_msg(&id));
                    }
                }
                self.note_buffer(cx);
            }
            Frame::Summary(s) => {
                if let Some(c) = self.dtn.as_mut() {
                    c.on_summary(fpk, (*s).clone(), now, |_| true);
                }
                self.dtn_plan(cx);
            }
        }
        self.effects(cx);
        self.busy(cx);
    }

    fn on_timer(&mut self, cx: &mut Cx<Frame>, token: u64) {
        let now = Self::ms(cx);
        match token & 0xff {
            T_HOUSE => {
                if self.role == Role::Replayer && self.old.len() >= 100 {
                    // recordings an hour old (seqnos are the origin's wall clock;
                    // signatures are stubbed here, a real recording keeps its own)
                    let old: Vec<Announce> =
                        self.old.drain(..50).map(|a| Announce { seq: a.seq.saturating_sub(3_600_000), ..a }).collect();
                    for nb in cx.neighbours() {
                        for a in &old {
                            self.send_to(cx, nb.0, Frame::Ann(a.clone()), None);
                        }
                    }
                }
                let storm = self.role == Role::Storm && cx.online();
                if storm || (cx.online() && self.core.announce_due(now)) {
                    let o = self.core.next_announce(WALL_MS + now);
                    let a = Announce {
                        hops: 0,
                        cost: 0,
                        origin: self.pk,
                        seq: o.seq,
                        flags: o.flags,
                        scope: o.scope,
                        uplink: o.uplink,
                        name: self.name.clone(),
                        sig: Sig([0; 64]),
                    };
                    self.core.originate(a, now);
                    self.busy(cx);
                }
                self.core.tick(now);
                self.effects(cx);
                if self.dtn.is_some() {
                    if let Some(c) = self.dtn.as_mut() {
                        c.tick(now);
                    }
                    let encounters = now / 10_000 != now.saturating_sub(self.period / MS) / 10_000;
                    self.dtn_summaries(cx, encounters);
                    self.dtn_plan(cx);
                }
                // forget packet ids after a while (loop detection window)
                if self.seen.len() > 4096 {
                    let cut = cx.now().saturating_sub(30 * SEC);
                    self.seen.retain(|_, t| *t > cut);
                }
                let p = if self.role == Role::Storm { 10 * MS } else { self.period };
                cx.set_timer(p, T_HOUSE);
            }
            T_BURST => {
                self.core.tick(now);
                self.effects(cx);
                if cx.now() < self.burst_until {
                    cx.set_timer(10 * MS, T_BURST);
                } else {
                    self.burst_armed = false;
                }
            }
            T_RETRY => {
                let msg = (token >> 8) as MsgId;
                let now_us = cx.now();
                let Some(o) = self.outbox.get_mut(&msg) else { return };
                if now_us.saturating_sub(o.started) > 10 * 60 * SEC {
                    self.outbox.remove(&msg);
                    return;
                }
                // anything in flight longer than the RTO is lost: resend, back off
                let rto = o.rto;
                let lost: Vec<u16> =
                    o.inflight.iter().filter(|(_, t)| now_us.saturating_sub(**t) >= rto).map(|(p, _)| *p).collect();
                if !lost.is_empty() {
                    for p in lost {
                        o.inflight.remove(&p);
                    }
                    o.cwnd = (o.cwnd / 2.0).max(2.0);
                    o.rto = (o.rto * 2).min(30 * SEC);
                }
                let next = o.rto;
                let (dst, size, none_acked) = (o.dst, o.size, o.left == o.parts);
                self.transmit(cx, msg);
                cx.set_timer(next, T_RETRY | (msg as u64) << 8);
                // the live attempt isn't getting through: store-and-forward too
                if none_acked && self.dtn.is_some() && self.bundled.insert(msg) {
                    self.originate_bundle(cx, msg, dst, size);
                }
            }
            _ => {}
        }
    }

    fn on_send(&mut self, cx: &mut Cx<Frame>, msg: MsgId, dst: NodeId, size: u32) {
        cx.copied(msg);
        let parts = size.div_ceil(PACKET - PKT_HDR as u32).max(1) as u16;
        self.outbox.insert(
            msg,
            Outgoing {
                dst,
                size,
                parts,
                acked: vec![false; parts as usize],
                left: parts,
                inflight: Map::default(),
                cwnd: INITIAL_WINDOW,
                srtt: None,
                rto: SEC,
                started: cx.now(),
            },
        );
        self.transmit(cx, msg);
        cx.set_timer(SEC, T_RETRY | (msg as u64) << 8);
    }

    fn on_reach(&mut self, cx: &mut Cx<Frame>, token: u64, gateways: Option<Vec<(NodeId, u32)>>) {
        let target = key(token as NodeId);
        let now = Self::ms(cx);
        let gws = gateways.map(|v| v.into_iter().map(|(g, c)| (key(g), c)).collect());
        self.core.on_resolved(target, gws, now);
        self.effects(cx);
        self.busy(cx);
    }

    fn on_undelivered(&mut self, cx: &mut Cx<Frame>, to: NodeId, f: Frame) {
        let now = Self::ms(cx);
        match f {
            Frame::Dial => {
                self.core.dial_failed(key(to), now);
                self.effects(cx);
            }
            Frame::Bundle(b, copies) => {
                if let Some(c) = self.dtn.as_mut() {
                    c.transferred(key(to), b.id, copies, false, now);
                }
            }
            Frame::Offer(o) => {
                if let Some(c) = self.dtn.as_mut() {
                    c.transferred(key(to), o.id, o.copies, false, now);
                }
            }
            // a summary that didn't arrive: the next one tells it everything
            Frame::Summary(_) => {
                if let Some(c) = self.dtn.as_mut() {
                    c.new_contact(key(to));
                }
            }
            _ => {}
        }
    }

    fn on_online(&mut self, cx: &mut Cx<Frame>, online: bool) {
        let now = Self::ms(cx);
        if !online {
            self.conns.clear();
        }
        self.core.set_internet(online && cx.has_inet());
        self.core.tick(now);
        self.effects(cx);
    }
}
