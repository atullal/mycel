//! Mycel's mesh router (`mycel_net::mesh::core::Router`, the real code) on
//! the topologies and direct messages of Meshtasticator runs
//! (`bench/meshtasticator/run.py`), to compare against Meshtastic's managed
//! flooding.
//!
//! The router runs on a virtual clock like its own test harness
//! (`mesh/core/tests.rs`): links are the Meshtasticator run's links (RSSI at
//! or above the modem's sensitivity), each hop is a reliable unicast link
//! with a fixed delay, and no collisions or airtime are modelled. That suits
//! Mycel's radios (Bluetooth, Wi-Fi) and favours it on LoRa, so the numbers
//! that compare are *what has to be transmitted*: data transmissions per
//! delivered message, and the routing protocol's own announcements, also
//! expressed as the LoRa airtime they'd need.
//!
//! Usage: mesh-routing <run.json>... (prints one CSV row per file)

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;

use bytes::Bytes;
use mycel_crypto::{Sig, SignPk};
use mycel_net::mesh::core::{Announce, Config, Frame, Out, Router, SeqReq, Time};

const WALL: u64 = 1_700_000_000_000;
const STEP: Time = 5;
const HOP_DELAY: Time = 5;
const RETRY_EVERY: Time = 100;
const GIVE_UP: Time = 30_000;

fn key(i: usize) -> SignPk {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&(i as u32).to_be_bytes());
    k[31] = 0x6d;
    SignPk(k)
}

enum Msg {
    Ann(Announce),
    Req(SeqReq),
    Frame(Frame),
    /// A direct (one-hop, not mesh) message.
    Direct(u64),
}

struct Net {
    nodes: Vec<Router>,
    index: HashMap<SignPk, usize>,
    links: HashSet<(usize, usize)>,
    now: Time,
    queue: BinaryHeap<Reverse<(Time, u64, usize, usize)>>,
    msgs: HashMap<u64, Msg>,
    next: u64,
    ann_sends: u64,
    ann_broadcasts: HashSet<(usize, SignPk, u64)>,
    seqreq_sends: u64,
    data_sends: u64,
    delivered: HashMap<u64, (Time, usize)>,
}

impl Net {
    fn post(&mut self, from: usize, to: usize, m: Msg) {
        let id = self.next;
        self.next += 1;
        self.msgs.insert(id, m);
        self.queue.push(Reverse((self.now + HOP_DELAY, id, from, to)));
    }

    fn effects(&mut self, i: usize) {
        let mut outs = Vec::new();
        self.nodes[i].drain(&mut outs);
        for o in outs {
            match o {
                Out::Announce { to, ann } => {
                    self.ann_sends += 1;
                    self.ann_broadcasts.insert((i, ann.origin, ann.seq));
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Ann(ann));
                    }
                }
                Out::SeqReq { to, req } => {
                    self.seqreq_sends += 1;
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Req(req));
                    }
                }
                Out::Frame { to, frame, .. } => {
                    self.data_sends += 1;
                    if let Some(&j) = self.index.get(&to) {
                        self.post(i, j, Msg::Frame(frame));
                    }
                }
                Out::Deliver { payload, .. } => {
                    let id = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    self.delivered.entry(id).or_insert((self.now, i));
                }
                _ => {}
            }
        }
    }

    fn pump(&mut self) {
        while let Some(Reverse((at, id, from, to))) = self.queue.peek().copied() {
            if at > self.now {
                break;
            }
            self.queue.pop();
            let m = self.msgs.remove(&id).unwrap();
            let (f, now) = (key(from), self.now);
            match m {
                Msg::Ann(a) => self.nodes[to].on_announce(f, a, now, WALL + now, |_| true),
                Msg::Req(r) => self.nodes[to].on_seqreq(f, r, now),
                Msg::Frame(fr) => self.nodes[to].on_frame(f, fr, now),
                Msg::Direct(mid) => {
                    self.delivered.entry(mid).or_insert((now, to));
                }
            }
            self.effects(to);
        }
    }

    fn step(&mut self) {
        self.now += STEP;
        self.pump();
        if self.now.is_multiple_of(10) {
            for i in 0..self.nodes.len() {
                let now = self.now;
                let r = &mut self.nodes[i];
                if r.announce_due(now) {
                    let o = r.next_announce(WALL + now);
                    let a = Announce {
                        hops: 0,
                        cost: 0,
                        origin: r.me(),
                        seq: o.seq,
                        flags: o.flags,
                        scope: o.scope,
                        uplink: o.uplink,
                        name: Arc::from(""),
                        sig: Sig([0; 64]),
                    };
                    r.originate(a, now);
                }
                r.tick(now);
                self.effects(i);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    src: usize,
    dst: usize,
    born: Time,
}

fn run(path: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let n = v["nodes"].as_u64().unwrap() as usize;
    let simtime = v["simtime_ms"].as_f64().unwrap() as Time;
    let links: Vec<(usize, usize)> = v["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l[0].as_u64().unwrap() as usize, l[1].as_u64().unwrap() as usize))
        .collect();
    let mut todo: Vec<Pending> = v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(k, m)| Pending {
            id: k as u64,
            src: m[0].as_u64().unwrap() as usize,
            dst: m[1].as_u64().unwrap() as usize,
            born: m[2].as_f64().unwrap() as Time,
        })
        .collect();
    todo.sort_by_key(|p| p.born);
    let total = todo.len();
    let nodes: Vec<Router> =
        (0..n).map(|i| Router::new(key(i), Config { seed: i as u64 + 1, ..Config::default() })).collect();
    let mut net = Net {
        index: nodes.iter().enumerate().map(|(i, r)| (r.me(), i)).collect(),
        nodes,
        links: HashSet::new(),
        now: 0,
        queue: BinaryHeap::new(),
        msgs: HashMap::new(),
        next: 0,
        ann_sends: 0,
        ann_broadcasts: HashSet::new(),
        seqreq_sends: 0,
        data_sends: 0,
        delivered: HashMap::new(),
    };
    for &(a, b) in &links {
        net.links.insert((a, b));
        for (x, y) in [(a, b), (b, a)] {
            net.nodes[x].set_direct(key(y), true, 0);
            net.nodes[x].hop_up(key(y), 0);
        }
    }
    let mut waiting: Vec<Pending> = Vec::new();
    let mut gave_up = 0;
    let mut k = 0;
    while net.now < simtime + 5_000 {
        net.step();
        let now = net.now;
        let mut batch: Vec<Pending> = Vec::new();
        while k < todo.len() && todo[k].born <= now {
            batch.push(todo[k]);
            k += 1;
        }
        if now.is_multiple_of(RETRY_EVERY) {
            batch.append(&mut waiting);
        }
        if !batch.is_empty() {
            let mut still = Vec::new();
            for p in batch {
                let dk = key(p.dst);
                if net.links.contains(&(p.src.min(p.dst), p.src.max(p.dst))) {
                    // neighbours talk directly, not through the mesh
                    net.data_sends += 1;
                    net.post(p.src, p.dst, Msg::Direct(p.id));
                    continue;
                }
                let sent = net.nodes[p.src].next_hop_local(&dk, now).is_some_and(|wp| {
                    let mut payload = vec![0u8; 40];
                    payload[..8].copy_from_slice(&p.id.to_be_bytes());
                    net.nodes[p.src].send(dk, wp, Bytes::from(payload), false, now)
                });
                if sent {
                    net.effects(p.src);
                } else if now.saturating_sub(p.born) < GIVE_UP {
                    still.push(p);
                } else {
                    gave_up += 1;
                }
            }
            waiting.extend(still);
        }
    }
    let delivered = net.delivered.len();
    let minutes = simtime as f64 / 60_000.0;
    let airtime_ann = v["airtime_180b_ms"].as_f64().unwrap_or(f64::NAN);
    // LoRa share of time each node would spend sending announcements
    let ann_util = net.ann_broadcasts.len() as f64 * airtime_ann / (n as f64 * simtime as f64);
    format!(
        "{},{},{},{},{},{},{},{:.3},{},{},{},{:.2},{:.4}",
        v["nodes"],
        v["hop_limit"],
        v["rep"],
        links.len(),
        total,
        delivered,
        gave_up,
        net.data_sends as f64 / delivered.max(1) as f64,
        net.ann_sends,
        net.ann_broadcasts.len(),
        net.seqreq_sends,
        net.ann_broadcasts.len() as f64 / n as f64 / minutes,
        ann_util,
    )
}

fn main() {
    println!(
        "nodes,hop_limit,rep,links,messages,delivered,no_route,data_tx_per_delivered,ann_unicast,ann_broadcast_equiv,seqreq,ann_bcast_per_node_min,lora_ann_airtime_share"
    );
    for path in std::env::args().skip(1) {
        println!("{}", run(&path));
    }
}
