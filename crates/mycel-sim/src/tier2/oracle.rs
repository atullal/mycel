//! The fastest path that was physically possible: an earliest-arrival
//! search over the recorded contact plan (who was in radio range of whom
//! when, who had internet when), carrying a message of a given size
//! store-and-forward hop by hop, waiting anywhere for free (any device can
//! hold it). This is the ground truth each delivered message is compared
//! with: `achieved / optimal` is the routing's optimality ratio.
//!
//! The internet is used at most once on a path (two internet hops are never
//! faster than one: each adds access delay on both ends). Internet delay
//! between two devices is the same model the engine uses (access + fibre
//! over the great circle, or via the relays when NAT forbids direct).
//! Queueing and contention are ignored: the oracle is a lower bound.
//!
//! A message of several packets can be pipelined: its first packets move on
//! while later ones are still arriving, which beats moving it whole hop by
//! hop. For those the bound is the fastest single packet plus the rest of
//! the message at the most the destination can take in at once (all its
//! radios and the fastest internet access together), never more than the
//! hop-by-hop time.

use crate::stats::Map;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::engine::{NodeId, Router, SEC, Sim, Time, hop_time};
use crate::models::Access;

/// One packet's payload: messages this small can't be pipelined.
pub const ONE_PACKET: u32 = 1200;

/// Adjacency built once from the contact plan.
pub struct Oracle {
    adj: Vec<Vec<(NodeId, u32)>>,
    /// Per pair (index into `windows`): [(from, to, radios)].
    windows: Vec<Vec<(Time, Time, super::engine::Techs)>>,
    inet: Vec<Vec<(Time, Time)>>,
    /// Devices that ever had internet, by radio area: radio never crosses
    /// areas, so only those in the destination's area can finish a path.
    inet_by_area: Map<u32, Vec<NodeId>>,
}

impl Oracle {
    pub fn new<R: Router>(sim: &Sim<R>) -> Oracle {
        let n = sim.core.len();
        let mut adj = vec![Vec::new(); n];
        let mut windows = Vec::new();
        let mut pairs: Vec<(&(NodeId, NodeId), &Vec<_>)> = sim.core.contacts.radio.iter().collect();
        pairs.sort_by_key(|p| *p.0);
        for ((a, b), w) in pairs {
            let idx = windows.len() as u32;
            windows.push(w.clone());
            adj[*a as usize].push((*b, idx));
            adj[*b as usize].push((*a, idx));
        }
        let inet = sim.core.contacts.inet.clone();
        let mut inet_by_area: Map<u32, Vec<NodeId>> = Map::default();
        for i in (0..n as NodeId).filter(|i| !inet[*i as usize].is_empty()) {
            inet_by_area.entry(sim.core.spec(i).area).or_default().push(i);
        }
        Oracle { adj, windows, inet, inet_by_area }
    }

    /// Earliest a message of `size` sent at `t0` from `src` can reach `dst`.
    pub fn earliest<R: Router>(&self, sim: &Sim<R>, src: NodeId, dst: NodeId, t0: Time, size: u32) -> Option<Time> {
        self.earliest_avoiding(sim, src, dst, t0, size, None)
    }

    /// [`Oracle::earliest`] through devices not marked in `avoid` (indexed
    /// by device): the fastest path that needs none of them, or `None` if
    /// every path in the contact plan crosses one. `src` and `dst` are
    /// never avoided.
    pub fn earliest_avoiding<R: Router>(
        &self,
        sim: &Sim<R>,
        src: NodeId,
        dst: NodeId,
        t0: Time,
        size: u32,
        avoid: Option<&[bool]>,
    ) -> Option<Time> {
        let n = self.adj.len();
        let banned = |v: NodeId| v != dst && avoid.is_some_and(|a| a.get(v as usize).copied().unwrap_or(false));
        let mut best: Map<NodeId, Time> = Map::default();
        let mut pq: BinaryHeap<Reverse<(Time, NodeId)>> = BinaryHeap::new();
        best.insert(src, t0);
        pq.push(Reverse((t0, src)));
        // internet entries popped so far: (when it entered, node)
        let mut first_inet: Option<Time> = None;
        let mut inet_done = false;
        // the longest internet detour (relays across the world) is well under this
        const WINDOW: Time = 600_000;
        while let Some(Reverse((t, u))) = pq.pop() {
            if best.get(&u).is_some_and(|b| *b < t) {
                continue;
            }
            if u == dst {
                return Some(t);
            }
            // radio hops
            for (v, w) in &self.adj[u as usize] {
                if banned(*v) {
                    continue;
                }
                for (from, to, techs) in &self.windows[*w as usize] {
                    if *to <= t {
                        continue;
                    }
                    let Some(tech) = techs.best(size) else { continue };
                    let depart = t.max(*from);
                    let arrive = depart + hop_time(tech, size);
                    if arrive > *to {
                        continue; // the contact ends before it's through
                    }
                    if best.get(v).is_none_or(|b| arrive < *b) {
                        best.insert(*v, arrive);
                        pq.push(Reverse((arrive, *v)));
                    }
                    break; // later windows only arrive later
                }
            }
            // one internet hop, from the devices that reach it first
            if !inet_done && let Some(enter) = self.inet_window(u, t) {
                let f = *first_inet.get_or_insert(enter);
                if enter > f + WINDOW {
                    inet_done = true;
                    continue;
                }
                let up = sim.core.spec(u).inet.expect("inet").access.uplink();
                let air = size as u64 * 1_000_000 / up;
                let targets = self.inet_by_area.get(&sim.core.spec(dst).area).map_or(&[][..], |v| &v[..]);
                for &b in targets {
                    if b == u || banned(b) {
                        continue;
                    }
                    let arrive = enter + air + sim.inet_delay_any(u, b);
                    if !self.inet[b as usize].iter().any(|(s, e)| *s <= arrive && arrive < *e) {
                        continue;
                    }
                    if best.get(&b).is_none_or(|x| arrive < *x) {
                        best.insert(b, arrive);
                        pq.push(Reverse((arrive, b)));
                    }
                }
            }
            let _ = n;
        }
        None
    }

    /// Devices in the contact plan.
    pub fn len(&self) -> usize {
        self.adj.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adj.is_empty()
    }

    /// Pairs in radio contact at some time at or after `t`, over radios
    /// that can carry `size` bytes: the union of the contact graph from
    /// `t` on (a static world's links; for a moving one, a superset of what
    /// any one moment offers).
    pub fn links_after(&self, t: Time, size: u32) -> Vec<(NodeId, NodeId)> {
        let mut out = Vec::new();
        for (u, nbs) in self.adj.iter().enumerate() {
            for (v, w) in nbs {
                if (u as NodeId) < *v
                    && self.windows[*w as usize].iter().any(|(_, to, techs)| *to > t && techs.best(size).is_some())
                {
                    out.push((u as NodeId, *v));
                }
            }
        }
        out
    }

    /// Whether `u` has internet at some time at or after `t`.
    pub fn inet_after(&self, u: NodeId, t: Time) -> bool {
        self.inet_window(u, t).is_some()
    }

    /// When `u` can first use its internet at or after `t`.
    fn inet_window(&self, u: NodeId, t: Time) -> Option<Time> {
        self.inet[u as usize].iter().find(|(_, e)| *e > t).map(|(s, _)| t.max(*s))
    }

    /// The most bytes per second `dst` can receive: every radio at once,
    /// plus the fastest internet access there is if it has internet.
    fn max_rate_into<R: Router>(&self, sim: &Sim<R>, dst: NodeId) -> u64 {
        let spec = sim.core.spec(dst);
        let radios: u64 = spec.radios.iter().map(|t| t.rate()).sum();
        radios + spec.inet.map_or(0, |_| Access::Fibre.uplink())
    }

    /// The bound for a message of `size` (see the module docs).
    pub fn optimal<R: Router>(&self, sim: &Sim<R>, src: NodeId, dst: NodeId, t0: Time, size: u32) -> Option<Time> {
        let whole = self.earliest(sim, src, dst, t0, size)?;
        if size <= ONE_PACKET {
            return Some(whole);
        }
        let first = self.earliest(sim, src, dst, t0, ONE_PACKET).unwrap_or(whole);
        let rest = (size - ONE_PACKET) as u64 * SEC / self.max_rate_into(sim, dst).max(1);
        Some(whole.min(first + rest))
    }

    /// Fill `optimal` for every message (or for `sample` of them).
    pub fn annotate<R: Router>(&self, sim: &mut Sim<R>, sample: Option<usize>) {
        let n = sim.core.msgs.len();
        let step = sample.map_or(1, |s| (n / s.max(1)).max(1));
        for i in (0..n).step_by(step) {
            let m = sim.core.msgs[i].clone();
            let opt = self.optimal(sim, m.src, m.dst, m.sent, m.size);
            sim.core.msgs[i].optimal = opt;
            sim.core.msgs[i].checked = true;
        }
    }
}
