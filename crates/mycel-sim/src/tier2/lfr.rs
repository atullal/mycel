//! What devices that drop traffic *must* cost, as opposed to what the
//! defences let them cost: liar-free-reachable (LFR) delivery.
//!
//! Menger's theorem sets the limit: tolerating f droppers anywhere needs
//! f + 1 vertex-disjoint paths, and a pair whose every path crosses a
//! dropper can't be served without its cooperation, whatever the routing
//! does. So against devices that drop everything (black holes, liars) a
//! raw delivery ratio mixes two things: pairs the defence lost, and pairs
//! no defence could save. This module separates them, per run:
//!
//! - **LFR-reachable**: the honest pair still has a path once every
//!   dropper is removed, on the time-expanded contact graph: the oracle's
//!   own earliest-arrival search ([`Oracle::earliest_avoiding`]), store and
//!   forward included, so mobility and DTN count.
//! - **LFR delivery** = delivered / LFR-reachable: how much of what *could*
//!   be saved was. Raw delivery is delivered / feasible, as everywhere.
//! - **Liar-cut**: feasible messages every path of which crosses a
//!   dropper, and the distinct (source, destination) pairs they're between.
//! - **f + 1 disjoint paths**: pairs with at least f + 1 vertex-disjoint
//!   paths (f = the number of droppers), which no placement of the
//!   droppers can cut, and the honest pairs' own count of disjoint paths
//!   avoiding droppers (0, 1, 2, 3 or more): how fragile the saved pairs
//!   are. Disjoint *journeys* in a time-varying graph don't obey Menger's
//!   theorem (Kempe, Kleinberg and Kumar, STOC 2000), so these counts are
//!   over the union of the contact graph from the first message on: exact
//!   for a static world, an upper bound for a moving one.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::engine::{NodeId, Router, Sim, Time};
use super::oracle::Oracle;

/// LFR numbers of one run (honest-to-honest messages the oracle checked).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ceiling {
    /// f: devices that drop what they're given.
    pub droppers: usize,
    /// Messages between honest devices the oracle checked.
    pub messages: usize,
    /// Of those, with any path (or delivered anyway).
    pub feasible: usize,
    pub delivered: usize,
    /// With a path through honest devices only.
    pub reachable: usize,
    pub reachable_delivered: usize,
    /// Messages feasible, but every path of which crosses a dropper.
    pub cut: usize,
    /// Distinct (source, destination) pairs of those messages.
    #[serde(default)]
    pub cut_pairs: usize,
    /// Delivered although cut: should be 0 (droppers relay nothing); a
    /// check on the oracle and the roles.
    pub cut_delivered: usize,
    /// Distinct (source, destination) pairs among the feasible messages.
    pub pairs: usize,
    /// Pairs with at least f + 1 vertex-disjoint paths.
    pub pairs_f1_disjoint: usize,
    /// Pairs by vertex-disjoint paths avoiding every dropper: 0, 1, 2, ≥ 3.
    pub pairs_by_honest_paths: [usize; 4],
}

impl Ceiling {
    /// delivered / feasible.
    pub fn raw(&self) -> f64 {
        self.delivered as f64 / self.feasible.max(1) as f64
    }

    /// delivered (and LFR-reachable) / LFR-reachable.
    pub fn lfr(&self) -> f64 {
        self.reachable_delivered as f64 / self.reachable.max(1) as f64
    }

    /// The best raw delivery any routing could reach: LFR-reachable / feasible.
    pub fn ceiling(&self) -> f64 {
        self.reachable as f64 / self.feasible.max(1) as f64
    }

    pub fn line(&self) -> String {
        format!(
            "raw {:.1}% ({}/{}), LFR {:.1}% ({}/{} liar-free-reachable), ceiling {:.1}%, liar-cut messages {} \
             (delivered {}) between {} pairs; pairs {}: {} with ≥ f+1 = {} disjoint paths, by disjoint honest paths 0/1/2/≥3: {}/{}/{}/{}",
            100.0 * self.raw(),
            self.delivered,
            self.feasible,
            100.0 * self.lfr(),
            self.reachable_delivered,
            self.reachable,
            100.0 * self.ceiling(),
            self.cut,
            self.cut_delivered,
            self.cut_pairs,
            self.pairs,
            self.pairs_f1_disjoint,
            self.droppers + 1,
            self.pairs_by_honest_paths[0],
            self.pairs_by_honest_paths[1],
            self.pairs_by_honest_paths[2],
            self.pairs_by_honest_paths[3],
        )
    }
}

/// LFR numbers for a finished, oracle-annotated run with `droppers`.
pub fn ceiling<R: Router>(sim: &Sim<R>, oracle: &Oracle, droppers: &[NodeId]) -> Ceiling {
    let n = oracle.len();
    let mut avoid = vec![false; n];
    for d in droppers {
        if let Some(a) = avoid.get_mut(*d as usize) {
            *a = true;
        }
    }
    let mut c = Ceiling { droppers: droppers.len(), ..Ceiling::default() };
    let mut pairs: Vec<(NodeId, NodeId)> = Vec::new();
    let mut cut: Vec<(NodeId, NodeId)> = Vec::new();
    let mut first: Option<Time> = None;
    for m in sim.core.msgs.iter().filter(|m| m.checked && !avoid[m.src as usize] && !avoid[m.dst as usize]) {
        c.messages += 1;
        if m.optimal.is_none() && m.delivered.is_none() {
            continue;
        }
        c.feasible += 1;
        first = Some(first.map_or(m.sent, |t| t.min(m.sent)));
        pairs.push((m.src, m.dst));
        let ok = m.delivered.is_some();
        c.delivered += ok as usize;
        if oracle.earliest_avoiding(sim, m.src, m.dst, m.sent, m.size, Some(&avoid)).is_some() {
            c.reachable += 1;
            c.reachable_delivered += ok as usize;
        } else {
            c.cut += 1;
            c.cut_delivered += ok as usize;
            cut.push((m.src, m.dst));
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    c.pairs = pairs.len();
    cut.sort_unstable();
    cut.dedup();
    c.cut_pairs = cut.len();
    let Some(t0) = first else { return c };
    // radio links that can carry a small message, and the internet as one
    // hub no dropper sits in
    let links = oracle.links_after(t0, super::oracle::ONE_PACKET);
    let inet: Vec<bool> = (0..n as NodeId).map(|u| oracle.inet_after(u, t0)).collect();
    let none = vec![false; n];
    for (s, t) in pairs {
        let all = disjoint_paths(n, &links, &inet, &none, s, t, droppers.len() + 1);
        c.pairs_f1_disjoint += (all > droppers.len()) as usize;
        let honest = disjoint_paths(n, &links, &inet, &avoid, s, t, 3);
        c.pairs_by_honest_paths[honest.min(3)] += 1;
    }
    c
}

/// Vertex-disjoint paths from `s` to `t` (at most `limit`) over `links`,
/// without the devices in `removed`; devices with `inet` reach each other
/// through one shared hub (the internet), which isn't a device. Max flow
/// with every device split into in → out of capacity 1 (Edmonds–Karp).
fn disjoint_paths(
    n: usize,
    links: &[(NodeId, NodeId)],
    inet: &[bool],
    removed: &[bool],
    s: NodeId,
    t: NodeId,
    limit: usize,
) -> usize {
    const INF: u32 = u32::MAX / 2;
    let hub = 2 * n;
    let mut g = Flow::new(2 * n + 1);
    for v in 0..n {
        let cap = if v == s as usize || v == t as usize {
            INF
        } else if removed[v] {
            0
        } else {
            1
        };
        g.arc(2 * v, 2 * v + 1, cap);
        if inet[v] {
            g.arc(2 * v + 1, hub, INF);
            g.arc(hub, 2 * v, INF);
        }
    }
    for (a, b) in links {
        let (a, b) = (*a as usize, *b as usize);
        g.arc(2 * a + 1, 2 * b, 1);
        g.arc(2 * b + 1, 2 * a, 1);
    }
    g.max_flow(2 * s as usize + 1, 2 * t as usize, limit)
}

/// A residual graph for unit-capacity max flow.
struct Flow {
    head: Vec<Vec<usize>>,
    /// (to, capacity left)
    arcs: Vec<(usize, u32)>,
}

impl Flow {
    fn new(n: usize) -> Flow {
        Flow { head: vec![Vec::new(); n], arcs: Vec::new() }
    }

    fn arc(&mut self, a: usize, b: usize, cap: u32) {
        self.head[a].push(self.arcs.len());
        self.arcs.push((b, cap));
        self.head[b].push(self.arcs.len());
        self.arcs.push((a, 0));
    }

    /// Augmenting paths from `s` to `t`, at most `limit` of them.
    fn max_flow(&mut self, s: usize, t: usize, limit: usize) -> usize {
        let mut flow = 0;
        let mut via = vec![usize::MAX; self.head.len()];
        while flow < limit {
            via.iter_mut().for_each(|x| *x = usize::MAX);
            let mut q = VecDeque::from([s]);
            let mut found = false;
            'bfs: while let Some(u) = q.pop_front() {
                for &e in &self.head[u] {
                    let (v, cap) = self.arcs[e];
                    if cap > 0 && v != s && via[v] == usize::MAX {
                        via[v] = e;
                        if v == t {
                            found = true;
                            break 'bfs;
                        }
                        q.push_back(v);
                    }
                }
            }
            if !found {
                break;
            }
            // every path here carries one unit (device capacities are 1)
            let mut v = t;
            while v != s {
                let e = via[v];
                self.arcs[e].1 -= 1;
                self.arcs[e ^ 1].1 += 1;
                v = self.arcs[e ^ 1].0;
            }
            flow += 1;
        }
        flow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// s=0 to t=5 over two disjoint routes (0-1-2-5, 0-3-4-5) and a
    /// shortcut 1-4 that shares their devices.
    fn two_routes() -> Vec<(NodeId, NodeId)> {
        vec![(0, 1), (1, 2), (2, 5), (0, 3), (3, 4), (4, 5), (1, 4)]
    }

    #[test]
    fn disjoint_paths_count_devices_not_links() {
        let no = vec![false; 6];
        assert_eq!(disjoint_paths(6, &two_routes(), &no, &no, 0, 5, 10), 2);
        // a dropper on one route leaves one
        let mut gone = no.clone();
        gone[2] = true;
        assert_eq!(disjoint_paths(6, &two_routes(), &no, &gone, 0, 5, 10), 1);
        // a cut vertex: both routes through 1
        let star = vec![(0, 1), (1, 2), (1, 3), (2, 4), (3, 4)];
        assert_eq!(disjoint_paths(5, &star, &[false; 5], &[false; 5], 0, 4, 10), 1);
        let mut cut = vec![false; 5];
        cut[1] = true;
        assert_eq!(disjoint_paths(5, &star, &[false; 5], &cut, 0, 4, 10), 0);
        // the limit stops the search early
        assert_eq!(disjoint_paths(6, &two_routes(), &no, &no, 0, 5, 1), 1);
    }

    #[test]
    fn the_internet_is_a_hub_not_a_device() {
        // 0 and 3 in separate radio islands, 1 and 2 with internet
        let links = vec![(0, 1), (2, 3), (0, 4), (4, 5)];
        let inet = vec![false, true, true, false, false, true];
        let no = vec![false; 6];
        // 0-1-hub-2-3 and 0-4-5-hub-2-3 share device 2: one disjoint path
        assert_eq!(disjoint_paths(6, &links, &inet, &no, 0, 3, 10), 1);
        let mut gone = no.clone();
        gone[1] = true;
        // still through 4, 5 and the hub
        assert_eq!(disjoint_paths(6, &links, &inet, &gone, 0, 3, 10), 1);
        gone[4] = true;
        assert_eq!(disjoint_paths(6, &links, &inet, &gone, 0, 3, 10), 0);
    }
}
