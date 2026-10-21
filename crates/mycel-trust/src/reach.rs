//! Ancestry queries over the membership DAG: an incremental chain cover index.
//!
//! The DAG is split into **chains** (paths). Each op on a chain is
//! `(chain, seq)`. "Is `a` an ancestor of `b`?" becomes "does `b` reach
//! position `seq(a)` of `chain(a)`?". Every merge or chain start stores a
//! sparse **reach vector**: for each other chain it reaches, the highest
//! position reached. Ops that just continue a chain share the vector of the
//! chain's last merge, so a linear history stores one empty vector in total.
//!
//! **Sinks wait.** An op joins a chain only when it gets its first child:
//! until then nothing descends from it, so it is nobody's ancestor and its
//! own reach is that of its parents (at most `MAX_PARENTS` lookups). It then
//! continues the chain of a parent that is that chain's newest op, choosing
//! the oldest such chain, so the main line of history stays on one chain;
//! otherwise it starts a new chain. Ops that never get a child (invalid ops
//! nobody builds on, like the losers of a revocation storm) never take a
//! chain position, so they cannot leave the main line's chain behind them,
//! partly reached forever by everything after.
//!
//! A chain is **closed** when its newest op is a parent of a merge `x` that
//! continues another chain: nothing extends it any more, and all of it lies
//! in `x`'s past. That `(chain(x), seq(x))` is recorded as its absorber, and
//! a later vector that reaches the absorber drops the closed chain: its
//! reach is implied (all of it). So merged-in side branches do not inflate
//! the vectors of everything after them. Absorbers always have smaller chain
//! ids, so resolving an implied entry walks a strictly decreasing sequence.
//!
//! Cost: O(1) per linear op; O(Σ|parent vectors|) per merge or chain start;
//! a query is a binary search in one vector plus the absorber walk (times
//! the parent count when `b` is a sink). Memory is O(n) plus the stored
//! vectors, which hold only chains that are open (or partly reached) at a
//! merge: O(n · k) in the worst case for `k` such chains, where `k` is at
//! most the number of chain starts among ops that have children, against
//! the n² bits of an ancestor matrix. This is the chain cover idea Synapse
//! uses for Matrix auth chains (Jagadish 1990), with the absorption pruning
//! and the waiting sinks added so that closed branches and dead ends cost
//! nothing afterwards.

/// Reach of a whole (closed) chain.
const FULL: u32 = u32::MAX;

/// `chain` of an op that has no child yet.
const SINK: u32 = u32::MAX;

#[derive(Clone, Debug, Default)]
pub(crate) struct Reach {
    /// Per op; `SINK` until its first child.
    chain: Vec<u32>,
    /// Per op: 1-based position within its chain.
    seq: Vec<u32>,
    /// Per op: index into `vecs` of the reach vector that applies to it.
    vec_of: Vec<u32>,
    /// Parents of each op that has no child yet.
    sink_parents: std::collections::HashMap<u32, Box<[u32]>>,
    /// Reach vectors: `(chain, highest seq reached)`, sorted by chain, never
    /// holding the op's own chain. `vecs[0]` is empty.
    vecs: Vec<Box<[(u32, u32)]>>,
    /// Per chain: its newest op.
    tip: Vec<u32>,
    /// Per chain: `(chain, seq)` of the merge that closed it.
    absorbed: Vec<Option<(u32, u32)>>,
}

impl Reach {
    /// Chains in use.
    #[cfg(test)]
    fn chains(&self) -> usize {
        self.tip.len()
    }

    #[cfg(feature = "oracle")]
    pub(crate) fn debug_sizes(&self) -> String {
        format!(
            "chains {}, sinks {}, vectors {}, entries {}, max {}",
            self.tip.len(),
            self.sink_parents.len(),
            self.vecs.len(),
            self.vecs.iter().map(|v| v.len()).sum::<usize>(),
            self.vecs.iter().map(|v| v.len()).max().unwrap_or(0)
        )
    }

    /// Can a child of `p` continue `p`'s chain?
    fn eligible(&self, p: u32) -> bool {
        let c = self.chain[p as usize] as usize;
        self.tip[c] == p && self.absorbed[c].is_none()
    }

    /// Add an op whose parents (op indices) are all present; returns its index.
    pub(crate) fn push(&mut self, parents: &[u32]) -> u32 {
        if self.vecs.is_empty() {
            self.vecs.push(Box::new([]));
        }
        let me = self.chain.len() as u32;
        for &p in parents {
            if self.chain[p as usize] == SINK {
                self.place(p);
            }
        }
        self.chain.push(SINK);
        self.seq.push(0);
        self.vec_of.push(0);
        self.sink_parents.insert(me, parents.into());
        me
    }

    /// Give sink `x` (which just got its first child) a chain position.
    fn place(&mut self, x: u32) {
        let parents = self.sink_parents.remove(&x).expect("a sink keeps its parents");
        let ext = parents.iter().copied().filter(|&p| self.eligible(p)).min_by_key(|&p| self.chain[p as usize]);
        let (c, s) = match ext {
            Some(p) => (self.chain[p as usize], self.seq[p as usize] + 1),
            None => (self.tip.len() as u32, 1),
        };
        for &p in parents.iter() {
            if Some(p) != ext && self.eligible(p) {
                self.absorbed[self.chain[p as usize] as usize] = Some((c, s));
            }
        }
        if ext.is_some() {
            self.tip[c as usize] = x;
        } else {
            self.tip.push(x);
            self.absorbed.push(None);
        }
        let vec_of = match (ext, &parents[..]) {
            (Some(p), [_]) => self.vec_of[p as usize],
            _ => self.merged_vector(&parents, c, s),
        };
        let x = x as usize;
        self.chain[x] = c;
        self.seq[x] = s;
        self.vec_of[x] = vec_of;
    }

    fn merged_vector(&mut self, parents: &[u32], c: u32, s: u32) -> u32 {
        let mut keys: Vec<u32> = Vec::new();
        for &p in parents {
            let p = p as usize;
            keys.extend(self.vecs[self.vec_of[p] as usize].iter().map(|e| e.0));
            keys.push(self.chain[p]);
        }
        keys.sort_unstable();
        keys.dedup();
        keys.retain(|&k| k != c);
        // The exact reach per chain: a parent's vector can omit a chain it
        // reaches in full (implied by an absorber), so a plain max of the
        // stored entries could keep another parent's partial entry instead.
        let v: Vec<(u32, u32)> = keys
            .into_iter()
            .map(|k| {
                let reach = parents
                    .iter()
                    .map(|&p| {
                        let p = p as usize;
                        self.reach_with(&self.vecs[self.vec_of[p] as usize], self.chain[p], self.seq[p], k)
                    })
                    .max()
                    .unwrap_or(0);
                (k, reach)
            })
            .collect();
        // Drop closed chains whose absorber is reached: implied in full.
        let pruned: Vec<(u32, u32)> = v
            .iter()
            .copied()
            .filter(|&(cc, _)| match self.absorbed[cc as usize] {
                Some((c0, s0)) => self.reach_with(&v, c, s, c0) < s0,
                None => true,
            })
            .collect();
        if pruned.is_empty() {
            return 0;
        }
        self.vecs.push(pruned.into_boxed_slice());
        (self.vecs.len() - 1) as u32
    }

    /// Highest position of chain `c` in the past of (or at) an op with
    /// vector `v` at `(own_chain, own_seq)`; `FULL` for a closed chain reached
    /// in full.
    fn reach_with(&self, v: &[(u32, u32)], own_chain: u32, own_seq: u32, c: u32) -> u32 {
        let mut thresholds: Vec<u32> = Vec::new();
        let mut c = c;
        let mut val = loop {
            if c == own_chain {
                break own_seq;
            }
            if let Ok(i) = v.binary_search_by_key(&c, |e| e.0) {
                break v[i].1;
            }
            match self.absorbed[c as usize] {
                Some((c0, s0)) => {
                    thresholds.push(s0);
                    c = c0;
                }
                None => break 0,
            }
        };
        while let Some(s) = thresholds.pop() {
            val = if val >= s { FULL } else { 0 };
        }
        val
    }

    /// Is `a` an ancestor of `b`, or `b` itself?
    pub(crate) fn le(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        if self.chain[a as usize] == SINK {
            // No child, so nobody's ancestor.
            return false;
        }
        match self.sink_parents.get(&b) {
            Some(ps) => ps.iter().any(|&p| self.le_placed(a, p)),
            None => self.le_placed(a, b),
        }
    }

    /// `le` for ops that both have a chain position.
    fn le_placed(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        let (a, b) = (a as usize, b as usize);
        let v = &self.vecs[self.vec_of[b] as usize];
        self.reach_with(v, self.chain[b], self.seq[b], self.chain[a]) >= self.seq[a]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Brute-force ancestor sets.
    fn closure(parents: &[Vec<u32>]) -> Vec<Vec<bool>> {
        let n = parents.len();
        let mut anc = vec![vec![false; n]; n];
        for i in 0..n {
            anc[i][i] = true;
            for &p in &parents[i] {
                let row = anc[p as usize].clone();
                for (j, r) in row.into_iter().enumerate() {
                    anc[i][j] |= r;
                }
            }
        }
        anc
    }

    fn check(parents: &[Vec<u32>]) {
        let mut r = Reach::default();
        for ps in parents {
            r.push(ps);
        }
        let anc = closure(parents);
        for (b, row) in anc.iter().enumerate() {
            for (a, &want) in row.iter().enumerate() {
                assert_eq!(r.le(a as u32, b as u32), want, "le({a}, {b}) in {parents:?}");
            }
        }
    }

    /// Random DAG: each op picks 1..=k parents among earlier ops, biased to
    /// recent ones (like real heads) but sometimes far back.
    fn dag() -> impl Strategy<Value = Vec<Vec<u32>>> {
        prop::collection::vec(prop::collection::vec((any::<bool>(), 0u32..1000), 1..4), 1..60).prop_map(|picks| {
            let mut parents = vec![vec![]];
            for (i, ps) in picks.into_iter().enumerate() {
                let n = (i + 1) as u32;
                let mut chosen: Vec<u32> =
                    ps.into_iter().map(|(recent, x)| if recent { n - 1 - (x % n.min(3)) } else { x % n }).collect();
                chosen.sort_unstable();
                chosen.dedup();
                parents.push(chosen);
            }
            parents
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]
        #[test]
        fn matches_brute_force(parents in dag()) {
            check(&parents);
        }
    }

    #[test]
    fn linear_history_shares_one_vector() {
        let mut r = Reach::default();
        r.push(&[]);
        for i in 0..1000 {
            r.push(&[i]);
        }
        assert_eq!(r.vecs.len(), 1);
        assert_eq!(r.chains(), 1);
        assert!(r.le(0, 1000) && !r.le(1000, 0));
    }

    #[test]
    fn merged_branches_are_pruned() {
        // Rounds of 8 concurrent ops off the main line, each merged at once.
        let mut r = Reach::default();
        let mut parents = vec![vec![]];
        let mut head = r.push(&[]);
        for _ in 0..200 {
            let side: Vec<u32> = (0..8)
                .map(|_| {
                    parents.push(vec![head]);
                    r.push(&[head])
                })
                .collect();
            parents.push(side.clone());
            head = r.push(&side);
        }
        let longest = r.vecs.iter().map(|v| v.len()).max().unwrap();
        assert!(longest <= 8, "vectors stay bounded by the round width, got {longest}");
        check(&parents[..parents.len().min(400)]);
    }

    /// Regression (revocation storms): each round puts five ops on the head,
    /// the first to arrive is a dead end nobody builds on, and the next two
    /// are merged. When an op took its chain position on arrival, the dead
    /// end continued the main chain, which then stayed partly reached by
    /// everything after it: one more entry in every later vector per round.
    #[test]
    fn dead_ends_take_no_chain_position() {
        let mut r = Reach::default();
        let mut parents = vec![vec![]];
        let mut head = r.push(&[]);
        for _ in 0..300 {
            let side: Vec<u32> = (0..5)
                .map(|_| {
                    parents.push(vec![head]);
                    r.push(&[head])
                })
                .collect();
            parents.push(vec![side[1], side[2]]);
            head = r.push(&[side[1], side[2]]);
        }
        let longest = r.vecs.iter().map(|v| v.len()).max().unwrap();
        assert!(longest <= 1, "vectors stay bounded, got {longest}");
        let entries: usize = r.vecs.iter().map(|v| v.len()).sum();
        assert!(entries <= 300, "linear in the rounds, got {entries}");
        check(&parents[..parents.len().min(400)]);
    }

    #[test]
    fn sinks_reach_through_their_parents() {
        let parents: Vec<Vec<u32>> = vec![vec![], vec![0], vec![0], vec![1, 2], vec![3], vec![1]];
        check(&parents);
        let mut r = Reach::default();
        for ps in &parents {
            r.push(ps);
        }
        // 4 and 5 are sinks; 2 and 3 are placed.
        assert!(r.le(0, 4) && r.le(2, 4) && !r.le(5, 4) && !r.le(4, 5) && r.le(1, 5) && !r.le(2, 5));
    }

    /// Regression: merging a parent that reaches a closed chain in full
    /// (implied by an absorber, so not stored) with one holding a partial
    /// entry for that chain must keep the full reach, not the partial one.
    #[test]
    fn implied_reach_beats_a_partial_entry_on_merge() {
        let parents: Vec<Vec<u32>> = vec![
            vec![],
            vec![0],
            vec![0],
            vec![0],
            vec![0],
            vec![1],
            vec![0],
            vec![6],
            vec![2],
            vec![6],
            vec![8],
            vec![0],
            vec![11],
            vec![0],
            vec![13],
            vec![12],
            vec![0],
            vec![14],
            vec![15],
            vec![17, 18],
            vec![0],
            vec![0],
            vec![19],
            vec![0],
            vec![3, 13],
            vec![22],
            vec![24, 25],
            vec![0],
            vec![0],
            vec![0],
            vec![24],
            vec![11],
            vec![13],
            vec![0],
            vec![31, 32],
            vec![0],
            vec![0],
            vec![34],
            vec![26, 37],
        ];
        check(&parents);
    }

    #[test]
    fn chains_absorbed_into_absorbed_chains() {
        // a, b, c branch off; b absorbs c, then a absorbs b: c's reach must be
        // implied through two absorbers.
        let parents: Vec<Vec<u32>> = vec![vec![], vec![0], vec![0], vec![0], vec![2, 3], vec![1, 4], vec![5]];
        check(&parents);
    }
}
