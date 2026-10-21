//! The chain index (design §4.4): per author, the forest of hash-linked
//! envelope chains a replica holds, kept up to date on every insert.
//!
//! Each envelope joins the *run set* of its held predecessor (a valid
//! `author_prev` link: same author, seq one lower). A run set is a tree
//! rooted at its bottom envelope, whose predecessor is missing (a gap) or
//! absent (seq 0). Sets merge when a gap fills; the smaller one is
//! relabelled, so every envelope is relabelled O(log n) times in total and
//! `bottom(id)` is O(1). Heads (envelopes no held envelope names as a valid
//! predecessor) with their set's bottom are the author's runs.
//!
//! Forks are seqs holding more than one id (`multi`). Finding the id a
//! branch has at a seq jumps over unforked stretches, so it costs
//! O(log n) plus one step per forked seq in between, not O(distance).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use mycel_crypto::{Hash32, SignPk};

use super::MAX_RUNS_INLINE;
use super::msg::{AuthorEntry, Run};
use crate::EnvelopeId;

const CTX_BOUNDARY: &str = "mycel/v2/sync-boundary";

/// The envelope window (admission rule A3): an author's envelope at seq `s`
/// is stored only if `s < reach + WINDOW`, where `reach` is one past the
/// highest seq held on a chain from seq 0. Deterministic and monotone in
/// what is held (never in arrival order), so honest peers still converge;
/// bounds a writer's dangling envelopes to `WINDOW` seqs per chain.
pub const WINDOW: u64 = 4096;

#[derive(Clone, Copy, Debug)]
struct Node {
    author: u32,
    seq: u64,
    prev: Option<EnvelopeId>,
    set: u32,
}

#[derive(Debug, Default)]
struct RunSet {
    bottom: u64,
    /// The bottom's predecessor, if it has one (missing, or held but not a
    /// valid link).
    missing: Option<EnvelopeId>,
    members: Vec<EnvelopeId>,
    top: u64,
}

#[derive(Debug)]
struct AuthorChains {
    key: SignPk,
    by_seq: BTreeMap<u64, Vec<EnvelopeId>>,
    /// Seqs holding more than one id.
    multi: BTreeSet<u64>,
    /// (seq, id) of every head.
    heads: BTreeSet<(u64, EnvelopeId)>,
    reach: u64,
}

#[derive(Default)]
struct Cache {
    entries: Arc<BTreeMap<SignPk, AuthorEntry>>,
    dirty: BTreeSet<u32>,
    boundary: Option<Hash32>,
}

/// See the module docs.
#[derive(Default)]
pub struct ChainIndex {
    authors: Vec<AuthorChains>,
    author_ix: HashMap<SignPk, u32>,
    nodes: HashMap<EnvelopeId, Node>,
    sets: Vec<RunSet>,
    /// Missing predecessor → bottoms waiting for it.
    waiting: HashMap<EnvelopeId, Vec<EnvelopeId>>,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for ChainIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainIndex({} envelopes, {} authors)", self.nodes.len(), self.authors.len())
    }
}

impl ChainIndex {
    /// Number of envelopes held.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn holds(&self, id: &EnvelopeId) -> bool {
        self.nodes.contains_key(id)
    }

    pub fn seq(&self, id: &EnvelopeId) -> Option<u64> {
        self.nodes.get(id).map(|n| n.seq)
    }

    pub fn author(&self, id: &EnvelopeId) -> Option<SignPk> {
        self.nodes.get(id).map(|n| self.authors[n.author as usize].key)
    }

    /// One past the highest seq of `author` held on a chain from seq 0.
    pub fn reach(&self, author: &SignPk) -> u64 {
        self.author_ix.get(author).map_or(0, |a| self.authors[*a as usize].reach)
    }

    /// Admission rule A3 (see [`WINDOW`]).
    pub fn within_window(&self, author: &SignPk, seq: u64) -> bool {
        seq < self.reach(author).saturating_add(WINDOW)
    }

    /// The lowest seq reachable below `id` through held valid links.
    pub fn bottom(&self, id: &EnvelopeId) -> Option<u64> {
        self.nodes.get(id).map(|n| self.sets[n.set as usize].bottom)
    }

    /// The ids held at `seq` of `author`, lowest first.
    pub fn ids_at(&self, author: &SignPk, seq: u64) -> &[EnvelopeId] {
        self.author_ix
            .get(author)
            .and_then(|a| self.authors[*a as usize].by_seq.get(&seq))
            .map_or(&[], |v| v.as_slice())
    }

    /// Up to `n` ids of `author`'s highest seqs (lowest id per seq), newest first.
    pub fn recent(&self, author: &SignPk, n: usize) -> Vec<EnvelopeId> {
        let Some(a) = self.author_ix.get(author) else { return Vec::new() };
        self.authors[*a as usize].by_seq.values().rev().take(n).filter_map(|ids| ids.first().copied()).collect()
    }

    /// Record a newly stored envelope. Returns false if it was already held.
    pub fn insert(&mut self, id: EnvelopeId, author: SignPk, seq: u64, prev: Option<EnvelopeId>) -> bool {
        if self.nodes.contains_key(&id) {
            return false;
        }
        let a = match self.author_ix.get(&author) {
            Some(a) => *a,
            None => {
                let a = self.authors.len() as u32;
                self.authors.push(AuthorChains {
                    key: author,
                    by_seq: BTreeMap::new(),
                    multi: BTreeSet::new(),
                    heads: BTreeSet::new(),
                    reach: 0,
                });
                self.author_ix.insert(author, a);
                a
            }
        };
        let parent = prev.filter(|p| self.is_link(p, a, seq));
        let set = match parent {
            Some(p) => {
                let pn = self.nodes[&p];
                self.authors[a as usize].heads.remove(&(pn.seq, p));
                let s = &mut self.sets[pn.set as usize];
                s.members.push(id);
                s.top = s.top.max(seq);
                pn.set
            }
            None => {
                if let Some(p) = prev
                    && !self.nodes.contains_key(&p)
                {
                    self.waiting.entry(p).or_default().push(id);
                }
                self.sets.push(RunSet { bottom: seq, missing: prev, members: vec![id], top: seq });
                (self.sets.len() - 1) as u32
            }
        };
        self.nodes.insert(id, Node { author: a, seq, prev, set });
        let chains = &mut self.authors[a as usize];
        let ids = chains.by_seq.entry(seq).or_default();
        let at = ids.binary_search(&id).unwrap_or_else(|i| i);
        ids.insert(at, id);
        if ids.len() > 1 {
            chains.multi.insert(seq);
        }
        let mut has_child = false;
        for child in self.waiting.remove(&id).unwrap_or_default() {
            if self.is_link(&id, a, self.nodes[&child].seq) && self.nodes[&child].author == a {
                let cs = self.nodes[&child].set;
                let ps = self.nodes[&id].set;
                self.merge(ps, cs);
                has_child = true;
            }
        }
        if !has_child {
            self.authors[a as usize].heads.insert((seq, id));
        }
        let s = &self.sets[self.nodes[&id].set as usize];
        if s.bottom == 0 && s.missing.is_none() {
            let chains = &mut self.authors[a as usize];
            chains.reach = chains.reach.max(s.top.saturating_add(1));
        }
        let cache = self.cache.get_mut().unwrap_or_else(|e| e.into_inner());
        cache.dirty.insert(a);
        cache.boundary = None;
        true
    }

    /// Is held `prev` a valid predecessor of an envelope of author `a` at `seq`?
    fn is_link(&self, prev: &EnvelopeId, a: u32, seq: u64) -> bool {
        self.nodes.get(prev).is_some_and(|n| n.author == a && n.seq.checked_add(1) == Some(seq))
    }

    /// Merge run set `child` (rooted just above a node of `parent`) into
    /// `parent`: the result keeps the parent's bottom. The smaller member
    /// list is relabelled.
    fn merge(&mut self, parent: u32, child: u32) {
        if parent == child {
            return;
        }
        let (keep, gone) = if self.sets[parent as usize].members.len() >= self.sets[child as usize].members.len() {
            (parent, child)
        } else {
            (child, parent)
        };
        let moved = std::mem::take(&mut self.sets[gone as usize].members);
        for m in &moved {
            if let Some(n) = self.nodes.get_mut(m) {
                n.set = keep;
            }
        }
        let (bottom, missing) = (self.sets[parent as usize].bottom, self.sets[parent as usize].missing);
        let top = self.sets[parent as usize].top.max(self.sets[child as usize].top);
        let k = &mut self.sets[keep as usize];
        k.members.extend(moved);
        k.bottom = bottom;
        k.missing = missing;
        k.top = top;
        let g = &mut self.sets[gone as usize];
        g.members = Vec::new();
        g.top = 0;
    }

    /// The id that the branch ending at `head` holds at `seq`, if `seq` is
    /// within the branch (between its bottom and the head).
    pub fn branch_id_at(&self, head: &EnvelopeId, seq: u64) -> Option<EnvelopeId> {
        let hn = self.nodes.get(head)?;
        if seq > hn.seq || seq < self.sets[hn.set as usize].bottom {
            return None;
        }
        let chains = &self.authors[hn.author as usize];
        let mut cur = *head;
        let mut cur_seq = hn.seq;
        loop {
            if cur_seq == seq {
                return Some(cur);
            }
            // The highest forked seq in (seq, cur_seq]: above it, every seq
            // holds one id, so the branch's id there is that one.
            match chains.multi.range(seq + 1..=cur_seq).next_back().copied() {
                None => {
                    let above = chains.by_seq.get(&(seq + 1))?.first()?;
                    return self.nodes.get(above)?.prev;
                }
                Some(m) if m < cur_seq => {
                    let above = chains.by_seq.get(&(m + 1))?.first()?;
                    cur = self.nodes.get(above)?.prev?;
                    cur_seq = m;
                }
                Some(_) => {
                    cur = self.nodes.get(&cur)?.prev?;
                    cur_seq -= 1;
                }
            }
        }
    }

    /// Is `x` on the branch ending at `y` (or equal to it)?
    pub fn is_ancestor(&self, x: &EnvelopeId, y: &EnvelopeId) -> bool {
        let (Some(xn), Some(yn)) = (self.nodes.get(x), self.nodes.get(y)) else { return false };
        xn.author == yn.author && xn.set == yn.set && self.branch_id_at(y, xn.seq) == Some(*x)
    }

    /// The highest seq at which the branches ending at `x` and `y` hold the
    /// same id, if they share any.
    pub fn fork_point(&self, x: &EnvelopeId, y: &EnvelopeId) -> Option<u64> {
        let (xn, yn) = (self.nodes.get(x)?, self.nodes.get(y)?);
        if xn.author != yn.author || xn.set != yn.set {
            return None;
        }
        let (mut lo, mut hi) = (self.sets[xn.set as usize].bottom, xn.seq.min(yn.seq));
        let same = |s: u64| self.branch_id_at(x, s).is_some() && self.branch_id_at(x, s) == self.branch_id_at(y, s);
        if !same(lo) {
            return None;
        }
        // Monotone: the branches agree below the fork and differ above it.
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if same(mid) { lo = mid } else { hi = mid - 1 }
        }
        Some(lo)
    }

    /// The ids of the branch ending at `head` with seqs in `lo..=hi`, ascending.
    pub fn branch_ids(&self, head: &EnvelopeId, lo: u64, hi: u64) -> Vec<EnvelopeId> {
        if lo > hi {
            return Vec::new();
        }
        let Some(top) = self.branch_id_at(head, hi) else { return Vec::new() };
        let mut out = Vec::with_capacity((hi - lo + 1).min(1 << 20) as usize);
        let mut cur = Some(top);
        while let Some(id) = cur {
            let Some(n) = self.nodes.get(&id) else { break };
            if n.seq < lo {
                break;
            }
            out.push(id);
            if n.seq == lo {
                break;
            }
            cur = n.prev.filter(|p| self.nodes.contains_key(p));
        }
        out.reverse();
        out
    }

    /// Every author's frontier entry (at most [`MAX_RUNS_INLINE`] runs each,
    /// highest first). Shared, so taking one costs O(1); entries of authors
    /// that changed since the last call are recomputed first.
    pub fn entries(&self) -> Arc<BTreeMap<SignPk, AuthorEntry>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if !cache.dirty.is_empty() {
            let dirty = std::mem::take(&mut cache.dirty);
            let entries = Arc::make_mut(&mut cache.entries);
            for a in dirty {
                let e = self.entry(a);
                entries.insert(e.author, e);
            }
        }
        cache.entries.clone()
    }

    fn entry(&self, a: u32) -> AuthorEntry {
        let chains = &self.authors[a as usize];
        let runs = chains
            .heads
            .iter()
            .rev()
            .take(MAX_RUNS_INLINE)
            .map(|(seq, head)| Run { top: *seq, head: *head, bottom: self.sets[self.nodes[head].set as usize].bottom })
            .collect();
        AuthorEntry { author: chains.key, runs, truncated: chains.heads.len() > MAX_RUNS_INLINE }
    }

    /// The runs of `author` (all of them, highest first).
    pub fn runs(&self, author: &SignPk) -> Vec<Run> {
        let Some(a) = self.author_ix.get(author) else { return Vec::new() };
        self.authors[*a as usize]
            .heads
            .iter()
            .rev()
            .map(|(seq, head)| Run { top: *seq, head: *head, bottom: self.sets[self.nodes[head].set as usize].bottom })
            .collect()
    }

    /// The missing predecessor below a run's bottom, if any.
    pub fn gap_below(&self, head: &EnvelopeId) -> Option<EnvelopeId> {
        self.nodes.get(head).and_then(|n| self.sets[n.set as usize].missing)
    }

    /// A commitment to the whole envelope boundary: every author's heads
    /// (all of them, not just the listed ones) with their bottoms and gap
    /// ids. Cached until the next insert.
    pub fn boundary(&self) -> Hash32 {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = cache.boundary {
            return h;
        }
        let mut order: Vec<&AuthorChains> = self.authors.iter().collect();
        order.sort_by_key(|c| c.key);
        let mut h = mycel_crypto::Digest::new(CTX_BOUNDARY);
        h.update(&(order.len() as u64).to_le_bytes());
        for c in order {
            h.update(&c.key.0).update(&(c.heads.len() as u64).to_le_bytes());
            for (seq, head) in &c.heads {
                let set = &self.sets[self.nodes[head].set as usize];
                h.update(&seq.to_le_bytes()).update(&head.0).update(&set.bottom.to_le_bytes());
                match &set.missing {
                    Some(m) => h.update(&[1]).update(&m.0),
                    None => h.update(&[0]),
                };
            }
        }
        let out = h.finalize();
        cache.boundary = Some(out);
        out
    }
}
