//! Causal index of the changes in one document.
//!
//! For every applied change it keeps the author, sequence number, operation
//! counter range, a Lamport bound, a sparse vector clock and the change's
//! operations in run-length form (object, insert flag, object kind). That is
//! enough to validate a new change against its *declared* history — actor
//! sequence, counters, and that every object, element and predecessor it
//! names exists in that history with the right shape — at a cost proportional
//! to the change itself plus a logarithmic lookup per reference. Nothing is
//! replayed and Automerge is not consulted, so acceptance is a deterministic
//! function of the change and its dependencies, independent of whatever
//! concurrent changes a replica happens to hold.
//!
//! Vector clocks are stored relative to arrival order: a change whose
//! dependencies covered everything applied before it (the common, linear
//! case) stores nothing; otherwise it lists only the actors it had not fully
//! seen. Arrival order is local, but the clock it encodes is not.

use std::collections::{HashMap, HashSet};

use automerge::{ActorId, Change, ChangeHash};

use crate::change_ops::{self, Key, Obj, OpRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Map,
    List,
    Text,
    Table,
}

/// Operation actions as Automerge 0.12 encodes them (storage/change).
const DELETE: u64 = 3;
const INCREMENT: u64 = 5;
const MARK: u64 = 7;

impl Kind {
    fn made_by(action: u64) -> Option<Kind> {
        match action {
            0 => Some(Kind::Map),
            2 => Some(Kind::List),
            4 => Some(Kind::Text),
            6 => Some(Kind::Table),
            _ => None,
        }
    }
}

/// An operation id in document-wide actor numbering, `actor << 32 | counter`.
/// Counters are at most `u32::MAX` and never 0, so 0 is the root object.
type ObjKey = u64;
const ROOT: ObjKey = 0;

fn obj_key(actor: u32, counter: u64) -> ObjKey {
    (u64::from(actor) << 32) | counter
}

/// Consecutive operations of one change sharing object, insert flag and the
/// kind of object they create (if any).
#[derive(Clone, Copy, Debug)]
struct Run {
    /// Offset of the first operation in the change.
    start: u32,
    obj: ObjKey,
    insert: bool,
    make: Option<Kind>,
}

fn run_at(runs: &[Run], offset: u64) -> Run {
    runs[runs.partition_point(|r| u64::from(r.start) <= offset) - 1]
}

struct Node {
    hash: ChangeHash,
    actor: u32,
    seq: u64,
    start_op: u64,
    len: u64,
    /// Highest operation counter in this change's history, itself included.
    lamport: u64,
    /// Actors this change had not fully seen when it arrived: (actor, seq
    /// seen). Every other actor's clock entry is its number of changes that
    /// arrived before this one.
    behind: Box<[(u32, u64)]>,
    runs: Box<[Run]>,
}

/// A validated change, ready to insert.
pub(crate) struct Admitted {
    node: Node,
    new_actor: Option<ActorId>,
    deps: Vec<u32>,
}

pub(crate) struct Checkpoint {
    nodes: usize,
    actors: usize,
    heads: HashSet<u32>,
}

#[derive(Default)]
pub(crate) struct Index {
    actors: Vec<ActorId>,
    actor_ix: HashMap<ActorId, u32>,
    /// Per actor, its changes in sequence order (node indices, increasing).
    chains: Vec<Vec<u32>>,
    /// In arrival order.
    nodes: Vec<Node>,
    by_hash: HashMap<ChangeHash, u32>,
    heads: HashSet<u32>,
}

/// The vector clock of a set of dependencies, computed lazily per actor.
struct Clock<'a> {
    index: &'a Index,
    /// The dependencies cover every applied change.
    all: bool,
    /// Latest-arriving dependency with no `behind` entries.
    linear: Option<u32>,
    /// Dependencies with `behind` entries.
    others: Vec<u32>,
    memo: HashMap<u32, u64>,
}

impl<'a> Clock<'a> {
    fn new(index: &'a Index, deps: &[u32]) -> Self {
        let all = index.heads.iter().all(|h| deps.binary_search(h).is_ok());
        let (others, linear): (Vec<u32>, Vec<u32>) =
            deps.iter().partition(|&&d| !index.nodes[d as usize].behind.is_empty());
        Clock { index, all, linear: linear.into_iter().max(), others, memo: HashMap::new() }
    }

    /// Number of `actor`'s changes in the dependencies' history.
    fn get(&mut self, actor: u32) -> u64 {
        let Some(chain) = self.index.chains.get(actor as usize) else {
            return 0;
        };
        if self.all {
            return chain.len() as u64;
        }
        if let Some(seen) = self.memo.get(&actor) {
            return *seen;
        }
        let mut seen = self.linear.map_or(0, |d| self.index.arrived_by(actor, d));
        for &d in &self.others {
            seen = seen.max(self.index.seen(d, actor));
        }
        self.memo.insert(actor, seen);
        seen
    }
}

impl Index {
    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub(crate) fn contains(&self, hash: &ChangeHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    pub(crate) fn heads(&self) -> HashSet<ChangeHash> {
        self.heads.iter().map(|&h| self.nodes[h as usize].hash).collect()
    }

    /// Changes by `actor` that arrived no later than node `d`.
    fn arrived_by(&self, actor: u32, d: u32) -> u64 {
        self.chains[actor as usize].partition_point(|&n| n <= d) as u64
    }

    /// Clock entry of node `d` for `actor`.
    fn seen(&self, d: u32, actor: u32) -> u64 {
        let node = &self.nodes[d as usize];
        if node.actor == actor {
            return node.seq;
        }
        match node.behind.binary_search_by_key(&actor, |(a, _)| *a) {
            Ok(i) => node.behind[i].1,
            Err(_) => self.arrived_by(actor, d),
        }
    }

    /// Validate `change` against its declared history. All of its
    /// dependencies must already be in the index. `None` means the change is
    /// invalid with respect to that history — a property of the change and
    /// its dependencies alone, so every replica decides the same.
    pub(crate) fn admit(&self, change: &Change) -> Option<Admitted> {
        let mut deps: Vec<u32> = change.deps().iter().map(|h| self.by_hash.get(h).copied()).collect::<Option<_>>()?;
        deps.sort_unstable();
        deps.dedup();
        let actor = change.actor_id();
        let own = self.actor_ix.get(actor).copied();
        let own_ix = own.unwrap_or(self.actors.len() as u32);
        // The change's actor table in document numbering. Every other actor
        // it lists must have written something in its declared history.
        let mut table = vec![own_ix];
        let mut listed = HashSet::new();
        let mut clock = Clock::new(self, &deps);
        for other in change.other_actor_ids() {
            let ix = *self.actor_ix.get(other)?;
            if ix == own_ix || !listed.insert(ix) || clock.get(ix) == 0 {
                return None;
            }
            table.push(ix);
        }
        // Actor sequence is consecutive within declared history, and extends
        // this document's chain for the actor (a taken slot is equivocation,
        // which the caller resolves before validation).
        let seq = change.seq();
        let prior = own.map_or(0, |a| clock.get(a));
        if prior.checked_add(1) != Some(seq) || own.is_some_and(|a| self.chains[a as usize].len() as u64 != prior) {
            return None;
        }
        // Counters are Lamport timestamps: gaps are fine, overlap with declared
        // history is not, and upstream stores them as u32.
        let start = change.start_op().get();
        let len = change.len() as u64;
        let history = deps.iter().map(|&d| self.nodes[d as usize].lamport).max().unwrap_or(0);
        let last = start.checked_add(len)?.checked_sub(1)?;
        if start <= history || start > u64::from(u32::MAX) || last > u64::from(u32::MAX) {
            return None;
        }
        let mut runs: Vec<Run> = Vec::new();
        let mut resolve = |r: OpRef, runs: &[Run], i: u64| -> Option<(ObjKey, Run)> {
            let a = *table.get(r.actor)?;
            if a == own_ix && r.counter >= start {
                // Earlier operation of this same change.
                if r.counter >= start + i {
                    return None;
                }
                return Some((obj_key(a, r.counter), run_at(runs, r.counter - start)));
            }
            let chain = self.chains.get(a as usize)?;
            let pos = chain.partition_point(|&n| self.nodes[n as usize].start_op <= r.counter);
            let node = &self.nodes[chain[pos.checked_sub(1)?] as usize];
            if r.counter >= node.start_op + node.len || clock.get(a) < node.seq {
                return None; // a counter gap, or not in declared history
            }
            Some((obj_key(a, r.counter), run_at(&node.runs, r.counter - node.start_op)))
        };
        let rows = change_ops::visit(change, |i, row, preds| {
            let i = i as u64;
            let fail = || crate::SyncError::Encoding;
            let (obj, kind) = match row.obj {
                Obj::Root => (ROOT, Kind::Map),
                Obj::Op(r) => {
                    let (obj, run) = resolve(r, &runs, i).ok_or_else(fail)?;
                    (obj, run.make.ok_or_else(fail)?)
                }
            };
            // Upstream only places map keys in maps and elements in sequences,
            // and has no table support; anything else would panic or misplace.
            match (kind, row.key) {
                (Kind::Map, Key::Prop) if !row.insert => {}
                (Kind::List | Kind::Text, Key::Head) if row.insert => {}
                (Kind::List | Kind::Text, Key::Elem(r)) => {
                    let (_, elem) = resolve(r, &runs, i).ok_or_else(fail)?;
                    if !elem.insert || elem.obj != obj {
                        return Err(fail());
                    }
                }
                _ => return Err(fail()),
            }
            // Deletes and increments name an existing element; marks are
            // always new elements. Upstream writes nothing else, and applies
            // anything else out of order (found by fuzzing: its op order
            // check fails, and release builds keep a corrupt document).
            match (row.action, row.insert) {
                (DELETE | INCREMENT, true) | (MARK, false) => return Err(fail()),
                _ => {}
            }
            for p in preds {
                resolve(*p, &runs, i).ok_or_else(fail)?;
            }
            let make = Kind::made_by(row.action);
            match runs.last() {
                Some(last) if last.obj == obj && last.insert == row.insert && last.make == make => {}
                _ => runs.push(Run { start: i as u32, obj, insert: row.insert, make }),
            }
            Ok(())
        });
        if rows.ok()? as u64 != len {
            return None;
        }
        let behind = if clock.all {
            Box::default()
        } else {
            let mut behind = Vec::new();
            for a in 0..self.actors.len() as u32 {
                if Some(a) != own {
                    let seen = clock.get(a);
                    if seen < self.chains[a as usize].len() as u64 {
                        behind.push((a, seen));
                    }
                }
            }
            behind.into_boxed_slice()
        };
        Some(Admitted {
            node: Node {
                hash: change.hash(),
                actor: own_ix,
                seq,
                start_op: start,
                len,
                lamport: history.max(last),
                behind,
                runs: runs.into_boxed_slice(),
            },
            new_actor: own.is_none().then(|| actor.clone()),
            deps,
        })
    }

    pub(crate) fn insert(&mut self, admitted: Admitted) {
        let Admitted { node, new_actor, deps } = admitted;
        if let Some(actor) = new_actor {
            self.actor_ix.insert(actor.clone(), self.actors.len() as u32);
            self.actors.push(actor);
            self.chains.push(Vec::new());
        }
        let idx = self.nodes.len() as u32;
        self.chains[node.actor as usize].push(idx);
        for d in &deps {
            self.heads.remove(d);
        }
        self.heads.insert(idx);
        self.by_hash.insert(node.hash, idx);
        self.nodes.push(node);
    }

    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint { nodes: self.nodes.len(), actors: self.actors.len(), heads: self.heads.clone() }
    }

    /// Forget everything inserted since `cp`.
    pub(crate) fn rollback(&mut self, cp: Checkpoint) {
        while self.nodes.len() > cp.nodes {
            let node = self.nodes.pop().unwrap();
            self.chains[node.actor as usize].pop();
            self.by_hash.remove(&node.hash);
        }
        for actor in self.actors.drain(cp.actors..) {
            self.actor_ix.remove(&actor);
        }
        self.chains.truncate(cp.actors);
        self.heads = cp.heads;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::{AutoCommit, ObjType, ROOT, transaction::Transactable};

    fn actor(n: u8) -> ActorId {
        ActorId::from(vec![n; 32])
    }

    fn admit_all(index: &mut Index, changes: &[Change]) {
        for c in changes {
            let admitted = index.admit(c).unwrap_or_else(|| panic!("rejected {:?}", c.hash()));
            index.insert(admitted);
        }
    }

    #[test]
    fn upstream_changes_of_every_kind_are_admitted() {
        let mut index = Index::default();
        admit_all(&mut index, &crate::change_ops::tests::fixtures());
    }

    #[test]
    fn clocks_follow_declared_history_not_arrival() {
        // a and b edit concurrently from a shared base; c depends only on a.
        let mut base = AutoCommit::new().with_actor(actor(1));
        let text = base.put_object(ROOT, "text", ObjType::Text).unwrap();
        base.splice_text(&text, 0, 0, "base").unwrap();
        base.commit();
        let mut a = base.fork().with_actor(actor(2));
        let mut b = base.fork().with_actor(actor(3));
        a.splice_text(&text, 0, 0, "A").unwrap();
        a.commit();
        b.splice_text(&text, 0, 0, "B").unwrap();
        b.commit();
        let a_change = a.get_last_local_change().unwrap();
        let b_change = b.get_last_local_change().unwrap();
        // c (actor 1 again) names b's element without having seen b.
        let mut c = a.fork().with_actor(actor(1));
        c.splice_text(&text, 1, 0, "c").unwrap();
        c.commit();
        let mut bad = c.get_last_local_change().unwrap().decode();
        let b_elem = automerge::legacy::OpId(b_change.start_op().get(), actor(3));
        bad.operations[0].key = automerge::legacy::Key::Seq(automerge::legacy::ElementId::Id(b_elem));
        let bad = Change::from(bad);
        for order in [[&a_change, &b_change], [&b_change, &a_change]] {
            let mut index = Index::default();
            admit_all(&mut index, &base.get_changes(&[]));
            admit_all(&mut index, &order.map(|c| c.clone()));
            assert!(index.admit(&c.get_last_local_change().unwrap()).is_some());
            assert!(index.admit(&bad).is_none(), "b is outside c's declared history");
        }
    }

    /// Found by fuzzing (`fuzz/fuzz_targets/sync_doc.rs`): a member's change
    /// with an inserted delete (or increment), or a mark that isn't an
    /// insertion, passed the index; Automerge then applied it out of order
    /// (its debug check of the op order failed; release builds went on with
    /// a corrupt document). Automerge never writes such operations.
    #[test]
    fn inserted_deletes_and_uninserted_marks_are_refused() {
        use automerge::legacy::OpType;
        use automerge::marks::{ExpandMark, Mark};
        let mut d = AutoCommit::new().with_actor(actor(1));
        let text = d.put_object(ROOT, "text", ObjType::Text).unwrap();
        d.splice_text(&text, 0, 0, "abc").unwrap();
        d.commit();
        let base = d.get_changes(&[]);
        d.splice_text(&text, 1, 1, "").unwrap();
        d.mark(&text, Mark::new("bold".into(), true, 0, 2), ExpandMark::None).unwrap();
        d.commit();
        let honest = d.get_last_local_change().unwrap();
        let ops = honest.decode().operations;
        let at = |want: fn(&OpType) -> bool| ops.iter().position(|o| want(&o.action)).unwrap();
        let delete = at(|a| matches!(a, OpType::Delete));
        let mark = at(|a| matches!(a, OpType::MarkEnd(_)));
        let mut index = Index::default();
        admit_all(&mut index, &base);
        assert!(index.admit(&honest).is_some());
        let crafted = |edit: &dyn Fn(&mut automerge::legacy::Change)| {
            let mut c = honest.decode();
            edit(&mut c);
            Change::from(c)
        };
        let inserted_delete = crafted(&|c| c.operations[delete].insert = true);
        assert!(index.admit(&inserted_delete).is_none(), "an inserted delete");
        let inserted_increment = crafted(&|c| {
            c.operations[delete].insert = true;
            c.operations[delete].action = OpType::Increment(1);
        });
        assert!(index.admit(&inserted_increment).is_none(), "an inserted increment");
        let uninserted_mark = crafted(&|c| c.operations[mark].insert = false);
        assert!(index.admit(&uninserted_mark).is_none(), "a mark that isn't an insertion");
    }

    #[test]
    fn rollback_restores_the_index() {
        let mut d = AutoCommit::new().with_actor(actor(1));
        d.put(ROOT, "k", 1).unwrap();
        d.commit();
        let first = d.get_changes(&[]);
        let mut index = Index::default();
        admit_all(&mut index, &first);
        let cp = index.checkpoint();
        d.put(ROOT, "k", 2).unwrap();
        d.commit();
        let second = d.get_last_local_change().unwrap();
        admit_all(&mut index, std::slice::from_ref(&second));
        index.rollback(cp);
        assert!(!index.contains(&second.hash()));
        assert_eq!(index.heads(), HashSet::from([first[0].hash()]));
        assert!(index.admit(&second).is_some());
    }
}
