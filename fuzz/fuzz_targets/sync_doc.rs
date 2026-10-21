//! Documents edited concurrently by several authors with real Automerge
//! operations (maps, lists, text, counters, marks, blocks, forks and merges),
//! then validated by a replica's causal index (`doc_index.rs`) before
//! Automerge applies them, as a replica does. Optionally, one change's body
//! is mutated (and re-framed with a correct checksum) before delivery: a
//! member sending a crafted change.
//!
//! Properties, against Automerge as the oracle:
//! - liveness: every change Automerge itself produced is admitted once its
//!   dependencies are (an honest edit is never refused);
//! - safety: Automerge applies every admitted change, and the index's heads
//!   stay Automerge's heads;
//! - every honest change passes the network-wide parser (`bounded_change.rs`)
//!   and our op decoder reads it as Automerge does (no false refusals);
//! - and nothing panics, with overflow checks on in Automerge too.
//!
//! Counters and increments stay within ±2^32 (honest ones by construction,
//! a crafted change or the input is skipped): Automerge sums them with plain
//! `i64` arithmetic, which wraps in release builds (pinned by
//! `mycel-sync`'s `concurrent_counter_increments_that_overflow_converge`)
//! and would end the run here.
#![no_main]

use std::collections::HashSet;

use arbitrary::Arbitrary;
use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc, ScalarValue};
use libfuzzer_sys::fuzz_target;
use mycel_sync::fuzzing::{
    DocIndex, change_body, check_ops_against_upstream, counters_within, frame_change, parse_change,
};

#[derive(Arbitrary, Debug)]
enum Value {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    F64(f64),
    Bool(bool),
    Null,
    Counter(i64),
    Timestamp(i64),
}

impl From<Value> for ScalarValue {
    fn from(v: Value) -> Self {
        match v {
            Value::Int(i) => ScalarValue::Int(i),
            Value::Str(s) => ScalarValue::Str(s.into()),
            Value::Bytes(b) => ScalarValue::Bytes(b),
            Value::F64(f) => ScalarValue::F64(f),
            Value::Bool(b) => ScalarValue::Boolean(b),
            Value::Null => ScalarValue::Null,
            Value::Counter(c) => ScalarValue::counter(small(c)),
            Value::Timestamp(t) => ScalarValue::Timestamp(t),
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Kind {
    Map,
    List,
    Text,
}

#[derive(Arbitrary, Debug)]
enum Edit {
    Put { obj: u8, key: u8, value: Value },
    PutObject { obj: u8, key: u8, kind: Kind },
    Insert { obj: u8, index: u16, value: Value },
    InsertObject { obj: u8, index: u16, kind: Kind },
    Delete { obj: u8, key: u8 },
    Increment { obj: u8, key: u8, by: i64 },
    Splice { obj: u8, index: u16, delete: u8, text: String },
    Mark { obj: u8, start: u16, len: u8, name: u8, expand: u8 },
    SplitBlock { obj: u8, index: u16 },
    Commit,
    Merge { from: u8 },
}

#[derive(Arbitrary, Debug)]
struct Mutation {
    change: u8,
    at: u16,
    xor: u8,
    truncate: bool,
}

#[derive(Arbitrary, Debug)]
struct Input {
    edits: Vec<(u8, Edit)>,
    mutation: Option<Mutation>,
    reverse: bool,
}

const AUTHORS: usize = 3;

/// The largest counter value or increment fed to Automerge (see above): a
/// change holds at most 2^20 operations and a document here a few dozen
/// changes, so no sum of these reaches `i64::MAX`.
const COUNTER_BOUND: i64 = 1 << 32;

/// `v` scaled into ±[`COUNTER_BOUND`], keeping its sign.
fn small(v: i64) -> i64 {
    v >> 31
}

struct Author {
    doc: AutoCommit,
    objs: Vec<(ObjId, Kind)>,
}

impl Author {
    fn obj(&self, i: u8, want: &[Kind]) -> Option<ObjId> {
        let fits: Vec<&ObjId> =
            self.objs.iter().filter(|(_, k)| want.iter().any(|w| *w as u8 == *k as u8)).map(|(o, _)| o).collect();
        (!fits.is_empty()).then(|| fits[usize::from(i) % fits.len()].clone())
    }

    fn len(&self, obj: &ObjId) -> usize {
        self.doc.length(obj)
    }
}

fn obj_type(k: Kind) -> ObjType {
    match k {
        Kind::Map => ObjType::Map,
        Kind::List => ObjType::List,
        Kind::Text => ObjType::Text,
    }
}

fn key(k: u8) -> String {
    format!("k{}", k % 8)
}

fn apply(a: &mut Author, edit: Edit) {
    let seq = [Kind::List, Kind::Text];
    match edit {
        Edit::Put { obj, key: k, value } => {
            if let Some(o) = a.obj(obj, &[Kind::Map]) {
                let _ = a.doc.put(&o, key(k), ScalarValue::from(value));
            }
        }
        Edit::PutObject { obj, key: k, kind } => {
            if let Some(o) = a.obj(obj, &[Kind::Map])
                && let Ok(new) = a.doc.put_object(&o, key(k), obj_type(kind))
            {
                a.objs.push((new, kind));
            }
        }
        Edit::Insert { obj, index, value } => {
            if let Some(o) = a.obj(obj, &[Kind::List]) {
                let i = usize::from(index) % (a.len(&o) + 1);
                let _ = a.doc.insert(&o, i, ScalarValue::from(value));
            }
        }
        Edit::InsertObject { obj, index, kind } => {
            if let Some(o) = a.obj(obj, &[Kind::List]) {
                let i = usize::from(index) % (a.len(&o) + 1);
                if let Ok(new) = a.doc.insert_object(&o, i, obj_type(kind)) {
                    a.objs.push((new, kind));
                }
            }
        }
        Edit::Delete { obj, key: k } => {
            if let Some(o) = a.obj(obj, &[Kind::Map]) {
                let _ = a.doc.delete(&o, key(k));
            } else if let Some(o) = a.obj(obj, &seq) {
                let n = a.len(&o);
                if n > 0 {
                    let _ = a.doc.delete(&o, usize::from(k) % n);
                }
            }
        }
        Edit::Increment { obj, key: k, by } => {
            if let Some(o) = a.obj(obj, &[Kind::Map]) {
                let _ = a.doc.increment(&o, key(k), small(by));
            }
        }
        Edit::Splice { obj, index, delete, text } => {
            if let Some(o) = a.obj(obj, &[Kind::Text]) {
                let n = a.len(&o);
                let i = usize::from(index) % (n + 1);
                let del = (usize::from(delete) % 8).min(n - i);
                let text: String = text.chars().take(64).collect();
                let _ = a.doc.splice_text(&o, i, del as isize, &text);
            }
        }
        Edit::Mark { obj, start, len, name, expand } => {
            if let Some(o) = a.obj(obj, &[Kind::Text]) {
                let n = a.len(&o);
                if n > 0 {
                    let s = usize::from(start) % n;
                    let e = (s + usize::from(len)).min(n);
                    let expand = match expand % 4 {
                        0 => automerge::marks::ExpandMark::Before,
                        1 => automerge::marks::ExpandMark::After,
                        2 => automerge::marks::ExpandMark::Both,
                        _ => automerge::marks::ExpandMark::None,
                    };
                    let mark = automerge::marks::Mark::new(format!("m{}", name % 4), name % 2 == 0, s, e);
                    let _ = a.doc.mark(&o, mark, expand);
                }
            }
        }
        Edit::SplitBlock { obj, index } => {
            if let Some(o) = a.obj(obj, &[Kind::Text]) {
                let i = usize::from(index) % (a.len(&o) + 1);
                let _ = a.doc.split_block(&o, i);
            }
        }
        Edit::Commit => {
            a.doc.commit();
        }
        Edit::Merge { .. } => unreachable!("handled by the caller"),
    }
}

/// Deliver `changes` in dependency order (in the given order where it
/// allows): each change once all of its dependencies have been delivered.
fn deliver(changes: Vec<Change>, honest: &HashSet<ChangeHash>) {
    let mut index = DocIndex::default();
    let mut doc = AutoCommit::new().with_actor(ActorId::from(vec![0xee; 32]));
    let mut delivered: HashSet<ChangeHash> = HashSet::new();
    let mut pending = changes;
    loop {
        let before = pending.len();
        let mut later = Vec::new();
        for c in pending {
            if !c.deps().iter().all(|d| delivered.contains(d)) {
                later.push(c);
                continue;
            }
            delivered.insert(c.hash());
            if !index.admit(&c) {
                // only a crafted change may be refused
                assert!(!honest.contains(&c.hash()), "an honest change was refused: {:?}", c.decode());
                continue;
            }
            doc.apply_changes(vec![c.clone()]).expect("Automerge applies what the index admitted");
            assert!(doc.get_missing_deps(&[]).is_empty(), "admitted with missing dependencies");
            let heads: HashSet<ChangeHash> = doc.get_heads().into_iter().collect();
            assert_eq!(heads, index.heads(), "index heads diverge from Automerge's");
        }
        if later.is_empty() || later.len() == before {
            return;
        }
        pending = later;
    }
}

fuzz_target!(|input: Input| {
    let mut authors: Vec<Author> = (0..AUTHORS)
        .map(|i| Author {
            doc: AutoCommit::new().with_actor(ActorId::from(vec![i as u8 + 1; 32])),
            objs: vec![(ROOT, Kind::Map)],
        })
        .collect();
    for (who, edit) in input.edits.into_iter().take(64) {
        let w = usize::from(who) % AUTHORS;
        if let Edit::Merge { from } = edit {
            let f = usize::from(from) % AUTHORS;
            if f != w {
                let mut other = authors[f].doc.fork();
                let _ = authors[w].doc.merge(&mut other);
                // objects the other author made are now ours to edit too
                let theirs: Vec<(ObjId, Kind)> = authors[f].objs.clone();
                for o in theirs {
                    if !authors[w].objs.iter().any(|(x, _)| *x == o.0) && authors[w].doc.object_type(&o.0).is_ok() {
                        authors[w].objs.push(o);
                    }
                }
            }
            continue;
        }
        apply(&mut authors[w], edit);
    }
    let mut changes: Vec<Change> = Vec::new();
    let mut seen = HashSet::new();
    for a in &mut authors {
        a.doc.commit();
        for c in a.doc.get_changes(&[]) {
            if seen.insert(c.hash()) {
                changes.push(c);
            }
        }
    }
    // no false refusals: what Automerge writes, the network-wide parser and
    // our op decoder accept as it is
    for c in &changes {
        let parsed = parse_change(c.raw_bytes()).expect("an honest change parses");
        assert_eq!(parsed.hash(), c.hash());
        assert!(check_ops_against_upstream(&parsed).is_some(), "our op decoder refused an honest change");
    }
    let mut honest: HashSet<ChangeHash> = changes.iter().map(Change::hash).collect();
    if let Some(m) = input.mutation
        && !changes.is_empty()
    {
        let i = usize::from(m.change) % changes.len();
        let mut body = change_body(changes[i].raw_bytes()).unwrap_or_default().to_vec();
        if !body.is_empty() {
            let at = usize::from(m.at) % body.len();
            if m.truncate {
                body.truncate(at);
            } else {
                body[at] ^= m.xor.max(1);
            }
        }
        if let Some(crafted) = parse_change(&frame_change(1, &body)) {
            if !counters_within(&crafted, COUNTER_BOUND) {
                return;
            }
            // A crafted change may take an honest author's next slot (the
            // replica resolves such forks before validation; the index alone
            // refuses the second claimant), so that author's changes are no
            // longer owed admission.
            let actor = crafted.actor_id().clone();
            honest.retain(|h| changes.iter().find(|c| c.hash() == *h).is_some_and(|c| *c.actor_id() != actor));
            honest.remove(&changes[i].hash());
            changes[i] = crafted;
        }
    }
    if input.reverse {
        changes.reverse();
    }
    deliver(changes, &honest);
});
