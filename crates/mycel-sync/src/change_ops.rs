//! Streaming decoder for the columns of an Automerge 0.12 change that name
//! other operations: object, key, insert flag, action and predecessors.
//!
//! Mirrors automerge 0.12 `storage/change/change_op_columns.rs` (column
//! selection and per-row null rules) and `columnar/encoding/{rle,delta,boolean}`
//! (run encodings). Values, marks and expand flags are not decoded. It only
//! runs on bytes `Change::try_from` already accepted; anything it cannot read
//! the way upstream does is rejected. `tests::matches_upstream_decoding` checks
//! it against `Change::decode` on real changes of every kind.

use automerge::Change;

use crate::{Result, SyncError};

/// An operation id as written in a change: counter plus an index into the
/// change's actor table (0 = the change's own actor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpRef {
    pub counter: u64,
    pub actor: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Obj {
    Root,
    Op(OpRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Prop,
    Head,
    Elem(OpRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub obj: Obj,
    pub key: Key,
    pub insert: bool,
    pub action: u64,
}

const OBJ_ACTOR: u64 = 0x01;
const OBJ_CTR: u64 = 0x02;
const KEY_ACTOR: u64 = 0x11;
const KEY_CTR: u64 = 0x13;
const KEY_STR: u64 = 0x15;
const INSERT: u64 = 0x34;
const ACTION: u64 = 0x42;
const PRED_GROUP: u64 = 0x70;
const PRED_ACTOR: u64 = 0x71;
const PRED_CTR: u64 = 0x73;

fn bad<T>() -> Result<T> {
    Err(SyncError::Encoding)
}

fn unsigned(input: &mut &[u8]) -> Result<u64> {
    leb128::read::unsigned(input).map_err(|_| SyncError::Encoding)
}

fn signed(input: &mut &[u8]) -> Result<i64> {
    leb128::read::signed(input).map_err(|_| SyncError::Encoding)
}

fn take<'a>(input: &mut &'a [u8], len: u64) -> Result<&'a [u8]> {
    let len = usize::try_from(len).map_err(|_| SyncError::Encoding)?;
    let (head, tail) = input.split_at_checked(len).ok_or(SyncError::Encoding)?;
    *input = tail;
    Ok(head)
}

fn skip_string(input: &mut &[u8]) -> Result<()> {
    let len = unsigned(input)?;
    take(input, len).map(|_| ())
}

/// Run-length column (`RleDecoder`): `n > 0` repeats one value n times,
/// `n < 0` is followed by |n| literal values, `0` is followed by a null count.
/// `next` yields `None` once exhausted, `Some(None)` for a null.
struct Rle<'a, V> {
    data: &'a [u8],
    left: u64,
    literal: bool,
    last: Option<V>,
    read: fn(&mut &'a [u8]) -> Result<V>,
}

impl<'a, V: Copy> Rle<'a, V> {
    fn new(data: &'a [u8], read: fn(&mut &'a [u8]) -> Result<V>) -> Self {
        Rle { data, left: 0, literal: false, last: None, read }
    }

    fn next(&mut self) -> Result<Option<Option<V>>> {
        while self.left == 0 {
            if self.data.is_empty() {
                return Ok(None);
            }
            let control = signed(&mut self.data)?;
            if control > 0 {
                self.left = control as u64;
                self.last = Some((self.read)(&mut self.data)?);
                self.literal = false;
            } else if control < 0 {
                self.left = control.unsigned_abs();
                self.literal = true;
            } else {
                self.left = unsigned(&mut self.data)?;
                self.last = None;
                self.literal = false;
            }
        }
        self.left -= 1;
        if self.literal { Ok(Some(Some((self.read)(&mut self.data)?))) } else { Ok(Some(self.last)) }
    }
}

/// Delta column (`DeltaDecoder`): run-length signed deltas from 0.
struct Delta<'a> {
    rle: Rle<'a, i64>,
    value: i64,
}

impl<'a> Delta<'a> {
    fn new(data: &'a [u8]) -> Self {
        Delta { rle: Rle::new(data, signed), value: 0 }
    }

    fn next(&mut self) -> Result<Option<Option<i64>>> {
        Ok(self.rle.next()?.map(|delta| {
            delta.map(|d| {
                self.value = self.value.saturating_add(d);
                self.value
            })
        }))
    }
}

/// Boolean column (`BooleanDecoder`): alternating run lengths, false first.
struct Bools<'a> {
    data: &'a [u8],
    left: u64,
    value: bool,
}

impl Bools<'_> {
    fn next(&mut self) -> Result<Option<bool>> {
        while self.left == 0 {
            if self.data.is_empty() {
                return Ok(None);
            }
            self.left = unsigned(&mut self.data)?;
            self.value = !self.value;
        }
        self.left -= 1;
        Ok(Some(self.value))
    }
}

fn op_ref(counter: i64, actor: u64) -> Result<OpRef> {
    match (u64::try_from(counter), usize::try_from(actor)) {
        (Ok(counter), Ok(actor)) => Ok(OpRef { counter, actor }),
        _ => bad(),
    }
}

/// Call `f(index, row, preds)` for every operation in `change`, in order.
/// Returns the number of operations.
pub(crate) fn visit(change: &Change, mut f: impl FnMut(usize, &Row, &[OpRef]) -> Result<()>) -> Result<usize> {
    let raw = change.raw_bytes();
    // Chunk header: magic (4), checksum (4), type (1), ULEB body length.
    let mut input = raw.get(9..).ok_or(SyncError::Encoding)?;
    unsigned(&mut input)?;
    let deps = unsigned(&mut input)?.checked_mul(32).ok_or(SyncError::Encoding)?;
    take(&mut input, deps)?;
    skip_string(&mut input)?; // actor
    unsigned(&mut input)?; // seq
    unsigned(&mut input)?; // start op
    signed(&mut input)?; // time
    skip_string(&mut input)?; // message
    for _ in 0..unsigned(&mut input)? {
        skip_string(&mut input)?; // other actors
    }
    let count = unsigned(&mut input)?;
    if count > (input.len() / 2) as u64 {
        return bad();
    }
    let mut specs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        specs.push((unsigned(&mut input)?, unsigned(&mut input)?));
    }
    let mut columns: [&[u8]; 10] = [&[]; 10];
    let slot = |spec| match spec {
        OBJ_ACTOR => Some(0),
        OBJ_CTR => Some(1),
        KEY_ACTOR => Some(2),
        KEY_CTR => Some(3),
        KEY_STR => Some(4),
        INSERT => Some(5),
        ACTION => Some(6),
        PRED_GROUP => Some(7),
        PRED_ACTOR => Some(8),
        PRED_CTR => Some(9),
        _ => None,
    };
    let mut has_group = false;
    for (spec, len) in specs {
        let data = take(&mut input, len)?;
        has_group |= spec == PRED_GROUP;
        // Upstream only reads predecessor ids grouped under the group column.
        if matches!(spec, PRED_ACTOR | PRED_CTR) && !has_group {
            continue;
        }
        if let Some(i) = slot(spec) {
            columns[i] = data;
        }
    }
    let [obj_actor, obj_ctr, key_actor, key_ctr, key_str, insert, action, group, pred_actor, pred_ctr] = columns;
    // Upstream treats every object as the root unless both columns have data.
    let objs = !obj_actor.is_empty() && !obj_ctr.is_empty();
    let mut obj_actor = Rle::new(obj_actor, unsigned);
    let mut obj_ctr = Rle::new(obj_ctr, unsigned);
    let mut key_actor = Rle::new(key_actor, unsigned);
    let mut key_ctr = Delta::new(key_ctr);
    let mut key_str = Rle::new(key_str, skip_string);
    let mut insert = Bools { data: insert, left: 0, value: true };
    let mut action = Rle::new(action, unsigned);
    let mut group = Rle::new(group, unsigned);
    let mut pred_actor = Rle::new(pred_actor, unsigned);
    let mut pred_ctr = Delta::new(pred_ctr);
    let mut preds = Vec::new();
    let mut rows = 0;
    while let Some(next) = action.next()? {
        let Some(action) = next else { return bad() };
        let obj = if objs {
            match (obj_actor.next()?.flatten(), obj_ctr.next()?.flatten()) {
                (None, None) | (None, Some(0)) => Obj::Root,
                (Some(actor), Some(counter)) if counter > 0 => {
                    Obj::Op(op_ref(i64::try_from(counter).map_err(|_| SyncError::Encoding)?, actor)?)
                }
                _ => return bad(),
            }
        } else {
            Obj::Root
        };
        let key = match (key_actor.next()?.flatten(), key_ctr.next()?.flatten(), key_str.next()?.flatten()) {
            (None, None, Some(())) => Key::Prop,
            (None, Some(0), None) => Key::Head,
            // Upstream reads any element counter 0 as the head, but never
            // writes one with an actor (found by fuzzing: we read an element
            // no operation has, where upstream reads the head).
            (Some(_), Some(0), None) => return bad(),
            (Some(actor), Some(counter), None) => Key::Elem(op_ref(counter, actor)?),
            _ => return bad(),
        };
        let Some(insert) = insert.next()? else { return bad() };
        let Some(Some(n)) = group.next()? else { return bad() };
        preds.clear();
        for _ in 0..n {
            match (pred_actor.next()?.flatten(), pred_ctr.next()?.flatten()) {
                (Some(actor), Some(counter)) => preds.push(op_ref(counter, actor)?),
                _ => return bad(),
            }
        }
        f(rows, &Row { obj, key, insert, action }, &preds)?;
        rows += 1;
    }
    if rows != change.len() {
        return bad();
    }
    Ok(rows)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use automerge::{
        ActorId, AutoCommit, ObjType, ROOT, ReadDoc, ScalarValue,
        legacy::{ElementId, Key as LegacyKey, ObjectId, OpId as LegacyOpId},
        marks::{ExpandMark, Mark},
        transaction::Transactable,
    };

    fn actor(n: u8) -> ActorId {
        ActorId::from(vec![n; 32])
    }

    /// Changes covering every column this decoder reads: nested maps, lists
    /// and text, inserts after HEAD and after elements, overwrites and
    /// deletes (predecessors), counters and increments, marks, other actors'
    /// objects and elements, and conflicting values with several predecessors.
    /// Deterministic (fixed actors and timestamps), so their bytes can be
    /// compared with the audited fixtures.
    pub(crate) fn fixtures() -> Vec<Change> {
        let at = || automerge::transaction::CommitOptions::default().with_time(0);
        let mut a = AutoCommit::new().with_actor(actor(1));
        let map = a.put_object(ROOT, "map", ObjType::Map).unwrap();
        a.put(&map, "k", "v").unwrap();
        let list = a.put_object(ROOT, "list", ObjType::List).unwrap();
        a.insert(&list, 0, 1).unwrap();
        a.insert(&list, 1, ScalarValue::counter(5)).unwrap();
        a.insert(&list, 2, vec![0u8, 1, 2]).unwrap();
        let text = a.put_object(ROOT, "text", ObjType::Text).unwrap();
        a.splice_text(&text, 0, 0, "hello wörld 👋").unwrap();
        a.commit_with(at().with_message("first".to_string()));
        let mut b = a.fork().with_actor(actor(2));
        b.put(&map, "k", "b").unwrap();
        b.put(&map, "f", 1.5).unwrap();
        b.increment(&list, 1, 3).unwrap();
        b.splice_text(&text, 5, 1, ", ").unwrap();
        b.insert_object(&list, 0, ObjType::Map).unwrap();
        b.mark(&text, Mark::new("bold".into(), true, 0, 5), ExpandMark::After).unwrap();
        b.commit_with(at());
        a.put(&map, "k", "a").unwrap();
        a.put(&map, "neg", -7).unwrap();
        a.commit_with(at());
        a.merge(&mut b).unwrap();
        let mut c = a.fork().with_actor(actor(3));
        c.put(&map, "k", "resolved").unwrap(); // two predecessors
        c.delete(&list, 0).unwrap();
        c.splice_text(&text, 0, 4, "").unwrap();
        c.put(ROOT, "n", 7).unwrap();
        c.put(ROOT, "null", ()).unwrap();
        c.delete(ROOT, "list").unwrap();
        c.commit_with(at());
        a.merge(&mut c).unwrap();
        a.get_changes(&[])
    }

    fn convert(id: &LegacyOpId, actors: &[ActorId]) -> OpRef {
        OpRef { counter: id.counter(), actor: actors.iter().position(|a| a == id.actor()).unwrap() }
    }

    #[test]
    fn matches_upstream_decoding() {
        let changes = fixtures();
        assert!(changes.len() >= 3);
        let mut ops = 0;
        for change in changes {
            let actors: Vec<ActorId> = change.actors().cloned().collect();
            let expected = change.decode().operations;
            let mut seen = 0;
            visit(&change, |i, row, preds| {
                let op = &expected[i];
                let obj = match &op.obj {
                    ObjectId::Root => Obj::Root,
                    ObjectId::Id(id) => Obj::Op(convert(id, &actors)),
                };
                let key = match &op.key {
                    LegacyKey::Map(_) => Key::Prop,
                    LegacyKey::Seq(ElementId::Head) => Key::Head,
                    LegacyKey::Seq(ElementId::Id(id)) => Key::Elem(convert(id, &actors)),
                };
                assert_eq!((row.obj, row.key, row.insert), (obj, key, op.insert));
                let mut expected: Vec<OpRef> = op.pred.iter().map(|p| convert(p, &actors)).collect();
                let mut actual = preds.to_vec();
                expected.sort_by_key(|p| (p.counter, p.actor));
                actual.sort_by_key(|p| (p.counter, p.actor));
                assert_eq!(actual, expected);
                seen += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, expected.len());
            ops += seen;
        }
        assert!(ops > 20);
    }

    /// Found by fuzzing (`fuzz/fuzz_targets/sync_change.rs`, differential
    /// against Automerge): a key with an actor and counter 0 decoded here as
    /// an element, while Automerge reads it as the head. Upstream never
    /// writes it; it is refused.
    #[test]
    fn element_counter_zero_with_an_actor_is_refused() {
        let mut d = AutoCommit::new().with_actor(actor(1));
        let list = d.put_object(ROOT, "list", ObjType::List).unwrap();
        d.insert(&list, 0, 1).unwrap();
        d.commit();
        let mut crafted = d.get_last_local_change().unwrap().decode();
        let insert = crafted.operations.iter().position(|op| op.insert).unwrap();
        crafted.operations[insert].key = LegacyKey::Seq(ElementId::Id(LegacyOpId::new(0, &actor(1))));
        let crafted = Change::from(crafted);
        assert_eq!(crafted.decode().operations[insert].key, LegacyKey::Seq(ElementId::Head), "upstream: the head");
        assert!(visit(&crafted, |_, _, _| Ok(())).is_err());
    }

    #[test]
    fn large_paste_decodes_in_runs() {
        let mut d = AutoCommit::new().with_actor(actor(1));
        let text = d.put_object(ROOT, "text", ObjType::Text).unwrap();
        d.splice_text(&text, 0, 0, &"x".repeat(100_000)).unwrap();
        d.commit();
        let change = d.get_last_local_change().unwrap();
        assert_eq!(visit(&change, |_, _, _| Ok(())).unwrap(), 100_001);
        assert_eq!(d.text(&text).unwrap().len(), 100_000);
    }
}
