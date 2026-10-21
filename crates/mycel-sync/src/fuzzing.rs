//! Entry points for the fuzz targets in `fuzz/` (docs/TESTING.md,
//! "Fuzzing"), compiled only under `--cfg fuzzing`, which cargo-fuzz sets.
//! They reach the crate-private change parser, op decoder and causal index
//! through the functions a replica itself calls. Nothing here is API.

use std::collections::HashSet;

use automerge::legacy::{ElementId, Key as LegacyKey, ObjectId, OpId as LegacyOpId};
use automerge::{ActorId, Change, ChangeHash};
use mycel_trust::EpochId;
use sha2::{Digest, Sha256};

use crate::change_ops::{Key, Obj, OpRef};
use crate::{CTX_ENV_SIG, Envelope, EnvelopeId, Header, Replica, Result, StreamId, SyncError, content_aad, encode};

/// A change chunk of `kind` (1 = change, 2 = compressed change) around
/// `body`, with the length and SHA-256 checksum a well-formed chunk has: lets
/// a fuzzer mutate bodies without failing the checksum every time.
pub fn frame_change(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut header = vec![kind];
    leb128::write::unsigned(&mut header, body.len() as u64).expect("writes to a Vec");
    let mut hasher = Sha256::new();
    hasher.update(&header);
    hasher.update(body);
    let sum = hasher.finalize();
    let mut out = vec![0x85, 0x6f, 0x4a, 0x83];
    out.extend_from_slice(&sum[..4]);
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    out
}

/// The body of a change chunk: what follows its magic, checksum, type and
/// length (the inverse of [`frame_change`]).
pub fn change_body(chunk: &[u8]) -> Option<&[u8]> {
    let mut rest = chunk.get(9..)?;
    leb128::read::unsigned(&mut rest).ok()?;
    Some(rest)
}

/// Parse a change received from anyone, within the network-wide limits
/// (what a replica does to every decrypted document payload).
pub fn parse_change(bytes: &[u8]) -> Option<Change> {
    crate::bounded_change::parse(bytes).ok()
}

/// Decode `change`'s operations with this crate's column decoder and check
/// every row against Automerge's own decoding of the same change; panics on
/// any difference. Returns the number of operations, or `None` if our decoder
/// refused the change (refusing is allowed, disagreeing is not), or if a row
/// names an actor the change doesn't list: the causal index refuses those
/// (`doc_index.rs`), and Automerge's expansion of such a change panics. Also
/// `None` if the change lists an actor twice (the index refuses that too):
/// Automerge's expansion names actors by id, which can't tell the two apart.
pub fn check_ops_against_upstream(change: &Change) -> Option<usize> {
    let actors: Vec<ActorId> = change.actors().cloned().collect();
    if actors.iter().collect::<HashSet<_>>().len() != actors.len() {
        return None;
    }
    let mut ours: Vec<(Obj, Key, bool, Vec<OpRef>)> = Vec::new();
    crate::change_ops::visit(change, |_, row, preds| {
        ours.push((row.obj, row.key, row.insert, preds.to_vec()));
        Ok(())
    })
    .ok()?;
    let listed = |r: &OpRef| r.actor < actors.len();
    let all_listed = ours.iter().all(|(obj, key, _, preds)| {
        let obj_ok = match obj {
            Obj::Op(r) => listed(r),
            Obj::Root => true,
        };
        let key_ok = match key {
            Key::Elem(r) => listed(r),
            _ => true,
        };
        obj_ok && key_ok && preds.iter().all(listed)
    });
    if !all_listed {
        return None;
    }
    let expected = change.decode().operations;
    let convert = |id: &LegacyOpId| OpRef {
        counter: id.counter(),
        actor: actors.iter().position(|a| a == id.actor()).expect("upstream names a listed actor"),
    };
    assert_eq!(ours.len(), expected.len(), "every operation decoded");
    for (i, ((obj, key, insert, preds), op)) in ours.iter().zip(&expected).enumerate() {
        let want_obj = match &op.obj {
            ObjectId::Root => Obj::Root,
            ObjectId::Id(id) => Obj::Op(convert(id)),
        };
        let want_key = match &op.key {
            LegacyKey::Map(_) => Key::Prop,
            LegacyKey::Seq(ElementId::Head) => Key::Head,
            LegacyKey::Seq(ElementId::Id(id)) => Key::Elem(convert(id)),
        };
        assert_eq!((*obj, *key, *insert), (want_obj, want_key, op.insert), "operation {i} decodes differently");
        let mut want: Vec<OpRef> = op.pred.iter().map(convert).collect();
        let mut got = preds.clone();
        want.sort_by_key(|p| (p.counter, p.actor));
        got.sort_by_key(|p| (p.counter, p.actor));
        assert_eq!(got, want, "operation {i} has different predecessors");
    }
    Some(ours.len())
}

/// One document's causal index (see `doc_index.rs`).
#[derive(Default)]
pub struct DocIndex(crate::doc_index::Index);

impl DocIndex {
    /// Validate `change` against its declared history and, if valid, add it:
    /// what a replica does before handing a change to Automerge.
    pub fn admit(&mut self, change: &Change) -> bool {
        match self.0.admit(change) {
            Some(admitted) => {
                self.0.insert(admitted);
                true
            }
            None => false,
        }
    }

    pub fn contains(&self, hash: &ChangeHash) -> bool {
        self.0.contains(hash)
    }

    pub fn heads(&self) -> HashSet<ChangeHash> {
        self.0.heads()
    }
}

/// Seal `plaintext` into `stream` as the replica's own device would, but at
/// any chain position (`author_seq`, `author_prev`) and with a chosen nonce:
/// a member writing whatever it likes. Fails if the replica has no key to
/// write with.
pub fn seal(
    r: &Replica,
    stream: StreamId,
    plaintext: &[u8],
    author_seq: u64,
    author_prev: Option<EnvelopeId>,
    nonce: [u8; 24],
) -> Result<Envelope> {
    let epoch: EpochId = r.graph.state().write_epoch().ok_or(SyncError::NotAllowed("no epoch"))?;
    let key = r.ring.get(&epoch).ok_or(SyncError::NotAllowed("no epoch key"))?;
    let header = Header {
        space: r.space_id(),
        stream,
        author: r.me.sign_pk(),
        author_seq,
        author_prev,
        auth_heads: r.graph.heads(),
        epoch,
        nonce,
    };
    let ciphertext = key.seal(&header.nonce, &content_aad(&header), plaintext)?;
    let sig = r.me.sign(CTX_ENV_SIG, &[&encode(&header), &ciphertext]);
    Ok(Envelope { header, ciphertext, sig })
}
