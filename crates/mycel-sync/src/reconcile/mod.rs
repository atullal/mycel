//! Sync v2: set reconciliation whose cost follows the difference, not the
//! history (docs/ARCHITECTURE.md §"Live sync", design notes in the Sync v2
//! design doc).
//!
//! This module is sans-IO: a [`Session`] consumes and produces [`Msg`]s and
//! never touches a socket, a clock or a lock, so the node (`mycel-net`), the
//! simulator and the tests drive the same code.
//!
//! - **Digest.** Each side opens with a 32-byte commitment to the boundary
//!   of its set: op tips, every author's chain heads with their bottoms, and
//!   the ids missing below chain gaps. The boundary determines the set
//!   (ids are hashes over content that includes the references), so equal
//!   digests end the session in one round trip.
//! - **Frontier.** Otherwise each side sends, per author, its chain heads as
//!   full 32-byte ids with their seqs (normally one per author), as a delta
//!   against the frontiers of the last converged session with that peer
//!   when both remember it. Chains are hash-linked: holding the peer's head
//!   means holding its chain below it, so the holder of the longer chain
//!   streams the missing seq range.
//! - **Coverage ends a session.** Each side pins its opening frontier,
//!   streams what the peer's opening frontier shows it lacks, and sends
//!   `SendsDone` without waiting. After reading the peer's `SendsDone` it
//!   checks that it now covers the peer's opening frontier and says so in
//!   `Close`. Items arriving meanwhile from elsewhere don't matter.
//! - **Repair (phase 2).** A head that neither frontier places (a fork, an
//!   equivocation) is found by probing chain ids: galloping down from the
//!   tip, then bisecting. One id compares a whole prefix, so this takes
//!   O(log distance) rounds of at most 16 ids.
//!
//! Every item still goes through `Replica::ingest_batch`: nothing a
//! session summarises can admit or hide an item, only waste bytes or rounds.

use std::collections::BTreeMap;
use std::sync::Arc;

use mycel_crypto::SignPk;
use mycel_trust::{OpId, SpaceId};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::EnvelopeId;

mod index;
mod msg;
mod replica;
mod session;

#[cfg(any(test, feature = "model"))]
pub mod model;
#[cfg(test)]
mod tests;

pub use index::{ChainIndex, WINDOW};
pub use msg::{AbortReason, AuthorEntry, Coverage, Digest, Frontier, Msg, Open, RecordName, Run, Scope, Verdict};
pub use session::{Config, Outcome, PeerRecord, Received, Refusal, Role, Session, SessionError, SessionStats};

/// The protocol version in `Open`.
pub const VERSION: u16 = 1;
/// Feature bits this build understands (none yet).
pub const FEATURES: u64 = 0;
/// Data frames (`Ops`, `Chunk`) carry about this many bytes of items (one
/// item may exceed it alone): about 1.6 s on a 40 kB/s Bluetooth link, so
/// progress is visible and a broken session keeps what arrived.
pub const CHUNK_BYTES: usize = 64 * 1024;
/// The largest frame a session sends or accepts: a full chunk plus one
/// envelope at the size limit, or a control frame.
pub const MAX_FRAME: usize = CHUNK_BYTES + crate::MAX_ENVELOPE_CIPHERTEXT + 64 * 1024;
/// Frontiers go in chunks of this many authors (about 18 KB).
pub const FRONTIER_CHUNK_AUTHORS: usize = 256;
/// Runs listed per author; more are summarised as `truncated`.
pub const MAX_RUNS_INLINE: usize = 64;
/// Op tips accepted in a frontier.
pub const MAX_OP_TIPS: usize = 1024;
/// Points per probe.
pub const PROBE_POINTS: usize = 16;

const CTX_DIGEST: &str = "mycel/v2/sync-digest";

/// What a session needs from a set of items. `Replica` implements it, and
/// so does the synthetic model set used by tests and benchmarks.
pub trait SyncSet {
    type Op: Clone + Serialize + DeserializeOwned;
    type Env: Clone + Serialize + DeserializeOwned;
    fn space(&self) -> SpaceId;
    /// The envelope chains held (the canonical envelope set).
    fn index(&self) -> &ChainIndex;
    /// Tips of the canonical op DAG (stored, resolvable ops; pending ops
    /// are outside the set), sorted.
    fn op_tips(&self) -> Vec<OpId>;
    /// Is this op in the canonical op set?
    fn holds_op(&self, id: &OpId) -> bool;
    /// Canonical ops not in the causal past of `heads` (all held), in an
    /// order that puts parents first.
    fn ops_after(&self, heads: &[OpId]) -> Vec<OpId>;
    fn op_count(&self) -> u64;
    fn op(&self, id: &OpId) -> Option<Self::Op>;
    fn env(&self, id: &EnvelopeId) -> Option<Self::Env>;

    /// Items in the set; grows by one per item added.
    fn count(&self) -> u64 {
        self.op_count() + self.index().len() as u64
    }

    /// The set's digest (see the module docs).
    fn digest(&self) -> Digest {
        let tips = self.op_tips();
        let mut h = mycel_crypto::Digest::new(CTX_DIGEST);
        h.update(&self.space().0).update(&(tips.len() as u64).to_le_bytes());
        for t in &tips {
            h.update(&t.0);
        }
        h.update(&self.index().boundary().0);
        h.finalize().0
    }

    /// The full frontier summary, now.
    fn summary(&self) -> Summary {
        Summary { ops: self.op_tips(), authors: self.index().entries() }
    }
}

/// A resolved frontier: op tips and every author's entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub ops: Vec<OpId>,
    pub authors: Arc<BTreeMap<SignPk, AuthorEntry>>,
}

impl Summary {
    /// This summary as frontier chunks: a delta against `base` (named
    /// `name`) when given, else in full.
    pub fn chunks(&self, base: Option<(&Summary, RecordName)>) -> Vec<Frontier> {
        let (delta_of, ops, authors): (_, _, Vec<&AuthorEntry>) = match base {
            Some((b, name)) => (
                Some(name),
                (self.ops != b.ops).then(|| self.ops.clone()),
                self.authors.values().filter(|e| b.authors.get(&e.author) != Some(*e)).collect(),
            ),
            None => (None, Some(self.ops.clone()), self.authors.values().collect()),
        };
        let mut out: Vec<Frontier> = authors
            .chunks(FRONTIER_CHUNK_AUTHORS)
            .map(|c| Frontier { delta_of, ops: None, authors: c.iter().map(|e| (*e).clone()).collect(), more: true })
            .collect();
        if out.is_empty() {
            out.push(Frontier { delta_of, ops: None, authors: Vec::new(), more: true });
        }
        out[0].ops = ops;
        if let Some(last) = out.last_mut() {
            last.more = false;
        }
        out
    }

    /// The highest seq listed for `author`.
    fn top(&self, author: &SignPk) -> Option<u64> {
        self.authors.get(author).and_then(|e| e.runs.iter().map(|r| r.top).max())
    }
}

/// How many of these ids (of received items the set didn't hold before
/// ingesting them) it holds now: what a driver reports to
/// [`Session::ingested`].
pub fn gained<S: SyncSet>(set: &S, ops: &[OpId], envelopes: &[EnvelopeId]) -> u64 {
    (ops.iter().filter(|id| set.holds_op(id)).count() + envelopes.iter().filter(|id| set.index().holds(id)).count())
        as u64
}

/// Count postcard bytes without allocating.
pub fn encoded_len<T: Serialize + ?Sized>(v: &T) -> usize {
    struct Count(usize);
    impl postcard::ser_flavors::Flavor for Count {
        type Output = usize;
        fn try_push(&mut self, _: u8) -> postcard::Result<()> {
            self.0 += 1;
            Ok(())
        }
        fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
            self.0 += bytes.len();
            Ok(())
        }
        fn finalize(self) -> postcard::Result<usize> {
            Ok(self.0)
        }
    }
    postcard::serialize_with_flavor(v, Count(0)).unwrap_or(usize::MAX)
}

/// Bytes a frame takes on the stream: postcard plus a 4-byte length.
pub fn frame_len<T: Serialize + ?Sized>(v: &T) -> usize {
    encoded_len(v).saturating_add(4)
}
