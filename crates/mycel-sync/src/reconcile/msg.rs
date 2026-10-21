//! Sync v2 wire messages (postcard). New variants and fields are only ever
//! appended: postcard can't skip what it doesn't know, so `Open` carries a
//! version and feature bits, and a server that can't speak them answers
//! [`Verdict::Unsupported`] instead of failing to decode.
//!
//! The types are generic over the op (`O`) and envelope (`E`) types so the
//! same state machine runs on real replicas (`SignedOp`, `Envelope`) and on
//! the synthetic model sets used by tests and benchmarks.

use mycel_crypto::SignPk;
use mycel_trust::{OpId, SpaceId};
use serde::{Deserialize, Serialize};

use crate::EnvelopeId;

/// A 32-byte BLAKE3 commitment to a canonical set's boundary.
pub type Digest = [u8; 32];

/// The name of a remembered session: the two `Close` digests, client's
/// first.
pub type RecordName = (Digest, Digest);

/// One chain head of an author, with the lowest seq reachable below it
/// through held `author_prev` links (0 for a chain held from its start).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Run {
    pub top: u64,
    pub head: EnvelopeId,
    pub bottom: u64,
}

/// An author's chain heads, as full 32-byte ids (nothing is truncated, so
/// nothing can be ground). Normally one run. At most
/// [`super::MAX_RUNS_INLINE`] are listed, the highest first; `truncated`
/// says there are more and commits to all of them (heads, bottoms and gap
/// ids, as the digest does), so two sides whose commitments match know they
/// hold the same chains of this author without listing them. Listing fewer
/// never breaks convergence (each side sends what the other's frontier
/// shows it lacks); it only makes the peer's coverage check of this author
/// incomplete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorEntry {
    pub author: SignPk,
    pub runs: Vec<Run>,
    pub truncated: Option<Digest>,
}

/// A frontier, or one chunk of it. The first chunk carries the op tips;
/// `more` says further [`Msg::Frontier`] chunks follow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    /// `Some(record)`: only authors whose entry differs from the sender's
    /// opening frontier stored in that session record (entries are always
    /// absolute, never relative). `None`: the full frontier.
    pub delta_of: Option<RecordName>,
    /// Canonical op tips. In a delta, `None` means "unchanged".
    pub ops: Option<Vec<OpId>>,
    pub authors: Vec<AuthorEntry>,
    pub more: bool,
}

/// Reserved for partial replication; v2 always sends `Full`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open<O> {
    pub version: u16,
    /// Feature bits; none are defined yet, so this must be 0.
    pub features: u64,
    pub space: SpaceId,
    pub nonce: [u8; 16],
    /// The client's canonical digest now (its pinned opening set).
    pub digest: Digest,
    /// The last converged session with this server, if the client
    /// remembers one: frontiers below are deltas against it.
    pub memory: Option<RecordName>,
    pub scope: Scope,
    /// The client's opening frontier (first chunk), when it has a record
    /// to send a delta against or expects a difference.
    pub frontier: Option<Frontier>,
    /// Every membership op, in resolution order: only after `NeedInvite`.
    pub invite: Option<Vec<O>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict<O> {
    /// Equal digests: nothing to do.
    InSync {
        digest: Digest,
    },
    /// Digests differ, but neither side changed since a quiet converged
    /// session that both remember: the sets differ only by items one side
    /// refused.
    Unchanged {
        digest: Digest,
    },
    /// The server's opening frontier (first chunk). `need_full`: the server
    /// has no usable client frontier (none sent, or a delta against a
    /// record it lost): the client sends its full frontier next.
    Diff {
        digest: Digest,
        frontier: Frontier,
        need_full: bool,
    },
    NeedInvite,
    Denied,
    /// The client was removed: the proof (v1 semantics).
    Removed {
        ops: Vec<O>,
    },
    /// The server can't speak this version or these features.
    Unsupported {
        version: u16,
        features: u64,
    },
    /// Rate-limited: retry after this long. Never a reason to fall back to v1.
    Busy {
        retry_after_ms: u32,
    },
}

/// What a `Close` says about the peer's opening frontier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    /// I hold everything in your opening frontier.
    All,
    /// I still lack your op tips (`ops`) and/or runs of these authors.
    Missing { ops: bool, authors: Vec<SignPk> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// A per-peer budget ran out: retry later.
    Budget,
    /// The peer broke the protocol.
    Protocol,
    /// The sender is shutting down or the space went away.
    Gone,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg<O, E> {
    /// Client → server, first frame.
    Open(Open<O>),
    /// Server → client, first frame.
    Status(Verdict<O>),
    /// A further chunk of the sender's opening frontier.
    Frontier(Frontier),
    /// Canonical ops, in resolution order, ancestry-closed.
    Ops(Vec<O>),
    /// Envelopes: per author in ascending seq along a branch; authors
    /// interleaved by proportional round-robin.
    Chunk(Vec<E>),
    /// Phase 2: "which of these ids on my run of `author` do you hold?"
    Probe { author: SignPk, run: EnvelopeId, points: Vec<(u64, EnvelopeId)> },
    /// Bitmap over the probe's points (bit i: point i is held), and for each
    /// held point (in bit order) the lowest seq the replier holds below it
    /// through valid links: it holds the prober's branch on that interval.
    ProbeReply { author: SignPk, run: EnvelopeId, held: u16, bottoms: Vec<u64> },
    /// The sender has sent everything it owes for `phase`. Sent without
    /// waiting for anything from the peer.
    SendsDone { phase: u8 },
    /// Sent after reading the peer's `SendsDone` for `phase` and ingesting
    /// every frame before it. `digest` is the sender's live digest (the
    /// name of the next record); `quiet`: its set is its opening set plus
    /// what the peer sent; `phase2`: it is willing to run phase 2.
    Close { phase: u8, coverage: Coverage, refused: Vec<EnvelopeId>, digest: Digest, quiet: bool, phase2: bool },
    /// The session ends here.
    Abort { reason: AbortReason },
}
