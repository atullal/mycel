//! The chunk protocol's messages and its serving side.
//!
//! One QUIC bi-stream of kind `Chunk` per request, on the pooled connection
//! (low stream priority, like blobs, so messages go first):
//!
//! ```text
//! get:   C → S  Get{id}                    S → C  Found{len} ‖ bytes | NotFound | Busy
//! has:   C → S  Has{ids}                   S → C  Have{bits}
//! push:  C → S  Offer{space, root, total}  S → C  Accept | Complete | NoSpace | Denied
//!        C → S  Put{root, id, len} ‖ bytes S → C  Stored | NoSpace | Denied     (one stream per node)
//!        C → S  Done{root}                 S → C  Complete | Incomplete
//! ```
//!
//! **Get** is answered to anyone: a node is ciphertext, named by its hash,
//! and useless without a key that only travels inside messages. Devices we
//! share a conversation with are served freely; everyone else within a rate
//! per device and in total ([`SERVE_RATE_EACH`], [`SERVE_RATE_ALL`]), and
//! told `Busy` beyond it.
//!
//! **Offer** asks us to take a whole file, `total` bytes as stored:
//! - with a `space` we share with the sender, to keep it (pinned) like any
//!   attachment of that conversation: the same consent and size rules as
//!   blob pushes (a keeper takes any size, other devices up to
//!   [`crate::EAGER_PUSH_MAX`]);
//! - without one, to hold it for others in the cache, if the donated budget
//!   and the sender's standing ([`CacheTier`]) leave room. The room is
//!   promised until the pieces stop coming.
//!
//! Nothing is taken without an accepted offer, and no more than it declared.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use mycel_crypto::chunked::{self, Index, MAX_NODE};
use mycel_crypto::{Hash32, SignPk};
use mycel_trust::{Role, SpaceId};
use serde::{Deserialize, Serialize};

use super::store::{CacheTier, Refused, Source};
use super::{Chunks, Intake};
use crate::Inner;
use crate::wire::{recv_capped, send};

/// Ids in one `Has` request, at most.
pub(crate) const MAX_HAS: usize = 512;
/// The largest request frame: a full `Has`.
pub(crate) const MAX_REQ: usize = MAX_HAS * 32 + 1024;
/// Bytes per second served to one device we share no conversation with ...
pub const SERVE_RATE_EACH: u64 = 1024 * 1024;
/// ... and to all of them together.
pub const SERVE_RATE_ALL: u64 = 4 * 1024 * 1024;
/// A burst of this many seconds' worth is allowed.
const SERVE_BURST: u64 = 16;
/// What a `Has` request costs its sender, per id asked about.
const HAS_COST: u64 = 256;
/// A pinned offer nobody followed up on is forgotten after this long.
const INTAKE_TTL: Duration = Duration::from_secs(10 * 60);
const INTAKES_MAX: usize = 4096;
/// Offers one device may have open at once.
const INTAKES_EACH: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum ChunkReq {
    Get { id: Hash32 },
    Has { ids: Vec<Hash32> },
    Offer { space: Option<SpaceId>, root: Hash32, total: u64 },
    Put { root: Hash32, id: Hash32, len: u32 },
    Done { root: Hash32 },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ChunkResp {
    /// Followed by `len` raw bytes.
    Found {
        len: u32,
    },
    NotFound,
    /// Over the serving budget: try someone else, or later.
    Busy,
    /// One bit per id asked about, in order (bit 0 of byte 0 first).
    Have {
        bits: Vec<u8>,
    },
    Accept,
    /// We hold the whole file.
    Complete,
    Incomplete,
    NoSpace,
    Denied,
    Stored,
}

/// A bytes-per-second allowance with a burst.
struct Tokens {
    rate: f64,
    burst: f64,
    have: f64,
    at: Instant,
}

impl Tokens {
    fn new(rate: u64, now: Instant) -> Self {
        let burst = (rate * SERVE_BURST) as f64;
        Tokens { rate: rate as f64, burst, have: burst, at: now }
    }

    fn refill(&mut self, now: Instant) {
        self.have = (self.have + now.saturating_duration_since(self.at).as_secs_f64() * self.rate).min(self.burst);
        self.at = now;
    }
}

/// What may be served to devices we share no conversation with.
pub(crate) struct ServeBudget {
    all: Tokens,
    each: HashMap<SignPk, Tokens>,
    rate_each: u64,
}

impl ServeBudget {
    pub(crate) fn new(rate_each: u64, rate_all: u64) -> Self {
        ServeBudget { all: Tokens::new(rate_all, Instant::now()), each: HashMap::new(), rate_each }
    }

    /// Take `bytes` for `peer`, if both its share and the total allow.
    pub(crate) fn take(&mut self, peer: &SignPk, bytes: u64) -> bool {
        self.take_at(peer, bytes, Instant::now())
    }

    fn take_at(&mut self, peer: &SignPk, bytes: u64, now: Instant) -> bool {
        if self.each.len() > 4096 {
            // forget devices whose share has refilled: they lose nothing
            self.each.retain(|_, t| {
                t.refill(now);
                t.have < t.burst
            });
        }
        let rate = self.rate_each;
        let each = self.each.entry(*peer).or_insert_with(|| Tokens::new(rate, now));
        each.refill(now);
        self.all.refill(now);
        let n = bytes as f64;
        // neither is charged unless both allow it
        if each.have < n || self.all.have < n {
            return false;
        }
        each.have -= n;
        self.all.have -= n;
        true
    }
}

fn is_member_of_any(inner: &Inner, peer: &SignPk) -> bool {
    inner.spaces.lock().values().any(|r| r.is_member(peer))
}

/// One chunk request, on its own stream of a pooled connection.
pub(crate) async fn serve(inner: &Arc<Inner>, peer: SignPk, mut tx: SendStream, mut rx: RecvStream) -> Result<()> {
    let req: ChunkReq = recv_capped(&mut rx, crate::resources::FIRST_FRAME, &inner.frames(&peer), MAX_REQ).await?;
    let Some(chunks) = &inner.chunks else {
        send(&mut tx, &ChunkResp::Denied).await?;
        tx.finish().ok();
        return Ok(());
    };
    let res = match req {
        ChunkReq::Get { id } => serve_get(inner, chunks, peer, &mut tx, id).await,
        ChunkReq::Has { ids } => serve_has(inner, chunks, peer, &mut tx, ids).await,
        ChunkReq::Offer { space, root, total } => {
            let resp = offer(inner, chunks, peer, space, root, total).await;
            send(&mut tx, &resp).await
        }
        ChunkReq::Put { root, id, len } => serve_put(inner, chunks, peer, &mut tx, &mut rx, root, id, len).await,
        ChunkReq::Done { root } => {
            let resp = done(inner, chunks, peer, root).await;
            send(&mut tx, &resp).await
        }
    };
    tx.finish().ok();
    res
}

async fn serve_get(inner: &Arc<Inner>, chunks: &Chunks, peer: SignPk, tx: &mut SendStream, id: Hash32) -> Result<()> {
    let Some(len) = chunks.store.len_of(&id) else {
        return send(tx, &ChunkResp::NotFound).await;
    };
    if !is_member_of_any(inner, &peer) && !chunks.serve.lock().take(&peer, len as u64) {
        return send(tx, &ChunkResp::Busy).await;
    }
    let store = chunks.store.clone();
    // checked again on the way out: we never pass on a piece that rotted here
    let Ok(Ok(bytes)) = tokio::task::spawn_blocking(move || store.read_verified(&id)).await else {
        return send(tx, &ChunkResp::NotFound).await;
    };
    send(tx, &ChunkResp::Found { len: bytes.len() as u32 }).await?;
    crate::resources::write_all(tx, &bytes).await?;
    chunks.store.touch(&id, &peer);
    chunks.served.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

async fn serve_has(
    inner: &Arc<Inner>,
    chunks: &Chunks,
    peer: SignPk,
    tx: &mut SendStream,
    ids: Vec<Hash32>,
) -> Result<()> {
    if ids.len() > MAX_HAS {
        bail!("too many ids in one request");
    }
    if !is_member_of_any(inner, &peer) && !chunks.serve.lock().take(&peer, ids.len() as u64 * HAS_COST) {
        return send(tx, &ChunkResp::Busy).await;
    }
    let store = chunks.store.clone();
    let bits = tokio::task::spawn_blocking(move || {
        let mut bits = vec![0u8; ids.len().div_ceil(8)];
        for (i, id) in ids.iter().enumerate() {
            if store.has(id) {
                bits[i / 8] |= 1 << (i % 8);
            }
        }
        bits
    })
    .await?;
    send(tx, &ChunkResp::Have { bits }).await
}

/// Whether to take the file `peer` offers, and how.
async fn offer(
    inner: &Arc<Inner>,
    chunks: &Chunks,
    peer: SignPk,
    space: Option<SpaceId>,
    root: Hash32,
    total: u64,
) -> ChunkResp {
    let store = chunks.store.clone();
    let (complete, has_root) = tokio::task::spawn_blocking(move || (store.tree(&root).complete(), store.has(&root)))
        .await
        .unwrap_or((false, false));
    match space {
        Some(space) => {
            let (member, keeper) = inner
                .spaces
                .lock()
                .get(&space)
                .map_or((false, false), |r| (r.is_member(&peer), r.my_role() == Some(Role::Relay)));
            // membership, then the app's consent, then the size rule: as for blobs
            if !member || !(inner.blob_push_policy)(peer, space) || !(keeper || total <= crate::EAGER_PUSH_MAX) {
                return ChunkResp::Denied;
            }
            if !complete && crate::blobs::ensure_free_space(chunks.store.dir(), total).is_err() {
                return ChunkResp::NoSpace;
            }
            // Kept for the conversation from the root on. A root that isn't
            // here yet is pinned when it arrives (and is one): an offer
            // alone leaves nothing behind.
            if has_root {
                let store = chunks.store.clone();
                let _ = tokio::task::spawn_blocking(move || store.pin(root, space)).await;
            }
        }
        None if complete => return ChunkResp::Complete,
        None => match chunks.store.reserve(peer, root, total, chunks.tier(inner, &peer)) {
            Ok(()) => {}
            Err(Refused::Denied) => return ChunkResp::Denied,
            Err(_) => return ChunkResp::NoSpace,
        },
    }
    if complete {
        return ChunkResp::Complete;
    }
    let mut intakes = chunks.intakes.lock();
    let now = Instant::now();
    intakes.retain(|_, i| i.until > now);
    let mine = intakes.keys().filter(|(p, r)| *p == peer && *r != root).count();
    if intakes.len() >= INTAKES_MAX || mine >= INTAKES_EACH {
        return ChunkResp::NoSpace;
    }
    intakes.insert((peer, root), Intake { space, left: total, until: now + INTAKE_TTL });
    ChunkResp::Accept
}

#[allow(clippy::too_many_arguments)]
async fn serve_put(
    inner: &Arc<Inner>,
    chunks: &Chunks,
    peer: SignPk,
    tx: &mut SendStream,
    rx: &mut RecvStream,
    root: Hash32,
    id: Hash32,
    len: u32,
) -> Result<()> {
    // only what an accepted offer covers, and no more than it declared
    let covered = {
        let mut intakes = chunks.intakes.lock();
        match intakes.get_mut(&(peer, root)) {
            Some(i) if i.until > Instant::now() && i.left >= len as u64 && len as usize <= MAX_NODE => {
                i.until = Instant::now() + INTAKE_TTL;
                Some(i.space)
            }
            _ => None,
        }
    };
    let Some(space) = covered else {
        return send(tx, &ChunkResp::Denied).await;
    };
    if chunks.store.has(&id) {
        return send(tx, &ChunkResp::Stored).await;
    }
    // For a conversation, only the file's own nodes are taken: the root,
    // then what the indexes already here list (the sender goes parents
    // first). Anything else would be a way to store unrelated bytes.
    if space.is_some() && id != root && !chunks.store.is_protected(&id) {
        return send(tx, &ChunkResp::Denied).await;
    }
    let permit = inner.frames(&peer).admit(len as usize).await?;
    let (bytes, _permit) =
        crate::resources::read_body(rx, len as usize, false, permit, crate::resources::IDLE_TIMEOUT).await?;
    let tier = if space.is_some() { CacheTier::Contact } else { chunks.tier(inner, &peer) };
    let store = chunks.store.clone();
    let stored = tokio::task::spawn_blocking(move || {
        if let Some(space) = space
            && id == root
        {
            // the root of a file kept for a conversation: it must be an
            // index (and what its id says), and is pinned as it lands
            if chunked::node_id(&bytes) != id || Index::parse(&bytes).is_err() {
                return Err(Refused::Mismatch);
            }
            store.pin(root, space);
        }
        store.insert(id, &bytes, Source::Peer { peer, tier, root })
    })
    .await?;
    let resp = match stored {
        Ok(new) => {
            if new && let Some(i) = chunks.intakes.lock().get_mut(&(peer, root)) {
                i.left = i.left.saturating_sub(len as u64);
            }
            ChunkResp::Stored
        }
        Err(Refused::NoRoom | Refused::DiskFull) => ChunkResp::NoSpace,
        Err(Refused::Mismatch | Refused::Denied) => ChunkResp::Denied,
    };
    send(tx, &resp).await
}

/// The sender says the file is all here: check, and if it is in our cache
/// (held for whoever comes for it), say so where recipients look. A file
/// kept for a conversation is not announced: its members know who keeps it.
async fn done(inner: &Arc<Inner>, chunks: &Chunks, peer: SignPk, root: Hash32) -> ChunkResp {
    let intake = chunks.intakes.lock().remove(&(peer, root));
    let store = chunks.store.clone();
    let complete = tokio::task::spawn_blocking(move || store.tree(&root).complete()).await.unwrap_or(false);
    if !complete {
        return ChunkResp::Incomplete;
    }
    if intake.is_some_and(|i| i.space.is_none()) {
        super::announce(inner, root);
    }
    ChunkResp::Complete
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strangers_are_served_within_their_share_and_the_total() {
        let mut b = ServeBudget::new(100, 250);
        let (p1, p2, p3) = (SignPk([1; 32]), SignPk([2; 32]), SignPk([3; 32]));
        let burst = 100 * SERVE_BURST;
        let t0 = Instant::now();
        assert!(b.take_at(&p1, burst, t0));
        assert!(!b.take_at(&p1, 1, t0), "its own share is spent");
        assert!(b.take_at(&p2, burst, t0), "another device still has its own");
        // the total (250 a second) runs out before the third device's share
        assert!(b.take_at(&p3, burst / 2, t0));
        assert!(!b.take_at(&p3, 1, t0));
        // both refill with time, each at its own rate
        let later = t0 + Duration::from_secs(2);
        assert!(b.take_at(&p1, 200, later));
        assert!(!b.take_at(&p1, 1, later));
        assert!(b.take_at(&p3, 300, later), "what the total refilled, less what the first device just took");
        assert!(!b.take_at(&p2, 1, later));
    }

    #[test]
    fn requests_and_answers_round_trip() {
        let req = ChunkReq::Has { ids: vec![Hash32([7; 32]); MAX_HAS] };
        let bytes = postcard::to_allocvec(&req).unwrap();
        assert!(bytes.len() <= MAX_REQ, "a full Has fits the request frame");
        assert!(
            matches!(postcard::from_bytes::<ChunkReq>(&bytes).unwrap(), ChunkReq::Has { ids } if ids.len() == MAX_HAS)
        );
        let resp = ChunkResp::Have { bits: vec![0b101] };
        assert_eq!(postcard::from_bytes::<ChunkResp>(&postcard::to_allocvec(&resp).unwrap()).unwrap(), resp);
    }
}
