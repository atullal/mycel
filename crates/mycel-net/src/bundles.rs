//! Store-and-forward for spaces (Sync v2 design §9, findings 6 and 9):
//! what a node hands to carriers for a member it can't reach live.
//!
//! - **Sealed and padded.** The payload (kind
//!   [`mesh::dtn::KIND_SPACE_SYNC_SEALED`], bundle header version 2) is
//!   sealed to the destination's key-exchange key with HPKE base mode
//!   (RFC 9180, the lockbox suite: `mycel_crypto::seal_lockbox`), with
//!   `info = "mycel/v2/dtn-seal" ‖ src ‖ dst`, after padding the plaintext
//!   to its PADMÉ size class (at most 12% overhead; Nikitin et al. 2019).
//!   Carriers, strangers included, learn the source, the destination, a
//!   size class and timing: not the space, its members or its items, which
//!   the version 1 payload exposed (signed, not encrypted). A destination
//!   known to speak only version 1 still gets the old payload; any other
//!   destination gets the sealed one (private by default).
//! - **Oldest missing first, in one pass.** Ops the destination may lack
//!   come first (what follows the op tips it verified in the last session,
//!   else all of them, in resolution order, as a causal prefix), then per
//!   author the envelopes above what it is known to hold on that branch, in
//!   ascending seq, authors interleaved by round-robin, until the 200 KB
//!   payload budget. Every bundle extends valid chains (recent envelopes
//!   without their prefix would stay pending at the destination).
//! - **Incremental.** What is in flight to a destination (sent, not yet
//!   known delivered) is skipped by the next bundle, so a large backlog
//!   goes out as a sequence of bundles instead of the same one again; a
//!   live session with the destination clears it (anything still missing
//!   is then sent again).
//! - **Deduplicated on the plaintext.** HPKE seals with a fresh ephemeral
//!   key each time, so the bundle id changes on every seal; a plaintext
//!   identical to one in flight is not sealed or sent again.
//! - **One budget per source.** At most [`SOURCE_BUDGET`] of our bundles
//!   are in flight across all destinations and spaces, under carriers'
//!   per-source share, so our own backlog can't evict itself.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mycel_crypto::{Hash32, Lockbox, SignPk};
use mycel_sync::reconcile::{SyncSet, encoded_len};
use mycel_sync::{Envelope, EnvelopeId, Replica};
use mycel_trust::{OpId, SignedOp, SpaceId};
use serde::{Deserialize, Serialize};

use crate::mesh;

/// Our bundles in flight, all destinations and spaces together.
pub const SOURCE_BUDGET: usize = 3 * 1024 * 1024;
const CTX_SEAL: &[u8] = b"mycel/v2/dtn-seal";
const CTX_PLAIN: &str = "mycel/v2/dtn-plain";

/// The sealed payload's plaintext (before padding).
#[derive(Debug, Serialize, Deserialize)]
pub struct DtnPayload2 {
    pub space: SpaceId,
    /// Canonical ops, parents first.
    pub ops: Vec<SignedOp>,
    /// Per author ascending seq, authors interleaved.
    pub envelopes: Vec<Envelope>,
}

/// PADMÉ: round `len` up so that only O(log log len) bits of it show.
pub fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = usize::BITS - 1 - len.leading_zeros(); // floor(log2 len)
    let s = (usize::BITS - 1 - (e as usize).leading_zeros()) + 1; // floor(log2 e) + 1
    let last = e - s;
    let mask = (1usize << last) - 1;
    (len + mask) & !mask
}

fn seal_info(src: &SignPk, dst: &SignPk) -> Vec<u8> {
    [CTX_SEAL, &src.0, &dst.0].concat()
}

/// Seal a payload for `dst` (its key-exchange key `kex`): padded, then HPKE.
pub fn seal(src: &SignPk, dst: &SignPk, kex: &mycel_crypto::KexPk, payload: &DtnPayload2) -> Result<(Vec<u8>, Hash32)> {
    let mut plain = postcard::to_allocvec(payload)?;
    let digest = Hash32::digest(CTX_PLAIN, &plain);
    plain.resize(padme(plain.len()), 0);
    let lockbox = mycel_crypto::seal_lockbox(kex, &seal_info(src, dst), &plain)?;
    Ok((postcard::to_allocvec(&lockbox)?, digest))
}

/// Open a sealed payload from `src` addressed to us.
pub fn open(keys: &mycel_crypto::DeviceKeys, src: &SignPk, sealed: &[u8]) -> Result<DtnPayload2> {
    let lockbox: Lockbox = postcard::from_bytes(sealed).context("sealed bundle")?;
    let plain = keys.open_lockbox(&seal_info(src, &keys.sign_pk()), &lockbox)?;
    let (payload, rest) = postcard::take_from_bytes::<DtnPayload2>(&plain)?;
    if rest.iter().any(|b| *b != 0) || plain.len() != padme(plain.len() - rest.len()) {
        return Err(anyhow!("bad bundle padding"));
    }
    Ok(payload)
}

/// What is in flight to one destination in one space.
#[derive(Default)]
struct InFlight {
    ops: HashSet<OpId>,
    envelopes: HashSet<EnvelopeId>,
    /// Plaintext digests in flight (dedup), with their bytes and when sent.
    bundles: VecDeque<(Hash32, usize, Instant)>,
}

/// Store-and-forward state of a node.
#[derive(Default)]
pub(crate) struct Bundles {
    flight: HashMap<(SignPk, SpaceId), InFlight>,
    /// Bundles sent (and refused for the budget), for tests and diagnostics.
    pub(crate) sent: u64,
    pub(crate) over_budget: u64,
    pub(crate) duplicates: u64,
}

impl Bundles {
    fn expire(&mut self, lifetime: Duration) {
        for f in self.flight.values_mut() {
            while f.bundles.front().is_some_and(|(_, _, t)| t.elapsed() > lifetime) {
                f.bundles.pop_front();
            }
            if f.bundles.is_empty() {
                f.ops.clear();
                f.envelopes.clear();
            }
        }
        self.flight.retain(|_, f| !f.bundles.is_empty());
    }

    pub(crate) fn in_flight_bytes(&self) -> usize {
        self.flight.values().flat_map(|f| f.bundles.iter().map(|(_, n, _)| *n)).sum()
    }

    /// A live session with `peer` in `space` succeeded: whatever was in
    /// flight there arrived or is no longer needed.
    pub(crate) fn delivered(&mut self, peer: &SignPk, space: &SpaceId) {
        self.flight.remove(&(*peer, *space));
    }
}

/// Pick what `peer` may lack, oldest first, within `budget` bytes of
/// encoded items, skipping what is in flight. `base_ops`: op tips the peer
/// is known to hold (empty: assume none).
pub(crate) fn select(
    r: &Replica,
    peer: &SignPk,
    base_ops: &[OpId],
    skip_ops: &HashSet<OpId>,
    skip_envs: &HashSet<EnvelopeId>,
    budget: usize,
) -> (Vec<SignedOp>, Vec<Envelope>) {
    let mut left = budget;
    let mut ops = Vec::new();
    let base: Vec<OpId> = base_ops.iter().filter(|o| r.holds_op(o)).copied().collect();
    let mut ops_cut = false;
    for id in r.ops_after(&base) {
        if skip_ops.contains(&id) {
            continue;
        }
        let Some(op) = SyncSet::op(r, &id) else { continue };
        let n = encoded_len(&op);
        if n > left {
            // A causal prefix: nothing after an op that didn't fit.
            ops_cut = true;
            break;
        }
        left -= n;
        ops.push(op);
    }
    if ops_cut {
        return (ops, Vec::new());
    }
    // Per author and branch: what the peer lacks, from the lowest seq.
    let mut queues: BTreeMap<(SignPk, EnvelopeId), VecDeque<EnvelopeId>> = BTreeMap::new();
    for (author, entry) in r.index().entries().iter() {
        let held = r.held_runs(peer, author);
        for run in &entry.runs {
            let lo = held
                .iter()
                .filter(|h| r.index().is_ancestor(&h.head, &run.head) && h.bottom <= run.bottom)
                .map(|h| h.top + 1)
                .max()
                .unwrap_or(run.bottom);
            if lo > run.top {
                continue;
            }
            let ids: VecDeque<EnvelopeId> =
                r.index().branch_ids(&run.head, lo, run.top).into_iter().filter(|id| !skip_envs.contains(id)).collect();
            if !ids.is_empty() {
                queues.insert((*author, run.head), ids);
            }
        }
    }
    // Round-robin across chains, one envelope each per turn.
    let mut envelopes = Vec::new();
    let mut seen = HashSet::new();
    'fill: while !queues.is_empty() {
        let keys: Vec<(SignPk, EnvelopeId)> = queues.keys().copied().collect();
        for k in keys {
            let Some(q) = queues.get_mut(&k) else { continue };
            let Some(id) = q.pop_front() else {
                queues.remove(&k);
                continue;
            };
            if q.is_empty() {
                queues.remove(&k);
            }
            if !seen.insert(id) {
                continue;
            }
            let Some(env) = r.envelope(&id) else { continue };
            let n = encoded_len(env);
            if n > left {
                // This chain stops here (later seqs need this one first).
                queues.remove(&k);
                if left < 512 {
                    break 'fill;
                }
                continue;
            }
            left -= n;
            envelopes.push(env.clone());
        }
    }
    (ops, envelopes)
}

impl crate::Inner {
    /// `peer` (a member of `space`) can't be reached live: send what it may
    /// lack through store-and-forward carriers (see the module docs).
    pub(crate) fn offer_bundle(&self, peer: SignPk, space: SpaceId) {
        let Some(mesh) = &self.mesh else { return };
        let me = self.keys.sign_pk();
        // Sealed unless the peer is known to speak only version 1.
        let v1_peer = self.v2.is_v1_only(&peer)
            || self.peers.lock().get(&peer).and_then(|p| p.protocol).is_some_and(|p| !p.supports(crate::Caps::SYNC_V2));
        let record = self.v2.record(peer, space);
        let mut b = self.bundles.lock();
        b.expire(crate::BUNDLE_LIFETIME);
        let room = SOURCE_BUDGET.saturating_sub(b.in_flight_bytes());
        // Encoding overhead beyond the items: the payload's frame, padding
        // (up to 12%) and the seal.
        let budget = crate::MAX_BUNDLE_PAYLOAD.min(room) * 7 / 8;
        if budget < 1024 {
            b.over_budget += 1;
            return;
        }
        let empty = InFlight::default();
        let f = b.flight.get(&(peer, space)).unwrap_or(&empty);
        let picked = self
            .with_space(&space, |r| {
                let kex = r.members().into_iter().find(|(k, _)| k.sign_pk == peer).map(|(k, _)| k.kex_pk)?;
                // Op tips the peer verified holding: its own opening tips and ours.
                let base: Vec<OpId> = record
                    .as_ref()
                    .map(|rec| [rec.peer.ops.clone(), rec.mine.ops.clone()].concat())
                    .unwrap_or_default();
                let (ops, envelopes) = select(r, &peer, &base, &f.ops, &f.envelopes, budget);
                (!ops.is_empty() || !envelopes.is_empty()).then_some((kex, ops, envelopes))
            })
            .ok()
            .flatten();
        let Some((kex, ops, envelopes)) = picked else { return };
        let op_ids: Vec<OpId> = ops.iter().map(|o| o.id()).collect();
        let env_ids: Vec<EnvelopeId> = envelopes.iter().map(|e| e.id()).collect();
        let (payload, digest, format) = if v1_peer {
            let p = crate::wire::DtnPayload { space, data: crate::wire::Data { ops, envelopes } };
            let Ok(bytes) = postcard::to_allocvec(&p) else { return };
            let digest = Hash32::digest(CTX_PLAIN, &bytes);
            (bytes, digest, mesh::dtn::BundleFormat::V1)
        } else {
            let p = DtnPayload2 { space, ops, envelopes };
            let Ok((bytes, digest)) = seal(&me, &peer, &kex, &p) else { return };
            (bytes, digest, mesh::dtn::BundleFormat::v2(mesh::dtn::KIND_SPACE_SYNC_SEALED))
        };
        if payload.len() > crate::MAX_BUNDLE_PAYLOAD {
            return;
        }
        let f = b.flight.entry((peer, space)).or_default();
        if f.bundles.iter().any(|(d, _, _)| *d == digest) {
            b.duplicates += 1;
            return; // already on its way
        }
        f.ops.extend(op_ids);
        f.envelopes.extend(env_ids);
        f.bundles.push_back((digest, payload.len(), Instant::now()));
        b.sent += 1;
        drop(b);
        mesh.send_bundle_as(peer, format, payload.into(), crate::BUNDLE_LIFETIME);
    }

    /// A bundle for us arrived through carriers: apply it like a sync from
    /// its (authenticated) source, if that source is a member. A payload
    /// kind this build doesn't know (a newer sender's) is refused unread;
    /// it was still delivered (the mesh has sent its receipt), so carriers
    /// stop carrying it.
    pub(crate) fn on_bundle(&self, src: SignPk, kind: u16, payload: &[u8]) -> Result<()> {
        let (space, data) = match kind {
            mesh::dtn::KIND_SPACE_SYNC => {
                let crate::wire::DtnPayload { space, data } = postcard::from_bytes(payload)?;
                (space, data)
            }
            mesh::dtn::KIND_SPACE_SYNC_SEALED => {
                let p = open(&self.keys, &src, payload)?;
                (p.space, crate::wire::Data { ops: p.ops, envelopes: p.envelopes })
            }
            _ => {
                return Err(crate::VersionError::Unsupported {
                    what: "bundle payload kind",
                    version: kind.into(),
                    newest: mesh::dtn::KIND_SPACE_SYNC_SEALED.into(),
                }
                .into());
            }
        };
        if !self.with_space(&space, |r| r.is_member(&src)).unwrap_or(false) {
            return Ok(());
        }
        self.ingest(&space, src, data, &[]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mycel_crypto::DeviceKeys;
    use mycel_sync::StreamId;
    use mycel_trust::Role;

    use super::*;

    fn space_with(n: usize) -> (Replica, Arc<DeviceKeys>, Vec<Envelope>) {
        let (mut a, _) = Replica::create(Arc::new(DeviceKeys::generate()), None).unwrap();
        let bk = Arc::new(DeviceKeys::generate());
        a.add_member(bk.public(), Role::Writer).unwrap();
        let feed = StreamId::new_feed();
        let envs =
            (0..n).map(|i| a.append(feed, format!("message {i:04} ...........").into_bytes()).unwrap().1).collect();
        (a, bk, envs)
    }

    /// Finding 9: carriers (strangers included) can't read a sealed bundle:
    /// no space id, no member key, no item header in the clear. Only the
    /// destination opens it, and a changed byte doesn't open.
    #[test]
    fn a_sealed_bundle_hides_the_space_from_carriers() {
        let (a, bk, envs) = space_with(3);
        let me = a.me().sign_pk();
        let p = DtnPayload2 { space: a.space_id(), ops: a.all_ops(), envelopes: envs.clone() };
        let (sealed, _) = seal(&me, &bk.sign_pk(), &bk.public().kex_pk, &p).unwrap();
        let has = |needle: &[u8]| sealed.windows(needle.len()).any(|w| w == needle);
        assert!(!has(&a.space_id().0), "space id in the clear");
        assert!(!has(&bk.sign_pk().0), "member key in the clear");
        assert!(!has(&envs[0].id().0) && !has(&envs[0].header.author.0));
        let opened = open(&bk, &me, &sealed).unwrap();
        assert_eq!((opened.space, opened.envelopes.len(), opened.ops.len()), (a.space_id(), 3, p.ops.len()));
        // Not for anyone else, not from anyone else, not altered.
        let other = DeviceKeys::generate();
        assert!(open(&other, &me, &sealed).is_err());
        assert!(open(&bk, &other.sign_pk(), &sealed).is_err());
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&bk, &me, &bad).is_err());
        // Padded to its size class.
        let plain = postcard::to_allocvec(&p).unwrap().len();
        assert!(sealed.len() >= padme(plain));
    }

    /// Findings 6 and the oldest-first rule: one pass picks ops first, then
    /// each chain from the lowest seq the destination lacks; what is in
    /// flight is skipped, so a backlog larger than a bundle goes out as a
    /// sequence of bundles, each extending valid chains.
    #[test]
    fn selection_is_oldest_missing_first_and_incremental() {
        let (mut a, bk, envs) = space_with(100);
        let peer = bk.sign_pk();
        let env_size = encoded_len(&envs[50]);
        let ops_size: usize = a.all_ops().iter().map(encoded_len).sum();
        // Ops first, then the chain from seq 0.
        let (ops, picked) = select(&a, &peer, &[], &HashSet::new(), &HashSet::new(), ops_size + 10 * env_size + 100);
        assert_eq!(ops.len(), a.all_ops().len());
        let seqs: Vec<u64> = picked.iter().map(|e| e.header.author_seq).collect();
        assert_eq!(seqs, (0..10).collect::<Vec<_>>());
        // The next bundle skips what is in flight.
        let skip_ops: HashSet<OpId> = ops.iter().map(|o| o.id()).collect();
        let skip_envs: HashSet<EnvelopeId> = picked.iter().map(|e| e.id()).collect();
        let (ops2, picked2) = select(&a, &peer, &[], &skip_ops, &skip_envs, 10 * env_size + 100);
        assert!(ops2.is_empty());
        assert_eq!(picked2.first().map(|e| e.header.author_seq), Some(10));
        // A destination known to hold the chain up to seq 49 gets 50 onward.
        let mut b = Replica::join(bk.clone(), a.op(&a.space_id()).unwrap().clone(), None).unwrap();
        b.ingest_batch(a.all_ops(), envs[..50].to_vec());
        let entry = b.index().entries()[&a.me().sign_pk()].clone();
        a.note_frontier(peer, [&entry]);
        let tips = a.op_tips();
        let (ops3, picked3) = select(&a, &peer, &tips, &HashSet::new(), &HashSet::new(), 5 * env_size + 100);
        assert!(ops3.is_empty(), "the peer verified our op tips");
        assert_eq!(picked3.first().map(|e| e.header.author_seq), Some(50));
        // Ops larger than the budget: a causal prefix of ops, no envelopes.
        let (ops4, picked4) =
            select(&a, &peer, &[], &HashSet::new(), &HashSet::new(), encoded_len(&a.all_ops()[0]) + 1);
        assert_eq!((ops4.len(), picked4.len()), (1, 0));
    }

    #[test]
    fn padme_overhead_is_at_most_12_percent_and_classes_are_coarse() {
        for len in [1usize, 2, 9, 100, 1000, 4095, 65_000, 200_000] {
            let p = padme(len);
            assert!(p >= len && (p - len) as f64 <= 0.12 * len as f64 + 1.0, "{len} -> {p}");
            assert_eq!(padme(p), p, "a class maps to itself");
        }
        // Lengths near 200 KB fall into few classes.
        let classes: HashSet<usize> = (190_000..200_000).map(padme).collect();
        assert!(classes.len() <= 8, "{} classes", classes.len());
    }
}
