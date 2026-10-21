//! Delivery state without an O(envelopes × peers) holder map (Sync v2
//! design §10, WP7).
//!
//! Who holds an envelope is computed, not stored per envelope: for each
//! member we keep the chain runs it was seen to hold, per author (at most
//! [`RUNS_PER_AUTHOR`]), and a member holds envelope `e` if one of its runs
//! of `e`'s author ends at a head on `e`'s branch, with a bottom at or below
//! `e`'s seq. Chains are hash-linked, so that is exact (up to BLAKE3
//! collisions) and costs O(runs) per query through the chain index.
//!
//! Evidence comes from (1) sessions: the frontiers both sides verified
//! (Sync v2) or the inventories (v1); (2) gossip: the absolute entries a
//! neighbour sends with its pushes and announcements, and the items it
//! pushed; (3) **seen notes**, only from members who turned read receipts
//! on: a member's entries for authors that changed, signed by the member
//! (`"mycel/v2/seen"`), sealed under the space's current epoch key (so
//! keepers and carriers can't read them), at most one new note per member
//! per [`SEEN_INTERVAL_MS`], riding on gossip messages that are sent
//! anyway. Notes are not part of the synced set or its digest, and never
//! start a session.
//!
//! Memory is O(members × authors × runs), and at most [`MAX_MEMBERS`]
//! members are tracked per space (the oldest evidence goes first).

use std::collections::{BTreeMap, HashMap, VecDeque};

use mycel_crypto::{Sig, SignPk};
use mycel_trust::EpochId;
use serde::{Deserialize, Serialize};

use crate::reconcile::{AuthorEntry, Run};
use crate::{EnvelopeId, Replica};

/// Runs kept per (member, author), highest first.
pub const RUNS_PER_AUTHOR: usize = 4;
/// Members tracked per space.
pub const MAX_MEMBERS: usize = 256;
/// A member's seen notes are taken at most this often (ms of their clock,
/// enforced on ours by arrival time).
pub const SEEN_INTERVAL_MS: u64 = 30_000;
/// Authors in one seen note (about 70 B each: a note stays under 512 B).
pub const SEEN_AUTHORS: usize = 5;

const CTX_SEEN: &str = "mycel/v2/seen";
const AAD_SEEN: &[u8] = b"mycel/v2/seen-note";

/// What one member holds, per author.
#[derive(Default)]
pub(crate) struct Delivery {
    members: HashMap<SignPk, BTreeMap<SignPk, Vec<Run>>>,
    /// Members in order of first evidence (for the cap).
    order: VecDeque<SignPk>,
    /// Per member: the last seen-note seq taken, and when (ms since start).
    seen: HashMap<SignPk, (u64, std::time::Instant)>,
    /// Our own notes: the next seq, and the entries the last one covered.
    my_seq: u64,
    my_last: BTreeMap<SignPk, AuthorEntry>,
    my_at: Option<std::time::Instant>,
}

/// A seen note as carried (sealed under the epoch key).
#[derive(Serialize, Deserialize)]
struct Sealed {
    epoch: EpochId,
    nonce: [u8; 24],
    ct: Vec<u8>,
}

/// A seen note's plaintext.
#[derive(Serialize, Deserialize)]
struct SeenNote {
    member: SignPk,
    seq: u64,
    entries: Vec<AuthorEntry>,
    sig: Sig,
}

fn signed_bytes(space: &[u8; 32], member: &SignPk, seq: u64, entries: &[AuthorEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 32 + 8 + 70 * entries.len());
    v.extend_from_slice(space);
    v.extend_from_slice(&member.0);
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&postcard::to_allocvec(entries).unwrap_or_default());
    v
}

impl Delivery {
    fn runs_mut(&mut self, member: SignPk) -> &mut BTreeMap<SignPk, Vec<Run>> {
        if !self.members.contains_key(&member) {
            if self.members.len() >= MAX_MEMBERS
                && let Some(old) = self.order.pop_front()
            {
                self.members.remove(&old);
            }
            self.order.push_back(member);
        }
        self.members.entry(member).or_default()
    }
}

impl Replica {
    /// Record that `peer` holds these envelopes (from a sync inventory, or
    /// items it sent us). Ids we don't hold are ignored; consecutive ids
    /// extend one run.
    pub fn note_holder(&mut self, peer: SignPk, ids: &[EnvelopeId]) {
        let mut by_chain: Vec<(SignPk, u64, EnvelopeId)> =
            ids.iter().filter_map(|id| Some((self.index.author(id)?, self.index.seq(id)?, *id))).collect();
        if by_chain.is_empty() {
            return;
        }
        by_chain.sort();
        by_chain.dedup();
        for (author, seq, id) in by_chain {
            let parent = self.index.parent(&id);
            let index = &self.index;
            let runs = self.delivery.runs_mut(peer).entry(author).or_default();
            if runs.iter().any(|r| r.top >= seq && index.is_ancestor(&id, &r.head) && r.bottom <= seq) {
                continue;
            }
            // Extends a run whose head is its predecessor?
            if let Some(r) = runs.iter_mut().find(|r| Some(r.head) == parent) {
                r.head = id;
                r.top = seq;
            } else {
                runs.push(Run { top: seq, head: id, bottom: seq });
            }
            trim(runs);
        }
    }

    /// Record that `peer` holds these frontier entries (a verified session
    /// frontier, a neighbour's gossip entries, a seen note). Runs whose
    /// head we don't hold are ignored (we couldn't place them).
    pub fn note_frontier<'a>(&mut self, peer: SignPk, entries: impl IntoIterator<Item = &'a AuthorEntry>) {
        for e in entries {
            for run in &e.runs {
                if !self.index.holds(&run.head) {
                    continue;
                }
                let index = &self.index;
                let runs = self.delivery.runs_mut(peer).entry(e.author).or_default();
                if runs.iter().any(|r| index.is_ancestor(&run.head, &r.head) && r.bottom <= run.bottom) {
                    continue;
                }
                // (a held head's bottom in our index is at least as good)
                let bottom = index.bottom(&run.head).map_or(run.bottom, |b| b.max(run.bottom));
                runs.retain(|r| !(index.is_ancestor(&r.head, &run.head) && bottom <= r.bottom));
                runs.push(Run { top: run.top, head: run.head, bottom });
                trim(runs);
            }
        }
    }

    /// The runs of `author` that `member` is known to hold (highest first).
    pub fn held_runs(&self, member: &SignPk, author: &SignPk) -> Vec<Run> {
        let mut v = self.delivery.members.get(member).and_then(|m| m.get(author)).cloned().unwrap_or_default();
        v.sort_by_key(|r| std::cmp::Reverse(r.top));
        v
    }

    /// The members known to hold envelope `id`.
    pub fn holders(&self, id: &EnvelopeId) -> std::collections::BTreeSet<SignPk> {
        let (Some(author), Some(seq)) = (self.index.author(id), self.index.seq(id)) else { return Default::default() };
        self.delivery
            .members
            .iter()
            .filter(|(_, by_author)| {
                by_author.get(&author).is_some_and(|runs| {
                    runs.iter().any(|r| r.top >= seq && r.bottom <= seq && self.index.is_ancestor(id, &r.head))
                })
            })
            .map(|(m, _)| *m)
            .collect()
    }

    /// Our seen note, sealed, if read receipts are on and something changed
    /// since the last one (at most one per [`SEEN_INTERVAL_MS`]): the
    /// entries of up to [`SEEN_AUTHORS`] authors that changed. `None` when
    /// there is nothing new, it is too soon, or there is no epoch key.
    pub fn seen_note(&mut self) -> Option<Vec<u8>> {
        if self.delivery.my_at.is_some_and(|t| (t.elapsed().as_millis() as u64) < SEEN_INTERVAL_MS) {
            return None;
        }
        let all = self.index.entries();
        let changed: Vec<AuthorEntry> = all
            .values()
            .filter(|e| self.delivery.my_last.get(&e.author) != Some(*e))
            .take(SEEN_AUTHORS)
            .map(|e| AuthorEntry { author: e.author, runs: e.runs.iter().take(1).copied().collect(), truncated: None })
            .collect();
        if changed.is_empty() {
            return None;
        }
        let me = self.me.sign_pk();
        let seq = self.delivery.my_seq;
        let space = self.space_id();
        let sig = self.me.sign(CTX_SEEN, &[&signed_bytes(&space.0, &me, seq, &changed)]);
        let note = SeenNote { member: me, seq, entries: changed.clone(), sig };
        let plain = postcard::to_allocvec(&note).ok()?;
        let (epoch, nonce, ct) = self.seal_ephemeral(AAD_SEEN, &plain)?;
        let sealed = postcard::to_allocvec(&Sealed { epoch, nonce, ct }).ok()?;
        self.delivery.my_seq += 1;
        self.delivery.my_at = Some(std::time::Instant::now());
        for e in changed {
            if let Some(full) = all.get(&e.author) {
                self.delivery.my_last.insert(e.author, full.clone());
            }
        }
        Some(sealed)
    }

    /// A seen note received (from any member, who may be forwarding it):
    /// opened with the epoch key, checked (the signer is a current member,
    /// the signature holds, the seq is newer than the last we took from
    /// it, and not sooner than [`SEEN_INTERVAL_MS`] after it) and recorded.
    /// Returns the member it was from, or `None` if it was refused (then it
    /// is not forwarded either).
    pub fn accept_seen(&mut self, _from: &SignPk, sealed: &[u8]) -> Option<SignPk> {
        if sealed.len() > crate::reconcile::gossip::MAX_SEEN_NOTE {
            return None;
        }
        let Sealed { epoch, nonce, ct } = postcard::from_bytes(sealed).ok()?;
        let plain = self.open_ephemeral(&epoch, &nonce, AAD_SEEN, &ct)?;
        let note: SeenNote = postcard::from_bytes(&plain).ok()?;
        if note.entries.len() > SEEN_AUTHORS || note.member == self.me.sign_pk() || !self.is_member(&note.member) {
            return None;
        }
        if let Some((last, at)) = self.delivery.seen.get(&note.member)
            && (note.seq <= *last || (at.elapsed().as_millis() as u64) < SEEN_INTERVAL_MS / 2)
        {
            return None;
        }
        let space = self.space_id();
        note.member
            .verify(CTX_SEEN, &[&signed_bytes(&space.0, &note.member, note.seq, &note.entries)], &note.sig)
            .ok()?;
        self.delivery.seen.insert(note.member, (note.seq, std::time::Instant::now()));
        self.note_frontier(note.member, &note.entries);
        Some(note.member)
    }
}

#[cfg(test)]
impl Replica {
    /// Runs recorded in all (tests: memory follows runs, not envelopes).
    pub(crate) fn delivery_runs(&self) -> usize {
        self.delivery.members.values().flat_map(|m| m.values()).map(Vec::len).sum()
    }
}

/// Keep the highest runs.
fn trim(runs: &mut Vec<Run>) {
    if runs.len() > RUNS_PER_AUTHOR {
        runs.sort_by_key(|r| std::cmp::Reverse(r.top));
        runs.truncate(RUNS_PER_AUTHOR);
    }
}
