//! What this device keeps secret about a space, and when it replaces it
//! (docs/TRUST.md §6, "Forward secrecy").
//!
//! - **Reader keys.** Lockboxes used to be sealed to a key derived from the
//!   device's seed, so the seed alone opened every epoch a keeper holds.
//!   A replica with a [`KeyPolicy`] publishes random *reader keys* in the
//!   space instead, a new one every [`KeyPolicy::reader_period`], keeps a
//!   replaced one for [`KeyPolicy::reader_retention`] (someone who hasn't
//!   heard of the new one still seals to it), then deletes it.
//! - **The keyring is stored**, sealed under a key derived from the seed,
//!   with the reader keys. A lockbox can't be opened again once its reader
//!   key is gone, so the epoch keys can no longer be re-derived at every
//!   start; and what is stored is useless without the seed.
//! - **Timed rotation.** A writer moves to a new epoch once the current one
//!   is [`KeyPolicy::epoch_period`] old, so each reader key covers a bounded
//!   stretch of content. Every clock here is this device's own.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mycel_crypto::{Hash32, KexSecret, SymKey, Zeroizing};
use mycel_trust::{EpochId, Role, SignedOp};
use serde::{Deserialize, Serialize};

use crate::Replica;

/// Purpose label of the storage key these secrets are sealed under.
const PURPOSE: &str = "space-secrets";
/// First byte of the sealed record's plaintext.
const VERSION: u8 = 1;
/// A gap this long between two looks at the clock means the device wasn't
/// running: that time doesn't count toward deleting a replaced reader key,
/// because nothing sealed to it could arrive meanwhile.
const DOWNTIME: u64 = 6 * 3600;
/// The stored record follows the clock at most this often when nothing
/// else changed.
const ALIVE_SAVE_EVERY: u64 = 3600;
/// At most one "I lost my earlier keys" reader key per this long, however
/// often the write epoch turns out closed to us.
const LOST_GAP: u64 = 3600;

/// Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn wall_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// When this device replaces its keys in a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    /// How long a reader key is the one others seal to before this device
    /// publishes the next. Zero: publish none (lockboxes stay sealed to the
    /// kex key derived from the seed).
    pub reader_period: Duration,
    /// How long a replaced reader key is kept, counted while this device is
    /// running, before it is deleted.
    pub reader_retention: Duration,
    /// A writer rotates the epoch on its next write once it has held the
    /// current epoch's key this long (plus a jitter of up to a quarter, so
    /// writers don't all rotate at once). Zero: only on membership changes.
    pub epoch_period: Duration,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        KeyPolicy {
            reader_period: Duration::from_secs(7 * 24 * 3600),
            reader_retention: Duration::from_secs(30 * 24 * 3600),
            epoch_period: Duration::from_secs(24 * 3600),
        }
    }
}

struct Reader {
    secret: KexSecret,
    /// When this device made it.
    created: u64,
    /// When it stopped being the key in the graph (running time, see
    /// [`DOWNTIME`]); `None` while it is.
    superseded: Option<u64>,
}

/// One replica's secrets and their bookkeeping.
pub(crate) struct KeyState {
    policy: Option<KeyPolicy>,
    clock: Clock,
    /// Reader keys this device holds, oldest first.
    readers: Vec<Reader>,
    /// When this device first held each epoch's key.
    seen: HashMap<EpochId, u64>,
    /// The clock at the last upkeep.
    last_alive: u64,
    /// `last_alive` in the stored record.
    saved_alive: u64,
    /// When this device last published a reader key saying it lost the
    /// earlier ones.
    last_lost: u64,
}

impl Default for KeyState {
    fn default() -> Self {
        KeyState {
            policy: None,
            clock: Arc::new(wall_clock),
            readers: Vec::new(),
            seen: HashMap::new(),
            last_alive: 0,
            saved_alive: 0,
            last_lost: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredReader {
    seed: [u8; 32],
    created: u64,
    superseded: Option<u64>,
}

/// The sealed record: everything needed to read the space after a restart
/// that the seed and the membership ops no longer give.
#[derive(Serialize, Deserialize)]
struct Stored {
    readers: Vec<StoredReader>,
    /// (epoch, its key, when this device first held it)
    ring: Vec<(EpochId, SymKey, u64)>,
    last_alive: u64,
}

impl Drop for Stored {
    fn drop(&mut self) {
        for r in &mut self.readers {
            r.seed.fill(0);
        }
    }
}

impl Replica {
    /// Start (or stop, with `None`) replacing this device's keys in this
    /// space on a schedule. Off until set: a replica that was only handed a
    /// space (an invitation not yet accepted) publishes nothing. Returns
    /// the reader-key op this authored, if any: pass it on like any other.
    pub fn set_key_policy(&mut self, policy: Option<KeyPolicy>) -> Option<SignedOp> {
        self.keys.policy = policy;
        self.key_upkeep()
    }

    pub fn key_policy(&self) -> Option<KeyPolicy> {
        self.keys.policy
    }

    /// Replace the clock (Unix seconds) the key schedule reads: for tests
    /// and simulators.
    pub fn set_key_clock(&mut self, clock: Clock) {
        self.keys.clock = clock;
    }

    /// How many reader keys this device holds for the space: the current
    /// one and the replaced ones it hasn't deleted yet.
    pub fn reader_keys_held(&self) -> usize {
        self.keys.readers.len()
    }

    #[cfg(test)]
    pub(crate) fn reader_seeds_for_test(&self) -> Vec<[u8; 32]> {
        self.keys.readers.iter().map(|r| r.secret.seed()).collect()
    }

    /// Open what the graph now holds for us, with the reader keys we keep.
    pub(crate) fn unlock(&mut self) -> usize {
        let readers: Vec<KexSecret> = self.keys.readers.iter().map(|r| r.secret.clone()).collect();
        let added = self.graph.unlock_with(&self.me, &readers, &mut self.ring);
        self.note_epoch_keys();
        added
    }

    /// An epoch key we made ourselves. (If its op isn't in the graph yet,
    /// it is noted and stored when that arrives: [`Replica::unlock`].)
    pub(crate) fn hold_epoch_key(&mut self, epoch: EpochId, key: SymKey) {
        self.ring.insert(epoch, key);
        self.note_epoch_keys();
    }

    /// Note when we first held each of the graph's epoch keys, and store
    /// the keyring if it gained one.
    fn note_epoch_keys(&mut self) {
        let now = (self.keys.clock)();
        let mut gained = false;
        for e in &self.graph.state().epochs {
            if self.ring.get(&e.id).is_some() && !self.keys.seen.contains_key(&e.id) {
                self.keys.seen.insert(e.id, now);
                gained = true;
            }
        }
        if gained {
            // Not awaited on: if this write is lost, the lockbox is opened
            // again at the next start, with a reader key that is still
            // there (it outlives the write by `reader_retention`).
            let _ = self.save_secrets(false);
        }
    }

    /// Bring back what [`Replica::sealed_secrets`] stored. A record that
    /// doesn't open (another device's, a damaged one) is ignored: the
    /// replica then holds only what its seed opens, and says so with its
    /// next reader key.
    pub(crate) fn load_secrets(&mut self, sealed: &[u8]) {
        let Ok(plain) = self.me.open_stored(PURPOSE, &self.space_id().0, sealed).map(Zeroizing::new) else {
            return;
        };
        let Some((&VERSION, body)) = plain.split_first() else { return };
        let Ok(mut stored) = postcard::from_bytes::<Stored>(body) else { return };
        for r in &stored.readers {
            self.keys.readers.push(Reader {
                secret: KexSecret::from_seed(&r.seed),
                created: r.created,
                superseded: r.superseded,
            });
        }
        for (epoch, key, seen) in std::mem::take(&mut stored.ring) {
            self.ring.insert(epoch, key);
            self.keys.seen.insert(epoch, seen);
        }
        self.keys.last_alive = stored.last_alive;
        self.keys.saved_alive = stored.last_alive;
    }

    /// This device's secrets for the space, sealed under a key derived from
    /// its seed and bound to the space: what the store keeps.
    pub fn sealed_secrets(&self) -> crate::Result<Vec<u8>> {
        let stored = Stored {
            readers: self
                .keys
                .readers
                .iter()
                .map(|r| StoredReader { seed: r.secret.seed(), created: r.created, superseded: r.superseded })
                .collect(),
            ring: self
                .graph
                .state()
                .epochs
                .iter()
                .filter_map(|e| {
                    let key = self.ring.get(&e.id)?.clone();
                    Some((e.id, key, self.keys.seen.get(&e.id).copied().unwrap_or(self.keys.last_alive)))
                })
                .collect(),
            last_alive: self.keys.last_alive,
        };
        let mut plain = Zeroizing::new(vec![VERSION]);
        plain.extend_from_slice(
            &postcard::to_allocvec(&stored).map(Zeroizing::new).map_err(|_| crate::SyncError::Encoding)?,
        );
        Ok(self.me.seal_stored(PURPOSE, &self.space_id().0, &plain)?)
    }

    /// Store the secrets. `durable`: don't return before they are safe.
    pub(crate) fn save_secrets(&mut self, durable: bool) -> std::result::Result<(), String> {
        // (none while restoring, and none for a replica kept in memory)
        let Some(store) = self.store.clone() else { return Ok(()) };
        let sealed = self.sealed_secrets().map_err(|e| e.to_string())?;
        store.put_secrets(&self.space_id(), sealed, durable)?;
        self.keys.saved_alive = self.keys.last_alive;
        Ok(())
    }

    /// Keep this device's reader keys in order: count running time, delete
    /// the replaced keys that have been kept long enough, and publish a new
    /// one when it has none in the space, when the current one is old, or
    /// when it can no longer open what the others seal to. Cheap when there
    /// is nothing to do; call it now and then, and it runs on its own
    /// whenever membership ops arrive and before every write.
    ///
    /// Returns the op it authored, if any (already in the graph and stored).
    pub fn key_upkeep(&mut self) -> Option<SignedOp> {
        let policy = self.keys.policy?;
        let now = (self.keys.clock)();
        let mut changed = false;

        // Time this device wasn't running doesn't age its replaced keys.
        let k = &mut self.keys;
        if k.last_alive == 0 {
            k.last_alive = now;
        }
        if now > k.last_alive.saturating_add(DOWNTIME) {
            let gap = now - k.last_alive;
            for r in &mut k.readers {
                if let Some(t) = &mut r.superseded {
                    *t = t.saturating_add(gap);
                    changed = true;
                }
            }
        }
        // (a clock that went back just makes the keys wait longer)
        k.last_alive = now;
        let retention = policy.reader_retention.as_secs();
        let held = k.readers.len();
        // (kept: the current one, and the replaced ones still inside the retention)
        k.readers.retain(|r| r.superseded.is_none_or(|t| now < t.saturating_add(retention)));
        changed |= k.readers.len() != held;

        let me = self.me.sign_pk();
        let reads = self.my_role().is_some_and(Role::can_read);
        let in_graph = self.graph.state().members.get(&me).and_then(|m| m.reader.clone());
        let current =
            in_graph.as_ref().and_then(|r| self.keys.readers.iter().position(|h| h.secret.public() == &r.key));
        // Whatever isn't the graph's key for us has been replaced.
        for (i, r) in self.keys.readers.iter_mut().enumerate() {
            if Some(i) != current && r.superseded.is_none() {
                r.superseded = Some(now);
                changed = true;
            }
        }
        let period = policy.reader_period.as_secs();
        // (publish?, having lost the earlier keys?)
        let (publish, lost) = if !reads || period == 0 {
            (false, false)
        } else {
            match (&in_graph, current) {
                // none in this space yet
                (None, _) => (true, false),
                // the graph's key for us isn't one we hold: our storage was
                // lost or rolled back
                (Some(_), None) => (true, true),
                (Some(r), Some(i)) => {
                    if self.write_epoch_is_closed_to_me(r.lost_before) {
                        (now >= self.keys.last_lost.saturating_add(LOST_GAP), true)
                    } else {
                        (now >= self.keys.readers[i].created.saturating_add(period), false)
                    }
                }
            }
        };
        let mut authored = None;
        if publish {
            authored = self.publish_reader_key(current, lost, now);
            // (stored, durably, by that)
            changed &= authored.is_none();
        }
        if changed || now >= self.keys.saved_alive.saturating_add(ALIVE_SAVE_EVERY) {
            let _ = self.save_secrets(false);
        }
        authored
    }

    /// Make a reader key, store it, then publish it. In that order: once
    /// the op is out, others seal to the key, and a private half that never
    /// reached the disk would be lost with the next crash.
    fn publish_reader_key(&mut self, replaced: Option<usize>, lost: bool, now: u64) -> Option<SignedOp> {
        let secret = KexSecret::generate();
        let public = secret.public().clone();
        let op = self.graph.publish_reader_key(&self.me, public, lost).ok()?;
        let was = replaced.map(|i| self.keys.readers[i].superseded);
        if let Some(i) = replaced {
            self.keys.readers[i].superseded.get_or_insert(now);
        }
        self.keys.readers.push(Reader { secret, created: now, superseded: None });
        if self.save_secrets(true).is_err() {
            // Not stored: not published. Try again at the next upkeep.
            self.keys.readers.pop();
            if let (Some(i), Some(was)) = (replaced, was) {
                self.keys.readers[i].superseded = was;
            }
            return None;
        }
        if lost {
            self.keys.last_lost = now;
        }
        // A reader key changes nobody's role and no epoch: no envelope's
        // validity depends on it, so nothing is re-derived.
        if self.graph.insert(op.clone()).is_err() {
            return None;
        }
        self.persist_op(&op);
        Some(op)
    }

    /// We are a recipient of the write epoch and can't open it, and the
    /// graph doesn't already say so (`lost_before`: our latest op that
    /// declared our earlier keys gone).
    fn write_epoch_is_closed_to_me(&self, lost_before: Option<mycel_trust::OpId>) -> bool {
        let st = self.graph.state();
        let Some(e) = st.write_epoch().and_then(|id| st.epoch(&id)) else { return false };
        if self.ring.get(&e.id).is_some() || !e.recipients.contains(&self.me.sign_pk()) {
            return false;
        }
        // If we declared our keys lost after this epoch was sealed, writers
        // will move on from it without another word from us. Otherwise
        // (nothing declared, or its author had seen it) it is news.
        lost_before.is_none_or(|lost| self.graph.in_past(&lost, &[e.created_by]))
    }

    /// Should a writer leave `epoch` for a new one although it could still
    /// write under it? When it is old ([`KeyPolicy::epoch_period`]), or
    /// when a reader said it lost the key this epoch was sealed to.
    pub(crate) fn should_rotate(&self, epoch: &EpochId) -> bool {
        let Some(policy) = self.keys.policy else { return false };
        if self.graph.epoch_closed_to_a_reader(epoch) {
            return true;
        }
        let period = policy.epoch_period.as_secs();
        if period == 0 {
            return false;
        }
        let Some(seen) = self.keys.seen.get(epoch) else { return false };
        let jitter = rotation_jitter(&self.me.sign_pk(), epoch, period);
        (self.keys.clock)() >= seen.saturating_add(period).saturating_add(jitter)
    }
}

/// How much longer than `period` this device waits before leaving `epoch`:
/// up to a quarter of it, a different amount for each device and epoch, so
/// the first one due rotates and the rest find a fresh epoch.
pub(crate) fn rotation_jitter(me: &mycel_crypto::SignPk, epoch: &EpochId, period: u64) -> u64 {
    let mut input = me.0.to_vec();
    input.extend_from_slice(&epoch.0);
    let hash = Hash32::digest("mycel/v1/rotation-jitter", &input);
    u64::from_le_bytes(hash.0[..8].try_into().expect("8 bytes")) % (period / 4 + 1)
}
