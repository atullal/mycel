//! Chunked files: attachments as trees of content-addressed nodes
//! (`mycel_crypto::chunked`, docs/TRUST.md §7c), held in one store for the
//! whole device and moved node by node.
//!
//! What that buys over a blob per conversation (`blobs.rs`, still served):
//!
//! - **Any holder can serve, every piece is checked.** A node is named by
//!   the hash of its ciphertext, so it can come from a member, a keeper or a
//!   device that only caches it, several at once, and a wrong piece is
//!   caught when it arrives (the source is dropped), not at the end.
//! - **One copy.** A file forwarded to another conversation, and a *public*
//!   file anyone sends, are the same nodes: stored once here, and already
//!   here when someone else offers them.
//! - **Files outlive their sender.** When a member can't be reached, the
//!   file is also handed to devices willing to hold it (keepers, contacts,
//!   devices nearby on a fast link), and the member finds them later
//!   ([`Holders`]). Holders keep what is asked for and let the rest go
//!   (`store.rs`).
//!
//! [`store`] is the disk side, `proto.rs` the wire and the serving side,
//! `transfer.rs` the asking side (fetching, pushing, replicating).

pub mod holders;
#[cfg(feature = "dht")]
pub mod holders_dht;
mod proto;
pub mod store;
#[cfg(test)]
mod tests;
mod transfer;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mycel_crypto::{Hash32, SignPk, SymKey};
use mycel_trust::SpaceId;
use parking_lot::Mutex;

pub use self::holders::{Holders, MemHolders};
#[cfg(feature = "dht")]
pub use self::holders_dht::DhtHolders;
pub(crate) use self::proto::serve;
pub use self::proto::{SERVE_RATE_ALL, SERVE_RATE_EACH};
pub use self::store::{CacheTier, ChunkStats, ChunkStore, DEFAULT_CACHE_BUDGET, Refused, SealSession, Tree};
pub use self::transfer::REPLICAS;
use crate::{Inner, Node, Progress};

/// Whose files this device holds for others, and how willingly.
pub type CachePolicy = Arc<dyn Fn(&SignPk) -> CacheTier + Send + Sync>;
/// Devices to ask to hold a file for a member who can't be reached, best first.
pub type ReplicaCandidates = Arc<dyn Fn() -> Vec<SignPk> + Send + Sync>;

/// How often a holder repeats that it holds a file (lookups forget).
const ANNOUNCE_EVERY: Duration = Duration::from_secs(30 * 60);

/// An accepted offer: what its sender may still push for it.
pub(crate) struct Intake {
    /// The conversation it is kept for; `None`: for the cache.
    pub(crate) space: Option<SpaceId>,
    pub(crate) left: u64,
    pub(crate) until: Instant,
}

/// A node's chunk state.
pub(crate) struct Chunks {
    pub(crate) store: Arc<ChunkStore>,
    policy: Mutex<Option<CachePolicy>>,
    holders: Mutex<Option<Arc<dyn Holders>>>,
    candidates: Mutex<Option<ReplicaCandidates>>,
    pub(crate) serve: Mutex<proto::ServeBudget>,
    pub(crate) intakes: Mutex<HashMap<(SignPk, Hash32), Intake>>,
    /// Node bytes served to other devices that asked ...
    pub(crate) served: AtomicU64,
    /// ... and pushed to devices that lacked them.
    pub(crate) pushed: AtomicU64,
}

impl Chunks {
    /// The chunk store under the blob directory (`<blobs>/.chunks`); `None`
    /// without blob storage, or if it can't be opened.
    pub(crate) fn open(blob_dir: Option<&Path>) -> Option<Chunks> {
        let dir = blob_dir?.join(".chunks");
        let store = match ChunkStore::open(&dir, DEFAULT_CACHE_BUDGET) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[mycel] file store unavailable: {e:#}");
                return None;
            }
        };
        store.autosave();
        Some(Chunks {
            store,
            policy: Mutex::default(),
            holders: Mutex::default(),
            candidates: Mutex::default(),
            serve: Mutex::new(proto::ServeBudget::new(SERVE_RATE_EACH, SERVE_RATE_ALL)),
            intakes: Mutex::default(),
            served: AtomicU64::new(0),
            pushed: AtomicU64::new(0),
        })
    }

    /// How willingly we hold files for `peer`: the app's answer, or by
    /// default as a contact if we share a conversation, a stranger if not.
    pub(crate) fn tier(&self, inner: &Inner, peer: &SignPk) -> CacheTier {
        // (the lock is not held while the app's answer runs)
        let policy = self.policy.lock().clone();
        if let Some(policy) = policy {
            return policy(peer);
        }
        if inner.spaces.lock().values().any(|r| r.is_member(peer)) { CacheTier::Contact } else { CacheTier::Stranger }
    }

    pub(crate) fn holders(&self) -> Option<Arc<dyn Holders>> {
        self.holders.lock().clone()
    }

    pub(crate) fn candidates(&self) -> Vec<SignPk> {
        let candidates = self.candidates.lock().clone();
        candidates.map(|f| f()).unwrap_or_default()
    }
}

/// Say (now, and again while we keep it) that we hold the file under `root`.
pub(crate) fn announce(inner: &Arc<Inner>, root: Hash32) {
    let Some(chunks) = &inner.chunks else { return };
    chunks.store.note_held(root);
    let Some(holders) = chunks.holders() else { return };
    let keys = inner.keys.clone();
    tokio::spawn(async move {
        let _ = holders.announce(root, keys).await;
    });
}

/// Repeat our announcements for as long as the node lives and still holds
/// the files whole.
async fn reannounce(inner: std::sync::Weak<Inner>) {
    loop {
        let Some(strong) = inner.upgrade() else { return };
        if let Some(chunks) = &strong.chunks
            && let Some(holders) = chunks.holders()
        {
            let store = chunks.store.clone();
            let held = tokio::task::spawn_blocking(move || store.held_complete()).await.unwrap_or_default();
            for root in held {
                let _ = holders.announce(root, strong.keys.clone()).await;
            }
        }
        drop(strong);
        tokio::time::sleep(ANNOUNCE_EVERY).await;
    }
}

impl Node {
    fn chunks(&self) -> Result<&Chunks> {
        self.inner.chunks.as_ref().context("file storage disabled")
    }

    /// The device's chunk store (`None` without blob storage): where a file
    /// is sealed into ([`ChunkStore::begin_seal`]) and opened from.
    pub fn chunk_store(&self) -> Option<Arc<ChunkStore>> {
        self.inner.chunks.as_ref().map(|c| c.store.clone())
    }

    /// Disk space donated to holding other people's files
    /// ([`DEFAULT_CACHE_BUDGET`] unless set; 0 holds nothing).
    pub fn set_cache_budget(&self, bytes: u64) {
        if let Some(c) = &self.inner.chunks {
            c.store.set_budget(bytes);
        }
    }

    /// Decide whose files this device holds for others (default: contacts
    /// are those we share a conversation with, everyone else a stranger).
    pub fn set_cache_policy(&self, policy: CachePolicy) {
        if let Some(c) = &self.inner.chunks {
            *c.policy.lock() = Some(policy);
        }
    }

    /// Where holders are announced and looked up. Without one, files are
    /// only found with members, keepers and devices in range.
    pub fn set_holders(&self, holders: Arc<dyn Holders>) {
        if let Some(c) = &self.inner.chunks
            && c.holders.lock().replace(holders).is_none()
        {
            tokio::spawn(reannounce(Arc::downgrade(&self.inner)));
        }
    }

    /// Devices to ask to hold a file when a member can't be reached (the
    /// app's contacts, best first). Devices nearby on a fast link are asked
    /// after them.
    pub fn set_replica_candidates(&self, candidates: ReplicaCandidates) {
        if let Some(c) = &self.inner.chunks {
            *c.candidates.lock() = Some(candidates);
        }
    }

    /// Node bytes this device has served to others.
    pub fn chunk_bytes_served(&self) -> u64 {
        self.inner.chunks.as_ref().map_or(0, |c| c.served.load(Ordering::Relaxed))
    }

    /// Node bytes this device has pushed to others (only what they lacked).
    pub fn chunk_bytes_pushed(&self) -> u64 {
        self.inner.chunks.as_ref().map_or(0, |c| c.pushed.load(Ordering::Relaxed))
    }

    /// Whether every node of the file under `root` is here.
    pub async fn file_complete(&self, root: Hash32) -> bool {
        let Some(store) = self.chunk_store() else { return false };
        tokio::task::spawn_blocking(move || store.tree(&root).complete()).await.unwrap_or(false)
    }

    /// A file sealed into the store ([`ChunkStore::begin_seal`]) now
    /// belongs to `space`: keep it, and send it on in the background by the
    /// push policy (keepers always, members if it is at most
    /// [`crate::EAGER_PUSH_MAX`]). If a member can't be reached and fewer
    /// than [`REPLICAS`] other devices hold the file, it is also offered to
    /// `replicas`, then to [`Node::set_replica_candidates`] and to devices
    /// nearby on a fast link, to hold until the member comes for it.
    pub async fn add_file(&self, space: SpaceId, root: Hash32, replicas: Vec<SignPk>) -> Result<()> {
        let store = self.chunks()?.store.clone();
        let complete = tokio::task::spawn_blocking(move || {
            store.pin(root, space);
            store.tree(&root).complete()
        })
        .await?;
        anyhow::ensure!(complete, "the file isn't whole in the store");
        self.with_space(&space, |_| ())?;
        tokio::spawn(transfer::distribute(Arc::downgrade(&self.inner), space, root, replicas));
        Ok(())
    }

    /// Get every node of the file under `root` into the store, kept for
    /// `space`: from the conversation's members at once, then from devices
    /// that say they hold it ([`Holders`]), the root's hints (read with
    /// `key`, if given) and devices in range. Picks up where an earlier
    /// attempt stopped. `size` is the plaintext size the message gives: a
    /// tree that lists more is refused. `progress` gets `(bytes here, bytes
    /// in all)` as stored.
    pub async fn fetch_file(
        &self,
        space: SpaceId,
        root: Hash32,
        size: u64,
        key: Option<SymKey>,
        progress: Progress,
    ) -> Result<()> {
        let me = self.id();
        let mut members: Vec<SignPk> = self
            .with_space(&space, |r| r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|p| *p != me).collect())
            .unwrap_or_default();
        let peers = self.peers();
        members.sort_by_key(|pk| !peers.get(pk).is_some_and(|p| p.online()));
        transfer::fetch(&self.inner, space, root, size, key, members, progress)
            .await
            .map_err(|e| e.context("couldn't download the file from anyone who has it"))
    }

    /// Offer the whole file to `peer`: for `space` (a conversation we share
    /// with it: it keeps the file), or with `None` for its cache. Only what
    /// it lacks is sent.
    pub async fn push_file(&self, peer: SignPk, space: Option<SpaceId>, root: Hash32) -> Result<()> {
        self.chunks()?;
        transfer::push(&self.inner, peer, space, root, false).await
    }

    /// Say that this device holds the file under `root`, so anyone with its
    /// reference can find it here ([`Node::set_holders`]). Holders for
    /// others do this themselves; an app calls it for files it wants found
    /// (public ones).
    pub fn announce_file(&self, root: Hash32) {
        announce(&self.inner, root);
    }
}
