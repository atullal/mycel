//! The chunk store: one content-addressed pool of file nodes for the whole
//! device, shared by every conversation (a node referenced twice is stored
//! once).
//!
//! A node is either **pinned** or **cached**:
//!
//! - Pinned nodes belong to a file some conversation of this device refers
//!   to (or that a keeper was asked to hold). They are never evicted while
//!   that reference stands, and they count against no budget (the free-disk
//!   floor still applies to every transfer).
//! - Cached nodes are held for others, inside a budget the user donates
//!   ([`DEFAULT_CACHE_BUDGET`] unless set). When room is needed the least
//!   requested go first; requests age (a score halves every
//!   [`HALF_LIFE`] seconds), so what many devices keep asking for stays and
//!   what nobody asks for fades. Nothing is dropped for its age alone.
//!
//! Which nodes a pinned file consists of is read from its index nodes,
//! which list their children in the clear (`mycel_crypto::chunked`): no key
//! is needed, so keepers and caches can do it too.
//!
//! Everything stored was checked against its id first, so a holder can't be
//! made to keep (or serve) bytes under the wrong name.
//!
//! Layout: `<dir>/<first byte, hex>/<id, hex>`; `<dir>/meta` holds the pins
//! and the cache's request counts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mycel_crypto::chunked::{self, Index, MAX_NODE};
use mycel_crypto::{Hash32, SignPk};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Disk space donated to holding other people's files, unless the user
/// chooses otherwise ([`ChunkStore::set_budget`]).
pub const DEFAULT_CACHE_BUDGET: u64 = 1024 * 1024 * 1024;
/// A cached node's request count halves every week it isn't asked for.
pub const HALF_LIFE: u64 = 7 * 24 * 3600;
/// Devices we don't know may fill this fraction of the cache together ...
const STRANGER_SHARE: u64 = 4;
/// ... and each of them this fraction.
const STRANGER_EACH: u64 = 16;
/// One device asking again and again counts once in this long (seconds).
const REPEAT_GAP: u64 = 3600;
/// Room promised to a device that offered a file is kept this long between
/// its pieces.
const RESERVATION_TTL: Duration = Duration::from_secs(10 * 60);
/// What a contact's file starts with: it outranks anything nobody has asked
/// for lately, and yields to what several devices have.
const CONTACT_SCORE: f32 = 1.0;
/// The cache's counts are written out at most this often.
const SAVE_EVERY: Duration = Duration::from_secs(60);

/// Whose pieces a device is willing to hold for others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CacheTier {
    /// Nothing from this device.
    Refuse,
    /// A device we don't know: only into free room, within a small share.
    Stranger,
    /// A contact: may displace what nobody has asked for lately.
    Contact,
}

/// Why a node was not stored.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The bytes are not what the id names.
    Mismatch,
    /// No room within the donated budget (or this device's share of it).
    NoRoom,
    /// Storing it would leave too little free disk space.
    DiskFull,
    /// This device takes nothing from that one.
    Denied,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::Mismatch => "file piece doesn't match its id (corrupt or wrong data)",
            Refused::NoRoom => "no room left for other people's files",
            Refused::DiskFull => "not enough free disk space",
            Refused::Denied => "not accepted from this device",
        })
    }
}

impl std::error::Error for Refused {}

/// Where a node to store comes from.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// This device made or asked for it.
    Own,
    /// Another device pushed it, for the file `root`.
    Peer { peer: SignPk, tier: CacheTier, root: Hash32 },
}

#[derive(Clone, Debug)]
struct Cached {
    size: u32,
    /// Requests by other devices, decayed to `stamp`.
    hits: f32,
    /// Unix seconds of the last update of `hits`.
    stamp: u64,
    /// First bytes of the key of the last device that asked.
    last_peer: [u8; 8],
    /// The stranger that pushed it (its share is charged), if one did.
    stranger: Option<SignPk>,
}

impl Cached {
    fn score(&self, now: u64) -> f32 {
        let age = now.saturating_sub(self.stamp) as f32;
        self.hits * 0.5f32.powf(age / HALF_LIFE as f32)
    }
}

struct Reservation {
    left: u64,
    until: Instant,
}

#[derive(Default)]
struct State {
    budget: u64,
    cache: HashMap<Hash32, Cached>,
    cache_bytes: u64,
    stranger_bytes: u64,
    by_stranger: HashMap<SignPk, u64>,
    /// Pinned files: root → who wants each kept (a space id, or a tag).
    roots: BTreeMap<Hash32, BTreeSet<Hash32>>,
    /// Every node listed under a pinned root (present here or not yet),
    /// and whether it is listed as an index.
    pinned: HashMap<Hash32, bool>,
    /// Nodes of a file being sealed: protected until it is pinned.
    holds: HashMap<Hash32, u32>,
    /// Room promised to (device, file) offers.
    reserved: HashMap<(SignPk, Hash32), Reservation>,
    /// Files we took in whole to hold for others: what we say we hold.
    held: BTreeSet<Hash32>,
    dirty: bool,
}

impl State {
    fn protected(&self, id: &Hash32) -> bool {
        self.pinned.contains_key(id) || self.holds.contains_key(id)
    }

    fn reserved_for_others(&mut self, mine: Option<&(SignPk, Hash32)>, now: Instant) -> u64 {
        self.reserved.retain(|_, r| r.until > now);
        self.reserved.iter().filter(|(k, _)| Some(*k) != mine).map(|(_, r)| r.left).sum()
    }

    fn uncache(&mut self, id: &Hash32) -> Option<Cached> {
        let c = self.cache.remove(id)?;
        self.cache_bytes -= c.size as u64;
        if let Some(s) = c.stranger {
            self.stranger_bytes -= c.size as u64;
            if let Some(b) = self.by_stranger.get_mut(&s) {
                *b = b.saturating_sub(c.size as u64);
                if *b == 0 {
                    self.by_stranger.remove(&s);
                }
            }
        }
        self.dirty = true;
        Some(c)
    }

    fn encache(&mut self, id: Hash32, c: Cached) {
        self.cache_bytes += c.size as u64;
        if let Some(s) = c.stranger {
            self.stranger_bytes += c.size as u64;
            *self.by_stranger.entry(s).or_default() += c.size as u64;
        }
        self.cache.insert(id, c);
        self.dirty = true;
    }

    /// Cached nodes to drop so that `need` more bytes fit beside what is
    /// promised to others: the least requested first, the longest unasked
    /// among equals, and none scoring `below` or more. `None`: they don't fit.
    fn make_room(&mut self, need: u64, below: f32, mine: Option<&(SignPk, Hash32)>, now: u64) -> Option<Vec<Hash32>> {
        if need > self.budget {
            return None;
        }
        let taken = self.cache_bytes + self.reserved_for_others(mine, Instant::now());
        let deficit = (taken + need).saturating_sub(self.budget);
        if deficit == 0 {
            return Some(Vec::new());
        }
        let victims = self.least_wanted(deficit, below, now)?;
        for v in &victims {
            self.uncache(v);
        }
        Some(victims)
    }

    /// The least requested cached nodes adding up to `bytes`, none scoring
    /// `below` or more; `None` if those don't add up to it.
    fn least_wanted(&self, bytes: u64, below: f32, now: u64) -> Option<Vec<Hash32>> {
        let mut order: Vec<(f32, u64, Hash32, u32)> =
            self.cache.iter().map(|(id, c)| (c.score(now), c.stamp, *id, c.size)).filter(|c| c.0 < below).collect();
        order.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        let mut freed = 0;
        let mut victims = Vec::new();
        for (_, _, id, size) in order {
            if freed >= bytes {
                break;
            }
            freed += size as u64;
            victims.push(id);
        }
        (freed >= bytes).then_some(victims)
    }

    /// Bring the cache back inside its budget (it shrank, or nodes joined
    /// it without asking): the least requested go.
    fn shrink(&mut self, now: u64) -> Vec<Hash32> {
        let over = self.cache_bytes.saturating_sub(self.budget);
        let victims =
            self.least_wanted(over, f32::INFINITY, now).unwrap_or_else(|| self.cache.keys().copied().collect());
        for v in &victims {
            self.uncache(v);
        }
        victims
    }
}

#[derive(Serialize, Deserialize)]
struct MetaEntry {
    id: Hash32,
    hits: f32,
    stamp: u64,
    last_peer: [u8; 8],
    stranger: Option<SignPk>,
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    roots: Vec<(Hash32, Vec<Hash32>)>,
    cache: Vec<MetaEntry>,
    held: Vec<Hash32>,
}

/// What a file's index nodes say it consists of, as far as they are here.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    /// Every distinct node, parents before children: `(id, length, is an index)`.
    pub nodes: Vec<(Hash32, u32, bool)>,
    /// Index nodes listed but not here: what is under them is unknown.
    pub unknown: usize,
    /// Listed nodes that are not here (including the unknown indexes).
    pub missing: usize,
}

impl Tree {
    /// Every node of the file is here.
    pub fn complete(&self) -> bool {
        self.missing == 0 && !self.nodes.is_empty()
    }

    /// Bytes of the distinct nodes known, as stored.
    pub fn total(&self) -> u64 {
        self.nodes.iter().map(|(_, len, _)| *len as u64).sum()
    }
}

/// How full the store is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChunkStats {
    pub cache_bytes: u64,
    pub cache_nodes: usize,
    pub budget: u64,
    pub pinned_files: usize,
    pub pinned_nodes: usize,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn peer_tag(peer: &SignPk) -> [u8; 8] {
    peer.0[..8].try_into().expect("8 bytes")
}

pub struct ChunkStore {
    dir: PathBuf,
    st: Mutex<State>,
}

impl std::fmt::Debug for ChunkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkStore({})", self.dir.display())
    }
}

impl ChunkStore {
    /// Open (or create) the store in `dir`: reads the pins and counts, and
    /// looks at what is on disk.
    pub fn open(dir: &Path, budget: u64) -> Result<Arc<Self>> {
        std::fs::create_dir_all(dir).with_context(|| format!("can't create {}", dir.display()))?;
        let meta: Meta =
            std::fs::read(dir.join("meta")).ok().and_then(|b| postcard::from_bytes(&b).ok()).unwrap_or_default();
        let store =
            Arc::new(ChunkStore { dir: dir.to_path_buf(), st: Mutex::new(State { budget, ..State::default() }) });
        {
            let mut st = store.st.lock();
            for (root, owners) in meta.roots {
                st.roots.insert(root, owners.into_iter().collect());
            }
            st.held = meta.held.into_iter().collect();
        }
        let roots: Vec<Hash32> = store.st.lock().roots.keys().copied().collect();
        let pinned = store.reachable(roots.iter().map(|r| (*r, true)).collect());
        let known: HashMap<Hash32, MetaEntry> = meta.cache.into_iter().map(|e| (e.id, e)).collect();
        let now = unix_now();
        let mut st = store.st.lock();
        st.pinned = pinned;
        for (id, size) in store.scan()? {
            if st.pinned.contains_key(&id) {
                continue;
            }
            let c = match known.get(&id) {
                Some(e) => Cached { size, hits: e.hits, stamp: e.stamp, last_peer: e.last_peer, stranger: e.stranger },
                None => Cached { size, hits: 0.0, stamp: now, last_peer: [0; 8], stranger: None },
            };
            st.encache(id, c);
        }
        st.dirty = false;
        let over = st.shrink(now);
        drop(st);
        store.delete(&over);
        Ok(store)
    }

    /// Keep the cache's counts on disk while the store lives (needs a Tokio
    /// runtime). They are also written when it is dropped.
    pub fn autosave(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SAVE_EVERY).await;
                let Some(store) = weak.upgrade() else { return };
                let _ = tokio::task::spawn_blocking(move || store.save_if_dirty()).await;
            }
        });
    }

    fn scan(&self) -> Result<Vec<(Hash32, u32)>> {
        let mut out = Vec::new();
        for sub in std::fs::read_dir(&self.dir)? {
            let sub = sub?;
            if !sub.file_type()?.is_dir() {
                continue;
            }
            for f in std::fs::read_dir(sub.path())? {
                let f = f?;
                let name = f.file_name();
                let name = name.to_string_lossy();
                let id = (name.len() == 64).then(|| hex32(&name)).flatten();
                match (id, f.metadata()) {
                    (Some(id), Ok(m)) if m.is_file() && m.len() <= MAX_NODE as u64 => out.push((id, m.len() as u32)),
                    // a write that never finished, or not ours
                    _ => {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
        }
        Ok(out)
    }

    /// Where the store lives.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, id: &Hash32) -> PathBuf {
        let name = id.to_string();
        self.dir.join(&name[..2]).join(name)
    }

    /// Whether the node is here (whole: nodes appear by rename).
    pub fn has(&self, id: &Hash32) -> bool {
        self.path(id).is_file()
    }

    /// The node's length as stored, if it is here.
    pub fn len_of(&self, id: &Hash32) -> Option<u32> {
        std::fs::metadata(self.path(id)).ok().filter(|m| m.is_file()).map(|m| m.len() as u32)
    }

    /// The node's bytes.
    pub fn read(&self, id: &Hash32) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(id))
    }

    /// The node's bytes, checked against its id again: disks fail, and a
    /// crash can leave a file that was renamed before its data was written.
    /// A node that no longer matches is dropped, so it is fetched afresh.
    pub fn read_verified(&self, id: &Hash32) -> std::io::Result<Vec<u8>> {
        let bytes = self.read(id)?;
        if chunked::node_id(&bytes) != *id {
            self.st.lock().uncache(id);
            let _ = std::fs::remove_file(self.path(id));
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "stored file piece was corrupt"));
        }
        Ok(bytes)
    }

    fn delete(&self, ids: &[Hash32]) {
        for id in ids {
            let _ = std::fs::remove_file(self.path(id));
        }
    }

    /// Everything listed under `start` (`(id, is an index)`), following the
    /// index nodes that are here: each id, and whether it is listed as an index.
    fn reachable(&self, start: Vec<(Hash32, bool)>) -> HashMap<Hash32, bool> {
        let mut seen: HashMap<Hash32, bool> = HashMap::new();
        let mut todo = start;
        while let Some((id, is_index)) = todo.pop() {
            match seen.get(&id) {
                Some(true) => continue,
                Some(false) if !is_index => continue,
                _ => {}
            }
            seen.insert(id, is_index);
            if !is_index {
                continue;
            }
            let Ok(bytes) = self.read(&id) else { continue };
            let Ok(index) = Index::parse(&bytes) else { continue };
            todo.extend(index.children.iter().map(|(c, _)| (*c, index.level > 1)));
        }
        seen
    }

    /// What the file under `root` consists of, as far as its index nodes
    /// here say. Reads no keys.
    pub fn tree(&self, root: &Hash32) -> Tree {
        let mut tree = Tree::default();
        let mut seen = HashSet::new();
        let mut todo = std::collections::VecDeque::from([(*root, 0u32, true)]);
        while let Some((id, listed_len, is_index)) = todo.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if !is_index {
                if self.len_of(&id) != Some(listed_len) {
                    tree.missing += 1;
                }
                tree.nodes.push((id, listed_len, false));
                continue;
            }
            let index = self.read(&id).ok().filter(|b| listed_len == 0 || b.len() == listed_len as usize);
            let Some(bytes) = index else {
                tree.unknown += 1;
                tree.missing += 1;
                tree.nodes.push((id, listed_len, true));
                continue;
            };
            let Ok(index) = Index::parse(&bytes) else {
                tree.unknown += 1;
                tree.missing += 1;
                continue;
            };
            tree.nodes.push((id, bytes.len() as u32, true));
            todo.extend(index.children.iter().map(|(c, len)| (*c, *len, index.level > 1)));
        }
        tree
    }

    /// Keep the file under `root` for `owner` (a space id, or any tag):
    /// its nodes, those here and those still to come, are never evicted
    /// while any owner keeps it.
    pub fn pin(&self, root: Hash32, owner: Hash32) {
        let new = {
            let mut st = self.st.lock();
            let owners = st.roots.entry(root).or_default();
            let fresh = owners.is_empty();
            owners.insert(owner) && fresh
        };
        if new {
            self.adopt(vec![(root, true)]);
        }
        self.save_roots();
    }

    /// Mark everything listed under `start` as pinned.
    fn adopt(&self, start: Vec<(Hash32, bool)>) {
        let ids = self.reachable(start);
        let mut st = self.st.lock();
        for (id, is_index) in ids {
            st.uncache(&id);
            *st.pinned.entry(id).or_default() |= is_index;
        }
    }

    /// `owner` no longer needs the file. Once nobody does, its nodes are
    /// held like anyone else's: inside the budget, by how often they're asked for.
    pub fn unpin(&self, root: &Hash32, owner: &Hash32) {
        let gone = {
            let mut st = self.st.lock();
            let Some(owners) = st.roots.get_mut(root) else { return };
            owners.remove(owner);
            let gone = owners.is_empty();
            if gone {
                st.roots.remove(root);
            }
            gone
        };
        if gone {
            self.rebuild_pinned();
        }
        self.save_roots();
    }

    /// Drop every pin `owner` holds (it left the conversation).
    pub fn unpin_owner(&self, owner: &Hash32) {
        let changed = {
            let mut st = self.st.lock();
            let before = st.roots.len();
            st.roots.retain(|_, owners| {
                owners.remove(owner);
                !owners.is_empty()
            });
            st.roots.len() != before
        };
        if changed {
            self.rebuild_pinned();
            self.save_roots();
        }
    }

    fn rebuild_pinned(&self) {
        let roots: Vec<(Hash32, bool)> = self.st.lock().roots.keys().map(|r| (*r, true)).collect();
        let pinned = self.reachable(roots);
        let released: Vec<Hash32> = {
            let mut st = self.st.lock();
            let old = std::mem::replace(&mut st.pinned, pinned);
            old.into_keys().filter(|id| !st.pinned.contains_key(id)).collect()
        };
        self.release(&released);
    }

    /// Nodes that were protected and no longer are: cached from now on.
    fn release(&self, ids: &[Hash32]) {
        let now = unix_now();
        let sizes: Vec<(Hash32, u32)> = ids.iter().filter_map(|id| Some((*id, self.len_of(id)?))).collect();
        let over = {
            let mut st = self.st.lock();
            for (id, size) in sizes {
                if !st.protected(&id) && !st.cache.contains_key(&id) {
                    st.encache(id, Cached { size, hits: 0.0, stamp: now, last_peer: [0; 8], stranger: None });
                }
            }
            st.shrink(now)
        };
        self.delete(&over);
    }

    /// Whether the node belongs to a pinned file (or one being sealed).
    pub fn is_protected(&self, id: &Hash32) -> bool {
        self.st.lock().protected(id)
    }

    /// Who has the file pinned.
    pub fn owners(&self, root: &Hash32) -> Vec<Hash32> {
        self.st.lock().roots.get(root).map(|o| o.iter().copied().collect()).unwrap_or_default()
    }

    /// We took the file under `root` in whole, to hold for others.
    pub fn note_held(&self, root: Hash32) {
        let mut st = self.st.lock();
        st.dirty |= st.held.insert(root);
    }

    /// The files we hold for others that are still whole here (those that
    /// lost a node to eviction are forgotten).
    pub fn held_complete(&self) -> Vec<Hash32> {
        let held: Vec<Hash32> = self.st.lock().held.iter().copied().collect();
        let (whole, gone): (Vec<Hash32>, Vec<Hash32>) = held.into_iter().partition(|r| self.tree(r).complete());
        if !gone.is_empty() {
            let mut st = self.st.lock();
            for r in &gone {
                st.held.remove(r);
            }
            st.dirty = true;
        }
        whole
    }

    /// Whether `owner` (or anyone, with `None`) has the file pinned.
    pub fn is_pinned(&self, root: &Hash32, owner: Option<&Hash32>) -> bool {
        self.st.lock().roots.get(root).is_some_and(|o| owner.is_none_or(|w| o.contains(w)))
    }

    /// Promise `bytes` of the cache to `peer` for the file `root`, if they
    /// fit now by the rules for `tier` (nothing is evicted yet). Lasts while
    /// its pieces keep coming.
    pub fn reserve(&self, peer: SignPk, root: Hash32, bytes: u64, tier: CacheTier) -> Result<(), Refused> {
        self.reserve_at(peer, root, bytes, tier, unix_now())
    }

    fn reserve_at(&self, peer: SignPk, root: Hash32, bytes: u64, tier: CacheTier, now: u64) -> Result<(), Refused> {
        if tier == CacheTier::Refuse {
            return Err(Refused::Denied);
        }
        self.disk_floor(bytes)?;
        let mut st = self.st.lock();
        let key = (peer, root);
        let taken = st.cache_bytes + st.reserved_for_others(Some(&key), Instant::now());
        let deficit = (taken + bytes).saturating_sub(st.budget);
        let fits = match tier {
            CacheTier::Refuse => false,
            CacheTier::Stranger => deficit == 0 && Self::stranger_ok(&st, &peer, bytes),
            CacheTier::Contact => bytes <= st.budget && st.least_wanted(deficit, CONTACT_SCORE, now).is_some(),
        };
        if !fits {
            return Err(Refused::NoRoom);
        }
        st.reserved.insert(key, Reservation { left: bytes, until: Instant::now() + RESERVATION_TTL });
        Ok(())
    }

    fn stranger_ok(st: &State, peer: &SignPk, more: u64) -> bool {
        let mine = st.by_stranger.get(peer).copied().unwrap_or(0);
        st.stranger_bytes + more <= st.budget / STRANGER_SHARE && mine + more <= st.budget / STRANGER_EACH
    }

    fn disk_floor(&self, need: u64) -> Result<(), Refused> {
        match crate::blobs::free_space(&self.dir) {
            Some(free) if free < need.saturating_add(crate::blobs::MIN_FREE_SPACE) => Err(Refused::DiskFull),
            _ => Ok(()),
        }
    }

    /// Store a node. Its bytes must be what `id` names. A node of a pinned
    /// file (or one being sealed) is always kept; any other is cached if the
    /// rules for its source leave room. Returns whether it was new.
    pub fn insert(&self, id: Hash32, bytes: &[u8], source: Source) -> Result<bool, Refused> {
        self.insert_at(id, bytes, source, unix_now())
    }

    fn insert_at(&self, id: Hash32, bytes: &[u8], source: Source, now: u64) -> Result<bool, Refused> {
        if bytes.len() > MAX_NODE || chunked::node_id(bytes) != id {
            return Err(Refused::Mismatch);
        }
        if self.has(&id) {
            return Ok(false);
        }
        let size = bytes.len() as u64;
        self.disk_floor(size)?;
        let (protected, is_index, victims) = {
            let mut st = self.st.lock();
            if st.protected(&id) {
                (true, st.pinned.get(&id).copied().unwrap_or(false), Vec::new())
            } else {
                let (below, stranger, key) = match source {
                    Source::Own => (f32::INFINITY, None, None),
                    Source::Peer { tier: CacheTier::Refuse, .. } => return Err(Refused::Denied),
                    Source::Peer { peer, tier: CacheTier::Stranger, root } => {
                        if !Self::stranger_ok(&st, &peer, size) {
                            return Err(Refused::NoRoom);
                        }
                        (0.0, Some(peer), Some((peer, root)))
                    }
                    Source::Peer { peer, tier: CacheTier::Contact, root } => (CONTACT_SCORE, None, Some((peer, root))),
                };
                let victims = st.make_room(size, below, key.as_ref(), now).ok_or(Refused::NoRoom)?;
                if let Some(r) = key.and_then(|k| st.reserved.get_mut(&k)) {
                    r.left = r.left.saturating_sub(size);
                    r.until = Instant::now() + RESERVATION_TTL;
                }
                let hits =
                    if matches!(source, Source::Peer { tier: CacheTier::Contact, .. }) { CONTACT_SCORE } else { 0.0 };
                st.encache(id, Cached { size: size as u32, hits, stamp: now, last_peer: [0; 8], stranger });
                (false, false, victims)
            }
        };
        self.delete(&victims);
        if let Err(e) = self.write(&id, bytes, protected) {
            self.st.lock().uncache(&id);
            eprintln!("[mycel] couldn't store a file piece: {e:#}");
            return Err(Refused::DiskFull);
        }
        // a pinned index brings its children with it
        if is_index && let Ok(index) = Index::parse(bytes) {
            self.adopt(index.children.iter().map(|(c, _)| (*c, index.level > 1)).collect());
        }
        // While it was being written, its file may have been unpinned or
        // (cached) picked to make room: a node on disk is always accounted for.
        let orphan = {
            let st = self.st.lock();
            !st.protected(&id) && !st.cache.contains_key(&id)
        };
        if orphan {
            self.release(&[id]);
        }
        Ok(true)
    }

    /// Write to a temporary name, then rename: a node is here whole or not at all.
    fn write(&self, id: &Hash32, bytes: &[u8], durable: bool) -> Result<()> {
        use std::io::Write;
        let path = self.path(id);
        let dir = path.parent().context("bad chunk path")?;
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".tmp-{:016x}", mycel_crypto::random_u64()));
        let res = (|| {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            if durable {
                f.sync_data()?;
            }
            std::fs::rename(&tmp, &path)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(res?)
    }

    /// Another device asked for this node: what is asked for stays longer.
    pub fn touch(&self, id: &Hash32, peer: &SignPk) {
        self.touch_at(id, peer, unix_now());
    }

    fn touch_at(&self, id: &Hash32, peer: &SignPk, now: u64) {
        let mut st = self.st.lock();
        let Some(c) = st.cache.get_mut(id) else { return };
        let tag = peer_tag(peer);
        if c.last_peer == tag && now.saturating_sub(c.stamp) < REPEAT_GAP {
            return;
        }
        c.hits = c.score(now) + 1.0;
        c.stamp = now;
        c.last_peer = tag;
        st.dirty = true;
    }

    /// Change the donated budget; shrinking it drops the least requested.
    pub fn set_budget(&self, bytes: u64) {
        let over = {
            let mut st = self.st.lock();
            st.budget = bytes;
            st.shrink(unix_now())
        };
        self.delete(&over);
    }

    pub fn stats(&self) -> ChunkStats {
        let st = self.st.lock();
        ChunkStats {
            cache_bytes: st.cache_bytes,
            cache_nodes: st.cache.len(),
            budget: st.budget,
            pinned_files: st.roots.len(),
            pinned_nodes: st.pinned.len(),
        }
    }

    /// Whether a cached node is here and how it ranks (tests, diagnostics).
    pub fn cached_score(&self, id: &Hash32) -> Option<f32> {
        self.st.lock().cache.get(id).map(|c| c.score(unix_now()))
    }

    /// Start sealing a file into the store: its nodes are protected from
    /// eviction until [`SealSession::finish`] pins the file.
    pub fn begin_seal(self: &Arc<Self>) -> SealSession {
        SealSession { store: self.clone(), ids: HashSet::new() }
    }

    fn snapshot(&self) -> Meta {
        let st = self.st.lock();
        Meta {
            roots: st.roots.iter().map(|(r, o)| (*r, o.iter().copied().collect())).collect(),
            cache: st
                .cache
                .iter()
                .filter(|(_, c)| c.hits > 0.0 || c.stranger.is_some())
                .map(|(id, c)| MetaEntry {
                    id: *id,
                    hits: c.hits,
                    stamp: c.stamp,
                    last_peer: c.last_peer,
                    stranger: c.stranger,
                })
                .collect(),
            held: st.held.iter().copied().collect(),
        }
    }

    /// Write the pins and counts out (atomically).
    pub fn save(&self) -> Result<()> {
        let meta = self.snapshot();
        self.st.lock().dirty = false;
        let bytes = postcard::to_allocvec(&meta)?;
        let tmp = self.dir.join(format!(".meta-{:016x}", mycel_crypto::random_u64()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, self.dir.join("meta"))?;
        Ok(())
    }

    fn save_roots(&self) {
        if let Err(e) = self.save() {
            eprintln!("[mycel] couldn't save the file store's index: {e:#}");
        }
    }

    fn save_if_dirty(&self) {
        if self.st.lock().dirty {
            let _ = self.save();
        }
    }
}

impl Drop for ChunkStore {
    fn drop(&mut self) {
        self.save_if_dirty();
    }
}

/// A file being sealed into the store (see [`ChunkStore::begin_seal`]).
pub struct SealSession {
    store: Arc<ChunkStore>,
    ids: HashSet<Hash32>,
}

impl SealSession {
    /// Store one node of the file (the sink for `chunked::seal_file`).
    pub fn put(&mut self, id: &Hash32, bytes: &[u8]) -> std::io::Result<()> {
        if self.ids.insert(*id) {
            *self.store.st.lock().holds.entry(*id).or_default() += 1;
        }
        self.store.insert(*id, bytes, Source::Own).map(|_| ()).map_err(std::io::Error::other)
    }

    /// The file is whole: pin it for `owner`.
    pub fn finish(self, root: Hash32, owner: Hash32) {
        self.store.pin(root, owner);
    }
}

impl Drop for SealSession {
    fn drop(&mut self) {
        let freed: Vec<Hash32> = {
            let mut st = self.store.st.lock();
            self.ids
                .drain()
                .filter(|id| match st.holds.get_mut(id) {
                    Some(n) if *n > 1 => {
                        *n -= 1;
                        false
                    }
                    _ => {
                        st.holds.remove(id);
                        true
                    }
                })
                .collect()
        };
        self.store.release(&freed);
    }
}

fn hex32(s: &str) -> Option<Hash32> {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(Hash32(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycel_crypto::chunked::{Mode, Params, seal_file_with};

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("mycel-chunk-store-{:016x}", mycel_crypto::random_u64()))
    }

    fn open(dir: &Path, budget: u64) -> Arc<ChunkStore> {
        ChunkStore::open(dir, budget).unwrap()
    }

    /// A leaf-like node of `len` bytes that no file lists.
    fn node(seed: u8, len: usize) -> (Hash32, Vec<u8>) {
        let bytes: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8).wrapping_mul(31)).collect();
        (chunked::node_id(&bytes), bytes)
    }

    fn pk(n: u8) -> SignPk {
        SignPk([n; 32])
    }

    fn from(n: u8, tier: CacheTier) -> Source {
        Source::Peer { peer: pk(n), tier, root: Hash32([0; 32]) }
    }

    const SMALL: Params = Params { fixed: 100, min: 16, avg: 64, max: 256, fanout: 4 };

    /// Seal `data` straight into `store` (unpinned unless the caller pins).
    fn seal_into(store: &Arc<ChunkStore>, data: &[u8], owner: Option<Hash32>) -> (Hash32, Vec<Hash32>) {
        let mut session = store.begin_seal();
        let mut ids = Vec::new();
        let f = seal_file_with(
            SMALL,
            &Mode::private(),
            &[],
            &mut &data[..],
            |id, b| {
                ids.push(*id);
                session.put(id, b)
            },
            |_| {},
        )
        .unwrap();
        match owner {
            Some(o) => session.finish(f.root, o),
            None => drop(session),
        }
        (f.root, ids)
    }

    #[test]
    fn only_bytes_matching_their_id_are_stored() {
        let dir = temp();
        let s = open(&dir, 1 << 20);
        let (id, bytes) = node(1, 100);
        assert_eq!(s.insert(Hash32([9; 32]), &bytes, Source::Own), Err(Refused::Mismatch));
        assert_eq!(s.insert(id, &bytes, Source::Own), Ok(true));
        assert_eq!(s.insert(id, &bytes, Source::Own), Ok(false), "stored once");
        assert_eq!(s.read(&id).unwrap(), bytes);
        assert_eq!(s.stats().cache_bytes, 100);
        // a node that rots on disk is dropped when read
        std::fs::write(s.path(&id), b"rot").unwrap();
        assert!(s.read_verified(&id).is_err());
        assert!(!s.has(&id));
        assert_eq!(s.stats().cache_bytes, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_pinned_file_is_never_evicted_and_an_unpinned_one_joins_the_cache() {
        let dir = temp();
        let s = open(&dir, 300);
        let owner = Hash32([7; 32]);
        let data = vec![5u8; 1000];
        let (root, ids) = seal_into(&s, &data, Some(owner));
        assert!(s.tree(&root).complete());
        assert_eq!(s.stats().cache_bytes, 0, "pinned nodes use none of the budget");
        assert_eq!(s.stats().pinned_nodes, ids.len());
        // the cache fills and overflows around it; the file stays
        for i in 0..20u8 {
            let (id, bytes) = node(i, 100);
            s.insert(id, &bytes, Source::Own).unwrap();
        }
        assert!(s.stats().cache_bytes <= 300);
        assert!(s.tree(&root).complete());
        // a second owner keeps it when the first lets go
        let other = Hash32([8; 32]);
        s.pin(root, other);
        s.unpin(&root, &owner);
        assert!(s.is_pinned(&root, Some(&other)) && !s.is_pinned(&root, Some(&owner)));
        assert!(s.tree(&root).complete());
        // the last owner lets go: its nodes are cached, inside the budget
        s.unpin(&root, &other);
        assert_eq!(s.stats().pinned_files, 0);
        assert!(s.stats().cache_bytes <= 300, "{:?}", s.stats());
        assert!(!s.tree(&root).complete(), "more than the budget holds");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_file_dropped_while_sealing_is_only_cached() {
        let dir = temp();
        let s = open(&dir, 1 << 20);
        let (root, ids) = seal_into(&s, &[3u8; 500], None);
        assert_eq!(s.stats().pinned_nodes, 0);
        assert_eq!(s.stats().cache_nodes, ids.len());
        assert!(s.tree(&root).complete());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nodes_arriving_under_a_pinned_root_are_pinned_as_their_indexes_arrive() {
        let (src_dir, dst_dir) = (temp(), temp());
        let src = open(&src_dir, 1 << 20);
        let (root, _) = seal_into(&src, &vec![9u8; 100 * 16 + 1], Some(Hash32([1; 32])));
        let tree = src.tree(&root);
        assert!(tree.nodes.iter().filter(|n| n.2).count() >= 3, "several levels: {tree:?}");
        let dst = open(&dst_dir, 0); // no cache at all: only pinned nodes are kept
        dst.pin(root, Hash32([2; 32]));
        assert!(!dst.tree(&root).complete());
        // leaves before their index are refused (nothing says they belong) ...
        let leaf = tree.nodes.iter().find(|n| !n.2).unwrap().0;
        assert_eq!(dst.insert(leaf, &src.read(&leaf).unwrap(), from(1, CacheTier::Contact)), Err(Refused::NoRoom));
        // ... parents first, everything is kept
        for (id, _, _) in &tree.nodes {
            dst.insert(*id, &src.read(id).unwrap(), from(1, CacheTier::Stranger)).unwrap();
        }
        assert!(dst.tree(&root).complete());
        assert_eq!(dst.stats().cache_bytes, 0);
        for d in [src_dir, dst_dir] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn the_least_requested_go_first_and_requests_age() {
        let dir = temp();
        let s = open(&dir, 300);
        let t0 = 1_000_000;
        let nodes: Vec<_> = (0..3u8).map(|i| node(i, 100)).collect();
        for (id, bytes) in &nodes {
            s.insert_at(*id, bytes, Source::Own, t0).unwrap();
        }
        // node 0: asked for by three devices; node 1: by one; node 2: by none
        for p in 1..=3 {
            s.touch_at(&nodes[0].0, &pk(p), t0 + 10);
        }
        s.touch_at(&nodes[1].0, &pk(1), t0 + 10);
        // the same device asking again soon doesn't count twice
        s.touch_at(&nodes[1].0, &pk(1), t0 + 20);
        let (id3, b3) = node(3, 100);
        s.insert_at(id3, &b3, Source::Own, t0 + 30).unwrap();
        assert!(!s.has(&nodes[2].0), "the one nobody asked for went");
        assert!(s.has(&nodes[0].0) && s.has(&nodes[1].0));
        let (id4, b4) = node(4, 100);
        s.touch_at(&id3, &pk(9), t0 + 31);
        s.touch_at(&id3, &pk(8), t0 + 32);
        s.insert_at(id4, &b4, Source::Own, t0 + 40).unwrap();
        assert!(!s.has(&nodes[1].0), "then the one asked for once");
        assert!(s.has(&nodes[0].0));
        // popularity fades: ten weeks on, three old requests weigh less
        // than one fresh one, but age alone removes nothing
        let later = t0 + 10 * HALF_LIFE;
        assert!(s.has(&nodes[0].0) && s.has(&id3) && s.has(&id4), "nothing expires by age");
        s.touch_at(&id4, &pk(5), later);
        s.touch_at(&id3, &pk(5), later);
        let (id5, b5) = node(5, 100);
        s.insert_at(id5, &b5, Source::Own, later + 1).unwrap();
        assert!(!s.has(&nodes[0].0), "the once-popular node nobody asks for any more goes first");
        assert!(s.has(&id3) && s.has(&id4) && s.has(&id5));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn strangers_fill_only_free_room_and_only_their_share() {
        let dir = temp();
        let s = open(&dir, 1600); // a stranger: 100 each, 400 together
        let (a, ab) = node(1, 100);
        assert_eq!(s.insert(a, &ab, from(1, CacheTier::Stranger)), Ok(true));
        let (b, bb) = node(2, 50);
        assert_eq!(s.insert(b, &bb, from(1, CacheTier::Stranger)), Err(Refused::NoRoom), "its own share is used up");
        let mut strangers = vec![a];
        for p in 2..=4 {
            let (id, bytes) = node(10 + p, 100);
            assert_eq!(s.insert(id, &bytes, from(p, CacheTier::Stranger)), Ok(true));
            strangers.push(id);
        }
        let (c, cb) = node(3, 100);
        assert_eq!(s.insert(c, &cb, from(5, CacheTier::Stranger)), Err(Refused::NoRoom), "strangers' share is used up");
        assert_eq!(s.insert(c, &cb, from(5, CacheTier::Refuse)), Err(Refused::Denied));
        // contacts are not held to it, and may displace what nobody asked for
        let mut contacts = Vec::new();
        for i in 0..12u8 {
            let (id, bytes) = node(40 + i, 100);
            assert_eq!(s.insert(id, &bytes, from(6, CacheTier::Contact)), Ok(true));
            contacts.push(id);
        }
        assert_eq!(s.stats().cache_bytes, 1600);
        let (d, db) = node(4, 100);
        assert_eq!(s.insert(d, &db, from(6, CacheTier::Contact)), Ok(true));
        assert_eq!(strangers.iter().filter(|id| s.has(id)).count(), 3, "a stranger's unrequested node made way");
        assert!(contacts.iter().all(|id| s.has(id)), "a contact's fresh node is not displaced by another");
        // but a full cache of things people ask for is not displaced
        let dir2 = temp();
        let s2 = open(&dir2, 200);
        for i in 0..2u8 {
            let (id, bytes) = node(i, 100);
            s2.insert(id, &bytes, Source::Own).unwrap();
            s2.touch(&id, &pk(1));
            s2.touch(&id, &pk(2));
        }
        let (e, eb) = node(9, 100);
        assert_eq!(s2.insert(e, &eb, from(6, CacheTier::Contact)), Err(Refused::NoRoom));
        assert_eq!(s2.insert(e, &eb, from(7, CacheTier::Stranger)), Err(Refused::NoRoom));
        for d in [dir, dir2] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn offers_reserve_room_and_two_cannot_have_the_same_room() {
        let dir = temp();
        let s = open(&dir, 1000);
        let (r1, r2) = (Hash32([1; 32]), Hash32([2; 32]));
        assert_eq!(s.reserve(pk(1), r1, 800, CacheTier::Contact), Ok(()));
        assert_eq!(s.reserve(pk(2), r2, 300, CacheTier::Contact), Err(Refused::NoRoom));
        assert_eq!(s.reserve(pk(2), r2, 200, CacheTier::Contact), Ok(()));
        assert_eq!(s.reserve(pk(3), r2, 1, CacheTier::Stranger), Err(Refused::NoRoom));
        assert_eq!(s.reserve(pk(3), r2, 1, CacheTier::Refuse), Err(Refused::Denied));
        // pieces of the reserved file draw on its own reservation
        let (a, ab) = node(1, 400);
        let src = Source::Peer { peer: pk(1), tier: CacheTier::Contact, root: r1 };
        assert_eq!(s.insert(a, &ab, src), Ok(true));
        let (b, bb) = node(2, 400);
        assert_eq!(s.insert(b, &bb, src), Ok(true));
        // someone without a reservation can't take what is promised
        let (c, cb) = node(3, 150);
        assert_eq!(s.insert(c, &cb, from(4, CacheTier::Stranger)), Err(Refused::NoRoom));
        // more than a stranger's share is never promised
        assert_eq!(open(&temp(), 1600).reserve(pk(1), r1, 101, CacheTier::Stranger), Err(Refused::NoRoom));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pins_and_counts_survive_a_restart() {
        let dir = temp();
        let owner = Hash32([4; 32]);
        let (root, popular, plain) = {
            let s = open(&dir, 250);
            let (root, _) = seal_into(&s, &[1u8; 300], Some(owner));
            let (popular, pb) = node(1, 100);
            let (plain, qb) = node(2, 100);
            s.insert(plain, &qb, Source::Own).unwrap();
            s.insert(popular, &pb, Source::Own).unwrap();
            s.touch(&popular, &pk(1));
            s.touch(&popular, &pk(2));
            // a write that never finished is cleaned up on the next start
            std::fs::write(s.path(&popular).with_file_name(".tmp-dead"), b"x").unwrap();
            (root, popular, plain)
        };
        let s = open(&dir, 250);
        assert!(s.is_pinned(&root, Some(&owner)));
        assert!(s.tree(&root).complete());
        assert_eq!(s.stats().cache_bytes, 200);
        assert!(s.cached_score(&popular).unwrap() > 1.5, "request counts were kept");
        assert!(!s.path(&popular).with_file_name(".tmp-dead").exists());
        let (id, bytes) = node(3, 100);
        s.insert(id, &bytes, Source::Own).unwrap();
        assert!(s.has(&popular) && !s.has(&plain), "and still decide what goes");
        // a smaller budget on a later start drops down to it
        drop(s);
        let s = open(&dir, 100);
        assert!(s.stats().cache_bytes <= 100);
        assert!(s.tree(&root).complete());
        s.set_budget(0);
        assert_eq!(s.stats().cache_nodes, 0);
        assert!(s.tree(&root).complete());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_tree_says_what_is_missing() {
        let (src_dir, dst_dir) = (temp(), temp());
        let src = open(&src_dir, 1 << 20);
        let (root, _) = seal_into(&src, &vec![2u8; 100 * 6], Some(Hash32([1; 32])));
        let full = src.tree(&root);
        assert!(full.complete());
        assert_eq!(full.nodes[0].0, root, "parents first");
        let dst = open(&dst_dir, 1 << 20);
        assert!(!dst.tree(&root).complete());
        assert_eq!(dst.tree(&root).unknown, 1);
        for (id, _, _) in full.nodes.iter().take(full.nodes.len() - 1) {
            dst.insert(*id, &src.read(id).unwrap(), Source::Own).unwrap();
        }
        let t = dst.tree(&root);
        assert_eq!((t.missing, t.unknown), (1, 0));
        assert_eq!(t.total(), full.total());
        for d in [src_dir, dst_dir] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }
}
