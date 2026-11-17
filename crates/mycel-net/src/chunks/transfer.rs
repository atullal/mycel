//! The asking side of the chunk protocol: fetching a file from whoever has
//! its nodes, pushing one to a device, and making sure a file a member
//! couldn't be given is held by someone until that member comes for it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::Connection;
use mycel_crypto::chunked::{self, Index, MAX_INDEX, MAX_LEVEL, MAX_NODE, TAG};
use mycel_crypto::{Hash32, SignPk, SymKey};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;

use super::proto::{ChunkReq, ChunkResp, MAX_HAS};
use super::store::{ChunkStore, Refused, Source};
use crate::blobs::SpaceReservation;
use crate::link::path_in_use;
use crate::resources::{FramePermit, PeerFrames};
use crate::wire::{StreamKind, recv_capped, send};
use crate::{EAGER_PUSH_MAX, Inner, PathKind, PeerState, Progress, open_bi, pooled};

/// Requests in flight per source, each its own stream.
const STREAMS_PER_SOURCE: usize = 2;
/// A source that lacks this many nodes in a row doesn't have the file.
const MISS_LIMIT: u32 = 3;
/// A source that is busy this many times in a row is left alone.
const BUSY_LIMIT: u32 = 20;
const BUSY_WAIT: Duration = Duration::from_millis(500);
/// A file a member couldn't be given should be held by this many devices
/// besides the sender.
pub const REPLICAS: usize = 2;
/// Devices asked in one round to hold a file (each that can't be reached
/// costs a connection timeout).
const CANDIDATES_PER_ROUND: usize = 8;
/// When the sender tries again to place a file nobody could take.
const REPLICATE_RETRY: [Duration; 2] = [Duration::from_secs(30), Duration::from_secs(5 * 60)];
/// How long a lookup of holders may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Links a whole file is worth sending over to a device that only holds it
/// for someone else: not Bluetooth or a low-power radio (hours per
/// gigabyte), and not the mesh (other people's radios).
fn fast(kind: PathKind) -> bool {
    !matches!(kind, PathKind::Mesh) && kind.prior_rate() >= 1_000_000.0
}

fn conn_kind(conn: &Connection) -> Option<PathKind> {
    path_in_use(&conn.paths()).map(|p| PathKind::of(p.remote_addr()))
}

// ─────────────────────────────── one request ───────────────────────────────

async fn ask(conn: &Connection, frames: &PeerFrames, req: &ChunkReq) -> Result<ChunkResp> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Chunk).await?;
    let sent = crate::wire::send_len(&mut tx, req).await?;
    tx.finish()?;
    recv_capped(&mut rx, crate::resources::reply_timeout(sent), frames, 4096).await
}

enum Got {
    /// The node's bytes, and the memory they are counted against.
    Found(Vec<u8>, FramePermit),
    NotFound,
    Busy,
}

/// Ask one source for one node. `len`: what its parent says it is.
async fn get(conn: &Connection, frames: &PeerFrames, id: Hash32, len: Option<u32>) -> Result<Got> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Chunk).await?;
    send(&mut tx, &ChunkReq::Get { id }).await?;
    tx.finish()?;
    match recv_capped::<ChunkResp>(&mut rx, crate::resources::REPLY_TIMEOUT, frames, 4096).await? {
        ChunkResp::Found { len: got } => {
            if got as usize > MAX_NODE || len.is_some_and(|l| l != got) {
                return Err(BadSource.into());
            }
            let permit = frames.admit(got as usize).await?;
            let (bytes, permit) =
                crate::resources::read_body(&mut rx, got as usize, false, permit, crate::resources::IDLE_TIMEOUT)
                    .await?;
            Ok(Got::Found(bytes, permit))
        }
        ChunkResp::NotFound => Ok(Got::NotFound),
        ChunkResp::Busy => Ok(Got::Busy),
        other => bail!("unexpected answer: {other:?}"),
    }
}

/// A source sent bytes that aren't the node asked for.
#[derive(Debug)]
struct BadSource;

impl std::fmt::Display for BadSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the device sent a file piece that doesn't match its id")
    }
}

impl std::error::Error for BadSource {}

// ─────────────────────────────── fetching ───────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Root,
    /// An index expected at this level.
    Index(u8),
    Leaf,
}

#[derive(Clone, Copy, Debug)]
struct Want {
    id: Hash32,
    /// What its parent says its length is (the root has none).
    len: Option<u32>,
    kind: Kind,
}

#[derive(Default)]
struct FetchState {
    /// Nodes to get: indexes at the front (they say what else there is).
    pending: VecDeque<Want>,
    active: usize,
    /// Every node of the file known so far.
    seen: HashSet<Hash32>,
    /// Who said they don't have a node.
    lacks: HashMap<Hash32, HashSet<SignPk>>,
    /// Sources that sent something wrong.
    banned: HashSet<SignPk>,
    /// Bytes of the nodes known, and of those here, as stored.
    total: u64,
    done: u64,
    /// The file itself is wrong or can't be stored: no source will help.
    failed: Option<String>,
    last_error: Option<String>,
}

/// One download: the nodes still to get, shared by every source's workers.
struct Fetch {
    store: Arc<ChunkStore>,
    root: Hash32,
    /// No honest file of the size the message gives lists more than this.
    max_total: u64,
    max_nodes: usize,
    progress: Progress,
    st: Mutex<FetchState>,
    changed: tokio::sync::Notify,
}

/// The most a file of `size` plaintext bytes takes as stored, and the most
/// nodes it has: a tag per piece, pieces no smaller than the smallest cut
/// (but for one), and their indexes. Generous, and far below what a tree
/// could otherwise claim.
fn limits(size: u64) -> (u64, usize) {
    let leaves = size / (chunked::CHUNK_MIN as u64) + 2;
    let nodes = leaves + leaves / 2 + MAX_LEVEL as u64 + 2;
    let bytes = size
        .saturating_add(leaves.saturating_mul(TAG as u64))
        .saturating_add(nodes.saturating_mul(80))
        .saturating_add(MAX_INDEX as u64);
    (bytes, usize::try_from(nodes).unwrap_or(usize::MAX))
}

impl Fetch {
    /// Take in an index node that is here now: list its children, follow
    /// those that are here too, queue the rest. (Blocking: reads the store.)
    fn absorb(&self, bytes: Vec<u8>, kind: Kind) -> Result<(), String> {
        let mut st = self.st.lock();
        let mut todo = vec![(bytes, kind)];
        while let Some((bytes, kind)) = todo.pop() {
            let index = Index::parse(&bytes).map_err(|e| e.to_string())?;
            if matches!(kind, Kind::Index(l) if l != index.level) {
                return Err("malformed file index: level out of place".into());
            }
            for (id, len) in &index.children {
                if !st.seen.insert(*id) {
                    continue;
                }
                st.total += *len as u64;
                if st.total > self.max_total || st.seen.len() > self.max_nodes {
                    return Err("the file is larger than its message says".into());
                }
                let kind = if index.level > 1 { Kind::Index(index.level - 1) } else { Kind::Leaf };
                let here = self.store.len_of(id) == Some(*len);
                let index_bytes = (here && kind != Kind::Leaf).then(|| self.store.read(id).ok()).flatten();
                match (here, kind, index_bytes) {
                    (true, Kind::Leaf, _) => st.done += *len as u64,
                    (true, _, Some(b)) => {
                        st.done += *len as u64;
                        todo.push((b, kind));
                    }
                    _ => {
                        let want = Want { id: *id, len: Some(*len), kind };
                        if kind == Kind::Leaf { st.pending.push_back(want) } else { st.pending.push_front(want) }
                    }
                }
            }
        }
        Ok(())
    }

    /// Start from what is already here.
    fn begin(&self) -> Result<(), String> {
        {
            let mut st = self.st.lock();
            st.seen.insert(self.root);
        }
        match self.store.read(&self.root) {
            Ok(bytes) => {
                {
                    let mut st = self.st.lock();
                    st.total += bytes.len() as u64;
                    st.done += bytes.len() as u64;
                }
                self.absorb(bytes, Kind::Root)
            }
            Err(_) => {
                self.st.lock().pending.push_front(Want { id: self.root, len: None, kind: Kind::Root });
                Ok(())
            }
        }
    }

    fn finished(&self) -> bool {
        let st = self.st.lock();
        st.failed.is_none() && st.pending.is_empty() && st.active == 0
    }

    fn report(&self) {
        let (done, total) = {
            let st = self.st.lock();
            (st.done, st.total)
        };
        if total > 0 {
            (self.progress)(done, total);
        }
    }

    /// The next node `source` might have. `Err(true)`: nothing for it now,
    /// but nodes in flight elsewhere may come back; `Err(false)`: nothing
    /// for it at all.
    fn take(&self, source: &SignPk) -> Result<Want, bool> {
        let mut st = self.st.lock();
        if st.failed.is_some() || st.banned.contains(source) {
            return Err(false);
        }
        let at = st.pending.iter().position(|w| !st.lacks.get(&w.id).is_some_and(|l| l.contains(source)));
        match at.and_then(|i| st.pending.remove(i)) {
            Some(w) => {
                st.active += 1;
                Ok(w)
            }
            None => Err(st.active > 0),
        }
    }

    /// A node came back unfetched: someone else may have it.
    fn give_back(&self, want: Want, lacked_by: Option<SignPk>) {
        {
            let mut st = self.st.lock();
            st.active = st.active.saturating_sub(1);
            if let Some(pk) = lacked_by {
                st.lacks.entry(want.id).or_default().insert(pk);
            }
            if want.kind == Kind::Leaf { st.pending.push_back(want) } else { st.pending.push_front(want) }
        }
        self.changed.notify_waiters();
    }

    /// Store a node a source sent (blocking), and if it is an index, take
    /// in what it lists.
    fn store_node(&self, want: Want, bytes: Vec<u8>) -> Stored {
        let len = bytes.len() as u64;
        match self.store.insert(want.id, &bytes, Source::Own) {
            Ok(_) => {}
            // (the node is still wanted: the worker hands it back)
            Err(Refused::Mismatch) => return Stored::BadSource,
            Err(e) => return self.fail(e.to_string()),
        }
        {
            let mut st = self.st.lock();
            st.active = st.active.saturating_sub(1);
            st.done += len;
            if want.kind == Kind::Root {
                st.total += len;
            }
        }
        if want.kind != Kind::Leaf
            && let Err(e) = self.absorb(bytes, want.kind)
        {
            self.st.lock().failed = Some(e);
            return Stored::Fatal;
        }
        Stored::Ok
    }

    /// The download can't go on, whoever is asked.
    fn fail(&self, why: String) -> Stored {
        let mut st = self.st.lock();
        st.active = st.active.saturating_sub(1);
        st.failed = Some(why);
        Stored::Fatal
    }
}

enum Stored {
    Ok,
    /// The bytes weren't the node asked for.
    BadSource,
    /// The file is malformed or can't be stored (already recorded).
    Fatal,
}

/// One stream to one source: keep fetching nodes until none are left for it.
async fn fetch_worker(inner: Arc<Inner>, pk: SignPk, f: Arc<Fetch>) {
    let (mut misses, mut busy, mut failures) = (0u32, 0u32, 0u32);
    let frames = inner.reply_frames(&pk);
    loop {
        // Connect first: a source that is slow to reach holds no node.
        let conn = match pooled(&inner, &pk).await {
            Ok(c) => c,
            Err(e) => {
                f.st.lock().last_error = Some(format!("{e:#}"));
                return;
            }
        };
        let changed = f.changed.notified();
        let want = match f.take(&pk) {
            Ok(w) => w,
            Err(false) => return,
            Err(true) => {
                let _ = tokio::time::timeout(Duration::from_millis(500), changed).await;
                continue;
            }
        };
        match get(&conn, &frames, want.id, want.len).await {
            Ok(Got::Found(bytes, permit)) => {
                let fetch = f.clone();
                let stored = tokio::task::spawn_blocking(move || fetch.store_node(want, bytes)).await;
                drop(permit);
                match stored {
                    Ok(Stored::Ok) => {
                        (misses, busy, failures) = (0, 0, 0);
                        f.report();
                        f.changed.notify_waiters();
                    }
                    Ok(Stored::BadSource) => {
                        {
                            let mut st = f.st.lock();
                            st.banned.insert(pk);
                            st.last_error = Some(BadSource.to_string());
                        }
                        f.give_back(want, None);
                        return;
                    }
                    Ok(Stored::Fatal) => {
                        f.changed.notify_waiters();
                        return;
                    }
                    Err(_) => {
                        f.give_back(want, None);
                        return;
                    }
                }
            }
            Ok(Got::NotFound) => {
                f.give_back(want, Some(pk));
                misses += 1;
                if misses >= MISS_LIMIT {
                    return;
                }
            }
            Ok(Got::Busy) => {
                f.give_back(want, None);
                busy += 1;
                if busy >= BUSY_LIMIT {
                    f.st.lock().last_error = Some("the device that holds the file is serving others".into());
                    return;
                }
                tokio::time::sleep(BUSY_WAIT).await;
            }
            Err(e) => {
                let bad = e.is::<BadSource>();
                if bad {
                    f.st.lock().banned.insert(pk);
                }
                f.st.lock().last_error = Some(format!("{e:#}"));
                f.give_back(want, None);
                failures += 1;
                // once more (a dead pooled connection is redialed), then give up on it
                if bad || failures >= 2 {
                    return;
                }
            }
        }
        drop(conn);
    }
}

/// Run every source's workers until they have nothing left to do.
async fn run(inner: &Arc<Inner>, f: &Arc<Fetch>, sources: &[SignPk]) {
    let mut tasks = tokio::task::JoinSet::new();
    for pk in sources {
        for _ in 0..STREAMS_PER_SOURCE {
            tasks.spawn(fetch_worker(inner.clone(), *pk, f.clone()));
        }
    }
    while tasks.join_next().await.is_some() {
        if f.finished() {
            break;
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // a worker cut off mid-node no longer holds it
    let mut st = f.st.lock();
    st.active = 0;
}

fn nearby_fast(inner: &Inner) -> Vec<SignPk> {
    let fast_peer = |p: &PeerState| p.nearby || p.links.iter().any(|k| fast(*k));
    inner.peers.lock().iter().filter(|(_, p)| fast_peer(p)).map(|(k, _)| *k).collect()
}

/// See [`crate::Node::fetch_file`].
pub(crate) async fn fetch(
    inner: &Arc<Inner>,
    owner: Hash32,
    root: Hash32,
    size: u64,
    key: Option<SymKey>,
    members: Vec<SignPk>,
    progress: Progress,
) -> Result<()> {
    let chunks = inner.chunks.as_ref().context("file storage disabled")?;
    let (max_total, max_nodes) = limits(size);
    let f = Arc::new(Fetch {
        store: chunks.store.clone(),
        root,
        max_total,
        max_nodes,
        progress,
        st: Mutex::default(),
        changed: tokio::sync::Notify::new(),
    });
    let begin = f.clone();
    tokio::task::spawn_blocking(move || {
        // kept from the first node on: nothing of it is evicted half way
        begin.store.pin(root, owner);
        begin.begin()
    })
    .await?
    .map_err(|e| anyhow!(e))?;
    // what is already here counts from the start
    f.report();
    if f.finished() {
        return Ok(());
    }
    let need = {
        let st = f.st.lock();
        if st.total > 0 { st.total - st.done } else { max_total }
    };
    let _reservation = SpaceReservation::acquire(chunks.store.dir(), need)?;
    let me = inner.keys.sign_pk();
    let mut tried: HashSet<SignPk> = HashSet::from([me]);
    // first the conversation's own members (and keepers), all at once
    let first: Vec<SignPk> = members.into_iter().filter(|pk| tried.insert(*pk)).collect();
    run(inner, &f, &first).await;
    if !f.finished() && f.st.lock().failed.is_none() {
        // then whoever else holds it: the devices its sender meant to give
        // it to, those that say they have it, and devices in range
        let mut more: Vec<SignPk> = Vec::new();
        if let Some(key) = &key {
            let store = f.store.clone();
            let key = key.clone();
            let hints = tokio::task::spawn_blocking(move || {
                let bytes = store.read(&root).ok()?;
                let (_, _, hints) = chunked::open_index(&root, &key, &bytes).ok()?;
                Some(hints)
            })
            .await?;
            more.extend(hints.unwrap_or_default().into_iter().map(SignPk));
        }
        if let Some(holders) = chunks.holders() {
            let found = tokio::time::timeout(LOOKUP_TIMEOUT, holders.find(root)).await.unwrap_or_default();
            more.extend(found);
        }
        more.extend(nearby_fast(inner));
        let second: Vec<SignPk> = more.into_iter().filter(|pk| tried.insert(*pk)).collect();
        if !second.is_empty() {
            run(inner, &f, &second).await;
        }
    }
    f.report();
    let st = f.st.lock();
    if let Some(e) = &st.failed {
        bail!("{e}");
    }
    if st.pending.is_empty() {
        return Ok(());
    }
    let why = st.last_error.clone().unwrap_or_else(|| "nobody reachable has this file".into());
    Err(anyhow!(why).context(format!(
        "download stopped at {} of {}",
        crate::human_size(st.done),
        crate::human_size(st.total)
    )))
}

// ─────────────────────────────── pushing ───────────────────────────────

/// Send one node. `Ok(false)`: the device has no room for more.
async fn put(
    conn: &Connection,
    frames: &PeerFrames,
    (store, pushed): (&Arc<ChunkStore>, &std::sync::atomic::AtomicU64),
    root: Hash32,
    id: Hash32,
    len: u32,
) -> Result<bool> {
    let read = store.clone();
    let bytes = tokio::task::spawn_blocking(move || read.read(&id)).await??;
    anyhow::ensure!(bytes.len() == len as usize, "a stored file piece changed size");
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Chunk).await?;
    send(&mut tx, &ChunkReq::Put { root, id, len }).await?;
    // The device may answer without reading (it has the node already, or
    // refuses): a write cut short is its answer's business, not an error.
    let _ = crate::resources::write_all(&mut tx, &bytes).await;
    tx.finish().ok();
    match recv_capped::<ChunkResp>(&mut rx, crate::resources::reply_timeout(bytes.len()), frames, 4096).await? {
        ChunkResp::Stored => {
            pushed.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        ChunkResp::NoSpace => Ok(false),
        other => bail!("push refused: {other:?}"),
    }
}

/// See [`crate::Node::push_file`]. `fast_only`: give up if the device is
/// only reachable over a slow link (it would hold the file for others: not
/// worth hours of someone's Bluetooth).
pub(crate) async fn push(
    inner: &Arc<Inner>,
    pk: SignPk,
    space: Option<SpaceId>,
    root: Hash32,
    fast_only: bool,
) -> Result<()> {
    let chunks = inner.chunks.as_ref().context("file storage disabled")?;
    let store = chunks.store.clone();
    let walk = store.clone();
    let tree = tokio::task::spawn_blocking(move || walk.tree(&root)).await?;
    anyhow::ensure!(tree.complete(), "the file isn't whole here");
    let conn = pooled(inner, &pk).await?;
    if fast_only && conn_kind(&conn).is_some_and(|k| !fast(k)) {
        bail!("only reachable over a slow link");
    }
    let frames = inner.reply_frames(&pk);
    match ask(&conn, &frames, &ChunkReq::Offer { space, root, total: tree.total() }).await? {
        ChunkResp::Complete => return Ok(()),
        ChunkResp::Accept => {}
        other => bail!("push refused: {other:?}"),
    }
    // only what it lacks: it may hold some of the file from someone else
    let mut missing = Vec::new();
    for batch in tree.nodes.chunks(MAX_HAS) {
        let ids = batch.iter().map(|n| n.0).collect();
        let bits = match ask(&conn, &frames, &ChunkReq::Has { ids }).await? {
            ChunkResp::Have { bits } => bits,
            _ => Vec::new(), // too busy to say: send them all
        };
        let has = |i: usize| bits.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0);
        missing.extend(batch.iter().enumerate().filter(|(i, _)| !has(*i)).map(|(_, n)| *n));
    }
    // Indexes first, parents before children: the device learns from them
    // which nodes belong to the file.
    for (id, len, _) in missing.iter().filter(|n| n.2) {
        if !put(&conn, &frames, (&store, &chunks.pushed), root, *id, *len).await? {
            bail!("the device has no room left");
        }
    }
    let leaves: Arc<Mutex<VecDeque<(Hash32, u32)>>> =
        Arc::new(Mutex::new(missing.iter().filter(|n| !n.2).map(|n| (n.0, n.1)).collect()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..STREAMS_PER_SOURCE {
        let (conn, frames, store, leaves) = (conn.clone(), frames.clone(), store.clone(), leaves.clone());
        let inner = inner.clone();
        tasks.spawn(async move {
            let pushed = &inner.chunks.as_ref().context("file storage disabled")?.pushed;
            loop {
                let Some((id, len)) = leaves.lock().pop_front() else { return Ok(()) };
                if !put(&conn, &frames, (&store, pushed), root, id, len).await? {
                    bail!("the device has no room left");
                }
            }
        });
    }
    let mut result = Ok(());
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => result = Err(e),
            Err(e) => result = Err(anyhow!("push task failed: {e}")),
        }
    }
    result?;
    match ask(&conn, &frames, &ChunkReq::Done { root }).await? {
        ChunkResp::Complete => Ok(()),
        other => bail!("push incomplete: {other:?}"),
    }
}

// ─────────────────────────────── replicating ───────────────────────────────

/// A file was added to `space`: push it by the push policy, and if a member
/// can't be reached and too few other devices hold it, hand it to devices
/// willing to hold it for that member. Tried again a couple of times while
/// the node runs (a member or a holder may turn up).
pub(crate) async fn distribute(inner: Weak<Inner>, space: SpaceId, root: Hash32, replicas: Vec<SignPk>) {
    // devices that have the whole file from us
    let mut holders: HashSet<SignPk> = HashSet::new();
    let mut waits = REPLICATE_RETRY.iter();
    loop {
        let Some(strong) = inner.upgrade() else { return };
        let settled = distribute_once(&strong, space, root, &replicas, &mut holders).await;
        drop(strong);
        if settled {
            return;
        }
        let Some(wait) = waits.next() else { return };
        tokio::time::sleep(*wait).await;
    }
}

/// One round. `true`: every member has the file or enough devices hold it.
async fn distribute_once(
    inner: &Arc<Inner>,
    space: SpaceId,
    root: Hash32,
    replicas: &[SignPk],
    holders: &mut HashSet<SignPk>,
) -> bool {
    let Some(chunks) = &inner.chunks else { return true };
    let store = chunks.store.clone();
    let Ok(tree) = tokio::task::spawn_blocking(move || store.tree(&root)).await else { return true };
    if !tree.complete() {
        return true; // no longer ours to give
    }
    let total = tree.total();
    let me = inner.keys.sign_pk();
    let Ok(members) = inner.with_space(&space, |r| {
        r.members().into_iter().filter(|(k, _)| k.sign_pk != me).map(|(k, role)| (k.sign_pk, role)).collect::<Vec<_>>()
    }) else {
        return true;
    };
    // keepers always, members if it is small: as for blobs
    let mut pushes = tokio::task::JoinSet::new();
    for (pk, role) in &members {
        if holders.contains(pk) || !(*role == Role::Relay || total <= EAGER_PUSH_MAX) {
            continue;
        }
        let (inner, pk) = (inner.clone(), *pk);
        pushes.spawn(async move { (pk, push(&inner, pk, Some(space), root, false).await.is_ok()) });
    }
    while let Some(res) = pushes.join_next().await {
        if let Ok((pk, true)) = res {
            holders.insert(pk);
        }
    }
    // Who may not get it from us: members we couldn't give it to, and for
    // a file too big to push, members who aren't around to fetch it.
    let peers = inner.peers.lock().clone();
    let online = |pk: &SignPk| peers.get(pk).is_some_and(PeerState::online);
    let unreached = members
        .iter()
        .filter(|(pk, role)| *role != Role::Relay && !holders.contains(pk))
        .any(|(pk, _)| total <= EAGER_PUSH_MAX || !online(pk));
    if !unreached || holders.len() >= REPLICAS {
        return true;
    }
    // Devices willing to hold it: those the sender named, the app's
    // contacts, then devices nearby on a fast link.
    let mut seen: HashSet<SignPk> = members.iter().map(|(pk, _)| *pk).chain([me]).collect();
    let mut candidates: Vec<SignPk> = replicas
        .iter()
        .copied()
        .chain(chunks.candidates())
        .chain(nearby_fast(inner))
        .filter(|pk| seen.insert(*pk) && !holders.contains(pk))
        .collect();
    // those that are around first (in the order given among equals)
    candidates.sort_by_key(|pk| !online(pk));
    for pk in candidates.into_iter().take(CANDIDATES_PER_ROUND) {
        if holders.len() >= REPLICAS {
            break;
        }
        if push(inner, pk, None, root, true).await.is_ok() {
            holders.insert(pk);
        }
    }
    holders.len() >= REPLICAS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_follow_the_size_a_message_gives() {
        let (bytes, nodes) = limits(0);
        assert!(nodes >= 2 && bytes >= (TAG + chunked::MIN_INDEX) as u64);
        // a gigabyte in fixed mebibyte pieces fits with room to spare ...
        let size = 1u64 << 30;
        let (bytes, nodes) = limits(size);
        let honest_nodes = 1024 + 1;
        let honest_bytes = size + 1024 * TAG as u64 + 1024 * 68 + 64;
        assert!(nodes >= honest_nodes && bytes >= honest_bytes);
        // ... and in the smallest content-defined pieces too
        assert!(nodes as u64 > size / chunked::CHUNK_MIN as u64);
        // but a tree can't claim much more than the message does
        assert!(bytes < size + size / 50 + (1 << 20));
    }

    #[test]
    fn slow_links_are_not_used_to_place_files_with_holders() {
        assert!(fast(PathKind::Network) && fast(PathKind::PeerWifi) && fast(PathKind::Ethernet));
        assert!(fast(PathKind::WifiDirect) && fast(PathKind::Relay));
        assert!(!fast(PathKind::Bluetooth) && !fast(PathKind::Mesh) && !fast(PathKind::Ieee802154));
    }
}
