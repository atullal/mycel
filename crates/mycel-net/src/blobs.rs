//! Blobs: immutable, content-addressed (BLAKE3), already-encrypted bytes of
//! any size, stored per space and streamed between members over QUIC.
//!
//! Protocol: one QUIC bi-stream of kind `Blob` per request, on the pooled
//! connection to the member (low stream priority, so messages go first):
//!
//! ```text
//! range:  C → S  GetRange{space, hash, offset, len}  S → C  Range{total, offset} ‖ bytes[offset..offset+len)
//! push:   C → S  Offer{space, hash, len}             S → C  Stored (have it) | SendFrom{offset} | NoSpace | Busy | Denied
//!         C → S  bytes[offset..len]                  S → C  Stored
//! ```
//! (`Get`, `Put` and `GetFrom` are older whole-blob / resume-from requests;
//! still served.)
//!
//! Downloads come from every member that has the blob at once: the missing
//! bytes are cut into pieces of up to 4 MiB, each fetched with `GetRange` on
//! its own stream, two at a time per member. When there's nothing left to
//! hand out, an idle member takes over the second half of the biggest piece
//! still in flight; a member that fails gives its unfinished pieces back.
//!
//! Bytes go straight between the QUIC stream and disk in small buffers, so
//! memory stays bounded whatever the size. Data lands in `<hash>.part`, with
//! a `<hash>.ranges` file listing which bytes are there (pieces arrive out of
//! order; no `.ranges` means the `.part` is a plain prefix, as pushes and
//! older versions write it). The file is renamed into place only once the
//! BLAKE3 hash of the whole blob matches; an interrupted transfer leaves both
//! behind and the next attempt (from any members that have the blob) fetches
//! only what's missing.
//!
//! There's no size limit and no quota. The only guard is free disk space: a
//! transfer that would leave less than [`MIN_FREE_SPACE`] free is refused.
//!
//! Push policy: blobs up to [`EAGER_PUSH_MAX`] are pushed to every member when
//! posted; bigger ones are pushed only to keepers (whose job is to hold data
//! while the sender is offline) and members fetch them on demand, from the
//! sender, a keeper or any member that already downloaded them. Receivers
//! enforce it too: only a keeper accepts an unsolicited push above the limit.

use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use mycel_crypto::{Digest, Hash32, SignPk};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::wire::*;
use crate::{Inner, NetEvent, Node, on_conn, open_bi, pooled};

/// Blobs up to this size are pushed to every member as soon as they're posted.
pub const EAGER_PUSH_MAX: u64 = 16 * 1024 * 1024;
/// A transfer is refused if it would leave less free disk space than this.
pub const MIN_FREE_SPACE: u64 = 1024 * 1024 * 1024;
/// Stream ↔ disk buffer size.
const IO_CHUNK: usize = 256 * 1024;

/// Progress callback: `(bytes done, total bytes)`.
pub type Progress = Arc<dyn Fn(u64, u64) + Send + Sync>;

fn no_progress() -> Progress {
    Arc::new(|_, _| {})
}

/// Bytes available to us on the filesystem holding `path` (or its nearest
/// existing ancestor). `None` if unknown.
pub fn free_space(path: &Path) -> Option<u64> {
    let existing = path.ancestors().find(|a| a.exists())?;
    free_space_at(existing)
}

#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_cast)]
fn free_space_at(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // statfs, not statvfs: macOS statvfs has 32-bit block counts.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `s` a writable statfs.
    (unsafe { libc::statfs(c.as_ptr(), &mut s) } == 0).then(|| s.f_bavail as u64 * s.f_bsize as u64)
}

#[cfg(all(unix, not(target_os = "macos")))]
#[allow(clippy::unnecessary_cast)]
fn free_space_at(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `s` a writable statvfs.
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| s.f_bavail as u64 * s.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_space_at(_path: &Path) -> Option<u64> {
    None
}

/// Human-readable byte count ("1.5 GB").
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// Fail unless writing `need` more bytes under `dir` leaves [`MIN_FREE_SPACE`] free.
pub fn ensure_free_space(dir: &Path, need: u64) -> Result<()> {
    if let Some(free) = free_space(dir)
        && free < need.saturating_add(MIN_FREE_SPACE)
    {
        bail!(
            "not enough disk space: this needs {} but only {} is free (Mycel always keeps {} free)",
            human_size(need),
            human_size(free),
            human_size(MIN_FREE_SPACE)
        );
    }
    Ok(())
}

/// Incremental [`blob_hash`]: feed the blob's bytes in pieces.
pub fn blob_digest() -> Digest {
    Digest::new(BLOB_HASH_CTX)
}

fn part_path(path: &Path) -> PathBuf {
    path.with_extension("part")
}

/// One writer per blob file at a time (pushes and fetches of the same blob
/// would otherwise interleave in the same `.part`). Process-wide, keyed by
/// path, so it also works with several nodes in one process (tests).
static WRITING: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(Mutex::default);

struct WriteLock(PathBuf);

impl WriteLock {
    fn try_acquire(path: &Path) -> Option<Self> {
        WRITING.lock().insert(path.to_path_buf()).then(|| WriteLock(path.to_path_buf()))
    }

    async fn acquire(path: &Path) -> Self {
        loop {
            if let Some(l) = Self::try_acquire(path) {
                return l;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        WRITING.lock().remove(&self.0);
    }
}

/// Hash the first `len` bytes of `path` into `digest`.
async fn hash_prefix(path: &Path, len: u64, digest: &mut Digest) -> Result<()> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut left = len;
    while left > 0 {
        let want = (buf.len() as u64).min(left) as usize;
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            bail!("partial blob shrank while reading it");
        }
        digest.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(())
}

/// Receive bytes `[offset, total)` into `part` (truncated to `offset` first).
async fn receive_into(
    rx: &mut RecvStream,
    part: &Path,
    offset: u64,
    total: u64,
    digest: &mut Digest,
    progress: &Progress,
) -> Result<()> {
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(part)
        .await
        .with_context(|| format!("can't write {}", part.display()))?;
    f.set_len(offset).await?;
    f.seek(SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut done = offset;
    progress(done, total);
    while done < total {
        // QUIC hands data over a packet at a time; batch it so each disk
        // write (a blocking-pool round trip) is a full buffer.
        let want = (buf.len() as u64).min(total - done) as usize;
        let mut n = 0;
        let mut ended = false;
        while n < want && !ended {
            match rx.read(&mut buf[n..want]).await {
                Ok(Some(k)) => n += k,
                // keep what arrived, so the next attempt resumes after it
                Ok(None) | Err(_) => ended = true,
            }
        }
        digest.update(&buf[..n]);
        f.write_all(&buf[..n]).await?;
        done += n as u64;
        progress(done, total);
        if ended {
            f.flush().await?;
            bail!("transfer interrupted at {} of {}", human_size(done), human_size(total));
        }
    }
    f.flush().await?;
    f.sync_all().await?;
    Ok(())
}

/// Send bytes `[offset, len)` of `path`.
async fn send_from(tx: &mut SendStream, path: &Path, offset: u64, len: u64, progress: &Progress) -> Result<()> {
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut done = offset;
    while done < len {
        let want = (buf.len() as u64).min(len - done) as usize;
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            bail!("blob file shrank while sending it");
        }
        tx.write_all(&buf[..n]).await?;
        done += n as u64;
        progress(done, len);
    }
    Ok(())
}

/// Verify the hash, then move the finished `.part` into place.
async fn commit(inner: &Inner, part: &Path, path: &Path, hash: Hash32, digest: &Digest) -> Result<()> {
    if digest.finalize() != hash {
        let _ = tokio::fs::remove_file(part).await;
        return Err(HashMismatch.into());
    }
    tokio::fs::rename(part, path).await?;
    inner.emit(NetEvent::BlobStored { hash });
    Ok(())
}

#[derive(Debug)]
struct HashMismatch;

impl std::fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("blob hash mismatch (corrupt or wrong data from peer)")
    }
}

impl std::error::Error for HashMismatch {}

async fn part_len(part: &Path) -> u64 {
    tokio::fs::metadata(part).await.map(|m| m.len()).unwrap_or(0)
}

// ───────────────────────────── partial downloads ─────────────────────────────

/// Byte ranges of a blob we already hold in its `.part` file: sorted,
/// disjoint, half-open `[start, end)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let (mut s, mut e) = (start, end);
        let mut out = Vec::with_capacity(self.0.len() + 1);
        for &(a, b) in &self.0 {
            if b < s || a > e {
                out.push((a, b));
            } else {
                s = s.min(a);
                e = e.max(b);
            }
        }
        out.push((s, e));
        out.sort_unstable();
        self.0 = out;
    }

    fn covered(&self) -> u64 {
        self.0.iter().map(|(a, b)| b - a).sum()
    }

    /// How many bytes from 0 on are contiguous.
    fn prefix(&self) -> u64 {
        match self.0.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }

    /// The gaps in `[0, total)`.
    fn missing(&self, total: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut at = 0;
        for &(a, b) in &self.0 {
            if a > at {
                out.push((at, a.min(total)));
            }
            at = at.max(b);
        }
        if at < total {
            out.push((at, total));
        }
        out.retain(|(a, b)| a < b);
        out
    }
}

/// The `.ranges` file next to a `.part`: which bytes of it are filled in.
/// No such file means the `.part` is a plain prefix (how pushes and older
/// versions write it).
fn ranges_path(part: &Path) -> PathBuf {
    part.with_extension("ranges")
}

#[derive(Serialize, Deserialize)]
struct RangesFile {
    total: u64,
    done: Ranges,
}

/// What a `.part` file holds, for a blob of `total` bytes (`None`: unknown yet).
async fn load_done(part: &Path, total: Option<u64>) -> Ranges {
    if let Ok(bytes) = tokio::fs::read(ranges_path(part)).await {
        return match postcard::from_bytes::<RangesFile>(&bytes) {
            Ok(f) if total.is_none_or(|t| t == f.total) => f.done,
            _ => Ranges::default(), // stale or damaged: start over
        };
    }
    let mut r = Ranges::default();
    let len = part_len(part).await;
    r.insert(0, total.map_or(len, |t| len.min(t)));
    r
}

async fn save_done(part: &Path, total: u64, done: &Ranges) -> Result<()> {
    let bytes = postcard::to_allocvec(&RangesFile { total, done: done.clone() })?;
    let tmp = part.with_extension(format!("ranges.{:x}", mycel_crypto::random_u64()));
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, ranges_path(part)).await?;
    Ok(())
}

async fn drop_partial(part: &Path) {
    let _ = tokio::fs::remove_file(part).await;
    let _ = tokio::fs::remove_file(ranges_path(part)).await;
}

// ─────────────────────────────── server side ───────────────────────────────

/// One blob request, on its own stream of a pooled connection.
pub(crate) async fn serve(inner: &Arc<Inner>, peer: SignPk, mut tx: SendStream, mut rx: RecvStream) -> Result<()> {
    let req: BlobReq = recv(&mut rx).await?;
    let (space, hash) = match &req {
        BlobReq::Get { space, hash }
        | BlobReq::Put { space, hash, .. }
        | BlobReq::GetFrom { space, hash, .. }
        | BlobReq::Offer { space, hash, .. }
        | BlobReq::GetRange { space, hash, .. } => (*space, *hash),
    };
    let (allowed, keeper) = inner
        .spaces
        .lock()
        .get(&space)
        .map_or((false, false), |r| (r.is_member(&peer), r.my_role() == Some(Role::Relay)));
    let path = inner.blob_path(&space, &hash).filter(|_| allowed);
    // Unsolicited pushes follow the push policy: keepers take any size, other
    // devices only small blobs (big ones they fetch when their user asks), so
    // a member can't fill someone's disk with files they never opened.
    let push_ok = |len: u64| keeper || len <= EAGER_PUSH_MAX;
    let res = match (req, path) {
        (_, None) => send(&mut tx, &BlobResp::Denied).await,
        (BlobReq::Put { len, .. } | BlobReq::Offer { len, .. }, Some(_)) if !push_ok(len) => {
            send(&mut tx, &BlobResp::Denied).await
        }
        (BlobReq::Get { .. }, Some(path)) => serve_get(inner, &mut tx, &path, None).await,
        (BlobReq::GetFrom { offset, .. }, Some(path)) => serve_get(inner, &mut tx, &path, Some(offset)).await,
        (BlobReq::GetRange { offset, len, .. }, Some(path)) => serve_range(inner, &mut tx, &path, offset, len).await,
        (BlobReq::Put { len, .. }, Some(path)) => serve_put(inner, &mut tx, &mut rx, &path, hash, len, false).await,
        (BlobReq::Offer { len, .. }, Some(path)) => serve_put(inner, &mut tx, &mut rx, &path, hash, len, true).await,
    };
    tx.finish().ok();
    res
}

async fn blob_len(path: &Path) -> Option<u64> {
    match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() => Some(m.len()),
        _ => None,
    }
}

/// Counts bytes served into [`Node::blob_bytes_served`].
fn count_served(inner: &Arc<Inner>, from: u64) -> Progress {
    let inner = inner.clone();
    let last = std::sync::atomic::AtomicU64::new(from);
    Arc::new(move |done, _| {
        let prev = last.swap(done, std::sync::atomic::Ordering::Relaxed);
        inner.blob_served.fetch_add(done.saturating_sub(prev), std::sync::atomic::Ordering::Relaxed);
    })
}

async fn serve_get(inner: &Arc<Inner>, tx: &mut SendStream, path: &Path, offset: Option<u64>) -> Result<()> {
    let Some(len) = blob_len(path).await else {
        return send(tx, &BlobResp::NotFound).await;
    };
    let start = match offset {
        None => {
            send(tx, &BlobResp::Found { len }).await?;
            0
        }
        Some(o) => {
            let o = if o <= len { o } else { 0 };
            send(tx, &BlobResp::Range { total: len, offset: o }).await?;
            o
        }
    };
    send_from(tx, path, start, len, &count_served(inner, start)).await
}

async fn serve_range(inner: &Arc<Inner>, tx: &mut SendStream, path: &Path, offset: u64, len: u64) -> Result<()> {
    let Some(total) = blob_len(path).await else {
        return send(tx, &BlobResp::NotFound).await;
    };
    let start = offset.min(total);
    send(tx, &BlobResp::Range { total, offset: start }).await?;
    let end = start.saturating_add(len).min(total);
    send_from(tx, path, start, end, &count_served(inner, start)).await
}

async fn serve_put(
    inner: &Arc<Inner>,
    tx: &mut SendStream,
    rx: &mut RecvStream,
    path: &Path,
    hash: Hash32,
    len: u64,
    handshake: bool,
) -> Result<()> {
    if path.exists() {
        return send(tx, &BlobResp::Stored).await;
    }
    let Some(_lock) = WriteLock::try_acquire(path) else {
        return send(tx, &if handshake { BlobResp::Busy } else { BlobResp::Denied }).await;
    };
    let part = part_path(path);
    // Legacy `Put` streams from 0 without asking; `Offer` resumes after the
    // contiguous prefix we hold (a multi-source download may have left
    // other ranges too: a push writes sequentially, so they are dropped).
    let mut offset = if handshake { load_done(&part, Some(len)).await.prefix() } else { 0 };
    let _ = tokio::fs::remove_file(ranges_path(&part)).await;
    if offset > len {
        offset = 0;
    }
    let dir = path.parent().context("bad blob path")?;
    if ensure_free_space(dir, len - offset).is_err() {
        return send(tx, &if handshake { BlobResp::NoSpace } else { BlobResp::Denied }).await;
    }
    tokio::fs::create_dir_all(dir).await?;
    let mut digest = blob_digest();
    if offset > 0 && hash_prefix(&part, offset, &mut digest).await.is_err() {
        offset = 0;
        digest = blob_digest();
    }
    if handshake {
        send(tx, &BlobResp::SendFrom { offset }).await?;
    }
    receive_into(rx, &part, offset, len, &mut digest, &no_progress()).await?;
    commit(inner, &part, path, hash, &digest).await?;
    send(tx, &BlobResp::Stored).await
}

// ─────────────────────────────── client side ───────────────────────────────

/// Push a stored blob to one member (resuming a partial copy they have).
async fn push(inner: &Arc<Inner>, pk: SignPk, space: SpaceId, hash: Hash32, path: &Path) -> Result<()> {
    let len = tokio::fs::metadata(path).await?.len();
    on_conn!(inner, &pk, |conn| async {
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Blob).await?;
        send(&mut tx, &BlobReq::Offer { space, hash, len }).await?;
        match recv::<BlobResp>(&mut rx).await? {
            BlobResp::Stored => Ok(()),
            BlobResp::SendFrom { offset } if offset <= len => {
                send_from(&mut tx, path, offset, len, &no_progress()).await?;
                tx.finish()?;
                match recv::<BlobResp>(&mut rx).await? {
                    BlobResp::Stored => Ok(()),
                    other => Err(anyhow!("push failed: {other:?}")),
                }
            }
            other => Err(anyhow!("push refused: {other:?}")),
        }
    })
}

/// Ranges are fetched in pieces of at most this size ...
const PIECE: u64 = 4 * 1024 * 1024;
/// ... with this many requests in flight per source (each its own QUIC
/// stream on the pooled connection), so there's no gap between pieces.
const STREAMS_PER_SOURCE: usize = 2;
/// An idle source takes over the second half of a piece still in flight
/// elsewhere when at least this much of it is left (end game).
const STEAL_MIN: u64 = 512 * 1024;
/// The `.ranges` file is rewritten after this many new bytes.
const SAVE_EVERY: u64 = 4 * 1024 * 1024;

/// Shared state of one multi-source download.
struct Download {
    space: SpaceId,
    hash: Hash32,
    total: u64,
    part: PathBuf,
    progress: Progress,
    st: Mutex<DlState>,
    /// A piece finished or came back.
    changed: tokio::sync::Notify,
}

struct DlState {
    done: Ranges,
    /// Not yet handed to any source.
    pending: std::collections::VecDeque<(u64, u64)>,
    /// In flight: worker id → (next byte, end). A stealer may lower `end`.
    active: HashMap<u64, (u64, u64)>,
    next_id: u64,
    unsaved: u64,
}

/// What a source should do next.
enum Take {
    /// Fetch `[start, end)` as piece `id`.
    Piece { id: u64, start: u64, end: u64 },
    /// Nothing to hand out, but pieces are in flight elsewhere and may come
    /// back (their source fails): wait.
    Wait,
    Done,
}

impl Download {
    /// Hand out the next piece (or half of the biggest one in flight).
    fn take(&self) -> Take {
        let mut st = self.st.lock();
        let range = match st.pending.pop_front() {
            Some((a, b)) if b - a > PIECE => {
                st.pending.push_front((a + PIECE, b));
                (a, a + PIECE)
            }
            Some(r) => r,
            None => {
                let Some((&victim, &(cur, end))) = st.active.iter().max_by_key(|(_, (c, e))| e.saturating_sub(*c))
                else {
                    return Take::Done;
                };
                if end.saturating_sub(cur) < 2 * STEAL_MIN {
                    return Take::Wait;
                }
                let mid = cur + (end - cur) / 2;
                st.active.insert(victim, (cur, mid));
                (mid, end)
            }
        };
        let id = st.next_id;
        st.next_id += 1;
        st.active.insert(id, range);
        Take::Piece { id, start: range.0, end: range.1 }
    }

    /// `[start, start+n)` is on disk. Returns where this worker should stop
    /// now, and a snapshot to save if it's time.
    fn mark(&self, id: u64, start: u64, n: u64) -> (u64, Option<Ranges>) {
        let (done, end, save) = {
            let mut st = self.st.lock();
            let end = st.active.get(&id).map_or(start, |r| r.1);
            let upto = (start + n).min(end.max(start));
            st.done.insert(start, upto);
            if let Some(r) = st.active.get_mut(&id) {
                r.0 = upto;
            }
            st.unsaved += upto - start;
            let save = (st.unsaved >= SAVE_EVERY).then(|| {
                st.unsaved = 0;
                st.done.clone()
            });
            (st.done.covered(), end, save)
        };
        (self.progress)(done, self.total);
        (end, save)
    }

    /// The worker stopped; whatever it didn't fetch goes back in the queue.
    fn release(&self, id: u64) {
        {
            let mut st = self.st.lock();
            if let Some((cur, end)) = st.active.remove(&id)
                && cur < end
            {
                st.pending.push_front((cur, end));
            }
        }
        self.changed.notify_waiters();
    }

    fn snapshot(&self) -> Ranges {
        self.st.lock().done.clone()
    }

    fn finished(&self) -> bool {
        self.st.lock().done.covered() >= self.total
    }
}

/// Fetch `[start, end)` of the blob from one source into the `.part` file.
async fn fetch_range(conn: &Connection, dl: &Download, id: u64, start: u64, end: u64) -> Result<()> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Blob).await?;
    let (space, hash) = (dl.space, dl.hash);
    send(&mut tx, &BlobReq::GetRange { space, hash, offset: start, len: end - start }).await?;
    tx.finish()?;
    match recv::<BlobResp>(&mut rx).await? {
        BlobResp::Range { total, offset } if total == dl.total && offset == start => {}
        other => bail!("not available: {other:?}"),
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&dl.part)
        .await
        .with_context(|| format!("can't write {}", dl.part.display()))?;
    f.seek(SeekFrom::Start(start)).await?;
    let mut buf = vec![0u8; IO_CHUNK];
    let (mut at, mut end) = (start, end);
    while at < end {
        let want = (buf.len() as u64).min(end - at) as usize;
        let mut n = 0;
        let mut ended = false;
        while n < want && !ended {
            match rx.read(&mut buf[n..want]).await {
                Ok(Some(k)) => n += k,
                Ok(None) | Err(_) => ended = true,
            }
        }
        f.write_all(&buf[..n]).await?;
        let (new_end, save) = dl.mark(id, at, n as u64);
        at += n as u64;
        end = new_end;
        if let Some(done) = save {
            f.flush().await?;
            save_done(&dl.part, dl.total, &done).await?;
        }
        if ended && at < end {
            bail!("transfer interrupted");
        }
    }
    // the rest of this piece went to a faster source
    rx.stop(0u32.into()).ok();
    f.flush().await?;
    Ok(())
}

/// One source: probe it, then keep fetching pieces until none are left.
async fn source_worker(inner: Arc<Inner>, pk: SignPk, dl: Arc<Download>) -> Result<()> {
    let mut failures = 0;
    loop {
        // Connect first: a source that is slow to reach holds no piece.
        let conn = pooled(&inner, &pk).await?;
        let changed = dl.changed.notified();
        let (id, start, end) = match dl.take() {
            Take::Piece { id, start, end } => (id, start, end),
            Take::Done => return Ok(()),
            Take::Wait => {
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), changed).await;
                continue;
            }
        };
        let res = fetch_range(&conn, &dl, id, start, end).await;
        dl.release(id);
        drop(conn);
        match res {
            Ok(()) => failures = 0,
            // once more (a dead pooled connection is redialed), then give up on it
            Err(_) if failures == 0 => failures += 1,
            Err(e) => return Err(e),
        }
    }
}

/// Ask a member whether it has the blob; `Some(total)` if it does.
async fn probe(inner: &Arc<Inner>, pk: SignPk, space: SpaceId, hash: Hash32) -> Result<u64> {
    on_conn!(inner, &pk, |conn| async {
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Blob).await?;
        send(&mut tx, &BlobReq::GetRange { space, hash, offset: 0, len: 0 }).await?;
        tx.finish()?;
        match recv::<BlobResp>(&mut rx).await? {
            BlobResp::Range { total, .. } => Ok(total),
            other => Err(anyhow!("not available: {other:?}")),
        }
    })
}

enum Step {
    Probed(SignPk, Result<u64>),
    Worker(Result<()>),
}

/// Download a blob from every member that has it at once: disjoint ranges
/// from each (several streams per source), a failed source's ranges go to
/// the others, and the whole file is checked against its hash at the end.
async fn download(inner: &Arc<Inner>, sources: Vec<SignPk>, space: SpaceId, hash: Hash32, path: &Path, progress: &Progress) -> Result<()> {
    let part = part_path(path);
    let dir = path.parent().context("bad blob path")?;
    tokio::fs::create_dir_all(dir).await?;
    let mut tasks = tokio::task::JoinSet::new();
    for pk in sources {
        let inner = inner.clone();
        tasks.spawn(async move { Step::Probed(pk, probe(&inner, pk, space, hash).await) });
    }
    let mut dl: Option<Arc<Download>> = None;
    let mut workers = 0usize;
    let mut last_err: Option<anyhow::Error> = None;
    let start_workers = |dl: &Arc<Download>, pk: SignPk, tasks: &mut tokio::task::JoinSet<Step>| {
        for _ in 0..STREAMS_PER_SOURCE {
            let (inner, dl) = (inner.clone(), dl.clone());
            tasks.spawn(async move { Step::Worker(source_worker(inner, pk, dl).await) });
        }
    };
    while let Some(step) = tasks.join_next().await {
        // Done: don't wait for slow probes or sources still dialing.
        if dl.as_ref().is_some_and(|d| d.finished()) {
            break;
        }
        match step.map_err(|e| anyhow!("download task failed: {e}"))? {
            Step::Probed(pk, Ok(total)) => {
                if dl.is_none() {
                    let done = load_done(&part, Some(total)).await;
                    ensure_free_space(dir, total - done.covered().min(total))?;
                    // From now on the `.part` may have holes: say what it holds.
                    save_done(&part, total, &done).await?;
                    progress(done.covered(), total);
                    let pending = done.missing(total).into();
                    dl = Some(Arc::new(Download {
                        space,
                        hash,
                        total,
                        part: part.clone(),
                        progress: progress.clone(),
                        st: Mutex::new(DlState { done, pending, active: HashMap::new(), next_id: 0, unsaved: 0 }),
                        changed: tokio::sync::Notify::new(),
                    }));
                }
                let d = dl.as_ref().expect("set above");
                if total == d.total {
                    start_workers(d, pk, &mut tasks);
                    workers += STREAMS_PER_SOURCE;
                } // else: it disagrees on the size; not used
            }
            Step::Probed(_, Err(e)) => last_err = Some(e),
            Step::Worker(res) => {
                workers -= 1;
                if let Err(e) = res {
                    last_err = Some(e);
                }
                // (Pieces handed back by a failed source go to whoever is left.)
                if workers == 0 && tasks.is_empty() {
                    break;
                }
            }
        }
    }
    let Some(dl) = dl else {
        return Err(last_err.unwrap_or_else(|| anyhow!("nobody else in the conversation has this file")));
    };
    let done = dl.snapshot();
    if done.covered() < dl.total {
        save_done(&part, dl.total, &done).await.ok();
        let e = last_err.unwrap_or_else(|| anyhow!("no source left"));
        return Err(e.context(format!(
            "download stopped at {} of {}",
            human_size(done.covered()),
            human_size(dl.total)
        )));
    }
    // Pieces arrived out of order: hash the finished file once.
    {
        let f = tokio::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&part).await?;
        f.set_len(dl.total).await?;
        f.sync_all().await?;
    }
    let mut digest = blob_digest();
    hash_prefix(&part, dl.total, &mut digest).await?;
    let res = commit(inner, &part, path, hash, &digest).await;
    if res.is_err() {
        drop_partial(&part).await;
    } else {
        let _ = tokio::fs::remove_file(ranges_path(&part)).await;
    }
    res
}

impl Node {
    /// Local path of a blob we hold completely.
    pub fn blob_path(&self, space: &SpaceId, hash: &Hash32) -> Option<PathBuf> {
        self.inner.blob_path(space, hash).filter(|p| p.is_file())
    }

    /// Blob bytes this node has sent to members that fetched them.
    pub fn blob_bytes_served(&self) -> u64 {
        self.inner.blob_served.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A fresh path to build a blob in before [`Node::add_blob`] (same filesystem
    /// as the blob store, so adding it is a rename).
    pub fn blob_staging_path(&self) -> Option<PathBuf> {
        let dir = self.inner.blob_dir.as_ref()?.join(".staging");
        Some(dir.join(format!("{:016x}", mycel_crypto::random_u64())))
    }

    /// Store an (already encrypted) blob from memory. Returns its hash.
    pub async fn put_blob(&self, space: SpaceId, bytes: Vec<u8>) -> Result<Hash32> {
        let hash = blob_hash(&bytes);
        let staged = self.blob_staging_path().context("blob storage disabled")?;
        tokio::fs::create_dir_all(staged.parent().unwrap()).await?;
        tokio::fs::write(&staged, &bytes).await?;
        self.add_blob(space, &staged, hash).await?;
        Ok(hash)
    }

    /// Move a finished blob file (whose hash the caller computed while writing
    /// it) into the store, then push it per the push policy (module docs).
    pub async fn add_blob(&self, space: SpaceId, staged: &Path, hash: Hash32) -> Result<()> {
        let path = self.inner.blob_path(&space, &hash).context("blob storage disabled")?;
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        tokio::fs::rename(staged, &path).await?;
        let len = tokio::fs::metadata(&path).await?.len();
        let me = self.id();
        let targets: Vec<SignPk> = self.with_space(&space, |r| {
            r.members()
                .into_iter()
                .filter(|(k, role)| k.sign_pk != me && (*role == Role::Relay || len <= EAGER_PUSH_MAX))
                .map(|(k, _)| k.sign_pk)
                .collect()
        })?;
        for pk in targets {
            let (inner, path) = (self.inner.clone(), path.clone());
            tokio::spawn(async move {
                let _ = push(&inner, pk, space, hash, &path).await;
            });
        }
        Ok(())
    }

    /// Get a blob: local if present, otherwise from the members that have it.
    pub async fn fetch_blob(&self, space: SpaceId, hash: Hash32) -> Result<PathBuf> {
        self.fetch_blob_with_progress(space, hash, no_progress()).await
    }

    /// [`Node::fetch_blob`], reporting `(bytes, total)` as it downloads.
    /// Downloads from every member that has the blob at once, and resumes a
    /// partial download (from whichever members have it now).
    pub async fn fetch_blob_with_progress(&self, space: SpaceId, hash: Hash32, progress: Progress) -> Result<PathBuf> {
        let path = self.inner.blob_path(&space, &hash).context("blob storage disabled")?;
        if path.is_file() {
            return Ok(path);
        }
        let _lock = WriteLock::acquire(&path).await;
        if path.is_file() {
            return Ok(path); // someone else (a push, another fetch) just finished it
        }
        let me = self.id();
        let mut members: Vec<SignPk> = self.with_space(&space, |r| {
            r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|p| *p != me).collect()
        })?;
        let peers = self.peers();
        members.sort_by_key(|pk| !peers.get(pk).is_some_and(|p| p.online()));
        // A bad copy is only caught by the final hash (it's dropped then):
        // try once more from scratch.
        let mut res = download(&self.inner, members.clone(), space, hash, &path, &progress).await;
        if res.as_ref().is_err_and(|e| e.is::<HashMismatch>()) {
            res = download(&self.inner, members, space, hash, &path, &progress).await;
        }
        res.map(|()| path)
            .map_err(|e| e.context("couldn't download the file from anyone in the conversation"))
    }
}