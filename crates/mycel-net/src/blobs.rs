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
//! order; no `.ranges` means the `.part` is a plain prefix, as keeper pushes and
//! older versions write it). The file is renamed into place only once the
//! BLAKE3 hash of the whole blob matches; an interrupted transfer leaves both
//! behind and the next attempt (from any members that have the blob) fetches
//! only what's missing. Ordinary eager pushes use isolated disposable stages.
//!
//! There is no cumulative member quota. Concurrent remote writes reserve
//! capacity process-wide and keep at least [`MIN_FREE_SPACE`] free. Accepted
//! members can still consume available storage through repeated valid pushes.
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

use crate::resources::PeerFrames;
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

#[cfg(windows)]
fn free_space_at(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0u64;
    // SAFETY: the path is NUL-terminated and `available` is writable; the
    // optional total/free outputs are deliberately omitted.
    (unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, std::ptr::null_mut(), std::ptr::null_mut()) } != 0)
        .then_some(available)
}

#[cfg(not(any(unix, windows)))]
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

/// Conservative process-wide reservation pool. Counting reservations on other
/// volumes too can reject a transfer early, but cannot overcommit one volume.
/// Keep the entire remaining-byte reservation until all writers have stopped;
/// bytes already written may be double-counted briefly, which is conservative.
static RESERVED: LazyLock<Mutex<u64>> = LazyLock::new(Mutex::default);

struct SpaceReservation(u64);

impl SpaceReservation {
    fn acquire(dir: &Path, need: u64) -> Result<Self> {
        let mut reserved = RESERVED.lock();
        Self::claim(&mut reserved, free_space(dir), need)?;
        Ok(Self(need))
    }

    fn claim(reserved: &mut u64, free: Option<u64>, need: u64) -> Result<()> {
        let free = free.context("cannot determine free disk space for blob transfer")?;
        let all = reserved.checked_add(need).context("disk reservation overflow")?;
        if all.checked_add(MIN_FREE_SPACE).is_none_or(|required| free < required) {
            bail!("not enough disk space after active transfers are reserved");
        }
        *reserved = all;
        Ok(())
    }
}

impl Drop for SpaceReservation {
    fn drop(&mut self) {
        *RESERVED.lock() -= self.0;
    }
}

/// Eager pushes never share the resumable `.part` / `.ranges` files used by
/// explicit downloads and keepers. Creation is synchronous so cancellation
/// cannot race a queued blocking open that recreates the file after cleanup.
struct PushStage(PathBuf);

impl PushStage {
    fn create(path: &Path) -> Result<(Self, tokio::fs::File)> {
        let stage = path.with_extension(format!("push.{:016x}", mycel_crypto::random_u64()));
        let file = std::fs::OpenOptions::new().create_new(true).write(true).open(&stage)?;
        Ok((Self(stage), tokio::fs::File::from_std(file)))
    }
}

impl Drop for PushStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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
    mut f: tokio::fs::File,
    offset: u64,
    total: u64,
    digest: &mut Digest,
    progress: &Progress,
) -> Result<()> {
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
            match crate::resources::idle(rx.read(&mut buf[n..want])).await {
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
        crate::resources::write_all(tx, &buf[..n]).await?;
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

/// A `.ranges` file's contents, if they describe a blob of `total` bytes:
/// sorted, disjoint, non-empty ranges within it, as [`Ranges::insert`] keeps
/// them. A damaged file (or one another program wrote) is refused: its
/// ranges would break the resume arithmetic.
fn parse_ranges(bytes: &[u8], total: Option<u64>) -> Option<Ranges> {
    let f: RangesFile = postcard::from_bytes(bytes).ok()?;
    let ranges = &f.done.0;
    let valid = ranges.iter().all(|&(a, b)| a < b && b <= f.total) && ranges.windows(2).all(|w| w[0].1 < w[1].0);
    (valid && total.is_none_or(|t| t == f.total)).then_some(f.done)
}

/// What a `.part` file holds, for a blob of `total` bytes (`None`: unknown yet).
async fn load_done(part: &Path, total: Option<u64>) -> Ranges {
    if let Ok(bytes) = tokio::fs::read(ranges_path(part)).await {
        // stale or damaged: start over
        return parse_ranges(&bytes, total).unwrap_or_default();
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
    let req: BlobReq = recv_small(&mut rx, crate::resources::FIRST_FRAME, &inner.frames(&peer)).await?;
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
    // Application consent is separate from cryptographic membership. Check
    // before even deriving a push path, including the legacy Put protocol.
    let is_push = matches!(&req, BlobReq::Put { .. } | BlobReq::Offer { .. });
    let allowed = allowed && (!is_push || (inner.blob_push_policy)(peer, space));
    let path = allowed.then(|| inner.blob_path(&space, &hash)).flatten();
    // Unsolicited pushes follow the push policy: keepers take any size, other
    // devices only small blobs (big ones they fetch when their user asks).
    // This bounds one push; it is not a cumulative quota for accepted members.
    let push_ok = |len: u64| keeper || len <= EAGER_PUSH_MAX;
    let res = match (req, path) {
        (_, None) => send(&mut tx, &BlobResp::Denied).await,
        (BlobReq::Put { len, .. } | BlobReq::Offer { len, .. }, Some(_)) if !push_ok(len) => {
            send(&mut tx, &BlobResp::Denied).await
        }
        (BlobReq::Get { .. }, Some(path)) => serve_get(inner, &mut tx, &path, None).await,
        (BlobReq::GetFrom { offset, .. }, Some(path)) => serve_get(inner, &mut tx, &path, Some(offset)).await,
        (BlobReq::GetRange { offset, len, .. }, Some(path)) => serve_range(inner, &mut tx, &path, offset, len).await,
        (BlobReq::Put { len, .. }, Some(path)) => {
            let push = IncomingPush { hash, len, handshake: false, keeper };
            serve_put(inner, &mut tx, &mut rx, &path, push).await
        }
        (BlobReq::Offer { len, .. }, Some(path)) => {
            let push = IncomingPush { hash, len, handshake: true, keeper };
            serve_put(inner, &mut tx, &mut rx, &path, push).await
        }
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

/// A blob a member pushes to us.
struct IncomingPush {
    hash: Hash32,
    len: u64,
    /// `Offer` (we answer before the bytes come), not the legacy `Put`.
    handshake: bool,
    /// We are a keeper of the space: we keep partial pushes to resume.
    keeper: bool,
}

async fn serve_put(
    inner: &Arc<Inner>,
    tx: &mut SendStream,
    rx: &mut RecvStream,
    path: &Path,
    push: IncomingPush,
) -> Result<()> {
    let IncomingPush { hash, len, handshake, keeper } = push;
    if path.exists() {
        return send(tx, &BlobResp::Stored).await;
    }
    let Some(_lock) = WriteLock::try_acquire(path) else {
        return send(tx, &if handshake { BlobResp::Busy } else { BlobResp::Denied }).await;
    };
    let resume_part = part_path(path);
    // Only an explicitly configured keeper retains unsolicited partials.
    // Ordinary eager pushes start at zero in an isolated disposable stage.
    let mut offset = if keeper && handshake { load_done(&resume_part, Some(len)).await.prefix() } else { 0 };
    if offset > len {
        offset = 0;
    }
    let mut digest = blob_digest();
    if offset > 0 && hash_prefix(&resume_part, offset, &mut digest).await.is_err() {
        offset = 0;
        digest = blob_digest();
    }
    let dir = path.parent().context("bad blob path")?;
    let Ok(_reservation) = SpaceReservation::acquire(dir, len - offset) else {
        return send(tx, &if handshake { BlobResp::NoSpace } else { BlobResp::Denied }).await;
    };
    tokio::fs::create_dir_all(dir).await?;
    let stage;
    let (part, file) = if keeper {
        let _ = tokio::fs::remove_file(ranges_path(&resume_part)).await;
        let file = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&resume_part).await?;
        (resume_part.as_path(), file)
    } else {
        let (guard, file) = PushStage::create(path)?;
        stage = guard;
        (stage.0.as_path(), file)
    };
    if handshake {
        send(tx, &BlobResp::SendFrom { offset }).await?;
    }
    receive_into(rx, file, offset, len, &mut digest, &no_progress()).await?;
    commit(inner, part, path, hash, &digest).await?;
    if !keeper {
        drop_partial(&resume_part).await;
    }
    send(tx, &BlobResp::Stored).await
}

// ─────────────────────────────── client side ───────────────────────────────

/// Push a stored blob to one member (resuming a partial copy they have).
async fn push(inner: &Arc<Inner>, pk: SignPk, space: SpaceId, hash: Hash32, path: &Path) -> Result<()> {
    let len = tokio::fs::metadata(path).await?.len();
    on_conn!(inner, &pk, |conn| async {
        let (mut tx, mut rx) = open_bi(&conn, StreamKind::Blob).await?;
        send(&mut tx, &BlobReq::Offer { space, hash, len }).await?;
        match recv_small::<BlobResp>(&mut rx, crate::resources::REPLY_TIMEOUT, &inner.reply_frames(&pk)).await? {
            BlobResp::Stored => Ok(()),
            BlobResp::SendFrom { offset } if offset <= len => {
                send_from(&mut tx, path, offset, len, &no_progress()).await?;
                tx.finish()?;
                // The bytes written may still be queued for a slow link.
                let wait = crate::resources::reply_timeout(usize::try_from(len - offset).unwrap_or(usize::MAX));
                match recv_small::<BlobResp>(&mut rx, wait, &inner.reply_frames(&pk)).await? {
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
    // Owned by the workers too: cancelling the parent cannot release capacity
    // while an aborted worker still has pending disk I/O.
    _reservation: SpaceReservation,
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
    Piece {
        id: u64,
        start: u64,
        end: u64,
    },
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
async fn fetch_range(
    conn: &Connection,
    frames: &PeerFrames,
    dl: &Download,
    id: u64,
    start: u64,
    end: u64,
) -> Result<()> {
    let (mut tx, mut rx) = open_bi(conn, StreamKind::Blob).await?;
    let (space, hash) = (dl.space, dl.hash);
    send(&mut tx, &BlobReq::GetRange { space, hash, offset: start, len: end - start }).await?;
    tx.finish()?;
    match recv_small::<BlobResp>(&mut rx, crate::resources::REPLY_TIMEOUT, frames).await? {
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
            match crate::resources::idle(rx.read(&mut buf[n..want])).await {
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
        let res = fetch_range(&conn, &inner.reply_frames(&pk), &dl, id, start, end).await;
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
        match recv_small::<BlobResp>(&mut rx, crate::resources::REPLY_TIMEOUT, &inner.reply_frames(&pk)).await? {
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
async fn download(
    inner: &Arc<Inner>,
    sources: Vec<SignPk>,
    space: SpaceId,
    hash: Hash32,
    path: &Path,
    progress: &Progress,
) -> Result<()> {
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
                    let reservation = SpaceReservation::acquire(dir, total - done.covered().min(total))?;
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
                        _reservation: reservation,
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
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
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
        let mut members: Vec<SignPk> = self
            .with_space(&space, |r| r.members().into_iter().map(|(k, _)| k.sign_pk).filter(|p| *p != me).collect())?;
        let peers = self.peers();
        members.sort_by_key(|pk| !peers.get(pk).is_some_and(|p| p.online()));
        // A bad copy is only caught by the final hash (it's dropped then):
        // try once more from scratch.
        let mut res = download(&self.inner, members.clone(), space, hash, &path, &progress).await;
        if res.as_ref().is_err_and(|e| e.is::<HashMismatch>()) {
            res = download(&self.inner, members, space, hash, &path, &progress).await;
        }
        res.map(|()| path).map_err(|e| e.context("couldn't download the file from anyone in the conversation"))
    }
}

/// For the `blob_ranges` fuzz target: a `.ranges` file read back from
/// disk, then the arithmetic a resumed download does with it. Panics if what
/// loads isn't a valid set of ranges within the blob, or stops being one.
#[cfg(fuzzing)]
pub(crate) fn fuzz_ranges(bytes: &[u8], total: Option<u64>, inserts: &[(u64, u64)]) -> bool {
    let Some(mut done) = parse_ranges(bytes, total) else { return false };
    let f: RangesFile = postcard::from_bytes(bytes).expect("parsed above");
    let total = f.total;
    let check = |done: &Ranges| {
        let missing = done.missing(total);
        let gaps: u64 = missing.iter().map(|(a, b)| b - a).sum();
        assert_eq!(done.covered() + gaps, total, "{done:?} and the gaps {missing:?} cover the blob");
        assert!(done.prefix() <= total);
    };
    check(&done);
    for &(a, b) in inserts {
        done.insert(a.min(total), b.min(total));
        check(&done);
    }
    let saved = postcard::to_allocvec(&RangesFile { total, done: done.clone() }).expect("encodes");
    assert_eq!(parse_ranges(&saved, Some(total)), Some(done), "what we save loads back");
    true
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn reservation_arithmetic_counts_concurrent_writers_and_remaining_resume_bytes() {
        let free = Some(MIN_FREE_SPACE + 100);
        let mut reserved = 0;
        SpaceReservation::claim(&mut reserved, free, 60).unwrap();
        assert!(SpaceReservation::claim(&mut reserved, free, 41).is_err());
        assert_eq!(reserved, 60, "refusal leaves the pool unchanged");
        // A 70-byte resume with a 30-byte prefix reserves only 40 new bytes.
        SpaceReservation::claim(&mut reserved, free, 70 - 30).unwrap();
        assert_eq!(reserved, 100);
        assert!(SpaceReservation::claim(&mut reserved, None, 0).is_err());
        assert!(SpaceReservation::claim(&mut reserved, Some(u64::MAX), u64::MAX).is_err());
    }

    #[tokio::test]
    async fn cancelled_reservation_releases_capacity() {
        let before = *RESERVED.lock();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _reservation = SpaceReservation::acquire(&std::env::temp_dir(), 1).unwrap();
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        assert_eq!(*RESERVED.lock(), before + 1);
        task.abort();
        let _ = task.await;
        assert_eq!(*RESERVED.lock(), before);
    }

    /// Found by fuzzing (`fuzz/fuzz_targets/blob_ranges.rs`): a damaged
    /// `.ranges` file loaded as it was, and a reversed range made the bytes
    /// held underflow (a panic in debug builds; in release ones a wrapped
    /// count that called the download complete). Overlapping or out-of-blob
    /// ranges overstated what was held the same way. Such a file now means
    /// starting the download over.
    #[test]
    fn a_damaged_ranges_file_is_refused() {
        let file = |total: u64, done: &[(u64, u64)]| {
            postcard::to_allocvec(&RangesFile { total, done: Ranges(done.to_vec()) }).unwrap()
        };
        let good = file(100, &[(0, 10), (20, 30)]);
        assert_eq!(parse_ranges(&good, Some(100)), Some(Ranges(vec![(0, 10), (20, 30)])));
        assert_eq!(parse_ranges(&good, None).unwrap().covered(), 20);
        assert_eq!(parse_ranges(&good, Some(99)), None, "for another size: stale");
        for bad in [
            file(100, &[(10, 5)]),           // reversed
            file(100, &[(5, 5)]),            // empty
            file(100, &[(0, 50), (40, 60)]), // overlapping
            file(100, &[(0, 10), (10, 20)]), // touching: insert merges these
            file(100, &[(20, 30), (0, 10)]), // unsorted
            file(100, &[(90, 101)]),         // beyond the blob
            file(u64::MAX, &[(0, u64::MAX), (0, u64::MAX)]),
            b"download ranges".to_vec(),
        ] {
            assert_eq!(parse_ranges(&bad, None), None, "{bad:?}");
        }
        // what a download saves always loads back
        let mut r = Ranges::default();
        for (a, b) in [(50, 60), (0, 10), (10, 20), (55, 70), (99, 100)] {
            r.insert(a, b);
        }
        assert_eq!(parse_ranges(&file(100, &r.0), Some(100)), Some(r));
    }

    #[test]
    fn eager_stage_drop_preserves_download_partials() {
        let dir = std::env::temp_dir().join(format!("mycel-stage-security-{}", mycel_crypto::random_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let part = part_path(&path);
        std::fs::write(&part, b"download prefix").unwrap();
        std::fs::write(ranges_path(&part), b"download ranges").unwrap();
        let (stage, file) = PushStage::create(&path).unwrap();
        let stage_path = stage.0.clone();
        drop(file);
        drop(stage);
        assert!(!stage_path.exists());
        assert_eq!(std::fs::read(&part).unwrap(), b"download prefix");
        assert_eq!(std::fs::read(ranges_path(&part)).unwrap(), b"download ranges");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
