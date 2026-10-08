//! Blobs: immutable, content-addressed (BLAKE3), already-encrypted bytes of
//! any size, stored per space and streamed between members over QUIC.
//!
//! Protocol (ALPN `mycel/blob/0`, one bi-stream per transfer):
//!
//! ```text
//! fetch:  C → S  GetFrom{space, hash, offset}     S → C  Range{total, offset'} ‖ bytes[offset'..total]
//! push:   C → S  Offer{space, hash, len}          S → C  Stored (have it) | SendFrom{offset} | NoSpace | Busy | Denied
//!         C → S  bytes[offset..len]               S → C  Stored
//! ```
//! (`Get` and `Put` are the original whole-blob requests; still served.)
//!
//! Bytes go straight between the QUIC stream and disk in small buffers, so
//! memory stays bounded whatever the size. Data lands in `<hash>.part` and is
//! renamed into place only once the BLAKE3 hash of the whole blob matches; an
//! interrupted transfer leaves the `.part` behind and the next attempt (from
//! any member that has the blob) resumes from where it stopped.
//!
//! There's no size limit and no quota. The only guard is free disk space: a
//! transfer that would leave less than [`MIN_FREE_SPACE`] free is refused.
//!
//! Push policy: blobs up to [`EAGER_PUSH_MAX`] are pushed to every member when
//! posted; bigger ones are pushed only to keepers (whose job is to hold data
//! while the sender is offline) and members fetch them on demand, from the
//! sender, a keeper or any member that already downloaded them. Receivers
//! enforce it too: only a keeper accepts an unsolicited push above the limit.

use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use mycel_crypto::{Digest, Hash32, SignPk};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::wire::*;
use crate::{Inner, NetEvent, Node, connect, to_sign_pk};

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

// ─────────────────────────────── server side ───────────────────────────────

pub(crate) async fn serve(inner: &Arc<Inner>, conn: Connection) -> Result<()> {
    let peer = to_sign_pk(&conn.remote_id());
    let (mut tx, mut rx) = conn.accept_bi().await?;
    let req: BlobReq = recv(&mut rx).await?;
    let (space, hash) = match &req {
        BlobReq::Get { space, hash }
        | BlobReq::Put { space, hash, .. }
        | BlobReq::GetFrom { space, hash, .. }
        | BlobReq::Offer { space, hash, .. } => (*space, *hash),
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
        (BlobReq::Get { .. }, Some(path)) => serve_get(&mut tx, &path, None).await,
        (BlobReq::GetFrom { offset, .. }, Some(path)) => serve_get(&mut tx, &path, Some(offset)).await,
        (BlobReq::Put { len, .. }, Some(path)) => serve_put(inner, &mut tx, &mut rx, &path, hash, len, false).await,
        (BlobReq::Offer { len, .. }, Some(path)) => serve_put(inner, &mut tx, &mut rx, &path, hash, len, true).await,
    };
    let _ = tx.finish();
    // Let the client read everything before the connection goes away.
    conn.closed().await;
    res
}

async fn serve_get(tx: &mut SendStream, path: &Path, offset: Option<u64>) -> Result<()> {
    let len = match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() => m.len(),
        _ => return send(tx, &BlobResp::NotFound).await,
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
    send_from(tx, path, start, len, &no_progress()).await
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
    // Legacy `Put` streams from 0 without asking; `Offer` can resume.
    let mut offset = if handshake { part_len(&part).await } else { 0 };
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
    let conn = connect(inner, &pk, ALPN_BLOB).await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    send(&mut tx, &BlobReq::Offer { space, hash, len }).await?;
    let res = match recv::<BlobResp>(&mut rx).await? {
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
    };
    conn.close(0u32.into(), b"done");
    res
}

/// Fetch a blob from one member into `path`, resuming from `<path>.part`.
async fn fetch_from(
    inner: &Arc<Inner>,
    pk: SignPk,
    space: SpaceId,
    hash: Hash32,
    path: &Path,
    progress: &Progress,
) -> Result<()> {
    let part = part_path(path);
    let have = part_len(&part).await;
    let conn = connect(inner, &pk, ALPN_BLOB).await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    send(&mut tx, &BlobReq::GetFrom { space, hash, offset: have }).await?;
    tx.finish()?;
    let res = async {
        let (total, offset) = match recv::<BlobResp>(&mut rx).await? {
            BlobResp::Range { total, offset } if offset <= have.min(total) => (total, offset),
            other => bail!("not available: {other:?}"),
        };
        let dir = path.parent().context("bad blob path")?;
        tokio::fs::create_dir_all(dir).await?;
        ensure_free_space(dir, total - offset)?;
        let mut digest = blob_digest();
        if offset > 0 {
            hash_prefix(&part, offset, &mut digest).await?;
        }
        receive_into(&mut rx, &part, offset, total, &mut digest, progress).await?;
        commit(inner, &part, path, hash, &digest).await
    }
    .await;
    conn.close(0u32.into(), b"done");
    res
}

impl Node {
    /// Local path of a blob we hold completely.
    pub fn blob_path(&self, space: &SpaceId, hash: &Hash32) -> Option<PathBuf> {
        self.inner.blob_path(space, hash).filter(|p| p.is_file())
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

    /// Get a blob: local if present, otherwise from any member that has it.
    pub async fn fetch_blob(&self, space: SpaceId, hash: Hash32) -> Result<PathBuf> {
        self.fetch_blob_with_progress(space, hash, no_progress()).await
    }

    /// [`Node::fetch_blob`], reporting `(bytes, total)` as it downloads.
    /// Resumes a partial download, from whichever member has the blob.
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
        let mut last_err = None;
        for pk in members {
            // A resumed prefix that turns out to be bad is dropped; retry once from scratch.
            for _ in 0..2 {
                match fetch_from(&self.inner, pk, space, hash, &path, &progress).await {
                    Ok(()) => return Ok(path),
                    Err(e) => {
                        let retry = e.is::<HashMismatch>();
                        last_err = Some(e);
                        if !retry {
                            break;
                        }
                    }
                }
            }
        }
        Err(match last_err {
            Some(e) => e.context("couldn't download the file from anyone in the conversation"),
            None => anyhow!("nobody else in the conversation has this file"),
        })
    }
}
