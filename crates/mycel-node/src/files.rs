//! Attachment files on disk: turning what the UI hands us into a readable
//! file (paths, `file://` URLs, folders and macOS packages), streaming
//! encryption into the blob store and decryption out of it, and clear errors
//! when the OS won't let us read something.
//!
//! Everything here is blocking std I/O with bounded buffers; callers run it
//! on `spawn_blocking`.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::{Digest, Hash32, STREAM_MAGIC, SymKey, is_stream, open_stream, seal_stream};

/// Legacy (one-shot) attachments were capped at 50 MiB; anything bigger
/// that isn't a stream is refused rather than read into memory.
const MAX_LEGACY_BLOB: u64 = 64 * 1024 * 1024;
/// Zip entries bigger than this are stored, not deflated (speed).
const DEFLATE_MAX: u64 = 64 * 1024 * 1024;

/// What the UI gave us (a path, or a `file://` URL from a drop or a picker)
/// as a filesystem path.
pub fn local_path(raw: &str) -> PathBuf {
    let s = raw.trim_matches(|c| c == '\n' || c == '\r');
    if let Some(rest) = s.strip_prefix("file://") {
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        let decoded = percent_decode(rest);
        #[cfg(windows)]
        {
            // file:///C:/x → C:/x
            let b = decoded.as_bytes();
            if b.len() > 2 && b[0] == b'/' && b[2] == b':' {
                return PathBuf::from(&decoded[1..]);
            }
        }
        return PathBuf::from(decoded);
    }
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(s)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn in_icloud(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/Library/Mobile Documents/") || s.contains("/Library/CloudStorage/")
}

/// A human explanation of why `path` couldn't be read, keeping the OS error
/// as the cause (shown after a colon with `{:#}`).
pub fn read_error(path: &Path, e: io::Error) -> anyhow::Error {
    let shown = path.display();
    let code = e.raw_os_error();
    // EDEADLK (11) / ETIMEDOUT (60): the iCloud file provider couldn't download a placeholder.
    let icloud_code = cfg!(target_os = "macos") && matches!(code, Some(11) | Some(60));
    let msg = match e.kind() {
        io::ErrorKind::NotFound => format!("can't find {shown} (was it moved or deleted?)"),
        io::ErrorKind::PermissionDenied if cfg!(target_os = "macos") => format!(
            "macOS didn't let Mycel read {shown}. Allow Mycel in System Settings > Privacy & Security > \
             Files and Folders (or Full Disk Access), then try again"
        ),
        io::ErrorKind::PermissionDenied => format!("no permission to read {shown}"),
        _ if code == Some(21) => format!("{shown} is a folder"),
        _ if icloud_code || in_icloud(path) => format!(
            "{shown} is stored in iCloud and couldn't be downloaded. Open it in Finder to download it, then try again"
        ),
        _ => format!("can't read {shown}"),
    };
    anyhow::Error::new(e).context(msg)
}

/// Zip a folder (or a macOS package such as `.app`, `.pages`, `.key`,
/// `.rtfd`) into `out`, keeping its name as the top-level entry, symlinks
/// and unix permissions. Streams file by file.
pub fn zip_dir(dir: &Path, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(out).with_context(|| format!("can't create {}", out.display()))?;
    let mut zip = zip::ZipWriter::new(BufWriter::with_capacity(1 << 20, file));
    let root = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "folder".into());
    add_to_zip(&mut zip, dir, &root)?;
    zip.finish()?.flush()?;
    Ok(())
}

fn add_to_zip<W: Write + io::Seek>(zip: &mut zip::ZipWriter<W>, path: &Path, rel: &str) -> Result<()> {
    use zip::{CompressionMethod, write::SimpleFileOptions};
    let meta = std::fs::symlink_metadata(path).map_err(|e| read_error(path, e))?;
    let opts = SimpleFileOptions::default();
    #[cfg(unix)]
    let opts = {
        use std::os::unix::fs::PermissionsExt;
        opts.unix_permissions(meta.permissions().mode() & 0o7777)
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(path).map_err(|e| read_error(path, e))?;
        zip.add_symlink(rel, target.to_string_lossy(), opts)?;
    } else if ft.is_dir() {
        zip.add_directory(format!("{rel}/"), opts)?;
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| read_error(path, e))?
            .collect::<io::Result<_>>()
            .map_err(|e| read_error(path, e))?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            add_to_zip(zip, &e.path(), &format!("{rel}/{}", e.file_name().to_string_lossy()))?;
        }
    } else if ft.is_file() {
        let method = if meta.len() > DEFLATE_MAX { CompressionMethod::Stored } else { CompressionMethod::Deflated };
        let opts = opts.compression_method(method).large_file(meta.len() >= u32::MAX as u64);
        zip.start_file(rel, opts)?;
        let mut f = File::open(path).map_err(|e| read_error(path, e))?;
        io::copy(&mut f, zip).map_err(|e| read_error(path, e))?;
    }
    // sockets, fifos, devices: skipped
    Ok(())
}

/// Reads the source and writes the same bytes to our plaintext copy,
/// remembering a read error so it can be explained (not just "i/o error").
struct Tee<R, W> {
    src: R,
    copy: W,
    read_err: Option<io::Error>,
}

impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match self.src.read(buf) {
            Ok(n) => n,
            Err(e) => {
                let again = io::Error::new(e.kind(), e.to_string());
                self.read_err = Some(e);
                return Err(again);
            }
        };
        self.copy.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Hashes everything written through it (the blob id).
struct Hashing<W> {
    inner: W,
    digest: Digest,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.digest.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Stream `src` into a sealed blob at `sealed` (hashing it on the way) and a
/// plaintext copy at `plain_copy`, in one pass with bounded memory.
/// Returns the blob hash and the plaintext size.
pub fn seal_file(
    src: &Path,
    plain_copy: &Path,
    sealed: &Path,
    key: &SymKey,
    nonce: &[u8; 24],
    aad: &[u8],
    progress: impl FnMut(u64),
) -> Result<(Hash32, u64)> {
    for p in [plain_copy, sealed] {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
    }
    let input = File::open(src).map_err(|e| read_error(src, e))?;
    let copy = File::create(plain_copy).with_context(|| format!("can't write {}", plain_copy.display()))?;
    let out = File::create(sealed).with_context(|| format!("can't write {}", sealed.display()))?;
    let mut tee = Tee { src: input, copy: BufWriter::with_capacity(1 << 20, copy), read_err: None };
    let mut hashing = Hashing { inner: BufWriter::with_capacity(1 << 20, out), digest: mycel_net::blob_digest() };
    let len = match seal_stream(key, nonce, aad, &mut tee, &mut hashing, progress) {
        Ok(n) => n,
        Err(e) => {
            return Err(match tee.read_err.take() {
                Some(re) => read_error(src, re),
                None => anyhow!("couldn't encrypt {}: {e}", src.display()),
            });
        }
    };
    tee.copy.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    let hash = hashing.digest.finalize();
    hashing.inner.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok((hash, len))
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Decrypt the blob at `blob` into `out`: streamed format if it starts with
/// the stream magic, else the legacy one-shot format. Returns the plaintext size.
pub fn open_file(blob: &Path, out: &Path, key: &SymKey, nonce: &[u8; 24], aad: &[u8]) -> Result<u64> {
    let mut f = File::open(blob)?;
    let mut prefix = [0u8; STREAM_MAGIC.len()];
    let n = read_full(&mut f, &mut prefix)?;
    let mut w = BufWriter::with_capacity(1 << 20, File::create(out)?);
    let len = if is_stream(&prefix[..n]) {
        let mut r = io::Cursor::new(prefix[..n].to_vec()).chain(f);
        open_stream(key, nonce, aad, &mut r, &mut w, |_| {})
            .map_err(|e| anyhow!("attachment failed to decrypt ({e})"))?
    } else {
        if f.metadata()?.len() > MAX_LEGACY_BLOB {
            bail!("attachment has an unknown format");
        }
        let mut ct = prefix[..n].to_vec();
        f.read_to_end(&mut ct)?;
        let plain = key.open(nonce, aad, &ct).map_err(|_| anyhow!("attachment failed to decrypt"))?;
        w.write_all(&plain)?;
        plain.len() as u64
    };
    w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_urls_become_paths() {
        assert_eq!(local_path("file:///Users/a/My%20File.png"), PathBuf::from("/Users/a/My File.png"));
        assert_eq!(local_path("file://localhost/tmp/x"), PathBuf::from("/tmp/x"));
        assert_eq!(local_path("file:///tmp/r%C3%A9sum%C3%A9.pdf"), PathBuf::from("/tmp/résumé.pdf"));
        assert_eq!(local_path("/plain/path 100%.txt"), PathBuf::from("/plain/path 100%.txt"));
        assert_eq!(local_path("file:///bad%zz%"), PathBuf::from("/bad%zz%"));
    }

    #[test]
    fn read_errors_explain_themselves() {
        let e = read_error(Path::new("/x/y"), io::Error::from(io::ErrorKind::NotFound));
        assert!(format!("{e:#}").starts_with("can't find /x/y"));
        let e = read_error(Path::new("/x/y"), io::Error::from_raw_os_error(1));
        let s = format!("{e:#}");
        assert!(s.contains("/x/y") && s.to_lowercase().contains("not permitted"), "{s}");
        #[cfg(target_os = "macos")]
        assert!(s.contains("Privacy & Security"), "{s}");
    }
}
