//! Chunked, streaming XChaCha20-Poly1305 for attachments of any size
//! (docs/TRUST.md §6, "Attachments").
//!
//! This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015):
//! the plaintext is cut into fixed-size chunks and chunk `i` is sealed with a
//! nonce derived from the attachment nonce and `i`, and with associated data
//! binding the caller's AAD, the chunk size, `i` and a "final chunk" flag.
//! So chunks can't be reordered, dropped, duplicated, truncated at a chunk
//! boundary or extended, and memory use is one chunk regardless of file size.
//!
//! Format (`MYCELBLOB1`):
//! ```text
//! "MYCELBLOB1\0" ‖ chunk_size: u32 LE ‖ sealed chunk 0 ‖ … ‖ sealed chunk n   (n ≥ 0)
//! ```
//! Every chunk but the last carries exactly `chunk_size` plaintext bytes; the
//! last carries `0..=chunk_size` bytes and is sealed with the final flag set.
//! An empty plaintext is a single, empty, final chunk.

use std::io::{Read, Write};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{CryptoError, Result, SymKey};

/// Magic prefix of a streamed attachment blob.
pub const STREAM_MAGIC: &[u8; 11] = b"MYCELBLOB1\0";
/// Magic plus the little-endian `u32` chunk size.
pub const STREAM_HEADER_LEN: usize = STREAM_MAGIC.len() + 4;
/// Default plaintext chunk size: 1 MiB.
pub const STREAM_CHUNK: usize = 1 << 20;
/// Largest chunk size we accept when opening (bounds memory per chunk).
pub const STREAM_MAX_CHUNK: usize = 16 << 20;
/// Poly1305 tag length added to every chunk.
pub const STREAM_TAG: usize = 16;

const CTX_CHUNK: &[u8] = b"mycel/v0/stream-chunk";

/// True if `prefix` (the first bytes of a blob) starts a streamed blob.
pub fn is_stream(prefix: &[u8]) -> bool {
    prefix.starts_with(STREAM_MAGIC)
}

/// Size of the sealed blob for a plaintext of `len` bytes (default chunk size).
pub fn sealed_len(len: u64) -> u64 {
    let chunk = STREAM_CHUNK as u64;
    let chunks = if len == 0 { 1 } else { len.div_ceil(chunk) };
    STREAM_HEADER_LEN as u64 + len + chunks * STREAM_TAG as u64
}

fn chunk_nonce(base: &[u8; 24], index: u64) -> XNonce {
    let mut n = *base;
    for (b, i) in n[16..].iter_mut().zip(index.to_le_bytes()) {
        *b ^= i;
    }
    XNonce::from(n)
}

fn chunk_aad(aad: &[u8], chunk: u32, index: u64, last: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTX_CHUNK.len() + 4 + aad.len() + 13);
    out.extend_from_slice(CTX_CHUNK);
    out.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(&chunk.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.push(last as u8);
    out
}

/// Seals one attachment chunk by chunk.
pub struct StreamSealer {
    aead: XChaCha20Poly1305,
    nonce: [u8; 24],
    aad: Vec<u8>,
    chunk: u32,
    index: u64,
    finished: bool,
}

impl StreamSealer {
    pub fn new(key: &SymKey, nonce: &[u8; 24], aad: &[u8]) -> Self {
        Self::with_chunk_size(key, nonce, aad, STREAM_CHUNK)
    }

    /// Custom chunk size (tests; `1..=STREAM_MAX_CHUNK`).
    pub fn with_chunk_size(key: &SymKey, nonce: &[u8; 24], aad: &[u8], chunk: usize) -> Self {
        assert!((1..=STREAM_MAX_CHUNK).contains(&chunk), "bad chunk size");
        StreamSealer {
            aead: XChaCha20Poly1305::new(&key.0.into()),
            nonce: *nonce,
            aad: aad.to_vec(),
            chunk: chunk as u32,
            index: 0,
            finished: false,
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk as usize
    }

    pub fn header(&self) -> [u8; STREAM_HEADER_LEN] {
        let mut h = [0u8; STREAM_HEADER_LEN];
        h[..STREAM_MAGIC.len()].copy_from_slice(STREAM_MAGIC);
        h[STREAM_MAGIC.len()..].copy_from_slice(&self.chunk.to_le_bytes());
        h
    }

    /// Seal the next chunk: exactly `chunk_size` bytes, or up to that for the last one.
    pub fn seal_chunk(&mut self, plain: &[u8], last: bool) -> Result<Vec<u8>> {
        let full = plain.len() == self.chunk as usize;
        if self.finished || plain.len() > self.chunk as usize || (!last && !full) {
            return Err(CryptoError::Encrypt);
        }
        let aad = chunk_aad(&self.aad, self.chunk, self.index, last);
        let ct = self
            .aead
            .encrypt(&chunk_nonce(&self.nonce, self.index), Payload { msg: plain, aad: &aad })
            .map_err(|_| CryptoError::Encrypt)?;
        self.index += 1;
        self.finished = last;
        Ok(ct)
    }
}

/// Opens a streamed attachment chunk by chunk.
pub struct StreamOpener {
    aead: XChaCha20Poly1305,
    nonce: [u8; 24],
    aad: Vec<u8>,
    chunk: u32,
    index: u64,
    finished: bool,
}

impl StreamOpener {
    /// `header` is the first [`STREAM_HEADER_LEN`] bytes of the blob.
    pub fn new(key: &SymKey, nonce: &[u8; 24], aad: &[u8], header: &[u8]) -> Result<Self> {
        if header.len() < STREAM_HEADER_LEN || !is_stream(header) {
            return Err(CryptoError::Decrypt);
        }
        let chunk = u32::from_le_bytes(header[STREAM_MAGIC.len()..STREAM_HEADER_LEN].try_into().unwrap());
        if chunk == 0 || chunk as usize > STREAM_MAX_CHUNK {
            return Err(CryptoError::Decrypt);
        }
        Ok(StreamOpener {
            aead: XChaCha20Poly1305::new(&key.0.into()),
            nonce: *nonce,
            aad: aad.to_vec(),
            chunk,
            index: 0,
            finished: false,
        })
    }

    /// Size of every sealed chunk except possibly the last.
    pub fn sealed_chunk_size(&self) -> usize {
        self.chunk as usize + STREAM_TAG
    }

    /// Open the next chunk. `last` must be true exactly for the final chunk
    /// (the caller knows it from hitting end of input).
    pub fn open_chunk(&mut self, ct: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished || ct.len() > self.sealed_chunk_size() || (!last && ct.len() != self.sealed_chunk_size()) {
            return Err(CryptoError::Decrypt);
        }
        let aad = chunk_aad(&self.aad, self.chunk, self.index, last);
        let plain = self
            .aead
            .decrypt(&chunk_nonce(&self.nonce, self.index), Payload { msg: ct, aad: &aad })
            .map_err(|_| CryptoError::Decrypt)?;
        self.index += 1;
        self.finished = last;
        Ok(plain)
    }
}

/// Read until `buf` is full or the input ends; returns the bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(CryptoError::Io(e.to_string())),
        }
    }
    Ok(n)
}

fn io(e: std::io::Error) -> CryptoError {
    CryptoError::Io(e.to_string())
}

/// Encrypt all of `src` into `dst` (header + chunks) with bounded memory.
/// `progress` gets the plaintext bytes consumed so far. Returns the plaintext length.
pub fn seal_stream(
    key: &SymKey,
    nonce: &[u8; 24],
    aad: &[u8],
    src: &mut impl Read,
    dst: &mut impl Write,
    progress: impl FnMut(u64),
) -> Result<u64> {
    seal_stream_with(StreamSealer::new(key, nonce, aad), src, dst, progress)
}

/// [`seal_stream`] with a given sealer (custom chunk size in tests).
pub fn seal_stream_with(
    mut sealer: StreamSealer,
    src: &mut impl Read,
    dst: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> Result<u64> {
    dst.write_all(&sealer.header()).map_err(io)?;
    let size = sealer.chunk_size();
    let mut cur = vec![0u8; size];
    let mut next = vec![0u8; size];
    let mut cur_len = read_full(src, &mut cur)?;
    let mut total = cur_len as u64;
    loop {
        // Look ahead one chunk: the current one is final iff nothing follows.
        let next_len = if cur_len == size { read_full(src, &mut next)? } else { 0 };
        let last = next_len == 0;
        dst.write_all(&sealer.seal_chunk(&cur[..cur_len], last)?).map_err(io)?;
        progress(total);
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        total += cur_len as u64;
    }
    dst.flush().map_err(io)?;
    Ok(total)
}

/// Decrypt a streamed blob from `src` (starting at its header) into `dst`.
/// `progress` gets the sealed bytes consumed so far. Returns the plaintext length.
/// Fails on any tampering, truncation or trailing data.
pub fn open_stream(
    key: &SymKey,
    nonce: &[u8; 24],
    aad: &[u8],
    src: &mut impl Read,
    dst: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> Result<u64> {
    let mut header = [0u8; STREAM_HEADER_LEN];
    if read_full(src, &mut header)? != STREAM_HEADER_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut opener = StreamOpener::new(key, nonce, aad, &header)?;
    let size = opener.sealed_chunk_size();
    let mut cur = vec![0u8; size];
    let mut next = vec![0u8; size];
    let mut cur_len = read_full(src, &mut cur)?;
    let mut consumed = (STREAM_HEADER_LEN + cur_len) as u64;
    let mut total = 0u64;
    loop {
        let next_len = if cur_len == size { read_full(src, &mut next)? } else { 0 };
        let last = next_len == 0;
        let plain = opener.open_chunk(&cur[..cur_len], last)?;
        dst.write_all(&plain).map_err(io)?;
        total += plain.len() as u64;
        progress(consumed);
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        consumed += cur_len as u64;
    }
    dst.flush().map_err(io)?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    const AAD: &[u8] = b"mycel/v0/attachment";

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) ^ (i >> 7)) as u8).collect()
    }

    fn seal(key: &SymKey, nonce: &[u8; 24], plain: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let sealer = StreamSealer::with_chunk_size(key, nonce, AAD, chunk);
        seal_stream_with(sealer, &mut &plain[..], &mut out, |_| {}).unwrap();
        out
    }

    fn open(key: &SymKey, nonce: &[u8; 24], ct: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        open_stream(key, nonce, AAD, &mut &ct[..], &mut out, |_| {})?;
        Ok(out)
    }

    #[test]
    fn roundtrip_at_chunk_boundaries() {
        let (k, n) = (SymKey::generate(), random());
        let c = 64;
        for len in [0, 1, c - 1, c, c + 1, 2 * c, 2 * c + 1, 10 * c, 10 * c + 17] {
            let plain = data(len);
            let ct = seal(&k, &n, &plain, c);
            let chunks = if len == 0 { 1 } else { len.div_ceil(c) };
            assert_eq!(ct.len(), STREAM_HEADER_LEN + len + chunks * STREAM_TAG, "len {len}");
            assert!(is_stream(&ct));
            assert_eq!(open(&k, &n, &ct).unwrap(), plain, "len {len}");
        }
    }

    #[test]
    fn default_chunk_size_and_sealed_len() {
        let (k, n) = (SymKey::generate(), random());
        for len in [0, STREAM_CHUNK, 3 * STREAM_CHUNK + 5] {
            let plain = data(len);
            let mut ct = Vec::new();
            let got = seal_stream(&k, &n, AAD, &mut &plain[..], &mut ct, |_| {}).unwrap();
            assert_eq!(got, len as u64);
            assert_eq!(ct.len() as u64, sealed_len(len as u64));
            assert_eq!(open(&k, &n, &ct).unwrap(), plain);
        }
    }

    #[test]
    fn tamper_wrong_key_nonce_or_aad_fail() {
        let (k, n) = (SymKey::generate(), random());
        let ct = seal(&k, &n, &data(1000), 100);
        for i in [0, 5, STREAM_HEADER_LEN, STREAM_HEADER_LEN + 150, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert!(open(&k, &n, &bad).is_err(), "flip at {i}");
        }
        assert!(open(&SymKey::generate(), &n, &ct).is_err());
        assert!(open(&k, &random(), &ct).is_err());
        let mut out = Vec::new();
        assert!(open_stream(&k, &n, b"other", &mut &ct[..], &mut out, |_| {}).is_err());
    }

    #[test]
    fn truncation_and_extension_fail() {
        let (k, n) = (SymKey::generate(), random());
        let c = 100;
        let sealed = c + STREAM_TAG;
        let ct = seal(&k, &n, &data(5 * c), c); // 5 full chunks, the 5th is final
        // drop the final chunk (cut exactly at a chunk boundary)
        assert!(open(&k, &n, &ct[..STREAM_HEADER_LEN + 4 * sealed]).is_err());
        // cut inside a chunk, header only, or nothing at all
        assert!(open(&k, &n, &ct[..ct.len() - 3]).is_err());
        assert!(open(&k, &n, &ct[..STREAM_HEADER_LEN]).is_err());
        assert!(open(&k, &n, &[]).is_err());
        // append a valid-looking chunk, or garbage
        let mut ext = ct.clone();
        ext.extend_from_slice(&ct[STREAM_HEADER_LEN..STREAM_HEADER_LEN + sealed]);
        assert!(open(&k, &n, &ext).is_err());
        let mut ext = ct.clone();
        ext.push(0);
        assert!(open(&k, &n, &ext).is_err());
        // an empty plaintext can't be "extended" either
        let empty = seal(&k, &n, &[], c);
        let mut ext = empty.clone();
        ext.extend_from_slice(&empty[STREAM_HEADER_LEN..]);
        assert!(open(&k, &n, &ext).is_err());
    }

    #[test]
    fn reorder_duplicate_and_chunk_size_change_fail() {
        let (k, n) = (SymKey::generate(), random());
        let c = 100;
        let s = c + STREAM_TAG;
        let ct = seal(&k, &n, &data(3 * c + 10), c);
        let h = STREAM_HEADER_LEN;
        let chunk = |i: usize| &ct[h + i * s..(h + (i + 1) * s).min(ct.len())];
        let swapped = [&ct[..h], chunk(1), chunk(0), chunk(2), chunk(3)].concat();
        assert!(open(&k, &n, &swapped).is_err());
        let dup = [&ct[..h], chunk(0), chunk(0), chunk(2), chunk(3)].concat();
        assert!(open(&k, &n, &dup).is_err());
        // claim a different chunk size in the header
        let mut resized = ct.clone();
        resized[STREAM_MAGIC.len()..h].copy_from_slice(&(c as u32 + 1).to_le_bytes());
        assert!(open(&k, &n, &resized).is_err());
        let mut huge = ct.clone();
        huge[STREAM_MAGIC.len()..h].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&k, &n, &huge).is_err());
    }

    #[test]
    fn legacy_one_shot_is_not_mistaken_for_a_stream() {
        let (k, n) = (SymKey::generate(), random());
        let legacy = k.seal(&n, AAD, b"old attachment").unwrap();
        assert!(!is_stream(&legacy));
        assert!(open(&k, &n, &legacy).is_err());
        assert_eq!(k.open(&n, AAD, &legacy).unwrap(), b"old attachment");
    }

    #[test]
    fn sealer_rejects_misuse() {
        let k = SymKey::generate();
        let mut s = StreamSealer::with_chunk_size(&k, &random(), AAD, 10);
        assert!(s.seal_chunk(&[0; 5], false).is_err(), "short non-final chunk");
        assert!(s.seal_chunk(&[0; 11], true).is_err(), "oversized chunk");
        s.seal_chunk(&[0; 3], true).unwrap();
        assert!(s.seal_chunk(&[0; 3], true).is_err(), "nothing after the final chunk");
    }

    #[test]
    fn digest_matches_one_shot() {
        let bytes = data(10_000);
        let mut d = crate::Digest::new("mycel/v0/blob");
        for part in bytes.chunks(777) {
            d.update(part);
        }
        assert_eq!(d.finalize(), crate::Hash32::digest("mycel/v0/blob", &bytes));
    }
}
