//! Content-addressed, chunked attachments (docs/TRUST.md §7c).
//!
//! A file is a tree. **Leaves** are sealed pieces of the plaintext; **index
//! nodes** list their children. Every node is addressed by the BLAKE3 hash of
//! its bytes as stored (its ciphertext), so any device can hold and serve any
//! node without being able to read it, and a receiver checks each node as it
//! arrives: a bad source is caught at the chunk, not at the end of the file.
//! The reference a message carries is the root's id and the root's key.
//!
//! ```text
//! leaf   = XChaCha20-Poly1305(key, NODE_NONCE, "mycel/v0/chunk-leaf", plaintext piece)
//! index  = "MYCELINDEX1\0" ‖ level: u8 ‖ count: u32 LE ‖ count × (child id: 32 ‖ child length: u32 LE)
//!          ‖ XChaCha20-Poly1305(key, NODE_NONCE, "mycel/v0/chunk-index" ‖ BLAKE3(all of the above),
//!                               count × child key: 32 ‖ hint count: u8 ‖ hints × 32)
//! id     = BLAKE3-derive_key("mycel/v0/chunk", node bytes)
//! ```
//!
//! An index at level 1 lists leaves; at level `n` it lists indexes of level
//! `n − 1`. The child ids and lengths are in the clear, so a device that
//! holds a file for others (a keeper, a cache) can tell which nodes belong
//! to it and whether it has them all, without any key. The child *keys* are
//! sealed: only someone with the root key can open anything.
//!
//! A node's key is derived from that node's content, so no key ever seals
//! two different nodes and the nonce can be a constant. What else goes into
//! the key is the file's **mode**:
//!
//! - **Private** (the default): each key is derived from a fresh random
//!   secret, the node's position and the node's content. The same file sent
//!   twice shares nothing.
//!   Pieces are a fixed size: cutting by content would let their lengths
//!   fingerprint the file to whoever stores them, and buys nothing when
//!   nothing is shared anyway.
//! - **Public**: each key is derived from the node's content alone
//!   (convergent encryption) and the plaintext is cut where its content says
//!   ([`cdc_cut`]). The same bytes give the same nodes on every device, so
//!   they are stored and fetched once, by anyone. The price: whoever has a
//!   file can compute its ids and check who holds or asks for it.
//!
//! A reader doesn't need to know the mode: it follows ids and keys.

use std::io::{Read, Write};
use std::sync::LazyLock;

use crate::{Digest, Hash32, SymKey};

/// Domain of a node's id.
pub const CHUNK_HASH_CTX: &str = "mycel/v0/chunk";
const CTX_LEAF: &[u8] = b"mycel/v0/chunk-leaf";
const CTX_INDEX: &[u8] = b"mycel/v0/chunk-index";
const CTX_INDEX_HEADER: &str = "mycel/v0/chunk-index-header";
const CTX_PRIVATE_KEY: &str = "mycel/v0/chunk-key";
const CTX_PUBLIC_LEAF_KEY: &str = "mycel/v0/chunk-convergent-leaf";
const CTX_PUBLIC_INDEX_KEY: &str = "mycel/v0/chunk-convergent-index";
const CTX_GEAR: &str = "mycel/v0/chunker-gear";
/// Not a secret, and never used with one key for two different nodes: a
/// node's key is derived from that node's content ([`Mode`]), so the same
/// key and nonce can only ever seal the same bytes again.
const NODE_NONCE: [u8; 24] = *b"mycel/v0/chunk-nonce\0\0\0\0";

/// Magic prefix of an index node.
pub const INDEX_MAGIC: &[u8; 12] = b"MYCELINDEX1\0";
/// Poly1305 tag added to every sealed part.
pub const TAG: usize = 16;
/// Private files: every piece but the last is this long.
pub const CHUNK_FIXED: usize = 1 << 20;
/// Public files: no piece but the last is shorter than this ...
pub const CHUNK_MIN: usize = 256 << 10;
/// ... they average about this ...
pub const CHUNK_AVG: usize = 1 << 20;
/// ... and none is longer than this. Also the largest piece a reader takes.
pub const CHUNK_MAX: usize = 4 << 20;
/// Children per index node, at most.
pub const MAX_CHILDREN: usize = 8192;
/// Index levels, at most (8192⁴ pieces: more than any disk).
pub const MAX_LEVEL: u8 = 4;
/// Devices a root may name as likely holders.
pub const MAX_HINTS: usize = 8;
/// The largest sealed leaf.
pub const MAX_LEAF: usize = CHUNK_MAX + TAG;
const INDEX_HEADER: usize = INDEX_MAGIC.len() + 1 + 4;
const INDEX_ENTRY: usize = 32 + 4;
/// The smallest index: one child, no hints.
pub const MIN_INDEX: usize = INDEX_HEADER + INDEX_ENTRY + 32 + 1 + TAG;
/// The largest index: every child, every hint.
pub const MAX_INDEX: usize = INDEX_HEADER + MAX_CHILDREN * (INDEX_ENTRY + 32) + 1 + MAX_HINTS * 32 + TAG;
/// The largest node of either kind.
pub const MAX_NODE: usize = if MAX_LEAF > MAX_INDEX { MAX_LEAF } else { MAX_INDEX };

/// What marks a message's attachment reference as a chunked file: these
/// bytes sit where older references carry a random nonce, followed by one
/// byte of flags and zeros.
pub const CHUNKED_MARKER: &[u8; 14] = b"MYCELCHUNKED1\0";
const FLAG_PUBLIC: u8 = 1;

/// The `nonce` field of a chunked file's reference.
pub fn marker(public: bool) -> [u8; 24] {
    let mut m = [0u8; 24];
    m[..CHUNKED_MARKER.len()].copy_from_slice(CHUNKED_MARKER);
    m[CHUNKED_MARKER.len()] = if public { FLAG_PUBLIC } else { 0 };
    m
}

/// `Some(public)` if a reference's `nonce` field says it is a chunked file,
/// `None` for the older single-blob format.
pub fn parse_marker(nonce: &[u8; 24]) -> Option<bool> {
    nonce.starts_with(CHUNKED_MARKER).then(|| nonce[CHUNKED_MARKER.len()] & FLAG_PUBLIC != 0)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChunkedError {
    /// The bytes are not the node their id names.
    #[error("file piece doesn't match its id (corrupt or wrong data)")]
    Mismatch,
    #[error("malformed file index: {0}")]
    Malformed(&'static str),
    #[error("file piece failed to decrypt")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("file is larger than its message says")]
    TooLarge,
    #[error("i/o error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, ChunkedError>;

fn io(e: std::io::Error) -> ChunkedError {
    ChunkedError::Io(e.to_string())
}

/// A node's id: the hash of its bytes as stored.
pub fn node_id(bytes: &[u8]) -> Hash32 {
    Hash32::digest(CHUNK_HASH_CTX, bytes)
}

// ─────────────────────────────── chunker ───────────────────────────────

/// The gear table: 256 fixed 64-bit values, one per byte value. Part of the
/// format: every device must cut public files at the same places.
static GEAR: LazyLock<[u64; 256]> = LazyLock::new(|| {
    let mut bytes = [0u8; 256 * 8];
    blake3::Hasher::new_derive_key(CTX_GEAR).finalize_xof().fill(&mut bytes);
    let mut table = [0u64; 256];
    for (g, b) in table.iter_mut().zip(bytes.chunks_exact(8)) {
        *g = u64::from_le_bytes(b.try_into().expect("8 bytes"));
    }
    table
});

/// Cut points are where the rolling hash's top bits are zero: two more bits
/// than the average size has up to that size, two fewer after it (22 and 18
/// for 1 MiB), so sizes cluster around the average (FastCDC's normalized
/// chunking). The top bits depend on the last 64 bytes.
fn masks(avg: usize) -> (u64, u64) {
    let bits = avg.max(2).ilog2();
    let top = |n: u32| !0u64 << (64 - n.clamp(1, 63));
    (top(bits + 2), top(bits.saturating_sub(2)))
}

/// Content-defined chunking: the length of the next piece of a public file.
///
/// `buf` starts where the piece starts. It must hold [`CHUNK_MAX`] bytes, or
/// all that is left of the input (`eof`); otherwise this may return `None`
/// (more bytes are needed to decide). The cut depends only on the bytes of
/// the piece itself, so identical stretches of two files are cut alike once
/// a cut falls in the same place, and an insertion moves only nearby cuts.
pub fn cdc_cut(buf: &[u8], eof: bool) -> Option<usize> {
    cdc_cut_with(buf, eof, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX)
}

fn cdc_cut_with(buf: &[u8], eof: bool, min: usize, avg: usize, max: usize) -> Option<usize> {
    let limit = buf.len().min(max);
    if limit > min {
        let gear = &*GEAR;
        let (hard, easy) = masks(avg);
        let mut h = 0u64;
        let middle = avg.min(limit);
        for (i, b) in buf[..limit].iter().enumerate().skip(min) {
            h = (h << 1).wrapping_add(gear[*b as usize]);
            let mask = if i < middle { hard } else { easy };
            if h & mask == 0 {
                return Some(i + 1);
            }
        }
    }
    if limit == max {
        Some(max)
    } else if eof {
        Some(buf.len())
    } else {
        None
    }
}

// ─────────────────────────────── nodes ───────────────────────────────

/// How a file's keys are made (module docs).
#[derive(Clone, Debug)]
pub enum Mode {
    /// Keys from this secret, each node's position and its content. Use a
    /// fresh secret per file ([`Mode::private`]), so that two copies share
    /// nothing; it is not needed again after sealing. A secret used twice
    /// gives the same node for the same content at the same position (which
    /// shows that two files begin alike), but never one key for two
    /// different nodes.
    Private(SymKey),
    /// Keys from each node's content alone.
    Public,
}

impl Mode {
    pub fn private() -> Mode {
        Mode::Private(SymKey::generate())
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Mode::Public)
    }

    fn leaf_key(&self, ordinal: u64, plain: &[u8]) -> SymKey {
        self.node_key(0, ordinal, Hash32::digest(CTX_PUBLIC_LEAF_KEY, plain))
    }

    fn index_key(&self, level: u8, ordinal: u64, header: &[u8], tail: &[u8]) -> SymKey {
        let mut d = Digest::new(CTX_PUBLIC_INDEX_KEY);
        d.update(header).update(tail);
        self.node_key(level, ordinal, d.finalize())
    }

    /// The key of the node at this position with this `content`: a digest
    /// of everything the key will seal and authenticate. Either way the key
    /// depends on the content, which is what lets every node share one
    /// nonce: a key is never used for anything but the node it came from.
    fn node_key(&self, level: u8, ordinal: u64, content: Hash32) -> SymKey {
        match self {
            Mode::Private(secret) => {
                let mut d = Digest::new(CTX_PRIVATE_KEY);
                d.update(&secret.0).update(&[level]).update(&ordinal.to_le_bytes()).update(&content.0);
                SymKey(d.finalize().0)
            }
            Mode::Public => SymKey(content.0),
        }
    }
}

/// A child as its parent's holder of the key sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Child {
    pub id: Hash32,
    pub key: SymKey,
    /// Bytes of the child node as stored.
    pub len: u32,
}

/// Seal one piece of plaintext. Returns the leaf's bytes.
fn seal_leaf(key: &SymKey, plain: &[u8]) -> Result<Vec<u8>> {
    key.seal(&NODE_NONCE, CTX_LEAF, plain).map_err(|_| ChunkedError::Encrypt)
}

/// Check that `bytes` are the node `id` names.
pub fn verify_node(id: &Hash32, bytes: &[u8]) -> Result<()> {
    if node_id(bytes) == *id { Ok(()) } else { Err(ChunkedError::Mismatch) }
}

/// Open a leaf: checks it against its id, then decrypts it.
pub fn open_leaf(id: &Hash32, key: &SymKey, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < TAG || bytes.len() > MAX_LEAF {
        return Err(ChunkedError::Malformed("leaf size"));
    }
    verify_node(id, bytes)?;
    key.open(&NODE_NONCE, CTX_LEAF, bytes).map_err(|_| ChunkedError::Decrypt)
}

fn index_aad(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CTX_INDEX.len() + 32);
    aad.extend_from_slice(CTX_INDEX);
    aad.extend_from_slice(&Hash32::digest(CTX_INDEX_HEADER, header).0);
    aad
}

fn seal_index(
    mode: &Mode,
    level: u8,
    ordinal: u64,
    children: &[Child],
    hints: &[[u8; 32]],
) -> Result<(Vec<u8>, SymKey)> {
    debug_assert!(!children.is_empty() && children.len() <= MAX_CHILDREN && hints.len() <= MAX_HINTS);
    let mut node = Vec::with_capacity(INDEX_HEADER + children.len() * (INDEX_ENTRY + 32) + 1 + hints.len() * 32 + TAG);
    node.extend_from_slice(INDEX_MAGIC);
    node.push(level);
    node.extend_from_slice(&(children.len() as u32).to_le_bytes());
    for c in children {
        node.extend_from_slice(&c.id.0);
        node.extend_from_slice(&c.len.to_le_bytes());
    }
    let mut tail = Vec::with_capacity(children.len() * 32 + 1 + hints.len() * 32);
    for c in children {
        tail.extend_from_slice(&c.key.0);
    }
    tail.push(hints.len() as u8);
    for h in hints {
        tail.extend_from_slice(h);
    }
    let key = mode.index_key(level, ordinal, &node, &tail);
    let sealed = key.seal(&NODE_NONCE, &index_aad(&node), &tail).map_err(|_| ChunkedError::Encrypt)?;
    node.extend_from_slice(&sealed);
    Ok((node, key))
}

/// An index node as anyone can read it: which nodes it lists, not their keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index<'a> {
    /// 1: the children are leaves. Higher: indexes one level down.
    pub level: u8,
    /// Each child's id and its length as stored.
    pub children: Vec<(Hash32, u32)>,
    header: &'a [u8],
    sealed: &'a [u8],
}

impl<'a> Index<'a> {
    /// Read an index node's public part. Everything is bounds-checked: the
    /// bytes may come from anyone.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < MIN_INDEX || bytes.len() > MAX_INDEX {
            return Err(ChunkedError::Malformed("index size"));
        }
        if !bytes.starts_with(INDEX_MAGIC) {
            return Err(ChunkedError::Malformed("not an index"));
        }
        let level = bytes[INDEX_MAGIC.len()];
        if level == 0 || level > MAX_LEVEL {
            return Err(ChunkedError::Malformed("index level"));
        }
        let count =
            u32::from_le_bytes(bytes[INDEX_MAGIC.len() + 1..INDEX_HEADER].try_into().expect("4 bytes")) as usize;
        if count == 0 || count > MAX_CHILDREN {
            return Err(ChunkedError::Malformed("child count"));
        }
        let entries_end = INDEX_HEADER + count * INDEX_ENTRY;
        // the sealed part holds every child's key, the hint count and a tag
        if bytes.len() < entries_end + count * 32 + 1 + TAG {
            return Err(ChunkedError::Malformed("index truncated"));
        }
        let (min, max) = if level == 1 { (TAG, MAX_LEAF) } else { (MIN_INDEX, MAX_INDEX) };
        let mut children = Vec::with_capacity(count);
        for e in bytes[INDEX_HEADER..entries_end].chunks_exact(INDEX_ENTRY) {
            let id = Hash32(e[..32].try_into().expect("32 bytes"));
            let len = u32::from_le_bytes(e[32..].try_into().expect("4 bytes"));
            if (len as usize) < min || len as usize > max {
                return Err(ChunkedError::Malformed("child size"));
            }
            children.push((id, len));
        }
        Ok(Index { level, children, header: &bytes[..entries_end], sealed: &bytes[entries_end..] })
    }

    /// Bytes of all the children as stored.
    pub fn children_len(&self) -> u64 {
        self.children.iter().map(|(_, len)| *len as u64).sum()
    }

    /// Open the sealed part: the children with their keys, and the hints.
    pub fn open(&self, key: &SymKey) -> Result<(Vec<Child>, Vec<[u8; 32]>)> {
        let tail = key.open(&NODE_NONCE, &index_aad(self.header), self.sealed).map_err(|_| ChunkedError::Decrypt)?;
        let keys_len = self.children.len() * 32;
        let hints = tail.get(keys_len).copied().ok_or(ChunkedError::Malformed("index keys"))? as usize;
        if hints > MAX_HINTS || tail.len() != keys_len + 1 + hints * 32 {
            return Err(ChunkedError::Malformed("index hints"));
        }
        let children = self
            .children
            .iter()
            .zip(tail[..keys_len].chunks_exact(32))
            .map(|((id, len), k)| Child { id: *id, key: SymKey(k.try_into().expect("32 bytes")), len: *len })
            .collect();
        let hints = tail[keys_len + 1..].chunks_exact(32).map(|h| h.try_into().expect("32 bytes")).collect();
        Ok((children, hints))
    }
}

/// Check an index node against its id and open it with its key.
pub fn open_index(id: &Hash32, key: &SymKey, bytes: &[u8]) -> Result<(u8, Vec<Child>, Vec<[u8; 32]>)> {
    verify_node(id, bytes)?;
    let index = Index::parse(bytes)?;
    let (children, hints) = index.open(key)?;
    Ok((index.level, children, hints))
}

// ─────────────────────────────── sealing ───────────────────────────────

/// Sizes used when sealing. Readers accept any sizes within the format's
/// limits; public files only share nodes if they were cut with the same ones.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub fixed: usize,
    pub min: usize,
    pub avg: usize,
    pub max: usize,
    pub fanout: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params { fixed: CHUNK_FIXED, min: CHUNK_MIN, avg: CHUNK_AVG, max: CHUNK_MAX, fanout: MAX_CHILDREN }
    }
}

/// What sealing a file produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedFile {
    /// The root index: what a reference names ...
    pub root: Hash32,
    /// ... and the key that opens it.
    pub key: SymKey,
    /// Plaintext bytes.
    pub len: u64,
    /// Bytes of every node as stored (a node listed twice counts twice).
    pub sealed_len: u64,
    /// Nodes in the tree (a node listed twice counts twice).
    pub nodes: u64,
}

struct Level {
    pending: Vec<Child>,
    /// Index nodes sealed at this level so far.
    sealed: u64,
}

struct Builder<'a, F> {
    mode: &'a Mode,
    fanout: usize,
    sink: F,
    /// `levels[0]` collects leaves for level-1 indexes, and so on up.
    levels: Vec<Level>,
    sealed_len: u64,
    nodes: u64,
}

impl<F: FnMut(&Hash32, &[u8]) -> std::io::Result<()>> Builder<'_, F> {
    fn emit(&mut self, bytes: &[u8]) -> Result<Hash32> {
        let id = node_id(bytes);
        (self.sink)(&id, bytes).map_err(io)?;
        self.sealed_len += bytes.len() as u64;
        self.nodes += 1;
        Ok(id)
    }

    /// Add a child at `depth` (0: a leaf). A full index is only sealed when
    /// another child arrives, so the tree never ends in an index of one.
    fn push(&mut self, depth: usize, child: Child) -> Result<()> {
        if depth as u8 >= MAX_LEVEL {
            return Err(ChunkedError::TooLarge);
        }
        if self.levels.len() <= depth {
            self.levels.push(Level { pending: Vec::new(), sealed: 0 });
        }
        if self.levels[depth].pending.len() >= self.fanout {
            let parent = self.seal_level(depth, &[])?;
            self.push(depth + 1, parent)?;
        }
        self.levels[depth].pending.push(child);
        Ok(())
    }

    fn seal_level(&mut self, depth: usize, hints: &[[u8; 32]]) -> Result<Child> {
        let children = std::mem::take(&mut self.levels[depth].pending);
        let ordinal = self.levels[depth].sealed;
        self.levels[depth].sealed += 1;
        let (bytes, key) = seal_index(self.mode, depth as u8 + 1, ordinal, &children, hints)?;
        let id = self.emit(&bytes)?;
        Ok(Child { id, key, len: bytes.len() as u32 })
    }

    /// Seal what is pending, bottom up; the last index is the root.
    fn finish(mut self, hints: &[[u8; 32]]) -> Result<(Child, u64, u64)> {
        let mut depth = 0;
        loop {
            let top = depth + 1 >= self.levels.len();
            let node = self.seal_level(depth, if top { hints } else { &[] })?;
            if top {
                return Ok((node, self.sealed_len, self.nodes));
            }
            self.push(depth + 1, node)?;
            depth += 1;
        }
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
            Err(e) => return Err(io(e)),
        }
    }
    Ok(n)
}

/// Seal all of `src` as a chunked file, with memory bounded by one piece.
/// Every node goes to `sink(id, bytes)` as it is made, children before
/// their parents, the root last. `hints` (private files only: a public
/// file's nodes depend on nothing but its content) are devices likely to
/// hold the file, readable only with the root key. `progress` gets the
/// plaintext bytes consumed so far.
pub fn seal_file(
    mode: &Mode,
    hints: &[[u8; 32]],
    src: &mut impl Read,
    sink: impl FnMut(&Hash32, &[u8]) -> std::io::Result<()>,
    progress: impl FnMut(u64),
) -> Result<SealedFile> {
    seal_file_with(Params::default(), mode, hints, src, sink, progress)
}

/// [`seal_file`] with given sizes (tests: small trees).
pub fn seal_file_with(
    params: Params,
    mode: &Mode,
    hints: &[[u8; 32]],
    src: &mut impl Read,
    sink: impl FnMut(&Hash32, &[u8]) -> std::io::Result<()>,
    mut progress: impl FnMut(u64),
) -> Result<SealedFile> {
    let Params { fixed, min, avg, max, fanout } = params;
    if !(1..=CHUNK_MAX).contains(&fixed) || !(1..=CHUNK_MAX).contains(&max) || min > avg || avg > max {
        return Err(ChunkedError::Malformed("chunk sizes"));
    }
    if !(2..=MAX_CHILDREN).contains(&fanout) {
        return Err(ChunkedError::Malformed("fanout"));
    }
    let hints = if mode.is_public() { &[][..] } else { &hints[..hints.len().min(MAX_HINTS)] };
    let mut b = Builder { mode, fanout, sink, levels: Vec::new(), sealed_len: 0, nodes: 0 };
    let window = if mode.is_public() { max } else { fixed };
    let mut buf = vec![0u8; window];
    let mut have = 0usize;
    let mut eof = false;
    let (mut total, mut leaves) = (0u64, 0u64);
    loop {
        if !eof && have < window {
            let got = read_full(src, &mut buf[have..])?;
            have += got;
            eof = have < window;
        }
        if have == 0 && leaves > 0 {
            break;
        }
        let cut = if mode.is_public() {
            cdc_cut_with(&buf[..have], eof, min, avg, max).ok_or(ChunkedError::Malformed("chunker"))?
        } else {
            have
        };
        let plain = &buf[..cut];
        let key = mode.leaf_key(leaves, plain);
        let sealed = seal_leaf(&key, plain)?;
        let id = b.emit(&sealed)?;
        b.push(0, Child { id, key, len: sealed.len() as u32 })?;
        leaves += 1;
        total += cut as u64;
        progress(total);
        buf.copy_within(cut..have, 0);
        have -= cut;
        if have == 0 && eof {
            break;
        }
    }
    let (root, sealed_len, nodes) = b.finish(hints)?;
    Ok(SealedFile { root: root.id, key: root.key, len: total, sealed_len, nodes })
}

// ─────────────────────────────── opening ───────────────────────────────

/// Decrypt a chunked file into `dst`. `read_node` hands over a node's bytes
/// by id (from the local store); every node is checked against its id and
/// its place in the tree before use. Fails rather than write more than
/// `max_len` plaintext bytes (the size the message gives), so a reference
/// can't unfold into more than it claims. `progress` gets the plaintext
/// bytes written so far. Returns the plaintext length.
pub fn open_file(
    root: &Hash32,
    key: &SymKey,
    max_len: u64,
    mut read_node: impl FnMut(&Hash32) -> std::io::Result<Vec<u8>>,
    dst: &mut impl Write,
    mut progress: impl FnMut(u64),
) -> Result<u64> {
    let mut written = 0u64;
    let root = Child { id: *root, key: key.clone(), len: 0 };
    open_under(&root, None, max_len, &mut read_node, dst, &mut progress, &mut written)?;
    dst.flush().map_err(io)?;
    Ok(written)
}

fn open_under(
    node: &Child,
    expect_level: Option<u8>,
    max_len: u64,
    read_node: &mut impl FnMut(&Hash32) -> std::io::Result<Vec<u8>>,
    dst: &mut impl Write,
    progress: &mut impl FnMut(u64),
    written: &mut u64,
) -> Result<()> {
    let bytes = read_node(&node.id).map_err(io)?;
    let (level, children, _) = open_index(&node.id, &node.key, &bytes)?;
    if expect_level.is_some_and(|l| l != level) {
        return Err(ChunkedError::Malformed("index level out of place"));
    }
    drop(bytes);
    for child in &children {
        if level > 1 {
            open_under(child, Some(level - 1), max_len, read_node, dst, progress, written)?;
            continue;
        }
        let sealed = read_node(&child.id).map_err(io)?;
        if sealed.len() != child.len as usize {
            return Err(ChunkedError::Mismatch);
        }
        let plain = open_leaf(&child.id, &child.key, &sealed)?;
        *written += plain.len() as u64;
        if *written > max_len {
            return Err(ChunkedError::TooLarge);
        }
        dst.write_all(&plain).map_err(io)?;
        progress(*written);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Deterministic, incompressible-looking bytes (xorshift).
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn cuts(data: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let window = &data[at..data.len().min(at + CHUNK_MAX)];
            let n = cdc_cut(window, at + window.len() == data.len()).unwrap();
            out.push(n);
            at += n;
        }
        out
    }

    type Store = HashMap<Hash32, Vec<u8>>;

    fn seal(mode: &Mode, params: Params, data: &[u8]) -> (SealedFile, Store, Vec<Hash32>) {
        let mut store = Store::new();
        let mut order = Vec::new();
        let sealed = seal_file_with(
            params,
            mode,
            &[],
            &mut &data[..],
            |id, bytes| {
                order.push(*id);
                store.insert(*id, bytes.to_vec());
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        (sealed, store, order)
    }

    fn open(f: &SealedFile, store: &Store, max: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        open_file(
            &f.root,
            &f.key,
            max,
            |id| store.get(id).cloned().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)),
            &mut out,
            |_| {},
        )?;
        Ok(out)
    }

    const SMALL: Params = Params { fixed: 64, min: 16, avg: 64, max: 256, fanout: 4 };

    #[test]
    fn the_gear_table_is_fixed() {
        // Part of the format: changing it changes every public file's ids.
        assert_eq!(GEAR[0], 0x69fe_02e1_6fc0_c092, "{:#x}", GEAR[0]);
        assert_eq!(GEAR[255], 0x89c1_b7d1_96c7_fdf2, "{:#x}", GEAR[255]);
        assert_eq!(masks(CHUNK_AVG), (!0 << 42, !0 << 46));
        assert_eq!(GEAR.iter().copied().collect::<std::collections::HashSet<_>>().len(), 256);
    }

    #[test]
    fn cuts_are_deterministic_bounded_and_average_about_a_mebibyte() {
        let data = pseudo_random(48 << 20, 7);
        let a = cuts(&data);
        assert_eq!(a, cuts(&data), "same bytes, same cuts");
        assert_eq!(a.iter().sum::<usize>(), data.len());
        let (last, rest) = a.split_last().unwrap();
        assert!(rest.iter().all(|n| (CHUNK_MIN + 1..=CHUNK_MAX).contains(n)), "{a:?}");
        assert!(*last <= CHUNK_MAX);
        let avg = data.len() / a.len();
        assert!((CHUNK_AVG * 3 / 4..=CHUNK_AVG * 3 / 2).contains(&avg), "average piece {avg}");
    }

    #[test]
    fn known_input_known_cuts() {
        // Pins the chunker: public files only dedup if every build cuts alike.
        let expected = [1_732_440, 1_158_610, 984_222, 1_574_271, 1_229_774, 1_048_854, 660_437];
        assert_eq!(cuts(&pseudo_random(8 << 20, 42)), expected);
    }

    #[test]
    fn cuts_at_the_edges() {
        assert_eq!(cdc_cut(&[], true), Some(0));
        assert_eq!(cdc_cut(&[], false), None);
        assert_eq!(cdc_cut(&[1; 10], true), Some(10));
        assert_eq!(cdc_cut(&[1; CHUNK_MIN], true), Some(CHUNK_MIN), "nothing is cut below the minimum");
        assert_eq!(cdc_cut(&[1; CHUNK_MIN], false), None);
        // constant bytes never hit a cut point: the maximum applies
        let zeros = vec![0u8; CHUNK_MAX + 5];
        assert_eq!(cdc_cut(&zeros, false), Some(CHUNK_MAX));
        assert_eq!(cdc_cut(&zeros[..CHUNK_MAX - 1], false), None, "undecided until the maximum or the end");
        assert_eq!(cdc_cut(&zeros[..CHUNK_MAX - 1], true), Some(CHUNK_MAX - 1));
    }

    #[test]
    fn an_insertion_moves_only_nearby_cuts() {
        let data = pseudo_random(24 << 20, 11);
        let mut edited = data.clone();
        edited.splice(5_000_000..5_000_000, [9u8; 1234]);
        let ends = |d: &[u8]| {
            let mut at = 0;
            cuts(d)
                .into_iter()
                .map(|n| {
                    at += n;
                    d.len() - at // distance from the end: the same for cuts after the edit
                })
                .collect::<std::collections::HashSet<_>>()
        };
        let (a, b) = (ends(&data), ends(&edited));
        let shared = a.intersection(&b).count();
        assert!(shared + 4 >= a.len(), "{shared} of {} cuts survive an insertion", a.len());
    }

    #[test]
    fn round_trips_at_piece_boundaries_in_both_modes() {
        for len in [0usize, 1, 63, 64, 65, 128, 1000, 64 * 4, 64 * 4 + 1, 64 * 16, 64 * 16 + 1, 64 * 70] {
            let data = pseudo_random(len, len as u64 + 1);
            for mode in [Mode::private(), Mode::Public] {
                let (f, store, order) = seal(&mode, SMALL, &data);
                assert_eq!(f.len, len as u64);
                assert_eq!(order.last(), Some(&f.root), "the root is sealed last");
                assert_eq!(f.nodes as usize, order.len());
                assert_eq!(open(&f, &store, len as u64).unwrap(), data, "{len} bytes, {mode:?}");
            }
        }
    }

    #[test]
    fn trees_grow_levels_and_never_end_in_an_index_of_one() {
        // 16 leaves with a fanout of 4: exactly four full level-1 indexes.
        let (f, store, _) = seal(&Mode::private(), SMALL, &pseudo_random(64 * 16, 3));
        let root = Index::parse(&store[&f.root]).unwrap();
        assert_eq!((root.level, root.children.len()), (2, 4));
        // one more leaf: a fifth level-1 index, and a third level
        let (f, store, _) = seal(&Mode::private(), SMALL, &pseudo_random(64 * 16 + 1, 3));
        let root = Index::parse(&store[&f.root]).unwrap();
        assert_eq!((root.level, root.children.len()), (3, 2));
        // exactly one full index is the root itself
        let (f, store, _) = seal(&Mode::private(), SMALL, &pseudo_random(64 * 4, 3));
        let root = Index::parse(&store[&f.root]).unwrap();
        assert_eq!((root.level, root.children.len()), (1, 4));
    }

    #[test]
    fn the_real_sizes_round_trip() {
        let data = pseudo_random(5 * CHUNK_FIXED + 12345, 5);
        for mode in [Mode::private(), Mode::Public] {
            let (f, store, _) = seal(&mode, Params::default(), &data);
            assert_eq!(open(&f, &store, data.len() as u64).unwrap(), data);
            let root = Index::parse(&store[&f.root]).unwrap();
            assert_eq!(root.level, 1);
            assert_eq!(root.children_len() + store[&f.root].len() as u64, f.sealed_len);
            if !mode.is_public() {
                assert_eq!(root.children.len(), 6);
                assert!(root.children[..5].iter().all(|(_, n)| *n as usize == CHUNK_FIXED + TAG));
            }
        }
    }

    #[test]
    fn public_files_share_every_node_and_private_files_none() {
        let data = pseudo_random(64 * 40, 9);
        let (a, sa, _) = seal(&Mode::Public, SMALL, &data);
        let (b, sb, _) = seal(&Mode::Public, SMALL, &data);
        assert_eq!(a, b, "the same content gives the same reference");
        assert_eq!(sa, sb);
        let (c, sc, _) = seal(&Mode::private(), SMALL, &data);
        let (d, sd, _) = seal(&Mode::private(), SMALL, &data);
        assert_ne!(c.root, d.root);
        assert!(sc.keys().all(|id| !sd.contains_key(id)), "nothing in common between two private copies");
        assert!(sc.keys().all(|id| !sa.contains_key(id)));
    }

    #[test]
    fn public_files_share_what_they_have_in_common() {
        let common = pseudo_random(64 * 60, 21);
        let mut other = pseudo_random(700, 22);
        other.extend_from_slice(&common);
        let (_, a, _) = seal(&Mode::Public, SMALL, &common);
        let (_, b, _) = seal(&Mode::Public, SMALL, &other);
        let leaves =
            |s: &Store| s.iter().filter(|(_, v)| !v.starts_with(INDEX_MAGIC)).map(|(k, _)| *k).collect::<Vec<_>>();
        let shared = leaves(&a).iter().filter(|id| b.contains_key(id)).count();
        assert!(
            shared * 2 > leaves(&a).len(),
            "{shared} of {} pieces shared after a prefix was added",
            leaves(&a).len()
        );
    }

    #[test]
    fn a_private_file_hides_repeated_content() {
        let data = vec![7u8; 64 * 8];
        let (_, store, order) = seal(&Mode::private(), SMALL, &data);
        assert_eq!(store.len(), order.len(), "identical pieces seal to different nodes");
        let (_, store, order) = seal(&Mode::Public, SMALL, &data);
        assert!(store.len() < order.len(), "a public file stores a repeated piece once");
    }

    /// Every key in a sealed tree, with the id of the node it opens.
    fn keys_of(f: &SealedFile, store: &Store) -> Vec<(SymKey, Hash32)> {
        let mut out = vec![(f.key.clone(), f.root)];
        let mut at = 0;
        while at < out.len() {
            let (key, id) = out[at].clone();
            at += 1;
            if store[&id].starts_with(INDEX_MAGIC) {
                let (_, children, _) = open_index(&id, &key, &store[&id]).unwrap();
                out.extend(children.into_iter().map(|c| (c.key, c.id)));
            }
        }
        out
    }

    /// The nonce is a constant, so a key must never seal two different
    /// nodes. That holds even for a secret used for two files (which the
    /// runtime never does): they share a key only where they share the node.
    #[test]
    fn a_secret_used_twice_never_gives_one_key_to_two_nodes() {
        let mode = Mode::private();
        let one = pseudo_random(64 * 9, 31);
        // the same length (so the same tree shape), another third piece
        let mut two = one.clone();
        two[64 * 2] ^= 1;
        let (a, sa, _) = seal(&mode, SMALL, &one);
        let (b, sb, _) = seal(&mode, SMALL, &two);
        let mut by_key: HashMap<[u8; 32], Hash32> = HashMap::new();
        let (ka, kb) = (keys_of(&a, &sa), keys_of(&b, &sb));
        assert_eq!(ka.len(), kb.len());
        for (key, id) in ka.iter().chain(&kb) {
            assert_eq!(*by_key.entry(key.0).or_insert(*id), *id, "one key, two different nodes");
        }
        // the pieces they have in common are the same nodes; the changed
        // piece and every index above it are not
        let shared = ka.iter().filter(|k| kb.contains(k)).count();
        assert!(shared > 0 && shared < ka.len(), "{shared} of {}", ka.len());
        assert_ne!(a.key.0, b.key.0);
        assert_eq!(open(&a, &sa, one.len() as u64).unwrap(), one);
        assert_eq!(open(&b, &sb, two.len() as u64).unwrap(), two);
        // and the same file under the same secret is the same file
        assert_eq!(seal(&mode, SMALL, &one).0, a);
    }

    #[test]
    fn tampering_wrong_keys_and_swaps_are_caught_at_the_node() {
        let data = pseudo_random(64 * 9, 4);
        let (f, store, order) = seal(&Mode::private(), SMALL, &data);
        let max = data.len() as u64;
        // a flipped bit anywhere, in any node
        for id in &order {
            for at in [0, store[id].len() / 2, store[id].len() - 1] {
                let mut bad = store.clone();
                bad.get_mut(id).unwrap()[at] ^= 1;
                assert_eq!(open(&f, &bad, max), Err(ChunkedError::Mismatch));
            }
        }
        // the wrong key
        let wrong = SealedFile { key: SymKey::generate(), ..f.clone() };
        assert_eq!(open(&wrong, &store, max), Err(ChunkedError::Decrypt));
        // one leaf served in place of another
        let (a, b) = (order[0], order[1]);
        let mut swapped = store.clone();
        swapped.insert(a, store[&b].clone());
        assert_eq!(open(&f, &swapped, max), Err(ChunkedError::Mismatch));
        // a missing node
        let mut missing = store.clone();
        missing.remove(&order[2]);
        assert!(matches!(open(&f, &missing, max), Err(ChunkedError::Io(_))));
        // more plaintext than the message said
        assert_eq!(open(&f, &store, max - 1), Err(ChunkedError::TooLarge));
        assert_eq!(open(&f, &store, max).unwrap(), data);
    }

    #[test]
    fn a_leaf_does_not_open_as_an_index_or_the_other_way_round() {
        let (f, store, order) = seal(&Mode::private(), SMALL, &pseudo_random(200, 8));
        let root = store[&f.root].clone();
        assert!(open_leaf(&f.root, &f.key, &root).is_err());
        let leaf = store[&order[0]].clone();
        assert!(matches!(open_index(&order[0], &f.key, &leaf), Err(ChunkedError::Malformed(_))));
    }

    #[test]
    fn index_parsing_rejects_what_does_not_fit() {
        let (f, store, _) = seal(&Mode::private(), SMALL, &pseudo_random(64 * 3, 2));
        let good = store[&f.root].clone();
        assert!(Index::parse(&good).is_ok());
        let patched = |at: usize, bytes: &[u8]| {
            let mut b = good.clone();
            b[at..at + bytes.len()].copy_from_slice(bytes);
            b
        };
        let level = INDEX_MAGIC.len();
        assert!(Index::parse(&patched(0, b"X")).is_err(), "magic");
        assert!(Index::parse(&patched(level, &[0])).is_err(), "level 0");
        assert!(Index::parse(&patched(level, &[MAX_LEVEL + 1])).is_err(), "too deep");
        assert!(Index::parse(&patched(level + 1, &0u32.to_le_bytes())).is_err(), "no children");
        assert!(Index::parse(&patched(level + 1, &(MAX_CHILDREN as u32 + 1).to_le_bytes())).is_err(), "too many");
        assert!(Index::parse(&patched(level + 1, &100u32.to_le_bytes())).is_err(), "more children than bytes");
        let first_len = INDEX_HEADER + 32;
        assert!(Index::parse(&patched(first_len, &(MAX_LEAF as u32 + 1).to_le_bytes())).is_err(), "oversized leaf");
        assert!(Index::parse(&patched(first_len, &0u32.to_le_bytes())).is_err(), "leaf without a tag");
        assert!(Index::parse(&good[..good.len() - 40]).is_err(), "truncated");
        assert!(Index::parse(&[]).is_err());
        // a changed child list no longer matches the sealed keys
        let mut relisted = good.clone();
        relisted[INDEX_HEADER] ^= 1;
        assert_eq!(Index::parse(&relisted).unwrap().open(&f.key), Err(ChunkedError::Decrypt));
    }

    #[test]
    fn hints_travel_sealed_in_a_private_root_only() {
        let hints = [[1u8; 32], [2u8; 32]];
        let data = pseudo_random(300, 6);
        let run = |mode: &Mode| {
            let mut store = Store::new();
            let f = seal_file_with(
                SMALL,
                mode,
                &hints,
                &mut &data[..],
                |id, b| {
                    store.insert(*id, b.to_vec());
                    Ok(())
                },
                |_| {},
            )
            .unwrap();
            let (_, _, got) = open_index(&f.root, &f.key, &store[&f.root]).unwrap();
            (got, store[&f.root].clone())
        };
        let (got, root) = run(&Mode::private());
        assert_eq!(got, hints.to_vec());
        assert!(!root.windows(32).any(|w| w == [1u8; 32]), "hints are not in the clear");
        assert!(run(&Mode::Public).0.is_empty(), "a public file depends on nothing but its content");
    }

    #[test]
    fn markers_tell_the_formats_apart() {
        assert_eq!(parse_marker(&marker(false)), Some(false));
        assert_eq!(parse_marker(&marker(true)), Some(true));
        assert_eq!(parse_marker(&[0u8; 24]), None);
        assert_eq!(parse_marker(&crate::random()), None);
    }

    #[test]
    fn a_sink_error_stops_sealing() {
        let data = pseudo_random(64 * 5, 1);
        let mut n = 0;
        let res = seal_file_with(
            SMALL,
            &Mode::Public,
            &[],
            &mut &data[..],
            |_, _| {
                n += 1;
                if n == 3 { Err(std::io::Error::other("disk full")) } else { Ok(()) }
            },
            |_| {},
        );
        assert!(matches!(res, Err(ChunkedError::Io(e)) if e.contains("disk full")));
    }
}
