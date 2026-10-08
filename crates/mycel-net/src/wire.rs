//! Framing and message types for Mycel's Iroh protocols.

use anyhow::{Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, Sig};
use mycel_sync::{Envelope, EnvelopeId};
use mycel_trust::{EpochId, OpId, SignedOp, SpaceId};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Mycel's protocol. One QUIC connection per pair of devices carries every
/// exchange (sync sessions, contact cards, ephemeral messages, blob
/// transfers) as its own QUIC stream, so there is no handshake per exchange
/// and QUIC stream priorities put chat ahead of file bytes. (Replaces the
/// per-exchange-connection ALPNs `mycel/sync/1`, `mycel/card/0`,
/// `mycel/eph/0`, `mycel/blob/0`.)
pub const ALPN: &[u8] = b"mycel/2";

/// The first byte of every stream on [`ALPN`]: what the stream carries. (A
/// label, like HTTP/3's stream types; QUIC does the multiplexing.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamKind {
    /// Bi-stream: one sync session (see crate docs).
    Sync = 1,
    /// Bi-stream: the client sends nothing more, the server sends its card.
    Card = 2,
    /// Uni-stream: one ephemeral message.
    Ephemeral = 3,
    /// Bi-stream: one blob request (see `blobs.rs`).
    Blob = 4,
}

impl StreamKind {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => StreamKind::Sync,
            2 => StreamKind::Card,
            3 => StreamKind::Ephemeral,
            4 => StreamKind::Blob,
            _ => return None,
        })
    }

    /// noq stream priority (higher is sent first within a connection):
    /// messages, cards and presence ahead of bulk file bytes.
    pub fn priority(self) -> i32 {
        match self {
            StreamKind::Blob => -1,
            _ => 1,
        }
    }
}

pub const MAX_FRAME: usize = 64 * 1024 * 1024;

pub async fn send<T: Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    if bytes.len() > MAX_FRAME {
        bail!("frame too large");
    }
    s.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    s.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv<T: DeserializeOwned>(r: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub ops: Vec<OpId>,
    pub envelopes: Vec<EnvelopeId>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Data {
    pub ops: Vec<SignedOp>,
    pub envelopes: Vec<Envelope>,
}

/// A store-and-forward bundle's payload: what a member may lack of a space
/// (all signed and encrypted; carriers can't read it).
#[derive(Debug, Serialize, Deserialize)]
pub struct DtnPayload {
    pub space: SpaceId,
    pub data: Data,
}

/// Sync protocol (strictly alternating, see crate docs).
#[derive(Debug, Serialize, Deserialize)]
pub enum SyncMsg {
    /// `invite` carries every membership op when pushing a space to a device
    /// that may not have it yet.
    Hello {
        space: SpaceId,
        inv: Inventory,
        invite: Option<Vec<SignedOp>>,
    },
    Denied,
    /// You were removed: here is the proof (revocation + its causal past).
    Removed { ops: Vec<SignedOp> },
    /// Server doesn't know the space; resend Hello with `invite`.
    NeedInvite,
    Accept { inv: Inventory, want: Inventory },
    DataAndWant { data: Data, want: Inventory },
    Data { data: Data },
}

/// A device's public, self-signed contact card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub keys: MemberKeys,
    pub name: String,
    pub sig: Sig,
}

const CTX_CARD: &str = "mycel/v0/contact-card";

impl ContactCard {
    pub fn new(keys: &DeviceKeys, name: &str) -> Self {
        let public = keys.public();
        let name: String = name.chars().take(64).collect();
        let sig = keys.sign(CTX_CARD, &[&postcard::to_allocvec(&public).unwrap(), name.as_bytes()]);
        ContactCard { keys: public, name, sig }
    }

    pub fn verify(&self) -> Result<()> {
        self.keys.verify_binding()?;
        self.keys.sign_pk.verify(
            CTX_CARD,
            &[&postcard::to_allocvec(&self.keys)?, self.name.as_bytes()],
            &self.sig,
        )?;
        Ok(())
    }
}

/// Ephemeral message (typing, presence), encrypted under the space's current epoch.
/// The sender is the authenticated QUIC peer, so no extra signature is needed.
#[derive(Debug, Serialize, Deserialize)]
pub struct EphMsg {
    pub space: SpaceId,
    pub epoch: EpochId,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn eph_aad(space: &SpaceId, sender: &[u8; 32]) -> Vec<u8> {
    [b"mycel/v0/ephemeral".as_slice(), &space.0, sender].concat()
}

/// Blob requests (see `blobs.rs`). New variants are only ever appended, so
/// older peers' requests keep decoding.
#[derive(Debug, Serialize, Deserialize)]
pub enum BlobReq {
    /// Whole blob (original protocol). Answered with `Found{len}` + bytes.
    Get { space: SpaceId, hash: Hash32 },
    /// Followed by `len` raw bytes, no handshake (original protocol).
    Put { space: SpaceId, hash: Hash32, len: u64 },
    /// Bytes from `offset` on (resume). Answered with `Range` + bytes.
    GetFrom { space: SpaceId, hash: Hash32, offset: u64 },
    /// Offer to push `len` bytes. Answered with `Stored` (already have it),
    /// `SendFrom`, `NoSpace`, `Busy` or `Denied`.
    Offer { space: SpaceId, hash: Hash32, len: u64 },
    /// Exactly bytes `[offset, offset + len)` (clamped to the blob), for
    /// downloading disjoint ranges from several members at once. `len` 0
    /// just asks whether they have it and how big it is. Answered with
    /// `Range{total, offset}` + those bytes, `NotFound` or `Denied`.
    GetRange { space: SpaceId, hash: Hash32, offset: u64, len: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BlobResp {
    /// Followed by `len` raw bytes.
    Found { len: u64 },
    NotFound,
    Denied,
    Stored,
    /// Followed by bytes `[offset, total)`. `offset` may be lower than asked.
    Range { total: u64, offset: u64 },
    /// Send bytes `[offset, len)` (we already hold the first `offset`).
    SendFrom { offset: u64 },
    /// Accepting it would leave too little free disk space.
    NoSpace,
    /// Another transfer of this blob is in progress.
    Busy,
}

pub const BLOB_HASH_CTX: &str = "mycel/v0/blob";

/// A blob's id: domain-separated BLAKE3 of its (encrypted) bytes.
pub fn blob_hash(bytes: &[u8]) -> Hash32 {
    Hash32::digest(BLOB_HASH_CTX, bytes)
}
