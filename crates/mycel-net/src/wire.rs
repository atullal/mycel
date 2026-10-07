//! Framing and message types for Mycel's Iroh protocols.

use anyhow::{Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, Sig};
use mycel_sync::{Envelope, EnvelopeId};
use mycel_trust::{EpochId, OpId, SignedOp, SpaceId};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const ALPN_SYNC: &[u8] = b"mycel/sync/1";
pub const ALPN_CARD: &[u8] = b"mycel/card/0";
pub const ALPN_EPH: &[u8] = b"mycel/eph/0";
pub const ALPN_BLOB: &[u8] = b"mycel/blob/0";

pub const MAX_FRAME: usize = 64 * 1024 * 1024;
pub const MAX_BLOB: u64 = 50 * 1024 * 1024;

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

#[derive(Debug, Serialize, Deserialize)]
pub enum BlobReq {
    Get { space: SpaceId, hash: Hash32 },
    /// Followed by `len` raw bytes.
    Put { space: SpaceId, hash: Hash32, len: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BlobResp {
    /// Followed by `len` raw bytes.
    Found { len: u64 },
    NotFound,
    Denied,
    Stored,
}

pub fn blob_hash(bytes: &[u8]) -> Hash32 {
    Hash32::digest("mycel/v0/blob", bytes)
}
