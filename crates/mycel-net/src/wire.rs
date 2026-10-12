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
/// Typing/presence plaintext limit; a full 1024-event queue holds at most
/// 4 MiB of ephemeral payloads. Media uses separate protocols.
pub const MAX_EPHEMERAL: usize = 4 * 1024;
pub(crate) const MAX_EPHEMERAL_CIPHERTEXT: usize = MAX_EPHEMERAL + 16;
// Space, epoch, nonce and postcard length-prefix overhead fit in 128 bytes.
pub(crate) const MAX_EPHEMERAL_FRAME: usize = MAX_EPHEMERAL + 128;

/// Count encoded bytes without allocating, stopping at the caller's budget.
pub(crate) fn encoded_size<T: Serialize + ?Sized>(msg: &T, max: usize) -> Result<usize> {
    struct Count { len: usize, max: usize }
    impl postcard::ser_flavors::Flavor for Count {
        type Output = usize;
        fn try_push(&mut self, _: u8) -> postcard::Result<()> { self.try_extend(&[0]) }
        fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
            self.len = self.len.checked_add(bytes.len()).filter(|n| *n <= self.max)
                .ok_or(postcard::Error::SerializeBufferFull)?;
            Ok(())
        }
        fn finalize(self) -> postcard::Result<usize> { Ok(self.len) }
    }
    Ok(postcard::serialize_with_flavor(msg, Count { len: 0, max })?)
}

pub(crate) fn encode_bounded<T: Serialize>(msg: &T, max: usize) -> Result<Vec<u8>> {
    let len = encoded_size(msg, max)?;
    let mut bytes = vec![0; len];
    let used = postcard::to_slice(msg, &mut bytes)?.len();
    bytes.truncate(used);
    Ok(bytes)
}

pub async fn send<T: Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    // Measure with a capped serializer before any output allocation. The
    // fixed slice also caps a custom serializer that changes between passes.
    let len = encoded_size(msg, MAX_FRAME)?;
    let _permit = crate::resources::frame_bytes(len)?;
    let mut bytes = vec![0; len];
    let bytes = postcard::to_slice(msg, &mut bytes)?;
    crate::resources::write_all(s, &(bytes.len() as u32).to_le_bytes()).await?;
    crate::resources::write_all(s, bytes).await?;
    Ok(())
}

/// Receive a value. Application handlers retaining variable-sized messages
/// across awaits use `recv_held` to retain their encoded-byte reservation.
pub async fn recv<T: DeserializeOwned>(r: &mut RecvStream) -> Result<T> {
    Ok(recv_held(r).await?.0)
}

pub(crate) async fn recv_held<T: DeserializeOwned>(r: &mut RecvStream) -> Result<(T, crate::resources::FramePermit)> {
    recv_held_from(r, crate::resources::HEADER_TIMEOUT, crate::resources::IDLE_TIMEOUT).await
}

#[cfg(test)]
async fn recv_from<T: DeserializeOwned, R: tokio::io::AsyncRead + Unpin>(
    r: &mut R, header_timeout: std::time::Duration, idle_timeout: std::time::Duration,
) -> Result<T> {
    Ok(recv_held_from(r, header_timeout, idle_timeout).await?.0)
}

pub(crate) async fn recv_ephemeral<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<(EphMsg, crate::resources::FramePermit)> {
    let (msg, permit): (EphMsg, _) = recv_held_limited_from(
        r, crate::resources::HEADER_TIMEOUT, crate::resources::IDLE_TIMEOUT, MAX_EPHEMERAL_FRAME,
    ).await?;
    if msg.ciphertext.len() > MAX_EPHEMERAL_CIPHERTEXT { bail!("ephemeral message too large"); }
    Ok((msg, permit))
}

async fn recv_held_from<T: DeserializeOwned, R: tokio::io::AsyncRead + Unpin>(
    r: &mut R, header_timeout: std::time::Duration, idle_timeout: std::time::Duration,
) -> Result<(T, crate::resources::FramePermit)> {
    recv_held_limited_from(r, header_timeout, idle_timeout, MAX_FRAME).await
}

async fn recv_held_limited_from<T: DeserializeOwned, R: tokio::io::AsyncRead + Unpin>(
    r: &mut R, header_timeout: std::time::Duration, idle_timeout: std::time::Duration, max: usize,
) -> Result<(T, crate::resources::FramePermit)> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    tokio::time::timeout(header_timeout, r.read_exact(&mut len)).await??;
    let len = u32::from_le_bytes(len) as usize;
    if len > max.min(MAX_FRAME) { bail!("frame too large"); }
    let _permit = crate::resources::frame_bytes(len)?;
    // A length prefix reserves budget, never a length-sized allocation.
    // Receive bounded chunks, growing only when bytes actually arrive.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    while buf.len() < len {
        let take = chunk.len().min(len - buf.len());
        let got = tokio::time::timeout(idle_timeout, r.read(&mut chunk[..take])).await??;
        if got == 0 { bail!("truncated frame"); }
        if buf.capacity() < buf.len() + got {
            let target = (buf.len() + got).next_power_of_two().min(len);
            buf.reserve_exact(target - buf.len());
        }
        buf.extend_from_slice(&chunk[..got]);
    }
    // The caller retains this reservation until the decoded message has
    // finished processing, including waits for another frame or a reply.
    Ok((postcard::from_bytes(&buf)?, _permit))
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

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::{sync::atomic::{AtomicUsize, Ordering}, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SHORT: Duration = Duration::from_millis(25);

    #[tokio::test]
    async fn security_frame_header_and_body_inactivity_expire() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&[1, 0]).await.unwrap();
        assert!(recv_from::<u8, _>(&mut rx, SHORT, SHORT).await.is_err());
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&(MAX_FRAME as u32).to_le_bytes()).await.unwrap();
        assert!(recv_from::<Vec<u8>, _>(&mut rx, SHORT, SHORT).await.is_err());
        // A stalled maximum-size declaration never reaches a deserializer.
    }

    #[tokio::test]
    async fn security_frames_reject_oversize_truncation_and_bad_encoding() {
        for bytes in [
            ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec(),
            [4u32.to_le_bytes().as_slice(), &[1, 2]].concat(),
            [1u32.to_le_bytes().as_slice(), &[255]].concat(),
        ] {
            assert!(recv_from::<bool, _>(&mut std::io::Cursor::new(bytes), SHORT, SHORT).await.is_err());
        }
    }

    #[test]
    fn security_bounded_serializer_stops_before_processing_large_output() {
        struct Many<'a>(&'a AtomicUsize);
        impl Serialize for Many<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(100_000))?;
                for _ in 0..100_000 {
                    self.0.fetch_add(1, Ordering::Relaxed);
                    seq.serialize_element(&42u8)?;
                }
                seq.end()
            }
        }
        let count = AtomicUsize::new(0);
        assert!(encode_bounded(&Many(&count), 32).is_err());
        assert!(count.load(Ordering::Relaxed) <= 32);
        let message = vec![1u8; 125];
        let encoded = postcard::to_allocvec(&message).unwrap();
        assert_eq!(encode_bounded(&message, encoded.len()).unwrap(), encoded);
        assert!(encode_bounded(&message, encoded.len() - 1).is_err());
    }

    #[tokio::test]
    async fn security_maximum_frame_remains_supported() {
        struct ByteCount(usize);
        impl<'de> Deserialize<'de> for ByteCount {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = ByteCount;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("bytes") }
                    fn visit_borrowed_bytes<E: serde::de::Error>(self, v: &'de [u8]) -> std::result::Result<ByteCount, E> { Ok(ByteCount(v.len())) }
                }
                deserializer.deserialize_bytes(Visitor)
            }
        }
        let payload = MAX_FRAME - 4; // postcard's four-byte length prefix
        let mut prefix = (MAX_FRAME as u32).to_le_bytes().to_vec();
        let len = postcard::to_allocvec(&payload).unwrap();
        assert_eq!(len.len(), 4);
        prefix.extend_from_slice(&len);
        let mut reader = std::io::Cursor::new(prefix).chain(tokio::io::repeat(0).take(payload as u64));
        let count: ByteCount = recv_from(&mut reader, Duration::from_secs(5), Duration::from_secs(5)).await.unwrap();
        assert_eq!(count.0, payload);
    }

    #[tokio::test]
    async fn security_frame_budget_released_after_decode_failure_and_cancellation() {
        let frames = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
        crate::resources::with_frames(frames.clone(), async {
            let bytes = [1u32.to_le_bytes().as_slice(), &[255]].concat();
            assert!(recv_from::<bool, _>(&mut std::io::Cursor::new(bytes), SHORT, SHORT).await.is_err());
        }).await;
        assert_eq!(frames.available_permits(), 64);
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(&64u32.to_le_bytes()).await.unwrap();
        crate::resources::with_frames(frames.clone(), async {
            assert!(tokio::time::timeout(SHORT, recv_from::<u8, _>(&mut rx, Duration::from_secs(5), Duration::from_secs(5))).await.is_err());
        }).await;
        assert_eq!(frames.available_permits(), 64);
    }
    #[tokio::test]
    async fn security_frame_budget_is_held_during_deserialization() {
        struct Checked;
        impl<'de> Deserialize<'de> for Checked {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                let _ = u8::deserialize(deserializer)?;
                assert!(crate::resources::frame_bytes(1).is_err());
                Ok(Checked)
            }
        }
        let frames = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        crate::resources::with_frames(frames.clone(), async {
            let bytes = [1u32.to_le_bytes().as_slice(), &[7]].concat();
            recv_from::<Checked, _>(&mut std::io::Cursor::new(bytes), SHORT, SHORT).await.unwrap();
        }).await;
        assert_eq!(frames.available_permits(), 1);
    }

    #[tokio::test]
    async fn security_frame_read_deadline_resets_after_progress() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let data = vec![42u8; 256];
        let encoded = postcard::to_allocvec(&data).unwrap();
        let writer = tokio::spawn(async move {
            tx.write_all(&(encoded.len() as u32).to_le_bytes()).await.unwrap();
            for chunk in encoded.chunks(32) {
                tokio::time::sleep(Duration::from_millis(30)).await;
                tx.write_all(chunk).await.unwrap();
            }
        });
        let actual: Vec<u8> = recv_from(&mut rx, Duration::from_secs(5), Duration::from_millis(100)).await.unwrap();
        assert_eq!(actual, data);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn security_decoded_message_holds_budget_until_processing_finishes() {
        let encoded = postcard::to_allocvec(&vec![42u8; 63]).unwrap();
        assert_eq!(encoded.len(), 64);
        let bytes = [64u32.to_le_bytes().as_slice(), &encoded].concat();
        let frames = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
        crate::resources::with_frames(frames.clone(), async {
            let (message, permit) = recv_held_from::<Vec<u8>, _>(
                &mut std::io::Cursor::new(bytes.clone()), SHORT, SHORT,
            ).await.unwrap();
            assert_eq!(frames.available_permits(), 0);
            // Waiting for a peer's next frame must not let another stream
            // reserve the same bytes while this decoded value stays alive.
            tokio::task::yield_now().await;
            assert!(recv_held_from::<Vec<u8>, _>(
                &mut std::io::Cursor::new(bytes.clone()), SHORT, SHORT,
            ).await.is_err());
            assert_eq!(message, vec![42; 63]);
            drop(message);
            drop(permit);
            assert!(recv_held_from::<Vec<u8>, _>(
                &mut std::io::Cursor::new(bytes), SHORT, SHORT,
            ).await.is_ok());
        }).await;
        assert_eq!(frames.available_permits(), 64);
    }

    #[tokio::test]
    async fn security_ephemeral_ciphertext_and_frame_limits_precede_decryption() {
        for length in [MAX_EPHEMERAL_CIPHERTEXT, MAX_EPHEMERAL_CIPHERTEXT + 1] {
            let msg = EphMsg { space: Hash32([0; 32]), epoch: EpochId([1; 16]), nonce: [0; 24], ciphertext: vec![0; length] };
            let encoded = postcard::to_allocvec(&msg).unwrap();
            let bytes = [(encoded.len() as u32).to_le_bytes().as_slice(), &encoded].concat();
            let received = recv_ephemeral(&mut std::io::Cursor::new(bytes)).await;
            assert_eq!(received.is_ok(), length == MAX_EPHEMERAL_CIPHERTEXT);
        }
        // Reject the declaration alone, before allocating/decoding its body.
        let bytes = ((MAX_EPHEMERAL_FRAME + 1) as u32).to_le_bytes().to_vec();
        let error = match recv_ephemeral(&mut std::io::Cursor::new(bytes)).await {
            Err(error) => error,
            Ok(_) => panic!("oversized ephemeral frame accepted"),
        };
        assert_eq!(error.to_string(), "frame too large");
    }

}
