//! Mycel cryptographic primitives (see docs/TRUST.md §2).
//!
//! Thin, opinionated wrappers over vetted crates. No custom cryptography:
//! - Ed25519 signatures (`ed25519-dalek`, strict verification)
//! - HPKE RFC 9180 lockboxes: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305
//! - XChaCha20-Poly1305 content encryption
//! - BLAKE3 for ids and key commitments
//! - Chunked streaming XChaCha20-Poly1305 (STREAM) for attachments of any size
//!
//! Every signature / hash / HPKE `info` is domain-separated with a context string.

use std::fmt;

pub mod stream;
pub use stream::{
    STREAM_CHUNK, STREAM_HEADER_LEN, STREAM_MAGIC, StreamOpener, StreamSealer, is_stream, open_stream, seal_stream,
    sealed_len,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HpkeKem = hpke::kem::X25519HkdfSha256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid public key")]
    BadPublicKey,
    #[error("decryption failed")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("os randomness unavailable")]
    Rng,
    #[error("i/o error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS CSPRNG unavailable");
    out
}

pub fn random_u64() -> u64 {
    u64::from_le_bytes(random())
}

/// Length-prefix the context so `ctx ‖ msg` boundaries are unambiguous.
fn framed(ctx: &str, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(1 + ctx.len() + len);
    out.push(u8::try_from(ctx.len()).expect("context string too long"));
    out.extend_from_slice(ctx.as_bytes());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

// ───────────────────────────── ids ─────────────────────────────

/// A 32-byte BLAKE3 digest used for op / envelope / space ids.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Domain-separated BLAKE3 (`derive_key` mode keyed by the context).
    pub fn digest(ctx: &str, bytes: &[u8]) -> Self {
        let mut h = blake3::Hasher::new_derive_key(ctx);
        h.update(bytes);
        Hash32(*h.finalize().as_bytes())
    }
}

/// Incremental [`Hash32::digest`]: same result for the same bytes, fed in pieces.
#[derive(Clone)]
pub struct Digest(blake3::Hasher);

impl Digest {
    pub fn new(ctx: &str) -> Self {
        Digest(blake3::Hasher::new_derive_key(ctx))
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    pub fn finalize(&self) -> Hash32 {
        Hash32(*self.0.finalize().as_bytes())
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.0)[..12])
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ─────────────────────────── signatures ───────────────────────────

/// Ed25519 public key. Also the device's Iroh node id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignPk(pub [u8; 32]);

impl SignPk {
    pub fn verify(&self, ctx: &str, msg: &[&[u8]], sig: &Sig) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::BadPublicKey)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify_strict(&framed(ctx, msg), &sig).map_err(|_| CryptoError::BadSignature)
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Debug for SignPk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pk:{}", self.short())
    }
}

/// Ed25519 signature (64 bytes; serde as a byte string).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sig(pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sig:{}", hex::encode(&self.0[..4]))
    }
}

impl Serialize for Sig {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        let arr: [u8; 64] = v.try_into().map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        Ok(Sig(arr))
    }
}

/// X25519 public key used for HPKE lockboxes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KexPk(pub [u8; 32]);

impl fmt::Debug for KexPk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kex:{}", hex::encode(&self.0[..4]))
    }
}

/// Public identity of a member device, with a self-signature binding the kex key
/// to the signing key (TRUST.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberKeys {
    pub sign_pk: SignPk,
    pub kex_pk: KexPk,
    pub kex_sig: Sig,
}

const CTX_KEX_BINDING: &str = "mycel/v0/kex-binding";

impl MemberKeys {
    pub fn verify_binding(&self) -> Result<()> {
        self.sign_pk.verify(CTX_KEX_BINDING, &[&self.kex_pk.0], &self.kex_sig)
    }
}

/// A device's secret keys, derived from a single 32-byte seed so only the seed
/// needs to live in the OS keychain.
#[derive(ZeroizeOnDrop)]
pub struct DeviceKeys {
    seed: [u8; 32],
    #[zeroize(skip)]
    sign: SigningKey,
    #[zeroize(skip)]
    kex_sk: <HpkeKem as hpke::Kem>::PrivateKey,
    #[zeroize(skip)]
    public: MemberKeys,
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self::from_seed(random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sign = SigningKey::from_bytes(&seed);
        let kex_ikm = blake3::derive_key("mycel/v0/kex-seed", &seed);
        let (kex_sk, kex_pk) = HpkeKem::derive_keypair(&kex_ikm);
        let kex_pk = KexPk(kex_pk.to_bytes().as_slice().try_into().expect("x25519 pk is 32 bytes"));
        let sign_pk = SignPk(sign.verifying_key().to_bytes());
        let kex_sig = Sig(sign.sign(&framed(CTX_KEX_BINDING, &[&kex_pk.0])).to_bytes());
        DeviceKeys { seed, sign, kex_sk, public: MemberKeys { sign_pk, kex_pk, kex_sig } }
    }

    /// The seed, for persisting in the OS keychain. Handle with care.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public(&self) -> MemberKeys {
        self.public
    }

    pub fn sign_pk(&self) -> SignPk {
        self.public.sign_pk
    }

    pub fn sign(&self, ctx: &str, msg: &[&[u8]]) -> Sig {
        Sig(self.sign.sign(&framed(ctx, msg)).to_bytes())
    }

    pub fn open_lockbox(&self, info: &[u8], lockbox: &Lockbox) -> Result<Vec<u8>> {
        let encapped =
            <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&lockbox.enc).map_err(|_| CryptoError::Decrypt)?;
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &self.kex_sk,
            &encapped,
            info,
            &lockbox.ct,
            b"",
        )
        .map_err(|_| CryptoError::Decrypt)
    }
}

// ─────────────────────────── lockboxes ───────────────────────────

/// An HPKE-sealed secret addressed to one recipient's kex key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockbox {
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}

pub fn seal_lockbox(recipient: &KexPk, info: &[u8], plaintext: &[u8]) -> Result<Lockbox> {
    let pk = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(&recipient.0).map_err(|_| CryptoError::BadPublicKey)?;
    let (enc, ct) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeS::Base, &pk, info, plaintext, b"")
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Lockbox { enc: enc.to_bytes().to_vec(), ct })
}

// ─────────────────────── symmetric content keys ───────────────────────

/// A 256-bit symmetric key (epoch key). Zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SymKey(pub [u8; 32]);

impl fmt::Debug for SymKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymKey(…)")
    }
}

impl SymKey {
    pub fn generate() -> Self {
        SymKey(random())
    }

    /// Public commitment to this key (TRUST.md §4) — lets recipients detect a
    /// rotator handing different members different keys.
    pub fn commitment(&self) -> Hash32 {
        Hash32(blake3::derive_key("mycel/v0/epoch-commit", &self.0))
    }

    /// XChaCha20-Poly1305 with a fresh random 192-bit nonce.
    pub fn seal(&self, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        XChaCha20Poly1305::new(&self.0.into())
            .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Encrypt)
    }

    pub fn open(&self, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        XChaCha20Poly1305::new(&self.0.into())
            .decrypt(&XNonce::from(*nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_with_domain_separation() {
        let d = DeviceKeys::generate();
        let sig = d.sign("mycel/v0/test", &[b"hello"]);
        assert!(d.sign_pk().verify("mycel/v0/test", &[b"hello"], &sig).is_ok());
        assert_eq!(d.sign_pk().verify("mycel/v0/other", &[b"hello"], &sig), Err(CryptoError::BadSignature));
        assert_eq!(d.sign_pk().verify("mycel/v0/test", &[b"hellO"], &sig), Err(CryptoError::BadSignature));
    }

    #[test]
    fn framing_prevents_boundary_shifting() {
        let d = DeviceKeys::generate();
        let sig = d.sign("ab", &[b"c"]);
        assert!(d.sign_pk().verify("a", &[b"bc"], &sig).is_err());
    }

    #[test]
    fn kex_binding_and_seed_determinism() {
        let seed = random();
        let a = DeviceKeys::from_seed(seed);
        let b = DeviceKeys::from_seed(seed);
        assert_eq!(a.public(), b.public());
        assert!(a.public().verify_binding().is_ok());
        let mut forged = a.public();
        forged.kex_pk = DeviceKeys::generate().public().kex_pk;
        assert!(forged.verify_binding().is_err());
    }

    #[test]
    fn lockbox_roundtrip_and_info_binding() {
        let bob = DeviceKeys::generate();
        let eve = DeviceKeys::generate();
        let lb = seal_lockbox(&bob.public().kex_pk, b"ctx-1", b"secret").unwrap();
        assert_eq!(bob.open_lockbox(b"ctx-1", &lb).unwrap(), b"secret");
        assert!(bob.open_lockbox(b"ctx-2", &lb).is_err(), "info is bound");
        assert!(eve.open_lockbox(b"ctx-1", &lb).is_err(), "wrong recipient");
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let k = SymKey::generate();
        let n = random();
        let ct = k.seal(&n, b"aad", b"data").unwrap();
        assert_eq!(k.open(&n, b"aad", &ct).unwrap(), b"data");
        assert!(k.open(&n, b"AAD", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(k.open(&n, b"aad", &bad).is_err());
        assert!(SymKey::generate().open(&n, b"aad", &ct).is_err());
    }

    #[test]
    fn sig_serde_roundtrip() {
        let d = DeviceKeys::generate();
        let s = d.sign("x", &[b"y"]);
        let bytes = postcard::to_allocvec(&s).unwrap();
        let back: Sig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
