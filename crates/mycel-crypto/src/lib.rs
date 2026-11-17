//! Mycel cryptographic primitives (see docs/TRUST.md §2).
//!
//! Thin, opinionated wrappers over vetted crates. No custom cryptography:
//! - Ed25519 signatures (`ed25519-dalek`, strict verification)
//! - HPKE (RFC 9180) lockboxes with the X-Wing hybrid KEM (X25519 + ML-KEM-768),
//!   HKDF-SHA256 and ChaCha20-Poly1305: a lockbox stays sealed unless both
//!   X25519 and ML-KEM-768 are broken
//! - XChaCha20-Poly1305 content encryption
//! - BLAKE3 for ids and key commitments
//! - Chunked streaming XChaCha20-Poly1305 (STREAM) for attachments of any size
//!
//! Every signature / hash / HPKE `info` is domain-separated with a context string.

use std::fmt;
use std::sync::Arc;

pub mod chunked;
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
/// A buffer that is wiped when dropped, for callers that hold key material
/// outside the types here.
pub use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HpkeKem = hpke::kem::XWing;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// Length of a lockbox public key ([`KexPk`]): an X-Wing encapsulation key
/// (ML-KEM-768's 1184 bytes, then X25519's 32).
pub const KEX_PK_LEN: usize = 1216;
/// Length of a lockbox's encapsulated key ([`Lockbox::enc`]): an X-Wing
/// ciphertext (ML-KEM-768's 1088 bytes, then X25519's 32).
pub const LOCKBOX_ENC_LEN: usize = 1120;
/// What a lockbox adds to its plaintext: the encapsulated key and the AEAD tag.
pub const LOCKBOX_OVERHEAD: usize = LOCKBOX_ENC_LEN + 16;

/// Bound into every lockbox's HPKE `info`, before the caller's own. It names
/// the suite, so a lockbox made for another one (the X25519-only lockboxes
/// of earlier builds) never opens as this one.
const LOCKBOX_SUITE: &str = "mycel/v1/lockbox/xwing-hkdfsha256-chacha20poly1305";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid public key")]
    BadPublicKey,
    #[error("decryption failed")]
    Decrypt,
    #[error("lockbox was sealed with a key agreement this build doesn't support (made by an older build?)")]
    UnsupportedLockbox,
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

/// The public key lockboxes are sealed to: an X-Wing (X25519 + ML-KEM-768)
/// encapsulation key, [`KEX_PK_LEN`] bytes. Shared, so copies are cheap.
///
/// Decoding checks the length only. [`KexPk::validate`] checks that X-Wing
/// accepts the key; [`MemberKeys::verify_binding`] runs it, so a key that
/// passed there can always be sealed to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KexPk(Arc<[u8; KEX_PK_LEN]>);

impl KexPk {
    /// A well-formed key from its bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = Self::from_len_checked(bytes).ok_or(CryptoError::BadPublicKey)?;
        key.validate()?;
        Ok(key)
    }

    fn from_len_checked(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; KEX_PK_LEN] = bytes.try_into().ok()?;
        Some(KexPk(Arc::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8; KEX_PK_LEN] {
        &self.0
    }

    /// Is this a key X-Wing can encapsulate to? (ML-KEM requires a canonical
    /// encoding; any 32 bytes are an X25519 key.)
    pub fn validate(&self) -> Result<()> {
        self.parse().map(|_| ())
    }

    fn parse(&self) -> Result<<HpkeKem as hpke::Kem>::PublicKey> {
        <HpkeKem as hpke::Kem>::PublicKey::from_bytes(&self.0[..]).map_err(|_| CryptoError::BadPublicKey)
    }
}

impl fmt::Debug for KexPk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kex:{}", hex::encode(&self.0[..4]))
    }
}

impl Serialize for KexPk {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0[..])
    }
}

impl<'de> Deserialize<'de> for KexPk {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Bytes;
        impl<'de> serde::de::Visitor<'de> for Bytes {
            type Value = KexPk;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a {KEX_PK_LEN}-byte lockbox key")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<KexPk, E> {
                // The 32-byte X25519 keys of earlier builds end here.
                KexPk::from_len_checked(v).ok_or_else(|| E::invalid_length(v.len(), &self))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<KexPk, A::Error> {
                let mut bytes = Vec::with_capacity(KEX_PK_LEN);
                while let Some(b) = seq.next_element::<u8>()? {
                    if bytes.len() == KEX_PK_LEN {
                        return Err(serde::de::Error::invalid_length(KEX_PK_LEN + 1, &self));
                    }
                    bytes.push(b);
                }
                self.visit_bytes(&bytes)
            }
        }
        d.deserialize_bytes(Bytes)
    }
}

/// Public identity of a member device, with a self-signature binding the kex key
/// to the signing key (TRUST.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberKeys {
    pub sign_pk: SignPk,
    pub kex_pk: KexPk,
    pub kex_sig: Sig,
}

/// Not the context earlier builds signed their X25519 keys under.
const CTX_KEX_BINDING: &str = "mycel/v1/kex-binding";

impl MemberKeys {
    /// The device key signed this kex key, and the kex key is one lockboxes
    /// can be sealed to.
    pub fn verify_binding(&self) -> Result<()> {
        self.sign_pk.verify(CTX_KEX_BINDING, &[self.kex_pk.as_bytes()], &self.kex_sig)?;
        self.kex_pk.validate()
    }
}

/// A lockbox keypair: X-Wing, which keeps its private key as a 32-byte seed.
#[derive(Clone)]
pub struct KexSecret {
    /// (zeroizes itself on drop)
    sk: <HpkeKem as hpke::Kem>::PrivateKey,
    pk: KexPk,
}

impl KexSecret {
    /// The keypair X-Wing expands from `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(seed).expect("an X-Wing private key is 32 bytes");
        let pk = HpkeKem::sk_to_pk(&sk);
        let pk = KexPk::from_len_checked(&pk.to_bytes()).expect("an X-Wing public key is KEX_PK_LEN bytes");
        KexSecret { sk, pk }
    }

    /// A fresh random keypair, derived from nothing: a reader key
    /// (TRUST.md §6), which its owner can delete.
    pub fn generate() -> Self {
        let mut seed: [u8; 32] = random();
        let key = Self::from_seed(&seed);
        seed.zeroize();
        key
    }

    /// The seed, for the owner's own sealed storage. Handle with care.
    pub fn seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.sk.to_bytes());
        seed
    }

    pub fn public(&self) -> &KexPk {
        &self.pk
    }

    /// Open a lockbox sealed to this key with the same `info`.
    pub fn open_lockbox(&self, info: &[u8], lockbox: &Lockbox) -> Result<Vec<u8>> {
        // What an X25519 lockbox of an earlier build looks like: say so,
        // rather than "decryption failed".
        if lockbox.enc.len() != LOCKBOX_ENC_LEN {
            return Err(CryptoError::UnsupportedLockbox);
        }
        let encapped =
            <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&lockbox.enc).map_err(|_| CryptoError::Decrypt)?;
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &self.sk,
            &encapped,
            &lockbox_info(info),
            &lockbox.ct,
            b"",
        )
        .map_err(|_| CryptoError::Decrypt)
    }
}

impl fmt::Debug for KexSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KexSecret({:?})", self.pk)
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
    kex: KexSecret,
    #[zeroize(skip)]
    public: MemberKeys,
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self::from_seed(random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sign = SigningKey::from_bytes(&seed);
        // Not the label earlier builds derived their X25519 key under.
        let mut kex_seed = blake3::derive_key("mycel/v1/kex-seed/xwing", &seed);
        let kex = KexSecret::from_seed(&kex_seed);
        kex_seed.zeroize();
        let kex_pk = kex.public().clone();
        let sign_pk = SignPk(sign.verifying_key().to_bytes());
        let kex_sig = Sig(sign.sign(&framed(CTX_KEX_BINDING, &[kex_pk.as_bytes()])).to_bytes());
        DeviceKeys { seed, sign, kex, public: MemberKeys { sign_pk, kex_pk, kex_sig } }
    }

    /// The seed, for persisting in the OS keychain. Handle with care.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public(&self) -> MemberKeys {
        self.public.clone()
    }

    pub fn sign_pk(&self) -> SignPk {
        self.public.sign_pk
    }

    pub fn sign(&self, ctx: &str, msg: &[&[u8]]) -> Sig {
        Sig(self.sign.sign(&framed(ctx, msg)).to_bytes())
    }

    /// Open a lockbox sealed to this device's own kex key (the one in
    /// [`DeviceKeys::public`]).
    pub fn open_lockbox(&self, info: &[u8], lockbox: &Lockbox) -> Result<Vec<u8>> {
        self.kex.open_lockbox(info, lockbox)
    }

    /// The key this device seals its own stored secrets of kind `purpose`
    /// with: derived from the seed, so what is stored is useless without it.
    fn storage_key(&self, purpose: &str) -> SymKey {
        let mut h = blake3::Hasher::new_derive_key("mycel/v1/storage-key");
        h.update(&self.seed);
        h.update(&framed(purpose, &[]));
        SymKey(*h.finalize().as_bytes())
    }

    /// Seal `plaintext` for this device's own storage: a random nonce, then
    /// XChaCha20-Poly1305 under a key derived from the seed for `purpose`.
    /// `aad` binds it to where it is kept (which space, which record).
    pub fn seal_stored(&self, purpose: &str, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = random();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&self.storage_key(purpose).seal(&nonce, aad, plaintext)?);
        Ok(out)
    }

    /// Open what [`DeviceKeys::seal_stored`] made, with the same `purpose`
    /// and `aad`.
    pub fn open_stored(&self, purpose: &str, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ct) = sealed.split_first_chunk::<24>().ok_or(CryptoError::Decrypt)?;
        self.storage_key(purpose).open(nonce, aad, ct)
    }
}

// ─────────────────────────── lockboxes ───────────────────────────

/// An HPKE-sealed secret addressed to one recipient's kex key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockbox {
    /// The X-Wing encapsulated key: [`LOCKBOX_ENC_LEN`] bytes.
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}

/// A lockbox's HPKE `info`: the suite, then the caller's context.
fn lockbox_info(info: &[u8]) -> Vec<u8> {
    framed(LOCKBOX_SUITE, &[info])
}

pub fn seal_lockbox(recipient: &KexPk, info: &[u8], plaintext: &[u8]) -> Result<Lockbox> {
    let pk = recipient.parse()?;
    let (enc, ct) =
        hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeS::Base, &pk, &lockbox_info(info), plaintext, b"")
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
        assert_eq!(bob.open_lockbox(b"ctx-2", &lb), Err(CryptoError::Decrypt), "info is bound");
        assert_eq!(eve.open_lockbox(b"ctx-1", &lb), Err(CryptoError::Decrypt), "wrong recipient");
    }

    /// The hybrid's sizes: what a member's key and each lockbox cost.
    #[test]
    fn lockbox_and_key_sizes() {
        let bob = DeviceKeys::generate();
        assert_eq!(bob.public().kex_pk.as_bytes().len(), KEX_PK_LEN);
        assert_eq!(KEX_PK_LEN, 1216);
        let lb = seal_lockbox(&bob.public().kex_pk, b"ctx", &[7u8; 32]).unwrap();
        assert_eq!(lb.enc.len(), LOCKBOX_ENC_LEN);
        assert_eq!(LOCKBOX_ENC_LEN, 1120);
        assert_eq!(lb.enc.len() + lb.ct.len(), 32 + LOCKBOX_OVERHEAD);
        // on the wire: two length prefixes more
        assert_eq!(postcard::to_allocvec(&lb).unwrap().len(), 32 + LOCKBOX_OVERHEAD + 3);
        assert_eq!(postcard::to_allocvec(&bob.public()).unwrap().len(), 32 + (2 + KEX_PK_LEN) + (1 + 64));
    }

    #[test]
    fn a_tampered_lockbox_does_not_open() {
        let bob = DeviceKeys::generate();
        let lb = seal_lockbox(&bob.public().kex_pk, b"ctx", b"secret").unwrap();
        // the ML-KEM part, the X25519 part and the ciphertext
        for at in [0, 500, LOCKBOX_ENC_LEN - 1] {
            let mut bad = lb.clone();
            bad.enc[at] ^= 1;
            assert_eq!(bob.open_lockbox(b"ctx", &bad), Err(CryptoError::Decrypt), "enc byte {at}");
        }
        for at in 0..lb.ct.len() {
            let mut bad = lb.clone();
            bad.ct[at] ^= 1;
            assert_eq!(bob.open_lockbox(b"ctx", &bad), Err(CryptoError::Decrypt), "ct byte {at}");
        }
        let mut short = lb.clone();
        short.ct.pop();
        assert_eq!(bob.open_lockbox(b"ctx", &short), Err(CryptoError::Decrypt));
    }

    /// Two seals of the same secret to the same key share nothing.
    #[test]
    fn lockboxes_are_randomized() {
        let bob = DeviceKeys::generate();
        let a = seal_lockbox(&bob.public().kex_pk, b"ctx", b"secret").unwrap();
        let b = seal_lockbox(&bob.public().kex_pk, b"ctx", b"secret").unwrap();
        assert_ne!(a.enc, b.enc);
        assert_ne!(a.ct, b.ct);
    }

    /// The kex key is derived from the seed alone, the same way on every
    /// run and platform: pinned, so a change of derivation (which would
    /// orphan every lockbox sealed to existing devices) can't go unnoticed.
    #[test]
    fn kex_key_derivation_is_pinned() {
        let d = DeviceKeys::from_seed([7; 32]);
        let pk = d.public().kex_pk;
        assert_eq!(pk, DeviceKeys::from_seed([7; 32]).public().kex_pk);
        assert_ne!(pk, DeviceKeys::from_seed([8; 32]).public().kex_pk);
        assert_eq!(
            Hash32::digest("mycel/test/kex-pk", pk.as_bytes()).to_string(),
            "67cb120f66df5322a730c379b300eb84233173ac2995aa51b5e2800d5fcfb528",
            "the kex key derived from a seed changed"
        );
        // and the private half matches the public one
        let lb = seal_lockbox(&pk, b"ctx", b"secret").unwrap();
        assert_eq!(DeviceKeys::from_seed([7; 32]).open_lockbox(b"ctx", &lb).unwrap(), b"secret");
    }

    #[test]
    fn kex_secret_from_its_seed() {
        let seed = random();
        let a = KexSecret::from_seed(&seed);
        assert_eq!(a.public(), KexSecret::from_seed(&seed).public());
        assert!(a.public().validate().is_ok());
        let lb = seal_lockbox(a.public(), b"ctx", b"secret").unwrap();
        assert_eq!(KexSecret::from_seed(&seed).open_lockbox(b"ctx", &lb).unwrap(), b"secret");
        assert_eq!(KexSecret::from_seed(&random()).open_lockbox(b"ctx", &lb), Err(CryptoError::Decrypt));
        assert!(!format!("{a:?}").contains(&hex::encode(seed)), "Debug never prints the secret");
    }

    /// A reader key is random: nothing a device's seed gives opens what was
    /// sealed to it, and its seed round-trips for sealed storage.
    #[test]
    fn a_generated_kex_secret_is_not_derived_from_the_device() {
        let device = DeviceKeys::generate();
        let (a, b) = (KexSecret::generate(), KexSecret::generate());
        assert_ne!(a.public(), b.public());
        assert_ne!(a.public(), &device.public().kex_pk);
        let lb = seal_lockbox(a.public(), b"ctx", b"secret").unwrap();
        assert_eq!(device.open_lockbox(b"ctx", &lb), Err(CryptoError::Decrypt));
        assert_eq!(DeviceKeys::from_seed(device.seed()).open_lockbox(b"ctx", &lb), Err(CryptoError::Decrypt));
        assert_eq!(KexSecret::from_seed(&a.seed()).open_lockbox(b"ctx", &lb).unwrap(), b"secret");
    }

    #[test]
    fn stored_secrets_are_sealed_to_the_seed_purpose_and_place() {
        let d = DeviceKeys::generate();
        let sealed = d.seal_stored("space-secrets", b"space-1", b"reader keys").unwrap();
        assert_eq!(sealed.len(), 24 + b"reader keys".len() + 16);
        assert_eq!(d.open_stored("space-secrets", b"space-1", &sealed).unwrap(), b"reader keys");
        // the same device after a restart
        let again = DeviceKeys::from_seed(d.seed());
        assert_eq!(again.open_stored("space-secrets", b"space-1", &sealed).unwrap(), b"reader keys");
        // another place, another purpose, another device, a changed byte, a short record
        assert_eq!(d.open_stored("space-secrets", b"space-2", &sealed), Err(CryptoError::Decrypt));
        assert_eq!(d.open_stored("other", b"space-1", &sealed), Err(CryptoError::Decrypt));
        assert_eq!(DeviceKeys::generate().open_stored("space-secrets", b"space-1", &sealed), Err(CryptoError::Decrypt));
        for at in [0, 23, 24, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert_eq!(d.open_stored("space-secrets", b"space-1", &bad), Err(CryptoError::Decrypt), "byte {at}");
        }
        assert_eq!(d.open_stored("space-secrets", b"space-1", &sealed[..10]), Err(CryptoError::Decrypt));
        // sealed twice: nothing in common (a fresh nonce each time)
        assert_ne!(sealed, d.seal_stored("space-secrets", b"space-1", b"reader keys").unwrap());
    }

    /// What earlier builds made (X25519 keys and lockboxes) is refused, with
    /// an error that says why, and never opens.
    #[test]
    fn the_x25519_format_of_earlier_builds_is_refused() {
        let bob = DeviceKeys::generate();
        // a 32-byte kex key: not a key
        assert_eq!(KexPk::from_bytes(&[9u8; 32]), Err(CryptoError::BadPublicKey));
        let old_key = postcard::to_allocvec(&[9u8; 32]).unwrap();
        assert!(postcard::from_bytes::<KexPk>(&old_key).is_err());
        // old member keys (32 + 32 + 64 bytes, no length prefixes) don't decode
        let old_member = [[1u8; 32].as_slice(), &[2u8; 32], &[3u8; 64]].concat();
        assert!(postcard::from_bytes::<MemberKeys>(&old_member).is_err());
        // a lockbox with a 32-byte encapsulated key: named as unsupported
        let old = Lockbox { enc: vec![1; 32], ct: vec![2; 48] };
        assert_eq!(bob.open_lockbox(b"ctx", &old), Err(CryptoError::UnsupportedLockbox));
        assert_eq!(
            bob.open_lockbox(b"ctx", &Lockbox { enc: vec![], ct: vec![] }),
            Err(CryptoError::UnsupportedLockbox)
        );
    }

    #[test]
    fn kex_keys_are_length_checked_on_decode_and_validated_before_use() {
        let bob = DeviceKeys::generate().public();
        // round trips: postcard (bytes) and JSON (a sequence)
        let bytes = postcard::to_allocvec(&bob).unwrap();
        assert_eq!(postcard::from_bytes::<MemberKeys>(&bytes).unwrap(), bob);
        let json = serde_json::to_string(&bob.kex_pk).unwrap();
        assert_eq!(serde_json::from_str::<KexPk>(&json).unwrap(), bob.kex_pk);
        // one byte short or long: refused
        for len in [KEX_PK_LEN - 1, KEX_PK_LEN + 1] {
            let wrong = postcard::to_allocvec(&serde_bytes_of(&vec![0u8; len])).unwrap();
            assert!(postcard::from_bytes::<KexPk>(&wrong).is_err(), "{len} bytes");
            assert_eq!(KexPk::from_bytes(&vec![0u8; len]), Err(CryptoError::BadPublicKey));
        }
        // the right length but not an ML-KEM key (coefficients out of range):
        // decodes, and is refused wherever it would be used
        let junk = postcard::to_allocvec(&serde_bytes_of(&vec![0xffu8; KEX_PK_LEN])).unwrap();
        let junk: KexPk = postcard::from_bytes(&junk).unwrap();
        assert_eq!(junk.validate(), Err(CryptoError::BadPublicKey));
        assert_eq!(KexPk::from_bytes(&[0xff; KEX_PK_LEN]), Err(CryptoError::BadPublicKey));
        assert_eq!(seal_lockbox(&junk, b"ctx", b"secret"), Err(CryptoError::BadPublicKey));
        let mut forged = bob.clone();
        forged.kex_pk = junk;
        assert!(forged.verify_binding().is_err());
    }

    /// Bytes as serde's byte-string type (what `KexPk` encodes as).
    fn serde_bytes_of(v: &[u8]) -> impl Serialize + '_ {
        struct B<'a>(&'a [u8]);
        impl Serialize for B<'_> {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0)
            }
        }
        B(v)
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
