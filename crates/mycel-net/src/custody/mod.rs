//! Offline delivery through the internet: **custodians** (design record:
//! docs/OFFLINE_DELIVERY.md).
//!
//! When a live sync to a member doesn't get through, the sender seals what
//! the member lacks into a **parcel** and hands it to up to
//! [`DEFAULT_COPIES`] custodians over the internet: devices that store it
//! and give it to the recipient when it comes back. Custodians are chosen
//! in order ([`select`]): the sender's own other devices, devices that share
//! a space with the recipient (they will meet it), then volunteers whose
//! keys are XOR-closest to the recipient's (Kademlia's metric, so sender and
//! recipient find the same ones without a central index: [`Directory`]).
//!
//! - **Sealed sender.** A parcel names only its recipient. The sender's key,
//!   its signature, the space and the envelopes are inside an HPKE seal to
//!   the recipient's key-exchange key, padded to a PADMÉ size class. A
//!   custodian learns the recipient key, a size class, timing, and who
//!   handed it the parcel (the QUIC connection), nothing else; a parcel at
//!   rest names no sender.
//! - **Only the recipient fetches.** The fetch stream runs on a QUIC
//!   connection authenticated to the fetcher's key, and a custodian lists and
//!   hands over only parcels addressed to that key, so nobody else can drain
//!   or enumerate a device's mail. The recipient's signed receipt (or the
//!   sender's release secret) makes a custodian drop its copy.
//! - **Strict, fair limits** ([`Vault`]): a total store, a maximum parcel,
//!   and shares per depositor key, per source address and per recipient;
//!   deposit rate limits; a small proof of work from depositors that share
//!   no space with the custodian (a fresh key costs nothing); when the store
//!   is full, room is taken from the biggest depositor, never from a small
//!   one. Custodians never pass parcels on to other custodians, and every
//!   answer is to an address QUIC has validated, so nothing amplifies.
//!
//! This module is pure (no I/O, no clock): formats, the custodian's store,
//! selection, the directory and the sender's record. The node drives it
//! over the `Custody` stream kind (`custody/node.rs`).

pub(crate) mod node;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use mycel_crypto::{DeviceKeys, Digest, Hash32, KexPk, Lockbox, Sig, SignPk};
use serde::{Deserialize, Serialize};

/// Parcel format versions (what a custodian checks: the id rule).
pub const PARCEL_V1: u8 = 1;
/// Custodians a sender aims for.
pub const DEFAULT_COPIES: usize = 3;
/// Candidates tried per parcel at most (dials to devices that turn out to
/// be offline or refuse).
pub const MAX_ATTEMPTS: usize = 8;
/// The default lifetime of a parcel (the store-and-forward bundles' 3 days).
pub const DEFAULT_LIFETIME_MS: u64 = 3 * 24 * 3600 * 1000;
/// Keys a `Find` answer holds at most.
pub const FIND_MAX: usize = 8;
/// Parcels one `Listing` names at most, and the bytes one `Parcels` frame
/// carries at most (several rounds empty a bigger mailbox).
pub const LISTING_MAX: usize = 64;
pub const ROUND_BYTES: u64 = 2 * 1024 * 1024;

const CTX_ID: &str = "mycel/v1/custody-id";
const CTX_SEAL: &[u8] = b"mycel/v1/custody-seal";
const CTX_INNER: &str = "mycel/v1/custody-inner";
const CTX_RECEIPT: &str = "mycel/v1/custody-receipt";
const CTX_RELEASE: &str = "mycel/v1/custody-release";
const CTX_STAMP: &str = "mycel/v1/custody-stamp";
const CTX_RANK: &str = "mycel/v1/custody-rank";

// ───────────────────────────── parcels ─────────────────────────────

/// What a custodian stores: addressed to `dst`, sealed to it. Everything a
/// custodian sees is here; the sender is inside `sealed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parcel {
    pub version: u8,
    pub dst: SignPk,
    /// Wall-clock ms at the sender, rounded down to the minute (no finer
    /// timing than the deposit itself shows).
    pub created: u64,
    /// ms after `created` it is worth delivering.
    pub lifetime: u64,
    /// `H(secret)`: whoever shows the secret (the sender) may withdraw it.
    pub release: Hash32,
    /// postcard [`Lockbox`]: the HPKE-sealed, padded [`Sealed`].
    pub sealed: Vec<u8>,
}

impl Parcel {
    /// The id: a hash of every field, so a custodian can't change one
    /// without changing the id (and the seal binds the header too).
    pub fn id(&self) -> Hash32 {
        let mut d = Digest::new(CTX_ID);
        d.update(&[self.version])
            .update(&self.dst.0)
            .update(&self.created.to_le_bytes())
            .update(&self.lifetime.to_le_bytes())
            .update(&self.release.0)
            .update(&(self.sealed.len() as u64).to_le_bytes())
            .update(&self.sealed);
        d.finalize()
    }

    /// Wall-clock ms after which nobody needs it.
    pub fn expires(&self) -> u64 {
        self.created.saturating_add(self.lifetime)
    }

    pub fn size(&self) -> u64 {
        self.sealed.len() as u64
    }
}

/// Inside the seal: who sent it, what kind of payload, signed by the sender
/// over the header it travels under.
#[derive(Debug, Serialize, Deserialize)]
struct Sealed {
    src: SignPk,
    kind: u16,
    payload: Vec<u8>,
    sig: Sig,
}

/// A parcel opened by its recipient.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened {
    pub src: SignPk,
    pub kind: u16,
    pub payload: Vec<u8>,
}

/// PADMÉ (Nikitin et al., 2019): round `len` up so that only O(log log len)
/// bits of it show, at most 12% more. (The same rule as the Sync v2 stage 3
/// sealed bundles: research_notes/v2-designs/sync-v2.md §9.2.)
pub fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = usize::BITS - 1 - len.leading_zeros(); // floor(log2 len)
    let s = (usize::BITS - 1 - (e as usize).leading_zeros()) + 1; // floor(log2 e) + 1
    let last = e - s;
    let mask = (1usize << last) - 1;
    (len + mask) & !mask
}

fn header_bytes(dst: &SignPk, created: u64, lifetime: u64, release: &Hash32) -> Vec<u8> {
    [&dst.0[..], &created.to_le_bytes(), &lifetime.to_le_bytes(), &release.0].concat()
}

fn seal_info(dst: &SignPk, created: u64, lifetime: u64, release: &Hash32) -> Vec<u8> {
    [CTX_SEAL, &header_bytes(dst, created, lifetime, release)].concat()
}

/// The release hash of a secret.
pub fn release_hash(secret: &[u8; 32]) -> Hash32 {
    Hash32::digest(CTX_RELEASE, secret)
}

/// Seal `payload` (of payload `kind`, e.g. `mesh::dtn::KIND_SPACE_SYNC`) from
/// `keys` to `dst` (its key-exchange key `kex`). `now_ms` is the wall clock.
/// Returns the parcel and the secret that withdraws it.
pub fn seal(
    keys: &DeviceKeys,
    dst: SignPk,
    kex: &KexPk,
    kind: u16,
    payload: Vec<u8>,
    lifetime: u64,
    now_ms: u64,
) -> anyhow::Result<(Parcel, [u8; 32])> {
    let created = now_ms - now_ms % 60_000;
    let secret: [u8; 32] = mycel_crypto::random();
    let release = release_hash(&secret);
    let header = header_bytes(&dst, created, lifetime, &release);
    let payload_hash = Hash32::digest(CTX_INNER, &payload);
    let sig = keys.sign(CTX_INNER, &[&header, &kind.to_le_bytes(), &payload_hash.0]);
    let inner = Sealed { src: keys.sign_pk(), kind, payload, sig };
    let mut plain = postcard::to_allocvec(&inner)?;
    plain.resize(padme(plain.len()), 0);
    let lockbox = mycel_crypto::seal_lockbox(kex, &seal_info(&dst, created, lifetime, &release), &plain)?;
    let parcel = Parcel { version: PARCEL_V1, dst, created, lifetime, release, sealed: postcard::to_allocvec(&lockbox)? };
    Ok((parcel, secret))
}

/// Open a parcel addressed to `keys`: decrypt, check the padding and the
/// sender's signature over the header. (Whether the sender may write to
/// the space inside is the space's business, checked as for any sync.)
pub fn open(keys: &DeviceKeys, p: &Parcel) -> anyhow::Result<Opened> {
    use anyhow::{anyhow, bail};
    if p.version != PARCEL_V1 {
        return Err(crate::VersionError::Unsupported {
            what: "custody parcel",
            version: p.version.into(),
            newest: PARCEL_V1.into(),
        }
        .into());
    }
    if p.dst != keys.sign_pk() {
        bail!("parcel for another device");
    }
    let lockbox: Lockbox = postcard::from_bytes(&p.sealed)?;
    let plain = keys.open_lockbox(&seal_info(&p.dst, p.created, p.lifetime, &p.release), &lockbox)?;
    let (inner, rest) = postcard::take_from_bytes::<Sealed>(&plain)?;
    if rest.iter().any(|b| *b != 0) || plain.len() != padme(plain.len() - rest.len()) {
        bail!("bad parcel padding");
    }
    let header = header_bytes(&p.dst, p.created, p.lifetime, &p.release);
    let payload_hash = Hash32::digest(CTX_INNER, &inner.payload);
    inner
        .src
        .verify(CTX_INNER, &[&header, &inner.kind.to_le_bytes(), &payload_hash.0], &inner.sig)
        .map_err(|_| anyhow!("bad parcel signature"))?;
    Ok(Opened { src: inner.src, kind: inner.kind, payload: inner.payload })
}

/// "I, the recipient, have parcel `id`", signed by the recipient (whose key
/// the custodian knows: it is the parcel's `dst`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub id: Hash32,
    pub sig: Sig,
}

impl Receipt {
    pub fn sign(keys: &DeviceKeys, id: Hash32) -> Receipt {
        Receipt { id, sig: keys.sign(CTX_RECEIPT, &[&id.0]) }
    }

    pub fn verify(&self, dst: &SignPk) -> bool {
        dst.verify(CTX_RECEIPT, &[&self.id.0], &self.sig).is_ok()
    }
}

// ───────────────────────────── proof of work ─────────────────────────────

fn stamp_prefix(id: &Hash32, custodian: &SignPk) -> Digest {
    let mut d = Digest::new(CTX_STAMP);
    d.update(&id.0).update(&custodian.0);
    d
}

fn zero_bits(h: &Hash32) -> u32 {
    let mut n = 0;
    for b in h.0 {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// A stamp of `bits` leading zero bits for parcel `id` at `custodian`
/// (bound to both, so one stamp is good at one custodian for one parcel).
/// About 2^bits hashes; 0 bits is free.
pub fn mint(id: &Hash32, custodian: &SignPk, bits: u8) -> u64 {
    if bits == 0 {
        return 0;
    }
    let prefix = stamp_prefix(id, custodian);
    let mut nonce = mycel_crypto::random_u64();
    loop {
        let mut d = prefix.clone();
        if zero_bits(&d.update(&nonce.to_le_bytes()).finalize()) >= bits as u32 {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Whether `stamp` has `bits` leading zero bits for `id` at `custodian`.
pub fn stamp_ok(id: &Hash32, custodian: &SignPk, stamp: u64, bits: u8) -> bool {
    bits == 0 || zero_bits(&stamp_prefix(id, custodian).update(&stamp.to_le_bytes()).finalize()) >= bits as u32
}

// ───────────────────────────── wire ─────────────────────────────

/// Why a custodian refused a deposit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Refusal {
    /// Custody is off on this device (a setting, a phone on battery or a
    /// metered network).
    NotServing,
    /// A parcel format this build doesn't check.
    Unsupported,
    TooBig,
    Expired,
    /// Created in the future, or otherwise not well formed.
    Malformed,
    /// A stranger's deposit without a valid proof of work.
    NoStamp,
    RateLimited,
    /// The depositor's share is used up.
    DepositorShare,
    /// The share of the address it deposits from is used up.
    OriginShare,
    /// The recipient's share is used up.
    RecipientShare,
    /// No room, and nobody holds more than the depositor.
    Full,
}

/// A custodian's answer to a deposit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Deposit {
    Stored,
    /// Already held (or already delivered): counts as stored.
    Duplicate,
    Refused(Refusal),
}

/// Messages on a `Custody` stream (node protocol, wire version 2, capability
/// [`crate::Caps::CUSTODY`]). The first message says what the stream is:
///
/// ```text
/// deposit   S → C  Deposit{parcel, stamp}       C → S  Deposited(answer)
/// fetch     R → C  Fetch                        then as push, from Listing
/// push      C → R  Listing{items}               R → C  Take{want, receipts}
///           C → R  Parcels{parcels}             R → C  Receipts{receipts}
///           ... rounds until an empty Listing
/// release   S → C  Release{id, secret}          C → S  Released{ok}
/// find      X → C  Find{target}                 C → X  Found{custodians}
/// ```
///
/// Variants are only ever appended (a new one needs a capability).
#[derive(Debug, Serialize, Deserialize)]
pub enum Msg {
    Deposit { parcel: Parcel, stamp: u64 },
    Deposited(Deposit),
    /// "Anything for me?": the connection proves who asks.
    Fetch,
    /// Parcels held for the device on the other end: (id, size).
    Listing { items: Vec<(Hash32, u32)> },
    /// The ones it wants, and receipts for the ones it already has.
    Take { want: Vec<Hash32>, receipts: Vec<Receipt> },
    Parcels { parcels: Vec<Parcel> },
    Receipts { receipts: Vec<Receipt> },
    Release { id: Hash32, secret: [u8; 32] },
    Released { ok: bool },
    /// The custodians the answerer knows XOR-closest to `target`.
    Find { target: SignPk },
    Found { custodians: Vec<SignPk> },
}

/// The largest custody frame: a deposit (one parcel) or one round of
/// parcels.
pub const MAX_MSG: usize = ROUND_BYTES as usize + 64 * 1024;
/// The largest frame that may open a custody stream (a deposit is the
/// biggest), before anything is known about the opener.
pub const MAX_FIRST: usize = 300 * 1024;

// ───────────────────────────── the custodian's store ─────────────────────────────

/// Where a deposit came from, for per-address shares: an IPv4 address, an
/// IPv6 /64, the internet relay (shared by many devices, so a bigger
/// share), or a local link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    Ip([u8; 16]),
    Relay,
    Link,
}

impl Origin {
    pub fn of_ip(ip: std::net::IpAddr) -> Origin {
        match ip {
            std::net::IpAddr::V4(v4) => Origin::Ip(v4.to_ipv6_mapped().octets()),
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Origin::Ip(v4.to_ipv6_mapped().octets()),
                None => {
                    let mut o = v6.octets();
                    o[8..].fill(0); // the /64
                    Origin::Ip(o)
                }
            },
        }
    }
}

/// Who deposits: the authenticated key, its address, and whether it shares
/// a space with the custodian (a known device: no proof of work, a bigger
/// share).
#[derive(Clone, Copy, Debug)]
pub struct Depositor {
    pub key: SignPk,
    pub origin: Origin,
    pub known: bool,
}

/// A custodian's limits. The defaults are conservative: the carrier's
/// parcel size and lifetime caps, half its store.
#[derive(Clone, Debug)]
pub struct VaultConfig {
    /// Store custody at all.
    pub serve: bool,
    /// Bytes held in total.
    pub capacity: u64,
    /// The largest parcel.
    pub max_parcel: usize,
    /// Bytes held for one depositor key (a known one: twice that).
    pub per_depositor: u64,
    /// Parcels held for one depositor key.
    pub per_depositor_count: usize,
    /// Bytes held from one address (an IPv4 address or IPv6 /64).
    pub per_origin: u64,
    /// ... and from everyone behind the internet relay together.
    pub per_relay: u64,
    /// Bytes held for one recipient.
    pub per_recipient: u64,
    /// Parcels held in total.
    pub max_parcels: usize,
    /// The longest lifetime honoured (ms from arrival).
    pub max_lifetime: u64,
    /// How far in the future `created` may be (clock skew), ms.
    pub max_skew: u64,
    /// Proof-of-work bits asked of strangers (0: none).
    pub stamp_bits: u8,
    /// Deposits per depositor: burst, then one per this many ms.
    pub depositor_burst: u32,
    pub depositor_every_ms: u64,
    /// Deposits per origin: burst, then one per this many ms.
    pub origin_burst: u32,
    pub origin_every_ms: u64,
}

impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig {
            serve: true,
            capacity: 32 << 20,
            max_parcel: 256 << 10,
            per_depositor: 2 << 20,
            per_depositor_count: 256,
            per_origin: 8 << 20,
            per_relay: 16 << 20,
            per_recipient: 4 << 20,
            max_parcels: 8192,
            max_lifetime: 7 * 24 * 3600 * 1000,
            max_skew: 10 * 60_000,
            stamp_bits: 16,
            depositor_burst: 32,
            depositor_every_ms: 2_000,
            origin_burst: 128,
            origin_every_ms: 500,
        }
    }
}

/// A token bucket (tokens, last refill in ms).
#[derive(Clone, Copy, Debug)]
struct Tokens {
    left: f64,
    at: u64,
}

/// Rate limits per key, bounded: idle (full) buckets are forgotten first.
#[derive(Debug)]
struct Limiter<K> {
    burst: f64,
    every_ms: f64,
    buckets: HashMap<K, Tokens>,
}

const LIMITER_MAX: usize = 4096;

impl<K: std::hash::Hash + Eq + Copy> Limiter<K> {
    fn new(burst: u32, every_ms: u64) -> Self {
        Limiter { burst: burst.max(1) as f64, every_ms: every_ms.max(1) as f64, buckets: HashMap::new() }
    }

    fn refill(&self, t: &mut Tokens, now: u64) {
        let gained = now.saturating_sub(t.at) as f64 / self.every_ms;
        t.left = (t.left + gained).min(self.burst);
        t.at = now.max(t.at);
    }

    /// Take one token for `k` now; `false` if it has none.
    fn take(&mut self, k: K, now: u64) -> bool {
        if !self.buckets.contains_key(&k) && self.buckets.len() >= LIMITER_MAX {
            self.forget_idle(now);
        }
        let (burst, every) = (self.burst, self.every_ms);
        let t = self.buckets.entry(k).or_insert(Tokens { left: burst, at: now });
        let gained = now.saturating_sub(t.at) as f64 / every;
        t.left = (t.left + gained).min(burst);
        t.at = now.max(t.at);
        if t.left >= 1.0 {
            t.left -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets that have refilled (nothing to remember); if all are
    /// busy, the half least recently used.
    fn forget_idle(&mut self, now: u64) {
        let mut buckets = std::mem::take(&mut self.buckets);
        buckets.retain(|_, t| {
            self.refill(t, now);
            t.left < self.burst
        });
        if buckets.len() >= LIMITER_MAX {
            let mut ages: Vec<u64> = buckets.values().map(|t| t.at).collect();
            ages.sort_unstable();
            let cut = ages[ages.len() / 2];
            buckets.retain(|_, t| t.at > cut);
        }
        self.buckets = buckets;
    }
}

struct Held {
    parcel: Parcel,
    depositor: SignPk,
    origin: Origin,
    /// Wall-clock ms it expires here.
    until: u64,
}

#[derive(Default)]
struct Share {
    bytes: u64,
    /// (until, id), soonest-expiring first.
    ids: BTreeSet<(u64, Hash32)>,
}

impl Share {
    fn add(&mut self, until: u64, id: Hash32, size: u64) {
        self.bytes += size;
        self.ids.insert((until, id));
    }

    fn remove(&mut self, until: u64, id: &Hash32, size: u64) {
        self.bytes = self.bytes.saturating_sub(size);
        self.ids.remove(&(until, *id));
    }
}

/// What a custodian has done, for tests and the network panel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultStats {
    pub stored: u64,
    pub duplicates: u64,
    pub refused: u64,
    pub delivered: u64,
    pub receipted: u64,
    pub released: u64,
    pub expired: u64,
    pub evicted: u64,
    /// Refusals by reason.
    pub refusals: Vec<(Refusal, u64)>,
}

/// Ids remembered as delivered or released (a re-deposit is a duplicate).
const GONE_MAX: usize = 8192;

/// A custodian's store of parcels for others. Wall-clock ms throughout
/// (parcels' `created` is the sender's wall clock).
pub struct Vault {
    cfg: VaultConfig,
    held: HashMap<Hash32, Held>,
    expiry: BTreeSet<(u64, Hash32)>,
    used: u64,
    by_depositor: HashMap<SignPk, Share>,
    by_origin: HashMap<Origin, u64>,
    by_dst: HashMap<SignPk, Share>,
    gone: HashSet<Hash32>,
    gone_order: VecDeque<Hash32>,
    depositor_rate: Limiter<SignPk>,
    origin_rate: Limiter<Origin>,
    stats: VaultStats,
    refusals: HashMap<Refusal, u64>,
}

impl Vault {
    pub fn new(cfg: VaultConfig) -> Vault {
        Vault {
            depositor_rate: Limiter::new(cfg.depositor_burst, cfg.depositor_every_ms),
            origin_rate: Limiter::new(cfg.origin_burst, cfg.origin_every_ms),
            cfg,
            held: HashMap::new(),
            expiry: BTreeSet::new(),
            used: 0,
            by_depositor: HashMap::new(),
            by_origin: HashMap::new(),
            by_dst: HashMap::new(),
            gone: HashSet::new(),
            gone_order: VecDeque::new(),
            stats: VaultStats::default(),
            refusals: HashMap::new(),
        }
    }

    pub fn config(&self) -> &VaultConfig {
        &self.cfg
    }

    pub fn set_serving(&mut self, on: bool) {
        self.cfg.serve = on;
    }

    pub fn serving(&self) -> bool {
        self.cfg.serve
    }

    pub fn stats(&self) -> VaultStats {
        let mut s = self.stats.clone();
        s.refusals = self.refusals.iter().map(|(k, v)| (*k, *v)).collect();
        s.refusals.sort_by_key(|(k, _)| format!("{k:?}"));
        s
    }

    /// Bytes and parcels held.
    pub fn used(&self) -> (u64, usize) {
        (self.used, self.held.len())
    }

    pub fn holds(&self, id: &Hash32) -> bool {
        self.held.contains_key(id)
    }

    fn refuse(&mut self, why: Refusal) -> Deposit {
        self.stats.refused += 1;
        *self.refusals.entry(why).or_default() += 1;
        Deposit::Refused(why)
    }

    fn origin_share(&self, o: &Origin) -> u64 {
        match o {
            Origin::Relay => self.cfg.per_relay,
            _ => self.cfg.per_origin,
        }
    }

    /// `d` deposits `p` with `stamp` at us (`me`), at wall-clock `now`.
    pub fn deposit(&mut self, d: &Depositor, p: Parcel, stamp: u64, me: &SignPk, now: u64) -> Deposit {
        if !self.cfg.serve {
            return self.refuse(Refusal::NotServing);
        }
        if p.version != PARCEL_V1 {
            return self.refuse(Refusal::Unsupported);
        }
        if p.sealed.len() > self.cfg.max_parcel {
            return self.refuse(Refusal::TooBig);
        }
        if p.created > now.saturating_add(self.cfg.max_skew) || p.dst == *me {
            return self.refuse(Refusal::Malformed);
        }
        if p.expires() <= now {
            return self.refuse(Refusal::Expired);
        }
        let id = p.id();
        if self.held.contains_key(&id) || self.gone.contains(&id) {
            self.stats.duplicates += 1;
            return Deposit::Duplicate;
        }
        // Rate limits before anything costly; failed attempts count too.
        if !self.depositor_rate.take(d.key, now) || !self.origin_rate.take(d.origin, now) {
            return self.refuse(Refusal::RateLimited);
        }
        if !d.known && !stamp_ok(&id, me, stamp, self.cfg.stamp_bits) {
            return self.refuse(Refusal::NoStamp);
        }
        let size = p.size();
        let mult = if d.known { 2 } else { 1 };
        let mine = self.by_depositor.get(&d.key);
        if mine.map_or(0, |s| s.bytes) + size > self.cfg.per_depositor * mult
            || mine.map_or(0, |s| s.ids.len()) >= self.cfg.per_depositor_count * mult as usize
        {
            return self.refuse(Refusal::DepositorShare);
        }
        if self.by_origin.get(&d.origin).copied().unwrap_or(0) + size > self.origin_share(&d.origin) {
            return self.refuse(Refusal::OriginShare);
        }
        if self.by_dst.get(&p.dst).map_or(0, |s| s.bytes) + size > self.cfg.per_recipient {
            return self.refuse(Refusal::RecipientShare);
        }
        if !self.make_room(&d.key, size) {
            return self.refuse(Refusal::Full);
        }
        let until = p.expires().min(now.saturating_add(self.cfg.max_lifetime));
        self.used += size;
        self.by_depositor.entry(d.key).or_default().add(until, id, size);
        *self.by_origin.entry(d.origin).or_default() += size;
        self.by_dst.entry(p.dst).or_default().add(until, id, size);
        self.expiry.insert((until, id));
        self.held.insert(id, Held { parcel: p, depositor: d.key, origin: d.origin, until });
        self.stats.stored += 1;
        Deposit::Stored
    }

    /// Room for `size` more bytes from `key`: while the store (or the
    /// parcel count) is over, the soonest-expiring parcel of whoever holds
    /// the most goes, as long as that is someone holding more than `key`
    /// would (fair share: a flood evicts itself, never a small depositor).
    fn make_room(&mut self, key: &SignPk, size: u64) -> bool {
        let mine = self.by_depositor.get(key).map_or(0, |s| s.bytes) + size;
        while self.used + size > self.cfg.capacity || self.held.len() >= self.cfg.max_parcels {
            let Some((big, bytes)) =
                self.by_depositor.iter().filter(|(_, s)| !s.ids.is_empty()).map(|(k, s)| (*k, s.bytes)).max_by_key(|x| x.1)
            else {
                return false;
            };
            if bytes <= mine || big == *key {
                return false;
            }
            let Some(&(_, victim)) = self.by_depositor.get(&big).and_then(|s| s.ids.first()) else { return false };
            self.drop_held(&victim);
            self.stats.evicted += 1;
        }
        true
    }

    fn drop_held(&mut self, id: &Hash32) -> Option<Held> {
        let h = self.held.remove(id)?;
        let size = h.parcel.size();
        self.used = self.used.saturating_sub(size);
        self.expiry.remove(&(h.until, *id));
        if let Some(s) = self.by_depositor.get_mut(&h.depositor) {
            s.remove(h.until, id, size);
            if s.ids.is_empty() {
                self.by_depositor.remove(&h.depositor);
            }
        }
        if let Some(n) = self.by_origin.get_mut(&h.origin) {
            *n = n.saturating_sub(size);
            if *n == 0 {
                self.by_origin.remove(&h.origin);
            }
        }
        if let Some(s) = self.by_dst.get_mut(&h.parcel.dst) {
            s.remove(h.until, id, size);
            if s.ids.is_empty() {
                self.by_dst.remove(&h.parcel.dst);
            }
        }
        Some(h)
    }

    fn forget(&mut self, id: Hash32) {
        if self.gone.insert(id) {
            self.gone_order.push_back(id);
            while self.gone_order.len() > GONE_MAX {
                if let Some(old) = self.gone_order.pop_front() {
                    self.gone.remove(&old);
                }
            }
        }
    }

    /// Whether we hold anything for `dst`.
    pub fn has_mail(&self, dst: &SignPk) -> bool {
        self.by_dst.contains_key(dst)
    }

    /// Recipients we hold parcels for.
    pub fn recipients(&self) -> Vec<SignPk> {
        self.by_dst.keys().copied().collect()
    }

    /// What we hold for `dst` (soonest-expiring first), at most `max` ids.
    pub fn listing(&self, dst: &SignPk, max: usize) -> Vec<(Hash32, u32)> {
        self.by_dst
            .get(dst)
            .map(|s| {
                s.ids
                    .iter()
                    .take(max)
                    .filter_map(|(_, id)| self.held.get(id).map(|h| (*id, h.parcel.size() as u32)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The parcels among `want` that are for `dst` (nobody else's), within
    /// `budget` bytes.
    pub fn take(&self, dst: &SignPk, want: &[Hash32], budget: u64) -> Vec<Parcel> {
        let mut left = budget;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for id in want {
            let Some(h) = self.held.get(id).filter(|h| h.parcel.dst == *dst) else { continue };
            if !seen.insert(*id) || h.parcel.size() > left {
                continue;
            }
            left -= h.parcel.size();
            out.push(h.parcel.clone());
        }
        out
    }

    /// `dst` says it has parcel `r.id` (signed): drop our copy. `false` for
    /// a bad signature or a parcel for someone else.
    pub fn receipt(&mut self, dst: &SignPk, r: &Receipt) -> bool {
        if !r.verify(dst) {
            return false;
        }
        match self.held.get(&r.id) {
            Some(h) if h.parcel.dst != *dst => return false,
            Some(_) => {
                self.drop_held(&r.id);
                self.stats.receipted += 1;
                self.stats.delivered += 1;
            }
            None => {}
        }
        self.forget(r.id);
        true
    }

    /// The sender withdraws parcel `id` (it showed the secret).
    pub fn release(&mut self, id: &Hash32, secret: &[u8; 32]) -> bool {
        let ok = self.held.get(id).is_some_and(|h| h.parcel.release == release_hash(secret));
        if ok {
            self.drop_held(id);
            self.forget(*id);
            self.stats.released += 1;
        }
        ok
    }

    /// Drop what expired by wall-clock `now`.
    pub fn tick(&mut self, now: u64) {
        while let Some(&(until, id)) = self.expiry.first()
            && until <= now
        {
            self.drop_held(&id);
            self.stats.expired += 1;
        }
    }

    /// Internal consistency (tests and fuzzing).
    pub fn check(&self) -> Result<(), String> {
        let sum: u64 = self.held.values().map(|h| h.parcel.size()).sum();
        if sum != self.used {
            return Err(format!("used {} != {}", self.used, sum));
        }
        let dep: u64 = self.by_depositor.values().map(|s| s.bytes).sum();
        let dst: u64 = self.by_dst.values().map(|s| s.bytes).sum();
        let org: u64 = self.by_origin.values().sum();
        if dep != sum || dst != sum || org != sum || self.expiry.len() != self.held.len() {
            return Err("shares out of step".into());
        }
        if self.used > self.cfg.capacity || self.held.len() > self.cfg.max_parcels {
            return Err("over capacity".into());
        }
        Ok(())
    }
}

// ───────────────────────────── selection ─────────────────────────────

/// Why a custodian was chosen (in order of preference).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// One of the sender's own other devices.
    Own,
    /// Shares a space with the recipient: it will meet it.
    Shares,
    /// A volunteer, XOR-closest to the recipient's key.
    Volunteer,
}

/// XOR distance (Kademlia's metric), as bytes compared big-endian.
pub fn distance(a: &SignPk, b: &SignPk) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a.0[i] ^ b.0[i];
    }
    d
}

fn rank(dst: &SignPk, k: &SignPk) -> Hash32 {
    Hash32::digest(CTX_RANK, &[&dst.0[..], &k.0].concat())
}

/// The custodians to try for `dst`, best first, at most `max`: the
/// sender's own devices (`own`), then devices sharing a space with the
/// recipient (`shares`), each online ones first and otherwise in a fixed
/// order per recipient (rendezvous hash, so retries go to the same ones);
/// then `volunteers` by XOR distance to `dst`, which the recipient computes
/// the same way to find them. Never `dst` or `me`, nobody twice.
pub fn select(
    dst: &SignPk,
    me: &SignPk,
    own: &[SignPk],
    shares: &[SignPk],
    volunteers: &[SignPk],
    online: &dyn Fn(&SignPk) -> bool,
    max: usize,
) -> Vec<(SignPk, Tier)> {
    let mut seen: HashSet<SignPk> = [*dst, *me].into_iter().collect();
    let mut out = Vec::new();
    let mut tier = |keys: &[SignPk], t: Tier, out: &mut Vec<(SignPk, Tier)>| {
        let mut ks: Vec<(bool, [u8; 32], SignPk)> = keys
            .iter()
            .filter(|k| seen.insert(**k))
            .map(|k| match t {
                Tier::Volunteer => (false, distance(dst, k), *k),
                _ => (!online(k), rank(dst, k).0, *k),
            })
            .collect();
        ks.sort_unstable();
        out.extend(ks.into_iter().map(|(_, _, k)| (k, t)));
    };
    tier(own, Tier::Own, &mut out);
    tier(shares, Tier::Shares, &mut out);
    tier(volunteers, Tier::Volunteer, &mut out);
    out.truncate(max);
    out
}

// ───────────────────────────── directory ─────────────────────────────

/// Entries per bucket (Kademlia's k).
pub const BUCKET: usize = 16;
/// An entry not heard from for this long may be replaced (ms).
pub const STALE_MS: u64 = 3600 * 1000;

/// The custodians a device knows, in Kademlia k-buckets by XOR distance
/// from its own key: at most [`BUCKET`] per bucket, so the table stays
/// small (a few hundred keys) yet knows its own neighbourhood finely and
/// far regions coarsely. Like Kademlia, a full bucket keeps its old,
/// recently heard entries rather than taking every newcomer: a flood of
/// fresh keys can't flush the custodians that have been around. Only
/// devices we have talked to (whose hello advertised custody) are added;
/// keys from others' `Found` answers are candidates for one lookup, not
/// entries.
pub struct Directory {
    me: SignPk,
    buckets: Vec<Vec<(SignPk, u64)>>,
}

impl Directory {
    pub fn new(me: SignPk) -> Directory {
        Directory { me, buckets: vec![Vec::new(); 257] }
    }

    fn bucket(&self, k: &SignPk) -> usize {
        let d = distance(&self.me, k);
        let lead: u32 = zero_bits(&Hash32(d));
        lead.min(256) as usize
    }

    /// We heard from custodian `k` at `now` (ms).
    pub fn add(&mut self, k: SignPk, now: u64) {
        if k == self.me {
            return;
        }
        let i = self.bucket(&k);
        let b = &mut self.buckets[i];
        if let Some(e) = b.iter_mut().find(|e| e.0 == k) {
            e.1 = now;
            return;
        }
        if b.len() < BUCKET {
            b.push((k, now));
            return;
        }
        // full: replace the stalest entry only if it went quiet
        if let Some(e) = b.iter_mut().min_by_key(|e| e.1)
            && now.saturating_sub(e.1) > STALE_MS
        {
            *e = (k, now);
        }
    }

    pub fn remove(&mut self, k: &SignPk) {
        let i = self.bucket(k);
        self.buckets[i].retain(|e| e.0 != *k);
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, k: &SignPk) -> bool {
        self.buckets[self.bucket(k)].iter().any(|e| e.0 == *k)
    }

    /// The `n` known custodians XOR-closest to `target`.
    pub fn closest(&self, target: &SignPk, n: usize) -> Vec<SignPk> {
        let mut all: Vec<([u8; 32], SignPk)> =
            self.buckets.iter().flatten().map(|(k, _)| (distance(target, k), *k)).collect();
        all.sort_unstable();
        all.into_iter().take(n).map(|(_, k)| k).collect()
    }
}

// ───────────────────────────── the sender's record ─────────────────────────────

/// A parcel we deposited (or are depositing).
#[derive(Clone, Debug)]
pub struct Deposited {
    pub dst: SignPk,
    pub space: Hash32,
    /// What it carries (envelope and op ids), so later parcels skip them.
    pub envelopes: Vec<Hash32>,
    pub ops: Vec<Hash32>,
    pub secret: [u8; 32],
    /// Custodians that acknowledged custody.
    pub custodians: Vec<SignPk>,
    /// Wall-clock ms it expires.
    pub until: u64,
    /// Still being deposited.
    pub pending: bool,
}

/// Parcels remembered at most.
pub const OUTBOX_MAX: usize = 1024;

/// The sender's record of its parcels: what is in custody (so the next
/// parcel to the same member carries only what is new), who holds each
/// (the delivery state the app shows), and the secrets that withdraw them
/// once the member has synced live.
#[derive(Default)]
pub struct Outbox {
    parcels: HashMap<Hash32, Deposited>,
    order: VecDeque<Hash32>,
    by_item: HashMap<Hash32, Vec<Hash32>>,
}

impl Outbox {
    pub fn add(&mut self, id: Hash32, d: Deposited) {
        if self.parcels.contains_key(&id) {
            return;
        }
        for e in d.envelopes.iter().chain(&d.ops) {
            self.by_item.entry(*e).or_default().push(id);
        }
        self.parcels.insert(id, d);
        self.order.push_back(id);
        while self.order.len() > OUTBOX_MAX {
            if let Some(old) = self.order.pop_front() {
                self.remove(&old);
            }
        }
    }

    pub fn get(&self, id: &Hash32) -> Option<&Deposited> {
        self.parcels.get(id)
    }

    pub fn len(&self) -> usize {
        self.parcels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parcels.is_empty()
    }

    /// `c` took custody of `id`: `true` if that is news.
    pub fn ack(&mut self, id: &Hash32, c: SignPk) -> bool {
        match self.parcels.get_mut(id) {
            Some(d) if !d.custodians.contains(&c) => {
                d.custodians.push(c);
                true
            }
            _ => false,
        }
    }

    /// Depositing `id` is over: kept if someone took it, else forgotten (so
    /// what it carried goes in the next parcel).
    pub fn settle(&mut self, id: &Hash32) {
        let keep = match self.parcels.get_mut(id) {
            Some(d) => {
                d.pending = false;
                !d.custodians.is_empty()
            }
            None => return,
        };
        if !keep {
            self.remove(id);
        }
    }

    pub fn remove(&mut self, id: &Hash32) -> Option<Deposited> {
        let d = self.parcels.remove(id)?;
        for e in d.envelopes.iter().chain(&d.ops) {
            if let Some(v) = self.by_item.get_mut(e) {
                v.retain(|x| x != id);
                if v.is_empty() {
                    self.by_item.remove(e);
                }
            }
        }
        self.order.retain(|x| x != id);
        Some(d)
    }

    /// Envelopes and ops already in custody (or on their way) for `dst`.
    pub fn covered(&self, dst: &SignPk, space: &Hash32) -> HashSet<Hash32> {
        self.parcels
            .values()
            .filter(|d| d.dst == *dst && d.space == *space)
            .flat_map(|d| d.envelopes.iter().chain(&d.ops).copied())
            .collect()
    }

    /// The custodians holding a parcel that carries `item`.
    pub fn custodians_of(&self, item: &Hash32) -> BTreeSet<SignPk> {
        self.by_item
            .get(item)
            .map(|ids| ids.iter().filter_map(|i| self.parcels.get(i)).flat_map(|d| d.custodians.iter().copied()).collect())
            .unwrap_or_default()
    }

    /// `dst` synced `space` with us live: the parcels for it are no longer
    /// needed. Returns them (to release at their custodians).
    pub fn delivered(&mut self, dst: &SignPk, space: &Hash32) -> Vec<(Hash32, Deposited)> {
        let ids: Vec<Hash32> = self
            .parcels
            .iter()
            .filter(|(_, d)| d.dst == *dst && d.space == *space && !d.pending)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter().filter_map(|id| self.remove(&id).map(|d| (id, d))).collect()
    }

    /// Forget what expired by wall-clock `now`.
    pub fn expire(&mut self, now: u64) {
        let old: Vec<Hash32> = self.parcels.iter().filter(|(_, d)| d.until <= now).map(|(id, _)| *id).collect();
        for id in old {
            self.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests;
