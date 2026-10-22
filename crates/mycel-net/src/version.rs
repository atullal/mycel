//! Protocol versions and capabilities (docs/PROTOCOL.md).
//!
//! Two mechanisms, as in HTTP/3 or QUIC itself:
//!
//! - **Wire versions** change what a byte means, so peers must agree on one
//!   before the first byte. They are chosen during the QUIC handshake by
//!   ALPN: a dialer offers every version it speaks (newest first, see
//!   [`crate::wire::alpns`] and [`crate::mesh::alpns`]) and the accepting
//!   side picks the newest one it also speaks. Nothing is sent to find out,
//!   and a peer that only speaks the old version keeps working.
//! - **Capabilities** ([`Caps`]) add things without changing what existing
//!   bytes mean: a new stream kind, an optional field, a new datagram type.
//!   On a connection of version 2 or later each side tells the other its set
//!   once, in a small [`Hello`]; a feature is used only when both sides have
//!   it. Unknown bits are ignored, so new ones can be assigned without a
//!   version change, and each hello sets one random *reserved* bit
//!   ([`Caps::RESERVED`], like TLS GREASE, RFC 8701) so an implementation
//!   that wrongly rejects unknown bits is caught at once, not years later.
//!
//! Version 1 is everything Mycel spoke before versions existed (pre-release
//! builds); version 2 is the first negotiated one. What v1 and v2 devices
//! can do together is in docs/PROTOCOL.md §5.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A wire version (a generation of every Mycel wire format at once).
pub type WireVersion = u16;

/// Pre-release builds: no negotiation, no hello.
pub const WIRE_V1: WireVersion = 1;
/// The first negotiated version: ALPN selection plus a capability hello.
pub const WIRE_V2: WireVersion = 2;
/// The newest version this build speaks (and offers by default).
pub const WIRE_VERSION: WireVersion = WIRE_V2;
/// The oldest version this build still speaks.
pub const MIN_WIRE_VERSION: WireVersion = WIRE_V1;

/// A set of capabilities (one bit each; see [`CAPABILITIES`]).
///
/// Bits are assigned once and never reused. A device advertises the ones it
/// implements; a feature is used on a connection only if it is in both
/// sides' sets ([`Caps::intersection`]).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Caps(u64);

impl Caps {
    /// Nothing beyond the wire version's baseline.
    pub const NONE: Caps = Caps(0);
    /// Negotiated set-reconciliation sync: a new stream kind that replaces
    /// the inventory exchange of `Sync` streams (node protocol).
    pub const SYNC_V2: Caps = Caps(1 << 0);
    /// Per-hop route attestations on mesh announcements (mesh protocol).
    pub const ROUTE_ATTEST: Caps = Caps(1 << 1);
    /// Speaks the custody protocol: deposits parcels for offline members
    /// with custodians and fetches its own (node protocol, stream kind
    /// `Custody`; docs/OFFLINE_DELIVERY.md). Bit 2 is taken by the Sync v2
    /// stage 3 work (`GOSSIP`).
    pub const CUSTODY: Caps = Caps(1 << 3);
    /// Keeps parcels for others now (a custodian). Not a feature both
    /// sides need: read from what the peer advertised
    /// ([`PeerProtocol::advertised`]), beside an agreed [`Caps::CUSTODY`].
    pub const CUSTODIAN: Caps = Caps(1 << 4);
    /// Bits never assigned: hellos set one at random so that peers keep
    /// ignoring bits they don't know (see the module docs).
    pub const RESERVED: Caps = Caps(0xffff << 48);
    /// Every bit this build has a name for.
    pub const KNOWN: Caps = Caps(Self::SYNC_V2.0 | Self::ROUTE_ATTEST.0 | Self::CUSTODY.0 | Self::CUSTODIAN.0);
    /// What this build implements, and so advertises by default.
    /// (`ROUTE_ATTEST` is registered for the work that implements it; a
    /// build sets it here once it does.)
    pub const SUPPORTED: Caps = Caps(Self::SYNC_V2.0 | Self::CUSTODY.0 | Self::CUSTODIAN.0);

    /// The raw bits, unknown ones included.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Bits as received: unknown ones are kept (they are simply never
    /// asked about).
    pub const fn from_bits(bits: u64) -> Caps {
        Caps(bits)
    }

    pub const fn contains(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Caps) -> Caps {
        Caps(self.0 | other.0)
    }

    pub const fn intersection(self, other: Caps) -> Caps {
        Caps(self.0 & other.0)
    }

    pub const fn difference(self, other: Caps) -> Caps {
        Caps(self.0 & !other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The bits this build has no name for.
    pub const fn unknown(self) -> Caps {
        self.difference(Self::KNOWN)
    }
}

impl std::ops::BitOr for Caps {
    type Output = Caps;
    fn bitor(self, rhs: Caps) -> Caps {
        self.union(rhs)
    }
}

impl fmt::Debug for Caps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        for c in CAPABILITIES {
            if self.contains(c.cap) {
                set.entry(&format_args!("{}", c.name));
            }
        }
        if !self.unknown().is_empty() {
            set.entry(&format_args!("{:#x}", self.unknown().0));
        }
        set.finish()
    }
}

/// One entry of the capability registry.
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub cap: Caps,
    pub name: &'static str,
    /// The protocol whose hello it is meaningful in: `"node"` or `"mesh"`.
    pub protocol: &'static str,
    pub summary: &'static str,
}

/// The capability registry. New bits are appended here (and in
/// docs/PROTOCOL.md §4); a bit is never reassigned.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        cap: Caps::SYNC_V2,
        name: "SYNC_V2",
        protocol: "node",
        summary: "set-reconciliation sync stream (cost tracks the difference, not the history)",
    },
    Capability {
        cap: Caps::ROUTE_ATTEST,
        name: "ROUTE_ATTEST",
        protocol: "mesh",
        summary: "per-hop attestations on route announcements",
    },
    Capability {
        cap: Caps::CUSTODY,
        name: "CUSTODY",
        protocol: "node",
        summary: "custody stream: sealed parcels for offline members deposited with custodians, fetched by their recipient",
    },
    Capability {
        cap: Caps::CUSTODIAN,
        name: "CUSTODIAN",
        protocol: "node",
        summary: "keeps parcels for others now (read from what the peer advertised)",
    },
];

/// What a device speaks: the newest wire version it offers and the
/// capabilities it advertises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol {
    /// The newest wire version offered (between [`MIN_WIRE_VERSION`] and
    /// [`WIRE_VERSION`]); every older one down to [`MIN_WIRE_VERSION`] is
    /// accepted too. Set to [`WIRE_V1`] to behave like a pre-release build.
    pub version: WireVersion,
    pub caps: Caps,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol { version: WIRE_VERSION, caps: Caps::SUPPORTED }
    }
}

impl Protocol {
    /// The versions offered, newest first.
    pub fn versions(&self) -> impl Iterator<Item = WireVersion> {
        (MIN_WIRE_VERSION..=self.version.clamp(MIN_WIRE_VERSION, WIRE_VERSION)).rev()
    }
}

/// A protocol's ALPNs, one per wire version, oldest first: entry `i` names
/// version `MIN_WIRE_VERSION + i`. The array's length follows
/// [`WIRE_VERSION`], so raising it without naming the new version's ALPN
/// doesn't build, and [`alpn_table_ok`] (asserted at compile time beside
/// each table) rejects a table with versions out of place or two versions
/// under one name, which would let one version's bytes reach a peer under
/// another's name.
pub type AlpnTable = [(WireVersion, &'static [u8]); (WIRE_VERSION - MIN_WIRE_VERSION + 1) as usize];

/// Whether `t` lists every version in order, each under its own name.
pub const fn alpn_table_ok(t: &AlpnTable) -> bool {
    const fn same(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    let mut i = 0;
    while i < t.len() {
        if t[i].0 != MIN_WIRE_VERSION + i as WireVersion || t[i].1.is_empty() {
            return false;
        }
        let mut j = 0;
        while j < i {
            if same(t[i].1, t[j].1) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// The ALPNs in `t` for wire versions `newest` down to the oldest
/// supported, newest first: what a dialer offers and, in that order of
/// preference, what a listener accepts.
pub fn alpns_in(t: &AlpnTable, newest: WireVersion) -> Vec<&'static [u8]> {
    Protocol { version: newest, caps: Caps::NONE }.versions().map(|v| t[usize::from(v - MIN_WIRE_VERSION)].1).collect()
}

/// The wire version `alpn` stands for in `t`.
pub fn version_in(t: &AlpnTable, alpn: &[u8]) -> Option<WireVersion> {
    t.iter().find(|(_, a)| *a == alpn).map(|(v, _)| *v)
}

/// What was agreed with a peer on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerProtocol {
    /// The wire version the handshake chose.
    pub version: WireVersion,
    /// Capabilities both sides have: what may be used.
    pub caps: Caps,
    /// What the peer advertised, unknown bits included (diagnostics).
    pub advertised: Caps,
}

impl PeerProtocol {
    /// A connection on which no hello is exchanged (version 1).
    pub const fn baseline(version: WireVersion) -> Self {
        PeerProtocol { version, caps: Caps::NONE, advertised: Caps::NONE }
    }

    /// After the peer's hello: what both sides have.
    pub fn agreed(version: WireVersion, ours: Caps, theirs: Caps) -> Self {
        // reserved bits are noise by definition, even if we sent one
        let ours = ours.difference(Caps::RESERVED);
        PeerProtocol { version, caps: ours.intersection(theirs), advertised: theirs }
    }

    /// Whether `cap` may be used with this peer.
    pub fn supports(&self, cap: Caps) -> bool {
        !cap.is_empty() && self.caps.contains(cap)
    }
}

/// The capability hello, sent once per connection by each side on version
/// 2 and later. It may only grow at the end: receivers read the fields they
/// know and ignore any bytes after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub caps: Caps,
}

/// Hellos are tiny; a longer one is refused.
pub const MAX_HELLO: usize = 256;

impl Hello {
    /// Our hello: `caps` plus one random reserved bit.
    pub fn ours(caps: Caps) -> Hello {
        let bit = 48 + (mycel_crypto::random_u64() % 16);
        Hello { caps: caps.union(Caps(1 << bit)) }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a hello encodes")
    }

    /// A hello from a peer; trailing bytes (fields added later) are ignored.
    pub fn decode(bytes: &[u8]) -> Result<Hello, VersionError> {
        if bytes.len() > MAX_HELLO {
            return Err(VersionError::Malformed("hello"));
        }
        postcard::take_from_bytes::<Hello>(bytes).map(|(h, _rest)| h).map_err(|_| VersionError::Malformed("hello"))
    }
}

/// QUIC application error code on a stream reset or stop: "I don't speak
/// what this stream carries" (an unknown stream kind). The opener gets
/// [`VersionError::StreamRefused`] instead of waiting for a timeout.
pub const STREAM_REFUSED: u32 = 0x6d79_0001;

/// Why something versioned could not be used. Every decoder refuses with
/// one of these rather than guessing at bytes it does not understand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// `what` arrived in a version this build does not speak.
    Unsupported { what: &'static str, version: u32, newest: u32 },
    /// A stream started with a kind byte this build does not know.
    UnknownStreamKind(u8),
    /// The peer reset our stream with [`STREAM_REFUSED`]: it does not know
    /// that stream kind (it runs an older build).
    StreamRefused,
    /// The peer does not have a capability this needs.
    MissingCapability(Caps),
    /// A versioned header that does not parse.
    Malformed(&'static str),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::Unsupported { what, version, newest } if version > newest => write!(
                f,
                "{what} version {version} is newer than this build understands (up to {newest}): update Mycel"
            ),
            VersionError::Unsupported { what, version, .. } => write!(f, "{what} version {version} is not supported"),
            VersionError::UnknownStreamKind(k) => write!(f, "unknown stream kind {k}"),
            VersionError::StreamRefused => write!(f, "the device doesn't support this exchange (an older version)"),
            VersionError::MissingCapability(c) => write!(f, "the device lacks capability {c:?}"),
            VersionError::Malformed(what) => write!(f, "malformed {what}"),
        }
    }
}

impl std::error::Error for VersionError {}

/// If `err` is a stream reset or stop with [`STREAM_REFUSED`], the typed
/// error for it; otherwise `err` unchanged.
pub(crate) fn refusal(err: anyhow::Error) -> anyhow::Error {
    use iroh::endpoint::{ReadError, ReadExactError, VarInt, WriteError};
    let code = VarInt::from_u32(STREAM_REFUSED);
    let is_refusal = |e: &(dyn std::error::Error + 'static)| {
        matches!(e.downcast_ref::<ReadError>(), Some(ReadError::Reset(c)) if *c == code)
            || matches!(e.downcast_ref::<ReadExactError>(), Some(ReadExactError::ReadError(ReadError::Reset(c))) if *c == code)
            || matches!(e.downcast_ref::<WriteError>(), Some(WriteError::Stopped(c)) if *c == code)
    };
    // (an `io::Error` hides the error it wraps from `source()`)
    let refused = err.chain().any(|e| {
        is_refusal(e) || e.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).is_some_and(|e| is_refusal(e))
    });
    if refused { anyhow::Error::new(VersionError::StreamRefused) } else { err }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bits_are_unique_and_outside_the_reserved_range() {
        let mut seen = Caps::NONE;
        for c in CAPABILITIES {
            assert_eq!(c.cap.bits().count_ones(), 1, "{} is one bit", c.name);
            assert!(seen.intersection(c.cap).is_empty(), "{} reuses a bit", c.name);
            assert!(Caps::RESERVED.intersection(c.cap).is_empty(), "{} is reserved", c.name);
            seen = seen | c.cap;
        }
        assert_eq!(seen, Caps::KNOWN);
        assert!(Caps::KNOWN.contains(Caps::SUPPORTED));
    }

    #[test]
    fn unknown_capability_bits_are_ignored() {
        let future = Caps::from_bits(1 << 40);
        let theirs = Caps::SYNC_V2 | future | Caps::from_bits(1 << 50);
        let ours = Caps::SYNC_V2 | Caps::ROUTE_ATTEST;
        let p = PeerProtocol::agreed(WIRE_V2, ours, theirs);
        assert_eq!(p.caps, Caps::SYNC_V2, "only what both have; unknown and reserved bits drop out");
        assert!(p.supports(Caps::SYNC_V2) && !p.supports(Caps::ROUTE_ATTEST) && !p.supports(Caps::NONE));
        assert_eq!(p.advertised.unknown(), future | Caps::from_bits(1 << 50));
        assert_eq!(format!("{theirs:?}"), format!("{{SYNC_V2, {:#x}}}", (1u64 << 40) | (1u64 << 50)));
        // even a reserved bit we happened to send is never "agreed"
        let grease = Caps::from_bits(1 << 49);
        assert!(PeerProtocol::agreed(WIRE_V2, grease, grease).caps.is_empty());
    }

    #[test]
    fn hellos_carry_one_reserved_bit_and_may_grow() {
        for _ in 0..64 {
            let h = Hello::ours(Caps::SYNC_V2);
            assert!(h.caps.contains(Caps::SYNC_V2));
            assert_eq!(h.caps.intersection(Caps::RESERVED).bits().count_ones(), 1);
            assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
        }
        // a later version appends fields: we read ours and ignore the rest
        let mut longer = Hello { caps: Caps::ROUTE_ATTEST }.encode();
        longer.extend_from_slice(&[7, 1, 2, 3]);
        assert_eq!(Hello::decode(&longer).unwrap().caps, Caps::ROUTE_ATTEST);
        assert_eq!(Hello::decode(&[]), Err(VersionError::Malformed("hello")));
        assert_eq!(Hello::decode(&[0xff; 11]), Err(VersionError::Malformed("hello")));
        assert_eq!(Hello::decode(&vec![0; MAX_HELLO + 1]), Err(VersionError::Malformed("hello")));
    }

    #[test]
    fn versions_offered_newest_first() {
        assert_eq!(Protocol::default().versions().collect::<Vec<_>>(), vec![WIRE_V2, WIRE_V1]);
        let old = Protocol { version: WIRE_V1, caps: Caps::NONE };
        assert_eq!(old.versions().collect::<Vec<_>>(), vec![WIRE_V1]);
        // out of range is clamped, never empty
        assert_eq!(Protocol { version: 0, caps: Caps::NONE }.versions().count(), 1);
        assert_eq!(Protocol { version: 99, caps: Caps::NONE }.versions().next(), Some(WIRE_VERSION));
    }

    #[test]
    fn errors_explain_newer_versions() {
        let e = VersionError::Unsupported { what: "bundle", version: 3, newest: 2 };
        assert!(e.to_string().contains("newer than this build"), "{e}");
        let e = VersionError::Unsupported { what: "bundle", version: 0, newest: 2 };
        assert_eq!(e.to_string(), "bundle version 0 is not supported");
    }
}
