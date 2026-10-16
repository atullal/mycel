//! Beacons (discovery) and link addresses.
//!
//! A beacon is one UDP datagram sent to [`GROUP`] on [`DISCOVERY_PORT`] from
//! the interface's data socket, so its source address *is* the address to
//! send QUIC packets to:
//!
//! ```text
//! "MYCELIF" 0x01 | node key (32) | name length (1) | name (UTF-8, ≤ 64)
//! ```
//!
//! Beacons are not authenticated: a forged one only adds an address that
//! fails QUIC's handshake (every path is authenticated to the peer's key).

use std::net::{Ipv6Addr, SocketAddrV6};

use mycel_crypto::SignPk;
use mycel_net::PathKind;
use mycel_net::link::{CustomAddr, TRANSPORT_IFACE};

/// Transient link-local multicast group ("myc" "el").
pub const GROUP: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0x6d79, 0x6365, 0x6c00);
pub const DISCOVERY_PORT: u16 = 45_812;
const MAGIC: &[u8; 8] = b"MYCELIF\x01";
pub const MAX_NAME: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub key: SignPk,
    pub name: String,
}

impl Beacon {
    pub fn encode(&self) -> Vec<u8> {
        let mut name = self.name.as_bytes();
        if name.len() > MAX_NAME {
            let mut end = MAX_NAME;
            while !self.name.is_char_boundary(end) {
                end -= 1;
            }
            name = &name[..end];
        }
        let mut out = Vec::with_capacity(8 + 32 + 1 + name.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.key.0);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Beacon> {
        let rest = b.strip_prefix(MAGIC.as_slice())?;
        let key = SignPk(rest.get(..32)?.try_into().ok()?);
        let len = *rest.get(32)? as usize;
        let name = std::str::from_utf8(rest.get(33..33 + len)?).ok()?.to_string();
        Some(Beacon { key, name })
    }
}

/// Where a path goes: medium, *our* interface index, and the peer's
/// link-local socket address on it. Only meaningful on this machine (the
/// index is ours), so these are never published, only learned from beacons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IfaceAddr {
    pub kind: PathKind,
    pub index: u32,
    pub ip: Ipv6Addr,
    pub port: u16,
}

impl IfaceAddr {
    pub fn to_custom(self) -> CustomAddr {
        let mut d = [0u8; 23];
        d[0] = self.kind.code();
        d[1..5].copy_from_slice(&self.index.to_be_bytes());
        d[5..21].copy_from_slice(&self.ip.octets());
        d[21..23].copy_from_slice(&self.port.to_be_bytes());
        CustomAddr::from_parts(TRANSPORT_IFACE, &d)
    }

    pub fn from_custom(a: &CustomAddr) -> Option<IfaceAddr> {
        let d = a.data();
        if a.id() != TRANSPORT_IFACE || d.len() != 23 {
            return None;
        }
        Some(IfaceAddr {
            kind: PathKind::from_code(d[0]),
            index: u32::from_be_bytes(d[1..5].try_into().ok()?),
            ip: Ipv6Addr::from(<[u8; 16]>::try_from(&d[5..21]).ok()?),
            port: u16::from_be_bytes(d[21..23].try_into().ok()?),
        })
    }

    pub fn socket(self) -> SocketAddrV6 {
        // the scope only matters for link-local addresses (Linux's lo uses ::1)
        let scope = if self.ip.is_unicast_link_local() { self.index } else { 0 };
        SocketAddrV6::new(self.ip, self.port, 0, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_round_trip() {
        let b = Beacon { key: SignPk([9; 32]), name: "Alice’s Laptop".into() };
        assert_eq!(Beacon::decode(&b.encode()), Some(b));
        assert_eq!(Beacon::decode(b"MYCELIF\x02rest"), None, "other version");
        assert_eq!(Beacon::decode(&b"MYCELIF\x01"[..]), None, "truncated");
        let long = Beacon { key: SignPk([1; 32]), name: "é".repeat(40) };
        let back = Beacon::decode(&long.encode()).unwrap();
        assert!(back.name.len() <= MAX_NAME && long.name.starts_with(&back.name), "cut on a char boundary");
    }

    #[test]
    fn addresses_carry_their_medium() {
        let a = IfaceAddr { kind: PathKind::Uwb, index: 12, ip: "fe80::abcd".parse().unwrap(), port: 50_001 };
        let c = a.to_custom();
        assert_eq!(PathKind::of_custom_addr(&c), PathKind::Uwb, "the node reads the medium");
        assert_eq!(IfaceAddr::from_custom(&c), Some(a));
        assert_eq!(a.socket().scope_id(), 12);
        assert_eq!(IfaceAddr::from_custom(&CustomAddr::from_parts(TRANSPORT_IFACE, &[0; 5])), None);
        assert!(GROUP.is_multicast());
    }
}
