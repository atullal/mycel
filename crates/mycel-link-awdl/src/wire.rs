//! Platform-independent pieces of the AWDL link: the Bonjour service and TXT
//! record, and the tiny control datagrams that tell a listener which device
//! a new flow belongs to.
//!
//! QUIC packets travel *unframed*, one per UDP datagram, so a full-size QUIC
//! packet (1452 bytes, Iroh's path-MTU ceiling) still fits awdl0's 1500-byte
//! MTU over IPv6. Control datagrams are told apart by an 8-byte magic plus
//! an exact length; a QUIC packet matching both by chance (≈2⁻⁶⁴) would only
//! be dropped, and QUIC retransmits it.

use mycel_crypto::SignPk;

/// Bonjour service type advertised and browsed.
pub const SERVICE_TYPE: &str = "_mycel-p2p._udp";
/// TXT keys.
pub const TXT_KEY: &str = "pk";
pub const TXT_NAME: &str = "n";
pub const TXT_VERSION: &str = "v";
/// Longest display name put in the TXT record (bytes).
pub const MAX_NAME: usize = 63;

const MAGIC: &[u8; 8] = b"\xffMYCAWD\x01";
pub const CONTROL_LEN: usize = 8 + 1 + 32;

/// A control datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// "I am `key`" — sent first and then periodically on every outbound flow.
    Hello(SignPk),
    /// Reply to a hello: "and I am `key`" — proves the flow works both ways.
    Ack(SignPk),
}

impl Control {
    pub fn encode(&self) -> [u8; CONTROL_LEN] {
        let (kind, key) = match self {
            Control::Hello(k) => (1u8, k),
            Control::Ack(k) => (2u8, k),
        };
        let mut out = [0u8; CONTROL_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = kind;
        out[9..].copy_from_slice(&key.0);
        out
    }

    /// `None` for anything that isn't a control datagram (i.e. QUIC).
    pub fn decode(b: &[u8]) -> Option<Control> {
        if b.len() != CONTROL_LEN || &b[..8] != MAGIC {
            return None;
        }
        let key = SignPk(b[9..].try_into().ok()?);
        match b[8] {
            1 => Some(Control::Hello(key)),
            2 => Some(Control::Ack(key)),
            _ => None,
        }
    }
}

/// Bonjour instance name for a device: unique enough (64-bit prefix of the
/// key) and within the 63-byte DNS label limit. The full key is in the TXT.
pub fn instance_name(me: &SignPk) -> String {
    format!("mycel-{}", hex::encode(&me.0[..8]))
}

/// What a peer advertises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    pub key: SignPk,
    pub name: Option<String>,
}

/// TXT record entries for our advertisement.
pub fn txt_entries(me: &SignPk, name: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (TXT_VERSION, b"1".to_vec()),
        (TXT_KEY, hex::encode(me.0).into_bytes()),
        (TXT_NAME, truncate_utf8(name, MAX_NAME).as_bytes().to_vec()),
    ]
}

/// Parse a peer's TXT values (`pk` hex key, optional `n` name).
pub fn parse_advert(pk: Option<&[u8]>, name: Option<&[u8]>) -> Option<Advert> {
    let pk = pk?;
    if pk.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(pk, &mut key).ok()?;
    let name = name
        .and_then(|n| std::str::from_utf8(n).ok())
        // (trimmed again after the cut, which can end on whitespace)
        .map(|n| truncate_utf8(n.trim(), MAX_NAME).trim_end().to_string())
        .filter(|n| !n.is_empty());
    Some(Advert { key: SignPk(key), name })
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Apple's peer-to-peer Wi-Fi interfaces: `awdl0` (Apple Wireless Direct
/// Link) and `llw0` (its low-latency companion). BSD names aren't API, but
/// they have been stable since AWDL shipped; this only decides which
/// interfaces count as "peer-to-peer" for filtering.
pub fn is_peer_to_peer_interface(name: &str) -> bool {
    name.starts_with("awdl") || name.starts_with("llw")
}

/// `dns_sd` error code for "Local Network privacy denied this".
pub const DNS_POLICY_DENIED: i32 = -65570;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SignPk {
        SignPk([b; 32])
    }

    #[test]
    fn control_roundtrip() {
        for c in [Control::Hello(key(7)), Control::Ack(key(0xab))] {
            let b = c.encode();
            assert_eq!(b.len(), CONTROL_LEN);
            assert_eq!(Control::decode(&b), Some(c));
        }
    }

    #[test]
    fn quic_packets_are_not_control() {
        let mut b = Control::Hello(key(1)).encode();
        assert_eq!(Control::decode(&b[..CONTROL_LEN - 1]), None, "short");
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(Control::decode(&long), None, "long");
        b[8] = 9;
        assert_eq!(Control::decode(&b), None, "unknown kind");
        b[8] = 1;
        b[0] = 0xc3; // a QUIC long-header first byte
        assert_eq!(Control::decode(&b), None, "no magic");
        assert_eq!(Control::decode(&[0x40; 1200]), None, "1-RTT packet");
    }

    #[test]
    fn advert_roundtrip() {
        let me = key(0x5a);
        let e = txt_entries(&me, "Alice's MacBook");
        let get = |k: &str| e.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_slice());
        assert_eq!(
            parse_advert(get(TXT_KEY), get(TXT_NAME)),
            Some(Advert { key: me, name: Some("Alice's MacBook".into()) })
        );
        assert_eq!(parse_advert(get(TXT_KEY), None).unwrap().name, None);
        assert_eq!(parse_advert(get(TXT_KEY), Some(b"  ")).unwrap().name, None);
    }

    #[test]
    fn bad_adverts_rejected() {
        assert_eq!(parse_advert(None, Some(b"x")), None);
        assert_eq!(parse_advert(Some(b"abcd"), None), None);
        assert_eq!(parse_advert(Some(&[b'z'; 64]), None), None);
        assert!(parse_advert(Some(&[b'A'; 64]), Some(&[0xff, 0xfe])).unwrap().name.is_none());
    }

    /// Found by fuzzing (`fuzz/fuzz_targets/link_wire.rs`): a long name was
    /// trimmed before being cut to [`MAX_NAME`], so a cut landing in
    /// whitespace kept it, and the same advert parsed to different names
    /// depending on whether it had been re-encoded.
    #[test]
    fn a_name_cut_in_whitespace_is_trimmed() {
        let name = format!("{}{}tail", "A".repeat(MAX_NAME - 3), " ".repeat(10));
        let pk = hex::encode(key(2).0);
        let a = parse_advert(Some(pk.as_bytes()), Some(name.as_bytes())).unwrap();
        assert_eq!(a.name.as_deref(), Some("A".repeat(MAX_NAME - 3).as_str()));
        let e = txt_entries(&a.key, a.name.as_deref().unwrap());
        let get = |k: &str| e.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_slice());
        assert_eq!(parse_advert(get(TXT_KEY), get(TXT_NAME)), Some(a), "parsing is idempotent");
    }

    #[test]
    fn long_names_truncate_on_char_boundary() {
        let name = "é".repeat(40); // 80 bytes
        let e = txt_entries(&key(1), &name);
        let n = &e.iter().find(|(k, _)| *k == TXT_NAME).unwrap().1;
        assert!(n.len() <= MAX_NAME);
        assert!(std::str::from_utf8(n).is_ok());
    }

    #[test]
    fn instance_names_fit_a_dns_label() {
        let n = instance_name(&key(0xff));
        assert!(n.len() <= 63);
        assert_eq!(n, "mycel-ffffffffffffffff");
    }

    #[test]
    fn peer_to_peer_interfaces() {
        assert!(is_peer_to_peer_interface("awdl0"));
        assert!(is_peer_to_peer_interface("llw0"));
        for n in ["en0", "lo0", "utun3", "bridge0", "anpi0"] {
            assert!(!is_peer_to_peer_interface(n), "{n}");
        }
    }
}
