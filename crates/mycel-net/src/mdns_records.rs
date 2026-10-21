//! The Bonjour records a LAN peer's advertisement arrives in (SRV and TXT
//! record data), as the system's DNS-SD daemon hands them to
//! `native_mdns.rs`. Pure parsers of untrusted bytes, kept apart from the
//! Apple-only FFI so the fuzz targets reach them on every platform
//! (docs/TESTING.md, "Fuzzing").
use iroh::address_lookup::UserData;

/// One SRV record of a peer's instance: a host and a port. iroh's mDNS
/// advertises one per port (its LAN socket, a NAT mapping, ...), each with
/// its own host name and addresses.
pub(crate) type Target = (String, u16);

/// An SRV record's target name, from its uncompressed wire format into the
/// presentation form DNSServiceGetAddrInfo takes.
pub(crate) fn wire_name(mut wire: &[u8]) -> Option<String> {
    let mut name = String::new();
    loop {
        let (&len, rest) = wire.split_first()?;
        if len == 0 {
            break;
        }
        let len = len as usize;
        if len > 63 || rest.len() < len {
            return None;
        }
        for &b in &rest[..len] {
            match b {
                b'.' | b'\\' => {
                    name.push('\\');
                    name.push(b as char);
                }
                b' '..=b'~' => name.push(b as char),
                _ => return None,
            }
        }
        name.push('.');
        wire = &rest[len..];
    }
    (!name.is_empty() && name.len() <= 255).then_some(name)
}
pub(crate) fn parse_srv(rdata: &[u8]) -> Option<Target> {
    let port = u16::from_be_bytes(rdata.get(4..6)?.try_into().ok()?);
    Some((wire_name(rdata.get(6..)?)?, port))
}
/// A peer's Iroh user data from its TXT record data, if it has any.
pub(crate) fn parse_txt(mut txt: &[u8]) -> Option<UserData> {
    while let Some((&len, rest)) = txt.split_first() {
        let len = len as usize;
        if rest.len() < len {
            return None;
        }
        let value = &rest[..len];
        txt = &rest[len..];
        if let Some(value) = value.strip_prefix(b"user-data=") {
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
    }
    None
}
