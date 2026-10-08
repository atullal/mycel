//! Mesh frames on the wire (datagrams on a hop connection), mesh addresses,
//! and the signatures on announcements.

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use mycel_crypto::{DeviceKeys, Sig, SignPk};

use super::core::{Announce, Frame};
use crate::link::{CustomAddr, TRANSPORT_MESH};

const OGM_CTX: &str = "mycel/v1/mesh-announce";
pub(crate) const T_OGM: u8 = 1;
pub(crate) const T_DATA: u8 = 2;
/// Data frame header: type, ttl, flags, dst, src, waypoint, id, offset, total.
pub const DATA_HDR: usize = 3 + 32 * 3 + 4 + 2 + 2;
const F_REACHED: u8 = 1;
const F_CONTROL: u8 = 2;
/// QUIC's minimum MTU, and the largest packet the mesh carries: bigger ones
/// (MTU probes) are dropped, so end-to-end connections stay at 1200 bytes.
/// A hop's own MTU varies (it falls back to 1200 after loss); a 1200-byte
/// packet always gets through, whole or in two fragments, where a larger
/// one would be lost for good until the end-to-end path re-learnt its MTU.
pub const MIN_QUIC_MTU: usize = 1200;
pub const MAX_NAME: usize = 32;

/// A device's mesh address for `dst`, leaving through (and answered via)
/// `waypoint`: a neighbour, or a gateway.
pub fn mesh_addr(dst: &SignPk, waypoint: &SignPk) -> CustomAddr {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&dst.0);
    data[32..].copy_from_slice(&waypoint.0);
    CustomAddr::from_parts(TRANSPORT_MESH, &data)
}

/// `(destination, waypoint)` of a mesh address.
pub fn parse_mesh_addr(a: &CustomAddr) -> Option<(SignPk, SignPk)> {
    if a.id() != TRANSPORT_MESH || a.data().len() != 64 {
        return None;
    }
    let d = a.data();
    Some((SignPk(d[..32].try_into().ok()?), SignPk(d[32..].try_into().ok()?)))
}

pub fn truncate(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// Our announcement, signed.
pub fn sign_announce(keys: &DeviceKeys, seq: u64, flags: u8, name: &str) -> Announce {
    let name = truncate(name, MAX_NAME);
    let origin = keys.sign_pk();
    let sig = keys.sign(OGM_CTX, &[&origin.0, &seq.to_be_bytes(), &[flags], name.as_bytes()]);
    Announce { hops: 0, cost: 0, origin, seq, flags, name: Arc::from(name), sig }
}

/// The origin's signature over everything but `hops` and `cost`.
pub fn verify_announce(a: &Announce) -> bool {
    a.origin
        .verify(OGM_CTX, &[&a.origin.0, &a.seq.to_be_bytes(), &[a.flags], a.name.as_bytes()], &a.sig)
        .is_ok()
}

pub fn encode_announce(a: &Announce) -> Bytes {
    let mut b = BytesMut::with_capacity(1 + 1 + 4 + 32 + 8 + 1 + 1 + a.name.len() + 64);
    b.put_u8(T_OGM);
    b.put_u8(a.hops);
    b.put_u32(a.cost);
    b.put_slice(&a.origin.0);
    b.put_u64(a.seq);
    b.put_u8(a.flags);
    b.put_u8(a.name.len() as u8);
    b.put_slice(a.name.as_bytes());
    b.put_slice(&a.sig.0);
    b.freeze()
}

pub fn decode_announce(b: &[u8]) -> Option<Announce> {
    const FIXED: usize = 1 + 1 + 4 + 32 + 8 + 1 + 1;
    if b.len() < FIXED + 64 || b[0] != T_OGM {
        return None;
    }
    let hops = b[1];
    let cost = u32::from_be_bytes(b[2..6].try_into().ok()?);
    let origin = SignPk(b[6..38].try_into().ok()?);
    let seq = u64::from_be_bytes(b[38..46].try_into().ok()?);
    let flags = b[46];
    let n = b[47] as usize;
    if n > MAX_NAME || b.len() != FIXED + n + 64 {
        return None;
    }
    let name = std::str::from_utf8(&b[FIXED..FIXED + n]).ok()?;
    let sig = Sig(b[FIXED + n..].try_into().ok()?);
    Some(Announce { hops, cost, origin, seq, flags, name: Arc::from(name), sig })
}

fn header(f: &Frame, offset: u16, b: &mut BytesMut) {
    b.put_u8(T_DATA);
    b.put_u8(f.ttl);
    b.put_u8(if f.reached { F_REACHED } else { 0 } | if f.control { F_CONTROL } else { 0 });
    b.put_slice(&f.dst.0);
    b.put_slice(&f.src.0);
    b.put_slice(&f.waypoint.0);
    b.put_u32(f.id);
    b.put_u16(offset);
    b.put_u16(f.total);
}

/// Encoded datagrams of at most `max` bytes each, or `None` if the frame
/// can't (or shouldn't) be split to fit.
pub fn encode_frame(f: &Frame, max: usize) -> Option<Vec<Bytes>> {
    let room = max.checked_sub(DATA_HDR)?;
    if f.payload.len() <= room {
        let mut b = BytesMut::with_capacity(DATA_HDR + f.payload.len());
        header(f, f.offset, &mut b);
        b.put_slice(&f.payload);
        return Some(vec![b.freeze()]);
    }
    if f.total as usize > MIN_QUIC_MTU || room < 64 {
        return None;
    }
    Some(
        f.payload
            .chunks(room)
            .enumerate()
            .map(|(i, chunk)| {
                let mut b = BytesMut::with_capacity(DATA_HDR + chunk.len());
                header(f, f.offset + (i * room) as u16, &mut b);
                b.put_slice(chunk);
                b.freeze()
            })
            .collect(),
    )
}

pub fn decode_frame(b: Bytes) -> Option<Frame> {
    if b.len() < DATA_HDR || b[0] != T_DATA {
        return None;
    }
    let pk = |at: usize| -> Option<SignPk> { Some(SignPk(b[at..at + 32].try_into().ok()?)) };
    let frame = Frame {
        ttl: b[1],
        reached: b[2] & F_REACHED != 0,
        control: b[2] & F_CONTROL != 0,
        dst: pk(3)?,
        src: pk(35)?,
        waypoint: pk(67)?,
        id: u32::from_be_bytes(b[99..103].try_into().ok()?),
        offset: u16::from_be_bytes(b[103..105].try_into().ok()?),
        total: u16::from_be_bytes(b[105..107].try_into().ok()?),
        payload: b.slice(DATA_HDR..),
    };
    (frame.offset as usize + frame.payload.len() <= frame.total as usize).then_some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcements_round_trip_and_verify() {
        let k = DeviceKeys::generate();
        let mut a = sign_announce(&k, 1_700_000_000_000, 1, "Atul’s MacBook Pro with a long name");
        assert!(a.name.len() <= MAX_NAME);
        a.hops = 3;
        a.cost = 1234;
        let b = decode_announce(&encode_announce(&a)).unwrap();
        assert_eq!(a, b);
        assert!(verify_announce(&b), "hops and cost are not signed: relays fill them in");
        let mut flipped = b.clone();
        flipped.flags = 0;
        assert!(!verify_announce(&flipped), "the gateway flag is signed");
    }

    #[test]
    fn mesh_addresses_round_trip() {
        let (a, b) = (DeviceKeys::generate().sign_pk(), DeviceKeys::generate().sign_pk());
        let addr = mesh_addr(&a, &b);
        assert_eq!(crate::link::PathKind::of_custom(addr.id()), crate::link::PathKind::Mesh);
        assert_eq!(parse_mesh_addr(&addr), Some((a, b)));
    }

    #[test]
    fn frames_round_trip_with_flags() {
        let (a, b) = (DeviceKeys::generate().sign_pk(), DeviceKeys::generate().sign_pk());
        let f = Frame {
            ttl: 5,
            reached: true,
            control: true,
            dst: a,
            src: b,
            waypoint: b,
            id: 9,
            offset: 0,
            total: 3,
            payload: Bytes::from_static(b"abc"),
        };
        let d = decode_frame(encode_frame(&f, 1200).unwrap().remove(0)).unwrap();
        assert!(d.reached && d.control && d.ttl == 5 && d.id == 9 && &d.payload[..] == b"abc");
    }
}
