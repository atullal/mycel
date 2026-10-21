//! Mesh frames on the wire (datagrams on a hop connection), mesh addresses,
//! and the signatures on announcements.

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use mycel_crypto::{DeviceKeys, Sig, SignPk};

use super::core::{Announce, Frame, Origination, SeqReq};
use crate::link::{CustomAddr, TRANSPORT_MESH};

const OGM_CTX: &str = "mycel/v1/mesh-announce";
pub(crate) const T_OGM: u8 = 1;
pub(crate) const T_DATA: u8 = 2;
pub(crate) const T_SEQREQ: u8 = 3;
/// Several announcements for one neighbour in one datagram.
pub(crate) const T_OGMS: u8 = 4;
/// Data frame header: type, ttl, flags, dst, src, waypoint, id, offset, total.
pub const DATA_HDR: usize = 3 + 32 * 3 + 4 + 2 + 2;
const F_REACHED: u8 = 1;
const F_CONTROL: u8 = 2;
/// Flag bits not assigned yet (wire version 2): relays carry them
/// unchanged and a destination ignores the ones it doesn't know, so a later
/// version can mark frames end to end without upgrading every relay. A
/// change relays must understand needs a new datagram type, sent only to
/// neighbours whose hello has the capability for it.
pub const F_EXTENSIONS: u8 = !(F_REACHED | F_CONTROL);
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
pub fn sign_announce(keys: &DeviceKeys, o: Origination, name: &str) -> Announce {
    let name = truncate(name, MAX_NAME);
    let origin = keys.sign_pk();
    let sig = keys.sign(OGM_CTX, &signed_parts(&origin, o.seq, o.flags, o.scope, o.uplink, &name).each());
    Announce {
        hops: 0,
        cost: 0,
        origin,
        seq: o.seq,
        flags: o.flags,
        scope: o.scope,
        uplink: o.uplink,
        name: Arc::from(name),
        sig,
    }
}

/// What the origin signs: everything but `hops` and `cost`.
struct Parts {
    origin: [u8; 32],
    seq: [u8; 8],
    rest: [u8; 6],
    name: Vec<u8>,
}

impl Parts {
    fn each(&self) -> [&[u8]; 4] {
        [&self.origin, &self.seq, &self.rest, &self.name]
    }
}

fn signed_parts(origin: &SignPk, seq: u64, flags: u8, scope: u8, uplink: u32, name: &str) -> Parts {
    let u = uplink.to_be_bytes();
    Parts {
        origin: origin.0,
        seq: seq.to_be_bytes(),
        rest: [flags, scope, u[0], u[1], u[2], u[3]],
        name: name.as_bytes().to_vec(),
    }
}

/// The origin's signature over everything but `hops` and `cost`.
pub fn verify_announce(a: &Announce) -> bool {
    let p = signed_parts(&a.origin, a.seq, a.flags, a.scope, a.uplink, &a.name);
    a.origin.verify(OGM_CTX, &p.each(), &a.sig).is_ok()
}

const OGM_FIXED: usize = 1 + 1 + 4 + 32 + 8 + 1 + 1 + 4 + 1;
/// A sequence-number request's encoded length.
pub const SEQREQ_LEN: usize = 1 + 32 + 8 + 1;

/// [`encode_announce`]'s length for `a`, without encoding it.
pub fn announce_len(a: &Announce) -> usize {
    OGM_FIXED + a.name.len() + 64
}

pub fn encode_announce(a: &Announce) -> Bytes {
    let mut b = BytesMut::with_capacity(announce_len(a));
    b.put_u8(T_OGM);
    b.put_u8(a.hops);
    b.put_u32(a.cost);
    b.put_slice(&a.origin.0);
    b.put_u64(a.seq);
    b.put_u8(a.flags);
    b.put_u8(a.scope);
    b.put_u32(a.uplink);
    b.put_u8(a.name.len() as u8);
    b.put_slice(a.name.as_bytes());
    b.put_slice(&a.sig.0);
    b.freeze()
}

pub fn decode_announce(b: &[u8]) -> Option<Announce> {
    if b.len() < OGM_FIXED + 64 || b[0] != T_OGM {
        return None;
    }
    let hops = b[1];
    let cost = u32::from_be_bytes(b[2..6].try_into().ok()?);
    let origin = SignPk(b[6..38].try_into().ok()?);
    let seq = u64::from_be_bytes(b[38..46].try_into().ok()?);
    let flags = b[46];
    let scope = b[47];
    let uplink = u32::from_be_bytes(b[48..52].try_into().ok()?);
    let n = b[52] as usize;
    if n > MAX_NAME || b.len() != OGM_FIXED + n + 64 {
        return None;
    }
    let name = std::str::from_utf8(&b[OGM_FIXED..OGM_FIXED + n]).ok()?;
    let sig = Sig(b[OGM_FIXED + n..].try_into().ok()?);
    Some(Announce { hops, cost, origin, seq, flags, scope, uplink, name: Arc::from(name), sig })
}

/// The encoded length of the announcement starting at `b[0]`, if whole.
fn announce_len_at(b: &[u8]) -> Option<usize> {
    let n = *b.get(OGM_FIXED - 1)? as usize;
    let len = OGM_FIXED + n + 64;
    (b.first() == Some(&T_OGM) && n <= MAX_NAME && b.len() >= len).then_some(len)
}

/// Announcements for one neighbour, packed into as few datagrams of at
/// most `max` bytes as they fit in (one per datagram if `max` is small).
/// Each QUIC packet on a hop costs ~40 bytes of headers and, on Bluetooth,
/// a connection event: a tick's worth of rebroadcasts or a new neighbour's
/// greeting goes in one or two.
pub fn encode_announces(anns: &[Announce], max: usize) -> Vec<Bytes> {
    let mut out = Vec::new();
    let mut cur = BytesMut::new();
    for (a, first) in anns.iter().zip(batch_starts(anns, max)) {
        if first && !cur.is_empty() {
            out.push(std::mem::take(&mut cur).freeze());
        }
        if cur.is_empty() {
            cur.put_u8(T_OGMS);
        }
        cur.put_slice(&encode_announce(a));
    }
    if !cur.is_empty() {
        out.push(cur.freeze());
    }
    out
}

/// For each of `anns`, whether it starts a new datagram in
/// [`encode_announces`]: the packing both it and [`announces_lens`] use.
fn batch_starts(anns: &[Announce], max: usize) -> impl Iterator<Item = bool> + '_ {
    let mut cur = 0;
    anns.iter().map(move |a| {
        let e = announce_len(a);
        let first = cur == 0 || cur + e > max;
        if first {
            cur = 1; // the T_OGMS byte
        }
        cur += e;
        first
    })
}

/// The lengths of the datagrams [`encode_announces`] packs `anns` into,
/// without encoding them.
pub fn announces_lens(anns: &[Announce], max: usize) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for (a, first) in anns.iter().zip(batch_starts(anns, max)) {
        match out.last_mut() {
            Some(cur) if !first => *cur += announce_len(a),
            _ => out.push(1 + announce_len(a)),
        }
    }
    out
}

/// The datagrams carrying `anns` to one neighbour, as the node sends what
/// one routing step produced for it: one announcement alone as itself
/// (`T_OGM`), several packed into `T_OGMS` datagrams of at most `max`
/// bytes ([`encode_announces`]).
pub fn encode_announcements(anns: &[Announce], max: usize) -> Vec<Bytes> {
    match anns {
        [a] => vec![encode_announce(a)],
        _ => encode_announces(anns, max),
    }
}

/// The lengths of [`encode_announcements`]' datagrams, without encoding.
pub fn announcements_lens(anns: &[Announce], max: usize) -> Vec<usize> {
    match anns {
        [a] => vec![announce_len(a)],
        _ => announces_lens(anns, max),
    }
}

/// The announcements in a `T_OGMS` datagram (none if any is malformed).
pub fn decode_announces(b: &[u8]) -> Vec<Announce> {
    let mut out = Vec::new();
    let Some((&T_OGMS, mut rest)) = b.split_first() else { return out };
    while !rest.is_empty() {
        let Some(len) = announce_len_at(rest) else { return Vec::new() };
        let Some(a) = decode_announce(&rest[..len]) else { return Vec::new() };
        out.push(a);
        rest = &rest[len..];
    }
    out
}

pub fn encode_seqreq(r: &SeqReq) -> Bytes {
    let mut b = BytesMut::with_capacity(SEQREQ_LEN);
    b.put_u8(T_SEQREQ);
    b.put_slice(&r.origin.0);
    b.put_u64(r.seq);
    b.put_u8(r.hops);
    b.freeze()
}

pub fn decode_seqreq(b: &[u8]) -> Option<SeqReq> {
    if b.len() != SEQREQ_LEN || b[0] != T_SEQREQ {
        return None;
    }
    Some(SeqReq {
        origin: SignPk(b[1..33].try_into().ok()?),
        seq: u64::from_be_bytes(b[33..41].try_into().ok()?),
        hops: b[41],
    })
}

fn header(f: &Frame, offset: u16, b: &mut BytesMut) {
    b.put_u8(T_DATA);
    b.put_u8(f.ttl);
    b.put_u8(if f.reached { F_REACHED } else { 0 } | if f.control { F_CONTROL } else { 0 } | (f.ext & F_EXTENSIONS));
    b.put_slice(&f.dst.0);
    b.put_slice(&f.src.0);
    b.put_slice(&f.waypoint.0);
    b.put_u32(f.id);
    b.put_u16(offset);
    b.put_u16(f.total);
}

/// The payload bytes each of a frame's datagrams carries when they are at
/// most `max` bytes, or `None` if it can't (or shouldn't) be split to fit:
/// how [`encode_frame`] and [`frame_lens`] cut it.
fn frame_room(f: &Frame, max: usize) -> Option<usize> {
    let room = max.checked_sub(DATA_HDR)?;
    if f.payload.len() > room && (f.total as usize > MIN_QUIC_MTU || room < 64) {
        return None;
    }
    Some(room)
}

/// The lengths of [`encode_frame`]'s datagrams, without encoding them.
pub fn frame_lens(f: &Frame, max: usize) -> Option<Vec<usize>> {
    let room = frame_room(f, max)?;
    let len = f.payload.len();
    if len <= room {
        return Some(vec![DATA_HDR + len]);
    }
    Some((0..len.div_ceil(room)).map(|i| DATA_HDR + room.min(len - i * room)).collect())
}

/// Encoded datagrams of at most `max` bytes each, or `None` if the frame
/// can't (or shouldn't) be split to fit.
pub fn encode_frame(f: &Frame, max: usize) -> Option<Vec<Bytes>> {
    let room = frame_room(f, max)?;
    if f.payload.len() <= room {
        let mut b = BytesMut::with_capacity(DATA_HDR + f.payload.len());
        header(f, f.offset, &mut b);
        b.put_slice(&f.payload);
        return Some(vec![b.freeze()]);
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
        ext: b[2] & F_EXTENSIONS,
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
        let o = Origination { seq: 1_700_000_000_000, flags: 1, scope: 2, uplink: 345 };
        let mut a = sign_announce(&k, o, "Alice’s MacBook Pro with a long name");
        assert!(a.name.len() <= MAX_NAME);
        a.hops = 3;
        a.cost = 1234;
        let b = decode_announce(&encode_announce(&a)).unwrap();
        assert_eq!(a, b);
        assert!(verify_announce(&b), "hops and cost are not signed: relays fill them in");
        let mut flipped = b.clone();
        flipped.flags = 0;
        assert!(!verify_announce(&flipped), "the gateway flag is signed");
        let mut cheaper = b.clone();
        cheaper.uplink = 1;
        assert!(!verify_announce(&cheaper), "so is the uplink cost");
        let r = SeqReq { origin: k.sign_pk(), seq: 42, hops: 3 };
        assert_eq!(decode_seqreq(&encode_seqreq(&r)), Some(r));
    }

    #[test]
    fn announcements_batch_into_datagrams() {
        let anns: Vec<Announce> = (0..20)
            .map(|i| {
                let k = DeviceKeys::generate();
                let o = Origination { seq: 1_700_000_000_000 + i, flags: 0, scope: 8, uplink: 0 };
                let mut a = sign_announce(&k, o, &"n".repeat(i as usize % 9));
                a.hops = (i % 7) as u8;
                a.cost = 100 * i as u32;
                a
            })
            .collect();
        let grams = encode_announces(&anns, 1100);
        assert!(grams.len() > 1 && grams.len() < 5, "{} datagrams", grams.len());
        assert!(grams.iter().all(|g| g.len() <= 1100));
        let back: Vec<Announce> = grams.iter().flat_map(|g| decode_announces(g)).collect();
        assert_eq!(back, anns);
        assert!(back.iter().all(verify_announce));
        // too small for two: one per datagram, still decodable
        assert_eq!(encode_announces(&anns[..3], 10).len(), 3);
        // a truncated batch is dropped whole
        let g = &grams[0];
        assert!(decode_announces(&g[..g.len() - 1]).is_empty());
        assert!(encode_announces(&[], 1100).is_empty());
    }

    /// A small deterministic generator for the length tests (xorshift64*).
    struct Gen(u64);

    impl Gen {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as usize % n.max(1)
        }
    }

    /// The length functions the tier-2 simulator charges (`mycel-sim`)
    /// agree with the encoders, byte for byte, on random input.
    #[test]
    fn lengths_match_the_encoders() {
        let mut g = Gen(0x9e37_79b9_7f4a_7c15);
        let pk = |g: &mut Gen| SignPk([g.below(256) as u8; 32]);
        for _ in 0..2_000 {
            let anns: Vec<Announce> = (0..1 + g.below(40))
                .map(|_| Announce {
                    hops: g.below(16) as u8,
                    cost: g.below(1 << 20) as u32,
                    origin: pk(&mut g),
                    seq: g.below(1 << 40) as u64,
                    flags: g.below(4) as u8,
                    scope: g.below(16) as u8,
                    uplink: g.below(1 << 20) as u32,
                    name: Arc::from("n".repeat(g.below(MAX_NAME + 1)).as_str()),
                    sig: Sig([7; 64]),
                })
                .collect();
            let max = 60 + g.below(1_500);
            let lens = |v: Vec<Bytes>| v.iter().map(|d| d.len()).collect::<Vec<_>>();
            assert_eq!(announces_lens(&anns, max), lens(encode_announces(&anns, max)));
            assert_eq!(announcements_lens(&anns, max), lens(encode_announcements(&anns, max)));
            assert_eq!(announce_len(&anns[0]), encode_announce(&anns[0]).len());
            let len = g.below(MIN_QUIC_MTU + 400);
            let f = Frame {
                ttl: 8,
                reached: false,
                control: g.below(2) == 1,
                ext: 0,
                dst: pk(&mut g),
                src: pk(&mut g),
                waypoint: pk(&mut g),
                id: g.below(1 << 30) as u32,
                offset: 0,
                total: len as u16,
                payload: Bytes::from(vec![1; len]),
            };
            let max = DATA_HDR + g.below(1_500);
            assert_eq!(frame_lens(&f, max), encode_frame(&f, max).map(lens), "{len} bytes in {max}");
        }
        let r = SeqReq { origin: pk(&mut g), seq: 1, hops: 2 };
        assert_eq!(encode_seqreq(&r).len(), SEQREQ_LEN);
        // one announcement goes alone, without the batch's type byte
        let one = &[sign_announce(&DeviceKeys::generate(), Origination { seq: 1, flags: 0, scope: 8, uplink: 0 }, "a")];
        assert_eq!(encode_announcements(one, 1200)[0][0], T_OGM);
        assert_eq!(announcements_lens(one, 1200), vec![OGM_FIXED + 1 + 64]);
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
            ext: 0,
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
        assert_eq!(d.ext, 0);
        // flags a later version assigns survive the trip, in every fragment
        let marked = Frame { ext: 0x84, total: 600, payload: Bytes::from(vec![7; 600]), ..f };
        let grams = encode_frame(&marked, 400).unwrap();
        assert!(grams.len() > 1);
        assert!(grams.into_iter().map(|g| decode_frame(g).unwrap()).all(|d| d.ext == 0x84 && d.reached && d.control));
        // ... and never pass for the flags this version assigns
        let only_ext = Frame { reached: false, control: false, ext: 0xff, ..marked };
        let d = decode_frame(encode_frame(&only_ext, 1200).unwrap().remove(0)).unwrap();
        assert!(!d.reached && !d.control && d.ext == F_EXTENSIONS);
    }
}
