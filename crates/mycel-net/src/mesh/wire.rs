//! Mesh frames on the wire (datagrams on a hop connection), mesh addresses,
//! and the signatures on announcements.

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use mycel_crypto::{DeviceKeys, Sig, SignPk};

use super::core::{Announce, Check, Frame, Hop, MAX_CHAIN, NO_SIG, Origination, SeqReq, fields_digest, hop_signed};
use crate::link::{CustomAddr, TRANSPORT_MESH};

const OGM_CTX: &str = "mycel/v1/mesh-announce";
/// What each hop of a route attestation signs under (`core::hop_signed`).
const ATTEST_CTX: &str = "mycel/v2/mesh-attest-hop";
pub(crate) const T_OGM: u8 = 1;
pub(crate) const T_DATA: u8 = 2;
pub(crate) const T_SEQREQ: u8 = 3;
/// Several announcements for one neighbour in one datagram.
pub(crate) const T_OGMS: u8 = 4;
/// Several attested announcements (`ROUTE_ATTEST`) in one datagram, sent
/// only to a neighbour whose hop hello has the capability.
pub(crate) const T_AOGMS: u8 = 5;
/// An attested announcement's flags: the origin's signature follows ...
const A_BASE: u8 = 1;
/// ... and the chain ends with its sender's own hop (naming the receiver).
const A_OWN: u8 = 2;
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
        chain: None,
        sign_link: None,
    }
}

/// `a` with our own attestation hop signed for neighbour `to`, if the router
/// asked for one ([`Announce::sign_link`]).
pub fn sign_hop(keys: &DeviceKeys, a: Announce, to: &SignPk) -> Announce {
    let Some(link) = a.sign_link else { return a };
    let m = hop_signed(&fields_digest(&a), a.hops, a.cost, to, link);
    let sig = keys.sign(ATTEST_CTX, &[&m]);
    a.signed_by(keys.sign_pk(), sig)
}

/// A signature the router asks about ([`Check`]): the origin's, or one hop's
/// of an attestation chain.
pub fn verify(c: Check<'_>) -> bool {
    match c {
        Check::Origin(a) => verify_announce(a),
        Check::Hop { ann, hop, pos, next } => {
            let m = hop_signed(&fields_digest(ann), pos, hop.cost, &next, hop.link);
            hop.signer.verify(ATTEST_CTX, &[&m], &hop.sig).is_ok()
        }
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

pub fn encode_announce(a: &Announce) -> Bytes {
    let mut b = BytesMut::with_capacity(OGM_FIXED + a.name.len() + 64);
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
    Some(Announce { hops, cost, origin, seq, flags, scope, uplink, name: Arc::from(name), sig, chain: None, sign_link: None })
}

/// An attested announcement's fixed part: [`OGM_FIXED`] without the type
/// byte, then its flags byte.
const AOGM_FIXED: usize = OGM_FIXED; // no type byte; a flags byte instead
/// The origin's hop (its cost is 0) and the sender's own (its cost is the
/// announcement's): a link cost and a signature.
const SHORT_HOP: usize = 4 + 64;
/// A hop in between: its key, cost, link cost and signature.
const RELAY_HOP: usize = 32 + 4 + 4 + 64;

/// Whether the attested form of `a` (signed, or with `sign_link` still to
/// sign) ends with its sender's own hop, and whether it carries the
/// origin's signature: only then, since a receiver that won't pass it on
/// needs neither (the chain's first hop covers the same fields).
fn attested_shape(a: &Announce) -> (bool, bool) {
    let own = a.sign_link.is_some() || a.chain_len() == a.hops as usize + 1;
    (own, own && a.sig != NO_SIG)
}

/// Bytes of `a` on the wire: attested if it has a chain (or a hop to sign),
/// else as version 1 sends it. What the control budget and the simulator
/// count.
pub fn wire_len(a: &Announce) -> usize {
    if a.chain.is_none() && a.sign_link.is_none() {
        return OGM_FIXED + a.name.len() + 64;
    }
    let (own, base) = attested_shape(a);
    let between = (a.hops as usize).saturating_sub(1);
    AOGM_FIXED
        + a.name.len()
        + if base { 64 } else { 0 }
        + SHORT_HOP
        + between * RELAY_HOP
        + if own && a.hops > 0 { SHORT_HOP } else { 0 }
}

/// One attested announcement (signed: no `sign_link` left), appended to
/// `b`. `None` if its chain isn't one a receiver could take (see
/// [`decode_attested`]).
fn put_attested(a: &Announce, b: &mut BytesMut) -> Option<()> {
    let chain = a.chain.as_ref()?;
    let hops: Vec<&Hop> = chain.iter().collect::<Vec<_>>().into_iter().rev().collect();
    let h = a.hops as usize;
    let (own, base) = attested_shape(a);
    if a.sign_link.is_some() || a.cost == u32::MAX || hops.len() > MAX_CHAIN || hops.len() != h + own as usize {
        return None;
    }
    if (h == 0 && !own) || hops[0].signer != a.origin || hops[0].cost != 0 || (own && hops[h].cost != a.cost) {
        return None;
    }
    b.put_u8(a.hops);
    b.put_u32(a.cost);
    b.put_slice(&a.origin.0);
    b.put_u64(a.seq);
    b.put_u8(a.flags);
    b.put_u8(a.scope);
    b.put_u32(a.uplink);
    b.put_u8(a.name.len() as u8);
    b.put_slice(a.name.as_bytes());
    b.put_u8(if base { A_BASE } else { 0 } | if own { A_OWN } else { 0 });
    if base {
        b.put_slice(&a.sig.0);
    }
    let between = h.saturating_sub(1);
    for x in &hops[1..1 + between] {
        b.put_slice(&x.signer.0);
    }
    b.put_u32(hops[0].link);
    b.put_slice(&hops[0].sig.0);
    for x in &hops[1..1 + between] {
        b.put_u32(x.cost);
        b.put_u32(x.link);
        b.put_slice(&x.sig.0);
    }
    if own && h > 0 {
        b.put_u32(hops[h].link);
        b.put_slice(&hops[h].sig.0);
    }
    Some(())
}

/// Attested announcements for one neighbour, packed into as few `T_AOGMS`
/// datagrams of at most `max` bytes as they fit in. Those that don't fit
/// in one datagram, or aren't attested, come back for the caller to send
/// unattested.
pub fn encode_attested(anns: Vec<Announce>, max: usize) -> (Vec<Bytes>, Vec<Announce>) {
    let mut out = Vec::new();
    let mut rest = Vec::new();
    let mut cur = BytesMut::new();
    let mut one = BytesMut::new();
    for a in anns {
        one.clear();
        if put_attested(&a, &mut one).is_none() || one.len() + 1 > max {
            rest.push(Announce { chain: None, sign_link: None, ..a });
            continue;
        }
        if !cur.is_empty() && cur.len() + one.len() > max {
            out.push(std::mem::take(&mut cur).freeze());
        }
        if cur.is_empty() {
            cur.put_u8(T_AOGMS);
        }
        cur.put_slice(&one);
    }
    if !cur.is_empty() {
        out.push(cur.freeze());
    }
    (out, rest)
}

/// Reads fixed-size fields off the front of a slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn key(&mut self) -> Option<SignPk> {
        Some(SignPk(self.take(32)?.try_into().ok()?))
    }
    fn sig(&mut self) -> Option<Sig> {
        Some(Sig(self.take(64)?.try_into().ok()?))
    }
}

fn get_attested(r: &mut Reader<'_>, from: &SignPk) -> Option<Announce> {
    let hops = r.u8()?;
    let cost = r.u32()?;
    let origin = r.key()?;
    let seq = r.u64()?;
    let flags = r.u8()?;
    let scope = r.u8()?;
    let uplink = r.u32()?;
    let n = r.u8()? as usize;
    if n > MAX_NAME || cost == u32::MAX {
        return None;
    }
    let name = std::str::from_utf8(r.take(n)?).ok()?;
    let att = r.u8()?;
    let (base, own) = (att & A_BASE != 0, att & A_OWN != 0);
    let h = hops as usize;
    if att & !(A_BASE | A_OWN) != 0 || (h == 0 && !own) || h + own as usize > MAX_CHAIN {
        return None;
    }
    let sig = if base { r.sig()? } else { NO_SIG };
    let between = h.saturating_sub(1);
    let keys: Vec<SignPk> = (0..between).map(|_| r.key()).collect::<Option<_>>()?;
    let mut chain = Arc::new(Hop { signer: origin, cost: 0, link: r.u32()?, sig: r.sig()?, prev: None });
    for k in keys {
        let (cost, link, sig) = (r.u32()?, r.u32()?, r.sig()?);
        chain = Arc::new(Hop { signer: k, cost, link, sig, prev: Some(chain) });
    }
    if own && h > 0 {
        chain = Arc::new(Hop { signer: *from, cost, link: r.u32()?, sig: r.sig()?, prev: Some(chain) });
    }
    let name = Arc::from(name);
    Some(Announce { hops, cost, origin, seq, flags, scope, uplink, name, sig, chain: Some(chain), sign_link: None })
}

/// The attested announcements in a `T_AOGMS` datagram from neighbour `from`
/// (none if any is malformed). Each chain has the hops at positions 0 to
/// `hops` − 1, plus `from`'s own if the flag says so: the shape is checked
/// here, what each hop may claim and its signature by the router.
pub fn decode_attested(b: &[u8], from: &SignPk) -> Vec<Announce> {
    let Some((&T_AOGMS, rest)) = b.split_first() else { return Vec::new() };
    let mut r = Reader(rest);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let Some(a) = get_attested(&mut r, from) else { return Vec::new() };
        out.push(a);
    }
    out
}

/// The encoded length of the announcement starting at `b[0]`, if whole.
fn announce_len(b: &[u8]) -> Option<usize> {
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
    for a in anns {
        let e = encode_announce(a);
        if !cur.is_empty() && cur.len() + e.len() > max {
            out.push(std::mem::take(&mut cur).freeze());
        }
        if cur.is_empty() {
            cur.put_u8(T_OGMS);
        }
        cur.put_slice(&e);
    }
    if !cur.is_empty() {
        out.push(cur.freeze());
    }
    out
}

/// The announcements in a `T_OGMS` datagram (none if any is malformed).
pub fn decode_announces(b: &[u8]) -> Vec<Announce> {
    let mut out = Vec::new();
    let Some((&T_OGMS, mut rest)) = b.split_first() else { return out };
    while !rest.is_empty() {
        let Some(len) = announce_len(rest) else { return Vec::new() };
        let Some(a) = decode_announce(&rest[..len]) else { return Vec::new() };
        out.push(a);
        rest = &rest[len..];
    }
    out
}

pub fn encode_seqreq(r: &SeqReq) -> Bytes {
    let mut b = BytesMut::with_capacity(1 + 32 + 8 + 1);
    b.put_u8(T_SEQREQ);
    b.put_slice(&r.origin.0);
    b.put_u64(r.seq);
    b.put_u8(r.hops);
    b.freeze()
}

pub fn decode_seqreq(b: &[u8]) -> Option<SeqReq> {
    if b.len() != 42 || b[0] != T_SEQREQ {
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
