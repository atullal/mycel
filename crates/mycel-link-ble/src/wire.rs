//! Bytes on the air: the GATT info record a peripheral publishes, and the
//! framing of the L2CAP byte stream that carries QUIC packets.
//!
//! An L2CAP connection-oriented channel is a reliable byte stream (Apple
//! hands it to us as an `NSInputStream`/`NSOutputStream` pair), so QUIC
//! packets get a length prefix:
//!
//! ```text
//! frame  = len:u16be  type:u8  body[len-1]
//! type 1 = hello:  "MYCL" version:u8 node_key[32] name:utf8 [0x00 ext]   (first frame,
//!                  both ways; the name is always empty now, older builds sent one)
//! type 2 = packet: one QUIC datagram
//! type 3 = ping:   empty; sent every few seconds so a dead channel is noticed
//!                  even when the OS doesn't report it and QUIC is idle
//! ```
//!
//! The hello tells the accepting side which node is on the other end (the
//! dialing side already read it from GATT). It is *not* authenticated: QUIC's
//! TLS handshake authenticates the node key end to end, so a device lying in
//! its hello can at worst black-hole the Bluetooth path for that key.
//!
//! The channel isn't encrypted (anyone in range can listen to it), so the
//! hello never carries the display name: a device learns a nearby node's
//! name from its signed contact card, inside the encrypted QUIC session.
//!
//! Room to grow (docs/PROTOCOL.md §3.9): a name never contains a NUL byte,
//! and readers stop the name at the first one, so a later build can append
//! fields after a NUL to the GATT record and the hello (a supported version
//! range, say) that this build ignores. A later build must keep sending
//! version 1 records and hellos until every build it should reach reads
//! such fields.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use mycel_crypto::SignPk;

pub const VERSION: u8 = 1;
const MAGIC: &[u8; 4] = b"MYCL";
const T_HELLO: u8 = 1;
const T_PACKET: u8 = 2;
const T_PING: u8 = 3;
/// Largest frame accepted (type byte + body). QUIC packets are ≤ ~1500 bytes;
/// anything much bigger means the stream is out of sync.
pub const MAX_FRAME: usize = 4096;
/// Longest display name carried in GATT / hello.
pub const MAX_NAME: usize = 64;
/// Longest GATT info record read: the most an attribute value can hold
/// (Bluetooth Core, Vol 3 Part F §3.2.9), so fields a later build appends
/// fit.
pub const MAX_GATT: usize = 512;

/// What a peripheral publishes in its GATT characteristic: where its L2CAP
/// channel listens and which node it is. Anyone in range can read it, with
/// no pairing, so a device publishes [`GattInfo::published`]: never its
/// display name (that comes from its signed contact card). The `name` field
/// stays in the format so older builds' payloads still decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GattInfo {
    pub psm: u16,
    pub key: SignPk,
    pub name: String,
}

/// Cut `name` to at most [`MAX_NAME`] bytes on a char boundary.
pub fn clip_name(name: &str) -> &str {
    let mut end = name.len().min(MAX_NAME);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// A name as it goes on the air: no NUL (that ends the name, see the module
/// docs), at most [`MAX_NAME`] bytes.
fn air_name(name: &str) -> String {
    clip_name(&name.replace('\0', "")).to_owned()
}

/// A name as read off the air: up to the first NUL (what follows is for a
/// later build), at most [`MAX_NAME`] bytes.
fn read_name(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    clip_name(&String::from_utf8_lossy(&b[..end])).to_owned()
}

impl GattInfo {
    /// What this device serves: the PSM and node key, and no name.
    pub fn published(psm: u16, key: SignPk) -> GattInfo {
        GattInfo { psm, key, name: String::new() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let name = air_name(&self.name);
        let mut v = Vec::with_capacity(35 + name.len());
        v.push(VERSION);
        v.extend_from_slice(&self.psm.to_be_bytes());
        v.extend_from_slice(&self.key.0);
        v.extend_from_slice(name.as_bytes());
        v
    }

    pub fn decode(b: &[u8]) -> Option<GattInfo> {
        if b.len() < 35 || b[0] != VERSION || b.len() > MAX_GATT {
            return None;
        }
        let psm = u16::from_be_bytes([b[1], b[2]]);
        let key = SignPk(b[3..35].try_into().ok()?);
        let name = read_name(&b[35..]);
        Some(GattInfo { psm, key, name })
    }
}

/// One decoded frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Hello { key: SignPk, name: String },
    Packet(Bytes),
    Ping,
}

fn frame(ty: u8, body_len: usize, body: impl FnOnce(&mut BytesMut)) -> Bytes {
    let len = 1 + body_len;
    let mut b = BytesMut::with_capacity(2 + len);
    b.put_u16(len as u16);
    b.put_u8(ty);
    body(&mut b);
    debug_assert_eq!(b.len(), 2 + len);
    b.freeze()
}

/// The hello this device sends: its node key, and an empty name (the field
/// stays so older builds decode it).
pub fn encode_hello(key: &SignPk) -> Bytes {
    hello_frame(key, "")
}

/// A hello carrying `name`, as older builds sent it (tests decode those).
fn hello_frame(key: &SignPk, name: &str) -> Bytes {
    let name = air_name(name);
    frame(T_HELLO, 4 + 1 + 32 + name.len(), |b| {
        b.put_slice(MAGIC);
        b.put_u8(VERSION);
        b.put_slice(&key.0);
        b.put_slice(name.as_bytes());
    })
}

pub fn encode_ping() -> Bytes {
    frame(T_PING, 0, |_| {})
}

/// Frame one QUIC packet; `None` if it is too big to frame.
pub fn encode_packet(data: &[u8]) -> Option<Bytes> {
    if data.is_empty() || 1 + data.len() > MAX_FRAME {
        return None;
    }
    Some(frame(T_PACKET, data.len(), |b| b.put_slice(data)))
}

/// The stream carried something that isn't Mycel framing: close the channel.
#[derive(Debug, PartialEq, Eq)]
pub struct BadStream(pub &'static str);

/// Reassembles frames from arbitrary chunks of the byte stream.
#[derive(Default)]
pub struct Deframer {
    buf: BytesMut,
}

impl Deframer {
    /// Feed bytes as they arrive; returns every frame completed by them.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, BadStream> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len == 0 || len > MAX_FRAME {
                return Err(BadStream("bad frame length"));
            }
            if self.buf.len() < 2 + len {
                break;
            }
            let _ = self.buf.split_to(2);
            let mut f = self.buf.split_to(len).freeze();
            let ty = f[0];
            let body = f.split_off(1);
            out.push(match ty {
                T_PACKET => Frame::Packet(body),
                T_PING => Frame::Ping,
                T_HELLO => {
                    // (any length up to MAX_FRAME: a later build may append
                    // fields after the name's NUL)
                    if body.len() < 37 || &body[..4] != MAGIC {
                        return Err(BadStream("bad hello"));
                    }
                    if body[4] != VERSION {
                        return Err(BadStream("unsupported version"));
                    }
                    let key = SignPk(body[5..37].try_into().expect("32 bytes"));
                    let name = read_name(&body[37..]);
                    Frame::Hello { key, name }
                }
                _ => return Err(BadStream("unknown frame type")),
            });
        }
        Ok(out)
    }
}

/// Frames waiting for the output stream, bounded in bytes. When it is full,
/// new packets are dropped (QUIC treats that as loss and slows down) instead
/// of blocking the sender or piling up seconds of delay on a slow radio.
pub struct OutQueue {
    frames: VecDeque<Bytes>,
    /// Bytes of the front frame already written.
    front_off: usize,
    queued: usize,
    cap: usize,
    pub dropped: u64,
}

impl OutQueue {
    pub fn new(cap: usize) -> Self {
        OutQueue { frames: VecDeque::new(), front_off: 0, queued: 0, cap, dropped: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued
    }

    /// Queue a frame. An empty queue always takes one frame, so a packet
    /// larger than the cap still gets through. Returns false if dropped.
    pub fn push(&mut self, frame: Bytes) -> bool {
        if !self.frames.is_empty() && self.queued + frame.len() > self.cap {
            self.dropped += 1;
            return false;
        }
        self.queued += frame.len();
        self.frames.push_back(frame);
        true
    }

    /// The bytes to write next (the unwritten rest of the front frame).
    pub fn peek(&self) -> Option<&[u8]> {
        self.frames.front().map(|f| &f[self.front_off..])
    }

    /// `n` bytes of [`peek`](Self::peek) were written.
    pub fn advance(&mut self, n: usize) {
        let Some(front) = self.frames.front() else { return };
        let left = front.len() - self.front_off;
        let n = n.min(left);
        self.front_off += n;
        self.queued -= n;
        if self.front_off == front.len() {
            self.frames.pop_front();
            self.front_off = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SignPk {
        SignPk([b; 32])
    }

    #[test]
    fn gatt_info_roundtrip_and_limits() {
        let i = GattInfo { psm: 0x00c1, key: key(7), name: "Alice’s MacBook".into() };
        let b = i.encode();
        assert_eq!(GattInfo::decode(&b), Some(i));
        assert_eq!(GattInfo::decode(&b[..34]), None, "too short");
        let mut wrong = b.clone();
        wrong[0] = 9;
        assert_eq!(GattInfo::decode(&wrong), None, "unknown version");
        // long names are clipped on a char boundary and still fit
        let long = GattInfo { psm: 1, key: key(1), name: "é".repeat(100) };
        let d = GattInfo::decode(&long.encode()).unwrap();
        assert_eq!(d.name, "é".repeat(32));
        assert!(long.encode().len() <= 35 + MAX_NAME);
    }

    /// A later build may append fields after a NUL that ends the name: the
    /// GATT record and the hello still read, the extra bytes ignored. This
    /// build never puts a NUL in a name.
    #[test]
    fn fields_a_later_build_appends_are_ignored() {
        let i = GattInfo { psm: 0x00c1, key: key(7), name: "Bob".into() };
        let mut b = i.encode();
        b.push(0);
        b.extend_from_slice(&[1, 2, 0xff, 0, 9]); // e.g. a version range
        assert_eq!(GattInfo::decode(&b), Some(i.clone()));
        b.resize(MAX_GATT, 7);
        assert_eq!(GattInfo::decode(&b), Some(i));
        b.push(7);
        assert_eq!(GattInfo::decode(&b), None, "longer than an attribute can be");
        let sneaky = GattInfo { psm: 1, key: key(1), name: "a\0b".into() };
        assert_eq!(GattInfo::decode(&sneaky.encode()).unwrap().name, "ab");
        // a long name on its own, with no NUL, still reads (as before)
        let long = GattInfo { psm: 1, key: key(1), name: "n".repeat(MAX_NAME) };
        assert_eq!(GattInfo::decode(&long.encode()).unwrap().name, "n".repeat(MAX_NAME));

        let hello = hello_frame(&key(3), "bob");
        let mut longer = hello[3..].to_vec(); // the hello body
        longer.extend_from_slice(&[0, 1, 2, 3]);
        let mut framed = ((1 + longer.len()) as u16).to_be_bytes().to_vec();
        framed.push(1);
        framed.extend_from_slice(&longer);
        framed.extend_from_slice(&encode_ping());
        let got = Deframer::default().push(&framed).unwrap();
        assert_eq!(got, vec![Frame::Hello { key: key(3), name: "bob".into() }, Frame::Ping]);
        let got = Deframer::default().push(&hello_frame(&key(3), "x\0y")).unwrap();
        assert_eq!(got, vec![Frame::Hello { key: key(3), name: "xy".into() }]);
    }

    /// Regression: the readable characteristic carried the profile's display
    /// name to anyone in Bluetooth range.
    #[test]
    fn the_published_info_carries_no_name() {
        let published = GattInfo::published(0x00c1, key(7));
        let bytes = published.encode();
        assert_eq!(bytes.len(), 35, "version, PSM and key only");
        let decoded = GattInfo::decode(&bytes).unwrap();
        assert_eq!((decoded.psm, decoded.key), (0x00c1, key(7)));
        assert!(decoded.name.is_empty());
    }

    /// Regression: the hello, the first frame on an unencrypted L2CAP
    /// channel, carried the profile's display name to whichever device
    /// opened or accepted the channel (and to anyone listening).
    #[test]
    fn the_hello_carries_no_name() {
        let hello = encode_hello(&key(7));
        assert_eq!(hello.len(), 2 + 1 + 4 + 1 + 32, "magic, version and key only");
        let got = Deframer::default().push(&hello).unwrap();
        assert_eq!(got, vec![Frame::Hello { key: key(7), name: String::new() }]);
    }

    /// The tier-2 simulator charges 3 bytes per QUIC packet on Bluetooth
    /// (`mycel_sim::quic::BLE_FRAMING`): the length and the type byte.
    #[test]
    fn packet_framing_is_three_bytes() {
        for n in [1, 40, 1200, 1452] {
            assert_eq!(encode_packet(&vec![9; n]).unwrap().len(), n + 3);
        }
    }

    #[test]
    fn frames_survive_any_chunking() {
        let pkts: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 1 + i * 97]).collect();
        let mut stream = hello_frame(&key(3), "bob").to_vec();
        for p in &pkts {
            stream.extend_from_slice(&encode_packet(p).unwrap());
        }
        stream.extend_from_slice(&encode_ping());
        for chunk in [1, 2, 3, 7, 100, 1500, stream.len()] {
            let mut d = Deframer::default();
            let mut got = Vec::new();
            for c in stream.chunks(chunk) {
                got.extend(d.push(c).unwrap());
            }
            assert_eq!(got.len(), 22, "chunk {chunk}");
            assert_eq!(got[21], Frame::Ping);
            assert_eq!(got[0], Frame::Hello { key: key(3), name: "bob".into() });
            for (f, p) in got[1..21].iter().zip(&pkts) {
                assert_eq!(f, &Frame::Packet(Bytes::copy_from_slice(p)));
            }
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Deframer::default().push(&[0, 0]).is_err(), "zero length");
        assert!(Deframer::default().push(&[0xff, 0xff]).is_err(), "too long");
        assert!(Deframer::default().push(&[0, 2, 9, 9]).is_err(), "unknown type");
        assert!(Deframer::default().push(&[0, 3, 1, b'X', b'Y']).is_err(), "short hello");
        assert_eq!(encode_packet(&[]), None);
        assert_eq!(encode_packet(&vec![0; MAX_FRAME]), None);
        assert!(encode_packet(&vec![0; MAX_FRAME - 1]).is_some());
    }

    #[test]
    fn out_queue_drops_when_full_and_tracks_partial_writes() {
        let mut q = OutQueue::new(100);
        assert!(q.push(Bytes::from(vec![1; 150])), "empty queue takes an oversized frame");
        assert!(!q.push(Bytes::from(vec![2; 10])), "full: dropped");
        assert_eq!(q.dropped, 1);
        q.advance(149);
        assert_eq!(q.peek(), Some(&[1u8][..]));
        q.advance(1);
        assert!(q.is_empty());
        assert!(q.push(Bytes::from(vec![3; 60])));
        assert!(q.push(Bytes::from(vec![4; 40])));
        assert!(!q.push(Bytes::from(vec![5; 1])));
        assert_eq!(q.queued_bytes(), 100);
        q.advance(70); // finishes the first frame; advance never crosses frames
        assert_eq!(q.peek().unwrap().len(), 40);
        q.advance(40);
        assert_eq!(q.peek(), None);
        assert_eq!(q.queued_bytes(), 0);
    }
}
