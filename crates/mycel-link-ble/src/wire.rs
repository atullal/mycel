//! Bytes on the air: the GATT info record a peripheral publishes, and the
//! framing of the L2CAP byte stream that carries QUIC packets.
//!
//! An L2CAP connection-oriented channel is a reliable byte stream (Apple
//! hands it to us as an `NSInputStream`/`NSOutputStream` pair), so QUIC
//! packets get a length prefix:
//!
//! ```text
//! frame  = len:u16be  type:u8  body[len-1]
//! type 1 = hello:  "MYCL" version:u8 node_key[32] name:utf8   (first frame, both ways)
//! type 2 = packet: one QUIC datagram
//! type 3 = ping:   empty; sent every few seconds so a dead channel is noticed
//!                  even when the OS doesn't report it and QUIC is idle
//! ```
//!
//! The hello tells the accepting side which node is on the other end (the
//! dialing side already read it from GATT). It is *not* authenticated: QUIC's
//! TLS handshake authenticates the node key end to end, so a device lying in
//! its hello can at worst black-hole the Bluetooth path for that key.

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

/// What a peripheral publishes in its GATT characteristic: where its L2CAP
/// channel listens and which node it is.
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

impl GattInfo {
    pub fn encode(&self) -> Vec<u8> {
        let name = clip_name(&self.name);
        let mut v = Vec::with_capacity(35 + name.len());
        v.push(VERSION);
        v.extend_from_slice(&self.psm.to_be_bytes());
        v.extend_from_slice(&self.key.0);
        v.extend_from_slice(name.as_bytes());
        v
    }

    pub fn decode(b: &[u8]) -> Option<GattInfo> {
        if b.len() < 35 || b[0] != VERSION || b.len() > 35 + MAX_NAME {
            return None;
        }
        let psm = u16::from_be_bytes([b[1], b[2]]);
        let key = SignPk(b[3..35].try_into().ok()?);
        let name = String::from_utf8_lossy(&b[35..]).into_owned();
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

pub fn encode_hello(key: &SignPk, name: &str) -> Bytes {
    let name = clip_name(name);
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
                    if body.len() < 37 || &body[..4] != MAGIC || body.len() > 37 + MAX_NAME {
                        return Err(BadStream("bad hello"));
                    }
                    if body[4] != VERSION {
                        return Err(BadStream("unsupported version"));
                    }
                    let key = SignPk(body[5..37].try_into().expect("32 bytes"));
                    let name = String::from_utf8_lossy(&body[37..]).into_owned();
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

    #[test]
    fn frames_survive_any_chunking() {
        let pkts: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 1 + i * 97]).collect();
        let mut stream = encode_hello(&key(3), "bob").to_vec();
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
