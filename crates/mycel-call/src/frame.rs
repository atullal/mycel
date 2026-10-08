//! Media framing: one Opus frame per QUIC datagram.
//!
//! ```text
//! 0      track kind (0x01 = audio; any other kind is another track,
//!        e.g. video, handed to the call's TrackSink)
//! 1..5   sequence number, u32 LE (one per 20 ms frame, never reused)
//! 5..9   capture timestamp, u32 LE, in 48 kHz samples
//! 9      flags (bit 0: sender is muted)
//! 10..   Opus packet
//! ```
//!
//! Each QUIC connection is already authenticated and encrypted end to end,
//! and carries one call between two devices, so frames carry no call id or
//! MAC. When a path can't carry datagrams, the same frames go on a
//! unidirectional stream that starts with the track kind byte, each frame
//! prefixed with its length (u16 LE).

use anyhow::{Result, bail};
use bytes::{BufMut, Bytes, BytesMut};

pub const KIND_AUDIO: u8 = 0x01;
pub const HEADER_LEN: usize = 10;
pub const FLAG_MUTED: u8 = 0x01;
/// Largest frame we send or accept.
pub const MAX_FRAME: usize = HEADER_LEN + crate::codec::MAX_PACKET;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioFrame {
    pub seq: u32,
    pub timestamp: u32,
    pub flags: u8,
    pub payload: Bytes,
}

impl AudioFrame {
    pub fn muted(&self) -> bool {
        self.flags & FLAG_MUTED != 0
    }

    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        b.put_u8(KIND_AUDIO);
        b.put_u32_le(self.seq);
        b.put_u32_le(self.timestamp);
        b.put_u8(self.flags);
        b.put_slice(&self.payload);
        b.freeze()
    }

    pub fn decode(data: Bytes) -> Result<AudioFrame> {
        if data.len() <= HEADER_LEN {
            bail!("frame too short ({} bytes)", data.len());
        }
        if data.len() > MAX_FRAME {
            bail!("frame too long ({} bytes)", data.len());
        }
        if data[0] != KIND_AUDIO {
            bail!("unknown frame kind {:#x}", data[0]);
        }
        let u32_at = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        Ok(AudioFrame { seq: u32_at(1), timestamp: u32_at(5), flags: data[9], payload: data.slice(HEADER_LEN..) })
    }

    /// The frame as it goes on a stream: u16 LE length, then the frame.
    pub fn encode_for_stream(&self) -> Bytes {
        let f = self.encode();
        let mut b = BytesMut::with_capacity(2 + f.len());
        b.put_u16_le(f.len() as u16);
        b.put_slice(&f);
        b.freeze()
    }
}

/// Splits a byte stream back into frames (stream fallback).
#[derive(Default)]
pub struct StreamDeframer {
    buf: BytesMut,
}

impl StreamDeframer {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next complete frame, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        if len > MAX_FRAME {
            bail!("stream frame too long ({len} bytes)");
        }
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        let _ = self.buf.split_to(2);
        let frame = self.buf.split_to(len).freeze();
        AudioFrame::decode(frame).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u32) -> AudioFrame {
        AudioFrame { seq, timestamp: seq * 960, flags: FLAG_MUTED, payload: Bytes::from(vec![seq as u8; 37]) }
    }

    #[test]
    fn datagram_round_trip() {
        let f = frame(7);
        let wire = f.encode();
        assert_eq!(wire.len(), HEADER_LEN + 37);
        let back = AudioFrame::decode(wire).unwrap();
        assert_eq!(back, f);
        assert!(back.muted());
    }

    #[test]
    fn rejects_garbage() {
        assert!(AudioFrame::decode(Bytes::from_static(&[1, 2, 3])).is_err());
        let mut bad = frame(1).encode().to_vec();
        bad[0] = 0x7f;
        assert!(AudioFrame::decode(Bytes::from(bad)).is_err());
        assert!(AudioFrame::decode(Bytes::from(vec![KIND_AUDIO; MAX_FRAME + 1])).is_err());
        // header only, no Opus packet
        assert!(AudioFrame::decode(frame(1).encode().slice(..HEADER_LEN)).is_err());
    }

    #[test]
    fn stream_framing_survives_arbitrary_splits() {
        let wire: Vec<u8> = (0..20).flat_map(|i| frame(i).encode_for_stream().to_vec()).collect();
        for step in [1, 3, 7, 64, 1000] {
            let mut d = StreamDeframer::default();
            let mut got = Vec::new();
            for chunk in wire.chunks(step) {
                d.push(chunk);
                while let Some(f) = d.next_frame().unwrap() {
                    got.push(f.seq);
                }
            }
            assert_eq!(got, (0..20).collect::<Vec<_>>(), "step {step}");
        }
        let mut d = StreamDeframer::default();
        d.push(&u16::MAX.to_le_bytes());
        assert!(d.next_frame().is_err(), "oversized length rejected");
    }
}
