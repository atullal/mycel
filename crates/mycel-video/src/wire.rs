//! What video looks like on the wire, and what the webview gets.
//!
//! Video shares the call's QUIC connections with audio but never its
//! datagrams: every encoded frame goes on its own **unidirectional stream**
//! whose first byte is its track kind, as the call engine expects of every
//! track other than audio (it hands those streams to its `TrackSink`):
//!
//! ```text
//! 0      kind: 0x10 = a video frame, 0x11 = the video control stream
//! ```
//!
//! A frame stream then carries one frame and ends:
//!
//! ```text
//! 0..4   sequence number, u32 LE (one per encoded frame, never reused)
//! 4..12  capture time, µs since the Unix epoch, u64 LE
//! 12     flags (bit 0: keyframe)
//! 13..15 width, u16 LE      15..17 height, u16 LE
//! 17..19 config length, u16 LE, then the config: the H.264 `avcC` record
//!        (SPS + PPS), on keyframes only
//! ..     the frame: H.264 NAL units, each prefixed with its u32 BE length
//! ```
//!
//! Control messages ([`VideoCtrl`]: each a u16 LE length and postcard
//! bytes) go in datagrams starting with kind 0x11, or, on a path without
//! datagrams, on one control stream (kind 0x11) per direction.

use anyhow::{Result, bail, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

/// Track kinds (the first byte of a stream); audio is 0x01.
pub const KIND_FRAME: u8 = 0x10;
pub const KIND_CTRL: u8 = 0x11;
pub const STREAM_HEADER_LEN: usize = 1;
pub const FRAME_HEADER_LEN: usize = 19;
/// No single frame may be larger (a 720p keyframe is ~50–150 KB).
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const MAX_CONFIG: usize = 1024;
pub const FLAG_KEY: u8 = 0x01;

/// One encoded frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedFrame {
    pub seq: u32,
    /// When the picture was captured, µs since the Unix epoch.
    pub capture_us: u64,
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
    /// `avcC` (on keyframes): what a decoder needs to start.
    pub config: Option<Bytes>,
    /// AVCC: NAL units with u32 BE length prefixes.
    pub data: Bytes,
}

impl EncodedFrame {
    /// The frame stream's bytes after the stream header.
    pub fn encode(&self) -> Bytes {
        let cfg = self.config.as_deref().unwrap_or(&[]);
        let mut b = BytesMut::with_capacity(STREAM_HEADER_LEN + FRAME_HEADER_LEN + cfg.len() + self.data.len());
        b.put_u8(KIND_FRAME);
        b.put_u32_le(self.seq);
        b.put_u64_le(self.capture_us);
        b.put_u8(if self.keyframe { FLAG_KEY } else { 0 });
        b.put_u16_le(self.width);
        b.put_u16_le(self.height);
        b.put_u16_le(cfg.len() as u16);
        b.put_slice(cfg);
        b.put_slice(&self.data);
        b.freeze()
    }

    /// Parse a frame stream's bytes after the stream header.
    pub fn decode(b: Bytes) -> Result<EncodedFrame> {
        ensure!(b.len() >= FRAME_HEADER_LEN, "frame header too short ({} bytes)", b.len());
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let seq = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let capture_us = u64::from_le_bytes(b[4..12].try_into().unwrap());
        let flags = b[12];
        let (width, height) = (u16_at(13), u16_at(15));
        let cfg_len = u16_at(17) as usize;
        ensure!(cfg_len <= MAX_CONFIG, "config too long ({cfg_len} bytes)");
        ensure!(b.len() >= FRAME_HEADER_LEN + cfg_len, "frame cut short");
        let config = (cfg_len > 0).then(|| b.slice(FRAME_HEADER_LEN..FRAME_HEADER_LEN + cfg_len));
        let data = b.slice(FRAME_HEADER_LEN + cfg_len..);
        ensure!(!data.is_empty(), "empty frame");
        Ok(EncodedFrame { seq, capture_us, keyframe: flags & FLAG_KEY != 0, width, height, config, data })
    }
}

/// A stream of this track kind is video's.
pub fn is_video_kind(kind: u8) -> bool {
    matches!(kind, KIND_FRAME | KIND_CTRL)
}

pub fn ctrl_stream_header() -> [u8; STREAM_HEADER_LEN] {
    [KIND_CTRL]
}

/// Video control messages (one control stream per direction).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCtrl {
    /// My decoder lost its place: it can't go on from frame `missing`.
    /// Send a keyframe (unless one newer than that is already on its way).
    KeyframeRequest { missing: u32 },
    /// What I'm sending: camera on or off, and paused because the path
    /// can't carry video.
    State { camera: bool, paused: bool },
    /// I gave up on frame `seq` (its stream was reset). Said here too,
    /// because a reset can overtake a stream's first bytes, and then the
    /// receiver can't tell which frame it was.
    Dropped { seq: u32 },
}

impl VideoCtrl {
    pub fn encode(&self) -> Bytes {
        let body = postcard::to_allocvec(self).expect("serializable");
        let mut b = BytesMut::with_capacity(2 + body.len());
        b.put_u16_le(body.len() as u16);
        b.put_slice(&body);
        b.freeze()
    }
}

/// Which picture a [`UiFrame`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiSource {
    /// From the other device.
    Remote = 0,
    /// Our own camera (self-view), as we send it.
    Local = 1,
}

/// An encoded frame on its way to the webview, which decodes it (WebCodecs).
///
/// Binary layout (all little-endian):
///
/// ```text
/// 0      layout version (1)
/// 1      source: 0 = remote, 1 = self-view
/// 2      flags (bit 0: keyframe)
/// 3      0
/// 4..36  peer: whose video this is (32-byte device key)
/// 36..40 sequence number u32
/// 40..48 capture time, µs since the Unix epoch, u64
/// 48..50 width u16      50..52 height u16
/// 52..54 config length u16, then the avcC config, then the frame (AVCC)
/// ```
#[derive(Clone, Debug)]
pub struct UiFrame {
    pub source: UiSource,
    pub peer: [u8; 32],
    pub frame: EncodedFrame,
}

pub const UI_HEADER_LEN: usize = 54;

impl UiFrame {
    pub fn encode(&self) -> Vec<u8> {
        let f = &self.frame;
        let cfg = f.config.as_deref().unwrap_or(&[]);
        let mut b = Vec::with_capacity(UI_HEADER_LEN + cfg.len() + f.data.len());
        b.push(1);
        b.push(self.source as u8);
        b.push(if f.keyframe { FLAG_KEY } else { 0 });
        b.push(0);
        b.extend_from_slice(&self.peer);
        b.extend_from_slice(&f.seq.to_le_bytes());
        b.extend_from_slice(&f.capture_us.to_le_bytes());
        b.extend_from_slice(&f.width.to_le_bytes());
        b.extend_from_slice(&f.height.to_le_bytes());
        b.extend_from_slice(&(cfg.len() as u16).to_le_bytes());
        b.extend_from_slice(cfg);
        b.extend_from_slice(&f.data);
        b
    }

    pub fn decode(b: &[u8]) -> Result<UiFrame> {
        ensure!(b.len() > UI_HEADER_LEN && b[0] == 1, "not a UI frame");
        let source = match b[1] {
            0 => UiSource::Remote,
            1 => UiSource::Local,
            s => bail!("unknown source {s}"),
        };
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let cfg_len = u16_at(52) as usize;
        ensure!(b.len() > UI_HEADER_LEN + cfg_len, "UI frame cut short");
        let all = Bytes::copy_from_slice(b);
        Ok(UiFrame {
            source,
            peer: b[4..36].try_into().unwrap(),
            frame: EncodedFrame {
                seq: u32::from_le_bytes(b[36..40].try_into().unwrap()),
                capture_us: u64::from_le_bytes(b[40..48].try_into().unwrap()),
                keyframe: b[2] & FLAG_KEY != 0,
                width: u16_at(48),
                height: u16_at(50),
                config: (cfg_len > 0).then(|| all.slice(UI_HEADER_LEN..UI_HEADER_LEN + cfg_len)),
                data: all.slice(UI_HEADER_LEN + cfg_len..),
            },
        })
    }
}

/// Splits a control stream back into messages.
#[derive(Default)]
pub struct CtrlDeframer {
    buf: BytesMut,
}

impl CtrlDeframer {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_msg(&mut self) -> Result<Option<VideoCtrl>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        ensure!(len <= 1024, "control message too long ({len} bytes)");
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        let _ = self.buf.split_to(2);
        let body = self.buf.split_to(len);
        Ok(Some(postcard::from_bytes(&body)?))
    }
}

// ───────────────────────────── H.264 helpers ─────────────────────────────

/// An `avcC` record (ISO 14496-15) from one SPS and one PPS.
pub fn avcc_record(sps: &[u8], pps: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(11 + sps.len() + pps.len());
    b.put_u8(1); // configurationVersion
    b.put_u8(sps.get(1).copied().unwrap_or(0x42)); // profile
    b.put_u8(sps.get(2).copied().unwrap_or(0)); // compatibility
    b.put_u8(sps.get(3).copied().unwrap_or(0x1f)); // level
    b.put_u8(0xff); // 4-byte NAL lengths
    b.put_u8(0xe1); // one SPS
    b.put_u16(sps.len() as u16);
    b.put_slice(sps);
    b.put_u8(1); // one PPS
    b.put_u16(pps.len() as u16);
    b.put_slice(pps);
    b.freeze()
}

/// The SPS and PPS inside an `avcC` record.
pub fn avcc_parameter_sets(avcc: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(avcc.len() >= 7 && avcc[0] == 1, "not an avcC record");
    let mut i = 5;
    let n_sps = avcc[i] & 0x1f;
    i += 1;
    ensure!(n_sps >= 1, "no SPS");
    let take = |i: &mut usize| -> Result<Vec<u8>> {
        ensure!(avcc.len() >= *i + 2, "avcC cut short");
        let len = u16::from_be_bytes([avcc[*i], avcc[*i + 1]]) as usize;
        *i += 2;
        ensure!(avcc.len() >= *i + len, "avcC cut short");
        let v = avcc[*i..*i + len].to_vec();
        *i += len;
        Ok(v)
    };
    let sps = take(&mut i)?;
    for _ in 1..n_sps {
        take(&mut i)?;
    }
    ensure!(avcc.len() > i, "no PPS");
    i += 1;
    let pps = take(&mut i)?;
    Ok((sps, pps))
}

/// The WebCodecs codec string for an `avcC` record, e.g. `avc1.42e01f`.
pub fn codec_string(avcc: &[u8]) -> String {
    if avcc.len() < 4 {
        return "avc1.42e01f".into();
    }
    format!("avc1.{:02x}{:02x}{:02x}", avcc[1], avcc[2], avcc[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u32, key: bool) -> EncodedFrame {
        EncodedFrame {
            seq,
            capture_us: 1_700_000_000_000_000 + seq as u64,
            keyframe: key,
            width: 1280,
            height: 720,
            config: key.then(|| avcc_record(&[0x67, 0x42, 0xe0, 0x1f, 9], &[0x68, 1, 2])),
            data: Bytes::from(vec![seq as u8; 300]),
        }
    }

    #[test]
    fn frame_round_trip() {
        for key in [true, false] {
            let f = frame(9, key);
            let wire = f.encode();
            assert_eq!(wire[0], KIND_FRAME);
            let back = EncodedFrame::decode(wire.slice(STREAM_HEADER_LEN..)).unwrap();
            assert_eq!(back, f);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(is_video_kind(KIND_CTRL) && !is_video_kind(0x01), "audio is not video");
        assert!(EncodedFrame::decode(Bytes::from_static(&[0; 10])).is_err());
        let mut w = frame(1, true).encode().slice(STREAM_HEADER_LEN..).to_vec();
        w[17] = 0xff;
        w[18] = 0xff; // config longer than allowed
        assert!(EncodedFrame::decode(Bytes::from(w)).is_err());
        // header and config, but no picture
        let f = frame(1, true);
        let cut = f.encode().slice(STREAM_HEADER_LEN..STREAM_HEADER_LEN + FRAME_HEADER_LEN + f.config.unwrap().len());
        assert!(EncodedFrame::decode(cut).is_err());
    }

    #[test]
    fn ctrl_messages_survive_splits() {
        let msgs = [VideoCtrl::KeyframeRequest { missing: 7 }, VideoCtrl::State { camera: true, paused: false }, VideoCtrl::KeyframeRequest { missing: u32::MAX }];
        let wire: Vec<u8> = msgs.iter().flat_map(|m| m.encode().to_vec()).collect();
        for step in [1, 2, 5, 100] {
            let mut d = CtrlDeframer::default();
            let mut got = vec![];
            for c in wire.chunks(step) {
                d.push(c);
                while let Some(m) = d.next_msg().unwrap() {
                    got.push(m);
                }
            }
            assert_eq!(got, msgs);
        }
    }

    #[test]
    fn ui_frame_round_trip() {
        let ui = UiFrame { source: UiSource::Local, peer: [7; 32], frame: frame(3, true) };
        let b = ui.encode();
        let back = UiFrame::decode(&b).unwrap();
        assert_eq!(back.source, UiSource::Local);
        assert_eq!(back.peer, [7; 32]);
        assert_eq!(back.frame, ui.frame);
    }

    #[test]
    fn avcc_round_trip_and_codec_string() {
        let sps = [0x67, 0x64, 0x00, 0x28, 0xac, 0xd9];
        let pps = [0x68, 0xeb, 0xe3, 0xcb];
        let rec = avcc_record(&sps, &pps);
        assert_eq!(codec_string(&rec), "avc1.640028");
        let (s, p) = avcc_parameter_sets(&rec).unwrap();
        assert_eq!((s.as_slice(), p.as_slice()), (&sps[..], &pps[..]));
        assert!(avcc_parameter_sets(&rec[..8]).is_err());
    }
}
