//! Opus (RFC 6716) for calls: 48 kHz mono, 20 ms frames, VoIP mode, in-band
//! FEC. A small safe wrapper over `unsafe-libopus` (libopus 1.3.1 translated
//! to Rust, so there is no C toolchain and it builds for every target).

use anyhow::{Result, bail};
use unsafe_libopus as unsafe_ffi;
use unsafe_libopus::varargs::{VarArg, VarArgs};

/// Every call runs at this rate internally; devices are resampled to it.
pub const SAMPLE_RATE: u32 = 48_000;
pub const FRAME_MS: u32 = 20;
/// Samples in one 20 ms frame at 48 kHz.
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE / 1000 * FRAME_MS) as usize;
/// Big enough for any frame at the highest bitrate we use.
pub const MAX_PACKET: usize = 1275;

fn check(code: i32, what: &str) -> Result<i32> {
    if code < 0 {
        bail!("opus {what} failed ({code})");
    }
    Ok(code)
}

pub struct Encoder {
    st: *mut unsafe_ffi::OpusEncoder,
    bitrate: u32,
    loss: u8,
}

// The encoder state is plain memory owned by this value; it is only ever
// used through `&mut self`.
unsafe impl Send for Encoder {}

impl Encoder {
    pub fn new(bitrate: u32) -> Result<Encoder> {
        let mut err = 0;
        // SAFETY: valid arguments; the returned pointer is checked below.
        let st = unsafe { unsafe_ffi::opus_encoder_create(SAMPLE_RATE as i32, 1, unsafe_ffi::OPUS_APPLICATION_VOIP, &mut err) };
        if st.is_null() || err != unsafe_ffi::OPUS_OK {
            bail!("opus encoder could not start ({err})");
        }
        let mut e = Encoder { st, bitrate: 0, loss: 0 };
        e.ctl(unsafe_ffi::OPUS_SET_SIGNAL_REQUEST, unsafe_ffi::OPUS_SIGNAL_VOICE)?;
        e.ctl(unsafe_ffi::OPUS_SET_COMPLEXITY_REQUEST, 7)?;
        e.ctl(unsafe_ffi::OPUS_SET_INBAND_FEC_REQUEST, 1)?;
        e.ctl(unsafe_ffi::OPUS_SET_VBR_REQUEST, 1)?;
        e.set_bitrate(bitrate)?;
        e.set_expected_loss(5)?;
        Ok(e)
    }

    fn ctl(&mut self, request: i32, value: i32) -> Result<()> {
        // SAFETY: `st` is a live encoder; SET requests take one i32.
        let r = unsafe { unsafe_ffi::opus_encoder_ctl_impl(self.st, request, VarArgs::new(vec![VarArg::I32(value)])) };
        check(r, "setting").map(|_| ())
    }

    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }

    pub fn set_bitrate(&mut self, bps: u32) -> Result<()> {
        let bps = bps.clamp(6_000, 64_000);
        if bps != self.bitrate {
            self.ctl(unsafe_ffi::OPUS_SET_BITRATE_REQUEST, bps as i32)?;
            self.bitrate = bps;
        }
        Ok(())
    }

    /// Expected packet loss (percent): Opus spends more bits on FEC as it rises.
    pub fn set_expected_loss(&mut self, pct: u8) -> Result<()> {
        let pct = pct.min(40);
        if pct != self.loss {
            self.ctl(unsafe_ffi::OPUS_SET_PACKET_LOSS_PERC_REQUEST, pct as i32)?;
            self.loss = pct;
        }
        Ok(())
    }

    /// Encode one 20 ms frame (`FRAME_SAMPLES` mono samples in -1..1).
    pub fn encode(&mut self, pcm: &[f32], out: &mut [u8]) -> Result<usize> {
        if pcm.len() != FRAME_SAMPLES {
            bail!("opus frames are {FRAME_SAMPLES} samples, got {}", pcm.len());
        }
        // SAFETY: pointers and lengths come from live slices.
        let n = unsafe {
            unsafe_ffi::opus_encode_float(self.st, pcm.as_ptr(), FRAME_SAMPLES as i32, out.as_mut_ptr(), out.len() as i32)
        };
        Ok(check(n, "encode")? as usize)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_encoder_create, destroyed once.
        unsafe { unsafe_ffi::opus_encoder_destroy(self.st) }
    }
}

pub struct Decoder {
    st: *mut unsafe_ffi::OpusDecoder,
}

unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new() -> Result<Decoder> {
        let mut err = 0;
        // SAFETY: valid arguments; checked below.
        let st = unsafe { unsafe_ffi::opus_decoder_create(SAMPLE_RATE as i32, 1, &mut err) };
        if st.is_null() || err != unsafe_ffi::OPUS_OK {
            bail!("opus decoder could not start ({err})");
        }
        Ok(Decoder { st })
    }

    fn run(&mut self, data: Option<&[u8]>, fec: bool, out: &mut [f32]) -> Result<usize> {
        if out.len() < FRAME_SAMPLES {
            bail!("output buffer too small");
        }
        let (ptr, len) = match data {
            Some(d) if !d.is_empty() => (d.as_ptr(), d.len() as i32),
            _ => (std::ptr::null(), 0),
        };
        // SAFETY: `out` holds at least one frame; `ptr` is null or a live slice.
        let n = unsafe { unsafe_ffi::opus_decode_float(self.st, ptr, len, out.as_mut_ptr(), FRAME_SAMPLES as i32, fec as i32) };
        Ok(check(n, "decode")? as usize)
    }

    /// Decode a received packet into `out` (at least one frame long).
    pub fn decode(&mut self, packet: &[u8], out: &mut [f32]) -> Result<usize> {
        if packet.is_empty() {
            bail!("empty packet");
        }
        self.run(Some(packet), false, out)
    }

    /// A packet never arrived: packet-loss concealment.
    pub fn conceal(&mut self, out: &mut [f32]) -> Result<usize> {
        self.run(None, false, out)
    }

    /// A packet never arrived but the next one did: rebuild the lost frame
    /// from the forward-error-correction data the next packet carries.
    pub fn recover(&mut self, next_packet: &[u8], out: &mut [f32]) -> Result<usize> {
        self.run(Some(next_packet), true, out)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_decoder_create, destroyed once.
        unsafe { unsafe_ffi::opus_decoder_destroy(self.st) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::estimate_frequency;

    fn sine(freq: f32, n: usize, offset: usize) -> Vec<f32> {
        (0..n)
            .map(|i| 0.5 * (2.0 * std::f32::consts::PI * freq * (i + offset) as f32 / SAMPLE_RATE as f32).sin())
            .collect()
    }

    #[test]
    fn round_trip_keeps_the_tone() {
        let mut enc = Encoder::new(24_000).unwrap();
        let mut dec = Decoder::new().unwrap();
        let mut out = Vec::new();
        let mut bytes = 0;
        for f in 0..50 {
            let pcm = sine(440.0, FRAME_SAMPLES, f * FRAME_SAMPLES);
            let mut pkt = [0u8; MAX_PACKET];
            let n = enc.encode(&pcm, &mut pkt).unwrap();
            bytes += n;
            let mut frame = [0f32; FRAME_SAMPLES];
            assert_eq!(dec.decode(&pkt[..n], &mut frame).unwrap(), FRAME_SAMPLES);
            out.extend_from_slice(&frame);
        }
        // one second at ~24 kbps is ~3 KB
        assert!((1_500..5_000).contains(&bytes), "bytes {bytes}");
        let f = estimate_frequency(&out[SAMPLE_RATE as usize / 5..], SAMPLE_RATE).unwrap();
        assert!((f - 440.0).abs() < 5.0, "decoded {f} Hz");
    }

    #[test]
    fn low_bitrate_for_bluetooth_is_small() {
        let mut enc = Encoder::new(12_000).unwrap();
        let mut bytes = 0;
        for f in 0..50 {
            let mut pkt = [0u8; MAX_PACKET];
            bytes += enc.encode(&sine(300.0, FRAME_SAMPLES, f * FRAME_SAMPLES), &mut pkt).unwrap();
        }
        assert!(bytes < 2_200, "12 kbps should be ~1.5 KB/s, got {bytes}");
    }

    #[test]
    fn concealment_and_fec_produce_a_frame() {
        let mut enc = Encoder::new(16_000).unwrap();
        enc.set_expected_loss(20).unwrap();
        let mut dec = Decoder::new().unwrap();
        let mut frame = [0f32; FRAME_SAMPLES];
        let mut pkts = Vec::new();
        for f in 0..10 {
            let mut pkt = [0u8; MAX_PACKET];
            let n = enc.encode(&sine(300.0, FRAME_SAMPLES, f * FRAME_SAMPLES), &mut pkt).unwrap();
            pkts.push(pkt[..n].to_vec());
        }
        for p in &pkts[..5] {
            dec.decode(p, &mut frame).unwrap();
        }
        assert_eq!(dec.conceal(&mut frame).unwrap(), FRAME_SAMPLES);
        assert_eq!(dec.recover(&pkts[7], &mut frame).unwrap(), FRAME_SAMPLES);
        assert!(dec.decode(&[], &mut frame).is_err());
    }
}
