//! Platforms without a video backend yet: calls stay audio-only.

use std::sync::Arc;

use anyhow::{Result, bail};

use crate::pattern::Nv12;
use crate::source::{PictureSink, SourceHandle, VideoSource};
use crate::wire::EncodedFrame;

const UNSUPPORTED: &str = "Video isn't available on this device yet.";

pub struct PixelBuffer;

impl PixelBuffer {
    pub fn from_nv12(_p: &Nv12) -> Result<PixelBuffer> {
        bail!(UNSUPPORTED)
    }

    pub fn size(&self) -> (u32, u32) {
        (0, 0)
    }

    pub fn luma(&self) -> Result<(usize, usize, Vec<u8>)> {
        bail!(UNSUPPORTED)
    }
}

pub struct H264Encoder;

impl H264Encoder {
    pub fn new(_w: u32, _h: u32, _fps: u32, _bps: u32) -> Result<H264Encoder> {
        bail!(UNSUPPORTED)
    }

    pub fn size(&self) -> (u32, u32) {
        (0, 0)
    }

    pub fn set_bitrate(&mut self, _bps: u32) {}

    pub fn describe(&self) -> String {
        String::new()
    }

    pub fn encode(&mut self, _pb: &PixelBuffer, _pts_us: i64, _force_key: bool) -> Result<Option<EncodedFrame>> {
        bail!(UNSUPPORTED)
    }
}

#[derive(Default)]
pub struct H264Decoder;

impl H264Decoder {
    pub fn decode(&mut self, _f: &EncodedFrame) -> Result<PixelBuffer> {
        bail!(UNSUPPORTED)
    }
}

pub const CAMERA_DENIED: &str = UNSUPPORTED;

struct NoCamera;

impl VideoSource for NoCamera {
    fn describe(&self) -> String {
        "No camera".into()
    }

    fn start(&self, _sink: PictureSink) -> Result<SourceHandle> {
        bail!(UNSUPPORTED)
    }
}

pub fn camera() -> Arc<dyn VideoSource> {
    Arc::new(NoCamera)
}
