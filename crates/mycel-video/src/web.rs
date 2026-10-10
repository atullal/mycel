//! Video where the app's web view does the camera and the encoding (Android,
//! Windows, Linux): their web views capture with `getUserMedia` and encode
//! H.264 with WebCodecs `VideoEncoder`, in hardware where the platform has
//! it (MediaCodec on Android, Media Foundation in WebView2) and under the
//! platform's codec licence, as VideoToolbox is on Apple devices. The page
//! pushes each encoded frame here ([`push`]); the rest of the pipeline (rate
//! control, pacing, giving up on stuck frames, keyframes) is the same as on
//! a Mac.
//!
//! The pieces the pipeline expects, for frames that arrive already encoded:
//! - [`PixelBuffer`] carries one encoded frame instead of pixels;
//! - [`H264Encoder`] passes frames through, and since a skipped frame
//!   breaks the H.264 reference chain, it drops frames after a gap (or when
//!   a keyframe is wanted) until the web view's next keyframe, and asks the
//!   web view for one;
//! - its size, frame rate and bitrate become targets the page encodes to
//!   ([`push`] returns them), the lowest across a group call's peers.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, bail};
use parking_lot::Mutex;
use serde::Serialize;

use crate::pattern::Nv12;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
use crate::source::{Picture, wall_us};
use crate::source::{PictureSink, SourceHandle, VideoSource};
use crate::wire::EncodedFrame;

pub const CAMERA_DENIED: &str = "Mycel isn't allowed to use the camera. Allow it for Mycel in your system's settings, then turn the camera on again.";

/// The track paces frames by dropping pictures; here the web view encodes at
/// the target frame rate instead, and dropping an encoded frame would cost a
/// keyframe.
pub const SOURCE_PACED: bool = true;

/// One encoded frame from the web view, numbered so gaps can be seen.
#[derive(Clone)]
pub struct PixelBuffer {
    frame: Arc<EncodedFrame>,
    number: u64,
}

impl PixelBuffer {
    pub fn from_nv12(_p: &Nv12) -> Result<PixelBuffer> {
        bail!("Raw pictures (the test pattern) need a native encoder, which this device doesn't have.")
    }

    pub fn size(&self) -> (u32, u32) {
        (self.frame.width as u32, self.frame.height as u32)
    }

    pub fn luma(&self) -> Result<(usize, usize, Vec<u8>)> {
        bail!("Encoded frames have no pixels to read.")
    }
}

/// What the web view should encode to: the smallest of what each peer's
/// track asks for. `keyframe`: make the next frame a keyframe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Targets {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
    pub keyframe: bool,
}

#[derive(Clone, Copy)]
struct Want {
    width: u32,
    height: u32,
    fps: u32,
    bitrate: u32,
}

#[derive(Default)]
struct Web {
    /// The camera's sink while it's on ([`camera`] started).
    sink: Mutex<Option<PictureSink>>,
    /// What each live encoder (one per peer track) wants.
    wants: Mutex<BTreeMap<u64, Want>>,
    next_encoder: AtomicU64,
    #[cfg_attr(any(target_os = "macos", target_os = "ios"), allow(dead_code))]
    next_frame: AtomicU64,
    want_key: AtomicBool,
}

static WEB: LazyLock<Web> = LazyLock::new(Web::default);

/// A frame the web view encoded (`number`: its place in the web view's
/// encoding order). Returns what to encode next, or `None` if
/// the camera isn't on (stop capturing). (Apple devices use their own
/// camera, so there's nothing to push to.)
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn push(frame: EncodedFrame, number: Option<u64>) -> Option<Targets> {
    let sink = WEB.sink.lock().clone()?;
    // The web view's own count, so a frame it encoded but never delivered
    // shows as a gap; else in order of arrival.
    let number = number.unwrap_or_else(|| WEB.next_frame.fetch_add(1, Ordering::Relaxed));
    let (width, height) = (frame.width as u32, frame.height as u32);
    let capture_us = if frame.capture_us == 0 { wall_us() } else { frame.capture_us };
    sink(Picture { width, height, capture_us, buf: PixelBuffer { frame: Arc::new(frame), number } });
    Some(targets())
}

/// The camera is on (a call wants our video): the web view should capture.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn camera_on() -> bool {
    WEB.sink.lock().is_some()
}

/// What the web view should encode to now (and whether a keyframe is
/// wanted: reading it clears it).
pub fn targets() -> Targets {
    let wants = WEB.wants.lock();
    let mut t = wants.values().fold(None::<Want>, |acc, w| {
        Some(match acc {
            None => *w,
            Some(a) => Want {
                width: a.width.min(w.width),
                height: a.height.min(w.height),
                fps: a.fps.min(w.fps),
                bitrate: a.bitrate.min(w.bitrate),
            },
        })
    });
    let t = t.get_or_insert(Want { width: 640, height: 360, fps: 15, bitrate: 500_000 });
    Targets {
        width: t.width,
        height: t.height,
        fps: t.fps,
        bitrate: t.bitrate,
        keyframe: WEB.want_key.swap(false, Ordering::Relaxed),
    }
}

/// Passes the web view's frames through (see the module docs).
pub struct H264Encoder {
    id: u64,
    width: u32,
    height: u32,
    /// The number of the last frame passed on; a jump is a gap.
    last: Option<u64>,
    /// Drop deltas until a keyframe (fresh, forced, or after a gap).
    need_key: bool,
}

impl H264Encoder {
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<H264Encoder> {
        let id = WEB.next_encoder.fetch_add(1, Ordering::Relaxed);
        WEB.wants.lock().insert(id, Want { width, height, fps, bitrate });
        WEB.want_key.store(true, Ordering::Relaxed);
        Ok(H264Encoder { id, width, height, last: None, need_key: true })
    }

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The track's quality changed: the web view encodes to the new size and
    /// frame rate (and sends a keyframe when it re-configures).
    pub fn retarget(&mut self, width: u32, height: u32, fps: u32) {
        (self.width, self.height) = (width, height);
        if let Some(w) = WEB.wants.lock().get_mut(&self.id) {
            (w.width, w.height, w.fps) = (width, height, fps);
        }
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        if let Some(w) = WEB.wants.lock().get_mut(&self.id) {
            w.bitrate = bps;
        }
    }

    pub fn describe(&self) -> String {
        "H.264 (web view)".into()
    }

    pub fn encode(&mut self, pb: &PixelBuffer, _pts_us: i64, force_key: bool) -> Result<Option<EncodedFrame>> {
        let gap = self.last.is_some_and(|n| pb.number != n + 1);
        if (force_key || gap) && std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!("[video web] frame {} after {:?}: forced {force_key} gap {gap}", pb.number, self.last);
        }
        if force_key || gap {
            self.need_key = true;
        }
        self.last = Some(pb.number);
        if self.need_key && !pb.frame.keyframe {
            WEB.want_key.store(true, Ordering::Relaxed);
            return Ok(None);
        }
        self.need_key = false;
        Ok(Some((*pb.frame).clone()))
    }
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        WEB.wants.lock().remove(&self.id);
    }
}

/// Decoding happens in the web view; tests that decode in Rust run on Apple
/// devices.
#[derive(Default)]
pub struct H264Decoder;

impl H264Decoder {
    pub fn decode(&mut self, _f: &EncodedFrame) -> Result<PixelBuffer> {
        bail!("Video is decoded by the web view on this device.")
    }
}

/// The camera, as seen from the runtime: on while the web view may push
/// frames. (The web view asks for camera access itself.)
struct WebCamera;

struct CameraOn;


impl Drop for CameraOn {
    fn drop(&mut self) {
        WEB.sink.lock().take();
    }
}

impl VideoSource for WebCamera {
    fn describe(&self) -> String {
        "Camera (web view)".into()
    }

    fn start(&self, sink: PictureSink) -> Result<SourceHandle> {
        *WEB.sink.lock() = Some(sink);
        WEB.want_key.store(true, Ordering::Relaxed);
        Ok(SourceHandle::new(CameraOn))
    }
}

#[cfg_attr(any(target_os = "macos", target_os = "ios"), allow(dead_code))]
pub fn camera() -> Arc<dyn VideoSource> {
    Arc::new(WebCamera)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn frame(key: bool) -> PixelBuffer {
        let f = EncodedFrame {
            seq: 0,
            capture_us: 1,
            keyframe: key,
            width: 640,
            height: 360,
            config: key.then(|| Bytes::from_static(b"avcC")),
            data: Bytes::from_static(b"\0\0\0\x01\x65"),
        };
        PixelBuffer { frame: Arc::new(f), number: 0 }
    }

    /// The backend's state is process-wide: one test at a time.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn numbered(mut pb: PixelBuffer, n: u64) -> PixelBuffer {
        pb.number = n;
        pb
    }

    #[test]
    fn passes_frames_and_recovers_from_gaps_with_a_keyframe() {
        let _one = ONE_AT_A_TIME.lock();
        let mut enc = H264Encoder::new(640, 360, 30, 800_000).unwrap();
        // fresh: deltas wait for a keyframe
        assert!(enc.encode(&numbered(frame(false), 1), 0, false).unwrap().is_none());
        assert!(enc.encode(&numbered(frame(true), 2), 0, false).unwrap().is_some());
        assert!(enc.encode(&numbered(frame(false), 3), 0, false).unwrap().is_some());
        // frame 4 skipped by the track: 5 can't be decoded without it
        assert!(enc.encode(&numbered(frame(false), 5), 0, false).unwrap().is_none());
        assert!(enc.encode(&numbered(frame(false), 6), 0, false).unwrap().is_none());
        assert!(enc.encode(&numbered(frame(true), 7), 0, false).unwrap().is_some());
        // a forced keyframe (loss on the path) waits for the next keyframe too
        assert!(enc.encode(&numbered(frame(false), 8), 0, true).unwrap().is_none());
        assert!(enc.encode(&numbered(frame(true), 9), 0, false).unwrap().is_some());
    }

    #[test]
    fn targets_follow_the_most_constrained_peer() {
        let _one = ONE_AT_A_TIME.lock();
        let _ = targets();
        let a = H264Encoder::new(1280, 720, 30, 1_500_000).unwrap();
        let mut b = H264Encoder::new(640, 360, 15, 400_000).unwrap();
        b.set_bitrate(300_000);
        let t = targets();
        assert_eq!((t.width, t.height, t.fps, t.bitrate), (640, 360, 15, 300_000));
        assert!(t.keyframe, "new encoders want a keyframe");
        assert!(!targets().keyframe, "asked once");
        drop(b);
        let t = targets();
        assert_eq!((t.width, t.height, t.fps, t.bitrate), (1280, 720, 30, 1_500_000));
        drop(a);
    }
}
