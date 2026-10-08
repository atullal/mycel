//! Where pictures come from: the camera, or a test pattern.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::platform::PixelBuffer;

/// Wall-clock µs since the Unix epoch (capture times travel with frames so
/// the receiver can measure capture-to-display delay).
pub fn wall_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// One captured picture (cloning shares the pixels).
#[derive(Clone)]
pub struct Picture {
    pub width: u32,
    pub height: u32,
    pub capture_us: u64,
    pub buf: PixelBuffer,
}

pub type PictureSink = Arc<dyn Fn(Picture) + Send + Sync>;

/// Keeps a source running; dropping it stops the source.
pub struct SourceHandle(#[allow(dead_code)] Box<dyn Send>);

impl SourceHandle {
    pub fn new(inner: impl Send + 'static) -> SourceHandle {
        SourceHandle(Box::new(inner))
    }
}

pub trait VideoSource: Send + Sync + 'static {
    /// Shown in call stats ("FaceTime HD Camera", "Test pattern").
    fn describe(&self) -> String;
    /// Make sure we may use the camera, asking the user if the OS hasn't
    /// yet. Blocking (it may wait for the user); errors say what to do.
    fn prepare(&self) -> Result<()> {
        Ok(())
    }
    /// Start delivering pictures to `sink` until the handle is dropped.
    fn start(&self, sink: PictureSink) -> Result<SourceHandle>;
}

/// A moving test pattern with the frame counter drawn in (see
/// [`crate::pattern`]), at a fixed size and frame rate.
pub struct TestPattern {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

impl Default for TestPattern {
    fn default() -> Self {
        TestPattern { width: 1280, height: 720, fps: 30 }
    }
}

struct Stop(Arc<AtomicBool>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl VideoSource for TestPattern {
    fn describe(&self) -> String {
        format!("Test pattern {}x{} {} fps", self.width, self.height, self.fps)
    }

    fn start(&self, sink: PictureSink) -> Result<SourceHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let (w, h, fps) = (self.width, self.height, self.fps.max(1));
        let flag = stop.clone();
        std::thread::Builder::new().name("mycel-video-test".into()).spawn(move || {
            let start = Instant::now();
            let interval = Duration::from_secs_f64(1.0 / fps as f64);
            let mut n: u32 = 0;
            while !flag.load(Ordering::Relaxed) {
                let due = start + interval * n;
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
                let capture_us = wall_us();
                let pic = crate::pattern::draw(n & 0xffff, w, h);
                if let Ok(buf) = PixelBuffer::from_nv12(&pic) {
                    sink(Picture { width: w, height: h, capture_us, buf });
                }
                n = n.wrapping_add(1);
            }
        })?;
        Ok(SourceHandle::new(Stop(stop)))
    }
}

/// The video source for this device. `MYCEL_VIDEO` picks it:
/// - unset / `camera`: the default camera
/// - `test`: the test pattern at 720p30
pub fn default_source() -> Arc<dyn VideoSource> {
    match std::env::var("MYCEL_VIDEO").unwrap_or_default().trim() {
        "test" => Arc::new(TestPattern::default()),
        _ => crate::platform::camera(),
    }
}
