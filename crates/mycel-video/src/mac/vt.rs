//! Hardware H.264 through VideoToolbox: pixel buffers, the encoder, and a
//! decoder (used by tests and headless runs; the app's webview decodes with
//! WebCodecs, which uses the same hardware).

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::mpsc;

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSString};

use super::ffi::*;
use crate::pattern::Nv12;
use crate::wire::{EncodedFrame, avcc_parameter_sets, avcc_record};

fn key(k: CFStringRef) -> &'static NSString {
    // SAFETY: CFStringRef constants are toll-free bridged NSStrings that live forever.
    unsafe { &*(k as *const NSString) }
}

fn dict(pairs: &[(CFStringRef, &AnyObject)]) -> Retained<NSDictionary<NSString, AnyObject>> {
    let keys: Vec<&NSString> = pairs.iter().map(|(k, _)| key(*k)).collect();
    let vals: Vec<&AnyObject> = pairs.iter().map(|(_, v)| *v).collect();
    NSDictionary::from_slices(&keys, &vals)
}

fn cf<T: objc2::Message>(o: &T) -> *const c_void {
    o as *const T as *const c_void
}

fn cf_bool(b: bool) -> CFTypeRef {
    // SAFETY: the CFBoolean constants are always valid.
    unsafe { if b { kCFBooleanTrue } else { kCFBooleanFalse } }
}

fn num(n: f64) -> Retained<NSNumber> {
    NSNumber::new_f64(n)
}

fn int(n: i64) -> Retained<NSNumber> {
    NSNumber::new_i64(n)
}

/// A retained `CVPixelBuffer`.
pub struct PixelBuffer(CVPixelBufferRef);

// SAFETY: CVPixelBuffers are reference counted thread-safely, and we only
// touch their memory while locked.
unsafe impl Send for PixelBuffer {}
unsafe impl Sync for PixelBuffer {}

impl PixelBuffer {
    /// Retain a buffer someone else owns (e.g. a camera's).
    ///
    /// # Safety
    /// `pb` must be a valid `CVPixelBufferRef`.
    pub unsafe fn retain(pb: CVPixelBufferRef) -> PixelBuffer {
        unsafe { CFRetain(pb as CFTypeRef) };
        PixelBuffer(pb)
    }

    pub fn raw(&self) -> CVPixelBufferRef {
        self.0
    }

    pub fn size(&self) -> (u32, u32) {
        unsafe { (CVPixelBufferGetWidth(self.0) as u32, CVPixelBufferGetHeight(self.0) as u32) }
    }

    /// A new IOSurface-backed NV12 buffer holding `p`.
    pub fn from_nv12(p: &Nv12) -> Result<PixelBuffer> {
        let pb = Self::new_nv12(p.width, p.height)?;
        unsafe {
            CVPixelBufferLockBaseAddress(pb.0, 0);
            for (plane, src, row_bytes) in [(0, &p.y, p.width as usize), (1, &p.uv, p.width as usize)] {
                let dst = CVPixelBufferGetBaseAddressOfPlane(pb.0, plane);
                let stride = CVPixelBufferGetBytesPerRowOfPlane(pb.0, plane);
                let rows = CVPixelBufferGetHeightOfPlane(pb.0, plane);
                for r in 0..rows.min(src.len() / row_bytes) {
                    std::ptr::copy_nonoverlapping(src.as_ptr().add(r * row_bytes), dst.add(r * stride), row_bytes);
                }
            }
            CVPixelBufferUnlockBaseAddress(pb.0, 0);
        }
        Ok(pb)
    }

    /// A new, uninitialised IOSurface-backed NV12 buffer.
    fn new_nv12(width: u32, height: u32) -> Result<PixelBuffer> {
        let empty = NSDictionary::<NSString, AnyObject>::new();
        let fmt = int(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i64);
        let attrs = dict(&[
            (unsafe { kCVPixelBufferIOSurfacePropertiesKey }, &empty),
            (unsafe { kCVPixelBufferPixelFormatTypeKey }, &fmt),
        ]);
        let mut pb: CVPixelBufferRef = null_mut();
        let rc = unsafe {
            CVPixelBufferCreate(
                null(),
                width as usize,
                height as usize,
                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                cf(&*attrs),
                &mut pb,
            )
        };
        ensure!(rc == 0 && !pb.is_null(), "CVPixelBufferCreate failed ({rc})");
        Ok(PixelBuffer(pb))
    }

    /// The luma plane, tightly packed: (width, height, bytes). NV12 only.
    pub fn luma(&self) -> Result<(usize, usize, Vec<u8>)> {
        unsafe {
            let fmt = CVPixelBufferGetPixelFormatType(self.0);
            ensure!(
                fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange || fmt == u32::from_be_bytes(*b"420f"),
                "not NV12"
            );
            CVPixelBufferLockBaseAddress(self.0, kCVPixelBufferLock_ReadOnly);
            let (w, h) = (CVPixelBufferGetWidth(self.0), CVPixelBufferGetHeight(self.0));
            let base = CVPixelBufferGetBaseAddressOfPlane(self.0, 0);
            let stride = CVPixelBufferGetBytesPerRowOfPlane(self.0, 0);
            let mut out = vec![0u8; w * h];
            for r in 0..h {
                std::ptr::copy_nonoverlapping(base.add(r * stride), out.as_mut_ptr().add(r * w), w);
            }
            CVPixelBufferUnlockBaseAddress(self.0, kCVPixelBufferLock_ReadOnly);
            Ok((w, h, out))
        }
    }
}

impl Clone for PixelBuffer {
    fn clone(&self) -> Self {
        unsafe { PixelBuffer::retain(self.0) }
    }
}

impl Drop for PixelBuffer {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as CFTypeRef) }
    }
}

// ─────────────────────────────── encoder ───────────────────────────────

struct Encoded {
    keyframe: bool,
    config: Option<Bytes>,
    data: Bytes,
}

/// One message per frame handed to the encoder: the frame, `None` if the
/// encoder dropped it, or its error.
type EncOut = mpsc::Sender<Result<Option<Encoded>>>;

unsafe extern "C-unwind" fn on_encoded(
    refcon: *mut c_void,
    _src: *mut c_void,
    status: OSStatus,
    flags: u32,
    sb: CMSampleBufferRef,
) {
    // SAFETY: refcon is the session's boxed sender, alive until after invalidate.
    let tx = unsafe { &*(refcon as *const EncOut) };
    if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
        eprintln!("[video] encoded: status {status} flags {flags:#x} sample {}", !sb.is_null());
    }
    if status != 0 {
        let _ = tx.send(Err(anyhow::anyhow!("H.264 encoder error {status}")));
        return;
    }
    if sb.is_null() || flags & kVTEncodeInfo_FrameDropped != 0 {
        // dropped by the encoder's rate control: say so at once, or the
        // caller would wait out its timeout for a frame that never comes
        let _ = tx.send(Ok(None));
        return;
    }
    let _ = tx.send(unsafe { read_sample(sb) }.map(Some));
}

/// Pull the frame, its keyframe flag and (on keyframes) its SPS/PPS out of
/// an encoder output.
unsafe fn read_sample(sb: CMSampleBufferRef) -> Result<Encoded> {
    unsafe {
        let mut keyframe = true;
        let atts = CMSampleBufferGetSampleAttachmentsArray(sb, 0);
        if !atts.is_null() && CFArrayGetCount(atts) > 0 {
            let d = CFArrayGetValueAtIndex(atts, 0);
            let not_sync = CFDictionaryGetValue(d, kCMSampleAttachmentKey_NotSync);
            keyframe = not_sync.is_null() || not_sync == kCFBooleanFalse;
        }
        let bb = CMSampleBufferGetDataBuffer(sb);
        ensure!(!bb.is_null(), "encoder output without data");
        let len = CMBlockBufferGetDataLength(bb);
        let mut data = vec![0u8; len];
        let rc = CMBlockBufferCopyDataBytes(bb, 0, len, data.as_mut_ptr() as *mut c_void);
        ensure!(rc == 0, "copying encoded data failed ({rc})");
        let mut config = None;
        if keyframe {
            let desc = CMSampleBufferGetFormatDescription(sb);
            let set = |i: usize| -> Result<Vec<u8>> {
                let (mut p, mut n, mut count, mut hl) = (null(), 0usize, 0usize, 0i32);
                let rc =
                    CMVideoFormatDescriptionGetH264ParameterSetAtIndex(desc, i, &mut p, &mut n, &mut count, &mut hl);
                ensure!(rc == 0 && !p.is_null(), "no H.264 parameter set {i} ({rc})");
                ensure!(hl == 4, "unexpected NAL length size {hl}");
                Ok(std::slice::from_raw_parts(p, n).to_vec())
            };
            let (sps, pps) = (set(0)?, set(1)?);
            config = Some(avcc_record(&sps, &pps));
        }
        Ok(Encoded { keyframe, config, data: Bytes::from(data) })
    }
}

/// How an encoder session is set up. [`H264Encoder`] starts with the first
/// mode that VideoToolbox accepts and moves down the list when a session
/// stops answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderMode {
    /// Low-latency rate control (macOS 11.3+): no frame buffering in the
    /// encoder, steadier frame sizes. The encoder scales the picture.
    LowLatency,
    /// VideoToolbox's default H.264 encoder, scaling the picture itself.
    Standard,
    /// The default encoder, fed pictures already scaled to the output size
    /// by a pixel transfer session.
    PreScaled,
    /// Apple's software H.264 encoder (macOS only), fed scaled pictures.
    Software,
}

impl EncoderMode {
    const ALL: [EncoderMode; 4] =
        [EncoderMode::LowLatency, EncoderMode::Standard, EncoderMode::PreScaled, EncoderMode::Software];

    fn next(self) -> Option<EncoderMode> {
        let i = Self::ALL.iter().position(|m| *m == self)?;
        Self::ALL.get(i + 1).copied()
    }

    fn prescales(self) -> bool {
        matches!(self, EncoderMode::PreScaled | EncoderMode::Software)
    }
}

/// Consecutive frames VideoToolbox doesn't return at all (200 ms each)
/// before a session is given up for the next mode. Also how many pictures
/// a new session gets to produce its first frame, dropped or not.
const STALL_TIMEOUTS: u32 = 3;
/// Consecutive frames without output, drops included, before a session
/// that did produce frames is given up: rate control drops a frame or two
/// after a big keyframe, never a second's worth.
const STALL_FRAMES: u32 = 30;

/// (mode, width, height) whose sessions in this process produced nothing at
/// all before they were given up. New encoders of that size skip the mode,
/// so a size change doesn't stall the track again.
static UNANSWERED: std::sync::Mutex<Vec<(EncoderMode, u32, u32)>> = std::sync::Mutex::new(Vec::new());

fn unanswered(mode: EncoderMode, width: u32, height: u32) -> bool {
    UNANSWERED.lock().is_ok_and(|v| v.contains(&(mode, width, height)))
}

/// Scales pictures to the encoder's output size: with a pixel transfer
/// session, or on the CPU if that fails (a virtual Mac has no hardware
/// scaler).
struct Scaler {
    /// `None` once a transfer failed: the CPU scales from then on.
    transfer: Option<VTSessionRef>,
    width: u32,
    height: u32,
}

impl Scaler {
    fn new(width: u32, height: u32) -> Scaler {
        let mut session: VTSessionRef = null_mut();
        let rc = unsafe { VTPixelTransferSessionCreate(null(), &mut session) };
        let transfer = (rc == 0 && !session.is_null()).then_some(session);
        if transfer.is_none() {
            eprintln!("[video] no pixel transfer session ({rc}): scaling on the CPU");
        }
        Scaler { transfer, width, height }
    }

    fn scale(&mut self, pb: &PixelBuffer) -> Result<PixelBuffer> {
        if pb.size() == (self.width, self.height) {
            return Ok(pb.clone());
        }
        // a new buffer per frame: the encoder may still hold the last one
        let out = PixelBuffer::new_nv12(self.width, self.height)?;
        if let Some(session) = self.transfer {
            let rc = unsafe { VTPixelTransferSessionTransferImage(session, pb.raw(), out.raw()) };
            if rc == 0 {
                return Ok(out);
            }
            eprintln!("[video] pixel transfer to {}x{} failed ({rc}): scaling on the CPU", self.width, self.height);
            unsafe {
                VTPixelTransferSessionInvalidate(session);
                CFRelease(session as CFTypeRef);
            }
            self.transfer = None;
        }
        cpu_scale(pb, &out)?;
        Ok(out)
    }
}

#[cfg(test)]
impl Scaler {
    /// Scale on the CPU only, as after a failed transfer.
    fn cpu_only(&mut self) {
        if let Some(session) = self.transfer.take() {
            unsafe {
                VTPixelTransferSessionInvalidate(session);
                CFRelease(session as CFTypeRef);
            }
        }
    }
}

impl Drop for Scaler {
    fn drop(&mut self) {
        if let Some(session) = self.transfer.take() {
            unsafe {
                VTPixelTransferSessionInvalidate(session);
                CFRelease(session as CFTypeRef);
            }
        }
    }
}

/// Scale one NV12 (or full-range NV12) picture into another on the CPU.
fn cpu_scale(src: &PixelBuffer, dst: &PixelBuffer) -> Result<()> {
    let format = unsafe { CVPixelBufferGetPixelFormatType(src.0) };
    ensure!(
        format == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
            || format == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        "can't scale pixel format {format:#x}"
    );
    unsafe {
        CVPixelBufferLockBaseAddress(src.0, kCVPixelBufferLock_ReadOnly);
        CVPixelBufferLockBaseAddress(dst.0, 0);
        // (plane, bytes per sample): Y, then interleaved CbCr
        for (plane, channels) in [(0, 1), (1, 2)] {
            let geometry = |pb: CVPixelBufferRef| {
                let rows = CVPixelBufferGetHeightOfPlane(pb, plane);
                let stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
                let width = CVPixelBufferGetWidthOfPlane(pb, plane);
                (CVPixelBufferGetBaseAddressOfPlane(pb, plane), width, rows, stride)
            };
            let (sp, sw, sh, ss) = geometry(src.0);
            let (dp, dw, dh, ds) = geometry(dst.0);
            // SAFETY: each plane is `rows` rows of `stride` bytes, locked above
            let from = std::slice::from_raw_parts(sp, ss * sh);
            let to = std::slice::from_raw_parts_mut(dp, ds * dh);
            box_scale(from, (sw, sh, ss), to, (dw, dh, ds), channels);
        }
        CVPixelBufferUnlockBaseAddress(dst.0, 0);
        CVPixelBufferUnlockBaseAddress(src.0, kCVPixelBufferLock_ReadOnly);
    }
    Ok(())
}

/// Area-average a plane of `width`×`height` samples of `channels`
/// interleaved bytes (rows `stride` bytes apart) into another: each output
/// sample is the mean of the source samples it covers, or the nearest one
/// when scaling up. Linear in the source size.
fn box_scale(
    src: &[u8],
    (sw, sh, ss): (usize, usize, usize),
    dst: &mut [u8],
    (dw, dh, ds): (usize, usize, usize),
    channels: usize,
) {
    if sw == 0 || sh == 0 {
        return;
    }
    let span = |i: usize, from: usize, to: usize| {
        let a = (i * from / to).min(from - 1);
        (a, ((i + 1) * from / to).clamp(a + 1, from))
    };
    for y in 0..dh {
        let (y0, y1) = span(y, sh, dh);
        for x in 0..dw {
            let (x0, x1) = span(x, sw, dw);
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            for c in 0..channels {
                let mut sum = 0u32;
                for sy in y0..y1 {
                    let row = &src[sy * ss..];
                    sum += (x0..x1).map(|sx| u32::from(row[sx * channels + c])).sum::<u32>();
                }
                dst[y * ds + x * channels + c] = ((sum + n / 2) / n) as u8;
            }
        }
    }
}

/// One VTCompressionSession, configured.
struct Session {
    raw: VTSessionRef,
    /// `None`: VideoToolbox doesn't say (low-latency mode).
    hardware: Option<bool>,
}

impl Session {
    fn open(mode: EncoderMode, width: u32, height: u32, fps: u32, out: *mut EncOut) -> Option<Session> {
        let yes = NSNumber::new_bool(true);
        let spec = match mode {
            EncoderMode::LowLatency => {
                Some(dict(&[(unsafe { kVTVideoEncoderSpecification_EnableLowLatencyRateControl }, &yes)]))
            }
            EncoderMode::Standard | EncoderMode::PreScaled => None,
            #[cfg(target_os = "macos")]
            EncoderMode::Software => {
                let id = NSString::from_str("com.apple.videotoolbox.videoencoder.h264");
                Some(dict(&[(unsafe { kVTVideoEncoderSpecification_EncoderID }, &id)]))
            }
            // iPhones and iPads have no software H.264 encoder
            #[cfg(not(target_os = "macos"))]
            EncoderMode::Software => return None,
        };
        let mut raw: VTSessionRef = null_mut();
        let rc = unsafe {
            VTCompressionSessionCreate(
                null(),
                width as i32,
                height as i32,
                kCMVideoCodecType_H264,
                spec.as_deref().map(cf).unwrap_or(null()),
                null(),
                null(),
                on_encoded,
                out as *mut c_void,
                &mut raw,
            )
        };
        if rc != 0 || raw.is_null() {
            if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
                eprintln!("[video] no {mode:?} H.264 session for {width}x{height} ({rc})");
            }
            return None;
        }
        let mut session = Session { raw, hardware: None };
        unsafe {
            let set = |k: CFStringRef, v: CFTypeRef| VTSessionSetProperty(raw, k, v);
            set(kVTCompressionPropertyKey_RealTime, cf_bool(true));
            set(kVTCompressionPropertyKey_AllowFrameReordering, cf_bool(false));
            if mode != EncoderMode::LowLatency {
                // (low-latency mode picks its own profile)
                set(kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_High_AutoLevel);
            }
            // Keyframes when asked for (loss, a new viewer), plus one every
            // 10 s as a backstop.
            set(kVTCompressionPropertyKey_MaxKeyFrameInterval, cf(&*int(fps as i64 * 10)));
            set(kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, cf(&*num(10.0)));
            set(kVTCompressionPropertyKey_ExpectedFrameRate, cf(&*int(fps as i64)));
            #[cfg(target_os = "macos")]
            {
                let mut hw: CFTypeRef = null();
                let rc = VTSessionCopyProperty(
                    raw,
                    kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
                    null(),
                    &mut hw,
                );
                if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
                    eprintln!(
                        "[video] {mode:?} hardware query: rc {rc} value {}",
                        if hw.is_null() {
                            "none"
                        } else if hw == kCFBooleanTrue {
                            "true"
                        } else {
                            "false"
                        }
                    );
                }
                if rc == 0 && !hw.is_null() {
                    session.hardware = Some(hw == kCFBooleanTrue);
                    CFRelease(hw);
                }
            }
            #[cfg(target_os = "ios")]
            {
                session.hardware = Some(true);
            }
            VTCompressionSessionPrepareToEncodeFrames(raw);
        }
        Some(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            VTCompressionSessionCompleteFrames(self.raw, CMTime::INVALID);
            VTCompressionSessionInvalidate(self.raw);
            CFRelease(self.raw as CFTypeRef);
        }
    }
}

/// A real-time H.264 encoder for one output size. Input pictures of any
/// size are scaled, by VideoToolbox or (in the later modes) beforehand.
///
/// A session that stops answering, as the low-latency encoder of a virtual
/// Mac did at 160x90, is replaced by the next [`EncoderMode`]; when none is
/// left, `encode` fails, so the track sees an error instead of a camera that
/// silently sends nothing.
pub struct H264Encoder {
    session: Option<Session>,
    scaler: Option<Scaler>,
    out: *mut EncOut,
    rx: mpsc::Receiver<Result<Option<Encoded>>>,
    width: u32,
    height: u32,
    fps: u32,
    bitrate: u32,
    mode: EncoderMode,
    /// Frames the encoder's rate control dropped.
    pub dropped: u32,
    /// Frames VideoToolbox didn't return in time (neither encoded nor
    /// dropped): a late one would be mistaken for the next frame's, so the
    /// session is flushed before the next frame goes in.
    pub timed_out: u32,
    /// Sessions given up for the next mode.
    pub fallbacks: u32,
    /// A frame timed out: drain the session before encoding another.
    stale: bool,
    /// Frames produced by the current session.
    made: u32,
    /// Consecutive frames without output, and how many of them timed out.
    silent: u32,
    silent_timeouts: u32,
    /// Modes that act as if VideoToolbox never answered, or dropped every
    /// frame, for tests.
    #[cfg(test)]
    unanswering: Vec<EncoderMode>,
    #[cfg(test)]
    dropping: Vec<EncoderMode>,
}

// SAFETY: a VTCompressionSession may be used from any one thread at a time.
unsafe impl Send for H264Encoder {}

impl H264Encoder {
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<H264Encoder> {
        let (tx, rx) = mpsc::channel();
        let out = Box::into_raw(Box::new(tx));
        let mut enc = H264Encoder {
            session: None,
            scaler: None,
            out,
            rx,
            width,
            height,
            fps,
            bitrate,
            mode: EncoderMode::LowLatency,
            dropped: 0,
            timed_out: 0,
            fallbacks: 0,
            stale: false,
            made: 0,
            silent: 0,
            silent_timeouts: 0,
            #[cfg(test)]
            unanswering: Vec::new(),
            #[cfg(test)]
            dropping: Vec::new(),
        };
        let first = if std::env::var_os("MYCEL_VIDEO_NO_LOW_LATENCY").is_some() {
            EncoderMode::Standard
        } else {
            EncoderMode::LowLatency
        };
        let modes = EncoderMode::ALL.into_iter().skip_while(|m| *m != first);
        // skip what already failed at this size, unless nothing else is left
        let mut modes: Vec<EncoderMode> = modes.collect();
        if modes.iter().any(|m| !unanswered(*m, width, height)) {
            modes.retain(|m| !unanswered(*m, width, height));
        }
        if !modes.into_iter().any(|m| enc.open(m).is_ok()) {
            bail!("couldn't create an H.264 encoder for {width}x{height}");
        }
        Ok(enc)
    }

    /// Replace the session with one in `mode`. If that fails, the old one
    /// stays.
    fn open(&mut self, mode: EncoderMode) -> Result<()> {
        let session =
            Session::open(mode, self.width, self.height, self.fps, self.out).context("no session in that mode")?;
        // dropping the old session flushes it into `rx`: drained here
        self.session = Some(session);
        while self.rx.try_recv().is_ok() {}
        self.stale = false;
        self.scaler = mode.prescales().then(|| Scaler::new(self.width, self.height));
        self.mode = mode;
        self.made = 0;
        self.silent = 0;
        self.silent_timeouts = 0;
        let bitrate = self.bitrate;
        self.set_bitrate(bitrate);
        Ok(())
    }

    fn raw(&self) -> VTSessionRef {
        self.session.as_ref().expect("an open session").raw
    }

    /// Only a source that encodes itself (`web`) can change size in place;
    /// the track re-creates this encoder instead.
    pub fn retarget(&mut self, _width: u32, _height: u32, _fps: u32) {}

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn mode(&self) -> EncoderMode {
        self.mode
    }

    /// For stats: "H.264 hardware", "H.264 software", "H.264 low-latency",
    /// with " (scaled first)" in the pre-scaling modes.
    pub fn describe(&self) -> String {
        let hardware = self.session.as_ref().and_then(|s| s.hardware);
        let base = match (hardware, self.mode) {
            (Some(true), _) => "H.264 hardware",
            (Some(false), _) | (None, EncoderMode::Software) => "H.264 software",
            (None, EncoderMode::LowLatency) => "H.264 low-latency",
            (None, _) => "H.264",
        };
        if self.mode.prescales() { format!("{base} (scaled first)") } else { base.into() }
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        self.bitrate = bps;
        let raw = self.raw();
        unsafe {
            VTSessionSetProperty(raw, kVTCompressionPropertyKey_AverageBitRate, cf(&*int(bps as i64)));
            // A hard cap of 1.5× over each second keeps keyframes from
            // flooding the path.
            let bytes = int((bps as f64 * 1.5 / 8.0) as i64);
            let secs = num(1.0);
            let limits = NSArray::<AnyObject>::from_slice(&[&**bytes as &AnyObject, &**secs as &AnyObject]);
            if std::env::var_os("MYCEL_VIDEO_NO_LIMIT").is_none() {
                VTSessionSetProperty(raw, kVTCompressionPropertyKey_DataRateLimits, cf(&*limits));
            }
        }
    }

    /// Encode one picture (`pts` in µs). Returns the frame, or `None` if the
    /// encoder chose to drop it or didn't answer in time. `seq` and
    /// `capture_us` are left for the caller.
    pub fn encode(&mut self, pb: &PixelBuffer, pts_us: i64, force_key: bool) -> Result<Option<EncodedFrame>> {
        let out = self.encode_once(pb, pts_us, force_key)?;
        if out.is_some() {
            self.made += 1;
            self.silent = 0;
            self.silent_timeouts = 0;
        } else {
            self.silent += 1;
            let never_started = self.made == 0 && self.silent >= STALL_TIMEOUTS;
            if never_started || self.silent_timeouts >= STALL_TIMEOUTS || self.silent >= STALL_FRAMES {
                self.fall_back()?;
            }
        }
        Ok(out)
    }

    /// The session has gone quiet: move to the next mode, or fail.
    fn fall_back(&mut self) -> Result<()> {
        let (mode, w, h) = (self.mode, self.width, self.height);
        let why = format!(
            "{mode:?} H.264 encoder at {w}x{h} returned nothing for {} frames ({} not answered, {} made before)",
            self.silent, self.silent_timeouts, self.made
        );
        if self.made == 0
            && let Ok(mut v) = UNANSWERED.lock()
            && !v.contains(&(mode, w, h))
        {
            v.push((mode, w, h));
        }
        let mut next = mode.next();
        while let Some(m) = next {
            if self.open(m).is_ok() {
                self.fallbacks += 1;
                eprintln!("[video] {why}; now {m:?}");
                return Ok(());
            }
            next = m.next();
        }
        // keep the last session for drop; the caller starts over
        bail!("{why}; no other encoder mode left")
    }

    fn encode_once(&mut self, pb: &PixelBuffer, pts_us: i64, force_key: bool) -> Result<Option<EncodedFrame>> {
        let raw = self.raw();
        if self.stale {
            // whatever the last frame turns out to be, it isn't this one's
            unsafe { VTCompressionSessionCompleteFrames(raw, CMTime::INVALID) };
            while self.rx.try_recv().is_ok() {}
            self.stale = false;
        }
        #[cfg(test)]
        if self.unanswering.contains(&self.mode) {
            self.timed_out += 1;
            self.silent_timeouts += 1;
            return Ok(None);
        }
        #[cfg(test)]
        if self.dropping.contains(&self.mode) {
            self.dropped += 1;
            return Ok(None);
        }
        let scaled = match &mut self.scaler {
            Some(s) => Some(s.scale(pb)?),
            None => None,
        };
        let input = scaled.as_ref().unwrap_or(pb);
        let yes = NSNumber::new_bool(true);
        let props = force_key.then(|| dict(&[(unsafe { kVTEncodeFrameOptionKey_ForceKeyFrame }, &yes)]));
        let mut info = 0u32;
        let rc = unsafe {
            VTCompressionSessionEncodeFrame(
                raw,
                input.raw(),
                CMTime::micros(pts_us),
                CMTime::INVALID,
                props.as_deref().map(cf).unwrap_or(null()),
                null_mut(),
                &mut info,
            )
        };
        ensure!(rc == 0, "H.264 encode failed ({rc}, info {info:#x})");
        if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!("[video] encode info flags {info:#x}");
        }
        // real time, no reordering: the frame is out as soon as it's encoded
        unsafe { VTCompressionSessionCompleteFrames(raw, CMTime::INVALID) };
        match self.rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(r) => {
                let Some(e) = r? else {
                    self.dropped += 1;
                    return Ok(None);
                };
                Ok(Some(EncodedFrame {
                    seq: 0,
                    capture_us: 0,
                    keyframe: e.keyframe,
                    width: self.width as u16,
                    height: self.height as u16,
                    config: e.config,
                    data: e.data,
                }))
            }
            Err(_) => {
                eprintln!(
                    "[video] {:?} H.264 encoder at {}x{}: no answer in 200 ms (info {info:#x})",
                    self.mode, self.width, self.height
                );
                self.timed_out += 1;
                self.silent_timeouts += 1;
                self.stale = true;
                Ok(None)
            }
        }
    }
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        // the session goes first: its callback holds `out`
        self.session = None;
        self.scaler = None;
        unsafe { drop(Box::from_raw(self.out)) };
    }
}

// ─────────────────────────────── decoder ───────────────────────────────

type DecOut = mpsc::Sender<Result<PixelBuffer>>;

unsafe extern "C-unwind" fn on_decoded(
    refcon: *mut c_void,
    _src: *mut c_void,
    status: OSStatus,
    _flags: u32,
    image: CVPixelBufferRef,
    _pts: CMTime,
    _dur: CMTime,
) {
    // SAFETY: refcon is the session's boxed sender, alive until after invalidate.
    let tx = unsafe { &*(refcon as *const DecOut) };
    if status != 0 || image.is_null() {
        let _ = tx.send(Err(anyhow::anyhow!("H.264 decode error {status}")));
        return;
    }
    let _ = tx.send(Ok(unsafe { PixelBuffer::retain(image) }));
}

/// Decodes the frames an [`H264Encoder`] makes (configured by the `avcC` on
/// keyframes; re-created when it changes).
pub struct H264Decoder {
    session: VTSessionRef,
    format: CMFormatDescriptionRef,
    config: Option<Bytes>,
    out: *mut DecOut,
    rx: mpsc::Receiver<Result<PixelBuffer>>,
}

unsafe impl Send for H264Decoder {}

impl Default for H264Decoder {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        H264Decoder { session: null_mut(), format: null_mut(), config: None, out: Box::into_raw(Box::new(tx)), rx }
    }
}

impl H264Decoder {
    fn configure(&mut self, avcc: &Bytes) -> Result<()> {
        self.teardown();
        let (sps, pps) = avcc_parameter_sets(avcc)?;
        let ptrs = [sps.as_ptr(), pps.as_ptr()];
        let sizes = [sps.len(), pps.len()];
        let mut fmt: CMFormatDescriptionRef = null_mut();
        let rc = unsafe {
            CMVideoFormatDescriptionCreateFromH264ParameterSets(null(), 2, ptrs.as_ptr(), sizes.as_ptr(), 4, &mut fmt)
        };
        ensure!(rc == 0 && !fmt.is_null(), "bad H.264 parameter sets ({rc})");
        let pf = int(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange as i64);
        let attrs = dict(&[(unsafe { kCVPixelBufferPixelFormatTypeKey }, &pf)]);
        let record = VTDecompressionOutputCallbackRecord { callback: on_decoded, refcon: self.out as *mut c_void };
        let mut session: VTSessionRef = null_mut();
        let rc = unsafe { VTDecompressionSessionCreate(null(), fmt, null(), cf(&*attrs), &record, &mut session) };
        if rc != 0 || session.is_null() {
            unsafe { CFRelease(fmt as CFTypeRef) };
            bail!("couldn't create an H.264 decoder ({rc})");
        }
        unsafe { VTSessionSetProperty(session, kVTDecompressionPropertyKey_RealTime, cf_bool(true)) };
        self.session = session;
        self.format = fmt;
        self.config = Some(avcc.clone());
        Ok(())
    }

    fn teardown(&mut self) {
        unsafe {
            if !self.session.is_null() {
                VTDecompressionSessionWaitForAsynchronousFrames(self.session);
                VTDecompressionSessionInvalidate(self.session);
                CFRelease(self.session as CFTypeRef);
                self.session = null_mut();
            }
            if !self.format.is_null() {
                CFRelease(self.format as CFTypeRef);
                self.format = null_mut();
            }
        }
    }

    /// Decode one frame (they must come in order, from a keyframe on).
    pub fn decode(&mut self, f: &EncodedFrame) -> Result<PixelBuffer> {
        if let Some(c) = &f.config
            && self.config.as_ref() != Some(c)
        {
            self.configure(c)?;
        }
        ensure!(!self.session.is_null(), "no keyframe yet");
        unsafe {
            let len = f.data.len();
            let mut bb: CMBlockBufferRef = null_mut();
            let rc = CMBlockBufferCreateWithMemoryBlock(
                null(),
                null_mut(),
                len,
                null(),
                null(),
                0,
                len,
                kCMBlockBufferAssureMemoryNowFlag,
                &mut bb,
            );
            ensure!(rc == 0, "CMBlockBufferCreate failed ({rc})");
            CMBlockBufferReplaceDataBytes(f.data.as_ptr() as *const c_void, bb, 0, len);
            let mut sb: CMSampleBufferRef = null_mut();
            let sizes = [len];
            let rc = CMSampleBufferCreateReady(null(), bb, self.format, 1, 0, null(), 1, sizes.as_ptr(), &mut sb);
            CFRelease(bb as CFTypeRef);
            ensure!(rc == 0, "CMSampleBufferCreate failed ({rc})");
            let mut info = 0u32;
            let rc = VTDecompressionSessionDecodeFrame(self.session, sb, 0, null_mut(), &mut info);
            VTDecompressionSessionWaitForAsynchronousFrames(self.session);
            CFRelease(sb as CFTypeRef);
            ensure!(rc == 0, "H.264 decode failed ({rc})");
        }
        self.rx.try_recv().context("the decoder produced no picture")?
    }
}

impl Drop for H264Decoder {
    fn drop(&mut self) {
        self.teardown();
        unsafe { drop(Box::from_raw(self.out)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{draw, read_counter};

    /// Encode `frames` pictures of the test pattern (always 720p: the
    /// encoder scales it) and decode them again, reading the counters back.
    /// The encoder may drop a picture to hold its bitrate (after a big
    /// keyframe); every frame it does produce must decode to the right one,
    /// and each session's first frame, like a forced one, is a keyframe.
    /// Returns (frames made, keyframe bytes, all bytes).
    fn round_trip(enc: &mut H264Encoder, frames: u32) -> (usize, usize, usize) {
        let (w, h) = enc.size();
        let mut dec = H264Decoder::default();
        let (mut bytes, mut made, mut key_bytes) = (0, 0usize, 0);
        let (mut sessions, mut first) = (enc.fallbacks, true);
        for n in 0..frames {
            let pb = PixelBuffer::from_nv12(&draw(n, 1280, 720)).unwrap();
            let out = enc.encode(&pb, n as i64 * 33_333, n == 30).unwrap();
            if enc.fallbacks != sessions {
                (sessions, first) = (enc.fallbacks, true);
            }
            let Some(f) = out else { continue };
            if first || n == 30 {
                assert!(f.keyframe, "{w}x{h} frame {n} is a keyframe");
                key_bytes += f.data.len();
            } else {
                assert!(!f.keyframe, "{w}x{h} frame {n}");
            }
            first = false;
            assert_eq!(f.config.is_some(), f.keyframe);
            bytes += f.data.len();
            made += 1;
            let pic = dec.decode(&f).unwrap();
            assert_eq!(pic.size(), (w, h));
            let (lw, lh, luma) = pic.luma().unwrap();
            assert_eq!(read_counter(&luma, lw, lh, lw), Some(n), "{w}x{h} frame {n}");
        }
        assert_eq!(made + enc.dropped as usize + enc.timed_out as usize, frames as usize, "one answer per frame");
        (made, key_bytes, bytes)
    }

    #[test]
    fn encode_decode_round_trip_with_scaling() {
        for (w, h, bps) in [(1280, 720, 2_500_000), (424, 240, 250_000), (160, 90, 60_000)] {
            let mut enc = H264Encoder::new(w, h, 30, bps).unwrap();
            let t0 = std::time::Instant::now();
            let (made, key_bytes, bytes) = round_trip(&mut enc, 60);
            let per = t0.elapsed() / 60;
            eprintln!(
                "{w}x{h} @ {bps}: {} made {made}/60 (dropped {}, timed out {}, fallbacks {}), keyframes ~{} B, \
                 deltas ~{} B, {:.1} kbit/s at 30 fps, {per:?}/frame encode+decode",
                enc.describe(),
                enc.dropped,
                enc.timed_out,
                enc.fallbacks,
                key_bytes / 2,
                (bytes - key_bytes) / made.saturating_sub(2).max(1),
                bytes as f64 * 8.0 / 2.0 / 1000.0,
            );
            assert!(made >= 50, "{w}x{h}: made {made} of 60, dropped {}, timed out {}", enc.dropped, enc.timed_out);
        }
    }

    /// A session that never answers (what the low-latency encoder of the
    /// macOS CI runner's virtual Mac did at 160x90) is replaced after
    /// STALL_TIMEOUTS frames, and a new encoder of that size skips the mode.
    #[test]
    fn a_session_that_never_answers_is_replaced() {
        let mut enc = H264Encoder::new(192, 108, 30, 60_000).unwrap();
        assert_eq!(enc.mode(), EncoderMode::LowLatency);
        enc.unanswering = vec![EncoderMode::LowLatency];
        let (made, _, _) = round_trip(&mut enc, 60);
        assert_eq!((enc.mode(), enc.fallbacks, enc.timed_out), (EncoderMode::Standard, 1, STALL_TIMEOUTS));
        assert!(made >= 50, "made {made} of 60 ({} dropped)", enc.dropped);
        assert_eq!(H264Encoder::new(192, 108, 30, 60_000).unwrap().mode(), EncoderMode::Standard);
    }

    /// Further down: pictures scaled before the encoder sees them, then
    /// (on a Mac) the software encoder.
    #[test]
    fn falls_back_to_scaling_first_then_software() {
        let mut enc = H264Encoder::new(256, 144, 30, 100_000).unwrap();
        enc.unanswering = vec![EncoderMode::LowLatency, EncoderMode::Standard];
        let (made, _, _) = round_trip(&mut enc, 60);
        assert_eq!((enc.mode(), enc.fallbacks), (EncoderMode::PreScaled, 2));
        assert!(enc.describe().ends_with("(scaled first)"), "{}", enc.describe());
        assert!(made >= 50, "made {made} of 60 ({} dropped)", enc.dropped);

        #[cfg(target_os = "macos")]
        {
            let mut enc = H264Encoder::new(256, 144, 30, 100_000).unwrap();
            assert_eq!(enc.mode(), EncoderMode::PreScaled, "the modes that never answered are skipped");
            enc.unanswering = vec![EncoderMode::PreScaled];
            let (made, _, _) = round_trip(&mut enc, 60);
            assert_eq!(enc.mode(), EncoderMode::Software);
            assert_eq!(enc.describe(), "H.264 software (scaled first)");
            assert!(made >= 50, "made {made} of 60 ({} dropped)", enc.dropped);
        }
    }

    /// Drops count too: a new session that drops its first STALL_TIMEOUTS
    /// pictures is replaced, and one that worked is replaced after a second
    /// (STALL_FRAMES) of nothing but drops, not sooner.
    #[test]
    fn a_session_that_only_drops_is_replaced() {
        let pb = PixelBuffer::from_nv12(&draw(0, 1280, 720)).unwrap();
        let mut enc = H264Encoder::new(224, 126, 30, 60_000).unwrap();
        enc.dropping = vec![EncoderMode::LowLatency];
        for n in 0..STALL_TIMEOUTS {
            assert_eq!(enc.mode(), EncoderMode::LowLatency, "frame {n}");
            assert!(enc.encode(&pb, i64::from(n) * 33_333, false).unwrap().is_none());
        }
        assert_eq!((enc.mode(), enc.dropped), (EncoderMode::Standard, STALL_TIMEOUTS));

        let mut enc = H264Encoder::new(288, 162, 30, 100_000).unwrap();
        let (made, _, _) = round_trip(&mut enc, 10);
        assert!(made > 0);
        enc.dropping = vec![EncoderMode::LowLatency];
        for n in 0..STALL_FRAMES {
            assert_eq!(enc.mode(), EncoderMode::LowLatency, "after {n} drops");
            assert!(enc.encode(&pb, i64::from(10 + n) * 33_333, false).unwrap().is_none());
        }
        assert_eq!(enc.mode(), EncoderMode::Standard);
        // it made frames, so a new encoder of that size still starts low-latency
        assert_eq!(H264Encoder::new(288, 162, 30, 100_000).unwrap().mode(), EncoderMode::LowLatency);
    }

    /// Pictures scaled on the CPU (when the pixel transfer fails, as it may
    /// without a hardware scaler) encode and decode to the right frames,
    /// 8x down to the smallest size.
    #[test]
    fn cpu_scaled_pictures_round_trip() {
        let mut enc = H264Encoder::new(160, 90, 30, 60_000).unwrap();
        enc.open(EncoderMode::PreScaled).unwrap();
        enc.scaler.as_mut().unwrap().cpu_only();
        let (made, _, _) = round_trip(&mut enc, 60);
        assert!(made >= 50, "made {made} of 60 ({} dropped)", enc.dropped);
        assert!(enc.scaler.as_ref().unwrap().transfer.is_none());
    }

    #[test]
    fn box_scale_averages_what_each_sample_covers() {
        // 4x2 → 2x1, one channel: the mean of each 2x2 block
        let src = [0, 2, 10, 20, 4, 6, 30, 40];
        let mut dst = [0u8; 2];
        box_scale(&src, (4, 2, 4), &mut dst, (2, 1, 2), 1);
        assert_eq!(dst, [3, 25]);
        // two interleaved channels, rows padded to a stride of 6 bytes
        let src = [1, 100, 3, 200, 9, 9, 5, 100, 7, 200, 9, 9];
        let mut dst = [0u8; 2];
        box_scale(&src, (2, 2, 6), &mut dst, (1, 1, 2), 2);
        assert_eq!(dst, [4, 150]);
        // 3 → 2: every source sample counts, none twice
        let mut dst = [0u8; 2];
        box_scale(&[0, 90, 200], (3, 1, 3), &mut dst, (2, 1, 2), 1);
        assert_eq!(dst, [0, 145]);
        // scaling up repeats the nearest sample
        let mut dst = [0u8; 4];
        box_scale(&[10, 20], (2, 1, 2), &mut dst, (4, 1, 4), 1);
        assert_eq!(dst, [10, 10, 20, 20]);
    }

    /// With no mode left, `encode` fails instead of returning nothing forever.
    #[test]
    fn an_encoder_with_no_mode_left_fails() {
        let mut enc = H264Encoder::new(320, 180, 30, 150_000).unwrap();
        enc.unanswering = EncoderMode::ALL.to_vec();
        let pb = PixelBuffer::from_nv12(&draw(0, 1280, 720)).unwrap();
        let err =
            (0..20).find_map(|n| enc.encode(&pb, n * 33_333, false).err()).expect("fails once every mode stalled");
        assert!(err.to_string().contains("no other encoder mode left"), "{err:#}");
        assert_eq!(enc.timed_out, STALL_TIMEOUTS * enc.fallbacks + STALL_TIMEOUTS);
    }

    #[test]
    fn portrait_and_four_three_camera_frames_keep_their_shape() {
        for (source_w, source_h, w, h) in [(720, 1280, 288, 512), (1280, 960, 240, 180), (960, 1280, 192, 256)] {
            let mut enc = H264Encoder::new(w, h, 30, 350_000).unwrap();
            let mut dec = H264Decoder::default();
            let mut source = draw(0, source_w, source_h);
            source.y.fill(16);
            source.uv.fill(128);
            let radius = i64::from(source_w.min(source_h) / 6);
            for y in 0..source_h {
                for x in 0..source_w {
                    let dx = i64::from(x) - i64::from(source_w / 2);
                    let dy = i64::from(y) - i64::from(source_h / 2);
                    if dx * dx + dy * dy <= radius * radius {
                        source.y[(y * source_w + x) as usize] = 235;
                    }
                }
            }
            let pb = PixelBuffer::from_nv12(&source).unwrap();
            let f = enc.encode(&pb, 0, true).unwrap().expect("first frame");
            assert_eq!((u32::from(f.width), u32::from(f.height)), (w, h));
            let pic = dec.decode(&f).unwrap();
            assert_eq!(pic.size(), (w, h));
            let (lw, lh, luma) = pic.luma().unwrap();
            let horizontal = (0..lw).filter(|x| luma[(lh / 2) * lw + x] > 180).count();
            let vertical = (0..lh).filter(|y| luma[y * lw + lw / 2] > 180).count();
            assert!(horizontal > 20 && vertical > 20, "circle survives compression");
            assert!(
                horizontal.abs_diff(vertical) <= 4,
                "{source_w}x{source_h} => {w}x{h}: circle is {horizontal}x{vertical}"
            );
            assert_eq!(source_w * h, source_h * w);
        }
    }
}
