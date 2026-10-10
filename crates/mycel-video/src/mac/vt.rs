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
                p.width as usize,
                p.height as usize,
                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                cf(&*attrs),
                &mut pb,
            )
        };
        ensure!(rc == 0 && !pb.is_null(), "CVPixelBufferCreate failed ({rc})");
        let pb = PixelBuffer(pb);
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

    /// The luma plane, tightly packed: (width, height, bytes). NV12 only.
    pub fn luma(&self) -> Result<(usize, usize, Vec<u8>)> {
        unsafe {
            let fmt = CVPixelBufferGetPixelFormatType(self.0);
            ensure!(fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange || fmt == u32::from_be_bytes(*b"420f"), "not NV12");
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

type EncOut = mpsc::Sender<Result<Encoded>>;

unsafe extern "C-unwind" fn on_encoded(refcon: *mut c_void, _src: *mut c_void, status: OSStatus, flags: u32, sb: CMSampleBufferRef) {
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
        return; // dropped by the encoder's rate control: nothing to send
    }
    let _ = tx.send(unsafe { read_sample(sb) });
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
                let rc = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(desc, i, &mut p, &mut n, &mut count, &mut hl);
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

/// A real-time H.264 encoder session for one output size. Input pictures of
/// any size are scaled by VideoToolbox.
pub struct H264Encoder {
    session: VTSessionRef,
    out: *mut EncOut,
    rx: mpsc::Receiver<Result<Encoded>>,
    width: u32,
    height: u32,
    /// `None`: VideoToolbox doesn't say (low-latency mode).
    pub hardware: Option<bool>,
    pub low_latency: bool,
}

// SAFETY: a VTCompressionSession may be used from any one thread at a time.
unsafe impl Send for H264Encoder {}

impl H264Encoder {
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<H264Encoder> {
        let (tx, rx) = mpsc::channel();
        let out = Box::into_raw(Box::new(tx));
        // Low-latency rate control (macOS 11.3+): no frame buffering in the
        // encoder, steadier frame sizes. Fall back if it isn't available.
        let yes = NSNumber::new_bool(true);
        let low = dict(&[(unsafe { kVTVideoEncoderSpecification_EnableLowLatencyRateControl }, &yes)]);
        let mut session: VTSessionRef = null_mut();
        let mut low_latency = false;
        let specs = if std::env::var_os("MYCEL_VIDEO_NO_LOW_LATENCY").is_some() { vec![null()] } else { vec![cf(&*low), null()] };
        for spec in specs {
            session = null_mut();
            let rc = unsafe {
                VTCompressionSessionCreate(
                    null(),
                    width as i32,
                    height as i32,
                    kCMVideoCodecType_H264,
                    spec,
                    null(),
                    null(),
                    on_encoded,
                    out as *mut c_void,
                    &mut session,
                )
            };
            if rc == 0 && !session.is_null() {
                low_latency = !spec.is_null();
                break;
            }
        }
        if session.is_null() {
            drop(unsafe { Box::from_raw(out) });
            bail!("couldn't create an H.264 encoder for {width}x{height}");
        }
        let mut enc = H264Encoder { session, out, rx, width, height, hardware: None, low_latency };
        unsafe {
            let set = |k: CFStringRef, v: CFTypeRef| VTSessionSetProperty(session, k, v);
            set(kVTCompressionPropertyKey_RealTime, cf_bool(true));
            set(kVTCompressionPropertyKey_AllowFrameReordering, cf_bool(false));
            if !low_latency {
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
                let rc = VTSessionCopyProperty(session, kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder, null(), &mut hw);
                if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
                    eprintln!("[video] hardware query: rc {rc} value {}", if hw.is_null() { "none" } else if hw == kCFBooleanTrue { "true" } else { "false" });
                }
                if rc == 0 && !hw.is_null() {
                    enc.hardware = Some(hw == kCFBooleanTrue);
                    CFRelease(hw);
                }
            }
            #[cfg(target_os = "ios")]
            {
                enc.hardware = Some(true);
            }
            VTCompressionSessionPrepareToEncodeFrames(session);
        }
        enc.set_bitrate(bitrate);
        Ok(enc)
    }

    /// Only a source that encodes itself (`web`) can change size in place;
    /// the track re-creates this encoder instead.
    pub fn retarget(&mut self, _width: u32, _height: u32, _fps: u32) {}

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// For stats: "H.264 hardware", "H.264 software", "H.264 low-latency".
    pub fn describe(&self) -> String {
        match (self.hardware, self.low_latency) {
            (Some(true), _) => "H.264 hardware".into(),
            (Some(false), _) => "H.264 software".into(),
            (None, true) => "H.264 low-latency".into(),
            (None, false) => "H.264".into(),
        }
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        unsafe {
            VTSessionSetProperty(self.session, kVTCompressionPropertyKey_AverageBitRate, cf(&*int(bps as i64)));
            // A hard cap of 1.5× over each second keeps keyframes from
            // flooding the path.
            let bytes = int((bps as f64 * 1.5 / 8.0) as i64);
            let secs = num(1.0);
            let limits = NSArray::<AnyObject>::from_slice(&[&**bytes as &AnyObject, &**secs as &AnyObject]);
            if std::env::var_os("MYCEL_VIDEO_NO_LIMIT").is_none() {
                VTSessionSetProperty(self.session, kVTCompressionPropertyKey_DataRateLimits, cf(&*limits));
            }
        }
    }

    /// Encode one picture (`pts` in µs). Returns the frame, or `None` if the
    /// encoder chose to drop it. `seq` and `capture_us` are left for the caller.
    pub fn encode(&mut self, pb: &PixelBuffer, pts_us: i64, force_key: bool) -> Result<Option<EncodedFrame>> {
        let yes = NSNumber::new_bool(true);
        let props = force_key.then(|| dict(&[(unsafe { kVTEncodeFrameOptionKey_ForceKeyFrame }, &yes)]));
        let mut info = 0u32;
        let rc = unsafe {
            VTCompressionSessionEncodeFrame(
                self.session,
                pb.raw(),
                CMTime::micros(pts_us),
                CMTime::INVALID,
                props.as_deref().map(cf).unwrap_or(null()),
                null_mut(),
                &mut info,
            )
        };
        ensure!(rc == 0, "H.264 encode failed ({rc})");
        if std::env::var_os("MYCEL_VIDEO_DEBUG").is_some() {
            eprintln!("[video] encode info flags {info:#x}");
        }
        // real time, no reordering: the frame is out as soon as it's encoded
        unsafe { VTCompressionSessionCompleteFrames(self.session, CMTime::INVALID) };
        match self.rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(r) => {
                let e = r?;
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
            Err(_) => Ok(None),
        }
    }
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        unsafe {
            VTCompressionSessionCompleteFrames(self.session, CMTime::INVALID);
            VTCompressionSessionInvalidate(self.session);
            CFRelease(self.session as CFTypeRef);
            drop(Box::from_raw(self.out));
        }
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
        let rc = unsafe { CMVideoFormatDescriptionCreateFromH264ParameterSets(null(), 2, ptrs.as_ptr(), sizes.as_ptr(), 4, &mut fmt) };
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

    /// Encode the test pattern, decode it again, and read the counters back.
    /// The encoder may drop a picture to hold its bitrate (after a big
    /// keyframe); every frame it does produce must decode to the right one.
    #[test]
    fn encode_decode_round_trip_with_scaling() {
        for (w, h, bps) in [(1280, 720, 2_500_000), (424, 240, 250_000), (160, 90, 60_000)] {
            let mut enc = H264Encoder::new(w, h, 30, bps).unwrap();
            let mut dec = H264Decoder::default();
            let (mut bytes, mut made, mut key_bytes) = (0, 0, 0);
            let t0 = std::time::Instant::now();
            for n in 0..60u32 {
                // the source is always 720p; the encoder scales it
                let pb = PixelBuffer::from_nv12(&draw(n, 1280, 720)).unwrap();
                let Some(f) = enc.encode(&pb, n as i64 * 33_333, n == 30).unwrap() else { continue };
                if n == 0 || n == 30 {
                    assert!(f.keyframe, "frame {n} is a keyframe");
                    key_bytes += f.data.len();
                } else {
                    assert!(!f.keyframe, "frame {n}");
                }
                assert_eq!(f.config.is_some(), f.keyframe);
                bytes += f.data.len();
                made += 1;
                let pic = dec.decode(&f).unwrap();
                assert_eq!(pic.size(), (w, h));
                let (lw, lh, luma) = pic.luma().unwrap();
                assert_eq!(read_counter(&luma, lw, lh, lw), Some(n), "{w}x{h} frame {n}");
            }
            let per = t0.elapsed() / 60;
            eprintln!(
                "{w}x{h} @ {bps}: {} made {made}/60, keyframes ~{} B, deltas ~{} B, {:.1} kbit/s at 30 fps, {per:?}/frame encode+decode",
                enc.describe(),
                key_bytes / 2,
                (bytes - key_bytes) / (made - 2).max(1),
                bytes as f64 * 8.0 / 2.0 / 1000.0,
            );
            assert!(made >= 50, "the encoder dropped {} of 60", 60 - made);
        }
    }
}
