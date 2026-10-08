//! The camera, through AVFoundation, and the camera permission.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Bool, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, define_class, msg_send};
use objc2_av_foundation::{
    AVCaptureConnection, AVCaptureDevice, AVCaptureDeviceInput, AVCaptureOutput, AVCaptureSession,
    AVCaptureSessionPreset1280x720, AVCaptureVideoDataOutput, AVCaptureVideoDataOutputSampleBufferDelegate,
    AVMediaTypeVideo,
};
use objc2_core_media::CMSampleBuffer;
use objc2_foundation::{NSDictionary, NSNumber, NSString};

use super::ffi::*;
use super::vt::PixelBuffer;
use crate::source::{Picture, PictureSink, SourceHandle, VideoSource, wall_us};

pub const CAMERA_DENIED: &str =
    "Mycel isn't allowed to use the camera. Allow it in System Settings > Privacy & Security > Camera, then turn the camera on again.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CameraPermission {
    NotDetermined,
    Restricted,
    Denied,
    Authorized,
}

fn media_video() -> &'static NSString {
    // SAFETY: an AVFoundation constant.
    unsafe { AVMediaTypeVideo }.expect("AVMediaTypeVideo")
}

/// What the user decided about camera access (never prompts).
pub fn camera_permission() -> CameraPermission {
    // SAFETY: a class method taking a media type.
    let status = unsafe { AVCaptureDevice::authorizationStatusForMediaType(media_video()) };
    match status.0 {
        0 => CameraPermission::NotDetermined,
        1 => CameraPermission::Restricted,
        2 => CameraPermission::Denied,
        _ => CameraPermission::Authorized,
    }
}

/// Ask once if the user hasn't decided yet (the system shows its prompt
/// with the app's NSCameraUsageDescription). Blocks until they answer.
pub fn ensure_camera_permission() -> Result<()> {
    match camera_permission() {
        CameraPermission::Authorized => Ok(()),
        CameraPermission::Denied | CameraPermission::Restricted => bail!(CAMERA_DENIED),
        CameraPermission::NotDetermined => {
            let (tx, rx) = std::sync::mpsc::channel::<bool>();
            let block = RcBlock::new(move |granted: Bool| {
                let _ = tx.send(granted.as_bool());
            });
            // SAFETY: takes a media type and a `void (^)(BOOL)` block, which it copies.
            unsafe { AVCaptureDevice::requestAccessForMediaType_completionHandler(media_video(), &block) };
            match rx.recv_timeout(Duration::from_secs(120)) {
                Ok(true) => Ok(()),
                Ok(false) => bail!(CAMERA_DENIED),
                Err(_) => bail!("No answer to the camera permission prompt."),
            }
        }
    }
}

pub struct DelegateIvars {
    sink: PictureSink,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "MycelVideoCaptureDelegate"]
    #[ivars = DelegateIvars]
    struct CaptureDelegate;

    unsafe impl NSObjectProtocol for CaptureDelegate {}

    unsafe impl AVCaptureVideoDataOutputSampleBufferDelegate for CaptureDelegate {
        #[unsafe(method(captureOutput:didOutputSampleBuffer:fromConnection:))]
        fn did_output(&self, _output: &AVCaptureOutput, sample: &CMSampleBuffer, _connection: &AVCaptureConnection) {
            let raw = sample as *const CMSampleBuffer as CMSampleBufferRef;
            // SAFETY: a valid sample buffer for the duration of this call.
            let pb = unsafe { CMSampleBufferGetImageBuffer(raw) };
            if pb.is_null() {
                return;
            }
            // SAFETY: a valid CVPixelBuffer; retained for as long as the picture lives.
            let buf = unsafe { PixelBuffer::retain(pb) };
            let (width, height) = buf.size();
            (self.ivars().sink)(Picture { width, height, capture_us: wall_us(), buf });
        }
    }
);

impl CaptureDelegate {
    fn new(sink: PictureSink) -> Retained<Self> {
        let this = Self::alloc().set_ivars(DelegateIvars { sink });
        // SAFETY: NSObject's init.
        unsafe { msg_send![super(this), init] }
    }
}

/// The default camera at 720p (or what it can do), NV12.
pub struct Camera;

struct Running {
    session: Retained<AVCaptureSession>,
    _output: Retained<AVCaptureVideoDataOutput>,
    _delegate: Retained<CaptureDelegate>,
    _queue: dispatch2::DispatchRetained<DispatchQueue>,
}

// SAFETY: AVCaptureSession is documented thread-safe for start/stop; the
// other objects are only kept alive here.
unsafe impl Send for Running {}

impl Drop for Running {
    fn drop(&mut self) {
        // SAFETY: stopRunning may be called from any thread (it blocks).
        unsafe { self.session.stopRunning() };
    }
}

impl VideoSource for Camera {
    fn describe(&self) -> String {
        // SAFETY: a class method taking a media type.
        unsafe { AVCaptureDevice::defaultDeviceWithMediaType(media_video()) }
            .map(|d| unsafe { d.localizedName() }.to_string())
            .unwrap_or_else(|| "No camera".into())
    }

    fn prepare(&self) -> Result<()> {
        ensure_camera_permission()
    }

    fn start(&self, sink: PictureSink) -> Result<SourceHandle> {
        ensure_camera_permission()?;
        // SAFETY: AVFoundation calls with valid arguments; the session is
        // configured before it starts running.
        unsafe {
            let device = AVCaptureDevice::defaultDeviceWithMediaType(media_video()).context("No camera found.")?;
            let input = AVCaptureDeviceInput::deviceInputWithDevice_error(&device)
                .map_err(|e| anyhow!("The camera can't be opened: {}", e.localizedDescription()))?;
            let session = AVCaptureSession::new();
            session.beginConfiguration();
            if session.canSetSessionPreset(AVCaptureSessionPreset1280x720) {
                session.setSessionPreset(AVCaptureSessionPreset1280x720);
            }
            if !session.canAddInput(&input) {
                session.commitConfiguration();
                bail!("The camera is in use by something else.");
            }
            session.addInput(&input);
            let output = AVCaptureVideoDataOutput::new();
            let fmt = NSNumber::new_u32(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange);
            let key = &*(kCVPixelBufferPixelFormatTypeKey as *const NSString);
            let settings = NSDictionary::<NSString, AnyObject>::from_slices(&[key], &[&*fmt as &AnyObject]);
            output.setVideoSettings(Some(&settings));
            output.setAlwaysDiscardsLateVideoFrames(true);
            let delegate = CaptureDelegate::new(sink);
            let queue = DispatchQueue::new("org.mycel.camera", None);
            output.setSampleBufferDelegate_queue(Some(ProtocolObject::from_ref(&*delegate)), Some(&queue));
            if !session.canAddOutput(&output) {
                session.commitConfiguration();
                bail!("The camera's video can't be read.");
            }
            session.addOutput(&output);
            session.commitConfiguration();
            session.startRunning();
            let _ = std::ptr::null::<c_void>();
            Ok(SourceHandle::new(Running { session, _output: output, _delegate: delegate, _queue: queue }))
        }
    }
}

pub fn camera() -> Arc<dyn VideoSource> {
    Arc::new(Camera)
}
