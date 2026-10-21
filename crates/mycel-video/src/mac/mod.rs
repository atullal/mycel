//! Apple (macOS, iOS, iPadOS): AVFoundation camera, VideoToolbox H.264.

pub mod camera;
pub mod ffi;
pub mod vt;

pub use camera::{CAMERA_DENIED, CameraPermission, camera, camera_permission, ensure_camera_permission};
pub use vt::{EncoderMode, H264Decoder, H264Encoder, PixelBuffer};

/// The track paces frames itself (by not encoding pictures it can't send).
pub const SOURCE_PACED: bool = false;
