//! macOS: AVFoundation camera, VideoToolbox H.264.

pub mod camera;
pub mod ffi;
pub mod vt;

pub use camera::{CAMERA_DENIED, CameraPermission, camera, camera_permission, ensure_camera_permission};
pub use vt::{H264Decoder, H264Encoder, PixelBuffer};
