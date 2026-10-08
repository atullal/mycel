//! Live video for Mycel calls.
//!
//! Video rides the call's own QUIC connection (so it uses every path the
//! call does and moves with it), on streams of its own: see [`wire`] for
//! the format, [`track`] for the engine, [`rate`] for how much is sent.
//!
//! # Choices, and why
//!
//! **Codec: H.264 through Apple's VideoToolbox.** Every Mac since 2011 has
//! a hardware H.264 encoder and decoder; VideoToolbox drives them (with a
//! software fallback) in real-time mode with no frame reordering, at a few
//! percent of one core for 720p30. It ships with macOS, so there's nothing
//! to bundle and no patent-licence question for us: Apple's codec licence
//! covers its use. And every browser engine decodes H.264 in hardware too,
//! which is what lets the webview decode (below). Alternatives considered:
//! - *openh264* (Cisco, BSD): software only (several times the CPU of the
//!   hardware path, and battery), a C++ build for both Mac architectures,
//!   and Cisco's patent cover applies only to their prebuilt binaries, not
//!   to builds from source.
//! - *VP8/VP9/AV1 in software* (libvpx, rav1e/dav1d): royalty-free but no
//!   hardware encode on most Macs; AV1 hardware decode only on M3 and later.
//!   Worth revisiting for other platforms; the wire format names the codec
//!   by its config record so another can be added beside H.264.
//!
//! **Transport: one QUIC stream per frame.** QUIC already fragments,
//! retransmits and congestion-controls streams, so a frame either arrives
//! whole or its stream is reset; there's no reassembly layer of our own. A
//! frame that is late (stuck over 1.5 s) or superseded by a newer keyframe
//! is reset, so QUIC stops resending it, and the receiver asks for a
//! keyframe if it lost one it needed. Audio stays in QUIC datagrams, which
//! QUIC packs into each packet before any stream data, and video streams
//! get the lowest stream priority, so video can't push audio aside. The
//! alternative, datagrams with our own fragmentation, would lose a whole
//! frame (and everything after it until a keyframe) on any one lost packet
//! and need our own retransmission to do better: measured on a lossy link
//! it is strictly worse for H.264, whose frames depend on each other.
//!
//! **Decoding: in the webview, with WebCodecs.** The app hands the webview
//! encoded frames (a few KB each) and its `VideoDecoder` decodes them in
//! hardware straight onto a canvas. Decoding in Rust and handing over
//! pictures instead would move ~40 MB/s of raw 720p30 (or need a JPEG
//! re-encode per frame) across the IPC bridge. WebCodecs `VideoDecoder`
//! is in WebKit since Safari 16.4, which every macOS from 11 (Big Sur) can
//! install, so the app's minimum system version stays at 11.0; a webview
//! without it shows "video isn't supported" and the call stays audio-only.
//! [`platform::H264Decoder`] decodes in Rust for tests and headless runs.

pub mod pattern;
pub mod rate;
pub mod receiver;
pub mod source;
pub mod track;
pub mod wire;

#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(not(target_os = "macos"))]
mod stub;

/// The video backend for this platform.
pub mod platform {
    #[cfg(target_os = "macos")]
    pub use crate::mac::{CAMERA_DENIED, H264Decoder, H264Encoder, PixelBuffer, camera};
    #[cfg(not(target_os = "macos"))]
    pub use crate::stub::{CAMERA_DENIED, H264Decoder, H264Encoder, PixelBuffer, camera};
}

pub use source::{Picture, TestPattern, VideoSource, default_source};
pub use track::{CameraState, TrackOptions, VideoInfo, VideoTrack};
pub use wire::{EncodedFrame, UiFrame, UiSource};
