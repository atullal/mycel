//! Live voice calls over the Mycel fabric.
//!
//! A call is one QUIC connection (ALPN `mycel/call/0`) dialed straight to the
//! other device's key, on the node's own endpoint. It therefore uses every
//! path the node has (same network, peer-to-peer Wi-Fi, internet relay,
//! Bluetooth LE) and moves between them mid-call with QUIC multipath, under
//! Mycel's path selector. Audio is Opus (48 kHz mono, 20 ms frames, in-band
//! FEC) in QUIC datagrams, played out through an adaptive jitter buffer; the
//! bitrate follows the path (32 kbps on fast paths, 12 kbps on Bluetooth)
//! and the loss the other side reports.
//!
//! - [`proto`]: signalling and the call id that binds a call to its conversation
//! - [`state`]: the call state machine (ringing, answer, hang-up, glare)
//! - [`frame`], [`jitter`], [`codec`], [`bitrate`]: the media path
//! - [`audio`]: the [`audio::AudioIo`] trait and its backends (Apple voice
//!   processing with echo cancellation, plain devices via cpal, test audio)
//! - [`CallManager`]: places, answers and runs calls

pub mod api;
pub mod audio;
pub mod bitrate;
pub mod codec;
mod engine;
pub mod frame;
pub mod jitter;
pub mod level;
#[cfg(target_os = "macos")]
pub mod mac;
mod manager;
pub mod proto;
pub mod resample;
pub mod state;

pub use api::{CallInfo, CallPhase, CallStats, Direction, EndReason};
pub use manager::{BoxFuture, CallEvent, CallHost, CallManager, selected_path};
pub use proto::ALPN_CALL;
