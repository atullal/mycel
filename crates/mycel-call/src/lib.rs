//! Live voice calls over the Mycel fabric: 1:1 and group (up to 8 people).
//!
//! A call is a full mesh of QUIC connections (ALPN `mycel/call/1`), one per
//! pair of participants, each dialed straight to the other device's key on
//! the node's own endpoint. Every connection therefore uses every path the
//! node has (same network, peer-to-peer Wi-Fi, internet relay, Bluetooth
//! LE) and moves between them mid-call with QUIC multipath, under Mycel's
//! path selector. Audio is Opus (48 kHz mono, 20 ms frames, in-band FEC) in
//! QUIC datagrams: each frame is encoded once per bitrate tier and sent to
//! every peer. Each peer is played out through its own adaptive jitter
//! buffer and decoder, and the peers are mixed. The bitrate to each peer
//! follows the path to it (32 kbps on fast paths, 12 kbps on Bluetooth) and
//! the loss it reports.
//!
//! - [`proto`]: signalling, and the call id that binds a call to its conversation
//! - [`state`]: what to do with a ring (busy, glare, a call already going on)
//! - [`engine`]: the media engine, and the [`engine::TrackSink`] seam for
//!   other tracks (video) on the same connections
//! - [`frame`], [`jitter`], [`codec`], [`bitrate`]: the media path
//! - [`audio`]: the [`audio::AudioIo`] trait and its backends (Apple voice
//!   processing with echo cancellation, plain devices via cpal, test audio)
//! - [`CallManager`]: places, answers and runs calls
//! - video (`mycel_video`): the built-in [`engine::TrackSink`], a video
//!   track on every person's connection

pub mod api;
pub mod audio;
pub mod bitrate;
pub mod codec;
pub mod engine;
pub mod frame;
pub mod jitter;
pub mod level;
#[cfg(target_os = "android")]
pub mod android;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod mac;
mod manager;
pub mod proto;
pub mod resample;
pub mod state;
mod video;

pub use api::{CallInfo, CallPhase, CallStats, Direction, EndReason, Participant, ParticipantState};
pub use engine::TrackSink;
pub use manager::{BoxFuture, CallEvent, CallHost, CallManager, selected_path};
pub use proto::{ALPN_CALL, MAX_PARTICIPANTS};
