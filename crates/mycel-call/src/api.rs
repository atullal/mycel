//! Serializable call types shown to apps (docs/RUNTIME_API.md "Calls").
//! JSON field names and enum values are camelCase, ids are lowercase hex.

use mycel_net::PathKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// - `connecting`: dialing their device (outgoing), or answered and setting
///   up audio (incoming)
/// - `ringing`: their device is ringing (outgoing), or yours is (incoming)
/// - `active`: talking
/// - `ended`: over; see `endReason`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallPhase {
    Connecting,
    Ringing,
    Active,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndReason {
    /// You hung up (or cancelled before they answered).
    HungUp,
    /// They hung up.
    RemoteHungUp,
    /// You declined.
    Declined,
    /// They declined.
    RemoteDeclined,
    /// They're in another call.
    Busy,
    /// Their device couldn't be reached (offline, or no path to it).
    Unavailable,
    /// Nobody answered.
    NoAnswer,
    /// An incoming call you didn't answer.
    Missed,
    /// You both called at the same moment; this one was merged into the other.
    Replaced,
    /// Every path to them died and none came back.
    ConnectionLost,
    /// Mycel isn't allowed to use the microphone.
    MicDenied,
    /// Something else went wrong (`error` says what).
    Failed,
}

/// Live numbers about a call, for the in-call bar and diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallStats {
    /// Round-trip time of the path in use.
    pub rtt_ms: u32,
    /// Frames we sent that the other side reported missing, last second (0..100).
    pub loss_pct: f32,
    /// Inter-arrival jitter of what we receive.
    pub jitter_ms: f32,
    /// Audio held in our jitter buffer.
    pub buffer_ms: u32,
    /// Estimated mouth-to-ear delay of what we hear (network one way +
    /// jitter buffer + one frame + device buffers).
    pub latency_ms: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    /// Frames that never arrived in time (concealed).
    pub frames_lost: u64,
    pub frames_late: u64,
    /// `datagram` (normal) or `stream` (fallback when a path has no datagrams).
    pub transport: String,
    /// What captures and plays audio ("Voice processing", "Test tone 440 Hz", ...).
    pub audio_device: String,
    /// Test audio only: the frequency of what we hear (Hz).
    pub heard_tone_hz: Option<f32>,
    /// Test audio only: measured mouth-to-ear-and-back time of our own tone
    /// bursts echoed by the other side.
    pub measured_round_trip_ms: Option<f32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallInfo {
    /// Hex call id (bound to the conversation and the caller).
    pub id: String,
    pub conversation: String,
    /// The other device.
    pub peer: String,
    pub peer_name: String,
    pub direction: Direction,
    pub state: CallPhase,
    pub end_reason: Option<EndReason>,
    /// Human-readable cause for `failed` (and other ends where it helps).
    pub error: Option<String>,
    /// When the call was placed or arrived (ms since epoch).
    pub started_at: u64,
    /// When it became active (ms since epoch).
    pub connected_at: Option<u64>,
    /// Talking time so far (0 until active).
    pub duration_ms: u64,
    /// The path carrying the call right now.
    pub path: Option<PathKind>,
    /// Our Opus send bitrate (bits/s).
    pub bitrate: u32,
    pub muted: bool,
    pub remote_muted: bool,
    /// Microphone level, 0..1 (0 while muted).
    pub level: f32,
    /// Level of what we hear, 0..1.
    pub remote_level: f32,
    /// Echo cancellation is on (otherwise headphones avoid echo).
    pub echo_cancellation: bool,
    pub stats: CallStats,
    /// Video both ways (camera off and nothing received when it's a voice call).
    pub video: mycel_video::VideoInfo,
}
