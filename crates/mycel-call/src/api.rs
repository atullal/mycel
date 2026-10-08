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
/// - `joinable`: a group call you declined or missed is still going on;
///   join it with `accept_call`
/// - `ended`: over; see `endReason`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallPhase {
    Connecting,
    Ringing,
    Active,
    Joinable,
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
    /// The group call already has the most people a call can have.
    Full,
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

/// Where someone stands in a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParticipantState {
    /// Their device is ringing.
    Ringing,
    /// In the call; our audio to them is being set up.
    Connecting,
    /// In the call.
    Joined,
    Declined,
    /// It rang out.
    Missed,
    /// In another call.
    Busy,
    /// Their device couldn't be reached.
    Unavailable,
    /// Was in the call and left (or their connection dropped).
    Left,
}

/// Someone else in (or invited to) a call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub id: String,
    pub name: String,
    pub state: ParticipantState,
    pub muted: bool,
    /// Level of what they say, 0..1 (0 unless we're talking to them).
    pub level: f32,
    /// Talking right now.
    pub speaking: bool,
    /// The path to their device.
    pub path: Option<PathKind>,
    /// Our Opus bitrate to them (bits/s).
    pub bitrate: u32,
    pub rtt_ms: u32,
    /// Of what we send them, the share they reported missing (0..100).
    pub loss_pct: f32,
    /// Video with them, both ways (their camera, our video to them).
    pub video: mycel_video::PeerVideo,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallInfo {
    /// Hex call id (bound to the conversation and the caller).
    pub id: String,
    pub conversation: String,
    /// More than two people may be in it (a group conversation).
    pub group: bool,
    /// The group's name (group calls).
    pub title: Option<String>,
    /// 1:1: the other device. Group: who started the call.
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
    /// Everyone else in, or rung for, the call (1:1: just the other person).
    pub participants: Vec<Participant>,
    /// People in the call right now, you included if you're in it.
    pub joined_count: u32,
    /// Whoever is talking loudest right now.
    pub active_speaker: Option<String>,
    /// The path carrying the call right now (group: to the first person who
    /// joined; see `participants` for each).
    pub path: Option<PathKind>,
    /// Our Opus send bitrate (bits/s).
    pub bitrate: u32,
    pub muted: bool,
    /// 1:1: the other person muted themselves.
    pub remote_muted: bool,
    /// Microphone level, 0..1 (0 while muted).
    pub level: f32,
    /// Level of everything we hear, mixed, 0..1.
    pub remote_level: f32,
    /// Echo cancellation is on (otherwise headphones avoid echo).
    pub echo_cancellation: bool,
    pub stats: CallStats,
    /// Video both ways (camera off and nothing received when it's a voice call).
    pub video: mycel_video::VideoInfo,
}
