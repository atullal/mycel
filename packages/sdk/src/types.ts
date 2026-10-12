// TypeScript mirrors of crates/mycel-node/src/api.rs (the v0 runtime contract,
// see docs/RUNTIME_API.md). JSON field names are camelCase, enum values are
// camelCase strings, and every id is a lowercase hex string.
//
// Keep this file in lock-step with api.rs: one TS declaration per Rust type.

/** Hex-encoded 32-byte Ed25519 public key (device id = Iroh endpoint id). */
export type PeerId = string;
/** Hex-encoded Space id. */
export type ConversationId = string;
/** Hex-encoded envelope id of the message entry. */
export type MessageId = string;

export interface Profile {
  id: PeerId;
  name: string;
  /** Shareable code: give it to someone so they can add you as a contact. */
  contactCode: string;
}

export interface Contact {
  id: PeerId;
  name: string;
  /** Currently visible on the local network (mDNS). */
  nearby: boolean;
  /** We have an open/recent connection to them. */
  online: boolean;
}

/** Someone advertising on the local network, not necessarily a contact. */
export interface NearbyPeer {
  id: PeerId;
  name: string;
  isContact: boolean;
}

export type MemberRole = "admin" | "member" | "readOnly" | "keeper";

export interface Member {
  id: PeerId;
  name: string;
  role: MemberRole;
  isMe: boolean;
}

export interface ConversationSummary {
  id: ConversationId;
  /** Original encrypted spaces represented by this conversation, including id. */
  aliases: ConversationId[];
  /** Stable display identity across late-arriving direct-chat aliases. Not a wire-space ID. */
  threadKey: string;
  title: string;
  /** True for a 1:1 conversation. */
  direct: boolean;
  members: Member[];
  lastMessage: MessageView | null;
  unread: number;
  /** False once we've been removed (history stays readable locally). */
  active: boolean;
  myRole: MemberRole | null;
  /**
   * A message request: someone who isn't a contact added you. Nothing is
   * posted (no receipts, no replies) until you accept; decline to leave.
   */
  request: boolean;
  /** Who added you (for requests). */
  invitedBy: PeerId | null;
}

export interface Attachment {
  /** Hex BLAKE3 of the encrypted blob. */
  blob: string;
  name: string;
  mime: string;
  size: number;
  /** Present once the blob is available locally. */
  localPath: string | null;
}

export interface Reaction {
  emoji: string;
  by: PeerId[];
}

/**
 * - `local`: written locally, not yet seen by any other member or keeper.
 * - `sent`: at least one other device (member or keeper) holds it.
 * - `delivered`: every other member has it.
 * - `read`: every other member has read up to it.
 */
export type Delivery = "local" | "sent" | "delivered" | "read";

export interface MessageView {
  id: MessageId;
  conversation: ConversationId;
  author: PeerId;
  authorName: string;
  /** Author's claimed wall clock (ms since epoch). Display only. */
  sentAt: number;
  body: string;
  replyTo: MessageId | null;
  edited: boolean;
  deleted: boolean;
  attachments: Attachment[];
  reactions: Reaction[];
  isMine: boolean;
  /** Only meaningful for my own messages. */
  delivery: Delivery;
}

/**
 * - `local`: loopback only (tests).
 * - `lan`: local paths only (same network, peer-to-peer Wi-Fi, Bluetooth); never the internet.
 * - `internet`: every path: the local ones plus internet relays and discovery.
 */
export type NetworkMode = "local" | "lan" | "internet";

/**
 * A path between two devices:
 * - `network`: same Wi-Fi/Ethernet/cable network (or direct over the internet)
 * - `peerWifi`: Apple peer-to-peer Wi-Fi (like AirDrop), no shared network needed
 * - `bluetooth`: Bluetooth LE, slow, no Wi-Fi needed
 * - `relay`: through an encrypted internet relay
 * - `mesh`: relayed hop by hop by other nearby Mycel devices (they can't read it)
 */
/**
 * The medium a path travels over. Path selection ranks paths by what they
 * measure, so any of these can carry traffic; the kind is for display.
 * - `wifiDirect`: a Wi-Fi Direct (or Wi-Fi Aware) group
 * - `uwb`: an ultra-wideband radio; `ieee802154`: Thread / 6LoWPAN
 * - `ethernet`: a cable (Ethernet, Thunderbolt or USB bridge)
 * - `other`: any other network interface (see `LinkStatus.label`)
 */
export type PathKind =
  | "network"
  | "peerWifi"
  | "bluetooth"
  | "relay"
  | "wifiDirect"
  | "uwb"
  | "ieee802154"
  | "ethernet"
  | "other"
  | "mesh";

/** A link: peer-to-peer Wi-Fi, Bluetooth, or one kind of network interface. */
export interface LinkStatus {
  kind: PathKind;
  /** Which interfaces, for interface links ("lowpan0", "p2p-wlan0-0"). */
  label?: string | null;
  active: boolean;
  /** Why it isn't working, in actionable words. */
  detail: string | null;
  /** Devices reachable over it right now. */
  peers: number;
}

export interface PeerPaths {
  id: PeerId;
  name: string;
  online: boolean;
  /** The path the last exchange used. */
  via: PathKind | null;
  /** Paths available without the internet. */
  available: PathKind[];
  /** When `via` is `mesh`: the nearby device it goes through, and how many hops. */
  mesh: MeshVia | null;
}

/** A mesh route: "Mesh (via Bob, 2 hops)". */
export interface MeshVia {
  /** The neighbour it leaves through (needn't be a contact). */
  via: PeerId;
  viaName: string;
  /** Hops to the peer (2 = one device in between; 0 = unknown, beyond a gateway). */
  hops: number;
  /** Through a gateway and the internet: `via` is the gateway. */
  gateway: boolean;
}

export interface NetworkStatus {
  mode: NetworkMode;
  /** The mode the next launch uses (differs from `mode` until a restart). */
  nextMode: NetworkMode;
  onlinePeers: PeerId[];
  /** Peers reachable without the internet. */
  nearbyPeers: number;
  /** Local addresses we're listening on (diagnostics). */
  addresses: string[];
  links: LinkStatus[];
  peers: PeerPaths[];
}

// ---------------------------------------------------------------------------
// Calls (live voice, 1:1 and group)

/** Hex call id, bound to the conversation and the caller. */
export type CallId = string;

export type CallDirection = "outgoing" | "incoming";

/**
 * - `connecting`: dialing (outgoing), or answered / joining and setting up audio
 * - `ringing`: their devices are ringing (outgoing), or yours is (incoming)
 * - `active`: talking
 * - `joinable`: a group call you declined or missed is still going on; join with `calls.join`
 * - `ended`: over; see `endReason`
 */
export type CallState = "connecting" | "ringing" | "active" | "joinable" | "ended";

/**
 * - `hungUp`: you hung up (or cancelled before they answered)
 * - `remoteHungUp`: they hung up
 * - `declined`: you declined; `remoteDeclined`: they did
 * - `busy`: they're in another call
 * - `unavailable`: their device couldn't be reached (offline, or no path to it)
 * - `noAnswer`: nobody answered; `missed`: an incoming call you didn't answer
 * - `replaced`: you both called at the same moment and this one merged into the other (don't show it)
 * - `connectionLost`: every path died and none came back
 * - `micDenied`: Mycel isn't allowed to use the microphone
 * - `full`: the group call already has the most people a call can have (8)
 * - `failed`: something else (`error` says what)
 */
export type CallEndReason =
  | "hungUp"
  | "remoteHungUp"
  | "declined"
  | "remoteDeclined"
  | "busy"
  | "unavailable"
  | "noAnswer"
  | "missed"
  | "replaced"
  | "connectionLost"
  | "micDenied"
  | "full"
  | "failed";

/**
 * Where someone stands in a call: `ringing` (their device rings), `connecting`
 * (in the call, our audio to them is being set up), `joined`, `declined`,
 * `missed`, `busy` (in another call), `unavailable` (unreachable), `left`.
 */
export type ParticipantState =
  | "ringing"
  | "connecting"
  | "joined"
  | "declined"
  | "missed"
  | "busy"
  | "unavailable"
  | "left";

/** Someone else in (or rung for) a call. */
export interface Participant {
  id: PeerId;
  name: string;
  state: ParticipantState;
  muted: boolean;
  /** Level of what they say, 0..1 (0 unless you're talking to them). */
  level: number;
  /** Talking right now. */
  speaking: boolean;
  /** The path to their device. */
  path: PathKind | null;
  /** Our Opus bitrate to them, bits/s. */
  bitrate: number;
  rttMs: number;
  /** Of what we send them, the share they reported missing (0..100). */
  lossPct: number;
  /** Video with them, both ways (their camera; our video to them, at the quality their path allows). */
  video: PeerVideo;
}

/** Video with one person in a call. */
export interface PeerVideo {
  /** Our video is going out to them. */
  sending: boolean;
  /** Our video to them is paused: the path to them is too slow. */
  paused: boolean;
  /** Their camera is on. */
  remoteCamera: boolean;
  /** Their video is paused on their side (slow connection). */
  remotePaused: boolean;
  /** Their frames are arriving right now. */
  receiving: boolean;
  sendWidth: number;
  sendHeight: number;
  sendFps: number;
  bitrate: number;
  sentBitrate: number;
  queueMs: number;
  recvWidth: number;
  recvHeight: number;
  recvFps: number;
  latencyMs: number;
  framesSent: number;
  framesReceived: number;
  framesSkipped: number;
  keyframesSent: number;
  keyframeRequests: number;
  encoder: string;
}

/** Live numbers about a call (in-call bar, diagnostics). */
export interface CallStats {
  rttMs: number;
  /** Of what we send, the share the other side reported missing (0..100). */
  lossPct: number;
  jitterMs: number;
  /** Audio held in our jitter buffer. */
  bufferMs: number;
  /** Estimated mouth-to-ear delay of what we hear. */
  latencyMs: number;
  framesSent: number;
  framesReceived: number;
  framesLost: number;
  framesLate: number;
  /** `datagram` normally; `stream` when a path can't carry datagrams. */
  transport: string;
  /** What captures and plays audio ("Voice processing (echo cancellation)", ...). */
  audioDevice: string;
  /** Test audio only: frequency of what we hear (Hz). */
  heardToneHz: number | null;
  /** Test audio only: measured round trip of our tone bursts, echoed back. */
  measuredRoundTripMs: number | null;
}

export interface CallInfo {
  id: CallId;
  conversation: ConversationId;
  /** A group conversation's call: more than two people may be in it (up to 8). */
  group: boolean;
  /** The group's name (group calls). */
  title: string | null;
  /** 1:1: the other device. Group: who started the call (`peerName` "You" if it was you). */
  peer: PeerId;
  peerName: string;
  direction: CallDirection;
  state: CallState;
  endReason: CallEndReason | null;
  /** Human-readable cause, e.g. for `failed` or `unavailable`. */
  error: string | null;
  /** When the call was placed or arrived (ms since epoch). */
  startedAt: number;
  /** When it became active (ms since epoch). */
  connectedAt: number | null;
  /** Talking time so far. */
  durationMs: number;
  /** Everyone else in, or rung for, the call (1:1: just the other person). Joined first. */
  participants: Participant[];
  /** People in the call right now, you included if you're in it. */
  joinedCount: number;
  /** Whoever is talking loudest right now. */
  activeSpeaker: PeerId | null;
  /** The path carrying the call (group: to the first person who joined; see `participants`). */
  path: PathKind | null;
  /** Our Opus send bitrate, bits/s (32k on fast paths, ~12k on Bluetooth). */
  bitrate: number;
  muted: boolean;
  /** 1:1: the other person muted themselves. */
  remoteMuted: boolean;
  /** Microphone level 0..1 (0 while muted). */
  level: number;
  /** Level of everything we hear, mixed, 0..1. */
  remoteLevel: number;
  /** Echo cancellation is on (otherwise suggest headphones). */
  echoCancellation: boolean;
  stats: CallStats;
  /** Video both ways (camera off and nothing received in a voice call). */
  video: VideoInfo;
}

/**
 * Our camera in a call:
 * - `off`, `starting`, `on`
 * - `denied`: Mycel isn't allowed to use the camera (`error` says where to allow it)
 * - `failed`: it couldn't start (`error` says why); the call goes on without video
 */
export type CameraState = "off" | "starting" | "on" | "denied" | "failed";

/** Live video state and numbers for a call. */
export interface VideoInfo {
  camera: CameraState;
  error: string | null;
  /** Our video is going out. */
  sending: boolean;
  /** Our video is paused: the path is too slow (Bluetooth). Show "Video paused: slow connection". */
  paused: boolean;
  /** The other side has its camera on. */
  remoteCamera: boolean;
  /** The other side's video is paused (slow connection). */
  remotePaused: boolean;
  /** Their frames are arriving right now. */
  receiving: boolean;
  sendWidth: number;
  sendHeight: number;
  sendFps: number;
  /** Target video bitrate (bits/s). */
  bitrate: number;
  /** What we actually sent over the last second (bits/s). */
  sentBitrate: number;
  /** How long our frames wait in queues beyond the base delay. */
  queueMs: number;
  recvWidth: number;
  recvHeight: number;
  recvFps: number;
  /** Their capture to arrival here (clocks of two devices: approximate). */
  latencyMs: number;
  framesSent: number;
  framesReceived: number;
  framesSkipped: number;
  keyframesSent: number;
  keyframeRequests: number;
  /** What captures our video ("FaceTime HD Camera", "Test pattern ..."). */
  source: string;
  /** Which encoder ("H.264 low-latency", "H.264 hardware", ...). */
  encoder: string;
}

/**
 * - `upload`: encrypting an attachment we're sending.
 * - `download`: downloading an attachment someone sent.
 */
export type TransferDirection = "upload" | "download";

/** Pushed to UIs (Tauri event `mycel://event`), tagged by `type`. */
export type MycelEvent =
  /** Anything about a conversation changed (messages, members, receipts). */
  | { type: "conversationUpdated"; conversation: ConversationId }
  /** We were added to a new conversation. */
  | { type: "conversationAdded"; conversation: ConversationId }
  | { type: "typing"; conversation: ConversationId; peer: PeerId }
  | { type: "contactsChanged" }
  | { type: "nearbyChanged" }
  | { type: "networkChanged" }
  | { type: "blobReady"; blob: string }
  /**
   * An attachment transfer moved forward (at most every 250 ms, plus a final
   * event with `done === total`). `id` is the path passed to `send_message`
   * for uploads, and the blob id for downloads. `rate` is bytes per second
   * over the last few seconds.
   */
  | { type: "transferProgress"; direction: TransferDirection; id: string; done: number; total: number; rate: number }
  /** Someone is calling: show Accept / Decline. */
  | { type: "callIncoming"; call: CallInfo }
  /** A call changed (state, path, bitrate, mute); ~10x a second while active, for duration and meters. */
  | { type: "callUpdated"; call: CallInfo };

/** Alias matching the Rust name. */
export type Event = MycelEvent;

export type EventType = MycelEvent["type"];

/** The event variant with the given `type` tag. */
export type EventOf<T extends EventType> = Extract<MycelEvent, { type: T }>;

/** Every `type` tag, for exhaustiveness checks and runtime validation. */
export const EVENT_TYPES: readonly EventType[] = [
  "conversationUpdated",
  "conversationAdded",
  "typing",
  "contactsChanged",
  "nearbyChanged",
  "networkChanged",
  "blobReady",
  "transferProgress",
  "callIncoming",
  "callUpdated",
] as const;
