# Mycel Runtime API (v0 contract)

The Rust runtime (`mycel_node::Runtime`) exposes this API. The Tauri host wraps each method as a command, and `@mycel/sdk` (TypeScript) wraps each command. Types are defined in `crates/mycel-node/src/api.rs`; JSON field names are **camelCase**, enum values are **camelCase** strings, and all ids are lowercase hex strings.

## Rust surface (implemented in `crates/mycel-node/src/runtime.rs`)

```rust
impl Runtime {
    pub async fn open(data_dir: impl AsRef<Path>, mode: NetworkMode, name: Option<String>) -> Result<Arc<Runtime>>;
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event>;
    pub async fn shutdown(&self) -> Result<()>;

    // identity & contacts (host-level, shared by all apps)
    pub fn profile(&self) -> Profile;
    pub fn set_name(&self, name: String) -> Result<Profile>;
    pub fn add_contact(&self, code: String) -> Result<Contact>;          // from a contact code
    pub async fn add_nearby_contact(&self, id: PeerId) -> Result<Contact>; // fetches their card over the LAN
    pub fn remove_contact(&self, id: PeerId) -> Result<()>;
    pub fn contacts(&self) -> Vec<Contact>;
    pub fn nearby(&self) -> Vec<NearbyPeer>;
    pub fn network_status(&self) -> NetworkStatus;

    // messaging (chat kit)
    pub fn conversations(&self) -> Vec<ConversationSummary>;               // newest activity first
    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary>;
    pub fn create_conversation(&self, title: Option<String>, members: Vec<PeerId>) -> Result<ConversationSummary>;
    pub fn messages(&self, id: ConversationId, limit: Option<u32>, before: Option<MessageId>) -> Result<Vec<MessageView>>; // oldest → newest
    pub async fn send_message(&self, id: ConversationId, body: String, reply_to: Option<MessageId>, attachments: Vec<String> /* file paths */) -> Result<MessageView>;
    pub fn edit_message(&self, id: ConversationId, message: MessageId, body: String) -> Result<()>;
    pub fn delete_message(&self, id: ConversationId, message: MessageId) -> Result<()>;
    pub fn toggle_reaction(&self, id: ConversationId, message: MessageId, emoji: String) -> Result<()>;
    pub fn mark_read(&self, id: ConversationId) -> Result<()>;
    pub fn set_typing(&self, id: ConversationId) -> Result<()>;
    pub fn add_members(&self, id: ConversationId, members: Vec<PeerId>) -> Result<()>;
    pub fn remove_member(&self, id: ConversationId, member: PeerId) -> Result<()>;   // member == me → leave
    pub fn leave_conversation(&self, id: ConversationId) -> Result<()>;
    pub fn add_keeper(&self, id: ConversationId, keeper: PeerId) -> Result<()>;   // keeper must be a contact
    pub fn rename_conversation(&self, id: ConversationId, title: String) -> Result<()>;
    pub async fn fetch_attachment(&self, blob: String) -> Result<String>;       // local file path

    // calls (live voice, 1:1 and group)
    pub async fn start_call(&self, conversation: ConversationId) -> Result<CallInfo>;
    pub async fn accept_call(&self, call: String) -> Result<CallInfo>;
    pub fn decline_call(&self, call: String) -> Result<()>;
    pub fn end_call(&self, call: String) -> Result<()>;
    pub fn set_muted(&self, call: String, muted: bool) -> Result<CallInfo>;
    pub fn call_status(&self) -> Vec<CallInfo>;
    // video in calls
    pub async fn start_call_with(&self, conversation: ConversationId, video: bool) -> Result<CallInfo>;
    pub async fn accept_call_with(&self, call: String, video: bool) -> Result<CallInfo>;
    pub async fn set_camera(&self, call: String, on: bool) -> Result<CallInfo>;
    pub fn video_keyframe(&self, call: String) -> Result<()>;
    pub fn video_frames(&self) -> broadcast::Receiver<mycel_video::UiFrame>;
    pub async fn sync_now(&self);                                               // pull-to-refresh
}
```

## Tauri commands (snake_case names, camelCase args)

| Command | Args | Returns |
|---|---|---|
| `get_profile` | — | `Profile` |
| `set_name` | `{ name }` | `Profile` |
| `add_contact` | `{ code }` | `Contact` |
| `add_nearby_contact` | `{ id }` | `Contact` |
| `remove_contact` | `{ id }` | `null` |
| `list_contacts` | — | `Contact[]` |
| `list_nearby` | — | `NearbyPeer[]` |
| `network_status` | — | `NetworkStatus` |
| `list_conversations` | — | `ConversationSummary[]` |
| `get_conversation` | `{ id }` | `ConversationSummary` |
| `create_conversation` | `{ title?, members }` | `ConversationSummary` |
| `list_messages` | `{ id, limit?, before? }` | `MessageView[]` |
| `send_message` | `{ id, body, replyTo?, attachments? }` | `MessageView` |
| `edit_message` | `{ id, message, body }` | `null` |
| `delete_message` | `{ id, message }` | `null` |
| `toggle_reaction` | `{ id, message, emoji }` | `null` |
| `mark_read` | `{ id }` | `null` |
| `set_typing` | `{ id }` | `null` |
| `add_members` | `{ id, members }` | `null` |
| `remove_member` | `{ id, member }` | `null` |
| `add_keeper` | `{ id, keeper }` | `null` |
| `rename_conversation` | `{ id, title }` | `null` |
| `fetch_attachment` | `{ blob }` | `string` (path) |
| `accept_request` | `{ id }` | `ConversationSummary` |
| `decline_request` | `{ id, block? }` | `null` |
| `stage_file` | raw bytes as the body; `x-mycel-name` header = URI-encoded file name | `string` (path to pass in `attachments`) |
| `start_call` | `{ conversation, video? }` | `CallInfo` |
| `accept_call` | `{ call, video? }` | `CallInfo` |
| `set_camera` | `{ call, on }` | `CallInfo` |
| `video_keyframe` | `{ call }` | `null` |
| `video_subscribe` | `{ channel }` (Tauri only) | `null`; frames arrive on the channel |
| `decline_call` | `{ call }` | `null` |
| `end_call` | `{ call }` | `null` |
| `set_muted` | `{ call, muted }` | `CallInfo` |
| `call_status` | — | `CallInfo[]` |

`stage_file` is host-only (Tauri). It is for pasted images and other files without a path. The SDK calls it through `files.stage()`.

Errors are rejected promises carrying a human-readable string. It includes the cause, e.g. `macOS didn't let Mycel read /Users/me/Desktop/x.mov. Allow Mycel in System Settings > Privacy & Security > Files and Folders …: Operation not permitted (os error 1)`.

**Event:** the Tauri event `mycel://event` carries one `Event` (tagged by `type`): `conversationUpdated`, `conversationAdded`, `typing`, `contactsChanged`, `nearbyChanged`, `networkChanged`, `blobReady`, `transferProgress`, `callIncoming`, `callUpdated`.

`transferProgress { direction: "upload" | "download", id, done, total, rate }` (`rate` = bytes per second over the last 3 s):
- Emitted at most every 250 ms, plus a final event with `done == total`.
- For uploads, `id` is the exact string passed in `send_message`'s `attachments`, and the bytes count plaintext encrypted.
- For downloads, `id` is the blob id, and the bytes count sealed bytes received.
- The SDK's React hook `useTransfer(id)` returns the latest `{ done, total }`.

## Semantics the UI can rely on
- **Instant local writes:** `send_message` returns as soon as the message is written locally (`delivery: "local"`). It moves to `sent`, then `delivered`, then `read` as peers sync, and each step emits `conversationUpdated`.
- **Direct conversations:** a conversation with exactly one other member and no title is `direct`. Its title is the other person's name.
- **Author-only edits and deletes:** only the author can edit or delete a message. Others' attempts are ignored by every peer.
- **Typing is ephemeral:** a `typing` event should be shown for about 4 seconds.
- **Message order:** messages arrive in causal order. `sentAt` is display-only (the author's clock).
- **Attachments are lazy:** an attachment's `localPath` is `null` until fetched. Call `fetch_attachment`, then wait for `blobReady`.
- **Attachments of any size:**
  - There is no size limit. Files are encrypted and transferred as streams with bounded memory (docs/TRUST.md §7b).
  - Attachments up to 16 MiB are pushed to members right away. Bigger ones are downloaded when you call `fetch_attachment`, from the sender, a keeper or any member that has them. An interrupted download resumes where it stopped.
  - A transfer is refused, with a clear error, if it would leave less than 1 GiB of free disk.
  - `send_message` resolves once the files are encrypted locally. Watch `transferProgress` while it runs.
- **What `attachments` accepts:**
  - Local file paths, or `file://` URLs.
  - A folder or macOS package (`.app`, `.pages`, `.key`, `.rtfd`, …) is sent as `<name>.zip`.
  - Files staged under the data dir's `uploads/` (HTTP uploads, `stage_file`) are deleted once the message is sent; the attachment then lives in `files/`.
- **Offline-first:** everything works with no network at all. Peers on the same LAN find each other via mDNS with no internet.

## Calls (live voice and video, 1:1 and group)
Audio is captured and played by the runtime (Rust), never by the webview, so
the same commands work in the Tauri host and over `mycel serve`.

`start_call` in a direct conversation rings the other person. In a group, it
rings every other member, and up to 8 people can be in the call at once.

| Event | When |
|---|---|
| `callIncoming { call }` | Someone is calling (`state: "ringing"`, `direction: "incoming"`): show Accept / Decline |
| `callUpdated { call }` | Any change: state, people, path, bitrate, mute; about 10×/s while `active` (duration, level meters) |

`CallInfo`:

| Field | |
|---|---|
| `id` | hex call id (bound to the conversation and the caller, see below) |
| `conversation`, `direction` | `direction`: `outgoing` / `incoming` |
| `group`, `title` | a group conversation's call (more than two people may join), and the group's name |
| `peer`, `peerName` | 1:1: the other person. Group: who started the call (`peerName` is `"You"` if you did) |
| `state` | `connecting` (dialing / answered or joining, starting audio), `ringing`, `active`, `joinable` (a group call you declined or missed is still going on: `accept_call` joins it), `ended` |
| `endReason` | `hungUp`, `remoteHungUp` (1:1: they hung up; group: the last other person left), `declined`, `remoteDeclined`, `busy`, `unavailable` (nobody can be reached), `noAnswer` (45 s), `missed`, `replaced` (two calls started at once; this one merged into the other: don't show it), `connectionLost`, `micDenied`, `full` (8 people already), `failed` |
| `error` | human-readable cause where it helps (`failed`, `unavailable`) |
| `startedAt`, `connectedAt`, `durationMs` | ms since epoch / talking time |
| `participants` | everyone else in, or rung for, the call (1:1: the other person), joined first: `{ id, name, state, muted, level, speaking, path, bitrate, rttMs, lossPct }`. `state`: `ringing`, `connecting`, `joined`, `declined`, `missed`, `busy`, `unavailable`, `left`. `path` and `bitrate` are per person |
| `joinedCount` | people in the call now, you included if you're in it |
| `activeSpeaker` | the loudest person talking right now (a participant `id`), or `null` |
| `path` | the path carrying the call now: `network`, `peerWifi`, `bluetooth`, `relay`, `mesh` (through other nearby devices), or another medium (group: to the first person who joined; see `participants`) |
| `bitrate` | our Opus bitrate (bits/s): 32k on fast paths, 24k via relay, 12k on Bluetooth, lower under loss (group: see `participants`) |
| `muted`, `remoteMuted` | `remoteMuted`: 1:1 only (group: each participant's `muted`) |
| `level`, `remoteLevel` | 0..1 meters: yours (0 while muted), and everything you hear mixed |
| `echoCancellation` | false → suggest headphones |
| `stats` | `rttMs`, `lossPct` (of what we send, as the other side reports), `jitterMs`, `bufferMs`, `latencyMs` (estimate), `framesSent/Received/Lost/Late`, `transport` (`datagram` / `stream`), `audioDevice`, and with test audio `heardToneHz`, `measuredRoundTripMs` |
| `video` | see **Video** below; in a voice call `camera: "off"` and nothing received |

Semantics:
- **Ringing needs only the devices online.** The caller dials each other
  device's key directly (ALPN `mycel/call/1` on the node's endpoint, so every
  path: network, peer-to-peer Wi-Fi, relay, Bluetooth). If nobody can be
  reached within a few seconds the call ends `unavailable`.
- **Group calls are a full mesh.** Everyone in the call has their own
  connection to everyone else. Each frame is encoded once per bitrate tier
  and sent to each person at the bitrate their path allows. What you hear is
  everyone's voice mixed on your device, each through its own jitter buffer.
  There is no server or host in the middle: whoever started the call can
  leave, and it goes on.
- **At most 8 people in a call.** Each device sends its voice to every other
  one, so upload and CPU grow with the group (7 × 32 kbps ≈ 0.3 Mbps up at
  8 people, too much for Bluetooth). A 9th person gets `full`. A call rings at
  most 31 members.
- **Joining and leaving.** Declining a group call, or letting it ring out,
  leaves it `joinable` for as long as it goes on (`joinedCount` says how many
  are in it). `accept_call`, or `start_call` in that conversation, joins it.
  `end_call` leaves; the call goes on for the others and ends when the last
  person leaves. `start_call` in a group that already has a call going on
  joins that call instead of starting a second one.
- **Only members may call or join.** A device rings, or lets someone join or
  watch its call, only if both are current (non-keeper) members of the
  conversation, it isn't a message request you haven't accepted (or one you
  declined), and the caller isn't blocked. Otherwise the call ends `failed`.
  Someone removed from the group is dropped from its call within a second.
- **One call at a time.** A second caller gets `busy`. Answering a ringing
  call hangs up the one in progress. If two people call the same conversation
  at once, everyone ends up in one call (the other one ends `replaced`).
- **Microphone permission** is asked on `start_call` / `accept_call` the first
  time (macOS shows NSMicrophoneUsageDescription). If it's denied, the command
  fails with *"Mycel isn't allowed to use the microphone. Allow it in System
  Settings > Privacy & Security > Microphone, then call again."*
- `call_status` lists live calls plus ones that ended in the last 10 s.

### Video
Video rides the same call (the same QUIC connection, so every path and the
same moves between them). Our camera is captured and encoded by the runtime
(H.264 in hardware through VideoToolbox); **the webview only decodes**, with
WebCodecs `VideoDecoder`, which needs Safari 16.4 or later (on macOS 11+,
update Safari). `@mycel/sdk` does it for you: `useVideoCanvas(ref, { call,
source, peer })` in React, or `videoCanvas(canvas)` + `mycel.calls.onVideo`.

- **Starting:** `start_call { video: true }` / `accept_call { video: true }`,
  or `set_camera { call, on }` at any time (also before the call is
  answered). The first time, macOS asks for the camera
  (NSCameraUsageDescription); if denied, `set_camera` fails, the call goes on
  without video, and `video.camera` is `denied` with `video.error`:
  *"Mycel isn't allowed to use the camera. Allow it in System Settings >
  Privacy & Security > Camera, then turn the camera on again."*
- **Group calls:** every person gets their own video stream (`frame.peer`
  says whose; show one tile each), encoded at the quality the path to that
  person allows; `participants[].video` has each one's numbers both ways.
- **What's sent** follows the path: up to 720p30 on cable, a Wi-Fi network or
  UWB; 480p30 on peer-to-peer Wi-Fi / Wi-Fi Direct; 360p via a relay; and
  nothing under 1 Mbit/s (Bluetooth, Thread/802.15.4) or over the multi-hop mesh: `video.paused` on our
  side and `video.remotePaused` on theirs ("Video paused: slow connection"),
  resuming by itself when a faster path returns. Under that ceiling a
  delay-based controller keeps video's queueing to tens of ms, so audio
  keeps priority: video starts at 320×180 and ramps up within ~4 s.
- **`video` fields:** `camera` (`off`, `starting`, `on`, `denied`, `failed`),
  `error`, `sending`, `paused`, `remoteCamera`, `remotePaused`, `receiving`,
  `sendWidth/Height`, `sendFps`, `bitrate` (target), `sentBitrate`,
  `queueMs`, `recvWidth/Height`, `recvFps`, `latencyMs` (their capture to
  arrival here; two clocks, so approximate), `framesSent/Received/Skipped`,
  `keyframesSent`, `keyframeRequests`, `source` (camera name), `encoder`.

**Frames** (Tauri: `video_subscribe` with a `Channel`, raw bytes per
message; HTTP: `GET /api/video`, each frame a u32 LE length then the
frame). One frame, little-endian:

| Bytes | |
|---|---|
| 0 | layout version (1) |
| 1 | source: 0 = the other device, 1 = our self-view (show it mirrored) |
| 2 | flags: bit 0 keyframe |
| 4..36 | peer: whose video (32-byte device key) |
| 36..40 | sequence number |
| 40..48 | capture time, µs since the epoch |
| 48..52 | width, height (u16 each) |
| 52..54 | avcC length, then the H.264 `avcC` record (keyframes only: configure the decoder with it as `description`, codec `avc1.PPCCLL` from its bytes 1–3), then the frame (AVCC: 4-byte big-endian NAL lengths) |

Frames arrive in order, starting at a keyframe. If the webview's decoder
loses its place (an error, or it joined mid-stream), call `video_keyframe`.
`MYCEL_VIDEO=test` replaces the camera with a moving test pattern (headless
runs); `MYCEL_VIDEO_DEBUG=1` logs frames and the rate controller.

`MYCEL_AUDIO` picks the audio backend (hosts and `mycel serve`): unset =
Apple voice processing with echo cancellation on macOS (falls back to plain
devices), `device` = plain default devices, `test[:<hz>]` = a sine tone in
and nothing played (headless testing), `test:bursts[:<hz>]` = tone bursts
that measure the round trip, `test:echo` = send back whatever arrives.
`MYCEL_CALL_DEBUG=1` logs each call's paths once a second.

## Message requests
When someone who isn't your contact adds you, the conversation arrives with `request: true` and `invitedBy` set.
- Until you call `accept_request`, nothing is posted: no profile, no read receipts, no replies.
- `accept_request` makes the inviter a contact.
- `decline_request {block: true}` also refuses future invites from that key at the network layer.

## Answers to contract questions (v0)
- **Leaving:** call `remove_member(id, myId)`. Anyone can leave; the last admin can't. Leaving doesn't rotate keys itself; the next writer automatically rotates to a key the leaver doesn't have.
- **Contact codes** are opaque strings: `mycel:` + base64url(signed contact card). Paste them as-is.
- **Untitled groups** show the members' names. Renaming makes a conversation a group. `create_conversation` always creates a new conversation.
- **Keepers** don't count toward `delivered` or `read`; they only make `sent` possible while everyone else is offline.
- **`localPath`** is a filesystem path under the data dir: `files/<blob>/<name>`. Senders also get a decrypted copy there.
- **`fetch_attachment`** resolves after the file is downloaded and decrypted, and also emits `blobReady`.
- **Deleted messages** come back with an empty body and no attachments or reactions.
- **Typing:** your own typing events are never echoed back to you.
- **Pagination:** `list_messages` returns the newest `limit` messages (default 200) older than `before`.

## HTTP transport (`mycel serve`)
`mycel serve` exposes the same command table on `http://127.0.0.1:<port>`. It refuses to listen on anything but loopback.

| Route | What |
|---|---|
| `POST /api/cmd/<command>` | JSON args → JSON result; errors are `400 {"error": "..."}`. Requires the header `X-Mycel: 1`. |
| `GET /api/events` | Server-Sent Events, one JSON `Event` per message |
| `GET /api/video` | Video frames (see **Video**): one long binary response, each frame a u32 LE length then the frame |
| `POST /api/upload?name=<file>` | Raw body, streamed to disk with no size limit → `{"path": "..."}` to pass in `attachments`. Requires `X-Mycel: 1`. |
| `GET /api/file?path=<path>` | Serves attachment files under the data dir only (sandboxed, nosniff). Streamed, with `Range` support |
| `GET /api/boot.js` | Tells `@mycel/sdk` to use the HTTP transport |

**Security:**
- The `Host` header must be a loopback host, which blocks DNS rebinding.
- Every route requires the per-run token. It's embedded in the page `mycel serve` returns, so other origins can't read it. Fetch calls send it as the `X-Mycel` header; EventSource and `<img>` requests send it as `?t=`. The CLI reads it from `<data>/http-token`, which has mode `0600`.
