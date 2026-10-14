//! Public, serializable API types of the Mycel runtime.
//!
//! This is the contract between the Rust core and every UI: the Tauri host
//! exposes these as commands/events and `@mycel/sdk` mirrors them in
//! TypeScript (see docs/RUNTIME_API.md). All ids are lowercase hex strings so
//! they survive JSON unchanged.

use serde::{Deserialize, Serialize};

pub use mycel_call::{CallInfo, CallPhase, CallStats, Direction as CallDirection, EndReason as CallEndReason};
pub use mycel_net::{LinkStatus, PathKind};

/// Hex-encoded 32-byte Ed25519 public key (device id = Iroh endpoint id).
pub type PeerId = String;
/// Hex-encoded Space id.
pub type ConversationId = String;
/// Hex-encoded envelope id of the message entry.
pub type MessageId = String;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: PeerId,
    pub name: String,
    /// Shareable code: give it to someone so they can add you as a contact.
    pub contact_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub id: PeerId,
    pub name: String,
    /// Currently visible on the local network (mDNS).
    pub nearby: bool,
    /// We have an open/recent connection to them.
    pub online: bool,
}

/// Someone advertising on the local network, not necessarily a contact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbyPeer {
    pub id: PeerId,
    pub name: String,
    pub is_contact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MemberRole {
    Admin,
    Member,
    ReadOnly,
    Keeper,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: PeerId,
    pub name: String,
    pub role: MemberRole,
    pub is_me: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSummary {
    pub id: ConversationId,
    /// Original spaces represented by this logical conversation. Old IDs
    /// remain valid aliases; message operations retain their source space.
    #[serde(default)]
    pub aliases: Vec<ConversationId>,
    /// Stable local UI/notification identity, independent of transport and
    /// independently created direct-space IDs. Never used as a wire space ID.
    #[serde(default)]
    pub thread_key: String,
    pub title: String,
    /// True for a 1:1 conversation.
    pub direct: bool,
    pub members: Vec<Member>,
    pub last_message: Option<MessageView>,
    pub unread: u32,
    /// False once we've been removed (history stays readable locally).
    pub active: bool,
    pub my_role: Option<MemberRole>,
    /// A message request: someone who isn't a contact added you. Accept to
    /// reply (and add them as a contact), or decline / block.
    pub request: bool,
    /// Who added you (for requests).
    pub invited_by: Option<PeerId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    /// Hex BLAKE3 of the encrypted blob.
    pub blob: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// Present once the blob is available locally.
    pub local_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reaction {
    pub emoji: String,
    pub by: Vec<PeerId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Delivery {
    /// Written locally, not yet seen by any other member or keeper.
    Local,
    /// At least one other device (member or keeper) holds it.
    Sent,
    /// Every other member has it.
    Delivered,
    /// Every other member has read up to it.
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    pub id: MessageId,
    pub conversation: ConversationId,
    pub author: PeerId,
    pub author_name: String,
    /// Author's claimed wall clock (ms since epoch). Display only.
    pub sent_at: u64,
    pub body: String,
    pub reply_to: Option<MessageId>,
    pub edited: bool,
    pub deleted: bool,
    pub attachments: Vec<Attachment>,
    pub reactions: Vec<Reaction>,
    pub is_mine: bool,
    /// Only meaningful for my own messages.
    pub delivery: Delivery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkMode {
    /// Loopback only (tests).
    Local,
    /// Local network via mDNS, no internet needed.
    Lan,
    /// LAN + internet relays and DNS discovery.
    Internet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub mode: NetworkMode,
    /// The mode the next launch will use (differs from `mode` until restart).
    pub next_mode: NetworkMode,
    pub online_peers: Vec<PeerId>,
    /// Peers reachable without the internet (same network, peer-to-peer
    /// Wi-Fi or Bluetooth).
    pub nearby_peers: u32,
    /// Local addresses we're listening on (diagnostics).
    pub addresses: Vec<String>,
    /// Peer-to-peer Wi-Fi and Bluetooth: working or why not.
    pub links: Vec<LinkStatus>,
    /// How each reachable peer can be reached, and which path is in use.
    pub peers: Vec<PeerPaths>,
}

/// Paths to one peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerPaths {
    pub id: PeerId,
    pub name: String,
    pub online: bool,
    /// The path the last exchange used.
    pub via: Option<PathKind>,
    /// Paths currently available without the internet.
    pub available: Vec<PathKind>,
    /// When `via` is the mesh: the nearby device it goes through, and hops.
    pub mesh: Option<MeshVia>,
}

/// A mesh route: "Mesh (via Bob, 2 hops)".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshVia {
    /// The neighbour it leaves through (never needs to be a contact).
    pub via: PeerId,
    pub via_name: String,
    /// Hops to the peer (2 = one device in between; 0 = unknown, beyond a
    /// gateway).
    pub hops: u8,
    /// Through a gateway and the internet (`via` is the gateway).
    pub gateway: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferDirection {
    /// Encrypting an attachment we're sending.
    Upload,
    /// Downloading an attachment someone sent.
    Download,
}

/// Something the user should know about: a problem Mycel recovered from, or
/// one that is still going on. [`crate::Runtime::notices`] lists the current
/// ones; [`Event::NoticesChanged`] says the list changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Notice {
    /// This profile's identity isn't on this device (the profile was restored
    /// or moved from another device), so Mycel started a new identity:
    /// contacts need the new contact code. The old profile is kept, unchanged,
    /// in the folder `kept_in`.
    #[serde(rename_all = "camelCase")]
    IdentityReplaced { kept_in: String },
    /// The saved network choice couldn't be read, so Mycel uses local paths
    /// only (the most private choice) until another one is chosen.
    NetworkModeReset,
    /// `count` saved records couldn't be read. They were set aside (kept, not
    /// deleted) so Mycel could start; the conversations they belong to may
    /// miss some history until peers sync it again.
    #[serde(rename_all = "camelCase")]
    RecordsSetAside { count: u64 },
    /// Saving to this device is failing (for example, storage is full). Mycel
    /// keeps retrying; new messages can't be sent until saving works again.
    #[serde(rename_all = "camelCase")]
    StorageFailing { error: String },
}

/// What a local alert is about. A native shell shows each kind as one fixed,
/// generic sentence: no names, message text or IDs ever reach the OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertKind {
    Message,
    MessageRequest,
    GroupInvitation,
    IncomingCall,
    MissedCall,
}

/// A private local alert for the native shell. The chat layer has already
/// decided it is news; every string here is an opaque local key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub kind: AlertKind,
    /// What the alert is about (a conversation's stable thread key). A
    /// thread's alerts are withdrawn together and suppressed while it is on
    /// screen (`Runtime::alert_thread` maps what the app shows to a thread).
    pub thread: String,
    /// A later alert with the same key replaces this one.
    pub key: String,
    /// What a tap opens, resolved again through `Runtime::alert_route` when
    /// tapped (it may have moved, or be gone).
    pub target: String,
    /// Also show it while the app is focused on something else. False when
    /// the app has its own UI for it (an incoming call rings in the app).
    pub foreground: bool,
}

/// Pushed to UIs (Tauri event `mycel://event`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    /// Anything about a conversation changed (messages, members, receipts).
    #[serde(rename_all = "camelCase")]
    ConversationUpdated { conversation: ConversationId },
    /// We were added to a new conversation.
    #[serde(rename_all = "camelCase")]
    ConversationAdded { conversation: ConversationId },
    #[serde(rename_all = "camelCase")]
    Typing { conversation: ConversationId, peer: PeerId },
    ContactsChanged,
    NearbyChanged,
    NetworkChanged,
    #[serde(rename_all = "camelCase")]
    BlobReady { blob: String },
    /// An attachment transfer moved forward (at most every 250 ms, plus a
    /// final event with `done == total`). `id` is the path passed to
    /// `send_message` for uploads, and the blob id for downloads. `rate` is
    /// bytes per second over the last few seconds.
    #[serde(rename_all = "camelCase")]
    TransferProgress { direction: TransferDirection, id: String, done: u64, total: u64, rate: u64 },
    /// Someone is calling: show Accept / Decline.
    #[serde(rename_all = "camelCase")]
    CallIncoming { call: CallInfo },
    /// A call changed: state, path, bitrate, mute; about 10 times a second
    /// while active (for the duration and level meters).
    #[serde(rename_all = "camelCase")]
    CallUpdated { call: CallInfo },
    /// The list of [`Notice`]s changed: fetch it again with `notices`.
    NoticesChanged,
    /// For the native shell, not apps (hosts don't forward it): show a
    /// private local alert.
    #[serde(rename_all = "camelCase")]
    Alert { alert: Alert },
    /// For the native shell: take back delivered alerts, all of `thread`'s,
    /// or only the one with `key`.
    #[serde(rename_all = "camelCase")]
    AlertWithdrawn { thread: String, key: Option<String> },
}

impl Event {
    /// Shell-only events (alerts) that hosts handle themselves instead of
    /// forwarding to apps.
    pub fn is_for_shell(&self) -> bool {
        matches!(self, Event::Alert { .. } | Event::AlertWithdrawn { .. })
    }
}
