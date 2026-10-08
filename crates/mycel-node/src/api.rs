//! Public, serializable API types of the Mycel runtime.
//!
//! This is the contract between the Rust core and every UI: the Tauri host
//! exposes these as commands/events and `@mycel/sdk` mirrors them in
//! TypeScript (see docs/RUNTIME_API.md). All ids are lowercase hex strings so
//! they survive JSON unchanged.

use serde::{Deserialize, Serialize};

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
}

/// Pushed to UIs (Tauri event `mycel://event`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
}
