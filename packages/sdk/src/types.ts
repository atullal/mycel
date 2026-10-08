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
 */
export type PathKind = "network" | "peerWifi" | "bluetooth" | "relay";

/** A non-IP link (peer-to-peer Wi-Fi, Bluetooth). */
export interface LinkStatus {
  kind: PathKind;
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
  | { type: "blobReady"; blob: string };

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
] as const;
