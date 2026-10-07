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
    pub fn send_message(&self, id: ConversationId, body: String, reply_to: Option<MessageId>, attachments: Vec<String> /* file paths */) -> Result<MessageView>;
    pub fn edit_message(&self, id: ConversationId, message: MessageId, body: String) -> Result<()>;
    pub fn delete_message(&self, id: ConversationId, message: MessageId) -> Result<()>;
    pub fn toggle_reaction(&self, id: ConversationId, message: MessageId, emoji: String) -> Result<()>;
    pub fn mark_read(&self, id: ConversationId) -> Result<()>;
    pub fn set_typing(&self, id: ConversationId) -> Result<()>;
    pub fn add_members(&self, id: ConversationId, members: Vec<PeerId>) -> Result<()>;
    pub fn remove_member(&self, id: ConversationId, member: PeerId) -> Result<()>;
    pub fn add_keeper(&self, id: ConversationId, keeper: PeerId) -> Result<()>;   // keeper must be a contact
    pub fn rename_conversation(&self, id: ConversationId, title: String) -> Result<()>;
    pub async fn fetch_attachment(&self, blob: String) -> Result<String>;       // local file path
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

Errors are rejected promises carrying a human-readable string.

**Event:** the Tauri event `mycel://event` carries one `Event` (tagged by `type`): `conversationUpdated`, `conversationAdded`, `typing`, `contactsChanged`, `nearbyChanged`, `networkChanged`, `blobReady`.

## Semantics the UI can rely on
- **Instant local writes:** `send_message` returns as soon as the message is written locally (`delivery: "local"`). It moves to `sent`, then `delivered`, then `read` as peers sync, and each step emits `conversationUpdated`.
- **Direct conversations:** a conversation with exactly one other member and no title is `direct`. Its title is the other person's name.
- **Author-only edits and deletes:** only the author can edit or delete a message. Others' attempts are ignored by every peer.
- **Typing is ephemeral:** a `typing` event should be shown for about 4 seconds.
- **Message order:** messages arrive in causal order. `sentAt` is display-only (the author's clock).
- **Attachments are lazy:** an attachment's `localPath` is `null` until fetched. Call `fetch_attachment`, then wait for `blobReady`.
- **Offline-first:** everything works with no network at all. Peers on the same LAN find each other via mDNS with no internet.
