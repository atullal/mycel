# Mycel runtime API

This is the reference for the API that apps and hosts use to talk to the Mycel
runtime: its commands, events and data types. The same commands are reachable
from Rust, as Tauri commands in the native host, over the local HTTP API of
`mycel serve`, and through the TypeScript SDK. It is for people who build an
app on Mycel or put a new host around the runtime.

Mycel is experimental and unaudited. This document describes the v0 runtime
contract.

## Contents

- [Overview](#overview)
- [Commands](#commands)
- [Events](#events)
- [Types](#types)
- [Behaviour](#behaviour)
- [Calls](#calls)
- [HTTP API](#http-api)
- [TypeScript SDK](#typescript-sdk)
- [Rust API](#rust-api)
- [Shell alerts](#shell-alerts)

## Overview

One runtime, `mycel_node::Runtime`, holds a device's identity, conversations
and connections. Every transport ends in the same `Runtime` methods:

| Transport | Commands | Events |
|---|---|---|
| Rust | methods on `Runtime` | `Runtime::subscribe()` |
| Tauri (the native host) | `invoke("<command>", args)` | the Tauri event `mycel://event` |
| HTTP (`mycel serve`) | `POST /api/cmd/<command>` | `GET /api/events` (Server-Sent Events) |
| TypeScript SDK (`@mycel/sdk`) | methods on the `mycel` client | `mycel.on(type, handler)` |

The SDK uses the Tauri transport inside the host and the HTTP transport on a
page served by `mycel serve`. Anywhere else it falls back to an in-memory mock.

The API is defined in these files:

| File | Contents |
|---|---|
| `crates/mycel-node/src/api.rs` | the data types and events |
| `crates/mycel-node/src/runtime.rs` | `Runtime`, the implementation |
| `crates/mycel-node/src/dispatch.rs` | commands by name with JSON arguments (HTTP) |
| `apps/host/src-tauri/src/commands.rs` | the Tauri commands |
| `crates/mycel-cli/src/main.rs` | `mycel serve` and its HTTP routes |
| `packages/sdk/src/types.ts`, `client.ts`, `transport.ts` | the SDK's mirror of the above |

### Conventions

- Command names are snake_case. JSON field names, argument names and enum
  values are camelCase (`replyTo`, `"readOnly"`).
- A command's arguments are the fields of one JSON object. A field marked `?`
  may be left out. A command without arguments takes `{}`.
- A result of `null` means the command returns nothing.
- Ids are lowercase hex strings. A `PeerId` is a device's 32-byte Ed25519
  public key, a `ConversationId` is a space id, and a `MessageId` is the
  envelope id of the message's entry.
- Timestamps are milliseconds since the Unix epoch.

### Errors

A failed command yields one human-readable string that includes its cause:

```text
macOS didn't let Mycel read /Users/me/Desktop/x.mov. Allow Mycel in System Settings > Privacy & Security > Files and Folders (or Full Disk Access), then try again: Operation not permitted (os error 1)
```

There are no error codes.

| Transport | A failure is |
|---|---|
| Rust | `Err(anyhow::Error)` |
| Tauri | a rejected promise carrying the string |
| HTTP | status `400` with the body `{"error": "..."}` |
| SDK | a rejected promise carrying an `Error` with the string as its message |

### Examples

With the SDK:

```ts
import { mycel } from "@mycel/sdk";

const chat = await mycel.chat.create(null, [contactId]);
await mycel.chat.send(chat.id, "hello");
const stop = mycel.on("conversationUpdated", (e) => {
  console.log(e.conversation);
});
```

Against a running `mycel serve`, from a terminal:

```sh
mycel call list_conversations
mycel call send_message '{"id": "<conversation id>", "body": "hello"}'
```

From Rust:

```rust
use mycel_node::{Runtime, api::NetworkMode};

let rt = Runtime::open("/path/to/data", NetworkMode::Lan, None).await?;
let mut events = rt.subscribe();
let profile = rt.profile();
```

## Commands

Every command below exists on every transport, except where a section says
otherwise. In the tables, `id` is a `ConversationId`, `message` a `MessageId`
and `call` a call id, unless a type is given.

### Profile and contacts

| Command | Arguments | Result | Description |
|---|---|---|---|
| `get_profile` | none | `Profile` | This device's id, name and contact codes. |
| `set_name` | `name: string` | `Profile` | Sets the display name and announces it in every conversation. |
| `add_contact` | `code: string` | `Contact` | Adds a contact from a [contact code](#contact-codes). |
| `add_nearby_contact` | `id: PeerId` | `Contact` | Fetches a nearby device's signed card and adds it as a contact. |
| `remove_contact` | `id: PeerId` | `null` | Removes a contact. |
| `list_contacts` | none | `Contact[]` | The contacts, sorted by name. |
| `list_nearby` | none | `NearbyPeer[]` | Devices discovered nearby, contacts or not, sorted by name. |

`set_name` trims the name, keeps its first 64 characters and refuses an empty
one.

### Network and notices

| Command | Arguments | Result | Description |
|---|---|---|---|
| `network_status` | none | `NetworkStatus` | The network mode, reachable peers, links and relaying. |
| `set_network_mode` | `mode: NetworkMode` | `NetworkStatus` | Saves the mode for the next start. |
| `list_notices` | none | `Notice[]` | Problems the user should know about. See [Notices](#notices). |
| `dismiss_notice` | `notice: Notice` | `null` | Stops reporting a notice the user has seen. |

`set_network_mode` accepts `lan` and `internet`. The mode is fixed while the
runtime runs, so the result's `nextMode` changes and its `mode` does not.

### Conversations

| Command | Arguments | Result | Description |
|---|---|---|---|
| `list_conversations` | none | `ConversationSummary[]` | The conversations, newest activity first. |
| `get_conversation` | `id` | `ConversationSummary` | One conversation. |
| `create_conversation` | `title?: string`, `members: PeerId[]` | `ConversationSummary` | Starts a direct chat or a group. |
| `rename_conversation` | `id`, `title: string` | `null` | Names a group. Admins only. |
| `add_members` | `id`, `members: PeerId[]` | `null` | Adds contacts to a group. Admins only. |
| `remove_member` | `id`, `member: PeerId` | `null` | Removes a member (admins), or leaves when `member` is this device. |
| `add_keeper` | `id`, `keeper: PeerId` | `null` | Adds a contact as a keeper. Admins only. |
| `mark_read` | `id` | `null` | Marks the conversation read up to its newest message. |
| `set_typing` | `id` | `null` | Tells the other members that this user is typing. |

One member and no title makes a direct chat. What these commands do in a
direct chat is described under [Direct conversations](#direct-conversations),
and the rest under [Groups and membership](#groups-and-membership).

### Message requests

| Command | Arguments | Result | Description |
|---|---|---|---|
| `accept_request` | `id` | `ConversationSummary` | Accepts a message request. The inviter becomes a contact. |
| `decline_request` | `id`, `block?: boolean` | `null` | Declines a message request and leaves the conversation. |

[How message requests work](#how-message-requests-work) says what a request
is.

### Messages

| Command | Arguments | Result | Description |
|---|---|---|---|
| `list_messages` | `id`, `limit?: number`, `before?: MessageId` | `MessageView[]` | A page of messages, oldest first. |
| `messages_around` | `id`, `message`, `before?: number`, `after?: number` | `MessageWindow` | The messages around one message. |
| `search_messages` | `id`, `query: string`, `limit?: number` | `MessageView[]` | The messages that match a query, newest first. |
| `send_message` | `id`, `body: string`, `replyTo?: MessageId`, `attachments?: string[]`, `publicAttachments?: string[]` | `MessageView` | Sends a message. |
| `edit_message` | `id`, `message`, `body: string` | `null` | Replaces the text of this user's own message. |
| `delete_message` | `id`, `message` | `null` | Deletes this user's own message for everyone. |
| `delete_message_local` | `id`, `message` | `null` | Hides any message on this device only. |
| `restore_message_local` | `id`, `message` | `null` | Shows a message hidden on this device again. |
| `toggle_reaction` | `id`, `message`, `emoji: string` | `null` | Adds this user's reaction, or removes it if present. |

`attachments` holds file paths and `publicAttachments` names those of them to
send as public files; see [How attachments work](#how-attachments-work).
Limits and defaults of the first three commands are under
[Pagination and search](#pagination-and-search).

### Attachments

| Command | Arguments | Result | Description |
|---|---|---|---|
| `fetch_attachment` | `blob: string` | `string` | Downloads and decrypts an attachment and returns its local path. |

A file that has no path, such as a pasted image or a browser `File`, is
handed to the runtime as bytes first: with `stage_file` in the
[Tauri host](#host-only-commands), with `POST /api/upload` over
[HTTP](#http-api), or with `mycel.files.stage()` in the SDK, which uses
whichever applies. Each returns a path to pass in `attachments`.

### Call commands

| Command | Arguments | Result | Description |
|---|---|---|---|
| `start_call` | `conversation: ConversationId`, `video?: boolean` | `CallInfo` | Rings the conversation, or joins its call if there is one. |
| `accept_call` | `call`, `video?: boolean` | `CallInfo` | Answers a ringing call, or joins a `joinable` one. |
| `decline_call` | `call` | `null` | Declines a ringing call. |
| `end_call` | `call` | `null` | Hangs up, or cancels a call that has not been answered. |
| `set_muted` | `call`, `muted: boolean` | `CallInfo` | Mutes or unmutes the microphone. |
| `set_camera` | `call`, `on: boolean` | `CallInfo` | Turns the camera on or off. |
| `video_keyframe` | `call`, `source?: string` | `null` | Asks for fresh keyframes after a decoder lost its place. |
| `call_status` | none | `CallInfo[]` | Live calls, and calls that ended in the last 10 seconds. |

`video_keyframe`'s `source` is `"local"` for the self-view or `"remote"` for
everyone else's video. Without it, both are refreshed. [Calls](#calls)
describes how calls behave.

### Sync

| Command | Arguments | Result | Description |
|---|---|---|---|
| `sync_now` | none | `null` | Syncs every conversation with every reachable member now. |

`sync_now` is available over HTTP and from Rust (`Runtime::sync_now`). The
Tauri host does not register it and the SDK has no method for it.

### Host-only commands

The Tauri host registers these in addition. They are not in the HTTP
dispatcher. Apps reach them through the SDK methods named here.

| Command | Arguments | Result | Description |
|---|---|---|---|
| `restart_app` | none | `null` | Relaunches the app, so a new network mode takes effect. SDK: `network.restart()`. |
| `open_file` | `path: string` | `null` | Opens a downloaded attachment. SDK: `files.open()` on phones. |
| `stage_file` | the file's bytes as the request body | `string` | Saves bytes as a file that can be attached. SDK: `files.stage()`. |
| `video_subscribe` | `channel` | `null` | Streams [video frames](#video-frame-format) on a Tauri channel. SDK: `calls.onVideo()`. |
| `video_targets` | none | `Targets` or `null` | What the web view should encode its camera to. |
| `video_push` | one encoded frame as the request body | `Targets` or `null` | Hands the runtime a frame the web view encoded. |

`open_file` only opens files under the data directory's `files/` folder. It
shows the share sheet on iPhone and iPad, an "Open with" chooser on Android,
and uses the default app on a computer.

`stage_file` takes the file name, URI-encoded, in the `x-mycel-name` header
and returns a path to pass in `attachments`. A later call with that path,
URI-encoded, in the `x-mycel-append` header appends its body to the staged
file, so a large file can arrive in pieces. On Android, where the web view can
only send JSON, the bytes travel as `{"base64": "..."}`.

`video_targets` and `video_push` serve the platforms where the web view
captures the camera; see [Video](#video). `Targets` is
`{ width, height, fps, bitrate, keyframe }`. Only one `video_subscribe`
subscription is live at a time: a new one replaces the previous one.

The host also registers `prepare_notifications`, `set_notification_context`,
`notification_target` and `take_notification_action` for its own shell UI.
They are not part of the app API.

## Events

An event is a JSON object tagged by `type`.

| Event | Fields | Meaning |
|---|---|---|
| `conversationUpdated` | `conversation` | Something about a conversation changed: messages, members, receipts. |
| `conversationAdded` | `conversation` | A conversation was created here, or this device was added to one. |
| `typing` | `conversation`, `peer` | The member `peer` is typing. |
| `contactsChanged` | none | The contact list, or a contact's state, changed. |
| `nearbyChanged` | none | The devices nearby changed. |
| `networkChanged` | none | The network status changed. |
| `blobReady` | `blob` | An attachment finished downloading and has a `localPath`. |
| `transferProgress` | `direction`, `id`, `done`, `total`, `rate` | An attachment transfer moved forward. See [Transfer progress](#transfer-progress). |
| `callIncoming` | `call: CallInfo` | Someone is calling: offer to accept or decline. |
| `callUpdated` | `call: CallInfo` | A call changed. About 10 times a second while `active`. |
| `noticesChanged` | none | The list of notices changed. |

Apart from the call events, an event says what changed, not what it changed
to: fetch the data again. `conversation` is the conversation's current `id`.
There is no event for a change of this device's own name; `set_name` returns
the new profile.

If the Tauri host falls behind and drops events, it sends `contactsChanged`,
`nearbyChanged`, `networkChanged`, `noticesChanged` and a
`conversationUpdated` for every conversation, so a UI that re-fetches on
events recovers.

Two further events, `alert` and `alertWithdrawn`, are for native shells and
never reach apps. See [Shell alerts](#shell-alerts).

## Types

Field names are as they appear in JSON. The Rust definitions are in
`crates/mycel-node/src/api.rs` and the TypeScript ones in
`packages/sdk/src/types.ts`. The call types are under [Calls](#calls).

### `Profile`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | This device's id. |
| `name` | `string` | The display name. |
| `contactCode` | `string` | The short [contact code](#contact-codes). |
| `contactCodeFull` | `string` | The full contact code. The SDK's mock leaves it out. |

### `Contact`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | The contact's device. |
| `name` | `string` | Their name. |
| `nearby` | `boolean` | Discovered on the local network or over a direct device link. |
| `online` | `boolean` | There is an open or recent connection to them. |
| `awaitingKeys` | `boolean` | Added from a short contact code whose keys have not been fetched yet. |

### `NearbyPeer`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | The device. |
| `name` | `string` | The name it announces. |
| `isContact` | `boolean` | It is already a contact. |

### `ConversationSummary`

| Field | Type | Meaning |
|---|---|---|
| `id` | `ConversationId` | The conversation's id: the lowest of `aliases`. |
| `aliases` | `ConversationId[]` | Every space shown as this conversation, `id` included. |
| `threadKey` | `string` | A stable local identity for UI state and notifications. Never a space id. |
| `title` | `string` | The title, or the other members' names if there is none. |
| `direct` | `boolean` | A conversation between two people. |
| `members` | `Member[]` | The members, this device first, then by name. |
| `lastMessage` | `MessageView` or `null` | The newest message that is neither deleted nor hidden here. |
| `unread` | `number` | Messages from others after this device's read marker. |
| `active` | `boolean` | False once this device has left or been removed. |
| `myRole` | `MemberRole` or `null` | This device's role; `null` when not a member. |
| `request` | `boolean` | A [message request](#how-message-requests-work) not yet accepted. |
| `invitedBy` | `PeerId` or `null` | Who added this device, for a request. |

### `Member`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | The member's device. |
| `name` | `string` | Their name. A keeper's ends in ` (keeper)`. |
| `role` | `MemberRole` | `admin`, `member`, `readOnly` or `keeper`. |
| `isMe` | `boolean` | This device. |

### `MessageView`

| Field | Type | Meaning |
|---|---|---|
| `id` | `MessageId` | The message. |
| `conversation` | `ConversationId` | The space the message was written in. |
| `author` | `PeerId` | Who wrote it. |
| `authorName` | `string` | Their name. |
| `sentAt` | `number` | The author's clock when it was written. Display only. |
| `body` | `string` | The text. |
| `replyTo` | `MessageId` or `null` | The message it replies to. |
| `edited` | `boolean` | The author edited it. |
| `deleted` | `boolean` | The author deleted it. |
| `attachments` | `Attachment[]` | Its files. |
| `reactions` | `Reaction[]` | Its reactions. |
| `isMine` | `boolean` | This device wrote it. |
| `delivery` | `Delivery` | How far it has got. Only meaningful when `isMine`. |

`Delivery` is one of:

| Value | Meaning |
|---|---|
| `local` | Written on this device; no other member or keeper has it yet. |
| `sent` | At least one other device, member or keeper, holds it. |
| `delivered` | Every other member has it. |
| `read` | Every other member has read up to it. |

A `Reaction` is `{ emoji: string, by: PeerId[] }`.

### `Attachment`

| Field | Type | Meaning |
|---|---|---|
| `blob` | `string` | The attachment's id: the hex BLAKE3 hash of its encrypted form. |
| `name` | `string` | The file name, made safe to use as one path component. |
| `mime` | `string` | The MIME type. |
| `size` | `number` | The size in bytes. |
| `localPath` | `string` or `null` | Where the file is on this device, once it is. |
| `public` | `boolean` | It was sent as a [public file](#how-attachments-work). |

### `MessageWindow`

| Field | Type | Meaning |
|---|---|---|
| `messages` | `MessageView[]` | The window, oldest first. |
| `hasEarlier` | `boolean` | Older messages exist before the window. |
| `hasLater` | `boolean` | Newer messages exist after it. |

### `NetworkStatus`

| Field | Type | Meaning |
|---|---|---|
| `mode` | `NetworkMode` | The mode in use. |
| `nextMode` | `NetworkMode` | The mode the next start will use. |
| `onlinePeers` | `PeerId[]` | The peers with an open or recent connection. |
| `nearbyPeers` | `number` | Peers reachable without the internet. |
| `addresses` | `string[]` | The local addresses the device listens on, for diagnostics. |
| `links` | `LinkStatus[]` | Each link: working, or why not. |
| `peers` | `PeerPaths[]` | How each reachable peer can be reached. Online first, then by name. |
| `relay` | `RelayInfo` | What this device does about relaying over the internet. |

`NetworkMode` is one of:

| Value | Meaning |
|---|---|
| `local` | Loopback only, for tests. `set_network_mode` refuses it. |
| `lan` | Local paths only: the same network, peer-to-peer Wi-Fi, Bluetooth. Never the internet. |
| `internet` | Every path: the local ones plus internet relays and discovery. |

### `RelayInfo`

`NetworkStatus.relay` describes relaying over the internet between devices
that cannot dial each other.

| Field | Type | Meaning |
|---|---|---|
| `relaying` | `boolean` | The internet can dial in to this device, and it relays for devices that ask. |
| `clients` | `number` | How many devices it is relaying for. |
| `relays` | `string[]` | The names of the devices that relay for this one. |
| `metered` | `boolean` | Its connection is paid for by the byte (mobile data), so it carries nobody else's traffic over it. |

While `relaying` is true, the device's IP address is published under its key.
`relays` is filled when the internet cannot dial in to this device and no
relay server is connected.

### `LinkStatus`

| Field | Type | Meaning |
|---|---|---|
| `kind` | `PathKind` | Which kind of link. |
| `label` | `string` | What exactly it is. Left out when the kind says enough. |
| `active` | `boolean` | It is working: advertising and discovering. |
| `detail` | `string` or `null` | Why it is not working, in words the user can act on. |
| `peers` | `number` | Devices reachable over it right now. |

### `PeerPaths`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | The peer. |
| `name` | `string` | Their name. |
| `online` | `boolean` | There is an open or recent connection to them. |
| `via` | `PathKind` or `null` | The path the last exchange used. |
| `available` | `PathKind[]` | The paths available without the internet. |
| `mesh` | `MeshVia` or `null` | The route, when `via` is `mesh`. |

A `MeshVia` describes a mesh route:

| Field | Type | Meaning |
|---|---|---|
| `via` | `PeerId` | The neighbour the route leaves through. It need not be a contact. |
| `viaName` | `string` | That neighbour's name. |
| `hops` | `number` | Hops to the peer: 2 means one device in between, 0 means unknown. |
| `gateway` | `boolean` | The route goes through a gateway and the internet; `via` is the gateway. |

### `PathKind`

| Value | Meaning |
|---|---|
| `network` | The same Wi-Fi, Ethernet or cable network, or a direct connection over the internet. |
| `peerWifi` | Apple peer-to-peer Wi-Fi. No shared network needed. |
| `bluetooth` | Bluetooth LE. |
| `relay` | Through an internet relay, end-to-end encrypted. |
| `wifiDirect` | A Wi-Fi Direct group. |
| `uwb` | An ultra-wideband radio. |
| `ieee802154` | A low-power IEEE 802.15.4 radio: Thread, 6LoWPAN. |
| `ethernet` | A cable: Ethernet, Thunderbolt or a USB bridge. |
| `other` | Any other network interface; `LinkStatus.label` names it. |
| `mesh` | Relayed hop by hop by other nearby Mycel devices, which cannot read it. |

### `Notice`

A notice is tagged by `kind`. [Notices](#notices) says when each appears.

| Kind | Fields | Meaning |
|---|---|---|
| `identityReplaced` | `keptIn: string` | A new identity was started; the old profile is kept in the folder `keptIn`. |
| `networkModeReset` | none | The saved network mode could not be read, so only local paths are used. |
| `recordsSetAside` | `count: number` | `count` stored records could not be read and were set aside, not deleted. |
| `storageFailing` | `error: string` | Saving to this device is failing and being retried. |

## Behaviour

### Sending and delivery

`send_message` returns as soon as the message is written on this device, with
`delivery: "local"`. The message then moves to `sent`, `delivered` and `read`
as peers sync, and each step emits `conversationUpdated`. Keepers do not count
towards `delivered` or `read`. They only make `sent` possible while everyone
else is offline.

A message needs a body or at least one attachment. A reply is written to the
space that holds the message it replies to.

Messages arrive in causal order. `sentAt` comes from the author's clock and is
for display only.

Only the author can edit or delete a message. The commands refuse anyone
else's message, and every peer ignores such an edit or delete if one arrives.
A deleted message comes back with `deleted: true`, an empty body and no
attachments or reactions.

`delete_message_local` hides a message on this device and sends nothing.
`restore_message_local` undoes that. It cannot bring back a message its author
deleted.

A `typing` event should be shown for about 4 seconds. A device's own typing is
never echoed back to it.

Everything works with no network at all. Peers on the same local network find
each other through mDNS, with no internet.

### Direct conversations

A conversation with exactly one other member and no title is `direct`. Its
title is the other person's name.

Two people can each start a direct chat before their devices meet, so one pair
can own several two-person spaces. They show as one conversation:

- `id` is the lowest of its `aliases`, and every alias is a valid id.
- `threadKey` is derived from the two signing keys and stays the same
  whichever spaces exist.
- A message stays in the space it was written in
  (`MessageView.conversation`). New messages and calls go to the lowest space
  both people can write in, which both devices choose alike.
- The timeline keeps each space's causal order and never places a message
  before this device first saw its space, so a space that turns up later
  cannot backdate messages into existing history.

Only original private chats merge. Requests, declined invitations and anything
ever named, marked a group or joined by a third person stay apart. The rules
are in `mycel_kit_chat::thread`.

`create_conversation` with one member and no title returns the existing direct
chat with that person, if there is one this device can still write in. In
every other case it creates a new conversation.

Administering a direct chat never splits it:

- `add_members` starts a new group with both people and those added, and
  `conversationAdded` announces it. The direct chat's history is not shared
  with them.
- `rename_conversation` and removing the other person are refused.
- Leaving leaves every alias, or none if this device is the last admin of any
  of them.
- `add_keeper` adds the keeper to every alias this device administers.

After leaving, the chat's history is one inactive conversation. Its
`threadKey` differs from that of a new chat with the same person.

### Groups and membership

A conversation without a title shows its members' names, or `Just you` when
there is nobody else. Renaming makes a conversation a group.

`create_conversation`, `add_members` and `add_keeper` take contacts only.
Admins add and remove members, add keepers and rename.

To leave, call `remove_member` with this device's own id. Anyone can leave
except the last admin. Leaving does not rotate keys itself: the next writer
rotates to a key the leaver does not have.

After this device leaves or is removed, the conversation has `active: false`
and its history stays readable on this device.

A keeper is a member with the role `keeper`: it stores and relays the
conversation's encrypted data and cannot read it.
[ARCHITECTURE.md](ARCHITECTURE.md) describes keepers.

### How message requests work

When someone who is not a contact adds this device to a conversation, the
conversation arrives with `request: true` and `invitedBy` set. An invitation
from a contact is an ordinary conversation at once.

Until `accept_request`, this device posts nothing to the conversation: no
profile, no read receipts, no replies. Sending, calling and `fetch_attachment`
fail with an error that says to accept first.

`accept_request` makes the inviter a contact. `decline_request` leaves the
conversation, which then disappears from `list_conversations`. With
`block: true` it also refuses future invitations from that key at the network
layer.

### Contact codes

A contact code is an opaque string that starts with `mycel:`. Pass it to
`add_contact` as it is. It comes in two forms.

`Profile.contactCode` is the short form: the device key and its signed name,
plus address hints. Show it as text and as a QR code. A contact added from it
has `awaitingKeys: true` until this device has reached theirs and fetched its
signed card, unless the two already share a conversation. Until then
`create_conversation`, `add_members` and `add_keeper` fail for that contact
with an error that says so. `contactsChanged` fires when the keys arrive.

`Profile.contactCodeFull`, about 1.8 kB, holds the card itself. A contact
added from it is usable at once, with no connection.

### Pagination and search

`list_messages` returns the newest `limit` messages, oldest first (default
200, at most 10,000). With `before` it returns the newest messages older than
that one. Page back by passing the oldest message returned as the next
`before`.

`messages_around` returns one message with up to `before` older and `after`
newer messages around it (default 25 each, at most 10,000), and says whether
more exist on either side. It opens a conversation at a search hit or a quoted
message.

`search_messages` returns the messages that contain every whitespace-separated
term of `query`, case-insensitively, in their text or an attachment name. It
searches all the history synced to this device, skips deleted messages, and
returns at most `limit` matches, newest first (default 100, at most 1,000).

All three work across a direct chat's aliases and skip messages hidden on this
device. `list_messages` and `messages_around` cost the page, not the history,
at any depth.

The runtime folds new entries into a cached view
(`mycel_kit_chat::ChatState`). A late entry that belongs before ones already
shown takes back only those, up to 1,024, so a busy, long conversation costs
per message, not per history.

### How attachments work

An attachment's `localPath` is `null` until the file is on this device. Call
`fetch_attachment` with the attachment's `blob`. It resolves with the path
after the file is downloaded and decrypted, and emits `blobReady`. The path is
`files/<blob>/<name>` under the data directory. A sender gets a decrypted copy
there too.

Attachments have no size limit. Files are encrypted in pieces with bounded
memory, and each piece is checked when it arrives
([TRUST.md](TRUST.md), section 7c).

- Attachments up to 16 MiB are pushed to members right away. Bigger ones are
  downloaded on `fetch_attachment`, from the sender, a keeper or any member
  that has them. An interrupted download resumes where it stopped.
- If a member cannot be reached when a file is sent, the file is also handed
  to contacts, and to devices nearby on a fast link, that are willing to hold
  it. The member finds it with them later, even if the sender is gone by then.
- A device holds other people's files inside a budget of 1 GiB and lets go of
  the least requested first. The environment variable `MYCEL_FILE_CACHE_MB`
  changes the budget; 0 holds nothing.
- A transfer is refused, with a clear error, if it would leave less than 1 GiB
  of free disk.

`send_message` resolves once the files are encrypted locally. Its
`attachments` accepts:

- local file paths, or `file://` URLs;
- an attachment's own `localPath`, to forward it. If that copy is unchanged,
  the message refers to the same file, so nothing is encrypted again and
  nothing is sent to devices that already have it;
- a folder or a macOS package (`.app`, `.pages`, `.key`, `.rtfd`, …), which is
  sent as `<name>.zip`.

Files staged under the data directory's `uploads/` folder, by `stage_file` or
an HTTP upload, are deleted once the message is sent. The attachment then
lives in `files/`.

Paths listed in `publicAttachments`, which must also be in `attachments`, are
sent as **public files**. A public file is one file wherever it is sent: it is
stored and downloaded once, and kept available by everyone who has it. In
exchange, anyone who has the file can tell that this device sent or holds it.
`Attachment.public` says which attachments were sent this way. Everything else
is private.

### Transfer progress

`transferProgress` reports a transfer as
`{ direction, id, done, total, rate }`:

- `direction` is `"upload"` or `"download"`.
- For an upload, `id` is the exact string passed in `attachments`, and the
  bytes count plaintext encrypted.
- For a download, `id` is the blob id, and the bytes count sealed bytes
  received.
- `rate` is bytes per second over the last 3 seconds.

The event is emitted at most every 250 ms, plus a final one with
`done == total`. The SDK's React hook `useTransfer(id)` returns the latest
`{ done, total, rate }`.

### Notices

A notice is a problem the user should know about: one Mycel recovered from,
or one that is still going on.

- `identityReplaced`: this profile's identity is not on this device, because
  the profile was restored or moved from another device. Mycel started a new
  identity, so contacts need the new contact code. The old profile is kept
  unchanged.
- `networkModeReset`: the saved network mode was unreadable. Mycel uses local
  paths only, the most private choice, until another mode is chosen.
- `recordsSetAside`: some stored records were unreadable. They are kept, not
  deleted, and the conversations they belong to may miss some history until
  peers sync it again.
- `storageFailing`: saving is failing, for example because storage is full.
  Mycel keeps retrying, and new messages cannot be sent until saving works
  again.

The first three come from startup and are never announced by an event, so a
UI fetches `list_notices` once when it starts and again on every
`noticesChanged`.

Startup notices are kept across restarts until `dismiss_notice`, because a
phone may start Mycel in the background where nobody sees them.
`storageFailing` is listed while saving fails. It cannot be dismissed and
clears when saving works again.

## Calls

Calls are live voice and video, between two people or in a group. Audio is
captured and played by the runtime, never by the web view, so the same
commands work in the Tauri host and over `mycel serve`.

`start_call` in a direct conversation rings the other person. In a group it
rings every other member. The command returns while the call is `connecting`.
`callIncoming` announces a call on the devices that ring, and `callUpdated`
reports every change: state, people, path, bitrate, mute.

### Call rules

Ringing needs only the devices to be online. The caller dials each other
device's key directly (ALPN `mycel/call/1` on the node's endpoint), so a call
can use every path: network, peer-to-peer Wi-Fi, Bluetooth, relay, mesh. If
nobody can be reached within a few seconds, the call ends `unavailable`.

A group call is a full mesh. Everyone in the call has a connection to everyone
else. Each audio frame is encoded once per bitrate tier and sent to each
person at the bitrate their path allows. What a person hears is everyone's
voice mixed on their own device, each through its own jitter buffer. There is
no server or host in the middle: whoever started the call can leave, and it
goes on.

At most 8 people can be in a call. Each device sends its voice to every other
one, so upload and CPU grow with the group: 7 × 32 kbps ≈ 0.3 Mbps up at 8
people, too much for Bluetooth. A ninth person gets `full`. A call rings at
most 31 members.

Declining a group call, or letting it ring out, leaves it `joinable` for as
long as it goes on; `joinedCount` says how many are in it. `accept_call`, or
`start_call` in that conversation, joins it. `end_call` leaves; the call goes
on for the others and ends when the last person leaves. `start_call` in a
group that already has a call joins that call instead of starting a second
one.

Only members may call or join. A device rings, or lets someone join or watch
its call, only if both are current members of the conversation and not
keepers, the conversation is not a message request it has not accepted or one
it declined, and the caller is not blocked. Otherwise the call ends `failed`.
Someone removed from a group is dropped from its call within a second.

A device is in one call at a time. A second caller gets `busy`. Answering a
ringing call hangs up the one in progress. If two people call the same
conversation at once, everyone ends up in one call and the other one ends
`replaced`.

The microphone permission is asked for on the first `start_call` or
`accept_call`. If it is denied, the command fails with an error that says
where to allow it. On macOS:

```text
Mycel isn't allowed to use the microphone. Allow it in System Settings > Privacy & Security > Microphone, then call again.
```

### `CallInfo`

| Field | Type | Meaning |
|---|---|---|
| `id` | `string` | The hex call id, bound to the conversation and the caller. |
| `conversation` | `ConversationId` | The conversation the call belongs to. |
| `group` | `boolean` | A group conversation's call: more than two people may join. |
| `title` | `string` or `null` | The group's name, for a group call. |
| `peer` | `PeerId` | 1:1: the other person. Group: who started the call. |
| `peerName` | `string` | Their name; `"You"` if this device started a group call. |
| `direction` | `string` | `outgoing` or `incoming`. |
| `state` | `string` | See [Call states](#call-states). |
| `endReason` | `string` or `null` | See [End reasons](#end-reasons). |
| `error` | `string` or `null` | A human-readable cause where it helps (`failed`, `unavailable`). |
| `startedAt` | `number` | When the call was placed or arrived. |
| `connectedAt` | `number` or `null` | When it became active. |
| `durationMs` | `number` | Talking time so far. |
| `participants` | `Participant[]` | Everyone else in, or rung for, the call. Those who joined come first. |
| `joinedCount` | `number` | People in the call now, this device included if it is in. |
| `activeSpeaker` | `PeerId` or `null` | The loudest person talking right now. |
| `path` | `PathKind` or `null` | The path carrying the call. Group: the path to the first person who joined. |
| `bitrate` | `number` | This device's Opus bitrate in bits/s. Group: see `participants`. |
| `muted` | `boolean` | This device's microphone is muted. |
| `remoteMuted` | `boolean` | 1:1: the other person is muted. Group: see `participants`. |
| `level` | `number` | Microphone level, 0 to 1; 0 while muted. |
| `remoteLevel` | `number` | Level of everything heard, mixed, 0 to 1. |
| `echoCancellation` | `boolean` | Echo cancellation is on. If not, suggest headphones. |
| `stats` | `CallStats` | Live numbers about the call. |
| `video` | `VideoInfo` | Video both ways. In a voice call the camera is `off` and nothing is received. |

The Opus bitrate is 32 kbit/s on fast paths, 24 kbit/s through a relay or the
mesh and 12 kbit/s on Bluetooth, and lower under loss.

### Call states

| State | Meaning |
|---|---|
| `connecting` | Dialling, or answered or joining and starting audio. |
| `ringing` | Their devices are ringing, or this one is. |
| `active` | Talking. |
| `joinable` | A group call this device declined or missed is still going on. `accept_call` joins it. |
| `ended` | Over. `endReason` says why. |

### End reasons

| Reason | Meaning |
|---|---|
| `hungUp` | This device hung up, or cancelled before an answer. |
| `remoteHungUp` | 1:1: they hung up. Group: the last other person left. |
| `declined` | This device declined. |
| `remoteDeclined` | They declined. |
| `busy` | They are in another call. |
| `unavailable` | Nobody could be reached. |
| `noAnswer` | Nobody answered within 45 seconds. |
| `missed` | An incoming call this device did not answer. |
| `replaced` | Two calls started at once and this one merged into the other. Do not show it. |
| `connectionLost` | Every path died and none came back. |
| `micDenied` | Mycel is not allowed to use the microphone. |
| `full` | The call already has 8 people. |
| `failed` | Something else went wrong; `error` says what. |

### `Participant`

| Field | Type | Meaning |
|---|---|---|
| `id` | `PeerId` | The person's device. |
| `name` | `string` | Their name. |
| `state` | `string` | `ringing`, `connecting`, `joined`, `declined`, `missed`, `busy`, `unavailable` or `left`. |
| `muted` | `boolean` | They are muted. |
| `level` | `number` | Level of what they say, 0 to 1. |
| `speaking` | `boolean` | They are talking right now. |
| `path` | `PathKind` or `null` | The path to their device. |
| `bitrate` | `number` | The Opus bitrate sent to them, in bits/s. |
| `rttMs` | `number` | Round-trip time to them. |
| `lossPct` | `number` | Of what is sent to them, the share they reported missing, 0 to 100. |
| `video` | `PeerVideo` | Video with them, both ways. |

### `CallStats`

| Field | Type | Meaning |
|---|---|---|
| `rttMs` | `number` | Round-trip time of the path in use. |
| `lossPct` | `number` | Of what is sent, the share the other side reported missing, 0 to 100. |
| `jitterMs` | `number` | Inter-arrival jitter of what is received. |
| `bufferMs` | `number` | Audio held in the jitter buffer. |
| `latencyMs` | `number` | Estimated mouth-to-ear delay of what is heard. |
| `framesSent`, `framesReceived` | `number` | Audio frames sent and received. |
| `framesLost`, `framesLate` | `number` | Frames that never arrived in time, and frames that arrived late. |
| `transport` | `string` | `datagram`, or `stream` when a path cannot carry datagrams. |
| `audioDevice` | `string` | What captures and plays audio. |
| `heardToneHz` | `number` or `null` | Test audio only: the frequency heard. |
| `measuredRoundTripMs` | `number` or `null` | Test audio only: the measured round trip of this device's tone bursts. |

### Video

Video rides the same call, on the same QUIC connection, so it uses every path
and moves between them as audio does.

On macOS, iPhone and iPad the runtime captures and encodes the camera (H.264
in hardware through VideoToolbox). On Android, Windows and Linux the web view
captures and encodes it with WebCodecs (`webCameraStream` in the SDK) and
hands each frame to the runtime with `video_push`, asking `video_targets` what
to encode.

Received video is decoded in the web view with the WebCodecs `VideoDecoder`,
which on a Mac needs Safari 16.4 or later (on macOS 11 and later, update
Safari). The SDK does this: `useVideoCanvas(ref, { call, source, peer })` in
React, or `videoCanvas(canvas)` with `mycel.calls.onVideo`.

To start video, pass `video: true` to `start_call` or `accept_call`, or call
`set_camera` at any time, also before the call is answered. The first time,
the system asks for the camera. If the user denies it, `set_camera` fails, the
call goes on without video, and `video.camera` is `denied` with `video.error`
saying where to allow it.

In a group call every person has their own video stream, encoded at the
quality the path to that person allows. A frame's `peer` says whose it is, and
`participants[].video` has each person's numbers both ways.

What is sent follows the path:

| Path | Video |
|---|---|
| cable, a Wi-Fi network, UWB | up to 720p at 30 fps |
| peer-to-peer Wi-Fi, Wi-Fi Direct | up to 480p at 30 fps |
| relay | up to 360p |
| under 1 Mbit/s (Bluetooth, Thread/802.15.4), or the multi-hop mesh | none |

When a path carries no video, `video.paused` is set on the sending side and
`video.remotePaused` on the receiving side ("Video paused: slow connection").
Video resumes by itself when a faster path returns. Under the path's ceiling a
delay-based controller keeps video's queueing to tens of milliseconds, so
audio keeps priority. Video starts at 320×180 and ramps up within a few
seconds.

### `VideoInfo` and `PeerVideo`

`CallInfo.video` is a `VideoInfo`. `Participant.video` is a `PeerVideo`, which
has the same fields without `camera`, `error` and `source`.

| Field | Type | Meaning |
|---|---|---|
| `camera` | `string` | `off`, `starting`, `on`, `denied` or `failed`. |
| `error` | `string` or `null` | Why the camera is `denied` or `failed`, and what to do. |
| `sending` | `boolean` | This device's video is going out. |
| `paused` | `boolean` | This device's video is paused: the path is too slow. |
| `remoteCamera` | `boolean` | The other side's camera is on. |
| `remotePaused` | `boolean` | The other side's video is paused. |
| `receiving` | `boolean` | Their frames are arriving. |
| `sendWidth`, `sendHeight`, `sendFps` | `number` | The size and frame rate being sent. |
| `bitrate` | `number` | The target video bitrate, in bits/s. |
| `sentBitrate` | `number` | What was sent over the last second, in bits/s. |
| `queueMs` | `number` | How long frames wait in queues beyond the base delay. |
| `recvWidth`, `recvHeight`, `recvFps` | `number` | The size and frame rate being received. |
| `latencyMs` | `number` | Their capture to arrival here. Two clocks, so approximate. |
| `framesSent`, `framesReceived` | `number` | Video frames sent and received. |
| `framesSkipped` | `number` | Pictures not sent because the path was backed up. |
| `keyframesSent`, `keyframeRequests` | `number` | Keyframes sent, and keyframes asked for after losing frames. |
| `source` | `string` | What captures the video, for example the camera's name. |
| `encoder` | `string` | Which encoder is in use. |

### Video frame format

The runtime hands encoded frames to the UI: everyone's video and this device's
self-view. Over Tauri, `video_subscribe` delivers one frame per channel
message as raw bytes. Over HTTP, `GET /api/video` is one long response in
which each frame follows a `u32` little-endian length.

One frame, little-endian:

| Bytes | Contents |
|---|---|
| 0 | layout version, 1 |
| 1 | source: 0 = another device, 1 = the self-view (show it mirrored) |
| 2 | flags: bit 0 marks a keyframe |
| 3 | 0 |
| 4..36 | whose video: the 32-byte device key |
| 36..40 | sequence number, `u32` |
| 40..48 | capture time in µs since the epoch, `u64` |
| 48..50 | width, `u16` |
| 50..52 | height, `u16` |
| 52..54 | length of the `avcC` record, `u16` |
| 54.. | the `avcC` record, then the frame |

The H.264 `avcC` record is present on keyframes only. Configure the decoder
with it as `description`, with the codec string `avc1.PPCCLL` taken from its
bytes 1 to 3. The frame is in AVCC form: NAL units with 4-byte big-endian
lengths.

Frames arrive in order, starting at a keyframe. If a decoder loses its place,
after an error or because it joined mid-stream, call `video_keyframe`.

### Environment variables

These apply to hosts and to `mycel serve`.

| Variable | Effect |
|---|---|
| `MYCEL_AUDIO` | Picks the audio backend; values below. |
| `MYCEL_CALL_DEBUG=1` | Logs each active call's paths once a second. |
| `MYCEL_VIDEO=test` | Replaces the camera with a moving test pattern, for headless runs. |
| `MYCEL_VIDEO_DEBUG=1` | Logs video frames and the rate controller. |

`MYCEL_AUDIO` takes:

- unset or `auto`: Apple voice processing with echo cancellation on macOS,
  iPhone and iPad (falling back to plain devices), the phone's call audio with
  echo cancellation on Android, and plain default devices elsewhere;
- `device`: plain default input and output devices, no echo cancellation;
- `test` or `test:<hz>`: a sine tone in and nothing played;
- `test:bursts` or `test:bursts:<hz>`: tone bursts that measure the round
  trip;
- `test:echo`: sends back whatever arrives.

## HTTP API

`mycel serve` runs a device and exposes the commands on
`http://127.0.0.1:7777`. The `--http` option changes the address, and the
server refuses anything but a loopback address.

| Route | Purpose |
|---|---|
| `GET /` | The web UI, with the per-run token embedded. |
| `GET /api/health` | `{"ok": true, "id": ..., "name": ..., "transport": "http"}`. |
| `POST /api/cmd/<command>` | Runs a command: JSON arguments in, JSON result out. |
| `GET /api/events` | Server-Sent Events, one JSON event per message. |
| `GET /api/video` | [Video frames](#video-frame-format) as one long binary response. |
| `POST /api/upload?name=<file>` | Saves the raw body as a file; returns `{"path": "..."}` to pass in `attachments`. |
| `GET /api/file?path=<path>` | Serves an attachment file. |

`/api/cmd` runs every command in [Commands](#commands) except the
[host-only](#host-only-commands) ones. Over HTTP, `send_message` accepts only
paths under the data directory's `uploads/` folder, where `/api/upload` puts
files, so an attachment cannot be forwarded by its `localPath`.

`/api/upload` streams the body to disk with no size limit. It answers `507`
when the announced `Content-Length` would leave too little free disk.

`/api/file` serves files under the data directory's `files/` and `uploads/`
folders only. Responses are streamed, support `Range`, and carry
`X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`.

### Access control

- The `Host` header must name the server's own loopback address, which blocks
  DNS rebinding. Anything else gets `403`.
- Every `/api/` route requires the per-run token, and answers `403` without
  it. The token is embedded in the page `mycel serve` returns, so other
  origins cannot read it.
- `fetch` calls send the token in the `X-Mycel` header. `/api/events`,
  `/api/video` and `/api/file` also accept it as the query parameter `t`, for
  `EventSource` and `<img>`.
- The server writes its address and the token to `<data>/http-token` with
  mode `0600`. `mycel call` reads it from there.

With the default data directory:

```sh
TOKEN=$(cut -d' ' -f2 ~/.mycel/http-token)
curl -H "X-Mycel: $TOKEN" -d '{}' http://127.0.0.1:7777/api/cmd/get_profile
```

## TypeScript SDK

`@mycel/sdk` exports a typed client, `mycel`, with a method for every command
except `sync_now`. Each method returns a promise.

| SDK method | Command |
|---|---|
| `profile.get()` | `get_profile` |
| `profile.setName(name)` | `set_name` |
| `contacts.list()` | `list_contacts` |
| `contacts.add(code)` | `add_contact` |
| `contacts.addNearby(id)` | `add_nearby_contact` |
| `contacts.remove(id)` | `remove_contact` |
| `nearby.list()` | `list_nearby` |
| `network.status()` | `network_status` |
| `network.setMode(mode)` | `set_network_mode` |
| `network.restart()` | `restart_app` (Tauri host only) |
| `notices.list()` | `list_notices` |
| `notices.dismiss(notice)` | `dismiss_notice` |
| `chat.list()` | `list_conversations` |
| `chat.get(id)` | `get_conversation` |
| `chat.create(title, members)` | `create_conversation` |
| `chat.rename(id, title)` | `rename_conversation` |
| `chat.addMembers(id, members)` | `add_members` |
| `chat.removeMember(id, member)` | `remove_member` |
| `chat.addKeeper(id, keeper)` | `add_keeper` |
| `chat.markRead(id)` | `mark_read` |
| `chat.typing(id)` | `set_typing` |
| `chat.acceptRequest(id)` | `accept_request` |
| `chat.declineRequest(id, { block? })` | `decline_request` |
| `chat.messages(id, { limit?, before? })` | `list_messages` |
| `chat.around(id, message, { before?, after? })` | `messages_around` |
| `chat.search(id, query, limit?)` | `search_messages` |
| `chat.send(id, body, { replyTo?, attachments?, publicAttachments? })` | `send_message` |
| `chat.edit(id, message, body)` | `edit_message` |
| `chat.delete(id, message)` | `delete_message` |
| `chat.deleteLocal(id, message)` | `delete_message_local` |
| `chat.restoreLocal(id, message)` | `restore_message_local` |
| `chat.react(id, message, emoji)` | `toggle_reaction` |
| `chat.fetchAttachment(blob)` | `fetch_attachment` |
| `calls.start(conversation, { video? })` | `start_call` |
| `calls.accept(call, { video? })` | `accept_call` |
| `calls.join(call, { video? })` | `accept_call`, on a `joinable` call |
| `calls.decline(call)` | `decline_call` |
| `calls.end(call)` | `end_call` |
| `calls.setMuted(call, muted)` | `set_muted` |
| `calls.setCamera(call, on)` | `set_camera` |
| `calls.requestKeyframe(call, source?)` | `video_keyframe` |
| `calls.status()` | `call_status` |

The client has a few members that are not commands:

| Member | Purpose |
|---|---|
| `on(type, handler)` | Subscribes to one event type, or `"*"` for all. Returns an unsubscribe function. |
| `calls.onVideo(handler)` | Receives parsed video frames. Returns an unsubscribe function. |
| `calls.videoSupported` | Whether the transport delivers video frames. |
| `files.pick()` | Lets the user choose files; resolves to paths for `attachments`. |
| `files.stage(files)` | Turns browser `File` objects into paths for `attachments`. |
| `files.url(path)` | A URL the web view can load for a local file. |
| `files.open(path)` | Opens a local file. |
| `files.onDragDrop(handler)` | Native drag-and-drop with real paths. Tauri host only. |
| `transport` | The transport in use; `transport.kind` is `tauri`, `http` or `mock`. |

On Android the SDK asks for the microphone through the web view before
`start_call` and `accept_call`, because there only an app's screen can ask.

`@mycel/sdk/react` has hooks over the client, among them `useConversations`,
`useMessages`, `useCalls`, `useTransfer` and `useVideoCanvas`. They are
defined in `packages/sdk/react/index.ts`.

## Rust API

`Runtime` is in `crates/mycel-node/src/runtime.rs`. Its methods take the same
arguments as the commands, in the same order.

```rust
impl Runtime {
    // lifecycle
    pub async fn open(data_dir: impl AsRef<Path>, mode: NetworkMode, name: Option<String>) -> Result<Arc<Runtime>>;
    pub async fn open_with(opts: RuntimeOptions) -> Result<Arc<Runtime>>;
    pub fn subscribe(&self) -> broadcast::Receiver<Event>;
    pub fn data_dir(&self) -> &Path;
    pub fn flush(&self) -> Result<()>;                // durability barrier before going to the background
    pub async fn shutdown(&self) -> Result<()>;

    // profile and contacts
    pub fn profile(&self) -> Profile;
    pub fn set_name(&self, name: String) -> Result<Profile>;
    pub fn add_contact(&self, code: String) -> Result<Contact>;
    pub async fn add_nearby_contact(&self, id: PeerId) -> Result<Contact>;
    pub fn remove_contact(&self, id: PeerId) -> Result<()>;
    pub fn contacts(&self) -> Vec<Contact>;
    pub fn nearby(&self) -> Vec<NearbyPeer>;

    // network and notices
    pub fn network_status(&self) -> NetworkStatus;
    pub fn set_network_mode(&self, mode: NetworkMode) -> Result<NetworkStatus>;
    pub fn launch_network_mode(data_dir: &Path, default: NetworkMode) -> NetworkMode;
    pub fn saved_network_mode(data_dir: &Path) -> Result<Option<NetworkMode>>;
    pub fn notices(&self) -> Vec<Notice>;
    pub fn dismiss_notice(&self, notice: Notice) -> Result<()>;
    pub async fn sync_now(&self);

    // conversations
    pub fn conversations(&self) -> Vec<ConversationSummary>;
    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary>;
    pub fn create_conversation(&self, title: Option<String>, members: Vec<PeerId>) -> Result<ConversationSummary>;
    pub fn rename_conversation(&self, id: ConversationId, title: String) -> Result<()>;
    pub fn add_members(&self, id: ConversationId, members: Vec<PeerId>) -> Result<()>;
    pub fn remove_member(&self, id: ConversationId, member: PeerId) -> Result<()>;
    pub fn leave_conversation(&self, id: ConversationId) -> Result<()>;
    pub fn add_keeper(&self, id: ConversationId, keeper: PeerId) -> Result<()>;
    pub fn mark_read(&self, id: ConversationId) -> Result<()>;
    pub fn set_typing(&self, id: ConversationId) -> Result<()>;
    pub fn accept_request(&self, id: ConversationId) -> Result<ConversationSummary>;
    pub fn decline_request(&self, id: ConversationId, block: bool) -> Result<()>;

    // messages
    pub fn messages(&self, id: ConversationId, limit: Option<u32>, before: Option<MessageId>) -> Result<Vec<MessageView>>;
    pub fn messages_around(&self, id: ConversationId, message: MessageId, before: Option<u32>, after: Option<u32>) -> Result<MessageWindow>;
    pub fn search_messages(&self, id: ConversationId, query: String, limit: Option<u32>) -> Result<Vec<MessageView>>;
    pub async fn send_message(&self, id: ConversationId, body: String, reply_to: Option<MessageId>, attachments: Vec<String>) -> Result<MessageView>;
    pub async fn send_message_with(&self, id: ConversationId, body: String, reply_to: Option<MessageId>, attachments: Vec<String>, public: Vec<String>) -> Result<MessageView>;
    pub fn edit_message(&self, id: ConversationId, message: MessageId, body: String) -> Result<()>;
    pub fn delete_message(&self, id: ConversationId, message: MessageId) -> Result<()>;
    pub fn delete_message_local(&self, id: ConversationId, message: MessageId) -> Result<()>;
    pub fn restore_message_local(&self, id: ConversationId, message: MessageId) -> Result<()>;
    pub fn toggle_reaction(&self, id: ConversationId, message: MessageId, emoji: String) -> Result<()>;

    // attachments
    pub async fn fetch_attachment(&self, blob: String) -> Result<String>;
    pub fn new_upload_path(&self, name: &str) -> Result<PathBuf>;
    pub async fn stage_upload(&self, name: &str, data: &[u8]) -> Result<String>;

    // calls
    pub async fn start_call(&self, conversation: ConversationId) -> Result<CallInfo>;
    pub async fn start_call_with(&self, conversation: ConversationId, video: bool) -> Result<CallInfo>;
    pub async fn accept_call(&self, call: String) -> Result<CallInfo>;
    pub async fn accept_call_with(&self, call: String, video: bool) -> Result<CallInfo>;
    pub fn decline_call(&self, call: String) -> Result<()>;
    pub fn end_call(&self, call: String) -> Result<()>;
    pub fn set_muted(&self, call: String, muted: bool) -> Result<CallInfo>;
    pub async fn set_camera(&self, call: String, on: bool) -> Result<CallInfo>;
    pub fn video_keyframe(&self, call: String, source: Option<String>) -> Result<()>;
    pub fn video_frames(&self) -> broadcast::Receiver<mycel_video::UiFrame>;
    pub fn call_status(&self) -> Vec<CallInfo>;

    // shell alerts
    pub fn alert_thread(&self, context: &str) -> Option<String>;
    pub fn alert_route(&self, target: &str) -> Option<ConversationId>;
}
```

Where a command and its method differ:

| Command | Method |
|---|---|
| `get_profile` | `profile` |
| `list_contacts`, `list_nearby`, `list_notices` | `contacts`, `nearby`, `notices` |
| `list_conversations`, `get_conversation` | `conversations`, `conversation` |
| `list_messages` | `messages` |
| `send_message` | `send_message_with` |
| `start_call`, `accept_call` | `start_call_with`, `accept_call_with` |

`RuntimeOptions` has the fields `data_dir`, `mode`, `name`, `default_name`,
`keeper` and `port`. `open` is `open_with` for an ordinary device on a random
port.

`subscribe` yields every event, the shell-only ones included. A host forwards
an event to apps only if `Event::is_for_shell()` is false.

## Shell alerts

Two events are for native shells only. Hosts consume them and never forward
them to apps.

| Event | Fields | Meaning |
|---|---|---|
| `alert` | `alert: Alert` | Show a private local alert. |
| `alertWithdrawn` | `thread: string`, `key?: string` | Take back delivered alerts: all of `thread`'s, or only the one with `key`. |

An `Alert` has these fields:

| Field | Type | Meaning |
|---|---|---|
| `kind` | `string` | `message`, `messageRequest`, `groupInvitation`, `incomingCall` or `missedCall`. |
| `thread` | `string` | What the alert is about: a conversation's `threadKey`. |
| `key` | `string` | A later alert with the same key replaces this one. |
| `target` | `string` | What a tap opens. |
| `foreground` | `boolean` | Also show it while the app is focused on something else. |

The chat layer (`mycel_kit_chat::alerts`) decides what is news: a new message
from someone else, a message request, a group invitation, a call ringing or
missed. It also decides when an alert is stale: read on this device, answered
or declined. The strings in an alert are opaque local keys, never names or
message text.

A native shell does four things with them:

- It shows one fixed sentence per `kind`.
- It replaces an alert that has the same `key`, and withdraws a thread's
  alerts together.
- It suppresses alerts while the app is focused on their thread. When
  `foreground` is false it suppresses them while the app is focused at all,
  because the app rings calls itself. `Runtime::alert_thread(context)` maps
  what the app shows to a thread.
- On a tap it resolves `target` again through `Runtime::alert_route(target)`,
  which returns the conversation to open now, or nothing if it is gone.
