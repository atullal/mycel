# Mycel architecture

Mycel (after mycelium: an underground network with no centre) is a platform
for peer-to-peer, end-to-end encrypted apps with no trusted server. Every
device is a router, and every device checks everything it receives.

This document is for engineers who have read the project README and want to
know how Mycel is put together: its goals, its layers and vocabulary, what
each layer does today and where its code lives, and how devices reach each
other when they have no direct link. It summarises, and links to the
documents that hold the detail:

- [TRUST.md](TRUST.md): the security specification.
- [ROUTING.md](ROUTING.md): the routing design and the reasons for it.
- [RUNTIME_API.md](RUNTIME_API.md): the API that apps use.
- [RULES_ABI.md](RULES_ABI.md): the contract between the runtime and rules.
- [CONFIGURATION.md](CONFIGURATION.md): every setting.
- [PLATFORMS.md](PLATFORMS.md): what works on which platform.
- [TESTING.md](TESTING.md): how Mycel is tested, with measured results.

Mycel is experimental and has had no external security review.
[Status and limitations](#status-and-limitations) says what is verified and
what is not. The [documentation index](README.md) lists every document.

## Contents

- [Goals and non-goals](#goals-and-non-goals)
- [Layer model](#layer-model)
- [Core vocabulary](#core-vocabulary)
- [L0 Network](#l0-network)
- [L1 Identity](#l1-identity)
- [L2 Trust](#l2-trust)
- [L3 Data and sync](#l3-data-and-sync)
- [L4 Rules](#l4-rules)
- [L5 SDK and kits](#l5-sdk-and-kits)
- [L6 Host](#l6-host)
- [Keepers](#keepers)
- [Calls](#calls)
- [Messaging on these primitives](#messaging-on-these-primitives)
- [Reaching devices without a direct link](#reaching-devices-without-a-direct-link)
- [Design decisions](#design-decisions)
- [Status and limitations](#status-and-limitations)

## Goals and non-goals

Mycel has five goals.

1. No trusted server. Every always-on node is untrusted, replaceable and
   runnable by anyone. It stores and forwards ciphertext only.
2. Real authorisation. Users read only what they are allowed to read, which
   encryption enforces. They do only what they are allowed to do, which
   signatures and deterministic validation on every honest peer enforce.
3. Offline first. Every operation works locally and syncs later, over
   whatever path exists: the same network, peer-to-peer Wi-Fi, Bluetooth,
   the internet, other devices.
4. Apps on a shared runtime. Identity, contacts, sync, encryption,
   networking and calls belong to the platform. An app is its data model,
   its rules and its UI. Messaging is the app built on it.
5. Native. A Rust core in a Tauri 2 shell on macOS, iPhone and iPad,
   Android, Windows and Linux.

It accepts four limits as non-goals.

- Globally unique names. A contact is a key with a name the person chose.
- Instant, global revocation. A removal propagates as peers sync, and a
  removed user keeps what they already decrypted.
- Strict global ordering of events. Mycel gives causal order.
- Payments or marketplaces.

## Layer model

```text
 L7  Apps            Messaging
 ──────────────────────────────────────────────────────────────────────────
 L6  Host            Tauri shell around one runtime: profile, contacts,
                     nearby, network panel, notices, notifications
 ──────────────────────────────────────────────────────────────────────────
 L5  SDK + Kits      @mycel/sdk (TypeScript client, transports, React hooks)
                     Chat kit (ops, deterministic reducer, threads, alerts)
 ──────────────────────────────────────────────────────────────────────────
 L4  Rules           Deterministic validators in WASM (wasmi)
 ──────────────────────────────────────────────────────────────────────────
 L3  Data & Sync     Doc (Automerge) · Feed (causal) · Blob · Ephemeral
                     Signed, encrypted envelopes · live sync · redb storage
 ──────────────────────────────────────────────────────────────────────────
 L2  Trust           Spaces · membership graph · roles · epoch keys
                     (hybrid post-quantum HPKE lockboxes) · signatures
 ──────────────────────────────────────────────────────────────────────────
 L1  Identity        Device keys · signed contact cards · contacts
 ──────────────────────────────────────────────────────────────────────────
 L0  Network         Iroh QUIC by public key, multipath, hole punching,
                     relays, mDNS / Bonjour / DNS / DHT discovery; links
                     (peer-to-peer Wi-Fi, Bluetooth LE, network interfaces);
                     mesh; gateways; store-and-forward
 ══════════════════════════════════════════════════════════════════════════
 Keepers             Headless Mycel nodes that store and serve ciphertext.
                     Untrusted. Anyone runs one.
```

As a rule of thumb, L0 to L3 are the network and the storage (like TCP/IP,
TLS and a database), L4 and L5 are the framework, L6 is the browser and L7
is the sites.

| Layer | Code |
|---|---|
| L0 Network | `crates/mycel-net`, `crates/mycel-link-awdl`, `crates/mycel-link-ble`, `crates/mycel-link-iface` |
| L1 Identity | `crates/mycel-crypto`, `crates/mycel-node` |
| L2 Trust | `crates/mycel-crypto`, `crates/mycel-trust` |
| L3 Data and sync | `crates/mycel-sync`, `crates/mycel-net`, `crates/mycel-node` |
| L4 Rules | `crates/mycel-rules`, `crates/mycel-rules-abi`, `rules/` |
| L5 SDK and kits | `packages/sdk`, `crates/mycel-kit-chat` |
| L6 Host | `apps/host`, `crates/mycel-node`, `crates/mycel-cli` |
| L7 Apps | `apps/messaging` |
| Calls | `crates/mycel-call`, `crates/mycel-video` |

`crates/mycel-node` is the runtime: a facade over the lower crates with the
API that apps use. `crates/mycel-sim` is the simulator described in
[SIMULATION.md](SIMULATION.md).

## Core vocabulary

| Term | Meaning | Example |
|---|---|---|
| Device | One installation with its own keys. A device is a member of spaces. | Alice's laptop |
| Space | The unit of trust and collaboration: members, roles and resources. | A chat, a group |
| Role | What a member may do in a space: `Relay < Reader < Writer < Admin`. | Admin of a group |
| Doc | A mergeable Automerge document, for collaboratively edited state. | A space's settings |
| Feed | Signed, encrypted entries in causal order, for messages and events. | Chat messages |
| Blob | Immutable, content-addressed, encrypted bytes. | Photos, files |
| Ephemeral message | Sent to members who are online, never stored. | Typing |
| Rule | A deterministic check: may this author make this change, given the causal state? | "Messages are at most 16 KiB" |
| Keeper | An always-on, untrusted member with the Relay role that stores ciphertext and passes it on. | A home server, a spare laptop |

Three different things are called a relay. A **relay server** is an Iroh
relay on the internet, n0's or your own. A **relay** is a Mycel device that
forwards another device's packets, in the mesh or over the internet. The
**Relay role** is the membership role that keepers hold.

## L0 Network

The network layer connects two devices by their public keys over every
path they have, and keeps the connection alive while paths come and go. It
is built on Iroh 1.3 and lives in `crates/mycel-net`, with one crate per
link.

### Connections and protocols

Connections are QUIC, dialled by public key. Iroh tries hole punching first
and falls back to a relay server, which sees only encrypted QUIC traffic.
The remote node ID is a device key, so every connection is authenticated
to a device, and L2 maps that device to its roles.

Each protocol is named by an ALPN, the TLS field that says what a
connection carries.

| ALPN | Carries |
|---|---|
| `mycel/2` | Everything except calls and mesh hops |
| `mycel/call/1` | Live calls, on connections of their own |
| `mycel/mesh/1` | Hop connections between neighbours in the mesh |

On `mycel/2` there is one long-lived connection per pair of devices, kept
by a small pool (`pool.rs`) that redials it when it dies and closes it
after 60 seconds without use. Every exchange is its own QUIC stream,
labelled by a one-byte stream kind: `Sync` (docs, feeds and membership),
`Card` (a contact card), `Ephemeral` (typing and presence), and `Blob` and
`Chunk` (attachments). A sync therefore costs no handshake, and stream
priorities send messages ahead of file bytes. Everything a peer sends is
bounded before it can cost much ([TRUST.md](TRUST.md), section 8d).

### Network modes and outside services

| Mode | Name in the app | Uses |
|---|---|---|
| `internet` (default) | All paths | Every path, including relay servers and DNS and DHT discovery |
| `lan` | Local only | The same network, links and the mesh; never the internet |
| `local` | (tests) | Loopback only |

In `internet` mode a device uses three outside services by default: n0's
relay servers, n0's DNS server and the Mainline DHT (`services.rs`). Each
can be switched off, and the relay servers can be replaced with your own
([CONFIGURATION.md](CONFIGURATION.md)). With the relay servers and the DNS
server off, nothing but other devices and the DHT is involved: a device is
found by its record in the DHT and reached directly or through
[devices that relay for it](#relays-among-devices). A device with no relay
server connected (switched off, blocked or down) falls back to those
relays by itself.

### Discovery

On a local network, devices find each other by mDNS: Iroh's own, or on iOS
the system's Bonjour, which needs no multicast entitlement. The two see
each other.

On the internet, each device publishes its own signed record (pkarr) in the
Mainline DHT and on n0's DNS server. The record says where to dial the
device and which devices carry traffic to it (`mesh/records.rs`). A
device's DHT node serves other nodes' queries once it has been reachable
for 15 minutes, and remembers the nodes it knows across restarts, so only a
first start depends on the DHT's well-known bootstrap hosts.

First contact usually comes from a [contact code](#l1-identity), which
carries the device's current addresses and so works where discovery is
blocked.

### Paths and links

One connection keeps several paths open (multipath QUIC) and moves between
them without reconnecting. A path is an IP path (the same network, or
direct over the internet), a relay server, or a link. A **link** is a path
that Mycel adds as an Iroh custom transport (`mycel_net::link::Link`).

| Link | Medium | Platforms | Code |
|---|---|---|---|
| Peer-to-peer Wi-Fi | Apple's AWDL (what AirDrop uses) | macOS, iOS | `crates/mycel-link-awdl` |
| Bluetooth LE | L2CAP channels, through CoreBluetooth or BlueZ | macOS, iOS, Linux | `crates/mycel-link-ble` |
| Network interfaces | Any interface the OS exposes | macOS, iOS, Android, Linux | `crates/mycel-link-iface` |
| Mesh | Other Mycel devices, hop by hop | All | `crates/mycel-net/src/mesh/` |

Peer-to-peer Wi-Fi needs no shared network, only Wi-Fi switched on. The
two Bluetooth back ends are wire-compatible, so a Linux machine and a Mac
link with each other.

The interface link makes every network interface its own path, whatever is
behind it: a cable between two computers, a second network card, or a
Wi-Fi Direct group, 802.11s mesh, UWB or 802.15.4 radio that the OS
presents as an interface. It leaves an ordinary network card with a
routable address to Iroh's IP transport. On Linux it can also form Wi-Fi
Direct groups with other Mycel devices, which is off by default because it
takes over the radio's peer-to-peer side.

The mesh has its own part,
[Reaching devices without a direct link](#reaching-devices-without-a-direct-link).

### Path selection and aggregation

`MycelPathSelector` (`link.rs`) ranks paths by the time a typical 64 KiB
exchange would take: the RTT plus 64 KiB divided by the estimated
throughput. The estimate starts from a prior for the medium
(`PathKind::prior_rate`, from 100 MB/s for a cable down to 30 kB/s for
Bluetooth) and then follows what the path delivers. So there is no rule per
radio: new hardware ranks itself by what it measures, and a link whose
prior was too optimistic loses the traffic within seconds. Selection runs
again every second, and a dead path is noticed within about 3 to 5 seconds.

Bandwidth adds up across paths. noq, the QUIC implementation under Iroh,
sends on every path marked Available, each within its own congestion
window, and the selector marks Available every healthy path that will not
hold the selected one back. A path stays a backup when its RTT is much
higher, when its rate is under 1/8 of the selected path's (Bluetooth next
to Wi-Fi), or when it loses more than 25 % of its packets. That prevents
head-of-line blocking within a stream. There is no striping at the
application level: one stream spreads over the paths by itself.

This relies on small patches to the vendored Iroh and noq, described in
`vendor/iroh/MYCEL_PATCH.md` and `vendor/noq-proto/MYCEL_PATCH.md`.

## L1 Identity

A device's identity is two keys that are generated on the device and never
leave it: an Ed25519 key for signing and an X-Wing key (a hybrid of X25519
and ML-KEM-768) for lockboxes, both from one 32-byte seed. The signing key
is also the device's Iroh node ID. The identity key is the account: there
is no recovery if it is lost.

iOS keeps the key in a device-only Keychain item, and the other platforms
in a private `identity.key` file in the data folder. On iOS and Android the
data folder is kept out of backups, so a restored or new phone starts a new
identity. A profile is locked while it is open, so one data folder has one
running copy, and a damaged identity read fails closed and never creates a
new identity.

A **contact card** holds a device's keys and display name, signed by the
device. A **contact code** is what a person shares so that others can add
the device: `mycel:` followed by base64url data and the device's current
addresses as hints. It has two forms.

- The short code is what the profile shows, as text and as a QR code. It
  holds the device key and the name it signed, not the card: the lockbox
  key alone is 1216 bytes. The adding device fetches the card the first
  time it reaches the device. Until then the contact is listed but cannot
  be put in a conversation.
- The full code holds the whole card, in under 2 kB of text, and needs no
  connection.

Display names come from signed profile updates. An unsigned name heard over
a radio is only a fallback. The code is in `crates/mycel-crypto` (keys) and
`crates/mycel-node` (`identity.rs`, `runtime/contacts.rs`), and the
specification is [TRUST.md](TRUST.md), section 3.

## L2 Trust

The trust layer decides who may read and write what, with no server to
ask. It is a small layer of Mycel's own, built only from standard, widely
reviewed primitives, in `crates/mycel-crypto` and `crates/mycel-trust`.
Apps see spaces, roles and members, never its internals. Its specification
is [TRUST.md](TRUST.md).

A space is defined by its **membership graph**: signed, hash-linked
operations (`Genesis`, `Add`, `SetRole`, `Remove`, `Rotate`, `Leave`,
`ReaderKey`) in causal order. Every peer replays them to compute the
current members and their roles.

| Role | May |
|---|---|
| `Relay` | Store and forward ciphertext (keepers) |
| `Reader` | Also hold the decryption keys |
| `Writer` | Also write: its signed changes are accepted |
| `Admin` | Also change membership |

Each space has a current **epoch key**, sealed to every reader in an HPKE
lockbox whose key agreement is hybrid post-quantum (X25519 + ML-KEM-768).
Removing a member rotates the epoch, so a removed member cannot read new
data. A writer whose newest epoch is not shared with exactly the current
readers rotates before it writes, which heals the space after concurrent
membership changes. Every change, feed entry and membership operation is
signed by a device key.

The core invariant is **causal authorisation**: a change is authorised
against the membership state in its causal past, not against the
receiver's current view. All honest peers therefore reach the same
decision to accept or reject, so they converge. When a removal and edits
are concurrent, a deterministic rule decides the outcome: removal wins over
concurrent operations from the removed member, and seniority breaks ties
between concurrent admin operations.

Forward secrecy comes in windows. Lockboxes are sealed to **reader keys**
that each device publishes per space, replaces every week and deletes 30
running days later, not to a key derived from its identity. The epoch keys
a device has opened are kept, sealed, in its database, and writers rotate
the epoch once a day. A stolen identity key therefore opens old ciphertext
only for what a member was given when it joined. A device publishes reader
keys only where its user takes part: an unanswered message request gets
none. [TRUST.md](TRUST.md), section 6, has the schedule and what it does
and does not protect.

## L3 Data and sync

L3 turns the trust layer into data that apps use. Its four primitives are
in `crates/mycel-sync` (envelopes, docs, feeds) and `crates/mycel-net`
(sync, attachments, ephemeral messages).

| Primitive | Built from | Properties |
|---|---|---|
| Doc | Automerge 0.12 changes in signed, encrypted envelopes | Maps, lists, text and counters, with history |
| Feed | Signed, encrypted entries that name the entries their author had seen | Causal order; concurrent entries by author's clock, then id |
| Blob | A tree of separately sealed, content-addressed pieces | Any size; resumable; every piece checked on arrival |
| Ephemeral | `Ephemeral` streams, encrypted with the current epoch key | Never stored; at most 64 KiB |

### Envelopes and validation

Each Automerge change and each feed entry travels in its own signed,
encrypted **envelope**. Peers and keepers sync sets of envelopes, not
Automerge sync messages: Automerge is the merge engine, and its sync
protocol is not used. The reason is that every change must pass signature
and authorisation checks before it is applied, and keepers must store and
validate data they cannot decrypt. An envelope's validity can be decided
from its header alone, so keepers enforce write permissions too.

Every peer puts every incoming change through the same steps:

```text
verify signature → resolve author → decrypt
  → validate with the rules (L4) against the causal state
  → apply, or quarantine
```

A rejected change is never applied, so honest peers never build on it, and
anything that depends on it is rejected too. The envelope format and the
validity rules are in [TRUST.md](TRUST.md), section 7.

### Live sync

A change is pushed to the members who are online after 5 ms of coalescing.
Members forward what they receive to other members, who may be out of the
author's reach. Every space is also synced with each peer every 15
seconds, with backoff for peers that fail. A sync sends membership
operations first, then envelopes, as a set difference over full
inventories of ids.

### Attachments

An attachment is a **chunked file**: a tree of pieces, each sealed
separately and addressed by the hash of its ciphertext, in one store for
the whole device. Any device can hold and serve a piece it cannot read, and
a receiver checks every piece as it arrives.

Files up to 16 MiB are pushed to members when they are posted. Larger ones
are pushed to keepers, and a member fetches one when its user opens it,
from every device that has it at once. When a member cannot be reached, the
sender also hands the file to contacts and to devices nearby on a fast
link, which cache it within a budget their owner donates. A file sent as
public is stored and sent once wherever it is used, at the price that
anyone who has the file can tell which devices hold it.

Attachments in the older single-blob format still download and open. The
format, the cache rules and the limits are in [TRUST.md](TRUST.md),
section 7c.

### Storage and views

`crates/mycel-node` stores membership operations, envelopes and small
key-value records in redb, with batched, ordered writes, and attachments as
files on disk. The key-value records include each space's keyring, sealed
under a key derived from the device's seed. Documents and feeds are rebuilt
from these on start.

For chat, the runtime folds new feed entries into a cached view, tracks
delivery, pages history by cursor and searches the local history. None of
that touches the network.

## L4 Rules

Rules are validators, written in Rust, compiled to WebAssembly and run by
every peer in [wasmi](https://github.com/wasmi-labs/wasmi), a pure-Rust
interpreter. The host is `crates/mycel-rules`, the shared `no_std` types
are `crates/mycel-rules-abi`, and the guest SDK and the bundles are under
`rules/`.

Every honest peer must reach the same verdict for the same input, so
execution is deterministic. A bundle may import nothing and may not use
floats. Each call runs on a fresh instance with a fixed fuel budget and a
memory cap, and every trap becomes the same rejection. wasmi is pinned to
an exact version, because its fuel cost model is part of what peers must
agree on. [RULES_ABI.md](RULES_ABI.md) is the exact contract.

One bundle is in use. `rules/chat-rules` checks every decrypted chat feed
entry on every peer: roles and size limits. The runtime embeds the bundle
and identifies it by hash. The rule that only an author may edit or delete
a message stays in the chat reducer, so validation needs no facts from
other entries.

## L5 SDK and kits

`@mycel/sdk` (`packages/sdk`, TypeScript) is a typed client for the runtime
API over three transports: Tauri IPC in the app, HTTP against
`mycel serve`, and an in-memory mock for demos and tests. It also provides
React hooks (`useConversations`, `useMessages`, `useCalls`, `useTransfer`,
`useVideoCanvas` and others) and the helpers that decode video and capture
the camera in a web view.

The Chat kit (`crates/mycel-kit-chat`) is the messaging data model. It
defines the ops (`Text`, `Edit`, `Delete`, `React`, `Receipt`, `Profile`,
`Meta`) and a deterministic reducer over the causally ordered feed. Its
`thread` module shows two direct chats that two people started separately
as one conversation, and its `alerts` module decides which changes deserve
a private local alert.

## L6 Host

One native shell (`apps/host`, Tauri 2) runs one runtime and the Messaging
app. The host owns what apps share: identity, contacts, nearby devices,
network status, keepers and notices. The UI is a web UI, and under 720 px
wide it switches to the phone layout.

Notifications are independent of the app. A kit decides what is news and
emits an opaque alert (kind, thread, key, target). The host shows one fixed
sentence per kind, routes taps through OS ids it never reuses, suppresses
alerts about what is on screen, and handles permissions. No names, text or
ids reach the OS.

`mycel serve` (`crates/mycel-cli`) runs the same runtime and UI headless,
over a token-protected HTTP API on localhost, for scripting and for tests
that drive a browser.

## Keepers

A keeper is a headless Mycel node (`mycel keeper`): the same core with no
UI. It is a member with the `Relay` role. It stores the encrypted
operations, envelopes and attachments of the spaces it was added to,
validates their headers, and serves them to members. It holds no keys and
never decrypts.

A keeper gives a space availability. A sender can post while the recipient
is offline and then go offline too, and the recipient gets the messages
from the keeper. A space can list several keepers, and losing one loses
nothing.

## Calls

Calls are a platform service on L0 connections, in `crates/mycel-call`
(signalling and audio) and `crates/mycel-video`. A call is a full mesh of
QUIC connections, called legs, on ALPN `mycel/call/1`, one per pair of
people in it. Each leg is dialled straight to the other device's key, so it
uses every path the node has and moves between them mid-call. A call needs
no server, and holds at most 8 people, because each device sends to every
other. [RUNTIME_API.md](RUNTIME_API.md) describes how calls behave for an
app, and [PLATFORMS.md](PLATFORMS.md) what each platform supports.

### Signalling

Each leg has one control stream, whose first message says why the leg
exists: `Ring` (the initiator rings a member), `Join` (a participant
connects to another one already in the call) or `Watch` (someone who
declined or missed a group call keeps a leg to one participant, to hear who
is in the call and join later).

The call id is
`BLAKE3::derive_key("mycel/v0/call-id", space ‖ initiator key ‖ nonce)`.
Every device rechecks it, and only rings for, or lets someone join or
watch, a current member of that space. For a `Ring`, the dialler must be
the initiator. Simultaneous calls in one conversation resolve to the call
of the lower device key.

### Audio

Audio is Opus (48 kHz mono, 20 ms frames, in-band FEC), one frame per QUIC
datagram, or on a unidirectional stream where a path carries no datagrams.
Each frame is encoded once per bitrate tier in use and sent to each peer at
the tier its path allows, from 32 kbps on a fast medium down to 12 kbps on
Bluetooth. Each peer is played through its own adaptive jitter buffer and
decoder, and the peers are mixed.

### Video

Video is a track on the same legs, through the audio engine's `TrackSink`
interface: one camera per call and one `VideoTrack` per peer, each encoded
as H.264 at the quality the path to that peer allows. A medium under
1 Mbit/s, such as Bluetooth, and the mesh carry no video.

Each encoded frame goes on its own unidirectional QUIC stream at the lowest
stream priority, so video cannot push audio aside. A frame is reset when a
keyframe supersedes it or it has been stuck for 1.5 seconds, and the
receiver asks for a keyframe after any loss. Control messages go in
datagrams, because a stream would wait behind video data that QUIC is still
recovering after a path change.

macOS and iOS encode in hardware through VideoToolbox. An encoder session
that stops answering is replaced by a fallback mode: the default encoder,
then pictures scaled before encoding, then on a Mac the software encoder.
On Android, Windows and Linux the web view captures the camera and encodes
with WebCodecs. On every platform the receiving web view decodes with
WebCodecs.

## Messaging on these primitives

Messaging (`apps/messaging`) is the app built on the platform. Its own code
is the conversation list, the chat screen and the calls UI. Everything else
comes from the platform and the Chat kit.

| Need | Primitive |
|---|---|
| Direct chat or group | A space: two members, or admin and member roles |
| Messages, replies, edits, deletes, reactions | The `mycel.chat.messages` feed, checked by the chat rules |
| Read receipts and delivery state | `Receipt` ops in the feed |
| Files and media | Blobs, with a key per attachment |
| Typing | Ephemeral messages |
| Offline delivery | Peers, keepers and store-and-forward carriers |
| Calls | `mycel-call` and `mycel-video` legs between members |
| Permissions | Writers post; authors edit and delete their own messages; admins manage membership and the title |

The app has direct chats and groups, message requests, replies, edits,
deletes (for everyone, or only on this device), reactions, read receipts,
typing, search, files of any size, voice notes, members, keepers, leaving,
and voice and video calls.

## Reaching devices without a direct link

Two devices with a direct path use it. Otherwise four mechanisms apply,
each building on the one before. The mesh carries a connection through
nearby devices. Gateways join a mesh to the internet. Internet relays
connect devices behind routers with no relay server. Store-and-forward
moves messages when no live path exists.

The code is in `crates/mycel-net/src/mesh/`. This part is a tour:
[ROUTING.md](ROUTING.md) has the protocols, their defaults and the reasons
for each choice, and [TRUST.md](TRUST.md), sections 8b and 8c, says what
relays, gateways and carriers can see and do.

### The mesh

Alice and Carol are out of each other's radio range, and Bob is in range of
both, so Alice's packets for Carol go through Bob. Bob need not be a
contact or a member of anything they share. What he forwards are the QUIC
packets of Alice's connection to Carol, encrypted and authenticated end to
end with keys only Alice and Carol hold: he can drop or delay them, but
cannot read, alter or forge them. There is no server, no coordinator and no
special node. Every Mycel device is a router.

A hop is a QUIC connection (ALPN `mycel/mesh/1`) between two neighbours:
devices with a direct path, over any link or the local network. Mesh frames
are QUIC datagrams on it, unreliable and unordered like IP, because the
end-to-end connection already does loss recovery and congestion control. A
hop connection is itself multipath, so a relay uses its best link to the
next device and moves between links mid-hop.

To Iroh the mesh is one more custom transport (`PathKind::Mesh`). A mesh
address names a destination and a waypoint, the neighbour the packet leaves
through: `mesh(Carol, via Bob)`. Each route is a distinct address, so Iroh
opens one QUIC path per route, up to 3 per destination, and the path
selector aggregates routes and fails over between them as it does with
direct links. A direct path always wins: a device with any direct path to
Carol gets no mesh addresses for her.

Routing is distance vector with signed announcements, after B.A.T.M.A.N.,
with Babel's loop freedom and timing (`mesh/core.rs`). Every device
announces itself about every 16 seconds, and each device passes an
announcement on once with its own hop cost added. Most announcements travel
2 hops, and every eighth the full 10. Costs are measured, not assumed: a
hop costs its RTT, plus the time to move 64 KiB at the rate its congestion
window allows, plus 2 ms. No medium is ranked by type.

Relaying for others is on by default, within a budget of 1 MiB/s per
neighbour and 4 MiB/s in total, and can be turned off
([CONFIGURATION.md](CONFIGURATION.md)). The mesh keeps working with no
internet at all.

End-to-end packets on the mesh are capped at QUIC's 1200-byte minimum, so a
hop that falls back to its base MTU does not lose them, and a frame too
large for a hop's datagram is split in two. Each hop drops from the tail
beyond 1/8 of its congestion window, so a slow hop does not build seconds
of delay.

### Gateways and global routing

Two phones that only have Bluetooth, one in Boston and one in Berlin, can
hold one connection. No route table spans the planet, and Bluetooth hops
cannot cross an ocean, so each layer does what it scales to.

```text
 Boston                                                          Berlin
 phone ─BLE─ phone ─BLE─ phone ─BLE─ laptop        laptop ─BLE─ phone
 (no internet)                       (gateway)     (gateway)    (no internet)
   │  local mesh: signed distance       │  ════ internet ════  │  local mesh
   │  vector, a few hops                │  (QUIC, relays,      │
   │                                    │   hole punching)     │
   └── record in the global directory: "Boston phone ── via ─▶ Boston laptop"
       (pkarr signed by the phone's own key; Mainline DHT + n0's DNS server)
```

A device with the internet that relays for others is a **gateway**. Its
signed announcements carry a gateway flag and its measured uplink cost. A
device without the internet sends anything it has no route for to the
gateway with the lowest total cost, mesh cost plus uplink cost, so a fibre
gateway four hops away beats a congested one next door.

The device also picks its best 2 gateways and signs a record that names
them. The gateways publish the record for it, after checking the signature
and that the record names them. Anyone with the internet resolves the
device's key as usual and gets one mesh address per gateway, each its own
QUIC path. Packets reach a gateway over an internet hop, a hop connection
opened on demand, and the gateway routes them into its mesh.

A gateway is not an open proxy: it never looks up or dials anyone for
traffic that came from the internet. End to end it is still one QUIC
connection, and nothing in between can read it.

### Relays among devices

Two devices behind home routers cannot dial each other: each router lets
in only answers to what went out. Something both can reach has to pass the
first packets between them. By default that is one of n0's relay servers.
Devices can also do it for each other (`mesh/relay.rs`), which is what
makes the relay servers optional.

A device that the internet can dial in to is an **internet relay**. It
finds this out by itself, and its record says so. A device that the
internet cannot dial in to, and that has no relay server connected, picks
up to 2 relays among the devices it knows and the relays those devices
name in their own records. It names the relays that agreed in its own
record, the way a Bluetooth-only device names its gateways, and publishes
no address of its own.

A relay works only for those who asked: it carries traffic between two
internet hops only if one end is its client, within a budget. It also
tells the client the address it sees the client at, which the client
offers to the devices it talks to, so a connection that started through a
relay can move to a direct path.

A device whose default route leaves through mobile data is neither a
gateway nor an internet relay: nobody else's traffic is paid for by it. It
still relays between devices near it, which costs no data.

### Store-and-forward

When there is no live path, data that must arrive later still moves.
Members of a conversation store and forward for each other through sync
and keepers, and devices that share nothing with the sender carry it too
(`mesh/dtn.rs`).

A sync to a member that fails, or is not through within 10 seconds, is
also handed to carriers as a **bundle**: the envelopes the member may lack,
still signed and encrypted, under a header signed by the source. A bundle
moves along any part of the route that is live, hop by hop with custody.
While a device holds spare copies it gives half to the likeliest neighbour
without one, and a single copy climbs toward neighbours more likely to
meet the internet. A bundle that reaches one of the destination's gateways
waits there, in a mailbox, until the destination appears. The destination
signs a receipt, and every carrier that hears of it drops its copy.

Carriers bound what they hold: 64 MiB of other devices' bundles, 4 MiB per
source, 256 KiB per bundle, and 7 days at most (a sync bundle asks for 3).
Bundles carry messages only, not files.

## Design decisions

Sync is Mycel's own envelope protocol, not Automerge's sync protocol, so
that every change is authorised before it is applied and keepers can
validate what they cannot read.

The trust layer is Mycel's own minimal layer, built only from standard
primitives, in preference to a pre-1.0 library.

Keys are per epoch, not per message. A CRDT keeps its full history, which
conflicts with per-message forward secrecy as in Signal. Mycel uses
per-epoch keys and keeps history.

Rules are Rust compiled to WebAssembly and run by a deterministic
interpreter. wasmi was chosen over wasmtime and extism for small builds and
determinism. The UI is TypeScript.

Packaging is host-first. One native shell holds the keys, the network and
the runtime, and apps reach them only through the SDK.

There is no push service. Waking a suspended phone needs the OS vendor's
push service, which needs a server, and Mycel runs none.

For multiplexing and path aggregation the network layer reuses QUIC and
Iroh, and adds a stream kind byte and a path selector. Three Iroh
components are not used:

- `iroh_util::connection_pool`. Its actor keeps a sender to itself, so it
  never exits and holds the `Endpoint` and its UDP socket after the node
  shuts down. A node restarted in the same process then cannot bind its
  port again. `pool.rs` has the same behaviour and shuts down.
- `iroh-blobs`. Its ids are plain BLAKE3 roots, where Mycel addresses
  ciphertext by domain-separated hashes. Its downloader takes the
  providers of one blob one after another, where Mycel fetches a file from
  several devices at once. It brings its own store and data layout. And
  its own ALPN would put file bytes and chat on different connections, so
  stream priorities could not put chat first.
- `iroh-gossip`. Member-to-member sync covers today's groups, which are
  capped well below the size where broadcast trees pay off.

[ROUTING.md](ROUTING.md) records the routing decisions: what the mesh and
store-and-forward take from Babel, B.A.T.M.A.N., PRoPHET and others, and
what was rejected.

## Status and limitations

Mycel is experimental. Everything described above is built.
[TESTING.md](TESTING.md) describes how it is tested, with measured results,
[SIMULATION.md](SIMULATION.md) how it scales in simulation, and
[BENCHMARKS.md](BENCHMARKS.md) how store-and-forward compares with other
routers on real contact traces. The limitations below are the ones known
today.

### What has run on real hardware and networks

- Bluetooth has run between a real iPhone and Macs, and real sessions have
  seen channels drop.
- Peer-to-peer Wi-Fi, Bluetooth on Linux (BlueZ) and Wi-Fi Direct group
  formation are tested on emulated links, and the Linux code builds in CI.
  They have not been tested between real devices.
- The interface link has been tested on macOS only, and not with UWB,
  802.15.4 or Wi-Fi Direct hardware. Macs have no UWB radio, and on Linux
  UWB carries data only through IEEE 802.15.4z chips that the kernel
  exposes as a 6LoWPAN interface.
- Internet relays, and running without n0's servers, are tested between
  processes on one computer. No test that runs by default uses the public
  DHT or n0's servers; two opt-in tests in
  `crates/mycel-net/tests/internet.rs` do. No test exercises the
  reachability check, the mobile-data check or a relayed connection
  through real routers.
- The move from a relayed path to a direct one is tested where nothing
  stands between the two devices. That shows the address is offered and
  the path opened, not that real routers let it through. Routers that give
  a device a different outside port for every destination will not, and
  the relay then carries everything, within its budget.

### Security

- No external review. The trust layer and its cryptography have had
  internal adversarial reviews, not an independent audit.
  [TRUST.md](TRUST.md), section 10, lists what the layer does not do.
- Forward secrecy has a join window and no way back. What a member is
  given when it joins a space, and what is written until the first
  rotation after its first reader key (about a day), is still sealed to
  the key derived from its identity. A device that cannot open an epoch,
  because its database was lost or because the writer had been out of
  touch for over 30 days and sealed to a reader key since deleted, never
  reads what was written under it. The conversation moves to a new epoch,
  and that stretch stays closed on that device.
- Post-quantum protection covers lockboxes, not signatures or the
  transport handshake.
- Metadata is visible. Keepers, relays and gateways see who talks to whom,
  sizes and timing. An internet relay publishes its IP address under its
  key, for anyone who knows the key; a device behind a router publishes
  none.
- A relay can drop traffic, and one that lies about its cost can attract
  traffic and drop it. Several routes through distinct neighbours and
  QUIC's dead-path detection limit the damage; [TRUST.md](TRUST.md),
  section 8b, lists the other defences.
- One device per member. There are no multi-device identities and no
  account recovery.

### Platforms and the app

- Bluetooth runs on macOS, iOS and Linux, and peer-to-peer Wi-Fi on macOS
  and iOS. Android and Windows reach other devices over IP networks and the
  mesh, and Android also over other network interfaces
  ([PLATFORMS.md](PLATFORMS.md)).
- A suspended iPhone or iPad does not receive messages until Mycel is
  opened again, or gets them later from a keeper or through
  store-and-forward. Calls continue in the background, and Android keeps
  running in the background.
- Every device must run the same build. A space does not carry its own
  rules bundle: every runtime runs the chat rules built into it, and the
  wire format still changes between builds.
- Calls are a full mesh: at most 8 people, and each sends to every other.
- When two direct chats with one person show as one conversation, a
  message never sorts before this device first saw its space, so two
  devices can order the merged history differently.
- Desktop notification centres cannot take back an alert once it is shown.
- A stranger's message request that was declined to make room for others
  stays stored: the device leaves the space but does not delete it.

### Scaling

- Sync exchanges full inventories of ids, so its cost grows with the size
  of a space.
- Trust resolution is quadratic when many membership changes are
  concurrent.
- The key schedule costs operations. Every reader adds one per space per
  week and every active space one rotation per day, whatever else happens.
  For a space of a few hundred members that is megabytes a week.
- A writer who sends K conflicting versions of a change in K separate
  batches costs K document rebuilds. Within one batch it costs one.
- Unread counts scale with the unread backlog.
- Loading a space checks its whole feed against the chat rules again.
- Keepers cannot merge ciphertext, and history is never compacted, so
  storage grows with a space's history.
- Routing traffic grows slowly with the mesh: in simulation, 3.4 kB/s per
  device with 2,000 Bluetooth-only phones, which is 8.4 % of a Bluetooth
  radio ([SIMULATION.md](SIMULATION.md)).

### Routing and relaying

- The sender chooses only the first hop of each route, so two routes can
  share relays further on.
- Failover between gateway paths pauses for 0.8 to 2.6 seconds in the
  in-process tests. Data in flight on the dead path leaves a hole that
  flow control waits on until that path's loss detection gives up.
- A record names at most 3 gateways. A device that moves keeps working
  once its new record propagates: at once on n0's DNS server, in seconds
  to a minute on the DHT. Meanwhile the old gateways drop packets for it.
- A device finds internet relays only among the devices it already knows
  and the relays those name: two steps, no further. Someone new, with no
  relay server, no contact that relays and none behind a relay, cannot be
  reached from the internet until one appears. There is no global list of
  relays, because a list anybody can write to is one anybody can fill with
  their own.
- If nobody a device knows is reachable from the internet, there is no
  relay. Most phones on mobile data are not reachable, and computers on
  home networks often are only if the router maps a port.
- The reachability check is the DHT library's: a packet to the device's own
  public address that comes back. It cannot tell a router that lets one
  port in from one that lets all in. The address a new relay publishes is
  the address the DHT sees with the device's QUIC port, which is right for
  a public address or a router that keeps ports, and a failed dial
  otherwise.
- Mobile data is recognised by the name of the network interface. A phone
  on a hotspot and a tethered laptop look like any Wi-Fi from the inside
  and are not caught.
