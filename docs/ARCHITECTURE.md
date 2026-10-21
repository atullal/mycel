# Mycel architecture

Mycel (after mycelium: an underground network with no centre) is a platform
for peer-to-peer, end-to-end encrypted apps with no trusted server. Every
device is a router, and every device checks everything it receives. The
trust layer is specified in [TRUST.md](TRUST.md), routing in
[ROUTING.md](ROUTING.md), wire formats and their versions in
[PROTOCOL.md](PROTOCOL.md), and the app API in [RUNTIME_API.md](RUNTIME_API.md).
What is built is in [§7](#7-what-is-built).

---

## 1. Goals and non-goals

**Goals**
1. **No trusted server.** Every always-on node is untrusted, replaceable, and runnable by anyone. It stores and forwards ciphertext only.
2. **Real authorization.** Users only read what they're allowed to read (enforced by encryption), and only do what they're allowed to do (enforced by signatures plus deterministic validation on every honest peer).
3. **Offline-first.** Every operation works locally and syncs later, over whatever path exists: the same network, peer-to-peer Wi-Fi, Bluetooth, the internet, other devices.
4. **Apps on a shared runtime.** Identity, contacts, sync, encryption, networking and calls belong to the platform; an app is its data model, rules and UI. Messaging is the app built on it.
5. **Native.** A Rust core in a Tauri 2 shell on macOS, iPhone and iPad, Android, Windows and Linux.

**Non-goals (accepted limits)**
- Globally unique names. A contact is a key with a name the person chose.
- Instant, global revocation. It propagates as peers sync; a removed user keeps what they already decrypted.
- Strict global ordering of events. Mycel gives causal order.
- Payments or marketplaces.

---

## 2. Layer model

```
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
                     (HPKE lockboxes) · signatures
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

**Rule of thumb:** L0–L3 are the network and storage (like TCP/IP + TLS + a database). L4–L5 are the framework. L6 is the browser. L7 is the sites.

---

## 3. Core vocabulary

| Concept | What it is | Example |
|---|---|---|
| **Device** | One installation, holding one Ed25519 signing key and one X25519 key. Its Iroh node ID *is* its signing key. A device is a member of spaces. | Alice's laptop |
| **Space** | The unit of trust and collaboration: members, roles and resources. | A chat, a group |
| **Role** | What a member may do in a space: `Relay < Reader < Writer < Admin`. | Admin of a group |
| **Doc** | A mergeable Automerge document, for collaboratively edited state. | A space's settings |
| **Feed** | Signed, encrypted entries in causal order, for messages and events. | Chat messages |
| **Blob** | Immutable, content-addressed, encrypted bytes. | Photos, files |
| **Ephemeral message** | Sent to members who are online, never stored. | Typing |
| **Rule** | A deterministic check: may this author make this change, given the causal state? | "messages are at most 16 KiB" |
| **Keeper** | An always-on, untrusted member with the Relay role: stores ciphertext and passes it on. | A home server, a spare laptop |

---

## 4. Layer details

### L0 Network: Iroh

- **Connections:** QUIC, dialed by public key (Iroh 1.3, vendored with a small multipath patch: `vendor/iroh/MYCEL_PATCH.md`). Hole punching first; relay fallback. Relays only see encrypted QUIC traffic.
- **Network modes:** `internet` (the default, "All paths": every path, including the n0 relays and DNS/DHT discovery), `lan` ("Local only": the same network, peer-to-peer Wi-Fi, Bluetooth, other interfaces and the mesh; never the internet) and `local` (loopback, for tests).
- **Discovery:** on the LAN, mDNS (Iroh's, through a patched `swarm-discovery`), and on iOS the system's Bonjour, which needs no multicast entitlement; the two see each other. On the internet, pkarr records through the n0 DNS relay and the Mainline DHT. First contact usually comes from a **contact code**: a signed contact card plus the device's current addresses, so it works where discovery is blocked.
- **Protocols** (ALPN is the TLS field that labels which protocol a connection carries):
  - **Versions** ([PROTOCOL.md](PROTOCOL.md)): a dialer offers every wire version it speaks, newest first, as separate ALPNs, and the listener picks the newest it also speaks, during the QUIC handshake. Version 1 is what pre-release builds speak (`mycel/2`, `mycel/mesh/1`); version 2 (`mycel/node/2`, `mycel/mesh/2`) adds a capability hello per connection, typed refusal of unknown stream kinds and versioned store-and-forward bundles. Additions ride on capability bits both sides must have.
  - `mycel/node/2` (version 1: `mycel/2`): everything except calls and mesh hops, on **one long-lived connection per pair of devices**. A small pool in `mycel-net` (`pool.rs`) keeps one connection per peer, redials it when it dies and closes it after 60 s unused. Every exchange is its own QUIC stream on it, labelled by a one-byte stream kind (like HTTP/3 stream types): `Sync` (Doc/Feed/membership sync, L3), `Card` (contact card), `Ephemeral` (typing/presence, a uni-stream), `Blob` (one blob request), and on version 2 `Hello` (capabilities, once per connection). So there's no handshake per sync, and QUIC stream priorities apply: messages, cards and presence (priority 1) go ahead of file bytes (−1). QUIC does the multiplexing, flow control and loss recovery; there's no framing layer on top.
  - `mycel/call/2` (version 1: `mycel/call/1`): live calls (below), their own connections.
  - `mycel/mesh/2` (version 1: `mycel/mesh/1`): hop connections between neighbours for multi-hop relaying (§8).
- **Peer authentication comes free:** the remote node ID *is* a device key. L2 maps it to roles.
- **Paths (multipath QUIC):** one connection keeps several paths open and moves between them without reconnecting: IP paths (same network, or direct over the internet), the internet relay, and **links**, non-IP paths that are Iroh custom transports (`mycel_net::link::Link`). The links are:
  - **peer-to-peer Wi-Fi** on macOS and iOS: Apple's AWDL (what AirDrop uses) through Network.framework, found by the Bonjour service `_mycel-p2p._udp`; no shared Wi-Fi network needed, only Wi-Fi switched on (`crates/mycel-link-awdl`);
  - **Bluetooth LE**: L2CAP channels through CoreBluetooth on macOS and iOS, and through BlueZ (`bluer`) on Linux, wire-compatible (same service and characteristic UUIDs, GATT info, PSM, framing and state machine), so a Linux machine and a Mac link with each other (`crates/mycel-link-ble`);
  - **other network interfaces** (`crates/mycel-link-iface`, below), including Wi-Fi Direct groups, which Mycel forms with other Mycel devices on Linux when turned on;
  - the **mesh** (§8).

  Verification: the Bluetooth link has run between a real iPhone and Macs. Peer-to-peer Wi-Fi, BlueZ and Wi-Fi Direct group formation are built and tested on emulated links (and, for the Linux code, in CI builds), but have not been tested between real devices.
  - `MycelPathSelector` *selects* the path where a typical 64 KiB exchange finishes first: RTT + 64 KiB ÷ estimated throughput. The estimate starts at the medium's prior (`PathKind::prior_rate`: cable 100 MB/s > network 50 > peer-to-peer Wi-Fi and Wi-Fi Direct 25 > relay 2 > other 1 > UWB 0.6 > mesh 0.5 > Bluetooth 0.03 > 802.15.4 0.015 MB/s), rises with any faster sample and falls to what a busy path delivers once its queue grows (RTT > 2 × base + 10 ms). A path busy with our own traffic counts its RTT only up to that level: the queue is ours and the throughput estimate already prices it in, so a bulk transfer's own queue can't hand the selection to an idle, unmeasured path (it did: a 10 MB/s link lost the primary to a 300 KB/s one mid-transfer).
  - So there is no per-radio rule: a new kind of hardware ranks itself by what it measures, and a link whose prior is too optimistic loses the traffic within seconds (`crates/mycel-net/tests/media.rs`). Dead paths are noticed within ~3–5 s. `MYCEL_PATH_DEBUG=1` logs every path's estimates.
  - The Iroh patch opens custom-transport addresses as backup paths, pings every path each second, and lets a selector mark **several paths Available**.
- **Bandwidth aggregation:** noq's own multipath scheduler sends on every validated Available path, each within its own congestion window. `poll_transmit` walks the paths in order and each sends until its window is full, so the overflow spills onto the next path. Next to the selected path, the selector marks Available every other healthy path that won't hold it back: distinct interfaces (Ethernet, Thunderbolt bridge, Wi-Fi; a second IPv4/IPv6 path over the same interface doesn't count), peer-to-peer Wi-Fi and other links, and the relay if its base RTT is close. It leaves a path as a Backup when its base RTT is above max(3× selected, selected + 15 ms), when it delivers under 1/8 of the selected path's rate while both are busy, or when it loses more than 25 % of packets; these rules prevent head-of-line blocking within a stream. A path whose estimated throughput is under 1/8 of the selected one's (Bluetooth or 802.15.4 next to Wi-Fi) is only ever a backup unless it's the only path. Selection re-runs every second. There's no app-level striping: one stream (a file) spreads over the paths by itself.
- **Any network interface** (`crates/mycel-link-iface`): every interface the OS exposes is its own path, whatever is behind it: a Thunderbolt or USB cable between two computers, a second NIC, a network without DHCP, or a Wi-Fi Direct group, 802.11s mesh, UWB or 802.15.4 radio that the OS presents as an interface.
  - One UDP socket per interface, bound to its IPv6 link-local address (macOS also pins it with `IPV6_BOUND_IF`), so packets leave by that interface only. Each socket sends a beacon (node key + name) to the link-local group `ff12::6d79:6365:6c00` port 45812 every second, and its source address is where QUIC packets go. Iroh sees each (interface, peer) as its own custom address carrying the medium, so multipath measures, aggregates and fails over between interfaces, and a mesh can hop over them.
  - The medium comes from the interface type (`ARPHRD_IEEE802154` / `ARPHRD_6LOWPAN`, Wi-Fi from sysfs, macOS `sdl_type`) and name; `MYCEL_IFACE_MEDIUM=wpan0=uwb` says what an interface is, `MYCEL_IFACES=a,b` restricts the set. VPNs, tunnels, container and VM plumbing, and AWDL (the peer-to-peer Wi-Fi link drives it) are skipped. An ordinary NIC with a routable address is left to Iroh's IP transport (one radio, one path; also under `MYCEL_IP=0`, which means "no Wi-Fi/Ethernet networking"); with only link-local addresses it is the link's. Interface changes arrive by netlink (Linux) or the routing socket (macOS), plus a rescan every 10 s.
  - Measured on one Mac (both nodes local, so the OS's stack, not the air): 242 MB/s over `lo0`, 200 MB/s over `en0`; with `lo0` and `en0` both shared, two paths. The link runs on macOS, iOS, Android and Linux; it has been tested on macOS only, and not with UWB, 802.15.4 or Wi-Fi Direct hardware. Macs have no UWB radio, and on Linux UWB carries data only through IEEE 802.15.4z chips that the kernel exposes as a 6LoWPAN interface.
  - *Wi-Fi Direct on Linux* (`mycel-link-iface::wifi_direct`): off by default, turned on with `MYCEL_WIFI_DIRECT=1` or `MYCEL_LINKS=all,wifidirect`, because it takes over the radio's P2P side. Through wpa_supplicant's D-Bus API, a WPS vendor extension marks Mycel devices in P2P discovery; the lower key starts GO negotiation with push-button WPS and the other side accepts; a peer that already owns a group is joined. The resulting `p2p-*` interface becomes a path as above. macOS has no Wi-Fi Direct API (AWDL fills that role).
- **Mesh (multi-hop):** devices with no direct path reach each other through other nearby Mycel devices, hop by hop, over whatever links each hop has. To Iroh it's one more custom transport (`PathKind::Mesh`), ranked by measured cost like any path, so it gets multipath, aggregation and failover like any link. See §8.
- **Multi-source downloads:** a blob is fetched as disjoint ranges from every member that has it (`GetRange`, two streams per source on the pooled connections). Idle sources take over half of a slow piece at the end, a failed source's ranges go back to the others, a `.ranges` file next to the `.part` keeps resume working, and the whole file's BLAKE3 hash is checked at the end.
- **Live calls** (`crates/mycel-call`), 1:1 and group: a call is a full mesh of QUIC connections ("legs") on ALPN `mycel/call/2` (`mycel/call/1` with pre-release builds, PROTOCOL.md §3.8), one per pair of people in it. Each is dialed straight to the other device's key on the node's own endpoint (`NodeOptions::extra_protocols`), so it rides every path above and moves between them mid-call like any other connection. A 1:1 call is the one-leg case.
  - *Signalling*: one control stream per leg. Its first message says why it exists:
    - `Ring`: the initiator rings each member.
    - `Join`: a participant connects to another one already in the call. Of two people not yet connected, the lower key dials; if both do, the leg dialed by the lower key survives.
    - `Watch`: someone who declined or missed a group call keeps a leg to one participant, so they hear who is in the call and can join later.

    Then come `Ringing`, `Accept`/`Decline`/`Busy`/`Glare`/`Existing`/`Denied`/`Full`, `Started`, `Roster` (who the sender is talking to), `Mute`, `Report` and `HangUp`. The call id is `BLAKE3::derive_key("mycel/v0/call-id", space ‖ initiator key ‖ nonce)`. Every device rechecks it, and only rings for, or lets someone join or watch, a current member of that space; for a `Ring`, the dialer must be the initiator. Simultaneous calls in one conversation resolve to the call of the lower device key, and a ring into a conversation that already has a call is answered `Existing`, so the caller joins that call. The call ends for you when nobody is left to talk to. At most 8 people: each device sends to every other, so upload grows with the group.
  - *Media*: Opus (libopus 1.3.1 in Rust via `unsafe-libopus`), 48 kHz mono, 20 ms frames, in-band FEC, one frame per QUIC datagram (10-byte header: track kind, sequence, timestamp, flags); a unidirectional stream (starting with the kind byte) if a path has no datagrams. QUIC already encrypts end to end. Each frame is encoded once per bitrate tier in use (8/12/16/24/32 kbps) and sent to each peer at the tier its path allows. Datagrams and streams of any other track kind go to a `TrackSink` (the seam video uses on the same legs).
  - *Receive*: one adaptive jitter buffer and decoder per peer (40–120 ms from RFC 3550 jitter, grows after underruns, trims bursts), all pulled by the playback clock and mixed (scaled down only if the sum would clip); Opus PLC for a missing frame, FEC from the next frame when it's there. The play thread keeps the device's largest recent burst plus a quarter frame queued for the speaker (25 ms at least, 100 ms at most, decaying with a ~1.5 s half-life): Core Audio takes ~10 ms at a time, some Bluetooth headsets and Linux sound servers 20–40 ms or more.
  - *Threads*: the send thread (wakes every 2 ms, encodes each 20 ms frame once per tier) and the play thread (every 3 ms) run under the Mach time-constraint (real-time) policy on macOS and iOS (`mycel_video::realtime`, the policy Core Audio gives its own I/O threads), so timer coalescing in a throttled process (an app in the background, a CI runner) can't make them wake tens of milliseconds late. The kernel lets such a thread run at least half its 20 ms period per wake-up before preempting it and demotes one that hogs the CPU. Elsewhere they are ordinary threads: Linux and Windows timers already wake on time.
  - *Bitrate*: the path sets a ceiling (32 kbps on a network, peer-to-peer Wi-Fi or another fast medium, 24 kbps via a relay or the mesh, 12 kbps on Bluetooth, ~1.5 KB/s of audio); reported loss > 3 % or RTT > 500 ms steps down, 5 clean seconds step back up.
  - *Audio I/O* behind the `AudioIo` trait: Apple's voice-processing I/O unit on macOS and iOS (echo cancellation, noise suppression, AGC); AAudio's voice-communication preset on Android; plain devices via `cpal` with resampling on Windows and Linux; or software test sources and sinks.
  - *Video* (`crates/mycel-video`): a track on every person's call connection, through the engine's `TrackSink` seam: one camera per call, a `VideoTrack` per peer, each encoded at the quality the path to that peer allows (so a group call can send 720p to someone on the same network and 480p to someone over peer-to-peer Wi-Fi, and nothing over Bluetooth). Each encoded frame goes on its own unidirectional QUIC stream (kind byte `0x10`), lowest stream priority. Control (keyframe requests naming the missing frame, dropped-frame notices, camera/paused state every second) goes in datagrams of kind `0x11` (a control stream only on paths without datagrams): a stream would get stuck behind the video data QUIC is still recovering after a path change.
    - Encoding: H.264 in hardware through VideoToolbox on macOS and iOS (real-time, no reordering, low-latency rate control). An encoder session that stops answering (3 pictures with no answer in 200 ms, a new session's first 3 pictures with no frame, or a second of nothing but drops) is replaced by the next mode: VideoToolbox's default encoder, then pictures scaled to the output size first (a pixel transfer session, or the CPU if that fails), then on a Mac the software encoder; a mode that never produced a frame at a size is skipped for that size for the rest of the process, and when no mode is left the track sees an error. On Android, Windows and Linux the web view captures the camera and encodes H.264 with WebCodecs, and the runtime sends those frames the same way. The receiving web view decodes with WebCodecs.
    - Frames are paced into QUIC at 2× the target bitrate in pieces sized to the rate (small on slow paths, so no single video packet holds audio up), and reset when superseded by a keyframe or stuck for 1.5 s.
    - A delay-based controller (QUIC's smoothed RTT above its recent minimum, as LEDBAT measures queueing; slow start from 150 kbit/s; back-off at 35 ms) picks bitrate and resolution under a per-path ceiling from the medium's prior throughput: 720p on a cable, a network or UWB; 480p on peer-to-peer Wi-Fi or Wi-Fi Direct; 360p via a relay; none under 1 Mbit/s (Bluetooth, 802.15.4) nor over the multi-hop mesh.
    - The receiver reorders, holds deltas until a keyframe after any loss, and asks for one at once.

### L1 Identity

- **Device keys** (Ed25519 for signing, X25519 for lockboxes) are generated on the device and never leave it. iOS keeps them in a device-only Keychain item; the other platforms in a private `identity.key` file in the data folder. On iOS and Android the data folder is kept out of backups, so a restored or new phone starts a new identity, and an iOS profile whose Keychain key isn't on the device is kept aside (`Notice::IdentityReplaced`). The identity key is the account: there is no recovery if it is lost.
- **Profiles are locked** while open (one running copy per data folder), and a damaged identity read fails closed instead of creating a new identity.
- **Contacts:** a contact card holds a device's keys and display name, signed by the device. A contact code is `mycel:` + the card, base64url, plus the device's current addresses as hints. Names come from signed profile updates; unsigned names heard over a radio are only a fallback.

### L2 Trust

Our own minimal layer, built only from vetted primitives. The full specification is [TRUST.md](TRUST.md).
- **Space membership graph:** signed, hash-linked operations (`Genesis`, `Add`, `SetRole`, `Remove`, `Rotate`, `Leave`), causally ordered. Every peer replays them to compute current membership.
- **Roles** (enforced cryptographically): `Relay < Reader < Writer < Admin`.
  - `Relay`: can store and forward ciphertext (keepers).
  - `Reader`: holds the decryption keys.
  - `Writer`: changes are signed by a member key that is accepted.
  - `Admin`: can change membership.
- **Epoch keys:** each space has a current epoch key, sealed to every reader in an HPKE lockbox. Removing a member rotates the epoch, so a removed member can't read new data.
- **Signatures:** every change, feed entry and membership op is signed by a device key.
- **Core invariant: causal authorization.** A change is authorized against the membership state *in its causal past*, not against the receiver's current view. All honest peers therefore reach the same accept/reject decision, so they converge.
- **Concurrent revocation:** when removal and edits happen concurrently, a deterministic rule decides the outcome. Removal wins over concurrent ops from the removed member, and seniority breaks ties between concurrent admin ops.
- Apps only see spaces, roles and members, never the trust layer's internals.

### L3 Data & Sync

| Primitive | Backing | Notes |
|---|---|---|
| **Doc** | Automerge (Rust `automerge` 0.12) inside signed, encrypted envelopes | Maps, lists, text, counters, with history |
| **Feed** | Signed, encrypted entries, each naming the entries its author had seen | Causal order, with a deterministic order for concurrent entries |
| **Blob** | Streaming AEAD (STREAM over XChaCha20-Poly1305, TRUST.md §7b), addressed by a BLAKE3 hash | Any size; resumable; fetched from every member that has it at once |
| **Ephemeral** | `Ephemeral` streams on the node protocol, encrypted with the space key | Never stored; at most 64 KiB |

- **Encrypted sync:** each Automerge change, and each feed entry, travels in its own signed, encrypted **envelope**. Peers and keepers sync envelope sets, not Automerge sync messages, so Automerge is the merge engine but its sync protocol isn't used. The reason: every change must pass signature and authorization checks *before* it is applied, and keepers must store and validate data they cannot decrypt. Envelope validity is decidable from the header alone, so keepers enforce write permissions too.
- **Ingress pipeline** (every peer, every incoming change):
  `verify signature → resolve author → decrypt → L4 validate against the causal state → apply, or quarantine`.
  Rejected changes are never applied, so honest peers never build on them, and anything that depends on them is rejected too.
- **Live sync:** a change is pushed to online members after 5 ms of coalescing (a change made during a running sync triggers one more), forwarded epidemically, and every space is synced with each peer every 15 s, with backoff for peers that fail.
- **Storage:** redb (membership ops, envelopes, small key-values) with batched, ordered writes, plus files on disk for blobs. Everything else is derived on start.
- **Chat views:** the runtime folds new feed entries into a cached view, pages history by cursor, and searches the local history; none of it touches the network.

### L4 Rules

Validators run as WASM in [`wasmi`](https://github.com/wasmi-labs/wasmi) 2.0.0, a pure-Rust interpreter (pinned exactly; chosen over wasmtime/extism for small builds and determinism). Crates: `mycel-rules` (host), `mycel-rules-abi` (shared `no_std` types), and the guest SDK under `rules/`. Exact spec: [RULES_ABI.md](RULES_ABI.md).
- **Determinism:** bundles may import nothing; floats, SIMD, threads, memory64, multi-memory and start functions are rejected at load; each call runs on a fresh instance with a fixed fuel budget (20M) and a memory cap (16 MiB); every trap (out of fuel, OOM, stack overflow, panic) becomes the same `Reject(Trap)`. wasmi runs with its portable (loop) dispatch, which behaves the same at every optimisation level.
- **ABI v1:** the guest exports `memory`, `mycel_abi_version() -> 1`, `mycel_alloc(len) -> ptr`, `mycel_validate(ptr, len) -> i64` and optionally `mycel_reduce(ptr, len) -> i64`. Input is a postcard `RuleInput { author, author_role, stream, payload, context }`.
- **In use:** `rules/chat-rules` (14 KB of WASM) checks every decrypted chat feed entry on every peer: roles and size limits. The runtime embeds this bundle and identifies it by hash. Author-only edit and delete stays in the deterministic chat reducer, so validation needs no facts from other entries.

### L5 SDK + Kits

- **`@mycel/sdk`** (TypeScript): a typed client for the runtime API over three transports (Tauri IPC in the app, HTTP with `mycel serve`, and an in-memory mock for demos and tests), plus React hooks (`useConversations`, `useMessages`, `useCalls`, `useTransfer`, `useVideoCanvas`, …) and the video decoding and web-camera helpers.
- **Chat kit** (`crates/mycel-kit-chat`): the messaging data model. Ops (`Text`, `Edit`, `Delete`, `React`, `Receipt`, `Profile`, `Meta`), a deterministic reducer over the causally ordered feed, the rules for showing two separately created direct chats with the same person as one (`thread`), and which changes deserve a private local alert (`alerts`).

### L6 Host

One native shell (`apps/host`, Tauri 2) runs one runtime and the Messaging app:
- **Shared** identity, contacts, nearby devices, network status, keepers and notices.
- **Notifications are app-agnostic:** a kit decides what is news and emits an opaque alert (kind, thread, key, target); the host only shows one fixed sentence per kind, routes taps through OS ids it never reuses, suppresses alerts about what's on screen, and handles permissions. No names, text or IDs reach the OS.
- The UI is a web UI; under 720 px wide it switches to the phone layout.
- `mycel serve` (`crates/mycel-cli`) runs the same runtime and UI headless, over a token-protected localhost HTTP API, for scripting and browser-driven tests.

### Keepers

A keeper is a headless Mycel node (`mycel keeper`): the same core, no UI.
- **Availability:** a member with the `Relay` role. It stores the encrypted ops, envelopes and blobs of the spaces it was added to, validates their headers, and serves them to members. It holds no keys and never decrypts.
- **Offline delivery:** a sender can post while the recipient is offline and then go offline too; the recipient gets the messages from the keeper.
- A space can list several keepers. Losing one loses nothing.

---

## 5. Messaging on these primitives

| Need | Mycel primitive |
|---|---|
| Direct chat or group | Space (direct = 2 members; group = admin and member roles) |
| Messages, replies, edits, deletes, reactions | Feed `messages` (Chat kit), checked by the chat rules |
| Read receipts and delivery state | `Receipt` ops in the feed |
| Files and media | Blobs, encrypted per attachment |
| Typing | Ephemeral messages |
| Offline delivery | Peers, keepers and store-and-forward carriers |
| Calls | `mycel-call` and `mycel-video` legs between members |
| Rules | Writers post; authors edit and delete their own messages (reducer); admins manage membership and the title |

**App-specific code:** the conversation list, the chat screen, calls UI. Everything else comes from the platform and the Chat kit.
**Known tension:** a CRDT's full history conflicts with Signal-style per-message forward secrecy. Mycel uses per-epoch keys and keeps history (TRUST.md §10).

---

## 6. Design decisions

- **Sync:** our own envelope protocol instead of Automerge's sync protocol (L3), so every change is authorized before it is applied and keepers validate what they can't read.
- **Trust layer:** our own minimal layer (TRUST.md), only from standard primitives, rather than a pre-1.0 library.
- **Rules language:** Rust compiled to WASM, run by a deterministic interpreter. The UI is TypeScript.
- **Packaging:** host-first. One native shell holds the keys, the network and the runtime; apps reach them only through the SDK.
- **No push service.** Waking a suspended phone needs the OS vendor's push service, which needs a server; Mycel runs none (§7, limitations).
- **What the network layer reuses and what it adds.**
  - *Multiplexing* is QUIC's: native streams on one connection, QUIC flow control, loss recovery and noq stream priorities. Mycel adds only a 1-byte stream kind and the per-exchange messages.
  - *Path aggregation* is noq's multipath scheduler with per-path congestion control. Mycel's patch to Iroh only lets a selector mark more than one path Available (and pings every path); `MycelPathSelector` decides which ones. There's no app-level striping.
  - *Connection pool*: `iroh_util::connection_pool` (what iroh-blobs uses) builds with Iroh 1.3, but its actor keeps a sender to itself, so it never exits and keeps the `Endpoint` (and its UDP socket) alive after the node shuts down. A node restarted in the same process then can't bind its port again; the runtime tests do exactly that. `mycel-net/src/pool.rs` is a ~100-line pool with the same behaviour (one dial at a time per peer, redial when closed, idle close) plus shutdown.
  - *Blobs*: `iroh-blobs` 0.103.1 builds with Iroh 1.3 and has BAO-verified streaming, range requests and resume, but isn't used: (1) its blob id is the BAO root (plain BLAKE3), while Mycel attachments are addressed by `BLAKE3 derive_key("mycel/v0/blob")`; (2) its multi-provider downloader runs providers one after another for a single blob, so it doesn't fetch one big file from several members at once; (3) it brings its own store and data layout, and every download would need an export (a copy) for the runtime to decrypt; (4) its own ALPN means file bytes and chat would be on different connections, so stream priorities couldn't put chat first. A consequence: a bad source is caught by the whole-file hash at the end, not per chunk.
  - *Group broadcast*: `iroh-gossip` isn't used; member-to-member sync covers today's groups (calls and chats are capped well below where broadcast trees pay off).

---

## 7. What is built

| Layer | Built |
|---|---|
| **L0 Network** | Iroh 1.3 QUIC dialed by key, multipath, three network modes (`internet`, `lan`, `local`). Discovery by mDNS, by Bonjour on iOS, by contact-code address hints, and by pkarr records (n0 DNS relay, Mainline DHT). Links as custom transports with live failover: peer-to-peer Wi-Fi (AWDL) on macOS and iOS, Bluetooth LE (CoreBluetooth on macOS and iOS, BlueZ on Linux), and an interface link on Unix, with opt-in Wi-Fi Direct group formation on Linux. **One pooled connection per peer** (ALPN `mycel/node/2`, or `mycel/2` with a pre-release build; versions negotiated in the handshake, capabilities in a hello: PROTOCOL.md) with every sync, card, ephemeral message and blob request as its own prioritised QUIC stream; calls on `mycel/call/2` (`mycel/call/1` with pre-release builds). **Bandwidth aggregation** over comparable paths; Bluetooth stays a backup. **Mesh** (§8): multi-hop relaying through nearby devices over any link, signed Babel-style distance-vector routes, up to 3 routes per destination as separate aggregated QUIC paths, relay budgets. **Global routing** (§9): gateways, signed reachability records in the DHT and the n0 relay, store-and-forward bundles with custody, mailboxes and receipts. Resource limits on everything a peer sends (TRUST.md §8d). |
| **L1 Identity** | Device keys (iOS Keychain; a private `identity.key` file elsewhere), kept out of iOS and Android backups; profile locks; signed contact cards and contact codes; contacts; names from signed profiles. |
| **L2 Trust** | Membership DAG, deterministic resolution (seniority, revocation wins, cutoffs), epochs with HPKE lockboxes, self-healing rotation, leave. |
| **L3 Data** | Docs (Automerge), Feeds (causal, deterministic order), Blobs (encrypted, any size, streamed to disk, resumable, hash-checked; up to 16 MiB pushed to members, bigger ones pulled on demand **from every member that has them at once**), ephemeral messages, redb storage with batched writes, restore on start, delivery tracking, cursor paging and local search. |
| **L4 Rules** | wasmi 2.0 deterministic engine (fuel, memory caps, no floats or imports). The chat rules (Rust → 14 KB WASM) run on every decrypted chat entry on every peer. |
| **L5 SDK + Kits** | `@mycel/sdk` (types, Tauri/HTTP/mock transports, React hooks); Chat kit (ops, deterministic reducer, one chat per person, alerts). |
| **L6 Host** | Tauri 2 host (profile, contacts, nearby, network and notices panels; private notifications) on macOS, iPhone and iPad, Android, Windows and Linux; `mycel serve` web host; `mycel keeper`. |
| **Keepers** | `mycel keeper`: accepts spaces, stores and serves ciphertext, never decrypts. |
| **Calls** | Voice over every path (`mycel-call`), 1:1 and group (full mesh, up to 8, join late, leave without ending it): direct dial by key, membership-checked signalling, Opus + FEC in QUIC datagrams, encode once per bitrate tier, per-peer jitter buffer and mix, path-aware bitrate per peer, echo cancellation on Apple platforms and Android, mute, glare, busy. **Video** (`mycel-video`): a track on every person's connection (1:1 and group tiles), hardware H.264 on Apple platforms and web-view encoding elsewhere, a QUIC stream per frame, delay-based rate control under a per-path ceiling, keyframe recovery, paused on Bluetooth and the mesh. |
| **Apps** | **Messaging**: direct chats and groups, message requests, replies, edits, deletes (for everyone, or only on this device), reactions, read receipts, typing, search, files of any size, voice notes, members, keepers, leave, voice and video calls. |

How it is tested, with measured results: [TESTING.md](TESTING.md). How it
scales in simulation, and how it compares with other routers on real
contact traces: [SIMULATION.md](SIMULATION.md), [BENCHMARKS.md](BENCHMARKS.md).

**Limitations:**
- **No external review.** The trust layer and its cryptography have had internal adversarial reviews, not an independent audit (TRUST.md §10 lists what it doesn't do).
- **Links and their verification.** Bluetooth runs on macOS, iOS and Linux; peer-to-peer Wi-Fi on macOS and iOS; Android and Windows reach other devices over IP networks and the mesh (Android also over other interfaces). Bluetooth has run between a real iPhone and Macs, and real sessions have seen channels drop. Peer-to-peer Wi-Fi, BlueZ and Wi-Fi Direct group formation are built and tested on emulated links, not between real devices.
- **A suspended iPhone or iPad receives messages late** ("slow mode"): when iOS lends Mycel background time, on Bluetooth events, or when it is opened, from the sender, a keeper or store-and-forward. Waking it on time would need Apple's push service, which needs a server, which Mycel doesn't use; an optional, content- and identity-blind wake relay is designed, not built ([WAKE_RELAY.md](WAKE_RELAY.md)). Calls continue in the background; Android keeps running in the background and restarts after a reboot ([PLATFORMS.md](PLATFORMS.md#background-delivery-without-a-server)).
- **One device per member:** no multi-device identities, no account recovery (L1).
- **Same chat rules everywhere.** A space doesn't carry its own rules bundle: every runtime runs the chat rules built into it, so the devices in a space should run builds with the same rules. Wire formats are versioned since wire version 2 ([PROTOCOL.md](PROTOCOL.md)): a build negotiates with newer builds, and speaks wire version 1 (pinned byte for byte) with pre-release builds. `scripts/v1-compat` runs real pre-release code (main `98d9b7b`, the `dev-2026-10-09-apps` release) against this build; the release speaks the same wire format but validates some data differently (PROTOCOL.md §5), and older pre-release builds changed formats unannounced and may not interoperate.
- **Calls** are a full mesh: at most 8 people, and each sends to every other.
- **Scaling characteristics:**
  - Sync exchanges full ID inventories, so its cost grows with the size of a space.
  - Trust resolution is quadratic when many membership changes are concurrent.
  - A writer who sends K conflicting versions in K separate batches costs K document rebuilds; within one batch it's one.
  - Unread counts scale with the unread backlog.
  - Loading a space re-checks its whole feed against the chat rules.
  - Keepers can't merge ciphertext, and history is never compacted, so storage grows with a space's history.
- **Ordering** of messages written offline is by when each device first saw them, so two devices can show concurrent messages in a different order.
- **Notifications:** desktop notification centres can't take back an alert once shown.
- **Requests:** a stranger's request declined to make room for others stays stored (left, not deleted).
- **Metadata:** keepers, relays and gateways see who talks to whom, sizes and timing (TRUST.md §8b–8c).

## 8. Mesh: how it stays decentralised without a direct link

Alice and Carol are out of each other's radio range, and Bob is in range of both. Alice's packets for Carol go Alice → Bob → Carol. Bob needn't be a contact or a member of anything they share, and he can't read what he carries. There's no server, no coordinator and no special node: every Mycel device is a router, so the network is the devices themselves. Implementation: `crates/mycel-net/src/mesh/` (the routing core `core.rs` is a pure state machine; `mod.rs` drives it over QUIC). The design record, with the protocols it draws on: [ROUTING.md](ROUTING.md).

**What a relay carries.** It forwards the QUIC packets of Alice's connection *to Carol*: encrypted and authenticated end to end with keys only Alice and Carol hold (QUIC/TLS, dialed by Carol's key). A relay can drop or delay them, but it can't read, alter or forge them. CRDT sync, calls and files run unchanged on top.

**Hops are link-agnostic.** A hop is a QUIC connection (ALPN `mycel/mesh/2`, or `mycel/mesh/1` to a pre-release build) between two *neighbours*: devices with a direct path, found by any link (Bluetooth, peer-to-peer Wi-Fi, an interface link) or on the LAN. Mesh frames are QUIC datagrams on it: unreliable and unordered, like IP, because the end-to-end connection already does loss recovery and congestion control. The mesh code never looks at a link type, so any link carries and relays mesh traffic with no mesh changes. A hop connection is itself multipath, so a relay uses its best link to the next device and moves between links mid-hop.

**Several routes at once (multiplexed hops).** A mesh address names a destination *and a waypoint*: the neighbour the packet leaves through, which also routes the replies (`mesh(Carol, via Bob)`). Each route is a distinct address, so Iroh opens one QUIC path per route, each with its own RTT, congestion window and failover. `MycelPathSelector` aggregates comparable routes exactly as it does direct links. A device keeps up to 3 routes per destination, through distinct neighbours, chosen from the routing table (cheapest first, sticky so they don't flap, none costlier than 4× the best + 30 ms). With A–B–C and A–D–C, one transfer uses both relays; when B leaves mid-transfer it finishes over D.

**Routing** is distance vector with originator announcements, after B.A.T.M.A.N., with Babel's loop freedom and timing (details and reasons: [ROUTING.md](ROUTING.md) §6):
- Every device announces itself every 16 s: device key, sequence number (milliseconds since the epoch), flags, scope, uplink cost and name, signed with the device key. What changes goes out at once: retractions, seqno requests, a greeting with our routes for a new neighbour.
- Each device passes each announcement on once, 10–50 ms later (enough to hear the cheapest copy, and it desynchronizes neighbours), with its hop cost added. It never sends it back to the neighbour its best copy came from (split horizon), nor to a neighbour that already sent it.
- To reach Carol, a device uses the neighbour that delivered Carol's cheapest fresh *feasible* announcement (Babel's feasibility condition: strictly closer than anything it advertised itself, so no loop forms even while routes change). When a hop drops, the routes it carried are retracted at once (a triggered update with cost ∞) and a seqno request travels toward the origin for a fresh announcement.
- Fisheye: each period's announcement travels 2 hops, every 8th one the full 10.
- Costs are measured, not assumed: a hop costs its connection's smoothed RTT plus 2 ms, so among equally fast routes the shorter one wins. No medium is ranked by type, so new hardware ranks itself.

**No loops, no storms:**
- every frame carries a TTL (10 hops);
- frames are never forwarded back to where they came from;
- each announcement is passed on at most once per sequence number;
- announcements are capped at 100/s per neighbour.

In a six-device ring, each device sends no more announcements than the protocol predicts (its own to each neighbour, and each other device's passed on once), and no frame loops.

**Relaying for others** is on by default and capped per neighbour (1 MiB/s) and in total (4 MiB/s). `MYCEL_MESH_RELAY=0` keeps using the mesh but relays nothing; nobody then routes through that device. `MYCEL_MESH=0` turns the mesh off.

**Direct always beats mesh.** A device with any direct path to Carol gets no mesh addresses for her, and the mesh refuses to carry packets to a neighbour. That also guarantees hop connections never run over the mesh themselves (no nesting). Between mesh and the internet relay, measured cost decides (RTT + 64 KiB ÷ measured throughput; the mesh starts from a 0.5 MB/s prior, below the relay's 2 MB/s, because it is at least two hops over links it doesn't know), and comparable ones aggregate. The mesh keeps working with no internet at all.

**MTU.** End-to-end packets on the mesh are capped at QUIC's 1200-byte minimum. A frame that doesn't fit a hop's datagram is split in two and reassembled at the destination; relays can split again. Larger inner packets were tried: when a hop fell back to its base MTU after loss, every large packet was lost until the end-to-end path re-learnt its MTU, and throughput collapsed. Each hop also drops from the tail beyond 1/8 of its congestion window queued (at least 16 KiB), so a slow hop doesn't build seconds of delay and the end-to-end connection sees congestion early. A quarter window and a full window were measured too: throughput across two routes was more variable.

**Short queues under the hops.** Below QUIC, each hop to a device in range is a first-in, first-out send buffer (a radio's, a Bluetooth controller's) that the hop's own congestion control fills until it overflows, and announcements, keep-alives and acknowledgements wait in it with the bulk data. So each device runs CoDel on its hops: when a hop's smoothed RTT stays more than a target (3 packets' time at the hop's rate, 20–250 ms) above its lowest for 100 ms (or the hop's RTT, if longer), it drops a data frame, then more often while that lasts, and the end-to-end connections slow down before the buffer fills. Control frames and packets of 400 bytes or less are never dropped this way, internet hops don't have it, and a queue that a second of dropping doesn't drain is taken as the hop's new base. On a saturated two-hop route at 400 kB/s a small exchange then takes ~50 ms instead of ~560 ms (ROUTING.md §6.14).

**Store-and-forward.** Members of a conversation store and forward for each other through CRDT sync and keepers. Strangers carry bundles too (§9): already-encrypted envelopes, moved along live segments, toward connectivity, held in mailboxes at gateways.

**Measured** (in-memory links, `cargo test -p mycel-net --test mesh -- --nocapture`):

| Test | Result |
|---|---|
| Relaying overhead | ≈0.1 ms per hop on a round trip (5-device line: 1 hop 0.08–0.35 ms … 4 hops 0.38–0.70 ms) |
| Two disjoint relays, each over 400 KB/s links | 1.84–1.97× one relay's throughput (4 MB, 20 runs); transfer survives losing a relay |
| A small exchange across a two-hop route a bulk transfer saturates (400 KB/s links) | ≈40–60 ms (median), ≈560 ms without the hops' queue management |
| Route heal | ≈5 s after the middle device of a line leaves, over a longer route |
| Call through one relay (test tones, `mycel-call`) | 0 % loss, ≈95 ms mouth-to-ear (jitter buffer included) |
| Relay capped at 100 KB/s | 500 KB took 4.3 s |
| Hops over peer-to-peer Wi-Fi, then 30 KB/s Bluetooth (emulated) | Sync works both ways |
| A relay reached over peer-to-peer Wi-Fi + Bluetooth (emulated), Wi-Fi cut mid-transfer | The hop moves to Bluetooth; the 1.5 MB transfer finishes |

**Limits:**
- relays see who talks to whom, and when (see [TRUST.md](TRUST.md) §8b);
- a relay that lies about its cost can attract traffic and drop it (several routes through distinct neighbours, and QUIC's dead-path detection, limit the damage);
- routing traffic grows slowly with the mesh: in simulation, 3.4 kB/s per device with 2,000 Bluetooth-only phones, 8.4 % of a Bluetooth radio ([ROUTING.md](ROUTING.md) §10);
- route choice is by RTT; throughput is left to the multipath scheduler's per-path measurements;
- only the first hop of each route is chosen by the sender, so two routes can share relays further on.

## 9. Global routing: from a Bluetooth-only phone in the US to one in Europe

The question: two phones that only have Bluetooth, one in Boston, one in Berlin. No route table spans the planet, and Bluetooth hops can't cross an ocean (about 100,000 hops of 50 m). The answer is a hierarchy, each layer doing what it scales to. The survey and design record are in [ROUTING.md](ROUTING.md).

```
 Boston                                                          Berlin
 phone ─BLE─ phone ─BLE─ phone ─BLE─ laptop        laptop ─BLE─ phone
 (no internet)                       (gateway)     (gateway)    (no internet)
   │  local mesh: signed distance       │  ════ internet ════  │  local mesh
   │  vector, a few hops                │  (QUIC, relays,      │
   │                                    │   hole punching)     │
   └── record in the global directory: "Boston phone ── via ─▶ Boston laptop"
       (pkarr signed by the phone's own key; Mainline DHT + n0 DNS relay)
```

1. **Local mesh** (§8). Inside radio range, devices route by signed announcements, as distance vector. Announcements are scoped: every period to 2 hops, every 8th period to 10.
2. **Gateways.** A device with the internet that relays for others is a gateway. Its signed announcements carry a gateway flag and its uplink cost (measured internet RTT).
3. **Default route.** A device without the internet sends anything it has no route for to the gateway with the lowest *total* cost (mesh cost + uplink). A fibre gateway four hops away beats a congested one next door.
4. **Records.** A device without the internet picks its best 2 gateways (through distinct first hops where it can) and signs a pkarr record with its own key: `mycel-gw:<gateway>:<mesh cost>,…|exp:<unix>`. It sends the record to those gateways as mesh control messages.
   - **Publishing:** each gateway checks the signature and that the record names it, then publishes it to the Mainline DHT and the n0 pkarr relay. Limits: one per origin per 10 s, at most 1024 origins.
   - **Lifetime:** records are valid 30 min and refreshed every 10 min, and at once (at most every 5 s) when the gateway set changes.
5. **Lookup.** Anyone with the internet resolves a key as usual. If the record names gateways, the device is behind them.
   - **Addresses:** the sender's Iroh gets one mesh address per gateway, `mesh(dst, via G)`, each its own QUIC path, aggregated and failed over like any other.
   - **Internet hops:** packets reach G over an internet hop (a QUIC connection opened on demand, hung up after 60 s idle), and G routes them into its mesh.
   - **Replies:** the reply's waypoint is G, so replies come back the same way.
   - **No open proxy:** gateways never relay internet → internet.
6. **Boston to Berlin.** The Boston phone dials the Berlin phone's key.
   - **Out of Boston:** having no internet, it addresses the packet via its own gateway. The packet climbs 3 BLE hops to the Boston laptop.
   - **Across the internet:** the Boston laptop resolves the Berlin phone's record and dials the Berlin laptop.
   - **Into Berlin:** the Berlin laptop routes the packet down its mesh.
   - **Encryption:** it is one QUIC connection, encrypted end to end; nothing in between can read it.
   - **Measured** (in-process): first sync 0.58 s, including lookups, dials and the handshake. A test-tone call had 84 ms RTT with 3 BLE hops at 10 ms each way, and 0 % loss.
7. **When there's no live path: store-and-forward** ([`mesh/dtn.rs`](../crates/mycel-net/src/mesh/dtn.rs)).
   - **Bundles:** a failed sync to a member becomes a *bundle*: the envelopes the member may lack, still signed and encrypted, signed by the source. It goes:
     1. along any part of the route that is live now, hop by hop with custody;
     2. while it has copies to spare, half of them to the likeliest neighbour without one (32 copies for chat-sized bundles, down to 4 for big ones);
     3. as a single copy, toward neighbours with better delivery predictability (PRoPHET) for *the internet*, so a Bluetooth phone's message climbs toward connectivity.
   - **Mailboxes:** a bundle that reaches one of the destination's gateways waits there until the destination appears on that gateway's mesh.
   - **Receipts:** the destination signs a receipt; receipts spread and every carrier drops its copy.
   - **Limits:** a 64 MiB store, 256 KiB bundles, 4 MiB per source, lifetimes up to 7 days (3 days for sync bundles).

**Route freshness under churn** (measured in the virtual-time harness, `mesh/core/tests.rs`, 500 ms announcement period, 5 ms per hop):

| | |
|---|---|
| Dead route stops being used (retraction, triggered) | 25 ms on an 8-device line (timeout alone: 1.75–7 s) |
| A ring that loses a link heals (seqno request to the origin) | 0.6 s, 0 loops at any instant |
| Routes across a new link: 2 hops / up to 8 hops | 0.4 s / 1.4 s |
| 60 link flaps in a 30-device random mesh with traffic | 0 frame loops, 0 route loops (Babel's feasibility condition) |
| Two gateways (250 KB/s each) for one Bluetooth-only device | 2.0× one path; one gateway lost mid-transfer: the other carries on, longest pause 0.8–2.6 s |
| Spray, then the gradient toward the internet, vs Spray-and-Wait, 4 clusters in a chain | first copy reaches the internet in 28 min mean vs undelivered in 12 h (40 traces) |

**Limits:**
- Failover between gateway paths pauses for 0.8–2.6 s. Data in flight on the dead path leaves a hole that flow control waits on until that path's loss detection gives up.
- Records name at most 3 gateways. A device that moves keeps working once its new record propagates: at once on the n0 relay, in seconds to a minute on the DHT. Meanwhile the old gateways drop packets for it.
- The DHT path (`dht` feature) is built and on in the app, but tests never touch the public DHT. It is exercised only by real use.
- Relays and gateways see who talks to whom, sizes and timing ([TRUST.md](TRUST.md) §8b–8c).
