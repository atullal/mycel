# Mycel protocol versions

Every byte Mycel puts on a wire, on disk or under a signature, what version
it is, and what a device does with a version it doesn't know. Code:
`crates/mycel-net/src/version.rs` (versions, capabilities, typed errors),
`wire.rs` and `mesh/` (the formats). The architecture is in
[ARCHITECTURE.md](ARCHITECTURE.md), the trust rules in [TRUST.md](TRUST.md),
routing in [ROUTING.md](ROUTING.md).

Until wire version 2, every device had to run the same build: nothing said
which format a peer spoke, so any change broke mixed groups silently. Now
each connection agrees on a version before its first byte, and features
are added behind capabilities both sides must have.

---

## 1. Two mechanisms

Mycel separates changes that alter what existing bytes mean from changes
that only add something, as QUIC and HTTP/3 do.

| | **Wire version** | **Capability** |
|---|---|---|
| For | A change an older device would misread | An addition an older device can do without |
| Chosen | In the QUIC handshake, by ALPN, before any byte | Once per connection, in a capability hello |
| Cost | Nothing: no round trip | One small exchange per connection, beside the first real one |
| Example | v2 adds the hello stream kind and versioned bundle offers | `SYNC_V2`, a new sync stream; `ROUTE_ATTEST`, attested announcements |

**Versions by ALPN.** A dialer offers every version it speaks, newest first
(`wire::alpns`, `mesh::alpns`, through iroh's `ConnectOptions::with_additional_alpns`).
Each protocol's names are one table (`wire::ALPNS`, `mesh::ALPNS`, of type
`version::AlpnTable`) whose length follows `WIRE_VERSION`, and a
compile-time check (`version::alpn_table_ok`) requires every version in
place under its own name: raising `WIRE_VERSION` without naming the new
version's ALPN doesn't build, so one version's bytes can't reach a peer
under another version's name.
The listener registers its versions newest first and TLS picks the first of
its own that the dialer offered, so two devices land on the newest version
both speak, and a device that only speaks an old one keeps working. Nothing
is sent to find out. This is how HTTP/2 and HTTP/3 are selected (RFC 7301,
RFC 9114 §3.1).

**Capabilities by hello.** A capability is one bit in a 64-bit set
(`version::Caps`). On a connection of version 2 or later, each side sends its
set once in a `Hello`; a feature is used on that connection only if both
sets have its bit (`PeerProtocol::supports`, from `PeerProtocol::agreed`,
the intersection). Unknown bits are ignored. That is QUIC's rule for
transport parameters (RFC 9000 §7.4.2).

**Grease.** Extension points that are never exercised rust shut: a peer that
wrongly rejects unknown values keeps working until the day a real one
appears (RFC 8701 §1, the TLS experience). So every hello also sets one
random bit from a reserved range (`Caps::RESERVED`, bits 48–63, never
assigned), and every receiver must ignore it, from the first release on.
`PeerProtocol::agreed` drops reserved bits even if both sides happened to
send the same one.

---

## 2. Wire versions

| Version | Built by | What it is |
|---|---|---|
| **1** | Pre-release builds (everything before this document; exactly which ones in §5) | No negotiation, no hello. Named by the ALPNs `mycel/2` and `mycel/mesh/1`. |
| **2** | This build and later | Version 1 plus: a capability hello on the node protocol and on mesh hops; stream kinds a device doesn't know refused with a typed error; versioned bundle offers and bundle header v2; data-frame flags carried end to end. |

A device speaks every version from `MIN_WIRE_VERSION` (1) to
`WIRE_VERSION` (2). `NodeOptions::protocol` (copied into
`MeshOptions::protocol`) sets the newest version it offers and the
capabilities it advertises; `Protocol { version: WIRE_V1, .. }` behaves like
a pre-release build, which the mixed-version tests use (§8).

What was agreed with a peer is in `PeerState::protocol`, and
`Node::negotiate(peer)` returns it (dialing if needed, waiting for the hello
on a new connection). For a mesh neighbour: `Mesh::neighbour_protocol`.
`PeerState::protocol` is set for peers we dialed, and on connections a peer
dialed only for a device we already track or share a space with: anyone can
dial (a fresh key costs nothing) and `PeerState` entries are never removed,
so a stranger's connection or hello creates no state (the connection itself
still knows its version).

---

## 3. Every format

### 3.1 Connections (ALPN)

| ALPN | Version | Carries |
|---|---|---|
| `mycel/node/2` | node protocol v2 | Sync, cards, ephemeral messages, blobs, the hello: one pooled connection per pair of devices |
| `mycel/2` | node protocol v1 | The same, without hello (the name predates versioning) |
| `mycel/mesh/2` | mesh v2 | Hop connections between neighbours |
| `mycel/mesh/1` | mesh v1 | The same, as pre-release builds speak it |
| `mycel/call/2` | call protocol v2 | One connection per pair of people in a call (§3.8) |
| `mycel/call/1` | call protocol v1 | The same, as pre-release builds speak it |

Before node protocol v1 (`mycel/2`), each exchange had its own ALPN
(`mycel/sync/1`, `mycel/card/0`, `mycel/eph/0`, `mycel/blob/0`); no build
that speaks those is supported. Test-only ALPNs (`mycel-sim/bulk`,
`test/...`) are not part of the protocol.

### 3.2 Node protocol streams

Every exchange is a QUIC stream whose first byte is its kind
(`wire::StreamKind`). Frames on it are a 4-byte little-endian length and a
postcard body (at most 64 MiB; 4 KiB for cards and blob requests; 256 bytes,
`version::MAX_HELLO`, for hellos, the same limit as on mesh hops, so a hello
one protocol takes the other takes too).

| Kind | Byte | Stream | Since | Body |
|---|---|---|---|---|
| `Sync` | 1 | bi | v1 | `SyncMsg`: `Hello{space, inv, invite?}` → `Denied` / `Removed{ops}` / `NeedInvite` / `Accept{inv, want}` → `DataAndWant{data, want}` → `Data{data}` |
| `Card` | 2 | bi | v1 | The listener's `ContactCard` |
| `Ephemeral` | 3 | uni | v1 | `EphMsg{space, epoch, nonce, ciphertext}` |
| `Blob` | 4 | bi | v1 | `BlobReq` → `BlobResp` + raw bytes. New request variants are only ever appended. |
| `Hello` | 5 | bi | v2 | The dialer's `Hello{caps}`, then the listener's |
| `SyncV2` | 6 | bi | v2, `SYNC_V2` | One Sync v2 session (`mycel_sync::reconcile::Msg`, `Open` first), opened only to a peer whose hello agreed `SYNC_V2`. A listener that fails after accepting it resets with `0x6d790002` (`SYNC_V2_FAILED`), never with `STREAM_REFUSED`; a device that refuses it all the same is synced with `Sync` and not offered `SyncV2` for 30 min |
| `Gossip` | 7 | uni | v2, `GOSSIP` | One dissemination message (`mycel_sync::reconcile::gossip::GossipMsg`: `Push`, `IHave`, `Have`, `Graft`, `Prune`; at most 64 KiB), sent only to a peer whose hello agreed `GOSSIP`, and taken only from a current member of the message's space |

A device with Sync v2 serves at most one `Sync` (v1) session per (peer,
space) every 5 s (`V1_SERVE_INTERVAL`); it refuses the excess by resetting
the stream with `0x6d790003` (`SYNC_V1_LIMITED`), which a current build
takes as `Busy` and an older one as a failed session it retries on its own
schedule.

**Unknown kinds.** A kind the stream's connection version doesn't have
(any byte not in the table, or `Hello`, `SyncV2` or `Gossip` on a v1 connection, or
`SyncV2` at a device without Sync v2) is refused at
once: the listener stops the receive side and resets the send side with the
QUIC application error `STREAM_REFUSED` (`0x6d790001`). The opener's next
read or write fails, and `version::refusal` turns that into
`VersionError::StreamRefused`, so a newer build probing an older one learns
it in one round trip instead of waiting out a 60 s reply timeout, and no
byte is ever read as something else. The connection carries on.

**The hello.** The dialer opens it right after dialing (`start_hello`), on
its own stream next to the exchange it dialed for. The two race: nothing
may assume the hello arrives, or is answered, before that exchange.
Nothing waits on it unless it needs a capability (`PooledConn::protocol`:
a sync waits four round trips on the path in use, between 750 ms and 3 s,
then uses v1 for that session; `Node::negotiate` waits up to
`REPLY_TIMEOUT`). Mesh hops advertise only the capabilities registered for
the mesh protocol (`Caps::for_protocol`): a hop never hears `SYNC_V2` or
`GOSSIP`. It costs one stream each
way with a few bytes in each, per connection, not per exchange. It may
only grow at the end: receivers read the fields they know and ignore the
rest (`Hello::decode`).

A hello that fails (its stream lost on a flaky Bluetooth or multi-hop
path, no stream credit in time, a timeout) leaves the connection without
capabilities *for now*: it is counted (`ConnectionCounts::hellos_failed`)
and tried again on a later use of the same pooled connection, no sooner
than `pool::HELLO_RETRY` (30 s, doubling) after the failure and at most
`pool::HELLO_TRIES` (3) times in all. While a retry is out, whoever needs
a capability waits for its outcome. Pooled connections live until
`POOL_IDLE`, so without the retry one lost packet would cost a pair of
devices every capability for as long as they keep talking.

### 3.3 Contact cards and contact codes

- **Card** (`wire::ContactCard`): `{keys: MemberKeys, name, sig}`, the
  signature over `postcard(keys) ‖ name` in context `mycel/v0/contact-card`.
  Served on `Card` streams.
- **Contact code** (format 1, `CONTACT_CODE_FORMAT` in mycel-node):
  `mycel:` + base64url(postcard(card)), optionally `@ip:port,...` address
  hints. A later format will be written `mycel<N>:`: this build refuses it
  with `VersionError::Unsupported` ("update Mycel"), and older builds don't
  take it for a contact code. Bare base64 (no prefix) is still read as
  format 1.

### 3.4 Ephemeral messages and blobs

- Ephemeral messages are sealed under the space's current epoch key with
  AAD `mycel/v0/ephemeral ‖ space ‖ sender`. They are never stored.
- A blob's id is `BLAKE3 derive_key("mycel/v0/blob", ciphertext)`; blob
  bytes are sealed in chunks (`mycel/v0/stream-chunk`, attachment AAD
  `mycel/v0/attachment`).

### 3.5 Mesh hops

A hop is a QUIC connection between neighbours (`mycel/mesh/2` or `/1`).
Routing and relayed packets are QUIC datagrams, typed by their first byte;
store-and-forward uses streams on the same connection.

| Datagram | Byte | Layout |
|---|---|---|
| `T_OGM` | 1 | One announcement: type, hops, cost u32, origin (32), seq u64, flags, scope, uplink u32, name length, name, signature (64). Big-endian. Signed by the origin in context `mycel/v1/mesh-announce` over everything but hops and cost. |
| `T_DATA` | 2 | Relayed packet: type, ttl, flags, dst (32), src (32), waypoint (32), id u32, offset u16, total u16 (107 bytes), then payload (an end-to-end QUIC packet, or a control message for the destination's router). |
| `T_SEQREQ` | 3 | Ask an origin for a fresh announcement: origin, seq, hops. |
| `T_OGMS` | 4 | Several announcements in one datagram. |

- **Unknown datagram types** are dropped, hop-locally (a relay can't route
  what it can't parse). A new type is only ever sent to a neighbour whose
  hello has the capability for it.
- **Data-frame flags:** bit 0 `REACHED` (the waypoint is passed), bit 1
  `CONTROL` (for the destination's router). Since v2 the other six
  (`wire::F_EXTENSIONS`) are *end-to-end extension flags*: relays carry them
  unchanged and a destination ignores the ones it doesn't know, so a later
  version can mark packets end to end without upgrading every relay. (v1
  relays clear them; a v2 sender may set them only when that loss is
  harmless.) The `T_DATA` header is not authenticated, so **any relay can
  set or clear any of these bits**, not only a v1 one: they are hints, and
  a use of one must stay safe whatever value arrives (no priority, "do not
  store" or other promise may rest on them). Anything that needs integrity
  belongs inside the end-to-end QUIC payload.
- **Control messages** (`T_DATA` with `CONTROL`): first byte the kind;
  `1` = a signed reachability record for a gateway to publish (§3.7).
  Unknown kinds are ignored.
- (`mycel/v0/mesh-verified-announce` keys a device's cache of announcement
  signatures it has checked. It never leaves the device, so it has no wire
  version.)

| Stream | Kind byte | Since | Body |
|---|---|---|---|
| uni | `1` summary | v1 | postcard `WireSummary` (what a carrier holds, receipts, predictabilities, room); ends with the stream |
| uni | `2` hello | v2 | `Hello{caps}` (at most `MAX_HELLO`, 256 bytes); each side sends one per hop |
| bi | `3` offer | v1 | 4-byte big-endian length + postcard `WireOffer`, answered `WireAnswer`, then the payload and a 1-byte receipt |
| bi | `4` offer v2 | v2 | The same, with the bundle's `(version, kind)` in front of the offer |

Unknown uni-stream kinds are read and ignored; an unknown offer kind gets
no answer (the stream ends).

### 3.6 Store-and-forward bundles

A bundle travels through carriers that are not its destination, possibly
for days, possibly through devices running several different builds, and
its sender cannot negotiate with a destination that is offline. So a bundle
names its own format (`dtn::BundleFormat`) in two parts, after the Bundle
Protocol's split between the primary block that every node processes and
the payload only the endpoint reads (RFC 9171 §4.3):

- **Header version**, what carriers check: the id and signature rules.
  - **v1**: id = `BLAKE3("mycel/v0/dtn-bundle"; src ‖ dst ‖ payload)`;
    signature in context `mycel/v0/dtn-bundle` over `id ‖ created ‖
    lifetime`. The payload kind is implicitly 1.
  - **v2**: id = `BLAKE3("mycel/v2/dtn-bundle-id"; kind ‖ src ‖ dst ‖
    payload)`; signature in context `mycel/v2/dtn-bundle` over `version ‖
    kind ‖ id ‖ created ‖ lifetime`. Its own contexts, so no v1 signature
    or id can be replayed as a v2 one, and the version is signed.
- **Payload kind**, what only the destination reads. Kind 1
  (`KIND_SPACE_SYNC`): postcard `DtnPayload{space, data}`, signed ops and
  encrypted envelopes of one space, readable by any carrier (the space id,
  every membership op and every envelope header). Kind 2
  (`KIND_SPACE_SYNC_SEALED`, header v2 only): postcard
  `Lockbox{enc, ct}`, the HPKE base-mode seal (the lockbox suite) to the
  destination's key-exchange key with `info = "mycel/v2/dtn-seal" ‖ src ‖
  dst` of `DtnPayload2{space, ops, envelopes}` followed by zero bytes up to
  its PADMÉ size class (`bundles.rs`). A node sends kind 2 to every member
  not known to speak only version 1.

Receipts (context `mycel/v0/dtn-receipt`, over the id) are the same for
both: ids of different versions never collide.

| A carrier is offered | It |
|---|---|
| a header version it can check, any payload kind | takes and carries it like any other: it never reads payloads, so an unknown kind is safe to carry |
| a header version it can't check | refuses it (`WireAnswer::Refuse`): it can't verify the signature, and carrying unverifiable bytes would let anyone fill its store |
| (as sender) a v2 bundle, next hop speaks mesh v1 | doesn't offer it (a v1 carrier would read it as v1 and find the signature bad); the planner tries another neighbour |

The destination refuses a payload kind it doesn't know, unread, with
`VersionError::Unsupported` (it still signs the receipt: the bundle was
delivered, carriers should stop carrying it).

The planner reads a hop's version from the hop connection itself (its
ALPN), never from separate state, so a hop replaced in between can't pair
one connection with another's version.

A node sends space data in sealed v2 bundles (kind 2), except to a member
known to speak only version 1 (`PeerState::protocol` without `SYNC_V2`, or
remembered as v1-only), which gets a v1 bundle (kind 1). A v2 bundle
crosses only v2 carriers. Sealing is the default because the v1 payload
exposed a space's membership to strangers (Sync v2 finding 9): a member
not seen since an upgrade loses bundles until it is seen, rather than
every carrier learning the space.

**Header v2 is provisional.** Sealed sync bundles (kind 2) are the first
v2 bundles a build originates (pre-release builds only), and the header's
bytes may still change. One change is planned before any build sends one:
every header version splits the carrier population (a carrier refuses
what it can't check, and carriers are the slowest devices to upgrade, the
case store-and-forward exists for), so header v2 should gain a list of
extension blocks covered by the signature (type, flags including "the
destination may ignore it", bytes), as the Bundle Protocol's extension
blocks under a stable primary block do (RFC 9171 §4.2.4, §4.3.2). Later
additions are then new block types that v2 carriers still verify and
carry, not new header versions. Until that lands, sealed sync bundles are
the only v2 originator, no release may ship with them, and no other change
may depend on the v2 header's bytes (§9).

### 3.7 Discovery and gateway records

- **LAN** (mDNS `_mycel._udp`; Bonjour on iOS): user data `mycel:<name>`,
  unauthenticated, only a hint; QUIC authenticates the key.
- **Reachability records** (pkarr signed packets, through the n0 DNS relay
  and the Mainline DHT): user data `mycel-gw:<z32 key>:<cost>,...|exp:<unix
  s>`, signed by the device's key by pkarr itself. A later layout gets a new
  prefix (`mycel-gw2:`), which older readers don't match and skip.

### 3.8 Calls and video

- **Versions by ALPN**, like the node protocol: a dialer offers
  `mycel/call/2` and `mycel/call/1` (`proto::ALPNS_CALL`, newest first,
  through `Node::connect_offering`), and a listener serves both in that
  order, so a leg lands on the newest both ends speak. A leg's version is
  its connection's ALPN (`proto::leg_version`).
- One bidirectional control stream per leg: messages are a 2-byte
  little-endian length and a postcard `Ctrl` (at most 4 KiB). Both
  versions carry the same bytes; **call/2 adds a promise**: its receiver
  skips `Ctrl` and `VideoCtrl` variants it doesn't have (`proto::recv`,
  `CtrlDeframer::next_msg`) instead of ending the leg. Pre-release builds
  speak only call/1, and they end the leg on a variant they don't know.
- So a new `Ctrl` or `VideoCtrl` variant is appended, says the call
  version that introduced it (`Ctrl::since`, `VideoCtrl::since`, matches
  with no catch-all), and is sent only on legs of that version or newer:
  every message a leg queues passes `proto::send_on` (video:
  `TrackOptions::call_version`), which drops what the leg's version
  lacks. Every message so far is in call/1.
- `Ring`, `Join` and `Watch` carry a `version` field, which nothing reads
  and which stays 1 so they keep their call/1 bytes. A change an older
  build would *misread* takes a new ALPN (`mycel/call/3`), never new bytes
  under an old one.
- Call id: `BLAKE3 derive_key("mycel/v0/call-id", space ‖ initiator ‖
  nonce)`.
- Media: datagrams and unidirectional streams start with a track kind byte:
  `0x01` audio (10-byte frame header), `0x10` video frame, `0x11` video
  control (2-byte length + postcard `VideoCtrl`). Kinds a device doesn't
  know go to the call's `TrackSink`, which drops them.
- `VideoCtrl` variants are only ever appended. A device skips a control
  message whose variant tag it doesn't have (`CtrlDeframer::next_msg`) and
  reads on, so a newer build's message doesn't end the control stream (and
  with it keyframe requests for the rest of the call); a message that
  doesn't decode is still an error.

### 3.9 Links

Links carry opaque QUIC packets, so their framing versions are independent
of the wire version (QUIC and ALPN negotiate above them):

| Link | Versioned by | Unknown version |
|---|---|---|
| Bluetooth LE | `VERSION` byte (1) in the GATT info record and the L2CAP hello (`MYCL` + version). The name ends at the first NUL (names never contain one); since this build, readers ignore anything after it, in a GATT record of up to 512 bytes (`MAX_GATT`) or a hello of any length | GATT record ignored; channel closed as "unsupported version" |
| Peer-to-peer Wi-Fi (AWDL) | TXT `v=1`; control datagrams' 8-byte magic ends in a version byte (`\xffMYCAWD\x01`) | Not recognised as control (treated as a QUIC packet, which fails authentication) |
| Interface link | Beacon magic `MYCELIF\x01` | Beacon ignored |

**Not negotiated yet.** Each link format carries one version and rejects
any other; neither side can offer two. So the first change to a link's
framing would split mixed-version radio neighbourhoods: devices on
different builds would stop finding each other over Bluetooth or AWDL,
the offline case Mycel exists for. Until links negotiate, a link framing
change **must keep accepting version 1 beside the new one** and keep
sending version 1 to devices that only announce it (§9).

Bluetooth is ready for the negotiation to be added without a split: a
later build can append a supported version range after a NUL to its
version 1 GATT record and hello, which this build reads past. (Pre-release
builds don't: they refuse a GATT record longer than 99 bytes and show the
appended bytes as part of the name, so until they are retired an appended
field must be short and is best left out towards devices that don't
announce one.)

### 3.10 Spaces: trust ops, envelopes, rules

These are content-addressed: a space id is its genesis op's id, every op and
envelope is named by the hash of its bytes, and those names are referenced
by later records. Their version is their hash and signature contexts.

| Format | Context strings |
|---|---|
| Trust op (`SignedOp{op, sig}`) | signature `mycel/v0/op` over postcard(op); id `mycel/v0/op-id` over postcard(signed op); lockbox HPKE info `mycel/v0/lockbox ‖ epoch ‖ recipient`; keyring `mycel/v0/keyring ‖ space ‖ nonce ‖ recipient`; epoch id `mycel/v0/epoch-id`, key commitment `mycel/v0/epoch-commit` |
| Envelope | signature `mycel/v0/envelope`, id `mycel/v0/envelope-id`, content AAD `mycel/v0/content`; named streams `mycel/v0/named-stream` |
| Device keys | X25519 key bound to the signing key `mycel/v0/kex-binding`; X25519 seed derived with `mycel/v0/kex-seed` |
| Chat kit | direct-thread id `mycel/v0/direct-thread` |
| Rules bundle | id `mycel/v0/rules-bundle` over the WASM bytes; guest ABI `ABI_VERSION` = 1 ([RULES_ABI.md](RULES_ABI.md)) |

**These contexts were not bumped for wire version 2,** and that is
deliberate: a context's version changes exactly when what it covers
changes. Bumping `mycel/v0/op-id` without a format change would rename every
op and so every space, and orphan every reference to them, for nothing.
`v0` is simply the generation from before versioning; the mesh announcement
context already says `v1` for the same reason (it was changed once).

**Changing them** is a space-level change, not a connection-level one:
every member must resolve every op the same way, so a member that can't
parse a new op kind would see a different membership. Worse, sync carries
typed `Vec<SignedOp>` in `SyncMsg`, so one op of an unknown variant makes
the whole `Hello`/`Data` frame fail to decode (an untyped postcard error,
not a `VersionError`) and sync of the whole space with that peer stops
until it upgrades. `SyncV2` sessions still carry typed items
(`reconcile::Msg<SignedOp, Envelope>`), so the same holds there. The
fix belongs to the `SYNC_V2` stream: it should carry ops and envelopes as
length-delimited opaque items, each decoded on its own, so one a device can't read is set
aside (quarantined, with `VersionError::Unsupported`) while the rest of
the frame syncs. A new op `Action`, envelope header field or stream kind
therefore must (1) get a capability bit, (2) be used in a space only once
every current member's devices support it, and (3) never be sent to a peer
whose hello lacks it. Old records stay valid forever under their old
contexts.

**Rule (2) has no mechanism yet.** Capabilities are known per connection
only: they are not recorded in the space, and nothing carries them for
members reached only through relays or store-and-forward, or for members
who are offline, so no device can check "every current member" today. It
needs a per-device capability statement recorded in the space, signed by
the device and stored with its membership (for example in a member or
device op), which does not exist yet (§9). **Until it lands, no change
may add an op `Action` variant or an envelope field.**

### 3.11 On disk

| File | Versioned by | Unknown version |
|---|---|---|
| `mycel.redb` (ops, envelopes, key-values, quarantine) | `STORE_FORMAT` (1) under `format` (u32 LE) in the `meta` table, read before any other table is opened. A store from before formats were recorded (no `meta` table) is format 1. | A newer format is refused untouched (`VersionError::Unsupported { what: "store" }`): never misread, never overwritten, no table created. Older formats would be migrated forward on open (there are none yet). |
| `identity-state.json` | `version: 1`, `deny_unknown_fields` | Refused ("unsupported identity marker version"); the identity is left alone |
| `identity.key` | 32 raw bytes, checked against the marker's public key | Refused |
| Records in the store | postcard of the wire types above; undecodable rows are quarantined, not deleted | Set aside, startup continues |

The `meta` table and its `format` key are permanent: no migration renames
or reshapes them, so every build finds the format first even if a newer
format renamed every other table. Pre-release builds don't check the
format, so a future format 2 store must not be openable by them by
accident: its migration will rename the tables it changes (redb table
names), so an old build finds them missing rather than misreading them.

---

## 4. Capability registry

`version::CAPABILITIES`; a bit is assigned once and never reused.

| Bit | Name | Protocol | Meaning | Status |
|---|---|---|---|---|
| 0 | `SYNC_V2` | node | Negotiated set-reconciliation sync: a new stream kind whose cost tracks the difference, not the history | Implemented (stream kind `SyncV2`, `mycel_sync::reconcile`); advertised by default (`Caps::SUPPORTED`) unless `NodeOptions::sync_v2` is off |
| 1 | `ROUTE_ATTEST` | mesh | Per-hop attestations on route announcements | Registered; future |
| 2 | `GOSSIP` | node | Dissemination: Plumtree push of new items on `Gossip` uni-streams (with `SYNC_V2`, whose sessions repair what gossip misses) | Implemented (stream kind `Gossip`, `mycel_sync::reconcile::gossip`); advertised by default unless `NodeOptions::sync_v2` is off |
| 3–47 | | | Free, assigned in order | |
| 48–63 | reserved | | Grease: one random bit per hello, never assigned | |

`Caps::SUPPORTED` (what a build advertises by default) is `SYNC_V2 |
GOSSIP` in this build: a bit is added there in the change that implements it.

---

## 5. Mixed versions: what v1 and v2 devices do together

A v2 device and a v1 (pre-release) device:

- **connect** either way: the v2 side offers `mycel/node/2` and `mycel/2`,
  the v1 side offers or accepts only `mycel/2`, so the handshake picks v1;
- **sync spaces, exchange cards, ephemeral messages and blobs, and push
  invitations** exactly as two v1 devices do (v1 formats are unchanged);
- **send no hello and use no capability**: `PeerProtocol::baseline(1)`;
- **relay for each other** on a `mycel/mesh/1` hop: announcements and data
  frames are unchanged (a v1 relay clears end-to-end extension flags);
- **carry each other's v1 bundles**; a v2 bundle is never offered to a v1
  carrier, and a v1 device never originates one;
- **call each other** on `mycel/call/1` (unchanged), and the current
  device sends that leg only call/1 messages.

Two v2 devices use v2 on both protocols and the capabilities they share.

**Which pre-release builds are version 1.** Version 1 is the node and mesh
wire format of main at commit `98d9b7b` (the last commit before
versioning). Its bytes are pinned by golden vectors that `98d9b7b`'s own
`mycel-net` printed (`mesh::v1_vectors`, and the contact code in
`mycel-node`): every version 1 encoder and decoder in this build must
match them byte for byte. `scripts/v1-compat/run.sh` reproduces that: it
checks out the old code, prints the vectors with its encoders and
compares them, then runs an old node against a node of this build (a
space synced both ways, cards fetched). Run on 2026-10-21, both passed
against `98d9b7b` and against the `dev-2026-10-09-apps` release (the one
testers run): 33 of 33 vectors, including sync data with a signed op and
an envelope.

That is about bytes on the wire and one basic exchange, not about
everything a build accepts: between that release and `98d9b7b`,
validation and resolution changed (bounded checks on untrusted sync,
trust ops applied in causal order), so a change or op ordering the
release produces may still be refused or resolved differently by a newer
build. **Full interoperability is a claim only against `98d9b7b`**, and
even there only as far as the mixed-version tests and that script go.
Pre-release builds older than `dev-2026-10-09-apps` are not checked at
all.

Pre-release builds stay usable, with one limit from before versioning:
the chat rules bundle a space runs is not recorded in the space
([RULES_ABI.md](RULES_ABI.md) §6), so devices in one space should still run
builds with the same rules.

---

## 6. Changing a format: the checklist

1. **Can an older device misread it?** Then it is a new wire version: a new
   ALPN offered beside the old ones, handled side by side until the old one
   is retired (never reuse an ALPN for different bytes).
2. **Is it an addition an older device can do without?** Then it is a
   capability: append a bit to `CAPABILITIES` and this document §4, use it
   only when `PeerProtocol::supports` says both sides have it.
   **A capability that adds security must state its downgrade policy**:
   anyone can simply not advertise a bit, so "used only when both sides
   have it" alone lets an attacker opt out. Say how peers without it are
   treated once enough peers have it. For `ROUTE_ATTEST`: once a device
   has attesting neighbours, routes through hops that don't attest rank
   below attested ones and are used only as a fallback (a lying relay
   that stops advertising the bit loses its routes instead of keeping
   them).
3. **New stream kind:** next free byte; older devices refuse it with
   `STREAM_REFUSED`, so it must also be behind a capability.
4. **New enum variant** in a postcard message: only appended, and only sent
   to peers that can decode it, because postcard fails on an unknown
   variant tag. On the node protocol and mesh that takes a capability (as
   a new `BlobReq` variant would); on call legs, the call version that
   introduced it (`Ctrl::since`, `VideoCtrl::since`, §3.8).
5. **New signed or hashed format:** a new context string with the new
   version in it, and the version inside what is signed.
6. **New persisted layout:** bump `STORE_FORMAT` with a migration, and make
   the old layout unreadable to the old build (renamed tables).
7. **Out-of-band formats** (codes, records): a new prefix, so old readers
   skip it and new readers can name the version they don't support.
8. **Tests:** a device offering only the old version against one with the
   new (`Protocol { version: WIRE_V1, .. }` in `mycel-net`), and a test that
   unknown values are refused or ignored as the format says. Those tests
   run this build's code on both sides, so they can't see an old format
   changing by accident: the golden vectors (`mesh::v1_vectors`) can. Never
   regenerate a version's vectors from a newer build; a new version gets
   its own, printed once by the build that introduces it.

---

## 7. Errors

`version::VersionError`, attached to `anyhow` errors so callers can
`downcast_ref` it:

| Variant | When |
|---|---|
| `Unsupported { what, version, newest }` | A format version this build doesn't speak (a store, contact code, bundle header or payload kind). Its message says "update Mycel" when the version is newer. |
| `UnknownStreamKind(byte)` | (Listener side) a stream started with a kind the connection's version doesn't have |
| `StreamRefused` | (Opener side) the peer reset our stream with `STREAM_REFUSED` |
| `MissingCapability(caps)` | A feature needs a capability the peer lacks |
| `Malformed(what)` | A versioned header that doesn't parse (a hello) |

No decoder panics on input from a peer, and none guesses: a version or kind
it doesn't know is refused or, where the format says so (capability bits,
data-frame extension flags, mesh uni-stream and control kinds, bundle
payload kinds at a carrier, call and video control messages of a newer
variant, fields after the name in a Bluetooth GATT record or hello),
ignored or carried unread.

---

## 8. Tests

`cargo test -p mycel-net --lib version` and `mesh::tests`, `-p mycel-node
--lib`, `-p mycel-call --lib`:

| Test | Shows |
|---|---|
| `version_tests::a_failed_hello_is_retried_on_the_same_connection` | A hello the peer drops leaves the connection without capabilities, is counted, and a later use of the same connection agrees them; when every try is lost it stops after `HELLO_TRIES` |
| `version_tests::a_node_serves_its_newest_versions_first` | A full `Node` (mesh on) answers a dialer that lists the oldest version first with the newest, on the node protocol and mesh |
| `version_tests::current_devices_negotiate_version_2_and_common_capabilities` | Two v2 nodes agree v2 and exactly the shared capabilities; an unknown bit is ignored; one dial, and one hello served (counted) for two `negotiate` calls |
| `version_tests::strangers_that_dial_leave_no_peer_state` | 8 strangers (4 on v1, 4 with a v2 hello) dial a node and fetch its card: it answers all and keeps no `PeerState` for them; a member that dials is noted |
| `version_tests::every_version_has_its_own_alpns` | One ALPN per version per protocol, none shared, each maps back to its version; the compile-time table check refuses duplicates, misplaced versions and empty names |
| `version_tests::a_version_1_device_and_a_version_2_device_talk_version_1` | A v1-only node and a v2 node pick v1 whoever dials, send no hello, and sync a space both ways and fetch cards |
| `version_tests::unknown_stream_kinds_are_refused_cleanly` | An unknown bi or uni stream kind is refused in under 5 s with `StreamRefused` and the connection carries on; a hello on a v1 connection is refused too |
| `version_tests::bundles_of_an_unknown_payload_kind_are_refused_unread` | The destination refuses an unknown payload kind with a typed error |
| `mesh::tests::hops_negotiate_versions_and_capabilities` | Mesh hops: v2 with shared capabilities between v2 devices, v1 with none to a v1 device |
| `mesh::tests::bundles_cross_hops_by_their_format` | A carrier carries a v2 bundle of an unknown payload kind, refuses an unknown header version, and a v2 bundle is never offered over a v1 hop (`encode_offer` gives nothing, and the v1 carrier refuses nothing: it was never asked); v1 bundles cross both |
| `mesh::tests::the_planner_sends_bundles_only_over_hops_that_take_their_format` | Through the planner (`Mesh::send_bundle_as`): a v2 bundle reaches only the v2 neighbour and is never offered to the v1 one; a v1 bundle then reaches both |
| `mesh::v1_vectors::*` | Every version 1 encoding byte for byte against vectors printed by main `98d9b7b`: ALPNs, stream kinds, every `SyncMsg` (one carrying a signed op and an envelope), `DtnPayload`, `EphMsg`, every blob request and answer, a contact card and its signature, a signed announcement, a `T_OGMS` pair, a `T_SEQREQ`, a data-frame header and a control frame's, a bundle id and signature, a `K_OFFER` frame, offer answers, a receipt, a carrier summary; and that this build decodes them. Not pinned: the reachability record inside a control frame (pkarr-signed, with a timestamp) |
| `scripts/v1-compat/run.sh` (by hand, not in CI) | The vectors above printed again by `98d9b7b`'s own code and compared; a node built from `98d9b7b` (or `BASE=dev-2026-10-09-apps`) and one of this build pick version 1, sync a space both ways and fetch each other's cards over loopback (`tests/v1_compat.rs`, ignored in a plain `cargo test`) |
| `mesh::core::tests::relays_carry_unknown_frame_flags_unchanged`, `mesh::wire::tests::frames_round_trip_with_flags` | End-to-end extension flags survive relaying and fragmentation |
| `version::tests::*` | Registry bits unique and outside the reserved range; unknown and reserved bits ignored; hellos carry one reserved bit and may grow at the end |
| `store::tests::stores_record_their_format_and_newer_ones_are_refused`, `stores_from_before_formats_open_as_format_1`, `a_newer_store_without_the_tables_we_know_is_refused` | Store format recorded in `meta`; a newer one refused untouched, even when it renamed every other table |
| `runtime::tests::contact_codes_carry_their_format`, `version_1_contact_codes_are_pinned` | `mycel2:` codes refused with a typed error; `mycel:` and bare codes read; a version 1 code byte for byte as `98d9b7b` writes it |
| `proto::tests::messages_round_trip`, `recv_skips_messages_from_a_newer_revision` (mycel-call) | Call control messages of a newer variant are skipped on a stream and the next message arrives; garbage is still an error |
| `proto::tests::legs_get_only_the_messages_their_version_has` (mycel-call) | Call versions by ALPN, newest first; a message newer than a leg is never sent on it; every current message is in call/1 |
| `calls::a_call_1_device_and_a_call_2_device_call_on_call_1` (mycel-call) | A device serving only `mycel/call/1` and a current one call each other both ways on call/1 with audio; two current devices land on call/2 |
| `wire::tests::ctrl_messages_from_newer_builds_are_skipped` (mycel-video) | Video control messages of a newer variant are skipped and the next one arrives; garbage is still an error |
| `wire::tests::fields_a_later_build_appends_are_ignored` (mycel-link-ble) | A GATT record or L2CAP hello with fields after the name's NUL still reads; names never carry a NUL |

---

## 9. Not done yet

What versioning does not cover yet, so that no other change relies on it:

- **Capabilities recorded in a space** (§3.10): a signed per-device
  capability statement stored with membership. Until it exists, no op
  `Action` variant or envelope field may be added.
- **Link framing negotiation** (§3.9): Bluetooth LE and AWDL carry one
  framing version each. A framing change must keep accepting version 1
  beside the new one until the L2CAP hello and GATT record carry a version
  range (Bluetooth readers already skip appended fields).
- **Bundle header v2 extension blocks** (§3.6): planned before any release
  originates a v2 bundle (sealed sync bundles already do, in pre-release
  builds).
- **Persisted peer capabilities**: which payload kind a member gets is
  decided from capabilities seen since the node started; they are not
  kept across restarts yet.
- **Ops and envelopes as opaque items in sync** (§3.10): for `SYNC_V2`, so
  one unreadable item doesn't stop a space's sync.
- **`ROUTE_ATTEST` ranking** (§6): the downgrade policy above is the rule
  the attestation work must implement; nothing implements it yet.
- **Cross-build interop in CI**: `scripts/v1-compat/run.sh` runs a real
  pre-release build against this one, by hand (it builds the old code from
  scratch, minutes). It covers the node protocol only: mesh hops,
  store-and-forward and calls between builds are tested with this build's
  code on both sides, not with the old code.
