# Offline delivery through the internet: custodians

A message to a device that is offline used to sit on the sender's device
with a clock until both were online at the same moment, even when the
recipient's other contacts and plenty of other Mycel devices were online
the whole time. This document is the design record of the fix:
**custodians**, devices that hold a sealed copy for the recipient and hand
it over when it comes back. Code: `crates/mycel-net/src/custody/` (the pure
state machines in `mod.rs`, the node's side in `node.rs`). Wire formats are
in [PROTOCOL.md](PROTOCOL.md) §3.12, limits in [TRUST.md](TRUST.md) §8f, and
how it sits beside keepers and store-and-forward in
[ARCHITECTURE.md](ARCHITECTURE.md) and [ROUTING.md](ROUTING.md) §7.5.

---

## 1. The problem

The bug report: in a one-to-one chat the recipient's device is offline, the
sender's other devices and other Mycel devices are online, and the message
shows a clock forever. The user expects the network to carry it.

Why it didn't (verified in the code before this change):

1. `Runtime::delivery` showed `Local` (the clock) until a member or keeper
   (`Role::Relay`) held the envelope.
2. Space sync is member-gated (`serve_sync` and Sync v2 refuse non-members),
   and a direct chat has no keeper unless someone adds one, so no other
   device would take the envelope.
3. The store-and-forward carrier (`mesh/dtn.rs`, `offer_bundle`) moves
   bundles only between mesh neighbours (radio and LAN hops). Internet peers
   are not carriers, and gateways refuse internet-to-internet relaying (they
   are not open proxies).
4. Even when a carrier took a bundle, the app kept showing the clock.

## 2. What others do

| System | Where offline messages wait | Who can fetch | What the store learns | Abuse control | Fit for Mycel |
|---|---|---|---|---|---|
| **Briar Mailbox** | A spare phone the user owns, reached as a Tor onion service; contacts upload to per-contact folders | The owner | Contacts' uploads (over Tor); content is encrypted | Pairing by QR: only the owner's contacts can upload | The idea of *your own device first* fits; needing a dedicated device does not (most users have none) |
| **SimpleX** | Unidirectional queues on SMP relays the *recipient* chooses | The recipient, per-queue keys | No user identities; with private message routing (two relays) the destination relay doesn't see the sender's IP | Per-queue keys, server rate limits | Recipient-authenticated pull and "no user ids on the server" fit; relays are run by operators, a server dependency Mycel avoids |
| **Session** | A *swarm* of service nodes chosen by the recipient's key | The recipient | Recipient key, size, time; onion requests hide the sender's IP | Staking (Oxen) for Sybil resistance; PoW on storage was dropped | Key-addressed placement fits; staking and onion routing are out of scope |
| **Cwtch** | Untrusted servers that store everything for a group | Every member downloads everything and trial-decrypts | Nothing about who talks to whom | Server-side limits | Strong metadata privacy at a bandwidth cost that rules it out for phones on slow links |
| **Ditto** | Peers in the mesh and a "Big Peer" cloud | Peers by subscription | The cloud sees data | Accounts | Shows mesh sync works; the cloud role is what Mycel won't have |
| **Bluesky PDS** | The user's own always-on server | Anyone (public data) | Everything (public) | Accounts, moderation | A personal always-on host; public data, so a different problem |
| **Kademlia / S/Kademlia** | k nodes XOR-closest to a key | Anyone who looks up the key | The key | S/Kademlia: costly node ids, disjoint lookup paths, sibling sets | XOR placement lets a sender and a recipient find the same nodes with no index; S/Kademlia's defences are the known answer to eclipse attacks |
| **libp2p** | Kademlia records; circuit relay v2 with reservations | By key | Record contents | Relay v2: short reservations, data caps per circuit | Strict, small, per-peer budgets for a service run for strangers |
| **iroh** | Address records (pkarr) in the Mainline DHT and the n0 relay | Anyone, by key | Addresses | Signed records | Already used by Mycel to find a device by key; holds addresses, not messages (BEP 44 values are at most 1000 bytes) |
| **Signal sealed sender** | Signal's servers | The recipient | The recipient; the sender is inside the encryption (the server still sees the IP) | Delivery tokens from the recipient's profile key, rate limits | Sealing the sender inside the envelope is cheap and removes it from what rests on a stranger's disk |

## 3. The choice

A Session-style placement by the recipient's key, without staking, with a
Briar-style preference for devices the sender already trusts, Signal-style
sealed sender inside, and SimpleX-style recipient-authenticated pull:

1. **Custodians in order of trust** (`custody::select`): the sender's own
   other devices (in this build, the keepers of its spaces: always-on
   devices it or its contacts chose), then devices that share a space with
   the recipient (they will meet it anyway: it syncs with them when it comes
   back), then **volunteers** XOR-closest to the recipient's key. Up to 3
   copies (`DEFAULT_COPIES`), at most 8 candidates tried.
2. **Volunteers without an index**: every device keeps the custodians it has
   talked to in Kademlia k-buckets (`custody::Directory`, 16 per bucket,
   keeping old live entries as Kademlia does), and answers `Find{target}`
   with the 8 closest it knows. A lookup asks the 3 closest known, then the
   3 closest of what they named (two rounds of α = 3). Sender and recipient
   both look up the recipient's key, so they find the same custodians. Keys
   from answers are only candidates for that lookup; a device enters the
   directory only after its own hello advertised custody, so others' answers
   can't fill it.
3. **Sealed parcels**: the payload (today the space's signed ops and
   encrypted envelopes the recipient lacks, `KIND_SPACE_SYNC`) and the
   sender's key and signature are sealed with HPKE to the recipient's
   key-exchange key, after padding to a PADMÉ size class. The parcel names
   only the recipient.
4. **Only the recipient fetches**: the fetch runs on a QUIC connection
   authenticated to the fetcher's key (Mycel's endpoint id is its signing
   key), and a custodian lists and hands over only parcels addressed to that
   key. No separate proof of key ownership is needed, and none can be
   replayed: the TLS handshake is the proof.
5. **Receipts and releases**: the recipient signs a receipt per parcel; the
   custodian drops it, and remembers the id so a re-deposit is a duplicate.
   The sender, once a live sync with the recipient succeeds, withdraws the
   parcel at each custodian with the secret whose hash the parcel carries.

Why not the alternatives: putting messages in the Mainline DHT (values are
1000 bytes, stored by BitTorrent nodes that don't know Mycel, no deletion);
a Cwtch-style broadcast store (cost grows with everyone's traffic, not
yours); dedicated mailbox devices only (most people have none); onion
routing every deposit (a large build for a privacy gain the threat model in
§6 shows is partial anyway; recorded as later work).

## 4. How it works

### Sending

1. A live sync to a member fails, or isn't through after 10 s
   (`BUNDLE_AFTER`, as for store-and-forward bundles). Besides offering a
   bundle to mesh carriers, the node calls `offer_custody(peer, space)`.
2. `plan`: what the member lacks (envelopes it isn't known to hold), minus
   what is already in custody for it (`Outbox::covered`), within 200 KB of
   items (`MAX_BUNDLE_PAYLOAD`), with the space's ops the first time. So a
   backlog goes out as successive parcels, not the same one again. Sealed
   (`custody::seal`), registered in the outbox as pending.
3. `candidates`: the tiers above; within the first two, devices seen online
   first, then a fixed order per recipient (rendezvous hash) so retries go
   to the same devices.
4. Deposits run in parallel to the first 3; each failure (offline,
   refusal) starts the next candidate. A custodian that shares no space with
   the sender asks for a proof of work, so the sender mints one for it
   (bound to that parcel and that custodian). Each `Stored` answer is an
   acknowledgement: the outbox records the custodian and the app's delivery
   state changes.
5. A live sync with the member later withdraws its parcels (`Release`).

### Keeping and delivering

- A custodian stores the parcel in its `Vault` (limits in §5).
- **Pull**: a device asks for its mail ("anything for me?", `Fetch`) of every
  custodian it connects to (at most every 10 min per custodian, and only
  custodians it dialed or shares a space with), and every 30 min of the 3
  custodians closest to its own key.
- **Push**: a custodian holding mail for a device delivers when that device
  connects to it, and otherwise tries to dial it (which looks up its
  record, so a device whose record says it is online is reached), backing
  off from 1 min to 1 h, at most 4 new attempts every 10 s.
- **Rounds**: `Listing` (ids and sizes) → `Take` (what it lacks, receipts
  for what it already has) → `Parcels` (up to 2 MiB) → `Receipts`, until
  the listing is empty or a round makes no progress. The recipient opens
  each parcel, checks the padding and the sender's signature, and applies
  the payload exactly as a sync from that sender: the space's own rules
  decide whether the sender may write there.

### What the app shows

`Delivery` gains `Carried` between `Local` and `Sent`
(`crates/mycel-node/src/api.rs`), with `MessageView::carried_by`: how many
devices acknowledged custody of a sealed copy, internet custodians and
store-and-forward carriers that took our bundle alike (`Node::carried`).
`Sent`, `Delivered` and `Read` keep their meaning: `Carried` is only shown
while no member or keeper holds the message. The Messaging app draws a
clock with a hand-off arrow, titled "Waiting for the recipient — carried by
3 devices" ([USER_GUIDE.md](USER_GUIDE.md) §9).

## 5. Limits and abuse resistance

Custody is on by default with conservative limits (`VaultConfig::default`):

| Limit | Default | Why |
|---|---|---|
| Store | 32 MiB | Half the mesh carrier's 64 MiB, on top of it |
| Parcel | 256 KiB | The carrier's bundle cap |
| Per depositor key | 2 MiB, 256 parcels (twice for a device that shares a space with us) | One device can't take the store |
| Per source address | 8 MiB per IPv4 address or IPv6 /64; 16 MiB for everyone behind the internet relay | Fresh keys are free; addresses aren't |
| Per recipient | 4 MiB | Nobody can bury one victim's mailbox, nor make one recipient cost the custodian the store |
| Parcels in total | 8,192 | Small parcels can't exhaust memory by count |
| Lifetime | At most 7 days from arrival (parcels ask 3 days) | As carriers |
| Clock skew | `created` at most 10 min in the future | |
| Deposit rate | Per key: 32, then one per 2 s; per address: 128, then one per 0.5 s | Bursts, then a trickle |
| Proof of work | 16 bits (about 65,000 BLAKE3 hashes) from depositors that share no space with the custodian, bound to the parcel and the custodian | A fresh key must pay, and a stamp is good once, at one custodian |
| When full | The soonest-expiring parcel of the biggest depositor goes, only if it holds more than the newcomer would | A flood evicts itself, never a small depositor |
| Find, fetch | 16 lookups (then one per s) and 8 fetches (then one per 5 s) per peer | |

- **No amplification**: custodians never pass parcels to other custodians;
  every exchange runs on a QUIC connection whose address was validated
  during the handshake, so nothing can be reflected at a forged address;
  the answer to a deposit is a few bytes.
- **Draining and enumeration**: listings and parcels go only to the key on
  the other end of the connection; a parcel for someone else is never
  listed or handed out, receipts are verified against the parcel's
  recipient, and a release needs the sender's secret.
- **Sybil and eclipse**: grinding keys close to a target is cheap, so a
  volunteer tier alone could be captured; the first two tiers (own devices,
  co-members) come before volunteers, and a captured volunteer can only
  drop what it holds (the other copies still deliver). S/Kademlia's costly
  node ids and disjoint lookups are later work (§8).
- **Phones**: `Node::set_custodian(false)` (the Network panel's "Carry for
  others" switch, `set_custodian` in the API) refuses deposits at once and
  stops advertising `CUSTODIAN` on new connections; parcels already held are
  still delivered. A host can turn it off on battery or a metered network.
- **Older builds**: everything rides on the `CUSTODY` capability (stream
  kind 8, wire version 2); a peer without it is never sent a custody
  stream, and a build without custody refuses the stream kind with
  `STREAM_REFUSED`, so older builds are unaffected.

## 6. Threat model: what custodians learn

| A custodian learns | From |
|---|---|
| The recipient's key | The parcel's `dst` (needed to deliver) |
| A size class | PADMÉ padding: at most 12% overhead, O(log log size) bits of the size |
| When the parcel was created (to the minute), its lifetime, when it was deposited and fetched | The header, and the connections |
| **Who deposited it** (key and address) | The QUIC connection. In the common case that is the sender. If the sender deposits through one of its own devices, that device learns it instead |
| The recipient's address when it fetches | The QUIC connection |
| That the depositor and recipient are probably in contact | Both of the above |

It does **not** learn the content, the space, the other members, the
sender's identity from the parcel itself (a parcel at rest, or handed on,
names no sender), or anything about other recipients' mail. It can drop or
delay a parcel (other copies still arrive), but can't alter it (the header
is bound to the seal and to the id, the content is AEAD-sealed and signed by
the sender inside), forge one (the recipient checks the sender's signature
and the space's rules), or replay one usefully (applying the same sync
twice changes nothing).

Compared with today's paths: a keeper is a member and sees the space's
ciphertext and its members; a mesh carrier sees the source and destination
keys of a bundle (version 1 bundles also expose the space; the Sync v2 stage
3 sealed bundles fix that). A custodian sees less about the content than
either, and about the same metadata as a relay.

Harvest-now-decrypt-later applies as for the lockbox suite (X25519 HPKE);
the Sync v2 design records the hybrid KEM migration (X-Wing) that would
cover parcels too.

## 7. Measured

- **Unit tests** (`cargo test -p mycel-net --lib custody`, 14 tests): parcels
  open only for their recipient and carry no sender in the clear; the header
  can't be changed or re-addressed; padding classes; stamps bind parcel and
  custodian; a custodian delivers only to the recipient and drops on a
  genuine receipt, not a forged one; strangers need a stamp, known devices
  don't; malformed, expired, oversized and newer-format parcels are
  refused; a spammer hits its depositor share, then fresh keys from one
  address hit the address share, bursts hit the rate limit; a full store
  evicts from the biggest depositor only; selection order; the directory's
  bucket policy; the outbox's coverage, acknowledgements and release.
- **Real QUIC nodes** (`cargo test -p mycel-net --test custody`, 3 tests, loopback):
  - A writes to B while B is offline; C (in a group with A and B) takes
    custody about 16 s after the write (the live attempt has to fail
    first: a dial to a dead address times out); A shuts down; Eve fetching
    from C gets nothing and C keeps B's parcel; B restarts with only its
    spaces' genesis ops, syncs with C, and has A's message **11 ms** later
    (membership included, from the parcel); B's receipt clears C.
  - The same through a volunteer A and B share no space with: A pays the
    proof of work, B finds the volunteer by looking up its own key.
  - A stranger flooding a custodian is cut off with `DepositorShare` within
    its 48 KiB share; an honest device's deposit is still stored.
- **Runtime** (`cargo test -p mycel-node --test runtime
  a_message_to_an_offline_device_is_carried_and_delivered_later`): through the
  whole app API, a message to an offline device reads `Local`, then
  `Carried` with `carried_by == 1`; after the sender closes, the recipient
  reopens and gets it from Carol.
- **Simulation** (`offline-recipient`, tier 2, `crates/mycel-sim/src/tier2/custody.rs`;
  [SIMULATION.md](SIMULATION.md)): internet-only devices in four time zones,
  phones used 07–23 local and online a quarter of that in ~15 min spells,
  half the people with a laptop, 5% with an always-on device, 10% of direct
  chats with a keeper, 30% of phones refusing custody; the real `select` and
  `Vault`. 12 seeds per run, "keepers only" (before) against custodians:

  | Messages sent while the recipient was offline | Keepers only | Custodians |
  |---|---|---|
  | Delivered within 1 h (200 people, CI size, seeds from 1) | 32.7% | **59.9%** |
  | Delivered within 4 h | 68.5% | **85.9%** |
  | Delivered within 24 h | 99.6% | 100.0% |
  | Latency p50 / p95 (all messages) | 4,109 s / 50,555 s | **1,508 s / 29,505 s** |
  | Within 1 h / 4 h, 2,000 people, seeds from 2000 | 34.2% / 71.2% | **62.7% / 88.4%** |

  98.4% of those messages found a custodian, 2.89 on average; the busiest
  custodian held 27 KB. Within a day both reach ~100% (everyone is awake at
  some point): custody changes how soon. The tail is set by time zones (a
  recipient asleep until morning), which no custodian shortens. The model
  favours custody in two ways, stated in the scenario: the XOR lookup is
  taken as converged, and a custodian and recipient online together are
  taken to find each other within a second.
- **Fuzzing** (`fuzz/fuzz_targets/custody.rs`): the custody messages, parcel
  opening, and a store driven by hostile steps with `Vault::check` after
  each: 159,453 inputs in 3 minutes, no finding.

## 8. Not done, and risks

- **Persistence**: a custodian keeps parcels in memory (as the mesh carrier
  does); a restart loses them. The other copies, and the sender's own retry
  on its next failed sync, cover it; persisting the vault in the store is
  the next step.
- **Own devices**: Mycel has one device per member and no multi-device
  identity, so "the sender's own other devices" are, in this build, the
  keepers of its spaces. A real "my devices" pairing would make that tier
  exact.
- **The sender is visible to the custodian it deposits with** (§6). Hiding
  it would need a two-hop deposit (through an own device or a volunteer
  proxy, as SimpleX's private routing does).
- **Volunteer capture**: no S/Kademlia defences yet (costly node ids,
  disjoint lookup paths); mitigated by the tier order and multiple copies.
- **Lookup convergence**: two rounds of α = 3 over each device's directory;
  in a large network without shared contacts a sender's and a recipient's
  lookups may find different volunteers. The simulator assumes they agree.
- **Parcels repeat what bundles carry**: a sender with mesh neighbours sends
  both a carrier bundle and custody parcels for the same envelopes. Both
  are bounded; receipts and releases clear them.
- **Payload**: parcels carry the version 1 payload (`DtnPayload`, every op
  the first time, envelopes in id order). The Sync v2 stage 3 branch
  (`v2/w2-sync3`) builds `KIND_SPACE_SYNC_SEALED` with oldest-missing-first
  selection; its `DtnPayload2` plaintext can go inside a parcel as a new
  inner payload kind without changing the parcel format (the parcel carries
  any `kind`). Its PADMÉ rule is the same as here. Capability bit 2 and
  stream kind 7 are that branch's (`GOSSIP`, `Gossip`), which is why
  custody takes bit 3 (`CUSTODY`), bit 4 (`CUSTODIAN`) and stream kind 8.
- **Battery and metered detection**: the switch exists (`set_custodian`);
  hosts don't yet flip it from battery or network state.
- **Receipts don't spread between custodians**: each custodian learns of
  delivery from the recipient (when it fetches or is pushed to) or from the
  sender's release; one the recipient never talks to again keeps its copy
  until it expires.
- **Not reviewed externally**, like the rest of the trust layer.
