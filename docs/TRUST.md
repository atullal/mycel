# Mycel trust layer: specification

How Mycel decides who may read and write what, with no server to ask. This
is the layer as implemented in `crates/mycel-crypto`, `crates/mycel-trust`
and `crates/mycel-sync`. Its records are generation 0 (`mycel/v0/…` context
strings), unchanged by wire version 2; how they would change is in
[PROTOCOL.md](PROTOCOL.md) §3.10.

> **Rule zero: no custom cryptography.** Only standard, widely reviewed
> primitives. **This layer has not had an external review.** Don't rely on
> it for anything that needs to stay secret until it has.

## 1. Threat model

**Adversaries we defend against**
- **Outsiders:** anyone on the network, including relays and keepers. They must not read content, forge membership, or forge content.
- **Keepers:** honest-but-curious or malicious storage nodes. They can drop, delay or replay data. They cannot read it, forge it, or make it valid.
- **Removed members:** must not read content created after peers learn of the removal. Must not get new writes accepted.
- **Lower-privileged members:** readers cannot write; writers cannot change membership.
- **Malicious writers:** cannot impersonate other authors, rewrite others' history, or make peers diverge.

**Out of scope (documented limits)**
- **Admins are trusted with keys.** A malicious admin can leak keys out-of-band.
- **A removed member keeps what they already decrypted,** and can read content that partitioned peers keep encrypting under an old epoch before they learn of the removal.
- **Metadata is visible to keepers:** membership public keys, envelope authors, sizes and timing.
- **Availability:** keepers can withhold data. Mitigation is multiple keepers. Withholding cannot be detected.
- **Phones that are asleep:** with no push server, a suspended iPhone receives nothing until iOS lends Mycel time or it is opened ("slow mode"). An optional wake relay is designed, not built (§8e).
- **Forward secrecy within an epoch:** not provided. Only post-compromise security on rotation.
- **A compromised device** can act as its member until removed.

## 2. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Signatures, device identity, transport identity | Ed25519 | `ed25519-dalek` |
| Key agreement for lockboxes | HPKE (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode | `hpke` |
| Content encryption | XChaCha20-Poly1305 (192-bit random nonce) | `chacha20poly1305` |
| Hashing, IDs, key commitments | BLAKE3 (`derive_key` mode for commitments) | `blake3` |
| Canonical encoding (bytes that get signed) | postcard (deterministic for a fixed schema) | `postcard` |
| Randomness | OS CSPRNG | `rand`/`getrandom` |
| Secret hygiene | zeroize on drop | `zeroize` |

**Domain separation:** every signature, KDF and HPKE `info` input is prefixed with a unique context string, e.g. `mycel/v0/op`, `mycel/v0/envelope`, `mycel/v0/lockbox`. This also separates our signatures from TLS signatures made with the same Ed25519 key by Iroh. TLS 1.3 signs a 64-space-prefixed context, so the two cannot collide.

## 3. Identity

- **Device keys:**
  - `sign`: Ed25519. Also the Iroh node ID, so a transport connection authenticates the device.
  - `kex`: X25519, used for lockboxes.
- **MemberKeys:** `{ sign_pk, kex_pk, kex_sig }`, where `kex_sig = Sign(sign_sk, "mycel/v0/kex-binding" ‖ kex_pk)`. This proves the device holds both keys, so an attacker cannot substitute a kex key during the invite exchange.
- **A member is one device.** Each device has its own keys; one person's devices are separate members of a space.

## 4. Spaces and the membership graph

A **Space** is defined by a DAG of signed **membership ops**:

```
SignedOp { op: Op, sig: Ed25519(author, "mycel/v0/op" ‖ postcard(op)) }
Op       { space: SpaceId?, parents: [OpId], author: SignPk, nonce: u64, action: Action }
OpId     = BLAKE3(postcard(SignedOp))
SpaceId  = OpId of the Genesis op   (Genesis has space = None, parents = [])
```

`nonce` is random. It makes otherwise-identical ops distinct, e.g. re-adding the same member.

**Roles** (fixed order `Relay < Reader < Writer < Admin`):

| Role | Read keys | Write content | Rotate keys | Change membership | Store/forward |
|---|:-:|:-:|:-:|:-:|:-:|
| Relay (keepers) | | | | | ● |
| Reader | ● | | | | ● |
| Writer | ● | ● | ● | | ● |
| Admin | ● | ● | ● | ● | ● |

**Actions**

| Action | Authorized if author (in the op's causal state) is | Effect |
|---|---|---|
| `Genesis { founder, rotation }` | anyone (must be the unique root) | founder = Admin; epoch 0 |
| `Add { member, role, keyring }` | Admin | member gets role; `keyring` lockbox gives readers all prior epoch keys |
| `SetRole { member, role, cutoff, rotation? }` | Admin | changes role. A *downgrade* is a **revocation**: it carries `cutoff`, and if read access is lost it also carries `rotation` |
| `Remove { member, cutoff, rotation }` | Admin | **revocation**: removes the member and must rotate |
| `Rotate { rotation }` | Writer+ | new epoch key for exactly the current readers |

**Rotation** = `{ epoch: EpochId(random 16B), commitment, lockboxes: [(recipient SignPk, HPKE ciphertext)] }`
- `commitment = BLAKE3.derive_key("mycel/v0/epoch-commit", key)`. Each recipient checks the key it unseals against the commitment, so a rotator cannot hand some members a different key undetected.
- HPKE `info = "mycel/v0/lockbox" ‖ epoch ‖ recipient_sign_pk`. This binds each lockbox to its epoch (a random 128-bit ID) and its recipient. Genesis can't bind the space ID because the space ID is the hash of genesis itself. Keyring lockboxes in `Add` additionally bind `space ‖ op nonce`.
- **Validation:** the recipient set must equal *exactly* the set of members with read capability in the post-op state. A lockbox for a non-member, or a missing member, makes the op invalid.

## 5. Resolving the graph (deterministic, so it converges)

Every peer computes the valid op set and the resulting state with the same algorithm:

1. **Topological order** `T`: Kahn's algorithm, ties broken by `OpId` bytes.
2. **Seniority:** founder = rank 0. Every other member is ranked by the `T`-index of the first `Add` naming them. This is independent of validity, so it is stable.
3. **Revocation winners:** consider revocation ops in order of (author seniority, `T`-index). A revocation `r` **loses** if an earlier winner `w` revokes `r`'s author and `r` is concurrent with `w`. Concurrent means neither is an ancestor of the other. This makes mutual removal resolve in favour of the more senior admin.
4. **Concurrent invalidation:** for each winner `w` targeting member `X`, every op by `X` that is concurrent with `w` is invalid. *Revocation wins over concurrent actions by the revoked member.*
5. **Authorization replay:** walk `T`, skipping ops invalidated in step 4. Check each op against `state(valid ∩ past(op))`, i.e. *what the author could prove they were allowed to do when they made the op*. An unauthorized op is invalid and excluded from every state. Its descendants are judged on their own merits.
6. If a step-3 winner fails step 5, drop it from the candidates and repeat from step 3. This terminates because the candidate set only shrinks.
7. **Current state** = replay of all valid ops in `T`.

Ops whose parents are unknown are **pending** and are not evaluated until the parents arrive.

**Heads.** The authoring frontier (`heads()`: the `parents` of a new op, and the `auth_heads` of a new envelope) is the set of causally maximal **valid** ops. Invalid ops are still stored, still count for ancestry, and still sync, but they never become heads. Otherwise anyone able to sign an op (a Reader, or a member being removed) could append a fan-out of more than `MAX_PARENTS` (64) invalid ops; every admin op would then need more parents than an op may carry, and nobody could revoke the attacker. Because ancestry still runs through every stored op, a valid op written after an invalid one keeps it in its past. A genuinely concurrent *valid* frontier wider than 64 ops is never truncated; authoring fails instead (a known protocol limit).

**Pending caps.** Pending ops are held in memory before anyone can tell whether they are authorized, so the pool is bounded: at most `MAX_PENDING` (4,096) in total and `MAX_PENDING_PER_AUTHOR` (256) per author. The per-author cap stops one member (or one stolen key) from filling the shared pool and starving everyone else's out-of-order ops; ops whose parents are all known bypass the pool entirely, so a full pool never blocks a ready admin op such as a revocation. An op refused by a full pool is not lost: it is offered again by the next sync. To keep honest syncs inside these caps, peers send ops in resolution order (`op_ids()`/`all_ops()`: topological, then pending ops by id), so a receiver normally admits every op directly; a new member receives a single admin's 10,000-op history in one exchange.

**Named keys (admission rule A2).** Only *named* keys may author ops or envelopes; anything else is dropped before storage. A key is named if it is the founder, or a stored op whose parents are all known (not pending) adds it, and that op's author was **ever granted Admin**: by genesis, an `Add` with the Admin role or a `SetRole` to Admin, made by the founder or by another ever-admin key. Validity and revocations are deliberately ignored, so the rule depends only on which ops are held, never on arrival order, the pending pool or resolution: honest peers holding the same ops name the same keys, and Sync v2 can summarise one canonical set. What it buys: a Writer, Reader, keeper or removed member can't mint author keys (each minted key could store envelopes and grow every sync frontier); only keys some admin once added can. The trade-off: an admin whose rights were later revoked can still mint authors (their later `Add`s are invalid, so the minted keys are never members and their envelopes are never valid, but they are stored and synced), so a revoked admin's key can cost storage until the space is re-founded. Grants by a key not yet known to be an admin are held and applied if it becomes one, in any order.

An op whose author isn't named yet (its `Add` hasn't arrived, or is pending) is not lost: within one batch (`insert_many`, which restore and sync use) it is admitted as soon as a later op of the batch names its author, so a batch in any order, such as a restore that reads ops in key order, admits exactly what a causally ordered one does. Between batches such ops wait in a bounded pool (`MAX_UNNAMED`, 1,024 in total, 64 per author), outside the graph so peers keep offering them, and are admitted and persisted when their author is named.

**Cost.** Admission (rule A2 above) happens before resolution: the resolver and its oracle (below) see the same admitted op set. Peers resolve incrementally (`crates/mycel-trust/src/resolve.rs`) and get exactly the result of the steps above. The from-scratch implementation of those steps is kept as `oracle::resolve_full`, and differential tests require identical results (order, validity, heads, winners, state, `state_at`, ancestry) after every insert of random concurrent histories (§9).

- **Ancestry** comes from a chain cover index (`reach.rs`), the approach Synapse uses for Matrix auth chains, instead of an n × n ancestor bitset. A linear op costs O(1); a merge stores one sparse vector of the other chains it reaches. Side branches that get merged stop costing anything once merged, and ops nobody builds on (the losers of a revocation storm) never take a chain position. Memory is O(n · k) in the worst case for `k` chains that stay open and partly reached, not O(n²).
- **Fast path.** An op that descends from the current valid heads and conflicts with nothing is checked against the running state of each round and applied in place: O(op), plus, for a reader `Add`, one recipient insert per epoch the member lacks (§6).
- **Concurrency** re-resolves only a **region**: the ops that arrived after the newest cut the new op can be resolved against. A cut is the valid heads after an earlier update; it qualifies when the new op descends from it and nothing before it can change (no older op outside it that is valid or could win is concurrent with the new op, and seniority does not move for anyone with older revocations). This is the conflicted-subgraph idea of Matrix state resolution v2.1. Cuts thin out geometrically (O(log n) kept), so an op whose parents arrived `lag` ops ago re-resolves fewer than about `2 · lag`. Everything is re-resolved (a full recompute) when a new op moves the seniority of a member with older revocations, when one update ranks a member and also carries their revocation of someone whose older conflicting op is still in play, and when a new op's parents are older than every cut kept. The last costs O(n) and any key ever named can trigger it with one cheap invalid op (§10).
- **Rounds** of the winners loop (step 6) are all kept, because the loop is path dependent, but they share storage: each op's flags are stored as runs over the rounds and rounds whose valid ops agree share one state. A removed member's k concurrent `Leave`s make k + 1 rounds (each wins one round, then fails); later inserts still cost what they did before.
- **Measured** (one insert at a time, Apple M5 Pro, `cargo bench -p mycel-trust --features oracle --bench resolve --profile replay`): insert cost stays flat from 1,000 to 100,000 ops, 27–28 µs for one admin's linear history and 38–45 µs in a revocation storm, of which 24–33 µs is the signature check; memory is linear, about 1.1–1.5 KiB per op. Before, every insert ran the from-scratch resolution: 80 ms at 10,000 linear ops and 9.1 s at 100,000 (with a 1.2 GB bitset), and 588 s in a 10,000-op storm. Details, and the adversarial cases of §10, in [BENCHMARKS.md §7](BENCHMARKS.md#7-membership-resolution-mycel-trust).

## 6. Epochs and encryption keys

- **Each peer keeps a keyring:** `EpochId → key`. It fills it by unsealing lockboxes addressed to itself from valid ops only, and verifies each key against its commitment.
- **Recipients of an epoch:** the lockbox recipients, plus members later added with a `keyring` containing that epoch.
- **Writing:** a writer encrypts with the latest epoch in `T` order whose recipients equal *exactly* the current readers. If none qualifies (after a concurrent add or remove), the writer first issues a `Rotate`. This *self-heals*: no epoch shared with a removed member is used once the removal is known.

## 7. Content envelopes

Content (Automerge changes) travels in signed, encrypted envelopes:

```
Header {
  space, doc: DocId, author: SignPk,
  author_seq: u64, author_prev: Option<EnvelopeId>,   // per-author hash chain within the space
  auth_heads: [OpId],                                  // membership heads the author saw
  epoch: EpochId, nonce: [u8; 24],
}
Envelope   { header, ciphertext, sig: Ed25519(author, "mycel/v0/envelope" ‖ postcard(header) ‖ ciphertext) }
EnvelopeId = BLAKE3(postcard(Envelope))
ciphertext = XChaCha20-Poly1305(key = epoch key, nonce, aad = "mycel/v0/content" ‖ postcard(header), plaintext = automerge change bytes)
```

**Validity is decidable without decrypting**, which lets keepers enforce it too. An envelope is valid iff:
1. the signature verifies against `header.author`;
2. every `auth_heads` op is known (otherwise the envelope is pending);
3. the author has the **Writer** role in `state(valid ∩ past(auth_heads))`;
4. the author is a recipient of `header.epoch` in that state;
5. **cutoff rule:** for every winning revocation `w` of the author that is *not* in `past(auth_heads)`, the envelope must lie in the author's hash chain at or before `w.cutoff`. `cutoff` = the latest envelope from that member the revoker had seen. This blocks a removed member from backdating `auth_heads` to keep writing;
6. the per-author chain is consistent: `author_prev` must be the author's envelope with `author_seq − 1`. Forks (equivocation) after a cutoff are excluded by rule 5. Before a cutoff, a fork is accepted but flagged.

**Storage window** (before validity, so keepers apply it too): an envelope
is stored only if its `author_seq` is below the author's *reach* plus 4,096,
where reach is one past the highest seq held on a chain from seq 0. The rule
depends only on what is held, never on arrival order, so peers that end up
with the same items store the same set; it bounds a writer's dangling
envelopes (no predecessor held) to 4,096 seqs per chain. Senders send each
author's chain in ascending seq, so honest data never waits on it; a
refused envelope is offered again once its prefix has arrived.

**After decrypting** (members only):
7. the Automerge change's actor ID must equal `header.author`. Authors cannot write under someone else's actor.

8. the change must be consistent with its **declared history** (its `deps` and their ancestors), never with whatever else a peer happens to hold: its actor sequence number is exactly one more than that actor's latest change in that history; its operation counters start above every counter in that history and fit in 32 bits; every actor in its actor table wrote something in that history; and every object, list/text element and predecessor its operations name exists in that history (or earlier in the same change) with the right shape (objects are maps, lists or text; elements are insertions into that same object). Its operations have the shapes Automerge writes: deletes and increments never insert, marks always insert, and an element key naming an actor never has counter 0 (counter 0 is the head of a sequence). A change that fails is rejected for good. Checking this uses a per-document causal index (author, sequence, counter range and run-length operation summary per change, plus a sparse vector clock), so it costs the size of the change plus a logarithmic lookup per reference — no replay.
9. **resource limits** (before Automerge parses anything): every operation id (object, key and predecessor counters, and actor numbers) fits in 32 bits, as Automerge stores them; at most 16 MiB after decompression, 1,048,576 operations, and a logical expansion of run-length/group-encoded columns of at most 64 values (or string bytes) per byte of change body, never below 4M (deleting a long run encodes in a few bytes) and never above 16M values / 16 MiB of strings. Writers stay far inside this: a local edit is written as changes of at most 65,536 operations and 512 KiB each, so a multi-megabyte paste becomes several consecutive changes that every released version accepts.

**Materialization:** a document = the valid, decryptable changes, applied in causal order. A change waits, still encrypted, until its dependencies are applied; validated changes reach Automerge in batches. Equivocation (two changes for one actor sequence number) is resolved by the lowest envelope ID, on every peer; if a lower-ID fork displaces a change that was already applied, the document is re-derived once per received batch, however many forks the batch carries. If a newly arrived revocation invalidates envelopes that were already applied, the peer **rebuilds** the document from its envelope store; other membership changes only touch envelopes whose validity or decryptability changed. Every peer holding the same graph and envelopes arrives at the same document.

## 7b. Attachments (blobs)

An attachment is a **blob**: immutable bytes, content-addressed by `BlobId = BLAKE3-derive_key("mycel/v0/blob", sealed bytes)`. The chat message (an encrypted feed entry, §7) carries an `AttachmentRef { blob, key, nonce, name, mime, size }`. So the per-attachment key travels end-to-end encrypted, and the signed message pins the exact ciphertext by hash.

**Encryption (streaming, any size).** Each attachment gets a fresh random 256-bit `key` and 192-bit `nonce`. The plaintext is sealed with the STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár) over XChaCha20-Poly1305:

```
blob     = "MYCELBLOB1\0" ‖ chunk_size: u32 LE ‖ C_0 ‖ … ‖ C_n            (n ≥ 0, chunk_size = 1 MiB)
C_i      = XChaCha20-Poly1305(key, nonce_i, aad_i, P_i)                   (|P_i| = chunk_size for i < n, 0..=chunk_size for i = n)
nonce_i  = nonce with its last 8 bytes XORed with i (u64 LE)
aad_i    = "mycel/v0/stream-chunk" ‖ len(A): u32 LE ‖ A ‖ chunk_size: u32 LE ‖ i: u64 LE ‖ final: u8     (A = "mycel/v0/attachment")
```

- The final flag and the index are authenticated, so chunks can't be dropped, reordered, duplicated, truncated at a chunk boundary or extended. An empty file is one empty final chunk. The header's chunk size is bound into every chunk's AAD.
- Memory is one chunk (plus I/O buffers) whatever the file size. Encryption reads the source once, writing the sealed blob (hashed as it's written) and the sender's plaintext copy in the same pass.
- **Legacy format:** attachments from earlier versions used one-shot `XChaCha20-Poly1305(key, nonce, A, plaintext)`. A blob without the magic prefix is opened that way. Only blobs up to 64 MiB are opened like that, so a hostile reference can't make a peer read a huge blob into memory.
- Code: `crates/mycel-crypto/src/stream.rs`. Tests cover roundtrip at chunk boundaries (0, 1, chunk − 1, chunk, chunk + 1, many chunks), tampering, wrong key/nonce/AAD, truncation, extension, reordering, duplication and chunk-size changes.

**Transfer.** Blobs are stored per space (`blobs/<space>/<blob>`) and served only to the space's members (stream kind `Blob` on the node protocol). They are streamed between QUIC and disk into `<blob>.part`, in disjoint ranges from every member that has the blob. The receiver checks the BLAKE3 hash of the whole blob before renaming it into place, so a peer can't substitute data. An interrupted transfer resumes from the `.part`, possibly from a different member. The final hash check covers the prefix too, and a bad prefix is discarded and fetched again.

**Availability and disk use.** There is no size limit and no per-space quota.
- Blobs up to 16 MiB are pushed to every member as soon as they're posted. Bigger ones are pushed only to keepers, and members fetch them when their user clicks download, from anyone in the space who has them.
- Receivers enforce this: a personal device refuses an unsolicited push above 16 MiB, so a member can't fill your disk with large files you never opened. Keepers accept any size.
- Every transfer is refused if it would leave less than 1 GiB of free disk space.

## 8. Transport rules

- **ALPN** `mycel/node/2` (`mycel/2` with a pre-release build, [PROTOCOL.md](PROTOCOL.md)): one connection per pair of devices; sync, cards, ephemeral messages and blobs are QUIC streams on it, labelled by a stream-kind byte. Iroh authenticates the remote node ID, which equals the remote `sign_pk`.
- **Responders serve a space only to its current members**, including Relays. Requests from non-members are refused.
- **Sync order:** membership ops first (resolution order, ancestry-closed), then envelopes, each author's chain in ascending seq. Sync v2 (stream kind `SyncV2`) finds the difference from a 32-byte digest and per-author chain heads (full ids); v1 (`Sync`, for builds without v2) by set difference over full ID inventories. Neither summary admits or hides anything: every item still goes through the receiver's checks, and a lying peer can only waste bounded bytes or withhold.
- **Dissemination** (stream kind `Gossip`, capability `GOSSIP`): new items are pushed over a Plumtree eager/lazy tree on a symmetric overlay of members (every member up to 6; otherwise 2 locality and 2 rendezvous-random edges per device, at most 12 accepted, keepers 64). A gossip message is taken only from a current member of its space; its items still go through the receiver's checks, its frontier entries only decide whom to ask (a session) and who holds what (delivery state, below). Limits: a 64 KiB frame; pushes of at most 16 KiB of items and 16 ops; at most 256 frontier entries and 24 KiB of them per message; `Have` of at most 64 ids; forwarding queued per outgoing link and per author, sent by deficit round-robin within the link's byte rate (20 KiB/s on slow links, 1 MiB/s otherwise), each author's queue capped at 256 items or 256 KiB (oldest dropped, repaired by announcements and anti-entropy), so one author can't take more than its share of a Bluetooth link. A push of items the receiver can't admit (an author whose `Add` it lacks) makes it pull with a session.
- **Delivery state** ("delivered to"): computed from the chain runs each member was seen to hold, per author (a verified Sync v2 frontier, gossip entries, items it sent, a v1 inventory), at most 4 runs per (member, author) and 256 members per space, not a per-envelope holder map. With read receipts on (`NodeOptions::read_receipts`, off by default), a device also shares **seen notes**: its entries for up to 5 changed authors, signed (`mycel/v2/seen`) and sealed under the space's current epoch key, so keepers and carriers can't read them; at most one per member per 30 s (a replayed or early note is dropped), carried on gossip messages already being sent (512 B per message), never starting a session.
- **Mixed groups:** a device with Sync v2 serves a peer at most one v1 session per space every 5 s (`SYNC_V1_LIMITED` beyond), since v1 members still re-sync with every member after each change.
- **Sync v2 limits** (none depends on the peer acknowledging anything): one session at a time per (peer, space) in either role (when two devices open to each other at once the lower key's session runs and the other side gets `Busy`, which is never a failure: it waits and runs its own session afterwards), at most 4 served per peer across spaces; sessions that find a difference, per (peer, space): a burst of 32, then 4 per second (`Busy` beyond); bytes sent per (peer, space): one full catch-up of our current set (it grows with the set, during a session too), then 1 MiB/min (the session stops and resumes later, keeping what arrived); phase-2 (fork placement) sessions: 6 per peer per hour; a peer's frontier: at least 65,536 authors whatever we know ourselves (2 × the authors we know + 1,024 if that is more), 4 chain heads per author on average and at most 64 listed per author (more are covered by a commitment); probes: 16 ids each, 64 runs and 8 rounds per session; session frames at most 1.1 MiB plus one envelope. The opening `Open` (it may carry an invite) and the answer to it (it may carry a `Removed` proof) both carry the whole membership history, so they get v1's 64 MiB frame limit, and an `Open` from a device we share no space with is charged to the stranger frame budget, as v1's `Hello` is. Received bytes are bounded per session (4 GiB) but not yet per peer over time (see §10).
- **Everything received is validated by the receiver.** Nothing is trusted because of who sent it.
- **ALPN** `mycel/mesh/2` (`mycel/mesh/1` with a pre-release build): hop connections between nearby devices for multi-hop relaying ([ARCHITECTURE.md](ARCHITECTURE.md) §8). Accepted from anyone nearby: relaying needs no membership. What crosses a relay is the QUIC traffic of a connection between two *other* devices, so the rules above still apply end to end. See §8b.

## 8b. Mesh relays: what they can and can't do

A relay forwards QUIC packets of a connection between two other devices.

**A relay cannot:**
- read them: they're encrypted end to end (QUIC/TLS 1.3, keyed to the two devices);
- change or inject packets: AEAD, so altered packets are dropped by the receiver's QUIC;
- impersonate either end: the connection authenticates the remote device key;
- forge routes *to someone else*: each announcement is signed by its origin's device key. One with a bad signature, or one more than 10 minutes from the receiver's clock, is rejected;
- make a device join anything: relaying needs no membership, and a relay is given none.

**A relay learns (metadata):**
- *Who talks to whom.* Each mesh frame's header carries the source and destination device keys and the waypoint, in clear to each relay. Hops are themselves QUIC connections, so headers are hidden from radio eavesdroppers who aren't Mycel devices on the path.
- *When, how often and how much.* Packet sizes and timing, which reveal activity patterns (a call is a steady 50 packets/s, a file is a burst).
- *Who is around.* Every device within 8 hops receives every announcement: the device key and the display name (the same name already shown over Bluetooth, peer-to-peer Wi-Fi and the LAN).

**A malicious relay can:**
- *Drop or delay traffic* (denial of service). Mitigations:
  - up to 3 routes per destination, through distinct neighbours, as separate QUIC paths, so traffic moves to the others when one goes dark (dead paths are noticed in about 3 s);
  - direct paths are always preferred.
- *Claim a low cost to attract traffic* (black hole): costs aren't signed (each hop adds its own). A claim no honest relay can make (a relayed route with no hops, or under the least each hop adds) gets the neighbour distrusted for 10 minutes: the routes it gave go, the routes it relays are ignored, and it stays reachable itself (`docs/ROUTING.md` §6, item 12). A plausible lie (one hop from everyone, at the least cost) can't be refuted from announcements, but the destination's acknowledgements don't come back through it: after two timeouts in a row with nothing acknowledged, a source prefers another route to that destination for 2 minutes, and its bundles send only one share of their copies down the route that failed (`docs/ROUTING.md` §6, item 13, and §7.3). In the node the evidence is what QUIC authenticated on each mesh path (frames from packets it decrypted), so a relay can drop it but not fake it; a suspected hop's route stops being offered as a path for that destination. That costs the traffic lost to two silences (about 6 s with real nodes), and only the ends of a connection learn it. Signed per-hop route attestations, planned for the next protocol version, would stop the lie itself.
- *Replay old announcements of a device that left*, within the 10-minute window, keeping a dead route alive. That costs only failed attempts.

**Load and abuse:**
- relaying for others is capped per neighbour (1 MiB/s) and in total (4 MiB/s);
- announcements are capped at 100/s per neighbour;
- frames have a TTL and are never sent back where they came from;
- reassembly buffers are bounded;
- `MYCEL_MESH_RELAY=0` relays nothing; `MYCEL_MESH=0` turns the mesh off.

**Limits (known):**
- No onion routing or padding: relays see endpoints, sizes and timing. Hiding who-talks-to-whom would need onion-style layered encryption and cover traffic, at a large bandwidth cost on Bluetooth.
- Sybil devices nearby can each be a neighbour (each is rate-limited separately); the radio's range is the practical bound.
- **Bluetooth shows the device key to anyone in range.** The link has no pairing and the L2CAP channel isn't encrypted. The readable GATT characteristic carries the L2CAP PSM and the device's long-term key, and the first frame on a channel (the hello) carries the key again, to whichever device opened or accepted it. Neither carries the display name any more (the hello's name field is always empty; older builds still send one): a nearby device learns the name from the signed contact card, fetched inside the encrypted QUIC session, which a stranger can still do once it has a channel. So a nearby attacker scanning for Mycel's service can recognise a device by its key (passive), and one advertising the service can get the key from a channel and the name from the card (active). How long a device is exposed: computers whenever Mycel runs; iPhones and iPads while Mycel is open. In the background an iPhone keeps scanning and dialing (the `bluetooth-central` background mode) but **links only with known devices**: contacts and members of its conversations (`Runtime::set_background`, `mycel-link-ble`'s restricted mode). It still connects to an unknown advertiser long enough to read its GATT key (that read reveals nothing about the iPhone but its rotating Bluetooth address), then hangs up and doesn't dial it again; a channel a stranger opens to it is closed at the stranger's hello. `bluetooth-peripheral` is deliberately not declared, so a locked iPhone neither advertises nor serves the characteristic. Residual: an attacker who knows the key of one of the victim's contacts (read passively from that contact's Mac, say) can advertise that key and receive the iPhone's key in its hello before QUIC's handshake fails; that tracks a targeted victim, not every passer-by. Android has no Bluetooth link yet. The fix for all of it, rotating tokens in place of the key and identity only inside an encrypted handshake, is not built.

## 8c. Gateways, records and carriers (global routing, store-and-forward)

**Records.** A gateway record ("D is reached via G1, G2") is a pkarr packet signed by D's own key.
- **Forging:** nobody else can publish one for D. A gateway publishes only records that name it, that it can verify, at most one per origin per 10 s, at most 1024 origins.
- **Expiry:** records expire after 30 minutes, and the newest by timestamp wins.

**Attacks and mitigations:**
- **Black-hole gateway.** A gateway, or a relay on the way to it, accepts traffic and drops it.
  - *Mitigations:*
    - a device publishes 2 gateways through distinct first hops where it can, each a separate QUIC path, so traffic continues on the other;
    - a sender keeps every gateway the record names as its own path;
    - store-and-forward bundles wait for a receipt and are carried by several copies.
  - *Remaining:* a device with a single gateway in range depends on it.
- **Sybil gateways.** Many fake devices near D announce themselves as gateways with a low uplink cost to be chosen.
  - *Mitigations:* each must be a real radio neighbour, rate-limited separately. The uplink cost is signed by the gateway (it can lie, but only about itself). The traffic stays end-to-end encrypted.
  - *Remaining:* gateways are chosen by their announced cost, which a gateway can misstate about itself. Once a connection runs, the multipath selector ranks its paths by measured RTT, throughput and loss.
- **Eclipse.** All of D's neighbours are hostile: they can drop everything and publish nothing for D.
  - *Mitigations:* none at the routing layer. It's the radio-range equivalent of being on a hostile Wi-Fi. Detection: D sees no receipts and no live connections. Content is still never readable or forgeable.
- **Directory.** Publishing many records for many keys would require many keys; each record costs a signature, and gateways cap what they publish. The n0 relay and the DHT apply their own limits. Lookups can't be forged (signatures), only withheld; the DHT and the relay are independent.
- **Open proxy.** A gateway never relays internet → internet, so nobody can bounce traffic through it.
- **Budgets.** Traffic crossing between the mesh and the internet has its own cap (2 MiB/s per gateway) on top of the per-neighbour and total relay caps.

**Store-and-forward carriers** hold bundles for a destination key. A space's bundles are sealed to the destination (HPKE base mode to its key-exchange key, the lockbox suite, `info` binding source and destination) and padded to a PADMÉ size class before sealing (`mycel-net/src/bundles.rs`; Sync v2 finding 9: the version 1 payload, still sent to members known to speak only version 1, is signed but not sealed, so any carrier could read the space id, every membership op and every envelope header).
- **They learn:** the destination key, the source key, a size class (O(log log size) bits), and when bundles were created and moved.
- **They can't:** read, alter (the source signs the bundle and the envelopes inside are signed), or fake delivery (receipts are signed by the destination).
- **Abuse limits:** a 64 MiB store, 256 KiB bundles, 4 MiB per source, lifetimes up to 7 days, and per-neighbour rate limits. A bundle is never sent back to the device that gave it. A source keeps at most 3 MiB of its own bundles in flight across all destinations (under carriers' 4 MiB share, so its backlog can't evict itself), skips what is already in flight to a destination, and never seals the same plaintext twice while it is in flight.
- **Forward secrecy:** none. A sealed bundle is opened with the destination's long-term key-exchange key; a carrier that keeps it and later obtains that key reads it. A hybrid post-quantum KEM (X-Wing) waits for the lockbox suite's migration; forward secrecy for an offline recipient would need prekeys.
- **Receipts** are tiny and public: they reveal that D received *something* from S. That is the same metadata the bundle already showed carriers.

## 8d. Resource limits

Everything a peer sends is bounded before it can cost much. Limits give
backpressure, not resets: a peer over a limit waits, so a long sync over
Bluetooth still completes. Code: `crates/mycel-net/src/resources.rs` and
`link.rs`, `crates/mycel-sync`, `crates/mycel-node`.

- **Streams:** QUIC allows each connection 64 bidirectional and 128
  unidirectional streams at once. A peer that opens more waits for one to
  end; nothing is reset.
- **Frame memory** (encoded bytes a peer can make us hold; the largest frame
  is 64 MiB):
  - Devices we share a space with draw on one 128 MiB pool, at most 32 MiB
    each. Devices we share nothing with get their own 32 MiB pool, 8 MiB
    each, so a crowd of new keys can't push out the people we talk to. Mesh
    neighbours have a third pool (32 MiB, 4 MiB each).
  - The pool is charged only as bytes arrive, so a slow peer delays only its
    own frames. After a 60-second grace a frame must average 512 B/s to keep
    its memory. Frames we send are charged to nobody.
- **Deadlines:** a stream a peer opens must start its first frame within
  10 s; a reply may take 60 s to start, plus the time our own queued bytes
  need to drain; bytes under way may stall for at most 30 s. No exchange has
  a fixed total deadline.
- **Sync responses** are deduplicated and their encoded size measured
  before any ciphertext is copied.
- **Ephemeral messages** (typing, presence): at most 64 KiB of plaintext,
  checked before decryption.
- **Document changes:** the limits of §7 rule 9, checked before Automerge
  parses anything; writers split large edits so every reader accepts them.
- **Membership:** the pending-op caps of §5 (4,096 in total, 256 per author).
- **Message requests:** contacts are always admitted and don't count. A
  stranger can have at most 32 pending requests; when strangers fill all
  256 slots, the oldest request from the inviter with the most pending is
  declined, so a flood displaces its own requests first.
- **Attachments:** see §7b. Concurrent transfers reserve disk space from one
  shared account, so they can't each count the same free space.

## 8e. Optional wake relay (designed, not built)

**Not built, and off by default if it ever is.** Design:
[WAKE_RELAY.md](WAKE_RELAY.md). It would let a contact wake a suspended
iPhone through Apple's push service, which needs a server holding the app
developer's APNs key. It is the only place Mycel's design would admit an
operator, so its trust is fixed here before any code:

- **Trusted for availability only.** It can drop, delay, replay or reorder
  wakes, or stop running; the device then stays in slow mode. It is never
  trusted for confidentiality or integrity: it relays no content and holds
  no key that decrypts any, and envelopes are checked by the trust layer as
  always.
- **Content-blind.** A wake is a capability ID plus a fixed-size HPKE blob
  (RFC 9180 PSK mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305) sealed to
  that capability's own wake key with that capability's own 32-byte random
  PSK, both separate from the device's Mycel keys and from every other
  capability's. The blob holds only a timestamp and a
  fetch hint the extension doesn't trust; the content comes over Mycel's
  own paths.
- **Identity-blind.** The relay sees a push token and random registration
  and capability IDs, never Mycel identity keys. Wakes reach it through a
  one-hop proxy or Oblivious HTTP (RFC 9458), so it doesn't see senders'
  addresses.
- **Unlinkable, revocable capabilities.** Each contact gets its own
  capability (a random ID and its own wake key) over the end-to-end
  channel; two capabilities share nothing but the relay's URL, so contacts
  can't link theirs to others'; the device can revoke any; the relay
  rate-limits each.
- **Wakes are attributed by capability, never by their contents.** HPKE's
  PSK mode lets the device check that the sender held the capability's
  PSK, so a wake proves only "from whoever holds this capability", which
  the device gave to exactly one contact. The assumption, stated: the PSK
  stays secret between the device and that contact (it travels only end to
  end and lives only in their keychains); the wake public key needs no
  secrecy. Abuse is counted and revoked per capability ID: a malicious
  contact can burn only its own, never forge one that passes for another
  contact's. The relay can't forge wakes (it never sees a PSK), only drop
  or replay them.
- **What it learns:** a push token (which Apple can tie to an Apple ID),
  how many capabilities a registration has, and when each fires. Timing is
  the residual leak, shared with Apple; random delay, coalescing and cover
  wakes reduce it but can't hide it from Apple.
- **Who can run one:** only the holder of a build's APNs key can send pushes
  for it, so "self-hosted" means per build. Android needs no relay: the
  same capability can be a UnifiedPush endpoint at a distributor the user
  chose (also only designed).

## 9. Code and tests

| Spec section | Code | What the tests cover |
|---|---|---|
| §2 primitives | `crates/mycel-crypto` | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper; the streaming attachment AEAD (§7b): chunk boundaries, tamper, truncation, extension, reorder, duplication, chunk-size change, legacy detection, incremental digest |
| §3–§6 graph, resolution, epochs | `crates/mycel-trust` (`resolve.rs` = §5, incremental; `oracle.rs` = §5 from scratch; `reach.rs` = ancestry) | Forged admin ops, pending ops, removal and rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, leave, epoch-ID reuse, ops from never-added keys; fan-outs of invalid ops, wide valid frontiers, pending-pool limits and ready admin ops; rule A2: only keys added by an ever-admin are named, named keys don't depend on arrival order, a batch in any order (a restore in key order, an admin chain, seeded shuffles) admits what a causal one does, an op before its author's `Add` is admitted once the `Add` arrives, the unnamed pool is bounded. **Differential tests** (`diff_tests.rs`, proptest): random concurrent histories from four replicas (concurrent adds, removals and role changes, revocation storms, mutual revocation cycles, equivocation, reused epochs, stale recipients, out-of-order and duplicate delivery, batches, a member's `Add` and their revocation delivered in one update, revocation spam by removed members) must resolve exactly as `resolve_full` after every insert, with and without the fast path; hand-built regressions for histories the generator rarely reaches (a seniority move inside one update, seniority moves before a cut, round-0 states, re-added readers, lagging ops, dead chains, concurrent `Leave`s); the ancestry index is checked against brute force |
| §7 envelopes | `crates/mycel-sync` | Replication, reader writes rejected, keeper can't read, outsider and tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, equivocation; decompression and expansion bombs, malformed and deferred changes, declared-history checks (actor, counters, object references), delivery-order and restore consistency |
| §8–§8d transport, mesh, limits | `crates/mycel-net`, `crates/mycel-node` | End to end over real Iroh QUIC with five nodes (admin, writer, reader, keeper, outsider); forged, renamed and replayed mesh announcements; signed-field cache mutation; stream and frame budgets, stalled and progressing I/O, duplicate requests, invitation validation order, ephemeral limits; attachment consent and disk reservations across restarts |

`scripts/security-check.sh` runs these security tests without retries, then
the web checks, `npm audit` and the RustSec advisories through cargo-deny
(`cargo deny check advisories`, the policy in `deny.toml`). CI runs the same
checks on every pull request and the Audit workflow runs them daily against
new advisories. Vulnerabilities always fail; so do unmaintained and unsound
crates, unless `deny.toml` accepts one by ID with the reason Mycel isn't
exposed and a review date (`.cargo/audit.toml` mirrors the list for
`cargo audit --deny unsound --deny unmaintained`). As of 2026-10-21 it
accepts, all on Linux or at build time only:

- RUSTSEC-2024-0429, unsound `glib::VariantStrIter` in glib 0.18, which
  comes with Tauri's GTK 3 webview: no Tauri release is on gtk-rs 0.19 yet,
  and nothing in this repository or between it and glib calls that API;
- RUSTSEC-2026-0370/0371/0372, `zvariant`, `zbus_names` and
  `zvariant_derive` "unmaintained" since zbus 6 absorbed them; zbus 5 still
  comes with Tauri's notification and opener plugins;
- RUSTSEC-2024-0370 and RUSTSEC-2024-0436, the `proc-macro-error` and
  `paste` proc macros, which never run in a shipped binary.

`zip` was moved to 9.0.5 for RUSTSEC-2026-0367/0368/0369 (extraction
flaws; Mycel only writes archives, when it zips a shared folder).
`rustls-webpki` was moved to 0.103.16 and `webpki-roots` and
`webpki-root-certs` to 1.0.10 for RUSTSEC-2026-0382/0381/0383 (emSign
intermediates whose private keys are public could anchor a TLS chain; these
crates sit on the relay and HTTPS client paths through Iroh, reqwest and
Tauri). Lockfile only, no vendored code changed.

## 9b. Hardening

Adversarial reviews of this code found the issues below. Each is fixed and
has a regression test that failed against the old code. Described as what
the code does now:

| Area | Attack or failure | What the code does |
|---|---|---|
| Attachment names | A peer-chosen file name could escape the download folder | Names are reduced to a safe basename and confined to `files/`; macOS downloads carry the quarantine flag; the app can only open files there |
| Strangers | Anyone on the LAN could push a conversation and impersonate a name | Invites from non-contacts are **message requests**: nothing is trusted, posted or stored until Accept. Decline and Block exist; blocked keys are refused at the network layer; personal devices refuse Relay-role invites |
| Attachment consent | Membership granted by a pending request let a stranger push files before the user accepted | Consent is stored before the invite is admitted and survives restarts; pending and hidden requests can't push files or be downloaded from |
| Pre-authentication work | Junk ops and envelopes from unknown keys cost CPU and memory | Ops and envelopes from never-added keys are dropped before storage; parents, `auth_heads`, invites and lockboxes are capped; state caches are bounded |
| Revocation | A fan-out of invalid ops, or a flood of ops with missing parents, could stop an admin from removing a member | Authoring uses the frontier of *valid* ops; the pending pool is capped per author and ready ops bypass it (§5) |
| Author minting | Any member (a Reader, a keeper, a removed member) could add unlimited author keys whose envelopes every peer stored and listed in every sync frontier | Only keys added by an ever-admin are named (rule A2, §5) |
| Restore order | With rule A2, a restore (ops read in key order) dropped ops whose author's `Add` was still pending at that point, a member's `Remove` among them, so the device kept treating a removed member as a member | A batch admits ops of authors named later in the same batch; between batches they wait in a bounded pool (§5) |
| Epoch IDs | Reusing an epoch ID with a different key could break convergence | `EpochId = H(commitment)`, checked structurally; each key is checked against its own op's commitment |
| Equivocation | Two changes for one Automerge (actor, seq) could make documents diverge; a revocation could leave stale exclusions | The lowest envelope ID wins everywhere; exclusions are recomputed from the currently valid changes, so live and restored replicas agree |
| Change parsing | A malformed change from any writer crashed every member, and kept crashing them after restart; small compressed changes expanded without limit | Decompression and logical expansion are bounded before parsing (§7 rule 9); parser and apply panics are contained; changes apply to a candidate document first; changes waiting for dependencies stay outside Automerge |
| Change acceptance | Whether a change was accepted could depend on unrelated local history or arrival order | Changes are checked against their declared dependency history only (§7 rule 8) |
| Mesh announcements | The signature cache was keyed by origin and sequence, so altered signed fields could reuse an earlier check | The cache keys on a digest of every signed field and the signature; only the hop count and cost added on the way may change |
| Network resources | Unbounded stream tasks; memory allocated up front for a declared 64 MiB frame; no inbound deadlines; repeated IDs in a sync request multiplied copies | The limits of §8d |
| Crashes | An overflow panic poisoned a global lock (crash loop) | Checked arithmetic; locks that can't be poisoned |
| Leaving | A member who had left could keep posting with backdated heads | `Leave` carries a cutoff and counts as a revocation |
| Disk use | Blobs weren't scoped to a space; failed pushes left partial files; concurrent transfers counted the same free space | Blobs are stored per space; pushes stage to disposable files cleaned up on failure; transfers reserve space from one account (§7b, §8d) |
| Identity | A failed read could silently create a new identity; on iOS the key was a plain file | Reads fail closed and the profile is locked; iOS keeps the key in a device-only Keychain item, moved there only after it is safely stored, with no plaintext fallback |
| Storage | A save could report success before an earlier batch was written; failed batches were dropped; a damaged setting silently reset | Commits are ordered and failures retried; damaged records are set aside, not deleted; an unreadable network setting becomes Local only, never wider; the user is told (`Notice`) |
| Notifications and logs | OS notifications showed names, text and file names; logs showed file paths | Notifications say only what happened; Bluetooth diagnostics are opt-in; logs are private to the user on Unix; attachment errors are redacted |
| Local HTTP API (`mycel serve`) | Any local page could call it | A per-run secret token on every route (embedded in the page; a `0600` file for the CLI); loopback `Host` only; file serving limited to attachment folders; attachments from the browser only as uploads |

## 10. Limitations

What this layer does **not** do:

- **No external review.** The design and code have had internal
  adversarial reviews with regression tests, not an independent
  cryptographic audit.
- **No per-message forward secrecy.** Content keys are per epoch, and the
  history of a document stays readable to its members. A stolen device key
  plus the stored lockboxes and history exposes the epochs that device
  could read. Removing a member doesn't erase what they already received.
- **Not post-quantum.** Lockboxes use X25519 and are stored long-term on
  keepers, so they are exposed to harvest-now-decrypt-later attacks.
- **Metadata.** Keepers see membership keys, authors, sizes and timing;
  mesh relays and gateways see who talks to whom, sizes and timing (§8b–8c).
  Transport encryption doesn't hide IP addresses or local discovery names,
  and there is no anonymity.
- `NeedInvite` vs `Denied` reveals whether a node holds a space whose 256-bit
  ID you already know. mDNS and the card protocol reveal device names and
  public keys on the LAN, by design.
- **One device per member.** There are no multi-device identities and no
  device revocation for a person: each device is its own member, and the
  identity key is the account, with no recovery if it is lost.
- **Keys at rest.** iOS keeps the device key in the Keychain; the other
  platforms keep `identity.key` as a file (owner-only on Unix; on Windows,
  the user profile's permissions). Downloaded attachments are plaintext in
  the app's files folder. There is no database encryption, app lock or
  app-switcher redaction.
- **Scale.** Membership resolution is incremental (§5): flat per-insert
  cost to 100,000 ops, linear or in revocation storms. What remains
  superlinear, partly under an attacker's control (any key ever named in
  the space can author ops, valid or not):
  - A new op whose parents lie far back re-resolves everything that
    arrived after the newest cut it can use: up to about twice its lag, or
    the whole history when its parents are older than every cut kept
    (roughly, older than half the history). An honest device back from a
    long time offline pays this once; a removed member can send such ops
    at will, e.g. ops on their own `Add` from before their removal:
    measured 5 ms per op at 10,000 ops and 99 ms at 100,000, against
    25 µs for an op on the heads, so a few such ops per second keep one
    core busy in a 100,000-op space. Re-resolving only the ops concurrent
    with the new one, instead of every op since the cut, would remove
    this; it is not done.
  - A removed member's k pairwise-concurrent `Leave`s add k rounds to the
    winners loop (§5 step 6). Later inserts are unaffected (measured
    33 µs after 1,000 such `Leave`s at 10,000 ops), but inserting the
    `Leave`s costs about k³: the i-th re-resolves up to i ops in each of
    i rounds. Measured 0.3 s for 200 and 57 s for 1,000 (worst single
    insert 0.2 s). Dropping revocation candidates whose author is not a
    member in their causal state ignoring concurrency would end this, but
    it changes which ops are valid in rare histories (a member added on a
    branch that only becomes valid in a later round), so it needs a
    protocol decision.
  - The ancestry index grows with chains that stay open and partly
    reached, O(n · k) in the worst case, and whoever appends ops can make
    `k` grow with their op count: merges that each name a non-tip op of
    many side chains keep those chains open. Measured with crafted ops:
    0.3, 1.3 and 5.1 million vector entries (8 bytes each) at 19,000,
    38,000 and 76,000 ops, 4× per doubling (an estimate by that trend:
    about 500 million entries, 4 GB, at 760,000 ops). Bounding the
    vectors is not done.
  - Inserting an op into the topological order shifts the ops after it,
    and a reader `Add` writes the member into every epoch they lack, since
    the state lists each epoch's recipients.

  Envelope validity is recomputed on each membership change. Rotation
  sends one lockbox per reader: fine up to a few hundred members. Sync v2
  costs about what differs (an idle check is one round trip and a few
  hundred bytes), but v1 sessions with devices without it still exchange
  full ID inventories. Invites and `Removed` proofs carry the whole
  membership history in one frame (at most 64 MiB, as in v1: about 1,900
  removals in a 300-reader group); a space whose history outgrows that
  can't invite or tell a removed member. A space with more than 65,536
  authors ever named fails v2 sessions with devices that know fewer than
  half of them (no fallback to v1 for that).
- **Received sync bytes** are bounded per session (4 GiB), not per (peer,
  space) over time: a misbehaving member can stream valid but useless or
  duplicate items, at most 4 sessions at a time, each checked by the
  receiver. The byte budget restrains only honest senders.
- **Rebuild costs.** A batch carrying a lower-ID fork of an already-applied
  change costs one linear rebuild of that document, and the displaced
  change's descendants are dropped, as for revocations. Honest edits built
  on a removed member's concurrent edits are dropped on rebuild (Automerge
  needs their dependencies).
- **Protocol bound.** A genuinely concurrent valid frontier wider than 64
  ops can't be authored on (§5).
- **Resource use** is bounded per peer and per node (§8d), not per process:
  decoding, history, codecs and the OS network stack cost memory on top.
  Accepted members' history and attachments have no cumulative storage
  quota, and a process killed mid-push can leave staging files behind.
- **Forks before a cutoff** are tolerated but not shown in the UI.
- **No timely delivery to a suspended iPhone.** Without a push server, iOS
  wakes Mycel only on its own schedule (background refresh, Bluetooth
  events) or when it's opened; the wake relay that would change that is a
  design only (§8e).
