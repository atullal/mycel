# Mycel trust layer: specification

How Mycel decides who may read and write what, with no server to ask. This
is the layer as implemented in `crates/mycel-crypto`, `crates/mycel-trust`
and `crates/mycel-sync`; the wire format is version 0 (`mycel/v0/…` context
strings).

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
- **Forward secrecy within an epoch:** not provided. Only post-compromise security on rotation.
- **A compromised device** can act as its member until removed.

## 2. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Signatures, device identity, transport identity | Ed25519 | `ed25519-dalek` |
| Key agreement for lockboxes | HPKE (RFC 9180), base mode: the X-Wing hybrid KEM (X25519 + ML-KEM-768, KEM id `0x647a`), HKDF-SHA256, ChaCha20-Poly1305 | `hpke` (`x-wing`, `ml-kem`) |
| Content encryption | XChaCha20-Poly1305 (192-bit random nonce) | `chacha20poly1305` |
| Hashing, IDs, key commitments | BLAKE3 (`derive_key` mode for commitments) | `blake3` |
| Canonical encoding (bytes that get signed) | postcard (deterministic for a fixed schema) | `postcard` |
| Randomness | OS CSPRNG | `rand`/`getrandom` |
| Secret hygiene | zeroize on drop | `zeroize` |

**Domain separation:** every signature, KDF and HPKE `info` input is prefixed with a unique context string, e.g. `mycel/v0/op`, `mycel/v0/envelope`, `mycel/v0/lockbox`. This also separates our signatures from TLS signatures made with the same Ed25519 key by Iroh. TLS 1.3 signs a 64-space-prefixed context, so the two cannot collide.

**Hybrid post-quantum lockboxes.** A lockbox is what keepers store for years, so it is what a recorded-now, decrypted-later attack would go for. Its key agreement is X-Wing: the shared secret comes from both X25519 and ML-KEM-768 (FIPS 203), so a lockbox stays sealed unless *both* are broken (a quantum computer breaks X25519; ML-KEM is the newer, less studied one).
- **What is hybrid:** every lockbox, so every epoch key and every keyring handed to a new member.
- **What is still classical:** signatures (Ed25519) and the transport handshake (TLS 1.3 with X25519, §8). A forged signature needs the quantum computer at the time of the attack, not later; recorded transport traffic could be decrypted later, and what it would reveal is the envelopes and lockboxes inside, which are encrypted again as above, plus the metadata of §10.
- **Sizes:** a lockbox key is 1216 bytes (X25519: 32) and a lockbox's encapsulated key 1120 bytes (32). A lockbox holding an epoch key is 1168 bytes (80), so a rotation costs about 1.2 kB per reader, and adding a member about 2.5 kB (their keys, and their keyring's lockbox). The symmetric parts are unchanged: 256-bit keys, which Grover's algorithm doesn't bring within reach.
- **Suite binding:** every lockbox's HPKE `info` starts with `mycel/v1/lockbox/xwing-hkdfsha256-chacha20poly1305`, then the caller's context, and the KEM id is in HPKE's own key schedule. The X25519 lockboxes of earlier builds are refused by their length, with an error that says so (`UnsupportedLockbox`); their 32-byte keys don't decode as lockbox keys; and `kex_sig` is made under a new context, so an old binding doesn't verify.
- **Keys:** a lockbox key decodes if it has the right length, and is checked to be one X-Wing accepts (ML-KEM's canonical encoding) wherever it is admitted: `verify_binding`, so in every `Genesis` and `Add` op and every contact card. A key that passed can always be sealed to, so a member can't block rotations with a malformed key.

## 3. Identity

- **Device keys:**
  - `sign`: Ed25519. Also the Iroh node ID, so a transport connection authenticates the device.
  - `kex`: X-Wing (X25519 + ML-KEM-768), used for lockboxes. Both are derived from the device's 32-byte seed (the kex key from `BLAKE3-derive_key("mycel/v1/kex-seed/xwing", seed)`), so the seed is still all an identity is.
  - *Reader keys*: random X-Wing keys the device publishes per space, replaces weekly and deletes (§6). In a space where it has published one, its lockboxes are sealed to that instead of `kex`. They are not derived from the seed; the device stores them, sealed under a key that is.
- **MemberKeys:** `{ sign_pk, kex_pk, kex_sig }`, where `kex_sig = Sign(sign_sk, "mycel/v1/kex-binding" ‖ kex_pk)`. This proves the device holds both keys, so an attacker cannot substitute a kex key during the invite exchange. A lockbox is only ever sealed to a `kex_pk` under such a signature.
- **Contact codes** come in two forms (`crates/mycel-node/src/runtime/contacts.rs`). The *short* code, the one shown as text and as a QR code, holds `sign_pk` and the name it signed: the 1216-byte `kex_pk` is too much to paste or scan. The device that adds it fetches the signed card (`MemberKeys`, name) from the device the first time it reaches it, checks it against the `sign_pk` it was given, and only then can put the contact in a space; meanwhile nothing is sealed to it. The *full* code holds the whole signed card and needs no connection.
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
| `Leave { cutoff }` | any member (not the last Admin) | the author leaves: a revocation of itself, with no rotation |
| `ReaderKey { key, lost_previous }` | Reader+ | the author's lockboxes are sealed to `key` from this op on (§6); `lost_previous` says it can't open what was sealed to its earlier reader keys |

**Rotation** = `{ epoch: EpochId(random 16B), commitment, lockboxes: [(recipient SignPk, HPKE ciphertext)] }`
- `commitment = BLAKE3.derive_key("mycel/v0/epoch-commit", key)`. Each recipient checks the key it unseals against the commitment, so a rotator cannot hand some members a different key undetected.
- HPKE `info = "mycel/v0/lockbox" ‖ epoch ‖ recipient_sign_pk`. This binds each lockbox to its epoch (a random 128-bit ID) and its recipient. Genesis can't bind the space ID because the space ID is the hash of genesis itself. Keyring lockboxes in `Add` additionally bind `space ‖ op nonce`.
- **Which key a lockbox is sealed to:** the recipient's *reader key*, the last `ReaderKey` op of that member in `T` order (§5) as the sealer sees the graph; or the `kex_pk` in its `MemberKeys` while it has published none (§6). Both are keys the recipient's device key signed. A member that loses read access drops its reader key: if it reads again later, it starts from its `kex_pk`.
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

**Cost.** Resolution keeps a running state while history is linear (each op's past contains every valid op before it), so a long run of one admin's ops resolves in linear time; only ops concurrent with others replay their own past.

## 6. Epochs and encryption keys

- **Each peer keeps a keyring:** `EpochId → key`. It fills it by unsealing lockboxes addressed to itself from valid ops only, and verifies each key against its commitment.
- **Recipients of an epoch:** the lockbox recipients, plus members later added with a `keyring` containing that epoch.
- **Writing:** a writer encrypts with the latest epoch in `T` order whose recipients equal *exactly* the current readers. If none qualifies (after a concurrent add or remove), the writer first issues a `Rotate`. This *self-heals*: no epoch shared with a removed member is used once the removal is known.

### Forward secrecy: reader keys, a stored keyring, timed rotation

**The problem.** Every lockbox used to be sealed to `kex_pk`, which is derived from the device's seed, and a device rebuilt its keyring at each start by opening those lockboxes again. So the seed alone, with the lockboxes a keeper stores, opened every epoch the device could ever read, for ever.

**What a device does now** in each space it takes part in (`crates/mycel-sync/src/keys.rs`):

1. **Reader keys.** It publishes a random X-Wing key, a *reader key*, in a `ReaderKey` op, and a new one every 7 days. From that op on, others seal its lockboxes to it (§4). The private half is not derived from the seed.
2. **Deletion.** A replaced reader key is kept for 30 days and then deleted. It is kept because someone who hasn't seen the new one still seals to it. The 30 days count only while the device runs: a gap of more than 6 hours in its own clock is time it was off, when nothing could reach it, so a device waking from a long sleep deletes nothing before it has synced.
3. **A stored keyring.** Opened epoch keys are kept, with the reader keys, in one record per space, sealed with XChaCha20-Poly1305 under `BLAKE3-derive_key("mycel/v1/storage-key", seed ‖ purpose)` and bound to the space as associated data. They are no longer re-derived at start: a lockbox whose reader key is gone can't be opened again by anyone, the device included. The record is useless without the seed, and to another space.
4. **Timed rotation.** A writer rotates the epoch on its next write once it has held the current epoch's key for 24 hours, plus a per-device, per-epoch jitter of up to 6 hours so that writers don't all rotate together. Two that do anyway produce two epochs, of which the later in `T` order is written under; both stay readable.
5. **Store first.** A reader key's private half is written to the device's storage, durably, before the `ReaderKey` op is published. If it can't be stored, it isn't published.

All of this runs on the device's own clock and on the graph. No op carries a time, so nothing depends on anyone else's clock, and a clock set back only delays things.

**When a lockbox can't be opened.** A sealer that was out of touch for longer than the retention seals to a reader key its recipient has deleted; so does anyone, after a device lost its storage. The recipient then can't read that epoch. When this is the epoch being written under, it publishes a `ReaderKey` with `lost_previous` (at most one an hour). Every peer can then tell from the graph which epochs were sealed without knowing of that op, and a writer whose write epoch is one of them rotates on its next write. So the conversation moves on to an epoch everyone can read; what was written under the closed epoch stays closed to that device. This is a rule for writers, not a validity rule: envelopes under such an epoch remain valid.

**What this gives, and what it doesn't.**

| Someone who has | can open |
|---|---|
| the seed alone, and every op and envelope ever stored anywhere | only the lockboxes sealed to `kex_pk`: see "the join window" below |
| the seed and a copy of the device's database | everything that device has read: the database holds the history and, in the stored keyring, the key of every epoch it opened (the keyring is not pruned). Beyond that, only what is sealed to the reader keys still in it: about the last 7 + 30 days' worth |
| a copy of the database without the seed | nothing: the record is sealed under the seed |
| the device, unlocked and running | everything it can read. Nothing here is protection against that |

- **The join window.** A member being added has published no reader key in the space, so the `keyring` lockbox in its `Add` (every epoch up to then) is sealed to its `kex_pk`, as is each rotation until a sealer has seen its first `ReaderKey`. The same holds for a space's founder between `Genesis` and its first `ReaderKey`, and after a member regains read access. The seed alone therefore still opens *what a member was given when it joined* and what was written until the first rotation after its first reader key: with timed rotation, at most about a day (30 hours) of an active conversation. Closing this would take signed prekeys in contact cards; it is not done.
- **Requests.** A device publishes reader keys only in spaces its user takes part in: ones it made, a contact's, and requests once accepted. An unanswered message request gets nothing signed back, so until it is accepted, what it holds is sealed to `kex_pk`.
- **Not per-message.** A content key is still per epoch: someone with an epoch key reads every message under it. The window of one stolen reader key is the epochs sealed while it was current or kept.
- **An active thief.** Someone holding the seed can also sign as the device: publish a reader key of their own and be sealed to from then on, until the device is removed. Reader keys protect the past, not the future.
- **Cost.** One `ReaderKey` op (about 1.4 kB) per reader per space per week, and one rotation (1.2 kB per reader) per active space per day. Each op is also one more node in the graph every peer resolves (§10, Scale).
- **A reader can now add to the graph, and make writers rotate.** Before, a Reader could author nothing but its own leaving. It can now publish `ReaderKey` ops without limit, and each one marked `lost_previous` costs the next writer a rotation (a lockbox per reader). A member that does this on purpose is stopped by removing it, as one that floods the graph with rotations is.
- **Storage ordering.** The stored keyring is written in the background after each new epoch key; if that write is lost in a crash, the key is opened again from its lockbox at the next start, which works as long as the reader key is still held (30 days).

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

**After decrypting** (members only):
7. the Automerge change's actor ID must equal `header.author`. Authors cannot write under someone else's actor.

8. the change must be consistent with its **declared history** (its `deps` and their ancestors), never with whatever else a peer happens to hold: its actor sequence number is exactly one more than that actor's latest change in that history; its operation counters start above every counter in that history and fit in 32 bits; every actor in its actor table wrote something in that history; and every object, list/text element and predecessor its operations name exists in that history (or earlier in the same change) with the right shape (objects are maps, lists or text; elements are insertions into that same object). A change that fails is rejected for good. Checking this uses a per-document causal index (author, sequence, counter range and run-length operation summary per change, plus a sparse vector clock), so it costs the size of the change plus a logarithmic lookup per reference — no replay.
9. **resource limits** (before Automerge parses anything): at most 16 MiB after decompression, 1,048,576 operations, and a logical expansion of run-length/group-encoded columns of at most 64 values (or string bytes) per byte of change body, never below 4M (deleting a long run encodes in a few bytes) and never above 16M values / 16 MiB of strings. Writers stay far inside this: a local edit is written as changes of at most 65,536 operations and 512 KiB each, so a multi-megabyte paste becomes several consecutive changes that every released version accepts.

**Materialization:** a document = the valid, decryptable changes, applied in causal order. A change waits, still encrypted, until its dependencies are applied; validated changes reach Automerge in batches. Equivocation (two changes for one actor sequence number) is resolved by the lowest envelope ID, on every peer; if a lower-ID fork displaces a change that was already applied, the document is re-derived once per received batch, however many forks the batch carries. If a newly arrived revocation invalidates envelopes that were already applied, the peer **rebuilds** the document from its envelope store; other membership changes only touch envelopes whose validity or decryptability changed. Every peer holding the same graph and envelopes arrives at the same document.

## 7b. Attachments (blobs)

This is the format of attachments sent before chunked files (§7c). It is no longer produced; these attachments still download and open.

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

**Transfer.** Blobs are stored per space (`blobs/<space>/<blob>`) and served only to the space's members (stream kind `Blob` on ALPN `mycel/2`). They are streamed between QUIC and disk into `<blob>.part`, in disjoint ranges from every member that has the blob. The receiver checks the BLAKE3 hash of the whole blob before renaming it into place, so a peer can't substitute data. An interrupted transfer resumes from the `.part`, possibly from a different member. The final hash check covers the prefix too, and a bad prefix is discarded and fetched again.

**Availability and disk use.** There is no size limit and no per-space quota.
- Blobs up to 16 MiB are pushed to every member as soon as they're posted. Bigger ones are pushed only to keepers, and members fetch them when their user clicks download, from anyone in the space who has them.
- Receivers enforce this: a personal device refuses an unsolicited push above 16 MiB, so a member can't fill your disk with large files you never opened. Keepers accept any size.
- Every transfer is refused if it would leave less than 1 GiB of free disk space.

## 7c. Chunked files

New attachments are **chunked files**: a tree of small, separately sealed nodes, each named by the hash of its ciphertext, kept in one store for the whole device. Any device can hold and serve a node it can't read, and a receiver checks every node as it arrives. Attachments in the older format (§7b) still download and open, and their blobs are still served.

**Format** (`crates/mycel-crypto/src/chunked.rs`).

```
leaf   = XChaCha20-Poly1305(key, N, "mycel/v0/chunk-leaf", piece of the plaintext)
index  = "MYCELINDEX1\0" ‖ level: u8 ‖ count: u32 LE ‖ count × (child id: 32 ‖ child length: u32 LE)
         ‖ XChaCha20-Poly1305(key, N, "mycel/v0/chunk-index" ‖ H(all of the above),
                              count × child key: 32 ‖ hint count: u8 ‖ hints × 32)
id     = BLAKE3-derive_key("mycel/v0/chunk", node bytes)
N      = "mycel/v0/chunk-nonce" ‖ 4 zero bytes          H = BLAKE3-derive_key("mycel/v0/chunk-index-header", ·)
```

- An index at level 1 lists leaves; at level *n* it lists indexes of level *n* − 1 (at most 8,192 children, 4 levels). A full index is only closed when another child arrives, so the same pieces always give the same tree.
- A node's key is derived from that node's content (below), so no key ever seals two different nodes, and the nonce is a constant: the same key and nonce can only seal the same bytes again.
- The child ids and lengths are in the clear; the child keys are sealed. So a keeper or a cache can tell which nodes make up a file and whether it has them all, with no key, and only someone with the root key can open anything.
- **The reference.** The message's `AttachmentRef` keeps its shape (so older messages and the chat rules are unchanged): `blob` is the root node's id, `key` opens the root, and `nonce` holds the marker `MYCELCHUNKED1\0`, one flag byte (bit 0: public) and zeros instead of a nonce. A reference whose `nonce` doesn't start with the marker is a §7b blob.
- **A reader checks** each node against its id before using it, each index's level against its place in the tree, every length against the format's limits, and stops rather than write more plaintext than the message's `size`. A leaf never opens as an index or the other way round (different associated data). Before fetching, a tree that lists more nodes or bytes than a file of that `size` can have is refused, so a small reference can't unfold into a huge download.

**Two modes, chosen per file by the sender.**
- **Private** (the default). Every key is derived from a fresh random secret, the node's position and the node's content: `BLAKE3-derive_key("mycel/v0/chunk-key", secret ‖ level ‖ ordinal ‖ c)`, where `c` is what the node's key would be in a public file. The secret makes the keys unguessable and the content keeps each key to one node, whatever a caller does with the secret. The same file sent twice shares no node, and a repeated piece inside one file seals to different nodes. Pieces are a fixed 1 MiB: cutting by content would let the piece lengths fingerprint the file to whoever stores it, and gains nothing when nothing is shared.
- **Public** (opt-in: `send_message`'s `publicAttachments`). Every key is derived from the node's own content (convergent encryption: `BLAKE3-derive_key("mycel/v0/chunk-convergent-leaf", piece)`, and for an index `…-index` over its child list and child keys), and the plaintext is cut where its content says: a gear rolling hash (a fixed 256-entry table from BLAKE3), pieces of 256 KiB to 4 MiB, about 1 MiB on average. The same bytes give the same nodes and the same reference on every device, so a public file is stored once per device and sent only to devices that lack it, whoever sends it and in whichever conversation; two public files with a long stretch in common share that stretch's pieces.
  - **The price.** Anyone who has the file can compute its ids. They can check whether a device holds it, find devices that announced it, and so tell that two people have the same file. Someone who knows most of a file can test guesses for the rest. Don't send as public what you wouldn't want confirmed.
- **Forwarding** an attachment reuses its reference and its nodes, in either mode: the runtime does so when the path it is given is this device's own copy of a chunked attachment and still decrypts to the same bytes (an edited copy is sealed as a new file). The file is then kept for the other conversation too, and only devices that lack it are sent anything.

**Store** (`crates/mycel-net/src/chunks/store.rs`): `blobs/.chunks/`, one for all conversations. Nothing is stored unless its bytes hash to its id.
- **Pinned** nodes belong to a file one of this device's conversations refers to (sent, downloaded, or pushed by a member; on a keeper, pushed for a conversation it keeps). They are never evicted while that holds, and count against no budget.
- **Cached** nodes are held for others inside a donated budget: 1 GiB unless `MYCEL_FILE_CACHE_MB` says otherwise (0: hold nothing). When room is needed the least requested go first. A request by another device adds one to a node's score (not if that device was also the last to ask, within the hour), and scores halve every week. Nothing is dropped because of its age: only to make room.
- **Whose files.** A contact's file may displace the least requested nodes, but none that two or more devices asked for within the last week. Devices that aren't contacts get free room only, a quarter of the budget together and a sixteenth each. A blocked device gets nothing. The cache is apart from conversations, like the store-and-forward store (§8c): a device whose message request is still pending, or was declined without blocking it, can use it as any other stranger can; pushes *for a conversation* still need the app's consent.
- Every transfer keeps 1 GiB of disk free, as for blobs.

**Transfer** (`crates/mycel-net/src/chunks/`, stream kind `Chunk` on ALPN `mycel/2`).
- **Fetching.** A node is asked for by id, from the conversation's members first, all at once. A source that sends bytes that aren't the node is dropped on the spot and the node is asked of someone else; nothing wrong is stored. A download picks up where it stopped: the nodes already here are not fetched again.
- **Serving.** A node is given to anyone who asks for it by id: it is ciphertext, and its id is only known to those who have the reference (or, for a public file, the file). Devices we share a conversation with are served freely; all others at 1 MiB/s each and 4 MiB/s together (bursts of 16 s' worth), and are told to come back beyond that.
- **Pushing** needs an accepted offer naming the file and its size, and no more than that is taken (a device may have 16 offers open). Only nodes the receiver lacks are sent.
  - For a conversation, the rules are those of §7b: membership, the app's consent, keepers any size, other devices up to 16 MiB. The file is pinned when its root arrives and is an index, and after that only nodes the file's own indexes list are taken, so an offer alone leaves nothing behind and a push can't be used to store unrelated bytes.
  - For the cache, the budget rules above. The room is promised when the offer is accepted, for as long as the nodes keep coming (10 minutes between them at most).

**When a member can't be reached** (its push failed, or the file is too big to push and the member isn't around), the sender also hands the file to devices willing to hold it, until 2 devices besides itself have it: devices the app names, its contacts, then devices nearby on a fast link (those around first, up to 8 asked per try). Never over Bluetooth, a low-power radio or the mesh. It tries again 30 seconds and 5 minutes later while the app runs. A device that takes a whole file into its cache says so under an id derived from the root (with the internet: as a signed peer on the Mainline DHT, joined only when first needed; never in the local modes). A member who finds nobody of the conversation with the file then asks, together: the devices the root names (a private root can carry up to 8, sealed; Messaging names none, since that would show a conversation which devices its sender knows), the devices that announced it, and devices nearby on a fast link.

**What a holder and an observer learn.**
- A keeper or a cache: the node ids and sizes, which nodes make up a file and so its size, who pushed it, who asks for it and when. Not the content, the name or the type.
- For a public file, anyone who has the file can also tell what a holder holds (above).
- The lookup uses the one DHT node the device already runs for its records, and is off when the DHT is (`MYCEL_DHT=0`). The DHT nodes near a file's id see the device key and IP address of whoever announces or asks. The id is derived from the root, not the root, so it fetches nothing.

**Limits.**
- **"Never expires" is not a promise.** A file lasts while some device has all its nodes: pinned, for as long as a member or a keeper keeps the conversation; cached, for as long as it is asked for more than what competes with it for the holder's budget. A file many people use is held by many devices and keeps being asked for, so it is very likely to stay; nothing enforces it. To be sure, keep it in a conversation with a keeper.
- **Popularity can be faked.** A device with several keys can inflate a node's score on a holder (only an immediate repeat by the same key is ignored). It costs the holder nothing beyond its budget.
- **Holders make no commitment.** A cache may drop a file at any time, and there is no proof of storage: a holder that announces a file it doesn't have is found out only when its nodes are asked for.
- **Bluetooth is too slow for files.** At about 30 KB/s a gigabyte takes nine hours of contact, so files are not placed with holders over Bluetooth or the mesh, and store-and-forward bundles (§8c) still carry messages only. A file reaches a member who was away through a holder that member can later reach: over the internet, or by being near it on a fast link.
- **Nothing is fetched automatically.** A file is downloaded when its recipient opens it (files up to 16 MiB are still pushed to members who can be reached).
- **Placing a file with holders is not resumed** after the sender's app restarts, and only the sender does it (not the other members who have the file).
- **A conversation's files are not released yet.** Leaving a conversation, or deleting a message, doesn't unpin its files (as blobs were never deleted); the store can release them, the app doesn't ask it to.
- **Signed peers** are only stored by DHT nodes that run the same library's extension, far fewer than the DHT has. The lookup has run against a local DHT in tests, never the public one.
- As in §7b, a member can still fill other members' and keepers' disks with repeated valid pushes.

**Code and tests.** `crates/mycel-crypto/src/chunked.rs` (the chunker's cut points on a known input, sizes and boundaries, both modes, tree shapes, tampering, wrong keys, swapped and missing nodes, index parsing, hints); `crates/mycel-net/src/chunks/` (the store: pinning, eviction order, ageing, shares, reservations, restart; the protocol against a source that lies, a tree larger than its message says, pushes without or beyond an offer); `crates/mycel-net/tests/chunks.rs` (push policy, resume, several sources, a file fetched from a stranger's cache after its sender left, budgets, one copy of a public file); `crates/mycel-node` (new attachments are chunked, old ones still open, contacts and blocked devices).

## 8. Transport rules

- **ALPN** `mycel/2`: one connection per pair of devices; sync, cards, ephemeral messages and blobs are QUIC streams on it, labelled by a stream-kind byte. Iroh authenticates the remote node ID, which equals the remote `sign_pk`.
- **Responders serve a space only to its current members**, including Relays. Requests from non-members are refused.
- **Sync order:** membership ops first, then envelopes (set difference over full ID inventories).
- **Everything received is validated by the receiver.** Nothing is trusted because of who sent it.
- **ALPN** `mycel/mesh/1`: hop connections between nearby devices for multi-hop relaying ([ARCHITECTURE.md](ARCHITECTURE.md) §8). Accepted from anyone nearby: relaying needs no membership. What crosses a relay is the QUIC traffic of a connection between two *other* devices, so the rules above still apply end to end. See §8b.

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
- **Open proxy.** A gateway never looks up or dials anyone for traffic that came from the internet, and passes traffic between two internet hops only when one end asked it to be its relay (below), so nobody can bounce traffic through it.

**Relays among devices** ([ARCHITECTURE.md](ARCHITECTURE.md) §9b). A device the internet can reach relays between two internet hops for devices that asked; a device behind a router names its relays in its own record.
- **A relay can't** read, change or forge what it carries, or impersonate either end: as for mesh relays (§8b), it forwards the QUIC packets of a connection between two other devices.
- **A relay learns** the client's IP address (it is connected to it), who reaches the client through it, sizes and timing. A device asks 2 relays, among devices it already knows and the relays those devices name in their records (so a contact can point it at a relay of the contact's choosing; it is still asked only if its own signed record says it relays).
- **Asking is authenticated.** A request to relay counts only if it arrives straight from the asking device on its own hop connection (QUIC authenticates the device key); a frame that merely claims a source is ignored. So nobody can enrol someone else as a client, or make a relay carry traffic between two devices of their choosing.
- **A device that claims to relay and doesn't** (or drops what it carries) costs its clients a path: a client gives up on a relay that doesn't answer within 10 s or can't be connected to within 30 s, for 10 minutes, and takes another candidate. With 2 relays the other path carries on.
- **A relay that lies about the client's address** (it tells the client the address it sees it at) makes the client offer a wrong address for direct paths. Dials to it fail; the relayed path is unaffected. One address is kept, from the relays chosen.
- **A relay's own exposure.** Its record gives its IP address to anyone who knows its key, and anyone who knows its key can ask it to relay, up to 256 clients and 2 MiB/s (§8d: strangers can fill the places but can't keep out the devices the relay knows). `MYCEL_INTERNET_RELAY=0` turns the role off.
- **Records** are signed by their owner as before; the relay flag and the relays named are inside the signature. A record naming relays that never agreed costs the lookups a failed path.
- *Remaining:* no anonymity (relays see endpoints and timing); relays aren't chosen for trustworthiness beyond being devices the client already knows; a hostile contact that relays can watch a client's traffic patterns and drop its incoming connections on that path.
- **Budgets.** Traffic crossing between the mesh and the internet has its own cap (2 MiB/s per gateway) on top of the per-neighbour and total relay caps.

**Store-and-forward carriers** hold bundles: already-signed, already-encrypted envelopes for a destination key.
- **They learn:** the destination key, the source key, sizes, and when bundles were created and moved.
- **They can't:** read, alter (the source signs the bundle and the envelopes inside are signed), or fake delivery (receipts are signed by the destination).
- **Abuse limits:** a 64 MiB store, 256 KiB bundles, 4 MiB per source, lifetimes up to 7 days, and per-neighbour rate limits. A bundle is never sent back to the device that gave it.
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
- **Relaying over the internet** (§8c): 2 MiB/s between internet hops, on
  top of the mesh's 1 MiB/s per neighbour and 4 MiB/s in total; at most 256
  clients. When strangers fill all 256 places, a device we know (a contact,
  someone in our chats) takes the place of the stranger that asked longest
  ago; a stranger is refused. A client that stops asking is forgotten after
  3 minutes.

## 9. Code and tests

| Spec section | Code | What the tests cover |
|---|---|---|
| §2 primitives | `crates/mycel-crypto` | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper; the hybrid lockbox: sizes, tampering in either KEM part and in the ciphertext, a pinned key derivation, the X25519 keys and lockboxes of earlier builds refused; reader keys not derived from the seed; sealed device storage; the streaming attachment AEAD (§7b): chunk boundaries, tamper, truncation, extension, reorder, duplication, chunk-size change, legacy detection, incremental digest |
| §3–§6 graph, resolution, epochs | `crates/mycel-trust` (`resolve.rs` = §5) | Reader keys (`reader_tests.rs`): sealing moves to a published reader key, a deleted key closes its lockboxes while a kept keyring stays whole, concurrent reader keys and rotations converge in every delivery order, who may publish one, malformed keys, the join window, epochs closed by a lost key. Forged admin ops, pending ops, removal and rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, leave, epoch-ID reuse, ops from never-added keys; fan-outs of invalid ops, wide valid frontiers, pending-pool limits and ready admin ops |
| §7 envelopes | `crates/mycel-sync` | The key schedule (`keys_tests.rs`): nothing published until the schedule is on, reader keys replaced weekly and deleted after 30 running days, stored before published, sealed secrets bound to device and space, restarts with and without them, an attacker with the seed and a keeper's data, timed rotation and its jitter, concurrent rotations, a sealer behind inside and past the retention, downtime, a clock set back, lost storage, keepers, restoring stored ops in any order. Replication, reader writes rejected, keeper can't read, outsider and tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, equivocation; decompression and expansion bombs, malformed and deferred changes, declared-history checks (actor, counters, object references), delivery-order and restore consistency |
| §8–§8d transport, mesh, limits | `crates/mycel-net`, `crates/mycel-node` | End to end over real Iroh QUIC with five nodes (admin, writer, reader, keeper, outsider); forged, renamed and replayed mesh announcements; signed-field cache mutation; stream and frame budgets, stalled and progressing I/O, duplicate requests, invitation validation order, ephemeral limits; attachment consent and disk reservations across restarts |

`scripts/security-check.sh` runs these security tests without retries, then
the web checks, `npm audit` and the RustSec advisories through cargo-deny
(`cargo deny check advisories`, the policy in `deny.toml`). CI runs the same
checks on every pull request and the Audit workflow runs them daily against
new advisories. Vulnerabilities always fail; so do unmaintained and unsound
crates, unless `deny.toml` accepts one by ID with the reason Mycel isn't
exposed and a review date (`.cargo/audit.toml` mirrors the list for
`cargo audit --deny unsound --deny unmaintained`). As of 2026-11-17 it
accepts, each on one platform or at build time only:

- RUSTSEC-2024-0429, unsound `glib::VariantStrIter` in glib 0.18, which
  comes with Tauri's GTK 3 webview: no Tauri release is on gtk-rs 0.19 yet,
  and nothing in this repository or between it and glib calls that API;
- RUSTSEC-2026-0370/0371/0372, `zvariant`, `zbus_names` and
  `zvariant_derive` "unmaintained" since zbus 6 absorbed them; zbus 5 still
  comes with Tauri's notification and opener plugins;
- RUSTSEC-2024-0370 and RUSTSEC-2024-0436, the `proc-macro-error` and
  `paste` proc macros, which never run in a shipped binary;
- RUSTSEC-2026-0543, `chrono` "unmaintained": on Windows only, where it
  comes with `wmi`, which Iroh's network monitor uses. Neither has a release
  without it, and nothing in this repository uses it.

`zip` was moved to 9.0.5 for RUSTSEC-2026-0367/0368/0369 (extraction
flaws; Mycel only writes archives, when it zips a shared folder).
`rustls-webpki` was moved to 0.103.16 and `webpki-roots` and
`webpki-root-certs` to 1.0.10 for RUSTSEC-2026-0382/0381/0383 (emSign
intermediates whose private keys are public could anchor a TLS chain; these
crates sit on the relay and HTTPS client paths through Iroh, reqwest and
Tauri). Lockfile only, no vendored code changed.
`ctutils` was moved to 0.4.8 for RUSTSEC-2026-0385 (constant-time helpers
that could compile to a branch on a secret value; the RustCrypto hashes and
Iroh use them) and `rustix` to 1.1.6 for RUSTSEC-2026-0486 (unsound
extended-attribute reads into an empty buffer). `async-executor` 1.14.0 was
withdrawn by its authors and is now 1.14.1. Lockfile only again.

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
- **Forward secrecy in windows, not per message** (§6). Content keys are
  per epoch, and the history of a document stays readable to its members.
  Lockboxes are sealed to reader keys that a device replaces weekly and
  deletes 30 running days later, so a stolen device key alone, with all
  the ciphertext keepers hold, opens only what was sealed to the key
  derived from it: what a member was given when it joined a space (every
  epoch up to then), what was sealed until the first rotation after its
  first reader key, and requests it never accepted. A stolen device key
  *and* database exposes the history in that database and the epochs
  sealed to the reader keys still in it. Whoever holds the device key can
  also act as the device from then on. Removing a member doesn't erase
  what they already received.
- **A lost reader key loses its epochs.** A device that can't open an
  epoch (it lost its storage; or the sealer was out of touch for more than
  the 30 days and sealed to a key since deleted) can't read what was
  written under it, on that device, ever: nobody re-seals an old epoch
  key. It says so in the graph and writers move to a new epoch, so only
  that stretch is lost. Two groups of members cut off from each other for
  over a month, both writing, is the case to know about.
- **Post-quantum only in part.** Lockboxes, which keepers store long-term,
  are hybrid (X25519 + ML-KEM-768, §2), so recording them now and breaking
  X25519 later doesn't open them. Signatures are Ed25519: someone with a
  quantum computer could forge membership ops, envelopes and cards from
  then on. The transport handshake is X25519 only: recorded traffic could
  be decrypted later, which exposes what §8b lists as metadata (the
  content inside is encrypted under epoch keys). A hybrid handshake exists
  in the stack Mycel builds on but isn't used: the rustls version in the
  lockfile offers X25519MLKEM768 only with its `aws-lc-rs` provider, Iroh
  takes that provider behind its `tls-aws-lc-rs` feature
  (`Builder::crypto_provider`), and noq has a test for such a handshake;
  Mycel builds Iroh with `ring`, which has no ML-KEM, and switching means
  building AWS-LC (C and assembly) for every platform. ML-KEM-768 and its
  Rust implementation (`ml-kem`) are also much younger than X25519; the
  hybrid is there so that a flaw in them costs nothing today.
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
  the app's files folder. Reader keys and opened epoch keys are in the
  database, sealed under a key derived from the device key (§6); the rest
  of the database (ops and envelopes, which are ciphertext; contacts;
  settings) is not encrypted. There is no app lock or app-switcher
  redaction.
- **Scale.** Resolution is linear for linear history but O(n²) for heavily
  concurrent membership ops, and envelope validity is recomputed on each
  membership change. Rotation sends one lockbox per reader, about 1.2 kB
  each (§2): 350 kB for 300 readers, so fine up to a few hundred members.
  The key schedule (§6) adds ops that nobody asked for: a rotation per
  active space per day and a reader key per reader per week, so a space of
  300 readers gains about 300 ops a week (0.4 MB of reader keys, and
  2.5 MB of rotations if it is written to every day), and its graph grows
  by its readers' keys even while nothing is written. Each reader-key op
  is also a membership change, so envelope validity is recomputed for it.
  The periods are per-replica settings (`KeyPolicy`), not yet scaled to
  the size of a space. Sync exchanges full ID inventories.
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
