# Mycel Trust Layer v0 — specification

> Status: draft for phase 0 — 2026-10-07. Our own minimal layer; it sits behind the `Trust` abstraction so it can later migrate to Keyhive.
> **Rule zero: no custom cryptography.** Only standard, widely reviewed primitives. This spec must get an external review before real users depend on it.

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
- **Availability:** keepers can withhold data. Mitigation is multiple keepers. Withholding cannot be detected in v0.
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
- **v0 simplification:** member = device. (Multi-device agents arrive in phase 1, as a signed device list under one agent key.)

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

**After decrypting** (members only):
7. the Automerge change's actor ID must equal `header.author`. Authors cannot write under someone else's actor.

**Materialization:** a document = the valid, decryptable changes, applied in causal order. If a newly arrived revocation invalidates envelopes that were already applied, the peer **rebuilds** the document from its envelope store. Every peer holding the same graph and envelopes arrives at the same document.

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
- **Legacy format:** attachments sent before this used one-shot `XChaCha20-Poly1305(key, nonce, A, plaintext)`. A blob without the magic prefix is opened that way. Only blobs up to 64 MiB are opened like that (the old cap was 50 MiB), so a hostile reference can't make a peer read a huge blob into memory.
- Code: `crates/mycel-crypto/src/stream.rs`. Tests cover roundtrip at chunk boundaries (0, 1, chunk − 1, chunk, chunk + 1, many chunks), tampering, wrong key/nonce/AAD, truncation, extension, reordering, duplication and chunk-size changes.

**Transfer.** Blobs are stored per space (`blobs/<space>/<blob>`) and served only to the space's members (stream kind `Blob` on ALPN `mycel/2`). They are streamed between QUIC and disk into `<blob>.part`, in disjoint ranges from every member that has the blob. The receiver checks the BLAKE3 hash of the whole blob before renaming it into place, so a peer can't substitute data. An interrupted transfer resumes from the `.part`, possibly from a different member. The final hash check covers the prefix too, and a bad prefix is discarded and fetched again.

**Availability and disk use.** There is no size limit and no per-space quota.
- Blobs up to 16 MiB are pushed to every member as soon as they're posted. Bigger ones are pushed only to keepers, and members fetch them when their user clicks download, from anyone in the space who has them.
- Receivers enforce this: a personal device refuses an unsolicited push above 16 MiB, so a member can't fill your disk with large files you never opened. Keepers accept any size.
- Every transfer is refused if it would leave less than 1 GiB of free disk space.

## 8. Transport rules

- **ALPN** `mycel/2`: one connection per pair of devices; sync, cards, ephemeral messages and blobs are QUIC streams on it, labelled by a stream-kind byte (until 2026-10-08: `mycel/sync/1`, `mycel/card/0`, `mycel/eph/0`, `mycel/blob/0`). Iroh authenticates the remote node ID, which equals the remote `sign_pk`.
- **Responders serve a space only to its current members**, including Relays. Requests from non-members are refused.
- **Sync order:** membership ops first, then envelopes (set difference over IDs in v0; range-based reconciliation later).
- **Everything received is validated by the receiver.** Nothing is trusted because of who sent it.

## 9. Implementation status (phase 0, 2026-10-07)

| Spec section | Code | Tests |
|---|---|---|
| §2 primitives | `crates/mycel-crypto` | 14 unit tests: domain separation, framing, kex binding, lockbox info binding, AEAD tamper; streaming attachment AEAD (§7b): chunk boundaries, tamper, truncation, extension, reorder, legacy detection, incremental digest |
| §3–§6 graph, resolution, epochs | `crates/mycel-trust` (`resolve.rs` = §5) | 13 tests: forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation |
| §7 envelopes | `crates/mycel-sync` | 9 tests: replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion |
| §8 transport | `crates/mycel-net` | end-to-end over real Iroh QUIC: 5 nodes (admin, writer, reader, keeper, outsider) |

## 9b. Security review (2026-10-07) — fixed

An independent adversarial review found these issues. All are fixed, each with a regression test:

| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | Critical | Peer-chosen attachment names allowed path traversal on download | Strict basename sanitizer, paths confined to `files/`, macOS quarantine xattr on downloads, opener scope narrowed |
| 2 | High | Any LAN outsider could push a conversation and impersonate a name | Invites from non-contacts become **message requests** (nothing is trusted or posted until Accept), Decline/Block, blocked keys refused at the network layer, Relay-role invites refused on personal devices |
| 3 | High | Pre-authentication CPU/RAM exhaustion via junk ops and envelopes | Ops and envelopes from never-added keys are dropped before storage; caps on parents, auth_heads, pending ops, invite size and lockboxes; bounded state cache; index passed to replay |
| 4 | High | Epoch-ID reuse with a different key could break convergence | `EpochId = H(commitment)`, checked structurally; unlock verifies each key against its own op's commitment |
| 5 | Medium | Duplicate Automerge (actor, seq) could make docs diverge | Equivocation detected: the lowest envelope ID wins on every peer, and the doc is rebuilt canonically |
| 6 | Medium | Overflow panic poisoned the global lock (crash loop) | `checked_add`; `parking_lot` mutexes (no poisoning) |
| 7 | Low | Members who had left could keep posting with backdated heads | `Leave` carries a cutoff and is treated as a revocation |
| 8 | Low | Blobs weren't scoped to a space, and had no quota | Per-space blob directories. The 2 GiB per-space quota was later replaced (§7b) by refusing unsolicited pushes above 16 MiB on personal devices and refusing any transfer that would leave less than 1 GiB free |
| 9 | Low | Local HTTP API gaps | Per-run secret token (embedded in the page, `0600` file for the CLI) on every route; file serving limited to attachment folders; browser attachments must come from uploads |

**Still open:**
- `NeedInvite` vs `Denied` reveals whether a node holds a space whose 256-bit ID you already know.
- mDNS and the card protocol reveal device names and public keys on the LAN, by design.

**Spec drift fixed in this doc:**
- The sync protocol runs as `Sync` streams on ALPN `mycel/2` (it was ALPN `mycel/sync/1`).
- The header field is `stream` (Doc or Feed), not `doc`.
- Seniority is computed from ops that pass authorization ignoring concurrency.
- Forks before a cutoff are tolerated but not yet surfaced in the UI.

## 10. Known v0 gaps (tracked)
- **Post-quantum:** lockboxes are long-lived ciphertext stored on keepers, so they are exposed to harvest-now-decrypt-later attacks. Move to X-Wing (hybrid ML-KEM + X25519, already supported by `hpke` 0.14) once the IETF draft is final.
- **Performance:** resolution is O(n²) in membership ops, which is fine for hundreds of ops. Envelope validity is recomputed on every ingest, which is fine for thousands of envelopes. Incremental resolution is planned for phase 1.
- **Sync efficiency:** sync sends full ID inventories. Replace with range-based set reconciliation (Negentropy-style).
- Multi-device agents and device revocation (phase 1).
- Rotation cost is O(n) lockboxes per rotation. Fine for groups up to a few hundred; switch to TreeKEM/BeeKEM-style rotation later.
- Honest edits built on top of a removed member's concurrent edits are dropped on rebuild (Automerge needs dependencies). This needs a "re-author" recovery flow.
- Keepers see metadata.
- Needs a professional cryptographic review before production.
