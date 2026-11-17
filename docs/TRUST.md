# Mycel trust layer: specification

This document specifies how Mycel decides who may read and write what, with no
server to ask. It covers the threat model, identities and keys, membership, key
rotation, the formats of everything that is signed or encrypted, the transport
and mesh rules, resource limits, and what the layer does not do.

It is written for security reviewers, and for anyone changing
`crates/mycel-crypto`, `crates/mycel-trust`, `crates/mycel-sync`,
`crates/mycel-net` or `crates/mycel-node`: comments in that code cite the
sections here by number, so the numbers are kept stable. Context strings carry
the format version: `mycel/v0/…`, and `mycel/v1/…` where a construction has
replaced an earlier one.

> **This layer has not had an external review.** Do not rely on it for anything
> that needs to stay secret until it has. Its one design rule is no custom
> cryptography: only standard, widely reviewed primitives.

Three terms recur:

- A **space** is a set of member devices and the content they share, such as a
  conversation. Its membership is a graph of signed ops ([§4]).
- A **keeper** is a member with the `Relay` role: it stores and forwards a
  space's ciphertext and holds no keys.
- A **mesh relay** ([§8b]) or a **device relay** ([§8c]) forwards the packets of
  a connection between two other devices. It is not a member of anything by
  being a relay.

## Contents

1. [Threat model](#1-threat-model)
2. [Primitives](#2-primitives)
3. [Identity](#3-identity)
4. [Spaces and the membership graph](#4-spaces-and-the-membership-graph)
5. [Resolving the graph](#5-resolving-the-graph)
6. [Epochs and encryption keys](#6-epochs-and-encryption-keys)
7. [Content envelopes](#7-content-envelopes)
   - 7b. [Blob attachments (older format)](#7b-blob-attachments-older-format)
   - 7c. [Chunked files](#7c-chunked-files)
8. [Transport rules](#8-transport-rules)
   - 8b. [Mesh relays](#8b-mesh-relays)
   - 8c. [Gateways, records and carriers](#8c-gateways-records-and-carriers)
   - 8d. [Resource limits](#8d-resource-limits)
9. [Code and tests](#9-code-and-tests)
   - 9b. [Hardening](#9b-hardening)
10. [Limitations](#10-limitations)

## 1. Threat model

This section names the adversaries the layer defends against and the risks it
leaves out. [§10] lists the limitations in full.

### Adversaries defended against

- Outsiders: anyone on the network, including relays and keepers. They must not
  read content, forge membership or forge content.
- Keepers: storage nodes that are honest but curious, or malicious. They can
  drop, delay or replay data. They cannot read it, forge it, or make it valid.
- Removed members. They must not read content created after peers learn of the
  removal, and must not get new writes accepted.
- Lower-privileged members. Readers cannot write; writers cannot change
  membership.
- Malicious writers. They cannot impersonate other authors, rewrite others'
  history, or make peers diverge.

### Out of scope

- Admins are trusted with keys. A malicious admin can leak keys out of band.
- A removed member keeps what they already decrypted, and can read content that
  partitioned peers keep encrypting under an old epoch before they learn of the
  removal.
- Metadata is visible to keepers: membership public keys, envelope authors,
  sizes and timing.
- Keepers can withhold data. The mitigation is several keepers. Withholding
  cannot be detected.
- There is no forward secrecy within an epoch, only post-compromise security on
  rotation. [§6] says what reader keys and timed rotation add.
- A compromised device can act as its member until removed.

## 2. Primitives

This section lists the cryptographic primitives and the crates that provide
them, says how their inputs are kept apart, and specifies the hybrid
post-quantum key agreement used for lockboxes.

| Purpose | Primitive | Crate |
|---|---|---|
| Signatures, device identity, transport identity | Ed25519, strict verification | `ed25519-dalek` |
| Key agreement for lockboxes | HPKE (RFC 9180), base mode: the X-Wing hybrid KEM (X25519 + ML-KEM-768, KEM id `0x647a`), HKDF-SHA256, ChaCha20-Poly1305 | `hpke`, over `x-wing` and `ml-kem` |
| Content encryption | XChaCha20-Poly1305, 192-bit random nonce | `chacha20poly1305` |
| Hashing, IDs, key commitments | BLAKE3, `derive_key` mode | `blake3` |
| Canonical encoding of the bytes that are signed | postcard, deterministic for a fixed schema | `postcard` |
| Randomness | OS CSPRNG | `getrandom` |
| Secret hygiene | zeroize on drop | `zeroize` |

### Domain separation

Every signature, key derivation and HPKE `info` input carries a context string
that no other use shares, for example `mycel/v0/op`, `mycel/v0/envelope` and
`mycel/v0/lockbox`.

- A signature is made over `len(context): u8 ‖ context ‖ message`, so the
  boundary between context and message is unambiguous. The formats below write
  this as `Ed25519(key, "context" ‖ message)`.
- Hashes and key derivations use BLAKE3's `derive_key` mode with the context.

This also separates Mycel's signatures from the TLS signatures that Iroh makes
with the same Ed25519 key. TLS 1.3 signs a context prefixed with 64 spaces, so
the two cannot collide.

### Hybrid post-quantum lockboxes

A **lockbox** is a secret sealed with HPKE to one recipient's key. Epoch keys
and keyrings travel in lockboxes ([§4]). Keepers store lockboxes for years, so a
lockbox is what an attacker who records now and decrypts later would go for.

The key agreement of a lockbox is X-Wing: the shared secret comes from both
X25519 and ML-KEM-768 (FIPS 203), so a lockbox stays sealed unless both are
broken. A quantum computer breaks X25519; ML-KEM is the newer and less studied
of the two.

Every lockbox is hybrid, so every epoch key and every keyring handed to a new
member is. Signatures (Ed25519) and the transport handshake (TLS 1.3 with
X25519, [§8]) are still classical; [§10] says what that exposes. The symmetric
parts are unchanged: 256-bit keys, which Grover's algorithm does not bring
within reach.

| | X-Wing | X25519 alone |
|---|---|---|
| Lockbox public key (`kex_pk`) | 1216 bytes | 32 bytes |
| Encapsulated key of a lockbox | 1120 bytes | 32 bytes |
| Lockbox holding an epoch key | 1168 bytes | 80 bytes |

A rotation therefore costs about 1.2 kB per reader, and adding a member about
2.5 kB: their keys, and their keyring's lockbox.

The suite is bound into every lockbox. Its HPKE `info` is the suite label, then
the caller's own `info`, and the KEM id is in HPKE's own key schedule:

```text
info  = len(suite): u8 ‖ suite ‖ caller's info
suite = "mycel/v1/lockbox/xwing-hkdfsha256-chacha20poly1305"
```

Lockboxes and keys in the X25519 format of earlier builds are refused:

- an X25519 lockbox is refused by its length, with an error that says so
  (`UnsupportedLockbox`);
- a 32-byte key does not decode as a lockbox key;
- `kex_sig` ([§3]) is made under a new context, so an old binding does not
  verify.

A lockbox key decodes if it has the right length. Wherever one is admitted, it
is also checked to be a key X-Wing accepts (ML-KEM's canonical encoding): by
`verify_binding` in every `Genesis` and `Add` op and every contact card, and by
`validate` in every `ReaderKey` op. A key that passed can always be sealed to,
so a member cannot block rotations with a malformed key.

## 3. Identity

This section defines a device's keys, how its public keys are bound to each
other, and how one device learns another's keys. A member is one device: each
device has its own keys, and one person's devices are separate members of a
space.

### Device keys

A device's identity is its 32-byte seed. Two key pairs are derived from it, so
the seed is all an identity is:

- `sign` is an Ed25519 key pair with the seed as its secret key. Its public
  half, `sign_pk`, is also the Iroh node ID, so a transport connection
  authenticates the device.
- `kex` is an X-Wing key pair (X25519 + ML-KEM-768), used for lockboxes. Its
  32-byte secret is `BLAKE3-derive_key("mycel/v1/kex-seed/xwing", seed)`.

A device also holds **reader keys**: random X-Wing keys that it publishes per
space, replaces weekly and deletes ([§6]). In a space where it has published
one, its lockboxes are sealed to that key instead of `kex`. Reader keys are not
derived from the seed; the device stores them, sealed under a key that is.

### Member keys

A device is named in a space by its `MemberKeys`:

```text
MemberKeys { sign_pk, kex_pk, kex_sig }
kex_sig = Ed25519(sign_sk, "mycel/v1/kex-binding" ‖ kex_pk)
```

The signature proves that the device holds both keys, so an attacker cannot
substitute a kex key during the invite exchange. A lockbox is only ever sealed
to a `kex_pk` under such a signature.

### Contact codes

A contact code is what a person shares so that others can add their device
(`crates/mycel-node/src/runtime/contacts.rs`). It comes in two forms.

The **short** code is the one shown as text and as a QR code. It holds `sign_pk`
and the name the device signed, because the 1216-byte `kex_pk` is too much to
paste or scan. The device that adds it fetches the signed card from the other
device the first time it reaches it, checks the card against the `sign_pk` it
was given, and only then can put the contact in a space. Until then nothing is
sealed to it.

The **full** code holds the whole signed card and needs no connection.

```text
short code = { sign_pk, name, sig: Ed25519(sign_sk, "mycel/v1/contact-stub" ‖ name) }
card       = { keys: MemberKeys, name, sig: Ed25519(sign_sk, "mycel/v0/contact-card" ‖ postcard(keys) ‖ name) }
```

Either form may be followed by the device's current addresses. They are unsigned
hints, used only to find the device.

## 4. Spaces and the membership graph

A space is defined by a directed acyclic graph of signed **membership ops**.
This section gives the op format, the roles, what each action does and who may
issue it, and how an epoch key reaches its readers. [§5] says how peers agree on
which ops are valid.

### Ops

```text
SignedOp { op: Op, sig: Ed25519(author, "mycel/v0/op" ‖ postcard(op)) }
Op       { space: SpaceId?, parents: [OpId], author: SignPk, nonce: u64, action: Action }
OpId     = BLAKE3-derive_key("mycel/v0/op-id", postcard(SignedOp))
SpaceId  = OpId of the Genesis op   (Genesis has space = None, parents = [])
```

`nonce` is random. It makes otherwise identical ops distinct, for example when
the same member is added again.

An op is refused before it is stored if its signature does not verify, if it has
more than 64 parents (`MAX_PARENTS`) or names a parent twice, if it belongs to
another space, or if no known op has ever added its author. A `Genesis` must
have no space, no parents and its founder as author. Every other op must name
its space and have at least one parent.

### Roles

Roles have a fixed order: `Relay < Reader < Writer < Admin`. A member with the
`Relay` role is a keeper.

| Role | Read keys | Write content | Rotate keys | Change membership | Store and forward |
|---|:-:|:-:|:-:|:-:|:-:|
| Relay | | | | | ● |
| Reader | ● | | | | ● |
| Writer | ● | ● | ● | | ● |
| Admin | ● | ● | ● | ● | ● |

### Actions

Each action names the role its author must hold in the op's causal state ([§5],
step 5).

- `Genesis { founder, rotation }` creates the space. Anyone may author one; it
  must be the unique root. The founder becomes Admin, and `rotation` seals the
  first epoch key to the founder alone.
- `Add { member, role, keyring? }` (Admin) gives `role` to a device that is not
  a member. A role that can read comes with `keyring`: a lockbox holding the
  keys of all earlier epochs.
- `SetRole { member, role, revocation?, rotation? }` (Admin) changes a member's
  role. A downgrade is a **revocation** and carries `revocation`. If the member
  loses read access, it also carries `rotation`.
- `Remove { member, revocation, rotation }` (Admin) removes the member. It is a
  revocation, and it must rotate.
- `Rotate { rotation }` (Writer or Admin) creates a new epoch key for exactly
  the current readers.
- `Leave { cutoff }` (any member) removes its author. It is a revocation of the
  author by itself, with no rotation.
- `ReaderKey { key, lost_previous }` (Reader or above): from this op on, the
  author's lockboxes are sealed to `key` ([§6]). `lost_previous` says that the
  author cannot open what was sealed to its earlier reader keys.

A revocation carries a `cutoff`: the latest envelope from the revoked member
that the revoker had seen, if any ([§7], rule 5). In `SetRole` and `Remove` it
is the one field of `revocation`.

No op may leave a space without an Admin. A `SetRole`, `Remove` or `Leave` that
would is not authorised, so the last Admin cannot leave.

### Rotations and lockboxes

A rotation distributes a fresh random 256-bit epoch key:

```text
Rotation   { epoch: EpochId, commitment, lockboxes: [(recipient SignPk, Lockbox)] }
Lockbox    = HPKE seal of the epoch key to the recipient's key, with info
info       = "mycel/v0/lockbox" ‖ epoch ‖ recipient SignPk
commitment = BLAKE3-derive_key("mycel/v0/epoch-commit", epoch key)
EpochId    = first 16 bytes of BLAKE3-derive_key("mycel/v0/epoch-id", commitment)
```

- Each recipient checks the key it unseals against `commitment`, so a rotator
  cannot hand some members a different key undetected.
- `EpochId` is derived from the commitment, and every peer checks that
  derivation, so two rotations can share an ID only if they share a key. A
  rotation whose ID is already an epoch of the state it is checked against is
  not authorised.
- `info` binds each lockbox to its epoch and its recipient. Genesis cannot bind
  the space ID, because the space ID is the hash of genesis itself.
- Lockboxes are sorted by recipient key, with no recipient twice and at most
  1,024 of them (`MAX_MEMBERS`).
- The recipient set must equal exactly the set of members with read access in
  the state after the op. A lockbox for a non-member, or a missing member, makes
  the op invalid.

A lockbox is sealed to the recipient's reader key: the last `ReaderKey` op of
that member in `T` order ([§5]) as the sealer sees the graph. While the member
has published none, it is sealed to the `kex_pk` in its `MemberKeys` ([§6]).
Both are keys the recipient's device key signed. A member that loses read access
drops its reader key: if it reads again later, it starts from its `kex_pk`.

The keyring of an `Add` is one lockbox, always sealed to the new member's
`kex_pk`, with its own context and the op's nonce in its `info`:

```text
keyring = HPKE seal of postcard([(EpochId, epoch key)]) to the new member's kex_pk, with info
info    = "mycel/v0/keyring" ‖ space ‖ op nonce: u64 LE ‖ new member's SignPk
```

## 5. Resolving the graph

Every peer computes the set of valid ops and the resulting membership with the
same deterministic algorithm, so peers that hold the same ops agree. This
section gives the algorithm, the rule for authoring on top of the graph, and the
bounds on ops that cannot be evaluated yet.

### Algorithm

1. Topological order `T`. Kahn's algorithm, ties broken by `OpId` bytes.
2. Seniority. The founder has rank 0. Every other member is ranked by the
   `T`-index of the first `Add` naming them among the ops that pass the
   authorisation replay of step 5 with nothing excluded. Seniority is computed
   once, before any revocation is decided, so it does not depend on which
   revocations win.
3. Revocation winners. Consider the revocation ops (`Remove`, a downgrading
   `SetRole`, `Leave`) in order of (author seniority, `T`-index). A revocation
   `r` loses if an earlier winner `w` revokes `r`'s author and `r` is concurrent
   with `w`. Concurrent means that neither is an ancestor of the other. This
   makes mutual removal resolve in favour of the more senior admin.
4. Concurrent invalidation. For each winner `w` targeting member `X`, every op
   by `X` that is concurrent with `w` is invalid. Revocation wins over
   concurrent actions by the revoked member.
5. Authorisation replay. Walk `T`, skipping the ops invalidated in step 4. Check
   each op against `state(valid ∩ past(op))`: what the author could prove they
   were allowed to do when they made the op. An unauthorised op is invalid and
   excluded from every state. Its descendants are judged on their own merits.
6. If a winner of step 3 fails step 5, drop it from the candidates and repeat
   from step 3. This terminates because the candidate set only shrinks.
7. The current state is the replay of all valid ops in `T`.

Ops whose parents are unknown are **pending**. They are not evaluated until the
parents arrive.

### Heads

The authoring frontier, `heads()`, is the set of causally maximal valid ops. It
gives a new op its `parents` and a new envelope its `auth_heads`. Invalid ops
are still stored, still count for ancestry and still sync, but they never become
heads.

If they did, anyone able to sign an op (a Reader, or a member being removed)
could append a fan-out of more than `MAX_PARENTS` (64) invalid ops. Every admin
op would then need more parents than an op may carry, and nobody could revoke
the attacker. Because ancestry still runs through every stored op, a valid op
written after an invalid one keeps it in its past.

A genuinely concurrent valid frontier wider than 64 ops is never truncated.
Authoring fails instead; this is a known protocol limit.

### Pending ops

Pending ops are held in memory before anyone can tell whether they are
authorised, so the pool is bounded: at most `MAX_PENDING` (4,096) in total and
`MAX_PENDING_PER_AUTHOR` (256) per author.

- The per-author cap stops one member, or one stolen key, from filling the
  shared pool and starving everyone else's out-of-order ops.
- Ops whose parents are all known bypass the pool, so a full pool never blocks a
  ready admin op such as a revocation.
- An op refused by a full pool is not lost: the next sync offers it again.

To keep honest syncs inside these caps, peers send ops in resolution order
(`op_ids()` and `all_ops()`: topological, then pending ops by ID), so a receiver
normally admits every op directly. Sent in that order, a single admin's
10,000-op history is admitted by a graph in one batch. The network layer has its
own, smaller cap on an invitation ([§8]).

### Cost

Resolution keeps a running state while history is linear, that is, while each
op's past contains every valid op before it. A long run of one admin's ops
therefore resolves in linear time. Only ops concurrent with others replay their
own past.

## 6. Epochs and encryption keys

An **epoch** is one content key together with the members it was given to. This
section says which epoch a writer uses, how a device keeps its keys, and how
reader keys and timed rotation limit what a stolen identity key opens.

### Keyrings and the write epoch

Each peer keeps a keyring, `EpochId → key`. It fills it by unsealing the
lockboxes addressed to itself in valid ops only, and checks each key against its
commitment.

The recipients of an epoch are the lockbox recipients of its rotation, plus the
members later added with read access by an `Add` that has the rotation in its
causal past: those are the epochs a keyring covers.

A writer encrypts under the latest epoch in `T` order whose recipients equal
exactly the current readers. If none qualifies (after a concurrent add or
remove), or the writer does not hold that epoch's key, it first issues a
`Rotate`. This self-heals: no epoch shared with a removed member is used once
the removal is known.

### Forward secrecy

A lockbox sealed to `kex_pk` can be opened with the seed alone, for ever,
because `kex_pk` is derived from the seed. Someone with the seed and the
lockboxes a keeper stores would hold every epoch key sealed that way. To limit
what a stolen seed opens, a device does the following in each space it takes
part in (`crates/mycel-sync/src/keys.rs`):

1. Reader keys. It publishes a random X-Wing key, a reader key, in a `ReaderKey`
   op, and a new one every 7 days. From that op on, others seal its lockboxes to
   it ([§4]). The private half is not derived from the seed.
2. Deletion. A replaced reader key is kept for 30 days and then deleted. It is
   kept because someone who has not seen the new one still seals to it. The 30
   days count only while the device runs: a gap of more than 6 hours in its own
   clock is time it was off, when nothing could reach it, so a device waking
   from a long sleep deletes nothing before it has synced.
3. A stored keyring. Opened epoch keys are kept, with the reader keys, in one
   sealed record per space (below). They are not derived again at each start: a
   lockbox whose reader key is gone cannot be opened again by anyone, the device
   included. The record is useless without the seed, and useless to another
   space.
4. Timed rotation. A writer rotates the epoch on its next write once it has held
   the current epoch's key for 24 hours, plus a per-device, per-epoch jitter of
   up to 6 hours so that writers do not all rotate together. Two that do anyway
   produce two epochs, of which the later in `T` order is written under; both
   stay readable.
5. Store first. A reader key's private half is written to the device's storage,
   durably, before the `ReaderKey` op is published. If it cannot be stored, it
   is not published.

The stored record is sealed under a key derived from the seed and bound to its
space as associated data:

```text
record      = nonce: [u8; 24] ‖ XChaCha20-Poly1305(storage key, nonce, aad = SpaceId, secrets)
storage key = BLAKE3-derive_key("mycel/v1/storage-key", seed ‖ len(purpose): u8 ‖ purpose)
purpose     = "space-secrets"
```

All of this runs on the device's own clock and on the graph. No op carries a
time, so nothing depends on anyone else's clock, and a clock set back only
delays things. The periods are the defaults of `KeyPolicy`.

### When a lockbox cannot be opened

A sealer that was out of touch for longer than the retention seals to a reader
key its recipient has deleted. So does anyone, after a device has lost its
storage. The recipient then cannot read that epoch.

The recipient says so in the graph, with a `ReaderKey` op marked
`lost_previous`:

- a device whose storage no longer holds the reader key the graph shows for it
  publishes a new one, marked, at once;
- a device that still holds its key but cannot open the epoch being written
  under publishes one, marked, at most once an hour.

Every peer can then tell from the graph which epochs were sealed without
knowledge of that op, and a writer whose write epoch is one of them rotates on
its next write. So the conversation moves on to an epoch everyone can read. What
was written under the closed epoch stays closed to that device.

This is a rule for writers, not a validity rule: envelopes under such an epoch
remain valid.

### What a stolen key opens

Someone who has:

- the seed alone, and every op and envelope ever stored anywhere, can open only
  the lockboxes sealed to `kex_pk` (the join window, below);
- the seed and a copy of the device's database can open everything that device
  has read. The database holds the history and, in the stored keyring, the key
  of every epoch it opened; the keyring is not pruned. Beyond that, they can
  open only what is sealed to the reader keys still in it: about the last 7 + 30
  days' worth;
- a copy of the database without the seed can open nothing: the record is sealed
  under the seed;
- the device itself, unlocked and running, has everything that device can read.
  Nothing here protects against that.

### What reader keys do not give

The **join window** stays open to the seed. A member being added has published
no reader key in the space, so the `keyring` lockbox in its `Add` (every epoch
up to then) is sealed to its `kex_pk`, as is each rotation until a sealer has
seen its first `ReaderKey`. The same holds for a space's founder between
`Genesis` and its first `ReaderKey`, and after a member regains read access. The
seed alone therefore still opens what a member was given when it joined, and
what was written until the first rotation after its first reader key: with timed
rotation, at most about a day (30 hours) of an active conversation. Closing the
window would take signed prekeys in contact cards; that is not done.

The other limits:

- A device publishes reader keys only in spaces its user takes part in: ones it
  made, a contact's, and requests once accepted. An unanswered message request
  gets nothing signed back, so until it is accepted, what it holds is sealed to
  `kex_pk`.
- A content key is still per epoch, not per message: someone with an epoch key
  reads every message under it. The window of one stolen reader key is the
  epochs sealed while it was current or kept.
- Someone holding the seed can also sign as the device: publish a reader key of
  their own and be sealed to from then on, until the device is removed. Reader
  keys protect the past, not the future.
- The schedule adds one `ReaderKey` op (about 1.4 kB) per reader per space per
  week, and one rotation (1.2 kB per reader) per active space per day. Each op
  is also one more node in the graph every peer resolves ([§10], Scale).
- A Reader can publish `ReaderKey` ops without limit, and each one marked
  `lost_previous` costs the next writer a rotation: a lockbox per reader. A
  member that does this on purpose is stopped by removing it, as is one that
  floods the graph with rotations.
- The stored keyring is written in the background after each new epoch key. If
  that write is lost in a crash, the key is opened again from its lockbox at the
  next start, which works as long as the reader key is still held (30 days).

## 7. Content envelopes

Content travels in signed, encrypted **envelopes**. This section gives the
envelope format, the rules that decide whether an envelope is valid, the further
checks members make after decrypting, and how a document is built from the valid
envelopes. The validity rules need no key, so keepers enforce them too.

### Envelope format

A space holds two kinds of stream. The envelopes of a document carry Automerge
changes; the envelopes of a feed carry append-only entries.

```text
Header {
  space, stream: StreamId, author: SignPk,
  author_seq: u64, author_prev: Option<EnvelopeId>,   // per-author hash chain within the space
  auth_heads: [OpId],                                  // membership heads the author saw
  epoch: EpochId, nonce: [u8; 24],
}
StreamId   { kind: Doc | Feed, id: [u8; 16] }
Envelope   { header, ciphertext, sig: Ed25519(author, "mycel/v0/envelope" ‖ postcard(header) ‖ ciphertext) }
EnvelopeId = BLAKE3-derive_key("mycel/v0/envelope-id", postcard(Envelope))
ciphertext = XChaCha20-Poly1305(key = epoch key, nonce, aad = "mycel/v0/content" ‖ postcard(header), plaintext)
plaintext  = Automerge change bytes (Doc), or postcard(FeedEntry { deps: [EnvelopeId], ts_ms: u64, body }) (Feed)
```

An envelope is refused before it is stored if it belongs to another space, if
its ciphertext is larger than 1 MiB (`MAX_ENVELOPE_CIPHERTEXT`), if it lists
more than 64 `auth_heads` (`MAX_AUTH_HEADS`), if no known op has ever added its
author, or if its signature does not verify. Larger data travels as attachments
([§7b], [§7c]).

### Validity without decrypting

An envelope is valid if and only if:

1. the signature verifies against `header.author`;
2. every `auth_heads` op is known (otherwise the envelope is pending);
3. the author is a Writer or an Admin in `state(valid ∩ past(auth_heads))`;
4. the author is a recipient of `header.epoch` in that state;
5. cutoff rule: for every winning revocation `w` of the author that is not in
   `past(auth_heads)`, the envelope lies in the author's hash chain at or before
   `w.cutoff`. `cutoff` is the latest envelope from that member the revoker had
   seen; if the revoker had seen none, no such envelope is valid. This blocks a
   removed member from backdating `auth_heads` to keep writing;
6. the per-author chain is consistent: the author's first envelope has
   `author_seq` 0 and no `author_prev`, and every other one names as
   `author_prev` the author's envelope with `author_seq − 1` (while that one is
   missing, the envelope is pending). Forks (equivocation) after a cutoff are
   excluded by rule 5. Before a cutoff, a fork is accepted but flagged.

### Checks after decrypting

Only members hold the key, so only they make these checks. They apply to
document changes.

7. The Automerge change's actor ID must equal `header.author`. Authors cannot
   write under someone else's actor.
8. The change must be consistent with its declared history (its `deps` and their
   ancestors), never with whatever else a peer happens to hold:
   - its actor sequence number is exactly one more than that actor's latest
     change in that history;
   - its operation counters start above every counter in that history and fit in
     32 bits;
   - every actor in its actor table wrote something in that history;
   - every object, list or text element and predecessor that its operations name
     exists in that history, or earlier in the same change, with the right
     shape: objects are maps, lists or text, and elements are insertions into
     that same object.

   A change that fails is rejected for good. The check uses a per-document
   causal index (author, sequence, counter range and run-length operation
   summary per change, plus a sparse vector clock), so it costs the size of the
   change plus a logarithmic lookup per reference, with no replay.
9. The change must be within resource limits, checked before Automerge parses
   anything:
   - at most 16 MiB after decompression;
   - at most 1,048,576 operations;
   - a logical expansion of run-length and group-encoded columns of at most 64
     values (or string bytes) per byte of change body. The allowance is never
     below 4M values or 4 MiB of strings, because deleting a long run encodes in
     a few bytes, and never above 16M values or 16 MiB of strings.

   Writers stay far inside this. A local edit is written as changes of at most
   65,536 operations and 512 KiB each, so a multi-megabyte paste becomes several
   consecutive changes that every released version accepts.

A feed entry is decoded and passed to the application's rules, which see the
author's role in the same causal state as rule 3 ([RULES_ABI.md](RULES_ABI.md)).

### Materialisation

A document is the valid, decryptable changes, applied in causal order. A change
waits, still encrypted, until its dependencies are applied. Validated changes
reach Automerge in batches.

Equivocation, two changes for one actor sequence number, is resolved by the
lowest envelope ID, on every peer. If a lower-ID fork displaces a change that
was already applied, the document is re-derived once per received batch, however
many forks the batch carries.

If a newly arrived revocation invalidates envelopes that were already applied,
the peer rebuilds the document from its envelope store. Other membership changes
touch only the envelopes whose validity or decryptability changed.

Every peer holding the same graph and envelopes arrives at the same document.

## 7b. Blob attachments (older format)

This is the format of attachments sent before chunked files ([§7c]). It is no
longer produced. These attachments still download and open, and their blobs are
still served.

An attachment in this format is a **blob**: immutable bytes, content-addressed
by `BlobId = BLAKE3-derive_key("mycel/v0/blob", sealed bytes)`. The chat
message, an encrypted feed entry ([§7]), carries an
`AttachmentRef { blob, key, nonce, name, mime, size }`. So the per-attachment
key travels end-to-end encrypted, and the signed message pins the exact
ciphertext by hash.

### Blob encryption

Each attachment has its own random 256-bit `key` and 192-bit `nonce`. The
plaintext is sealed with the STREAM construction (Hoang, Reyhanitabar, Rogaway,
Vizár) over XChaCha20-Poly1305:

```text
blob     = "MYCELBLOB1\0" ‖ chunk_size: u32 LE ‖ C_0 ‖ … ‖ C_n            (n ≥ 0, chunk_size = 1 MiB)
C_i      = XChaCha20-Poly1305(key, nonce_i, aad_i, P_i)                   (|P_i| = chunk_size for i < n, 0..=chunk_size for i = n)
nonce_i  = nonce with its last 8 bytes XORed with i (u64 LE)
aad_i    = "mycel/v0/stream-chunk" ‖ len(A): u32 LE ‖ A ‖ chunk_size: u32 LE ‖ i: u64 LE ‖ final: u8     (A = "mycel/v0/attachment")
```

- The final flag and the index are authenticated, so chunks cannot be dropped,
  reordered, duplicated, truncated at a chunk boundary or extended. An empty
  file is one empty final chunk.
- The header's chunk size is bound into every chunk's AAD. A reader refuses a
  chunk size of 0 or above 16 MiB.
- Opening holds one chunk in memory, plus I/O buffers, whatever the file size.
- Attachments from the earliest versions used one-shot
  `XChaCha20-Poly1305(key, nonce, A, plaintext)`. A blob without the magic
  prefix is opened that way, and only if it is at most 64 MiB, so a hostile
  reference cannot make a peer read a huge blob into memory.

The code is `crates/mycel-crypto/src/stream.rs`.

### Blob transfer

Blobs are stored per space (`blobs/<space>/<blob>`) and served only to the
space's members, on streams of kind `Blob` ([§8]). They are streamed between
QUIC and disk into `<blob>.part`, in disjoint ranges from every member that has
the blob.

The receiver checks the BLAKE3 hash of the whole blob before renaming it into
place, so a peer cannot substitute data. An interrupted transfer resumes from
the `.part`, possibly from a different member. The final hash check covers the
prefix too, and a bad prefix is discarded and fetched again.

### Push rules and disk use

There is no size limit and no per-space quota. These rules also govern pushes of
chunked files for a conversation ([§7c]):

- A push is taken only from a member of the space, and only where the app has
  given its consent for that conversation ([§9b]).
- A file of up to 16 MiB is pushed to every member as soon as it is posted. A
  bigger one is pushed only to keepers, and members fetch it when their user
  asks for it, from anyone in the space who has it.
- Receivers enforce this. A personal device refuses an unsolicited push above 16
  MiB, so a member cannot fill another's disk with large files they never
  opened. Keepers accept any size.
- Every transfer is refused if it would leave less than 1 GiB of free disk
  space.

## 7c. Chunked files

New attachments are **chunked files**: a tree of small, separately sealed nodes,
each named by the hash of its ciphertext, kept in one store for the whole
device. Any device can hold and serve a node it cannot read, and a receiver
checks every node as it arrives. This section gives the node format, the two
sealing modes, and the rules for storing, fetching, pushing and holding nodes.

### Node format

The format is in `crates/mycel-crypto/src/chunked.rs`.

```text
leaf   = XChaCha20-Poly1305(key, N(key), "mycel/v0/chunk-leaf", piece of the plaintext)
index  = "MYCELINDEX1\0" ‖ level: u8 ‖ count: u32 LE ‖ count × (child id: 32 ‖ child length: u32 LE)
         ‖ XChaCha20-Poly1305(key, N(key), "mycel/v0/chunk-index" ‖ H(all of the above),
                                   count × child key: 32 ‖ hint count: u8 ‖ hints × 32)
id     = BLAKE3-derive_key("mycel/v0/chunk", node bytes)
N(key) = first 24 bytes of BLAKE3-derive_key("mycel/v0/chunk-nonce", key)
H      = BLAKE3-derive_key("mycel/v0/chunk-index-header", ·)
```

- An index at level 1 lists leaves; an index at a higher level lists indexes of
  the level below. An index has at most 8,192 children and a tree at most 4
  levels. A full index is only closed when another child arrives, so the same
  pieces always give the same tree.
- A node's key is derived from that node's content (see the modes below), so no
  key ever seals two different nodes. The nonce is derived from the key and
  stored nowhere: the same key and nonce can only seal the same bytes again.
- The child IDs and lengths are in the clear; the child keys are sealed. So a
  keeper or a cache can tell which nodes make up a file and whether it has them
  all, with no key, and only someone with the root key can open anything.

### The reference in a message

The message's `AttachmentRef` keeps its shape ([§7b]), so older messages and the
chat rules are unchanged. `blob` is the root node's ID, `key` opens the root,
and `nonce` holds the marker `MYCELCHUNKED1\0`, one flag byte (bit 0: public)
and zeros instead of a nonce. A reference whose `nonce` does not start with the
marker is a blob of [§7b].

### What a reader checks

A reader checks each node against its ID before using it, each index's level
against its place in the tree, and every length against the format's limits. It
stops rather than write more plaintext than the message's `size`. A leaf never
opens as an index or the other way round, because their associated data differ.

Before fetching, a tree that lists more nodes or bytes than a file of that
`size` can have is refused, so a small reference cannot unfold into a huge
download.

### Private and public files

The sender chooses one of two modes for each file.

**Private** is the default. Every key is derived from a fresh random secret, the
node's position and the node's content:
`BLAKE3-derive_key("mycel/v0/chunk-key", secret ‖ level ‖ ordinal ‖ c)`. `level`
is one byte (0 for a leaf), `ordinal` is the node's number at its level (`u64`
LE), and `c` is what the node's key would be in a public file.

- The secret makes the keys unguessable, and the content keeps each key to one
  node, whatever a caller does with the secret.
- The same file sent twice shares no node, and a repeated piece inside one file
  seals to different nodes.
- Pieces are a fixed 1 MiB. Cutting by content would let the piece lengths
  fingerprint the file to whoever stores it, and gains nothing when nothing is
  shared.

**Public** is opt-in (`send_message`'s `publicAttachments`). Every key is
derived from the node's own content, which is convergent encryption: for a leaf,
`BLAKE3-derive_key("mycel/v0/chunk-convergent-leaf", piece)`; for an index, the
same with `mycel/v0/chunk-convergent-index` over its child list and child keys.

- The plaintext is cut where its content says: a gear rolling hash (a fixed
  256-entry table derived with BLAKE3), pieces of 256 KiB to 4 MiB, about 1 MiB
  on average.
- The same bytes give the same nodes and the same reference on every device. A
  public file is therefore stored once per device and sent only to devices that
  lack it, whoever sends it and in whichever conversation.
- Two public files with a long stretch in common share that stretch's pieces.

The price of a public file is that anyone who has the file can compute its IDs.
They can check whether a device holds it, find devices that announced it, and so
tell that two people have the same file. Someone who knows most of a file can
test guesses for the rest. **Do not send as public what you would not want
confirmed.**

Forwarding an attachment reuses its reference and its nodes, in either mode. The
runtime does so when the path it is given is this device's own copy of a chunked
attachment and still decrypts to the same bytes; an edited copy is sealed as a
new file. The file is then kept for the other conversation too, and only devices
that lack it are sent anything.

### The chunk store

One store, `blobs/.chunks/`, serves all conversations
(`crates/mycel-net/src/chunks/store.rs`). Nothing is stored unless its bytes
hash to its ID. A node in it is either pinned or cached.

**Pinned** nodes belong to a file that one of this device's conversations refers
to: sent, downloaded, or pushed by a member. On a keeper they belong to a file
pushed for a conversation it keeps. They are never evicted while that holds, and
count against no budget.

**Cached** nodes are held for others inside a donated budget: 1 GiB unless
`MYCEL_FILE_CACHE_MB` says otherwise (0 holds nothing; see
[CONFIGURATION.md](CONFIGURATION.md)).

- When room is needed, the least requested nodes go first. Nothing is dropped
  because of its age, only to make room.
- A request by another device adds one to a node's score, unless that device was
  also the last to ask, within the hour. Scores halve every week.
- A contact's file may displace the least requested nodes, but none that two or
  more devices asked for within the last week.
- Devices that are not contacts get free room only: a quarter of the budget
  together and a sixteenth each.
- A blocked device gets nothing.

The cache is apart from conversations, like the store-and-forward store ([§8c]).
A device whose message request is still pending, or was declined without
blocking it, can use the cache as any other stranger can. Pushes for a
conversation still need the app's consent.

Every transfer keeps 1 GiB of disk free, as for blobs.

### Fetching, serving and pushing nodes

Nodes move on streams of kind `Chunk` ([§8]); the code is
`crates/mycel-net/src/chunks/`.

A node is fetched by ID, from the conversation's members first, all at once. A
source that sends bytes that are not the node is dropped on the spot and the
node is asked of someone else; nothing wrong is stored. A download picks up
where it stopped: the nodes already here are not fetched again.

A node is served to anyone who asks for it by ID. It is ciphertext, and its ID
is known only to those who have the reference or, for a public file, the file.
Devices that share a conversation with this one are served freely. All others
are served at 1 MiB/s each and 4 MiB/s together (bursts of 16 s' worth), and are
told to come back beyond that.

A push needs an accepted offer naming the file and its size, and no more than
that is taken. A device may have 16 offers open. Only nodes the receiver lacks
are sent.

- For a conversation, the rules are those of [§7b]: membership, the app's
  consent, keepers any size, other devices up to 16 MiB. The file is pinned when
  its root arrives and is an index. After that only nodes the file's own indexes
  list are taken, so an offer alone leaves nothing behind and a push cannot be
  used to store unrelated bytes.
- For the cache, the budget rules above apply. The room is promised when the
  offer is accepted, for as long as the nodes keep coming (10 minutes between
  them at most).

### When a member cannot be reached

When a push to a member failed, or the file is too big to push and the member is
not around, the sender also hands the file to devices willing to hold it, until
2 devices besides itself have it. It asks the devices the app names, then its
contacts, then devices nearby on a fast link (those around first, up to 8 asked
per try). It never does this over Bluetooth, a low-power radio or the mesh. It
tries again 30 seconds and 5 minutes later while the app runs.

A device that takes a whole file into its cache says so under an ID derived from
the root. With the internet it does so as a signed peer on the Mainline DHT,
joined only when first needed; it never does so in the local modes.

A member who finds nobody of the conversation with the file then asks, together:
the devices the root names, the devices that announced it, and devices nearby on
a fast link. A private root can name up to 8 devices, sealed. Messaging names
none, since that would show a conversation which devices its sender knows.

### What a holder and an observer learn

- A keeper or a cache learns the node IDs and sizes, which nodes make up a file
  and so its size, who pushed it, who asks for it and when. It does not learn
  the content, the name or the type.
- For a public file, anyone who has the file can also tell what a holder holds
  (above).
- The lookup uses the one DHT node the device already runs for its records, and
  is off when the DHT is (`MYCEL_DHT=0`). The DHT nodes near a file's ID see the
  device key and IP address of whoever announces or asks. The ID is derived from
  the root and is not the root, so it fetches nothing.

### Limits of chunked files

- A file is not guaranteed to last. It lasts while some device has all its
  nodes: pinned, for as long as a member or a keeper keeps the conversation;
  cached, for as long as it is asked for more than what competes with it for the
  holder's budget. A file many people use is held by many devices and keeps
  being asked for, so it is very likely to stay; nothing enforces it. To be
  sure, keep it in a conversation with a keeper.
- Popularity can be faked. A device with several keys can inflate a node's score
  on a holder: only an immediate repeat by the same key is ignored. It costs the
  holder nothing beyond its budget.
- Holders make no commitment. A cache may drop a file at any time, and there is
  no proof of storage: a holder that announces a file it does not have is found
  out only when its nodes are asked for.
- Bluetooth is too slow for files. At about 30 kB/s a gigabyte takes nine hours
  of contact, so files are not placed with holders over Bluetooth or the mesh,
  and store-and-forward bundles ([§8c]) still carry messages only. A file
  reaches a member who was away through a holder that member can later reach:
  over the internet, or by being near it on a fast link.
- Nothing is fetched automatically. A file is downloaded when its recipient
  opens it. Files up to 16 MiB are still pushed to members who can be reached.
- Placing a file with holders is not resumed after the sender's app restarts,
  and only the sender does it, not the other members who have the file.
- A conversation's files are not released yet. Leaving a conversation, or
  deleting a message, does not unpin its files, as blobs were never deleted. The
  store can release them; the app does not ask it to.
- Signed peers are stored only by DHT nodes that run the same library's
  extension, far fewer than the DHT has. The lookup has run against a local DHT
  in tests, never the public one.
- As in [§7b], a member can still fill other members' and keepers' disks with
  repeated valid pushes.

## 8. Transport rules

Devices talk over QUIC connections made by Iroh, which authenticates each end by
its device key. This section states what a device accepts on those connections.
The rule under all of them: everything received is validated by the receiver,
and nothing is trusted because of who sent it.

### The `mycel/2` protocol

One connection per pair of devices carries everything, under the ALPN `mycel/2`.
Sync sessions, contact cards, ephemeral messages, blob requests and chunk
requests are QUIC streams on it, each labelled by a stream-kind byte. Iroh
authenticates the remote node ID, which equals the remote `sign_pk`. The
handshake is TLS 1.3 with X25519 ([§10]).

- Membership gate. A responder serves a space only to its current members,
  keepers included. Requests from non-members are refused. A device that was
  removed is sent the revocation and its causal past, and nothing else.
- Sync order. Membership ops come first, then envelopes, as a set difference
  over full ID inventories.
- Invitations. A member pushes a space to a device that does not hold it by
  sending every membership op it holds. The receiver takes it only if it has at
  most 4,096 ops (`MAX_INVITE_OPS`), the ops prove that both the receiver and
  the sender are members, the receiver's role is acceptable (a personal device
  refuses the `Relay` role), and the app's policy accepts it ([§9b], message
  requests).
- Contact cards. Anyone may ask a device for its card, which is public and
  self-signed ([§3]).
- Ephemeral messages, such as typing and presence, are sealed under the space's
  write epoch with `aad = "mycel/v0/ephemeral" ‖ space ‖ sender SignPk`. They
  are not signed: the sender is the authenticated QUIC peer, and a message is
  taken only from a member of the space.

### The `mycel/mesh/1` protocol

Hop connections between nearby devices, for multi-hop relaying, use the ALPN
`mycel/mesh/1` ([ARCHITECTURE.md](ARCHITECTURE.md)). They are accepted from
anyone nearby: relaying needs no membership. What crosses a relay is the QUIC
traffic of a connection between two other devices, so the rules above still
apply end to end ([§8b]).

## 8b. Mesh relays

A mesh relay forwards the QUIC packets of a connection between two other
devices. This section says what such a relay cannot do, what it learns, what a
malicious one can do, and how its load is bounded.

### What a relay cannot do

A relay cannot:

- read the packets: they are encrypted end to end (QUIC with TLS 1.3, keyed to
  the two devices);
- change or inject packets: they are protected by an AEAD, so the receiver's
  QUIC drops altered packets;
- impersonate either end: the connection authenticates the remote device key;
- forge routes to someone else: each announcement is signed by its origin's
  device key. One with a bad signature, or one more than 10 minutes from the
  receiver's clock, is rejected;
- make a device join anything: relaying needs no membership, and a relay is
  given none.

### What a relay learns

A relay learns metadata:

- Who talks to whom. Each mesh frame's header carries the source and destination
  device keys and the waypoint, in clear to each relay. Hops are themselves QUIC
  connections, so headers are hidden from radio eavesdroppers who are not Mycel
  devices on the path.
- When, how often and how much. Packet sizes and timing reveal activity
  patterns: a call is a steady 50 packets/s, a file is a burst.
- Who is around. An announcement carries its origin's device key and display
  name, the same name already shown over Bluetooth, peer-to-peer Wi-Fi and the
  LAN. It travels 2 hops in most periods and up to 10 hops in every 8th, and
  every device in that range receives it.

### What a malicious relay can do

It can drop or delay traffic, which is denial of service. Two things limit the
damage:

- a device keeps up to 3 routes per destination, through distinct neighbours, as
  separate QUIC paths, so traffic moves to the others when one goes dark (a dead
  path is noticed in about 3 s);
- direct paths are always preferred.

It can claim a low cost to attract traffic and then drop it (a black hole).
Costs are not signed, because each hop adds its own.

- A claim no honest relay can make (a relayed route with no hops, or a cost
  under the least each hop adds) gets the neighbour distrusted for 10 minutes.
  The routes it gave go, the routes it relays are ignored, and it stays
  reachable itself.
- A plausible lie (one hop from everyone, at the least cost) cannot be refuted
  from announcements, but the destination's acknowledgements do not come back
  through it. After two timeouts in a row with nothing acknowledged, a source
  prefers another route to that destination for 2 minutes, and its bundles send
  only one share of their copies down the route that failed.
- In the node, the evidence is what QUIC authenticated on each mesh path: frames
  from packets it decrypted. A relay can drop that evidence but not fake it. A
  suspected hop's route stops being offered as a path for that destination.
- Detection costs the traffic lost to two silences (about 6 s with real nodes),
  and only the ends of a connection learn of it.

Signed per-hop route attestations, planned for the next protocol version, would
stop the lie itself. [ROUTING.md](ROUTING.md) describes both defences.

It can replay old announcements of a device that left, within the 10-minute
window, keeping a dead route alive. That costs only failed attempts.

### Load and abuse limits

- Relaying for others is capped per neighbour (1 MiB/s) and in total (4 MiB/s).
- Announcements are capped at 100 per second per neighbour.
- Frames have a TTL and are never sent back where they came from.
- Reassembly buffers are bounded.
- `MYCEL_MESH_RELAY=0` forwards no live traffic for others. It does not stop
  the device accepting and carrying store-and-forward bundles. `MYCEL_MESH=0`
  turns the mesh off ([CONFIGURATION.md](CONFIGURATION.md)).

### Limits of mesh relaying

- There is no onion routing or padding: relays see endpoints, sizes and timing.
  Hiding who talks to whom would need onion-style layered encryption and cover
  traffic, at a large bandwidth cost on Bluetooth.
- Sybil devices nearby can each be a neighbour. Each is rate-limited separately;
  the radio's range is the practical bound.

## 8c. Gateways, records and carriers

Beyond radio range, devices find each other through signed reachability records
and reach each other through gateways, device relays and store-and-forward
carriers. This section says what each of those can and cannot do. In every case
the traffic they carry stays end-to-end encrypted.

### Records

A reachability record says how to reach a device D: the addresses to dial, and
the gateways or relays that carry traffic to it ("D is reached via G1, G2"). It
is a pkarr packet signed by D's own key
(`crates/mycel-net/src/mesh/directory.rs`).

- Nobody else can publish a record for D. A gateway publishes only records that
  name it and that it can verify, at most one per origin per 10 s, for at most
  1,024 origins.
- Records expire after 30 minutes, and the newest by timestamp wins.
- The relay flag and the relays named are inside the signature. A record naming
  relays that never agreed costs the lookups a failed path.
- A record gives IP addresses only while its device is public: it relays for
  others, or it is reachable and uses no relay server. A device behind a router
  publishes none.
- Publishing many records for many keys would require many keys. Each record
  costs a signature, and gateways cap what they publish. The directories, the
  Mainline DHT and n0's DNS server, apply their own limits.
- Lookups cannot be forged, because records are signed. They can only be
  withheld, and the DHT and n0's server are independent of each other.

### Attacks and mitigations

#### Black-hole gateway

A gateway, or a relay on the way to it, accepts traffic and drops it.

- A device publishes 2 gateways through distinct first hops where it can, each a
  separate QUIC path, so traffic continues on the other.
- A sender keeps every gateway the record names as its own path.
- Store-and-forward bundles wait for a receipt and are carried by several
  copies.

What remains: a device with a single gateway in range depends on it.

#### Sybil gateways

Many fake devices near D announce themselves as gateways with a low uplink cost,
to be chosen.

- Each must be a real radio neighbour, rate-limited separately.
- The uplink cost is signed by the gateway: it can lie, but only about itself.
- The traffic stays end-to-end encrypted.

What remains: gateways are chosen by their announced cost, which a gateway can
misstate about itself. Once a connection runs, the multipath selector ranks its
paths by measured RTT, throughput and loss.

#### Eclipse

All of D's neighbours are hostile. They can drop everything and publish nothing
for D.

There is no mitigation at the routing layer: this is the radio-range equivalent
of being on a hostile Wi-Fi. D can detect it, because it sees no receipts and no
live connections. Content is still never readable or forgeable.

#### Open proxy

A gateway never looks up or dials anyone for traffic that came from the
internet. It passes traffic between two internet hops only when one end asked it
to be its relay (below). So nobody can bounce traffic through it.

Traffic crossing between the mesh and the internet has its own cap, 2 MiB/s per
gateway, on top of the per-neighbour and total relay caps.

### Device relays

A device the internet can reach relays between two internet hops for devices
that asked. A device behind a router names its relays in its own record
(`crates/mycel-net/src/mesh/relay.rs`).

- A device relay cannot read, change or forge what it carries, or impersonate
  either end. As for mesh relays ([§8b]), it forwards the QUIC packets of a
  connection between two other devices.
- It learns the client's IP address (it is connected to it), who reaches the
  client through it, sizes and timing.
- A device asks 2 relays, among devices it already knows and the relays those
  devices name in their records. So a contact can point it at a relay of the
  contact's choosing; that relay is still asked only if its own signed record
  says it relays.
- Asking is authenticated. A request to relay counts only if it arrives straight
  from the asking device on its own hop connection, where QUIC authenticates the
  device key. A frame that merely claims a source is ignored. So nobody can
  enrol someone else as a client, or make a relay carry traffic between two
  devices of their choosing.
- A device that claims to relay and does not, or drops what it carries, costs
  its clients a path. A client gives up on a relay that does not answer within
  10 s or cannot be connected to within 30 s, for 10 minutes, and takes another
  candidate. With 2 relays the other path carries on.
- A relay tells the client the address it sees it at. One that lies makes the
  client offer a wrong address for direct paths. Dials to it fail; the relayed
  path is unaffected. One address is kept, from the relays chosen.
- A relay is itself exposed. Its record gives its IP address to anyone who knows
  its key, and anyone who knows its key can ask it to relay, within the limits
  of [§8d]: strangers can fill the places but cannot keep out the devices the
  relay knows. `MYCEL_INTERNET_RELAY=0` turns the role off.

What remains: there is no anonymity, since relays see endpoints and timing.
Relays are not chosen for trustworthiness beyond being devices the client
already knows. A hostile contact that relays can watch a client's traffic
patterns and drop its incoming connections on that path.

### Store-and-forward carriers

Carriers hold **bundles**: already-signed, already-encrypted envelopes for a
destination key.

- They learn the destination key, the source key, sizes, and when bundles were
  created and moved.
- They cannot read a bundle. They cannot alter one: the source signs the bundle,
  and the envelopes inside are signed. They cannot fake delivery: receipts are
  signed by the destination.
- A destination applies a bundle only if its source is a member of the space it
  is for.
- Abuse is limited by a 64 MiB store, 256 KiB bundles, 4 MiB per source,
  lifetimes of up to 7 days, and per-neighbour rate limits. A bundle is never
  sent back to the device that gave it.
- Receipts are tiny and public. They reveal that D received something from S,
  which is the same metadata the bundle already showed carriers.

## 8d. Resource limits

Everything a peer sends is bounded before it can cost much. Limits give
backpressure, not resets: a peer over a limit waits, so a long sync over
Bluetooth still completes. The code is in `crates/mycel-net/src/resources.rs`
and `link.rs`, `crates/mycel-sync` and `crates/mycel-node`.

### Streams and frame memory

QUIC allows each connection 64 bidirectional and 128 unidirectional streams at
once. A peer that opens more waits for one to end; nothing is reset.

Frame memory is the encoded bytes a peer can make a device hold. The largest
frame is 64 MiB. Each kind of peer draws on its own pool:

| Peers | Pool | Share of each peer |
|---|---|---|
| Devices that share a space with this one | 128 MiB | 32 MiB |
| Devices that share nothing with it | 32 MiB | 8 MiB |
| Mesh neighbours | 32 MiB | 4 MiB |

- The separate pool for devices that share nothing means a crowd of new keys
  cannot push out the people a device talks to.
- A frame larger than its sender's share takes the whole share. Devices that
  share nothing with this one may send frames of at most 8 MiB, and mesh
  neighbours of at most 16 MiB.
- A pool is charged only as bytes arrive, so a slow peer delays only its own
  frames.
- After a 60-second grace, a frame must average 512 B/s to keep its memory.
- A frame that finds its pool full waits up to 10 s for room and is then
  dropped.
- Frames a device sends are charged to nobody.

### Deadlines

- A stream a peer opens must start its first frame within 10 s.
- A reply may take 60 s to start, plus the time the asker's own queued bytes
  need to drain.
- Bytes under way may stall for at most 30 s.

No exchange has a fixed total deadline.

### Content

- Sync responses are deduplicated and their encoded size measured before any
  ciphertext is copied.
- Ephemeral messages (typing, presence) are at most 64 KiB of plaintext, checked
  before decryption.
- Envelopes are at most 1 MiB of ciphertext, with at most 64 `auth_heads`
  ([§7]).
- Document changes have the limits of [§7] rule 9, checked before Automerge
  parses anything. Writers split large edits so that every reader accepts them.
- Membership has the pending-op caps of [§5] (4,096 in total, 256 per author),
  64 parents per op, 1,024 lockboxes per rotation ([§4]) and 4,096 ops per
  invitation ([§8]).

### Message requests

Contacts are always admitted and do not count. A stranger can have at most 32
pending requests. When strangers fill all 256 slots, the oldest request from the
inviter with the most pending is declined, so a flood displaces its own requests
first.

### Attachments

The limits are those of [§7b] and [§7c]. Concurrent transfers reserve disk space
from one shared account, so they cannot each count the same free space.

### Relaying over the internet

A device relay ([§8c]) carries 2 MiB/s between internet hops, on top of the mesh
relay caps ([§8b]), for at most 256 clients. When strangers fill all 256 places,
a device the relay knows (a contact, someone in its chats) takes the place of
the stranger that asked longest ago; a stranger is refused. A client that stops
asking is forgotten after 3 minutes.

## 9. Code and tests

This section maps the specification to the code, says what the security tests
cover, and records the state of dependency advisories. [TESTING.md](TESTING.md)
covers the rest of the test suite.

| Sections | Code | Tests |
|---|---|---|
| [§2], [§3] and the formats of [§7b], [§7c] | `crates/mycel-crypto` | in `lib.rs`, `stream.rs`, `chunked.rs` |
| [§3] to [§6]: graph, resolution, epochs | `crates/mycel-trust` (`resolve.rs` is [§5]) | `tests.rs`, `reader_tests.rs` |
| [§6] key schedule, [§7] envelopes | `crates/mycel-sync` (`keys.rs` is the key schedule) | `tests.rs`, `keys_tests.rs` |
| [§7b] to [§8d]: files, transport, mesh, limits | `crates/mycel-net`, `crates/mycel-node` | in the modules, and each crate's `tests/` |

### What the tests cover

`crates/mycel-crypto`:

- domain separation, framing, kex binding, lockbox `info` binding, AEAD
  tampering;
- the hybrid lockbox: sizes, tampering in either KEM part and in the ciphertext,
  a pinned key derivation, the X25519 keys and lockboxes of earlier builds
  refused;
- reader keys not derived from the seed, and sealed device storage;
- the streaming attachment AEAD ([§7b]): round trips at chunk boundaries (0, 1,
  chunk − 1, chunk, chunk + 1, many chunks), tampering, wrong key, nonce or AAD,
  truncation, extension, reordering, duplication, chunk-size changes, legacy
  detection, incremental digest;
- chunked files ([§7c]): the chunker's cut points on a known input, sizes and
  boundaries, both modes, tree shapes, tampering, wrong keys, swapped and
  missing nodes, index parsing, hints.

`crates/mycel-trust`:

- reader keys (`reader_tests.rs`): sealing moves to a published reader key, a
  deleted key closes its lockboxes while a kept keyring stays whole, concurrent
  reader keys and rotations converge in every delivery order, who may publish
  one, malformed keys, the join window, epochs closed by a lost key;
- membership: forged admin ops, pending ops, removal and rotation, concurrent
  revocation, mutual removal (seniority), delivery-order convergence, rotation
  recipient checks, bad key commitment, last admin, self-healing rotation,
  leave, epoch-ID reuse, ops from never-added keys;
- bounds: fan-outs of invalid ops, wide valid frontiers, pending-pool limits and
  ready admin ops.

`crates/mycel-sync`:

- the key schedule (`keys_tests.rs`): nothing published until the schedule is
  on, reader keys replaced weekly and deleted after 30 running days, stored
  before published, sealed secrets bound to device and space, restarts with and
  without them, an attacker with the seed and a keeper's data, timed rotation
  and its jitter, concurrent rotations, a sealer behind inside and past the
  retention, downtime, a clock set back, lost storage, keepers, restoring stored
  ops in any order;
- envelopes: replication, reader writes rejected, keeper cannot read, outsider
  and tampered envelopes, forged actor, backdated writes after removal, 3-way
  convergence, demotion, feed causal order, restore from storage, equivocation;
- changes: decompression and expansion bombs, malformed and deferred changes,
  declared-history checks (actor, counters, object references), delivery-order
  and restore consistency.

`crates/mycel-net` and `crates/mycel-node`:

- end to end over real Iroh QUIC with five nodes (admin, writer, reader, keeper,
  outsider);
- forged, renamed and replayed mesh announcements, and signed-field cache
  mutation;
- stream and frame budgets, stalled and progressing I/O, duplicate requests,
  invitation validation order, ephemeral limits;
- attachment consent and disk reservations across restarts;
- the chunk store (`crates/mycel-net/src/chunks/`): pinning, eviction order,
  ageing, shares, reservations, restart;
- the chunk protocol: a source that lies, a tree larger than its message says,
  pushes without or beyond an offer;
- chunk transfer (`crates/mycel-net/tests/chunks.rs`): push policy, resume,
  several sources, a file fetched from a stranger's cache after its sender left,
  budgets, one copy of a public file;
- in `crates/mycel-node`: new attachments are chunked, old ones still open,
  contacts and blocked devices.

### Running the checks

`scripts/security-check.sh` runs these security tests without retries, then the
web checks, `npm audit` and the RustSec advisories through cargo-deny
(`cargo deny check advisories`, the policy in `deny.toml`). CI runs the same
checks on every pull request, and the Audit workflow runs them daily against new
advisories.

### Dependency advisories

Vulnerabilities always fail. So do unmaintained and unsound crates, unless
`deny.toml` accepts one by ID with the reason Mycel is not exposed and a review
date. `.cargo/audit.toml` mirrors the list for
`cargo audit --deny unsound --deny unmaintained`.

As of 2026-11-17 `deny.toml` accepts the following, each on one platform or at
build time only:

- RUSTSEC-2024-0429, unsound `glib::VariantStrIter` in glib 0.18, which comes
  with Tauri's GTK 3 webview: no Tauri release is on gtk-rs 0.19 yet, and
  nothing in this repository or between it and glib calls that API;
- RUSTSEC-2026-0370/0371/0372, `zvariant`, `zbus_names` and `zvariant_derive`
  "unmaintained" since zbus 6 absorbed them; zbus 5 still comes with Tauri's
  notification and opener plugins;
- RUSTSEC-2024-0370 and RUSTSEC-2024-0436, the `proc-macro-error` and `paste`
  proc macros, which never run in a shipped binary;
- RUSTSEC-2026-0543, `chrono` "unmaintained": on Windows only, where it comes
  with `wmi`, which Iroh's network monitor uses. Neither has a release without
  it, and nothing in this repository uses it.

The lockfile is past these advisories, with no vendored code changed:

- `zip` 9.0.5, for RUSTSEC-2026-0367/0368/0369: extraction flaws. Mycel only
  writes archives, when it zips a shared folder.
- `rustls-webpki` 0.103.16, and `webpki-roots` and `webpki-root-certs` 1.0.10,
  for RUSTSEC-2026-0382/0381/0383: emSign intermediates whose private keys are
  public could anchor a TLS chain. These crates sit on the relay and HTTPS
  client paths through Iroh, reqwest and Tauri.
- `ctutils` 0.4.8, for RUSTSEC-2026-0385: constant-time helpers that could
  compile to a branch on a secret value. The RustCrypto hashes and Iroh use
  them.
- `rustix` 1.1.6, for RUSTSEC-2026-0486: unsound extended-attribute reads into
  an empty buffer.
- `async-executor` 1.14.1: its authors withdrew 1.14.0.

## 9b. Hardening

This table lists the attacks and failures that internal adversarial reviews
raised, and what the code does about each. Every row has a regression test.

| Area | Attack or failure | What the code does |
|---|---|---|
| Attachment names | A peer-chosen file name that escapes the download folder | Names are cut to a safe basename inside `files/`, the only folder the app opens files from. macOS downloads carry the quarantine flag. |
| Strangers | A conversation pushed by anyone on the LAN, under an impersonated name | An invite from a non-contact is a message request: nothing is trusted, posted or stored until the user accepts. Decline and Block exist, and blocked keys are refused at the network layer. |
| Keeper invites | A personal device invited as a keeper, to use its disk | Personal devices refuse invites to the `Relay` role. |
| Attachment consent | Files pushed by a stranger whose request is still pending, on the strength of the membership it granted | Consent is stored before the invite is admitted and survives restarts. Pending and hidden requests cannot push files or be downloaded from. |
| Pre-authentication work | Junk ops and envelopes from unknown keys, costing CPU and memory | Ops and envelopes from never-added keys are dropped before storage. Parents, `auth_heads`, invites and lockboxes are capped, and state caches are bounded. |
| Revocation | A fan-out of invalid ops, or a flood of ops with missing parents, to stop an admin removing a member | Authoring uses the frontier of valid ops. The pending pool is capped per author, and ready ops bypass it ([§5]). |
| Epoch IDs | An epoch ID reused with a different key, to break convergence | `EpochId` is derived from the commitment and checked structurally. Each key is checked against its own op's commitment ([§4]). |
| Equivocation | Two changes for one Automerge (actor, seq), to make documents diverge | The lowest envelope ID wins on every peer. |
| Equivocation | Stale exclusions left by a revocation | Exclusions are recomputed from the currently valid changes, so live and restored replicas agree. |
| Change parsing | A malformed change that crashes every member, again after each restart | Parser and apply panics are contained. Changes apply to a candidate document first, and changes waiting for dependencies stay outside Automerge. |
| Change parsing | A small compressed change that expands without limit | Decompression and logical expansion are bounded before parsing ([§7] rule 9). |
| Change acceptance | Acceptance of a change that depends on unrelated local history or arrival order | Changes are checked against their declared dependency history only ([§7] rule 8). |
| Mesh announcements | Altered signed fields that reuse a signature check cached by origin and sequence | The cache keys on a digest of every signed field and the signature. Only the hop count and cost added on the way may change. |
| Network resources | Unbounded stream tasks; memory allocated up front for a declared 64 MiB frame; no inbound deadlines; repeated IDs in a sync request multiplying copies | The limits of [§8d]. |
| Crashes | An overflow panic that poisons a global lock, so the app crash-loops | Arithmetic is checked, and locks cannot be poisoned. |
| Leaving | Posts with backdated heads from a member who has left | `Leave` carries a cutoff and counts as a revocation. |
| Disk use | Blobs not scoped to a space | Blobs are stored per space ([§7b]). |
| Disk use | Partial files left by failed pushes | Pushes stage to disposable files that are removed on failure. |
| Disk use | Concurrent transfers counting the same free space | Transfers reserve space from one account ([§8d]). |
| Identity | A failed read that silently creates a new identity | Reads fail closed and the profile is locked. |
| Identity | On iOS, the key kept as a plain file | iOS keeps the key in a device-only Keychain item, moved there only after it is safely stored, with no plaintext fallback. |
| Storage | A save reported as done before an earlier batch is written; failed batches dropped | Commits are ordered and failures retried. |
| Storage | A damaged setting silently reset | Damaged records are set aside, not deleted, and the user is told (`Notice`). An unreadable network setting becomes Local only, never wider. |
| Notifications | Names, message text and file names in OS notifications | Notifications say only what happened. |
| Logs | File paths in logs | Logs are private to the user on Unix, attachment errors are redacted, and Bluetooth diagnostics are opt-in. |
| Local HTTP API (`mycel serve`) | Calls from any local page | Every route needs a per-run secret token (embedded in the page; a `0600` file for the CLI). Only a loopback `Host` is accepted, file serving is limited to attachment folders, and the browser sends attachments only as uploads. |

## 10. Limitations

This section lists what the layer does not do. Limits that belong to one
mechanism are stated with it: chunked files in [§7c], mesh relays in [§8b],
gateways and device relays in [§8c].

### No external review

The design and code have had internal adversarial reviews with regression tests,
not an independent cryptographic audit.

### Forward secrecy in windows, not per message

Content keys are per epoch, and the history of a document stays readable to its
members.

Lockboxes are sealed to reader keys that a device replaces weekly and deletes 30
running days later ([§6]). So a stolen device key alone, with all the ciphertext
keepers hold, opens only what was sealed to the key derived from it: what a
member was given when it joined a space (every epoch up to then), what was
sealed until the first rotation after its first reader key, and requests it
never accepted.

A stolen device key and database exposes the history in that database and the
epochs sealed to the reader keys still in it. Whoever holds the device key can
also act as the device from then on. Removing a member does not erase what they
already received.

### A lost reader key loses its epochs

A device that cannot open an epoch cannot read what was written under it, on
that device, ever: nobody re-seals an old epoch key. This happens when the
device lost its storage, or when the sealer was out of touch for more than the
30 days and sealed to a key since deleted.

The device says so in the graph and writers move to a new epoch, so only that
stretch is lost. The case to know about is two groups of members cut off from
each other for over a month, both writing.

### Post-quantum only in part

Lockboxes, which keepers store long-term, are hybrid (X25519 + ML-KEM-768,
[§2]), so recording them now and breaking X25519 later does not open them.

Signatures are Ed25519: someone with a quantum computer could forge membership
ops, envelopes and cards from then on. A forgery needs the quantum computer at
the time of the attack, not later.

The transport handshake is X25519 only: recorded traffic could be decrypted
later. That exposes what [§8b] lists as metadata, and the envelopes and
lockboxes inside, which are encrypted again under epoch keys and hybrid
lockboxes.

A hybrid handshake exists in the stack Mycel builds on but is not used. The
rustls version in the lockfile offers X25519MLKEM768 only with its `aws-lc-rs`
provider, Iroh takes that provider behind its `tls-aws-lc-rs` feature
(`Builder::crypto_provider`), and noq has a test for such a handshake. Mycel
builds Iroh with `ring`, which has no ML-KEM, and switching means building
AWS-LC (C and assembly) for every platform.

ML-KEM-768 and its Rust implementation (`ml-kem`) are also much younger than
X25519. The hybrid is there so that a flaw in them costs nothing today.

### Metadata

Keepers see membership keys, authors, sizes and timing. Mesh relays and gateways
see who talks to whom, sizes and timing ([§8b], [§8c]). Transport encryption
does not hide IP addresses or local discovery names, and there is no anonymity.

`NeedInvite` as opposed to `Denied` reveals whether a node holds a space whose
256-bit ID the asker already knows. mDNS and the card protocol reveal device
names and public keys on the LAN, by design.

### One device per member

There are no multi-device identities and no device revocation for a person. Each
device is its own member, and the identity key is the account, with no recovery
if it is lost.

### Keys at rest

- iOS keeps the device key in the Keychain. The other platforms keep
  `identity.key` as a file: owner-only on Unix; on Windows, under the user
  profile's permissions.
- Downloaded attachments are plaintext in the app's files folder.
- Reader keys and opened epoch keys are in the database, sealed under a key
  derived from the device key ([§6]). The rest of the database is not encrypted:
  ops and envelopes, which are ciphertext; contacts; settings.
- There is no app lock and no app-switcher redaction.

### Scale

Resolution is linear for linear history but O(n²) for heavily concurrent
membership ops, and envelope validity is recomputed on each membership change.
Sync exchanges full ID inventories.

Rotation sends one lockbox per reader, about 1.2 kB each ([§2]): 350 kB for 300
readers, so fine up to a few hundred members.

The key schedule ([§6]) adds ops that nobody asked for: a rotation per active
space per day and a reader key per reader per week. A space of 300 readers gains
about 300 ops a week (0.4 MB of reader keys, and 2.5 MB of rotations if it is
written to every day), and its graph grows by its readers' keys even while
nothing is written. Each reader-key op is also a membership change, so envelope
validity is recomputed for it. The periods are per-replica settings
(`KeyPolicy`), not yet scaled to the size of a space.

### Protocol bounds

- A genuinely concurrent valid frontier wider than 64 ops cannot be authored on
  ([§5]).
- A rotation carries at most 1,024 lockboxes and must be sealed to every reader
  ([§4]), so a space with more readers than that cannot rotate.
- A pushed invitation carries every membership op the sender holds and is
  refused above 4,096 ops ([§8]), so a space whose graph has grown past that can
  no longer be pushed to a device that does not hold it.

### Rebuild costs

A batch carrying a lower-ID fork of an already-applied change costs one linear
rebuild of that document, and the displaced change's descendants are dropped, as
for revocations. Honest edits built on a removed member's concurrent edits are
dropped on rebuild, because Automerge needs their dependencies.

### Resource use

Resource use is bounded per peer and per node ([§8d]), not per process:
decoding, history, codecs and the OS network stack cost memory on top. Accepted
members' history and attachments have no cumulative storage quota, and a process
killed mid-push can leave staging files behind.

### Forks before a cutoff

Forks before a cutoff are tolerated ([§7], rule 6) but not shown in the UI.

[§1]: #1-threat-model
[§2]: #2-primitives
[§3]: #3-identity
[§4]: #4-spaces-and-the-membership-graph
[§5]: #5-resolving-the-graph
[§6]: #6-epochs-and-encryption-keys
[§7]: #7-content-envelopes
[§7b]: #7b-blob-attachments-older-format
[§7c]: #7c-chunked-files
[§8]: #8-transport-rules
[§8b]: #8b-mesh-relays
[§8c]: #8c-gateways-records-and-carriers
[§8d]: #8d-resource-limits
[§9]: #9-code-and-tests
[§9b]: #9b-hardening
[§10]: #10-limitations
