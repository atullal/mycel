# Mycel — architecture for peer-to-peer, authenticated, fully distributed apps

> Working codename **Mycel** (after mycelium: an underground network with no center). Rename freely.
> Status: v0.3 — 2026-10-07. Phase 0 and phase 1 (platform v0 + Messaging) are implemented. See [§11 Implementation status](#11-implementation-status-2026-10-07). The trust layer is specified in [TRUST.md](TRUST.md).
> Validation targets: **Messaging**, **Newsroom**, **Collaborative docs**, **Turn-based narrative RPG** (Disco Elysium–like).

---

## 1. Goals and non-goals

**Goals**
1. **No trusted server.** Every always-on node is untrusted, replaceable, and runnable by anyone. It stores and forwards ciphertext only.
2. **Real authorization.** Users only read what they're allowed to read (enforced by encryption), and only do what they're allowed to do (enforced by signatures plus deterministic validation on every honest peer).
3. **Offline-first.** Every operation works locally and syncs later.
4. **Rapid app building.** An app = schema + roles + rules + UI. The four target apps should each be mostly UI code.
5. **Native.** Tauri 2 (desktop first, mobile second), Rust core.

**Non-goals (accepted limits)**
- Globally unique names (use petnames plus optional DNS-verified handles).
- Instant, global revocation (it propagates as peers sync; a removed user keeps what they already decrypted).
- Strict global ordering of events (we get causal order, plus single-writer turns where needed).
- Payments or marketplaces.

---

## 2. Layer model

```
 L7  Apps            Messaging · Newsroom · Docs · RPG · (future apps)
 ──────────────────────────────────────────────────────────────────────────
 L6  Host            Shell runtime: app sandbox, identity & contacts UI,
                     invites, notifications, keeper config, permissions prompts
 ──────────────────────────────────────────────────────────────────────────
 L5  SDK + Kits      TS SDK (useSpace/useDoc/useFeed/usePresence/act)
                     Kits: Chat · RichText · Workflow · Presence · Files · Game
 ──────────────────────────────────────────────────────────────────────────
 L4  Rules           Schemas · Roles · Path policies · Actions + Reducers ·
                     Workflows · Branches/Proposals · Validators (WASM)
 ──────────────────────────────────────────────────────────────────────────
 L3  Data & Sync     Doc (Automerge) · Feed (append-only) · Blob · Channel
                     Encrypted sync · Local storage · Local indexes/queries
 ──────────────────────────────────────────────────────────────────────────
 L2  Trust           Spaces · Membership graph · Access levels · Group keys
                     (encryption, post-compromise security) · Signatures
 ──────────────────────────────────────────────────────────────────────────
 L1  Identity        Device keys · Agents (users) · Personas · Contacts
 ──────────────────────────────────────────────────────────────────────────
 L0  Network         Iroh: QUIC by public key, hole punching, relays,
                     discovery (mDNS / DNS / DHT), gossip, blob transfer
 ══════════════════════════════════════════════════════════════════════════
 Keepers             Headless Mycel nodes: availability, mailbox,
                     push wake-ups, bootstrap. Untrusted. Anyone runs one.
```

**Rule of thumb:** L0–L3 are the "new internet" (like TCP/IP + TLS + storage). L4–L5 are the "framework" (like a web framework). L6 is the "browser". L7 is the "sites".

---

## 3. Core vocabulary (the entire mental model)

An app developer should only need these nouns:

| Concept | What it is | Example |
|---|---|---|
| **Device** | One installation, holding one Ed25519 key in the OS keychain. Its Iroh node ID *is* its key. | Alice's laptop |
| **Agent** | A user: a signed, evolving set of devices. | Alice |
| **Persona** | An Agent identity that can't be linked to another Agent. | Anonymous source "Nightjar" |
| **Space** | The unit of trust and collaboration: members + roles + resources + rules. Spaces can nest; a space can be a member of another space. | A chat group, a newsroom desk, a docs folder, a game session |
| **Role** | A named bundle of capabilities in a space. | editor, commenter, player |
| **Doc** | A mergeable Automerge document, for collaboratively edited state. | Story draft, doc body, settings |
| **Feed** | An append-only, signed, chunked log, for messages, events and actions. | Chat messages, game moves, audit log |
| **Blob** | Immutable, content-addressed, encrypted bytes. | Images, PDFs, game assets |
| **Channel** | Ephemeral pub/sub: never stored, members only. | Typing, cursors, presence |
| **Action** | A signed intent appended to a Feed and applied by a deterministic **Reducer** to derive state. | `move_to(location)`, `submit_for_legal` |
| **Rule** | A deterministic check: may this author make this change, given the causal state? | "only legal may set status=cleared" |
| **Keeper** | An always-on, untrusted node that stores ciphertext and relays it. | A $5 VPS, a home NAS, a hosted service |

Every resource is addressable:
`mycel://<space-id>/<resource-kind>/<resource-id>[/path][#heads]`

---

## 4. Layer details

### L0 Network: Iroh
- **Connections:** QUIC, dialed by public key (`iroh` 1.x). Hole punching first; relay fallback. Relays only see encrypted QUIC traffic.
- **Discovery:** LAN via mDNS; global via DNS/pkarr records (a public key's signed address published to DNS); optional DHT. First contact usually comes from an **invite** (QR code or link containing a key, a capability and keeper hints).
- **Protocols multiplexed by ALPN** (the TLS field that labels which protocol a connection carries):
  - `mycel/sync/1`: Doc and Feed sync (L3)
  - `iroh-blobs`: blob transfer
  - `iroh-gossip`: Channels and change announcements
  - `mycel/trust/1`: membership and key-agreement messages
- **Peer authentication comes free:** the remote node ID *is* a Device key. L2 maps Device → Agent → roles.

### L1 Identity
- **Device keys** are generated on device and stored in the Keychain / Secure Enclave / Android Keystore. They never leave the device.
- **Agent** = a signed device list, kept as a small Doc. To add a device, an existing device signs it in (QR pairing). Removing a lost device triggers key rotation in every space.
- **Personas** = separate Agent roots with no cross-signature, so they can't be linked. The host keeps them separate in the UI and on the network: different keepers and separate connection pools.
- **Contacts** = local petnames mapped to Agent keys. Optional: an Agent can prove control of a domain (`alice.example.com`, Bluesky-style), giving human-readable verification with no global registry.
- **Recovery:** primarily multi-device. Later: social recovery (k-of-n trustees hold shares of a key, using Shamir secret sharing).

### L2 Trust (our own minimal layer, see [TRUST.md](TRUST.md); Keyhive later, behind the same API)
- **Space membership graph:** signed, hash-linked operations (`add`, `remove`, `change_role`, `nest`), causally ordered. Every peer replays them to compute current membership.
- **Access levels** (enforced cryptographically): `relay < read < write < admin`.
  - `relay`: can store and forward ciphertext (keepers).
  - `read`: holds the decryption keys.
  - `write`: changes are signed by a member key that is accepted.
  - `admin`: can change membership.
- **Group keys:** continuous group key agreement (Keyhive's BeeKEM, a group key-agreement scheme) gives each space an epoch key. Removing a member rotates the epoch, which gives post-compromise security (a removed or compromised member can't read new data).
- **Signatures:** every change, feed entry and membership op is signed by a Device key, which maps to an Agent.
- **Core invariant: causal authorization.** A change is authorized against the membership state *in its causal past*, not against the receiver's current view. All honest peers therefore reach the same accept/reject decision, so they converge.
- **Concurrent revocation:** when removal and edits happen concurrently, a deterministic rule decides the outcome. The default: removal wins over concurrent ops from the removed member, and seniority breaks ties between concurrent admin ops.
- **Decision:** we ship our own minimal trust layer built only from vetted primitives, specified in TRUST.md. We migrate to Keyhive once it is mature, which is why apps only see Spaces, Roles and Replicas, never the trust layer's internals.

### L3 Data & Sync
| Primitive | Backing | Notes |
|---|---|---|
| **Doc** | Automerge (Rust `automerge` 0.12) inside signed, encrypted envelopes | Rich text, maps, lists, counters; history and branches for free |
| **Feed** | Automerge docs chunked by epoch/size, entries signed | Keeps any single doc small; old chunks can be archived or dropped (retention) |
| **Blob** | `iroh-blobs` (BLAKE3 content addressing), encrypted with the space key | Deduplicated, resumable, fetchable from any peer that holds it |
| **Channel** | `iroh-gossip` topic per space, payloads encrypted | Never persisted |

- **Encrypted sync (decided in phase 0):** each Automerge change travels in its own signed, encrypted **envelope**. Peers and keepers sync envelope sets, not Automerge sync messages, so we use Automerge as the merge engine but **not samod**. The reason: every change must pass signature and authorization checks *before* it is applied, and keepers must store and validate data they cannot decrypt. Envelope validity is decidable from the header alone, so keepers enforce write permissions too.
- **Ingress pipeline** (every peer, every incoming change):
  `verify signature → resolve author (Device→Agent) → decrypt → L4 validate against the causal state → apply, or quarantine`.
  Rejected changes are never applied, so honest peers never build on them, and anything that depends on them is rejected too.
- **Storage:** SQLite (metadata, indexes) plus a filesystem chunk store.
- **Local query engine:** indexes maintained from the patches each change produces (inbox lists, search, "my assignments"). Queries never touch the network.

### L4 Rules: the part that makes apps cheap
Two write models, chosen per resource:

1. **Direct CRDT editing + path policies**, for free-form collaboration (text, settings).
   A change is applied speculatively in a sandbox. The paths it touched are extracted from the resulting patches and checked against the policy table.
2. **Actions + Reducers** (event sourcing), for anything with invariants (workflows, game moves, votes).
   Actions are appended to a Feed. A pure, deterministic reducer folds `(state, action, author, roles)` into new state or rejects the action. Concurrent conflicting actions resolve by a deterministic order (Lamport clock, then author key), so every peer derives the same state.

Building blocks:
- **Schema:** typed Docs, Feeds and Actions, with versioned migrations.
- **Roles → capabilities:** `read(path)`, `write(path)`, `append(feed)`, `act(action)`, `admin`.
- **Workflows:** a state machine with role-gated transitions and optional required signatures (e.g. legal sign-off).
- **Proposals/branches:** propose changes on an Automerge branch; a role with merge rights accepts them (suggestion mode, edit review, alternate game timelines).
- **Validators and reducers run as WASM** in [`wasmi`](https://github.com/wasmi-labs/wasmi) 2.0.0, a pure-Rust interpreter (pinned exactly; chosen over wasmtime/extism for small builds and determinism). Crate `mycel-rules` (host), `mycel-rules-abi` (shared `no_std` types), and the guest SDK under `rules/`. The space pins a hash of its **rules bundle** (`BLAKE3::derive_key("mycel/v0/rules-bundle", wasm)`). Peers whose rules version differs from the pinned one go read-only until they upgrade. This guarantees every peer runs identical rules.
  - **Determinism:** bundles may import nothing; floats, SIMD, threads, memory64, multi-memory and start functions are rejected at load; each call runs on a fresh instance with a fixed fuel budget (20M) and a memory cap (16 MiB); every trap (out of fuel, OOM, stack overflow, panic) becomes the same `Reject(Trap)`.
  - **ABI v1:** the guest exports `memory`, `mycel_abi_version() -> 1`, `mycel_alloc(len) -> ptr`, `mycel_validate(ptr, len) -> i64` and optionally `mycel_reduce(ptr, len) -> i64`. Input is a postcard `RuleInput { author, author_role, stream, payload, context }`; `validate` returns `0` = accept or `(1 << 32) | code` = reject. Exact spec and ingest guidance: [RULES_ABI.md](RULES_ABI.md).
  - Example: `rules/chat-rules` validates the Chat kit's message feed (roles, size limits); author-only edit/delete stays in the deterministic chat reducer.

### L5 SDK + Kits
- **Rust core** exposed to the UI through Tauri commands/events. The **TypeScript SDK** offers:
  `defineApp`, `useSpace`, `useDoc`, `useFeed`, `useQuery`, `usePresence`, `act()`, `invite()`, `propose()`.
- **Kits** are reusable vertical slices (schema + rules + UI components):

| Kit | Provides | Used by |
|---|---|---|
| **Chat** | threads, replies, reactions, edits/deletes, read receipts | Messaging, Newsroom (story chat), Docs (comments), RPG (party chat) |
| **RichText** | ProseMirror ↔ Automerge, marks, comments anchored to text, suggestions | Docs, Newsroom |
| **Workflow** | role-gated state machines, sign-offs, audit trail | Newsroom, Docs (approvals), RPG (turn phases) |
| **Presence** | cursors, who's-here, typing, selection | all four |
| **Files** | blob upload, preview, galleries, attachments | Messaging, Newsroom, Docs |
| **Game** | turn manager, commit-reveal dice, hidden per-player state, votes | RPG (and any future game) |

### L6 Host ("the browser")
One native shell runs many apps:
- **Shared** identity, devices, contacts, keepers, notifications and invites across all apps.
- **Apps are sandboxed web bundles** plus a manifest declaring which SDK capabilities they need. Apps never touch keys or the network directly.
- **Each app can also ship as a standalone Tauri binary** by embedding the same core. The host model is the default because it keeps the SDK boundary honest.

### Keepers
A keeper is a headless Mycel node (the same core, no UI):
- **Availability:** stores encrypted docs, feeds and blobs for spaces that granted it `relay` access.
- **Mailbox:** store-and-forward for offline peers (critical on mobile).
- **Push wake-ups:** sends a content-free ping through APNs/FCM so the phone wakes and syncs. This is the one unavoidable platform dependency on mobile.
- **Bootstrap:** acts as an Iroh relay and a discovery hint.
- A space lists several keepers. Losing one loses nothing.

---

## 5. Validating against the four apps

### 5.1 Messaging
| Need | Mycel primitive |
|---|---|
| DM or group | Space (DM = 2 members; group = admin/member roles) |
| Messages | Feed `messages` (Chat kit), chunked by epoch |
| Media | Blobs (Files kit) |
| Typing / online | Channel (Presence kit) |
| Read receipts | Doc: per-member last-read pointer |
| Offline delivery | Keeper mailbox + push wake-up |
| Disappearing messages / forward secrecy | Epoch keys with retention: delete old chunk keys to get forward secrecy at epoch granularity |
| Rules | members append; authors edit/delete their own messages; admins manage membership |

**App-specific code:** conversation list UI and the chat screen. Nearly everything else comes from the Chat, Files and Presence kits.
**Known tension:** a CRDT's full history conflicts with Signal-grade per-message forward secrecy. Epoch-based retention is the compromise.

### 5.2 Newsroom
| Need | Mycel primitive |
|---|---|
| Org → desks → stories | Nested Spaces (story space is a member of its desk space; permissions inherit) |
| Roles | reporter, editor, legal, publisher, source (Persona) |
| Story draft | Doc + RichText kit |
| Edit review | Proposals (branches) merged by an editor |
| Story lifecycle | Workflow kit: `draft → edit → legal → approved → published`, where `approved` requires a legal signature |
| Anonymous tips | Separate "tips" Space; sources join as unlinkable Personas; Feed `tips` |
| Leaked documents | Encrypted Blobs, readable only by the story space |
| Audit trail | Signed Feed (free: every change is signed) |
| Publishing | Export a signed public snapshot (public read) to a static site |

**App-specific code:** the workflow definition and newsroom UI. RichText, Workflow and Chat are reused.

### 5.3 Collaborative docs (Google Docs–like)
| Need | Mycel primitive |
|---|---|
| Folders and sharing | Nested Spaces; share link = invite capability carrying a role |
| Roles | owner, editor, commenter, viewer, public-viewer |
| Document | Doc + RichText kit |
| Comments | Chat kit threads anchored to text ranges |
| Suggestion mode | Proposals (branches) per suggester; accept/reject merges |
| Version history | Automerge history; named versions = tagged heads |
| Live cursors | Channel (Presence kit) |
| Rules | commenter may write `comments/*` only; viewer is read-only |

**App-specific code:** file browser, editor chrome and sharing dialog.

### 5.4 Turn-based narrative RPG (Disco Elysium–like, co-op)
| Need | Mycel primitive |
|---|---|
| Session | Space: players, plus an optional host/narrator role |
| Game content (dialogue trees, art, skills) | Signed, versioned **content bundle** as Blobs; the space pins the content hash |
| World state | **Actions + Reducer**: a Feed `moves` folded by a deterministic engine (WASM). Every peer computes the same world. |
| Turns | Game kit turn manager: only the turn holder's actions are valid, which gives a total order without consensus |
| Skill checks / dice | Commit-reveal randomness: each player commits a hash of a secret, then reveals it, and the combined seeds give fair dice that are reproducible and verifiable |
| Inner voices / private thoughts / secret items | Per-player private Doc encrypted to that player only (hidden-information state) |
| Party decisions | Game kit votes (Actions with a quorum rule) |
| Party chat | Chat kit |
| Saves and "what if" | Automerge branches = alternate timelines; load = checkout heads |
| AFK / dropouts | Rule: skip-turn vote or timeout. Timeouts use each peer's own wall clock, so they are advisory. |

**App-specific code:** the game engine reducer (Rust → WASM), the content, and the game UI. The Game kit is new and reusable for future games.
**Known limit:** anyone with the content bundle can read the script. Fine for co-op; competitive hidden information would need encrypted content.

### Reuse matrix
|            | Chat | RichText | Workflow | Presence | Files | Game |
|------------|:----:|:--------:|:--------:|:--------:|:-----:|:----:|
| Messaging  | ●    |          |          | ●        | ●     |      |
| Newsroom   | ●    | ●        | ●        | ●        | ●     |      |
| Docs       | ●    | ●        | ○        | ●        | ●     |      |
| RPG        | ●    |          | ○        | ●        | ●     | ●    |

● core dependency  ○ light use

---

## 6. What an app definition looks like (target DX)

```ts
// newsroom/app.ts — the whole permission and workflow model of the newsroom
import { defineApp, doc, feed, roles, workflow, kits } from "@mycel/sdk"

export default defineApp({
  id: "org.example.newsroom",
  rules: "./rules.wasm",            // compiled from the declarations below + custom validators
  roles: roles({
    publisher: ["admin"],
    editor:    ["read", "write", "merge", "act:story.*"],
    legal:     ["read", "comment", "act:story.clear"],
    reporter:  ["read", "write:story.body", "propose", "act:story.submit"],
    source:    ["append:tips"],     // Persona; sees nothing else
  }),
  resources: {
    story: doc(kits.richText.schema, {
      "meta.*":     { write: ["editor"] },
      "comments.*": { append: ["*"] },
    }),
    lifecycle: workflow({
      draft:    { submit: { to: "edit",     by: ["reporter"] } },
      edit:     { send:   { to: "legal",    by: ["editor"] },
                  reject: { to: "draft",    by: ["editor"] } },
      legal:    { clear:  { to: "approved", by: ["legal"], signoff: true } },
      approved: { publish:{ to: "published",by: ["publisher"] } },
    }),
    tips:  feed({ read: ["editor"] }),
    chat:  kits.chat.feed(),
  },
})
```

Everything else (sync, encryption, keepers, invites, presence, audit) comes from the platform.

---

## 7. Mapping to existing components

| Layer | Use | Build ourselves |
|---|---|---|
| L0 | `iroh` 1.3, `iroh-gossip`, `iroh-blobs` | ALPN routing, invite format |
| L1 | Ed25519 (`ed25519-dalek`), OS keychain (`keyring`) | Agent device lists, personas, contacts |
| L2 | `ed25519-dalek`, `hpke`, `blake3` (later: `keyhive_core`) | ✅ v0 built: membership DAG, deterministic resolution, epochs, lockboxes |
| L3 | `automerge` 0.12, `chacha20poly1305` | ✅ v0 built: envelopes, validation, materialization. Next: Feed, Blob, Channel, indexer |
| L4 | `wasmi` 2.0.0 (pinned), `postcard` | ✅ v0 built: deterministic WASM rules runtime + guest SDK ([RULES_ABI.md](RULES_ABI.md)). Next: policy engine, workflows, proposals |
| L5 | `@automerge/prosemirror` 0.2, React | TS SDK, kits |
| L6 | `tauri` 2.12 | Host shell, app sandbox, manifests |
| Keepers | the same core, headless | Mailbox, push bridge |

---

## 8. Build order (each step adds new primitives; later apps mostly compose them)

| Phase | Deliverable | Proves |
|---|---|---|
| **0. Core spike ✅** | Iroh nodes syncing encrypted Docs; membership-gated transport; reader writes dropped; keeper relays ciphertext; removal with key rotation | L0–L3, ingress validation (29 tests) |
| **1. Platform v0 + Messaging** | Trust (Keyhive), Feeds, Channels, Blobs, keeper mailbox, TS SDK, Host shell, Chat/Presence/Files kits | Membership, encryption, offline delivery |
| **2. Docs** | RichText kit, proposals/branches, share links, path policies | Fine-grained rules, branches |
| **3. Newsroom** | Workflow kit, nested spaces, personas, public publishing | Composition: should be mostly reuse |
| **4. RPG** | Actions/Reducers in WASM, Game kit (turns, commit-reveal dice, hidden state), content bundles | Deterministic replicated logic |

---

## 8b. Future app: peer-to-peer version control (from user, 2026-10-07)
Automerge-based version control for humans **and agents**:
- Each agent is a member with Writer access to its own branch.
- Humans review and merge proposals; every change is signed.
- Repos sync between devices with no central host.

Needs atomic multi-file snapshots and conflict surfacing for code, which plain Automerge merges don't give. Built on L4 Proposals plus the Workflow kit. Planned after the four target apps. Until then, this repo itself uses git.

## 9. Top risks
1. **Keyhive maturity:** pre-1.0 and unaudited. Mitigation: the `Trust` trait; a minimal fallback built on `keyhive_crypto` primitives.
2. **Encrypted sync through keepers:** keepers can't merge ciphertext, so storage grows until members compact it. Track Subduction/sedimentree.
3. **Validating CRDT changes:** extracting touched paths from patches must be exact, and rejections must be deterministic across rule versions. Heavily property-test it.
4. **Concurrent revocation semantics:** the hardest correctness area. Needs a written spec plus simulation tests with partitioned peers.
5. **Rules/schema versioning across peers:** pinned rules bundles plus read-only fallback. Migrations must be deterministic.
6. **Mobile:** background sync limits mean keepers and push wake-ups are required for messaging.
7. **Metadata privacy:** keepers and relays see which keys talk and when. Acceptable for v1; personas use separate keepers.

## 10. Decisions (2026-10-07)
- **Rules language:** Rust compiled to WASM. The UI is TypeScript.
- **Packaging:** host-first.
- **Trust layer:** our own minimal, secure layer (TRUST.md), migrating to Keyhive later.
- **Name:** Mycel.
- **Sync:** our own envelope protocol instead of samod (see L3).

## 11. Implementation status (2026-10-07)

| Layer | Built | Not yet |
|---|---|---|
| **L0 Network** | Iroh 1.3 QUIC dialed by key. Modes: `lan` (mDNS only, no internet), `internet` (n0 relays, DNS discovery, mDNS), `local` (tests). Live sync engine: push on change, epidemic forwarding, 15 s periodic sync, backoff. ALPNs: sync, card, ephemeral, blob. | DHT discovery; self-hosted relay config |
| **L1 Identity** | Device keys (seed file `identity.key`, mode 0600), signed contact cards and codes, contacts, LAN names | Multi-device agents, personas, OS keychain, social recovery |
| **L2 Trust** | Membership DAG, deterministic resolution (seniority, revocation wins, cutoffs), epochs + HPKE lockboxes, self-healing rotation, Leave | External crypto review; X-Wing (post-quantum) lockboxes; TreeKEM-style rotation |
| **L3 Data** | Docs (Automerge), Feeds (causal, deterministic order), Blobs (encrypted, content-addressed, any size: streaming STREAM-construction AEAD, streamed to disk, resumable, hash-checked; small ones pushed, big ones pulled on demand), ephemeral Channels, redb storage with batched writes, restore on start, delivery tracking | Range-based set reconciliation, compaction; multi-source parallel blob download |
| **L4 Rules** | wasmi 2.0 deterministic engine (fuel, memory caps, no floats/imports). Chat rules (Rust → 14 KB WASM) run on every decrypted feed entry on every peer. | Rules pinned as a membership op; Doc path policies; action reducers in production |
| **L5 SDK + Kits** | `@mycel/sdk` (types, Tauri/HTTP/mock transports, React hooks); Chat kit (Rust ops + deterministic reducer) | RichText, Workflow, Game kits |
| **L6 Host** | Tauri 2 host shell (apps rail, profile/contacts/nearby/network panels); `mycel serve` web host; `mycel keeper` | App sandboxing via iframes + manifests |
| **Keepers** | `mycel keeper`: accepts spaces, stores and serves ciphertext, never decrypts | Push wake-ups (APNs/FCM) for mobile |
| **Apps** | **Messaging**: DMs, groups, replies, edits, deletes, reactions, read receipts, typing, files, members, keepers, leave | Docs, Newsroom, RPG |

Tests: 93 Rust tests, including real-QUIC multi-node, real mDNS, runtime end-to-end with storage, and keeper offline delivery. Plus a UI end-to-end run driven in headless Chrome against real LAN devices. See [TESTING.md](TESTING.md).
