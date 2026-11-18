# Testing Mycel

This document explains how to run Mycel's tests, what continuous integration
(CI) runs on every change, what the automated suites cover, and what the
manual and hardware tests measured. It is written for contributors. The last
section lists what has not been tested.

Simulator results are in [SIMULATION.md](SIMULATION.md) and store-and-forward
benchmarks in [BENCHMARKS.md](BENCHMARKS.md). Passing tests are not an audit:
Mycel has not had an external security audit
([SECURITY.md](../SECURITY.md)).

## Contents

- [Running the tests](#running-the-tests)
  - [What the tests run on](#what-the-tests-run-on)
  - [Platform notes](#platform-notes)
  - [Tests ignored by default](#tests-ignored-by-default)
- [What CI runs](#what-ci-runs)
  - [CI jobs and their local commands](#ci-jobs-and-their-local-commands)
  - [The project's own macOS runner](#the-projects-own-macos-runner)
  - [Other workflows](#other-workflows)
  - [Security check script](#security-check-script)
  - [Before merging to main](#before-merging-to-main)
- [Automated tests by crate](#automated-tests-by-crate)
- [Manual and hardware test results](#manual-and-hardware-test-results)
  - [Voice calls](#voice-calls)
  - [Several devices on one computer, real UI](#several-devices-on-one-computer-real-ui)
  - [Local HTTP API hardening](#local-http-api-hardening)
  - [Large attachments](#large-attachments)
  - [Peer-to-peer Wi-Fi, two processes on one Mac](#peer-to-peer-wi-fi-two-processes-on-one-mac)
  - [Multipath aggregation, connection reuse, multi-source downloads](#multipath-aggregation-connection-reuse-multi-source-downloads)
  - [Mesh relaying](#mesh-relaying)
  - [Global routing and store-and-forward](#global-routing-and-store-and-forward)
  - [Phones and the other platforms](#phones-and-the-other-platforms)
  - [Timing on the macOS CI runner](#timing-on-the-macos-ci-runner)
  - [Real hardware](#real-hardware)
- [What is not tested](#what-is-not-tested)

## Running the tests

You need the Rust toolchain pinned in `rust-toolchain.toml` and Node.js 22.18
or later. On Linux you also need the system libraries listed in
[CONTRIBUTING.md](../CONTRIBUTING.md).

```sh
cargo test --workspace --exclude mycel-host   # every Rust crate except the host app
cargo test -p mycel-host --lib                # the host app (needs the webview libraries)
npm ci
npm run typecheck && npm test                 # SDK, Messaging and host UI
```

Many tests print what they measured. To see it, run one test file with
`--nocapture`:

```sh
cargo test -p mycel-net --test mesh -- --nocapture
```

### What the tests run on

Most tests start real nodes that speak real QUIC to each other. The nodes
connect over loopback, or over in-memory links that stand in for radios:

- `mycel_net::link::MemNet` is one link with a set rate and latency, which a
  test can cut and restore.
- `mycel_net::emu::EmuNet` is a shared medium with positions, range, rate,
  delay, jitter and loss. The simulator uses it.

An emulated link can carry any medium label (`PathKind`), so path selection,
aggregation and failover are tested between media the test machine does not
have.

The only tests that contact outside services (n0's relay and DNS servers, the
public DHT) are the two in `crates/mycel-net/tests/internet.rs`. They are
ignored by default.

### Platform notes

On macOS, three tests need the terminal to have Local Network access:
`lan_discovery_via_mdns`, `one_path_per_interface` and
`sync_over_an_interface_with_ip_off`. Without it they fail with "No route to
host". Allow it in System Settings > Privacy & Security > Local Network.

Tests that measure speed or time emulated radios (video frame rates, mesh
throughput, link failover, real-time simulator scenarios) run one at a time
within each test binary. They can still miss their deadlines on a heavily
loaded machine, so rerun a failed timing test on its own before treating it
as a regression.

### Tests ignored by default

Some tests need a network, particular hardware or a lot of time, and are
marked `#[ignore]`.

| Tests | Why they are ignored | Command |
|---|---|---|
| Heavier and real-time simulator scenarios | slow | `cargo test -p mycel-sim -- --ignored` |
| `crates/mycel-net/tests/internet.rs` | uses n0's servers and the public DHT | `cargo test -p mycel-net --features dht --test internet -- --ignored --nocapture` |
| `crates/mycel-link-awdl/tests/bonjour_loopback.rs` | needs a Mac with Bonjour | `cargo test -p mycel-link-awdl -- --ignored` |
| Native Bonjour discovery (`crates/mycel-net/src/native_mdns.rs`) | needs a LAN and macOS Local Network permission | `cargo test -p mycel-net --lib native_bonjour -- --ignored` |
| Bluetooth fault simulation over many more seeds | slow | `cargo test -p mycel-link-ble --release -- --ignored seed_sweep` |

A few benchmarks and by-hand measurements are ignored too. The doc comment on
each gives its command.

`cargo test -p mycel-sim` runs the lighter simulator scenarios at reduced
size, and `-- --ignored` adds the heavier ones, still at reduced size. The
full-size runs are a separate command, described in
[SIMULATION.md](SIMULATION.md):

```sh
cargo run --release -p mycel-sim -- all
```

## What CI runs

`.github/workflows/ci.yml` runs on every pull request, merge-queue entry and
push to `main`. Its last job, CI result, passes only when every other job
passed or was skipped. It is the one check that branch protection requires.

### CI jobs and their local commands

Each subsection is named after a CI job and gives the commands that job
runs. `--locked` makes cargo fail if `Cargo.lock` is out of date. CI pins the
version of every tool it installs; the versions are in the workflow file.

#### Rustfmt

Checks the formatting of both Cargo workspaces: the main one and `rules/`.
`vendor/` is excluded.

```sh
cargo fmt --all --check
cargo fmt --all --check --manifest-path rules/Cargo.toml
```

#### Clippy

Runs on Linux, macOS and Windows, with warnings as errors.

```sh
cargo clippy --locked --workspace --all-targets -- -D warnings
```

On Windows, CI adds `--exclude mycel-sim --exclude mycel-bench`: the
simulator and the benchmarks are Unix development tools.

#### Tests

Runs the runtime crates' tests on Linux, macOS and Windows. The build is
optimised (`CARGO_PROFILE_DEV_OPT_LEVEL=2`) because some tests time real work,
such as sync ingest and multipath throughput, and a debug build on a small
runner misses their bars.

```sh
export CARGO_PROFILE_DEV_OPT_LEVEL=2
cargo test --locked --no-fail-fast \
  -p mycel-crypto -p mycel-trust -p mycel-sync -p mycel-rules -p mycel-kit-chat \
  -p mycel-net -p mycel-link-iface -p mycel-link-ble -p mycel-call -p mycel-video -p mycel-node \
  2>&1 | tee test.log
python3 scripts/ci/retry-failed.py test.log   # only if the tests failed
```

Even in an optimised build, a different timing test can miss its deadline in
each run on the small CI machines. When the test command fails,
`scripts/ci/retry-failed.py` reruns each failed test, up to twice. A test that
passes on a retry is reported as a "Flaky test" warning on the run. A test
that fails three times fails the job.

On macOS, a CI runner cannot answer the Local Network prompt, so CI skips the
three LAN discovery tests there. They run on Linux and Windows only. CI
appends this to the test command:

```sh
-- --skip lan_discovery_via_mdns --skip one_path_per_interface \
   --skip sync_over_an_interface_with_ip_off
```

The macOS job also logs how late a 3 ms sleep wakes, in a step named Timer
probe. [Timing on the macOS CI runner](#timing-on-the-macos-ci-runner)
explains why.

#### Security regressions

Runs the security suites on Linux with no retries: a security regression must
stay a failure.

```sh
cargo test --locked --lib -p mycel-crypto -p mycel-trust -p mycel-sync -p mycel-rules
cargo test --locked -p mycel-net --test blob_security
cargo test --locked -p mycel-node --test attachment_security
```

#### Rustdoc

Builds the API documentation with warnings as errors. Broken intra-doc links
and stray HTML in doc comments fail the build.

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --workspace --exclude mycel-host
```

#### Rules (WebAssembly)

Lints the rules workspace for the WebAssembly target, rebuilds the guest
bundles into the rules runtime's test fixtures, then runs the runtime against
them.

```sh
(cd rules && cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings)
rules/build.sh
cargo test --locked -p mycel-rules
```

#### Dependencies (cargo-deny)

The dependency check is `cargo deny --locked check`. It covers advisories,
licences, bans and sources, with the policy in `deny.toml`. CI runs it for
both workspaces.

```sh
cargo deny --locked check
cargo deny --locked --manifest-path rules/Cargo.toml --target wasm32-unknown-unknown check \
  -A license-exception-not-encountered -A license-not-encountered -A advisory-not-detected
```

#### Web (types, tests, build)

Type-checks the TypeScript workspaces, runs their `node:test` suites, builds
the UI and audits the npm dependencies that ship.

```sh
npm ci
npm run typecheck
npm test
npm run build
npm audit --omit=dev
```

#### Spelling

The spelling check is [`typos`](https://github.com/crate-ci/typos), over
code, comments and docs. Its configuration and the list of accepted words are
in `_typos.toml`.

```sh
typos
```

#### Workflows (actionlint, zizmor)

Lints the workflow files and `.github/dependabot.yml`.

```sh
actionlint
zizmor .github/workflows .github/dependabot.yml
```

#### Jobs with no local command

- Dependency review runs on pull requests only. It fails when the pull
  request adds a dependency with a known vulnerability of low severity or
  higher.
- Sign-off (DCO) runs on pull requests only. Every commit except merge
  commits needs a `Signed-off-by` line, which `git commit -s` adds
  ([CONTRIBUTING.md](../CONTRIBUTING.md)).
- Gradle wrapper checks that the checked-in `gradle-wrapper.jar` is an
  official Gradle build.

### The project's own macOS runner

The macOS Clippy and Tests jobs can run on the project's own Mac, a
self-hosted runner, in place of GitHub's hosted macOS runner. A job named
Runners decides where they go.

Runners sends the two jobs to the project's Mac when the repository variable
`MACOS_RUNNER` is `self-hosted`, and only for code that a maintainer pushed.
Pull requests from forks and from Dependabot never run there. With the
variable unset, every job runs on GitHub's runners.

The measurements under [Timing on the macOS CI
runner](#timing-on-the-macos-ci-runner) describe GitHub's hosted runner.

### Other workflows

| Workflow | Runs | What it does |
|---|---|---|
| Apps (`apps.yml`) | pushes to `main`, `dev-*` and `v*` tags | builds, tests and smoke-tests the Linux and Windows apps |
| Audit (`audit.yml`) | daily | checks locked dependencies against new advisories |
| CodeQL (`codeql.yml`) | pull requests, pushes to `main`, weekly | code scanning of Rust, TypeScript and the workflows |
| Scorecard (`scorecard.yml`) | pushes to `main`, weekly, branch protection changes | OpenSSF Scorecard supply-chain checks |

The Apps workflow does not run on pull requests. Its Linux job runs the web
checks and the host app's own Rust tests, builds the deb, rpm and AppImage
packages, checks that the binary contains no build-machine paths
(`scripts/ci/check-build-paths.sh`), starts the app on a virtual display, and
probes whether WebKitGTK can send video the way the app does. Its Windows job
builds the installer and the MSI, runs the same path check, starts the app,
and runs the video probe in Edge. On a tag, a third job publishes the
installers with `SHA256SUMS` and a build provenance attestation. What these
jobs found is under [Linux and Windows on GitHub
Actions](#linux-and-windows-on-github-actions).

The host app's tests are the one Rust suite that the Apps workflow runs and
`ci.yml` does not:

```sh
cargo test --locked -p mycel-host --lib
```

The Audit workflow runs the advisory checks against unchanged code:

```sh
cargo deny --locked check advisories
cargo deny --locked --manifest-path rules/Cargo.toml --target wasm32-unknown-unknown \
  check advisories -A advisory-not-detected
npm audit --omit=dev
```

### Security check script

`scripts/security-check.sh` runs the security suites and the advisory checks
in one command, on a development machine with Rust, Node and cargo-deny.
Nothing is retried.

```sh
scripts/security-check.sh
```

It runs, in order:

1. The library tests of `mycel-crypto`, `mycel-trust`, `mycel-sync`,
   `mycel-rules`, `mycel-net` and `mycel-node`.
2. The `blob_security` tests of `mycel-net`, and the `attachment_security`,
   `forward_secrecy` and `contact_codes` tests of `mycel-node`.
3. The host app's library tests.
4. `npm run typecheck` and `npm run build`.
5. `npm audit --audit-level=low`.
6. `cargo deny --locked check advisories`, which applies the same policy as
   CI. Each accepted advisory has its reason in `deny.toml`.

### Before merging to main

A change merges to `main` when:

- the workspace tests pass twice in a row;
- clippy is clean with `-D warnings`;
- `cargo fmt --all --check` passes;
- `npm run build` passes, if TypeScript changed.

Iroh, noq, swarm-discovery, swift-rs and the notification plugin are vendored
under `vendor/` with small patches. Read the `MYCEL_PATCH.md` beside each
before touching them; [CONTRIBUTING.md](../CONTRIBUTING.md) has the rules.
Built apps (`dist-release/`) and contact-trace data (`bench/data/`) are never
committed.

## Automated tests by crate

Unit tests sit beside the code in each crate's `src/`, and integration tests
in its `tests/` directory. Each subsection below says what the suite
establishes, the areas it covers, and the files to open first. Paths are
relative to the crate unless they start with `crates/`.

`mycel-cli` and `mycel-bench` have no automated tests. The manual tests in the
next section drive `mycel serve` and `mycel keeper`.

### `mycel-crypto`

The suite establishes that signatures, key exchange, lockboxes and attachment
encryption reject input that was tampered with, truncated or meant for
another context, and that key derivations and formats stay pinned.

- Signing and framing: domain separation, framing that prevents boundary
  shifting, key-exchange binding, deterministic keys from a seed.
- Hybrid lockboxes: round trip and info binding, sizes, tampering, randomised
  output, pinned key derivation, keys length-checked on decode and validated
  before use, and the X25519 format of earlier builds refused.
- Reader keys and sealed device storage: a generated key-exchange secret is
  not derived from the device seed, and stored secrets are sealed to the
  seed, their purpose and their place.
- Streamed attachments: sizes at chunk boundaries (empty, one byte, exactly
  one chunk, many chunks); tampering and a wrong key, nonce or associated
  data; truncation and extension; reordered, duplicated or resized chunks; a
  legacy one-shot blob that is not mistaken for a stream; an incremental
  digest equal to the one-shot digest.
- Chunked attachments: content-defined cut points that are deterministic,
  bounded and move only near an insertion; trees that round-trip at piece
  boundaries in both modes; public files that share every node and private
  files that share none; a private file that hides repeated content; no key
  sealing two nodes; tampering, wrong keys and swapped nodes caught at the
  node; malformed indexes refused.

Files: `src/lib.rs`, `src/stream.rs`, `src/chunked.rs`.

### `mycel-trust`

The suite establishes that every device computes the same membership and keys
from the same signed operations, in any delivery order, and that operations
from unauthorised or removed members never take effect.

- Authorisation: roles and key distribution, forged and tampered admin
  operations, operations from keys that were never added, readers that cannot
  rotate, the last admin staying.
- Removal and rotation: removal with rotation, concurrent revocation, mutual
  removal decided by seniority, leaving, rotation recipients checked against
  the readers, a bad key commitment, self-healing rotation after a concurrent
  add and remove, and epoch IDs that cannot be reused with a different key.
- Convergence: the same result in any delivery order, operations held pending
  until their parents arrive, batch insert equal to sequential inserts.
- Resistance to flooding: a fan-out of invalid operations cannot block a
  revocation, wide valid frontiers are not truncated, and the pending pool is
  limited per author.
- Reader keys: who may publish one, sealing that moves to it, a deleted key
  that closes its lockboxes, convergence under concurrency, and epochs closed
  by a lost key.

Files: `src/tests.rs`, `src/reader_tests.rs`.

### `mycel-sync`

The suite establishes that replicas converge on the same documents and feeds
whatever the delivery order, that roles are enforced on every replica, and
that hostile input is bounded before it is parsed.

- Replication and roles: writer changes replicate, reader writes are rejected
  everywhere, a keeper stores and validates but cannot read, outsider and
  tampered envelopes, a forged actor, backdated writes after removal,
  demotion.
- Convergence: concurrent edits, feeds in causal order, document equivocation
  resolved identically everywhere, restore from storage, changes delivered in
  reverse dependency order.
- Hostile and malformed changes: decompression and run-length expansion
  bombs, malformed and deferred changes, declared-history checks (actor
  sequence, counters, object references), and large pastes split into changes
  that every peer accepts.
- Cost: a 2,000-message feed ingested in one batch, and document work that
  scales with the change, not the history.
- The key schedule, on a test clock: weekly reader keys, deleted after 30
  days of running time and stored before they are published; timed rotation
  with jitter; restarts with and without the stored keyring; an attacker who
  has only the device seed; restore from stored operations in any order;
  long absences; keepers.
- The Automerge change format: the locked Automerge version is the audited
  one and still writes the audited bytes.

Files: `src/tests.rs`, `src/keys_tests.rs`, `src/bounded_change.rs`.

### `mycel-net`

The suite establishes that real nodes find each other, sync and move files
over real QUIC on whatever links exist, directly or through other devices,
and that a peer cannot make a node hold unbounded memory or disk. Measured
results from these tests are under [Multipath
aggregation](#multipath-aggregation-connection-reuse-multi-source-downloads),
[Mesh relaying](#mesh-relaying) and [Global
routing](#global-routing-and-store-and-forward).

- Sync and discovery (`tests/phase0.rs`): five nodes over real QUIC; invites
  and live sync with no manual calls; an invite policy that refuses; contact
  cards, ephemeral messages and encrypted blobs; mDNS discovery on the test
  machine; a first sync with the inviter that brings a 10 MiB history.
- Connection reuse (`tests/pool.rs`): syncs, card fetches and ephemeral
  messages share one pooled connection; a peer restarted on the same port is
  redialed; an idle connection is closed and redialed on use.
- Links and paths (`tests/links.rs`, `tests/media.rs`, `tests/aggregate.rs`):
  two devices with no IP sync over in-memory links, prefer the faster one and
  fall back to a Bluetooth-like one; a live QUIC connection moves to another
  link mid-transfer; media are ranked by what they measure, with no rule per
  radio; one stream uses two comparable links at once and survives losing
  one; a slow link never slows a fast one.
- Blobs (`tests/blobs.rs`, `tests/multisource.rs`): a 40 MiB blob streamed to
  disk; an interrupted multi-source download resumed from its `.part` and
  `.ranges` files; a corrupt partial copy detected and refetched from another
  member while the sender is offline; the push policy (small blobs to
  everyone, big ones to keepers only); the free-space guard; a download from
  three sources that survives losing one.
- Chunked files (`tests/chunks.rs`, `src/chunks/`): the push policy, resuming
  and fetching from every holder; a file that outlives its sender in the
  cache of a device outside the conversation; replicas placed with contacts
  when a member is away; cache budgets; a public file stored and sent once; a
  source that sends wrong bytes dropped at that piece; pushes that need an
  accepted offer; pinning, eviction and stranger shares in the store.
- Resource limits (`tests/blob_security.rs`, `src/wire.rs`,
  `src/resources.rs`): stream and frame budgets, stalled and progressing I/O,
  duplicate requests, ephemeral limits, failed eager pushes that leave
  nothing staged and keep a download's resume state, and a trickling stranger
  that delays only itself.
- Mesh (`tests/mesh.rs`, `src/mesh/core/tests.rs`): devices with no direct
  link sync through a relay that is in no space and sees no plaintext; two
  routes aggregate and fail over; a route heals when a middle device leaves;
  a ring neither storms nor loops; relay budgets hold; a hop moves between a
  fast link and a Bluetooth-like one; forged, stale and flooding
  announcements are rejected; fragments reassemble; routing convergence and
  churn in virtual time.
- Gateways and store-and-forward (`tests/global.rs`,
  `src/mesh/dtn/tests.rs`): Bluetooth-only devices sync through two gateways
  and an emulated internet; two gateways are two paths; custody, mailboxes,
  receipts, budgets, lifetimes and resumed transfers for bundles; a data mule
  that carries a message across partitions.
- Device relays and records (`tests/relay.rs`, `src/mesh/records.rs`,
  `src/mesh/directory.rs`): two devices behind routers sync through a third
  device with no relay server and no DNS server; only devices whose record
  says they relay are asked; a relay is learned from a contact's record; a
  device's own record follows its addresses and role, and never publishes
  private addresses.
- The real internet (`tests/internet.rs`, ignored by default): a device's
  record reaches n0's DNS server and is read back, and the public DHT is
  joined with no relay or DNS server.
- Platform behaviour (`tests/timers.rs`, `tests/path_queue.rs`): Windows
  timer resolution, and a path-open queue that does not grow.

### `mycel-call`

The suite establishes that calls set up, carry audio and video, follow the
path they are on and end correctly between real nodes, and that devices
outside a conversation cannot ring or join.

- Audio pipeline (unit tests in `src/`): an Opus round trip that keeps a
  440 Hz tone, a 12 kbps stream of about 1.5 KB/s, loss concealment and FEC;
  the frame codec and stream framing under arbitrary splits; resampling
  across rates; a test audio device that paces itself at 10 and 40 ms
  periods.
- Jitter buffer: prebuffering, reordering, loss concealed with FEC from the
  next frame, late and duplicate frames dropped, a target that grows with
  jitter but never past 120 ms, underrun then concealment then rebuffering,
  bursts trimmed.
- Bitrate controller: path ceilings, stepping down on loss and high RTT, slow
  recovery, FEC that tracks loss.
- Playout cushion: it follows the device's buffer (25 ms for 10 ms bursts,
  covers 40 and 60 ms Bluetooth bursts, never over 100 ms) and shrinks back
  after a hiccup.
- Call state: a call ID bound to space, caller and nonce; ringing, busy, and
  two people calling each other at once ending in one call.
- Calls between real nodes (`tests/calls.rs`): audio both ways with measured
  latency, mute, and hang-up by either side; decline, no answer, missed,
  busy, and rings forged by a non-member refused; simultaneous calls merged
  into one; a call that moves from a fast in-memory link to a Bluetooth-like
  one at 12 kbps; datagrams falling back to a stream; a call through a mesh
  relay, and one across two gateways.
- Group calls (`tests/group_calls.rs`): ringing everyone, joining late,
  leaving without ending the call, outsiders and removed members refused, a
  call with no IP at all.
- Video calls (`tests/video.rs`, Apple platforms only): video both ways,
  video on a slow link that leaves audio alone, video pausing on Bluetooth, a
  group video call of three.

### `mycel-video`

The suite establishes that video is paced to what the path can carry and
recovers from loss, and that on Apple platforms the encoder and the media
threads keep working when the system throttles them.

- Rate controller: a budget for every kind of path, ramp-up, back-off when
  frames queue, pacing, path changes.
- Wire formats and receiver: frame and control formats, reordering, keyframe
  recovery.
- Camera frames: portrait, landscape and 4:3 frames keep their shape.
- VideoToolbox (Apple platforms): encode and decode; one answer from the
  encoder per frame (a frame, a drop or a timeout, counted apart); a stalled
  encoder session replaced by the next mode, down to CPU scaling and the
  software encoder; an error when no mode is left.
- Real-time scheduling (Apple platforms): promoted media threads wake on
  time, also when the test re-runs itself throttled, and the kernel's stored
  policy is read back.
- Video between real nodes (`tests/track.rs`, Apple platforms only): video
  both ways, recovery from lost frames with keyframes, adapting to a slow
  link.

Files: `src/rate.rs`, `src/receiver.rs`, `src/mac/vt.rs`, `src/realtime.rs`,
`tests/track.rs`.

### `mycel-node`

The suite establishes that the whole messaging API works end to end on real
storage and real QUIC, across restarts, and that strangers, blocked devices
and hostile files stay out.

- Messaging (`tests/runtime.rs`): direct messages, delivery then read,
  replies, reactions, edits, deletes, attachments, persistence across a
  restart; keeper delivery while the sender is offline; group admin removal;
  the chat rules rejecting a forged operation on every peer; message
  requests, with declined and blocked strangers staying out; contact-code
  address hints connecting without discovery.
- Attachments: a 120 MiB attachment byte-exact between two nodes with upload
  and download progress; legacy one-shot attachments still open; folders sent
  as .zip from a `file://` URL; unreadable files that explain why; hostile
  attachment names neutralised; consent kept across restarts
  (`tests/attachment_security.rs`).
- Calls through the JSON command table: a voice call refused while the
  conversation is a message request, then ringing, answering, audio, mute and
  hang-up; a group call between three runtimes.
- Contact codes (`tests/contact_codes.rs`): short and full codes; a contact
  added from a short code gets its keys from the device, also across a
  restart; a full code needs no connection; altered and foreign codes, and
  codes of earlier builds, are refused.
- Reader keys end to end (`tests/forward_secrecy.rs`): none for an unanswered
  request, a keyring that survives a restart and is useless to another
  identity, a keeper in between.
- Conversations: one chat per person across separately created spaces, paging
  and search, local hide and restore across restarts
  (`tests/message_visibility.rs`).
- Identity and storage (`src/identity.rs`, `src/store.rs`): fault injection
  on the identity file and the store; closing the store releases its file at
  once, so a restarted runtime opens it while a straggling task still holds
  the old handle.

### `mycel-link-awdl`

The unit tests cover control datagrams, TXT records and interface filtering.
Two Bonjour loopback tests in `tests/bonjour_loopback.rs` need a Mac and are
ignored by default.

### `mycel-link-ble`

The suite establishes that the Bluetooth link keeps one working channel per
pair of devices through connection faults, with the radio replaced by a model.

- Framing and bounded queues.
- The connection state machine: who dials, duplicates, timeouts, backoff,
  address rotation.
- A fake radio (`src/fake.rs`): sync between real nodes with IP off; the
  radio's rate holds when its thread wakes late, and is never exceeded.
- A deterministic simulation (`src/sim.rs`): hours of simulated faults
  between two devices.
- The macOS stream code over in-process pipes.

### `mycel-link-iface`

The suite establishes that the interface link picks the right interfaces and
syncs over one with IP off.

- Interface classification: the medium from type and name, software
  interfaces skipped, ordinary NICs left to IP, environment overrides.
- Beacons.
- A sync over a real interface with IP off (`tests/sync.rs`), and one path
  per interface (`tests/paths.rs`). Both use the loopback interface unless
  `MYCEL_IFACE_TEST` names another.

### `mycel-kit-chat`

The suite establishes that the chat reducer accepts only what the author or
an admin may do, and that merged threads keep a stable order.

- Messages: author-only edits and deletes, reactions, receipts and unread
  counts, admin-only metadata, tolerance of garbage entries.
- Thread merging: a late alias cannot backdate messages, and a message
  written at an alias's first-seen time sorts after that alias's older
  messages.
- Alerts.

Files: `src/lib.rs`, `src/thread.rs`, `src/alerts.rs`.

### `mycel-rules` and `mycel-rules-abi`

The suite establishes that the WebAssembly rules engine is deterministic and
bounded: fuel and memory limits, banned features refused at load, ABI
violations, the chat rules, wire compatibility with the chat kit, and a
pinned fuel cost model.

Files: `crates/mycel-rules/src/tests.rs`, `crates/mycel-rules-abi/src/lib.rs`.

### `mycel-sim`

`tests/scenarios.rs` runs the simulator's scenarios at reduced size. Each must
pass, or fail exactly as expected. The lighter scenarios run by default and
the rest with `-- --ignored`. Unit tests cover the simulator's own models.

### `mycel-host`

The host app's tests cover log file handling and notifications: notification
privacy, deduplication, tap routing and permission handling.

Files: `apps/host/src-tauri/src/lib.rs`, `apps/host/src-tauri/src/notify.rs`.

### Web

`npm test` runs each workspace's `tests/*.test.ts` with Node's built-in
TypeScript type stripping.

- SDK (`packages/sdk/tests/`): paging, search, presence and conversation
  identity.
- Messaging (`apps/messaging/tests/`): layout and swipe gestures.
- Host UI (`apps/host/tests/`): notices, notification actions and status, and
  relay status text.

## Manual and hardware test results

These results come from running Mycel by hand or from reading what a test
printed. Results that depend on hardware were measured on one Mac (18 cores,
24 GB) unless a section says otherwise.

### Voice calls

Audio input and output were replaced by test sources and sinks
(`MYCEL_AUDIO=test…`), and the devices ran with `--net local` (loopback only,
no mDNS).

#### Two devices driven over the HTTP API

Two real `mycel serve --net local` devices in a debug build, driven over the
HTTP API with the per-run token from `<data>/http-token`. Contact codes were
exchanged and a direct conversation created, then `start_call` →
`accept_call` → 10 s → `set_muted` → `end_call`.

| Measurement | Alice (440 Hz tone) | Bob (660 Hz tone) |
|---|---|---|
| Ringing after `start_call` | | 0.10 s |
| Active after `start_call` | 0.11 s | 0.11 s |
| Heard | 660.0 Hz | 440.0 Hz |
| Frames sent / received / lost | 509 / 509 / 0 | 509 / 509 / 0 |
| Path, bitrate, transport | network, 32 kbps, datagrams | same |
| Jitter, jitter buffer | 1.1 ms, 40 ms | 0.8 ms, 40 ms |
| CPU during the call (debug build, incl. test-audio thread) | 6.8 % | 6.8 % |
| Memory | 41 MB | 41 MB |

Mute reached the other side (`remoteMuted`), and Bob's call ended
`remoteHungUp`.

For latency, Alice sent 1 kHz tone bursts (`test:bursts`) and Bob sent back
what he heard (`test:echo`). Alice measured 160 ms from saying a burst to
hearing it back, which is about 80 ms mouth to ear each way, including both
test devices' 10 ms buffers.

#### Integration tests

In-process tests in `crates/mycel-call/tests/calls.rs`:

| Measurement | Result |
|---|---|
| Ring to active | ~105 ms |
| Mouth to ear over loopback | 75–95 ms, no loss |
| No IP: the fast in-memory link is cut and the call moves to a Bluetooth-like link (20 KB/s, 20 ms each way) | after ~5.8 s (the 5 s dead-path timeout) |
| The same call on the Bluetooth-like link | 12 kbps, 50 frames/s, RTT 50 ms, jitter buffer 80 ms, ~160 ms mouth to ear |
| A call through a mesh relay, with no direct link | 0 % loss, ≈95 ms |

After the move to the Bluetooth-like link, both directions still heard the
right tone.

Long-lived connections keep their quiet backup link paths because Mycel's
Iroh patch pings link paths every second (item 3 in
`vendor/iroh/MYCEL_PATCH.md`). Without that, noq re-arms a path's keepalive
only when a packet arrives on it, and the test failed about one run in three.

#### Real UI

Both `mycel serve` web UIs ran in headless Chromium. Alice clicks the phone
button and Bob gets the incoming-call card. He accepts, and both show the
in-call bar with time, path, bitrate and meters. Bob mutes and Alice's bar
says so. Alice hangs up and Bob's bar shows *Call ended*.

#### Group calls

`crates/mycel-call/tests/group_calls.rs` uses real nodes and real QUIC, with a
different test tone per person. Each device checks that its mix holds every
other person's tone and not its own.

- Alice (1 kHz bursts) calls a group of four, and Bob, Carol and Dave all
  ring. Bob and Carol answer, and Dave declines.
  - The 3-way mesh is up ~105 ms after Alice presses call.
  - Alice's voice reaches Bob and Carol in 80–100 ms, mouth to ear, mixed
    with the third person's.
  - Each person is reached on the network path at 32 kbps, with 0 frames
    lost.
- Dave's call stays `joinable` (*3 in call*). He joins with the call button
  and is meshed with all three others in ~52 ms, then hears all three.
- Bob leaves and the others go on. Alice, who started the call, leaves too,
  and Carol and Dave still hear each other. When Carol leaves, Dave's call
  ends (`remoteHungUp`).
- Outsiders are refused. Eve, not in the group, sends `Join`, `Watch` or
  `Ring` with the real call reference. Both devices in the call answer
  `Denied` and nothing shows up.
- Carol is removed from the group mid-call, then tries to join. Her join
  ends `failed` and nobody hears her: for 2 s, checked every 100 ms, neither
  device has her joined or a level for her, and her tone stays below both the
  noise-floor bound and 5 % of the other voice.
- With no IP at all, three devices on fast in-memory links hold a 3-way
  call.
- `group_call_between_runtimes` runs the same flow through the JSON command
  table: `group`, `title`, `participants` and `joinedCount`.

### Several devices on one computer, real UI

Three `mycel serve --net lan` devices (Alice, Bob, Carol) plus one
`mycel keeper --net lan`, each a separate process with its own identity and
storage. The real web UI was driven in headless Chrome.

| Step | Result |
|---|---|
| Discovery | Alice saw Bob and Carol by name over mDNS, no codes exchanged |
| DM | Alice → Bob over the LAN. Bob got it with an unread badge |
| Reply + file | Bob replied with a file. Alice saw it, and her message went to read |
| Download + reaction | Alice fetched the encrypted file from Bob peer-to-peer, decrypted it, and reacted |
| Group | Alice created a group with Bob and Carol; Carol received it |
| Keeper | Alice added the keeper; it joined and stored the group's ciphertext |
| Offline delivery | Bob quit. Alice sent, then quit too. Bob restarted while Alice was offline and still received the message from the keeper and peers |
| Message request | Alice started a chat with Bob, who didn't have her as a contact: Bob saw it under Requests, with the composer hidden; he accepted and replied, and Alice received the reply |
| No internet | `lsof` on every Mycel process showed only mDNS (UDP 5353), local QUIC sockets and the localhost UI. No relay, DNS or other outbound internet connections |

To run it yourself:

```sh
cargo build -p mycel-cli && npm install && npm run build
./target/debug/mycel serve --data /tmp/a --name Alice --net lan --http 127.0.0.1:7701 &
./target/debug/mycel serve --data /tmp/b --name Bob   --net lan --http 127.0.0.1:7702 &
open http://127.0.0.1:7701 http://127.0.0.1:7702
```

### Local HTTP API hardening

Requests made with curl against a live `mycel serve`:

| Request | Result |
|---|---|
| No token | 403 |
| Old static marker | 403 |
| Wrong `Host` (DNS rebinding) | 403 |
| `identity.key` via `/api/file` | 403 |
| Events without the token | 403 |
| Attachment from outside `uploads/` | refused |
| Correct token | 200 |

The token file is mode `0600`.

### Large attachments

Two `mycel serve` devices in a debug build. The file was uploaded over
`/api/upload` with `curl -T` (streamed), sent with `send_message`, then
fetched with `fetch_attachment` on the other device. Memory was sampled with
`ps -o rss` every 0.5 s.

| File | Mode | Upload + encrypt | Fetch + decrypt | sha256 | Peak RSS (alice / bob) |
|---|---|---|---|---|---|
| 200 MiB random | `--net local` | 1 s + 1 s | 6 s | match | 42 / 40 MB (baseline 29 / 29) |
| 1 GiB random | `--net lan` | 1 s + 3 s | 21 s | match | 42 / 39 MB (baseline 30 / 32) |

`/api/file` served the 1 GiB file back byte-exact. A `Range: bytes=100-199`
request got `206` with `content-range: bytes 100-199/1073741824`.

In the real UI, a 300 MB file attached with the file picker was delivered in
about 7 s. Bob's download, with a progress bar, took about 5 s, sha256
identical, with Bob's process at 39 MB of memory.

### Peer-to-peer Wi-Fi, two processes on one Mac

Two devices with `MYCEL_IP=0` (no Wi-Fi or Ethernet IP transport at all, only
links):

- Each found the other over the Bonjour peer-to-peer service.
  `network_status` showed `available: ["peerWifi"]`, `via: "peerWifi"`.
- A message and a 20 MB attachment went A → B. The file's sha256 matched, and
  A's message went to *delivered*.
- `lsof` on B: the only peer sockets were UDP on `fe80…%awdl0`, plus mDNS.

On one Mac the AWDL traffic loops locally, so this doesn't test the radio
between two devices.

### Multipath aggregation, connection reuse, multi-source downloads

#### Aggregation

`crates/mycel-net/tests/aggregate.rs` joins two endpoints with no IP by
rate-limited in-memory links with 5 ms latency, and sends one QUIC stream.
Debug build.

```sh
cargo test -p mycel-net --test aggregate -- --nocapture --test-threads=1
```

| Links | Throughput | Bytes per path |
|---|---|---|
| one 10 MB/s link | 8.3–8.5 MB/s | all on it |
| two 10 MB/s links | 16.0–16.5 MB/s (1.91–1.97×) | ≈ 20–26 MB on each |
| two links, one cut at 25 % | 40 MB in ≈ 11 s | the live one takes over after ≈ 5 s |
| 10 MB/s + 20 KB/s Bluetooth | 7.9–8.3 MB/s (fast link alone: 8.0–8.3) | Bluetooth 0.0 MB (backup) |
| 10 MB/s + a slow link (300 KB/s, 60 ms) | 7.7–8.2 MB/s | slow link 0.2–0.3 MB |

The single-link figure is under 10 MB/s because the in-memory "radio" drops
packets once its 250 ms queue is full, and Cubic keeps filling it.

In the cut case, the bytes that were in flight on the dead path are resent
only when that path's 5 s idle timeout closes it (noq requeues them when it
discards the path). Until then the stream is held up at that hole. So a cut
costs about 5 s, then everything continues on the live path.

#### Connection reuse

`crates/mycel-net/tests/pool.rs`, two nodes on loopback:

| Measurement | Result |
|---|---|
| First sync, with the handshake | 24–37 ms |
| Each later sync on the pooled connection | 2.0–4.0 ms |
| 20 syncs + a card + a typing message | 1 dial, 1 accepted connection |
| Next sync after the peer restarts on the same port (a redial) | 26–30 ms |

#### Multi-source download

`crates/mycel-net/tests/multisource.rs`, each source on its own 4 MB/s link to
the downloader:

| Measurement | Result |
|---|---|
| One source | 3.6–3.7 MB/s |
| Three sources | 9.4–9.7 MB/s (2.6×) |
| One source shut down a third of the way in | the 24 MiB finished in about 3.0 s from the other two, hash-checked and byte-exact |
| Served by each source | 8–13 MB |

#### Two devices on one computer

Two `mycel serve --net local` processes in debug builds, driven over the HTTP
API by `scripts/net-bench.py`, before and after pooled connections:

| Measurement | One connection per exchange | Pooled connection |
|---|---|---|
| 10 consecutive messages, send → visible on the other device | 92–104 ms each (median 94) | 11–20 ms (first 20, median 12) |
| first message after 65 s quiet | n/a | 24 ms (the 15 s periodic sync keeps the pooled connection warm) |
| 1 GiB attachment: fetch + decrypt | 141.7 s (8 MB/s) | 111.9–131.6 s (8–10 MB/s); release build 100.6 s (11 MB/s) |
| sha256 / peak RSS (alice / bob) | match / 43 / 36 MB | match / 47–52 / 36–39 MB |

Message latency was mostly an 80 ms debounce, which made sense while every
sync paid a handshake. On a pooled connection a sync is one stream, so
changes are pushed after 5 ms, and a change made while a sync to that peer is
running triggers one more sync.

To run it:

```sh
head -c 1073741824 /dev/urandom > /tmp/big.bin
python3 scripts/net-bench.py target/debug/mycel /tmp/bench after /tmp/big.bin [--cold]
```

The script starts both devices (`--net local`, ports 7811 and 7812), exchanges
contact codes, creates a direct conversation, then times messages and the
attachment.

#### The loopback ceiling

The 1 GiB transfer over loopback is capped by the platform, not by Mycel. A
bare QUIC stream between two plain upstream Iroh 1.3.0 endpoints (no Mycel
code, no patch) on the same Mac does 9–10 MB/s over 127.0.0.1 and over the
Mac's own interface address. That is with no loss, a 1.4–2.6 ms RTT and a
300 MB congestion window, and it is the same with noq-udp's
`fast-apple-datapath`. Mycel's own figures match it.

With only loopback, aggregation can't show a real gain, so the aggregation
numbers above come from the in-memory links. The LAN-mode run under [Large
attachments](#large-attachments) took 21 s per GiB, which is faster than
this. The difference is unexplained.

### Mesh relaying

`crates/mycel-net/tests/mesh.rs` and `tests/links.rs` use in-memory links, one
per radio "edge". Unit tests are in `src/mesh/`.

| Test | Where | Result |
|---|---|---|
| A–B–C, where A and C have no direct link, sync through B | `line_a_b_c_syncs_through_a_non_member` | B is in no space and none of the plaintext crosses it (every relayed byte is inspected) |
| Two disjoint relays, A–B–C and A–D–C, over 400 KB/s links, one stream | `two_routes_aggregate_and_fail_over` | 1.8–1.9× one relay (4 MB, five runs); the transfer survives B leaving mid-way |
| A 5-device line | `five_device_line_latency_per_hop` | reaches 4 hops; ≈0.1 ms per hop on a round trip |
| The middle device leaves | `route_heals_when_a_middle_device_leaves` | the route heals over a longer path after ≈5 s |
| A 6-device ring | `ring_has_no_storms_or_loops` | no more announcements than predicted; nothing loops (no TTL drops) |
| A 100 KB/s relay budget | `relay_budget_is_enforced` | the budget holds; a non-relaying device isn't routed through |
| Hops over a fast link, then a Bluetooth-like one | `hops_over_peer_wifi_and_bluetooth` | ok |
| A hop whose fast link is cut mid-transfer | `a_hop_moves_between_its_links` | carries on over its Bluetooth-like link |
| A live QUIC connection moves to another link mid-transfer (no mesh) | `tests/links.rs` `live_connection_moves_to_another_link` | failover ≈5 s |

### Global routing and store-and-forward

| Test | Where | Result |
|---|---|---|
| Learn routes across a new link: 2 hops / up to 8 hops | `mesh::core::tests::convergence_time_to_learn_new_routes` | 0.4 s / 1.4 s (500 ms period, 5 ms hops) |
| A dead route stops being used | `convergence_dead_route_stops_being_used` | 25 ms (retraction) |
| A ring heals around a cut | `convergence_heals_around_a_ring_without_loops` | 0.6 s, 0 loops |
| 60 link flaps, 30-device mesh, traffic | `churn_never_loops` | 0 frame loops, 0 route loops |
| Gateway by total cost (far fast uplink beats near slow one) | `gateway_choice_by_total_cost` | ok |
| BLE-only US (3 hops from its gateway) ↔ BLE-only EU, live sync | `tests/global.rs` | first sync 0.58 s; relays and gateways hold no space |
| Test-tone call along that route | `mycel-call` `call_across_two_gateways_and_the_internet` | RTT 84 ms, ~137 ms mouth-to-ear, 0 % loss |
| Two gateways for one device | `two_gateways_are_two_paths_and_fail_over` | 2.0× one path; one lost: longest pause 0.8–2.6 s |
| Partial route → custody → delivery; mailbox; receipts; budgets | `mesh::dtn::tests` | ok |
| Offers refused before the payload; full neighbours skipped; resume; lifetimes from creation; per-source eviction; copies by size; copies in flight | `mesh::dtn::tests` | ok |
| Spray then the internet gradient vs Spray-and-Wait, 4 clusters in a chain, 40 traces | `gradient_beats_spray_and_wait` | 28 min mean vs undelivered in 12 h |
| Data mule across partitions (real QUIC) | `a_data_mule_carries_a_message_across_partitions` | delivered 1 s after meeting; short-lived bundle expired at the mule |
| A relay carries between two devices behind routers, both ways, and for nobody who didn't ask | `mesh::core::tests::a_relay_carries_between_two_devices_behind_routers`, `no_relaying_between_live_hops_without_a_client` | ok |
| Relay clients bounded, forgotten when they stop asking; relay hops redialed and never idled out; a separate budget; nothing over a metered uplink | `relay_clients_are_bounded_and_lapse`, `relay_hops_are_redialed_and_never_idle_out`, `relaying_between_internet_hops_has_its_own_budget`, `a_metered_device_is_no_gateway_and_no_relay` | ok |
| Two devices behind routers sync through a third device, no relay server (real QUIC) | `tests/relay.rs` `two_devices_behind_routers_sync_through_a_relay` | behind the relay after 4.4 s; first sync 5 ms; the relay holds no space |
| Two relays for one device | `two_relays_are_two_paths_and_one_can_go` | a path through each, then a direct path too; 200 kB delivered after one relay went |
| Only devices whose record says they relay are asked | `only_devices_that_say_they_relay_are_asked` | ok |
| A relay found in a contact's record | `a_relay_is_learned_from_a_contacts_record` | ok |
| A device's own record follows its addresses and role; private addresses never published | `mesh::records::tests`, `mesh::directory::tests` | ok |

To run them with their output:

```sh
cargo test -p mycel-net mesh -- --nocapture
cargo test -p mycel-net --test global -- --nocapture
cargo test -p mycel-net --test relay -- --nocapture
```

In these tests the internet is loopback IP between the devices that have it,
and the global record directory is shared in memory. What that leaves
untested is under [On real networks](#on-real-networks).

### Phones and the other platforms

Simulators and an emulator ran on a Mac, with a desktop peer from
`mycel serve`. Android was driven through its real UI with `adb shell input`,
plus Chrome DevTools on the debug build. The iOS Simulator was checked from
screenshots and the app's log, and the on-screen keyboard with an XCUITest
(`apps/host/ios-uitests`).

#### Startup and layout

On the iPhone 18 Pro and iPad Pro 11" simulators (iOS 27) and the Pixel 7
emulator (Android 14):

| Test | Result |
|---|---|
| App starts, runtime opens, profile named after the device | ok |
| Layout under the status bar / notch / home indicator / navigation bar | phone layout edge to edge; iPad two-pane layout |

#### iOS Simulator

| Test | Result |
|---|---|
| Desktop peer → phone: message request arrives (iPhone simulator, found over mDNS) | ok, a few seconds |
| On-screen keyboard (iPhone 18 Pro simulator, XCUITest) | header on screen, composer just above the keyboard's bar, also after sending; the message arrives at the desktop peer |
| Bluetooth without the hardware (iPhone simulator) | Bluetooth reports "Unsupported" and the app carries on |

iOS slides the page under the keyboard and shrinks `innerHeight` too, so the
app sizes itself to the visible part.

#### Android emulator

| Test | Result |
|---|---|
| Desktop peer → phone: message request arrives (release APK, contact code, emulator behind NAT) | ok, a few seconds |
| Phone → desktop: add contact, send, reply (DevTools, then the real UI) | ok both ways; replied through the on-screen keyboard |
| On-screen keyboard | page shrinks above the keyboard, composer stays in sight, tab bar hides while typing |
| Back button | closes the keyboard, then returns from a conversation to the list; from the list it leaves the app |
| Attachments from a desktop peer (PNG + text file) | both arrive; the photo downloads and shows inline; the text file opens in the system viewer through the FileProvider ("Open with") |
| Sending a file from the phone (staged in two pieces, base64 over IPC) | arrives intact at the desktop peer |
| Voice call setup | system microphone prompt on the first call, then the desktop peer rings; hang-up shows "missed" there (no audio device in the emulator) |
| Keyframes from the phone, counted in 12–15 s captures at the desktop | 2 of 118 frames (one asked for); otherwise one every 10 s |

In the background and swiped away, the foreground service keeps the runtime
running. Messages from the desktop peer arrive and show a notification, also
after swiping Mycel away, and reopening shows them. There is no notification
while Mycel is in front.

A video call ran both ways between the emulator's virtual camera and a
desktop peer with `MYCEL_VIDEO=test`. The phone shows the desktop's 720p at
~30 fps, and the desktop receives the phone's 720×1280. The phone's frames,
captured from the desktop's video stream, decode with ffmpeg (Constrained
Baseline, no errors). The emulator's software codec is slow, so it sends
~10–20 fps.

#### Linux and Windows on GitHub Actions

The core tests pass on Linux and Windows in an optimised build. On Windows a
1 ms sleep takes 14.4 ms with the default timer and 2.4 ms with the 1 ms timer
Mycel asks for (`crates/mycel-net/tests/timers.rs`).

The Linux and Windows apps launch in the smoke test: the runtime opens, the
app is still running after the wait, and the UI renders (WebKitGTK and
WebView2 screenshots). Linux takes ~25 s to open on the bare runner. A thread
dump shows GTK's `g_application_register` waiting on a desktop D-Bus service
that isn't there, before Mycel's code runs.

Sending video from the Linux and Windows web views was probed with no camera,
using `scripts/ci/video-probe.html`. The page captures, then encodes H.264
with WebCodecs as `packages/sdk/src/webcam.ts` does.

| Web view | Camera | Result |
|---|---|---|
| Edge 153 | fake camera | 30 frames, avcC, software encoder (no GPU) |
| WebKitGTK 2.50.4 (Ubuntu 22.04) and 2.52.6 (24.04) | WebKit's mock camera | 30 frames, avcC, through a canvas |

WebKitGTK has no H.264 encoder until GStreamer's x264 or openh264 is
installed. With one installed, frames straight from the camera `<video>` fail
("Encoding failed"), while synthetic frames and the camera drawn on a canvas
encode. So the app goes through a canvas.

The rules engine gives the same verdicts and uses the same fuel at every
optimisation level. The `mycel-rules` tests at opt-level 2 report the same
verdicts and fuel (56,749 for a 16 KiB message) with wasmi's portable
dispatch. wasmi's tail-call dispatch overflowed a 2 MiB thread stack there.

### Timing on the macOS CI runner

The hosted macOS runner is a virtual Mac whose jobs behave as if they ran at
utility QoS. That is inferred, not read off the runner: under
`taskpolicy -c utility` a local run fails in exactly the CI way, with the
same numbers, and passes with the fixes below.

At utility QoS the kernel coalesces timers, so an ordinary thread's short
sleep oversleeps by a lot. Measured on the 18-core Mac with `thread::sleep`,
200 samples, p50–p90: a 3 ms sleep takes 4.5 ms normally but 17–27 ms under
`taskpolicy -c utility`, and a 10 ms sleep takes 66–90 ms.

That is what failed CI:

| What | Expected | On the runner |
|---|---|---|
| Test camera | 30 frames/s | 10–13 frames/s |
| Fake Bluetooth radio | 40 KiB/s | 5.4 KiB/s |
| Calls | no build-up | built up 300 ms of delay |

All three reproduce exactly under `taskpolicy -c utility`. The radio test
gave the same 5.4 KiB/s, 13 % of raw.

#### Fixes

The fixes are tested under `taskpolicy -c utility` too.

- Media threads (a call's send and play threads, the test audio device, the
  test camera) ask for real-time scheduling through `mycel_video::realtime`,
  the time-constraint policy Core Audio gives its own I/O threads. A promoted
  thread's 3 ms sleep takes 3.01 ms (p99 3.04 ms), throttled or not. This
  matters outside CI too: an app in the background is throttled the same way,
  and its call must not fall behind.
- Emulated radios count the time that actually passed, not the time they
  asked to sleep. The fake radio's goodput is 30.8 KiB/s throttled and
  31.5 KiB/s normal, and the busiest channel carries 39.1–39.8 KiB/s of its
  40. The radio step is a function of the clock, tested with late wake-ups
  and stalls, and the bulk-sync test also fails if the radio ever carries
  more than its rate.
- `recovers_from_lost_frames_with_keyframes` failed on the runner too. It now
  measures the frame rate over 2 s, not 1 s: a 1 s window read a throttled
  25-26 frames as exactly 25.0 fps, its bar.
- Tests that time a call (mouth-to-ear latency) run alone in their test
  binary (`cpu_alone`); the others share the CPU. Throttled, with 18 CPU
  burners alongside, mouth-to-ear is 75–95 ms 1:1 and 80–100 ms in the 3-way
  call. It was 207 ms when the latency test ran beside nine others.

#### Checks on the real-time promotion

The promotion is checked on any Mac, throttled or not. A test re-runs itself
under `taskpolicy -c utility` and requires a promoted thread's 3 ms sleeps to
wake under 2 ms late (p90). Measured, they wake 10–14 µs late (p90), while an
ordinary thread beside it woke 12–16 ms late (p50).

A test also reads the stored policy back. XNU raises `computation` to half
the period whatever is asked, so a call thread may run 10 ms per wake-up at
real-time priority.

The darwin background band (`taskpolicy -b`) is throttled even for real-time
threads (175–195 ms sleeps, measured in review). If the runner ever moved
there, these fixes would stop working, so the macOS test job first logs how
late a 3 ms sleep wakes, in the step named Timer probe.

#### Encoder returns nothing at 160×90 on the runner

This is not explained. On the runner, VideoToolbox's low-latency encoder
returned nothing at 160×90 in `encode_decode_round_trip_with_scaling`.
1280×720 and 424×240 were fine, and so is 160×90 on a real Mac, with the
hardware or the software encoder, throttled or not. The runner has no
hardware scaler ("IOServiceMatching failed for AppleM2ScalerParavirtDriver"),
and 160×90 is the only size in that test scaled down more than 4× from its
720p source.

Wherever this happens it would mean no video on Bluetooth, so the encoder now
handles it. A session that stops answering is replaced by the next mode: the
default encoder, pictures scaled first by a pixel transfer session or the
CPU, then the software encoder ([ARCHITECTURE.md](ARCHITECTURE.md) describes
the video path). Tests force each step: a session that never answers, one
that only drops, CPU scaling 8× down, and no mode left.

Whether this makes the test pass on the runner has not been verified.

### Real hardware

This is what has run on real devices.

- Macs: the app on the LAN; a Mac's Bluetooth advertising, L2CAP publishing
  and scanning (a Mac can't connect to itself, so a link needs two devices);
  peer-to-peer Wi-Fi between two processes on one Mac
  ([above](#peer-to-peer-wi-fi-two-processes-on-one-mac)).
- iPhone: LAN discovery through the system's Bonjour, found by Macs and
  finding them; Bluetooth links between the iPhone and Macs.

Bluetooth on real radios has had far less time than over emulated links, and
real sessions have seen channels drop and be redialed. What has not run
between real devices is listed [below](#between-real-devices).

## What is not tested

### On real networks

No test that runs by default covers:

- the public DHT and n0's relay and DNS servers;
- the reachability check and the mobile-data check on real networks;
- a relayed connection moving to a direct path through real routers.

Two tests do use the real internet and are ignored unless asked for. One
checks that a device's record reaches n0's DNS server and is read back. The
other joins the DHT with no relay or DNS server. They publish this computer's
records under throwaway keys, with no IP address:

```sh
cargo test -p mycel-net --features dht --test internet -- --ignored --nocapture
```

### Between real devices

Not tested between real devices:

- peer-to-peer Wi-Fi (AWDL) on macOS and iOS;
- Bluetooth through BlueZ on Linux;
- Wi-Fi Direct group formation on Linux;
- the interface link with UWB or 802.15.4 hardware.

These are built and tested on emulated links, and the Linux code in CI.

Not run on real hardware at all:

- the iPhone camera;
- Android on a physical phone;
- the Windows and Linux apps on desktop machines.

### In CI

- The test job in `ci.yml` names the crates it runs. It leaves out
  `mycel-link-awdl`, `mycel-rules-abi` and `mycel-sim`, so run those suites
  locally.
- `mycel-host` is tested by the Apps workflow, which does not run on pull
  requests.
- Three LAN discovery tests are skipped on the macOS runner and run on Linux
  and Windows only.
- Video encoding and decoding need VideoToolbox, so the video tests in
  `mycel-video` and `mycel-call` run in the macOS job only.
- Ignored tests never run in CI.
