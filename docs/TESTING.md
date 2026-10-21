# Testing Mycel

What the tests cover, how to run them, and what was measured. Results that
depend on hardware were measured on one Mac (18 cores, 24 GB) unless a
section says otherwise. Simulation and benchmark results are in
[SIMULATION.md](SIMULATION.md) and [BENCHMARKS.md](BENCHMARKS.md).

## Running the tests

```sh
cargo test --workspace --exclude mycel-host   # about 500 Rust tests
cargo test -p mycel-host --lib                # the host's own tests (needs the webview libraries)
cargo clippy --workspace --all-targets -- -D warnings
npm install && npm run typecheck && npm test  # SDK, Messaging and host (Node 22.18 or later)
npm run build                                 # the UI
scripts/security-check.sh                     # security regressions, npm audit, RustSec advisories
(cd apps/host/src-tauri/gen/android && ./gradlew :app:testArm64DebugUnitTest)  # Android JVM tests (JDK 17, Android SDK)
```

- `cargo test -p mycel-sim` runs the simulator's scenarios at CI size;
  `-- --ignored` runs the full sizes (see [SIMULATION.md](SIMULATION.md)).
- Tests that measure speed or time emulated radios (video frame rates, mesh
  throughput, link failover, real-time simulator scenarios) run one at a time
  within each test binary, and can still miss their deadlines on a heavily
  loaded machine.
- On a Mac, three tests need the terminal to have Local Network access
  (`lan_discovery_via_mdns`, `one_path_per_interface`,
  `sync_over_an_interface_with_ip_off`). Without it they fail with "No route
  to host": allow it in System Settings > Privacy & Security > Local Network.
- Most tests start real nodes speaking real QUIC, over loopback or over
  in-memory links with a set rate, latency and loss (`mycel_net::MemNet`,
  `mycel_net::emu::EmuNet`). Emulated links can carry any medium label
  (`PathKind`), so path selection, aggregation and failover are tested
  between media the test machine doesn't have.

**In CI** (`.github/workflows/ci.yml`, on every pull request and push to
`main`): rustfmt; clippy with `-D warnings` and the tests, in optimised
builds, on Linux, macOS and Windows; the security regression tests with no
retries; rustdoc with `-D warnings`; the WebAssembly rules; cargo-deny
(advisories, licences, duplicate and unknown sources, `deny.toml`); the web
checks; spelling; and the workflows themselves (actionlint, zizmor). The
Fuzz workflow runs every fuzz target ([Fuzzing](#fuzzing)) briefly on pull
requests and for ten minutes each night. The
Apps workflow builds and launches the Linux and Windows apps. CodeQL and
OpenSSF Scorecard run on their own schedules. On the small CI machines, one timing test
usually misses its deadline somewhere in a run, a different one each time:
CI retries a failed test twice (`scripts/ci/retry-failed.py`) and flags one
that then passes as a "Flaky test" warning; one that fails three times fails
the run.

**Timing on the macOS runner.** The hosted macOS runner is a virtual Mac
whose jobs behave as if they ran at utility QoS. That is inferred, not
read off the runner: under `taskpolicy -c utility` a local run fails in
exactly the CI way, with the same numbers, and passes with the fixes below.
At utility QoS the kernel coalesces timers, so an ordinary thread's short
sleep oversleeps by a lot. Measured on the 18-core Mac (`thread::sleep`, 200 samples, p50–p90):
3 ms takes 4.5 ms normally but 17–27 ms under `taskpolicy -c utility`, and
10 ms takes 66–90 ms. That is what failed CI: the test camera made 10–13
frames/s instead of 30, the fake Bluetooth radio moved 5.4 KiB/s instead
of 40, and calls built up 300 ms of delay. All three reproduce exactly under
`taskpolicy -c utility` (the radio test gave the same 5.4 KiB/s, 13 % of
raw). The fixes, now tested that way too:
- Media threads (a call's send and play threads, the test audio device, the
  test camera) ask for real-time scheduling (`mycel_video::realtime`, the
  time-constraint policy Core Audio gives its own I/O threads). A promoted
  thread's 3 ms sleep takes 3.01 ms (p99 3.04 ms) throttled or not. This
  matters outside CI too: an app in the background is throttled the same
  way, and its call must not fall behind.
- Emulated radios count the time that actually passed, not the time they
  asked to sleep (fake radio: 30.8 KiB/s goodput throttled, 31.5 KiB/s
  normal; the busiest channel carries 39.1–39.8 KiB/s of its 40). The radio
  step is a function of the clock, tested with late wake-ups and stalls, and
  the bulk-sync test also fails if the radio ever carries more than its rate.
- `recovers_from_lost_frames_with_keyframes` failed on the runner too; it
  now measures the frame rate over 2 s, not 1 s (a 1 s window read a
  throttled 25-26 frames as exactly 25.0 fps, its bar).

The real-time promotion is checked on any Mac, throttled or not: a test
re-runs itself under `taskpolicy -c utility` and requires a promoted
thread's 3 ms sleeps to wake under 2 ms late (p90); measured, 10–14 µs
late (p90), while an ordinary thread beside it woke 12–16 ms late (p50). A test
also reads the stored policy back: XNU raises `computation` to half the
period whatever is asked, so a call thread may run 10 ms per wake-up at
real-time priority. The darwin background band (`taskpolicy -b`) is
throttled even for real-time threads (175–195 ms sleeps, measured in
review); if the runner
ever moved there these fixes would stop working, so the macOS test job
first logs how late a 3 ms sleep wakes ("Timer probe").
- Tests that time a call (mouth-to-ear latency) run alone in their test
  binary (`cpu_alone`); the others share the CPU. Throttled, with 18 CPU
  burners alongside, mouth-to-ear is 75–95 ms 1:1 and 80–100 ms in the
  3-way call (it was 207 ms when the latency test ran beside nine others).

Not explained: on the runner, VideoToolbox's low-latency encoder returned
nothing at 160×90 in `encode_decode_round_trip_with_scaling` (1280×720 and
424×240 were fine, and so is 160×90 on a real Mac, hardware or software
encoder, throttled or not). The runner has no hardware scaler
("IOServiceMatching failed for AppleM2ScalerParavirtDriver"), and 160×90 is
the only size in that test scaled down more than 4× from its 720p source. Since it would
mean no video on Bluetooth wherever it happens, the encoder now handles it:
a session that stops answering is replaced by the next mode (default
encoder, pictures scaled first by a pixel transfer session or the CPU, the
software encoder; ARCHITECTURE.md, Video). Tests force each step (a session
that never answers, one that only drops, CPU scaling 8× down, no mode
left). Whether this makes the runner pass is not verified: this branch has
not run on the runner yet.

**Before merging to `main`:** the workspace tests pass twice in a row, clippy
is clean with `-D warnings`, `cargo fmt --all --check` passes, and `npm run build` passes if TypeScript changed. Iroh, noq,
swarm-discovery, swift-rs and the notification plugin are vendored with
small patches: read the `MYCEL_PATCH.md` next to each before touching them.
Built apps (`dist-release/`) and contact-trace data (`bench/data/`) are never
committed.

## Automated tests by crate

| Crate | What the tests prove |
|---|---|
| `mycel-crypto` | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper detection; **streaming attachment AEAD**: chunk-boundary sizes (0, 1, exactly one chunk, many), tamper, wrong key/nonce/AAD, truncation, extension, reorder/duplicate, chunk-size change, legacy one-shot detection, incremental digest == one-shot |
| `mycel-trust` | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped**; a fan-out of invalid ops can't block a revocation, wide valid frontiers aren't truncated, pending-pool limits per author; **differential tests**: the incremental resolver against the from-scratch oracle (`resolve_full`) on random concurrent histories (revocation storms, mutual revocation cycles, equivocation, out-of-order and duplicate delivery, an `Add` and the added member's revocation in one update, revocation spam), checked after every insert, with and without the fast path; both resolvers see the same admitted op set, so admission rule A2 (below) sits in front of both (`PROPTEST_CASES=<n>` for a longer run); **admission rule A2**: only keys added by an ever-admin are named, whatever the arrival order; a batch in any order (a restore in key order, a chain of admins, seeded shuffles) admits what a causal one does; an op before its author's `Add` is admitted once the `Add` arrives; the unnamed pool is bounded |
| `mycel-sync` | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere**; decompression and run-length expansion bombs, malformed and deferred changes, declared-history checks (actor sequence, counters, object references), delivery-order and restore consistency, large pastes split and accepted |
| `mycel-sync` (Sync v2) | `reconcile/tests.rs`: session matrix on the model set (idle in one round trip at 10 and 1,000 envelopes per author; one new envelope; catch-up with and without a record; both sides missing different things; gaps; forks at the start, middle and tip, then the next session stays in phase 1; three-way fork and seq reuse; an equivocation flood beyond the listed heads; > 256 authors; items arriving mid-session stay in phase 1; a broken session resumes without resending; refused items settle into `Unchanged`; a lost record). Seeded property tests: two replicas with random divergent sets (forks, gaps, pending ops, an attacker's junk from authors nobody may write) converge to the union of what they may hold, 300 worlds; 3–5 peers syncing pairwise reach one set. The incremental chain index equals a rebuild in any insertion order; equal heads with different gaps give different digests; the envelope window. Adversarial frames: malformed, out of order, oversized frontiers, data floods, probe floods, a lying frontier or `Close`, the send budget (and raising it mid-session), version and feature mismatches; a fresh peer (frontier caps for knowing no authors) catching up with a peer listing 1,500 authors, in both roles. Real replicas: every item still validated (reader writes stay invalid), forged and outsider items in a chunk refused, an equivocating author's branches reach every peer. `bench_sync_v2` (ignored, release): BENCHMARKS.md §8 |
| `mycel-sync` (Sync v2 stage 3) | `reconcile/gossip_tests.rs` (model sets, in-memory network, real sessions for pulls): a write reaches a 12-member group with 11 payload copies after warm-up; groups of 6 are a full mesh; 10, 50 and 200 members: degree ≤ 12, every device keeps edges, the overlay is connected and symmetric; three radio clusters joined by random edges; a duplicate push prunes the edge to lazy; a device that misses pushes is repaired by `IHave`, graft and pull; a 500-item change is announced and pulled, not pushed; a graft beyond the degree cap is dropped with alternatives; a flooding author can't starve another on a slow link (the quiet author's items leave within the first 9 of 63); `Have` removes queued items; a new item over 1 KiB is announced with `Have` before forwarding; seen notes ride once per neighbour; limits. Regressions from the QUIC benchmark (each failed before its fix): a session from outside the neighbours that is faster than the tree, three per message for six messages with jittered delivery, leaves the eager edges one spanning tree and the next message needs no repair (`a_session_faster_than_the_tree_does_not_cut_it`); an edge lazy at one end only is repaired by the next messages and both ends agree; a push from a non-neighbour over the degree cap gets a dropping prune; one announcer is grafted and pulled at a time; an author hears back from the neighbours its push reached. The model network can deliver with jitter (2–60 ms, any order). `tests.rs`: an arrival re-checks only the envelopes waiting for it (2 status checks with 1,000 pending, finding 5); holders follow from runs (v1 inventory in any order, a verified frontier; one run in memory, not one entry per envelope); seen notes are sealed (no plaintext), signed, one per interval, replays, tampering and non-members refused. `bench_gossip_dissemination_cost` and `bench_gossip_jittered` (ignored): BENCHMARKS.md §8.1 |
| `mycel-net` (Sync v2 stage 3) | `tests/sync_v2.rs`: gossip reaches a 12-member group over QUIC with ≤ 1.5 payload copies per member and ≤ 2 sessions per message (measured: 12 copies, 0 sessions, 52 ms); a v2 node serves a v1 peer one v1 session per space per 5 s (the excess is `Busy` to a current build); a 10-member group's message now takes 0 sessions (gossip). Unit: `busy_never_falls_back_to_v1` (Busy over QUIC: no fallback, nothing remembered, no v1 session), `a_hung_hello_falls_back_to_v1_quickly` (a hello that never answers holds a sync ≤ 3 s, not 60), v1 sessions served once per interval per (peer, space), hop hellos carry no node capability (`hops_negotiate_versions_and_capabilities`), sealed bundles hide the space, members and headers and open only for the destination, oldest-missing-first incremental selection (causal op prefix, skip what is in flight, start above what the peer holds), plaintext dedup and the 3 MiB per-source budget, PADMÉ overhead ≤ 12%; the data-mule test (`tests/global.rs`) now carries a sealed bundle. `tests/sync_v2_bench.rs` (ignored): BENCHMARKS.md §8.1 |
| `mycel-net` (Sync v2) | `tests/sync_v2.rs`, real QUIC: an idle check between two nodes is 261 B on the stream; Sync v2 is chosen by capability: a node without it doesn't advertise `SYNC_V2`, so a v2 node syncs it with v1 without trying v2 (no fallback), its v1 sessions are served, and a `SyncV2` stream opened to it anyway is reset at once with `STREAM_REFUSED`; an unknown stream kind is reset at once with `STREAM_REFUSED`; one message in a 10-member group takes 45–57 sessions (v1: ~90); a catch-up longer than a reply timeout over a 25 kB/s emulated radio link; explicit syncs from both sides at the same moment both succeed and leave no backoff (20 rounds); a two-way catch-up of 13 MB each way at once, with no failed session and at most 1.1× the payload sent; invites and `Removed` proofs with 1.4 MB of membership history; an eager frontier over 300 authors to a device that answers `NeedInvite`. Unit: the periodic backoff schedule (15 s → 600 s, reset on loss), one session per (peer, space) in either role, phase-2 slots reserved and refunded, ambiguous refusals remembered the second time; `version_tests::a_refused_sync_v2_falls_back_and_is_remembered`: two current nodes use v2, and a `SyncV2` stream a peer refuses all the same falls back to v1 and is remembered at once |
| `mycel-net` | **Bandwidth aggregation** (`aggregate.rs`, no IP, rate-limited in-memory links): one stream over two 10 MB/s links ≈ 1.9× one link; one link cut a quarter of the way in, the transfer still completes; a fast link + 20 KB/s Bluetooth, and a fast link + a slow 300 KB/s / 60 ms one, never drop below the fast link alone. **Connection reuse** (`pool.rs`): 20 syncs + a card + a typing message = 1 dial / 1 accepted connection; a peer restarted on the same port is redialed; an idle connection is closed and redialed on use. **Multi-source download** (`multisource.rs`): three members hold a 24 MiB blob, each on its own 4 MB/s link; the fourth downloads from all three at ≈2.6× one source, one source is shut down a third of the way in, the rest comes from the other two, hash-checked and byte-exact. **Links**: two devices with no IP at all sync over in-memory links, prefer the faster one, fall back to a Bluetooth-like one; **a live QUIC connection moves to another link mid-transfer** (failover ≈5 s). Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on the test machine**; **40 MiB blob streamed to disk, interrupted (multi-source, out-of-order) download resumed from its `.part` + `.ranges`, corrupt partial copy detected and refetched from another member while the sender is offline, push policy (small → everyone, big → keepers only)**; free-space guard; stream and frame budgets, stalled and progressing I/O, duplicate requests, ephemeral limits; Windows timer resolution (`timers.rs`); the path-open queue doesn't grow (`path_queue.rs`). **Wire versions** (`version_tests`, `version::tests`; docs/PROTOCOL.md §8): a version-1-only node and a version 2 node pick version 1 whoever dials, send no hello, and still sync a space both ways and fetch cards; two version 2 nodes agree on exactly the capabilities both have, unknown bits ignored, one dial and one hello served (counted) for two `negotiate` calls; **a hello the peer drops is counted and retried on the same connection, which then agrees capabilities (bounded tries)**; a full node answers a dialer listing the oldest version first with the newest, on the node protocol and mesh; **8 strangers that dial (v1, and v2 with a hello) leave no peer state**; one ALPN per version per protocol, checked at compile time; an unknown stream kind is refused with a typed error in under 5 s and the connection carries on; an unknown bundle payload kind is refused unread. **Version 1 golden vectors** (`mesh::v1_vectors`): every version 1 encoding (ALPNs, stream kinds, every `SyncMsg`, ephemeral, blob, card, announcement, data-frame header, bundle id/signature, `K_OFFER`, answers, receipt, summary) byte for byte against bytes printed by main `98d9b7b` itself, decoded back (also sync data carrying a signed op and an envelope, every blob request and answer, `T_OGMS`, `T_SEQREQ`, a control frame); **`scripts/v1-compat/run.sh`** (by hand) prints those vectors again with the pre-release code's own encoders and compares them, and runs a node built from `98d9b7b` (or the `dev-2026-10-09-apps` release) against this build: version 1, a space synced both ways, cards fetched; passed against both on 2026-10-21 |
| `mycel-net` mesh | **Multi-hop mesh** (`tests/mesh.rs`, in-memory links, one per radio "edge"; unit tests in `src/mesh/`): A–B–C where A and C have no direct link sync through B, **B is in no space and none of the plaintext crosses it** (every relayed byte is inspected); two disjoint relays A–B–C + A–D–C over 400 KB/s links carry **1.8–1.9× one relay** on one stream (4 MB, five runs) and the transfer survives B leaving mid-way; a 5-device line reaches 4 hops (≈0.1 ms per hop on a round trip); a route heals over a longer path ≈5 s after the middle device leaves; a 6-device ring sends no more announcements than predicted and nothing loops (no TTL drops); a 100 KB/s relay budget holds and a non-relaying device isn't routed through; hops over a fast link then a Bluetooth-like one; a hop whose fast link is cut mid-transfer carries on over its Bluetooth-like link; **a hop over a real network interface link** (`mycel-link-iface/tests/sync.rs`, `lo0`); forged, renamed and replayed announcements rejected; per-neighbour announcement rate limit; fragmentation and re-fragmentation; routing convergence, churn and store-and-forward in virtual time (`mesh/core/tests.rs`, `mesh/dtn/tests.rs`); gateways and the data mule (`tests/global.rs`); **mixed versions**: hops negotiate version 2 and shared capabilities, or version 1 with a pre-release device; a carrier carries a version 2 bundle of an unknown payload kind, refuses an unknown header version, and never offers a version 2 bundle over a version 1 hop (no offer is encoded, and the v1 carrier refuses nothing), also through the planner end to end (a v2 bundle reaches only the v2 neighbour, v1 bundles reach both); unassigned data-frame flags survive relaying and fragmentation |
| `mycel-call` | **Live calls.** Unit: Opus round trip keeps a 440 Hz tone, 12 kbps fits ~1.5 KB/s, PLC and FEC; frame codec and stream fallback framing under arbitrary splits; **jitter buffer**: prebuffering, reorder, loss → FEC from the next frame, late and duplicate frames dropped, target grows with jitter but never past 120 ms, underrun → conceal → rebuffer → resume, bursts trimmed; **bitrate controller** (path ceilings, loss/RTT step-down, slow recovery, FEC loss %); resampler pitch/length across rates; call id binds space + caller + nonce; **state machine**: answer and hang-up from either side, decline, ring timeout on both sides, setup timeout, busy, **both call at once → one call**. Integration (real nodes, real QUIC, test audio): audio both ways with measured latency, mute, hang-up by either side; decline / no answer / missed / busy / **forged rings from a non-member refused**; simultaneous calls merge; **no IP: a call starts on a fast in-memory link, the link is cut, the same call continues over a 20 KB/s Bluetooth-like link at 12 kbps**; datagram → stream fallback; **a call through a mesh relay** (no direct link; 0 % loss, ≈95 ms); group calls (below); video calls both ways, recovery from lost frames, adapting to a slow link; **the playout cushion follows the device's buffer** (25 ms for 10 ms bursts, covers 40 and 60 ms Bluetooth bursts, never over 100 ms, shrinks back after a hiccup); the test audio device paces itself at 10 and 40 ms periods; control messages from a newer variant skipped on a stream (the next one arrives), garbage still an error; video control messages of a newer variant skipped likewise; **call versions by ALPN** (`mycel/call/2` beside `/1`): a message newer than a leg's version is never sent on it, and a device serving only `mycel/call/1` (as pre-release builds do) and a current one call each other both ways on call/1 with audio, two current devices on call/2 |
| `mycel-video` | Rate controller (a budget for every kind of path, ramp-up, back-off when frames queue, pacing, path changes), frame and control wire formats, receiver reordering and keyframe recovery; on Apple platforms, VideoToolbox encode and decode, and camera frames keeping their shape in portrait, landscape and 4:3, one answer from the encoder per frame (a frame, a drop, or a timeout, counted apart), a stalled encoder session replaced by the next mode down to CPU scaling and the software encoder, and an error when none is left; media threads promoted to real-time scheduling wake on time (p90 under 2 ms late for 3 ms sleeps), also when the test re-runs itself throttled, and the kernel's stored policy read back |
| `mycel-node` | Full messaging API on real storage: DMs, delivery → read, replies, reactions, edits, deletes, attachments, **restart persistence**, **keeper delivery while the sender is offline**, group admin removal, **L4 rules rejecting a forged op**, **message requests + declined/blocked strangers stay out**, **contact-code address hints connect without discovery**, **hostile attachment names neutralised**; **voice call refused while the conversation is a message request, then rings, answers, carries audio, mutes and hangs up through the JSON command table**; **120 MiB attachment byte-exact between two nodes with upload/download progress**, **legacy one-shot attachments still open**, **folders sent as .zip via a `file://` URL**, `file://` decoding, **unreadable files explain why** (missing, permission denied → macOS privacy hint); one chat per person across separately created spaces, paging and search, local hide and restore across restarts, attachment consent across restarts, identity and storage fault injection; closing the store releases its file at once, so a restarted runtime opens it even while a straggling task still holds the old handle; **the store records its format (in a `meta` table no migration renames) and a newer one is refused untouched, even with every other table renamed**, `mycel2:` contact codes refused with a typed error, a version 1 contact code pinned byte for byte |
| `mycel-link-awdl` | Control datagrams, TXT records, interface filtering; plus 2 ignored Bonjour loopback tests (`-- --ignored`) |
| `mycel-link-ble` | Framing, bounded queues, connection state machine (who dials, duplicates, timeouts, backoff, address rotation), fake-radio sync between real nodes with IP off, hours of simulated faults between two devices, macOS stream code over in-process pipes; the fake radio's rate holds when its thread wakes late, and is never exceeded; a GATT record or hello with fields a later build appends after the name's NUL still reads |
| `mycel-link-iface` | Interface classification (medium from type and name, software interfaces skipped, ordinary NICs left to IP), environment overrides, beacons; a sync over a real interface with IP off, one path per interface |
| `mycel-kit-chat` | Author-only edits/deletes, reactions, receipts/unread, admin-only meta, garbage tolerance, thread merging (a late alias can't backdate messages; a message written at an alias's first-seen time sorts after that alias's older messages), alerts |
| `mycel-rules(-abi)` | Deterministic WASM engine: fuel/memory limits, banned features, ABI violations, chat rules, wire compatibility with the chat kit, the fuel cost model pinned |
| `mycel-sim` | Every scenario at CI size, and the simulator's own models (`cargo test -p mycel-sim`) |
| `mycel-host` | Log file privacy, notification privacy, deduplication, tap routing and permission handling |
| Web (`npm test`) | SDK paging, search, presence and conversation identity; Messaging layout and swipe gestures; host notices and notification actions |

## Fuzzing

Every decoder that reads bytes from someone else is fuzzed with libFuzzer
(`cargo-fuzz`), with AddressSanitizer, overflow checks and debug assertions
on in every crate, Automerge included. (The main workspace builds Automerge
without overflow checks, because its counters wrap in release builds: see
the counter row below. The targets that apply changes keep counter values
and increments within ±2^32 instead, generating them so or skipping an
input whose crafted change has larger ones, so that every other integer
overflow in Automerge still ends a run.) Bridgefy's mesh fell to one
crafted message because clients forwarded before they parsed
([ePrint 2021/214](https://eprint.iacr.org/2021/214)); here a node parses and checks everything before acting on it, and these
targets look for inputs where the parsing itself panics, hangs or allocates
without bound.

The targets live in `fuzz/`, a Cargo workspace of their own (excluded from
the main one, so stable builds never see it), and need a nightly toolchain.
Crate-private decoders are reached through `fuzzing` modules in
`mycel-net` and `mycel-sync`, compiled only under `cfg(fuzzing)` (which
cargo-fuzz sets): they are not API.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
fuzz/run.sh 600                       # every target for 10 minutes, 2 at a time
JOBS=1 fuzz/run.sh 60 mesh_wire       # one target for a minute
cargo +nightly fuzz run mesh_wire fuzz/artifacts/mesh_wire/crash-…   # replay an input
cd fuzz && cargo run --example seeds  # rewrite the seed corpora
```

`fuzz/run.sh` builds every target once, then runs each with the corpus in
`fuzz/corpus/<target>` (started from the committed seeds in
`fuzz/seeds/<target>`: for targets that read raw bytes, real messages
encoded by the code a node sends them with; for every target, each input
that once failed), a 10 s limit per input (a hang), a 2 GiB memory limit
and a 512 MiB limit on any single allocation (no input of a few KiB should
need that). Structure-aware targets (`arbitrary`) build their messages
from the fuzzer's bytes, so real encodings would not help them; they run
with `-max_len=16384 -len_control=0`, so their inputs are long enough for
whole scenarios (64 edits, 24 messages, 128 steps) from the first minute
rather than after libFuzzer's slow length ramp. Failing inputs land in
`fuzz/artifacts/<target>/`. Every run appends a line to
`fuzz/logs/runs.tsv` (target, start, CPU and wall seconds, inputs run,
revision), from which the totals below can be checked.

Where a value can be encoded again, targets check the round trip
(decode → encode gives the input back, or a value that decodes equal);
where there is an independent implementation, they compare against it. The
first byte of a raw input often selects the decoder.

| Target | What it feeds, and the properties beyond "no panic" |
|---|---|
| `mesh_wire` | Mesh datagrams (`mesh/wire.rs`): announcements, batches, seqno requests, data frames and fragments, mesh addresses. Canonical re-encoding; a frame split for any hop MTU reassembles |
| `mesh_router` | The router (`mesh/core.rs`) driven by hostile neighbours: raw datagrams dispatched as the driver does, and structured announcements, frames and seqno requests that pass the decoder (signatures decided by the input: a liar may hold a valid one), plus links, sends, lookups and time. The router never addresses itself, what it emits re-encodes, a relayed frame's TTL goes down |
| `dtn` | Store-and-forward (`mesh/dtn.rs`): summary, offer and answer messages, then a carrier fed hostile summaries (NaN predictabilities included), offers, bundles, partial transfers and receipts. Never plans a bundle to ourselves; what we tell neighbours are probabilities; after every step, what the carrier remembers from neighbours (their predictabilities and bundle ids, the transitive predictabilities they gave us) is within its caps (inputs reach the per-neighbour cap of 80 predictabilities; the 4,096-entry caps need more bytes than one input holds, and unit tests cover them) |
| `net_stream` | A peer's stream read as the node reads it (`wire.rs`): length prefix against the limit and the peer's memory budget, then postcard, for sync sessions, ephemeral messages, blob requests and answers, contact cards. Canonical re-encoding; **no allocation beyond what arrived**: a counting allocator checks that the most memory live at once while reading an input stays within 16 times its length plus 2 MiB (serde trusts a declared sequence length for up to 1 MiB of preallocation), so a length prefix alone can't reserve a frame |
| `postcard_messages` | Every other postcard decoder of untrusted bytes: store-and-forward payloads, feed entries, keyrings, membership ops and envelopes (from peers and from storage), contact cards, chat payloads, the rules ABI, call and video control. Round trip; signature checks run |
| `sync_change` | Document changes (`bounded_change.rs`, `change_ops.rs`), raw or re-framed with a valid checksum so mutations reach the column decoders. **Differential**: our op-column decoder (`change_ops.rs`) reads exactly the rows Automerge 0.12's own decoder does. Consistency (not a differential: our parser is a preflight in front of Automerge's loader): what we accept, Automerge loads again with the same hash and bytes, and parses again. Over-strict refusals are checked in `sync_doc`, which has honest changes to check them on |
| `sync_doc` | Concurrent real Automerge edits (maps, lists, text, counters, marks, forks, merges) through a replica's causal index (`doc_index.rs`), optionally with one change mutated. Automerge as the oracle: every honest change passes the network-wide parser and our op decoder (no false refusals), is admitted once its dependencies are, every admitted change applies, the heads agree |
| `sync_replica` | A replica receiving what a malicious *member* can send: anything sealed with the epoch key at any position of its chain (forks included), raw envelopes and ops. **Convergence**: a replica fed in batches and one restored from storage in reverse order end in the same state |
| `sync_v2_wire` | Every Sync v2 decoder: session frames (`reconcile::Msg`, on real and model items), gossip messages (`GossipMsg`), the sealed bundle payload (`bundles::DtnPayload2`, and `bundles::open` with a fixed device key on any bytes), seen notes (`Replica::accept_seen` on any bytes). Stable re-encoding, and the allocation-free size count (`encoded_len`) equals the encoding's length; PADMÉ classes are fixed points |
| `sync_v2_session` | `Session::on_msg` with arbitrary frame sequences, structure-aware: one side runs a real session over a model set built from the input (chains, forks), the fuzzer's frames name real heads, seqs and items of a second model set (frontiers, deltas, chunks, probes, probe replies, `SendsDone`, `Close`, every verdict) or are raw postcard. The session never hands back an item the frame didn't carry; at most 4,096 frames sent per input frame and 100,000 in all |
| `sync_gossip` | The disseminator under arbitrary member lists (classes, reachability, capabilities), local writes up to 3 KB items, pushes, announcements, `Have`, grafts, prunes (structured or raw), ticks and failed sends. Every message it sends fits the 64 KiB frame and passes a second disseminator's limits (no `TooLarge`); actions per step bounded; degree within its cap |
| `trust_graph` | Membership (`mycel-trust`): DAGs of validly signed ops by members and outsiders, any parents, roles, removals, rotations, departures. **Convergence**: inserted one at a time and in a shuffled batch, the resolution is the same |
| `rules_wasm` | Rules bundles any admin may publish: `wasm-smith` modules with the ABI's exports loaded under small limits and run. What loads is valid under exactly the documented feature set; every call is deterministic (same verdict and fuel, twice and on a fresh engine) |
| `rules_bundles` | The shipped chat and counter bundles on members' inputs. **Differential**: the WebAssembly chat rules reach the verdict of the same rules written natively; the counter folds as native arithmetic does |
| `call_media` | Call audio: datagram and stream framing (any split), the Opus decoder (transpiled C) on any packet, the jitter buffer on hostile sequence numbers and timing. Decoded audio is finite and fits the buffer |
| `video_media` | Call video: frames, control stream (any split), the webview frame layout, H.264 `avcC` records, the reorder buffer on hostile sequence numbers, keyframes and give-ups. Delivery strictly in order, from a keyframe after every loss |
| `link_ble` | Bluetooth LE: GATT info, the L2CAP byte stream (any split), and the connection state machine fed a hostile radio. Never routes to or reports our own key |
| `link_wire` | Peer-to-peer Wi-Fi control datagrams and TXT adverts, interface beacons and link addresses, and the Bonjour SRV and TXT records of LAN discovery (`mdns_records.rs`: parsed only on Apple platforms, but kept apart from the Apple FFI so they are fuzzed on Linux CI too). Round trip |
| `contact_code` | Contact codes as pasted or scanned (`mycel:` + base64url + address hints), raw and validly signed. Decodes only with a valid signature and at most eight hints |
| `directory_record` | Reachability records (pkarr packets from the relay, the DHT or a gateway), raw and validly signed. Opens only as signed by its own key, with at most three gateways; what we seal opens the same |
| `blob_ranges` | Node storage: the `.ranges` file of a partial download as read back from disk (damaged, or written by something else). What loads covers the blob exactly with the gaps a resume fetches, and stays so as pieces arrive |

**Not fuzzed here:** the redb database file format itself (a damaged
database fails to open; records inside it that don't decode are set aside,
and the op and envelope decoders they go through are in `postcard_messages`);
JSON the node writes for itself (the identity marker, saved notices); and
the QUIC and TLS stacks (Iroh, the vendored noq, rustls) below our framing.

**In CI** (`.github/workflows/fuzz.yml`): pull requests that touch Rust
build every target and run each for 30 s; every night, and on demand, each
runs for 10 minutes, four at a time, and the corpora are minimised and kept
in the Actions cache for the next night. A failure uploads the failing
inputs and logs as an artifact.

**Found and fixed** (each with a regression unit test in the owning crate;
none in the harnesses; one found in review of the fuzzing, not by it):

| Target | Crate | What a crafted input did | Fix | Regression test |
|---|---|---|---|---|
| `sync_doc` | `mycel-sync` | A member's change with an *inserted* delete or increment, or a mark that isn't an insertion, passed the causal index; Automerge applied it out of order (its debug op-order check failed; release builds carry on with a corrupt document) | The index refuses them: Automerge never writes such operations | `doc_index::tests::inserted_deletes_and_uninserted_marks_are_refused` |
| `sync_change` | `mycel-sync` | An operation id beyond `u32` (object, key or predecessor counter, or actor number) panicked inside Automerge's change loader, which converts with `unwrap`. The replica's `catch_unwind` caught it, but a parser must refuse, not crash | The column preflight refuses such ids before Automerge parses the change | `change_resources::tests::operation_ids_beyond_u32_are_refused` |
| `sync_change` | `mycel-sync` | Differential: a key with an actor and counter 0 decoded here as an element, where Automerge reads the head (the index then refused it: safe, but the decoders disagreed) | Refused in the op decoder; Automerge never writes it | `change_ops::tests::element_counter_zero_with_an_actor_is_refused` |
| `sync_doc` | `mycel-sync` | Two honest concurrent counter increments overflowed when merged: Automerge adds with plain `i64` arithmetic, so debug builds panicked (refusing a change release builds accept, which wrap identically everywhere) | The main workspace builds Automerge without overflow checks in every profile, as release builds are (the fuzz targets keep them on and keep counters within ±2^32, above) | `tests::concurrent_counter_increments_that_overflow_converge` |
| `mesh_router` | `mycel-net` | Smoothing a measured hop cost multiplied a `u32` by 7: above `u32::MAX / 7` (costs are in 0.1 ms units, so about 61,000 s, 17 hours, per 64 KiB) debug builds panicked and release builds wrapped to a near-zero cost, making the slowest hop the cheapest. No real link measures that (it takes round trips of about 1,100 s at the minimum window), but the driver can report costs up to its cap of `u32::MAX / 2`: hardening, not a reachable Bluetooth case. The per-hop penalty overflowed the same way | Smoothed in `u64`, capped where the driver caps costs; the penalty saturates | `mesh::core::tests::smoothing_a_very_slow_hop_cost_does_not_overflow` |
| `dtn` | `mycel-net` | A neighbour's summary reporting a NaN delivery predictability kept it through `clamp`, and NaN outranks every real value where candidates are ranked by `total_cmp` | NaN counts as 0 | `mesh::dtn::tests::a_reported_nan_predictability_counts_as_zero` |
| `blob_ranges` | `mycel-net` | A damaged `.ranges` file loaded as it was: a reversed range underflowed the bytes held (debug panic; release called the download complete), and overlapping or out-of-blob ranges overstated it | Only sorted, disjoint ranges within the blob load; anything else restarts the download | `blobs::security_tests::a_damaged_ranges_file_is_refused` |
| `call_media` | `mycel-call` | Sequence numbers near `u32::MAX` (a peer picks its own) overflowed the jitter buffer's depth and next-frame arithmetic | Widened to `u64`; depth saturates | `jitter::tests::sequence_numbers_near_the_top_of_the_range_play` |
| `video_media` | `mycel-video` | After frame `u32::MAX` the next expected frame wrapped to 0, so an older held keyframe reached the decoder after newer frames | Widened: past the top of the range everything is late | `receiver::tests::delivery_never_goes_backwards_past_the_top_of_the_range` |
| `link_wire` | `mycel-link-iface` | A beacon's one-byte name length let a forged beacon carry 255 bytes of name, where the format has at most 64 | Longer names are refused | `wire::tests::a_beacon_with_an_overlong_name_is_refused` |
| review | `mycel-net` | Not found by the fuzzer, which had no property on state size (it has now): one hostile neighbour sending summaries between full ones, each full of new destinations and bundle ids, grew what a carrier remembers of it, and the transitive predictabilities it gave the carrier, without bound (1,000 summaries of 64 new keys: 64,000 entries for the neighbour and 64,001 of our own), as long as the link stayed up | Capped: a neighbour's predictabilities at one summary's worth (80; its latest summary in full, then the likeliest of what it said before), the bundle ids we remember it holding at 4,096 beyond those we hold, and our own predictabilities at 4,096, trimmed to the likeliest once a quarter over (amortised constant cost) | `mesh::dtn::tests::a_neighbour_cannot_grow_what_we_remember_without_bound`, `trimming_predictabilities_forgets_the_least_likely` |
| `link_wire` | `mycel-link-awdl` | A long advertised name was trimmed before being cut to length, so a cut in whitespace kept it, and the same advert parsed differently once re-encoded | Trimmed again after the cut | `wire::tests::a_name_cut_in_whitespace_is_trimmed` |

Also fixed while writing the targets: a store-and-forward resume offset
from a neighbour was cast to `usize` before being bounded (it would
truncate on 32-bit devices). The DTN summary and offer conversions moved
into functions the driver and the `dtn` target share, so the target feeds
the production decoders.

Harness bugs, not product bugs (fixed in the targets): `trust_graph`
compared op counts without the pending ops; `link_ble` reused channel ids,
which the platform layers never do (they number channels from a counter);
`sync_change` called Automerge's `Change::decode`, which panics on an
operation naming an actor the change doesn't list (Mycel never calls it on
a received change: the causal index refuses such changes first), and
named actors by id, which can't tell apart an actor a change lists twice
(the index refuses those too); and one early `rules_wasm` harness failed
on empty input. One `sync_replica` timeout (346 s for one input) did not
reproduce: the input replays in 0.25 s (libFuzzer's timer is wall time,
which keeps running while the machine is stalled or asleep).

**Run so far:** about 7.1 hours of fuzzing (2026-10-20 and 21, Apple M5
Pro, two fuzzers at a time), in three rounds:

- Round 1 ran every target for 10 minutes or until its first failure:
  about 2.2 hours of wall time, *estimated* from libFuzzer's logs, which
  are no longer on disk.
- Round 2, after the fixes, ran the highest-risk targets longest
  (`sync_change`, `sync_replica`, `mesh_router` and `net_stream` 20
  minutes, `sync_doc` 30; `mesh_wire`, `link_ble`, `link_wire` and
  `trust_graph` 10; the rest 5 more): 3.4 CPU-hours as measured at the
  time, of which the surviving logs (one run per target) account for 2.9.
  It found the last three `mycel-sync` bugs above.
- Round 3, after Automerge's overflow checks were turned back on and the
  new properties added (state bounds in `dtn`, the allocation check in
  `net_stream`, no false refusals in `sync_doc`), 1.5 CPU-hours *measured*
  from `fuzz/logs/runs.tsv`: `sync_doc` 26.5 minutes of CPU, `mesh_wire`
  25.0, `sync_change` and `sync_replica` 13.3 each, `dtn` and
  `net_stream` 5.5 each, `link_wire` 1.5. Nothing failed. One
  `sync_change` "timeout" (6,674 s for one input) was the machine
  stalling, not the input: it replays in 34 ms.

- Round 4 (Sync v2 stage 3, 2026-10-21): the three new targets 10 minutes
  each, measured in `fuzz/logs/runs.tsv`: `sync_v2_session` 584 CPU-s
  (283,563 inputs), `sync_gossip` 585 CPU-s (45,609), `sync_v2_wire`
  589 CPU-s (1,788,720). Nothing failed. `sync_gossip` was run again for
  10 minutes after the view hysteresis change (see the ledger). While
  writing `sync_gossip`, one limit was found by reading what it checks:
  a gossip announcement capped only by entry count could exceed the
  receiver's 64 KiB frame when an equivocating author lists 64 runs;
  entries are now capped at 24 KiB per message as well.

Totals per target range from about 10 minutes (`link_ble`, `trust_graph`)
to about an hour (`sync_doc`); `mesh_wire` and `sync_change` are at about
45. Short, by fuzzing standards, and short of the hour each the
highest-risk targets were meant to get: the nightly CI runs (3 CPU-hours a
night) are relied on for depth from here.

## Voice calls

Audio I/O was replaced by test sources and sinks (`MYCEL_AUDIO=test…`), and
the devices ran with `--net local` (loopback only, no mDNS).

**Two real `mycel serve --net local` devices, driven over the HTTP API** (per-run
token from `<data>/http-token`; contact codes exchanged, a DM created, then
`start_call` → `accept_call` → 10 s → `set_muted` → `end_call`; debug build):

| | Alice (440 Hz tone) | Bob (660 Hz tone) |
|---|---|---|
| Ringing after `start_call` | | 0.10 s |
| Active after `start_call` | 0.11 s | 0.11 s |
| Heard | **660.0 Hz** | **440.0 Hz** |
| Frames sent / received / lost | 509 / 509 / 0 | 509 / 509 / 0 |
| Path, bitrate, transport | network, 32 kbps, datagrams | same |
| Jitter, jitter buffer | 1.1 ms, 40 ms | 0.8 ms, 40 ms |
| CPU during the call (debug build, incl. test-audio thread) | 6.8 % | 6.8 % |
| Memory | 41 MB | 41 MB |

Mute reached the other side (`remoteMuted`), and Bob's call ended
`remoteHungUp`. **Latency:** with Alice sending 1 kHz tone bursts
(`test:bursts`) and Bob sending back what he hears (`test:echo`), Alice measured
**160 ms** from saying a burst to hearing it back, i.e. about **80 ms mouth to
ear** each way, including both test devices' 10 ms buffers.

**Integration tests (`crates/mycel-call/tests/calls.rs`, in-process):**
ring → active in ~105 ms; mouth-to-ear 75–95 ms over loopback; no loss. With
no IP at all, a call on a fast in-memory link whose link is cut moves to a
Bluetooth-like link (20 KB/s, 20 ms each way) after **~5.8 s** (the 5 s
dead-path timeout) and continues there at **12 kbps, 50 frames/s, RTT 50 ms,
jitter buffer 80 ms, ~160 ms mouth to ear**, both directions still hearing
the right tone. Long-lived connections keep their quiet backup link paths
because Mycel's Iroh patch pings link paths every second
(`vendor/iroh/MYCEL_PATCH.md` §3): without that, noq re-arms a path's
keepalive only when a packet arrives on it, and the test failed about one
run in three.

**Real UI** (both `mycel serve` web UIs in headless Chromium): Alice clicks the
phone button; Bob gets the incoming-call card; he accepts; both show the
in-call bar with time, path, bitrate and meters; Bob mutes and Alice's bar
says so; Alice hangs up and Bob's bar shows *Call ended*.

**Group calls** (`crates/mycel-call/tests/group_calls.rs`, real nodes and real
QUIC, a different test tone per person; each device checks that its mix holds
every other person's tone and not its own):
- Alice (1 kHz bursts) calls a group of four, and Bob, Carol and Dave all
  ring. Bob and Carol answer, and Dave declines.
  - The 3-way mesh is up **~105 ms** after Alice presses call.
  - Alice's voice reaches Bob and Carol in **80–100 ms**, mouth to ear, mixed
    with the third person's.
  - Each person is reached on the network path at 32 kbps, with 0 frames lost.
- Dave's call stays `joinable` (*3 in call*). He joins with the call button
  and is meshed with all three others in **~52 ms**, then hears all three.
- Bob leaves and the others go on. Alice, who started the call, leaves too,
  and Carol and Dave still hear each other. When Carol leaves, Dave's call
  ends (`remoteHungUp`).
- Outsiders are refused. Eve, not in the group, sends `Join`, `Watch` or
  `Ring` with the real call reference. Both devices in the call answer
  `Denied` and nothing shows up.
- Carol is removed from the group mid-call, then tries to join. Her join
  ends `failed` and nobody hears her: for 2 s, checked every 100 ms,
  neither device has her joined or a level for her, and her tone stays
  below both the noise-floor bound and 5 % of the other voice.
- With no IP at all, three devices on fast in-memory links hold a 3-way
  call.
- `group_call_between_runtimes` runs the same flow through the JSON command
  table: `group`, `title`, `participants` and `joinedCount`.

## Several devices on one computer, real UI

Three `mycel serve --net lan` devices (Alice, Bob, Carol) plus one
`mycel keeper --net lan`, each a separate process with its own identity and
storage. The real web UI was driven in headless Chrome.

| Step | Result |
|---|---|
| Discovery | Alice saw Bob and Carol **by name over mDNS**, no codes exchanged |
| DM | Alice → Bob over the LAN. Bob got it with an unread badge |
| Reply + file | Bob replied with a file. Alice saw it, and her message went to **read** |
| Download + reaction | Alice fetched the encrypted file from Bob peer-to-peer, decrypted it, and reacted |
| Group | Alice created a group with Bob and Carol; Carol received it |
| Keeper | Alice added the keeper; it joined and stored the group's ciphertext |
| Offline delivery | Bob quit. Alice sent, then quit too. Bob restarted **while Alice was offline** and still received the message from the keeper and peers |
| Message request | Alice started a chat with Bob, who didn't have her as a contact: Bob saw it under **Requests**, with the composer hidden; he accepted and replied, and Alice received the reply |
| No internet | `lsof` on every Mycel process showed only mDNS (UDP 5353), local QUIC sockets and the localhost UI. No relay, DNS or other outbound internet connections |

To run it yourself:

```sh
cargo build -p mycel-cli && npm install && npm run build
./target/debug/mycel serve --data /tmp/a --name Alice --net lan --http 127.0.0.1:7701 &
./target/debug/mycel serve --data /tmp/b --name Bob   --net lan --http 127.0.0.1:7702 &
open http://127.0.0.1:7701 http://127.0.0.1:7702
```

### Local HTTP API hardening (curl against a live `mycel serve`)

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

### Large attachments (two `mycel serve` devices, debug build)

The file was uploaded over `/api/upload` with `curl -T` (streamed), sent with
`send_message`, then fetched with `fetch_attachment` on the other device.
Memory was sampled with `ps -o rss` every 0.5 s.

| File | Mode | Upload + encrypt | Fetch + decrypt | sha256 | Peak RSS (alice / bob) |
|---|---|---|---|---|---|
| 200 MiB random | `--net local` | 1 s + 1 s | 6 s | match | 42 / 40 MB (baseline 29 / 29) |
| 1 GiB random | `--net lan` | 1 s + 3 s | 21 s | match | 42 / 39 MB (baseline 30 / 32) |

`/api/file` served the 1 GiB file back byte-exact. A `Range: bytes=100-199` request got `206` with `content-range: bytes 100-199/1073741824`.

In the real UI, a 300 MB file attached with the file picker was delivered in
about 7 s; Bob's download, with a progress bar, took about 5 s, sha256
identical, with Bob's process at 39 MB of memory.

### Peer-to-peer Wi-Fi, two processes on one Mac

Two devices with `MYCEL_IP=0` (no Wi-Fi/Ethernet IP transport at all, only
links):
- each found the other over the Bonjour peer-to-peer service;
  `network_status` showed `available: ["peerWifi"]`, `via: "peerWifi"`;
- a message and a 20 MB attachment went A → B; the file's sha256 matched,
  and A's message went to *delivered*;
- `lsof` on B: the only peer sockets were UDP on `fe80…%awdl0`, plus mDNS.

On one Mac the AWDL traffic loops locally, so this doesn't test the radio
between two devices.

## Multipath aggregation, connection reuse, multi-source downloads

**Aggregation** (`crates/mycel-net/tests/aggregate.rs`, two endpoints with no IP, joined only by rate-limited in-memory links with 5 ms latency; one QUIC stream, debug build; `cargo test -p mycel-net --test aggregate -- --nocapture --test-threads=1`):

| Links | Throughput | Bytes per path |
|---|---|---|
| one 10 MB/s link | 8.3–8.5 MB/s | all on it |
| two 10 MB/s links | 16.0–16.5 MB/s (**1.91–1.97×**) | ≈ 20–26 MB on each |
| two links, one cut at 25 % | 40 MB in ≈ 11 s | the live one takes over after ≈ 5 s |
| 10 MB/s + 20 KB/s Bluetooth | 7.9–8.3 MB/s (fast link alone: 8.0–8.3) | Bluetooth 0.0 MB (backup) |
| 10 MB/s + a slow link (300 KB/s, 60 ms) | 7.7–8.2 MB/s | slow link 0.2–0.3 MB |

The single-link figure is under 10 MB/s because the in-memory "radio" drops packets once its 250 ms queue is full, and Cubic keeps filling it. In the cut case, the bytes that were in flight on the dead path are resent only when that path's 5 s idle timeout closes it (noq requeues them when it discards the path). Until then the stream is held up at that hole, so a cut costs about 5 s, then everything continues on the live path.

**Connection reuse** (`tests/pool.rs`, two nodes on loopback): first sync with the handshake 24–37 ms, then **2.0–4.0 ms per sync** on the pooled connection. 20 syncs + a card + a typing message = **1 dial, 1 accepted connection**. After the peer restarts on the same port, the next sync redials it (26–30 ms).

**Multi-source** (`tests/multisource.rs`, each source on its own 4 MB/s link to the downloader): one source 3.6–3.7 MB/s; three sources **9.4–9.7 MB/s (2.6×)**. One source shut down a third of the way in; the 24 MiB finished in about 3.0 s from the other two, hash-checked and byte-exact. Each source served 8–13 MB.

**Two devices on one computer** (two `mycel serve --net local` processes, driven over the HTTP API by `scripts/net-bench.py`; debug builds), before and after pooled connections:

| | One connection per exchange | Pooled connection |
|---|---|---|
| 10 consecutive messages, send → visible on the other device | 92–104 ms each (median 94) | **11–20 ms** (first 20, median 12) |
| first message after 65 s quiet | n/a | 24 ms (the 15 s periodic sync keeps the pooled connection warm) |
| 1 GiB attachment: fetch + decrypt | 141.7 s (8 MB/s) | 111.9–131.6 s (8–10 MB/s); release build 100.6 s (11 MB/s) |
| sha256 / peak RSS (alice / bob) | match / 43 / 36 MB | match / 47–52 / 36–39 MB |

Message latency was mostly an 80 ms debounce, which made sense while every sync paid a handshake. On a pooled connection a sync is one stream, so changes are pushed after 5 ms, and a change made while a sync to that peer is running triggers one more sync.

**The 1 GiB transfer over loopback is capped by the platform, not by Mycel**: a bare QUIC stream between two plain upstream Iroh 1.3.0 endpoints (no Mycel code, no patch) on the same Mac does 9–10 MB/s over 127.0.0.1 and over the Mac's own interface address. That's with no loss, a 1.4–2.6 ms RTT and a 300 MB congestion window, and it's the same with noq-udp's `fast-apple-datapath`. Mycel's own figures match it. With only loopback, aggregation can't show a real gain, so the aggregation numbers above come from the in-memory links. (The earlier LAN-mode run's 21 s per GiB, above, is faster than this, and the difference is unexplained.)

To run it: `head -c 1073741824 /dev/urandom > /tmp/big.bin; python3 scripts/net-bench.py target/debug/mycel /tmp/bench after /tmp/big.bin [--cold]`. It starts both devices (`--net local`, ports 7811/7812), exchanges contact codes, creates a DM, then times messages and the attachment.

## Global routing and store-and-forward

| Test | Where | Result |
|---|---|---|
| Learn routes across a new link: 2 hops / up to 8 hops | `mesh::core::tests::convergence_time_to_learn_new_routes` | 0.4 s / 1.4 s (500 ms period, 5 ms hops) |
| A dead route stops being used | `convergence_dead_route_stops_being_used` | 25 ms (retraction) |
| A ring heals around a cut | `convergence_heals_around_a_ring_without_loops` | 0.6 s, 0 loops |
| 60 link flaps, 30-device mesh, traffic | `churn_never_loops` | 0 frame loops, 0 route loops |
| Every routing defence at work (§6 item 15 of `docs/ROUTING.md`): 3 plausible liars, feedback from what arrived, slow hops, 60 link cuts and repairs | `churn_never_loops_with_every_defence` | 0 frame loops, 0 route loops among honest devices; 5,660 of 7,200 delivered; 18 suspicions, 2 shuns, 885 deferred announcements, hold-down engaged (each asserted non-zero) |
| A liar that waits before its cost drops; the destination in range; a seqno answer's feasibility distance; a greeting to an unmeasured hop; shunning's seqno requests | `a_sudden_uncorroborated_shortcut_…`, `a_seqno_answer_sets_the_feasibility_distance`, `a_greeting_to_an_unmeasured_hop_is_paced`, `shunning_asks_around_within_a_bound` | held from the drop; never held; set; 400 announcements, then 2% of the link; 32 requests, recent destinations only |
| Gateway by total cost (far fast uplink beats near slow one) | `gateway_choice_by_total_cost` | ok |
| BLE-only US (3 hops from its gateway) ↔ BLE-only EU, live sync | `tests/global.rs` | first sync 0.58 s; relays and gateways hold no space |
| Test-tone call along that route | `mycel-call` `call_across_two_gateways_and_the_internet` | RTT 84 ms, ~137 ms mouth-to-ear, 0 % loss |
| Two gateways for one device | `two_gateways_are_two_paths_and_fail_over` | 2.0× one path; one lost: longest pause 0.8–2.6 s |
| Partial route → custody → delivery; mailbox; receipts; budgets | `mesh::dtn::tests` | ok |
| Offers refused before the payload; full neighbours skipped; resume; lifetimes from creation; per-source eviction; copies by size; copies in flight | `mesh::dtn::tests` | ok |
| Spray then the internet gradient vs Spray-and-Wait, 4 clusters in a chain, 40 traces | `gradient_beats_spray_and_wait` | 28 min mean vs undelivered in 12 h |
| Data mule across partitions (real QUIC) | `a_data_mule_carries_a_message_across_partitions` | delivered 1 s after meeting; short-lived bundle expired at the mule |

Run them with output: `cargo test -p mycel-net mesh -- --nocapture`, `cargo test -p mycel-net --test global -- --nocapture`.

## Phones and the other platforms

Simulators and an emulator on a Mac, with a desktop peer from `mycel serve`.
Android was driven through its real UI with `adb shell input`, plus Chrome
DevTools on the debug build. The iOS Simulator was checked from screenshots
and the app's log, and the on-screen keyboard with an XCUITest
(`apps/host/ios-uitests`).

| Test | Where | Result |
|---|---|---|
| App starts, runtime opens, profile named after the device | iPhone 18 Pro and iPad Pro 11" simulators (iOS 27), Pixel 7 emulator (Android 14) | ok |
| Layout under the status bar / notch / home indicator / navigation bar | same | phone layout edge to edge; iPad two-pane layout |
| Desktop peer → phone: message request arrives | iPhone simulator (found over mDNS), Android release APK (contact code, emulator behind NAT) | ok, a few seconds |
| Phone → desktop: add contact, send, reply | Android (DevTools, then the real UI) | ok both ways; replied through the on-screen keyboard |
| On-screen keyboard | Android | page shrinks above the keyboard, composer stays in sight, tab bar hides while typing |
| On-screen keyboard | iPhone 18 Pro simulator, XCUITest | header on screen, composer just above the keyboard's bar, also after sending; the message arrives at the desktop peer (iOS slides the page under the keyboard and shrinks `innerHeight` too, so the app sizes itself to the visible part) |
| Back button | Android | closes the keyboard, then returns from a conversation to the list; from the list it leaves the app |
| Attachments from a desktop peer (PNG + text file) | Android | both arrive; the photo downloads and shows inline; the text file opens in the system viewer through the FileProvider ("Open with") |
| Sending a file from the phone | Android (staged in two pieces, base64 over IPC) | arrives intact at the desktop peer |
| Voice call setup | Android | system microphone prompt on the first call, then the desktop peer rings; hang-up shows "missed" there (no audio device in the emulator) |
| In the background and swiped away | Android | the foreground service keeps the runtime running; messages from the desktop peer arrive and show a notification, also after swiping Mycel away; reopening shows them; no notification while Mycel is in front |
| Foreground service type | Pixel 7 emulator (Android 14, API 34), app targeting API 36 | `dumpsys activity services`: `isForeground=true`, `types=0x10` (`connectedDevice`), silent notification in the `mycel-connection` channel |
| Restart after a reboot (2026-10-20) | same | `BootReceiver` started `MycelService` as a foreground service; the runtime opened with no window ("started in the background"); opening the app afterwards adopted it (one process, no second profile lock). Mycel was exempt from battery optimisation in this run |
| Restart after an update (2026-10-20, again 2026-10-21) | same, `adb install -r`, not exempt | `MY_PACKAGE_REPLACED` started the service and the runtime with no window |
| Process killed (`kill -9`) | same, exempt and then not exempt | Android restarted the sticky service after ~4 s, foreground, runtime reopened. On this emulator a restart of a service that was foreground becomes foreground even without the exemption |
| Refused restart (2026-10-21) | same, not exempt; the service demoted first (`cmd appops set dev.mycel.host RUN_ANY_IN_BACKGROUND ignore`, then `allow`), then `kill -9` | Android restarted the service and refused `startForeground` ("Background started FGS: Disallowed"); the service caught up ("background catch-up: synced in 10.0 s": nothing to sync, then the 10 s linger) and stopped itself. That a catch-up delivers is covered on macOS by the host's windowless lifecycle test (two runtimes on loopback), not on the emulator |
| App opened during that catch-up (2026-10-21) | same; the app launched 3 s after the refused restart | the app's start made the service foreground; when the old catch-up ended it did **not** stop the service (`dumpsys`: `isForeground=true`, `lastStartId=7`, 45 s later with the app in the background). Before the fix, the catch-up's plain `stopSelf()` stopped it |
| Background use restricted in Settings (2026-10-21) | same, `RUN_ANY_IN_BACKGROUND ignore` | Android ignores `startForeground` without an exception ("not allowed due to bg restriction"); the old code took the call as a success, left a plain background service, and Android stopped it as idle about a minute later with no catch-up. The service now asks Android (`foregroundServiceType`) whether it took, and catches up once instead. Android also demotes a running foreground service when this restriction is set |
| Background start before the fix | same | Iroh's DNS resolver panicked ("android context was not initialized"); the background start now shares the application context with `ndk_context` and hands it back before tao's activity setup (`android.rs`) |
| Battery optimisation prompt | same | the Profile panel's *In the background* card explained, then **Allow background use** opened Android's prompt; after **Allow**, `dumpsys deviceidle whitelist` listed `user,dev.mycel.host` |
| WorkManager backstop | same | `CatchUpWorker` was enqueued and its first run returned SUCCESS (service already running) |
| WorkManager catch-up (2026-10-21) | same, rooted emulator: clock moved 3 h 10 min ahead (`date`), 30 s for the clock change's start allowance to lapse, then `cmd jobscheduler run -f -n androidx.work.systemjobscheduler dev.mycel.host 2` with the service stopped | the worker opened the runtime with no window, Android refused the service ("not allowed to start in the background"), the worker caught up ("synced in 10.0 s") and returned SUCCESS. A forced run without moving the clock is skipped by WorkManager as early. With the clock change's allowance still active, the worker restarted the service instead (also correct) |
| iOS slow mode | iPhone 17 Pro simulator (iOS 26.4), simulator build | builds with no warnings and launches (both `BGTaskScheduler` tasks registered before launch finishes, no crash); going to the background submitted both requests, which the Simulator refuses as unavailable (`BGTaskSchedulerErrorDomain` 1), as documented (that build resubmitted both each time). Rebuilt 2026-10-21 (iPhone 17 Pro simulator, iOS 26.3): leaving the app now first asks for the pending requests and submits only the kinds missing (here both, since the Simulator refused them), and the app survives being sent to the background twice. The Simulator never runs background tasks and has no Bluetooth, so the catch-up and state restoration are untested |
| Video call, both ways | Android emulator (virtual camera) ↔ desktop peer (`MYCEL_VIDEO=test`) | phone shows the desktop's 720p at ~30 fps; desktop receives the phone's 720×1280. The phone's frames, captured from the desktop's video stream, decode with ffmpeg (Constrained Baseline, no errors). The emulator's software codec is slow, so it sends ~10–20 fps |
| Keyframes from the phone | same, counted in 12–15 s captures at the desktop | 2 of 118 frames (one asked for); otherwise one every 10 s |
| Bluetooth without the hardware | iPhone simulator | Bluetooth reports "Unsupported" and the app carries on |
| Core tests on Linux and Windows | GitHub Actions, optimised build | pass. On Windows a 1 ms sleep takes 14.4 ms with the default timer and 2.4 ms with the 1 ms timer Mycel asks for (`tests/timers.rs`) |
| Sending video from Linux and Windows web views, no camera | GitHub Actions, `scripts/ci/video-probe.html` (capture, then WebCodecs H.264 as `webcam.ts` does) | Edge 153 with a fake camera: 30 frames, avcC, software encoder (no GPU). WebKitGTK 2.50.4 (Ubuntu 22.04) and 2.52.6 (24.04) with WebKit's mock camera: no H.264 encoder until GStreamer's x264 or openh264 is installed; then frames straight from the camera `<video>` fail ("Encoding failed") while synthetic frames and the camera drawn on a canvas encode, so the app goes through a canvas: 30 frames, avcC |
| Linux and Windows apps launch | GitHub Actions smoke test | runtime opens, app still running after the wait, UI renders (WebKitGTK, WebView2 screenshots). Linux takes ~25 s to open on the bare runner: GTK's `g_application_register` waits on a desktop D-Bus service that isn't there (thread dump), before Mycel's code runs |
| Rules engine at every optimisation level | `mycel-rules` tests at opt-level 2 | same verdicts and fuel (56,603 for a 16 KiB message) with wasmi's portable dispatch; its tail-call dispatch overflowed a 2 MiB thread stack there |

## Real hardware

- **Macs:** the app on the LAN; a Mac's Bluetooth advertising, L2CAP
  publishing and scanning (a Mac can't connect to itself, so a link needs two
  devices); peer-to-peer Wi-Fi between two processes on one Mac (above).
- **iPhone:** LAN discovery through the system's Bonjour, found by Macs and
  finding them; Bluetooth links between the iPhone and Macs.
- **Not tested between real devices:** peer-to-peer Wi-Fi (AWDL) on macOS
  and iOS; Bluetooth through BlueZ on Linux; Wi-Fi Direct group formation on
  Linux; the interface link with UWB or 802.15.4 hardware. These are built
  and tested on emulated links, and the Linux code in CI.
- **Not run on real hardware:** the iPhone camera, Android on a physical
  phone, and the Windows and Linux apps on desktop machines.
- Bluetooth on real radios has had far less time than over emulated links,
  and real sessions have seen channels drop and be redialed.
