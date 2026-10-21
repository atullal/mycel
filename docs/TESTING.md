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
| `mycel-trust` | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped**; a fan-out of invalid ops can't block a revocation, wide valid frontiers aren't truncated, pending-pool limits per author |
| `mycel-sync` | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere**; decompression and run-length expansion bombs, malformed and deferred changes, declared-history checks (actor sequence, counters, object references), delivery-order and restore consistency, large pastes split and accepted |
| `mycel-net` | **Bandwidth aggregation** (`aggregate.rs`, no IP, rate-limited in-memory links): one stream over two 10 MB/s links ≈ 1.9× one link; one link cut a quarter of the way in, the transfer still completes; a fast link + 20 KB/s Bluetooth, and a fast link + a slow 300 KB/s / 60 ms one, never drop below the fast link alone. **Connection reuse** (`pool.rs`): 20 syncs + a card + a typing message = 1 dial / 1 accepted connection; a peer restarted on the same port is redialed; an idle connection is closed and redialed on use. **Multi-source download** (`multisource.rs`): three members hold a 24 MiB blob, each on its own 4 MB/s link; the fourth downloads from all three at ≈2.6× one source, one source is shut down a third of the way in, the rest comes from the other two, hash-checked and byte-exact. **Links**: two devices with no IP at all sync over in-memory links, prefer the faster one, fall back to a Bluetooth-like one; **a live QUIC connection moves to another link mid-transfer** (failover ≈5 s). Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on the test machine**; **40 MiB blob streamed to disk, interrupted (multi-source, out-of-order) download resumed from its `.part` + `.ranges`, corrupt partial copy detected and refetched from another member while the sender is offline, push policy (small → everyone, big → keepers only)**; free-space guard; stream and frame budgets, stalled and progressing I/O, duplicate requests, ephemeral limits; Windows timer resolution (`timers.rs`); the path-open queue doesn't grow (`path_queue.rs`) |
| `mycel-net` mesh | **Multi-hop mesh** (`tests/mesh.rs`, in-memory links, one per radio "edge"; unit tests in `src/mesh/`): A–B–C where A and C have no direct link sync through B, **B is in no space and none of the plaintext crosses it** (every relayed byte is inspected); two disjoint relays A–B–C + A–D–C over 400 KB/s links carry **1.8–1.9× one relay** on one stream (4 MB, five runs) and the transfer survives B leaving mid-way; a 5-device line reaches 4 hops (≈0.1 ms per hop on a round trip); a route heals over a longer path ≈5 s after the middle device leaves; a 6-device ring sends no more announcements than predicted and nothing loops (no TTL drops); a 100 KB/s relay budget holds and a non-relaying device isn't routed through; hops over a fast link then a Bluetooth-like one; a hop whose fast link is cut mid-transfer carries on over its Bluetooth-like link; **a hop over a real network interface link** (`mycel-link-iface/tests/sync.rs`, `lo0`); forged, renamed and replayed announcements rejected; per-neighbour announcement rate limit; fragmentation and re-fragmentation; routing convergence, churn and store-and-forward in virtual time (`mesh/core/tests.rs`, `mesh/dtn/tests.rs`); gateways and the data mule (`tests/global.rs`) |
| `mycel-call` | **Live calls.** Unit: Opus round trip keeps a 440 Hz tone, 12 kbps fits ~1.5 KB/s, PLC and FEC; frame codec and stream fallback framing under arbitrary splits; **jitter buffer**: prebuffering, reorder, loss → FEC from the next frame, late and duplicate frames dropped, target grows with jitter but never past 120 ms, underrun → conceal → rebuffer → resume, bursts trimmed; **bitrate controller** (path ceilings, loss/RTT step-down, slow recovery, FEC loss %); resampler pitch/length across rates; call id binds space + caller + nonce; **state machine**: answer and hang-up from either side, decline, ring timeout on both sides, setup timeout, busy, **both call at once → one call**. Integration (real nodes, real QUIC, test audio): audio both ways with measured latency, mute, hang-up by either side; decline / no answer / missed / busy / **forged rings from a non-member refused**; simultaneous calls merge; **no IP: a call starts on a fast in-memory link, the link is cut, the same call continues over a 20 KB/s Bluetooth-like link at 12 kbps**; datagram → stream fallback; **a call through a mesh relay** (no direct link; 0 % loss, ≈95 ms); group calls (below); video calls both ways, recovery from lost frames, adapting to a slow link |
| `mycel-video` | Rate controller (a budget for every kind of path, ramp-up, back-off when frames queue, pacing, path changes), frame and control wire formats, receiver reordering and keyframe recovery; on Apple platforms, VideoToolbox encode and decode, and camera frames keeping their shape in portrait, landscape and 4:3 |
| `mycel-node` | Full messaging API on real storage: DMs, delivery → read, replies, reactions, edits, deletes, attachments, **restart persistence**, **keeper delivery while the sender is offline**, group admin removal, **L4 rules rejecting a forged op**, **message requests + declined/blocked strangers stay out**, **contact-code address hints connect without discovery**, **hostile attachment names neutralised**; **voice call refused while the conversation is a message request, then rings, answers, carries audio, mutes and hangs up through the JSON command table**; **120 MiB attachment byte-exact between two nodes with upload/download progress**, **legacy one-shot attachments still open**, **folders sent as .zip via a `file://` URL**, `file://` decoding, **unreadable files explain why** (missing, permission denied → macOS privacy hint); one chat per person across separately created spaces, paging and search, local hide and restore across restarts, attachment consent across restarts, identity and storage fault injection |
| `mycel-link-awdl` | Control datagrams, TXT records, interface filtering; plus 2 ignored Bonjour loopback tests (`-- --ignored`) |
| `mycel-link-ble` | Framing, bounded queues, connection state machine (who dials, duplicates, timeouts, backoff, address rotation), fake-radio sync between real nodes with IP off, hours of simulated faults between two devices, macOS stream code over in-process pipes |
| `mycel-link-iface` | Interface classification (medium from type and name, software interfaces skipped, ordinary NICs left to IP), environment overrides, beacons; a sync over a real interface with IP off, one path per interface |
| `mycel-kit-chat` | Author-only edits/deletes, reactions, receipts/unread, admin-only meta, garbage tolerance, thread merging, alerts |
| `mycel-rules(-abi)` | Deterministic WASM engine: fuel/memory limits, banned features, ABI violations, chat rules, wire compatibility with the chat kit, the fuel cost model pinned |
| `mycel-sim` | Every scenario at CI size, and the simulator's own models (`cargo test -p mycel-sim`) |
| `mycel-host` | Log file privacy, notification privacy, deduplication, tap routing and permission handling |
| Web (`npm test`) | SDK paging, search, presence and conversation identity; Messaging layout and swipe gestures; host notices and notification actions |

## Fuzzing

Every decoder that reads bytes from someone else is fuzzed with libFuzzer
(`cargo-fuzz`), with AddressSanitizer, overflow checks and debug assertions
on. Bridgefy's mesh fell to one crafted message because clients forwarded
before they parsed ([ePrint 2021/214](https://eprint.iacr.org/2021/214));
here a node parses and checks everything before acting on it, and these
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
from the fuzzer's bytes, so real encodings would not help them.
Failing inputs land in `fuzz/artifacts/<target>/`.

Where a value can be encoded again, targets check the round trip
(decode → encode gives the input back, or a value that decodes equal);
where there is an independent implementation, they compare against it. The
first byte of a raw input often selects the decoder.

| Target | What it feeds, and the properties beyond "no panic" |
|---|---|
| `mesh_wire` | Mesh datagrams (`mesh/wire.rs`): announcements, batches, seqno requests, data frames and fragments, mesh addresses. Canonical re-encoding; a frame split for any hop MTU reassembles |
| `mesh_router` | The router (`mesh/core.rs`) driven by hostile neighbours: raw datagrams dispatched as the driver does, and structured announcements, frames and seqno requests that pass the decoder (signatures decided by the input: a liar may hold a valid one), plus links, sends, lookups and time. The router never addresses itself, what it emits re-encodes, a relayed frame's TTL goes down |
| `dtn` | Store-and-forward (`mesh/dtn.rs`): summary, offer and answer messages, then a carrier fed hostile summaries (NaN predictabilities included), offers, bundles, partial transfers and receipts. Never plans a bundle to ourselves; what we tell neighbours are probabilities |
| `net_stream` | A peer's stream read as the node reads it (`wire.rs`): length prefix against the limit and the peer's memory budget, then postcard, for sync sessions, ephemeral messages, blob requests and answers, contact cards. No allocation beyond what arrived; canonical re-encoding |
| `postcard_messages` | Every other postcard decoder of untrusted bytes: store-and-forward payloads, feed entries, keyrings, membership ops and envelopes (from peers and from storage), contact cards, chat payloads, the rules ABI, call and video control. Round trip; signature checks run |
| `sync_change` | Document changes (`bounded_change.rs`, `change_ops.rs`), raw or re-framed with a valid checksum so mutations reach the column decoders. **Differential against Automerge 0.12**: whatever we accept, Automerge loads with the same hash; our op decoder reads exactly Automerge's rows |
| `sync_doc` | Concurrent real Automerge edits (maps, lists, text, counters, marks, forks, merges) through a replica's causal index (`doc_index.rs`), optionally with one change mutated. Automerge as the oracle: an honest change is always admitted once its dependencies are, every admitted change applies, the heads agree |
| `sync_replica` | A replica receiving what a malicious *member* can send: anything sealed with the epoch key at any position of its chain (forks included), raw envelopes and ops. **Convergence**: a replica fed in batches and one restored from storage in reverse order end in the same state |
| `trust_graph` | Membership (`mycel-trust`): DAGs of validly signed ops by members and outsiders, any parents, roles, removals, rotations, departures. **Convergence**: inserted one at a time and in a shuffled batch, the resolution is the same |
| `rules_wasm` | Rules bundles any admin may publish: `wasm-smith` modules with the ABI's exports loaded under small limits and run. What loads is valid under exactly the documented feature set; every call is deterministic (same verdict and fuel, twice and on a fresh engine) |
| `rules_bundles` | The shipped chat and counter bundles on members' inputs. **Differential**: the WebAssembly chat rules reach the verdict of the same rules written natively; the counter folds as native arithmetic does |
| `call_media` | Call audio: datagram and stream framing (any split), the Opus decoder (transpiled C) on any packet, the jitter buffer on hostile sequence numbers and timing. Decoded audio is finite and fits the buffer |
| `video_media` | Call video: frames, control stream (any split), the webview frame layout, H.264 `avcC` records, the reorder buffer on hostile sequence numbers, keyframes and give-ups. Delivery strictly in order, from a keyframe after every loss |
| `link_ble` | Bluetooth LE: GATT info, the L2CAP byte stream (any split), and the connection state machine fed a hostile radio. Never routes to or reports our own key |
| `link_wire` | Peer-to-peer Wi-Fi control datagrams and TXT adverts, interface beacons and link addresses, and (Apple) Bonjour SRV and TXT records. Round trip |
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
none in the harnesses):

| Target | Crate | What a crafted input did | Fix | Regression test |
|---|---|---|---|---|
| `sync_doc` | `mycel-sync` | A member's change with an *inserted* delete or increment, or a mark that isn't an insertion, passed the causal index; Automerge applied it out of order (its debug op-order check failed; release builds carry on with a corrupt document) | The index refuses them: Automerge never writes such operations | `doc_index::tests::inserted_deletes_and_uninserted_marks_are_refused` |
| `sync_change` | `mycel-sync` | An operation id beyond `u32` (object, key or predecessor counter, or actor number) panicked inside Automerge's change loader, which converts with `unwrap`. The replica's `catch_unwind` caught it, but a parser must refuse, not crash | The column preflight refuses such ids before Automerge parses the change | `change_resources::tests::operation_ids_beyond_u32_are_refused` |
| `sync_change` | `mycel-sync` | Differential: a key with an actor and counter 0 decoded here as an element, where Automerge reads the head (the index then refused it: safe, but the decoders disagreed) | Refused in the op decoder; Automerge never writes it | `change_ops::tests::element_counter_zero_with_an_actor_is_refused` |
| `sync_doc` | `mycel-sync` | Two honest concurrent counter increments overflowed when merged: Automerge adds with plain `i64` arithmetic, so debug builds panicked (refusing a change release builds accept, which wrap identically everywhere) | Automerge is built without overflow checks in every profile, as release builds are | `tests::concurrent_counter_increments_that_overflow_converge` |
| `mesh_router` | `mycel-net` | Smoothing a measured hop cost multiplied a `u32` by 7: above about 61 s per 64 KiB (a congested Bluetooth hop) debug builds panicked and release builds wrapped to a near-zero cost, making the slowest hop the cheapest. The per-hop penalty overflowed the same way | Smoothed in `u64`, capped where the driver caps costs; the penalty saturates | `mesh::core::tests::smoothing_a_very_slow_hop_cost_does_not_overflow` |
| `dtn` | `mycel-net` | A neighbour's summary reporting a NaN delivery predictability kept it through `clamp`, and NaN outranks every real value where candidates are ranked by `total_cmp` | NaN counts as 0 | `mesh::dtn::tests::a_reported_nan_predictability_counts_as_zero` |
| `blob_ranges` | `mycel-net` | A damaged `.ranges` file loaded as it was: a reversed range underflowed the bytes held (debug panic; release called the download complete), and overlapping or out-of-blob ranges overstated it | Only sorted, disjoint ranges within the blob load; anything else restarts the download | `blobs::security_tests::a_damaged_ranges_file_is_refused` |
| `call_media` | `mycel-call` | Sequence numbers near `u32::MAX` (a peer picks its own) overflowed the jitter buffer's depth and next-frame arithmetic | Widened to `u64`; depth saturates | `jitter::tests::sequence_numbers_near_the_top_of_the_range_play` |
| `video_media` | `mycel-video` | After frame `u32::MAX` the next expected frame wrapped to 0, so an older held keyframe reached the decoder after newer frames | Widened: past the top of the range everything is late | `receiver::tests::delivery_never_goes_backwards_past_the_top_of_the_range` |
| `link_wire` | `mycel-link-iface` | A beacon's one-byte name length let a forged beacon carry 255 bytes of name, where the format has at most 64 | Longer names are refused | `wire::tests::a_beacon_with_an_overlong_name_is_refused` |
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

**Run so far:** about 5.6 CPU-hours (2026-10-20 and 21, Apple M5 Pro, two
fuzzers at a time). A first round ran every target for 10 minutes or until
its first failure (2.2 hours; wall time, measured from libFuzzer's logs).
After the fixes, a second round (3.4 CPU-hours, measured; it found the
last three `mycel-sync` bugs above, and every run after their fixes ended
clean) ran the highest-risk targets longest:
`sync_change`, `sync_replica`, `mesh_router` and `net_stream` 20 minutes,
`sync_doc` 30; `mesh_wire`, `link_ble`, `link_wire` and `trust_graph` 10;
the rest, which had run clean for 10 minutes in the first round, 5 more.
Totals per target range from 10 minutes (`link_ble`, `link_wire`,
`trust_graph`) to 36 (`sync_doc`). Short, by fuzzing standards: the nightly
CI runs (3 CPU-hours a night) are what grows the corpora from here.

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
  ends `failed` and nobody hears her.
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
