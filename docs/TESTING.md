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
| `mycel-trust` | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped**; a fan-out of invalid ops can't block a revocation, wide valid frontiers aren't truncated, pending-pool limits per author |
| `mycel-sync` | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere**; decompression and run-length expansion bombs, malformed and deferred changes, declared-history checks (actor sequence, counters, object references), delivery-order and restore consistency, large pastes split and accepted |
| `mycel-net` | **Bandwidth aggregation** (`aggregate.rs`, no IP, rate-limited in-memory links): one stream over two 10 MB/s links ≈ 1.9× one link; one link cut a quarter of the way in, the transfer still completes; a fast link + 20 KB/s Bluetooth, and a fast link + a slow 300 KB/s / 60 ms one, never drop below the fast link alone. **Connection reuse** (`pool.rs`): 20 syncs + a card + a typing message = 1 dial / 1 accepted connection; a peer restarted on the same port is redialed; an idle connection is closed and redialed on use. **Multi-source download** (`multisource.rs`): three members hold a 24 MiB blob, each on its own 4 MB/s link; the fourth downloads from all three at ≈2.6× one source, one source is shut down a third of the way in, the rest comes from the other two, hash-checked and byte-exact. **Links**: two devices with no IP at all sync over in-memory links, prefer the faster one, fall back to a Bluetooth-like one; **a live QUIC connection moves to another link mid-transfer** (failover ≈5 s). Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on the test machine**; **40 MiB blob streamed to disk, interrupted (multi-source, out-of-order) download resumed from its `.part` + `.ranges`, corrupt partial copy detected and refetched from another member while the sender is offline, push policy (small → everyone, big → keepers only)**; free-space guard; stream and frame budgets, stalled and progressing I/O, duplicate requests, ephemeral limits; Windows timer resolution (`timers.rs`); the path-open queue doesn't grow (`path_queue.rs`) |
| `mycel-net` mesh | **Multi-hop mesh** (`tests/mesh.rs`, in-memory links, one per radio "edge"; unit tests in `src/mesh/`): A–B–C where A and C have no direct link sync through B, **B is in no space and none of the plaintext crosses it** (every relayed byte is inspected); two disjoint relays A–B–C + A–D–C over 400 KB/s links carry **1.8–1.9× one relay** on one stream (4 MB, five runs) and the transfer survives B leaving mid-way; a 5-device line reaches 4 hops (≈0.1 ms per hop on a round trip); a route heals over a longer path ≈5 s after the middle device leaves; a 6-device ring sends no more announcements than predicted and nothing loops (no TTL drops); a 100 KB/s relay budget holds and a non-relaying device isn't routed through; hops over a fast link then a Bluetooth-like one; a hop whose fast link is cut mid-transfer carries on over its Bluetooth-like link; **a hop over a real network interface link** (`mycel-link-iface/tests/sync.rs`, `lo0`); forged, renamed and replayed announcements rejected; per-neighbour announcement rate limit; fragmentation and re-fragmentation; routing convergence, churn and store-and-forward in virtual time (`mesh/core/tests.rs`, `mesh/dtn/tests.rs`); gateways and the data mule (`tests/global.rs`) |
| `mycel-call` | **Live calls.** Unit: Opus round trip keeps a 440 Hz tone, 12 kbps fits ~1.5 KB/s, PLC and FEC; frame codec and stream fallback framing under arbitrary splits; **jitter buffer**: prebuffering, reorder, loss → FEC from the next frame, late and duplicate frames dropped, target grows with jitter but never past 120 ms, underrun → conceal → rebuffer → resume, bursts trimmed; **bitrate controller** (path ceilings, loss/RTT step-down, slow recovery, FEC loss %); resampler pitch/length across rates; call id binds space + caller + nonce; **state machine**: answer and hang-up from either side, decline, ring timeout on both sides, setup timeout, busy, **both call at once → one call**. Integration (real nodes, real QUIC, test audio): audio both ways with measured latency, mute, hang-up by either side; decline / no answer / missed / busy / **forged rings from a non-member refused**; simultaneous calls merge; **no IP: a call starts on a fast in-memory link, the link is cut, the same call continues over a 20 KB/s Bluetooth-like link at 12 kbps**; datagram → stream fallback; **a call through a mesh relay** (no direct link; 0 % loss, ≈95 ms); group calls (below); video calls both ways, recovery from lost frames, adapting to a slow link; **the playout cushion follows the device's buffer** (25 ms for 10 ms bursts, covers 40 and 60 ms Bluetooth bursts, never over 100 ms, shrinks back after a hiccup); the test audio device paces itself at 10 and 40 ms periods |
| `mycel-video` | Rate controller (a budget for every kind of path, ramp-up, back-off when frames queue, pacing, path changes), frame and control wire formats, receiver reordering and keyframe recovery; on Apple platforms, VideoToolbox encode and decode, and camera frames keeping their shape in portrait, landscape and 4:3, one answer from the encoder per frame (a frame, a drop, or a timeout, counted apart), a stalled encoder session replaced by the next mode down to CPU scaling and the software encoder, and an error when none is left; media threads promoted to real-time scheduling wake on time (p90 under 2 ms late for 3 ms sleeps), also when the test re-runs itself throttled, and the kernel's stored policy read back |
| `mycel-node` | Full messaging API on real storage: DMs, delivery → read, replies, reactions, edits, deletes, attachments, **restart persistence**, **keeper delivery while the sender is offline**, group admin removal, **L4 rules rejecting a forged op**, **message requests + declined/blocked strangers stay out**, **contact-code address hints connect without discovery**, **hostile attachment names neutralised**; **voice call refused while the conversation is a message request, then rings, answers, carries audio, mutes and hangs up through the JSON command table**; **120 MiB attachment byte-exact between two nodes with upload/download progress**, **legacy one-shot attachments still open**, **folders sent as .zip via a `file://` URL**, `file://` decoding, **unreadable files explain why** (missing, permission denied → macOS privacy hint); one chat per person across separately created spaces, paging and search, local hide and restore across restarts, attachment consent across restarts, identity and storage fault injection; closing the store releases its file at once, so a restarted runtime opens it even while a straggling task still holds the old handle |
| `mycel-link-awdl` | Control datagrams, TXT records, interface filtering; plus 2 ignored Bonjour loopback tests (`-- --ignored`) |
| `mycel-link-ble` | Framing, bounded queues, connection state machine (who dials, duplicates, timeouts, backoff, address rotation), fake-radio sync between real nodes with IP off, hours of simulated faults between two devices, macOS stream code over in-process pipes; the fake radio's rate holds when its thread wakes late, and is never exceeded |
| `mycel-link-iface` | Interface classification (medium from type and name, software interfaces skipped, ordinary NICs left to IP), environment overrides, beacons; a sync over a real interface with IP off, one path per interface |
| `mycel-kit-chat` | Author-only edits/deletes, reactions, receipts/unread, admin-only meta, garbage tolerance, thread merging (a late alias can't backdate messages; a message written at an alias's first-seen time sorts after that alias's older messages), alerts |
| `mycel-rules(-abi)` | Deterministic WASM engine: fuel/memory limits, banned features, ABI violations, chat rules, wire compatibility with the chat kit, the fuel cost model pinned |
| `mycel-sim` | Every scenario at CI size, and the simulator's own models (`cargo test -p mycel-sim`) |
| `mycel-host` | Log file privacy, notification privacy, deduplication, tap routing and permission handling |
| Web (`npm test`) | SDK paging, search, presence and conversation identity; Messaging layout and swipe gestures; host notices and notification actions |

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
