# Testing Mycel

## Automated (run `cargo test --workspace --exclude mycel-host`)

All 210 tests pass and clippy is clean (2026-10-08).

| Crate | Tests | What they prove |
|---|---|---|
| `mycel-crypto` | 14 | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper detection; **streaming attachment AEAD**: chunk-boundary sizes (0, 1, exactly one chunk, many), tamper, wrong key/nonce/AAD, truncation, extension, reorder/duplicate, chunk-size change, legacy one-shot detection, incremental digest == one-shot |
| `mycel-trust` | 17 | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped** |
| `mycel-sync` | 14 | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere** |
| `mycel-net` | 13 | **Bandwidth aggregation** (`aggregate.rs`, no IP, rate-limited in-memory links): one stream over two 10 MB/s links ≈ 1.9× one link; one link cut a quarter of the way in, the transfer still completes; a fast link + 20 KB/s Bluetooth, and a fast link + a slow 300 KB/s / 60 ms one, never drop below the fast link alone. **Connection reuse** (`pool.rs`): 20 syncs + a card + a typing message = 1 dial / 1 accepted connection; a peer restarted on the same port is redialed; an idle connection is closed and redialed on use. **Multi-source download** (`multisource.rs`): three members hold a 24 MiB blob, each on its own 4 MB/s link; the fourth downloads from all three at ≈2.6× one source, one source is shut down a third of the way in, the rest comes from the other two, hash-checked and byte-exact. **Links**: two devices with no IP at all sync over in-memory links, prefer peer-to-peer Wi-Fi, fall back to Bluetooth; **a live QUIC connection moves to another link mid-transfer** (failover ≈5 s); Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on this machine**; **40 MiB blob streamed to disk, interrupted (multi-source, out-of-order) download resumed from its `.part` + `.ranges`, corrupt partial copy detected and refetched from another member while the sender is offline, push policy (small → everyone, big → keepers only)**; free-space guard |
| `mycel-net` mesh | 14 | **Multi-hop mesh** (`tests/mesh.rs`, in-memory links, one per radio "edge"; unit tests in `src/mesh.rs`): A–B–C where A and C have no direct link sync through B, **B is in no space and none of the plaintext crosses it** (every relayed byte is inspected); two disjoint relays A–B–C + A–D–C over 400 KB/s links carry **1.8–1.9× one relay** on one stream (4 MB, five runs) and the transfer survives B leaving mid-way; a 5-device line reaches 4 hops (≈0.1 ms per hop on a round trip); a route heals over a longer path ≈5 s after the middle device leaves; a 6-device ring sends the predicted ≈13 announcements/s per device and nothing loops (no TTL drops); a 100 KB/s relay budget holds and a non-relaying device isn't routed through; hops over peer-to-peer Wi-Fi then Bluetooth; a hop whose fast link is cut mid-transfer carries on over its Bluetooth link; **a hop over a real network interface link** (`mycel-link-iface/tests/sync.rs`, lo0); forged, renamed and replayed announcements rejected; per-neighbour announcement rate limit; fragmentation and re-fragmentation |
| `mycel-call` | 36 | **Live calls.** Unit: Opus round trip keeps a 440 Hz tone, 12 kbps fits ~1.5 KB/s, PLC and FEC; frame codec and stream fallback framing under arbitrary splits; **jitter buffer**: prebuffering, reorder, loss → FEC from the next frame, late and duplicate frames dropped, target grows with jitter but never past 120 ms, underrun → conceal → rebuffer → resume, bursts trimmed; **bitrate controller** (path ceilings, loss/RTT step-down, slow recovery, FEC loss %); resampler pitch/length across rates; call id binds space + caller + nonce; **state machine**: answer and hang-up from either side, decline, ring timeout on both sides, setup timeout, busy, **both call at once → one call**. Integration (two real nodes, real QUIC, test audio): audio both ways with measured latency, mute, hang-up by either side; decline / no answer / missed / busy / **forged rings from a non-member refused**; simultaneous calls merge; **no IP: call starts on peer-to-peer Wi-Fi, the link is cut, the same call continues over a 20 KB/s Bluetooth-like link at 12 kbps**; datagram → stream fallback; **a call through a mesh relay** (no direct link; 0 % loss, ≈95 ms) |
| `mycel-node` | 11 | Full messaging API on real storage: DMs, delivery → read, replies, reactions, edits, deletes, attachments, **restart persistence**, **keeper delivery while the sender is offline**, group admin removal, **L4 rules rejecting a forged op**, **message requests + declined/blocked strangers stay out**, **contact-code address hints connect without discovery**, **hostile attachment names neutralized**; **voice call refused while the conversation is a message request, then rings, answers, carries audio, mutes and hangs up through the JSON command table**; **120 MiB attachment (past the old 50 MiB cap) byte-exact between two nodes with upload/download progress**, **legacy one-shot attachments still open**, **folders sent as .zip via a `file://` URL**, `file://` decoding, **unreadable files explain why** (missing, permission denied → macOS privacy hint) |
| `mycel-link-awdl` | 9 | Control datagrams, TXT records, interface filtering; plus 2 ignored Bonjour loopback tests (`-- --ignored`) |
| `mycel-link-ble` | 19 | Framing, bounded queues, connection state machine (who dials, duplicates, timeouts, backoff), fake-radio sync between real nodes with IP off, macOS stream code over in-process pipes |
| `mycel-kit-chat` | 4 | Author-only edits/deletes, reactions, receipts/unread, admin-only meta, garbage tolerance |
| `mycel-rules(-abi)` | 27 | Deterministic WASM engine: fuel/memory limits, banned features, ABI violations, chat rules, wire compatibility with the chat kit |

## Voice calls (2026-10-07, this Mac)

Audio I/O was replaced by test sources and sinks (`MYCEL_AUDIO=test…`): this
shell's microphone permission is *not determined*, and opening the real
microphone would have prompted. Nothing called the real laptops on the LAN
(`--net local`: loopback only, no mDNS).

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
no IP at all, a call on peer-to-peer Wi-Fi (in-memory link) whose link is cut
moves to a Bluetooth-like link (20 KB/s, 20 ms each way) after **~5.8 s**
(the 5 s dead-path timeout) and continues there at **12 kbps, 50 frames/s,
RTT 50 ms, jitter buffer 80 ms, ~160 ms mouth to ear**, both directions still
hearing the right tone. This test first failed about one run in three:
long-lived connections lost their quiet backup link paths after ~5 s (noq
re-arms a path's keepalive only when a packet arrives on it). Mycel's Iroh
patch now pings link paths every second (`vendor/iroh/MYCEL_PATCH.md` §3);
8/8 runs passed after it.

**Real UI** (both `mycel serve` web UIs in headless Chromium): Alice clicks the
phone button; Bob gets the incoming-call card ([screenshot](screenshots/15-call-incoming.png));
he accepts; both show the in-call bar with time, path, bitrate and meters; Bob
mutes and Alice's bar says so ([screenshot](screenshots/16-in-call.png)); Alice
hangs up and Bob's bar shows *Call ended*.

Not exercised here: real microphones and speakers, Apple's voice-processing
unit (echo cancellation), and real peer-to-peer Wi-Fi / Bluetooth radios
(that needs two Macs: [TWO_LAPTOPS.md](TWO_LAPTOPS.md) §5b).

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
- With no IP at all, three devices on in-memory peer-to-peer Wi-Fi links hold
  a 3-way call, each person on the `peerWifi` path.
- `group_call_between_runtimes` runs the same flow through the JSON command
  table: `group`, `title`, `participants` and `joinedCount`.
- In the UI (mock runtime), tiles show each person's level ring, path and
  bitrate ([screenshot](screenshots/17-group-call.png)), and a call you
  declined offers **Join call** ([screenshot](screenshots/18-group-call-join.png)).

## Real-device run (2026-10-07, this Mac, LAN mode)

Setup: three `mycel serve --net lan` devices (Alice, Bob, Carol) plus one `mycel keeper --net lan`, each a separate process with its own identity and storage. The real web UI was driven in headless Chrome.

| Step | Result |
|---|---|
| Discovery | Alice saw Bob and Carol **by name over mDNS**, no codes exchanged ([screenshot](screenshots/02-alice-new-conv.png)) |
| DM | Alice → Bob over the LAN. Bob got it with an unread badge. (This first run predates message requests; strangers are now held as requests, see below.) ([screenshot](screenshots/04-bob-inbox.png)) |
| Reply + file | Bob replied with a file. Alice saw it, and her message went to **read** ✓✓ ([screenshot](screenshots/06-alice-sees-reply.png)) |
| Download + reaction | Alice fetched the encrypted file from Bob peer-to-peer and decrypted it, then reacted 👍 ([screenshot](screenshots/07-alice-download-react.png)) |
| Group | Alice created a group with Bob and Carol; Carol received it ([screenshot](screenshots/09-carol-inbox.png)) |
| Keeper | Alice added the keeper; it joined and stored the group's ciphertext |
| Offline delivery | Bob quit. Alice sent, then quit too. Bob restarted **while Alice was offline** and still received the message from the keeper and peers |
| No internet | `lsof` on every Mycel process showed only mDNS (UDP 5353), local QUIC sockets and the localhost UI. No relay, DNS or other outbound internet connections |

### Message requests (second real-device run, latest build)
Alice started a chat with Bob, who didn't have her as a contact:
- Bob saw it under **Requests**, with the composer hidden ([screenshot](screenshots/12-bob-request.png)).
- He accepted and replied, and Alice received the reply.

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
Setup: two `mycel serve` devices with separate data dirs. The file was uploaded over `/api/upload` with `curl -T` (streamed), sent with `send_message`, then fetched with `fetch_attachment` on the other device. Memory was sampled with `ps -o rss` every 0.5 s.

| File | Mode | Upload + encrypt | Fetch + decrypt | sha256 | Peak RSS (alice / bob) |
|---|---|---|---|---|---|
| 200 MiB random | `--net local` | 1 s + 1 s | 6 s | match | 42 / 40 MB (baseline 29 / 29) |
| 1 GiB random | `--net lan` | 1 s + 3 s | 21 s | match | 42 / 39 MB (baseline 30 / 32) |

`/api/file` served the 1 GiB file back byte-exact. A `Range: bytes=100-199` request got `206` with `content-range: bytes 100-199/1073741824`.

### Re-running it yourself
```sh
cargo build -p mycel-cli && npm install && npm run build
./target/debug/mycel serve --data /tmp/a --name Alice --net lan --http 127.0.0.1:7701 &
./target/debug/mycel serve --data /tmp/b --name Bob   --net lan --http 127.0.0.1:7702 &
open http://127.0.0.1:7701 http://127.0.0.1:7702
```
For two laptops, see [TWO_LAPTOPS.md](TWO_LAPTOPS.md).

## Network paths and big files (2026-10-07, this Mac)

**Any-size files, real UI.** Two `mycel serve --net lan` devices, UI driven in headless Chrome. A 300 MB file was attached with the file picker and sent: delivered in about 7 s. Bob clicked download and watched a progress bar ([screenshot](screenshots/13-big-file-progress.png)): done in about 5 s, sha256 identical, Bob's process stayed at 39 MB of memory. The agent's own runs: 1 GiB in 21 s, peak memory about 42 MB.

**Peer-to-peer Wi-Fi only.** Two devices with `MYCEL_IP=0` (no Wi-Fi/Ethernet IP transport at all, only links):
- each found the other over the Bonjour peer-to-peer service, `network_status` showed `available: ["peerWifi"]`, `via: "peerWifi"`
- a message and a 20 MB attachment went A → B; the file's sha256 matched, A's message went to *delivered*
- `lsof` on B: the only peer sockets were UDP on `fe80…%awdl0`, plus mDNS

On one Mac the AWDL traffic loops locally, so the real radio test needs two Macs (see TWO_LAPTOPS.md §7). Bluetooth: advertising, L2CAP publishing and scanning were verified on this Mac (121 nearby BLE devices seen); a Mac can't connect to itself, so the Bluetooth path's first real crossing is the two-laptop test.

**Network panel** shows the mode switch, each path's state and which path each person is reached by ([screenshot](screenshots/14-network-paths.png)).

## Multipath aggregation, connection reuse, multi-source downloads (2026-10-08)

**Aggregation** (`crates/mycel-net/tests/aggregate.rs`, two endpoints with no IP, joined only by rate-limited in-memory links with 5 ms latency; one QUIC stream, debug build; `cargo test -p mycel-net --test aggregate -- --nocapture --test-threads=1`):

| Links | Throughput | Bytes per path |
|---|---|---|
| one 10 MB/s link | 8.3–8.5 MB/s | all on it |
| two 10 MB/s links | 16.0–16.5 MB/s (**1.91–1.97×**) | ≈ 20–26 MB on each |
| two links, one cut at 25 % | 40 MB in ≈ 11 s | the live one takes over after ≈ 5 s |
| 10 MB/s + 20 KB/s Bluetooth | 7.9–8.3 MB/s (fast link alone: 8.0–8.3) | Bluetooth 0.0 MB (backup) |
| 10 MB/s + slow "peer Wi-Fi" (300 KB/s, 60 ms) | 7.7–8.2 MB/s | slow link 0.2–0.3 MB |

The single-link figure is under 10 MB/s because the in-memory "radio" drops packets once its 250 ms queue is full, and Cubic keeps filling it. In the cut case, the bytes that were in flight on the dead path are resent only when that path's 5 s idle timeout closes it (noq requeues them when it discards the path). Until then the stream is held up at that hole, so a cut costs about 5 s, then everything continues on the live path.

**Connection reuse** (`tests/pool.rs`, two nodes on loopback): first sync with the handshake 24–37 ms, then **2.0–4.0 ms per sync** on the pooled connection. 20 syncs + a card + a typing message = **1 dial, 1 accepted connection**. After the peer restarts on the same port, the next sync redials it (26–30 ms).

**Multi-source** (`tests/multisource.rs`, each source on its own 4 MB/s link to the downloader): one source 3.6–3.7 MB/s; three sources **9.4–9.7 MB/s (2.6×)**. One source shut down a third of the way in; the 24 MiB finished in about 3.0 s from the other two, hash-checked and byte-exact. Each source served 8–13 MB.

**Real devices on this Mac** (two `mycel serve --net local` processes, driven over the HTTP API by a script; "before" = commit `5cb1454`, debug builds):

| | Before | After |
|---|---|---|
| 10 consecutive messages, send → visible on the other device | 92–104 ms each (median 94) | **11–20 ms** (first 20, median 12) |
| first message after 65 s quiet | n/a | 24 ms (the 15 s periodic sync keeps the pooled connection warm) |
| 1 GiB attachment: fetch + decrypt | 141.7 s (8 MB/s) | 111.9–131.6 s (8–10 MB/s); release build 100.6 s (11 MB/s) |
| sha256 / peak RSS (alice / bob) | match / 43 / 36 MB | match / 47–52 / 36–39 MB |

Message latency was mostly the scheduler's 80 ms debounce, which made sense while every sync paid a handshake. On a pooled connection a sync is one stream, so changes are now pushed after 5 ms, and a change made while a sync to that peer is running triggers one more sync (before, it waited for the next 15 s periodic sync).

**The 1 GiB transfer is capped by the platform, not by Mycel**: a bare QUIC stream between two plain *upstream* Iroh 1.3.0 endpoints (no Mycel code, no patch) on this Mac does 9–10 MB/s over 127.0.0.1 and over the Mac's own interface address. That's with no loss, a 1.4–2.6 ms RTT and a 300 MB congestion window, and it's the same with noq-udp's `fast-apple-datapath`. Mycel's own figures match it. With only loopback here, aggregation can't show a real gain, so the aggregation numbers above come from the in-memory links. This doesn't explain the 21 s/GiB measured on 2026-10-07 (LAN mode); it's worth chasing upstream (noq's macOS UDP path).

Re-run: `head -c 1073741824 /dev/urandom > /tmp/big.bin; python3 scripts/net-bench.py target/debug/mycel /tmp/bench after /tmp/big.bin [--cold]`. It starts both devices (`--net local`, ports 7811/7812), exchanges contact codes, creates a DM, then times messages and the attachment.

## Global routing and store-and-forward (2026-10-08)

| Test | Where | Result |
|---|---|---|
| Learn routes across a new link: 2 hops / up to 8 hops | `mesh::core::tests::convergence_time_to_learn_new_routes` | 0.4 s / 1.4 s (500 ms period, 5 ms hops) |
| A dead route stops being used | `convergence_dead_route_stops_being_used` | 25 ms (retraction) |
| A ring heals around a cut | `convergence_heals_around_a_ring_without_loops` | 0.6 s, 0 loops |
| 60 link flaps, 30-device mesh, traffic | `churn_never_loops` | 0 frame loops, 0 route loops |
| Announcement overhead, fisheye + flood reduction | `overhead_per_device_against_mesh_size` | −55 % (25), −68 % (50), −75 % (100 devices) |
| Gateway by total cost (far fast uplink beats near slow one) | `gateway_choice_by_total_cost` | ok |
| BLE-only US (3 hops from its gateway) ↔ BLE-only EU, live sync | `tests/global.rs` | first sync 0.58 s; relays and gateways hold no space |
| Test-tone call along that route | `mycel-call` `call_across_two_gateways_and_the_internet` | RTT 84 ms, ~137 ms mouth-to-ear, 0 % loss |
| Two gateways for one device | `two_gateways_are_two_paths_and_fail_over` | 2.0× one path; one lost: longest pause 0.8–2.6 s |
| Partial route → custody → delivery; mailbox; receipts; budgets | `mesh::dtn::tests` | ok |
| Offers refused before the payload; full neighbours skipped; resume; lifetimes from creation; per-source eviction; copies by size; copies in flight | `mesh::dtn::tests` | ok |
| Spray then the internet gradient vs Spray-and-Wait, 4 clusters in a chain, 40 traces | `gradient_beats_spray_and_wait` | 28 min mean vs undelivered in 12 h |
| Data mule across partitions (real QUIC) | `a_data_mule_carries_a_message_across_partitions` | delivered 1 s after meeting; short-lived bundle expired at the mule |

Run them with output: `cargo test -p mycel-net mesh -- --nocapture`, `cargo test -p mycel-net --test global -- --nocapture`.


## Phones and the other platforms (2026-10-09)

Simulators on this Mac, a desktop peer from `mycel serve`. Android was driven
through its real UI with `adb shell input`, plus Chrome DevTools on the debug
build. The iOS Simulator was checked from screenshots and the app's log (tap
automation tools don't support Xcode 27 yet).

| Test | Where | Result |
|---|---|---|
| App starts, runtime opens, profile named after the device | iPhone 18 Pro and iPad Pro 11" simulators (iOS 27), Pixel 7 emulator (Android 14) | ok ("iPhone 18 Pro", "iPad Pro 11-inch (M5)", "Android SDK built for arm64") |
| Layout under the status bar / notch / home indicator / navigation bar | same | phone layout edge to edge; iPad two-pane layout |
| Desktop peer → phone: message request arrives | iPhone simulator (found over mDNS), Android release APK (contact code, emulator behind NAT) | ok, a few seconds |
| Phone → desktop: add contact, send, reply | Android (DevTools, then the real UI) | ok both ways; replied through the on-screen keyboard |
| On-screen keyboard | Android | page shrinks above the keyboard, composer stays in sight, tab bar hides while typing |
| Back button | Android | closes the keyboard, then returns from a conversation to the list; from the list it leaves the app |
| Voice call setup | Android | system microphone prompt on the first call, then the desktop peer rings; hang-up shows "missed" there (no audio device in the emulator) |
| Bluetooth / peer-to-peer Wi-Fi without the hardware | iPhone simulator | Bluetooth reports "Unsupported" and the app carries on |
| Core tests on Linux and Windows | GitHub Actions (`apps.yml`) | first run: runtime, sync, trust, net, links pass; Apple-only video tests now skipped there; timing tests run optimised |
