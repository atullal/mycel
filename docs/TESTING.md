# Testing Mycel

## Automated (run `cargo test --workspace --exclude mycel-host`)

All 159 tests pass and clippy is clean (2026-10-07).

| Crate | Tests | What they prove |
|---|---|---|
| `mycel-crypto` | 14 | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper detection; **streaming attachment AEAD**: chunk-boundary sizes (0, 1, exactly one chunk, many), tamper, wrong key/nonce/AAD, truncation, extension, reorder/duplicate, chunk-size change, legacy one-shot detection, incremental digest == one-shot |
| `mycel-trust` | 17 | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped** |
| `mycel-sync` | 14 | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere** |
| `mycel-net` | 9 | **Links**: two devices with no IP at all sync over in-memory links, prefer peer-to-peer Wi-Fi, fall back to Bluetooth; **a live QUIC connection moves to another link mid-transfer** (failover ≈5 s); Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on this machine**; **40 MiB blob streamed to disk, interrupted download resumed from its `.part`, corrupt partial copy detected and refetched from another member while the sender is offline, push policy (small → everyone, big → keepers only)**; free-space guard |
| `mycel-call` | 35 | **Live calls.** Unit: Opus round trip keeps a 440 Hz tone, 12 kbps fits ~1.5 KB/s, PLC and FEC; frame codec and stream fallback framing under arbitrary splits; **jitter buffer**: prebuffering, reorder, loss → FEC from the next frame, late and duplicate frames dropped, target grows with jitter but never past 120 ms, underrun → conceal → rebuffer → resume, bursts trimmed; **bitrate controller** (path ceilings, loss/RTT step-down, slow recovery, FEC loss %); resampler pitch/length across rates; call id binds space + caller + nonce; **state machine**: answer and hang-up from either side, decline, ring timeout on both sides, setup timeout, busy, **both call at once → one call**. Integration (two real nodes, real QUIC, test audio): audio both ways with measured latency, mute, hang-up by either side; decline / no answer / missed / busy / **forged rings from a non-member refused**; simultaneous calls merge; **no IP: call starts on peer-to-peer Wi-Fi, the link is cut, the same call continues over a 20 KB/s Bluetooth-like link at 12 kbps**; datagram → stream fallback |
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
