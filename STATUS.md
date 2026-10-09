# Mycel: where things stand

*Last updated: 2026-10-09, 4:45 am ET. This is a snapshot for collaborators. The
design docs in `docs/` are the source of truth.*

## TL;DR

- `main` has the full stack:
  - encrypted P2P messaging;
  - 1:1 and group voice and video calls;
  - files of any size;
  - multipath over Wi-Fi, peer-to-peer Wi-Fi (AWDL) and Bluetooth LE;
  - multi-hop mesh relaying;
  - **global routing**: gateways, lookup by key through the Mainline DHT, and store-and-forward for strangers.
- A test build is on the [dev-2026-10-08 pre-release](https://github.com/atullal/mycel/releases/tag/dev-2026-10-08).
- The world-scale **network simulator** and the **benchmarks** against established open-source routers are finished. They're merged on the branch `integrate-sim-bench`, not on `main` yet.
- **Carrier fixes and most simulator findings done** (on `integrate-sim-bench`): Mycel now matches or beats the best established router on every heavy benchmark trace. Routing overhead is down ~8×, and a crash and a memory leak are fixed. **In progress:** a last round of fixes. The second test build follows, expected mid-morning on 2026-10-09.

## Try it

1. Download `Mycel_0.1.0_universal.dmg` from the
   [pre-release](https://github.com/atullal/mycel/releases/tag/dev-2026-10-08).
   It runs on Apple silicon and Intel Macs.
2. The app is unsigned. On first launch, right-click **Mycel > Open**. If macOS
   says it is "damaged", run `xattr -dr com.apple.quarantine /Applications/Mycel.app`.
3. **Every device you test with needs the same build.** Mesh hopping changed the
   connection format, so older builds can't talk to this one.
4. The full walkthrough (pairing, permissions, Bluetooth and peer-to-peer
   Wi-Fi testing, logs at `~/Library/Application Support/dev.mycel.host/mycel.log`)
   is in [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md).

To build from source, see the [README](README.md). `cargo test --workspace --exclude mycel-host` runs about 260 Rust tests.

## Where to read

| Topic | Doc |
|---|---|
| Architecture, layers, and a built / not-yet table per layer | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (§11 status, §12 mesh) |
| Routing: survey of ~20 protocols, what we reuse and why, how global reach works | [docs/ROUTING.md](docs/ROUTING.md) |
| Trust layer (membership, epochs, revocation, security review fixes) | [docs/TRUST.md](docs/TRUST.md) |
| App API / SDK | [docs/RUNTIME_API.md](docs/RUNTIME_API.md) |
| Tests and measured evidence | [docs/TESTING.md](docs/TESTING.md) |

## How routing works, in one paragraph

Every device is a router; there's no server. Locally, each device keeps a small
distributed route table built from signed announcements: Babel-style loop-free
routes, instant withdrawals, and fisheye scoping so far-away routes update less
often. A device with internet becomes a **gateway** for nearby Bluetooth-only or
peer-to-peer-only devices. Those devices publish signed "reach me via gateway G"
records in the Mainline DHT, so anyone on the internet can find them by key.
Gateway choice uses the measured **total** route cost, not hop count. If no live
route exists, the message moves as far as it can and is **carried**: devices hold
encrypted bundles they can't read and pass them toward devices more likely to
reach the internet. Mailboxes and signed receipts round this out. Code:
`crates/mycel-net/src/mesh/` (`core.rs` routing, `dtn.rs` store-and-forward).

## In progress right now

The simulator and benchmarks are done. Both are merged on `integrate-sim-bench`,
which is pushed but **not to build on**: it lands on `main` with the carrier fixes
below. The old `wip/sim` and `wip/bench` branches will be deleted then.

### Simulator (`crates/mycel-sim`, `docs/SIMULATION.md`): done

The simulator tests Mycel on every kind of network at global scale:
- **Tier 1** runs real Mycel nodes over emulated radios and an internet with
  real latency. About 500 nodes fit on one Mac.
- **Tier 2** drives the real routing core and carrier for 10,000+ virtual
  devices in virtual time. Every delivery is compared against the fastest one
  that was physically possible, and against simple baseline routers.

26 scenarios at full size: **17 pass**, 4 fail by design (each tied to an open
finding), 4 fail and 1 wasn't run. Highlights:
- US to Europe between Bluetooth-only phones: messages pass. A call over the
  same route loses too much audio.
- 10,000 devices with 30% of them leaving and joining every minute: 100%
  delivered.
- Disaster zone: a stranger carrying a message now delivers it, in 50 s.

**Fixed along the way:**
- Route recomputation is incremental: 25× faster at scale, same results.
- Failed dials back off.
- The carrier sprays copies (Spray-and-Focus), delivers before relaying, and
  drops the oldest when full.
- Slow syncs are handed to the carrier as bundles.

**Open findings** (details in SIMULATION.md §4):
1. **Route announcements overload Bluetooth** at conference density and at
   global scale. This is the main problem, and the fix is a protocol choice
   still to make.
2. A panic in the QUIC library at 300 nodes under memory pressure.
3. Memory growth in the internet-shutdown scenario.
4. Delivery on real conference traces and in the disaster zone is below
   target. The carrier fixes below address it.

### Benchmarks (`bench/`, `docs/BENCHMARKS.md`): done

Mycel's carrier ran against The ONE's five standard routers on real Bluetooth
contact traces (CRAWDAD Infocom 2005/2006, Cambridge) and ONE's Helsinki city
scenario. Meshtasticator compared it with Meshtastic-style flooding.
- **Mycel today** matches or beats the best ONE router on Cambridge,
  Infocom 2005 and Infocom 2006 with gateways. It loses on Infocom 2006 and
  on every Helsinki run. It always sends far fewer copies.
- **Measured on an experimental copy of the carrier**, the fixes below take
  Mycel past the best ONE router on every heavy-workload trace except Helsinki
  with gateways. For example, Infocom 2006 goes from 28.9% delivered to 56.8%,
  against 38.0%, and Helsinki from 30.4% to 73.1%, against 47.4%. On Helsinki
  chat, 32 copies bring it to 97.2%, against MaxProp's 98.1% at a third of the
  traffic.
- **Against Meshtastic-style flooding:** Mycel delivers 98–100% of direct
  messages against 39–73%. Its route announcements don't fit a LoRa radio's
  capacity, though, so LoRa would need a different routing mode.

### Carrier fixes: done (on `integrate-sim-bench`)

- **Offer before payload:** a receiver accepts, resumes or refuses from the
  signed header, before any bytes move. Summaries advertise free space.
- **Interrupted transfers resume**, from any carrier, for 5 minutes.
- **Lifetimes count from creation**, not from each hop.
- **Spray first:** copies go out before the single-copy gradient, which now
  climbs toward the internet only.
- **32 copies for chat-sized bundles**, falling to 4 at 256 KiB.
- **Two copy-accounting bugs fixed:** one custody copy could become two, and
  partial summaries caused millions of duplicate offers.

Benchmarks on the real code (delivered; best ONE router in brackets):
- Infocom 2006 heavy: 28.9% → **57.0%** (38.0%)
- Helsinki heavy: 30.4% → **62.9%** (47.4%)
- Helsinki chat: 87.7% → **97.2%** (98.1%), at a third of MaxProp's traffic

Simulator: `disaster-dtn` goes from 60% to 87%. Real Infocom traces go from
13% to 28% (2005) and from 31% to 51% (2006).

Still losing: Helsinki with tram gateways (37.2% against 51.2%).

**Wire format changed:** the bundle offer and summary fields are new, so
everyone needs the new build.

### Simulator findings: mostly fixed (on `integrate-sim-bench`)

- **Routing overhead.** Announcements now go out every 16 s instead of every
  2 s, with immediate updates on change. New neighbours are greeted with our
  routes, and each device opens at most 6 hop connections. The hop limit is 10.
  - 2,000 Bluetooth phones: 67% → **8%** of the radio, 85% → **100%** routed.
  - 300 phones: 99% of pairs routed in 1.1 s; before, never.
  - US–EU call over Bluetooth hops: 0% audio loss.
- **Crash.** A late QUIC handshake packet could abort the whole app. That's
  fixed in a vendored, patched `noq-proto`, and any connection-level panic now
  closes only that connection.
- **Memory.** An iroh-patch bug re-queued paths on every retry. Memory is now
  flat at ~100 MB for 30 walking nodes, where it peaked at 30 GB before.
- **Helsinki with tram gateways** is no longer a loss: 52.7% against MaxProp's
  51.2%. The gradient now weighs a neighbour's free room.
- **Disaster zone** passes at 87%. The simulator's oracle and copy metrics were
  corrected.

### Now: last round (two agents)

- **Carrier summaries** are now most of the control traffic: 8 KB/s per device
  at global scale. They'll carry only what the forwarding policy uses, as deltas.
- **Repeat messages at global scale** are slower than first ones: the first
  send is lost on a stale internet hop.
- **Conference hall:** Bluetooth queue drops, slow on some seeds.
- **Internet-shutdown call:** connects, but the test tone isn't heard.

### Then

1. Re-run the benchmarks and the affected simulations on the real code.
2. Run the full test suite twice, plus clippy, then merge into `main`.
3. Publish a new universal DMG as the next pre-release.

## Known issues and open questions

- **Bluetooth between two real Macs.** The link connects without pairing, but
  in one test session one laptop kept hanging up after 5–10 s and stopped
  advertising for 10 minutes. The leading suspect is an older build on that
  laptop. We need that laptop's `mycel.log` from the new build to confirm.
- **Peer-to-peer Wi-Fi and Bluetooth on real radios** have far less mileage than
  the emulated tests. Real two-device and multi-device testing is the most
  valuable thing to do with the DMG.
- **Linux:** the Linux Bluetooth (BlueZ) and Wi-Fi Direct code has only been
  cross-compiled and checked, never run on hardware. A Linux machine is
  available for that and for Shadow and Mininet-WiFi.
- **Flaky speed tests.** Tests that measure speed can flake under heavy machine
  load. They now run one at a time within each test binary.
- **Three local-discovery tests fail on the main dev Mac** (`lan_discovery_via_mdns`,
  `one_path_per_interface`, `sync_over_an_interface_with_ip_off`). macOS has
  denied that terminal Local Network access, so this is the environment, not the
  code. If you see "No route to host" to LAN addresses from your terminal,
  allow it in System Settings > Privacy & Security > Local Network.
- **Not audited.** The trust layer needs an external cryptographic review
  before anyone relies on it.

## How we work

- `main` stays green. Merge only after `cargo test --workspace` passes twice in
  a row and `cargo clippy --workspace --all-targets` is clean. Also run
  `npm run build` if you touched TypeScript.
- Use feature branches and PRs into `main`.
- Iroh is vendored with a small multipath patch. Read
  `vendor/iroh/MYCEL_PATCH.md` before touching it.
- Don't commit `dist-release/` (built apps) or any CRAWDAD trace data.

## What's next after this

- Real-device testing with the new build: two or more Macs, Bluetooth-only and
  peer-to-peer-Wi-Fi-only setups, and hopping through a third device.
- Simulation runs on the Linux machine: Shadow at thousands of real nodes,
  and Mininet-WiFi against B.A.T.M.A.N., OLSR and Babel.
- Identity: one person on several devices, personas, and the OS keychain.
- More apps on the platform: a collaborative docs editor, a newsroom, a
  narrative RPG, and P2P version control.
- An external review of the cryptography.
