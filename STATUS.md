# Mycel: where things stand

*Last updated: 2026-10-09, 2:30 pm ET. This is a snapshot for collaborators. The
design docs in `docs/` are the source of truth.*

## TL;DR

- `main` has the full stack:
  - encrypted P2P messaging;
  - 1:1 and group voice and video calls;
  - files of any size;
  - multipath over Wi-Fi, peer-to-peer Wi-Fi (AWDL) and Bluetooth LE;
  - multi-hop mesh routing;
  - **global routing**: gateways, lookup by key through the Mainline DHT, and
    store-and-forward for strangers.
- **New on 2026-10-09:**
  - a world-scale **simulator** (`crates/mycel-sim`);
  - **benchmarks** against established routers (`bench/`);
  - the fixes they led to: a faster and leaner carrier, 8× less routing
    overhead, a crash fix, a memory-leak fix, and a multipath fix.
- **New in the afternoon of 2026-10-09: apps for iPhone and iPad, Android,
  Windows and Linux** next to the Mac app. Same UI and runtime everywhere;
  what works on which platform is in [docs/PLATFORMS.md](docs/PLATFORMS.md).
- Test build: the [dev-2026-10-09 pre-release](https://github.com/atullal/mycel/releases/tag/dev-2026-10-09).
  **Its wire format changed, so every device needs this build.**

## Try it

1. Download `Mycel_0.1.0_universal.dmg` from the
   [pre-release](https://github.com/atullal/mycel/releases/tag/dev-2026-10-09).
   It runs on Apple silicon and Intel Macs.
2. The app is unsigned. On first launch, right-click **Mycel > Open**. If macOS
   says it is "damaged", run `xattr -dr com.apple.quarantine /Applications/Mycel.app`.
3. **Every device you test with needs the same build.** The store-and-forward
   protocol changed, so older builds can't carry messages for this one.
4. The full walkthrough (pairing, permissions, Bluetooth and peer-to-peer
   Wi-Fi testing, logs at `~/Library/Application Support/dev.mycel.host/mycel.log`)
   is in [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md).

To build from source, see the [README](README.md). `cargo test --workspace --exclude mycel-host` runs about 300 Rust tests.

## Apps for every platform

How to build and install each one: [docs/PLATFORMS.md](docs/PLATFORMS.md).

| Platform | State |
|---|---|
| macOS | as before (universal DMG) |
| iPhone, iPad | Runs on the iOS 27 Simulator (iPhone and iPad layouts). Messages to and from a desktop peer work. On devices it needs an Apple ID in Xcode to sign (`scripts/package-ios.sh --install`). Voice calls use Apple's voice processing. Peer-to-peer Wi-Fi, Bluetooth and the camera now share the Mac code, but haven't run on an iPhone yet. |
| Android 9+ | Signed release APK (`scripts/package-android.sh`). Tested on the Android 14 emulator: messages in both directions through the real UI, the on-screen keyboard, and profile and contact codes. Voice calls use the phone's echo canceller. No Bluetooth, Wi-Fi Direct or camera yet. |
| Windows 10+ | NSIS installer and MSI built by GitHub Actions. CI launches the app on a Windows runner: the runtime opens and the UI renders in WebView2 (screenshot artifact). Not tried on a desktop PC yet. |
| Linux | deb, rpm and AppImage built by GitHub Actions. CI launches the app under a virtual display: the runtime opens and the UI renders in WebKitGTK (screenshot artifact). On that bare CI machine it took about 25 s to open (likely a desktop D-Bus service timing out; being checked). Not tried on a Linux desktop yet. |

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

## What landed on 2026-10-09

The full write-ups are in [docs/SIMULATION.md](docs/SIMULATION.md) (method,
models with sources, results, findings) and
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

**Simulator** (`crates/mycel-sim`):
- **Tier 1** runs real nodes over emulated radios and an internet with real
  latency.
- **Tier 2** drives the real routing core and carrier for 10,000+ virtual
  devices in virtual time. Each delivery is compared against the fastest one
  physically possible, and against simple baseline routers.
- `cargo run --release -p mycel-sim -- <scenario|all>`. CI-sized versions run
  in `cargo test -p mycel-sim`.

**Benchmarks** (`bench/`):
- The ONE's routers on real Bluetooth contact traces: CRAWDAD Infocom 2005,
  Infocom 2006 and Cambridge (fetched by `bench/fetch.sh`, never committed),
  plus Helsinki.
- Meshtasticator for LoRa-style flooding.
- Scripts for Shadow, Mininet-WiFi and CORE/EMANE on Linux.

**What changed in Mycel because of them:**
- **Carrier (store-and-forward):**
  - Offers come before payloads.
  - Interrupted transfers resume.
  - Lifetimes count from creation.
  - Spray-first.
  - The gradient climbs toward the internet and prefers neighbours with room.
  - Small bundles get more copies.
  - Summaries only say what changed.
  - On every heavy benchmark trace Mycel now matches or beats the best ONE
    router, with far fewer transmissions. For example, Infocom 2006 is 57%
    against 38%.
- **Routing:**
  - Babel-style timing, with a 16 s period and immediate updates on change.
  - Greetings for new neighbours.
  - At most 6 hop connections per device, and routes up to 10 hops.
  - Route recomputation is incremental.
  - With 2,000 Bluetooth phones, routing uses 8% of the radio, against 67%
    before, and 100% of pairs are routed.
  - At 2,000 devices worldwide, all control traffic is 727 B/s per device.
- **Stability:**
  - A late QUIC handshake packet could abort the app. That's fixed in vendored
    `noq-proto` (`vendor/noq-proto/MYCEL_PATCH.md`).
  - Iroh patch §5 fixes a path-queue memory leak.
  - Iroh patch §6 turns routes found after connecting into paths. Before, a
    second mesh route often never got used.
  - Quitting waits at most 2 s.

**Scenario status:** all 25 scenarios in SIMULATION.md §3 pass at the
largest size this Mac runs. That's up to 100 seats for the conference and
2,002 devices for global scale. Not rerun: the 300-seat conference, the
10k–100k-device runs (for the Linux machine) and `scale-ceiling`.

`disaster-dtn` is judged on the mean of 12 seeds because single runs swing
±3–6 points (SIMULATION.md §4, open 12).

## Known issues and open questions

- **Fixed on 2026-10-09: rules engine stack overflow.** wasmi's tail-call
  dispatch, which it picks in optimised builds, overflowed a 2 MiB thread
  stack while validating chat messages at opt-level 2 on every platform we
  tried. Release builds happened to pass. Mycel now uses wasmi's portable
  (loop) dispatch everywhere, with identical fuel accounting. Builds made
  before this commit (including the dev-2026-10-09 DMG) still have the
  risky dispatch, though their release optimisation level passed the
  tests.

- **New platforms, first builds:**
  - Windows and Linux builds have only run on CI machines so far.
  - iPhone peer-to-peer Wi-Fi, Bluetooth and the camera are untested on
    hardware.
  - The on-screen keyboard is checked on Android but not on an iPhone yet.
  - Phones suspend Mycel in the background. Messages arrive when it's opened
    again, or through a keeper or store-and-forward.
  - Sending video works from Apple devices only.
  - Core tests on CI: Linux all pass. Windows 265 of 267 pass. The two
    failures (`two_links_add_up`, `sync_over_links_and_fall_back_to_bluetooth`)
    rank emulated links by measured speed. The suspect is Windows' coarse
    default timer (about 15.6 ms) skewing the emulated links' pacing. Not
    yet confirmed.

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
- **Flaky speed tests.** Tests that measure speed (video fps, mesh throughput)
  can flake under heavy machine load. They run one at a time within each test
  binary, as do the real-time simulator scenarios.
- **Two routes on saturated links:** `two_routes_aggregate_and_fail_over`
  reaches 1.2–1.4× instead of ≥1.5× in about 1 run in 10. Route announcements
  share the saturated, lossy links and get lost. The fix is to prioritise
  control traffic on hop connections, or to use delay-based congestion control
  on mesh paths.
- **Upstream QUIC bug:** the `noq-proto` crash may be triggerable by a remote
  peer. Our vendored copy is patched. A report for the maintainers is drafted in
  `vendor/noq-proto/UPSTREAM_ISSUE.md` but not filed yet.
- **LoRa-class radios** can't carry Mycel's proactive announcements
  (BENCHMARKS.md §6.6). They'd need on-demand routing.
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
