# Mycel: where things stand

*Last updated: 2026-10-08, 6:30 pm ET. This is a snapshot for collaborators. The
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
- **In progress** on two `wip/` branches: a world-scale **network simulator**, and **benchmarks** against established open-source routers. They found real bugs, and fixes are under way.
- When those land, a second test build follows, expected late on 2026-10-08.

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

Two Claude Code agents are working in parallel on separate branches. Both
branches are pushed as backups. **Don't build on `wip/*`**: they'll be merged
into `main` and deleted.

### 1. Simulator (`wip/sim` → `crates/mycel-sim`, `docs/SIMULATION.md`)

The simulator tests Mycel on every kind of network at global scale. It has two tiers:

- **Tier 1, emulation.** Real Mycel nodes (crypto, QUIC, mesh, sync, calls)
  run over emulated radios (`mycel_net::emu::EmuNet`). The emulation covers
  position and range, throughput, delay and jitter, shared airtime, loss, NAT and
  relays, and an internet with latency from great-circle distance. About 500 nodes
  fit on one Mac.
- **Tier 2, discrete-event simulation.** The real routing core and carrier drive
  10,000–100,000 virtual devices in 24 cities on 6 continents, with mobility,
  churn and real contact traces.
  - Every delivery is compared against an **oracle**: the fastest delivery that
    was physically possible. This measures "did it use the fastest path?".
  - The same scenarios also run simple baseline routers for comparison.
- **Scenarios** include:
  - café, office, apartment Wi-Fi mesh, conference hall;
  - an 8+ hop Bluetooth city block, internet shutdown, disaster zone with data mules, rural road;
  - **US to Europe between Bluetooth-only phones**;
  - gateway choice, partial routes with custody;
  - 100k devices, 30% churn, attacks, multipath, and mixed radios in one room.

**Found and fixed so far** (committed on `wip/sim`, not on `main` yet):
- **Speed:** recomputing routes is now incremental, 25× faster at scale.
- **Carrier:**
  - Spray-and-Focus;
  - deliveries before relays;
  - drop-oldest when the buffer is full;
  - forgetting neighbours that are gone.
- **Node:** dial backoff, and slow syncs handed off as bundles.

**Being worked on:**
- a stranger carrying a message never delivered it in the disaster scenario;
- Bluetooth queue drops in the 300-person conference hall;
- route convergence at full size.

### 2. Benchmarks (`wip/bench` → `bench/`, `docs/BENCHMARKS.md`)

These run established open-source tools on identical inputs, so we aren't
grading our own homework:

- **The ONE**, the standard DTN simulator. Its Epidemic, PRoPHET,
  Spray-and-Wait, MaxProp and Direct Delivery routers run against Mycel's carrier
  on **real Bluetooth contact traces**: CRAWDAD Haggle, from the Infocom 2005 and
  2006 conferences and Cambridge, plus ONE's Helsinki city scenario. There are two
  workloads, ONE's standard heavy one and a chat-like one.
  - The CRAWDAD data's licence forbids redistribution, so it's gitignored.
    `bench/fetch.sh` downloads it.
- **Meshtasticator** compares Meshtastic's flood routing with Mycel's routing on
  the same layouts.
- **Linux-only tools** have ready-to-run scripts in `bench/linux/` for when we
  use the Linux machine: Shadow, Mininet-WiFi against the reference
  B.A.T.M.A.N./OLSR/Babel daemons, and CORE/EMANE.

**Interim results** (measured on the carrier before the fixes above):
- **Copies:** Mycel makes far fewer copies than Epidemic or PRoPHET.
- **Delivery:** Mycel is competitive, and best on Infocom 2005's heavy workload.
- **Losses** being diagnosed, with fixes being tested:
  - *Delay on heavy workloads:* on Cambridge, half of Mycel's deliveries took
    over 23 minutes, against 9–42 s for ONE's routers.
  - *Delivery on Helsinki:* 26%, against 44–48% for Spray-and-Wait and MaxProp.

### Then

1. Merge both into `main`.
2. Apply the benchmark fixes and re-run the comparisons.
3. Run the full test suite twice, plus clippy.
4. Publish a new universal DMG as the next pre-release.

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
