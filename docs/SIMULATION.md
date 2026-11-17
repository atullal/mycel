# Simulation: real-world scenarios, scale and routing

This report describes the simulator in `crates/mycel-sim`, the scenarios it
runs and what they found. The simulator tests Mycel's networking against
emulated versions of the networks people have (Bluetooth, AWDL, Wi-Fi Direct,
Wi-Fi LAN, 802.11s mesh, Ethernet, UWB, Thread, cellular, and the internet
with NAT and relays), with a focus on hops and routing.

It is written for contributors who change routing, store-and-forward or the
link layers, and for readers who want the evidence behind
[ROUTING.md](ROUTING.md). Store-and-forward measured against the routers of
The ONE simulator is in [BENCHMARKS.md](BENCHMARKS.md).

Contents:

1. [Summary](#1-summary)
2. [Method](#2-method)
3. [Scenarios and results](#3-scenarios-and-results)
4. [Findings](#4-findings)
5. [Benchmarks against external baselines](#5-benchmarks-against-external-baselines)
6. [Limitations](#6-limitations)
7. [Reproducing the results](#7-reproducing-the-results)
8. [Wiring other routing cores](#8-wiring-other-routing-cores)

## 1. Summary

The simulator's central question is whether a message from a Bluetooth-only
phone in the US reaches a Bluetooth-only phone in Europe, and whether the
path it takes is the fastest one that existed. It answers in two tiers.
Tier 1 runs real Mycel nodes over emulated radios and wires, in real time.
Tier 2 runs the real routing core and store-and-forward carrier in a
virtual-time simulation; the largest run reported here has 10,003 devices.

Each scenario is named and seeded, and holds the code to objectives such as
delivery ratio, latency, and optimality against the fastest path that was
physically possible. The headline results, for seed 1:

- US to Europe between Bluetooth-only phones. In tier 2 (`us-eu`), 100% of
  messages are delivered, with a latency p95 of 0.725 s and a median of 1.22×
  the fastest possible path. With real nodes (`us-eu-live`), 100% are
  delivered with a p95 of 0.805 s, and a call sets up in 1.63 s over the mesh.
- Scale. At 2,002 devices on 6 continents (`global-scale`), 100% of messages
  are delivered. A first message to a stranger takes 0.741 s at p95, and a
  message on a warm connection 0.211 s. Control traffic is 706 B/s per device.
- Announcement overhead. Among 2,000 Bluetooth-only phones (`flood-scaling`),
  route announcements cost 3.4 kB/s per device, 8.4% of one BLE radio, and
  100% of sampled pairs within 8 hops have a route.
- Store-and-forward. In a disaster zone (`disaster-dtn`) the carrier delivers
  a mean of 87.2% over seeds 1–12, and 77–98% per seed. On the Infocom 2006
  contact trace it delivers 51.2% against PRoPHET's 38.6%. On Infocom 2005 it
  trails PRoPHET, 27.9% against 30.7%.
- Adversaries. Black holes, an announcement storm, a replayer and a Sybil
  gateway leave delivery at 100% (`adversarial`). Black holes that lie
  plausibly take it to 94% at seed 1, 76% at seed 2 and 87% at seed 3. This is
  open.

Three caveats qualify these numbers:

- Every radio and network here is emulated or modelled. No result comes from
  real devices. [§6](#6-limitations) says what the simulation leaves out.
- Most results are for one seed. Where three seeds were run, some thresholds
  do not hold on all of them ([§4](#4-findings), fixed 22 and open 15).
- The runs shared a loaded machine, so wall times and the real-time tier-1
  latencies are pessimistic.

The simulator also found defects in the routing core, the carrier, the
vendored QUIC stack and the simulator itself. [§4](#4-findings) records each
with its evidence, and lists what is still open.

## 2. Method

Real code and global scale do not fit in one process, so the simulator has
two tiers. Both take their link parameters from the same models
([§2.6](#26-link-and-network-models)).

Paths in this report are shortened. `mesh/…` is under
`crates/mycel-net/src/`. `tier1/…`, `tier2/…`, `scenarios/…`, `models.rs`
and `traces.rs` are under `crates/mycel-sim/src/`.

### 2.1 Tier 1: real nodes over emulated networks

Tier 1 runs real `Node`s in one process: iroh QUIC, multipath, the mesh (the
routing core and carrier inside the node), sync, and calls with test-tone
"microphones".

The network is `mycel_net::emu::EmuNet`. It models shared media with
positions, range, rate, airtime (half-duplex, one collision domain per
radio), latency, in-order jitter and loss. It also has per-pair rules (NAT,
access latency, 802.11s hops), discovery, and devices coming and going.

Tier 1 runs in real time, because iroh, noq and the mesh read `std::time`.
Paused tokio time was measured: it gave no speed-up and mixed clocks. A node
costs ~2–2.5 MB and ~1% of a core. 500 nodes were measured (1.2 GB) on one
Mac with 18 cores and 24 GB.

### 2.2 Tier 2: discrete-event simulation

Tier 2 runs the sans-IO routing core (`mesh/core.rs`) and the
store-and-forward carrier (`mesh/dtn.rs`). Both are the real code, driven by
a discrete-event engine. Beside them run models of earlier designs and
baseline routers.

The network is modelled: per-hop latency plus size ÷ rate per radio, the
internet with geography, NAT and relays, a record directory, mobility, churn
and contact traces. Time is virtual, in microseconds, with one event queue.

On the same Mac, tier 2 processes ~1.1 M events/s on one core. 2,002 devices
for 12 simulated minutes take 116 s and 840 MB. 10,003 devices take 33 min
and 2.15 GB, measured on a loaded, swapping machine.

### 2.3 Messages and calls

In tier 1 a message is real Mycel sync: a change to a shared document, timed
until the recipient's replica shows it. A call is a real `mycel-call` call.

In tier 2 a message is split into QUIC-sized packets and sent by a QUIC-like
sender: per-packet acks, a congestion window starting at 10 packets, an
adaptive retransmission timeout, and retransmission for 10 minutes. If the
live attempt isn't getting through, the message also becomes a
store-and-forward bundle, as in the node. Call setup is an offer and an
answer through the routing.

### 2.4 Optimality

For each delivered message, in every scenario, the achieved latency is
divided by the fastest path that was physically possible. The ratio is
reported as p50 / p95 / p99.

In tier 2 the fastest path comes from an oracle (`tier2/oracle.rs`). It is an
earliest-arrival search over the ground-truth contact plan (who could hear
whom when, who had internet when) that moves the message store-and-forward
hop by hop and waits anywhere for free. In tier 1 it is Dijkstra over the
emulated media.

The oracle is a lower bound: it has no congestion control, no lookups and no
handshakes. What the ratio measures therefore depends on the message:

- for small messages, routing (path choice and lookups);
- for large ones, also QUIC slow start over long round trips;
- in tier 1, also Mycel sync's own round trips. A 32 ms message on a 5 ms LAN
  path is 6×.

### 2.5 Objectives and candidates

Each scenario holds a candidate to objectives: delivery ratio, latency p95,
optimality, call setup, audio loss, overhead, relay fairness. It passes,
fails, or fails as expected with the reason recorded (a known gap, or a
finding with evidence).

Tier-1 scenarios judge the real node. Tier-2 scenarios judge the candidate
that `--candidate` names:

- `global`, the default: the routing core and carrier;
- `main`: the earlier flooding mesh, modelled;
- `stand-in`: an earlier model of the current design, kept as a reference.

Every scenario is named, seeded and reproducible. The same seed gives the
same result, and tier 2 is fully deterministic.

### 2.6 Link and network models

`models.rs` has every number and its source. The radios:

| Medium | Goodput | Latency (+ jitter) | Range indoors / outdoors | Source |
|---|---|---|---|---|
| BLE L2CAP CoC | 40 kB/s per radio | 15 ms + 15 | 20 / 60 m | Bluetooth Core 5.x; Apple WWDC17 (L2CAP CoC); Gomez et al., Sensors 2012 |
| AWDL | 12 MB/s | 2 ms + 20 (channel hopping) | 50 / 100 m | Stute et al., MobiCom 2018 |
| Wi-Fi Direct | 8 MB/s | 3 ms + 5 | 50 / 150 m | Wi-Fi P2P spec; measured 50–150 Mbit/s |
| Wi-Fi LAN (AP) | 15 MB/s shared | 3 ms + 5 | 40 / 100 m | busy 802.11ac BSS |
| 802.11s mesh | 10 MB/s ÷ min(hops, 4) | +3 ms per hop | building | Li et al., MobiCom 2001 (chain capacity → ~¼) |
| Ethernet | 110 MB/s | 0.2 ms | wired | GbE TCP goodput |
| UWB (802.15.4z HRP) | 250 kB/s | 2 ms | 30 / 60 m | DW3000 data mode |
| Thread / 802.15.4 | 8 kB/s, 1% loss | 10 ms + 10 | 25 / 80 m | 250 kbit/s PHY, 6LoWPAN overhead |
| The ONE Bluetooth | 250 kB/s | 1 ms | 10 m | The ONE default settings (trace replay only) |

A BLE radio's 40 kB/s is shared by the links with data queued. Each peer has
a 16 KiB drop-tail queue, the size of the real link's
(`mycel_link_ble::OUT_QUEUE_BYTES`), and connection events are served in turn
(Bluetooth Core 5.4, Vol 6, Part B, §4.5.1).

The internet:

| Part | Model | Source |
|---|---|---|
| Cellular access | LTE 1.5 MB/s up, 20 ms one way; 5G 5 MB/s, 8 ms | Narayanan et al., IMC 2021; Ookla/OpenSignal |
| Backbone | 5 µs/km × 1.4 over the great circle | Singla et al., HotNets 2014; checked against WonderNetwork ([§5.5](#55-internet-latency-from-measured-data)) |
| NAT | hard–hard and hard–easy relay, others direct | Ford et al., USENIX ATC 2005; Richter et al., IMC 2016 |
| Relays | client → nearest relay → peer's relay → peer | n0 relay regions |

### 2.7 Devices, mobility and churn

The tier-2 world has 24 cities on 6 continents, weighted by population.
Internet adoption is by region, from GSMA, *The Mobile Economy* 2024: ~85–90%
in North America and Europe, ~60% in Asia-Pacific and Latin America, ~35% in
Sub-Saharan Africa. Phones have BLE plus AWDL (30%) or Wi-Fi Direct. Most
cellular devices are behind carrier-grade NAT.

Mobility is static, random waypoint, or scripted paths (mules). Churn
switches devices off and on.

## 3. Scenarios and results

Results are for seed 1 at full size unless noted. Tier-1 scenarios judge the
real node; tier-2 scenarios judge the routing core and carrier. Every
scenario below passes its objectives at the seed and size shown. Where other
seeds fail, the scenario's entry says so.

The scenarios ran as separate processes and were joined with `mycel-sim
merge`, with the fixes of [§4](#4-findings) in place. The machine was loaded
(load averages of 9 to 40 on 18 cores, with other simulations and builds
running), so wall times are pessimistic, and the real-time tier-1 latencies
(calls especially) carry that load. Replays of real contact traces are in
[§5.2](#52-real-contact-traces).

### 3.1 Tier 1: real nodes

Message delivery over a fixed topology:

| Scenario | Setting | Delivered | Latency p50 | p95 | Optimality p50 / p95 / p99 | Wall |
|---|---|---:|---:|---:|---:|---:|
| `cafe` | one Wi-Fi access point, phones and laptops | 100% | 0.032 s | 0.039 s | 5.77 / 7.00 / 7.22× | 18 s |
| `office` | Ethernet and Wi-Fi on two floors | 100% | 0.032 s | 0.034 s | 6.00 / 59.3 / 60.6× | 10 s |
| `apartment-80211s` | a building on an 802.11s Wi-Fi mesh | 100% | 0.083 s | 0.095 s | 5.63 / 6.98 / 6.98× | 10 s |
| `city-block` | a Bluetooth chain with no internet, 8 hops | 100% | 0.973 s | 0.978 s | 3.24 / 3.26 / 3.26× | 24 s |
| `rural-line` | a line of houses on Wi-Fi Direct and BLE | 100% | 0.100 s | 0.120 s | 5.73 / 6.87 / 6.87× | 18 s |
| `us-eu-live` | BLE → gateway → internet → gateway → BLE | 100% | 0.788 s | 0.805 s | 4.17 / 4.26 / 4.26× | 20 s |
| `nat-relay` | NAT types and relay paths | 100% | 0.233 s | 0.488 s | 3.32 / 4.57 / 4.80× | 23 s |
| `nat-relay` | the same, during the relay outage | 100% | 0.263 s | 0.772 s | 3.32 / 6.39 / 130× | same run |
| `adversarial-live` | past a black hole and an announcement storm | 100% | 0.275 s | 0.308 s | 3.66 / 4.11 / 4.11× | 16 s |

Other results from these runs:

- Calls. In `cafe` the call sets up in 0.051 s, with 0.0% loss and 101 ms
  latency, on path `Some(Network)`. In `us-eu-live` it sets up in 1.63 s,
  with 0.0% loss and 435 ms latency, on path `Some(Mesh)`.
- Bulk throughput. `apartment-80211s`: 8.2 MB/s to the next flat, 2.2 MB/s
  7 flats away. `rural-line`: 6.7 MB/s to the next house, 0.70 MB/s over 5
  hops.
- `city-block` also delivers over 9 hops (`max_hops` = 10).

Scenarios that measure something else:

- `multipath` (several radios between two devices, aggregated): 3 links
  carry 8.0 MB/s and 1 link 2.9 MB/s (2.76×). Wall 21 s.
- `mixed-room` (two devices that share Ethernet, Wi-Fi Direct, UWB and
  Bluetooth LE). The media are switched off one after another, and the path
  is each time the best medium still up: Ethernet → `Some(Ethernet)`, Wi-Fi
  Direct → `Some(WifiDirect)`, UWB → `Some(Uwb)`, Bluetooth LE →
  `Some(Bluetooth)`. Wall 26 s.
- `disaster-live` (two camps and a mule that walks between them). A mule
  that is a member delivers in 49 s, a stranger mule in 50 s. Wall 60 s.
- `scale-ceiling` measures how many real nodes one machine runs. Its
  figures are in [§2.1](#21-tier-1-real-nodes-over-emulated-networks).

`conference` is a hall of dense BLE and AWDL with no Wi-Fi:

- 24 seats (scale 0.08), seeds 1–5: 100% of messages delivered on every
  seed, p95 0.20 / 1.19 / 0.89 / 0.48 / 0.60 s, 0 Bluetooth packets dropped.
  Wall 15–20 s.
- 30 seats, seed 1: 100% delivered, p95 0.411 s.
- 100 seats, seed 1 (a seat hears ~49 others, with 12 hop connections each):
  100% delivered, p50 0.463 s, p95 1.10 s, 26 of 169,243 Bluetooth packets
  dropped, +272 MB (2.7 MB per node). Wall 38 s.

`shutdown` is an internet shutdown: mesh only, people walking. At full size,
seeds 1–4:

- messages between devices connected at the time: 100 / 90 / 100 / 100%
  delivered, p95 0.59 / 0.78 / 0.76 / 6.97 s;
- a call between two walkers: heard on every seed, loss 0.0%, setup
  0.58–1.02 s, over the mesh or Bluetooth;
- memory +69–87 MB for 30 nodes. Wall 49–123 s.

### 3.2 Tier 2: the routing core and carrier

Message delivery:

| Scenario | Setting | Size | Delivered | Latency p95 | Optimality p50 / p95 / p99 | Wall |
|---|---|---|---:|---:|---:|---:|
| `us-eu` | US to Europe, BLE-only phones a few hops from a gateway | full | 100% | 0.725 s | 1.22 / 2.15 / 2.38× | 1 s |
| `gateway-choice` | a near gateway on a slow uplink, a far one on fibre | full | 100% | 1.11 s | 6.26 / 9.12 / 9.19× | 0 s |
| `mailbox` | destination offline for hours, one drain | full | 100% | 9900 s | 1.00 / 1.00 / 1.00× | 0 s |
| `global-scale` | 6 continents, mixed connectivity | 2,002 devices (0.02) | 100% | 0.690 s | p50 3.96× | 119 s |
| `churn` | devices leave and join each minute | 1,001 devices (scale 0.1) | 100% | 61.2 s | 5.87 / 12.5 / 17.1× | 81 s |
| `adversarial` | black holes, a storm, replays, a Sybil gateway | full | 100% | 0.097 s | 1.88 / 5.97 / 8.65× | 142 s |
| `trace-replay` | a synthetic contact trace, The ONE's workload | full | 99.5% of feasible | 1245 s | 1.22 / 7.55 / 46.9× | 49 s |
| `disaster-dtn` | a disaster zone, seed 1 | full | 90% | 7625 s | 1.43 / 6.11 / 6.81× | 95 s |

More from these runs:

- `gateway-choice`: 100% of relayed bytes go via the far fibre gateway. Its
  100 KB and 1 MB messages are judged against the pipelining bound (fixed
  12).
- `global-scale`: first contact p95 0.741 s (objective ≤ 3 s), optimality
  p95 12.9×. Warm p50 0.119 s, p95 0.211 s, optimality p95 2.88×. Control
  706 B/s per device: routing 470, carrier 235. At CI size (1,499 devices)
  the warm optimality p95 is 2.65×.
- `churn`: control 698 B/s per device. Over the fixes of §4, routing went
  2,659 → 469 and carrier 4,540 → 256. Full size before the carrier fixes:
  100%, p95 65.2 s.
- `adversarial`: clean 100%, attacked 100%, Sybil gateway 100%. Black holes
  lying plausibly (judged, ≥ 90%): 94%, p95 29 s. That run fails with seed 2
  (76%) and seed 3 (87%): open 15. At CI size (0.1): 100%, lying plausibly
  97%, and it passes with seeds 2 and 3.
- `trace-replay`: the synthetic trace has 40 devices and 17,562 contacts
  over 72 h. 3,983 of 4,000 sent are delivered, p50 4.7 s, overhead 3.26.
  Earlier optimality figures: p95/p99 8.38/18.0× before fixed 21, and 10.1×
  at 54cc562 after the routing changes; the oracle is pipelining-aware since
  fixed 12. Seeds 2 and 3: 99.8% and 99.0%, optimality p99 19.9× and 25.5×.
  On real traces: Infocom 2006 50.8% (passes); Infocom 2005 27.5% against a
  target of 30% (not rerun; see [§5.2](#52-real-contact-traces)).
- `disaster-dtn` is judged on the mean of seeds 1–12: 87.2% delivered
  (target ≥ 80%; per seed 77–98%). Seeds 2–13 give a mean of 87.1%, seeds
  3–14 86.9%. At seed 1: 21.2 replicas and 32.9 hand-offs per message
  (budget 32). On the same world (seed 1, 60 of 60 messages feasible for
  every router): PRoPHET 67%, spray-and-wait (L=8) 27%, epidemic 100%. At CI
  size (0.1): 89%.

Scenarios that measure something else:

- `routing-convergence` (convergence, loops, and re-convergence after a hub
  fails): 99% of pairs routed in 1.1 s, 0 loops, re-converged in 0.1 s,
  stretch 1.01×. The `main` candidate never routes 99%. Wall 15 s.
- `flood-scaling` (announcement overhead against mesh size): at the largest
  size, 8.4% of a BLE radio in steady state and 100% of pairs routed; `main`
  136.1%. Before fixed 14: 67.0%, 85% routed. The table is in
  [§5.4](#54-announcement-overhead-against-mesh-size). Wall 839 s.
- `flood-hop-limit` (managed flooding): reach by hop limit 1..7 is 16%, 33%,
  53%, 68%, 83%, 92%, 93%. The table is in
  [§5.3](#53-flooding-baseline). Wall 0 s.

`partial-route` has a Bluetooth chain with a break in it, which a walking
mule bridges: a partial route, custody at the break, and the mule completes
it. Delivery by the width of the break (wall 0 s):

| Gap | Routing core and carrier | Stand-in, custody | Sender holds |
|---|---|---|---|
| 100 m | 100% | 100%, p50 97.5 s | 100%, p50 98.2 s |
| 300 m | 100% | 0%, p50 0 s | 0%, p50 0 s |

## 4. Findings

Each finding has its evidence and a way to reproduce it, with `--seed 1`
unless noted. Code comments cite them by number: "fixed N" is a finding in
[§4.1](#41-findings-that-changed-the-code), and "open N" or "finding N" is
one in [§4.2](#42-open-findings). The numbers are kept when a finding closes.

### 4.1 Findings that changed the code

By area:

- routing core: fixed 1, 4, 14, 19, 20 and 21;
- carrier: fixed 2, 3, 5, 6, 8, 13 and 17;
- node and vendored QUIC stack: fixed 9, 10 and 16;
- the simulator and emulator themselves: fixed 7, 11, 12, 15, 18 and 22.

#### Fixed 1: the routing core's `tick` did a full pass every 10–20 ms

`tick` re-ran route publishing for every origin (allocating a new map),
recomputed gateway choice, and scanned every route, origin, record and
lookup for expiry. On a router that knows ~80 origins this dominated tier 2:
a 2,002-device `global-scale` took 3,075 s.

`tick` now revisits only what changed: a queue of due rebroadcasts, exact
expiry deadlines, dirty origins, and an incremental gateway table
(`mesh/core.rs`). The results are identical: the same 140,349,740 events and
every metric bit-for-bit on the tier-2 suite. The same run now takes 116 s,
and the CI-sized tier-2 suite 31 s instead of 183 s. The real node ticks
every 20 ms too, so phones benefit.

#### Fixed 2: a stranger mule never carried anything

In `disaster-live` a member mule delivered in 49 s and a stranger mule
never. There were two causes:

- The carrier sprayed copies only when its own predictability for the
  destination was exactly 0. Camp A and a passer-by who had both met camp B
  ranked equal, so A kept the bundle. The fix was Spray-and-Focus: half the
  copies go to the likeliest neighbour that is no worse a carrier. (Fixed 8
  later replaced it with spray-first.)
- The node offered a bundle only when its sync with camp B failed. A stale
  connection to B made that take 60 s, by which time the mules had walked
  out of range. A sync not through in 10 s is now also bundled.

The stranger mule now delivers in 50 s. The code is in `mesh/dtn.rs` and
`crates/mycel-net/src/lib.rs`; the tests are
`a_passer_by_as_good_as_the_holder_gets_a_copy` and
`a_mailbox_does_not_spray`.

#### Fixed 3: sprays could starve deliveries

Transfers left in bundle-id order, so 1 MB sprays to bystanders queued on
the radio ahead of the destination. Deliveries now go first, then live
routes, the gradient and sprays, and spraying skips clearly worse carriers.
On the CI-sized synthetic trace, spraying to anyone delivered 18%; this
delivers 86%.

#### Fixed 4: failed dials were retried on every plan

At CI size, `disaster-dtn` made 56,987 dials to destinations not on the
internet. They now back off (2 s, doubling to 60 s): 471 dials. Meanwhile
`toward` answers `Unreachable`, so a gateway holding such a bundle stops
counting the internet and carries it by predictability for the destination.
The code is in `mesh/core.rs`; the test is `failed_dials_back_off`.

#### Fixed 5: a full carrier refused everything new

Its own bundles also counted against the space for others. On Infocom 2005,
258,751 hand-offs were refused. The carrier now drops the carried bundle
nearest expiry (drop-oldest; Lindgren and Phanse, 2006), and `capacity`
counts only what it carries, as documented. Refusals fell to 76,434, and
deliveries rose from 325 to 519. The test is
`a_full_store_drops_the_oldest_carried_bundle`.

#### Fixed 6: carriers kept every neighbour's last summary forever

A summary is ~5 KB, and a phone in a crowd meets thousands of devices a day.
Summaries are now forgotten 10 minutes after the neighbour was last heard.
The test is `neighbours_long_gone_are_forgotten`.

#### Fixed 7: simulator bugs

- The tier-2 driver handed a message to the carrier again on every retry
  once the source had passed on custody, multiplying copies. This inflated
  earlier store-and-forward numbers: `disaster-dtn` showed 88% where the
  truth is 60%, and the CI synthetic trace 92% where it is 50%. Each message
  is now bundled once, as in the node.
- Runs that check only a sample of messages against the oracle counted
  every delivered message as feasible, so each router had a different
  denominator.
- Tier 2 uses `verified_max: 64`, because signatures are stubbed. The
  4,096-entry cache was ~300 KB per router.

#### Fixed 8: the carrier's measured fixes are applied

The fixes measured in
[BENCHMARKS.md §6](BENCHMARKS.md#6-where-mycel-lost-why-and-the-fix) are
applied to `mesh/dtn.rs`, the node (`mesh/mod.rs`) and tier 2:

- bundles are offered before their payload, and a refusal costs a round
  trip, not the transfer;
- summaries carry the room left, so full carriers aren't offered anything;
- a cut transfer resumes;
- lifetimes run from creation;
- a source over its share makes way with its own bundles first;
- copies in flight aren't given twice. Before this, a single copy in
  custody offered to a second neighbour while the first transfer was still
  under way became two. On `disaster-dtn` that alone was half the copies per
  message (60 → 34).

The policy changed too: spray-first, a single copy follows predictability
toward the internet only, and small bundles get more copies (32 at 16 KiB or
less, 4 at 256 KiB or more).

Effect, seed 1 unless noted:

- `disaster-dtn`: 60% → 87% (mean of 5 seeds 90%). With the old policy
  (Spray-and-Focus, max(P(dst), P(internet)), 4 copies) on the new
  mechanics: 52% (mean of 5 seeds). With no gradient: 77%. With 4, 8 or 16
  copies for small bundles: 60%, 69% or 68%.
- `trace-replay` on real traces: Infocom 2005 13.0% → 27.9% of messages;
  Infocom 2006 31.3% → 51.2%, ahead of PRoPHET (38.6%), Spray-and-Wait
  (28.6%) and Epidemic (20.6%).

Carrier policies can be chosen for any scenario with `MYCEL_DTN`, for
example `MYCEL_DTN=spray=focus,gradient=both,copies_small=4` (see
`DtnConfig::tune`). The tests are in `mesh/dtn/tests.rs`:

- `offers_are_refused_before_the_payload`;
- `a_refusal_marks_the_neighbour_full_until_its_next_summary`;
- `cut_transfers_resume`;
- `lifetimes_run_from_creation_not_per_hop`;
- `a_source_over_its_share_makes_way_with_its_own`;
- `copies_by_size`, `spray_modes`;
- `copies_in_flight_are_not_given_twice`.

#### Fixed 9: a panic in the QUIC stack aborted the whole process

Was open 7. It happened in a 300-node tier-1 `conference` run. The vendored
`noq` and `noq-proto` carry a fix with regression tests
(`vendor/noq-proto/MYCEL_PATCH.md`); a state-machine panic now closes only
that connection.

#### Fixed 10: walking devices grew memory without bound

Was open 8. `shutdown` peaked at 30 GB of physical footprint. Resident size
read +4.8 GB: under memory pressure it leaves out compressed and swapped
pages.

`sample` showed one core spinning in Iroh's path-open retry queue. When a
path can't be opened yet (no CIDs, or path IDs used up), Iroh re-queued the
address once per connection to that peer, and every lookup re-added every
custom address. With Mycel's several connections per peer and more links
than a connection's 8 path IDs, the queue multiplied every 333 ms.

The fix queues each address once (`vendor/iroh/MYCEL_PATCH.md`, item 5).
After it:

- full-size `shutdown` passes with memory flat at ~100 MB (+106 MB for 30
  nodes, 3.5 MB each) over 500 s;
- `crates/mycel-net/tests/path_queue.rs` (16 links, 4 connections) grows
  <2 MB in 10 s; without the fix, 21 MB in 5 s.

`tier1::resources()` now reads the physical footprint on macOS.
`MYCEL_SIM_MEMLOG=<secs>` logs memory and tasks during a run, and
`examples/mem_walk.rs` tracks memory for N walking nodes.

#### Fixed 11: copies counted custody moves

Was open 3.

- `copies/msg` now counts replicas: a carrier kept some copies while it
  handed others on. `hand-offs/msg` counts every carrier-to-carrier
  transfer, The ONE's "relayed"; `trace-replay`'s overhead ratio uses it.
- `disaster-dtn`, seed 1: 27.4 replicas and 32.5 hand-offs per message.
  Spray-first with 32 copies for 2 kB bundles makes most of them.
- The target is now the carrier's copy budget for that size (32), not
  Spray-and-Wait's 8. With 8 copies delivery falls at seeds 1–3, from
  87/93/85% to 85/85/60%. It passes.
- Still open: an 8-copy budget showed 32.7 replicas (open 3).

#### Fixed 12: the oracle wasn't a lower bound for multi-packet messages

Was open 10. The bound for those is now the fastest single packet, plus the
rest at the most the destination can take in at once (all its radios and the
fastest access), and never above the hop-by-hop time. Synthetic
`trace-replay` optimality p50 went from 0.630 to 1.23. No ratio is below 1
any more.

#### Fixed 13: neighbours' predictability tables are sorted vectors

Was part of open 6. The vectors are half the size of the hash maps and hold
the same values.

#### Fixed 14: announcements no longer overload Bluetooth

Was open 1. Every device re-flooded a signed ~120-byte announcement every
2 s, unicast to every neighbour. The changes were measured with `MYCEL_CORE`
knobs (`Config::tune`), then made in `mesh/core.rs` and the node:

- Babel's timing. The period is 16 s, not 2 s, and the full scope goes out
  every 8th period, not every 4th. Lost links never waited for the period
  (hop connections time out in seconds and trigger retractions and seqno
  requests), so it only refreshes. What changes goes out at once: a new
  neighbour is greeted with our routes (one per 4 s, for crowds), and a
  device's first neighbour gets a full-scope announcement.
- Flood reduction off. Skipping a rebroadcast after hearing 3 copies assumes
  broadcast radios. Over unicast hops it left 9% of pairs unrouted
  (`routing-convergence`: 91% with it, 99% without, at 16 s).
- 10 hops, not 8. Routes follow the cheapest path, which can be a hop or two
  longer than the fewest hops. Every unrouted pair left in `flood-scaling`
  and `routing-convergence` was exactly 8 radio hops apart with no
  announcement received: 97% → 100% of pairs.
- Batched announcements (one datagram per neighbour per tick), and at most 6
  hop connections opened per device in range. The others open theirs: ~11 in
  all in the conference, from 15, and 37% fewer Bluetooth packets.

Before → after, seed 1:

- `routing-convergence` (300 phones): 99% of pairs routed never → in 1.1 s;
  after the hub fails, re-converged never → 0.1 s; 0 loops; control 18.6 →
  6.2 kB/s per device, cold start included.
- `flood-scaling`, 2,000 Bluetooth-only phones, steady state: 26.8 → 3.4
  kB/s per device (67% → 8.4% of a BLE radio), 85% → 100% of pairs routed
  ([§5.4](#54-announcement-overhead-against-mesh-size)).
- `global-scale` at 2,002 devices: routing traffic 3,768 → 467 B/s per
  device; the simulation runs 6× faster (140 M → 29 M events).
- `churn` at 1,001 devices: routing traffic 2,659 → 470 B/s, delivery and
  latency unchanged (100%, p95 61.2 s).
- `us-eu-live`: passes (call loss 0%), but that scenario sets its own 1 s
  period; the 66.7% loss was most likely the overloaded machine (open 9).
- `conference` (24 seats): 80% → 100% delivered; p95 still over 3 s until
  fixed 15.

The tests are `new_neighbours_are_greeted_and_lone_devices_announce_fully`
and `flood_reduction_is_off_and_floods_reach_everyone`
(`mesh/core/tests.rs`), and `announcements_batch_into_datagrams`
(`mesh/wire.rs`).

#### Fixed 15: the emulator's Bluetooth model queued a whole radio in one FIFO

Was open 1's `conference` latency, and open 11. `EmuNet` gave each radio one
transmit queue bounded at 250 ms (10 KB at 40 kB/s) for all its peers. A
burst to one peer (a QUIC handshake, a sync) therefore dropped packets to
every other peer: 15–25% of Bluetooth packets in `conference`, whatever the
announcement settings.

The real link isn't like that. `mycel-link-ble` opens one L2CAP channel per
peer, each with its own 16 KiB drop-tail queue (`OUT_QUEUE_BYTES`), and the
controller serves its connections in turn, one connection event each
(Bluetooth Core 5.4, Vol 6, Part B, §4.5.1).

The fix is `Medium::peer_queue`: each link has its own byte-bounded queue,
and the radio's rate is shared between the links with data queued at either
end. `Tech::Ble` uses 16 KiB (`crates/mycel-net/src/emu.rs`, test
`peer_queues_share_the_radio`). `MYCEL_SIM_BLE_QUEUE=radio` brings back the
old model for comparison. Results:

- `conference`, 24 seats, seeds 1–5: Bluetooth drops 15–25% → 0%, p95
  1.4–8.2 s → 0.20–1.19 s (target 3 s). 30 seats: p95 0.41 s. 100 seats:
  p95 1.10 s in 38 s of wall time; it didn't finish in 30 min before, with
  the path-queue leak of fixed 10.
- `shutdown`, full size, seed 1: with the old model p95 was 10.2 s and the
  call never rang; now p95 is 0.59 s and the tone is heard. Seeds 1–4: heard
  every time, loss 0%, over the mesh or straight over Bluetooth.
- Every other Bluetooth scenario passes at full size with it (`city-block`,
  `rural-line`, `us-eu-live`, `disaster-live`, `mixed-room`,
  `adversarial-live`, `multipath`).

No change was needed in the node: with the real queueing, a burst to one
neighbour no longer costs the others, and nothing is dropped. The limit of
the new model is in [§6](#6-limitations).

#### Fixed 16: shutting the lab down took minutes

A node's endpoint close waits for every peer to acknowledge
CONNECTION_CLOSE, up to 3 probe timeouts per connection. To peers on a slow
radio or already gone, that is seconds per node, and the lab closed nodes
one after another (30 walkers: ~4 minutes; a 24-seat conference: 70 s).

The lab now closes every node at once, and `Node::shutdown` waits at most
2 s (`SHUTDOWN_GRACE`) for the acks; the close frames still go out at once.
Quitting the app no longer hangs on a slow radio either. `shutdown` at full
size: 502 s → 49–123 s wall. `conference` at 24 seats: 96 s → 15–20 s.

#### Fixed 17: carrier summaries went to every neighbour every 10 s, whole

Was open 1, first bullet. Each summary listed everything held, the latest
256 receipts and up to 64 predictabilities (36 B each), whether anything had
changed or not: 8,004 B/s per device at 2,002 devices in `global-scale`,
4,540 in `churn`.

`Carrier::summaries` now decides per neighbour (see
[ROUTING.md](ROUTING.md)):

- everything at first contact (`new_contact`) and every 60 s;
- between those, only what changed, at most every 2 s: bundles taken and
  receipts learnt since, room, and the predictabilities the gradient uses.
  With the internet gradient that is P(internet), plus P(destination) for
  destinations a neighbour asks for (`wants`: it holds bundles for them that
  the internet can't deliver);
- nothing if nothing changed. A summary whose stream failed (or, in the
  simulator, that didn't arrive) resets the neighbour to a full one.

Full summaries keep the 64 most useful predictabilities. PRoPHET's
transitivity needs destination predictabilities to travel hop by hop, and
the internet gradient falls back on them for destinations the internet
doesn't reach; `wants` alone answers only one hop away. The `disaster-dtn`
numbers can't separate these variants (open 12).

Measured, seed 1:

- `global-scale`: carrier 8,004 → 257 B/s, total control 8,470 → 727 B/s
  (target 1,000: passes);
- `churn`: carrier 4,540 → 264 B/s, delivery and latency unchanged;
- `mailbox`, `partial-route` and synthetic `trace-replay`: unchanged;
- the bench's forwarding: unchanged (it sends full summaries; the Cambridge
  rerun is identical);
- `disaster-dtn`: see open 12.

A full summary every 120 s instead of 60 s would halve what is left (279 →
156 B/s at 300 s) but cost `disaster-dtn` ~5 points of 12-seed mean, within
the noise of open 12.

The tests are `summaries_say_what_changed_and_only_what_the_gradient_uses`
and `wants_bring_destination_predictabilities` (`mesh/dtn/tests.rs`).

#### Fixed 18: warm messages between internet devices lost their first packet

Was open 4: `global-scale` warm optimality p95 was 32.2×, for messages
between two devices that both have the internet. This was a simulator
artefact, not a node bug.

The tier-2 driver sent app data through the routing core unless the peer was
in radio range. Two devices with the internet reach each other by dialling
an internet hop, which makes the peer a core neighbour, and the core refuses
data for a neighbour ("a direct path always wins"). So the first message got
through on the dial, and the second, a minute later over the hop still up,
was dropped. The destination's acks were dropped the same way. The 1 s
retransmission went out after the hop had idled out, and looked up and
dialled again: first-contact latency + 1 s.

It was traced on the pair 688 → 447 (seed 1): 447's ack was refused at
120.559 s, and 688's retry went out at 121.000 s.

In the node, two devices with the internet talk over Iroh's own direct
connection, pooled for `POOL_IDLE` (60 s), not through the mesh. The driver
now does the same: data goes direct over the internet while a connection is
warm (any packet within 60 s, or an internet hop up). Warm: p95 1.69 →
0.286 s, optimality p95 32.2 → 4.45× (target 5×). First contact is unchanged
(p95 0.741 s).

#### Fixed 19: warm messages behind gateways paid a lookup and a dial again

Warm messages to a device behind gateways paid a lookup and a dial again.
`global-scale` at its CI size (1,499 devices) failed: warm optimality p95
5.14× against 5×, and the same on e6a972b, 77 commits earlier.

It was traced per packet (seed 1). Of the 13 warm messages over 5×, 10 went
from a device with the internet to one behind gateways, and their internet
hop took as long as at first contact (0.4–0.8 s, against an optimum of
0.07–0.15 s for the whole way). The other 3 are open 13.

There were two causes in the routing core's choice among a record's gateways
(`next_hop`, `mesh/core.rs`):

- An untried gateway looked cheaper than the working one. It was costed as a
  flat 100 ms (`DEFAULT_INTERNET_COST`). A measured hop costs its round trip
  plus the time to move 64 KiB: 160–320 ms between continents in the
  simulator, more in the node (RTT × (1 + 64 KiB ÷ cwnd)). So once the first
  gateway's hop was measured, the next packet dialled the record's other
  gateway and waited for it (n365 → n217: dial n229 at +0 ms, connected at
  +271 ms), and again whenever the unused hop idled out after a minute.
- The record had just expired. A looked-up record is trusted for 60 s, and
  the warm message came a minute after the first. When the dial was through,
  the record was out of date, so the packet waited for a second lookup
  (+190 ms). In the node, a gateway relaying a long flow parked it for a
  lookup every minute.

The fix has two parts, with no wire change:

- An untried gateway is costed as the cheapest measured hop to another
  gateway of the same record (they sit in one mesh around the destination;
  100 ms only when none is measured), and one with a hop up wins ties.
- A record out of date is looked up again on use while a hop up to one of
  its gateways keeps carrying the traffic, for another minute
  (`REACH_STALE`); it never starts a dial.

The tests are `a_working_gateway_is_kept_over_untried_ones` and
`an_out_of_date_record_keeps_a_working_gateway_while_it_is_looked_up`
(`mesh/core/tests.rs`).

`global-scale`, warm messages, optimality p95 (p99):

| Size, seed | Before | After |
|---|---|---|
| 1,499 devices (CI), seed 1 | 5.14× (8.54×) | 2.65× (5.14×) |
| 1,499 devices, seed 2 | 5.89× (10.9×) | 2.69× (4.58×) |
| 1,499 devices, seed 3 | 5.48× (10.7×) | 3.37× (7.61×) |
| 2,002 devices, seed 1 | 4.45× (11.2×) | 2.88× (3.40×) |

Other effects:

- Warm latency p95: 0.512 → 0.211 s (CI) and 0.286 → 0.211 s (2,002
  devices). All messages, optimality p50: 4.42 → 3.26× (CI).
- Dials: 322 → 240 at 2,002 devices. Control traffic: 739 → 730 B/s per
  device (CI), 727 → 706 (2,002).
- First contact is unchanged (p50 6.4×): it pays a lookup and a handshake
  the oracle doesn't.
- At CI size every other tier-2 scenario gives the same numbers but `churn`
  (latency p95 40.0 → 39.0 s, optimality p95 13.8 → 13.9×, control 653 →
  646 B/s).
- At full size `us-eu` (latency p50 0.409 → 0.387 s, control 1,069 → 1,048
  B/s), `gateway-choice` (p95 1.12 → 1.11 s) and `churn` at 1,001 devices
  (optimality p95 12.6 → 12.5×, control 707 → 698 B/s) move a little, the
  others not at all.

What is left of the warm tail is open 13.

#### Fixed 20: black holes pulled in most traffic at full size

`adversarial` failed: 82% delivered against 90% (93% at CI size).

It was traced per packet (seed 1). All 54 undelivered messages were sent
into a black hole, and every retransmission took the same way. The
scenario's 15 black holes relay every route at zero cost. An announcement's
hops and cost aren't signed, so their neighbours believed them and routed
through them (210 of the 300 phones are next to one). Store-and-forward
didn't help: bundles followed the same routes, and two black holes next to
each other, each believing the other, handed every bundle back and forth
until the run ended. At CI size there are 4 black holes among 80 phones, and
fewer routes cross one.

The fix is in `mesh/core.rs`. A relayed announcement no honest relay can
send gets its sender distrusted for 10 minutes. Such an announcement has
zero hops from someone other than the origin, or a cost below 2.1 ms a hop
(`MIN_HOP_COST`, the least a hop adds). The routes the sender gave go at
once, the routes it relays are ignored (it isn't sent back seqnos it has),
and it stays reachable itself.

Honest relays never trip it: no device distrusted a neighbour in any other
tier-2 scenario, nor in `churn_never_loops`; released builds since
dev-2026-10-08 keep the same invariant. There is no wire change. The test is
`a_neighbour_relaying_impossible_routes_is_not_routed_through`.

Results:

- Full size, seed 1: delivered 82% → 100%, latency p95 1.28 → 0.097 s,
  optimality p50/p95/p99 36.6/170/1570× → 1.88/5.97/8.65×. The Sybil gateway
  run: 299/300 → 300/300, p95 1.20 → 0.095 s.
- Control traffic: 19.7 → 19.5 kB/s per device. Routing 14.8 → 18.1 kB/s
  (the zero-cost routes had cut honest flooding short; the run without
  attackers sends 17.3 kB/s in all), carrier 4.9 → 1.4 kB/s.
- CI size: 93% → 100%, p95 1.20 → 0.079 s.
- Every other tier-2 scenario gives identical numbers, at CI and full size.

#### Fixed 21: black holes that lie plausibly

Was open 14. A liar that claims to be one hop from every origin, at the
least cost an honest relay could report (2.1 ms), passes the check of fixed
20 and pulls in every route longer than about two hops. `adversarial` runs
15 of them (the same devices as its black holes; they drop the bundles they
take too): 76% delivered at full size, p95 91 s.

Nothing in an announcement gives them away, but the destination's
acknowledgements don't come back. There are two defences, both without a
wire change.

The first is end-to-end feedback (`Router::feedback`, `mesh/core.rs`). The
transport reports a retransmission timeout with nothing acknowledged, and
each acknowledgement. A next hop is suspected for a destination, for 2
minutes, after two timeouts in a row through it, on a mesh route that still
claims the destination, over a silence of at least 1.5 s plus twice the
route's cost. Packets (ours and those we relay to it) then take the next
feasible route, which is loop-free like the best; with every route
suspected, still the best. One acknowledgement clears the count. Routes via
gateways or the internet aren't judged. It is bounded: 1,024 destinations, 4
suspects each.

The second is one share down a route that just failed (`Carrier::doubt`,
`mesh/dtn.rs`). When feedback judged a mesh route, our own bundles for that
destination send half their copies along the live route and the rest to
other neighbours, one share each, keeping the last. Without that evidence
custody moves whole, as before.

Results:

- Full size, seed 1: 76% → 94% delivered, p95 91 → 31 s; 1.0 → 3.8
  replicas per message; control 21.5 → 23.3 kB/s per device in that run.
- CI size: 80% → 97%, p95 91 → 7.1 s.
- The run is now judged: ≥ 90%.

Variants were tried and measured on the full-size synthetic `trace-replay`
(brief Bluetooth contacts, 1 MB messages, where routes stop delivering for
ordinary reasons). Before, its optimality p95/p99 was 8.38/18.0×.

- Steering custody hand-offs off a suspected hop too, and dropping packets
  once every route was suspected: 7.59/53.7×, and no better against the
  liars (93% at full size). Not kept.
- Feedback without the bundle split: 10.5/54.3×.
- A 3 s minimum silence, or 3 strikes: 9.18/36.8×, and the liars got through
  more (93%).
- Kept: 8.24/36.8×, 3,985 of 4,000 delivered (was 3,982), overhead 3.21 (was
  3.15). The p99 is the 5th-slowest of the 400 messages the oracle checks:
  four more messages now miss a contact and wait 1–4 minutes, others finish
  sooner. Every other tier-2 scenario gives the same numbers, at CI and full
  size.

The tier-2 driver feeds both defences from its acknowledgements. The node
feeds them from what QUIC authenticated on each mesh path of its connections
(`mesh/watch.rs`, `Router::path_feedback`; see [ROUTING.md](ROUTING.md)).
With real nodes, a relay that keeps announcing a destination and drops
everything to and from it is routed around in 6.6 s
(`a_relay_that_drops_one_destination_is_routed_around`), and a slow, lossy
two-hop route suspects nothing (`a_slow_lossy_route_is_not_suspected`). When
a suspicion leaves no feasible route (we advertised the cheap one), a fresh
seqno is asked for.

Signed per-hop route attestations would stop the lie itself. They change the
announcement format, so they are planned for the next protocol version.

The tests are `unacknowledged_packets_move_a_destination_off_its_next_hop`
(`mesh/core/tests.rs`) and `a_doubted_route_gets_one_share_of_our_bundle`
(`mesh/dtn/tests.rs`).

#### Fixed 22: every router now sees the same world

Was open 12's main cause. Waypoint mobility drew its targets from the random
stream that also draws every radio frame's jitter and the routers' own
randomness. Anything that changed what was sent therefore changed where
everyone walked and who met whom. In `disaster-dtn` at CI size, seed 1, the
seven routers compared side by side each had a different world: 3, 11, 5,
11, 3, 7 and 12 of the 12 messages had any path at all.

Walking devices now have their own stream, seeded from the scenario's
(`tier2/engine.rs`). All seven routers see the same 9 there, and a routing
change no longer moves the world. Only `disaster-dtn` has walking devices.

Its numbers on the fixed worlds, full size: seeds 1–12 mean 87.2% (was
80.3%), 2–13 mean 87.1%, 3–14 mean 86.9% (per seed 77–98%). At seed 1,
PRoPHET delivers 67%, spray-and-wait 27% and epidemic 100%, on the same
world as GLOBAL's 90%.

Every tier-2 scenario was rerun at CI and full size with seeds 1, 2 and 3.
Every threshold holds on all three except two:

- `adversarial`'s plausible-liar run (open 15);
- at CI size only, `disaster-dtn` with seeds 2 and 3 (75% and 75%: 6 of 8
  and 9 of 12 messages; seed 3 failed on the old worlds too) and
  `flood-hop-limit` with seed 3 (reach falls from 99% to 95% at hop 7; the
  same on 4aab57a, before any of this work). The CI tests run seed 1.

### 4.2 Open findings

Open findings that have closed keep their numbers, so that references to
them still resolve:

| Open | Closed by | Subject |
|---:|---|---|
| 4 | fixed 18 | warm messages, a simulator artefact |
| 7 | fixed 9 | the QUIC panic |
| 8 | fixed 10 | memory with walking devices |
| 10 | fixed 12 | the oracle's bound for multi-packet messages |
| 14 | fixed 21 | black holes that lie plausibly, in the simulator and the node |

For open 14, signed route attestations wait for the next protocol version.
Open 1, 11 and 12 are partly closed; what is left of each is below.

#### Open 1: Bluetooth control traffic, what is left after fixed 14, 15 and 17

Carrier summaries were fixed 17, and `conference` latency was fixed 15 (the
emulator's Bluetooth queue). `global-scale` is at 706 B/s per device
(routing 470, carrier 235) against its 1 KB/s target.

To reproduce:

```sh
cargo run --release -p mycel-sim -- global-scale --scale 0.02
cargo run --release -p mycel-sim -- conference --scale 0.1
```

The old routing settings, for comparison:

```sh
MYCEL_CORE=every=2000,far=4,hops=8,reduction=on,greet=own
```

#### Open 2: on Infocom 2005 the carrier still trails PRoPHET slightly

It delivers 27.9% of messages against 30.7%, at a third of PRoPHET's median
latency (1,349 s against 4,371 s) and a seventh of its overhead (8.7 against
59.7); see [§5.2](#52-real-contact-traces). Before fixed 8 it delivered 13%.
On Infocom 2006 it now leads (51.2% against 38.6%).

Following predictability for the destination rather than the internet
speeds the median (782 s) but delivers less (23.6%).

To reproduce:

```sh
MYCEL_TRACE=bench/data/infocom2005/contacts.Exp3.dat \
  cargo run --release -p mycel-sim -- trace-replay
```

#### Open 3: replicas can exceed the copy budget

With `copies_small=8`, `disaster-dtn` made 32.7 replicas per message (seed
1). A hand-off whose ack is lost when a contact ends leaves copies on both
sides, since the giver keeps what it thinks it didn't give. Merged copies
are also re-split.

To reproduce:

```sh
MYCEL_DTN=copies_small=8 cargo run --release -p mycel-sim -- disaster-dtn
```

#### Open 5: spray policy

Spray-and-Focus (copies only to neighbours no worse than us) replaced
spraying only on zero knowledge and moved `disaster-dtn` from 38% to 60%.
Spray-first (copies to the likeliest neighbour, better or not, while there
are copies to spare) now replaces it: 90% on `disaster-dtn` (mean of 5
seeds) with the other fixes, and on The ONE's Helsinki trace 62.9% against
39.5%
([BENCHMARKS.md §6.5](BENCHMARKS.md#65-results-on-the-real-carrier-and-the-defaults)).

#### Open 6: tier-2 memory is ~200 KB per device

That is at 10k devices, and it is mostly routing state for ~80 origins
(route entries, `heard` lists). The neighbours' predictability tables are
halved (fixed 13).

#### Open 9: `us-eu-live`'s call lost 66.7% of its audio

That was at full size on the loaded machine (0% at CI size). At a load of
~9: 0% loss, messages p95 0.88 s. The scenario sets its own 1 s announcement
period, so the loss was most likely CPU starvation, not announcements.

#### Open 11: variation left in `shutdown`

`shutdown`'s call and messages were the emulator's one-queue Bluetooth model
(fixed 15), and its slow teardown was sequential closes (fixed 16).

The variation that remains: at seed 4 one message of 20 took 7.0 s, and at
seed 2 one wasn't delivered within 20 s. The walkers separate mid-delivery
(1.4 m/s, 60 m Bluetooth range). Both are within the 80% / 10 s targets.

#### Open 12: `disaster-dtn` varies from seed to seed

Its swings from change to change were mostly the world moving with the
routing (fixed 22). Seed to seed it still varies, 77–98% at full size, which
is why it is judged on the mean of 12 seeds.

#### Open 13: the warm tail left in `global-scale`

The tail is pairs in one neighbourhood whose mesh route crosses Bluetooth.
After fixed 19, at CI size, that is all 3 warm messages over 5× with seed 1
(at 15×, 11× and 5.1×), and 6 of the 7 with seed 3.

Phones with AWDL and phones with Wi-Fi Direct share only Bluetooth. A route
between those islands (or around a gap in one) takes a 40–55 ms Bluetooth
hop or two, while the oracle goes over the internet between two devices of
the neighbourhood (10–20 ms). There are two cases:

- Both ends have the internet. The node's Iroh connection has the direct (or
  relayed) internet path beside the mesh path, and its path selector takes
  the faster. The tier-2 driver (`Global::send_packet`) sends through the
  core whenever it has a mesh route, so it measures the mesh path alone
  here: a gap in the model, not in the node.
- One end or neither has the internet. The core keeps traffic on a local
  mesh route by design (a mesh route beats gateways, and `gateway_addrs`
  offers no gateways for a device the mesh reaches), even when the internet
  through the destination's gateways would be faster. Trading a slow local
  route for gateway traffic (metered, budgeted) is a design question, not a
  bug.

To reproduce:

```sh
cargo run --release -p mycel-sim -- global-scale --scale 0.01 --seed 3
```

#### Open 15: the plausible-liar target holds on seed 1 only

`adversarial` judges its plausible black holes at ≥ 90%, set from seed 1
(94%, 281 of 300). With seed 2 they take delivery to 76% (227 of 300,
latency p50 1.04 s, p95 61 s), with seed 3 to 87% (262 of 300). The naive
black holes, the storm, the replayer and the Sybil gateway stay at 100% on
all three.

The defences of fixed 21 aren't enough where most of a destination's
neighbourhood sits next to a liar: every alternative leads to one too. The
target isn't lowered. Whether to lower it (seeds 1–3 support about 75%) or
strengthen the defence is open.

To reproduce:

```sh
cargo run --release -p mycel-sim -- adversarial --seed 2
```

## 5. Benchmarks against external baselines

### 5.1 Baseline routers in tier 2

`tier2/dtn.rs` has baseline routers that run on the same scenarios, the same
traces and the same workload as Mycel's, for like-for-like comparisons:

- Epidemic (Vahdat & Becker 2000);
- binary Spray-and-Wait (Spyropoulos et al. 2005);
- plain PRoPHET (RFC 6693), with The ONE's parameters: P_init 0.75, β 0.25,
  γ 0.98 per 30 s;
- managed flooding as Meshtastic and BitChat do it: a hop limit, duplicate
  suppression, and a random delayed rebroadcast that is cancelled when the
  device hears another rebroadcast.

All have a FIFO-drop buffer and a TTL.

### 5.2 Real contact traces

`traces.rs` reads CRAWDAD cambridge/haggle (`contacts.ExpN.dat`: Intel,
Cambridge, Infocom 2005/2006; Cambridge city per-node files) and a generic
CSV (for example NUS Bluetooth via `bench/traces/nus_to_csv.py`).

You download the traces yourself, under CRAWDAD's terms: cite the dataset,
don't try to identify people, don't re-share it. They are never
redistributed in this repository. [§7](#7-reproducing-the-results) has the
commands. Without the traces, `trace-replay` uses a synthetic trace with the
same shape (heavy-tailed Pareto α 0.6 inter-contacts, as Chaintreau et al.
measured on these traces), and says so.

The workload is The ONE's default settings: a message every 25–35 s, 500
kB–1 MB, TTL 300 min, 5 MB buffers, Bluetooth 250 kB/s. The metrics are
delivery ratio, latency distribution, The ONE's overhead ratio ((relayed −
delivered) ÷ delivered), and buffer occupancy (average, peak).

The traces:

| Trace | Devices | Span | Contacts |
|---|---|---:|---:|
| Infocom 2005 | 41 iMotes | 70.6 h | 17,712 |
| Infocom 2006 | 98 iMotes | 93.7 h | 149,066 |
| Synthetic, same shape | 40 devices | 72 h | 17,562 |

Results, seed 1, with the real traces given as
`MYCEL_TRACE=…/contacts.Exp3.dat` and `contacts.Exp6.dat`. "Global core +
DTN" is Mycel's routing core and carrier. Delivered is a share of 4,000
messages.

| Trace | Router | Delivered | Latency p50 | p95 | Overhead | Buffer avg |
|---|---|---:|---:|---:|---:|---:|
| Infocom 2005 | global core + DTN | 27.9% | 1,349 s | 15,532 s | 8.7 | 1653 kB |
| Infocom 2005 | epidemic | 18.8% | 6,222 s | 17,124 s | 116.3 | 2205 kB |
| Infocom 2005 | PRoPHET | 30.7% | 4,371 s | 16,194 s | 59.7 | 1712 kB |
| Infocom 2005 | spray-and-wait (L=6) | 26.7% | 2,452 s | 15,894 s | 8.1 | 2148 kB |
| Infocom 2005 | managed flooding (7 hops) | 5.7% | 15 s | 49 s | – | – |
| Infocom 2006 | global core + DTN | 51.2% | 1,040 s | 15,218 s | 9.1 | 999 kB |
| Infocom 2006 | epidemic | 20.6% | 6,597 s | 16,984 s | 289.1 | 1652 kB |
| Infocom 2006 | PRoPHET | 38.6% | 4,274 s | 16,633 s | 153.1 | 1192 kB |
| Infocom 2006 | spray-and-wait (L=6) | 28.6% | 1,922 s | 15,736 s | 12.2 | 1437 kB |
| Infocom 2006 | managed flooding (7 hops) | 14.2% | 33 s | 78 s | – | – |
| Synthetic | global core + DTN | 99.5% | 5 s | 1,212 s | 3.4 | 236 kB |
| Synthetic | epidemic | 65.7% | 4,353 s | 15,804 s | 151.7 | 2534 kB |
| Synthetic | PRoPHET | 99.2% | 398 s | 5,591 s | 86.4 | 2518 kB |
| Synthetic | spray-and-wait (L=6) | 56.5% | 146 s | 7,224 s | 7.2 | 2522 kB |
| Synthetic | managed flooding (7 hops) | 61.9% | 25 s | 48 s | – | – |

Reading the table:

- Managed flooding only forwards to devices in contact now, so it has no
  buffer.
- Epidemic is buffer-bound at 5 MB: it floods the buffers and evicts.
- With the carrier fixes (fixed 8) the carrier leads on Infocom 2006 and
  trails PRoPHET by 3 points on Infocom 2005, at a fraction of its latency
  and overhead (open 2). Before fixed 8 it delivered 13.0% and 31.3%.
- On the synthetic trace the carrier delivers the most, fastest.

The ONE's own routers on the same traces (Epidemic, PRoPHET, Spray-and-Wait,
MaxProp) are in [BENCHMARKS.md](BENCHMARKS.md). The ONE's link model
differs: whole messages over contacts that must last.

### 5.3 Flooding baseline

Meshtastic reports, for LoRa meshes, that reach rises with the hop limit and
levels off around 3–5, while each extra hop adds redundant rebroadcasts
(hence its default of 3). `flood-hop-limit` reproduces the shape on a
100-device Bluetooth neighbourhood:

| Hop limit | Reach, delayed suppressible rebroadcast | New devices per transmission | Reach, rebroadcast always | New devices per transmission |
|---:|---:|---:|---:|---:|
| 1 | 16% | 15.25 | 16% | 15.47 |
| 2 | 33% | 4.42 | 39% | 2.43 |
| 3 | 53% | 3.99 | 63% | 1.82 |
| 4 | 68% | 3.68 | 82% | 1.45 |
| 5 | 83% | 3.38 | 96% | 1.23 |
| 6 | 92% | 3.10 | 100% | 1.06 |
| 7 | 93% | 2.94 | 100% | 1.00 |

The setting is 100 BLE devices outdoors, one per 625 m² (~18 in range), and
one broadcast from a random device, averaged over runs. Reach rises with the
hop limit and levels off, while each extra hop adds redundant transmissions:
the shape Meshtastic reports, and why it defaults to 3.

This comparison is qualitative only. The model has no collisions, so
usefulness falls through redundancy, not loss.

### 5.4 Announcement overhead against mesh size

`flood-scaling` at full size has Bluetooth-only phones, one per 900 m², with
~12 neighbours. The table gives:

- control bytes per device per second in steady state (over one full fisheye
  cycle after a first one);
- in round brackets, that as a share of one BLE radio (40 kB/s);
- in square brackets, the first cycle, with everyone starting at once;
- the share of sampled pairs within 8 hops that have a route.

| Devices | Now (16 s, full scope of 10 hops every 8th) | Now + flood reduction | Now, fisheye off | Before (2 s, 8 hops every 4th, flood reduction) | Earlier flooding mesh (40 s) |
|---:|---:|---:|---:|---:|---:|
| 250 | 2.5 kB/s (6.3%) [3.5], 100% routed | 2.0 kB/s (4.9%), 100% | 9.4 kB/s (23%), 100% | 18.3 kB/s (46%) [30.4], 92% | 48.0 kB/s (120%) |
| 500 | 2.8 kB/s (7.0%) [4.3], 100% | 2.3 kB/s (5.8%), 100% | 12.2 kB/s (31%), 100% | 22.1 kB/s (55%) [35.4], 90% | 49.6 kB/s (124%) |
| 1,000 | 3.1 kB/s (7.7%) [4.9], 100% | 2.5 kB/s (6.3%), 100% | 13.4 kB/s (34%), 100% | 23.4 kB/s (59%) [37.1], 92% | 52.2 kB/s (131%) |
| 2,000 | 3.4 kB/s (8.4%) [5.8], 100% | 2.8 kB/s (6.9%), 100% | 15.7 kB/s (39%), 100% | 26.8 kB/s (67%) [41.2], 85% | 54.4 kB/s (136%) |

Fisheye cuts traffic 4–5×. Flood reduction would save another 18% here,
where every device sees every flood from several sides, but it leaves pairs
unrouted in sparser meshes (`routing-convergence`), so it stays off. All
variants greet new neighbours.

Traffic grows slowly with the number of devices: the near scope costs the
same at any size, and the full scope reaches more devices.

### 5.5 Internet latency from measured data

The data is WonderNetwork's public sample of a day of global pings (19–20
July 2020, 246 servers, 2.9 M rows; credit: WonderNetwork,
["A day in the life of the internet"](https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/)).
Their terms ask for credit and a link and give no redistribution licence, so
the data isn't committed. [§7](#7-reproducing-the-results) has the commands
to download it, fit the model against it, and make tier 2 use it.

The fit is over 29,889 server pairs ≥ 200 km apart (derived statistics
only):

| Quantity | Value |
|---|---|
| min RTT ÷ light in fibre over the great circle (path inflation) | median 2.04×, p95 4.5× |
| least squares | min RTT ≈ 25 ms + 17.0 µs × km |
| our model (1.4×) ÷ measured average RTT | median 0.69, p95 0.97 |

Round-trip times for some pairs:

| Pair | Measured | Model |
|---|---:|---:|
| New York – London (5,547 km) | 71 ms | 78 ms |
| New York – Los Angeles | 68 ms | 56 ms |
| London – Frankfurt | 13 ms | 9 ms |
| London – Tokyo | 217 ms | 134 ms |
| Sydney – Singapore | 94 ms | 88 ms |
| São Paulo – Miami | 123 ms | 92 ms |

So 1.4× fits well-cabled corridors (the transatlantic routes the US–Europe
scenarios use) within 10%, and underestimates the median pair by ~30%. Use
`MYCEL_PINGS` for global numbers.

## 6. Limitations

These results are simulation and emulation. None of them comes from real
radios, real phones or the real internet.

What is real code and what is a model:

- Tier 1 runs the real node (QUIC, multipath, the mesh, sync, calls), but
  every medium under it is `EmuNet`. Which of Mycel's links have also run
  between real devices is in [TESTING.md](TESTING.md).
- Tier 2 runs the real routing core and carrier. Everything around them is a
  model: the QUIC-like sender, radios as a latency and a rate per hop, the
  internet, NAT, relays, and the record directory. Signatures are stubbed,
  so tier 2 says nothing about the cost of cryptography.

What the models leave out:

- Collisions and hidden terminals in tier 2. Tier 1 models airtime
  contention per collision domain, not collisions.
- Fading (loss is i.i.d.), rate adaptation and battery.
- Load in tier 2: its latencies are optimistic under load.
- The real Bluetooth controller's total throughput falls somewhat with many
  connections (more connection-event overhead). The model keeps 40 kB/s for
  the whole radio, which is already about a third of one good L2CAP link.
- Longer internet routes. The backbone model underestimates latency for the
  median pair of cities ([§5.5](#55-internet-latency-from-measured-data)).
- A direct internet path beside a mesh route in tier 2, which a node would
  have and prefer when it is faster (open 13).

How far the runs go:

- Size. The current results for `global-scale`, `churn` and `conference`
  are below full size: 2,002 and 10,003 devices, 1,001 devices, and up to
  100 seats.
- Seeds. Most results are for seed 1. `disaster-dtn` varies from 77% to 98%
  between seeds (open 12), and the plausible-liar objective holds on seed 1
  only (open 15).
- Machine. Everything ran on one loaded Mac. Tier 1 measures the wall clock,
  so its latencies and call results include that load (open 9).
- Traces. The real contact traces are two conference traces from iMotes;
  [BENCHMARKS.md §5](BENCHMARKS.md#5-limitations) says what such traces
  miss.

## 7. Reproducing the results

Run scenarios with the `mycel-sim` binary:

```sh
cargo run --release -p mycel-sim -- list
cargo run --release -p mycel-sim -- all                    # everything, full size
cargo run --release -p mycel-sim -- us-eu,mailbox --scale 0.1 --seed 7
cargo run --release -p mycel-sim -- t2 --candidate main    # hold the earlier mesh design to the same objectives
cargo test -p mycel-sim                                    # CI sizes; `-- --ignored` for the rest
```

`t1` and `t2` select one tier. Each run writes `report.md` and
`results.json` to `target/mycel-sim`, or to the directory given with
`--out`. `merge` joins runs made separately:

```sh
cargo run --release -p mycel-sim -- merge DIR... --out DIR
```

Tier-2 scenarios run in parallel. Tier-1 scenarios measure the wall clock,
so they run one at a time, after tier 2.

### 7.1 Environment variables

Environment variables change what a run does:

| Variable | Effect |
|---|---|
| `MYCEL_CORE` | routing core knobs (`Config::tune`): `every`, `far`, `hops`, `greet`, `fisheye`, `reduction` |
| `MYCEL_DTN` | carrier knobs (`DtnConfig::tune`): `spray`, `gradient`, `copies`, `copies_small`, `room` |
| `MYCEL_TRACE` | the contact trace `trace-replay` replays, in place of the synthetic one |
| `MYCEL_PINGS` | directory of measured pings; tier 2 uses them in place of the latency model |
| `MYCEL_SIM_BLE_QUEUE=radio` | the old Bluetooth model, one queue per radio (fixed 15) |
| `MYCEL_SIM_MEMLOG=<secs>` | log memory and live tasks during a tier-1 run |

`examples/mem_walk.rs` tracks memory for walking nodes:

```sh
cargo run --release -p mycel-sim --example mem_walk
```

### 7.2 Contact traces

`bench/fetch.sh traces` puts the Haggle contact files in `bench/data/` (the
same files the benchmarks replay). `bench/fetch.sh dataport <archives>`
unpacks the full IEEE DataPort archives (free account) into
`bench/data/dataport/`. Then:

```sh
bench/fetch.sh traces
MYCEL_TRACE=bench/data/infocom2006/contacts.Exp6.dat cargo run --release -p mycel-sim -- trace-replay
```

`export-trace` writes the trace in `MYCEL_TRACE`, or the synthetic one, as
`contacts.csv` in the `--out` directory, in the format the benchmarks
replay.

### 7.3 Measured internet latency

```sh
bench/fetch.sh latency                              # downloads to bench/data/wondernetwork/
cargo run --release -p mycel-sim -- fit-latency     # fits the model against it
MYCEL_PINGS=bench/data/wondernetwork cargo run --release -p mycel-sim -- global-scale --scale 0.02
```

With `MYCEL_PINGS`, tier 2 uses the measured RTT between the servers nearest
each device instead of the model.

## 8. Wiring other routing cores

Tier 2 drives any sans-IO router through `tier2::engine::Router` (frames,
links, internet, timers, a directory). `tier2/global.rs` is the adapter for
the routing core and carrier, and the template for others. An adapter
translates the core's effects (`Out`) into `Cx` calls (`send_radio`,
`send_inet`, `set_timer`, `reach_put`/`reach_get`, `delivered`, `receipt`),
and feeds the core's inputs from the `Router` callbacks.
