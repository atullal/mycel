# Simulation: real-world scenarios, scale and routing

`crates/mycel-sim` tests Mycel against the networks people actually have
(Bluetooth, AWDL, Wi-Fi Direct, Wi-Fi LAN, 802.11s mesh, Ethernet, UWB,
Thread, cellular, the internet with NAT and relays) and at global scale, with
a focus on hops and routing: *does a message from a Bluetooth-only phone in
the US reach a Bluetooth-only phone in Europe, and is the path it takes the
fastest one that existed?*

```
cargo run --release -p mycel-sim -- list
cargo run --release -p mycel-sim -- all                    # everything, full size
cargo run --release -p mycel-sim -- us-eu,mailbox --scale 0.1 --seed 7
cargo run --release -p mycel-sim -- t2 --candidate main    # hold main's old mesh to the same objectives
cargo test -p mycel-sim                                    # CI sizes; `-- --ignored` for the rest
```

Each run writes `target/mycel-sim/report.md` and `results.json`. Every
scenario is named, seeded and reproducible (same seed → same result; tier 2
is fully deterministic). Each scenario holds a *candidate* to objectives
(delivery ratio, latency p95, optimality, call setup, audio loss, overhead,
relay fairness) and passes, fails, or **fails as expected** with the reason
recorded (a known gap, or a finding with evidence).

## 1. Method

**Two tiers**, because real code and global scale don't fit in one process:

| | Tier 1: emulation | Tier 2: discrete-event simulation |
|---|---|---|
| What runs | Real `Node`s: iroh QUIC, multipath, the mesh (GLOBAL's routing core and carrier inside the node), sync, calls with test-tone "microphones" | GLOBAL's sans-IO routing core (`mesh/core.rs`) and store-and-forward carrier (`mesh/dtn.rs`), the real code, plus models and baselines |
| Network | `mycel_net::emu::EmuNet`: shared media with positions, range, rate, airtime (half-duplex, one collision domain per radio), latency, jitter (in-order), loss, per-pair rules (NAT, access latency, 802.11s hops), discovery, devices coming and going | Per-hop latency + size/rate per radio, the internet with geography, NAT and relays, a record directory, mobility, churn, contact traces |
| Time | Real time (iroh, noq and the mesh read `std::time`; paused tokio time gave no speed-up and mixed clocks, measured) | Virtual (µs), one event queue |
| Scale on this Mac (18 cores, 24 GB) | ~2–2.5 MB and ~1% of a core per node: 500 nodes measured (1.2 GB) | ~1.1 M events/s on one core. 2,002 devices × 12 min: 116 s, 840 MB. 10,003 devices: 33 min, 2.15 GB (on a loaded, swapping machine). 100k: not run (≈ 5 h and 15–20 GB by extrapolation) |

**Messages** in tier 1 are real Mycel sync (a change to a shared document,
timed until the recipient's replica shows it). In tier 2 a message is split
into QUIC-sized packets with a QUIC-like sender (per-packet acks, a congestion
window starting at 10 packets, adaptive RTO, retransmission for 10 minutes);
if the live attempt isn't getting through, it also becomes a store-and-forward
bundle, as the node does. **Calls** in tier 1 are real `mycel-call` calls; in
tier 2 call setup is an offer and an answer through the routing.

**Optimality, for every scenario.** For each delivered message, the
achieved latency is divided by the fastest path that was physically possible:
an earliest-arrival search over the ground-truth contact plan (who could hear
whom when, who had internet when), moving the message store-and-forward hop by
hop and waiting anywhere for free (`tier2/oracle.rs`; tier 1 does Dijkstra over
the emulated media). Reported as p50 / p95 / p99. The oracle is a lower bound:
no congestion control, no lookups, no handshakes. So for small messages the
ratio measures routing (path choice, lookups); for large ones it also measures
QUIC slow start over long round trips; and in tier 1 it includes Mycel sync's
own round trips (a 32 ms message on a 5 ms LAN path is 6×).

**Candidates.** Tier-2 objectives judge `--candidate global` (default: GLOBAL's
routing core + carrier), `main` (the mesh before GLOBAL, modelled), or
`stand-in` (an earlier model of the GLOBAL design, kept as a reference).

## 2. Models and sources

`crates/mycel-sim/src/models.rs` has every number and its source; summary:

| Medium | Goodput | Latency (+ jitter) | Range in/out | Source |
|---|---|---|---|---|
| BLE L2CAP CoC | 40 kB/s | 15 ms + 15 | 20 / 60 m | Bluetooth Core 5.x; Apple WWDC17 (L2CAP CoC); Gomez et al., Sensors 2012 |
| AWDL | 12 MB/s | 2 ms + 20 (channel hopping) | 50 / 100 m | Stute et al., MobiCom 2018 |
| Wi-Fi Direct | 8 MB/s | 3 ms + 5 | 50 / 150 m | Wi-Fi P2P spec; measured 50–150 Mbit/s |
| Wi-Fi LAN (AP) | 15 MB/s shared | 3 ms + 5 | 40 / 100 m | busy 802.11ac BSS |
| 802.11s mesh | 10 MB/s ÷ min(hops, 4) | +3 ms per hop | building | Li et al., MobiCom 2001 (chain capacity → ~¼) |
| Ethernet | 110 MB/s | 0.2 ms | wired | GbE TCP goodput |
| UWB (802.15.4z HRP) | 250 kB/s | 2 ms | 30 / 60 m | DW3000 data mode |
| Thread / 802.15.4 | 8 kB/s, 1% loss | 10 ms + 10 | 25 / 80 m | 250 kbit/s PHY, 6LoWPAN overhead |
| The ONE Bluetooth | 250 kB/s | 1 ms | 10 m | The ONE default settings (trace replay only) |
| Cellular access | LTE 1.5 MB/s up, 20 ms one way; 5G 5 MB/s, 8 ms | | | Narayanan et al., IMC 2021; Ookla/OpenSignal |
| Backbone | | 5 µs/km × 1.4 over the great circle | | Singla et al., HotNets 2014; checked against WonderNetwork (§5) |
| NAT | hard–hard and hard–easy relay, others direct | | | Ford et al., USENIX ATC 2005; Richter et al., IMC 2016 |
| Relays | client → nearest relay → peer's relay → peer | | | n0 relay regions |

Device mixes (tier 2 world): 24 cities on 6 continents, weighted by
population, with internet adoption by region (GSMA, *The Mobile Economy* 2024:
~85–90% North America/Europe, ~60% Asia-Pacific/Latin America, ~35%
Sub-Saharan Africa); phones have BLE plus AWDL (30%) or Wi-Fi Direct;
carrier-grade NAT for most cellular. Mobility: static, random waypoint,
scripted paths (mules). Churn: devices switched off and on.

Not modelled (limits): collisions and hidden terminals in tier 2 (tier 1
models airtime contention per collision domain, not collisions), fading
(loss is i.i.d.), rate adaptation, battery. Tier-2 latencies are optimistic
under load.

## 3. Scenarios and results

Seed 1, full size unless noted, run on 8 October 2026. Candidate: the GLOBAL
core and carrier (tier 2), the real node (tier 1). ✅ pass, ⏳ fails as
expected (reason in the report: a known gap or a finding), ❌ fail.

The scenarios ran as separate processes and were joined with
`mycel-sim merge`. The rows marked *(carrier)* were rerun on 9 October
with the store-and-forward fixes from the benchmarks (§4, fixed 8), on a
less loaded machine. The Mac was heavily loaded throughout: another agent's
Java simulations, a host build and other apps, a load average of ~20 on
18 cores, and 8 of 9 GB swap in use. Wall times are pessimistic, and the
real-time tier-1 latencies (calls especially) carry that load. The ONE
trace replays are in §5. `scale-ceiling` (50 → 500 real nodes) didn't
finish within 40 minutes under this load and was stopped. On a quieter
machine it measured 500 nodes in 1.2 GB (§1).

| Scenario | Tier | Size | Status | Result | Wall |
|---|---|---|---|---|---:|
| `cafe` | 1 | full | ✅ | messages: 100% delivered, p50 0.032 s, p95 0.039 s, optimality p50/p95/p99 5.77/7.00/7.22× · call: setup 0.051 s, loss 0.0%, latency 101 ms, path Some(Network) | 18 s |
| `office` | 1 | full | ✅ | messages: 100% delivered, p50 0.032 s, p95 0.034 s, optimality p50/p95/p99 6.00/59.3/60.6× | 10 s |
| `apartment-80211s` | 1 | full | ✅ | messages: 100% delivered, p50 0.083 s, p95 0.095 s, optimality p50/p95/p99 5.63/6.98/6.98× · bulk: next flat 8.2 MB/s, 7 flats away 2.2 MB/s | 10 s |
| `conference` | 1 | 24 seats (scale 0.1; 100 didn't finish, 300 crashed) | ⏳ | messages: 80% delivered, p50 0.853 s, p95 3.36 s, optimality p50/p95/p99 22.7/89.5/89.5×<br>✗ messages: delivery: 80.0 % (target ≥ 95.0 %); ✗ messages: latency p95: 3.36 s (target ≤ 3.00 s) | 180 s |
| `city-block` | 1 | full | ✅ | 8 hops: 100% delivered, p50 0.957 s, p95 1.01 s, optimality p50/p95/p99 3.19/3.38/3.38× · 9 hops: not delivered (max_hops = 8) | 70 s |
| `shutdown` | 1 | 15 walkers (scale 0.5; full size before: +4.8 GB, see finding 8) *(carrier)* | ✅ | messages (connected at the time): 100% delivered, p50 0.231 s, p95 0.359 s, optimality p50/p95/p99 3.63/5.42/5.42× · call between two walkers: setup 0.698 s, heard, loss 4.4%, path Mesh | 106 s |
| `disaster-live` | 1 | full *(carrier)* | ✅ | member mule: 49 s; stranger mule: 49 s (it never arrived before fixed 2) | 62 s |
| `rural-line` | 1 | full | ✅ | messages: 100% delivered, p50 0.114 s, p95 0.130 s, optimality p50/p95/p99 5.67/6.78/6.78× · bulk: next house 6.6 MB/s, 5 hops 0.59 MB/s | 20 s |
| `us-eu-live` | 1 | full | ⏳ | messages: 100% delivered, p50 0.814 s, p95 1.40 s, optimality p50/p95/p99 4.31/7.43/7.43× · call: setup 1.79 s, loss 66.7%, latency 175 ms, path None<br>✗ call: audio loss: 66.7 % (target ≤ 5.00 %) | 63 s |
| `nat-relay` | 1 | full | ✅ | messages: 100% delivered, p50 0.233 s, p95 0.488 s, optimality p50/p95/p99 3.32/4.57/4.80× · during the relay outage: 100% delivered, p50 0.263 s, p95 0.772 s, optimality p50/p95/p99 3.32/6.39/130× | 23 s |
| `adversarial-live` | 1 | full | ✅ | messages past a black hole and a storm: 100% delivered, p50 1.87 s, p95 4.01 s, optimality p50/p95/p99 24.9/53.5/53.5× | 46 s |
| `multipath` | 1 | full | ✅ | 3 links 8.0 MB/s, 1 link 2.9 MB/s (2.78×) | 21 s |
| `mixed-room` | 1 | full | ✅ | Ethernet→Some(Ethernet), Wi-Fi Direct→Some(WifiDirect), UWB→Some(Uwb), Bluetooth LE→Some(Bluetooth) | 30 s |
| `us-eu` | 2 | full *(carrier)* | ✅ | global core + DTN: 100% delivered, p95 0.799 s, optimality p50/p95/p99 1.29/2.29/4.19× | 1 s |
| `gateway-choice` | 2 | full *(carrier)* | ✅ | global core + DTN: 100% delivered, p95 1.12 s, optimality p50/p95/p99 2.49/6.41/6.50× · 100% of relayed bytes via the far fibre gateway | 0 s |
| `routing-convergence` | 2 | full | ⏳ | global core: 99% routed in never, 100% in never, 0 loops, re-converged in never, stretch 1.06× · main: 99% in never, 0 loops, re-converged in never<br>✗ cold start: 99% of pairs within 8 hops routed: ∞ s (target ≤ 12.0 s); ✗ after the busiest device fails: 99% routed again: ∞ s (target ≤ 8.00 s) | 39 s |
| `flood-scaling` | 2 | full | ⏳ | largest N: global core 76.9% of BLE, main 136.1%<br>✗ announcement traffic at the largest N, as a share of one BLE radio: 76.9 % (target ≤ 10.0 %) | 1344 s |
| `partial-route` | 2 | full *(carrier)* | ✅ | gap 100 m: global core + DTN 100%; stand-in custody 100% p50 97.5 s; sender-holds 100% p50 98.2 s · gap 300 m: global core + DTN 100%; stand-in custody 0% p50 0 s; sender-holds 0% p50 0 s | 0 s |
| `disaster-dtn` | 2 | full *(carrier)* | ⏳ | global core + DTN: 87% delivered (mean of seeds 1–5: 90%), p95 5917 s, optimality p50/p95/p99 1.00/3.93/5.04× · PRoPHET 58%, spray-and-wait (L=8) 32%, epidemic 100%<br>✗ copies per message: 33.5 (target ≤ 8.00): expected, open finding 3 | 31 s |
| `mailbox` | 2 | full *(carrier)* | ✅ | global core + DTN: 100% delivered, p95 9900 s, optimality p50/p95/p99 1.00/1.00/1.00× | 0 s |
| `global-scale` | 2 | 10,003 devices (0.1) | ❌ | global core + DTN: 100% delivered, p95 0.819 s, optimality p50/p95/p99 6.12/12.9/19.2× · 10003 devices, 71% with internet; 673610627 events in 1982 s wall<br>✗ optimality p95 (achieved / fastest feasible): 12.9 × (target ≤ 5.00 ×); ✗ control traffic per device: 6051 B/s (target ≤ 1000 B/s) | 2682 s |
| `churn` | 2 | 1,001 devices (scale 0.1) *(carrier)* | ✅ | global core + DTN: 100% delivered, p95 61.2 s, optimality p50/p95/p99 5.87/12.5/17.1× (full size before the carrier fixes: 100%, p95 65.2 s) | 98 s |
| `adversarial` | 2 | full | ✅ | global core + DTN: 100% delivered, p95 15.0 s, optimality p50/p95/p99 32.7/718/2015× · global core + DTN: clean 100%, attacked 100%, Sybil gateway 100% | 980 s |
| `trace-replay` | 2 | full *(carrier)* | ✅ | synthetic trace (40 devices, 17,562 contacts over 72 h): global core + DTN 99.8% of feasible, p50 4.8 s, p95 1212 s, optimality p50/p95/p99 0.630/1.38/2.70× · real Infocom 2006: 50.8% (passes); Infocom 2005: 27.5% (target 30%; §5) | 106 s |
| `flood-hop-limit` | 2 | full | ✅ | reach by hop limit 1..7: 16%, 33%, 53%, 68%, 83%, 92%, 93% | 0 s |

## 4. Findings

Each with the evidence and how to reproduce it (`--seed 1` unless noted).

### Fixed (in this branch)

1. **The routing core's `tick` did a full pass every 10–20 ms.** It
   re-ran route publishing for every origin (allocating a new map),
   recomputed gateway choice, and scanned every route, origin, record and
   lookup for expiry. On a router that knows ~80 origins this dominated
   tier 2: a 2,002-device `global-scale` took 3,075 s. `tick` now
   revisits only what changed: a queue of due rebroadcasts, exact expiry
   deadlines, dirty origins, and an incremental gateway table. The results
   are identical: the same 140,349,740 events and every metric
   bit-for-bit on the tier-2 suite. The same run now takes 116 s, and the
   CI-sized tier-2 suite 31 s instead of 183 s. The real node ticks every
   20 ms too, so phones benefit. (`mesh/core.rs`.)
2. **A stranger mule never carried anything (`disaster-live`).** Two
   causes:
   - The carrier sprayed copies only when its own predictability for the
     destination was exactly 0. Camp A and a passer-by who had both met
     camp B ranked equal, so A kept the bundle. Now Spray-and-Focus: half
     the copies go to the likeliest neighbour that is no worse a carrier.
   - The node offered a bundle only when its sync with camp B failed. A
     stale connection to B made that take 60 s, by which time the mules
     had walked out of range. A sync not through in 10 s is now also
     bundled.

   Member mule 49 s, stranger mule never → 50 s.
   (`mesh/dtn.rs`, `lib.rs`; tests `a_passer_by_as_good_as_the_holder_gets_a_copy`,
   `a_mailbox_does_not_spray`.)
3. **Sprays could starve deliveries.** Transfers left in bundle-id order,
   so 1 MB sprays to bystanders queued on the radio ahead of the
   destination. Deliveries now go first, then live routes, the gradient
   and sprays, and spraying skips clearly worse carriers. On the CI-sized
   synthetic trace, spraying to anyone delivered 18%; this delivers 86%.
4. **Failed dials were retried on every plan.** At CI size,
   `disaster-dtn` made 56,987 dials to destinations not on the internet.
   They now back off (2 s, doubling to 60 s): 471 dials. Meanwhile
   `toward` answers `Unreachable`, so a gateway holding such a bundle
   stops counting the internet and carries it by predictability for the
   destination. (`mesh/core.rs`, test `failed_dials_back_off`.)
5. **A full carrier refused everything new, and its own bundles counted
   against the space for others.** On Infocom 2005, 258,751 hand-offs
   were refused. It now drops the carried bundle nearest expiry
   (drop-oldest; Lindgren and Phanse, 2006), and `capacity` counts only
   what it carries, as documented. Refusals fell to 76,434; deliveries
   rose from 325 to 519. (Test `a_full_store_drops_the_oldest_carried_bundle`.)
6. **Carriers kept every neighbour's last summary forever** (~5 KB each).
   A phone in a crowd meets thousands of devices a day. Summaries are now
   forgotten 10 minutes after the neighbour was last heard. (Test
   `neighbours_long_gone_are_forgotten`.)
7. **Simulator bugs:**
   - The tier-2 driver handed a message to the carrier again on every
     retry once the source had passed on custody, multiplying copies. This
     inflated earlier store-and-forward numbers: `disaster-dtn` showed
     88% where the truth is 60%, and the CI synthetic trace 92% where it
     is 50%. Each message is now bundled once, as the node does.
   - Runs that check only a sample of messages against the oracle counted
     every delivered message as feasible, so each router had a different
     denominator.
   - Tier 2 uses `verified_max: 64` (signatures are stubbed); the 4,096-entry
     cache was ~300 KB per router.

8. **The carrier's measured fixes (from `docs/BENCHMARKS.md` §6) are
   applied** to `mesh/dtn.rs`, the node (`mesh/mod.rs`) and tier 2:
   - bundles are offered before their payload, and a refusal costs a
     round trip, not the transfer;
   - summaries carry the room left, so full carriers aren't offered
     anything;
   - a cut transfer resumes;
   - lifetimes run from creation;
   - a source over its share makes way with its own bundles first;
   - copies in flight aren't given twice. Before this, a single copy in
     custody offered to a second neighbour while the first transfer was
     still under way became two. On `disaster-dtn` that alone was half
     the copies per message (60 → 34).
   - Policy: spray-first, a single copy follows predictability toward the
     internet only, and small bundles get more copies (32 at 16 KiB or
     less, 4 at 256 KiB or more).

   Effect, seed 1 unless noted:
   - `disaster-dtn`: 60% → 87% (mean of 5 seeds 90%). With the old policy
     (Spray-and-Focus, max(P(dst), P(internet)), 4 copies) on the new
     mechanics: 52% (mean of 5 seeds). With no gradient: 77%. With 4, 8
     or 16 copies for small bundles: 60%, 69% or 68%.
   - `trace-replay` on real traces: Infocom 2005 13.0% → 27.9% of
     messages; Infocom 2006 31.3% → 51.2%, ahead of PRoPHET (38.6%),
     Spray-and-Wait (28.6%) and Epidemic (20.6%).

   Choose carrier policies for any scenario with
   `MYCEL_DTN=spray=focus,gradient=both,copies_small=4` (see
   `DtnConfig::tune`). Tests in `mesh/dtn/tests.rs`:
   - `offers_are_refused_before_the_payload`;
   - `a_refusal_marks_the_neighbour_full_until_its_next_summary`;
   - `cut_transfers_resume`;
   - `lifetimes_run_from_creation_not_per_hop`;
   - `a_source_over_its_share_makes_way_with_its_own`;
   - `copies_by_size`, `spray_modes`;
   - `copies_in_flight_are_not_given_twice`.

### Open (with evidence)

1. **Announcements overload Bluetooth: the top finding.** Every
   rebroadcast is unicast to every neighbour every 2 s, so a device sends
   about origins in scope × neighbours × ~120 B per period:
   - `global-scale` (neighbourhoods of 80): 6.1 KB/s per device at 10k and
     9.4 KB/s at 2k, against a 1 KB/s target.
   - `routing-convergence` at full size (300 phones): 18.6 KB/s per device.
     Phones whose peer-to-peer radios differ (AWDL vs Wi-Fi Direct) share
     only BLE (40 kB/s). Saturated, those links deliver announcements late,
     routes expire and return, and routing sits at 91–98% of pairs, never
     99%. The mesh before GLOBAL does worse: 183 KB/s, ~92%.
   - `flood-scaling`: see the table in §5.
   - `conference` (tier 1, 24 seats): BLE queues drop packets; 80% of
     messages delivered, p95 3.4 s (targets 95%, 3 s).

   Directions, all trade-offs between convergence and overhead, so
   GLOBAL's call:
   - Babel's timing: 4 s hellos, 16 s updates, with triggered updates and
     retractions already in place.
   - A byte budget per hop derived from its measured cost.
   - Sending an (origin, seqno)'s 64-byte signature once, pulled on
     demand.
   - OLSR-style relay selection.
   - A cap on mesh neighbours in the node (a real BLE radio holds ~10
     connections).

   Repro: `mycel-sim routing-convergence`, `mycel-sim flood-scaling`,
   `mycel-sim global-scale --scale 0.02`.
2. **On Infocom 2005 the carrier still trails PRoPHET slightly** (§5):
   27.9% of messages against 30.7%, at a third of its median latency
   (1,349 s against 4,371 s) and a seventh of its overhead (8.7 against
   59.7). Before fixed 8 it delivered 13%. On Infocom 2006 it now leads
   (51.2% against 38.6%). Following predictability for the destination
   rather than the internet speeds the median (782 s) but delivers less
   (23.6%). Repro: `MYCEL_TRACE=bench/data/infocom2005/contacts.Exp3.dat mycel-sim trace-replay`.
3. **`disaster-dtn`: many copies per message** (34 at seed 1, against a
   target of 8 set for Spray-and-Wait; delivery now 87–93%). The metric
   counts every custody hand-off, and a single copy climbing the internet
   gradient changes hands many times as people move: 17 per message with
   no gradient, 35 with it, for 13 points more delivery. Small bundles
   also start with 32 copies, chosen for chat speed
   (`docs/BENCHMARKS.md` §6.5); with 4 the count is still 22. A hand-off
   only to a neighbour better by a wider margin, or a hand-off budget per
   bundle, would cut it; both trade delivery.
4. **`global-scale` optimality p95 is 12.9×** (target 5×). Messages to
   new peers pay a record lookup (~2 × access + 150 ms) and a dial; the
   oracle has neither. A target per "first contact" vs "warm connection"
   would say more. Delivery is 100%, p95 0.8 s.
5. **Spray policy.** Spray-and-Focus (copies only to neighbours no worse
   than us) replaced spraying only on zero knowledge and moved
   `disaster-dtn` from 38% to 60%. Spray-first (copies to the likeliest
   neighbour, better or not, while there are copies to spare) now
   replaces it: 90% on `disaster-dtn` (mean of 5 seeds) with the other
   fixes, and on The ONE's Helsinki trace 62.9% against 39.5%
   (`docs/BENCHMARKS.md` §6.5).
6. **Tier-2 memory is ~200 KB per device** at 10k, mostly routing state
   for ~80 origins (route entries, `heard` lists) and neighbours'
   64-entry predictability maps. A sorted `Vec` instead of a `HashMap` for
   the latter would roughly halve it.
7. **A panic in the QUIC stack kills the process under load.**
   `conference` at full size (300 real nodes, 36 GB footprint, swapping)
   aborted. `noq-proto` 1.3.0 `connection/mod.rs:4172`
   (`discard_space`) expects "PathId::ZERO is alive while
   Initial/Handshake spaces exist". Path 0 was gone before the handshake
   finished. The panic poisoned noq's mutex, and a panic while unwinding
   aborted the process. In the app that means one bad connection crashes
   the node. It may relate to Mycel's iroh patch opening backup paths
   during the handshake (`vendor/iroh/MYCEL_PATCH.md`); worth a minimal
   repro upstream. At 100 seats, spawning didn't finish in 30 min; 24
   seats ran.
8. **Memory grows with walking devices in tier 1.** `shutdown` at full
   size (30 walking nodes, 373 s): +4.8 GB, 159 MB per node, against
   1 MB per node for 12 nodes over 46 s. Messages took p95 14.4 s and the
   call couldn't join. Not yet known whether the emulator (per-pair
   delivery queues and tasks) or the node (connections remade as devices
   move) holds it. Repro: `mycel-sim shutdown`, watching RSS.
9. **`us-eu-live`'s call lost 66.7% of its audio** at full size on the
   loaded machine (0% at CI size earlier). Real-time audio over three
   emulated BLE hops shares the radio with announcements (finding 1).
   Messages: 100%, p95 1.4 s.
10. **The oracle is a lower bound only for single-packet messages.** It
   moves a whole message per hop. For 0.5–1 MB messages a pipelined live
   path beats it, giving ratios below 1 in `trace-replay`.

## 5. Benchmarks against external baselines

**Baseline routers in tier 2** (`tier2/dtn.rs`), run on the same scenarios,
the same traces and the same workload, for apples-to-apples comparisons:
Epidemic (Vahdat & Becker 2000), binary Spray-and-Wait (Spyropoulos et al.
2005), plain PRoPHET (RFC 6693, The ONE's parameters: P_init 0.75, β 0.25,
γ 0.98 per 30 s), and **managed flooding** as Meshtastic and BitChat do it
(hop limit, duplicate suppression, random delayed rebroadcast cancelled when
it hears another rebroadcast). All have a FIFO-drop buffer and a TTL.

**Real contact traces.** `traces.rs` reads CRAWDAD cambridge/haggle
(`contacts.ExpN.dat`: Intel, Cambridge, Infocom 2005/2006; Cambridge city
per-node files) and a generic CSV (e.g. NUS Bluetooth via
`bench/traces/nus_to_csv.py`). Licence: "cite, don't re-identify, don't
re-share", so they are not in the repository. `bench/fetch.sh traces` puts
the Haggle contact files in `bench/data/` (the same files the benchmarks
replay), and `bench/fetch.sh dataport <archives>` unpacks the full IEEE
DataPort archives (free account) into `bench/data/dataport/`. Then
`MYCEL_TRACE=bench/data/infocom2006/contacts.Exp6.dat cargo run --release -p mycel-sim -- trace-replay`.
Without them, `trace-replay` uses a synthetic trace with the same shape
(heavy-tailed Pareto α 0.6 inter-contacts, as Chaintreau et al. measured on
these traces), and says so. Workload: The ONE's default settings (a message
every 25–35 s, 500 kB–1 MB, TTL 300 min, 5 MB buffers, Bluetooth 250 kB/s).
Metrics: delivery ratio, latency distribution, The ONE's overhead ratio
((relayed − delivered) / delivered), buffer occupancy (average, peak).

| Trace | Router | Delivered (of 4,000) | Latency p50 | p95 | Overhead | Buffer avg |
|---|---|---:|---:|---:|---:|---:|
| Infocom 2005 (41 iMotes, 70.6 h, 17,712 contacts) | **global core + DTN** | 27.9% (13.0% before fixed 8) | 1,349 s | 15,532 s | 8.7 | 1653 kB |
| Infocom 2005 (41 iMotes, 70.6 h, 17,712 contacts) | epidemic | 18.8% | 6,222 s | 17,124 s | 116.3 | 2205 kB |
| Infocom 2005 (41 iMotes, 70.6 h, 17,712 contacts) | PRoPHET | 30.7% | 4,371 s | 16,194 s | 59.7 | 1712 kB |
| Infocom 2005 (41 iMotes, 70.6 h, 17,712 contacts) | spray-and-wait (L=6) | 26.7% | 2,452 s | 15,894 s | 8.1 | 2148 kB |
| Infocom 2005 (41 iMotes, 70.6 h, 17,712 contacts) | managed flooding (7 hops) | 5.7% | 15 s | 49 s | – | – |
| Infocom 2006 (98 iMotes, 93.7 h, 149,066 contacts) | **global core + DTN** | 51.2% (31.3% before fixed 8) | 1,040 s | 15,218 s | 9.1 | 999 kB |
| Infocom 2006 (98 iMotes, 93.7 h, 149,066 contacts) | epidemic | 20.6% | 6,597 s | 16,984 s | 289.1 | 1652 kB |
| Infocom 2006 (98 iMotes, 93.7 h, 149,066 contacts) | PRoPHET | 38.6% | 4,274 s | 16,633 s | 153.1 | 1192 kB |
| Infocom 2006 (98 iMotes, 93.7 h, 149,066 contacts) | spray-and-wait (L=6) | 28.6% | 1,922 s | 15,736 s | 12.2 | 1437 kB |
| Infocom 2006 (98 iMotes, 93.7 h, 149,066 contacts) | managed flooding (7 hops) | 14.2% | 33 s | 78 s | – | – |
| Synthetic, same shape (40 devices, 72 h, 17,562 contacts) | **global core + DTN** | 99.5% | 5 s | 1,212 s | 3.4 | 236 kB |
| Synthetic, same shape (40 devices, 72 h, 17,562 contacts) | epidemic | 65.7% | 4,353 s | 15,804 s | 151.7 | 2534 kB |
| Synthetic, same shape (40 devices, 72 h, 17,562 contacts) | PRoPHET | 99.2% | 398 s | 5,591 s | 86.4 | 2518 kB |
| Synthetic, same shape (40 devices, 72 h, 17,562 contacts) | spray-and-wait (L=6) | 56.5% | 146 s | 7,224 s | 7.2 | 2522 kB |
| Synthetic, same shape (40 devices, 72 h, 17,562 contacts) | managed flooding (7 hops) | 61.9% | 25 s | 48 s | – | – |

Run on this Mac with the real traces (`MYCEL_TRACE=…/contacts.Exp3.dat` and
`contacts.Exp6.dat`), seed 1. Overhead is The ONE's (relayed − delivered) ÷
delivered. Managed flooding only forwards to devices in contact now, so it
has no buffer. Epidemic is buffer-bound at 5 MB: it floods the buffers and
evicts. With the carrier fixes (§4, fixed 8) GLOBAL's carrier leads on
Infocom 2006 and trails PRoPHET by 3 points on Infocom 2005, at a fraction
of its latency and overhead (open finding 2). On the synthetic trace it
delivers the most, fastest. The ONE's own routers on the same traces (Epidemic, PRoPHET,
Spray-and-Wait, MaxProp) are in `docs/BENCHMARKS.md` (the bench work); its
link model differs: whole messages over contacts that must last.

**Flooding baseline vs Meshtasticator.** Meshtastic's simulator reports, for
LoRa meshes, that reach rises with the hop limit and levels off around 3–5,
while each extra hop adds redundant rebroadcasts (hence the default of 3).
`flood-hop-limit` reproduces the shape on a 100-device Bluetooth
neighbourhood:

| Hop limit | Reach, delayed suppressible rebroadcast | New devices per transmission | Reach, rebroadcast always | New devices per transmission |
|---:|---:|---:|---:|---:|
| 1 | 16% | 15.25 | 16% | 15.47 |
| 2 | 33% | 4.42 | 39% | 2.43 |
| 3 | 53% | 3.99 | 63% | 1.82 |
| 4 | 68% | 3.68 | 82% | 1.45 |
| 5 | 83% | 3.38 | 96% | 1.23 |
| 6 | 92% | 3.10 | 100% | 1.06 |
| 7 | 93% | 2.94 | 100% | 1.00 |

100 BLE devices outdoors, one per 625 m² (~18 in range); one broadcast from a random device, averaged over runs. Reach rises with the hop limit and levels off, while each extra hop adds redundant transmissions: Meshtasticator's published shape, and why Meshtastic defaults to 3.

**Announcement overhead vs mesh size** (`flood-scaling`, full size: Bluetooth-only phones, one per 900 m², ~12 neighbours, 40 s): control bytes per device per second, as a share of one BLE radio (40 kB/s), and the share of sampled pairs within 8 hops that have a route.

| Devices | GLOBAL core (fisheye + reduction, 2 s) | fisheye only | neither | every 10 s | Mesh before GLOBAL |
|---:|---:|---:|---:|---:|---:|
| 250 | 21.7 kB/s (54%), 92% routed | 23.0 kB/s (58%), 94% routed | 44.2 kB/s (111%), 59% routed | 7.0 kB/s (18%), 88% routed | 48.0 kB/s (120%) |
| 500 | 25.7 kB/s (64%), 89% routed | 26.8 kB/s (67%), 90% routed | 51.9 kB/s (130%), 50% routed | 8.7 kB/s (22%), 91% routed | 49.6 kB/s (124%) |
| 1,000 | 27.3 kB/s (68%), 92% routed | 28.3 kB/s (71%), 90% routed | 55.3 kB/s (138%), 42% routed | 9.2 kB/s (23%), 86% routed | 52.2 kB/s (131%) |
| 2,000 | 30.8 kB/s (77%), 84% routed | 31.8 kB/s (79%), 88% routed | 61.0 kB/s (153%), 36% routed | 10.6 kB/s (26%), 84% routed | 54.4 kB/s (136%) |

Fisheye halves the traffic and is what keeps routes; flood reduction barely matters at ~12 neighbours. Even a 10 s period costs a quarter of a BLE radio at 2,000 devices: open finding 1.

Qualitative only: this model has no collisions (Meshtasticator's LoRa model
does), so usefulness falls through redundancy, not loss.

**Internet latency from measured data.** WonderNetwork's public sample of a
day of global pings (19–20 July 2020, 246 servers, 2.9 M rows; credit:
WonderNetwork, ["A day in the life of the internet"](https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/)).
Their terms ask for credit and a link and give no redistribution licence, so
the data isn't committed: `bench/fetch.sh latency` downloads it to
`bench/data/wondernetwork/`; `cargo run --release -p mycel-sim -- fit-latency` fits our
model against it; `MYCEL_PINGS=bench/data/wondernetwork` makes tier 2 use the
measured RTT between the servers nearest each device instead of the model.
Fit over 29,889 server pairs ≥ 200 km apart (derived statistics only):

| | |
|---|---|
| min RTT ÷ light in fibre over the great circle (path inflation) | median **2.04×**, p95 4.5× |
| least squares | min RTT ≈ 25 ms + 17.0 µs × km |
| our model (1.4×) ÷ measured average RTT | median 0.69, p95 0.97 |
| New York – London (5,547 km) | measured 71 ms, model 78 ms |
| New York – Los Angeles | 68 ms vs 56 ms |
| London – Frankfurt | 13 ms vs 9 ms |
| London – Tokyo | 217 ms vs 134 ms |
| Sydney – Singapore | 94 ms vs 88 ms |
| São Paulo – Miami | 123 ms vs 92 ms |

So 1.4× fits well-cabled corridors (the transatlantic routes the US–Europe
scenarios use) within 10%, and underestimates the median pair by ~30%: use
`MYCEL_PINGS` for global numbers.

## 6. To run on Linux (Docker or a Linux machine)

The external tools have one home, `bench/` (`docs/BENCHMARKS.md`); what
needs Linux is in `bench/linux/` with its own README, and hasn't run yet.
What each adds to this simulator:

- **The ONE** (runs anywhere Java does; already run, `docs/BENCHMARKS.md`
  §3): its routers on the same CRAWDAD traces through `bench/run.py`.
  `mycel-sim export-trace` writes any trace this simulator reads (the
  synthetic one included) as the benchmarks' contacts CSV, which
  `bench/traces/convert.py` turns into a workload and The ONE's events.
- **Shadow** (real Mycel CLI processes, real syscalls, simulated network):
  `bench/linux/shadow/make_config.py` builds the world graph with this
  simulator's fibre model, or WonderNetwork's measured RTTs with
  `--measured`. A traffic driver through the local API is the missing
  piece. It covers the IP side at scale with the real binary.
- **Mininet-WiFi** (mac80211_hwsim, real 802.11 MAC, kernels' routing):
  `bench/linux/mininet_wifi_mesh.py --proto batman_adv|olsrd|babeld|mycel`
  builds an ad-hoc line (`--spacing 40` is `city-block`'s) and compares
  Mycel's mesh with batman-adv, olsrd and babeld on identical topologies,
  with collisions and rate adaptation EmuNet lacks.
- **CORE / EMANE**: the same topologies with EMANE's 802.11abg, TDMA and LTE
  radio models for PHY-level realism.
- **quic-network-simulator**: an endpoint image for Mycel's QUIC so the
  ns-3-based interop scenarios (handshake loss, blackholes, rebinding,
  migration, drop and corruption rates) run against it and against
  quinn/quiche.

## 7. Wiring other routing cores

Tier 2 drives any sans-IO router through `tier2::engine::Router` (frames,
links, internet, timers, a directory). `tier2/global.rs` is the adapter for
GLOBAL's core and carrier and the template for others: translate the core's
effects (`Out`) into `Cx` calls (`send_radio`, `send_inet`, `set_timer`,
`reach_put`/`reach_get`, `delivered`, `receipt`) and its inputs from the
`Router` callbacks.
