# Simulation: real-world scenarios, scale and routing

`crates/mycel-sim` tests Mycel against the networks people actually have
(Bluetooth, AWDL, Wi-Fi Direct, Wi-Fi LAN, 802.11s mesh, Ethernet, UWB,
Thread, cellular, the internet with NAT and relays) and at global scale, with
a focus on hops and routing: *does a message from a Bluetooth-only phone in
the US reach a Bluetooth-only phone in Europe, and is the path it takes the
fastest one that existed?*

Every medium here is emulated. Which of Mycel's links have also run
between real devices is in [TESTING.md](TESTING.md#real-hardware).

```
cargo run --release -p mycel-sim -- list
cargo run --release -p mycel-sim -- all                    # everything, full size
cargo run --release -p mycel-sim -- us-eu,mailbox --scale 0.1 --seed 7
cargo run --release -p mycel-sim -- t2 --candidate main    # hold the earlier mesh design to the same objectives
cargo run --release -p mycel-sim -- ci --seed 1000 --runs 10  # CI's gate: 10 seeds per scenario (§1)
cargo run --release -p mycel-sim -- liar-ceiling           # plausible liars, four strategies, seeds 1–20 (§4, open 15)
cargo test --release -p mycel-sim                          # CI sizes; `-- --ignored` for the rest
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
| What runs | Real `Node`s: iroh QUIC, multipath, the mesh (the routing core and carrier inside the node), sync, calls with test-tone "microphones" | The sans-IO routing core (`mesh/core.rs`) and store-and-forward carrier (`mesh/dtn.rs`), the real code, plus models and baselines |
| Network | `mycel_net::emu::EmuNet`: shared media with positions, range, rate, airtime (half-duplex, one collision domain per radio), latency, jitter (in-order), loss, per-pair rules (NAT, access latency, 802.11s hops), discovery, devices coming and going | Per-hop latency + size/rate per radio, the internet with geography, NAT and relays, a record directory, mobility, churn, contact traces |
| Time | Real time (iroh, noq and the mesh read `std::time`; paused tokio time gave no speed-up and mixed clocks, measured) | Virtual (µs), one event queue |
| Scale on one Mac (18 cores, 24 GB) | ~2–2.5 MB and ~1% of a core per node: 500 nodes measured (1.2 GB) | ~1.1 M events/s on one core. 2,002 devices × 12 min: 116 s, 840 MB. 10,003 devices: 33 min, 2.15 GB (on a loaded, swapping machine) |

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
the emulated media). Reported as p50 and the tail (below). The oracle is a lower bound:
no congestion control, no lookups, no handshakes. So for small messages the
ratio measures routing (path choice, lookups); for large ones it also measures
QUIC slow start over long round trips; and in tier 1 it includes Mycel sync's
own round trips (a 32 ms message on a 5 ms LAN path is 6×).

**Candidates.** Tier-2 objectives judge `--candidate global` (default: the
routing core and carrier), `main` (the earlier flooding mesh, modelled), or
`stand-in` (an earlier model of the current design, kept as a reference).

**The tail.** p99 of a few hundred messages is one of the few slowest:
at n = 400 its exact 95% interval (from the order statistics) runs from the
9th-largest ratio to the largest, and below 299 messages it has no upper
bound at all. So the tail is reported, and judged, in numbers that hold at
that size (`stats::Tail`): p95 with its exact interval; CVaR₉₅, the mean of
the worst 5% (it moves with every message in the tail, not with one order
statistic); and how many messages are over 10× and over 30×, with Wilson
95% intervals on the share (`trace-replay` gates all four: p95, CVaR₉₅
and the upper Wilson bounds over 10× and over 30×). p99 is reported only
for 4,000 messages or more, pooled over seeds (`--runs`). Tier 1 has tens of messages per run
and reports the slowest instead.

**Seeds and verdicts** (`src/seeds.rs`, `src/stats.rs`). A seed is a
replication, never a tuning target. Replication seeds come from a base and
a run index (`run_seed(base, i)`, SplitMix64's mixer over both: ns-3's
fixed seed with an advancing run number), and each seed's randomness is
split into streams that never share a sequence: the world
(`Rng::new(seed ^ tag)`, as before), walking devices (fixed 22), the
workload where the world already draws from the bare seed
(`Stream::Workload`), the engine's radio jitter (`Stream::Protocol`), and
each routing core's generator (`Stream::Routers`, one sub-stream per
device). Before, the engine drew its jitter from `Rng::new(seed)`, the
very sequence a mesh's positions came from, and the routers' seeds were
`seed × constant ^ device`: xorshift states a few bits apart. (So every
tier-2 number changed once; §3 is rerun on the split streams.)

Objectives come in two kinds (`Slo::invariant`):

- **Invariants** hold on every seed, or the gate fails: no packet sent
  round a loop, no honest route through a black hole once the defence has
  run, routes converge at all (and again after the busiest device fails),
  nothing delivered between a pair every path of which crosses a liar.
  A scenario expected to fail (a known gap) is excused its quality
  objectives, never an invariant (`ScenarioResult::finish`); a candidate
  that doesn't model an invariant (`main`'s loops and convergence) has it
  as a quality objective instead.
- **Quality objectives** (delivery, latency, optimality) pass on at least
  8 of 10 seeds. If each seed passes with probability 0.95, that gate fails
  1.2% of the time (exact binomial, `stats::spurious_fail`), while three
  seeds that all pass bound a seed's failure rate only below 63% (ten:
  26%). The gate's seeds are fixed and tier 2 is deterministic, so that
  1.2% describes fresh seeds (the soak), not the gate: there a seed that
  misses, misses on every run until the code changes, and uses up slack.
  `gateway-choice` has 1 of its 2 allowed misses used (1 KB optimality
  p50 2.03× against 2×, on 1 of the 10 gate seeds); every other gated
  scenario passes on all 10. Such a seed is printed as a "quality miss
  (within 8 of 10)", not as a failing seed.
- **A known gap** (a scenario expected to fail, like `liar-ceiling` from
  225 phones) is judged the other way round: its invariants on every
  seed, and its quality objectives must keep failing. Its own misses are
  "known-gap misses", never seeds to pin. A seed where it passes is
  printed ("known gap closed"); once it passes on 8 of 10 (16 of 20) the
  expectation is stale, the verdict fails and those seeds are named.

Thresholds are calibrated on base 2000's seeds (30 at CI size), never on
the gate's (base 1000). CI's "Simulation" job (`.github/workflows/ci.yml`)
runs `mycel-sim ci --seed 1000 --runs 10`: the nine tier-2 scenarios of
`seeds::CI_SUITE` at CI size, ten seeds each, in parallel, then the pinned
regression seeds (`seeds::PINNED`), every objective; every failing seed is
printed with the command that replays it, and the verdicts go to the job
summary. `--min-pass` above `--runs` is refused rather than failing every
scenario. A nightly soak (`.github/workflows/sim-soak.yml`) runs the gate's
scenarios, the heavier ones and `liar-ceiling` on 20 fresh seeds (the base
is the run's id) and prints each failing seed, to be pinned once its cause
is fixed (TigerBeetle's VOPR keeps every seed for the same reason).
`liar-ceiling` runs there at scale 0.75 (225 phones, 3 worlds per seed),
where liars cost delivery and the announcement formats differ (at CI size
they can't be told apart: open 15); it is a known gap at that size, so the
soak guards its invariant and flags the day it passes. The soak as
configured (`liar-ceiling` at 0.75 included) ran end to end on 4 seeds
(`mycel-sim soak --seed 4242 --runs 4`, the 18-core Mac, 4 threads): 170 s
wall, 1,308 s of CPU, 2.9 GB peak memory; every verdict passed, the gap
closed on 0 of 4. Summed run times: `liar-ceiling` 680 s (four runs at a
time), `global-scale` 287 s, `churn` 262 s, the rest 147 s. So 20 seeds
is an estimated 110 CPU-minutes, roughly 30–60 minutes on the 4-vCPU
runner (an extrapolation, not run there; the job's limit is 150), with
memory bounded by `liar-ceiling`'s cap of 4 runs in flight (open 15).
`cargo test --release -p mycel-sim` runs the same gate scenario by
scenario. Runtime, measured on the 18-core Mac with 4 threads while other
jobs ran: `mycel-sim ci --seed 1000 --runs 10` took 93 s wall, 367 s of
CPU and 1.3 GB peak memory (runs summed: `adversarial` 181 s,
`disaster-dtn` 146 s with epidemic now run on each of its 20 worlds, the
other seven 17 s together), and `cargo test --release -p mycel-sim`
156 s for the scenario tests (tier 1's CI three included), 245 s with an
incremental build. On CI's 4-vCPU
runner we estimate (not measured) about 3–6 minutes for the gate plus
the release build; the job's limit is 45 minutes.

## 2. Models and sources

`crates/mycel-sim/src/models.rs` has every number and its source; summary:

| Medium | Goodput | Latency (+ jitter) | Range in/out | Source |
|---|---|---|---|---|
| BLE L2CAP CoC | 40 kB/s per radio, shared by the links with data queued; a 16 KiB drop-tail queue per peer | 15 ms + 15 | 20 / 60 m | Bluetooth Core 5.x (connection events served in turn: 5.4 Vol 6 Part B §4.5.1); Apple WWDC17 (L2CAP CoC); Gomez et al., Sensors 2012; queue = `mycel_link_ble::OUT_QUEUE_BYTES` |
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

Seed 1, full size unless noted. Candidate: the routing core and carrier
(tier 2), the real node (tier 1). ✅ pass, ⏳ fails as expected (reason in
the report: a known gap or a finding), ❌ fail.

The scenarios ran as separate processes and were joined with
`mycel-sim merge`, with the fixes of §4 in place. The machine was loaded
(load averages of 9 to 40 on 18 cores, with other simulations and builds
running), so wall times are pessimistic, and the real-time tier-1 latencies
(calls especially) carry that load. Trace replays are in §5. The tier-2
rows were rerun on the split random streams of §1 (seed 1, one process,
4 threads); every tier-2 number moved once with that change, and the old
value is given where it matters. Tail columns are p50/p95 and CVaR₉₅
(§1); p99 appears only where a sample has 4,000 messages. Tier-1 rows give
p50/p95/max: their runs have at most a few dozen messages (under 51),
where the nearest-rank "p99" these rows used to print is the maximum.

| Scenario | Tier | Size | Status | Result | Wall |
|---|---|---|---|---|---:|
| `cafe` | 1 | full | ✅ | messages: 100% delivered, p50 0.032 s, p95 0.039 s, optimality p50/p95/max 5.77/7.00/7.22× · call: setup 0.051 s, loss 0.0%, latency 101 ms, path Some(Network) | 18 s |
| `office` | 1 | full | ✅ | messages: 100% delivered, p50 0.032 s, p95 0.034 s, optimality p50/p95/max 6.00/59.3/60.6× | 10 s |
| `apartment-80211s` | 1 | full | ✅ | messages: 100% delivered, p50 0.083 s, p95 0.095 s, optimality p50/p95/max 5.63/6.98/6.98× · bulk: next flat 8.2 MB/s, 7 flats away 2.2 MB/s | 10 s |
| `conference` | 1 | 24 seats (scale 0.08), seeds 1–5; 30 and 100 seats, seed 1 | ✅ | 24 seats: messages 100% delivered every seed, p95 0.20 / 1.19 / 0.89 / 0.48 / 0.60 s; 0 Bluetooth packets dropped (was 15–25%, p95 up to 8.2 s, fixed 15) · 30 seats: 100%, p95 0.411 s · 100 seats (a seat hears ~49, 12 hop connections each): 100%, p50 0.463 s, p95 1.10 s, 26 of 169,243 Bluetooth packets dropped, +272 MB (2.7 MB per node; 100 seats didn't finish in 30 min before) | 15–20 s (24), 38 s (100) |
| `city-block` | 1 | full | ✅ | 8 hops: 100% delivered, p50 0.973 s, p95 0.978 s, optimality p50/p95/max 3.24/3.26/3.26× · 9 hops: delivered (max_hops = 10) | 24 s |
| `shutdown` | 1 | full, seeds 1–4 | ✅ | messages (connected at the time): 100 / 90 / 100 / 100% delivered, p95 0.59 / 0.78 / 0.76 / 6.97 s · call between two walkers: heard every seed, loss 0.0%, setup 0.58–1.02 s, over the mesh or Bluetooth (fixed 15) · memory +69–87 MB for 30 nodes | 49–123 s (was 502 s, fixed 16) |
| `disaster-live` | 1 | full | ✅ | member mule: 49 s; stranger mule: 50 s (it never arrived before fixed 2) | 60 s |
| `rural-line` | 1 | full | ✅ | messages: 100% delivered, p50 0.100 s, p95 0.120 s, optimality p50/p95/max 5.73/6.87/6.87× · bulk: next house 6.7 MB/s, 5 hops 0.70 MB/s | 18 s |
| `us-eu-live` | 1 | full | ✅ | messages: 100% delivered, p50 0.788 s, p95 0.805 s, optimality p50/p95/max 4.17/4.26/4.26× · call: setup 1.63 s, loss 0.0%, latency 435 ms, path Some(Mesh) | 20 s |
| `nat-relay` | 1 | full | ✅ | messages: 100% delivered, p50 0.233 s, p95 0.488 s, optimality p50/p95/max 3.32/4.57/4.80× · during the relay outage: 100% delivered, p50 0.263 s, p95 0.772 s, optimality p50/p95/max 3.32/6.39/130× | 23 s |
| `adversarial-live` | 1 | full | ✅ | messages past a black hole and a storm: 100% delivered, p50 0.275 s, p95 0.308 s, optimality p50/p95/max 3.66/4.11/4.11× | 16 s |
| `multipath` | 1 | full | ✅ | 3 links 8.0 MB/s, 1 link 2.9 MB/s (2.76×) | 21 s |
| `mixed-room` | 1 | full | ✅ | Ethernet→Some(Ethernet), Wi-Fi Direct→Some(WifiDirect), UWB→Some(Uwb), Bluetooth LE→Some(Bluetooth) | 26 s |
| `us-eu` | 2 | full | ✅ | global core + DTN: 100% delivered, p95 0.737 s, optimality p50/p95 1.23/2.24×, CVaR₉₅ 2.34× (was p95 0.725 s, 2.15× on the shared streams) · CI size, 30 calibration seeds: optimality p95 2.22–2.37× | 1 s |
| `gateway-choice` | 2 | full | ✅ | global core + DTN: 100% delivered, p95 1.12 s, optimality p50/p95 6.26/9.15×, CVaR₉₅ 9.18× (100 KB and 1 MB messages against the pipelining bound) · 100% of relayed bytes via the far fibre gateway · CI size: 1 KB optimality p50 1.51–2.03× over 30 calibration seeds (target 2×, missed on 1) | 0 s |
| `routing-convergence` | 2 | full | ✅ | global core: 99% routed in 1.1 s, 100% in 1.9 s, 0 loops, re-converged in 0.1 s, stretch 1.01× (before: 99% never, re-converged never) · main: 99% in never · CI size, 30 calibration seeds: 99% in 0.6–0.8 s, 0 loops on every seed | 15 s |
| `flood-scaling` | 2 | full | ✅ | largest N (2,000): global core 8.3% of BLE in steady state (8.4% on the shared streams), 100% of pairs routed (before: 67.0%, 92% routed), main 136.2% | 333 s |
| `partial-route` | 2 | full | ✅ | gap 100 m: global core + DTN 100%; stand-in custody 100% p50 97.6 s; sender-holds 100% p50 98.5 s · gap 300 m: global core + DTN 100%; stand-in custody 0%; sender-holds 0% | 0 s |
| `disaster-dtn` | 2 | full, judged on 12 worlds from seed 1 | ✅ | **global core + DTN: mean 88.1% delivered** (target ≥ 80%; per world 78–100%; 87.2% on the shared streams) · seed 1: 93%, p95 7680 s, optimality p50/p95 1.45/5.38×, 21.3 replicas and 32.6 hand-offs per message (budget 32; mean of the 12 worlds 21.2) · latency p50 against epidemic's, median of the 12 worlds' ratios, 1.42× (per world 1.24–2.34×; target 3×) · PRoPHET 67%, spray-and-wait (L=8) 28%, epidemic 100%, on the same world (60 of 60 messages feasible for every router) · CI size (0.1, 48 messages, mean of 20 worlds): 81.1–91.0% over 30 calibration seeds, median 85.2% (finding 25) | 45 s |
| `mailbox` | 2 | full | ✅ | global core + DTN: 100% delivered, p95 9900 s, optimality p50/p95 1.00/1.00× | 0 s |
| `global-scale` | 2 | 2,002 devices (0.02) | ✅ | global core + DTN: 100% delivered, p95 0.690 s, optimality p50 3.76×, p95 10.0× · first contact p95 0.741 s (≤ 3 s), optimality p95 12.9× · warm p50 0.117 s, p95 0.211 s, optimality p95 2.76× (2.88× on the shared streams; 4.45× before fixed 19; 32.2× before fixed 18) · control 708 B/s per device (was 8,470): routing 470, carrier 238 (was 8,004, fixed 17) · CI size (1,499 devices, shared streams): warm optimality p95 2.65× (was 5.14×, failing) | 58 s |
| `churn` | 2 | 1,001 devices (scale 0.1) | ✅ | global core + DTN: 100% delivered, p95 61.1 s, optimality p50/p95 5.99/12.6×, CVaR₉₅ 16.0× (p50/p95 5.87/12.5× on the shared streams); control 700 B/s per device: routing 2,659 → 471, carrier 4,540 → 256 (full size before the carrier fixes: 100%, p95 65.2 s) | 33 s |
| `adversarial` | 2 | full | ✅ | global core + DTN: 100% delivered, p95 0.091 s, optimality p50/p95 1.91/6.02×, CVaR₉₅ 7.84× (was 82%, p95 1.28 s, 36.6/170× p50/p95, failing: fixed 20) · clean 100%, attacked 100%, Sybil gateway 100% · black holes lying plausibly (today's one-hop liar, judged ≥ 90%; a weak attacker: open 15): 91%, liar-free-reachable delivery 91% of a 100% ceiling (94% on the shared streams; 76% before fixed 21); 85.4% mean over seeds 1–20, and 78.4% for the chain-extending lie any liar can tell today (open 15) · CI size (0.1), 30 calibration seeds: lying plausibly 88.3–100%, median 96.7% | 265 s |
| `liar-ceiling` | 2 | full, seeds 1–20 | ⏳ | ceiling 100% on every seed · each announcement format against its worst strategy: today 78.4% (chain-extending liar, min 69%), signed per-hop chain 78.4% (+0.0), chain + each hop's measured cost 98.9% (+20.6 ± 2.4 points) · by strategy: one-hop liar 85.4%, chain-extending liar 78.4%, honest dropper 98.9%, honest grey hole 99.5% (open 15) · CI size (seeds 1–20): 97.0% (one-hop liar), chain alone +0.3 ± 0.7, hop costs +2.7 ± 0.9 | 507 s |
| `trace-replay` | 2 | full | ✅ | synthetic trace (40 devices, 17,562 contacts over 72 h): global core + DTN 99.0% of feasible (3,981 of 4,000 sent), p50 4.7 s, p95 1311 s, optimality p50 1.22×, p95 8.30× [6.24–13.8], CVaR₉₅ 23.1×, 3 of 396 over 30× (Wilson upper bound 2.2%), overhead 3.34 (was 8.38/18.0× p95/p99: fixed 21; pipelining-aware oracle, fixed 12) · ten full-size calibration seeds pooled (3,982 messages): p95 8.30× [7.73–9.20], CVaR₉₅ 39.8× (the p99 jump 36.8× → 46.9× on the shared streams: finding 26) · real Infocom 2006: 50.8% (passes); Infocom 2005: 27.5% (target 30%; §5; not rerun) | 49 s |
| `flood-hop-limit` | 2 | full | ✅ | reach by hop limit 1..7: 16%, 33%, 52%, 70%, 83%, 91%, 94% (640 broadcasts, the same at every limit; the shape checks are paired, "reach rises" a non-inferiority test, weakest step 6→7 +3.1 ± 1.5 points: finding 24) | 0.5 s |

## 4. Findings

Each with the evidence and how to reproduce it (`--seed 1` unless noted).

### Findings that changed the code

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
9. **A panic in the QUIC stack aborted the whole process** (was open 7),
   in a 300-node tier-1 `conference` run. The vendored `noq` and
   `noq-proto` carry a fix with regression tests
   (`vendor/noq-proto/MYCEL_PATCH.md`); a state-machine panic now closes
   only that connection.
10. **Walking devices grew memory without bound** (was open 8). `shutdown`
   peaked at 30 GB of physical footprint (resident size read +4.8 GB:
   under memory pressure it leaves out compressed and swapped pages).
   - `sample` showed one core spinning in Iroh's path-open retry queue.
   - When a path can't be opened yet (no CIDs, or path IDs used up), Iroh
     re-queued the address once per connection to that peer. Every lookup
     re-added every custom address.
   - With Mycel's several connections per peer and more links than a
     connection's 8 path IDs, the queue multiplied every 333 ms.
   - Fix: each address is queued once (`vendor/iroh/MYCEL_PATCH.md` §5).
   - After: full-size `shutdown` passes with memory flat at ~100 MB (+106 MB
     for 30 nodes, 3.5 MB each) over 500 s.
   - `crates/mycel-net/tests/path_queue.rs` (16 links, 4 connections) grows
     <2 MB in 10 s; without the fix, 21 MB in 5 s.
   - `tier1::resources()` now reads the physical footprint on macOS.
     `MYCEL_SIM_MEMLOG=<secs>` logs memory and tasks during a run, and
     `examples/mem_walk.rs` tracks memory for N walking nodes.
11. **Copies counted custody moves** (was open 3).
   - `copies/msg` now counts replicas: a carrier kept some copies while it
     handed others on. `hand-offs/msg` counts every carrier-to-carrier
     transfer, The ONE's "relayed"; trace-replay's overhead ratio uses it.
   - `disaster-dtn`, seed 1: 27.4 replicas and 32.5 hand-offs per message.
     Spray-first with 32 copies for 2 kB bundles makes most of them.
   - The target is now the carrier's copy budget for that size (32), not
     Spray-and-Wait's 8. With 8 copies delivery falls at seeds 1–3, from
     87/93/85% to 85/85/60%. It passes.
   - Open: an 8-copy budget still showed 32.7 replicas (finding 3 below).
12. **The oracle wasn't a lower bound for multi-packet messages** (was
   open 10). The bound for those is now the fastest single packet, plus
   the rest at the most the destination can take in at once (all its
   radios and the fastest access), and never above the hop-by-hop time.
   Synthetic `trace-replay` optimality p50 went from 0.630 to 1.23. No
   ratio is below 1 any more.
13. **Neighbours' predictability tables** are sorted vectors, half the
   size of the hash maps (was part of open 6). They hold the same values.

14. **Announcements no longer overload Bluetooth** (was open finding 1).
   Every device re-flooded a signed ~120-byte announcement every 2 s,
   unicast to every neighbour. Measured with `MYCEL_CORE` knobs
   (`Config::tune`), then changed in `mesh/core.rs` and the node:
   - **Babel's timing.** The period is 16 s, not 2 s; the full scope
     every 8th period, not every 4th. Lost links never waited for the
     period (hop connections time out in seconds and trigger retractions
     and seqno requests), so it only refreshes. What changes goes out at
     once: a new neighbour is greeted with our routes (one per 4 s, for
     crowds), and a device's first neighbour gets a full-scope
     announcement.
   - **Flood reduction off.** Skipping a rebroadcast after hearing 3
     copies assumes broadcast radios; over unicast hops it left 9% of
     pairs unrouted (`routing-convergence`: 91% with it, 99% without, at
     16 s).
   - **10 hops, not 8.** Routes follow the cheapest path, which can be a
     hop or two longer than the fewest hops. Every unrouted pair left in
     `flood-scaling` and `routing-convergence` was exactly 8 radio hops
     apart with no announcement received: 97% → 100% of pairs.
   - **Batched announcements** (one datagram per neighbour per tick) and
     **at most 6 hop connections opened per device** in range (others
     open theirs: ~11 in all in the conference, from 15; 37% fewer
     Bluetooth packets).

   Before → after, seed 1:
   - `routing-convergence` (300 phones): 99% of pairs routed never → in
     1.1 s; after the hub fails, re-converged never → 0.1 s; 0 loops;
     control 18.6 → 6.2 kB/s per device, cold start included.
   - `flood-scaling`, 2,000 Bluetooth-only phones, steady state: 26.8 →
     3.4 kB/s per device (67% → 8.4% of a BLE radio), 85% → 100% of pairs
     routed (§5).
   - `global-scale` at 2,002 devices: routing traffic 3,768 → 467 B/s per
     device; the simulation runs 6× faster (140 M → 29 M events).
   - `churn` at 1,001 devices: routing traffic 2,659 → 470 B/s, delivery
     and latency unchanged (100%, p95 61.2 s).
   - `us-eu-live`: passes (call loss 0%), but that scenario sets its own
     1 s period; the 66.7% loss was most likely the overloaded machine.
   - `conference` (24 seats): 80% → 100% delivered; p95 still over 3 s
     until fixed 15.

   Tests: `new_neighbours_are_greeted_and_lone_devices_announce_fully`,
   `flood_reduction_is_off_and_floods_reach_everyone` (`mesh/core/tests.rs`),
   `announcements_batch_into_datagrams` (`mesh/wire.rs`).
15. **The emulator's Bluetooth model queued a whole radio in one FIFO**
   (was open 1's `conference` latency and open 11). `EmuNet` gave each
   radio one transmit queue bounded at 250 ms (10 KB at 40 kB/s) for all
   its peers, so a burst to one peer (a QUIC handshake, a sync) dropped
   packets to every other peer: 15–25% of Bluetooth packets in
   `conference`, whatever the announcement settings. The real link isn't
   like that: `mycel-link-ble` opens one L2CAP channel per peer, each with
   its own 16 KiB drop-tail queue (`OUT_QUEUE_BYTES`), and the controller
   serves its connections in turn, one connection event each (Bluetooth
   Core 5.4, Vol 6, Part B, §4.5.1).
   - Fix: `Medium::peer_queue` gives each link its own byte-bounded queue
     and shares the radio's rate between the links with data queued at
     either end; `Tech::Ble` uses 16 KiB (`crates/mycel-net/src/emu.rs`,
     test `peer_queues_share_the_radio`). `MYCEL_SIM_BLE_QUEUE=radio`
     brings back the old model for comparison.
   - `conference`, 24 seats, seeds 1–5: Bluetooth drops 15–25% → 0%, p95
     1.4–8.2 s → 0.20–1.19 s (target 3 s); 30 seats: p95 0.41 s; 100
     seats: p95 1.10 s in 38 s of wall time (it didn't finish in 30 min
     before, with the path-queue leak of fixed 10).
   - `shutdown`, full size, seed 1: old model p95 10.2 s and the call
     never rang; now p95 0.59 s and the tone is heard (seeds 1–4: heard
     every time, loss 0%, over the mesh or straight over Bluetooth).
   - Every other Bluetooth scenario passes at full size with it
     (`city-block`, `rural-line`, `us-eu-live`, `disaster-live`,
     `mixed-room`, `adversarial-live`, `multipath`).
   - No change was needed in the node: with the real queueing, a burst to
     one neighbour no longer costs the others, and nothing is dropped.
     Limit: the real controller's total throughput falls somewhat with
     many connections (more connection-event overhead); 40 kB/s for the
     whole radio is already about a third of one good L2CAP link.
16. **Shutting the lab down took minutes.** A node's endpoint close
   waits for every peer to acknowledge CONNECTION_CLOSE, up to 3 probe
   timeouts per connection; to peers on a slow radio or already gone,
   that is seconds per node, and the lab closed nodes one after another
   (30 walkers: ~4 minutes; a 24-seat conference: 70 s).
   - Fix: the lab closes every node at once, and `Node::shutdown` waits
     at most 2 s (`SHUTDOWN_GRACE`) for the acks; the close frames still go
     out at once. Quitting the app no longer hangs on a slow radio either.
   - `shutdown` at full size: 502 s → 49–123 s wall; `conference` 24
     seats: 96 s → 15–20 s.

17. **Carrier summaries went to every neighbour every 10 s, whole** (was
   open 1, first bullet). Each listed everything held, the latest 256
   receipts and up to 64 predictabilities (36 B each), whether anything had
   changed or not: 8,004 B/s per device at 2,002 devices in
   `global-scale`, 4,540 in `churn`. `Carrier::summaries` now decides per
   neighbour (docs/ROUTING.md §7):
   - everything at first contact (`new_contact`) and every 60 s;
   - between those, only what changed, at most every 2 s: bundles taken
     and receipts learnt since, room, and the predictabilities the
     gradient uses. With the internet gradient that is P(internet), plus
     P(destination) for destinations a neighbour asks for (`wants`: it
     holds bundles for them that the internet can't deliver);
   - nothing if nothing changed. A summary whose stream failed (or, in
     the simulator, that didn't arrive) resets the neighbour to a full one.

   Full summaries keep the 64 most useful predictabilities: PRoPHET's
   transitivity needs destination predictabilities to travel hop by hop,
   and the internet gradient falls back on them for destinations the
   internet doesn't reach; `wants` alone answers only one hop away. (The
   `disaster-dtn` numbers can't separate these variants: open 12.)

   Measured (seed 1): `global-scale` carrier 8,004 → 257 B/s, total control
   8,470 → 727 B/s (target 1,000: passes); `churn` carrier 4,540 → 264 B/s,
   delivery and latency unchanged; `mailbox`, `partial-route` and synthetic
   `trace-replay` unchanged; the bench's forwarding is unchanged (it sends
   full summaries; Cambridge rerun identical). For `disaster-dtn`, see
   open 12. A full summary every 120 s instead of 60 s would halve what is
   left (279 → 156 B/s at 300 s) but cost `disaster-dtn` ~5 points of
   12-seed mean, within the noise of open 12.
   Tests: `summaries_say_what_changed_and_only_what_the_gradient_uses`,
   `wants_bring_destination_predictabilities` (`mesh/dtn/tests.rs`).
18. **Warm messages between two devices with the internet lost their
   first packet** (was open 4: `global-scale` warm optimality p95 32.2×).
   A simulator artefact, not a node bug. The tier-2 driver sent app data
   through the routing core unless the peer was in radio range. Two devices
   with the internet reach each other by dialling an internet hop, which
   makes the peer a core neighbour, and the core refuses data for a
   neighbour ("a direct path always wins"). So the first message got
   through on the dial, and the second, a minute later over the hop still
   up, was dropped. The destination's acks were dropped the same way. The
   1 s retransmission went out after the hop had idled out, and looked up
   and dialled again: first-contact latency + 1 s. Traced on the pair
   688 → 447 (seed 1): 447's ack refused at 120.559 s, 688's retry at
   121.000 s. In the node, two devices with the internet talk over Iroh's
   own direct connection, pooled for `POOL_IDLE` (60 s), not through
   the mesh. The driver now does the same: data goes direct over the
   internet while a connection is warm (any packet within 60 s, or an
   internet hop up). Warm: p95 1.69 → 0.286 s, optimality p95 32.2 →
   4.45× (target 5×); first contact unchanged (p95 0.741 s).

19. **Warm messages to a device behind gateways paid a lookup and a dial
   again** (`global-scale` at its CI size, 1,499 devices, failed: warm
   optimality p95 5.14× against 5×; the same on e6a972b, 77 commits
   earlier). Traced per packet (seed 1): of the 13 warm messages
   over 5×, 10 went from a device with the internet to one behind
   gateways, and their internet hop took as long as at first contact
   (0.4–0.8 s, against an optimum of 0.07–0.15 s for the whole way; the
   other 3 are open 13). Two causes in the routing core's choice among a
   record's gateways (`next_hop`, `mesh/core.rs`):
   - **An untried gateway looked cheaper than the working one.** It was
     costed as a flat 100 ms (`DEFAULT_INTERNET_COST`). A measured hop
     costs its round trip *plus* the time to move 64 KiB: 160–320 ms
     between continents in the simulator, more in the node (RTT ×
     (1 + 64 KiB ÷ cwnd)). So once the first gateway's hop was measured,
     the next packet dialled the record's other gateway and waited for it
     (n365 → n217: dial n229 at +0 ms, connected at +271 ms), and again
     whenever the unused hop idled out after a minute.
   - **The record had just expired.** A looked-up record is trusted for
     60 s, and the warm message came a minute after the first. When the
     dial was through, the record was out of date, so the packet waited
     for a second lookup (+190 ms). In the node, a gateway relaying a
     long flow parked it for a lookup every minute.

   Fix: an untried gateway is costed as the cheapest measured hop to
   another gateway of the same record (they sit in one mesh around the
   destination; 100 ms only when none is measured), and one with a hop
   up wins ties. A record out of date is looked up again on use while a
   hop up to one of its gateways keeps carrying the traffic, for another
   minute (`REACH_STALE`); it never starts a dial. Tests
   `a_working_gateway_is_kept_over_untried_ones` and
   `an_out_of_date_record_keeps_a_working_gateway_while_it_is_looked_up`
   (`mesh/core/tests.rs`). No wire change.

   `global-scale`, warm messages, optimality p95 (p99):

   | Size, seed | Before | After |
   |---|---|---|
   | 1,499 devices (CI), seed 1 | 5.14× (8.54×) | 2.65× (5.14×) |
   | 1,499 devices, seed 2 | 5.89× (10.9×) | 2.69× (4.58×) |
   | 1,499 devices, seed 3 | 5.48× (10.7×) | 3.37× (7.61×) |
   | 2,002 devices, seed 1 | 4.45× (11.2×) | 2.88× (3.40×) |

   Warm latency p95 0.512 → 0.211 s (CI) and 0.286 → 0.211 s (2,002
   devices); all messages, optimality p50 4.42 → 3.26× (CI). Dials
   322 → 240 at 2,002 devices; control traffic 739 → 730 B/s per device
   (CI), 727 → 706 (2,002). First contact is unchanged (p50 6.4×): it
   pays a lookup and a handshake the oracle doesn't. At CI size every
   other tier-2 scenario gives the same numbers but `churn` (latency p95
   40.0 → 39.0 s, optimality p95 13.8 → 13.9×, control 653 → 646 B/s);
   at full size `us-eu` (latency p50 0.409 → 0.387 s, control 1,069 →
   1,048 B/s), `gateway-choice` (p95 1.12 → 1.11 s) and `churn` at 1,001
   devices (optimality p95 12.6 → 12.5×, control 707 → 698 B/s) move a
   little, the others not at all. What is left of the warm tail is
   open 13.
20. **Black holes pulled in most traffic at full size** (`adversarial`
   failed: 82% delivered against 90%; 93% at CI size). Traced per packet
   (seed 1): all 54 undelivered messages were sent into a black hole,
   and every retransmission took the same way. The scenario's 15 black
   holes relay every route at zero cost. An announcement's hops and cost
   aren't signed, so their neighbours believed them and routed through
   them (210 of the 300 phones are next to one). Store-and-forward didn't
   help: bundles followed the same routes, and two black holes next to
   each other, each believing the other, handed every bundle back and
   forth until the run ended. At CI size there are 4 black holes among
   80 phones, and fewer routes cross one.

   Fix (`mesh/core.rs`): a relayed announcement no honest relay can send
   (zero hops from someone other than the origin, or a cost below 2.1 ms
   a hop: `MIN_HOP_COST`, the least a hop adds) gets its sender
   distrusted for 10 minutes. The routes it gave go at once, the routes
   it relays are ignored (it isn't sent back seqnos it has), and it stays
   reachable itself. Honest relays never trip it: no device distrusted a
   neighbour in any other tier-2 scenario, nor in `churn_never_loops`;
   released builds since dev-2026-10-08 keep the same invariant. No wire
   change. Test
   `a_neighbour_relaying_impossible_routes_is_not_routed_through`.

   Full size, seed 1: delivered 82% → 100%, latency p95 1.28 → 0.097 s,
   optimality p50/p95/p99 36.6/170/1570× → 1.88/5.97/8.65×; the Sybil
   gateway run 299/300 → 300/300, p95 1.20 → 0.095 s. Control traffic
   19.7 → 19.5 kB/s per device: routing 14.8 → 18.1 kB/s (the zero-cost
   routes had cut honest flooding short; the run without attackers sends
   17.3 kB/s in all), carrier 4.9 → 1.4 kB/s. CI size: 93% → 100%, p95
   1.20 → 0.079 s. Every other tier-2 scenario gives identical numbers,
   at CI and full size.
21. **Black holes that lie plausibly** (was open 14). A liar that claims
   to be one hop from every origin at the least cost an honest relay
   could report (2.1 ms) passes fixed 20's check and pulls in every
   route longer than about two hops. `adversarial` runs 15 of them (the
   same devices as its black holes; they drop the bundles they take too):
   76% delivered at full size, p95 91 s. Nothing in an announcement gives
   them away, but the destination's acknowledgements don't come back.
   Two defences, both without a wire change:
   - **End-to-end feedback** (`Router::feedback`, `mesh/core.rs`). The
     transport reports a retransmission timeout with nothing acknowledged,
     and each acknowledgement. Two timeouts in a row through one next hop,
     on a mesh route that still claims the destination, over a silence of
     at least 1.5 s plus twice the route's cost, and that hop is
     suspected for that destination for 2 minutes: packets (ours and those
     we relay to it) take the next feasible route, which is loop-free
     like the best; with every route suspected, still the best. One
     acknowledgement clears the count; routes via gateways or the internet
     aren't judged. Bounded: 1,024 destinations, 4 suspects each.
   - **One share down a route that just failed** (`Carrier::doubt`,
     `mesh/dtn.rs`). When feedback judged a mesh route, our own bundles
     for that destination send half their copies along the live route and
     the rest to other neighbours, one share each, keeping the last. Without
     that evidence custody moves whole, as before.

   Full size, seed 1: 76% → 94% delivered, p95 91 → 31 s; 1.0 → 3.8
   replicas per message; control 21.5 → 23.3 kB/s per device in that run.
   CI size: 80% → 97%, p95 91 → 7.1 s. The run is now judged: ≥ 90%.

   What was tried and measured on the full-size synthetic `trace-replay`
   (brief Bluetooth contacts, 1 MB messages, where routes stop delivering
   for ordinary reasons; before: optimality p95/p99 8.38/18.0×):
   - steering custody hand-offs off a suspected hop too, and dropping
     packets once every route was suspected: 7.59/53.7×, and no better
     against the liars (93% at full size); not kept;
   - feedback without the bundle split: 10.5/54.3×;
   - a 3 s minimum silence, or 3 strikes: 9.18/36.8×, and the liars got
     through more (93%);
   - kept: 8.24/36.8×, 3,985 of 4,000 delivered (was 3,982), overhead
     3.21 (was 3.15). The p99 is the 5th-slowest of the 400 messages the
     oracle checks: four more messages now miss a contact and wait 1–4
     minutes, others finish sooner. Every other tier-2 scenario gives the
     same numbers, at CI and full size.

   The tier-2 driver feeds both from its acknowledgements. The node feeds
   them from what QUIC authenticated on each mesh path of its connections
   (`mesh/watch.rs`, `Router::path_feedback`; `docs/ROUTING.md` §6, item
   13): with real nodes, a relay that keeps announcing a destination and
   drops everything to and from it is routed around in 6.6 s
   (`a_relay_that_drops_one_destination_is_routed_around`), and a slow,
   lossy two-hop route suspects nothing
   (`a_slow_lossy_route_is_not_suspected`). When a suspicion leaves no
   feasible route (we advertised the cheap one), a fresh seqno is asked
   for. Signed per-hop route attestations would stop the lie itself; they
   change the announcement format, so they are planned for the next
   protocol version (`docs/ROUTING.md` §6, item 13). Tests
   `unacknowledged_packets_move_a_destination_off_its_next_hop`
   (`mesh/core/tests.rs`), `a_doubted_route_gets_one_share_of_our_bundle`
   (`mesh/dtn/tests.rs`).

22. **Every router now sees the same world** (was open 12's main
   cause). Waypoint mobility drew its targets from the random stream that
   also draws every radio frame's jitter and the routers' own randomness,
   so anything that changed what was sent changed where everyone walked
   and who met whom. In `disaster-dtn` at CI size, seed 1, the seven
   routers compared side by side each had a different world: 3, 11, 5, 11,
   3, 7 and 12 of the 12 messages had any path at all. Walking devices now
   have their own stream, seeded from the scenario's (`tier2/engine.rs`):
   all seven see the same 9 there, and a routing change no longer moves
   the world. Only `disaster-dtn` has walking devices. Its numbers on the
   fixed worlds, full size: seeds 1–12 mean 87.2% (was 80.3%), 2–13 mean
   87.1%, 3–14 mean 86.9% (per seed 77–98%); PRoPHET 67%, spray-and-wait
   27% and epidemic 100% at seed 1 on the same world as GLOBAL's 90%.
   Every tier-2 scenario was rerun at CI and full size with seeds 1, 2
   and 3. Every threshold holds on all three except two:
   - `adversarial`'s plausible-liar run (open 15);
   - at CI size only, `disaster-dtn` with seeds 2 and 3 (75% and 75%:
     6 of 8 and 9 of 12 messages; seed 3 failed on the old worlds too)
     and `flood-hop-limit` with seed 3 (reach falls from 99% to 95% at
     hop 7; the same on 4aab57a, before any of this work). The CI tests
     ran seed 1. (Both fixed: 24 and 25; CI now gates on ten seeds, 23.)

23. **One seed carried every tier-2 verdict, and seeds shared streams.**
   CI ran seed 1 and the thresholds were set from it; three seeds that
   all pass bound a seed's failure rate only below 63%. The engine drew
   radio jitter and the routers' randomness from `Rng::new(seed)`, the
   same sequence a mesh's positions came from, and each router's seed
   was `seed × constant ^ device`. Now (§1, "Seeds and verdicts"): split
   streams, replication seeds from a base and a run index, invariants on
   every seed, quality on 8 of 10, thresholds from calibration seeds,
   pinned regression seeds and a nightly soak. On the 30 calibration
   seeds (base 2000, `mycel-sim ci --seed 2000 --runs 30 --min-pass 1`)
   every invariant held on every seed, and six scenarios passed every
   quality objective on all 30. Three missed once each: `gateway-choice`
   (1 KB optimality p50 2.03×, target 2.00×), `adversarial` (plausible
   liars 88.3%, target 90%) and `disaster-dtn` (latency p50 3.42× epidemic's,
   target 3×, on one world's 20-odd deliveries; now the median over its 20
   worlds, which ran 0.96–1.01× over the same 30: fixed 25). At a per-seed
   pass rate of 29/30 a scenario fails 8 of 10 0.37% of the time, and the
   suite about 1.1% per change (point estimates). The trace-replay tail
   thresholds sit above the worst of the 30 (p95 6.43× against 8×, CVaR₉₅
   86.0× against 120×, Wilson bound over 10× 8.01% against 12%, over 30×
   4.49% against 6%). The gate's own seeds (base 1000) all pass;
   `gateway-choice` on 9 of 10 (2.03× again).
24. **`flood-hop-limit`'s shape check compared different broadcasts.**
   (It is a check on the managed-flooding baseline, not Mycel's router.)
   Each hop limit's run drew new sources from one shared stream, so
   neighbouring limits compared different messages: at CI size with
   seed 3, reach "fell" from 99% to 95% at hop 7 on 20 broadcasts. Every
   limit now sends the same broadcasts (sources and times, from the
   workload stream), 640 at any size (was 20 at CI size, 60 at full), and
   both shape checks are paired, per broadcast:
   - "Reach rises" is a non-inferiority test with a 3-point margin: every
     step up in the hop limit must *show* it loses less than 3 points, the
     mean per-broadcast difference minus two standard errors above −3
     points, so a noisy or underpowered run fails rather than passes.
     Reach needn't rise exactly: with duplicate suppression, a device that
     first hears a copy late, over a long path, has fewer hops left to
     pass it on. (An earlier version passed unless there was evidence of
     a fall, the reverse of non-inferiority, and was labelled as one.)
     One broadcast's reach swings by ~15 points between runs, so with 160
     broadcasts two standard errors of a step were 2–5 points and the
     true test failed on 9 of 30 calibration seeds (mean falls of at most
     2.4 points, most within half a point of zero);
     with 640 they are 1–2.5 points, and on the 30 calibration seeds the
     weakest step's mean was −0.9 points and its lower bound −2.2 (the
     gate's 10 seeds: −1.6). All 40 pass.
   - "Diminishing returns" needs positive evidence: hop 6→7's gain minus
     half of 2→3's must be below zero by more than two standard errors.
     (With 40 broadcasts that missed on 2 of 30 calibration seeds, on
     noise; with 160, on 1 of 30, a world that saturates late; with 640
     it passes on all 30 and on the gate's 10.)
   - The pairing itself is an invariant of the scenario: every hop
     limit's run must have sent the same (time, source) broadcasts, as
     the engine recorded them. Drawing each run's sources afresh again
     fails it on every seed (checked by mutation: 13 of 14 runs differ).
   Seed 3 at CI size is pinned (`seeds::PINNED`) and passes. On today's
   streams it no longer reproduces the unpaired failure (the workload
   moved to its own stream, so seed 3's world changed): it guards the
   paired criterion, and the invariant above guards the pairing.
25. **`disaster-dtn` at CI size failed on sample size.** A CI-size world
   had 12 messages (one message was 8 points of delivery: seeds 2 and 3
   "failed" at 6 of 8 and 9 of 12). It now has 48 messages and, like the
   full size (12 seeds), is judged on a mean: of 20 worlds (seed, seed +
   1, ...). That is what the spread needs: one world ranged 43–100% over
   the 30 calibration seeds, so the spread is the worlds', not the 48
   messages'. The mean of 6 worlds fell below 80% on 2 of 30 (73.6% and
   77.9%), and so did the mean of 10 (78.2% twice; median 86.3%): a few
   per cent false alarm per change at 8 of 10. The mean of 20 (CI size
   now) ran 81.1–91.0% over the 30 (p10 82.0%, median 85.2%, p90 88.3%)
   and passed on all 30; at full size the mean of 12 is 88.1% (per world
   78–100%). "48 messages" is what each world sends; only those with a
   path count, roughly 20 to 48 per world (seed 2's own world has about
   22, so one message there is ~4.5 points), which is why the verdict is
   over worlds. The other two objectives are judged over the same worlds
   now (they were judged on the given seed's world alone, and latency
   missed once in 30 calibration seeds on that: 3.42× against 3×): copies
   per message on the mean, and latency p50 against epidemic's on the
   median of the per-world ratios, epidemic run on every world (one
   world's p50 over a handful of deliveries swings: 0.50–1.85× within one
   seed's 20). Over the 30 calibration seeds the median ran 0.96–1.01×
   and the mean copies 6.8–7.6 (budget 32); at full size, seed 1, 1.42×
   (per world 1.24–2.34×) and 21.2. The 20 worlds, with epidemic on
   each, cost about 17 s of CPU per seed at CI size (503 s for the 30).
   Seeds 2 and 3 at CI size are pinned (`seeds::PINNED`) and pass.
26. **The `trace-replay` p99 jump (36.8× → 46.9×) was one message
   changing places.** Tier 2 is deterministic, so the two commits were
   run on the same synthetic trace (full size: 40 devices, 400 messages
   checked) and seeds 1–3, and compared message by message (the dump is
   `MYCEL_SIM_DUMP=<dir>`). Seed 1, the ten slowest at each commit
   (ratio at c1d38de / at c3217f2):

   | c1d38de's ten slowest | ratio | c3217f2's ten slowest | ratio |
   |---|---|---|---|
   | #1830 (24→38) | 304.5 / 303.5 | #1830 (24→38) | 304.5 / 303.5 |
   | #2610 (17→13) | 83.1 / 99.9 | #3240 (11→7) | 1.2 / 101.4 |
   | #3020 (28→22) | 40.6 / 12.3 | #2610 (17→13) | 83.1 / 99.9 |
   | #3990 (34→22) | 38.2 / 46.9 | #2310 (23→31) | 11.2 / 48.5 |
   | #3730 (1→31) | 36.8 / 36.8 | #3990 (34→22) | 38.2 / 46.9 |
   | #2440 (18→21) | 31.3 / 7.3 | #740 (34→12) | 27.1 / 37.1 |
   | #740 (34→12) | 27.1 / 37.1 | #3730 (1→31) | 36.8 / 36.8 |
   | #3530 (3→7) | 23.2 / 23.2 | #2500 (6→1) | 8.4 / 32.7 |
   | #3910 (18→21) | 20.8 / 9.5 | #2370 (16→2) | 7.3 / 29.1 |
   | #1310 (4→29) | 14.9 / 15.5 | #2200 (23→3) | 9.2 / 25.6 |

   The "p99" is the 5th-slowest: #3730 at 36.8× (the same at both
   commits), then #3990 at 46.9× once #3240 and #2310 moved up. Only 5
   of the ten slowest are the same messages. Over the 398 messages
   delivered at both, 69 are identical, 26 slower by more than 10% at
   c3217f2 and 30 faster, mean log-ratio −0.006. Seeds 2 and 3 move the
   other way: p99 34.8× → 19.9× and 41.8× → 25.5× (top-ten overlap 7 and
   4 of 10; mean log-ratios −0.012 and −0.036); p95 8.24 → 7.55×,
   6.96 → 7.27×, 9.10 → 8.51×. Nothing in the simulator changed between
   the two commits; c3217f2 changed the routing core so that a suspicion
   re-offers the destination's routes and, when nothing feasible is left,
   asks for a fresh seqno. Its footprint here is tiny: seed 1, 551 → 505
   hop suspicions, 3,199,871 → 3,198,096 seqno requests (0.06% fewer),
   1,665,350 → 1,664,603 retractions, routing control 176 B/s per device
   at both; seeds 2 and 3 alike (483 → 477 and 533 → 526 suspicions,
   seqno requests within 0.1%). On a trace of brief
   Bluetooth contacts even that moves control traffic in time, and with it
   which 1 MB message catches which contact: a reshuffle of the slowest
   few, not a regression. The p99 of 400 can't tell the two apart (its
   95% interval runs from the 9th-largest ratio to the largest), which is
   why the gate is now p95, CVaR₉₅ and the shares over 10× and 30× (§1), and p99
   is reported only pooled over 4,000 messages or more. On the ten full-size
   calibration seeds (base 2000, split streams) each seed's p95 ran
   6.30–11.8×, CVaR₉₅ 22.9–67.6× and the Wilson upper bound on the share
   over 30× 2.20–3.92% (over 10×: 3.90–9.11%); pooled, 3,982 messages: p50 1.22×, p95 8.30×
   [7.73–9.20], CVaR₉₅ 39.8×, 159 over 10× (3.4–4.6%), 57 over 30×
   (1.1–1.8%), 18 short of a pooled p99. The gate: p95 ≤ 15×, CVaR₉₅ ≤
   100×, over 10× ≤ 12% and over 30× ≤ 6% (upper bounds) at full size;
   8×, 120×, 12% and 6% at CI size, where the worst of 30 seeds was
   6.43×, 86.0×, 8.01% and 4.49% (the gate's 10: 5.28×, 23.0×, 5.03%,
   3.61%).

23. **Routing defences without a wire change, measured one by one**
   (`docs/ROUTING.md` §6, item 15). Eight were built in the core. Each
   was run alone, all eight together, and the kept set, on seeds 1–10 of
   `adversarial` (half and full size, plus a fan-out workload), `churn`,
   `global-scale`, `trace-replay` and `routing-convergence`. The harness
   is `crates/mycel-sim/examples/ablation.rs` (GLOBAL core only, scaled
   copies of the scenarios). Every run is in
   `bench/results/routing-defences/per_seed.csv`. Seeds 11–20 were kept
   apart for calibration. Kept on by default: cross-destination
   aggregation, the corroboration hold-down and a 2% control budget per
   hop. After the review fixes they take plausible liars at full size
   from 83.8% to 86.9% (10 of 10 seeds), and at half size from 90.6% to
   91.9% (8/1). Nothing else moved beyond the seeds' scatter. Opt-in:
   trust-graph relay preference. It gives the largest gain (half size
   95.7%, 9/1), but clean optimality p95 goes 5.35 → 6.08 on 9 of 10
   seeds. Dropped: a randomised suspicion threshold, churn-conditioned
   suspicion, hedging and smoothed costs (why: `docs/ROUTING.md`). The
   simulator feeds the preference from a membership model
   (`tier2::global::spaces`: two spaces of 8 per device, one local, one
   anywhere; adversaries in none unless `MYCEL_SPACES=insiders`). The
   review found, and fixed, a control budget that never limited a
   greeting (it is sent before the hop is measured), shunning that sent
   a seqno-request burst growing with history, a hold-down that a liar
   could pass by waiting, and destinations going offline shunning an
   honest relay. Each has a regression test in `mesh::core::tests`.

24. **A seqno request's answer didn't set the feasibility distance.**
   This is Babel's invariant (RFC 8966 §3.7.3) and the bug predates the
   GLOBAL defences. A device could accept a costlier route that loops
   through the neighbour it had just told the cheap one. It caused the
   frame loops of full-size `adversarial` with plausible liars: with no
   defences, 33 (seeds 3 and 4) and 134 in the fan-out before the fix,
   0 over seeds 1–10 after it. Cost: delivery under liars with no
   defences 87.0% → 83.8% (full size), as honest alternatives wait for a
   fresh seqno. Test: `a_seqno_answer_sets_the_feasibility_distance`.

### Open findings

1. **Bluetooth control traffic: what is left after fixed 14, 15 and 17.**
   - *(Carrier summaries: fixed 17. `conference` latency: fixed 15, the
     emulator's Bluetooth queue.)* `global-scale` is at 706 B/s per device
     (routing 470, carrier 235) against its 1 KB/s target.

   Repro: `mycel-sim global-scale --scale 0.02`, `mycel-sim conference
   --scale 0.1`. Old routing settings for comparison:
   `MYCEL_CORE=every=2000,far=4,hops=8,reduction=on,greet=own`.
2. **On Infocom 2005 the carrier still trails PRoPHET slightly** (§5):
   27.9% of messages against 30.7%, at a third of its median latency
   (1,349 s against 4,371 s) and a seventh of its overhead (8.7 against
   59.7). Before fixed 8 it delivered 13%. On Infocom 2006 it now leads
   (51.2% against 38.6%). Following predictability for the destination
   rather than the internet speeds the median (782 s) but delivers less
   (23.6%). Repro: `MYCEL_TRACE=bench/data/infocom2005/contacts.Exp3.dat mycel-sim trace-replay`.
3. **Replicas can exceed the copy budget.** With `copies_small=8`,
   `disaster-dtn` made 32.7 replicas per message (seed 1). A hand-off whose
   ack is lost when a contact ends leaves copies on both sides, since the
   giver keeps what it thinks it didn't give. Merged copies are also
   re-split. Repro: `MYCEL_DTN=copies_small=8 mycel-sim disaster-dtn`.
4. *(fixed 18: warm messages, a simulator artefact)*
5. **Spray policy.** Spray-and-Focus (copies only to neighbours no worse
   than us) replaced spraying only on zero knowledge and moved
   `disaster-dtn` from 38% to 60%. Spray-first (copies to the likeliest
   neighbour, better or not, while there are copies to spare) now
   replaces it: 90% on `disaster-dtn` (mean of 5 seeds) with the other
   fixes, and on The ONE's Helsinki trace 62.9% against 39.5%
   (`docs/BENCHMARKS.md` §6.5).
6. **Tier-2 memory is ~200 KB per device** at 10k, mostly routing state
   for ~80 origins (route entries, `heard` lists). The neighbours'
   predictability tables are halved (fixed 13).
7. *(fixed 9: the QUIC panic)*
8. *(fixed 10: memory with walking devices)*
9. **`us-eu-live`'s call lost 66.7% of its audio** at full size on the
   loaded machine (0% at CI size). At a load of ~9: 0% loss, messages p95
   0.88 s. The scenario sets its own 1 s announcement period, so the loss
   was most likely CPU starvation, not announcements.
10. *(fixed 12: the oracle's bound for multi-packet messages)*
11. *(fixed 15 and 16: `shutdown`'s call and messages were the emulator's
   one-queue Bluetooth model; its slow teardown was sequential closes.)*
   Remaining variation: at seed 4 one message of 20 took 7.0 s, at seed
   2 one wasn't delivered within 20 s. The walkers separate mid-delivery
   (1.4 m/s, 60 m Bluetooth range); both are within the 80% / 10 s
   targets.
12. *(fixed 22: `disaster-dtn`'s swings from change to change were
   mostly the world moving with the routing. Seed to seed it still
   varies, 77–98% at full size, which is why it is judged on the mean of
   12 seeds.)*
13. **The warm tail left in `global-scale` is pairs in one neighbourhood
   whose mesh route crosses Bluetooth** (after fixed 19, at CI size: all
   3 warm messages over 5× with seed 1, at 15×, 11× and 5.1×; 6 of the 7
   with seed 3). Phones with
   AWDL and phones with Wi-Fi Direct share only Bluetooth, so a route
   between those islands (or around a gap in one) takes a 40–55 ms
   Bluetooth hop or two, while the oracle goes over the internet between
   two devices of the neighbourhood (10–20 ms). Two cases:
   - *Both ends have the internet:* the node's Iroh connection has the
     direct (or relayed) internet path beside the mesh path, and its
     path selector takes the faster. The tier-2 driver
     (`Global::send_packet`) sends through the core whenever it has a
     mesh route, so it measures the mesh path alone here: a gap in the
     model, not in the node.
   - *One end or neither has the internet:* the core keeps traffic on a
     local mesh route by design (a mesh route beats gateways, and
     `gateway_addrs` offers no gateways for a device the mesh reaches),
     even when the internet through the destination's gateways would be
     faster. Trading a slow local route for gateway traffic (metered,
     budgeted) is a design question, not a bug.

   Repro: `mycel-sim global-scale --scale 0.01 --seed 3`.
14. *(fixed 21: black holes that lie plausibly, in the simulator and the
   node; signed route attestations wait for the next protocol version.)*
15. **Plausible liars: the defences lose pairs they could save, and a
   signed per-hop chain alone buys nothing against a liar that picks its
   lie; binding each hop's measured cost is what pays.** `adversarial`
   judges its plausible black holes at ≥ 90%, set from seed 1 (94% then,
   91% on the split streams). `liar-ceiling` runs that attack on seeds
   1–20 at full size (300 phones, 15 bad devices that drop what they
   relay, 300 messages), four ways on the same world and traffic each
   seed:
   - a *one-hop liar* (today's `Role::Liar`): one hop from every origin at
     the 2.1 ms floor;
   - a *chain-extending liar* (`Role::AttestedLiar`): the cheapest chain
     it was sent, plus one hop and the 2.1 ms floor, so it understates
     only its own link. That is the most a signed per-hop chain lets a
     liar say, and it is open to an unattested liar too;
   - an *honest dropper*: announces the truth and drops everything;
   - an *honest grey hole*: announces the truth and drops half the
     messages it relays (chosen per message), forwarding the rest.

   Attestation only takes lies away: whatever an attested liar can say,
   an unattested one can say too. So each announcement format is judged
   by the worst strategy it leaves open: with no attestation (today) all
   four; with a signed per-hop chain, all but the
   one-hop lie; with each hop's measured cost signed into the chain too
   (each upstream entry carries the upstream's cost to the named next
   hop), only the truthful two. "Worst" is the strategy with the lowest
   mean over the seeds, fixed before two formats are compared, so a gain
   is a paired difference between two strategies seed by seed. (An
   earlier version took each seed's worst strategy: over nested strategy
   sets every per-seed difference is then ≥ 0 by construction, and taking
   the minimum of noisy outcomes biases the gain upward, so its "± 2 SE"
   looked like evidence when it was selection. That per-seed worst, a
   bad device that knew which strategy hurts most in its world, is kept
   as an upper bound on each gain, without error bars.) Liar-free-reachable (LFR) delivery counts
   only the pairs still connected once every bad device is removed, on
   the time-expanded contact graph (`tier2/lfr.rs`).

   | Seeds 1–20, full size, by strategy | Delivered (mean, min–max) | vs the one-hop liar, paired |
   |---|---|---|
   | one-hop liar | 85.4% (77.3–91.0%) | |
   | chain-extending liar | 78.4% (69.3–88.0%) | −7.0 ± 1.4 points, worse on 20 of 20 seeds |
   | honest dropper | 98.9% (97.0–100%) | +13.6 ± 1.5 points, better on 20 of 20 |
   | honest grey hole | 99.5% (98.0–100%) | +14.1 ± 1.5 points, better on 20 of 20 |

   | Each format against its worst strategy, full size | Strategy | Delivered (mean, min) | Gained over the format before, paired |
   |---|---|---|---|
   | no attestation (today) | chain-extending liar | 78.4% (69.3%) | |
   | signed per-hop chain | chain-extending liar | 78.4% (69.3%) | +0.0 ± 0.0 points (the same strategy: nothing taken away that mattered) |
   | chain + each hop's measured cost | honest dropper | 98.9% (97.0%) | +20.6 ± 2.4 points, better on 20 of 20 |

   (± two standard errors of the per-seed differences.) At full size the
   per-seed worst picks the same strategy on every seed, so the upper
   bounds equal these. By scale, seeds 1–20 each:

   | Scale (phones, liars) | Today's worst strategy | Signed chain alone | + each hop's cost | Per-seed worst: today, chain gain, cost gain (upper bounds) | One-hop vs chain-extending lie |
   |---|---|---|---|---|---|
   | 0.1 (80, 4) | one-hop liar, 97.0% (min 92%) | +0.3 ± 0.7 (7 seeds better, 5 worse) | +2.7 ± 0.9 → 100.0% | 96.6%, +0.8, +2.7 | 97.0% vs 97.3% |
   | 0.5 (150, 7) | chain-extending, 92.9% (min 79%) | +0.0 ± 0.0 | +6.7 ± 2.0 → 99.6% | 92.3%, +0.6, +6.7 | 93.2% vs 92.9% |
   | 0.75 (225, 11) | chain-extending, 84.5% (min 75%) | +0.0 ± 0.0 | +15.1 ± 2.5 → 99.6% | 84.3%, +0.2, +15.1 | 88.2% vs 84.5% |
   | 1.0 (300, 15) | chain-extending, 78.4% (min 69%) | +0.0 ± 0.0 | +20.6 ± 2.4 → 98.9% | 78.4%, +0.0, +20.6 | 85.4% vs 78.4% |

   (The per-seed-worst gains of +0.8, +0.6 and +0.2 that an earlier
   version of this table gave for the chain alone were that selection
   artefact: with one strategy fixed per format they are +0.3 ± 0.7, in
   noise, at 0.1 and exactly 0 above.)

   What the numbers say:
   - **Nothing here is inherent.** The liar-free ceiling is 100% on every
     seed at every scale: no pair has every path through a bad device
     (liar-cut 0 messages, 0 pairs), every pair has at least two liar-free
     vertex-disjoint paths and 294 or more of each seed's ~300 have three
     or more (the world is static, so these counts are exact), and
     196–266 have the f + 1 disjoint paths (15 or 16) that no placement
     of the f liars could cut. So LFR delivery equals raw delivery, and
     the 90% target isn't the wrong number: against the worst lie open
     today the defences (fixed 21) lose 12–31% of pairs they could save
     at full size. Lowering the target would hide that.
   - **Today's real threat is the chain-extending lie, not the one-hop
     lie.** An earlier version of this finding compared the attested
     strategy with today's one-hop liar and read the −7.0 points as "a
     chain makes it worse". That doesn't follow: the one-hop liar is a
     weak, partly self-defeating attacker at large scale, and any liar
     can switch to the chain-extending lie today, with no wire change.
     The one-hop liar claims a far origin at 1 hop, so its neighbours
     hold that route in the near scope and expire it after 3.5
     announcement periods, while the liar can only refresh it when the
     origin's far-scope announcement arrives; every other route is
     infeasible (they advertised the cheap one), so they retract and ask
     for a fresh seqno: 1.3–2.3 million seqno requests and 1.1–2.1
     million retractions per run, against medians of 1,350 and 96 with
     chain-extending liars (open 16). Between refreshes the honest
     routes carry traffic. The chain-extending liar keeps its routes
     fresh, and more traffic stays pulled: 189 honest routes ran through
     a liar at the end of the run (mean of 20 seeds) against 142 with
     the one-hop liar. The gap opens with scale: within noise up to 150
     phones, −3.7 points at 225 and −7.0 at 300. So `adversarial`'s
     plausible-liar gate (one-hop liars at CI size) is a gate against a
     weak attacker, and the honest worst case today is 78.4% at full
     size, not 85.4%.
   - **A signed per-hop chain alone buys nothing** against a liar that
     picks its lie: +0.0 points from 150 phones on (the chain-extending
     lie is the worst strategy with or without it), +0.3 ± 0.7 at 80
     phones, within noise.
   - **Binding each hop's measured cost is what pays:** +20.6 points at
     full size (to 98.9%; latency p95 1.5 s, median of the seeds, against
     53 s with the one-hop liar). So step 12 of the routing plan is worth
     its bytes only if each upstream entry carries the upstream's measured
     cost to the named next hop; without it, it isn't (`docs/ROUTING.md`
     §6, item 13 plans the chain without it).
   - **Caveats.** The truthful strategies here are not the strongest
     possible: the dropper drops everything, the easiest kind to detect,
     and the grey hole (half the messages, at random) did *less* damage
     than the dropper on every scale (99.5% at full size). An adaptive
     grey hole (one that drops only once trusted, or only some
     destinations, or only when the defence isn't looking) isn't
     modelled, so +20.6 is an upper bound on what cost binding buys
     against truthful droppers. On the other side, what attestations
     give the defence is not modelled either: a chain names who signed
     each hop, so a source that loses traffic could blame the last
     signer rather than only its own next hop. That could make the chain
     alone worth more than the +0.0 measured here, which counts only
     what it stops a liar from saying.
   - Without a wire change, the remaining 12–31 points are the end-to-end
     defence's to win (it detects only by losing traffic first, and per
     source and destination).

   `liar-ceiling` fails as expected from scale 0.75 on (LFR delivery
   against the worst unattested strategy 84.5% there, 78.4% at full size,
   target 90%); at CI size (80 phones, 4 liars, seeds 1–3) it passes with
   96.7% (one-hop liar; chain alone +0.6 ± 1.1, hop costs +2.8 ± 2.2), and the nightly soak
   runs it at 0.75 on fresh seeds (§1), where its invariant (nothing
   delivered between a pair every path of which crosses a dropper) is
   checked in the regime that matters. Repro: `mycel-sim liar-ceiling`
   (seeds 1–20 at full size: 80 runs). The scenario runs at most
   `MYCEL_SIM_MAX_PAR` runs at once (default 4, never more than rayon's
   threads), on one pool shared by every caller, the soak's parallel
   seeds included: a full-size run holds about 1 GB at its peak (995 MB
   with one in flight, measured by a reviewer), so one per core, as
   before, was an estimated 13–18 GB on the 18-core Mac. Measured on that
   Mac with `RAYON_NUM_THREADS=4` and the default cap: full size 507 s
   wall, 4.2 GB peak; `MYCEL_SIM_LIAR_SEEDS=20 mycel-sim liar-ceiling
   --scale 0.75` 246 s, 1.9 GB; `--scale 0.5` 92 s, 1.1 GB; `--scale
   0.1` 20 s, 0.26 GB. Per seed the numbers are identical to the runs
   before the cap (and to the first version's three strategies);
   `mycel-sim adversarial --seed 2`.
   Over seeds 1–10 the GLOBAL core alone delivers 83.8% at full size
   (fixed 24 lowered it from 87.0%); its default defences take that to
   86.9% (ROUTING.md).
16. **Today's liar makes its neighbourhood ask for seqnos millions of
   times a run.** The mechanism is open 15's: routes it claims at 1 hop
   expire on the near scope's schedule and come back only at the far
   scope's, and each loss with nothing feasible left sends a retraction
   and a seqno request to every neighbour (`after_loss`, rate-limited per
   origin and device by `SEQREQ_GAP`). In `liar-ceiling` that is 1.3–2.3
   million seqno requests per 210 s run of 300 phones (about 30 per device
   per second), and routing control of 21.9 kB/s per device against
   15.9 kB/s with chain-extending liars and 16.3 kB/s with honest droppers (mean
   of 20 seeds): about 6 kB/s more per device, 15% of a Bluetooth radio.
   A cheap way for one device to load its neighbourhood's control
   plane; a hold-down on routes that keep expiring, or a limit on seqno
   requests per neighbour rather than per origin, would bound it. The
   behaviour is the real `mycel_net::mesh::core`'s, which the simulator
   wraps, so the fix belongs to the routing work, not the simulator.
   Repro: `mycel-sim liar-ceiling --scale 0.5` (12 s with the first
   version's three strategies; 105k–123k seqno requests per run of 150
   phones).

17. **Packets can cycle among honest devices in `churn`.** The
   frame-loop counter (a device seeing the same packet twice) is 0 in
   `routing-convergence`, in the core's link-flap tests (including the
   one with every defence at work), and, since fixed 24, in full-size
   `adversarial` without defences. Two cases remain. `churn` at 1,000
   devices, seed 3, counts 54 with no defences (as on `main`) and 90
   with the default set. Full-size `adversarial`'s fan-out with the
   default set counts 1 (seed 6). Not root-caused, and not the
   seqno-answer bug: fixing it left churn at 54. The suspect is where a
   feasible-route choice meets something outside Babel's feasibility
   condition. For example, a hop without a route forwards along its
   default route toward a gateway, while the next one still routes
   toward the destination. Repro: `MYCEL_CORE=defences=none cargo run
   --release -p mycel-sim --example ablation -- churn 3 0.1`.

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
`bench/traces/nus_to_csv.py`). You download the traces yourself, under
CRAWDAD's terms (cite the dataset, don't try to identify people, don't
re-share it); they are never redistributed in this repository. `bench/fetch.sh traces` puts
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

Run with the real traces (`MYCEL_TRACE=…/contacts.Exp3.dat` and
`contacts.Exp6.dat`), seed 1. Overhead is The ONE's (relayed − delivered) ÷
delivered. Managed flooding only forwards to devices in contact now, so it
has no buffer. Epidemic is buffer-bound at 5 MB: it floods the buffers and
evicts. With the carrier fixes (§4, fixed 8) the carrier leads on
Infocom 2006 and trails PRoPHET by 3 points on Infocom 2005, at a fraction
of its latency and overhead (open finding 2). On the synthetic trace it
delivers the most, fastest. The ONE's own routers on the same traces (Epidemic, PRoPHET,
Spray-and-Wait, MaxProp) are in `docs/BENCHMARKS.md`; its
link model differs: whole messages over contacts that must last.

**Flooding baseline.** Meshtastic reports, for LoRa meshes, that reach
rises with the hop limit and levels off around 3–5, while each extra hop
adds redundant rebroadcasts (hence its default of 3). `flood-hop-limit`
reproduces the shape on a 100-device Bluetooth neighbourhood:

| Hop limit | Reach, delayed suppressible rebroadcast | New devices per transmission | Reach, rebroadcast always | New devices per transmission |
|---:|---:|---:|---:|---:|
| 1 | 16% | 15.25 | 16% | 15.47 |
| 2 | 33% | 4.42 | 39% | 2.43 |
| 3 | 53% | 3.99 | 63% | 1.82 |
| 4 | 68% | 3.68 | 82% | 1.45 |
| 5 | 83% | 3.38 | 96% | 1.23 |
| 6 | 92% | 3.10 | 100% | 1.06 |
| 7 | 93% | 2.94 | 100% | 1.00 |

100 BLE devices outdoors, one per 625 m² (~18 in range); one broadcast from a random device, averaged over runs. Reach rises with the hop limit and levels off, while each extra hop adds redundant transmissions: the shape Meshtastic reports, and why it defaults to 3.

**Announcement overhead vs mesh size** (`flood-scaling`, full size: Bluetooth-only phones, one per 900 m², ~12 neighbours). Control bytes per device per second in steady state (over one full fisheye cycle after a first one), as a share of one BLE radio (40 kB/s), and the share of sampled pairs within 8 hops that have a route. In brackets: the first cycle, everyone starting at once.

| Devices | Now (16 s, full scope of 10 hops every 8th) | Now + flood reduction | Now, fisheye off | Before (2 s, 8 hops every 4th, flood reduction) | Earlier flooding mesh (40 s) |
|---:|---:|---:|---:|---:|---:|
| 250 | 2.5 kB/s (6.3%) [3.5], 100% routed | 2.0 kB/s (4.9%), 100% | 9.4 kB/s (23%), 100% | 18.3 kB/s (46%) [30.4], 92% | 48.0 kB/s (120%) |
| 500 | 2.8 kB/s (7.0%) [4.3], 100% | 2.3 kB/s (5.8%), 100% | 12.2 kB/s (31%), 100% | 22.1 kB/s (55%) [35.4], 90% | 49.6 kB/s (124%) |
| 1,000 | 3.1 kB/s (7.7%) [4.9], 100% | 2.5 kB/s (6.3%), 100% | 13.4 kB/s (34%), 100% | 23.4 kB/s (59%) [37.1], 92% | 52.2 kB/s (131%) |
| 2,000 | 3.4 kB/s (8.4%) [5.8], 100% | 2.8 kB/s (6.9%), 100% | 15.7 kB/s (39%), 100% | 26.8 kB/s (67%) [41.2], 85% | 54.4 kB/s (136%) |

Fisheye cuts traffic 4–5×. Flood reduction would save another 18% here, where every device sees every flood from several sides, but it leaves pairs unrouted in sparser meshes (`routing-convergence`), so it stays off. All variants greet new neighbours. Traffic grows slowly with N: the near scope costs the same at any size; the full scope reaches more devices.

Qualitative only: this model has no collisions, so usefulness falls through
redundancy, not loss.

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

## 6. Wiring other routing cores

Tier 2 drives any sans-IO router through `tier2::engine::Router` (frames,
links, internet, timers, a directory). `tier2/global.rs` is the adapter for
the routing core and carrier and the template for others: translate the core's
effects (`Out`) into `Cx` calls (`send_radio`, `send_inet`, `set_timer`,
`reach_put`/`reach_get`, `delivered`, `receipt`) and its inputs from the
`Router` callbacks.

## 7. Scenario catalogue and fidelity

Two pieces from the simulation-fidelity roadmap (WP15 and WP19): a
declarative catalogue of real-world scenarios, and a framework that says
what every simulated number can be trusted for and how robust a verdict is
over what is not known. Neither changes the engine, the routing core or
the hand-written scenarios of §3, so the CI gate's numbers are unchanged
(checked: below).

```
cargo run --release -p mycel-sim -- catalogue                       # the 36 scenarios, status, fidelity, needs
cargo run --release -p mycel-sim -- catalogue earthquake --runs 10  # CI size, 10 seeds, judged as the gate judges
cargo run --release -p mycel-sim -- catalogue all --seed 1          # every runnable one, one seed
cargo run --release -p mycel-sim -- catalogue festival --off fisheye,dtn   # swarm toggles off (WP20)
cargo run --release -p mycel-sim -- catalogue my-town.toml          # a scenario file of your own
cargo run --release -p mycel-sim -- robust earthquake --points 32 --runs 3 --morris-r 8
```

### 7.1 Fidelity levels

Every result carries a fidelity level: the lowest among the models it
uses (`src/fidelity.rs`). The levels are the design's (§3 of the
roadmap): **L0** abstract (a disc, instant links, literature constants:
good for logic bugs, invariants and comparing designs on one world),
**L1** literature-grounded (cited parameters, not checked on our devices:
the direction of an effect), **L2** calibrated on our own measurements
with a discrepancy term, **L3** validated on held-out measurements, **L4**
a recorded real day replayed. Nothing is above L1 today, and the radio is
a disc, so **every tier-2 number in this document is L0**, and so is every
tier-1 number (EmuNet's media are discs too). `report.md` now has
Fidelity, Region and Robust-pass columns on every row; the hand-written
scenarios get their tier's default (`Fidelity::tier_default`).

`fidelity::MODELS` lists 55 models the catalogue can ask for: 20 the
simulator has (with their level and source) and 35 it lacks (with the work
package that brings each and the direction its absence biases results:
optimistic, pessimistic or either way). A catalogue scenario names the
models its key physics **needs**. If a needed model is missing:

- a non-essential need is a note;
- an essential need runs on the component's stand-in (the disc for an
  interference model, instant links for BLE discovery), and the result is
  a **bound**, never a verdict: on an optimistic bound a missed objective
  is a finding (reality is worse) and a pass is inconclusive;
- an essential need with no meaningful stand-in (storage-full devices on
  unlimited storage, a censor without a censorship model) **blocks** the
  scenario: it is listed with what it waits for, and not run.

When a work package lands a model (WP7–WP12 are in progress on other
branches), its entry gets a level, the scenarios that need it become
verdicts, and their numbers start to mean more. That is the point of
stating needs as data.

### 7.2 The catalogue

`crates/mycel-sim/scenarios/NN-name.toml`, the 36 situations of the
roadmap's table, compiled into the binary (`catalogue::FILES`; a test
fails if a file is not listed, malformed, or misnumbered). Each composes:
a region and layout (field, clusters, line, several cities, or a contact
trace), people at full and CI size and the share running Mycel
(adoption), a device mix (iPhones with AWDL, others with Wi-Fi Direct,
BLE-only phones), mobility (static, random waypoint, or static clusters
with walking mules), the radio's neighbour cap, internet (share or exact
gateways, access mix, hard-NAT share, outages of everything or cellular
only, devices abroad), OS behaviour (battery deaths, churn, restart
storms, devices away for hours), adversaries by role and share, a
workload (rate, size, destinations near, far, any or abroad, calls),
objectives, the statistics plan, the uncertain parameters of its
robustness study, the swarm toggles WP20 may vary, and its needs. Full
sizes are the design's; CI sizes shrink the area with the population to
keep density, and are what `catalogue` runs unless `--full`.

Randomness in the composition is keyed per entity (`keyed(seed, purpose,
entity, k)`): device i's place, radios, internet and attacker rank do not
move when adoption, the attacker share or the internet share do, so the
points of a robustness study differ in the parameter, not in a reshuffled
world (WP1's common-random-numbers rule, applied here to the world; the
engine's own streams are WP1's). Tested: raising the attacker share keeps
every earlier attacker, raising adoption keeps every earlier device's
place and radios.

The **range multiplier** (an uncertain parameter) is applied to the
geometry: for a disc, scaling every range by m is exactly scaling every
distance by 1/m (places, area, walking speed), so the engine and its
oracle are untouched. It is exact only for a uniform multiplier on a
disc; WP7's link budget replaces it. Its prior, ×0.63–×1.58 log-uniform,
is a ±6 dB link-budget error at path-loss exponent 3 (computed), a span
that covers per-handset RSSI offsets (estimate).

Three new world components, all **L0 stand-ins** and exogenous (drawn
from the seed, not from traffic): battery deaths (each device dies at a
log-normal time around a median, σ 0.5 by default; WP9's energy model
replaces it), devices away for hours, and restart storms. They only add
scheduled events, so their CPU cost is the cost of the devices that
remain (measured below).

Every catalogue scenario gets a radio-neighbour cap of 8 unless it says
otherwise (Android allows about 7 BLE connections, iOS 6–15 reported).
Without it the first timing run of `office` (150 phones in a 60 × 40 m
room, everyone in range of everyone over Wi-Fi Direct and AWDL) took
422 s for 20 simulated minutes and its devices sent **64.8 kB/s of
control each**, more than a BLE radio carries: an uncapped clique's
announcement traffic grows with its size. With the cap: 2 s, 1.05 kB/s.
The node itself dials at most `max_neighbours` = 6 hop connections and
accepts others' (about 12 in all in a crowd: `mesh/mod.rs`), and real
radios cap connections too, so the uncapped run measured the simulator,
not Mycel. It is a drift between the tier-2 world and the node worth
knowing: a hand-written tier-2 scenario that does not set
`Plan::max_neighbours` (only `global-scale` and `churn` do) gives every device
every neighbour in range, which overstates control traffic in dense
places (catalogue finding 1, §7.5).

### 7.3 Robustness and sensitivity (`src/uq/`)

A verdict counts only if it holds over a **joint uncertainty region** of
what cannot be measured yet, not at one nominal point and not at three
independent corners (pessimistic corners stacked together make a world
nobody believes in, and corners miss interior and interaction worst
cases). `mycel-sim robust NAME` runs, for the scenario's objective
(`[uq] metric`: delivery, latency p95 or control):

1. the nominal point, replicated over `--runs` seeds;
2. `--points` scrambled Sobol points of the region (Joe–Kuo direction
   numbers, Owen scrambling in Burley's hash form; tested: the first 2^m
   points keep the (0, m, 2)-net property after scrambling, and a 4,096-
   point estimate of a 5-D integral is within 0.5%), mapped through the
   parameters' priors and a Gaussian copula for parameters known to move
   together, each point replicated on the **same** seeds. The
   **robust-pass fraction** is the share of points that pass, with a
   Wilson interval; points come from the prior, so it is the
   prior-weighted pass probability;
3. **Morris screening**, `--morris-r` trajectories of k + 1 points on a
   4-level grid (μ* with a bootstrap interval, and σ for interactions);
4. a **Gaussian-process emulator** (Matérn 5/2, one length scale per
   parameter, a noise term, hyperparameters by maximum marginal
   likelihood) on the space-filling runs, checked by closed-form
   leave-one-out (RMSE, Q², coverage of the 95% interval) and on the
   Morris runs as a held-out set;
5. **Sobol first-order and total indices** on the emulator (Saltelli's
   first-order and Jansen's total estimator, 4,096 base rows, 200
   bootstrap resamples). Tested on the Ishigami function: every index
   within 0.03 of the analytic values directly, and within 0.06 through
   an emulator fitted on 256 points (Q² > 0.95). The intervals cover the
   Monte Carlo error on the emulator, not the emulator's own error, which
   is reported beside them;
6. a **worst-case search** on the emulator (sep-CMA-ES from the worst
   sampled points and the centre), and the point found **confirmed with
   `--confirm` fresh seeds**. A verdict is called robust only if the
   nominal point, every sampled point and the confirmed worst case pass;
   the report says the worst case was found by search, not proven.

Every step is judged against **seed noise**, because a scenario's metric
moves with the seed as well as with the parameters, and with a few seeds
per point the seed can be most of what the points show (it was, in the
first `rural-starlink` study: §7.7). The study pools each point's spread
over its seeds into one run's noise, and from it:

- the **signal share**: the part of the variance between points' means
  that is not seed noise (also about the best leave-one-out Q² any
  emulator can reach), and how many seeds per point would bring it to
  80%;
- the **emulator's known noise**: each point's mean is fitted with its
  noise variance fixed (stochastic kriging: Ankenman, Nelson and Staum,
  *Oper. Res.* 58, 2010), and only a small extra nugget is fitted; fitted
  alone, the nugget lost to short length scales that explained noise;
- a **noise floor for each Morris factor**: the μ* that seed noise alone
  would give, from the spread over seeds of each elementary effect (paired
  on the same seeds, so common random numbers count); a factor whose μ*
  interval does not clear its floor is not distinguishable from noise;
- how many failing points fail **beyond noise** (their mean's 95% interval
  excludes the threshold).

The parameters a verdict hinges on are those with a total index ≥ 0.1 only
if the emulator is **adequate**: signal share ≥ 0.5 and leave-one-out Q² ≥
0.6 × the signal share (our thresholds; there is no standard value, and
Marrel et al., *RESS* 94, 2009, judge emulators case by case). Otherwise
they are the Morris factors above their noise floor, and the report says
which basis it used; with neither, it names none rather than ranking
noise. Before Sobol estimation every output is centred: the first-order
estimator is unbiased under a constant shift, but its variance grows with
the square of the metric's mean (Ishigami plus 1000 at 4,096 rows gave
S₁ = −3.8 ± 8.7 against 0.28 ± 0.045 without the offset; regression test
`a_large_mean_does_not_widen_the_intervals`; centring as in Owen, *ACM
TOMACS* 23, 2013).

The parameters a verdict hinges on are the ones that jump WP14's
measurement queue. `uq::params::builtin` has 14 named
parameters, each with a range, a prior and a source or "(estimate)":
`range_mult`, `adoption`, `inet_share`, `nat_hard`, `max_neighbours`,
`walk_speed`, `pause_s`, `msg_rate`, `adversary_share`,
`battery_median_h`, `ios_share`, `ble_only_share`, `churn_per_min`,
`mule_share`. None is calibrated on Mycel's own devices yet (WP14), so
robustness here is robustness over today's ignorance, not a calibrated
error bar.

### 7.4 Catalogue results at CI size

`mycel-sim catalogue all --seed 1` (one run: seed 2515552253147602109,
run 0 of base 1, before single runs took the seed as given; replay a row
with `catalogue NAME --seed 2515552253147602109`), CI sizes, the routing
core and carrier with their defaults, the 18-core Mac with other jobs
running (load 9–13), one scenario at a time on one thread. **Every number
is L0**, and every *bound* row ran without a model its result depends on
(column "needs"). The objectives are product targets written before the
runs, not thresholds calibrated on seeds (§1): a miss is a question to
answer, and none of these scenarios is in the CI gate. One seed per row:
the multi-seed verdicts (`--runs 10`) are the next step for the rows that
matter, and were run for `long-haul-flight` (finding 3).

| # | Scenario | Status (needs) | Devices | Delivered (of feasible) | p95 | Control per device | Wall | Objectives |
|---|---|---|---:|---:|---:|---:|---:|---|
| 1 | `city-commute` | bound (transit, iOS, Doze) | 200 | 100% of 351 | 0.33 s | **20.4 kB/s** | 384 s | met; control: finding 2 |
| 2 | `campus` | bound (Copenhagen trace) | 60 | 100% of 292 | 0.24 s | 1.70 kB/s | 40 s | met |
| 3 | `office` | bound, optimistic (UDP blocked, walls) | 150 | 100% of 130 | 0.20 s | 1.05 kB/s | 6 s | met (inconclusive) |
| 4 | `apartment-block` | bound, optimistic (walls) | 100 | 100% of 86 | 0.12 s | 0.95 kB/s | 3 s | met (inconclusive) |
| 5 | `rural-starlink` | **verdict** | 90 | 80.9% of 47 | 4,734 s | 0.40 kB/s | 8 s | **p95 missed** (≤ 3,600 s) |
| 6 | `rural-line` | bound, optimistic (Wi-Fi Direct setup) | 30 | 100% of 36 | 0.08 s | 0.20 kB/s | 0.3 s | met (inconclusive) |
| 7 | `earthquake` | bound (disaster mobility, BLE discovery) | 150 | 100% of 367 | 838 s | 2.11 kB/s | 52 s | met |
| 8 | `flood-evacuation` | bound (map flows) | 200 | 89.7% of 339 | 4,734 s | 0.65 kB/s | 41 s | met |
| 9 | `protest-shutdown` | bound, optimistic (SINR, body loss, jamming) | 150 (5 attackers) | 98.7% of 525 | **127 s** | 7.06 kB/s | 83 s | **p95 missed** (≤ 60 s): a finding |
| 10 | `protest-mobile-off` | bound, optimistic (body loss) | 150 | 100% of 530 | 0.43 s | 7.16 kB/s | 99 s | met (inconclusive) |
| 11 | `festival` | bound, optimistic (SINR, cell capacity) | 150 | 100% of 394 | 0.24 s | **6.43 kB/s** | 75 s | **control missed** (≤ 4 kB/s): a finding |
| 12 | `stadium-exit` | bound (crowd flow, BLE discovery) | 150 | 100% of 195 | 3.28 s | **46.8 kB/s** | 140 s | **loop invariant broken**: finding 5; control: finding 2 |
| 13 | `conference-hall` | bound, optimistic (SINR) | 200 | 100% of 258 | 0.23 s | 2.67 kB/s | 12 s | met (inconclusive) |
| 14 | `subway` | bound (transit) | 200 | **74.0%** of 285 | 1,339 s | 1.42 kB/s | 16 s | **delivery missed** (≥ 80%) |
| 15 | `long-haul-flight` | **verdict** | 60 | **97.6%** of 212 | 1.56 s | 0.71 kB/s | 2 s | **delivery missed** (≥ 99%): finding 3 |
| 16 | `cross-continent` | bound, optimistic (DHT latency) | 200 | 100% of 154 | 0.48 s | 0.37 kB/s | 1 s | met (inconclusive) |
| 17 | `sparse-internet` | **verdict** | 200 | 100% of 230 | 3.08 s | 1.02 kB/s | 6 s | met |
| 18 | `censored-country` | blocked (censorship) | | | | | | |
| 19 | `whitelist-intranet` | blocked (whitelist) | | | | | | |
| 20 | `update-storm` | bound, optimistic (mixed versions) | 200 | 100% of 825 | 0.97 s | **17.5 kB/s** | 472 s | see finding 2 |
| 21 | `flash-crowd` | bound, optimistic (DHT latency) | 200 | 100% of 190 | 0.29 s | 1.09 kB/s | 3 s | met (inconclusive) |
| 22 | `night-doze` | blocked (iOS lifecycle, Doze) | | | | | | |
| 23 | `adversary-sweep` | **verdict** | 150 (9 attackers) | 98.3% of 595 | 1.91 s | 2.18 kB/s | 1 s | met |
| 24 | `eclipse-vip` | blocked (DHT eclipse) | | | | | | |
| 25 | `hospital` | bound, optimistic (walls) | 150 | 100% of 173 | 0.20 s | 2.68 kB/s | 11 s | met (inconclusive) |
| 26 | `refugee-camp` | **verdict** | 200 | 100% of 493 | 1.44 s | 1.93 kB/s | 72 s | met |
| 27 | `mountain-trail` | bound (shadowing) | 100 | 80.2% of 106 | 8,097 s | 0.12 kB/s | 8 s | met |
| 28 | `highway-v2v` | bound, optimistic (BLE discovery, Wi-Fi Direct setup) | 200 | 100% of 160 | 0.34 s | **19.7 kB/s** | 55 s | met (inconclusive); control: finding 2 |
| 29 | `ferry` | **verdict** | 150 | 99.6% of 265 | 314 s | 3.57 kB/s | 36 s | met |
| 30 | `clock-skew` | blocked (clock skew) | | | | | | |
| 31 | `storage-full` | blocked (storage full) | | | | | | |
| 32 | `low-battery-cascade` | bound, optimistic (energy) | 200 | 100% of 427 | 0.43 s | **13.5 kB/s** | 699 s | met (inconclusive); control: finding 2 |
| 33 | `ios-heavy` | blocked (iOS lifecycle) | | | | | | |
| 34 | `android-oem-mix` | blocked (Doze, OEM killers) | | | | | | |
| 35 | `long-offline-mailbox` | **verdict** | 200 | 100% of 1,091 | 23,708 s | 1.14 kB/s | 217 s | met |
| 36 | `group-chat` | blocked (group sync, WP4) | | | | | | |

Rows 32 and 35 ran in a second pass with the same seed after the first
was stopped at its time limit (28 minutes); every other row is the first
pass. Totals: 36 scenarios, 7 verdicts, 20 bounds, 9 blocked; of the
verdicts, 5 met their objectives and 2 missed (`rural-starlink`,
`long-haul-flight`). `stadium-exit` also broke the loop invariant on this
seed (finding 5).

### 7.5 What the catalogue found

None of these changed routing code: the routing core and carrier belong
to the routing tracks (v2/w2-harden is working on the seqno-request
storm of open finding 16, which finding 2 may share a cause with). Each
is reproducible from the command given.

1. **The tier-2 world has no neighbour cap unless a scenario sets one;
   the node has one.** The node dials at most 6 hop connections (about 12
   in all, `mesh/mod.rs`), but a tier-2 device links to everyone in range
   unless `Plan::max_neighbours` is set (`global-scale` and `churn` set
   8). In a dense room that turns into a clique: 150 phones in a 60 × 40 m
   office sent 64.8 kB/s of control each and took 422 s for 20 simulated
   minutes; with a cap of 8, 1.05 kB/s and 2 s. The catalogue now caps at
   8 by default (Android ~7 BLE connections, iOS 6–15 reported) and
   varies it over 6–15 in robustness studies. The hand-written tier-2
   scenarios are unchanged; the dense ones among them overstate control.
2. **Walking devices multiply routing control traffic.** `city-commute`
   at CI size (200 phones over 707 × 707 m, 85% with internet), 5
   simulated minutes, seed 2515552253147602109, only the share of walkers
   (1.2 m/s, random waypoint) changed:

   | Walkers | Control per device | Seqno requests | Retractions | Routes up |
   |---:|---:|---:|---:|---:|
   | 0% | 1.22 kB/s | not recorded | not recorded | not recorded |
   | 5% | 6.65 kB/s | 520,166 | 300,830 | 532,760 |
   | 20% | 15.6 kB/s | 2,176,779 | 1,378,636 | 1,369,799 |
   | 50% | 24.8 kB/s | 4,376,281 | 3,016,223 | 2,387,853 |

   At 50%, 24.3 of the 24.8 kB/s is routing (the carrier 0.46 kB/s): the
   200 devices sent 7.6 million announcements in 5 minutes (126 per device
   per second), 61% of a 40 kB/s BLE radio spent on routing control. It is the same without internet (25.0
   kB/s), so it is the mesh's own churn, not gateways. `stadium-exit`
   (everyone walking in a crowd) reached **46.8 kB/s** per device, more
   than a BLE radio carries; `highway-v2v` 19.7 kB/s and `update-storm`
   17.5 kB/s. Delivery stayed at 100% in all of these, but on real radios
   this control would crowd out the data and drain batteries. Part of it
   is an L0 artefact: the disc has no hysteresis, so a device walking
   along the edge of range flips links every 5 s mobility step; but real
   radios flap more at the edge, not less (fading), so the core needs
   damping on route churn driven by link churn (a hold-down, or rate
   limits per neighbour on seqno requests and retractions). Reproduce:
   `mycel-sim catalogue city-commute --minutes 5 --seed 2515552253147602109`
   (the per-kind split is in the report's notes).
3. **A static, capped cabin loses about 2% of feasible messages.**
   `long-haul-flight` (60 phones in a 60 × 6 m cabin, no internet, nobody
   moving, cap 8) on 10 seeds (`catalogue long-haul-flight --runs 10`):
   delivery of feasible messages median 98.1%, min 94.3%, ≥ 99% on 1 of
   10 seeds. With the cap lifted to 60 (everyone linked to everyone), 100%
   on 10 of 10. On the first seed 870 packets were dropped for want of a
   route, and 37 messages became bundles of which 32 were delivered: the
   carrier cannot help when nobody moves. The oracle found a path for
   every one of them on the capped links. Not yet explained: either the
   core loses routes in a capped static graph, or the engine's cap (when
   a device relinks, it drops links to neighbours that it did not pick
   among its own nearest 8, though they picked it) churns links at start
   in a way the core handles badly. Either way it is worth a look.
4. **Misses on the targets** (one seed each): `protest-shutdown`'s p95 is
   127 s against 60 s (an optimistic bound, so reality is worse);
   `festival` spends 6.43 kB/s of control per device against a 4 kB/s
   budget (10% of a BLE radio; also optimistic); `subway` delivers 74.0%
   of feasible messages against 80% (static car clusters stand in for
   moving trains); `rural-starlink`, a verdict at L0, has a p95 of 79
   minutes against 60 with one satellite gateway and nine walkers.
5. **A packet came back to a relay: the mesh route and the no-internet
   default route can form a transient loop.** `stadium-exit`, seed
   2515552253147602109, broke the loop invariant once (one packet). Traced
   hop by hop (a temporary print in `tier2/global.rs`, not committed):
   device 64 had internet and a mesh route to the destination 83 through
   38 and sent the packet there at 186.379 s; 38 passed it to 22 along its
   own route; at 186.809 s 22 had **no internet and no mesh route to 83
   any more** (the route it had announced to 38 had just gone, and 38 had
   not caught up), so it took the no-internet default route
   (`core.rs` `next_hop`, step 4) to its cheapest gateway, which was 64.
   That BLE hop delivered 3.57 s later (queued behind control traffic,
   finding 2); by then 64 had lost its route through 38 too, sent the
   packet over the internet to a gateway near 83, and it was delivered.
   Each route is loop-free toward its own target (Babel's feasibility
   condition for routes to 83; the gateway's own announcements for the
   default route), but **switching a packet from one to the other in
   mid-path is covered by neither**: had the hop to 64 been fast, 64
   would still have held its route through 38 and the packet would have
   circled 64 → 38 → 22 → 64 until the retraction reached 38 and 64 or
   the TTL ran out. So this is a real transient loop, not an artefact of
   the detector's 30 s window. It needs a relay without internet that
   loses its route while its upstream still has one, so walking crowds
   with half the devices online are where it shows. Possible fixes, for
   the routing track: when a relay falls back to the default route for a
   packet that came over the mesh, make the gateway its waypoint and have
   the gateway send it over the internet rather than back into the mesh;
   or do what Babel does and drop it (the end-to-end retransmission and
   the carrier recover). Not fixed here: the routing core belongs to the
   routing tracks. Replay: `mycel-sim catalogue stadium-exit --people 3000
   --minutes 20 --seed 2515552253147602109`.

### 7.6 The CI gate is unchanged

The catalogue and the robustness tools add code beside the engine, not in
it, so the gate must give the same numbers. Checked by running it twice,
`mycel-sim ci --seed 1000 --runs 10`, once with the binary of
`v2/integration` (4a321e48) and once with this branch's, both with 4
threads: the verdicts are identical, and all 90 per-seed results are
identical in every metric and note except wall-clock times (and the new
`fidelity` field, which only labels them). All 9 scenarios and the
pinned seeds pass, as before. Wall time 101 s and 104 s (noise; the
machine was running other jobs). `report.md` now has Fidelity, Region and
Robust-pass columns on every row; the gate's tier-2 scenarios get the
tier's default, L0, with no region studied.
