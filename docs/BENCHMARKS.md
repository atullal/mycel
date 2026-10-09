# Benchmarks against external simulators

Mycel's routing code, run against the reference implementations other projects
use, on the same inputs:

- **Store-and-forward** (`crates/mycel-net/src/mesh/dtn.rs`, the real
  `Carrier`) against **The ONE**'s reference routers: Epidemic, PRoPHET,
  binary Spray-and-Wait, MaxProp and Direct Delivery. Both replay the same
  real Bluetooth contact traces and the same message workloads.
- **Local mesh routing** (`crates/mycel-net/src/mesh/core.rs`, the real
  `Router`) against **Meshtastic's managed flooding**, as simulated by
  **Meshtasticator**, on the same topologies and the same direct messages.

Everything here runs on macOS (this Mac: 18 cores, 24 GB). The benchmarks
that need Linux (Shadow, Mininet-WiFi against batman-adv/OLSR/Babel,
CORE/EMANE, quic-network-simulator, libp2p perf) are scripted in
`bench/linux/` but **have not run yet** (see §7).

## Headline

"With fixes" is the experimental carrier with the fixes measured in §6
(`all,spray,evict,inet`, 4 copies). It is **not** in `mesh/dtn.rs` yet. "≤ 1 h" is the share of
*all* messages created that arrived within an hour.

| Trace | Workload | Best ONE router (delivery) | Its ≤ 1 h | Its overhead | Mycel today | Mycel ≤ 1 h | Mycel overhead | Mycel with fixes | Fixes ≤ 1 h |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| cambridge | heavy | MaxProp 9.4 % | 8.8 % | 10.4 | 9.4 % | 5.7 % | 0.2 | 14.7 % | 10.7 % |
| infocom2005 | heavy | MaxProp 20.4 % | 16.8 % | 66.0 | 22.0 % | 7.7 % | 0.4 | 31.7 % | 22.0 % |
| infocom2006 | heavy | MaxProp 38.0 % | 30.0 % | 202.8 | 28.9 % | 16.1 % | 6.0 | 56.8 % | 42.9 % |
| infocom2006-gw | heavy | MaxProp 40.3 % | 33.0 % | 277.0 | 40.9 % | 24.8 % | 7.3 | 58.1 % | 47.7 % |
| helsinki | heavy | MaxProp 47.4 % | 18.9 % | 31.8 | 30.4 % | 8.2 % | 6.1 | 73.1 % | 34.6 % |
| helsinki-gw | heavy | MaxProp 51.2 % | 21.4 % | 35.6 | 31.9 % | 8.7 % | 6.3 | 39.6 % | 25.1 % |
| cambridge | chat | MaxProp 51.5 % | 11.9 % | 6.0 | 45.9 % | 11.1 % | 4.7 | 48.5 % | 11.3 % |
| infocom2005 | chat | MaxProp 84.2 % | 24.6 % | 36.8 | 82.5 % | 23.3 % | 7.2 | 82.5 % | 23.9 % |
| infocom2006 | chat | MaxProp 83.2 % | – | 215.4 | 82.9 % | 44.8 % | 6.2 | – | – |
| infocom2006-gw | chat | SprayAndWait 76.6 % | – | 3.4 | 84.4 % | 51.3 % | 4.0 | – | – |
| helsinki | chat | MaxProp 98.1 % | 98.0 % | 90.4 | 87.7 % | 49.7 % | 17.8 | 91.3 % | 60.7 % |
| helsinki-gw | chat | MaxProp 98.1 % | 98.1 % | 102.1 | 90.7 % | 59.6 % | 12.5 | 92.7 % | 67.1 % |

- **Today, Mycel's carrier is frugal but slow with big messages.**
  - It sends 0.2–18 relays per delivered message. Epidemic, PRoPHET and
    MaxProp send 6–1,343.
  - On the conference traces it delivers about as much as the best ONE
    router. But with 0.5–1 MB messages, fewer arrive within an hour than
    with any ONE router on Cambridge and Helsinki, Direct Delivery
    included. On Infocom 2005 only Epidemic is slower.
  - **Cause:** 95–99% of its transfers on the conference traces are
    refused by full receivers, only after the whole payload has crossed
    the link, and then retried (§6.1).
- **Short contacts (Helsinki) are its worst case.** It matches Direct
  Delivery (§6.2).
- **The fixes, measured on the same inputs:**
  - Four bug fixes (§6.1–6.2), eviction and spray-first (§6.3–6.4).
  - They make Mycel beat the best ONE router on 5 of 6 heavy traces, on
    total delivery and on delivery within an hour.
  - They do it with 2–36× fewer transmissions than MaxProp.
  - The exception is Helsinki-gw: the gradient toward 6 tram gateways
    with 5 MB stores (§6.3).
- **Chat-sized messages.**
  - On Infocom 2005 and 2006, Mycel is within 2 points of MaxProp today,
    at 1/5–1/35 of its overhead. On Cambridge it delivers 46% against
    MaxProp's 51.5%.
  - On Infocom 2006 with gateways it is the best of the routers that
    finished: 84.4% delivered with a 25-minute median, against 76.6% and
    2 hours for Spray-and-Wait. MaxProp didn't finish.
  - On Helsinki it needs a bigger copy budget for small bundles (§6.3).
- **Local routing against Meshtastic's flooding.** Mycel's routes deliver
  98–100% of direct messages, against 39–73% for flooding, with 2–3 data
  transmissions against 6–16. Its announcements don't fit a LoRa channel
  (§4).

## 1. Tools, versions and inputs

| | Version | Notes |
|---|---|---|
| [The ONE](https://github.com/akeranen/the-one) | `c973bfb`, OpenJDK 27 (Homebrew) | Batch mode (`bench/one/one.sh`). MaxProp needs `-Djava.util.Arrays.useLegacyMergeSort=true`: its comparator isn't transitive and Java 7+ TimSort rejects it. |
| [Meshtasticator](https://github.com/GUVWAF/Meshtasticator) | `17ceb82`, Python 3.14.6 venv | Its discrete-event simulator without the GUI (`bench/meshtasticator/run.py`). |
| Mycel | this branch | `bench/mycel-bench`: `dtn-replay`, `mesh-routing`, `route-check`. They link the real `mycel-net` code. |

**Contact traces.** These are real Bluetooth sightings between iMotes carried by people (CRAWDAD
`cambridge/haggle`: Scott, Gass, Crowcroft, Hui, Diot, Chaintreau,
doi:10.15783/C70011). IEEE DataPort needs a login, so `bench/fetch.sh` takes
the unmodified files from the mobemu repository, which redistributes them.
The licence asks users not to re-share them, so they live in the gitignored
`bench/data/` and are never committed.

| Trace | Devices | Contacts | Span | Median contact | Gateways (`-gw` variants) |
|---|---:|---:|---:|---:|---|
| `cambridge`: students in Cambridge (Exp. 2) | 12 | 2,614 | 126.6 h | 117 s | none |
| `infocom2005`: conference (Exp. 3) | 41 | 16,738 | 70.6 h | 60 s | none |
| `infocom2006`: conference (Exp. 6) | 98 | 142,306 | 93.7 h | 60 s | `infocom2006-gw`: the 17 static long-range iMotes have the internet |
| `helsinki`: The ONE's default scenario (pedestrians, cars, trams), captured with `ConnectivityONEReport` | 126 | 31,643 | 12 h | 2.4 s | `helsinki-gw`: the 6 trams have the internet |

Contacts are internal iMotes only (external devices are dropped). The
Helsinki movement is simulated once and then replayed as a trace, so every
router, The ONE's included, sees exactly the same contacts.

**Workloads.** These are generated once by `bench/traces/convert.py workload`, seeded. The
same message list goes to The ONE (as an external events file) and to
Mycel.

| Workload | Messages | Size | TTL | Links | Buffer |
|---|---|---|---|---|---|
| `heavy` | one every 25–35 s between random devices | 500 kB–1 MB | 300 min | 250 kB/s | 5 MB |
| `chat` | one every 25–35 s between random devices | 1–10 kB | 24 h | 250 kB/s | 5 MB |

`heavy` is The ONE's `default_settings.txt` workload, its standard
benchmark. `chat` is closer to what Mycel carries: chat-sized messages
that have a day to arrive. Spray-and-Wait uses L = 4 copies, the same as
Mycel's default (The ONE's default is 6). PRoPHET uses The ONE's
parameters with a 30 s time unit.

**How Mycel is driven** (`bench/mycel-bench/src/dtn_replay.rs`): the real
`Carrier` runs, and the harness around it models what The ONE's
`ActiveRouter` does.
- **Links:** a contact is a 250 kB/s link. A device takes part in one
  transfer at a time. A transfer finishes after `size / speed` if the
  contact lasts that long, otherwise it is aborted.
  - Completion is applied at its exact time, before a contact that ends
    later goes down. The ONE also updates every host at every event.
  - The first round of results applied completions only at the next
    1-second step. That aborted 40 ms chat transfers on 2-second contacts:
    9,620 spurious aborts on Helsinki chat. It cost Mycel 4 points of
    delivery on Helsinki heavy and 870 s of median latency on Helsinki
    chat. All numbers here are from after that fix.
- **Timing:** the carrier plans every second, as the real driver does
  (`DTN_EVERY`). Summaries go out when a contact comes up and every 5 s
  after that.
- **Live routes:** these come from a breadth-first search over the contacts
  that are up now. `route-check` runs the real `Router` on the same traces
  to check that shortcut. On 30 minutes of Infocom 2006, whenever a
  multi-hop path existed, the router followed a working route 94.1% of the
  time, so the shortcut slightly flatters Mycel. On Helsinki it was 71%,
  but multi-hop paths existed only 160 times there.

Differences that matter when reading the tables:
- **Full buffers.** The ONE's buffers drop the oldest messages when full,
  including the sender's own. Mycel's carrier refuses new bundles instead,
  so strangers can't push others' data out. It also keeps its own
  messages for their whole lifetime.
- **Bundle size.** Mycel's real maximum is 256 KiB, and the node splits
  bigger data. The replay raises it to 4 MiB so that one message is one
  bundle, as in The ONE.

## 2. Running it

```sh
bench/fetch.sh                          # tools + traces (once)
bench/one/one.sh build                  # compile The ONE (once)
cargo build --release -p mycel-bench
bench/run.py                            # every trace × workload, both sides; skips finished runs
bench/run.py --routers mycel --force    # Mycel only, all traces: after changing mesh/dtn.rs
bench/run.py --only helsinki --workloads heavy --routers mycel --force   # one case
bench/run.py --summary-only             # rebuild bench/results/summary.{md,csv}
bench/ablation.py                       # the carrier fixes of §6, one at a time
bench/external/venv/bin/python bench/meshtasticator/run.py   # Meshtasticator sweep
./target/release/mesh-routing bench/results/meshtasticator/dm-*.json > bench/results/meshtasticator/mycel-routing.csv
python3 bench/meshtasticator/report.py
```

`run.py` resumes a killed ONE batch: only routers without a finished report
run again. On this Mac every run takes seconds to minutes except Infocom
2006 with `chat`, where The ONE takes much longer:
- Epidemic: about 30 min.
- PRoPHET: about 20 min.
- MaxProp: 73 min, and more than 2 h 23 min with gateways (not
  finished).

Mycel's replay of the same runs takes 11–25 min.

## 3. Results: store-and-forward on real contact traces

Bold rows are Mycel's carrier as it is on this branch. "Overhead" is The
ONE's ratio, (relayed − delivered) / delivered. Latency is over delivered
messages only.

**Heavy workload** (500 kB–1 MB, TTL 300 min)

| Scenario | Router | Delivered | Latency avg (s) | Latency median (s) | Overhead | Hops avg |
|---|---|---:|---:|---:|---:|---:|
| cambridge | Epidemic | 6.4 % | 320 | 30 | 48.55 | 2.26 |
| cambridge | Prophet | 7.9 % | 293 | 38 | 34.97 | 1.70 |
| cambridge | SprayAndWait | 8.8 % | 196 | 9 | 7.07 | 1.57 |
| cambridge | MaxProp | 9.4 % | 837 | 14 | 10.41 | 1.76 |
| cambridge | DirectDelivery | 7.2 % | 354 | 38 | 0.00 | 1.00 |
| cambridge | **Mycel** | 9.4 % | 4499 | 1395 | 0.19 | 1.15 |
| infocom2005 | Epidemic | 7.6 % | 1669 | 415 | 247.28 | 5.03 |
| infocom2005 | Prophet | 12.1 % | 2032 | 864 | 165.23 | 2.88 |
| infocom2005 | SprayAndWait | 16.9 % | 1272 | 494 | 8.71 | 1.92 |
| infocom2005 | MaxProp | 20.4 % | 2045 | 435 | 66.04 | 3.33 |
| infocom2005 | DirectDelivery | 16.7 % | 2809 | 1953 | 0.00 | 1.00 |
| infocom2005 | **Mycel** | 22.0 % | 7148 | 6370 | 0.43 | 1.17 |
| infocom2006 | Epidemic | 8.7 % | 2227 | 499 | 1116.39 | 7.75 |
| infocom2006 | Prophet | 18.5 % | 4104 | 1938 | 529.20 | 3.55 |
| infocom2006 | SprayAndWait | 25.9 % | 2290 | 858 | 8.94 | 1.98 |
| infocom2006 | MaxProp | 38.0 % | 2351 | 312 | 202.77 | 4.33 |
| infocom2006 | DirectDelivery | 20.2 % | 5093 | 3625 | 0.00 | 1.00 |
| infocom2006 | **Mycel** | 28.9 % | 5066 | 2339 | 5.98 | 3.57 |
| infocom2006-gw | Epidemic | 10.8 % | 2307 | 357 | 1343.12 | 6.40 |
| infocom2006-gw | Prophet | 18.4 % | 3430 | 1108 | 758.99 | 3.07 |
| infocom2006-gw | SprayAndWait | 31.0 % | 2175 | 554 | 7.50 | 1.92 |
| infocom2006-gw | MaxProp | 40.3 % | 2092 | 234 | 276.98 | 3.92 |
| infocom2006-gw | DirectDelivery | 22.7 % | 4507 | 2618 | 0.00 | 1.00 |
| infocom2006-gw | **Mycel** | 40.8 % | 4481 | 1533 | 7.25 | 4.42 |
| helsinki | Epidemic | 20.1 % | 3221 | 2417 | 98.75 | 4.39 |
| helsinki | Prophet | 21.6 % | 3864 | 2861 | 70.58 | 2.96 |
| helsinki | SprayAndWait | 44.5 % | 3012 | 2452 | 6.57 | 1.98 |
| helsinki | MaxProp | 47.4 % | 5927 | 4662 | 31.80 | 1.69 |
| helsinki | DirectDelivery | 31.7 % | 6586 | 5713 | 0.00 | 1.00 |
| helsinki | **Mycel** | 30.4 % | 7617 | 6891 | 6.08 | 1.75 |
| helsinki-gw | Epidemic | 18.7 % | 3245 | 2596 | 189.78 | 4.82 |
| helsinki-gw | Prophet | 22.4 % | 3839 | 2850 | 131.00 | 3.54 |
| helsinki-gw | SprayAndWait | 46.1 % | 3028 | 2466 | 6.37 | 1.98 |
| helsinki-gw | MaxProp | 51.2 % | 5748 | 4527 | 35.64 | 1.76 |
| helsinki-gw | DirectDelivery | 31.9 % | 6544 | 5666 | 0.00 | 1.00 |
| helsinki-gw | **Mycel** | 31.9 % | 7709 | 7272 | 6.32 | 1.69 |

**Chat workload** (1–10 kB, TTL 24 h)

| Scenario | Router | Delivered | Latency avg (s) | Latency median (s) | Overhead | Hops avg |
|---|---|---:|---:|---:|---:|---:|
| cambridge | Epidemic | 44.4 % | 30238 | 26302 | 29.37 | 2.96 |
| cambridge | Prophet | 44.5 % | 28729 | 24598 | 21.05 | 2.23 |
| cambridge | SprayAndWait | 45.3 % | 29274 | 25438 | 3.37 | 1.79 |
| cambridge | MaxProp | 51.5 % | 30009 | 26723 | 6.02 | 2.34 |
| cambridge | DirectDelivery | 33.8 % | 29458 | 25956 | 0.00 | 1.00 |
| cambridge | **Mycel** | 45.9 % | 29798 | 26501 | 4.69 | 2.43 |
| infocom2005 | Epidemic | 72.5 % | 24863 | 21303 | 145.25 | 3.61 |
| infocom2005 | Prophet | 68.5 % | 22207 | 17712 | 144.78 | 2.69 |
| infocom2005 | SprayAndWait | 81.0 % | 22966 | 18020 | 3.19 | 1.99 |
| infocom2005 | MaxProp | 84.2 % | 21379 | 16543 | 36.83 | 3.44 |
| infocom2005 | DirectDelivery | 68.3 % | 26974 | 22954 | 0.00 | 1.00 |
| infocom2005 | **Mycel** | 82.5 % | 22320 | 17393 | 7.19 | 3.90 |
| infocom2006 | Epidemic | 64.1 % | 18881 | 12729 | 678.02 | 5.38 |
| infocom2006 | Prophet | 65.7 % | 15019 | 7769 | 601.98 | 3.47 |
| infocom2006 | SprayAndWait | 74.3 % | 17050 | 8733 | 3.54 | 2.08 |
| infocom2006 | MaxProp | 83.2 % | 8830 | 2751 | 215.40 | 5.04 |
| infocom2006 | DirectDelivery | 51.5 % | 27721 | 22743 | 0.00 | 1.00 |
| infocom2006 | **Mycel** | 82.9 % | 8898 | 2661 | 6.24 | 4.35 |
| infocom2006-gw | Epidemic | 63.7 % | 17969 | 12068 | 833.47 | 4.79 |
| infocom2006-gw | Prophet | 65.4 % | 14474 | 6793 | 701.60 | 3.34 |
| infocom2006-gw | SprayAndWait | 76.6 % | 15819 | 7169 | 3.37 | 2.04 |
| infocom2006-gw | DirectDelivery | 54.0 % | 26338 | 20466 | 0.00 | 1.00 |
| infocom2006-gw | **Mycel** | 84.4 % | 6820 | 1478 | 4.02 | 3.93 |
| helsinki | Epidemic | 87.8 % | 1652 | 1191 | 182.80 | 3.69 |
| helsinki | Prophet | 90.4 % | 1866 | 1579 | 155.60 | 2.67 |
| helsinki | SprayAndWait | 91.9 % | 3411 | 2214 | 3.22 | 2.02 |
| helsinki | MaxProp | 98.1 % | 972 | 855 | 90.43 | 3.97 |
| helsinki | DirectDelivery | 63.3 % | 8028 | 5383 | 0.00 | 1.00 |
| helsinki | **Mycel** | 87.7 % | 4388 | 3116 | 17.82 | 5.02 |
| helsinki-gw | Epidemic | 87.5 % | 1587 | 1133 | 251.90 | 3.87 |
| helsinki-gw | Prophet | 89.6 % | 1851 | 1528 | 222.11 | 2.86 |
| helsinki-gw | SprayAndWait | 92.0 % | 3366 | 2185 | 3.21 | 2.03 |
| helsinki-gw | MaxProp | 98.1 % | 930 | 805 | 102.13 | 4.24 |
| helsinki-gw | DirectDelivery | 63.3 % | 8027 | 5383 | 0.00 | 1.00 |
| helsinki-gw | **Mycel** | 90.7 % | 3755 | 2548 | 12.54 | 4.50 |

- Infocom 2006 chat with gateways has no MaxProp row: it hadn't finished
  after 2 h 23 min, so it was stopped. The same run without gateways took
  73 min.
- The ONE's PRoPHET and MaxProp vary by up to about a point between
  identical runs (MaxProp on Infocom 2006 heavy: 38.8%, then 38.0%). Its
  other routers and Mycel are deterministic.

**Latency over delivered messages flatters routers that drop messages.**
In `heavy`, a 5 MB buffer holds 5–10 messages. The ONE's routers drop the
oldest when full, so the only messages they deliver are the ones whose
destination turned up soon after. Mycel's medians count messages that
waited hours and still arrived. The fair comparison is the share of *all*
created messages delivered within a time:

| Scenario | Workload | Router | ≤ 1 min | ≤ 10 min | ≤ 1 h |
|---|---|---|---:|---:|---:|
| cambridge | heavy | Epidemic | 3.8 % | 5.5 % | 6.4 % |
| cambridge | heavy | Prophet | 4.4 % | 6.6 % | 7.9 % |
| cambridge | heavy | SprayAndWait | 5.5 % | 7.9 % | 8.8 % |
| cambridge | heavy | MaxProp | 5.8 % | 7.8 % | 8.8 % |
| cambridge | heavy | DirectDelivery | 3.8 % | 5.8 % | 7.2 % |
| cambridge | heavy | **Mycel** | 2.9 % | 4.0 % | 5.7 % |
| cambridge | chat | Epidemic | 4.3 % | 6.4 % | 10.1 % |
| cambridge | chat | Prophet | 4.2 % | 7.0 % | 10.9 % |
| cambridge | chat | SprayAndWait | 5.5 % | 7.7 % | 11.2 % |
| cambridge | chat | MaxProp | 5.8 % | 8.4 % | 11.9 % |
| cambridge | chat | DirectDelivery | 3.8 % | 5.8 % | 8.2 % |
| cambridge | chat | **Mycel** | 5.9 % | 8.2 % | 11.1 % |
| infocom2005 | heavy | Epidemic | 1.9 % | 4.2 % | 6.4 % |
| infocom2005 | heavy | Prophet | 2.2 % | 5.5 % | 9.6 % |
| infocom2005 | heavy | SprayAndWait | 4.3 % | 9.0 % | 15.2 % |
| infocom2005 | heavy | MaxProp | 4.9 % | 11.1 % | 16.8 % |
| infocom2005 | heavy | DirectDelivery | 2.1 % | 4.8 % | 11.3 % |
| infocom2005 | heavy | **Mycel** | 1.6 % | 3.1 % | 7.7 % |
| infocom2005 | chat | Epidemic | 2.1 % | 4.8 % | 13.6 % |
| infocom2005 | chat | Prophet | 2.4 % | 6.2 % | 16.9 % |
| infocom2005 | chat | SprayAndWait | 4.9 % | 9.5 % | 20.6 % |
| infocom2005 | chat | MaxProp | 6.9 % | 13.7 % | 24.6 % |
| infocom2005 | chat | DirectDelivery | 2.5 % | 5.0 % | 12.0 % |
| infocom2005 | chat | **Mycel** | 7.6 % | 13.2 % | 23.3 % |
| infocom2006 | heavy | Epidemic | 1.6 % | 4.6 % | 6.9 % |
| infocom2006 | heavy | Prophet | 1.8 % | 5.8 % | 11.3 % |
| infocom2006 | heavy | SprayAndWait | 5.4 % | 11.4 % | 20.4 % |
| infocom2006 | heavy | MaxProp | 7.3 % | 22.4 % | 30.0 % |
| infocom2006 | heavy | DirectDelivery | 2.1 % | 5.0 % | 10.1 % |
| infocom2006 | heavy | **Mycel** | 6.8 % | 10.9 % | 16.1 % |
| infocom2006 | chat | **Mycel** | 20.6 % | 30.3 % | 44.8 % |
| infocom2006-gw | heavy | Epidemic | 2.7 % | 6.2 % | 8.7 % |
| infocom2006-gw | heavy | Prophet | 3.1 % | 7.7 % | 12.5 % |
| infocom2006-gw | heavy | SprayAndWait | 9.6 % | 15.9 % | 24.6 % |
| infocom2006-gw | heavy | MaxProp | 9.1 % | 25.6 % | 33.0 % |
| infocom2006-gw | heavy | DirectDelivery | 4.8 % | 7.6 % | 12.6 % |
| infocom2006-gw | heavy | **Mycel** | 10.1 % | 16.8 % | 24.8 % |
| infocom2006-gw | chat | DirectDelivery | 5.2 % | 8.2 % | 13.4 % |
| infocom2006-gw | chat | **Mycel** | 25.5 % | 35.5 % | 51.3 % |
| helsinki | heavy | Epidemic | 0.1 % | 1.7 % | 13.0 % |
| helsinki | heavy | Prophet | 0.1 % | 2.2 % | 12.4 % |
| helsinki | heavy | SprayAndWait | 0.1 % | 3.4 % | 30.5 % |
| helsinki | heavy | MaxProp | 0.1 % | 1.9 % | 18.9 % |
| helsinki | heavy | DirectDelivery | 0.1 % | 1.9 % | 11.6 % |
| helsinki | heavy | **Mycel** | 0.0 % | 0.6 % | 8.2 % |
| helsinki | chat | Epidemic | 0.6 % | 15.8 % | 79.6 % |
| helsinki | chat | Prophet | 0.6 % | 12.4 % | 81.1 % |
| helsinki | chat | SprayAndWait | 0.8 % | 14.7 % | 62.2 % |
| helsinki | chat | MaxProp | 0.8 % | 28.0 % | 98.0 % |
| helsinki | chat | DirectDelivery | 0.4 % | 5.1 % | 24.2 % |
| helsinki | chat | **Mycel** | 0.5 % | 7.3 % | 49.7 % |
| helsinki-gw | heavy | Epidemic | 0.1 % | 2.0 % | 11.7 % |
| helsinki-gw | heavy | Prophet | 0.3 % | 2.4 % | 13.1 % |
| helsinki-gw | heavy | SprayAndWait | 0.6 % | 4.2 % | 31.3 % |
| helsinki-gw | heavy | MaxProp | 0.5 % | 2.6 % | 21.4 % |
| helsinki-gw | heavy | DirectDelivery | 0.3 % | 2.1 % | 11.9 % |
| helsinki-gw | heavy | **Mycel** | 0.3 % | 1.1 % | 8.7 % |
| helsinki-gw | chat | Epidemic | 1.2 % | 19.1 % | 79.4 % |
| helsinki-gw | chat | Prophet | 0.9 % | 13.4 % | 81.1 % |
| helsinki-gw | chat | SprayAndWait | 1.3 % | 15.4 % | 62.7 % |
| helsinki-gw | chat | MaxProp | 1.5 % | 31.6 % | 98.1 % |
| helsinki-gw | chat | DirectDelivery | 0.6 % | 5.1 % | 24.2 % |
| helsinki-gw | chat | **Mycel** | 0.8 % | 10.2 % | 59.6 % |

The ONE's chat runs on Infocom 2006 predate the per-message report, so
only Mycel (and Direct Delivery with gateways) have rows there.

## 4. Results: local mesh routing against Meshtastic's flooding

`bench/meshtasticator/run.py` runs Meshtasticator's discrete-event simulator
headless. It uses LONG_FAST and 3GPP suburban path loss over 15 × 15 km,
with 40-byte payloads, a message per node every 100 s on average, and 30
minutes per run. Node movement and asymmetric links are off, so the graph
stays fixed. Each setting runs 3 times, with batchSim.py's seeded
placement. Each run's topology and direct messages are dumped, and
`mesh-routing` runs Mycel's real `Router` on the same graph and the same
messages: it sends signed announcements, builds route tables and forwards
hop by hop.

**Meshtastic managed flooding, broadcasts (Meshtasticator)**

| Nodes | Hop limit | Reach | Usefulness | Transmissions per message |
|---:|---:|---:|---:|---:|
| 10 | 1 | 57 % | 59 % | 2.7 |
| 10 | 3 | 75 % | 52 % | 4.3 |
| 10 | 5 | 79 % | 50 % | 4.9 |
| 10 | 7 | 77 % | 50 % | 4.8 |
| 25 | 1 | 43 % | 56 % | 3.4 |
| 25 | 3 | 58 % | 45 % | 6.4 |
| 25 | 5 | 61 % | 41 % | 7.8 |
| 25 | 7 | 62 % | 41 % | 8.2 |
| 50 | 1 | 31 % | 53 % | 3.8 |
| 50 | 3 | 37 % | 41 % | 7.1 |
| 50 | 5 | 37 % | 39 % | 8.2 |
| 50 | 7 | 38 % | 38 % | 8.7 |

**Direct messages: Meshtastic (hop limit 3) vs Mycel's router, same topologies and messages**

| Nodes | Links | Meshtastic delivered | Meshtastic tx per delivered | Mycel delivered | Mycel data tx per delivered | Mycel announcements per node per min | Mycel control traffic per node | Announcement airtime on LoRa LongFast |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 17 | 73 % | 5.7 | 100.0 % | 2.0 | 150 | 9 kbit/s | 723 % of the channel |
| 25 | 81 | 58 % | 10.2 | 99.9 % | 2.2 | 242 | 27 kbit/s | 1166 % of the channel |
| 50 | 239 | 39 % | 16.2 | 97.9 % | 2.9 | 284 | 50 kbit/s | 1366 % of the channel |

- **Broadcasts.** Meshtasticator's flooding reproduces Meshtastic's
  published shape: reach rises with the hop limit and levels off around
  3–5, while usefulness (the share of rebroadcasts that reach someone new)
  falls.
- **Direct messages.** Flooding delivers 39–73% with 6–16 transmissions per
  delivered message. Mycel's routes deliver 98–100% with 2–3 data
  transmissions per message.
- **The cost.** That gain comes from Mycel's proactive announcements. On a
  LoRa channel they would need 7–14× more airtime than the channel has.
  `mesh-routing` models reliable links without collisions or airtime, which
  flatters Mycel on LoRa. On Mycel's own radios the same control traffic
  (9–50 kbit/s per device, at 10–50 devices) is small on Wi-Fi. On a BLE
  link of ~300 kbit/s it is a noticeable share. **Mycel's mesh as designed
  does not fit LoRa-class radios.** On them, flooding with a hop limit, as Meshtastic
  does, is the right design.

## 5. What it shows

- **Frugal.** At 0.2–18 relays per delivered message (overhead), Mycel's
  carrier comes close to routers that send 5–35× more:
  - Infocom 2006 chat: 82.9% at overhead 6, against MaxProp's 83.2% at
    215.
  - Infocom 2005 chat: 82.5% at 7, against MaxProp's 84.2% at 37.
- **Gateways help Mycel and barely help The ONE's routers.** Adding the
  17 static gateways to Infocom 2006:
  - heavy: Mycel goes from 28.9% to 40.8%; MaxProp from 38.0% to 40.3%;
  - chat: Mycel's median falls from 2,661 s to 1,478 s.

  The ONE's routers don't know those devices have the internet. Mycel's
  default route and internet gradient do.
- **Live routes are what the router really does.** On Infocom 2006,
  `route-check` shows the real `Router` following a working multi-hop
  route 94.1% of the time one exists. Those hops count in the delivered
  messages' hop counts: 3.6–4.4 on Infocom 2006, against 1.0–2.1 for
  Direct Delivery and Spray-and-Wait.
- **Local mesh routing** delivers 98–100% of direct messages on
  Meshtasticator's topologies, against 39–73% for managed flooding (§4).

## 6. Where Mycel loses, why, and the fix

Every fix below was measured, not just proposed. `bench/mycel-bench/src/carrier_fixed.rs`
is a copy of the real carrier with each fix behind a switch, and
`bench/ablation.py` runs the switches one at a time on the same traces.
With all switches off, the copy reproduces the real carrier's numbers
exactly (checked on every trace). Nothing in `crates/mycel-net` has been
changed yet.

### 6.1 Big messages: refusals livelock the links (the heavy workload)

**Symptom.** With 500 kB–1 MB messages, Mycel delivers about as many
messages as the best ONE router, but far later:

| Heavy workload | Mycel median | ONE routers' medians | Delivered within 1 h (all messages) |
|---|---:|---:|---|
| Cambridge | 1,395 s | 9–38 s | Mycel 5.7%; every ONE router 6.4–8.8%, Direct Delivery included |
| Infocom 2005 | 6,370 s | 415–1,953 s | Mycel 7.7%; ONE routers 6.4–16.8% |

**Evidence.** Almost every transfer Mycel starts is refused by the
receiver after it has crossed the link:

| | Transfers started | Refused ("store full") | Accepted by a carrier |
|---|---:|---:|---:|
| Cambridge, heavy | 155,359 | 152,573 (98%) | 271 |
| Infocom 2005, heavy | 443,137 | 437,303 (99%) | 742 |
| Infocom 2006, heavy | 1,377,615 | 1,344,330 (98%) | 18,782 |
| Infocom 2006 with gateways, heavy | 891,870 | 848,249 (95%) | 32,749 |

**Causes**, all in `mesh/dtn.rs` plus the driver in `mesh/mod.rs`:
1. **The refusal comes only after the whole payload has been sent.** The
   driver sends the whole bundle (`send_bundle`), the receiver reads
   it to the end (`on_bundle_stream`) and only then calls `accept`. Each
   refusal costs a full 2–4 s transfer of link time, and keeps both
   devices busy so they can't deliver anything else.
2. **The same refused bundle is sent again a second later.** `transferred(ok
   = false)` clears `in_flight`, and nothing remembers that the neighbour
   is full. The result is a livelock: the link spends its time carrying
   bundles that will be refused.
3. **The neighbour is full because of its own messages.** `store` adds a
   device's own bundles to `used` (the space it lends to others) without
   any check. They stay there for their whole lifetime, so a device with a
   backlog of its own messages refuses everyone else's, permanently.
4. **Lifetimes restart at every hop.** `store` sets `until = now +
   lifetime`, not `created + lifetime`. Stale bundles keep using space,
   and the real node then refuses them at the next hop
   (`verify_bundle` checks `created + lifetime > wall_ms()`), again after
   the whole transfer. In the replay this shows up as deliveries after the
   TTL.

**Fixes**, as switches in `carrier_fixed.rs`:
- **`free`** (causes 1 and 2): summaries say how much room is left. The
  planner doesn't send to a neighbour without room for the bundle, unless
  that neighbour is the destination. A refusal marks the neighbour as full
  until its next summary. In `mesh/mod.rs` the same idea becomes an offer
  before the payload: send (id, size, copies, expiry) and wait for
  accept or refuse. BPv7 custody signalling does the same.
- **`own`** (cause 3): a device's own bundles use their own quota, not the
  space it lends to others.
- **`expiry`** (cause 4): a carrier expires a bundle at `created + lifetime`.
  On the real node that means converting through `wall_ms()`, with a bound
  on clock skew, or using a BPv7 Bundle Age block, which needs no clocks.
- **`resume`**: an interrupted transfer keeps the bytes that arrived, and
  the next attempt to the same device sends only the rest. Mycel's file
  transfers already work this way (`.part` + `.ranges`), and BPv7 calls it
  reactive fragmentation. Splitting bundles at 256 KiB, as the real node
  does, gets part of the benefit.

### 6.2 Short contacts: Helsinki

**Symptom.** Helsinki is pedestrians, cars and trams. Its median contact
lasts 2.4 s, and 73% of contacts are shorter than the 4 s a 1 MB bundle
needs at 250 kB/s. On the heavy workload Mycel delivers 30.4%, against
44.5% for Spray-and-Wait and 47.4% for MaxProp. Direct Delivery manages
31.7% by doing nothing, so Mycel is no better than not routing at all.

**Evidence.**
- 57% of Mycel's transfers are aborted when the contact ends (22,699 of
  39,773), and 35% are refused (13,974).
- Spray-and-Wait starts 14,086 transfers in total.
- Almost all of Mycel's transfers (38,018) follow the predictability
  gradient. That gradient means little in movement without social
  structure (§6.3).

**Causes and fixes.** The refusal livelock of §6.1 accounts for part of the
gap: `free` alone takes delivery to 45.2%. Lost progress on cut transfers
accounts for the rest: `resume` alone takes it to 43.3%. With all four
fixes Mycel delivers 66.3%, against 47.4% for the best ONE router.
- The ONE's routers can't resume, so `resume` is an advantage they don't
  have. Without it, `own,free,expiry` reaches 49.5%, still above MaxProp.

### 6.3 Copies don't spread, and the destination gradient wanders

**Symptom.** On Helsinki, Mycel is slower than Spray-and-Wait. Even with
all four fixes, 15% of heavy messages arrive within an hour, against
30.5%. With chat-sized messages the median is 3,116 s, against 2,214 s
for Spray-and-Wait, at 5× the transmissions (overhead 17.8 vs 3.2).

**Evidence.** On Helsinki chat, Mycel made 68 spray transfers and 22,461
gradient transfers. The carrier sprays only when its utility for the
destination is exactly zero (`mine == 0.0`). After a few encounters, the
transitive PRoPHET update (β = 0.9) gives nearly every device some
predictability for nearly every destination, so Spray-and-Wait almost
never runs.
- The 4 copies go only to "better" neighbours.
- Single copies move with custody along a gradient that, in random
  movement, doesn't point anywhere.
- The `nograd` diagnostic (spray-first, no gradient at all) brings
  Helsinki chat to 2,272 s at overhead 3.3, the same as Spray-and-Wait.

**Fixes.**
- **`spray`**: while a bundle has more than one copy, hand half of them to
  the most useful neighbour that lacks it, whether or not it is better
  than us. The gradient then moves single copies only.
- `fallback`, which sprays only when no neighbour is clearly better, is
  within 2.5 points of `spray` on every trace.
- **`inet`**: the single-copy gradient follows predictability for the
  internet only, not for the destination. The internet is the gradient's
  purpose in ROUTING.md §7.2. Without gateways, `inet` is the same as no
  gradient.

**It depends on movement, and on `evict` (§6.4).**
- On Infocom 2006 (98 people with social structure), `spray` without
  `evict` *hurts*: delivery falls from 51.1% to 46.6%, and from 30.3% to
  26.8% within an hour. Copies sprayed into full stores crowd out the
  gradient's better choices.
- With `evict`, the difference disappears: 55.6% for `all,evict`
  against 54.4% for `all,spray,evict`, both 43% within an hour.
- On Helsinki, spray-first plus `inet` is what closes the gap: 73.1%
  delivered and 34.6% within 1 h, against 44.5% and 30.5% for
  Spray-and-Wait.

**Open question: the gradient toward the internet.**
- On Helsinki-gw, 6 trams with 5 MB stores are the only gateways.
  Climbing toward them funnels heavy bundles into tiny stores: 39.6%
  delivered with `inet`, against 63.4% with no gradient.
- With chat-sized bundles the same gradient helps: 67.1% within 1 h,
  against 65.5% with no gradient.
- Real gateways have 64 MiB stores and real uplinks, so this bench is
  the worst case. The SIM agent's partition and disaster scenarios, where
  the gradient is meant to pay off, should settle it before it changes.

**Chat needs more copies.** On Helsinki chat, MaxProp delivers 98% within
an hour by copying everywhere, at overhead 90. Four copies cap Mycel at
61%. Small bundles are cheap to copy, so the copy budget should depend on
size. `all,spray,evict,inet` with `--copies`:

| Helsinki chat | Delivered | ≤ 10 min | ≤ 1 h | Overhead |
|---|---:|---:|---:|---:|
| 4 copies (today's default) | 91.3 % | 13.9 % | 60.7 % | 3.3 |
| 8 | 95.3 % | 17.4 % | 79.4 % | 7.1 |
| 16 | 96.5 % | 20.4 % | 89.5 % | 14.3 |
| 32 | 97.2 % | 18.5 % | 94.7 % | 26.3 |
| MaxProp | 98.1 % | 28.0 % | 98.0 % | 90.4 |
| Epidemic | 87.8 % | 15.8 % | 79.6 % | 182.8 |

On the conference traces more copies don't help. Infocom 2005 gains 1
point at 32 copies. Cambridge, whose 12 devices share small stores, loses
3 points.
A budget such as 32 copies for bundles of 16 KiB or less, falling to 4 at
256 KiB, gives chat MaxProp-like speed at a third of its overhead.

To reproduce one row:

```sh
./target/release/dtn-replay --contacts bench/traces/out/helsinki.csv \
  --messages bench/traces/out/helsinki-chat-msgs.csv --ttl-min 1440 \
  --carrier fixed --fixes all,spray,evict,inet --copies 32 --latencies /tmp/lat.csv
```

### 6.4 Speed versus completeness when stores fill

**Symptom.** With the fixes above, Mycel delivers far more in total, but
fresh messages still arrive later than with the best ONE router. On
Infocom 2005 heavy with `all`, 15.3% arrive within an hour, against
16.8% for MaxProp.

**Cause.** A full Mycel store refuses new bundles and keeps old ones until
they expire. The ONE's routers drop their oldest message to take a new one,
which favours messages young enough to still arrive soon.

**Fix: `evict`.** When the store is full, drop the carried bundles that
expire soonest, never one of the device's own, to make room for one that
expires later. If its source is over its share, its own older bundles go
first.
- For senders to avoid sending what would be refused, a summary also
  lists the receiver's soonest-expiring carried bundles (expiry, size; up
  to 32).
- Two earlier versions of this switch brought back tens of thousands of
  refusals (87,000 on Cambridge). One checked the per-source share before
  evicting; the other advertised all carried bytes as room. `refused_by`
  in the replay output is how that showed up.

**Effect.** On the conference traces `evict` is the biggest speed gain:

| Trace | Within 1 h, `all` → `all,evict` | Best ONE router |
|---|---|---|
| Infocom 2005 | 15.3% → 21.7% | 16.8% |
| Infocom 2006 | 30.3% → 43.0% | 30.0% |

It costs total delivery wherever stores overflow:
- Cambridge: 16.4% → 14.5%
- Infocom 2005: 35.8% → 29.9%
- Helsinki without spray-first: 66.3% → 49.3%

That trade is a policy choice. Fresh-first suits chat, keep-everything
suits files, so it could be a per-bundle class.

### 6.5 Results of the fixes

Heavy workload, every trace. "Best ONE" rows are The ONE's best router by
total delivery and, where different, by delivery within an hour. Mycel
rows add fixes cumulatively. `all` = `own,free,expiry,resume`. The full
grid, chat included, is in `bench/results/ablation/ablation.md`.

| Trace | Router or Mycel variant | Delivered | ≤ 1 min | ≤ 10 min | ≤ 1 h | Overhead | Refused |
|---|---|---:|---:|---:|---:|---:|---:|
| cambridge | best ONE by delivery: MaxProp | 9.4 % | 5.8 % | 7.8 % | 8.8 % | 10.4 | – |
| cambridge | best ONE within 1 h: SprayAndWait | 8.8 % | 5.5 % | 7.9 % | 8.8 % | 7.1 | – |
| cambridge | Mycel today | 9.4 % | 2.9 % | 4.0 % | 5.7 % | 0.2 | 152,573 |
| cambridge | Mycel + own, free, expiry | 16.3 % | 4.6 % | 6.5 % | 9.3 % | 1.7 | 451 |
| cambridge | Mycel + resume (= all) | 16.4 % | 4.6 % | 6.5 % | 9.4 % | 1.7 | 470 |
| cambridge | Mycel all + evict | 14.5 % | 5.8 % | 8.3 % | 10.8 % | 4.4 | 275 |
| cambridge | Mycel all + spray + evict | 14.2 % | 5.9 % | 8.5 % | 10.6 % | 5.7 | 240 |
| cambridge | Mycel all + spray + evict + inet | 14.7 % | 5.9 % | 8.4 % | 10.7 % | 5.2 | 220 |
| cambridge | Mycel all + spray + evict, no gradient | 14.7 % | 5.8 % | 8.4 % | 10.7 % | 5.2 | 217 |
| infocom2005 | best ONE by delivery: MaxProp | 20.4 % | 4.9 % | 11.1 % | 16.8 % | 66.0 | – |
| infocom2005 | Mycel today | 22.0 % | 1.6 % | 3.1 % | 7.7 % | 0.4 | 437,303 |
| infocom2005 | Mycel + own, free, expiry | 35.8 % | 3.0 % | 6.5 % | 15.1 % | 3.3 | 1,952 |
| infocom2005 | Mycel + resume (= all) | 35.8 % | 3.1 % | 6.6 % | 15.3 % | 3.2 | 1,891 |
| infocom2005 | Mycel all + evict | 29.9 % | 6.7 % | 13.0 % | 21.7 % | 7.3 | 294 |
| infocom2005 | Mycel all + spray + evict | 28.4 % | 6.8 % | 13.7 % | 21.7 % | 9.5 | 315 |
| infocom2005 | Mycel all + spray + evict + inet | 31.7 % | 6.8 % | 13.3 % | 22.0 % | 7.4 | 266 |
| infocom2005 | Mycel all + spray + evict, no gradient | 31.6 % | 6.8 % | 13.3 % | 22.1 % | 7.5 | 268 |
| infocom2006 | best ONE by delivery: MaxProp | 38.1 % | 7.3 % | 22.4 % | 30.0 % | 202.8 | – |
| infocom2006 | Mycel today | 28.9 % | 6.8 % | 10.9 % | 16.1 % | 6.0 | 1,344,330 |
| infocom2006 | Mycel + own, free, expiry | 51.2 % | 14.8 % | 22.0 % | 30.3 % | 6.4 | 3,883 |
| infocom2006 | Mycel + resume (= all) | 51.1 % | 14.9 % | 22.1 % | 30.3 % | 6.3 | 3,846 |
| infocom2006 | Mycel all + evict | 55.6 % | 19.4 % | 29.6 % | 43.0 % | 6.7 | 798 |
| infocom2006 | Mycel all + spray + evict | 54.4 % | 19.6 % | 30.2 % | 43.1 % | 8.7 | 857 |
| infocom2006 | Mycel all + spray + evict + inet | 56.8 % | 19.5 % | 29.9 % | 42.9 % | 7.6 | 568 |
| infocom2006-gw | best ONE by delivery: MaxProp | 40.3 % | 9.1 % | 25.6 % | 33.0 % | 277.0 | – |
| infocom2006-gw | Mycel today | 40.9 % | 10.1 % | 16.8 % | 24.8 % | 7.3 | 848,249 |
| infocom2006-gw | Mycel + own, free, expiry | 57.6 % | 16.9 % | 24.9 % | 35.2 % | 5.6 | 2,690 |
| infocom2006-gw | Mycel + resume (= all) | 57.4 % | 16.9 % | 24.9 % | 35.1 % | 5.6 | 2,782 |
| infocom2006-gw | Mycel all + evict | 58.0 % | 25.3 % | 35.1 % | 47.9 % | 4.4 | 267 |
| infocom2006-gw | Mycel all + spray + evict | 57.8 % | 25.0 % | 35.2 % | 47.6 % | 7.7 | 389 |
| infocom2006-gw | Mycel all + spray + evict + inet | 58.1 % | 25.0 % | 35.2 % | 47.7 % | 7.6 | 368 |
| helsinki | best ONE by delivery: MaxProp | 47.4 % | 0.1 % | 1.9 % | 18.9 % | 31.8 | – |
| helsinki | best ONE within 1 h: SprayAndWait | 44.6 % | 0.1 % | 3.4 % | 30.5 % | 6.6 | – |
| helsinki | Mycel today | 30.4 % | 0.0 % | 0.6 % | 8.2 % | 6.1 | 13,974 |
| helsinki | Mycel + own, free, expiry | 49.5 % | 0.1 % | 0.9 % | 10.8 % | 10.9 | 17 |
| helsinki | Mycel + resume (= all) | 66.3 % | 0.1 % | 1.2 % | 15.2 % | 9.3 | 19 |
| helsinki | Mycel all + evict | 49.3 % | 0.1 % | 1.1 % | 15.3 % | 13.9 | 8 |
| helsinki | Mycel all + spray + evict | 41.7 % | 0.1 % | 1.6 % | 23.1 % | 20.5 | 6 |
| helsinki | Mycel all + spray + evict + inet | 73.1 % | 0.1 % | 2.8 % | 34.6 % | 4.0 | 0 |
| helsinki | Mycel all + spray + evict, no gradient | 73.0 % | 0.1 % | 2.8 % | 34.5 % | 4.0 | 0 |
| helsinki-gw | best ONE by delivery: MaxProp | 51.2 % | 0.5 % | 2.6 % | 21.4 % | 35.6 | – |
| helsinki-gw | best ONE within 1 h: SprayAndWait | 46.1 % | 0.6 % | 4.2 % | 31.3 % | 6.4 | – |
| helsinki-gw | Mycel today | 31.9 % | 0.3 % | 1.1 % | 8.7 % | 6.3 | 12,091 |
| helsinki-gw | Mycel + own, free, expiry | 47.1 % | 0.3 % | 1.5 % | 12.3 % | 10.3 | 53 |
| helsinki-gw | Mycel + resume (= all) | 63.1 % | 0.3 % | 1.9 % | 15.3 % | 8.4 | 43 |
| helsinki-gw | Mycel all + evict | 42.8 % | 0.5 % | 2.4 % | 19.1 % | 14.6 | 16 |
| helsinki-gw | Mycel all + spray + evict | 37.8 % | 0.4 % | 2.7 % | 23.0 % | 22.8 | 15 |
| helsinki-gw | Mycel all + spray + evict + inet | 39.6 % | 0.6 % | 3.3 % | 25.1 % | 19.8 | 30 |
| helsinki-gw | Mycel all + spray + evict, no gradient | 63.4 % | 0.4 % | 3.5 % | 31.4 % | 6.2 | 20 |

On the chat workload, the four bug fixes change nothing: a 5 MB store
holds hundreds of chat bundles, so nothing is refused. What matters there
is spray-first and the copy budget (§6.3).

### 6.6 LoRa-class radios

Mycel's proactive announcements don't fit a LoRa channel (§4). That isn't
a target today. If it becomes one, those radios should use on-demand
route discovery (AODV- or Reticulum-style) or plain flooding with a hop
limit, not periodic announcements.

## 7. Not run yet (needs Linux)

`bench/linux/README.md` has the scripts and instructions:
- **Shadow:** real `mycel` binaries on a simulated internet.
- **Mininet-WiFi:** Mycel's mesh against batman-adv, olsrd and babeld on
  identical 802.11 ad-hoc chains.
- **CORE/EMANE**, **quic-network-simulator** and **libp2p test-plans perf**.

None of these has run: Docker on this Mac is stuck, and no Linux machine
was reachable. `iroh-netbench` 0.2.0 was skipped, because it needs custom
glue around a peer session.

## 8. Limits

- The contact traces are old: iMotes sampled every 120 s, from 2005–2006.
  Contacts shorter than a scan are invisible, so phones today meet more
  often than these traces show.
- Links are 250 kB/s with no loss, no contention between parallel contacts,
  and one transfer per device at a time, as in The ONE. Real BLE L2CAP
  gives ~40–100 kB/s, and AWDL gives far more.
- In the `-gw` variants, "the internet" is an always-up clique of 250 kB/s
  links between the gateways. Both sides get it: The ONE as permanent
  connections at t = 0, Mycel through the same `--gateways` list. Mycel
  additionally knows these devices have the internet (P = 1 toward
  `INTERNET`, plus a default route toward the nearest one). The ONE's
  routers only see them as well connected.
- Mycel is run with signatures off (closures that return true). Its CPU
  cost is not part of these numbers.
