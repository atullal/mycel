# Benchmarks against an external simulator

Mycel's store-and-forward code (`crates/mycel-net/src/mesh/dtn.rs`, the real
`Carrier`) against **The ONE**'s reference routers: Epidemic, PRoPHET,
binary Spray-and-Wait, MaxProp and Direct Delivery. Both replay the same
real Bluetooth contact traces and the same message workloads.

Everything here ran on one Mac (18 cores, 24 GB). Simulations of Mycel's own
routing at scale are in [SIMULATION.md](SIMULATION.md). §7 measures
something else: the cost of resolving a space's membership graph.

## Headline

Mycel's carrier has the fixes of §6, applied to `mesh/dtn.rs` and the
node's protocol, with the defaults chosen in §6.5: spray-first, a single
copy follows predictability toward the internet, 32 copies for bundles of
16 KiB or less falling to 4 at 256 KiB, offers before payloads, resume,
lifetimes from creation, and eviction of the soonest-expiring carried
bundles. "Before" is the carrier this benchmark first measured. "≤ 1 h" is
the share of *all* messages created that arrived within an hour.

| Trace | Workload | Best ONE router (delivery) | Its ≤ 1 h | Its overhead | Mycel before | Before ≤ 1 h | Mycel now | Now ≤ 1 h | Now overhead |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| cambridge | heavy | MaxProp 9.4 % | 8.8 % | 10.4 | 9.4 % | 5.7 % | **14.8 %** | **10.6 %** | 5.1 |
| infocom2005 | heavy | MaxProp 20.4 % | 16.8 % | 66.0 | 22.0 % | 7.7 % | **32.1 %** | **22.1 %** | 7.1 |
| infocom2006 | heavy | MaxProp 38.0 % | 30.0 % | 202.8 | 28.9 % | 16.1 % | **57.0 %** | **43.0 %** | 7.3 |
| infocom2006-gw | heavy | MaxProp 40.3 % | 33.0 % | 277.0 | 40.9 % | 24.8 % | **58.5 %** | **48.2 %** | 5.3 |
| helsinki | heavy | MaxProp 47.4 % (Spray-and-Wait: 30.5 % ≤ 1 h) | 18.9 % | 31.8 | 30.4 % | 8.2 % | **62.9 %** | 30.5 % | 4.7 |
| helsinki-gw | heavy | MaxProp 51.2 % (Spray-and-Wait: 31.3 % ≤ 1 h) | 21.4 % | 35.6 | 31.9 % | 8.7 % | **52.7 %** | 27.7 % | 9.7 |
| cambridge | chat | MaxProp 51.5 % | 11.9 % | 6.0 | 45.9 % | 11.1 % | 50.6 % | 11.5 % | 5.1 |
| infocom2005 | chat | MaxProp 84.2 % | 24.6 % | 36.8 | 82.5 % | 23.3 % | 84.1 % | 24.4 % | 16.2 |
| infocom2006 | chat | MaxProp 83.2 % | – | 215.4 | 82.9 % | 44.8 % | 83.2 % | 46.9 % | 18.3 |
| infocom2006-gw | chat | Spray-and-Wait 76.6 % | – | 3.4 | 84.4 % | 51.3 % | **84.4 %** | 51.6 % | 11.1 |
| helsinki | chat | MaxProp 98.1 % | 98.0 % | 90.4 | 87.7 % | 49.7 % | 97.2 % | 94.4 % | 26.1 |
| helsinki-gw | chat | MaxProp 98.1 % | 98.1 % | 102.1 | 90.7 % | 59.6 % | 96.0 % | 87.7 % | 37.3 |

- **Heavy messages: Mycel now beats the best ONE router on 5 of 6 traces**,
  on total delivery and on delivery within an hour (Helsinki within an
  hour: a tie with Spray-and-Wait), with 2–52× fewer transmissions than
  MaxProp. Before the fixes it delivered as much on the conference
  traces but far later, and lost on Helsinki: 95–99% of its transfers were
  refused only after the whole payload had crossed the link (§6.1).
- **Chat-sized messages: level with MaxProp** on Cambridge and both
  Infocoms (within 1 point, with up to 12× less overhead), best on
  Infocom 2006 with gateways. On Helsinki, 32 copies for small bundles
  take delivery within an hour from 50% to 94%; MaxProp still gets 98%
  there by copying to everyone (overhead 90 against 26).
- **Helsinki with gateways, heavy: now ahead on delivery**, at 52.7%
  against MaxProp's 51.2%, with half the transmissions of before (overhead
  9.7, was 19.4).
  - The single copy used to climb toward the 6 tram gateways, which move
    fast (contacts of seconds) and have 5 MB stores, so transfers to them
    were cut and their stores filled: 37.2%.
  - The gradient now discounts a neighbour that can take fewer than 4
    more bundles of the size (`room_aware`, §6.5).
  - Spray-and-Wait still gets more there within an hour: 31.3% against
    27.7%.

## 1. Tools, versions and inputs

| | Version | Notes |
|---|---|---|
| [The ONE](https://github.com/akeranen/the-one) | `c973bfb`, OpenJDK 27 (Homebrew) | Batch mode (`bench/one/one.sh`). MaxProp needs `-Djava.util.Arrays.useLegacyMergeSort=true`: its comparator isn't transitive and Java 7+ TimSort rejects it. |
| Mycel | this repository | `bench/mycel-bench`: `dtn-replay` and `route-check`. They link the real `mycel-net` code. |

**Contact traces.** These are real Bluetooth sightings between iMotes carried by people (CRAWDAD
`cambridge/haggle`: Scott, Gass, Crowcroft, Hui, Diot, Chaintreau,
doi:10.15783/C70011). You download them yourself, under CRAWDAD's terms:
cite the dataset, don't try to identify people, don't re-share it.
`bench/fetch.sh` fetches the unmodified files (IEEE DataPort needs a login,
so it takes them from the mobemu repository) into the gitignored
`bench/data/`; they are never redistributed in this repository.

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
- **Offers and resume, as on the node:** each bundle is offered before its
  payload, and a device tries its planned hand-offs in order until one is
  taken. An offer costs no link time here (it is a round trip, against
  seconds of payload). A transfer cut when a contact ends leaves the bytes
  that arrived with the receiver, and the next offer of that bundle sends
  only the rest (`--no-resume` turns that off: The ONE's routers can't
  resume).
- **Live routes:** these come from a breadth-first search over the contacts
  that are up now. `route-check` runs the real `Router` on the same traces
  to check that shortcut. On 30 minutes of Infocom 2006, whenever a
  multi-hop path existed, the router followed a working route 94.1% of the
  time, so the shortcut slightly flatters Mycel. On Helsinki it was 71%,
  but multi-hop paths existed only 160 times there.

Differences that matter when reading the tables:
- **Full buffers.** The ONE's buffers drop the oldest messages when full,
  including the sender's own. Mycel's carrier drops the carried bundles
  that expire soonest, never the device's own, whose messages don't count
  against the room it lends to others.
- **Bundle size.** Mycel's real maximum is 256 KiB, and the node splits
  bigger data. The replay raises it to 4 MiB so that one message is one
  bundle, as in The ONE.

## 2. Running it

```sh
bench/fetch.sh                          # tools + traces (once)
bench/one/one.sh build                  # compile The ONE (once)
cargo build --profile replay -p mycel-bench   # speed-optimised (the release profile optimises for size)
bench/run.py                            # every trace × workload, both sides; skips finished runs
bench/run.py --routers mycel --force    # Mycel only, all traces: after changing mesh/dtn.rs
bench/run.py --only helsinki --workloads heavy --routers mycel --force   # one case
bench/run.py --summary-only             # rebuild bench/results/summary.{md,csv}
bench/ablation.py                       # the carrier's policy knobs (§6.5), one variant at a time
```

`run.py` resumes a killed ONE batch: only routers without a finished report
run again. Every run takes seconds to minutes except Infocom
2006 with `chat`, where The ONE takes much longer:
- Epidemic: about 30 min.
- PRoPHET: about 20 min.
- MaxProp: 73 min, and more than 2 h 23 min with gateways (not
  finished).

Mycel's replay of all twelve runs takes under 5 minutes with 4 jobs
(the slowest, Infocom 2006 with gateways, about 3 minutes).

## 3. Results: store-and-forward on real contact traces

Bold rows are Mycel's carrier. "Overhead" is The
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
| cambridge | **Mycel** | 14.8 % | 3206 | 254 | 5.14 | 1.67 |
| infocom2005 | Epidemic | 7.6 % | 1669 | 415 | 247.28 | 5.03 |
| infocom2005 | Prophet | 12.1 % | 2032 | 864 | 165.23 | 2.88 |
| infocom2005 | SprayAndWait | 16.9 % | 1272 | 494 | 8.71 | 1.92 |
| infocom2005 | MaxProp | 20.4 % | 2045 | 435 | 66.04 | 3.33 |
| infocom2005 | DirectDelivery | 16.7 % | 2809 | 1953 | 0.00 | 1.00 |
| infocom2005 | **Mycel** | 32.1 % | 3480 | 1106 | 7.09 | 3.05 |
| infocom2006 | Epidemic | 8.7 % | 2227 | 499 | 1116.39 | 7.75 |
| infocom2006 | Prophet | 18.5 % | 4104 | 1938 | 529.20 | 3.55 |
| infocom2006 | SprayAndWait | 25.9 % | 2290 | 858 | 8.94 | 1.98 |
| infocom2006 | MaxProp | 38.0 % | 2351 | 312 | 202.77 | 4.33 |
| infocom2006 | DirectDelivery | 20.2 % | 5093 | 3625 | 0.00 | 1.00 |
| infocom2006 | **Mycel** | 57.0 % | 2672 | 489 | 7.27 | 4.39 |
| infocom2006-gw | Epidemic | 10.8 % | 2307 | 357 | 1343.12 | 6.40 |
| infocom2006-gw | Prophet | 18.4 % | 3430 | 1108 | 758.99 | 3.07 |
| infocom2006-gw | SprayAndWait | 31.0 % | 2175 | 554 | 7.50 | 1.92 |
| infocom2006-gw | MaxProp | 40.3 % | 2092 | 234 | 276.98 | 3.92 |
| infocom2006-gw | DirectDelivery | 22.7 % | 4507 | 2618 | 0.00 | 1.00 |
| infocom2006-gw | **Mycel** | 58.5 % | 1910 | 206 | 5.33 | 3.66 |
| helsinki | Epidemic | 20.1 % | 3221 | 2417 | 98.75 | 4.39 |
| helsinki | Prophet | 21.6 % | 3864 | 2861 | 70.58 | 2.96 |
| helsinki | SprayAndWait | 44.5 % | 3012 | 2452 | 6.57 | 1.98 |
| helsinki | MaxProp | 47.4 % | 5927 | 4662 | 31.80 | 1.69 |
| helsinki | DirectDelivery | 31.7 % | 6586 | 5713 | 0.00 | 1.00 |
| helsinki | **Mycel** | 62.9 % | 5096 | 3731 | 4.67 | 1.91 |
| helsinki-gw | Epidemic | 18.7 % | 3245 | 2596 | 189.78 | 4.82 |
| helsinki-gw | Prophet | 22.4 % | 3839 | 2850 | 131.00 | 3.54 |
| helsinki-gw | SprayAndWait | 46.1 % | 3028 | 2466 | 6.37 | 1.98 |
| helsinki-gw | MaxProp | 51.2 % | 5748 | 4527 | 35.64 | 1.76 |
| helsinki-gw | DirectDelivery | 31.9 % | 6544 | 5666 | 0.00 | 1.00 |
| helsinki-gw | **Mycel** | 52.7 % | 4666 | 3404 | 9.70 | 2.46 |

**Chat workload** (1–10 kB, TTL 24 h)

| Scenario | Router | Delivered | Latency avg (s) | Latency median (s) | Overhead | Hops avg |
|---|---|---:|---:|---:|---:|---:|
| cambridge | Epidemic | 44.4 % | 30238 | 26302 | 29.37 | 2.96 |
| cambridge | Prophet | 44.5 % | 28729 | 24598 | 21.05 | 2.23 |
| cambridge | SprayAndWait | 45.3 % | 29274 | 25438 | 3.37 | 1.79 |
| cambridge | MaxProp | 51.5 % | 30009 | 26723 | 6.02 | 2.34 |
| cambridge | DirectDelivery | 33.8 % | 29458 | 25956 | 0.00 | 1.00 |
| cambridge | **Mycel** | 50.6 % | 30377 | 27499 | 5.11 | 2.48 |
| infocom2005 | Epidemic | 72.5 % | 24863 | 21303 | 145.25 | 3.61 |
| infocom2005 | Prophet | 68.5 % | 22207 | 17712 | 144.78 | 2.69 |
| infocom2005 | SprayAndWait | 81.0 % | 22966 | 18020 | 3.19 | 1.99 |
| infocom2005 | MaxProp | 84.2 % | 21379 | 16543 | 36.83 | 3.44 |
| infocom2005 | DirectDelivery | 68.3 % | 26974 | 22954 | 0.00 | 1.00 |
| infocom2005 | **Mycel** | 84.1 % | 21475 | 16642 | 16.18 | 3.51 |
| infocom2006 | Epidemic | 64.1 % | 18881 | 12729 | 678.02 | 5.38 |
| infocom2006 | Prophet | 65.7 % | 15019 | 7769 | 601.98 | 3.47 |
| infocom2006 | SprayAndWait | 74.3 % | 17050 | 8733 | 3.54 | 2.08 |
| infocom2006 | MaxProp | 83.2 % | 8830 | 2751 | 215.40 | 5.04 |
| infocom2006 | DirectDelivery | 51.5 % | 27721 | 22743 | 0.00 | 1.00 |
| infocom2006 | **Mycel** | 83.2 % | 7837 | 2281 | 18.31 | 4.30 |
| infocom2006-gw | Epidemic | 63.7 % | 17969 | 12068 | 833.47 | 4.79 |
| infocom2006-gw | Prophet | 65.4 % | 14474 | 6793 | 701.60 | 3.34 |
| infocom2006-gw | SprayAndWait | 76.6 % | 15819 | 7169 | 3.37 | 2.04 |
| infocom2006-gw | DirectDelivery | 54.0 % | 26338 | 20466 | 0.00 | 1.00 |
| infocom2006-gw | **Mycel** | 84.4 % | 6697 | 1455 | 11.09 | 4.13 |
| helsinki | Epidemic | 87.8 % | 1652 | 1191 | 182.80 | 3.69 |
| helsinki | Prophet | 90.4 % | 1866 | 1579 | 155.60 | 2.67 |
| helsinki | SprayAndWait | 91.9 % | 3411 | 2214 | 3.22 | 2.02 |
| helsinki | MaxProp | 98.1 % | 972 | 855 | 90.43 | 3.97 |
| helsinki | DirectDelivery | 63.3 % | 8028 | 5383 | 0.00 | 1.00 |
| helsinki | **Mycel** | 97.2 % | 1374 | 1173 | 26.12 | 3.24 |
| helsinki-gw | Epidemic | 87.5 % | 1587 | 1133 | 251.90 | 3.87 |
| helsinki-gw | Prophet | 89.6 % | 1851 | 1528 | 222.11 | 2.86 |
| helsinki-gw | SprayAndWait | 92.0 % | 3366 | 2185 | 3.21 | 2.03 |
| helsinki-gw | MaxProp | 98.1 % | 930 | 805 | 102.13 | 4.24 |
| helsinki-gw | DirectDelivery | 63.3 % | 8027 | 5383 | 0.00 | 1.00 |
| helsinki-gw | **Mycel** | 96.0 % | 1898 | 1408 | 37.31 | 3.77 |

- Infocom 2006 chat with gateways has no MaxProp row: it hadn't finished
  after 2 h 23 min, so it was stopped. The same run without gateways took
  73 min.
- The ONE's PRoPHET and MaxProp vary by up to about a point between
  identical runs (MaxProp on Infocom 2006 heavy: 38.8%, then 38.0%). Its
  other routers and Mycel are deterministic.

**Latency over delivered messages flatters routers that drop messages.**
In `heavy`, a 5 MB buffer holds 5–10 messages. The ONE's routers drop the
oldest when full, so the only messages they deliver are the ones whose
destination turned up soon after. Mycel's medians count more messages that
waited hours and still arrived. The fair comparison is the share of *all*
created messages delivered within a time:

| Scenario | Workload | Router | ≤ 1 min | ≤ 10 min | ≤ 1 h |
|---|---|---|---:|---:|---:|
| cambridge | heavy | Epidemic | 3.8 % | 5.5 % | 6.4 % |
| cambridge | heavy | Prophet | 4.4 % | 6.6 % | 7.9 % |
| cambridge | heavy | SprayAndWait | 5.5 % | 7.9 % | 8.8 % |
| cambridge | heavy | MaxProp | 5.8 % | 7.8 % | 8.8 % |
| cambridge | heavy | DirectDelivery | 3.8 % | 5.8 % | 7.2 % |
| cambridge | heavy | **Mycel** | 5.9 % | 8.4 % | 10.6 % |
| cambridge | chat | Epidemic | 4.3 % | 6.4 % | 10.1 % |
| cambridge | chat | Prophet | 4.2 % | 7.0 % | 10.9 % |
| cambridge | chat | SprayAndWait | 5.5 % | 7.7 % | 11.2 % |
| cambridge | chat | MaxProp | 5.8 % | 8.4 % | 11.9 % |
| cambridge | chat | DirectDelivery | 3.8 % | 5.8 % | 8.2 % |
| cambridge | chat | **Mycel** | 5.9 % | 8.3 % | 11.5 % |
| infocom2005 | heavy | Epidemic | 1.9 % | 4.2 % | 6.4 % |
| infocom2005 | heavy | Prophet | 2.2 % | 5.5 % | 9.6 % |
| infocom2005 | heavy | SprayAndWait | 4.3 % | 9.0 % | 15.2 % |
| infocom2005 | heavy | MaxProp | 4.9 % | 11.1 % | 16.8 % |
| infocom2005 | heavy | DirectDelivery | 2.1 % | 4.8 % | 11.3 % |
| infocom2005 | heavy | **Mycel** | 6.8 % | 13.4 % | 22.1 % |
| infocom2005 | chat | Epidemic | 2.1 % | 4.8 % | 13.6 % |
| infocom2005 | chat | Prophet | 2.4 % | 6.2 % | 16.9 % |
| infocom2005 | chat | SprayAndWait | 4.9 % | 9.5 % | 20.6 % |
| infocom2005 | chat | MaxProp | 6.9 % | 13.7 % | 24.6 % |
| infocom2005 | chat | DirectDelivery | 2.5 % | 5.0 % | 12.0 % |
| infocom2005 | chat | **Mycel** | 7.6 % | 14.0 % | 24.4 % |
| infocom2006 | heavy | Epidemic | 1.6 % | 4.6 % | 6.9 % |
| infocom2006 | heavy | Prophet | 1.8 % | 5.8 % | 11.3 % |
| infocom2006 | heavy | SprayAndWait | 5.4 % | 11.4 % | 20.4 % |
| infocom2006 | heavy | MaxProp | 7.3 % | 22.4 % | 30.0 % |
| infocom2006 | heavy | DirectDelivery | 2.1 % | 5.0 % | 10.1 % |
| infocom2006 | heavy | **Mycel** | 19.6 % | 29.9 % | 43.0 % |
| infocom2006 | chat | **Mycel** | 20.7 % | 31.1 % | 46.9 % |
| infocom2006-gw | heavy | Epidemic | 2.7 % | 6.2 % | 8.7 % |
| infocom2006-gw | heavy | Prophet | 3.1 % | 7.7 % | 12.5 % |
| infocom2006-gw | heavy | SprayAndWait | 9.6 % | 15.9 % | 24.6 % |
| infocom2006-gw | heavy | MaxProp | 9.1 % | 25.6 % | 33.0 % |
| infocom2006-gw | heavy | DirectDelivery | 4.8 % | 7.6 % | 12.6 % |
| infocom2006-gw | heavy | **Mycel** | 25.2 % | 35.2 % | 48.2 % |
| infocom2006-gw | chat | DirectDelivery | 5.2 % | 8.2 % | 13.4 % |
| infocom2006-gw | chat | **Mycel** | 25.4 % | 35.6 % | 51.6 % |
| helsinki | heavy | Epidemic | 0.1 % | 1.7 % | 13.0 % |
| helsinki | heavy | Prophet | 0.1 % | 2.2 % | 12.4 % |
| helsinki | heavy | SprayAndWait | 0.1 % | 3.4 % | 30.5 % |
| helsinki | heavy | MaxProp | 0.1 % | 1.9 % | 18.9 % |
| helsinki | heavy | DirectDelivery | 0.1 % | 1.9 % | 11.6 % |
| helsinki | heavy | **Mycel** | 0.1 % | 2.7 % | 30.5 % |
| helsinki | chat | Epidemic | 0.6 % | 15.8 % | 79.6 % |
| helsinki | chat | Prophet | 0.6 % | 12.4 % | 81.1 % |
| helsinki | chat | SprayAndWait | 0.8 % | 14.7 % | 62.2 % |
| helsinki | chat | MaxProp | 0.8 % | 28.0 % | 98.0 % |
| helsinki | chat | DirectDelivery | 0.4 % | 5.1 % | 24.2 % |
| helsinki | chat | **Mycel** | 0.5 % | 18.4 % | 94.4 % |
| helsinki-gw | heavy | Epidemic | 0.1 % | 2.0 % | 11.7 % |
| helsinki-gw | heavy | Prophet | 0.3 % | 2.4 % | 13.1 % |
| helsinki-gw | heavy | SprayAndWait | 0.6 % | 4.2 % | 31.3 % |
| helsinki-gw | heavy | MaxProp | 0.5 % | 2.6 % | 21.4 % |
| helsinki-gw | heavy | DirectDelivery | 0.3 % | 2.1 % | 11.9 % |
| helsinki-gw | heavy | **Mycel** | 0.4 % | 3.0 % | 27.7 % |
| helsinki-gw | chat | Epidemic | 1.2 % | 19.1 % | 79.4 % |
| helsinki-gw | chat | Prophet | 0.9 % | 13.4 % | 81.1 % |
| helsinki-gw | chat | SprayAndWait | 1.3 % | 15.4 % | 62.7 % |
| helsinki-gw | chat | MaxProp | 1.5 % | 31.6 % | 98.1 % |
| helsinki-gw | chat | DirectDelivery | 0.6 % | 5.1 % | 24.2 % |
| helsinki-gw | chat | **Mycel** | 1.0 % | 14.6 % | 87.7 % |

The ONE's chat runs on Infocom 2006 predate the per-message report, so
only Mycel (and Direct Delivery with gateways) have rows there.

## 4. Limits

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
- Offers cost no link time in the replay. On a real link each is a round
  trip (tens of milliseconds over BLE); Mycel makes 1.0–1.5 offers per
  transfer it starts (`offers` and `started` in each run's output).

## 5. What it shows

- **Frugal and fast.** Mycel's overhead is 4.7–37 relays per
  delivered message, against 6–1,343 for The ONE's routers, and it
  delivers more:
  - Infocom 2006 heavy: 57.0% (43.0% within an hour) at overhead 7, against
    MaxProp's 38.0% (30.0%) at 203.
  - Infocom 2006 chat: 83.2% at overhead 18, against MaxProp's 83.2% at 215.
- **Gateways help Mycel and barely help The ONE's routers** on the
  conference trace. Adding the 17 static gateways to Infocom 2006 heavy
  takes Mycel's median from 489 s to 200 s; MaxProp goes from 38.0% to
  40.3%. The ONE's routers don't know those devices have the internet.
  Mycel's default route and internet gradient do. With fast-moving
  gateways (Helsinki's trams) the gradient costs Mycel instead (§6.5).
- **Live routes are what the router really does.** On Infocom 2006,
  `route-check` shows the real `Router` following a working multi-hop
  route 94.1% of the time one exists. Those hops count in the delivered
  messages' hop counts: 3.6–4.4 on Infocom 2006, against 1.0–2.1 for
  Direct Delivery and Spray-and-Wait.

## 6. Where Mycel lost, why, and the fix

**All of this is now applied** to the real carrier (`mesh/dtn.rs`) and
the node's protocol (`mesh/mod.rs`); §6.5 has the results and the choice
of defaults. §6.1–6.4 keep the diagnosis as it was made: an experimental
copy of the carrier with each fix behind a switch, measured one at a time
on the same traces (`bench/results/ablation/`, the historical record).
The copy is retired; the policy choices that remain are `DtnConfig`
knobs, measured with `bench/ablation.py` into `bench/results/knobs/`.

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

**Fixes** (switches in the experimental copy; how they were applied is
in each item):
- **`free`** (causes 1 and 2): summaries say how much room is left. The
  planner doesn't send to a neighbour without room for the bundle, unless
  that neighbour is the destination. A refusal marks the neighbour as full
  until its next summary. In `mesh/mod.rs` the same idea becomes an offer
  before the payload: send (id, size, copies, expiry) and wait for
  accept or refuse. BPv7 custody signalling does the same.
  *Applied:* `Carrier::offered` answers take (from an offset), duplicate
  or refuse before any payload; summaries carry `free` and `evictable`
  (soonest-expiring carried bundles, relative times); a refusal for lack
  of room stops offers to that neighbour until its next summary.
- **`own`** (cause 3): a device's own bundles use their own quota, not the
  space it lends to others. *Applied* (by the simulator work first).
- **`expiry`** (cause 4): a carrier expires a bundle at `created + lifetime`.
  On the real node that means converting through `wall_ms()`, with a bound
  on clock skew, or using a BPv7 Bundle Age block, which needs no clocks.
  *Applied:* `Carrier::set_clock` gives the carrier its wall-clock
  offset; a bundle expires at `created + lifetime`, and never later than
  one lifetime after it arrived, whatever the source's clock says.
- **`resume`**: an interrupted transfer keeps the bytes that arrived, and
  the next attempt to the same device sends only the rest. Mycel's file
  transfers already work this way (`.part` + `.ranges`), and BPv7 calls it
  reactive fragmentation. Splitting bundles at 256 KiB, as the real node
  does, gets part of the benefit. *Applied:* `Carrier::keep_partial`
  keeps a cut transfer's bytes for 5 minutes (at most a quarter of the
  store, two bundles' worth per source), and the next offer of that
  bundle, from any carrier, is answered from that offset; the id is
  checked when the last byte arrives.

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

**The gradient toward the internet, with fast-moving gateways.**
- On Helsinki-gw, 6 trams with 5 MB stores are the only gateways.
  Climbing toward them funnels heavy bundles into tiny stores: 39.6%
  delivered with `inet`, against 63.4% with no gradient.
- With chat-sized bundles the same gradient helps: 67.1% within 1 h,
  against 65.5% with no gradient.
- Real gateways have 64 MiB stores and real uplinks, so this bench is
  the worst case. The simulator's partition and disaster scenarios, where
  the gradient is meant to pay off, decided the default (§6.5).

**Chat needs more copies.** On Helsinki chat, MaxProp delivers 98% within
an hour by copying everywhere, at overhead 90. Four copies cap Mycel at
61%. Small bundles are cheap to copy, so the copy budget should depend on
size. `all,spray,evict,inet` with `--copies`:

| Helsinki chat | Delivered | ≤ 10 min | ≤ 1 h | Overhead |
|---|---:|---:|---:|---:|
| 4 copies (the earlier default) | 91.3 % | 13.9 % | 60.7 % | 3.3 |
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

These rows come from the retired experimental copy (`bench/results/ablation/`).
On the real carrier the same choice is the `copies_small` knob, measured in §6.5.

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
first. *Applied*, including the per-source order; nothing is dropped
unless that makes room.
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

That trade is a policy choice: fresh-first suits chat, keep-everything
suits files.

### 6.5 Results on the real carrier, and the defaults

Every row is the real carrier (`dtn-replay --knobs`), with the mechanics
above always on. The variants differ in policy only: how copies spread
(`spray`) and what the single copy's gradient measures (`gradient`).
`bench/results/knobs/knobs.md` has the full grid, chat and per-variant
offer and cut counts included.

| Trace | Default: spray-first, internet gradient | Spray-and-Focus, max(P(dst), P(internet)) (the simulator's first choice) | Spray-first, max(P(dst), P(internet)) | Spray-first, no gradient | 4 copies whatever the size | No resume |
|---|---|---|---|---|---|---|
| cambridge heavy | **14.8 %** / 10.6 % | 14.2 % / 10.7 % | 14.3 % / 10.6 % | 14.8 % / 10.6 % | 14.8 % / 10.6 % | 14.8 % / 10.6 % |
| infocom2005 heavy | **32.1 %** / 22.1 % | 28.1 % / 21.6 % | 28.3 % / 21.6 % | 32.1 % / 22.1 % | 32.1 % / 22.1 % | 32.1 % / 22.1 % |
| infocom2006 heavy | **57.0 %** / 43.0 % | 54.5 % / 43.1 % | 55.0 % / 43.4 % | 57.0 % / 43.0 % | 57.0 % / 43.0 % | 57.0 % / 43.0 % |
| infocom2006-gw heavy | **58.3 %** / 48.2 % | 58.3 % / 48.1 % | 58.4 % / 48.2 % | 58.3 % / 48.1 % | 58.3 % / 48.2 % | 58.4 % / 48.3 % |
| helsinki heavy | **62.9 %** / 30.5 % | 39.5 % / 16.9 % | 34.6 % / 19.4 % | 62.9 % / 30.5 % | 62.9 % / 30.5 % | 58.1 % / 25.7 % |
| helsinki-gw heavy | 37.2 % / 24.3 % | 35.3 % / 20.2 % | 35.0 % / 21.4 % | **55.0 %** / 28.9 % | 37.2 % / 24.3 % | 35.9 % / 21.2 % |
| helsinki chat | **97.2 %** / 94.4 % | 94.5 % / 79.4 % | 96.3 % / 89.2 % | 97.2 % / 94.4 % | 91.3 % / 60.7 % | 97.2 % / 94.4 % |
| helsinki-gw chat | 96.0 % / 87.7 % | 95.3 % / 83.0 % | 95.0 % / 86.1 % | 95.7 % / 88.6 % | 92.4 % / 68.7 % | 96.0 % / 87.7 % |
| infocom2006 chat | 83.2 % / 46.9 % | 83.3 % / 46.5 % | 83.3 % / 47.2 % | 83.2 % / 46.9 % | 83.0 % / 45.8 % | 83.2 % / 46.9 % |

Cells are delivered / delivered within an hour, as shares of all messages
created. Without gateways, "internet gradient" and "no gradient" are the
same thing (nobody has the internet), and spray-first and fallback (spray
only when no neighbour is clearly better) coincide.

**The defaults, and why:**
- **Spray-first** (`Spray::First`): while a bundle has copies to spare,
  half go to the likeliest neighbour without one, better than us or not.
  It wins or ties everywhere. Spray-and-Focus, which the simulator had first
  chosen, only sprays to neighbours no worse than us; on Helsinki, where
  movement has no social structure, that keeps copies where they are
  (39.5% against 62.9% heavy, 79% against 94% of chat within an hour).
- **The single copy follows predictability toward the internet only**
  (`Gradient::Internet`; for the destination itself once the internet has
  proved not to reach it). Following predictability for the destination
  costs 2–4 points of heavy delivery on the conference traces and 28 on
  Helsinki. Following nothing ties on the conference traces and wins on
  Helsinki with gateways (55.0% against 37.2%), but loses 13 points in the
  simulator's disaster zone (77% against 90% within 3 h, mean of 5 seeds,
  `docs/SIMULATION.md`), and getting a message out of a partition toward
  the internet is what the gradient is for (`docs/ROUTING.md` §7.2). The
  trams are the worst case for it: fast-moving gateways with tiny stores.
- **The gradient weighs room** (`room_aware`, on; `room=on|off`). A
  neighbour whose summary shows free room for fewer than 4 more bundles of
  this size counts in proportion: its utility is multiplied by
  free / (4 × size).
  - Helsinki with gateways, heavy: 37.2% → 52.7% delivered, 24.3% → 27.7%
    within an hour, and overhead 19.4 → 9.7.
  - Infocom 2006 with gateways, heavy: 58.3% → 58.5%.
  - Every other trace and workload: identical. Without gateways, the
    internet gradient has nothing to climb.
  - `disaster-dtn` in the simulator: identical (stores never fill there).
  - The rows above are with it on. The table's Helsinki-gw default column
    (37.2%) was before it.
- **Copies by size** (`copies_small` 32 at 16 KiB or less, `copies` 4 at
  256 KiB or more, geometric in between): chat within an hour on Helsinki
  goes from 60.7% to 94.4% (with gateways 68.7% to 87.7%), at 3–8× the
  transmissions. Heavy bundles keep 4 copies. On the conference traces
  more copies change little.
- **Resume** is worth 5 points of heavy delivery on Helsinki (2.4 s median
  contacts) and nothing where contacts are long.

To reproduce one cell:

```sh
./target/replay/dtn-replay --contacts bench/traces/out/helsinki.csv \
  --messages bench/traces/out/helsinki-chat-msgs.csv --ttl-min 1440 \
  --knobs spray=focus,gradient=both --latencies /tmp/lat.csv
```

## 7. Membership resolution (`mycel-trust`)

Every peer resolves a space's membership graph (TRUST.md §5) whenever an op
arrives. The resolver used to rebuild everything on each insert: an n × n
ancestor bitset and a replay of each concurrent op's past, inside a loop
rerun whenever a revocation winner failed. It is now incremental, with the
old resolver kept as the differential-test oracle (`oracle::resolve_full`).
`crates/mycel-trust/benches/resolve.rs` builds two histories live, one
`insert` at a time:

- **linear**: one admin's run of rotations, each on the previous op.
- **storm**: 12 admins; every round, four of them remove each other in a
  cycle on the same heads while a fifth rotates, then a survivor adds back
  whoever was removed. 29% of all ops are winning revocations, and as many
  are invalid (lost or concurrently revoked) and stay as dead ends.

"Before" is one `resolve_full` of the same ops: what every insert cost
before. "Resolver heap" is what the graph holds beyond the ops themselves
(resolution bookkeeping and the membership state); before, the graph kept
the bitset, so the oracle's peak is the comparable figure. Apple M5 Pro,
18 cores, `--profile replay`, measured 2026-10-21 with other builds
running (load average about 8), so single numbers are ±15%.

| History | Ops | Insert, mean | of which signature check | Worst insert, last 10% | Resolver heap | Before: per insert | Before: heap |
|---|---:|---:|---:|---:|---:|---:|---:|
| linear | 1,000 | 27 µs | 24 µs | 57 µs | 1.1 MiB | 1.0 ms | 1.8 MiB |
| linear | 10,000 | 27 µs | 24 µs | 37 µs | 13.7 MiB | 78 ms | 21.8 MiB |
| linear | 100,000 | 28 µs | 24 µs | 89 µs | 117 MiB | 9.1 s | 1,283 MiB |
| storm | 1,004 | 38 µs | 33 µs | 54 µs | 1.3 MiB | 515 ms | 2.6 MiB |
| storm | 10,000 | 38 µs | 30 µs | 76 µs | 14.0 MiB | 588 s | 28.5 MiB |
| storm | 100,000 | 48 µs | 37 µs | 243 µs | 127 MiB | not run | not run |

- **Insert cost is flat in history size.** Resolution itself is about
  3–4 µs per op for the linear history and 6–11 µs in the storm (insert
  minus the separately timed signature check); the rest is the Ed25519
  check `insert` does first. The 100,000-op storm builds in 6.1 s.
- **Before, it grew with history**: about n² for linear history
  (78 ms → 9.1 s per insert from 10,000 to 100,000 ops) and about n³ in
  the storm (515 ms → 588 s from 1,000 to 10,000). The 100,000-op storm
  was not run: by that trend, one insert would take days.
- **Memory is linear.** Resolver heap is 1.2–1.3 KiB per op in both
  histories: per-op metadata, undo logs, per-round flags, and the
  membership state with each epoch's recipients (about 400,000 entries at
  100,000 linear ops). The bitset alone was n²/8 bytes: 1.2 GB at 100,000
  ops.
- **A new member's first sync** (`insert_many` of the whole history into a
  fresh graph, one full resolution): 28–32 µs/op linear and 39–46 µs/op storm,
  so 3.2 s and 4.6 s at 100,000 ops, again mostly signature checks.

Three things kept the storm from scaling in the first incremental version,
each found by profiling this benchmark (the differential tests guarded
the changes):

- **Dead ends held chain positions.** An op took its chain position on
  arrival, so when the first op of a round to arrive was a loser nobody
  built on, the main chain ended there, and every later op's reach vector
  kept one more partly reached chain per round: 6.8 million vector entries
  at 20,000 ops, 1.6 GB of heap and 328 µs per insert at 100,000. Ops now
  join a chain only when they get their first child: 28,568 entries at
  100,000 ops.
- **Re-adding a reader rescanned every epoch.** A member added back is a
  recipient of every epoch in the adder's past; the resolver checked all of
  them. It now starts after the prefix of epochs the member already holds.
- **Full resolutions were quadratic in revocations per member.** Steps 3
  and 4 scanned every revocation of an op's author, and the region walk
  copied its undo logs at merges: 125 µs/op for a 100,000-op first sync.
  Winners are now indexed per target in topological order, with each scan
  stopping at a winner whose earlier (or later) winners all lie in its
  past (or future), and the logs are shared lists.

Reproduce (the oracle columns: `--oracle-max`, `--oracle-storm-max`; the
storm oracle at 10,000 ops takes about ten minutes):

```sh
cargo bench -p mycel-trust --features oracle --bench resolve --profile replay -- \
  1000 10000 100000 --oracle-max 100000 --oracle-storm-max 10000
```

Correctness is checked separately: `cargo test -p mycel-trust` runs
random concurrent histories through both resolvers (TRUST.md §9).
`PROPTEST_CASES=6000` (18,000 histories, each checked after every insert)
passed on this version, and 10,000 per property before the last two
changes.
