# Benchmarks that need Linux

**None of this has run yet.** It was written on macOS while no Linux machine
was reachable. The scripts are starting points; expect to fix a few things on
first contact. Results go into `docs/BENCHMARKS.md` next to the macOS ones.

Target: Ubuntu 24.04 (bare metal or a VM with nested virtualisation off),
8+ cores, 16+ GB RAM. `setup-ubuntu.sh` installs everything below into
`~/mycel-bench` and leaves the system otherwise alone (apart from apt packages
and Mininet-WiFi's kernel module `mac80211_hwsim`, loaded on demand).

| Tool | What it measures for Mycel | Script |
|---|---|---|
| [Shadow](https://shadow.github.io) | Real `mycel` binaries, hundreds to thousands, on a simulated internet (latencies from a city graph). Deterministic. | `shadow/make_config.py` |
| [Mininet-WiFi](https://github.com/intrig-unicamp/mininet-wifi) | Mycel's mesh vs batman-adv, OLSR (olsrd) and Babel (babeld) on identical emulated 802.11 ad-hoc topologies: delivery, convergence after a node moves or dies, overhead. | `mininet_wifi_mesh.py` |
| [CORE](https://github.com/coreemu/core) + [EMANE](https://github.com/adjacentlink/emane) | Same comparison with EMANE's radio models (RF pathloss, mobility scripts). | see below |
| [quic-network-simulator](https://github.com/quic-interop/quic-network-simulator) | Mycel's QUIC (noq via Iroh) under ns-3 scenarios: loss, reordering, satellite BDP, blackholes. | see below |
| [libp2p test-plans perf](https://github.com/libp2p/test-plans) | Throughput against iperf / quic-go / libp2p baselines. | see below |

## 1. Setup

```sh
bench/linux/setup-ubuntu.sh            # apt deps, Rust, Shadow, Mininet-WiFi, babeld, olsrd, batctl
cargo build --release -p mycel-cli     # the `mycel` binary every experiment runs
```

## 2. Shadow: real Mycel nodes on a simulated internet

Shadow runs unmodified Linux binaries and intercepts their system calls.
Known risk for us: Tokio and noq use `epoll`, `recvmmsg`/`sendmmsg`, UDP GSO
and ECN socket options. Shadow implements most of these, but not all of
them. If a socket call fails, check Shadow's log for the unsupported syscall
or option first, then see whether `noq-udp` can run without it (GSO and ECN
are optional in QUIC).

```sh
python3 bench/linux/shadow/make_config.py --nodes 200 --cities bench/linux/shadow/cities.csv > shadow.yaml
shadow --progress true shadow.yaml
```

The generator builds a GML graph with one vertex per city and edge latency
from great-circle distance (light in fibre, 5 µs/km, × 1.5 for indirect
routes), assigns nodes to cities, and starts `mycel keeper`
(always-on) on each. Not done yet: inside Shadow there are no n0 relays,
no DNS discovery and (probably) no mDNS, so nodes must be told each other's
addresses. The next step is a driver that hands every node a few contact
codes with address hints (`mycel id`) and then generates traffic with
`mycel call`. Measure connection setup, sync spread and message latency
against the latency model.

## 3. Mininet-WiFi: Mycel's mesh against batman-adv, OLSR and Babel

```sh
sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 20 --proto mycel
sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 20 --proto batman_adv
sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 20 --proto olsrd
sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 20 --proto babeld
```

Stations are placed on a line (or a grid with `--grid`) so that only
neighbours hear each other, forming an N-hop chain. For the IP routing
daemons, the script pings end to end and runs iperf3; for Mycel, every
station runs `mycel serve --net lan` with `MYCEL_LINKS=iface` (the
network-interface link, so Mycel sees the ad-hoc interface as a link) and
the script reads route state through `mycel call network_status`. The
comparison that matters: time until the far end is reachable, recovery
after `--kill-middle`, and control traffic (`tcpdump` byte counts per
station).

## 4. CORE / EMANE

Install CORE 9.x from its GitHub releases, EMANE from Adjacent Link's
packages. Build a topology in `core-gui` (or `core-cli xml`) with N nodes
on an EMANE `rfpipe` network, add the services `OLSR`, `Babel`, or a
custom service (CORE's "custom services" folder; not written yet) running
`mycel serve --net lan` with `MYCEL_LINKS=iface`. Mobility:
EMANE location events or a CORE mobility script.

## 5. quic-network-simulator

An endpoint is a Docker image with `/run_endpoint.sh` that reads
`ROLE`, `TESTCASE`, `REQUESTS`. Build one wrapping a tiny client/server
around Mycel's QUIC transport (Iroh endpoint with `ip=true`, a fixed
ALPN that downloads `REQUESTS`), then run the simulator's `simple-p2p`,
`drop-rate`, `blackhole` and `satellite` scenarios. Compare throughput
and time-to-completion with quic-go and quinn endpoints from the
interop runner.

## 6. libp2p perf

`libp2p/test-plans/perf` runs on Docker. Add a Mycel "implementation"
that serves the perf protocol (upload N bytes, download M bytes) over a
Mycel connection; compare with the iperf, HTTPS, quic-go and rust-libp2p
baselines it already has.
