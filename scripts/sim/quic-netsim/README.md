# quic-network-simulator

[quic-network-simulator](https://github.com/quic-interop/quic-network-simulator)
runs a QUIC client and server in Docker containers across an ns-3 link with
scripted conditions (loss, reordering, blackholes, handshake loss, NAT
rebinding, path migration). Iroh/noq isn't in the interop runner's list, so a
small endpoint image is needed:

1. `Dockerfile`: build `mycel-cli` and add the runner's `run_endpoint.sh`
   contract (read `ROLE`, `TESTCASE`, `REQUESTS`; serve or fetch files over
   Mycel's QUIC with `mycel serve` / `mycel-sim`'s bulk ALPN).
2. Test cases that matter for Mycel: `handshakeloss`, `transfer`,
   `multiplexing`, `blackhole`, `rebind-addr`, `connectionmigration`, plus
   the simulator's `drop-rate` and `corruption-rate` scenarios at 1–20%.
3. Compare with quiche/quinn on the same scenarios (they're in the runner).

What tier 1 already covers without Docker: loss, delay, jitter and rate per
link (EmuNet), path migration between links (`mixed-room`, `multipath`), relay
failover (`nat-relay`). What this adds: a reference ns-3 link model and
cross-implementation comparison. Needs Docker; not run yet.
