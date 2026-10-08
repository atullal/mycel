# Mycel

Peer-to-peer, end-to-end encrypted, fully distributed apps. **No trusted server.** Works on a LAN with no internet at all.

- **Current status and work in progress: [STATUS.md](STATUS.md)**
- Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), including implementation status
- Trust layer spec: [docs/TRUST.md](docs/TRUST.md)
- App API: [docs/RUNTIME_API.md](docs/RUNTIME_API.md)
- Rules (L4) ABI: [docs/RULES_ABI.md](docs/RULES_ABI.md)
- Routing (local mesh, gateways, global reach, store-and-forward): [docs/ROUTING.md](docs/ROUTING.md)
- Testing and evidence: [docs/TESTING.md](docs/TESTING.md)
- Two-laptop guide: [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md)

```
crates/
  mycel-crypto     Ed25519, HPKE lockboxes, XChaCha20-Poly1305, BLAKE3
  mycel-trust      Spaces: signed membership DAG, deterministic resolution, epochs
  mycel-sync       signed + encrypted envelopes → Automerge Docs and causal Feeds
  mycel-net        Iroh QUIC multipath, live sync, mDNS, invites, blobs, the mesh
                   (mesh/core.rs routing, mesh/dtn.rs store-and-forward, gateways)
  mycel-link-awdl  link over Apple peer-to-peer Wi-Fi (AWDL, Network.framework)
  mycel-link-ble   link over Bluetooth LE L2CAP (CoreBluetooth; BlueZ on Linux)
  mycel-link-iface link over any other network interface (UWB, Wi-Fi Direct, a second NIC…)
  mycel-call       voice calls (1:1 and group): Opus over QUIC datagrams on every path
  mycel-video      video calls: camera, hardware H.264, frames on QUIC streams
  mycel-rules      L4: deterministic WASM rules engine (wasmi); mycel-rules-abi = shared ABI
  mycel-kit-chat   chat data model + deterministic reducer
  mycel-node       the Runtime (storage, identity, contacts, messaging API)
  mycel-cli        `mycel serve | keeper | id | call`
rules/             rule modules written in Rust, compiled to WASM (`rules/build.sh`)
packages/sdk       @mycel/sdk (TypeScript: types, transports, React hooks)
apps/messaging     the Messaging app (React, SDK only)
apps/host          the Mycel Host (Tauri 2 shell + web UI)
vendor/iroh        Iroh 1.3 with Mycel's multipath patch (vendor/iroh/MYCEL_PATCH.md)
```

## Quick start

Needs Rust (stable, edition 2024), Node.js 20+, and on a Mac the Xcode Command
Line Tools. For the native app also `cargo install tauri-cli --version '^2' --locked`.

```sh
npm install && npm run build                  # UI
cargo build -p mycel-cli                      # CLI
./target/debug/mycel serve --name Alice       # then open http://127.0.0.1:7777
./target/debug/mycel keeper --data ~/.mycel-keeper   # optional always-on keeper
cargo test --workspace --exclude mycel-host   # Rust tests (~260)
cargo clippy --workspace --all-targets        # kept clean
```

Native app: `scripts/package-mac.sh --universal` builds `dist-release/Mycel_*_universal.dmg`
(runs on Apple silicon and Intel; unsigned, see [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md)
for opening it). Builds are tested against each other only at the same version:
install the same build on every device you test with.

> **Not audited.** Don't trust Mycel with real secrets until the trust layer has an external cryptographic review.
