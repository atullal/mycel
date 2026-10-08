# Mycel

Peer-to-peer, end-to-end encrypted, fully distributed apps. **No trusted server.** Works on a LAN with no internet at all.

- Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), including implementation status
- Trust layer spec: [docs/TRUST.md](docs/TRUST.md)
- App API: [docs/RUNTIME_API.md](docs/RUNTIME_API.md)
- Rules (L4) ABI: [docs/RULES_ABI.md](docs/RULES_ABI.md)
- Testing and evidence: [docs/TESTING.md](docs/TESTING.md)
- Two-laptop guide: [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md)

```
crates/
  mycel-crypto    Ed25519, HPKE lockboxes, XChaCha20-Poly1305, BLAKE3
  mycel-trust     Spaces: signed membership DAG, deterministic resolution, epochs
  mycel-sync      signed + encrypted envelopes → Automerge Docs and causal Feeds
  mycel-net       Iroh QUIC, live sync, mDNS, invites, cards, typing, blobs
  mycel-call      live voice calls: Opus over QUIC datagrams on every path
  mycel-rules     L4: deterministic WASM rules engine (wasmi)
  mycel-kit-chat  chat data model + deterministic reducer
  mycel-node      the Runtime (storage, identity, contacts, messaging API)
  mycel-cli       `mycel serve | keeper | id | call`
rules/            rule modules written in Rust, compiled to WASM
packages/sdk      @mycel/sdk (TypeScript: types, transports, React hooks)
apps/messaging    the Messaging app (React, SDK only)
apps/host         the Mycel Host (Tauri 2 shell + web UI)
```

## Quick start
```sh
npm install && npm run build                  # UI
cargo build -p mycel-cli                      # CLI
./target/debug/mycel serve --name Alice       # then open http://127.0.0.1:7777
./target/debug/mycel keeper --data ~/.mycel-keeper   # optional always-on keeper
cargo test --workspace --exclude mycel-host   # 159 Rust tests
```

Native app: `cd apps/host && cargo tauri build` (see [docs/TWO_LAPTOPS.md](docs/TWO_LAPTOPS.md)).

> **Not audited.** Don't trust Mycel with real secrets until the trust layer has an external cryptographic review.
