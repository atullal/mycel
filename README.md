# Mycel

Peer-to-peer, authenticated, fully distributed apps. No trusted server.

- Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Trust layer spec: [docs/TRUST.md](docs/TRUST.md)

```
crates/
  mycel-crypto  Ed25519, HPKE lockboxes, XChaCha20-Poly1305, BLAKE3
  mycel-trust   Spaces: signed membership DAG, deterministic resolution, epochs
  mycel-sync    signed+encrypted Automerge envelopes, validation, documents
  mycel-net     Iroh transport + membership-gated sync protocol
  mycel-node    facade crate + demo
```

```sh
cargo test --workspace                     # 29 tests
cargo run -p mycel-node --example demo     # 5-node walkthrough over real QUIC
```

> Not audited. Do not trust with real secrets until the trust layer has an external cryptographic review.
