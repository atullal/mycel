# Changelog

Notable changes to Mycel. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The first public version. It contains:

### Added

- **Apps:** the Mycel host (Tauri 2) for macOS, iPhone and iPad, Android,
  Windows and Linux, running the Messaging app: direct chats and groups,
  message requests, replies, edits, deletes (for everyone, or on this device
  only), reactions, read receipts, typing, search, voice notes, files of any
  size, members and keepers, and private notifications that never show names
  or text.
- **Calls:** voice and video, 1:1 and groups of up to 8, as a full mesh of
  QUIC connections that move between paths mid-call; Opus with FEC and
  per-path bitrate; hardware H.264 on Apple platforms and web-view encoding
  elsewhere; echo cancellation on Apple platforms and Android.
- **Trust layer:** spaces with a signed, hash-linked membership graph,
  deterministic resolution of concurrent changes, roles, epoch keys sealed to
  each reader with HPKE, revocation with key rotation and cutoffs.
- **Data and sync:** every change signed and encrypted in its own envelope
  and checked before it is applied; Automerge documents and causal feeds;
  streaming encryption for attachments, downloaded from every member that
  has them at once and resumable; keepers that store and serve ciphertext
  without reading it.
- **Rules:** a deterministic WebAssembly rules engine (wasmi) and the chat
  rules, compiled from Rust, run by every peer.
- **Network:** Iroh QUIC dialed by key, with multipath aggregation and
  failover across the LAN (mDNS, and Bonjour on iOS), the internet,
  Bluetooth LE (macOS, iOS, Linux), peer-to-peer Wi-Fi (macOS, iOS), other
  network interfaces, and opt-in Wi-Fi Direct groups on Linux; one pooled
  connection per peer with prioritised streams.
- **Routing:** a multi-hop mesh with signed, loop-free distance-vector
  routes; gateways and signed reachability records in the Mainline DHT for
  reach from anywhere; store-and-forward with custody, mailboxes and signed
  receipts.
- **Hardening:** resource limits on everything a peer sends, and fixes for
  the findings of internal adversarial reviews, each with a regression test
  ([TRUST.md](docs/TRUST.md) §8d and §9b).
- **Fuzzing:** libFuzzer targets for every decoder of untrusted bytes, run
  on pull requests and nightly ([TESTING.md](docs/TESTING.md), "Fuzzing").
  The bugs they found are fixed. Among them, document changes are now
  refused that are shaped as Automerge never writes them (inserted deletes
  and increments, marks that aren't insertions, element keys with an actor
  and counter 0) or that name operation ids beyond 32 bits
  ([TRUST.md](docs/TRUST.md) §7, rules 8 and 9). Builds from before this
  admit some such crafted changes where newer ones refuse them, so a space
  mixing the two can disagree about a malicious member's edits.
- **SDK and CLI:** `@mycel/sdk` (TypeScript client, Tauri/HTTP/mock
  transports, React hooks) and the `mycel` CLI (`serve`, `keeper`, `id`,
  `call`).
- **Simulator and benchmarks:** `mycel-sim`, with real nodes over emulated
  radios and up to 10,000+ virtual devices in virtual time, and replays
  against The ONE's routers on real contact traces.

### Known limitations

- The cryptography and trust layer have not had an external audit.
- Peer-to-peer Wi-Fi, and Bluetooth and Wi-Fi Direct on Linux, are tested
  on emulated links, not between real devices. Windows and Linux apps have
  run on CI machines only, Android on the emulator only.
- A suspended iPhone or iPad doesn't receive messages until Mycel is opened
  again.
- Every device must run the same build.

More in [ARCHITECTURE.md](docs/ARCHITECTURE.md) §7 and
[TRUST.md](docs/TRUST.md) §10.

[Unreleased]: https://github.com/atullal/mycel/commits/main
