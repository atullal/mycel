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
- **The internet without a relay server:** a device the internet can reach
  relays for devices behind routers, for those that ask, within a budget;
  a device behind a router names its relays in its record. Each device
  publishes its own signed record in the DHT (and on n0's DNS server unless
  switched off) and remembers DHT nodes across restarts. n0's relay servers
  and DNS server are each optional (`MYCEL_RELAYS`, `MYCEL_N0_DNS`); the
  default still uses them, and falls back to device relays when no relay
  server is connected.
- **Metered uplinks:** on mobile data a device is neither a gateway nor a
  relay.
- **Hardening:** resource limits on everything a peer sends, and fixes for
  the findings of internal adversarial reviews, each with a regression test
  ([TRUST.md](docs/TRUST.md) §8d and §9b).
- **SDK and CLI:** `@mycel/sdk` (TypeScript client, Tauri/HTTP/mock
  transports, React hooks) and the `mycel` CLI (`serve`, `keeper`, `id`,
  `call`).
- **Simulator and benchmarks:** `mycel-sim`, with real nodes over emulated
  radios and up to 10,000+ virtual devices in virtual time, and replays
  against The ONE's routers on real contact traces.
- **Chunked files:** attachments are trees of content-addressed, separately
  sealed pieces in one store per device. Every piece is checked on arrival
  and can come from any device that holds it; a file a member couldn't be
  given waits in the caches of contacts and nearby devices, which keep what
  is asked for and let the rest go; a file sent as *public* is stored and
  sent once wherever it is used ([TRUST.md](docs/TRUST.md) §7c). Older
  attachments still open. This changes what goes over the network and what
  is stored on disk.

### Changed

- **Records and relaying on the wire:** a relay control message between hop
  neighbours, and new items in reachability records (`mycel-relay`; a
  device's own record now carries its relays). A device's record on n0's
  DNS server no longer carries its display name. Passing traffic between
  two internet hops, which nothing asked for before, now needs one end to
  be a relay's client. A device the internet can reach now publishes its IP
  address under its key, because it relays by default
  (`MYCEL_INTERNET_RELAY=0` turns that off).
- **Lockboxes are hybrid post-quantum.** The key agreement that seals epoch
  keys to readers is X-Wing (X25519 + ML-KEM-768) instead of X25519 alone,
  so lockboxes recorded today stay sealed if X25519 is broken later.
  Signatures and the transport handshake are unchanged
  ([TRUST.md](docs/TRUST.md) §2, §10). A member's lockbox key is 1216 bytes
  and a lockbox about 1.2 kB.
  **Not compatible with earlier builds, on the wire or on disk:** member
  keys, membership ops, contact cards and stored contacts changed. Data and
  codes of earlier builds are refused (an old key doesn't decode, an old
  lockbox is named as unsupported, an old key binding doesn't verify);
  nothing of theirs is opened with the new keys. Start from a new profile.
- **Contact codes are short.** The code a profile shows (text and QR code)
  now holds the device key and its signed name, about 150 characters,
  instead of the whole card: the lockbox key no longer fits a QR code. The
  adding device fetches the signed card from the device the first time it
  reaches it; until then the contact is listed (`awaitingKeys`) and can't be
  put in a conversation. `Profile.contactCodeFull` and `mycel id` give the
  full code, which holds the card and needs no connection. Codes of earlier
  builds aren't accepted.
- **Forward secrecy in windows.** Lockboxes are no longer sealed to a key
  derived from the device's identity, which used to open every epoch for
  ever. Each device publishes a random *reader key* per space (a new
  membership op, `ReaderKey`), replaces it every 7 days and deletes it
  after 30 more days of running; the epoch keys it has opened and its
  reader keys are stored in its database, sealed under a key derived from
  its identity, instead of being re-derived at every start; and writers
  rotate the epoch once it is a day old. A stolen identity key, with
  everything keepers store, then opens only what a member was given when
  it joined a space ([TRUST.md](docs/TRUST.md) §6 says exactly what). A
  device publishes reader keys only where its user takes part: an
  unanswered message request still gets nothing back.
  **Wire and storage:** a new op kind in the membership graph, which
  earlier builds can't decode, and a new `space-secrets/<space>` record in
  the database.
- **Stored ops are restored parents first.** A restart handed the graph
  its stored ops in storage order, and the graph refuses an op whose
  author it hasn't seen added: an op by anyone but the founder could be
  dropped until a peer sent it again, which made its author's later
  messages wait. Members now author ops routinely (their reader keys), so
  a restore sorts them first.

### Known limitations

- The cryptography and trust layer have not had an external audit.
- What a member is given when it joins a space is sealed to the key
  derived from its identity, not to a reader key; and a device that loses
  its database, or is sealed to by someone out of touch for over a month,
  can't read the epochs it missed.
- Peer-to-peer Wi-Fi, and Bluetooth and Wi-Fi Direct on Linux, are tested
  on emulated links, not between real devices. Windows and Linux apps have
  run on CI machines only, Android on the emulator only.
- Relays among devices, running without n0's servers, and finding who
  holds a file through the DHT are tested between processes on one
  computer (and a local test DHT), not across real routers or on the
  public DHT.
- A suspended iPhone or iPad doesn't receive messages until Mycel is opened
  again.
- Every device must run the same build.

More in [ARCHITECTURE.md](docs/ARCHITECTURE.md) §7 and
[TRUST.md](docs/TRUST.md) §10.

[Unreleased]: https://github.com/atullal/mycel/commits/main
