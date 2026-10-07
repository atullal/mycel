# Testing Mycel

## Automated (run `cargo test --workspace --exclude mycel-host`)

All 79 tests pass and clippy is clean (2026-10-07).

| Crate | Tests | What they prove |
|---|---|---|
| `mycel-crypto` | 6 | Domain separation, framing, kex binding, lockbox info binding, AEAD tamper detection |
| `mycel-trust` | 17 | Forged admin ops, pending ops, removal + rotation, concurrent revocation, mutual removal (seniority), delivery-order convergence, rotation recipient checks, bad key commitment, last admin, self-healing rotation, batch insert, leave, **epoch-ID reuse rejected**, **ops from never-added keys dropped** |
| `mycel-sync` | 14 | Replication, reader writes rejected, keeper can't read, outsider/tampered envelopes, forged actor, backdated writes after removal, 3-way convergence, demotion, feed causal order, restore from storage, 2,000-message ingest, **doc equivocation resolves identically everywhere** |
| `mycel-net` | 5 | Real QUIC between 5 nodes; invites + live sync with no manual calls; refusing invites; contact cards, typing, encrypted blobs; **real mDNS discovery on this machine** |
| `mycel-node` | 6 | Full messaging API on real storage: DMs, delivery → read, replies, reactions, edits, deletes, attachments, **restart persistence**, **keeper delivery while the sender is offline**, group admin removal, **L4 rules rejecting a forged op**, **message requests + declined/blocked strangers stay out**, **contact-code address hints connect without discovery**, **hostile attachment names neutralized** |
| `mycel-kit-chat` | 4 | Author-only edits/deletes, reactions, receipts/unread, admin-only meta, garbage tolerance |
| `mycel-rules(-abi)` | 27 | Deterministic WASM engine: fuel/memory limits, banned features, ABI violations, chat rules, wire compatibility with the chat kit |

## Real-device run (2026-10-07, this Mac, LAN mode)

Setup: three `mycel serve --net lan` devices (Alice, Bob, Carol) plus one `mycel keeper --net lan`, each a separate process with its own identity and storage. The real web UI was driven in headless Chrome.

| Step | Result |
|---|---|
| Discovery | Alice saw Bob and Carol **by name over mDNS**, no codes exchanged ([screenshot](screenshots/02-alice-new-conv.png)) |
| DM | Alice → Bob over the LAN. Bob got it with an unread badge, and Alice was auto-added to his contacts ([screenshot](screenshots/04-bob-inbox.png)) |
| Reply + file | Bob replied with a file. Alice saw it, and her message went to **read** ✓✓ ([screenshot](screenshots/06-alice-sees-reply.png)) |
| Download + reaction | Alice fetched the encrypted file from Bob peer-to-peer and decrypted it, then reacted 👍 ([screenshot](screenshots/07-alice-download-react.png)) |
| Group | Alice created a group with Bob and Carol; Carol received it ([screenshot](screenshots/09-carol-inbox.png)) |
| Keeper | Alice added the keeper; it joined and stored the group's ciphertext |
| Offline delivery | Bob quit. Alice sent, then quit too. Bob restarted **while Alice was offline** and still received the message from the keeper and peers |
| No internet | `lsof` on every Mycel process showed only mDNS (UDP 5353), local QUIC sockets and the localhost UI. No relay, DNS or other outbound internet connections |

### Message requests (second real-device run, latest build)
Alice started a chat with Bob, who didn't have her as a contact:
- Bob saw it under **Requests**, with the composer hidden ([screenshot](screenshots/12-bob-request.png)).
- He accepted and replied, and Alice received the reply.

### Local HTTP API hardening (curl against a live `mycel serve`)
| Request | Result |
|---|---|
| No token | 403 |
| Old static marker | 403 |
| Wrong `Host` (DNS rebinding) | 403 |
| `identity.key` via `/api/file` | 403 |
| Events without the token | 403 |
| Attachment from outside `uploads/` | refused |
| Correct token | 200 |

The token file is mode `0600`.

### Re-running it yourself
```sh
cargo build -p mycel-cli && npm install && npm run build
./target/debug/mycel serve --data /tmp/a --name Alice --net lan --http 127.0.0.1:7701 &
./target/debug/mycel serve --data /tmp/b --name Bob   --net lan --http 127.0.0.1:7702 &
open http://127.0.0.1:7701 http://127.0.0.1:7702
```
For two laptops, see [TWO_LAPTOPS.md](TWO_LAPTOPS.md).
