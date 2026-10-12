# Security hardening review, October 11, 2026

Baseline: `e6a972b645767bc985f6a67ca6f93d9b1c7a84d6`.
Work branch: `codex/security-hardening`.

This is an engineering security review with attack regression tests, not an
independent certification or a guarantee of no vulnerabilities.

## Scope and acceptance contract

Review four independent boundaries: cryptography and membership; network/API
ingress; attachments; identity persistence and mobile storage. Reproduce concrete
findings with isolated test identities and synthetic payloads, then repair the
highest-risk defects without changing wire formats or silently replacing keys.
No scans or test traffic against unrelated systems or people. No real user
messages, keys, or attachments belong in test artifacts or logs.

Required checks: targeted adversarial regressions, existing crypto/trust/sync
tests, affected node/network tests, relevant platform compile checks, dependency
advisory scans, and an independent review of the final patches. A passing test
does not establish cryptographic security or hardware reliability.

## Architecture decisions

- Preserve the existing encryption algorithms and protocol. Forward secrecy and
  recovery from a stolen long-lived device key need a separately reviewed
  protocol migration; an improvised ratchet is out of scope for this patch.
- Invalid or unauthenticated remote input must not enter trusted caches or block
  valid membership updates. Bound allocations, concurrent work, and stalled I/O.
- Identity read failures must fail closed. Secure-store migration must preserve
  the exact existing identity and verify durable storage before deleting any
  legacy seed. Do not fall back to plaintext on secure-store errors.
- Pending message requests must not authorize unsolicited attachment storage.
- Preserve the current main checkout and the separately installed iPhone build.

## Evidence and findings

Implementation and a separate agent review are complete for the patch scope.
The final causal-validation fix also passed independent source review. This branch is local; it is not
merged, published, or installed on the iPhone. The release gates below remain.

| Boundary | Confirmed defect | Remediation in this branch |
| --- | --- | --- |
| Routing authentication | A cache keyed only by origin/sequence accepted altered signed announcement fields after one valid signature | Cache the complete signed content and signature; forwarding cost/hops remain mutable |
| Network resources | Unbounded stream tasks, eager allocation from a declared 64 MiB frame, missing inbound deadlines | Nonblocking process/connection admission, byte reservations, incremental reads, header/idle/session deadlines |
| Sync responses | Repeated requested IDs cloned the same ciphertext repeatedly before checking response size | Deduplicate and measure encoded size before cloning; bounded serialization |
| Membership | Invalid operation heads and unresolved-operation floods could prevent an administrator from revoking a member | Use the causally maximal valid frontier; bound unresolved operations per author; admit immediately resolvable operations independently |
| Convergence | Revocation could leave stale equivocation exclusions, making a live replica disagree with a restored replica | Recompute exclusions from the currently valid change set |
| Change parsing | Small compressed changes could cause unbounded expansion; logical column runs also bypass a byte-only limit | Bound both decompression and logical expansion before the upstream parser |
| Document application | A structurally parseable change could panic Automerge; deferred malformed changes could poison later updates; acceptance could depend on unrelated local history | Contain parser/application panics, validate against declared dependency history, apply to a candidate document, and keep missing-dependency changes outside Automerge |
| Attachment consent | Membership granted during a pending request allowed unsolicited blob writes before user acceptance | Persist provisional consent before admission; deny pending/hidden pushes and explicit downloads; bounded pending requests |
| Attachment storage | Failed eager pushes retained partial files; concurrent writers reused the same free-space snapshot | Disposable push staging, cancellation cleanup, shared capacity reservations, Windows free-space query |
| Identity | Read failures could silently create a replacement identity; seed was a plaintext file on iOS | Fail-closed reads and profile lock; iOS create-only Keychain migration with durable recovery states and identity binding |
| Persistence | A flush could finish before an earlier drained batch; failed batches were discarded; malformed settings silently reset | Serialized commit barrier, retained failures, durable security-state transactions, strict decoding and atomic mode changes |
| Notifications/logs | OS notifications included names, message text and filenames; diagnostic logs exposed file paths | Generic notifications; opt-in BLE diagnostics; private Unix logs; redact attachment-open errors |
| iOS lifecycle | Background handling had no persistence barrier or expiration handler | Flush on suspension and before ending the task; end exactly once using UIKit's invalid-task constant |

Regression failures were captured against the original implementation before
the corresponding fixes: `trust-red.log`, `trust-frontier-pending-red.log`, and
`network-red.log`. Additional regression tests cover migration failures,
durability, attachment consent and cancellation. These tests use synthetic
identities and content. Logs are in the ignored `dist-release/security/` folder.

### Validation record

- Baseline crypto/trust/sync/rules libraries: 69 tests passed before the new
  attack regressions. Eight trust/sync regressions and two network regressions
  then failed against their original implementations.
- The deferred-document regression failed before its fix in
  `trust-queued-poison-red.log`. Two further regressions demonstrated that
  undeclared actor and object dependencies could change acceptance based on
  arrival order (`trust-causal-context-red.log`). The final trust/sync suite
  passes 60 tests, including delivery-order and restore consistency, transitive
  dependencies, counter bounds and ordinary out-of-order delivery. Across these
  phases, 11 trust/sync regression failures were reproduced before their fixes.
- Network: 76 library tests passed, one ignored. Five phase0 tests, one pool
  test and three global tests passed. The initial nine-test mesh integration
  run passed. A later run missed the aggregation throughput threshold (1.26x);
  that single timing benchmark passed in isolation afterward (2.05x). The
  failure is retained in `network-final.log`, not hidden by a retry wrapper.
  After final review, DTN acknowledgment and outgoing stream writes received
  inactivity deadlines; all 76 network library tests and three global DTN
  integration tests passed again (`network-review-final.log`).
- Attachments: three consent tests, two push-stage tests, three reservation
  tests and the admission-limit boundary test passed. Three existing blob and
  multisource tests and nine runtime integration tests passed.
- Identity/store: migration fault-injection, permissions, profile lease,
  malformed-state and durability-barrier tests passed. The startup corruption
  regression also proves that failed startup releases the database/profile
  instead of leaving detached networking tasks alive.
- Host: three notification privacy tests and the retained iOS logging-pipe
  regression passed. The latter preserves the earlier fix for an idle CPU spin.
- `cargo check --locked -p mycel-host --target aarch64-apple-ios` and the CLI
  compile check passed. These are compile checks, not device acceptance tests.
- TypeScript workspace checking and the production frontend build passed.
- Final combined run: `cargo test --locked --workspace --lib --no-fail-fast` —
  **319 passed, zero failed, three ignored**, across 15 libraries. The ignored
  tests are microphone status, the BLE seed sweep, and the large-mesh overhead
  benchmark. They are not counted as passes. Results: `workspace-lib-tests.log`
  and `workspace-results.json`.
- Test environment: macOS, Rust 1.99.0, cargo-audit 0.22.2. The ignored
  `dist-release/security/review-manifest.json` records the final source commit
  and SHA-256 hashes of the evidence files.

### Enforced resource policies

These limits retain the wire format but intentionally reject oversized input
that older builds may have accepted:

- 64 inbound streams per process and eight per connection; reject overload
  before spawning tasks. Mesh DTN shares the process admission budget.
- 64 MiB maximum ordinary frame; 128 MiB of encoded-frame reservations per
  process and per connection, held while variable-size messages are handled.
  Five-second header deadline, 30-second I/O inactivity deadline, 60-second
  inbound sync deadline. Large blob/DTN payloads use inactivity deadlines.
- 4 KiB maximum ephemeral plaintext. The app currently uses these messages for
  typing indicators; media has separate protocols.
- 1 MiB maximum expanded serialized document change, 65,536 operations,
  1,048,576 logical column values/group entries, 1 MiB expanded column strings.
  Writers enforce the same limits and roll back rejected local edits.
  Declared dependency ancestry must justify actor sequence, operation counters
  and object references. Counters may have gaps but cannot overlap causal
  history or exceed the upstream graph's 32-bit counter storage.
- 4,096 unresolved membership operations total, 256 per author. These quotas
  do not block a ready administrator operation.
- 256 provisional/pending invitations total and 32 per inviter. Because known
  contacts are classified after admission, a full provisional queue can also
  defer a new contact's invitation until a slot is freed.

## Encryption and compression

Messages use XChaCha20-Poly1305 with per-epoch keys distributed through HPKE
lockboxes, authenticated membership and signed envelopes. Attachments use
independent random keys and authenticated streaming encryption. Relays do not
receive plaintext content keys. The review did not establish an encryption
bypass; the routing-cache defect concerns routing metadata and availability.

This design does **not** provide Signal-style per-message forward secrecy or
post-compromise recovery. A stolen long-lived device secret plus retained
lockboxes/history can expose historical epoch keys. Revocation does not erase
anything a former member already received. Changing that requires a reviewed
protocol and retention design, not a cipher substitution.

Blanket compression is not implemented. Automerge already compresses changes;
bounded decoding is mandatory. Ciphertext is not usefully compressible. A future
attachment codec must run before encryption, have explicit decoded-size limits,
and avoid mixing secrets with attacker-controlled inputs in a shared adaptive
compression context. Compression does not provide security.

## Dependency review

`npm audit --json`: zero reported vulnerabilities in the current lockfile.
RustSec database commit `7eebec69c352c7191b1f13eb95dd510eeca5d1de` (October 9,
2026): zero entries in the main vulnerability category, **four advisories** in
warning categories. This is not a clean audit:

- `glib 0.18.5`: [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html),
  unsound iterator implementation, fixed in versions >=0.20.0. The Linux GTK
  dependency remains affected; reaching the vulnerable API from Mycel was not
  established. The advisory is not suppressed.
- `atomic-polyfill 1.0.3`: RUSTSEC-2023-0089, unmaintained.
- `paste 1.0.15`: RUSTSEC-2024-0436, unmaintained.
- `proc-macro-error 1.0.4`: RUSTSEC-2024-0370, unmaintained.

`cargo audit --deny unsound` exits unsuccessfully because of `glib`.
`scripts/security-check.sh` deliberately preserves that failing gate and does
not retry failed security tests. It requires the normal build dependencies and
`cargo-audit`; it does not install tools or modify audit exceptions.

## Remaining limits and release gates

- Real-device Keychain migration, lock/unlock/background behavior, app upgrades,
  reinstalls and backup/restore need device validation. Mock fault injection and
  cross-compilation do not establish these properties. The separately installed
  iPhone build has not been replaced by this security branch.
- Only iOS uses the new native secure store. Other platforms retain file-backed
  identities. Unix profiles are restricted to 0700 and new seeds to 0600;
  Windows relies on the user's profile ACL and has no native vault migration.
- Downloaded attachments are plaintext inside the app's private files directory.
  Application-level database encryption, attachment-cache encryption/expiry,
  backup exclusion, app-switcher redaction and biometric app locking are not
  implemented by this patch. OS sandbox/data protection remains relevant.
- Transport encryption does not hide peer identity, IP address, traffic timing,
  packet sizes, local discovery names or all routing metadata. There is no
  anonymity guarantee.
- Concurrent remote blob reservations do not set a cumulative accepted-member
  storage quota. Local upload staging/decryption is not in that shared pool.
  Pending requests are count-bounded, but the history of each accepted or pending
  space has no cumulative byte quota. Task cancellation cleans eager push
  stages, but abrupt process death can leave them on disk.
- A genuinely valid membership frontier exceeding the protocol's 64-parent
  bound remains a protocol limitation. Valid heads must never be silently
  truncated to make authoring succeed.
- Encoded-byte reservations do not constitute a whole-process heap cap.
  Cryptographic validation, decoded objects, history, call/video codecs and
  platform networking have additional costs. Resource exhaustion is reduced,
  not eliminated. Transactional document application clones state, validates a
  dependency-only fork and traverses causal ancestry; dependency retries can
  rescan history. Large-document performance needs measurement.
- Linux and Windows runtime behavior, Android runtime behavior, long-duration
  fuzzing, physical-device compromise and a third-party cryptographic audit are
  outside the completed validation. Native dependencies/codecs remain additional
  attack surfaces.

Reference criteria: [OWASP MASVS](https://mas.owasp.org/MASVS/),
[Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services),
[Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/),
and [MLS, RFC 9420](https://www.rfc-editor.org/info/rfc9420/).
