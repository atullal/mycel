# Mycel's patch to noq-proto 1.3.0 and noq 1.3.0

noq is the QUIC implementation under Iroh 1.3 (`vendor/iroh`). Both crates
are vendored unchanged except for the lines marked `MYCEL PATCH`, and wired
in with `[patch.crates-io]` in the workspace `Cargo.toml`. Each has its own
`[workspace]` table so its own test suite still runs:

```sh
CARGO_TARGET_DIR=target/noq cargo test --manifest-path vendor/noq-proto/Cargo.toml --lib
CARGO_TARGET_DIR=target/noq cargo test --manifest-path vendor/noq/Cargo.toml --lib
```

## 1. noq-proto: a late HANDSHAKE_DONE after path 0 was discarded panicked

`src/connection/mod.rs`, `Connection::discard_space`.

A multipath client is Established, and may open paths and abandon
`PathId::ZERO`, one round trip before HANDSHAKE_DONE confirms the handshake.
noq-proto puts HANDSHAKE_DONE and the server's first path CIDs in different
packets. If the packet with HANDSHAKE_DONE is lost, the client can still open
path 1 with those CIDs. If path 0 is then abandoned (Iroh closing a redundant
IP path, a path idle timeout, or the server abandoning it) and discarded, the
retransmitted HANDSHAKE_DONE arrives on path 1. `discard_space(Handshake)` then
did
`self.paths.get_mut(&PathId::ZERO).expect("PathId::ZERO is alive while Initial/Handshake spaces exist")`
and panicked.

Seen in Mycel's simulator: `conference` at 300 real nodes under heavy memory
pressure, where loss and delay are high (docs/SIMULATION.md §4).

**Fix:** if `PathId::ZERO` is gone, there is no in-flight state left to clean
up, because its packets died with the path. Return instead of panicking.

**Test:** `tests::multipath::late_handshake_done_after_path_zero_discarded`.
The client loses every packet carrying HANDSHAKE_DONE, opens path 1, closes
path 0 and waits for it to be discarded. Then HANDSHAKE_DONE gets through.
Upstream 1.3.0 panics at `mod.rs:4172`, the same line as the simulator crash.

## 2. noq: a panic in one connection aborted the process

`src/mutex.rs` and `src/connection.rs` (`ConnectionDriver::poll`).

The connection driver polls the state machine while holding the connection's
lock. A panic in that state machine (above) poisoned the lock. Stream and path
handles lock it in their `Drop`, so while the panic unwound,
`lock().unwrap()` panicked again. A panic while panicking aborts: one bad
connection took the whole Mycel node down.

**Fix:**
- `Mutex::lock` recovers a poisoned guard instead of panicking.
- `ConnectionDriver::poll` runs the driver under `catch_unwind`. On a panic it:
  - closes that connection with `TransportError(INTERNAL_ERROR)`, so pending
    and future calls fail with that error;
  - tells the endpoint the connection is drained, so it forgets the
    connection's IDs;
  - never drives that state machine again.
- Other connections and the endpoint carry on.

**Test:** `tests::driver_panic_closes_only_that_connection` (in noq). A
test-only hook makes one connection's driver panic while it has live streams.
That connection must close with INTERNAL_ERROR, and a new connection on the
same endpoint must still work. Upstream 1.3.0 aborts the test process with
"thread caused non-unwinding panic. aborting."

## Upstream report (draft, not filed)

The text is in `vendor/noq-proto/UPSTREAM_ISSUE.md`.

**Drop this patch** once upstream releases fixes for both.
