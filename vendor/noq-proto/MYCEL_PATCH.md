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

## 3. noq-proto: a path that dies stalls the connection for its idle timeout and more

`src/connection/mod.rs` and `src/connection/paths.rs`, every line marked
`MYCEL PATCH (failover, MYCEL_PATCH.md §3)`. This is separate from §1 and §2,
which are being proposed upstream on their own; this section can go upstream
independently.

**Seen as:** in Mycel, a transfer over two mesh routes. When one relay leaves,
the rest of the transfer should finish over the other in ~6 s, but about 1 run
in 4 took ~23 s (`two_routes_aggregate_and_fail_over`). Traced with
instrumented noq, one run went like this:

1. **The receiver kept acknowledging on the dead path.** A packet with only
   ACKs goes on the lowest-numbered path that may send data. If that path is
   the one that died, every ACK goes into it until its idle timeout (5 s in
   Mycel). The sender hears nothing on *any* path, so its live path's window
   fills and stalls too.
2. **Data in flight on the dead path waited for the path to be discarded.**
   Abandoning a path (idle timeout) only stops new sends. The packets in flight
   are declared lost when the path is *discarded*: 3 PTOs after the peer's
   PATH_ABANDON arrives. Until then nothing retransmits them, and the receiver
   can't deliver anything after the gap.
3. **That PTO was inflated by stale ACKs.** When the receiver finally sent its
   ACKs on the live path, they included PATH_ACKs for packets of the dead path
   that it had received 5 s earlier. RFC 9002 caps the peer's reported ACK
   delay at `max_ack_delay` and takes the sample, so the dead path's RTT
   estimate jumped to seconds (pto_base 6.6 s), and its drain took 3 × 6.6 s.
   That is the 20-second stall.

**Fix** (multipath only; single-path connections behave as before):

- **A path that looks dead is passed over** (`path_unresponsive`,
  `check_unresponsive`, `scheduling_info`). It counts as dead when nothing it
  carried was acknowledged, over any path, for about 3 PTOs *and* nothing
  arrived on it for a PTO (new `PathData::last_recv`). "Not acknowledged" is
  either two probe timeouts in a row, or, on a path in constant use whose
  probe timer each send postpones, the oldest unacknowledged packet going out
  more than 3 PTOs ago.
  - Each condition alone is normal. A path whose packets are acknowledged on
    another path hears little itself. A single PTO fires now and then on a
    healthy path: an ACK held for the peer's max_ack_delay on a fast link is
    enough.
  - Once found dead, it stays dead (`unresponsive_since`) until a packet
    arrives on it or something sent on it *since* is acknowledged. Late ACKs
    for what it carried before don't revive it.
  - It is checked on every probe timeout and on every send.
  - While another validated path doesn't look dead, it gets no new data and no
    ACK-only packets. With no alternative, nothing changes.
- **The application is told.** When a path is found dead, the connection emits
  the new `PathEvent::Unresponsive { id }`. `PathStats` gains `last_recv` and
  `unresponsive_from` (when it was found dead, or `None`), so a path selector
  can see it too.
  - noq forwards the event (`vendor/noq/src/connection.rs`).
  - Iroh selects again at once on it
    (`vendor/iroh/src/socket/remote_map/remote_state.rs`).
  - Mycel's `MycelPathSelector` and `path_in_use` pass over such a path.
  - `vendor/noq/Cargo.toml` patches `noq-proto` to the vendored copy, so noq's
    own tests build against these changes.
- **ACK-only packets move off a quiet path.** They still go on the
  lowest-numbered path that may send data, as upstream, unless nothing arrived
  on it for a PTO while another path has heard from the peer since. Then they
  go on the path that heard last, even a backup path, since ACKs aren't data
  (`is_ack_path`). The receiver of a transfer usually sends nothing
  ack-eliciting, so it can't see a path die the way a sender does, but it
  does see it go quiet.
- **A dead path's data moves at once.** When a path is found dead (and on
  each later PTO on it) while another isn't, its in-flight packets are
  declared lost, so their frames are retransmitted on the other paths. A PING goes out on it instead
  of the usual probes, to notice if it comes back. When a path is abandoned
  because it went silent (`TimedOut`) or the network under it changed, its
  in-flight packets are declared lost then too (`lose_in_flight`, factored out
  of `discard_path`). A path closed by the application or the peer keeps
  upstream's behaviour, since it may still deliver what it carries. If the
  packets did arrive, the late ACKs find nothing to acknowledge, the loss
  counts as spurious, and the duplicates are discarded by the peer.
- **Stale ACKs give no RTT sample.** A peer must acknowledge within its
  max_ack_delay, so an ACK reporting more than twice that (+ timer
  granularity) is a later copy of a lost one. Its delay measures the peer's
  wait for a working path, not this path, so its RTT sample is skipped.

**Test:** `tests::multipath::data_in_flight_on_a_dead_path_moves_to_the_other`.
Two paths on separate links carry a 1 MB stream. One link silently drops
everything mid-transfer (`ManyToManyRouting::cut_link`).
- The rest must arrive within 2 s, the survivor's RTT must stay under 100 ms,
  and the client must get `PathEvent::Unresponsive` for the dead path, with
  `unresponsive_from` set in its stats.
- Upstream it takes the 10 s idle timeout plus the drain (10.2 s); with the
  patch, 0.27 s.

In Mycel, `two_routes_aggregate_and_fail_over` finishes the rest of the
transfer after losing a relay in ~6.5 s, where it took 6–25 s before.

**Drop §3** once upstream sends ACK-only packets on a working path,
retransmits a dead path's in-flight data promptly, and ignores stale ACK RTT
samples in multipath.

## Upstream report (draft, not filed)

The text is in `vendor/noq-proto/UPSTREAM_ISSUE.md`.

**Drop §1 and §2** once upstream releases fixes for both (the draft report
above covers those two; §3 would be a report of its own).
