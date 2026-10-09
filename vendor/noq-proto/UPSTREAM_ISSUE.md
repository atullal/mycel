# Draft report for n0-computer/noq (NOT FILED)

> **Before filing:** a peer can probably trigger this remotely. A malicious
> server could abandon a client's path 0 and then send HANDSHAKE_DONE late,
> and together with the poisoned-lock abort that crashes the client process.
> Consider reporting it privately (a GitHub security advisory) rather than as
> a public issue. Ask the project owner before sending anything.

---

**Title:** Panic in `discard_space` when HANDSHAKE_DONE arrives after PathId::ZERO was discarded (multipath), and the panic aborts the process

**Version:** noq-proto 1.3.0, noq 1.3.0 (via iroh 1.3.0)

## What happens

A multipath client panics:

```
thread 'tokio-rt-worker' panicked at noq-proto-1.3.0/src/connection/mod.rs:4172:
PathId::ZERO is alive while Initial/Handshake spaces exist
```

The panic happens while noq's connection lock is held, so the lock is
poisoned. Stream and path handles lock it in `Drop` with `.unwrap()`, so
during unwinding the process aborts with "thread caused non-unwinding panic.
aborting." One misbehaving connection kills every connection in the process.

## Why

- The client becomes Established when it receives the server's Finished.
  Multipath is then usable, but the handshake isn't confirmed until
  HANDSHAKE_DONE arrives.
- The server sends HANDSHAKE_DONE in one packet and the first
  PATH_NEW_CONNECTION_ID frames in another. If the packet with HANDSHAKE_DONE
  is lost, the client can still open path 1.
- If path 0 is then abandoned and discarded, the retransmitted HANDSHAKE_DONE
  arrives on path 1. Ways for path 0 to go:
  - the application closes it (iroh closes redundant IP paths);
  - its idle timeout fires;
  - the peer abandons it.
- `Frame::HandshakeDone` calls `discard_space(SpaceKind::Handshake)`, which
  `expect`s `self.paths[PathId::ZERO]`.

We hit it under heavy loss and delay: hundreds of nodes on one machine, with
iroh opening extra (custom-transport) paths as soon as a client connection
registers.

## Reproduction

A deterministic test with the existing harness: `src/tests/multipath.rs`,
`late_handshake_done_after_path_zero_discarded`, in our patch. It:
1. drops every client-bound packet carrying HANDSHAKE_DONE (decoded with
   `decode_packet` + `frame::Iter`);
2. opens path 1 and closes path 0;
3. steps until `PathEvent::Discarded { id: PathId::ZERO }`;
4. lets HANDSHAKE_DONE through.

On 1.3.0 it panics at `mod.rs:4172`.

## Suggested fixes

1. `discard_space`: if `PathId::ZERO` no longer exists, skip the in-flight
   cleanup and loss-timer update, since its packets died with the path:

   ```rust
   let Some(path) = self.paths.get_mut(&PathId::ZERO) else { return };
   ```

   Alternatively, don't allow abandoning PathId::ZERO before the handshake
   is confirmed. That can't stop the peer or an idle timeout, though.

2. noq: make a state-machine panic close only that connection. Options:
   - recover poisoned guards in `Mutex::lock`;
   - wrap `ConnectionDriver::poll` in `catch_unwind`;
   - on a panic, terminate the connection with INTERNAL_ERROR and send
     `EndpointEvent::drained()`.

   Our patch does all three and has a test that injects a driver panic
   (`driver_panic_closes_only_that_connection`).

Both patches are about 40 lines. We're happy to open a PR.
