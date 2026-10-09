# Mycel's patch to Iroh 1.3.0

Upstream Iroh 1.3 opens extra QUIC multipath paths only for IP (via hole
punching) and relay addresses. Custom-transport addresses (Mycel's
peer-to-peer Wi-Fi and Bluetooth links) were used only if they were the
first path, so losing that path killed the connection.

Changes (all in `src/socket/remote_map/remote_state.rs`, marked `MYCEL PATCH`):

1. When a client connection is registered, every known custom-transport
   address for the remote is opened as a (backup) path.
2. Custom addresses learned later (address lookup results, or addresses
   passed to `connect`) are queued and opened on all live connections.

3. Every path on every connection is pinged once a second
   (`ping_link_paths`; first only custom-transport paths, now all). noq
   re-arms a path's keepalive only when a packet arrives on it and may
   acknowledge on any path, so on a quiet backup path one side could stop
   sending on it and the other side's 5 s path idle timeout closed it: a
   call that had been running for a while could then not fail over from
   peer-to-peer Wi-Fi to Bluetooth. Pinging every path also means a live
   path always *receives* something each second, which the selector uses
   to spot a dead path (nothing received for 3 s) before its idle timeout.
   That matters with several connections to one peer (Mycel's pooled
   connection plus a call): Iroh selects one path across all of them and
   re-opens it on every client connection, so a dead path that one
   connection still lists would otherwise be re-opened on the others.

4. **Several Available paths (bandwidth aggregation).** noq already
   schedules packets on every validated path whose local status is
   `PathStatus::Available` (`Connection::scheduling_info`): `poll_transmit`
   walks the paths in path-id order and each one sends until its own
   congestion window (and pacer) is full, so with two Available paths the
   first fills its window and the overflow goes to the second. Upstream
   Iroh marks only the selected path Available, so the others idled. The
   patch:
   - `PathSelection::also_use(&path)`: a selector may name extra paths to
     send on. They are kept in `State::also_available` (replaced on every
     selection; empty for selectors that never call it, so upstream
     behaviour is unchanged for them).
   - `path_status_for_addr` returns Available for the selected path *and*
     the `also_available` ones; all others stay Backup.
   - `apply_selected_path` does not close an `also_available` IP path as a
     redundant IP path (the selector decides which IP paths are distinct
     interfaces worth keeping; the rest are still closed as before).
   - selection re-runs every second (on the link-ping tick), not only
     when a path opens or closes, so the Available set follows RTT, loss
     and rate.

5. **Each path to open is queued once** (`State::queue_open_paths`).
   - When a path can't be opened yet (`RemoteCidsExhausted` or
     `MaxPathIdReached`), upstream queues its address for a retry in
     333 ms, once per connection that failed. Every lookup result (patch 2)
     also re-adds every custom address.
   - With several connections to one remote, the queue multiplied with each
     retry. Mycel has several: the pooled connection, calls and other
     protocols. More links than the 8 path IDs per connection is easy for a
     device on the move.
   - In the 30-walker `shutdown` simulation that peaked at 30 GB, with one
     core busy re-trying. Now an address already queued isn't queued again.
   - Covered by `crates/mycel-net/tests/path_queue.rs`: 16 links and 4
     connections. Memory stays flat with the fix and grows ~4 MB a second
     without it.

Path *selection* policy lives in Mycel: `mycel_net::link::MycelPathSelector`
picks the selected path and which other paths join the aggregate.

Covered by `crates/mycel-net/tests/aggregate.rs` (two rate-limited links
≈ 1.9× one link on one stream; a cut link; a slow link never slows a fast one).

Covered by `crates/mycel-net/tests/links.rs`
(`live_connection_moves_to_another_link`) and, for 3,
`crates/mycel-call/tests/calls.rs` (`call_moves_from_peer_wifi_to_bluetooth`). Drop this patch once upstream
opens custom paths itself.
