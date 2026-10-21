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

6. **Addresses found after a connection is up reach it**
   (`Endpoint::add_remote_addrs`; `ActorMessage::AddRemoteAddrs`,
   `RemoteMap::add_remote_addrs`, `RemoteStateMessage::AddAddrs`).
   - Patch 2 opens custom addresses that Address Lookup returns. But a remote
     runs Address Lookup only while it has no selected path, so a link or
     mesh route found after the connection came up was never opened on it.
     Mycel's `MemoryLookup` is pull-based and nothing pulled.
   - Seen as `two_routes_aggregate_and_fail_over` failing ~35% of runs: when
     the second mesh route was announced a moment after `connect`, the
     connection kept one path.
   - The new method hands a remote's actor addresses directly. It inserts
     them, then queues every custom address to open on the live
     connections, as patch 2 does. It starts no Address Lookup, and it does
     nothing for a remote without an actor. Learning mesh routes to many
     devices therefore costs nothing until one of them is connected.
   - Mycel calls it whenever a link or mesh route adds an address
     (`Inner::open_on_live_connections`).
   - Covered by `crates/mycel-net/tests/mesh.rs`
     (`a_route_found_later_joins_the_live_connection`).

7. **A path QUIC finds dead triggers a new selection**
   (`RemoteStateActor::handle_path_event`, `NoqPathEvent::Unresponsive`).
   noq (vendor/noq-proto/MYCEL_PATCH.md §3) emits the event when a path
   stopped carrying anything and moves its data to the other paths. Iroh then
   runs the path selector at once instead of at the next one-second tick. The
   selector sees the path's `PathStats::unresponsive_from` and passes it over.
   Covered by `crates/mycel-net/tests/links.rs`
   (`live_connection_moves_to_another_link`): the backup link is selected when
   the transfer finishes, 0.2–0.3 s after the cut.

Path *selection* policy lives in Mycel: `mycel_net::link::MycelPathSelector`
picks the selected path and which other paths join the aggregate.

Covered by `crates/mycel-net/tests/aggregate.rs` (two rate-limited links
≈ 1.9× one link on one stream; a cut link; a slow link never slows a fast one).

Covered by `crates/mycel-net/tests/links.rs`
(`live_connection_moves_to_another_link`) and, for 3,
`crates/mycel-call/tests/calls.rs` (`call_moves_from_peer_wifi_to_bluetooth`). Drop this patch once upstream
opens custom paths itself.

Packaging: the crate's own `Cargo.lock` from the published package is not
kept. Iroh has no `[workspace]` table here, so it is a member of Mycel's
workspace and builds from the workspace's `Cargo.lock`; the stale copy only
made vulnerability scanners report versions Mycel never builds.
