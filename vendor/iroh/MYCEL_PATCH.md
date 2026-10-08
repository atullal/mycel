# Mycel's patch to Iroh 1.3.0

Upstream Iroh 1.3 opens extra QUIC multipath paths only for IP (via hole
punching) and relay addresses. Custom-transport addresses (Mycel's
peer-to-peer Wi-Fi and Bluetooth links) were used only if they were the
first path, so losing that path killed the connection.

Change (all in `src/socket/remote_map/remote_state.rs`, marked `MYCEL PATCH`):

1. When a client connection is registered, every known custom-transport
   address for the remote is opened as a (backup) path.
2. Custom addresses learned later (address lookup results, or addresses
   passed to `connect`) are queued and opened on all live connections.

3. Every custom-transport path on every connection is pinged once a
   second (`ping_link_paths`). noq re-arms a path's keepalive only when a
   packet arrives on it and may acknowledge on any path, so on a quiet
   backup path one side could stop sending on it and the other side's
   5 s path idle timeout closed it: a call that had been running for a
   while could then not fail over from peer-to-peer Wi-Fi to Bluetooth.

Path *selection* is unchanged in Iroh; Mycel installs its own
`PathSelector` (`mycel_net::link::MycelPathSelector`).

Covered by `crates/mycel-net/tests/links.rs`
(`live_connection_moves_to_another_link`) and, for 3,
`crates/mycel-call/tests/calls.rs` (`call_moves_from_peer_wifi_to_bluetooth`). Drop this patch once upstream
opens custom paths itself.
