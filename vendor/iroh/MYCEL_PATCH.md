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

Path *selection* is unchanged in Iroh; Mycel installs its own
`PathSelector` (`mycel_net::link::MycelPathSelector`).

Covered by `crates/mycel-net/tests/links.rs`
(`live_connection_moves_to_another_link`). Drop this patch once upstream
opens custom paths itself.
