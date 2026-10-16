//! End-to-end evidence for the router: whether our QUIC connections' mesh
//! paths get anything back.
//!
//! A relay that keeps announcing a route and drops what it is given (a black
//! hole that lies plausibly) can't be refuted from announcements. What it
//! can't fake is the far end's packets: QUIC counts a frame only once it
//! has decrypted and authenticated the packet carrying it, so a relay can
//! drop them but not make them up. Each connection to a device we reach
//! through the mesh is watched path by path (`mesh(dst, via)` is the path
//! through first hop `via`): a path we keep sending on that has had no
//! authenticated frame back for [`SILENT`] (both ends send keep-alives every
//! 1.5 s, and acknowledge them) is reported to the router, as is its closing
//! while still silent (QUIC gives a path up after 5 s of that). Frames
//! arriving again clear it. The router decides
//! ([`Router::path_feedback`](super::core::Router::path_feedback)): only a
//! mesh route that still claims the destination is judged, and only after
//! a silence scaled to the route's cost, so a slow or lossy radio isn't
//! blamed. Paths through gateways, the internet or a direct link aren't
//! mesh routes and aren't judged.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::TransportAddr;
use iroh::endpoint::{Connection, FrameStats, PathId};
use mycel_crypto::SignPk;

use super::core::Time;
use super::wire::parse_mesh_addr;
use super::{Driver, Mesh, to_sign_pk};

/// How often a connection's paths are looked at.
const POLL: Duration = Duration::from_millis(500);
/// No authenticated frame back for this long on a path we send on: silent.
/// (Keep-alives go both ways every 1.5 s; QUIC drops a path after 5 s.)
const SILENT: Duration = Duration::from_secs(3);

/// What we saw of one path when its authenticated frames last moved.
struct Seen {
    rx: u64,
    tx: u64,
    since: Instant,
    /// When we last reported it silent (once per [`SILENT`]).
    reported: Option<Instant>,
    dst: SignPk,
    via: SignPk,
}

/// Every frame QUIC counted on a path: each from a packet it authenticated.
fn authed(f: &FrameStats) -> u64 {
    [
        f.acks,
        f.path_acks,
        f.ping,
        f.stream,
        f.datagram,
        f.crypto,
        f.max_data,
        f.max_stream_data,
        f.new_connection_id,
        f.path_new_connection_id,
        f.path_challenge,
        f.path_response,
        f.immediate_ack,
        f.ack_frequency,
    ]
    .iter()
    .fold(0u64, |a, x| a.saturating_add(*x))
}

impl Mesh {
    /// Watch an end-to-end connection's mesh paths for the router (see the
    /// module docs). Each connection is watched once, until it closes.
    pub fn watch(&self, conn: &Connection) {
        self.d.watch(conn.clone());
    }

    /// The first hops of the routes to `dst` offered as QUIC paths now.
    pub fn offered(&self, dst: &SignPk) -> Vec<SignPk> {
        self.d.router.lock().offered(dst)
    }

    /// Tests: as a relay, drop every frame to or from `dst` while still
    /// announcing routes to it (a black hole).
    pub fn set_black_hole(&self, dst: Option<SignPk>) {
        *self.d.black_hole.lock() = dst;
    }
}

impl Driver {
    fn watch(self: &Arc<Self>, conn: Connection) {
        if !self.watched.lock().insert(conn.stable_id()) {
            return;
        }
        let d = self.clone();
        self.keep(tokio::spawn(async move { d.watch_paths(conn).await }));
    }

    async fn watch_paths(self: Arc<Self>, conn: Connection) {
        let peer = to_sign_pk(&conn.remote_id());
        let id = conn.stable_id();
        let mut seen: HashMap<PathId, Seen> = HashMap::new();
        let closed = conn.closed();
        tokio::pin!(closed);
        loop {
            tokio::select! {
                _ = &mut closed => break,
                _ = tokio::time::sleep(POLL) => {}
            }
            if self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            // (dst, via, silent since): None = frames are arriving again
            let mut verdicts: Vec<(SignPk, SignPk, Option<Instant>)> = Vec::new();
            {
                let paths = conn.paths();
                let mut open = Vec::new();
                for p in paths.iter() {
                    let TransportAddr::Custom(a) = p.remote_addr() else { continue };
                    let Some((dst, via)) = parse_mesh_addr(a) else { continue };
                    if dst != peer || via == dst {
                        continue;
                    }
                    open.push(p.id());
                    let st = p.stats();
                    let (rx, tx) = (authed(&st.frame_rx), st.udp_tx.datagrams);
                    let e = seen.entry(p.id()).or_insert(Seen { rx, tx, since: now, reported: None, dst, via });
                    if rx != e.rx {
                        if e.reported.is_some() {
                            verdicts.push((dst, via, None));
                        }
                        *e = Seen { rx, tx, since: now, reported: None, dst, via };
                    } else if tx > e.tx
                        && now.duration_since(e.since) >= SILENT
                        && e.reported.is_none_or(|t| now.duration_since(t) >= SILENT)
                    {
                        e.reported = Some(now);
                        verdicts.push((dst, via, Some(e.since)));
                    }
                }
                // a path that closed while silent: QUIC gave it up
                seen.retain(|pid, e| {
                    let keep = open.contains(pid);
                    if !keep && e.reported.is_some() {
                        verdicts.push((e.dst, e.via, Some(e.since)));
                    }
                    keep
                });
            }
            for (dst, via, silent) in verdicts {
                let since = silent.map(|t| t.saturating_duration_since(self.base).as_millis() as Time);
                let judged = self.with_router(|r, now| r.path_feedback(dst, via, since, now));
                if judged && let Some(c) = &self.carrier {
                    c.lock().doubt(dst, self.now());
                }
            }
        }
        self.watched.lock().remove(&id);
    }
}
