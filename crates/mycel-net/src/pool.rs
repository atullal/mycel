//! One long-lived QUIC connection per peer, shared by every exchange (each
//! one a QUIC stream on it).
//!
//! Modelled on `iroh_util::connection_pool` (the pool iroh-blobs uses), which
//! we can't use as is: its actor keeps a sender to itself, so it never stops
//! and holds the `Endpoint` (and its UDP socket) after the node shuts down;
//! a node restarted in the same process can't bind its port again.
//!
//! - one dial at a time per peer; everyone else waits for it and shares it;
//! - a connection that has closed is replaced on the next use;
//! - one with no stream in use for [`crate::POOL_IDLE`] is closed;
//! - [`Pool::shutdown`] drops everything.
//!
//! A dial offers every wire version the node speaks (newest first, see
//! [`crate::wire::alpns`]); the entry remembers the one the handshake chose
//! and, on version 2 and later, the capabilities agreed in the hello
//! (`crate::start_hello`). A hello that fails (a stream lost on a flaky
//! Bluetooth or multi-hop path, a timeout) is tried again on a later use of
//! the connection, at most [`HELLO_TRIES`] times in all and no sooner than
//! [`HELLO_RETRY`] (doubling) after the last failure; until one succeeds
//! the connection has no capabilities.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use iroh::Endpoint;
use iroh::endpoint::{ConnectOptions, Connection};
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::version::{PeerProtocol, WireVersion};
use crate::{CONNECT_TIMEOUT, to_endpoint_id, wire};

/// Most capability hellos sent on one connection (the first and retries).
pub(crate) const HELLO_TRIES: u32 = 3;
/// How long after a failed hello the next one may go; doubled after each.
pub(crate) const HELLO_RETRY: Duration = if cfg!(test) { Duration::from_millis(300) } else { Duration::from_secs(30) };

/// Where a connection's capability hello stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HelloState {
    /// Not sent yet: the connection was just dialed.
    Due,
    /// On its way (`tries` failed before it).
    Sending { tries: u32 },
    /// The last one failed at `at`; `tries` have failed in all.
    Failed { at: Instant, tries: u32 },
    /// Agreed (or version 1, which has no hello), or out of tries.
    Done,
}

struct Entry {
    conn: Connection,
    /// Exchanges using it right now, and when the last one ended.
    users: AtomicUsize,
    last_used: Mutex<Instant>,
    /// The wire version the handshake chose.
    version: WireVersion,
    /// What was agreed with the peer: set once its hello has been answered
    /// (at once on version 1, which has none), or failed.
    protocol: watch::Sender<Option<PeerProtocol>>,
    hello: Mutex<HelloState>,
}

#[derive(Default)]
struct Slot {
    /// Serialises dialing.
    dial: tokio::sync::Mutex<()>,
    entry: Mutex<Option<Arc<Entry>>>,
}

pub(crate) struct Pool {
    endpoint: Endpoint,
    /// The node protocol's ALPNs we offer, newest first.
    alpns: Vec<&'static [u8]>,
    slots: Mutex<HashMap<SignPk, Arc<Slot>>>,
    /// Connections dialed so far (each one a QUIC handshake).
    pub(crate) dialed: AtomicU64,
}

/// A pooled connection, held while one exchange uses it.
pub(crate) struct PooledConn {
    entry: Arc<Entry>,
}

impl PooledConn {
    /// The wire version the handshake chose.
    pub(crate) fn version(&self) -> WireVersion {
        self.entry.version
    }

    /// Another lease on the same connection (for a task of its own).
    pub(crate) fn share(&self) -> PooledConn {
        lease(&self.entry)
    }

    /// Whether this lease should send the connection's hello: the
    /// connection was just dialed, or its last hello failed long enough ago
    /// and tries are left. True for one caller only; that caller then
    /// reports the outcome ([`Self::set_protocol`] or
    /// [`Self::hello_failed`]). Until a retry's outcome, the connection's
    /// protocol is unknown again, so whoever needs a capability waits for it.
    pub(crate) fn claim_hello(&self) -> bool {
        let mut hello = self.entry.hello.lock();
        let tries = match *hello {
            HelloState::Due => 0,
            HelloState::Failed { at, tries } if tries < HELLO_TRIES && at.elapsed() >= retry_after(tries) => {
                self.entry.protocol.send_replace(None);
                tries
            }
            _ => return false,
        };
        *hello = HelloState::Sending { tries };
        true
    }

    /// Record what was agreed with the peer (the hello's outcome).
    pub(crate) fn set_protocol(&self, p: PeerProtocol) {
        *self.entry.hello.lock() = HelloState::Done;
        self.entry.protocol.send_replace(Some(p));
    }

    /// The hello failed: no capabilities for now (`baseline`), and another
    /// try on a later use if any are left. Returns how many have failed.
    pub(crate) fn hello_failed(&self, baseline: PeerProtocol) -> u32 {
        let mut hello = self.entry.hello.lock();
        let tries = match *hello {
            HelloState::Sending { tries } => tries + 1,
            _ => 1,
        };
        *hello = if tries < HELLO_TRIES { HelloState::Failed { at: Instant::now(), tries } } else { HelloState::Done };
        self.entry.protocol.send_replace(Some(baseline));
        tries
    }

    /// What was agreed with the peer, waiting up to `wait` for its hello
    /// (sent as soon as the connection is up, so normally one round trip).
    /// No answer by then: the version's baseline, no capabilities.
    pub(crate) async fn protocol(&self, wait: Duration) -> PeerProtocol {
        let mut rx = self.entry.protocol.subscribe();
        let got = tokio::time::timeout(wait, rx.wait_for(Option::is_some)).await;
        match got {
            Ok(Ok(p)) => p.expect("waited for Some"),
            _ => PeerProtocol::baseline(self.entry.version),
        }
    }
}

impl Deref for PooledConn {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.entry.conn
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        *self.entry.last_used.lock() = Instant::now();
        self.entry.users.fetch_sub(1, Ordering::SeqCst);
    }
}

fn lease(entry: &Arc<Entry>) -> PooledConn {
    entry.users.fetch_add(1, Ordering::SeqCst);
    PooledConn { entry: entry.clone() }
}

/// How long after the `tries`-th failed hello the next may go.
fn retry_after(tries: u32) -> Duration {
    HELLO_RETRY * 2u32.saturating_pow(tries.saturating_sub(1))
}

impl Pool {
    /// Dials offer wire versions `newest` down to the oldest supported.
    pub(crate) fn new(endpoint: Endpoint, newest: WireVersion) -> Self {
        Pool { endpoint, alpns: wire::alpns(newest), slots: Mutex::default(), dialed: AtomicU64::new(0) }
    }

    fn slot(&self, peer: &SignPk) -> Arc<Slot> {
        self.slots.lock().entry(*peer).or_default().clone()
    }

    fn live(slot: &Slot) -> Option<PooledConn> {
        let entry = slot.entry.lock();
        entry.as_ref().filter(|e| e.conn.close_reason().is_none()).map(lease)
    }

    /// The connection to `peer`, dialing it if there is no live one.
    pub(crate) async fn get(&self, peer: &SignPk) -> Result<PooledConn> {
        let slot = self.slot(peer);
        if let Some(c) = Self::live(&slot) {
            return Ok(c);
        }
        let _dialing = slot.dial.lock().await;
        if let Some(c) = Self::live(&slot) {
            return Ok(c); // someone else just dialed it
        }
        let id = to_endpoint_id(peer)?;
        let (first, rest) = self.alpns.split_first().expect("at least one version");
        let options = ConnectOptions::new().with_additional_alpns(rest.iter().map(|a| a.to_vec()).collect());
        let connect = async {
            let connecting = self.endpoint.connect_with_opts(id, first, options).await?;
            anyhow::Ok(connecting.await?)
        };
        let conn = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(anyhow!("can't reach the device: {e}")),
            Err(_) => return Err(anyhow!("can't reach the device: connect timed out")),
        };
        self.dialed.fetch_add(1, Ordering::Relaxed);
        // (the handshake can only pick one of the ALPNs we offered)
        let Some(version) = wire::version_of(conn.alpn()) else {
            conn.close(0u32.into(), b"unexpected protocol");
            return Err(anyhow!("can't reach the device: it chose a protocol we didn't offer"));
        };
        let entry = Arc::new(Entry {
            conn,
            users: AtomicUsize::new(0),
            last_used: Mutex::new(Instant::now()),
            version,
            protocol: watch::Sender::new(None),
            hello: Mutex::new(HelloState::Due),
        });
        let leased = lease(&entry);
        *slot.entry.lock() = Some(entry);
        Ok(leased)
    }

    /// Stop using the connection to `peer` (it died); the next use redials.
    pub(crate) fn forget(&self, peer: &SignPk) {
        if let Some(slot) = self.slots.lock().get(peer) {
            slot.entry.lock().take();
        }
    }

    /// Close connections nobody has used for `idle`, and drop closed ones.
    pub(crate) fn reap(&self, idle: Duration) {
        let slots: Vec<Arc<Slot>> = self.slots.lock().values().cloned().collect();
        for slot in slots {
            let mut entry = slot.entry.lock();
            let Some(e) = entry.as_ref() else { continue };
            let unused = e.users.load(Ordering::SeqCst) == 0 && e.last_used.lock().elapsed() >= idle;
            if e.conn.close_reason().is_some() {
                entry.take();
            } else if unused {
                e.conn.close(0u32.into(), b"idle");
                entry.take();
            }
        }
        self.slots.lock().retain(|_, s| s.entry.lock().is_some() || s.dial.try_lock().is_err());
    }

    pub(crate) fn shutdown(&self) {
        for (_, slot) in self.slots.lock().drain() {
            if let Some(e) = slot.entry.lock().take() {
                e.conn.close(0u32.into(), b"shutdown");
            }
        }
    }
}
