//! A device's own record, kept published, and other devices' records,
//! looked up: the two halves of finding a device by its key with no server
//! of ours (`directory.rs` has the format and the backends).
//!
//! [`OwnRecord`] is an Iroh address lookup: Iroh tells it the endpoint's
//! addresses whenever they change, the mesh tells it the device's
//! [`Role`], and it signs the record and publishes it in every directory
//! backend, again when either changes and every [`REPUBLISH`]. It replaces
//! Iroh's own publisher, so one record says everything, everywhere.
//!
//! Which addresses go in it:
//! - relay servers: always (they don't say where the device is);
//! - IP addresses: only while the device is *public* (it relays for
//!   others, or it is reachable and uses no relay server). Then anyone who
//!   knows its key learns its address, which is what being dialed directly
//!   takes. A device behind a router publishes none: they would help
//!   nobody, and its relays are how it is reached.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iroh::TransportAddr;
use iroh::address_lookup::{AddressLookup, Error, Item};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use mycel_crypto::{DeviceKeys, SignPk};
use n0_future::boxed::BoxStream;
use parking_lot::Mutex;

use super::directory::{self, Directory, Role};

/// The record is published again this often even if nothing changed (it
/// says it is valid for [`directory::RECORD_LIFETIME`]).
pub const REPUBLISH: Duration = Duration::from_secs(5 * 60);
/// After a change, wait this long for the next one before publishing.
const SETTLE: Duration = Duration::from_millis(500);
/// When no backend took the record, try again after this long.
const RETRY: Duration = Duration::from_secs(30);
/// How long a lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Content {
    addrs: Vec<TransportAddr>,
    role: Role,
}

#[derive(Debug, Default)]
struct State {
    /// The endpoint's addresses, as Iroh last told us.
    addrs: Vec<TransportAddr>,
    role: Role,
    /// Publish IP addresses (see the module docs).
    public: bool,
}

/// This device's record: built from what Iroh and the mesh say, published
/// by [`OwnRecord::run`].
pub struct OwnRecord {
    keys: Arc<DeviceKeys>,
    dir: Arc<dyn Directory>,
    state: Mutex<State>,
    wake: tokio::sync::Notify,
    published: AtomicU64,
    /// Publish only IP addresses the whole internet can use: not private,
    /// loopback or link-local ones (tests on one machine turn it off).
    global_only: bool,
}

impl std::fmt::Debug for OwnRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnRecord({})", self.keys.sign_pk().short())
    }
}

/// Whether the whole internet can route to `ip`.
pub fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // carrier-grade NAT (100.64/10) and benchmarking (198.18/15)
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] == 0
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // global unicast (2000::/3), less documentation (2001:db8::/32)
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

impl OwnRecord {
    pub fn new(keys: Arc<DeviceKeys>, dir: Arc<dyn Directory>, global_only: bool) -> Arc<Self> {
        Arc::new(OwnRecord {
            keys,
            dir,
            state: Mutex::default(),
            wake: tokio::sync::Notify::new(),
            published: AtomicU64::new(0),
            global_only,
        })
    }

    /// The device's role, and whether its IP addresses are published.
    pub fn set_role(&self, role: Role, public: bool) {
        let mut s = self.state.lock();
        if s.role != role || s.public != public {
            s.role = role;
            s.public = public;
            drop(s);
            self.wake.notify_one();
        }
    }

    /// Records published so far.
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    fn content(&self) -> Content {
        let s = self.state.lock();
        let mut addrs: Vec<TransportAddr> = s
            .addrs
            .iter()
            .filter(|a| match a {
                TransportAddr::Relay(_) => true,
                TransportAddr::Ip(sa) => s.public && sa.port() != 0 && (!self.global_only || is_global(&sa.ip())),
                _ => false,
            })
            .cloned()
            .collect();
        addrs.sort();
        addrs.dedup();
        // a pkarr packet holds about 1000 bytes
        addrs.truncate(8);
        Content { addrs, role: s.role.clone() }
    }

    /// Keep the record published until the task is dropped.
    pub async fn run(self: Arc<Self>) {
        let mut last: Option<Content> = None;
        let mut due = Instant::now() + REPUBLISH;
        loop {
            tokio::select! {
                _ = self.wake.notified() => tokio::time::sleep(SETTLE).await,
                _ = tokio::time::sleep_until(due.into()) => {}
            }
            let now = self.content();
            let changed = last.as_ref() != Some(&now);
            if !changed && Instant::now() < due {
                continue;
            }
            // nothing to say, and nothing said before that it would replace
            let empty = now.addrs.is_empty() && now.role == Role::Plain;
            if empty && last.as_ref().is_none_or(|l| l.addrs.is_empty() && l.role == Role::Plain) {
                last = Some(now);
                due = Instant::now() + REPUBLISH;
                continue;
            }
            let sent = match directory::seal_own(&self.keys, now.addrs.clone(), &now.role) {
                Ok(rec) => self.dir.put(rec).await.is_ok(),
                Err(_) => false,
            };
            if sent {
                self.published.fetch_add(1, Ordering::Relaxed);
                last = Some(now);
                due = Instant::now() + REPUBLISH;
            } else {
                due = Instant::now() + RETRY;
            }
        }
    }
}

impl AddressLookup for OwnRecord {
    fn publish(&self, data: &EndpointData) {
        let addrs: Vec<TransportAddr> =
            data.addrs().filter(|a| !matches!(a, TransportAddr::Custom(_))).cloned().collect();
        let mut s = self.state.lock();
        if s.addrs != addrs {
            s.addrs = addrs;
            drop(s);
            self.wake.notify_one();
        }
    }
}

/// An Iroh address lookup over the directory: the addresses in a device's
/// record. (The devices that carry traffic to it are the mesh's part:
/// [`super::MeshLookup`].)
#[derive(Debug, Clone)]
pub struct DirectoryLookup {
    dir: Arc<dyn Directory>,
    me: SignPk,
}

impl DirectoryLookup {
    pub fn new(dir: Arc<dyn Directory>, me: SignPk) -> Self {
        DirectoryLookup { dir, me }
    }
}

impl AddressLookup for DirectoryLookup {
    fn resolve(&self, endpoint_id: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        use n0_future::StreamExt;
        let peer = SignPk(*endpoint_id.as_bytes());
        if peer == self.me {
            return None;
        }
        let dir = self.dir.clone();
        let stream = n0_future::stream::once_future(async move {
            let rec = tokio::time::timeout(LOOKUP_TIMEOUT, dir.get(peer)).await.ok().flatten()?;
            let rec = directory::read(&rec, Some(&peer))?;
            let addrs: Vec<TransportAddr> = rec
                .addrs
                .into_iter()
                .filter(|a| match a {
                    TransportAddr::Ip(sa) => usable(sa),
                    TransportAddr::Relay(_) => true,
                    _ => false,
                })
                .collect();
            (!addrs.is_empty()).then(|| {
                Ok(Item::new(EndpointInfo::from_parts(endpoint_id, EndpointData::new(addrs)), "mycel-directory", None))
            })
        })
        .filter_map(|x| x);
        Some(Box::pin(stream))
    }
}

/// An address worth dialing: a record can name any, so not ones that reach
/// nothing (port 0, the unspecified or a multicast address).
fn usable(sa: &SocketAddr) -> bool {
    sa.port() != 0 && !sa.ip().is_unspecified() && !sa.ip().is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::directory::MemDirectory;

    fn ip(s: &str) -> TransportAddr {
        TransportAddr::Ip(s.parse().unwrap())
    }

    #[test]
    fn only_addresses_the_internet_routes_to_are_global() {
        for a in ["8.8.8.8", "203.0.114.9", "2a00:1450:4001:81b::200e"] {
            assert!(is_global(&a.parse().unwrap()), "{a}");
        }
        for a in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.9",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::",
        ] {
            assert!(!is_global(&a.parse().unwrap()), "{a}");
        }
    }

    async fn published(dir: &MemDirectory, me: &SignPk) -> Option<directory::Record> {
        directory::read(&dir.get(*me).await?, Some(me))
    }

    async fn eventually(what: &str, mut f: impl AsyncFnMut() -> bool) {
        for _ in 0..100 {
            if f().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// A device behind a router publishes its relays and no IP address; a
    /// public one publishes the addresses the internet can use.
    #[tokio::test]
    async fn the_record_follows_addresses_and_role_and_hides_private_addresses() {
        let dir = MemDirectory::new();
        let keys = Arc::new(DeviceKeys::generate());
        let me = keys.sign_pk();
        let own = OwnRecord::new(keys, Arc::new(dir.clone()), true);
        let task = tokio::spawn(own.clone().run());
        let addrs = vec![ip("192.168.1.20:4433"), ip("198.51.100.200:0"), ip("93.184.216.34:4433")];
        own.publish(&EndpointData::new(addrs));
        // not public: no address, so nothing worth publishing yet
        tokio::time::sleep(SETTLE * 2).await;
        assert!(published(&dir, &me).await.is_none());
        // behind a router, with a relay: the relay, and still no address
        let relay = DeviceKeys::generate().sign_pk();
        own.set_role(Role::Via(vec![(relay, 150)]), false);
        eventually("the record names the relay", async || {
            published(&dir, &me).await.is_some_and(|r| r.gateways == vec![(relay, 150)] && r.addrs.is_empty())
        })
        .await;
        // it becomes a relay itself: its global address only
        own.set_role(Role::Relay, true);
        eventually("the record says relay, with the public address", async || {
            published(&dir, &me).await.is_some_and(|r| r.relay && r.addrs == vec![ip("93.184.216.34:4433")])
        })
        .await;
        // back to a plain device: the old claims are replaced
        own.set_role(Role::Plain, false);
        eventually("the record is plain again", async || {
            published(&dir, &me).await.is_some_and(|r| !r.relay && r.gateways.is_empty() && r.addrs.is_empty())
        })
        .await;
        assert!(own.published() >= 3);
        task.abort();
    }

    #[tokio::test]
    async fn lookups_return_the_addresses_in_a_record() {
        use n0_future::StreamExt;
        let dir = MemDirectory::new();
        let keys = DeviceKeys::generate();
        let id = iroh::PublicKey::from_bytes(&keys.sign_pk().0).unwrap();
        let lookup = DirectoryLookup::new(Arc::new(dir.clone()), DeviceKeys::generate().sign_pk());
        // no record: nothing
        assert!(lookup.resolve(id).unwrap().next().await.is_none());
        let rec = directory::seal_own(&keys, vec![ip("93.184.216.34:4433"), ip("0.0.0.0:1")], &Role::Relay).unwrap();
        dir.put(rec).await.unwrap();
        let item = lookup.resolve(id).unwrap().next().await.unwrap().unwrap();
        let got: Vec<TransportAddr> = item.endpoint_info().addrs().cloned().collect();
        assert_eq!(got, vec![ip("93.184.216.34:4433")]);
        // behind a router, relays only: no addresses to give (the mesh
        // lookup gives the relays)
        let rec = directory::seal_own(&keys, vec![], &Role::Via(vec![(DeviceKeys::generate().sign_pk(), 9)])).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        dir.put(rec).await.unwrap();
        assert!(lookup.resolve(id).unwrap().next().await.is_none());
    }
}
