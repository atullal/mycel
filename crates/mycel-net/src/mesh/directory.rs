//! Reachability records: how to reach a device, published under its key in
//! a global directory nobody here runs.
//!
//! A record is a **pkarr signed packet** (the format Iroh's own address
//! lookup uses), signed by the device's own key. Anyone resolves it by that
//! key, as with any Iroh endpoint. It carries the addresses to dial and, in
//! the endpoint info's user data, items separated by `|`:
//!
//! - `mycel-gw:<z32>:<cost>,…`: the devices that carry traffic to it, each
//!   with its cost to it. *Gateways*, for a device without the internet: it
//!   signs the record with no network at all and hands it to its gateways
//!   over the mesh, and they publish it. Or *relays*, for a device the
//!   internet can't dial in to: it keeps a connection up to each and
//!   publishes the record itself.
//! - `mycel-relay`: the internet can reach it, and it relays for devices
//!   that ask.
//! - `exp:<unix s>`: nobody should use the record after that.
//!
//! A record with no `mycel-gw` reads as "dial it directly" ([`open`]).
//!
//! Backends ([`Directory`]):
//! - [`PkarrDirectory`]: the BitTorrent Mainline DHT (the `dht` feature; no
//!   operator at all) and, unless switched off, the n0 pkarr relay (what
//!   Iroh resolves through by default). Lookups ask both; the newest record
//!   wins.
//! - [`MemDirectory`]: in memory, shared by the devices of one test.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use iroh::endpoint_info::{EndpointInfo, UserData};
use iroh_dns::pkarr::SignedPacket;
use mycel_crypto::{DeviceKeys, SignPk};
use n0_future::boxed::BoxFuture;
use parking_lot::Mutex;

/// What a record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reach {
    pub node: SignPk,
    /// Gateways with the device's mesh cost to each (0.1 ms units).
    pub gateways: Vec<(SignPk, u32)>,
    /// Unix seconds after which nobody should use it.
    pub expires: u64,
}

/// No `=` in user data: the TXT parser splits on it.
const PREFIX: &str = "mycel-gw:";
const RELAY: &str = "mycel-relay";
const EXPIRES: &str = "exp:";

/// Everything a record says ([`read`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub node: SignPk,
    /// The devices that carry traffic to it (gateways or relays), with its
    /// cost to each.
    pub gateways: Vec<(SignPk, u32)>,
    /// It relays for devices that ask.
    pub relay: bool,
    /// Where to dial it: IP addresses and relay servers.
    pub addrs: Vec<iroh::TransportAddr>,
    /// Unix seconds after which nobody should use it (0: it doesn't say).
    pub expires: u64,
}

/// What a device says about itself in the record it publishes ([`seal_own`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Role {
    /// Dial me at my addresses.
    #[default]
    Plain,
    /// The internet can reach me, and I relay for devices that ask.
    Relay,
    /// The internet can't dial in to me: reach me through these relays
    /// (with my cost to each).
    Via(Vec<(SignPk, u32)>),
}
/// How long a record says it is valid, and the pkarr TTL.
pub const RECORD_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// The DNS lifetime (seconds) of a device's own record, as Iroh's publisher
/// sets it: its addresses change, and a DNS cache mustn't hold old ones
/// for long. (The record itself still says it is valid for
/// [`RECORD_LIFETIME`], and is published again every few minutes.)
const OWN_TTL: u32 = 30;

fn unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn to_id(pk: &SignPk) -> Option<iroh::EndpointId> {
    iroh::PublicKey::from_bytes(&pk.0).ok()
}

/// Sign `gateways` as our record (no network needed).
pub fn seal(keys: &DeviceKeys, gateways: &[(SignPk, u32)]) -> Result<Bytes> {
    let secret = iroh::SecretKey::from_bytes(&keys.seed());
    let mut s = String::from(PREFIX);
    for (i, (g, c)) in gateways.iter().take(3).enumerate() {
        if i > 0 {
            s.push(',');
        }
        let id = to_id(g).context("bad gateway key")?;
        s.push_str(&format!("{}:{c}", id.to_z32()));
    }
    s.push_str(&format!("|exp:{}", unix() + RECORD_LIFETIME.as_secs()));
    let ud: UserData = s.parse().map_err(|_| anyhow::anyhow!("record too long"))?;
    let info = EndpointInfo::new(secret.public()).with_user_data(Some(ud));
    let packet = info
        .to_pkarr_signed_packet(&secret, RECORD_LIFETIME.as_secs() as u32)
        .map_err(|e| anyhow::anyhow!("signing the record: {e}"))?;
    Ok(Bytes::copy_from_slice(packet.as_bytes()))
}

/// Sign our own record: where to dial us, and our [`Role`].
pub fn seal_own(keys: &DeviceKeys, addrs: Vec<iroh::TransportAddr>, role: &Role) -> Result<Bytes> {
    let secret = iroh::SecretKey::from_bytes(&keys.seed());
    let mut s = String::new();
    match role {
        Role::Plain => {}
        Role::Relay => s.push_str(RELAY),
        Role::Via(relays) => {
            s.push_str(PREFIX);
            for (i, (g, c)) in relays.iter().take(3).enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let id = to_id(g).context("bad relay key")?;
                s.push_str(&format!("{}:{c}", id.to_z32()));
            }
        }
    }
    if !s.is_empty() {
        s.push('|');
    }
    s.push_str(&format!("{EXPIRES}{}", unix() + RECORD_LIFETIME.as_secs()));
    let ud: UserData = s.parse().map_err(|_| anyhow::anyhow!("record too long"))?;
    // no custom addresses: a link's address means nothing to anyone out of its range
    let addrs = addrs.into_iter().filter(|a| !matches!(a, iroh::TransportAddr::Custom(_))).collect();
    let data = iroh::endpoint_info::EndpointData::new(addrs).with_user_data(ud);
    let packet = EndpointInfo::from_parts(secret.public(), data)
        .to_pkarr_signed_packet(&secret, OWN_TTL)
        .map_err(|e| anyhow::anyhow!("signing the record: {e}"))?;
    Ok(Bytes::copy_from_slice(packet.as_bytes()))
}

/// Verify a record (its key's signature) and read all of it. `None` if it
/// isn't one, is signed by someone other than `expect`, or has expired.
/// Items it doesn't know are skipped, so a record from Iroh's own publisher
/// reads as addresses only.
pub fn read(bytes: &[u8], expect: Option<&SignPk>) -> Option<Record> {
    let packet = SignedPacket::from_bytes(bytes).ok()?;
    let node = SignPk(*packet.public_key().as_bytes());
    if expect.is_some_and(|e| *e != node) {
        return None;
    }
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).ok()?;
    let mut rec = Record {
        node,
        gateways: Vec::new(),
        relay: false,
        addrs: info.addrs().filter(|a| !matches!(a, iroh::TransportAddr::Custom(_))).cloned().collect(),
        expires: 0,
    };
    for item in info.user_data().map(|u| u.as_ref()).unwrap_or_default().split('|') {
        if let Some(list) = item.strip_prefix(PREFIX) {
            for part in list.split(',').filter(|p| !p.is_empty()).take(3) {
                let (z, c) = part.split_once(':')?;
                let id = iroh::PublicKey::from_z32(z).ok()?;
                rec.gateways.push((SignPk(*id.as_bytes()), c.parse().ok()?));
            }
        } else if item == RELAY {
            rec.relay = true;
        } else if let Some(exp) = item.strip_prefix(EXPIRES) {
            rec.expires = exp.parse().ok()?;
        }
    }
    if rec.expires != 0 && rec.expires < unix() {
        return None;
    }
    // it can't be both: a relay is a device the internet reaches
    if rec.relay && !rec.gateways.is_empty() {
        rec.relay = false;
    }
    rec.gateways.retain(|(g, _)| *g != node);
    Some(rec)
}

/// The pkarr packet's timestamp (µs): newer replaces older.
pub fn timestamp(bytes: &[u8]) -> Option<u64> {
    Some(SignedPacket::from_bytes(bytes).ok()?.timestamp().as_micros())
}

/// Verify a record (its key's signature) and read it. `None` if it isn't
/// one, is signed by someone other than `expect`, or has expired.
pub fn open(bytes: &[u8], expect: Option<&SignPk>) -> Option<Reach> {
    let packet = SignedPacket::from_bytes(bytes).ok()?;
    let node = SignPk(*packet.public_key().as_bytes());
    if expect.is_some_and(|e| *e != node) {
        return None;
    }
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).ok()?;
    let ud = info.user_data()?;
    let rest = ud.as_ref().strip_prefix(PREFIX)?;
    let (list, exp) = rest.split_once("|exp:")?;
    let expires: u64 = exp.parse().ok()?;
    if expires < unix() {
        return None;
    }
    let mut gateways = Vec::new();
    for part in list.split(',').filter(|p| !p.is_empty()).take(3) {
        let (z, c) = part.split_once(':')?;
        let id = iroh::PublicKey::from_z32(z).ok()?;
        gateways.push((SignPk(*id.as_bytes()), c.parse().ok()?));
    }
    Some(Reach { node, gateways, expires })
}

/// Where records live.
pub trait Directory: Send + Sync + Debug + 'static {
    /// Publish a sealed record (anyone's: it is signed by its owner).
    fn put(&self, record: Bytes) -> BoxFuture<Result<()>>;
    /// The newest record for `node`, if any.
    fn get(&self, node: SignPk) -> BoxFuture<Option<Bytes>>;
}

/// Records in memory (tests): the newest per key, by pkarr timestamp.
#[derive(Debug, Clone, Default)]
pub struct MemDirectory {
    records: Arc<Mutex<HashMap<SignPk, Bytes>>>,
}

impl MemDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Directory for MemDirectory {
    fn put(&self, record: Bytes) -> BoxFuture<Result<()>> {
        let records = self.records.clone();
        Box::pin(async move {
            let packet = SignedPacket::from_bytes(&record).map_err(|_| anyhow::anyhow!("not a signed record"))?;
            let node = SignPk(*packet.public_key().as_bytes());
            let mut map = records.lock();
            let newer =
                map.get(&node).and_then(|old| timestamp(old)).is_none_or(|t| packet.timestamp().as_micros() > t);
            if newer {
                map.insert(node, record);
            }
            Ok(())
        })
    }

    fn get(&self, node: SignPk) -> BoxFuture<Option<Bytes>> {
        let r = self.records.lock().get(&node).cloned();
        Box::pin(async move { r })
    }
}

/// Which backends a [`PkarrDirectory`] uses.
#[derive(Clone, Debug)]
pub struct PkarrOptions {
    /// The n0 pkarr relay (a server; records appear there at once).
    pub n0: bool,
    /// The Mainline DHT (the `dht` feature; no operator).
    pub dht: bool,
    /// DHT nodes remembered from an earlier run ([`PkarrDirectory::dht_nodes`]),
    /// tried along with the well-known bootstrap hosts, so a device that
    /// has been on the DHT once doesn't depend on those hosts again.
    pub dht_nodes: Vec<String>,
}

impl Default for PkarrOptions {
    fn default() -> Self {
        PkarrOptions { n0: true, dht: true, dht_nodes: Vec::new() }
    }
}

/// What the DHT tells us about ourselves ([`PkarrDirectory::dht_status`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DhtStatus {
    /// Nodes in our routing table: 0 means the DHT is out of reach.
    pub nodes: usize,
    /// DHT nodes we never contacted have sent us requests: unsolicited
    /// packets from the internet get through to this device.
    pub reachable: bool,
    /// Our address as DHT nodes see it (the DHT socket's, not Iroh's).
    pub public: Option<std::net::SocketAddrV4>,
    /// We answer other nodes' queries (the library's adaptive mode turns
    /// that on after 15 minutes of being reachable).
    pub serving: bool,
}

/// Lookups answered from memory for this long ...
const CACHE: Duration = Duration::from_secs(30);
/// ... "no record" for this long ...
const CACHE_NONE: Duration = Duration::from_secs(10);
/// ... for at most this many devices.
const CACHE_MAX: usize = 1024;

/// The real directory: the Mainline DHT (the `dht` feature) and, unless
/// switched off, the n0 pkarr relay (Iroh's default resolver).
#[derive(Debug)]
pub struct PkarrDirectory {
    relays: Vec<iroh::address_lookup::PkarrRelayClient>,
    #[cfg(feature = "dht")]
    dht: Option<n0_mainline::Dht>,
    /// The address lookup and the mesh both ask for a device as it is
    /// dialed: one query serves both.
    cache: Mutex<HashMap<SignPk, (Option<Bytes>, std::time::Instant)>>,
}

impl PkarrDirectory {
    /// The n0 relay (with the endpoint's TLS and DNS settings) and a
    /// Mainline DHT node of our own, as `opts` says. The DHT node starts as
    /// a client and, once it has been reachable for 15 minutes, serves
    /// other nodes' queries too (the library's adaptive mode).
    pub fn new(endpoint: &iroh::Endpoint, opts: &PkarrOptions) -> Result<Self> {
        let mut relays = Vec::new();
        if opts.n0 {
            let url: url::Url = iroh::address_lookup::N0_DNS_PKARR_RELAY_PROD.parse()?;
            let dns = endpoint.dns_resolver().map_err(|e| anyhow::anyhow!("{e}"))?.clone();
            relays.push(iroh::address_lookup::PkarrRelayClient::new(url, endpoint.tls_config().clone(), dns));
        }
        #[cfg(feature = "dht")]
        let dht = if opts.dht {
            let mut b = n0_mainline::Dht::builder();
            // only `host:port` strings we wrote ourselves, at most a few dozen
            let known: Vec<&String> =
                opts.dht_nodes.iter().filter(|n| n.parse::<std::net::SocketAddrV4>().is_ok()).take(64).collect();
            b.extra_bootstrap(&known);
            b.build().ok()
        } else {
            None
        };
        #[cfg(feature = "dht")]
        let any = !relays.is_empty() || dht.is_some();
        #[cfg(not(feature = "dht"))]
        let any = !relays.is_empty();
        if !any {
            bail!("no directory backend is switched on");
        }
        Ok(PkarrDirectory {
            relays,
            #[cfg(feature = "dht")]
            dht,
            cache: Mutex::default(),
        })
    }

    /// DHT nodes we know now, as `ip:port`: keep them for
    /// [`PkarrOptions::dht_nodes`] next time. Empty without the DHT.
    pub async fn dht_nodes(&self) -> Vec<String> {
        #[cfg(feature = "dht")]
        if let Some(dht) = &self.dht {
            return dht.to_bootstrap().await.unwrap_or_default();
        }
        Vec::new()
    }

    /// Our DHT node, for whatever else lives on the DHT (who holds a file:
    /// `chunks/holders_dht.rs`): a device runs one, not one per use.
    #[cfg(feature = "dht")]
    pub fn dht(&self) -> Option<n0_mainline::Dht> {
        self.dht.clone()
    }

    /// What the DHT knows about us; `None` without the DHT.
    pub async fn dht_status(&self) -> Option<DhtStatus> {
        #[cfg(feature = "dht")]
        if let Some(dht) = &self.dht {
            let info = dht.info().await.ok()?;
            return Some(DhtStatus {
                nodes: info.routing_table_size(),
                reachable: !info.firewalled(),
                public: info.public_address(),
                serving: info.server_mode(),
            });
        }
        None
    }

    fn cached(&self, node: &SignPk) -> Option<Option<Bytes>> {
        let cache = self.cache.lock();
        let (rec, at) = cache.get(node)?;
        let ttl = if rec.is_some() { CACHE } else { CACHE_NONE };
        (at.elapsed() < ttl).then(|| rec.clone())
    }

    fn remember(&self, node: SignPk, rec: Option<Bytes>) {
        let mut cache = self.cache.lock();
        if cache.len() >= CACHE_MAX {
            cache.retain(|_, (r, at)| at.elapsed() < if r.is_some() { CACHE } else { CACHE_NONE });
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(node, (rec, std::time::Instant::now()));
    }
}

#[cfg(feature = "dht")]
fn to_item(p: &SignedPacket) -> n0_mainline::MutableItem {
    n0_mainline::MutableItem::new_signed_unchecked(
        *p.public_key().as_bytes(),
        p.signature().to_bytes(),
        p.encoded_packet(),
        p.timestamp().as_micros() as i64,
        None,
    )
}

#[cfg(feature = "dht")]
fn from_item(i: &n0_mainline::MutableItem) -> Option<SignedPacket> {
    SignedPacket::from_parts_unchecked(
        i.key(),
        i.signature(),
        iroh_dns::pkarr::Timestamp::from_micros(i.seq() as u64),
        i.value(),
    )
    .ok()
}

impl Directory for Arc<PkarrDirectory> {
    fn put(&self, record: Bytes) -> BoxFuture<Result<()>> {
        let me = self.clone();
        Box::pin(async move {
            let packet = SignedPacket::from_bytes(&record).map_err(|_| anyhow::anyhow!("not a signed record"))?;
            let mut ok = false;
            for r in &me.relays {
                ok |= r.publish(&packet).await.is_ok();
            }
            #[cfg(feature = "dht")]
            if let Some(dht) = &me.dht {
                ok |= dht.put_mutable(to_item(&packet), None).await.is_ok();
            }
            if !ok {
                bail!("no directory accepted the record");
            }
            // what we just published is the newest there is
            me.remember(SignPk(*packet.public_key().as_bytes()), Some(record));
            Ok(())
        })
    }

    fn get(&self, node: SignPk) -> BoxFuture<Option<Bytes>> {
        let me = self.clone();
        Box::pin(async move {
            let id = to_id(&node)?;
            if let Some(hit) = me.cached(&node) {
                return hit;
            }
            let mut best: Option<SignedPacket> = None;
            let mut keep = |p: SignedPacket| {
                if best.as_ref().is_none_or(|b| p.timestamp().as_micros() > b.timestamp().as_micros()) {
                    best = Some(p);
                }
            };
            for r in &me.relays {
                if let Ok(Ok(p)) = tokio::time::timeout(Duration::from_secs(5), r.resolve(id)).await {
                    keep(p);
                }
            }
            #[cfg(feature = "dht")]
            if let Some(dht) = &me.dht
                && let Ok(Ok(Some(item))) =
                    tokio::time::timeout(Duration::from_secs(10), dht.get_mutable_most_recent(id.as_bytes(), None))
                        .await
                && let Some(p) = from_item(&item)
            {
                keep(p);
            }
            let found = best.map(|p| Bytes::copy_from_slice(p.as_bytes()));
            me.remember(node, found.clone());
            found
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_are_bound_to_their_key() {
        let k = DeviceKeys::generate();
        let gws = [(DeviceKeys::generate().sign_pk(), 1234), (DeviceKeys::generate().sign_pk(), 56)];
        let rec = seal(&k, &gws).unwrap();
        let r = open(&rec, Some(&k.sign_pk())).unwrap();
        assert_eq!(r.node, k.sign_pk());
        assert_eq!(r.gateways, gws.to_vec());
        assert!(r.expires > unix());
        // someone else's key: refused
        assert!(open(&rec, Some(&DeviceKeys::generate().sign_pk())).is_none());
        // tampered: refused
        let mut bad = rec.to_vec();
        let last = bad.len() - 3;
        bad[last] ^= 1;
        assert!(open(&bad, None).is_none());
    }

    #[test]
    fn own_records_say_where_to_dial_and_what_the_device_does() {
        let k = DeviceKeys::generate();
        let ip: iroh::TransportAddr = iroh::TransportAddr::Ip("203.0.113.7:4433".parse().unwrap());
        // a relay: its address, and that it relays
        let rec = seal_own(&k, vec![ip.clone()], &Role::Relay).unwrap();
        let r = read(&rec, Some(&k.sign_pk())).unwrap();
        assert!(r.relay && r.gateways.is_empty());
        assert_eq!(r.addrs, vec![ip.clone()]);
        assert!(r.expires > unix());
        // to the gateway view it is "no record: dial it"
        assert!(open(&rec, None).is_none());
        // behind a router: no address, its relays (never itself, at most 3)
        let relays: Vec<(SignPk, u32)> = (0..4).map(|i| (DeviceKeys::generate().sign_pk(), 100 + i)).collect();
        let mut named = relays.clone();
        named.insert(1, (k.sign_pk(), 1));
        let rec = seal_own(&k, vec![], &Role::Via(named)).unwrap();
        let r = read(&rec, None).unwrap();
        assert!(!r.relay && r.addrs.is_empty());
        assert_eq!(r.gateways, relays[..2].to_vec());
        // the gateway view reads the same relays
        assert_eq!(open(&rec, Some(&k.sign_pk())).unwrap().gateways.len(), 3);
        // plain: addresses only
        let rec = seal_own(&k, vec![ip.clone()], &Role::Plain).unwrap();
        let r = read(&rec, None).unwrap();
        assert!(!r.relay && r.gateways.is_empty() && r.addrs == vec![ip]);
        // signed by its owner, whole
        assert!(read(&rec, Some(&DeviceKeys::generate().sign_pk())).is_none());
        let mut bad = rec.to_vec();
        let last = bad.len() - 3;
        bad[last] ^= 1;
        assert!(read(&bad, None).is_none());
        // a gateway's record for a device without the internet reads too
        let gws = [(DeviceKeys::generate().sign_pk(), 77)];
        let r = read(&seal(&k, &gws).unwrap(), None).unwrap();
        assert_eq!((r.gateways, r.relay, r.addrs.len()), (gws.to_vec(), false, 0));
    }

    #[tokio::test]
    async fn the_newest_record_wins() {
        let d = MemDirectory::new();
        let k = DeviceKeys::generate();
        let (g1, g2) = (DeviceKeys::generate().sign_pk(), DeviceKeys::generate().sign_pk());
        let first = seal(&k, &[(g1, 1)]).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = seal(&k, &[(g2, 1)]).unwrap();
        d.put(second.clone()).await.unwrap();
        d.put(first).await.unwrap(); // older: ignored
        let got = d.get(k.sign_pk()).await.unwrap();
        assert_eq!(open(&got, None).unwrap().gateways, vec![(g2, 1)]);
        assert!(d.put(Bytes::from_static(b"junk")).await.is_err());
    }
}
