//! Reachability records: "device D, which has no internet, is reached via
//! gateways G1, G2", published in a global directory nobody here runs.
//!
//! A record is a **pkarr signed packet** (the format Iroh's own address
//! lookup uses), signed by D's own key. D signs it with no network at all
//! and hands it to its gateways over the mesh; they publish it. Anyone
//! resolves it by D's key, as with any Iroh endpoint. The gateways go in the
//! endpoint info's user data: `mycel-gw:<gw z32>:<mesh cost>,…|exp:<unix s>`.
//! A device's own Iroh record (when it has the internet) has no `mycel-gw`,
//! so it reads as "no record: dial it directly".
//!
//! Backends ([`Directory`]):
//! - [`PkarrDirectory`]: the n0 pkarr relay (what Iroh resolves through by
//!   default) and, with the `dht` feature, the BitTorrent Mainline DHT
//!   (no operator at all). Lookups ask both; the newest record wins.
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
/// How long a record says it is valid, and the pkarr TTL.
pub const RECORD_LIFETIME: Duration = Duration::from_secs(30 * 60);

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
            let newer = map.get(&node).and_then(|old| timestamp(old)).is_none_or(|t| packet.timestamp().as_micros() > t);
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

/// The real directory: the n0 pkarr relay (Iroh's default resolver) and,
/// with the `dht` feature, the Mainline DHT.
#[derive(Debug)]
pub struct PkarrDirectory {
    relays: Vec<iroh::address_lookup::PkarrRelayClient>,
    #[cfg(feature = "dht")]
    dht: Option<n0_mainline::Dht>,
}

impl PkarrDirectory {
    /// Use the n0 relay (with the endpoint's TLS and DNS settings) and, if
    /// `dht`, a Mainline DHT client of our own.
    pub fn new(endpoint: &iroh::Endpoint, dht: bool) -> Result<Self> {
        let url: url::Url = iroh::address_lookup::N0_DNS_PKARR_RELAY_PROD.parse()?;
        let dns = endpoint.dns_resolver().map_err(|e| anyhow::anyhow!("{e}"))?.clone();
        let relay = iroh::address_lookup::PkarrRelayClient::new(url, endpoint.tls_config().clone(), dns);
        #[cfg(feature = "dht")]
        let dht = if dht { n0_mainline::Dht::client().ok() } else { None };
        #[cfg(not(feature = "dht"))]
        let _ = dht;
        Ok(PkarrDirectory {
            relays: vec![relay],
            #[cfg(feature = "dht")]
            dht,
        })
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
            Ok(())
        })
    }

    fn get(&self, node: SignPk) -> BoxFuture<Option<Bytes>> {
        let me = self.clone();
        Box::pin(async move {
            let id = to_id(&node)?;
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
                    tokio::time::timeout(Duration::from_secs(10), dht.get_mutable_most_recent(id.as_bytes(), None)).await
                && let Some(p) = from_item(&item)
            {
                keep(p);
            }
            best.map(|p| Bytes::copy_from_slice(p.as_bytes()))
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
