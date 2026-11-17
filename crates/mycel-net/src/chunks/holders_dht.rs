//! File holders on the BitTorrent Mainline DHT: nobody runs it, and a
//! holder is found by anyone who has the file's reference.
//!
//! A holder announces itself as a *signed peer* under an id derived from the
//! file's root: its device key, signed by that key, so a lookup returns keys
//! to dial, not addresses (addresses come from the usual address lookup).
//! Signed peers are an extension that only DHT nodes built on this library
//! store; ordinary BitTorrent nodes ignore the announcement, so there are
//! far fewer places to find it than there are DHT nodes. Tests run against
//! a local DHT, never the public one.
//!
//! What it shows, and to whom: the DHT nodes near the id learn that the
//! device (key and IP address) holds, or is looking for, *some* file. The id
//! is not the root, so they can't fetch anything with it; someone who has
//! the reference (or, for a public file, the file) can tell which file it is.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use n0_future::StreamExt;
use n0_future::boxed::BoxFuture;
use n0_mainline::{Dht, Id, SigningKey};
use parking_lot::Mutex;

use super::holders::Holders;

const CTX_INFO_HASH: &str = "mycel/v0/file-holders";
/// A lookup collects answers for this long at most.
const FIND_TIMEOUT: Duration = Duration::from_secs(10);
/// Holders taken from one lookup, at most.
const FIND_MAX: usize = 32;

/// See the module docs. The DHT node is started on first use, so a device
/// that never holds or looks up a file never joins.
#[derive(Debug, Default)]
pub struct DhtHolders {
    dht: Mutex<Option<Dht>>,
}

impl DhtHolders {
    /// With a DHT node of its own (the default bootstrap nodes), started
    /// when first needed.
    pub fn new() -> Self {
        Self::default()
    }

    /// With a DHT node the caller already runs.
    pub fn with(dht: Dht) -> Self {
        DhtHolders { dht: Mutex::new(Some(dht)) }
    }

    fn dht(&self) -> Result<Dht> {
        let mut dht = self.dht.lock();
        if dht.is_none() {
            *dht = Some(Dht::client()?);
        }
        Ok(dht.clone().expect("set above"))
    }
}

/// Where a file's holders are announced: not the root itself, and apart
/// from anything else on the DHT.
fn info_hash(root: &Hash32) -> Id {
    let digest = Hash32::digest(CTX_INFO_HASH, &root.0);
    Id::from_bytes(&digest.0[..20]).expect("20 bytes")
}

impl Holders for DhtHolders {
    fn announce(&self, root: Hash32, keys: Arc<DeviceKeys>) -> BoxFuture<Result<()>> {
        let dht = self.dht();
        Box::pin(async move {
            let signer = SigningKey::from_bytes(&keys.seed());
            dht?.announce_signed_peer(info_hash(&root), &signer).await.map_err(|e| anyhow!("{e}"))?;
            Ok(())
        })
    }

    fn find(&self, root: Hash32) -> BoxFuture<Vec<SignPk>> {
        let dht = self.dht();
        Box::pin(async move {
            let Ok(dht) = dht else { return Vec::new() };
            let Ok(mut answers) = dht.get_signed_peers(info_hash(&root)).await else { return Vec::new() };
            let mut found = BTreeSet::new();
            let collect = async {
                while let Some(batch) = answers.next().await {
                    found.extend(batch.iter().map(|a| SignPk(*a.key())));
                    if found.len() >= FIND_MAX {
                        break;
                    }
                }
            };
            let _ = tokio::time::timeout(FIND_TIMEOUT, collect).await;
            found.into_iter().take(FIND_MAX).collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a DHT of our own (ten nodes on loopback): a holder's announcement
    /// is found by another node, by the file's root only.
    #[tokio::test(flavor = "multi_thread")]
    async fn holders_are_announced_and_found_on_a_dht() {
        let testnet = n0_mainline::Testnet::new(10).await.unwrap();
        let node = || DhtHolders::with(Dht::builder().bootstrap(&testnet.bootstrap).build().unwrap());
        let (holder, other, seeker) = (node(), node(), node());
        let (a, b) = (Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()));
        let (root, unknown) = (Hash32([3; 32]), Hash32([4; 32]));
        holder.announce(root, a.clone()).await.unwrap();
        other.announce(root, b.clone()).await.unwrap();
        let mut want = vec![a.sign_pk(), b.sign_pk()];
        want.sort();
        assert_eq!(seeker.find(root).await, want);
        assert!(seeker.find(unknown).await.is_empty());
        assert_ne!(info_hash(&root).as_bytes()[..], root.0[..20], "the root itself is not what is announced");
    }
}
