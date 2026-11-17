//! Who holds a file: what a recipient falls back on when nobody in the
//! conversation is around to serve it.
//!
//! A device that took a whole file into its cache, to hold for whoever
//! comes for it, says so under the file's root id; anyone who has the
//! reference can ask who did.
//! What is published is a device key next to a root id: it shows that the
//! device holds *something*, and to whoever also has the reference (or, for
//! a public file, the file itself) what. Nothing is published for a file a
//! device merely has in its own chats unless the app asks
//! ([`crate::Node::announce_file`]).
//!
//! Backends: [`MemHolders`] (tests; devices of one process), and with the
//! `dht` feature `DhtHolders` (the BitTorrent Mainline DHT, signed announces).

use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Result;
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use n0_future::boxed::BoxFuture;
use parking_lot::Mutex;

/// Where devices say which files they hold.
pub trait Holders: Send + Sync + Debug + 'static {
    /// Say that this device (`keys`) holds the file under `root`. Lasts a
    /// while (backends expire entries); holders repeat it.
    fn announce(&self, root: Hash32, keys: Arc<DeviceKeys>) -> BoxFuture<Result<()>>;
    /// Devices that said they hold the file under `root` (unverified: a
    /// holder is only believed once its pieces check out).
    fn find(&self, root: Hash32) -> BoxFuture<Vec<SignPk>>;
}

/// Announcements in memory, shared by the devices of one test.
#[derive(Debug, Clone, Default)]
pub struct MemHolders {
    map: Arc<Mutex<HashMap<Hash32, BTreeSet<SignPk>>>>,
    lookups: Arc<Mutex<Vec<Hash32>>>,
}

impl MemHolders {
    pub fn new() -> Self {
        Self::default()
    }

    /// Who announced `root` so far.
    pub fn holders(&self, root: &Hash32) -> Vec<SignPk> {
        self.map.lock().get(root).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }

    /// Every lookup made, in order.
    pub fn lookups(&self) -> Vec<Hash32> {
        self.lookups.lock().clone()
    }
}

impl Holders for MemHolders {
    fn announce(&self, root: Hash32, keys: Arc<DeviceKeys>) -> BoxFuture<Result<()>> {
        self.map.lock().entry(root).or_default().insert(keys.sign_pk());
        Box::pin(async { Ok(()) })
    }

    fn find(&self, root: Hash32) -> BoxFuture<Vec<SignPk>> {
        self.lookups.lock().push(root);
        let found = self.holders(&root);
        Box::pin(async move { found })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn announcements_are_found_by_root() {
        let h = MemHolders::new();
        let (a, b) = (Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()));
        let (x, y) = (Hash32([1; 32]), Hash32([2; 32]));
        h.announce(x, a.clone()).await.unwrap();
        h.announce(x, b.clone()).await.unwrap();
        h.announce(x, a.clone()).await.unwrap();
        let mut want = vec![a.sign_pk(), b.sign_pk()];
        want.sort();
        assert_eq!(h.find(x).await, want);
        assert!(h.find(y).await.is_empty());
        assert_eq!(h.lookups(), vec![x, y]);
    }
}
