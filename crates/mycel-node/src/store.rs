//! Durable storage (redb): membership ops, envelopes and small key-values.
//!
//! Replicas call [`mycel_sync::Store`] on every new item. Writes are buffered
//! and committed in one transaction every ~100 ms (or on [`DbStore::flush`]),
//! so syncing thousands of envelopes doesn't fsync thousands of times.
//! Everything else (documents, feeds, keys) is derived from these inputs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::Hash32;
use mycel_sync::{Envelope, Store};
use mycel_trust::{SignedOp, SpaceId};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const OPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ops");
const ENVS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("envelopes");
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");

enum Write {
    Op(Vec<u8>, Vec<u8>),
    Env(Vec<u8>, Vec<u8>),
    Kv(String, Option<Vec<u8>>),
}

#[derive(Default)]
struct Pending {
    queue: Vec<Write>,
    closed: bool,
    // Store callbacks cannot return errors. Keep failures sticky so that every
    // subsequent barrier/read reports them instead of claiming durability.
    error: Option<String>,
}

struct Shared {
    pending: Mutex<Pending>,
    cv: Condvar,
    // Held from before draining the queue through transaction completion.
    commit_gate: Mutex<()>,
    #[cfg(test)]
    fail_next_commit: std::sync::atomic::AtomicBool,
}

/// Everything stored for one space: its ops (incl. genesis) and envelopes.
pub type StoredSpace = (Vec<SignedOp>, Vec<Envelope>);

pub struct DbStore {
    db: Arc<Database>,
    shared: Arc<Shared>,
    flusher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn key(space: &SpaceId, id: &Hash32) -> Vec<u8> {
    [space.0.as_slice(), id.0.as_slice()].concat()
}

fn commit(db: &Database, batch: &[Write]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let txn = db.begin_write()?;
    {
        let mut ops = txn.open_table(OPS)?;
        let mut envs = txn.open_table(ENVS)?;
        let mut kv = txn.open_table(KV)?;
        for w in batch {
            match w {
                Write::Op(k, v) => {
                    ops.insert(k.as_slice(), v.as_slice())?;
                }
                Write::Env(k, v) => {
                    envs.insert(k.as_slice(), v.as_slice())?;
                }
                Write::Kv(k, Some(v)) => {
                    kv.insert(k.as_str(), v.as_slice())?;
                }
                Write::Kv(k, None) => {
                    kv.remove(k.as_str())?;
                }
            }
        }
    }
    txn.commit()?;
    Ok(())
}

fn commit_pending(db: &Database, shared: &Shared, extra: Vec<Write>) -> Result<()> {
    let _gate = shared.commit_gate.lock().unwrap();
    let batch = {
        let mut pending = shared.pending.lock().unwrap();
        if let Some(error) = &pending.error {
            bail!("storage durability failed: {error}");
        }
        if pending.closed && !extra.is_empty() {
            bail!("storage is closed");
        }
        pending.queue.extend(extra);
        std::mem::take(&mut pending.queue)
    };
    #[cfg(test)]
    let outcome = if shared
        .fail_next_commit
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        Err(anyhow!("injected commit failure"))
    } else {
        commit(db, &batch)
    };
    #[cfg(not(test))]
    let outcome = commit(db, &batch);
    if let Err(error) = outcome {
        let mut pending = shared.pending.lock().unwrap();
        // Retain the failed batch before later writes for diagnosis. A sticky
        // error disallows retries because transaction outcome can be uncertain.
        let later = std::mem::replace(&mut pending.queue, batch);
        pending.queue.extend(later);
        pending.error = Some(format!("{error:#}"));
        shared.cv.notify_all();
        return Err(error);
    }
    Ok(())
}

impl DbStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let db = Arc::new(Database::create(path)?);
        // make sure tables exist
        commit(&db, &[Write::Kv("__init".into(), Some(vec![]))])?;
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending::default()),
            cv: Condvar::new(),
            commit_gate: Mutex::new(()),
            #[cfg(test)]
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
        });
        let (db2, sh2) = (db.clone(), shared.clone());
        let flusher = std::thread::spawn(move || {
            loop {
                {
                    let p = sh2.pending.lock().unwrap();
                    let (p, _) = sh2
                        .cv
                        .wait_timeout_while(p, Duration::from_millis(100), |p| {
                            p.queue.is_empty() && !p.closed && p.error.is_none()
                        })
                        .unwrap();
                    if p.error.is_some() || (p.closed && p.queue.is_empty()) {
                        return;
                    }
                }
                if commit_pending(&db2, &sh2, Vec::new()).is_err() {
                    // The failure is retained and surfaced by every barrier/read.
                    return;
                }
            }
        });
        Ok(Arc::new(DbStore {
            db,
            shared,
            flusher: Mutex::new(Some(flusher)),
        }))
    }

    fn enqueue(&self, w: Write) {
        let mut pending = self.shared.pending.lock().unwrap();
        if pending.closed {
            pending
                .error
                .get_or_insert_with(|| "storage is closed".into());
        } else {
            pending.queue.push(w);
        }
        self.shared.cv.notify_one();
    }

    /// Barrier covering every write enqueued before this call, including any
    /// batch already drained by the background flusher.
    pub fn flush(&self) -> Result<()> {
        commit_pending(&self.db, &self.shared, Vec::new())
    }

    /// Apply a group of key-value changes in one durable transaction. Prior
    /// buffered writes are included. Callers must publish in-memory security
    /// changes only after this succeeds.
    pub fn kv_batch_durable(&self, entries: Vec<(String, Option<Vec<u8>>)>) -> Result<()> {
        let writes = entries.into_iter().map(|(k, v)| Write::Kv(k, v)).collect();
        commit_pending(&self.db, &self.shared, writes)
    }

    pub fn close(&self) -> Result<()> {
        self.shared.pending.lock().unwrap().closed = true;
        self.shared.cv.notify_all();
        if let Some(h) = self.flusher.lock().unwrap().take() {
            h.join().map_err(|_| anyhow!("storage flusher panicked"))?;
        }
        self.flush()
    }

    /// Absence is allowed; malformed persisted security state is an error.
    pub fn kv_decode<T: serde::de::DeserializeOwned>(&self, k: &str) -> Result<Option<T>> {
        self.kv_get(k)?
            .map(|bytes| {
                let (value, rest) = postcard::take_from_bytes(&bytes)
                    .with_context(|| format!("corrupt persisted {k}"))?;
                if !rest.is_empty() {
                    bail!("corrupt persisted {k}: trailing bytes");
                }
                Ok(value)
            })
            .transpose()
    }

    pub fn kv_get(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.flush()?;
        let txn = self.db.begin_read()?;
        let t = txn.open_table(KV)?;
        Ok(t.get(k)?.map(|v| v.value().to_vec()))
    }

    pub fn kv_put(&self, k: &str, v: Vec<u8>) {
        self.enqueue(Write::Kv(k.to_string(), Some(v)));
    }

    pub fn kv_delete(&self, k: &str) {
        self.enqueue(Write::Kv(k.to_string(), None));
    }

    /// Every stored space: (genesis + other ops, envelopes).
    pub fn load_spaces(&self) -> Result<HashMap<SpaceId, StoredSpace>> {
        self.flush()?;
        let txn = self.db.begin_read()?;
        let mut out: HashMap<SpaceId, StoredSpace> = HashMap::new();
        let space_of = |k: &[u8]| -> Result<Hash32> {
            if k.len() != 64 {
                bail!("corrupt stored record key");
            }
            Ok(Hash32(k[..32].try_into().expect("checked key length")))
        };
        for row in txn.open_table(OPS)?.iter()? {
            let (k, v) = row?;
            let op = postcard::from_bytes::<SignedOp>(v.value())
                .context("corrupt stored membership operation")?;
            out.entry(space_of(k.value())?).or_default().0.push(op);
        }
        for row in txn.open_table(ENVS)?.iter()? {
            let (k, v) = row?;
            let env =
                postcard::from_bytes::<Envelope>(v.value()).context("corrupt stored envelope")?;
            out.entry(space_of(k.value())?).or_default().1.push(env);
        }
        Ok(out)
    }
}

impl Drop for DbStore {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Store for DbStore {
    fn put_op(&self, space: &SpaceId, op: &SignedOp) {
        let v = postcard::to_allocvec(op).expect("encodes");
        self.enqueue(Write::Op(key(space, &op.id()), v));
    }

    fn put_envelope(&self, space: &SpaceId, env: &Envelope) {
        let v = postcard::to_allocvec(env).expect("encodes");
        self.enqueue(Write::Env(key(space, &env.id()), v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (std::path::PathBuf, Arc<DbStore>) {
        let path = std::env::temp_dir().join(format!(
            "mycel-store-security-{}.redb",
            hex::encode(mycel_crypto::random::<16>())
        ));
        let store = DbStore::open(&path).unwrap();
        (path, store)
    }

    #[test]
    fn corrupt_security_records_are_errors_and_absence_is_distinct() {
        let (path, store) = test_store();
        assert!(store.kv_decode::<Vec<u64>>("blocked").unwrap().is_none());
        store
            .kv_batch_durable(vec![("blocked".into(), Some(vec![255]))])
            .unwrap();
        assert!(store.kv_decode::<Vec<u64>>("blocked").is_err());
        store
            .kv_batch_durable(vec![("blocked".into(), Some(vec![0, 1]))])
            .unwrap();
        assert!(
            store.kv_decode::<Vec<u64>>("blocked").is_err(),
            "trailing bytes are corruption"
        );
        store.close().unwrap();
        drop(store);
        fs_cleanup(path);
    }

    #[test]
    fn failed_commit_is_retained_and_every_barrier_stays_failed() {
        let (path, store) = test_store();
        store
            .shared
            .fail_next_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store
                .kv_batch_durable(vec![("request".into(), Some(vec![1]))])
                .is_err()
        );
        assert_eq!(store.shared.pending.lock().unwrap().queue.len(), 1);
        assert!(store.flush().is_err());
        assert!(store.kv_get("request").is_err());
        assert!(store.close().is_err());
        drop(store);
        fs_cleanup(path);
    }

    #[test]
    fn flush_waits_for_inflight_commit_before_claiming_success() {
        let (path, store) = test_store();
        // Model a background batch already drained under the commit gate.
        let gate = store.shared.commit_gate.lock().unwrap();
        let batch = vec![Write::Kv("inflight".into(), Some(vec![7]))];
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let other = store.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx.send(other.flush().is_ok()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        commit(&store.db, &batch).unwrap();
        drop(gate);
        assert!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        waiter.join().unwrap();
        assert_eq!(store.kv_get("inflight").unwrap(), Some(vec![7]));
        store.close().unwrap();
        drop(store);
        fs_cleanup(path);
    }

    #[test]
    fn atomic_security_batch_survives_reopen() {
        let (path, store) = test_store();
        store.kv_put("requests", vec![1]);
        store
            .kv_batch_durable(vec![
                ("requests".into(), None),
                ("hidden".into(), Some(vec![2])),
            ])
            .unwrap();
        store.close().unwrap();
        drop(store);
        let reopened = DbStore::open(&path).unwrap();
        assert_eq!(reopened.kv_get("requests").unwrap(), None);
        assert_eq!(reopened.kv_get("hidden").unwrap(), Some(vec![2]));
        reopened.close().unwrap();
        drop(reopened);
        fs_cleanup(path);
    }

    #[tokio::test]
    async fn corrupt_space_startup_releases_profile_and_database() {
        let dir = std::env::temp_dir().join(format!(
            "mycel-corrupt-startup-{}-{}", std::process::id(), mycel_crypto::random_u64()
        ));
        let runtime = crate::Runtime::open(&dir, crate::api::NetworkMode::Local, None).await.unwrap();
        runtime.shutdown().await.unwrap();
        drop(runtime);
        {
            let db = Database::create(dir.join("mycel.redb")).unwrap();
            let transaction = db.begin_write().unwrap();
            {
                let mut ops = transaction.open_table(OPS).unwrap();
                ops.insert(&[0u8; 64][..], &[255u8][..]).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(crate::Runtime::open(&dir, crate::api::NetworkMode::Local, None).await.is_err());
        // Detached network tasks would retain the store and its database lock.
        let lease = crate::identity::ProfileLock::acquire(&dir).unwrap();
        let store = DbStore::open(dir.join("mycel.redb")).unwrap();
        store.close().unwrap();
        drop(store);
        drop(lease);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn fs_cleanup(path: std::path::PathBuf) {
        let _ = std::fs::remove_file(path);
    }
}
