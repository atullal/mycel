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

use anyhow::Result;
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

struct Shared {
    queue: Mutex<Vec<Write>>,
    cv: Condvar,
    closed: Mutex<bool>,
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

fn commit(db: &Database, batch: Vec<Write>) -> Result<()> {
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

impl DbStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let db = Arc::new(Database::create(path)?);
        // make sure tables exist
        commit(&db, vec![Write::Kv("__init".into(), Some(vec![]))])?;
        let shared = Arc::new(Shared {
            queue: Mutex::new(Vec::new()),
            cv: Condvar::new(),
            closed: Mutex::new(false),
        });
        let (db2, sh2) = (db.clone(), shared.clone());
        let flusher = std::thread::spawn(move || {
            loop {
                let batch = {
                    let q = sh2.queue.lock().unwrap();
                    let (mut q, _) = sh2
                        .cv
                        .wait_timeout_while(q, Duration::from_millis(100), |q| q.is_empty())
                        .unwrap();
                    std::mem::take(&mut *q)
                };
                if let Err(e) = commit(&db2, batch) {
                    eprintln!("mycel: storage write failed: {e}");
                }
                if *sh2.closed.lock().unwrap() && sh2.queue.lock().unwrap().is_empty() {
                    return;
                }
            }
        });
        Ok(Arc::new(DbStore { db, shared, flusher: Mutex::new(Some(flusher)) }))
    }

    fn enqueue(&self, w: Write) {
        self.shared.queue.lock().unwrap().push(w);
        self.shared.cv.notify_one();
    }

    /// Commit everything queued so far, synchronously.
    pub fn flush(&self) -> Result<()> {
        let batch = std::mem::take(&mut *self.shared.queue.lock().unwrap());
        commit(&self.db, batch)
    }

    pub fn close(&self) -> Result<()> {
        *self.shared.closed.lock().unwrap() = true;
        self.shared.cv.notify_all();
        if let Some(h) = self.flusher.lock().unwrap().take() {
            let _ = h.join();
        }
        self.flush()
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
        let space_of = |k: &[u8]| Hash32(k[..32].try_into().unwrap());
        for row in txn.open_table(OPS)?.iter()? {
            let (k, v) = row?;
            if let Ok(op) = postcard::from_bytes::<SignedOp>(v.value()) {
                out.entry(space_of(k.value())).or_default().0.push(op);
            }
        }
        for row in txn.open_table(ENVS)?.iter()? {
            let (k, v) = row?;
            if let Ok(env) = postcard::from_bytes::<Envelope>(v.value()) {
                out.entry(space_of(k.value())).or_default().1.push(env);
            }
        }
        Ok(out)
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
