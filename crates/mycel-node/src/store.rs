//! Durable storage (redb): membership ops, envelopes and small key-values.
//!
//! Replicas call [`mycel_sync::Store`] on every new item. Writes are buffered
//! and committed in one transaction every ~100 ms (or on [`DbStore::flush`]),
//! so syncing thousands of envelopes doesn't fsync thousands of times.
//! Everything else (documents, feeds, keys) is derived from these inputs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::Hash32;
use mycel_sync::{Envelope, Store};
use mycel_trust::{SignedOp, SpaceId};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const OPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ops");
const ENVS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("envelopes");
const KV: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");
/// Stored records that couldn't be decoded, kept byte for byte under
/// `<table>/<key>` so one bad row neither blocks startup nor is deleted.
const QUARANTINE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("quarantine");

/// Synced records buffered for the next commit. Past this, a healthy store
/// makes writers wait for the flusher; a failing one stops buffering them.
const MAX_BUFFERED_BYTES: usize = 64 << 20;
/// Backoff between commit retries after a failure.
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(30);

enum Write {
    Op(Vec<u8>, Vec<u8>),
    Env(Vec<u8>, Vec<u8>),
    Kv(String, Option<Vec<u8>>),
}

impl Write {
    fn size(&self) -> usize {
        match self {
            Write::Op(k, v) | Write::Env(k, v) => k.len() + v.len(),
            Write::Kv(k, v) => k.len() + v.as_ref().map_or(0, Vec::len),
        }
    }
}

#[derive(Default)]
struct Pending {
    queue: Vec<Write>,
    /// Size of `queue`.
    bytes: usize,
    closed: bool,
    // Store callbacks cannot return errors. While commits fail, every barrier
    // and read reports the failure instead of claiming durability, and the
    // flusher retries the queued writes, in order, until a commit succeeds.
    error: Option<String>,
    retry_at: Option<Instant>,
    backoff: Duration,
    /// Synced records not buffered because saving was failing and the buffer
    /// was full. Their replicas still hold them, and peers resend them.
    dropped: u64,
}

type Listener = Arc<dyn Fn() + Send + Sync>;

struct Shared {
    path: PathBuf,
    /// `None` only while a failed database is being reopened.
    db: RwLock<Option<Database>>,
    pending: Mutex<Pending>,
    cv: Condvar,
    // Held from before draining the queue through transaction completion.
    commit_gate: Mutex<()>,
    max_buffered: AtomicUsize,
    /// Called when saving starts failing or works again.
    listener: Mutex<Option<Listener>>,
    #[cfg(test)]
    fail_commits: AtomicUsize,
}

impl Shared {
    fn with_db<R>(&self, f: impl FnOnce(&Database) -> Result<R>) -> Result<R> {
        let db = self.db.read().unwrap();
        f(db.as_ref().context("storage is unavailable")?)
    }

    /// redb latches an I/O failure (every later operation reports it) until
    /// the database is opened again, which also repairs it.
    fn reopen(&self) -> Result<()> {
        let mut db = self.db.write().unwrap();
        // Close first: the file is locked while open.
        *db = None;
        *db = Some(Database::create(&self.path).context("reopen storage")?);
        Ok(())
    }

    fn health_changed(&self) {
        let listener = self.listener.lock().unwrap().clone();
        if let Some(listener) = listener {
            listener();
        }
    }
}

/// Everything stored for one space: its ops (incl. genesis) and envelopes.
pub type StoredSpace = (Vec<SignedOp>, Vec<Envelope>);

pub struct DbStore {
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

/// Commit everything queued plus `extra`. While saving is failing, barriers
/// (`retry == false`) report the failure without trying; the flusher and
/// `close` retry. Every write is idempotent (content-addressed records and
/// whole key-value values), so retrying a batch whose outcome was unclear
/// is safe, and queue order is kept, so later values still win.
fn commit_pending(shared: &Shared, extra: Vec<Write>, retry: bool) -> Result<()> {
    let _gate = shared.commit_gate.lock().unwrap();
    let (mut batch, taken, failing) = {
        let mut pending = shared.pending.lock().unwrap();
        if let Some(error) = &pending.error
            && !retry
        {
            bail!("storage durability failed: {error}");
        }
        if pending.closed && !extra.is_empty() {
            bail!("storage is closed");
        }
        let mut batch = std::mem::take(&mut pending.queue);
        pending.bytes = 0;
        // Writers waiting for buffer space can continue.
        shared.cv.notify_all();
        let taken = batch.len();
        batch.extend(extra);
        (batch, taken, pending.error.is_some())
    };
    let outcome = (|| {
        #[cfg(test)]
        if shared
            .fail_commits
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            bail!("injected commit failure");
        }
        if failing {
            shared.reopen()?;
        }
        shared.with_db(|db| commit(db, &batch))
    })();
    let mut pending = shared.pending.lock().unwrap();
    match outcome {
        Ok(()) => {
            let recovered = pending.error.take().is_some();
            pending.retry_at = None;
            pending.backoff = Duration::ZERO;
            drop(pending);
            if recovered {
                shared.health_changed();
            }
            Ok(())
        }
        Err(error) => {
            // Keep the buffered writes ahead of later ones. A barrier's own
            // writes are not kept: its caller was told they failed and does
            // not publish them, so they must not land later behind its back.
            batch.truncate(taken);
            let later = std::mem::replace(&mut pending.queue, batch);
            pending.queue.extend(later);
            pending.bytes = pending.queue.iter().map(Write::size).sum();
            let first = pending.error.is_none();
            pending.error = Some(format!("{error:#}"));
            pending.backoff = if first { RETRY_FIRST } else { (pending.backoff * 2).min(RETRY_MAX) };
            pending.retry_at = Some(Instant::now() + pending.backoff);
            shared.cv.notify_all();
            drop(pending);
            if first {
                eprintln!("mycel: saving failed ({error:#}); retrying");
                shared.health_changed();
            }
            Err(error)
        }
    }
}

impl DbStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path)?;
        // make sure tables exist
        commit(&db, &[Write::Kv("__init".into(), Some(vec![]))])?;
        let shared = Arc::new(Shared {
            path,
            db: RwLock::new(Some(db)),
            pending: Mutex::new(Pending::default()),
            cv: Condvar::new(),
            commit_gate: Mutex::new(()),
            max_buffered: AtomicUsize::new(MAX_BUFFERED_BYTES),
            listener: Mutex::new(None),
            #[cfg(test)]
            fail_commits: AtomicUsize::new(0),
        });
        let sh2 = shared.clone();
        let flusher = std::thread::spawn(move || {
            loop {
                {
                    let mut p = sh2.pending.lock().unwrap();
                    loop {
                        // `close` makes the final attempt itself.
                        if p.closed {
                            return;
                        }
                        match p.retry_at {
                            Some(at) => match at.checked_duration_since(Instant::now()) {
                                Some(wait) if !wait.is_zero() => {
                                    p = sh2.cv.wait_timeout(p, wait).unwrap().0;
                                }
                                _ => break,
                            },
                            None if !p.queue.is_empty() => break,
                            None => p = sh2.cv.wait_timeout(p, Duration::from_millis(100)).unwrap().0,
                        }
                    }
                }
                // A failure is retained, surfaced by every barrier and read,
                // reported to the listener, and retried after a backoff.
                let _ = commit_pending(&sh2, Vec::new(), true);
            }
        });
        Ok(Arc::new(DbStore {
            shared,
            flusher: Mutex::new(Some(flusher)),
        }))
    }

    /// `listener` is called whenever saving starts failing or works again
    /// (see [`DbStore::failure`]).
    pub fn on_health_change(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        *self.shared.listener.lock().unwrap() = Some(listener);
    }

    /// Why saving is failing right now, if it is.
    pub fn failure(&self) -> Option<String> {
        let pending = self.shared.pending.lock().unwrap();
        let error = pending.error.clone()?;
        Some(match pending.dropped {
            0 => error,
            n => format!("{error} ({n} received records will be fetched again)"),
        })
    }

    /// Make the next `n` commits fail, as a full or failing disk would.
    #[cfg(test)]
    pub(crate) fn fail_commits(&self, n: usize) {
        self.shared.fail_commits.store(n, Ordering::SeqCst);
    }

    /// Fail now, rather than buffer a local change that can't be saved.
    pub fn check_writable(&self) -> Result<()> {
        match self.failure() {
            Some(error) => bail!("Mycel can't save to this device right now: {error}"),
            None => Ok(()),
        }
    }

    fn enqueue(&self, w: Write) {
        let shared = &self.shared;
        let mut pending = shared.pending.lock().unwrap();
        if pending.closed {
            pending
                .error
                .get_or_insert_with(|| "storage is closed".into());
            return;
        }
        if let Write::Kv(key, _) = &w {
            // A newer value supersedes a queued one: the queue is committed
            // whole, so the result is the same and repeated settings writes
            // can't grow the buffer.
            if let Some(i) = pending
                .queue
                .iter()
                .position(|q| matches!(q, Write::Kv(k, _) if k == key))
            {
                let old = pending.queue.remove(i);
                pending.bytes -= old.size();
            }
        } else {
            let limit = shared.max_buffered.load(Ordering::Relaxed);
            // Healthy but behind: wait for the flusher (backpressure).
            while pending.error.is_none()
                && !pending.closed
                && !pending.queue.is_empty()
                && pending.bytes + w.size() > limit
            {
                shared.cv.notify_all();
                pending = shared.cv.wait_timeout(pending, Duration::from_millis(100)).unwrap().0;
            }
            // Failing: never grow without bound. The record stays in memory in
            // its replica and peers send it again; local changes are refused
            // up front while failing (`check_writable`).
            if pending.error.is_some() && pending.bytes + w.size() > limit {
                pending.dropped += 1;
                return;
            }
        }
        pending.bytes += w.size();
        pending.queue.push(w);
        shared.cv.notify_all();
    }

    /// Barrier covering every write enqueued before this call, including any
    /// batch already drained by the background flusher.
    pub fn flush(&self) -> Result<()> {
        commit_pending(&self.shared, Vec::new(), false)
    }

    /// Apply a group of key-value changes in one durable transaction. Prior
    /// buffered writes are included. Callers must publish in-memory security
    /// changes only after this succeeds.
    pub fn kv_batch_durable(&self, entries: Vec<(String, Option<Vec<u8>>)>) -> Result<()> {
        let writes = entries.into_iter().map(|(k, v)| Write::Kv(k, v)).collect();
        commit_pending(&self.shared, writes, false)
    }

    pub fn close(&self) -> Result<()> {
        self.shared.pending.lock().unwrap().closed = true;
        self.shared.cv.notify_all();
        if let Some(h) = self.flusher.lock().unwrap().take() {
            h.join().map_err(|_| anyhow!("storage flusher panicked"))?;
        }
        // One last attempt, even after a failure.
        commit_pending(&self.shared, Vec::new(), true)
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
        self.shared.with_db(|db| {
            let txn = db.begin_read()?;
            let t = txn.open_table(KV)?;
            Ok(t.get(k)?.map(|v| v.value().to_vec()))
        })
    }

    pub fn kv_put(&self, k: &str, v: Vec<u8>) {
        self.enqueue(Write::Kv(k.to_string(), Some(v)));
    }

    pub fn kv_delete(&self, k: &str) {
        self.enqueue(Write::Kv(k.to_string(), None));
    }

    /// Every stored space: (genesis + other ops, envelopes), and how many
    /// undecodable records were moved aside into the quarantine table.
    pub fn load_spaces(&self) -> Result<(HashMap<SpaceId, StoredSpace>, u64)> {
        self.flush()?;
        let mut out: HashMap<SpaceId, StoredSpace> = HashMap::new();
        let mut bad: Vec<(&'static str, Vec<u8>, Vec<u8>)> = Vec::new();
        let space_of = |k: &[u8]| -> Option<Hash32> { Some(Hash32(k.get(..32)?.try_into().ok()?)).filter(|_| k.len() == 64) };
        self.shared.with_db(|db| {
            let txn = db.begin_read()?;
            for row in txn.open_table(OPS)?.iter()? {
                let (k, v) = row?;
                match (space_of(k.value()), postcard::from_bytes::<SignedOp>(v.value())) {
                    (Some(space), Ok(op)) => out.entry(space).or_default().0.push(op),
                    _ => bad.push(("ops", k.value().to_vec(), v.value().to_vec())),
                }
            }
            for row in txn.open_table(ENVS)?.iter()? {
                let (k, v) = row?;
                match (space_of(k.value()), postcard::from_bytes::<Envelope>(v.value())) {
                    (Some(space), Ok(env)) => out.entry(space).or_default().1.push(env),
                    _ => bad.push(("envelopes", k.value().to_vec(), v.value().to_vec())),
                }
            }
            Ok(())
        })?;
        let count = bad.len() as u64;
        if !bad.is_empty() {
            eprintln!("mycel: {count} stored records couldn't be read; set them aside");
            // Skipped either way; if moving them fails they're retried next time.
            if let Err(error) = self.quarantine(&bad) {
                eprintln!("mycel: couldn't set aside unreadable records: {error:#}");
            }
        }
        Ok((out, count))
    }

    fn quarantine(&self, rows: &[(&'static str, Vec<u8>, Vec<u8>)]) -> Result<()> {
        let _gate = self.shared.commit_gate.lock().unwrap();
        self.shared.with_db(|db| {
            let txn = db.begin_write()?;
            {
                let mut quarantine = txn.open_table(QUARANTINE)?;
                let mut ops = txn.open_table(OPS)?;
                let mut envs = txn.open_table(ENVS)?;
                for (table, key, value) in rows {
                    let kept = [table.as_bytes(), b"/", key].concat();
                    quarantine.insert(kept.as_slice(), value.as_slice())?;
                    match *table {
                        "ops" => ops.remove(key.as_slice())?,
                        _ => envs.remove(key.as_slice())?,
                    };
                }
            }
            txn.commit()?;
            Ok(())
        })
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

    async fn eventually(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition did not become true");
    }

    #[tokio::test]
    async fn failed_commits_are_retried_in_order_and_failed_barriers_are_not() {
        let (path, store) = test_store();
        let changes = Arc::new(AtomicUsize::new(0));
        let counter = changes.clone();
        store.on_health_change(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        store.shared.fail_commits.store(1, Ordering::SeqCst);
        store.kv_put("name", vec![1]);
        // Fails, either itself or because the background commit just did.
        assert!(
            store
                .kv_batch_durable(vec![("request".into(), Some(vec![1]))])
                .is_err()
        );
        assert!(store.failure().is_some());
        assert!(store.flush().is_err());
        assert!(store.check_writable().is_err());
        assert!(store.kv_get("name").is_err());
        store.kv_put("name", vec![2]);
        eventually(|| store.failure().is_none()).await;
        assert_eq!(store.kv_get("name").unwrap(), Some(vec![2]));
        assert_eq!(store.kv_get("request").unwrap(), None, "a failed barrier never lands later");
        assert_eq!(changes.load(Ordering::SeqCst), 2, "failing, then working again");
        store.check_writable().unwrap();
        store.close().unwrap();
        drop(store);
        fs_cleanup(path);
    }

    #[tokio::test]
    async fn buffer_is_bounded_while_failing_and_kept_records_land_in_order() {
        let (path, store) = test_store();
        store.shared.max_buffered.store(2_000, Ordering::SeqCst);
        store.shared.fail_commits.store(usize::MAX, Ordering::SeqCst);
        let space: SpaceId = Hash32([7; 32]);
        store.enqueue(Write::Op(key(&space, &Hash32([0; 32])), vec![0; 100]));
        eventually(|| store.failure().is_some()).await;
        for n in 1..=100u8 {
            store.enqueue(Write::Op(key(&space, &Hash32([n; 32])), vec![n; 100]));
            store.kv_put("name", vec![n]);
        }
        {
            let pending = store.shared.pending.lock().unwrap();
            assert!(pending.bytes <= 2_000 + 64, "{}", pending.bytes);
            assert_eq!(pending.queue.iter().filter(|w| matches!(w, Write::Kv(..))).count(), 1);
            assert!(pending.dropped > 0);
        }
        assert!(store.failure().unwrap().contains("fetched again"));
        store.shared.fail_commits.store(0, Ordering::SeqCst);
        eventually(|| store.failure().is_none()).await;
        assert_eq!(store.kv_get("name").unwrap(), Some(vec![100]));
        let kept = store.shared.with_db(|db| Ok(db.begin_read()?.open_table(OPS)?.iter()?.count())).unwrap();
        assert!((1..100).contains(&kept), "{kept}");
        store.close().unwrap();
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
        store.shared.with_db(|db| commit(db, &batch)).unwrap();
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
    async fn unreadable_records_are_set_aside_and_startup_continues() {
        let dir = std::env::temp_dir().join(format!(
            "mycel-corrupt-startup-{}-{}", std::process::id(), mycel_crypto::random_u64()
        ));
        let runtime = crate::Runtime::open(&dir, crate::api::NetworkMode::Local, None).await.unwrap();
        let id = runtime.profile().id;
        runtime.shutdown().await.unwrap();
        drop(runtime);
        let rows: [(&str, &[u8], &[u8]); 3] =
            [("ops", &[0u8; 64], &[255u8]), ("envelopes", &[1u8; 64], &[254u8, 1]), ("ops", &[2u8; 5], &[0u8])];
        {
            let db = Database::create(dir.join("mycel.redb")).unwrap();
            let transaction = db.begin_write().unwrap();
            {
                let mut ops = transaction.open_table(OPS).unwrap();
                let mut envs = transaction.open_table(ENVS).unwrap();
                for (table, key, value) in rows {
                    match table {
                        "ops" => ops.insert(key, value).unwrap(),
                        _ => envs.insert(key, value).unwrap(),
                    };
                }
            }
            transaction.commit().unwrap();
        }
        let runtime = crate::Runtime::open(&dir, crate::api::NetworkMode::Local, None).await.unwrap();
        assert_eq!(runtime.profile().id, id);
        assert!(runtime.notices().contains(&crate::api::Notice::RecordsSetAside { count: 3 }));
        runtime.shutdown().await.unwrap();
        drop(runtime);
        {
            let db = Database::create(dir.join("mycel.redb")).unwrap();
            let transaction = db.begin_read().unwrap();
            let quarantine = transaction.open_table(QUARANTINE).unwrap();
            let ops = transaction.open_table(OPS).unwrap();
            for (table, key, value) in rows {
                let kept = [table.as_bytes(), b"/", key].concat();
                assert_eq!(quarantine.get(kept.as_slice()).unwrap().unwrap().value(), value, "kept byte for byte");
                assert!(ops.get(key).unwrap().is_none());
            }
        }
        let runtime = crate::Runtime::open(&dir, crate::api::NetworkMode::Local, None).await.unwrap();
        assert!(runtime.notices().is_empty(), "set aside once");
        runtime.shutdown().await.unwrap();
        drop(runtime);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn fs_cleanup(path: std::path::PathBuf) {
        let _ = std::fs::remove_file(path);
    }
}
