//! Blob transfer over real QUIC: streaming to disk, resume after an
//! interrupted download, recovery from a corrupt partial file, serving from
//! any member that has the blob, and the eager-push policy.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::{DeviceKeys, Hash32};
use mycel_net::{EAGER_PUSH_MAX, NetMode, Node, NodeOptions, Progress, blob_digest};
use mycel_trust::{Role, SpaceId};
use parking_lot::Mutex;

const MIB: usize = 1024 * 1024;

async fn node(name: &str) -> (Node, PathBuf) {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    let dir = std::env::temp_dir().join(format!("mycel-test-blobs-{}", mycel_crypto::random_u64()));
    opts.blob_dir = Some(dir.clone());
    (Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap(), dir)
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Deterministic, incompressible-looking bytes (xorshift).
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Write `bytes` as a staged blob of `node` (streaming hash), then add it.
async fn add_file_blob(node: &Node, space: SpaceId, bytes: &[u8]) -> Hash32 {
    let staged = node.blob_staging_path().unwrap();
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    let mut f = std::fs::File::create(&staged).unwrap();
    let mut d = blob_digest();
    for chunk in bytes.chunks(MIB) {
        f.write_all(chunk).unwrap();
        d.update(chunk);
    }
    drop(f);
    let hash = d.finalize();
    assert_eq!(hash, mycel_net::wire::blob_hash(bytes), "streaming hash == one-shot hash");
    node.add_blob(space, &staged, hash).await.unwrap();
    hash
}

type Seen = Arc<Mutex<Vec<(u64, u64)>>>;

fn recorder() -> (Progress, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    (Arc::new(move |d, t| s.lock().push((d, t))), seen)
}

fn part(dir: &Path, space: &SpaceId, hash: &Hash32) -> PathBuf {
    dir.join(space.to_string()).join(format!("{hash}.part"))
}

#[tokio::test(flavor = "multi_thread")]
async fn big_blobs_stream_resume_and_follow_push_policy() {
    let (alice, alice_dir) = node("alice").await;
    let (bob, bob_dir) = node("bob").await;
    let (carol, carol_dir) = node("carol").await;
    let (keeper, keeper_dir) = node("keeper").await;
    let all = [&alice, &bob, &carol, &keeper];
    for a in all {
        for b in all {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
    let (space, genesis) = alice.create_space().unwrap();
    alice
        .with_space(&space, |r| {
            r.add_member(bob.keys().public(), Role::Writer)?;
            r.add_member(carol.keys().public(), Role::Writer)?;
            r.add_member(keeper.keys().public(), Role::Relay)
        })
        .unwrap()
        .unwrap();
    for n in [&bob, &carol, &keeper] {
        n.join_space(genesis.clone()).unwrap();
        n.sync_with(alice.id(), space, true).await.unwrap();
    }

    // Small blob: pushed to everyone right away.
    let small = pseudo_random(MIB, 1);
    let small_hash = alice.put_blob(space, small.clone()).await.unwrap();
    eventually("small blob pushed to every member", || {
        [&bob, &carol, &keeper].iter().all(|n| n.blob_path(&space, &small_hash).is_some())
    })
    .await;

    // Big blob (> EAGER_PUSH_MAX): only the keeper gets it eagerly.
    let big = pseudo_random(40 * MIB, 2);
    assert!(big.len() as u64 > EAGER_PUSH_MAX);
    let hash = add_file_blob(&alice, space, &big).await;
    eventually("keeper holds the big blob", || keeper.blob_path(&space, &hash).is_some()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(bob.blob_path(&space, &hash).is_none(), "big blobs aren't pushed to members");
    assert_eq!(std::fs::read(keeper.blob_path(&space, &hash).unwrap()).unwrap(), big);

    // Bob starts downloading and is interrupted part way.
    let (progress, seen) = recorder();
    let fetch = {
        let bob = Arc::new(bob);
        let b = bob.clone();
        let task = tokio::spawn(async move { b.fetch_blob_with_progress(space, hash, progress).await });
        eventually("download under way", || seen.lock().last().is_some_and(|(d, _)| *d >= 4 * MIB as u64)).await;
        task.abort();
        let _ = task.await;
        bob
    };
    let partial = std::fs::metadata(part(&bob_dir, &space, &hash)).unwrap().len();
    assert!(partial > 0 && partial < big.len() as u64, "interrupted download leaves a .part ({partial})");
    assert!(fetch.blob_path(&space, &hash).is_none());

    // …and resumes where it stopped.
    let (progress, seen) = recorder();
    let path = fetch.fetch_blob_with_progress(space, hash, progress).await.unwrap();
    let first = seen.lock()[0];
    assert!(first.0 >= partial, "resumed from {first:?}, partial {partial}");
    assert_eq!(seen.lock().last().unwrap(), &(big.len() as u64, big.len() as u64));
    assert_eq!(std::fs::read(&path).unwrap(), big);
    assert!(!part(&bob_dir, &space, &hash).exists());

    // Alice goes offline. Carol has a corrupt partial copy; it's detected,
    // dropped, and she gets the blob from whoever else has it.
    alice.shutdown().await.unwrap();
    let carol_part = part(&carol_dir, &space, &hash);
    std::fs::create_dir_all(carol_part.parent().unwrap()).unwrap();
    std::fs::write(&carol_part, vec![0xAB; 3 * MIB]).unwrap();
    let path = carol.fetch_blob(space, hash).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), big);

    for n in [&*fetch, &carol, &keeper] {
        n.shutdown().await.unwrap();
    }
    for d in [alice_dir, bob_dir, carol_dir, keeper_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn free_space_guard() {
    let dir = std::env::temp_dir();
    if mycel_net::free_space(&dir).is_some() {
        let e = mycel_net::ensure_free_space(&dir, u64::MAX / 4).unwrap_err().to_string();
        assert!(e.contains("not enough disk space"), "{e}");
    }
    assert_eq!(mycel_net::human_size(1536), "1.5 KB");
    assert_eq!(mycel_net::human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
}
