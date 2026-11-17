//! The chunk protocol against devices that don't follow it, over real QUIC.
//! (The behaviour between honest devices is tested from outside the crate:
//! `tests/chunks.rs`.)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use mycel_crypto::chunked::{self, Mode};
use mycel_crypto::{DeviceKeys, Hash32};

use super::holders::{Holders, MemHolders};
use super::proto::{ChunkReq, ChunkResp};
use super::store::Source;
use super::transfer;
use crate::wire::{ALPN, StreamKind, recv, send};
use crate::{NetMode, Node, NodeOptions, stream_kind};

async fn node(name: &str) -> (Node, PathBuf) {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    let dir = std::env::temp_dir().join(format!("mycel-test-chunks-{:016x}", mycel_crypto::random_u64()));
    opts.blob_dir = Some(dir.clone());
    (Node::spawn(Arc::new(DeviceKeys::generate()), opts).await.unwrap(), dir)
}

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

fn seal(node: &Node, data: &[u8], owner: Hash32) -> chunked::SealedFile {
    let store = node.chunk_store().unwrap();
    let mut session = store.begin_seal();
    let f = chunked::seal_file(&Mode::private(), &[], &mut &data[..], |id, b| session.put(id, b), |_| {}).unwrap();
    session.finish(f.root, owner);
    f
}

fn open(node: &Node, f: &chunked::SealedFile) -> Vec<u8> {
    let store = node.chunk_store().unwrap();
    let mut out = Vec::new();
    chunked::open_file(&f.root, &f.key, f.len, |id| store.read(id), &mut out, |_| {}).unwrap();
    out
}

/// A device that answers every request for a node of the file with bytes
/// of the right length that aren't it. Returns its endpoint, its keys and
/// how many requests it got.
async fn liar(lens: HashMap<Hash32, u32>) -> (Endpoint, DeviceKeys, Arc<AtomicUsize>) {
    let keys = DeviceKeys::generate();
    let ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&keys.seed()))
        .relay_mode(iroh::RelayMode::Disabled)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let (accept, count, lens) = (ep.clone(), asked.clone(), Arc::new(lens));
    tokio::spawn(async move {
        while let Some(incoming) = accept.accept().await {
            let Ok(conn) = incoming.await else { continue };
            let (count, lens) = (count.clone(), lens.clone());
            tokio::spawn(async move {
                while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                    let (count, lens) = (count.clone(), lens.clone());
                    tokio::spawn(async move {
                        if stream_kind(&mut rx).await.ok() != Some(StreamKind::Chunk) {
                            return;
                        }
                        let Ok(ChunkReq::Get { id }) = recv::<ChunkReq>(&mut rx).await else { return };
                        count.fetch_add(1, Ordering::Relaxed);
                        match lens.get(&id) {
                            Some(len) => {
                                let _ = send(&mut tx, &ChunkResp::Found { len: *len }).await;
                                let _ = crate::resources::write_all(&mut tx, &vec![0x5a; *len as usize]).await;
                            }
                            None => {
                                let _ = send(&mut tx, &ChunkResp::NotFound).await;
                            }
                        }
                        tx.finish().ok();
                        let _ = tx.stopped().await;
                    });
                }
            });
        }
    });
    (ep, keys, asked)
}

/// A source sends wrong bytes for the first node it is asked for. They are
/// caught as they arrive (not at the end of the file), that source is not
/// asked again, and the file completes from a device found by lookup.
#[tokio::test(flavor = "multi_thread")]
async fn a_source_that_sends_wrong_bytes_is_dropped_at_that_piece() {
    let (honest, honest_dir) = node("honest").await;
    let (victim, victim_dir) = node("victim").await;
    let owner = Hash32([1; 32]);
    let data = pseudo_random(6 * 1024 * 1024 + 99, 5);
    let file = seal(&honest, &data, owner);
    let tree = honest.chunk_store().unwrap().tree(&file.root);
    let (liar_ep, liar_keys, asked) = liar(tree.nodes.iter().map(|n| (n.0, n.1)).collect()).await;
    victim.add_peer_addr(honest.addr());
    victim.add_peer_addr(liar_ep.addr());
    let holders = MemHolders::new();
    holders.announce(file.root, honest.keys().clone()).await.unwrap();
    victim.set_holders(Arc::new(holders.clone()));

    // the liar is the only source at first; the honest one is looked up after
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let progress = {
        let seen = seen.clone();
        Arc::new(move |done, total| seen.lock().push((done, total)))
    };
    transfer::fetch(&victim.inner, owner, file.root, file.len, None, vec![liar_keys.sign_pk()], progress)
        .await
        .unwrap();
    assert_eq!(open(&victim, &file), data);
    assert!(victim.file_complete(file.root).await);
    assert_eq!(asked.load(Ordering::Relaxed), 1, "one wrong answer, and the liar is not asked again");
    assert_eq!(holders.lookups(), vec![file.root]);
    let last = *seen.lock().last().unwrap();
    assert_eq!(last, (file.sealed_len, file.sealed_len), "progress ends at the total");

    // Alone, the liar gets nowhere, and nothing wrong is ever stored.
    let (lonely, lonely_dir) = node("lonely").await;
    lonely.add_peer_addr(liar_ep.addr());
    let err = transfer::fetch(
        &lonely.inner,
        owner,
        file.root,
        file.len,
        None,
        vec![liar_keys.sign_pk()],
        Arc::new(|_, _| {}),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match its id"), "{err:#}");
    assert!(tree.nodes.iter().all(|n| !lonely.chunk_store().unwrap().has(&n.0)));

    liar_ep.close().await;
    for n in [&honest, &victim, &lonely] {
        n.shutdown().await.unwrap();
    }
    for d in [honest_dir, victim_dir, lonely_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A reference that claims a small file can't make a device fetch a big one.
#[tokio::test(flavor = "multi_thread")]
async fn a_tree_bigger_than_its_message_says_is_refused() {
    let (sender, sender_dir) = node("sender").await;
    let (receiver, receiver_dir) = node("receiver").await;
    let owner = Hash32([2; 32]);
    let data = pseudo_random(3 * 1024 * 1024, 9);
    let file = seal(&sender, &data, owner);
    receiver.add_peer_addr(sender.addr());
    let fetch = |size: u64| {
        let (inner, root, from) = (receiver.inner.clone(), file.root, sender.id());
        async move { transfer::fetch(&inner, owner, root, size, None, vec![from], Arc::new(|_, _| {})).await }
    };
    let err = fetch(1024).await.unwrap_err();
    assert!(format!("{err:#}").contains("larger than its message says"), "{err:#}");
    assert!(!receiver.file_complete(file.root).await);
    // with the size it really has, the same file comes
    fetch(file.len).await.unwrap();
    assert_eq!(open(&receiver, &file), data);
    for n in [&sender, &receiver] {
        n.shutdown().await.unwrap();
    }
    for d in [sender_dir, receiver_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Nothing is taken without an accepted offer, no more than it declared,
/// and nothing that isn't what its id says.
#[tokio::test(flavor = "multi_thread")]
async fn pushes_need_an_accepted_offer_and_stay_within_it() {
    let (pusher, pusher_dir) = node("pusher").await;
    let (holder, holder_dir) = node("holder").await;
    pusher.add_peer_addr(holder.addr());
    let conn = pusher.inner.endpoint.connect(holder.addr(), ALPN).await.unwrap();
    let ask = |req: ChunkReq, body: Vec<u8>| {
        let conn = conn.clone();
        async move {
            let (mut tx, mut rx) = crate::open_bi(&conn, StreamKind::Chunk).await.unwrap();
            send(&mut tx, &req).await.unwrap();
            let _ = crate::resources::write_all(&mut tx, &body).await;
            tx.finish().ok();
            recv::<ChunkResp>(&mut rx).await.unwrap()
        }
    };
    let piece = |seed: u64, len: usize| {
        let bytes = pseudo_random(len, seed);
        (chunked::node_id(&bytes), bytes)
    };
    let root = Hash32([7; 32]);
    let store = holder.chunk_store().unwrap();
    // no offer: refused
    let (a, ab) = piece(1, 1000);
    assert_eq!(ask(ChunkReq::Put { root, id: a, len: 1000 }, ab.clone()).await, ChunkResp::Denied);
    assert!(!store.has(&a));
    // an offer for 1500 bytes: one piece fits, the next doesn't
    assert_eq!(ask(ChunkReq::Offer { space: None, root, total: 1500 }, vec![]).await, ChunkResp::Accept);
    assert_eq!(ask(ChunkReq::Put { root, id: a, len: 1000 }, ab).await, ChunkResp::Stored);
    let (b, bb) = piece(2, 1000);
    assert_eq!(ask(ChunkReq::Put { root, id: b, len: 1000 }, bb).await, ChunkResp::Denied);
    assert!(store.has(&a) && !store.has(&b));
    // bytes that aren't what their id says
    let (c, _) = piece(3, 400);
    assert_eq!(ask(ChunkReq::Put { root, id: c, len: 400 }, vec![1; 400]).await, ChunkResp::Denied);
    assert!(!store.has(&c));
    // "all here" is checked, not believed
    assert_eq!(ask(ChunkReq::Done { root }, vec![]).await, ChunkResp::Incomplete);
    // a space the pusher isn't in (or we don't have): refused
    let space = Hash32([9; 32]);
    assert_eq!(ask(ChunkReq::Offer { space: Some(space), root, total: 10 }, vec![]).await, ChunkResp::Denied);
    // a cache that holds nothing takes nothing
    holder.set_cache_budget(0);
    assert!(!store.has(&a), "shrinking the budget drops what it held");
    assert_eq!(ask(ChunkReq::Offer { space: None, root, total: 10 }, vec![]).await, ChunkResp::NoSpace);
    // and what it has is still found by anyone who asks, or not
    assert_eq!(ask(ChunkReq::Get { id: a }, vec![]).await, ChunkResp::NotFound);
    let (d, db) = piece(4, 300);
    store.insert(d, &db, Source::Own).unwrap_err();
    for n in [&pusher, &holder] {
        n.shutdown().await.unwrap();
    }
    for dir in [pusher_dir, holder_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A member pushing a file for a conversation can store that file's nodes
/// and nothing else, and an offer alone leaves nothing behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_conversation_push_takes_only_the_files_own_nodes() {
    use mycel_trust::Role;
    let (pusher, pusher_dir) = node("pusher").await;
    let (holder, holder_dir) = node("holder").await;
    pusher.add_peer_addr(holder.addr());
    holder.add_peer_addr(pusher.addr());
    let (space, genesis) = pusher.create_space().unwrap();
    pusher.with_space(&space, |r| r.add_member(holder.keys().public(), Role::Writer)).unwrap().unwrap();
    holder.join_space(genesis).unwrap();
    holder.sync_with(pusher.id(), space, true).await.unwrap();
    // a cache that takes nothing: whatever lands is there because it is pinned
    holder.set_cache_budget(0);
    let data = pseudo_random(2 * 1024 * 1024 + 5, 11);
    let file = seal(&pusher, &data, space);
    let source = pusher.chunk_store().unwrap();
    let tree = source.tree(&file.root);
    let leaf = tree.nodes.iter().find(|n| !n.2).unwrap().0;
    let conn = pusher.inner.endpoint.connect(holder.addr(), ALPN).await.unwrap();
    let ask = |req: ChunkReq, body: Vec<u8>| {
        let conn = conn.clone();
        async move {
            let (mut tx, mut rx) = crate::open_bi(&conn, StreamKind::Chunk).await.unwrap();
            send(&mut tx, &req).await.unwrap();
            let _ = crate::resources::write_all(&mut tx, &body).await;
            tx.finish().ok();
            recv::<ChunkResp>(&mut rx).await.unwrap()
        }
    };
    let put =
        |root: Hash32, id: Hash32, bytes: Vec<u8>| ask(ChunkReq::Put { root, id, len: bytes.len() as u32 }, bytes);
    let store = holder.chunk_store().unwrap();
    let stray = pseudo_random(700, 12);
    let stray_id = chunked::node_id(&stray);

    // an offer for a file that never comes pins nothing
    let ghost = Hash32([5; 32]);
    assert_eq!(ask(ChunkReq::Offer { space: Some(space), root: ghost, total: 5000 }, vec![]).await, ChunkResp::Accept);
    assert_eq!(store.stats().pinned_files, 0);
    // bytes that aren't an index don't become a pinned root
    assert_eq!(put(stray_id, stray_id, stray.clone()).await, ChunkResp::Denied, "no offer for that root");
    assert_eq!(
        ask(ChunkReq::Offer { space: Some(space), root: stray_id, total: 5000 }, vec![]).await,
        ChunkResp::Accept
    );
    assert_eq!(put(stray_id, stray_id, stray.clone()).await, ChunkResp::Denied, "a root must be an index");
    assert_eq!(store.stats().pinned_files, 0);

    // the real file: its root, then what the root lists; nothing else
    let offer = ChunkReq::Offer { space: Some(space), root: file.root, total: tree.total() };
    assert_eq!(ask(offer, vec![]).await, ChunkResp::Accept);
    assert_eq!(put(file.root, leaf, source.read(&leaf).unwrap()).await, ChunkResp::Denied, "not before its index");
    assert_eq!(put(file.root, stray_id, stray.clone()).await, ChunkResp::Denied);
    assert_eq!(put(file.root, file.root, source.read(&file.root).unwrap()).await, ChunkResp::Stored);
    assert!(store.is_pinned(&file.root, Some(&space)));
    assert_eq!(put(file.root, stray_id, stray).await, ChunkResp::Denied, "not part of the file");
    for (id, _, _) in tree.nodes.iter().skip(1) {
        assert_eq!(put(file.root, *id, source.read(id).unwrap()).await, ChunkResp::Stored);
    }
    assert_eq!(ask(ChunkReq::Done { root: file.root }, vec![]).await, ChunkResp::Complete);
    assert_eq!(open(&holder, &file), data);
    assert!(!store.has(&stray_id));
    assert_eq!(store.stats().cache_nodes, 0);

    // a file too big to be pushed to a device that isn't a keeper
    let big = ChunkReq::Offer { space: Some(space), root: ghost, total: crate::EAGER_PUSH_MAX + 1 };
    assert_eq!(ask(big, vec![]).await, ChunkResp::Denied);
    for n in [&pusher, &holder] {
        n.shutdown().await.unwrap();
    }
    for dir in [pusher_dir, holder_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
