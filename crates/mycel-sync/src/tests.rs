use super::*;
use automerge::{ROOT, transaction::Transactable};
use serde_json::json;

fn dev() -> Arc<DeviceKeys> {
    Arc::new(DeviceKeys::generate())
}

/// Full bidirectional sync of ops then envelopes (what mycel-net does over Iroh).
fn sync(a: &mut Replica, b: &mut Replica) {
    for _ in 0..2 {
        for id in a.op_ids() {
            let op = a.op(&id).unwrap().clone();
            b.ingest_op(op).unwrap();
        }
        for id in b.op_ids() {
            let op = b.op(&id).unwrap().clone();
            a.ingest_op(op).unwrap();
        }
        for id in a.envelope_ids() {
            b.ingest_envelope(a.envelope(&id).unwrap().clone()).unwrap();
        }
        for id in b.envelope_ids() {
            a.ingest_envelope(b.envelope(&id).unwrap().clone()).unwrap();
        }
    }
}

fn put(r: &mut Replica, doc: StreamId, key: &str, val: &str) -> Envelope {
    let (k, v) = (key.to_string(), val.to_string());
    r.change(doc, move |d| d.put(ROOT, k, v)).unwrap().1.unwrap()
}

/// Founder + a member with `role`, both synced.
fn pair(role: Role) -> (Replica, Replica, Arc<DeviceKeys>) {
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis, None).unwrap();
    a.add_member(bk.public(), role).unwrap();
    sync(&mut a, &mut b);
    (a, b, bk)
}

#[test]
fn writer_changes_replicate() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    put(&mut a, doc, "title", "Groceries");
    put(&mut b, doc, "note", "eggs");
    sync(&mut a, &mut b);
    assert_eq!(a.doc_json(&doc), json!({"title": "Groceries", "note": "eggs"}));
    assert_eq!(a.doc_json(&doc), b.doc_json(&doc));
}

#[test]
fn reader_writes_are_rejected_everywhere() {
    let (mut a, mut r, _) = pair(Role::Reader);
    let doc = Replica::new_doc_id();
    put(&mut a, doc, "title", "Story");
    sync(&mut a, &mut r);
    assert_eq!(r.doc_json(&doc), json!({"title": "Story"}), "reader can read");

    let env = put(&mut r, doc, "title", "HACKED");
    assert_eq!(
        r.status(&env.id()),
        Status::Invalid("author not a writer at auth_heads")
    );
    assert_eq!(r.doc_json(&doc), json!({"title": "Story"}), "rolled back locally");
    sync(&mut a, &mut r);
    assert_eq!(a.doc_json(&doc), json!({"title": "Story"}));
}

#[test]
fn keeper_stores_and_validates_but_cannot_read() {
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    let kk = dev();
    let mut keeper = Replica::join(kk.clone(), genesis, None).unwrap();
    a.add_member(kk.public(), Role::Relay).unwrap();
    let doc = Replica::new_doc_id();
    let env = put(&mut a, doc, "secret", "the source is X");
    sync(&mut a, &mut keeper);

    assert_eq!(keeper.status(&env.id()), Status::Valid, "keeper can validate");
    assert_eq!(keeper.opaque_count(), 1);
    assert_eq!(keeper.doc_json(&doc), serde_json::Value::Null, "keeper can't read");
    let ct = &keeper.envelope(&env.id()).unwrap().ciphertext;
    assert!(!String::from_utf8_lossy(ct).contains("the source is X"));
}

#[test]
fn outsider_and_tampered_envelopes() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    put(&mut a, doc, "k", "v");

    // An outsider who learned the genesis op can replicate the graph but has no
    // role and no keys: it cannot even produce an envelope.
    let genesis = a.op(&a.space_id()).unwrap().clone();
    let mut eve = Replica::join(dev(), genesis, None).unwrap();
    sync(&mut a, &mut eve);
    assert!(eve.change(doc, |d| d.put(ROOT, "k", "evil")).is_err());

    // Tampering with ciphertext breaks the signature.
    let mut env = put(&mut a, doc, "k", "v2");
    env.ciphertext[0] ^= 1;
    assert!(matches!(b.ingest_envelope(env), Err(SyncError::Crypto(_))));
}

#[test]
fn outsider_signed_envelope_is_invalid() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    put(&mut a, doc, "k", "v");
    sync(&mut a, &mut b);
    // Eve signs a well-formed envelope using an epoch id she saw in public ops.
    let eve = dev();
    let header = Header {
        space: a.space_id(),
        stream: doc,
        author: eve.sign_pk(),
        author_seq: 0,
        author_prev: None,
        auth_heads: a.graph.heads(),
        epoch: a.graph.state().write_epoch().unwrap(),
        nonce: random(),
    };
    let ct = b"garbage".to_vec();
    let sig = eve.sign(CTX_ENV_SIG, &[&encode(&header), &ct]);
    let env = Envelope { header, ciphertext: ct, sig };
    let id = env.id();
    // Refused at the door: never stored, never relayed.
    assert!(matches!(a.ingest_envelope(env), Err(SyncError::NotAllowed(_))));
    assert!(!a.has_envelope(&id));
}

#[test]
fn author_cannot_write_under_another_actor() {
    let (mut a, mut b, bk) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    put(&mut a, doc, "k", "a");
    sync(&mut a, &mut b);

    // b crafts an Automerge change whose actor is a's key, and seals it as b.
    let mut forged = AutoCommit::new().with_actor(ActorId::from(a.me.sign_pk().0.to_vec()));
    forged.put(ROOT, "k", "forged").unwrap();
    forged.commit();
    let plain = forged.get_last_local_change().unwrap().bytes().to_vec();
    let epoch = b.graph.state().write_epoch().unwrap();
    let header = Header {
        space: b.space_id(),
        stream: doc,
        author: bk.sign_pk(),
        author_seq: 0,
        author_prev: None,
        auth_heads: b.graph.heads(),
        epoch,
        nonce: random(),
    };
    let key = b.ring.get(&epoch).unwrap();
    let ct = key.seal(&header.nonce, &content_aad(&header), &plain).unwrap();
    let sig = bk.sign(CTX_ENV_SIG, &[&encode(&header), &ct]);
    a.ingest_envelope(Envelope { header, ciphertext: ct, sig }).unwrap();
    assert_eq!(a.doc_json(&doc), json!({"k": "a"}), "forged actor never applied");
}

#[test]
fn removal_cuts_off_reads_and_backdated_writes() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    let before = put(&mut b, doc, "b", "old edit");
    sync(&mut a, &mut b);

    a.remove_member(b.me.sign_pk()).unwrap();
    // b hasn't heard yet and keeps writing with stale auth_heads (= backdating).
    let after = put(&mut b, doc, "b", "edit after removal");
    put(&mut a, doc, "a", "new secret");
    sync(&mut a, &mut b);

    for r in [&a, &b] {
        assert_eq!(r.status(&before.id()), Status::Valid, "pre-removal edits survive");
        assert_eq!(r.status(&after.id()), Status::Invalid("beyond revocation cutoff"));
    }
    assert_eq!(a.doc_json(&doc), json!({"b": "old edit", "a": "new secret"}));
    assert_eq!(b.doc_json(&doc), json!({"b": "old edit"}), "can't decrypt new epoch");

    // Once b knows it was removed, it has no write epoch key and no role to rotate.
    assert!(b.change(doc, |d| d.put(ROOT, "b", "again")).is_err());
}

#[test]
fn concurrent_edits_converge() {
    let (mut a, genesis) = Replica::create(dev(), None).unwrap();
    let (bk, ck) = (dev(), dev());
    let mut b = Replica::join(bk.clone(), genesis.clone(), None).unwrap();
    let mut c = Replica::join(ck.clone(), genesis, None).unwrap();
    a.add_member(bk.public(), Role::Writer).unwrap();
    a.add_member(ck.public(), Role::Writer).unwrap();
    sync(&mut a, &mut b);
    sync(&mut a, &mut c);

    let doc = Replica::new_doc_id();
    for (i, r) in [&mut a, &mut b, &mut c].into_iter().enumerate() {
        put(r, doc, &format!("k{i}"), "x");
        put(r, doc, "shared", &format!("from {i}"));
    }
    sync(&mut a, &mut b);
    sync(&mut b, &mut c);
    sync(&mut a, &mut c);
    assert_eq!(a.doc_json(&doc), b.doc_json(&doc));
    assert_eq!(b.doc_json(&doc), c.doc_json(&doc));
    assert_eq!(a.doc_json(&doc).as_object().unwrap().len(), 4);
}

#[test]
fn demoted_writer_becomes_read_only() {
    let (mut a, mut b, bk) = pair(Role::Writer);
    let doc = Replica::new_doc_id();
    put(&mut b, doc, "k", "by writer");
    sync(&mut a, &mut b);
    a.set_role(bk.sign_pk(), Role::Reader).unwrap();
    sync(&mut a, &mut b);
    let env = put(&mut b, doc, "k", "by reader");
    assert_eq!(
        b.status(&env.id()),
        Status::Invalid("author not a writer at auth_heads")
    );
    put(&mut a, doc, "k2", "admin");
    sync(&mut a, &mut b);
    assert_eq!(b.doc_json(&doc), json!({"k": "by writer", "k2": "admin"}), "still reads");
    assert_eq!(a.doc_json(&doc), b.doc_json(&doc));
}

#[test]
fn feeds_order_causally_and_converge() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let feed = StreamId::named(StreamKind::Feed, "messages");
    a.append(feed, b"a1".to_vec()).unwrap();
    a.append(feed, b"a2".to_vec()).unwrap();
    sync(&mut a, &mut b);
    // concurrent appends on both sides
    b.append(feed, b"b1".to_vec()).unwrap();
    a.append(feed, b"a3".to_vec()).unwrap();
    sync(&mut a, &mut b);
    let fa: Vec<Vec<u8>> = a.feed(&feed).into_iter().map(|i| i.body).collect();
    let fb: Vec<Vec<u8>> = b.feed(&feed).into_iter().map(|i| i.body).collect();
    assert_eq!(fa, fb, "same order everywhere");
    assert_eq!(&fa[..2], &[b"a1".to_vec(), b"a2".to_vec()], "causal prefix");
    assert_eq!(fa.len(), 4);
    // b1 and a3 both depend on a2
    let items = a.feed(&feed);
    assert!(items[2].deps.contains(&items[1].id) && items[3].deps.contains(&items[1].id));
    assert_eq!(items[0].author_role, Role::Admin);
}

#[test]
fn reader_feed_appends_rejected() {
    let (mut a, mut r, _) = pair(Role::Reader);
    let feed = StreamId::new_feed();
    a.append(feed, b"hello".to_vec()).unwrap();
    sync(&mut a, &mut r);
    let (_, env) = r.append(feed, b"spam".to_vec()).unwrap();
    assert!(matches!(r.status(&env.id()), Status::Invalid(_)));
    sync(&mut a, &mut r);
    assert_eq!(a.feed_len(&feed), 1);
    assert_eq!(r.feed_len(&feed), 1);
}

#[derive(Default)]
struct MemStore {
    ops: std::sync::Mutex<Vec<SignedOp>>,
    envs: std::sync::Mutex<Vec<Envelope>>,
}
impl Store for MemStore {
    fn put_op(&self, _: &SpaceId, op: &SignedOp) {
        self.ops.lock().unwrap().push(op.clone());
    }
    fn put_envelope(&self, _: &SpaceId, env: &Envelope) {
        self.envs.lock().unwrap().push(env.clone());
    }
}

#[test]
fn restore_from_store_reproduces_state() {
    let store = Arc::new(MemStore::default());
    let ak = dev();
    let (mut a, genesis) = Replica::create(ak.clone(), Some(store.clone())).unwrap();
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis.clone(), None).unwrap();
    a.add_member(bk.public(), Role::Writer).unwrap();
    sync(&mut a, &mut b);
    let feed = StreamId::new_feed();
    let doc = StreamId::new_doc();
    b.append(feed, b"from b".to_vec()).unwrap();
    put(&mut b, doc, "k", "v");
    sync(&mut a, &mut b);
    a.append(feed, b"from a".to_vec()).unwrap();

    let ops: Vec<SignedOp> = store.ops.lock().unwrap().iter()
        .filter(|o| o.id() != genesis.id()).cloned().collect();
    let envs = store.envs.lock().unwrap().clone();
    let mut restored = Replica::restore(ak, genesis, ops, envs, None).unwrap();
    assert_eq!(restored.graph().state(), a.graph().state());
    assert_eq!(restored.feed(&feed), a.feed(&feed));
    assert_eq!(restored.doc_json(&doc), a.doc_json(&doc));
    // and it can keep writing on the same author chain
    let (_, env) = restored.append(feed, b"after restart".to_vec()).unwrap();
    assert_eq!(restored.status(&env.id()), Status::Valid);
}

#[test]
fn many_messages_ingest_quickly() {
    let (mut a, mut b, _) = pair(Role::Writer);
    let feed = StreamId::new_feed();
    for i in 0..2000 {
        a.append(feed, format!("msg {i}").into_bytes()).unwrap();
    }
    let envs: Vec<Envelope> = a.envelope_ids().iter().map(|i| a.envelope(i).unwrap().clone()).collect();
    let t = std::time::Instant::now();
    let res = b.ingest_batch(vec![], envs);
    let took = t.elapsed();
    assert_eq!(res.envelopes, 2000);
    assert_eq!(b.feed_len(&feed), 2000);
    assert_eq!(b.feed(&feed).last().unwrap().body, b"msg 1999");
    assert!(took.as_secs_f64() < 10.0, "ingest took {took:?}");
    eprintln!("ingested 2000 envelopes in {took:?}");
}

#[test]
fn doc_equivocation_resolves_identically_everywhere() {
    let (mut a, mut b, bk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    put(&mut a, doc, "base", "x");
    sync(&mut a, &mut b);
    // b equivocates: two different changes with the same (actor, seq)
    let fork = |val: &str| -> Envelope {
        let mut d = b.doc(&doc).unwrap().clone();
        d.put(ROOT, "k", val.to_string()).unwrap();
        d.commit();
        let plain = d.get_last_local_change().unwrap().bytes().to_vec();
        let epoch = b.graph.state().write_epoch().unwrap();
        let (seq, prev) = b.my_chain_tip();
        let header = Header { space: b.space_id(), stream: doc, author: bk.sign_pk(),
            author_seq: seq, author_prev: prev, auth_heads: b.graph.heads(), epoch, nonce: random() };
        let ct = b.ring.get(&epoch).unwrap().seal(&header.nonce, &content_aad(&header), &plain).unwrap();
        let sig = bk.sign(CTX_ENV_SIG, &[&encode(&header), &ct]);
        Envelope { header, ciphertext: ct, sig }
    };
    let e1 = fork("one");
    let e2 = fork("two");
    // a and c (another device of b's) receive them in opposite orders
    let mut c = Replica::join(bk.clone(), a.op(&a.space_id()).unwrap().clone(), None).unwrap();
    c.ingest_batch(a.all_ops(), a.envelope_ids().iter().map(|i| a.envelope(i).unwrap().clone()).collect());
    a.ingest_envelope(e1.clone()).unwrap();
    a.ingest_envelope(e2.clone()).unwrap();
    c.ingest_envelope(e2).unwrap();
    c.ingest_envelope(e1).unwrap();
    assert_eq!(a.doc_json(&doc), c.doc_json(&doc), "same winner regardless of order");
}
