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

#[test]
fn invalid_membership_fanout_does_not_block_sealing() {
    let (mut a, reader, rk) = pair(Role::Reader);
    let target = dev();
    let ops = (0..65).map(|nonce| mycel_trust::SignedOp::sign(&rk, mycel_trust::Op {
        space: Some(a.space_id()), parents: reader.graph.heads(), author: rk.sign_pk(), nonce,
        action: mycel_trust::Action::Add { member: target.public(), role: Role::Relay, keyring: None },
    })).collect();
    let result = a.ingest_batch(ops, vec![]);
    assert_eq!(result.rejected, 0);
    let doc = StreamId::new_doc();
    let env = put(&mut a, doc, "still", "writable");
    assert_eq!(env.header.auth_heads.len(), 1);
    assert_eq!(a.doc_json(&doc), json!({"still": "writable"}));
}

#[test]
fn revocation_recomputes_equivocation_from_remaining_valid_changes() {
    let (mut a, b, bk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let fork = |value: &str| {
        let mut d = AutoCommit::new().with_actor(ActorId::from(bk.sign_pk().0.to_vec()));
        d.put(ROOT, "fork", value).unwrap();
        d.commit();
        let plaintext = d.get_last_local_change().unwrap().bytes().to_vec();
        signed_doc_payload(&b, doc, &plaintext)
    };
    let one = fork("one");
    let two = fork("two");
    let (x, y) = if one.id() < two.id() { (one, two) } else { (two, one) };
    a.ingest_envelope(y.clone()).unwrap();
    a.ingest_envelope(x.clone()).unwrap();
    assert!(a.equivocated.contains(&y.id()));
    let (remove, _, _) = a.graph.remove_member(&a.me, bk.sign_pk(), Some(y.id())).unwrap();
    a.ingest_op(remove).unwrap();
    assert_eq!(a.status(&x.id()), Status::Invalid("beyond revocation cutoff"));
    assert_eq!(a.status(&y.id()), Status::Valid);
    let restored = Replica::restore(a.me.clone(), a.op(&a.space_id()).unwrap().clone(), a.all_ops(),
        a.envelope_ids().iter().map(|id| a.envelope(id).unwrap().clone()).collect(), None).unwrap();
    assert_eq!(a.doc_json(&doc), restored.doc_json(&doc));
    assert!(!a.equivocated.contains(&y.id()));
    assert!(a.doc_json(&doc).get("fork").is_some());
}

fn signed_doc_payload(author: &Replica, doc: StreamId, plaintext: &[u8]) -> Envelope {
    let epoch = author.graph.state().write_epoch().unwrap();
    let (author_seq, author_prev) = author.my_chain_tip();
    let header = Header { space: author.space_id(), stream: doc, author: author.me.sign_pk(),
        author_seq, author_prev, auth_heads: author.graph.heads(), epoch, nonce: random() };
    let ciphertext = author.ring.get(&epoch).unwrap().seal(&header.nonce, &content_aad(&header), plaintext).unwrap();
    let sig = author.me.sign(CTX_ENV_SIG, &[&encode(&header), &ciphertext]);
    Envelope { header, ciphertext, sig }
}

#[test]
fn oversized_compressed_change_is_not_materialized() {
    let (mut a, b, bk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let mut d = AutoCommit::new().with_actor(ActorId::from(bk.sign_pk().0.to_vec()));
    d.put(ROOT, "oversized", "z".repeat(MAX_ENVELOPE_CIPHERTEXT + 1)).unwrap();
    d.commit();
    let mut change = d.get_last_local_change().unwrap();
    assert!(change.raw_bytes().len() > MAX_ENVELOPE_CIPHERTEXT);
    let plain = change.bytes().to_vec();
    assert_eq!(plain[8], 2, "test must exercise a compressed change");
    assert!(plain.len() < MAX_ENVELOPE_CIPHERTEXT);
    a.ingest_envelope(signed_doc_payload(&b, doc, &plain)).unwrap();
    assert!(a.doc_json(&doc).get("oversized").is_none());
}

#[test]
fn oversized_local_change_rolls_back_before_next_edit() {
    let (mut a, _) = Replica::create(dev(), None).unwrap();
    let doc = StreamId::new_doc();
    put(&mut a, doc, "kept", "small");
    let count = a.envelope_ids().len();
    assert!(matches!(a.change(doc, |d| d.put(ROOT, "oversized", "z".repeat(MAX_ENVELOPE_CIPHERTEXT + 1))), Err(SyncError::TooLarge)));
    assert_eq!(a.envelope_ids().len(), count);
    assert_eq!(a.doc_json(&doc), json!({"kept": "small"}));
    put(&mut a, doc, "next", "works");
    assert_eq!(a.doc_json(&doc), json!({"kept": "small", "next": "works"}));
}

#[test]
fn oversized_local_operation_run_rolls_back_before_next_edit() {
    let (mut a, _) = Replica::create(dev(), None).unwrap();
    let doc = StreamId::new_doc();
    put(&mut a, doc, "kept", "small");
    let count = a.envelope_ids().len();
    let result = a.change(doc, |d| {
        let text = d.put_object(ROOT, "text", automerge::ObjType::Text)?;
        d.splice_text(&text, 0, 0, &"a".repeat(MAX_DOC_CHANGE_OPS))
    });
    assert!(matches!(result, Err(SyncError::TooLarge)));
    assert_eq!(a.envelope_ids().len(), count);
    assert_eq!(a.doc_json(&doc), json!({"kept": "small"}));
    put(&mut a, doc, "next", "works");
    assert_eq!(a.doc_json(&doc), json!({"kept": "small", "next": "works"}));
}

#[test]
fn malformed_change_sequence_cannot_unwind_or_poison_document() {
    let (mut a, mut b, bk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    put(&mut a, doc, "kept", "small");
    let mut source = AutoCommit::new().with_actor(ActorId::from(bk.sign_pk().0.to_vec()));
    source.put(ROOT, "malformed", "discard").unwrap();
    source.commit();
    let mut expanded = source.get_last_local_change().unwrap().decode();
    expanded.seq = 2;
    assert!(expanded.deps.is_empty());
    let mut change = automerge::Change::from(expanded);
    let empty_doc = StreamId::new_doc();
    let empty_malformed = signed_doc_payload(&b, empty_doc, &change.bytes());
    let empty_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        a.ingest_envelope(empty_malformed)
    }));
    assert!(matches!(empty_result, Ok(Ok(true))));
    assert!(!a.docs.contains_key(&empty_doc), "failed apply must not create an empty document");
    let malformed = signed_doc_payload(&b, doc, &change.bytes());
    let id = malformed.id();
    let before_applied = a.docs[&doc].applied.clone();
    let before_seqs = a.docs[&doc].seqs.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        a.ingest_envelope(malformed)
    }));
    assert!(matches!(result, Ok(Ok(true))));
    assert_eq!(a.status(&id), Status::Valid, "auth status stays independent of document payload");
    assert_eq!(a.doc_json(&doc), json!({"kept": "small"}));
    assert_eq!(a.docs[&doc].applied, before_applied);
    assert_eq!(a.docs[&doc].seqs, before_seqs);
    let valid = put(&mut b, doc, "writer", "works");
    a.ingest_envelope(valid).unwrap();
    put(&mut a, doc, "next", "works");
    assert_eq!(a.doc_json(&doc), json!({"kept": "small", "writer": "works", "next": "works"}));
}

#[test]
fn malformed_waiting_change_does_not_block_its_real_dependency() {
    let (mut receiver, mut honest, _) = pair(Role::Writer);
    let attacker_keys = dev();
    receiver.add_member(attacker_keys.public(), Role::Writer).unwrap();
    let mut attacker = Replica::join(attacker_keys.clone(), receiver.op(&receiver.space_id()).unwrap().clone(), None).unwrap();
    sync(&mut receiver, &mut attacker);
    sync(&mut receiver, &mut honest);
    let doc = StreamId::new_doc();
    let dependency = put(&mut honest, doc, "good", "dependency");
    let hash = honest.doc(&doc).unwrap().clone().get_last_local_change().unwrap().hash();
    let mut source = AutoCommit::new().with_actor(ActorId::from(attacker_keys.sign_pk().0.to_vec()));
    source.put(ROOT, "malformed", "discard").unwrap();
    source.commit();
    let mut expanded = source.get_last_local_change().unwrap().decode();
    expanded.seq = 2; // attacker has no first change, even after the honest dep arrives
    expanded.deps = vec![hash];
    let mut change = automerge::Change::from(expanded);
    let malformed = signed_doc_payload(&attacker, doc, &change.bytes());
    let bad_id = malformed.id();
    receiver.ingest_envelope(malformed).unwrap();
    receiver.ingest_envelope(dependency).unwrap();
    assert_eq!(receiver.doc_json(&doc), json!({"good": "dependency"}));
    assert!(!receiver.docs[&doc].applied.contains(&bad_id));
    let next = put(&mut honest, doc, "next", "works");
    receiver.ingest_envelope(next).unwrap();
    assert_eq!(receiver.doc_json(&doc), json!({"good": "dependency", "next": "works"}));
    let restored = Replica::restore(receiver.me.clone(), receiver.op(&receiver.space_id()).unwrap().clone(),
        receiver.all_ops(), receiver.envelope_ids().iter().map(|id| receiver.envelope(id).unwrap().clone()).collect(), None).unwrap();
    assert_eq!(receiver.doc_json(&doc), restored.doc_json(&doc));
}

#[test]
fn document_changes_delivered_in_reverse_dependency_order_converge() {
    let (mut receiver, mut writer, _) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let mut envelopes = Vec::new();
    for n in 0..12 {
        envelopes.push(put(&mut writer, doc, &format!("key{n}"), &format!("value{n}")));
    }
    envelopes.reverse();
    let result = receiver.ingest_batch(vec![], envelopes.clone());
    assert_eq!(result.rejected, 0);
    assert_eq!(receiver.docs[&doc].applied.len(), envelopes.len());
    assert_eq!(receiver.doc_json(&doc), writer.doc_json(&doc));
    let restored = Replica::restore(receiver.me.clone(), receiver.op(&receiver.space_id()).unwrap().clone(),
        receiver.all_ops(), envelopes, None).unwrap();
    assert_eq!(restored.doc_json(&doc), writer.doc_json(&doc));
}

#[test]
fn lower_id_fork_waiting_on_a_dependency_remains_canonical() {
    let (mut source, writer, wk) = pair(Role::Writer);
    let mut receiver = Replica::restore(source.me.clone(), source.op(&source.space_id()).unwrap().clone(),
        source.all_ops(), vec![], None).unwrap();
    let doc = StreamId::new_doc();
    let dependency = put(&mut source, doc, "base", "present");
    let mut waiting = source.doc(&doc).unwrap().clone().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    waiting.put(ROOT, "fork", "waiting").unwrap();
    waiting.commit();
    let waiting_bytes = waiting.get_last_local_change().unwrap().bytes().to_vec();
    let mut ready = AutoCommit::new().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    ready.put(ROOT, "fork", "ready").unwrap();
    ready.commit();
    let ready_bytes = ready.get_last_local_change().unwrap().bytes().to_vec();
    // Generate both nonce variants together; this only selects delivery/fork
    // ordering, and does not rely on any particular random ID value.
    let (x, y) = (0..128).find_map(|_| {
        let x = signed_doc_payload(&writer, doc, &waiting_bytes);
        let y = signed_doc_payload(&writer, doc, &ready_bytes);
        (x.id() < y.id()).then_some((x, y))
    }).unwrap();
    receiver.ingest_envelope(y).unwrap();
    receiver.ingest_envelope(x).unwrap();
    receiver.ingest_envelope(dependency).unwrap();
    assert_eq!(receiver.doc_json(&doc), json!({"base": "present", "fork": "waiting"}));
}

fn empty_copy(r: &Replica) -> Replica {
    Replica::restore(r.me.clone(), r.op(&r.space_id()).unwrap().clone(), r.all_ops(), vec![], None).unwrap()
}

fn assert_context_independent_rejection(mut receiver: Replica, good: Envelope, bad: Envelope,
    doc: StreamId, expected: serde_json::Value) {
    let mut other = empty_copy(&receiver);
    receiver.ingest_envelope(bad.clone()).unwrap();
    receiver.ingest_envelope(good.clone()).unwrap();
    other.ingest_envelope(good.clone()).unwrap();
    other.ingest_envelope(bad.clone()).unwrap();
    assert_eq!(receiver.doc_json(&doc), expected);
    assert_eq!(other.doc_json(&doc), expected);
    for envelopes in [vec![bad.clone(), good.clone()], vec![good.clone(), bad.clone()]] {
        let restored = Replica::restore(receiver.me.clone(), receiver.op(&receiver.space_id()).unwrap().clone(),
            receiver.all_ops(), envelopes, None).unwrap();
        assert_eq!(restored.doc_json(&doc), expected);
        assert!(!restored.docs[&doc].applied.contains(&bad.id()));
    }
}

#[test]
fn omitted_actor_predecessor_is_rejected_in_every_delivery_order() {
    let (receiver, writer, wk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let mut first = AutoCommit::new().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    first.put(ROOT, "first", "valid").unwrap();
    first.commit();
    let good = signed_doc_payload(&writer, doc, &first.get_last_local_change().unwrap().bytes());
    let mut malformed = AutoCommit::new().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    malformed.put(ROOT, "bad", "discard").unwrap();
    malformed.commit();
    let mut expanded = malformed.get_last_local_change().unwrap().decode();
    expanded.seq = 2;
    expanded.start_op = std::num::NonZeroU64::new(2).unwrap();
    assert!(expanded.deps.is_empty());
    let bad = signed_doc_payload(&writer, doc, &automerge::Change::from(expanded).bytes());
    assert_context_independent_rejection(receiver, good, bad, doc, json!({"first": "valid"}));
}

#[test]
fn omitted_object_creator_is_rejected_in_every_delivery_order() {
    let (receiver, writer, wk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let mut parent = AutoCommit::new().with_actor(ActorId::from(receiver.me.sign_pk().0.to_vec()));
    let obj = parent.put_object(ROOT, "container", automerge::ObjType::Map).unwrap();
    parent.commit();
    let good = signed_doc_payload(&receiver, doc, &parent.get_last_local_change().unwrap().bytes());
    let mut child = parent.with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    child.put(&obj, "bad", "discard").unwrap();
    child.commit();
    let mut expanded = child.get_last_local_change().unwrap().decode();
    expanded.deps.clear();
    let bad = signed_doc_payload(&writer, doc, &automerge::Change::from(expanded).bytes());
    assert_context_independent_rejection(receiver, good, bad, doc, json!({"container": {}}));
}

#[test]
fn actor_predecessor_can_be_transitive_through_another_actor() {
    let (mut first, mut second, _) = pair(Role::Writer);
    let mut receiver = empty_copy(&first);
    let doc = StreamId::new_doc();
    let first_env = put(&mut first, doc, "first", "valid");
    let first_hash = first.doc(&doc).unwrap().clone().get_last_local_change().unwrap().hash();
    second.ingest_envelope(first_env.clone()).unwrap();
    let second_env = put(&mut second, doc, "second", "valid");
    let second_hash = second.doc(&doc).unwrap().clone().get_last_local_change().unwrap().hash();
    let mut third = second.doc(&doc).unwrap().clone().with_actor(ActorId::from(first.me.sign_pk().0.to_vec()));
    third.put(ROOT, "third", "valid").unwrap();
    third.commit();
    let mut expanded = third.get_last_local_change().unwrap().decode();
    expanded.deps.retain(|hash| *hash != first_hash);
    assert_eq!(expanded.deps, vec![second_hash]);
    assert_eq!(expanded.seq, 2);
    let third_env = signed_doc_payload(&first, doc, &automerge::Change::from(expanded).bytes());
    let envelopes = vec![third_env, second_env, first_env];
    receiver.ingest_batch(vec![], envelopes.clone());
    let expected = json!({"first": "valid", "second": "valid", "third": "valid"});
    assert_eq!(receiver.doc_json(&doc), expected);
    let restored = Replica::restore(receiver.me.clone(), receiver.op(&receiver.space_id()).unwrap().clone(),
        receiver.all_ops(), envelopes, None).unwrap();
    assert_eq!(restored.doc_json(&doc), expected);
}

#[test]
fn causal_operation_counters_allow_gaps_but_reject_overlap_and_overflow() {
    let (mut receiver, writer, wk) = pair(Role::Writer);
    let doc = StreamId::new_doc();
    let mut source = AutoCommit::new().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    source.put(ROOT, "first", "valid").unwrap();
    source.commit();
    let mut expanded = source.get_last_local_change().unwrap().decode();
    expanded.start_op = std::num::NonZeroU64::new(100).unwrap();
    let mut gap = automerge::Change::from(expanded.clone());
    let good = signed_doc_payload(&writer, doc, &gap.bytes());
    receiver.ingest_envelope(good).unwrap();
    assert_eq!(receiver.doc_json(&doc), json!({"first": "valid"}));
    expanded.seq = 2;
    expanded.deps = vec![gap.hash()];
    let mut overlap = automerge::Change::from(expanded);
    let bad = signed_doc_payload(&writer, doc, &overlap.bytes());
    let bad_id = bad.id();
    receiver.ingest_envelope(bad).unwrap();
    assert!(receiver.doc_rejected.contains(&bad_id));
    assert_eq!(receiver.doc_json(&doc), json!({"first": "valid"}));

    let overflow_doc = StreamId::new_doc();
    let mut two_ops = AutoCommit::new().with_actor(ActorId::from(wk.sign_pk().0.to_vec()));
    two_ops.put(ROOT, "one", "bad").unwrap();
    two_ops.put(ROOT, "two", "bad").unwrap();
    two_ops.commit();
    let mut expanded = two_ops.get_last_local_change().unwrap().decode();
    expanded.start_op = std::num::NonZeroU64::new(u32::MAX as u64).unwrap();
    let mut overflow = automerge::Change::from(expanded.clone());
    let bytes = overflow.bytes().to_vec();
    assert!(bounded_change::parse(&bytes).is_ok(), "upstream only checks the starting counter");
    let bad = signed_doc_payload(&writer, overflow_doc, &bytes);
    let bad_id = bad.id();
    receiver.ingest_envelope(bad).unwrap();
    assert!(receiver.doc_rejected.contains(&bad_id));
    assert!(!receiver.docs.contains_key(&overflow_doc));

    expanded.operations.clear();
    expanded.start_op = std::num::NonZeroU64::new(1).unwrap();
    let empty = automerge::Change::from(expanded);
    assert_eq!(empty.len(), 0);
    assert!(Replica::causal_metadata_valid(None, &empty));
}
