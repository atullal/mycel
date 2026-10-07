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

fn put(r: &mut Replica, doc: DocId, key: &str, val: &str) -> Envelope {
    let (k, v) = (key.to_string(), val.to_string());
    r.change(doc, move |d| d.put(ROOT, k, v)).unwrap().1.unwrap()
}

/// Founder + a member with `role`, both synced.
fn pair(role: Role) -> (Replica, Replica, Arc<DeviceKeys>) {
    let (mut a, genesis) = Replica::create(dev()).unwrap();
    let bk = dev();
    let mut b = Replica::join(bk.clone(), genesis).unwrap();
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
    let (mut a, genesis) = Replica::create(dev()).unwrap();
    let kk = dev();
    let mut keeper = Replica::join(kk.clone(), genesis).unwrap();
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
    let mut eve = Replica::join(dev(), genesis).unwrap();
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
        doc,
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
    a.ingest_envelope(env).unwrap();
    assert_eq!(a.status(&id), Status::Invalid("author not a writer at auth_heads"));
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
        doc,
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
    let (mut a, genesis) = Replica::create(dev()).unwrap();
    let (bk, ck) = (dev(), dev());
    let mut b = Replica::join(bk.clone(), genesis.clone()).unwrap();
    let mut c = Replica::join(ck.clone(), genesis).unwrap();
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
