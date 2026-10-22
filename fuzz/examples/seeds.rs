//! Writes the seed corpora in `fuzz/seeds/` (docs/TESTING.md, "Fuzzing"):
//! real messages, encoded by the same code a node sends them with, for the
//! targets that read raw bytes. Each seed starts with the selector byte its
//! target dispatches on. Structured targets (`arbitrary` inputs) need no
//! seeds: their corpora grow from the first run.
//!
//!   cd fuzz && cargo run --example seeds   # rewrites fuzz/seeds/
//!
//! Everything is deterministic except epoch keys and AEAD nonces, which are
//! random by design; rerunning rewrites those seeds with different bytes.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ROOT};
use bytes::Bytes;
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::link::CustomAddr;
use mycel_net::mesh::core::{Announce, Frame, Origination, SeqReq};
use mycel_net::mesh::{directory, wire as mesh};
use mycel_net::wire::{BlobReq, BlobResp, ContactCard, Data, DtnPayload, EphMsg, Inventory, SyncMsg};
use mycel_sync::{FeedEntry, Replica, StreamId, StreamKind};
use mycel_trust::Role;
use serde::Serialize;

struct Seeds<'a> {
    root: &'a Path,
}

impl Seeds<'_> {
    fn put(&self, target: &str, name: &str, selector: Option<u8>, body: &[u8]) {
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("a seed directory");
        let bytes: Vec<u8> = selector.into_iter().chain(body.iter().copied()).collect();
        fs::write(dir.join(name), bytes).expect("a seed file");
    }
}

fn pc<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).expect("encodes")
}

/// A stream frame as `wire.rs` writes it: u32 little-endian length, body.
fn framed<T: Serialize>(v: &T) -> Vec<u8> {
    let body = pc(v);
    [(body.len() as u32).to_le_bytes().as_slice(), &body].concat()
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    let _ = fs::remove_dir_all(&root);
    let s = Seeds { root: &root };

    // A space as a node makes one: founder A adds writer B; B edits a
    // document and posts to a feed.
    let founder = Arc::new(DeviceKeys::from_seed([1; 32]));
    let writer = Arc::new(DeviceKeys::from_seed([2; 32]));
    let (mut a, genesis) = Replica::create(founder.clone(), None).expect("a space");
    a.add_member(writer.public(), Role::Writer).expect("adds a writer");
    let ops = a.all_ops();
    let mut b = Replica::restore(writer.clone(), genesis.clone(), ops.clone(), vec![], None).expect("restores");
    let doc = StreamId::named(StreamKind::Doc, "notes");
    let (_, edit) = b
        .change(doc, |d| {
            d.put(ROOT, "title", "groceries")?;
            let list = d.put_object(ROOT, "items", ObjType::List)?;
            d.insert(&list, 0, "milk")?;
            Ok(())
        })
        .expect("an edit");
    let edit = edit.expect("an edit seals an envelope");
    let feed = StreamId::named(StreamKind::Feed, "chat");
    let chat = mycel_kit_chat::ChatOp::Text { body: "hello".into(), reply_to: None, attachments: vec![] };
    let (_, post) = b.append(feed, chat.encode()).expect("a post");
    let space = a.space_id();
    let envelopes = vec![edit.clone(), post.clone()];
    let inv =
        Inventory { ops: ops.iter().map(|o| o.id()).collect(), envelopes: envelopes.iter().map(|e| e.id()).collect() };
    let card = ContactCard::new(&founder, "Alice");

    // net_stream: selector picks the reader, then frames as sent.
    let hello = SyncMsg::Hello { space, inv: inv.clone(), invite: Some(ops.clone()) };
    let data = SyncMsg::Data { data: Data { ops: ops.clone(), envelopes: envelopes.clone() } };
    let accept = SyncMsg::Accept { inv: inv.clone(), want: Inventory::default() };
    s.put("net_stream", "sync-session", Some(0), &[framed(&hello), framed(&accept), framed(&data)].concat());
    s.put("net_stream", "sync-denied", Some(0), &framed(&SyncMsg::Denied));
    let (epoch, nonce, ciphertext) = b.seal_ephemeral(b"aad", b"typing").expect("an ephemeral message");
    s.put("net_stream", "ephemeral", Some(1), &framed(&EphMsg { space, epoch, nonce, ciphertext }));
    let hash = Hash32([5; 32]);
    s.put("net_stream", "blob-get", Some(2), &framed(&BlobReq::GetRange { space, hash, offset: 64, len: 4096 }));
    s.put("net_stream", "blob-found", Some(3), &framed(&BlobResp::Found { len: 4096 }));
    s.put("net_stream", "card", Some(4), &framed(&card));

    // postcard_messages: the selector is the type (see the target).
    let dtn = DtnPayload { space, data: Data { ops: ops.clone(), envelopes: envelopes.clone() } };
    s.put("postcard_messages", "dtn-payload", Some(0), &pc(&dtn));
    s.put("postcard_messages", "sync-data", Some(1), &pc(&data));
    let entry = FeedEntry { deps: vec![edit.id()], ts_ms: 1_760_000_000_000, body: chat.encode() };
    s.put("postcard_messages", "feed-entry", Some(2), &pc(&entry));
    s.put("postcard_messages", "op-genesis", Some(3), &pc(&genesis));
    s.put("postcard_messages", "op-add", Some(3), &pc(ops.last().expect("an add")));
    s.put("postcard_messages", "envelope-doc", Some(4), &pc(&edit));
    s.put("postcard_messages", "envelope-feed", Some(4), &pc(&post));
    s.put("postcard_messages", "card", Some(6), &pc(&card));
    s.put("postcard_messages", "chat-op", Some(7), &chat.encode());
    s.put("postcard_messages", "chat-typing", Some(7), &mycel_kit_chat::ChatSignal::Typing.encode());
    let input = mycel_rules_abi::RuleInput {
        author: writer.sign_pk().0,
        author_role: mycel_rules_abi::RoleTag::Writer,
        stream: mycel_rules_abi::StreamTag { kind: mycel_rules_abi::StreamKind::Feed, id: [0; 16] },
        payload: chat.encode(),
        context: vec![],
    };
    s.put("postcard_messages", "rule-input", Some(8), &mycel_rules_abi::encode(&input));
    let reduce = mycel_rules_abi::ReduceInput { input, state: vec![1, 2, 3] };
    s.put("postcard_messages", "reduce-input", Some(9), &mycel_rules_abi::encode(&reduce));
    let abi_chat = mycel_rules_abi::chat::ChatOp::Profile { name: "Alice".into() };
    s.put("postcard_messages", "abi-chat-op", Some(10), &mycel_rules_abi::encode(&abi_chat));
    let call = mycel_call::proto::CallRef {
        space,
        initiator: founder.sign_pk(),
        nonce: [7; 16],
        call: mycel_call::proto::call_id(&space, &founder.sign_pk(), &[7; 16]),
    };
    let ring = mycel_call::proto::Ctrl::Ring { version: 1, call, group: false }.encode();
    s.put("postcard_messages", "call-ring", Some(11), &ring[2..]);
    let report = mycel_call::proto::Ctrl::Mute { muted: true }.encode();
    s.put("postcard_messages", "call-mute", Some(11), &report[2..]);
    let video = mycel_video::wire::VideoCtrl::KeyframeRequest { missing: 42 };
    s.put("postcard_messages", "video-ctrl", Some(12), &pc(&video));
    s.put("postcard_messages", "inventory", Some(13), &pc(&inv));

    // sync_change: a whole change (mode 0) and its body (mode 1, which the
    // target re-frames), from a real multi-object edit.
    let mut d = AutoCommit::new();
    d.put(ROOT, "n", 1).expect("put");
    let text = d.put_object(ROOT, "text", ObjType::Text).expect("text");
    d.splice_text(&text, 0, 0, "hello world").expect("splice");
    let map = d.put_object(ROOT, "map", ObjType::Map).expect("map");
    d.put(&map, "counter", automerge::ScalarValue::counter(3)).expect("counter");
    d.commit();
    d.splice_text(&text, 5, 6, "").expect("delete");
    d.increment(&map, "counter", 2).expect("increment");
    for (i, change) in d.get_changes(&[]).iter().enumerate() {
        let raw = change.raw_bytes();
        s.put("sync_change", &format!("change-{i}"), Some(0), raw);
        let mut body = &raw[9..];
        leb128::read::unsigned(&mut body).expect("a chunk length");
        s.put("sync_change", &format!("body-{i}"), Some(1), body);
    }

    // mesh_wire: datagrams as a neighbour sends them.
    let o = Origination { seq: 7, flags: 0, scope: 2, uplink: 1_000 };
    let ann = mesh::sign_announce(&founder, o, "Alice's phone");
    s.put("mesh_wire", "announce", None, &mesh::encode_announce(&ann));
    let ann2 = mesh::sign_announce(&writer, Origination { seq: 1, flags: 1, scope: 0, uplink: 0 }, "Bob");
    for (i, batch) in mesh::encode_announces(&[ann, ann2], 1_200).iter().enumerate() {
        s.put("mesh_wire", &format!("announce-batch-{i}"), None, batch);
    }
    // attested (ROUTE_ATTEST): the selector is the sending neighbour's key
    // byte; one hop's chain with the sender's own hop, then a refresh
    // without it
    let relay = SignPk([7; 32]);
    let o = Origination { seq: 1_760_000_000_000, flags: 0, scope: 10, uplink: 0 };
    let mut a = mesh::sign_announce(&founder, o, "Alice's phone");
    a.sign_link = Some(320);
    let mut a = mesh::sign_hop(&founder, a, &relay);
    (a.hops, a.cost, a.sign_link) = (1, 320, Some(450));
    let a = a.signed_by(relay, mycel_crypto::Sig([3; 64]));
    let refresh = Announce { seq: a.seq + 128_000, chain: None, same: true, ..a.clone() };
    let (grams, _) = mesh::encode_attested(vec![a, refresh], 1_200);
    s.put("mesh_wire", "attested-batch", Some(7), &grams[0]);
    let req = SeqReq { origin: writer.sign_pk(), seq: 9, hops: 3 };
    s.put("mesh_wire", "seqreq", None, &mesh::encode_seqreq(&req));
    let payload = Bytes::from((0..600u32).map(|i| i as u8).collect::<Vec<_>>());
    let frame = Frame {
        ttl: 16,
        reached: false,
        control: false,
        ext: 0,
        dst: writer.sign_pk(),
        src: founder.sign_pk(),
        waypoint: SignPk([0; 32]),
        id: 3,
        offset: 0,
        total: payload.len() as u16,
        payload,
    };
    let parts = mesh::encode_frame(&frame, mesh::DATA_HDR + 256).expect("fragments");
    for (i, p) in parts.iter().enumerate() {
        s.put("mesh_wire", &format!("data-fragment-{i}"), None, p);
    }

    // link_wire: the selector is the decoder (see the target).
    let awdl = mycel_link_awdl::wire::Control::Hello(founder.sign_pk()).encode();
    s.put("link_wire", "awdl-hello", Some(0), &awdl);
    let txt = mycel_link_awdl::wire::txt_entries(&founder.sign_pk(), "Alice");
    let get = |k: &str| txt.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let advert = [get(mycel_link_awdl::wire::TXT_KEY), vec![0xff], get(mycel_link_awdl::wire::TXT_NAME)].concat();
    s.put("link_wire", "awdl-advert", Some(1), &advert);
    let beacon = mycel_link_iface::wire::Beacon { key: founder.sign_pk(), name: "Alice".into() };
    s.put("link_wire", "iface-beacon", Some(2), &beacon.encode());
    let addr = mycel_link_iface::wire::IfaceAddr {
        kind: mycel_net::PathKind::WifiDirect,
        index: 4,
        ip: "fe80::1".parse().expect("an address"),
        port: 4_433,
    }
    .to_custom();
    s.put("link_wire", "iface-addr", Some(3), &custom_addr_bytes(&addr));
    // SRV rdata: priority, weight, port, then the target as DNS labels.
    let srv = [&[0, 0, 0, 0, 0x11, 0x51][..], b"\x05alice\x05local\x00"].concat();
    s.put("link_wire", "mdns-srv", Some(4), &srv);
    let mdns_txt = [&[b"user=abc".len() as u8][..], b"user=abc"].concat();
    s.put("link_wire", "mdns-txt", Some(5), &mdns_txt);

    // contact_code: a code as shared, with address hints.
    let hints = vec!["192.0.2.1:4433".to_string(), "[2001:db8::1]:4433".to_string()];
    let code = mycel_node::encode_contact_code_with_hints(&card, &hints);
    s.put("contact_code", "code-with-hints", Some(0), code.as_bytes());
    s.put("contact_code", "code", Some(0), mycel_node::encode_contact_code(&card).as_bytes());

    // directory_record: a sealed reachability record.
    let record = directory::seal(&founder, &[(writer.sign_pk(), 1_000)]).expect("a record");
    s.put("directory_record", "record", Some(0), &record);

    let count: usize =
        fs::read_dir(&root).expect("seeds").map(|d| fs::read_dir(d.unwrap().path()).unwrap().count()).sum();
    println!("wrote {count} seeds to {}", root.display());
}

/// The mesh and interface targets build a [`CustomAddr`] from a first byte
/// (the low byte of the transport id) and the address data.
fn custom_addr_bytes(addr: &CustomAddr) -> Vec<u8> {
    [&[addr.id() as u8][..], addr.data()].concat()
}
