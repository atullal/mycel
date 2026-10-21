//! Writes the seed corpora in `fuzz/seeds/` (docs/TESTING.md, "Fuzzing"):
//! real messages, encoded by the same code a node sends them with, for the
//! targets that read raw bytes. Each seed starts with the selector byte its
//! target dispatches on. Structured targets (`arbitrary` inputs) need no
//! seeds: their corpora grow from the first run.
//!
//!   fuzz/seeds.sh   # writes fuzz/seeds/
//!
//! **Deterministic**: rerunning writes the same bytes, so only a change in an
//! encoding shows up in git. Keys come from fixed seeds, and everything the
//! code draws from the OS's randomness (space ids, epoch keys, lockboxes,
//! AEAD nonces) comes from a fixed stream instead: `seeds.sh` builds this
//! with getrandom's `custom` backend, defined below (only here: nothing
//! else in the build changes, and a fuzz target never links this). The one
//! seed that carries the time, a reachability record (its expiry and the
//! pkarr timestamp), is written only if missing.
//!
//! **Non-destructive**: it writes only the seeds it makes. It never deletes
//! anything, and never touches a `regression-*` input (one that once failed,
//! kept so every run tries it again); files it no longer makes are listed,
//! for a person to delete.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(getrandom_backend = "custom")]
use std::sync::Mutex;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ROOT};
use bytes::Bytes;
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::link::CustomAddr;
use mycel_net::mesh::core::{Frame, Origination, SeqReq};
use mycel_net::mesh::{directory, wire as mesh};
use mycel_net::wire::{BlobReq, BlobResp, ContactCard, Data, DtnPayload, EphMsg, Inventory, SyncMsg};
use mycel_sync::{Envelope, EnvelopeId, FeedEntry, Replica, StreamId, StreamKind};
use mycel_trust::Role;
use serde::Serialize;

/// The randomness every crate here draws through getrandom 0.4 (Mycel's
/// keys, nonces and op ids, HPKE, Automerge): a BLAKE3 output stream from a
/// fixed key, in the order this single-threaded program asks for it. For
/// seed files only: nothing that runs a node is built with it.
#[cfg(getrandom_backend = "custom")]
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    static STREAM: Mutex<Option<blake3::OutputReader>> = Mutex::new(None);
    let mut stream = STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let reader = stream.get_or_insert_with(|| blake3::Hasher::new_derive_key("mycel fuzz seeds v1").finalize_xof());
    // SAFETY: getrandom passes a writable buffer of `len` bytes (perhaps
    // uninitialised: zeroed before it is read as a slice).
    let buf = unsafe {
        std::ptr::write_bytes(dest, 0, len);
        std::slice::from_raw_parts_mut(dest, len)
    };
    reader.fill(buf);
    Ok(())
}

/// What was written, left alone, and found in the seed directories.
struct Seeds {
    root: PathBuf,
    made: RefCell<BTreeSet<PathBuf>>,
    written: Cell<usize>,
}

impl Seeds {
    /// Write seed `name` for `target` unless it already holds these bytes.
    fn put(&self, target: &str, name: &str, selector: Option<u8>, body: &[u8]) {
        self.write(target, name, selector, body, true);
    }

    /// Write seed `name` only if it is missing (a seed that carries the time).
    fn put_once(&self, target: &str, name: &str, selector: Option<u8>, body: &[u8]) {
        self.write(target, name, selector, body, false);
    }

    fn write(&self, target: &str, name: &str, selector: Option<u8>, body: &[u8], replace: bool) {
        assert!(!name.starts_with("regression-"), "regression inputs are never written here: {name}");
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("a seed directory");
        let path = dir.join(name);
        assert!(self.made.borrow_mut().insert(path.clone()), "two seeds named {target}/{name}");
        let bytes: Vec<u8> = selector.into_iter().chain(body.iter().copied()).collect();
        let old = fs::read(&path).ok();
        if old.as_deref() == Some(&bytes[..]) || (old.is_some() && !replace) {
            return;
        }
        fs::write(&path, bytes).expect("a seed file");
        self.written.set(self.written.get() + 1);
    }

    /// Report, and list what is in the directories but wasn't made now.
    fn finish(&self) {
        let made = self.made.borrow();
        let (mut regressions, mut stale) = (0, Vec::new());
        for dir in fs::read_dir(&self.root).expect("seeds") {
            for file in fs::read_dir(dir.expect("a seed directory").path()).expect("a seed directory") {
                let path = file.expect("a seed file").path();
                if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with("regression-")) {
                    regressions += 1;
                } else if !made.contains(&path) {
                    stale.push(path);
                }
            }
        }
        println!(
            "{} seeds, {} written, the rest unchanged; {regressions} regression inputs kept",
            made.len(),
            self.written.get()
        );
        for path in stale {
            let path = path.strip_prefix(&self.root).unwrap_or(&path);
            println!("not made by this generator (left in place): fuzz/seeds/{}", path.display());
        }
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
    if !cfg!(all(fuzzing, getrandom_backend = "custom")) {
        eprintln!("seeds: built without fixed randomness, so every run would write different bytes: use fuzz/seeds.sh");
        std::process::exit(2);
    }
    let s = Seeds {
        root: Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds"),
        made: RefCell::default(),
        written: Cell::default(),
    };

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
    // As `Replica::append` seals a post, at a fixed time instead of now.
    let entry = FeedEntry { deps: vec![], ts_ms: TS_MS, body: chat.encode() };
    let post = seal(&b, feed, &pc(&entry), 1, Some(edit.id()));
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
    let entry = FeedEntry { deps: vec![edit.id()], ts_ms: TS_MS, body: chat.encode() };
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
    let mut d = AutoCommit::new().with_actor(automerge::ActorId::from(&[7u8; 16][..]));
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
    // Flag bits this version doesn't assign (relays carry them unchanged).
    let payload = Bytes::from_static(b"marked by a later version");
    let marked = Frame { ext: 0x84, reached: true, total: payload.len() as u16, payload, ..frame };
    let marked = mesh::encode_frame(&marked, usize::MAX).expect("one datagram");
    s.put("mesh_wire", "data-extension-flags", None, &marked[0]);

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
    s.put_once("directory_record", "record", Some(0), &record);

    s.finish();
}

/// The wall time in seeds that carry one (2025-10-09).
const TS_MS: u64 = 1_760_000_000_000;

/// Seal `plaintext` as `r`'s device would at chain position `seq`, after
/// `prev` (mycel-sync's fuzzing helper: `seeds.sh` builds with `fuzzing`).
#[cfg(fuzzing)]
fn seal(r: &Replica, stream: StreamId, plaintext: &[u8], seq: u64, prev: Option<EnvelopeId>) -> Envelope {
    mycel_sync::fuzzing::seal(r, stream, plaintext, seq, prev, mycel_crypto::random()).expect("sealed")
}

#[cfg(not(fuzzing))]
fn seal(_: &Replica, _: StreamId, _: &[u8], _: u64, _: Option<EnvelopeId>) -> Envelope {
    unreachable!("main stops first")
}

/// The mesh and interface targets build a [`CustomAddr`] from a first byte
/// (the low byte of the transport id) and the address data.
fn custom_addr_bytes(addr: &CustomAddr) -> Vec<u8> {
    [&[addr.id() as u8][..], addr.data()].concat()
}
