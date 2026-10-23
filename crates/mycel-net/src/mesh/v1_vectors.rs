//! Wire version 1 pinned byte for byte (docs/PROTOCOL.md §5).
//!
//! The mixed-version tests stand in for a pre-release device with this
//! build's code offering only version 1, so a change to a version 1
//! encoding would change both sides of them at once and pass, while real
//! pre-release devices broke. These vectors were not written by this
//! build: they were printed by the pre-release code itself (`mycel-net` at
//! main `98d9b7b`, the commit before versioning) from the same fixed
//! inputs, and every version 1 encoder and decoder here must match them
//! exactly. Never regenerate them from this build; a mismatch means a
//! version 1 format changed, which needs a new wire version instead
//! (§6).
//!
//! To check them against the pre-release code yourself:
//! `scripts/v1-compat/run.sh` checks out `98d9b7b`, prints every vector
//! with its encoders (`scripts/v1-compat/gen_vectors.rs`, the same inputs
//! as here) and compares them with this file, then runs a `98d9b7b` node
//! against a node of this build.

use bytes::Bytes;
use mycel_crypto::{DeviceKeys, Hash32, Sig, SignPk};
use mycel_sync::{Envelope, Header, StreamId};
use mycel_trust::{Action, EpochId, Op, SignedOp};

use super::core::{Frame, Origination, SeqReq};
use super::dtn::{Bundle, BundleFormat, Offer};
use super::{
    K_SUMMARY, RECEIPT_CTX, WireAnswer, WireSummary, bundle_id_of, bundle_sig_ok, bundle_signed, decode_offer,
    encode_offer,
};
use crate::version::WIRE_V1;
use crate::wire::{self, BlobReq, BlobResp, ContactCard, Data, DtnPayload, EphMsg, Inventory, StreamKind, SyncMsg};

const ALPN_NODE_V1: &[&str] = &["6d7963656c2f32"];

const ALPN_MESH_V1: &[&str] = &["6d7963656c2f6d6573682f31"];

const STREAM_KINDS: &[&str] = &["01020304"];

const SYNC_HELLO: &[&str] = &[
    "000303030303030303030303030303030303030303030303030303030303030303010404040404040404040404040404",
    "040404040404040404040404040404040404010505050505050505050505050505050505050505050505050505050505",
    "05050500",
];

const SYNC_HELLO_INVITE: &[&str] = &["00030303030303030303030303030303030303030303030303030303030303030300000100"];

const SYNC_DENIED: &[&str] = &["01"];

const SYNC_REMOVED: &[&str] = &["0200"];

const SYNC_NEED_INVITE: &[&str] = &["03"];

const SYNC_ACCEPT: &[&str] = &[
    "040104040404040404040404040404040404040404040404040404040404040404040105050505050505050505050505",
    "050505050505050505050505050505050505050000",
];

const SYNC_DATA_AND_WANT: &[&str] = &[
    "050000010404040404040404040404040404040404040404040404040404040404040404010505050505050505050505",
    "050505050505050505050505050505050505050505",
];

const SYNC_DATA: &[&str] = &["060000"];

const DTN_PAYLOAD: &[&str] = &["03030303030303030303030303030303030303030303030303030303030303030000"];

const EPH: &[&str] = &[
    "030303030303030303030303030303030303030303030303030303030303030306060606060606060606060606060606",
    "070707070707070707070707070707070707070707070707020809",
];

const BLOB_REQ_GET_RANGE: &[&str] = &[
    "040303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505",
    "0505050505050505050505050505050505ac02f0a204",
];

const BLOB_RESP_RANGE: &[&str] = &["04f0a204ac02"];

const CARD: &[&str] = &[
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5ca81c5f57ae7cdfbb18a320d0fadd82ba",
    "62099053528e6bef97253fabf64ea6044027c3553dd604a179b8c97f311ead1db4d4f16dcd6399ea0132bf191f0129c5",
    "ff88320a8d6f808b162c78e41ab866145613eaa9aa0efee5cc23e854a1dc51f3070341646140b8325c913e52bd042506",
    "17dc99bf5b9e50ce8f845232792bad91d3e492ddc4bc2e405a2e6aafeba3481fd42e28171b92e1600a099b110bf185c3",
    "6a3aae49a808",
];

const BUNDLE_ID: &[&str] = &["672c2a26dbc3241ab767ff50b47fd6ce613eaf9fdf9a0d194890ceb193eed0ff"];

const BUNDLE_SIG: &[&str] = &[
    "70206b2cae190f7b4f997ad22f1a07f9dc3d080afbd5fea084d84a5fe846e8cd837e7918a35dd53b60ec0d517d1ee2b3",
    "50daa1c7e80fe22afe17a07360216809",
];

const K_OFFER_VEC: &[&str] = &[
    "03672c2a26dbc3241ab767ff50b47fd6ce613eaf9fdf9a0d194890ceb193eed0ff8a88e3dd7409f195fd52db2d3cba5d",
    "72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3",
    "940980d095ffbc31c0cf244070206b2cae190f7b4f997ad22f1a07f9dc3d080afbd5fea084d84a5fe846e8cd837e7918",
    "a35dd53b60ec0d517d1ee2b350daa1c7e80fe22afe17a0736021680904",
];

const ANSWERS: &[&str] = &["00ac02010201"];

const RECEIPT_SIG: &[&str] = &[
    "2618f5abd35aee67213f0aa093b2a680c55003720d1e91a29b0b5aba90a98e5aac84181784abc49f57c6294747cfbc8b",
    "0ab2618527e966091b365f0e3391a10a",
];

const K_SUMMARY_VEC: &[&str] = &[
    "010101672c2a26dbc3241ab767ff50b47fd6ce613eaf9fdf9a0d194890ceb193eed0ff01672c2a26dbc3241ab767ff50",
    "b47fd6ce613eaf9fdf9a0d194890ceb193eed0ff8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b",
    "8fc9b3944070206b2cae190f7b4f997ad22f1a07f9dc3d080afbd5fea084d84a5fe846e8cd837e7918a35dd53b60ec0d",
    "517d1ee2b350daa1c7e80fe22afe17a07360216809018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df6",
    "0f5b8fc9b3940000003f80804001e807d00f010909090909090909090909090909090909090909090909090909090909",
    "090909",
];

const ANNOUNCE: &[&str] = &[
    "0100000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c000000000000002a0106",
    "000003090341646142abd9ed95668f7366c96e6e8a7bd2872c52caf0c9e3da03164ef32ea28fe31a9f85ce550b2c6e36",
    "f204933c4273b4e4d192eeb9bfc5ac1e378b3d8747bfd607",
];

const DATA_FRAME: &[&str] = &[
    "0209018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3c",
    "ba5d72ca6709bf1d94121bf3748801b40f6f5c0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    "0a0a0a0102030400000003706b74",
];

const SYNC_DATA_FULL: &[&str] = &[
    "060101030303030303030303030303030303030303030303030303030303030303030301040404040404040404040404",
    "04040404040404040404040404040404040404048a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801",
    "b40f6f5c0705010505050505050505050505050505050505050505050505050505050505050505403910e32e573c92eb",
    "cf9a00679bb8c8d84fde15e65b81ea2d1100a31ab0bb2ac4d1174fa40c0a5b72bddf6bae58f1f56f519d8f291c092e2e",
    "e98555b6845ee008010303030303030303030303030303030303030303030303030303030303030303010b0b0b0b0b0b",
    "0b0b0b0b0b0b0b0b0b0b8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c020105050505",
    "050505050505050505050505050505050505050505050505050505050104040404040404040404040404040404040404",
    "040404040404040404040404040606060606060606060606060606060607070707070707070707070707070707070707",
    "070707070703010203400c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
    "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
];

const BLOB_REQ_GET: &[&str] = &[
    "000303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505",
    "0505050505050505050505050505050505",
];

const BLOB_REQ_PUT: &[&str] = &[
    "010303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505",
    "0505050505050505050505050505050505f0a204",
];

const BLOB_REQ_GET_FROM: &[&str] = &[
    "020303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505",
    "0505050505050505050505050505050505ac02",
];

const BLOB_REQ_OFFER: &[&str] = &[
    "030303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505",
    "0505050505050505050505050505050505f0a204",
];

const BLOB_RESPS: &[&str] = &["00f0a20401020305ac020607"];

const OGMS: &[&str] = &[
    "040100000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c000000000000002a01",
    "06000003090341646142abd9ed95668f7366c96e6e8a7bd2872c52caf0c9e3da03164ef32ea28fe31a9f85ce550b2c6e",
    "36f204933c4273b4e4d192eeb9bfc5ac1e378b3d8747bfd6070100000000008139770ea87d175f56a35466c34c7ecccb",
    "8d8a91b4ee37a25df60f5b8fc9b394000000000000000700020000000002426f74407642183a6635abf291311b78b1cf",
    "9ad3884179c43cdd939d2a64e0c6debc40d37f89fcab832d3b53d6939f8d38378ace9eb9113879633d7ed32497807c07",
];

const SEQREQ: &[&str] = &["038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c000000000000002b02"];

const CONTROL_FRAME: &[&str] = &[
    "0209028139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3c",
    "ba5d72ca6709bf1d94121bf3748801b40f6f5c0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    "0a0a0a010203040000000301aabb",
];

fn golden(parts: &[&str]) -> Vec<u8> {
    let hex = parts.concat();
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

fn pc<T: serde::Serialize>(t: &T) -> Vec<u8> {
    postcard::to_allocvec(t).unwrap()
}

/// The fixed inputs the vectors were printed from.
struct Inputs {
    a: DeviceKeys,
    b: DeviceKeys,
    space: Hash32,
    op: Hash32,
    env: Hash32,
}

/// The data of `SYNC_DATA_FULL`, as `gen_vectors.rs` builds it: one signed
/// op and one envelope (whose signature is a fixed pattern: only its bytes
/// are pinned).
fn full_data(a: &DeviceKeys, space: Hash32, op: Hash32, env: Hash32) -> Data {
    let signed = SignedOp::sign(
        a,
        Op {
            space: Some(space),
            parents: vec![op],
            author: a.sign_pk(),
            nonce: 7,
            action: Action::Leave { cutoff: Some(env) },
        },
    );
    let header = Header {
        space,
        stream: StreamId { kind: mycel_sync::StreamKind::Feed, id: [11; 16] },
        author: a.sign_pk(),
        author_seq: 2,
        author_prev: Some(env),
        auth_heads: vec![op],
        epoch: EpochId([6; 16]),
        nonce: [7; 24],
    };
    let envelope = Envelope { header, ciphertext: vec![1, 2, 3], sig: Sig([12; 64]) };
    Data { ops: vec![signed], envelopes: vec![envelope] }
}

fn inputs() -> Inputs {
    Inputs {
        a: DeviceKeys::from_seed([1; 32]),
        b: DeviceKeys::from_seed([2; 32]),
        space: Hash32([3; 32]),
        op: Hash32([4; 32]),
        env: Hash32([5; 32]),
    }
}

/// Connection names and stream kinds.
#[test]
fn version_1_alpns_and_stream_kinds() {
    assert_eq!(wire::ALPN_V1, golden(ALPN_NODE_V1).as_slice());
    assert_eq!(super::ALPN_V1, golden(ALPN_MESH_V1).as_slice());
    assert_eq!(wire::version_of(&golden(ALPN_NODE_V1)), Some(WIRE_V1));
    assert_eq!(super::version_of(&golden(ALPN_MESH_V1)), Some(WIRE_V1));
    let kinds = [StreamKind::Sync, StreamKind::Card, StreamKind::Ephemeral, StreamKind::Blob];
    assert_eq!(kinds.iter().map(|k| *k as u8).collect::<Vec<_>>(), golden(STREAM_KINDS));
    for (k, b) in kinds.iter().zip(golden(STREAM_KINDS)) {
        assert_eq!(StreamKind::on(WIRE_V1, b), Some(*k));
    }
}

/// Every sync message, the store-and-forward payload, ephemeral messages,
/// blob requests and answers.
#[test]
fn version_1_node_protocol_messages() {
    let Inputs { a, space, op, env, .. } = inputs();
    let inv = Inventory { ops: vec![op], envelopes: vec![env] };
    let resps = [
        pc(&BlobResp::Found { len: 70000 }),
        pc(&BlobResp::NotFound),
        pc(&BlobResp::Denied),
        pc(&BlobResp::Stored),
        pc(&BlobResp::SendFrom { offset: 300 }),
        pc(&BlobResp::NoSpace),
        pc(&BlobResp::Busy),
    ];
    let cases: [(&[&str], Vec<u8>); 19] = [
        (SYNC_HELLO, pc(&SyncMsg::Hello { space, inv: inv.clone(), invite: None })),
        (SYNC_HELLO_INVITE, pc(&SyncMsg::Hello { space, inv: Inventory::default(), invite: Some(vec![]) })),
        (SYNC_DENIED, pc(&SyncMsg::Denied)),
        (SYNC_REMOVED, pc(&SyncMsg::Removed { ops: vec![] })),
        (SYNC_NEED_INVITE, pc(&SyncMsg::NeedInvite)),
        (SYNC_ACCEPT, pc(&SyncMsg::Accept { inv: inv.clone(), want: Inventory::default() })),
        (SYNC_DATA_AND_WANT, pc(&SyncMsg::DataAndWant { data: Data::default(), want: inv.clone() })),
        (SYNC_DATA, pc(&SyncMsg::Data { data: Data::default() })),
        (SYNC_DATA_FULL, pc(&SyncMsg::Data { data: full_data(&a, space, op, env) })),
        (DTN_PAYLOAD, pc(&DtnPayload { space, data: Data::default() })),
        (EPH, pc(&EphMsg { space, epoch: EpochId([6; 16]), nonce: [7; 24], ciphertext: vec![8, 9] })),
        (BLOB_REQ_GET_RANGE, pc(&BlobReq::GetRange { space, hash: env, offset: 300, len: 70000 })),
        (BLOB_REQ_GET, pc(&BlobReq::Get { space, hash: env })),
        (BLOB_REQ_PUT, pc(&BlobReq::Put { space, hash: env, len: 70000 })),
        (BLOB_REQ_GET_FROM, pc(&BlobReq::GetFrom { space, hash: env, offset: 300 })),
        (BLOB_REQ_OFFER, pc(&BlobReq::Offer { space, hash: env, len: 70000 })),
        (BLOB_RESP_RANGE, pc(&BlobResp::Range { total: 70000, offset: 300 })),
        (BLOB_RESPS, resps.concat()),
        (ANSWERS, [pc(&WireAnswer::Take(300)), pc(&WireAnswer::Duplicate), pc(&WireAnswer::Refuse(true))].concat()),
    ];
    for (i, (want, got)) in cases.iter().enumerate() {
        assert_eq!(got, &golden(want), "vector {i}");
    }
    // ... and this build reads what pre-release builds send
    match postcard::from_bytes(&golden(SYNC_HELLO)).unwrap() {
        SyncMsg::Hello { space: s, inv: i, invite: None } => {
            assert_eq!((s, i.ops, i.envelopes), (space, vec![op], vec![env]));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(postcard::from_bytes(&golden(SYNC_NEED_INVITE)).unwrap(), SyncMsg::NeedInvite));
    match postcard::from_bytes(&golden(SYNC_DATA_AND_WANT)).unwrap() {
        SyncMsg::DataAndWant { data, want } => assert!(data.ops.is_empty() && want.ops == vec![op]),
        other => panic!("{other:?}"),
    }
    match postcard::from_bytes(&golden(BLOB_REQ_GET_RANGE)).unwrap() {
        BlobReq::GetRange { offset, len, .. } => assert_eq!((offset, len), (300, 70000)),
        other => panic!("{other:?}"),
    }
    match postcard::from_bytes(&golden(SYNC_DATA_FULL)).unwrap() {
        SyncMsg::Data { data } => {
            assert_eq!(data.ops.len(), 1);
            data.ops[0].verify_standalone().unwrap();
            assert_eq!(data.ops[0].op.action, Action::Leave { cutoff: Some(env) });
            let e = &data.envelopes[0];
            assert_eq!(
                (e.header.author_seq, e.header.author_prev, &e.ciphertext[..]),
                (2, Some(env), &[1u8, 2, 3][..])
            );
        }
        other => panic!("{other:?}"),
    }
    let eph: EphMsg = postcard::from_bytes(&golden(EPH)).unwrap();
    assert_eq!((eph.epoch, eph.ciphertext), (EpochId([6; 16]), vec![8, 9]));
}

/// A contact card: its bytes and its signature (context and signed
/// bytes), both ways.
#[test]
fn version_1_contact_card() {
    let Inputs { a, .. } = inputs();
    assert_eq!(pc(&ContactCard::new(&a, "Ada")), golden(CARD));
    let card: ContactCard = postcard::from_bytes(&golden(CARD)).unwrap();
    card.verify().unwrap();
    assert_eq!((card.keys.sign_pk, card.name.as_str()), (a.sign_pk(), "Ada"));
}

/// Mesh hops: a signed announcement and a relayed data frame's header.
#[test]
fn version_1_mesh_datagrams() {
    let Inputs { a, b, .. } = inputs();
    let ann = super::wire::sign_announce(&a, Origination { seq: 42, flags: 1, scope: 6, uplink: 777 }, "Ada");
    assert_eq!(super::wire::encode_announce(&ann).to_vec(), golden(ANNOUNCE));
    let theirs = super::wire::decode_announce(&golden(ANNOUNCE)).unwrap();
    assert!(super::wire::verify_announce(&theirs));
    assert_eq!((theirs.origin, theirs.seq, &*theirs.name), (a.sign_pk(), 42, "Ada"));

    let bo = super::wire::sign_announce(&b, Origination { seq: 7, flags: 0, scope: 2, uplink: 0 }, "Bo");
    let ogms = super::wire::encode_announces(&[ann.clone(), bo], 1200);
    assert_eq!(ogms.iter().map(|d| d.to_vec()).collect::<Vec<_>>(), vec![golden(OGMS)]);
    let theirs = super::wire::decode_announces(&golden(OGMS));
    assert_eq!(theirs.iter().map(|a| (a.origin, a.seq)).collect::<Vec<_>>(), vec![(a.sign_pk(), 42), (b.sign_pk(), 7)]);
    assert!(theirs.iter().all(super::wire::verify_announce));
    let req = SeqReq { origin: a.sign_pk(), seq: 43, hops: 2 };
    assert_eq!(super::wire::encode_seqreq(&req).to_vec(), golden(SEQREQ));
    assert_eq!(super::wire::decode_seqreq(&golden(SEQREQ)), Some(req));

    let frame = Frame {
        ttl: 9,
        reached: true,
        control: false,
        ext: 0,
        dst: b.sign_pk(),
        src: a.sign_pk(),
        waypoint: SignPk([10; 32]),
        id: 0x01020304,
        offset: 0,
        total: 3,
        payload: Bytes::from_static(b"pkt"),
    };
    assert_eq!(super::wire::encode_frame(&frame, 1200).unwrap().remove(0).to_vec(), golden(DATA_FRAME));
    let theirs = super::wire::decode_frame(Bytes::from(golden(DATA_FRAME))).unwrap();
    assert!(theirs.reached && !theirs.control && theirs.ext == 0);
    assert_eq!((theirs.ttl, theirs.id, theirs.dst, &theirs.payload[..]), (9, 0x01020304, b.sign_pk(), &b"pkt"[..]));
    // a control message (for the destination's router): a reachability record's kind byte
    let control = Frame { reached: false, control: true, payload: Bytes::from_static(&[1, 0xaa, 0xbb]), ..frame };
    assert_eq!(super::wire::encode_frame(&control, 1200).unwrap().remove(0).to_vec(), golden(CONTROL_FRAME));
    let theirs = super::wire::decode_frame(Bytes::from(golden(CONTROL_FRAME))).unwrap();
    assert!(!theirs.reached && theirs.control && theirs.ext == 0 && theirs.payload[0] == 1);
}

/// Store-and-forward: a version 1 bundle's id and signature, its offer on
/// a version 1 hop, a receipt and a carrier's summary.
#[test]
fn version_1_bundles() {
    let Inputs { a, b, .. } = inputs();
    let payload = b"v1 bundle";
    let (created, lifetime) = (1_700_000_000_000u64, 600_000u64);
    let id = bundle_id_of(BundleFormat::V1, &a.sign_pk(), &b.sign_pk(), payload);
    assert_eq!(id.0.to_vec(), golden(BUNDLE_ID));
    assert_eq!(super::bundle_id(&a.sign_pk(), &b.sign_pk(), payload), id);
    let sig = super::sign_bundle(&a, BundleFormat::V1, &id, created, lifetime);
    assert_eq!(sig.0.to_vec(), golden(BUNDLE_SIG));
    assert!(bundle_sig_ok(BundleFormat::V1, &a.sign_pk(), &id, created, lifetime, &sig));
    let (ctx, head) = bundle_signed(BundleFormat::V1);
    assert_eq!((ctx, head.len()), ("mycel/v0/dtn-bundle", 0));

    let bundle = Bundle {
        format: BundleFormat::V1,
        id,
        src: a.sign_pk(),
        dst: b.sign_pk(),
        created,
        lifetime,
        payload: Bytes::from_static(payload),
        sig,
    };
    assert_eq!(encode_offer(WIRE_V1, &Offer::of(&bundle, 4)).unwrap(), Some(golden(K_OFFER_VEC)));
    let o = decode_offer(&golden(K_OFFER_VEC)).unwrap().unwrap();
    assert_eq!(o.format, BundleFormat::V1);
    assert_eq!(
        (o.id, o.src, o.dst, o.size, o.created, o.lifetime, o.copies),
        (id, a.sign_pk(), b.sign_pk(), 9, created, lifetime, 4)
    );
    assert!(bundle_sig_ok(o.format, &o.src, &o.id, o.created, o.lifetime, &o.sig));

    assert_eq!(b.sign(RECEIPT_CTX, &[&id.0]).0.to_vec(), golden(RECEIPT_SIG));
    let summary = WireSummary {
        full: true,
        ids: vec![id],
        receipts: vec![(id, b.sign_pk(), sig)],
        preds: vec![(b.sign_pk(), 0.5)],
        free: 1 << 20,
        evictable: vec![(1000, 2000)],
        wants: vec![SignPk([9; 32])],
    };
    let mut msg = vec![K_SUMMARY];
    msg.extend_from_slice(&pc(&summary));
    assert_eq!(msg, golden(K_SUMMARY_VEC));
    let theirs: WireSummary = postcard::from_bytes(&golden(K_SUMMARY_VEC)[1..]).unwrap();
    assert!(theirs.full && theirs.ids == vec![id] && theirs.free == 1 << 20 && theirs.wants == vec![SignPk([9; 32])]);
}
