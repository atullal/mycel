//! Prints the wire version 1 golden vectors with the pre-release code's own
//! encoders. Not part of this build: `run.sh` copies it into a checkout of
//! main `98d9b7b` (the commit before versioning) as
//! `crates/mycel-net/src/mesh/v1_gen.rs`, and `compare.py` checks what it
//! prints against `crates/mycel-net/src/mesh/v1_vectors.rs`.
//!
//! The inputs must stay exactly those of `v1_vectors.rs`. Each line is
//! `VECTOR <NAME> <hex>`, NAME being the constant's name there.

use bytes::Bytes;
use mycel_crypto::{DeviceKeys, Hash32, Sig, SignPk};
use mycel_sync::{Envelope, Header, StreamId};
use mycel_trust::{Action, EpochId, Op, SignedOp};

use super::core::{Frame, Origination, SeqReq};
use super::{K_OFFER, K_SUMMARY, RECEIPT_CTX, WireAnswer, WireOffer, WireSummary};
use crate::wire::{self, BlobReq, BlobResp, ContactCard, Data, DtnPayload, EphMsg, Inventory, StreamKind, SyncMsg};

fn pc<T: serde::Serialize>(t: &T) -> Vec<u8> {
    postcard::to_allocvec(t).unwrap()
}

fn print(name: &str, bytes: &[u8]) {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("VECTOR {name} {hex}");
}

/// The non-empty sync data of `SYNC_DATA_FULL`: one signed op and one
/// envelope, from fixed inputs (the envelope's signature is a fixed
/// pattern: only its bytes are pinned, not its validity).
pub(crate) fn full_data(a: &DeviceKeys, space: Hash32, op: Hash32, env: Hash32) -> Data {
    let signed = SignedOp::sign(
        a,
        Op { space: Some(space), parents: vec![op], author: a.sign_pk(), nonce: 7, action: Action::Leave { cutoff: Some(env) } },
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

#[test]
fn print_version_1_vectors() {
    let a = DeviceKeys::from_seed([1; 32]);
    let b = DeviceKeys::from_seed([2; 32]);
    let (space, op, env) = (Hash32([3; 32]), Hash32([4; 32]), Hash32([5; 32]));
    let inv = Inventory { ops: vec![op], envelopes: vec![env] };

    print("ALPN_NODE_V1", wire::ALPN);
    print("ALPN_MESH_V1", super::ALPN);
    print("STREAM_KINDS", &[StreamKind::Sync as u8, StreamKind::Card as u8, StreamKind::Ephemeral as u8, StreamKind::Blob as u8]);
    print("SYNC_HELLO", &pc(&SyncMsg::Hello { space, inv: inv.clone(), invite: None }));
    print("SYNC_HELLO_INVITE", &pc(&SyncMsg::Hello { space, inv: Inventory::default(), invite: Some(vec![]) }));
    print("SYNC_DENIED", &pc(&SyncMsg::Denied));
    print("SYNC_REMOVED", &pc(&SyncMsg::Removed { ops: vec![] }));
    print("SYNC_NEED_INVITE", &pc(&SyncMsg::NeedInvite));
    print("SYNC_ACCEPT", &pc(&SyncMsg::Accept { inv: inv.clone(), want: Inventory::default() }));
    print("SYNC_DATA_AND_WANT", &pc(&SyncMsg::DataAndWant { data: Data::default(), want: inv.clone() }));
    print("SYNC_DATA", &pc(&SyncMsg::Data { data: Data::default() }));
    print("SYNC_DATA_FULL", &pc(&SyncMsg::Data { data: full_data(&a, space, op, env) }));
    print("DTN_PAYLOAD", &pc(&DtnPayload { space, data: Data::default() }));
    print("EPH", &pc(&EphMsg { space, epoch: EpochId([6; 16]), nonce: [7; 24], ciphertext: vec![8, 9] }));
    print("BLOB_REQ_GET_RANGE", &pc(&BlobReq::GetRange { space, hash: env, offset: 300, len: 70000 }));
    print("BLOB_REQ_GET", &pc(&BlobReq::Get { space, hash: env }));
    print("BLOB_REQ_PUT", &pc(&BlobReq::Put { space, hash: env, len: 70000 }));
    print("BLOB_REQ_GET_FROM", &pc(&BlobReq::GetFrom { space, hash: env, offset: 300 }));
    print("BLOB_REQ_OFFER", &pc(&BlobReq::Offer { space, hash: env, len: 70000 }));
    print("BLOB_RESP_RANGE", &pc(&BlobResp::Range { total: 70000, offset: 300 }));
    let resps = [
        pc(&BlobResp::Found { len: 70000 }),
        pc(&BlobResp::NotFound),
        pc(&BlobResp::Denied),
        pc(&BlobResp::Stored),
        pc(&BlobResp::SendFrom { offset: 300 }),
        pc(&BlobResp::NoSpace),
        pc(&BlobResp::Busy),
    ];
    print("BLOB_RESPS", &resps.concat());
    print("ANSWERS", &[pc(&WireAnswer::Take(300)), pc(&WireAnswer::Duplicate), pc(&WireAnswer::Refuse(true))].concat());
    print("CARD", &pc(&ContactCard::new(&a, "Ada")));

    let payload = b"v1 bundle";
    let (created, lifetime) = (1_700_000_000_000u64, 600_000u64);
    let id = super::bundle_id(&a.sign_pk(), &b.sign_pk(), payload);
    print("BUNDLE_ID", &id.0);
    let sig = a.sign("mycel/v0/dtn-bundle", &[&id.0, &created.to_be_bytes(), &lifetime.to_be_bytes()]);
    print("BUNDLE_SIG", &sig.0);
    let offer =
        WireOffer { id, src: a.sign_pk(), dst: b.sign_pk(), size: payload.len() as u64, created, lifetime, sig, copies: 4 };
    let mut msg = vec![K_OFFER];
    msg.extend_from_slice(&pc(&offer));
    print("K_OFFER_VEC", &msg);
    print("RECEIPT_SIG", &b.sign(RECEIPT_CTX, &[&id.0]).0);
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
    print("K_SUMMARY_VEC", &msg);

    let ann = super::wire::sign_announce(&a, Origination { seq: 42, flags: 1, scope: 6, uplink: 777 }, "Ada");
    print("ANNOUNCE", &super::wire::encode_announce(&ann));
    let ann_b = super::wire::sign_announce(&b, Origination { seq: 7, flags: 0, scope: 2, uplink: 0 }, "Bo");
    let ogms = super::wire::encode_announces(&[ann.clone(), ann_b], 1200);
    assert_eq!(ogms.len(), 1);
    print("OGMS", &ogms[0]);
    print("SEQREQ", &super::wire::encode_seqreq(&SeqReq { origin: a.sign_pk(), seq: 43, hops: 2 }));
    let frame = Frame {
        ttl: 9,
        reached: true,
        control: false,
        dst: b.sign_pk(),
        src: a.sign_pk(),
        waypoint: SignPk([10; 32]),
        id: 0x01020304,
        offset: 0,
        total: 3,
        payload: Bytes::from_static(b"pkt"),
    };
    print("DATA_FRAME", &super::wire::encode_frame(&frame, 1200).unwrap()[0]);
    let control = Frame { reached: false, control: true, payload: Bytes::from_static(&[1, 0xaa, 0xbb]), ..frame };
    print("CONTROL_FRAME", &super::wire::encode_frame(&control, 1200).unwrap()[0]);
}
