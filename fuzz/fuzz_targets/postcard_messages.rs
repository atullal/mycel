//! Every postcard message decoded from untrusted bytes outside a stream
//! reader: store-and-forward payloads, decrypted feed entries and keyrings,
//! membership ops and envelopes (from peers and from storage), contact
//! cards, chat payloads, the rules ABI, and call and video control messages.
//! The first input byte picks the type.
//!
//! Properties: no panic; whatever decodes re-encodes to bytes that decode to
//! an equal value (and encode identically again); signature checks on
//! decoded ops, envelopes and cards run without panicking.
#![no_main]

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use mycel_crypto::SymKey;
use mycel_trust::{EpochId, SignedOp};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(data: &[u8]) -> Option<T> {
    let value: T = postcard::from_bytes(data).ok()?;
    let once = postcard::to_allocvec(&value).expect("a decoded value encodes");
    let back: T = postcard::from_bytes(&once).expect("our own encoding decodes");
    assert_eq!(back, value);
    assert_eq!(postcard::to_allocvec(&back).unwrap(), once);
    Some(value)
}

/// For types without `PartialEq`: the encoding is stable.
fn stable<T: Serialize + DeserializeOwned>(data: &[u8]) -> Option<T> {
    let value: T = postcard::from_bytes(data).ok()?;
    let once = postcard::to_allocvec(&value).expect("a decoded value encodes");
    let back: T = postcard::from_bytes(&once).expect("our own encoding decodes");
    assert_eq!(postcard::to_allocvec(&back).unwrap(), once);
    Some(value)
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, data)) = data.split_first() else { return };
    match kind % 14 {
        0 => {
            stable::<mycel_net::wire::DtnPayload>(data);
        }
        1 => {
            stable::<mycel_net::wire::SyncMsg>(data);
        }
        2 => {
            roundtrip::<mycel_sync::FeedEntry>(data);
        }
        3 => {
            if let Some(op) = roundtrip::<SignedOp>(data) {
                let _ = op.id();
                let _ = op.verify_standalone();
            }
        }
        4 => {
            if let Some(env) = roundtrip::<mycel_sync::Envelope>(data) {
                let _ = env.id();
                let _ = env.verify_sig();
            }
        }
        5 => {
            // a keyring sealed to a new member
            if let Ok(entries) = postcard::from_bytes::<Vec<(EpochId, SymKey)>>(data) {
                let again = postcard::to_allocvec(&entries).unwrap();
                let back: Vec<(EpochId, SymKey)> = postcard::from_bytes(&again).unwrap();
                assert!(back == entries);
            }
        }
        6 => {
            if let Some(card) = roundtrip::<mycel_net::ContactCard>(data) {
                let _ = card.verify();
            }
        }
        7 => {
            if let Some(op) = mycel_kit_chat::ChatOp::decode(data) {
                assert_eq!(mycel_kit_chat::ChatOp::decode(&op.encode()), Some(op));
            }
            if let Some(s) = mycel_kit_chat::ChatSignal::decode(data) {
                assert_eq!(mycel_kit_chat::ChatSignal::decode(&s.encode()), Some(s));
            }
        }
        8 => {
            if let Some(v) = mycel_rules_abi::decode_exact::<mycel_rules_abi::RuleInput>(data) {
                let again = mycel_rules_abi::encode(&v);
                assert_eq!(mycel_rules_abi::decode_exact::<mycel_rules_abi::RuleInput>(&again), Some(v));
            }
        }
        9 => {
            if let Some(v) = mycel_rules_abi::decode_exact::<mycel_rules_abi::ReduceOutput>(data) {
                let again = mycel_rules_abi::encode(&v);
                assert_eq!(mycel_rules_abi::decode_exact::<mycel_rules_abi::ReduceOutput>(&again), Some(v));
            }
            if let Some(v) = mycel_rules_abi::decode_exact::<mycel_rules_abi::ReduceInput>(data) {
                let again = mycel_rules_abi::encode(&v);
                assert_eq!(mycel_rules_abi::decode_exact::<mycel_rules_abi::ReduceInput>(&again), Some(v));
            }
        }
        10 => {
            if let Some(v) = mycel_rules_abi::decode_exact::<mycel_rules_abi::chat::ChatOp>(data) {
                let again = mycel_rules_abi::encode(&v);
                assert_eq!(mycel_rules_abi::decode_exact::<mycel_rules_abi::chat::ChatOp>(&again), Some(v));
            }
        }
        11 => {
            if let Ok(c) = mycel_call::proto::Ctrl::decode(data) {
                let wire = c.encode();
                assert_eq!(mycel_call::proto::Ctrl::decode(&wire[2..]).unwrap(), c);
            }
        }
        12 => {
            roundtrip::<mycel_video::wire::VideoCtrl>(data);
        }
        _ => {
            stable::<mycel_net::wire::Inventory>(data);
        }
    }
});
