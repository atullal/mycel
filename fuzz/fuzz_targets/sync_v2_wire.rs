//! Every Sync v2 decoder of untrusted bytes: session frames (`Msg`, on real
//! and model items), gossip messages, the sealed store-and-forward payload
//! (opened with a fixed device's key), and seen notes (opened by a replica
//! of a fixed space). The first input byte picks the decoder.
//!
//! Properties: no panic; whatever decodes re-encodes stably; a sealed
//! bundle or seen note that opens is well-formed, and opening never panics
//! whatever the bytes.
#![no_main]

use std::sync::{Arc, Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use mycel_crypto::DeviceKeys;
use mycel_sync::reconcile::gossip::GossipMsg;
use mycel_sync::reconcile::model::{ModelEnv, ModelOp};
use mycel_sync::reconcile::{Msg, encoded_len};
use mycel_sync::{Envelope, Replica};
use mycel_trust::SignedOp;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn stable<T: Serialize + DeserializeOwned>(data: &[u8]) -> Option<T> {
    let value: T = postcard::from_bytes(data).ok()?;
    let once = postcard::to_allocvec(&value).expect("a decoded value encodes");
    let back: T = postcard::from_bytes(&once).expect("our own encoding decodes");
    assert_eq!(postcard::to_allocvec(&back).unwrap(), once);
    assert_eq!(encoded_len(&back), once.len(), "the size count matches the encoding");
    Some(value)
}

struct Fixed {
    keys: Arc<DeviceKeys>,
    replica: Mutex<Replica>,
}

fn fixed() -> &'static Fixed {
    static F: OnceLock<Fixed> = OnceLock::new();
    F.get_or_init(|| {
        let keys = Arc::new(DeviceKeys::from_seed([7; 32]));
        let (replica, _) = Replica::create(keys.clone(), None).expect("a space");
        Fixed { keys, replica: Mutex::new(replica) }
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, data)) = data.split_first() else { return };
    match kind % 6 {
        0 => {
            stable::<Msg<SignedOp, Envelope>>(data);
        }
        1 => {
            stable::<Msg<ModelOp, ModelEnv>>(data);
        }
        2 => {
            if let Some(m) = stable::<GossipMsg<SignedOp, Envelope>>(data) {
                let _ = m.space();
            }
        }
        3 => {
            stable::<mycel_net::bundles::DtnPayload2>(data);
        }
        4 => {
            let f = fixed();
            let src = mycel_crypto::SignPk([1; 32]);
            if let Ok(p) = mycel_net::bundles::open(&f.keys, &src, data) {
                let _ = postcard::to_allocvec(&p).expect("an opened payload encodes");
            }
            let n = mycel_net::bundles::padme(data.len());
            assert!(n >= data.len() && mycel_net::bundles::padme(n) == n);
        }
        _ => {
            let f = fixed();
            let mut r = f.replica.lock().unwrap();
            let from = mycel_crypto::SignPk([2; 32]);
            let _ = r.accept_seen(&from, data);
        }
    }
});
