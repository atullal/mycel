//! Reachability records (`mesh/directory.rs`): pkarr signed packets fetched
//! from the n0 relay or the Mainline DHT (anyone can publish), or handed to
//! a gateway over the mesh to publish. Two modes, by the first input byte:
//! raw packet bytes, or a validly signed packet whose user data is the
//! input (the signature would stop raw bytes from ever reaching the
//! `mycel-gw:` parser).
//!
//! Properties: no panic; a record opens only as signed by its own key, with
//! at most three gateways; a record we seal opens to what we sealed.
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use mycel_crypto::{DeviceKeys, SignPk};
use mycel_net::iroh::SecretKey;
use mycel_net::iroh::endpoint_info::{EndpointInfo, UserData};
use mycel_net::mesh::directory;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let keys = DeviceKeys::from_seed([3; 32]);
    let me = keys.sign_pk();
    match mode % 3 {
        0 => {
            let _ = directory::timestamp(rest);
            if let Some(r) = directory::open(rest, None) {
                assert!(r.gateways.len() <= 3);
                assert!(directory::open(rest, Some(&r.node)).is_some());
                assert!(directory::open(rest, Some(&SignPk([0; 32]))).is_none() || r.node == SignPk([0; 32]));
            }
        }
        1 => {
            let Ok(text) = std::str::from_utf8(rest) else { return };
            let Ok(user) = UserData::from_str(text) else { return };
            let secret = SecretKey::from_bytes(&keys.seed());
            let info = EndpointInfo::new(secret.public()).with_user_data(Some(user));
            let Ok(packet) = info.to_pkarr_signed_packet(&secret, 60) else { return };
            if let Some(r) = directory::open(packet.as_bytes(), Some(&me)) {
                assert_eq!(r.node, me);
                assert!(r.gateways.len() <= 3);
            }
        }
        _ => {
            // Seal gateways taken from the input: what opens is what was sealed.
            let gateways: Vec<(SignPk, u32)> = rest
                .as_chunks::<5>()
                .0
                .iter()
                .take(3)
                .map(|&[seed, a, b, c, d]| {
                    (DeviceKeys::from_seed([seed; 32]).sign_pk(), u32::from_le_bytes([a, b, c, d]))
                })
                .collect();
            let record = directory::seal(&keys, &gateways).expect("three gateways fit a record");
            let r = directory::open(&record, Some(&me)).expect("our own record opens");
            assert_eq!(r.gateways, gateways);
        }
    }
});
