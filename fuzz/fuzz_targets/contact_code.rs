//! Contact codes (`mycel-node`): what a user pastes or scans from anyone,
//! `mycel:` + base64url(postcard(card)) and optional `@ip:port,…` hints.
//! Two modes, by the first input byte: the input as the pasted text, or a
//! validly signed card with the input as its name and hints, so the fuzzer
//! gets past the signature.
//!
//! Properties: no panic; a code decodes only with a valid signature and at
//! most eight hints; our own codes decode to the card and hints encoded.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mycel_crypto::DeviceKeys;
use mycel_net::ContactCard;
use mycel_node::{decode_contact_code_with_hints, encode_contact_code, encode_contact_code_with_hints};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let text = String::from_utf8_lossy(rest);
    if mode % 2 == 0 {
        if let Ok((card, hints)) = decode_contact_code_with_hints(&text) {
            card.verify().expect("decoded cards are verified");
            assert!(hints.len() <= 8);
            let again = decode_contact_code_with_hints(&encode_contact_code(&card)).expect("re-encodes");
            assert_eq!(again.0, card);
        }
    } else {
        let (name, hints) = text.split_once('\n').unwrap_or((&text, ""));
        let card = ContactCard::new(&DeviceKeys::from_seed([4; 32]), name);
        let hints: Vec<String> = hints.split('\n').filter(|h| !h.is_empty()).map(str::to_string).collect();
        let code = encode_contact_code_with_hints(&card, &hints);
        let (back, addrs) = decode_contact_code_with_hints(&code).expect("our own code decodes");
        assert_eq!(back, card);
        assert!(addrs.len() <= 8);
    }
});
