//! Custody (`custody/`): the messages on a `Custody` stream, decoded from
//! the input bytes, then a custodian's store fed by hostile depositors and
//! recipients: deposits of any parcel (any version, recipient, clock,
//! lifetime, size, stamp, address, known or not), listings and takes for
//! anyone, receipts (genuine, forged and for others), releases with right
//! and wrong secrets, the clock moving either way, and serving switched on
//! and off.
//!
//! Properties: no panic; a decoded message re-encodes to the same bytes;
//! opening a parcel never panics and only its recipient opens one; after
//! every step the store's books balance and stay within its limits
//! (`Vault::check`); nobody takes a parcel addressed to someone else.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::custody::{self, Depositor, Msg, Origin, Parcel, Receipt, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;

#[derive(Arbitrary, Debug)]
enum Step {
    Deposit { from: u8, to: u8, version: u8, created: i32, lifetime: u32, len: u16, stamp: u64, origin: u8, known: bool },
    Listing { who: u8 },
    Take { who: u8, of: u8 },
    Receipt { signer: u8, claimed: u8, of: u8 },
    Release { of: u8, right: bool },
    Tick(i32),
    Serve(bool),
}

#[derive(Arbitrary, Debug)]
struct Input {
    capacity: u16,
    per_depositor: u16,
    per_recipient: u16,
    max_parcels: u8,
    stamp_bits: u8,
    steps: Vec<Step>,
}

fuzz_target!(|data: &[u8]| {
    // the wire: every message a peer can send
    if let Ok(msg) = postcard::from_bytes::<Msg>(data) {
        let bytes = postcard::to_allocvec(&msg).expect("a decoded message encodes");
        let again: Msg = postcard::from_bytes(&bytes).expect("and decodes");
        assert_eq!(postcard::to_allocvec(&again).unwrap(), bytes);
    }
    let keys: Vec<DeviceKeys> = (0..4u8).map(|i| DeviceKeys::from_seed([i + 1; 32])).collect();
    if let Ok(p) = postcard::from_bytes::<Parcel>(data) {
        let _ = p.id();
        for k in &keys {
            if custody::open(k, &p).is_ok() {
                assert_eq!(p.dst, k.sign_pk());
            }
        }
    }
    let Ok(input) = Input::arbitrary(&mut Unstructured::new(data)) else { return };
    let cfg = VaultConfig {
        capacity: u64::from(input.capacity) * 64,
        per_depositor: u64::from(input.per_depositor) * 16,
        per_recipient: u64::from(input.per_recipient) * 16,
        max_parcels: usize::from(input.max_parcels).max(1),
        stamp_bits: input.stamp_bits % 6,
        ..Default::default()
    };
    let me = SignPk([0xcc; 32]);
    let mut v = Vault::new(cfg);
    let mut now = NOW;
    let mut held: Vec<(Parcel, [u8; 32])> = Vec::new();
    let pk = |i: u8| keys[usize::from(i) % keys.len()].sign_pk();
    for step in input.steps.into_iter().take(128) {
        match step {
            Step::Deposit { from, to, version, created, lifetime, len, stamp, origin, known } => {
                let secret = [from; 32];
                let p = Parcel {
                    version: version % 3,
                    dst: if to == 0xff { me } else { pk(to) },
                    created: now.saturating_add_signed(i64::from(created)),
                    lifetime: u64::from(lifetime),
                    release: custody::release_hash(&secret),
                    sealed: vec![to; usize::from(len) % 4096],
                };
                let d = Depositor { key: SignPk([from; 32]), origin: Origin::Ip([origin % 4; 16]), known };
                let _ = v.deposit(&d, p.clone(), stamp, &me, now);
                if held.len() < 64 {
                    held.push((p, secret));
                }
            }
            Step::Listing { who } => {
                for (id, _) in v.listing(&pk(who), 64) {
                    assert!(v.holds(&id));
                }
            }
            Step::Take { who, of } => {
                let ids: Vec<Hash32> = held.iter().skip(usize::from(of) % 8).take(8).map(|(p, _)| p.id()).collect();
                for p in v.take(&pk(who), &ids, u64::MAX) {
                    assert_eq!(p.dst, pk(who), "only the recipient's own parcels");
                }
            }
            Step::Receipt { signer, claimed, of } => {
                if let Some((p, _)) = held.get(usize::from(of) % held.len().max(1)) {
                    let r = Receipt::sign(&keys[usize::from(signer) % keys.len()], p.id());
                    let ok = v.receipt(&pk(claimed), &r);
                    if ok {
                        assert_eq!(pk(claimed), pk(signer));
                    }
                }
            }
            Step::Release { of, right } => {
                if let Some((p, s)) = held.get(usize::from(of) % held.len().max(1)) {
                    let id = p.id();
                    let secret = if right { *s } else { [0xee; 32] };
                    let was = v.holds(&id);
                    let ok = v.release(&id, &secret);
                    assert!(!ok || (was && right));
                }
            }
            Step::Tick(d) => {
                now = now.saturating_add_signed(i64::from(d) * 1000);
                v.tick(now);
            }
            Step::Serve(on) => v.set_serving(on),
        }
        v.check().expect("books balance, within limits");
    }
});
