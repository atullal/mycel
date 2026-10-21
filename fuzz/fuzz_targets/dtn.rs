//! Store and forward (`mesh/dtn.rs`, `mesh/mod.rs`): the summary, offer and
//! answer messages neighbours send over hop streams, then a carrier fed by
//! hostile neighbours: summaries (decoded from the input bytes, so every
//! value the wire allows, NaN predictabilities included), offers, bundles,
//! partial transfers, receipts and the planner. Signature checks are decided
//! by the input.
//!
//! Properties: no panic; decoded messages re-encode to equal values; the
//! planner never hands a bundle (or zero copies of one) to ourselves; what
//! we tell neighbours are probabilities; after every step, what the carrier
//! remembers from neighbours (their predictabilities and bundle ids, and the
//! transitive predictabilities they gave us) is within its caps.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{Hash32, Sig, SignPk};
use mycel_net::fuzzing;
use mycel_net::mesh::core::Toward;
use mycel_net::mesh::dtn::{Accepted, Bundle, Carrier, DtnConfig, Gradient, Offer, Receipt, Spray};

const PEERS: u8 = 8;

fn pk(i: u8) -> SignPk {
    match i % (PEERS + 1) {
        PEERS => mycel_net::mesh::dtn::INTERNET,
        i => SignPk([i; 32]),
    }
}

#[derive(Arbitrary, Debug)]
enum Step {
    Summary { from: u8, body: Vec<u8>, verify: bool },
    Offer { from: u8, src: u8, dst: u8, size: u32, lifetime: u32, copies: u8, verify: bool },
    Bundle { from: u8, src: u8, dst: u8, len: u16, lifetime: u32, copies: u8, verify: bool },
    Partial { src: u8, dst: u8, len: u16 },
    Originate { dst: u8, len: u16, lifetime: u32 },
    Receipt { dst: u8, of: u8 },
    Encounter(u8),
    NewContact(u8),
    Plan { neighbours: u8, toward: Vec<u8> },
    Transferred { to: u8, of: u8, copies: u8, ok: bool },
    Refused { to: u8, of: u8, full: bool },
    Doubt(u8),
    SetInternet(bool),
    Summaries { neighbours: u8 },
    Tick(u32),
}

#[derive(Arbitrary, Debug)]
struct Input {
    spray: u8,
    gradient: u8,
    carry: bool,
    messages: Vec<u8>,
    steps: Vec<Step>,
}

const WALL0: u64 = 1_760_000_000_000;

fn messages(data: &[u8]) {
    let Some((&kind, body)) = data.split_first() else { return };
    match kind % 3 {
        0 => {
            if let Some(s) = fuzzing::dtn_summary(body)
                && let Some(again) = fuzzing::encode_dtn_summary(s.clone())
            {
                let back = fuzzing::dtn_summary(&again).expect("our own summary decodes");
                // (compare as bits: a NaN predictability is not equal to itself)
                assert_eq!(format!("{back:?}"), format!("{s:?}"));
            }
        }
        1 => {
            if let Some(o) = fuzzing::dtn_offer(body) {
                let again = fuzzing::encode_dtn_offer(&o).expect("an offer fits");
                assert_eq!(fuzzing::dtn_offer(&again), Some(o));
            }
        }
        _ => {
            let _ = fuzzing::dtn_answer(body);
        }
    }
}

fn bundle(src: u8, dst: u8, len: u16, created: u64, lifetime: u32) -> Bundle {
    let (src, dst) = (pk(src), pk(dst));
    let payload = Bytes::from(vec![len as u8; usize::from(len)]);
    Bundle {
        id: mycel_net::mesh::bundle_id(&src, &dst, &payload),
        src,
        dst,
        created,
        lifetime: u64::from(lifetime),
        payload,
        sig: Sig([0; 64]),
    }
}

fuzz_target!(|input: Input| {
    messages(&input.messages);
    let me = pk(0);
    let cfg = DtnConfig {
        spray: [Spray::First, Spray::Fallback, Spray::Focus][usize::from(input.spray % 3)],
        gradient: [Gradient::Internet, Gradient::Both, Gradient::Destination, Gradient::Off]
            [usize::from(input.gradient % 4)],
        carry: input.carry,
        ..DtnConfig::default()
    };
    let mut c = Carrier::new(me, cfg);
    let mut now: u64 = 1_000;
    let mut known: Vec<Bundle> = Vec::new();
    for step in input.steps.into_iter().take(128) {
        let wall = WALL0 + now;
        c.set_clock(now, wall);
        match step {
            Step::Summary { from, body, verify } => {
                if let Some(s) = fuzzing::dtn_summary(&body) {
                    c.on_summary(pk(from), s, now, |_: &Receipt| verify);
                }
            }
            Step::Offer { from, src, dst, size, lifetime, copies, verify } => {
                let b = bundle(src, dst, 0, wall, lifetime);
                let o = Offer { size: u64::from(size), copies, ..Offer::of(&b, copies) };
                let _ = c.offered(pk(from), &o, now, |_| verify);
            }
            Step::Bundle { from, src, dst, len, lifetime, copies, verify } => {
                let b = bundle(src, dst, len % 4096, wall, lifetime);
                known.push(b.clone());
                if let Accepted::ForMe(got) = c.accept(pk(from), b, copies, now, |_| verify) {
                    assert_eq!(got.dst, me);
                }
            }
            Step::Partial { src, dst, len } => {
                let b = bundle(src, dst, len % 4096, wall, 60_000);
                let half = b.payload.slice(..b.payload.len() / 2);
                c.keep_partial(b.id, b.src, half, now);
                let _ = c.partial(&b.id);
            }
            Step::Originate { dst, len, lifetime } => {
                let b = bundle(0, dst, len % 4096, wall, lifetime);
                known.push(b.clone());
                let _ = c.originate(b, now);
            }
            Step::Receipt { dst, of } => {
                let id = known.get(usize::from(of)).map_or(Hash32([of; 32]), |b| b.id);
                c.add_receipt(Receipt { id, dst: pk(dst), sig: Sig([0; 64]) });
            }
            Step::Encounter(p) => c.encounter(pk(p), now),
            Step::NewContact(p) => c.new_contact(pk(p)),
            Step::Plan { neighbours, toward } => {
                let nbs: Vec<SignPk> = (1..PEERS).filter(|i| neighbours & (1 << i) != 0).map(pk).collect();
                let mut u = Unstructured::new(&toward);
                let plan = c.plan(
                    now,
                    |_| match u.int_in_range(0..=3u8).unwrap_or(2) {
                        // (the router never names us as the next hop)
                        0 => Toward::Hop(pk(1 + u.arbitrary::<u8>().unwrap_or(0) % (PEERS - 1))),
                        1 => Toward::Soon,
                        2 => Toward::Nowhere,
                        _ => Toward::Unreachable,
                    },
                    &nbs,
                );
                for t in plan {
                    assert_ne!(t.to, me, "a bundle handed to ourselves");
                    assert!(t.copies >= 1, "a transfer of no copies: {t:?}");
                }
            }
            Step::Transferred { to, of, copies, ok } => {
                let id = known.get(usize::from(of)).map_or(Hash32([of; 32]), |b| b.id);
                c.transferred(pk(to), id, copies, ok, now);
            }
            Step::Refused { to, of, full } => {
                let id = known.get(usize::from(of)).map_or(Hash32([of; 32]), |b| b.id);
                c.refused(pk(to), id, full, now);
            }
            Step::Doubt(p) => c.doubt(pk(p), now),
            Step::SetInternet(on) => c.set_internet(on),
            Step::Summaries { neighbours } => {
                let nbs: Vec<SignPk> = (1..PEERS).filter(|i| neighbours & (1 << i) != 0).map(pk).collect();
                for (to, s) in c.summaries(now, &nbs) {
                    assert_ne!(to, me);
                    for (_, p) in &s.preds {
                        assert!((0.0..=1.0).contains(p), "we tell neighbours a predictability of {p}");
                    }
                    let _ = fuzzing::encode_dtn_summary(s);
                }
            }
            Step::Tick(ms) => {
                now += u64::from(ms % 600_000);
                c.tick(now);
            }
        }
        for id in c.held() {
            if let Some(b) = c.bundle(&id) {
                assert_eq!(b.id, id);
            }
        }
        if let Err(grew) = fuzzing::dtn_bounds(&c) {
            panic!("a neighbour grew the carrier's state: {grew}");
        }
        let _ = c.stats();
        let _ = c.p(&pk(1), now);
    }
});
