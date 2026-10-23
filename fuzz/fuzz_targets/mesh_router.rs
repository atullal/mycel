//! The mesh router (`mesh/core.rs`), driven by hostile neighbours: links
//! coming and going, internet lookups, our own sends, and above all
//! datagrams. Datagrams arrive either as raw bytes (dispatched by type
//! exactly as the driver's `on_datagram` does) or as structured
//! announcements, frames and seqno requests that pass the decoder, so the
//! fuzzer reaches the routing logic without first having to learn the
//! framing. Signature checks are decided by the input: a liar may hold a
//! valid signature.
//!
//! Properties: nothing panics (overflow checks are on), the router never
//! addresses itself, what it emits re-encodes, and a frame relayed in the
//! step it arrived has a lower TTL than it arrived with.
#![no_main]

use std::sync::Arc;

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{Sig, SignPk};
use mycel_net::mesh::core::{Announce, Config, Frame, Out, Router, SeqReq};
use mycel_net::mesh::wire;

const PEERS: u8 = 12;

fn pk(i: u8) -> SignPk {
    SignPk([i % PEERS; 32])
}

#[derive(Arbitrary, Debug)]
enum Step {
    HopUp(u8),
    HopDown(u8),
    SetDirect(u8, bool),
    SetCost(u8, u32),
    DialFailed(u8),
    SetInternet(bool),
    SetUplink(u32),
    Raw {
        from: u8,
        bytes: Vec<u8>,
        verify: bool,
    },
    Announce {
        from: u8,
        origin: u8,
        hops: u8,
        cost: u32,
        seq: i32,
        flags: u8,
        scope: u8,
        uplink: u32,
        name: String,
        verify: bool,
    },
    Frame {
        from: u8,
        dst: u8,
        src: u8,
        waypoint: u8,
        ttl: u8,
        reached: bool,
        control: bool,
        ext: u8,
        id: u32,
        offset: u16,
        total: u16,
        len: u16,
    },
    SeqReq {
        from: u8,
        origin: u8,
        seq: i32,
        hops: u8,
    },
    Send {
        dst: u8,
        waypoint: u8,
        len: u16,
        control: bool,
    },
    Resolved {
        target: u8,
        gateways: Option<Vec<(u8, u32)>>,
    },
    AdmitRecord(u8),
    Feedback {
        dst: u8,
        acked: bool,
    },
    PathFeedback {
        dst: u8,
        via: u8,
        silent: Option<u16>,
    },
    Toward(u8),
    Originate,
    Tick(u16),
}

#[derive(Arbitrary, Debug)]
struct Input {
    gateway: bool,
    fisheye: bool,
    flood_reduction: bool,
    steps: Vec<Step>,
}

const WALL0: u64 = 1_760_000_000_000;

/// `arrived`: the (TTL, extension bits) of a frame that arrived this step.
fn check(me: SignPk, outs: &mut Vec<Out>, arrived: Option<(u8, u8)>) {
    for out in outs.drain(..) {
        match out {
            Out::Announce { to, ann } => {
                assert_ne!(to, me, "announcement to ourselves");
                assert!(ann.name.len() <= wire::MAX_NAME);
                assert_eq!(wire::decode_announce(&wire::encode_announce(&ann)), Some(ann));
            }
            Out::SeqReq { to, .. } => assert_ne!(to, me, "seqno request to ourselves"),
            Out::Frame { to, frame, relayed } => {
                assert_ne!(to, me, "frame to ourselves");
                assert!(frame.offset as usize + frame.payload.len() <= frame.total as usize, "{frame:?}");
                if relayed && let Some((ttl, ext)) = arrived {
                    assert!(frame.ttl < ttl, "relayed frame kept its TTL");
                    assert_eq!(frame.ext, ext, "a relay changed flag bits it doesn't know");
                }
            }
            Out::Dial(p) | Out::Hangup(p) | Out::Resolve(p) => assert_ne!(p, me),
            Out::RouteUp { dst, via, .. } | Out::RouteDown { dst, via } => {
                assert_ne!(dst, me);
                assert_ne!(via, me);
            }
            Out::Deliver { .. } | Out::Control { .. } | Out::PublishReach { .. } => {}
        }
    }
}

fuzz_target!(|input: Input| {
    let me = pk(0);
    let cfg = Config {
        gateway: input.gateway,
        fisheye: input.fisheye,
        flood_reduction: input.flood_reduction,
        ..Config::default()
    };
    let mut r = Router::new(me, cfg);
    let mut now: u64 = 1_000;
    let mut outs = Vec::new();
    for step in input.steps.into_iter().take(256) {
        let wall = WALL0 + now;
        let mut arrived = None;
        match step {
            Step::HopUp(p) => r.hop_up(pk(p), now),
            Step::HopDown(p) => r.hop_down(pk(p), now),
            Step::SetDirect(p, on) => r.set_direct(pk(p), on, now),
            Step::SetCost(p, c) => r.set_cost(pk(p), c),
            Step::DialFailed(p) => r.dial_failed(pk(p), now),
            Step::SetInternet(on) => r.set_internet(on),
            Step::SetUplink(u) => r.set_uplink(u),
            Step::Raw { from, bytes, verify } => {
                let from = pk(from);
                // as `Driver::on_datagram`
                match bytes.first() {
                    Some(&1) => {
                        if let Some(a) = wire::decode_announce(&bytes) {
                            r.on_announce(from, a, now, wall, |_| verify);
                        }
                    }
                    Some(&4) => {
                        for a in wire::decode_announces(&bytes) {
                            r.on_announce(from, a, now, wall, |_| verify);
                        }
                    }
                    Some(&2) => {
                        if let Some(f) = wire::decode_frame(Bytes::from(bytes)) {
                            arrived = Some((f.ttl, f.ext));
                            r.on_frame(from, f, now);
                        }
                    }
                    Some(&3) => {
                        if let Some(q) = wire::decode_seqreq(&bytes) {
                            r.on_seqreq(from, q, now);
                        }
                    }
                    _ => {}
                }
            }
            Step::Announce { from, origin, hops, cost, seq, flags, scope, uplink, name, verify } => {
                let a = Announce {
                    hops,
                    cost,
                    origin: pk(origin),
                    seq: wall.saturating_add_signed(i64::from(seq)),
                    flags,
                    scope,
                    uplink,
                    name: Arc::from(wire::truncate(&name, wire::MAX_NAME)),
                    sig: Sig([origin; 64]),
                };
                // only what the decoder lets through
                let a = wire::decode_announce(&wire::encode_announce(&a)).expect("valid announcement");
                r.on_announce(pk(from), a, now, wall, |_| verify);
            }
            Step::Frame { from, dst, src, waypoint, ttl, reached, control, ext, id, offset, total, len } => {
                let len = usize::from(len) % (wire::MIN_QUIC_MTU + 1);
                let total = total.max(offset.saturating_add(len as u16));
                let f = Frame {
                    ttl,
                    reached,
                    control,
                    ext,
                    dst: pk(dst),
                    src: pk(src),
                    waypoint: pk(waypoint),
                    id,
                    offset,
                    total,
                    payload: Bytes::from(vec![id as u8; len]),
                };
                let grams = wire::encode_frame(&f, usize::MAX).expect("unbounded datagram");
                if let Some(f) = wire::decode_frame(grams[0].clone()) {
                    arrived = Some((f.ttl, f.ext));
                    r.on_frame(pk(from), f, now);
                }
            }
            Step::SeqReq { from, origin, seq, hops } => {
                let q = SeqReq { origin: pk(origin), seq: wall.saturating_add_signed(i64::from(seq)), hops };
                r.on_seqreq(pk(from), q, now);
            }
            Step::Send { dst, waypoint, len, control } => {
                let payload = Bytes::from(vec![7u8; usize::from(len) % (wire::MIN_QUIC_MTU + 1)]);
                r.send(pk(dst), pk(waypoint), payload, control, now);
            }
            Step::Resolved { target, gateways } => {
                let gws = gateways.map(|g| g.into_iter().take(8).map(|(p, c)| (pk(p), c)).collect());
                r.on_resolved(pk(target), gws, now);
            }
            Step::AdmitRecord(p) => {
                r.admit_record(pk(p), now);
            }
            Step::Feedback { dst, acked } => {
                r.feedback(pk(dst), acked, now);
            }
            Step::PathFeedback { dst, via, silent } => {
                let since = silent.map(|ms| now.saturating_sub(u64::from(ms)));
                r.path_feedback(pk(dst), pk(via), since, now);
            }
            Step::Toward(p) => {
                let _ = r.toward(&pk(p), now);
                let _ = r.next_hop_local(&pk(p), now);
                let _ = r.route_hops(&pk(p), &pk(p.wrapping_add(1)));
                let _ = r.gateways_with_cost(now);
                let _ = r.reachable();
            }
            Step::Originate => {
                if r.announce_due(now) {
                    let o = r.next_announce(wall);
                    let ann = wire::sign_announce(&mycel_crypto::DeviceKeys::from_seed([0; 32]), o, "me");
                    // (our own key is a stand-in: the router never verifies its own)
                    r.originate(Announce { origin: me, ..ann }, now);
                }
            }
            Step::Tick(ms) => {
                now += u64::from(ms);
                r.tick(now);
            }
        }
        r.drain(&mut outs);
        check(me, &mut outs, arrived);
    }
    let _ = r.stats();
});
