//! The driver's view of a hop connection (in-memory links, real QUIC).

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::presets;
use iroh::endpoint::transports::{PathSelection, PathSelectionContext, PathSelector};
use iroh::protocol::{AcceptError, ProtocolHandler, Router as Routes};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use mycel_crypto::DeviceKeys;

use super::{ALPN, Mesh, MeshOptions};
use crate::link::{Link, MemNet, PathKind, transport_config};
use crate::version::{Caps, PeerProtocol, Protocol, WIRE_V1, WIRE_V2};

const PLAIN: &[u8] = b"test/plain";

/// Selects a path only over one medium (to set which path each end selects).
#[derive(Debug)]
struct Only(PathKind);

impl PathSelector for Only {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(p) = ctx.paths().find(|p| PathKind::of(&TransportAddr::from(p.network_path().remote())) == self.0) {
            selection.set(&p);
        }
        selection
    }
}

/// Keeps connections open.
#[derive(Debug, Clone)]
struct Hold;

impl ProtocolHandler for Hold {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        conn.closed().await;
        Ok(())
    }
}

struct Device {
    keys: Arc<DeviceKeys>,
    ep: Endpoint,
    mesh: Mesh,
    _routes: Routes,
}

async fn device(keys: Arc<DeviceKeys>, only: PathKind, nets: &[&MemNet]) -> Device {
    let mut b = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&keys.seed()))
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .path_selector(Arc::new(Only(only)))
        .transport_config(transport_config())
        .alpns(vec![ALPN.to_vec(), PLAIN.to_vec()]);
    for n in nets {
        b = b.add_custom_transport(n.link(keys.sign_pk()).transport());
    }
    let ep = b.bind().await.unwrap();
    let mesh = Mesh::new(keys.clone(), "test", MeshOptions { store_and_forward: None, ..MeshOptions::default() });
    let routes = Routes::builder(ep.clone()).accept(ALPN, mesh.protocol()).accept(PLAIN, Hold).spawn();
    mesh.attach(ep.clone());
    Device { keys, ep, mesh, _routes: routes }
}

/// A device on one medium that speaks `protocol` on its hops, and carries
/// bundles for others.
async fn versioned(protocol: Protocol, net: &MemNet) -> Device {
    let keys = Arc::new(DeviceKeys::generate());
    let alpns = super::alpns(protocol.version);
    let ep = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&keys.seed()))
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .transport_config(transport_config())
        .alpns(alpns.iter().map(|a| a.to_vec()).collect())
        .add_custom_transport(net.link(keys.sign_pk()).transport())
        .bind()
        .await
        .unwrap();
    let mesh = Mesh::new(keys.clone(), "test", MeshOptions { protocol, ..MeshOptions::default() });
    let mut routes = Routes::builder(ep.clone());
    for alpn in alpns {
        routes = routes.accept(alpn, mesh.protocol());
    }
    let routes = routes.spawn();
    mesh.attach(ep.clone());
    Device { keys, ep, mesh, _routes: routes }
}

/// `a` and `b` are in range of each other on `net`: wait for their hop.
async fn neighbours(net: &MemNet, a: &Device, b: &Device) {
    let (pa, pb) = (a.keys.sign_pk(), b.keys.sign_pk());
    for (from, to) in [(a, b), (b, a)] {
        let found = iroh::address_lookup::MemoryLookup::new();
        let addr = TransportAddr::Custom(net.addr_of(&to.keys.sign_pk()));
        found.add_endpoint_info(EndpointAddr::from_parts(to.ep.id(), [addr]));
        from.ep.address_lookup().unwrap().add(found);
    }
    a.mesh.set_direct(pb, true);
    b.mesh.set_direct(pa, true);
    eventually("the hop is up on both ends", || {
        a.mesh.connected_neighbours().contains(&pb) && b.mesh.connected_neighbours().contains(&pa)
    })
    .await;
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Each end selects its own path to the other, and only the end that dialed
/// a connection opens paths on it. So on a hop the neighbour dialed, the
/// path our end selected for them may be missing, and then no path there is
/// selected: the hop must still get a measured cost (else routing uses a
/// guess) and its congestion window (else relayed frames queue against the
/// minimum and drop).
#[tokio::test(flavor = "multi_thread")]
async fn a_hop_the_neighbour_dialed_has_a_cost_and_a_window() {
    let wifi = MemNet::new(1, PathKind::PeerWifi);
    let bt = MemNet::new(1, PathKind::Bluetooth);
    let (k1, k2) = (Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()));
    // the lower key dials the hop: make that Alice
    let (ka, kb) = if k1.sign_pk() < k2.sign_pk() { (k1, k2) } else { (k2, k1) };
    // Alice's end selects Bluetooth, Bob's peer-to-peer Wi-Fi.
    let a = device(ka, PathKind::Bluetooth, &[&wifi, &bt]).await;
    let b = device(kb, PathKind::PeerWifi, &[&wifi, &bt]).await;
    let on = |n: &MemNet, d: &Device| {
        EndpointAddr::from_parts(d.ep.id(), [TransportAddr::Custom(n.addr_of(&d.keys.sign_pk()))])
    };
    let selected = |c: &iroh::endpoint::Connection| {
        c.paths().iter().find(|p| p.is_selected()).map(|p| PathKind::of(p.remote_addr()))
    };

    // Bob reaches Alice over Wi-Fi first: his end selects it.
    let b_to_a = b.ep.connect(on(&wifi, &a), PLAIN).await.unwrap();
    eventually("bob selects wi-fi", || selected(&b_to_a) == Some(PathKind::PeerWifi)).await;
    // Wi-Fi goes out of range (else Alice's end would open a Wi-Fi path on
    // her connections too), and Alice reaches Bob over Bluetooth.
    wifi.cut();
    let a_to_b = a.ep.connect(on(&bt, &b), PLAIN).await.unwrap();
    eventually("alice selects bluetooth", || selected(&a_to_b) == Some(PathKind::Bluetooth)).await;

    // They're neighbours: Alice (the lower key) dials the hop, on Bluetooth.
    let (pa, pb) = (a.keys.sign_pk(), b.keys.sign_pk());
    a.mesh.set_direct(pb, true);
    b.mesh.set_direct(pa, true);
    eventually("the hop is up on both ends", || {
        a.mesh.connected_neighbours().contains(&pb) && b.mesh.connected_neighbours().contains(&pa)
    })
    .await;
    let hop = b.mesh.d.conn(&pa).unwrap();
    assert!(hop.side().is_server(), "alice dialed the hop");
    let kinds: Vec<PathKind> = hop.paths().iter().map(|p| PathKind::of(p.remote_addr())).collect();
    assert_eq!(kinds, vec![PathKind::Bluetooth], "the hop has only bluetooth");
    assert_eq!(selected(&hop), None, "bob's end selected wi-fi: nothing on the hop is selected");

    // Bob's end still measures the hop and knows its window.
    let mut costs = Vec::new();
    eventually("bob measures the hop", || {
        costs = b.mesh.d.hop_costs();
        costs.iter().any(|(pk, _)| *pk == pa)
    })
    .await;
    assert!(b.mesh.d.hops.lock().get(&pa).is_some_and(|h| h.path.is_some()), "the hop's path is remembered");
    let window = b.mesh.d.hop_window(&pa, &hop, None);
    assert!(window >= 1200, "bob's end knows the hop's congestion window ({window})");
    // ... as Alice's end, where the hop's path is selected, does
    assert!(a.mesh.d.hop_costs().iter().any(|(pk, _)| *pk == pb));
    let a_hop = a.mesh.d.conn(&pb).unwrap();
    assert!(a.mesh.d.hop_window(&pb, &a_hop, None) >= 1200);

    for c in [&b_to_a, &a_to_b] {
        c.close(0u32.into(), b"done");
    }
}

/// Hops between current devices run version 2 and agree on the
/// capabilities both have (unknown bits ignored); a hop to a pre-release
/// device runs version 1, with none, whoever dials it.
#[tokio::test(flavor = "multi_thread")]
async fn hops_negotiate_versions_and_capabilities() {
    let net = MemNet::new(1, PathKind::Bluetooth);
    let future = Caps::from_bits(1 << 41);
    let a = versioned(Protocol { version: WIRE_V2, caps: Caps::ROUTE_ATTEST | Caps::SYNC_V2 | future }, &net).await;
    let b = versioned(Protocol { version: WIRE_V2, caps: Caps::ROUTE_ATTEST }, &net).await;
    let old = versioned(Protocol { version: WIRE_V1, caps: Caps::ROUTE_ATTEST }, &net).await;
    let (pa, pb, po) = (a.keys.sign_pk(), b.keys.sign_pk(), old.keys.sign_pk());
    neighbours(&net, &a, &b).await;
    neighbours(&net, &a, &old).await;
    neighbours(&net, &b, &old).await;
    let agreed = |d: &Device, peer| d.mesh.neighbour_protocol(&peer).is_some_and(|p| !p.caps.is_empty());
    eventually("both hellos on the a–b hop", || agreed(&a, pb) && agreed(&b, pa)).await;
    for (d, peer) in [(&a, pb), (&b, pa)] {
        let p = d.mesh.neighbour_protocol(&peer).unwrap();
        assert_eq!((p.version, p.caps), (WIRE_V2, Caps::ROUTE_ATTEST), "{p:?}");
    }
    assert!(b.mesh.neighbour_protocol(&pa).unwrap().advertised.contains(future));
    for (d, peer) in [(&a, po), (&old, pa), (&b, po), (&old, pb)] {
        assert_eq!(d.mesh.neighbour_protocol(&peer), Some(PeerProtocol::baseline(WIRE_V1)));
    }
}

/// Bundle formats across hops (docs/PROTOCOL.md §3.6): a carrier takes and
/// carries a version 2 bundle whose payload kind it doesn't know (it never
/// reads payloads), refuses a header version it can't check, and a
/// version 1 hop is never offered a version 2 bundle (version 1 bundles
/// still cross it).
#[tokio::test(flavor = "multi_thread")]
async fn bundles_cross_hops_by_their_format() {
    use super::dtn::{Bundle, BundleFormat, Offer};
    use super::{Sent, bundle_id_of, bundle_signed, encode_offer, send_bundle, wall_ms};
    let net = MemNet::new(1, PathKind::Bluetooth);
    let a = versioned(Protocol::default(), &net).await;
    let b = versioned(Protocol::default(), &net).await;
    let old = versioned(Protocol { version: WIRE_V1, caps: Caps::NONE }, &net).await;
    neighbours(&net, &a, &b).await;
    neighbours(&net, &a, &old).await;
    let far = DeviceKeys::generate().sign_pk(); // the destination, out of range
    let signed = |format: BundleFormat, payload: &'static [u8]| {
        let id = bundle_id_of(format, &a.keys.sign_pk(), &far, payload);
        let (created, lifetime) = (wall_ms(), 600_000u64);
        let (ctx, head) = if format.checkable() { bundle_signed(format) } else { ("mycel/v9/unknown", vec![]) };
        let sig = a.keys.sign(ctx, &[&head, &id.0, &created.to_be_bytes(), &lifetime.to_be_bytes()]);
        let src = a.keys.sign_pk();
        Bundle { format, id, src, dst: far, created, lifetime, payload: bytes::Bytes::from_static(payload), sig }
    };
    let frames = crate::resources::PeerFrames::unbudgeted();
    let to_b = a.mesh.d.conn(&b.keys.sign_pk()).unwrap();
    let to_old = a.mesh.d.conn(&old.keys.sign_pk()).unwrap();

    let unknown_kind = signed(BundleFormat::v2(0x7777), b"a payload kind from a later version");
    assert!(matches!(send_bundle(&to_b, WIRE_V2, &unknown_kind, 1, &frames).await.unwrap(), Sent::Took));
    assert!(b.mesh.holds_bundle(&unknown_kind.id), "carried, unread");

    let unknown_version = signed(BundleFormat { version: 9, kind: 1 }, b"a header from a later version");
    assert!(matches!(send_bundle(&to_b, WIRE_V2, &unknown_version, 1, &frames).await.unwrap(), Sent::Refused(false)));
    assert!(!b.mesh.holds_bundle(&unknown_version.id));

    let v2 = signed(BundleFormat::v2(super::dtn::KIND_SPACE_SYNC), b"version 2");
    // never offered (not merely refused: a v1 carrier would find the
    // signature bad, after the offer had cost the hop its bytes)
    assert!(encode_offer(WIRE_V1, &Offer::of(&v2, 1)).unwrap().is_none());
    assert!(encode_offer(WIRE_V2, &Offer::of(&v2, 1)).unwrap().is_some());
    assert!(encode_offer(WIRE_V1, &Offer::of(&signed(BundleFormat::V1, b"v1"), 1)).unwrap().is_some());
    assert!(matches!(send_bundle(&to_old, WIRE_V1, &v2, 1, &frames).await.unwrap(), Sent::Refused(false)));
    assert_eq!(old.mesh.dtn_stats().refused, 0, "the version 1 carrier was never offered it");
    let v1 = signed(BundleFormat::V1, b"version 1");
    assert!(matches!(send_bundle(&to_old, WIRE_V1, &v1, 1, &frames).await.unwrap(), Sent::Took));
    assert!(old.mesh.holds_bundle(&v1.id) && !old.mesh.holds_bundle(&v2.id));
    // and a version 1 bundle over a version 2 hop
    let v1b = signed(BundleFormat::V1, b"version 1 again");
    assert!(matches!(send_bundle(&to_b, WIRE_V2, &v1b, 1, &frames).await.unwrap(), Sent::Took));
    assert!(b.mesh.holds_bundle(&v1b.id));
    // a carrier only signs what it can check
    assert!(
        a.mesh
            .send_bundle_as(far, BundleFormat { version: 9, kind: 1 }, v1.payload.clone(), Duration::from_secs(60))
            .is_none()
    );
    assert!(
        a.mesh.send_bundle_as(far, BundleFormat::v2(0x7777), v1.payload.clone(), Duration::from_secs(60)).is_some()
    );
}

/// An offer's first frame carries its bundle's format: a version 2 hop
/// gets any format back as sent (one this build can't check included, for
/// the receiver to refuse), a version 1 hop only version 1 bundles, and an
/// offer kind from a later version decodes to nothing (left unanswered).
#[test]
fn offers_carry_their_bundle_format() {
    use super::dtn::{BundleFormat, Offer};
    use super::{decode_offer, encode_offer};
    let offer = |format| Offer {
        format,
        id: mycel_crypto::Hash32([1; 32]),
        src: mycel_crypto::SignPk([2; 32]),
        dst: mycel_crypto::SignPk([3; 32]),
        size: 1234,
        created: 5,
        lifetime: 6,
        copies: 7,
        sig: mycel_crypto::Sig([8; 64]),
    };
    for format in
        [BundleFormat::V1, BundleFormat::v2(1), BundleFormat::v2(0x7777), BundleFormat { version: 9, kind: 1 }]
    {
        let o = offer(format);
        let v2 = encode_offer(WIRE_V2, &o).unwrap().expect("a version 2 hop takes every format");
        assert_eq!(decode_offer(&v2).unwrap(), Some(o.clone()));
        let v1 = encode_offer(WIRE_V1, &o).unwrap();
        assert_eq!(v1.is_some(), format == BundleFormat::V1);
        if let Some(v1) = v1 {
            assert_eq!(decode_offer(&v1).unwrap(), Some(o));
        }
    }
    let mut later = encode_offer(WIRE_V2, &offer(BundleFormat::V1)).unwrap().unwrap();
    later[0] = 0x7f;
    assert_eq!(decode_offer(&later).unwrap(), None);
    assert_eq!(decode_offer(&[]).unwrap(), None);
}

/// The same through the planner, as a node sends: a version 2 bundle goes
/// only to the neighbour whose hop runs version 2, never to the one on
/// version 1 (whose refusal of it doesn't stop version 1 bundles going
/// there).
#[tokio::test(flavor = "multi_thread")]
async fn the_planner_sends_bundles_only_over_hops_that_take_their_format() {
    use super::dtn::{BundleFormat, KIND_SPACE_SYNC};
    let net = MemNet::new(1, PathKind::Bluetooth);
    let a = versioned(Protocol::default(), &net).await;
    let b = versioned(Protocol::default(), &net).await;
    let old = versioned(Protocol { version: WIRE_V1, caps: Caps::NONE }, &net).await;
    neighbours(&net, &a, &b).await;
    neighbours(&net, &a, &old).await;
    assert_eq!(a.mesh.neighbour_protocol(&old.keys.sign_pk()).map(|p| p.version), Some(WIRE_V1));
    let far = DeviceKeys::generate().sign_pk(); // the destination, out of range
    let lifetime = Duration::from_secs(600);
    let v2 = a.mesh.send_bundle_as(far, BundleFormat::v2(KIND_SPACE_SYNC), b"version 2".to_vec().into(), lifetime);
    let v2 = v2.unwrap();
    eventually("the version 2 neighbour carries the version 2 bundle", || b.mesh.holds_bundle(&v2)).await;
    let v1 = a.mesh.send_bundle(far, b"version 1".to_vec().into(), lifetime).unwrap();
    eventually("both neighbours carry the version 1 bundle", || b.mesh.holds_bundle(&v1) && old.mesh.holds_bundle(&v1))
        .await;
    // the planner has run many times since: the version 1 hop never got it
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!old.mesh.holds_bundle(&v2), "a version 2 bundle reached a version 1 carrier");
    assert_eq!(old.mesh.dtn_stats().refused, 0, "nor was it offered there (it would refuse the signature)");
}

/// The queue management on a hop ([`super::Aqm`]), on a fake clock: a brief
/// or short queue gets no drops; a standing one gets its first drop after
/// an interval and then more, faster; a queue the drops don't drain (not
/// ours) is taken as the base instead of starving our traffic; and a slow
/// link is allowed a few packets' time of queue.
#[test]
fn hop_queue_management_drops_only_for_a_standing_queue() {
    use super::Aqm;
    let ms = Duration::from_millis;
    let t0 = Instant::now();
    let mut q = Aqm::new(t0);
    q.rate = 400_000.0; // 20 ms target, 100 ms interval
    assert!(!q.drop_now(ms(5), t0), "base 5 ms");
    // 15 ms of queue for a second, or 200 ms of it for half an interval
    assert!((1..=100).all(|i| !q.drop_now(ms(20), t0 + ms(10 * i))));
    assert!((1..=9).all(|i| !q.drop_now(ms(205), t0 + ms(1000 + 5 * i))));
    assert!(!q.drop_now(ms(10), t0 + ms(1050)));

    // 50 ms of queue that stays: a drop after an interval, then closer ones
    let start = t0 + ms(1100);
    let drops: Vec<u64> = (0..100).filter(|i| q.drop_now(ms(55), start + ms(5 * i))).map(|i| 5 * i).collect();
    assert_eq!(drops.first(), Some(&100), "{drops:?}");
    assert!(drops.len() >= 5, "{drops:?}");
    let gaps: Vec<u64> = drops.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.windows(2).all(|g| g[1] <= g[0]), "drops come faster: {drops:?}");

    // it doesn't drain: someone else's queue. After a second, no more drops
    // at that delay; it is the base now.
    let later = start + ms(1200);
    assert!((0..400).filter(|i| q.drop_now(ms(55), later + ms(5 * i))).count() <= 1);
    assert!(q.base.is_some_and(|b| b >= ms(50)), "{:?}", q.base);
    // ... and the base comes back down once it does drain
    assert!(!q.drop_now(ms(6), later + ms(2100)));
    assert_eq!(q.base, Some(ms(6)));

    // a burst that the drops do drain, a quarter every half second: they
    // go on until it's gone, and the base stays
    let mut d = Aqm::new(t0);
    d.rate = 400_000.0;
    assert!(!d.drop_now(ms(5), t0));
    let mut rtt = 300.0_f64;
    let mut dropped = 0;
    for i in 1..=600 {
        dropped += d.drop_now(Duration::from_secs_f64(rtt / 1000.0), t0 + ms(5 * i)) as u32;
        rtt = (rtt * 0.9971).max(5.0); // -25% per 100 steps (0.5 s)
    }
    assert!(dropped >= 10, "{dropped} drops");
    assert!(d.base.is_some_and(|b| b < ms(6)), "{:?}", d.base);

    // a 20 kB/s link: three packets' time of queue (180 ms) is fine
    let mut slow = Aqm::new(t0);
    slow.rate = 20_000.0;
    assert!(!slow.drop_now(ms(10), t0));
    assert!((1..=300).all(|i| !slow.drop_now(ms(160), t0 + ms(10 * i))));
}

/// The store-and-forward stream lengths the tier-2 simulator charges
/// (`mycel-sim`) are the encoders' own, on random summaries, offers and
/// answers; the borrowed summary encoding still decodes.
#[test]
fn stream_lengths_match_the_encoders() {
    use super::dtn::{Answer, BundleFormat, Offer, Receipt, Summary};
    use super::{
        BUNDLE_VERDICT_LEN, STREAM_FRAME_PREFIX, WireAnswer, answer_stream_len, decode_summary, encode_offer,
        encode_summary, offer_stream_len, summary_stream_len,
    };
    use mycel_crypto::{Hash32, Sig, SignPk};
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut below = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n.max(1)
    };
    for _ in 0..300 {
        let s = Summary {
            full: below(2) == 1,
            ids: (0..below(600)).map(|i| Hash32([i as u8; 32])).collect(),
            receipts: (0..below(300))
                .map(|i| Receipt { id: Hash32([i as u8; 32]), dst: SignPk([1; 32]), sig: Sig([2; 64]) })
                .collect(),
            preds: (0..below(80)).map(|i| (SignPk([i as u8; 32]), i as f32 / 80.0)).collect(),
            free: below(1 << 40),
            evictable: (0..below(40)).map(|i| (i * 1_000_003, i << 20)).collect(),
            wants: (0..below(20)).map(|i| SignPk([i as u8; 32])).collect(),
        };
        let body = encode_summary(s.clone()).unwrap();
        assert_eq!(summary_stream_len(&s), Some(1 + body.len()));
        assert_eq!(decode_summary(&body).unwrap(), s);
        let o = Offer {
            format: if below(2) == 1 { BundleFormat::V1 } else { BundleFormat::v2(below(70_000) as u16) },
            id: Hash32([3; 32]),
            src: SignPk([4; 32]),
            dst: SignPk([5; 32]),
            size: below(1 << 30),
            created: 1_700_000_000_000 + below(1 << 40),
            lifetime: below(1 << 34),
            copies: below(256) as u8,
            sig: Sig([6; 64]),
        };
        for v in [WIRE_V1, WIRE_V2] {
            let want = encode_offer(v, &o).unwrap().map(|m| STREAM_FRAME_PREFIX + m.len());
            assert_eq!(offer_stream_len(v, &o), want);
        }
        for a in [Answer::Take { from: below(1 << 40) }, Answer::Duplicate, Answer::Refuse("store full")] {
            let body = crate::wire::encode_bounded(&WireAnswer::from(a), 64).unwrap();
            assert_eq!(answer_stream_len(a), STREAM_FRAME_PREFIX + body.len());
        }
    }
    assert_eq!(BUNDLE_VERDICT_LEN, 1);
}
