//! Custody's pure parts: parcels, stamps, the custodian's limits,
//! selection, the directory and the sender's record.

use super::*;
use mycel_crypto::DeviceKeys;

const NOW: u64 = 1_800_000_000_000;

fn keys() -> DeviceKeys {
    DeviceKeys::generate()
}

fn parcel_for(from: &DeviceKeys, to: &DeviceKeys, payload: Vec<u8>) -> (Parcel, [u8; 32]) {
    seal(from, to.sign_pk(), &to.public().kex_pk, 1, payload, DEFAULT_LIFETIME_MS, NOW).unwrap()
}

fn known(k: SignPk) -> Depositor {
    Depositor { key: k, origin: Origin::Ip([1; 16]), known: true }
}

fn pk(b: u8) -> SignPk {
    SignPk([b; 32])
}

#[test]
fn parcels_open_only_for_their_recipient_and_hide_the_sender() {
    let (a, b, c) = (keys(), keys(), keys());
    let (p, _) = parcel_for(&a, &b, b"hello".to_vec());
    // nothing on the outside names the sender
    let bytes = postcard::to_allocvec(&p).unwrap();
    assert!(!bytes.windows(32).any(|w| w == a.sign_pk().0), "the sender's key is not in the clear");
    let o = open(&b, &p).unwrap();
    assert_eq!(o, Opened { src: a.sign_pk(), kind: 1, payload: b"hello".to_vec() });
    assert!(open(&c, &p).is_err(), "someone else can't open it");
    // a custodian can't change the header: the seal binds it
    let mut q = p.clone();
    q.lifetime += 1;
    assert_ne!(q.id(), p.id());
    assert!(open(&b, &q).is_err());
    // nor re-address it
    let mut r = p.clone();
    r.dst = c.sign_pk();
    assert!(open(&c, &r).is_err());
    // a newer format is refused with a typed error
    let mut v = p.clone();
    v.version = 2;
    assert!(open(&b, &v).unwrap_err().downcast_ref::<crate::VersionError>().is_some());
    // created is rounded to the minute
    assert_eq!(p.created % 60_000, 0);
}

#[test]
fn parcels_are_padded_to_size_classes() {
    let (a, b) = (keys(), keys());
    let sizes: Vec<u64> = (1000..1100).map(|n| parcel_for(&a, &b, vec![7; n]).0.size()).collect();
    let classes: BTreeSet<u64> = sizes.iter().copied().collect();
    assert!(classes.len() <= 3, "100 lengths fall in a few classes: {classes:?}");
    for n in [0usize, 1, 2, 100, 1000, 65_536, 200_000] {
        assert!(padme(n) >= n && padme(n) as f64 <= n as f64 * 1.12 + 2.0);
    }
}

#[test]
fn stamps_bind_parcel_and_custodian() {
    let id = Hash32::digest("t", b"x");
    let s = mint(&id, &pk(1), 10);
    assert!(stamp_ok(&id, &pk(1), s, 10));
    let reused = (0..20).filter(|_| stamp_ok(&id, &pk(2), mint(&id, &pk(1), 12), 12)).count();
    assert!(reused <= 1, "bound to the custodian: {reused} of 20 also good elsewhere");
    let other = Hash32::digest("t", b"y");
    // a stamp for one parcel is (almost surely) worthless for another
    let wrong = (0..20).filter(|_| stamp_ok(&other, &pk(1), mint(&id, &pk(1), 12), 12)).count();
    assert!(wrong <= 1);
    assert!(stamp_ok(&id, &pk(1), 0, 0), "0 bits is free");
}

#[test]
fn a_custodian_stores_delivers_only_to_the_recipient_and_drops_on_receipt() {
    let (a, b, c, eve) = (keys(), keys(), keys(), keys());
    let mut v = Vault::new(VaultConfig::default());
    let (p, secret) = parcel_for(&a, &b, b"m1".to_vec());
    let id = p.id();
    assert_eq!(v.deposit(&known(a.sign_pk()), p.clone(), 0, &c.sign_pk(), NOW), Deposit::Stored);
    assert_eq!(v.deposit(&known(a.sign_pk()), p.clone(), 0, &c.sign_pk(), NOW), Deposit::Duplicate);
    // nobody but the recipient sees or takes it
    assert!(v.listing(&eve.sign_pk(), 64).is_empty());
    assert!(v.take(&eve.sign_pk(), &[id], u64::MAX).is_empty());
    assert_eq!(v.listing(&b.sign_pk(), 64), vec![(id, p.size() as u32)]);
    assert_eq!(v.take(&b.sign_pk(), &[id], u64::MAX), vec![p.clone()]);
    // a receipt signed by someone else, or for someone else, does nothing
    assert!(!v.receipt(&b.sign_pk(), &Receipt::sign(&eve, id)));
    assert!(!v.receipt(&eve.sign_pk(), &Receipt::sign(&eve, id)));
    assert!(v.holds(&id));
    // a wrong secret doesn't withdraw it
    assert!(!v.release(&id, &[0; 32]));
    assert!(v.receipt(&b.sign_pk(), &Receipt::sign(&b, id)));
    assert!(!v.holds(&id) && !v.has_mail(&b.sign_pk()));
    // a delivered parcel deposited again is a duplicate, not stored again
    assert_eq!(v.deposit(&known(a.sign_pk()), p, 0, &c.sign_pk(), NOW), Deposit::Duplicate);
    assert!(!v.holds(&id));
    // the sender's secret withdraws another
    let (q, s2) = parcel_for(&a, &b, b"m2".to_vec());
    v.deposit(&known(a.sign_pk()), q.clone(), 0, &c.sign_pk(), NOW);
    assert!(v.release(&q.id(), &s2) && !v.holds(&q.id()));
    let _ = secret;
    v.check().unwrap();
}

#[test]
fn strangers_need_a_stamp_and_known_devices_do_not() {
    let (a, b, c) = (keys(), keys(), keys());
    let mut v = Vault::new(VaultConfig { stamp_bits: 8, ..Default::default() });
    let stranger = Depositor { key: a.sign_pk(), origin: Origin::Ip([2; 16]), known: false };
    let (p, _) = parcel_for(&a, &b, b"x".to_vec());
    assert_eq!(v.deposit(&stranger, p.clone(), 0, &c.sign_pk(), NOW), Deposit::Refused(Refusal::NoStamp));
    let stamp = mint(&p.id(), &c.sign_pk(), 8);
    assert_eq!(v.deposit(&stranger, p.clone(), stamp, &c.sign_pk(), NOW), Deposit::Stored);
    let (q, _) = parcel_for(&a, &b, b"y".to_vec());
    // a stamp minted for another custodian doesn't count here
    let elsewhere = (0..64).map(|_| mint(&q.id(), &pk(9), 8)).find(|s| !stamp_ok(&q.id(), &c.sign_pk(), *s, 8));
    if let Some(s) = elsewhere {
        assert_eq!(v.deposit(&stranger, q.clone(), s, &c.sign_pk(), NOW), Deposit::Refused(Refusal::NoStamp));
    }
    assert_eq!(v.deposit(&known(a.sign_pk()), q, 0, &c.sign_pk(), NOW), Deposit::Stored);
}

#[test]
fn malformed_expired_oversized_and_off_are_refused() {
    let (a, b, c) = (keys(), keys(), keys());
    let me = c.sign_pk();
    let mut v = Vault::new(VaultConfig { max_parcel: 4096, ..Default::default() });
    let (big, _) = parcel_for(&a, &b, vec![1; 8000]);
    assert_eq!(v.deposit(&known(a.sign_pk()), big, 0, &me, NOW), Deposit::Refused(Refusal::TooBig));
    let (p, _) = parcel_for(&a, &b, b"x".to_vec());
    assert_eq!(
        v.deposit(&known(a.sign_pk()), p.clone(), 0, &me, p.expires() + 1),
        Deposit::Refused(Refusal::Expired)
    );
    assert_eq!(
        v.deposit(&known(a.sign_pk()), p.clone(), 0, &me, NOW - 3600 * 1000),
        Deposit::Refused(Refusal::Malformed),
        "created an hour in the future"
    );
    let (to_me, _) = parcel_for(&a, &c, b"x".to_vec());
    assert_eq!(v.deposit(&known(a.sign_pk()), to_me, 0, &me, NOW), Deposit::Refused(Refusal::Malformed));
    let mut newer = p.clone();
    newer.version = 9;
    assert_eq!(v.deposit(&known(a.sign_pk()), newer, 0, &me, NOW), Deposit::Refused(Refusal::Unsupported));
    v.set_serving(false);
    assert_eq!(v.deposit(&known(a.sign_pk()), p.clone(), 0, &me, NOW), Deposit::Refused(Refusal::NotServing));
    v.set_serving(true);
    assert_eq!(v.deposit(&known(a.sign_pk()), p.clone(), 0, &me, NOW), Deposit::Stored);
    // lifetimes are capped from arrival, and expire
    v.tick(p.expires() - 1);
    assert!(v.holds(&p.id()));
    v.tick(p.expires());
    assert!(!v.holds(&p.id()));
    assert_eq!(v.stats().expired, 1);
    v.check().unwrap();
}

/// A spammer (one key, one address) fills its share and is cut off; an
/// honest depositor still gets in; a flood from fresh keys on one address
/// hits the address's share; rate limits stop bursts.
#[test]
fn a_spammer_is_cut_off_by_its_shares_and_rate() {
    let (spam, honest, b, c) = (keys(), keys(), keys(), keys());
    let me = c.sign_pk();
    let cfg = VaultConfig {
        stamp_bits: 0,
        per_depositor: 64 << 10,
        per_origin: 256 << 10,
        per_recipient: 1 << 20,
        depositor_burst: 1000,
        origin_burst: 1000,
        ..Default::default()
    };
    let mut v = Vault::new(cfg);
    let s = Depositor { key: spam.sign_pk(), origin: Origin::Ip([6; 16]), known: false };
    let mut stored = 0;
    let mut refused = None;
    for i in 0..200u32 {
        let (p, _) = parcel_for(&spam, &b, vec![i as u8; 4000 + i as usize]);
        match v.deposit(&s, p, 0, &me, NOW) {
            Deposit::Stored => stored += 1,
            Deposit::Refused(r) => {
                refused = Some(r);
                break;
            }
            Deposit::Duplicate => {}
        }
    }
    assert_eq!(refused, Some(Refusal::DepositorShare));
    assert!(stored * 4000 <= 64 << 10, "{stored} stored");
    // the honest depositor is unaffected
    let (p, _) = parcel_for(&honest, &b, b"hi".to_vec());
    let h = Depositor { key: honest.sign_pk(), origin: Origin::Ip([7; 16]), known: false };
    assert_eq!(v.deposit(&h, p, 0, &me, NOW), Deposit::Stored);
    // fresh keys from the same address hit the address's share
    let mut origin_cut = false;
    for _ in 0..200 {
        let k = keys();
        let (p, _) = parcel_for(&k, &b, vec![1; 16_000]);
        let d = Depositor { key: k.sign_pk(), origin: Origin::Ip([6; 16]), known: false };
        if v.deposit(&d, p, 0, &me, NOW) == Deposit::Refused(Refusal::OriginShare) {
            origin_cut = true;
            break;
        }
    }
    assert!(origin_cut);
    // a burst over the rate is refused, and refilled later
    let mut v = Vault::new(VaultConfig { stamp_bits: 0, depositor_burst: 3, depositor_every_ms: 1000, ..Default::default() });
    let d = known(spam.sign_pk());
    let answers: Vec<Deposit> =
        (0..5).map(|i| v.deposit(&d, parcel_for(&spam, &b, vec![i; 10]).0, 0, &me, NOW)).collect();
    assert_eq!(answers.iter().filter(|a| **a == Deposit::Stored).count(), 3);
    assert_eq!(answers[4], Deposit::Refused(Refusal::RateLimited));
    assert_eq!(v.deposit(&d, parcel_for(&spam, &b, vec![9; 10]).0, 0, &me, NOW + 1000), Deposit::Stored);
    v.check().unwrap();
}

#[test]
fn a_full_store_evicts_from_the_biggest_depositor_only() {
    let (big, small, b, b2, c) = (keys(), keys(), keys(), keys(), keys());
    let me = c.sign_pk();
    let cfg = VaultConfig {
        capacity: 200 << 10,
        per_depositor: 1 << 20,
        per_recipient: 1 << 20,
        per_origin: 1 << 20,
        stamp_bits: 0,
        depositor_burst: 1000,
        origin_burst: 1000,
        ..Default::default()
    };
    let mut v = Vault::new(cfg);
    let dbig = Depositor { key: big.sign_pk(), origin: Origin::Ip([1; 16]), known: false };
    let dsmall = Depositor { key: small.sign_pk(), origin: Origin::Ip([2; 16]), known: false };
    let mut i = 0u8;
    while v.deposit(&dbig, parcel_for(&big, &b, vec![i; 20_000]).0, 0, &me, NOW) == Deposit::Stored {
        i += 1;
    }
    assert_eq!(v.deposit(&dbig, parcel_for(&big, &b, vec![99; 20_000]).0, 0, &me, NOW), Deposit::Refused(Refusal::Full));
    // the small depositor gets in by evicting the big one's parcels
    for k in 0..3u8 {
        assert_eq!(v.deposit(&dsmall, parcel_for(&small, &b2, vec![k; 20_000]).0, 0, &me, NOW), Deposit::Stored);
    }
    assert!(v.stats().evicted >= 3);
    assert_eq!(v.listing(&b2.sign_pk(), 64).len(), 3);
    v.check().unwrap();
}

#[test]
fn selection_prefers_own_devices_then_co_members_then_closest_volunteers() {
    let dst = pk(0x80);
    let me = pk(1);
    let own = [pk(10), pk(11)];
    let shares = [pk(20), dst, me, pk(10)];
    let mut vol = [pk(0x81), pk(0xff), pk(0x00), pk(0x90)];
    let online = |k: &SignPk| *k == pk(11);
    let got = select(&dst, &me, &own, &shares, &vol, &online, 16);
    let keys: Vec<SignPk> = got.iter().map(|x| x.0).collect();
    assert_eq!(got[0], (pk(11), Tier::Own), "an online own device first");
    assert_eq!(got[1], (pk(10), Tier::Own));
    assert_eq!(got[2], (pk(20), Tier::Shares));
    assert_eq!(&keys[3..], &[pk(0x81), pk(0x90), pk(0xff), pk(0x00)], "volunteers by XOR distance");
    assert!(!keys.contains(&dst) && !keys.contains(&me));
    assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), keys.len(), "nobody twice");
    // the order of volunteers doesn't depend on how they were listed
    vol.reverse();
    assert_eq!(select(&dst, &me, &own, &shares, &vol, &online, 16), got);
    assert_eq!(select(&dst, &me, &own, &shares, &vol, &online, 2).len(), 2);
}

#[test]
fn the_directory_keeps_buckets_small_and_old_entries() {
    let me = SignPk([0; 32]);
    let mut d = Directory::new(me);
    // 100 keys in the far half: one bucket of 16
    for i in 0..100u8 {
        let mut k = [0u8; 32];
        k[0] = 0x80 | (i & 0x7f);
        k[1] = i;
        d.add(SignPk(k), NOW);
    }
    assert_eq!(d.len(), BUCKET);
    // a newcomer doesn't flush a live entry; it replaces a stale one
    let mut fresh = [0u8; 32];
    fresh[0] = 0xc0;
    fresh[5] = 1;
    d.add(SignPk(fresh), NOW + 1);
    assert!(!d.contains(&SignPk(fresh)));
    d.add(SignPk(fresh), NOW + STALE_MS + 1);
    assert!(d.contains(&SignPk(fresh)) && d.len() == BUCKET);
    // closest by XOR to a target
    let target = SignPk(fresh);
    assert_eq!(d.closest(&target, 1), vec![target]);
    d.add(me, NOW);
    assert!(!d.contains(&me));
}

#[test]
fn the_outbox_tracks_custody_coverage_and_release() {
    let mut o = Outbox::default();
    let (dst, space) = (pk(2), Hash32::digest("s", b"1"));
    let (e1, e2, op) = (Hash32::digest("e", b"1"), Hash32::digest("e", b"2"), Hash32::digest("o", b"1"));
    let p1 = Hash32::digest("p", b"1");
    let d = |envs: Vec<Hash32>| Deposited {
        dst,
        space,
        envelopes: envs,
        ops: vec![op],
        secret: [1; 32],
        custodians: vec![],
        until: NOW + 1000,
        pending: true,
    };
    o.add(p1, d(vec![e1]));
    assert!(o.covered(&dst, &space).contains(&e1) && o.covered(&dst, &space).contains(&op));
    assert_eq!(o.custodians_of(&e1).len(), 0);
    assert!(o.ack(&p1, pk(7)) && !o.ack(&p1, pk(7)) && o.ack(&p1, pk(8)));
    o.settle(&p1);
    assert_eq!(o.custodians_of(&e1).len(), 2);
    // a parcel nobody took is forgotten: its items go in the next one
    let p2 = Hash32::digest("p", b"2");
    o.add(p2, d(vec![e2]));
    o.settle(&p2);
    assert!(!o.covered(&dst, &space).contains(&e2) && o.get(&p2).is_none());
    // a live sync releases the rest
    let done = o.delivered(&dst, &space);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].1.custodians, vec![pk(7), pk(8)]);
    assert!(o.is_empty() && o.custodians_of(&e1).is_empty());
    o.add(p1, d(vec![e1]));
    o.expire(NOW + 1000);
    assert!(o.is_empty());
}

#[test]
fn origins_group_addresses() {
    use std::net::IpAddr;
    let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
    let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
    let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
    assert_eq!(Origin::of_ip(a), Origin::of_ip(b), "one /64");
    assert_ne!(Origin::of_ip(a), Origin::of_ip(c));
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
    assert_eq!(Origin::of_ip(v4), Origin::of_ip(mapped));
}

#[test]
fn wire_messages_round_trip() {
    let (a, b) = (keys(), keys());
    let (p, _) = parcel_for(&a, &b, b"x".to_vec());
    let msgs = vec![
        Msg::Deposit { parcel: p.clone(), stamp: 7 },
        Msg::Deposited(Deposit::Refused(Refusal::Full)),
        Msg::Fetch,
        Msg::Listing { items: vec![(p.id(), 3)] },
        Msg::Take { want: vec![p.id()], receipts: vec![Receipt::sign(&b, p.id())] },
        Msg::Parcels { parcels: vec![p] },
        Msg::Find { target: pk(3) },
        Msg::Found { custodians: vec![pk(4)] },
    ];
    for m in msgs {
        let bytes = postcard::to_allocvec(&m).unwrap();
        let back: Msg = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(format!("{m:?}"), format!("{back:?}"));
    }
}
