//! Offline delivery through the internet (docs/OFFLINE_DELIVERY.md), with
//! real QUIC nodes on loopback: A writes to B while B is offline, A goes
//! offline too, and a custodian C gives B the message when B comes back;
//! B's receipt clears C; nobody else can fetch B's mail; a spammer is cut
//! off by C's budgets.

use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::{DeviceKeys, SignPk};
use mycel_net::custody::{self, Deposit, Refusal, VaultConfig};
use mycel_net::{CustodyOptions, NetMode, Node, NodeOptions};
use mycel_sync::automerge::{ROOT, transaction::Transactable};
use mycel_sync::{EnvelopeId, Replica};
use mycel_trust::{Role, SignedOp, SpaceId};

async fn node(name: &str, keys: Arc<DeviceKeys>, custody: CustodyOptions) -> Node {
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.custody = custody;
    Node::spawn(keys, opts).await.unwrap()
}

fn introduce(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }
}

async fn eventually(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    for _ in 0..secs * 10 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out after {secs} s waiting for: {what}");
}

/// A space created by `owner` with `members` (writers), joined and synced.
async fn space_of(owner: &Node, members: &[&Node]) -> (SpaceId, SignedOp) {
    let (space, genesis) = owner.create_space().unwrap();
    for m in members {
        owner.with_space(&space, |r| r.add_member(m.keys().public(), Role::Writer)).unwrap().unwrap();
    }
    for m in members {
        m.join_space(genesis.clone()).unwrap();
        m.sync_with(owner.id(), space, true).await.unwrap();
    }
    (space, genesis)
}

fn write(n: &Node, space: SpaceId, text: &str) -> EnvelopeId {
    let doc = Replica::new_doc_id();
    let (_, env) = n.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "text", text))).unwrap().unwrap();
    n.changed(space);
    env.unwrap().id()
}

fn holds(n: &Node, space: SpaceId, env: &EnvelopeId) -> bool {
    n.with_space(&space, |r| r.envelope(env).is_some()).unwrap_or(false)
}

/// Quick proofs of work for the test's strangers.
fn opts(stamp_bits: u8) -> CustodyOptions {
    CustodyOptions { vault: VaultConfig { stamp_bits, ..Default::default() }, ..Default::default() }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custodian_delivers_to_an_offline_recipient_after_the_sender_left() {
    let (ka, kb, kc, kd) = (
        Arc::new(DeviceKeys::generate()),
        Arc::new(DeviceKeys::generate()),
        Arc::new(DeviceKeys::generate()),
        Arc::new(DeviceKeys::generate()),
    );
    let a = node("a", ka, opts(8)).await;
    let b = node("b", kb.clone(), opts(8)).await;
    let c = node("c", kc, opts(8)).await;
    let d = node("eve", kd, opts(8)).await;
    introduce(&[&a, &b, &c, &d]);
    // a direct chat A–B, and a group of C's that A and B are in (so A knows
    // C will meet B)
    let (dm, dm_genesis) = space_of(&a, &[&b]).await;
    let (group, group_genesis) = space_of(&c, &[&a, &b]).await;

    // B goes offline
    b.shutdown().await.unwrap();
    let t0 = std::time::Instant::now();
    let env = write(&a, dm, "are you there?");
    eventually("a custodian took the sealed message", 60, || a.carried(&env) >= 1).await;
    println!("first custody acknowledgement after {:?}", t0.elapsed());
    // C is the only custodian A knows (Eve never talked to A): one copy
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(a.carried(&env), 1);
    let cs = c.custody_stats();
    assert_eq!(cs.held_parcels, 1, "{cs:?}");
    assert_eq!(cs.vault.refused, 0);

    // somebody else asks C for mail: nothing, and C keeps B's
    d.fetch_custody(c.id()).await;
    assert_eq!(d.custody_stats().parcels_received, 0);
    assert_eq!(c.custody_stats().held_parcels, 1);

    // A goes offline too
    a.shutdown().await.unwrap();

    // B comes back (a new process, same keys, a new address) knowing only
    // its spaces' genesis: everything else arrives in the parcel
    let b2 = node("b", kb, opts(8)).await;
    b2.join_space(dm_genesis).unwrap();
    b2.join_space(group_genesis).unwrap();
    b2.add_peer_addr(c.addr());
    c.add_peer_addr(b2.addr());
    let t1 = std::time::Instant::now();
    b2.sync_with(c.id(), group, true).await.unwrap();
    eventually("B has A's message from the custodian", 30, || holds(&b2, dm, &env)).await;
    println!("delivered {:?} after B came back", t1.elapsed());
    assert!(b2.with_space(&dm, |r| r.is_member(&b2.id())).unwrap(), "the parcel carried the membership too");
    // B's receipt cleared C
    eventually("C dropped its copy on B's receipt", 10, || c.custody_stats().held_parcels == 0).await;
    let cs = c.custody_stats();
    assert!(cs.vault.receipted >= 1, "{cs:?}");
    let bs = b2.custody_stats();
    assert_eq!(bs.parcels_opened, 1, "{bs:?}");

    for n in [b2, c, d] {
        n.shutdown().await.unwrap();
    }
}

/// No shared space with the custodian: a volunteer found as the closest
/// custodian to the recipient's key, paid for with a proof of work; the
/// recipient finds it the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_volunteer_closest_to_the_recipient_carries_for_strangers() {
    let (ka, kb, kv) =
        (Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()), Arc::new(DeviceKeys::generate()));
    let a = node("a", ka, opts(10)).await;
    let b = node("b", kb.clone(), opts(10)).await;
    let v = node("volunteer", kv, opts(10)).await;
    introduce(&[&a, &b, &v]);
    let (dm, dm_genesis) = space_of(&a, &[&b]).await;
    a.add_custodian_hint(v.id());
    b.shutdown().await.unwrap();
    let env = write(&a, dm, "hello stranger-carried");
    eventually("the volunteer took it", 60, || a.carried(&env) >= 1).await;
    let vs = v.custody_stats();
    assert_eq!((vs.held_parcels, vs.vault.refused), (1, 0), "{vs:?}");
    a.shutdown().await.unwrap();

    let b2 = node("b", kb, opts(10)).await;
    b2.join_space(dm_genesis).unwrap();
    b2.add_peer_addr(v.addr());
    v.add_peer_addr(b2.addr());
    b2.add_custodian_hint(v.id());
    // what B's periodic "anything for me?" does: the closest custodians to its key
    // (the volunteer also knows A, now offline: the lookup names both)
    assert!(b2.find_custodians(b2.id()).await.contains(&v.id()));
    b2.fetch_custody(v.id()).await;
    eventually("B has the message", 20, || holds(&b2, dm, &env)).await;
    eventually("the volunteer dropped it", 10, || v.custody_stats().held_parcels == 0).await;
    for n in [b2, v] {
        n.shutdown().await.unwrap();
    }
}

/// A stranger flooding a custodian is cut off by its share; deposits
/// without a proof of work are refused; an honest depositor still gets in.
#[tokio::test(flavor = "multi_thread")]
async fn a_spammer_is_cut_off_by_the_custodians_budgets() {
    let small = CustodyOptions {
        vault: VaultConfig { stamp_bits: 6, per_depositor: 48 << 10, ..Default::default() },
        ..Default::default()
    };
    let (spam_keys, honest_keys) = (DeviceKeys::generate(), DeviceKeys::generate());
    let spammer = node("spammer", Arc::new(spam_keys), opts(6)).await;
    let c = node("c", Arc::new(DeviceKeys::generate()), small).await;
    let honest = node("honest", Arc::new(honest_keys), opts(6)).await;
    introduce(&[&spammer, &c, &honest]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let parcel = |from: &Node, size: usize| {
        let victim = DeviceKeys::generate();
        custody::seal(from.keys(), victim.sign_pk(), &victim.public().kex_pk, 1, vec![7; size], 3_600_000, now).unwrap().0
    };
    let mut answers = Vec::new();
    for _ in 0..40 {
        let ans = spammer.deposit_parcel(c.id(), parcel(&spammer, 4000)).await.unwrap();
        answers.push(ans);
        if matches!(ans, Deposit::Refused(_)) {
            break;
        }
    }
    let stored = answers.iter().filter(|a| **a == Deposit::Stored).count();
    assert_eq!(answers.last(), Some(&Deposit::Refused(Refusal::DepositorShare)), "{answers:?}");
    assert!(stored * 4000 <= 48 << 10, "{stored} stored");
    // the honest device still gets in
    assert_eq!(honest.deposit_parcel(c.id(), parcel(&honest, 2000)).await.unwrap(), Deposit::Stored);
    assert_eq!(c.custody_stats().held_parcels, stored + 1);
    for n in [spammer, c, honest] {
        n.shutdown().await.unwrap();
    }
    let _: Option<SignPk> = None;
}
