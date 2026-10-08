//! Two nodes with Iroh's IP transport off find each other with interface
//! beacons and sync over a real network interface, through the link's own
//! per-interface sockets.
//!
//! Runs on the loopback interface by default, so nothing leaves the machine
//! (macOS's `lo0` has `fe80::1` and multicast; Linux's `lo` needs
//! `ip link set lo multicast on`, else the test says so and passes).
//! `MYCEL_IFACE_TEST=en0` runs it over a real interface instead, with a
//! private discovery group and port.

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::DeviceKeys;
use mycel_link_iface::classify::{Decision, Rules, classify};
use mycel_link_iface::{IfaceLink, Options, ifaces};
use mycel_net::link::Link;
use mycel_net::{NetMode, Node, NodeOptions, PathKind};
use mycel_sync::{
    Replica,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use serde_json::json;

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// The interface to test on and the rules that select it, or `None` if this
/// machine has none usable.
fn test_iface(port: u16) -> Option<(String, Options)> {
    let want = std::env::var("MYCEL_IFACE_TEST").ok();
    let all = ifaces::list();
    let name = match &want {
        Some(n) => n.clone(),
        None => all.iter().find(|i| i.loopback)?.name.clone(),
    };
    let rules = Rules { ip_covers_routable: false, loopback: want.is_none(), only: Some(vec![name.clone()]), medium: vec![] };
    let i = all.iter().find(|i| i.name == name)?;
    match classify(i, &rules) {
        Decision::Use { .. } => {}
        Decision::Skip(why) => {
            eprintln!("SKIPPED: {name} is not usable here ({why})");
            return None;
        }
    }
    // a private group and port: never seen by other Mycel nodes nearby
    let group = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0x6d79, 0x7465, 0x7374);
    Some((name, Options { rules, group, port, wifi_direct: false }))
}

async fn iface_node(name: &str, opts: &Options) -> (Node, Arc<IfaceLink>) {
    let keys = Arc::new(DeviceKeys::generate());
    let link = IfaceLink::new(keys.sign_pk(), name, opts.clone());
    let mut nopts = NodeOptions::new(NetMode::Local, name);
    nopts.ip = false;
    nopts.links = vec![link.clone() as Arc<dyn Link>];
    (Node::spawn(keys, nopts).await.unwrap(), link)
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_over_an_interface_with_ip_off() {
    let port = 46_000 + (std::process::id() % 1000) as u16;
    let Some((iface, opts)) = test_iface(port) else { return };
    let (alice, alink) = iface_node("alice", &opts).await;
    let (bob, _blink) = iface_node("bob", &opts).await;

    eventually("bob found over the interface", || {
        alice.peers().get(&bob.id()).is_some_and(|p| !p.links.is_empty() && p.online())
    })
    .await;
    eventually("alice found over the interface", || {
        bob.peers().get(&alice.id()).is_some_and(|p| !p.links.is_empty() && p.online())
    })
    .await;
    let (_, kind, local) = alink.in_use().into_iter().find(|(n, ..)| *n == iface).expect("socket on the interface");
    eprintln!("alice on {iface} ({}) at {local}; peers {:?}", kind.label(), alink.peers().len());

    let (space, genesis) = alice.create_space().unwrap();
    alice.with_space(&space, |r| r.add_member(bob.keys().public(), Role::Writer)).unwrap().unwrap();
    bob.join_space(genesis).unwrap();
    bob.sync_with(alice.id(), space, true).await.unwrap();
    let doc = Replica::new_doc_id();
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "msg", "over a network interface"))).unwrap().unwrap();
    bob.sync_with(alice.id(), space, false).await.unwrap();
    assert_eq!(bob.with_space(&space, |r| r.doc_json(&doc)).unwrap(), json!({"msg": "over a network interface"}));

    let via = bob.peers()[&alice.id()].via;
    assert_eq!(via, Some(kind), "the path is the interface's medium");
    assert_ne!(via, Some(PathKind::Relay));
    let st = alice.link_status();
    assert!(st.iter().any(|s| s.kind == kind && s.active && s.peers == 1 && s.label.as_deref() == Some(&*iface)), "{st:?}");
}
