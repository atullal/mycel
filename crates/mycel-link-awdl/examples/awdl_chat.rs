//! Chat between two Macs over peer-to-peer Wi-Fi only (no IP transports).
//!
//! ```text
//! awdl_chat <name> [--invite] [--once] [--big]
//! ```
//!
//! Starts a Mycel node whose *only* transport is the AWDL link (`ip = false`),
//! prints every device it discovers and which path it is reached over.
//! With `--invite`, the first device found gets a new shared space with a
//! greeting in it; the other side answers in the same document, so the doc
//! syncs both ways. Lines typed on stdin are added to the doc as messages.
//! `--once` exits (status 0) as soon as the two-way sync is confirmed.
//! `--big` (both sides) then also pushes a 300 KB message, to exercise
//! full-size QUIC packets and congestion control on the link.
//!
//! Single-Mac test (two processes, any interface instead of AWDL only):
//! ```text
//! MYCEL_AWDL_ANY_INTERFACE=1 cargo run -p mycel-link-awdl --example awdl_chat -- bob
//! MYCEL_AWDL_ANY_INTERFACE=1 cargo run -p mycel-link-awdl --example awdl_chat -- alice --invite
//! ```
//! `MYCEL_AWDL_DEBUG=1` logs the link's discovery and flows.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use mycel_crypto::{DeviceKeys, SignPk};
use mycel_net::{NetEvent, NetMode, Node, NodeOptions, PathKind};
use mycel_sync::automerge::{ROOT, transaction::Transactable};
use mycel_trust::{Role, SpaceId};
use tokio::io::AsyncBufReadExt;

fn peers_line(node: &Node) -> String {
    let mut out: Vec<String> = node
        .peers()
        .iter()
        .filter(|(_, p)| !p.links.is_empty() || p.via.is_some())
        .map(|(pk, p)| {
            let links: Vec<&str> = p.links.iter().map(|k| k.label()).collect();
            format!(
                "{} ({}) links=[{}] via={}",
                p.name.as_deref().unwrap_or("?"),
                pk.short(),
                links.join(", "),
                p.via.map(|v| v.label()).unwrap_or("-")
            )
        })
        .collect();
    out.sort();
    if out.is_empty() {
        "none".into()
    } else {
        out.join("; ")
    }
}

fn first_link_peer(node: &Node) -> Option<SignPk> {
    node.peers()
        .into_iter()
        .find(|(_, p)| p.links.contains(&PathKind::PeerWifi))
        .map(|(pk, _)| pk)
}

/// Every `key → text` in every doc of the space.
fn messages(node: &Node, space: &SpaceId) -> Vec<(String, String)> {
    node.with_space(space, |r| {
        let mut out = Vec::new();
        for d in r.doc_ids() {
            if let serde_json::Value::Object(m) = r.doc_json(&d) {
                for (k, v) in m {
                    out.push((k, v.as_str().unwrap_or_default().to_string()));
                }
            }
        }
        out
    })
    .unwrap_or_default()
}

fn post(node: &Node, space: &SpaceId, key: &str, text: &str) -> anyhow::Result<()> {
    let doc = node
        .with_space(space, |r| r.doc_ids().into_iter().next())?
        .unwrap_or_else(mycel_sync::Replica::new_doc_id);
    node.with_space(space, |r| r.change(doc, |d| d.put(ROOT, key, text)))??;
    node.changed(*space);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(name) = args.iter().find(|a| !a.starts_with("--")).cloned() else {
        eprintln!("usage: awdl_chat <name> [--invite] [--once] [--big]");
        std::process::exit(2);
    };
    let invite = args.iter().any(|a| a == "--invite");
    let once = args.iter().any(|a| a == "--once");
    let big = args.iter().any(|a| a == "--big");

    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Lan, name.clone());
    opts.ip = false; // every packet goes over the AWDL link
    opts.links = vec![mycel_link_awdl::link(keys.sign_pk(), &name)];
    let node = Node::spawn(keys, opts).await?;
    println!(
        "[{name}] started as {} (ip transports off)",
        node.id().short()
    );
    let mut events = node.subscribe();

    let mut status = String::new();
    let mut peers = String::new();
    let mut space: Option<SpaceId> = None;
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut got_reply = false;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut stdin_open = true;
    let mut sent = 0u32;
    let me_key = format!("{name}:hello");

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            ev = events.recv() => {
                match ev {
                    Ok(NetEvent::SpaceAdded { space: s, from }) => {
                        println!("[{name}] invited to space {s} by {}", from.short());
                        space = Some(s);
                        node.sync_with(from, s, true).await?;
                        post(&node, &s, &me_key, &format!("hi from {name}, over peer-to-peer Wi-Fi"))?;
                        let stats = node.sync_with(from, s, false).await?;
                        println!("[{name}] replied and synced back ({stats:?})");
                        if once {
                            print_msgs(&name, &node, &s, &mut seen);
                            // let the inviter pull too (and push the big one), then leave
                            for _ in 0..(if big { 60 } else { 6 }) {
                                if big && messages(&node, &s).iter().any(|(k, _)| k.ends_with(":big")) {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                            print_msgs(&name, &node, &s, &mut seen);
                            report_and_exit(&name, &node).await;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(e) => anyhow::bail!(e),
                }
            }
            line = stdin.next_line(), if stdin_open => {
                match line {
                    Ok(Some(l)) if !l.trim().is_empty() => {
                        if let Some(s) = space {
                            sent += 1;
                            post(&node, &s, &format!("{name}:{sent}"), l.trim())?;
                        } else {
                            println!("[{name}] (no shared space yet)");
                        }
                    }
                    Ok(Some(_)) => {}
                    _ => stdin_open = false,
                }
            }
        }

        let st = format!("{:?}", node.link_status());
        if st != status {
            println!("[{name}] link status: {st}");
            status = st;
        }
        let p = peers_line(&node);
        if p != peers {
            println!("[{name}] peers: {p}");
            peers = p;
        }

        if invite
            && space.is_none()
            && let Some(peer) = first_link_peer(&node)
        {
            let (s, _genesis) = node.create_space()?;
            let card = node.fetch_card(peer).await?;
            node.with_space(&s, |r| r.add_member(card.keys, Role::Writer))??;
            post(&node, &s, &me_key, &format!("hello from {name}"))?;
            let stats = node.sync_with(peer, s, false).await?;
            println!(
                "[{name}] created space {s}, invited {} ({stats:?})",
                peer.short()
            );
            space = Some(s);
        }

        if let Some(s) = space {
            print_msgs(&name, &node, &s, &mut seen);
            if invite
                && !got_reply
                && seen
                    .iter()
                    .any(|(k, _)| k.ends_with(":hello") && *k != me_key)
            {
                got_reply = true;
                println!("[{name}] TWO-WAY SYNC OK: my greeting went out and the reply came back");
                if big && let Some(peer) = first_link_peer(&node) {
                    let t = std::time::Instant::now();
                    post(&node, &s, &format!("{name}:big"), &noise(300_000))?;
                    node.sync_with(peer, s, false).await?;
                    println!("[{name}] pushed a 300 KB message in {:?}", t.elapsed());
                }
                if once {
                    report_and_exit(&name, &node).await;
                }
            }
        }
    }
}

/// Incompressible text (so the bytes really cross the link).
fn noise(len: usize) -> String {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ std::process::id() as u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(b"0123456789abcdef"[(x & 15) as usize])
        })
        .collect()
}

fn print_msgs(name: &str, node: &Node, s: &SpaceId, seen: &mut BTreeSet<(String, String)>) {
    for m in messages(node, s) {
        if seen.insert(m.clone()) {
            if m.1.len() > 80 {
                println!("[{name}] doc: {} = <{} bytes>", m.0, m.1.len());
            } else {
                println!("[{name}] doc: {} = {:?}", m.0, m.1);
            }
        }
    }
}

async fn report_and_exit(name: &str, node: &Node) -> ! {
    println!("[{name}] final peers: {}", peers_line(node));
    println!("[{name}] final link status: {:?}", node.link_status());
    let _ = node.shutdown().await;
    std::process::exit(0);
}
