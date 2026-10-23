//! Chat between two Macs over Bluetooth LE only (no IP at all).
//!
//! ```text
//! ble_chat <name> [--log 0|1|2] [--scan-only]
//! ```
//!
//! Starts a Mycel node whose *only* transport is the Bluetooth link
//! (`ip = false`), prints the radio status, every peer it finds and the path
//! each exchange used. With the first peer found, the device with the lower
//! node key creates a space, invites the other over Bluetooth, and both sync
//! a "chat" doc both ways. Then type lines to send them; `/bench <KiB>` sends
//! a big random value and reports throughput; `/status`; `/quit`.
//!
//! `--scan-only` just starts the link and logs what the radio does (one-Mac
//! smoke test: advertising starts, scanning runs). `MYCEL_BLE_SCAN_ALL=1`
//! also logs every non-Mycel BLE device seen (proves the radio receives).
//!
//! ## Two-Mac test
//!
//! On both Macs (same checkout):
//! 1. `cargo build --release -p mycel-link-ble --example ble_chat`
//! 2. Turn Wi-Fi **off** (Control Center > Wi-Fi) and unplug Ethernet; leave
//!    Bluetooth on. (The node never uses IP anyway; this proves it.)
//! 3. In Terminal: `target/release/examples/ble_chat alice` (other Mac: `bob`).
//!    First run: macOS asks "Allow Terminal to use Bluetooth?" — Allow. (Or
//!    System Settings > Privacy & Security > Bluetooth > enable your terminal.)
//! 4. Within ~10 s each side prints `saw Mycel device …`, `dialing …`,
//!    `connected to … in 1.4 s`, `… is node xxxxxxxx "bob"`, `channel N open`,
//!    `channel N: hello from …`, `linked to …`, then `found …`, the invite, and
//!    `chat doc: {"hello from alice":"hi!","hello from bob":"hi!"}` with
//!    `path: Bluetooth`. (Both sides dial; if both channels come up, both
//!    print `two channels to …: keeping A …, dropping B …` naming the same A.)
//! 5. Type a line on one Mac; it shows up in `chat doc:` on the other.
//!    `/bench 64` reports KiB/s.
//! 6. Optional: carry one laptop out of range — `lost …` — and back —
//!    `linked to …` again within seconds, and chat resumes. Every channel
//!    close is logged with who closed it and why.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::link::{Link, LinkEvent, PathKind};
use mycel_net::{NetEvent, NetMode, Node, NodeOptions};
use mycel_sync::{
    StreamId, StreamKind,
    automerge::{ROOT, transaction::Transactable},
};
use mycel_trust::Role;
use tokio::io::{AsyncBufReadExt, BufReader};

fn short(k: &mycel_crypto::SignPk) -> String {
    k.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut name = None;
    let mut log = 1;
    let mut scan_only_mode = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--log" => log = args.next().and_then(|v| v.parse().ok()).unwrap_or(2),
            "--scan-only" => scan_only_mode = true,
            _ => name = Some(a),
        }
    }
    let name = name.unwrap_or_else(|| "mac".into());
    mycel_link_ble::set_log_level(log);

    let keys = Arc::new(DeviceKeys::generate());
    let me = keys.sign_pk();
    println!("node {} \"{name}\"", short(&me));
    let link = mycel_link_ble::link(me);

    if scan_only_mode {
        return scan_only(link).await;
    }

    let mut opts = NodeOptions::new(NetMode::Lan, &name);
    opts.ip = false; // Bluetooth is the only way out
    opts.links = vec![link.clone()];
    let node = Node::spawn(keys, opts).await?;
    let mut events = node.subscribe();

    // ── wait for the first peer on Bluetooth ──
    let status_every = Duration::from_secs(5);
    let mut last_status = Instant::now() - status_every;
    let peer = loop {
        if last_status.elapsed() >= status_every {
            last_status = Instant::now();
            for s in node.link_status() {
                println!(
                    "status: {} active={} peers={} {}",
                    s.kind.label(),
                    s.active,
                    s.peers,
                    s.detail.unwrap_or_default()
                );
            }
        }
        if let Some((pk, p)) = node.peers().into_iter().find(|(_, p)| p.links.contains(&PathKind::Bluetooth)) {
            println!("found {} \"{}\" on {:?}", short(&pk), p.name.unwrap_or_default(), p.links);
            break pk;
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), events.recv()).await;
    };

    // ── set up a shared space: the lower key invites the other ──
    let chat = StreamId::named(StreamKind::Doc, "ble-chat");
    let t = Instant::now();
    let space = if me < peer {
        let card = node.fetch_card(peer).await?;
        println!("fetched {}'s card over Bluetooth in {:?}", card.name, t.elapsed());
        let (space, _) = node.create_space()?;
        node.with_space(&space, |r| r.add_member(card.keys, Role::Writer))??;
        node.with_space(&space, |r| r.change(chat, |d| d.put(ROOT, format!("hello from {name}"), "hi!").map(|_| ())))??;
        node.sync_with(peer, space, false).await?;
        println!("invited {} and synced in {:?}", card.name, t.elapsed());
        space
    } else {
        println!("waiting for {} to invite us…", short(&peer));
        loop {
            match events.recv().await {
                Ok(NetEvent::SpaceAdded { space, from }) if from == peer => break space,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => anyhow::bail!("node stopped: {e}"),
            }
        }
    };
    node.with_space(&space, |r| r.change(chat, |d| d.put(ROOT, format!("hello from {name}"), "hi!").map(|_| ())))??;
    let t = Instant::now();
    let stats = node.sync_with(peer, space, false).await?;
    println!("synced both ways in {:?} (received {} ops, {} envelopes)", t.elapsed(), stats.ops, stats.envelopes);
    print_doc(&node, &space, &chat);
    print_path(&node, &peer);
    println!("type a message (or /bench <KiB>, /status, /quit)");

    // ── chat ──
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut n = 0u32;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                let line = line.trim().to_string();
                if line == "/quit" { break }
                if line == "/status" {
                    for s in node.link_status() { println!("status: {s:?}"); }
                    print_path(&node, &peer);
                    continue;
                }
                let (key, value) = if let Some(kib) = line.strip_prefix("/bench ") {
                    let kib: usize = kib.trim().parse().unwrap_or(16);
                    // random-ish text so compression can't help
                    let mut x = 0x1234_5678u32;
                    let s: String = (0..kib * 1024).map(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; (b'a' + (x % 26) as u8) as char }).collect();
                    (format!("bench-{name}"), s)
                } else {
                    n += 1;
                    (format!("{name}-{n:03}"), line)
                };
                let size = value.len();
                node.with_space(&space, |r| r.change(chat, |d| d.put(ROOT, key.as_str(), value).map(|_| ())))??;
                let t = Instant::now();
                match node.sync_with(peer, space, false).await {
                    Ok(_) => {
                        let el = t.elapsed();
                        print!("sent {key} ({size} B) in {el:?}");
                        if size > 4096 { print!(" = {:.1} KiB/s", size as f64 / 1024.0 / el.as_secs_f64()); }
                        println!();
                        print_path(&node, &peer);
                    }
                    Err(e) => println!("sync failed: {e:#}"),
                }
            }
            ev = events.recv() => {
                match ev {
                    Ok(NetEvent::SpaceChanged { space: s }) if s == space => print_doc(&node, &space, &chat),
                    Ok(NetEvent::PeersChanged) => {
                        if let Some(p) = node.peers().get(&peer) {
                            println!("peer {}: links {:?}, last path {:?}", short(&peer), p.links, p.via);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    node.shutdown().await?;
    Ok(())
}

fn print_doc(node: &Node, space: &mycel_trust::SpaceId, chat: &StreamId) {
    let doc = node.with_space(space, |r| r.doc_json(chat)).unwrap_or_default();
    let mut shown = serde_json::Map::new();
    if let Some(m) = doc.as_object() {
        for (k, v) in m {
            let v = match v.as_str() {
                Some(s) if s.len() > 60 => serde_json::Value::String(format!("<{} bytes>", s.len())),
                _ => v.clone(),
            };
            shown.insert(k.clone(), v);
        }
    }
    println!("chat doc: {}", serde_json::Value::Object(shown));
}

fn print_path(node: &Node, peer: &mycel_crypto::SignPk) {
    if let Some(p) = node.peers().get(peer) {
        println!("  path: {}", p.via.map(|v| v.label()).unwrap_or("?"));
    }
}

/// Start just the link and print what it does (one-Mac smoke test).
async fn scan_only(link: Arc<dyn Link>) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    link.start(tx)?;
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let s = link.status();
                println!("[{:>3}s] status: active={} peers={} detail={:?}", started.elapsed().as_secs(), s.active, s.peers, s.detail);
            }
            ev = rx.recv() => match ev {
                Some(LinkEvent::Found { peer, name, .. }) => println!("FOUND {} {name:?}", short(&peer)),
                Some(LinkEvent::Lost { peer, .. }) => println!("LOST {}", short(&peer)),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    link.stop();
    Ok(())
}
