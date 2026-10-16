//! Phase 0 demo: `cargo run -p mycel-node --example demo`

use std::sync::Arc;

use anyhow::Result;
use mycel_node::{NetMode, Node, NodeOptions, Role, crypto::DeviceKeys, sync::Replica};
use mycel_sync::automerge::{ROOT, transaction::Transactable};

async fn node(name: &str) -> Result<Node> {
    let n = Node::spawn(Arc::new(DeviceKeys::generate()), NodeOptions::new(NetMode::Local, name)).await?;
    println!("  {name:<7} online  id={}", n.id().short());
    Ok(n)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n1. Five devices start (each key = its Iroh address)");
    let alice = node("alice").await?;
    let bob = node("bob").await?;
    let carol = node("carol").await?;
    let keeper = node("keeper").await?;
    let eve = node("eve").await?;
    let all = [&alice, &bob, &carol, &keeper, &eve];
    for a in all {
        for b in all {
            if a.id() != b.id() {
                a.add_peer_addr(b.addr());
            }
        }
    }

    println!("\n2. Alice founds a newsroom space: bob=Writer, carol=Reader, keeper=Relay");
    let (space, genesis) = alice.create_space()?;
    alice.with_space(&space, |r| {
        r.add_member(bob.keys().public(), Role::Writer)?;
        r.add_member(carol.keys().public(), Role::Reader)?;
        r.add_member(keeper.keys().public(), Role::Relay)
    })??;
    for (name, n) in [("bob", &bob), ("carol", &carol), ("keeper", &keeper)] {
        n.join_space(genesis.clone())?;
        let s = n.sync_with(alice.id(), space, true).await?;
        println!(
            "  {name:<7} joined via invite, got {} membership ops, role={:?}",
            s.ops,
            n.with_space(&space, |r| r.my_role())?.unwrap()
        );
    }

    println!("\n3. Bob writes a story and pushes it ONLY to the keeper");
    let doc = Replica::new_doc_id();
    bob.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "Mayor resigns")))??;
    bob.sync_with(keeper.id(), space, false).await?;
    keeper.with_space(&space, |r| {
        println!("  keeper  stores {} valid envelope(s) it cannot read; doc = {}", r.opaque_count(), r.doc_json(&doc))
    })?;

    println!("\n4. Carol syncs with the keeper (never talks to Bob)");
    carol.sync_with(keeper.id(), space, false).await?;
    println!("  carol   reads {}", carol.with_space(&space, |r| r.doc_json(&doc))?);

    println!("\n5. Carol (Reader) tries to rewrite the headline");
    carol.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "headline", "FAKE NEWS")))??;
    carol.sync_with(keeper.id(), space, false).await?;
    alice.sync_with(keeper.id(), space, false).await?;
    println!(
        "  alice   sees {}  (carol's write rejected by every peer)",
        alice.with_space(&space, |r| r.doc_json(&doc))?
    );

    println!("\n6. Eve (outsider who stole the invite) tries to sync");
    eve.join_space(genesis.clone())?;
    println!("  eve     -> {}", eve.sync_with(alice.id(), space, true).await.unwrap_err());

    println!("\n7. Alice removes Bob (keys rotate), adds a confidential note");
    alice.with_space(&space, |r| r.remove_member(bob.id()))??;
    alice.with_space(&space, |r| r.change(doc, |d| d.put(ROOT, "source", "confidential")))??;
    alice.sync_with(keeper.id(), space, false).await?;
    println!("  bob     -> keeper: {}", bob.sync_with(keeper.id(), space, false).await.unwrap_err());
    carol.sync_with(keeper.id(), space, false).await?;
    println!("  carol   reads {}", carol.with_space(&space, |r| r.doc_json(&doc))?);
    println!("  bob     still has only {}\n", bob.with_space(&space, |r| r.doc_json(&doc))?);

    for n in [alice, bob, carol, keeper, eve] {
        n.shutdown().await?;
    }
    Ok(())
}
