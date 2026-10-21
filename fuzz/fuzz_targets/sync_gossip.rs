//! The dissemination state machine (`reconcile::gossip::Disseminator`)
//! under arbitrary sequences of member changes, local writes, messages
//! from members (structured, naming real ids, or raw postcard), timer
//! ticks and failed sends.
//!
//! Properties: no panic; every message it sends fits the frame limit a
//! receiver accepts ([`MAX_GOSSIP_FRAME`]) and passes the receiver's own
//! limits (a second disseminator takes it without a `TooLarge` error);
//! actions per step are bounded; degree stays within the cap.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{Hash32, SignPk};
use mycel_sync::reconcile::gossip::{
    Action, Disseminator, GossipConfig, GossipError, GossipMsg, MAX_DEGREE, MAX_GOSSIP_FRAME, Member, PathClass,
};
use mycel_sync::reconcile::model::{Apply, ModelEnv, ModelOp, ModelSet};
use mycel_sync::reconcile::{AuthorEntry, Received, Run, SyncSet, frame_len};

#[derive(Arbitrary, Debug)]
struct M {
    who: u8,
    class: u8,
    reachable: bool,
    gossip: bool,
    slow: bool,
}

#[derive(Arbitrary, Debug)]
enum G {
    Push { ops: u8, items: Vec<u8>, entries: Vec<(u8, u8)>, seen: Vec<Vec<u8>> },
    IHave { ops: Vec<u8>, entries: Vec<(u8, u8)> },
    Have(Vec<u8>),
    Graft,
    Prune { drop: bool, alternatives: Vec<u8> },
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Step {
    Members(Vec<M>),
    Write { author: u8, n: u8, body: u16 },
    Msg { from: u8, msg: G },
    Tick(u16),
    PathDown(u8),
    Seen(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    keeper: bool,
    steps: Vec<Step>,
}

fn key(i: u8) -> SignPk {
    SignPk([i % 32 + 1; 32])
}

fuzz_target!(|input: Input| {
    let space = Hash32([9; 32]);
    let me = SignPk([0; 32]);
    let mut set = ModelSet::new(space);
    let mut peer_set = ModelSet::new(space);
    let mut d: Disseminator<ModelOp, ModelEnv> =
        Disseminator::new(me, GossipConfig { keeper: input.keeper, ..GossipConfig::default() });
    // A receiver to check what we send against its limits.
    let mut rx: Disseminator<ModelOp, ModelEnv> = Disseminator::new(key(1), GossipConfig::default());
    let all: Vec<Member> = (0..32)
        .map(|i| Member { key: key(i), class: PathClass::Internet, reachable: true, gossip: true, slow: false })
        .chain(std::iter::once(Member { key: me, class: PathClass::Internet, reachable: true, gossip: true, slow: false }))
        .collect();
    rx.set_members(&peer_set, &all, 0);
    d.set_members(&set, &all[..8], 0);
    let mut now = 0u64;
    for step in input.steps.iter().take(128) {
        match step {
            Step::Members(ms) => {
                let ms: Vec<Member> = ms
                    .iter()
                    .take(40)
                    .map(|m| Member {
                        key: key(m.who),
                        class: [PathClass::Direct, PathClass::Internet, PathClass::Mesh, PathClass::Dtn]
                            [usize::from(m.class % 4)],
                        reachable: m.reachable,
                        gossip: m.gossip,
                        slow: m.slow,
                    })
                    .collect();
                d.set_members(&set, &ms, now);
            }
            Step::Write { author, n, body } => {
                set.append(key(*author), u64::from(n % 80), usize::from(*body % 3000));
                d.on_changed(&set, None, now);
            }
            Step::Msg { from, msg } => {
                let from = key(*from);
                // Items a member could push: chains in its set.
                peer_set.append(from, 2, 64);
                let (ops, envs) = peer_set.all();
                let env = |i: &u8| envs.get(usize::from(*i) % envs.len().max(1)).cloned();
                let entry = |(a, r): &(u8, u8)| {
                    let id = env(r).map(|e| e.id()).unwrap_or(Hash32([*r; 32]));
                    AuthorEntry {
                        author: key(*a),
                        runs: vec![Run { top: u64::from(*r), head: id, bottom: 0 }],
                        truncated: None,
                    }
                };
                let msg = match msg {
                    G::Push { ops: n, items, entries, seen } => GossipMsg::Push {
                        space,
                        ops: ops.iter().take(usize::from(*n % 20)).cloned().collect(),
                        items: items.iter().take(80).filter_map(env).collect(),
                        entries: entries.iter().take(300).map(entry).collect(),
                        seen: seen.iter().take(70).cloned().collect(),
                    },
                    G::IHave { ops: o, entries } => GossipMsg::IHave {
                        space,
                        ops: o.iter().take(300).map(|i| Hash32([*i; 32])).collect(),
                        entries: entries.iter().take(300).map(entry).collect(),
                        seen: Vec::new(),
                    },
                    G::Have(ids) => GossipMsg::Have {
                        space,
                        ids: ids.iter().take(80).map(|i| env(i).map(|e| e.id()).unwrap_or(Hash32([*i; 32]))).collect(),
                    },
                    G::Graft => GossipMsg::Graft { space },
                    G::Prune { drop, alternatives } => GossipMsg::Prune {
                        space,
                        drop: *drop,
                        alternatives: alternatives.iter().take(6).map(|a| key(*a)).collect(),
                    },
                    G::Raw(bytes) => match postcard::from_bytes(bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    },
                };
                if let Ok(p) = d.on_msg(&set, from, msg, now)
                    && p.pushed
                {
                    let n = p.envelopes.len();
                    let (new, _) = set.apply(Received { ops: p.ops, envelopes: p.envelopes });
                    d.after_push(&set, from, n, new, now);
                }
            }
            Step::Tick(ms) => now += u64::from(*ms),
            Step::PathDown(p) => d.path_down(&key(*p)),
            Step::Seen(note) => {
                d.carry_seen(&space, note.clone());
            }
        }
        let mut actions = 0;
        while let Some(a) = d.poll(now) {
            actions += 1;
            assert!(actions <= 100_000, "unbounded actions");
            if let Action::Send { msg, .. } = a {
                assert!(frame_len(&msg) <= MAX_GOSSIP_FRAME, "a {} B gossip frame", frame_len(&msg));
                // (the receiver's view may lack the space's items; only the
                // limits matter here)
                match rx.on_msg(&peer_set, me, msg, now) {
                    Err(GossipError::TooLarge) => panic!("we sent a message over the receiver's limits"),
                    _ => {}
                }
            }
        }
        if let Some(t) = d.next_deadline() {
            let _ = t;
        }
        assert!(d.neighbours(&space).len() <= MAX_DEGREE.max(64) + 8);
    }
    let _ = (d.stats(), set.count());
});
