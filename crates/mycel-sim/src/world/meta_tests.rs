//! Determinism meta-tests (the practice S2 describes for deterministic
//! simulation testing, s2.dev/blog/dst): the same seed gives the same run
//! hash; every model on one seed sees the same exogenous world; one extra
//! frame moves no draw it cannot have caused; an exported world replays
//! bit for bit.

use std::sync::Arc;

use crate::models::{Access, Env, Nat, Tech};
use crate::scenarios::t2::{GCfg, Model, Plan, World, run};
use crate::tier2::engine::{Cx, Mobility, NodeSpec, Over};
use crate::tier2::{Action, Area, Inet, MS, MsgId, NodeId, Router, SEC, Sim, Techs, Time};
use crate::world::trace::WorldTrace;

/// A small world with everything exogenous in it: walkers, a device that
/// switches off and on, an internet outage, a trace contact, sends and a
/// call.
fn world(seed: u64) -> (World, Plan, Time) {
    let mut rng = crate::stats::Rng::new(seed);
    let mut w = World {
        areas: vec![
            Area { latlon: (48.86, 2.35), env: Env::Outdoor },
            Area { latlon: (40.71, -74.0), env: Env::Indoor },
        ],
        specs: Vec::new(),
    };
    for i in 0..30 {
        let inet = (i % 10 == 0).then_some(Inet { access: Access::Lte, nat: Nat::Easy });
        let mut s = crate::tier2::world::phone(0, (rng.range(0.0, 300.0), rng.range(0.0, 300.0)), inet, &mut rng);
        if i % 3 == 0 {
            s.mobility = Mobility::Waypoint { w: 300.0, h: 300.0, speed: 1.5, pause: 20 * SEC };
        }
        w.specs.push(s);
    }
    for i in 0..3 {
        w.specs.push(NodeSpec {
            area: 1,
            xy: (i as f64 * 15.0, 0.0),
            radios: Techs::of(&[Tech::Ble]),
            inet: (i == 2).then_some(Inet { access: Access::Fibre, nat: Nat::Open }),
            mobility: Mobility::Static,
            online: true,
        });
    }
    let mut plan = Plan::default();
    for k in 0..24u64 {
        let (a, b) = (rng.below(33) as NodeId, rng.below(33) as NodeId);
        if a != b {
            plan.sends.push((10 * SEC + k * 2 * SEC, a, b, 1500, k % 7 == 0));
        }
    }
    plan.acts.push((30 * SEC, Action::Online(4, false)));
    plan.acts.push((50 * SEC, Action::Online(4, true)));
    plan.acts.push((20 * SEC, Action::Inet(10, false)));
    plan.acts.push((40 * SEC, Action::Inet(10, true)));
    plan.acts.push((25 * SEC, Action::Contact(1, 31, Techs::of(&[Tech::Ble]), true)));
    plan.acts.push((35 * SEC, Action::Contact(1, 31, Techs::of(&[Tech::Ble]), false)));
    plan.acts.push((45 * SEC, Action::Move(7, (5.0, 5.0))));
    (w, plan, 90 * SEC)
}

#[test]
fn same_seed_same_run_hash() {
    let (w, plan, until) = world(3);
    for m in [Model::Global(GCfg::default()), Model::Epidemic] {
        let (a, b) = (run(m, &w, &plan, 3, until, None), run(m, &w, &plan, 3, until, None));
        assert_eq!(a.run_hash, b.run_hash, "{}", m.name());
        assert_eq!(a.exo_hash, b.exo_hash);
        assert!(a.m.delivered > 0, "{}: the world carries traffic", m.name());
    }
    // another seed: another run (and another world, mobility being keyed by it)
    let (x, y) = (run(Model::Epidemic, &w, &plan, 3, until, None), run(Model::Epidemic, &w, &plan, 4, until, None));
    assert_ne!(x.run_hash, y.run_hash);
    assert_ne!(x.exo_hash, y.exo_hash);
}

#[test]
fn every_model_sees_the_same_exogenous_world() {
    let (w, plan, until) = world(5);
    let models = [
        Model::Global(GCfg::default()),
        Model::Global(GCfg::routing()),
        Model::Main,
        Model::StandIn,
        Model::SenderHolds,
        Model::Epidemic,
        Model::Spray(4),
        Model::Prophet,
        Model::Flood(3),
    ];
    let runs: Vec<_> = models.iter().map(|m| run(*m, &w, &plan, 5, until, None)).collect();
    for (m, r) in models.iter().zip(&runs) {
        assert_eq!(r.exo_hash, runs[0].exo_hash, "{} saw another world", m.name());
    }
    // ...while what the routers did differs
    let distinct: std::collections::HashSet<&String> = runs.iter().map(|r| &r.run_hash).collect();
    assert!(distinct.len() >= models.len() - 1, "run hashes: {distinct:?}");
    // adversary placement is part of the world
    let mut liars = plan.clone();
    liars.roles.insert(3, crate::tier2::mycel::Role::Liar);
    assert_ne!(run(Model::Epidemic, &w, &liars, 5, until, None).exo_hash, runs[0].exo_hash);
}

#[test]
fn an_exported_world_replays_bit_for_bit() {
    let (w, mut plan, until) = world(7);
    plan.keep_world = true;
    for m in [Model::Global(GCfg::default()), Model::Main, Model::Spray(4)] {
        let src = run(m, &w, &plan, 7, until, None);
        let trace = src.world.expect("kept");
        assert_eq!(trace.exo_hash, src.exo_hash);
        assert!(trace.events.iter().any(|e| matches!(e.1, crate::world::WorldEvent::Move { .. })));
        // through JSON, as `export-world` and `replay --world` do
        let back: WorldTrace = serde_json::from_slice(&serde_json::to_vec(&trace).expect("json")).expect("parse");
        let back = Arc::new(back);
        let rp = run(m, &w, &Plan::replaying(&back), back.seed, back.until, None);
        assert_eq!(rp.exo_hash, src.exo_hash, "{}: the replay rebuilds the world", m.name());
        assert_eq!(rp.run_hash, src.run_hash, "{}: the replay is the run", m.name());
        assert_eq!((rp.m.delivered, rp.m.latency_s), (src.m.delivered, src.m.latency_s));
    }
    // and through the CLI's entry point
    let src = run(Model::Global(GCfg::default()), &w, &plan, 7, until, None);
    let mut r =
        crate::scenarios::t2::replay_world(Arc::new(src.world.expect("kept")), Some(crate::scenarios::Candidate::Main));
    r.finish();
    assert_eq!(r.status, crate::report::Status::Pass, "{:?}", r.failed_slos());
}

// ── CRN isolation ──

const EXTRA: u64 = 1 << 40;
const TICK: u64 = 1;

#[derive(Clone)]
struct Ping {
    id: u64,
    ttl: u8,
    tainted: bool,
}

/// Gossip that leans on randomness: random start phases, random periods,
/// random next hops, all from `Cx::rng`. Frames sent by a device after it
/// was causally touched by the extra frame are tainted.
struct Gossip {
    me: NodeId,
    log: Vec<(Time, NodeId, u64, u8)>,
    tainted_since: Option<Time>,
    extra: Option<(NodeId, Time)>,
    sent: u64,
}

impl Gossip {
    fn send(&mut self, cx: &mut Cx<Ping>, ttl: u8) {
        let nbs = cx.neighbours();
        if nbs.is_empty() {
            return;
        }
        let nb = nbs[cx.rng().below(nbs.len())].0;
        self.sent += 1;
        let p = Ping { id: (u64::from(self.me) << 32) | self.sent, ttl, tainted: self.tainted_since.is_some() };
        cx.send_radio(nb, p, 100, false, None);
    }
}

impl Router for Gossip {
    type Frame = Ping;
    fn size(_: &Ping) -> u32 {
        100
    }
    fn is_control(_: &Ping) -> bool {
        false
    }
    fn msg_of(_: &Ping) -> Option<MsgId> {
        None
    }
    fn on_start(&mut self, cx: &mut Cx<Ping>) {
        let phase = (cx.rng().f64() * 500.0) as Time * MS;
        cx.set_timer(phase + 1, TICK);
        if let Some((_, at)) = self.extra {
            cx.set_timer(at, EXTRA);
        }
    }
    fn on_link(&mut self, _: &mut Cx<Ping>, _: NodeId, _: Techs, _: bool) {}
    fn on_frame(&mut self, cx: &mut Cx<Ping>, from: NodeId, _: Over, f: Ping) {
        self.log.push((cx.now(), from, f.id, f.ttl));
        if f.tainted && self.tainted_since.is_none() {
            self.tainted_since = Some(cx.now());
        }
        if f.ttl > 0 {
            self.send(cx, f.ttl - 1);
        }
    }
    fn on_timer(&mut self, cx: &mut Cx<Ping>, token: u64) {
        if token == EXTRA {
            let (nb, _) = self.extra.expect("extra");
            self.tainted_since = Some(cx.now());
            cx.send_radio(nb, Ping { id: u64::MAX, ttl: 0, tainted: true }, 100, false, None);
            return;
        }
        self.send(cx, 2);
        let next = 300 * MS + (cx.rng().f64() * 400.0) as Time * MS;
        cx.set_timer(next, TICK);
    }
    fn on_send(&mut self, _: &mut Cx<Ping>, _: MsgId, _: NodeId, _: u32) {}
}

/// Devices on the line, 40 m apart.
const LINE: usize = 80;

fn gossip(extra: Option<(NodeId, NodeId, Time)>, until: Time) -> Vec<Gossip> {
    // BLE devices 40 m apart (outdoor range 60 m: one neighbour each side)
    let specs: Vec<NodeSpec> = (0..LINE)
        .map(|i| NodeSpec {
            area: 0,
            xy: (i as f64 * 40.0, 0.0),
            radios: Techs::of(&[Tech::Ble]),
            inet: None,
            mobility: Mobility::Static,
            online: true,
        })
        .collect();
    let areas = vec![Area { latlon: (0.0, 0.0), env: Env::Outdoor }];
    let mut sim = Sim::new(areas, specs, 11, |i, _| Gossip {
        me: i,
        log: Vec::new(),
        tainted_since: None,
        extra: extra.filter(|e| e.0 == i).map(|e| (e.1, e.2)),
        sent: 0,
    });
    sim.start();
    sim.run(until);
    sim.routers
}

/// Candidate B sends one extra frame on link 0 → 1 at 2 s. Nothing can
/// travel faster than one BLE hop latency per hop, so device x cannot be
/// touched before 2 s + x hops: every device's events before that are the
/// same in A and B, and devices beyond the cone at the end are the same
/// throughout. (With one shared generator, the extra frame's jitter draw
/// moved every later draw of every device at once.)
#[test]
fn one_extra_frame_moves_only_what_it_can_have_caused() {
    let (at, until) = (2 * SEC, 3 * SEC);
    let hop = Tech::Ble.latency().as_micros() as Time;
    let a = gossip(None, until);
    let b = gossip(Some((0, 1, at)), until);
    let (mut clean, mut changed) = (0, 0);
    for (x, y) in a.iter().zip(&b) {
        let cone = at + u64::from(x.me) * hop;
        let before = |l: &[(Time, NodeId, u64, u8)]| l.iter().filter(|e| e.0 < cone).cloned().collect::<Vec<_>>();
        assert_eq!(before(&x.log), before(&y.log), "device {} changed before the extra frame could reach it", x.me);
        assert!(x.log.iter().any(|e| e.0 >= at), "device {} was busy after the extra frame", x.me);
        if cone >= until {
            clean += 1;
        }
        if x.log != y.log {
            changed += 1;
        }
        // the frame-level taint never gets ahead of the cone
        assert!(y.tainted_since.is_none_or(|t| t >= cone), "device {} tainted at {:?}", x.me, y.tainted_since);
    }
    assert!(clean >= 10 && changed >= 2, "clean {clean}, changed {changed}: the test must have both");
}
