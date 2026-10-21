//! Ablation harness for the routing defences (`docs/ROUTING.md` §6, item
//! 15): the GLOBAL core only (no reference models), on the worlds and plans
//! of the tier-2 scenarios `adversarial` (plus a fan-out workload of the
//! same liars), `churn`, `global-scale` and `trace-replay`, copied from
//! `scenarios/t2.rs` so each can be scaled. Core knobs come from
//! `MYCEL_CORE` as in the scenarios (e.g. `defences=none`,
//! `defences=default`, `defences=none,corroborate=on`); `MYCEL_SPACES`
//! picks the membership model (`tier2::global::spaces`); `ABL_VARIANTS`
//! (comma-separated) limits `adversarial` to some of its runs.
//!
//! `cargo run --release -p mycel-sim --example ablation -- <scenario> <seed> [scale]`
//! prints one JSON line per run (delivery over reachable pairs and over
//! all sent, optimality p50/p95/p99, control bytes per device and second,
//! the core's counters and the frame-loop count under `extra`).

use mycel_sim::models::Env;
use mycel_sim::scenarios::t2::{GCfg, Model, Plan, World, run};
use mycel_sim::stats::{Map, Rng};
use mycel_sim::tier2::engine::{Mobility, NodeSpec};
use mycel_sim::tier2::mycel::Role;
use mycel_sim::tier2::world::{self, cellular, phone};
use mycel_sim::tier2::{Action, Area, MIN, MS, NodeId, SEC, Techs, Time};
use serde_json::json;

fn mesh_world(n: usize, seed: u64, m2_per_device: f64) -> World {
    let mut rng = Rng::new(seed);
    let side = (n as f64 * m2_per_device).sqrt();
    World {
        areas: vec![Area { latlon: (48.86, 2.35), env: Env::Outdoor }],
        specs: (0..n).map(|_| phone(0, (rng.range(0.0, side), rng.range(0.0, side)), None, &mut rng)).collect(),
    }
}

fn emit(scenario: &str, variant: &str, seed: u64, r: &mycel_sim::scenarios::t2::Run) {
    let m = &r.m;
    let knobs = std::env::var("MYCEL_CORE").unwrap_or_default();
    let line = json!({
        "scenario": scenario, "variant": variant, "seed": seed, "knobs": knobs,
        "spaces": std::env::var("MYCEL_SPACES").unwrap_or_default(),
        "sent": m.sent, "feasible": m.feasible, "delivered": m.delivered, "delivery_ratio": m.delivery_ratio,
        "opt_p50": m.optimality.p50, "opt_p95": m.optimality.p95, "opt_p99": m.optimality.p99, "opt_n": m.optimality.n,
        "lat_p50": m.latency_s.p50, "lat_p95": m.latency_s.p95,
        "ctrl_b_s": m.ctrl_bytes_per_node_s, "copies": m.copies_per_msg, "handoffs": m.handoffs_per_msg,
        "wall_s": m.wall_s, "extra": r.extra,
    });
    println!("{line}");
}

fn n(scale: f64, full: usize, min: usize) -> usize {
    ((full as f64 * scale).round() as usize).max(min)
}

fn adversarial(seed: u64, scale: f64) {
    let mut rng = Rng::new(seed ^ 0xbad);
    let nn = n(scale, 300, 80);
    let mut w = mesh_world(nn, seed, 900.0);
    for s in w.specs.iter_mut().take(nn / 20) {
        s.inet = Some(cellular(&mut rng));
    }
    let bad: Vec<NodeId> = (0..(nn / 20).max(2)).map(|_| rng.below(nn) as NodeId).collect();
    let storm = rng.below(nn) as NodeId;
    let replay = rng.below(nn) as NodeId;
    let mut roles = Map::default();
    for b in &bad {
        roles.insert(*b, Role::BlackHole);
    }
    roles.insert(storm, Role::Storm);
    roles.insert(replay, Role::Replayer);
    let mut plan = Plan::default();
    let mut k = 0;
    while plan.sends.len() < n(scale, 300, 60) && k < 10_000 {
        k += 1;
        let (a, b) = (rng.below(nn) as NodeId, rng.below(nn) as NodeId);
        if a != b && !roles.contains_key(&a) && !roles.contains_key(&b) {
            plan.sends.push((30 * SEC + plan.sends.len() as Time * 300 * MS, a, b, 1000, false));
        }
    }
    let until = 30 * SEC + plan.sends.len() as Time * 300 * MS + 90 * SEC;
    let attacked = Plan { roles: roles.clone(), ..plan.clone() };
    let sybil = rng.below(nn) as NodeId;
    let sybil_plan =
        Plan { poison: Some(sybil), roles: [(sybil, Role::BlackHole)].into_iter().collect(), ..plan.clone() };
    let liar_plan = Plan { roles: bad.iter().map(|b| (*b, Role::Liar)).collect(), ..plan.clone() };
    // the same liars, honest until a quarter of the messages have been
    // sent (most of the traffic comes once they have turned)
    let turn = plan.sends.get(plan.sends.len() / 4).map(|s| s.0);
    let adaptive_plan = Plan { roles: bad.iter().map(|b| (*b, Role::AdaptiveLiar)).collect(), turn, ..plan.clone() };
    // the same liars, but few sources each sending to many destinations (a
    // device messaging its contacts): what cross-destination aggregation
    // needs to see; its own stream, so the other plans don't move
    let mut fan_rng = Rng::new(seed ^ 0xfa);
    let senders: Vec<NodeId> =
        (0..nn / 15).map(|_| fan_rng.below(nn) as NodeId).filter(|a| !liar_plan.roles.contains_key(a)).collect();
    let mut fanout = Plan { roles: liar_plan.roles.clone(), ..Plan::default() };
    let mut k = 0;
    while fanout.sends.len() < plan.sends.len() && k < 10_000 && !senders.is_empty() {
        k += 1;
        let a = senders[fan_rng.below(senders.len())];
        let b = fan_rng.below(nn) as NodeId;
        if a != b && !fanout.roles.contains_key(&b) {
            fanout.sends.push((30 * SEC + fanout.sends.len() as Time * 300 * MS, a, b, 1000, false));
        }
    }
    let g = Model::Global(GCfg::default());
    let runs: Vec<(&str, &Plan)> = vec![
        ("clean", &plan),
        ("black-holes", &attacked),
        ("plausible-liars", &liar_plan),
        ("sybil", &sybil_plan),
        ("liars-fanout", &fanout),
        ("adaptive-liars", &adaptive_plan),
    ];
    // ABL_VARIANTS=a,b runs only those
    let only = std::env::var("ABL_VARIANTS").unwrap_or_default();
    let runs: Vec<(&str, &Plan)> =
        runs.into_iter().filter(|(v, _)| only.is_empty() || only.split(',').any(|o| o == *v)).collect();
    use rayon::prelude::*;
    let out: Vec<_> = runs.par_iter().map(|(v, p)| (*v, run(g, &w, p, seed, until, None))).collect();
    for (v, r) in out {
        emit("adversarial", v, seed, &r);
    }
}

fn churn(seed: u64, scale: f64) {
    let nn = n(scale, 10_000, 800);
    let mut rng = Rng::new(seed ^ 0xc4);
    let (areas, specs) = world::global(nn, 60, &mut rng);
    let w = World { areas, specs };
    let nn = w.specs.len();
    let (warm, dur) = (2 * MIN, 10 * MIN);
    let mut plan = Plan { max_neighbours: Some(8), ..Plan::default() };
    let mut away: Vec<NodeId> = Vec::new();
    for minute in 0..(dur / MIN) {
        let t = warm + minute * MIN;
        for a in away.drain(..) {
            plan.acts.push((t + rng.below(60) as Time * SEC, Action::Online(a, true)));
        }
        for _ in 0..(nn as f64 * 0.15) as usize {
            let d = rng.below(nn) as NodeId;
            away.push(d);
            plan.acts.push((t + rng.below(60) as Time * SEC, Action::Online(d, false)));
        }
    }
    let msgs = n(scale, 1000, 150);
    for k in 0..msgs {
        let (a, b) = (rng.below(nn) as NodeId, rng.below(nn) as NodeId);
        if a != b {
            plan.sends.push((warm + (k as Time * dur) / msgs as Time, a, b, 1000, false));
        }
    }
    let until = warm + dur + 10 * MIN;
    let r = run(Model::Global(GCfg::default()), &w, &plan, seed, until, Some(300));
    emit("churn", "churn", seed, &r);
}

fn global_scale(seed: u64, scale: f64) {
    let nn = n(scale, 100_000, 1500);
    let mut rng = Rng::new(seed);
    let (areas, specs) = world::global(nn, 80, &mut rng);
    let w = World { areas, specs };
    let nn = w.specs.len();
    let msgs = n(scale, 2000, 200);
    let warm = 2 * MIN;
    let mut plan = Plan { max_neighbours: Some(8), ..Plan::default() };
    for k in 0..msgs {
        let (a, b) = (rng.below(nn) as NodeId, rng.below(nn) as NodeId);
        if a != b {
            let t = warm + (k as Time * 5 * MIN) / msgs as Time;
            plan.sends.push((t, a, b, 1000, false));
            plan.sends.push((t + MIN, a, b, 1000, false));
        }
    }
    let until = warm + 5 * MIN + 5 * MIN;
    let r = run(Model::Global(GCfg::default()), &w, &plan, seed, until, Some(400));
    emit("global-scale", "scale", seed, &r);
}

fn trace_replay(seed: u64, scale: f64) {
    let trace = mycel_sim::traces::synthetic(n(scale, 40, 12), (n(scale, 72, 12) as Time) * 3600 * SEC, seed);
    let w = World {
        areas: vec![Area { latlon: (52.2, 0.12), env: Env::Indoor }],
        specs: (0..trace.nodes)
            .map(|i| NodeSpec {
                area: 0,
                xy: (i as f64 * 1000.0, 0.0),
                radios: Techs::of(&[mycel_sim::models::Tech::OneBt]),
                inet: None,
                mobility: Mobility::Static,
                online: true,
            })
            .collect(),
    };
    let bt = Techs::of(&[mycel_sim::models::Tech::OneBt]);
    let mut acts = Vec::new();
    for (s, e, a, b) in &trace.contacts {
        acts.push((*s, Action::Contact(*a, *b, bt, true)));
        acts.push(((*e).max(*s + 1), Action::Contact(*a, *b, bt, false)));
    }
    let mut rng = Rng::new(seed);
    let mut plan = Plan { acts, ..Plan::default() };
    let mut t = 25 * SEC;
    let ttl = 300 * MIN;
    while t + ttl / 4 < trace.duration && plan.sends.len() < n(scale, 4000, 200) {
        let (a, b) = (rng.below(trace.nodes) as NodeId, rng.below(trace.nodes) as NodeId);
        if a != b {
            plan.sends.push((t, a, b, rng.range(500_000.0, 1_000_000.0) as u32, false));
        }
        t += (rng.range(25.0, 35.0) * SEC as f64) as Time;
    }
    plan.baseline = Some(mycel_sim::tier2::dtn::Opts { buffer: 5 << 20, ttl });
    plan.dtn = Some(mycel_net::mesh::dtn::DtnConfig {
        capacity: 5 << 20,
        max_bundle: 1 << 20,
        per_source: 5 << 20,
        max_lifetime: ttl / MS,
        copies: 6,
        ..mycel_net::mesh::dtn::DtnConfig::default()
    });
    plan.bundle_lifetime_ms = Some(ttl / MS);
    let r = run(Model::Global(GCfg::default()), &w, &plan, seed, trace.duration, Some(400));
    emit("trace-replay", "trace", seed, &r);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let seed: u64 = a[2].parse().expect("seed");
    let scale: f64 = a.get(3).map_or(1.0, |s| s.parse().expect("scale"));
    match a[1].as_str() {
        "adversarial" => adversarial(seed, scale),
        "churn" => churn(seed, scale),
        "global-scale" => global_scale(seed, scale),
        "trace-replay" => trace_replay(seed, scale),
        s => panic!("unknown {s}"),
    }
}
