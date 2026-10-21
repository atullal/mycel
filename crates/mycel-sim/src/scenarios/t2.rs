//! Tier-2 scenarios: routing at scale and across the world, in virtual time.
//!
//! Each scenario runs the *candidate* routing core and holds it to the
//! objectives: by default the GLOBAL core (`mycel_net::mesh::core`, the real
//! code, driven by [`crate::tier2::global`]). Reference models run alongside:
//! the mesh as it was before GLOBAL (`main`), the stand-in model of the whole
//! GLOBAL design (including store-and-forward not yet in the core),
//! sender-holds, epidemic and spray-and-wait. Every delivered message is
//! compared with the fastest feasible path from the ground-truth contact
//! plan: the optimality ratio.

use crate::stats::Map;
use rayon::prelude::*;
use std::rc::Rc;
use std::time::Instant;

use mycel_net::mesh::core::Config;
use serde_json::json;

use super::{Candidate, Opts, Scenario};
use crate::models::{Access, Env, Nat, Tech};
use crate::report::{ScenarioResult, fmt};
use crate::stats::Rng;
use crate::tier2::dtn::{Dtn, Kind};
use crate::tier2::engine::{Mobility, NodeSpec};
use crate::tier2::global::{Global, Shared, key, node};
use crate::tier2::mycel::{Cfg, Mycel, Role};
use crate::tier2::oracle::Oracle;
use crate::tier2::world::{self, ble_only, cellular, phone};
use crate::tier2::{Action, Area, HOUR, Inet, MIN, MS, NodeId, Router, SEC, Sim, T2Metrics, Techs, Time, metrics};

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "us-eu", title: "US to Europe: BLE-only phones 3–6 hops from a gateway", tier: 2, run: us_eu
        },
        Scenario {
            name: "gateway-choice",
            title: "Gateway by total cost: near slow uplink vs far fibre",
            tier: 2,
            run: gateway_choice,
        },
        Scenario {
            name: "routing-convergence",
            title: "Convergence, loops and re-convergence after a hub fails",
            tier: 2,
            run: convergence,
        },
        Scenario {
            name: "flood-scaling",
            title: "Announcement overhead vs size; fisheye and flood reduction",
            tier: 2,
            run: flood_scaling,
        },
        Scenario {
            name: "partial-route",
            title: "Partial route, custody at the break, mule completes it",
            tier: 2,
            run: partial_route,
        },
        Scenario {
            name: "disaster-dtn",
            title: "Disaster zone: gradient DTN vs spray-and-wait vs epidemic",
            tier: 2,
            run: disaster_dtn,
        },
        Scenario { name: "mailbox", title: "Mailbox: destination offline for hours, one drain", tier: 2, run: mailbox },
        Scenario {
            name: "global-scale",
            title: "100k devices on 6 continents, mixed connectivity",
            tier: 2,
            run: global_scale,
        },
        Scenario { name: "churn", title: "Churn: 30% of devices leave and join each minute", tier: 2, run: churn },
        Scenario {
            name: "adversarial",
            title: "Black holes, announcement storm, replays, Sybil gateway",
            tier: 2,
            run: adversarial,
        },
        Scenario {
            name: "trace-replay",
            title: "Real contact traces (CRAWDAD Haggle) with The ONE's workload",
            tier: 2,
            run: trace_replay,
        },
        Scenario {
            name: "flood-hop-limit",
            title: "Managed flooding: reach vs usefulness by hop limit (Meshtasticator check)",
            tier: 2,
            run: flood_hop_limit,
        },
    ]
}

const NEEDS_GLOBAL: &str = "the GLOBAL routing core replaces main's mesh (gateways, records, internet hops)";

// ───────────────────────────── plumbing ─────────────────────────────

#[derive(Clone)]
pub struct World {
    pub areas: Vec<Area>,
    pub specs: Vec<NodeSpec>,
}

/// What happens in a run, independent of the routing model.
#[derive(Clone, Default)]
pub struct Plan {
    /// (when, from, to, size, a call offer)
    pub sends: Vec<(Time, NodeId, NodeId, u32, bool)>,
    pub acts: Vec<(Time, Action)>,
    pub max_neighbours: Option<usize>,
    pub poison: Option<NodeId>,
    pub roles: Map<NodeId, Role>,
    /// Store-and-forward settings for the GLOBAL carrier (default: its own).
    pub dtn: Option<mycel_net::mesh::dtn::DtnConfig>,
    pub bundle_lifetime_ms: Option<u64>,
    /// Buffer and TTL for the baseline routers.
    pub baseline: Option<crate::tier2::dtn::Opts>,
}

impl Plan {
    fn apply<R: Router>(&self, sim: &mut Sim<R>) {
        if let Some(m) = self.max_neighbours {
            sim.core.max_neighbours = m;
        }
        sim.core.dir_poison = self.poison;
        for (t, s, d, size, call) in &self.sends {
            if *call {
                sim.call_at(*t, *s, *d);
            } else {
                sim.send_at(*t, *s, *d, *size);
            }
        }
        for (t, a) in &self.acts {
            sim.act_at(*t, a.clone());
        }
    }

    fn role(&self, i: NodeId) -> Role {
        self.roles.get(&i).copied().unwrap_or_default()
    }
}

/// GLOBAL core settings a scenario may vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GCfg {
    pub announce_every_ms: u64,
    pub fisheye: bool,
    /// With fisheye: the full scope every this many periods.
    pub far_every: u64,
    pub max_hops: u8,
    pub flood_reduction: bool,
    /// GLOBAL's store-and-forward carrier on top of routing.
    pub dtn: bool,
}

impl Default for GCfg {
    fn default() -> Self {
        let c = Config::default();
        GCfg {
            announce_every_ms: c.announce_every,
            fisheye: c.fisheye,
            far_every: c.far_every,
            max_hops: c.max_hops,
            flood_reduction: c.flood_reduction,
            dtn: true,
        }
    }
}

impl GCfg {
    /// Routing only (no store-and-forward).
    pub fn routing() -> GCfg {
        GCfg { dtn: false, ..GCfg::default() }
    }

    /// The core's announcement settings before finding 1 (docs/SIMULATION.md
    /// §4): every 2 s, the full scope (8 hops) every 4th, flood reduction on.
    /// (New neighbours are greeted either way.)
    pub fn before() -> GCfg {
        GCfg { announce_every_ms: 2_000, far_every: 4, max_hops: 8, flood_reduction: true, ..GCfg::routing() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Model {
    Global(GCfg),
    Main,
    StandIn,
    SenderHolds,
    Epidemic,
    Spray(u8),
    Prophet,
    /// Managed flooding with this hop limit.
    Flood(u8),
}

impl Model {
    fn of(c: Candidate) -> Model {
        match c {
            Candidate::Global => Model::Global(GCfg::default()),
            Candidate::Main => Model::Main,
            Candidate::StandIn => Model::StandIn,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Model::Global(g) if *g == GCfg::default() => "global core + DTN".into(),
            Model::Global(g) if *g == GCfg::routing() => "global core (routing only)".into(),
            Model::Global(g) => format!(
                "global core{} (every {} s, fisheye {} (full scope every {}), flood reduction {})",
                if g.dtn { " + DTN" } else { "" },
                g.announce_every_ms / 1000,
                if g.fisheye { "on" } else { "off" },
                g.far_every,
                if g.flood_reduction { "on" } else { "off" }
            ),
            Model::Main => "main (mesh before GLOBAL)".into(),
            Model::StandIn => "stand-in (design reference)".into(),
            Model::SenderHolds => "sender holds until a route".into(),
            Model::Epidemic => "epidemic".into(),
            Model::Spray(l) => format!("spray-and-wait (L={l})"),
            Model::Prophet => "PRoPHET".into(),
            Model::Flood(h) => format!("managed flooding (hop limit {h})"),
        }
    }
}

pub struct Run {
    pub m: T2Metrics,
    pub extra: serde_json::Value,
    /// Messages to a device this sender had already reached (a delivered
    /// message between the pair before this one was sent): the record
    /// lookup and the connection are warm. `None` if there were none.
    pub warm: Option<T2Metrics>,
    /// The others: first contact, paying a record lookup and a dial the
    /// oracle doesn't model.
    pub first: Option<T2Metrics>,
}

#[allow(clippy::too_many_arguments)]
fn go<R: Router>(
    w: &World,
    plan: &Plan,
    seed: u64,
    until: Time,
    sample: Option<usize>,
    name: &str,
    make: impl FnMut(NodeId, &NodeSpec) -> R,
    extra: impl Fn(&Sim<R>) -> serde_json::Value,
) -> Run {
    let t = Instant::now();
    let mut sim = Sim::new(w.areas.clone(), w.specs.clone(), seed, make);
    plan.apply(&mut sim);
    sim.start();
    sim.run(until);
    sim.finish();
    let wall = t.elapsed().as_secs_f64();
    Oracle::new(&sim).annotate(&mut sim, sample);
    let m = metrics(&sim, name, wall, None);
    let warm_set = warm_messages(&sim.core.msgs);
    let (warm, first) = if warm_set.is_empty() {
        (None, None)
    } else {
        let is_warm = |r: &crate::tier2::engine::MsgRecord| warm_set.contains(&(r.src, r.dst, r.sent));
        (
            Some(metrics(&sim, &format!("{name}, warm"), wall, Some(&is_warm))),
            Some(metrics(
                &sim,
                &format!("{name}, first contact"),
                wall,
                Some(&|r: &crate::tier2::engine::MsgRecord| !is_warm(r)),
            )),
        )
    };
    Run { m, extra: extra(&sim), warm, first }
}

/// (src, dst, sent) of each message sent after an earlier one between the
/// same pair had been delivered.
/// (sent, delivered) of every message between one pair.
type PairSends = Vec<(Time, Option<Time>)>;

fn warm_messages(msgs: &[crate::tier2::engine::MsgRecord]) -> std::collections::HashSet<(NodeId, NodeId, Time)> {
    let mut by_pair: Map<(NodeId, NodeId), PairSends> = Map::default();
    for r in msgs {
        by_pair.entry((r.src, r.dst)).or_default().push((r.sent, r.delivered));
    }
    let mut out = std::collections::HashSet::new();
    for ((src, dst), mut v) in by_pair {
        v.sort_unstable();
        let mut reached: Option<Time> = None;
        for (sent, delivered) in v {
            if reached.is_some_and(|t| t <= sent) {
                out.insert((src, dst, sent));
            }
            if let Some(d) = delivered {
                reached = Some(reached.map_or(d, |t| t.min(d)));
            }
        }
    }
    out
}

/// The core's settings for a scenario, with `MYCEL_CORE` knobs on top (e.g.
/// `MYCEL_CORE=every=8000,greet=all`; see `Config::tune`).
fn global_cfg(g: GCfg, seed: u64, i: NodeId) -> Config {
    let mut c = Config {
        announce_every: g.announce_every_ms,
        fisheye: g.fisheye,
        far_every: g.far_every,
        max_hops: g.max_hops,
        flood_reduction: g.flood_reduction,
        seed: seed.wrapping_mul(0x9e37_79b9) ^ (i as u64 + 1),
        // signatures are stubbed (always valid): the cache only costs memory
        verified_max: 64,
        ..Config::default()
    };
    if let Ok(k) = std::env::var("MYCEL_CORE") {
        c.tune(&k).expect("MYCEL_CORE");
    }
    c
}

fn mycel_extra(sim: &Sim<Mycel>) -> serde_json::Value {
    let s = sim.routers.iter().fold(crate::tier2::mycel::MycelStats::default(), |mut a, r| {
        a.ogm_limited += r.stats.ogm_limited;
        a.ogm_stale += r.stats.ogm_stale;
        a.dropped_blackhole += r.stats.dropped_blackhole;
        a.dropped_no_route += r.stats.dropped_no_route;
        a.held += r.stats.held;
        a.mailbox_drained += r.stats.mailbox_drained;
        a
    });
    json!({"ogm_limited": s.ogm_limited, "ogm_stale": s.ogm_stale, "dropped_blackhole": s.dropped_blackhole,
           "dropped_no_route": s.dropped_no_route, "held": s.held, "mailbox_drained": s.mailbox_drained})
}

pub fn run(model: Model, w: &World, plan: &Plan, seed: u64, until: Time, sample: Option<usize>) -> Run {
    let name = model.name();
    match model {
        Model::Global(g) => {
            let shared = Rc::new(Shared::default());
            let sh = shared.clone();
            let spaces = crate::tier2::global::spaces(&w.specs, &plan.roles, seed);
            go(
                w,
                plan,
                seed,
                until,
                sample,
                &name,
                |i, _| {
                    let mut r = Global::new(i, global_cfg(g, seed, i), shared.clone());
                    if g.dtn {
                        r = r.with_dtn(dtn_cfg(plan));
                        r.bundle_lifetime_ms = plan.bundle_lifetime_ms.unwrap_or(24 * 3600 * 1000);
                    }
                    r.role = plan.role(i);
                    r.core.set_affinity(spaces[i as usize].iter().map(|j| (key(*j), 1)));
                    r
                },
                move |sim| {
                    let mut t = mycel_net::mesh::core::Stats::default();
                    for r in &sim.routers {
                        let s = r.core.stats();
                        t.announcements_sent += s.announcements_sent;
                        t.announcements_received += s.announcements_received;
                        t.announcements_limited += s.announcements_limited;
                        t.announcements_stale += s.announcements_stale;
                        t.announcements_suppressed += s.announcements_suppressed;
                        t.announcements_implausible += s.announcements_implausible;
                        t.neighbours_distrusted += s.neighbours_distrusted;
                        t.hops_suspected += s.hops_suspected;
                        t.hops_shunned += s.hops_shunned;
                        t.announcements_deferred += s.announcements_deferred;
                        t.retractions_sent += s.retractions_sent;
                        t.seqreqs_sent += s.seqreqs_sent;
                        t.infeasible += s.infeasible;
                        t.dropped_no_route += s.dropped_no_route;
                        t.dropped_pending += s.dropped_pending;
                        t.dropped_ttl += s.dropped_ttl;
                        t.dials += s.dials;
                        t.resolves += s.resolves;
                        t.gateway_out += s.gateway_out;
                        t.dropped_budget += s.dropped_budget;
                        t.dropped_queue += s.dropped_queue;
                    }
                    let mut d = mycel_net::mesh::dtn::DtnStats::default();
                    let (mut peak, mut avg) = (0u64, 0.0f64);
                    let mut kinds = [0u64; 4];
                    for r in &sim.routers {
                        for (k, b) in kinds.iter_mut().zip(r.ctrl_by_kind) {
                            *k += b;
                        }
                        if let Some(c) = &r.dtn {
                            let s = c.stats();
                            d.originated += s.originated;
                            d.accepted += s.accepted;
                            d.delivered += s.delivered;
                            d.handed_on += s.handed_on;
                            d.expired += s.expired;
                            d.cleared_by_receipt += s.cleared_by_receipt;
                            d.refused += s.refused;
                        }
                        peak = peak.max(r.buffer_peak);
                        avg += r.buffer_area / sim.now.max(1) as f64;
                    }
                    let n = sim.routers.len().max(1) as f64;
                    let secs = (sim.now as f64 / SEC as f64).max(1e-9);
                    json!({"loops": sh.loops.get(), "announcements_sent": t.announcements_sent,
                           "announcements_received": t.announcements_received, "announcements_limited": t.announcements_limited,
                           "announcements_stale": t.announcements_stale, "announcements_suppressed": t.announcements_suppressed,
                           "announcements_implausible": t.announcements_implausible, "neighbours_distrusted": t.neighbours_distrusted, "hops_suspected": t.hops_suspected,
                           "hops_shunned": t.hops_shunned, "announcements_deferred": t.announcements_deferred,
                           "retractions_sent": t.retractions_sent, "seqreqs_sent": t.seqreqs_sent, "infeasible": t.infeasible,
                           "dropped_no_route": t.dropped_no_route, "dropped_pending": t.dropped_pending, "dropped_ttl": t.dropped_ttl,
                           "dials": t.dials, "resolves": t.resolves, "gateway_out": t.gateway_out,
                           "dropped_budget": t.dropped_budget, "dropped_queue": t.dropped_queue,
                           "routes_up": sh.routes_up.get(), "routes_down": sh.routes_down.get(),
                           "dtn_originated": d.originated, "dtn_accepted": d.accepted, "dtn_delivered": d.delivered, "dtn_handed_on": d.handed_on,
                           "dtn_expired": d.expired, "dtn_cleared_by_receipt": d.cleared_by_receipt, "dtn_refused": d.refused,
                           "buffer_peak_bytes": peak, "buffer_avg_bytes": avg / n,
                           "control_b_s_per_device": {
                               "routing": kinds[0] as f64 / n / secs, "carrier": kinds[1] as f64 / n / secs,
                               "dials": kinds[2] as f64 / n / secs, "other": kinds[3] as f64 / n / secs}})
                },
            )
        }
        Model::Main | Model::StandIn | Model::SenderHolds => {
            let cfg = Rc::new(match model {
                Model::Main => Cfg::main(),
                Model::StandIn => Cfg::global(),
                _ => Cfg::sender_holds(),
            });
            go(w, plan, seed, until, sample, &name, |i, _| Mycel::new(i, cfg.clone(), plan.role(i)), mycel_extra)
        }
        Model::Epidemic | Model::Spray(_) | Model::Prophet | Model::Flood(_) => {
            let kind = match model {
                Model::Spray(l) => Kind::SprayAndWait(l),
                Model::Prophet => Kind::Prophet,
                Model::Flood(h) => Kind::Flood { hops: h, window_ms: 200, suppress: 1 },
                _ => Kind::Epidemic,
            };
            let inet: Rc<Vec<NodeId>> =
                Rc::new((0..w.specs.len() as NodeId).filter(|i| w.specs[*i as usize].inet.is_some()).collect());
            let opts = plan.baseline.unwrap_or_default();
            let flood: Rc<crate::tier2::dtn::FloodStats> = Rc::default();
            go(
                w,
                plan,
                seed,
                until,
                sample,
                &name,
                |i, _| Dtn::with(i, kind, opts, inet.clone(), flood.clone()),
                |sim| {
                    let peak = sim.routers.iter().map(|r| r.buffer_peak).max().unwrap_or(0);
                    let avg = sim.routers.iter().map(|r| r.buffer_area / sim.now.max(1) as f64).sum::<f64>()
                        / sim.routers.len().max(1) as f64;
                    json!({"buffer_peak_bytes": peak, "buffer_avg_bytes": avg})
                },
            )
        }
    }
}

fn row(m: &T2Metrics) -> String {
    format!(
        "**{}**: delivered {}/{} feasible ({:.0}%); latency p50 {} s, p95 {} s; optimality p50 {}×, p95 {}×, p99 {}×; \
         round trip p95 {} s; copies/msg {:.1}, hand-offs/msg {:.1}; control {} B/s per device; {:.1} s wall",
        m.model,
        m.delivered,
        m.feasible,
        100.0 * m.delivery_ratio,
        fmt(m.latency_s.p50),
        fmt(m.latency_s.p95),
        fmt(m.optimality.p50),
        fmt(m.optimality.p95),
        fmt(m.optimality.p99),
        fmt(m.round_trip_s.p95),
        m.copies_per_msg,
        m.handoffs_per_msg,
        fmt(m.ctrl_bytes_per_node_s),
        m.wall_s,
    )
}

fn inf_if_none(m: &T2Metrics, x: f64) -> f64 {
    if m.delivered == 0 { f64::INFINITY } else { x }
}

/// The standard objectives on the candidate's numbers.
fn hold(r: &mut ScenarioResult, m: &T2Metrics, min_delivery: f64, max_p95_s: f64, max_opt_p95: f64) {
    r.at_least("delivery (of feasible)", m.delivery_ratio * 100.0, min_delivery * 100.0, "%");
    r.at_most("latency p95", inf_if_none(m, m.latency_s.p95), max_p95_s, "s");
    r.at_most("optimality p95 (achieved / fastest feasible)", inf_if_none(m, m.optimality.p95), max_opt_p95, "×");
}

fn headline(r: &mut ScenarioResult, m: &T2Metrics) {
    r.headline(format!(
        "{}: {:.0}% delivered, p95 {} s, optimality p50/p95/p99 {}/{}/{}×",
        m.model,
        100.0 * m.delivery_ratio,
        fmt(m.latency_s.p95),
        fmt(m.optimality.p50),
        fmt(m.optimality.p95),
        fmt(m.optimality.p99)
    ));
}

/// Run the candidate and the references; report them all.
fn compare(
    r: &mut ScenarioResult,
    o: &Opts,
    w: &World,
    plan: &Plan,
    until: Time,
    sample: Option<usize>,
    refs: &[Model],
) -> (Run, Vec<Run>) {
    let cand_model = Model::of(o.candidate);
    let models: Vec<Model> =
        std::iter::once(cand_model).chain(refs.iter().copied().filter(|m| *m != cand_model)).collect();
    let mut others: Vec<Run> = models.par_iter().map(|m| run(*m, w, plan, o.seed, until, sample)).collect();
    let cand = others.remove(0);
    headline(r, &cand.m);
    r.note(row(&cand.m));
    if !cand.extra.is_null() {
        r.note(format!("{} counters: {}", cand.m.model, cand.extra));
    }
    for x in &others {
        r.note(row(&x.m));
    }
    let mut all: Vec<serde_json::Value> = vec![json!({"metrics": cand.m, "extra": cand.extra})];
    all.extend(others.iter().map(|x| json!({"metrics": x.m, "extra": x.extra})));
    r.metrics = serde_json::Value::Array(all);
    (cand, others)
}

fn expect(r: &mut ScenarioResult, o: &Opts, _needs_dtn: bool) {
    if o.candidate == Candidate::Main {
        r.expect_fail(NEEDS_GLOBAL);
    }
}

fn dev(area: u32, xy: (f64, f64), radios: &[Tech], inet: Option<Inet>) -> NodeSpec {
    NodeSpec { area, xy, radios: Techs::of(radios), inet, mobility: Mobility::Static, online: true }
}

// ───────────────────────────── us-eu ─────────────────────────────

/// The user's question: a phone in the US with only Bluetooth, several hops
/// from the nearest device with internet, messages and calls a
/// Bluetooth-only phone in Europe behind its own gateway.
fn us_eu(o: Opts) -> ScenarioResult {
    let mut r =
        ScenarioResult::new("us-eu", "US to Europe: BLE-only phones 3–6 hops from a gateway", 2, o.seed, o.scale);
    let mut rng = Rng::new(o.seed);
    let mut w = World { areas: Vec::new(), specs: Vec::new() };
    let mut sources = Vec::new();
    for (i, hops) in (3..=6).enumerate() {
        let area = w.areas.len() as u32;
        w.areas.push(Area { latlon: (40.71 + i as f64 * 0.01, -74.0), env: Env::Outdoor });
        sources.push(w.specs.len() as NodeId);
        for h in 0..hops {
            w.specs.push(ble_only(area, (h as f64 * 50.0, 0.0), None));
        }
        w.specs.push(ble_only(area, (hops as f64 * 50.0, 0.0), Some(Inet { access: Access::Lte, nat: Nat::Hard })));
        for _ in 0..o.n(20, 3) {
            w.specs.push(ble_only(area, (rng.range(0.0, hops as f64 * 50.0), rng.range(-30.0, 30.0)), None));
        }
    }
    let eu = w.areas.len() as u32;
    w.areas.push(Area { latlon: (51.51, -0.13), env: Env::Outdoor });
    let dst = w.specs.len() as NodeId;
    w.specs.push(ble_only(eu, (0.0, 0.0), None));
    w.specs.push(ble_only(eu, (50.0, 0.0), None));
    w.specs.push(ble_only(eu, (100.0, 0.0), Some(Inet { access: Access::Fibre, nat: Nat::Easy })));
    let per = o.n(10, 3);
    let mut plan = Plan::default();
    for (i, s) in sources.iter().enumerate() {
        for k in 0..per {
            plan.sends.push((30 * SEC + (k as Time * 7 + i as Time) * SEC, *s, dst, 1000, false));
        }
        plan.sends.push((40 * SEC + i as Time * SEC, *s, dst, 300, true));
        plan.sends.push((90 * SEC + i as Time * SEC, *s, dst, 300, true));
    }
    let until = 30 * SEC + per as Time * 7 * SEC + 90 * SEC;
    let (cand, _) = compare(&mut r, &o, &w, &plan, until, None, &[Model::Main, Model::StandIn]);
    hold(&mut r, &cand.m, 0.99, 5.0, 3.0);
    r.at_most(
        "call setup / message round trip p95",
        if cand.m.round_trip_s.n == 0 { f64::INFINITY } else { cand.m.round_trip_s.p95 },
        3.0,
        "s",
    );
    expect(&mut r, &o, false);
    r.note("Path: the US phone's packets climb 3–6 Bluetooth hops along its default route to the LTE phone (a gateway by total cost), which resolves the London phone's record (it names the London gateway), dials it over the internet, and the London gateway carries them the last two Bluetooth hops. Main before GLOBAL never crossed the internet, so nothing arrives although the oracle finds a sub-second path.");
    r
}

// ───────────────────────────── gateway-choice ─────────────────────────────

fn gateway_choice(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "gateway-choice",
        "Gateway by total cost: near slow uplink vs far fibre",
        2,
        o.seed,
        o.scale,
    );
    let mut w = World {
        areas: vec![
            Area { latlon: (40.71, -74.0), env: Env::Outdoor },
            Area { latlon: (51.51, -0.13), env: Env::Indoor },
        ],
        specs: Vec::new(),
    };
    w.specs.push(dev(0, (0.0, 0.0), &[Tech::Ble, Tech::Awdl], None));
    let near = w.specs.len() as NodeId;
    w.specs.push(dev(0, (40.0, 0.0), &[Tech::Ble], Some(Inet { access: Access::Slow, nat: Nat::Easy })));
    w.specs.push(dev(0, (-90.0, 0.0), &[Tech::Awdl], None));
    w.specs.push(dev(0, (-180.0, 0.0), &[Tech::Awdl], None));
    let far = w.specs.len() as NodeId;
    w.specs.push(dev(0, (-270.0, 0.0), &[Tech::Awdl], Some(Inet { access: Access::Fibre, nat: Nat::Easy })));
    let dst = w.specs.len() as NodeId;
    // the recipient: a laptop without internet, next to a home server in London
    w.specs.push(dev(1, (0.0, 0.0), &[Tech::Ble, Tech::WifiDirect], None));
    w.specs.push(dev(
        1,
        (10.0, 0.0),
        &[Tech::Ble, Tech::WifiDirect],
        Some(Inet { access: Access::Fibre, nat: Nat::Open }),
    ));
    let sizes: Vec<u32> =
        [1_000u32, 100_000, 1_000_000].iter().flat_map(|s| std::iter::repeat_n(*s, o.n(10, 3))).collect();
    let mut plan = Plan::default();
    for (i, s) in sizes.iter().enumerate() {
        plan.sends.push((20 * SEC + i as Time * 3 * SEC, 0, dst, *s, false));
    }
    let until = 20 * SEC + sizes.len() as Time * 3 * SEC + 90 * SEC;
    let cand_model = Model::of(o.candidate);
    // relayed bytes through each gateway, and optimality by size, for the candidate
    let shared = Rc::new(Shared::default());
    let by_size = |msgs: &[crate::tier2::engine::MsgRecord], size: u32| -> crate::stats::Summary {
        let v: Vec<f64> = msgs
            .iter()
            .filter(|m| m.size == size)
            .filter_map(|m| Some((m.delivered? - m.sent) as f64 / (m.optimal? - m.sent).max(1) as f64))
            .collect();
        crate::stats::Summary::of(&v)
    };
    let (via_far, via_near, sizes_opt) = match cand_model {
        Model::Global(g) => {
            let mut sim = Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| {
                Global::new(i, global_cfg(g, o.seed, i), shared.clone())
            });
            plan.apply(&mut sim);
            sim.start();
            sim.run(until);
            sim.finish();
            Oracle::new(&sim).annotate(&mut sim, None);
            let so: Vec<(u32, crate::stats::Summary)> =
                [1_000u32, 100_000, 1_000_000].iter().map(|s| (*s, by_size(&sim.core.msgs, *s))).collect();
            (
                sim.core.counters[far as usize].relay_bytes as f64,
                sim.core.counters[near as usize].relay_bytes as f64,
                so,
            )
        }
        _ => {
            let cfg = Rc::new(if cand_model == Model::Main { Cfg::main() } else { Cfg::global() });
            let mut sim =
                Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| Mycel::new(i, cfg.clone(), Role::Honest));
            plan.apply(&mut sim);
            sim.start();
            sim.run(until);
            sim.finish();
            Oracle::new(&sim).annotate(&mut sim, None);
            let so: Vec<(u32, crate::stats::Summary)> =
                [1_000u32, 100_000, 1_000_000].iter().map(|s| (*s, by_size(&sim.core.msgs, *s))).collect();
            (
                sim.core.counters[far as usize].relay_bytes as f64,
                sim.core.counters[near as usize].relay_bytes as f64,
                so,
            )
        }
    };
    for (size, s) in &sizes_opt {
        r.note(format!("{} B messages: optimality p50 {}×, p95 {}× (n={})", size, fmt(s.p50), fmt(s.p95), s.n));
    }
    let share = via_far / (via_far + via_near).max(1.0);
    let (cand, _) = compare(&mut r, &o, &w, &plan, until, None, &[Model::Main, Model::StandIn]);
    r.at_least("delivery (of feasible)", cand.m.delivery_ratio * 100.0, 99.0, "%");
    r.at_least("relayed bytes through the far fibre gateway", 100.0 * share, 95.0, "%");
    let small = sizes_opt.first().map(|x| x.1).unwrap_or_default();
    r.at_most(
        "optimality p50, 1 KB messages (routing)",
        if small.n == 0 { f64::INFINITY } else { small.p50 },
        2.0,
        "×",
    );
    expect(&mut r, &o, false);
    r.headline(format!("{:.0}% of relayed bytes via the far fibre gateway", 100.0 * share));
    r.note("Total cost per hop is latency + size/rate and the gateway adds its uplink: for 100 KB the near gateway costs ~2.5 s of Bluetooth + 10 s of uplink, the far one ~30 ms of AWDL + fibre. Optimality compares each message with the oracle's fastest path over the same ground truth. The oracle moves a message whole, hop by hop, with no congestion control: larger messages pay QUIC slow start (10 packets, doubling per ~90 ms round trip) on top, and the first message to a destination pays a record lookup (~150 ms) and a dial; so routing is judged on 1 KB messages, and larger ratios are transport cost.");
    r
}

// ───────────────────────────── convergence ─────────────────────────────

/// Next hops, for walking routes through the routers' own tables.
pub trait NextHop {
    fn next(&self, dst: NodeId, now: Time) -> Option<NodeId>;
}

impl NextHop for Global {
    fn next(&self, dst: NodeId, now: Time) -> Option<NodeId> {
        self.core.next_hop_local(&key(dst), now / MS).map(|k| node(&k))
    }
}

impl NextHop for Mycel {
    fn next(&self, dst: NodeId, now: Time) -> Option<NodeId> {
        self.next_hop(dst, now)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Walk {
    Reached(u8),
    /// The devices visited, the last one repeating.
    Loop(Vec<NodeId>),
    Dead,
}

/// Follow next hops from `a` to `b` through the routers' tables.
pub fn walk<R: Router + NextHop>(sim: &Sim<R>, a: NodeId, b: NodeId, max: u8) -> Walk {
    let mut at = a;
    let mut seen = vec![a];
    for h in 1..=max {
        let Some(n) = sim.routers[at as usize].next(b, sim.now) else { return Walk::Dead };
        if !sim.core.neighbours_of(at).contains(&n) {
            return Walk::Dead; // stale: not a neighbour any more
        }
        if n == b {
            return Walk::Reached(h);
        }
        if seen.contains(&n) {
            seen.push(n);
            return Walk::Loop(seen);
        }
        seen.push(n);
        at = n;
    }
    Walk::Dead
}

fn bfs(nbrs: &dyn Fn(NodeId) -> Vec<NodeId>, src: NodeId, max: u8) -> Map<NodeId, u8> {
    let mut seen = Map::default();
    let mut q = std::collections::VecDeque::new();
    seen.insert(src, 0u8);
    q.push_back(src);
    while let Some(u) = q.pop_front() {
        let h = seen[&u];
        if h >= max {
            continue;
        }
        for v in nbrs(u) {
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(v) {
                e.insert(h + 1);
                q.push_back(v);
            }
        }
    }
    seen
}

/// Sampled pairs within `max` radio hops (ground truth).
fn pairs_within<R: Router>(
    sim: &Sim<R>,
    n: usize,
    max: u8,
    k: usize,
    rng: &mut Rng,
    skip: Option<NodeId>,
) -> Vec<(NodeId, NodeId, u8)> {
    let mut out = Vec::new();
    let nb = |u: NodeId| sim.core.neighbours_of(u);
    let mut tries = 0;
    while out.len() < k && tries < k * 20 {
        tries += 1;
        let a = rng.below(n) as NodeId;
        if Some(a) == skip || !sim.core.is_online(a) {
            continue;
        }
        let d = bfs(&nb, a, max);
        let mut cands: Vec<(NodeId, u8)> =
            d.into_iter().filter(|(b, h)| *b != a && *h >= 1 && Some(*b) != skip).collect();
        if cands.is_empty() {
            continue;
        }
        cands.sort_unstable();
        let (b, h) = cands[rng.below(cands.len())];
        out.push((a, b, h));
    }
    out
}

struct ConvResult {
    loop_examples: Vec<String>,
    cold_99: Option<f64>,
    cold_100: Option<f64>,
    loops: u64,
    reconv_99: Option<f64>,
    stretch: f64,
    ctrl_b_s: f64,
}

fn converge<R: Router + NextHop>(mut sim: Sim<R>, n: usize, seed: u64, max_hops: u8) -> ConvResult {
    sim.start();
    let mut rng = Rng::new(seed ^ 0xc0);
    sim.run(MS);
    let pairs = pairs_within(&sim, n, max_hops, 300, &mut rng, None);
    let (mut cold_99, mut cold_100, mut loops) = (None, None, 0u64);
    let mut examples = Vec::new();
    let mut t = 0;
    let mut stretch = Vec::new();
    while t < 40 * SEC {
        t += 100 * MS;
        sim.run(t);
        let mut ok = 0;
        for (a, b, h) in &pairs {
            match walk(&sim, *a, *b, max_hops * 2) {
                Walk::Reached(got) => {
                    ok += 1;
                    if t == 40 * SEC {
                        stretch.push(got as f64 / *h as f64);
                    }
                }
                Walk::Loop(path) => {
                    loops += 1;
                    if examples.len() < 5 {
                        examples.push(format!("t={:.1} s {a}→{b}: {path:?}", t as f64 / SEC as f64));
                    }
                }
                Walk::Dead => {}
            }
        }
        let frac = ok as f64 / pairs.len().max(1) as f64;
        if cold_99.is_none() && frac >= 0.99 {
            cold_99 = Some(t as f64 / SEC as f64);
        }
        if cold_100.is_none() && frac >= 1.0 {
            cold_100 = Some(t as f64 / SEC as f64);
        }
    }
    // the busiest device (most neighbours) fails
    let hub = (0..n as NodeId).max_by_key(|i| (sim.core.degree(*i), *i)).unwrap_or(0);
    sim.act_at(t + 1, Action::Online(hub, false));
    sim.run(t + 2);
    let fail_at = t;
    let pairs2 = pairs_within(&sim, n, max_hops, 300, &mut rng, Some(hub));
    let mut reconv_99 = None;
    while t < fail_at + 30 * SEC {
        t += 100 * MS;
        sim.run(t);
        let mut ok = 0;
        for (a, b, _) in &pairs2 {
            match walk(&sim, *a, *b, max_hops * 2) {
                Walk::Reached(_) => ok += 1,
                Walk::Loop(path) => {
                    loops += 1;
                    if examples.len() < 10 {
                        examples
                            .push(format!("t={:.1} s (after the hub failed) {a}→{b}: {path:?}", t as f64 / SEC as f64));
                    }
                }
                Walk::Dead => {}
            }
        }
        if reconv_99.is_none() && ok as f64 >= 0.99 * pairs2.len() as f64 {
            reconv_99 = Some((t - fail_at) as f64 / SEC as f64);
        }
    }
    let ctrl: u64 = sim.core.counters.iter().map(|c| c.ctrl_bytes).sum();
    ConvResult {
        loop_examples: examples,
        cold_99,
        cold_100,
        loops,
        reconv_99,
        stretch: if stretch.is_empty() { f64::NAN } else { stretch.iter().sum::<f64>() / stretch.len() as f64 },
        ctrl_b_s: ctrl as f64 / n as f64 / (t as f64 / SEC as f64),
    }
}

fn mesh_world(n: usize, seed: u64, m2_per_device: f64) -> World {
    let mut rng = Rng::new(seed);
    let side = (n as f64 * m2_per_device).sqrt();
    World {
        areas: vec![Area { latlon: (48.86, 2.35), env: Env::Outdoor }],
        specs: (0..n).map(|_| phone(0, (rng.range(0.0, side), rng.range(0.0, side)), None, &mut rng)).collect(),
    }
}

fn convergence(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "routing-convergence",
        "Convergence, loops and re-convergence after a hub fails",
        2,
        o.seed,
        o.scale,
    );
    let n = o.n(300, 80);
    // sparse enough that routes are several hops long
    let w = mesh_world(n, o.seed, 2500.0);
    let g = GCfg::routing();
    let shared = Rc::new(Shared::default());
    let gsim = Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| {
        Global::new(i, global_cfg(g, o.seed, i), shared.clone())
    });
    let gr = converge(gsim, n, o.seed, 8);
    let cfg = Rc::new(Cfg::main());
    let msim = Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| Mycel::new(i, cfg.clone(), Role::Honest));
    let mr = converge(msim, n, o.seed, 8);
    let f = |x: Option<f64>| x.map_or("never".into(), |v| format!("{v:.1} s"));
    let c = if o.candidate == Candidate::Main { &mr } else { &gr };
    r.at_most("cold start: 99% of pairs within 8 hops routed", c.cold_99.unwrap_or(f64::INFINITY), 12.0, "s");
    r.at_most("loops seen while walking routes (every 100 ms)", c.loops as f64, 0.0, "");
    r.at_most("after the busiest device fails: 99% routed again", c.reconv_99.unwrap_or(f64::INFINITY), 8.0, "s");
    r.at_most("route length vs shortest (hops)", c.stretch, 1.5, "×");
    if o.candidate == Candidate::Main {
        r.expect_fail(NEEDS_GLOBAL);
    }
    r.headline(format!(
        "global core: 99% routed in {}, 100% in {}, {} loops, re-converged in {}, stretch {:.2}×",
        f(gr.cold_99),
        f(gr.cold_100),
        gr.loops,
        f(gr.reconv_99),
        gr.stretch
    ));
    r.headline(format!("main: 99% in {}, {} loops, re-converged in {}", f(mr.cold_99), mr.loops, f(mr.reconv_99)));
    r.note(format!("{n} phones (BLE + peer Wi-Fi) scattered at one per 2,500 m²; 300 sampled pairs within 8 radio hops; routes are walked hop by hop through each device's own table every 100 ms (a loop = a device repeating). Control traffic: global core {:.0} B/s per device, main {:.0} B/s.", gr.ctrl_b_s, mr.ctrl_b_s));
    for e in &gr.loop_examples {
        r.note(format!("global core loop: {e}"));
    }
    r.metrics = json!({
        "global": {"cold_99_s": gr.cold_99, "cold_100_s": gr.cold_100, "loops": gr.loops, "reconverge_99_s": gr.reconv_99, "stretch": gr.stretch, "ctrl_b_s": gr.ctrl_b_s},
        "main": {"cold_99_s": mr.cold_99, "cold_100_s": mr.cold_100, "loops": mr.loops, "reconverge_99_s": mr.reconv_99, "stretch": mr.stretch, "ctrl_b_s": mr.ctrl_b_s},
    });
    r
}

// ───────────────────────────── flood-scaling ─────────────────────────────

fn flood_scaling(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "flood-scaling",
        "Announcement overhead vs size; fisheye and flood reduction",
        2,
        o.seed,
        o.scale,
    );
    let sizes: Vec<usize> = if o.scale >= 1.0 { vec![250, 500, 1000, 2000] } else { vec![o.n(250, 60)] };
    let ble = Tech::Ble.rate() as f64;
    let now = GCfg::routing();
    let variants = [
        ("now", now),
        ("now, flood reduction on", GCfg { flood_reduction: true, ..now }),
        ("now, fisheye off", GCfg { fisheye: false, ..now }),
        ("before (every 2 s, full scope of 8 hops every 4th, reduction on)", GCfg::before()),
    ];
    // Bluetooth-only phones, one per 900 m² outdoors: ~12 neighbours each
    let worlds: Vec<_> = sizes
        .iter()
        .map(|&n| {
            let mut w = mesh_world(n, o.seed, 900.0);
            for s in w.specs.iter_mut() {
                s.radios = Techs::of(&[Tech::Ble]);
            }
            w
        })
        .collect();
    // steady state: after one full fisheye cycle (cold start is reported
    // apart), over the next cycle (at least 32 s). Every (size, variant) run is
    // independent, so they all run at once: (steady, cold, coverage, wall).
    let jobs: Vec<(usize, usize)> = (0..sizes.len()).flat_map(|i| (0..variants.len()).map(move |v| (i, v))).collect();
    let runs: Vec<(f64, f64, f64, f64)> = jobs
        .par_iter()
        .map(|&(i, v)| {
            let (n, w, g) = (sizes[i], &worlds[i], variants[v].1);
            let cycle = g.announce_every_ms * if g.fisheye { g.far_every.max(1) } else { 1 } * MS;
            let warm = cycle.max(10 * SEC);
            let window = cycle.max(32 * SEC);
            let shared = Rc::new(Shared::default());
            let t = Instant::now();
            let mut sim = Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| {
                Global::new(i, global_cfg(g, o.seed, i), shared.clone())
            });
            sim.start();
            sim.run(warm);
            let ctrl = |sim: &Sim<Global>| sim.core.counters.iter().map(|c| c.ctrl_bytes).sum::<u64>();
            let cold = ctrl(&sim);
            sim.run(warm + window);
            let steady = (ctrl(&sim) - cold) as f64 / n as f64 / (window as f64 / SEC as f64);
            let cold = cold as f64 / n as f64 / (warm as f64 / SEC as f64);
            let wall = t.elapsed().as_secs_f64();
            let mut rng = Rng::new(o.seed);
            let pairs = pairs_within(&sim, n, 8, 200, &mut rng, None);
            let ok = pairs.iter().filter(|(a, b, _)| matches!(walk(&sim, *a, *b, 16), Walk::Reached(_))).count();
            (steady, cold, ok as f64 / pairs.len().max(1) as f64, wall)
        })
        .collect();
    let mains: Vec<f64> = worlds
        .par_iter()
        .map(|w| {
            let cfg = Rc::new(Cfg::main());
            let mut sim =
                Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| Mycel::new(i, cfg.clone(), Role::Honest));
            sim.start();
            sim.run(40 * SEC);
            metrics(&sim, "main", 0.0, None).ctrl_bytes_per_node_s
        })
        .collect();
    let mut rows = Vec::new();
    let mut cand_worst = 0.0f64;
    let mut cand_cov = 1.0f64;
    let mut main_worst = 0.0f64;
    for (i, &n) in sizes.iter().enumerate() {
        let mut line = format!("N={n}:");
        for (v, (label, g)) in variants.into_iter().enumerate() {
            let (steady, cold, cov, wall) = runs[i * variants.len() + v];
            let share = steady / ble;
            if label == "now" {
                cand_worst = cand_worst.max(share);
                cand_cov = cand_cov.min(cov);
            }
            line.push_str(&format!(
                " [{label}: {} B/s per device ({:.1}% of BLE), first cycle {} B/s, {:.0}% routed]",
                fmt(steady),
                100.0 * share,
                fmt(cold),
                100.0 * cov
            ));
            rows.push(json!({"n": n, "variant": label, "every_ms": g.announce_every_ms, "far_every": g.far_every, "fisheye": g.fisheye, "flood_reduction": g.flood_reduction, "ctrl_bytes_per_node_s": steady, "first_cycle_bytes_per_node_s": cold, "ble_share": share, "coverage": cov, "wall_s": wall}));
        }
        let share = mains[i] / ble;
        main_worst = main_worst.max(share);
        line.push_str(&format!(" [main: {} B/s ({:.1}% of BLE)]", fmt(mains[i]), 100.0 * share));
        rows.push(json!({"n": n, "model": "main", "ctrl_bytes_per_node_s": mains[i], "ble_share": share}));
        r.note(line);
    }
    let worst = if o.candidate == Candidate::Main { main_worst } else { cand_worst };
    r.at_most("announcement traffic at the largest N, as a share of one BLE radio", 100.0 * worst, 10.0, "%");
    if o.candidate == Candidate::Global {
        r.at_least("pairs within 8 hops routed, every N", 100.0 * cand_cov, 95.0, "%");
    }
    r.headline(format!("largest N: global core {:.1}% of BLE, main {:.1}%", 100.0 * cand_worst, 100.0 * main_worst));
    r.note("Bluetooth-only phones (one per 900 m², ~12 neighbours each). Each device originates one ~120-byte announcement per period and sends each rebroadcast to each neighbour that hasn't sent it the same one (hop connections are unicast). With fisheye, only every few periods floods the full scope; the others flood 2 hops. Traffic is measured in steady state, over one full fisheye cycle after a first one (whose cost, everyone starting at once, is shown apart). Flood reduction (a device with ≥ 8 neighbours skips a rebroadcast it heard 3 equal copies of) assumes broadcast radios: over unicast hops, the 3 copies reached their senders' neighbours, not ours, and coverage falls. Main floods every announcement 8 hops every 2 s.");
    if o.candidate == Candidate::Main && main_worst > 0.10 {
        r.expect_fail(NEEDS_GLOBAL);
    }
    r.metrics = serde_json::Value::Array(rows);
    r
}

// ───────────────────────────── partial-route ─────────────────────────────

fn partial_route(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "partial-route",
        "Partial route, custody at the break, mule completes it",
        2,
        o.seed,
        o.scale,
    );
    let mut metrics_all = Vec::new();
    for gap in [100.0, 300.0] {
        let mut w = World { areas: vec![Area { latlon: (34.05, -118.24), env: Env::Outdoor }], specs: Vec::new() };
        for x in [0.0, 50.0, 100.0] {
            w.specs.push(ble_only(0, (x, 0.0), None));
        }
        let d_x = 100.0 + gap;
        w.specs.push(ble_only(0, (d_x, 0.0), None));
        let e = w.specs.len() as NodeId;
        w.specs.push(ble_only(0, (d_x + 50.0, 0.0), None));
        w.specs.push(ble_only(0, (d_x + 100.0, 0.0), Some(cellular(&mut Rng::new(o.seed)))));
        let bridge: Vec<NodeId> = (1..)
            .map(|k| 100.0 + 50.0 * k as f64)
            .take_while(|x| *x < d_x)
            .map(|x| {
                w.specs.push(ble_only(0, (x, 0.0), None));
                w.specs.len() as NodeId - 1
            })
            .collect();
        let walk_s = ((d_x + 20.0) - 90.0) / 1.4;
        let t0 = 120 * SEC;
        let t1 = t0 + (walk_s * SEC as f64) as Time;
        let t2 = t1 + 60 * SEC;
        let t3 = t2 + (walk_s * SEC as f64) as Time;
        let mut mule = ble_only(0, (d_x + 20.0, 5.0), None);
        mule.mobility = Mobility::Path(vec![
            (0, (d_x + 20.0, 5.0)),
            (t0, (d_x + 20.0, 5.0)),
            (t1, (90.0, 5.0)),
            (t2, (90.0, 5.0)),
            (t3, (d_x + 20.0, 5.0)),
        ]);
        w.specs.push(mule);
        let mut plan = Plan::default();
        for b in &bridge {
            plan.acts.push((40 * SEC, Action::Online(*b, false)));
        }
        for k in 0..o.n(10, 3) {
            plan.sends.push((60 * SEC + k as Time * 2 * SEC, 0, e, 2000, false));
        }
        let until = t3 + 120 * SEC;
        let mut runs: Vec<Run> = [Model::of(o.candidate), Model::StandIn, Model::SenderHolds]
            .par_iter()
            .map(|m| run(*m, &w, &plan, o.seed, until, None))
            .collect();
        let (holds, stand, cand) = (runs.pop().unwrap(), runs.pop().unwrap(), runs.pop().unwrap());
        r.at_least(&format!("gap {gap} m: delivery"), 100.0 * cand.m.delivery_ratio, 99.0, "%");
        r.at_most(&format!("gap {gap} m: optimality p95"), inf_if_none(&cand.m, cand.m.optimality.p95), 2.0, "×");
        r.headline(format!(
            "gap {gap} m: {} {:.0}%; stand-in custody {:.0}% p50 {} s; sender-holds {:.0}% p50 {} s",
            cand.m.model,
            100.0 * cand.m.delivery_ratio,
            100.0 * stand.m.delivery_ratio,
            fmt(stand.m.latency_s.p50),
            100.0 * holds.m.delivery_ratio,
            fmt(holds.m.latency_s.p50)
        ));
        for x in [&cand, &stand, &holds] {
            r.note(format!("gap {gap} m — {}", row(&x.m)));
        }
        metrics_all.push(json!({"gap": gap, "candidate": cand.m, "stand_in": stand.m, "sender_holds": holds.m}));
    }
    expect(&mut r, &o, true);
    r.note("The messages leave A over the last known (stale) route and wait in custody at C, the break. With a 100 m gap the mule briefly bridges both sides, so a whole route exists for a few seconds and sender-holds also delivers (same time); with 300 m it never does, and only custody delivers: the mule, which was on the far side more recently, gets a copy down the gradient and hands it over when it walks back.");
    r.metrics = serde_json::Value::Array(metrics_all);
    r
}

// ───────────────────────────── disaster-dtn ─────────────────────────────

/// Seeds the full `disaster-dtn` is judged on (the mean of their deliveries).
const DISASTER_SEEDS: u64 = 12;

fn disaster_world(o: &Opts) -> (World, Vec<(NodeId, NodeId)>) {
    let mut rng = Rng::new(o.seed ^ 0xd15a);
    let mut w = World {
        areas: vec![
            Area { latlon: (18.54, -72.34), env: Env::Outdoor },
            Area { latlon: (40.71, -74.01), env: Env::Indoor },
        ],
        specs: Vec::new(),
    };
    let camps = [(100.0, 100.0), (1100.0, 150.0), (200.0, 1100.0), (1050.0, 1050.0)];
    let per = o.n(15, 4);
    let mut members: Vec<Vec<NodeId>> = vec![Vec::new(); camps.len()];
    for (ci, c) in camps.iter().enumerate() {
        for _ in 0..per {
            members[ci].push(w.specs.len() as NodeId);
            w.specs.push(phone(0, (c.0 + rng.range(-40.0, 40.0), c.1 + rng.range(-40.0, 40.0)), None, &mut rng));
        }
    }
    // sparse internet: one satellite terminal at camp 0
    w.specs.push(dev(0, camps[0], &[Tech::Ble, Tech::WifiDirect], Some(Inet { access: Access::Slow, nat: Nat::Easy })));
    for _ in 0..o.n(8, 3) {
        let mut m = phone(0, (rng.range(0.0, 1200.0), rng.range(0.0, 1200.0)), None, &mut rng);
        m.mobility = Mobility::Waypoint { w: 1200.0, h: 1200.0, speed: 1.5, pause: 2 * MIN };
        w.specs.push(m);
    }
    let mut abroad = Vec::new();
    for i in 0..4 {
        abroad.push(w.specs.len() as NodeId);
        w.specs.push(dev(1, (i as f64 * 1000.0, 0.0), &[], Some(world::home(&mut rng))));
    }
    let mut pairs = Vec::new();
    for k in 0..o.n(60, 12) {
        let sc = k % camps.len();
        let src = members[sc][rng.below(per)];
        let dst = if k % 3 == 0 {
            abroad[rng.below(abroad.len())]
        } else {
            let other = (sc + 1 + rng.below(camps.len() - 1)) % camps.len();
            members[other][rng.below(per)]
        };
        pairs.push((src, dst));
    }
    (w, pairs)
}

fn disaster_dtn(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "disaster-dtn",
        "Disaster zone: gradient DTN vs spray-and-wait vs epidemic",
        2,
        o.seed,
        o.scale,
    );
    let plan_for = |pairs: &[(NodeId, NodeId)]| {
        let mut plan = Plan::default();
        for (k, (s, d)) in pairs.iter().enumerate() {
            plan.sends.push((5 * MIN + k as Time * 30 * SEC, *s, *d, 2000, false));
        }
        plan
    };
    let (w, pairs) = disaster_world(&o);
    let plan = plan_for(&pairs);
    let until = 3 * HOUR;
    // One run swings by tens of points with timing alone (seed to seed, or a
    // few bytes more per summary: docs/SIMULATION.md §4, open 12), so the full
    // scenario is judged on the mean of 12 seeds (worlds and runs), the given
    // seed first.
    let more_seeds = |k: u64| {
        let ok = Opts { seed: o.seed + k, ..o };
        let (w, pairs) = disaster_world(&ok);
        100.0 * run(Model::of(o.candidate), &w, &plan_for(&pairs), ok.seed, until, None).m.delivery_ratio
    };
    let full = o.scale >= 1.0;
    let ((cand, others), more) = rayon::join(
        || {
            compare(
                &mut r,
                &o,
                &w,
                &plan,
                until,
                None,
                &[Model::Main, Model::StandIn, Model::Prophet, Model::Spray(8), Model::Epidemic, Model::Flood(7)],
            )
        },
        || if full { (1..DISASTER_SEEDS).into_par_iter().map(more_seeds).collect() } else { Vec::new() },
    );
    let epi = others.iter().find(|x| x.m.model == "epidemic").map(|x| x.m.clone()).unwrap_or_default();
    if full {
        let mut per_seed = vec![100.0 * cand.m.delivery_ratio];
        per_seed.extend(more);
        let mean = per_seed.iter().sum::<f64>() / per_seed.len() as f64;
        let (lo, hi) = per_seed.iter().fold((f64::INFINITY, 0.0f64), |(l, h), x| (l.min(*x), h.max(*x)));
        r.at_least(
            &format!("delivery within 3 h (of feasible), mean of seeds {}–{}", o.seed, o.seed + DISASTER_SEEDS - 1),
            mean,
            80.0,
            "%",
        );
        r.note(format!(
            "{} delivery by seed {}–{}: {} (mean {mean:.1}%, min {lo:.0}%, max {hi:.0}%).",
            cand.m.model,
            o.seed,
            o.seed + DISASTER_SEEDS - 1,
            per_seed.iter().map(|x| format!("{x:.0}%")).collect::<Vec<_>>().join(", ")
        ));
    } else {
        r.at_least("delivery within 3 h (of feasible)", 100.0 * cand.m.delivery_ratio, 80.0, "%");
    }
    // replicas, not hand-offs: moving the only copy (custody) makes none.
    // The bound is the carrier's own copy budget for 2 kB bundles (32, set
    // for chat speed: docs/BENCHMARKS.md §6.3); 8 copies deliver less here
    let budget = dtn_cfg(&plan).copies_for(2000) as f64;
    r.at_most("copies per message (replicas)", inf_if_none(&cand.m, cand.m.copies_per_msg), budget, "");
    r.note(format!(
        "{}: {:.1} replicas and {:.1} carrier-to-carrier hand-offs per message (custody moves make up the difference).",
        cand.m.model, cand.m.copies_per_msg, cand.m.handoffs_per_msg
    ));
    r.at_most(
        "latency p50 vs epidemic's",
        inf_if_none(&cand.m, cand.m.latency_s.p50 / epi.latency_s.p50.max(1e-9)),
        3.0,
        "×",
    );
    for x in &others {
        headline(&mut r, &x.m);
    }
    expect(&mut r, &o, true);
    r.note("Epidemic is the delivery-time lower bound for flooding DTN at the price of a copy on nearly every device. Spray-and-wait caps copies at 8 and waits for a carrier to meet the destination. The gradient (stand-in) moves a few copies toward whoever most recently had a way to the internet: the satellite terminal and the rescuers who pass it.");
    r
}

// ───────────────────────────── mailbox ─────────────────────────────

fn mailbox(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("mailbox", "Mailbox: destination offline for hours, one drain", 2, o.seed, o.scale);
    let mut w = World {
        areas: vec![
            Area { latlon: (40.71, -74.0), env: Env::Indoor },
            Area { latlon: (52.52, 13.40), env: Env::Indoor },
        ],
        specs: Vec::new(),
    };
    w.specs.push(ble_only(0, (0.0, 0.0), Some(Inet { access: Access::Lte, nat: Nat::Hard })));
    w.specs.push(ble_only(0, (10.0, 0.0), None));
    w.specs.push(ble_only(0, (15.0, 5.0), Some(Inet { access: Access::Cable, nat: Nat::Easy })));
    w.specs.push(ble_only(1, (0.0, 0.0), Some(Inet { access: Access::Fibre, nat: Nat::Easy })));
    let dst = w.specs.len() as NodeId;
    w.specs.push(ble_only(1, (12.0, 0.0), None));
    let off = 2 * MIN;
    let back = off + 3 * HOUR;
    let n = o.n(20, 4);
    let mut plan = Plan::default();
    plan.acts.push((off, Action::Online(dst, false)));
    plan.acts.push((back, Action::Online(dst, true)));
    let first = off + 10 * MIN;
    for k in 0..n {
        plan.sends.push((first + k as Time * 5 * MIN, (k % 2) as NodeId, dst, 1500, false));
    }
    let until = back + 5 * MIN;
    let (cand, _) = compare(&mut r, &o, &w, &plan, until, None, &[Model::Main, Model::StandIn]);
    r.at_least("delivered after it reappears", cand.m.delivered as f64, n as f64, "messages");
    // the first message waited the longest: its latency minus the wait until `back`
    let last =
        if cand.m.delivered == n { cand.m.latency_s.max - (back - first) as f64 / SEC as f64 } else { f64::INFINITY };
    r.at_most("everything delivered within (after it reappears)", last.max(0.0), 30.0, "s");
    expect(&mut r, &o, true);
    r.note("The Berlin gateway's record for the recipient outlives its absence; senders' gateways send there and the gateway keeps a mailbox until the recipient's announcements return. Without a mailbox, live routing retries end to end for 10 minutes and gives up.");
    r
}

// ───────────────────────────── global-scale ─────────────────────────────

fn global_scale(o: Opts) -> ScenarioResult {
    let mut r =
        ScenarioResult::new("global-scale", "100k devices on 6 continents, mixed connectivity", 2, o.seed, o.scale);
    let n = o.n(100_000, 1500);
    let mut rng = Rng::new(o.seed);
    let (areas, specs) = world::global(n, 80, &mut rng);
    let w = World { areas, specs };
    let n = w.specs.len();
    let msgs = o.n(2000, 200);
    let warm = 2 * MIN;
    let mut plan = Plan { max_neighbours: Some(8), ..Plan::default() };
    for k in 0..msgs {
        let (a, b) = (rng.below(n) as NodeId, rng.below(n) as NodeId);
        if a != b {
            let t = warm + (k as Time * 5 * MIN) / msgs as Time;
            plan.sends.push((t, a, b, 1000, false));
            // and again a minute later: the record and the connection are warm
            plan.sends.push((t + MIN, a, b, 1000, false));
        }
    }
    let until = warm + 5 * MIN + 5 * MIN;
    let refs: &[Model] = if n > 20_000 { &[] } else { &[Model::Main] };
    let (cand, _) = compare(&mut r, &o, &w, &plan, until, Some(400), refs);
    // A first message to a stranger looks up its record (~2 × access +
    // 150 ms) and dials it; the oracle pays neither, so its ratio says more
    // about the oracle than the route. Speed is judged on latency there,
    // and on the ratio once the pair is warm.
    r.at_least("delivery (of feasible)", 100.0 * cand.m.delivery_ratio, 95.0, "%");
    r.at_most("latency p95", inf_if_none(&cand.m, cand.m.latency_s.p95), 10.0, "s");
    if let Some(f) = &cand.first {
        r.at_most("first contact: latency p95", inf_if_none(f, f.latency_s.p95), 3.0, "s");
        r.note(format!("first contact: {}", row(f)));
    }
    if let Some(wm) = &cand.warm {
        r.at_most("warm: optimality p95", inf_if_none(wm, wm.optimality.p95), 5.0, "×");
        r.note(format!("warm: {}", row(wm)));
    }
    r.at_most("control traffic per device", cand.m.ctrl_bytes_per_node_s, 1000.0, "B/s");
    let kind = |k: &str| cand.extra.get("control_b_s_per_device").and_then(|v| v.get(k)).and_then(|v| v.as_f64());
    if let (Some(routing), Some(carrier)) = (kind("routing"), kind("carrier")) {
        r.at_most("of which routing (announcements, seqno requests)", routing, 1000.0, "B/s");
        r.note(format!("Control traffic per device: routing {routing:.0} B/s, store-and-forward carrier {carrier:.0} B/s (summaries of what changed, everything every 60 s; docs/SIMULATION.md §4)."));
    }
    expect(&mut r, &o, false);
    let inet = w.specs.iter().filter(|s| s.inet.is_some()).count();
    r.headline(format!(
        "{n} devices, {:.0}% with internet; {} events in {:.0} s wall",
        100.0 * inet as f64 / n as f64,
        cand.m.events,
        cand.m.wall_s
    ));
    r.note(format!(
        "Relay load ({}): {} devices relayed, Jain fairness {:.2}, the busiest carried {:.1}% of relayed bytes.",
        cand.m.model,
        cand.m.relays,
        cand.m.relay_jain,
        100.0 * cand.m.relay_max_share
    ));
    r
}

// ───────────────────────────── churn ─────────────────────────────

fn churn(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new("churn", "Churn: 30% of devices leave and join each minute", 2, o.seed, o.scale);
    let n = o.n(10_000, 800);
    let mut rng = Rng::new(o.seed ^ 0xc4);
    let (areas, specs) = world::global(n, 60, &mut rng);
    let w = World { areas, specs };
    let n = w.specs.len();
    let (warm, dur) = (2 * MIN, 10 * MIN);
    let mut plan = Plan { max_neighbours: Some(8), ..Plan::default() };
    let mut away: Vec<NodeId> = Vec::new();
    for minute in 0..(dur / MIN) {
        let t = warm + minute * MIN;
        for a in away.drain(..) {
            plan.acts.push((t + rng.below(60) as Time * SEC, Action::Online(a, true)));
        }
        for _ in 0..(n as f64 * 0.15) as usize {
            let d = rng.below(n) as NodeId;
            away.push(d);
            plan.acts.push((t + rng.below(60) as Time * SEC, Action::Online(d, false)));
        }
    }
    let msgs = o.n(1000, 150);
    for k in 0..msgs {
        let (a, b) = (rng.below(n) as NodeId, rng.below(n) as NodeId);
        if a != b {
            plan.sends.push((warm + (k as Time * dur) / msgs as Time, a, b, 1000, false));
        }
    }
    let until = warm + dur + 10 * MIN;
    let (cand, _) = compare(&mut r, &o, &w, &plan, until, Some(300), &[Model::Main, Model::StandIn]);
    hold(&mut r, &cand.m, 0.90, 120.0, 20.0);
    expect(&mut r, &o, false);
    r.note("Each minute 15% of devices switch off and the previous minute's 15% come back (30% toggle). A message is feasible if the oracle finds any path given who was online when; senders retransmit end to end for 10 minutes.");
    r
}

// ───────────────────────────── adversarial ─────────────────────────────

fn adversarial(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "adversarial",
        "Black holes, announcement storm, replays, Sybil gateway",
        2,
        o.seed,
        o.scale,
    );
    let mut rng = Rng::new(o.seed ^ 0xbad);
    let n = o.n(300, 80);
    let mut w = mesh_world(n, o.seed, 900.0);
    for s in w.specs.iter_mut().take(n / 20) {
        s.inet = Some(cellular(&mut rng));
    }
    let bad: Vec<NodeId> = (0..(n / 20).max(2)).map(|_| rng.below(n) as NodeId).collect();
    let storm = rng.below(n) as NodeId;
    let replay = rng.below(n) as NodeId;
    let mut roles = Map::default();
    for b in &bad {
        roles.insert(*b, Role::BlackHole);
    }
    roles.insert(storm, Role::Storm);
    roles.insert(replay, Role::Replayer);
    let mut plan = Plan::default();
    let mut k = 0;
    while plan.sends.len() < o.n(300, 60) && k < 10_000 {
        k += 1;
        let (a, b) = (rng.below(n) as NodeId, rng.below(n) as NodeId);
        if a != b && !roles.contains_key(&a) && !roles.contains_key(&b) {
            plan.sends.push((30 * SEC + plan.sends.len() as Time * 300 * MS, a, b, 1000, false));
        }
    }
    let until = 30 * SEC + plan.sends.len() as Time * 300 * MS + 90 * SEC;
    let attacked = Plan { roles: roles.clone(), ..plan.clone() };
    let sybil = rng.below(n) as NodeId;
    let sybil_plan =
        Plan { poison: Some(sybil), roles: [(sybil, Role::BlackHole)].into_iter().collect(), ..plan.clone() };
    // the same devices as black holes that lie plausibly and drop bundles too
    let liar_plan = Plan { roles: bad.iter().map(|b| (*b, Role::Liar)).collect(), ..plan.clone() };
    let ((clean, liars), ((cand, _), syb)) = rayon::join(
        || {
            rayon::join(
                || run(Model::of(o.candidate), &w, &plan, o.seed, until, None),
                || run(Model::of(o.candidate), &w, &liar_plan, o.seed, until, None),
            )
        },
        || {
            rayon::join(
                || compare(&mut r, &o, &w, &attacked, until, None, &[Model::Main, Model::StandIn]),
                || run(Model::of(o.candidate), &w, &sybil_plan, o.seed, until, None),
            )
        },
    );
    let num = |k1: &str, k2: &str| cand.extra.get(k1).or(cand.extra.get(k2)).and_then(|v| v.as_u64()).unwrap_or(0);
    let limited = num("announcements_limited", "ogm_limited");
    let stale = num("announcements_stale", "ogm_stale");
    let distrusted = num("neighbours_distrusted", "neighbours_distrusted");
    r.at_least(
        "delivery with 5% black holes + a storm + a replayer (of feasible)",
        100.0 * cand.m.delivery_ratio,
        90.0,
        "%",
    );
    r.at_least(
        "delivery vs the same run without attackers",
        100.0 * cand.m.delivery_ratio / clean.m.delivery_ratio.max(1e-9),
        90.0,
        "%",
    );
    r.check("storm announcements rate-limited", limited > 0, format!("{limited} dropped by per-neighbour limits"));
    r.check("replayed announcements dropped as stale", stale > 0, format!("{stale} stale"));
    r.at_least(
        "delivery with 5% black holes lying plausibly, dropping packets and bundles (of feasible)",
        100.0 * liars.m.delivery_ratio,
        90.0,
        "%",
    );
    r.check(
        "black holes' impossible routes refused",
        o.candidate != Candidate::Global || distrusted > 0,
        format!("{distrusted} times a device stopped routing through a lying neighbour"),
    );
    r.headline(format!(
        "{}: clean {:.0}%, attacked {:.0}%, Sybil gateway {:.0}%, black holes lying plausibly {:.0}%",
        cand.m.model,
        100.0 * clean.m.delivery_ratio,
        100.0 * cand.m.delivery_ratio,
        100.0 * syb.m.delivery_ratio,
        100.0 * liars.m.delivery_ratio
    ));
    r.note(row(&clean.m));
    r.note(format!(
        "Black holes lying plausibly (the same devices claim to be one hop from everyone at the least cost an honest relay could report, and drop packets and bundles alike; nothing an announcement shows gives them away, but the destination's acknowledgements don't come back: the source moves off a next hop after two timeouts and spreads its bundle's copies; docs/SIMULATION.md §4, fixed 21): {}",
        row(&liars.m)
    ));
    r.note(format!(
        "Sybil gateway (every lookup also returns a free route via it, and it swallows what it gets): {}",
        row(&syb.m)
    ));
    r.note("Forged announcements (bad signatures) are covered by the core's and wire.rs's own tests (the simulator skips signature checks). Black holes here re-announce every route at zero cost and drop all transit packets: a cost no honest relay can send, so their neighbours stop routing through them (`mesh/core.rs`, distrust). In the real node several routes are open QUIC paths at once; in this simulation a packet takes the core's single best next hop, so the numbers are a worst case for black holes.");
    if o.candidate == Candidate::Main {
        r.expect_fail(NEEDS_GLOBAL);
    }
    r
}

// ───────────────────────────── trace replay ─────────────────────────────

/// A world for a contact trace: one device per trace node, far apart (no
/// links from geometry), every contact a trace event over The ONE's
/// default Bluetooth interface (250 kB/s).
/// The scenario's carrier settings, with `MYCEL_DTN` knobs on top (e.g.
/// `MYCEL_DTN=spray=focus,gradient=both`; see `DtnConfig::tune`).
fn dtn_cfg(plan: &Plan) -> mycel_net::mesh::dtn::DtnConfig {
    let mut cfg = plan.dtn.clone().unwrap_or_default();
    if let Ok(k) = std::env::var("MYCEL_DTN") {
        cfg.tune(&k).expect("MYCEL_DTN");
    }
    cfg
}

fn trace_world(t: &crate::traces::Trace) -> (World, Vec<(Time, Action)>) {
    let w = World {
        areas: vec![Area { latlon: (52.2, 0.12), env: Env::Indoor }],
        specs: (0..t.nodes)
            .map(|i| NodeSpec {
                area: 0,
                xy: (i as f64 * 1000.0, 0.0),
                radios: Techs::of(&[Tech::OneBt]),
                inet: None,
                mobility: Mobility::Static,
                online: true,
            })
            .collect(),
    };
    let bt = Techs::of(&[Tech::OneBt]);
    let mut acts = Vec::new();
    for (s, e, a, b) in &t.contacts {
        acts.push((*s, Action::Contact(*a, *b, bt, true)));
        acts.push(((*e).max(*s + 1), Action::Contact(*a, *b, bt, false)));
    }
    (w, acts)
}

fn trace_replay(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "trace-replay",
        "Real contact traces (CRAWDAD Haggle) with The ONE's workload",
        2,
        o.seed,
        o.scale,
    );
    let trace = match std::env::var("MYCEL_TRACE") {
        Ok(p) => match crate::traces::load(std::path::Path::new(&p)) {
            Ok(t) => t,
            Err(e) => {
                r.check("load MYCEL_TRACE", false, e.to_string());
                return r;
            }
        },
        Err(_) => {
            r.note("No MYCEL_TRACE set: using a synthetic trace of the same shape (bench/fetch.sh traces gets the real Haggle traces into bench/data/). Numbers below are for the synthetic trace.");
            crate::traces::synthetic(o.n(40, 12), (o.n(72, 12) as Time) * 3600 * SEC, o.seed)
        }
    };
    let (w, acts) = trace_world(&trace);
    // The ONE's default workload: a message every 25–35 s between random
    // devices, 500 kB–1 MB, TTL 300 min; buffers of 5 MB, FIFO drop.
    let mut rng = Rng::new(o.seed);
    let mut plan = Plan { acts, ..Plan::default() };
    let mut t = 25 * SEC;
    let ttl = 300 * MIN;
    while t + ttl / 4 < trace.duration && plan.sends.len() < o.n(4000, 200) {
        let (a, b) = (rng.below(trace.nodes) as NodeId, rng.below(trace.nodes) as NodeId);
        if a != b {
            plan.sends.push((t, a, b, rng.range(500_000.0, 1_000_000.0) as u32, false));
        }
        t += (rng.range(25.0, 35.0) * SEC as f64) as Time;
    }
    plan.baseline = Some(crate::tier2::dtn::Opts { buffer: 5 << 20, ttl });
    plan.dtn = Some(mycel_net::mesh::dtn::DtnConfig {
        capacity: 5 << 20,
        max_bundle: 1 << 20,
        per_source: 5 << 20,
        max_lifetime: ttl / MS,
        copies: 6,
        ..mycel_net::mesh::dtn::DtnConfig::default()
    });
    plan.bundle_lifetime_ms = Some(ttl / MS);
    let until = trace.duration;
    let models = [Model::Global(GCfg::default()), Model::Epidemic, Model::Prophet, Model::Spray(6), Model::Flood(7)];
    let mut rows = Vec::new();
    let runs: Vec<Run> = models.par_iter().map(|m| run(*m, &w, &plan, o.seed, until, Some(400))).collect();
    for (m, x) in models.into_iter().zip(runs) {
        // The ONE's relayed counts every transfer, the final one to the
        // destination included, so its (relayed − delivered)/delivered is
        // carrier-to-carrier hand-offs per delivered message
        let handed = x.m.handoffs_per_msg * x.m.sent as f64;
        let overhead = if x.m.delivered == 0 { f64::INFINITY } else { handed / x.m.delivered as f64 };
        let peak = x.extra.get("buffer_peak_bytes").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let avg = x.extra.get("buffer_avg_bytes").and_then(|v| v.as_f64()).unwrap_or(0.0);
        r.note(format!(
            "**{}**: delivered {:.1}% of sent ({}/{}), {:.1}% of feasible; latency p50 {} s, p95 {} s; overhead ratio {} (The ONE's (relayed − delivered)/delivered); buffer avg {:.0} kB, peak {:.0} kB",
            x.m.model,
            100.0 * x.m.delivered as f64 / x.m.sent.max(1) as f64,
            x.m.delivered,
            x.m.sent,
            100.0 * x.m.delivery_ratio,
            fmt(x.m.latency_s.p50),
            fmt(x.m.latency_s.p95),
            fmt(overhead),
            avg / 1e3,
            peak / 1e3
        ));
        rows.push(json!({"model": x.m.model, "metrics": x.m, "overhead_ratio": overhead, "buffer_peak_bytes": peak, "buffer_avg_bytes": avg, "extra": x.extra}));
        if matches!(m, Model::Global(_)) {
            r.at_least("global + DTN: delivery (of feasible)", 100.0 * x.m.delivery_ratio, 30.0, "%");
            headline(&mut r, &x.m);
        }
    }
    r.headline(format!(
        "trace: {} ({} devices, {} contacts over {:.1} h)",
        trace.name,
        trace.nodes,
        trace.contacts.len(),
        trace.duration as f64 / HOUR as f64
    ));
    r.note("Workload as The ONE's default settings (MessageEventGenerator: interval 25–35 s, size 500k–1M, msgTtl 300 min; 5 MB buffers; Bluetooth interface 250 kB/s). `cargo run -p mycel-sim -- export-one` writes the same trace as The ONE connection events, so its Epidemic, PRoPHET, SprayAndWait and MaxProp routers can run on identical input (see docs/SIMULATION.md). MaxProp isn't reimplemented here.");
    r.metrics = serde_json::Value::Array(rows);
    r
}

// ───────────────────────────── flooding hop limit ─────────────────────────────

fn flood_hop_limit(o: Opts) -> ScenarioResult {
    let mut r = ScenarioResult::new(
        "flood-hop-limit",
        "Managed flooding: reach vs usefulness by hop limit (Meshtasticator check)",
        2,
        o.seed,
        o.scale,
    );
    // a neighbourhood mesh: BLE outdoors, one device per 625 m² (~18 in
    // range), about 6 hops across, like the small LoRa meshes Meshtasticator models
    let n = o.n(100, 60);
    let mut w = mesh_world(n, o.seed, 625.0);
    for s in w.specs.iter_mut() {
        s.radios = Techs::of(&[Tech::Ble]);
    }
    let mut rng = Rng::new(o.seed);
    let msgs = o.n(60, 20);
    let mut rows = Vec::new();
    let mut reach_by_h = Vec::new();
    let mut useful_by_h = Vec::new();
    for h in 1..=7u8 {
        for suppress in [1u8, 255] {
            let flood: Rc<crate::tier2::dtn::FloodStats> = Rc::default();
            let kind = Kind::Flood { hops: h, window_ms: 200, suppress };
            let mut sim = Sim::new(w.areas.clone(), w.specs.clone(), o.seed, |i, _| {
                Dtn::with(i, kind, crate::tier2::dtn::Opts::default(), Rc::default(), flood.clone())
            });
            for k in 0..msgs {
                sim.send_at(2 * SEC + k as Time * 2 * SEC, rng.below(n) as NodeId, crate::tier2::dtn::BROADCAST, 200);
            }
            sim.start();
            sim.run(2 * SEC + msgs as Time * 2 * SEC + 10 * SEC);
            let reached = flood.reached.borrow();
            let rb = flood.rebroadcasts.borrow();
            let (mut reach, mut useful) = (0.0, 0.0);
            for m in 0..msgs as u32 {
                let got = reached.get(&m).map_or(1, |s| s.len()) as f64;
                let tx = 1.0 + rb.get(&m).map_or(0, |x| x.0) as f64;
                reach += got / n as f64;
                useful += (got - 1.0) / tx;
            }
            reach /= msgs as f64;
            useful /= msgs as f64;
            if suppress == 1 {
                reach_by_h.push(reach);
            } else {
                useful_by_h.push(useful);
            }
            rows.push(json!({"hop_limit": h, "suppression": suppress == 1, "reach": reach, "new_devices_per_transmission": useful}));
            r.note(format!(
                "hop limit {h}, {}: reach {:.0}% of devices, {:.2} new devices per transmission",
                if suppress == 1 { "suppressed rebroadcasts" } else { "no suppression" },
                100.0 * reach,
                useful
            ));
        }
    }
    // qualitative Meshtasticator check: reach rises with the hop limit and
    // saturates, while each transmission reaches fewer new devices
    let rising = reach_by_h.windows(2).all(|w| w[1] + 0.02 >= w[0]);
    let gain =
        |a: usize, b: usize| reach_by_h.get(b).copied().unwrap_or(0.0) - reach_by_h.get(a).copied().unwrap_or(0.0);
    let diminishing = gain(5, 6) < gain(1, 2) / 2.0;
    let falling = useful_by_h.windows(2).all(|w| w[1] <= w[0] + 0.05);
    r.check("reach rises with the hop limit", rising, format!("{reach_by_h:.2?}"));
    r.check(
        "diminishing returns (hop 6→7 gains < half of 2→3)",
        diminishing,
        format!("{:.2} vs {:.2}", gain(5, 6), gain(1, 2)),
    );
    r.check("each transmission reaches fewer new devices as the limit rises", falling, format!("{useful_by_h:.2?}"));
    r.headline(format!(
        "reach by hop limit 1..7: {}",
        reach_by_h.iter().map(|x| format!("{:.0}%", 100.0 * x)).collect::<Vec<_>>().join(", ")
    ));
    r.note("Meshtasticator (Meshtastic's discrete-event simulator) reports the same shape on LoRa: reach grows with the hop limit and levels off around 3–5 for typical densities, while the share of useful rebroadcasts falls and channel load grows, which is why Meshtastic defaults to 3. This model has no collisions (its LoRa model does), so usefulness here only falls through redundancy, not loss; the comparison is qualitative.");
    r.metrics = serde_json::Value::Array(rows);
    r
}
