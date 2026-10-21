//! CI-sized runs of the simulation scenarios. Tier 2 is gated on ten seeds
//! each (`mycel_sim::seeds`): invariants on every seed, quality objectives
//! on at least 8 of 10, with thresholds calibrated on other seeds; seeds
//! that once failed are pinned and must pass whole. Tier 1 (real nodes,
//! real time) runs seed 1. Full sizes run with
//! `cargo run --release -p mycel-sim -- all` (see docs/SIMULATION.md); the
//! heavier runs here are `#[ignore]`d: `cargo test -p mycel-sim -- --ignored`.
//! Run optimised (`--release`): the gate is about 10× the runs it was.

use std::sync::RwLock;

use mycel_sim::report::Status;
use mycel_sim::scenarios::{self, Candidate, Opts};
use mycel_sim::seeds::{self, CI_SUITE, GATE_MIN_PASS, PINNED, gate_seeds, replicate, verdict};

/// Tier-1 scenarios measure latency on the wall clock, so each runs alone:
/// never beside another one or the CPU-heavy tier-2 runs.
static WALL_CLOCK: RwLock<()> = RwLock::new(());

/// A tier-2 scenario (virtual time) on the gate's seeds, at its CI size.
fn check(name: &str) {
    let _shared = WALL_CLOCK.read().unwrap_or_else(|e| e.into_inner());
    let scale = CI_SUITE.iter().find(|s| s.0 == name).map(|s| s.1).expect("in the CI suite");
    let v = verdict(&replicate(name, scale, &gate_seeds(), Candidate::Global), GATE_MIN_PASS);
    assert!(v.pass, "{name} failed the multi-seed gate:\n{}", v.markdown());
}

/// A tier-2 scenario on seed 1 only, at `scale`, every objective.
fn check_one(name: &str, scale: f64) {
    let _shared = WALL_CLOCK.read().unwrap_or_else(|e| e.into_inner());
    run(name, scale);
}

/// A tier-1 scenario (real nodes, real time): alone.
fn check_live(name: &str, scale: f64) {
    let _alone = WALL_CLOCK.write().unwrap_or_else(|e| e.into_inner());
    run(name, scale);
}

fn run(name: &str, scale: f64) {
    run_seed(name, scale, 1);
}

fn run_seed(name: &str, scale: f64, seed: u64) {
    let s = scenarios::find(name).expect("scenario");
    let mut r = (s.run)(Opts { seed, scale, candidate: Candidate::Global });
    r.finish();
    let failed: Vec<String> =
        r.failed_slos().iter().map(|f| format!("{}: {} (target {})", f.name, f.actual, f.target)).collect();
    assert!(
        matches!(r.status, Status::Pass | Status::ExpectedFail),
        "{name} (seed {seed}): {:?}\n  {}\n  headline: {}\n  notes: {}",
        r.status,
        failed.join("\n  "),
        r.headline.join("; "),
        r.notes.join("\n  ")
    );
}

// ───────────── tier 2 (virtual time: fast), ten seeds each ─────────────

#[test]
fn us_eu() {
    check("us-eu");
}

#[test]
fn gateway_choice() {
    check("gateway-choice");
}

#[test]
fn partial_route() {
    check("partial-route");
}

#[test]
fn mailbox() {
    check("mailbox");
}

#[test]
fn flood_hop_limit() {
    check("flood-hop-limit");
}

#[test]
fn trace_replay() {
    check("trace-replay");
}

#[test]
fn adversarial() {
    check("adversarial");
}

#[test]
fn routing_convergence() {
    check("routing-convergence");
}

#[test]
fn disaster_dtn() {
    check("disaster-dtn");
}

/// Seeds that once failed (`seeds::PINNED`): every objective, every time.
#[test]
fn pinned_regressions() {
    for (name, scale, seed) in PINNED {
        let _shared = WALL_CLOCK.read().unwrap_or_else(|e| e.into_inner());
        run_seed(name, *scale, *seed);
    }
}

#[test]
fn every_gated_scenario_has_a_test() {
    let here = include_str!("scenarios.rs");
    for (name, _) in seeds::CI_SUITE {
        assert!(here.contains(&format!("check(\"{name}\")")), "{name} is gated but not tested");
    }
}

#[test]
#[ignore = "heavier: the nightly soak runs it on fresh seeds"]
fn liar_ceiling() {
    check_one("liar-ceiling", 0.1);
}

#[test]
#[ignore = "heavier"]
fn flood_scaling() {
    check_one("flood-scaling", 0.1);
}

#[test]
#[ignore = "heavier"]
fn global_scale() {
    check_one("global-scale", 0.01);
}

#[test]
#[ignore = "heavier"]
fn churn() {
    check_one("churn", 0.05);
}

// ───────────── tier 1 (real nodes, real time) ─────────────

#[test]
fn cafe() {
    check_live("cafe", 0.1);
}

#[test]
fn mixed_room() {
    check_live("mixed-room", 0.1);
}

#[test]
fn city_block() {
    check_live("city-block", 0.1);
}

#[test]
#[ignore = "real time: ~1 min"]
fn nat_relay() {
    check_live("nat-relay", 0.1);
}

#[test]
#[ignore = "real time"]
fn office() {
    check_live("office", 0.1);
}

#[test]
#[ignore = "real time"]
fn apartment() {
    check_live("apartment-80211s", 0.1);
}

#[test]
#[ignore = "real time"]
fn multipath() {
    check_live("multipath", 0.1);
}

#[test]
#[ignore = "real time"]
fn rural_line() {
    check_live("rural-line", 0.1);
}

#[test]
#[ignore = "real time"]
fn us_eu_live() {
    check_live("us-eu-live", 0.1);
}

#[test]
#[ignore = "real time"]
fn adversarial_live() {
    check_live("adversarial-live", 0.1);
}

#[test]
#[ignore = "real time, ~1 min"]
fn disaster_live() {
    check_live("disaster-live", 0.1);
}

#[test]
#[ignore = "real time"]
fn shutdown() {
    check_live("shutdown", 0.1);
}

#[test]
#[ignore = "real time"]
fn conference() {
    check_live("conference", 0.1);
}

#[test]
#[ignore = "real time"]
fn scale_ceiling() {
    check_live("scale-ceiling", 0.1);
}
