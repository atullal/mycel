//! CI-sized runs of the simulation scenarios. Each must pass, or fail
//! exactly as expected (a known gap, with its reason in the report). Full
//! sizes run with `cargo run --release -p mycel-sim -- all` (see
//! docs/SIMULATION.md); the heavier CI runs here are `#[ignore]`d:
//! `cargo test -p mycel-sim -- --ignored`.

use std::sync::RwLock;

use mycel_sim::report::Status;
use mycel_sim::scenarios::{self, Candidate, Opts};

/// Tier-1 scenarios measure latency on the wall clock, so each runs alone:
/// never beside another one or the CPU-heavy tier-2 runs.
static WALL_CLOCK: RwLock<()> = RwLock::new(());

/// A tier-2 scenario (virtual time): any number at once.
fn check(name: &str, scale: f64) {
    let _shared = WALL_CLOCK.read().unwrap_or_else(|e| e.into_inner());
    run(name, scale);
}

/// A tier-1 scenario (real nodes, real time): alone.
fn check_live(name: &str, scale: f64) {
    let _alone = WALL_CLOCK.write().unwrap_or_else(|e| e.into_inner());
    run(name, scale);
}

fn run(name: &str, scale: f64) {
    let s = scenarios::find(name).expect("scenario");
    let mut r = (s.run)(Opts { seed: 1, scale, candidate: Candidate::Global });
    r.finish();
    let failed: Vec<String> = r.failed_slos().iter().map(|f| format!("{}: {} (target {})", f.name, f.actual, f.target)).collect();
    assert!(
        matches!(r.status, Status::Pass | Status::ExpectedFail),
        "{name}: {:?}\n  {}\n  headline: {}\n  notes: {}",
        r.status,
        failed.join("\n  "),
        r.headline.join("; "),
        r.notes.join("\n  ")
    );
}

// ───────────── tier 2 (virtual time: fast) ─────────────

#[test]
fn us_eu() {
    check("us-eu", 0.1);
}

#[test]
fn gateway_choice() {
    check("gateway-choice", 0.1);
}

#[test]
fn partial_route() {
    check("partial-route", 0.1);
}

#[test]
fn mailbox() {
    check("mailbox", 0.1);
}

#[test]
fn flood_hop_limit() {
    check("flood-hop-limit", 0.2);
}

#[test]
fn trace_replay() {
    check("trace-replay", 0.05);
}

#[test]
fn adversarial() {
    check("adversarial", 0.1);
}

#[test]
#[ignore = "heavier: ~1 min in debug"]
fn routing_convergence() {
    check("routing-convergence", 0.1);
}

#[test]
#[ignore = "heavier"]
fn disaster_dtn() {
    check("disaster-dtn", 0.1);
}

#[test]
#[ignore = "heavier"]
fn flood_scaling() {
    check("flood-scaling", 0.1);
}

#[test]
#[ignore = "heavier"]
fn global_scale() {
    check("global-scale", 0.01);
}

#[test]
#[ignore = "heavier"]
fn churn() {
    check("churn", 0.05);
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
