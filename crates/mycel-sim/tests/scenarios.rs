//! CI-sized runs of the simulation scenarios. Each must pass, or fail
//! exactly as expected (a known gap, with its reason in the report). Full
//! sizes run with `cargo run --release -p mycel-sim -- all` (see
//! docs/SIMULATION.md); the heavier CI runs here are `#[ignore]`d:
//! `cargo test -p mycel-sim -- --ignored`.

use mycel_sim::report::Status;
use mycel_sim::scenarios::{self, Candidate, Opts};

fn check(name: &str, scale: f64) {
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
    check("cafe", 0.1);
}

#[test]
fn mixed_room() {
    check("mixed-room", 0.1);
}

#[test]
fn city_block() {
    check("city-block", 0.1);
}

#[test]
#[ignore = "real time: ~1 min"]
fn nat_relay() {
    check("nat-relay", 0.1);
}

#[test]
#[ignore = "real time"]
fn office() {
    check("office", 0.1);
}

#[test]
#[ignore = "real time"]
fn apartment() {
    check("apartment-80211s", 0.1);
}

#[test]
#[ignore = "real time"]
fn multipath() {
    check("multipath", 0.1);
}

#[test]
#[ignore = "real time"]
fn rural_line() {
    check("rural-line", 0.1);
}

#[test]
#[ignore = "real time"]
fn us_eu_live() {
    check("us-eu-live", 0.1);
}

#[test]
#[ignore = "real time"]
fn adversarial_live() {
    check("adversarial-live", 0.1);
}

#[test]
#[ignore = "real time, ~1 min"]
fn disaster_live() {
    check("disaster-live", 0.1);
}

#[test]
#[ignore = "real time"]
fn shutdown() {
    check("shutdown", 0.1);
}

#[test]
#[ignore = "real time"]
fn conference() {
    check("conference", 0.1);
}

#[test]
#[ignore = "real time"]
fn scale_ceiling() {
    check("scale-ceiling", 0.1);
}
