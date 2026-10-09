//! Named, seeded, reproducible scenarios with service-level objectives.

pub mod t1;
pub mod t2;

use crate::report::ScenarioResult;

/// Which routing core tier-2 scenarios hold to their objectives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate {
    /// The GLOBAL routing core (`mycel_net::mesh::core`), the real code.
    Global,
    /// The mesh as it was on main before GLOBAL (`mesh.rs`, modelled).
    Main,
    /// The stand-in model of the whole GLOBAL design, including the
    /// store-and-forward parts not yet in the core (a design reference).
    StandIn,
}

#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub seed: u64,
    /// 1.0 = the full scenario; CI runs smaller (e.g. 0.05–0.2).
    pub scale: f64,
    pub candidate: Candidate,
}

impl Opts {
    pub fn ci() -> Opts {
        Opts { seed: 1, scale: 0.1, candidate: Candidate::Global }
    }

    /// `full` scaled, at least `min`.
    pub fn n(&self, full: usize, min: usize) -> usize {
        ((full as f64 * self.scale).round() as usize).max(min)
    }
}

pub struct Scenario {
    pub name: &'static str,
    pub title: &'static str,
    pub tier: u8,
    pub run: fn(Opts) -> ScenarioResult,
}

pub fn all() -> Vec<Scenario> {
    let mut v = t1::scenarios();
    v.extend(t2::scenarios());
    v
}

pub fn find(name: &str) -> Option<Scenario> {
    all().into_iter().find(|s| s.name == name)
}
