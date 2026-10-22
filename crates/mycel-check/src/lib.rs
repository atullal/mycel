//! Bounded model checking of Mycel's sans-IO cores, with
//! [Stateright](https://docs.rs/stateright): the real state machines, not
//! re-written models of them, explored over every interleaving of a small
//! configuration (docs/TESTING.md, "Model checking"; design: WP20 of the
//! simulation-fidelity plan).
//!
//! - [`router`]: `mesh::core::Router`, Babel-style distance vector with
//!   feasibility. Invariants: no routing loop over any usable route, and the
//!   feasibility condition with its inductive invariant.
//! - [`carrier`]: `mesh::dtn::Carrier`, store-and-forward. Invariant: a bundle
//!   taken into custody is never lost. Liveness (checked as recovery from
//!   every reachable state): receipts clear every copy once the destination
//!   is reachable again, and reach every holder connected to a device that
//!   has one when it is not.
//! - [`ble`]: `mycel_link_ble::core::Core`, the BLE connection state
//!   machine. Invariant: both ends never route over different channels once
//!   settled. Liveness (recovery): a lost link is always re-established
//!   while the peer advertises.
//!
//! Each model's network is at least as adversarial as the real one where
//! that is cheap (messages reorder freely; datagrams may be lost, and
//! duplicated within each bound's duplicate budget, which is 0 in most
//! published bounds: docs/TESTING.md), so what holds here holds for the
//! real schedules too, within the bound. Time is
//! abstracted to a few jumps sized to cross the cores' own timers.
//!
//! Every state is the cores' full internal state. The cores aren't `Hash`,
//! so each harness hashes and compares its states by their `Debug` text.
//! That text covers every field, but it is not quite full width:
//! mycel-crypto's `Debug` prints a `SignPk` as its first 4 bytes, a
//! `Hash32` as its first 6 and a `Sig` as its first 4. Two states that
//! differ only beyond those prefixes would be taken for one, and the second
//! never explored. In these harnesses that cannot happen for keys and
//! bundle ids (each device's key, and the one bundle id, differ in their
//! first byte) or signatures (all zero). The router's set of verified
//! announcement hashes holds real hashes, printed to 48 bits: a collision
//! among the few thousand a check sees has probability about 2⁻²⁵ (an
//! estimate: n²/2⁴⁹ for n = 4,096). A harness that adds keys must keep them
//! distinct in their first 4 bytes. (Maps whose iteration order depends on
//! their history can print one state two ways; that costs a duplicate
//! visit, never a missed one.)

pub mod ble;
pub mod carrier;
pub mod router;

use std::fmt::Debug;
use std::hash::Hash;

/// What one bounded check explored, for the published bounds
/// (docs/TESTING.md) and the CI log.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub name: String,
    pub bound: String,
    pub states: usize,
    pub unique: usize,
    pub depth: usize,
    pub secs: f64,
    /// Property violated, with the path that violates it (None: all held).
    pub violation: Option<(String, String)>,
    /// The check stopped at its time budget before exhausting the bound.
    pub timed_out: bool,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<34} {:>10} states {:>10} unique  depth {:>3}  {:>7.1} s  {}  [{}]",
            self.name,
            self.states,
            self.unique,
            self.depth,
            self.secs,
            match (&self.violation, self.timed_out) {
                (Some((p, _)), _) => format!("VIOLATED: {p}"),
                (None, true) => "held (time budget hit: bound not exhausted)".to_string(),
                (None, false) => "held (exhaustive)".to_string(),
            },
            self.bound
        )
    }
}

/// Run a model's checker depth-first (memory: one path, not a frontier)
/// on `threads` threads within `budget`, and summarise.
pub fn run<M>(name: &str, bound: &str, model: M, threads: usize, budget: std::time::Duration) -> Outcome
where
    M: stateright::Model + Send + Sync + 'static,
    M::State: Debug + Hash + Clone + PartialEq + Send + Sync + 'static,
    M::Action: Debug + Clone + PartialEq + Send + Sync + 'static,
{
    use stateright::Checker;
    let props: Vec<&'static str> = model.properties().iter().map(|p| p.name).collect();
    let started = std::time::Instant::now();
    let checker = model
        .checker()
        .threads(threads)
        .timeout(budget)
        .finish_when(stateright::HasDiscoveries::AnyFailures)
        .spawn_dfs()
        .join();
    let secs = started.elapsed().as_secs_f64();
    let mut violation = None;
    for p in props {
        if let Some(path) = checker.discovery(p) {
            // `sometimes` properties are reached, not violated
            if matches!(checker.discovery_classification(p), stateright::DiscoveryClassification::Counterexample) {
                let steps: Vec<(M::State, Option<M::Action>)> = path.into();
                let mut text = String::new();
                for (state, action) in steps {
                    text.push_str(&format!("{state:?}\n"));
                    if let Some(a) = action {
                        text.push_str(&format!("--> {a:?}\n"));
                    }
                }
                violation = Some((p.to_string(), text));
                break;
            }
        }
    }
    let timed_out = violation.is_none() && secs >= budget.as_secs_f64() * 0.98;
    Outcome {
        name: name.to_string(),
        bound: bound.to_string(),
        states: checker.state_count(),
        unique: checker.unique_state_count(),
        depth: checker.max_depth(),
        secs,
        violation,
        timed_out,
    }
}
