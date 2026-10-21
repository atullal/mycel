//! Swarm testing of the tier-2 GLOBAL core (Groce, Zhang, Eide, Chen and
//! Regehr, "Swarm Testing", ISSTA 2012,
//! <https://www.cs.utah.edu/~regehr/papers/swarm12.pdf>): each run enables
//! a random subset of world features and faults, each with probability
//! 1/2, instead of a fixed configuration with everything on. The paper's
//! finding is that features suppress each other's failures (churn hides a
//! slow liar; mobility hides a partition), so random subsets find bugs a
//! single "everything" configuration misses.
//!
//! Every run is checked against invariants that hold in *every*
//! configuration (no packet loops back to a device it passed; no panic;
//! nothing delivered that wasn't sent). A failing run is minimised by
//! delta debugging over its enabled features (one feature removed at a
//! time until none can go: 1-minimal, Zeller and Hildebrandt 2002) and
//! printed as a line for [`PINNED`], which `mycel-sim swarm` replays first.
//! Worlds are small (about 60 devices) and short, so a CI budget buys many
//! configurations; the regular scenarios cover scale.

use crate::models::Env;
use crate::scenarios::t2::{GCfg, Model, Plan, World, run};
use crate::stats::{Map, Rng};
use crate::tier2::engine::{Mobility, NodeSpec};
use crate::tier2::mycel::Role;
use crate::tier2::world::{ble_only, cellular, phone};
use crate::tier2::{Action, Area, MIN, MS, NodeId, SEC, Time};

/// The features a run may enable (bit i of a mask is `FEATURES[i]`).
pub const FEATURES: [&str; 12] = [
    "internet",          // 10% of devices have the internet (gateways, internet hops)
    "ble-only",          // 30% of devices have only Bluetooth LE
    "mobility",          // 30% of devices walk (random waypoint, 1.4 m/s)
    "churn",             // 10% of devices switch off and back on, each minute
    "internet-flaps",    // devices with the internet lose it for a while
    "store-and-forward", // GLOBAL's DTN carrier on
    "no-fisheye",        // every announcement to the full scope
    "flood-reduction",   // skip rebroadcasts heard 3 times
    "black-holes",       // 5% claim zero-cost routes and drop
    "liars",             // 5% lie plausibly and drop
    "droppers",          // 5% announce honestly and drop
    "partition",         // a third of the devices walk away mid-run and back
];

/// Failing configurations found by swarm runs, minimised: (seed, mask).
/// Replayed first by `mycel-sim swarm`; empty while none has been found.
pub const PINNED: &[(u64, u32)] = &[];

fn on(mask: u32, f: &str) -> bool {
    FEATURES.iter().position(|x| *x == f).is_some_and(|i| mask & (1 << i) != 0)
}

/// The feature names a mask enables.
pub fn names(mask: u32) -> Vec<&'static str> {
    FEATURES.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, f)| *f).collect()
}

/// The configuration a run draws: each feature with probability 1/2.
pub fn draw(seed: u64) -> u32 {
    let mut rng = Rng::new(seed ^ 0x5a4d);
    (0..FEATURES.len()).filter(|_| rng.chance(0.5)).fold(0, |m, i| m | (1 << i))
}

/// What one run showed.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub seed: u64,
    pub mask: u32,
    pub sent: usize,
    pub feasible: usize,
    pub delivered: usize,
    pub loops: u64,
    /// The panic's message, if it panicked.
    pub panic: Option<String>,
}

impl Outcome {
    /// The invariants every configuration must keep; `Err` names the first broken.
    pub fn check(&self) -> Result<(), String> {
        if let Some(p) = &self.panic {
            return Err(format!("panicked: {p}"));
        }
        if self.loops > 0 {
            return Err(format!("{} packets looped back to a device they had passed", self.loops));
        }
        if self.delivered > self.sent {
            return Err(format!("{} delivered of {} sent", self.delivered, self.sent));
        }
        Ok(())
    }
}

/// The world and plan of one configuration (`n` devices).
pub fn build(seed: u64, mask: u32, n: usize) -> (World, Plan, Time, GCfg) {
    let mut rng = Rng::new(seed);
    let side = (n as f64 * 900.0).sqrt();
    let mut specs: Vec<NodeSpec> = (0..n)
        .map(|_| {
            let xy = (rng.range(0.0, side), rng.range(0.0, side));
            if on(mask, "ble-only") && rng.chance(0.3) { ble_only(0, xy, None) } else { phone(0, xy, None, &mut rng) }
        })
        .collect();
    if on(mask, "internet") {
        for s in specs.iter_mut() {
            if rng.chance(0.1) {
                s.inet = Some(cellular(&mut rng));
            }
        }
    }
    if on(mask, "mobility") {
        for s in specs.iter_mut() {
            if rng.chance(0.3) {
                s.mobility = Mobility::Waypoint { w: side, h: side, speed: 1.4, pause: 30 * SEC };
            }
        }
    }
    let w = World { areas: vec![Area { latlon: (48.86, 2.35), env: Env::Outdoor }], specs };
    let (warm, dur) = (60 * SEC, 4 * MIN);
    let mut plan = Plan::default();
    let mut roles: Map<NodeId, Role> = Map::default();
    for (f, role) in [("black-holes", Role::BlackHole), ("liars", Role::Liar), ("droppers", Role::Dropper)] {
        if on(mask, f) {
            for _ in 0..(n / 20).max(1) {
                roles.insert(rng.below(n) as NodeId, role);
            }
        }
    }
    let mut k = 0;
    while plan.sends.len() < 40 && k < 10_000 {
        k += 1;
        let (a, b) = (rng.below(n) as NodeId, rng.below(n) as NodeId);
        if a != b && !roles.contains_key(&a) && !roles.contains_key(&b) {
            plan.sends.push((warm + plan.sends.len() as Time * dur / 40, a, b, 1000, false));
        }
    }
    plan.roles = roles;
    if on(mask, "churn") {
        for minute in 0..(dur / MIN) {
            for _ in 0..(n / 10).max(1) {
                let d = rng.below(n) as NodeId;
                let t = warm + minute * MIN + rng.below(30) as Time * SEC;
                plan.acts.push((t, Action::Online(d, false)));
                plan.acts.push((t + 20 * SEC + rng.below(20) as Time * SEC, Action::Online(d, true)));
            }
        }
    }
    if on(mask, "internet-flaps") {
        for (i, s) in w.specs.iter().enumerate() {
            if s.inet.is_some() && rng.chance(0.5) {
                let t = warm + rng.below(dur as usize / 1000) as Time * MS * 1000;
                plan.acts.push((t, Action::Inet(i as NodeId, false)));
                plan.acts.push((t + MIN, Action::Inet(i as NodeId, true)));
            }
        }
    }
    if on(mask, "partition") {
        let (away, back) = (warm + dur / 4, warm + dur / 2);
        for (i, s) in w.specs.iter().enumerate() {
            if i % 3 == 0 {
                plan.acts.push((away, Action::Move(i as NodeId, (s.xy.0 + 10.0 * side, s.xy.1))));
                plan.acts.push((back, Action::Move(i as NodeId, s.xy)));
            }
        }
    }
    let g = GCfg {
        dtn: on(mask, "store-and-forward"),
        fisheye: !on(mask, "no-fisheye"),
        flood_reduction: on(mask, "flood-reduction"),
        ..GCfg::default()
    };
    (w, plan, warm + dur + 2 * MIN, g)
}

/// Run one configuration and check it.
pub fn run_one(seed: u64, mask: u32, n: usize) -> Outcome {
    let (w, plan, until, g) = build(seed, mask, n);
    let ran =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(Model::Global(g), &w, &plan, seed, until, None)));
    match ran {
        Ok(x) => Outcome {
            seed,
            mask,
            sent: x.m.sent,
            feasible: x.m.feasible,
            delivered: x.m.delivered,
            loops: x.extra.get("loops").and_then(|v| v.as_u64()).unwrap_or(0),
            panic: None,
        },
        Err(e) => Outcome {
            seed,
            mask,
            sent: 0,
            feasible: 0,
            delivered: 0,
            loops: 0,
            panic: Some(
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
            ),
        },
    }
}

/// Delta debugging over the enabled features: drop each one whose removal
/// still fails, until none can go (1-minimal).
pub fn minimise(mask: u32, fails: impl Fn(u32) -> bool) -> u32 {
    let mut m = mask;
    loop {
        let smaller = (0..FEATURES.len()).filter(|i| m & (1 << i) != 0).map(|i| m & !(1 << i)).find(|c| fails(*c));
        match smaller {
            Some(c) => m = c,
            None => return m,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_vary_and_cover_every_feature() {
        let masks: Vec<u32> = (0..64).map(draw).collect();
        let all = masks.iter().fold(0, |a, m| a | m);
        assert_eq!(all, (1 << FEATURES.len()) - 1, "every feature is drawn sometimes");
        assert!(masks.iter().any(|m| m.count_ones() <= 4) && masks.iter().any(|m| m.count_ones() >= 8));
    }

    #[test]
    fn minimising_keeps_only_what_the_failure_needs() {
        // a "failure" that needs features 2 and 7 together
        let need = (1 << 2) | (1 << 7);
        let m = minimise(0b1111_1111_1111, |m| m & need == need);
        assert_eq!(m, need);
    }

    #[test]
    fn pinned_configurations_hold() {
        for &(seed, mask) in PINNED {
            let o = run_one(seed, mask, 60);
            assert!(o.check().is_ok(), "pinned swarm seed {seed} {:?}: {:?}", names(mask), o.check());
        }
    }
}
