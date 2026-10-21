//! Running catalogue scenarios: one seed, many seeds (judged as the CI
//! gate judges, [`crate::seeds::verdict`]), and robustness studies
//! ([`crate::uq::study`]).

use rayon::prelude::*;
use serde_json::json;

use super::compose::{Composed, Knobs, Size, Swarm, compose};
use super::{Metric, Spec, Status};
use crate::report::{ScenarioResult, fmt};
use crate::scenarios::t2::{Model, run as run_t2};
use crate::seeds::{Verdict, verdict};
use crate::tier2::T2Metrics;
use crate::uq::{Experiment, params::Region};

/// What one run measured.
pub struct Outcome {
    pub m: T2Metrics,
    pub loops: u64,
    pub composed_devices: usize,
    pub attackers: usize,
}

/// Compose and run once.
pub fn outcome(s: &Spec, k: &Knobs, size: Size, swarm: &Swarm, seed: u64) -> anyhow::Result<Outcome> {
    let Composed { world, plan, until, sample, gcfg, devices, attackers } = compose(s, k, size, swarm, seed)?;
    let r = run_t2(Model::Global(gcfg), &world, &plan, seed, until, sample);
    let loops = r.extra.get("loops").and_then(|v| v.as_u64()).unwrap_or(0);
    Ok(Outcome { m: r.m, loops, composed_devices: devices, attackers })
}

/// A metric's value from a run.
pub fn metric_of(metric: Metric, m: &T2Metrics) -> f64 {
    match metric {
        // nothing feasible → no evidence either way: NaN, which fails
        Metric::Delivery if m.feasible == 0 => f64::NAN,
        Metric::Delivery => 100.0 * m.delivery_ratio,
        Metric::LatencyP95 if m.delivered == 0 => f64::INFINITY,
        Metric::LatencyP95 => m.latency_s.p95,
        Metric::Control => m.ctrl_bytes_per_node_s,
    }
}

/// One seed, judged against the scenario's objectives.
pub fn result(s: &Spec, size: Size, label: &str, seed: u64) -> ScenarioResult {
    let mut r = ScenarioResult::new(&s.name, &s.title, 2, seed, size.people as f64 / s.size.people as f64);
    let mut fid = s.fidelity();
    let status = s.status();
    if status == Status::Blocked {
        r.fidelity = Some(fid.clone());
        let waits: Vec<String> = fid
            .missing
            .iter()
            .filter(|m| m.essential && m.stand_in.is_none())
            .map(|m| format!("{} ({})", m.wanted, m.wp))
            .collect();
        r.check("runnable (its key models exist)", false, format!("blocked on {}", waits.join(", ")));
        r.expect_fail(&format!("blocked until {}", waits.join(", ")));
        r.headline(format!("blocked on {}", waits.join(", ")));
        return r;
    }
    let t = std::time::Instant::now();
    let k = Knobs::nominal(s);
    let o = match outcome(s, &k, size, &Swarm::default(), seed) {
        Ok(o) => o,
        Err(e) => {
            r.check("composes", false, format!("{e:#}"));
            return r;
        }
    };
    r.wall_s = t.elapsed().as_secs_f64();
    let m = &o.m;
    r.at_most("packets that came back to a device they had passed (loops)", o.loops as f64, 0.0, "").invariant();
    let bound = fid.is_bound();
    let tag = if bound { format!(" [bound, {}]", fid.bound_bias().label()) } else { String::new() };
    let deliv = if m.feasible == 0 { f64::NAN } else { 100.0 * m.delivery_ratio };
    r.at_least(&format!("delivery (of feasible){tag}"), deliv, 100.0 * s.objectives.delivery_min, "%");
    if let Some(p95) = s.objectives.latency_p95_max_s {
        let v = if m.delivered == 0 { f64::INFINITY } else { m.latency_s.p95 };
        r.at_most(&format!("latency p95{tag}"), v, p95, "s");
    }
    if let Some(c) = s.objectives.control_max_bps {
        r.at_most(&format!("control per device{tag}"), m.ctrl_bytes_per_node_s, c, "B/s");
    }
    if bound {
        // a bound reports its objectives and is never a verdict on them:
        // a miss on an optimistic bound is a finding (reality is worse),
        // a pass is inconclusive
        r.note(format!(
            "A bound, not a verdict: it runs without {} ({}). {}",
            fid.missing.iter().filter(|x| x.essential).map(|x| x.wanted.as_str()).collect::<Vec<_>>().join(", "),
            fid.bound_bias().label(),
            match fid.bound_bias() {
                crate::fidelity::Bias::Optimistic =>
                    "A missed objective is a finding (reality is worse); a pass is inconclusive.",
                crate::fidelity::Bias::Pessimistic =>
                    "A pass is a finding (reality is better); a miss is inconclusive.",
                _ => "Neither a pass nor a miss is conclusive.",
            }
        ));
    }
    r.headline(format!(
        "{} devices{}: {}% of {} feasible delivered, p95 {} s, control {} B/s per device",
        o.composed_devices,
        if o.attackers > 0 { format!(" ({} attackers)", o.attackers) } else { String::new() },
        fmt(deliv),
        m.feasible,
        fmt(m.latency_s.p95),
        fmt(m.ctrl_bytes_per_node_s)
    ));
    r.note(format!(
        "{label}: {} people × adoption {} → {} devices for {} min.",
        size.people,
        s.size.adoption,
        o.composed_devices,
        size.duration / crate::tier2::MIN
    ));
    r.note(format!("Proves (once its models are in): {}", s.proves));
    r.note(format!("Key physics: {}", s.key_physics.join("; ")));
    fid.region = "nominal point (no uncertainty region)".into();
    r.fidelity = Some(fid);
    r.optimality.clone_from(&m.optimality_ratios);
    r.metrics = json!({"metrics": m, "loops": o.loops, "attackers": o.attackers});
    r
}

/// Every seed, judged as CI judges (invariants on every seed, quality on
/// at least `min_pass`).
pub fn replicate(s: &Spec, size: Size, label: &str, seeds: &[u64], min_pass: usize) -> (Vec<ScenarioResult>, Verdict) {
    let rs: Vec<ScenarioResult> = seeds
        .par_iter()
        .map(|seed| {
            let mut r = result(s, size, label, *seed);
            r.finish();
            r
        })
        .collect();
    let v = verdict(&rs, min_pass);
    (rs, v)
}

/// A catalogue scenario as a robustness [`Experiment`].
pub struct Study {
    pub spec: Spec,
    pub size: Size,
    region: Region,
}

impl Study {
    pub fn new(spec: Spec, size: Size) -> anyhow::Result<Study> {
        let region = spec.region()?;
        anyhow::ensure!(region.dims() > 0, "{}: no uncertain parameters ([uq] parameters)", spec.name);
        anyhow::ensure!(spec.status() != Status::Blocked, "{}: blocked", spec.name);
        Ok(Study { spec, size, region })
    }

    /// The objective the study judges: (threshold, higher is better).
    pub fn threshold(&self) -> (f64, bool) {
        match self.spec.uq.metric {
            Metric::Delivery => (100.0 * self.spec.objectives.delivery_min, true),
            Metric::LatencyP95 => (self.spec.objectives.latency_p95_max_s.unwrap_or(f64::INFINITY), false),
            Metric::Control => (self.spec.objectives.control_max_bps.unwrap_or(f64::INFINITY), false),
        }
    }
}

impl Experiment for Study {
    fn name(&self) -> String {
        self.spec.name.clone()
    }

    fn region(&self) -> &Region {
        &self.region
    }

    fn metric(&self) -> String {
        match self.spec.uq.metric {
            Metric::Delivery => "delivery (of feasible) %".into(),
            Metric::LatencyP95 => "latency p95 s".into(),
            Metric::Control => "control B/s per device".into(),
        }
    }

    fn run(&self, x: &[f64], seed: u64) -> f64 {
        let mut k = Knobs::nominal(&self.spec);
        for (p, v) in self.region.params.iter().zip(x) {
            k.set(&p.name, *v).expect("builtin parameters");
        }
        match outcome(&self.spec, &k, self.size, &Swarm::default(), seed) {
            Ok(o) => metric_of(self.spec.uq.metric, &o.m),
            Err(_) => f64::NAN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{all, find};

    /// Every runnable catalogue scenario runs at a small size with no
    /// packet loops (the invariant), and its result carries its fidelity.
    #[test]
    fn every_catalogue_scenario_runs_small_without_loops() {
        let specs: Vec<Spec> = all();
        let out: Vec<(String, Status, ScenarioResult)> = specs
            .par_iter()
            .map(|s| {
                // a tenth of the CI population, at least 40 people, 20 minutes at most
                let ci = Size::ci(s);
                let size = Size {
                    people: (s.size.ci_people / 10).max(40).min(s.size.ci_people),
                    duration: ci.duration.min(20 * crate::tier2::MIN),
                };
                let mut r = result(s, size, "test", 1);
                r.finish();
                (s.name.clone(), s.status(), r)
            })
            .collect();
        for (name, status, r) in &out {
            let f = r.fidelity.as_ref().expect("labelled");
            assert_eq!(f.is_bound(), *status == Status::Bound, "{name}");
            if *status == Status::Blocked {
                assert!(r.headline[0].starts_with("blocked"), "{name}");
                continue;
            }
            for slo in r.slos.iter().filter(|s| s.invariant) {
                assert!(slo.pass, "{name}: {} = {}", slo.name, slo.actual);
            }
        }
        assert!(out.iter().any(|x| x.1 == Status::Blocked), "some scenarios wait for their models");
    }

    #[test]
    fn a_studys_parameters_reach_the_world() {
        let s = find("earthquake").unwrap();
        let st = Study::new(s, Size { people: 300, duration: 30 * crate::tier2::MIN }).unwrap();
        let names: Vec<&str> = st.region().params.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"range_mult"));
        let x = st.region().nominal();
        let a = st.run(&x, 3);
        assert_eq!(a, st.run(&x, 3), "deterministic");
        assert!(a.is_nan() || (0.0..=100.0).contains(&a));
    }
}
