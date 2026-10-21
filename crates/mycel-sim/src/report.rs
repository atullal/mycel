//! Scenario results, service-level objectives, and the Markdown/JSON report.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::fidelity::Fidelity;

/// One objective: what was required and what happened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slo {
    pub name: String,
    pub target: String,
    pub actual: String,
    pub pass: bool,
    /// The measured number, for objectives that have one (calibration
    /// across seeds reads it).
    #[serde(default)]
    pub value: Option<f64>,
    /// An invariant (no loops, no route through a black hole after the
    /// defence, convergence at all) must hold on every seed; any other
    /// objective is a quality metric, judged on how many seeds pass
    /// ([`crate::seeds`]).
    #[serde(default)]
    pub invariant: bool,
}

impl Slo {
    /// Make this objective an invariant: zero tolerance on every seed.
    pub fn invariant(&mut self) {
        self.invariant = true;
    }

    /// An invariant only where the candidate models it (`on`); elsewhere a
    /// quality objective, which an expected failure covers.
    pub fn invariant_if(&mut self, on: bool) {
        self.invariant = on;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Pass,
    Fail,
    /// Fails today, as expected, until the named work lands.
    ExpectedFail,
    /// Was expected to fail but passed: the expectation is stale.
    UnexpectedPass,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub name: String,
    pub title: String,
    pub tier: u8,
    pub seed: u64,
    pub scale: f64,
    pub status: Status,
    /// Why it's expected to fail (and what fixes it).
    pub expected_fail: Option<String>,
    pub slos: Vec<Slo>,
    /// Key numbers, one line each, for the summary table.
    pub headline: Vec<String>,
    pub notes: Vec<String>,
    pub metrics: serde_json::Value,
    pub wall_s: f64,
    /// The candidate's optimality ratios (achieved / fastest feasible), one
    /// per delivered message, for pooling across seeds ([`crate::seeds`]):
    /// p99 only means something over thousands. Not written out.
    #[serde(skip)]
    pub optimality: Vec<f64>,
    /// What the result can be trusted for: its fidelity level, the models
    /// it ran without, the uncertainty region it covers
    /// ([`crate::fidelity`]). [`ScenarioResult::finish`] fills in the
    /// tier's default for scenarios that don't set one.
    #[serde(default)]
    pub fidelity: Option<Fidelity>,
}

impl ScenarioResult {
    pub fn new(name: &str, title: &str, tier: u8, seed: u64, scale: f64) -> Self {
        ScenarioResult {
            name: name.into(),
            title: title.into(),
            tier,
            seed,
            scale,
            status: Status::Pass,
            expected_fail: None,
            slos: Vec::new(),
            headline: Vec::new(),
            notes: Vec::new(),
            metrics: serde_json::Value::Null,
            wall_s: 0.0,
            optimality: Vec::new(),
            fidelity: None,
        }
    }

    pub fn expect_fail(&mut self, why: &str) {
        self.expected_fail = Some(why.into());
    }

    fn push(&mut self, slo: Slo) -> &mut Slo {
        self.slos.push(slo);
        self.slos.last_mut().expect("just pushed")
    }

    /// Require `actual <= max`.
    pub fn at_most(&mut self, name: &str, actual: f64, max: f64, unit: &str) -> &mut Slo {
        self.push(Slo {
            name: name.into(),
            target: format!("≤ {} {unit}", fmt(max)),
            actual: format!("{} {unit}", fmt(actual)),
            pass: actual.is_finite() && actual <= max,
            value: Some(actual),
            invariant: false,
        })
    }

    /// Require `actual >= min`.
    pub fn at_least(&mut self, name: &str, actual: f64, min: f64, unit: &str) -> &mut Slo {
        self.push(Slo {
            name: name.into(),
            target: format!("≥ {} {unit}", fmt(min)),
            actual: format!("{} {unit}", fmt(actual)),
            pass: actual.is_finite() && actual >= min,
            value: Some(actual),
            invariant: false,
        })
    }

    pub fn check(&mut self, name: &str, ok: bool, actual: impl Into<String>) -> &mut Slo {
        self.push(Slo {
            name: name.into(),
            target: "true".into(),
            actual: actual.into(),
            pass: ok,
            value: None,
            invariant: false,
        })
    }

    pub fn headline(&mut self, s: impl Into<String>) {
        self.headline.push(s.into());
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    /// Settle the status from the SLOs and the expectation. An expectation
    /// covers quality objectives only: a broken invariant fails the
    /// scenario whatever is expected of it (a candidate that doesn't model
    /// one mustn't emit it as an invariant).
    pub fn finish(&mut self) {
        if self.fidelity.is_none() {
            self.fidelity = Some(Fidelity::tier_default(self.tier));
        }
        if self.slos.iter().any(|s| s.invariant && !s.pass) {
            self.status = Status::Fail;
            return;
        }
        let ok = self.slos.iter().all(|s| s.pass);
        self.status = match (ok, self.expected_fail.is_some()) {
            (true, false) => Status::Pass,
            (false, false) => Status::Fail,
            (false, true) => Status::ExpectedFail,
            (true, true) => Status::UnexpectedPass,
        };
    }

    pub fn failed_slos(&self) -> Vec<&Slo> {
        self.slos.iter().filter(|s| !s.pass).collect()
    }
}

pub fn fmt(x: f64) -> String {
    if !x.is_finite() {
        "∞".into()
    } else if x == 0.0 {
        "0".into()
    } else if x.abs() >= 100.0 {
        format!("{x:.0}")
    } else if x.abs() >= 10.0 {
        format!("{x:.1}")
    } else if x.abs() >= 1.0 {
        format!("{x:.2}")
    } else {
        format!("{x:.3}")
    }
}

fn status_label(s: &Status) -> &'static str {
    match s {
        Status::Pass => "✅ pass",
        Status::Fail => "❌ FAIL",
        Status::ExpectedFail => "⏳ expected fail",
        Status::UnexpectedPass => "⚠️ passes (stale expectation)",
    }
}

/// The Markdown report.
pub fn markdown(results: &[ScenarioResult]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Mycel simulation results\n");
    let _ = writeln!(
        s,
        "Fidelity: the lowest level among the models a result uses (L0 abstract … L4 field-replayed; docs/SIMULATION.md §7). A **bound** ran without a model its result depends on and is never a verdict.\n"
    );
    let _ = writeln!(
        s,
        "| Scenario | Tier | Status | Fidelity | Region | Robust pass | Headline |\n|---|---|---|---|---|---|---|"
    );
    for r in results {
        let (fid, region, robust) = match &r.fidelity {
            Some(f) => (f.short(), f.region.clone(), f.robust_pass.clone().unwrap_or_else(|| "not studied".into())),
            None => ("unlabelled".into(), String::new(), String::new()),
        };
        let _ = writeln!(
            s,
            "| `{}` {} | {} | {} | {fid} | {region} | {robust} | {} |",
            r.name,
            r.title,
            r.tier,
            status_label(&r.status),
            r.headline.join("; ")
        );
    }
    for r in results {
        let _ = writeln!(s, "\n## `{}`: {}\n", r.name, r.title);
        let _ = writeln!(
            s,
            "Tier {} · seed {} · scale {} · {:.1} s wall · {}\n",
            r.tier,
            r.seed,
            r.scale,
            r.wall_s,
            status_label(&r.status)
        );
        if let Some(why) = &r.expected_fail {
            let _ = writeln!(s, "> Expected to fail until: {why}\n");
        }
        if let Some(f) = &r.fidelity {
            let models: Vec<String> = f.models.iter().map(|(_, m, l)| format!("{m} {l:?}")).collect();
            let _ = writeln!(s, "Fidelity {}; models: {}.\n", f.short(), models.join(", "));
            for m in &f.missing {
                let _ = writeln!(
                    s,
                    "- without `{}` ({}, {}{}): {}\n",
                    m.wanted,
                    m.wp,
                    if m.essential { "essential, " } else { "" },
                    m.bias.label(),
                    m.stand_in.as_deref().map_or("no stand-in".to_string(), |x| format!("stand-in `{x}`"))
                );
            }
        }
        let _ = writeln!(s, "| Objective | Target | Actual | |\n|---|---|---|---|");
        for o in &r.slos {
            let _ = writeln!(s, "| {} | {} | {} | {} |", o.name, o.target, o.actual, if o.pass { "✅" } else { "❌" });
        }
        for n in &r.notes {
            let _ = writeln!(s, "\n- {n}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expected_failure_never_hides_a_broken_invariant() {
        let mut r = ScenarioResult::new("x", "x", 2, 1, 1.0);
        r.at_least("delivery", 80.0, 90.0, "%");
        r.expect_fail("a known gap");
        r.finish();
        assert_eq!(r.status, Status::ExpectedFail);
        r.at_most("loops", 1.0, 0.0, "").invariant();
        r.finish();
        assert_eq!(r.status, Status::Fail, "the gap is expected, the loop isn't");
    }
}
