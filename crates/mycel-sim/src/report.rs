//! Scenario results, service-level objectives, and the Markdown/JSON report.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

/// One objective: what was required and what happened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slo {
    pub name: String,
    pub target: String,
    pub actual: String,
    pub pass: bool,
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
        }
    }

    pub fn expect_fail(&mut self, why: &str) {
        self.expected_fail = Some(why.into());
    }

    /// Require `actual <= max`.
    pub fn at_most(&mut self, name: &str, actual: f64, max: f64, unit: &str) {
        self.slos.push(Slo {
            name: name.into(),
            target: format!("≤ {} {unit}", fmt(max)),
            actual: format!("{} {unit}", fmt(actual)),
            pass: actual.is_finite() && actual <= max,
        });
    }

    /// Require `actual >= min`.
    pub fn at_least(&mut self, name: &str, actual: f64, min: f64, unit: &str) {
        self.slos.push(Slo {
            name: name.into(),
            target: format!("≥ {} {unit}", fmt(min)),
            actual: format!("{} {unit}", fmt(actual)),
            pass: actual.is_finite() && actual >= min,
        });
    }

    pub fn check(&mut self, name: &str, ok: bool, actual: impl Into<String>) {
        self.slos.push(Slo { name: name.into(), target: "true".into(), actual: actual.into(), pass: ok });
    }

    pub fn headline(&mut self, s: impl Into<String>) {
        self.headline.push(s.into());
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    /// Settle the status from the SLOs and the expectation.
    pub fn finish(&mut self) {
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
    let _ = writeln!(s, "| Scenario | Tier | Status | Headline |\n|---|---|---|---|");
    for r in results {
        let _ = writeln!(
            s,
            "| `{}` {} | {} | {} | {} |",
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
