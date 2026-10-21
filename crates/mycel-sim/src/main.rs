//! `mycel-sim <scenario|all|t1|t2|ci|soak|list> [--seed N] [--scale X] [--runs K [--min-pass M]] [--candidate main|stand-in] [--out DIR]`
//!
//! Runs scenarios and writes `report.md` and `results.json` into `--out`
//! (default `target/mycel-sim`). `mycel-sim merge DIR... --out DIR` joins
//! runs made separately (e.g. in parallel processes) into one report.
//! `ci` and `soak` are the tier-2 suites at their CI sizes; with `--runs K`
//! each scenario runs on K seeds from the base `--seed` and is judged as
//! CI judges it (`mycel_sim::seeds`), printing every failing seed; `ci`
//! also replays the pinned regression seeds, and `gate.md` holds the
//! verdicts alone.
//!
//! `mycel-sim export-world <scenario,...> [--seed N] [--scale X] --out DIR`
//! writes the exogenous world of every tier-2 run the scenarios make, one
//! JSON file per run; `mycel-sim replay --world FILE [--candidate C]`
//! replays one. `mycel-sim crn [--seed N] [--runs K]` measures what common
//! random numbers buy (docs/SIMULATION.md §1, "World and streams").

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use mycel_sim::report::{Status, markdown};
use mycel_sim::scenarios::{self, Candidate, Opts};
use rayon::prelude::*;

#[derive(Parser)]
#[command(about = "Mycel network simulation: real-world scenarios, scale and routing")]
struct Args {
    /// A scenario name (or several, comma-separated), `all`, `t1`, `t2`,
    /// `list`, `merge`, `fit-latency`, `export-trace` (write MYCEL_TRACE,
    /// or the synthetic trace, as the benchmarks' contacts CSV),
    /// `export-world`, `replay` or `crn`.
    what: String,
    /// For `merge`: directories holding a `results.json` each. For
    /// `export-world`: the scenarios (comma-separated). For `crn`: the
    /// scenarios to measure (default: churn, disaster-dtn, trace-replay).
    dirs: Vec<PathBuf>,
    /// For `replay`: the exported world (a file `export-world` wrote).
    #[arg(long)]
    world: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// 1.0 = full size; smaller for quick runs.
    #[arg(long, default_value_t = 1.0)]
    scale: f64,
    /// Which routing core tier-2 objectives judge: `global` (the GLOBAL
    /// core), `main` (the mesh before it) or `stand-in` (design reference).
    #[arg(long, default_value = "global")]
    candidate: String,
    #[arg(long, default_value = "target/mycel-sim")]
    out: PathBuf,
    /// Replications: run each scenario on this many seeds derived from
    /// `--seed` (the base) and judge them together: invariants on every
    /// seed, quality objectives on at least `--min-pass` of them.
    #[arg(long, default_value_t = 1)]
    runs: usize,
    /// With `--runs`: how many seeds each quality objective must pass on
    /// (default 80%, rounded up).
    #[arg(long)]
    min_pass: Option<usize>,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let all = scenarios::all();
    if a.what == "export-trace" {
        // the trace in MYCEL_TRACE (or the synthetic stand-in) for bench/ (The ONE, dtn-replay)
        let t = match std::env::var("MYCEL_TRACE") {
            Ok(p) => mycel_sim::traces::load(std::path::Path::new(&p))?,
            Err(_) => mycel_sim::traces::synthetic(40, 72 * 3600 * mycel_sim::tier2::SEC, a.seed),
        };
        std::fs::create_dir_all(&a.out)?;
        let path = a.out.join("contacts.csv");
        mycel_sim::traces::export_csv(&t, &path)?;
        eprintln!("{}: {} devices, {} contacts → {}", t.name, t.nodes, t.contacts.len(), path.display());
        return Ok(());
    }
    if a.what == "fit-latency" {
        let dir = std::env::var("MYCEL_PINGS").unwrap_or_else(|_| "bench/data/wondernetwork".into());
        let m = mycel_sim::latency::Measured::load(std::path::Path::new(&dir))?;
        let f = mycel_sim::latency::fit(&m);
        std::fs::create_dir_all(&a.out)?;
        std::fs::write(a.out.join("latency-fit.json"), serde_json::to_string_pretty(&f)?)?;
        println!("{}", serde_json::to_string_pretty(&f)?);
        return Ok(());
    }
    if a.what == "merge" {
        let mut results: Vec<mycel_sim::report::ScenarioResult> = Vec::new();
        for d in &a.dirs {
            let text = std::fs::read_to_string(d.join("results.json"))?;
            results.extend(serde_json::from_str::<Vec<mycel_sim::report::ScenarioResult>>(&text)?);
        }
        // in the order scenarios are listed
        results.sort_by_key(|r| all.iter().position(|s| s.name == r.name).unwrap_or(usize::MAX));
        std::fs::create_dir_all(&a.out)?;
        std::fs::write(a.out.join("report.md"), markdown(&results))?;
        std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
        eprintln!("merged {} scenarios into {}", results.len(), a.out.join("report.md").display());
        return Ok(());
    }
    if a.what == "export-world" {
        let names = a.dirs.first().and_then(|d| d.to_str()).unwrap_or_default().to_string();
        let wanted: Vec<&str> = names.split(',').filter(|n| !n.is_empty()).collect();
        let pick: Vec<_> = all.iter().filter(|s| s.tier == 2 && wanted.contains(&s.name)).collect();
        anyhow::ensure!(!pick.is_empty(), "export-world <tier-2 scenario,...>; try `list`");
        let dir = a.out.join("worlds");
        std::fs::create_dir_all(&dir)?;
        mycel_sim::world::trace::export_to(dir.clone());
        for s in pick {
            let mut r = (s.run)(Opts { seed: a.seed, scale: a.scale, candidate: Candidate::Global });
            r.finish();
            eprintln!("  {}: {:?}", s.name, r.status);
        }
        let n = std::fs::read_dir(&dir)?.count();
        eprintln!("{n} world(s) in {}", dir.display());
        return Ok(());
    }
    if a.what == "replay" {
        let path = a.world.as_ref().ok_or_else(|| anyhow::anyhow!("replay --world FILE"))?;
        let t = std::sync::Arc::new(mycel_sim::world::trace::WorldTrace::load(path)?);
        let also = match a.candidate.as_str() {
            "main" => Some(Candidate::Main),
            "stand-in" | "standin" => Some(Candidate::StandIn),
            _ => Some(Candidate::Global),
        };
        let t0 = Instant::now();
        let mut r = scenarios::t2::replay_world(t, also);
        r.wall_s = t0.elapsed().as_secs_f64();
        r.finish();
        for h in &r.headline {
            eprintln!("  {h}");
        }
        for n in r.notes.iter().filter(|n| n.contains("hash")) {
            eprintln!("  {n}");
        }
        for f in r.failed_slos() {
            eprintln!("    ✗ {}: {} (target {})", f.name, f.actual, f.target);
        }
        std::fs::create_dir_all(&a.out)?;
        let results = vec![r];
        std::fs::write(a.out.join("report.md"), markdown(&results))?;
        std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
        anyhow::ensure!(matches!(results[0].status, Status::Pass), "replay failed");
        return Ok(());
    }
    if a.what == "crn" {
        let names = a.dirs.first().and_then(|d| d.to_str()).map(str::to_string);
        let k = if a.runs > 1 { a.runs } else { 10 };
        let picked: Vec<(&str, f64, &str)> = mycel_sim::crn::DEFAULT
            .iter()
            .copied()
            .filter(|(n, _, _)| names.as_deref().is_none_or(|w| w.split(',').any(|x| x == *n)))
            .collect();
        let mut rows = Vec::new();
        for (name, scale, b) in picked {
            let t0 = Instant::now();
            rows.extend(mycel_sim::crn::measure(name, scale, b, a.seed, k));
            eprintln!("  {name}: {:.0} s wall", t0.elapsed().as_secs_f64());
        }
        let md = mycel_sim::crn::markdown(&rows);
        println!("{md}");
        std::fs::create_dir_all(&a.out)?;
        std::fs::write(a.out.join("crn.md"), &md)?;
        std::fs::write(a.out.join("crn.json"), serde_json::to_string_pretty(&rows)?)?;
        return Ok(());
    }
    if a.what == "list" {
        for s in &all {
            println!("{:16} tier {}  {}", s.name, s.tier, s.title);
        }
        return Ok(());
    }
    let suite = |list: &[(&str, f64)]| -> Vec<(&scenarios::Scenario, f64)> {
        list.iter().filter_map(|(n, scale)| all.iter().find(|s| s.name == *n).map(|s| (s, *scale))).collect()
    };
    // (scenario, scale): the suites carry their own CI sizes
    let picked: Vec<(&scenarios::Scenario, f64)> = match a.what.as_str() {
        "all" => all.iter().map(|s| (s, a.scale)).collect(),
        "t1" => all.iter().filter(|s| s.tier == 1).map(|s| (s, a.scale)).collect(),
        "t2" => all.iter().filter(|s| s.tier == 2).map(|s| (s, a.scale)).collect(),
        "ci" => suite(mycel_sim::seeds::CI_SUITE),
        "soak" => suite(mycel_sim::seeds::SOAK_SUITE),
        names => {
            let wanted: Vec<&str> = names.split(',').collect();
            let v: Vec<_> = all.iter().filter(|s| wanted.contains(&s.name)).map(|s| (s, a.scale)).collect();
            anyhow::ensure!(!v.is_empty(), "no scenario {names:?}; try `list`");
            v
        }
    };
    let candidate = match a.candidate.as_str() {
        "global" | "core" => Candidate::Global,
        "main" => Candidate::Main,
        "stand-in" | "standin" => Candidate::StandIn,
        c => anyhow::bail!("unknown candidate {c}"),
    };
    if a.runs > 1 {
        return replications(&a, &picked, candidate);
    }
    let scales: Vec<f64> = picked.iter().map(|p| p.1).collect();
    let pick: Vec<&scenarios::Scenario> = picked.iter().map(|p| p.0).collect();
    let scale_of = |s: &scenarios::Scenario| pick.iter().position(|p| p.name == s.name).map_or(a.scale, |i| scales[i]);
    let one = |s: &scenarios::Scenario| {
        eprintln!("▶ {} (tier {}): {}", s.name, s.tier, s.title);
        let t = Instant::now();
        let mut r = (s.run)(Opts { seed: a.seed, scale: scale_of(s), candidate });
        r.wall_s = t.elapsed().as_secs_f64();
        r.finish();
        eprintln!("  {}: {:?} in {:.1} s — {}", s.name, r.status, r.wall_s, r.headline.join("; "));
        for f in r.failed_slos() {
            eprintln!("    ✗ {}: {}: {} (target {})", s.name, f.name, f.actual, f.target);
        }
        r
    };
    // Tier 2 runs in virtual time, so its scenarios (and the runs inside them)
    // share the cores. Tier 1 measures the wall clock: one scenario at a time,
    // after tier 2.
    let tier2: Vec<_> = pick.par_iter().filter(|s| s.tier == 2).map(|s| one(s)).collect();
    let tier1 = pick.iter().filter(|s| s.tier != 2).map(|s| one(s));
    let mut results: Vec<_> = tier2.into_iter().chain(tier1).collect();
    results.sort_by_key(|r| pick.iter().position(|s| s.name == r.name).unwrap_or(usize::MAX));
    std::fs::create_dir_all(&a.out)?;
    std::fs::write(a.out.join("report.md"), markdown(&results))?;
    std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
    eprintln!("wrote {}", a.out.join("report.md").display());
    let failed = results.iter().filter(|r| matches!(r.status, Status::Fail | Status::UnexpectedPass)).count();
    anyhow::ensure!(failed == 0, "{failed} scenario(s) failed");
    Ok(())
}

/// `--runs K`: each scenario on K seeds from `--seed` (the base), judged
/// together (`mycel_sim::seeds`). Prints every failing seed with the
/// command that replays it.
fn replications(a: &Args, picked: &[(&scenarios::Scenario, f64)], candidate: Candidate) -> anyhow::Result<()> {
    use mycel_sim::seeds::{min_pass, replicate, verdict};
    let seeds = mycel_sim::stats::run_seeds(a.seed, a.runs);
    let m = a.min_pass.unwrap_or_else(|| min_pass(a.runs));
    anyhow::ensure!(m <= a.runs, "--min-pass {m} is more than --runs {}: every scenario would fail", a.runs);
    eprintln!("base seed {}, {} runs: seeds {seeds:?}; quality must pass on ≥ {m}", a.seed, a.runs);
    let judge = |(s, scale): &(&scenarios::Scenario, f64)| {
        eprintln!("▶ {} at scale {scale} on {} seeds", s.name, seeds.len());
        let t = Instant::now();
        let rs = replicate(s.name, *scale, &seeds, candidate);
        let v = verdict(&rs, m);
        eprintln!("{}  ({:.0} s wall)", v.markdown(), t.elapsed().as_secs_f64());
        (rs, v)
    };
    // tier 2 shares the cores; tier 1 measures the wall clock, alone, after
    let tier2: Vec<_> = picked.par_iter().filter(|p| p.0.tier == 2).map(judge).collect();
    let tier1: Vec<_> = picked.iter().filter(|p| p.0.tier != 2).map(judge).collect();
    let all: Vec<_> = tier2.into_iter().chain(tier1).collect();
    let t = Instant::now();
    // the gate also replays the seeds that once failed, whole
    let pinned = if a.what == "ci" { mycel_sim::seeds::check_pinned(candidate) } else { Vec::new() };
    let mut md = format!(
        "# Mycel simulation: {} seeds from base {}\n\nInvariants must hold on every seed; quality objectives on at least {m} of {}.\n\n",
        seeds.len(),
        a.seed,
        seeds.len()
    );
    for (_, v) in &all {
        md.push_str(&v.markdown());
        md.push('\n');
    }
    if a.what == "ci" {
        md.push_str(&format!(
            "### Pinned regression seeds: {}\n\n",
            if pinned.is_empty() { "✅ pass".to_string() } else { format!("❌ FAIL\n\n- {}", pinned.join("\n- ")) }
        ));
        eprintln!("pinned seeds: {} failing ({:.0} s wall)", pinned.len(), t.elapsed().as_secs_f64());
    }
    let results: Vec<_> = all.iter().flat_map(|(rs, _)| rs.iter().cloned()).collect();
    let verdicts: Vec<_> = all.iter().map(|(_, v)| v.clone()).collect();
    std::fs::create_dir_all(&a.out)?;
    // the verdicts alone (CI's job summary), then everything
    std::fs::write(a.out.join("gate.md"), &md)?;
    md.push_str(&markdown(&results));
    std::fs::write(a.out.join("report.md"), md)?;
    std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
    std::fs::write(a.out.join("verdicts.json"), serde_json::to_string_pretty(&verdicts)?)?;
    eprintln!("wrote {}", a.out.join("report.md").display());
    // the seeds to pin, once their cause is fixed; then what missed within
    // the m-of-k slack (the gate's seeds are fixed, so such a seed misses on
    // every run until the code changes) and where a known gap closed
    for v in &verdicts {
        for seed in v.failing_seeds() {
            println!("failing seed: {} {}  ({})", v.name, seed, v.repro(seed));
        }
        for seed in v.missed_within_slack() {
            println!(
                "quality miss (within {} of {}): {} {}  ({})",
                v.min_pass,
                v.seeds.len(),
                v.name,
                seed,
                v.repro(seed)
            );
        }
        if v.pass {
            for (seed, _) in &v.unexpected_passes {
                println!("known gap closed: {} {}  ({})", v.name, seed, v.repro(*seed));
            }
        }
    }
    for p in &pinned {
        println!("failing seed: {p}");
    }
    let mut failed: Vec<&str> = verdicts.iter().filter(|v| !v.pass).map(|v| v.name.as_str()).collect();
    if !pinned.is_empty() {
        failed.push("pinned regression seeds");
    }
    anyhow::ensure!(failed.is_empty(), "{} scenario(s) failed the gate: {}", failed.len(), failed.join(", "));
    Ok(())
}
