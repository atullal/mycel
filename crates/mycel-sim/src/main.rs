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
//! The declarative catalogue (`crates/mycel-sim/scenarios/*.toml`):
//! `mycel-sim catalogue` lists it with each scenario's status and
//! fidelity; `mycel-sim catalogue NAME... [--runs K] [--full]` runs
//! scenarios (`all` for every runnable one; a path for a file of your
//! own); `mycel-sim robust NAME [--points N] [--runs K] [--morris-r R]`
//! studies a verdict over its uncertainty region (docs/SIMULATION.md §7).

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
    /// `list`, `merge`, `fit-latency`, or `export-trace` (write MYCEL_TRACE,
    /// or the synthetic trace, as the benchmarks' contacts CSV).
    what: String,
    /// For `merge`: directories holding a `results.json` each. For
    /// `catalogue` and `robust`: scenario names (or `.toml` paths).
    dirs: Vec<PathBuf>,
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
    /// Catalogue: run at full size instead of the scenario's CI size.
    #[arg(long)]
    full: bool,
    /// Robust: space-filling points over the uncertainty region.
    #[arg(long, default_value_t = 32)]
    points: usize,
    /// Robust: Morris trajectories (0: no screening).
    #[arg(long, default_value_t = 8)]
    morris_r: usize,
    /// Robust: fresh seeds confirming the worst case found.
    #[arg(long, default_value_t = 10)]
    confirm: usize,
    /// Catalogue: swarm toggles to switch off, comma-separated (fisheye,
    /// flood-reduction, dtn, churn, outages, adversaries, battery).
    #[arg(long, value_delimiter = ',')]
    off: Vec<String>,
    /// Catalogue and robust: people present instead of the CI (or full) size.
    #[arg(long)]
    people: Option<usize>,
    /// Catalogue and robust: simulated minutes instead of the scenario's.
    #[arg(long)]
    minutes: Option<f64>,
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
    if a.what == "catalogue" {
        return catalogue(&a);
    }
    if a.what == "robust" {
        return robust(&a);
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

/// The catalogue's scenarios named on the command line (`all`: every one).
fn catalogue_specs(a: &Args) -> anyhow::Result<Vec<mycel_sim::catalogue::Spec>> {
    use mycel_sim::catalogue;
    let mut out = Vec::new();
    for d in &a.dirs {
        let name = d.to_string_lossy();
        if name == "all" {
            out.extend(catalogue::all());
        } else if name.ends_with(".toml") {
            out.push(catalogue::load(d)?);
        } else {
            out.push(catalogue::find(&name).ok_or_else(|| anyhow::anyhow!("no catalogue scenario {name:?}"))?);
        }
    }
    Ok(out)
}

/// The run size: CI (or `--full`), with `--people` / `--minutes` on top.
fn size_of(a: &Args, s: &mycel_sim::catalogue::Spec) -> mycel_sim::catalogue::compose::Size {
    use mycel_sim::catalogue::compose::Size;
    let mut size = if a.full { Size::full(s) } else { Size::ci(s) };
    if let Some(p) = a.people {
        size.people = p.clamp(1, s.size.people);
    }
    if let Some(m) = a.minutes {
        size.duration = (m * mycel_sim::tier2::MIN as f64) as mycel_sim::tier2::Time;
    }
    size
}

/// `catalogue`: list, or run the named scenarios on `--runs` seeds.
fn catalogue(a: &Args) -> anyhow::Result<()> {
    use mycel_sim::catalogue::{self, Status, run};
    if a.dirs.is_empty() {
        println!("| # | Scenario | Status | Fidelity | Size (people × adoption) | Needs |\n|---|---|---|---|---|---|");
        for s in catalogue::all() {
            let f = s.fidelity();
            let needs: Vec<String> = f
                .missing
                .iter()
                .map(|m| format!("{}{} ({})", m.wanted, if m.essential { "*" } else { "" }, m.wp))
                .collect();
            println!(
                "| {} | `{}` {} | {:?} | {} | {} × {} (CI {}) | {} |",
                s.number,
                s.name,
                s.title,
                s.status(),
                f.short(),
                s.size.people,
                s.size.adoption,
                s.size.ci_people,
                needs.join(", ")
            );
        }
        return Ok(());
    }
    let specs = catalogue_specs(a)?;
    for t in &a.off {
        anyhow::ensure!(catalogue::SWARM_TOGGLES.contains(&t.as_str()), "unknown toggle {t:?}");
    }
    let swarm = catalogue::compose::Swarm { off: a.off.clone() };
    // one run: the seed as given (as for the hand-written scenarios), so a
    // printed failing seed replays with `--seed`
    let seeds = if a.runs <= 1 { vec![a.seed] } else { mycel_sim::stats::run_seeds(a.seed, a.runs) };
    let mut results = Vec::new();
    let mut verdicts = Vec::new();
    let mut failed = Vec::new();
    let mut md = format!("# Mycel scenario catalogue: {} seeds from base {}\n\n", seeds.len(), a.seed);
    for s in &specs {
        let size = size_of(a, s);
        let label = if a.people.is_some() || a.minutes.is_some() {
            "scaled down"
        } else if a.full {
            "full size"
        } else {
            "CI size"
        };
        let m = a.min_pass.unwrap_or_else(|| mycel_sim::seeds::min_pass(seeds.len()).min(s.stats.min_pass));
        let t = Instant::now();
        let status = s.status();
        if status == Status::Blocked {
            let r = {
                let mut r = run::result(s, size, label, seeds[0]);
                r.finish();
                r
            };
            eprintln!("▶ {} {}: {}", s.number, s.name, r.headline.join("; "));
            md.push_str(&format!("### `{}`: blocked\n\n{}\n\n", s.name, r.headline.join("; ")));
            results.push(r);
            write_catalogue(a, &md, &results, &verdicts)?;
            continue;
        }
        let (rs, v) = run::replicate(s, size, label, &seeds, m.min(seeds.len()), &swarm);
        let fid = s.fidelity();
        eprintln!(
            "▶ {} {} ({:?}, {}): {} in {:.0} s — {}",
            s.number,
            s.name,
            status,
            fid.short(),
            if v.pass { "pass" } else { "FAIL" },
            t.elapsed().as_secs_f64(),
            rs[0].headline.join("; ")
        );
        // replay lines name the catalogue command and its size
        let mut size_args = format!("--people {} --minutes {}", size.people, size.duration / mycel_sim::tier2::MIN);
        if !a.off.is_empty() {
            size_args.push_str(&format!(" --off {}", a.off.join(",")));
        }
        let vm = v.markdown().replace(
            &format!("-p mycel-sim -- {} --scale {}", v.name, v.scale),
            &format!("-p mycel-sim -- catalogue {} {size_args}", v.name),
        );
        md.push_str(&format!("{vm}*Status: {:?}; fidelity {}.*\n\n", status, fid.short()));
        for seed in v.failing_seeds() {
            println!(
                "failing seed: {} {seed}  (cargo run --release -p mycel-sim -- catalogue {} {size_args} --seed {seed})",
                v.name, v.name
            );
        }
        // invariants always count; quality only where the result is a verdict
        if !v.invariant_failures.is_empty() || (status == Status::Verdict && !v.pass) {
            failed.push(s.name.clone());
        }
        for (seed, what) in v.invariant_failures.iter().chain(&v.quality_misses) {
            eprintln!("    ✗ {} seed {seed}: {what}", s.name);
        }
        results.extend(rs);
        verdicts.push(v);
        // written after every scenario, so a long run killed part way keeps what it did
        write_catalogue(a, &md, &results, &verdicts)?;
    }
    write_catalogue(a, &md, &results, &verdicts)?;
    eprintln!("wrote {}", a.out.join("report.md").display());
    anyhow::ensure!(failed.is_empty(), "{} scenario(s) failed: {}", failed.len(), failed.join(", "));
    Ok(())
}

fn write_catalogue(
    a: &Args,
    md: &str,
    results: &[mycel_sim::report::ScenarioResult],
    verdicts: &[mycel_sim::seeds::Verdict],
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&a.out)?;
    std::fs::write(a.out.join("report.md"), format!("{md}{}", markdown(results)))?;
    std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(results)?)?;
    std::fs::write(a.out.join("verdicts.json"), serde_json::to_string_pretty(verdicts)?)?;
    Ok(())
}

/// `robust NAME`: the verdict's robustness over its uncertainty region.
fn robust(a: &Args) -> anyhow::Result<()> {
    use mycel_sim::catalogue::run::Study;
    use mycel_sim::uq::{Plan, study};
    let specs = catalogue_specs(a)?;
    anyhow::ensure!(!specs.is_empty(), "name a catalogue scenario");
    std::fs::create_dir_all(&a.out)?;
    let mut md = String::from("# Mycel robustness studies\n\n");
    let mut all = Vec::new();
    let mut rows = Vec::new();
    for s in specs {
        let size = size_of(a, &s);
        let st = Study::new(s, size)?;
        let (threshold, higher_is_better) = st.threshold();
        let plan = Plan {
            points: a.points,
            seeds: mycel_sim::stats::run_seeds(a.seed, a.runs.max(1)),
            morris_r: a.morris_r,
            threshold,
            higher_is_better,
            confirm_seeds: mycel_sim::stats::run_seeds(a.seed ^ 0x636f_6e66, a.confirm.max(1)),
            sobol_n: 4096,
            boots: 200,
            seed: a.seed,
        };
        eprintln!(
            "▶ robust {} at {} people: {} points × {} seeds, Morris r = {}",
            st.spec.name,
            size.people,
            plan.points,
            plan.seeds.len(),
            plan.morris_r
        );
        let r = study(&st, &plan)?;
        let mut row = mycel_sim::catalogue::run::study_result(&st, &r);
        row.finish();
        rows.push(row);
        eprintln!(
            "  {} in {:.0} s: {}; hinges on {}",
            if r.robust { "robust" } else { "not robust" },
            r.wall_s,
            r.robust_pass_label(),
            r.hinges_on().join(", ")
        );
        md.push_str(&format!(
            "{}\nFidelity {} at {} people ({} min); the region's robustness is over today's ignorance, not a calibrated error bar.\n\n",
            r.markdown(),
            st.spec.fidelity().short(),
            size.people,
            size.duration / mycel_sim::tier2::MIN
        ));
        all.push(r);
    }
    std::fs::write(a.out.join("robustness.md"), &md)?;
    std::fs::write(a.out.join("robustness.json"), serde_json::to_string_pretty(&all)?)?;
    // the scorecard: fidelity, region and robust-pass fraction per row
    std::fs::write(a.out.join("report.md"), markdown(&rows))?;
    std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&rows)?)?;
    eprintln!("wrote {}", a.out.join("robustness.md").display());
    Ok(())
}
