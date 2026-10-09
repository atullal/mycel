//! `mycel-sim <scenario|all|list> [--seed N] [--scale X] [--candidate main|stand-in] [--out DIR]`
//!
//! Runs scenarios and writes `report.md` and `results.json` into `--out`
//! (default `target/mycel-sim`). `mycel-sim merge DIR... --out DIR` joins
//! runs made separately (e.g. in parallel processes) into one report.

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use mycel_sim::report::{Status, markdown};
use mycel_sim::scenarios::{self, Candidate, Opts};

#[derive(Parser)]
#[command(about = "Mycel network simulation: real-world scenarios, scale and routing")]
struct Args {
    /// A scenario name (or several, comma-separated), `all`, `t1`, `t2`,
    /// `list`, `merge`, `fit-latency`, or `export-trace` (write MYCEL_TRACE,
    /// or the synthetic trace, as the benchmarks' contacts CSV).
    what: String,
    /// For `merge`: directories holding a `results.json` each.
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
    if a.what == "list" {
        for s in &all {
            println!("{:16} tier {}  {}", s.name, s.tier, s.title);
        }
        return Ok(());
    }
    let pick: Vec<&scenarios::Scenario> = match a.what.as_str() {
        "all" => all.iter().collect(),
        "t1" => all.iter().filter(|s| s.tier == 1).collect(),
        "t2" => all.iter().filter(|s| s.tier == 2).collect(),
        names => {
            let wanted: Vec<&str> = names.split(',').collect();
            let v: Vec<_> = all.iter().filter(|s| wanted.contains(&s.name)).collect();
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
    let opts = Opts { seed: a.seed, scale: a.scale, candidate };
    let mut results = Vec::new();
    for s in pick {
        eprintln!("▶ {} (tier {}): {}", s.name, s.tier, s.title);
        let t = Instant::now();
        let mut r = (s.run)(opts);
        r.wall_s = t.elapsed().as_secs_f64();
        r.finish();
        eprintln!("  {:?} in {:.1} s — {}", r.status, r.wall_s, r.headline.join("; "));
        for f in r.failed_slos() {
            eprintln!("    ✗ {}: {} (target {})", f.name, f.actual, f.target);
        }
        results.push(r);
    }
    std::fs::create_dir_all(&a.out)?;
    std::fs::write(a.out.join("report.md"), markdown(&results))?;
    std::fs::write(a.out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
    eprintln!("wrote {}", a.out.join("report.md").display());
    let failed = results.iter().filter(|r| matches!(r.status, Status::Fail | Status::UnexpectedPass)).count();
    anyhow::ensure!(failed == 0, "{failed} scenario(s) failed");
    Ok(())
}
