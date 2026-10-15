//! Real contact traces: who was in Bluetooth range of whom, when.
//!
//! Formats:
//! - **CRAWDAD cambridge/haggle** iMote traces (Scott et al., doi:10.15783/C70011):
//!   `contacts.ExpN.dat`, one row per contact: recorder id, seen id, first
//!   and last sighting (seconds), sequence number, gap since the previous
//!   contact. Intel (Exp1), Cambridge Computer Lab (Exp2), Infocom 2005
//!   (Exp3), Infocom 2006 (Exp6). Only the experiment's own iMotes are kept
//!   (external devices seen have higher ids).
//! - **Cambridge city** (same dataset): a directory of `N.dat` files, each
//!   the sightings by iMote N: seen id, first, last (Unix seconds).
//! - **Generic CSV**: `a,b,start,end` in seconds (e.g. the NUS Bluetooth
//!   trace converted from its SQL dump by `bench/traces/nus_to_csv.py`).
//!
//! The data isn't redistributable (CRAWDAD's terms: register, cite, don't
//! re-share), so it isn't in the repository: `bench/fetch.sh traces` downloads
//! the Haggle contact files into `bench/data/`, and `bench/fetch.sh dataport
//! <archives>` unpacks the full IEEE DataPort archives (free account). Without it,
//! [`synthetic`] makes a trace with the same statistical shape (heavy-tailed
//! inter-contact times, short contacts) so the pipeline runs anywhere.
//!
//! Sightings are one-sided and overlap; they are merged into symmetric
//! contacts per pair (the union of both sides' intervals).

use std::path::Path;

use anyhow::{Context, Result};

use crate::stats::Rng;
use crate::tier2::{SEC, Time};

/// Contacts between devices `0..nodes`, times in µs from the trace's start.
#[derive(Clone, Debug)]
pub struct Trace {
    pub name: String,
    pub nodes: usize,
    /// (start, end, a, b), a < b, sorted by start.
    pub contacts: Vec<(Time, Time, u32, u32)>,
    pub duration: Time,
}

/// iMotes in each Haggle experiment (higher ids are external devices).
fn haggle_internal(exp: &str) -> Option<u32> {
    match exp {
        "Exp1" => Some(9),
        "Exp2" => Some(12),
        "Exp3" => Some(41),
        "Exp6" => Some(98),
        _ => None,
    }
}

/// Load a trace file or directory (format from its name).
pub fn load(path: &Path) -> Result<Trace> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("trace").to_string();
    if path.is_dir() {
        return load_city(path);
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut rows: Vec<(u32, u32, f64, f64)> = Vec::new();
    if name.ends_with(".csv") {
        for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            let f: Vec<&str> = line.split(',').map(str::trim).collect();
            if f.len() < 4 {
                continue;
            }
            let (Ok(a), Ok(b), Ok(s), Ok(e)) = (f[0].parse(), f[1].parse(), f[2].parse(), f[3].parse()) else {
                continue;
            };
            rows.push((a, b, s, e));
        }
    } else {
        let exp = name.split('.').nth(1).unwrap_or("");
        let internal = haggle_internal(exp);
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let (Ok(a), Ok(b), Ok(s), Ok(e)) =
                (f[0].parse::<u32>(), f[1].parse::<u32>(), f[2].parse::<f64>(), f[3].parse::<f64>())
            else {
                continue;
            };
            if internal.is_some_and(|m| a > m || b > m) {
                continue;
            }
            rows.push((a, b, s, e));
        }
    }
    Ok(build(name, rows))
}

/// Cambridge city: `N.dat` per iMote (seen id, first, last).
fn load_city(dir: &Path) -> Result<Trace> {
    let mut rows = Vec::new();
    let mut ids: Vec<u32> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
        let Ok(rec) = stem.parse::<u32>() else { continue };
        ids.push(rec);
        for line in std::fs::read_to_string(&p)?.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            let (Ok(b), Ok(s), Ok(e)) = (f[0].parse::<u32>(), f[1].parse::<f64>(), f[2].parse::<f64>()) else {
                continue;
            };
            rows.push((rec, b, s, e));
        }
    }
    // keep sightings between the experiment's own iMotes
    rows.retain(|(a, b, _, _)| ids.contains(a) && ids.contains(b));
    Ok(build(dir.file_name().and_then(|n| n.to_str()).unwrap_or("city").to_string(), rows))
}

fn build(name: String, rows: Vec<(u32, u32, f64, f64)>) -> Trace {
    let mut ids: Vec<u32> = rows.iter().flat_map(|r| [r.0, r.1]).collect();
    ids.sort_unstable();
    ids.dedup();
    let index = |x: u32| ids.binary_search(&x).expect("id") as u32;
    let t0 = rows.iter().map(|r| r.2.min(r.3)).fold(f64::INFINITY, f64::min);
    let mut per_pair: std::collections::BTreeMap<(u32, u32), Vec<(Time, Time)>> = Default::default();
    for (a, b, s, e) in rows {
        if a == b {
            continue;
        }
        let (a, b) = (index(a), index(b));
        let (s, e) = (((s - t0) * SEC as f64) as Time, ((e - t0).max(s - t0) * SEC as f64) as Time);
        per_pair.entry((a.min(b), a.max(b))).or_default().push((s, e));
    }
    let mut contacts = Vec::new();
    for ((a, b), mut v) in per_pair {
        v.sort_unstable();
        let mut cur = v[0];
        for (s, e) in v.into_iter().skip(1) {
            if s <= cur.1 {
                cur.1 = cur.1.max(e);
            } else {
                contacts.push((cur.0, cur.1, a, b));
                cur = (s, e);
            }
        }
        contacts.push((cur.0, cur.1, a, b));
    }
    contacts.sort_unstable();
    let duration = contacts.iter().map(|c| c.1).max().unwrap_or(0);
    Trace { name, nodes: ids.len(), contacts, duration }
}

/// A synthetic trace with the shape of human Bluetooth contacts: per pair,
/// heavy-tailed (Pareto, α 0.6, as Chaintreau et al. measured on these
/// traces) inter-contact times between 2 min and 1 day, contacts lasting
/// 2–20 min. Not a substitute for the real data; it lets the replay
/// pipeline and The ONE comparison run without it.
pub fn synthetic(nodes: usize, duration: Time, seed: u64) -> Trace {
    let mut rng = Rng::new(seed);
    let mut contacts = Vec::new();
    // only a fraction of pairs ever meet (groups of colleagues)
    for a in 0..nodes as u32 {
        for b in a + 1..nodes as u32 {
            if !rng.chance(0.35) {
                continue;
            }
            let mut t: Time = (rng.f64() * 3600.0 * SEC as f64) as Time;
            while t < duration {
                let len = rng.range(120.0, 1200.0);
                let end = (t + (len * SEC as f64) as Time).min(duration);
                contacts.push((t, end, a, b));
                // Pareto inter-contact: x_min 2 min, α 0.6, capped at a day
                let gap = (120.0 / rng.f64().max(1e-9).powf(1.0 / 0.6)).min(86_400.0);
                t = end + (gap * SEC as f64) as Time;
            }
        }
    }
    contacts.sort_unstable();
    Trace { name: format!("synthetic ({nodes} devices)"), nodes, contacts, duration }
}

/// Write the trace as the benchmarks' contacts CSV (`t_start,t_end,a,b`,
/// seconds), the input `bench/traces/convert.py` turns into a workload and
/// The ONE's events, and `dtn-replay` replays (docs/BENCHMARKS.md).
pub fn export_csv(t: &Trace, path: &Path) -> Result<()> {
    let mut body = String::from("t_start,t_end,a,b\n");
    for (s, e, a, b) in &t.contacts {
        body += &format!("{},{},{a},{b}\n", *s as f64 / SEC as f64, *e as f64 / SEC as f64);
    }
    std::fs::write(path, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haggle_rows_merge_and_filter_external_devices() {
        let dir = std::env::temp_dir().join(format!("mycel-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("contacts.Exp3.dat");
        // 1 saw 2 over [100, 200]; 2 saw 1 over [150, 260]; 1 saw external 500
        std::fs::write(&p, "1 2 100 200 1 0\n2 1 150 260 1 0\n1 500 100 400 1 0\n3 1 1000 1000 1 0\n").unwrap();
        let t = load(&p).unwrap();
        assert_eq!(t.nodes, 3, "external device dropped");
        assert_eq!(t.contacts[0], (0, 160 * SEC, 0, 1), "both sides merged into one contact");
        assert_eq!(t.contacts.len(), 2);
        let csv = dir.join("contacts.csv");
        export_csv(&t, &csv).unwrap();
        assert!(std::fs::read_to_string(&csv).unwrap().starts_with("t_start,t_end,a,b\n0,160,0,1\n"));
    }

    #[test]
    fn synthetic_is_reproducible() {
        let a = synthetic(10, 24 * 3600 * SEC, 3);
        let b = synthetic(10, 24 * 3600 * SEC, 3);
        assert_eq!(a.contacts, b.contacts);
        assert!(!a.contacts.is_empty());
    }
}
