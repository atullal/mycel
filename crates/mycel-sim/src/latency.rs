//! Internet latency from measured data: WonderNetwork's public sample of
//! global pings (19–20 July 2020: ~250 servers in ~250 cities pinging each
//! other hourly, `ping -c 30` min/avg/max/mdev). Credit: WonderNetwork /
//! WonderProxy, "A day in the life of the internet",
//! <https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/>.
//!
//! The data isn't in the repository (no redistribution licence is given):
//! `bench/fetch.sh latency` downloads it into `bench/data/wondernetwork/`.
//! With it, [`Measured::load`] gives a city-pair RTT table, [`fit`] checks
//! the fibre model in [`crate::models`] against it, and the tier-2 engine
//! uses measured RTTs between the servers nearest each device (plus the
//! devices' access latency). Without it, the great-circle model is used.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::models::km;
use crate::stats::{Map, Summary};

#[derive(Clone, Debug)]
pub struct Server {
    pub id: u32,
    pub name: String,
    pub latlon: (f64, f64),
}

/// Per server pair: median of each hour's minimum and average RTT (ms).
pub struct Measured {
    pub servers: Vec<Server>,
    pub rtt: Map<(u32, u32), (f64, f64)>,
}

fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

impl Measured {
    /// Load `servers.csv` and `pings.csv` from `dir`.
    pub fn load(dir: &Path) -> Result<Measured> {
        let servers: Vec<Server> = std::fs::read_to_string(dir.join("servers.csv"))
            .with_context(|| format!("{}/servers.csv (run bench/fetch.sh latency)", dir.display()))?
            .lines()
            .skip(1)
            .filter_map(|l| {
                let f = fields(l);
                Some(Server { id: f.first()?.parse().ok()?, name: f.get(2)?.clone(), latlon: (f.get(8)?.parse().ok()?, f.get(9)?.parse().ok()?) })
            })
            .collect();
        let text = std::fs::read_to_string(dir.join("pings.csv")).context("pings.csv")?;
        let mut acc: Map<(u32, u32), (Vec<f64>, Vec<f64>)> = Map::default();
        for l in text.lines().skip(1) {
            let f = fields(l);
            let (Some(a), Some(b), Some(min), Some(avg)) = (
                f.first().and_then(|x| x.parse::<u32>().ok()),
                f.get(1).and_then(|x| x.parse::<u32>().ok()),
                f.get(3).and_then(|x| x.parse::<f64>().ok()),
                f.get(4).and_then(|x| x.parse::<f64>().ok()),
            ) else {
                continue;
            };
            if a == b || min <= 0.0 {
                continue;
            }
            let e = acc.entry((a.min(b), a.max(b))).or_default();
            e.0.push(min);
            e.1.push(avg);
        }
        let rtt = acc.into_iter().map(|(k, (mut mn, mut av))| (k, (median(&mut mn), median(&mut av)))).collect();
        Ok(Measured { servers, rtt })
    }

    /// The server nearest a point, and how far it is (km).
    pub fn nearest(&self, p: (f64, f64)) -> Option<(&Server, f64)> {
        self.servers.iter().map(|s| (s, km(p, s.latlon))).min_by(|a, b| a.1.total_cmp(&b.1))
    }

    /// Measured median RTT (ms) between the servers nearest `a` and `b`,
    /// if both are within 500 km of a server and the pair was measured.
    pub fn rtt_ms(&self, a: (f64, f64), b: (f64, f64)) -> Option<f64> {
        let (sa, da) = self.nearest(a)?;
        let (sb, db) = self.nearest(b)?;
        if da > 500.0 || db > 500.0 {
            return None;
        }
        if sa.id == sb.id {
            return Some(1.0);
        }
        self.rtt.get(&(sa.id.min(sb.id), sa.id.max(sb.id))).map(|x| x.1)
    }
}

/// Fit of the great-circle model against the measurements.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Fit {
    pub pairs: usize,
    /// Measured min RTT / (2 × great-circle km × 4.9 µs/km): path inflation over fibre at the speed of light in glass.
    pub inflation: Summary,
    /// Least squares: min RTT (ms) = intercept + slope × km.
    pub intercept_ms: f64,
    pub slope_us_per_km: f64,
    /// Our model's error against measured average RTT, as model / measured.
    pub model_over_measured: Summary,
    /// Some well-known pairs: (from, to, km, measured min, measured avg, model) in ms.
    pub examples: Vec<(String, String, f64, f64, f64, f64)>,
}

pub fn fit(m: &Measured) -> Fit {
    let by_id: Map<u32, &Server> = m.servers.iter().map(|s| (s.id, s)).collect();
    let (mut infl, mut ratio) = (Vec::new(), Vec::new());
    let (mut sx, mut sy, mut sxx, mut sxy, mut n) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for ((a, b), (mn, av)) in &m.rtt {
        let (Some(sa), Some(sb)) = (by_id.get(a), by_id.get(b)) else { continue };
        let d = km(sa.latlon, sb.latlon);
        if d < 200.0 {
            continue; // nearby servers: dominated by local routing, not distance
        }
        infl.push(mn / (2.0 * d * 4.9 / 1000.0));
        let model = 2.0 * crate::models::backbone(d).as_secs_f64() * 1000.0;
        ratio.push(model / av);
        sx += d;
        sy += mn;
        sxx += d * d;
        sxy += d * mn;
        n += 1.0;
    }
    let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let intercept = (sy - slope * sx) / n;
    let names = [("New York", "London"), ("New York", "Los Angeles"), ("London", "Frankfurt"), ("London", "Tokyo"), ("Sydney", "Singapore"), ("Sao Paulo", "Miami")];
    let mut examples = Vec::new();
    for (x, y) in names {
        let find = |name: &str| m.servers.iter().find(|s| s.name.replace('_', " ").eq_ignore_ascii_case(name) || s.name.eq_ignore_ascii_case(&name.replace(' ', "")));
        if let (Some(sa), Some(sb)) = (find(x), find(y))
            && let Some((mn, av)) = m.rtt.get(&(sa.id.min(sb.id), sa.id.max(sb.id)))
        {
            let d = km(sa.latlon, sb.latlon);
            examples.push((x.to_string(), y.to_string(), d, *mn, *av, 2.0 * crate::models::backbone(d).as_secs_f64() * 1000.0));
        }
    }
    Fit { pairs: n as usize, inflation: Summary::of(&infl), intercept_ms: intercept, slope_us_per_km: slope * 1000.0, model_over_measured: Summary::of(&ratio), examples }
}

static MEASURED: OnceLock<Option<Measured>> = OnceLock::new();

/// The measured table, if `MYCEL_PINGS` names its directory (loaded once).
/// Off by default so results don't depend on what's downloaded.
pub fn measured() -> Option<&'static Measured> {
    MEASURED.get_or_init(|| std::env::var("MYCEL_PINGS").ok().and_then(|d| Measured::load(Path::new(&d)).ok())).as_ref()
}
