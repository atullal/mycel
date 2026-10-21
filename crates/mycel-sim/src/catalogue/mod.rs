//! The declarative scenario catalogue (sim-fidelity WP15): real-world
//! situations as data, each composed from world components and stated
//! with its fidelity level.
//!
//! Each `crates/mycel-sim/scenarios/NN-name.toml` composes a region and
//! layout, a population and adoption, a device mix, mobility, a radio
//! profile, an internet profile (access, NAT, outages), OS behaviour
//! (battery, churn, restart storms), adversaries, a workload, a duration,
//! objectives with the statistics plan, the uncertain parameters a
//! robustness study varies ([`crate::uq`]), the swarm toggles that may vary
//! (WP20), and the models its key physics **needs**. The files are
//! compiled in ([`FILES`]); the hand-written scenarios stay as they are.
//!
//! A need names a model in [`crate::fidelity::MODELS`]. If the simulator
//! has it, it is used. If not:
//!
//! - a non-essential need is a note (with the direction it biases);
//! - an essential need runs on the component's stand-in, and the result is
//!   a **bound** in that direction, never a verdict;
//! - an essential need marked `stand_in = false` **blocks** the scenario:
//!   no stand-in would mean anything (storage-full devices on unlimited
//!   storage), so it is listed with what it waits for, and not run.
//!
//! Randomness is keyed per entity (`keyed(seed, purpose, entity, k)`), not
//! drawn from one sequence: device i's place, radios, internet and
//! attacker rank are the same whatever the adoption, the attacker share or
//! the internet share, so the points of a robustness study differ in the
//! parameter, not in a reshuffled world (common random numbers, WP1's
//! rule applied to the catalogue's world).

pub mod compose;
pub mod run;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::fidelity::{self, Fidelity, Missing};
use crate::models::Env;
use crate::uq::params::{Region, builtin};

/// The catalogue's files, compiled in, in order.
pub const FILES: &[(&str, &str)] = &[
    ("01-city-commute.toml", include_str!("../../scenarios/01-city-commute.toml")),
    ("02-campus.toml", include_str!("../../scenarios/02-campus.toml")),
    ("03-office.toml", include_str!("../../scenarios/03-office.toml")),
    ("04-apartment-block.toml", include_str!("../../scenarios/04-apartment-block.toml")),
    ("05-rural-starlink.toml", include_str!("../../scenarios/05-rural-starlink.toml")),
    ("06-rural-line.toml", include_str!("../../scenarios/06-rural-line.toml")),
    ("07-earthquake.toml", include_str!("../../scenarios/07-earthquake.toml")),
    ("08-flood-evacuation.toml", include_str!("../../scenarios/08-flood-evacuation.toml")),
    ("09-protest-shutdown.toml", include_str!("../../scenarios/09-protest-shutdown.toml")),
    ("10-protest-mobile-off.toml", include_str!("../../scenarios/10-protest-mobile-off.toml")),
    ("11-festival.toml", include_str!("../../scenarios/11-festival.toml")),
    ("12-stadium-exit.toml", include_str!("../../scenarios/12-stadium-exit.toml")),
    ("13-conference-hall.toml", include_str!("../../scenarios/13-conference-hall.toml")),
    ("14-subway.toml", include_str!("../../scenarios/14-subway.toml")),
    ("15-long-haul-flight.toml", include_str!("../../scenarios/15-long-haul-flight.toml")),
    ("16-cross-continent.toml", include_str!("../../scenarios/16-cross-continent.toml")),
    ("17-sparse-internet.toml", include_str!("../../scenarios/17-sparse-internet.toml")),
    ("18-censored-country.toml", include_str!("../../scenarios/18-censored-country.toml")),
    ("19-whitelist-intranet.toml", include_str!("../../scenarios/19-whitelist-intranet.toml")),
    ("20-update-storm.toml", include_str!("../../scenarios/20-update-storm.toml")),
    ("21-flash-crowd.toml", include_str!("../../scenarios/21-flash-crowd.toml")),
    ("22-night-doze.toml", include_str!("../../scenarios/22-night-doze.toml")),
    ("23-adversary-sweep.toml", include_str!("../../scenarios/23-adversary-sweep.toml")),
    ("24-eclipse-vip.toml", include_str!("../../scenarios/24-eclipse-vip.toml")),
    ("25-hospital.toml", include_str!("../../scenarios/25-hospital.toml")),
    ("26-refugee-camp.toml", include_str!("../../scenarios/26-refugee-camp.toml")),
    ("27-mountain-trail.toml", include_str!("../../scenarios/27-mountain-trail.toml")),
    ("28-highway-v2v.toml", include_str!("../../scenarios/28-highway-v2v.toml")),
    ("29-ferry.toml", include_str!("../../scenarios/29-ferry.toml")),
    ("30-clock-skew.toml", include_str!("../../scenarios/30-clock-skew.toml")),
    ("31-storage-full.toml", include_str!("../../scenarios/31-storage-full.toml")),
    ("32-low-battery-cascade.toml", include_str!("../../scenarios/32-low-battery-cascade.toml")),
    ("33-ios-heavy.toml", include_str!("../../scenarios/33-ios-heavy.toml")),
    ("34-android-oem-mix.toml", include_str!("../../scenarios/34-android-oem-mix.toml")),
    ("35-long-offline-mailbox.toml", include_str!("../../scenarios/35-long-offline-mailbox.toml")),
    ("36-group-chat.toml", include_str!("../../scenarios/36-group-chat.toml")),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// The design's catalogue number (sim-fidelity WP15 table).
    pub number: u32,
    pub name: String,
    pub title: String,
    /// What the scenario proves, once its models are in.
    pub proves: String,
    /// What dominates the result.
    pub key_physics: Vec<String>,
    pub size: Size,
    pub region: RegionSpec,
    #[serde(default)]
    pub devices: Devices,
    #[serde(default)]
    pub mobility: MobilitySpec,
    #[serde(default)]
    pub radio: RadioSpec,
    #[serde(default)]
    pub internet: InternetSpec,
    #[serde(default)]
    pub os: OsSpec,
    #[serde(default)]
    pub adversaries: Vec<AdversarySpec>,
    pub workload: WorkloadSpec,
    pub objectives: Objectives,
    #[serde(default)]
    pub stats: StatsSpec,
    #[serde(default)]
    pub uq: UqSpec,
    #[serde(default)]
    pub swarm: SwarmSpec,
    #[serde(default)]
    pub needs: Vec<Need>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Size {
    /// People present at full size.
    pub people: usize,
    /// People present at CI size (the default for catalogue runs).
    pub ci_people: usize,
    /// Share of the people running Mycel (nominal): devices = people × adoption.
    pub adoption: f64,
    pub duration_min: f64,
    /// A shorter run at CI size (default: the full duration).
    #[serde(default)]
    pub ci_duration_min: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    /// Uniformly over one width × height area.
    Field,
    /// `clusters` groups of radius `cluster_radius_m` spread over the area
    /// (shelters, villages, subway cars, cabins).
    Clusters,
    /// Along a line `width_m` long (a road, a trail, a row of houses).
    Line,
    /// One area per city in `cities`, at the cities' coordinates.
    Cities,
    /// Contacts from a trace (`trace`: `synthetic`, or `env` for MYCEL_TRACE).
    Trace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionSpec {
    pub layout: Layout,
    /// Metres, at full size; smaller runs shrink the area to keep density.
    pub width_m: f64,
    pub height_m: f64,
    pub env: RegionEnv,
    /// Where it is (internet geography).
    #[serde(default = "default_latlon")]
    pub latlon: [f64; 2],
    #[serde(default = "default_clusters")]
    pub clusters: usize,
    #[serde(default = "default_cluster_radius")]
    pub cluster_radius_m: f64,
    #[serde(default)]
    pub cities: Vec<String>,
    #[serde(default)]
    pub trace: Option<String>,
}

/// Where the radios are ([`Env`], in the catalogue's spelling).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegionEnv {
    Indoor,
    Outdoor,
    Crowd,
}

impl RegionEnv {
    pub fn env(self) -> Env {
        match self {
            RegionEnv::Indoor => Env::Indoor,
            RegionEnv::Outdoor => Env::Outdoor,
            RegionEnv::Crowd => Env::Crowd,
        }
    }
}

fn default_latlon() -> [f64; 2] {
    [52.52, 13.40]
}
fn default_clusters() -> usize {
    4
}
fn default_cluster_radius() -> f64 {
    40.0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Devices {
    /// iPhones: BLE + AWDL; other phones BLE + Wi-Fi Direct.
    #[serde(default = "default_ios")]
    pub ios_share: f64,
    /// Phones with peer Wi-Fi off or missing: BLE only.
    #[serde(default)]
    pub ble_only_share: f64,
}

fn default_ios() -> f64 {
    0.3
}

impl Default for Devices {
    fn default() -> Self {
        Devices { ios_share: default_ios(), ble_only_share: 0.0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MobilityModel {
    #[default]
    Static,
    /// A share of devices walk random waypoints over their area.
    Waypoint,
    /// Static clusters, and a share of devices walking between them.
    Mules,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobilitySpec {
    #[serde(default)]
    pub model: MobilityModel,
    /// Share of devices that move.
    #[serde(default = "one")]
    pub share: f64,
    #[serde(default = "default_speed")]
    pub speed_mps: f64,
    #[serde(default = "default_pause")]
    pub pause_s: f64,
}

fn one() -> f64 {
    1.0
}
fn default_speed() -> f64 {
    1.2
}
fn default_pause() -> f64 {
    120.0
}

impl Default for MobilitySpec {
    fn default() -> Self {
        MobilitySpec { model: MobilityModel::Static, share: 1.0, speed_mps: default_speed(), pause_s: default_pause() }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioSpec {
    /// Radio neighbours a device keeps connections to. Default 8: Android
    /// allows ~7 BLE connections (BTA_GATTC_CONN_MAX), iOS 6–15 reported;
    /// without a cap a dense room becomes a clique whose control traffic
    /// grows with its size (docs/SIMULATION.md §7, catalogue findings).
    #[serde(default)]
    pub max_neighbours: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMix {
    /// 75% cellular, 25% home broadband (the global world's mix).
    #[default]
    Mixed,
    Cellular,
    Home,
    /// A satellite terminal or congested 2G/3G (`Access::Slow`).
    Satellite,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternetSpec {
    /// Share of devices with internet (nominal).
    #[serde(default)]
    pub share: f64,
    /// Exactly this many gateways instead of a share (nominal).
    #[serde(default)]
    pub gateways: Option<usize>,
    #[serde(default)]
    pub access: AccessMix,
    /// Share of cellular devices behind endpoint-dependent NAT.
    #[serde(default = "default_nat_hard")]
    pub nat_hard: f64,
    #[serde(default)]
    pub outages: Vec<Outage>,
    /// Devices in a far city on home broadband, for `dest = "abroad"`.
    #[serde(default)]
    pub abroad: usize,
}

fn default_nat_hard() -> f64 {
    0.7
}

impl Default for InternetSpec {
    fn default() -> Self {
        InternetSpec {
            share: 0.0,
            gateways: None,
            access: AccessMix::Mixed,
            nat_hard: default_nat_hard(),
            outages: Vec::new(),
            abroad: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutageScope {
    All,
    /// Cellular access only: home broadband stays up.
    Cellular,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outage {
    pub at_min: f64,
    #[serde(default)]
    pub until_min: Option<f64>,
    pub scope: OutageScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsSpec {
    /// Battery stand-in: median hours until a device dies.
    #[serde(default)]
    pub battery_median_h: Option<f64>,
    /// Log-normal σ of the time to death.
    #[serde(default)]
    pub battery_sigma: Option<f64>,
    /// Share of devices switching off each minute (back the next minute).
    #[serde(default)]
    pub churn_per_min: f64,
    #[serde(default)]
    pub restart_storm: Option<RestartStorm>,
    /// A share of devices away (off) for hours: holidays, a phone left
    /// at home; their messages wait in mailboxes.
    #[serde(default)]
    pub away: Option<Away>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Away {
    pub share: f64,
    pub at_min: f64,
    pub hours: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartStorm {
    pub at_min: f64,
    pub within_min: f64,
    pub downtime_s: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdversarySpec {
    /// blackhole, liar, attested-liar, dropper, greyhole, storm, replayer,
    /// or sybil-directory (a black hole that also poisons record lookups).
    pub role: String,
    pub share: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dest {
    #[default]
    Any,
    /// Within 200 m, or the same cluster.
    Near,
    /// Another cluster or area.
    Far,
    /// The far city's devices (`internet.abroad`).
    Abroad,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSpec {
    pub per_device_hour: f64,
    #[serde(default = "default_min_messages")]
    pub min_messages: usize,
    #[serde(default = "default_max_messages")]
    pub max_messages: usize,
    #[serde(default = "default_size")]
    pub size_bytes: u32,
    #[serde(default = "default_start")]
    pub start_min: f64,
    /// Sending stops this long before the end (time to deliver).
    #[serde(default = "default_drain")]
    pub drain_min: f64,
    #[serde(default)]
    pub dest: Dest,
    #[serde(default)]
    pub calls_share: f64,
}

fn default_min_messages() -> usize {
    48
}
fn default_max_messages() -> usize {
    1500
}
fn default_size() -> u32 {
    1000
}
fn default_start() -> f64 {
    2.0
}
fn default_drain() -> f64 {
    5.0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Objectives {
    /// Delivery of feasible messages, a fraction.
    pub delivery_min: f64,
    #[serde(default)]
    pub latency_p95_max_s: Option<f64>,
    /// Control traffic per device (B/s): a BLE radio carries 40 kB/s.
    #[serde(default)]
    pub control_max_bps: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsSpec {
    #[serde(default = "default_seeds")]
    pub seeds: usize,
    #[serde(default = "default_min_pass")]
    pub min_pass: usize,
}

fn default_seeds() -> usize {
    10
}
fn default_min_pass() -> usize {
    8
}

impl Default for StatsSpec {
    fn default() -> Self {
        StatsSpec { seeds: default_seeds(), min_pass: default_min_pass() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Metric {
    /// Delivery of feasible messages, %.
    #[default]
    Delivery,
    /// Latency p95, s.
    LatencyP95,
    /// Control B/s per device.
    Control,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UqSpec {
    /// Uncertain parameters ([`crate::uq::params::BUILTIN`]).
    #[serde(default)]
    pub parameters: Vec<String>,
    #[serde(default)]
    pub metric: Metric,
    /// Ranges replacing the built-in ones.
    #[serde(default)]
    pub bounds: BTreeMap<String, [f64; 2]>,
    #[serde(default)]
    pub correlate: Vec<Correlation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub a: String,
    pub b: String,
    /// Spearman rank correlation.
    pub rho: f64,
    /// Why they move together.
    pub why: String,
}

/// Feature and fault toggles a swarm run may switch off (WP20 draws random
/// subsets; [`compose::Swarm`] applies one).
pub const SWARM_TOGGLES: &[&str] = &["fisheye", "flood-reduction", "dtn", "churn", "outages", "adversaries", "battery"];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSpec {
    #[serde(default)]
    pub toggles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Need {
    /// A model id from [`crate::fidelity::MODELS`].
    pub model: String,
    /// The result is about it: without it the run is a bound.
    #[serde(default)]
    pub essential: bool,
    /// Whether the component's stand-in means anything for this scenario;
    /// an essential need with `stand_in = false` blocks it.
    #[serde(default = "yes")]
    pub stand_in: bool,
    pub why: String,
}

fn yes() -> bool {
    true
}

/// Whether a catalogue scenario gives a verdict today.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Every essential model is in: its result is a verdict at its level.
    Verdict,
    /// An essential model is missing; it runs on a stand-in and its result
    /// is a bound in the stated direction.
    Bound,
    /// No stand-in means anything: not run until its models land.
    Blocked,
}

impl Spec {
    pub fn parse(text: &str) -> anyhow::Result<Spec> {
        let s: Spec = toml::from_str(text)?;
        s.validate()?;
        Ok(s)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let n = &self.name;
        anyhow::ensure!(
            !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "name {n:?}: lowercase, digits and dashes"
        );
        let share = |what: &str, x: f64| -> anyhow::Result<()> {
            anyhow::ensure!((0.0..=1.0).contains(&x), "{n}: {what} {x} is not a share in [0, 1]");
            Ok(())
        };
        share("adoption", self.size.adoption)?;
        share("ios_share", self.devices.ios_share)?;
        share("ble_only_share", self.devices.ble_only_share)?;
        share("mobility.share", self.mobility.share)?;
        share("internet.share", self.internet.share)?;
        share("internet.nat_hard", self.internet.nat_hard)?;
        share("os.churn_per_min", self.os.churn_per_min)?;
        share("workload.calls_share", self.workload.calls_share)?;
        share("objectives.delivery_min", self.objectives.delivery_min)?;
        anyhow::ensure!(
            self.size.ci_people <= self.size.people && self.size.ci_people > 0,
            "{n}: 0 < ci_people ≤ people"
        );
        anyhow::ensure!(self.size.duration_min > 0.0, "{n}: duration");
        anyhow::ensure!(self.region.width_m > 0.0 && self.region.height_m > 0.0, "{n}: region size");
        anyhow::ensure!(self.workload.per_device_hour > 0.0, "{n}: workload rate");
        anyhow::ensure!(
            self.workload.start_min + self.workload.drain_min
                < self.size.ci_duration_min.unwrap_or(self.size.duration_min),
            "{n}: the workload window is empty"
        );
        anyhow::ensure!(self.stats.min_pass <= self.stats.seeds && self.stats.seeds > 0, "{n}: stats");
        if self.region.layout == Layout::Cities {
            anyhow::ensure!(self.region.cities.len() >= 2, "{n}: a cities layout names two or more cities");
            for c in &self.region.cities {
                anyhow::ensure!(compose::city(c).is_some(), "{n}: unknown city {c:?}");
            }
        }
        if self.workload.dest == Dest::Abroad {
            anyhow::ensure!(self.internet.abroad > 0, "{n}: dest abroad needs internet.abroad devices");
        }
        for a in &self.adversaries {
            anyhow::ensure!(compose::role(&a.role).is_some(), "{n}: unknown adversary role {:?}", a.role);
            share("adversary share", a.share)?;
        }
        for t in &self.swarm.toggles {
            anyhow::ensure!(SWARM_TOGGLES.contains(&t.as_str()), "{n}: unknown swarm toggle {t:?}");
        }
        for need in &self.needs {
            anyhow::ensure!(fidelity::model(&need.model).is_some(), "{n}: unknown model {:?} in needs", need.model);
            anyhow::ensure!(!need.why.is_empty(), "{n}: say why it needs {}", need.model);
        }
        self.region()?;
        Ok(())
    }

    /// The models this scenario runs on.
    pub fn used(&self) -> Vec<&'static str> {
        let mut v = vec![if self.region.env == RegionEnv::Crowd { "crowd-disc" } else { "disc" }, "instant"];
        v.push(match (self.region.layout, self.mobility.model) {
            (Layout::Trace, _) => "trace",
            (_, MobilityModel::Static) => "static",
            (_, MobilityModel::Waypoint) => "waypoint",
            (_, MobilityModel::Mules) => "mules",
        });
        // the most specific model of a component first: it is the stand-in
        if self.os.battery_median_h.is_some() {
            v.push("battery-standin");
        }
        v.push("always-on");
        v.extend(["access-classes", "nat-3class", "backbone-fibre", "dht-fixed"]);
        if !self.internet.outages.is_empty() {
            v.push("outage");
        }
        if !self.adversaries.is_empty() {
            v.push("roles");
        }
        v.extend(["uniform", "shared-clock", "unlimited-storage", "one-build", "routing-core"]);
        v
    }

    /// The needs the simulator can't meet, each with its stand-in.
    pub fn missing(&self) -> Vec<Missing> {
        let used = self.used();
        self.needs
            .iter()
            .filter_map(|need| {
                let m = fidelity::model(&need.model)?;
                if m.level.is_some() {
                    return None;
                }
                let stand_in = need
                    .stand_in
                    .then(|| used.iter().filter_map(|u| fidelity::model(u)).find(|u| u.component == m.component))
                    .flatten()
                    .map(|u| u.id.to_string());
                Some(Missing {
                    component: m.component,
                    wanted: m.id.to_string(),
                    stand_in,
                    wp: m.wp.to_string(),
                    essential: need.essential,
                    bias: m.bias,
                })
            })
            .collect()
    }

    pub fn status(&self) -> Status {
        let missing = self.missing();
        if missing.iter().any(|m| m.essential && m.stand_in.is_none()) {
            Status::Blocked
        } else if missing.iter().any(|m| m.essential) {
            Status::Bound
        } else {
            Status::Verdict
        }
    }

    pub fn fidelity(&self) -> Fidelity {
        Fidelity::of(&self.used(), self.missing())
    }

    /// The nominal value of a named uncertain parameter in this world.
    pub fn nominal(&self, name: &str) -> Option<f64> {
        Some(match name {
            "range_mult" => 1.0,
            "adoption" => self.size.adoption,
            "inet_share" => match self.internet.gateways {
                Some(g) => g as f64 / self.devices_at(self.size.people, self.size.adoption).max(1) as f64,
                None => self.internet.share,
            },
            "nat_hard" => self.internet.nat_hard,
            "max_neighbours" => self.radio.max_neighbours.unwrap_or(8) as f64,
            "walk_speed" => self.mobility.speed_mps,
            "pause_s" => self.mobility.pause_s,
            "msg_rate" => 1.0,
            "adversary_share" => self.adversaries.iter().map(|a| a.share).sum(),
            "battery_median_h" => self.os.battery_median_h.unwrap_or(8.0),
            "ios_share" => self.devices.ios_share,
            "ble_only_share" => self.devices.ble_only_share,
            "churn_per_min" => self.os.churn_per_min,
            "mule_share" => self.mobility.share,
            _ => return None,
        })
    }

    /// The uncertainty region of the robustness study.
    pub fn region(&self) -> anyhow::Result<Region> {
        let mut params = Vec::new();
        for name in &self.uq.parameters {
            let mut p = builtin(name).ok_or_else(|| anyhow::anyhow!("{}: unknown parameter {name:?}", self.name))?;
            if let Some([lo, hi]) = self.uq.bounds.get(name) {
                p.lo = *lo;
                p.hi = *hi;
                p.source = format!("{} (range set by the scenario)", p.source);
            }
            p.nominal = self.nominal(name).expect("every builtin has a nominal");
            params.push(p);
        }
        for b in self.uq.bounds.keys() {
            anyhow::ensure!(self.uq.parameters.contains(b), "{}: bounds for {b:?}, which isn't varied", self.name);
        }
        let idx = |n: &str| self.uq.parameters.iter().position(|p| p == n);
        let mut corr = Vec::new();
        for c in &self.uq.correlate {
            let (Some(a), Some(b)) = (idx(&c.a), idx(&c.b)) else {
                anyhow::bail!("{}: correlation between parameters not varied", self.name)
            };
            corr.push((a, b, c.rho));
        }
        Region::new(params, corr).map_err(|e| anyhow::anyhow!("{}: {e}", self.name))
    }

    /// Devices running Mycel among `people` at `adoption` (at least 4).
    pub fn devices_at(&self, people: usize, adoption: f64) -> usize {
        ((people as f64 * adoption).round() as usize).max(4)
    }
}

/// Every catalogue scenario, parsed (panics on a malformed file: the
/// tests parse them all).
pub fn all() -> Vec<Spec> {
    FILES.iter().map(|(f, text)| Spec::parse(text).unwrap_or_else(|e| panic!("scenarios/{f}: {e:#}"))).collect()
}

pub fn find(name: &str) -> Option<Spec> {
    all().into_iter().find(|s| s.name == name || format!("{:02}", s.number) == name)
}

/// A file outside the compiled-in catalogue (`mycel-sim catalogue path.toml`).
pub fn load(path: &std::path::Path) -> anyhow::Result<Spec> {
    Spec::parse(&std::fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_is_compiled_in_parses_and_is_numbered_in_order() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("scenarios/")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|f| f.ends_with(".toml"))
            .collect();
        on_disk.sort();
        let compiled: Vec<String> = FILES.iter().map(|(f, _)| f.to_string()).collect();
        assert_eq!(on_disk, compiled, "every scenarios/*.toml is listed in FILES");
        let specs = all();
        assert_eq!(specs.len(), 36, "the design's 36 scenarios");
        for (i, (s, (f, _))) in specs.iter().zip(FILES).enumerate() {
            assert_eq!(s.number as usize, i + 1, "{f}");
            assert!(f.starts_with(&format!("{:02}-{}", s.number, s.name)), "{f} is named NN-<name>.toml");
            s.region().expect("its region is valid");
        }
        let mut names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 36, "unique names");
    }

    #[test]
    fn statuses_follow_the_needs() {
        let base = all().into_iter().find(|s| s.name == "rural-line").unwrap();
        let mut s = base.clone();
        s.needs.clear();
        assert_eq!(s.status(), Status::Verdict);
        s.needs.push(Need { model: "ble-discovery".into(), essential: false, stand_in: true, why: "x".into() });
        assert_eq!(s.status(), Status::Verdict, "a non-essential gap is a note");
        assert_eq!(s.missing()[0].stand_in.as_deref(), Some("instant"));
        s.needs[0].essential = true;
        assert_eq!(s.status(), Status::Bound);
        assert!(s.fidelity().is_bound());
        s.needs[0].stand_in = false;
        assert_eq!(s.status(), Status::Blocked);
        // an available model is no gap
        s.needs = vec![Need { model: "outage".into(), essential: true, stand_in: true, why: "x".into() }];
        assert_eq!(s.status(), Status::Verdict);
    }

    #[test]
    fn malformed_scenarios_are_refused() {
        let (_, text) = FILES[5];
        assert!(Spec::parse(text).is_ok());
        assert!(Spec::parse(&text.replace("adoption = 1.0", "adoption = 1.5")).is_err(), "a share above 1");
        assert!(Spec::parse(&format!("{text}\nbogus = 1\n")).is_err(), "unknown fields");
        let bad_need = format!("{text}\n[[needs]]\nmodel = \"warp-drive\"\nwhy = \"x\"\n");
        assert!(Spec::parse(&bad_need).is_err(), "unknown model");
    }
}
