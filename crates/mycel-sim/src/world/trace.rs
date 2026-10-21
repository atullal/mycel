//! Exported worlds: the exogenous part of a tier-2 run, as JSON, to replay
//! under any candidate (`mycel-sim export-world`, `mycel-sim replay
//! --world FILE`).
//!
//! A trace holds the world's starting state (areas, devices, radios,
//! internet), the workload intents (who sends what to whom, when), the
//! adversary placement, and every exogenous change in the order the engine
//! applied it: positions, links, devices switching on and off, internet
//! coming and going. Replay drives the engine from those events alone (no
//! geometry, no mobility model, no draws), so a replayed world gives the
//! run it was exported from bit for bit: the same run hash. This is the
//! format field logs are meant to be converted to (fidelity level L4,
//! docs/SIMULATION.md §1); a field log's links would come from its
//! contacts and RSSI, and its OS states would be observations to compare
//! against, not inputs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::WorldEvent;
use crate::tier2::engine::{Area, Inet, NodeId, Techs, Time};
use crate::tier2::mycel::Role;

/// The format version, bumped on any change that old files can't be read with.
pub const FORMAT: u32 = 1;

/// A device's starting state.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub area: u32,
    #[serde(with = "exact")]
    pub xy: (f64, f64),
    pub radios: Techs,
    pub inet: Option<Inet>,
    pub online: bool,
}

/// One exported world, and the run it came from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorldTrace {
    pub format: u32,
    /// The run it was exported from: model, plan label, seed.
    pub source: String,
    /// The seed of the run. Replay uses it for the endogenous streams, so
    /// the replay pairs with the original by common random numbers.
    pub seed: u64,
    /// The routing model of the source run (`Model::name`).
    pub model: String,
    /// The source run used each model's default settings (no scenario
    /// overrides of the carrier or the baselines): replaying its model
    /// must give its run hash.
    pub default_config: bool,
    pub until: Time,
    pub areas: Vec<Area>,
    pub devices: Vec<Device>,
    /// (when, from, to, bytes, a call offer)
    pub sends: Vec<(Time, NodeId, NodeId, u32, bool)>,
    pub max_neighbours: Option<usize>,
    pub dir_poison: Option<NodeId>,
    /// Adversary placement.
    pub roles: Vec<(NodeId, Role)>,
    /// How many of `events` happened while the run started (the links up
    /// at time 0, before any router's `on_start`).
    pub start_events: usize,
    /// Every exogenous change, in the order the engine applied it.
    pub events: Vec<(Time, WorldEvent)>,
    /// BLAKE3 over all of the above as the engine saw it (hex).
    pub exo_hash: String,
    /// BLAKE3 over every event the source run's routers saw (hex).
    pub run_hash: String,
}

impl WorldTrace {
    pub fn load(path: &Path) -> anyhow::Result<WorldTrace> {
        let t: WorldTrace = serde_json::from_slice(&std::fs::read(path)?)?;
        anyhow::ensure!(
            t.format == FORMAT,
            "{}: world format {} (this build reads {FORMAT})",
            path.display(),
            t.format
        );
        Ok(t)
    }

    /// Write it whole, then rename into place (parallel runs may export
    /// the same world).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// A file name for it: the start of its exogenous hash and its model.
    pub fn file_name(&self) -> String {
        let model: String =
            self.model.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
        format!("world-{}-{}-{model}.json", self.seed, &self.exo_hash[..12.min(self.exo_hash.len())])
    }
}

/// A point as `"x,y"` in Rust's shortest round-trip notation, parsed back
/// exactly (`str::parse` rounds correctly; serde_json's default float
/// parser may miss by an ulp, and one ulp of a position changes an
/// internet delay and so the run).
pub mod exact {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(p: &(f64, f64), s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:?},{:?}", p.0, p.1))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<(f64, f64), D::Error> {
        let s = String::deserialize(d)?;
        let (x, y) = s.split_once(',').ok_or_else(|| D::Error::custom("expected \"x,y\""))?;
        Ok((x.parse().map_err(D::Error::custom)?, y.parse().map_err(D::Error::custom)?))
    }
}

static EXPORT: OnceLock<PathBuf> = OnceLock::new();

/// Export every tier-2 world run from now on into `dir` (once per process).
pub fn export_to(dir: PathBuf) -> bool {
    EXPORT.set(dir).is_ok()
}

/// Where worlds are exported, if anywhere.
pub fn export_dir() -> Option<&'static Path> {
    EXPORT.get().map(PathBuf::as_path)
}
