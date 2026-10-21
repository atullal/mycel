//! Fidelity levels: what every simulated number can be trusted for
//! (sim-fidelity §3, WP19).
//!
//! Each model a result depends on has a level, and a result carries the
//! *lowest* level among its models:
//!
//! | Level | Meaning | Supports |
//! |---|---|---|
//! | L0 abstract | literature constants, a disc, instant links | logic bugs, invariants, relative comparisons |
//! | L1 literature-grounded | cited parameters, not checked on our devices | the direction of an effect, sensitivity |
//! | L2 calibrated | fitted to our own measurements with a discrepancy term (WP14) | absolute numbers in the measured conditions |
//! | L3 validated | predictions checked on held-out measurements within pre-registered tolerances | absolute numbers in similar conditions |
//! | L4 field-replayed | a recorded real day replayed and compared with the phones' own logs | the strongest evidence short of deployment |
//!
//! Nothing in the simulator is above L1 today, and the radio is a disc
//! (L0), so every tier-2 number is L0: good for invariants and for
//! comparing designs on identical worlds, not for absolute predictions.
//!
//! [`MODELS`] lists every model the scenario catalogue can ask for, whether
//! the simulator has it, its level, the work package that brings or
//! upgrades it, and which way its absence biases results. A catalogue
//! scenario that needs a missing model either runs on a stand-in and is
//! reported as a **bound** (never a verdict), or is **blocked** if no
//! stand-in means anything ([`crate::catalogue`]).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Level {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::L0 => "L0 abstract",
            Level::L1 => "L1 literature-grounded",
            Level::L2 => "L2 calibrated",
            Level::L3 => "L3 validated",
            Level::L4 => "L4 field-replayed",
        }
    }
}

/// The part of the world a model describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    Radio,
    Link,
    Mobility,
    Os,
    Internet,
    Dht,
    Censorship,
    Adversary,
    Workload,
    Clock,
    Storage,
    Versions,
    Code,
}

/// One model the catalogue can ask for.
#[derive(Clone, Copy, Debug)]
pub struct ModelInfo {
    pub id: &'static str,
    pub component: Component,
    /// Its level if the simulator has it, `None` if it does not yet.
    pub level: Option<Level>,
    /// The work package that brings it (or lifts its level).
    pub wp: &'static str,
    /// Where it comes from (for models the simulator has), or what it
    /// would be built from.
    pub source: &'static str,
    /// Which way results move while it is missing (for missing models).
    pub bias: Bias,
}

/// The direction a missing model pushes results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bias {
    /// Results look better than reality.
    Optimistic,
    Pessimistic,
    Unknown,
    /// Not applicable (the model is available).
    None,
}

impl Bias {
    pub fn label(self) -> &'static str {
        match self {
            Bias::Optimistic => "optimistic",
            Bias::Pessimistic => "pessimistic",
            Bias::Unknown => "either way",
            Bias::None => "",
        }
    }
}

const fn have(
    id: &'static str,
    component: Component,
    level: Level,
    wp: &'static str,
    source: &'static str,
) -> ModelInfo {
    ModelInfo { id, component, level: Some(level), wp, source, bias: Bias::None }
}

const fn want(id: &'static str, component: Component, wp: &'static str, source: &'static str, bias: Bias) -> ModelInfo {
    ModelInfo { id, component, level: None, wp, source, bias }
}

use Component as C;

/// Every model the catalogue knows. Available ones say where their numbers
/// come from (`models.rs` has each parameter's source); missing ones say
/// what would bring them.
pub const MODELS: &[ModelInfo] = &[
    // radio
    have(
        "disc",
        C::Radio,
        Level::L0,
        "WP7",
        "hard range per tech and environment, lossless hops (models.rs, tier2/engine.rs)",
    ),
    have(
        "crowd-disc",
        C::Radio,
        Level::L0,
        "WP7",
        "the disc at indoor range × 0.6 for bodies absorbing 2.4 GHz (models.rs Env::Crowd)",
    ),
    want("shadowing", C::Radio, "WP7", "log-normal, spatially correlated shadowing", Bias::Unknown),
    want(
        "tdl-fading",
        C::Radio,
        "WP7",
        "frequency-selective TDL channels (TGn/TGax, 3GPP TDL) with Doppler",
        Bias::Optimistic,
    ),
    want(
        "body-loss",
        C::Radio,
        "WP7",
        "body and crowd attenuation as a link-budget term (Leith & Farrell 2020: ~20 dB swings)",
        Bias::Optimistic,
    ),
    want(
        "wall-loss",
        C::Radio,
        "WP7",
        "per-wall attenuation in buildings (ITU-R P.1238 floor/wall factors)",
        Bias::Optimistic,
    ),
    want(
        "sinr-aggregate",
        C::Radio,
        "WP7",
        "SINR with exact near-field and aggregated far-field interference",
        Bias::Optimistic,
    ),
    want("jamming", C::Radio, "WP12", "BLE and Wi-Fi jammers, reactive advertising-channel jamming", Bias::Optimistic),
    want("wifi-contention", C::Radio, "WP8", "Bianchi DCF contention, hidden terminals", Bias::Optimistic),
    // link layer
    have(
        "instant",
        C::Link,
        Level::L0,
        "WP8",
        "links up the moment two devices are in range; no discovery or connection setup",
    ),
    want(
        "ble-discovery",
        C::Link,
        "WP8",
        "advertising/scan duty cycles (Android LOW_POWER 512/5120 ms, arXiv 2006.09099), connection setup, supervision timeout",
        Bias::Optimistic,
    ),
    want(
        "wifi-direct-formation",
        C::Link,
        "WP8",
        "Wi-Fi Direct discovery 4–17 s and group formation 1.5–2.5 s (JTIIK)",
        Bias::Optimistic,
    ),
    want(
        "awdl-windows",
        C::Link,
        "WP8",
        "AWDL availability windows and channel hopping (Stute et al. 2018)",
        Bias::Optimistic,
    ),
    // mobility
    have("static", C::Mobility, Level::L0, "WP11", "devices stay where they are placed"),
    have(
        "waypoint",
        C::Mobility,
        Level::L0,
        "WP11",
        "random waypoint in 5 s steps; lacks the heavy-tailed flights and pauses of human walks (SLAW, Lee et al.)",
    ),
    have(
        "mules",
        C::Mobility,
        Level::L0,
        "WP11",
        "static clusters with a share of devices walking random waypoints across the whole region",
    ),
    have(
        "trace",
        C::Mobility,
        Level::L1,
        "WP11/WP14",
        "contacts replayed from a trace (MYCEL_TRACE: CRAWDAD Haggle, Cambridge, NUS CSV) or the synthetic Pareto trace (traces.rs)",
    ),
    want("slaw", C::Mobility, "WP11", "Self-similar Least-Action Walk (Lee et al. 2009)", Bias::Unknown),
    want(
        "map-flows",
        C::Mobility,
        "WP11",
        "map-constrained flows (SUMO, OSM), evacuation routes, shelters",
        Bias::Unknown,
    ),
    want(
        "crowd-flow",
        C::Mobility,
        "WP11",
        "crowd dynamics at 2–7 people/m² (G. K. Still; Weidmann 1993)",
        Bias::Unknown,
    ),
    want("transit", C::Mobility, "WP11", "vehicles and transit lines moving groups together", Bias::Unknown),
    want(
        "copenhagen-trace",
        C::Mobility,
        "WP11/WP14",
        "Copenhagen Networks Study BLE proximity with RSSI (Sapiezynski et al. 2019)",
        Bias::Unknown,
    ),
    // operating systems and energy
    have(
        "always-on",
        C::Os,
        Level::L0,
        "WP9",
        "every device behaves like a desktop: never suspended, dozing or killed",
    ),
    have(
        "battery-standin",
        C::Os,
        Level::L0,
        "WP9",
        "each device dies at a drawn time (log-normal around a median); exogenous, not driven by traffic",
    ),
    want(
        "ios-lifecycle",
        C::Os,
        "WP9",
        "iOS foreground/background/suspended, BGAppRefresh, CoreBluetooth restoration",
        Bias::Optimistic,
    ),
    want(
        "android-doze",
        C::Os,
        "WP9",
        "Doze, App Standby buckets, foreground-service rules, OEM killers (dontkillmyapp)",
        Bias::Optimistic,
    ),
    want("energy", C::Os, "WP9", "battery drain driven by radio and CPU use", Bias::Optimistic),
    // internet
    have(
        "access-classes",
        C::Internet,
        Level::L1,
        "WP10",
        "fibre, cable, LTE, 5G, slow (satellite/2G): one-way latency and uplink from Narayanan et al. IMC 2021, Ookla (models.rs)",
    ),
    have(
        "nat-3class",
        C::Internet,
        Level::L1,
        "WP10",
        "open/easy/hard NAT, hard–hard and hard–easy relayed (Ford et al. 2005; Richter et al. 2016)",
    ),
    have(
        "backbone-fibre",
        C::Internet,
        Level::L1,
        "WP10",
        "5 µs/km × 1.4 over the great circle (Singla et al. 2014), checked against WonderNetwork",
    ),
    have("outage", C::Internet, Level::L0, "WP10", "scheduled internet outages: all devices, or cellular access only"),
    want(
        "ipv6",
        C::Internet,
        "WP10",
        "IPv4/IPv6 per network type, 464XLAT, IPv6 stateful firewalls",
        Bias::Pessimistic,
    ),
    want("udp-blocked", C::Internet, "WP10", "3–5% of networks block UDP (RFC 9308)", Bias::Optimistic),
    want(
        "handover",
        C::Internet,
        "WP10",
        "LTE handovers (24–40 ms gaps, Nokia/AAU), dead zones, address changes",
        Bias::Optimistic,
    ),
    want("relay-outage", C::Internet, "WP10", "relay failures and capacity limits in tier 2", Bias::Optimistic),
    want("cell-capacity", C::Internet, "WP10", "cell capacity collapse in dense crowds", Bias::Optimistic),
    want("geo-satellite", C::Internet, "WP10", "GEO in-flight Wi-Fi at 550–750 ms (Rula et al. 2018)", Bias::Unknown),
    // DHT
    have(
        "dht-fixed",
        C::Dht,
        Level::L0,
        "WP10",
        "record lookups always succeed in 150 ms plus twice the access latency",
    ),
    want(
        "dht-latency",
        C::Dht,
        "WP10",
        "Mainline lookup latency and failure (Jimenez et al. 2011; VPN0 2019: 1–20 s)",
        Bias::Optimistic,
    ),
    // censorship
    want(
        "censorship-sni",
        C::Censorship,
        "WP10",
        "QUIC SNI blocking with 180 s UDP drops (Zohaib et al., USENIX Security 2025), relays blocked, DHT throttled",
        Bias::Optimistic,
    ),
    want("whitelist", C::Censorship, "WP10", "only domestic paths reachable", Bias::Optimistic),
    // adversaries
    have(
        "roles",
        C::Adversary,
        Level::L1,
        "WP12",
        "black hole, liar, attested liar, honest dropper, grey hole, storm, replayer, Sybil directory poisoner (tier2/mycel.rs Role)",
    ),
    want("radio-sybil", C::Adversary, "WP12", "one radio, many identities", Bias::Optimistic),
    want("dht-eclipse", C::Adversary, "WP12", "eclipse of a target's DHT records", Bias::Optimistic),
    want("wormhole", C::Adversary, "WP12", "two colluders tunnelling announcements", Bias::Optimistic),
    // workload
    have("uniform", C::Workload, Level::L0, "WP16", "uniform random pairs, fixed sizes, a steady rate"),
    want("social", C::Workload, "WP16", "social graph, group fan-out, diurnal rhythm, bursts", Bias::Unknown),
    want("group-sync", C::Workload, "WP4", "real sync sessions in 50-member spaces with revocations", Bias::Optimistic),
    // clocks, storage, versions
    have("shared-clock", C::Clock, Level::L0, "WP17", "every device reads one wall clock"),
    want(
        "clock-skew",
        C::Clock,
        "WP17",
        "per-device offsets (MyShake: median 0.72 s) and hour-level outliers",
        Bias::Optimistic,
    ),
    have("unlimited-storage", C::Storage, Level::L0, "WP17", "stores refuse only at the carrier's own capacity"),
    want("storage-full", C::Storage, "WP17", "devices with no free space; OS purges", Bias::Optimistic),
    have("one-build", C::Versions, Level::L0, "WP17", "every device runs the same build"),
    want("mixed-versions", C::Versions, "WP17", "v1/v2 populations, update adoption curves", Bias::Optimistic),
    // code under test
    have(
        "routing-core",
        C::Code,
        Level::L1,
        "WP4/WP6",
        "the real sans-IO routing core and carrier (mesh/core.rs, mesh/dtn.rs); node glue re-implemented, signatures stubbed",
    ),
];

/// The model `id`, if the catalogue knows it.
pub fn model(id: &str) -> Option<&'static ModelInfo> {
    MODELS.iter().find(|m| m.id == id)
}

/// A model a result asked for but ran without.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Missing {
    pub component: Component,
    pub wanted: String,
    /// The stand-in it ran on instead, if any.
    pub stand_in: Option<String>,
    pub wp: String,
    /// The result is about this model: without it the run is a bound.
    pub essential: bool,
    pub bias: Bias,
}

/// What a result can be trusted for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fidelity {
    /// The lowest level among the models used.
    pub level: Level,
    /// (component, model, level) for each model used.
    pub models: Vec<(Component, String, Level)>,
    pub missing: Vec<Missing>,
    /// The uncertainty region the result covers ("nominal point" for a
    /// single run).
    pub region: String,
    /// The robust-pass fraction over that region, once studied.
    #[serde(default)]
    pub robust_pass: Option<String>,
}

impl Fidelity {
    /// From the models used and the ones missing.
    pub fn of(used: &[&str], missing: Vec<Missing>) -> Fidelity {
        let models: Vec<(Component, String, Level)> = used
            .iter()
            .filter_map(|id| model(id).and_then(|m| m.level.map(|l| (m.component, id.to_string(), l))))
            .collect();
        let level = models.iter().map(|m| m.2).min().unwrap_or(Level::L0);
        Fidelity { level, models, missing, region: "nominal point (no uncertainty region)".into(), robust_pass: None }
    }

    /// What every hand-written scenario of a tier runs on today.
    pub fn tier_default(tier: u8) -> Fidelity {
        if tier == 2 {
            Fidelity::of(
                &[
                    "disc",
                    "instant",
                    "waypoint",
                    "always-on",
                    "access-classes",
                    "nat-3class",
                    "backbone-fibre",
                    "dht-fixed",
                    "uniform",
                    "routing-core",
                ],
                Vec::new(),
            )
        } else {
            // tier 1: the real node over EmuNet (disc range, i.i.d. loss,
            // one collision domain per channel), in real time
            Fidelity::of(&["disc", "instant", "access-classes", "nat-3class", "backbone-fibre", "uniform"], Vec::new())
        }
    }

    /// Without an essential model the result is a bound, not a verdict.
    pub fn is_bound(&self) -> bool {
        self.missing.iter().any(|m| m.essential)
    }

    /// The bias of a bound: one direction if every essential missing model
    /// agrees, else "either way".
    pub fn bound_bias(&self) -> Bias {
        let mut it = self.missing.iter().filter(|m| m.essential).map(|m| m.bias);
        let Some(first) = it.next() else { return Bias::None };
        if it.all(|b| b == first) { first } else { Bias::Unknown }
    }

    /// "L0 · bound (optimistic): needs sinr-aggregate (WP7), ble-discovery (WP8)".
    pub fn short(&self) -> String {
        let mut s = self.level.label().split(' ').next().unwrap_or("L0").to_string();
        let blocked: Vec<String> = self
            .missing
            .iter()
            .filter(|m| m.essential && m.stand_in.is_none())
            .map(|m| format!("{} ({})", m.wanted, m.wp))
            .collect();
        if !blocked.is_empty() {
            s.push_str(&format!(" · blocked: needs {}", blocked.join(", ")));
        } else if self.is_bound() {
            let needs: Vec<String> =
                self.missing.iter().filter(|m| m.essential).map(|m| format!("{} ({})", m.wanted, m.wp)).collect();
            s.push_str(&format!(" · bound ({}): needs {}", self.bound_bias().label(), needs.join(", ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_missing_models_have_a_bias() {
        let mut ids: Vec<&str> = MODELS.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate model id");
        for m in MODELS {
            assert!(!m.source.is_empty() && !m.wp.is_empty(), "{}", m.id);
            assert_eq!(m.level.is_none(), m.bias != Bias::None, "{}: missing models say which way they bias", m.id);
        }
    }

    #[test]
    fn a_result_is_as_good_as_its_weakest_model() {
        let f = Fidelity::of(&["access-classes", "nat-3class"], Vec::new());
        assert_eq!(f.level, Level::L1);
        let f = Fidelity::tier_default(2);
        assert_eq!(f.level, Level::L0, "the disc is L0");
        assert!(!f.is_bound());
        let miss = |essential, bias| Missing {
            component: Component::Radio,
            wanted: "sinr-aggregate".into(),
            stand_in: Some("disc".into()),
            wp: "WP7".into(),
            essential,
            bias,
        };
        let f = Fidelity::of(&["disc"], vec![miss(false, Bias::Optimistic)]);
        assert!(!f.is_bound(), "a non-essential gap is a note");
        let f = Fidelity::of(&["disc"], vec![miss(true, Bias::Optimistic), miss(true, Bias::Optimistic)]);
        assert!(f.is_bound() && f.bound_bias() == Bias::Optimistic);
        assert!(f.short().contains("bound (optimistic)"), "{}", f.short());
        let f = Fidelity::of(&["disc"], vec![miss(true, Bias::Optimistic), miss(true, Bias::Pessimistic)]);
        assert_eq!(f.bound_bias(), Bias::Unknown);
    }
}
