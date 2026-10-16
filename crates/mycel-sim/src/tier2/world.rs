//! World models: continents → cities → neighbourhoods (radio areas) →
//! devices with their own radios, internet access and NAT.
//!
//! Device mixes are rough but sourced: smartphone penetration and mobile
//! internet adoption by region (GSMA "The Mobile Economy" 2024: mobile
//! internet users ~ 80–90% of the population in North America and Europe,
//! ~60% in Asia-Pacific and Latin America, ~30% in Sub-Saharan Africa).
//! Carrier-grade NAT (hard) for most cellular, easy NAT for most homes.

use super::engine::{Area, Inet, Mobility, NodeSpec, Techs};
use crate::models::{Access, Env, Nat, Tech};
use crate::stats::Rng;

/// A city: name, (lat, lon), weight (share of devices), internet adoption.
pub const CITIES: [(&str, f64, f64, f64, f64); 24] = [
    ("New York", 40.71, -74.01, 6.0, 0.88),
    ("Los Angeles", 34.05, -118.24, 4.0, 0.88),
    ("Chicago", 41.88, -87.63, 2.0, 0.88),
    ("Mexico City", 19.43, -99.13, 4.0, 0.65),
    ("São Paulo", -23.55, -46.63, 5.0, 0.65),
    ("Buenos Aires", -34.60, -58.38, 3.0, 0.70),
    ("London", 51.51, -0.13, 4.0, 0.90),
    ("Paris", 48.86, 2.35, 3.0, 0.90),
    ("Berlin", 52.52, 13.40, 2.0, 0.90),
    ("Madrid", 40.42, -3.70, 2.0, 0.88),
    ("Istanbul", 41.01, 28.98, 3.0, 0.75),
    ("Lagos", 6.52, 3.38, 4.0, 0.35),
    ("Nairobi", -1.29, 36.82, 2.0, 0.40),
    ("Cairo", 30.04, 31.24, 3.0, 0.50),
    ("Johannesburg", -26.20, 28.05, 2.0, 0.60),
    ("Mumbai", 19.08, 72.88, 6.0, 0.55),
    ("Delhi", 28.61, 77.21, 6.0, 0.55),
    ("Dhaka", 23.81, 90.41, 4.0, 0.45),
    ("Beijing", 39.90, 116.40, 6.0, 0.75),
    ("Shanghai", 31.23, 121.47, 6.0, 0.78),
    ("Tokyo", 35.68, 139.69, 6.0, 0.88),
    ("Jakarta", -6.21, 106.85, 4.0, 0.60),
    ("Sydney", -33.87, 151.21, 2.0, 0.88),
    ("Singapore", 1.35, 103.82, 2.0, 0.90),
];

/// A phone: BLE + peer Wi-Fi (AWDL on iPhones, Wi-Fi Direct on Android).
pub fn phone(area: u32, xy: (f64, f64), inet: Option<Inet>, rng: &mut Rng) -> NodeSpec {
    let p2p = if rng.chance(0.3) { Tech::Awdl } else { Tech::WifiDirect };
    NodeSpec { area, xy, radios: Techs::of(&[Tech::Ble, p2p]), inet, mobility: Mobility::Static, online: true }
}

/// A BLE-only device (an old phone, a phone with Wi-Fi off).
pub fn ble_only(area: u32, xy: (f64, f64), inet: Option<Inet>) -> NodeSpec {
    NodeSpec { area, xy, radios: Techs::of(&[Tech::Ble]), inet, mobility: Mobility::Static, online: true }
}

pub fn cellular(rng: &mut Rng) -> Inet {
    let access = if rng.chance(0.4) { Access::FiveG } else { Access::Lte };
    // most mobile carriers put phones behind carrier-grade NAT
    let nat = if rng.chance(0.7) { Nat::Hard } else { Nat::Easy };
    Inet { access, nat }
}

pub fn home(rng: &mut Rng) -> Inet {
    let access = if rng.chance(0.5) { Access::Fibre } else { Access::Cable };
    let nat = if rng.chance(0.8) {
        Nat::Easy
    } else if rng.chance(0.5) {
        Nat::Open
    } else {
        Nat::Hard
    };
    Inet { access, nat }
}

/// The global world: `n` devices across the cities above, in neighbourhoods
/// of ~`per_area` devices on 250 m × 250 m. Each device has internet with
/// its city's adoption rate (some on home broadband, most cellular).
pub fn global(n: usize, per_area: usize, rng: &mut Rng) -> (Vec<Area>, Vec<NodeSpec>) {
    let total: f64 = CITIES.iter().map(|c| c.3).sum();
    let mut areas = Vec::new();
    let mut specs = Vec::new();
    for (_, lat, lon, w, adoption) in CITIES {
        let count = ((n as f64) * w / total).round() as usize;
        let n_areas = count.div_ceil(per_area).max(1);
        for a in 0..n_areas {
            // neighbourhoods scattered over ~20 km around the centre
            let (dlat, dlon) = (rng.range(-0.09, 0.09), rng.range(-0.12, 0.12));
            let id = areas.len() as u32;
            areas.push(Area {
                latlon: (lat + dlat, lon + dlon),
                env: if a % 3 == 0 { Env::Outdoor } else { Env::Indoor },
            });
            let here = per_area.min(count - (a * per_area).min(count));
            for _ in 0..here {
                let xy = (rng.range(0.0, 250.0), rng.range(0.0, 250.0));
                let inet = if rng.chance(adoption) {
                    Some(if rng.chance(0.25) { home(rng) } else { cellular(rng) })
                } else {
                    None
                };
                specs.push(phone(id, xy, inet, rng));
            }
        }
    }
    (areas, specs)
}
