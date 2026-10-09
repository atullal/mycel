//! Link and network models, with where each number comes from. Both tiers
//! use these: tier 1 turns them into [`EmuNet`](mycel_net::emu::EmuNet)
//! media for real nodes, tier 2 into per-hop delay and capacity.
//!
//! The numbers are application-level goodput and one-way latency, not PHY
//! rates. Sources (see docs/SIMULATION.md for the full list):
//!
//! - **BLE L2CAP CoC**: 1M PHY tops out near 700–800 kbit/s of payload
//!   with data length extension and short connection intervals; phones and
//!   Macs typically get 100–400 kbit/s with several connections sharing the
//!   radio (Bluetooth Core 5.x; Apple "What's new in Core Bluetooth" WWDC17
//!   L2CAP CoC ~ 4× GATT; measurements in Gomez et al., "Overview and
//!   Evaluation of BLE", Sensors 2012). Latency is dominated by the
//!   connection interval (7.5 ms–4 s; Apple's minimum 15 ms). Range 10–30 m
//!   indoors, 50–100 m outdoors line of sight (Core spec class 2, 0 dBm).
//!   We use 40 KB/s (320 kbit/s), 15 ms + 15 ms jitter, 20 m indoor / 60 m
//!   outdoor.
//! - **AWDL** (Apple peer-to-peer Wi-Fi): an 802.11ac link that hops
//!   between its own channel and the infrastructure one in 16 TU slots
//!   (Stute et al., "One Billion Apples' Secret Sauce: Recipe for the Apple
//!   Wireless Direct Link Ad hoc Protocol", MobiCom 2018); AirDrop moves
//!   ~100–300 Mbit/s; channel switching adds tens of ms of jitter. We use
//!   12 MB/s (~100 Mbit/s), 2 ms + 20 ms jitter, 50 m indoor / 100 m outdoor.
//! - **Wi-Fi Direct** (802.11n/ac P2P group): like a Wi-Fi BSS with the
//!   group owner as AP; 50–150 Mbit/s, 100–200 m outdoors. 8 MB/s, 3 ms +
//!   5 ms jitter, 50 m / 150 m.
//! - **Wi-Fi AP LAN**: device → AP → device, two airtime hops in one
//!   collision domain; a busy 802.11ac BSS gives each of a few stations
//!   tens of Mbit/s. 15 MB/s shared, 3 ms + 5 ms jitter.
//! - **802.11s mesh**: each extra Wi-Fi hop on one channel divides
//!   throughput (a chain on one channel converges to ~1/4 of the
//!   single-hop rate: Li et al., "Capacity of Ad Hoc Wireless Networks",
//!   MobiCom 2001) and adds ~2–5 ms. We use rate / min(hops, 4) and 3 ms
//!   per hop.
//! - **Ethernet**: switched gigabit, ~940 Mbit/s TCP goodput, <0.3 ms.
//!   110 MB/s, 0.2 ms.
//! - **UWB** (802.15.4z HRP, 6.8 Mbit/s PHY; Qorvo DW3000 data mode): a few
//!   Mbit/s of payload at best, 10–50 m. 250 KB/s, 2 ms, 30 m.
//! - **802.15.4 / Thread** (O-QPSK 250 kbit/s PHY; with 6LoWPAN, MAC
//!   overhead and CSMA ~50–100 kbit/s of payload per hop; Thread group
//!   whitepapers): 8 KB/s, 10 ms + 10 ms jitter, 1% loss, 25 m.
//! - **Cellular access**: LTE median RTT to the first server ~40–60 ms,
//!   5G SA ~10–20 ms; uplink a few Mbit/s (Ookla/OpenSignal reports; Narayanan
//!   et al., "A First Look at Commercial 5G Performance", IMC 2021 (5G
//!   mmWave) and "Lumos5G" 2020). We use access one-way 20 ms (LTE), 8 ms
//!   (5G), uplink 1.5 MB/s.
//! - **Home broadband / fibre access**: 2–10 ms one way; uplink 2–100 MB/s.
//! - **Internet backbone**: light in fibre covers ~200 km/ms (refractive
//!   index ~1.47 → 4.9 µs/km); real routes are longer than the great
//!   circle by ~1.3–2× (Singla et al., "The Internet at the Speed of
//!   Light", HotNets 2014). We use 5 µs/km × 1.4: New York–London
//!   (5,570 km) → ~39 ms one way, ~78 ms RTT, matching the 70–80 ms
//!   measured on transatlantic routes.
//! - **NAT**: hole punching works between endpoint-independent ("easy")
//!   NATs, fails when both sides are endpoint-dependent ("hard", symmetric:
//!   most carrier-grade NATs) and mostly when one is hard and the other
//!   port-restricted (Ford et al., "Peer-to-Peer Communication Across NATs",
//!   USENIX ATC 2005; Richter et al., "A Multi-perspective Analysis of
//!   Carrier-Grade NAT Deployment", IMC 2016). Tailscale and n0 report
//!   ~90% of connections going direct. We use: hard–hard and hard–easy go
//!   through a relay, everything with an open side goes direct.
//! - **Relays**: regional relay servers (n0 runs them in North America,
//!   Europe and Asia-Pacific); the path is client → nearest relay → peer's
//!   relay → peer.

use std::time::Duration;

use mycel_net::emu::{Latency, Medium};
use mycel_net::link::PathKind;
use serde::{Deserialize, Serialize};

/// Where a radio is used: range differs a lot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Env {
    Indoor,
    Outdoor,
    /// A dense crowd: bodies absorb 2.4 GHz.
    Crowd,
}

/// A link technology with its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tech {
    Ble,
    Awdl,
    WifiDirect,
    WifiAp,
    WifiMesh,
    Ethernet,
    Uwb,
    Thread,
    /// The ONE simulator's default Bluetooth interface (250 kB/s, 10 m), for
    /// replaying contact traces with The ONE's standard settings.
    OneBt,
}

impl Tech {
    pub const ALL: [Tech; 9] =
        [Tech::Ble, Tech::Awdl, Tech::WifiDirect, Tech::WifiAp, Tech::WifiMesh, Tech::Ethernet, Tech::Uwb, Tech::Thread, Tech::OneBt];

    pub fn kind(self) -> PathKind {
        match self {
            Tech::Ble => PathKind::Bluetooth,
            Tech::Awdl => PathKind::PeerWifi,
            Tech::WifiDirect => PathKind::WifiDirect,
            Tech::WifiAp => PathKind::Network,
            Tech::WifiMesh => PathKind::Other,
            Tech::Ethernet => PathKind::Ethernet,
            Tech::Uwb => PathKind::Uwb,
            Tech::Thread => PathKind::Ieee802154,
            Tech::OneBt => PathKind::Bluetooth,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tech::Ble => "Bluetooth LE",
            Tech::Awdl => "AWDL",
            Tech::WifiDirect => "Wi-Fi Direct",
            Tech::WifiAp => "Wi-Fi LAN",
            Tech::WifiMesh => "802.11s mesh",
            Tech::Ethernet => "Ethernet",
            Tech::Uwb => "UWB",
            Tech::Thread => "Thread / 802.15.4",
            Tech::OneBt => "Bluetooth (The ONE default)",
        }
    }

    /// Payload bytes per second one radio sends.
    pub fn rate(self) -> u64 {
        match self {
            Tech::Ble => 40_000,
            Tech::Awdl => 12_000_000,
            Tech::WifiDirect => 8_000_000,
            Tech::WifiAp => 15_000_000,
            Tech::WifiMesh => 10_000_000,
            Tech::Ethernet => 110_000_000,
            Tech::Uwb => 250_000,
            Tech::Thread => 8_000,
            Tech::OneBt => 250_000,
        }
    }

    pub fn latency(self) -> Duration {
        Duration::from_micros(match self {
            Tech::Ble => 15_000,
            Tech::Awdl => 2_000,
            Tech::WifiDirect => 3_000,
            Tech::WifiAp => 3_000,
            Tech::WifiMesh => 3_000,
            Tech::Ethernet => 200,
            Tech::Uwb => 2_000,
            Tech::Thread => 10_000,
            Tech::OneBt => 1_000,
        })
    }

    pub fn jitter(self) -> Duration {
        Duration::from_micros(match self {
            Tech::Ble => 15_000,
            Tech::Awdl => 20_000,
            Tech::WifiDirect | Tech::WifiAp => 5_000,
            Tech::WifiMesh => 5_000,
            Tech::Ethernet => 50,
            Tech::Uwb => 1_000,
            Tech::Thread => 10_000,
            Tech::OneBt => 0,
        })
    }

    pub fn loss(self) -> f64 {
        match self {
            Tech::Thread => 0.01,
            Tech::Ble => 0.002,
            Tech::Ethernet | Tech::OneBt => 0.0,
            _ => 0.001,
        }
    }

    /// Range in metres.
    pub fn range(self, env: Env) -> f64 {
        let (indoor, outdoor) = match self {
            Tech::Ble => (20.0, 60.0),
            Tech::Awdl => (50.0, 100.0),
            Tech::WifiDirect => (50.0, 150.0),
            Tech::WifiAp | Tech::WifiMesh => (40.0, 100.0),
            Tech::Ethernet => (f64::INFINITY, f64::INFINITY),
            Tech::Uwb => (30.0, 60.0),
            Tech::Thread => (25.0, 80.0),
            Tech::OneBt => (10.0, 10.0),
        };
        match env {
            Env::Indoor => indoor,
            Env::Outdoor => outdoor,
            Env::Crowd => indoor * 0.6,
        }
    }

    /// Radios a device can't use while sending or receiving (one antenna).
    pub fn half_duplex(self) -> bool {
        !matches!(self, Tech::Ethernet)
    }

    /// One collision domain: everyone in range of a sender is quiet. BLE
    /// hops over 37 channels, so its neighbourhoods barely contend.
    pub fn shared_channel(self) -> bool {
        matches!(self, Tech::Awdl | Tech::WifiDirect | Tech::WifiAp | Tech::WifiMesh | Tech::Thread)
    }

    /// The tier-1 medium.
    pub fn medium(self, env: Env) -> Medium {
        let mut m = Medium::ideal(self.kind());
        m.label = self.label();
        m.rate = Some(self.rate());
        m.latency = Latency::Fixed(self.latency());
        m.jitter = self.jitter();
        m.loss = self.loss();
        m.range = self.range(env);
        m.half_duplex = self.half_duplex();
        m.shared_channel = self.shared_channel();
        m
    }
}

/// How a device reaches the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    Fibre,
    Cable,
    Lte,
    FiveG,
    /// A slow uplink: satellite or congested 2G/3G.
    Slow,
}

impl Access {
    /// One-way delay from the device to the internet core.
    pub fn latency(self) -> Duration {
        Duration::from_millis(match self {
            Access::Fibre => 2,
            Access::Cable => 8,
            Access::Lte => 20,
            Access::FiveG => 8,
            Access::Slow => 300,
        })
    }

    /// Uplink payload bytes per second.
    pub fn uplink(self) -> u64 {
        match self {
            Access::Fibre => 50_000_000,
            Access::Cable => 3_000_000,
            Access::Lte => 1_500_000,
            Access::FiveG => 5_000_000,
            Access::Slow => 10_000,
        }
    }
}

/// NAT behaviour for direct connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nat {
    /// Public address or UPnP / port mapping.
    Open,
    /// Endpoint-independent mapping: hole punching works.
    Easy,
    /// Endpoint-dependent (symmetric), e.g. carrier-grade NAT.
    Hard,
}

impl Nat {
    /// Whether two devices can talk directly, or need a relay.
    pub fn direct(a: Nat, b: Nat) -> bool {
        !matches!((a, b), (Nat::Hard, Nat::Hard) | (Nat::Hard, Nat::Easy) | (Nat::Easy, Nat::Hard))
    }
}

/// Fibre propagation with path inflation: microseconds per great-circle km.
pub const FIBRE_US_PER_KM: f64 = 5.0;
pub const PATH_INFLATION: f64 = 1.4;

/// One-way backbone delay over `km` of great circle.
pub fn backbone(km: f64) -> Duration {
    Duration::from_secs_f64(km * FIBRE_US_PER_KM * PATH_INFLATION / 1e6)
}

/// Regional relay servers (lat, lon), like n0's: us-east, us-west, eu-central, ap-southeast.
pub const RELAYS: [(&str, f64, f64); 4] =
    [("us-east", 39.04, -77.49), ("us-west", 37.34, -121.89), ("eu-central", 50.11, 8.68), ("ap-southeast", 1.35, 103.82)];

/// Great-circle km between two (lat, lon) points.
pub fn km(a: (f64, f64), b: (f64, f64)) -> f64 {
    mycel_net::emu::Pos::new(a.0, a.1).km(&mycel_net::emu::Pos::new(b.0, b.1))
}

/// The nearest relay to a (lat, lon) point.
pub fn nearest_relay(p: (f64, f64)) -> (f64, f64) {
    RELAYS
        .iter()
        .map(|(_, la, lo)| (*la, *lo))
        .min_by(|a, b| km(p, *a).total_cmp(&km(p, *b)))
        .expect("relays")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transatlantic_rtt_is_realistic() {
        let rtt = 2 * backbone(km((40.71, -74.01), (51.51, -0.13)));
        assert!((70..90).contains(&rtt.as_millis()), "{rtt:?}");
    }

    #[test]
    fn nat_rules() {
        assert!(Nat::direct(Nat::Easy, Nat::Easy));
        assert!(Nat::direct(Nat::Hard, Nat::Open));
        assert!(!Nat::direct(Nat::Hard, Nat::Hard));
        assert!(!Nat::direct(Nat::Easy, Nat::Hard));
    }
}
