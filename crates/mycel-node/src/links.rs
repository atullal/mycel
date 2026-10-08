//! The links a device runs besides Iroh's IP transport: every radio or
//! interface this platform can use.
//!
//! | link         | what                                                     | where          |
//! |--------------|----------------------------------------------------------|----------------|
//! | `awdl`       | Apple peer-to-peer Wi-Fi                                  | macOS          |
//! | `ble`        | Bluetooth LE (CoreBluetooth / BlueZ, wire-compatible)     | macOS, Linux   |
//! | `iface`      | any other network interface: UWB / 802.15.4, Thread,      | macOS, Linux   |
//! |              | Wi-Fi Direct and mesh groups, cables, a second NIC        |                |
//! | `wifidirect` | also *form* Wi-Fi Direct groups (wpa_supplicant); opt-in  | Linux          |
//!
//! `MYCEL_LINKS` picks them: unset or `all` = the defaults (all but
//! `wifidirect`), `none` = IP only, or a comma list of the names above
//! (`uwb`, `thread`, `802154` and `p2p` are other names for `iface`;
//! `all,wifidirect` = the defaults plus Wi-Fi Direct).
//! `MYCEL_WIFI_DIRECT=1` adds `wifidirect` to the defaults.
//!
//! The mesh relays over all of them (and the LAN): see [`mesh_options`].

use std::sync::Arc;

use mycel_crypto::SignPk;
use mycel_net::{Link, MeshOptions};

/// Multi-hop relaying through nearby devices, on unless `MYCEL_MESH=0`.
/// `MYCEL_MESH_RELAY=0` still uses the mesh but relays nothing for others.
pub fn mesh_options() -> Option<MeshOptions> {
    let off = |var: &str| std::env::var(var).is_ok_and(|v| v.trim() == "0");
    if off("MYCEL_MESH") {
        return None;
    }
    Some(MeshOptions { relay: !off("MYCEL_MESH_RELAY"), ..MeshOptions::default() })
}

/// Links this platform has, in the order they start.
const PLATFORM: &[&str] = if cfg!(target_os = "macos") {
    &["awdl", "ble", "iface"]
} else if cfg!(target_os = "linux") {
    &["ble", "iface", "wifidirect"]
} else if cfg!(unix) {
    &["iface"]
} else {
    &[]
};

/// Which of the platform's links `spec` (`MYCEL_LINKS`) turns on.
fn wanted(spec: &str, wifi_direct: bool) -> Vec<&'static str> {
    let spec = spec.trim().to_ascii_lowercase();
    if spec == "none" {
        return Vec::new();
    }
    let named: Vec<&str> = spec
        .split(',')
        .map(|w| match w.trim() {
            "uwb" | "thread" | "802154" | "802.15.4" | "p2p" | "interfaces" => "iface",
            "wifi-direct" | "wifi_direct" => "wifidirect",
            other => other,
        })
        .collect();
    let all = spec.is_empty() || named.contains(&"all");
    PLATFORM
        .iter()
        .copied()
        .filter(|l| match *l {
            "wifidirect" => named.contains(l) || (all && wifi_direct),
            _ => all || named.contains(l),
        })
        .collect()
}

/// The links for node `me` advertising `name`.
///
/// The interface link always leaves ordinary NICs with a routable address
/// to Iroh's IP transport, also under `MYCEL_IP=0`: that switch means "no
/// Wi-Fi / Ethernet networking, prove the other paths work".
pub fn device_links(me: SignPk, name: &str) -> Vec<Arc<dyn Link>> {
    let ip = true;
    let spec = std::env::var("MYCEL_LINKS").unwrap_or_default();
    let wifi_direct = std::env::var("MYCEL_WIFI_DIRECT").is_ok_and(|v| v.trim() == "1");
    let on = wanted(&spec, wifi_direct);
    let mut links: Vec<Arc<dyn Link>> = Vec::new();
    if on.contains(&"awdl") {
        links.push(mycel_link_awdl::link(me, name));
    }
    if on.contains(&"ble") {
        links.push(mycel_link_ble::link(me, name));
    }
    if on.contains(&"wifidirect") {
        links.push(mycel_link_iface::link_with_wifi_direct(me, name, ip));
    } else if on.contains(&"iface") {
        links.push(mycel_link_iface::link(me, name, ip));
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_links() {
        let defaults: Vec<&str> = PLATFORM.iter().copied().filter(|l| *l != "wifidirect").collect();
        assert_eq!(wanted("", false), defaults);
        assert_eq!(wanted("all", false), defaults);
        assert_eq!(wanted("none", true), Vec::<&str>::new());
        assert_eq!(wanted("all,ble", false), defaults, "all means all");
        if cfg!(target_os = "macos") {
            assert_eq!(wanted("awdl, BLE", false), vec!["awdl", "ble"]);
            assert_eq!(wanted("uwb", false), vec!["iface"]);
            assert_eq!(wanted("wifidirect", false), Vec::<&str>::new(), "not on macOS");
        }
        if cfg!(target_os = "linux") {
            assert_eq!(wanted("", true), vec!["ble", "iface", "wifidirect"]);
            assert_eq!(wanted("wifi-direct", false), vec!["wifidirect"]);
            assert_eq!(wanted("all,wifidirect", false), vec!["ble", "iface", "wifidirect"]);
            assert_eq!(wanted("awdl", false), Vec::<&str>::new(), "not on Linux");
        }
    }
}
