//! The non-IP links a device runs (peer-to-peer Wi-Fi, Bluetooth).
//!
//! `MYCEL_LINKS` picks them: unset or `all` = every link this platform has,
//! `none` = IP only, or a comma list of `awdl` / `ble`. The mesh relays over
//! all of them (and the LAN): see [`mesh_options`].

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

pub fn device_links(me: SignPk, name: &str) -> Vec<Arc<dyn Link>> {
    let want = std::env::var("MYCEL_LINKS").unwrap_or_default().to_ascii_lowercase();
    let want = want.trim();
    let on = |l: &str| want.is_empty() || want == "all" || want.split(',').any(|w| w.trim() == l);
    let mut links: Vec<Arc<dyn Link>> = Vec::new();
    if want == "none" {
        return links;
    }
    if on("awdl") {
        links.push(mycel_link_awdl::link(me, name));
    }
    if on("ble") {
        links.push(mycel_link_ble::link(me, name));
    }
    links
}
