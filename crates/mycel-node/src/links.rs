//! The non-IP links a device runs (peer-to-peer Wi-Fi, Bluetooth).
//!
//! `MYCEL_LINKS` picks them: unset or `all` = every link this platform has,
//! `none` = IP only, or a comma list of `awdl` / `ble`.

use std::sync::Arc;

use mycel_crypto::SignPk;
use mycel_net::Link;

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
