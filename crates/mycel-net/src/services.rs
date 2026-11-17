//! The outside services a device uses to be found and reached over the
//! internet, and what it finds out about its own connection.
//!
//! By default a device uses n0's relay servers and DNS server, as Iroh
//! does, and the BitTorrent Mainline DHT. Each can be switched off
//! ([`Services`]); with the relay servers and the DNS server off, nothing
//! but other devices and the DHT is involved:
//!
//! - **found**: the device's signed record is in the DHT
//!   (`mesh/records.rs`), and others' are read from it;
//! - **reached**: directly if the internet can dial in to it, else through
//!   devices that relay for it (`mesh/relay.rs`).
//!
//! [`watch`] tells the mesh what it can't see for itself: whether the
//! internet can dial in to this device, whether it is online, and whether
//! its uplink is mobile data.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::Endpoint;
use iroh::endpoint::presets;
use mycel_crypto::DeviceKeys;

use crate::NetMode;
use crate::mesh::Mesh;
use crate::mesh::directory::{Directory, PkarrDirectory, PkarrOptions};
use crate::mesh::records::{DirectoryLookup, OwnRecord};

/// Relay servers: what carries traffic between two devices that can't
/// reach each other directly, and helps them find a direct path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Relays {
    /// n0's public relay servers.
    #[default]
    N0,
    /// Relay servers of your own: the URLs of `iroh-relay`s.
    Custom(Vec<String>),
    /// None: devices relay for each other.
    None,
}

/// The outside services a device uses in [`NetMode::Internet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Services {
    pub relays: Relays,
    /// n0's DNS server: publish our record there and resolve through it.
    pub n0_dns: bool,
    /// The Mainline DHT: publish our record there and resolve through it.
    pub dht: bool,
    /// DHT nodes remembered from the last run ([`crate::Node::dht_nodes`]):
    /// with them, joining the DHT doesn't depend on its well-known
    /// bootstrap hosts.
    pub dht_nodes: Vec<String>,
}

impl Default for Services {
    fn default() -> Self {
        Services { relays: Relays::N0, n0_dns: true, dht: true, dht_nodes: Vec::new() }
    }
}

impl Services {
    /// From the environment:
    /// - `MYCEL_RELAYS`: `n0` (the default), `none`, or the URLs of your own
    ///   relay servers, separated by commas;
    /// - `MYCEL_N0_DNS=0`: don't use n0's DNS server;
    /// - `MYCEL_DHT=0`: don't use the Mainline DHT.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string());
        Self::parse(var("MYCEL_RELAYS").as_deref(), var("MYCEL_N0_DNS").as_deref(), var("MYCEL_DHT").as_deref())
    }

    fn parse(relays: Option<&str>, n0_dns: Option<&str>, dht: Option<&str>) -> Self {
        let relays = match relays.map(str::trim) {
            None | Some("") => Relays::N0,
            Some(v) if v.eq_ignore_ascii_case("n0") => Relays::N0,
            Some(v) if ["none", "off", "0"].iter().any(|n| v.eq_ignore_ascii_case(n)) => Relays::None,
            Some(v) => Relays::Custom(v.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect()),
        };
        Services { relays, n0_dns: n0_dns != Some("0"), dht: dht != Some("0"), dht_nodes: Vec::new() }
    }

    /// Nothing but devices and the DHT: no relay server, no DNS server.
    pub fn serverless() -> Self {
        Services { relays: Relays::None, n0_dns: false, dht: true, dht_nodes: Vec::new() }
    }
}

/// An endpoint builder for [`NetMode::Internet`] with these services. Our
/// own record isn't Iroh's to publish: [`OwnRecord`] does, so one record
/// says everything (addresses, relays) wherever it is published.
pub(crate) fn internet_builder(services: &Services) -> Result<iroh::endpoint::Builder> {
    let mut b = Endpoint::builder(presets::Minimal);
    if services.n0_dns {
        b = b
            .address_lookup(iroh::address_lookup::PkarrResolver::n0_dns())
            .address_lookup(iroh::address_lookup::DnsAddressLookup::n0_dns());
    }
    let mode = match &services.relays {
        Relays::N0 => iroh::endpoint::default_relay_mode(),
        Relays::None => iroh::RelayMode::Disabled,
        Relays::Custom(urls) => {
            let urls: Vec<iroh::RelayUrl> = urls
                .iter()
                .map(|u| u.parse().map_err(|e| anyhow::anyhow!("{e}")).with_context(|| format!("relay server {u:?}")))
                .collect::<Result<_>>()?;
            if urls.is_empty() { iroh::RelayMode::Disabled } else { iroh::RelayMode::custom(urls) }
        }
    };
    Ok(b.relay_mode(mode))
}

/// A node's record keeping: where records live, and its own.
pub(crate) struct Records {
    pub dir: Arc<dyn Directory>,
    /// The real directory (not a test's): it knows about the DHT.
    pub pkarr: Option<Arc<PkarrDirectory>>,
    pub own: Arc<OwnRecord>,
}

/// Set up the directory (`given`: a test's; else the real one, on the
/// internet), look other devices' records up through it, and have Iroh
/// tell our own record our addresses. The caller runs [`OwnRecord::run`].
pub(crate) fn records(
    endpoint: &Endpoint,
    keys: &Arc<DeviceKeys>,
    mode: NetMode,
    services: &Services,
    given: Option<Arc<dyn Directory>>,
) -> Option<Records> {
    let (dir, pkarr) = match given {
        Some(dir) => (dir, None),
        None if mode == NetMode::Internet => {
            let opts = PkarrOptions { n0: services.n0_dns, dht: services.dht, dht_nodes: services.dht_nodes.clone() };
            match PkarrDirectory::new(endpoint, &opts) {
                Ok(d) => {
                    let d = Arc::new(d);
                    (Arc::new(d.clone()) as Arc<dyn Directory>, Some(d))
                }
                Err(e) => {
                    eprintln!("[mycel] no record directory: {e:#}");
                    return None;
                }
            }
        }
        None => return None,
    };
    // on the internet only addresses the internet can use are published
    let own = OwnRecord::new(keys.clone(), dir.clone(), mode == NetMode::Internet);
    let lookups = endpoint.address_lookup().ok()?;
    lookups.add(own.clone());
    lookups.add(DirectoryLookup::new(dir.clone(), keys.sign_pk()));
    // what Iroh knows already (it tells us again on every change)
    iroh::address_lookup::AddressLookup::publish(&*own, &iroh::endpoint_info::EndpointData::from(endpoint.addr()));
    Some(Records { dir, pkarr, own })
}

/// Whether a network interface is mobile data, by its name: `pdp_ip0` on
/// iPhones and iPads; `rmnet…`, `ccmni…`, `seth_lte…` on Android (and the
/// `v4-` twin Android adds on IPv6-only networks); `wwan…`, `ww…` for a
/// modem on Linux. A hotspot or a tethered phone looks like any Wi-Fi or
/// Ethernet from here, and isn't caught.
pub fn is_mobile_data(interface: &str) -> bool {
    let n = interface.to_ascii_lowercase();
    let n = n.strip_prefix("v4-").unwrap_or(&n);
    ["pdp_ip", "rmnet", "ccmni", "seth_lte", "ww"].iter().any(|p| n.starts_with(p))
}

/// How often the uplink and the DHT are looked at.
const WATCH_EVERY: Duration = Duration::from_secs(15);

/// Tell the mesh what the device's connection is like, until dropped:
/// metered, online, and whether the internet can dial in to it.
pub(crate) async fn watch(pkarr: Arc<PkarrDirectory>, mesh: Mesh, endpoint: Endpoint) {
    let mut offered: Option<SocketAddr> = None;
    loop {
        let uplink = netwatch::interfaces::State::new().await.default_route_interface;
        mesh.set_metered(uplink.as_deref().is_some_and(is_mobile_data));
        if let Some(dht) = pkarr.dht_status().await {
            mesh.set_online(uplink.is_some() && dht.nodes > 0);
            mesh.set_reachable(dht.reachable);
            // Unsolicited packets reach our DHT socket, so the router in
            // front of us lets everything in, and such routers mostly keep
            // a socket's port: offer the address the DHT sees us at, with
            // our QUIC port. A wrong guess costs whoever tries it one
            // failed dial.
            let port = endpoint.bound_sockets().iter().find(|a| a.is_ipv4()).map(|a| a.port());
            let guess = match (dht.reachable, dht.public, port) {
                (true, Some(public), Some(port)) if port != 0 => Some(SocketAddr::new((*public.ip()).into(), port)),
                _ => None,
            };
            if guess != offered {
                if let Some(old) = offered {
                    endpoint.remove_external_addr(&old).await;
                }
                if let Some(new) = guess {
                    endpoint.add_external_addr(new).await;
                }
                offered = guess;
            }
        }
        tokio::time::sleep(WATCH_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_data_interfaces_by_name() {
        for n in ["pdp_ip0", "rmnet_data0", "rmnet0", "v4-rmnet_data2", "ccmni1", "seth_lte0", "wwan0", "wwp0s20u4"] {
            assert!(is_mobile_data(n), "{n}");
        }
        for n in ["en0", "eth0", "wlan0", "wlp3s0", "awdl0", "utun3", "lo0", "bridge100", "ap0"] {
            assert!(!is_mobile_data(n), "{n}");
        }
    }

    #[test]
    fn services_from_settings() {
        assert_eq!(Services::parse(None, None, None), Services::default());
        assert_eq!(Services::parse(Some("N0"), Some("1"), Some("")), Services::default());
        let s = Services::parse(Some("none"), Some("0"), None);
        assert_eq!(s, Services::serverless());
        let s = Services::parse(Some(" https://a.example , https://b.example,"), None, Some("0"));
        assert_eq!(s.relays, Relays::Custom(vec!["https://a.example".into(), "https://b.example".into()]));
        assert!(s.n0_dns && !s.dht);
        // and they make an endpoint builder, or say what is wrong
        assert!(internet_builder(&Services::serverless()).is_ok());
        assert!(internet_builder(&s).is_ok());
        let bad = Services { relays: Relays::Custom(vec!["not a url".into()]), ..Services::default() };
        assert!(internet_builder(&bad).is_err());
    }
}
