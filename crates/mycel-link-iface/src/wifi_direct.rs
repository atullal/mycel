//! Wi-Fi Direct on Linux: find nearby Mycel devices and form P2P groups with
//! them automatically, through wpa_supplicant's D-Bus API
//! (`fi.w1.wpa_supplicant1`, the `P2PDevice` interface).
//!
//! This only makes the radio link. Once a group is up, its `p2p-*` interface
//! appears and the interface link takes it like any other (beacons, its own
//! QUIC path, medium Wi-Fi Direct).
//!
//! - Advertising: a WPS vendor extension (`"myc" "EL" 0x01` + node key) in
//!   our P2P probe requests and responses, so peers can tell Mycel devices
//!   apart before connecting.
//! - Discovery: a continuous P2P `Find`; each `DeviceFound` peer's vendor
//!   extensions are checked for that marker.
//! - Group formation, no prompts (push-button WPS on both sides): the device
//!   with the lower key starts GO negotiation, wanting to be group owner; the
//!   other accepts when the request comes. A peer that already owns a group
//!   is joined instead, and a group owner lets Mycel peers in. One group per
//!   device; more Mycel devices join the same group.
//!
//! Needs wpa_supplicant running with D-Bus (`-u`), a driver with P2P
//! support (nl80211), and permission to use its D-Bus API (root or, on
//! Debian / Ubuntu, the `netdev` group). Distributions where NetworkManager
//! drives wpa_supplicant work too, but NetworkManager may also try to manage
//! the group interface.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use futures_util::StreamExt;
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

const SERVICE: &str = "fi.w1.wpa_supplicant1";
const ROOT: &str = "/fi/w1/wpa_supplicant1";
const IFACE: &str = "fi.w1.wpa_supplicant1.Interface";
const P2P: &str = "fi.w1.wpa_supplicant1.Interface.P2PDevice";
const WPS: &str = "fi.w1.wpa_supplicant1.Interface.WPS";
const PEER: &str = "fi.w1.wpa_supplicant1.Peer";
/// Vendor-extension marker: a made-up "OUI" ("myc") plus "EL" and a version.
const MARKER: &[u8; 6] = b"mycEL\x01";
/// Don't try the same peer again sooner than this.
const RETRY_PEER: Duration = Duration::from_secs(20);
/// Restart everything this long after wpa_supplicant went away or failed.
const RETRY: Duration = Duration::from_secs(10);

/// What the Network panel shows while there is no group yet.
pub type Status = Arc<Mutex<Option<String>>>;

/// Run until the task is dropped: form groups with Mycel peers.
pub async fn run(me: SignPk, status: Status) {
    loop {
        match session(me, &status).await {
            Ok(()) => {}
            Err(e) => {
                crate::log(format_args!("Wi-Fi Direct: {e:#}"));
                *status.lock() = Some(format!("Wi-Fi Direct unavailable: {e}"));
            }
        }
        tokio::time::sleep(RETRY).await;
    }
}

/// Our vendor extension.
pub fn marker(me: &SignPk) -> Vec<u8> {
    let mut v = MARKER.to_vec();
    v.extend_from_slice(&me.0);
    v
}

/// The node key in a peer's vendor extensions, if it is a Mycel device.
pub fn mycel_key(exts: &[Vec<u8>]) -> Option<SignPk> {
    exts.iter().find_map(|e| Some(SignPk(e.strip_prefix(MARKER.as_slice())?.get(..32)?.try_into().ok()?)))
}

fn args<'a>(pairs: &[(&'a str, Value<'a>)]) -> HashMap<&'a str, Value<'a>> {
    pairs.iter().cloned().collect()
}

async fn session(me: SignPk, status: &Status) -> Result<()> {
    let conn = Connection::system().await.context("no system D-Bus")?;
    let root = Proxy::new(&conn, SERVICE, ROOT, SERVICE).await?;
    let ifaces: Vec<OwnedObjectPath> =
        root.get_property("Interfaces").await.context("wpa_supplicant isn't running with D-Bus (-u)")?;
    // the first interface that does P2P
    let mut p2p = None;
    for path in ifaces {
        let p = Proxy::new(&conn, SERVICE, path.clone(), P2P).await?;
        if p.get_property::<HashMap<String, OwnedValue>>("P2PDeviceConfig").await.is_ok() {
            p2p = Some((path, p));
            break;
        }
    }
    let (path, p2p) = p2p.context("no Wi-Fi interface with P2P support")?;
    let exts: Vec<Vec<u8>> = vec![marker(&me)];
    p2p.set_property("P2PDeviceConfig", args(&[("VendorExtension", Value::from(exts))]))
        .await
        .context("can't set our P2P vendor extension")?;
    let mut found = p2p.receive_signal("DeviceFound").await?;
    let mut go_req = p2p.receive_signal("GONegotiationRequest").await?;
    let mut pbc_req = p2p.receive_signal("ProvisionDiscoveryPBCRequest").await?;
    let mut started = p2p.receive_signal("GroupStarted").await?;
    let mut finished = p2p.receive_signal("GroupFinished").await?;
    let mut stopped = p2p.receive_signal("FindStopped").await?;
    let find = || async { p2p.call_method("Find", &args(&[])).await.map(|_| ()) };
    find().await.context("P2P Find failed")?;
    crate::log(format_args!("Wi-Fi Direct: looking for Mycel devices on {}", path.as_str()));
    *status.lock() = Some("Looking for nearby devices…".into());

    // (role, group interface object)
    let mut group: Option<(String, OwnedObjectPath)> = None;
    let mut tried: HashMap<OwnedObjectPath, Instant> = HashMap::new();
    loop {
        tokio::select! {
            Some(m) = found.next() => {
                let Ok(peer) = m.body().deserialize::<OwnedObjectPath>() else { continue };
                let Some((key, peer_is_go)) = peer_info(&conn, &peer).await else { continue };
                if group.is_some() || tried.get(&peer).is_some_and(|t| t.elapsed() < RETRY_PEER) {
                    continue;
                }
                if peer_is_go {
                    crate::log(format_args!("Wi-Fi Direct: joining {}'s group", crate::short(&key)));
                    tried.insert(peer.clone(), Instant::now());
                    connect(&p2p, &peer, &[("join", Value::from(true))]).await;
                } else if me.0 < key.0 {
                    crate::log(format_args!("Wi-Fi Direct: forming a group with {}", crate::short(&key)));
                    tried.insert(peer.clone(), Instant::now());
                    connect(&p2p, &peer, &[("go_intent", Value::from(15i32))]).await;
                }
                // (the higher key waits for the lower one's request)
            }
            Some(m) = go_req.next() => {
                let Ok((peer, _pw, _intent)) = m.body().deserialize::<(OwnedObjectPath, u16, u8)>() else { continue };
                if group.is_none() && peer_info(&conn, &peer).await.is_some() {
                    crate::log(format_args!("Wi-Fi Direct: accepting a group from {}", peer.as_str()));
                    connect(&p2p, &peer, &[("go_intent", Value::from(0i32))]).await;
                }
            }
            Some(m) = pbc_req.next() => {
                // a Mycel peer wants to join the group we own: push the button
                let Ok(peer) = m.body().deserialize::<OwnedObjectPath>() else { continue };
                if let Some((role, gif)) = &group
                    && role == "GO"
                    && peer_info(&conn, &peer).await.is_some()
                {
                    let wps = Proxy::new(&conn, SERVICE, gif.clone(), WPS).await?;
                    let _ = wps.call_method("Start", &args(&[("Role", Value::from("enrollee")), ("Type", Value::from("pbc"))])).await;
                }
            }
            Some(m) = started.next() => {
                let Ok(info) = m.body().deserialize::<HashMap<String, OwnedValue>>() else { continue };
                let role = info.get("role").and_then(|v| String::try_from(v.clone()).ok()).unwrap_or_default();
                let Some(gif) = info.get("interface_object").and_then(|v| OwnedObjectPath::try_from(v.clone()).ok()) else { continue };
                let name: String = Proxy::new(&conn, SERVICE, gif.clone(), IFACE).await?.get_property("Ifname").await.unwrap_or_default();
                crate::log(format_args!("Wi-Fi Direct: group up on {name} as {role}"));
                *status.lock() = Some(format!("In a group on {name} ({})", if role == "GO" { "owner" } else { "member" }));
                group = Some((role, gif));
            }
            Some(_) = finished.next() => {
                crate::log(format_args!("Wi-Fi Direct: group ended"));
                group = None;
                *status.lock() = Some("Looking for nearby devices…".into());
                let _ = find().await;
            }
            Some(_) = stopped.next() => {
                // keep looking (a group owner keeps looking too, so others can join it)
                if group.as_ref().is_none_or(|(role, _)| role == "GO") {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = find().await;
                }
            }
            else => return Ok(()),
        }
    }
}

/// A peer's node key if it is a Mycel device, and whether it owns a group.
async fn peer_info(conn: &Connection, peer: &OwnedObjectPath) -> Option<(SignPk, bool)> {
    let p = Proxy::new(conn, SERVICE, peer.clone(), PEER).await.ok()?;
    let exts: Vec<Vec<u8>> = p.get_property("VendorExtension").await.ok()?;
    let key = mycel_key(&exts)?;
    // P2P Group Capability bit 0: P2P Group Owner
    let caps: u8 = p.get_property("GroupCapability").await.unwrap_or(0);
    Some((key, caps & 0x01 != 0))
}

/// Push-button connect to `peer`, plus `extra` arguments.
async fn connect(p2p: &Proxy<'_>, peer: &OwnedObjectPath, extra: &[(&str, Value<'_>)]) {
    let mut a = args(&[("peer", Value::from(peer.as_ref())), ("wps_method", Value::from("pbc"))]);
    a.extend(extra.iter().cloned());
    if let Err(e) = p2p.call_method("Connect", &a).await {
        crate::log(format_args!("Wi-Fi Direct: connect failed: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_mycel_devices() {
        let me = SignPk([5; 32]);
        assert_eq!(mycel_key(&[b"\x00\x50\xf2xx".to_vec(), marker(&me)]), Some(me));
        assert_eq!(mycel_key(&[b"mycEL\x02".to_vec()]), None);
        assert_eq!(mycel_key(&[]), None);
    }
}
