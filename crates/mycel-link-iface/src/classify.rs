//! Which network interfaces become paths, and what medium each one is.
//! Pure functions over [`IfaceInfo`], so the rules are unit-tested on any OS.

use std::net::Ipv6Addr;

use mycel_net::PathKind;

/// The hardware type the OS reports for an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hw {
    Unknown,
    /// Ethernet framing (wired NICs; on macOS Wi-Fi too).
    Ethernet,
    /// An 802.11 interface (Linux: has `/sys/class/net/<if>/wireless`).
    Wifi,
    Loopback,
    /// IEEE 802.15.4 (`ARPHRD_IEEE802154`, a raw `wpan*` radio).
    Ieee802154,
    /// 6LoWPAN on top of 802.15.4 (`ARPHRD_6LOWPAN`, `lowpan*`).
    Lowpan,
    /// IP-in-IP, SIT, TUN, WireGuard, PPP: no hardware of its own.
    Tunnel,
    /// A bridge or VLAN made by software.
    Virtual,
}

/// One interface as enumerated (see [`crate::ifaces`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfaceInfo {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub multicast: bool,
    pub loopback: bool,
    pub hw: Hw,
    /// Its IPv6 link-local address (what this link talks over).
    pub link_local: Option<Ipv6Addr>,
    /// It also has a routable address (IPv4 other than 169.254/16, global or
    /// ULA IPv6): Iroh's own IP transport reaches peers through it.
    pub routable: bool,
}

/// What to do with an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A path over it, of this medium, described as `label`.
    Use { kind: PathKind, label: String },
    /// Not ours; why (for diagnostics).
    Skip(&'static str),
}

/// Knobs from the link's options and the environment.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    /// Iroh's IP transport is on: leave it the interfaces it already uses.
    pub ip_covers_routable: bool,
    /// Tests: loopback counts as a medium too.
    pub loopback: bool,
    /// `MYCEL_IFACES=a,b`: only these interfaces.
    pub only: Option<Vec<String>>,
    /// `MYCEL_IFACE_MEDIUM=wpan0=uwb,...`: say what an interface is.
    pub medium: Vec<(String, PathKind)>,
}

impl Rules {
    /// `MYCEL_IFACES` and `MYCEL_IFACE_MEDIUM` from the environment.
    pub fn from_env(ip_covers_routable: bool) -> Rules {
        let only = std::env::var("MYCEL_IFACES")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>())
            .filter(|v| !v.is_empty());
        let medium = std::env::var("MYCEL_IFACE_MEDIUM").map(|v| parse_medium(&v)).unwrap_or_default();
        Rules { ip_covers_routable, loopback: false, only, medium }
    }
}

/// `wpan0=uwb,mesh0=other` → [(wpan0, Uwb), (mesh0, Other)]; unknown names skipped.
pub fn parse_medium(spec: &str) -> Vec<(String, PathKind)> {
    spec.split(',')
        .filter_map(|pair| {
            let (name, kind) = pair.split_once('=')?;
            Some((name.trim().to_string(), medium_named(kind.trim())?))
        })
        .collect()
}

/// A medium by the name a user would type.
pub fn medium_named(s: &str) -> Option<PathKind> {
    Some(match s.to_ascii_lowercase().replace(['-', '_', ' ', '.'], "").as_str() {
        "uwb" => PathKind::Uwb,
        "802154" | "ieee802154" | "thread" | "6lowpan" | "lowpan" | "zigbee" => PathKind::Ieee802154,
        "wifidirect" | "p2p" => PathKind::WifiDirect,
        "ethernet" | "cable" | "wired" => PathKind::Ethernet,
        "network" | "wifi" | "lan" => PathKind::Network,
        "other" => PathKind::Other,
        _ => return None,
    })
}

/// Software interfaces with no radio or cable of their own (VPNs, container
/// and VM plumbing), and ones another link already drives.
const SKIP_PREFIXES: &[(&str, &str)] = &[
    ("awdl", "the peer-to-peer Wi-Fi link drives it"),
    ("llw", "the peer-to-peer Wi-Fi link drives it"),
    ("utun", "VPN"),
    ("ipsec", "VPN"),
    ("ppp", "VPN or modem"),
    ("tun", "VPN"),
    ("tap", "VPN"),
    ("wg", "VPN"),
    ("tailscale", "VPN"),
    ("zt", "VPN"),
    ("gif", "tunnel"),
    ("stf", "tunnel"),
    ("sit", "tunnel"),
    ("ip6tnl", "tunnel"),
    ("anpi", "virtual"),
    ("ap", "the Mac's own hotspot"),
    ("vmenet", "virtual machine"),
    ("vmnet", "virtual machine"),
    ("vboxnet", "virtual machine"),
    ("docker", "container bridge"),
    ("br-", "container bridge"),
    ("veth", "container plumbing"),
    ("virbr", "virtual machine"),
    ("vnet", "virtual machine"),
    ("lxc", "container bridge"),
    ("cni", "container bridge"),
    ("flannel", "container bridge"),
    ("cali", "container plumbing"),
];

/// The rules, in order:
/// 1. down, filtered out (`MYCEL_IFACES`), no multicast or no IPv6 link-local
///    address (discovery and paths are link-local IPv6): skipped;
/// 2. loopback, VPNs, tunnels, container and VM plumbing, AWDL: skipped;
/// 3. `MYCEL_IFACE_MEDIUM` says what it is;
/// 4. 802.15.4 / 6LoWPAN hardware or a `wpan` / `lowpan` / `thread` name:
///    802.15.4 ("uwb" in the name: UWB); `p2p-*`: Wi-Fi Direct; `nan*`: Wi-Fi
///    Aware (NAN), also Wi-Fi peer-to-peer; "mesh" in the name: a Wi-Fi mesh;
/// 5. an ordinary NIC (Ethernet, Wi-Fi, a cable bridge) with a routable
///    address while Iroh's IP transport is on: skipped (that path exists
///    already; a second one over the same radio adds nothing). With only
///    link-local addresses (a Thunderbolt cable between two Macs, a network
///    with no DHCP) or with IP off, it is a path of its own.
pub fn classify(i: &IfaceInfo, rules: &Rules) -> Decision {
    if let Some(only) = &rules.only
        && !only.contains(&i.name)
    {
        return Decision::Skip("not in MYCEL_IFACES");
    }
    if !i.up {
        return Decision::Skip("down");
    }
    if i.loopback || i.hw == Hw::Loopback {
        if !rules.loopback {
            return Decision::Skip("loopback");
        }
    } else if let Some((_, why)) = SKIP_PREFIXES.iter().find(|(p, _)| i.name.starts_with(p)) {
        return Decision::Skip(why);
    } else if matches!(i.hw, Hw::Tunnel) {
        return Decision::Skip("tunnel");
    }
    if !i.multicast {
        return Decision::Skip("no multicast");
    }
    if i.link_local.is_none() {
        return Decision::Skip("no IPv6 link-local address");
    }
    let name = i.name.to_ascii_lowercase();
    let label = |what: &str| format!("{what} ({})", i.name);
    if let Some((_, kind)) = rules.medium.iter().find(|(n, _)| *n == i.name) {
        return Decision::Use { kind: *kind, label: label(kind.label()) };
    }
    if i.loopback || i.hw == Hw::Loopback {
        return Decision::Use { kind: PathKind::Other, label: label("Loopback") };
    }
    let lowpan = matches!(i.hw, Hw::Ieee802154 | Hw::Lowpan)
        || ["wpan", "lowpan", "thread"].iter().any(|p| name.starts_with(p));
    if name.contains("uwb") {
        return Decision::Use { kind: PathKind::Uwb, label: label("UWB") };
    }
    if lowpan {
        return Decision::Use { kind: PathKind::Ieee802154, label: label("802.15.4") };
    }
    if name.starts_with("p2p") {
        return Decision::Use { kind: PathKind::WifiDirect, label: label("Wi-Fi Direct") };
    }
    if name.starts_with("nan") {
        return Decision::Use { kind: PathKind::WifiDirect, label: label("Wi-Fi Aware") };
    }
    if name.contains("mesh") {
        return Decision::Use { kind: PathKind::Other, label: label("Wi-Fi mesh") };
    }
    if i.hw == Hw::Virtual && !name.starts_with("bridge") {
        return Decision::Skip("virtual");
    }
    if rules.ip_covers_routable && i.routable {
        return Decision::Skip("the network path covers it");
    }
    if name.starts_with("bridge") {
        return Decision::Use { kind: PathKind::Ethernet, label: label("Cable bridge") };
    }
    match i.hw {
        Hw::Wifi => Decision::Use { kind: PathKind::Network, label: label("Wi-Fi") },
        Hw::Ethernet if cfg!(target_os = "linux") => Decision::Use { kind: PathKind::Ethernet, label: label("Ethernet") },
        // macOS reports Wi-Fi as Ethernet too
        _ => Decision::Use { kind: PathKind::Network, label: label("Network") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, hw: Hw) -> IfaceInfo {
        IfaceInfo {
            name: name.into(),
            index: 7,
            up: true,
            multicast: true,
            loopback: false,
            hw,
            link_local: Some("fe80::1234".parse().unwrap()),
            routable: false,
        }
    }

    fn kind(d: Decision) -> Option<PathKind> {
        match d {
            Decision::Use { kind, .. } => Some(kind),
            Decision::Skip(_) => None,
        }
    }

    #[test]
    fn radios_get_their_medium() {
        let r = Rules::default();
        assert_eq!(kind(classify(&iface("lowpan0", Hw::Lowpan), &r)), Some(PathKind::Ieee802154));
        assert_eq!(kind(classify(&iface("wpan0", Hw::Tunnel), &r)), None, "a tunnel, even if named wpan");
        assert_eq!(kind(classify(&iface("wpan0", Hw::Unknown), &r)), Some(PathKind::Ieee802154), "OpenThread's wpan0");
        assert_eq!(kind(classify(&iface("uwb0", Hw::Lowpan), &r)), Some(PathKind::Uwb));
        assert_eq!(kind(classify(&iface("p2p-wlan0-0", Hw::Wifi), &r)), Some(PathKind::WifiDirect));
        assert_eq!(kind(classify(&iface("mesh0", Hw::Wifi), &r)), Some(PathKind::Other));
        assert_eq!(kind(classify(&iface("nan0", Hw::Ethernet), &r)), Some(PathKind::WifiDirect));
        assert_eq!(kind(classify(&iface("bridge0", Hw::Virtual), &r)), Some(PathKind::Ethernet));
        assert_eq!(kind(classify(&iface("wlan0", Hw::Wifi), &r)), Some(PathKind::Network));
        let label = classify(&iface("p2p-wlan0-0", Hw::Wifi), &r);
        assert_eq!(label, Decision::Use { kind: PathKind::WifiDirect, label: "Wi-Fi Direct (p2p-wlan0-0)".into() });
    }

    #[test]
    fn software_interfaces_are_skipped() {
        let r = Rules::default();
        for n in ["utun3", "awdl0", "llw0", "docker0", "veth12ab", "wg0", "tailscale0", "anpi0", "ap1", "vmenet0"] {
            assert_eq!(kind(classify(&iface(n, Hw::Ethernet), &r)), None, "{n}");
        }
        assert_eq!(kind(classify(&iface("sit0", Hw::Tunnel), &r)), None);
        assert_eq!(kind(classify(&iface("br0", Hw::Virtual), &r)), None, "a software bridge");
        let mut lo = iface("lo0", Hw::Loopback);
        lo.loopback = true;
        assert_eq!(kind(classify(&lo, &r)), None);
        assert_eq!(kind(classify(&lo, &Rules { loopback: true, ..Rules::default() })), Some(PathKind::Other));
    }

    #[test]
    fn needs_link_local_multicast_and_up() {
        let r = Rules::default();
        let mut i = iface("lowpan0", Hw::Lowpan);
        i.link_local = None;
        assert_eq!(classify(&i, &r), Decision::Skip("no IPv6 link-local address"));
        let mut i = iface("lowpan0", Hw::Lowpan);
        i.multicast = false;
        assert_eq!(classify(&i, &r), Decision::Skip("no multicast"));
        let mut i = iface("lowpan0", Hw::Lowpan);
        i.up = false;
        assert_eq!(classify(&i, &r), Decision::Skip("down"));
    }

    #[test]
    fn ordinary_nics_left_to_ip_unless_link_local_only() {
        let r = Rules { ip_covers_routable: true, ..Rules::default() };
        let mut en0 = iface("en0", Hw::Ethernet);
        en0.routable = true;
        assert_eq!(classify(&en0, &r), Decision::Skip("the network path covers it"));
        // IP off: it is ours (Linux can tell a cable from Wi-Fi; macOS calls both Ethernet)
        let wired = if cfg!(target_os = "linux") { PathKind::Ethernet } else { PathKind::Network };
        assert_eq!(kind(classify(&en0, &Rules::default())), Some(wired));
        // a cable between two Macs: link-local only
        let bridge = iface("bridge0", Hw::Virtual);
        assert_eq!(kind(classify(&bridge, &r)), Some(PathKind::Ethernet));
        // radios are always ours, even with routable addresses
        let mut p2p = iface("p2p-wlan0-0", Hw::Wifi);
        p2p.routable = true;
        assert_eq!(kind(classify(&p2p, &r)), Some(PathKind::WifiDirect));
    }

    #[test]
    fn overrides_from_the_environment() {
        assert_eq!(
            parse_medium("wpan0=uwb, mesh0=Thread,bad=zzz,x"),
            vec![("wpan0".into(), PathKind::Uwb), ("mesh0".into(), PathKind::Ieee802154)]
        );
        let r = Rules { medium: parse_medium("wpan0=uwb"), ..Rules::default() };
        assert_eq!(kind(classify(&iface("wpan0", Hw::Lowpan), &r)), Some(PathKind::Uwb));
        let r = Rules { only: Some(vec!["lowpan0".into()]), ..Rules::default() };
        assert_eq!(classify(&iface("wlan0", Hw::Wifi), &r), Decision::Skip("not in MYCEL_IFACES"));
        assert_eq!(medium_named("Wi-Fi Direct"), Some(PathKind::WifiDirect));
        assert_eq!(medium_named("802.15.4"), Some(PathKind::Ieee802154));
    }
}
