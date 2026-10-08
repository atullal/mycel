//! Enumerating the machine's network interfaces (getifaddrs, plus sysfs on
//! Linux and the link-layer type on macOS), and diffing two snapshots.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use crate::classify::{Hw, IfaceInfo};

/// Every interface, by name.
#[cfg(unix)]
pub fn list() -> Vec<IfaceInfo> {
    let mut by_name: BTreeMap<String, IfaceInfo> = BTreeMap::new();
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list that we free with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Vec::new();
    }
    let mut cur = addrs;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated C string.
        let cname = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        let name = cname.to_string_lossy().into_owned();
        let flags = ifa.ifa_flags as libc::c_int;
        let e = by_name.entry(name.clone()).or_insert_with(|| IfaceInfo {
            // SAFETY: a NUL-terminated name.
            index: unsafe { libc::if_nametoindex(cname.as_ptr()) },
            up: flags & libc::IFF_UP != 0 && flags & libc::IFF_RUNNING != 0,
            multicast: flags & libc::IFF_MULTICAST != 0,
            loopback: flags & libc::IFF_LOOPBACK != 0,
            hw: Hw::Unknown,
            link_local: None,
            routable: false,
            name,
        });
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points to a sockaddr of the family it names.
        unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    e.routable |= !ip.is_link_local() && !ip.is_loopback() && !ip.is_unspecified();
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = unscoped(Ipv6Addr::from(sa.sin6_addr.s6_addr));
                    if ip.is_unicast_link_local() {
                        e.link_local.get_or_insert(ip);
                    } else if e.loopback && ip.is_loopback() {
                        // Linux's lo has no link-local address; tests use ::1
                    } else {
                        e.routable |= !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast();
                    }
                }
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                libc::AF_LINK => {
                    let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                    e.hw = hw_of_ift(sdl.sdl_type);
                }
                _ => {}
            }
        }
    }
    // SAFETY: frees the list allocated above.
    unsafe { libc::freeifaddrs(addrs) };
    let mut out: Vec<IfaceInfo> = by_name.into_values().collect();
    for i in &mut out {
        if i.loopback {
            i.hw = Hw::Loopback;
            // Linux's lo has only ::1: use it in loopback test mode
            i.link_local.get_or_insert(Ipv6Addr::LOCALHOST);
        }
        #[cfg(target_os = "linux")]
        if i.hw == Hw::Unknown {
            i.hw = linux_hw(&i.name);
        }
    }
    out
}

#[cfg(not(unix))]
pub fn list() -> Vec<IfaceInfo> {
    Vec::new()
}

/// macOS embeds a link-local address's scope in its second 16-bit word.
fn unscoped(ip: Ipv6Addr) -> Ipv6Addr {
    let mut s = ip.segments();
    if ip.is_unicast_link_local() {
        s[1] = 0;
    }
    Ipv6Addr::from(s)
}

/// macOS `sdl_type` (`<net/if_types.h>`).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn hw_of_ift(t: u8) -> Hw {
    match t {
        0x06 => Hw::Ethernet,      // IFT_ETHER (Wi-Fi too)
        0x47 => Hw::Wifi,          // IFT_IEEE80211
        0x18 => Hw::Loopback,      // IFT_LOOP
        0x17 | 0x6c => Hw::Tunnel, // IFT_PPP, IFT_PDP
        0x37 | 0x39 => Hw::Tunnel, // IFT_GIF, IFT_STF
        0xd1 | 0x87 => Hw::Virtual, // IFT_BRIDGE, IFT_L2VLAN
        _ => Hw::Unknown,
    }
}

/// Linux: `ARPHRD_*` from `/sys/class/net/<if>/type`, Wi-Fi from its
/// `wireless` / `phy80211` entry, bridges and VLANs from `uevent`.
#[cfg(target_os = "linux")]
fn linux_hw(name: &str) -> Hw {
    let dir = std::path::Path::new("/sys/class/net").join(name);
    let ty: u32 = std::fs::read_to_string(dir.join("type")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let devtype = std::fs::read_to_string(dir.join("uevent"))
        .ok()
        .and_then(|u| u.lines().find_map(|l| l.strip_prefix("DEVTYPE=").map(str::to_string)))
        .unwrap_or_default();
    let wireless = dir.join("wireless").exists() || dir.join("phy80211").exists() || devtype == "wlan";
    hw_of_arphrd(ty, &devtype, wireless)
}

/// `ARPHRD_*` → hardware (`<linux/if_arp.h>`).
pub fn hw_of_arphrd(ty: u32, devtype: &str, wireless: bool) -> Hw {
    match ty {
        772 => Hw::Loopback,
        804 => Hw::Ieee802154, // ARPHRD_IEEE802154
        825 => Hw::Lowpan,     // ARPHRD_6LOWPAN
        // TUNNEL, TUNNEL6, SIT, IPGRE, IP6GRE, PPP
        768 | 769 | 776 | 778 | 823 | 512 => Hw::Tunnel,
        1 if wireless => Hw::Wifi,
        1 if devtype == "bridge" || devtype == "vlan" || devtype == "bond" => Hw::Virtual,
        1 => Hw::Ethernet,
        801..=803 => Hw::Wifi, // raw 802.11 (monitor)
        // 65534 = ARPHRD_NONE: TUN devices, OpenThread's wpan0, WireGuard
        _ => Hw::Unknown,
    }
}

/// What changed between two snapshots: interfaces to stop using and to start
/// using. An interface whose index, link-local address or flags changed is
/// both (its old socket is useless).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub gone: Vec<String>,
    pub new: Vec<String>,
}

pub fn diff(old: &[IfaceInfo], new: &[IfaceInfo]) -> Diff {
    let old: BTreeMap<&str, &IfaceInfo> = old.iter().map(|i| (i.name.as_str(), i)).collect();
    let new: BTreeMap<&str, &IfaceInfo> = new.iter().map(|i| (i.name.as_str(), i)).collect();
    let mut d = Diff::default();
    for (name, o) in &old {
        match new.get(name) {
            None => d.gone.push(name.to_string()),
            Some(n) if n != o => {
                d.gone.push(name.to_string());
                d.new.push(name.to_string());
            }
            Some(_) => {}
        }
    }
    for name in new.keys() {
        if !old.contains_key(name) {
            d.new.push(name.to_string());
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(name: &str, index: u32, ll: &str) -> IfaceInfo {
        IfaceInfo {
            name: name.into(),
            index,
            up: true,
            multicast: true,
            loopback: false,
            hw: Hw::Ethernet,
            link_local: Some(ll.parse().unwrap()),
            routable: false,
        }
    }

    #[test]
    fn diffs_snapshots() {
        let a = vec![i("en0", 4, "fe80::1"), i("lowpan0", 9, "fe80::2")];
        assert_eq!(diff(&a, &a), Diff::default());
        let mut b = vec![i("en0", 4, "fe80::1"), i("p2p-wlan0-0", 12, "fe80::3")];
        assert_eq!(diff(&a, &b), Diff { gone: vec!["lowpan0".into()], new: vec!["p2p-wlan0-0".into()] });
        b[0].link_local = Some("fe80::99".parse().unwrap());
        let d = diff(&a, &b);
        assert!(d.gone.contains(&"en0".into()) && d.new.contains(&"en0".into()), "readdressed: restart it");
        b[0] = i("en0", 4, "fe80::1");
        b[0].up = false;
        assert!(diff(&a, &b).gone.contains(&"en0".into()));
    }

    #[test]
    fn arphrd_types() {
        assert_eq!(hw_of_arphrd(804, "", false), Hw::Ieee802154);
        assert_eq!(hw_of_arphrd(825, "", false), Hw::Lowpan);
        assert_eq!(hw_of_arphrd(1, "wlan", true), Hw::Wifi);
        assert_eq!(hw_of_arphrd(1, "bridge", false), Hw::Virtual);
        assert_eq!(hw_of_arphrd(1, "", false), Hw::Ethernet);
        assert_eq!(hw_of_arphrd(776, "", false), Hw::Tunnel);
        assert_eq!(hw_of_arphrd(65534, "", false), Hw::Unknown, "TUN: decided by name");
        assert_eq!(hw_of_arphrd(772, "", false), Hw::Loopback);
    }

    #[test]
    fn strips_macos_embedded_scope() {
        let ip: Ipv6Addr = "fe80:4::1c2a:3bff:fe4d:5e6f".parse().unwrap();
        assert_eq!(unscoped(ip), "fe80::1c2a:3bff:fe4d:5e6f".parse::<Ipv6Addr>().unwrap());
        let g: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(unscoped(g), g);
    }

    #[test]
    fn this_machine_has_interfaces() {
        let all = list();
        if cfg!(unix) {
            assert!(all.iter().any(|i| i.loopback), "{all:?}");
            assert!(all.iter().all(|i| i.index > 0), "{all:?}");
        }
    }
}
