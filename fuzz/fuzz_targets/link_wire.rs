//! Discovery and control bytes from nearby devices on the other links:
//! peer-to-peer Wi-Fi control datagrams and Bonjour TXT adverts
//! (`mycel-link-awdl`), interface beacons and link addresses
//! (`mycel-link-iface`), and, on Apple platforms, the SRV and TXT records
//! of LAN discovery (`mycel-net`). The first input byte picks the decoder.
//!
//! Properties: no panic; whatever decodes re-encodes to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mycel_link_awdl::wire as awdl;
use mycel_link_iface::wire as iface;
use mycel_net::link::CustomAddr;

fuzz_target!(|data: &[u8]| {
    let Some((&kind, data)) = data.split_first() else { return };
    match kind % 6 {
        0 => {
            if let Some(c) = awdl::Control::decode(data) {
                assert_eq!(&c.encode()[..], data);
            }
        }
        1 => {
            // TXT values: the key, then (after a 0xff byte, if any) the name
            let (pk, name) = match data.iter().position(|b| *b == 0xff) {
                Some(i) => (&data[..i], Some(&data[i + 1..])),
                None => (data, None),
            };
            if let Some(a) = awdl::parse_advert(Some(pk), name) {
                assert!(a.name.as_ref().is_none_or(|n| n.len() <= awdl::MAX_NAME && !n.is_empty()));
                let txt = awdl::txt_entries(&a.key, a.name.as_deref().unwrap_or(""));
                let get = |k: &str| txt.iter().find(|(key, _)| *key == k).map(|(_, v)| v.as_slice());
                let back = awdl::parse_advert(get(awdl::TXT_KEY), get(awdl::TXT_NAME)).expect("our advert parses");
                assert_eq!(back, a);
            }
        }
        2 => {
            if let Some(b) = iface::Beacon::decode(data) {
                assert_eq!(iface::Beacon::decode(&b.encode()), Some(b));
            }
        }
        3 => {
            if let Some((&id, rest)) = data.split_first() {
                let addr = CustomAddr::from_parts(0x6d79_6300 | u64::from(id), rest);
                if let Some(a) = iface::IfaceAddr::from_custom(&addr) {
                    assert_eq!(iface::IfaceAddr::from_custom(&a.to_custom()), Some(a));
                    let _ = a.socket();
                }
            }
        }
        4 =>
        {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            if let Some((name, _port)) = mycel_net::fuzzing::mdns_srv(data) {
                assert!(!name.is_empty() && name.len() <= 255);
            }
        }
        _ => {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let _ = mycel_net::fuzzing::mdns_txt(data);
        }
    }
});
