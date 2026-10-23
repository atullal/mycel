//! The Bluetooth LE link (`mycel-link-ble`): the GATT info characteristic a
//! nearby device publishes, the byte stream of an L2CAP channel (split into
//! reads anywhere, as the radio delivers it), and the connection state
//! machine fed whatever a hostile radio environment reports.
//!
//! Properties: no panic; GATT info re-encodes to what was read; a stream
//! deframes to the same frames however it is split; the state machine
//! never routes to, or reports, our own key.
#![no_main]

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::SignPk;
use mycel_link_ble::core::{Cmd, Core, Input as Radio};
use mycel_link_ble::wire::{self, Deframer, GattInfo};

#[derive(Arbitrary, Debug)]
enum Event {
    Discovered(u8),
    Connected(u8),
    ConnectFailed(u8),
    Disconnected(u8),
    Info {
        pid: u8,
        psm: u16,
        key: u8,
        name: String,
    },
    RawInfo {
        pid: u8,
        bytes: Vec<u8>,
    },
    InfoFailed(u8),
    /// (the platform numbers the channel: see below)
    ChannelOpened {
        pid: Option<u8>,
    },
    OpenFailed(u8),
    Hello {
        chan: u8,
        key: u8,
        name: String,
    },
    ChannelClosed(u8),
    Tick(u16),
    RadioDown,
}

#[derive(Arbitrary, Debug)]
struct Input {
    info: Vec<u8>,
    stream: Vec<u8>,
    cuts: Vec<u8>,
    events: Vec<Event>,
}

fn key(i: u8) -> SignPk {
    SignPk([i % 6; 32])
}

fn pid(i: u8) -> String {
    format!("{:08x}-0000", i % 8)
}

fuzz_target!(|input: Input| {
    if let Some(info) = GattInfo::decode(&input.info) {
        assert!(info.name.len() <= 3 * wire::MAX_NAME, "lossy UTF-8 at most triples");
        let again = GattInfo::decode(&info.encode()).expect("our own encoding decodes");
        assert_eq!((again.psm, again.key), (info.psm, info.key));
    }
    // One read, then the same bytes in the reads the input cuts them into.
    let whole = Deframer::default().push(&input.stream);
    let mut d = Deframer::default();
    let mut pieces = Ok(Vec::new());
    let mut rest = &input.stream[..];
    let mut cuts = input.cuts.iter();
    while !rest.is_empty() {
        let n = usize::from(cuts.next().copied().unwrap_or(255)).clamp(1, rest.len());
        let (now, later) = rest.split_at(n);
        rest = later;
        match (d.push(now), &mut pieces) {
            (Ok(f), Ok(all)) => all.extend(f),
            (Err(e), p @ Ok(_)) => *p = Err(e),
            _ => {}
        }
    }
    match (&whole, &pieces) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "framing depends on how reads split the stream"),
        (Err(_), Err(_)) => {}
        // a stream that fails whole may fail in a later piece, after frames
        (Err(_), Ok(_)) | (Ok(_), Err(_)) => panic!("one split fails and the other doesn't"),
    }
    // The connection state machine.
    let me = key(0);
    let t0 = Instant::now();
    let mut now = t0;
    let mut core = Core::new(me, now);
    // Platforms number channels themselves and never reuse a number; events
    // name one of the channels opened so far, or one never opened.
    let mut opened: Vec<u64> = Vec::new();
    let chan_of = |opened: &[u64], c: u8| match opened.len() {
        0 => 1_000 + u64::from(c),
        n if usize::from(c) >= 2 * n => 1_000 + u64::from(c),
        n => opened[usize::from(c) % n],
    };
    for e in input.events.into_iter().take(128) {
        let radio = match e {
            Event::Discovered(p) => Radio::Discovered(pid(p)),
            Event::Connected(p) => Radio::Connected(pid(p)),
            Event::ConnectFailed(p) => Radio::ConnectFailed(pid(p)),
            Event::Disconnected(p) => Radio::Disconnected(pid(p)),
            Event::Info { pid: p, psm, key: k, name } => Radio::Info(pid(p), GattInfo { psm, key: key(k), name }),
            Event::RawInfo { pid: p, bytes } => match GattInfo::decode(&bytes) {
                Some(info) => Radio::Info(pid(p), info),
                None => Radio::InfoFailed(pid(p)),
            },
            Event::InfoFailed(p) => Radio::InfoFailed(pid(p)),
            Event::ChannelOpened { pid: p } => {
                let chan = opened.len() as u64 + 1;
                opened.push(chan);
                Radio::ChannelOpened { chan, pid: p.map(pid) }
            }
            Event::OpenFailed(p) => Radio::OpenFailed(pid(p)),
            Event::Hello { chan, key: k, name } => Radio::Hello { chan: chan_of(&opened, chan), key: key(k), name },
            Event::ChannelClosed(c) => Radio::ChannelClosed(chan_of(&opened, c)),
            Event::Tick(ms) => {
                now += Duration::from_millis(u64::from(ms) * 10);
                Radio::Tick
            }
            Event::RadioDown => Radio::RadioDown,
        };
        for cmd in core.handle(now, radio) {
            match cmd {
                Cmd::Route { key, .. } | Cmd::Unroute { key } | Cmd::Found { key, .. } | Cmd::Lost { key } => {
                    assert_ne!(key, me, "{cmd:?} names ourselves")
                }
                _ => {}
            }
        }
        let _ = core.peers();
        let _ = core.connecting(now);
    }
});
