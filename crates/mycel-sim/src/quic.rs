//! What a Mycel byte costs on a link: QUIC packets as noq (the QUIC stack
//! under iroh, `vendor/noq-proto`) builds them, and each link's framing
//! around a packet. Tier 2 charges these around the bytes Mycel's own
//! encoders produce (`mycel_net::mesh::wire` and the carrier's stream
//! lengths in `mycel_net::mesh`), so a format change shows up in its byte
//! counts and airtime without anyone editing the simulator.
//!
//! Fidelity (docs/SIMULATION.md §2, "Wire sizes"): the protocol constants
//! are exact, read from noq's code (**code**, with the file) or the RFCs
//! (**spec**). A few depend on connection state tier 2 does not keep (a
//! packet number's length, a stream id's, the MTU a hop has discovered)
//! and are fixed at a stated typical value (**estimate**). Not modelled:
//! ACK-only packets (the receiver of a hop or an end-to-end connection
//! acknowledges every second packet, ~34 bytes each, [`ACK_PACKET`]),
//! flow-control credit frames, and noq coalescing several small frames
//! into one packet. See SIMULATION.md for what that leaves out.
//!
//! `MYCEL_SIM_HOP_MTU=1200` charges every hop as before path-MTU discovery
//! has run ([`hop_mtu`]); the default is the MTU it reaches.

use std::sync::OnceLock;

use crate::models::Tech;

/// The first byte of a 1-RTT (short header) packet (**spec**: RFC 9000
/// §17.3.1).
pub const FLAGS: usize = 1;
/// The destination connection id in every short header: noq's default
/// generator, `HashedConnectionIdGenerator`, makes 8-byte ids (a 3-byte
/// nonce and a 5-byte keyed hash) and iroh keeps it (**code**:
/// `noq-proto/src/cid_generator.rs`, `config/mod.rs` `EndpointConfig::new`).
pub const CID: usize = 8;
/// The AEAD tag on every packet: 16 bytes for every QUIC v1 cipher suite
/// (**spec**: RFC 9001 §5.3; **code**: noq `tag_len_1rtt`).
pub const TAG: usize = 16;
/// The packet-number length noq budgets for when it sizes a datagram
/// (**code**: `connection/datagrams.rs` `max_size`, "the conservative
/// overhead bound for any packet number").
pub const MAX_PN: usize = 4;
/// A DATAGRAM frame's largest header: type and an 8-byte length (**code**:
/// `frame.rs` `Datagram::SIZE_BOUND`).
const DATAGRAM_SIZE_BOUND: usize = 1 + 8;
/// QUIC's minimum and initial MTU (**spec**: RFC 9000 §14; **code**:
/// `noq-proto/src/lib.rs` `INITIAL_MTU`). End-to-end connections over the
/// mesh stay at this size: relays drop larger packets
/// ([`mycel_net::mesh::wire::MIN_QUIC_MTU`]).
pub const INITIAL_MTU: usize = 1200;
/// The MTU a hop reaches once path-MTU discovery has run: noq's default
/// upper bound, "to stay within Ethernet's MTU when using IPv4 and IPv6"
/// (**code**: `config/transport.rs` `MtuDiscoveryConfig::default`). Both
/// of Mycel's own link framings carry it (the BLE frame takes up to 4,096
/// bytes; AWDL datagrams up to the IPv6 MTU).
pub const DISCOVERED_MTU: usize = 1452;
/// A hop connection's packet-number length (**estimate**): noq encodes a
/// packet number in 1 byte while fewer than 128 packets are unacknowledged
/// (`packet.rs` `PacketNumber::new`), and a Bluetooth hop's 16 KiB queue
/// holds about 13 full packets; Wi-Fi hops with large windows reach 2.
pub const HOP_PN: usize = 1;
/// A stream id's length (**estimate**): ids are varints, 2 bytes from a
/// connection's 17th stream of a kind to its 4,096th (RFC 9000 §2.1); the
/// carrier opens one stream per summary and per bundle.
pub const STREAM_ID: usize = 2;
/// An ACK-only packet on a hop or end-to-end connection: noq's multipath
/// PATH_ACK (type `0x3e`, 1 byte, **code**: `frame.rs`), the path id (1),
/// the largest packet number acknowledged (2, **estimate**), the ACK delay
/// (2: the default 25 ms at exponent 3 is 3,125, RFC 9000 §18.2), the range
/// count (1) and the first range (1), in a packet with a 1-byte packet
/// number.
pub const ACK_PACKET: usize = packet(1 + 1 + 2 + 2 + 1 + 1, 1);
/// One flight of a QUIC handshake (**spec**: RFC 9000 §14.1: client and
/// server pad every datagram carrying an ack-eliciting Initial packet to at
/// least 1,200 bytes). The rest of the handshake (the client's Finished,
/// the server's first 1-RTT frames) is not charged (**estimate**: ~200
/// bytes).
pub const HANDSHAKE_FLIGHT: usize = INITIAL_MTU;
/// UDP over IPv4 (RFC 768, RFC 791): what an IP link adds to each packet.
pub const UDP_IPV4: usize = 8 + 20;
/// UDP over IPv6 (RFC 768, RFC 8200).
pub const UDP_IPV6: usize = 8 + 40;
/// Mycel's Bluetooth framing on the L2CAP channel's byte stream: a 2-byte
/// length and a type byte per QUIC packet (**code**:
/// `mycel_link_ble::wire::encode_packet`, asserted in that crate's
/// `packet_framing_is_three_bytes`).
pub const BLE_FRAMING: usize = 3;
/// 6LoWPAN-compressed UDP over IPv6 on 802.15.4 (**estimate**: RFC 6282
/// IPHC, 2 bytes, plus NHC UDP with inline ports and checksum, 7). Mycel
/// has no Thread link today; the medium is modelled for comparison.
pub const LOWPAN_UDP: usize = 2 + 7;
/// What an internet path adds per packet (**estimate**: UDP over IPv4; IPv6
/// adds 20 bytes, and a path through a relay its TLS and TCP framing,
/// neither modelled).
pub const INTERNET_FRAMING: usize = UDP_IPV4;

/// The MTU tier 2 charges a hop at: [`DISCOVERED_MTU`], or
/// `MYCEL_SIM_HOP_MTU` (1,200 to 1,452) for hops that have not run path-MTU
/// discovery yet. Read once per process.
pub fn hop_mtu() -> usize {
    static MTU: OnceLock<usize> = OnceLock::new();
    *MTU.get_or_init(|| {
        std::env::var("MYCEL_SIM_HOP_MTU")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(DISCOVERED_MTU, |m| m.clamp(INITIAL_MTU, DISCOVERED_MTU))
    })
}

/// A QUIC variable-length integer's length (RFC 9000 §16).
pub const fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// The packet-number length noq picks with `unacked` packets sent after
/// the largest one acknowledged (**code**: `packet.rs` `PacketNumber::new`).
pub const fn pn_len(unacked: u64) -> usize {
    let range = (unacked + 1) * 2;
    if range < 1 << 8 {
        1
    } else if range < 1 << 16 {
        2
    } else if range < 1 << 24 {
        3
    } else {
        4
    }
}

/// A 1-RTT packet carrying `payload` bytes of frames, with a packet number
/// of `pn` bytes. Header protection samples 16 bytes from 4 bytes after the
/// packet number's start, so a shorter packet is padded (RFC 9001 §5.4.2).
pub const fn packet(payload: usize, pn: usize) -> usize {
    let payload = if pn + payload < 4 { 4 - pn } else { payload };
    FLAGS + CID + pn + payload + TAG
}

/// The largest datagram a connection at `mtu` takes (**code**:
/// `connection/datagrams.rs` `max_size`: the MTU less the short header with
/// a 4-byte packet number, the tag, and a DATAGRAM frame's largest header).
/// 1,414 bytes at [`DISCOVERED_MTU`], 1,162 at [`INITIAL_MTU`].
pub const fn datagram_max(mtu: usize) -> usize {
    mtu - (FLAGS + CID + MAX_PN + TAG) - DATAGRAM_SIZE_BOUND
}

/// The packet carrying one `len`-byte datagram on a hop: noq always writes
/// the DATAGRAM frame's length (**code**: `frame.rs`, `Datagram::encode`).
pub const fn datagram_packet(len: usize) -> usize {
    packet(1 + varint_len(len as u64) + len, HOP_PN)
}

/// Bytes on a link before its framing, and the packets they go in (each
/// packet pays the link's framing once).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wire {
    pub bytes: u32,
    pub packets: u32,
}

impl Wire {
    pub const fn one(bytes: usize) -> Wire {
        Wire { bytes: bytes as u32, packets: 1 }
    }

    /// One packet per datagram of these lengths.
    pub fn datagrams(lens: impl IntoIterator<Item = usize>) -> Wire {
        lens.into_iter().fold(Wire::default(), |w, l| w + Wire::one(datagram_packet(l)))
    }

    /// With each packet framed for `framing` bytes.
    pub const fn framed(self, framing: usize) -> u32 {
        self.bytes + self.packets * framing as u32
    }
}

impl std::ops::Add for Wire {
    type Output = Wire;
    fn add(self, o: Wire) -> Wire {
        Wire { bytes: self.bytes + o.bytes, packets: self.packets + o.packets }
    }
}

/// The packets noq cuts `len` bytes written to a stream at `offset` into,
/// at `mtu`, with `pn`-byte packet numbers, as `(stream bytes, packet
/// length)` per packet (**code**: `connection/streams/state.rs`
/// `write_stream_frames` and `send_buffer.rs` `poll_transmit`). A STREAM
/// frame is its type, the stream id, the offset unless it is 0, and the
/// data's length unless the frame runs to the end of the packet; noq
/// reserves 8 bytes for that length whenever the rest fits. A FIN rides on
/// the last frame's type byte; an empty write (`len` 0) is one packet
/// carrying it.
pub fn stream_packets(offset: u64, len: usize, mtu: usize, pn: usize) -> impl Iterator<Item = (usize, usize)> {
    let space = mtu - (FLAGS + CID + pn + TAG);
    let (mut at, end) = (offset, offset + len as u64);
    let mut first = true;
    std::iter::from_fn(move || {
        if at == end && !std::mem::take(&mut first) {
            return None;
        }
        first = false;
        let mut max = space - 1 - STREAM_ID;
        let off = if at != 0 { varint_len(at) } else { 0 };
        max -= off;
        let left = (end - at) as usize;
        let (take, length) = if left < max { (left.min(max - 8), true) } else { (max, false) };
        let header = 1 + STREAM_ID + off + if length { varint_len(take as u64) } else { 0 };
        at += take as u64;
        Some((take, packet(header + take, pn)))
    })
}

/// [`stream_packets`] summed, on a hop (its packet numbers [`HOP_PN`]).
pub fn stream(offset: u64, len: usize, mtu: usize) -> Wire {
    stream_packets(offset, len, mtu, HOP_PN).fold(Wire::default(), |w, (_, p)| w + Wire::one(p))
}

/// An application CONNECTION_CLOSE (type `0x1d`, error code 0 and a
/// `reason`-byte reason; RFC 9000 §19.19) in its own packet.
pub const fn close_packet(reason: usize) -> usize {
    packet(1 + 1 + varint_len(reason as u64) + reason, HOP_PN)
}

/// What a radio adds to each QUIC packet it carries. The rates in
/// [`crate::models`] are payload rates above this (L2CAP CoC payload for
/// Bluetooth, UDP/TCP goodput for Wi-Fi and Ethernet).
pub const fn framing(t: Tech) -> usize {
    match t {
        // the ONE's Bluetooth interface replays traces with the BLE link's framing
        Tech::Ble | Tech::OneBt => BLE_FRAMING,
        // `mycel-link-awdl`: QUIC packets unframed, one per UDP datagram
        // over IPv6 link-local on awdl0
        Tech::Awdl => UDP_IPV6,
        Tech::Thread => LOWPAN_UDP,
        // Wi-Fi, Ethernet and UWB as IP links (**estimate**: IPv4, as most
        // LANs are; noq's own default payload budget is 1500 − 28)
        Tech::WifiDirect | Tech::WifiAp | Tech::WifiMesh | Tech::Ethernet | Tech::Uwb => UDP_IPV4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_room_matches_noq() {
        // noq: MTU − (1 + 8-byte CID + 4-byte PN + 16-byte tag) − (1 + 8)
        assert_eq!(datagram_max(DISCOVERED_MTU), 1414);
        assert_eq!(datagram_max(INITIAL_MTU), 1162);
        // the largest datagram fills the packet, with the 2-byte length
        // noq writes instead of the 8 it budgets and a 1-byte packet number
        assert_eq!(datagram_packet(datagram_max(INITIAL_MTU)), INITIAL_MTU - 3 - 6);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 4);
        assert_eq!(varint_len(1 << 30), 8);
        assert_eq!(pn_len(0), 1);
        assert_eq!(pn_len(126), 1);
        assert_eq!(pn_len(127), 2);
        assert_eq!(ACK_PACKET, 34);
        assert_eq!(close_packet(4), 1 + 8 + 1 + 7 + 16);
        // a tiny packet is padded for header protection's sample
        assert_eq!(packet(1, 1), FLAGS + CID + 1 + 3 + TAG);
    }

    #[test]
    fn streams_are_cut_as_noq_cuts_them() {
        // every byte goes out once, no packet is over the MTU, and every
        // packet but the last is full but for its offset's growth or the
        // length noq reserves 8 bytes for when the rest nearly fits
        for (offset, len) in [(0, 0), (0, 1), (0, 1_100), (0, 1_166), (0, 1_200), (5, 1_000_000), (100_000, 70_000)] {
            for mtu in [INITIAL_MTU, DISCOVERED_MTU] {
                for pn in [1, 2] {
                    let ps: Vec<(usize, usize)> = stream_packets(offset, len, mtu, pn).collect();
                    assert_eq!(ps.iter().map(|p| p.0).sum::<usize>(), len, "{offset} {len} {mtu}");
                    assert!(ps.iter().all(|p| p.1 <= mtu));
                    assert!(!ps.is_empty());
                    assert!(ps[..ps.len() - 1].iter().all(|p| p.1 >= mtu - 8), "{ps:?}");
                }
            }
        }
        // one short write at offset 0: type, 2-byte id, 1-byte length
        let one: Vec<_> = stream_packets(0, 10, INITIAL_MTU, 1).collect();
        assert_eq!(one, vec![(10, packet(1 + 2 + 1 + 10, 1))]);
        // a full packet at offset 0 carries mtu − 26 − 3 bytes
        let full: Vec<_> = stream_packets(0, 5_000, INITIAL_MTU, 1).collect();
        assert_eq!(full[0], (INITIAL_MTU - 26 - 3, INITIAL_MTU));
        // and later ones pay their offset
        assert_eq!(full[1], (INITIAL_MTU - 26 - 3 - 2, INITIAL_MTU));
        // the last few bytes noq reserves 8 for the length of: cut short,
        // the rest in a packet of its own
        let edge = INITIAL_MTU - 26 - 3 - 5;
        let ps: Vec<_> = stream_packets(0, edge, INITIAL_MTU, 1).collect();
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].0 + ps[1].0, edge);
        assert_eq!(stream(0, 0, INITIAL_MTU).packets, 1);
    }

    #[test]
    fn every_radio_frames_its_packets() {
        for t in Tech::ALL {
            assert!(framing(t) > 0, "{t:?}");
        }
        assert_eq!(framing(Tech::Ble), 3);
        assert_eq!(Wire { bytes: 100, packets: 2 }.framed(3), 106);
    }
}
