//! Mesh datagrams as a neighbour sends them (`mesh/wire.rs`): announcements,
//! batches of them (attested ones too, `ROUTE_ATTEST`), seqno requests and
//! data frames, plus mesh addresses.
//!
//! Properties: no decoder panics; every accepted datagram re-encodes to the
//! same bytes (announcements, batches, attested batches with chains of the
//! shape the router expects or none, refreshes without their chain, seqno
//! requests) or to a frame that
//! decodes to the same fields; a decoded frame split into fragments for any
//! hop MTU reassembles into the same payload.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mycel_net::link::CustomAddr;
use mycel_net::mesh::core::Frame;
use mycel_net::mesh::wire;

fn fields(f: &Frame) -> impl PartialEq + std::fmt::Debug {
    (f.ttl, f.reached, f.control, f.dst, f.src, f.waypoint, f.id, f.offset, f.total, f.payload.clone())
}

fuzz_target!(|data: &[u8]| {
    if let Some(a) = wire::decode_announce(data) {
        assert_eq!(&wire::encode_announce(&a)[..], data, "announcements are canonical");
        assert!(a.name.len() <= wire::MAX_NAME);
        // (a random signature never verifies; this only runs the check)
        let _ = wire::verify_announce(&a);
    }
    let batch = wire::decode_announces(data);
    if !batch.is_empty() {
        let again = wire::encode_announces(&batch, usize::MAX);
        assert_eq!(again.len(), 1);
        assert_eq!(&again[0][..], data, "a batch re-encodes to the same datagram");
    }
    // attested batches, from a neighbour whose key the input picks
    if let Some((&k, rest)) = data.split_first() {
        let from = mycel_crypto::SignPk([k; 32]);
        let batch = wire::decode_attested(rest, &from);
        if !batch.is_empty() {
            for a in &batch {
                assert!(a.name.len() <= wire::MAX_NAME);
                assert!(a.cost != u32::MAX && a.sign_link.is_none());
                // a refresh without its chain, or a chain of the expected shape
                let n = a.chain.as_ref().map_or(0, |c| c.len());
                if a.same {
                    assert_eq!(n, 0);
                } else {
                    assert!(n == a.hops as usize || n == a.hops as usize + 1, "{n} hops for {}", a.hops);
                    assert!(n <= mycel_net::mesh::core::MAX_CHAIN && n > 0);
                }
                assert_eq!(wire::wire_len(a), {
                    let (g, r) = wire::encode_attested(vec![a.clone()], usize::MAX);
                    assert!(r.is_empty(), "a decoded announcement encodes");
                    g[0].len() - 1
                });
            }
            let (again, rest2) = wire::encode_attested(batch, usize::MAX);
            assert!(rest2.is_empty());
            assert_eq!(again.len(), 1);
            assert_eq!(&again[0][..], rest, "an attested batch re-encodes to the same datagram");
        }
    }
    if let Some(r) = wire::decode_seqreq(data) {
        assert_eq!(&wire::encode_seqreq(&r)[..], data);
    }
    if let Some(f) = wire::decode_frame(Bytes::copy_from_slice(data)) {
        assert!(f.offset as usize + f.payload.len() <= f.total as usize);
        let whole = wire::encode_frame(&f, usize::MAX).expect("fits an unbounded datagram");
        assert_eq!(whole.len(), 1);
        let back = wire::decode_frame(whole[0].clone()).expect("our own encoding decodes");
        assert_eq!(fields(&back), fields(&f));
        // Fragment for a hop MTU taken from the input.
        let mtu = wire::DATA_HDR + usize::from(data.last().copied().unwrap_or(0)) * 8;
        if let Some(parts) = wire::encode_frame(&f, mtu) {
            let mut payload = Vec::new();
            for p in parts {
                assert!(p.len() <= mtu.max(wire::DATA_HDR + f.payload.len().min(mtu)));
                let d = wire::decode_frame(p).expect("each fragment decodes");
                assert_eq!((d.id, d.total, d.dst, d.src), (f.id, f.total, f.dst, f.src));
                assert_eq!(d.offset as usize, f.offset as usize + payload.len());
                payload.extend_from_slice(&d.payload);
            }
            assert_eq!(payload, f.payload);
        }
    }
    // Mesh addresses come from Iroh's custom-address table (peers' records).
    if let Some((&id, rest)) = data.split_first() {
        let addr = CustomAddr::from_parts(u64::from(id) | 0x6d79_6300, rest);
        if let Some((dst, via)) = wire::parse_mesh_addr(&addr) {
            assert_eq!(wire::mesh_addr(&dst, &via), addr);
        }
    }
});
