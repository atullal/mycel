//! The world a tier-2 run happens in, split the way candidates are compared
//! (docs/SIMULATION.md §1, "World and streams"):
//!
//! - **Exogenous**: what no protocol decision can move. Geography, the
//!   devices and their radios, where they walk, who switches off when, who
//!   wants to send what when, which devices are adversaries, and (under the
//!   disc radio model) which pairs are in range. It depends only on the seed
//!   and the scenario. The engine keeps it apart from everything a router
//!   can touch (`tier2::engine::Exo`, which routers see read-only), hashes
//!   it as it unfolds ([`Digest`]), and can export it as a [`trace`] and
//!   replay it.
//! - **Endogenous**: models whose outcome depends on traffic (today the
//!   radio queues and jitter; later link setup, interference, energy and OS
//!   wakes). Their draws come from counter-based [`streams`] keyed per
//!   entity and event, so candidates share them (common random numbers).
//!
//! Every run carries two BLAKE3 digests: the **exogenous hash** (equal for
//! every candidate on one seed, checked as an invariant wherever a scenario
//! runs several models on one world) and the **run hash**, over every
//! event a router sees (equal for the same seed and candidate, and for a
//! run replayed from an exported world).

pub mod streams;
pub mod trace;

use serde::{Deserialize, Serialize};

pub use streams::{Key, Purpose, Streams, Substream};

use crate::tier2::engine::{NodeId, Techs, Time};

/// A change in the exogenous world, as the engine applied it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum WorldEvent {
    /// A device's position (a mobility step or a scripted move).
    Move { n: NodeId, xy: (f64, f64) },
    /// A radio link came up or went down (`a`'s side is told first).
    Link { a: NodeId, b: NodeId, techs: Techs, up: bool },
    /// A device switched on or off.
    Online { n: NodeId, on: bool },
    /// A device's internet came or went.
    Inet { n: NodeId, up: bool },
}

impl WorldEvent {
    /// A fixed binary encoding, for the exogenous hash.
    fn encode(&self, t: Time, out: &mut Digest) {
        match *self {
            WorldEvent::Move { n, xy } => out.record(0x10, t, n, xy.0.to_bits(), xy.1.to_bits()),
            WorldEvent::Link { a, b, techs, up } => {
                out.record(0x11, t, a, u64::from(b), u64::from(techs.0) | (u64::from(up) << 16))
            }
            WorldEvent::Online { n, on } => out.record(0x12, t, n, u64::from(on), 0),
            WorldEvent::Inet { n, up } => out.record(0x13, t, n, u64::from(up), 0),
        }
    }
}

/// A running BLAKE3 digest over fixed-size records, buffered so that a
/// million small records a second cost one large `update` per 4 KiB rather
/// than one per record.
#[derive(Clone)]
pub struct Digest {
    hasher: blake3::Hasher,
    buf: Vec<u8>,
    records: u64,
}

impl Default for Digest {
    fn default() -> Self {
        Digest { hasher: blake3::Hasher::new(), buf: Vec::with_capacity(4096), records: 0 }
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({} records, {})", self.records, self.hex())
    }
}

impl Digest {
    /// One record: a kind tag, the time, a device and two words.
    pub fn record(&mut self, kind: u8, t: Time, node: NodeId, a: u64, b: u64) {
        self.buf.push(kind);
        self.buf.extend_from_slice(&t.to_le_bytes());
        self.buf.extend_from_slice(&node.to_le_bytes());
        self.buf.extend_from_slice(&a.to_le_bytes());
        self.buf.extend_from_slice(&b.to_le_bytes());
        self.records += 1;
        if self.buf.len() >= 4000 {
            self.hasher.update(&self.buf);
            self.buf.clear();
        }
    }

    /// Arbitrary bytes, length-prefixed.
    pub fn bytes(&mut self, tag: u8, data: &[u8]) {
        self.buf.push(tag);
        self.buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(data);
        self.records += 1;
    }

    pub fn world_event(&mut self, t: Time, ev: &WorldEvent) {
        ev.encode(t, self);
    }

    /// How many records went in.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// The digest so far (the digest itself keeps running).
    pub fn finish(&self) -> [u8; 32] {
        let mut h = self.hasher.clone();
        h.update(&self.buf);
        *h.finalize().as_bytes()
    }

    pub fn hex(&self) -> String {
        hex(&self.finish())
    }
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_and_content_sensitive_and_buffering_invisible() {
        let (mut a, mut b, mut c) = (Digest::default(), Digest::default(), Digest::default());
        for i in 0..1000u32 {
            a.record(1, u64::from(i), i, 2, 3);
            b.record(1, u64::from(i), i, 2, 3);
        }
        assert_eq!(a.finish(), b.finish());
        // the same records unbuffered give the same digest
        let mut h = blake3::Hasher::new();
        for i in 0..1000u32 {
            let mut r = vec![1u8];
            r.extend_from_slice(&u64::from(i).to_le_bytes());
            r.extend_from_slice(&i.to_le_bytes());
            r.extend_from_slice(&2u64.to_le_bytes());
            r.extend_from_slice(&3u64.to_le_bytes());
            h.update(&r);
        }
        assert_eq!(a.finish(), *h.finalize().as_bytes());
        c.record(1, 1, 0, 2, 3);
        c.record(1, 0, 0, 2, 3);
        let mut d = Digest::default();
        d.record(1, 0, 0, 2, 3);
        d.record(1, 1, 0, 2, 3);
        assert_ne!(c.finish(), d.finish(), "order matters");
        assert_eq!(a.records(), 1000);
    }
}
