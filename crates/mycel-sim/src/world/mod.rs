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
//! Every run carries two [`Digest`]s: the **exogenous hash** (equal for
//! every candidate on one seed, checked as an invariant wherever a scenario
//! runs several models on one world) and the **run hash**, over every
//! event a router sees (equal for the same seed and candidate, and for a
//! run replayed from an exported world).

#[cfg(test)]
mod meta_tests;
pub mod streams;
pub mod trace;

use serde::{Deserialize, Serialize};

pub use streams::{Key, Purpose, Streams, Substream};

use crate::stats::mix64;
use crate::tier2::engine::{NodeId, Techs, Time};

/// A change in the exogenous world, as the engine applied it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum WorldEvent {
    /// A device's position (a mobility step or a scripted move).
    Move {
        n: NodeId,
        #[serde(with = "trace::exact")]
        xy: (f64, f64),
    },
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

/// A running digest of a sequence of records, for telling deterministic
/// runs apart: two 64-bit chains through SplitMix64's finaliser (a
/// bijection with full avalanche), one absorbing each record's first two
/// words and the other its last two, crossed after every record; finished
/// with BLAKE3 over both chains and the record count.
/// It detects divergence (two different record sequences that nobody
/// chose to collide should collide with odds near 2^-128, an estimate
/// from its 128-bit state, not a proof); it is not meant to resist an
/// adversary, and a
/// million records a second cost a few nanoseconds each, where feeding
/// every record to BLAKE3 itself cost ~100 ns (measured, fixed 27).
#[derive(Clone, Debug, Default)]
pub struct Digest {
    chains: [u64; 2],
    records: u64,
}

impl Digest {
    /// Four words: two into each chain (the two run in parallel), then
    /// each chain takes in the other, so every word reaches both.
    /// The second chain is offset by a nothing-up-my-sleeve constant (the
    /// fractional bits of √2, SHA-512's first initial word, FIPS 180-4) so
    /// the two chains never start equal.
    fn absorb(&mut self, w: [u64; 4]) {
        let c0 = mix64(mix64(self.chains[0] ^ w[0]) ^ w[1]);
        let c1 = mix64(mix64(self.chains[1] ^ w[2] ^ 0x6a09_e667_f3bc_c908) ^ w[3]);
        self.chains = [c0 ^ c1.rotate_left(32), c1 ^ c0.rotate_left(17)];
    }

    /// One record: a kind tag, the time, a device and two words.
    pub fn record(&mut self, kind: u8, t: Time, node: NodeId, a: u64, b: u64) {
        self.absorb([u64::from(kind) | (u64::from(node) << 8) | (1 << 40), t, a, b]);
        self.records += 1;
    }

    /// Arbitrary bytes (hashed with BLAKE3 first), with a tag.
    pub fn bytes(&mut self, tag: u8, data: &[u8]) {
        let h = blake3::hash(data);
        let w: Vec<u64> = h.as_bytes().chunks_exact(8).map(|w| u64::from_le_bytes(w.try_into().expect("8"))).collect();
        self.absorb([u64::from(tag) | (2 << 40), data.len() as u64, 0, 0]);
        self.absorb([w[0], w[1], w[2], w[3]]);
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
        let mut h = blake3::Hasher::new();
        h.update(&self.chains[0].to_le_bytes());
        h.update(&self.chains[1].to_le_bytes());
        h.update(&self.records.to_le_bytes());
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
    fn digest_is_order_and_content_sensitive() {
        let (mut a, mut b) = (Digest::default(), Digest::default());
        for i in 0..1000u32 {
            a.record(1, u64::from(i), i, 2, 3);
            b.record(1, u64::from(i), i, 2, 3);
        }
        assert_eq!(a.finish(), b.finish());
        assert_eq!(a.records(), 1000);
        let mut c = a.clone();
        c.record(1, 0, 0, 0, 0);
        assert_ne!(c.finish(), a.finish(), "one more record");
        // any one field of one record
        let one = |kind, t, node, x, y| {
            let mut d = Digest::default();
            d.record(kind, t, node, x, y);
            d.finish()
        };
        let base = one(1, 2, 3, 4, 5);
        for other in
            [one(9, 2, 3, 4, 5), one(1, 9, 3, 4, 5), one(1, 2, 9, 4, 5), one(1, 2, 3, 9, 5), one(1, 2, 3, 4, 9)]
        {
            assert_ne!(base, other);
        }
        // order
        let (mut x, mut y) = (Digest::default(), Digest::default());
        x.record(1, 1, 0, 2, 3);
        x.record(1, 0, 0, 2, 3);
        y.record(1, 0, 0, 2, 3);
        y.record(1, 1, 0, 2, 3);
        assert_ne!(x.finish(), y.finish(), "order matters");
        // bytes and records don't alias
        let (mut p, mut q) = (Digest::default(), Digest::default());
        p.bytes(1, b"abc");
        q.bytes(1, b"abd");
        assert_ne!(p.finish(), q.finish());
    }
}
