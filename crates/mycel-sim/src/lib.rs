//! Real-world network simulation for Mycel, in two tiers.
//!
//! - **Tier 1** ([`tier1`]): real Mycel nodes (iroh QUIC, multipath, the
//!   mesh, sync, calls with test tones) over emulated radios and wires
//!   ([`mycel_net::emu`]): Bluetooth LE, AWDL, Wi-Fi Direct, Wi-Fi LAN,
//!   802.11s, Ethernet, UWB, Thread, cellular and the internet with
//!   geographic latency, NAT and relays. Real time; a few hundred devices
//!   per machine.
//! - **Tier 2** ([`tier2`]): a discrete-event simulator in virtual time for
//!   10k–100k+ devices, running routing cores as sans-IO state machines,
//!   with a ground-truth oracle for the fastest feasible path of every
//!   message.
//!
//! Scenarios ([`scenarios`]) are named, seeded and reproducible, each with
//! service-level objectives; `cargo run -p mycel-sim -- all` runs them and
//! writes a report. See docs/SIMULATION.md.

pub mod latency;
pub mod models;
pub mod report;
pub mod scenarios;
pub mod stats;
pub mod tier1;
pub mod tier2;
pub mod traces;
