//! Mycel: peer-to-peer, authenticated, fully distributed apps.
//!
//! Facade over the layers (see docs/ARCHITECTURE.md):
//! - [`crypto`] — device keys, signatures, lockboxes, content encryption
//! - [`trust`]  — Spaces, membership graph, roles, epochs
//! - [`sync`]   — signed encrypted envelopes, Automerge documents
//! - [`net`]    — Iroh transport and the sync protocol

pub use mycel_crypto as crypto;
pub use mycel_net as net;
pub use mycel_sync as sync;
pub use mycel_trust as trust;

pub mod api;

pub use mycel_net::{NetMode, Node};
pub use mycel_trust::Role;
