//! Mycel: peer-to-peer, authenticated, fully distributed apps.
//!
//! Facade over the layers (see docs/ARCHITECTURE.md):
//! - [`crypto`] — device keys, signatures, lockboxes, content encryption
//! - [`trust`]  — Spaces, membership graph, roles, epochs
//! - [`sync`]   — signed encrypted envelopes, Docs and Feeds
//! - [`net`]    — Iroh transport, live sync, LAN discovery, blobs
//! - [`chat`]   — the chat kit
//! - [`call`]   — live voice calls
//! - [`Runtime`] — the app-facing API (docs/RUNTIME_API.md)

pub mod api;
pub mod dispatch;
pub mod links;
mod files;
mod runtime;
pub mod store;

pub use mycel_call as call;
pub use mycel_video as video;
pub use mycel_crypto as crypto;
pub use mycel_kit_chat as chat;
pub use mycel_net as net;
pub use mycel_sync as sync;
pub use mycel_trust as trust;

pub use mycel_net::{NetMode, Node, NodeOptions};
pub use mycel_trust::Role;
pub use runtime::{
    Runtime, RuntimeOptions, chat_rules_hash, decode_contact_code, decode_contact_code_with_hints,
    encode_contact_code, encode_contact_code_with_hints,
};
