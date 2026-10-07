//! The messaging app's message-feed wire format (the Chat kit), mirrored in `no_std` so the
//! `chat-rules` guest can decode it. Enabled by the `chat` feature.
//!
//! This must stay byte-identical to `mycel_kit_chat::ChatOp` (postcard). There, ids are
//! `mycel_crypto::Hash32`, a newtype over `[u8; 32]` that postcard writes as 32 raw bytes,
//! exactly like the `[u8; 32]` used here. `crates/mycel-rules` has a test that encodes every
//! variant with `mycel_kit_chat` and decodes it with this type.
//!
//! `RuleInput.payload` = postcard([`ChatOp`]). `RuleInput.context` is not used: author-only
//! edit/delete is enforced by the chat reducer (`mycel_kit_chat::reduce`) over the causally
//! ordered feed, not by the validator.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// A 32-byte id (message / blob hash). Wire-identical to `mycel_crypto::Hash32`.
pub type Hash32 = [u8; 32];

/// Maximum message body size in bytes (UTF-8).
pub const MAX_BODY: usize = 16 * 1024;
/// Maximum reaction size in bytes (one emoji grapheme cluster, possibly with modifiers).
pub const MAX_EMOJI: usize = 32;
/// Maximum display name (`Profile`) size in bytes.
pub const MAX_NAME: usize = 64;
/// Maximum conversation title (`Meta`) size in bytes (the reducer displays at most 128).
pub const MAX_TITLE: usize = 256;
/// Maximum attachments per message.
pub const MAX_ATTACHMENTS: usize = 10;
/// Maximum attachment file name / MIME type size in bytes.
pub const MAX_ATTACHMENT_FIELD: usize = 256;

/// A file attached to a message. Field order is part of the wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub blob: Hash32,
    pub key: [u8; 32],
    pub nonce: [u8; 24],
    pub name: String,
    pub mime: String,
    pub size: u64,
}

/// One entry in a chat message feed. Variant and field order are part of the wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatOp {
    /// 0
    Text {
        body: String,
        reply_to: Option<Hash32>,
        attachments: Vec<AttachmentRef>,
    },
    /// 1
    Edit { target: Hash32, body: String },
    /// 2
    Delete { target: Hash32 },
    /// 3
    React {
        target: Hash32,
        emoji: String,
        on: bool,
    },
    /// 4: "I have read everything up to and including `up_to`".
    Receipt { up_to: Hash32 },
    /// 5: the author's display name in this conversation.
    Profile { name: String },
    /// 6: conversation metadata (admins only).
    Meta { title: Option<String>, direct: bool },
}

/// Reject codes returned by `chat-rules` (`Reason::Rule(code)`).
pub mod codes {
    /// The payload is not a valid postcard `ChatOp` (or has trailing bytes).
    pub const MALFORMED_PAYLOAD: u32 = 1;
    /// Chat ops are only valid on a Feed stream.
    pub const WRONG_STREAM: u32 = 2;
    /// The op requires the Writer role (or above).
    pub const NOT_WRITER: u32 = 3;
    /// The op requires the Reader role (or above).
    pub const NOT_READER: u32 = 4;
    /// Body exceeds [`super::MAX_BODY`] bytes.
    pub const BODY_TOO_LONG: u32 = 5;
    /// Emoji empty or longer than [`super::MAX_EMOJI`] bytes.
    pub const BAD_EMOJI: u32 = 6;
    /// The op requires the Admin role (`Meta`).
    pub const NOT_ADMIN: u32 = 7;
    /// Profile name longer than [`super::MAX_NAME`] bytes, or title longer than
    /// [`super::MAX_TITLE`] bytes.
    pub const NAME_TOO_LONG: u32 = 8;
    /// More than [`super::MAX_ATTACHMENTS`] attachments, or an attachment name / MIME type
    /// longer than [`super::MAX_ATTACHMENT_FIELD`] bytes.
    pub const BAD_ATTACHMENT: u32 = 9;
}
