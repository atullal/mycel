//! Payload types for the messaging app's message feed (the Chat kit), shared by the
//! `chat-rules` guest and host-side tests/SDK code. Enabled by the `chat` feature.
//!
//! - `RuleInput.payload` = postcard([`ChatOp`]).
//! - `RuleInput.context` = for `Edit` and `Delete`: the 32-byte Agent key of the target
//!   message's original author, looked up by the host in the change's causal past.
//!   Ignored for the other ops.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// A 32-byte message id (the id of the feed entry / envelope that carried the message).
pub type MsgId = [u8; 32];

/// Maximum message body size in bytes (UTF-8).
pub const MAX_BODY: usize = 16 * 1024;
/// Maximum reaction size in bytes (one emoji grapheme cluster, possibly with modifiers).
pub const MAX_EMOJI: usize = 32;
/// Maximum attachment MIME type length in bytes.
pub const MAX_MIME: usize = 127;
/// Maximum attachment file name length in bytes.
pub const MAX_FILE_NAME: usize = 255;

/// One entry in a chat message feed. Variant order is part of the wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatOp {
    /// 0
    Text {
        body: String,
        reply_to: Option<MsgId>,
    },
    /// 1
    Edit { target: MsgId, body: String },
    /// 2
    Delete { target: MsgId },
    /// 3
    React { target: MsgId, emoji: String },
    /// 4: "I have read everything up to and including `up_to`".
    Receipt { up_to: MsgId },
    /// 5: an encrypted blob (Files kit) posted to the chat.
    Attachment {
        blob: [u8; 32],
        mime: String,
        name: String,
        size: u64,
        caption: String,
    },
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
    /// Body (or caption) exceeds [`super::MAX_BODY`] bytes.
    pub const BODY_TOO_LONG: u32 = 5;
    /// Emoji empty or longer than [`super::MAX_EMOJI`] bytes.
    pub const BAD_EMOJI: u32 = 6;
    /// Edit/Delete by someone other than the target message's author.
    pub const NOT_TARGET_AUTHOR: u32 = 7;
    /// Edit/Delete without a 32-byte target-author context.
    pub const MISSING_CONTEXT: u32 = 8;
    /// Attachment metadata out of bounds (MIME type or file name too long, empty MIME).
    pub const BAD_ATTACHMENT: u32 = 9;
}
