//! Rules for the messaging app's message feed.
//!
//! Payload: postcard([`ChatOp`]), byte-identical to `mycel_kit_chat::ChatOp`. Context: unused.
//!
//! - `Receipt` requires Reader (or above); `Meta` requires Admin; every other op requires
//!   Writer (or above);
//! - bodies are at most 16 KiB; reactions are 1..=32 bytes; profile names at most 64 bytes;
//!   titles at most 256 bytes; at most 10 attachments, each with name and MIME type at most
//!   256 bytes.
//!
//! Author-only edit/delete is *not* checked here: the deterministic chat reducer
//! (`mycel_kit_chat::reduce`) enforces it over the causally ordered feed, so the validator
//! needs no facts beyond the entry itself.
#![no_std]

use mycel_rules_abi::chat::{
    ChatOp, MAX_ATTACHMENT_FIELD, MAX_ATTACHMENTS, MAX_BODY, MAX_EMOJI, MAX_NAME, MAX_TITLE,
    codes::{
        BAD_ATTACHMENT, BAD_EMOJI, BODY_TOO_LONG, MALFORMED_PAYLOAD, NAME_TOO_LONG, NOT_ADMIN, NOT_READER, NOT_WRITER,
        WRONG_STREAM,
    },
};
use mycel_rules_guest::{RuleInput, StreamKind, Verdict, abi};

mycel_rules_guest::rules!(validate = validate);

pub fn validate(input: RuleInput) -> Verdict {
    match check(&input) {
        Ok(()) => Verdict::Accept,
        Err(code) => Verdict::reject(code),
    }
}

fn require(cond: bool, code: u32) -> Result<(), u32> {
    if cond { Ok(()) } else { Err(code) }
}

fn check(input: &RuleInput) -> Result<(), u32> {
    require(input.stream.kind == StreamKind::Feed, WRONG_STREAM)?;
    let op: ChatOp = abi::decode_exact(&input.payload).ok_or(MALFORMED_PAYLOAD)?;
    let role = input.author_role;
    match &op {
        ChatOp::Receipt { .. } => require(role.can_read(), NOT_READER)?,
        ChatOp::Meta { .. } => require(role.is_admin(), NOT_ADMIN)?,
        _ => require(role.can_write(), NOT_WRITER)?,
    }
    match op {
        ChatOp::Text { body, reply_to: _, attachments } => {
            require(body.len() <= MAX_BODY, BODY_TOO_LONG)?;
            require(attachments.len() <= MAX_ATTACHMENTS, BAD_ATTACHMENT)?;
            for a in &attachments {
                require(a.name.len() <= MAX_ATTACHMENT_FIELD && a.mime.len() <= MAX_ATTACHMENT_FIELD, BAD_ATTACHMENT)?;
            }
            Ok(())
        }
        ChatOp::Edit { target: _, body } => require(body.len() <= MAX_BODY, BODY_TOO_LONG),
        ChatOp::Delete { target: _ } => Ok(()),
        ChatOp::React { target: _, emoji, on: _ } => require(!emoji.is_empty() && emoji.len() <= MAX_EMOJI, BAD_EMOJI),
        ChatOp::Receipt { up_to: _ } => Ok(()),
        ChatOp::Profile { name } => require(name.len() <= MAX_NAME, NAME_TOO_LONG),
        ChatOp::Meta { title, direct: _ } => require(title.is_none_or(|t| t.len() <= MAX_TITLE), NAME_TOO_LONG),
    }
}
