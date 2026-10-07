//! Rules for the messaging app's message feed.
//!
//! Payload: postcard([`ChatOp`]). Context: for `Edit`/`Delete`, the 32-byte key of the target
//! message's author (supplied by the host from the change's causal past).
//!
//! - every op except `Receipt` requires Writer (or Admin);
//! - `Receipt` requires Reader (or above);
//! - message bodies and captions are at most 16 KiB; reactions are 1..=32 bytes;
//! - `Edit` and `Delete` are only allowed for the target message's original author.
#![no_std]

use mycel_rules_abi::chat::{
    ChatOp, MAX_BODY, MAX_EMOJI, MAX_FILE_NAME, MAX_MIME,
    codes::{
        BAD_ATTACHMENT, BAD_EMOJI, BODY_TOO_LONG, MALFORMED_PAYLOAD, MISSING_CONTEXT, NOT_READER,
        NOT_TARGET_AUTHOR, NOT_WRITER, WRONG_STREAM,
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

fn require_target_author(input: &RuleInput) -> Result<(), u32> {
    let target_author: &[u8; 32] = input
        .context
        .as_slice()
        .try_into()
        .map_err(|_| MISSING_CONTEXT)?;
    require(*target_author == input.author, NOT_TARGET_AUTHOR)
}

fn check(input: &RuleInput) -> Result<(), u32> {
    require(input.stream.kind == StreamKind::Feed, WRONG_STREAM)?;
    let op: ChatOp = abi::decode_exact(&input.payload).ok_or(MALFORMED_PAYLOAD)?;
    let role = input.author_role;
    if let ChatOp::Receipt { .. } = op {
        require(role.can_read(), NOT_READER)?;
    } else {
        require(role.can_write(), NOT_WRITER)?;
    }
    match op {
        ChatOp::Text { body, reply_to: _ } => require(body.len() <= MAX_BODY, BODY_TOO_LONG),
        ChatOp::Edit { target: _, body } => {
            require(body.len() <= MAX_BODY, BODY_TOO_LONG)?;
            require_target_author(input)
        }
        ChatOp::Delete { target: _ } => require_target_author(input),
        ChatOp::React { target: _, emoji } => {
            require(!emoji.is_empty() && emoji.len() <= MAX_EMOJI, BAD_EMOJI)
        }
        ChatOp::Attachment {
            blob: _,
            mime,
            name,
            size: _,
            caption,
        } => {
            require(!mime.is_empty() && mime.len() <= MAX_MIME, BAD_ATTACHMENT)?;
            require(name.len() <= MAX_FILE_NAME, BAD_ATTACHMENT)?;
            require(caption.len() <= MAX_BODY, BODY_TOO_LONG)
        }
        ChatOp::Receipt { up_to: _ } => Ok(()),
    }
}
