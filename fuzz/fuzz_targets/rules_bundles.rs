//! The shipped rules bundles (`crates/mycel-rules/fixtures`) run on what
//! members send: the chat rules on every message-feed entry, the counter
//! rules on actions and states. A differential: the chat bundle (Rust
//! compiled to WebAssembly, run by the `wasmi` interpreter under the real
//! limits) must reach exactly the verdict of the same rules written
//! natively here against the same `mycel-rules-abi` types; the counter's
//! reducer must fold exactly as native arithmetic does.
//!
//! Properties: no host panic; the verdicts agree, so in particular a valid
//! message never runs out of fuel or memory (a liveness bug), and a bad one
//! is never accepted.
#![no_main]

use std::sync::LazyLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use mycel_rules::RulesEngine;
use mycel_rules_abi::chat::{self, ChatOp, codes};
use mycel_rules_abi::{RoleTag, RuleInput, StreamKind, StreamTag, Verdict, decode_exact, encode};

static CHAT: LazyLock<RulesEngine> = LazyLock::new(|| {
    RulesEngine::load(include_bytes!("../../crates/mycel-rules/fixtures/chat_rules.wasm")).expect("chat rules load")
});
static COUNTER: LazyLock<RulesEngine> = LazyLock::new(|| {
    RulesEngine::load(include_bytes!("../../crates/mycel-rules/fixtures/counter_rules.wasm"))
        .expect("counter rules load")
});

/// `rules/chat-rules`, natively.
fn chat_verdict(input: &RuleInput) -> Verdict {
    let check = || -> Result<(), u32> {
        let ok = |c: bool, code: u32| if c { Ok(()) } else { Err(code) };
        ok(input.stream.kind == StreamKind::Feed, codes::WRONG_STREAM)?;
        let op: ChatOp = decode_exact(&input.payload).ok_or(codes::MALFORMED_PAYLOAD)?;
        let role = input.author_role;
        match &op {
            ChatOp::Receipt { .. } => ok(role.can_read(), codes::NOT_READER)?,
            ChatOp::Meta { .. } => ok(role.is_admin(), codes::NOT_ADMIN)?,
            _ => ok(role.can_write(), codes::NOT_WRITER)?,
        }
        match op {
            ChatOp::Text { body, attachments, .. } => {
                ok(body.len() <= chat::MAX_BODY, codes::BODY_TOO_LONG)?;
                ok(attachments.len() <= chat::MAX_ATTACHMENTS, codes::BAD_ATTACHMENT)?;
                for a in &attachments {
                    let fits = a.name.len() <= chat::MAX_ATTACHMENT_FIELD && a.mime.len() <= chat::MAX_ATTACHMENT_FIELD;
                    ok(fits, codes::BAD_ATTACHMENT)?;
                }
                Ok(())
            }
            ChatOp::Edit { body, .. } => ok(body.len() <= chat::MAX_BODY, codes::BODY_TOO_LONG),
            ChatOp::Delete { .. } | ChatOp::Receipt { .. } => Ok(()),
            ChatOp::React { emoji, .. } => ok(!emoji.is_empty() && emoji.len() <= chat::MAX_EMOJI, codes::BAD_EMOJI),
            ChatOp::Profile { name } => ok(name.len() <= chat::MAX_NAME, codes::NAME_TOO_LONG),
            ChatOp::Meta { title, .. } => ok(title.is_none_or(|t| t.len() <= chat::MAX_TITLE), codes::NAME_TOO_LONG),
        }
    };
    match check() {
        Ok(()) => Verdict::Accept,
        Err(code) => Verdict::reject(code),
    }
}

#[derive(serde::Serialize, serde::Deserialize, Arbitrary, Debug)]
enum CounterOp {
    Add(u32),
    Reset,
}

#[derive(Arbitrary, Debug)]
enum Payload {
    /// A well-formed chat op (any sizes), so most inputs reach the checks.
    Chat {
        op: Op,
        trailing: Vec<u8>,
    },
    Counter(CounterOp),
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Op {
    Text { body_len: u16, reply: bool, attachments: Vec<(u16, u16)> },
    Edit { body_len: u16 },
    Delete,
    React { emoji: String },
    Receipt,
    Profile { name: String },
    Meta { title: Option<String> },
}

fn chat_op(op: Op) -> ChatOp {
    let text = |n: u16| "é".repeat(usize::from(n) % (chat::MAX_BODY / 2 + 8));
    match op {
        Op::Text { body_len, reply, attachments } => ChatOp::Text {
            body: text(body_len),
            reply_to: reply.then_some([1; 32]),
            attachments: attachments
                .into_iter()
                .take(12)
                .map(|(n, m)| chat::AttachmentRef {
                    blob: [2; 32],
                    key: [3; 32],
                    nonce: [4; 24],
                    name: "n".repeat(usize::from(n) % 300),
                    mime: "m".repeat(usize::from(m) % 300),
                    size: 1,
                })
                .collect(),
        },
        Op::Edit { body_len } => ChatOp::Edit { target: [5; 32], body: text(body_len) },
        Op::Delete => ChatOp::Delete { target: [6; 32] },
        Op::React { emoji } => ChatOp::React { target: [7; 32], emoji, on: true },
        Op::Receipt => ChatOp::Receipt { up_to: [8; 32] },
        Op::Profile { name } => ChatOp::Profile { name },
        Op::Meta { title } => ChatOp::Meta { title, direct: false },
    }
}

fn run(data: &[u8]) -> arbitrary::Result<()> {
    let mut u = Unstructured::new(data);
    let role = match u.int_in_range(0..=3u8)? {
        0 => RoleTag::Admin,
        1 => RoleTag::Writer,
        2 => RoleTag::Reader,
        _ => RoleTag::Relay,
    };
    let kind = if u.ratio(1, 8)? { StreamKind::Doc } else { StreamKind::Feed };
    let payload = match Payload::arbitrary(&mut u)? {
        Payload::Chat { op, trailing } => {
            let mut p = encode(&chat_op(op));
            if u.ratio(1, 8)? {
                p.extend_from_slice(&trailing);
            }
            p
        }
        Payload::Counter(op) => encode(&op),
        Payload::Raw(bytes) => bytes,
    };
    let input = RuleInput {
        author: u.arbitrary()?,
        author_role: role,
        stream: StreamTag { kind, id: [0; 16] },
        payload,
        context: vec![],
    };
    let wasm = CHAT.validate_traced(&input);
    assert_eq!(wasm.result, chat_verdict(&input), "chat rules: wasm and native disagree ({:?})", wasm.detail);
    // The counter: validate and reduce agree with native arithmetic.
    let state: Option<u64> = u.arbitrary()?;
    let state_bytes = state.map(|s| encode(&s)).unwrap_or_default();
    let got = COUNTER.reduce(&input, &state_bytes);
    let want = match decode_exact::<CounterOp>(&input.payload) {
        None => Err(1),
        Some(CounterOp::Add(_)) if !role.can_write() => Err(2),
        Some(CounterOp::Reset) if !role.is_admin() => Err(3),
        Some(CounterOp::Add(n)) => state.unwrap_or(0).checked_add(u64::from(n)).map(|v| encode(&v)).ok_or(4),
        Some(CounterOp::Reset) => Ok(encode(&0u64)),
    };
    match (got, want) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(mycel_rules_abi::Reason::Rule(a)), Err(b)) => assert_eq!(a, b),
        (got, want) => panic!("counter rules: wasm {got:?}, native {want:?}"),
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(data);
});
