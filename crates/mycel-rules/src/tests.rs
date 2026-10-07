use super::*;
use mycel_rules_abi::chat::{AttachmentRef, ChatOp, codes};
use mycel_rules_abi::{encode, unpack_ptr_len};

const CHAT_RULES: &[u8] = include_bytes!("../fixtures/chat_rules.wasm");
const COUNTER_RULES: &[u8] = include_bytes!("../fixtures/counter_rules.wasm");

const ALICE: [u8; 32] = [0xA1; 32];
const BOB: [u8; 32] = [0xB0; 32];
const FEED: StreamTag = StreamTag {
    kind: StreamKind::Feed,
    id: [7; 16],
};

fn chat() -> RulesEngine {
    RulesEngine::load(CHAT_RULES).expect("chat rules load")
}

fn input(author: [u8; 32], role: RoleTag, op: &ChatOp, context: &[u8]) -> RuleInput {
    RuleInput {
        author,
        author_role: role,
        stream: FEED,
        payload: encode(op),
        context: context.to_vec(),
    }
}

fn op_input(role: RoleTag, op: &ChatOp) -> RuleInput {
    input(ALICE, role, op, &[])
}

fn text(body: &str) -> ChatOp {
    ChatOp::Text {
        body: body.into(),
        reply_to: None,
        attachments: vec![],
    }
}

fn attachment(name: &str, mime: &str) -> AttachmentRef {
    AttachmentRef {
        blob: [1; 32],
        key: [2; 32],
        nonce: [3; 24],
        name: name.into(),
        mime: mime.into(),
        size: 1234,
    }
}

fn with_attachments(atts: Vec<AttachmentRef>) -> ChatOp {
    ChatOp::Text {
        body: "see attached".into(),
        reply_to: None,
        attachments: atts,
    }
}

fn rule(code: u32) -> Verdict {
    Verdict::Reject(Reason::Rule(code))
}

/// A valid rules module in WAT with `validate_body` as the body of
/// `mycel_validate (param $ptr i32) (param $len i32) (result i64)`.
fn wat_guest(extra: &str, validate_body: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            {extra}
            (memory (export "memory") 1)
            (func (export "mycel_abi_version") (result i32) i32.const 1)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "mycel_validate") (param $ptr i32) (param $len i32) (result i64)
                {validate_body}))"#
    ))
    .expect("valid wat")
}

fn load_err(wasm: &[u8]) -> LoadError {
    RulesModule::load(wasm).expect_err("module must be rejected")
}

// ───────────────────────────── chat rules ─────────────────────────────

#[test]
fn chat_accepts_valid_ops() {
    let e = chat();
    let target = [9u8; 32];
    let cases = [
        (RoleTag::Writer, text("hello")),
        (RoleTag::Admin, text("hello from admin")),
        (
            RoleTag::Writer,
            ChatOp::Text {
                body: "re".into(),
                reply_to: Some(target),
                attachments: vec![],
            },
        ),
        (RoleTag::Writer, text(&"x".repeat(16 * 1024))),
        (
            RoleTag::Writer,
            with_attachments(vec![attachment(&"n".repeat(256), &"m".repeat(256)); 10]),
        ),
        (
            RoleTag::Writer,
            ChatOp::Edit {
                target,
                body: "fixed".into(),
            },
        ),
        // Edit/Delete of someone else's message passes validation: the chat reducer ignores
        // it (author-only edits are enforced over the causally ordered feed).
        (RoleTag::Writer, ChatOp::Delete { target }),
        (
            RoleTag::Writer,
            ChatOp::React {
                target,
                emoji: "👍🏽".into(),
                on: true,
            },
        ),
        (
            RoleTag::Writer,
            ChatOp::React {
                target,
                emoji: "x".repeat(32),
                on: false,
            },
        ),
        (RoleTag::Reader, ChatOp::Receipt { up_to: target }),
        (RoleTag::Writer, ChatOp::Receipt { up_to: target }),
        (
            RoleTag::Writer,
            ChatOp::Profile {
                name: "n".repeat(64),
            },
        ),
        (
            RoleTag::Writer,
            ChatOp::Profile {
                name: String::new(),
            },
        ),
        (
            RoleTag::Admin,
            ChatOp::Meta {
                title: Some("Book club".into()),
                direct: false,
            },
        ),
        (
            RoleTag::Admin,
            ChatOp::Meta {
                title: None,
                direct: true,
            },
        ),
    ];
    for (i, (role, op)) in cases.iter().enumerate() {
        let t = e.validate_traced(&op_input(*role, op));
        assert_eq!(t.result, Verdict::Accept, "case {i} {op:?}: {:?}", t.detail);
    }
}

#[test]
fn chat_rejects_invalid_ops() {
    let e = chat();
    let target = [9u8; 32];
    let cases = [
        // role checks
        (RoleTag::Reader, text("hi"), codes::NOT_WRITER),
        (RoleTag::Relay, text("hi"), codes::NOT_WRITER),
        (
            RoleTag::Reader,
            ChatOp::Edit {
                target,
                body: "x".into(),
            },
            codes::NOT_WRITER,
        ),
        (
            RoleTag::Reader,
            ChatOp::Delete { target },
            codes::NOT_WRITER,
        ),
        (
            RoleTag::Reader,
            ChatOp::React {
                target,
                emoji: "x".into(),
                on: true,
            },
            codes::NOT_WRITER,
        ),
        (
            RoleTag::Reader,
            ChatOp::Profile { name: "me".into() },
            codes::NOT_WRITER,
        ),
        (
            RoleTag::Relay,
            ChatOp::Receipt { up_to: target },
            codes::NOT_READER,
        ),
        (
            RoleTag::Writer,
            ChatOp::Meta {
                title: None,
                direct: false,
            },
            codes::NOT_ADMIN,
        ),
        (
            RoleTag::Reader,
            ChatOp::Meta {
                title: None,
                direct: false,
            },
            codes::NOT_ADMIN,
        ),
        // size limits
        (
            RoleTag::Writer,
            text(&"x".repeat(16 * 1024 + 1)),
            codes::BODY_TOO_LONG,
        ),
        (
            RoleTag::Writer,
            ChatOp::Edit {
                target,
                body: "x".repeat(16 * 1024 + 1),
            },
            codes::BODY_TOO_LONG,
        ),
        (
            RoleTag::Writer,
            ChatOp::React {
                target,
                emoji: "x".repeat(33),
                on: true,
            },
            codes::BAD_EMOJI,
        ),
        (
            RoleTag::Writer,
            ChatOp::React {
                target,
                emoji: String::new(),
                on: false,
            },
            codes::BAD_EMOJI,
        ),
        (
            RoleTag::Writer,
            ChatOp::Profile {
                name: "n".repeat(65),
            },
            codes::NAME_TOO_LONG,
        ),
        (
            RoleTag::Admin,
            ChatOp::Meta {
                title: Some("t".repeat(257)),
                direct: false,
            },
            codes::NAME_TOO_LONG,
        ),
        // attachments
        (
            RoleTag::Writer,
            with_attachments(vec![attachment("a", "b"); 11]),
            codes::BAD_ATTACHMENT,
        ),
        (
            RoleTag::Writer,
            with_attachments(vec![attachment(&"n".repeat(257), "image/png")]),
            codes::BAD_ATTACHMENT,
        ),
        (
            RoleTag::Writer,
            with_attachments(vec![
                attachment("ok", "image/png"),
                attachment("a.png", &"m".repeat(257)),
            ]),
            codes::BAD_ATTACHMENT,
        ),
    ];
    for (i, (role, op, code)) in cases.iter().enumerate() {
        assert_eq!(e.validate(&op_input(*role, op)), rule(*code), "case {i}");
    }
}

#[test]
fn chat_rejects_malformed_payloads_and_wrong_stream() {
    let e = chat();
    let mut c = input(ALICE, RoleTag::Writer, &text("hi"), &[]);
    let good = c.payload.clone();

    c.payload = vec![];
    assert_eq!(e.validate(&c), rule(codes::MALFORMED_PAYLOAD));
    c.payload = vec![42, 1, 2, 3]; // unknown variant
    assert_eq!(e.validate(&c), rule(codes::MALFORMED_PAYLOAD));
    c.payload = good.clone();
    c.payload.push(0); // trailing byte
    assert_eq!(e.validate(&c), rule(codes::MALFORMED_PAYLOAD));
    c.payload = vec![0, 2, 0xff, 0xfe, 0, 0]; // invalid UTF-8 body
    assert_eq!(e.validate(&c), rule(codes::MALFORMED_PAYLOAD));
    c.payload = vec![3, 0]; // React with a truncated target
    assert_eq!(e.validate(&c), rule(codes::MALFORMED_PAYLOAD));

    c.payload = good;
    c.stream.kind = StreamKind::Doc;
    assert_eq!(e.validate(&c), rule(codes::WRONG_STREAM));
}

/// `mycel_rules_abi::chat::ChatOp` (no_std, used by the wasm guest) must decode exactly the
/// bytes `mycel_kit_chat::ChatOp` produces, for every variant.
#[test]
fn chat_wire_format_matches_mycel_kit_chat() {
    use mycel_crypto::Hash32 as H;
    use mycel_kit_chat as kit;

    let kit_att = |name: &str, mime: &str| kit::AttachmentRef {
        blob: H([1; 32]),
        key: [2; 32],
        nonce: [3; 24],
        name: name.into(),
        mime: mime.into(),
        size: 1234,
    };
    // (kit op, the abi op it must decode to, role, expected verdict)
    let cases: Vec<(kit::ChatOp, ChatOp, RoleTag, Verdict)> = vec![
        (
            kit::ChatOp::Text {
                body: "hi ☕".into(),
                reply_to: Some(H([4; 32])),
                attachments: vec![kit_att("a.png", "image/png"), kit_att("b", "")],
            },
            ChatOp::Text {
                body: "hi ☕".into(),
                reply_to: Some([4; 32]),
                attachments: vec![attachment("a.png", "image/png"), attachment("b", "")],
            },
            RoleTag::Writer,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::Text {
                body: "x".repeat(16 * 1024 + 1),
                reply_to: None,
                attachments: vec![],
            },
            ChatOp::Text {
                body: "x".repeat(16 * 1024 + 1),
                reply_to: None,
                attachments: vec![],
            },
            RoleTag::Writer,
            rule(codes::BODY_TOO_LONG),
        ),
        (
            kit::ChatOp::Edit {
                target: H([5; 32]),
                body: "edited".into(),
            },
            ChatOp::Edit {
                target: [5; 32],
                body: "edited".into(),
            },
            RoleTag::Writer,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::Delete { target: H([6; 32]) },
            ChatOp::Delete { target: [6; 32] },
            RoleTag::Reader,
            rule(codes::NOT_WRITER),
        ),
        (
            kit::ChatOp::React {
                target: H([7; 32]),
                emoji: "🎉".into(),
                on: true,
            },
            ChatOp::React {
                target: [7; 32],
                emoji: "🎉".into(),
                on: true,
            },
            RoleTag::Writer,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::React {
                target: H([7; 32]),
                emoji: "🎉".into(),
                on: false,
            },
            ChatOp::React {
                target: [7; 32],
                emoji: "🎉".into(),
                on: false,
            },
            RoleTag::Admin,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::Receipt { up_to: H([8; 32]) },
            ChatOp::Receipt { up_to: [8; 32] },
            RoleTag::Reader,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::Profile {
                name: "Alice".into(),
            },
            ChatOp::Profile {
                name: "Alice".into(),
            },
            RoleTag::Writer,
            Verdict::Accept,
        ),
        (
            kit::ChatOp::Meta {
                title: Some("Team".into()),
                direct: false,
            },
            ChatOp::Meta {
                title: Some("Team".into()),
                direct: false,
            },
            RoleTag::Writer,
            rule(codes::NOT_ADMIN),
        ),
        (
            kit::ChatOp::Meta {
                title: None,
                direct: true,
            },
            ChatOp::Meta {
                title: None,
                direct: true,
            },
            RoleTag::Admin,
            Verdict::Accept,
        ),
    ];
    let e = chat();
    for (i, (kit_op, abi_op, role, verdict)) in cases.iter().enumerate() {
        let bytes = kit_op.encode();
        assert_eq!(
            mycel_rules_abi::decode_exact::<ChatOp>(&bytes).as_ref(),
            Some(abi_op),
            "case {i}: abi decode of kit bytes"
        );
        assert_eq!(encode(abi_op), bytes, "case {i}: abi encoding differs");
        assert_eq!(
            kit::ChatOp::decode(&encode(abi_op)).as_ref(),
            Some(kit_op),
            "case {i}: kit decode"
        );
        let c = RuleInput {
            author: ALICE,
            author_role: *role,
            stream: FEED,
            payload: bytes,
            context: vec![],
        };
        assert_eq!(e.validate(&c), *verdict, "case {i}: verdict");
    }
    // Every kit variant is covered above (keeps this test honest when variants are added).
    let covered: std::collections::BTreeSet<u8> =
        cases.iter().map(|(k, ..)| k.encode()[0]).collect();
    assert_eq!(covered, (0..7).collect());
}

#[test]
fn chat_fuel_is_well_within_budget() {
    let e = chat();
    let big = input(ALICE, RoleTag::Writer, &text(&"x".repeat(16 * 1024)), &[]);
    let t = e.validate_traced(&big);
    assert_eq!(t.result, Verdict::Accept);
    assert!(t.fuel_used > 0);
    eprintln!("chat-rules fuel for a 16 KiB message: {}", t.fuel_used);
    // Max-size message uses well under 1/10 of the budget.
    assert!(
        t.fuel_used < Limits::V1.fuel / 10,
        "fuel used: {}",
        t.fuel_used
    );
    let atts = op_input(
        RoleTag::Writer,
        &with_attachments(vec![attachment(&"n".repeat(256), &"m".repeat(256)); 10]),
    );
    let t = e.validate_traced(&atts);
    assert_eq!(t.result, Verdict::Accept);
    assert!(
        t.fuel_used < Limits::V1.fuel / 10,
        "fuel used: {}",
        t.fuel_used
    );
}

#[test]
fn chat_has_no_reducer() {
    let e = chat();
    assert!(!e.module().has_reducer());
    let c = input(ALICE, RoleTag::Writer, &text("hi"), &[]);
    assert_eq!(e.reduce(&c, &[]), Err(Reason::NoReducer));
}

// ───────────────────────────── determinism ─────────────────────────────

#[test]
fn determinism_repeated_calls_and_fresh_engines() {
    let target = [3u8; 32];
    let inputs = [
        input(ALICE, RoleTag::Writer, &text("hello"), &[]),
        input(ALICE, RoleTag::Reader, &text("hello"), &[]),
        input(ALICE, RoleTag::Writer, &ChatOp::Delete { target }, &[]),
        input(
            BOB,
            RoleTag::Writer,
            &ChatOp::Meta {
                title: None,
                direct: true,
            },
            &[],
        ),
        input(ALICE, RoleTag::Writer, &text(&"y".repeat(20_000)), &[]),
    ];
    let reference: Vec<_> = {
        let e = chat();
        inputs.iter().map(|i| e.validate_traced(i)).collect()
    };
    // Same engine, interleaved repeated calls in different orders.
    let e = chat();
    for round in 0..5 {
        for (j, i) in inputs.iter().enumerate().rev() {
            let t = e.validate_traced(i);
            assert_eq!(t.result, reference[j].result, "round {round} input {j}");
            assert_eq!(
                t.fuel_used, reference[j].fuel_used,
                "fuel round {round} input {j}"
            );
        }
    }
    // Fresh engines (and a clone used from another thread).
    for _ in 0..3 {
        let e = chat();
        let e2 = e.clone();
        let inputs2 = inputs.clone();
        let from_thread =
            std::thread::spawn(move || inputs2.iter().map(|i| e2.validate(i)).collect::<Vec<_>>())
                .join()
                .unwrap();
        for (j, i) in inputs.iter().enumerate() {
            assert_eq!(e.validate(i), reference[j].result);
            assert_eq!(from_thread[j], reference[j].result);
        }
    }
}

/// The fuel cost model is consensus: if a wasmi upgrade changes it, verdicts near the fuel
/// limit can change. This pins the exact fuel of a fixed workload so such a change is noticed
/// (and shipped as a new ABI/limits version rather than silently).
#[test]
fn fuel_cost_model_is_pinned() {
    let wasm = wat_guest(
        "",
        r#"(local $i i32)
           (loop $l
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (i32.store (i32.const 0) (local.get $i))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 1000))))
           (i64.const 0)"#,
    );
    let e = RulesEngine::load(&wasm).unwrap();
    let t = e.validate_traced(&input(ALICE, RoleTag::Writer, &text("x"), &[]));
    assert_eq!(t.result, Verdict::Accept);
    assert_eq!(t.fuel_used, 12_004, "fuel cost model changed");
}

#[test]
fn instances_do_not_keep_state_across_calls() {
    // Rejects if its mutable global was already incremented, i.e. if state leaked.
    let wasm = wat_guest(
        r#"(global $calls (mut i32) (i32.const 0))"#,
        r#"(global.set $calls (i32.add (global.get $calls) (i32.const 1)))
           (if (result i64) (i32.gt_u (global.get $calls) (i32.const 1))
               (then (i64.const 0x100000005))
               (else (i64.const 0)))"#,
    );
    let e = RulesEngine::load(&wasm).unwrap();
    let c = input(ALICE, RoleTag::Writer, &text("x"), &[]);
    for _ in 0..10 {
        assert_eq!(e.validate(&c), Verdict::Accept);
    }
}

// ───────────────────────────── reducer ─────────────────────────────

#[derive(serde::Serialize)]
enum CounterOp {
    Add(u32),
    Reset,
}

#[test]
fn counter_reducer_folds_actions() {
    let e = RulesEngine::load(COUNTER_RULES).unwrap();
    assert!(e.module().has_reducer());
    let act = |role, op: &CounterOp| RuleInput {
        author: ALICE,
        author_role: role,
        stream: FEED,
        payload: encode(op),
        context: vec![],
    };
    let mut state = Vec::new();
    for n in [1u32, 2, 39] {
        state = e
            .reduce(&act(RoleTag::Writer, &CounterOp::Add(n)), &state)
            .unwrap();
    }
    assert_eq!(postcard_u64(&state), 42);
    // Rejections leave the caller's state untouched.
    assert_eq!(
        e.reduce(&act(RoleTag::Reader, &CounterOp::Add(1)), &state),
        Err(Reason::Rule(2))
    );
    assert_eq!(
        e.reduce(&act(RoleTag::Writer, &CounterOp::Reset), &state),
        Err(Reason::Rule(3))
    );
    let reset = e
        .reduce(&act(RoleTag::Admin, &CounterOp::Reset), &state)
        .unwrap();
    assert_eq!(postcard_u64(&reset), 0);
    // Overflow and a corrupt state are deterministic rejections.
    let max = encode(&u64::MAX);
    assert_eq!(
        e.reduce(&act(RoleTag::Writer, &CounterOp::Add(1)), &max),
        Err(Reason::Rule(4))
    );
    assert_eq!(
        e.reduce(&act(RoleTag::Writer, &CounterOp::Add(1)), &[0xff]),
        Err(Reason::Rule(5))
    );
    // validate agrees with reduce's authorization.
    assert_eq!(
        e.validate(&act(RoleTag::Writer, &CounterOp::Reset)),
        rule(3)
    );
    assert_eq!(
        e.validate(&act(RoleTag::Admin, &CounterOp::Reset)),
        Verdict::Accept
    );
}

fn postcard_u64(bytes: &[u8]) -> u64 {
    mycel_rules_abi::decode_exact(bytes).expect("u64 state")
}

#[test]
fn reduce_input_ref_encoding_matches_abi_type() {
    let i = input(ALICE, RoleTag::Writer, &text("x"), &[1, 2]);
    #[derive(serde::Serialize)]
    struct ReduceInputRef<'a> {
        input: &'a RuleInput,
        #[serde(with = "mycel_rules_abi::serde_bytes")]
        state: &'a [u8],
    }
    // Also equal to a plain `&[u8]` (serde seq) encoding: postcard writes bytes identically.
    #[derive(serde::Serialize)]
    struct PlainSeq<'a> {
        input: &'a RuleInput,
        state: &'a [u8],
    }
    let owned = ReduceInput {
        input: i.clone(),
        state: vec![5, 6, 7],
    };
    assert_eq!(
        encode(&ReduceInputRef {
            input: &i,
            state: &[5, 6, 7]
        }),
        encode(&owned)
    );
    assert_eq!(
        encode(&PlainSeq {
            input: &i,
            state: &[5, 6, 7]
        }),
        encode(&owned)
    );
}

// ───────────────────────────── resource limits ─────────────────────────────

#[test]
fn infinite_loop_runs_out_of_fuel_deterministically() {
    let wasm = wat_guest("", "(loop $l (br $l)) (i64.const 0)");
    let c = input(ALICE, RoleTag::Writer, &text("x"), &[]);
    let mut details = Vec::new();
    for _ in 0..3 {
        let e = RulesEngine::load(&wasm).unwrap();
        let t = e.validate_traced(&c);
        assert_eq!(t.result, Verdict::Reject(Reason::Trap));
        assert_eq!(t.fuel_used, Limits::V1.fuel);
        details.push(t.detail.unwrap());
    }
    assert!(details[0].contains("fuel"), "{}", details[0]);
    // With a smaller budget it still terminates the same way.
    let small = Limits {
        fuel: 1000,
        ..Limits::V1
    };
    let e = RulesEngine::new(RulesModule::load_with_limits(&wasm, small).unwrap());
    assert_eq!(e.validate(&c), Verdict::Reject(Reason::Trap));
}

#[test]
fn memory_bomb_is_capped() {
    // Grows memory one page at a time until `memory.grow` fails, then traps.
    let bomb = wat_guest(
        "",
        r#"(block $done (loop $l
              (br_if $done (i32.eq (memory.grow (i32.const 1)) (i32.const -1)))
              (br $l)))
           unreachable"#,
    );
    let e = RulesEngine::load(&bomb).unwrap();
    let c = input(ALICE, RoleTag::Writer, &text("x"), &[]);
    assert_eq!(e.validate(&c), Verdict::Reject(Reason::Trap));

    // `memory.grow` past the cap fails (returns -1) instead of allocating; here the guest
    // reports how many pages it managed to grow: exactly up to 16 MiB = 256 pages.
    let probe = wat_guest(
        "",
        r#"(drop (memory.grow (i32.const 16384)))     ;; 1 GiB: must fail
           (block $done (loop $l
              (br_if $done (i32.eq (memory.grow (i32.const 1)) (i32.const -1)))
              (br $l)))
           (i64.or (i64.const 0x100000000) (i64.extend_i32_u (memory.size)))"#,
    );
    let e = RulesEngine::load(&probe).unwrap();
    assert_eq!(e.validate(&c), rule(256));

    // A module whose *initial* memory exceeds the cap is refused at load.
    let huge = wat::parse_str(
        r#"(module (memory (export "memory") 1000)
            (func (export "mycel_abi_version") (result i32) i32.const 1)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 0)
            (func (export "mycel_validate") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    assert!(matches!(load_err(&huge), LoadError::MemoryTooLarge { .. }));
}

#[test]
fn oversized_input_is_a_trap_not_a_crash() {
    let e = RulesEngine::new(
        RulesModule::load_with_limits(
            CHAT_RULES,
            Limits {
                max_memory_bytes: 2 * 1024 * 1024,
                ..Limits::V1
            },
        )
        .unwrap(),
    );
    // Larger than the whole memory cap: rejected without running the guest.
    let c = input(
        ALICE,
        RoleTag::Writer,
        &text(&"x".repeat(3 * 1024 * 1024)),
        &[],
    );
    assert_eq!(e.validate(&c), Verdict::Reject(Reason::Trap));
    // Fits the cap on its own, but the guest's copies don't: guest allocation fails -> trap.
    let c = input(ALICE, RoleTag::Writer, &text(&"x".repeat(1024 * 1024)), &[]);
    assert_eq!(e.validate(&c), Verdict::Reject(Reason::Trap));
}

#[test]
fn deep_recursion_traps() {
    let wasm = wat_guest(
        r#"(func $rec (param i32) (result i32) (call $rec (local.get 0)))"#,
        "(drop (call $rec (i32.const 0))) (i64.const 0)",
    );
    let e = RulesEngine::load(&wasm).unwrap();
    let t = e.validate_traced(&input(ALICE, RoleTag::Writer, &text("x"), &[]));
    assert_eq!(t.result, Verdict::Reject(Reason::Trap), "{:?}", t.detail);
}

// ───────────────────────────── ABI violations ─────────────────────────────

#[test]
fn bad_return_values_are_bad_abi() {
    let c = input(ALICE, RoleTag::Writer, &text("x"), &[]);
    for ret in ["-1", "0x200000000", "1"] {
        let e = RulesEngine::load(&wat_guest("", &format!("(i64.const {ret})"))).unwrap();
        assert_eq!(e.validate(&c), Verdict::Reject(Reason::BadAbi), "{ret}");
    }
    let e = RulesEngine::load(&wat_guest("", "(i64.const 0x1deadbeef)")).unwrap();
    assert_eq!(e.validate(&c), rule(0xdeadbeef));
}

#[test]
fn out_of_bounds_alloc_is_bad_abi() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1)
            (func (export "mycel_abi_version") (result i32) i32.const 1)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 65530)
            (func (export "mycel_validate") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    let e = RulesEngine::load(&wasm).unwrap();
    let t = e.validate_traced(&input(ALICE, RoleTag::Writer, &text("hello world"), &[]));
    assert_eq!(t.result, Verdict::Reject(Reason::BadAbi), "{:?}", t.detail);
}

#[test]
fn bad_reduce_output_is_bad_abi() {
    // Points the output at a range past the end of memory, then at garbage bytes.
    for (ret, what) in [
        ("0x0000fff000000100", "oob"),
        ("0x0000000000000003", "garbage"),
    ] {
        let wasm = wat::parse_str(format!(
            r#"(module (memory (export "memory") 1)
                (func (export "mycel_abi_version") (result i32) i32.const 1)
                (func (export "mycel_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "mycel_validate") (param i32 i32) (result i64) i64.const 0)
                (func (export "mycel_reduce") (param i32 i32) (result i64)
                    (i32.store (i32.const 0) (i32.const 0xffffffff))
                    (i64.const {ret})))"#
        ))
        .unwrap();
        let e = RulesEngine::load(&wasm).unwrap();
        let (p, l) = unpack_ptr_len(i64::from_str_radix(&ret[2..], 16).unwrap());
        let r = e.reduce_traced(&input(ALICE, RoleTag::Writer, &text("x"), &[]), &[]);
        assert_eq!(
            r.result,
            Err(Reason::BadAbi),
            "{what} ({p:#x}+{l}): {:?}",
            r.detail
        );
    }
}

// ───────────────────────────── load-time validation ─────────────────────────────

#[test]
fn float_ops_rejected_at_load() {
    // A float instruction buried in an otherwise valid module.
    let wasm = wat_guest(
        r#"(func $f (param i64) (result i64)
              (i64.reinterpret_f64 (f64.add (f64.reinterpret_i64 (local.get 0)) (f64.const 1))))"#,
        "(call $f (i64.const 0))",
    );
    let err = load_err(&wasm);
    assert!(
        matches!(err, LoadError::Invalid(ref m) if m.contains("float")),
        "{err}"
    );
    // A float-typed global, never used.
    let wasm = wat_guest("(global f32 (f32.const 0))", "(i64.const 0)");
    assert!(matches!(load_err(&wasm), LoadError::Invalid(_)));
    // A float in a function signature only.
    let wasm = wat_guest("(func (param f64))", "(i64.const 0)");
    assert!(matches!(load_err(&wasm), LoadError::Invalid(_)));
}

#[test]
fn simd_rejected_at_load() {
    let wasm = wat_guest(
        "(func (result v128) (v128.const i64x2 0 0))",
        "(i64.const 0)",
    );
    assert!(matches!(load_err(&wasm), LoadError::Invalid(_)));
}

#[test]
fn imports_rejected_at_load() {
    for import in [
        r#"(import "env" "now" (func (result i64)))"#,
        r#"(import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32)))"#,
        r#"(import "env" "g" (global i32))"#,
        r#"(import "env" "t" (table 1 funcref))"#,
    ] {
        let wasm = wat_guest(import, "(i64.const 0)");
        assert!(
            matches!(load_err(&wasm), LoadError::ForbiddenImport { .. }),
            "{import}"
        );
    }
    let imported_memory = wat::parse_str(
        r#"(module (import "env" "memory" (memory 1)) (export "memory" (memory 0))
            (func (export "mycel_abi_version") (result i32) i32.const 1)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 0)
            (func (export "mycel_validate") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    assert!(matches!(
        load_err(&imported_memory),
        LoadError::ForbiddenImport { .. }
    ));
}

#[test]
fn start_function_rejected_at_load() {
    let wasm = wat_guest("(func $s) (start $s)", "(i64.const 0)");
    assert!(matches!(load_err(&wasm), LoadError::Invalid(_)));
}

#[test]
fn abi_shape_enforced_at_load() {
    assert!(matches!(load_err(b"not wasm"), LoadError::Invalid(_)));
    let no_validate = wat::parse_str(
        r#"(module (memory (export "memory") 1)
            (func (export "mycel_abi_version") (result i32) i32.const 1)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 0))"#,
    )
    .unwrap();
    assert!(matches!(
        load_err(&no_validate),
        LoadError::MissingExport("mycel_validate")
    ));
    let wrong_sig = wat_guest(
        r#"(func (export "mycel_reduce") (param i32 i32) (result i32) i32.const 0)"#,
        "(i64.const 0)",
    );
    assert!(matches!(
        load_err(&wrong_sig),
        LoadError::BadExportType("mycel_reduce")
    ));
    let wrong_version = wat::parse_str(
        r#"(module (memory (export "memory") 1)
            (func (export "mycel_abi_version") (result i32) i32.const 2)
            (func (export "mycel_alloc") (param i32) (result i32) i32.const 0)
            (func (export "mycel_validate") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    assert!(matches!(
        load_err(&wrong_version),
        LoadError::AbiVersion {
            found: 2,
            expected: 1
        }
    ));
    let small = Limits {
        max_module_bytes: 100,
        ..Limits::V1
    };
    assert!(matches!(
        RulesModule::load_with_limits(CHAT_RULES, small),
        Err(LoadError::TooLarge { .. })
    ));
}

// ───────────────────────────── hashing ─────────────────────────────

#[test]
fn hash_is_stable_and_domain_separated() {
    // The empty wasm module; pins the hash function and its context string.
    const EMPTY_MODULE: &[u8] = b"\0asm\x01\0\0\0";
    assert_eq!(
        RulesHash::of(EMPTY_MODULE).to_string(),
        "80d7dd8898863822f4de644a03204437e2075b0681e72507d542c53a8268d8c4",
    );
    assert_eq!(
        RulesHash::of(CHAT_RULES).0,
        blake3::derive_key("mycel/v0/rules-bundle", CHAT_RULES)
    );
    assert_ne!(
        RulesHash::of(CHAT_RULES).0,
        *blake3::hash(CHAT_RULES).as_bytes()
    );

    let e1 = chat();
    let e2 = chat();
    assert_eq!(e1.hash(), e2.hash());
    assert_eq!(e1.hash(), RulesHash::of(CHAT_RULES));
    assert_ne!(e1.hash(), RulesHash::of(COUNTER_RULES));

    // Pinning.
    assert!(RulesModule::load_pinned(CHAT_RULES, RulesHash::of(CHAT_RULES)).is_ok());
    assert!(matches!(
        RulesModule::load_pinned(CHAT_RULES, RulesHash::of(COUNTER_RULES)),
        Err(LoadError::HashMismatch { .. })
    ));
}
