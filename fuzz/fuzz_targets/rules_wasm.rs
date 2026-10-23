//! Rules bundles (`mycel-rules`): a space's rules are WebAssembly that any
//! admin may publish, and every peer loads and runs them. `wasm-smith`
//! generates valid modules with the ABI's exports (and every other feature
//! the generator knows, floats, SIMD and threads included, which loading
//! must refuse); they are loaded under small limits and, when they load,
//! run on inputs from the fuzzer.
//!
//! Properties: no host panic or hang (fuel and memory caps hold); what loads
//! is valid under exactly the ABI's documented feature set (so no floats,
//! SIMD, threads or memory64), with no imports and no start function; every
//! call is deterministic (same verdict, same fuel, twice in a row on one
//! engine and once on a fresh engine), as consensus requires.
#![no_main]

use std::sync::LazyLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use mycel_rules::{Limits, RulesEngine, RulesModule};
use mycel_rules_abi::{RoleTag, RuleInput, StreamKind, StreamTag};
use wasmparser::{Parser, Payload, Validator, WasmFeatures};

static EXPORTS: LazyLock<Vec<u8>> = LazyLock::new(|| {
    wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "mycel_abi_version") (result i32) unreachable)
            (func (export "mycel_alloc") (param i32) (result i32) unreachable)
            (func (export "mycel_validate") (param i32 i32) (result i64) unreachable)
            (func (export "mycel_reduce") (param i32 i32) (result i64) unreachable))"#,
    )
    .expect("the export template parses")
});

const LIMITS: Limits = Limits { fuel: 200_000, max_memory_bytes: 1 << 20, max_module_bytes: 256 << 10 };

/// The ABI's feature list (crate docs of `mycel-rules`). `GC_TYPES` only
/// lets the validator name `funcref` and `externref`.
const ABI: WasmFeatures = WasmFeatures::GC_TYPES
    .union(WasmFeatures::MUTABLE_GLOBAL)
    .union(WasmFeatures::SIGN_EXTENSION)
    .union(WasmFeatures::SATURATING_FLOAT_TO_INT)
    .union(WasmFeatures::MULTI_VALUE)
    .union(WasmFeatures::BULK_MEMORY)
    .union(WasmFeatures::REFERENCE_TYPES)
    .union(WasmFeatures::TAIL_CALL)
    .union(WasmFeatures::EXTENDED_CONST);

fn input(u: &mut Unstructured) -> arbitrary::Result<RuleInput> {
    let role = match u.int_in_range(0..=3u8)? {
        0 => RoleTag::Admin,
        1 => RoleTag::Writer,
        2 => RoleTag::Reader,
        _ => RoleTag::Relay,
    };
    let kind = if u.arbitrary()? { StreamKind::Doc } else { StreamKind::Feed };
    Ok(RuleInput {
        author: u.arbitrary()?,
        author_role: role,
        stream: StreamTag { kind, id: u.arbitrary()? },
        payload: u.arbitrary()?,
        context: u.arbitrary()?,
    })
}

fn run(data: &[u8]) -> arbitrary::Result<()> {
    let mut u = Unstructured::new(data);
    let mut cfg = wasm_smith::Config::arbitrary(&mut u)?;
    cfg.exports = Some(EXPORTS.clone());
    cfg.max_memory32_bytes = cfg.max_memory32_bytes.min(4 << 20);
    cfg.max_memories = cfg.max_memories.min(2);
    cfg.max_funcs = cfg.max_funcs.min(32);
    cfg.max_instructions = cfg.max_instructions.min(512);
    let module = wasm_smith::Module::new(cfg, &mut u)?;
    let wasm = module.to_bytes();
    let Ok(loaded) = RulesModule::load_with_limits(&wasm, LIMITS) else { return Ok(()) };
    if let Err(e) = Validator::new_with_features(ABI).validate_all(&wasm) {
        panic!("loaded a module outside the ABI's feature set: {e}");
    }
    for payload in Parser::new(0).parse_all(&wasm) {
        match payload.expect("validated") {
            Payload::ImportSection(s) => assert_eq!(s.count(), 0, "loaded a module with imports"),
            Payload::StartSection { .. } => panic!("loaded a module with a start function"),
            _ => {}
        }
    }
    let engine = RulesEngine::new(loaded);
    let fresh = RulesEngine::new(RulesModule::load_with_limits(&wasm, LIMITS).expect("loads again"));
    for _ in 0..u.int_in_range(1..=3u8)? {
        let i = input(&mut u)?;
        let a = engine.validate_traced(&i);
        let b = engine.validate_traced(&i);
        let c = fresh.validate_traced(&i);
        assert!(a.fuel_used <= LIMITS.fuel);
        assert_eq!((a.result, a.fuel_used), (b.result, b.fuel_used), "validate is not deterministic");
        assert_eq!((a.result, a.fuel_used), (c.result, c.fuel_used), "validate depends on the engine");
        let state: Vec<u8> = u.arbitrary()?;
        let a = engine.reduce_traced(&i, &state);
        let b = fresh.reduce_traced(&i, &state);
        assert_eq!((&a.result, a.fuel_used), (&b.result, b.fuel_used), "reduce is not deterministic");
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(data);
});
