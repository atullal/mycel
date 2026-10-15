# Mycel rules ABI v1 (L4)

Implemented in `crates/mycel-rules` (host), `crates/mycel-rules-abi` (shared `no_std` types), and `rules/` (guest SDK and example bundles). See [ARCHITECTURE.md, L4](ARCHITECTURE.md#l4-rules).

App rules (validators and action reducers) are written in Rust, compiled to `wasm32-unknown-unknown`, and run by every peer with the [`wasmi`](https://github.com/wasmi-labs/wasmi) interpreter. A bundle is identified by its hash. The goal is the trust layer's invariant extended to app logic: **every honest peer reaches the same accept/reject decision for the same input.**

## 1. Bundle identity and limits

- `RulesHash = BLAKE3::derive_key("mycel/v0/rules-bundle", wasm_bytes)`.
- `Limits::V1`: **fuel 20,000,000 per call**, **memory 16 MiB**, **module ≤ 4 MiB**. Interpreter stack limits are fixed in the crate (recursion depth 1000, value stack 1 MB).
- **Consensus parameters:** the bundle bytes, the `Limits`, the wasmi version (pinned `=2.0.0`, with its portable loop dispatch at every optimisation level; its fuel cost model is part of consensus, guarded by the test `fuel_cost_model_is_pinned`), and the ABI version. Changing any of them can change verdicts near the limits, so every peer must run the same ones.

## 2. Module restrictions (checked at load)

A rules module is a wasm32 core module with:
- **no imports** of any kind (functions, memories, tables, globals). Its output is a pure function of its bytes and the input;
- **no floating point** (`f32`/`f64` types or instructions anywhere): NaN bit patterns aren't portable;
- no SIMD, relaxed SIMD, threads, memory64, multi-memory, custom page sizes, or start function;
- eager compilation, so all validation happens at load, not lazily during a call.

Allowed proposals: mutable-globals, sign-extension, multi-value, bulk-memory, reference-types, tail-call, extended-const (saturating float-to-int is enabled but unusable without floats).

Load also instantiates the module once and calls `mycel_abi_version()`.

## 3. Exports

| Export | Type | Required |
|---|---|---|
| `memory` | memory, 32-bit, initial size ≤ `max_memory_bytes` | yes |
| `mycel_abi_version` | `() -> i32`, must return `1` | yes |
| `mycel_alloc` | `(len: i32) -> i32` | yes |
| `mycel_validate` | `(ptr: i32, len: i32) -> i64` | yes |
| `mycel_reduce` | `(ptr: i32, len: i32) -> i64` | no |

Other exports (e.g. `__data_end`, `__heap_base`) are ignored.

## 4. Calling convention

Every call runs on a **fresh instance** with a **fresh fuel budget**; nothing survives between calls.

1. The host encodes the input with postcard: `RuleInput` for validate, `ReduceInput` for reduce.
2. The host calls `ptr = mycel_alloc(len)` and writes the input at `ptr`. An out-of-bounds `ptr` → `Reject(BadAbi)`. An input larger than the memory cap → `Reject(Trap)` without calling the guest.
3. The host calls `mycel_validate(ptr, len)` or `mycel_reduce(ptr, len)`.

Fuel covers `mycel_alloc` plus the entry point.

### Input encoding (postcard)

```
RuleInput {
  author:      [u8; 32]   // 32 raw bytes: the author's device key
  author_role: RoleTag    // 1 byte: Relay=0, Reader=1, Writer=2, Admin=3
  stream:      StreamTag { kind: 1 byte (Doc=0, Feed=1), id: 16 raw bytes }
  payload:     bytes      // varint len ‖ bytes: the decrypted entry / action
  context:     bytes      // varint len ‖ bytes: host-supplied facts (app-defined; may be empty)
}
ReduceInput { input: RuleInput, state: bytes }   // action = input.payload
```

### `mycel_validate` result (`i64`)

| Value | Verdict |
|---|---|
| `0` | `Accept` |
| `(1 << 32) \| code` (`code: u32`) | `Reject(Rule(code))` |
| anything else | `Reject(BadAbi)` |

### `mycel_reduce` result (`i64`)

`(ptr << 32) | len` (both `u32`), locating a postcard `ReduceOutput` in guest memory:
- variant 0: `Accept { state: bytes }`, the new state;
- variant 1: `Reject { code: u32 }`.

Bytes out of bounds, or that don't decode exactly (no trailing bytes) → `Reject(BadAbi)`.

### Verdicts

```
Verdict = Accept | Reject(Reason)
Reason  = Rule(u32)   // the rules rejected it with an app-defined code
        | Trap        // out of fuel, memory cap, stack overflow, unreachable/panic, OOB access...
        | BadAbi      // the guest broke this ABI
        | NoReducer   // reduce() on a bundle without mycel_reduce
```

All traps collapse to `Trap` so peers agree even if trap details differ. `validate_traced` / `reduce_traced` additionally return `fuel_used` and a human-readable `detail`; these are for logs only, not consensus.

## 5. Host API (`mycel-rules`)

```rust
RulesModule::load(&[u8]) / load_with_limits(&[u8], Limits) / load_pinned(&[u8], RulesHash)
    -> Result<RulesModule, LoadError>
RulesModule::{hash(), limits(), has_reducer()}
RulesEngine::new(RulesModule) / RulesEngine::load(&[u8])          // Clone + Send + Sync
RulesEngine::validate(&self, &RuleInput) -> Verdict
RulesEngine::reduce(&self, &RuleInput, state: &[u8]) -> Result<Vec<u8>, Reason>
RulesEngine::{validate_traced, reduce_traced} -> Trace<T> { result, fuel_used, detail }
RulesHash::of(&[u8])
```

## 6. Writing rules (guest SDK)

```rust
#![no_std]
use mycel_rules_guest::{RuleInput, Verdict};

fn validate(input: RuleInput) -> Verdict {
    if input.author_role.can_write() { Verdict::Accept } else { Verdict::reject(1) }
}
mycel_rules_guest::rules!(validate = validate);
// with a reducer `fn(RuleInput, &[u8]) -> Result<Vec<u8>, u32>`:
// mycel_rules_guest::rules!(validate = validate, reduce = reduce);
```

The SDK provides the exports, a bump allocator (it never frees; instances are discarded after each call) and a panic handler that traps. Build with `rules/build.sh`, which runs `cargo build --release --target wasm32-unknown-unknown` with `opt-level="z"`, LTO, `panic="abort"`, strip, and a 128 KiB shadow stack (a small initial memory makes per-call instantiation about 10× cheaper). Builds are byte-for-byte reproducible with the same rustc, so pin the toolchain when publishing a bundle hash.

Example bundles: `rules/chat-rules` (14 KB) and `rules/counter-rules` (7 KB, exercises `mycel_reduce`).

### Chat rules (`rules/chat-rules`)

Payload = postcard `ChatOp`, byte-identical to `mycel_kit_chat::ChatOp` (checked by `chat_wire_format_matches_mycel_kit_chat`). `context` is unused.

| Op | Needs | Limits |
|---|---|---|
| `Text` | Writer+ | body ≤ 16 KiB; ≤ 10 attachments; attachment name and MIME ≤ 256 bytes |
| `Edit` | Writer+ | body ≤ 16 KiB |
| `Delete` | Writer+ | |
| `React` | Writer+ | emoji 1..=32 bytes |
| `Receipt` | Reader+ | |
| `Profile` | Writer+ | name ≤ 64 bytes |
| `Meta` | Admin | title ≤ 256 bytes |

Payloads must decode exactly (no trailing bytes); ops are only valid on Feed streams. Reject codes are in `mycel_rules_abi::chat::codes`. **Author-only edit/delete is not a validator rule:** the deterministic chat reducer (`mycel_kit_chat::reduce`) enforces it over the causally ordered feed, so validation needs no facts from other entries.

Cost: a maximum-size (16 KiB) message uses about 57k fuel (0.3% of the budget). In a release build a small validate takes about 6 µs, a 16 KiB one about 17 µs, and loading a module about 170 µs. Burning the full 20M budget takes about 5–7 ms.

## 7. How the runtime uses it

1. **Pipeline position:** verify signature → resolve author → envelope validity (TRUST.md §7 rules 1–6) → decrypt → **`FeedValidator`** (here, `RulesEngine::validate`) → apply. Keepers cannot decrypt, so they enforce header validity only. An entry the rules reject never enters the feed on any peer; its envelope stays stored and is skipped.
2. **`RuleInput` fields:** `author` = the author's device key. `author_role` = the role in `state(valid ∩ past(auth_heads))`, the same causal state as TRUST.md §7 rule 3, never the receiver's current view. `payload` = the decrypted entry body. `context` is empty.
3. **Which rules apply:** the runtime embeds the chat rules bundle (`crates/mycel-rules/fixtures/chat_rules.wasm`, built from `rules/chat-rules`; `mycel_node::chat_rules_hash()` gives its hash) and runs it on the chat feed of every space. Other streams are not checked by rules. A space doesn't record which bundle it uses, so every peer must run the same build.
4. **Reducers:** the chat kit's reducer is native Rust (`mycel_kit_chat::reduce`), folding entries in the feed's deterministic order. `mycel_reduce` is part of the ABI and exercised by `rules/counter-rules` in tests.
5. **DoS:** a malicious Writer can cost each peer at most one full fuel budget (≈ 5–7 ms) per entry.
