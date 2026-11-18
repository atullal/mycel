# Mycel rules ABI

This is the specification of the WebAssembly ABI between the Mycel runtime and
app rules, version 2. It is for people who write a rules bundle or work on the
rules host. [ARCHITECTURE.md](ARCHITECTURE.md) places rules in the layer model
as L4.

App rules are validators and action reducers. They are written in Rust,
compiled to `wasm32-unknown-unknown`, and run by every peer with the
[`wasmi`](https://github.com/wasmi-labs/wasmi) interpreter. The ABI exists so
that every honest peer reaches the same accept or reject decision for the same
input. That is the trust layer's invariant, extended to app logic.

The code is in three places:

| Path | Contents |
|---|---|
| `crates/mycel-rules` | the host: loads and runs bundles |
| `crates/mycel-rules-abi` | the types host and guest share (`no_std`) |
| `rules/` | the guest SDK (`mycel-rules-guest`) and two example bundles |

## Bundle identity and limits

A rules bundle is one WebAssembly module. Its identity is a hash of its bytes:

```text
RulesHash = BLAKE3::derive_key("mycel/v0/rules-bundle", wasm_bytes)
```

`Limits::V1` holds the limits, unchanged since ABI version 1:

| Limit | Value |
|---|---|
| fuel per call | 20,000,000 |
| linear memory | 16 MiB |
| module size | 4 MiB |

The interpreter's stack limits are fixed in the host crate: a recursion depth
of 1,000 and a value stack of 1,000,000 bytes. A table holds at most 10,000
elements.

The bundle bytes, the `Limits`, the ABI version and the wasmi version are
consensus parameters. Changing any of them can change verdicts near the
limits, so every peer must run the same ones. wasmi is pinned to exactly
2.0.1 and always runs its portable loop dispatch, whatever the optimisation
level. Its fuel cost model is part of consensus, and the test
`fuel_cost_model_is_pinned` fails if it changes.

The ABI version changes whenever anything that decides a verdict does:

| Version | What changed |
|---|---|
| 1 | The first version, on wasmi 2.0.0. |
| 2 | wasmi 2.0.1, which also charges fuel for zero-initialising a function's locals (one unit per eight locals). The exports, encodings and limits are the same. |

A host refuses a module built for another version, so bundles are rebuilt
with `rules/build.sh` when the version changes.

## Module requirements

The host checks a module when it loads it, and never runs one it refused. A
rules module is a wasm32 core module that:

- imports nothing: no functions, memories, tables or globals. Its output is a
  pure function of its bytes and the input;
- contains no floating point, neither `f32` or `f64` types nor instructions,
  because NaN bit patterns are not portable;
- uses no SIMD, relaxed SIMD, threads, memory64, multi-memory, custom page
  sizes or wide arithmetic, and has no start function.

These proposals are allowed: mutable-globals, sign-extension, multi-value,
bulk-memory, reference-types, tail-call and extended-const. Saturating
float-to-int is enabled but unusable without floats.

Compilation is eager, so all validation happens at load and none during a
call. Load also instantiates the module once and calls `mycel_abi_version()`.

## Exports

| Export | Type | Required |
|---|---|---|
| `memory` | memory, 32-bit, initial size at most the memory limit | yes |
| `mycel_abi_version` | `() -> i32`, must return `2` | yes |
| `mycel_alloc` | `(len: i32) -> i32` | yes |
| `mycel_validate` | `(ptr: i32, len: i32) -> i64` | yes |
| `mycel_reduce` | `(ptr: i32, len: i32) -> i64` | no |

Other exports, such as `__data_end` and `__heap_base`, are ignored.

## Calling convention

Every call runs on a fresh instance with a fresh fuel budget. Nothing survives
between calls, so a verdict never depends on call history.

1. The host encodes the input with postcard: a `RuleInput` for validate, a
   `ReduceInput` for reduce.
2. The host calls `mycel_alloc(len)` and writes the input at the pointer it
   returns.
3. The host calls `mycel_validate(ptr, len)` or `mycel_reduce(ptr, len)`.

The fuel budget covers `mycel_alloc` plus the entry point. Growing memory past
the limit fails: `memory.grow` returns `-1`.

Three things can go wrong before the entry point returns:

- A trap during instantiation, `mycel_alloc` or the entry point gives
  `Reject(Trap)`.
- A pointer from `mycel_alloc` that leaves no room for the input in memory
  gives `Reject(BadAbi)`.
- An input larger than the memory limit gives `Reject(Trap)` without calling
  the guest.

### Input encoding

Both inputs are postcard encodings of types in `mycel-rules-abi`:

```text
RuleInput {
  author:      [u8; 32]   // 32 raw bytes: the author's device key
  author_role: RoleTag    // 1 byte: Relay=0, Reader=1, Writer=2, Admin=3
  stream:      StreamTag  // kind: 1 byte (Doc=0, Feed=1), then id: 16 raw bytes
  payload:     bytes      // varint length, then the decrypted entry or action
  context:     bytes      // varint length, then host-supplied facts
}

ReduceInput {
  input: RuleInput        // the action is input.payload
  state: bytes            // varint length, then the current state
}
```

`payload`, `context` and `state` are app-defined. `context` may be empty. It
must be derived only from the entry's causal past.

### `mycel_validate` result

The `i64` result decodes to exactly one verdict:

| Value | Verdict |
|---|---|
| `0` | `Accept` |
| `(1 << 32) \| code`, with `code` a `u32` | `Reject(Rule(code))` |
| anything else | `Reject(BadAbi)` |

### `mycel_reduce` result

The `i64` result is `(ptr << 32) | len`, both `u32`. It locates a postcard
`ReduceOutput` in guest memory:

| Variant | Contents | Meaning |
|---|---|---|
| 0 | `Accept { state: bytes }` | The action is valid; `state` is the new state. |
| 1 | `Reject { code: u32 }` | The action is rejected with an app-defined code. |

Bytes that are out of bounds, or that do not decode exactly with no trailing
bytes, give `Reject(BadAbi)`. Reducing with a bundle that has no
`mycel_reduce` gives `NoReducer` without running anything.

### Verdicts

```text
Verdict = Accept | Reject(Reason)

Reason  = Rule(u32)   // the rules rejected it with an app-defined code
        | Trap        // out of fuel, memory limit, stack overflow,
                      // unreachable or panic, out-of-bounds access
        | BadAbi      // the guest broke this ABI
        | NoReducer   // reduce on a bundle without mycel_reduce
```

Every trap collapses to `Trap`, so peers agree even where trap details differ.

## Host API

The host crate is `mycel-rules`.

```rust
impl RulesHash {
    pub fn of(wasm: &[u8]) -> RulesHash;
}

impl RulesModule {
    pub fn load(wasm: &[u8]) -> Result<RulesModule, LoadError>;
    pub fn load_with_limits(wasm: &[u8], limits: Limits) -> Result<RulesModule, LoadError>;
    pub fn load_pinned(wasm: &[u8], expected: RulesHash) -> Result<RulesModule, LoadError>;
    pub fn hash(&self) -> RulesHash;
    pub fn limits(&self) -> Limits;
    pub fn has_reducer(&self) -> bool;
}

impl RulesEngine {
    pub fn new(module: RulesModule) -> RulesEngine;
    pub fn load(wasm: &[u8]) -> Result<RulesEngine, LoadError>;
    pub fn module(&self) -> &RulesModule;
    pub fn hash(&self) -> RulesHash;
    pub fn validate(&self, input: &RuleInput) -> Verdict;
    pub fn validate_traced(&self, input: &RuleInput) -> Trace<Verdict>;
    pub fn reduce(&self, input: &RuleInput, state: &[u8]) -> Result<Vec<u8>, Reason>;
    pub fn reduce_traced(&self, input: &RuleInput, state: &[u8]) -> Trace<Result<Vec<u8>, Reason>>;
}

pub struct Trace<T> {
    pub result: T,
    pub fuel_used: u64,
    pub detail: Option<String>,
}
```

`load` uses `Limits::V1`. `load_pinned` also refuses bytes whose hash is not
the expected one. A `RulesEngine` is cheap to clone and is `Send + Sync`.

The traced calls add `fuel_used` and, for `Trap` and `BadAbi`, a
human-readable `detail`. Both are for logs and tuning, not for consensus.

Loading fails with one of these `LoadError` variants:

| Variant | Cause |
|---|---|
| `TooLarge` | The bundle is bigger than the module size limit. |
| `HashMismatch` | The bytes do not have the pinned hash. |
| `Invalid` | Not valid wasm under the allowed features. Any use of floats ends here. |
| `ForbiddenImport` | The module imports something. |
| `MissingExport` | A required export is absent. |
| `BadExportType` | An export has the wrong type. |
| `MemoryTooLarge` | The initial memory exceeds the memory limit. |
| `Instantiate` | The trial instantiation, or the version call, failed. |
| `AbiVersion` | `mycel_abi_version()` did not return the host's version. |

## Writing rules

The guest SDK is the crate `mycel-rules-guest`, in `rules/mycel-rules-guest`.
A bundle is a `cdylib` crate that registers its entry points with the `rules!`
macro:

```rust
#![no_std]
use mycel_rules_guest::{RuleInput, Verdict};

fn validate(input: RuleInput) -> Verdict {
    if input.author_role.can_write() { Verdict::Accept } else { Verdict::reject(1) }
}

mycel_rules_guest::rules!(validate = validate);
```

A bundle with a reducer registers both:

```rust
// fn reduce(input: RuleInput, state: &[u8]) -> Result<Vec<u8>, u32>
mycel_rules_guest::rules!(validate = validate, reduce = reduce);
```

The reducer gets the action in `input.payload` and the current state. It
returns the new state, or a reject code.

The SDK provides the exports, a bump allocator and a panic handler that traps.
The allocator does not reclaim memory in general, which is enough because
every instance is discarded after one call. Rules must not use `f32` or `f64`.

### Building

```sh
rules/build.sh
```

`rules/` is a Cargo workspace of its own, so wasm builds never touch the main
workspace. The script builds `chat-rules` and `counter-rules` for
`wasm32-unknown-unknown` in release mode and copies `chat_rules.wasm` and
`counter_rules.wasm` into `crates/mycel-rules/fixtures/`, where the host's
tests and the runtime read them. It needs the `wasm32-unknown-unknown` target,
which `rust-toolchain.toml` lists.

The release profile in `rules/Cargo.toml` sets `opt-level = "z"`, LTO, one
codegen unit, `panic = "abort"` and `strip`. `rules/.cargo/config.toml` links
with a 128 KiB shadow stack in place of the default 1 MiB. The host zeroes the
whole initial memory on every call, so a small initial memory makes calls
cheaper. The stack sits first in memory, so an overflow traps instead of
corrupting data.

Builds are byte-for-byte reproducible with the same rustc, so pin the
toolchain when publishing a bundle hash.

## Example bundles

`rules/chat-rules` is the bundle the runtime uses, about 14 KB of wasm. It is
described below.

`rules/counter-rules`, about 7 KB, is a shared counter that exercises
`mycel_reduce`. Its action is a postcard `CounterOp` and its state a postcard
`u64`. `Add(n)` needs the Writer role, `Reset` needs Admin, and an overflow is
rejected.

### Chat rules

The payload is a postcard `ChatOp`, byte-identical to
`mycel_kit_chat::ChatOp`; the test `chat_wire_format_matches_mycel_kit_chat`
checks that. `context` is unused. A payload must decode exactly, with no
trailing bytes, and an op is only valid on a Feed stream.

| Op | Role needed | Limits |
|---|---|---|
| `Text` | Writer or above | body at most 16 KiB; at most 10 attachments; attachment name and MIME type at most 256 bytes each |
| `Edit` | Writer or above | body at most 16 KiB |
| `Delete` | Writer or above | none |
| `React` | Writer or above | emoji 1 to 32 bytes |
| `Receipt` | Reader or above | none |
| `Profile` | Writer or above | name at most 64 bytes |
| `Meta` | Admin | title at most 256 bytes |

The reject codes are in `mycel_rules_abi::chat::codes`:

| Code | Name | Meaning |
|---|---|---|
| 1 | `MALFORMED_PAYLOAD` | The payload is not a valid `ChatOp`, or has trailing bytes. |
| 2 | `WRONG_STREAM` | The stream is not a Feed. |
| 3 | `NOT_WRITER` | The op needs the Writer role. |
| 4 | `NOT_READER` | The op needs the Reader role. |
| 5 | `BODY_TOO_LONG` | The body is over 16 KiB. |
| 6 | `BAD_EMOJI` | The emoji is empty or over 32 bytes. |
| 7 | `NOT_ADMIN` | The op needs the Admin role. |
| 8 | `NAME_TOO_LONG` | The profile name or the title is too long. |
| 9 | `BAD_ATTACHMENT` | Too many attachments, or an attachment name or MIME type is too long. |

Author-only edit and delete is not a validator rule. The deterministic chat
reducer, `mycel_kit_chat::reduce`, enforces it over the causally ordered feed,
so validation needs no facts from other entries.

A maximum-size message, and a message with ten attachments whose names and
MIME types are at the limit, each use less than a tenth of the fuel budget.
The test `chat_fuel_is_well_within_budget` asserts this.

## How the runtime uses rules

The runtime runs rules on feed entries, after decryption:

```text
verify signature → resolve author → envelope validity → decrypt
    → FeedValidator (RulesEngine::validate) → apply
```

Envelope validity means the rules that can be checked without decrypting, in
section 7 of [TRUST.md](TRUST.md). Keepers cannot decrypt, so they enforce
header validity only. An entry the rules reject never enters the feed on any
peer. Its envelope stays stored and is skipped.

The runtime fills `RuleInput` like this:

| Field | Value |
|---|---|
| `author` | the author's device key |
| `author_role` | the author's role in `state(valid ∩ past(auth_heads))` |
| `stream` | the Feed kind and the feed's id |
| `payload` | the decrypted entry body |
| `context` | empty |

`author_role` comes from the same causal state that envelope validity uses,
never from the receiver's current view.

The runtime embeds one bundle, `crates/mycel-rules/fixtures/chat_rules.wasm`,
built from `rules/chat-rules`, and runs it on the chat feed of every space.
`mycel_node::chat_rules_hash()` gives its hash. Other streams are not checked
by rules. A space does not record which bundle it uses, so every peer must run
the same build.

The chat kit's reducer is native Rust (`mycel_kit_chat::reduce`) and folds
entries in the feed's deterministic order. `mycel_reduce` is part of the ABI
and is exercised by `rules/counter-rules` in tests only.

A malicious Writer can cost each peer at most one full fuel budget per entry.
