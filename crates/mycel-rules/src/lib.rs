//! # mycel-rules: L4 deterministic rules runtime (host side)
//!
//! App rules (validators and action reducers) are written in Rust, compiled to
//! `wasm32-unknown-unknown`, and executed by every peer with the [`wasmi`] interpreter.
//! A Space pins the [`RulesHash`] of its rules bundle; every honest peer runs the identical
//! bytes, under identical limits, with no host imports, so every honest peer reaches the
//! same accept/reject decision for the same input (the "causal authorization" invariant
//! extended to app rules).
//!
//! ## Determinism measures
//!
//! - **No imports.** A rules module may not import anything (functions, memories, tables,
//!   globals). Its output is a pure function of its bytes and the input.
//! - **No floating point.** Modules containing `f32`/`f64` types or instructions are
//!   rejected at load (wasmi `Config::floats(false)`): NaN bit patterns are not portable.
//! - **No SIMD / relaxed SIMD / threads / memory64 / multi-memory / start function.**
//! - **Eager compilation**, so validation (and the float check) happens entirely at load.
//! - **Fuel**: each call gets a fixed budget ([`Limits::fuel`]); exhausting it traps.
//! - **Memory**: linear memory is capped ([`Limits::max_memory_bytes`]); `memory.grow`
//!   beyond the cap returns `-1` (guests typically then trap).
//! - **Fixed stack limits** (recursion depth, value stack) pinned in this crate.
//! - **Fresh instance per call.** Nothing survives between calls, so a verdict never depends
//!   on call history.
//! - **All traps collapse to [`Reason::Trap`]** (out-of-fuel, OOM, stack overflow,
//!   `unreachable`, out-of-bounds...), so peers agree even if trap details differ.
//! - `wasmi` is pinned to an exact version: its fuel cost model is part of consensus.
//!   [`Limits`] are part of consensus too; a Space should pin `(RulesHash, Limits)` (the
//!   defaults are [`Limits::V1`]).
//!
//! ## Guest ABI, version 1 (exact)
//!
//! A rules module is a wasm32 core module (MVP + mutable-globals, sign-extension,
//! saturating-float-to-int (unusable without floats), multi-value, bulk-memory,
//! reference-types, tail-call, extended-const). It has **no imports** and **no start
//! function**, and exports:
//!
//! | export | type | required |
//! |---|---|---|
//! | `memory` | memory, 32-bit, initial size ≤ `Limits::max_memory_bytes` | yes |
//! | `mycel_abi_version` | `() -> i32`, must return `1` | yes |
//! | `mycel_alloc` | `(len: i32) -> i32` | yes |
//! | `mycel_validate` | `(ptr: i32, len: i32) -> i64` | yes |
//! | `mycel_reduce` | `(ptr: i32, len: i32) -> i64` | no |
//!
//! Other exports are ignored. At load the host instantiates the module once and checks
//! `mycel_abi_version() == 1`.
//!
//! **Calling convention** (per call, on a fresh instance with a fresh fuel budget):
//! 1. The host encodes the input with postcard (`RuleInput` for validate, `ReduceInput` for
//!    reduce; layouts in [`mycel_rules_abi`]).
//! 2. The host calls `mycel_alloc(len)`; the guest returns a pointer to `len` writable bytes.
//!    The host writes the input there (out-of-bounds → [`Reason::BadAbi`]).
//! 3. The host calls `mycel_validate(ptr, len)` or `mycel_reduce(ptr, len)`.
//!
//! **`mycel_validate` result** (an `i64`, see [`mycel_rules_abi::decode_validate`]):
//! - `0` → [`Verdict::Accept`]
//! - `(1 << 32) | code` (`code: u32`) → `Verdict::Reject(Reason::Rule(code))`
//! - any other value → `Verdict::Reject(Reason::BadAbi)`
//!
//! **`mycel_reduce` result**: an `i64` packing `(ptr << 32) | len` (both `u32`) that locates,
//! in guest memory, a postcard-encoded [`ReduceOutput`]:
//! variant 0 `Accept { state: Vec<u8> }` or variant 1 `Reject { code: u32 }`. The bytes must
//! be in bounds and decode exactly (no trailing bytes); otherwise [`Reason::BadAbi`].
//!
//! Any trap during instantiation, `mycel_alloc`, `mycel_validate` or `mycel_reduce` gives
//! `Reject(Reason::Trap)`. An input larger than the memory cap is `Reject(Reason::Trap)`
//! without calling the guest (it could never be allocated).
//!
//! The `mycel-rules-guest` crate (in the separate `rules/` workspace) implements this ABI so
//! app authors only write `fn validate(input: RuleInput) -> Verdict`.

use std::fmt;

use mycel_rules_abi::{self as abi, ABI_VERSION, exports};
use serde::{Deserialize, Serialize};
use wasmi::{
    CompilationMode, Config, EnforcedLimits, Engine, ExternType, Instance, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc, ValType,
};

pub use mycel_rules_abi as abi_types;
pub use mycel_rules_abi::{Reason, ReduceInput, ReduceOutput, RoleTag, RuleInput, StreamKind, StreamTag, Verdict};

#[cfg(test)]
mod tests;

/// BLAKE3 key-derivation context for [`RulesHash`].
pub const RULES_HASH_CONTEXT: &str = "mycel/v0/rules-bundle";

// Pinned interpreter stack limits (part of consensus: exceeding them traps).
const MAX_RECURSION_DEPTH: usize = 1000;
const MAX_VALUE_STACK_BYTES: usize = 1_000_000;
const MAX_TABLE_ELEMENTS: usize = 10_000;

// ───────────────────────────── hash ─────────────────────────────

/// Identity of a rules bundle: `BLAKE3::derive_key("mycel/v0/rules-bundle", wasm_bytes)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RulesHash(pub [u8; 32]);

impl RulesHash {
    pub fn of(wasm: &[u8]) -> Self {
        RulesHash(blake3::derive_key(RULES_HASH_CONTEXT, wasm))
    }
}

impl fmt::Display for RulesHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for RulesHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string();
        write!(f, "RulesHash({})", &s[..12])
    }
}

// ───────────────────────────── limits ─────────────────────────────

/// Resource limits. These are consensus parameters: peers using different limits can reach
/// different verdicts for the same input near the limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Limits {
    /// Fuel per call (roughly one unit per executed wasm instruction, wasmi cost model).
    /// Covers `mycel_alloc` plus `mycel_validate`/`mycel_reduce`.
    pub fuel: u64,
    /// Maximum linear memory size in bytes.
    pub max_memory_bytes: usize,
    /// Maximum size of the wasm bundle in bytes.
    pub max_module_bytes: usize,
}

impl Limits {
    /// The default limits for ABI v1.
    pub const V1: Limits =
        Limits { fuel: 20_000_000, max_memory_bytes: 16 * 1024 * 1024, max_module_bytes: 4 * 1024 * 1024 };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::V1
    }
}

// ───────────────────────────── errors ─────────────────────────────

/// Why a rules bundle was refused at load time. A refused bundle is never executed; a peer
/// that cannot load a Space's pinned bundle should treat the Space as read-only.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("rules bundle is {size} bytes, limit is {limit}")]
    TooLarge { size: usize, limit: usize },
    #[error("rules bundle hash {actual} does not match pinned {expected}")]
    HashMismatch { expected: RulesHash, actual: RulesHash },
    /// Not valid wasm under the deterministic feature set (includes any float usage).
    #[error("invalid or non-deterministic wasm: {0}")]
    Invalid(String),
    #[error("rules modules may not import anything (found {module}::{name})")]
    ForbiddenImport { module: String, name: String },
    #[error("missing required export `{0}`")]
    MissingExport(&'static str),
    #[error("export `{0}` has the wrong type")]
    BadExportType(&'static str),
    #[error("initial memory of {bytes} bytes exceeds the limit of {limit}")]
    MemoryTooLarge { bytes: u64, limit: usize },
    #[error("instantiation failed: {0}")]
    Instantiate(String),
    #[error("module implements ABI version {found}, host implements {expected}")]
    AbiVersion { found: i32, expected: i32 },
}

// ───────────────────────────── module ─────────────────────────────

/// A validated, compiled rules bundle.
#[derive(Clone)]
pub struct RulesModule {
    engine: Engine,
    module: Module,
    hash: RulesHash,
    limits: Limits,
    has_reducer: bool,
}

impl fmt::Debug for RulesModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulesModule")
            .field("hash", &self.hash)
            .field("limits", &self.limits)
            .field("has_reducer", &self.has_reducer)
            .finish()
    }
}

fn engine_config() -> Config {
    let mut c = Config::default();
    c.consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .floats(false)
        .wasm_multi_memory(false)
        .wasm_custom_page_sizes(false)
        .wasm_wide_arithmetic(false)
        .allow_start_fn(false)
        .ignore_custom_sections(true)
        .set_max_recursion_depth(MAX_RECURSION_DEPTH)
        .set_max_stack_height(MAX_VALUE_STACK_BYTES)
        .enforced_limits(EnforcedLimits::strict());
    c
}

fn check_func(
    module: &Module,
    name: &'static str,
    params: &[ValType],
    results: &[ValType],
    required: bool,
) -> Result<bool, LoadError> {
    match module.get_export(name) {
        None if required => Err(LoadError::MissingExport(name)),
        None => Ok(false),
        Some(ExternType::Func(ft)) if ft.params() == params && ft.results() == results => Ok(true),
        Some(_) => Err(LoadError::BadExportType(name)),
    }
}

impl RulesModule {
    /// Validate and compile a rules bundle with the default [`Limits`].
    pub fn load(wasm: &[u8]) -> Result<Self, LoadError> {
        Self::load_with_limits(wasm, Limits::default())
    }

    /// Like [`load`](Self::load), but refuse bytes whose hash is not `expected`.
    pub fn load_pinned(wasm: &[u8], expected: RulesHash) -> Result<Self, LoadError> {
        let actual = RulesHash::of(wasm);
        if actual != expected {
            return Err(LoadError::HashMismatch { expected, actual });
        }
        Self::load(wasm)
    }

    /// Validate and compile a rules bundle with explicit limits.
    pub fn load_with_limits(wasm: &[u8], limits: Limits) -> Result<Self, LoadError> {
        if wasm.len() > limits.max_module_bytes {
            return Err(LoadError::TooLarge { size: wasm.len(), limit: limits.max_module_bytes });
        }
        let hash = RulesHash::of(wasm);
        let engine = Engine::new(&engine_config());
        let module = Module::new(&engine, wasm).map_err(|e| LoadError::Invalid(e.to_string()))?;

        if let Some(import) = module.imports().next() {
            return Err(LoadError::ForbiddenImport {
                module: import.module().to_owned(),
                name: import.name().to_owned(),
            });
        }
        match module.get_export(exports::MEMORY) {
            Some(ExternType::Memory(mt)) if !mt.is_64() => {
                let bytes = mt.minimum().saturating_mul(65536); // custom page sizes are disabled
                if bytes > limits.max_memory_bytes as u64 {
                    return Err(LoadError::MemoryTooLarge { bytes, limit: limits.max_memory_bytes });
                }
            }
            Some(_) => return Err(LoadError::BadExportType(exports::MEMORY)),
            None => return Err(LoadError::MissingExport(exports::MEMORY)),
        }
        use ValType::{I32, I64};
        check_func(&module, exports::ABI_VERSION, &[], &[I32], true)?;
        check_func(&module, exports::ALLOC, &[I32], &[I32], true)?;
        check_func(&module, exports::VALIDATE, &[I32, I32], &[I64], true)?;
        let has_reducer = check_func(&module, exports::REDUCE, &[I32, I32], &[I64], false)?;

        let this = RulesModule { engine, module, hash, limits, has_reducer };
        // Trial instantiation: catches data segments that don't fit, memory over the cap, etc.
        let (mut store, instance) = this.instantiate().map_err(|e| LoadError::Instantiate(e.to_string()))?;
        let found = instance
            .get_typed_func::<(), i32>(&store, exports::ABI_VERSION)
            .and_then(|f| f.call(&mut store, ()))
            .map_err(|e| LoadError::Instantiate(e.to_string()))?;
        if found != ABI_VERSION {
            return Err(LoadError::AbiVersion { found, expected: ABI_VERSION });
        }
        Ok(this)
    }

    pub fn hash(&self) -> RulesHash {
        self.hash
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Whether the bundle exports `mycel_reduce`.
    pub fn has_reducer(&self) -> bool {
        self.has_reducer
    }

    fn instantiate(&self) -> Result<(Store<StoreLimits>, Instance), wasmi::Error> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_bytes)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(1)
            .memories(1)
            .tables(16)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        store.set_fuel(self.limits.fuel)?;
        let instance = Instance::new(&mut store, &self.module, &[])?;
        Ok((store, instance))
    }
}

// ───────────────────────────── engine ─────────────────────────────

/// Executes a [`RulesModule`]. Cheap to clone; `Send + Sync`.
#[derive(Clone, Debug)]
pub struct RulesEngine {
    module: RulesModule,
}

/// Diagnostics for one call. Only `verdict`/`result` is consensus-relevant; `fuel_used`
/// and `detail` are for logging and tuning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace<T> {
    pub result: T,
    pub fuel_used: u64,
    /// Human-readable cause for `Trap` / `BadAbi` outcomes.
    pub detail: Option<String>,
}

enum Fail {
    Trap(String),
    BadAbi(String),
}

impl Fail {
    fn reason(&self) -> Reason {
        match self {
            Fail::Trap(_) => Reason::Trap,
            Fail::BadAbi(_) => Reason::BadAbi,
        }
    }
    fn detail(self) -> Option<String> {
        match self {
            Fail::Trap(d) | Fail::BadAbi(d) => Some(d),
        }
    }
}

fn trap(e: wasmi::Error) -> Fail {
    Fail::Trap(e.to_string())
}

/// A fresh instance plus everything a call needs.
struct Call {
    store: Store<StoreLimits>,
    instance: Instance,
    memory: Memory,
}

impl RulesEngine {
    pub fn new(module: RulesModule) -> Self {
        RulesEngine { module }
    }

    /// Shortcut for `RulesEngine::new(RulesModule::load(wasm)?)`.
    pub fn load(wasm: &[u8]) -> Result<Self, LoadError> {
        Ok(Self::new(RulesModule::load(wasm)?))
    }

    pub fn module(&self) -> &RulesModule {
        &self.module
    }

    pub fn hash(&self) -> RulesHash {
        self.module.hash
    }

    /// Run `mycel_validate` on a fresh instance.
    pub fn validate(&self, input: &RuleInput) -> Verdict {
        self.validate_traced(input).result
    }

    /// [`validate`](Self::validate) plus diagnostics.
    pub fn validate_traced(&self, input: &RuleInput) -> Trace<Verdict> {
        let bytes = abi::encode(input);
        let (res, fuel_used) = self.run(&bytes, |call, ptr, len| {
            let f: TypedFunc<(i32, i32), i64> = call
                .instance
                .get_typed_func(&call.store, exports::VALIDATE)
                .map_err(|e| Fail::BadAbi(e.to_string()))?;
            let ret = f.call(&mut call.store, (ptr, len)).map_err(trap)?;
            match abi::decode_validate(ret) {
                Verdict::Reject(Reason::BadAbi) => {
                    Err(Fail::BadAbi(format!("invalid mycel_validate return value {ret:#x}")))
                }
                v => Ok(v),
            }
        });
        match res {
            Ok(v) => Trace { result: v, fuel_used, detail: None },
            Err(f) => Trace { result: Verdict::Reject(f.reason()), fuel_used, detail: f.detail() },
        }
    }

    /// Run `mycel_reduce`: fold the action in `input.payload` into `state`.
    /// Returns the new state, or why the action was rejected.
    pub fn reduce(&self, input: &RuleInput, state: &[u8]) -> Result<Vec<u8>, Reason> {
        self.reduce_traced(input, state).result
    }

    /// [`reduce`](Self::reduce) plus diagnostics.
    pub fn reduce_traced(&self, input: &RuleInput, state: &[u8]) -> Trace<Result<Vec<u8>, Reason>> {
        if !self.module.has_reducer {
            return Trace { result: Err(Reason::NoReducer), fuel_used: 0, detail: None };
        }
        // Same postcard bytes as `ReduceInput { input: input.clone(), state: state.to_vec() }`.
        #[derive(Serialize)]
        struct ReduceInputRef<'a> {
            input: &'a RuleInput,
            #[serde(with = "mycel_rules_abi::serde_bytes")]
            state: &'a [u8],
        }
        let bytes = abi::encode(&ReduceInputRef { input, state });
        let (res, fuel_used) = self.run(&bytes, |call, ptr, len| {
            let f: TypedFunc<(i32, i32), i64> =
                call.instance.get_typed_func(&call.store, exports::REDUCE).map_err(|e| Fail::BadAbi(e.to_string()))?;
            let ret = f.call(&mut call.store, (ptr, len)).map_err(trap)?;
            let (out_ptr, out_len) = abi::unpack_ptr_len(ret);
            let data = call.memory.data(&call.store);
            let out = (out_ptr as usize)
                .checked_add(out_len as usize)
                .and_then(|end| data.get(out_ptr as usize..end))
                .ok_or_else(|| Fail::BadAbi(format!("reduce output {out_ptr:#x}+{out_len} out of bounds")))?;
            match abi::decode_exact::<ReduceOutput>(out) {
                Some(ReduceOutput::Accept { state }) => Ok(Ok(state)),
                Some(ReduceOutput::Reject { code }) => Ok(Err(Reason::Rule(code))),
                None => Err(Fail::BadAbi("malformed ReduceOutput".into())),
            }
        });
        match res {
            Ok(r) => Trace { result: r, fuel_used, detail: None },
            Err(f) => Trace { result: Err(f.reason()), fuel_used, detail: f.detail() },
        }
    }

    /// Instantiate, copy `input` into guest memory via `mycel_alloc`, then run `f`.
    fn run<R>(&self, input: &[u8], f: impl FnOnce(&mut Call, i32, i32) -> Result<R, Fail>) -> (Result<R, Fail>, u64) {
        let limits = self.module.limits;
        let mut store_out = None;
        let res = (|| {
            if input.len() > limits.max_memory_bytes || input.len() > i32::MAX as usize {
                return Err(Fail::Trap(format!("input of {} bytes exceeds memory cap", input.len())));
            }
            let (store, instance) = self.module.instantiate().map_err(trap)?;
            let memory =
                instance.get_memory(&store, exports::MEMORY).ok_or_else(|| Fail::BadAbi("no memory".into()))?;
            let mut call = Call { store, instance, memory };
            let len = input.len() as i32; // checked above
            let alloc: TypedFunc<i32, i32> =
                call.instance.get_typed_func(&call.store, exports::ALLOC).map_err(|e| Fail::BadAbi(e.to_string()))?;
            let alloc_res = alloc.call(&mut call.store, len);
            let r = match alloc_res {
                Err(e) => Err(trap(e)),
                Ok(ptr) => match call.memory.write(&mut call.store, ptr as u32 as usize, input) {
                    Err(_) => Err(Fail::BadAbi(format!(
                        "mycel_alloc returned {:#x}, out of bounds for {} bytes",
                        ptr as u32,
                        input.len()
                    ))),
                    Ok(()) => f(&mut call, ptr, len),
                },
            };
            store_out = Some(call.store);
            r
        })();
        let fuel_used = store_out.and_then(|s| s.get_fuel().ok()).map_or(0, |left| limits.fuel - left);
        (res, fuel_used)
    }
}
