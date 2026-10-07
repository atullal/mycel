//! Shared ABI types between the Mycel rules host ([`mycel-rules`]) and wasm rules guests.
//!
//! This crate is `no_std` + `alloc` so the same definitions compile into the host and into
//! `wasm32-unknown-unknown` guests. Every type here is encoded with [postcard] on the wire
//! between host and guest; the encoding of each type is part of the consensus ABI and must
//! not change without bumping [`ABI_VERSION`].
//!
//! See the `mycel-rules` crate docs for the full ABI specification (exports, calling
//! convention, return encodings).
//!
//! [`mycel-rules`]: ../mycel_rules/index.html
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[cfg(feature = "chat")]
pub mod chat;

#[doc(hidden)]
pub use serde_bytes;

/// The ABI version implemented by this crate. A guest's `mycel_abi_version()` export must
/// return exactly this value.
pub const ABI_VERSION: i32 = 1;

/// Export names (the complete guest interface).
pub mod exports {
    /// `memory`: the guest's (single, 32-bit) linear memory.
    pub const MEMORY: &str = "memory";
    /// `mycel_abi_version() -> i32`
    pub const ABI_VERSION: &str = "mycel_abi_version";
    /// `mycel_alloc(len: i32) -> i32`
    pub const ALLOC: &str = "mycel_alloc";
    /// `mycel_validate(ptr: i32, len: i32) -> i64`
    pub const VALIDATE: &str = "mycel_validate";
    /// `mycel_reduce(ptr: i32, len: i32) -> i64` (optional)
    pub const REDUCE: &str = "mycel_reduce";
}

/// The author's access level in the space, evaluated in the change's causal past.
/// Ordered: `Relay < Reader < Writer < Admin`. Postcard encodes it as one byte (0..=3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RoleTag {
    Relay = 0,
    Reader = 1,
    Writer = 2,
    Admin = 3,
}

impl RoleTag {
    pub fn can_read(self) -> bool {
        self >= RoleTag::Reader
    }
    pub fn can_write(self) -> bool {
        self >= RoleTag::Writer
    }
    pub fn is_admin(self) -> bool {
        self == RoleTag::Admin
    }
}

/// Which kind of stream a change belongs to. Postcard: one byte (0 = Doc, 1 = Feed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamKind {
    Doc = 0,
    Feed = 1,
}

/// The stream (doc or feed) a change targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamTag {
    pub kind: StreamKind,
    pub id: [u8; 16],
}

/// Input to `mycel_validate` (and, inside [`ReduceInput`], to `mycel_reduce`).
///
/// Postcard layout: `author` (32 raw bytes) ‖ `author_role` (1 byte) ‖ `stream.kind` (1 byte)
/// ‖ `stream.id` (16 raw bytes) ‖ `payload` (varint len ‖ bytes) ‖ `context` (varint len ‖ bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInput {
    /// The author's Agent key (Ed25519 public key bytes).
    pub author: [u8; 32],
    /// The author's role in the change's causal past.
    pub author_role: RoleTag,
    pub stream: StreamTag,
    /// The decrypted change / feed entry / action, app-defined encoding.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Host-supplied facts from the change's causal past that the rule needs
    /// (app-defined encoding; empty when unused). Must be derived only from the causal past.
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

/// Input to `mycel_reduce`: fold `input.payload` (the action) into `state`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReduceInput {
    pub input: RuleInput,
    #[serde(with = "serde_bytes")]
    pub state: Vec<u8>,
}

/// Output of `mycel_reduce`, written by the guest into its memory and located by the packed
/// `(ptr << 32) | len` return value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReduceOutput {
    /// Variant 0: the action is valid; this is the new state.
    Accept {
        #[serde(with = "serde_bytes")]
        state: Vec<u8>,
    },
    /// Variant 1: the action is rejected with an app-defined reason code.
    Reject { code: u32 },
}

/// Why a change was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Reason {
    /// The rules rejected it with an app-defined code.
    Rule(u32),
    /// The guest trapped: out of fuel, memory limit, stack overflow, `unreachable`, panic,
    /// out-of-bounds access... All traps collapse to this one value so every peer agrees.
    Trap,
    /// The guest violated the ABI (bad pointer/length, malformed return value or output).
    BadAbi,
    /// `reduce` was called but the module does not export `mycel_reduce`.
    NoReducer,
}

/// The accept/reject decision for a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Reject(Reason),
}

impl Verdict {
    /// Guest helper: reject with an app-defined code.
    pub const fn reject(code: u32) -> Self {
        Verdict::Reject(Reason::Rule(code))
    }
    pub fn is_accept(&self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

/// `mycel_validate` return value meaning "accept".
pub const VALIDATE_ACCEPT: i64 = 0;
/// High 32 bits of a `mycel_validate` return value meaning "reject with the code in the low 32 bits".
pub const VALIDATE_REJECT_TAG: i64 = 1;
/// Returned by guests that try to encode a host-only [`Reason`]; decodes as [`Reason::BadAbi`].
pub const VALIDATE_INVALID: i64 = -1;

/// Encode a guest's verdict as the `i64` returned by `mycel_validate`:
/// `Accept` → `0`; `Reject(Rule(c))` → `(1 << 32) | c`; anything else → `-1`.
pub const fn encode_validate(v: Verdict) -> i64 {
    match v {
        Verdict::Accept => VALIDATE_ACCEPT,
        Verdict::Reject(Reason::Rule(code)) => (VALIDATE_REJECT_TAG << 32) | code as i64,
        Verdict::Reject(_) => VALIDATE_INVALID,
    }
}

/// Decode a `mycel_validate` return value. Every `i64` maps to exactly one verdict; values that
/// are not produced by [`encode_validate`] for an `Accept`/`Rule` verdict are [`Reason::BadAbi`].
pub const fn decode_validate(ret: i64) -> Verdict {
    if ret == VALIDATE_ACCEPT {
        Verdict::Accept
    } else if (ret >> 32) == VALIDATE_REJECT_TAG {
        Verdict::Reject(Reason::Rule(ret as u32))
    } else {
        Verdict::Reject(Reason::BadAbi)
    }
}

/// Pack a guest pointer and length into the `i64` returned by `mycel_reduce`.
pub const fn pack_ptr_len(ptr: u32, len: u32) -> i64 {
    (((ptr as u64) << 32) | len as u64) as i64
}

/// Inverse of [`pack_ptr_len`].
pub const fn unpack_ptr_len(ret: i64) -> (u32, u32) {
    let bits = ret as u64;
    ((bits >> 32) as u32, bits as u32)
}

/// Strict postcard decode: the whole buffer must be consumed (no trailing bytes), so a
/// given byte string has at most one meaning.
pub fn decode_exact<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Option<T> {
    match postcard::take_from_bytes(bytes) {
        Ok((v, [])) => Some(v),
        _ => None,
    }
}

/// Postcard encode (infallible for the types in this crate).
pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).expect("postcard encoding into a Vec cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_encoding_roundtrip() {
        for v in [
            Verdict::Accept,
            Verdict::reject(0),
            Verdict::reject(7),
            Verdict::reject(u32::MAX),
        ] {
            assert_eq!(decode_validate(encode_validate(v)), v);
        }
        assert_eq!(
            encode_validate(Verdict::Reject(Reason::Trap)),
            VALIDATE_INVALID
        );
        for bad in [-1i64, 2 << 32, i64::MIN, i64::MAX, 1] {
            assert_eq!(
                decode_validate(bad),
                Verdict::Reject(Reason::BadAbi),
                "{bad}"
            );
        }
    }

    #[test]
    fn ptr_len_roundtrip() {
        for (p, l) in [(0, 0), (1, 2), (u32::MAX, u32::MAX), (0x8000_0000, 5)] {
            assert_eq!(unpack_ptr_len(pack_ptr_len(p, l)), (p, l));
        }
    }

    #[test]
    fn rule_input_layout() {
        let input = RuleInput {
            author: [7; 32],
            author_role: RoleTag::Writer,
            stream: StreamTag {
                kind: StreamKind::Feed,
                id: [9; 16],
            },
            payload: alloc::vec![1, 2, 3],
            context: alloc::vec![],
        };
        let bytes = encode(&input);
        let mut expected = alloc::vec![7u8; 32];
        expected.extend_from_slice(&[2, 1]);
        expected.extend_from_slice(&[9; 16]);
        expected.extend_from_slice(&[3, 1, 2, 3, 0]);
        assert_eq!(bytes, expected);
        assert_eq!(decode_exact::<RuleInput>(&bytes), Some(input));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_exact::<RuleInput>(&trailing), None);
    }
}
