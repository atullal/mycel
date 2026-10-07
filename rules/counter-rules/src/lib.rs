//! A shared counter driven by actions: a minimal example of the Actions + Reducers write model.
//!
//! - Action (payload): postcard(`CounterOp`).
//! - State: postcard(`u64`); empty state means 0.
//! - `Add(n)` requires Writer; `Reset` requires Admin; overflow is rejected.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use mycel_rules_guest::{RuleInput, Verdict, abi};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum CounterOp {
    Add(u32),
    Reset,
}

pub const MALFORMED: u32 = 1;
pub const NOT_WRITER: u32 = 2;
pub const NOT_ADMIN: u32 = 3;
pub const OVERFLOW: u32 = 4;
pub const BAD_STATE: u32 = 5;

mycel_rules_guest::rules!(validate = validate, reduce = reduce);

fn authorize(input: &RuleInput) -> Result<CounterOp, u32> {
    let op: CounterOp = abi::decode_exact(&input.payload).ok_or(MALFORMED)?;
    match op {
        CounterOp::Add(_) if !input.author_role.can_write() => Err(NOT_WRITER),
        CounterOp::Reset if !input.author_role.is_admin() => Err(NOT_ADMIN),
        op => Ok(op),
    }
}

pub fn validate(input: RuleInput) -> Verdict {
    match authorize(&input) {
        Ok(_) => Verdict::Accept,
        Err(code) => Verdict::reject(code),
    }
}

pub fn reduce(input: RuleInput, state: &[u8]) -> Result<Vec<u8>, u32> {
    let current: u64 = if state.is_empty() {
        0
    } else {
        abi::decode_exact(state).ok_or(BAD_STATE)?
    };
    let next = match authorize(&input)? {
        CounterOp::Add(n) => current.checked_add(u64::from(n)).ok_or(OVERFLOW)?,
        CounterOp::Reset => 0,
    };
    Ok(abi::encode(&next))
}
