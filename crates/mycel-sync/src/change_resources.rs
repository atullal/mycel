//! Resource-only preflight for Automerge 0.12 change column encoding.
//!
//! Upstream's public Change parser expands RLE runs while verifying ops. These
//! private encodings come from storage/change.rs, storage/columns and columnar/
//! encoding/{rle,boolean}. Count runs without expanding them; leave operation
//! semantics, column relationships, actor indices and UTF-8 to Automerge.

use crate::{Result, SyncError};

/// Per-change resource budget. Logical expansion (RLE runs, group counts,
/// repeated strings) may grow with the encoded input — `ratio` times the
/// change body — but never below `floor` (so small, highly repetitive edits
/// such as deleting a long run still work) or above `cap`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// Serialized change after decompression, framing included.
    pub bytes: usize,
    /// Operations in one change.
    pub ops: usize,
    /// Logical column cells plus entries declared by group counts.
    pub values: Scaled,
    /// String bytes after expanding string-column runs.
    pub strings: Scaled,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Scaled {
    pub floor: usize,
    pub ratio: usize,
    pub cap: usize,
}

impl Scaled {
    fn limit(self, body: usize) -> usize {
        body.saturating_mul(self.ratio).clamp(self.floor, self.cap)
    }
}

/// What every replica accepts from the network (see the constants in lib.rs).
pub(crate) const READ: Limits = Limits {
    bytes: crate::MAX_DOC_CHANGE_BYTES,
    ops: crate::MAX_DOC_CHANGE_OPS,
    values: Scaled { floor: crate::MAX_DOC_COLUMN_VALUES / 4, ratio: 64, cap: crate::MAX_DOC_COLUMN_VALUES },
    strings: Scaled {
        floor: crate::MAX_DOC_COLUMN_STRING_BYTES / 4,
        ratio: 64,
        cap: crate::MAX_DOC_COLUMN_STRING_BYTES,
    },
};

/// What this replica writes into one change. Local edits beyond it are split
/// into several changes, each within the limits that every released version
/// accepts (the 2026-10-12 build rejected more than 65,536 operations, 1 MiB
/// expanded, 1,048,576 logical values or 1 MiB of expanded strings).
pub(crate) const WRITE: Limits = Limits {
    bytes: crate::MAX_LOCAL_CHANGE_BYTES,
    ops: crate::MAX_LOCAL_CHANGE_OPS,
    values: Scaled { floor: 1 << 20, ratio: 1, cap: 1 << 20 },
    strings: Scaled { floor: 1 << 20, ratio: 1, cap: 1 << 20 },
};

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn unsigned(&mut self) -> Result<u64> {
        leb128::read::unsigned(&mut self.0).map_err(|_| SyncError::Encoding)
    }

    fn signed(&mut self) -> Result<i64> {
        leb128::read::signed(&mut self.0).map_err(|_| SyncError::Encoding)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8]> {
        let length = usize::try_from(length).map_err(|_| SyncError::Encoding)?;
        let (head, tail) = self.0.split_at_checked(length).ok_or(SyncError::Encoding)?;
        self.0 = tail;
        Ok(head)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = self.unsigned()?;
        self.take(length)
    }
}

struct Budget {
    values: u64,
    strings: u64,
    max_values: usize,
    max_strings: usize,
}

impl Budget {
    fn new(limits: &Limits, body: usize) -> Self {
        Budget { values: 0, strings: 0, max_values: limits.values.limit(body), max_strings: limits.strings.limit(body) }
    }
}

fn charge(total: &mut u64, amount: u64, limit: usize) -> Result<()> {
    *total = total.checked_add(amount).ok_or(SyncError::TooLarge)?;
    if *total > limit as u64 { Err(SyncError::TooLarge) } else { Ok(()) }
}

pub(super) fn check(body: &[u8], limits: &Limits) -> Result<()> {
    let mut input = Input(body);
    let deps = input.unsigned()?.checked_mul(32).ok_or(SyncError::Encoding)?;
    input.take(deps)?;
    input.bytes()?; // author actor
    input.unsigned()?; // sequence
    input.unsigned()?; // start operation
    input.signed()?; // timestamp
    input.bytes()?; // commit message
    let actors = input.unsigned()?;
    for _ in 0..actors {
        input.bytes()?;
    }
    let columns = input.unsigned()?;
    // Every column descriptor consumes at least two bytes. Avoid allocating
    // from an untrusted declared count, even though the whole frame is capped.
    if columns > (input.0.len() / 2) as u64 {
        return Err(SyncError::Encoding);
    }
    let mut descriptors = Vec::new();
    let mut previous = None;
    for _ in 0..columns {
        let spec = u32::try_from(input.unsigned()?).map_err(|_| SyncError::Encoding)?;
        if spec & 8 != 0 || previous.is_some_and(|p| spec < p) {
            return Err(SyncError::Encoding); // compressed columns are forbidden in changes
        }
        previous = Some(spec);
        descriptors.push((spec, input.unsigned()?));
    }
    let mut budget = Budget::new(limits, body.len());
    for (spec, length) in descriptors {
        let bytes = input.take(length)?;
        let rows = check_column(spec & 7, bytes, &mut budget)?;
        if spec == 0x42 && rows > limits.ops as u64 {
            return Err(SyncError::TooLarge);
        }
    }
    // Remaining bytes are opaque change metadata, already covered by the
    // serialized frame limit. No operation decoding is performed here.
    Ok(())
}

fn check_column(kind: u32, bytes: &[u8], budget: &mut Budget) -> Result<u64> {
    if kind == 7 {
        return Ok(0);
    } // raw value bytes, no run encoding
    let mut input = Input(bytes);
    let mut rows = 0u64;
    while !input.0.is_empty() {
        if kind == 4 {
            // alternating Boolean runs
            let count = input.unsigned()?;
            charge(&mut rows, count, budget.max_values)?;
            charge(&mut budget.values, count, budget.max_values)?;
            continue;
        }
        let control = input.signed()?;
        let count = if control == 0 { input.unsigned()? } else { control.unsigned_abs() };
        charge(&mut rows, count, budget.max_values)?;
        charge(&mut budget.values, count, budget.max_values)?;
        if control > 0 {
            check_value(kind, &mut input, count, budget)?;
        } else if control < 0 {
            for _ in 0..count {
                check_value(kind, &mut input, 1, budget)?;
            }
        }
    }
    Ok(rows)
}

fn check_value(kind: u32, input: &mut Input<'_>, repeat: u64, budget: &mut Budget) -> Result<()> {
    match kind {
        0 => {
            // group counts can allocate predecessor vectors inside one op
            let count = input.unsigned()?.checked_mul(repeat).ok_or(SyncError::TooLarge)?;
            charge(&mut budget.values, count, budget.max_values)?;
        }
        3 => {
            input.signed()?;
        } // delta-encoded integers
        5 => {
            let bytes = input.bytes()?;
            let count = (bytes.len() as u64).checked_mul(repeat).ok_or(SyncError::TooLarge)?;
            charge(&mut budget.strings, count, budget.max_strings)?;
        }
        _ => {
            input.unsigned()?;
        } // actors, integers, value metadata
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget::new(&READ, usize::MAX)
    }

    #[test]
    fn budget_scales_with_input_between_floor_and_cap() {
        let values = READ.values;
        assert_eq!(values.limit(0), values.floor);
        assert_eq!(values.limit(values.floor / values.ratio + 1), values.floor + values.ratio);
        assert_eq!(values.limit(usize::MAX), values.cap);
    }

    #[test]
    fn boolean_column_budget_is_inclusive_and_shared() {
        let max = crate::MAX_DOC_COLUMN_VALUES;
        let mut bytes = Vec::new();
        leb128::write::unsigned(&mut bytes, max as u64).unwrap();
        let mut budget = budget();
        assert_eq!(check_column(4, &bytes, &mut budget).unwrap(), max as u64);
        assert!(matches!(check_column(4, &[1], &mut budget), Err(SyncError::TooLarge)));
    }

    #[test]
    fn extreme_signed_runs_and_group_multiplication_are_rejected() {
        let mut minimum = Vec::new();
        leb128::write::signed(&mut minimum, i64::MIN).unwrap();
        assert!(matches!(check_column(2, &minimum, &mut budget()), Err(SyncError::TooLarge)));
        let mut group = Vec::new();
        leb128::write::signed(&mut group, 2).unwrap();
        leb128::write::unsigned(&mut group, u64::MAX).unwrap();
        assert!(matches!(check_column(0, &group, &mut budget()), Err(SyncError::TooLarge)));
        let mut null = vec![0];
        leb128::write::unsigned(&mut null, u64::MAX).unwrap();
        assert!(matches!(check_column(2, &null, &mut budget()), Err(SyncError::TooLarge)));
    }
}
