//! Resource-only preflight for Automerge 0.12 change column encoding.
//!
//! Upstream's public Change parser expands RLE runs while verifying ops. These
//! private encodings come from storage/change.rs, storage/columns and columnar/
//! encoding/{rle,boolean}. Count runs without expanding them; leave operation
//! semantics, column relationships, actor indices and UTF-8 to Automerge.

use crate::{
    MAX_DOC_CHANGE_OPS, MAX_DOC_COLUMN_STRING_BYTES, MAX_DOC_COLUMN_VALUES, Result, SyncError,
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

#[derive(Default)]
struct Budget {
    values: u64,
    strings: u64,
}

fn charge(total: &mut u64, amount: u64, limit: usize) -> Result<()> {
    *total = total.checked_add(amount).ok_or(SyncError::TooLarge)?;
    if *total > limit as u64 {
        Err(SyncError::TooLarge)
    } else {
        Ok(())
    }
}

pub(super) fn check(body: &[u8]) -> Result<()> {
    let mut input = Input(body);
    let deps = input
        .unsigned()?
        .checked_mul(32)
        .ok_or(SyncError::Encoding)?;
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
    let mut budget = Budget::default();
    for (spec, length) in descriptors {
        let bytes = input.take(length)?;
        let rows = check_column(spec & 7, bytes, &mut budget)?;
        if spec == 0x42 && rows > MAX_DOC_CHANGE_OPS as u64 {
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
            charge(&mut rows, count, MAX_DOC_COLUMN_VALUES)?;
            charge(&mut budget.values, count, MAX_DOC_COLUMN_VALUES)?;
            continue;
        }
        let control = input.signed()?;
        let count = if control == 0 {
            input.unsigned()?
        } else {
            control.unsigned_abs()
        };
        charge(&mut rows, count, MAX_DOC_COLUMN_VALUES)?;
        charge(&mut budget.values, count, MAX_DOC_COLUMN_VALUES)?;
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
            let count = input
                .unsigned()?
                .checked_mul(repeat)
                .ok_or(SyncError::TooLarge)?;
            charge(&mut budget.values, count, MAX_DOC_COLUMN_VALUES)?;
        }
        3 => {
            input.signed()?;
        } // delta-encoded integers
        5 => {
            let bytes = input.bytes()?;
            let count = (bytes.len() as u64)
                .checked_mul(repeat)
                .ok_or(SyncError::TooLarge)?;
            charge(&mut budget.strings, count, MAX_DOC_COLUMN_STRING_BYTES)?;
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

    #[test]
    fn boolean_column_budget_is_inclusive_and_shared() {
        let mut bytes = Vec::new();
        leb128::write::unsigned(&mut bytes, MAX_DOC_COLUMN_VALUES as u64).unwrap();
        let mut budget = Budget::default();
        assert_eq!(
            check_column(4, &bytes, &mut budget).unwrap(),
            MAX_DOC_COLUMN_VALUES as u64
        );
        assert!(matches!(
            check_column(4, &[1], &mut budget),
            Err(SyncError::TooLarge)
        ));
    }

    #[test]
    fn extreme_signed_runs_and_group_multiplication_are_rejected() {
        let mut minimum = Vec::new();
        leb128::write::signed(&mut minimum, i64::MIN).unwrap();
        assert!(matches!(
            check_column(2, &minimum, &mut Budget::default()),
            Err(SyncError::TooLarge)
        ));
        let mut group = Vec::new();
        leb128::write::signed(&mut group, 2).unwrap();
        leb128::write::unsigned(&mut group, u64::MAX).unwrap();
        assert!(matches!(
            check_column(0, &group, &mut Budget::default()),
            Err(SyncError::TooLarge)
        ));
        let mut null = vec![0];
        leb128::write::unsigned(&mut null, u64::MAX).unwrap();
        assert!(matches!(
            check_column(2, &null, &mut Budget::default()),
            Err(SyncError::TooLarge)
        ));
    }
}
