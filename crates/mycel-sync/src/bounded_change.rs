//! Resource gate for the Automerge 0.12 change framing. Its public Change
//! loader has no expansion limit and dispatches document/bundle parsers too.
//! This gate checks framing and logical column resource budgets; Automerge
//! still parses and verifies change semantics. Change columns cannot themselves
//! be compressed in 0.12.

use std::borrow::Cow;

use automerge::Change;
use flate2::{Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};

use crate::change_resources::{Limits, READ};
use crate::{Result, SyncError};

// Automerge 0.12 storage::{MAGIC_BYTES, chunk::ChunkType}. These framing
// definitions are private upstream; keep compatibility covered by roundtrips.
const MAGIC: [u8; 4] = [0x85, 0x6f, 0x4a, 0x83];
const CHANGE: u8 = 1;
const COMPRESSED_CHANGE: u8 = 2;

/// Parse a change received from anyone, within the network-wide limits.
pub(super) fn parse(bytes: &[u8]) -> Result<Change> {
    let raw = preflight(bytes, &READ)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Change::try_from(raw.as_ref())))
        .map_err(|_| SyncError::Encoding)?
        .map_err(|_| SyncError::Encoding)
}

/// Check a locally produced change against `limits` without parsing its ops.
pub(super) fn within(bytes: &[u8], limits: &Limits) -> Result<()> {
    preflight(bytes, limits).map(|_| ())
}

fn preflight<'a>(bytes: &'a [u8], limits: &Limits) -> Result<Cow<'a, [u8]>> {
    let raw = uncompressed_frame(bytes, limits.bytes)?;
    // The Automerge checksum is SHA-256(type || canonical ULEB length || body).
    // Check it before the upstream parser, which does not validate it itself.
    if Sha256::digest(&raw[8..])[..4] != raw[4..8] {
        return Err(SyncError::Encoding);
    }
    let mut body = &raw[9..];
    leb128::read::unsigned(&mut body).map_err(|_| SyncError::Encoding)?;
    crate::change_resources::check(body, limits)?;
    Ok(raw)
}

fn uncompressed_frame(bytes: &[u8], max: usize) -> Result<Cow<'_, [u8]>> {
    if bytes.len() > max {
        return Err(SyncError::TooLarge);
    }
    if bytes.len() < 10 || bytes[..4] != MAGIC {
        return Err(SyncError::Encoding);
    }
    // Reject Document (0), Bundle (3), and unknown types before any body parser
    // or inflater can run.
    if !matches!(bytes[8], CHANGE | COMPRESSED_CHANGE) {
        return Err(SyncError::Encoding);
    }
    let mut body = &bytes[9..];
    let declared = leb128::read::unsigned(&mut body).map_err(|_| SyncError::Encoding)?;
    let mut length = Vec::new();
    leb128::write::unsigned(&mut length, declared).map_err(|_| SyncError::Encoding)?;
    let header_len = bytes.len() - body.len();
    if bytes[9..header_len] != length || usize::try_from(declared).ok() != Some(body.len()) {
        return Err(SyncError::Encoding);
    }
    if bytes[8] == CHANGE {
        return Ok(Cow::Borrowed(bytes));
    }

    let expanded = inflate_bounded(body, max)?;
    let mut raw = Vec::with_capacity(12 + expanded.len());
    raw.extend_from_slice(&bytes[..8]);
    raw.push(CHANGE);
    leb128::write::unsigned(&mut raw, expanded.len() as u64).map_err(|_| SyncError::Encoding)?;
    if raw.len() + expanded.len() > max {
        return Err(SyncError::TooLarge);
    }
    raw.extend_from_slice(&expanded);
    Ok(Cow::Owned(raw))
}

fn inflate_bounded(compressed: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut decoder = Decompress::new(false); // Automerge uses raw DEFLATE.
    let mut output = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let before_in = decoder.total_in() as usize;
        let before_out = decoder.total_out() as usize;
        let available = scratch.len().min(max + 1 - output.len());
        let status = decoder
            .decompress(&compressed[before_in..], &mut scratch[..available], FlushDecompress::None)
            .map_err(|_| SyncError::Encoding)?;
        let produced = decoder.total_out() as usize - before_out;
        output.extend_from_slice(&scratch[..produced]);
        if output.len() > max {
            return Err(SyncError::TooLarge);
        }
        if status == Status::StreamEnd {
            // A second stream or bytes hidden after the DEFLATE terminator are
            // not part of a single Automerge change.
            return if decoder.total_in() as usize == compressed.len() { Ok(output) } else { Err(SyncError::Encoding) };
        }
        if decoder.total_in() as usize == before_in && produced == 0 {
            return Err(SyncError::Encoding); // truncated or stalled stream
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_DOC_CHANGE_BYTES;
    use automerge::{AutoCommit, ROOT, transaction::Transactable};
    use std::io::Write;

    fn change() -> Change {
        let mut doc = AutoCommit::new();
        doc.put(ROOT, "value", "abc".repeat(1000)).unwrap();
        doc.commit();
        doc.get_last_local_change().unwrap()
    }

    fn frame(kind: u8, checksum: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(checksum);
        bytes.push(kind);
        leb128::write::unsigned(&mut bytes, body.len() as u64).unwrap();
        bytes.extend_from_slice(body);
        bytes
    }

    fn body(bytes: &[u8]) -> &[u8] {
        let mut rest = &bytes[9..];
        leb128::read::unsigned(&mut rest).unwrap();
        rest
    }

    #[test]
    fn upstream_compressed_and_plain_changes_roundtrip() {
        let mut original = change();
        let plain = original.raw_bytes().to_vec();
        let compressed = original.bytes().to_vec();
        assert_eq!(plain[8], CHANGE);
        assert_eq!(compressed[8], COMPRESSED_CHANGE);
        for bytes in [plain, compressed] {
            let parsed = parse(&bytes).unwrap();
            assert_eq!(parsed.hash(), original.hash());
            assert_eq!(parsed.raw_bytes(), original.raw_bytes());
        }
    }

    #[test]
    fn framing_rejects_other_chunk_types_and_malformed_headers() {
        let plain = change().raw_bytes().to_vec();
        for kind in [0, 3, 4, 255] {
            let mut bytes = plain.clone();
            bytes[8] = kind;
            assert!(matches!(parse(&bytes), Err(SyncError::Encoding)));
        }
        for len in 0..10 {
            assert!(parse(&plain[..len]).is_err());
        }
        let mut bad_magic = plain.clone();
        bad_magic[0] ^= 1;
        let mut bad_checksum = plain.clone();
        bad_checksum[4] ^= 1;
        let mut overflow = plain[..9].to_vec();
        overflow.extend_from_slice(&[0xff; 10]);
        let mut unterminated = plain[..9].to_vec();
        unterminated.push(0x80);
        let mut noncanonical = plain[..9].to_vec();
        let mut encoded_len = Vec::new();
        leb128::write::unsigned(&mut encoded_len, body(&plain).len() as u64).unwrap();
        *encoded_len.last_mut().unwrap() |= 0x80;
        noncanonical.extend_from_slice(&encoded_len);
        noncanonical.push(0);
        noncanonical.extend_from_slice(body(&plain));
        let mut truncated = plain.clone();
        truncated.pop();
        let mut trailing = plain.clone();
        trailing.push(0);
        let mut concatenated = plain.clone();
        concatenated.extend_from_slice(&plain);
        for bytes in [bad_magic, bad_checksum, overflow, unterminated, noncanonical, truncated, trailing, concatenated]
        {
            assert!(matches!(parse(&bytes), Err(SyncError::Encoding)));
        }
    }

    #[test]
    fn compressed_stream_must_end_exactly_at_frame_boundary() {
        let compressed = change().bytes().to_vec();
        let payload = body(&compressed);
        let checksum = &compressed[4..8];
        let mut trailing = payload.to_vec();
        trailing.extend_from_slice(&[0, 1]);
        let mut concatenated = payload.to_vec();
        concatenated.extend_from_slice(payload);
        for invalid in [payload[..payload.len() - 1].to_vec(), trailing, concatenated, vec![0xff]] {
            assert!(matches!(parse(&frame(COMPRESSED_CHANGE, checksum, &invalid)), Err(SyncError::Encoding)));
        }
    }

    #[test]
    fn expanded_frame_limit_has_an_exact_inclusive_boundary() {
        let base = change();
        let mut expanded = base.decode();
        // The change's extra bytes are opaque metadata with no length prefix;
        // compensate for the few extra ULEB bytes in the larger outer frame.
        expanded.extra_bytes.resize(MAX_DOC_CHANGE_BYTES - base.raw_bytes().len(), 0);
        let candidate = Change::from(expanded.clone());
        let over = candidate.raw_bytes().len() - MAX_DOC_CHANGE_BYTES;
        expanded.extra_bytes.truncate(expanded.extra_bytes.len() - over);
        let mut exact = Change::from(expanded.clone());
        assert_eq!(exact.raw_bytes().len(), MAX_DOC_CHANGE_BYTES);
        assert!(parse(exact.raw_bytes()).is_ok());
        assert!(parse(&exact.bytes()).is_ok());
        expanded.extra_bytes.push(0);
        let mut oversized = Change::from(expanded);
        assert_eq!(oversized.raw_bytes().len(), MAX_DOC_CHANGE_BYTES + 1);
        assert!(matches!(parse(oversized.raw_bytes()), Err(SyncError::TooLarge)));
        assert!(matches!(parse(&oversized.bytes()), Err(SyncError::TooLarge)));
    }

    #[test]
    fn expansion_bomb_is_bounded_before_change_body_parsing() {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&vec![0; MAX_DOC_CHANGE_BYTES * 4]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 128 * 1024);
        assert!(matches!(parse(&frame(COMPRESSED_CHANGE, &[0; 4], &compressed)), Err(SyncError::TooLarge)));
        // These types must be rejected without interpreting their body.
        for kind in [0, 3] {
            assert!(matches!(parse(&frame(kind, &[0; 4], &compressed)), Err(SyncError::Encoding)));
        }
    }

    fn repeated_ops(rows: u64, predecessors: u64, key: &str) -> Vec<u8> {
        let unsigned = |n| {
            let mut v = Vec::new();
            leb128::write::unsigned(&mut v, n).unwrap();
            v
        };
        let run = |n, value: &[u8]| {
            let mut v = Vec::new();
            leb128::write::signed(&mut v, n).unwrap();
            v.extend_from_slice(value);
            v
        };
        let mut key_value = unsigned(key.len() as u64);
        key_value.extend_from_slice(key.as_bytes());
        let mut columns = vec![
            (0x15, run(rows as i64, &key_value)),
            (0x34, unsigned(rows)),
            (0x42, run(rows as i64, &unsigned(1))),
            (0x56, run(rows as i64, &unsigned(0))),
            (0x70, run(rows as i64, &unsigned(predecessors))),
        ];
        if predecessors != 0 {
            let count = rows.checked_mul(predecessors).unwrap() as i64;
            columns.push((0x71, run(count, &unsigned(0))));
            columns.push((0x73, run(count, &unsigned(0))));
        }
        let mut body = unsigned(0); // dependencies
        body.extend(unsigned(32));
        body.extend_from_slice(&[7; 32]); // actor
        body.extend_from_slice(&[1, 1, 0, 0, 0]); // seq/start/time/message/actors
        body.extend(unsigned(columns.len() as u64));
        for (spec, bytes) in &columns {
            body.extend(unsigned(*spec));
            body.extend(unsigned(bytes.len() as u64));
        }
        for (_, bytes) in columns {
            body.extend(bytes);
        }
        let mut raw = frame(CHANGE, &[0; 4], &body);
        let hash = Sha256::digest(&raw[8..]);
        raw[4..8].copy_from_slice(&hash[..4]);
        raw
    }

    #[test]
    fn logical_operation_limit_precedes_upstream_expansion() {
        let limits = Limits { ops: 1000, ..READ };
        let exact = repeated_ops(1000, 0, "k");
        assert!(exact.len() < 128);
        assert!(preflight(&exact, &limits).is_ok());
        let over = repeated_ops(1001, 0, "k");
        // Bounded demonstration that the upstream parser accepts this compact
        // amplification fixture; never hand it an unbounded adversarial count.
        assert_eq!(Change::try_from(over.as_slice()).unwrap().len(), 1001);
        assert!(matches!(preflight(&over, &limits), Err(SyncError::TooLarge)));
        let bomb = repeated_ops(i64::MAX as u64, 0, "k");
        assert!(matches!(parse(&bomb), Err(SyncError::TooLarge)));
    }

    #[test]
    fn tiny_changes_expand_at_most_to_the_floor() {
        // Five logical values per row; the body is a few dozen bytes.
        let rows = (READ.values.floor / 5) as u64;
        let exact = repeated_ops(rows, 0, "k");
        assert!(exact.len() < 128);
        assert_eq!(parse(&exact).unwrap().len() as u64, rows);
        assert!(matches!(parse(&repeated_ops(rows + 1, 0, "k")), Err(SyncError::TooLarge)));
    }

    #[test]
    fn single_operation_cannot_expand_unbounded_predecessors() {
        let bomb = repeated_ops(1, i64::MAX as u64, "k");
        assert!(bomb.len() < 160);
        assert!(matches!(parse(&bomb), Err(SyncError::TooLarge)));
    }

    #[test]
    fn repeated_column_strings_have_a_shared_expansion_limit() {
        let key = "k".repeat(1024);
        let rows = (READ.strings.floor / 1024) as u64;
        let exact = repeated_ops(rows, 0, &key);
        assert!(parse(&exact).is_ok());
        let over = repeated_ops(rows + 1, 0, &key);
        assert!(matches!(parse(&over), Err(SyncError::TooLarge)));
    }
}

/// Guard against an Automerge upgrade silently changing the format the
/// parsers in this module, `change_resources` and `change_ops` hard-code.
#[cfg(test)]
mod automerge_format {
    use super::*;

    const FIXTURES: &str = include_str!("fixtures/automerge-0.12.0-changes.hex");
    const REAUDIT: &str = "automerge changed: bounded_change.rs, change_resources.rs and change_ops.rs \
        re-implement its private change framing and column encodings. Re-audit them against the new \
        storage/ and columnar/ code, then regenerate src/fixtures \
        (MYCEL_WRITE_FIXTURES=1 cargo test -p mycel-sync write_fixtures -- --ignored)";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(line: &str) -> Vec<u8> {
        (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect()
    }

    fn stored() -> Vec<Vec<u8>> {
        FIXTURES.lines().filter(|l| !l.is_empty()).map(unhex).collect()
    }

    /// Column specs of a raw change, in order.
    fn specs(raw: &[u8]) -> Vec<u64> {
        let mut input = &raw[9..];
        let read = |input: &mut &[u8]| leb128::read::unsigned(input).unwrap();
        read(&mut input);
        let deps = read(&mut input) as usize;
        input = &input[deps * 32..];
        let len = read(&mut input) as usize;
        input = &input[len..];
        read(&mut input);
        read(&mut input);
        leb128::read::signed(&mut input).unwrap();
        let len = read(&mut input) as usize;
        input = &input[len..];
        for _ in 0..read(&mut input) {
            let len = read(&mut input) as usize;
            input = &input[len..];
        }
        (0..read(&mut input))
            .map(|_| {
                let spec = read(&mut input);
                read(&mut input);
                spec
            })
            .collect()
    }

    #[test]
    fn locked_automerge_is_the_audited_version() {
        // Windows checkouts may have CRLF line endings.
        let lock = include_str!("../../../Cargo.lock").replace("\r\n", "\n");
        assert!(lock.contains("name = \"automerge\"\nversion = \"0.12.0\"\n"), "{REAUDIT}");
    }

    #[test]
    fn automerge_still_writes_the_audited_bytes() {
        let fresh: Vec<Vec<u8>> = crate::change_ops::tests::fixtures().iter().map(|c| c.raw_bytes().to_vec()).collect();
        assert_eq!(
            fresh.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            stored().iter().map(|b| hex(b)).collect::<Vec<_>>(),
            "{REAUDIT}"
        );
    }

    #[test]
    fn audited_bytes_cover_every_column_kind_and_parse() {
        let stored = stored();
        let mut seen = std::collections::BTreeSet::new();
        for raw in &stored {
            seen.extend(specs(raw));
            let change = parse(raw).expect(REAUDIT);
            assert_eq!(change.raw_bytes(), raw.as_slice(), "{REAUDIT}");
            // Upstream re-encodes its own decoding identically.
            assert_eq!(Change::from(change.decode()).raw_bytes(), raw.as_slice(), "{REAUDIT}");
            let mut compressed = change.clone();
            assert_eq!(parse(&compressed.bytes()).unwrap().hash(), change.hash());
        }
        // Object, key, insert, action, value, predecessor, expand and mark
        // columns: every column type (group, actor, integer, delta, boolean,
        // string, value metadata, raw value).
        let expected = [0x01, 0x02, 0x11, 0x13, 0x15, 0x34, 0x42, 0x56, 0x57, 0x70, 0x71, 0x73, 0x94, 0xa5];
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), expected, "{REAUDIT}");
    }

    #[test]
    #[ignore]
    fn write_fixtures() {
        if std::env::var_os("MYCEL_WRITE_FIXTURES").is_none() {
            return;
        }
        let lines: String = crate::change_ops::tests::fixtures().iter().map(|c| hex(c.raw_bytes()) + "\n").collect();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/fixtures/automerge-0.12.0-changes.hex");
        std::fs::write(path, lines).unwrap();
    }
}
