//! Document changes as a member sends them (`bounded_change.rs`,
//! `change_ops.rs`): the decrypted payload of every document envelope. By
//! the first input byte, the rest is either a whole chunk, or a change body
//! that the harness frames with a correct length and checksum (so mutations
//! reach the column decoders instead of failing the checksum).
//!
//! Differential properties against Automerge 0.12's own loader: whatever we
//! accept, Automerge accepts with the same hash and bytes; our op-column
//! decoder, when it accepts a change, reads exactly the rows Automerge
//! decodes; parsing our own re-encoding gives the same change.
#![no_main]

use automerge::Change;
use libfuzzer_sys::fuzz_target;
use mycel_sync::fuzzing::{check_ops_against_upstream, frame_change, parse_change};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let bytes = match mode % 3 {
        0 => rest.to_vec(),
        1 => frame_change(1, rest),
        _ => frame_change(2, rest),
    };
    let Some(ours) = parse_change(&bytes) else { return };
    let theirs = Change::try_from(ours.raw_bytes()).expect("Automerge loads what we accepted");
    assert_eq!(theirs.hash(), ours.hash());
    assert_eq!(theirs.raw_bytes(), ours.raw_bytes());
    let again = parse_change(ours.raw_bytes()).expect("a change we accepted parses again");
    assert_eq!(again.hash(), ours.hash());
    let _ = check_ops_against_upstream(&ours);
});
