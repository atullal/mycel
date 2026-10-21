//! Node storage (`mycel-net`, `blobs.rs`): the `.ranges` file kept next to
//! a partial download, read back when the download resumes. It is local
//! state, but a damaged disk, a restored backup or another program can leave
//! anything there, and what loads drives the resume arithmetic: how much to
//! reserve, which byte ranges to fetch, when the blob is complete. Then the
//! pieces received are marked as a download marks them.
//!
//! Properties: no panic; what loads is a set of ranges within the blob,
//! which, with the gaps the resume fetches, covers it exactly; marking
//! pieces keeps that true; what is saved loads back the same.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mycel_net::fuzzing::blob_ranges;

#[derive(Arbitrary, Debug)]
struct Input {
    file: Vec<u8>,
    total: Option<u64>,
    inserts: Vec<(u64, u64)>,
}

fuzz_target!(|input: Input| {
    let inserts = &input.inserts[..input.inserts.len().min(64)];
    blob_ranges(&input.file, input.total, inserts);
    // The size a download expects is usually the file's own.
    blob_ranges(&input.file, None, inserts);
});
