//! A peer's stream on the Mycel protocol (`mycel/2`), read the way the node
//! reads it (`wire.rs`): a u32 length prefix checked against the reader's
//! limit and the peer's memory budget, a body read as it arrives, then
//! postcard. The first input byte picks the reader: a sync session, an
//! ephemeral message, a blob request or answer, a contact card.
//!
//! Properties: no panic, no allocation beyond what arrived (the budget code
//! grows buffers only with received bytes), and every decoded message
//! re-encodes canonically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mycel_net::fuzzing::{Reader, read_stream};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else { return };
    let reader = match kind % 5 {
        0 => Reader::Sync,
        1 => Reader::Ephemeral,
        2 => Reader::BlobReq,
        3 => Reader::BlobResp,
        _ => Reader::Card,
    };
    read_stream(reader, rest);
});
