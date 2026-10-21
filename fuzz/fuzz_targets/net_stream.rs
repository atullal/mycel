//! A peer's stream on the Mycel protocol (`mycel/2`), read the way the node
//! reads it (`wire.rs`): a u32 length prefix checked against the reader's
//! limit and the peer's memory budget, a body read as it arrives, then
//! postcard. The first input byte picks the reader: a sync session, an
//! ephemeral message, a blob request or answer, a contact card.
//!
//! Properties: no panic; every decoded message re-encodes canonically; and
//! no allocation beyond what arrived. A counting allocator measures the
//! most memory live at once while one input is read (its frames decoded,
//! then each message encoded and decoded twice more), which must stay
//! within [`PER_BYTE`] times the input plus [`SLACK`]: a length prefix
//! alone (say 64 MiB, `MAX_FRAME`) must not make the reader reserve its
//! length. The slack covers serde's cautious preallocation, which trusts a
//! declared sequence length up to 1 MiB.
#![no_main]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

use libfuzzer_sys::fuzz_target;
use mycel_net::fuzzing::{Reader, read_stream};

/// Bytes live now, and the most live since the last reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn shrank(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
}

// SAFETY: every call goes straight to the system allocator with the same
// arguments; the counters only observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size > layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Memory one input may hold at once, per byte of it (a frame's buffer, the
/// decoded message, and two re-encodings in flight)...
const PER_BYTE: usize = 16;
/// ...plus this, whatever its length.
const SLACK: usize = 2 << 20;

static WARM: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    // (the first read builds the thread's runtime, which stays)
    WARM.call_once(|| {
        read_stream(Reader::Sync, &[]);
    });
    let Some((&kind, rest)) = data.split_first() else { return };
    let reader = match kind % 5 {
        0 => Reader::Sync,
        1 => Reader::Ephemeral,
        2 => Reader::BlobReq,
        3 => Reader::BlobResp,
        _ => Reader::Card,
    };
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    read_stream(reader, rest);
    let most = PEAK.load(Ordering::Relaxed) - base;
    assert!(most <= PER_BYTE * data.len() + SLACK, "{most} bytes live at once reading {} bytes of stream", data.len());
});
