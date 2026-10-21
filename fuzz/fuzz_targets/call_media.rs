//! A call peer's media (`mycel-call`): audio frames in datagrams and on the
//! stream fallback, the Opus decoder (a C library transpiled to unsafe Rust)
//! fed whatever packets arrive, and the jitter buffer fed hostile sequence
//! numbers and timing, pulled by the playback clock as the engine does.
//! (Control messages are in `postcard_messages`.)
//!
//! Properties: no panic, no out-of-bounds or uninitialised read in the
//! codec (AddressSanitizer), audio frames re-encode to what was read, a
//! stream deframes the same however it is split, and decoded audio is
//! finite and never longer than the buffer.
#![no_main]

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mycel_call::codec::{Decoder, FRAME_SAMPLES};
use mycel_call::frame::{AudioFrame, StreamDeframer};
use mycel_call::jitter::{JitterBuffer, Playout};

#[derive(Arbitrary, Debug)]
enum Step {
    Datagram(Vec<u8>),
    Push { seq: u32, after_ms: u16 },
    Pop,
}

#[derive(Arbitrary, Debug)]
struct Input {
    stream: Vec<u8>,
    cut: u8,
    steps: Vec<Step>,
}

fn decode(dec: &mut Decoder, packet: &[u8], out: &mut [f32]) {
    if let Ok(n) = dec.decode(packet, out) {
        assert!(n <= out.len());
        assert!(out[..n].iter().all(|s| s.is_finite()), "the decoder produced a non-finite sample");
    }
}

fuzz_target!(|input: Input| {
    let deframe = |chunks: &mut dyn Iterator<Item = &[u8]>| {
        let mut d = StreamDeframer::default();
        let mut frames = Vec::new();
        for c in chunks {
            d.push(c);
            loop {
                match d.next_frame() {
                    Ok(Some(f)) => frames.push(f),
                    Ok(None) => break,
                    Err(_) => return (frames, true),
                }
            }
        }
        (frames, false)
    };
    let whole = deframe(&mut std::iter::once(&input.stream[..]));
    let split = deframe(&mut input.stream.chunks(usize::from(input.cut).max(1)));
    assert_eq!(whole, split, "the stream fallback depends on how reads split it");

    let mut dec = Decoder::new().expect("an Opus decoder");
    let mut out = vec![0f32; FRAME_SAMPLES];
    let mut jb = JitterBuffer::for_calls();
    let t0 = Instant::now();
    let mut now = t0;
    for step in input.steps.into_iter().take(512) {
        match step {
            Step::Datagram(bytes) => {
                if let Ok(f) = AudioFrame::decode(Bytes::from(bytes.clone())) {
                    assert_eq!(&f.encode()[..], &bytes[..]);
                    decode(&mut dec, &f.payload, &mut out);
                    jb.push(f.seq, f.payload, now);
                }
            }
            Step::Push { seq, after_ms } => {
                now += Duration::from_millis(u64::from(after_ms % 2000));
                jb.push(seq, Bytes::from_static(&[0xf8, 0xff, 0xfe]), now);
            }
            Step::Pop => match jb.pop() {
                Playout::Frame(p) => decode(&mut dec, &p, &mut out),
                Playout::Lost { fec: Some(p) } => {
                    let _ = dec.recover(&p, &mut out);
                }
                Playout::Lost { fec: None } => {
                    let _ = dec.conceal(&mut out);
                }
                Playout::Silence => {}
            },
        }
        let st = jb.stats();
        assert!(st.target_ms <= 120, "target delay beyond its bound: {st:?}");
        let _ = jb.depth();
    }
});
