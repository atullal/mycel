//! A call peer's video (`mycel-video`): encoded frames from frame streams,
//! the control stream, the frame layout handed to the webview, the H.264
//! `avcC` record inside keyframes, and the reorder buffer fed hostile
//! sequence numbers, keyframe flags and give-ups.
//!
//! Properties: no panic; frames re-encode to what was read (and survive the
//! webview layout); the control stream deframes the same however it is
//! split; the reorder buffer delivers in strictly increasing order, starting
//! at a keyframe after every loss, and holds a bounded number of frames.
#![no_main]

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mycel_video::receiver::Reorder;
use mycel_video::wire::{self, CtrlDeframer, EncodedFrame, UiFrame, UiSource};

#[derive(Arbitrary, Debug)]
enum Step {
    Frame { seq: u32, key: bool },
    Raw(Vec<u8>),
    Lost(u32),
    Tick(u16),
}

#[derive(Arbitrary, Debug)]
struct Input {
    frame: Vec<u8>,
    ui: Vec<u8>,
    avcc: Vec<u8>,
    ctrl: Vec<u8>,
    cut: u8,
    steps: Vec<Step>,
}

fuzz_target!(|input: Input| {
    if let Ok(f) = EncodedFrame::decode(Bytes::from(input.frame.clone())) {
        let wire_bytes = f.encode();
        assert_eq!(wire_bytes[0], wire::KIND_FRAME);
        assert_eq!(EncodedFrame::decode(wire_bytes.slice(1..)).expect("re-decodes"), f);
        let ui = UiFrame { source: UiSource::Remote, peer: [9; 32], frame: f.clone() }.encode();
        assert_eq!(UiFrame::decode(&ui).expect("UI layout decodes").frame, f);
    }
    if let Ok(u) = UiFrame::decode(&input.ui) {
        let _ = u.encode();
    }
    if let Ok((sps, pps)) = wire::avcc_parameter_sets(&input.avcc) {
        let again = wire::avcc_record(&sps, &pps);
        assert_eq!(wire::avcc_parameter_sets(&again).expect("our own record parses"), (sps, pps));
    }
    let _ = wire::codec_string(&input.avcc);
    let deframe = |chunks: &mut dyn Iterator<Item = &[u8]>| {
        let mut d = CtrlDeframer::default();
        let mut msgs = Vec::new();
        for c in chunks {
            d.push(c);
            loop {
                match d.next_msg() {
                    Ok(Some(m)) => msgs.push(m),
                    Ok(None) => break,
                    Err(_) => return (msgs, true),
                }
            }
        }
        (msgs, false)
    };
    let whole = deframe(&mut std::iter::once(&input.ctrl[..]));
    let split = deframe(&mut input.ctrl.chunks(usize::from(input.cut).max(1)));
    assert_eq!(whole, split);

    let mut r = Reorder::default();
    let mut now = Instant::now();
    let mut last: Option<u32> = None;
    let deliver = |out: Vec<EncodedFrame>, need_key: bool, last: &mut Option<u32>| {
        for (i, f) in out.iter().enumerate() {
            if let Some(l) = *last {
                assert!(f.seq > l, "delivered {} after {l}", f.seq);
            }
            if i == 0 && need_key {
                assert!(f.keyframe, "decoding resumed without a keyframe");
            }
            *last = Some(f.seq);
        }
    };
    for step in input.steps.into_iter().take(256) {
        let need_key = r.needs_keyframe();
        let out = match step {
            Step::Frame { seq, key } => {
                let f = EncodedFrame {
                    seq,
                    capture_us: 0,
                    keyframe: key,
                    width: 16,
                    height: 16,
                    config: None,
                    data: Bytes::from_static(b"\x00\x00\x00\x01\x65"),
                };
                r.push(f, now)
            }
            Step::Raw(bytes) => match EncodedFrame::decode(Bytes::from(bytes)) {
                Ok(f) => r.push(f, now),
                Err(_) => vec![],
            },
            Step::Lost(seq) => r.lost(seq, now),
            Step::Tick(ms) => {
                now += Duration::from_millis(u64::from(ms));
                r.tick(now).0
            }
        };
        deliver(out, need_key, &mut last);
    }
});
