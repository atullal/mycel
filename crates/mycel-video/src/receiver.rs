//! Puts received frames back in order for the decoder, and notices when a
//! frame is gone for good, so it can ask for a keyframe.
//!
//! H.264 frames depend on the ones before them: a decoder must start at a
//! keyframe and then see every frame, in order. Frames travel on separate
//! QUIC streams, so they can finish out of order; this holds early ones
//! back until the gap fills. A gap that doesn't fill within [`GAP_WAIT`]
//! (or a frame whose stream the sender gave up on) means the decoder can't
//! continue: everything is held until the next keyframe, which is requested
//! (and re-requested every [`REREQUEST`] until it comes).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::wire::EncodedFrame;

/// How long a missing frame may be late before we give up on it.
pub const GAP_WAIT: Duration = Duration::from_millis(250);
pub const REREQUEST: Duration = Duration::from_millis(400);
/// Most frames held while waiting.
const MAX_HELD: usize = 90;

#[derive(Debug, Default)]
pub struct ReceiverStats {
    pub delivered: u64,
    pub keyframes: u64,
    /// Frames given up on (lost, or too late).
    pub dropped: u64,
    pub keyframe_requests: u64,
}

#[derive(Debug)]
pub struct Reorder {
    /// The sequence number the decoder needs next.
    next: Option<u32>,
    /// Waiting for a keyframe (at the start, or after a loss).
    need_key: bool,
    held: BTreeMap<u32, EncodedFrame>,
    gap_since: Option<Instant>,
    last_request: Option<Instant>,
    /// Newest keyframe seen: frames before it don't matter any more.
    newest_key: Option<u32>,
    /// Frames the sender gave up on.
    gone: std::collections::BTreeSet<u32>,
    pub stats: ReceiverStats,
}

impl Default for Reorder {
    fn default() -> Self {
        Reorder {
            next: None,
            need_key: true,
            held: BTreeMap::new(),
            gap_since: None,
            last_request: None,
            newest_key: None,
            gone: Default::default(),
            stats: ReceiverStats::default(),
        }
    }
}

impl Reorder {
    /// The frame the decoder needs next (what a keyframe request names).
    pub fn missing(&self) -> u32 {
        self.next.unwrap_or(0)
    }

    /// Waiting for a keyframe right now.
    pub fn needs_keyframe(&self) -> bool {
        self.need_key
    }

    /// A frame arrived. Returns what the decoder can take now, in order.
    pub fn push(&mut self, f: EncodedFrame, now: Instant) -> Vec<EncodedFrame> {
        if self.next.is_some_and(|n| f.seq < n) || self.held.contains_key(&f.seq) {
            return vec![]; // late or duplicate
        }
        if f.keyframe && self.newest_key.is_none_or(|k| f.seq > k) {
            self.newest_key = Some(f.seq);
        }
        if self.held.len() >= MAX_HELD
            && let Some((&first, _)) = self.held.first_key_value()
        {
            self.held.remove(&first);
            self.stats.dropped += 1;
        }
        self.held.insert(f.seq, f);
        self.drain(now)
    }

    /// The sender gave up on frame `seq` (its stream was reset).
    pub fn lost(&mut self, seq: u32, now: Instant) -> Vec<EncodedFrame> {
        if self.next.is_some_and(|n| seq < n) || self.newest_key.is_some_and(|k| seq < k) {
            return vec![];
        }
        self.gone.insert(seq);
        self.drain(now)
    }

    /// Call regularly: gives up on frames that are late for too long.
    /// Returns frames that became deliverable, and whether to (re)send a
    /// keyframe request now.
    pub fn tick(&mut self, now: Instant) -> (Vec<EncodedFrame>, bool) {
        let mut out = vec![];
        if !self.need_key && self.gap_since.is_some_and(|t| now.duration_since(t) >= GAP_WAIT) {
            self.give_up();
            out = self.drain(now);
        }
        // (nothing has arrived yet: the first frame will be a keyframe anyway)
        let waiting = self.next.is_some() || !self.held.is_empty() || !self.gone.is_empty();
        let ask = self.need_key && waiting && self.last_request.is_none_or(|t| now.duration_since(t) >= REREQUEST);
        if ask {
            self.last_request = Some(now);
            self.stats.keyframe_requests += 1;
        }
        (out, ask)
    }

    fn give_up(&mut self) {
        if !self.need_key {
            self.need_key = true;
            // ask straight away
            self.last_request = None;
        }
        self.gap_since = None;
    }

    /// Start decoding again at held keyframe `k`; what's before it is moot.
    fn jump_to(&mut self, k: u32) {
        let before: Vec<u32> = self.held.range(..k).map(|(s, _)| *s).collect();
        self.stats.dropped += before.len() as u64;
        for s in before {
            self.held.remove(&s);
        }
        self.gone.retain(|s| *s > k);
        self.need_key = false;
        self.next = Some(k);
    }

    fn drain(&mut self, now: Instant) -> Vec<EncodedFrame> {
        let mut out = vec![];
        loop {
            let first_key = self.held.iter().find(|(_, f)| f.keyframe).map(|(s, _)| *s);
            if self.need_key {
                let Some(k) = first_key else { break };
                self.jump_to(k);
            }
            while let Some(n) = self.next {
                let Some(f) = self.held.remove(&n) else { break };
                if f.keyframe {
                    self.stats.keyframes += 1;
                }
                self.stats.delivered += 1;
                out.push(f);
                self.next = Some(n.wrapping_add(1));
            }
            if self.held.is_empty() {
                break;
            }
            let next = self.next.unwrap_or(0);
            match self.held.iter().find(|(_, f)| f.keyframe).map(|(s, _)| *s) {
                // a newer keyframe is already here: no need to wait for the gap
                Some(k) => self.jump_to(k),
                None if self.gone.contains(&next) => self.give_up(),
                None => break,
            }
            if self.need_key {
                break;
            }
        }
        self.gap_since = if self.held.is_empty() || self.need_key { None } else { self.gap_since.or(Some(now)) };
        out
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn f(seq: u32, key: bool) -> EncodedFrame {
        EncodedFrame {
            seq,
            capture_us: 0,
            keyframe: key,
            width: 16,
            height: 16,
            config: None,
            data: Bytes::from_static(b"x"),
        }
    }

    fn seqs(v: &[EncodedFrame]) -> Vec<u32> {
        v.iter().map(|f| f.seq).collect()
    }

    #[test]
    fn starts_at_a_keyframe_and_reorders() {
        let mut r = Reorder::default();
        let t = Instant::now();
        assert!(r.push(f(5, false), t).is_empty(), "nothing before a keyframe");
        assert_eq!(seqs(&r.push(f(6, true), t)), [6]);
        assert!(r.push(f(8, false), t).is_empty(), "7 is missing");
        assert_eq!(seqs(&r.push(f(7, false), t)), [7, 8]);
        assert!(r.push(f(7, false), t).is_empty(), "duplicate");
        assert!(r.push(f(5, false), t).is_empty(), "too old");
        assert_eq!(r.stats.delivered, 3);
    }

    #[test]
    fn a_lost_frame_waits_for_the_next_keyframe() {
        let mut r = Reorder::default();
        let t = Instant::now();
        assert_eq!(seqs(&r.push(f(0, true), t)), [0]);
        assert_eq!(seqs(&r.push(f(1, false), t)), [1]);
        // 2 never comes
        assert!(r.push(f(3, false), t).is_empty());
        let (out, ask) = r.tick(t + Duration::from_millis(100));
        assert!(out.is_empty() && !ask, "still waiting for 2");
        let (out, ask) = r.tick(t + GAP_WAIT + Duration::from_millis(1));
        assert!(out.is_empty());
        assert!(ask, "asks for a keyframe");
        assert!(r.needs_keyframe());
        assert!(r.push(f(4, false), t).is_empty(), "can't decode deltas now");
        let (_, again) = r.tick(t + GAP_WAIT + Duration::from_millis(50));
        assert!(!again, "doesn't spam requests");
        let (_, again) = r.tick(t + GAP_WAIT + REREQUEST + Duration::from_millis(5));
        assert!(again, "re-asks while the keyframe doesn't come");
        assert_eq!(seqs(&r.push(f(6, false), t)), Vec::<u32>::new());
        assert_eq!(seqs(&r.push(f(5, true), t)), [5, 6], "keyframe recovers, held frames follow");
        assert!(!r.needs_keyframe());
    }

    #[test]
    fn a_newer_keyframe_skips_the_wait() {
        let mut r = Reorder::default();
        let t = Instant::now();
        r.push(f(0, true), t);
        // the camera restarted: 1..4 never sent, 5 is a keyframe
        assert_eq!(seqs(&r.push(f(5, true), t)), [5]);
        assert!(!r.needs_keyframe());
        assert_eq!(r.tick(t).1, false, "nothing to ask for");
    }

    #[test]
    fn a_reset_stream_is_lost_at_once() {
        let mut r = Reorder::default();
        let t = Instant::now();
        r.push(f(0, true), t);
        r.push(f(2, false), t);
        assert!(r.lost(1, t).is_empty());
        assert!(r.needs_keyframe());
        let (_, ask) = r.tick(t);
        assert!(ask);
        // frames the sender dropped before a newer keyframe don't matter
        assert_eq!(seqs(&r.push(f(3, true), t)), [3]);
        assert!(r.lost(2, t).is_empty());
        assert!(!r.needs_keyframe());
    }
}
