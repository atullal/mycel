//! Adaptive jitter buffer.
//!
//! Frames arrive out of order, late, twice or never; the speaker needs one
//! frame every 20 ms. The buffer holds frames by sequence number and is
//! *pulled by the playback clock* ([`JitterBuffer::pop`] is called whenever the
//! device needs another frame), so sender/receiver clock drift never builds
//! up. It keeps a target depth derived from the measured inter-arrival jitter
//! (RFC 3550 estimator), clamped to 40–120 ms, grows it after underruns and
//! trims back when frames pile up.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::codec::FRAME_MS;

const FRAME: Duration = Duration::from_millis(FRAME_MS as u64);
/// More than this many frames missing in a row is a resync, not loss.
const MAX_GAP: u32 = 25;
/// Never hold more than this (5 s) of audio.
const MAX_PACKETS: usize = 250;
/// After an underrun, conceal this many frames before going silent.
const MAX_CONCEAL: u32 = 5;
/// Wait at most this many frames for a missing frame before writing it off.
const MAX_HOLDS: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Playout {
    /// Decode this packet.
    Frame(Bytes),
    /// The frame is missing: conceal it, from the next packet's FEC data if we have it.
    Lost { fec: Option<Bytes> },
    /// Nothing to play yet (not started, or long gap): play silence.
    Silence,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct JitterStats {
    /// Frames accepted into the buffer.
    pub received: u64,
    pub played: u64,
    /// Frames that never arrived in time and were concealed.
    pub lost: u64,
    /// Frames that arrived after their slot was played (dropped).
    pub late: u64,
    pub duplicates: u64,
    /// Times the buffer ran dry.
    pub underruns: u64,
    /// Frames skipped to bring latency back down.
    pub trimmed: u64,
    /// Concealed frames inserted to raise the delay (waiting for a late frame).
    pub stretched: u64,
    pub jitter_ms: f32,
    pub target_ms: u32,
    pub depth_ms: u32,
}

pub struct JitterBuffer {
    min: Duration,
    max: Duration,
    packets: BTreeMap<u32, Bytes>,
    next: u32,
    playing: bool,
    started: bool,
    concealing: u32,
    /// (arrival, seq) of the previous packet, for the jitter estimator.
    last: Option<(Instant, u32)>,
    /// Smoothed inter-arrival jitter, seconds.
    jitter: f64,
    /// Extra delay after underruns, seconds; decays slowly.
    bonus: f64,
    since_trim: u32,
    holds: u32,
    stats: JitterStats,
}

impl JitterBuffer {
    pub fn new(min: Duration, max: Duration) -> JitterBuffer {
        JitterBuffer {
            min,
            max: max.max(min),
            packets: BTreeMap::new(),
            next: 0,
            playing: false,
            started: false,
            concealing: 0,
            last: None,
            jitter: 0.0,
            bonus: 0.0,
            since_trim: 0,
            holds: 0,
            stats: JitterStats::default(),
        }
    }

    /// The default for calls: 40–120 ms.
    pub fn for_calls() -> JitterBuffer {
        JitterBuffer::new(Duration::from_millis(40), Duration::from_millis(120))
    }

    /// Delay the buffer aims to hold.
    pub fn target_delay(&self) -> Duration {
        let want = FRAME.as_secs_f64() + 3.0 * self.jitter + self.bonus;
        Duration::from_secs_f64(want).clamp(self.min, self.max)
    }

    fn target_frames(&self) -> u32 {
        (self.target_delay().as_millis() as u32).div_ceil(FRAME_MS).max(1)
    }

    /// Frames buffered from the play point on.
    pub fn depth(&self) -> u32 {
        match (self.packets.first_key_value(), self.packets.last_key_value()) {
            (Some((&first, _)), Some((&last, _))) => {
                let from = if self.playing { self.next.min(first) } else { first };
                last + 1 - from
            }
            _ => 0,
        }
    }

    pub fn stats(&self) -> JitterStats {
        JitterStats {
            jitter_ms: (self.jitter * 1000.0) as f32,
            target_ms: self.target_delay().as_millis() as u32,
            depth_ms: self.depth() * FRAME_MS,
            ..self.stats
        }
    }

    pub fn push(&mut self, seq: u32, payload: Bytes, now: Instant) {
        // RFC 3550 jitter: change in transit time between consecutive arrivals.
        if let Some((t, s)) = self.last {
            let arrival = now.saturating_duration_since(t).as_secs_f64();
            let sent = (seq as f64 - s as f64) * FRAME.as_secs_f64();
            let d = (arrival - sent).abs().min(1.0);
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.last = Some((now, seq));

        if self.started && seq < self.next {
            self.stats.late += 1;
            return;
        }
        if self.packets.contains_key(&seq) {
            self.stats.duplicates += 1;
            return;
        }
        self.packets.insert(seq, payload);
        self.stats.received += 1;
        while self.packets.len() > MAX_PACKETS {
            self.packets.pop_first();
        }
    }

    /// What to play for the next 20 ms.
    pub fn pop(&mut self) -> Playout {
        self.bonus *= 0.999;
        if !self.playing {
            let span = self.depth();
            if span == 0 || span < self.target_frames() {
                if self.started && self.concealing < MAX_CONCEAL {
                    self.concealing += 1;
                    return Playout::Lost { fec: None };
                }
                return Playout::Silence;
            }
            // enough buffered: (re)start at the oldest frame we hold
            self.next = *self.packets.first_key_value().unwrap().0;
            self.playing = true;
            self.started = true;
            self.concealing = 0;
        }

        let Some((&first, _)) = self.packets.first_key_value() else {
            // ran dry: conceal, and buffer a little more from now on
            self.playing = false;
            self.stats.underruns += 1;
            self.bonus = (self.bonus + FRAME.as_secs_f64()).min(0.06);
            self.concealing = 1;
            return Playout::Lost { fec: None };
        };
        if first > self.next + MAX_GAP {
            // a long hole (path change, sender paused): jump ahead
            self.next = first;
        }
        let target = self.target_frames();
        let out = if first == self.next {
            self.holds = 0;
            let p = self.packets.pop_first().unwrap().1;
            self.stats.played += 1;
            Playout::Frame(p)
        } else if self.depth() < target && self.holds < MAX_HOLDS {
            // Below target and the frame isn't here yet: wait for it (stretch
            // by one concealed frame) instead of writing it off. This is how
            // the delay grows when jitter rises.
            self.holds += 1;
            self.stats.stretched += 1;
            return Playout::Lost { fec: None };
        } else {
            self.holds = 0;
            self.stats.lost += 1;
            Playout::Lost { fec: self.packets.get(&(self.next + 1)).cloned() }
        };
        self.next += 1;

        // too much queued (e.g. a burst after a stall): skip a frame now and
        // then, faster the further over target we are
        self.since_trim += 1;
        let excess = self.depth().saturating_sub(target);
        let every = if excess > 6 { 2 } else { 10 };
        if excess > 2 && self.since_trim >= every {
            self.since_trim = 0;
            self.packets.remove(&self.next);
            self.next += 1;
            self.stats.trimmed += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seq: u32) -> Bytes {
        Bytes::from(seq.to_le_bytes().to_vec())
    }

    fn seq_of(b: &Bytes) -> u32 {
        u32::from_le_bytes(b[..4].try_into().unwrap())
    }

    /// Feed `arrivals` (seq, arrival ms) and pull one frame per 20 ms of
    /// playback clock, starting at `start_ms`; returns what was played.
    fn simulate(jb: &mut JitterBuffer, arrivals: &[(u32, u64)], start_ms: u64, pops: usize) -> Vec<Playout> {
        let t0 = Instant::now();
        let mut arrivals = arrivals.to_vec();
        arrivals.sort_by_key(|a| a.1);
        let mut i = 0;
        let mut out = Vec::new();
        for k in 0..pops {
            let now_ms = start_ms + k as u64 * 20;
            while i < arrivals.len() && arrivals[i].1 <= now_ms {
                jb.push(arrivals[i].0, p(arrivals[i].0), t0 + Duration::from_millis(arrivals[i].1));
                i += 1;
            }
            out.push(jb.pop());
        }
        out
    }

    fn played(out: &[Playout]) -> Vec<u32> {
        out.iter()
            .filter_map(|o| match o {
                Playout::Frame(b) => Some(seq_of(b)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn in_order_plays_everything_after_prebuffering() {
        let mut jb = JitterBuffer::for_calls();
        let arrivals: Vec<(u32, u64)> = (0..50).map(|s| (s, s as u64 * 20)).collect();
        let out = simulate(&mut jb, &arrivals, 0, 60);
        assert_eq!(out[0], Playout::Silence, "waits for the target depth first");
        assert_eq!(played(&out), (0..50).collect::<Vec<_>>());
        let st = jb.stats();
        assert_eq!((st.lost, st.late, st.duplicates), (0, 0, 0));
        assert_eq!(st.target_ms, 40, "steady arrivals keep the minimum delay");
    }

    #[test]
    fn reordered_frames_play_in_order() {
        let mut jb = JitterBuffer::for_calls();
        // pairs swapped: 1,0,3,2,...
        let arrivals: Vec<(u32, u64)> = (0..40).map(|s| (s ^ 1, s as u64 * 20)).collect();
        let out = simulate(&mut jb, &arrivals, 0, 50);
        assert_eq!(played(&out), (0..40).collect::<Vec<_>>());
        assert_eq!(jb.stats().lost, 0);
    }

    #[test]
    fn loss_is_concealed_with_fec_from_the_next_frame() {
        let mut jb = JitterBuffer::for_calls();
        let arrivals: Vec<(u32, u64)> = (0..30).filter(|s| *s != 10).map(|s| (s, s as u64 * 20)).collect();
        let out = simulate(&mut jb, &arrivals, 0, 40);
        let i = out.iter().position(|o| matches!(o, Playout::Lost { .. })).unwrap();
        assert_eq!(out[i], Playout::Lost { fec: Some(p(11)) }, "FEC comes from frame 11");
        assert!(matches!(&out[i - 1], Playout::Frame(b) if seq_of(b) == 9));
        assert!(matches!(&out[i + 1], Playout::Frame(b) if seq_of(b) == 11));
        assert_eq!(jb.stats().lost, 1);
    }

    #[test]
    fn late_and_duplicate_frames_are_dropped() {
        let mut jb = JitterBuffer::for_calls();
        // frame 5 arrives 200 ms late, frame 7 twice
        let mut arrivals: Vec<(u32, u64)> = (0..30).filter(|s| *s != 5).map(|s| (s, s as u64 * 20)).collect();
        arrivals.push((5, 5 * 20 + 200));
        arrivals.push((7, 7 * 20 + 5));
        let out = simulate(&mut jb, &arrivals, 0, 40);
        let seqs = played(&out);
        assert!(!seqs.contains(&5), "a frame whose slot passed is never played");
        assert_eq!(seqs.iter().filter(|s| **s == 7).count(), 1);
        let st = jb.stats();
        assert_eq!((st.late, st.duplicates, st.lost), (1, 1, 1));
        let mut sorted = seqs.clone();
        sorted.sort();
        assert_eq!(seqs, sorted, "still in order");
    }

    #[test]
    fn jitter_grows_the_target_but_never_past_the_max() {
        let mut jb = JitterBuffer::for_calls();
        // ±50 ms of jitter
        let arrivals: Vec<(u32, u64)> =
            (0..300).map(|s| (s, s as u64 * 20 + if s % 3 == 0 { 50 } else { 0 })).collect();
        let out = simulate(&mut jb, &arrivals, 0, 320);
        let st = jb.stats();
        assert!(st.target_ms > 60, "target {} ms", st.target_ms);
        assert!(st.target_ms <= 120);
        // with the bigger target nothing is lost once it settled
        let tail = &out[150..300];
        assert!(tail.iter().all(|o| matches!(o, Playout::Frame(_))), "{tail:?}");
    }

    #[test]
    fn underrun_conceals_then_rebuffers_and_resumes() {
        let mut jb = JitterBuffer::for_calls();
        // 1 s of audio, a 1 s outage (path failover), then audio again
        let arrivals: Vec<(u32, u64)> = (0..50).chain(100..150).map(|s| (s, s as u64 * 20)).collect();
        let out = simulate(&mut jb, &arrivals, 0, 160);
        let st = jb.stats();
        assert!(st.underruns >= 1);
        let seqs = played(&out);
        assert!(seqs.contains(&49) && seqs.contains(&100) && seqs.contains(&140), "resumes after the outage");
        // the first frames after the outage are concealment, then silence
        let after = out.iter().position(|o| matches!(o, Playout::Frame(b) if seq_of(b) == 49)).unwrap();
        assert!(matches!(out[after + 1], Playout::Lost { .. }));
        assert!(out[after + 1..after + 40].contains(&Playout::Silence));
    }

    #[test]
    fn a_burst_after_a_stall_is_trimmed_back_down() {
        let mut jb = JitterBuffer::for_calls();
        // 25 frames arrive at once, then steady
        let arrivals: Vec<(u32, u64)> = (0..200).map(|s| (s, if s < 25 { 500 } else { s as u64 * 20 })).collect();
        let _ = simulate(&mut jb, &arrivals, 500, 150);
        let st = jb.stats();
        assert!(st.trimmed > 0);
        assert!(st.depth_ms <= st.target_ms + 60, "depth {} target {}", st.depth_ms, st.target_ms);
    }
}
