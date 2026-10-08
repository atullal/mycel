//! How much video to send: resolution, frame rate and bitrate, from the
//! path in use and from how fast frames actually get through.
//!
//! - The **path** sets a ceiling, from what its medium typically carries
//!   (the prior the path selector uses too): video takes at most a quarter
//!   of it, up to 720p30 on cable, a Wi-Fi network or UWB; 480p30 on
//!   peer-to-peer Wi-Fi / Wi-Fi Direct (the radio hops channels); 360p via
//!   a relay; none under 1 Mbit/s (Bluetooth, IEEE 802.15.4: "video paused:
//!   slow connection", see [`BLUETOOTH`]).
//! - Under that ceiling a **delay-based controller** sets the bitrate: the
//!   path's smoothed RTT (QUIC's, which leaves out delayed-ACK time) above
//!   the lowest RTT seen lately (the base, as LEDBAT measures it) is
//!   queueing on the way, which audio feels as much as video does. Rising queueing means the path is full: back off (×0.75, and
//!   to no more than what was acknowledged meanwhile) before audio, which
//!   shares every queue on the way, suffers. Short queues: creep up (×1.12
//!   every 500 ms).
//! - Frames are **skipped before encoding** when too much is still queued, so
//!   a congested path drops frame rate rather than adding delay, and nothing
//!   already encoded is thrown away (which would break the frames after it).
//! - The **resolution** follows the bitrate down a ladder at once, and back
//!   up only after the bitrate has held for a while (each switch costs a
//!   keyframe).

use std::time::{Duration, Instant};

use mycel_net::PathKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quality {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

impl Quality {
    pub const fn new(width: u32, height: u32, fps: u32) -> Quality {
        Quality { width, height, fps }
    }

    pub fn pixels(&self) -> u32 {
        self.width * self.height
    }
}

/// (minimum bitrate, quality), best first.
pub const LADDER: [(u32, Quality); 6] = [
    (1_200_000, Quality::new(1280, 720, 30)),
    (650_000, Quality::new(848, 480, 30)),
    (350_000, Quality::new(640, 360, 24)),
    (160_000, Quality::new(424, 240, 15)),
    (70_000, Quality::new(320, 180, 10)),
    (0, Quality::new(160, 90, 5)),
];

/// Every path starts here (320×180): a first keyframe a slow path can't
/// carry would stall the audio queued behind it.
const START: u32 = 150_000;

/// What a path allows: (start bitrate, max bitrate, best quality).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathBudget {
    pub start: u32,
    pub max: u32,
    pub best: Quality,
}

/// Bluetooth LE: `None` = video paused. A Mac-to-Mac L2CAP channel carries
/// roughly 100–200 kbit/s in practice, shared with audio (12 kbit/s) and
/// QUIC's own overhead. Measured over a 20 KB/s link with 20 ms latency
/// (`tiny_video_over_bluetooth_measurement` in mycel-call's tests): even
/// 160×90 at 5 fps (~37 kbit/s) raised the audio's mouth-to-ear delay by
/// ~90 ms (176→268, 162→249 ms) and lost 4–8 audio frames per 10 s, so
/// video stays off on Bluetooth.
pub const BLUETOOTH: Option<PathBudget> = None;

/// `MYCEL_VIDEO_BLUETOOTH_KBPS=n`: send 160×90 at 5 fps within n kbit/s
/// over Bluetooth anyway (to measure, or on links known to be faster).
fn bluetooth_override() -> Option<PathBudget> {
    let kbps: u32 = std::env::var("MYCEL_VIDEO_BLUETOOTH_KBPS").ok()?.trim().parse().ok()?;
    let bps = kbps * 1000;
    Some(PathBudget { start: bps, max: bps, best: LADDER[LADDER.len() - 1].1 })
}

pub fn budget(path: Option<PathKind>) -> Option<PathBudget> {
    let Some(kind) = path else {
        // not known yet: modest
        return Some(PathBudget { start: START, max: 1_000_000, best: LADDER[1].1 });
    };
    if kind == PathKind::Bluetooth {
        return bluetooth_override().or(BLUETOOTH);
    }
    // Any medium by what it typically carries (the same prior the path
    // selector starts from): video may take a quarter of it, and a medium
    // under 1 Mbit/s (Bluetooth, IEEE 802.15.4) carries none.
    let prior = kind.prior_rate() * 8.0;
    if prior < MIN_PATH_BPS {
        return None;
    }
    let (best, cap) = match kind {
        // the radio also hops to the Wi-Fi network's channel: steadier at 480p
        PathKind::PeerWifi | PathKind::WifiDirect => (LADDER[1].1, 1_000_000),
        // a shared server on the internet
        PathKind::Relay => (LADDER[2].1, 500_000),
        // cable, Wi-Fi network, UWB, anything else fast
        _ => (LADDER[0].1, 2_500_000),
    };
    let max = cap.min((prior * 0.25) as u32);
    Some(PathBudget { start: START.min(max), max, best: quality_for(max, best) })
}

/// Below this typical throughput a path gets no video.
const MIN_PATH_BPS: f64 = 1_000_000.0;

/// The best rung of [`LADDER`] for `bps`, no better than `best`.
pub fn quality_for(bps: u32, best: Quality) -> Quality {
    LADDER
        .iter()
        .find(|(min, q)| bps >= *min && q.pixels() <= best.pixels())
        .map(|(_, q)| *q)
        .unwrap_or(LADDER[LADDER.len() - 1].1)
}

const MIN_BPS: u32 = 60_000;
/// Queueing (beyond the RTT) above this means the path is full. Audio
/// shares every queue video fills, so this is kept to tens of ms.
const DELAY_HIGH: Duration = Duration::from_millis(35);
/// ...and below this, there's room.
const DELAY_LOW: Duration = Duration::from_millis(12);
const BASE_PERIOD: Duration = Duration::from_secs(5);
const INCREASE_EVERY: Duration = Duration::from_millis(500);
/// Until the path first shows queueing, ramp up faster (×1.4 every 400 ms:
/// 150 kbit/s to 2.5 Mbit/s in ~3.5 s), like TCP's slow start...
const SLOW_START_EVERY: Duration = Duration::from_millis(400);
/// ...which ends at the second frame in a row delayed this much (not the
/// smoothed delay: an overshoot shouldn't last long enough to show in that).
const SLOW_START_EXIT: Duration = Duration::from_millis(40);
/// Not sending for this long resets to the start rate.
const IDLE_RESTART: Duration = Duration::from_secs(2);
const HOLD_AFTER_DECREASE: Duration = Duration::from_secs(2);
/// A better resolution needs the bitrate for it to hold this long (less
/// while ramping up at the start).
const UPGRADE_AFTER: Duration = Duration::from_secs(2);
const UPGRADE_AFTER_START: Duration = Duration::from_millis(700);
const UPGRADE_MARGIN: f64 = 1.3;
/// Skip encoding while this much (in time at the target rate) is waiting
/// to be handed to QUIC...
const MAX_QUEUED: Duration = Duration::from_millis(120);
/// ...or while a frame QUIC has had this long beyond the RTT isn't
/// acknowledged (the path is backed up: also a reason to slow down).
const MAX_STUCK: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    Send,
    /// Not time for a frame yet at this frame rate.
    NotYet,
    /// Our own sending is behind (pacing a big frame): skip this picture.
    Backlog,
    /// The path is backed up: skip this picture.
    Congested,
}

#[derive(Debug)]
pub struct RateController {
    path: Option<PathKind>,
    budget: Option<PathBudget>,
    target: u32,
    quality: Quality,
    /// Since when a better quality has been possible, continuously.
    better_since: Option<Instant>,
    /// Smoothed queueing delay of acknowledged frames.
    delay: Option<Duration>,
    /// Lowest delivery time this period and last: (current, previous, period start).
    base: (Option<Duration>, Option<Duration>, Option<Instant>),
    last_decrease: Option<Instant>,
    last_increase: Option<Instant>,
    next_frame: Option<Instant>,
    /// Bytes sent, for "are we using the budget": (window start, bytes).
    sent_window: (Option<Instant>, u64),
    sent_rate: u32,
    /// Bytes acknowledged, for "what the path really carries".
    acked_window: (Option<Instant>, u64),
    acked_rate: u32,
    congested: bool,
    /// Still ramping up fast: no sign of a full path yet.
    slow_start: bool,
    late_in_a_row: u32,
    /// Last acknowledged frame: no acks, no evidence to raise the rate on.
    last_ack: Option<Instant>,
    last_send: Option<Instant>,
}

impl RateController {
    pub fn new(path: Option<PathKind>) -> RateController {
        let budget = budget(path);
        let target = budget.map(|b| b.start).unwrap_or(0);
        let quality = budget.map(|b| quality_for(target, b.best)).unwrap_or(LADDER[LADDER.len() - 1].1);
        RateController {
            path,
            budget,
            target,
            quality,
            better_since: None,
            delay: None,
            base: (None, None, None),
            last_decrease: None,
            last_increase: None,
            next_frame: None,
            sent_window: (None, 0),
            sent_rate: 0,
            acked_window: (None, 0),
            acked_rate: 0,
            congested: false,
            slow_start: true,
            late_in_a_row: 0,
            last_ack: None,
            last_send: None,
        }
    }

    /// The path can't carry video: send nothing.
    pub fn paused(&self) -> bool {
        self.budget.is_none()
    }

    pub fn bitrate(&self) -> u32 {
        self.target
    }

    pub fn quality(&self) -> Quality {
        self.quality
    }

    pub fn path(&self) -> Option<PathKind> {
        self.path
    }

    /// What we actually sent over the last second (bits/s).
    pub fn sent_rate(&self) -> u32 {
        self.sent_rate
    }

    /// Smoothed queueing delay of what we send.
    pub fn queue_delay(&self) -> Option<Duration> {
        self.delay
    }

    /// One line for debugging.
    pub fn debug_line(&self) -> String {
        format!(
            "target {} sent {} acked {} delay {:?} slow_start {} quality {}x{}@{}",
            self.target,
            self.sent_rate,
            self.acked_rate,
            self.delay,
            self.slow_start,
            self.quality.width,
            self.quality.height,
            self.quality.fps
        )
    }

    /// The path in use changed: start over from its budget.
    pub fn set_path(&mut self, path: Option<PathKind>, now: Instant) {
        if path == self.path {
            return;
        }
        self.path = path;
        self.budget = budget(path);
        if let Some(b) = self.budget {
            // a different path: what we learned about the old one doesn't hold
            self.target = b.start.min(b.max);
            self.slow_start = true;
            self.quality = quality_for(self.target, b.best);
            self.better_since = None;
            self.delay = None;
            self.base = (None, None, None);
            self.last_decrease = Some(now);
        } else {
            self.target = 0;
        }
    }

    /// A picture is ready: send it, or skip it? `pending_bytes` is encoded
    /// but not yet handed to QUIC; `oldest` is how long the oldest frame
    /// handed to QUIC has gone unacknowledged.
    pub fn admit(&mut self, now: Instant, pending_bytes: u64, oldest: Option<Duration>, rtt: Duration) -> Admit {
        if self.paused() {
            return Admit::Congested;
        }
        let interval = Duration::from_secs_f64(1.0 / self.quality.fps as f64);
        // a little slack: capture clocks jitter
        if self.next_frame.is_some_and(|t| now + interval / 8 < t) {
            return Admit::NotYet;
        }
        if oldest.is_some_and(|a| a > rtt + MAX_STUCK) {
            self.congested = true;
            return Admit::Congested;
        }
        let budget_bytes = (self.target as f64 / 8.0 * MAX_QUEUED.as_secs_f64()) as u64;
        if pending_bytes > budget_bytes.max(8_000) {
            return Admit::Backlog;
        }
        // pace from the ideal schedule (so a 30 fps camera still gives 30),
        // restarting it after a pause
        self.next_frame = Some(match self.next_frame {
            Some(t) if now.duration_since(t) < interval => t + interval,
            _ => now + interval,
        });
        Admit::Send
    }

    /// A frame of `bytes` went out.
    pub fn on_sent(&mut self, now: Instant, bytes: usize) {
        // idle for a while (camera off): what we knew is stale; start low
        // again, as TCP does after idle (RFC 2861)
        if self.last_send.is_some_and(|t| now.duration_since(t) > IDLE_RESTART)
            && let Some(b) = self.budget
            && self.target > b.start
        {
            self.target = b.start;
            self.quality = quality_for(self.target, b.best);
            self.slow_start = true;
            self.delay = None;
        }
        self.last_send = Some(now);
        let (start, n) = &mut self.sent_window;
        let s = *start.get_or_insert(now);
        *n += bytes as u64;
        let span = now.duration_since(s);
        if span >= Duration::from_secs(1) {
            self.sent_rate = (*n as f64 * 8.0 / span.as_secs_f64()) as u32;
            *start = Some(now);
            *n = 0;
        }
    }

    /// The other side acknowledged a whole frame of `bytes` (what gets
    /// through, and evidence the path is in use).
    pub fn on_acked(&mut self, now: Instant, bytes: usize) {
        let (start, n) = &mut self.acked_window;
        let s = *start.get_or_insert(now);
        *n += bytes as u64;
        let span = now.duration_since(s);
        if span >= Duration::from_millis(500) {
            self.acked_rate = (*n as f64 * 8.0 / span.as_secs_f64()) as u32;
            *start = Some(now);
            *n = 0;
        }
        self.last_ack = Some(now);
    }

    /// The path's smoothed RTT now (QUIC's, which already leaves out the
    /// receiver's delayed-ACK time). Above the lowest RTT seen lately (the
    /// base), the excess is queueing: video's and everything else's,
    /// audio included.
    pub fn on_rtt(&mut self, now: Instant, rtt: Duration) {
        if rtt.is_zero() {
            return;
        }
        // the base: min over the last 5–10 s (so it follows a path change)
        let (cur, prev, since) = &mut self.base;
        if since.is_none_or(|t| now.duration_since(t) > BASE_PERIOD) {
            *prev = cur.take();
            *since = Some(now);
        }
        *cur = Some(cur.map_or(rtt, |c| c.min(rtt)));
        let base = match (*cur, *prev) {
            (Some(c), Some(p)) => c.min(p),
            (Some(c), None) => c,
            _ => rtt,
        };
        let q = rtt.saturating_sub(base);
        // (two in a row: one blip on a busy machine isn't a full path)
        if self.slow_start && q > SLOW_START_EXIT {
            self.late_in_a_row += 1;
            if self.late_in_a_row >= 2 {
                self.slow_start = false;
                self.congested = true;
            }
        } else {
            self.late_in_a_row = 0;
        }
        self.delay = Some(match self.delay {
            None => q,
            Some(d) => d.mul_f64(0.7) + q.mul_f64(0.3),
        });
    }

    /// Re-evaluate the bitrate and quality (call every ~100 ms). Returns the
    /// new quality if it changed.
    pub fn tick(&mut self, now: Instant, rtt: Duration) -> Option<Quality> {
        let b = self.budget?;
        let delay = self.delay.unwrap_or_default();
        let since = |t: Option<Instant>| t.map(|t| now.duration_since(t)).unwrap_or(Duration::MAX);
        let congested = std::mem::take(&mut self.congested);
        // raising the rate needs evidence: frames getting through right now
        let evidence = since(self.last_ack) < Duration::from_millis(500);
        if delay > DELAY_HIGH || congested {
            if since(self.last_decrease) > (rtt * 2).max(Duration::from_millis(300)) {
                self.slow_start = false;
                let mut t = self.target as f64 * 0.75;
                // what got through while the queue built is what the path
                // carries (but never more than halve at once: ACK timing is noisy)
                if self.acked_rate > 0 {
                    t = t.min(self.acked_rate as f64 * 0.85).max(self.target as f64 * 0.5);
                }
                self.target = (t as u32).max(MIN_BPS.min(b.max));
                self.last_decrease = Some(now);
                // what we measured belonged to the old rate
                self.delay = self.delay.map(|d| d / 2);
            }
        } else if !evidence {
            // nothing to go on
        } else if self.slow_start && delay < DELAY_LOW && since(self.last_increase) > SLOW_START_EVERY && self.target < b.max {
            self.target = ((self.target as f64 * 1.4) as u32).min(b.max);
            self.last_increase = Some(now);
        } else if delay < DELAY_LOW
            && since(self.last_decrease) > HOLD_AFTER_DECREASE
            && since(self.last_increase) > INCREASE_EVERY
            && self.target < b.max
            // probe upwards while we're sending near the target, or while
            // queues are near empty (simple pictures don't fill the budget,
            // and resolution follows the budget)
            && (self.sent_rate as f64 >= self.target as f64 * 0.5 || delay < DELAY_LOW / 3 || self.target < b.start)
        {
            self.target = ((self.target as f64 * 1.12) as u32).min(b.max);
            self.last_increase = Some(now);
        }
        let want = quality_for(self.target, b.best);
        if want.pixels() < self.quality.pixels() || (want.pixels() == self.quality.pixels() && want != self.quality) {
            self.quality = want;
            self.better_since = None;
            return Some(want);
        }
        // Going up costs a keyframe at the bigger size, a burst: only with
        // room to spare (30% over the rung) and queues near empty.
        let want = quality_for((self.target as f64 / UPGRADE_MARGIN) as u32, b.best);
        if want.pixels() > self.quality.pixels() && delay < DELAY_LOW {
            let hold = if self.slow_start { UPGRADE_AFTER_START } else { UPGRADE_AFTER };
            match self.better_since {
                Some(t) if now.duration_since(t) >= hold => {
                    self.quality = want;
                    self.better_since = None;
                    return Some(want);
                }
                Some(_) => {}
                None => self.better_since = Some(now),
            }
        } else {
            self.better_since = None;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(20);

    #[test]
    fn every_kind_of_path_has_a_budget() {
        let best = |k| budget(Some(k)).map(|b| (b.best.height, b.max));
        assert_eq!(best(PathKind::Ethernet), Some((720, 2_500_000)));
        assert_eq!(best(PathKind::Network), Some((720, 2_500_000)));
        assert_eq!(best(PathKind::Uwb), Some((720, 1_200_000)), "6.8 Mbit/s UWB: 720p within a quarter of it");
        assert_eq!(best(PathKind::Other), Some((720, 2_000_000)));
        assert_eq!(best(PathKind::PeerWifi), Some((480, 1_000_000)));
        assert_eq!(best(PathKind::WifiDirect), best(PathKind::PeerWifi), "Wi-Fi Direct like AWDL");
        assert_eq!(best(PathKind::Relay), Some((360, 500_000)));
        assert_eq!(best(PathKind::Bluetooth), None, "paused");
        assert_eq!(best(PathKind::Ieee802154), None, "paused");
        for k in PathKind::ALL {
            if let Some(b) = budget(Some(k)) {
                assert!(b.start <= b.max && b.max >= MIN_BPS, "{k:?}");
            }
        }
    }

    #[test]
    fn ladder_and_caps() {
        assert_eq!(quality_for(3_000_000, LADDER[0].1), Quality::new(1280, 720, 30));
        assert_eq!(quality_for(3_000_000, LADDER[1].1), Quality::new(848, 480, 30), "peer Wi-Fi tops out at 480p");
        assert_eq!(quality_for(400_000, LADDER[0].1), Quality::new(640, 360, 24));
        assert_eq!(quality_for(10_000, LADDER[0].1), Quality::new(160, 90, 5));
        assert!(RateController::new(Some(PathKind::Bluetooth)).paused());
        assert!(!RateController::new(Some(PathKind::Relay)).paused());
        assert_eq!(budget(Some(PathKind::Relay)).unwrap().best.height, 360);
    }

    /// A clean fast path: the bitrate climbs to the cap and the picture to
    /// 720p, within a few seconds.
    #[test]
    fn ramps_up_on_a_clean_path() {
        let mut c = RateController::new(Some(PathKind::Network));
        let t0 = Instant::now();
        let mut now = t0;
        for _ in 0..50 {
            now += Duration::from_millis(100);
            c.on_sent(now, (c.bitrate() / 8 / 10) as usize);
            c.on_acked(now, 1000);
            c.on_rtt(now, RTT + Duration::from_millis(5));
            c.tick(now, RTT);
        }
        assert_eq!(c.bitrate(), 2_500_000, "full rate after 5 s");
        for _ in 0..300 {
            now += Duration::from_millis(100);
            c.on_sent(now, (c.bitrate() / 8 / 10) as usize);
            c.on_acked(now, 1000);
            c.on_rtt(now, RTT + Duration::from_millis(5));
            c.tick(now, RTT);
        }
        assert_eq!(c.bitrate(), 2_500_000);
        assert_eq!(c.quality(), Quality::new(1280, 720, 30));
    }

    /// Queueing builds: back off quickly, and drop resolution with it.
    #[test]
    fn backs_off_when_frames_queue() {
        let mut c = RateController::new(Some(PathKind::Network));
        let mut now = Instant::now();
        // a clean path first (to learn its base delay), then queues build
        for _ in 0..30 {
            now += Duration::from_millis(100);
            c.on_acked(now, 30_000);
            c.on_rtt(now, RTT);
            c.tick(now, RTT);
        }
        let start = c.bitrate();
        for _ in 0..20 {
            now += Duration::from_millis(100);
            c.on_acked(now, 1000);
            c.on_rtt(now, RTT + Duration::from_millis(400));
            c.tick(now, RTT);
        }
        assert!(c.bitrate() < start / 3, "{} → {}", start, c.bitrate());
        assert!(c.quality().height <= 360, "{:?}", c.quality());
    }

    #[test]
    fn upgrades_resolution_only_after_holding() {
        let mut c = RateController::new(Some(PathKind::PeerWifi));
        let mut now = Instant::now();
        // squeeze to the bottom
        c.on_acked(now, 1000);
            c.on_rtt(now, RTT);
        for _ in 0..30 {
            now += Duration::from_millis(100);
            c.on_acked(now, 1000);
            c.on_rtt(now, Duration::from_millis(600));
            c.tick(now, RTT);
        }
        let low = c.quality();
        let mut switches = 0;
        for _ in 0..400 {
            now += Duration::from_millis(100);
            c.on_sent(now, (c.bitrate() / 80) as usize);
            c.on_acked(now, 1000);
            c.on_rtt(now, RTT);
            if c.tick(now, RTT).is_some() {
                switches += 1;
            }
        }
        assert!(c.quality().pixels() > low.pixels());
        assert_eq!(c.quality(), Quality::new(848, 480, 30), "capped at 480p on peer Wi-Fi");
        assert!(switches <= 5, "no flapping: {switches} switches");
    }

    #[test]
    fn no_ramp_without_traffic() {
        let mut c = RateController::new(Some(PathKind::Network));
        let mut now = Instant::now();
        let start = c.bitrate();
        for _ in 0..100 {
            now += Duration::from_millis(100);
            c.tick(now, RTT);
        }
        assert_eq!(c.bitrate(), start, "no frames, no evidence, no increase");
        // ramp, then go idle: restarts low
        for _ in 0..50 {
            now += Duration::from_millis(100);
            c.on_sent(now, 10_000);
            c.on_acked(now, 10_000);
            c.on_rtt(now, RTT);
            c.tick(now, RTT);
        }
        assert!(c.bitrate() > start * 4);
        now += Duration::from_secs(5);
        c.on_sent(now, 1000);
        assert_eq!(c.bitrate(), start, "after idle, start over");
    }

    #[test]
    fn paces_frames_and_skips_when_backed_up() {
        let mut c = RateController::new(Some(PathKind::Network));
        let mut now = Instant::now();
        let fps = c.quality().fps;
        let (mut sent, mut not_yet) = (0, 0);
        // a 60 fps camera for one second
        for _ in 0..60 {
            match c.admit(now, 0, None, RTT) {
                Admit::Send => sent += 1,
                Admit::NotYet => not_yet += 1,
                Admit::Backlog | Admit::Congested => unreachable!(),
            }
            now += Duration::from_micros(16_667);
        }
        assert!((sent - fps as i32).abs() <= 2, "sent {sent} at {fps} fps");
        assert!(not_yet > 20);
        now += Duration::from_secs(1);
        assert_eq!(c.admit(now, 10_000_000, Some(Duration::from_millis(50)), RTT), Admit::Backlog);
        assert_eq!(c.admit(now, 0, Some(Duration::from_secs(2)), RTT), Admit::Congested, "a frame stuck in flight");
    }

    #[test]
    fn path_changes() {
        let mut c = RateController::new(Some(PathKind::Network));
        let now = Instant::now();
        c.set_path(Some(PathKind::Bluetooth), now);
        assert!(c.paused());
        assert_eq!(c.admit(now, 0, None, RTT), Admit::Congested);
        c.set_path(Some(PathKind::PeerWifi), now);
        assert!(!c.paused());
        assert_eq!(c.bitrate(), START, "a new path starts low");
        assert!(c.quality().height <= 480);
    }
}
