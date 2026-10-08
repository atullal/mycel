//! Adaptive bitrate: pick the Opus bitrate from the path in use and what the
//! receiver reports (loss) plus the path's RTT.
//!
//! Every path has a ceiling: fast local paths 32 kbps, the internet relay
//! 24 kbps, Bluetooth LE 12 kbps (its real throughput is ~15–60 KB/s shared
//! with everything else; 12 kbps Opus is ~1.5 KB/s, ~4 KB/s with headers).
//! A path change jumps straight to the new ceiling. Loss or a very high RTT
//! steps down multiplicatively; a clean stretch steps back up slowly.

use std::time::{Duration, Instant};

use mycel_net::PathKind;

pub const FLOOR: u32 = 8_000;

pub fn ceiling(kind: PathKind) -> u32 {
    match kind {
        PathKind::Network | PathKind::PeerWifi => 32_000,
        // mesh hops may be Bluetooth: start lower; loss and RTT steer it from there
        PathKind::Relay | PathKind::Mesh => 24_000,
        PathKind::Bluetooth => 12_000,
    }
}

/// What the controller learns about the last interval.
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub path: Option<PathKind>,
    /// Fraction of frames the receiver didn't get (0..1).
    pub loss: f32,
    pub rtt: Duration,
}

pub struct BitrateController {
    path: Option<PathKind>,
    current: u32,
    last_down: Option<Instant>,
    clean_since: Option<Instant>,
    last_up: Option<Instant>,
}

impl BitrateController {
    pub fn new(path: Option<PathKind>) -> BitrateController {
        BitrateController {
            path,
            current: ceiling(path.unwrap_or(PathKind::Network)),
            last_down: None,
            clean_since: None,
            last_up: None,
        }
    }

    pub fn bitrate(&self) -> u32 {
        self.current
    }

    /// Expected loss in percent, for Opus FEC.
    pub fn fec_loss_percent(loss: f32) -> u8 {
        ((loss * 100.0).ceil() as i32 + 2).clamp(0, 30) as u8
    }

    /// Feed one observation; returns the new bitrate if it changed.
    pub fn update(&mut self, now: Instant, obs: Observation) -> Option<u32> {
        let before = self.current;
        if let Some(kind) = obs.path
            && self.path != Some(kind)
        {
            self.path = Some(kind);
            self.current = ceiling(kind);
            self.clean_since = None;
            self.last_down = Some(now);
        }
        let top = ceiling(self.path.unwrap_or(PathKind::Network));
        self.current = self.current.min(top);

        let can_step_down = |gap: u64| self.last_down.is_none_or(|t| now - t >= Duration::from_secs(gap));
        let congested = obs.rtt > Duration::from_millis(500);
        if obs.loss > 0.10 && can_step_down(1) {
            self.current = ((self.current as f32 * 0.7) as u32).max(FLOOR);
            self.last_down = Some(now);
            self.clean_since = None;
        } else if (obs.loss > 0.03 || congested) && can_step_down(2) {
            self.current = ((self.current as f32 * 0.85) as u32).max(FLOOR);
            self.last_down = Some(now);
            self.clean_since = None;
        } else if obs.loss < 0.01 && !congested {
            let since = *self.clean_since.get_or_insert(now);
            let steady = now - since >= Duration::from_secs(5);
            let paced = self.last_up.is_none_or(|t| now - t >= Duration::from_secs(2));
            if steady && paced && self.current < top {
                self.current = (self.current + 2_000).min(top);
                self.last_up = Some(now);
            }
        } else {
            self.clean_since = None;
        }
        (self.current != before).then_some(self.current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(path: PathKind, loss: f32, rtt_ms: u64) -> Observation {
        Observation { path: Some(path), loss, rtt: Duration::from_millis(rtt_ms) }
    }

    #[test]
    fn path_sets_the_ceiling() {
        let t = Instant::now();
        let mut c = BitrateController::new(Some(PathKind::PeerWifi));
        assert_eq!(c.bitrate(), 32_000);
        assert_eq!(c.update(t, obs(PathKind::Bluetooth, 0.0, 80)), Some(12_000), "Bluetooth: straight down");
        assert_eq!(c.update(t + Duration::from_secs(1), obs(PathKind::Relay, 0.0, 80)), Some(24_000));
        assert_eq!(c.update(t + Duration::from_secs(2), obs(PathKind::Network, 0.0, 5)), Some(32_000), "back up at once");
    }

    #[test]
    fn loss_steps_down_and_clean_time_steps_back_up() {
        let t = Instant::now();
        let mut c = BitrateController::new(Some(PathKind::Network));
        let s = |n: u64| t + Duration::from_secs(n);
        assert_eq!(c.update(s(1), obs(PathKind::Network, 0.2, 20)), Some(22_400));
        assert_eq!(c.update(s(1), obs(PathKind::Network, 0.2, 20)), None, "at most one step per second");
        assert_eq!(c.update(s(2), obs(PathKind::Network, 0.2, 20)), Some(15_680));
        for i in 3..20 {
            c.update(s(i), obs(PathKind::Network, 0.25, 20));
        }
        assert_eq!(c.bitrate(), FLOOR, "never below the floor");
        // clean again: nothing for 5 s, then +2 kbps every 2 s
        assert_eq!(c.update(s(20), obs(PathKind::Network, 0.0, 20)), None);
        assert_eq!(c.update(s(24), obs(PathKind::Network, 0.0, 20)), None);
        assert_eq!(c.update(s(25), obs(PathKind::Network, 0.0, 20)), Some(10_000));
        assert_eq!(c.update(s(26), obs(PathKind::Network, 0.0, 20)), None);
        assert_eq!(c.update(s(27), obs(PathKind::Network, 0.0, 20)), Some(12_000));
        for i in 28..80 {
            c.update(s(i), obs(PathKind::Network, 0.0, 20));
        }
        assert_eq!(c.bitrate(), 32_000, "recovers to the path's ceiling and stops there");
    }

    #[test]
    fn high_rtt_counts_as_congestion() {
        let t = Instant::now();
        let mut c = BitrateController::new(Some(PathKind::Relay));
        assert_eq!(c.update(t + Duration::from_secs(3), obs(PathKind::Relay, 0.0, 900)), Some(20_400));
    }

    #[test]
    fn fec_tracks_loss() {
        assert_eq!(BitrateController::fec_loss_percent(0.0), 2);
        assert_eq!(BitrateController::fec_loss_percent(0.12), 14);
        assert_eq!(BitrateController::fec_loss_percent(0.9), 30);
    }
}
