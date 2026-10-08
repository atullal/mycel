//! The connection state machine, free of any Bluetooth API so it can be
//! tested with fake radios. A platform backend feeds it [`Input`]s (what the
//! radio reported) and carries out the [`Cmd`]s it returns.
//!
//! Every device is both a peripheral (advertising, accepting L2CAP channels)
//! and a central (scanning, dialing). To get exactly one channel per pair of
//! devices, only the device with the *lower* node key dials; the other reads
//! the key over GATT, hangs up and waits. If the expected channel doesn't show
//! up (the lower-key device can't see us), the higher one dials after
//! [`DIAL_ANYWAY`]; if two channels do appear, both ends keep the same one
//! (see [`Core::prefer_new`]) and close the other.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mycel_crypto::SignPk;

use crate::wire::GattInfo;

/// A remote peripheral as the platform names it (CoreBluetooth: the
/// peripheral's identifier UUID).
pub type Pid = String;
/// A live L2CAP channel, numbered by the platform.
pub type ChanId = u64;

/// Give up on a pending BLE connection (the peripheral's address may have
/// rotated; scanning will find it again under a new identifier).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Reading GATT or opening the L2CAP channel takes at most this long.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
/// A new channel must say hello within this long.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The higher-key device dials anyway after waiting this long for the
/// lower-key one.
pub const DIAL_ANYWAY: Duration = Duration::from_secs(20);
/// Restart scanning this often, so peripherals that went away and came back
/// (or rotated their address) are reported again. Scans don't report
/// duplicates, which is what keeps the radio mostly idle in between.
pub const RESCAN_EVERY: Duration = Duration::from_secs(30);
/// A peripheral seen this recently is assumed to still be in range.
pub const RECENT: Duration = Duration::from_secs(75);
/// Forget peripherals not seen for this long.
pub const FORGET_AFTER: Duration = Duration::from_secs(180);
const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// What the radio reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Scanning saw a Mycel peripheral.
    Discovered(Pid),
    Connected(Pid),
    ConnectFailed(Pid),
    /// The BLE connection to a peripheral ended (for any reason).
    Disconnected(Pid),
    /// Read the peripheral's GATT info.
    Info(Pid, GattInfo),
    InfoFailed(Pid),
    /// An L2CAP channel opened: dialed by us over `pid`, or (`pid: None`)
    /// accepted by our peripheral.
    ChannelOpened { chan: ChanId, pid: Option<Pid> },
    OpenFailed(Pid),
    /// The first frame on a channel named the node at the other end.
    Hello { chan: ChanId, key: SignPk, name: String },
    /// The platform saw the channel close (stream ended or failed).
    ChannelClosed(ChanId),
    /// Periodic housekeeping (every couple of seconds).
    Tick,
    /// Bluetooth went off / unauthorized: every peripheral and channel is gone.
    RadioDown,
}

/// What the platform (or the hub) must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Open (or keep pending) a BLE connection to the peripheral.
    Connect(Pid),
    /// Cancel the connection or pending connection.
    Disconnect(Pid),
    /// Drop the platform's handle to the peripheral.
    Forget(Pid),
    /// Discover the Mycel service and read its info characteristic.
    ReadInfo(Pid),
    OpenChannel(Pid, u16),
    CloseChannel(ChanId),
    /// Stop and restart scanning.
    Rescan,
    /// Packets for `key` go out on `chan` from now on.
    Route { key: SignPk, chan: ChanId },
    Unroute { key: SignPk },
    /// Tell the node: `key` is reachable / no longer reachable.
    Found { key: SignPk, name: String },
    Lost { key: SignPk },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Known, not connected. Dial when due (if we are the dialer).
    Idle,
    Connecting(Instant),
    Reading(Instant),
    Opening(Instant),
    /// Our channel runs over this connection.
    Linked,
    /// The peer has the higher-priority role and dials us; we wait.
    Standby,
}

#[derive(Debug)]
struct Periph {
    phase: Phase,
    key: Option<SignPk>,
    seen: Instant,
    failures: u32,
    retry_at: Option<Instant>,
    /// When we started waiting for this (higher-priority) peer to dial us.
    standby_since: Option<Instant>,
}

#[derive(Debug)]
struct Chan {
    /// `Some`: we dialed it over this peripheral.
    pid: Option<Pid>,
    /// Expected (dialed) or announced (hello) node key.
    key: Option<SignPk>,
    hello: bool,
    opened: Instant,
}

pub struct Core {
    me: SignPk,
    periphs: HashMap<Pid, Periph>,
    chans: HashMap<ChanId, Chan>,
    /// The one channel carrying packets for each reachable node.
    active: HashMap<SignPk, ChanId>,
    last_scan: Instant,
}

fn backoff(failures: u32) -> Duration {
    (BACKOFF_BASE * (1u32 << failures.min(5))).min(BACKOFF_MAX)
}

impl Core {
    pub fn new(me: SignPk, now: Instant) -> Self {
        Core { me, periphs: HashMap::new(), chans: HashMap::new(), active: HashMap::new(), last_scan: now }
    }

    /// Nodes currently reachable.
    pub fn peers(&self) -> usize {
        self.active.len()
    }

    pub fn is_active(&self, key: &SignPk) -> bool {
        self.active.contains_key(key)
    }

    pub fn handle(&mut self, now: Instant, input: Input) -> Vec<Cmd> {
        let mut out = Vec::new();
        match input {
            Input::Discovered(pid) => {
                let p = self.periphs.entry(pid.clone()).or_insert(Periph {
                    phase: Phase::Idle,
                    key: None,
                    seen: now,
                    failures: 0,
                    retry_at: None,
                    standby_since: None,
                });
                p.seen = now;
                self.maybe_dial(&pid, now, &mut out);
            }
            Input::Connected(pid) => match self.periphs.get_mut(&pid) {
                Some(p) if matches!(p.phase, Phase::Connecting(_)) => {
                    p.phase = Phase::Reading(now);
                    out.push(Cmd::ReadInfo(pid));
                }
                // a connection we no longer want (raced with a cancel)
                _ => out.push(Cmd::Disconnect(pid)),
            },
            Input::Info(pid, info) => self.on_info(pid, info, now, &mut out),
            Input::ConnectFailed(pid) | Input::InfoFailed(pid) | Input::OpenFailed(pid) => {
                self.fail(&pid, now, &mut out);
            }
            Input::Disconnected(pid) => {
                let Some(p) = self.periphs.get(&pid) else { return out };
                match p.phase {
                    Phase::Idle | Phase::Standby => {}
                    Phase::Linked => {
                        let gone: Vec<ChanId> = self
                            .chans
                            .iter()
                            .filter(|(_, c)| c.pid.as_ref() == Some(&pid))
                            .map(|(id, _)| *id)
                            .collect();
                        for c in gone {
                            out.push(Cmd::CloseChannel(c));
                            self.channel_gone(c, now, &mut out);
                        }
                        if let Some(p) = self.periphs.get_mut(&pid) {
                            p.phase = Phase::Idle;
                            p.retry_at = Some(now + BACKOFF_BASE);
                        }
                    }
                    Phase::Connecting(_) | Phase::Reading(_) | Phase::Opening(_) => {
                        self.fail(&pid, now, &mut out);
                    }
                }
            }
            Input::ChannelOpened { chan, pid } => {
                let key = pid.as_ref().and_then(|p| self.periphs.get(p)).and_then(|p| p.key);
                if let Some(p) = pid.as_ref().and_then(|p| self.periphs.get_mut(p)) {
                    p.phase = Phase::Linked;
                }
                self.chans.insert(chan, Chan { pid, key, hello: false, opened: now });
            }
            Input::Hello { chan, key, name } => self.on_hello(chan, key, name, now, &mut out),
            Input::ChannelClosed(chan) => self.channel_gone(chan, now, &mut out),
            Input::Tick => self.tick(now, &mut out),
            Input::RadioDown => {
                let all: Vec<ChanId> = self.chans.keys().copied().collect();
                for c in all {
                    self.channel_gone(c, now, &mut out);
                }
                self.periphs.clear();
                out.retain(|c| !matches!(c, Cmd::Disconnect(_)));
            }
        }
        out
    }

    /// Whether we should dial `key` (rather than wait to be dialed).
    fn should_dial(&self, key: &SignPk, p: &Periph, now: Instant) -> bool {
        if *key == self.me || self.active.contains_key(key) {
            return false;
        }
        self.me < *key || p.standby_since.is_some_and(|t| now.duration_since(t) >= DIAL_ANYWAY)
    }

    fn maybe_dial(&mut self, pid: &Pid, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get(pid) else { return };
        let due = match p.phase {
            Phase::Idle => p.retry_at.is_none_or(|t| t <= now) && p.key.is_none_or(|k| self.should_dial(&k, p, now)),
            Phase::Standby => p.key.is_some_and(|k| self.should_dial(&k, p, now)),
            _ => false,
        };
        if due {
            let p = self.periphs.get_mut(pid).expect("present");
            p.phase = Phase::Connecting(now);
            out.push(Cmd::Connect(pid.clone()));
        }
    }

    fn fail(&mut self, pid: &Pid, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get_mut(pid) else { return };
        if !matches!(p.phase, Phase::Idle | Phase::Standby) {
            out.push(Cmd::Disconnect(pid.clone()));
        }
        p.failures = p.failures.saturating_add(1);
        p.retry_at = Some(now + backoff(p.failures));
        p.phase = Phase::Idle;
    }

    fn on_info(&mut self, pid: Pid, info: GattInfo, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get(&pid) else {
            out.push(Cmd::Disconnect(pid));
            return;
        };
        if !matches!(p.phase, Phase::Reading(_)) {
            return;
        }
        let key = info.key;
        // The same node under an older identifier (its address rotated):
        // keep only this one, unless the old one carries our live channel.
        let others: Vec<(Pid, Phase)> = self
            .periphs
            .iter()
            .filter(|(id, o)| **id != pid && o.key == Some(key))
            .map(|(id, o)| (id.clone(), o.phase))
            .collect();
        let linked_elsewhere = others.iter().any(|(_, ph)| *ph == Phase::Linked);
        if !linked_elsewhere {
            for (id, ph) in others {
                if !matches!(ph, Phase::Idle | Phase::Standby) {
                    out.push(Cmd::Disconnect(id.clone()));
                }
                out.push(Cmd::Forget(id.clone()));
                self.periphs.remove(&id);
            }
        }
        let p = self.periphs.get_mut(&pid).expect("present");
        p.key = Some(key);
        let p = self.periphs.get(&pid).expect("present");
        if !linked_elsewhere && self.should_dial(&key, p, now) {
            let p = self.periphs.get_mut(&pid).expect("present");
            p.phase = Phase::Opening(now);
            out.push(Cmd::OpenChannel(pid, info.psm));
        } else {
            // Ourselves, already linked, or the peer dials us: hang up and wait.
            let me = self.me;
            let p = self.periphs.get_mut(&pid).expect("present");
            p.phase = Phase::Standby;
            if key != me && !self.active.contains_key(&key) {
                p.standby_since.get_or_insert(now);
            }
            out.push(Cmd::Disconnect(pid));
        }
    }

    /// Who dialed a channel.
    fn initiator(&self, c: &Chan) -> Option<SignPk> {
        if c.pid.is_some() { Some(self.me) } else { c.key }
    }

    /// Two channels to the same node: keep the one dialed by the lower key
    /// (both ends compute the same answer); if both were dialed by the same
    /// side, the newer one (the older is probably dead).
    fn prefer_new(&self, new: &Chan, old: &Chan, key: &SignPk) -> bool {
        let lower = self.me.min(*key);
        let new_ok = self.initiator(new) == Some(lower);
        let old_ok = self.initiator(old) == Some(lower);
        if new_ok != old_ok { new_ok } else { true }
    }

    fn on_hello(&mut self, chan: ChanId, key: SignPk, name: String, now: Instant, out: &mut Vec<Cmd>) {
        let Some(c) = self.chans.get_mut(&chan) else { return };
        if c.hello || key == self.me || c.key.is_some_and(|k| k != key) {
            out.push(Cmd::CloseChannel(chan));
            self.channel_gone(chan, now, out);
            return;
        }
        c.key = Some(key);
        c.hello = true;
        let pid = c.pid.clone();
        if let Some(&old) = self.active.get(&key) {
            let keep_new = self.prefer_new(&self.chans[&chan], &self.chans[&old], &key);
            let (loser, winner) = if keep_new { (old, chan) } else { (chan, old) };
            let loser_pid = self.chans[&loser].pid.clone();
            let winner_pid = self.chans[&winner].pid.clone();
            if keep_new {
                self.active.insert(key, chan);
                out.push(Cmd::Route { key, chan });
            }
            out.push(Cmd::CloseChannel(loser));
            self.chans.remove(&loser);
            if let Some(lp) = loser_pid
                && Some(&lp) != winner_pid.as_ref()
                && let Some(p) = self.periphs.get_mut(&lp)
            {
                out.push(Cmd::Disconnect(lp));
                p.phase = Phase::Standby;
            }
        } else {
            self.active.insert(key, chan);
            out.push(Cmd::Route { key, chan });
            out.push(Cmd::Found { key, name });
        }
        // Linked now: stop waiting, and drop dials that would only duplicate it.
        let new_is_proper = self.initiator(&self.chans[&self.active[&key]]) == Some(self.me.min(key));
        let mut cancel = Vec::new();
        for (id, p) in self.periphs.iter_mut().filter(|(_, p)| p.key == Some(key)) {
            p.standby_since = None;
            if Some(id) == pid.as_ref() {
                p.failures = 0;
                continue;
            }
            if new_is_proper && matches!(p.phase, Phase::Connecting(_) | Phase::Reading(_) | Phase::Opening(_)) {
                p.phase = Phase::Standby;
                cancel.push(id.clone());
            }
        }
        out.extend(cancel.into_iter().map(Cmd::Disconnect));
    }

    fn channel_gone(&mut self, chan: ChanId, now: Instant, out: &mut Vec<Cmd>) {
        let Some(c) = self.chans.remove(&chan) else { return };
        if let Some(key) = c.key
            && self.active.get(&key) == Some(&chan)
        {
            self.active.remove(&key);
            out.push(Cmd::Unroute { key });
            out.push(Cmd::Lost { key });
        }
        if let Some(pid) = c.pid
            && let Some(p) = self.periphs.get_mut(&pid)
            && p.phase == Phase::Linked
        {
            // Hang up fully so the next attempt starts clean; retry soon.
            out.push(Cmd::Disconnect(pid));
            p.phase = Phase::Idle;
            if c.hello {
                p.failures = 0;
                p.retry_at = Some(now + BACKOFF_BASE);
            } else {
                p.failures = p.failures.saturating_add(1);
                p.retry_at = Some(now + backoff(p.failures));
            }
        }
    }

    fn tick(&mut self, now: Instant, out: &mut Vec<Cmd>) {
        if now.duration_since(self.last_scan) >= RESCAN_EVERY {
            self.last_scan = now;
            out.push(Cmd::Rescan);
        }
        let stale: Vec<ChanId> = self
            .chans
            .iter()
            .filter(|(_, c)| !c.hello && now.duration_since(c.opened) >= HELLO_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();
        for c in stale {
            out.push(Cmd::CloseChannel(c));
            self.channel_gone(c, now, out);
        }
        let pids: Vec<Pid> = self.periphs.keys().cloned().collect();
        for pid in pids {
            let Some(p) = self.periphs.get_mut(&pid) else { continue };
            let unseen = now.duration_since(p.seen);
            match p.phase {
                Phase::Connecting(t) if now.duration_since(t) >= CONNECT_TIMEOUT => self.fail(&pid, now, out),
                Phase::Reading(t) | Phase::Opening(t) if now.duration_since(t) >= SETUP_TIMEOUT => {
                    self.fail(&pid, now, out)
                }
                Phase::Idle | Phase::Standby if unseen >= FORGET_AFTER => {
                    self.periphs.remove(&pid);
                    out.push(Cmd::Forget(pid));
                }
                Phase::Idle | Phase::Standby if unseen < RECENT => {
                    if p.phase == Phase::Standby
                        && let Some(k) = p.key
                        && k != self.me
                        && !self.active.contains_key(&k)
                    {
                        p.standby_since.get_or_insert(now);
                    }
                    self.maybe_dial(&pid, now, out);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SignPk {
        SignPk([b; 32])
    }

    fn info(k: u8) -> GattInfo {
        GattInfo { psm: 0x80 + k as u16, key: key(k), name: format!("n{k}") }
    }

    #[test]
    fn lower_key_dials_and_links() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        assert_eq!(c.handle(t0, Input::Discovered("p".into())), vec![Cmd::Connect("p".into())]);
        assert_eq!(c.handle(t0, Input::Connected("p".into())), vec![Cmd::ReadInfo("p".into())]);
        assert_eq!(c.handle(t0, Input::Info("p".into(), info(2))), vec![Cmd::OpenChannel("p".into(), 0x82)]);
        assert!(c.handle(t0, Input::ChannelOpened { chan: 7, pid: Some("p".into()) }).is_empty());
        assert_eq!(
            c.handle(t0, Input::Hello { chan: 7, key: key(2), name: "bob".into() }),
            vec![Cmd::Route { key: key(2), chan: 7 }, Cmd::Found { key: key(2), name: "bob".into() }]
        );
        assert_eq!(c.peers(), 1);
        // the channel dies: Lost, hang up, and redial shortly
        assert_eq!(
            c.handle(t0, Input::ChannelClosed(7)),
            vec![Cmd::Unroute { key: key(2) }, Cmd::Lost { key: key(2) }, Cmd::Disconnect("p".into())]
        );
        assert_eq!(c.peers(), 0);
        assert!(c.handle(t0 + Duration::from_secs(1), Input::Tick).is_empty(), "not yet due");
        assert_eq!(c.handle(t0 + Duration::from_secs(3), Input::Tick), vec![Cmd::Connect("p".into())]);
    }

    #[test]
    fn higher_key_waits_then_dials_anyway() {
        let t0 = Instant::now();
        let mut c = Core::new(key(5), t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        // the peer has the lower key: it dials us, so hang up and wait
        assert_eq!(c.handle(t0, Input::Info("p".into(), info(2))), vec![Cmd::Disconnect("p".into())]);
        assert!(c.handle(t0 + Duration::from_secs(10), Input::Tick).is_empty());
        assert!(c.handle(t0 + Duration::from_secs(10), Input::Discovered("p".into())).is_empty());
        // it never did: dial ourselves
        let t1 = t0 + DIAL_ANYWAY;
        assert_eq!(c.handle(t1, Input::Tick), vec![Cmd::Connect("p".into())]);
        c.handle(t1, Input::Connected("p".into()));
        assert_eq!(c.handle(t1, Input::Info("p".into(), info(2))), vec![Cmd::OpenChannel("p".into(), 0x82)]);
    }

    #[test]
    fn higher_key_waiting_is_satisfied_by_incoming_channel() {
        let t0 = Instant::now();
        let mut c = Core::new(key(5), t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(2)));
        c.handle(t0, Input::ChannelOpened { chan: 1, pid: None });
        let out = c.handle(t0, Input::Hello { chan: 1, key: key(2), name: "a".into() });
        assert!(out.contains(&Cmd::Found { key: key(2), name: "a".into() }));
        // linked: no fallback dial, ever
        assert!(c.handle(t0 + DIAL_ANYWAY * 3, Input::Tick).iter().all(|c| matches!(c, Cmd::Rescan)));
    }

    #[test]
    fn duplicate_channels_resolve_the_same_way_on_both_ends() {
        // Both devices dialed each other (the higher one via its fallback).
        // Lower key 1, higher key 9. Each side sees: one channel it dialed and
        // one it accepted. Both must keep the channel dialed by key 1.
        let t0 = Instant::now();
        for order in [false, true] {
            // lower side: chan 10 = dialed by me (1), chan 11 = accepted from 9
            let mut lo = Core::new(key(1), t0);
            lo.handle(t0, Input::Discovered("p9".into()));
            lo.handle(t0, Input::Connected("p9".into()));
            lo.handle(t0, Input::Info("p9".into(), info(9)));
            lo.handle(t0, Input::ChannelOpened { chan: 10, pid: Some("p9".into()) });
            lo.handle(t0, Input::ChannelOpened { chan: 11, pid: None });
            // higher side: chan 20 = accepted from 1 (pairs with lo's 10), 21 = dialed by me
            let mut hi = Core::new(key(9), t0);
            hi.periphs.insert(
                "p1".into(),
                Periph {
                    phase: Phase::Opening(t0),
                    key: Some(key(1)),
                    seen: t0,
                    failures: 0,
                    retry_at: None,
                    standby_since: None,
                },
            );
            hi.handle(t0, Input::ChannelOpened { chan: 21, pid: Some("p1".into()) });
            hi.handle(t0, Input::ChannelOpened { chan: 20, pid: None });
            let (lo_a, lo_b, hi_a, hi_b) = if order { (10, 11, 20, 21) } else { (11, 10, 21, 20) };
            let mut lo_out = lo.handle(t0, Input::Hello { chan: lo_a, key: key(9), name: "".into() });
            lo_out.extend(lo.handle(t0, Input::Hello { chan: lo_b, key: key(9), name: "".into() }));
            let mut hi_out = hi.handle(t0, Input::Hello { chan: hi_a, key: key(1), name: "".into() });
            hi_out.extend(hi.handle(t0, Input::Hello { chan: hi_b, key: key(1), name: "".into() }));
            assert_eq!(lo.active[&key(9)], 10, "lower keeps the channel it dialed (order {order})");
            assert_eq!(hi.active[&key(1)], 20, "higher keeps the channel the lower dialed (order {order})");
            assert!(lo_out.contains(&Cmd::CloseChannel(11)));
            assert!(hi_out.contains(&Cmd::CloseChannel(21)));
            assert!(hi_out.contains(&Cmd::Disconnect("p1".into())), "higher drops its own dial");
            assert_eq!(lo_out.iter().filter(|c| matches!(c, Cmd::Found { .. })).count(), 1);
            assert_eq!(hi_out.iter().filter(|c| matches!(c, Cmd::Lost { .. })).count(), 0, "no flap");
        }
    }

    #[test]
    fn bad_hellos_and_silent_channels_are_closed() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(2)));
        c.handle(t0, Input::ChannelOpened { chan: 1, pid: Some("p".into()) });
        // dialed key 2 but the hello claims key 3
        let out = c.handle(t0, Input::Hello { chan: 1, key: key(3), name: "".into() });
        assert!(out.contains(&Cmd::CloseChannel(1)));
        assert_eq!(c.peers(), 0);
        // an accepted channel claiming to be us
        c.handle(t0, Input::ChannelOpened { chan: 2, pid: None });
        assert!(c.handle(t0, Input::Hello { chan: 2, key: key(1), name: "".into() }).contains(&Cmd::CloseChannel(2)));
        // an accepted channel that never says hello
        c.handle(t0, Input::ChannelOpened { chan: 3, pid: None });
        assert!(c.handle(t0 + HELLO_TIMEOUT, Input::Tick).contains(&Cmd::CloseChannel(3)));
    }

    #[test]
    fn failures_back_off_and_stale_peripherals_are_forgotten() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::ConnectFailed("p".into()));
        // backoff 4s after the first failure
        assert!(!c.handle(t0 + Duration::from_secs(3), Input::Tick).contains(&Cmd::Connect("p".into())));
        assert!(c.handle(t0 + Duration::from_secs(4), Input::Tick).contains(&Cmd::Connect("p".into())));
        // a pending connect that never completes is cancelled
        let out = c.handle(t0 + Duration::from_secs(4) + CONNECT_TIMEOUT, Input::Tick);
        assert!(out.contains(&Cmd::Disconnect("p".into())));
        // not seen for a long time: forgotten
        let out = c.handle(t0 + FORGET_AFTER, Input::Tick);
        assert!(out.contains(&Cmd::Forget("p".into())));
        assert!(c.periphs.is_empty());
    }

    #[test]
    fn rotated_address_replaces_the_old_identifier() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        c.handle(t0, Input::Discovered("old".into()));
        c.handle(t0, Input::ConnectFailed("old".into()));
        c.periphs.get_mut("old").unwrap().key = Some(key(2));
        c.handle(t0, Input::Discovered("new".into()));
        c.handle(t0, Input::Connected("new".into()));
        let out = c.handle(t0, Input::Info("new".into(), info(2)));
        assert!(out.contains(&Cmd::Forget("old".into())));
        assert!(out.contains(&Cmd::OpenChannel("new".into(), 0x82)));
    }

    #[test]
    fn radio_down_loses_everyone() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        c.handle(t0, Input::ChannelOpened { chan: 1, pid: None });
        c.handle(t0, Input::Hello { chan: 1, key: key(4), name: "".into() });
        assert_eq!(c.peers(), 1);
        let out = c.handle(t0, Input::RadioDown);
        assert!(out.contains(&Cmd::Lost { key: key(4) }));
        assert_eq!(c.peers(), 0);
    }

    #[test]
    fn rescans_periodically() {
        let t0 = Instant::now();
        let mut c = Core::new(key(1), t0);
        assert!(c.handle(t0 + Duration::from_secs(1), Input::Tick).is_empty());
        assert_eq!(c.handle(t0 + RESCAN_EVERY, Input::Tick), vec![Cmd::Rescan]);
        assert!(c.handle(t0 + RESCAN_EVERY + Duration::from_secs(1), Input::Tick).is_empty());
    }
}
