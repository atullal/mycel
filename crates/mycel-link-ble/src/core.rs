//! The connection state machine, free of any Bluetooth API so it can be
//! tested with fake radios. A platform backend feeds it [`Input`]s (what the
//! radio reported) and carries out the [`Cmd`]s it returns.
//!
//! Every device is both a peripheral (advertising, accepting L2CAP channels)
//! and a central (scanning, dialing). The rules, learned from two real Macs:
//!
//! - **Both sides dial**, as soon as they see each other (plus a little
//!   jitter). Whichever channel comes up first carries the traffic; a working
//!   connection is never hung up to satisfy a tie-break. After reading the
//!   peer's key, the *higher*-key side waits [`OPEN_DELAY_HIGHER`] before
//!   opening its own channel, so usually only one channel is opened at all.
//! - **Never cancel a BLE connection to a node we have a live channel with.**
//!   Between two Macs both directions share one radio link, and cancelling our
//!   side of it can take down the channel the *peer* opened. A connection we
//!   don't need right now is kept as a spare (`Phase::Spare`); when the
//!   channel dies, a new one opens over the spare at once.
//! - **Two live channels to one node** (both dialed at once): both ends keep
//!   the one dialed by the lower key (`Core::keep_new`). Only the side that
//!   dialed the loser closes it; the other side just stops using it (and
//!   closes it itself after [`DUPLICATE_GRACE`]), so the survivor is never
//!   touched and nobody sees the peer lost.
//! - **Stale handles**: a connect that doesn't complete in [`CONNECT_TIMEOUT`]
//!   is cancelled, the platform's handle dropped, and the peer is dialed again
//!   only after a *fresh* advertisement (CoreBluetooth never completes a
//!   connect to a peripheral object whose address went stale).
//! - **Never give up on a peer we can see**: retries back off to at most
//!   [`BACKOFF_MAX`], scanning restarts every [`RESCAN_EVERY`] so peers are
//!   reported again, and a peer is only forgotten after [`FORGET_AFTER`]
//!   without a single advertisement.
//! - **Restricted** ([`Input::Restrict`], an iPhone with Mycel in the
//!   background): no channel to, or from, a node outside the allowed set.
//!   A device whose GATT key isn't allowed is hung up on right after the
//!   read (the read reveals nothing about us) and not dialed again until
//!   the restriction lifts; live channels to such nodes are closed when it
//!   starts, and one a stranger opens is closed at its hello.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use mycel_crypto::SignPk;

use crate::hub::short;
use crate::info;
use crate::wire::GattInfo;

/// A remote peripheral as the platform names it (CoreBluetooth: the
/// peripheral's identifier UUID).
pub type Pid = String;
/// A live L2CAP channel, numbered by the platform.
pub type ChanId = u64;

/// Give up on a pending BLE connection, drop the handle, and wait for a fresh
/// advertisement (a connect to a stale peripheral never completes).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Reading GATT, or opening the L2CAP channel, takes at most this long.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// A new channel must say hello within this long. (The stream layer also
/// closes a channel that carries no bytes at all for `hub::SILENT_AFTER`.)
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(12);
/// After reading the peer's key, the higher-key side waits this long for the
/// lower-key side's channel before opening its own (usually avoids opening
/// two channels at all; never needed for correctness).
pub const OPEN_DELAY_HIGHER: Duration = Duration::from_millis(1500);
/// A duplicate channel the *peer* dialed and should close; if it is still
/// open after this long, close it ourselves.
pub const DUPLICATE_GRACE: Duration = Duration::from_secs(5);
/// Restart scanning this often, so peripherals are reported again even when
/// the OS filters duplicate advertisements.
pub const RESCAN_EVERY: Duration = Duration::from_secs(10);
/// Extra rescans (to find a fresh handle after a stale one) at most this often.
const RESCAN_SOON: Duration = Duration::from_secs(2);
/// A peripheral advertised this recently is in range: keep (re)dialing it.
pub const RECENT: Duration = Duration::from_secs(15);
/// Forget peripherals not seen for this long.
pub const FORGET_AFTER: Duration = Duration::from_secs(60);
/// Random extra delay before each dial / channel open, so two devices that
/// see each other at the same moment don't keep colliding.
pub const JITTER: Duration = Duration::from_millis(500);
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Retries while a peer is in range never wait longer than this.
pub const BACKOFF_MAX: Duration = Duration::from_secs(10);
/// Channels over one connection that died before saying hello, in a row,
/// before we hang that connection up and reconnect from scratch.
const SPARE_FAILURES_MAX: u32 = 3;
/// Another identifier of the same node advertised this much more recently:
/// dial that one instead.
const NEWER_BY: Duration = Duration::from_secs(2);
/// Log "saw …" again for a peripheral not seen for this long.
const SAW_AGAIN: Duration = Duration::from_secs(30);

/// What the radio reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Scanning saw a Mycel peripheral (an advertisement; may repeat).
    Discovered(Pid),
    Connected(Pid),
    ConnectFailed(Pid),
    /// The BLE connection to a peripheral ended (for any reason).
    Disconnected(Pid),
    /// Read the peripheral's GATT info.
    Info(Pid, GattInfo),
    InfoFailed(Pid),
    /// An L2CAP channel opened: dialed by us over `pid`, or (`pid: None`)
    /// accepted by our peripheral. `chan` is new: platforms never reuse a
    /// channel id.
    ChannelOpened {
        chan: ChanId,
        pid: Option<Pid>,
    },
    OpenFailed(Pid),
    /// The first frame on a channel named the node at the other end.
    Hello {
        chan: ChanId,
        key: SignPk,
        name: String,
    },
    /// The platform saw the channel close (stream ended or failed, or went
    /// silent). Channels *we* close are not reported back.
    ChannelClosed(ChanId),
    /// Periodic housekeeping (about every second).
    Tick,
    /// Bluetooth went off / unauthorized: every peripheral and channel is gone.
    RadioDown,
    /// `Some`: link only with these nodes (the app is in the background:
    /// opening a channel sends our node key, so a stranger advertising
    /// Mycel must not get one). `None`: link with anyone again.
    Restrict(Option<BTreeSet<SignPk>>),
}

/// What the platform (or the hub) must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Open a BLE connection to the peripheral.
    Connect(Pid),
    /// Cancel the connection or pending connection.
    Disconnect(Pid),
    /// Drop the platform's handle to the peripheral (a fresh one comes with
    /// the next advertisement).
    Forget(Pid),
    /// Discover the Mycel service and read its info characteristic.
    ReadInfo(Pid),
    OpenChannel(Pid, u16),
    CloseChannel(ChanId),
    /// Stop and restart scanning.
    Rescan,
    /// Packets for `key` go out on `chan` from now on.
    Route {
        key: SignPk,
        chan: ChanId,
    },
    Unroute {
        key: SignPk,
    },
    /// Tell the node: `key` is reachable / no longer reachable.
    Found {
        key: SignPk,
        name: String,
    },
    Lost {
        key: SignPk,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not connected. Dial when due.
    Idle,
    Connecting(Instant),
    Reading(Instant),
    Opening(Instant),
    /// Our channel runs over this connection.
    Linked,
    /// Connected and the peer's info known, but no channel of ours on it:
    /// the node is linked some other way, or we're giving the peer a moment
    /// to open its channel first. Opens a channel when the node isn't linked
    /// and `retry_at` has passed.
    Spare,
    /// The peripheral is this device. Never dialed.
    Myself,
    /// A node outside the allowed set while restricted: not dialed until
    /// the restriction lifts.
    Stranger,
}

#[derive(Debug)]
struct Periph {
    phase: Phase,
    key: Option<SignPk>,
    psm: Option<u16>,
    seen: Instant,
    failures: u32,
    /// Dial (Idle) or open a channel (Spare) no earlier than this.
    retry_at: Instant,
    /// The platform dropped its handle (a connect hung): wait for a fresh
    /// advertisement before dialing again.
    need_fresh: bool,
}

#[derive(Debug)]
struct Chan {
    /// `Some`: we dialed it over this peripheral.
    pid: Option<Pid>,
    /// Expected (dialed) or announced (hello) node key.
    key: Option<SignPk>,
    hello: bool,
    opened: Instant,
    /// A duplicate the peer dialed and should close (since when).
    doomed: Option<Instant>,
}

pub struct Core {
    me: SignPk,
    periphs: BTreeMap<Pid, Periph>,
    chans: BTreeMap<ChanId, Chan>,
    /// The one channel carrying packets for each reachable node.
    active: BTreeMap<SignPk, ChanId>,
    /// While restricted, the only nodes we link with.
    allowed: Option<BTreeSet<SignPk>>,
    last_scan: Instant,
    rng: u64,
    /// Upper bound of the random delay added to dials (tests set it to 0).
    pub(crate) jitter_max: Duration,
}

fn backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    (BACKOFF_BASE * (1u32 << (failures - 1).min(4))).min(BACKOFF_MAX)
}

/// Short printable form of a peripheral id (the first block of the UUID,
/// matching how bluetoothd logs it).
fn sp(pid: &str) -> &str {
    pid.split('-').next().unwrap_or(pid)
}

fn ms(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

impl Core {
    pub fn new(me: SignPk, now: Instant) -> Self {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write(&me.0);
        Core {
            me,
            periphs: BTreeMap::new(),
            chans: BTreeMap::new(),
            active: BTreeMap::new(),
            allowed: None,
            last_scan: now,
            rng: h.finish() | 1,
            jitter_max: JITTER,
        }
    }

    /// Make the jitter reproducible (simulations).
    #[cfg(test)]
    pub(crate) fn seed(&mut self, seed: u64) {
        self.rng = seed | 1;
    }

    /// Nodes currently reachable.
    pub fn peers(&self) -> usize {
        self.active.len()
    }

    pub fn is_active(&self, key: &SignPk) -> bool {
        self.active.contains_key(key)
    }

    /// Devices in range (advertising recently) that we aren't linked to yet,
    /// counted by node. A peripheral whose key we haven't read yet may well be
    /// a node we're already linked to (linked over a channel it dialed, or
    /// under a rotated address), so those only count beyond the number of
    /// linked nodes: better to under-report briefly than to claim to be
    /// connecting to a device that is linked.
    pub fn connecting(&self, now: Instant) -> usize {
        let mut keys = BTreeSet::new();
        let mut unknown = 0usize;
        for p in self.periphs.values() {
            if matches!(p.phase, Phase::Myself | Phase::Stranger) || now.saturating_duration_since(p.seen) >= RECENT {
                continue;
            }
            match p.key {
                Some(k) if !self.active.contains_key(&k) => {
                    keys.insert(k);
                }
                Some(_) => {}
                None => unknown += 1,
            }
        }
        keys.len() + unknown.saturating_sub(self.active.len())
    }

    fn jitter(&mut self) -> Duration {
        let max = self.jitter_max.as_millis() as u64;
        if max == 0 {
            return Duration::ZERO;
        }
        // xorshift64
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        Duration::from_millis(self.rng % (max + 1))
    }

    /// We may link with `key` (always, unless restricted).
    fn allows(&self, key: &SignPk) -> bool {
        self.allowed.as_ref().is_none_or(|a| a.contains(key))
    }

    /// How long to wait before opening a channel to `key` ourselves.
    fn open_delay(&mut self, key: SignPk) -> Duration {
        let bias = if self.me < key { Duration::ZERO } else { OPEN_DELAY_HIGHER };
        bias + self.jitter()
    }

    pub fn handle(&mut self, now: Instant, input: Input) -> Vec<Cmd> {
        let mut out = Vec::new();
        match input {
            Input::Discovered(pid) => self.on_discovered(pid, now, &mut out),
            Input::Connected(pid) => self.on_connected(pid, now, &mut out),
            Input::ConnectFailed(pid) => {
                if matches!(self.phase(&pid), Some(Phase::Connecting(_))) {
                    self.fail(&pid, "connect failed", now, &mut out);
                }
            }
            Input::InfoFailed(pid) => {
                let Some(p) = self.periphs.get_mut(&pid) else { return out };
                if !matches!(p.phase, Phase::Reading(_)) {
                    return out;
                }
                p.failures = p.failures.saturating_add(1);
                if p.failures < SPARE_FAILURES_MAX {
                    // Read again over the same connection before hanging up
                    // (a cancel may take down the peer's side of the link).
                    info(format_args!("{}: couldn't read its Mycel info; reading again", sp(&pid)));
                    p.phase = Phase::Reading(now);
                    out.push(Cmd::ReadInfo(pid));
                } else {
                    self.fail(&pid, "couldn't read its Mycel info", now, &mut out);
                }
            }
            Input::OpenFailed(pid) => {
                if matches!(self.phase(&pid), Some(Phase::Opening(_))) {
                    self.fail(&pid, "L2CAP channel open failed", now, &mut out);
                }
            }
            Input::Info(pid, info) => self.on_info(pid, info, now, &mut out),
            Input::Disconnected(pid) => self.on_disconnected(pid, now, &mut out),
            Input::ChannelOpened { chan, pid } => self.on_opened(chan, pid, now),
            Input::Hello { chan, key, name } => self.on_hello(chan, key, name, now, &mut out),
            Input::ChannelClosed(chan) => {
                if self.chans.contains_key(&chan) {
                    info(format_args!("channel {chan} gone"));
                }
                self.channel_gone(chan, now, &mut out);
            }
            Input::Tick => self.tick(now, &mut out),
            Input::RadioDown => {
                for key in std::mem::take(&mut self.active).into_keys() {
                    out.push(Cmd::Unroute { key });
                    out.push(Cmd::Lost { key });
                }
                self.chans.clear();
                self.periphs.clear();
            }
            Input::Restrict(peers) => self.on_restrict(peers, now, &mut out),
        }
        out
    }

    fn on_restrict(&mut self, peers: Option<BTreeSet<SignPk>>, now: Instant, out: &mut Vec<Cmd>) {
        self.allowed = peers;
        let Some(allowed) = self.allowed.clone() else {
            info(format_args!("linking with any Mycel device again"));
            let mut pids = Vec::new();
            for (pid, p) in self.periphs.iter_mut().filter(|(_, p)| p.phase == Phase::Stranger) {
                p.phase = Phase::Idle;
                p.retry_at = now;
                pids.push(pid.clone());
            }
            for pid in pids {
                self.maybe_dial(&pid, now, out);
            }
            return;
        };
        info(format_args!("linking only with {} known devices", allowed.len()));
        // Connections first, so closing a stranger's channel below doesn't
        // reopen one over its connection.
        for (pid, p) in &mut self.periphs {
            let Some(k) = p.key.filter(|k| !allowed.contains(k)) else { continue };
            if p.phase == Phase::Myself || p.phase == Phase::Stranger {
                continue;
            }
            if !matches!(p.phase, Phase::Idle) {
                out.push(Cmd::Disconnect(pid.clone()));
            }
            info(format_args!("{}: node {} isn't a known device; hanging up", sp(pid), short(&k)));
            p.phase = Phase::Stranger;
        }
        let strangers: Vec<ChanId> = self
            .chans
            .iter()
            .filter(|(_, c)| c.key.is_some_and(|k| !allowed.contains(&k)))
            .map(|(id, _)| *id)
            .collect();
        for c in strangers {
            self.close(c, "not a known device", now, out);
        }
    }

    fn phase(&self, pid: &Pid) -> Option<Phase> {
        self.periphs.get(pid).map(|p| p.phase)
    }

    /// Another identifier for node `key` (not `pid`) is busy with it.
    fn other_busy(&self, pid: &Pid, key: &SignPk, phases: fn(Phase) -> bool) -> bool {
        self.periphs.iter().any(|(id, o)| id != pid && o.key.as_ref() == Some(key) && phases(o.phase))
    }

    fn on_discovered(&mut self, pid: Pid, now: Instant, out: &mut Vec<Cmd>) {
        let jitter = self.jitter();
        match self.periphs.get_mut(&pid) {
            Some(p) => {
                if now.saturating_duration_since(p.seen) >= SAW_AGAIN {
                    info(format_args!("saw {} again", sp(&pid)));
                }
                p.seen = now;
                if p.need_fresh {
                    p.need_fresh = false;
                    crate::debug(format_args!("fresh advertisement from {}", sp(&pid)));
                }
            }
            None => {
                info(format_args!("saw Mycel device {}", sp(&pid)));
                self.periphs.insert(
                    pid.clone(),
                    Periph {
                        phase: Phase::Idle,
                        key: None,
                        psm: None,
                        seen: now,
                        failures: 0,
                        retry_at: now + jitter,
                        need_fresh: false,
                    },
                );
            }
        }
        self.maybe_dial(&pid, now, out);
    }

    fn on_connected(&mut self, pid: Pid, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get_mut(&pid) else {
            out.push(Cmd::Disconnect(pid));
            return;
        };
        match p.phase {
            Phase::Connecting(t) => {
                info(format_args!("connected to {} in {}; reading its info", sp(&pid), ms(now - t)));
            }
            // A connection we had given up on completed after all: use it.
            Phase::Idle => info(format_args!("connected to {} (late); reading its info", sp(&pid))),
            Phase::Myself | Phase::Stranger => {
                out.push(Cmd::Disconnect(pid));
                return;
            }
            _ => return, // already connected
        }
        p.phase = Phase::Reading(now);
        p.need_fresh = false;
        out.push(Cmd::ReadInfo(pid));
    }

    fn on_disconnected(&mut self, pid: Pid, now: Instant, out: &mut Vec<Cmd>) {
        let jitter = self.jitter();
        let Some(p) = self.periphs.get_mut(&pid) else { return };
        match p.phase {
            // Not connected (a late callback for our own cancel; a pending
            // connect that fails is reported as ConnectFailed).
            Phase::Idle | Phase::Connecting(_) | Phase::Myself | Phase::Stranger => {}
            Phase::Reading(_) | Phase::Opening(_) => {
                p.phase = Phase::Idle;
                p.failures = p.failures.saturating_add(1);
                let wait = backoff(p.failures) + jitter;
                p.retry_at = now + wait;
                info(format_args!("BLE connection to {} dropped during setup; redial in {}", sp(&pid), ms(wait)));
            }
            Phase::Linked | Phase::Spare => {
                p.phase = Phase::Idle;
                p.retry_at = now + jitter;
                info(format_args!("BLE connection to {} dropped; redialing", sp(&pid)));
                let gone: Vec<ChanId> =
                    self.chans.iter().filter(|(_, c)| c.pid.as_ref() == Some(&pid)).map(|(id, _)| *id).collect();
                for c in gone {
                    info(format_args!("channel {c} dropped with the connection"));
                    out.push(Cmd::CloseChannel(c));
                    self.channel_gone(c, now, out);
                }
            }
        }
    }

    /// Dial `pid` if it is due.
    fn maybe_dial(&mut self, pid: &Pid, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get(pid) else { return };
        let due = p.phase == Phase::Idle
            && !p.need_fresh
            && p.retry_at <= now
            && now.saturating_duration_since(p.seen) < RECENT
            && p.key.is_none_or(|k| {
                k != self.me
                    && self.allows(&k)
                    && !self.active.contains_key(&k)
                    && !self.other_busy(pid, &k, |ph| !matches!(ph, Phase::Idle | Phase::Myself))
                    // The node advertises under a newer identifier (its
                    // address rotated): this one would just hang.
                    && !self
                        .periphs
                        .iter()
                        .any(|(id, o)| id != pid && o.key == Some(k) && o.seen > p.seen + NEWER_BY)
            });
        if !due {
            return;
        }
        let p = self.periphs.get_mut(pid).expect("present");
        p.phase = Phase::Connecting(now);
        let who = p.key.map(|k| format!(" (node {})", short(&k))).unwrap_or_default();
        info(format_args!("dialing {}{who}, attempt {}", sp(pid), p.failures + 1));
        out.push(Cmd::Connect(pid.clone()));
    }

    /// Open a channel over spare connection `pid` if the node needs one.
    fn maybe_open(&mut self, pid: &Pid, now: Instant, out: &mut Vec<Cmd>) {
        let Some(p) = self.periphs.get(pid) else { return };
        let (Phase::Spare, Some(k), Some(psm)) = (p.phase, p.key, p.psm) else { return };
        if p.retry_at > now
            || !self.allows(&k)
            || self.active.contains_key(&k)
            || self.other_busy(pid, &k, |ph| matches!(ph, Phase::Opening(_) | Phase::Linked))
        {
            return;
        }
        let p = self.periphs.get_mut(pid).expect("present");
        p.phase = Phase::Opening(now);
        info(format_args!("opening L2CAP channel to {} over {} (psm {psm})", short(&k), sp(pid)));
        out.push(Cmd::OpenChannel(pid.clone(), psm));
    }

    /// A setup step failed (or timed out). Hang up unless the node is linked
    /// anyway (then the connection might share the radio link with the live
    /// channel: keep it as a spare), and retry with backoff.
    fn fail(&mut self, pid: &Pid, why: &str, now: Instant, out: &mut Vec<Cmd>) {
        let jitter = self.jitter();
        let live = self.periphs.get(pid).and_then(|p| p.key).is_some_and(|k| self.active.contains_key(&k));
        let Some(p) = self.periphs.get_mut(pid) else { return };
        p.failures = p.failures.saturating_add(1);
        let wait = backoff(p.failures) + jitter;
        p.retry_at = now + wait;
        let connected = matches!(p.phase, Phase::Reading(_) | Phase::Opening(_) | Phase::Spare | Phase::Linked);
        if live && connected && p.psm.is_some() {
            p.phase = Phase::Spare;
            info(format_args!("{}: {why}; already linked, keeping the connection", sp(pid)));
            return;
        }
        // A channel open that failed over a working connection: try again
        // over it before hanging up (the peer may be about to open its own
        // channel over the same radio link; cancelling could kill that).
        if matches!(p.phase, Phase::Opening(_)) && p.psm.is_some() && p.failures < SPARE_FAILURES_MAX {
            p.phase = Phase::Spare;
            info(format_args!("{}: {why}; retrying over the same connection in {}", sp(pid), ms(wait)));
            return;
        }
        if connected || matches!(p.phase, Phase::Connecting(_)) {
            out.push(Cmd::Disconnect(pid.clone()));
        }
        p.phase = Phase::Idle;
        info(format_args!("{}: {why}; retry in {}", sp(pid), ms(wait)));
    }

    fn on_info(&mut self, pid: Pid, info_rec: GattInfo, now: Instant, out: &mut Vec<Cmd>) {
        if !matches!(self.phase(&pid), Some(Phase::Reading(_))) {
            return;
        }
        let key = info_rec.key;
        if key == self.me {
            info(format_args!("{} is this device; ignoring it", sp(&pid)));
            out.push(Cmd::Disconnect(pid.clone()));
            self.periphs.get_mut(&pid).expect("present").phase = Phase::Myself;
            return;
        }
        if !self.allows(&key) {
            info(format_args!("{} is node {}, not a known device; hanging up", sp(&pid), short(&key)));
            out.push(Cmd::Disconnect(pid.clone()));
            let p = self.periphs.get_mut(&pid).expect("present");
            p.key = Some(key);
            p.phase = Phase::Stranger;
            return;
        }
        // The same node under an older identifier (its address rotated):
        // drop attempts in progress and idle handles; keep live connections.
        let others: Vec<(Pid, Phase)> = self
            .periphs
            .iter()
            .filter(|(id, o)| **id != pid && o.key == Some(key))
            .map(|(id, o)| (id.clone(), o.phase))
            .collect();
        for (id, ph) in others {
            match ph {
                Phase::Connecting(_) | Phase::Reading(_) | Phase::Opening(_) | Phase::Idle | Phase::Stranger => {
                    if !matches!(ph, Phase::Idle | Phase::Stranger) {
                        out.push(Cmd::Disconnect(id.clone()));
                    }
                    info(format_args!("{} replaces {} for node {}", sp(&pid), sp(&id), short(&key)));
                    out.push(Cmd::Forget(id.clone()));
                    self.periphs.remove(&id);
                }
                Phase::Linked | Phase::Spare | Phase::Myself => {}
            }
        }
        let connected_elsewhere = self.other_busy(&pid, &key, |ph| matches!(ph, Phase::Linked | Phase::Spare));
        let linked = self.active.contains_key(&key);
        let delay = self.open_delay(key);
        let me_lower = self.me < key;
        let p = self.periphs.get_mut(&pid).expect("present");
        p.key = Some(key);
        p.psm = Some(info_rec.psm);
        let tag = format!("{} is node {} (psm {})", sp(&pid), short(&key), info_rec.psm);
        if linked || connected_elsewhere {
            // Never hang up: this connection may share the radio link with the
            // channel that already works.
            p.phase = Phase::Spare;
            p.retry_at = now + delay;
            info(format_args!("{tag}: already linked; keeping this connection as a spare"));
        } else if me_lower {
            p.phase = Phase::Opening(now);
            info(format_args!("{tag}: opening L2CAP channel (we have the lower key)"));
            out.push(Cmd::OpenChannel(pid, info_rec.psm));
        } else {
            p.phase = Phase::Spare;
            p.retry_at = now + delay;
            info(format_args!("{tag}: it has the lower key; opening our channel in {} unless it opens one", ms(delay)));
        }
    }

    fn on_opened(&mut self, chan: ChanId, pid: Option<Pid>, now: Instant) {
        let key = pid.as_ref().and_then(|p| self.periphs.get(p)).and_then(|p| p.key);
        if let Some(p) = pid.as_ref().and_then(|p| self.periphs.get_mut(p))
            && matches!(p.phase, Phase::Opening(_) | Phase::Spare)
        {
            p.phase = Phase::Linked;
        }
        match &pid {
            Some(p) => info(format_args!(
                "channel {chan} open (we dialed {} over {}); waiting for its hello",
                key.map(|k| short(&k)).unwrap_or_default(),
                sp(p)
            )),
            None => info(format_args!("channel {chan} open (accepted); waiting for its hello")),
        }
        self.chans.insert(chan, Chan { pid, key, hello: false, opened: now, doomed: None });
    }

    /// Who dialed a channel.
    fn initiator(&self, c: &Chan) -> Option<SignPk> {
        if c.pid.is_some() { Some(self.me) } else { c.key }
    }

    /// Two live channels to node `key`: keep the one dialed by the lower key
    /// (both ends compute the same answer); if the same side dialed both, the
    /// newer one (the older one is probably dying).
    fn keep_new(&self, new: &Chan, old: &Chan, key: &SignPk) -> bool {
        let lower = self.me.min(*key);
        let (ni, oi) = (self.initiator(new), self.initiator(old));
        if ni != oi { ni == Some(lower) } else { true }
    }

    fn on_hello(&mut self, chan: ChanId, key: SignPk, name: String, now: Instant, out: &mut Vec<Cmd>) {
        if !self.allows(&key) {
            self.close(chan, "hello from a device that isn't known", now, out);
            return;
        }
        let Some(c) = self.chans.get_mut(&chan) else { return };
        if c.hello || key == self.me || c.key.is_some_and(|k| k != key) {
            self.close(chan, "unexpected hello", now, out);
            return;
        }
        c.key = Some(key);
        c.hello = true;
        let pid = c.pid.clone();
        let opened = c.opened;
        info(format_args!("channel {chan}: hello from {} after {}", short(&key), ms(now - opened)));
        match self.active.get(&key).copied() {
            None => {
                self.active.insert(key, chan);
                out.push(Cmd::Route { key, chan });
                out.push(Cmd::Found { key, name });
            }
            Some(old) => {
                let keep_new = self.keep_new(&self.chans[&chan], &self.chans[&old], &key);
                let (winner, loser) = if keep_new { (chan, old) } else { (old, chan) };
                if keep_new {
                    self.active.insert(key, chan);
                    out.push(Cmd::Route { key, chan });
                }
                let by = |c: &Chan, me: &SignPk| {
                    if c.pid.is_some() { "us".to_string() } else { short(&c.key.unwrap_or(*me)) }
                };
                info(format_args!(
                    "two channels to {}: keeping {winner} (dialed by {}), dropping {loser} (dialed by {})",
                    short(&key),
                    by(&self.chans[&winner], &self.me),
                    by(&self.chans[&loser], &self.me)
                ));
                if self.chans[&loser].pid.is_some() {
                    self.close(loser, "duplicate", now, out);
                } else if let Some(l) = self.chans.get_mut(&loser) {
                    // The peer dialed it and will close it; leave it alone so
                    // we never race the peer into closing the survivor.
                    l.doomed = Some(now);
                }
            }
        }
        if let Some(pid) = pid
            && let Some(p) = self.periphs.get_mut(&pid)
        {
            p.failures = 0;
        }
        // Pending dials to this node are pointless now. Don't cancel them
        // (nothing touches the radio link of a linked node); if one completes
        // anyway it becomes a spare.
        for p in self.periphs.values_mut().filter(|p| p.key == Some(key)) {
            if matches!(p.phase, Phase::Connecting(_)) {
                p.phase = Phase::Idle;
                p.retry_at = now;
            }
        }
    }

    /// Close a channel ourselves.
    fn close(&mut self, chan: ChanId, why: &str, now: Instant, out: &mut Vec<Cmd>) {
        info(format_args!("closing channel {chan}: {why}"));
        out.push(Cmd::CloseChannel(chan));
        self.channel_gone(chan, now, out);
    }

    fn channel_gone(&mut self, chan: ChanId, now: Instant, out: &mut Vec<Cmd>) {
        let Some(c) = self.chans.remove(&chan) else { return };
        if let Some(key) = c.key
            && self.active.get(&key) == Some(&chan)
        {
            // Another channel to the same node that said hello takes over
            // silently (e.g. the peer closed the one we were using as a
            // duplicate before we saw the other's hello).
            let next = self
                .chans
                .iter()
                .filter(|(_, o)| o.hello && o.key == Some(key))
                .min_by_key(|(id, o)| (o.doomed.is_some(), **id))
                .map(|(id, _)| *id);
            match next {
                Some(n) => {
                    info(format_args!("channel {n} now carries {}", short(&key)));
                    self.chans.get_mut(&n).expect("present").doomed = None;
                    self.active.insert(key, n);
                    out.push(Cmd::Route { key, chan: n });
                }
                None => {
                    self.active.remove(&key);
                    out.push(Cmd::Unroute { key });
                    out.push(Cmd::Lost { key });
                }
            }
        }
        let Some(pid) = c.pid else { return };
        if self.chans.values().any(|o| o.pid.as_ref() == Some(&pid)) {
            return; // another of our channels still runs over this connection
        }
        let still_linked = c.key.is_some_and(|k| self.active.contains_key(&k));
        let delay = c.key.map(|k| self.open_delay(k)).unwrap_or_default();
        let Some(p) = self.periphs.get_mut(&pid) else { return };
        if p.phase != Phase::Linked {
            return;
        }
        if c.hello {
            p.failures = 0;
        } else {
            p.failures = p.failures.saturating_add(1);
        }
        if !still_linked && p.failures >= SPARE_FAILURES_MAX {
            // Channels keep dying over this connection: start over.
            info(format_args!("channels over {} keep failing; reconnecting", sp(&pid)));
            out.push(Cmd::Disconnect(pid.clone()));
            p.phase = Phase::Idle;
            p.retry_at = now + backoff(p.failures);
            return;
        }
        // Keep the connection; reopen over it soon (if still needed).
        p.phase = Phase::Spare;
        p.retry_at = now + delay + backoff(p.failures);
        if !still_linked {
            info(format_args!("reopening a channel over {} in {}", sp(&pid), ms(p.retry_at - now)));
        }
        self.maybe_open(&pid, now, out);
    }

    fn rescan(&mut self, now: Instant, min_gap: Duration, out: &mut Vec<Cmd>) {
        if now.saturating_duration_since(self.last_scan) >= min_gap {
            self.last_scan = now;
            out.push(Cmd::Rescan);
        }
    }

    fn tick(&mut self, now: Instant, out: &mut Vec<Cmd>) {
        self.rescan(now, RESCAN_EVERY, out);
        let mut stale: Vec<(ChanId, &str)> = Vec::new();
        for (id, c) in &self.chans {
            if !c.hello && now.saturating_duration_since(c.opened) >= HELLO_TIMEOUT {
                stale.push((*id, "no hello"));
            } else if c.doomed.is_some_and(|t| now.saturating_duration_since(t) >= DUPLICATE_GRACE) {
                stale.push((*id, "duplicate the peer didn't close"));
            }
        }
        stale.sort();
        for (c, why) in stale {
            self.close(c, why, now, out);
        }
        let mut pids: Vec<Pid> = self.periphs.keys().cloned().collect();
        pids.sort();
        for pid in pids {
            let Some(p) = self.periphs.get_mut(&pid) else { continue };
            let linked = p.key.is_some_and(|k| self.active.contains_key(&k));
            match p.phase {
                Phase::Connecting(t) if linked && now.saturating_duration_since(t) >= CONNECT_TIMEOUT => {
                    // Linked some other way: leave the pending connect alone
                    // rather than touch a linked node's radio link.
                    p.phase = Phase::Idle;
                    info(format_args!("connect to {} still pending; already linked, leaving it", sp(&pid)));
                }
                Phase::Connecting(t) if now.saturating_duration_since(t) >= CONNECT_TIMEOUT => {
                    // CoreBluetooth never completes a connect to a stale
                    // peripheral: drop the handle, get a fresh one.
                    p.phase = Phase::Idle;
                    p.need_fresh = true;
                    p.failures = p.failures.saturating_add(1);
                    p.retry_at = now + backoff(p.failures);
                    info(format_args!(
                        "connect to {} timed out after {}; dropping the handle until it advertises again",
                        sp(&pid),
                        ms(CONNECT_TIMEOUT)
                    ));
                    out.push(Cmd::Disconnect(pid.clone()));
                    out.push(Cmd::Forget(pid.clone()));
                    self.rescan(now, RESCAN_SOON, out);
                }
                Phase::Reading(t) if now.saturating_duration_since(t) >= SETUP_TIMEOUT => {
                    self.fail(&pid, "reading its info timed out", now, out)
                }
                Phase::Opening(t) if now.saturating_duration_since(t) >= SETUP_TIMEOUT => {
                    self.fail(&pid, "opening the L2CAP channel timed out", now, out)
                }
                Phase::Idle | Phase::Stranger if now.saturating_duration_since(p.seen) >= FORGET_AFTER => {
                    info(format_args!("forgetting {} (not seen for {})", sp(&pid), ms(FORGET_AFTER)));
                    self.periphs.remove(&pid);
                    out.push(Cmd::Forget(pid));
                }
                Phase::Idle => self.maybe_dial(&pid, now, out),
                Phase::Spare => self.maybe_open(&pid, now, out),
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

    fn core(k: u8, t0: Instant) -> Core {
        let mut c = Core::new(key(k), t0);
        c.jitter_max = Duration::ZERO;
        c
    }

    fn s(x: u64) -> Duration {
        Duration::from_secs(x)
    }

    fn has(out: &[Cmd], f: impl Fn(&Cmd) -> bool) -> bool {
        out.iter().any(f)
    }

    #[test]
    fn lower_key_dials_and_links() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        assert_eq!(c.handle(t0, Input::Discovered("p".into())), vec![Cmd::Connect("p".into())]);
        assert_eq!(c.handle(t0, Input::Connected("p".into())), vec![Cmd::ReadInfo("p".into())]);
        assert_eq!(c.handle(t0, Input::Info("p".into(), info(2))), vec![Cmd::OpenChannel("p".into(), 0x82)]);
        assert!(c.handle(t0, Input::ChannelOpened { chan: 7, pid: Some("p".into()) }).is_empty());
        assert_eq!(
            c.handle(t0, Input::Hello { chan: 7, key: key(2), name: "bob".into() }),
            vec![Cmd::Route { key: key(2), chan: 7 }, Cmd::Found { key: key(2), name: "bob".into() }]
        );
        assert_eq!(c.peers(), 1);
        // the channel dies: Lost, keep the connection, reopen over it at once
        assert_eq!(
            c.handle(t0, Input::ChannelClosed(7)),
            vec![Cmd::Unroute { key: key(2) }, Cmd::Lost { key: key(2) }, Cmd::OpenChannel("p".into(), 0x82)]
        );
        assert_eq!(c.peers(), 0);
    }

    /// Regression: with the `bluetooth-central` background mode a locked
    /// iPhone dialed any device advertising Mycel and handed it its node key
    /// in the hello. Restricted, it reads a stranger's key, hangs up, and
    /// never opens a channel to it (nor keeps one a stranger opens), while a
    /// known device links as usual.
    #[test]
    fn restricted_links_only_with_known_nodes() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        assert!(c.handle(t0, Input::Restrict(Some([key(2)].into()))).is_empty());
        // A stranger with the higher key: unrestricted, we would open a
        // channel at once.
        assert_eq!(c.handle(t0, Input::Discovered("s".into())), vec![Cmd::Connect("s".into())]);
        c.handle(t0, Input::Connected("s".into()));
        assert_eq!(c.handle(t0, Input::Info("s".into(), info(9))), vec![Cmd::Disconnect("s".into())]);
        for i in 1..30 {
            let mut out = c.handle(t0 + s(i), Input::Discovered("s".into()));
            out.extend(c.handle(t0 + s(i), Input::Tick));
            assert!(out.iter().all(|c| *c == Cmd::Rescan), "never dialed again: {out:?}");
        }
        assert_eq!(c.connecting(t0 + s(29)), 0, "a stranger isn't a device we're connecting to");
        // A known device links.
        let t1 = t0 + s(29);
        assert_eq!(c.handle(t1, Input::Discovered("k".into())), vec![Cmd::Connect("k".into())]);
        c.handle(t1, Input::Connected("k".into()));
        assert_eq!(c.handle(t1, Input::Info("k".into(), info(2))), vec![Cmd::OpenChannel("k".into(), 0x82)]);
        c.handle(t1, Input::ChannelOpened { chan: 7, pid: Some("k".into()) });
        let out = c.handle(t1, Input::Hello { chan: 7, key: key(2), name: String::new() });
        assert!(has(&out, |c| matches!(c, Cmd::Found { .. })));
        // A channel a stranger opens to us is closed at its hello.
        c.handle(t1, Input::ChannelOpened { chan: 20, pid: None });
        assert_eq!(
            c.handle(t1, Input::Hello { chan: 20, key: key(9), name: String::new() }),
            vec![Cmd::CloseChannel(20)]
        );
        assert_eq!(c.peers(), 1);
        // Back in the foreground: the stranger is dialed again.
        assert!(has(&c.handle(t1, Input::Restrict(None)), |c| *c == Cmd::Connect("s".into())));
    }

    /// Going to the background hangs up on strangers already linked, and
    /// doesn't reopen a channel to them over the old connection.
    #[test]
    fn restricting_hangs_up_on_linked_strangers() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(9)));
        c.handle(t0, Input::ChannelOpened { chan: 7, pid: Some("p".into()) });
        c.handle(t0, Input::Hello { chan: 7, key: key(9), name: String::new() });
        assert_eq!(c.peers(), 1);
        assert_eq!(
            c.handle(t0, Input::Restrict(Some([key(2)].into()))),
            vec![
                Cmd::Disconnect("p".into()),
                Cmd::CloseChannel(7),
                Cmd::Unroute { key: key(9) },
                Cmd::Lost { key: key(9) }
            ]
        );
        assert_eq!(c.peers(), 0);
        for i in 1..20 {
            let mut out = c.handle(t0 + s(i), Input::Discovered("p".into()));
            out.extend(c.handle(t0 + s(i), Input::Tick));
            assert!(out.iter().all(|c| *c == Cmd::Rescan), "{out:?}");
        }
    }

    #[test]
    fn higher_key_also_dials_and_keeps_its_channel() {
        // The lower-key peer never dials (what the real test showed): the
        // higher one opens its own channel moments later, and keeps it.
        let t0 = Instant::now();
        let mut c = core(5, t0);
        assert_eq!(c.handle(t0, Input::Discovered("p".into())), vec![Cmd::Connect("p".into())]);
        c.handle(t0, Input::Connected("p".into()));
        assert!(c.handle(t0, Input::Info("p".into(), info(2))).is_empty(), "no hang-up, no open yet");
        let t1 = t0 + OPEN_DELAY_HIGHER;
        assert_eq!(c.handle(t1, Input::Tick), vec![Cmd::OpenChannel("p".into(), 0x82)]);
        c.handle(t1, Input::ChannelOpened { chan: 3, pid: Some("p".into()) });
        let out = c.handle(t1, Input::Hello { chan: 3, key: key(2), name: "".into() });
        assert!(has(&out, |c| matches!(c, Cmd::Found { .. })));
        // linked: stays linked, nothing is ever hung up
        for i in 1..120 {
            let out = c.handle(t1 + s(i), Input::Tick);
            assert!(out.iter().all(|c| *c == Cmd::Rescan), "{out:?}");
        }
        assert!(c.is_active(&key(2)));
    }

    #[test]
    fn first_connection_is_kept_regardless_of_who_dialed() {
        let t0 = Instant::now();
        for me in [1u8, 9] {
            // the peer (key 5) dialed us first
            let mut c = core(me, t0);
            c.handle(t0, Input::ChannelOpened { chan: 1, pid: None });
            let out = c.handle(t0, Input::Hello { chan: 1, key: key(5), name: "".into() });
            assert!(has(&out, |c| matches!(c, Cmd::Found { .. })));
            // then our own dial completes: keep it as a spare, never hang up
            c.handle(t0, Input::Discovered("p".into()));
            c.handle(t0, Input::Connected("p".into()));
            let out = c.handle(t0, Input::Info("p".into(), info(5)));
            assert!(out.is_empty(), "me={me}: {out:?}");
            for i in 1..60 {
                let out = c.handle(t0 + s(i), Input::Tick);
                assert!(out.iter().all(|c| *c == Cmd::Rescan), "me={me}: {out:?}");
            }
            assert_eq!(c.active[&key(5)], 1);
            // the accepted channel dies: open ours over the spare connection
            let out = c.handle(t0 + s(60), Input::ChannelClosed(1));
            assert!(has(&out, |c| matches!(c, Cmd::Lost { .. })));
            let mut later = c.handle(t0 + s(60), Input::Tick);
            later.extend(c.handle(t0 + s(62), Input::Tick));
            assert!(has(&later, |c| *c == Cmd::OpenChannel("p".into(), 0x85)), "me={me}: {later:?}");
            assert!(!has(&later, |c| matches!(c, Cmd::Disconnect(_))));
        }
    }

    /// Run two cores against each other with instant delivery: what one
    /// closes, the other sees closed.
    fn exchange(
        lo: &mut Core,
        hi: &mut Core,
        t: Instant,
        lo_in: Vec<Input>,
        hi_in: Vec<Input>,
    ) -> (Vec<Cmd>, Vec<Cmd>) {
        let (mut lo_out, mut hi_out) = (Vec::new(), Vec::new());
        for i in lo_in {
            lo_out.extend(lo.handle(t, i));
        }
        for i in hi_in {
            hi_out.extend(hi.handle(t, i));
        }
        (lo_out, hi_out)
    }

    #[test]
    fn simultaneous_dials_resolve_to_one_channel_without_flapping() {
        // Both dialed at once. Lower key 1, higher key 9. Channel A was dialed
        // by 1 (lo 10 <-> hi 20), channel B by 9 (lo 11 <-> hi 21). Every
        // order of hello arrival ends with both on A, B closed by its dialer,
        // and no Lost anywhere.
        let t0 = Instant::now();
        for order in 0..4 {
            let mut lo = core(1, t0);
            lo.handle(t0, Input::Discovered("p9".into()));
            lo.handle(t0, Input::Connected("p9".into()));
            lo.handle(t0, Input::Info("p9".into(), info(9)));
            lo.handle(t0, Input::ChannelOpened { chan: 10, pid: Some("p9".into()) });
            lo.handle(t0, Input::ChannelOpened { chan: 11, pid: None });
            let mut hi = core(9, t0);
            hi.handle(t0, Input::Discovered("p1".into()));
            hi.handle(t0, Input::Connected("p1".into()));
            hi.handle(t0, Input::Info("p1".into(), info(1)));
            hi.handle(t0 + OPEN_DELAY_HIGHER, Input::Tick);
            hi.handle(t0, Input::ChannelOpened { chan: 21, pid: Some("p1".into()) });
            hi.handle(t0, Input::ChannelOpened { chan: 20, pid: None });
            let h = |chan, k| Input::Hello { chan, key: key(k), name: "".into() };
            let (lo_first, hi_first) = (order & 1 == 0, order & 2 == 0);
            let lo_in = if lo_first { vec![h(10, 9), h(11, 9)] } else { vec![h(11, 9), h(10, 9)] };
            let hi_in = if hi_first { vec![h(20, 1), h(21, 1)] } else { vec![h(21, 1), h(20, 1)] };
            let (mut lo_out, mut hi_out) = exchange(&mut lo, &mut hi, t0, lo_in, hi_in);
            assert_eq!(lo.active[&key(9)], 10, "order {order}");
            assert_eq!(hi.active[&key(1)], 20, "order {order}");
            // only the dialer of the loser (hi) closes it; lo just waits
            assert!(hi_out.contains(&Cmd::CloseChannel(21)), "order {order}: {hi_out:?}");
            assert!(!lo_out.contains(&Cmd::CloseChannel(10)) && !lo_out.contains(&Cmd::CloseChannel(11)));
            // lo sees B end
            lo_out.extend(lo.handle(t0, Input::ChannelClosed(11)));
            for t in 1..30 {
                lo_out.extend(lo.handle(t0 + s(t), Input::Tick));
                hi_out.extend(hi.handle(t0 + s(t), Input::Tick));
            }
            for out in [&lo_out, &hi_out] {
                assert_eq!(out.iter().filter(|c| matches!(c, Cmd::Found { .. })).count(), 1, "order {order}");
                assert!(!has(out, |c| matches!(c, Cmd::Lost { .. })), "no flap, order {order}: {out:?}");
                assert!(!has(out, |c| matches!(c, Cmd::Disconnect(_))), "no hang-ups, order {order}: {out:?}");
                assert!(!has(out, |c| matches!(c, Cmd::OpenChannel(..))), "no reopen, order {order}: {out:?}");
            }
            assert!(!hi_out.contains(&Cmd::CloseChannel(20)));
        }
    }

    #[test]
    fn peer_closing_our_active_duplicate_switches_silently() {
        // hi routes B (dialed by itself) first; lo closes... no: lo never
        // closes B; but if B dies for any reason while A has said hello, A
        // takes over without a Lost.
        let t0 = Instant::now();
        let mut hi = core(9, t0);
        hi.handle(t0, Input::ChannelOpened { chan: 20, pid: None });
        hi.handle(t0, Input::ChannelOpened { chan: 21, pid: None });
        hi.handle(t0, Input::Hello { chan: 21, key: key(5), name: "".into() });
        let out = hi.handle(t0, Input::Hello { chan: 20, key: key(5), name: "".into() });
        // both dialed by the peer: the newer (20) wins, 21 waits for the peer
        assert_eq!(hi.active[&key(5)], 20);
        assert!(!out.contains(&Cmd::CloseChannel(21)));
        let out = hi.handle(t0 + s(1), Input::ChannelClosed(20));
        assert_eq!(out, vec![Cmd::Route { key: key(5), chan: 21 }], "21 takes over, no Lost");
        // and is no longer doomed
        assert!(hi.handle(t0 + s(30), Input::Tick).iter().all(|c| *c == Cmd::Rescan));
        // a doomed duplicate the peer never closes is closed by us
        hi.handle(t0, Input::ChannelOpened { chan: 22, pid: None });
        hi.handle(t0 + s(31), Input::Hello { chan: 22, key: key(5), name: "".into() });
        assert_eq!(hi.active[&key(5)], 22);
        let out = hi.handle(t0 + s(31) + DUPLICATE_GRACE, Input::Tick);
        assert!(out.contains(&Cmd::CloseChannel(21)), "{out:?}");
        assert!(!has(&out, |c| matches!(c, Cmd::Lost { .. })));
    }

    #[test]
    fn bad_hellos_and_silent_channels_are_closed() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
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
    fn stale_handle_connect_times_out_and_recovers_via_fresh_discovery() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        assert_eq!(c.handle(t0, Input::Discovered("p".into())), vec![Cmd::Connect("p".into())]);
        // the connect never completes (stale peripheral)
        assert!(!has(&c.handle(t0 + s(7), Input::Tick), |c| matches!(c, Cmd::Disconnect(_))));
        let out = c.handle(t0 + CONNECT_TIMEOUT, Input::Tick);
        assert!(out.contains(&Cmd::Disconnect("p".into())) && out.contains(&Cmd::Forget("p".into())), "{out:?}");
        assert!(out.contains(&Cmd::Rescan), "look for a fresh handle now");
        // without a fresh advertisement it is not redialed
        for t in 9..20 {
            assert!(!has(&c.handle(t0 + s(t), Input::Tick), |c| matches!(c, Cmd::Connect(_))));
        }
        // the rescan reports it again: dial at once (backoff has passed)
        let out = c.handle(t0 + s(20), Input::Discovered("p".into()));
        assert_eq!(out, vec![Cmd::Connect("p".into())]);
        // a late Disconnected for the cancelled attempt doesn't disturb the new one
        assert!(c.handle(t0 + s(20), Input::Disconnected("p".into())).is_empty());
        assert_eq!(c.handle(t0 + s(21), Input::Connected("p".into())), vec![Cmd::ReadInfo("p".into())]);
    }

    #[test]
    fn backoff_is_capped_and_never_gives_up_while_seen() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        c.handle(t0, Input::Discovered("p".into()));
        let mut t = t0;
        let mut last_dial = t0;
        let mut dials = 0;
        // fail every attempt for ten minutes; the peer keeps advertising
        for step in 0..(600 * 4) {
            t = t0 + Duration::from_millis(250 * step);
            let mut out = Vec::new();
            if step % 4 == 0 {
                out.extend(c.handle(t, Input::Discovered("p".into())));
                out.extend(c.handle(t, Input::Tick));
            }
            for cmd in out {
                if let Cmd::Connect(p) = cmd {
                    assert!(t - last_dial <= BACKOFF_MAX + s(2), "gap {:?}", t - last_dial);
                    last_dial = t;
                    dials += 1;
                    c.handle(t, Input::ConnectFailed(p));
                }
            }
        }
        assert!(dials > 50, "kept dialing: {dials}");
        assert!(t - last_dial <= BACKOFF_MAX + s(2));
        // not seen any more: stops dialing, then forgets
        let gone = t;
        let mut out = Vec::new();
        for i in 1..=FORGET_AFTER.as_secs() {
            out.extend(c.handle(gone + s(i), Input::Tick));
        }
        let dials_after = out.iter().filter(|c| matches!(c, Cmd::Connect(_))).count();
        assert!(dials_after <= 2, "{dials_after}");
        assert!(out.contains(&Cmd::Forget("p".into())));
        assert!(c.periphs.is_empty());
    }

    #[test]
    fn connection_drop_redials_promptly() {
        let t0 = Instant::now();
        let mut c = core(9, t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(2)));
        c.handle(t0 + OPEN_DELAY_HIGHER, Input::Tick);
        c.handle(t0 + s(2), Input::ChannelOpened { chan: 1, pid: Some("p".into()) });
        c.handle(t0 + s(2), Input::Hello { chan: 1, key: key(2), name: "".into() });
        let out = c.handle(t0 + s(100), Input::Disconnected("p".into()));
        assert!(out.contains(&Cmd::Lost { key: key(2) }) && out.contains(&Cmd::CloseChannel(1)), "{out:?}");
        let out = c.handle(t0 + s(100), Input::Discovered("p".into()));
        assert_eq!(out, vec![Cmd::Connect("p".into())]);
    }

    #[test]
    fn setup_failure_never_hangs_up_a_linked_node() {
        // We're linked over a channel the peer dialed; our own attempt's
        // channel open fails. Hanging up could take the peer's channel down
        // with it (shared radio link): keep the connection instead.
        let t0 = Instant::now();
        let mut c = core(1, t0);
        c.handle(t0, Input::Discovered("p".into()));
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(2)));
        c.handle(t0, Input::ChannelOpened { chan: 5, pid: None });
        c.handle(t0, Input::Hello { chan: 5, key: key(2), name: "".into() });
        let out = c.handle(t0, Input::OpenFailed("p".into()));
        assert!(!has(&out, |c| matches!(c, Cmd::Disconnect(_))), "{out:?}");
        assert_eq!(c.periphs["p"].phase, Phase::Spare);
    }

    #[test]
    fn rotated_address_replaces_the_old_identifier() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
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
        let mut c = core(1, t0);
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
        let mut c = core(1, t0);
        assert!(c.handle(t0 + s(1), Input::Tick).is_empty());
        assert_eq!(c.handle(t0 + RESCAN_EVERY, Input::Tick), vec![Cmd::Rescan]);
        assert!(c.handle(t0 + RESCAN_EVERY + s(1), Input::Tick).is_empty());
    }

    #[test]
    fn counts_devices_still_connecting() {
        let t0 = Instant::now();
        let mut c = core(1, t0);
        c.handle(t0, Input::Discovered("p".into()));
        assert_eq!(c.connecting(t0), 1);
        c.handle(t0, Input::Connected("p".into()));
        c.handle(t0, Input::Info("p".into(), info(2)));
        c.handle(t0, Input::ChannelOpened { chan: 1, pid: Some("p".into()) });
        c.handle(t0, Input::Hello { chan: 1, key: key(2), name: "".into() });
        assert_eq!(c.connecting(t0), 0);
        assert_eq!(c.connecting(t0 + RECENT), 0);

        // Linked over a channel the peer dialed while our own dial to it is
        // still pending (its key unread): not "connecting to 1 more device".
        let mut c = core(1, t0);
        c.handle(t0, Input::Discovered("q".into()));
        c.handle(t0, Input::ChannelOpened { chan: 1, pid: None });
        c.handle(t0, Input::Hello { chan: 1, key: key(2), name: "".into() });
        assert_eq!(c.connecting(t0), 0);
        // a second unknown peripheral beyond the linked node does count
        c.handle(t0, Input::Discovered("r".into()));
        assert_eq!(c.connecting(t0), 1);
    }
}
