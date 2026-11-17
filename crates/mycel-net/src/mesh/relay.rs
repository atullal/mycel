//! Relays among the devices themselves, so that reaching a device behind a
//! router needs no relay server.
//!
//! A device the internet can reach (a public address, a forwarded port) is
//! a **relay**: its record says so, and it carries traffic between two
//! internet hops for the devices that asked it to. A device the internet
//! can't dial in to, and with no relay server connected, is a **client**:
//! it picks relays among the devices it was told about
//! ([`super::Mesh::set_relay_candidates`]: its contacts, the people in its
//! chats, keepers) and the relays those devices name in their own records
//! (so one contact behind a relay is enough to find one), keeps a hop
//! connection up to each, asks each to relay for it, and names them in its
//! own record. Whoever looks the client up
//! gets one mesh address per relay, each its own QUIC path, exactly as for
//! a Bluetooth-only device behind gateways (the routing is in `core.rs`).
//!
//! The hop to a relay is an ordinary QUIC connection, so the relay sees the
//! client's address as the internet does, and says so in its answer. The
//! client gives that address to Iroh, which offers it to the devices it
//! talks to: a connection that started through a relay can then move to a
//! direct path, and the relay carries only what can't.
//!
//! A relay can drop or delay what it carries, and sees who talks to whom
//! and how much; it can't read or change it (`docs/TRUST.md` §8b). A device
//! asks at most [`super::MeshOptions::relays`] of them, so losing one costs
//! a path, not the connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::TransportAddr;
use mycel_crypto::SignPk;

use super::core::RELAY_REFRESH;
use super::directory::{self, Role};
use super::{Driver, LOOKUP_TIMEOUT};
use crate::link::path_in_use;

/// Control message: "be my relay" (and again every [`RELAY_REFRESH`]).
pub(super) const CTRL_RELAY_JOIN: u8 = 2;
/// The relay's answer: yes, followed by the asker's address as the relay
/// sees it (text, may be empty).
pub(super) const CTRL_RELAY_OK: u8 = 3;
/// ... or no: it isn't a relay (any more), or it is full.
pub(super) const CTRL_RELAY_NO: u8 = 4;

/// A candidate's record is read again this often.
const CHECK_EVERY: Duration = Duration::from_secs(5 * 60);
/// Lookups of candidates' records under way at once.
const CHECKS_AT_ONCE: usize = 4;
/// A relay that hasn't answered a request for this long is given up on.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// A relay we can't connect to within this long is given up on.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// A candidate that refused, didn't answer or couldn't be reached isn't
/// tried again for this long.
const GIVEN_UP_FOR: Duration = Duration::from_secs(10 * 60);
/// Candidates remembered.
pub(super) const CANDIDATES_MAX: usize = 256;
/// Relays learned from the candidates' records, at most.
const LEARNED_MAX: usize = 64;
/// How often the choice of relays is looked at again.
const EVERY: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Candidate {
    /// What its record said: it relays (`None`: not looked up yet).
    relay: Option<bool>,
    checked: Option<Instant>,
    checking: bool,
    /// Don't ask it before then.
    not_before: Option<Instant>,
}

/// One of the relays we chose.
struct Chosen {
    since: Instant,
    /// When we last asked it, and when it last said yes.
    asked: Option<Instant>,
    joined: Option<Instant>,
}

/// The driver's relay state: the candidates and the relays chosen.
#[derive(Default)]
pub(super) struct Relays {
    /// In the order given: the first are preferred.
    order: Vec<SignPk>,
    /// The relays those devices name in their records: tried after them.
    /// Only theirs, not the relays of relays: two steps from someone we
    /// know is as far as this goes.
    learned: Vec<SignPk>,
    cands: HashMap<SignPk, Candidate>,
    chosen: Vec<(SignPk, Chosen)>,
    /// Our address as the relays see it, given to Iroh.
    observed: Option<SocketAddr>,
    /// The role last told to the record (with the relays' costs then).
    role: Option<(Role, bool)>,
    last: Option<Instant>,
}

impl Relays {
    pub(super) fn set_candidates(&mut self, mut list: Vec<SignPk>) {
        list.dedup();
        list.truncate(CANDIDATES_MAX);
        self.learned.retain(|k| !list.contains(k));
        self.cands.retain(|k, _| list.contains(k) || self.learned.contains(k));
        self.order = list;
    }

    /// Every candidate, the preferred first.
    fn all(&self) -> Vec<SignPk> {
        self.order.iter().chain(&self.learned).copied().collect()
    }

    /// `relays` are named in the record of `by`, a device we were told
    /// about: candidates too.
    fn learn(&mut self, by: &SignPk, relays: &[(SignPk, u32)], me: &SignPk) {
        if !self.order.contains(by) {
            return;
        }
        for (r, _) in relays {
            if self.learned.len() >= LEARNED_MAX {
                break;
            }
            if r != me && !self.order.contains(r) && !self.learned.contains(r) {
                self.learned.push(*r);
            }
        }
    }

    fn give_up(&mut self, relay: &SignPk, now: Instant) {
        self.chosen.retain(|(k, _)| k != relay);
        if let Some(c) = self.cands.get_mut(relay) {
            c.not_before = Some(now + GIVEN_UP_FOR);
        }
    }

    fn is_chosen(&self, relay: &SignPk) -> bool {
        self.chosen.iter().any(|(k, _)| k == relay)
    }
}

/// What the device is doing about relays, for the Network panel and tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayStatus {
    /// The internet can reach this device and it relays for those who ask.
    pub relaying: bool,
    /// Devices it is the relay of.
    pub clients: usize,
    /// The relays it asked that said yes and are connected.
    pub relays: Vec<SignPk>,
    /// Its uplink is metered: it carries nobody else's traffic over it.
    pub metered: bool,
}

impl Driver {
    /// Whether a relay server (n0's or one configured) is connected.
    fn relay_server(&self) -> bool {
        self.endpoint.get().is_some_and(|ep| {
            use super::n0_watcher::Watcher;
            ep.home_relay_status().get().iter().any(|s| s.is_connected())
        })
    }

    pub(super) fn relay_status(&self) -> RelayStatus {
        let r = self.router.lock();
        let up: Vec<SignPk> = r.relays_up().into_iter().map(|(k, _)| k).collect();
        let st = self.relays.lock();
        RelayStatus {
            relaying: r.relaying(),
            clients: r.relay_clients(),
            relays: st.chosen.iter().filter(|(k, c)| c.joined.is_some() && up.contains(k)).map(|(k, _)| *k).collect(),
            metered: r.metered(),
        }
    }

    /// Once a second: be a relay or pick relays, as the device's situation
    /// says, and tell the record.
    pub(super) fn relay_tick(self: &Arc<Self>) {
        let now = Instant::now();
        {
            let mut st = self.relays.lock();
            if st.last.is_some_and(|t| now.duration_since(t) < EVERY) {
                return;
            }
            st.last = Some(now);
        }
        let reachable = self.opts.reachable.unwrap_or_else(|| self.reachable.load(Ordering::Relaxed));
        let metered = self.metered.load(Ordering::Relaxed);
        let server = self.relay_server();
        let (internet, serve) = self.with_router(|r, _| {
            r.set_metered(metered);
            r.set_relaying(r.internet() && reachable && self.opts.relay && self.opts.internet_relay);
            (r.internet(), r.relaying())
        });
        // a client only when nothing else lets the internet in
        let need = internet && !reachable && !server && self.opts.relays > 0;
        if need {
            self.check_candidates(now);
            self.choose_relays(now);
        } else if !self.relays.lock().chosen.is_empty() {
            self.relays.lock().chosen.clear();
            self.with_router(|r, now| r.set_relays(Vec::new(), now));
        }
        // the record: a relay, behind relays, or neither
        let up = self.router.lock().relays_up();
        let mut st = self.relays.lock();
        let via: Vec<(SignPk, u32)> =
            up.into_iter().filter(|(k, _)| st.chosen.iter().any(|(c, ch)| c == k && ch.joined.is_some())).collect();
        let role = if serve {
            Role::Relay
        } else if need && !via.is_empty() {
            Role::Via(via)
        } else {
            Role::Plain
        };
        // our addresses are worth publishing only if they can be dialed
        let public = serve || (reachable && !server);
        // the same relays as last time: keep that record (the costs move
        // all the time, and are only a hint)
        let same = match (&st.role, &role) {
            (Some((Role::Via(a), p)), Role::Via(b)) => {
                *p == public && a.len() == b.len() && a.iter().all(|(k, _)| b.iter().any(|(x, _)| x == k))
            }
            (Some((a, p)), b) => a == b && *p == public,
            (None, _) => false,
        };
        if !same {
            st.role = Some((role.clone(), public));
            drop(st);
            if let Some(own) = self.own.lock().clone() {
                own.set_role(role, public);
            }
        }
    }

    /// Read the records of candidates we haven't looked at for a while: do
    /// they relay?
    fn check_candidates(self: &Arc<Self>, now: Instant) {
        let Some(dir) = self.directory() else { return };
        let mut todo = Vec::new();
        {
            let mut st = self.relays.lock();
            let mut running = st.cands.values().filter(|c| c.checking).count();
            // with enough relays, only theirs are read again: a device
            // doesn't keep querying the directory for everyone it knows
            let enough = st.chosen.len() >= self.opts.relays.min(3);
            for pk in st.all() {
                if running >= CHECKS_AT_ONCE {
                    break;
                }
                if enough && !st.is_chosen(&pk) {
                    continue;
                }
                let c = st.cands.entry(pk).or_default();
                if c.checking || c.checked.is_some_and(|t| now.duration_since(t) < CHECK_EVERY) {
                    continue;
                }
                c.checking = true;
                running += 1;
                todo.push(pk);
            }
        }
        for pk in todo {
            let (me, dir) = (self.clone(), dir.clone());
            self.keep(tokio::spawn(async move {
                let rec = tokio::time::timeout(LOOKUP_TIMEOUT, dir.get(pk))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|b| directory::read(&b, Some(&pk)));
                let mut st = me.relays.lock();
                if let Some(c) = st.cands.get_mut(&pk) {
                    c.checking = false;
                    c.checked = Some(Instant::now());
                    c.relay = Some(rec.as_ref().is_some_and(|r| r.relay));
                }
                // the relays it is behind may relay for us too
                if let Some(r) = &rec {
                    st.learn(&pk, &r.gateways, &me.me);
                }
            }));
        }
    }

    /// Keep [`super::MeshOptions::relays`] relays chosen, connected and
    /// asked; give up on the ones that don't work.
    fn choose_relays(self: &Arc<Self>, now: Instant) {
        let up: Vec<SignPk> = self.router.lock().relays_up().into_iter().map(|(k, _)| k).collect();
        let direct: Vec<SignPk> = self.hops.lock().iter().filter(|(_, h)| h.direct).map(|(k, _)| *k).collect();
        let mut ask = Vec::new();
        let chosen: Vec<SignPk> = {
            let mut st = self.relays.lock();
            // the ones that aren't working out
            let mut gone = Vec::new();
            for (k, c) in &mut st.chosen {
                let connected = up.contains(k);
                if !connected {
                    // asked and answered on a connection that is gone
                    c.asked = None;
                    c.joined = None;
                }
                let unanswered = c.asked.is_some_and(|t| now.duration_since(t) >= JOIN_TIMEOUT)
                    && c.joined.is_none_or(|j| c.asked.is_some_and(|a| j < a));
                let unreachable = !connected && now.duration_since(c.since) >= CONNECT_TIMEOUT;
                if connected {
                    c.since = now;
                }
                if unanswered || unreachable || direct.contains(k) {
                    gone.push(*k);
                }
            }
            for k in gone {
                st.give_up(&k, now);
            }
            // candidates that no longer say they relay
            let cands = &st.cands;
            let stale: Vec<SignPk> = st
                .chosen
                .iter()
                .map(|(k, _)| *k)
                .filter(|k| cands.get(k).is_none_or(|c| c.relay == Some(false)))
                .collect();
            st.chosen.retain(|(k, _)| !stale.contains(k));
            // fill up from the candidates, in order
            let want = self.opts.relays.min(3);
            for pk in st.all() {
                if st.chosen.len() >= want {
                    break;
                }
                let ok =
                    st.cands.get(&pk).is_some_and(|c| c.relay == Some(true) && c.not_before.is_none_or(|t| now >= t))
                        && !st.is_chosen(&pk)
                        && !direct.contains(&pk)
                        && pk != self.me;
                if ok {
                    st.chosen.push((pk, Chosen { since: now, asked: None, joined: None }));
                }
            }
            // ask the connected ones, again every RELAY_REFRESH
            let refresh = Duration::from_millis(RELAY_REFRESH);
            for (k, c) in &mut st.chosen {
                if up.contains(k) && c.asked.is_none_or(|t| now.duration_since(t) >= refresh) {
                    c.asked = Some(now);
                    ask.push(*k);
                }
            }
            st.chosen.iter().map(|(k, _)| *k).collect()
        };
        self.with_router(|r, now| {
            r.set_relays(chosen, now);
            for relay in ask {
                r.send(relay, relay, Bytes::from_static(&[CTRL_RELAY_JOIN]), true, now);
            }
        });
    }

    /// `peer`'s address as we see it on its hop connection.
    fn observed_addr(&self, peer: &SignPk) -> Option<SocketAddr> {
        let conn = self.conn(peer)?;
        let paths = conn.paths();
        match path_in_use(&paths)?.remote_addr() {
            TransportAddr::Ip(sa) => Some(*sa),
            _ => None,
        }
    }

    /// A relay control message. `via` is the neighbour it came from on its
    /// authenticated hop connection: a request counts only straight from
    /// the device it is about.
    pub(super) fn on_relay_control(self: &Arc<Self>, from: SignPk, via: Option<SignPk>, payload: &[u8]) {
        if via != Some(from) {
            return;
        }
        match payload.first() {
            Some(&CTRL_RELAY_JOIN) => {
                // someone we know keeps a place when strangers fill the rest
                let known = self.relays.lock().order.contains(&from);
                let ok = self.with_router(|r, now| r.relay_join(from, known, now));
                let mut reply = vec![if ok { CTRL_RELAY_OK } else { CTRL_RELAY_NO }];
                if ok && let Some(addr) = self.observed_addr(&from) {
                    reply.extend_from_slice(addr.to_string().as_bytes());
                }
                self.with_router(|r, now| r.send(from, from, Bytes::from(reply), true, now));
            }
            Some(&CTRL_RELAY_OK) => {
                let now = Instant::now();
                let seen = std::str::from_utf8(&payload[1..]).ok().and_then(|s| s.parse::<SocketAddr>().ok());
                let changed = {
                    let mut st = self.relays.lock();
                    let Some((_, c)) = st.chosen.iter_mut().find(|(k, _)| *k == from) else { return };
                    c.joined = Some(now);
                    // one address, the one our relays agree on last
                    let seen = seen.filter(|a| a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast());
                    match seen {
                        Some(a) if st.observed != Some(a) => Some((st.observed.replace(a), a)),
                        _ => None,
                    }
                };
                // Iroh offers it to the devices we talk to, for a direct path
                if let Some((old, new)) = changed
                    && let Some(ep) = self.endpoint.get().cloned()
                {
                    self.keep(tokio::spawn(async move {
                        if let Some(old) = old {
                            ep.remove_external_addr(&old).await;
                        }
                        ep.add_external_addr(new).await;
                    }));
                }
            }
            Some(&CTRL_RELAY_NO) => {
                let mut st = self.relays.lock();
                if st.is_chosen(&from) {
                    st.give_up(&from, Instant::now());
                }
            }
            _ => {}
        }
    }
}
