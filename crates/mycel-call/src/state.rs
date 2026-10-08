//! The call state machine, free of I/O so every transition is testable.
//!
//! The manager feeds it what happened ([`Input`]) and performs what it asks
//! for ([`Effect`]). Simultaneous calls (both people press call at once) are
//! resolved by [`on_ring`]: the call placed by the lower device key wins, the
//! other side drops its own outgoing call and auto-answers, so the two end up
//! in exactly one call.

use std::time::{Duration, Instant};

use mycel_crypto::{Hash32, SignPk};

use crate::api::{CallPhase, Direction, EndReason};
use crate::proto::{CallId, Ctrl};

/// How long a call rings before giving up (caller side; the callee waits a
/// little longer so the caller's cancel normally arrives first).
pub const RING_TIMEOUT: Duration = Duration::from_secs(45);
pub const CALLEE_RING_SLACK: Duration = Duration::from_secs(5);
/// Answered, waiting for the caller to start audio.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Outgoing: their device answered our ring with `Ringing`.
    RemoteRinging,
    /// Outgoing: they accepted.
    RemoteAccepted,
    /// Incoming: the user answered.
    LocalAccept,
    /// Incoming: the caller started audio.
    RemoteStarted,
    LocalDecline,
    RemoteDeclined,
    RemoteBusy,
    RemoteGlare,
    LocalHangUp,
    RemoteHangUp,
    /// A deadline from [`CallState::deadline`] passed.
    Timeout,
    ConnectionLost,
    /// Outgoing: their device couldn't be reached at all.
    Unreachable,
    MicDenied,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Send(Ctrl),
    StartMedia,
    /// Stop audio, close the connection.
    Close,
}

#[derive(Clone, Debug)]
pub struct CallState {
    pub dir: Direction,
    pub phase: CallPhase,
    pub end: Option<EndReason>,
    pub created: Instant,
    pub active_at: Option<Instant>,
    pub ended_at: Option<Instant>,
    deadline: Option<Instant>,
}

impl CallState {
    pub fn outgoing(now: Instant, ring_timeout: Duration) -> CallState {
        CallState::new(Direction::Outgoing, CallPhase::Connecting, now, ring_timeout)
    }

    pub fn incoming(now: Instant, ring_timeout: Duration) -> CallState {
        CallState::new(Direction::Incoming, CallPhase::Ringing, now, ring_timeout + CALLEE_RING_SLACK)
    }

    fn new(dir: Direction, phase: CallPhase, now: Instant, timeout: Duration) -> CallState {
        CallState { dir, phase, end: None, created: now, active_at: None, ended_at: None, deadline: Some(now + timeout) }
    }

    pub fn is_live(&self) -> bool {
        self.phase != CallPhase::Ended
    }

    /// When to feed [`Input::Timeout`], if anything is pending.
    pub fn deadline(&self) -> Option<Instant> {
        if self.is_live() { self.deadline } else { None }
    }

    pub fn duration(&self, now: Instant) -> Duration {
        match self.active_at {
            Some(a) => self.ended_at.unwrap_or(now).saturating_duration_since(a),
            None => Duration::ZERO,
        }
    }

    fn end(&mut self, reason: EndReason, now: Instant, mut effects: Vec<Effect>) -> Vec<Effect> {
        self.phase = CallPhase::Ended;
        self.end = Some(reason);
        self.ended_at = Some(now);
        self.deadline = None;
        effects.push(Effect::Close);
        effects
    }

    fn activate(&mut self, now: Instant) {
        self.phase = CallPhase::Active;
        self.active_at = Some(now);
        self.deadline = None;
    }

    pub fn apply(&mut self, input: Input, now: Instant) -> Vec<Effect> {
        use CallPhase::*;
        use Direction::*;
        use Input::*;
        if !self.is_live() {
            return vec![];
        }
        let answered = self.phase == Active || (self.dir == Incoming && self.phase == Connecting);
        match (self.dir, self.phase, input) {
            (Outgoing, Connecting, RemoteRinging) => {
                self.phase = Ringing;
                vec![]
            }
            (Outgoing, Connecting | Ringing, RemoteAccepted) => {
                self.activate(now);
                vec![Effect::Send(Ctrl::Started), Effect::StartMedia]
            }
            (Incoming, Ringing, LocalAccept) => {
                self.phase = Connecting;
                self.deadline = Some(now + SETUP_TIMEOUT);
                vec![Effect::Send(Ctrl::Accept)]
            }
            (Incoming, Connecting, RemoteStarted) => {
                self.activate(now);
                vec![Effect::StartMedia]
            }
            (Incoming, Ringing, LocalDecline | LocalHangUp) => {
                self.end(EndReason::Declined, now, vec![Effect::Send(Ctrl::Decline)])
            }
            (_, _, LocalDecline | LocalHangUp) => self.end(EndReason::HungUp, now, vec![Effect::Send(Ctrl::HangUp)]),
            (Outgoing, Connecting | Ringing, RemoteDeclined) => self.end(EndReason::RemoteDeclined, now, vec![]),
            (Outgoing, Connecting | Ringing, RemoteBusy) => self.end(EndReason::Busy, now, vec![]),
            (Outgoing, Connecting | Ringing, RemoteGlare) => self.end(EndReason::Replaced, now, vec![]),
            (_, _, RemoteHangUp | RemoteDeclined) => {
                let reason = if answered {
                    EndReason::RemoteHungUp
                } else if self.dir == Incoming {
                    EndReason::Missed
                } else {
                    EndReason::RemoteDeclined
                };
                self.end(reason, now, vec![])
            }
            (Outgoing, Connecting | Ringing, Timeout) => {
                self.end(EndReason::NoAnswer, now, vec![Effect::Send(Ctrl::HangUp)])
            }
            (Incoming, Ringing, Timeout | ConnectionLost) => self.end(EndReason::Missed, now, vec![]),
            (_, _, Timeout | ConnectionLost) => self.end(EndReason::ConnectionLost, now, vec![]),
            (Outgoing, Connecting, Unreachable) => self.end(EndReason::Unavailable, now, vec![]),
            (_, _, MicDenied) => {
                let bye = if self.dir == Incoming && self.phase == Ringing { Ctrl::Decline } else { Ctrl::HangUp };
                self.end(EndReason::MicDenied, now, vec![Effect::Send(bye)])
            }
            (_, _, Failed) => self.end(EndReason::Failed, now, vec![Effect::Send(Ctrl::HangUp)]),
            // anything else is out of order: ignore it
            _ => vec![],
        }
    }
}

/// A call that's still live, as [`on_ring`] sees it.
#[derive(Clone, Debug)]
pub struct LiveCall {
    pub id: CallId,
    pub peer: SignPk,
    pub space: Hash32,
    pub dir: Direction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingDecision {
    /// Ring the user.
    Ring,
    /// We were calling them too: take this call instead of ours (end
    /// `replaces`, if it's still live) and answer it right away.
    AutoAccept { replaces: Option<CallId> },
    /// We were calling them too and ours wins: tell them so.
    Glare,
    /// Already in a call.
    Busy,
}

/// An incoming ring from `from` about `space`. `expecting` is true when our
/// own call to them just ended with `Glare` (theirs is the one to take).
pub fn on_ring(me: &SignPk, from: &SignPk, space: &Hash32, live: &[LiveCall], expecting: bool) -> RingDecision {
    let ours = live
        .iter()
        .find(|c| c.dir == Direction::Outgoing && c.peer == *from && c.space == *space);
    if let Some(ours) = ours {
        // Both calling: the lower key's call survives on both sides.
        return if me < from { RingDecision::Glare } else { RingDecision::AutoAccept { replaces: Some(ours.id) } };
    }
    if expecting {
        return RingDecision::AutoAccept { replaces: None };
    }
    if !live.is_empty() {
        return RingDecision::Busy;
    }
    RingDecision::Ring
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn answered_call_then_hang_up_from_either_side() {
        for caller_hangs_up in [true, false] {
            let t = t0();
            let mut caller = CallState::outgoing(t, RING_TIMEOUT);
            let mut callee = CallState::incoming(t, RING_TIMEOUT);
            assert_eq!(caller.phase, CallPhase::Connecting);
            assert!(caller.apply(Input::RemoteRinging, t).is_empty());
            assert_eq!(caller.phase, CallPhase::Ringing);
            assert_eq!(callee.apply(Input::LocalAccept, t), vec![Effect::Send(Ctrl::Accept)]);
            assert_eq!(callee.phase, CallPhase::Connecting);
            assert_eq!(
                caller.apply(Input::RemoteAccepted, t),
                vec![Effect::Send(Ctrl::Started), Effect::StartMedia]
            );
            assert_eq!(callee.apply(Input::RemoteStarted, t), vec![Effect::StartMedia]);
            assert_eq!((caller.phase, callee.phase), (CallPhase::Active, CallPhase::Active));
            assert_eq!(caller.deadline(), None, "no timeouts once talking");

            let later = t + Duration::from_secs(90);
            let (hanger, other) = if caller_hangs_up { (&mut caller, &mut callee) } else { (&mut callee, &mut caller) };
            assert_eq!(hanger.apply(Input::LocalHangUp, later), vec![Effect::Send(Ctrl::HangUp), Effect::Close]);
            assert_eq!(other.apply(Input::RemoteHangUp, later), vec![Effect::Close]);
            assert_eq!(hanger.end, Some(EndReason::HungUp));
            assert_eq!(other.end, Some(EndReason::RemoteHungUp));
            assert_eq!(hanger.duration(later + Duration::from_secs(5)), Duration::from_secs(90));
            // nothing moves an ended call
            assert!(other.apply(Input::RemoteAccepted, later).is_empty());
            assert_eq!(other.phase, CallPhase::Ended);
        }
    }

    #[test]
    fn decline() {
        let t = t0();
        let mut caller = CallState::outgoing(t, RING_TIMEOUT);
        let mut callee = CallState::incoming(t, RING_TIMEOUT);
        caller.apply(Input::RemoteRinging, t);
        assert_eq!(callee.apply(Input::LocalDecline, t), vec![Effect::Send(Ctrl::Decline), Effect::Close]);
        assert_eq!(callee.end, Some(EndReason::Declined));
        caller.apply(Input::RemoteDeclined, t);
        assert_eq!(caller.end, Some(EndReason::RemoteDeclined));
        assert_eq!(caller.duration(t), Duration::ZERO);
    }

    #[test]
    fn ring_timeout_on_both_sides() {
        let t = t0();
        let mut caller = CallState::outgoing(t, RING_TIMEOUT);
        let mut callee = CallState::incoming(t, RING_TIMEOUT);
        caller.apply(Input::RemoteRinging, t);
        assert_eq!(caller.deadline(), Some(t + RING_TIMEOUT));
        assert!(callee.deadline().unwrap() > caller.deadline().unwrap(), "callee waits for the caller's cancel");
        let fx = caller.apply(Input::Timeout, t + RING_TIMEOUT);
        assert_eq!(fx, vec![Effect::Send(Ctrl::HangUp), Effect::Close]);
        assert_eq!(caller.end, Some(EndReason::NoAnswer));
        // the cancel reaches the callee: it was missed
        callee.apply(Input::RemoteHangUp, t + RING_TIMEOUT);
        assert_eq!(callee.end, Some(EndReason::Missed));
        // or, if it never arrives, its own timer does the same
        let mut lonely = CallState::incoming(t, RING_TIMEOUT);
        lonely.apply(Input::Timeout, t + RING_TIMEOUT + CALLEE_RING_SLACK);
        assert_eq!(lonely.end, Some(EndReason::Missed));
        // answered but the caller never starts audio
        let mut stuck = CallState::incoming(t, RING_TIMEOUT);
        stuck.apply(Input::LocalAccept, t);
        assert_eq!(stuck.deadline(), Some(t + SETUP_TIMEOUT));
        stuck.apply(Input::Timeout, t + SETUP_TIMEOUT);
        assert_eq!(stuck.end, Some(EndReason::ConnectionLost));
    }

    #[test]
    fn caller_cancels_and_failures() {
        let t = t0();
        let mut c = CallState::outgoing(t, RING_TIMEOUT);
        c.apply(Input::LocalHangUp, t);
        assert_eq!(c.end, Some(EndReason::HungUp));
        let mut c = CallState::outgoing(t, RING_TIMEOUT);
        c.apply(Input::Unreachable, t);
        assert_eq!(c.end, Some(EndReason::Unavailable));
        let mut c = CallState::outgoing(t, RING_TIMEOUT);
        c.apply(Input::RemoteBusy, t);
        assert_eq!(c.end, Some(EndReason::Busy));
        let mut c = CallState::incoming(t, RING_TIMEOUT);
        assert_eq!(c.apply(Input::MicDenied, t), vec![Effect::Send(Ctrl::Decline), Effect::Close]);
        assert_eq!(c.end, Some(EndReason::MicDenied));
        // out-of-order input is ignored
        let mut c = CallState::incoming(t, RING_TIMEOUT);
        assert!(c.apply(Input::RemoteAccepted, t).is_empty());
        assert!(c.apply(Input::RemoteStarted, t).is_empty(), "audio can't start before we answer");
        assert_eq!(c.phase, CallPhase::Ringing);
        // connection drops mid-call
        let mut c = CallState::outgoing(t, RING_TIMEOUT);
        c.apply(Input::RemoteAccepted, t);
        c.apply(Input::ConnectionLost, t);
        assert_eq!(c.end, Some(EndReason::ConnectionLost));
    }

    /// Alice and Bob press "call" at the same moment.
    #[test]
    fn both_call_at_once_end_up_in_one_call() {
        let space = Hash32([1; 32]);
        let (alice, bob) = (SignPk([2; 32]), SignPk([9; 32]));
        assert!(alice < bob);
        let a_call = LiveCall { id: Hash32([10; 32]), peer: bob, space, dir: Direction::Outgoing };
        let b_call = LiveCall { id: Hash32([11; 32]), peer: alice, space, dir: Direction::Outgoing };

        // Alice's device gets Bob's ring: hers wins, Bob is told so.
        assert_eq!(on_ring(&alice, &bob, &space, std::slice::from_ref(&a_call), false), RingDecision::Glare);
        // Bob's device gets Alice's ring: he drops his call and answers hers.
        assert_eq!(
            on_ring(&bob, &alice, &space, std::slice::from_ref(&b_call), false),
            RingDecision::AutoAccept { replaces: Some(b_call.id) }
        );
        // Bob's outgoing call hears `Glare` and ends quietly as replaced.
        let t = t0();
        let mut bobs = CallState::outgoing(t, RING_TIMEOUT);
        bobs.apply(Input::RemoteGlare, t);
        assert_eq!(bobs.end, Some(EndReason::Replaced));
        // If Glare reached Bob first, Alice's ring still auto-answers.
        assert_eq!(on_ring(&bob, &alice, &space, &[], true), RingDecision::AutoAccept { replaces: None });

        // Alice's call then runs normally on both sides: exactly one call.
        let mut a = CallState::outgoing(t, RING_TIMEOUT);
        let mut b = CallState::incoming(t, RING_TIMEOUT);
        b.apply(Input::LocalAccept, t);
        a.apply(Input::RemoteAccepted, t);
        b.apply(Input::RemoteStarted, t);
        assert_eq!((a.phase, b.phase), (CallPhase::Active, CallPhase::Active));
    }

    #[test]
    fn busy_with_someone_else() {
        let space = Hash32([1; 32]);
        let (me, carol, dave) = (SignPk([2; 32]), SignPk([3; 32]), SignPk([4; 32]));
        let with_carol = LiveCall { id: Hash32([5; 32]), peer: carol, space, dir: Direction::Incoming };
        assert_eq!(on_ring(&me, &dave, &space, &[with_carol.clone()], false), RingDecision::Busy);
        // Carol calling again in the same conversation while we're in an incoming call with her: busy too
        assert_eq!(on_ring(&me, &carol, &space, &[with_carol], false), RingDecision::Busy);
        assert_eq!(on_ring(&me, &dave, &space, &[], false), RingDecision::Ring);
    }
}
