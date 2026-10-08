//! What to do with an incoming ring, free of I/O so every case is testable.
//!
//! Simultaneous calls (two people press call at once in the same
//! conversation) are resolved by [`on_ring`]: the call started by the lower
//! device key wins. The other side drops its own call (nobody was in it
//! yet) and answers the winner's at once, so everyone ends up in one call.
//! A ring for a conversation that already has a call going on gets that
//! call back (`Existing`), and the caller joins it instead.

use std::time::Duration;

use mycel_crypto::SignPk;

use crate::api::{CallPhase, Direction};
use crate::proto::{CallId, CallRef};

/// How long a call rings before giving up (caller side; the callee waits a
/// little longer so the caller's cancel normally arrives first).
pub const RING_TIMEOUT: Duration = Duration::from_secs(45);
pub const CALLEE_RING_SLACK: Duration = Duration::from_secs(5);
/// Answered, waiting for audio to start.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A call that's still live, as [`on_ring`] sees it.
#[derive(Clone, Debug)]
pub struct LiveCall {
    pub call: CallRef,
    pub dir: Direction,
    pub phase: CallPhase,
}

impl LiveCall {
    /// Being in it (or calling out) makes us busy for other conversations;
    /// a call ringing us, or one we may join, doesn't.
    fn engaged(&self) -> bool {
        match self.phase {
            CallPhase::Active | CallPhase::Connecting => true,
            CallPhase::Ringing => self.dir == Direction::Outgoing,
            CallPhase::Joinable | CallPhase::Ended => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingDecision {
    /// Ring the user.
    Ring,
    /// We were calling there too and theirs wins: end `replaces` (if it's
    /// still live) and answer this one right away.
    AutoAccept { replaces: Option<CallId> },
    /// We were calling there too and ours wins: tell them so.
    Glare,
    /// We're already in a call in this conversation: they should join it.
    Existing(CallRef),
    /// We already have this very call.
    Duplicate,
    /// Already in a call elsewhere.
    Busy,
}

/// An incoming ring from `from` (the initiator of `ring`). `expecting` is
/// true when our own call there just lost a glare (theirs is the one to take).
pub fn on_ring(me: &SignPk, from: &SignPk, ring: &CallRef, live: &[LiveCall], expecting: bool) -> RingDecision {
    if live.iter().any(|c| c.call.call == ring.call) {
        return RingDecision::Duplicate;
    }
    let here: Vec<&LiveCall> = live.iter().filter(|c| c.call.space == ring.space).collect();
    if let Some(c) = here.iter().find(|c| c.phase == CallPhase::Active) {
        return RingDecision::Existing(c.call);
    }
    let ours = here
        .iter()
        .find(|c| c.dir == Direction::Outgoing && c.call.initiator == *me && c.phase != CallPhase::Joinable);
    if let Some(ours) = ours {
        // Both calling: the lower key's call survives on both sides.
        return if me < from { RingDecision::Glare } else { RingDecision::AutoAccept { replaces: Some(ours.call.call) } };
    }
    if expecting {
        return RingDecision::AutoAccept { replaces: None };
    }
    if live.iter().any(LiveCall::engaged) {
        return RingDecision::Busy;
    }
    RingDecision::Ring
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycel_crypto::Hash32;

    fn r(space: u8, initiator: &SignPk, nonce: u8) -> CallRef {
        CallRef::new(Hash32([space; 32]), *initiator, [nonce; 16])
    }

    fn live(call: CallRef, dir: Direction, phase: CallPhase) -> LiveCall {
        LiveCall { call, dir, phase }
    }

    #[test]
    fn rings_when_free() {
        let (me, them) = (SignPk([1; 32]), SignPk([2; 32]));
        assert_eq!(on_ring(&me, &them, &r(1, &them, 1), &[], false), RingDecision::Ring);
        // another ring that's only ringing us (or one we may join) isn't busy
        for (dir, phase) in [(Direction::Incoming, CallPhase::Ringing), (Direction::Incoming, CallPhase::Joinable)] {
            let other = live(r(2, &them, 2), dir, phase);
            assert_eq!(on_ring(&me, &them, &r(1, &them, 1), &[other], false), RingDecision::Ring);
        }
    }

    #[test]
    fn busy_elsewhere() {
        let (me, them, x) = (SignPk([1; 32]), SignPk([2; 32]), SignPk([3; 32]));
        for (dir, phase) in [
            (Direction::Incoming, CallPhase::Active),
            (Direction::Outgoing, CallPhase::Ringing),
            (Direction::Incoming, CallPhase::Connecting),
        ] {
            let elsewhere = live(r(9, &x, 1), dir, phase);
            assert_eq!(on_ring(&me, &them, &r(1, &them, 1), &[elsewhere], false), RingDecision::Busy);
        }
    }

    #[test]
    fn simultaneous_calls_lower_key_wins_on_both_sides() {
        let (lo, hi) = (SignPk([1; 32]), SignPk([2; 32]));
        let (lo_call, hi_call) = (r(1, &lo, 1), r(1, &hi, 2));
        // lo hears hi's ring while ringing out: lo's call wins
        let lo_live = [live(lo_call, Direction::Outgoing, CallPhase::Ringing)];
        assert_eq!(on_ring(&lo, &hi, &hi_call, &lo_live, false), RingDecision::Glare);
        // hi hears lo's ring while ringing out: hi drops its call and answers
        let hi_live = [live(hi_call, Direction::Outgoing, CallPhase::Connecting)];
        assert_eq!(
            on_ring(&hi, &lo, &lo_call, &hi_live, false),
            RingDecision::AutoAccept { replaces: Some(hi_call.call) }
        );
        // hi's call already lost (Glare seen): lo's ring is answered at once
        assert_eq!(on_ring(&hi, &lo, &lo_call, &[], true), RingDecision::AutoAccept { replaces: None });
    }

    #[test]
    fn a_call_already_going_on_is_joined_instead() {
        let (me, a, b) = (SignPk([1; 32]), SignPk([2; 32]), SignPk([3; 32]));
        let going = r(1, &a, 1);
        for dir in [Direction::Incoming, Direction::Outgoing] {
            let l = [live(going, dir, CallPhase::Active)];
            assert_eq!(on_ring(&me, &b, &r(1, &b, 2), &l, false), RingDecision::Existing(going));
        }
        let l = [live(going, Direction::Incoming, CallPhase::Active)];
        assert_eq!(on_ring(&me, &a, &going, &l, false), RingDecision::Duplicate);
    }
}
