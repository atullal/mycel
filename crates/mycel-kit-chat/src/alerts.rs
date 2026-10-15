//! When a chat deserves a private local alert.
//!
//! The chat layer decides what is news: a new message from someone else, a
//! fresh message request or group invitation, a call ringing or missed. The
//! native shell then needs no messaging rules: it shows one fixed, generic
//! sentence per kind, suppresses alerts about what's on screen, and
//! withdraws the alerts it's told are stale. Nothing here sees message text,
//! names or attachments; threads and keys are opaque local strings.

use std::collections::{HashMap, HashSet, VecDeque};

use mycel_crypto::Hash32;

/// What an alert is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatAlert {
    Message,
    MessageRequest,
    GroupInvitation,
    IncomingCall,
    MissedCall,
}

/// The newest visible message of a thread, reduced to what the policy needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Latest {
    pub id: Hash32,
    pub mine: bool,
}

/// A logical conversation as the alert policy sees it.
#[derive(Clone, Copy, Debug)]
pub struct ThreadState<'a> {
    /// Stable local identity (`thread::thread_key`, or the space id).
    pub thread: &'a str,
    /// Keys the thread may have been known by before: its spaces' ids (a
    /// request is keyed by its space until accepted; aliases merge later).
    /// Their seen messages carry over and their alerts are withdrawn with it.
    pub previous: &'a [String],
    pub latest: Option<Latest>,
    pub unread: u32,
    /// I'm still a member.
    pub active: bool,
    /// A message request or group invitation I haven't accepted.
    pub request: bool,
    pub direct: bool,
}

/// What the shell should do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Show an alert. A later alert with the same `key` replaces it.
    Alert { kind: ChatAlert, key: String },
    /// Withdraw every delivered alert of this thread key.
    WithdrawThread(String),
    /// Withdraw the alert with this key.
    Withdraw(String),
}

/// Remember this many newest-message ids per thread, so deleting the newest
/// message doesn't alert again about the one that becomes the preview.
const SEEN_PER_THREAD: usize = 32;
/// The runtime keeps only recent call state; so does the policy.
const CALLS_REMEMBERED: usize = 512;

/// Per-device alert state. Not persisted: [`AlertPolicy::seed`] at startup
/// marks the existing history as seen, and every thread counts as possibly
/// having delivered alerts until they are first withdrawn.
#[derive(Default)]
pub struct AlertPolicy {
    seen: HashMap<String, VecDeque<Hash32>>,
    requests_seen: HashSet<String>,
    /// Thread keys known to have nothing delivered: no withdrawal needed.
    quiet: HashSet<String>,
    /// (call, missed) alerts already raised.
    calls: HashSet<(String, bool)>,
    /// Calls whose ringing alert must be withdrawn when they stop ringing.
    ringing: HashSet<String>,
}

pub fn message_key(thread: &str) -> String {
    format!("message:{thread}")
}

pub fn call_key(call: &str) -> String {
    format!("call:{call}")
}

pub fn missed_call_key(call: &str) -> String {
    format!("missed:{call}")
}

impl AlertPolicy {
    /// Startup: what's already here isn't news.
    pub fn seed(&mut self, t: &ThreadState) {
        if t.request {
            self.requests_seen.insert(t.thread.into());
        }
        if let Some(latest) = t.latest {
            self.seen.entry(t.thread.into()).or_default().push_back(latest.id);
        }
    }

    /// A conversation changed (`t` is its state now).
    pub fn conversation(&mut self, t: &ThreadState) -> Vec<Action> {
        if t.request && !t.direct && t.latest.is_none() {
            // A group invitation with nothing to read yet: once.
            let fresh = self.requests_seen.insert(t.thread.into());
            return if fresh && t.active { vec![self.alert(t.thread, ChatAlert::GroupInvitation)] } else { vec![] };
        }
        // Update the seen state even when nothing is shown, so the message
        // isn't news later (it arrived while the chat was read, say).
        let fresh = t.latest.is_some_and(|latest| self.observe(t, latest.id));
        if t.unread == 0 {
            // Read here (or nothing to read): take back what was shown. A
            // pending request keeps its alert until accepted or declined.
            return if t.request { vec![] } else { self.withdraw(t.thread, t.previous) };
        }
        match t.latest {
            Some(latest) if fresh && !latest.mine && t.active => {
                let kind = if t.request { ChatAlert::MessageRequest } else { ChatAlert::Message };
                vec![self.alert(t.thread, kind)]
            }
            _ => vec![],
        }
    }

    /// The conversation is gone from view (declined, or no longer known).
    pub fn gone(&mut self, thread: &str, previous: &[String]) -> Vec<Action> {
        self.withdraw(thread, previous)
    }

    /// An incoming call started ringing: alert once per call.
    pub fn call_ringing(&mut self, call: &str) -> Vec<Action> {
        if !self.remember_call(call, false) {
            return vec![];
        }
        self.ringing.insert(call.into());
        vec![Action::Alert { kind: ChatAlert::IncomingCall, key: call_key(call) }]
    }

    /// An incoming call changed. One that stopped ringing (answered,
    /// declined, ended) loses its ringing alert; one that went unanswered
    /// gets a missed-call alert, once.
    pub fn call_changed(&mut self, call: &str, ringing: bool, missed: bool) -> Vec<Action> {
        let mut actions = vec![];
        if !ringing && self.ringing.remove(call) {
            actions.push(Action::Withdraw(call_key(call)));
        }
        if missed && self.remember_call(call, true) {
            actions.push(Action::Alert { kind: ChatAlert::MissedCall, key: missed_call_key(call) });
        }
        actions
    }

    fn alert(&mut self, thread: &str, kind: ChatAlert) -> Action {
        self.quiet.remove(thread);
        Action::Alert { kind, key: message_key(thread) }
    }

    fn withdraw(&mut self, thread: &str, previous: &[String]) -> Vec<Action> {
        std::iter::once(thread)
            .chain(previous.iter().map(String::as_str))
            .filter(|key| self.quiet.insert((*key).to_string()))
            .map(|key| Action::WithdrawThread(key.into()))
            .collect()
    }

    /// Record `id` as seen in the thread; true if it's new.
    fn observe(&mut self, t: &ThreadState, id: Hash32) -> bool {
        // Seen state recorded under an earlier key (a request's space id, an
        // alias before it merged) carries over instead of alerting again.
        let carried: Vec<Hash32> = t
            .previous
            .iter()
            .filter(|key| key.as_str() != t.thread)
            .filter_map(|key| self.seen.remove(key))
            .flatten()
            .collect();
        let history = self.seen.entry(t.thread.into()).or_default();
        for old in carried {
            if !history.contains(&old) {
                history.push_back(old);
            }
        }
        let fresh = !history.contains(&id);
        if fresh {
            history.push_back(id);
        }
        while history.len() > SEEN_PER_THREAD {
            history.pop_front();
        }
        fresh
    }

    fn remember_call(&mut self, call: &str, missed: bool) -> bool {
        if !self.calls.insert((call.into(), missed)) {
            return false;
        }
        if self.calls.len() > CALLS_REMEMBERED {
            self.calls.retain(|(id, _)| id == call);
            self.ringing.retain(|id| id == call);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest(n: u8) -> Option<Latest> {
        Some(Latest { id: Hash32([n; 32]), mine: false })
    }

    fn chat<'a>(thread: &'a str, previous: &'a [String]) -> ThreadState<'a> {
        ThreadState { thread, previous, latest: latest(1), unread: 1, active: true, request: false, direct: false }
    }

    fn alert(kind: ChatAlert, thread: &str) -> Vec<Action> {
        vec![Action::Alert { kind, key: message_key(thread) }]
    }

    #[test]
    fn new_messages_alert_once_and_existing_history_does_not() {
        let mut policy = AlertPolicy::default();
        let mut t = chat("t", &[]);
        policy.seed(&t);
        assert!(policy.conversation(&t).is_empty(), "startup history is not news");
        t.latest = latest(2);
        assert_eq!(policy.conversation(&t), alert(ChatAlert::Message, "t"));
        assert!(policy.conversation(&t).is_empty(), "one alert per message");
        t.latest = Some(Latest { id: Hash32([3; 32]), mine: true });
        assert!(policy.conversation(&t).is_empty(), "my own messages");
        t.latest = latest(4);
        t.active = false;
        assert!(policy.conversation(&t).is_empty(), "no longer a member");
        t.active = true;
        t.latest = latest(4);
        assert!(policy.conversation(&t).is_empty(), "excluded messages still count as seen");
        t.latest = None;
        assert!(policy.conversation(&t).is_empty());
    }

    #[test]
    fn deleting_the_newest_message_does_not_realert_the_previous_one() {
        let mut policy = AlertPolicy::default();
        let mut t = chat("t", &[]);
        assert_eq!(policy.conversation(&t), alert(ChatAlert::Message, "t"));
        t.latest = latest(2);
        assert_eq!(policy.conversation(&t), alert(ChatAlert::Message, "t"));
        t.latest = latest(1);
        assert!(policy.conversation(&t).is_empty());
    }

    #[test]
    fn reading_withdraws_each_key_once_until_the_next_alert() {
        let mut policy = AlertPolicy::default();
        let previous = ["space-a".to_string(), "space-b".to_string()];
        let mut t = chat("direct:x", &previous);
        t.unread = 0;
        // After a restart anything may still be delivered: withdraw all keys.
        assert_eq!(
            policy.conversation(&t),
            vec![
                Action::WithdrawThread("direct:x".into()),
                Action::WithdrawThread("space-a".into()),
                Action::WithdrawThread("space-b".into()),
            ]
        );
        assert!(policy.conversation(&t).is_empty(), "nothing outstanding: no repeated withdrawals");
        t.unread = 1;
        t.latest = latest(2);
        assert_eq!(policy.conversation(&t), alert(ChatAlert::Message, "direct:x"));
        t.unread = 0;
        assert_eq!(policy.conversation(&t), vec![Action::WithdrawThread("direct:x".into())]);
        assert_eq!(policy.gone("direct:x", &previous), vec![]);
    }

    #[test]
    fn requests_alert_once_keep_their_alert_and_carry_seen_state_when_accepted() {
        let mut policy = AlertPolicy::default();
        let previous = ["space".to_string()];
        let mut request = chat("space", &previous);
        request.request = true;
        request.direct = true;
        assert_eq!(policy.conversation(&request), alert(ChatAlert::MessageRequest, "space"));
        request.unread = 0;
        assert!(policy.conversation(&request).is_empty(), "a pending request keeps its alert");
        // Accepted: now part of the logical direct chat, under a new key.
        let mut accepted = chat("direct:x", &previous);
        accepted.direct = true;
        assert!(policy.conversation(&accepted).is_empty(), "the request's message isn't news again");
        accepted.latest = latest(2);
        assert_eq!(policy.conversation(&accepted), alert(ChatAlert::Message, "direct:x"));
    }

    #[test]
    fn group_invitations_alert_once_and_declining_withdraws() {
        let mut policy = AlertPolicy::default();
        let mut invite = chat("group", &[]);
        invite.request = true;
        invite.latest = None;
        invite.unread = 0;
        assert_eq!(policy.conversation(&invite), alert(ChatAlert::GroupInvitation, "group"));
        assert!(policy.conversation(&invite).is_empty());
        assert_eq!(policy.gone("group", &[]), vec![Action::WithdrawThread("group".into())]);
        let mut startup = AlertPolicy::default();
        startup.seed(&invite);
        assert!(startup.conversation(&invite).is_empty(), "known at startup");
    }

    #[test]
    fn calls_alert_once_withdraw_when_answered_and_report_missed_once() {
        let mut policy = AlertPolicy::default();
        assert_eq!(policy.call_ringing("c"), vec![Action::Alert { kind: ChatAlert::IncomingCall, key: call_key("c") }]);
        assert!(policy.call_ringing("c").is_empty());
        assert!(policy.call_changed("c", true, false).is_empty(), "still ringing");
        assert_eq!(
            policy.call_changed("c", false, true),
            vec![
                Action::Withdraw(call_key("c")),
                Action::Alert { kind: ChatAlert::MissedCall, key: missed_call_key("c") },
            ]
        );
        assert!(policy.call_changed("c", false, true).is_empty());
        // Answered or declined calls only lose the ringing alert.
        policy.call_ringing("d");
        assert_eq!(policy.call_changed("d", false, false), vec![Action::Withdraw(call_key("d"))]);
        assert!(policy.call_changed("d", false, false).is_empty());
        // A group call missed while it goes on without me.
        assert_eq!(policy.call_changed("g", false, true).len(), 1);
        for n in 0..(CALLS_REMEMBERED + 10) {
            policy.call_ringing(&format!("bulk-{n}"));
        }
        assert!(policy.calls.len() <= CALLS_REMEMBERED && policy.ringing.len() <= CALLS_REMEMBERED);
    }
}
