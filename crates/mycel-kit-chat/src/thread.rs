//! One chat per person.
//!
//! Two people can each start a direct chat before their devices meet, so one
//! pair can own several two-person spaces. Every signed message stays in the
//! space it was written in; these rules present such spaces ("aliases") as
//! one logical chat:
//!
//! - [`classify`]: is a space an original private chat between me and one
//!   other person (or the history of one I've left)?
//! - [`thread_key`]: that chat's stable local identity, from the two signing
//!   keys, whichever spaces either device created.
//! - [`canonical_space`]: where new messages and calls go: the same space on
//!   both devices once synchronized, so new history stops splitting.
//! - [`merge`] / [`last`]: one timeline from several histories;
//!   [`newest_first`] / [`oldest_first`] page through it from any message
//!   at a cost proportional to the page, not the history.
//!
//! They are pure functions of facts the runtime caches per space
//! ([`Membership`] from the trust graph, the reduced [`ChatView`]), so neither
//! listing conversations nor handling an event rereads message history.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use mycel_crypto::{Hash32, SignPk};
use mycel_trust::{Action, Role, SpaceGraph, SpaceId};

use crate::{ChatView, Message};

/// Membership facts of one space. They change only when a membership op is
/// accepted (`SpaceGraph::len` grows), never with messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    /// Current members other than keepers (ciphertext-only relays).
    pub people: BTreeMap<SignPk, Role>,
    /// Everyone who ever held a role other than keeper. Once a third person
    /// could read a space it holds group history for good, even after they
    /// were removed; the same goes for a keeper once promoted to reader.
    pub ever_people: BTreeSet<SignPk>,
    /// My current role (`None` once I've left or been removed).
    pub my_role: Option<Role>,
}

impl Membership {
    /// Read from the validated membership graph (O(membership ops)).
    pub fn of(graph: &SpaceGraph, me: &SignPk) -> Membership {
        let state = graph.state();
        let people = state.members.iter().filter(|(_, m)| m.role != Role::Relay).map(|(pk, m)| (*pk, m.role)).collect();
        let resolution = graph.resolution();
        let ever_people = resolution
            .order
            .iter()
            .filter(|id| resolution.is_valid(id))
            .filter_map(|id| graph.get(id))
            .filter_map(|op| match &op.op.action {
                Action::Genesis { founder, .. } => Some(founder.sign_pk),
                Action::Add { member, role, .. } if *role != Role::Relay => Some(member.sign_pk),
                Action::SetRole { member, role, .. } if *role != Role::Relay => Some(*member),
                _ => None,
            })
            .collect();
        Membership { people, ever_people, my_role: state.role(me) }
    }

    fn can_write(&self, who: &SignPk) -> bool {
        self.people.get(who).is_some_and(|r| r.can_write())
    }
}

/// How a space takes part in a logical direct chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Direct {
    /// The other person.
    pub peer: SignPk,
    /// I'm still in it. Spaces I've left (or was removed from) form a
    /// separate, read-only history of the chat: after leaving I no longer
    /// learn who joins them, so they never merge into a current chat.
    pub current: bool,
}

/// Is this space an original private chat between me and exactly one other
/// person? It must have been created direct, never named or marked a group
/// by an admin, and its only people, ever, must be the two of us. Keepers
/// don't count. Local consent (message requests, declined and still-arriving
/// invitations) is the caller's to check: those spaces always stay apart.
pub fn classify(me: &SignPk, view: &ChatView, m: &Membership) -> Option<Direct> {
    if !view.direct || view.ever_group || m.ever_people.len() != 2 || !m.ever_people.contains(me) {
        return None;
    }
    let peer = *m.ever_people.iter().find(|k| *k != me)?;
    match m.my_role {
        Some(role) if role.can_read() => (m.people.len() == 2).then_some(Direct { peer, current: true }),
        None => Some(Direct { peer, current: false }),
        Some(_) => None, // keeping someone else's chat
    }
}

/// The stable local identity of a logical direct chat: the same on both
/// devices whichever spaces exist. Local only, never a wire ID.
pub fn thread_key(me: &SignPk, direct: &Direct) -> String {
    let mut keys = [*me, direct.peer];
    keys.sort();
    let bytes: Vec<u8> = keys.iter().flat_map(|k| k.0).collect();
    let digest = Hash32::digest("mycel/v0/direct-thread", &bytes);
    if direct.current { format!("direct:{digest}") } else { format!("direct-history:{digest}") }
}

/// Where a logical direct chat posts and calls next: the lowest space in
/// which both of us can write. Both devices compute it from replicated
/// membership alone, so once synchronized they choose the same space and new
/// history stops splitting across aliases. If none qualifies (one of us is
/// read-only everywhere else), the lowest space I can write in.
pub fn canonical_space<'a>(
    me: &SignPk,
    peer: &SignPk,
    aliases: impl IntoIterator<Item = (SpaceId, &'a Membership)>,
) -> Option<SpaceId> {
    let (mut both, mut mine): (Option<SpaceId>, Option<SpaceId>) = (None, None);
    for (space, m) in aliases {
        if !m.can_write(me) {
            continue;
        }
        mine = Some(mine.map_or(space, |s| s.min(space)));
        if m.can_write(peer) {
            both = Some(both.map_or(space, |s| s.min(space)));
        }
    }
    both.or(mine)
}

/// One history in a merged timeline.
#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    pub view: &'a ChatView,
    /// None of this history sorts before this time (ms). The runtime passes
    /// when this device first saw the space, so a space that turns up later
    /// (a contact can create one at any time) can't backdate messages into
    /// history that was already here. 0 for spaces older than that record.
    pub floor_ms: u64,
}

/// (time, source, index): sorting by it is the merged order.
fn key(sources: &[Source], s: usize, i: usize) -> (u64, usize, usize) {
    (sources[s].view.messages[i].order_ms.max(sources[s].floor_ms), s, i)
}

/// Several causally ordered histories as one timeline of (source, index),
/// oldest first. Each source keeps its causal order; across sources messages
/// interleave by author time made monotone along each history
/// ([`Message::order_ms`]) and clamped to the source's floor, ties broken by
/// source position. So the same sources and floors always give the same
/// order, a reply never precedes its parent, and no message precedes the
/// arrival of the space it was written in.
pub fn merge(sources: &[Source]) -> Vec<(usize, usize)> {
    let mut heads = BTreeSet::new();
    for (s, source) in sources.iter().enumerate() {
        if !source.view.messages.is_empty() {
            heads.insert(key(sources, s, 0));
        }
    }
    let mut out = Vec::with_capacity(sources.iter().map(|s| s.view.messages.len()).sum());
    while let Some((_, s, i)) = heads.pop_first() {
        out.push((s, i));
        if i + 1 < sources[s].view.messages.len() {
            heads.insert(key(sources, s, i + 1));
        }
    }
    out
}

/// The newest message `keep` accepts, in [`merge`] order, without merging:
/// each history is scanned back from its end only to its newest kept message.
pub fn last(sources: &[Source], mut keep: impl FnMut(usize, &Message) -> bool) -> Option<(usize, usize)> {
    sources
        .iter()
        .enumerate()
        .filter_map(|(s, source)| {
            let i = source.view.messages.iter().rposition(|m| keep(s, m))?;
            Some(key(sources, s, i))
        })
        .max()
        .map(|(_, s, i)| (s, i))
}

/// Index of the first message of source `s` that sorts after `anchor` in
/// [`merge`] order (O(log n): keys only grow along a history).
fn split(sources: &[Source], s: usize, anchor: (usize, usize)) -> usize {
    let (anchor_source, anchor_index) = anchor;
    if s == anchor_source {
        return anchor_index + 1;
    }
    let (k, ..) = key(sources, anchor_source, anchor_index);
    let floor = sources[s].floor_ms;
    sources[s].view.messages.partition_point(|m| (m.order_ms.max(floor), s) < (k, anchor_source))
}

/// The timeline backwards from just before `anchor` (from the newest
/// message without one), lazily: O(log n) to start, then O(log sources) per
/// message, so a page costs its own size whatever the history's length.
pub fn newest_first<'a>(
    sources: &'a [Source<'a>],
    anchor: Option<(usize, usize)>,
) -> impl Iterator<Item = (usize, usize)> + 'a {
    let mut heads = BinaryHeap::new();
    for s in 0..sources.len() {
        let end = match anchor {
            None => sources[s].view.messages.len(),
            Some(a) if a.0 == s => a.1,
            Some(a) => split(sources, s, a),
        };
        if end > 0 {
            heads.push(key(sources, s, end - 1));
        }
    }
    std::iter::from_fn(move || {
        let (_, s, i) = heads.pop()?;
        if i > 0 {
            heads.push(key(sources, s, i - 1));
        }
        Some((s, i))
    })
}

/// The timeline forwards from just after `anchor`, lazily (as
/// [`newest_first`]).
pub fn oldest_first<'a>(
    sources: &'a [Source<'a>],
    anchor: (usize, usize),
) -> impl Iterator<Item = (usize, usize)> + 'a {
    let mut heads = BinaryHeap::new();
    for s in 0..sources.len() {
        let start = split(sources, s, anchor);
        if start < sources[s].view.messages.len() {
            heads.push(Reverse(key(sources, s, start)));
        }
    }
    std::iter::from_fn(move || {
        let Reverse((_, s, i)) = heads.pop()?;
        if i + 1 < sources[s].view.messages.len() {
            heads.push(Reverse(key(sources, s, i + 1)));
        }
        Some((s, i))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatOp, reduce};
    use mycel_sync::FeedItem;

    fn pk(b: u8) -> SignPk {
        SignPk([b; 32])
    }

    fn text(n: u8, author: u8, ts_ms: u64) -> FeedItem {
        FeedItem {
            id: Hash32([n; 32]),
            author: pk(author),
            author_role: Role::Writer,
            ts_ms,
            deps: vec![],
            body: ChatOp::Text { body: format!("m{n}"), reply_to: None, attachments: vec![] }.encode(),
        }
    }

    fn meta(n: u8, title: Option<&str>, direct: bool) -> FeedItem {
        FeedItem {
            id: Hash32([n; 32]),
            author: pk(1),
            author_role: Role::Admin,
            ts_ms: 0,
            deps: vec![],
            body: ChatOp::Meta { title: title.map(Into::into), direct }.encode(),
        }
    }

    fn two_people() -> Membership {
        Membership {
            people: BTreeMap::from([(pk(1), Role::Admin), (pk(2), Role::Writer)]),
            ever_people: BTreeSet::from([pk(1), pk(2)]),
            my_role: Some(Role::Admin),
        }
    }

    #[test]
    fn only_original_untitled_two_person_spaces_are_direct() {
        let me = pk(1);
        let direct = reduce(&[meta(1, None, true)]);
        assert_eq!(classify(&me, &direct, &two_people()), Some(Direct { peer: pk(2), current: true }));

        // Named or marked a group once: group history for good.
        let renamed_back = reduce(&[meta(1, Some("Team"), false), meta(2, None, true)]);
        assert!(renamed_back.direct && renamed_back.title.is_none());
        assert_eq!(classify(&me, &renamed_back, &two_people()), None);
        assert_eq!(classify(&me, &reduce(&[meta(1, None, false)]), &two_people()), None);

        // A third person who ever had access, even if removed since.
        let mut former_group = two_people();
        former_group.ever_people.insert(pk(3));
        assert_eq!(classify(&me, &direct, &former_group), None);

        // Keepers aren't people; a space I keep for others isn't my chat.
        let mut kept = two_people();
        kept.my_role = Some(Role::Relay);
        assert_eq!(classify(&me, &direct, &kept), None);

        // The other person left: just me.
        let mut alone = two_people();
        alone.people.remove(&pk(2));
        assert_eq!(classify(&me, &direct, &alone), None);

        // I left: the chat's history, never merged with a current chat.
        let mut left = two_people();
        left.people.remove(&pk(1));
        left.my_role = None;
        let former = classify(&me, &direct, &left).unwrap();
        assert_eq!(former, Direct { peer: pk(2), current: false });
        let current = Direct { peer: pk(2), current: true };
        assert_ne!(thread_key(&me, &former), thread_key(&me, &current));
        assert_eq!(
            thread_key(&me, &current),
            thread_key(&pk(2), &Direct { peer: me, current: true }),
            "both people derive the same key"
        );
    }

    #[test]
    fn both_devices_post_to_the_lowest_space_both_can_write() {
        let (me, peer) = (pk(1), pk(2));
        let (low, mid, high) = (Hash32([1; 32]), Hash32([2; 32]), Hash32([3; 32]));
        let writable = two_people();
        let mut peer_read_only = two_people();
        peer_read_only.people.insert(peer, Role::Reader);
        let mut me_read_only = two_people();
        me_read_only.people.insert(me, Role::Reader);
        let choice = canonical_space(&me, &peer, [(high, &writable), (low, &peer_read_only), (mid, &writable)]);
        assert_eq!(choice, Some(mid), "the lowest space where both can write, regardless of input order");
        // My peer computes the same from the same replicated membership.
        let theirs = canonical_space(&peer, &me, [(low, &peer_read_only), (mid, &writable), (high, &writable)]);
        assert_eq!(theirs, Some(mid));
        assert_eq!(canonical_space(&me, &peer, [(high, &peer_read_only), (low, &peer_read_only)]), Some(low));
        assert_eq!(canonical_space(&me, &peer, [(low, &me_read_only)]), None);
    }

    #[test]
    fn a_late_alias_cannot_backdate_messages_into_existing_history() {
        // The original chat: messages at 100, 200, 300.
        let old = reduce(&[text(1, 1, 100), text(2, 2, 200), text(3, 1, 300)]);
        // A space the contact created later, first seen here at 1000, whose
        // messages claim to predate everything.
        let forged = reduce(&[text(4, 2, 50), text(5, 2, 1100)]);
        let sources = [Source { view: &old, floor_ms: 0 }, Source { view: &forged, floor_ms: 1000 }];
        let order: Vec<u8> = merge(&sources).into_iter().map(|(s, i)| sources[s].view.messages[i].id.0[0]).collect();
        assert_eq!(order, vec![1, 2, 3, 4, 5]);
        // Without the floor the backdated message would lead the history.
        let unclamped = [Source { view: &old, floor_ms: 0 }, Source { view: &forged, floor_ms: 0 }];
        assert_eq!(merge(&unclamped)[0], (1, 0));
    }

    #[test]
    fn merge_keeps_each_history_causal_and_last_agrees_with_merge() {
        // Clock skew: a reply (3) carries an earlier time than its parent (2).
        let a = reduce(&[text(1, 1, 100), text(2, 1, 500), text(3, 2, 150), text(4, 1, 600)]);
        let b = reduce(&[text(5, 2, 120), text(6, 2, 550), text(7, 2, 900)]);
        assert_eq!(a.messages[2].order_ms, 500, "monotone along the feed");
        let sources = [Source { view: &a, floor_ms: 0 }, Source { view: &b, floor_ms: 0 }];
        let merged = merge(&sources);
        let ids: Vec<u8> = merged.iter().map(|(s, i)| sources[*s].view.messages[*i].id.0[0]).collect();
        assert_eq!(ids, vec![1, 5, 2, 3, 6, 4, 7]);
        assert_eq!(last(&sources, |_, _| true), merged.last().copied());
        // Skipping hidden/deleted messages finds the newest remaining one.
        let newest_of_a = last(&sources, |s, m| s == 0 || m.id.0[0] != 7);
        assert_eq!(newest_of_a, Some((0, 3)));
        assert_eq!(last(&sources, |_, _| false), None);
        assert!(merge(&[]).is_empty());
    }

    #[test]
    fn paging_from_any_message_matches_the_merged_timeline() {
        let a = reduce(&[text(1, 1, 100), text(2, 1, 500), text(3, 2, 150), text(4, 1, 600), text(8, 1, 600)]);
        let b = reduce(&[text(5, 2, 120), text(6, 2, 550), text(7, 2, 900), text(9, 2, 600)]);
        for floors in [(0, 0), (0, 580), (700, 0)] {
            let sources = [Source { view: &a, floor_ms: floors.0 }, Source { view: &b, floor_ms: floors.1 }];
            let merged = merge(&sources);
            let newest: Vec<_> = newest_first(&sources, None).collect();
            assert_eq!(newest, merged.iter().rev().copied().collect::<Vec<_>>());
            for (at, anchor) in merged.iter().enumerate() {
                let before: Vec<_> = newest_first(&sources, Some(*anchor)).collect();
                assert_eq!(before, merged[..at].iter().rev().copied().collect::<Vec<_>>(), "before {anchor:?}");
                let after: Vec<_> = oldest_first(&sources, *anchor).collect();
                assert_eq!(after, merged[at + 1..].to_vec(), "after {anchor:?}");
            }
        }
    }

    #[test]
    fn a_page_of_a_huge_merged_history_costs_the_page() {
        fn history(author: u8, len: u64, offset: u64) -> ChatView {
            let items: Vec<FeedItem> = (0..len)
                .map(|n| FeedItem {
                    id: Hash32::digest("test/page", &[&n.to_le_bytes()[..], &[author]].concat()),
                    author: pk(author),
                    author_role: Role::Writer,
                    ts_ms: n * 2 + offset,
                    deps: vec![],
                    body: ChatOp::Text { body: String::new(), reply_to: None, attachments: vec![] }.encode(),
                })
                .collect();
            reduce(&items)
        }
        let (a, b) = (history(1, 60_000, 0), history(2, 40_000, 1));
        let sources = [Source { view: &a, floor_ms: 0 }, Source { view: &b, floor_ms: 0 }];
        let started = std::time::Instant::now();
        for anchor in [(0, 100), (0, 30_000), (1, 39_999), (0, 59_999)] {
            assert_eq!(newest_first(&sources, Some(anchor)).take(50).count(), 50);
            assert_eq!(oldest_first(&sources, (anchor.0, anchor.1 / 2)).take(50).count(), 50);
        }
        assert_eq!(newest_first(&sources, None).next(), Some((0, 59_999)));
        // Merging 100k messages takes far longer than these few pages.
        assert!(started.elapsed() < std::time::Duration::from_millis(200), "{:?}", started.elapsed());
    }
}
