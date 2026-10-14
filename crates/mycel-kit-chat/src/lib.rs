//! Chat kit (docs/ARCHITECTURE.md §L5): the messaging data model.
//!
//! A conversation is a Space with one Feed (`messages`). Every entry is a
//! postcard-encoded [`ChatOp`]. [`reduce`] folds the causally ordered feed into
//! a [`ChatView`] deterministically, so every peer shows the same thing. The
//! reducer enforces the chat rules that the trust layer can't express:
//! only a message's author may edit or delete it, and only admins may retitle.
//! [`ChatState`] does the same fold entry by entry, so a new message costs
//! O(1) however long the history, and can take back its newest entries when
//! a late entry belongs before them.
//!
//! [`thread`] decides which conversations are one logical chat with a person
//! and how their histories merge; [`alerts`] decides when a chat deserves a
//! private local alert. Both are pure, so the runtime only caches their inputs.

pub mod alerts;
pub mod thread;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use mycel_crypto::{Hash32, SignPk};
use mycel_sync::{FeedItem, StreamId, StreamKind};
use mycel_trust::Role;
use serde::{Deserialize, Serialize};

pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_EMOJI: usize = 32;
pub const MAX_NAME: usize = 64;

/// The feed every conversation uses for its messages.
pub fn messages_feed() -> StreamId {
    StreamId::named(StreamKind::Feed, "mycel.chat.messages")
}

/// A file attached to a message. The blob is encrypted with `key`/`nonce`,
/// which travel only inside the (end-to-end encrypted) message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub blob: Hash32,
    pub key: [u8; 32],
    pub nonce: [u8; 24],
    pub name: String,
    pub mime: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatOp {
    Text {
        body: String,
        reply_to: Option<Hash32>,
        attachments: Vec<AttachmentRef>,
    },
    Edit { target: Hash32, body: String },
    Delete { target: Hash32 },
    React { target: Hash32, emoji: String, on: bool },
    /// "I have read everything up to and including `up_to`."
    Receipt { up_to: Hash32 },
    /// The author's display name in this conversation.
    Profile { name: String },
    /// Conversation metadata (admins only).
    Meta { title: Option<String>, direct: bool },
}

impl ChatOp {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("encodes")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

/// Ephemeral (never stored) chat signals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatSignal {
    Typing,
}

impl ChatSignal {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("encodes")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: Hash32,
    pub author: SignPk,
    pub ts_ms: u64,
    /// The latest author time at or before this message in feed (causal)
    /// order. Merged timelines sort by it, so a backdated message can't
    /// move ahead of its own causal past ([`thread::merge`]).
    pub order_ms: u64,
    pub body: String,
    pub reply_to: Option<Hash32>,
    pub edited: bool,
    pub deleted: bool,
    pub attachments: Vec<AttachmentRef>,
    /// emoji → who reacted
    pub reactions: BTreeMap<String, BTreeSet<SignPk>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatView {
    /// In feed (causal) order.
    pub messages: Vec<Message>,
    pub names: HashMap<SignPk, String>,
    /// member → index (in `messages`) of the last message they've read.
    pub read_upto: HashMap<SignPk, usize>,
    pub title: Option<String>,
    pub direct: bool,
    /// An admin once marked this conversation as a group or named it. Later
    /// metadata can't turn group history back into a private direct chat.
    pub ever_group: bool,
    /// Signed names per writer, with the versions needed to decide which
    /// one is current across conversations.
    pub profiles: HashMap<SignPk, ProfileHistory>,
    /// message id → index in `messages`.
    index: HashMap<Hash32, usize>,
}

/// One writer's Profile entries in a conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileHistory {
    /// The causally latest entry: (author time, id) and its name.
    pub latest: (u64, Hash32),
    pub name: String,
    /// The greatest (author time, id) among them.
    pub high_water: (u64, Hash32),
    pub ids: HashSet<Hash32>,
}

impl ChatView {
    pub fn index_of(&self, id: &Hash32) -> Option<usize> {
        self.index.get(id).copied()
    }

    /// Messages by others after my read marker.
    pub fn unread_for(&self, me: &SignPk) -> u32 {
        let start = self.read_upto.get(me).map_or(0, |i| i + 1);
        self.messages[start.min(self.messages.len())..]
            .iter()
            .filter(|m| m.author != *me && !m.deleted)
            .count() as u32
    }

    pub fn has_read(&self, who: &SignPk, index: usize) -> bool {
        self.read_upto.get(who).is_some_and(|i| *i >= index)
    }
}

fn clamp(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Fold causally ordered feed items into the conversation view.
pub fn reduce(items: &[FeedItem]) -> ChatView {
    let mut state = ChatState::default();
    state.apply(items);
    Arc::unwrap_or_clone(state.view)
}

/// Entries that can still be taken back ([`ChatState::rewind`]).
pub const UNDO_WINDOW: usize = 1024;

/// A [`ChatView`] maintained entry by entry: [`ChatState::apply`] folds new
/// entries at O(1) each, and [`ChatState::rewind`] takes back the newest
/// ones (up to [`UNDO_WINDOW`]) when a late entry belongs before them.
#[derive(Clone, Debug, Default)]
pub struct ChatState {
    view: Arc<ChatView>,
    /// How to take back each of the newest entries, oldest first.
    undo: VecDeque<Undo>,
    applied: usize,
}

/// How to take back one entry.
#[derive(Clone, Debug)]
enum Undo {
    Nothing,
    /// A new message: remove it and restore its author's read marker.
    Text { author: SignPk, read: Option<usize> },
    /// A message changed: restore it.
    Message { at: usize, before: Box<Message> },
    Receipt { who: SignPk, read: Option<usize> },
    Profile { who: SignPk, name: Option<String>, history: Option<ProfileHistory> },
    Meta { title: Option<String>, direct: bool, ever_group: bool },
}

impl ChatState {
    pub fn view(&self) -> &Arc<ChatView> {
        &self.view
    }

    /// Entries folded so far.
    pub fn len(&self) -> usize {
        self.applied
    }

    pub fn is_empty(&self) -> bool {
        self.applied == 0
    }

    /// Fold entries that follow everything folded so far. Returns whether
    /// any signed name (Profile) changed.
    pub fn apply(&mut self, items: &[FeedItem]) -> bool {
        if items.is_empty() {
            return false;
        }
        let view = Arc::make_mut(&mut self.view);
        // Only the newest entries can be taken back: don't record the rest
        // (and keep the records contiguous with the end).
        let record_from = items.len().saturating_sub(UNDO_WINDOW);
        if record_from > 0 {
            self.undo.clear();
        }
        let mut profiles = false;
        for (n, item) in items.iter().enumerate() {
            let undo = fold(view, item);
            profiles |= matches!(undo, Undo::Profile { .. });
            if n >= record_from {
                self.undo.push_back(undo);
            }
        }
        self.applied += items.len();
        while self.undo.len() > UNDO_WINDOW {
            self.undo.pop_front();
        }
        profiles
    }

    /// Take back the newest entries until `len` remain. False (and nothing
    /// changed) when that reaches past the undo window: rebuild instead.
    pub fn rewind(&mut self, len: usize) -> bool {
        if len >= self.applied {
            return true;
        }
        if self.applied - len > self.undo.len() {
            return false;
        }
        let view = Arc::make_mut(&mut self.view);
        while self.applied > len {
            let undo = self.undo.pop_back().expect("checked above");
            unfold(view, undo);
            self.applied -= 1;
        }
        true
    }
}

/// Apply one entry; how to take it back.
fn fold(view: &mut ChatView, item: &FeedItem) -> Undo {
    let Some(op) = ChatOp::decode(&item.body) else {
        return Undo::Nothing; // unknown/garbage entries are ignored by everyone
    };
    match op {
        ChatOp::Text { body, reply_to, attachments } => {
            if body.len() > MAX_BODY {
                return Undo::Nothing;
            }
            let at = view.messages.len();
            let order_ms = view.messages.last().map_or(item.ts_ms, |m| m.order_ms.max(item.ts_ms));
            view.index.insert(item.id, at);
            view.messages.push(Message {
                id: item.id,
                author: item.author,
                ts_ms: item.ts_ms,
                order_ms,
                body,
                reply_to,
                edited: false,
                deleted: false,
                attachments,
                reactions: BTreeMap::new(),
            });
            // Writing a message implies having read everything before it.
            let read = view.read_upto.get(&item.author).copied();
            view.read_upto.insert(item.author, read.map_or(at, |r| r.max(at)));
            Undo::Text { author: item.author, read }
        }
        ChatOp::Edit { target, body } => {
            let Some(at) = view.index_of(&target) else { return Undo::Nothing };
            let m = &mut view.messages[at];
            if m.author != item.author || m.deleted || body.len() > MAX_BODY {
                return Undo::Nothing;
            }
            let before = Box::new(m.clone());
            m.body = body;
            m.edited = true;
            Undo::Message { at, before }
        }
        ChatOp::Delete { target } => {
            let Some(at) = view.index_of(&target) else { return Undo::Nothing };
            let m = &mut view.messages[at];
            if m.author != item.author {
                return Undo::Nothing;
            }
            let before = Box::new(m.clone());
            m.deleted = true;
            m.body.clear();
            m.attachments.clear();
            m.reactions.clear();
            Undo::Message { at, before }
        }
        ChatOp::React { target, emoji, on } => {
            if emoji.is_empty() || emoji.len() > MAX_EMOJI {
                return Undo::Nothing;
            }
            let Some(at) = view.index_of(&target) else { return Undo::Nothing };
            let m = &mut view.messages[at];
            if m.deleted {
                return Undo::Nothing;
            }
            let before = Box::new(m.clone());
            let who = m.reactions.entry(emoji.clone()).or_default();
            if on {
                who.insert(item.author);
            } else {
                who.remove(&item.author);
                if who.is_empty() {
                    m.reactions.remove(&emoji);
                }
            }
            Undo::Message { at, before }
        }
        ChatOp::Receipt { up_to } => {
            let Some(i) = view.index_of(&up_to) else { return Undo::Nothing };
            let read = view.read_upto.get(&item.author).copied();
            view.read_upto.insert(item.author, read.map_or(i, |r| r.max(i)));
            Undo::Receipt { who: item.author, read }
        }
        ChatOp::Profile { name } => {
            let name = clamp(name.trim(), MAX_NAME);
            if name.is_empty() {
                return Undo::Nothing;
            }
            let undo = Undo::Profile {
                who: item.author,
                name: view.names.get(&item.author).cloned(),
                history: view.profiles.get(&item.author).cloned(),
            };
            // Only writers' names count beyond this conversation.
            if item.author_role.can_write() {
                let version = (item.ts_ms, item.id);
                let history = view.profiles.entry(item.author).or_insert_with(|| ProfileHistory {
                    latest: version,
                    name: String::new(),
                    high_water: version,
                    ids: HashSet::new(),
                });
                history.high_water = history.high_water.max(version);
                history.ids.insert(item.id);
                history.latest = version;
                history.name = name.clone();
            }
            view.names.insert(item.author, name);
            undo
        }
        ChatOp::Meta { title, direct } => {
            if item.author_role != Role::Admin {
                return Undo::Nothing;
            }
            let undo = Undo::Meta { title: view.title.take(), direct: view.direct, ever_group: view.ever_group };
            view.title = title.map(|t| clamp(t.trim(), 128)).filter(|t| !t.is_empty());
            view.direct = direct;
            view.ever_group |= !direct || view.title.is_some();
            undo
        }
    }
}

fn unfold(view: &mut ChatView, undo: Undo) {
    let restore = |map: &mut HashMap<SignPk, usize>, who: SignPk, read: Option<usize>| match read {
        Some(r) => map.insert(who, r),
        None => map.remove(&who),
    };
    match undo {
        Undo::Nothing => {}
        Undo::Text { author, read } => {
            if let Some(m) = view.messages.pop() {
                view.index.remove(&m.id);
            }
            restore(&mut view.read_upto, author, read);
        }
        Undo::Message { at, before } => view.messages[at] = *before,
        Undo::Receipt { who, read } => {
            restore(&mut view.read_upto, who, read);
        }
        Undo::Profile { who, name, history } => {
            match name {
                Some(n) => view.names.insert(who, n),
                None => view.names.remove(&who),
            };
            match history {
                Some(h) => view.profiles.insert(who, h),
                None => view.profiles.remove(&who),
            };
        }
        Undo::Meta { title, direct, ever_group } => {
            view.title = title;
            view.direct = direct;
            view.ever_group = ever_group;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> SignPk {
        SignPk([b; 32])
    }

    fn item(n: u8, author: u8, role: Role, op: ChatOp) -> FeedItem {
        FeedItem {
            id: Hash32([n; 32]),
            author: pk(author),
            author_role: role,
            ts_ms: n as u64,
            deps: vec![],
            body: op.encode(),
        }
    }

    fn text(n: u8, author: u8, body: &str) -> FeedItem {
        item(n, author, Role::Writer, ChatOp::Text { body: body.into(), reply_to: None, attachments: vec![] })
    }

    #[test]
    fn edits_and_deletes_are_author_only() {
        let items = vec![
            text(1, 1, "hello"),
            item(2, 2, Role::Admin, ChatOp::Edit { target: Hash32([1; 32]), body: "hacked".into() }),
            item(3, 2, Role::Admin, ChatOp::Delete { target: Hash32([1; 32]) }),
            item(4, 1, Role::Writer, ChatOp::Edit { target: Hash32([1; 32]), body: "hello!".into() }),
        ];
        let v = reduce(&items);
        assert_eq!(v.messages[0].body, "hello!");
        assert!(v.messages[0].edited && !v.messages[0].deleted);
        let mut items = items;
        items.push(item(5, 1, Role::Writer, ChatOp::Delete { target: Hash32([1; 32]) }));
        items.push(item(6, 1, Role::Writer, ChatOp::Edit { target: Hash32([1; 32]), body: "zombie".into() }));
        let v = reduce(&items);
        assert!(v.messages[0].deleted);
        assert_eq!(v.messages[0].body, "");
    }

    #[test]
    fn deletion_clears_all_media_and_reactions_and_cannot_be_undone_by_later_ops() {
        for (mime, name) in [("image/png", "photo.png"), ("text/plain", "file.txt"), ("audio/mp4", "voice.m4a")] {
            let attachment = AttachmentRef {
                blob: Hash32([20; 32]), key: [21; 32], nonce: [22; 24],
                name: name.into(), mime: mime.into(), size: 123,
            };
            let target = Hash32([1; 32]);
            let mut items = vec![
                item(1, 1, Role::Writer, ChatOp::Text { body: "caption".into(), reply_to: None, attachments: vec![attachment.clone()] }),
                item(2, 2, Role::Writer, ChatOp::React { target, emoji: "test".into(), on: true }),
                item(3, 2, Role::Admin, ChatOp::Delete { target }),
            ];
            let forged = reduce(&items);
            assert!(!forged.messages[0].deleted);
            assert_eq!(forged.messages[0].attachments, vec![attachment]);
            items.extend([
                item(4, 1, Role::Writer, ChatOp::Delete { target }),
                item(5, 1, Role::Writer, ChatOp::Edit { target, body: "resurrect".into() }),
                item(6, 2, Role::Writer, ChatOp::React { target, emoji: "test".into(), on: true }),
            ]);
            let deleted = reduce(&items);
            let message = &deleted.messages[0];
            assert!(message.deleted);
            assert!(message.body.is_empty() && message.attachments.is_empty() && message.reactions.is_empty());
        }
    }

    #[test]
    fn reactions_toggle_and_receipts_track_unread() {
        let items = vec![
            text(1, 1, "a"),
            text(2, 1, "b"),
            item(3, 2, Role::Writer, ChatOp::React { target: Hash32([1; 32]), emoji: "👍".into(), on: true }),
            item(4, 3, Role::Writer, ChatOp::React { target: Hash32([1; 32]), emoji: "👍".into(), on: true }),
            item(5, 3, Role::Writer, ChatOp::React { target: Hash32([1; 32]), emoji: "👍".into(), on: false }),
            item(6, 2, Role::Writer, ChatOp::Receipt { up_to: Hash32([1; 32]) }),
        ];
        let v = reduce(&items);
        assert_eq!(v.messages[0].reactions["👍"], BTreeSet::from([pk(2)]));
        assert_eq!(v.unread_for(&pk(2)), 1);
        assert_eq!(v.unread_for(&pk(1)), 0, "own messages are never unread");
        assert_eq!(v.unread_for(&pk(9)), 2);
        assert!(v.has_read(&pk(1), 1), "author has read up to own message");
    }

    #[test]
    fn meta_requires_admin_and_profiles_name_people() {
        let items = vec![
            item(1, 1, Role::Admin, ChatOp::Meta { title: Some("Team".into()), direct: false }),
            item(2, 2, Role::Writer, ChatOp::Meta { title: Some("pwned".into()), direct: true }),
            item(3, 2, Role::Writer, ChatOp::Profile { name: "  Bob  ".into() }),
        ];
        let v = reduce(&items);
        assert_eq!(v.title.as_deref(), Some("Team"));
        assert!(!v.direct);
        assert_eq!(v.names[&pk(2)], "Bob");
    }

    /// A random conversation: three people (one admin) writing, editing,
    /// deleting, reacting, reading, renaming themselves and the chat.
    fn random_ops(seed: u64, len: usize) -> Vec<FeedItem> {
        let mut rng = seed;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut texts: Vec<(Hash32, u8)> = vec![];
        let mut items = vec![];
        for n in 0..len {
            let author = 1 + (next() % 3) as u8;
            let role = if author == 1 { Role::Admin } else { Role::Writer };
            let id = Hash32::digest("test/op", &[seed.to_le_bytes(), (n as u64).to_le_bytes()].concat());
            let target = |r: u64| texts.get((r as usize) % texts.len().max(1)).copied();
            let op = match next() % 9 {
                0..=2 => ChatOp::Text { body: format!("m{n}"), reply_to: None, attachments: vec![] },
                3 => match target(next()) {
                    Some((t, by)) => ChatOp::Edit { target: t, body: format!("edit {n} by {by}") },
                    None => ChatOp::Receipt { up_to: Hash32([0; 32]) },
                },
                4 => match target(next()) {
                    Some((t, _)) => ChatOp::Delete { target: t },
                    None => ChatOp::Profile { name: "x".into() },
                },
                5 => match target(next()) {
                    Some((t, _)) => ChatOp::React { target: t, emoji: ["a", "b"][(next() % 2) as usize].into(), on: next() % 3 != 0 },
                    None => ChatOp::Profile { name: "y".into() },
                },
                6 => match target(next()) {
                    Some((t, _)) => ChatOp::Receipt { up_to: t },
                    None => ChatOp::Profile { name: "z".into() },
                },
                7 => ChatOp::Profile { name: format!("name {n}") },
                _ => ChatOp::Meta { title: (next() % 2 == 0).then(|| format!("t{n}")), direct: next() % 2 == 0 },
            };
            if matches!(op, ChatOp::Text { .. }) {
                texts.push((id, author));
            }
            items.push(FeedItem { id, author: pk(author), author_role: role, ts_ms: n as u64, deps: vec![], body: op.encode() });
        }
        items
    }

    #[test]
    fn folding_entry_by_entry_and_rewinding_match_a_full_reduce() {
        for seed in 1..30u64 {
            let items = random_ops(seed * 104_729, 300);
            let mut state = ChatState::default();
            let mut at = 0;
            for chunk in [1, 7, 50, 2, 240] {
                let end = (at + chunk).min(items.len());
                state.apply(&items[at..end]);
                at = end;
                assert_eq!(**state.view(), reduce(&items[..at]), "seed {seed}");
            }
            // A late entry belongs before the newest 40: take them back, then
            // fold the corrected order.
            assert!(state.rewind(260));
            assert_eq!(**state.view(), reduce(&items[..260]));
            let mut corrected: Vec<FeedItem> = items[..260].to_vec();
            corrected.extend(items[260..].iter().rev().cloned());
            state.apply(&corrected[260..]);
            assert_eq!(**state.view(), reduce(&corrected), "seed {seed}");
            assert_eq!(state.len(), 300);
        }
    }

    #[test]
    fn rewinding_past_the_undo_window_is_refused() {
        let items = random_ops(7, UNDO_WINDOW + 10);
        let mut state = ChatState::default();
        state.apply(&items);
        let before = state.view().clone();
        assert!(!state.rewind(5), "beyond the window: rebuild instead");
        assert_eq!(state.view(), &before);
        assert!(state.rewind(10));
        assert_eq!(**state.view(), reduce(&items[..10]));
    }

    #[test]
    fn a_new_entry_costs_the_same_in_a_100k_message_chat() {
        let items: Vec<FeedItem> = (0..100_000u32)
            .map(|n| FeedItem {
                id: Hash32::digest("test/big", &n.to_le_bytes()),
                author: pk((n % 5) as u8),
                author_role: Role::Writer,
                ts_ms: n as u64,
                deps: vec![],
                body: ChatOp::Text { body: format!("message {n}"), reply_to: None, attachments: vec![] }.encode(),
            })
            .collect();
        let mut state = ChatState::default();
        state.apply(&items);
        let started = std::time::Instant::now();
        for n in 0..1_000u32 {
            let target = items[(n * 97) as usize].id;
            let op = match n % 3 {
                0 => ChatOp::Text { body: "new".into(), reply_to: Some(target), attachments: vec![] },
                1 => ChatOp::React { target, emoji: "ok".into(), on: true },
                _ => ChatOp::Receipt { up_to: target },
            };
            let item = FeedItem { id: Hash32::digest("test/new", &n.to_le_bytes()), author: pk(9), author_role: Role::Writer, ts_ms: 200_000 + n as u64, deps: vec![], body: op.encode() };
            state.apply(std::slice::from_ref(&item));
            assert!(state.view().index_of(&item.id).is_some() || n % 3 != 0);
        }
        assert!(state.rewind(state.len() - 500));
        // Re-reducing 100k messages per entry would take minutes here.
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "{:?}", started.elapsed());
        assert_eq!(state.view().messages.len(), 100_000 + 167);
    }

    #[test]
    fn garbage_and_oversized_entries_are_ignored() {
        let mut junk = text(1, 1, "x");
        junk.body = vec![0xff, 0xff, 0xff];
        let big = text(2, 1, &"a".repeat(MAX_BODY + 1));
        let v = reduce(&[junk, big, text(3, 1, "ok")]);
        assert_eq!(v.messages.len(), 1);
    }
}
