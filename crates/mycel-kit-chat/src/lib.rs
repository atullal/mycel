//! Chat kit (docs/ARCHITECTURE.md §L5): the messaging data model.
//!
//! A conversation is a Space with one Feed (`messages`). Every entry is a
//! postcard-encoded [`ChatOp`]. [`reduce`] folds the causally ordered feed into
//! a [`ChatView`] deterministically, so every peer shows the same thing. The
//! reducer enforces the chat rules that the trust layer can't express:
//! only a message's author may edit or delete it, and only admins may retitle.
//!
//! [`thread`] decides which conversations are one logical chat with a person
//! and how their histories merge; [`alerts`] decides when a chat deserves a
//! private local alert. Both are pure, so the runtime only caches their inputs.

pub mod alerts;
pub mod thread;

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
}

impl ChatView {
    pub fn index_of(&self, id: &Hash32) -> Option<usize> {
        self.messages.iter().position(|m| m.id == *id)
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
    let mut view = ChatView::default();
    let mut index: HashMap<Hash32, usize> = HashMap::new();
    for item in items {
        let Some(op) = ChatOp::decode(&item.body) else {
            continue; // unknown/garbage entries are ignored by everyone
        };
        match op {
            ChatOp::Text { body, reply_to, attachments } => {
                if body.len() > MAX_BODY {
                    continue;
                }
                index.insert(item.id, view.messages.len());
                let order_ms = view.messages.last().map_or(item.ts_ms, |m| m.order_ms.max(item.ts_ms));
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
            }
            ChatOp::Edit { target, body } => {
                if let Some(m) = index.get(&target).map(|i| &mut view.messages[*i])
                    && m.author == item.author
                    && !m.deleted
                    && body.len() <= MAX_BODY
                {
                    m.body = body;
                    m.edited = true;
                }
            }
            ChatOp::Delete { target } => {
                if let Some(m) = index.get(&target).map(|i| &mut view.messages[*i])
                    && m.author == item.author
                {
                    m.deleted = true;
                    m.body.clear();
                    m.attachments.clear();
                    m.reactions.clear();
                }
            }
            ChatOp::React { target, emoji, on } => {
                if emoji.is_empty() || emoji.len() > MAX_EMOJI {
                    continue;
                }
                if let Some(m) = index.get(&target).map(|i| &mut view.messages[*i])
                    && !m.deleted
                {
                    let who = m.reactions.entry(emoji.clone()).or_default();
                    if on {
                        who.insert(item.author);
                    } else {
                        who.remove(&item.author);
                        if who.is_empty() {
                            m.reactions.remove(&emoji);
                        }
                    }
                }
            }
            ChatOp::Receipt { up_to } => {
                if let Some(&i) = index.get(&up_to) {
                    let cur = view.read_upto.entry(item.author).or_insert(i);
                    *cur = (*cur).max(i);
                }
            }
            ChatOp::Profile { name } => {
                let name = clamp(name.trim(), MAX_NAME);
                if !name.is_empty() {
                    view.names.insert(item.author, name);
                }
            }
            ChatOp::Meta { title, direct } => {
                if item.author_role == Role::Admin {
                    view.title = title.map(|t| clamp(t.trim(), 128)).filter(|t| !t.is_empty());
                    view.direct = direct;
                    view.ever_group |= !direct || view.title.is_some();
                }
            }
        }
        // Writing a message implies having read everything before it.
        if let Some(&i) = index.get(&item.id) {
            let cur = view.read_upto.entry(item.author).or_insert(i);
            *cur = (*cur).max(i);
        }
    }
    view
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

    #[test]
    fn garbage_and_oversized_entries_are_ignored() {
        let mut junk = text(1, 1, "x");
        junk.body = vec![0xff, 0xff, 0xff];
        let big = text(2, 1, &"a".repeat(MAX_BODY + 1));
        let v = reduce(&[junk, big, text(3, 1, "ok")]);
        assert_eq!(v.messages.len(), 1);
    }
}
