//! The Mycel runtime: one device's identity, storage, network node and the
//! app-facing API (docs/RUNTIME_API.md). The Tauri host and the CLI both wrap it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64URL_NOPAD;
use mycel_crypto::{DeviceKeys, Hash32, MemberKeys, SignPk, SymKey, random};
use mycel_kit_chat::{AttachmentRef, ChatOp, ChatSignal, ChatView, messages_feed, reduce};
use mycel_net::{ContactCard, NetEvent, NetMode, Node, NodeOptions};
use mycel_sync::Replica;
use mycel_trust::{Role, SpaceId};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::*;
use crate::store::DbStore;

const ATTACHMENT_AAD: &[u8] = b"mycel/v0/attachment";

/// L4: the chat rules, compiled Rust → WASM (rules/chat-rules), run by every
/// peer on every decrypted chat entry. Pinned by hash.
const CHAT_RULES_WASM: &[u8] = include_bytes!("../../mycel-rules/fixtures/chat_rules.wasm");

struct WasmRules(mycel_rules::RulesEngine);

impl mycel_sync::FeedValidator for WasmRules {
    fn validate(&self, stream: &mycel_sync::StreamId, author: &SignPk, role: Role, body: &[u8]) -> bool {
        use mycel_rules::{RoleTag, RuleInput, StreamKind, StreamTag, Verdict};
        // Only the chat feed is governed by the chat rules.
        if *stream != messages_feed() {
            return true;
        }
        let input = RuleInput {
            author: author.0,
            author_role: match role {
                Role::Relay => RoleTag::Relay,
                Role::Reader => RoleTag::Reader,
                Role::Writer => RoleTag::Writer,
                Role::Admin => RoleTag::Admin,
            },
            stream: StreamTag { kind: StreamKind::Feed, id: stream.id },
            payload: body.to_vec(),
            context: vec![],
        };
        self.0.validate(&input) == Verdict::Accept
    }
}

pub fn chat_rules_hash() -> String {
    mycel_rules::RulesHash::of(CHAT_RULES_WASM).to_string()
}
const CONTACT_PREFIX: &str = "mycel:";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredContact {
    keys: MemberKeys,
    /// Empty = learn it from the person's Profile messages.
    name: String,
}

pub struct RuntimeOptions {
    pub data_dir: PathBuf,
    pub mode: NetworkMode,
    pub name: Option<String>,
    /// Keeper: accept every space we're added to, never post, just relay.
    pub keeper: bool,
    pub port: u16,
}

pub struct Runtime {
    data_dir: PathBuf,
    keys: Arc<DeviceKeys>,
    node: Node,
    store: Arc<DbStore>,
    events: broadcast::Sender<Event>,
    name: Mutex<String>,
    contacts: Mutex<BTreeMap<SignPk, StoredContact>>,
    mode: NetworkMode,
    keeper: bool,
}

// ───────────────────────────── helpers ─────────────────────────────

pub fn hex_id(pk: &SignPk) -> String {
    hex::encode(pk.0)
}

fn parse32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s.trim()).context("invalid id")?;
    v.try_into().map_err(|_| anyhow!("invalid id length"))
}

fn parse_pk(s: &str) -> Result<SignPk> {
    Ok(SignPk(parse32(s)?))
}

fn parse_space(s: &str) -> Result<SpaceId> {
    Ok(Hash32(parse32(s)?))
}

fn parse_hash(s: &str) -> Result<Hash32> {
    Ok(Hash32(parse32(s)?))
}

pub fn encode_contact_code(card: &ContactCard) -> String {
    format!("{CONTACT_PREFIX}{}", BASE64URL_NOPAD.encode(&postcard::to_allocvec(card).unwrap()))
}

pub fn decode_contact_code(code: &str) -> Result<ContactCard> {
    let code: String = code.split_whitespace().collect();
    let body = code.strip_prefix(CONTACT_PREFIX).unwrap_or(&code);
    let bytes = BASE64URL_NOPAD.decode(body.as_bytes()).context("not a Mycel contact code")?;
    let card: ContactCard = postcard::from_bytes(&bytes).context("not a Mycel contact code")?;
    card.verify().context("contact code signature is invalid")?;
    Ok(card)
}

fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("file");
    let clean: String = base
        .chars()
        .map(|c| if c.is_control() || c == ':' { '_' } else { c })
        .collect();
    if clean.is_empty() || clean == "." || clean == ".." {
        "file".into()
    } else {
        clean
    }
}

fn role_of(r: Role) -> MemberRole {
    match r {
        Role::Admin => MemberRole::Admin,
        Role::Writer => MemberRole::Member,
        Role::Reader => MemberRole::ReadOnly,
        Role::Relay => MemberRole::Keeper,
    }
}

fn net_mode(m: NetworkMode) -> NetMode {
    match m {
        NetworkMode::Local => NetMode::Local,
        NetworkMode::Lan => NetMode::Lan,
        NetworkMode::Internet => NetMode::Internet,
    }
}

fn load_or_create_identity(dir: &Path) -> Result<DeviceKeys> {
    let path = dir.join("identity.key");
    if let Ok(bytes) = std::fs::read(&path) {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("identity.key is corrupt"))?;
        return Ok(DeviceKeys::from_seed(seed));
    }
    let keys = DeviceKeys::generate();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, keys.seed())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(keys)
}

// ───────────────────────────── runtime ─────────────────────────────

impl Runtime {
    pub async fn open(
        data_dir: impl AsRef<Path>,
        mode: NetworkMode,
        name: Option<String>,
    ) -> Result<Arc<Runtime>> {
        Self::open_with(RuntimeOptions {
            data_dir: data_dir.as_ref().to_path_buf(),
            mode,
            name,
            keeper: false,
            port: 0,
        })
        .await
    }

    pub async fn open_with(opts: RuntimeOptions) -> Result<Arc<Runtime>> {
        let dir = opts.data_dir;
        std::fs::create_dir_all(&dir)?;
        let keys = Arc::new(load_or_create_identity(&dir)?);
        let store = DbStore::open(dir.join("mycel.redb"))?;

        let stored_name = store.kv_get("name")?.and_then(|b| String::from_utf8(b).ok());
        let name = match (opts.name, stored_name) {
            (Some(n), _) => {
                store.kv_put("name", n.clone().into_bytes());
                n
            }
            (None, Some(n)) => n,
            (None, None) => {
                if opts.keeper { "Keeper".to_string() } else { "Anonymous".to_string() }
            }
        };
        let contacts: BTreeMap<SignPk, StoredContact> = store
            .kv_get("contacts")?
            .and_then(|b| postcard::from_bytes::<Vec<StoredContact>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.keys.sign_pk, c))
            .collect();

        let mut nopts = NodeOptions::new(net_mode(opts.mode), name.clone());
        nopts.store = Some(store.clone());
        nopts.blob_dir = Some(dir.join("blobs"));
        nopts.port = opts.port;
        // v0 policy: accept any conversation we're added to (the inviter needed
        // our contact card to add us). Blocking lists can come later.
        nopts.invite_policy = Arc::new(|_, _| true);
        let engine = mycel_rules::RulesEngine::load(CHAT_RULES_WASM)
            .map_err(|e| anyhow!("chat rules failed to load: {e:?}"))?;
        nopts.feed_validator = Some(Arc::new(WasmRules(engine)));
        let node = Node::spawn(keys.clone(), nopts).await?;

        for (space, (ops, envs)) in store.load_spaces()? {
            let Some(genesis) = ops.iter().find(|o| o.id() == space).cloned() else {
                continue;
            };
            let rest: Vec<_> = ops.into_iter().filter(|o| o.id() != space).collect();
            match Replica::restore(keys.clone(), genesis, rest, envs, Some(store.clone())) {
                Ok(r) => {
                    node.insert_replica(r);
                }
                Err(e) => eprintln!("mycel: could not restore space {space}: {e}"),
            }
        }

        let (events, _) = broadcast::channel(1024);
        let rt = Arc::new(Runtime {
            data_dir: dir,
            keys,
            node,
            store,
            events,
            name: Mutex::new(name),
            contacts: Mutex::new(contacts),
            mode: opts.mode,
            keeper: opts.keeper,
        });
        tokio::spawn(bridge(Arc::downgrade(&rt), rt.node.subscribe()));
        // catch up with everyone right away
        for s in rt.node.space_ids() {
            rt.node.changed(s);
        }
        Ok(rt)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn is_keeper(&self) -> bool {
        self.keeper
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.node.shutdown().await?;
        self.store.close()?;
        Ok(())
    }

    // ───────────── identity & contacts ─────────────

    pub fn profile(&self) -> Profile {
        Profile {
            id: hex_id(&self.keys.sign_pk()),
            name: self.name.lock().unwrap().clone(),
            contact_code: encode_contact_code(&self.node.card()),
        }
    }

    pub fn set_name(&self, name: String) -> Result<Profile> {
        let name = name.trim().chars().take(64).collect::<String>();
        if name.is_empty() {
            bail!("name can't be empty");
        }
        *self.name.lock().unwrap() = name.clone();
        self.store.kv_put("name", name.clone().into_bytes());
        self.node.set_name(&name);
        // tell every conversation
        for space in self.node.space_ids() {
            if self.my_role(&space).is_some_and(Role::can_write) {
                let _ = self.post(space, ChatOp::Profile { name: name.clone() });
            }
        }
        Ok(self.profile())
    }

    fn save_contacts(&self) {
        let list: Vec<StoredContact> = self.contacts.lock().unwrap().values().cloned().collect();
        self.store.kv_put("contacts", postcard::to_allocvec(&list).unwrap());
    }

    fn remember(&self, keys: MemberKeys, name: String) -> Result<Contact> {
        if keys.sign_pk == self.keys.sign_pk() {
            bail!("that's your own contact code");
        }
        keys.verify_binding()?;
        self.contacts
            .lock()
            .unwrap()
            .insert(keys.sign_pk, StoredContact { keys, name });
        self.save_contacts();
        self.emit(Event::ContactsChanged);
        self.contact(&keys.sign_pk).context("contact vanished")
    }

    pub fn add_contact(&self, code: String) -> Result<Contact> {
        let card = decode_contact_code(&code)?;
        self.remember(card.keys, card.name)
    }

    pub async fn add_nearby_contact(&self, id: PeerId) -> Result<Contact> {
        let pk = parse_pk(&id)?;
        let card = self.node.fetch_card(pk).await?;
        self.remember(card.keys, card.name)
    }

    pub fn remove_contact(&self, id: PeerId) -> Result<()> {
        let pk = parse_pk(&id)?;
        self.contacts.lock().unwrap().remove(&pk);
        self.save_contacts();
        self.emit(Event::ContactsChanged);
        Ok(())
    }

    fn contact(&self, pk: &SignPk) -> Option<Contact> {
        // Don't hold the contacts lock across name_of (it locks contacts too).
        let known = self.contacts.lock().unwrap().contains_key(pk);
        if !known {
            return None;
        }
        let peers = self.node.peers();
        Some(Contact {
            id: hex_id(pk),
            name: self.name_of(pk),
            nearby: peers.get(pk).is_some_and(|p| p.nearby),
            online: peers.get(pk).is_some_and(|p| p.online()),
        })
    }

    pub fn contacts(&self) -> Vec<Contact> {
        let pks: Vec<SignPk> = self.contacts.lock().unwrap().keys().copied().collect();
        let mut out: Vec<Contact> = pks.iter().filter_map(|pk| self.contact(pk)).collect();
        out.sort_by_key(|c| c.name.to_lowercase());
        out
    }

    pub fn nearby(&self) -> Vec<NearbyPeer> {
        let contacts = self.contacts.lock().unwrap().clone();
        let mut out: Vec<NearbyPeer> = self
            .node
            .peers()
            .into_iter()
            .filter(|(_, p)| p.nearby)
            .map(|(pk, p)| NearbyPeer {
                id: hex_id(&pk),
                name: p.name.clone().unwrap_or_else(|| pk.short()),
                is_contact: contacts.contains_key(&pk),
            })
            .collect();
        out.sort_by_key(|p| p.name.to_lowercase());
        out
    }

    pub fn network_status(&self) -> NetworkStatus {
        let peers = self.node.peers();
        NetworkStatus {
            mode: self.mode,
            online_peers: peers
                .iter()
                .filter(|(_, p)| p.online())
                .map(|(pk, _)| hex_id(pk))
                .collect(),
            nearby_peers: peers.values().filter(|p| p.nearby).count() as u32,
            addresses: self.node.local_addresses(),
        }
    }

    /// Best display name: contact name, else the name they announced in any
    /// conversation, else the LAN name, else a short id.
    fn name_of(&self, pk: &SignPk) -> String {
        if *pk == self.keys.sign_pk() {
            return self.name.lock().unwrap().clone();
        }
        let contact_name = self.contacts.lock().unwrap().get(pk).map(|c| c.name.clone());
        if let Some(n) = contact_name.filter(|n| !n.is_empty()) {
            return n;
        }
        for space in self.node.space_ids() {
            if let Ok(view) = self.view(&space)
                && let Some(n) = view.names.get(pk)
            {
                return n.clone();
            }
        }
        if let Some(n) = self.node.peers().get(pk).and_then(|p| p.name.clone()) {
            return n;
        }
        pk.short()
    }

    // ───────────── messaging ─────────────

    fn my_role(&self, space: &SpaceId) -> Option<Role> {
        self.node.with_space(space, |r| r.my_role()).ok().flatten()
    }

    fn view(&self, space: &SpaceId) -> Result<ChatView> {
        let items = self.node.with_space(space, |r| r.feed(&messages_feed()))?;
        Ok(reduce(&items))
    }

    fn post(&self, space: SpaceId, op: ChatOp) -> Result<Hash32> {
        let (_, env) = self
            .node
            .with_space(&space, |r| r.append(messages_feed(), op.encode()))??;
        self.node.changed(space);
        Ok(env.id())
    }

    fn require_member(&self, space: &SpaceId) -> Result<Role> {
        match self.my_role(space) {
            Some(r) if r.can_write() => Ok(r),
            Some(_) => bail!("you can't post in this conversation"),
            None => bail!("you're no longer a member of this conversation"),
        }
    }

    fn require_admin(&self, space: &SpaceId) -> Result<()> {
        match self.my_role(space) {
            Some(Role::Admin) => Ok(()),
            _ => bail!("only admins can do that"),
        }
    }

    fn contact_keys(&self, id: &str) -> Result<MemberKeys> {
        let pk = parse_pk(id)?;
        self.contacts
            .lock()
            .unwrap()
            .get(&pk)
            .map(|c| c.keys)
            .ok_or_else(|| anyhow!("{} is not in your contacts", pk.short()))
    }

    fn summary(&self, space: &SpaceId) -> Result<ConversationSummary> {
        let me = self.keys.sign_pk();
        let view = self.view(space)?;
        let (members, my_role) = self.node.with_space(space, |r| (r.members(), r.my_role()))?;
        let mut members: Vec<Member> = members
            .into_iter()
            .map(|(k, role)| Member {
                id: hex_id(&k.sign_pk),
                name: if role == Role::Relay {
                    format!("{} (keeper)", self.name_of(&k.sign_pk))
                } else {
                    self.name_of(&k.sign_pk)
                },
                role: role_of(role),
                is_me: k.sign_pk == me,
            })
            .collect();
        members.sort_by_key(|m| (!m.is_me, m.name.to_lowercase()));
        let people: Vec<&Member> = members
            .iter()
            .filter(|m| !m.is_me && m.role != MemberRole::Keeper)
            .collect();
        let title = match &view.title {
            Some(t) => t.clone(),
            None if people.is_empty() => "Just you".to_string(),
            None => people.iter().map(|m| m.name.clone()).collect::<Vec<_>>().join(", "),
        };
        let last = view
            .messages
            .iter()
            .rev()
            .find(|m| !m.deleted)
            .map(|m| self.message_view(space, &view, m, &HashSet::new()));
        Ok(ConversationSummary {
            id: space.to_string(),
            title,
            direct: view.direct || (view.title.is_none() && people.len() == 1),
            members,
            last_message: last,
            unread: view.unread_for(&me),
            active: my_role.is_some(),
            my_role: my_role.map(role_of),
        })
    }

    fn message_view(
        &self,
        space: &SpaceId,
        view: &ChatView,
        m: &mycel_kit_chat::Message,
        _hint: &HashSet<SignPk>,
    ) -> MessageView {
        let me = self.keys.sign_pk();
        let is_mine = m.author == me;
        let delivery = if is_mine {
            self.delivery(space, view, m)
        } else {
            Delivery::Delivered
        };
        MessageView {
            id: m.id.to_string(),
            conversation: space.to_string(),
            author: hex_id(&m.author),
            author_name: self.name_of(&m.author),
            sent_at: m.ts_ms,
            body: m.body.clone(),
            reply_to: m.reply_to.map(|r| r.to_string()),
            edited: m.edited,
            deleted: m.deleted,
            attachments: m
                .attachments
                .iter()
                .map(|a| Attachment {
                    blob: a.blob.to_string(),
                    name: a.name.clone(),
                    mime: a.mime.clone(),
                    size: a.size,
                    local_path: self
                        .file_path(a)
                        .filter(|p| p.exists())
                        .map(|p| p.to_string_lossy().into_owned()),
                })
                .collect(),
            reactions: m
                .reactions
                .iter()
                .map(|(emoji, by)| Reaction {
                    emoji: emoji.clone(),
                    by: by.iter().map(hex_id).collect(),
                })
                .collect(),
            is_mine,
            delivery,
        }
    }

    fn delivery(&self, space: &SpaceId, view: &ChatView, m: &mycel_kit_chat::Message) -> Delivery {
        let me = self.keys.sign_pk();
        let Ok((members, holders)) = self.node.with_space(space, |r| (r.members(), r.holders(&m.id)))
        else {
            return Delivery::Local;
        };
        let others: Vec<SignPk> = members
            .iter()
            .filter(|(k, role)| k.sign_pk != me && *role != Role::Relay)
            .map(|(k, _)| k.sign_pk)
            .collect();
        let idx = view.index_of(&m.id).unwrap_or(usize::MAX);
        if !others.is_empty() && others.iter().all(|o| view.has_read(o, idx)) {
            Delivery::Read
        } else if !others.is_empty()
            && others.iter().all(|o| holders.contains(o) || view.has_read(o, idx))
        {
            Delivery::Delivered
        } else if !holders.is_empty() {
            Delivery::Sent
        } else {
            Delivery::Local
        }
    }

    pub fn conversations(&self) -> Vec<ConversationSummary> {
        let mut out: Vec<ConversationSummary> = self
            .node
            .space_ids()
            .iter()
            .filter(|s| self.my_role(s) != Some(Role::Relay))
            .filter_map(|s| self.summary(s).ok())
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.last_message.as_ref().map_or(0, |m| m.sent_at)));
        out
    }

    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary> {
        self.summary(&parse_space(&id)?)
    }

    pub fn create_conversation(
        &self,
        title: Option<String>,
        members: Vec<PeerId>,
    ) -> Result<ConversationSummary> {
        let keys: Vec<MemberKeys> = members
            .iter()
            .map(|m| self.contact_keys(m))
            .collect::<Result<_>>()?;
        let title = title.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        let direct = title.is_none() && keys.len() == 1;
        let (space, _) = self.node.create_space()?;
        let name = self.name.lock().unwrap().clone();
        self.node.with_space(&space, |r| -> Result<()> {
            for k in &keys {
                r.add_member(*k, Role::Writer)?;
            }
            r.append(messages_feed(), ChatOp::Meta { title: title.clone(), direct }.encode())?;
            r.append(messages_feed(), ChatOp::Profile { name }.encode())?;
            Ok(())
        })??;
        self.node.changed(space);
        self.emit(Event::ConversationAdded { conversation: space.to_string() });
        self.summary(&space)
    }

    pub fn messages(
        &self,
        id: ConversationId,
        limit: Option<u32>,
        before: Option<MessageId>,
    ) -> Result<Vec<MessageView>> {
        let space = parse_space(&id)?;
        let view = self.view(&space)?;
        let end = match before {
            Some(b) => view.index_of(&parse_hash(&b)?).unwrap_or(view.messages.len()),
            None => view.messages.len(),
        };
        let start = end.saturating_sub(limit.unwrap_or(200) as usize);
        Ok(view.messages[start..end]
            .iter()
            .map(|m| self.message_view(&space, &view, m, &HashSet::new()))
            .collect())
    }

    pub async fn send_message(
        &self,
        id: ConversationId,
        body: String,
        reply_to: Option<MessageId>,
        attachments: Vec<String>,
    ) -> Result<MessageView> {
        let space = parse_space(&id)?;
        self.require_member(&space)?;
        if body.trim().is_empty() && attachments.is_empty() {
            bail!("message is empty");
        }
        let reply_to = reply_to.map(|r| parse_hash(&r)).transpose()?;
        let mut refs = Vec::new();
        for path in attachments {
            refs.push(self.upload(space, Path::new(&path)).await?);
        }
        let msg_id = self.post(space, ChatOp::Text { body, reply_to, attachments: refs })?;
        let view = self.view(&space)?;
        let m = view
            .messages
            .iter()
            .find(|m| m.id == msg_id)
            .context("message was rejected")?;
        Ok(self.message_view(&space, &view, m, &HashSet::new()))
    }

    async fn upload(&self, space: SpaceId, path: &Path) -> Result<AttachmentRef> {
        let plain = tokio::fs::read(path)
            .await
            .with_context(|| format!("can't read {}", path.display()))?;
        let name = sanitize_file_name(&path.file_name().unwrap_or_default().to_string_lossy());
        let key = SymKey::generate();
        let nonce: [u8; 24] = random();
        let ct = key.seal(&nonce, ATTACHMENT_AAD, &plain)?;
        let blob = self.node.put_blob(space, ct).await?;
        let r = AttachmentRef {
            blob,
            key: key.0,
            nonce,
            mime: guess_mime(&name).into(),
            name,
            size: plain.len() as u64,
        };
        // keep a decrypted copy for ourselves
        if let Some(p) = self.file_path(&r) {
            if let Some(d) = p.parent() {
                tokio::fs::create_dir_all(d).await?;
            }
            tokio::fs::write(&p, &plain).await?;
        }
        Ok(r)
    }

    fn file_path(&self, a: &AttachmentRef) -> Option<PathBuf> {
        Some(self.data_dir.join("files").join(a.blob.to_string()).join(&a.name))
    }

    pub async fn fetch_attachment(&self, blob: String) -> Result<String> {
        let hash = parse_hash(&blob)?;
        // find the attachment (and its key) in our conversations
        let mut found = None;
        for space in self.node.space_ids() {
            if let Ok(view) = self.view(&space)
                && let Some(a) = view
                    .messages
                    .iter()
                    .flat_map(|m| &m.attachments)
                    .find(|a| a.blob == hash)
            {
                found = Some((space, a.clone()));
                break;
            }
        }
        let (space, a) = found.context("unknown attachment")?;
        let out = self.file_path(&a).context("no file path")?;
        if out.exists() {
            return Ok(out.to_string_lossy().into_owned());
        }
        let blob_path = self.node.fetch_blob(space, hash).await?;
        let ct = tokio::fs::read(&blob_path).await?;
        let plain = SymKey(a.key)
            .open(&a.nonce, ATTACHMENT_AAD, &ct)
            .context("attachment failed to decrypt")?;
        if let Some(d) = out.parent() {
            tokio::fs::create_dir_all(d).await?;
        }
        tokio::fs::write(&out, plain).await?;
        self.emit(Event::BlobReady { blob });
        self.emit(Event::ConversationUpdated { conversation: space.to_string() });
        Ok(out.to_string_lossy().into_owned())
    }

    fn own_message(&self, space: &SpaceId, msg: &str) -> Result<Hash32> {
        let id = parse_hash(msg)?;
        let view = self.view(space)?;
        let m = view.messages.iter().find(|m| m.id == id).context("unknown message")?;
        if m.author != self.keys.sign_pk() {
            bail!("you can only change your own messages");
        }
        Ok(id)
    }

    pub fn edit_message(&self, id: ConversationId, message: MessageId, body: String) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_member(&space)?;
        let target = self.own_message(&space, &message)?;
        self.post(space, ChatOp::Edit { target, body })?;
        Ok(())
    }

    pub fn delete_message(&self, id: ConversationId, message: MessageId) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_member(&space)?;
        let target = self.own_message(&space, &message)?;
        self.post(space, ChatOp::Delete { target })?;
        Ok(())
    }

    pub fn toggle_reaction(&self, id: ConversationId, message: MessageId, emoji: String) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_member(&space)?;
        let target = parse_hash(&message)?;
        let view = self.view(&space)?;
        let m = view.messages.iter().find(|m| m.id == target).context("unknown message")?;
        let on = !m
            .reactions
            .get(&emoji)
            .is_some_and(|by| by.contains(&self.keys.sign_pk()));
        self.post(space, ChatOp::React { target, emoji, on })?;
        Ok(())
    }

    pub fn mark_read(&self, id: ConversationId) -> Result<()> {
        let space = parse_space(&id)?;
        let me = self.keys.sign_pk();
        let view = self.view(&space)?;
        let Some((idx, last)) = view
            .messages
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| m.author != me)
        else {
            return Ok(());
        };
        if view.has_read(&me, idx) || !self.my_role(&space).is_some_and(Role::can_write) {
            return Ok(());
        }
        self.post(space, ChatOp::Receipt { up_to: last.id })?;
        Ok(())
    }

    pub fn set_typing(&self, id: ConversationId) -> Result<()> {
        let space = parse_space(&id)?;
        self.node.send_ephemeral(space, ChatSignal::Typing.encode())
    }

    pub fn add_members(&self, id: ConversationId, members: Vec<PeerId>) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_admin(&space)?;
        let keys: Vec<MemberKeys> = members
            .iter()
            .map(|m| self.contact_keys(m))
            .collect::<Result<_>>()?;
        self.node.with_space(&space, |r| -> Result<()> {
            for k in keys {
                if !r.is_member(&k.sign_pk) {
                    r.add_member(k, Role::Writer)?;
                }
            }
            Ok(())
        })??;
        self.node.changed(space);
        Ok(())
    }

    pub fn add_keeper(&self, id: ConversationId, keeper: PeerId) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_admin(&space)?;
        let k = self.contact_keys(&keeper)?;
        self.node.with_space(&space, |r| r.add_member(k, Role::Relay))??;
        self.node.changed(space);
        Ok(())
    }

    /// Remove someone (admins), or leave (anyone, when `member` is yourself).
    pub fn remove_member(&self, id: ConversationId, member: PeerId) -> Result<()> {
        let space = parse_space(&id)?;
        let pk = parse_pk(&member)?;
        if pk == self.keys.sign_pk() {
            return self.leave_conversation(id);
        }
        self.require_admin(&space)?;
        self.node.with_space(&space, |r| r.remove_member(pk))??;
        self.node.changed(space);
        Ok(())
    }

    pub fn leave_conversation(&self, id: ConversationId) -> Result<()> {
        let space = parse_space(&id)?;
        self.node.with_space(&space, |r| r.leave())?
            .map_err(|e| anyhow!("can't leave: {e} (the last admin must remove others or promote someone first)"))?;
        // tell everyone before we stop syncing this space
        let node_space = space;
        self.node.changed(node_space);
        Ok(())
    }

    pub fn rename_conversation(&self, id: ConversationId, title: String) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_admin(&space)?;
        let title = Some(title.trim().to_string()).filter(|t| !t.is_empty());
        self.post(space, ChatOp::Meta { title, direct: false })?;
        Ok(())
    }

    /// Sync every conversation with every member now (pull-to-refresh).
    pub async fn sync_now(&self) {
        for s in self.node.space_ids() {
            self.node.sync_all(s).await;
        }
    }
}

/// Translate network events into app events (and react to invites).
async fn bridge(rt: Weak<Runtime>, mut rx: broadcast::Receiver<NetEvent>) {
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let Some(rt) = rt.upgrade() else { return };
        match ev {
            NetEvent::SpaceChanged { space } => {
                rt.emit(Event::ConversationUpdated { conversation: space.to_string() });
            }
            NetEvent::SpaceAdded { space, from } => {
                if !rt.keeper {
                    // remember who added us, and introduce ourselves
                    let inviter = rt.node.with_space(&space, |r| {
                        r.members().into_iter().find(|(k, _)| k.sign_pk == from).map(|(k, _)| k)
                    });
                    let known = rt.contacts.lock().unwrap().contains_key(&from);
                    if let Ok(Some(keys)) = inviter
                        && !known
                    {
                        let _ = rt.remember(keys, String::new());
                    }
                    if rt.my_role(&space).is_some_and(Role::can_write) {
                        let name = rt.name.lock().unwrap().clone();
                        let _ = rt.post(space, ChatOp::Profile { name });
                    }
                }
                rt.emit(Event::ConversationAdded { conversation: space.to_string() });
            }
            NetEvent::Ephemeral { space, from, data } => {
                if let Some(ChatSignal::Typing) = ChatSignal::decode(&data) {
                    rt.emit(Event::Typing {
                        conversation: space.to_string(),
                        peer: hex_id(&from),
                    });
                }
            }
            NetEvent::PeersChanged => {
                rt.emit(Event::NearbyChanged);
                rt.emit(Event::NetworkChanged);
                rt.emit(Event::ContactsChanged);
            }
            NetEvent::BlobStored { .. } => {}
        }
    }
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<Runtime>();
    let _ = HashMap::<u8, u8>::new();
}
