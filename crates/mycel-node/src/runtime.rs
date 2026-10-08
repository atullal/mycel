//! The Mycel runtime: one device's identity, storage, network node and the
//! app-facing API (docs/RUNTIME_API.md). The Tauri host and the CLI both wrap it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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
/// Transfer progress events are throttled to one per this interval.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

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
    /// Reduced chat views, invalidated whenever a space changes.
    views: Mutex<HashMap<SpaceId, Arc<ChatView>>>,
    /// Names people announced (Profile ops), across all conversations.
    announced: Mutex<HashMap<SignPk, String>>,
    /// Conversations from non-contacts awaiting accept/decline: space → inviter.
    requests: Mutex<BTreeMap<SpaceId, SignPk>>,
    /// Declined conversations we keep locally but never show.
    hidden: Mutex<BTreeSet<SpaceId>>,
    /// Keys whose invites we refuse at the network layer.
    blocked: Arc<Mutex<BTreeSet<SignPk>>>,
    /// Direct-address hints from contact codes (for networks without mDNS).
    hints: Mutex<BTreeMap<SignPk, Vec<String>>>,
}

fn load_set<T: serde::de::DeserializeOwned + Ord>(store: &DbStore, key: &str) -> Result<BTreeSet<T>> {
    Ok(store
        .kv_get(key)?
        .and_then(|b| postcard::from_bytes::<Vec<T>>(&b).ok())
        .unwrap_or_default()
        .into_iter()
        .collect())
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

/// Contact code plus optional `@ip:port,ip:port` address hints (unsigned,
/// only used to find the device; its identity is still the signed card).
pub fn encode_contact_code_with_hints(card: &ContactCard, hints: &[String]) -> String {
    let base = encode_contact_code(card);
    if hints.is_empty() { base } else { format!("{base}@{}", hints.join(",")) }
}

pub fn decode_contact_code(code: &str) -> Result<ContactCard> {
    Ok(decode_contact_code_with_hints(code)?.0)
}

pub fn decode_contact_code_with_hints(code: &str) -> Result<(ContactCard, Vec<std::net::SocketAddr>)> {
    let code: String = code.split_whitespace().collect();
    let body = code.strip_prefix(CONTACT_PREFIX).unwrap_or(&code);
    let (card_part, hints) = body.split_once('@').unwrap_or((body, ""));
    let bytes = BASE64URL_NOPAD.decode(card_part.as_bytes()).context("not a Mycel contact code")?;
    let card: ContactCard = postcard::from_bytes(&bytes).context("not a Mycel contact code")?;
    card.verify().context("contact code signature is invalid")?;
    let hints = hints
        .split(',')
        .filter_map(|h| h.parse().ok())
        .take(8)
        .collect();
    Ok((card, hints))
}

/// A friendly default name: the computer's name.
fn default_device_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("scutil").args(["--get", "ComputerName"]).output()
        && out.status.success()
    {
        let n = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !n.is_empty() {
            return n.chars().take(64).collect();
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "Mycel user".into())
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

/// Make a peer-supplied file name safe to use as a single path component:
/// basename only, no separators/drive prefixes/control chars, no leading dots
/// (hidden files like `.zshenv`), bounded length. Security-critical: names
/// come from other people's messages.
pub fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut clean: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " .-_()[]+,@&'".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    while clean.starts_with('.') || clean.starts_with(' ') {
        clean.remove(0);
    }
    let clean: String = clean.trim_end_matches([' ', '.']).chars().take(120).collect();
    if clean.is_empty() { "file".into() } else { clean }
}

/// Mark a downloaded file as coming from the internet so macOS Gatekeeper
/// still checks it before anything executes it.
fn quarantine(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let value = format!("0081;{secs:x};Mycel;");
        let _ = xattr::set(path, "com.apple.quarantine", value.as_bytes());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
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
                if opts.keeper { "Keeper".to_string() } else { default_device_name() }
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
        // Invites from blocked keys are refused outright; invites from anyone
        // else are accepted, and non-contacts land as message requests.
        let blocked: Arc<Mutex<BTreeSet<SignPk>>> = Arc::new(Mutex::new(load_set(&store, "blocked")?));
        let blocked_for_policy = blocked.clone();
        nopts.invite_policy = Arc::new(move |from, _| !blocked_for_policy.lock().contains(from));
        let requests: BTreeMap<SpaceId, SignPk> = store
            .kv_get("requests")?
            .and_then(|b| postcard::from_bytes::<Vec<(SpaceId, SignPk)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let hidden: BTreeSet<SpaceId> = load_set(&store, "hidden")?;
        let hints: BTreeMap<SignPk, Vec<String>> = store
            .kv_get("hints")?
            .and_then(|b| postcard::from_bytes::<Vec<(SignPk, Vec<String>)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        nopts.accept_relay_invites = opts.keeper;
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
            views: Mutex::default(),
            announced: Mutex::default(),
            requests: Mutex::new(requests),
            hidden: Mutex::new(hidden),
            blocked,
            hints: Mutex::new(hints),
        });
        for (pk, addrs) in rt.hints.lock().iter() {
            let addrs: Vec<std::net::SocketAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
            rt.node.add_peer_hints(*pk, &addrs);
        }
        // warm caches (also learns everyone's announced names)
        for s in rt.node.space_ids() {
            let _ = rt.view(&s);
        }
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
            name: self.name.lock().clone(),
            contact_code: encode_contact_code_with_hints(&self.node.card(), &self.node.local_addresses()),
        }
    }

    pub fn set_name(&self, name: String) -> Result<Profile> {
        let name = name.trim().chars().take(64).collect::<String>();
        if name.is_empty() {
            bail!("name can't be empty");
        }
        *self.name.lock() = name.clone();
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
        let list: Vec<StoredContact> = self.contacts.lock().values().cloned().collect();
        self.store.kv_put("contacts", postcard::to_allocvec(&list).unwrap());
    }

    fn remember(&self, keys: MemberKeys, name: String) -> Result<Contact> {
        if keys.sign_pk == self.keys.sign_pk() {
            bail!("that's your own contact code");
        }
        keys.verify_binding()?;
        self.contacts
            .lock()
            .insert(keys.sign_pk, StoredContact { keys, name });
        self.save_contacts();
        self.emit(Event::ContactsChanged);
        self.contact(&keys.sign_pk).context("contact vanished")
    }

    pub fn add_contact(&self, code: String) -> Result<Contact> {
        let (card, hints) = decode_contact_code_with_hints(&code)?;
        if !hints.is_empty() {
            self.node.add_peer_hints(card.keys.sign_pk, &hints);
            let mut all = self.hints.lock();
            all.insert(card.keys.sign_pk, hints.iter().map(|h| h.to_string()).collect());
            let list: Vec<(SignPk, Vec<String>)> = all.iter().map(|(k, v)| (*k, v.clone())).collect();
            self.store.kv_put("hints", postcard::to_allocvec(&list).unwrap());
        }
        self.remember(card.keys, card.name)
    }

    pub async fn add_nearby_contact(&self, id: PeerId) -> Result<Contact> {
        let pk = parse_pk(&id)?;
        let card = self.node.fetch_card(pk).await?;
        self.remember(card.keys, card.name)
    }

    pub fn remove_contact(&self, id: PeerId) -> Result<()> {
        let pk = parse_pk(&id)?;
        self.contacts.lock().remove(&pk);
        self.save_contacts();
        self.emit(Event::ContactsChanged);
        Ok(())
    }

    fn contact(&self, pk: &SignPk) -> Option<Contact> {
        // Don't hold the contacts lock across name_of (it locks contacts too).
        let known = self.contacts.lock().contains_key(pk);
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
        let pks: Vec<SignPk> = self.contacts.lock().keys().copied().collect();
        let mut out: Vec<Contact> = pks.iter().filter_map(|pk| self.contact(pk)).collect();
        out.sort_by_key(|c| c.name.to_lowercase());
        out
    }

    pub fn nearby(&self) -> Vec<NearbyPeer> {
        let contacts = self.contacts.lock().clone();
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
            return self.name.lock().clone();
        }
        let contact_name = self.contacts.lock().get(pk).map(|c| c.name.clone());
        if let Some(n) = contact_name.filter(|n| !n.is_empty()) {
            return n;
        }
        let announced = self.announced.lock().get(pk).cloned();
        if let Some(n) = announced {
            return n;
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

    fn view(&self, space: &SpaceId) -> Result<Arc<ChatView>> {
        if let Some(v) = self.views.lock().get(space) {
            return Ok(v.clone());
        }
        let items = self.node.with_space(space, |r| r.feed(&messages_feed()))?;
        let view = Arc::new(reduce(&items));
        self.announced
            .lock()
            .extend(view.names.iter().map(|(k, v)| (*k, v.clone())));
        self.views.lock().insert(*space, view.clone());
        Ok(view)
    }

    fn invalidate(&self, space: &SpaceId) {
        self.views.lock().remove(space);
    }

    /// A local change: drop the cached view now, then sync + notify.
    fn touch(&self, space: SpaceId) {
        self.invalidate(&space);
        self.node.changed(space);
    }

    fn post(&self, space: SpaceId, op: ChatOp) -> Result<Hash32> {
        let (_, env) = self
            .node
            .with_space(&space, |r| r.append(messages_feed(), op.encode()))??;
        self.touch(space);
        Ok(env.id())
    }

    fn require_member(&self, space: &SpaceId) -> Result<Role> {
        if self.requests.lock().contains_key(space) {
            bail!("accept this message request before replying");
        }
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
        // (take the lock once: two guards in one expression would deadlock)
        let inviter = self.requests.lock().get(space).copied();
        Ok(ConversationSummary {
            id: space.to_string(),
            title,
            direct: view.direct || (view.title.is_none() && people.len() == 1),
            members,
            last_message: last,
            unread: view.unread_for(&me),
            active: my_role.is_some(),
            my_role: my_role.map(role_of),
            request: inviter.is_some(),
            invited_by: inviter.as_ref().map(hex_id),
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
                    name: sanitize_file_name(&a.name),
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
            .filter(|s| !self.hidden.lock().contains(*s))
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
        let name = self.name.lock().clone();
        self.node.with_space(&space, |r| -> Result<()> {
            for k in &keys {
                r.add_member(*k, Role::Writer)?;
            }
            r.append(messages_feed(), ChatOp::Meta { title: title.clone(), direct }.encode())?;
            r.append(messages_feed(), ChatOp::Profile { name }.encode())?;
            Ok(())
        })??;
        self.touch(space);
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
        for path in &attachments {
            refs.push(self.upload(space, path).await?);
        }
        let msg_id = self.post(space, ChatOp::Text { body, reply_to, attachments: refs })?;
        // Files the HTTP UI staged under uploads/ are now in files/; drop the staging copies.
        let uploads = self.data_dir.join("uploads").canonicalize().ok();
        for raw in &attachments {
            if let (Some(root), Ok(p)) = (&uploads, crate::files::local_path(raw).canonicalize())
                && let Some(dir) = p.parent().filter(|d| d.starts_with(root) && d != root)
            {
                let _ = tokio::fs::remove_dir_all(dir).await;
            }
        }
        let view = self.view(&space)?;
        let m = view
            .messages
            .iter()
            .find(|m| m.id == msg_id)
            .context("message was rejected")?;
        Ok(self.message_view(&space, &view, m, &HashSet::new()))
    }

    /// A throttled progress reporter emitting `TransferProgress` events.
    fn progress(&self, direction: TransferDirection, id: String) -> mycel_net::Progress {
        let events = self.events.clone();
        let last: Mutex<Option<Instant>> = Mutex::new(None);
        Arc::new(move |done, total| {
            let now = Instant::now();
            {
                let mut l = last.lock();
                if done < total && l.is_some_and(|t| now.duration_since(t) < PROGRESS_EVERY) {
                    return;
                }
                *l = Some(now);
            }
            let _ = events.send(Event::TransferProgress { direction, id: id.clone(), done, total });
        })
    }

    /// A fresh path under `uploads/` for a file the UI hands us as bytes
    /// (browser uploads, pasted images). Its folder is created.
    pub fn new_upload_path(&self, name: &str) -> Result<PathBuf> {
        let dir = self.data_dir.join("uploads").join(format!("{:016x}", mycel_crypto::random_u64()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(sanitize_file_name(name)))
    }

    /// Save bytes (e.g. a pasted image) as an attachable file; returns its path.
    pub async fn stage_upload(&self, name: &str, data: &[u8]) -> Result<String> {
        let path = self.new_upload_path(name)?;
        tokio::fs::write(&path, data).await?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// Encrypt one attachment into the blob store (streaming, any size) and
    /// keep a plaintext copy in `files/<blob>/`. Folders and macOS packages
    /// (`.app`, `.pages`, `.key`, `.rtfd`, …) are sent as a `.zip`.
    async fn upload(&self, space: SpaceId, raw: &str) -> Result<AttachmentRef> {
        let path = crate::files::local_path(raw);
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| crate::files::read_error(&path, e))?;
        if meta.is_dir() {
            let base = sanitize_file_name(&path.file_name().unwrap_or_default().to_string_lossy());
            let name = format!("{base}.zip");
            let dir = self.data_dir.join("uploads").join(format!(".zip-{:016x}", mycel_crypto::random_u64()));
            let out = dir.join(&name);
            let (src, dst) = (path.clone(), out.clone());
            let zipped = tokio::task::spawn_blocking(move || crate::files::zip_dir(&src, &dst))
                .await?
                .with_context(|| format!("couldn't zip the folder {}", path.display()));
            let res = match zipped {
                Ok(()) => self.encrypt_attachment(space, &out, name, raw).await,
                Err(e) => Err(e),
            };
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return res;
        }
        if !meta.is_file() {
            bail!("{} isn't a regular file", path.display());
        }
        let name = sanitize_file_name(&path.file_name().unwrap_or_default().to_string_lossy());
        self.encrypt_attachment(space, &path, name, raw).await
    }

    async fn encrypt_attachment(&self, space: SpaceId, src: &Path, name: String, id: &str) -> Result<AttachmentRef> {
        let size = tokio::fs::metadata(src)
            .await
            .map_err(|e| crate::files::read_error(src, e))?
            .len();
        // room for the sealed blob plus our plaintext copy
        mycel_net::ensure_free_space(&self.data_dir, mycel_crypto::sealed_len(size) + size)?;
        let staged = self.node.blob_staging_path().context("blob storage disabled")?;
        let files = self.data_dir.join("files");
        let incoming = files.join(format!(".incoming-{:016x}", mycel_crypto::random_u64()));
        let key = SymKey::generate();
        let nonce: [u8; 24] = random();
        let progress = self.progress(TransferDirection::Upload, id.to_string());
        let job = {
            let (src, copy, staged, key, progress) =
                (src.to_path_buf(), incoming.join(&name), staged.clone(), key.clone(), progress.clone());
            tokio::task::spawn_blocking(move || {
                crate::files::seal_file(&src, &copy, &staged, &key, &nonce, ATTACHMENT_AAD, |done| progress(done, size))
            })
        };
        let res = match job.await {
            Ok(Ok((blob, len))) => self.node.add_blob(space, &staged, blob).await.map(|()| (blob, len)),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e.into()),
        };
        let (blob, len) = match res {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_file(&staged).await;
                let _ = tokio::fs::remove_dir_all(&incoming).await;
                return Err(e);
            }
        };
        progress(len, len);
        // our decrypted copy: files/<blob>/<name>
        if tokio::fs::rename(&incoming, files.join(blob.to_string())).await.is_err() {
            let _ = tokio::fs::remove_dir_all(&incoming).await;
        }
        Ok(AttachmentRef { blob, key: key.0, nonce, mime: guess_mime(&name).into(), name, size: len })
    }

    /// Where an attachment's decrypted copy lives. Always inside `files/`.
    fn file_path(&self, a: &AttachmentRef) -> Option<PathBuf> {
        let root = self.data_dir.join("files");
        let path = root.join(a.blob.to_string()).join(sanitize_file_name(&a.name));
        path.starts_with(&root).then_some(path)
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
        let progress = self.progress(TransferDirection::Download, blob.clone());
        let blob_path = self.node.fetch_blob_with_progress(space, hash, progress.clone()).await?;
        let sealed = tokio::fs::metadata(&blob_path).await?.len();
        mycel_net::ensure_free_space(&self.data_dir, sealed)?;
        let dir = out.parent().context("no file path")?.to_path_buf();
        tokio::fs::create_dir_all(&dir).await?;
        // Decrypt next to the final name, then rename: a half-written file
        // never shows up as the attachment.
        let tmp = dir.join(format!(".{:016x}.part", mycel_crypto::random_u64()));
        let job = {
            let (blob_path, tmp, key, nonce) = (blob_path.clone(), tmp.clone(), SymKey(a.key), a.nonce);
            tokio::task::spawn_blocking(move || crate::files::open_file(&blob_path, &tmp, &key, &nonce, ATTACHMENT_AAD))
        };
        let res = match job.await {
            Ok(r) => r,
            Err(e) => Err(e.into()),
        };
        if let Err(e) = res {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        tokio::fs::rename(&tmp, &out).await?;
        quarantine(&out);
        progress(sealed, sealed);
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
        // No read receipts for message requests: the sender learns nothing
        // until we accept.
        if self.requests.lock().contains_key(&space) {
            return Ok(());
        }
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
        self.touch(space);
        Ok(())
    }

    pub fn add_keeper(&self, id: ConversationId, keeper: PeerId) -> Result<()> {
        let space = parse_space(&id)?;
        self.require_admin(&space)?;
        let k = self.contact_keys(&keeper)?;
        self.node.with_space(&space, |r| r.add_member(k, Role::Relay))??;
        self.touch(space);
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
        self.touch(space);
        Ok(())
    }

    pub fn leave_conversation(&self, id: ConversationId) -> Result<()> {
        let space = parse_space(&id)?;
        self.node.with_space(&space, |r| r.leave())?
            .map_err(|e| anyhow!("can't leave: {e} (the last admin must remove others or promote someone first)"))?;
        // tell everyone before we stop syncing this space
        let node_space = space;
        self.touch(node_space);
        Ok(())
    }

    fn save_requests(&self) {
        let list: Vec<(SpaceId, SignPk)> = self.requests.lock().iter().map(|(a, b)| (*a, *b)).collect();
        self.store.kv_put("requests", postcard::to_allocvec(&list).unwrap());
    }

    fn save_set<T: serde::Serialize + Copy>(&self, key: &str, set: &BTreeSet<T>) {
        let list: Vec<T> = set.iter().copied().collect();
        self.store.kv_put(key, postcard::to_allocvec(&list).unwrap());
    }

    /// Accept a message request: the inviter becomes a contact (with the name
    /// they announced) and we introduce ourselves.
    pub fn accept_request(&self, id: ConversationId) -> Result<ConversationSummary> {
        let space = parse_space(&id)?;
        let inviter = self.requests.lock().remove(&space).context("not a message request")?;
        self.save_requests();
        let keys = self.node.with_space(&space, |r| {
            r.members().into_iter().find(|(k, _)| k.sign_pk == inviter).map(|(k, _)| k)
        })?;
        if let Some(keys) = keys
            && !self.contacts.lock().contains_key(&inviter)
        {
            self.remember(keys, String::new())?;
        }
        if self.my_role(&space).is_some_and(Role::can_write) {
            let name = self.name.lock().clone();
            self.post(space, ChatOp::Profile { name })?;
        }
        self.emit(Event::ConversationUpdated { conversation: id.clone() });
        self.summary(&space)
    }

    /// Decline a message request (leave it), optionally blocking the inviter.
    pub fn decline_request(&self, id: ConversationId, block: bool) -> Result<()> {
        let space = parse_space(&id)?;
        let inviter = self.requests.lock().remove(&space).context("not a message request")?;
        self.save_requests();
        let _ = self.node.with_space(&space, |r| r.leave());
        self.touch(space);
        let hidden = {
            let mut h = self.hidden.lock();
            h.insert(space);
            h.clone()
        };
        self.save_set("hidden", &hidden);
        if block {
            let blocked = {
                let mut b = self.blocked.lock();
                b.insert(inviter);
                b.clone()
            };
            self.save_set("blocked", &blocked);
        }
        self.emit(Event::ConversationUpdated { conversation: id });
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
                rt.invalidate(&space);
                rt.emit(Event::ConversationUpdated { conversation: space.to_string() });
            }
            NetEvent::SpaceAdded { space, from } => {
                rt.invalidate(&space);
                if !rt.keeper {
                    let known = rt.contacts.lock().contains_key(&from);
                    if known {
                        // a contact added us: introduce ourselves right away
                        if rt.my_role(&space).is_some_and(Role::can_write) {
                            let name = rt.name.lock().clone();
                            let _ = rt.post(space, ChatOp::Profile { name });
                        }
                    } else {
                        // a stranger: message request; nothing is trusted or posted yet
                        rt.requests.lock().insert(space, from);
                        rt.save_requests();
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

#[cfg(test)]
mod tests {
    use super::sanitize_file_name as s;

    #[test]
    fn hostile_attachment_names_are_neutralized() {
        for evil in [
            "../../../../Library/LaunchAgents/x.plist",
            "/etc/passwd",
            "..\\..\\x.bat",
            "C:\\Windows\\x.exe",
            "..",
            ".",
            ".zshenv",
            "a/../../b",
            "\0x\n",
            "",
        ] {
            let n = s(evil);
            assert!(!n.contains('/') && !n.contains('\\') && !n.starts_with('.'), "{evil:?} -> {n:?}");
            assert!(!n.is_empty() && n != "..");
        }
        assert_eq!(s("Photo 1 (final).PNG"), "Photo 1 (final).PNG");
        assert_eq!(s("résumé.pdf"), "résumé.pdf");
        assert_eq!(s("../../x.plist"), "x.plist");
    }
}
