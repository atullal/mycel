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
use mycel_call::{ALPN_CALL, BoxFuture, CallEvent, CallHost, CallManager};
use mycel_net::{ContactCard, ExtraProtocol, NetEvent, NetMode, Node, NodeOptions, PathKind, PeerState};
use mycel_sync::Replica;
use mycel_trust::{Role, SpaceId};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::*;
use crate::store::DbStore;

const ATTACHMENT_AAD: &[u8] = b"mycel/v0/attachment";
/// Transfer progress events are throttled to one per this interval.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);
/// Transfer speed is averaged over this long.
const RATE_WINDOW: Duration = Duration::from_secs(3);

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

/// Bound unsolicited request metadata independently of blob consent. Accepted
/// conversations and their sync history are outside these admission limits.
const MAX_PENDING_REQUESTS: usize = 256;
const MAX_PENDING_PER_INVITER: usize = 32;

fn may_record_request(requests: &BTreeMap<SpaceId, SignPk>, from: &SignPk, space: &SpaceId) -> bool {
    requests.contains_key(space)
        || (requests.len() < MAX_PENDING_REQUESTS
            && requests.values().filter(|peer| *peer == from).count() < MAX_PENDING_PER_INVITER)
}

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
    /// The name a brand-new profile gets when `name` is `None` (instead of
    /// the computer's name). Ignored once the profile has a name.
    pub default_name: Option<String>,
    /// Keeper: accept every space we're added to, never post, just relay.
    pub keeper: bool,
    pub port: u16,
}

pub struct Runtime {
    data_dir: PathBuf,
    _profile_lock: crate::identity::ProfileLock,
    keys: Arc<DeviceKeys>,
    node: Node,
    store: Arc<DbStore>,
    events: broadcast::Sender<Event>,
    name: Mutex<String>,
    contacts: Mutex<BTreeMap<SignPk, StoredContact>>,
    mode: NetworkMode,
    /// The mode the next launch will use (`set_network_mode`).
    next_mode: Mutex<NetworkMode>,
    keeper: bool,
    /// Reduced chat views, invalidated whenever a space changes.
    views: Mutex<HashMap<SpaceId, Arc<ChatView>>>,
    /// Names people announced (Profile ops), across all conversations.
    announced: Mutex<HashMap<SignPk, String>>,
    /// Conversations from non-contacts awaiting accept/decline: space → inviter.
    requests: Arc<Mutex<BTreeMap<SpaceId, SignPk>>>,
    /// Just-accepted invites not yet classified (see `invite_policy`).
    arriving: Arc<Mutex<HashSet<SpaceId>>>,
    /// Declined conversations we keep locally but never show.
    hidden: Arc<Mutex<BTreeSet<SpaceId>>>,
    /// Per-device message visibility; never published to conversation peers.
    hidden_messages: Mutex<BTreeSet<(SpaceId, Hash32)>>,
    /// Keys whose invites we refuse at the network layer.
    blocked: Arc<Mutex<BTreeSet<SignPk>>>,
    /// Direct-address hints from contact codes (for networks without mDNS).
    hints: Mutex<BTreeMap<SignPk, Vec<String>>>,
    /// Live voice calls (not on keepers).
    calls: CallManager,
}

/// What calls need from the runtime: membership, names, dialing, events.
struct RuntimeCallHost {
    me: SignPk,
    rt: Weak<Runtime>,
}

impl CallHost for RuntimeCallHost {
    fn me(&self) -> SignPk {
        self.me
    }

    fn members(&self, space: &SpaceId) -> Result<Vec<SignPk>> {
        self.rt.upgrade().context("shutting down")?.call_members(space)
    }

    fn title(&self, space: &SpaceId) -> Option<String> {
        self.rt.upgrade()?.summary(space).ok().map(|s| s.title)
    }

    fn may_call(&self, space: &SpaceId, peer: &SignPk) -> bool {
        self.rt.upgrade().is_some_and(|rt| rt.may_call(space, peer))
    }

    fn name_of(&self, peer: &SignPk) -> String {
        self.rt.upgrade().map(|rt| rt.name_of(peer)).unwrap_or_else(|| peer.short())
    }

    fn connect(&self, peer: SignPk) -> BoxFuture<Result<mycel_net::iroh::endpoint::Connection>> {
        let rt = self.rt.clone();
        Box::pin(async move {
            let rt = rt.upgrade().context("shutting down")?;
            rt.node
                .connect(peer, ALPN_CALL)
                .await
                .map_err(|e| anyhow!("{} can't be reached right now ({e:#})", rt.name_of(&peer)))
        })
    }

    fn note_connection(&self, peer: &SignPk, conn: &mycel_net::iroh::endpoint::Connection) {
        if let Some(rt) = self.rt.upgrade() {
            rt.node.note_connection(*peer, conn);
        }
    }

    fn emit(&self, event: CallEvent) {
        if let Some(rt) = self.rt.upgrade() {
            rt.emit(match event {
                CallEvent::Incoming(call) => Event::CallIncoming { call },
                CallEvent::Updated(call) => Event::CallUpdated { call },
            });
        }
    }
}

fn load_set<T: serde::de::DeserializeOwned + Ord>(store: &DbStore, key: &str) -> Result<BTreeSet<T>> {
    Ok(store
        .kv_decode::<Vec<T>>(key)?
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
    #[cfg(target_os = "android")]
    if let Some(model) = android_property("ro.product.model") {
        return model.chars().take(64).collect();
    }
    // Windows sets COMPUTERNAME; Linux desktops rarely export HOSTNAME to apps.
    let env_name = |var: &str| std::env::var(var).ok().map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
    env_name("COMPUTERNAME")
        .or_else(|| env_name("HOSTNAME"))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty() && h != "localhost")
        })
        .map(|n| n.chars().take(64).collect())
        .unwrap_or_else(|| "Mycel user".into())
}

/// An Android system property such as `ro.product.model` ("Pixel 7").
#[cfg(target_os = "android")]
fn android_property(name: &str) -> Option<String> {
    let key = std::ffi::CString::new(name).ok()?;
    let mut value = [0 as std::ffi::c_char; 92]; // PROP_VALUE_MAX
    // SAFETY: the key is NUL-terminated and the buffer has PROP_VALUE_MAX bytes.
    let n = unsafe { libc::__system_property_get(key.as_ptr(), value.as_mut_ptr()) };
    if n <= 0 {
        return None;
    }
    // SAFETY: __system_property_get NUL-terminates what it wrote.
    let s = unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }.to_string_lossy().trim().to_string();
    (!s.is_empty()).then_some(s)
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
        "m4a" => "audio/mp4",
        "weba" => "audio/webm",
        "ogg" | "opus" => "audio/ogg",
        "webm" => "video/webm",
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
            default_name: None,
            keeper: false,
            port: 0,
        })
        .await
    }

    pub async fn open_with(opts: RuntimeOptions) -> Result<Arc<Runtime>> {
        let dir = opts.data_dir;
        let profile_lock = crate::identity::ProfileLock::acquire(&dir)?;
        let keys = Arc::new(crate::identity::load(&dir, &profile_lock)?);
        // Validate persisted mode before opening any network transport.
        let next_mode = Self::saved_network_mode(&dir)?.unwrap_or(opts.mode);
        let store = DbStore::open(dir.join("mycel.redb"))?;
        // Reject malformed persisted rows before spawning any transport task.
        let stored_spaces = store.load_spaces()?;

        let stored_name = store.kv_get("name")?.and_then(|b| String::from_utf8(b).ok());
        let name = match (opts.name, stored_name) {
            (Some(n), _) => {
                store.kv_put("name", n.clone().into_bytes());
                n
            }
            (None, Some(n)) => n,
            (None, None) => {
                if opts.keeper {
                    "Keeper".to_string()
                } else {
                    opts.default_name.unwrap_or_else(default_device_name)
                }
            }
        };
        let contacts: BTreeMap<SignPk, StoredContact> = store
            .kv_decode::<Vec<StoredContact>>("contacts")?
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.keys.sign_pk, c))
            .collect();

        let mut nopts = NodeOptions::new(net_mode(opts.mode), name.clone());
        nopts.store = Some(store.clone());
        nopts.blob_dir = Some(dir.join("blobs"));
        nopts.port = opts.port;
        if opts.mode != NetworkMode::Local {
            nopts.links = crate::links::device_links(keys.sign_pk(), &name);
            nopts.mesh = crate::links::mesh_options();
        }
        // MYCEL_IP=0: no Wi-Fi/Ethernet IP at all, links only (to test or
        // demonstrate peer-to-peer Wi-Fi and Bluetooth).
        if std::env::var("MYCEL_IP").is_ok_and(|v| v.trim() == "0") {
            nopts.ip = false;
        }
        // Load application consent before starting the network endpoint.
        let blocked: Arc<Mutex<BTreeSet<SignPk>>> = Arc::new(Mutex::new(load_set(&store, "blocked")?));
        let requests: Arc<Mutex<BTreeMap<SpaceId, SignPk>>> = Arc::new(Mutex::new(
            store.kv_decode::<Vec<(SpaceId, SignPk)>>("requests")?.unwrap_or_default().into_iter().collect(),
        ));
        let hidden: Arc<Mutex<BTreeSet<SpaceId>>> = Arc::new(Mutex::new(load_set(&store, "hidden")?));
        let hidden_messages = Mutex::new(load_set(&store, "hidden_messages")?);
        let arriving: Arc<Mutex<HashSet<SpaceId>>> = Arc::default();
        let (blocked_for_policy, hidden_for_policy) = (blocked.clone(), hidden.clone());
        let (arriving_for_policy, requests_for_policy, request_store) = (arriving.clone(), requests.clone(), store.clone());
        let keeper = opts.keeper;
        nopts.invite_policy = Arc::new(move |from, space| {
            // Serialize refusal checks and admission with accept/decline.
            let mut requests = requests_for_policy.lock();
            let blocked = blocked_for_policy.lock().contains(from);
            let hidden = hidden_for_policy.lock().contains(space);
            if blocked || hidden {
                return false;
            }
            if !keeper {
                // Persist provisional consent *before* network membership can
                // be persisted. A crash before the event bridge classifies this
                // invitation must restore a request, never an accepted chat.
                if !may_record_request(&requests, from, space) {
                    return false;
                }
                if !requests.contains_key(space) {
                    let mut pending = requests.clone();
                    pending.insert(*space, *from);
                    let list: Vec<_> = pending.iter().map(|(a, b)| (*a, *b)).collect();
                    let saved = postcard::to_allocvec(&list).map_err(anyhow::Error::from).and_then(|bytes| {
                        request_store.kv_batch_durable(vec![("requests".into(), Some(bytes))])
                    });
                    if saved.is_err() {
                        return false;
                    }
                    *requests = pending;
                }
                arriving_for_policy.lock().insert(*space);
            }
            true
        });
        let (requests_for_blobs, arriving_for_blobs, hidden_for_blobs) =
            (requests.clone(), arriving.clone(), hidden.clone());
        nopts.blob_push_policy = Arc::new(move |_peer, space| {
            let arriving = arriving_for_blobs.lock().contains(&space);
            let pending = requests_for_blobs.lock().contains_key(&space);
            let hidden = hidden_for_blobs.lock().contains(&space);
            keeper || (!arriving && !pending && !hidden)
        });
        let hints: BTreeMap<SignPk, Vec<String>> = store
            .kv_decode::<Vec<(SignPk, Vec<String>)>>("hints")?
            .unwrap_or_default()
            .into_iter()
            .collect();
        nopts.accept_relay_invites = opts.keeper;
        // Live calls share the endpoint (and so every path). Keepers relay
        // ciphertext only: no calls.
        let (call_tx, call_rx) = tokio::sync::mpsc::unbounded_channel();
        if !opts.keeper {
            nopts.extra_protocols.push(ExtraProtocol { alpn: ALPN_CALL.to_vec(), incoming: call_tx });
        }
        let engine = mycel_rules::RulesEngine::load(CHAT_RULES_WASM)
            .map_err(|e| anyhow!("chat rules failed to load: {e:?}"))?;
        nopts.feed_validator = Some(Arc::new(WasmRules(engine)));
        let node = Node::spawn(keys.clone(), nopts).await?;

        for (space, (ops, envs)) in stored_spaces {
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
        let me = keys.sign_pk();
        let rt = Arc::new_cyclic(|weak| Runtime {
            data_dir: dir,
            _profile_lock: profile_lock,
            keys,
            node,
            store,
            events,
            name: Mutex::new(name),
            contacts: Mutex::new(contacts),
            mode: opts.mode,
            next_mode: Mutex::new(next_mode),
            keeper: opts.keeper,
            views: Mutex::default(),
            announced: Mutex::default(),
            requests,
            arriving,
            hidden,
            hidden_messages,
            blocked,
            hints: Mutex::new(hints),
            calls: CallManager::new(Arc::new(RuntimeCallHost { me, rt: weak.clone() })),
        });
        if !rt.keeper {
            rt.calls.serve(call_rx);
        }
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

    /// Durability barrier used when the host enters the background.
    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.calls.shutdown().await;
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
            nearby: peers.get(pk).is_some_and(PeerState::is_directly_discovered),
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
        self.nearby_from_peers(self.node.peers())
    }

    fn nearby_from_peers(&self, peers: HashMap<SignPk, PeerState>) -> Vec<NearbyPeer> {
        let contacts = self.contacts.lock().clone();
        let mut out: Vec<NearbyPeer> = peers
            .into_iter()
            .filter(|(_, p)| p.is_directly_discovered())
            .map(|(pk, _)| NearbyPeer {
                id: hex_id(&pk),
                name: self.name_of(&pk),
                is_contact: contacts.contains_key(&pk),
            })
            .collect();
        out.sort_by_key(|p| p.name.to_lowercase());
        out
    }

    pub fn network_status(&self) -> NetworkStatus {
        let peers = self.node.peers();
        let me = self.keys.sign_pk();
        let mut paths: Vec<PeerPaths> = peers
            .iter()
            .filter(|(pk, p)| **pk != me && (p.online() || p.via.is_some()))
            .map(|(pk, p)| {
                let mut available: Vec<PathKind> = p.links.iter().copied().collect();
                if p.nearby {
                    available.insert(0, PathKind::Network);
                }
                PeerPaths {
                    id: hex_id(pk),
                    name: self.name_of(pk),
                    online: p.online(),
                    via: p.via,
                    available,
                    mesh: p.mesh.as_ref().map(|m| MeshVia {
                        via: hex_id(&m.via),
                        via_name: m.via_name.clone().unwrap_or_else(|| self.name_of(&m.via)),
                        hops: m.hops,
                        gateway: m.gateway,
                    }),
                }
            })
            .collect();
        paths.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name)));
        NetworkStatus {
            mode: self.mode,
            next_mode: *self.next_mode.lock(),
            online_peers: peers
                .iter()
                .filter(|(_, p)| p.online())
                .map(|(pk, _)| hex_id(pk))
                .collect(),
            nearby_peers: peers.values().filter(|p| p.is_directly_discovered()).count() as u32,
            addresses: self.node.local_addresses(),
            links: self.node.link_status(),
            peers: paths,
        }
    }

    /// The network mode saved by `set_network_mode`, if any. Hosts read it
    /// before opening the runtime (the mode is fixed while running).
    pub fn saved_network_mode(data_dir: &Path) -> Result<Option<NetworkMode>> {
        let Some(bytes) = crate::identity::read_optional(&data_dir.join("network-mode"), 64)? else {
            return Ok(None);
        };
        match std::str::from_utf8(&bytes).context("corrupt saved network mode")?.trim() {
            "lan" => Ok(Some(NetworkMode::Lan)),
            "internet" => Ok(Some(NetworkMode::Internet)),
            _ => bail!("corrupt saved network mode"),
        }
    }

    /// Choose the network mode for the next launch (`lan` = local paths only,
    /// `internet` = also relays). Takes effect after a restart.
    pub fn set_network_mode(&self, mode: NetworkMode) -> Result<NetworkStatus> {
        let word = match mode {
            NetworkMode::Lan => "lan",
            NetworkMode::Internet => "internet",
            NetworkMode::Local => bail!("local mode is for tests"),
        };
        crate::identity::atomic_write(&self.data_dir.join("network-mode"), word.as_bytes(), true)?;
        *self.next_mode.lock() = mode;
        self.emit(Event::NetworkChanged);
        Ok(self.network_status())
    }

    /// Best display name: contact name, else the name they announced in any
    /// conversation, else the discovered device name, else a short id.
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
        if self.arriving.lock().contains(space) {
            bail!("unknown conversation");
        }
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
        let (last, unread) = {
            let hidden = self.hidden_messages.lock();
            let visible =
                |m: &&mycel_kit_chat::Message| !m.deleted && !hidden.contains(&(*space, m.id));
            let last = view
                .messages
                .iter()
                .rev()
                .find(visible)
                .map(|m| self.message_view(space, &view, m, &HashSet::new()));
            let start = view
                .read_upto
                .get(&me)
                .map_or(0, |i| i + 1)
                .min(view.messages.len());
            let unread = view.messages[start..]
                .iter()
                .filter(visible)
                .filter(|m| m.author != me)
                .count() as u32;
            (last, unread)
        };
        // (take the lock once: two guards in one expression would deadlock)
        let inviter = self.requests.lock().get(space).copied();
        Ok(ConversationSummary {
            id: space.to_string(),
            title,
            direct: view.direct || (view.title.is_none() && people.len() == 1),
            members,
            last_message: last,
            unread,
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
            Some(b) => view
                .index_of(&parse_hash(&b)?)
                .unwrap_or(view.messages.len()),
            None => view.messages.len(),
        };
        let hidden = self.hidden_messages.lock();
        // Select visible messages before applying the page size. Hidden rows do
        // not shrink pages or prevent the UI from reaching older history.
        let mut selected: Vec<_> = view.messages[..end]
            .iter()
            .rev()
            .filter(|m| !hidden.contains(&(space, m.id)))
            .take(limit.unwrap_or(200).min(10_000) as usize)
            .collect();
        selected.reverse();
        Ok(selected
            .into_iter()
            .map(|m| self.message_view(&space, &view, m, &HashSet::new()))
            .collect())
    }

    /// Search the entire locally synchronized history, newest match first.
    pub fn search_messages(
        &self,
        id: ConversationId,
        query: String,
        limit: Option<u32>,
    ) -> Result<Vec<MessageView>> {
        let space = parse_space(&id)?;
        let view = self.view(&space)?;
        let terms: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let hidden = self.hidden_messages.lock();
        Ok(view
            .messages
            .iter()
            .rev()
            .filter(|m| !m.deleted && !hidden.contains(&(space, m.id)))
            .filter(|m| {
                let content = std::iter::once(m.body.as_str())
                    .chain(m.attachments.iter().map(|a| a.name.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                terms.iter().all(|term| content.contains(term))
            })
            .take(limit.unwrap_or(100).min(1_000) as usize)
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

    /// A throttled progress reporter emitting `TransferProgress` events,
    /// with the speed over the last [`RATE_WINDOW`].
    fn progress(&self, direction: TransferDirection, id: String) -> mycel_net::Progress {
        let events = self.events.clone();
        let samples: Mutex<std::collections::VecDeque<(Instant, u64)>> = Mutex::new(Default::default());
        Arc::new(move |done, total| {
            let now = Instant::now();
            let rate = {
                let mut s = samples.lock();
                if done < total && s.back().is_some_and(|&(t, _)| now.duration_since(t) < PROGRESS_EVERY) {
                    return;
                }
                sample_rate(&mut s, now, done)
            };
            let _ = events.send(Event::TransferProgress { direction, id: id.clone(), done, total, rate });
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
        // Consent applies even to already-cached files. Do not require current
        // membership: accepted history remains available after leaving a chat.
        if self.requests.lock().contains_key(&space) || self.arriving.lock().contains(&space)
            || self.hidden.lock().contains(&space)
        {
            bail!("accept this message request before downloading attachments");
        }
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

    /// Hide a message only on this device, including messages by other people.
    pub fn delete_message_local(&self, id: ConversationId, message: MessageId) -> Result<()> {
        self.set_message_hidden(id, message, true)
    }

    pub fn restore_message_local(&self, id: ConversationId, message: MessageId) -> Result<()> {
        self.set_message_hidden(id, message, false)
    }

    fn set_message_hidden(&self, id: ConversationId, message: MessageId, hide: bool) -> Result<()> {
        let space = parse_space(&id)?;
        let target = parse_hash(&message)?;
        let view = self.view(&space)?;
        if view.index_of(&target).is_none() {
            bail!("unknown message");
        }
        let mut hidden = self.hidden_messages.lock();
        let mut next = hidden.clone();
        let changed = if hide {
            next.insert((space, target))
        } else {
            next.remove(&(space, target))
        };
        if changed {
            self.store.kv_batch_durable(vec![(
                "hidden_messages".into(),
                Some(postcard::to_allocvec(
                    &next.iter().copied().collect::<Vec<_>>(),
                )?),
            )])?;
            *hidden = next;
        }
        drop(hidden);
        if changed {
            self.emit(Event::ConversationUpdated { conversation: id });
        }
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
        if self.requests.lock().contains_key(&space) || self.arriving.lock().contains(&space) {
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

    /// Accept a message request: the inviter becomes a contact (with the name
    /// they announced) and we introduce ourselves.
    pub fn accept_request(&self, id: ConversationId) -> Result<ConversationSummary> {
        let space = parse_space(&id)?;
        let inviter = {
            let mut requests = self.requests.lock();
            let inviter = *requests.get(&space).context("not a message request")?;
            let list: Vec<_> = requests.iter().filter(|(s, _)| **s != space).map(|(s, p)| (*s, *p)).collect();
            self.store.kv_batch_durable(vec![("requests".into(), Some(postcard::to_allocvec(&list)?))])?;
            requests.remove(&space);
            inviter
        };
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
        // Persist all refusal state atomically before relaxing the pending
        // gate. Keep lock order consistent with the push policy.
        {
            let mut requests = self.requests.lock();
            let inviter = *requests.get(&space).context("not a message request")?;
            let mut hidden = self.hidden.lock();
            let mut blocked = self.blocked.lock();
            let request_list: Vec<_> = requests.iter().filter(|(s, _)| **s != space).map(|(s, p)| (*s, *p)).collect();
            let mut hidden_next = hidden.clone();
            hidden_next.insert(space);
            let mut blocked_next = blocked.clone();
            if block {
                blocked_next.insert(inviter);
            }
            self.store.kv_batch_durable(vec![
                ("requests".into(), Some(postcard::to_allocvec(&request_list)?)),
                ("hidden".into(), Some(postcard::to_allocvec(&hidden_next.iter().copied().collect::<Vec<_>>())?)),
                ("blocked".into(), Some(postcard::to_allocvec(&blocked_next.iter().copied().collect::<Vec<_>>())?)),
            ])?;
            *hidden = hidden_next;
            *blocked = blocked_next;
            requests.remove(&space);
        }
        let _ = self.node.with_space(&space, |r| r.leave());
        self.touch(space);
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

    // ───────────── calls ─────────────

    /// The live-call engine (tests swap its audio with `calls().set_audio`).
    pub fn calls(&self) -> &CallManager {
        &self.calls
    }

    /// Whom a call in this conversation rings: everyone else in it.
    fn call_members(&self, space: &SpaceId) -> Result<Vec<SignPk>> {
        if self.keeper {
            bail!("keepers don't make calls");
        }
        if self.requests.lock().contains_key(space) {
            bail!("accept this message request before calling");
        }
        let me = self.keys.sign_pk();
        let (members, my_role) = self.node.with_space(space, |r| (r.members(), r.my_role()))?;
        if my_role.is_none_or(|r| r == Role::Relay) {
            bail!("you're no longer a member of this conversation");
        }
        let people: Vec<SignPk> = members
            .into_iter()
            .filter(|(k, role)| k.sign_pk != me && *role != Role::Relay)
            .map(|(k, _)| k.sign_pk)
            .collect();
        if people.is_empty() {
            bail!("there's nobody else in this conversation to call");
        }
        Ok(people)
    }

    /// May `peer` ring us about `space`? Both must be current members (not
    /// keepers); it must not be a message request we haven't accepted or a
    /// conversation we declined; and they must not be blocked.
    fn may_call(&self, space: &SpaceId, peer: &SignPk) -> bool {
        if self.keeper
            || self.requests.lock().contains_key(space)
            || self.hidden.lock().contains(space)
            || self.blocked.lock().contains(peer)
        {
            return false;
        }
        self.node
            .with_space(space, |r| {
                r.my_role().is_some_and(|m| m != Role::Relay)
                    && r.members().iter().any(|(k, role)| k.sign_pk == *peer && *role != Role::Relay)
            })
            .unwrap_or(false)
    }

    /// Call a conversation: the other person, or everyone in a group (up to
    /// 8 can be in the call at once). Joins the conversation's call instead
    /// if one is ringing you or going on without you. Returns at once (the
    /// call is `connecting`); watch `callUpdated` for ringing / active /
    /// ended (`unavailable` if nobody can be reached).
    pub async fn start_call(&self, conversation: ConversationId) -> Result<CallInfo> {
        let space = parse_space(&conversation)?;
        self.calls.start(space).await
    }

    /// Answer a ringing call, or join a `joinable` group call.
    pub async fn accept_call(&self, call: String) -> Result<CallInfo> {
        self.calls.accept(&call).await
    }

    pub fn decline_call(&self, call: String) -> Result<()> {
        self.calls.decline(&call)
    }

    /// Hang up (a group call goes on for the others), or cancel an outgoing
    /// call that hasn't been answered.
    pub fn end_call(&self, call: String) -> Result<()> {
        self.calls.end(&call)
    }

    pub fn set_muted(&self, call: String, muted: bool) -> Result<CallInfo> {
        self.calls.set_muted(&call, muted)
    }

    /// Turn our camera on or off in a call (before it's answered too). The
    /// first time, this waits for the user to answer the camera prompt.
    pub async fn set_camera(&self, call: String, on: bool) -> Result<CallInfo> {
        self.calls.set_camera(&call, on).await
    }

    /// The app's video decoder needs a fresh start: keyframes, please.
    pub fn video_keyframe(&self, call: String, source: Option<String>) -> Result<()> {
        self.calls.video_keyframe(&call, source.as_deref())
    }

    /// Encoded video frames for the app to decode and show: every call's
    /// remote video and our self-view (binary layout: `mycel_video::UiFrame`).
    pub fn video_frames(&self) -> tokio::sync::broadcast::Receiver<mycel_video::UiFrame> {
        self.calls.video_frames()
    }

    /// Start a call, with our camera on from the start if `video`.
    pub async fn start_call_with(&self, conversation: ConversationId, video: bool) -> Result<CallInfo> {
        let info = self.start_call(conversation).await?;
        if !video {
            return Ok(info);
        }
        // a denied camera doesn't stop the call: `video.error` says why
        Ok(self.set_camera(info.id.clone(), true).await.unwrap_or_else(|_| {
            self.call_status().into_iter().find(|c| c.id == info.id).unwrap_or(info)
        }))
    }

    /// Answer a call, with our camera on if `video`.
    pub async fn accept_call_with(&self, call: String, video: bool) -> Result<CallInfo> {
        if video {
            let _ = self.set_camera(call.clone(), true).await;
        }
        self.accept_call(call).await
    }

    /// Live calls, plus ones that ended in the last few seconds.
    pub fn call_status(&self) -> Vec<CallInfo> {
        self.calls.status()
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
                        let cleared = {
                            let mut requests = rt.requests.lock();
                            let list: Vec<_> = requests.iter().filter(|(s, _)| **s != space).map(|(s, p)| (*s, *p)).collect();
                            let result = postcard::to_allocvec(&list).map_err(anyhow::Error::from).and_then(|bytes| {
                                rt.store.kv_batch_durable(vec![("requests".into(), Some(bytes))])
                            });
                            if result.is_ok() {
                                requests.remove(&space);
                            }
                            result.is_ok()
                        };
                        if !cleared {
                            // Storage failure retains the conservative request.
                            continue;
                        }
                        // a contact added us: introduce ourselves right away
                        if rt.my_role(&space).is_some_and(Role::can_write) {
                            let name = rt.name.lock().clone();
                            let _ = rt.post(space, ChatOp::Profile { name });
                        }
                    }
                    // Stranger requests were persisted by invite_policy before
                    // admission. A concurrent accept/decline may already have
                    // removed one by the time this event is handled.
                }
                rt.arriving.lock().remove(&space);
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

/// Add a progress sample (`done` bytes at `now`) and return the speed in
/// bytes per second over the last [`RATE_WINDOW`].
fn sample_rate(s: &mut std::collections::VecDeque<(Instant, u64)>, now: Instant, done: u64) -> u64 {
    if s.back().is_some_and(|&(_, d)| done < d) {
        s.clear(); // restarted from scratch
    }
    // Only samples that moved: completion can be reported more than once (by
    // each source, then after the file is checked and synced, which can take
    // seconds), and a window holding only "all done" samples said 0 B/s for
    // a finished transfer.
    if s.back().is_none_or(|&(_, d)| done > d) {
        s.push_back((now, done));
    }
    while s.len() > 2 && s.front().is_some_and(|&(t, _)| now.duration_since(t) > RATE_WINDOW) {
        s.pop_front();
    }
    let ((t0, d0), (t1, d1)) = (s[0], s[s.len() - 1]);
    let secs = t1.duration_since(t0).as_secs_f64();
    if secs > 0.0 { ((d1 - d0) as f64 / secs) as u64 } else { 0 }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn nearby_list_includes_direct_radios_but_excludes_remote_reachability() {
        use super::*;
        let dir = std::env::temp_dir().join(format!("mycel-nearby-{}", mycel_crypto::random_u64()));
        let runtime = Runtime::open(&dir, NetworkMode::Local, Some("Discovery test".into())).await.unwrap();
        let bluetooth = DeviceKeys::generate().public();
        let wifi = DeviceKeys::generate().sign_pk();
        let lan = DeviceKeys::generate().sign_pk();
        let mesh = DeviceKeys::generate().sign_pk();
        let recent = DeviceKeys::generate().sign_pk();
        runtime.contacts.lock().insert(bluetooth.sign_pk, StoredContact { keys: bluetooth, name: "Alice's phone".into() });
        runtime.announced.lock().insert(wifi, "Bob's phone".into());
        let mut peers = HashMap::from([
            (bluetooth.sign_pk, PeerState { links: BTreeSet::from([PathKind::Bluetooth]), ..Default::default() }),
            (wifi, PeerState { links: BTreeSet::from([PathKind::PeerWifi]), ..Default::default() }),
            (lan, PeerState { nearby: true, ..Default::default() }),
            (mesh, PeerState { links: BTreeSet::from([PathKind::Mesh]), last_ok: Some(Instant::now()), ..Default::default() }),
            (recent, PeerState { last_ok: Some(Instant::now()), ..Default::default() }),
        ]);
        // This is the same filtering/name construction called by nearby(),
        // whose old mDNS-only filter omitted both radio-discovered phones.
        let nearby = runtime.nearby_from_peers(peers.clone());
        assert_eq!(nearby.len(), 3);
        let alice = nearby.iter().find(|p| p.id == hex_id(&bluetooth.sign_pk)).unwrap();
        assert_eq!(alice.name, "Alice's phone");
        assert!(alice.is_contact);
        let bob = nearby.iter().find(|p| p.id == hex_id(&wifi)).unwrap();
        assert_eq!(bob.name, "Bob's phone");
        assert!(!bob.is_contact);
        assert!(nearby.iter().any(|p| p.id == hex_id(&lan)));
        assert!(!nearby.iter().any(|p| p.id == hex_id(&mesh) || p.id == hex_id(&recent)));
        // A successful exchange or mesh fallback after the direct radio is
        // lost keeps online status, but must remove it from Nearby/pickers.
        let lost = peers.get_mut(&wifi).unwrap();
        lost.links = BTreeSet::from([PathKind::Mesh]);
        lost.last_ok = Some(Instant::now());
        assert!(lost.online());
        assert!(!runtime.nearby_from_peers(peers).iter().any(|p| p.id == hex_id(&wifi)));
        runtime.shutdown().await.unwrap();
        drop(runtime);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn voice_note_mime_types() {
        assert_eq!(super::guess_mime("Voice note.m4a"), "audio/mp4");
        assert_eq!(super::guess_mime("Voice note.WEBA"), "audio/webm");
        assert_eq!(super::guess_mime("Voice note.ogg"), "audio/ogg");
        assert_eq!(super::guess_mime("Movie.webm"), "video/webm");
    }

    #[test]
    fn pending_request_limits_apply_before_admission_and_keep_repeats_idempotent() {
        use super::*;
        fn space(n: usize) -> SpaceId {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            Hash32(bytes)
        }
        let first = SignPk([1; 32]);
        let second = SignPk([2; 32]);
        let mut pending = BTreeMap::new();
        for n in 0..MAX_PENDING_PER_INVITER {
            assert!(may_record_request(&pending, &first, &space(n)));
            pending.insert(space(n), first);
        }
        assert!(!may_record_request(&pending, &first, &space(32)));
        assert!(may_record_request(&pending, &second, &space(32)));
        for n in MAX_PENDING_PER_INVITER..MAX_PENDING_REQUESTS {
            let peer = SignPk([2 + (n / MAX_PENDING_PER_INVITER) as u8; 32]);
            assert!(may_record_request(&pending, &peer, &space(n)));
            pending.insert(space(n), peer);
        }
        assert!(!may_record_request(&pending, &second, &space(MAX_PENDING_REQUESTS)));
        assert!(may_record_request(&pending, &first, &space(0)), "existing request survives both limits");
    }

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

    /// 100 MB in 2 s, then "done" again 5 s later (the file was being
    /// checked): still 50 MB/s, not 0.
    #[test]
    fn a_late_repeat_of_done_keeps_the_speed() {
        use super::{Duration, Instant, sample_rate};
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let mut s = Default::default();
        for i in 0..=8u64 {
            sample_rate(&mut s, at(i * 250), i * 12_500_000);
        }
        let rate = sample_rate(&mut s, at(7_000), 100_000_000);
        assert_eq!(rate, 50_000_000);
    }
}
