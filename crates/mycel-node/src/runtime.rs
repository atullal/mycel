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
/// conversations and their sync history are outside these admission limits,
/// and so are contacts: strangers can never lock contacts out.
const MAX_PENDING_REQUESTS: usize = 256;
const MAX_PENDING_PER_INVITER: usize = 32;

/// What to do with an invitation before its membership is stored.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Admit,
    /// Admit, declining this older stranger request to make room.
    AdmitEvicting(SpaceId),
    Refuse,
}

/// Contacts are always admitted. A stranger is refused only past its own
/// limit; when strangers fill every slot, the oldest request of whoever has
/// the most pending is declined, so a flood from throwaway keys displaces
/// its own requests first and never refuses everyone new. `order` is this
/// session's arrival order, oldest first; requests not in it are older.
fn admit_request(
    requests: &BTreeMap<SpaceId, SignPk>,
    order: &[SpaceId],
    is_contact: impl Fn(&SignPk) -> bool,
    from: &SignPk,
    space: &SpaceId,
) -> Admission {
    if requests.contains_key(space) || is_contact(from) {
        return Admission::Admit;
    }
    let mut pending: HashMap<SignPk, usize> = HashMap::new();
    for inviter in requests.values().filter(|p| !is_contact(p)) {
        *pending.entry(*inviter).or_default() += 1;
    }
    if pending.get(from).is_some_and(|n| *n >= MAX_PENDING_PER_INVITER) {
        return Admission::Refuse;
    }
    if pending.values().sum::<usize>() < MAX_PENDING_REQUESTS {
        return Admission::Admit;
    }
    let most = pending.values().copied().max().unwrap_or(0);
    let age = |s: &SpaceId| order.iter().position(|o| o == s).map_or((0, 0), |i| (1, i));
    requests
        .iter()
        .filter(|(_, p)| pending.get(*p) == Some(&most) && !is_contact(p))
        .min_by_key(|(s, _)| age(s))
        .map_or(Admission::Refuse, |(s, _)| Admission::AdmitEvicting(*s))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredContact {
    keys: MemberKeys,
    /// Name imported from the authenticated card, used until a signed Profile
    /// supplies a newer name. This is not a user-defined local alias.
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
    contacts: Arc<Mutex<BTreeMap<SignPk, StoredContact>>>,
    mode: NetworkMode,
    /// The mode the next launch will use (`set_network_mode`).
    next_mode: Mutex<NetworkMode>,
    keeper: bool,
    /// Reduced chat views, invalidated whenever a space changes.
    views: Mutex<HashMap<SpaceId, Arc<ChatView>>>,
    /// Keep local Start chat calls idempotent, including double taps and
    /// concurrent callers. Transport discovery never defines chat identity.
    direct_chat_creation: Mutex<()>,
    /// Names people announced (Profile ops), across all conversations.
    announced: Mutex<HashMap<SignPk, String>>,
    /// Prevent an older conversation's Profile from reverting a newer rename.
    announced_versions: Mutex<HashMap<SignPk, (u64, Hash32)>>,
    /// Current display entry is separate from timestamp high-water: a causal
    /// rename after clock rollback must not let stale snapshots win again.
    announced_current: Mutex<HashMap<SignPk, Hash32>>,
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
    /// What startup recovered from (see `notices`).
    notices: Mutex<Vec<Notice>>,
    /// Stranger requests declined to make room for newer ones (see
    /// `admit_request`), still to be left.
    evicted: Arc<Mutex<Vec<SpaceId>>>,
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
        let identity = crate::identity::load(&dir, &profile_lock)?;
        let keys = Arc::new(identity.keys);
        let mut notices = Vec::new();
        if let Some(kept) = identity.replaced {
            notices.push(Notice::IdentityReplaced { kept_in: kept.display().to_string() });
        }
        // Validate persisted mode before opening any network transport.
        let next_mode = match Self::saved_network_mode(&dir) {
            Ok(mode) => mode.unwrap_or(opts.mode),
            Err(error) => {
                // Never widen to the internet on a guess, and never refuse to
                // start: local paths only until the user chooses again.
                eprintln!("mycel: {error:#}; using local paths only (lan)");
                if let Err(error) = crate::identity::atomic_write(&dir.join("network-mode"), b"lan", true) {
                    eprintln!("mycel: couldn't repair the saved network mode: {error:#}");
                }
                notices.push(Notice::NetworkModeReset);
                NetworkMode::Lan
            }
        };
        let store = DbStore::open(dir.join("mycel.redb"))?;
        // Set aside malformed persisted rows before spawning any transport task.
        let (stored_spaces, set_aside) = store.load_spaces()?;
        if set_aside > 0 {
            notices.push(Notice::RecordsSetAside { count: set_aside });
        }

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
        let contacts: Arc<Mutex<BTreeMap<SignPk, StoredContact>>> = Arc::new(Mutex::new(store
            .kv_decode::<Vec<StoredContact>>("contacts")?
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.keys.sign_pk, c))
            .collect()));

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
        let (contacts_for_policy, evicted): (_, Arc<Mutex<Vec<SpaceId>>>) = (contacts.clone(), Arc::default());
        let evicted_by_policy = evicted.clone();
        let arrival_order: Mutex<Vec<SpaceId>> = Mutex::default();
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
                let mut order = arrival_order.lock();
                order.retain(|s| requests.contains_key(s));
                let admission = {
                    let contacts = contacts_for_policy.lock();
                    admit_request(&requests, &order, |p| contacts.contains_key(p), from, space)
                };
                let evict = match admission {
                    Admission::Refuse => return false,
                    Admission::Admit => None,
                    Admission::AdmitEvicting(victim) => Some(victim),
                };
                if !requests.contains_key(space) {
                    let mut pending = requests.clone();
                    pending.insert(*space, *from);
                    let mut hidden = hidden_for_policy.lock();
                    let mut hidden_next = hidden.clone();
                    let mut writes = Vec::new();
                    // An evicted request is declined (kept, never shown), in
                    // the same transaction that records the new one.
                    if let Some(victim) = evict {
                        pending.remove(&victim);
                        hidden_next.insert(victim);
                        let list: Vec<_> = hidden_next.iter().copied().collect();
                        writes.push(("hidden".to_string(), postcard::to_allocvec(&list).ok()));
                    }
                    let list: Vec<_> = pending.iter().map(|(a, b)| (*a, *b)).collect();
                    writes.push(("requests".to_string(), postcard::to_allocvec(&list).ok()));
                    if writes.iter().any(|(_, v)| v.is_none()) || request_store.kv_batch_durable(writes).is_err() {
                        return false;
                    }
                    *requests = pending;
                    *hidden = hidden_next;
                    order.push(*space);
                    if let Some(victim) = evict {
                        evicted_by_policy.lock().push(victim);
                    }
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
        let health_events = events.clone();
        store.on_health_change(Arc::new(move || {
            let _ = health_events.send(Event::NoticesChanged);
        }));
        let me = keys.sign_pk();
        let rt = Arc::new_cyclic(|weak| Runtime {
            data_dir: dir,
            _profile_lock: profile_lock,
            keys,
            node,
            store,
            events,
            name: Mutex::new(name),
            contacts,
            mode: opts.mode,
            next_mode: Mutex::new(next_mode),
            keeper: opts.keeper,
            views: Mutex::default(),
            direct_chat_creation: Mutex::new(()),
            announced: Mutex::default(),
            announced_versions: Mutex::default(),
            announced_current: Mutex::default(),
            requests,
            arriving,
            hidden,
            hidden_messages,
            blocked,
            hints: Mutex::new(hints),
            calls: CallManager::new(Arc::new(RuntimeCallHost { me, rt: weak.clone() })),
            notices: Mutex::new(notices),
            evicted,
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
        let canonical = |id: String| parse_space(&id).map(|space| self.logical_id(&space)).unwrap_or(id);
        let e = match e {
            Event::ConversationUpdated { conversation } => Event::ConversationUpdated { conversation: canonical(conversation) },
            Event::ConversationAdded { conversation } => Event::ConversationAdded { conversation: canonical(conversation) },
            Event::Typing { conversation, peer } => Event::Typing { conversation: canonical(conversation), peer },
            Event::CallIncoming { call } => Event::CallIncoming { call: self.logical_call(call) },
            Event::CallUpdated { call } => Event::CallUpdated { call: self.logical_call(call) },
            other => other,
        };
        let _ = self.events.send(e);
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Problems the user should know about (see [`Notice`]).
    pub fn notices(&self) -> Vec<Notice> {
        let mut notices = self.notices.lock().clone();
        if let Some(error) = self.store.failure() {
            notices.push(Notice::StorageFailing { error });
        }
        notices
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

    /// The mode to launch with: the one saved by `set_network_mode`, else
    /// `default`. Hosts read it before opening the runtime (the mode is fixed
    /// while running). A saved mode that can't be read (releases before this
    /// one wrote it non-atomically) means local paths only (`lan`), the most
    /// private choice, never a wider one; `open` then repairs the file and
    /// reports [`Notice::NetworkModeReset`].
    pub fn launch_network_mode(data_dir: &Path, default: NetworkMode) -> NetworkMode {
        match Self::saved_network_mode(data_dir) {
            Ok(mode) => mode.unwrap_or(default),
            Err(error) => {
                eprintln!("mycel: {error:#}; using local paths only (lan)");
                NetworkMode::Lan
            }
        }
    }

    /// The network mode saved by `set_network_mode`, if any; an error if the
    /// saved mode can't be read (see `launch_network_mode`).
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

    /// Signed Profile names supersede the imported card name. Unsigned radio
    /// discovery is only a fallback when no authenticated name is known.
    fn name_of(&self, pk: &SignPk) -> String {
        if *pk == self.keys.sign_pk() {
            return self.name.lock().clone();
        }
        let announced = self.announced.lock().get(pk).cloned();
        if let Some(n) = announced {
            return n;
        }
        let contact_name = self.contacts.lock().get(pk).map(|c| c.name.clone());
        if let Some(n) = contact_name.filter(|n| !n.is_empty()) {
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
        let names_changed = self.learn_profile_names(&items);
        self.views.lock().insert(*space, view.clone());
        if names_changed {
            self.emit(Event::ContactsChanged);
            self.emit(Event::NearbyChanged);
            self.emit(Event::NetworkChanged);
        }
        Ok(view)
    }

    fn learn_profile_names(&self, items: &[mycel_sync::FeedItem]) -> bool {
        let mut latest = HashMap::new();
        let mut high_water = HashMap::new();
        let mut profile_ids = HashSet::new();
        for item in items {
            // feed() contains authenticated, accepted envelopes; the signer
            // can change only its own name, never another peer's contact.
            if !item.author_role.can_write() { continue; }
            let Some(ChatOp::Profile { name }) = ChatOp::decode(&item.body) else { continue };
            let name = name.trim();
            let mut end = name.len().min(mycel_kit_chat::MAX_NAME);
            while !name.is_char_boundary(end) { end -= 1; }
            let name = &name[..end];
            if name.is_empty() { continue; }
            profile_ids.insert(item.id);
            let version = (item.ts_ms, item.id);
            high_water.entry(item.author).and_modify(|previous: &mut (u64, Hash32)| {
                *previous = (*previous).max(version);
            }).or_insert(version);
            // Feed items are causally ordered. A later update in the same
            // history wins even when timestamps tie or the clock moves back.
            latest.insert(item.author, (item.ts_ms, item.id, name.to_owned()));
        }
        let mut versions = self.announced_versions.lock();
        let mut current = self.announced_current.lock();
        let mut names = self.announced.lock();
        let mut changed = false;
        for (author, (timestamp, id, name)) in latest {
            let version = (timestamp, id);
            if current.get(&author).is_none()
                || versions.get(&author).is_none_or(|previous| version > *previous)
                || current.get(&author).is_some_and(|previous| id != *previous && profile_ids.contains(previous))
            {
                current.insert(author, id);
                changed |= names.get(&author).is_none_or(|previous| previous != &name);
                names.insert(author, name);
            }
            let peak = high_water[&author];
            versions.entry(author).and_modify(|previous| *previous = (*previous).max(peak)).or_insert(peak);
        }
        changed
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
        // Don't sign what can't be saved: a peer could hold it while we lose it.
        self.store.check_writable()?;
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
            aliases: vec![space.to_string()],
            thread_key: space.to_string(),
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
        let mut seen = HashSet::new();
        let mut out: Vec<ConversationSummary> = self
            .node
            .space_ids()
            .iter()
            .filter(|s| self.my_role(s) != Some(Role::Relay))
            .filter(|s| !self.hidden.lock().contains(*s))
            .filter_map(|s| self.logical_summary(s).ok())
            .filter(|s| seen.insert(s.id.clone()))
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.last_message.as_ref().map_or(0, |m| m.sent_at)));
        out
    }

    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary> {
        self.logical_summary(&parse_space(&id)?)
    }

    /// Only original two-person direct spaces may share a logical chat.
    /// Requests, former groups, revoked history and hidden spaces stay separate.
    fn direct_peer(&self, space: &SpaceId) -> Option<SignPk> {
        if self.hidden.lock().contains(space)
            || self.arriving.lock().contains(space)
            || self.requests.lock().contains_key(space)
        {
            return None;
        }
        let view = self.view(space).ok()?;
        if !view.direct || view.title.is_some() {
            return None;
        }
        let me = self.keys.sign_pk();
        self.node.with_space(space, |r| {
            if !r.my_role().is_some_and(Role::can_read) { return None; }
            let people: BTreeSet<SignPk> = r.members().into_iter()
                .filter(|(_, role)| *role != Role::Relay)
                .map(|(keys, _)| keys.sign_pk).collect();
            if people.len() != 2 || !people.contains(&me) { return None; }
            // A removed third person still makes this group history. Likewise
            // a keeper promoted to a reader once had access to private data.
            for op in r.all_ops() {
                if !r.graph().is_valid(&op.id()) { continue; }
                use mycel_trust::Action;
                let member = match &op.op.action {
                    Action::Genesis { founder, .. } => Some(founder.sign_pk),
                    Action::Add { member, role, .. } if *role != Role::Relay => Some(member.sign_pk),
                    Action::SetRole { member, role, .. } if *role != Role::Relay => Some(*member),
                    _ => None,
                };
                if member.is_some_and(|key| !people.contains(&key)) { return None; }
            }
            // Current direct metadata cannot retroactively turn a group into
            // private two-person history for aggregation purposes.
            if r.feed(&messages_feed()).iter().any(|item| {
                item.author_role == Role::Admin && matches!(ChatOp::decode(&item.body),
                    Some(ChatOp::Meta { title, direct }) if !direct || title.as_ref().is_some_and(|t| !t.trim().is_empty()))
            }) { return None; }
            people.into_iter().find(|key| *key != me)
        }).ok().flatten()
    }

    fn conversation_spaces(&self, space: &SpaceId) -> Vec<SpaceId> {
        let Some(peer) = self.direct_peer(space) else { return vec![*space] };
        let mut spaces: Vec<_> = self.node.space_ids().into_iter()
            .filter(|candidate| self.direct_peer(candidate) == Some(peer)).collect();
        spaces.sort();
        spaces
    }

    fn logical_id(&self, space: &SpaceId) -> ConversationId {
        self.conversation_spaces(space).first().unwrap_or(space).to_string()
    }

    fn logical_summary(&self, space: &SpaceId) -> Result<ConversationSummary> {
        let spaces = self.conversation_spaces(space);
        let mut result = self.summary(&spaces[0])?;
        result.aliases = spaces.iter().map(ToString::to_string).collect();
        if let Some(peer) = self.direct_peer(&spaces[0]) {
            let mut keys = [self.keys.sign_pk(), peer];
            keys.sort();
            let bytes: Vec<_> = keys.into_iter().flat_map(|key| key.0).collect();
            result.thread_key = format!("direct:{}", Hash32::digest("mycel/v0/direct-thread", &bytes));
        }
        for other in &spaces[1..] {
            let summary = self.summary(other)?;
            result.unread = result.unread.saturating_add(summary.unread);
            // A logical chat can post if one original accepted space can.
            // Grant only the writer UI capability here: admin operations still
            // refer to the canonical space and keep its actual admin role.
            if result.my_role == Some(MemberRole::ReadOnly)
                && matches!(summary.my_role, Some(MemberRole::Admin | MemberRole::Member))
            {
                result.my_role = Some(MemberRole::Member);
            }
            if summary.last_message.as_ref().map(|m| (m.sent_at, &m.id))
                > result.last_message.as_ref().map(|m| (m.sent_at, &m.id))
            {
                result.last_message = summary.last_message;
            }
        }
        if spaces.len() > 1 {
            let entries = self.message_entries(&spaces[0])?;
            let hidden = self.hidden_messages.lock();
            result.last_message = entries.into_iter().rev().find_map(|(source, view, index)| {
                let message = &view.messages[index];
                (!message.deleted && !hidden.contains(&(source, message.id)))
                    .then(|| self.message_view(&source, &view, message, &HashSet::new()))
            });
        }
        Ok(result)
    }

    fn message_space(&self, space: &SpaceId, target: &Hash32) -> Result<SpaceId> {
        for source in self.conversation_spaces(space) {
            if self.view(&source)?.index_of(target).is_some() { return Ok(source); }
        }
        bail!("unknown message")
    }

    fn posting_space(&self, space: &SpaceId) -> Result<SpaceId> {
        self.conversation_spaces(space).into_iter()
            .find(|source| self.my_role(source).is_some_and(Role::can_write))
            .ok_or_else(|| anyhow!("you can't post in this conversation"))
    }

    fn logical_call(&self, mut call: CallInfo) -> CallInfo {
        if let Ok(space) = parse_space(&call.conversation) {
            call.conversation = self.logical_id(&space);
        }
        call
    }

    fn existing_direct_conversation(&self, peer: SignPk) -> Option<ConversationSummary> {
        // A stable choice on every device once all spaces have synchronized.
        // Legacy duplicates remain intact so their message history is never
        // discarded by starting another chat.
        let mut spaces = self.node.space_ids();
        spaces.sort();
        for space in spaces {
            if self.hidden.lock().contains(&space)
                || self.arriving.lock().contains(&space)
                || self.requests.lock().contains_key(&space)
            {
                continue;
            }
            if self.direct_peer(&space) == Some(peer)
                && self.my_role(&space).is_some_and(Role::can_write)
                && let Ok(summary) = self.logical_summary(&space)
            {
                return Some(summary);
            }
        }
        None
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
        let _creation_guard = direct.then(|| self.direct_chat_creation.lock());
        if direct && let Some(existing) = self.existing_direct_conversation(keys[0].sign_pk) {
            return Ok(existing);
        }
        self.store.check_writable()?;
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
        self.logical_summary(&space)
    }

    pub fn messages(
        &self,
        id: ConversationId,
        limit: Option<u32>,
        before: Option<MessageId>,
    ) -> Result<Vec<MessageView>> {
        let space = parse_space(&id)?;
        let mut entries = self.message_entries(&space)?;
        let end = match before {
            Some(b) => {
                let target = parse_hash(&b)?;
                entries.iter().position(|(_, view, index)| view.messages[*index].id == target)
                    .unwrap_or(entries.len())
            }
            None => entries.len(),
        };
        entries.truncate(end);
        let hidden = self.hidden_messages.lock();
        // Select visible messages before applying the page size. Hidden rows do
        // not shrink pages or prevent the UI from reaching older history.
        let mut selected: Vec<_> = entries.into_iter()
            .rev()
            .filter(|(source, view, index)| !hidden.contains(&(*source, view.messages[*index].id)))
            .take(limit.unwrap_or(200).min(10_000) as usize)
            .collect();
        selected.reverse();
        Ok(selected
            .into_iter()
            .map(|(source, view, index)| self.message_view(&source, &view, &view.messages[index], &HashSet::new()))
            .collect())
    }

    fn message_entries(&self, space: &SpaceId) -> Result<Vec<(SpaceId, Arc<ChatView>, usize)>> {
        let sources: Vec<_> = self.conversation_spaces(space).into_iter()
            .map(|source| self.view(&source).map(|view| (source, view))).collect::<Result<_>>()?;
        // Merge the heads of causally ordered histories. A global timestamp
        // sort would reorder replies before their parents under clock skew.
        let mut heads = BTreeSet::new();
        for (source_index, (_, view)) in sources.iter().enumerate() {
            if let Some(message) = view.messages.first() {
                heads.insert((message.ts_ms, message.id, source_index, 0));
            }
        }
        let mut entries = Vec::new();
        while let Some((_, _, source_index, index)) = heads.pop_first() {
            let (source, view) = &sources[source_index];
            entries.push((*source, view.clone(), index));
            if let Some(message) = view.messages.get(index + 1) {
                heads.insert((message.ts_ms, message.id, source_index, index + 1));
            }
        }
        Ok(entries)
    }

    /// Search the entire locally synchronized history, newest match first.
    pub fn search_messages(
        &self,
        id: ConversationId,
        query: String,
        limit: Option<u32>,
    ) -> Result<Vec<MessageView>> {
        let space = parse_space(&id)?;
        let entries = self.message_entries(&space)?;
        let terms: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        let hidden = self.hidden_messages.lock();
        Ok(entries.into_iter()
            .rev()
            .filter(|(source, view, index)| {
                let m = &view.messages[*index];
                !m.deleted && !hidden.contains(&(*source, m.id))
            })
            .filter(|(_, view, index)| {
                let m = &view.messages[*index];
                let content = std::iter::once(m.body.as_str())
                    .chain(m.attachments.iter().map(|a| a.name.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                terms.iter().all(|term| content.contains(term))
            })
            .take(limit.unwrap_or(100).min(1_000) as usize)
            .map(|(source, view, index)| self.message_view(&source, &view, &view.messages[index], &HashSet::new()))
            .collect())
    }

    pub async fn send_message(
        &self,
        id: ConversationId,
        body: String,
        reply_to: Option<MessageId>,
        attachments: Vec<String>,
    ) -> Result<MessageView> {
        let requested = parse_space(&id)?;
        let reply_to = reply_to.map(|r| parse_hash(&r)).transpose()?;
        let space = match reply_to {
            Some(target) => self.message_space(&requested, &target)?,
            None => self.posting_space(&requested)?,
        };
        self.require_member(&space)?;
        if body.trim().is_empty() && attachments.is_empty() {
            bail!("message is empty");
        }
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
        let space = self.message_space(&parse_space(&id)?, &parse_hash(&message)?)?;
        self.require_member(&space)?;
        let target = self.own_message(&space, &message)?;
        self.post(space, ChatOp::Edit { target, body })?;
        Ok(())
    }

    pub fn delete_message(&self, id: ConversationId, message: MessageId) -> Result<()> {
        let space = self.message_space(&parse_space(&id)?, &parse_hash(&message)?)?;
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
        let target = parse_hash(&message)?;
        let space = self.message_space(&parse_space(&id)?, &target)?;
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
        let space = self.message_space(&parse_space(&id)?, &parse_hash(&message)?)?;
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
        for source in self.conversation_spaces(&space) {
            self.mark_space_read(&source)?;
        }
        Ok(())
    }

    fn mark_space_read(&self, space: &SpaceId) -> Result<()> {
        // No read receipts for message requests: the sender learns nothing
        // until we accept.
        if self.requests.lock().contains_key(space) || self.arriving.lock().contains(space) {
            return Ok(());
        }
        let me = self.keys.sign_pk();
        let view = self.view(space)?;
        let Some((idx, last)) = view
            .messages
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| m.author != me)
        else {
            return Ok(());
        };
        if view.has_read(&me, idx) || !self.my_role(space).is_some_and(Role::can_write) {
            return Ok(());
        }
        self.post(*space, ChatOp::Receipt { up_to: last.id })?;
        Ok(())
    }

    pub fn set_typing(&self, id: ConversationId) -> Result<()> {
        let space = self.posting_space(&parse_space(&id)?)?;
        self.require_member(&space)?;
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
        self.logical_summary(&space)
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

    /// An invitation was admitted (see `invite_policy`): a contact's becomes
    /// a conversation, anyone else's stays a request. Either way it stops
    /// being hidden as arriving, even when storage fails.
    fn classify_arrival(&self, space: SpaceId, from: SignPk) {
        self.leave_evicted_requests();
        self.invalidate(&space);
        if !self.keeper {
            let known = self.contacts.lock().contains_key(&from);
            if known {
                let cleared = {
                    let mut requests = self.requests.lock();
                    let list: Vec<_> = requests.iter().filter(|(s, _)| **s != space).map(|(s, p)| (*s, *p)).collect();
                    let result = postcard::to_allocvec(&list).map_err(anyhow::Error::from).and_then(|bytes| {
                        self.store.kv_batch_durable(vec![("requests".into(), Some(bytes))])
                    });
                    if result.is_ok() {
                        requests.remove(&space);
                    }
                    result.is_ok()
                };
                // Storage failure retains the conservative request: it shows
                // as a request to accept, rather than not at all.
                // A contact added us: introduce ourselves right away.
                if cleared && self.my_role(&space).is_some_and(Role::can_write) {
                    let name = self.name.lock().clone();
                    let _ = self.post(space, ChatOp::Profile { name });
                }
            }
            // Stranger requests were persisted by invite_policy before
            // admission. A concurrent accept/decline may already have
            // removed one by the time this event is handled.
        }
        self.arriving.lock().remove(&space);
        self.emit(Event::ConversationAdded { conversation: space.to_string() });
    }

    /// Leave the stranger requests the invite policy declined to make room,
    /// as declining one by hand does.
    fn leave_evicted_requests(&self) {
        let evicted = std::mem::take(&mut *self.evicted.lock());
        for space in evicted {
            if self.node.with_space(&space, |r| r.leave()).is_ok() {
                self.touch(space);
            }
            self.emit(Event::ConversationUpdated { conversation: space.to_string() });
        }
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
        let space = parse_space(&self.logical_id(&parse_space(&conversation)?))?;
        self.calls.start(space).await.map(|call| self.logical_call(call))
    }

    /// Answer a ringing call, or join a `joinable` group call.
    pub async fn accept_call(&self, call: String) -> Result<CallInfo> {
        self.calls.accept(&call).await.map(|call| self.logical_call(call))
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
        self.calls.set_muted(&call, muted).map(|call| self.logical_call(call))
    }

    /// Turn our camera on or off in a call (before it's answered too). The
    /// first time, this waits for the user to answer the camera prompt.
    pub async fn set_camera(&self, call: String, on: bool) -> Result<CallInfo> {
        self.calls.set_camera(&call, on).await.map(|call| self.logical_call(call))
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
        self.calls.status().into_iter().map(|call| self.logical_call(call)).collect()
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
                let _ = rt.view(&space);
                rt.emit(Event::ConversationUpdated { conversation: space.to_string() });
            }
            NetEvent::SpaceAdded { space, from } => rt.classify_arrival(space, from),
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
    async fn signed_profile_clock_rollback_keeps_new_name_after_stale_snapshot_replay() {
        use super::*;
        let dir = std::env::temp_dir().join(format!("mycel-name-clock-{}", mycel_crypto::random_u64()));
        let runtime = Runtime::open(&dir, NetworkMode::Local, Some("Clock test".into())).await.unwrap();
        let peer = DeviceKeys::generate().sign_pk();
        let profile = |timestamp: u64, id: u8, name: &str| mycel_sync::FeedItem {
            id: Hash32([id; 32]), author: peer, author_role: Role::Writer,
            ts_ms: timestamp, deps: vec![], body: ChatOp::Profile { name: name.into() }.encode(),
        };
        // The helper consumes authenticated, causally ordered feed snapshots;
        // synthetic item clocks exercise ordering independent of OS time.
        let old = profile(1000, 1, "Old name");
        let new = profile(900, 2, "New name after clock rollback");
        assert!(runtime.learn_profile_names(std::slice::from_ref(&old)));
        assert!(runtime.learn_profile_names(&[old.clone(), new.clone()]));
        assert_eq!(runtime.name_of(&peer), "New name after clock rollback");
        assert!(!runtime.learn_profile_names(std::slice::from_ref(&old)));
        assert_eq!(runtime.name_of(&peer), "New name after clock rollback");
        let intermediate = profile(1100, 3, "Intermediate name");
        let latest = profile(800, 4, "Newest causal name");
        assert!(runtime.learn_profile_names(&[old.clone(), new, intermediate.clone(), latest]));
        assert_eq!(runtime.name_of(&peer), "Newest causal name");
        assert!(!runtime.learn_profile_names(&[old, intermediate]));
        assert_eq!(runtime.name_of(&peer), "Newest causal name");
        assert_eq!(runtime.announced_versions.lock()[&peer].0, 1100);
        runtime.shutdown().await.unwrap();
        drop(runtime);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_profile_rename_refreshes_imported_contact_nearby_network_and_chat_names() {
        use super::*;
        async fn eventually(mut check: impl FnMut() -> bool) {
            for _ in 0..300 {
                if check() { return; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("signed profile rename timed out");
        }
        let da = std::env::temp_dir().join(format!("mycel-name-a-{}", mycel_crypto::random_u64()));
        let db = std::env::temp_dir().join(format!("mycel-name-b-{}", mycel_crypto::random_u64()));
        let mut alice = Runtime::open(&da, NetworkMode::Local, Some("Alice".into())).await.unwrap();
        let bob = Runtime::open(&db, NetworkMode::Local, Some("iPhone".into())).await.unwrap();
        let imported_code = bob.profile().contact_code;
        let contact = alice.add_contact(imported_code.clone()).unwrap();
        assert_eq!(contact.name, "iPhone", "authenticated card is the initial fallback");
        bob.add_contact(alice.profile().contact_code).unwrap();
        alice.node.add_peer_addr(bob.node.addr());
        bob.node.add_peer_addr(alice.node.addr());
        let conversation = alice.create_conversation(None, vec![contact.id.clone()]).unwrap();
        eventually(|| bob.conversations().iter().any(|c| c.id == conversation.id && !c.request)).await;
        eventually(|| alice.view(&parse_space(&conversation.id).unwrap()).unwrap().names.contains_key(&bob.keys.sign_pk())).await;
        let old_items = alice.node.with_space(&parse_space(&conversation.id).unwrap(), |r| r.feed(&messages_feed())).unwrap();
        let mut events = alice.subscribe();
        bob.set_name("Manbirs iphone".into()).unwrap();
        // Contact refresh must happen from the sync bridge itself; this poll
        // deliberately does not read the conversation to warm its view.
        eventually(|| alice.contacts().iter().any(|c| c.id == contact.id && c.name == "Manbirs iphone")).await;
        let changed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(events.recv().await, Ok(Event::ContactsChanged)) {
                    return;
                }
            }
        }).await;
        assert!(changed.is_ok(), "signed rename refreshes contact subscribers");
        assert_eq!(alice.conversation(conversation.id.clone()).unwrap().title, "Manbirs iphone");
        assert_eq!(alice.create_conversation(None, vec![contact.id.clone()]).unwrap().id, conversation.id);
        let nearby = alice.nearby_from_peers(HashMap::from([(bob.keys.sign_pk(), PeerState {
            name: Some("Unsigned discovery label".into()),
            links: BTreeSet::from([PathKind::Bluetooth]), ..Default::default()
        })]));
        assert_eq!(nearby[0].name, "Manbirs iphone");
        assert!(alice.network_status().peers.iter().any(|p| p.id == contact.id && p.name == "Manbirs iphone"));
        assert!(!alice.learn_profile_names(&old_items), "reading old signed history cannot undo the rename");
        alice.add_contact(imported_code).unwrap();
        assert_eq!(alice.contacts()[0].name, "Manbirs iphone", "reimporting an old card cannot override a newer signed profile");
        assert_eq!(alice.contacts()[0].id, contact.id, "display-name changes preserve authenticated identity");
        alice.shutdown().await.unwrap();
        drop(alice);
        alice = Runtime::open(&da, NetworkMode::Local, Some("Alice".into())).await.unwrap();
        assert_eq!(alice.contacts()[0].name, "Manbirs iphone", "signed name is restored from encrypted history after restart");
        assert_eq!(alice.conversation(conversation.id).unwrap().title, "Manbirs iphone");
        alice.shutdown().await.unwrap();
        bob.shutdown().await.unwrap();
        drop((alice, bob));
        std::fs::remove_dir_all(da).unwrap();
        std::fs::remove_dir_all(db).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_chat_wire_identity_survives_bluetooth_wifi_mesh_and_direct_path_change() {
        use super::*;
        use mycel_net::link::{Link, MemNet};
        use mycel_net::MeshOptions;
        async fn eventually(mut check: impl FnMut() -> bool) {
            for _ in 0..400 {
                if check() { return; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("mixed-medium mesh test timed out");
        }
        async fn device(name: &str, radios: &[&MemNet]) -> Node {
            let keys = Arc::new(DeviceKeys::generate());
            let mut options = NodeOptions::new(NetMode::Local, name);
            options.ip = false;
            options.links = radios.iter().map(|radio| radio.link(keys.sign_pk()) as Arc<dyn Link>).collect();
            options.mesh = Some(MeshOptions { announce_every: Duration::from_millis(500), ..Default::default() });
            Node::spawn(keys, options).await.unwrap()
        }
        let bluetooth = MemNet::new(0, PathKind::Bluetooth);
        let wifi = MemNet::new(1, PathKind::PeerWifi);
        let direct = MemNet::new(2, PathKind::PeerWifi);
        let manbir = device("Manbir", &[&bluetooth, &direct]).await;
        let shreya = device("Shreya", &[&wifi, &direct]).await;
        // MemLink::start announces peers even when its net is already cut;
        // cut after startup so the test emits the matching Lost events.
        direct.cut();
        eventually(|| !manbir.peers().get(&shreya.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))
            && !shreya.peers().get(&manbir.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))).await;
        let mac = device("Mac relay", &[&bluetooth, &wifi]).await;
        eventually(|| manbir.peers().get(&shreya.id()).is_some_and(|p| p.links.contains(&PathKind::Mesh))
            && shreya.peers().get(&manbir.id()).is_some_and(|p| p.links.contains(&PathKind::Mesh))).await;
        assert!(!manbir.peers()[&shreya.id()].is_directly_discovered());
        let (space, genesis) = manbir.create_space().unwrap();
        manbir.with_space(&space, |r| -> Result<()> {
            r.add_member(shreya.keys().public(), Role::Writer)?;
            r.append(messages_feed(), ChatOp::Meta { title: None, direct: true }.encode())?;
            r.append(messages_feed(), ChatOp::Text { body: "Bluetooth to WiFi through Mac".into(), reply_to: None, attachments: vec![] }.encode())?;
            Ok(())
        }).unwrap().unwrap();
        shreya.join_space(genesis).unwrap();
        shreya.sync_with(manbir.id(), space, true).await.unwrap();
        shreya.with_space(&space, |r| r.append(messages_feed(), ChatOp::Text {
            body: "WiFi to Bluetooth through Mac".into(), reply_to: None, attachments: vec![]
        }.encode())).unwrap().unwrap();
        manbir.sync_with(shreya.id(), space, false).await.unwrap();
        assert_eq!(manbir.peers()[&shreya.id()].via, Some(PathKind::Mesh));
        for node in [&manbir, &shreya] {
            assert_eq!(node.space_ids(), vec![space]);
            assert_eq!(node.with_space(&space, |r| reduce(&r.feed(&messages_feed())).messages.len()).unwrap(), 2);
        }
        assert!(mac.space_ids().is_empty(), "transport relay is not invited into either chat");

        direct.restore();
        eventually(|| manbir.peers().get(&shreya.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))
            && shreya.peers().get(&manbir.id()).is_some_and(|p| p.links.contains(&PathKind::PeerWifi))).await;
        // End the relay route after direct discovery. The existing chat now
        // travels over peer WiFi without changing the signed space identity.
        bluetooth.cut();
        wifi.cut();
        manbir.with_space(&space, |r| r.append(messages_feed(), ChatOp::Text {
            body: "Same chat after direct path change".into(), reply_to: None, attachments: vec![]
        }.encode())).unwrap().unwrap();
        shreya.sync_with(manbir.id(), space, false).await.unwrap();
        assert_eq!(shreya.peers()[&manbir.id()].via, Some(PathKind::PeerWifi));
        for node in [&manbir, &shreya] {
            assert_eq!(node.space_ids(), vec![space]);
            assert_eq!(node.with_space(&space, |r| reduce(&r.feed(&messages_feed())).messages.len()).unwrap(), 3);
        }
        assert!(mac.space_ids().is_empty());
        manbir.shutdown().await.unwrap();
        mac.shutdown().await.unwrap();
        shreya.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_chats_created_independently_converge_without_moving_signed_messages() {
        use super::*;
        async fn eventually(mut check: impl FnMut() -> bool) {
            for _ in 0..300 {
                if check() { return; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("direct chat convergence timed out");
        }
        let da = std::env::temp_dir().join(format!("mycel-direct-a-{}", mycel_crypto::random_u64()));
        let db = std::env::temp_dir().join(format!("mycel-direct-b-{}", mycel_crypto::random_u64()));
        let alice = Runtime::open(&da, NetworkMode::Local, Some("Alice".into())).await.unwrap();
        let bob = Runtime::open(&db, NetworkMode::Local, Some("Bob".into())).await.unwrap();
        // Exchange only authenticated identity keys. Deliberately install no
        // address hints yet: both devices start a direct chat before meeting.
        alice.contacts.lock().insert(bob.keys.sign_pk(), StoredContact { keys: bob.keys.public(), name: "Bob".into() });
        bob.contacts.lock().insert(alice.keys.sign_pk(), StoredContact { keys: alice.keys.public(), name: "Alice".into() });
        alice.save_contacts();
        bob.save_contacts();
        let ac = alice.create_conversation(None, vec![bob.profile().id]).unwrap();
        let bc = bob.create_conversation(None, vec![alice.profile().id]).unwrap();
        assert_ne!(ac.id, bc.id);
        assert_eq!(ac.thread_key, bc.thread_key, "logical identity is the same before either space synchronizes");
        let am = alice.send_message(ac.id.clone(), "Alice original".into(), None, vec![]).await.unwrap();
        let file = db.join("voice-note.m4a");
        std::fs::write(&file, b"synthetic voice note attachment").unwrap();
        let bm = bob.send_message(bc.id.clone(), "Bob original".into(), None, vec![file.to_string_lossy().into_owned()]).await.unwrap();
        assert_eq!(alice.node.space_ids().len(), 1);
        assert_eq!(bob.node.space_ids().len(), 1);

        alice.node.add_peer_addr(bob.node.addr());
        bob.node.add_peer_addr(alice.node.addr());
        eventually(|| [alice.as_ref(), bob.as_ref()].iter().all(|rt| {
            let list = rt.conversations();
            list.len() == 1 && list[0].aliases.len() == 2
                && rt.messages(list[0].id.clone(), None, None).is_ok_and(|messages| messages.len() == 2)
        })).await;
        let canonical = ac.id.clone().min(bc.id.clone());
        for rt in [alice.as_ref(), bob.as_ref()] {
            assert_eq!(rt.node.space_ids().len(), 2, "both original wire spaces remain");
            assert_eq!(rt.conversations()[0].id, canonical);
            assert_eq!(rt.conversations()[0].thread_key, ac.thread_key);
            assert_eq!(rt.conversations()[0].unread, 1);
            for alias in [&ac.id, &bc.id] {
                assert_eq!(rt.conversation(alias.clone()).unwrap().id, canonical);
                let messages = rt.messages(alias.clone(), None, None).unwrap();
                assert!(messages.iter().any(|m| m.id == am.id && m.conversation == ac.id));
                assert!(messages.iter().any(|m| m.id == bm.id && m.conversation == bc.id));
            }
            let last = rt.messages(canonical.clone(), Some(1), None).unwrap();
            let earlier = rt.messages(canonical.clone(), Some(1), Some(last[0].id.clone())).unwrap();
            assert_eq!(last.len(), 1);
            assert_eq!(earlier.len(), 1);
            assert_ne!(last[0].id, earlier[0].id);
            assert_eq!(rt.search_messages(canonical.clone(), "original".into(), None).unwrap().len(), 2);
            assert_eq!(rt.create_conversation(None, vec![if rt.keys.sign_pk() == alice.keys.sign_pk() { bob.profile().id } else { alice.profile().id }]).unwrap().id, canonical);
        }
        assert!(alice.edit_message(canonical.clone(), bm.id.clone(), "unauthorized".into()).is_err());
        alice.edit_message(bc.id.clone(), am.id.clone(), "Alice original edited".into()).unwrap();
        bob.toggle_reaction(ac.id.clone(), bm.id.clone(), "ok".into()).unwrap();
        let reply = bob.send_message(bc.id.clone(), "Reply across old chat alias".into(), Some(am.id.clone()), vec![]).await.unwrap();
        assert_eq!(reply.conversation, ac.id, "reply uses its target's original signed feed");
        let downloaded = alice.fetch_attachment(bm.attachments[0].blob.clone()).await.unwrap();
        assert_eq!(std::fs::read(downloaded).unwrap(), b"synthetic voice note attachment");
        alice.delete_message_local(ac.id.clone(), bm.id.clone()).unwrap();
        assert!(!alice.messages(canonical.clone(), None, None).unwrap().iter().any(|m| m.id == bm.id));
        assert!(bob.messages(canonical.clone(), None, None).unwrap().iter().any(|m| m.id == bm.id));
        alice.restore_message_local(ac.id.clone(), bm.id.clone()).unwrap();
        eventually(|| {
            let messages = alice.messages(canonical.clone(), None, None).unwrap();
            messages.iter().any(|m| m.id == reply.id)
                && messages.iter().any(|m| m.id == bm.id && m.reactions.iter().any(|r| r.emoji == "ok"))
                && bob.messages(canonical.clone(), None, None).unwrap().iter().any(|m| m.id == am.id && m.edited)
        }).await;
        bob.delete_message(ac.id.clone(), bm.id.clone()).unwrap();
        eventually(|| alice.messages(canonical.clone(), None, None).unwrap().iter().any(|m| m.id == bm.id && m.deleted)).await;
        assert_eq!(alice.search_messages(canonical.clone(), "original".into(), None).unwrap().len(), 1);
        alice.mark_read(bc.id.clone()).unwrap();
        bob.mark_read(ac.id.clone()).unwrap();
        assert_eq!(alice.conversations()[0].unread, 0);
        assert_eq!(bob.conversations()[0].unread, 0);
        eventually(|| alice.messages(canonical.clone(), None, None).unwrap().iter().any(|m| m.id == am.id && m.delivery == Delivery::Read)).await;
        // Calls arriving on a legacy source retain that wire identity while
        // events/status present the canonical logical chat to the app.
        use mycel_call::audio::{TestAudio, TestSource};
        for rt in [&alice, &bob] {
            rt.calls.set_audio(Arc::new(TestAudio::new(TestSource::Sine { hz: 440.0, amp: 0.1 })));
        }
        let noncanonical = ac.id.clone().max(bc.id.clone());
        let raw_call = bob.calls.start(parse_space(&noncanonical).unwrap()).await.unwrap();
        assert_eq!(raw_call.conversation, noncanonical);
        eventually(|| alice.call_status().iter().any(|call| call.id == raw_call.id && call.state == CallPhase::Ringing)).await;
        assert!(alice.call_status().iter().any(|call| call.id == raw_call.id && call.conversation == canonical));
        assert!(bob.call_status().iter().any(|call| call.id == raw_call.id && call.conversation == canonical));
        assert_eq!(alice.accept_call(raw_call.id.clone()).await.unwrap().conversation, canonical);
        eventually(|| [alice.as_ref(), bob.as_ref()].iter().all(|rt| rt.call_status().iter().any(|call| call.id == raw_call.id && call.state == CallPhase::Active))).await;
        alice.end_call(raw_call.id.clone()).unwrap();
        eventually(|| bob.call_status().iter().any(|call| call.id == raw_call.id && call.state == CallPhase::Ended)).await;
        let canonical_call = alice.start_call(noncanonical).await.unwrap();
        assert_eq!(canonical_call.conversation, canonical);
        assert!(alice.calls.status().iter().any(|call| call.id == canonical_call.id && call.conversation == canonical),
            "new calls through old aliases choose the same canonical wire space on both devices");
        eventually(|| bob.call_status().iter().any(|call| call.id == canonical_call.id && call.state == CallPhase::Ringing)).await;
        bob.decline_call(canonical_call.id).unwrap();
        // Read projection never copied a signed message into another feed.
        assert!(!alice.view(&parse_space(&bc.id).unwrap()).unwrap().messages.iter().any(|m| m.id == parse_hash(&am.id).unwrap()));
        assert!(!bob.view(&parse_space(&ac.id).unwrap()).unwrap().messages.iter().any(|m| m.id == parse_hash(&bm.id).unwrap()));
        alice.shutdown().await.unwrap();
        bob.shutdown().await.unwrap();
        drop((alice, bob));
        let alice = Runtime::open(&da, NetworkMode::Local, Some("Alice".into())).await.unwrap();
        assert_eq!(alice.conversations().len(), 1);
        assert_eq!(alice.conversations()[0].aliases.len(), 2);
        assert_eq!(alice.messages(canonical, None, None).unwrap().len(), 3);
        alice.shutdown().await.unwrap();
        drop(alice);
        std::fs::remove_dir_all(da).unwrap();
        std::fs::remove_dir_all(db).unwrap();
    }

    #[tokio::test]
    async fn direct_chat_reuse_preserves_legacy_histories_and_respects_admission() {
        use super::*;
        let dir = std::env::temp_dir().join(format!("mycel-direct-{}", mycel_crypto::random_u64()));
        let runtime = Runtime::open(&dir, NetworkMode::Local, Some("Direct test".into())).await.unwrap();
        let peer = DeviceKeys::generate().public();
        runtime.contacts.lock().insert(peer.sign_pk, StoredContact { keys: peer, name: "Peer".into() });
        let create_legacy = || {
            let (space, _) = runtime.node.create_space().unwrap();
            runtime.node.with_space(&space, |r| -> Result<()> {
                r.add_member(peer, Role::Writer)?;
                r.append(messages_feed(), ChatOp::Meta { title: None, direct: true }.encode())?;
                Ok(())
            }).unwrap().unwrap();
            runtime.touch(space);
            space
        };
        let first = create_legacy();
        let second = create_legacy();
        let first_message = runtime.post(first, ChatOp::Text { body: "First history".into(), reply_to: None, attachments: vec![] }).unwrap().to_string();
        let second_message = runtime.post(second, ChatOp::Text { body: "Second history".into(), reply_to: None, attachments: vec![] }).unwrap().to_string();
        let selected = first.min(second);
        let other = first.max(second);
        let peer_id = hex_id(&peer.sign_pk);
        assert_eq!(runtime.create_conversation(None, vec![peer_id.clone()]).unwrap().id, selected.to_string());
        assert_eq!(runtime.conversations().len(), 1, "duplicates share one logical row");
        assert_eq!(runtime.node.space_ids().len(), 2, "both original encrypted spaces remain intact");
        assert_eq!(runtime.conversation(first.to_string()).unwrap().aliases.len(), 2);
        for alias in [first, second] {
            let history = runtime.messages(alias.to_string(), None, None).unwrap();
            assert_eq!(history.len(), 2);
            assert!(history.iter().any(|m| m.id == first_message && m.conversation == first.to_string()));
            assert!(history.iter().any(|m| m.id == second_message && m.conversation == second.to_string()));
        }

        // Admission gates must not be bypassed by reusing a pending/hidden chat.
        runtime.requests.lock().insert(selected, peer.sign_pk);
        assert_eq!(runtime.create_conversation(None, vec![peer_id.clone()]).unwrap().id, other.to_string());
        runtime.requests.lock().remove(&selected);
        runtime.hidden.lock().insert(selected);
        assert_eq!(runtime.create_conversation(None, vec![peer_id.clone()]).unwrap().id, other.to_string());
        runtime.hidden.lock().remove(&selected);
        runtime.arriving.lock().insert(selected);
        assert_eq!(runtime.create_conversation(None, vec![peer_id.clone()]).unwrap().id, other.to_string());
        runtime.arriving.lock().remove(&selected);

        // Keeper membership adds a transport/storage participant, not a person.
        let keeper = DeviceKeys::generate().public();
        runtime.node.with_space(&selected, |r| r.add_member(keeper, Role::Relay)).unwrap().unwrap();
        runtime.touch(selected);
        assert_eq!(runtime.create_conversation(None, vec![peer_id]).unwrap().id, selected.to_string());

        let former_group = create_legacy();
        let third = DeviceKeys::generate().public();
        runtime.node.with_space(&former_group, |r| -> Result<()> {
            r.add_member(third, Role::Writer)?;
            r.append(messages_feed(), ChatOp::Text { body: "Former group history".into(), reply_to: None, attachments: vec![] }.encode())?;
            r.remove_member(third.sign_pk)?;
            // Even an admin explicitly relabelling it cannot erase the fact
            // that a third person once had access to this space.
            r.append(messages_feed(), ChatOp::Meta { title: None, direct: true }.encode())?;
            Ok(())
        }).unwrap().unwrap();
        runtime.touch(former_group);
        assert!(runtime.direct_peer(&former_group).is_none());
        assert_eq!(runtime.conversations().len(), 2);
        assert_eq!(runtime.messages(selected.to_string(), None, None).unwrap().len(), 2);
        assert_eq!(runtime.messages(former_group.to_string(), None, None).unwrap().len(), 1);

        let promoted_keeper = create_legacy();
        runtime.node.with_space(&promoted_keeper, |r| -> Result<()> {
            r.add_member(third, Role::Relay)?;
            r.set_role(third.sign_pk, Role::Reader)?;
            r.set_role(third.sign_pk, Role::Relay)?;
            Ok(())
        }).unwrap().unwrap();
        runtime.touch(promoted_keeper);
        assert!(runtime.direct_peer(&promoted_keeper).is_none(), "a former reader must not be treated as a ciphertext-only keeper");
        let thread_key = runtime.conversation(selected.to_string()).unwrap().thread_key;
        runtime.node.with_space(&selected, |r| -> Result<()> {
            r.set_role(peer.sign_pk, Role::Admin)?;
            r.set_role(runtime.keys.sign_pk(), Role::Reader)?;
            Ok(())
        }).unwrap().unwrap();
        runtime.touch(selected);
        let logical = runtime.conversation(selected.to_string()).unwrap();
        assert_eq!(logical.my_role, Some(MemberRole::Member), "writable alias enables posting without granting canonical admin authority");
        assert_eq!(logical.thread_key, thread_key);
        let posted = runtime.send_message(selected.to_string(), "Writable source only".into(), None, vec![]).await.unwrap();
        assert_eq!(posted.conversation, other.to_string());
        let read_only_target = if selected == first { first_message } else { second_message };
        assert!(runtime.edit_message(other.to_string(), read_only_target, "cannot bypass source permissions".into()).is_err());
        runtime.shutdown().await.unwrap();
        drop(runtime);
        std::fs::remove_dir_all(dir).unwrap();
    }

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

    #[tokio::test]
    async fn a_contacts_invite_shows_as_a_request_when_storage_fails() {
        use super::*;
        let dir = std::env::temp_dir().join(format!("mycel-arrival-{}", mycel_crypto::random_u64()));
        let runtime = Runtime::open(&dir, NetworkMode::Local, Some("Arrival test".into())).await.unwrap();
        let peer = DeviceKeys::generate().public();
        runtime.contacts.lock().insert(peer.sign_pk, StoredContact { keys: peer, name: "Peer".into() });
        let (space, _) = runtime.node.create_space().unwrap();
        runtime.node.with_space(&space, |r| r.add_member(peer, Role::Writer)).unwrap().unwrap();
        // As invite_policy leaves an admitted invitation.
        runtime.requests.lock().insert(space, peer.sign_pk);
        runtime.arriving.lock().insert(space);
        runtime.store.fail_commits(usize::MAX);
        runtime.classify_arrival(space, peer.sign_pk);
        assert!(!runtime.arriving.lock().contains(&space), "never stuck hidden");
        assert!(runtime.requests.lock().contains_key(&space), "the conservative request is kept");
        assert!(runtime.conversations().iter().any(|c| c.id == space.to_string() && c.request));
        runtime.store.fail_commits(0);
        // Once storage works, the same arrival becomes the conversation.
        for _ in 0..200 {
            if runtime.store.failure().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        runtime.classify_arrival(space, peer.sign_pk);
        assert!(runtime.conversations().iter().any(|c| c.id == space.to_string() && !c.request));
        runtime.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_limits_never_refuse_contacts_or_everyone_new() {
        use super::*;
        fn space(n: usize) -> SpaceId {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            Hash32(bytes)
        }
        let stranger = |n: usize| {
            let mut bytes = [0xA0; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            SignPk(bytes)
        };
        let contact = SignPk([0xC0; 32]);
        let is_contact = |p: &SignPk| *p == contact;
        let (mut pending, mut order) = (BTreeMap::new(), Vec::new());
        fn record(pending: &mut BTreeMap<SpaceId, SignPk>, order: &mut Vec<SpaceId>, from: SignPk, at: SpaceId) {
            pending.insert(at, from);
            order.push(at);
        }
        for n in 0..MAX_PENDING_PER_INVITER {
            assert_eq!(admit_request(&pending, &[], is_contact, &stranger(0), &space(n)), Admission::Admit);
            record(&mut pending, &mut order, stranger(0), space(n));
        }
        assert_eq!(admit_request(&pending, &order, is_contact, &stranger(0), &space(999)), Admission::Refuse);
        assert_eq!(admit_request(&pending, &order, is_contact, &stranger(0), &space(0)), Admission::Admit, "repeats are idempotent");
        // Eight throwaway keys fill every slot.
        for n in MAX_PENDING_PER_INVITER..MAX_PENDING_REQUESTS {
            record(&mut pending, &mut order, stranger(n / MAX_PENDING_PER_INVITER), space(n));
        }
        // Contacts are always admitted, and their requests never count.
        assert_eq!(admit_request(&pending, &order, is_contact, &contact, &space(1000)), Admission::Admit);
        let mut with_contact = pending.clone();
        with_contact.insert(space(1000), contact);
        // A new stranger displaces the oldest request of a top inviter.
        assert_eq!(
            admit_request(&with_contact, &order, is_contact, &stranger(9), &space(1001)),
            Admission::AdmitEvicting(space(0))
        );
        // A heavy inviter loses its own requests first, even its newest.
        let mut fair = BTreeMap::new();
        let mut fair_order = Vec::new();
        for n in 0..MAX_PENDING_REQUESTS - MAX_PENDING_PER_INVITER {
            fair.insert(space(n), stranger(100 + n));
            fair_order.push(space(n));
        }
        for n in 0..MAX_PENDING_PER_INVITER {
            fair.insert(space(500 + n), stranger(7));
            fair_order.push(space(500 + n));
        }
        assert_eq!(
            admit_request(&fair, &fair_order, is_contact, &stranger(8), &space(2000)),
            Admission::AdmitEvicting(space(500))
        );
        // A profile already holding more requests than the limit (loaded
        // from disk, so no arrival order) still admits newcomers.
        let legacy: BTreeMap<_, _> = (0..300).map(|n| (space(n), stranger(n))).collect();
        assert_eq!(
            admit_request(&legacy, &[], is_contact, &stranger(5000), &space(3000)),
            Admission::AdmitEvicting(space(0))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_request_slots_never_lock_out_contacts_or_new_strangers() {
        use super::*;
        async fn eventually(mut check: impl FnMut() -> bool) {
            for _ in 0..300 {
                if check() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("condition did not become true");
        }
        let dirs: Vec<_> = (0..3)
            .map(|n| std::env::temp_dir().join(format!("mycel-request-slots-{n}-{}", mycel_crypto::random_u64())))
            .collect();
        let alice = Runtime::open(&dirs[0], NetworkMode::Local, Some("Alice".into())).await.unwrap();
        let bob = Runtime::open(&dirs[1], NetworkMode::Local, Some("Bob".into())).await.unwrap();
        let carol = Runtime::open(&dirs[2], NetworkMode::Local, Some("Carol".into())).await.unwrap();
        for a in [&alice, &bob, &carol] {
            for b in [&alice, &bob, &carol] {
                if a.profile().id != b.profile().id {
                    a.node.add_peer_addr(b.node.addr());
                }
            }
        }
        // Eight throwaway stranger keys already fill every request slot.
        let fake = |n: usize| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            Hash32(bytes)
        };
        for n in 0..MAX_PENDING_REQUESTS {
            let inviter = SignPk([0xE0 + (n / MAX_PENDING_PER_INVITER) as u8; 32]);
            alice.requests.lock().insert(fake(n), inviter);
        }
        let alice_id = alice.profile().id;
        alice.add_contact(bob.profile().contact_code).unwrap();
        bob.add_contact(alice.profile().contact_code).unwrap();
        carol.add_contact(alice.profile().contact_code).unwrap();

        let from_bob = bob.create_conversation(Some("From a contact".into()), vec![alice_id.clone()]).unwrap();
        eventually(|| alice.conversations().iter().any(|c| c.id == from_bob.id && !c.request)).await;
        assert!(alice.hidden.lock().is_empty(), "a contact never displaces anyone");

        let from_carol = carol.create_conversation(Some("From a stranger".into()), vec![alice_id]).unwrap();
        eventually(|| alice.conversations().iter().any(|c| c.id == from_carol.id && c.request)).await;
        assert_eq!(alice.hidden.lock().iter().copied().collect::<Vec<_>>(), vec![fake(0)]);
        assert_eq!(alice.requests.lock().len(), MAX_PENDING_REQUESTS);
        let saved: Vec<(SpaceId, SignPk)> = alice.store.kv_decode("requests").unwrap().unwrap();
        assert!(saved.iter().any(|(s, _)| s.to_string() == from_carol.id) && !saved.iter().any(|(s, _)| *s == fake(0)));
        let hidden: Vec<SpaceId> = alice.store.kv_decode("hidden").unwrap().unwrap();
        assert_eq!(hidden, vec![fake(0)]);
        for rt in [alice, bob, carol] {
            rt.shutdown().await.unwrap();
        }
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
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
