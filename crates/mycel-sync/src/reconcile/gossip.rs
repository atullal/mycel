//! Dissemination (Sync v2 stage 3, design §8): new items spread over a
//! Plumtree eager/lazy tree (Leitão, Pereira and Rodrigues, SRDS 2007) on a
//! symmetric overlay of the space's members, instead of sessions with every
//! member (O(members²) per change in v1).
//!
//! - **View.** Groups of [`FULL_MESH`] or fewer: every member is a
//!   neighbour. Larger ones: each device initiates [`LOCAL_EDGES`] edges to
//!   its best-placed reachable members (radio and LAN before internet before
//!   mesh) and [`RANDOM_EDGES`] to members picked uniformly by rendezvous
//!   hash over the whole member list (a random k-out graph with k ≥ 2 is
//!   connected with high probability, so physical clusters can't split the
//!   overlay). An edge exists once the far end has accepted the `Graft`;
//!   both ends then treat it as a neighbour (symmetric). A device accepts
//!   up to [`MAX_DEGREE`] edges (keepers [`KEEPER_DEGREE`]) and answers
//!   more with a dropping `Prune` that names alternatives.
//! - **Eager push.** New items (a local write, or what a push or session
//!   brought) go as `Push` to eager neighbours (all but the one they came
//!   from) when they fit in [`MAX_PUSH_BYTES`], and as `IHave` otherwise.
//!   A push that brings nothing new prunes the edge to lazy.
//! - **Lazy repair.** `IHave` (absolute frontier entries of the authors
//!   involved, aggregated over [`IHAVE_DELAY_MS`]) goes to
//!   [`IHAVE_FANOUT`] lazy neighbours, not all of them (Erlay's lesson). A
//!   device that doesn't cover an announcement within [`IHAVE_WAIT_FAST_MS`]
//!   (internet) or [`IHAVE_WAIT_SLOW_MS`] (Bluetooth, mesh) grafts the
//!   announcer (the edge becomes eager) and asks the driver for a Sync v2
//!   session with it ([`Action::Pull`]).
//! - **IDONTWANT.** Before forwarding a new item larger than
//!   [`HAVE_MIN_BYTES`], a device tells its other eager neighbours it has it
//!   (`Have`, as GossipSub v1.2's IDONTWANT), so they drop it from their
//!   queues to it instead of sending it over a slow link.
//! - **Byte-fair forwarding.** Pushes queue per outgoing link and per
//!   author, and leave by deficit round-robin across authors within the
//!   link's byte rate: on a 40 kB/s Bluetooth link no author gets more than
//!   its share, whatever it writes. A queue over its cap drops its oldest
//!   items (repaired by `IHave` and anti-entropy).
//!
//! Nothing here is trusted: every item still goes through
//! `Replica::ingest_batch`, frontier entries only decide who to ask, and
//! every per-peer amount is bounded. Like [`super::Session`], this is
//! sans-IO: the driver feeds messages and the time in, and sends what
//! [`Disseminator::poll`] yields.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use mycel_crypto::{Hash32, SignPk};
use mycel_trust::{OpId, SpaceId};
use serde::{Deserialize, Serialize};

use super::msg::AuthorEntry;
use super::{SyncSet, encoded_len};
use crate::EnvelopeId;

/// Groups up to this size: every member is a neighbour.
pub const FULL_MESH: usize = 6;
/// Edges a device initiates in a larger group: to its best-placed members,
/// and to members picked by rendezvous hash.
pub const LOCAL_EDGES: usize = 2;
pub const RANDOM_EDGES: usize = 2;
/// Edges a device accepts in all (initiated ones included), and a keeper.
pub const MAX_DEGREE: usize = 12;
pub const KEEPER_DEGREE: usize = 64;
/// A `Push` carries at most this many bytes of items; more is announced.
pub const MAX_PUSH_BYTES: usize = 16 * 1024;
/// Items a single change may push (more is announced).
pub const MAX_PUSH_ITEMS: usize = 64;
/// Ops a `Push` may carry.
pub const MAX_PUSH_OPS: usize = 16;
/// The largest gossip frame a device sends or accepts.
pub const MAX_GOSSIP_FRAME: usize = 64 * 1024;
/// Items larger than this are announced with `Have` before forwarding.
pub const HAVE_MIN_BYTES: usize = 1024;
/// Ids in one `Have`.
pub const MAX_HAVE_IDS: usize = 64;
/// Lazy neighbours an announcement goes to.
pub const IHAVE_FANOUT: usize = 3;
/// Announcements are aggregated for this long.
pub const IHAVE_DELAY_MS: u64 = 250;
/// How long an announced item may take to arrive by push before the device
/// grafts the announcer and pulls, on fast and on slow paths.
pub const IHAVE_WAIT_FAST_MS: u64 = 1_000;
pub const IHAVE_WAIT_SLOW_MS: u64 = 3_000;
/// Entries accepted in one announcement or push, and the bytes of entries
/// one carries (an equivocating author's entry lists up to 64 runs, so a
/// count alone wouldn't keep a message under [`MAX_GOSSIP_FRAME`]).
pub const MAX_ENTRIES: usize = 256;
pub const ENTRIES_BYTES: usize = 24 * 1024;
/// Alternatives named in a dropping `Prune`.
pub const MAX_ALTERNATIVES: usize = 4;
/// Seen notes attached to one message (bytes in all), and kept to forward.
pub const SEEN_BYTES_PER_MSG: usize = 512;
pub const MAX_SEEN_NOTE: usize = 512;
const SEEN_KEPT: usize = 64;
const SEEN_REMEMBERED: usize = 4096;
/// Views are redrawn this often (ms).
pub const VIEW_EPOCH_MS: u64 = 600_000;
/// Deficit round-robin quantum per author per round.
const QUANTUM: i64 = 2048;
/// A link's queue per author: items and bytes, beyond which the oldest go.
const QUEUE_ITEMS: usize = 256;
const QUEUE_BYTES: usize = 256 * 1024;
/// Ids a neighbour said it has, remembered per link.
const SKIP_REMEMBERED: usize = 4096;

const CTX_VIEW: &str = "mycel/v2/gossip-view";

/// An envelope as gossip sees it: its id.
pub trait GossipItem {
    fn gossip_id(&self) -> EnvelopeId;
}

impl GossipItem for crate::Envelope {
    fn gossip_id(&self) -> EnvelopeId {
        self.id()
    }
}

#[cfg(any(test, feature = "model"))]
impl GossipItem for super::model::ModelEnv {
    fn gossip_id(&self) -> EnvelopeId {
        self.id()
    }
}

/// One dissemination message, on a uni-stream of its own. Variants are only
/// ever appended (postcard can't skip unknown ones; the capability that
/// enables gossip names this version).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMsg<O, E> {
    /// New items: canonical ops first (parents first), then envelopes per
    /// author in ascending seq. `entries`: the sender's absolute frontier
    /// entries for those authors (what it holds).
    Push { space: SpaceId, ops: Vec<O>, items: Vec<E>, entries: Vec<AuthorEntry>, seen: Vec<Vec<u8>> },
    /// "I hold these": op tips and absolute entries of authors that changed.
    IHave { space: SpaceId, ops: Vec<OpId>, entries: Vec<AuthorEntry>, seen: Vec<Vec<u8>> },
    /// "Don't send me these, I have them" (IDONTWANT).
    Have { space: SpaceId, ids: Vec<EnvelopeId> },
    /// Make (or keep) the edge eager; accepted unless over the degree cap.
    Graft { space: SpaceId },
    /// `drop`: not a neighbour (over the degree cap, or no longer chosen),
    /// with alternatives to try; otherwise the edge becomes lazy.
    Prune { space: SpaceId, drop: bool, alternatives: Vec<SignPk> },
}

impl<O, E> GossipMsg<O, E> {
    pub fn space(&self) -> SpaceId {
        match self {
            GossipMsg::Push { space, .. }
            | GossipMsg::IHave { space, .. }
            | GossipMsg::Have { space, .. }
            | GossipMsg::Graft { space }
            | GossipMsg::Prune { space, .. } => *space,
        }
    }
}

/// How a member is reached now, best first: a direct radio or LAN path, the
/// internet, the mesh (by hops), store-and-forward only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathClass {
    Direct,
    Internet,
    Mesh,
    Dtn,
}

/// A member of a space as the driver sees it now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub key: SignPk,
    pub class: PathClass,
    /// Recent evidence it can be reached (a session or push succeeded).
    pub reachable: bool,
    /// It speaks gossip (its capability hello said so).
    pub gossip: bool,
    /// A slow link (Bluetooth, multi-hop): longer `IHave` waits, the slow
    /// byte rate.
    pub slow: bool,
}

/// Limits a driver may tune.
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Pushes per link, bytes per second, on fast and slow links, and the
    /// burst.
    pub fast_rate: f64,
    pub slow_rate: f64,
    pub burst: f64,
    /// This device is a keeper (accepts [`KEEPER_DEGREE`] edges).
    pub keeper: bool,
}

impl Default for GossipConfig {
    fn default() -> Self {
        // A slow link is a 40 kB/s Bluetooth hop shared with sessions,
        // blobs and routing: gossip takes at most half.
        GossipConfig { fast_rate: 1024.0 * 1024.0, slow_rate: 20.0 * 1024.0, burst: 64.0 * 1024.0, keeper: false }
    }
}

/// What the driver should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action<O, E> {
    Send {
        to: SignPk,
        msg: GossipMsg<O, E>,
    },
    /// Open a Sync v2 session with `peer` in `space` (a missed push).
    Pull {
        peer: SignPk,
        space: SpaceId,
    },
}

/// Counters for tests, the simulator and benchmarks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GossipStats {
    pub pushes_sent: u64,
    pub push_items_sent: u64,
    pub push_bytes_sent: u64,
    pub ihaves_sent: u64,
    pub haves_sent: u64,
    pub grafts_sent: u64,
    pub prunes_sent: u64,
    pub pulls: u64,
    /// Items received by push, and those already held.
    pub items_received: u64,
    pub duplicates: u64,
    /// Items dropped from a full link queue, and skipped because the
    /// neighbour said it had them.
    pub queue_dropped: u64,
    pub skipped_by_have: u64,
}

/// What a space's last announcement covered: changes are what differs.
#[derive(Clone, Default)]
struct Announced {
    entries: Arc<BTreeMap<SignPk, AuthorEntry>>,
    ops: Vec<OpId>,
}

#[derive(Default)]
struct View {
    members: BTreeMap<SignPk, Member>,
    epoch: u64,
    /// Edges we initiated (accepted or pending), and edges peers initiated
    /// to us that we accepted.
    initiated: BTreeSet<SignPk>,
    accepted: BTreeSet<SignPk>,
    /// Neighbours whose edge is lazy (pruned).
    lazy: BTreeSet<SignPk>,
    /// Members that dropped our graft lately (not chosen again this epoch).
    refused: BTreeSet<SignPk>,
    announced: Announced,
    /// Aggregated announcement: due time, changed entries, op tips.
    ihave: Option<PendingIHave>,
    /// Announced heads (and op tips) we don't cover, per announcer.
    missing: BTreeMap<SignPk, Missing>,
    seen: VecDeque<(Arc<Vec<u8>>, HashSet<SignPk>)>,
    seen_known: VecDeque<Hash32>,
    seen_set: HashSet<Hash32>,
    /// Round-robin position for anti-entropy partners.
    rr: usize,
}

/// Aggregated announcement: due time, changed entries, op tips, and the
/// one peer all of it came from, if one did (not announced back to it).
type PendingIHave = (u64, BTreeMap<SignPk, AuthorEntry>, Vec<OpId>, Option<SignPk>);

struct Missing {
    due: u64,
    heads: BTreeSet<EnvelopeId>,
    ops: BTreeSet<OpId>,
}

impl View {
    fn neighbours(&self) -> impl Iterator<Item = &SignPk> {
        self.initiated.iter().chain(self.accepted.iter().filter(|p| !self.initiated.contains(*p)))
    }

    fn is_neighbour(&self, p: &SignPk) -> bool {
        self.initiated.contains(p) || self.accepted.contains(p)
    }

    fn eager(&self, except: Option<SignPk>) -> Vec<SignPk> {
        self.neighbours().filter(|p| !self.lazy.contains(*p) && Some(**p) != except).copied().collect()
    }

    fn lazy_neighbours(&self, except: Option<SignPk>) -> Vec<SignPk> {
        self.neighbours().filter(|p| self.lazy.contains(*p) && Some(**p) != except).copied().collect()
    }

    fn degree(&self) -> usize {
        self.neighbours().count()
    }
}

struct Queued<E> {
    space: SpaceId,
    author: SignPk,
    id: EnvelopeId,
    size: usize,
    item: E,
}

/// One outgoing link: per-author queues, a deficit round-robin over them,
/// and a token bucket for the link's byte rate.
struct Link<E> {
    rate: f64,
    tokens: f64,
    at: u64,
    queues: BTreeMap<SignPk, (VecDeque<Queued<E>>, usize)>,
    order: VecDeque<SignPk>,
    deficit: HashMap<SignPk, i64>,
    skip: HashSet<EnvelopeId>,
    skip_order: VecDeque<EnvelopeId>,
}

impl<E> Link<E> {
    fn new(rate: f64, burst: f64, now: u64) -> Self {
        Link {
            rate,
            tokens: burst,
            at: now,
            queues: BTreeMap::new(),
            order: VecDeque::new(),
            deficit: HashMap::new(),
            skip: HashSet::new(),
            skip_order: VecDeque::new(),
        }
    }

    fn refill(&mut self, now: u64, burst: f64) {
        let dt = now.saturating_sub(self.at) as f64 / 1000.0;
        self.at = now.max(self.at);
        self.tokens = (self.tokens + dt * self.rate).min(burst);
    }

    fn remember_skip(&mut self, id: EnvelopeId) {
        if self.skip.insert(id) {
            self.skip_order.push_back(id);
            if self.skip_order.len() > SKIP_REMEMBERED
                && let Some(old) = self.skip_order.pop_front()
            {
                self.skip.remove(&old);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// The dissemination state of one device, across its spaces.
pub struct Disseminator<O, E> {
    me: SignPk,
    cfg: GossipConfig,
    views: HashMap<SpaceId, View>,
    links: HashMap<SignPk, Link<E>>,
    out: VecDeque<Action<O, E>>,
    stats: GossipStats,
}

impl<O: Clone + Serialize, E: Clone + Serialize + GossipItem> Disseminator<O, E> {
    pub fn new(me: SignPk, cfg: GossipConfig) -> Self {
        Disseminator {
            me,
            cfg,
            views: HashMap::new(),
            links: HashMap::new(),
            out: VecDeque::new(),
            stats: Default::default(),
        }
    }

    pub fn stats(&self) -> GossipStats {
        self.stats
    }

    /// The members of `set`'s space as the driver sees them now (us
    /// excluded or not). The first call starts gossip in the space, from
    /// what the set holds then. Recomputes the edges we initiate when the members, their
    /// reachability or the view epoch changed: new edges are grafted,
    /// dropped ones pruned. Cheap when nothing changed.
    pub fn set_members<S: SyncSet<Op = O, Env = E>>(&mut self, set: &S, members: &[Member], now: u64) {
        let me = self.me;
        let space = set.space();
        // A new view starts from what the set holds now: only later changes
        // are pushed.
        let view = self.views.entry(space).or_insert_with(|| View {
            announced: Announced { entries: set.index().entries(), ops: set.op_tips() },
            ..View::default()
        });
        let fresh: BTreeMap<SignPk, Member> =
            members.iter().filter(|m| m.key != me && m.gossip).map(|m| (m.key, *m)).collect();
        let epoch = now / VIEW_EPOCH_MS;
        // Hysteresis: edges are redrawn only when the member set or the
        // epoch changed, an edge we initiated leads to a member that is
        // unreachable now, or we have fewer than we want while a reachable
        // candidate exists. Reachability flags of other members change
        // often (they follow recent exchanges), and redrawing on each would
        // re-graft pruned edges and undo the tree.
        let same_set = fresh.len() == view.members.len() && fresh.keys().eq(view.members.keys());
        let want = fresh.len().min(if fresh.len() <= FULL_MESH { FULL_MESH } else { LOCAL_EDGES + RANDOM_EDGES });
        let broken = view.initiated.iter().any(|p| fresh.get(p).is_none_or(|m| !m.reachable));
        let short = view.initiated.len() < want
            && fresh.values().any(|m| m.reachable && !view.is_neighbour(&m.key) && !view.refused.contains(&m.key));
        if same_set && epoch == view.epoch && !view.initiated.is_empty() && !broken && !short {
            // (keep the latest flags for path classes and anti-entropy)
            view.members = fresh;
            return;
        }
        if epoch != view.epoch {
            view.refused.clear();
        }
        view.members = fresh;
        view.epoch = epoch;
        // Edges to non-members (removed, or no longer speaking gossip) go.
        view.accepted.retain(|p| view.members.contains_key(p));
        view.lazy.retain(|p| view.members.contains_key(p));
        let chosen = choose(&me, &space, view);
        let old: Vec<SignPk> = view.initiated.iter().copied().collect();
        for p in &old {
            if !chosen.contains(p) {
                view.initiated.remove(p);
                if view.members.contains_key(p) && !view.accepted.contains(p) {
                    self.out.push_back(Action::Send {
                        to: *p,
                        msg: GossipMsg::Prune { space, drop: true, alternatives: Vec::new() },
                    });
                    self.stats.prunes_sent += 1;
                }
            }
        }
        for p in chosen {
            if view.initiated.insert(p) && !view.accepted.contains(&p) {
                self.out.push_back(Action::Send { to: p, msg: GossipMsg::Graft { space } });
                self.stats.grafts_sent += 1;
            }
        }
        let rates: Vec<(SignPk, bool)> = view.members.values().map(|m| (m.key, m.slow)).collect();
        for (p, slow) in rates {
            if let Some(l) = self.links.get_mut(&p) {
                l.rate = if slow { self.cfg.slow_rate } else { self.cfg.fast_rate };
            }
        }
    }

    /// Forget a space (left, or removed).
    pub fn forget_space(&mut self, space: &SpaceId) {
        self.views.remove(space);
        for l in self.links.values_mut() {
            for (q, bytes) in l.queues.values_mut() {
                q.retain(|i| i.space != *space);
                *bytes = q.iter().map(|i| i.size).sum();
            }
            l.queues.retain(|_, (q, _)| !q.is_empty());
            let keep: HashSet<SignPk> = l.queues.keys().copied().collect();
            l.order.retain(|a| keep.contains(a));
        }
    }

    /// Our neighbours in `space`, with whether each edge is eager.
    pub fn neighbours(&self, space: &SpaceId) -> Vec<(SignPk, bool)> {
        self.views.get(space).map_or_else(Vec::new, |v| v.neighbours().map(|p| (*p, !v.lazy.contains(p))).collect())
    }

    /// Does `peer` take part in gossip with us in `space` (a neighbour)?
    pub fn is_neighbour(&self, space: &SpaceId, peer: &SignPk) -> bool {
        self.views.get(space).is_some_and(|v| v.is_neighbour(peer))
    }

    /// Members in `space` that gossip doesn't reach: they get sessions.
    pub fn covers(&self, space: &SpaceId, peer: &SignPk) -> bool {
        self.views.get(space).is_some_and(|v| v.members.contains_key(peer))
    }

    /// The partner for this period's anti-entropy session: round-robin over
    /// neighbours, and with probability 1/4 (`coin` % 4 == 0) a uniformly
    /// chosen reachable member outside them.
    pub fn anti_entropy_partner(&mut self, space: &SpaceId, coin: u64) -> Option<SignPk> {
        let view = self.views.get_mut(space)?;
        let neighbours: Vec<SignPk> = view.neighbours().copied().collect();
        let outside: Vec<SignPk> =
            view.members.values().filter(|m| m.reachable && !view.is_neighbour(&m.key)).map(|m| m.key).collect();
        if (coin.is_multiple_of(4) || neighbours.is_empty()) && !outside.is_empty() {
            return Some(outside[((coin / 4) % outside.len() as u64) as usize]);
        }
        if neighbours.is_empty() {
            return None;
        }
        view.rr = view.rr.wrapping_add(1);
        Some(neighbours[view.rr % neighbours.len()])
    }

    /// The set changed (a local write, or items a push or session brought
    /// from `from`): push what is new since the last announcement to eager
    /// neighbours, and announce it to a few lazy ones. Also settles
    /// announcements the set now covers.
    pub fn on_changed<S: SyncSet<Op = O, Env = E>>(&mut self, set: &S, from: Option<SignPk>, now: u64) {
        let space = set.space();
        let Some(view) = self.views.get_mut(&space) else { return };
        let cur = set.index().entries();
        let ops = set.op_tips();
        // Settle announcements now covered.
        view.missing.retain(|_, m| {
            m.heads.retain(|h| !set.index().holds(h));
            m.ops.retain(|o| !set.holds_op(o));
            !m.heads.is_empty() || !m.ops.is_empty()
        });
        let changed: Vec<&AuthorEntry> =
            cur.values().filter(|e| view.announced.entries.get(&e.author) != Some(*e)).collect();
        let ops_changed = ops != view.announced.ops;
        if changed.is_empty() && !ops_changed {
            return;
        }
        // What is new: per changed author, the seqs above what the last
        // announcement covered on that branch.
        let mut items: Vec<(SignPk, E)> = Vec::new();
        let mut bytes = 0usize;
        let mut fits = true;
        'authors: for e in &changed {
            let old = view.announced.entries.get(&e.author);
            for run in &e.runs {
                let lo = old
                    .and_then(|o| o.runs.iter().find(|r| set.index().is_ancestor(&r.head, &run.head)))
                    .map_or(run.bottom, |r| r.top + 1);
                if run.top < lo {
                    continue;
                }
                if run.top - lo >= MAX_PUSH_ITEMS as u64 || items.len() + (run.top - lo + 1) as usize > MAX_PUSH_ITEMS {
                    fits = false;
                    break 'authors;
                }
                for id in set.index().branch_ids(&run.head, lo, run.top) {
                    let Some(env) = set.env(&id) else { continue };
                    bytes += encoded_len(&env);
                    if bytes > MAX_PUSH_BYTES {
                        fits = false;
                        break 'authors;
                    }
                    items.push((e.author, env));
                }
            }
        }
        let mut new_ops: Vec<O> = Vec::new();
        if ops_changed && fits {
            let base: Vec<OpId> = view.announced.ops.iter().filter(|o| set.holds_op(o)).copied().collect();
            let after = set.ops_after(&base);
            if after.len() > MAX_PUSH_OPS {
                fits = false;
            } else {
                new_ops = after.iter().filter_map(|id| set.op(id)).collect();
                bytes += new_ops.iter().map(encoded_len).sum::<usize>();
                fits = bytes <= MAX_PUSH_BYTES;
            }
        }
        let entries = cap_entries(changed.iter().map(|e| (*e).clone()));
        let eager = view.eager(from);
        if fits {
            for p in &eager {
                if !new_ops.is_empty() {
                    let seen = take_seen(view, p);
                    self.out.push_back(Action::Send {
                        to: *p,
                        msg: GossipMsg::Push {
                            space,
                            ops: new_ops.clone(),
                            items: Vec::new(),
                            entries: Vec::new(),
                            seen,
                        },
                    });
                    self.stats.pushes_sent += 1;
                }
            }
            let (fast, slow, burst) = (self.cfg.fast_rate, self.cfg.slow_rate, self.cfg.burst);
            for p in &eager {
                let slow_link = view.members.get(p).is_some_and(|m| m.slow);
                let link =
                    self.links.entry(*p).or_insert_with(|| Link::new(if slow_link { slow } else { fast }, burst, now));
                for (author, env) in &items {
                    let id = env.gossip_id();
                    if link.skip.contains(&id) {
                        self.stats.skipped_by_have += 1;
                        continue;
                    }
                    let size = encoded_len(env);
                    let (q, qbytes) = link.queues.entry(*author).or_insert_with(|| (VecDeque::new(), 0));
                    if q.is_empty() {
                        link.order.push_back(*author);
                    }
                    q.push_back(Queued { space, author: *author, id, size, item: env.clone() });
                    *qbytes += size;
                    while q.len() > QUEUE_ITEMS || *qbytes > QUEUE_BYTES {
                        if let Some(old) = q.pop_front() {
                            *qbytes -= old.size;
                            self.stats.queue_dropped += 1;
                        }
                    }
                }
            }
        } else {
            // Too much for a push: announce to eager neighbours too (they
            // pull what they lack in a session).
            for p in &eager {
                let seen = take_seen(view, p);
                self.out.push_back(Action::Send {
                    to: *p,
                    msg: GossipMsg::IHave {
                        space,
                        ops: ops.iter().take(MAX_ENTRIES).copied().collect(),
                        entries: entries.clone(),
                        seen,
                    },
                });
                self.stats.ihaves_sent += 1;
            }
        }
        // Lazy announcement, aggregated.
        let due = now + IHAVE_DELAY_MS;
        let agg = view.ihave.get_or_insert_with(|| (due, BTreeMap::new(), Vec::new(), from));
        for e in entries {
            agg.1.insert(e.author, e);
        }
        agg.2 = ops.clone();
        if agg.3 != from {
            agg.3 = None;
        }
        view.announced = Announced { entries: cur, ops };
    }

    /// A message from `from` (whose membership of the message's space the
    /// driver has checked). Returns the items of a `Push` for the driver to
    /// ingest; it then calls [`Self::after_push`].
    pub fn on_msg<S: SyncSet<Op = O, Env = E>>(
        &mut self,
        set: &S,
        from: SignPk,
        msg: GossipMsg<O, E>,
        now: u64,
    ) -> Result<Pushed<O, E>, GossipError> {
        let space = msg.space();
        if space != set.space() {
            return Err(GossipError::WrongSpace);
        }
        let degree_cap = if self.cfg.keeper { KEEPER_DEGREE } else { MAX_DEGREE };
        let Some(view) = self.views.get_mut(&space) else { return Err(GossipError::UnknownSpace) };
        match msg {
            GossipMsg::Push { ops, items, entries, seen, .. } => {
                if ops.len() > MAX_PUSH_OPS || entries.len() > MAX_ENTRIES || seen.len() > SEEN_KEPT {
                    return Err(GossipError::TooLarge);
                }
                // A push from a member that isn't a neighbour yet: it chose
                // us (its graft may still be on the way).
                if !view.is_neighbour(&from) && view.members.contains_key(&from) && view.degree() < degree_cap {
                    view.accepted.insert(from);
                }
                self.stats.items_received += items.len() as u64;
                // IDONTWANT: large new items, before we forward them.
                let large: Vec<EnvelopeId> = items
                    .iter()
                    .filter(|e| !set.index().holds(&e.gossip_id()) && encoded_len(*e) > HAVE_MIN_BYTES)
                    .map(GossipItem::gossip_id)
                    .take(MAX_HAVE_IDS)
                    .collect();
                if !large.is_empty() {
                    for p in view.eager(Some(from)) {
                        self.out.push_back(Action::Send { to: p, msg: GossipMsg::Have { space, ids: large.clone() } });
                        self.stats.haves_sent += 1;
                    }
                }
                Ok(Pushed { ops, envelopes: items, entries, seen, pushed: true })
            }
            GossipMsg::IHave { ops, entries, seen, .. } => {
                if ops.len() > MAX_ENTRIES || entries.len() > MAX_ENTRIES || seen.len() > SEEN_KEPT {
                    return Err(GossipError::TooLarge);
                }
                let heads: BTreeSet<EnvelopeId> = entries
                    .iter()
                    .flat_map(|e| e.runs.iter().map(|r| r.head))
                    .filter(|h| !set.index().holds(h))
                    .collect();
                let missing_ops: BTreeSet<OpId> = ops.iter().filter(|o| !set.holds_op(o)).copied().collect();
                if !heads.is_empty() || !missing_ops.is_empty() {
                    let slow = view.members.get(&from).is_some_and(|m| m.slow);
                    let wait = if slow { IHAVE_WAIT_SLOW_MS } else { IHAVE_WAIT_FAST_MS };
                    let m = view.missing.entry(from).or_insert_with(|| Missing {
                        due: now + wait,
                        heads: BTreeSet::new(),
                        ops: BTreeSet::new(),
                    });
                    if m.heads.len() + heads.len() <= MAX_ENTRIES * 4 {
                        m.heads.extend(heads);
                    }
                    if m.ops.len() + missing_ops.len() <= MAX_ENTRIES {
                        m.ops.extend(missing_ops);
                    }
                }
                Ok(Pushed { ops: Vec::new(), envelopes: Vec::new(), entries, seen, pushed: false })
            }
            GossipMsg::Have { ids, .. } => {
                if ids.len() > MAX_HAVE_IDS {
                    return Err(GossipError::TooLarge);
                }
                if let Some(link) = self.links.get_mut(&from) {
                    let ids: HashSet<EnvelopeId> = ids.into_iter().collect();
                    for id in &ids {
                        link.remember_skip(*id);
                    }
                    let mut skipped = 0;
                    for (q, bytes) in link.queues.values_mut() {
                        q.retain(|i| {
                            let keep = !ids.contains(&i.id);
                            if !keep {
                                *bytes -= i.size;
                                skipped += 1;
                            }
                            keep
                        });
                    }
                    self.stats.skipped_by_have += skipped;
                } else {
                    let (fast, burst) = (self.cfg.fast_rate, self.cfg.burst);
                    let link = self.links.entry(from).or_insert_with(|| Link::new(fast, burst, now));
                    for id in ids {
                        link.remember_skip(id);
                    }
                }
                Ok(Pushed::default())
            }
            GossipMsg::Graft { .. } => {
                if !view.members.contains_key(&from) {
                    return Ok(Pushed::default());
                }
                if view.is_neighbour(&from) || view.degree() < degree_cap {
                    view.accepted.insert(from);
                    view.lazy.remove(&from);
                } else {
                    let alternatives: Vec<SignPk> =
                        view.neighbours().filter(|p| **p != from).take(MAX_ALTERNATIVES).copied().collect();
                    self.out.push_back(Action::Send {
                        to: from,
                        msg: GossipMsg::Prune { space, drop: true, alternatives },
                    });
                    self.stats.prunes_sent += 1;
                }
                Ok(Pushed::default())
            }
            GossipMsg::Prune { drop, alternatives, .. } => {
                if alternatives.len() > MAX_ALTERNATIVES {
                    return Err(GossipError::TooLarge);
                }
                if drop {
                    view.accepted.remove(&from);
                    if view.initiated.remove(&from) {
                        view.refused.insert(from);
                        // Replace the edge: an alternative it named, else the next by rank.
                        let pick = alternatives
                            .iter()
                            .find(|a| {
                                **a != self.me
                                    && view.members.contains_key(*a)
                                    && !view.is_neighbour(a)
                                    && !view.refused.contains(*a)
                            })
                            .copied()
                            .or_else(|| choose(&self.me, &space, view).into_iter().find(|p| !view.is_neighbour(p)));
                        if let Some(p) = pick {
                            view.initiated.insert(p);
                            self.out.push_back(Action::Send { to: p, msg: GossipMsg::Graft { space } });
                            self.stats.grafts_sent += 1;
                        }
                    }
                    view.lazy.remove(&from);
                } else if view.is_neighbour(&from) {
                    view.lazy.insert(from);
                }
                Ok(Pushed::default())
            }
        }
    }

    /// The driver ingested a push from `from`: `new` of its items were new
    /// to the set. Nothing new prunes the edge to lazy (Plumtree); something
    /// new is forwarded ([`Self::on_changed`]).
    pub fn after_push<S: SyncSet<Op = O, Env = E>>(&mut self, set: &S, from: SignPk, items: usize, new: u64, now: u64) {
        let space = set.space();
        if new == 0 {
            if items > 0 {
                self.stats.duplicates += items as u64;
                if let Some(view) = self.views.get_mut(&space)
                    && view.is_neighbour(&from)
                    && view.lazy.insert(from)
                {
                    self.out.push_back(Action::Send {
                        to: from,
                        msg: GossipMsg::Prune { space, drop: false, alternatives: Vec::new() },
                    });
                    self.stats.prunes_sent += 1;
                }
            }
            return;
        }
        self.stats.duplicates += (items as u64).saturating_sub(new);
        self.on_changed(set, Some(from), now);
    }

    /// Ask for a session with `peer` in `space` now (a push the set
    /// couldn't admit: its author's `Add` hasn't arrived).
    pub fn pull(&mut self, peer: SignPk, space: SpaceId) {
        self.out.push_back(Action::Pull { peer, space });
        self.stats.pulls += 1;
    }

    /// A send to `peer` failed (path down): drop what is queued to it and
    /// make its edges lazy, so the next view recomputation replaces it.
    pub fn path_down(&mut self, peer: &SignPk) {
        self.links.remove(peer);
        for v in self.views.values_mut() {
            if let Some(m) = v.members.get_mut(peer) {
                m.reachable = false;
            }
            if v.is_neighbour(peer) {
                v.lazy.insert(*peer);
            }
        }
    }

    /// A validated seen note to carry (ours, or one received and checked
    /// by the driver): attached to later messages to each neighbour once.
    /// Returns false if it was known already.
    pub fn carry_seen(&mut self, space: &SpaceId, note: Vec<u8>) -> bool {
        let Some(view) = self.views.get_mut(space) else { return false };
        if note.len() > MAX_SEEN_NOTE {
            return false;
        }
        let h = Hash32::digest("mycel/v2/seen-id", &note);
        if !view.seen_set.insert(h) {
            return false;
        }
        view.seen_known.push_back(h);
        if view.seen_known.len() > SEEN_REMEMBERED
            && let Some(old) = view.seen_known.pop_front()
        {
            view.seen_set.remove(&old);
        }
        view.seen.push_front((Arc::new(note), HashSet::new()));
        view.seen.truncate(SEEN_KEPT);
        true
    }

    /// When [`Self::poll`] has something next (ms), if it is waiting on a
    /// timer or a link's rate.
    pub fn next_deadline(&self) -> Option<u64> {
        let views = self
            .views
            .values()
            .flat_map(|v| v.ihave.as_ref().map(|i| i.0).into_iter().chain(v.missing.values().map(|m| m.due)));
        let links = self.links.values().filter(|l| !l.is_empty()).map(|l| {
            let need = (1.0 - l.tokens).max(0.0);
            l.at + (need / l.rate * 1000.0).ceil() as u64
        });
        views.chain(links).min()
    }

    /// The next thing to do at `now`, if any.
    pub fn poll(&mut self, now: u64) -> Option<Action<O, E>> {
        if let Some(a) = self.out.pop_front() {
            return Some(a);
        }
        self.fire_timers(now);
        if let Some(a) = self.out.pop_front() {
            return Some(a);
        }
        self.drain_links(now);
        self.out.pop_front()
    }

    fn fire_timers(&mut self, now: u64) {
        let mut rng_seed = now;
        for (space, view) in self.views.iter_mut() {
            if let Some((due, ..)) = &view.ihave
                && *due <= now
                && let Some((_, entries, ops, from)) = view.ihave.take()
            {
                let mut lazy = view.lazy_neighbours(from);
                // A few lazy neighbours, not all of them.
                rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let k = lazy.len();
                if k > IHAVE_FANOUT {
                    let start = (rng_seed >> 33) as usize % k;
                    lazy.rotate_left(start);
                    lazy.truncate(IHAVE_FANOUT);
                }
                let entries = cap_entries(entries.into_values());
                for p in lazy {
                    let seen = take_seen(view, &p);
                    self.out.push_back(Action::Send {
                        to: p,
                        msg: GossipMsg::IHave { space: *space, ops: ops.clone(), entries: entries.clone(), seen },
                    });
                    self.stats.ihaves_sent += 1;
                }
            }
            let due: Vec<SignPk> = view.missing.iter().filter(|(_, m)| m.due <= now).map(|(p, _)| *p).collect();
            for p in due {
                view.missing.remove(&p);
                // The tree missed it: make the edge eager and pull now.
                if view.is_neighbour(&p) && view.lazy.remove(&p) {
                    self.out.push_back(Action::Send { to: p, msg: GossipMsg::Graft { space: *space } });
                    self.stats.grafts_sent += 1;
                }
                self.out.push_back(Action::Pull { peer: p, space: *space });
                self.stats.pulls += 1;
            }
        }
    }

    /// Compose at most one push per link whose rate allows it, taking items
    /// across authors by deficit round-robin.
    fn drain_links(&mut self, now: u64) {
        let burst = self.cfg.burst;
        let mut sends = Vec::new();
        for (peer, link) in self.links.iter_mut() {
            if link.is_empty() {
                continue;
            }
            link.refill(now, burst);
            if link.tokens < 1.0 {
                continue;
            }
            let mut budget = (link.tokens as usize).min(MAX_PUSH_BYTES);
            let mut batch: Vec<Queued<E>> = Vec::new();
            let mut space: Option<SpaceId> = None;
            let mut rounds = 0;
            while !link.order.is_empty() && rounds < 4 * link.order.len() + 4 {
                rounds += 1;
                let Some(author) = link.order.pop_front() else { break };
                let d = link.deficit.entry(author).or_insert(0);
                *d += QUANTUM;
                let Some((q, qbytes)) = link.queues.get_mut(&author) else { continue };
                while let Some(front) = q.front() {
                    let fits_frame = batch.is_empty() || front.size <= budget;
                    let same_space = space.is_none_or(|s| s == front.space);
                    if (front.size as i64) > *d || !fits_frame || !same_space {
                        break;
                    }
                    let item = q.pop_front().expect("front exists");
                    *d -= item.size as i64;
                    *qbytes -= item.size;
                    budget = budget.saturating_sub(item.size);
                    space = Some(item.space);
                    batch.push(item);
                }
                if q.is_empty() {
                    link.queues.remove(&author);
                    link.deficit.remove(&author);
                } else {
                    link.order.push_back(author);
                }
                if budget == 0 {
                    break;
                }
            }
            if batch.is_empty() {
                continue;
            }
            let bytes: usize = batch.iter().map(|i| i.size).sum();
            link.tokens -= bytes as f64;
            sends.push((*peer, space.expect("a non-empty batch has a space"), batch, bytes));
        }
        for (peer, space, batch, bytes) in sends {
            let authors: BTreeSet<SignPk> = batch.iter().map(|i| i.author).collect();
            let items: Vec<E> = batch.into_iter().map(|i| i.item).collect();
            let (entries, seen) = match self.views.get_mut(&space) {
                // What we hold of those authors: the receiver learns we hold
                // at least this (delivery state).
                Some(view) => (
                    cap_entries(authors.iter().filter_map(|a| view.announced.entries.get(a).cloned())),
                    take_seen(view, &peer),
                ),
                None => (Vec::new(), Vec::new()),
            };
            self.stats.pushes_sent += 1;
            self.stats.push_items_sent += items.len() as u64;
            self.stats.push_bytes_sent += bytes as u64;
            self.out.push_back(Action::Send {
                to: peer,
                msg: GossipMsg::Push { space, ops: Vec::new(), items, entries, seen },
            });
        }
    }
}

/// The items of a received `Push` for the driver to ingest, the sender's
/// frontier entries (what it holds: delivery state), and seen notes for
/// the driver to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pushed<O, E> {
    pub ops: Vec<O>,
    pub envelopes: Vec<E>,
    pub entries: Vec<AuthorEntry>,
    pub seen: Vec<Vec<u8>>,
    /// It was a `Push` (call [`Disseminator::after_push`]).
    pub pushed: bool,
}

impl<O, E> Default for Pushed<O, E> {
    fn default() -> Self {
        Pushed { ops: Vec::new(), envelopes: Vec::new(), entries: Vec::new(), seen: Vec::new(), pushed: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipError {
    WrongSpace,
    UnknownSpace,
    TooLarge,
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GossipError::WrongSpace => "gossip for another space",
            GossipError::UnknownSpace => "gossip for a space we don't gossip in",
            GossipError::TooLarge => "gossip message over its limits",
        })
    }
}

impl std::error::Error for GossipError {}

/// At most [`MAX_ENTRIES`] entries and [`ENTRIES_BYTES`] of them.
fn cap_entries(entries: impl Iterator<Item = AuthorEntry>) -> Vec<AuthorEntry> {
    let mut bytes = 0;
    entries
        .take(MAX_ENTRIES)
        .take_while(|e| {
            bytes += encoded_len(e);
            bytes <= ENTRIES_BYTES
        })
        .collect()
}

/// Seen notes for one message to `peer`: newest first, each once per peer,
/// at most [`SEEN_BYTES_PER_MSG`] in all.
fn take_seen(view: &mut View, peer: &SignPk) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = 0;
    for (note, sent) in view.seen.iter_mut() {
        if sent.contains(peer) {
            continue;
        }
        if bytes + note.len() > SEEN_BYTES_PER_MSG {
            break;
        }
        bytes += note.len();
        sent.insert(*peer);
        out.push((**note).clone());
    }
    out
}

/// The edges to initiate: every member in a small group; otherwise the
/// best-placed reachable members and members picked by rendezvous hash
/// (both skipping members that refused us this epoch).
fn choose(me: &SignPk, space: &SpaceId, view: &View) -> Vec<SignPk> {
    let members: Vec<&Member> = view.members.values().collect();
    if members.len() <= FULL_MESH {
        return members.iter().map(|m| m.key).collect();
    }
    let epoch = view.epoch.to_le_bytes();
    let rank = |p: &SignPk| Hash32::digest(CTX_VIEW, &[&space.0[..], &me.0, &p.0, &epoch].concat());
    let mut ranked: Vec<(Hash32, &Member)> = members.iter().map(|m| (rank(&m.key), *m)).collect();
    ranked.sort_by_key(|(h, _)| *h);
    let usable = |m: &Member| m.reachable && !view.refused.contains(&m.key);
    let mut local: Vec<&(Hash32, &Member)> =
        ranked.iter().filter(|(_, m)| usable(m) && m.class <= PathClass::Internet).collect();
    local.sort_by_key(|(h, m)| (m.class, *h));
    let mut out: Vec<SignPk> = local.iter().take(LOCAL_EDGES).map(|(_, m)| m.key).collect();
    // Random edges: by rendezvous rank over the whole member list, skipping
    // members that are unreachable now (the next by rank takes their place).
    for (_, m) in &ranked {
        if out.len() >= LOCAL_EDGES + RANDOM_EDGES {
            break;
        }
        if usable(m) && !out.contains(&m.key) {
            out.push(m.key);
        }
    }
    // Too few reachable: fall back to unreachable members by rank (an
    // offline device still needs edges once it comes back).
    for (_, m) in &ranked {
        if out.len() >= LOCAL_EDGES + RANDOM_EDGES {
            break;
        }
        if !view.refused.contains(&m.key) && !out.contains(&m.key) {
            out.push(m.key);
        }
    }
    out
}
