//! Dissemination over the node protocol (Sync v2 stage 3): the driver for
//! `mycel_sync::reconcile::gossip` on [`StreamKind::Gossip`] uni-streams,
//! one message per stream.
//!
//! The [`Disseminator`] is sans-IO; this file feeds it the space's members
//! as the node sees them (reachability, path class, whether the peer's
//! capability hello agreed [`Caps::GOSSIP`]), every change of a replica
//! (a local write, what a session, push or bundle brought), and every
//! message from a member, and carries out what it asks: sends (in order per
//! peer, on the pooled connection) and pulls (a Sync v2 session).
//! Members gossip doesn't reach (builds without it, peers whose hello
//! hasn't been seen yet) keep getting sessions after a change, as before.
//!
//! Lock order: a replica (`spaces`) before the disseminator, never the
//! other way round; neither is held across an await.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use iroh::endpoint::RecvStream;
use mycel_crypto::SignPk;
use mycel_sync::reconcile::gossip::{Action, Disseminator, GossipMsg, MAX_GOSSIP_FRAME, Member, PathClass};
use mycel_sync::reconcile::{self, SyncSet};
use mycel_sync::{Envelope, EnvelopeId, Replica};
use mycel_trust::{SignedOp, SpaceId};
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

use crate::link::PathKind;
use crate::wire::{StreamKind, recv_bounded, send_len};
use crate::{Caps, Inner, NetEvent, PeerState, Trigger, on_conn, pooled, resources, sync_once};

pub(crate) type GMsg = GossipMsg<SignedOp, Envelope>;

/// Messages queued per peer before the oldest are dropped (gossip is
/// repaired by announcements and anti-entropy, so a slow peer can't make
/// us buffer without bound).
const PEER_QUEUE: usize = 256;

/// What the node keeps for gossip.
pub(crate) struct Gossip {
    pub(crate) d: Mutex<Disseminator<SignedOp, Envelope>>,
    pub(crate) wake: Notify,
    start: Instant,
    senders: Mutex<HashMap<SignPk, mpsc::Sender<GMsg>>>,
    totals: Mutex<GossipTotals>,
}

/// Counters for tests and diagnostics (bytes are frames on gossip streams).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GossipTotals {
    pub sent_msgs: u64,
    pub sent_bytes: u64,
    pub recv_msgs: u64,
    pub recv_bytes: u64,
    /// Items received by push that were new, and pulls (sessions) started.
    pub items_new: u64,
    pub pulls: u64,
    pub send_failures: u64,
}

impl Gossip {
    pub(crate) fn new(me: SignPk, keeper: bool) -> Self {
        let cfg = reconcile::gossip::GossipConfig { keeper, ..Default::default() };
        Gossip {
            d: Mutex::new(Disseminator::new(me, cfg)),
            wake: Notify::new(),
            start: Instant::now(),
            senders: Mutex::new(HashMap::new()),
            totals: Mutex::new(GossipTotals::default()),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub(crate) fn totals(&self) -> GossipTotals {
        *self.totals.lock()
    }

    pub(crate) fn stats(&self) -> reconcile::gossip::GossipStats {
        self.d.lock().stats()
    }
}

/// How the node sees a member now, for the view.
pub(crate) fn member(key: SignPk, state: Option<&PeerState>, gossip: bool) -> Member {
    let Some(s) = state else {
        return Member { key, class: PathClass::Internet, reachable: false, gossip, slow: false };
    };
    let class = if s.is_directly_discovered() {
        PathClass::Direct
    } else if s.via == Some(PathKind::Mesh) || s.mesh.is_some() {
        PathClass::Mesh
    } else {
        PathClass::Internet
    };
    let slow = matches!(s.via, Some(PathKind::Bluetooth | PathKind::Mesh));
    Member { key, class, reachable: s.online() && !s.backing_off(), gossip, slow }
}

impl Inner {
    /// Gossip is on (Sync v2 is, and we advertise [`Caps::GOSSIP`]).
    pub(crate) fn gossip_on(&self) -> bool {
        self.sync_v2 && self.protocol.caps.contains(Caps::GOSSIP)
    }

    /// Refresh the gossip view of `space` from the replica and peer states.
    pub(crate) fn gossip_view(&self, r: &Replica, peers: &HashMap<SignPk, PeerState>) {
        if !self.gossip_on() || r.my_role().is_none() {
            return;
        }
        let me = self.keys.sign_pk();
        let members: Vec<Member> = r
            .members()
            .into_iter()
            .map(|(k, _)| k.sign_pk)
            .filter(|p| *p != me)
            .map(|p| {
                let state = peers.get(&p);
                let gossip = state.and_then(|s| s.protocol).is_some_and(|pr| pr.supports(Caps::GOSSIP))
                    && !self.v2.is_v1_only(&p);
                member(p, state, gossip)
            })
            .collect();
        let now = self.gossip.now();
        self.gossip.d.lock().set_members(r, &members, now);
        self.gossip.wake.notify_one();
    }

    /// `space` changed (`from`: the peer whose push, session or bundle
    /// brought it; `None`: a local write). Pushes what is new.
    pub(crate) fn gossip_changed(&self, space: &SpaceId, from: Option<SignPk>) {
        if !self.gossip_on() {
            return;
        }
        let now = self.gossip.now();
        let _ = self.with_space(space, |r| self.gossip.d.lock().on_changed(r, from, now));
        self.gossip.wake.notify_one();
    }

    /// Does gossip reach `peer` in `space` (so a change needs no session)?
    pub(crate) fn gossip_covers(&self, space: &SpaceId, peer: &SignPk) -> bool {
        self.gossip_on() && self.gossip.d.lock().covers(space, peer)
    }
}

/// Carry out what the disseminator asks, as it asks it.
pub(crate) async fn pump(inner: Arc<Inner>) {
    loop {
        let actions: Vec<Action<SignedOp, Envelope>> = {
            let now = inner.gossip.now();
            let mut d = inner.gossip.d.lock();
            std::iter::from_fn(|| d.poll(now)).take(4096).collect()
        };
        for a in actions {
            match a {
                Action::Send { to, msg } => send(&inner, to, msg),
                Action::Pull { peer, space } => {
                    inner.gossip.totals.lock().pulls += 1;
                    tokio::spawn(sync_once(inner.clone(), peer, space, Trigger::Change));
                }
            }
        }
        let wait = {
            let next = inner.gossip.d.lock().next_deadline();
            let now = inner.gossip.now();
            next.map_or(Duration::from_secs(5), |t| Duration::from_millis(t.saturating_sub(now).clamp(1, 5000)))
        };
        tokio::select! {
            _ = inner.gossip.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// Queue `msg` to `peer`; one task per peer sends in order.
fn send(inner: &Arc<Inner>, peer: SignPk, msg: GMsg) {
    let mut senders = inner.gossip.senders.lock();
    let tx = senders.entry(peer).or_insert_with(|| {
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        tokio::spawn(sender(inner.clone(), peer, rx));
        tx
    });
    if tx.try_send(msg).is_err() {
        // Full (a stalled peer) or its task ended: start over next time.
        senders.remove(&peer);
    }
}

async fn sender(inner: Arc<Inner>, peer: SignPk, mut rx: mpsc::Receiver<GMsg>) {
    while let Some(msg) = rx.recv().await {
        let res = on_conn!(&inner, &peer, |conn| async {
            let mut tx = resources::within(resources::REPLY_TIMEOUT, "no stream", conn.open_uni()).await?;
            tx.set_priority(StreamKind::Gossip.priority()).ok();
            resources::write_all(&mut tx, &[StreamKind::Gossip as u8]).await?;
            let n = send_len(&mut tx, &msg).await?;
            tx.finish()?;
            anyhow::Ok(n)
        });
        match res {
            Ok(n) => {
                let mut t = inner.gossip.totals.lock();
                t.sent_msgs += 1;
                t.sent_bytes += n as u64 + 1;
            }
            Err(_) => {
                inner.gossip.totals.lock().send_failures += 1;
                inner.gossip.d.lock().path_down(&peer);
                inner.gossip.senders.lock().remove(&peer);
                return;
            }
        }
    }
}

/// A gossip message from `peer`, on its own uni-stream.
pub(crate) async fn serve(inner: &Arc<Inner>, peer: SignPk, mut rx: RecvStream) -> Result<()> {
    if !inner.gossip_on() {
        bail!("gossip is off");
    }
    let (msg, _permit) =
        recv_bounded::<GMsg>(&mut rx, resources::FIRST_FRAME, MAX_GOSSIP_FRAME, &inner.frames(&peer)).await?;
    let n = reconcile::frame_len(&msg) as u64;
    {
        let mut t = inner.gossip.totals.lock();
        t.recv_msgs += 1;
        t.recv_bytes += n + 1;
    }
    let space = msg.space();
    let now = inner.gossip.now();
    let res = inner.with_space(&space, |r| {
        if !r.is_member(&peer) {
            bail!("gossip from a non-member");
        }
        let pushed = inner.gossip.d.lock().on_msg(r, peer, msg, now)?;
        // What the sender holds: delivery state (design §10).
        r.note_frontier(peer, &pushed.entries);
        let mut changed = None;
        if pushed.pushed {
            let items = pushed.envelopes.len();
            let ids: Vec<EnvelopeId> = pushed.envelopes.iter().map(|e| e.id()).collect();
            let fresh_ids: Vec<EnvelopeId> = ids.iter().filter(|id| !r.index().holds(id)).copied().collect();
            let fresh_ops: Vec<_> = pushed.ops.iter().map(|o| o.id()).filter(|id| !r.holds_op(id)).collect();
            let (res, _refused) = r.ingest_batch_refused(pushed.ops, pushed.envelopes);
            let new = reconcile::gained(r, &fresh_ops, &fresh_ids);
            // The sender holds what it pushed.
            r.note_holder(peer, &ids);
            let mut d = inner.gossip.d.lock();
            d.after_push(r, peer, items, new, now);
            // Items we couldn't admit (an author whose `Add` hasn't reached
            // us, or beyond the chain window): a session with the pusher
            // brings ops first, then the chains in order.
            if fresh_ids.iter().any(|id| !r.index().holds(id)) {
                d.pull(peer, space);
            }
            changed = Some((res, new));
        }
        // Seen notes that check out are carried on (each once per neighbour).
        for note in pushed.seen {
            if r.accept_seen(&peer, &note).is_some() {
                inner.gossip.d.lock().carry_seen(&space, note);
            }
        }
        anyhow::Ok(changed)
    })??;
    inner.gossip.wake.notify_one();
    if let Some((res, new)) = res {
        inner.mark_ok(peer);
        if res.changed() || new > 0 {
            inner.gossip.totals.lock().items_new += new;
            inner.emit(NetEvent::SpaceChanged { space });
            if res.ops > 0 {
                inner.loss_signal(space);
            }
            // Members gossip doesn't reach still need sessions.
            inner.schedule(space);
        }
    }
    Ok(())
}

/// Keep the senders map from growing with peers we no longer talk to.
pub(crate) fn reap(inner: &Inner) {
    inner.gossip.senders.lock().retain(|_, tx| !tx.is_closed());
}
