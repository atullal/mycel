//! Mycel network layer v0 (docs/TRUST.md §8): Space sync over Iroh.
//!
//! The device's Ed25519 key *is* its Iroh endpoint id, so every QUIC
//! connection is already authenticated to a device. On top of that, both
//! sides refuse to sync a Space with anyone who isn't currently a member of it
//! (any role, including Relay keepers), and everything received is
//! re-validated by the receiving `Replica` — nothing is trusted because of
//! who sent it.
//!
//! Wire protocol (ALPN `mycel/sync/0`), one bi-stream, strictly alternating so
//! neither side can deadlock on flow control:
//!
//! ```text
//! C → S  Hello{space} + Inventory(C)
//! S → C  Denied | Inventory(S) + Want(S)
//! C → S  Data(for S) + Want(C)
//! S → C  Data(for C)
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr, PublicKey, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use mycel_crypto::{DeviceKeys, SignPk};
use mycel_sync::{Envelope, EnvelopeId, Replica};
use mycel_trust::{OpId, SignedOp, SpaceId};
use serde::{Deserialize, Serialize};

pub use iroh;

pub const ALPN: &[u8] = b"mycel/sync/0";
const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct Inventory {
    ops: Vec<OpId>,
    envelopes: Vec<EnvelopeId>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Data {
    ops: Vec<SignedOp>,
    envelopes: Vec<Envelope>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Msg {
    Hello { space: SpaceId, inv: Inventory },
    Denied,
    Accept { inv: Inventory, want: Inventory },
    DataAndWant { data: Data, want: Inventory },
    Data { data: Data },
}

async fn send(s: &mut SendStream, msg: &Msg) -> Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    s.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    s.write_all(&bytes).await?;
    Ok(())
}

async fn recv(r: &mut RecvStream) -> Result<Msg> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

fn to_sign_pk(pk: &PublicKey) -> SignPk {
    SignPk(*pk.as_bytes())
}

/// What one sync session transferred (counts of items *received*).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    pub ops: usize,
    pub envelopes: usize,
}

type Spaces = Arc<Mutex<HashMap<SpaceId, Replica>>>;

fn inventory(r: &Replica) -> Inventory {
    Inventory {
        ops: r.op_ids(),
        envelopes: r.envelope_ids(),
    }
}

fn missing(r: &Replica, theirs: &Inventory) -> Inventory {
    let ops: HashSet<OpId> = r.op_ids().into_iter().collect();
    let envs: HashSet<EnvelopeId> = r.envelope_ids().into_iter().collect();
    Inventory {
        ops: theirs.ops.iter().filter(|i| !ops.contains(i)).copied().collect(),
        envelopes: theirs
            .envelopes
            .iter()
            .filter(|i| !envs.contains(i))
            .copied()
            .collect(),
    }
}

fn gather(r: &Replica, want: &Inventory) -> Data {
    Data {
        ops: want.ops.iter().filter_map(|i| r.op(i).cloned()).collect(),
        envelopes: want
            .envelopes
            .iter()
            .filter_map(|i| r.envelope(i).cloned())
            .collect(),
    }
}

/// Ingest ops first (envelopes are validated against membership), ignoring
/// individually bad items: one malformed item must not poison the batch.
fn ingest(r: &mut Replica, data: Data) -> SyncStats {
    let mut stats = SyncStats::default();
    for op in data.ops {
        if r.ingest_op(op).unwrap_or(false) {
            stats.ops += 1;
        }
    }
    for env in data.envelopes {
        if r.ingest_envelope(env).unwrap_or(false) {
            stats.envelopes += 1;
        }
    }
    stats
}

#[derive(Clone)]
struct SyncHandler {
    spaces: Spaces,
}

impl std::fmt::Debug for SyncHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncHandler")
    }
}

impl SyncHandler {
    async fn serve(&self, conn: Connection) -> Result<()> {
        let peer = to_sign_pk(&conn.remote_id());
        let (mut tx, mut rx) = conn.accept_bi().await?;
        let Msg::Hello { space, inv } = recv(&mut rx).await? else {
            bail!("expected Hello");
        };
        // Membership gate: only current members (any role) may sync.
        let reply = {
            let spaces = self.spaces.lock().unwrap();
            match spaces.get(&space) {
                Some(r) if r.is_member(&peer) => Some(Msg::Accept {
                    inv: inventory(r),
                    want: missing(r, &inv),
                }),
                _ => None,
            }
        };
        let Some(reply) = reply else {
            send(&mut tx, &Msg::Denied).await?;
            tx.finish()?;
            conn.closed().await;
            return Ok(());
        };
        send(&mut tx, &reply).await?;
        let Msg::DataAndWant { data, want } = recv(&mut rx).await? else {
            bail!("expected DataAndWant");
        };
        let out = {
            let mut spaces = self.spaces.lock().unwrap();
            let r = spaces.get_mut(&space).context("space vanished")?;
            ingest(r, data);
            gather(r, &want)
        };
        send(&mut tx, &Msg::Data { data: out }).await?;
        tx.finish()?;
        conn.closed().await;
        Ok(())
    }
}

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        self.serve(conn)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// How the endpoint reaches the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    /// Direct addresses only, no relays or discovery (tests, LAN demos).
    Local,
    /// n0 preset: public relays + DNS discovery + hole punching.
    Internet,
}

/// A running Mycel device: identity, Iroh endpoint and its Space replicas.
pub struct Node {
    keys: Arc<DeviceKeys>,
    router: Router,
    spaces: Spaces,
}

impl Node {
    pub async fn spawn(keys: Arc<DeviceKeys>, mode: NetMode) -> Result<Self> {
        // Same Ed25519 key for transport and for Mycel signatures (domain-separated).
        let secret = SecretKey::from_bytes(&keys.seed());
        debug_assert_eq!(secret.public().as_bytes(), &keys.sign_pk().0);
        let builder = match mode {
            NetMode::Local => Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind_addr("127.0.0.1:0")?,
            NetMode::Internet => Endpoint::builder(presets::N0),
        };
        let endpoint = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let spaces: Spaces = Arc::default();
        let router = Router::builder(endpoint)
            .accept(
                ALPN,
                SyncHandler {
                    spaces: spaces.clone(),
                },
            )
            .spawn();
        Ok(Node {
            keys,
            router,
            spaces,
        })
    }

    pub fn keys(&self) -> &Arc<DeviceKeys> {
        &self.keys
    }

    pub fn id(&self) -> SignPk {
        self.keys.sign_pk()
    }

    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }

    /// Found a new Space; returns its id and the genesis op (part of invites).
    pub fn create_space(&self) -> Result<(SpaceId, SignedOp)> {
        let (r, genesis) = Replica::create(self.keys.clone())?;
        let id = r.space_id();
        self.spaces.lock().unwrap().insert(id, r);
        Ok((id, genesis))
    }

    pub fn join_space(&self, genesis: SignedOp) -> Result<SpaceId> {
        let r = Replica::join(self.keys.clone(), genesis)?;
        let id = r.space_id();
        self.spaces.lock().unwrap().entry(id).or_insert(r);
        Ok(id)
    }

    /// Run `f` against a Space replica (no await inside: the lock is sync).
    pub fn with_space<R>(&self, space: &SpaceId, f: impl FnOnce(&mut Replica) -> R) -> Result<R> {
        let mut spaces = self.spaces.lock().unwrap();
        let r = spaces.get_mut(space).ok_or_else(|| anyhow!("unknown space"))?;
        Ok(f(r))
    }

    /// One full bidirectional sync of `space` with `peer`.
    ///
    /// `trust_peer` lets a freshly-invited device sync with its inviter before
    /// it has learned (via that very sync) that the inviter is a member.
    pub async fn sync_with(
        &self,
        peer: EndpointAddr,
        space: SpaceId,
        trust_peer: bool,
    ) -> Result<SyncStats> {
        let peer_pk = to_sign_pk(&peer.id);
        let hello = self.with_space(&space, |r| {
            (trust_peer || r.is_member(&peer_pk)).then(|| Msg::Hello {
                space,
                inv: inventory(r),
            })
        })?;
        let hello = hello.ok_or_else(|| anyhow!("peer is not a member of this space"))?;
        let conn = self.router.endpoint().connect(peer, ALPN).await?;
        let (mut tx, mut rx) = conn.open_bi().await?;
        send(&mut tx, &hello).await?;
        let (their_inv, their_want) = match recv(&mut rx).await? {
            Msg::Accept { inv, want } => (inv, want),
            Msg::Denied => bail!("peer denied sync (we are not a member)"),
            _ => bail!("unexpected reply"),
        };
        let reply = self.with_space(&space, |r| Msg::DataAndWant {
            data: gather(r, &their_want),
            want: missing(r, &their_inv),
        })?;
        send(&mut tx, &reply).await?;
        tx.finish()?;
        let Msg::Data { data } = recv(&mut rx).await? else {
            bail!("expected Data");
        };
        let stats = self.with_space(&space, |r| ingest(r, data))?;
        conn.close(0u32.into(), b"done");
        Ok(stats)
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}
