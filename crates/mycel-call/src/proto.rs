//! Call signalling (ALPNs `mycel/call/2` and `mycel/call/1`, see
//! [`ALPNS_CALL`]).
//!
//! A call is a full mesh: every participant has one QUIC connection (a
//! "leg") to every other participant, dialed straight to their device key.
//! A call therefore only needs the devices online (no server), and it
//! inherits the node's multipath paths (network, peer-to-peer Wi-Fi, relay,
//! Bluetooth). A 1:1 call is the two-person case.
//!
//! Each leg has one bidirectional control stream, opened by the dialer and
//! carrying small length-prefixed postcard messages ([`Ctrl`]). Its first
//! message says why the leg exists:
//!
//! ```text
//! Ring: the initiator rings a member      Join: a participant connects to
//!                                         another one already in the call
//! dialer                member            joiner                participant
//!   Ring{call, group} ──▶ checks the call   Join{call} ─────────▶ in that call?
//!            ◀── Ringing | Busy | Glare |              ◀── Started | Full |
//!                Existing | Denied                         Glare | Denied
//!            ◀── Accept | Decline{missed}  (media flows both ways)
//!   Started ──▶ (media flows both ways)
//!
//! Watch: someone who declined or missed a group call keeps hearing who is
//! in it, through one participant, so they can join later:
//!   Watch{call} ──▶   ◀── Roster ...    later: Accept ──▶  ◀── Started
//!
//! On any leg, at any time: Roster{joined} · Mute · Report · HangUp
//! ```
//!
//! A [`CallRef`] names a call: its conversation (space), its initiator, a
//! random nonce, and the call id derived from those three. The receiving
//! side checks:
//! - the id;
//! - that the dialer (the QUIC-authenticated peer) is a current member of
//!   the conversation;
//! - for `Ring`, that the dialer is the initiator.
//!
//! A device takes `Join` and `Watch` only for a call it is in itself.
//!
//! Who dials whom:
//! - The initiator rings every member.
//! - Whoever joins dials `Join` to everyone in the roster it has no leg to.
//! - When two joiners dial each other at once, the leg dialed by the lower
//!   key survives; the other side answers `Glare`.
//!
//! Everyone in the call sends `Roster` on all its legs whenever its set of
//! joined peers changes. That is how newcomers, ringing members and watchers
//! all learn who is in the call.
//!
//! Media is Opus in QUIC datagrams on each leg ([`crate::frame`]), or on a
//! unidirectional stream when a path can't carry datagrams. Every datagram
//! and media stream starts with a one-byte track kind, so other tracks such
//! as video share the same legs (see [`crate::engine::TrackSink`]).
//!
//! Calls are capped at [`MAX_PARTICIPANTS`]. In a full mesh, every device
//! encodes each frame once per bitrate tier, but sends and decodes it once
//! per peer. So upload and CPU grow with the number of people:
//! 7 peers × 32 kbps ≈ 0.3 Mbps up per device, which Bluetooth can't carry
//! and a busy Wi-Fi barely can.

use anyhow::{Result, bail};
use mycel_crypto::{Hash32, SignPk};
use serde::{Deserialize, Serialize};

/// The call protocol as pre-release builds speak it (docs/PROTOCOL.md
/// §3.8). Those builds end a leg on a control message ([`Ctrl`], or video's
/// `VideoCtrl`) of a variant they don't have, so a leg on this version is
/// only ever sent the variants call/1 has ([`Ctrl::since`]).
pub const ALPN_CALL_V1: &[u8] = b"mycel/call/1";
/// The same bytes as [`ALPN_CALL_V1`], plus a promise: the receiver skips
/// [`Ctrl`] and `VideoCtrl` variants it doesn't have ([`recv`]) instead of
/// ending the leg. A later build may add messages of either kind and send
/// them on call/2 legs, and only there.
pub const ALPN_CALL_V2: &[u8] = b"mycel/call/2";
/// Every version of the call protocol this build speaks, newest (preferred)
/// first: dialers offer them in this order and listeners register them in
/// it, so two devices land on the newest both speak. A change an older
/// build would misread gets a new ALPN here, never new bytes under an old
/// one.
pub const ALPNS_CALL: [&[u8]; 2] = [ALPN_CALL_V2, ALPN_CALL_V1];
/// The newest call protocol version this build speaks.
pub const CALL_VERSION: u16 = 2;
/// Sent in `Ring`, `Join` and `Watch` since call/1. Nothing reads it (a
/// leg's version is its ALPN, [`version_of`]) and it stays 1, so those
/// messages keep their call/1 bytes.
pub const VERSION: u16 = 1;
/// How many [`Ctrl`] variants this build knows (a message whose tag is past
/// them comes from a newer build).
const KNOWN_CTRL: u32 = 16;
/// Most people in one call (you included).
pub const MAX_PARTICIPANTS: usize = 8;
/// Control messages are tiny; refuse anything bigger.
pub const MAX_CTRL: usize = 4096;
const CTX_CALL_ID: &str = "mycel/v0/call-id";

pub type CallId = Hash32;

/// The call protocol version a leg's connection runs, from its ALPN
/// (`Connection::alpn`); `None` for an ALPN that isn't the call protocol.
pub fn version_of(alpn: &[u8]) -> Option<u16> {
    match alpn {
        ALPN_CALL_V1 => Some(1),
        ALPN_CALL_V2 => Some(2),
        _ => None,
    }
}

/// [`version_of`] a leg's connection; 1 (send only what every build takes)
/// when the ALPN isn't one of ours.
pub fn leg_version(conn: &mycel_net::iroh::endpoint::Connection) -> u16 {
    version_of(conn.alpn()).unwrap_or(1)
}

/// The call protocol's entries for `NodeOptions::extra_protocols`: every
/// version this build speaks, newest first, all handed to `incoming`
/// (`CallManager::serve`), which tells them apart by [`leg_version`].
pub fn extra_protocols(
    incoming: tokio::sync::mpsc::UnboundedSender<mycel_net::iroh::endpoint::Connection>,
) -> Vec<mycel_net::ExtraProtocol> {
    ALPNS_CALL.iter().map(|a| mycel_net::ExtraProtocol { alpn: a.to_vec(), incoming: incoming.clone() }).collect()
}

/// Dial `peer` for a call leg, offering every version this build speaks
/// (for `CallHost::connect`).
pub async fn connect(node: &mycel_net::Node, peer: SignPk) -> Result<mycel_net::iroh::endpoint::Connection> {
    node.connect_offering(peer, &ALPNS_CALL).await
}

/// The id of a call placed by `caller` in `space`.
pub fn call_id(space: &Hash32, caller: &SignPk, nonce: &[u8; 16]) -> CallId {
    Hash32::digest(CTX_CALL_ID, &[space.0.as_slice(), &caller.0, nonce].concat())
}

/// Everything that names a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRef {
    pub space: Hash32,
    pub initiator: SignPk,
    pub nonce: [u8; 16],
    pub call: CallId,
}

impl CallRef {
    pub fn new(space: Hash32, initiator: SignPk, nonce: [u8; 16]) -> CallRef {
        CallRef { space, initiator, nonce, call: call_id(&space, &initiator, &nonce) }
    }

    /// The id really is derived from the rest.
    pub fn is_valid(&self) -> bool {
        self.call == call_id(&self.space, &self.initiator, &self.nonce)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ctrl {
    /// Initiator → member: please ring. `group`: more than two people may join.
    Ring {
        version: u16,
        call: CallRef,
        group: bool,
    },
    /// Participant → participant: I'm in this call too; let's talk.
    Join {
        version: u16,
        call: CallRef,
    },
    /// Someone not in the call → participant: keep me told who's in it.
    Watch {
        version: u16,
        call: CallRef,
    },
    /// It's ringing.
    Ringing,
    Accept,
    /// Not answering (`missed`: nobody answered, it rang out).
    Decline {
        missed: bool,
    },
    /// In another call.
    Busy,
    /// We started calls in the same conversation at the same moment and
    /// yours loses (or, answering a `Join`, we dialed each other and the
    /// leg I dialed wins).
    Glare,
    /// There's already a call going on in this conversation: join it.
    Existing {
        call: CallRef,
    },
    /// Not allowed (not a member, or not in that call).
    Denied,
    /// The call already has [`MAX_PARTICIPANTS`] people.
    Full,
    /// Media is running (answer to `Accept` or `Join`).
    Started,
    /// I've left the call (or stopped ringing you).
    HangUp,
    Mute {
        muted: bool,
    },
    /// Receiver report, about once a second: what arrived of what was sent.
    Report {
        loss_ppm: u32,
        jitter_ms: u16,
        bitrate: u32,
    },
    /// The peers the sender is talking to, plus the sender if it's in the call.
    Roster {
        joined: Vec<SignPk>,
    },
}

impl Ctrl {
    /// The first call protocol version that has this message: a leg of an
    /// older version is never sent it ([`may_send`]). Every message so far
    /// is in call/1. A variant added later says 2 (or newer) here, and the
    /// match has no catch-all so that nobody can add one without choosing.
    pub fn since(&self) -> u16 {
        match self {
            Ctrl::Ring { .. }
            | Ctrl::Join { .. }
            | Ctrl::Watch { .. }
            | Ctrl::Ringing
            | Ctrl::Accept
            | Ctrl::Decline { .. }
            | Ctrl::Busy
            | Ctrl::Glare
            | Ctrl::Existing { .. }
            | Ctrl::Denied
            | Ctrl::Full
            | Ctrl::Started
            | Ctrl::HangUp
            | Ctrl::Mute { .. }
            | Ctrl::Report { .. }
            | Ctrl::Roster { .. } => 1,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = postcard::to_allocvec(self).expect("control messages serialize");
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Ctrl> {
        if body.len() > MAX_CTRL {
            bail!("control message too large");
        }
        Ok(postcard::from_bytes(body)?)
    }
}

/// Whether a message introduced in call protocol version `since` may go
/// on a leg of version `leg`. An older leg's peer may be a pre-release
/// build, which ends the leg on a message it doesn't know.
pub fn may_send(since: u16, leg: u16) -> bool {
    since <= leg
}

pub async fn send(tx: &mut mycel_net::iroh::endpoint::SendStream, msg: &Ctrl) -> Result<()> {
    tx.write_all(&msg.encode()).await?;
    Ok(())
}

/// [`send`] on a leg of call protocol version `leg`: a message that leg
/// doesn't have is not sent (`Ok(false)`). Every message a leg queues
/// goes through here.
pub async fn send_on(tx: &mut mycel_net::iroh::endpoint::SendStream, leg: u16, msg: &Ctrl) -> Result<bool> {
    if !may_send(msg.since(), leg) {
        return Ok(false);
    }
    send(tx, msg).await?;
    Ok(true)
}

/// Whether `body` is a control message of a newer build: one whose variant
/// tag this build doesn't have.
fn from_newer_revision(body: &[u8]) -> bool {
    postcard::take_from_bytes::<u32>(body).is_ok_and(|(tag, _)| tag >= KNOWN_CTRL)
}

/// The next control message; `None` when the peer finished the stream.
/// Messages of a variant this build doesn't have (a newer build's, sent
/// only on call/2 legs) are skipped; a malformed message is an error.
pub async fn recv(rx: &mut mycel_net::iroh::endpoint::RecvStream) -> Result<Option<Ctrl>> {
    recv_from(rx).await
}

/// [`recv`] from any byte stream.
async fn recv_from<R: tokio::io::AsyncRead + Unpin>(rx: &mut R) -> Result<Option<Ctrl>> {
    use tokio::io::AsyncReadExt;
    loop {
        let mut len = [0u8; 2];
        // finished between messages: the end; inside one: an error
        if rx.read(&mut len[..1]).await? == 0 {
            return Ok(None);
        }
        rx.read_exact(&mut len[1..]).await?;
        let len = u16::from_le_bytes(len) as usize;
        if len > MAX_CTRL {
            bail!("control message too large");
        }
        let mut buf = vec![0u8; len];
        rx.read_exact(&mut buf).await?;
        match Ctrl::decode(&buf) {
            Ok(msg) => return Ok(Some(msg)),
            Err(_) if from_newer_revision(&buf) => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_id_binds_space_caller_and_nonce() {
        let space = Hash32([1; 32]);
        let (a, b) = (SignPk([2; 32]), SignPk([3; 32]));
        let n = [9u8; 16];
        let id = call_id(&space, &a, &n);
        assert_eq!(id, call_id(&space, &a, &n));
        assert_ne!(id, call_id(&Hash32([4; 32]), &a, &n), "another conversation");
        assert_ne!(id, call_id(&space, &b, &n), "another caller");
        assert_ne!(id, call_id(&space, &a, &[8; 16]), "another nonce");
        let r = CallRef::new(space, a, n);
        assert!(r.is_valid());
        assert!(!CallRef { initiator: b, ..r }.is_valid(), "someone else's call id");
    }

    /// On a stream: a message from a newer minor revision is skipped and
    /// the next one arrives; the stream finishing between messages is the
    /// end, inside one an error; garbage is an error.
    #[tokio::test]
    async fn recv_skips_messages_from_a_newer_revision() {
        let mut wire = Ctrl::Ringing.encode();
        wire.extend_from_slice(&[4, 0, KNOWN_CTRL as u8, 1, 2, 3]); // a newer revision's message
        wire.extend_from_slice(&Ctrl::Mute { muted: true }.encode());
        let mut rx = wire.as_slice();
        assert_eq!(recv_from(&mut rx).await.unwrap(), Some(Ctrl::Ringing));
        assert_eq!(recv_from(&mut rx).await.unwrap(), Some(Ctrl::Mute { muted: true }));
        assert_eq!(recv_from(&mut rx).await.unwrap(), None);
        let cut = &Ctrl::HangUp.encode()[..1];
        assert!(recv_from(&mut &cut[..]).await.is_err(), "finished inside a message");
        let garbage = [3, 0, 0xff, 0xff, 0xff];
        assert!(recv_from(&mut &garbage[..]).await.is_err());
        let too_big = ((MAX_CTRL + 1) as u16).to_le_bytes();
        assert!(recv_from(&mut &too_big[..]).await.is_err());
    }

    /// Versions are named by ALPN, newest first, one name each; a leg is
    /// only sent messages its version has, and every message so far is in
    /// call/1, so a pre-release peer (call/1 only) can take all of them.
    #[test]
    fn legs_get_only_the_messages_their_version_has() {
        assert_eq!(ALPNS_CALL, [b"mycel/call/2".as_slice(), b"mycel/call/1"]);
        for (i, alpn) in ALPNS_CALL.iter().enumerate() {
            assert_eq!(version_of(alpn), Some(CALL_VERSION - i as u16));
        }
        assert_eq!(version_of(b"mycel/2"), None);
        assert_eq!(version_of(b"mycel/call/3"), None);
        assert!(may_send(1, 1) && may_send(1, 2) && may_send(2, 2));
        assert!(!may_send(2, 1), "a newer message never goes on a call/1 leg");
        let call = CallRef::new(Hash32([5; 32]), SignPk([8; 32]), [6; 16]);
        let all = [
            Ctrl::Ring { version: VERSION, call, group: true },
            Ctrl::Join { version: VERSION, call },
            Ctrl::Watch { version: VERSION, call },
            Ctrl::Ringing,
            Ctrl::Accept,
            Ctrl::Decline { missed: false },
            Ctrl::Busy,
            Ctrl::Glare,
            Ctrl::Existing { call },
            Ctrl::Denied,
            Ctrl::Full,
            Ctrl::Started,
            Ctrl::HangUp,
            Ctrl::Mute { muted: false },
            Ctrl::Report { loss_ppm: 0, jitter_ms: 0, bitrate: 0 },
            Ctrl::Roster { joined: vec![] },
        ];
        assert_eq!(all.len() as u32, KNOWN_CTRL, "every variant listed");
        for m in &all {
            assert_eq!(m.since(), 1, "{m:?} is a call/1 message");
            assert!(may_send(m.since(), 1));
        }
        // the leg-opening messages keep their call/1 bytes
        let ring = Ctrl::Ring { version: VERSION, call, group: false }.encode();
        assert_eq!(&ring[2..4], &[0, 1], "variant 0, version 1");
    }

    #[test]
    fn messages_round_trip() {
        let call = CallRef::new(Hash32([5; 32]), SignPk([8; 32]), [6; 16]);
        let msgs = [
            Ctrl::Ring { version: VERSION, call, group: true },
            Ctrl::Join { version: VERSION, call },
            Ctrl::Watch { version: VERSION, call },
            Ctrl::Existing { call },
            Ctrl::Ringing,
            Ctrl::Decline { missed: true },
            Ctrl::Mute { muted: true },
            Ctrl::Report { loss_ppm: 12_000, jitter_ms: 9, bitrate: 32_000 },
            Ctrl::Roster { joined: vec![SignPk([1; 32]), SignPk([2; 32])] },
            Ctrl::HangUp,
        ];
        for m in msgs {
            let wire = m.encode();
            let len = u16::from_le_bytes([wire[0], wire[1]]) as usize;
            assert_eq!(len, wire.len() - 2);
            assert_eq!(Ctrl::decode(&wire[2..]).unwrap(), m);
        }
        assert!(Ctrl::decode(&[0xff, 0xff, 0xff]).is_err());
        // the last variant has the last known tag: KNOWN_CTRL is current
        let last = Ctrl::Roster { joined: vec![] }.encode();
        assert_eq!(postcard::take_from_bytes::<u32>(&last[2..]).unwrap().0, KNOWN_CTRL - 1);
        assert!(!from_newer_revision(&last[2..]));
        // a newer revision's message is recognised as such (and skipped by
        // `recv`); garbage is not
        assert!(from_newer_revision(&[KNOWN_CTRL as u8, 1, 2, 3]));
        assert!(Ctrl::decode(&[KNOWN_CTRL as u8, 1, 2, 3]).is_err());
        assert!(!from_newer_revision(&[0xff, 0xff, 0xff]));
        assert!(Ctrl::decode(&vec![0; MAX_CTRL + 1]).is_err());
        // a full roster stays far below the size limit
        let roster = Ctrl::Roster { joined: vec![SignPk([9; 32]); MAX_PARTICIPANTS] };
        assert!(roster.encode().len() < MAX_CTRL / 4);
    }
}
