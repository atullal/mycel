//! Call signalling (ALPN `mycel/call/1`).
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

pub const ALPN_CALL: &[u8] = b"mycel/call/1";
pub const VERSION: u16 = 1;
/// Most people in one call (you included).
pub const MAX_PARTICIPANTS: usize = 8;
/// Control messages are tiny; refuse anything bigger.
pub const MAX_CTRL: usize = 4096;
const CTX_CALL_ID: &str = "mycel/v0/call-id";

pub type CallId = Hash32;

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

pub async fn send(tx: &mut mycel_net::iroh::endpoint::SendStream, msg: &Ctrl) -> Result<()> {
    tx.write_all(&msg.encode()).await?;
    Ok(())
}

/// The next control message; `None` when the peer finished the stream.
pub async fn recv(rx: &mut mycel_net::iroh::endpoint::RecvStream) -> Result<Option<Ctrl>> {
    let mut len = [0u8; 2];
    match rx.read_exact(&mut len).await {
        Ok(()) => {}
        Err(mycel_net::iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_le_bytes(len) as usize;
    if len > MAX_CTRL {
        bail!("control message too large");
    }
    let mut buf = vec![0u8; len];
    rx.read_exact(&mut buf).await?;
    Ctrl::decode(&buf).map(Some)
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
        assert!(Ctrl::decode(&vec![0; MAX_CTRL + 1]).is_err());
        // a full roster stays far below the size limit
        let roster = Ctrl::Roster { joined: vec![SignPk([9; 32]); MAX_PARTICIPANTS] };
        assert!(roster.encode().len() < MAX_CTRL / 4);
    }
}
