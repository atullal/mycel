//! Call signalling (ALPN `mycel/call/0`).
//!
//! The caller dials the callee's device key directly, so a call only needs
//! both devices online: no server, no prior connection. One QUIC connection
//! per call; it inherits the node's multipath paths (network, peer-to-peer
//! Wi-Fi, relay, Bluetooth) and moves between them mid-call.
//!
//! One bidirectional control stream, opened by the caller, carries small
//! length-prefixed postcard messages ([`Ctrl`]):
//!
//! ```text
//! caller                          callee
//!   Ring{space, nonce, call} ───▶   checks: call == derive(space, caller, nonce),
//!                                   both are members of `space`
//!                         ◀───  Ringing | Busy | Glare | Denied
//!                         ◀───  Accept | Decline           (user answers)
//!   Started ────────────────▶      (media flows both ways: datagrams)
//!   Mute / Report / HangUp ◀──▶    Mute / Report / HangUp
//! ```
//!
//! Audio goes in QUIC datagrams ([`crate::frame`]), or on a unidirectional
//! stream if a path can't carry datagrams. The call id binds the call to the
//! conversation: it is derived from the space id, the caller's key (the
//! QUIC-authenticated peer) and a random nonce, and both sides check it.
//!
//! Group calls can come later on the same protocol: a group call is a mesh
//! of these 1:1 connections sharing one call id (`Ring` would carry the
//! participant list); nothing here assumes exactly two people per space.

use anyhow::{Result, bail};
use mycel_crypto::{Hash32, SignPk};
use serde::{Deserialize, Serialize};

pub const ALPN_CALL: &[u8] = b"mycel/call/0";
pub const VERSION: u16 = 0;
/// Control messages are tiny; refuse anything bigger.
pub const MAX_CTRL: usize = 4096;
const CTX_CALL_ID: &str = "mycel/v0/call-id";

pub type CallId = Hash32;

/// The id of a call placed by `caller` in `space`.
pub fn call_id(space: &Hash32, caller: &SignPk, nonce: &[u8; 16]) -> CallId {
    Hash32::digest(CTX_CALL_ID, &[space.0.as_slice(), &caller.0, nonce].concat())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ctrl {
    /// Caller → callee: please ring.
    Ring { version: u16, space: Hash32, nonce: [u8; 16], call: CallId },
    /// Callee: it's ringing.
    Ringing,
    Accept,
    Decline,
    /// Callee is in another call.
    Busy,
    /// We called each other at the same time and your call loses; mine is
    /// ringing you (see `state::on_ring`).
    Glare,
    /// Not allowed (not a member of that conversation).
    Denied,
    /// Caller: accept seen, media running.
    Started,
    HangUp,
    Mute { muted: bool },
    /// Receiver report, about once a second: what arrived of what was sent.
    Report { loss_ppm: u32, jitter_ms: u16, bitrate: u32 },
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
    }

    #[test]
    fn messages_round_trip() {
        let msgs = [
            Ctrl::Ring { version: VERSION, space: Hash32([5; 32]), nonce: [6; 16], call: Hash32([7; 32]) },
            Ctrl::Ringing,
            Ctrl::Mute { muted: true },
            Ctrl::Report { loss_ppm: 12_000, jitter_ms: 9, bitrate: 32_000 },
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
    }
}
