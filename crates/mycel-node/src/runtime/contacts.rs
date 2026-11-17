//! Contacts and contact codes.
//!
//! A contact code is what a person shares so that others can add their
//! device. It is `mycel:` + base64url, optionally followed by `@` and the
//! device's current addresses (unsigned hints). Two forms:
//!
//! - **Short** (what the profile shows, as text and as a QR code): the
//!   device key and the name it signed. A device's lockbox key is 1216 bytes
//!   (X-Wing, TRUST.md §2): too much to paste or scan, so the code doesn't
//!   carry it. The runtime fetches the device's signed card, which does, the
//!   first time it reaches the device. Until then the contact is *awaited*:
//!   it is listed and counts as a contact, but can't be put in a
//!   conversation, because nothing can be sealed to it yet.
//! - **Full**: the whole signed card, lockbox key included (about 1.8 kB of
//!   text). It needs no connection to the device, so it is the one to use
//!   where the two devices can't reach each other first.
//!
//! Either way a lockbox is only ever sealed to a key that the device's own
//! key signed (`MemberKeys::verify_binding`): the code names the device key,
//! and whatever arrives later is checked against it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Weak;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64URL_NOPAD;
use mycel_crypto::{DeviceKeys, MemberKeys, Sig, SignPk};
use mycel_net::{ContactCard, PeerState};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::{Runtime, StoredContact, hex_id, parse_pk};
use crate::api::{Contact, Event, PeerId, Profile};

const CONTACT_PREFIX: &str = "mycel:";
/// First byte of a code's payload: which form it is. (Codes of earlier
/// builds had no such byte, and don't decode as either.)
const KIND_SHORT: u8 = 1;
const KIND_FULL: u8 = 2;
/// Longest code looked at (a full code is under 2 kB).
const MAX_CODE: usize = 8 * 1024;
const MAX_NAME_CHARS: usize = 64;
const CTX_STUB: &str = "mycel/v1/contact-stub";

/// How long one attempt to fetch an awaited contact's card may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause between attempts: doubles from the first to the last.
const FETCH_RETRY_MIN: Duration = Duration::from_millis(500);
const FETCH_RETRY_MAX: Duration = Duration::from_secs(60);

/// What a short contact code carries: the device key, and the name it
/// signed. Enough to find the device and to check what it sends later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactStub {
    pub sign_pk: SignPk,
    pub name: String,
    pub sig: Sig,
}

impl ContactStub {
    pub fn new(keys: &DeviceKeys, name: &str) -> Self {
        let name: String = name.chars().take(MAX_NAME_CHARS).collect();
        let sig = keys.sign(CTX_STUB, &[name.as_bytes()]);
        ContactStub { sign_pk: keys.sign_pk(), name, sig }
    }

    pub fn verify(&self) -> Result<()> {
        if self.name.chars().count() > MAX_NAME_CHARS {
            bail!("name too long");
        }
        self.sign_pk.verify(CTX_STUB, &[self.name.as_bytes()], &self.sig)?;
        Ok(())
    }
}

/// A decoded contact code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactCode {
    Short(ContactStub),
    Full(ContactCard),
}

impl ContactCode {
    pub fn sign_pk(&self) -> SignPk {
        match self {
            ContactCode::Short(s) => s.sign_pk,
            ContactCode::Full(c) => c.keys.sign_pk,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ContactCode::Short(s) => &s.name,
            ContactCode::Full(c) => &c.name,
        }
    }
}

fn encode(kind: u8, body: Vec<u8>, hints: &[String]) -> String {
    let mut payload = Vec::with_capacity(1 + body.len());
    payload.push(kind);
    payload.extend_from_slice(&body);
    let base = format!("{CONTACT_PREFIX}{}", BASE64URL_NOPAD.encode(&payload));
    if hints.is_empty() { base } else { format!("{base}@{}", hints.join(",")) }
}

/// The short code: device key and signed name, plus optional
/// `@ip:port,ip:port` address hints (unsigned; only used to find the device).
pub fn encode_short_contact_code(stub: &ContactStub, hints: &[String]) -> String {
    encode(KIND_SHORT, postcard::to_allocvec(stub).expect("a stub encodes"), hints)
}

/// The full code: the whole signed card.
pub fn encode_contact_code(card: &ContactCard) -> String {
    encode_contact_code_with_hints(card, &[])
}

/// The full code plus optional `@ip:port,ip:port` address hints (unsigned,
/// only used to find the device; its identity is still the signed card).
pub fn encode_contact_code_with_hints(card: &ContactCard, hints: &[String]) -> String {
    encode(KIND_FULL, postcard::to_allocvec(card).expect("a card encodes"), hints)
}

/// Decode and verify a contact code of either form, with its address hints.
pub fn parse_contact_code(code: &str) -> Result<(ContactCode, Vec<SocketAddr>)> {
    const NOT_A_CODE: &str = "not a Mycel contact code (or one made by an older version of Mycel)";
    if code.len() > MAX_CODE {
        bail!("that's too long to be a Mycel contact code");
    }
    let code: String = code.split_whitespace().collect();
    let body = code.strip_prefix(CONTACT_PREFIX).unwrap_or(&code);
    let (card_part, hints) = body.split_once('@').unwrap_or((body, ""));
    let bytes = BASE64URL_NOPAD.decode(card_part.as_bytes()).context(NOT_A_CODE)?;
    let (kind, body) = bytes.split_first().context(NOT_A_CODE)?;
    let parsed = match *kind {
        KIND_SHORT => {
            let stub: ContactStub = postcard::from_bytes(body).context(NOT_A_CODE)?;
            stub.verify().context("contact code signature is invalid")?;
            ContactCode::Short(stub)
        }
        KIND_FULL => {
            let card: ContactCard = postcard::from_bytes(body).context(NOT_A_CODE)?;
            card.verify().context("contact code signature is invalid")?;
            ContactCode::Full(card)
        }
        _ => bail!(NOT_A_CODE),
    };
    let hints = hints.split(',').filter_map(|h| h.parse().ok()).take(8).collect();
    Ok((parsed, hints))
}

/// The card in a full contact code.
pub fn decode_contact_code(code: &str) -> Result<ContactCard> {
    Ok(decode_contact_code_with_hints(code)?.0)
}

/// The card in a full contact code, and its address hints. A short code has
/// no card: [`parse_contact_code`] reads both forms.
pub fn decode_contact_code_with_hints(code: &str) -> Result<(ContactCard, Vec<SocketAddr>)> {
    match parse_contact_code(code)? {
        (ContactCode::Full(card), hints) => Ok((card, hints)),
        (ContactCode::Short(_), _) => bail!("a short contact code doesn't hold the device's card"),
    }
}

/// Card fetches under way for awaited contacts. Dropped with the runtime,
/// which stops them.
#[derive(Default)]
pub(super) struct CardFetches(Mutex<HashMap<SignPk, tokio::task::AbortHandle>>);

impl Drop for CardFetches {
    fn drop(&mut self) {
        for (_, task) in self.0.lock().drain() {
            task.abort();
        }
    }
}

impl Runtime {
    pub fn profile(&self) -> Profile {
        let hints = self.node.local_addresses();
        let name = self.name.lock().clone();
        Profile {
            id: hex_id(&self.keys.sign_pk()),
            contact_code: encode_short_contact_code(&ContactStub::new(&self.keys, &name), &hints),
            contact_code_full: encode_contact_code_with_hints(&self.node.card(), &hints),
            name,
        }
    }

    pub(super) fn save_contacts(&self) {
        let list: Vec<StoredContact> = self.contacts.lock().values().cloned().collect();
        self.store.kv_put("contacts", postcard::to_allocvec(&list).unwrap());
    }

    fn save_awaiting(&self) {
        let list: Vec<(SignPk, String)> = self.awaiting.lock().iter().map(|(k, n)| (*k, n.clone())).collect();
        self.store.kv_put("contacts-awaiting", postcard::to_allocvec(&list).unwrap());
    }

    /// A contact, whether or not its keys have arrived yet.
    pub(super) fn is_contact(&self, pk: &SignPk) -> bool {
        self.contacts.lock().contains_key(pk) || self.awaiting.lock().contains_key(pk)
    }

    /// Keep a contact's verified keys. An empty `name` keeps the one its
    /// short code came with, if it was awaited.
    pub(super) fn remember(&self, keys: MemberKeys, name: String) -> Result<Contact> {
        if keys.sign_pk == self.keys.sign_pk() {
            bail!("that's your own contact code");
        }
        keys.verify_binding()?;
        let pk = keys.sign_pk;
        let awaited = self.awaiting.lock().remove(&pk);
        let name = if name.is_empty() { awaited.clone().unwrap_or_default() } else { name };
        self.contacts.lock().insert(pk, StoredContact { keys, name });
        self.save_contacts();
        if awaited.is_some() {
            self.save_awaiting();
            if let Some(task) = self.card_fetches.0.lock().remove(&pk) {
                task.abort();
            }
        }
        self.emit(Event::ContactsChanged);
        self.contact(&pk).context("contact vanished")
    }

    pub fn add_contact(&self, code: String) -> Result<Contact> {
        let (code, hints) = parse_contact_code(&code)?;
        let pk = code.sign_pk();
        if pk == self.keys.sign_pk() {
            bail!("that's your own contact code");
        }
        if !hints.is_empty() {
            self.node.add_peer_hints(pk, &hints);
            let mut all = self.hints.lock();
            all.insert(pk, hints.iter().map(|h| h.to_string()).collect());
            let list: Vec<(SignPk, Vec<String>)> = all.iter().map(|(k, v)| (*k, v.clone())).collect();
            self.store.kv_put("hints", postcard::to_allocvec(&list).unwrap());
        }
        match code {
            ContactCode::Full(card) => self.remember(card.keys, card.name),
            ContactCode::Short(stub) => {
                // Already known with its keys: nothing to wait for.
                if !self.contacts.lock().contains_key(&pk) {
                    // The device may already be in a conversation with us.
                    if let Some(keys) = self.keys_in_spaces(&pk) {
                        return self.remember(keys, stub.name);
                    }
                    self.awaiting.lock().insert(pk, stub.name);
                    self.save_awaiting();
                    self.fetch_card_of(pk);
                    self.emit(Event::ContactsChanged);
                }
                self.contact(&pk).context("contact vanished")
            }
        }
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
        if self.awaiting.lock().remove(&pk).is_some() {
            self.save_awaiting();
        }
        if let Some(task) = self.card_fetches.0.lock().remove(&pk) {
            task.abort();
        }
        self.emit(Event::ContactsChanged);
        Ok(())
    }

    pub(super) fn contact(&self, pk: &SignPk) -> Option<Contact> {
        // Don't hold the contacts lock across name_of (it locks contacts too).
        let has_keys = self.contacts.lock().contains_key(pk);
        if !has_keys && !self.awaiting.lock().contains_key(pk) {
            return None;
        }
        let peers = self.node.peers();
        Some(Contact {
            id: hex_id(pk),
            name: self.name_of(pk),
            nearby: peers.get(pk).is_some_and(PeerState::is_directly_discovered),
            online: peers.get(pk).is_some_and(|p| p.online()),
            awaiting_keys: !has_keys,
        })
    }

    pub fn contacts(&self) -> Vec<Contact> {
        let mut pks: Vec<SignPk> = self.contacts.lock().keys().copied().collect();
        pks.extend(self.awaiting.lock().keys().copied());
        let mut out: Vec<Contact> = pks.iter().filter_map(|pk| self.contact(pk)).collect();
        out.sort_by_key(|c| c.name.to_lowercase());
        out
    }

    /// The keys to seal to for contact `id`.
    pub(super) fn contact_keys(&self, id: &str) -> Result<MemberKeys> {
        let pk = parse_pk(id)?;
        if let Some(keys) = self.contacts.lock().get(&pk).map(|c| c.keys.clone()) {
            return Ok(keys);
        }
        if !self.awaiting.lock().contains_key(&pk) {
            bail!("{} is not in your contacts", pk.short());
        }
        if let Some(keys) = self.keys_in_spaces(&pk) {
            self.remember(keys.clone(), String::new())?;
            return Ok(keys);
        }
        Err(anyhow!(
            "Mycel hasn't reached {}'s device yet to get its encryption key. It keeps trying: \
             this works once they are online or nearby. (Their full contact code needs no connection.)",
            self.name_of(&pk)
        ))
    }

    /// The keys `pk` has as a member of a conversation we hold, if any:
    /// signed by `pk`, and checked when the membership op was accepted.
    fn keys_in_spaces(&self, pk: &SignPk) -> Option<MemberKeys> {
        self.node.space_ids().into_iter().find_map(|space| {
            self.node
                .with_space(&space, |r| r.members().into_iter().find(|(k, _)| k.sign_pk == *pk).map(|(k, _)| k))
                .ok()
                .flatten()
        })
    }

    /// Fetch every awaited contact's card (at startup).
    pub(super) fn fetch_awaited_cards(&self) {
        let pks: Vec<SignPk> = self.awaiting.lock().keys().copied().collect();
        for pk in pks {
            self.fetch_card_of(pk);
        }
    }

    /// Keep asking awaited contact `pk`'s device for its card, in the
    /// background, until it arrives or `pk` stops being awaited.
    fn fetch_card_of(&self, pk: SignPk) {
        // Outside a Tokio runtime nothing can be spawned: the next start
        // fetches it (`fetch_awaited_cards`).
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let mut fetches = self.card_fetches.0.lock();
        if fetches.get(&pk).is_some_and(|t| !t.is_finished()) {
            return;
        }
        let task = handle.spawn(fetch_card_until_known(self.this.clone(), pk));
        fetches.insert(pk, task.abort_handle());
    }
}

/// The task behind [`Runtime::fetch_card_of`]. It holds the runtime only
/// while it looks at it, never while it waits, so it can't keep a runtime
/// (its data directory, its sockets) alive after its owner let go.
async fn fetch_card_until_known(rt: Weak<Runtime>, pk: SignPk) {
    let mut pause = FETCH_RETRY_MIN;
    loop {
        let fetch = {
            let Some(rt) = rt.upgrade() else { return };
            if !rt.awaiting.lock().contains_key(&pk) {
                return;
            }
            // It may have put us in a conversation meanwhile: its keys are there.
            if let Some(keys) = rt.keys_in_spaces(&pk) {
                let _ = rt.remember(keys, String::new());
                return;
            }
            rt.node.card_fetch(pk)
        };
        let card = tokio::time::timeout(FETCH_TIMEOUT, fetch).await;
        if let Ok(Ok(card)) = card {
            let Some(rt) = rt.upgrade() else { return };
            // (`card_fetch` checked the card's signatures and that it is `pk`'s.)
            if rt.awaiting.lock().contains_key(&pk) {
                let _ = rt.remember(card.keys, card.name);
            }
            return;
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(FETCH_RETRY_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints() -> Vec<String> {
        vec!["192.168.1.20:4433".into(), "[fe80::1]:4433".into()]
    }

    #[test]
    fn short_and_full_codes_round_trip_with_hints() {
        let keys = DeviceKeys::generate();
        let stub = ContactStub::new(&keys, "Ines");
        let short = encode_short_contact_code(&stub, &hints());
        let (code, addrs) = parse_contact_code(&short).unwrap();
        assert_eq!(code, ContactCode::Short(stub));
        assert_eq!((code.sign_pk(), code.name()), (keys.sign_pk(), "Ines"));
        assert_eq!(addrs.len(), 2);

        let card = ContactCard::new(&keys, "Ines");
        let full = encode_contact_code_with_hints(&card, &hints());
        let (code, addrs) = parse_contact_code(&full).unwrap();
        assert_eq!(code, ContactCode::Full(card.clone()));
        assert_eq!(addrs.len(), 2);
        assert_eq!(decode_contact_code(&full).unwrap(), card);
        assert_eq!(decode_contact_code(&encode_contact_code(&card)).unwrap(), card);
        // a short code holds no card
        assert!(decode_contact_code(&short).is_err());
        // pasted with line breaks and spaces
        let wrapped: String = short.chars().flat_map(|c| [c, ' ', '\n']).collect();
        assert_eq!(parse_contact_code(&wrapped).unwrap().0.sign_pk(), keys.sign_pk());
    }

    /// The short code is what is pasted and scanned: it must stay small,
    /// which is why the 1216-byte lockbox key isn't in it.
    #[test]
    fn the_short_code_fits_a_qr_code_and_the_full_one_holds_the_lockbox_key() {
        let keys = DeviceKeys::generate();
        let name = "A name of the maximum length, sixty-four characters, no more....";
        assert_eq!(name.chars().count(), MAX_NAME_CHARS);
        let short = encode_short_contact_code(&ContactStub::new(&keys, name), &hints());
        // A version-10 QR code at error correction M (57×57 modules) holds
        // 213 bytes; with a long name and two addresses we stay near that.
        assert!(short.len() <= 300, "{} characters", short.len());
        let plain = encode_short_contact_code(&ContactStub::new(&keys, "Ines"), &[]);
        assert!(plain.len() <= 150, "{} characters", plain.len());
        let full = encode_contact_code(&ContactCard::new(&keys, "Ines"));
        assert!(full.len() > mycel_crypto::KEX_PK_LEN * 4 / 3, "{} characters", full.len());
        assert!(full.len() < 2_000, "{} characters", full.len());
    }

    #[test]
    fn altered_and_foreign_codes_are_refused() {
        let keys = DeviceKeys::generate();
        let stub = ContactStub::new(&keys, "Ines");
        // another name under the same signature
        let renamed = ContactStub { name: "Someone else".into(), ..stub.clone() };
        assert!(parse_contact_code(&encode_short_contact_code(&renamed, &[])).is_err());
        // another key under the same signature
        let rekeyed = ContactStub { sign_pk: DeviceKeys::generate().sign_pk(), ..stub.clone() };
        assert!(parse_contact_code(&encode_short_contact_code(&rekeyed, &[])).is_err());
        // a name longer than a device signs
        let long = "x".repeat(MAX_NAME_CHARS + 1);
        let sig = keys.sign(CTX_STUB, &[long.as_bytes()]);
        let long = ContactStub { sign_pk: keys.sign_pk(), name: long, sig };
        assert!(parse_contact_code(&encode_short_contact_code(&long, &[])).is_err());
        // a full card whose lockbox key isn't the one the device signed
        let mut card = ContactCard::new(&keys, "Ines");
        card.keys.kex_pk = DeviceKeys::generate().public().kex_pk;
        assert!(parse_contact_code(&encode_contact_code(&card)).is_err());
        // a stub passed off as a card, and the reverse
        let stub_bytes = postcard::to_allocvec(&stub).unwrap();
        assert!(parse_contact_code(&encode(KIND_FULL, stub_bytes, &[])).is_err());
        let card_bytes = postcard::to_allocvec(&ContactCard::new(&keys, "Ines")).unwrap();
        assert!(parse_contact_code(&encode(KIND_SHORT, card_bytes, &[])).is_err());
        // junk, an unknown kind, nothing, too much
        for bad in ["", "mycel:", "mycel:AAAA", "hello", "mycel:!!!"] {
            assert!(parse_contact_code(bad).is_err(), "{bad:?}");
        }
        assert!(parse_contact_code(&encode(9, vec![1, 2, 3], &[])).is_err());
        assert!(parse_contact_code(&"A".repeat(MAX_CODE + 1)).is_err());
    }

    /// A contact code of an earlier build: the signed card with a 32-byte
    /// X25519 key and no kind byte. It is refused, not half-read.
    #[test]
    fn codes_of_earlier_builds_are_refused() {
        let old_card = [[7u8; 32].as_slice(), &[8u8; 32], &[64], &[9u8; 64], &[4], b"Ines", &[64], &[9u8; 64]].concat();
        for first in [KIND_SHORT, KIND_FULL, 0x7f] {
            let mut bytes = old_card.clone();
            bytes[0] = first;
            let code = format!("{CONTACT_PREFIX}{}", BASE64URL_NOPAD.encode(&bytes));
            let err = parse_contact_code(&code).unwrap_err();
            assert!(format!("{err:#}").contains("contact code"), "{err:#}");
        }
    }
}
