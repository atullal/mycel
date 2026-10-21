//! A replica (`mycel-sync`) receiving what a malicious *member* can send: a
//! writer holding the space's epoch key seals whatever plaintext it likes
//! (honest Automerge changes, mutated ones, arbitrary bytes, feed entries)
//! at any position of its author chain, forking it at will; plus raw
//! envelopes and membership ops from the wire. This is the path every
//! document edit takes from the network to the app, and the one a stored
//! space takes on restart (`Replica::restore`).
//!
//! Property, beyond not panicking: convergence. Two replicas that receive
//! the same envelopes in different orders (one in batches as they arrive,
//! one restored from storage in reverse order) end in the same state:
//! the same status for every envelope, the same documents and feeds.
#![no_main]

use std::sync::{Arc, LazyLock};

use arbitrary::Arbitrary;
use automerge::ROOT;
use automerge::transaction::Transactable;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::DeviceKeys;
use mycel_sync::fuzzing::{change_body, frame_change, seal};
use mycel_sync::{Envelope, EnvelopeId, FeedEntry, Replica, StreamId, StreamKind};
use mycel_trust::{Role, SignedOp};

struct Setup {
    founder: Arc<DeviceKeys>,
    writer: Arc<DeviceKeys>,
    genesis: SignedOp,
    ops: Vec<SignedOp>,
}

/// One space, made once: founder A adds writer B. (Epoch keys are random,
/// so this is built once per process and every input runs against it.)
static SETUP: LazyLock<Setup> = LazyLock::new(|| {
    let founder = Arc::new(DeviceKeys::from_seed([1; 32]));
    let writer = Arc::new(DeviceKeys::from_seed([2; 32]));
    let (mut a, genesis) = Replica::create(founder.clone(), None).expect("a space");
    a.add_member(writer.public(), Role::Writer).expect("the founder adds a writer");
    let ops = a.all_ops();
    Setup { founder, writer, genesis, ops }
});

fn restore(keys: &Arc<DeviceKeys>, envelopes: Vec<Envelope>) -> Replica {
    let s = &*SETUP;
    Replica::restore(keys.clone(), s.genesis.clone(), s.ops.clone(), envelopes, None).expect("restores")
}

fn stream(i: u8) -> StreamId {
    let kind = if i.is_multiple_of(2) { StreamKind::Doc } else { StreamKind::Feed };
    StreamId::named(kind, &format!("s{}", i % 4))
}

#[derive(Arbitrary, Debug)]
enum Chain {
    /// Next on the writer's own chain.
    Next,
    /// A fork of an earlier envelope: same position, different content.
    Fork(u8),
    /// Anywhere, pointing at anything.
    Any { seq: u64, prev: Option<u8> },
}

#[derive(Arbitrary, Debug)]
enum Payload {
    /// An honest edit through the writer's own replica.
    Edit { key: u8, value: String },
    /// An honest edit's change, with one byte flipped and the checksum fixed.
    Mutated { key: u8, value: String, at: u16, xor: u8 },
    /// A change body framed with a valid checksum.
    Framed(Vec<u8>),
    /// A feed entry.
    Entry { deps: Vec<u8>, ts_ms: u64, body: Vec<u8> },
    /// Anything.
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Msg {
    Seal { stream: u8, payload: Payload, chain: Chain, nonce: [u8; 24] },
    WireEnvelope(Vec<u8>),
    WireOp(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    msgs: Vec<Msg>,
    batch: u8,
}

fn state(r: &mut Replica, ids: &[EnvelopeId]) -> String {
    let mut out = String::new();
    let mut ids = ids.to_vec();
    ids.sort();
    for id in &ids {
        out += &format!("{id:?}={:?};", r.status(id));
    }
    for i in 0..4 {
        let s = stream(i);
        if s.kind == StreamKind::Doc {
            out += &format!("{}\n", r.doc_json(&s));
        } else {
            for item in r.feed(&s) {
                out += &format!("{:?}/{:?}/{};", item.id, item.body, item.ts_ms);
            }
            out += "\n";
        }
    }
    out
}

fuzz_target!(|input: Input| {
    let s = &*SETUP;
    let mut writer = restore(&s.writer, vec![]);
    let mut sent: Vec<Envelope> = Vec::new();
    // (seq, id) of each envelope on the writer's chain, in order sealed
    let mut chain: Vec<(u64, EnvelopeId)> = Vec::new();
    let mut ops: Vec<SignedOp> = Vec::new();
    for msg in input.msgs.into_iter().take(24) {
        match msg {
            Msg::Seal { stream: st, payload, chain: at, nonce } => {
                let stream = stream(st);
                let (seq, prev) = match at {
                    Chain::Next => chain.last().map_or((0, None), |(s, id)| (s + 1, Some(*id))),
                    Chain::Fork(i) if !chain.is_empty() => {
                        let i = usize::from(i) % chain.len();
                        let (seq, _) = chain[i];
                        (seq, i.checked_sub(1).map(|p| chain[p].1))
                    }
                    Chain::Fork(_) => (0, None),
                    Chain::Any { seq, prev } => (seq, prev.and_then(|p| sent.get(usize::from(p)).map(Envelope::id))),
                };
                let mutate = match payload {
                    Payload::Mutated { at, xor, .. } => Some((at, xor)),
                    _ => None,
                };
                let plaintext = match payload {
                    Payload::Edit { key, value } | Payload::Mutated { key, value, .. }
                        if stream.kind == StreamKind::Doc =>
                    {
                        let Ok((_, Some(env))) =
                            writer.change(stream, |d| d.put(ROOT, format!("k{}", key % 4), value.clone()))
                        else {
                            continue;
                        };
                        // the honest envelope goes out as it is
                        chain.push((env.header.author_seq, env.id()));
                        sent.push(env.clone());
                        if let Some((at, xor)) = mutate {
                            let Some(change) = writer.doc(&stream).and_then(|d| d.clone().get_last_local_change())
                            else {
                                continue;
                            };
                            let mut body = change_body(change.raw_bytes()).unwrap_or_default().to_vec();
                            if !body.is_empty() {
                                let i = usize::from(at) % body.len();
                                body[i] ^= xor.max(1);
                            }
                            frame_change(1, &body)
                        } else {
                            continue;
                        }
                    }
                    Payload::Edit { value, .. } | Payload::Mutated { value, .. } => value.into_bytes(),
                    Payload::Framed(body) => frame_change(1, &body),
                    Payload::Entry { deps, ts_ms, body } => {
                        let deps = deps.iter().filter_map(|i| sent.get(usize::from(*i)).map(Envelope::id)).collect();
                        postcard::to_allocvec(&FeedEntry { deps, ts_ms, body }).unwrap()
                    }
                    Payload::Raw(bytes) => bytes,
                };
                let Ok(env) = seal(&writer, stream, &plaintext, seq, prev, nonce) else { continue };
                if matches!(at, Chain::Next) {
                    chain.push((seq, env.id()));
                }
                sent.push(env);
            }
            Msg::WireEnvelope(bytes) => {
                if let Ok(env) = postcard::from_bytes::<Envelope>(&bytes) {
                    sent.push(env);
                }
            }
            Msg::WireOp(bytes) => {
                if let Ok(op) = postcard::from_bytes::<SignedOp>(&bytes) {
                    ops.push(op);
                }
            }
        }
    }
    let ids: Vec<EnvelopeId> = sent.iter().map(Envelope::id).collect();
    // Replica 1: everything as it arrives, in batches, ops first.
    let mut one = restore(&s.founder, vec![]);
    one.ingest_batch(ops.clone(), vec![]);
    let size = usize::from(input.batch % 8) + 1;
    for chunk in sent.chunks(size) {
        one.ingest_batch(vec![], chunk.to_vec());
    }
    // Replica 2: restored from storage, in reverse order.
    let mut reversed = sent.clone();
    reversed.reverse();
    let mut two = restore(&s.founder, reversed);
    two.ingest_batch(ops, vec![]);
    assert_eq!(state(&mut one, &ids), state(&mut two, &ids), "replicas diverged");
});
