//! `Session::on_msg` with arbitrary frame sequences (structure-aware): one
//! side runs a real Sync v2 session over a model set built from the input;
//! the other side is the fuzzer, whose frames name ids, authors and seqs
//! drawn from a second model set (so they reach deep states: real heads,
//! forks, gaps, probes and closes), or raw postcard bytes.
//!
//! Properties: no panic; every call returns in bounded work (the frames a
//! session sends per input frame, and in all, are bounded); every item a
//! session hands back is one the frame carried (it never fabricates).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mycel_crypto::{Hash32, SignPk};
use mycel_sync::reconcile::model::{Apply, ModelEnv, ModelOp, ModelSet};
use mycel_sync::reconcile::{
    AbortReason, AuthorEntry, Config, Coverage, Frontier, Msg, Open, Run, Scope, Session, SyncSet, Verdict,
};

#[derive(Arbitrary, Debug)]
struct Chain {
    author: u8,
    len: u8,
    fork_at: Option<u8>,
    fork_len: u8,
}

#[derive(Arbitrary, Debug)]
struct Entry {
    author: u8,
    runs: Vec<(u8, u8, u8)>,
    truncated: bool,
}

#[derive(Arbitrary, Debug)]
struct Front {
    delta: bool,
    ops: Option<Vec<u8>>,
    entries: Vec<Entry>,
    more: bool,
}

#[derive(Arbitrary, Debug)]
enum Frame {
    Open { digest_theirs: bool, memory: bool, frontier: Option<Front>, version: u16, features: u8 },
    InSync { theirs: bool },
    Unchanged,
    Diff { frontier: Front, need_full: bool },
    Refusal(u8),
    Frontier(Front),
    Ops(Vec<u8>),
    Chunk(Vec<u8>),
    Probe { author: u8, run: u8, points: Vec<(u8, u8)> },
    ProbeReply { author: u8, run: u8, held: u16, bottoms: Vec<u8> },
    SendsDone(u8),
    Close { phase: u8, all: bool, ops: bool, authors: Vec<u8>, refused: Vec<u8>, digest_theirs: bool, quiet: bool, phase2: bool },
    Abort(u8),
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    server: bool,
    eager: bool,
    allow_phase2: bool,
    mine: Vec<Chain>,
    theirs: Vec<Chain>,
    frames: Vec<Frame>,
}

fn author(i: u8) -> SignPk {
    SignPk([i % 8 + 1; 32])
}

fn build(chains: &[Chain]) -> ModelSet {
    let mut s = ModelSet::new(Hash32([9; 32]));
    for c in chains.iter().take(8) {
        let ids = s.append(author(c.author), u64::from(c.len % 40), 8);
        if let Some(at) = c.fork_at
            && let Some(base) = ids.get(usize::from(at) % ids.len().max(1))
        {
            s.fork(author(c.author), Some(*base), u64::from(c.fork_len % 10) + 1, 1);
        }
    }
    s
}

struct Pools {
    envs: Vec<ModelEnv>,
    ops: Vec<ModelOp>,
}

impl Pools {
    fn env(&self, i: u8) -> Option<&ModelEnv> {
        (!self.envs.is_empty()).then(|| &self.envs[usize::from(i) % self.envs.len()])
    }

    fn id(&self, i: u8) -> Hash32 {
        self.env(i).map_or(Hash32([i; 32]), ModelEnv::id)
    }

    fn op_id(&self, i: u8) -> Hash32 {
        if self.ops.is_empty() { Hash32([i; 32]) } else { self.ops[usize::from(i) % self.ops.len()].id() }
    }

    fn frontier(&self, f: &Front, theirs: &ModelSet) -> Frontier {
        Frontier {
            delta_of: f.delta.then_some(([1; 32], [2; 32])),
            ops: f.ops.as_ref().map(|o| o.iter().take(8).map(|i| self.op_id(*i)).collect()),
            authors: f
                .entries
                .iter()
                .take(16)
                .map(|e| AuthorEntry {
                    author: author(e.author),
                    runs: e
                        .runs
                        .iter()
                        .take(8)
                        .map(|(top, head, bottom)| {
                            let head = self.id(*head);
                            let top = theirs.index().seq(&head).unwrap_or(u64::from(*top));
                            Run { top, head, bottom: u64::from(*bottom).min(top) }
                        })
                        .collect(),
                    truncated: e.truncated.then_some([3; 32]),
                })
                .collect(),
            more: f.more,
        }
    }
}

fn frame(f: &Frame, p: &Pools, theirs: &ModelSet, space: Hash32) -> Option<Msg<ModelOp, ModelEnv>> {
    Some(match f {
        Frame::Open { digest_theirs, memory, frontier, version, features } => Msg::Open(Open {
            version: if *version % 4 == 0 { *version } else { mycel_sync::reconcile::VERSION },
            features: u64::from(*features % 2),
            space,
            nonce: [5; 16],
            digest: if *digest_theirs { theirs.digest() } else { [0; 32] },
            memory: memory.then_some(([1; 32], [2; 32])),
            scope: Scope::Full,
            frontier: frontier.as_ref().map(|f| p.frontier(f, theirs)),
            invite: None,
        }),
        Frame::InSync { theirs: t } => {
            Msg::Status(Verdict::InSync { digest: if *t { theirs.digest() } else { [0; 32] } })
        }
        Frame::Unchanged => Msg::Status(Verdict::Unchanged { digest: theirs.digest() }),
        Frame::Diff { frontier, need_full } => Msg::Status(Verdict::Diff {
            digest: theirs.digest(),
            frontier: p.frontier(frontier, theirs),
            need_full: *need_full,
        }),
        Frame::Refusal(k) => Msg::Status(match k % 5 {
            0 => Verdict::NeedInvite,
            1 => Verdict::Denied,
            2 => Verdict::Removed { ops: p.ops.iter().take(3).cloned().collect() },
            3 => Verdict::Unsupported { version: 2, features: 0 },
            _ => Verdict::Busy { retry_after_ms: 100 },
        }),
        Frame::Frontier(f) => Msg::Frontier(p.frontier(f, theirs)),
        Frame::Ops(ix) => {
            Msg::Ops(ix.iter().take(32).filter_map(|i| (!p.ops.is_empty()).then(|| p.ops[usize::from(*i) % p.ops.len()].clone())).collect())
        }
        Frame::Chunk(ix) => Msg::Chunk(ix.iter().take(64).filter_map(|i| p.env(*i).cloned()).collect()),
        Frame::Probe { author: a, run, points } => Msg::Probe {
            author: author(*a),
            run: p.id(*run),
            points: points
                .iter()
                .take(20)
                .map(|(s, i)| (theirs.index().seq(&p.id(*i)).unwrap_or(u64::from(*s)), p.id(*i)))
                .collect(),
        },
        Frame::ProbeReply { author: a, run, held, bottoms } => Msg::ProbeReply {
            author: author(*a),
            run: p.id(*run),
            held: *held,
            bottoms: bottoms.iter().take(20).map(|b| u64::from(*b)).collect(),
        },
        Frame::SendsDone(ph) => Msg::SendsDone { phase: *ph % 4 },
        Frame::Close { phase, all, ops, authors, refused, digest_theirs, quiet, phase2 } => Msg::Close {
            phase: *phase % 4,
            coverage: if *all {
                Coverage::All
            } else {
                Coverage::Missing { ops: *ops, authors: authors.iter().take(8).map(|a| author(*a)).collect() }
            },
            refused: refused.iter().take(8).map(|i| p.id(*i)).collect(),
            digest: if *digest_theirs { theirs.digest() } else { [0; 32] },
            quiet: *quiet,
            phase2: *phase2,
        },
        Frame::Abort(r) => Msg::Abort {
            reason: match r % 3 {
                0 => AbortReason::Budget,
                1 => AbortReason::Protocol,
                _ => AbortReason::Gone,
            },
        },
        Frame::Raw(bytes) => return postcard::from_bytes(bytes).ok(),
    })
}

/// Frames a session may send in answer to one input frame (a frontier in
/// chunks plus data chunks for every chain of the model sets), and in all.
const PER_FRAME: usize = 4096;
const TOTAL: u64 = 100_000;

fuzz_target!(|input: Input| {
    let mut mine = build(&input.mine);
    let theirs = build(&input.theirs);
    let space = mine.space();
    let (ops, envs) = theirs.all();
    let pools = Pools { envs, ops };
    let cfg = Config { allow_phase2: input.allow_phase2, ..Config::default() };
    let mut frames = input.frames.iter();
    let mut session = if input.server {
        // The first frame a server reads is an `Open`.
        let open = match frames.next().and_then(|f| frame(f, &pools, &theirs, space)) {
            Some(Msg::Open(o)) => o,
            _ => Open {
                version: mycel_sync::reconcile::VERSION,
                features: 0,
                space,
                nonce: [5; 16],
                digest: theirs.digest(),
                memory: None,
                scope: Scope::Full,
                frontier: None,
                invite: None,
            },
        };
        Session::accept(&mine, cfg, open, None)
    } else {
        Session::open(&mine, cfg, [6; 16], None, input.eager, None)
    };
    let drain = |s: &mut Session<ModelSet>, set: &ModelSet| {
        let mut n = 0;
        while s.poll_send(set).is_some() {
            n += 1;
            assert!(n <= PER_FRAME, "a session sent more than {PER_FRAME} frames for one input frame");
        }
    };
    drain(&mut session, &mine);
    for f in frames.take(64) {
        let Some(msg) = frame(f, &pools, &theirs, space) else { continue };
        let carried: Vec<Hash32> = match &msg {
            Msg::Chunk(e) => e.iter().map(ModelEnv::id).collect(),
            Msg::Ops(o) => o.iter().map(ModelOp::id).collect(),
            _ => Vec::new(),
        };
        match session.on_msg(&mine, msg) {
            Ok(items) => {
                for id in items.envelopes.iter().map(ModelEnv::id).chain(items.ops.iter().map(ModelOp::id)) {
                    assert!(carried.contains(&id), "the session handed back an item the frame didn't carry");
                }
                let (new, refused) = mine.apply(items);
                session.ingested(new, &refused);
            }
            Err(_) => session.abort(AbortReason::Protocol),
        }
        drain(&mut session, &mine);
        assert!(session.stats().sent_frames <= TOTAL);
        if session.is_done() {
            break;
        }
    }
    let _ = (session.outcome(), session.record(), session.stats());
});
