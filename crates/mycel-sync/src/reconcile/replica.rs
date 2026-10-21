//! [`SyncSet`] for [`Replica`]: the canonical set is every stored envelope
//! and every stored, resolvable op (valid or not). Pending ops (missing
//! parents) stay outside it: they are neither summarised nor offered.

use std::collections::HashSet;

use mycel_trust::{OpId, SignedOp, SpaceId};

use super::{ChainIndex, SyncSet};
use crate::{Envelope, EnvelopeId, Replica};

impl SyncSet for Replica {
    type Op = SignedOp;
    type Env = Envelope;

    fn space(&self) -> SpaceId {
        self.space_id()
    }

    fn index(&self) -> &ChainIndex {
        &self.index
    }

    fn op_tips(&self) -> Vec<OpId> {
        let order = &self.graph.resolution().order;
        let parents: HashSet<&OpId> =
            order.iter().filter_map(|id| self.graph.get(id)).flat_map(|op| op.op.parents.iter()).collect();
        let mut tips: Vec<OpId> = order.iter().filter(|id| !parents.contains(id)).copied().collect();
        tips.sort();
        tips
    }

    fn holds_op(&self, id: &OpId) -> bool {
        // (in the resolved graph: stored and not pending)
        self.graph.in_past(id, std::slice::from_ref(id))
    }

    fn ops_after(&self, heads: &[OpId]) -> Vec<OpId> {
        self.graph.resolution().order.iter().filter(|id| !self.graph.in_past(id, heads)).copied().collect()
    }

    fn op_count(&self) -> u64 {
        self.graph.len() as u64
    }

    fn op(&self, id: &OpId) -> Option<SignedOp> {
        self.holds_op(id).then(|| self.graph.get(id).cloned()).flatten()
    }

    fn env(&self, id: &EnvelopeId) -> Option<Envelope> {
        self.envelopes.get(id).cloned()
    }
}

impl Replica {
    /// Ids of `author`'s latest envelopes (at most `n`, newest first): what a
    /// peer that verified our set certainly holds of a chain, for delivery
    /// status without a per-envelope holder pass.
    pub fn recent_envelopes(&self, author: &mycel_crypto::SignPk, n: usize) -> Vec<EnvelopeId> {
        self.index.recent(author, n)
    }
}
