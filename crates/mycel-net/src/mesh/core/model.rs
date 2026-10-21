//! Read-only views of a [`Router`]'s routing state, and one planted bug,
//! for the bounded model checker in `crates/mycel-check` (docs/TESTING.md,
//! "Model checking"). Compiled only with the `model` feature, which no
//! release build turns on. Nothing here changes what a router does, except
//! [`Router::model_plant_infeasible`], which exists to prove the checker
//! can find a real loop.

use mycel_crypto::SignPk;

use super::{INFINITY, Router, Time};

/// One route a router heard for an origin, as the checker sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelVia {
    /// The neighbour that advertised it.
    pub via: SignPk,
    /// The advertised sequence number and cost (the neighbour's own).
    pub seq: u64,
    pub adv: u32,
    /// Our cost through it.
    pub cost: u32,
    /// Feasible, fresh and through a direct neighbour whose hop is up: a
    /// route that can carry traffic now ([`Router::model_usable`]).
    pub usable: bool,
}

impl Router {
    /// Origins we hold an entry for (with routes or only a feasibility
    /// distance), sorted.
    pub fn model_origins(&self) -> Vec<SignPk> {
        let mut v: Vec<SignPk> = self.origins.keys().copied().collect();
        v.sort();
        v
    }

    /// Every route to `origin` we remember (retractions are not stored),
    /// sorted by neighbour.
    pub fn model_vias(&self, origin: &SignPk, now: Time) -> Vec<ModelVia> {
        let Some(o) = self.origins.get(origin) else { return Vec::new() };
        let mut v: Vec<ModelVia> = o
            .via
            .iter()
            .filter(|(_, v)| v.adv != INFINITY)
            .map(|(n, v)| ModelVia { via: *n, seq: v.seq, adv: v.adv, cost: v.cost, usable: self.usable(o, n, v, now) })
            .collect();
        v.sort_by_key(|m| m.via);
        v
    }

    /// The next hops of every route to `origin` that can carry traffic now
    /// (what [`Router::next_hop_local`] and packet forwarding choose
    /// among), sorted.
    pub fn model_usable(&self, origin: &SignPk, now: Time) -> Vec<SignPk> {
        self.model_vias(origin, now).into_iter().filter(|m| m.usable).map(|m| m.via).collect()
    }

    /// Our feasibility distance for `origin`: the (seqno, cost) we last
    /// advertised (Babel, RFC 8966 §3.5.1). `None`: never advertised, or
    /// forgotten.
    pub fn model_fd(&self, origin: &SignPk) -> Option<(u64, u32)> {
        self.origins.get(origin).and_then(|o| o.fd)
    }

    /// Plant a bug: treat every route as feasible. The model checker's
    /// acceptance test turns this on and must find a routing loop.
    pub fn model_plant_infeasible(&mut self, on: bool) {
        self.planted_infeasible = on;
    }
}
