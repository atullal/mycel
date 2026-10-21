//! Tier 2: a discrete-event simulation of routing for up to 100k+ devices,
//! in virtual time, with the routing logic as sans-IO [`Router`]s.

pub mod dtn;
pub mod engine;
pub mod global;
pub mod lfr;
pub mod mycel;
pub mod oracle;
pub mod swarm;
pub mod world;

use serde::{Deserialize, Serialize};

pub use engine::{Action, Area, HOUR, Inet, MIN, MS, MsgId, NodeId, NodeSpec, Router, SEC, Sim, Techs, Time};

use crate::stats::{P99_MIN_N, Summary, Tail, jain, max_share};

/// What a tier-2 run measured.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct T2Metrics {
    pub model: String,
    pub nodes: usize,
    pub sim_seconds: f64,
    pub sent: usize,
    /// Messages the oracle says could have been delivered at all.
    pub feasible: usize,
    pub delivered: usize,
    /// delivered / feasible.
    pub delivery_ratio: f64,
    /// Seconds from send to delivery.
    pub latency_s: Summary,
    /// achieved / optimal latency, per delivered message with an oracle
    /// answer. Written out without p99 below [`P99_MIN_N`] ratios: at a few
    /// hundred it is one of the few slowest ([`Tail`] has what holds).
    #[serde(serialize_with = "ratios_without_small_p99")]
    pub optimality: Summary,
    /// The tail of the same ratios in numbers that hold at a few hundred
    /// messages (p95 with its interval, CVaR₉₅, counts over 10× and 30×).
    #[serde(default)]
    pub optimality_tail: Tail,
    /// The ratios themselves, for pooling across seeds (not reported).
    #[serde(skip)]
    pub optimality_ratios: Vec<f64>,
    /// Seconds from send to the receipt (or a call's answer) at the sender.
    pub round_trip_s: Summary,
    /// Copies of each message that came to exist (1 = no duplication).
    pub copies_per_msg: f64,
    /// Carrier-to-carrier hand-offs per message (replicas and custody moves).
    #[serde(default)]
    pub handoffs_per_msg: f64,
    /// Control (announcements, summaries, receipts) per device per second.
    pub ctrl_bytes_per_node_s: f64,
    pub ctrl_frames_per_node_s: f64,
    /// Relay load across devices that relayed: Jain's index and the largest share.
    pub relay_jain: f64,
    pub relay_max_share: f64,
    pub relays: usize,
    pub peak_stored: u64,
    pub events: u64,
    pub wall_s: f64,
}

/// [`T2Metrics::optimality`] as written out: p99 only from [`P99_MIN_N`]
/// ratios on.
fn ratios_without_small_p99<S: serde::Serializer>(s: &Summary, ser: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ratios {
        n: usize,
        mean: f64,
        p50: f64,
        p95: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        p99: Option<f64>,
        max: f64,
    }
    Ratios { n: s.n, mean: s.mean, p50: s.p50, p95: s.p95, p99: (s.n >= P99_MIN_N).then_some(s.p99), max: s.max }
        .serialize(ser)
}

/// Summarise a finished run (`finish` + oracle annotations done).
pub fn metrics<R: Router>(
    sim: &Sim<R>,
    model: &str,
    wall_s: f64,
    only: Option<&dyn Fn(&engine::MsgRecord) -> bool>,
) -> T2Metrics {
    let msgs: Vec<&engine::MsgRecord> = sim.core.msgs.iter().filter(|m| only.is_none_or(|f| f(m))).collect();
    let n = sim.core.len();
    let secs = sim.now as f64 / SEC as f64;
    // feasible: of the messages the oracle checked (a sample in big runs),
    // those it found a path for or that got there anyway
    let feasible: Vec<&&engine::MsgRecord> =
        msgs.iter().filter(|m| m.checked && (m.optimal.is_some() || m.delivered.is_some())).collect();
    let delivered: Vec<&&engine::MsgRecord> = msgs.iter().filter(|m| m.delivered.is_some()).collect();
    let delivered_feasible = feasible.iter().filter(|m| m.delivered.is_some()).count();
    let lat: Vec<f64> = delivered.iter().map(|m| (m.delivered.unwrap() - m.sent) as f64 / SEC as f64).collect();
    let opt: Vec<f64> = delivered
        .iter()
        .filter_map(|m| {
            let o = m.optimal? - m.sent;
            let a = m.delivered? - m.sent;
            Some(a as f64 / o.max(1) as f64)
        })
        .collect();
    let rt: Vec<f64> = msgs.iter().filter_map(|m| Some((m.receipt? - m.sent) as f64 / SEC as f64)).collect();
    let copies =
        if msgs.is_empty() { 0.0 } else { msgs.iter().map(|m| m.copies as f64).sum::<f64>() / msgs.len() as f64 };
    let handoffs =
        if msgs.is_empty() { 0.0 } else { msgs.iter().map(|m| m.handoffs as f64).sum::<f64>() / msgs.len() as f64 };
    let ctrl_b: u64 = sim.core.counters.iter().map(|c| c.ctrl_bytes).sum();
    let ctrl_f: u64 = sim.core.counters.iter().map(|c| c.ctrl_frames).sum();
    let relay: Vec<f64> = sim.core.counters.iter().map(|c| c.relay_bytes as f64).filter(|b| *b > 0.0).collect();
    if std::env::var_os("MYCEL_SIM_EVENTS").is_some() {
        let k = sim.core.events_by_kind;
        eprintln!(
            "[events] {model}: frames {} timers {} lookups {} sends {} mobility {} actions {} probes {}",
            k[0], k[1], k[2], k[3], k[4], k[5], k[6]
        );
    }
    T2Metrics {
        model: model.to_string(),
        nodes: n,
        sim_seconds: secs,
        sent: msgs.len(),
        feasible: feasible.len(),
        delivered: delivered.len(),
        delivery_ratio: if feasible.is_empty() { 0.0 } else { delivered_feasible as f64 / feasible.len() as f64 },
        latency_s: Summary::of(&lat),
        optimality: Summary::of(&opt),
        optimality_tail: Tail::of(&opt),
        optimality_ratios: opt.clone(),
        round_trip_s: Summary::of(&rt),
        copies_per_msg: copies,
        handoffs_per_msg: handoffs,
        ctrl_bytes_per_node_s: ctrl_b as f64 / n.max(1) as f64 / secs.max(1e-9),
        ctrl_frames_per_node_s: ctrl_f as f64 / n.max(1) as f64 / secs.max(1e-9),
        relay_jain: jain(&relay),
        relay_max_share: max_share(&relay),
        relays: relay.len(),
        peak_stored: sim.core.counters.iter().map(|c| c.stored_peak).max().unwrap_or(0),
        events: sim.core.events_run,
        wall_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimality_p99_is_written_only_from_4000_ratios() {
        let few = T2Metrics { optimality: Summary::of(&[1.0; 400]), ..T2Metrics::default() };
        let v = serde_json::to_value(&few).expect("json");
        assert!(v["optimality"].get("p99").is_none() && v["optimality"]["p95"] == 1.0, "{v}");
        let many = T2Metrics { optimality: Summary::of(&vec![1.0; P99_MIN_N]), ..T2Metrics::default() };
        assert_eq!(serde_json::to_value(&many).expect("json")["optimality"]["p99"], 1.0);
        // latency keeps its p99 (a summary of seconds, not a verdict)
        assert!(v["latency_s"].get("p99").is_some());
    }
}
