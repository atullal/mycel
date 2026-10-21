//! A catalogue [`Spec`] plus parameter values → a tier-2 world and plan.
//!
//! The uncertain parameters ([`Knobs`]) start at the scenario's nominal
//! values and a robustness study overrides them. Every random choice is
//! keyed per entity ([`keyed`]), so a device keeps its place, radios,
//! internet and attacker rank as other parameters move.
//!
//! **Range multiplier.** The disc radio's range is a constant per
//! technology and environment (`models.rs`). Scaling every range by m is,
//! for a disc, exactly the same as scaling every distance by 1/m: places,
//! area sizes and walking speeds (pauses and timings unchanged). So
//! `range_mult` is applied to the geometry, and the engine and its oracle
//! are untouched. (It is exact only for a uniform multiplier on a disc; a
//! physical radio model (WP7) replaces it with link-budget parameters.)

use crate::catalogue::{AccessMix, Dest, Layout, MobilityModel, OutageScope, SWARM_TOGGLES, Spec, WorkloadSpec};
use crate::models::{Access, Env, Nat, Tech};
use crate::scenarios::t2::{GCfg, Plan, World};
use crate::stats::{Map, mix64};
use crate::tier2::engine::{Mobility, NodeSpec};
use crate::tier2::mycel::Role;
use crate::tier2::world::CITIES;
use crate::tier2::{Action, Area, Inet, MIN, NodeId, SEC, Techs, Time};
use crate::uq::sample::norm_quantile;

/// A uniform in [0, 1) keyed by (seed, purpose, entity, k): the same
/// entity gets the same draw whatever else changes.
pub fn keyed(seed: u64, purpose: u64, entity: u64, k: u64) -> f64 {
    let h =
        mix64(seed ^ mix64(purpose.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ mix64(entity ^ mix64(k ^ 0x6b65_7965_6400))));
    (h >> 11) as f64 / (1u64 << 53) as f64
}

// purposes of keyed draws
const P_X: u64 = 1;
const P_Y: u64 = 2;
const P_KIND: u64 = 3;
const P_BLE: u64 = 4;
const P_INET: u64 = 5;
const P_ACCESS: u64 = 6;
const P_NAT: u64 = 7;
const P_ADV: u64 = 8;
const P_MOVE: u64 = 9;
const P_BATTERY: u64 = 10;
const P_CHURN: u64 = 11;
const P_STORM: u64 = 12;
const P_SRC: u64 = 13;
const P_DST: u64 = 14;
const P_CALL: u64 = 15;
const P_CLUSTER: u64 = 16;
const P_CHURN_AT: u64 = 17;
const P_TRACE: u64 = 18;
const P_AWAY: u64 = 19;

/// The parameters a robustness study varies, at their values for one run.
#[derive(Clone, Debug, PartialEq)]
pub struct Knobs {
    pub range_mult: f64,
    pub adoption: f64,
    pub inet_share: f64,
    pub nat_hard: f64,
    pub max_neighbours: usize,
    pub walk_speed: f64,
    pub pause_s: f64,
    pub msg_rate: f64,
    pub adversary_share: f64,
    pub battery_median_h: Option<f64>,
    pub ios_share: f64,
    pub ble_only_share: f64,
    pub churn_per_min: f64,
    pub mule_share: f64,
}

impl Knobs {
    /// The scenario's own values.
    pub fn nominal(s: &Spec) -> Knobs {
        let n = |k: &str| s.nominal(k).expect("builtin");
        Knobs {
            range_mult: 1.0,
            adoption: n("adoption"),
            inet_share: n("inet_share"),
            nat_hard: n("nat_hard"),
            max_neighbours: n("max_neighbours") as usize,
            walk_speed: n("walk_speed"),
            pause_s: n("pause_s"),
            msg_rate: 1.0,
            adversary_share: n("adversary_share"),
            battery_median_h: s.os.battery_median_h,
            ios_share: n("ios_share"),
            ble_only_share: n("ble_only_share"),
            churn_per_min: n("churn_per_min"),
            mule_share: n("mule_share"),
        }
    }

    /// Set the named parameter (a study's point).
    pub fn set(&mut self, name: &str, v: f64) -> anyhow::Result<()> {
        match name {
            "range_mult" => self.range_mult = v,
            "adoption" => self.adoption = v,
            "inet_share" => self.inet_share = v,
            "nat_hard" => self.nat_hard = v,
            "max_neighbours" => self.max_neighbours = v.round().max(1.0) as usize,
            "walk_speed" => self.walk_speed = v,
            "pause_s" => self.pause_s = v,
            "msg_rate" => self.msg_rate = v,
            "adversary_share" => self.adversary_share = v,
            "battery_median_h" => self.battery_median_h = Some(v),
            "ios_share" => self.ios_share = v,
            "ble_only_share" => self.ble_only_share = v,
            "churn_per_min" => self.churn_per_min = v,
            "mule_share" => self.mule_share = v,
            _ => anyhow::bail!("unknown parameter {name:?}"),
        }
        Ok(())
    }
}

/// Swarm toggles switched off for one run (WP20 draws random subsets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swarm {
    pub off: Vec<String>,
}

impl Swarm {
    pub fn on(&self, t: &str) -> bool {
        debug_assert!(SWARM_TOGGLES.contains(&t), "{t}");
        !self.off.iter().any(|x| x == t)
    }

    /// The routing core's settings with the core's toggles applied.
    pub fn gcfg(&self) -> GCfg {
        let mut g = GCfg::default();
        g.fisheye &= self.on("fisheye");
        g.flood_reduction &= self.on("flood-reduction");
        g.dtn &= self.on("dtn");
        g
    }
}

/// One run's size: people present and how long.
#[derive(Clone, Copy, Debug)]
pub struct Size {
    pub people: usize,
    pub duration: Time,
}

impl Size {
    pub fn ci(s: &Spec) -> Size {
        Size { people: s.size.ci_people, duration: min(s.size.ci_duration_min.unwrap_or(s.size.duration_min)) }
    }

    pub fn full(s: &Spec) -> Size {
        Size { people: s.size.people, duration: min(s.size.duration_min) }
    }
}

fn min(m: f64) -> Time {
    (m * MIN as f64) as Time
}

/// A composed run: the world, the plan, how long, and how many messages
/// the oracle checks.
pub struct Composed {
    pub world: World,
    pub plan: Plan,
    pub until: Time,
    pub sample: Option<usize>,
    pub gcfg: GCfg,
    /// The Mycel devices in the scenario's region (not the far city's).
    pub devices: usize,
    pub attackers: usize,
}

/// A city's (lat, lon) and internet adoption from the world model.
pub fn city(name: &str) -> Option<((f64, f64), f64)> {
    CITIES.iter().find(|c| c.0 == name).map(|c| ((c.1, c.2), c.4))
}

/// An adversary role by its catalogue name (and whether it poisons lookups).
pub fn role(name: &str) -> Option<(Role, bool)> {
    Some(match name {
        "blackhole" => (Role::BlackHole, false),
        "liar" => (Role::Liar, false),
        "attested-liar" => (Role::AttestedLiar, false),
        "dropper" => (Role::Dropper, false),
        "greyhole" => (Role::GreyHole, false),
        "storm" => (Role::Storm, false),
        "replayer" => (Role::Replayer, false),
        "sybil-directory" => (Role::BlackHole, true),
        _ => return None,
    })
}

/// Build the run.
pub fn compose(s: &Spec, k: &Knobs, size: Size, swarm: &Swarm, seed: u64) -> anyhow::Result<Composed> {
    let r = &s.region;
    let m = k.range_mult;
    anyhow::ensure!(m > 0.0 && m.is_finite(), "range multiplier {m}");
    let mut w = World { areas: Vec::new(), specs: Vec::new() };
    let mut plan = Plan { max_neighbours: Some(k.max_neighbours), ..Plan::default() };
    // the trace layout: a trace's devices and contacts (no geometry)
    if r.layout == Layout::Trace {
        return compose_trace(s, k, size, swarm, seed);
    }
    let n = s.devices_at(size.people, k.adoption);
    // keep density: the area shrinks with the population (a line keeps its spacing)
    let f = size.people as f64 / s.size.people as f64;
    let (width, height) = match r.layout {
        Layout::Line => (r.width_m * f, r.height_m),
        _ => (r.width_m * f.sqrt(), r.height_m * f.sqrt()),
    };
    let (width, height) = (width / m, height / m);
    let cluster_r = r.cluster_radius_m / m;
    let areas: Vec<((f64, f64), f64)> = match r.layout {
        Layout::Cities => r.cities.iter().map(|c| city(c).expect("validated")).collect(),
        _ => vec![((r.latlon[0], r.latlon[1]), k.inet_share)],
    };
    for (ll, _) in &areas {
        w.areas.push(Area { latlon: *ll, env: r.env.env() });
    }
    // cluster centres: a jittered grid over the area, keyed per cluster
    let clusters = r.clusters.max(1);
    let cols = (clusters as f64).sqrt().ceil() as usize;
    let rows = clusters.div_ceil(cols);
    let centre = |c: usize| -> (f64, f64) {
        let (cx, cy) = (c % cols, c / cols);
        let jx = keyed(seed, P_CLUSTER, c as u64, 0) - 0.5;
        let jy = keyed(seed, P_CLUSTER, c as u64, 1) - 0.5;
        ((cx as f64 + 0.5 + 0.4 * jx) * width / cols as f64, (cy as f64 + 0.5 + 0.4 * jy) * height / rows as f64)
    };
    // internet: the devices with the lowest keyed draw get it (a nested
    // set as the share grows); at least one if the share is above 0
    let mut inet_rank: Vec<(f64, usize)> = (0..n).map(|i| (keyed(seed, P_INET, i as u64, 0), i)).collect();
    inet_rank.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut has_inet = vec![false; n];
    let share_of = |i: usize| -> f64 {
        match r.layout {
            Layout::Cities if s.internet.share == 0.0 && s.internet.gateways.is_none() => areas[i % areas.len()].1,
            _ => k.inet_share,
        }
    };
    if r.layout == Layout::Cities && s.internet.share == 0.0 && s.internet.gateways.is_none() {
        for (i, h) in has_inet.iter_mut().enumerate() {
            *h = keyed(seed, P_INET, i as u64, 0) < share_of(i);
        }
    } else {
        let count = (k.inet_share * n as f64).round() as usize;
        let count = if k.inet_share > 0.0 { count.max(1) } else { 0 };
        for (_, i) in inet_rank.iter().take(count.min(n)) {
            has_inet[*i] = true;
        }
    }
    for (i, inet_here) in has_inet.iter().copied().enumerate() {
        let u = |p: u64| keyed(seed, p, i as u64, 0);
        let (area, xy) = match r.layout {
            Layout::Field => (0, (u(P_X) * width, u(P_Y) * height)),
            Layout::Line => (0, (u(P_X) * width, (u(P_Y) - 0.5) * height)),
            Layout::Cities => ((i % areas.len()) as u32, (u(P_X) * width, u(P_Y) * height)),
            Layout::Clusters => {
                let c = centre(i % clusters);
                // uniform in a disc of radius cluster_r
                let rad = cluster_r * u(P_X).sqrt();
                let ang = std::f64::consts::TAU * u(P_Y);
                (0, (c.0 + rad * ang.cos(), c.1 + rad * ang.sin()))
            }
            Layout::Trace => unreachable!("handled above"),
        };
        let radios = if u(P_BLE) < k.ble_only_share {
            Techs::of(&[Tech::Ble])
        } else if u(P_KIND) < k.ios_share {
            Techs::of(&[Tech::Ble, Tech::Awdl])
        } else {
            Techs::of(&[Tech::Ble, Tech::WifiDirect])
        };
        let inet = inet_here.then(|| inet_for(s.internet.access, u(P_ACCESS), u(P_NAT), k.nat_hard));
        let moving = match s.mobility.model {
            MobilityModel::Static => false,
            MobilityModel::Waypoint | MobilityModel::Mules => u(P_MOVE) < k.mule_share,
        };
        let mobility = if moving {
            Mobility::Waypoint { w: width, h: height, speed: k.walk_speed / m, pause: (k.pause_s * SEC as f64) as Time }
        } else {
            Mobility::Static
        };
        w.specs.push(NodeSpec { area, xy, radios, inet, mobility, online: true });
    }
    // devices in a far city on home broadband
    let abroad: Vec<NodeId> = if s.internet.abroad > 0 {
        let a = w.areas.len() as u32;
        w.areas.push(Area { latlon: (40.71, -74.01), env: Env::Indoor });
        (0..s.internet.abroad)
            .map(|j| {
                let id = w.specs.len() as NodeId;
                let inet = Inet { access: Access::Fibre, nat: Nat::Easy };
                w.specs.push(NodeSpec {
                    area: a,
                    xy: (j as f64 * 1000.0, 0.0),
                    radios: Techs::NONE,
                    inet: Some(inet),
                    mobility: Mobility::Static,
                    online: true,
                });
                id
            })
            .collect()
    } else {
        Vec::new()
    };
    let attackers = assign_adversaries(s, k, n, swarm, seed, &mut plan);
    os_actions(s, k, n, size.duration, swarm, seed, &mut plan);
    outages(s, &w, n, swarm, &mut plan);
    let near = |a: usize, b: usize| -> bool {
        match r.layout {
            Layout::Clusters => a % clusters == b % clusters,
            Layout::Cities => a % areas.len() == b % areas.len(),
            _ => {
                let (p, q) = (w.specs[a].xy, w.specs[b].xy);
                ((p.0 - q.0).powi(2) + (p.1 - q.1).powi(2)).sqrt() <= 200.0 / m
            }
        }
    };
    workload(&s.workload, k, n, size.duration, seed, &plan.roles.clone(), &abroad, &near, &mut plan);
    Ok(Composed {
        world: w,
        plan,
        until: size.duration,
        sample: (n > 2000).then_some(300),
        gcfg: swarm.gcfg(),
        devices: n,
        attackers,
    })
}

fn inet_for(mix: AccessMix, ua: f64, un: f64, nat_hard: f64) -> Inet {
    let cellular = |ua: f64, un: f64| Inet {
        access: if ua < 0.4 { Access::FiveG } else { Access::Lte },
        nat: if un < nat_hard { Nat::Hard } else { Nat::Easy },
    };
    // home: 80% easy, 10% open, 10% hard (tier2/world.rs `home`)
    let home = |ua: f64, un: f64| Inet {
        access: if ua < 0.5 { Access::Fibre } else { Access::Cable },
        nat: if un < 0.8 {
            Nat::Easy
        } else if un < 0.9 {
            Nat::Open
        } else {
            Nat::Hard
        },
    };
    match mix {
        AccessMix::Cellular => cellular(ua, un),
        AccessMix::Home => home(ua, un),
        AccessMix::Satellite => Inet { access: Access::Slow, nat: Nat::Easy },
        // 25% home broadband, 75% cellular (tier2/world.rs `global`)
        AccessMix::Mixed => {
            if ua < 0.25 {
                home(ua / 0.25, un)
            } else {
                cellular((ua - 0.25) / 0.75, un)
            }
        }
    }
}

/// Attackers: devices ranked by a keyed draw take the roles in order, so
/// a larger share adds attackers and keeps the earlier ones. The shares
/// are scaled to sum to `adversary_share`. Returns how many.
fn assign_adversaries(s: &Spec, k: &Knobs, n: usize, swarm: &Swarm, seed: u64, plan: &mut Plan) -> usize {
    if s.adversaries.is_empty() || !swarm.on("adversaries") {
        return 0;
    }
    let total: f64 = s.adversaries.iter().map(|a| a.share).sum();
    let scale = if total > 0.0 { k.adversary_share / total } else { 0.0 };
    let mut rank: Vec<(f64, usize)> = (0..n).map(|i| (keyed(seed, P_ADV, i as u64, 0), i)).collect();
    rank.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut next = rank.into_iter().map(|x| x.1);
    let mut count = 0;
    for a in &s.adversaries {
        let (role, poison) = role(&a.role).expect("validated");
        let want = (a.share * scale * n as f64).round() as usize;
        for d in next.by_ref().take(want) {
            plan.roles.insert(d as NodeId, role);
            if poison && plan.poison.is_none() {
                plan.poison = Some(d as NodeId);
            }
            count += 1;
        }
    }
    count
}

/// Battery deaths, churn and restart storms, as scheduled actions.
fn os_actions(s: &Spec, k: &Knobs, n: usize, until: Time, swarm: &Swarm, seed: u64, plan: &mut Plan) {
    if let (Some(median), true) = (k.battery_median_h, swarm.on("battery")) {
        let sigma = s.os.battery_sigma.unwrap_or(0.5);
        for i in 0..n {
            // log-normal time to death around the median, keyed per device
            let z = norm_quantile(keyed(seed, P_BATTERY, i as u64, 0));
            let t = (median * (sigma * z).exp() * 3600.0 * SEC as f64) as Time;
            if t < until {
                plan.acts.push((t, Action::Online(i as NodeId, false)));
            }
        }
    }
    if k.churn_per_min > 0.0 && swarm.on("churn") {
        // each minute a keyed share switches off, and is back the next
        let minutes = until / MIN;
        for mi in 1..minutes {
            for i in 0..n {
                if keyed(seed, P_CHURN, i as u64, mi) < k.churn_per_min {
                    let at = mi * MIN + (keyed(seed, P_CHURN_AT, i as u64, mi) * 60.0) as Time * SEC;
                    plan.acts.push((at, Action::Online(i as NodeId, false)));
                    plan.acts.push((at + MIN, Action::Online(i as NodeId, true)));
                }
            }
        }
    }
    if let (Some(a), true) = (&s.os.away, swarm.on("churn")) {
        for i in 0..n {
            if keyed(seed, P_AWAY, i as u64, 0) < a.share {
                plan.acts.push((min(a.at_min), Action::Online(i as NodeId, false)));
                plan.acts.push((min(a.at_min + 60.0 * a.hours), Action::Online(i as NodeId, true)));
            }
        }
    }
    if let (Some(st), true) = (&s.os.restart_storm, swarm.on("churn")) {
        for i in 0..n {
            let at = min(st.at_min + keyed(seed, P_STORM, i as u64, 0) * st.within_min);
            let back = at + (st.downtime_s * SEC as f64) as Time;
            if at < until {
                plan.acts.push((at, Action::Online(i as NodeId, false)));
                plan.acts.push((back, Action::Online(i as NodeId, true)));
            }
        }
    }
}

fn outages(s: &Spec, w: &World, n: usize, swarm: &Swarm, plan: &mut Plan) {
    if !swarm.on("outages") {
        return;
    }
    for o in &s.internet.outages {
        for (i, spec) in w.specs.iter().enumerate().take(n) {
            let Some(inet) = spec.inet else { continue };
            let cellular = matches!(inet.access, Access::Lte | Access::FiveG);
            if o.scope == OutageScope::All || cellular {
                plan.acts.push((min(o.at_min), Action::Inet(i as NodeId, false)));
                if let Some(u) = o.until_min {
                    plan.acts.push((min(u), Action::Inet(i as NodeId, true)));
                }
            }
        }
    }
}

/// The messages: a steady rate between honest devices, keyed per message.
#[allow(clippy::too_many_arguments)]
fn workload(
    wl: &WorkloadSpec,
    k: &Knobs,
    n: usize,
    until: Time,
    seed: u64,
    roles: &Map<NodeId, Role>,
    abroad: &[NodeId],
    near: &dyn Fn(usize, usize) -> bool,
    plan: &mut Plan,
) {
    let honest: Vec<usize> = (0..n).filter(|i| !roles.contains_key(&(*i as NodeId))).collect();
    if honest.len() < 2 {
        return;
    }
    let start = min(wl.start_min);
    let end = until.saturating_sub(min(wl.drain_min)).max(start + SEC);
    let hours = (end - start) as f64 / 3_600_000_000.0;
    let count = ((wl.per_device_hour * k.msg_rate * n as f64 * hours).round() as usize)
        .clamp(wl.min_messages, wl.max_messages.max(wl.min_messages));
    for m in 0..count {
        let at = start + ((m as f64 + 0.5) / count as f64 * (end - start) as f64) as Time;
        let src = honest[(keyed(seed, P_SRC, m as u64, 0) * honest.len() as f64) as usize % honest.len()];
        let u = keyed(seed, P_DST, m as u64, 0);
        let dst = match wl.dest {
            Dest::Abroad => abroad[(u * abroad.len() as f64) as usize % abroad.len()] as usize,
            Dest::Any => honest[(u * honest.len() as f64) as usize % honest.len()],
            Dest::Near | Dest::Far => {
                let want_near = wl.dest == Dest::Near;
                let pool: Vec<usize> =
                    honest.iter().copied().filter(|d| *d != src && near(src, *d) == want_near).collect();
                if pool.is_empty() {
                    continue;
                }
                pool[(u * pool.len() as f64) as usize % pool.len()]
            }
        };
        if dst == src {
            continue;
        }
        let call = keyed(seed, P_CALL, m as u64, 0) < wl.calls_share;
        plan.sends.push((at, src as NodeId, dst as NodeId, if call { 300 } else { wl.size_bytes }, call));
    }
}

/// A trace's devices and contacts (the synthetic trace, or MYCEL_TRACE).
fn compose_trace(s: &Spec, k: &Knobs, size: Size, swarm: &Swarm, seed: u64) -> anyhow::Result<Composed> {
    let trace = match s.region.trace.as_deref() {
        Some("env") => {
            let p = std::env::var("MYCEL_TRACE").map_err(|_| anyhow::anyhow!("trace = \"env\" needs MYCEL_TRACE"))?;
            crate::traces::load(std::path::Path::new(&p))?
        }
        _ => {
            let nodes = s.devices_at(size.people, k.adoption);
            crate::traces::synthetic(nodes, size.duration, mix64(seed ^ P_TRACE))
        }
    };
    let n = trace.nodes;
    let mut w = World {
        areas: vec![Area { latlon: (s.region.latlon[0], s.region.latlon[1]), env: s.region.env.env() }],
        specs: (0..n)
            .map(|i| NodeSpec {
                area: 0,
                xy: (i as f64 * 1000.0, 0.0),
                radios: Techs::of(&[Tech::Ble]),
                inet: None,
                mobility: Mobility::Static,
                online: true,
            })
            .collect(),
    };
    let ble = Techs::of(&[Tech::Ble]);
    let mut plan = Plan { max_neighbours: Some(k.max_neighbours), ..Plan::default() };
    for (st, e, a, b) in &trace.contacts {
        if *st >= size.duration {
            continue;
        }
        plan.acts.push((*st, Action::Contact(*a, *b, ble, true)));
        plan.acts.push(((*e).max(*st + 1), Action::Contact(*a, *b, ble, false)));
    }
    for (i, spec) in w.specs.iter_mut().enumerate() {
        if keyed(seed, P_INET, i as u64, 0) < k.inet_share {
            spec.inet = Some(inet_for(s.internet.access, keyed(seed, P_ACCESS, i as u64, 0), 0.0, k.nat_hard));
        }
    }
    let attackers = assign_adversaries(s, k, n, swarm, seed, &mut plan);
    os_actions(s, k, n, size.duration, swarm, seed, &mut plan);
    workload(&s.workload, k, n, size.duration, seed, &plan.roles.clone(), &[], &|_, _| true, &mut plan);
    Ok(Composed {
        world: w,
        plan,
        until: size.duration,
        sample: (n > 2000).then_some(300),
        gcfg: swarm.gcfg(),
        devices: n,
        attackers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{all, find};

    #[test]
    fn keyed_draws_are_stable_and_distinct() {
        assert_eq!(keyed(1, 2, 3, 4), keyed(1, 2, 3, 4));
        assert_ne!(keyed(1, 2, 3, 4), keyed(1, 2, 3, 5));
        assert_ne!(keyed(1, 2, 3, 4), keyed(1, 3, 3, 4));
        let mean = (0..10_000).map(|i| keyed(9, 1, i, 0)).sum::<f64>() / 10_000.0;
        assert!((mean - 0.5).abs() < 0.01);
    }

    /// Common random numbers across a study's points: raising the
    /// adoption adds devices and keeps the first ones where they were;
    /// raising the attacker share keeps the earlier attackers.
    #[test]
    fn worlds_nest_as_parameters_grow() {
        let s = find("protest-shutdown").unwrap();
        let size = Size::ci(&s);
        let mut k = Knobs::nominal(&s);
        let a = compose(&s, &k, size, &Swarm::default(), 5).unwrap();
        k.adversary_share *= 2.0;
        let b = compose(&s, &k, size, &Swarm::default(), 5).unwrap();
        assert!(b.attackers > a.attackers);
        for d in a.plan.roles.keys() {
            assert!(b.plan.roles.contains_key(d), "attacker {d} stays one at a larger share");
        }
        // the same message count; a few more or fewer skipped as the honest set shrinks
        assert!(a.plan.sends.len().abs_diff(b.plan.sends.len()) <= a.plan.sends.len() / 50 + 1);
        k.adoption *= 1.5;
        let c = compose(&s, &k, size, &Swarm::default(), 5).unwrap();
        assert!(c.devices > a.devices);
        for (x, y) in a.world.specs.iter().zip(&c.world.specs).take(a.devices) {
            assert_eq!(x.xy, y.xy);
            assert_eq!(x.radios, y.radios);
        }
    }

    #[test]
    fn the_range_multiplier_scales_the_geometry() {
        let s = find("festival").unwrap();
        let size = Size::ci(&s);
        let mut k = Knobs::nominal(&s);
        let a = compose(&s, &k, size, &Swarm::default(), 1).unwrap();
        k.range_mult = 2.0;
        let b = compose(&s, &k, size, &Swarm::default(), 1).unwrap();
        for (x, y) in a.world.specs.iter().zip(&b.world.specs) {
            assert!((x.xy.0 / 2.0 - y.xy.0).abs() < 1e-9 && (x.xy.1 / 2.0 - y.xy.1).abs() < 1e-9);
            if let (Mobility::Waypoint { speed: s1, w: w1, .. }, Mobility::Waypoint { speed: s2, w: w2, .. }) =
                (&x.mobility, &y.mobility)
            {
                assert!((s1 / 2.0 - s2).abs() < 1e-12 && (w1 / 2.0 - w2).abs() < 1e-9);
            }
        }
    }

    #[test]
    fn every_runnable_scenario_composes_at_ci_size() {
        for s in all() {
            let c = compose(&s, &Knobs::nominal(&s), Size::ci(&s), &Swarm::default(), 1)
                .unwrap_or_else(|e| panic!("{}: {e:#}", s.name));
            assert!(c.devices >= 4, "{}", s.name);
            assert!(!c.plan.sends.is_empty(), "{}: no messages", s.name);
            let n = c.world.specs.len() as NodeId;
            for (_, a, b, _, _) in &c.plan.sends {
                assert!(*a < n && *b < n && a != b, "{}", s.name);
            }
            let gw = c.world.specs.iter().take(c.devices).filter(|x| x.inet.is_some()).count();
            let k = Knobs::nominal(&s);
            if k.inet_share > 0.0 && s.region.layout != Layout::Trace && s.region.layout != Layout::Cities {
                assert!(gw >= 1, "{}: internet share {} but no gateway", s.name, k.inet_share);
            }
        }
    }

    #[test]
    fn swarm_toggles_switch_features_off() {
        let s = find("protest-shutdown").unwrap();
        let k = Knobs::nominal(&s);
        let on = compose(&s, &k, Size::ci(&s), &Swarm::default(), 1).unwrap();
        let off = Swarm { off: vec!["adversaries".into(), "outages".into(), "dtn".into()] };
        let c = compose(&s, &k, Size::ci(&s), &off, 1).unwrap();
        assert!(on.attackers > 0 && c.attackers == 0);
        assert!(c.plan.acts.len() < on.plan.acts.len());
        assert!(!c.gcfg.dtn && on.gcfg.dtn);
    }
}
