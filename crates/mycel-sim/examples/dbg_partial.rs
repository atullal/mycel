//! Debug aid: step the partial-route world (300 m gap) and print where the
//! message is held and where the mule is.

use std::rc::Rc;

use mycel_sim::models::Env;
use mycel_sim::stats::Rng;
use mycel_sim::tier2::engine::Mobility;
use mycel_sim::tier2::mycel::{Cfg, Mycel, Role};
use mycel_sim::tier2::world::{ble_only, cellular};
use mycel_sim::tier2::{Action, Area, NodeId, SEC, Sim, Time};

fn main() {
    let gap = 300.0;
    let areas = vec![Area { latlon: (34.05, -118.24), env: Env::Outdoor }];
    let mut specs = Vec::new();
    for x in [0.0, 50.0, 100.0] {
        specs.push(ble_only(0, (x, 0.0), None));
    }
    let d_x = 100.0 + gap;
    specs.push(ble_only(0, (d_x, 0.0), None));
    specs.push(ble_only(0, (d_x + 50.0, 0.0), None));
    specs.push(ble_only(0, (d_x + 100.0, 0.0), Some(cellular(&mut Rng::new(1)))));
    let bridge: Vec<NodeId> = (1..)
        .map(|k| 100.0 + 50.0 * k as f64)
        .take_while(|x| *x < d_x)
        .map(|x| {
            specs.push(ble_only(0, (x, 0.0), None));
            specs.len() as NodeId - 1
        })
        .collect();
    let walk = ((d_x + 20.0) - 90.0) / 1.4;
    let t0 = 120 * SEC;
    let t1 = t0 + (walk * SEC as f64) as Time;
    let t2 = t1 + 60 * SEC;
    let t3 = t2 + (walk * SEC as f64) as Time;
    let mut mule = ble_only(0, (d_x + 20.0, 5.0), None);
    mule.mobility = Mobility::Path(vec![
        (0, (d_x + 20.0, 5.0)),
        (t0, (d_x + 20.0, 5.0)),
        (t1, (90.0, 5.0)),
        (t2, (90.0, 5.0)),
        (t3, (d_x + 20.0, 5.0)),
    ]);
    let m = specs.len() as NodeId;
    specs.push(mule);
    let cfg = Rc::new(Cfg::global());
    let mut sim = Sim::new(areas, specs, 1, |i, _| Mycel::new(i, cfg.clone(), Role::Honest));
    for b in &bridge {
        sim.act_at(40 * SEC, Action::Online(*b, false));
    }
    sim.send_at(60 * SEC, 0, 4, 2000);
    sim.start();
    let mut t = 0;
    while t < t3 + 120 * SEC {
        t += 10 * SEC;
        sim.run(t);
        let held: Vec<String> = (0..sim.routers.len())
            .filter(|i| !sim.routers[*i].held().is_empty())
            .map(|i| format!("{i}:{:?}", sim.routers[i].held()))
            .collect();
        println!(
            "t={} mule x {:.0} nbrs {:?} held {:?} delivered {:?}",
            t / SEC,
            sim.core.spec(m).xy.0,
            sim.core.neighbours_of(m),
            held,
            sim.core.msgs[0].delivered.map(|x| x / SEC)
        );
    }
}
