//! Runs the bounded model checks with published bounds and a time budget
//! each (docs/TESTING.md, "Model checking"): `mycel-check [SECS] [NAME…]`.

use std::time::Duration;

use mycel_check::carrier::CarrierModel;
use mycel_check::router::RouterModel;
use mycel_check::{Outcome, run};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let secs: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(120);
    let want =
        |n: &str| args.iter().skip(1).all(|a| a.parse::<u64>().is_ok()) || args.iter().any(|a| n.contains(a.as_str()));
    let budget = Duration::from_secs(secs);
    let mut outcomes: Vec<Outcome> = Vec::new();
    let mut check = |name: &str, f: &dyn Fn() -> Outcome| {
        if want(name) {
            let o = f();
            println!("{o}");
            if let Some((p, path)) = &o.violation {
                println!("{p}, counterexample:\n{path}");
            }
            outcomes.push(o);
        }
    };
    check("router/line", &|| {
        let mut m = RouterModel::new(3, &[(0, 1), (1, 2)]);
        if let Ok(b) = std::env::var("ROUTER_BUDGET") {
            let v: Vec<u8> = b.split(',').filter_map(|x| x.parse().ok()).collect();
            m.budget = mycel_check::router::Budget { steps: v[0], links: v[1], costs: v[2], losses: v[3], dups: v[4] };
        }
        run("router/line", &m.bound(), m, 3, budget)
    });
    check("router/triangle", &|| {
        let mut m = RouterModel::new(3, &[(0, 1), (1, 2), (0, 2)]);
        m.budget.steps = 1;
        m.budget.costs = 0;
        run("router/triangle", &m.bound(), m, 3, budget)
    });
    check("router/planted", &|| {
        let mut m = RouterModel::new(3, &[(0, 1), (1, 2), (0, 2)]);
        m.planted = true;
        run("router/planted", &m.bound(), m, 3, budget)
    });
    check("carrier/line", &|| {
        let mut m = CarrierModel::new(3, &[(0, 1), (1, 2)]);
        if let Ok(b) = std::env::var("CARRIER_BUDGET") {
            let v: Vec<u8> = b.split(',').filter_map(|x| x.parse().ok()).collect();
            m.budget = mycel_check::carrier::Budget { steps: v[0], links: v[1], drops: v[2] };
        }
        run("carrier/line", &m.bound(), m, 3, budget)
    });
    check("ble/pair", &|| {
        let mut m = mycel_check::ble::BleModel::default();
        if let Ok(b) = std::env::var("BLE_BUDGET") {
            let v: Vec<u8> = b.split(',').filter_map(|x| x.parse().ok()).collect();
            m = mycel_check::ble::BleModel {
                budget: mycel_check::ble::Budget { steps: v[0], fails: v[1], drops: v[2] },
                ..m
            };
        }
        run("ble/pair", &m.bound(), m, 3, budget)
    });
    // a violation fails, except where one is planted (there its absence
    // does); so does a bound not exhausted within the budget
    let failed = outcomes.iter().filter(|o| o.violation.is_some() != o.name.contains("planted") || o.timed_out).count();
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
