//! The model checks at bounds small enough for a debug test build: each
//! harness must exhaust its bound with every property holding, and the
//! planted bug must be found. The published bounds run in release
//! (`cargo run -p mycel-check --release`, docs/TESTING.md).

use std::time::Duration;

use mycel_check::ble::{self, BleModel};
use mycel_check::carrier::{self, CarrierModel};
use mycel_check::router::{self, RouterModel};
use mycel_check::run;
use stateright::{Checker, Model};

const BUDGET: Duration = Duration::from_secs(300);

#[test]
fn router_line_holds_exhaustively() {
    let mut m = RouterModel::new(3, &[(0, 1), (1, 2)]);
    m.budget = router::Budget { steps: 1, links: 1, costs: 1, losses: 1, dups: 0 };
    let o = run("router/line (test)", &m.bound(), m, 2, BUDGET);
    assert!(o.violation.is_none() && !o.timed_out, "{o}\n{:?}", o.violation);
    assert!(o.unique > 100, "explored something: {o}");
}

#[test]
fn router_planted_infeasible_route_makes_a_loop() {
    let mut m = RouterModel::new(3, &[(0, 1), (1, 2), (0, 2)]);
    m.planted = true;
    let o = run("router/planted (test)", &m.bound(), m, 2, BUDGET);
    let (p, _) = o.violation.as_ref().expect("the model checker finds the planted bug");
    assert!(p == "loop-free" || p == "feasible", "{p}");
}

#[test]
fn carrier_holds_exhaustively() {
    let mut m = CarrierModel::new(3, &[(0, 1), (1, 2)]);
    m.budget = carrier::Budget { steps: 1, links: 1, drops: 1 };
    let o = run("carrier/line (test)", &m.bound(), m, 2, BUDGET);
    assert!(o.violation.is_none() && !o.timed_out, "{o}\n{:?}", o.violation);
}

/// The plan's first wording of the receipt property ("the receipt
/// reaches the source") fails, as designed: a source that handed every copy
/// on is not told when one summary stream is lost (docs/TESTING.md, "Model
/// checking", finding 1). This pins that the checker still sees it.
#[test]
fn carrier_source_without_copies_is_not_told() {
    #[derive(Clone)]
    struct SourceTold(CarrierModel);
    impl Model for SourceTold {
        type State = carrier::State;
        type Action = carrier::Action;
        fn init_states(&self) -> Vec<carrier::State> {
            self.0.init_states()
        }
        fn actions(&self, s: &carrier::State, a: &mut Vec<carrier::Action>) {
            self.0.actions(s, a)
        }
        fn next_state(&self, s: &carrier::State, a: carrier::Action) -> Option<carrier::State> {
            self.0.next_state(s, a)
        }
        fn properties(&self) -> Vec<stateright::Property<Self>> {
            vec![stateright::Property::always("receipt reaches the source", |m: &SourceTold, s: &carrier::State| {
                m.0.source_told(s)
            })]
        }
    }
    let mut m = CarrierModel::new(3, &[(0, 1), (1, 2)]);
    m.budget = carrier::Budget { steps: 2, links: 0, drops: 1 };
    let c = SourceTold(m).checker().threads(2).timeout(BUDGET).spawn_dfs().join();
    assert!(c.discovery("receipt reaches the source").is_some(), "expected the known counterexample");
}

#[test]
fn ble_holds_exhaustively() {
    let mut m = BleModel::default();
    m.budget = ble::Budget { steps: 1, fails: 1, drops: 0 };
    let o = run("ble/pair (test)", &m.bound(), m, 2, BUDGET);
    assert!(o.violation.is_none() && !o.timed_out, "{o}\n{:?}", o.violation);
}
