//! What the interface link makes of this machine's interfaces.
//!
//! ```text
//! cargo run -p mycel-link-iface --example ifaces            # with IP on (the app's default)
//! cargo run -p mycel-link-iface --example ifaces -- --no-ip # links only (MYCEL_IP=0)
//! ```
//!
//! Only reads the interface list; sends nothing.

use mycel_link_iface::classify::{Decision, Rules, classify};
use mycel_link_iface::ifaces;

fn main() {
    let ip = !std::env::args().any(|a| a == "--no-ip");
    let rules = Rules::from_env(ip);
    println!("IP transport {}:", if ip { "on" } else { "off" });
    for i in ifaces::list() {
        let what = match classify(&i, &rules) {
            Decision::Use { kind, label } => format!("USE  {:<18} {label}", kind.label()),
            Decision::Skip(why) => format!("skip {why}"),
        };
        let ll = i.link_local.map(|a| a.to_string()).unwrap_or_else(|| "-".into());
        println!("  {:<12} #{:<3} {:<10} {:<28} {what}", i.name, i.index, format!("{:?}", i.hw), ll);
    }
}
