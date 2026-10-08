//! Bluetooth LE link for Mycel: the slow, last-resort path that works with no
//! Wi-Fi at all.
//!
//! Every device is both a BLE *peripheral* (advertises the Mycel service,
//! publishes an L2CAP connection-oriented channel, and serves a GATT
//! characteristic with the channel's PSM plus its node key and name) and a
//! *central* (scans for the service, reads the characteristic, opens the
//! channel). Both devices dial; the first channel up carries the traffic and
//! is never hung up (see [`core`] for the rules that keep exactly one channel
//! per pair and reconnect within seconds). Iroh's QUIC packets travel over
//! the channel, length-framed
//! (see [`wire`]); QUIC on top does encryption, authentication, congestion
//! control and loss recovery, so this link just moves bytes and drops packets
//! when the radio can't keep up.
//!
//! Layout, so other platforms can slot in:
//! - [`wire`], [`core`], `hub`, `transport`: platform-independent (framing, the
//!   connection state machine, routing, the Iroh custom transport).
//! - `macos`: CoreBluetooth backend. Linux (BlueZ), Windows, iOS and Android
//!   backends implement the same small `Backend` trait.

// Without a backend the shared machinery is unused (until one is written).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::Result;
use mycel_crypto::SignPk;
use mycel_net::link::{Link, LinkEvent, LinkStatus, PathKind};
use mycel_net::link::transports::CustomTransport;
use tokio::sync::mpsc;

pub mod core;
mod hub;
mod transport;
pub mod wire;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod sim;

pub use hub::Radio;
use hub::Hub;

/// The Mycel GATT service, advertised by every device.
pub const SERVICE_UUID: &str = "8E12485D-50ED-4B8D-A6F0-276C27F29CB6";
/// Read-only characteristic: [`wire::GattInfo`] (L2CAP PSM, node key, name).
pub const INFO_CHAR_UUID: &str = "CDCCEDAE-E668-4342-8B67-80BE49E7ED5B";
/// Bytes of outgoing frames queued per channel before new packets are dropped.
/// ~0.3 s at typical BLE L2CAP rates: enough to keep the radio busy, small
/// enough that QUIC sees loss instead of seconds of queueing delay.
pub const OUT_QUEUE_BYTES: usize = 16 * 1024;

/// A platform's radio driver. It reports what the radio does to the [`Hub`]
/// (`hub.input(..)`) and carries out the commands that returns.
pub(crate) trait Backend: Send + Sync + 'static {
    fn start(&self, hub: Arc<Hub>) -> Result<()>;
    fn set_name(&self, _name: &str) {}
    fn stop(&self) {}
}

/// The Bluetooth link for node `me`, advertising `name`.
///
/// On macOS this uses CoreBluetooth. The host app's Info.plist must contain
/// `NSBluetoothAlwaysUsageDescription` (macOS kills an app without it on first
/// Bluetooth use); a command-line tool uses its terminal's Bluetooth
/// permission. On other platforms the link reports itself unavailable.
pub fn link(me: SignPk, name: &str) -> Arc<dyn Link> {
    BleLink::new(me, name, platform_backend())
}

#[cfg(target_os = "macos")]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(macos::Mac::new())
}

#[cfg(not(target_os = "macos"))]
fn platform_backend() -> Box<dyn Backend> {
    Box::new(Unsupported)
}

/// No Bluetooth backend for this platform yet.
#[cfg_attr(target_os = "macos", allow(dead_code))]
struct Unsupported;

#[cfg_attr(target_os = "macos", allow(dead_code))]
const UNSUPPORTED: &str = "Bluetooth links aren't available on this platform yet";

impl Backend for Unsupported {
    fn start(&self, hub: Arc<Hub>) -> Result<()> {
        hub.set_radio(Radio::Unavailable(UNSUPPORTED.into()));
        anyhow::bail!(UNSUPPORTED)
    }
}

pub(crate) struct BleLink {
    hub: Arc<Hub>,
    backend: Box<dyn Backend>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<hub::Inbound>>>,
}

impl BleLink {
    pub(crate) fn new(me: SignPk, name: &str, backend: Box<dyn Backend>) -> Arc<BleLink> {
        let (hub, rx) = Hub::new(me, name);
        Arc::new(BleLink { hub, backend, rx: Arc::new(tokio::sync::Mutex::new(rx)) })
    }
}

/// What a status means for the user (`None`: working).
fn radio_detail(r: &Radio, in_app: bool) -> Option<String> {
    Some(match r {
        Radio::On => return None,
        Radio::NotStarted => "Bluetooth link not started".into(),
        Radio::Starting => "Starting Bluetooth…".into(),
        Radio::AwaitingPermission if in_app => {
            "Waiting for Bluetooth permission: answer the macOS prompt, or allow Mycel in System Settings > Privacy & Security > Bluetooth".into()
        }
        Radio::AwaitingPermission => {
            "Waiting for Bluetooth permission: answer the macOS prompt, or allow your terminal app in System Settings > Privacy & Security > Bluetooth".into()
        }
        Radio::Off => "Bluetooth is off".into(),
        Radio::Unauthorized if in_app => {
            "Allow Mycel to use Bluetooth in System Settings > Privacy & Security > Bluetooth".into()
        }
        Radio::Unauthorized => {
            "Allow your terminal app to use Bluetooth in System Settings > Privacy & Security > Bluetooth".into()
        }
        Radio::Unsupported => "This device doesn't support Bluetooth LE".into(),
        Radio::Resetting => "Bluetooth is restarting".into(),
        Radio::Unavailable(why) => why.clone(),
    })
}

impl Link for BleLink {
    fn kind(&self) -> PathKind {
        PathKind::Bluetooth
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(transport::BleTransport { hub: self.hub.clone(), rx: self.rx.clone() })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        self.hub.set_events(Some(events));
        self.backend.start(self.hub.clone())
    }

    fn set_name(&self, name: &str) {
        self.hub.set_name(name);
        self.backend.set_name(name);
    }

    fn status(&self) -> LinkStatus {
        let radio = self.hub.radio();
        let on = radio == Radio::On;
        let peers = if on { self.hub.peers() } else { 0 };
        let detail = radio_detail(&radio, in_app())
            .or_else(|| self.hub.problem())
            .or_else(|| if on { connecting_detail(self.hub.connecting(), peers) } else { None });
        LinkStatus { kind: PathKind::Bluetooth, label: None, active: on, detail, peers }
    }

    fn stop(&self) {
        self.backend.stop();
        self.hub.set_events(None);
    }
}

/// "Connecting to 1 device…" while devices in range aren't linked yet.
fn connecting_detail(connecting: usize, linked: usize) -> Option<String> {
    let more = if linked > 0 { " more" } else { "" };
    match connecting {
        0 => None,
        1 => Some(format!("Connecting to 1{more} device…")),
        n => Some(format!("Connecting to {n}{more} devices…")),
    }
}

/// Running inside an app bundle (vs. a command-line tool under a terminal).
fn in_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::in_app_bundle()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

// ───────────────────────────── logging ─────────────────────────────

static LOG: AtomicU8 = AtomicU8::new(0);

/// Log to stderr: 0 = quiet (default), 1 = every connect attempt and result,
/// channel open/close (with who closed it and why), tie-break decisions and
/// radio changes, 2 = also every state machine input and command.
/// `MYCEL_BLE_LOG` overrides at startup. Lines carry local wall-clock time
/// so two devices' logs (and bluetoothd's) can be lined up.
pub fn set_log_level(level: u8) {
    LOG.store(level, Ordering::Relaxed);
}

fn level() -> u8 {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        if let Some(l) = std::env::var("MYCEL_BLE_LOG").ok().and_then(|v| v.parse().ok()) {
            LOG.store(l, Ordering::Relaxed);
        }
    });
    LOG.load(Ordering::Relaxed)
}

pub(crate) fn info(args: std::fmt::Arguments) {
    if level() >= 1 {
        eprintln!("{} [ble] {args}", clock());
    }
}

pub(crate) fn debug(args: std::fmt::Arguments) {
    if level() >= 2 {
        eprintln!("{} [ble] {args}", clock());
    }
}

/// Local time of day, `HH:MM:SS.mmm`.
fn clock() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let ms = now.subsec_millis();
    #[cfg(unix)]
    {
        let secs = now.as_secs() as libc::time_t;
        // SAFETY: localtime_r only writes the tm we pass it.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
            return format!("{:02}:{:02}:{:02}.{ms:03}", tm.tm_hour, tm.tm_min, tm.tm_sec);
        }
    }
    let s = now.as_secs() % 86400;
    format!("{:02}:{:02}:{:02}.{ms:03}Z", s / 3600, s / 60 % 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_is_actionable() {
        assert_eq!(radio_detail(&Radio::On, true), None);
        assert_eq!(radio_detail(&Radio::Off, true).unwrap(), "Bluetooth is off");
        assert!(radio_detail(&Radio::Unauthorized, true).unwrap().contains("Allow Mycel to use Bluetooth"));
        assert!(radio_detail(&Radio::Unauthorized, false).unwrap().contains("terminal app"));
        assert_eq!(connecting_detail(0, 0), None);
        assert_eq!(connecting_detail(1, 0).unwrap(), "Connecting to 1 device…");
        assert_eq!(connecting_detail(2, 1).unwrap(), "Connecting to 2 more devices…");
    }

    #[test]
    fn unsupported_backend_reports_unavailable() {
        let l = BleLink::new(SignPk([1; 32]), "x", Box::new(Unsupported));
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(l.start(tx).is_err());
        let s = l.status();
        assert!(!s.active);
        assert_eq!(s.detail.as_deref(), Some(UNSUPPORTED));
        assert_eq!(s.peers, 0);
        assert_eq!(s.kind, PathKind::Bluetooth);
    }
}
