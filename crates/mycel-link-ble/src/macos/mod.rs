//! CoreBluetooth backend (macOS; iOS would share most of it).
//!
//! Threads:
//! - a private serial dispatch queue ("Q") owns every CoreBluetooth object
//!   and receives every CoreBluetooth delegate callback;
//! - a stream thread ("R") runs a CFRunLoop for the L2CAP channels'
//!   `NSInputStream`/`NSOutputStream`s (they deliver events only on a run
//!   loop that is actually running, which a GCD worker thread is not) and the
//!   1 s housekeeping timer (state machine tick, keepalive pings, silence).
//!
//! Scanning reports every advertisement (`AllowDuplicates`), throttled here
//! to one report per peripheral per [`REPORT_EVERY`]: without duplicates
//! macOS reports a peripheral once and then goes quiet about it for as long
//! as it pleases, which left two Macs in range unlinked for many minutes.
//!
//! Neither ever blocks on Iroh, and Iroh never blocks on them: packets to
//! send go into a bounded per-channel [`OutQueue`] and a block is posted to R
//! to drain it; packets received go into the hub's bounded inbound queue.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use anyhow::{Result, bail};
use block2::RcBlock;
use bytes::Bytes;
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, Message, define_class, msg_send};
use objc2_core_bluetooth::{
    CBAdvertisementDataLocalNameKey, CBAdvertisementDataServiceUUIDsKey, CBAttributePermissions, CBCentralManager,
    CBCentralManagerDelegate, CBCentralManagerScanOptionAllowDuplicatesKey, CBCharacteristic,
    CBCharacteristicProperties, CBL2CAPChannel, CBManager, CBManagerAuthorization, CBManagerState,
    CBMutableCharacteristic, CBMutableService, CBPeripheral, CBPeripheralDelegate, CBPeripheralManager,
    CBPeripheralManagerDelegate, CBService, CBUUID,
};
use objc2_core_foundation::{
    CFAbsoluteTimeGetCurrent, CFRetained, CFRunLoop, CFRunLoopTimer, kCFRunLoopDefaultMode,
};
use objc2_foundation::{
    NSArray, NSBundle, NSData, NSDefaultRunLoopMode, NSDictionary, NSError, NSInputStream, NSNumber,
    NSOutputStream, NSRunLoop, NSStream, NSStreamDelegate, NSStreamEvent, NSStreamStatus, NSString,
};
use parking_lot::Mutex;

use crate::core::{ChanId, Cmd, Input, Pid};
use crate::hub::{ChannelRx, Hub, PING_EVERY, PacketSink, Radio, SILENT_AFTER, short};
use crate::wire::{GattInfo, OutQueue, encode_hello, encode_ping};
use crate::{Backend, INFO_CHAR_UUID, OUT_QUEUE_BYTES, SERVICE_UUID, debug, info};

/// Housekeeping tick (timeouts, retries, rescans, pings).
const TICK_SECS: f64 = 1.0;
/// Bytes read from an input stream at a time.
const READ_CHUNK: usize = 8192;

/// Moves an Objective-C object between threads. Only used for objects that
/// are then touched from exactly one thread (Q or R) — see each use.
struct Sendable<T>(T);
unsafe impl<T> Send for Sendable<T> {}
unsafe impl<T> Sync for Sendable<T> {}

impl<T> Sendable<T> {
    /// Taking `self` whole makes closures capture the wrapper, not its field.
    fn into_inner(self) -> T {
        self.0
    }
}

/// Running inside an app bundle (vs. a command-line tool, whose Bluetooth
/// permission is its terminal's).
pub fn in_app_bundle() -> bool {
    NSBundle::mainBundle().bundlePath().hasSuffix(&NSString::from_str(".app"))
}

fn has_usage_description() -> bool {
    NSBundle::mainBundle()
        .objectForInfoDictionaryKey(&NSString::from_str("NSBluetoothAlwaysUsageDescription"))
        .is_some()
}

fn err_text(e: &NSError) -> String {
    e.localizedDescription().to_string()
}

fn uuid(s: &str) -> Retained<CBUUID> {
    unsafe { CBUUID::UUIDWithString(&NSString::from_str(s)) }
}

fn is_uuid(u: &Retained<CBUUID>, s: &str) -> bool {
    unsafe { u.UUIDString() }.to_string().eq_ignore_ascii_case(s)
}

fn pid_of(p: &CBPeripheral) -> Pid {
    unsafe { p.identifier() }.UUIDString().to_string()
}

// ─────────────────────────────── backend ───────────────────────────────

pub struct Mac {
    driver: Mutex<Option<Arc<Driver>>>,
}

impl Mac {
    pub fn new() -> Self {
        Mac { driver: Mutex::new(None) }
    }
}

impl Backend for Mac {
    fn start(&self, hub: Arc<Hub>) -> Result<()> {
        let mut slot = self.driver.lock();
        if slot.is_some() {
            return Ok(());
        }
        // An app bundle without the usage string is killed by macOS (SIGABRT,
        // "Namespace TCC") the moment it touches CoreBluetooth: refuse instead.
        if in_app_bundle() && !has_usage_description() {
            let why = "This app's Info.plist lacks NSBluetoothAlwaysUsageDescription, so macOS won't let it use Bluetooth";
            hub.set_radio(Radio::Unavailable(why.into()));
            bail!(why);
        }
        let auth = unsafe { CBManager::authorization_class() };
        info(format_args!("authorization: {}", auth_name(auth)));
        hub.set_radio(if auth == CBManagerAuthorization::NotDetermined { Radio::AwaitingPermission } else { Radio::Starting });
        let driver = Driver::spawn(hub)?;
        driver.on_queue(|d| d.create_managers());
        *slot = Some(driver);
        Ok(())
    }

    fn set_name(&self, _name: &str) {
        if let Some(d) = &*self.driver.lock() {
            d.on_queue(|d| d.publish_service());
        }
    }

    fn stop(&self) {
        let Some(d) = self.driver.lock().take() else { return };
        d.stopped.store(true, Ordering::SeqCst);
        d.hub.set_radio(Radio::NotStarted);
        let cmds = d.hub.input(Input::RadioDown);
        drop(cmds); // everything is being torn down anyway
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
        d.on_queue(move |d| {
            d.teardown();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(std::time::Duration::from_secs(2));
        d.on_streams(|_| close_all_streams());
        if let Some(rl) = d.rl.get() {
            rl.0.stop();
            rl.0.wake_up();
        }
    }
}

fn auth_name(a: CBManagerAuthorization) -> &'static str {
    match a {
        CBManagerAuthorization::AllowedAlways => "allowed",
        CBManagerAuthorization::Denied => "denied",
        CBManagerAuthorization::Restricted => "restricted",
        CBManagerAuthorization::NotDetermined => "not determined (macOS will ask)",
        _ => "unknown",
    }
}

fn radio_of(s: CBManagerState) -> Radio {
    match s {
        CBManagerState::PoweredOn => Radio::On,
        CBManagerState::PoweredOff => Radio::Off,
        CBManagerState::Unauthorized => Radio::Unauthorized,
        CBManagerState::Unsupported => Radio::Unsupported,
        CBManagerState::Resetting => Radio::Resetting,
        _ if unsafe { CBManager::authorization_class() } == CBManagerAuthorization::NotDetermined => {
            Radio::AwaitingPermission
        }
        _ => Radio::Starting,
    }
}

// ─────────────────────────────── driver ───────────────────────────────

/// CoreBluetooth objects. Only touched on Q.
#[derive(Default)]
struct CbState {
    delegate: Option<Retained<CbDelegate>>,
    central: Option<Retained<CBCentralManager>>,
    pm: Option<Retained<CBPeripheralManager>>,
    service: Option<Retained<CBMutableService>>,
    psm: Option<u16>,
    peripherals: HashMap<Pid, Retained<CBPeripheral>>,
    /// Must stay referenced or CoreBluetooth closes the channel.
    channels: HashMap<ChanId, Retained<CBL2CAPChannel>>,
    /// Scanning reports every advertisement; pass each peripheral on at
    /// most once per [`REPORT_EVERY`].
    reported: HashMap<Pid, std::time::Instant>,
}

const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(1);
/// Log a sighting (with RSSI) at level 1 when a peripheral wasn't reported
/// for this long.
const SAW_LOG_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

struct RunLoopRef(CFRetained<CFRunLoop>);
// CFRunLoopPerformBlock / WakeUp / Stop are thread-safe.
unsafe impl Send for RunLoopRef {}
unsafe impl Sync for RunLoopRef {}

struct Driver {
    hub: Arc<Hub>,
    queue: DispatchRetained<DispatchQueue>,
    cb: Mutex<Sendable<CbState>>,
    rl: OnceLock<RunLoopRef>,
    next_chan: AtomicU64,
    stopped: Arc<AtomicBool>,
}

impl Driver {
    /// A driver with its queue and stream thread running, no radio yet.
    fn spawn(hub: Arc<Hub>) -> Result<Arc<Driver>> {
        let driver = Arc::new(Driver {
            hub,
            queue: DispatchQueue::new("org.mycel.ble", None),
            cb: Mutex::new(Sendable(CbState::default())),
            rl: OnceLock::new(),
            next_chan: AtomicU64::new(1),
            stopped: Arc::new(AtomicBool::new(false)),
        });
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let weak = Arc::downgrade(&driver);
        let stopped = driver.stopped.clone();
        std::thread::Builder::new()
            .name("mycel-ble-streams".into())
            .spawn(move || stream_thread(weak, stopped, ready_tx))?;
        let rl = ready_rx.recv()?;
        let _ = driver.rl.set(rl);
        Ok(driver)
    }

    /// Run `f` on Q.
    fn on_queue(self: &Arc<Self>, f: impl FnOnce(&Arc<Driver>) + Send + 'static) {
        let me = self.clone();
        self.queue.exec_async(move || f(&me));
    }

    /// Run `f` on R.
    fn on_streams(self: &Arc<Self>, f: impl FnOnce(&Arc<Driver>) + Send + 'static) {
        let Some(rl) = self.rl.get() else { return };
        let me = self.clone();
        let job = Cell::new(Some(f));
        let block = RcBlock::new(move || {
            if let Some(f) = job.take() {
                f(&me)
            }
        });
        unsafe { rl.0.perform_block(kCFRunLoopDefaultMode.map(|m| &**m), Some(&block)) };
        rl.0.wake_up();
    }

    fn input(self: &Arc<Self>, i: Input) {
        let cmds = self.hub.input(i);
        self.exec(cmds);
    }

    /// Carry out the state machine's commands (from any thread).
    fn exec(self: &Arc<Self>, cmds: Vec<Cmd>) {
        for c in cmds {
            if let Cmd::CloseChannel(chan) = c {
                self.hub.remove_sink(chan);
                self.on_streams(move |_| {
                    if close_streams(chan) {
                        info(format_args!("L2CAP channel {chan} closed by us"));
                    }
                });
            }
            self.on_queue(move |d| d.exec_cb(c));
        }
    }

    /// On Q.
    fn exec_cb(self: &Arc<Self>, cmd: Cmd) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        // What the radio would have reported, had we had a handle to use.
        let mut follow_up = None;
        {
            let mut cb = self.cb.lock();
            let cb = &mut cb.0;
            let Some(central) = cb.central.clone() else { return };
            let periph = |pid: &Pid| cb.peripherals.get(pid).cloned();
            match cmd {
                Cmd::Connect(pid) => match periph(&pid) {
                    Some(p) => unsafe { central.connectPeripheral_options(&p, None) },
                    None => {
                        info(format_args!("no handle for {pid}; can't dial it"));
                        follow_up = Some(Input::ConnectFailed(pid));
                    }
                },
                Cmd::Disconnect(pid) => {
                    if let Some(p) = periph(&pid) {
                        debug(format_args!("cancelling the connection to {pid}"));
                        unsafe { central.cancelPeripheralConnection(&p) };
                    }
                }
                Cmd::Forget(pid) => {
                    // The next advertisement brings a fresh handle, reported at once.
                    cb.peripherals.remove(&pid);
                    cb.reported.remove(&pid);
                }
                Cmd::ReadInfo(pid) => match periph(&pid) {
                    Some(p) => {
                        let services = NSArray::from_retained_slice(&[uuid(SERVICE_UUID)]);
                        unsafe { p.discoverServices(Some(&services)) };
                    }
                    None => follow_up = Some(Input::InfoFailed(pid)),
                },
                Cmd::OpenChannel(pid, psm) => match periph(&pid) {
                    Some(p) => unsafe { p.openL2CAPChannel(psm) },
                    None => follow_up = Some(Input::OpenFailed(pid)),
                },
                Cmd::CloseChannel(chan) => {
                    cb.channels.remove(&chan);
                }
                Cmd::Rescan => {
                    unsafe { central.stopScan() };
                    scan(&central);
                }
                _ => {}
            }
        }
        if let Some(i) = follow_up {
            self.input(i);
        }
    }

    /// On Q: create the managers. Their first state callback follows.
    fn create_managers(self: &Arc<Self>) {
        let delegate = CbDelegate::new(Arc::downgrade(self));
        let central = unsafe {
            CBCentralManager::initWithDelegate_queue_options(
                CBCentralManager::alloc(),
                Some(ProtocolObject::from_ref(&*delegate)),
                Some(&self.queue),
                None,
            )
        };
        let pm = unsafe {
            CBPeripheralManager::initWithDelegate_queue_options(
                CBPeripheralManager::alloc(),
                Some(ProtocolObject::from_ref(&*delegate)),
                Some(&self.queue),
                None,
            )
        };
        let mut cb = self.cb.lock();
        cb.0.delegate = Some(delegate);
        cb.0.central = Some(central);
        cb.0.pm = Some(pm);
    }

    /// On Q: (re)publish the GATT service carrying our PSM, key and name.
    fn publish_service(self: &Arc<Self>) {
        let mut cb = self.cb.lock();
        let cb = &mut cb.0;
        let (Some(pm), Some(psm)) = (cb.pm.clone(), cb.psm) else { return };
        if let Some(old) = cb.service.take() {
            unsafe { pm.removeService(&old) };
        }
        let value = GattInfo { psm, key: self.hub.me, name: self.hub.name() }.encode();
        let ch = unsafe {
            CBMutableCharacteristic::initWithType_properties_value_permissions(
                CBMutableCharacteristic::alloc(),
                &uuid(INFO_CHAR_UUID),
                CBCharacteristicProperties::Read,
                Some(&NSData::with_bytes(&value)),
                CBAttributePermissions::Readable,
            )
        };
        let svc = unsafe { CBMutableService::initWithType_primary(CBMutableService::alloc(), &uuid(SERVICE_UUID), true) };
        let chars: Retained<NSArray<CBCharacteristic>> = NSArray::from_retained_slice(&[ch.into_super()]);
        unsafe { svc.setCharacteristics(Some(&chars)) };
        unsafe { pm.addService(&svc) };
        cb.service = Some(svc);
    }

    /// On Q: the radio went away; CoreBluetooth invalidated everything.
    fn radio_down(self: &Arc<Self>) {
        {
            let mut cb = self.cb.lock();
            cb.0.peripherals.clear();
            cb.0.channels.clear();
        }
        let cmds = self.hub.input(Input::RadioDown);
        drop(cmds);
        self.on_streams(|_| close_all_streams());
    }

    /// On Q: release the radio.
    fn teardown(self: &Arc<Self>) {
        let mut cb = self.cb.lock();
        let cb = &mut cb.0;
        if let Some(c) = cb.central.take() {
            unsafe {
                c.stopScan();
                for p in cb.peripherals.values() {
                    c.cancelPeripheralConnection(p);
                }
                c.setDelegate(None);
            }
        }
        if let Some(pm) = cb.pm.take() {
            unsafe {
                pm.stopAdvertising();
                pm.removeAllServices();
                if let Some(psm) = cb.psm.take() {
                    pm.unpublishL2CAPChannel(psm);
                }
                pm.setDelegate(None);
            }
        }
        cb.peripherals.clear();
        cb.channels.clear();
        cb.service = None;
        cb.delegate = None;
    }

    /// On Q: an L2CAP channel opened (we dialed it over `pid`, or accepted it).
    fn channel_opened(self: &Arc<Self>, channel: &CBL2CAPChannel, pid: Option<Pid>) {
        let (Some(input), Some(output)) = (unsafe { channel.inputStream() }, unsafe { channel.outputStream() }) else {
            if let Some(pid) = pid {
                self.input(Input::OpenFailed(pid));
            }
            return;
        };
        let chan = self.next_chan.fetch_add(1, Ordering::Relaxed);
        let peer = unsafe { channel.peer() }.map(|p| unsafe { p.identifier() }.UUIDString().to_string());
        info(format_args!(
            "L2CAP channel {chan} open ({} {}, psm {})",
            if pid.is_some() { "dialed to" } else { "accepted from" },
            peer.unwrap_or_else(|| "?".into()),
            unsafe { channel.PSM() }
        ));
        self.cb.lock().0.channels.insert(chan, channel.retain());
        self.attach(chan, input, output, pid);
    }

    /// Carry a channel's traffic over this stream pair (any thread).
    fn attach(self: &Arc<Self>, chan: ChanId, input: Retained<NSInputStream>, output: Retained<NSOutputStream>, pid: Option<Pid>) {
        let mut q = OutQueue::new(OUT_QUEUE_BYTES);
        q.push(encode_hello(&self.hub.me, &self.hub.name())); // always the first frame
        let q = Arc::new(Mutex::new(q));
        self.hub.add_sink(chan, Arc::new(StreamSink { chan, q: q.clone(), driver: Arc::downgrade(self) }));
        self.input(Input::ChannelOpened { chan, pid });
        let streams = Sendable((input, output));
        self.on_streams(move |d| {
            let (input, output) = streams.into_inner();
            install_streams(d, chan, input, output, q);
        });
    }
}

/// Diagnostics: `MYCEL_BLE_SCAN_ALL=1` scans for every BLE device and logs
/// the ones that aren't Mycel (proves the radio is receiving). Costs battery.
fn scan_all() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("MYCEL_BLE_SCAN_ALL").is_ok_and(|v| v == "1"))
}

/// Whether an advertisement lists the Mycel service.
fn advertises_mycel(adv: &NSDictionary<NSString, AnyObject>) -> bool {
    adv.objectForKey(unsafe { CBAdvertisementDataServiceUUIDsKey })
        .and_then(|o| o.downcast::<NSArray>().ok())
        .is_some_and(|a| {
            a.iter().any(|u| u.downcast::<CBUUID>().is_ok_and(|u| is_uuid(&u, SERVICE_UUID)))
        })
}

fn scan(central: &CBCentralManager) {
    let services = NSArray::from_retained_slice(&[uuid(SERVICE_UUID)]);
    let services = (!scan_all()).then_some(services);
    // Every advertisement, so a peer in range keeps being reported (the
    // `discovered` callback throttles). Without duplicates macOS may report
    // a peripheral once and never again.
    let yes = NSNumber::new_bool(true);
    let key: &NSString = unsafe { CBCentralManagerScanOptionAllowDuplicatesKey };
    let opts = NSDictionary::<NSString, AnyObject>::from_slices(&[key], &[&*yes as &AnyObject]);
    unsafe { central.scanForPeripheralsWithServices_options(services.as_deref(), Some(&opts)) };
    debug(format_args!("scanning"));
}

fn advertise(pm: &CBPeripheralManager) {
    if unsafe { pm.isAdvertising() } {
        return;
    }
    // A 128-bit service UUID fills most of the 31-byte advertisement; the
    // node key doesn't fit and is read over GATT instead.
    let services = NSArray::from_retained_slice(&[uuid(SERVICE_UUID)]);
    let name = NSString::from_str("Mycel");
    let keys: [&NSString; 2] = unsafe { [CBAdvertisementDataServiceUUIDsKey, CBAdvertisementDataLocalNameKey] };
    let data = NSDictionary::<NSString, AnyObject>::from_slices(&keys, &[&*services as &AnyObject, &*name as &AnyObject]);
    unsafe { pm.startAdvertising(Some(&data)) };
}

// ─────────────────────────── CoreBluetooth delegate ───────────────────────────

pub struct CbIvars {
    driver: Weak<Driver>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; no Drop impl.
    #[unsafe(super(NSObject))]
    #[name = "MycelBleCoreBluetoothDelegate"]
    #[ivars = CbIvars]
    struct CbDelegate;

    unsafe impl NSObjectProtocol for CbDelegate {}

    unsafe impl CBCentralManagerDelegate for CbDelegate {
        #[unsafe(method(centralManagerDidUpdateState:))]
        fn central_state(&self, central: &CBCentralManager) {
            let Some(d) = self.driver() else { return };
            let state = unsafe { central.state() };
            let radio = radio_of(state);
            info(format_args!("central state: {radio:?}"));
            d.hub.set_radio(radio.clone());
            if radio == Radio::On {
                d.hub.set_problem(None);
                scan(central);
                info(format_args!("scanning for Mycel devices"));
            } else {
                d.radio_down();
            }
        }

        #[unsafe(method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:))]
        fn discovered(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            adv: &NSDictionary<NSString, AnyObject>,
            rssi: &NSNumber,
        ) {
            let Some(d) = self.driver() else { return };
            let pid = pid_of(peripheral);
            let quiet_before = {
                let mut cb = d.cb.lock();
                let now = std::time::Instant::now();
                let last = cb.0.reported.get(&pid).copied();
                if last.is_some_and(|t| now.duration_since(t) < REPORT_EVERY) {
                    return;
                }
                cb.0.reported.insert(pid.clone(), now);
                if cb.0.reported.len() > 64 {
                    cb.0.reported.retain(|_, t| now.duration_since(*t) < SAW_LOG_AFTER);
                }
                last.is_none_or(|t| now.duration_since(t) >= SAW_LOG_AFTER)
            };
            let name = adv
                .objectForKey(unsafe { CBAdvertisementDataLocalNameKey })
                .and_then(|o| o.downcast::<NSString>().ok())
                .map(|s| s.to_string());
            if scan_all() && !advertises_mycel(adv) {
                if quiet_before {
                    info(format_args!("saw non-Mycel device {pid} name={name:?} rssi={}", rssi.intValue()));
                }
                return;
            }
            if quiet_before {
                info(format_args!("advertisement from {pid} name={name:?} rssi={}", rssi.intValue()));
            } else {
                debug(format_args!("advertisement from {pid} rssi={}", rssi.intValue()));
            }
            {
                let mut cb = d.cb.lock();
                let delegate = cb.0.delegate.clone();
                cb.0.peripherals.entry(pid.clone()).or_insert_with(|| {
                    if let Some(del) = &delegate {
                        unsafe { peripheral.setDelegate(Some(ProtocolObject::from_ref(&**del))) };
                    }
                    peripheral.retain()
                });
            }
            d.input(Input::Discovered(pid));
        }

        #[unsafe(method(centralManager:didConnectPeripheral:))]
        fn connected(&self, _central: &CBCentralManager, peripheral: &CBPeripheral) {
            let Some(d) = self.driver() else { return };
            debug(format_args!("connected to {}", pid_of(peripheral)));
            d.input(Input::Connected(pid_of(peripheral)));
        }

        #[unsafe(method(centralManager:didFailToConnectPeripheral:error:))]
        fn connect_failed(&self, _central: &CBCentralManager, peripheral: &CBPeripheral, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            info(format_args!("connect to {} failed: {:?}", pid_of(peripheral), error.map(err_text)));
            d.input(Input::ConnectFailed(pid_of(peripheral)));
        }

        #[unsafe(method(centralManager:didDisconnectPeripheral:error:))]
        fn disconnected(&self, _central: &CBCentralManager, peripheral: &CBPeripheral, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            info(format_args!(
                "BLE connection to {} ended: {}",
                pid_of(peripheral),
                error.map(err_text).unwrap_or_else(|| "cancelled by us".into())
            ));
            d.input(Input::Disconnected(pid_of(peripheral)));
        }
    }

    unsafe impl CBPeripheralDelegate for CbDelegate {
        #[unsafe(method(peripheral:didDiscoverServices:))]
        fn services(&self, peripheral: &CBPeripheral, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            let svc = unsafe { peripheral.services() }
                .and_then(|s| s.iter().find(|s| is_uuid(&unsafe { s.UUID() }, SERVICE_UUID)));
            match (error, svc) {
                (None, Some(svc)) => {
                    let chars = NSArray::from_retained_slice(&[uuid(INFO_CHAR_UUID)]);
                    unsafe { peripheral.discoverCharacteristics_forService(Some(&chars), &svc) };
                }
                _ => {
                    info(format_args!("{}: no Mycel service ({:?})", pid_of(peripheral), error.map(err_text)));
                    d.input(Input::InfoFailed(pid_of(peripheral)));
                }
            }
        }

        #[unsafe(method(peripheral:didDiscoverCharacteristicsForService:error:))]
        fn characteristics(&self, peripheral: &CBPeripheral, service: &CBService, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            let ch = unsafe { service.characteristics() }
                .and_then(|c| c.iter().find(|c| is_uuid(&unsafe { c.UUID() }, INFO_CHAR_UUID)));
            match (error, ch) {
                (None, Some(ch)) => unsafe { peripheral.readValueForCharacteristic(&ch) },
                _ => d.input(Input::InfoFailed(pid_of(peripheral))),
            }
        }

        #[unsafe(method(peripheral:didUpdateValueForCharacteristic:error:))]
        fn value(&self, peripheral: &CBPeripheral, ch: &CBCharacteristic, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            if !is_uuid(&unsafe { ch.UUID() }, INFO_CHAR_UUID) {
                return;
            }
            let pid = pid_of(peripheral);
            let info_rec = unsafe { ch.value() }.and_then(|v| GattInfo::decode(&v.to_vec()));
            match (error, info_rec) {
                (None, Some(i)) => {
                    info(format_args!("{pid} is node {} \"{}\" (psm {})", short(&i.key), i.name, i.psm));
                    d.input(Input::Info(pid, i));
                }
                _ => d.input(Input::InfoFailed(pid)),
            }
        }

        #[unsafe(method(peripheral:didOpenL2CAPChannel:error:))]
        fn dialed(&self, peripheral: &CBPeripheral, channel: Option<&CBL2CAPChannel>, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            let pid = pid_of(peripheral);
            match (error, channel) {
                (None, Some(ch)) => d.channel_opened(ch, Some(pid)),
                (e, _) => {
                    info(format_args!("L2CAP open to {pid} failed: {:?}", e.map(err_text)));
                    d.input(Input::OpenFailed(pid));
                }
            }
        }
    }

    unsafe impl CBPeripheralManagerDelegate for CbDelegate {
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn pm_state(&self, pm: &CBPeripheralManager) {
            let Some(d) = self.driver() else { return };
            let state = unsafe { pm.state() };
            info(format_args!("peripheral state: {:?}", radio_of(state)));
            if state == CBManagerState::PoweredOn {
                unsafe { pm.publishL2CAPChannelWithEncryption(false) };
            } else {
                let mut cb = d.cb.lock();
                cb.0.psm = None;
                cb.0.service = None;
            }
        }

        #[unsafe(method(peripheralManager:didPublishL2CAPChannel:error:))]
        fn published(&self, _pm: &CBPeripheralManager, psm: u16, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            if let Some(e) = error {
                d.hub.set_problem(Some(format!("Couldn't open a Bluetooth channel: {}", err_text(e))));
                return;
            }
            info(format_args!("L2CAP channel published, psm {psm}"));
            d.cb.lock().0.psm = Some(psm);
            d.publish_service();
        }

        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn added(&self, pm: &CBPeripheralManager, _service: &CBService, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            if let Some(e) = error {
                d.hub.set_problem(Some(format!("Couldn't publish the Mycel Bluetooth service: {}", err_text(e))));
                return;
            }
            advertise(pm);
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn advertising(&self, _pm: &CBPeripheralManager, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            match error {
                Some(e) => d.hub.set_problem(Some(format!("Couldn't advertise over Bluetooth: {}", err_text(e)))),
                None => info(format_args!("advertising as node {}", short(&d.hub.me))),
            }
        }

        #[unsafe(method(peripheralManager:didOpenL2CAPChannel:error:))]
        fn accepted(&self, _pm: &CBPeripheralManager, channel: Option<&CBL2CAPChannel>, error: Option<&NSError>) {
            let Some(d) = self.driver() else { return };
            match (error, channel) {
                (None, Some(ch)) => d.channel_opened(ch, None),
                (e, _) => info(format_args!("incoming L2CAP channel failed: {:?}", e.map(err_text))),
            }
        }
    }
);

impl CbDelegate {
    fn new(driver: Weak<Driver>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(CbIvars { driver });
        unsafe { msg_send![super(this), init] }
    }

    fn driver(&self) -> Option<Arc<Driver>> {
        self.ivars().driver.upgrade().filter(|d| !d.stopped.load(Ordering::SeqCst))
    }
}

// ─────────────────────────────── streams (R) ───────────────────────────────

struct StreamIo {
    input: Retained<NSInputStream>,
    output: Retained<NSOutputStream>,
    /// Streams hold their delegate weakly.
    _delegate: Retained<StreamDelegate>,
    rx: ChannelRx,
    q: Arc<Mutex<OutQueue>>,
    last_ping: std::time::Instant,
}

thread_local! {
    /// Open channels' streams; only on R.
    static STREAMS: RefCell<HashMap<ChanId, StreamIo>> = RefCell::new(HashMap::new());
}

/// Iroh's side of a channel: queue the frame, wake R if the queue was idle.
struct StreamSink {
    chan: ChanId,
    q: Arc<Mutex<OutQueue>>,
    driver: Weak<Driver>,
}

impl PacketSink for StreamSink {
    fn send(&self, frame: Bytes) -> bool {
        let (ok, was_empty) = {
            let mut q = self.q.lock();
            let was_empty = q.is_empty();
            (q.push(frame), was_empty)
        };
        if ok
            && was_empty
            && let Some(d) = self.driver.upgrade()
        {
            let chan = self.chan;
            d.on_streams(move |d| pump(d, chan));
        }
        ok
    }
}

fn stream_thread(driver: Weak<Driver>, stopped: Arc<AtomicBool>, ready: std::sync::mpsc::SyncSender<RunLoopRef>) {
    let Some(rl) = CFRunLoop::current() else { return };
    let tick = RcBlock::new(move |_t: *mut CFRunLoopTimer| {
        if let Some(d) = driver.upgrade()
            && !d.stopped.load(Ordering::SeqCst)
        {
            d.input(Input::Tick);
            stream_tick(&d);
        }
    });
    let timer = unsafe {
        CFRunLoopTimer::with_handler(None, CFAbsoluteTimeGetCurrent() + TICK_SECS, TICK_SECS, 0, 0, Some(&tick))
    };
    if let Some(t) = &timer {
        unsafe { t.set_tolerance(0.5) }; // let the OS batch wakeups
        rl.add_timer(Some(t), unsafe { kCFRunLoopDefaultMode });
    }
    let _ = ready.send(RunLoopRef(rl.clone()));
    while !stopped.load(Ordering::SeqCst) {
        CFRunLoop::run_in_mode(unsafe { kCFRunLoopDefaultMode }, 10.0, false);
    }
    if let Some(t) = &timer {
        t.invalidate();
    }
    close_all_streams();
}

fn install_streams(
    d: &Arc<Driver>,
    chan: ChanId,
    input: Retained<NSInputStream>,
    output: Retained<NSOutputStream>,
    q: Arc<Mutex<OutQueue>>,
) {
    let delegate = StreamDelegate::new(chan, Arc::downgrade(d));
    let rl = NSRunLoop::currentRunLoop();
    let mode = unsafe { NSDefaultRunLoopMode };
    for s in [&**input as &NSStream, &**output as &NSStream] {
        unsafe {
            s.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            s.scheduleInRunLoop_forMode(&rl, mode);
        }
        s.open();
    }
    STREAMS.with(|m| {
        m.borrow_mut().insert(
            chan,
            StreamIo { input, output, _delegate: delegate, rx: ChannelRx::default(), q, last_ping: std::time::Instant::now() },
        )
    });
    pump(d, chan);
}

/// Keep quiet channels pinged; drop ones the other end stopped talking on (R).
fn stream_tick(d: &Arc<Driver>) {
    let now = std::time::Instant::now();
    let (silent, ping): (Vec<ChanId>, Vec<ChanId>) = STREAMS.with(|m| {
        let mut m = m.borrow_mut();
        let silent = m.iter().filter(|(_, io)| io.rx.silent(now)).map(|(c, _)| *c).collect();
        let mut ping = Vec::new();
        for (c, io) in m.iter_mut() {
            // (minus a little: the 1 s tick may fire slightly early)
            if now.duration_since(io.last_ping) + std::time::Duration::from_millis(250) >= PING_EVERY {
                io.last_ping = now;
                if io.q.lock().push(encode_ping()) {
                    ping.push(*c);
                }
            }
        }
        (silent, ping)
    });
    for c in silent {
        channel_died(d, c, &format!("silent: nothing received for {} s (dead link)", SILENT_AFTER.as_secs()));
    }
    for c in ping {
        pump(d, c);
    }
}

/// Close a channel's streams (R). Returns whether it was open.
fn close_streams(chan: ChanId) -> bool {
    let Some(io) = STREAMS.with(|m| m.borrow_mut().remove(&chan)) else { return false };
    let rl = NSRunLoop::currentRunLoop();
    let mode = unsafe { NSDefaultRunLoopMode };
    for s in [&**io.input as &NSStream, &**io.output as &NSStream] {
        unsafe {
            s.setDelegate(None);
            s.removeFromRunLoop_forMode(&rl, mode);
        }
        s.close();
    }
    true
}

fn close_all_streams() {
    let chans: Vec<ChanId> = STREAMS.with(|m| m.borrow().keys().copied().collect());
    for c in chans {
        close_streams(c);
    }
}

/// The channel ended or broke (R): tell everyone.
fn channel_died(d: &Arc<Driver>, chan: ChanId, why: &str) {
    if close_streams(chan) {
        info(format_args!("L2CAP channel {chan} closed: {why}"));
        d.hub.remove_sink(chan);
        d.on_queue(move |d| {
            d.cb.lock().0.channels.remove(&chan);
        });
        d.input(Input::ChannelClosed(chan));
    }
}

/// Write queued frames while the stream takes them (R).
fn pump(d: &Arc<Driver>, chan: ChanId) {
    let failed = STREAMS.with(|m| {
        let m = m.borrow();
        let Some(io) = m.get(&chan) else { return false };
        // Writing to a stream that is still opening fails; OpenCompleted /
        // HasSpaceAvailable will call us again.
        if !matches!(io.output.streamStatus(), NSStreamStatus::Open | NSStreamStatus::Writing) {
            return false;
        }
        let mut q = io.q.lock();
        while let Some(chunk) = q.peek() {
            if !io.output.hasSpaceAvailable() {
                break;
            }
            let ptr = NonNull::new(chunk.as_ptr() as *mut u8).expect("non-null");
            let n = unsafe { io.output.write_maxLength(ptr, chunk.len()) };
            if n < 0 {
                return true;
            }
            if n == 0 {
                break;
            }
            q.advance(n as usize);
        }
        false
    });
    if failed {
        channel_died(d, chan, "write failed");
    }
}

/// Read everything available (R).
fn read(d: &Arc<Driver>, chan: ChanId) {
    let res = STREAMS.with(|m| {
        let mut m = m.borrow_mut();
        let io = m.get_mut(&chan)?;
        let mut buf = [0u8; READ_CHUNK];
        let mut cmds = Vec::new();
        while io.input.hasBytesAvailable() {
            let n = unsafe { io.input.read_maxLength(NonNull::new(buf.as_mut_ptr()).expect("non-null"), buf.len()) };
            if n < 0 {
                return Some(Err("read failed"));
            }
            if n == 0 {
                break;
            }
            match io.rx.on_bytes(&d.hub, chan, &buf[..n as usize]) {
                Ok(c) => cmds.extend(c),
                Err(e) => return Some(Err(e.0)),
            }
        }
        Some(Ok(cmds))
    });
    match res {
        Some(Ok(cmds)) => d.exec(cmds),
        Some(Err(why)) => {
            // tell the state machine first, then hang up
            channel_died(d, chan, why);
        }
        None => {}
    }
}

pub struct StreamIvars {
    chan: ChanId,
    driver: Weak<Driver>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; no Drop impl.
    #[unsafe(super(NSObject))]
    #[name = "MycelBleStreamDelegate"]
    #[ivars = StreamIvars]
    struct StreamDelegate;

    unsafe impl NSObjectProtocol for StreamDelegate {}

    unsafe impl NSStreamDelegate for StreamDelegate {
        #[unsafe(method(stream:handleEvent:))]
        fn handle_event(&self, stream: &NSStream, event: NSStreamEvent) {
            let Some(d) = self.ivars().driver.upgrade() else { return };
            let chan = self.ivars().chan;
            if event.contains(NSStreamEvent::HasBytesAvailable) {
                read(&d, chan);
            }
            if event.contains(NSStreamEvent::HasSpaceAvailable) || event.contains(NSStreamEvent::OpenCompleted) {
                pump(&d, chan);
            }
            if event.contains(NSStreamEvent::ErrorOccurred) {
                let why = stream.streamError().map(|e| err_text(&e)).unwrap_or_else(|| "unknown".into());
                channel_died(&d, chan, &format!("stream error: {why}"));
            } else if event.contains(NSStreamEvent::EndEncountered) {
                channel_died(&d, chan, "closed by the peer (stream ended)");
            }
        }
    }
);

impl StreamDelegate {
    fn new(chan: ChanId, driver: Weak<Driver>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(StreamIvars { chan, driver });
        unsafe { msg_send![super(this), init] }
    }
}

#[cfg(test)]
mod tests {
    //! The stream half of the backend (run loop thread, stream delegate,
    //! framing, backpressure, wakeups) between two in-process "devices",
    //! with `NSStream` bound pairs standing in for the L2CAP channel. Real
    //! QUIC runs over it. Only CoreBluetooth itself (discovery, GATT, opening
    //! the channel) is left for the two-Mac test.

    use std::time::Duration;

    use mycel_crypto::DeviceKeys;
    use mycel_net::iroh::endpoint::{Connection, presets};
    use mycel_net::iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use mycel_net::iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
    use mycel_net::link::LinkEvent;
    use tokio::sync::mpsc;

    use super::*;
    use crate::hub::addr_of;
    use crate::transport::BleTransport;

    const ALPN: &[u8] = b"test/ble-streams";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let (mut tx, mut rx) = conn.accept_bi().await?;
            let data = rx.read_to_end(1 << 20).await.map_err(AcceptError::from_err)?;
            tx.write_all(&data).await.map_err(AcceptError::from_err)?;
            tx.finish()?;
            conn.closed().await;
            Ok(())
        }
    }

    fn bound(size: usize) -> (Retained<NSInputStream>, Retained<NSOutputStream>) {
        let (mut i, mut o) = (None, None);
        NSStream::getBoundStreamsWithBufferSize_inputStream_outputStream(size, Some(&mut i), Some(&mut o));
        (i.unwrap(), o.unwrap())
    }

    struct Dev {
        keys: DeviceKeys,
        driver: Arc<Driver>,
        events: mpsc::UnboundedReceiver<LinkEvent>,
        rx: Arc<tokio::sync::Mutex<mpsc::Receiver<crate::hub::Inbound>>>,
    }

    fn dev(name: &str) -> Dev {
        let keys = DeviceKeys::generate();
        let (hub, rx) = Hub::new(keys.sign_pk(), name);
        let (tx, events) = mpsc::unbounded_channel();
        hub.set_events(Some(tx));
        hub.set_radio(Radio::On);
        let driver = Driver::spawn(hub).unwrap();
        Dev { keys, driver, events, rx: Arc::new(tokio::sync::Mutex::new(rx)) }
    }

    fn endpoint(d: &Dev) -> mycel_net::iroh::endpoint::Builder {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&d.keys.seed()))
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .add_custom_transport(Arc::new(BleTransport { hub: d.driver.hub.clone(), rx: d.rx.clone() }))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quic_over_run_loop_streams() {
        let mut a = dev("alice");
        let mut b = dev("bob");
        // a small buffer forces partial writes and HasSpaceAvailable backpressure
        let (b_in, a_out) = bound(2048);
        let (a_in, b_out) = bound(2048);
        a.driver.attach(1, a_in, a_out, None);
        b.driver.attach(1, b_in, b_out, None);
        let (ka, kb) = (a.keys.sign_pk(), b.keys.sign_pk());
        for (d, other) in [(&mut a, kb), (&mut b, ka)] {
            let got = tokio::time::timeout(Duration::from_secs(5), d.events.recv()).await.expect("hello exchanged");
            match got {
                Some(LinkEvent::Found { peer, addr, name }) => {
                    assert_eq!(peer, other);
                    assert_eq!(addr, addr_of(&peer));
                    assert!(name.is_some());
                }
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(d.driver.hub.peers(), 1);
        }

        let ea = endpoint(&a).bind().await.unwrap();
        let eb = endpoint(&b).alpns(vec![ALPN.to_vec()]).bind().await.unwrap();
        let router = Router::builder(eb.clone()).accept(ALPN, Echo).spawn();
        let to_b = EndpointAddr::from_parts(eb.id(), [TransportAddr::Custom(addr_of(&b.keys.sign_pk()))]);
        let conn = tokio::time::timeout(Duration::from_secs(10), ea.connect(to_b, ALPN)).await.unwrap().unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let t = std::time::Instant::now();
        tx.write_all(&payload).await.unwrap();
        tx.finish().unwrap();
        let back = tokio::time::timeout(Duration::from_secs(30), rx.read_to_end(1 << 20)).await.unwrap().unwrap();
        assert_eq!(back, payload, "echoed intact through both stream pairs");
        eprintln!("300 KB echoed over run-loop streams in {:?}", t.elapsed());
        conn.close(0u32.into(), b"done");
        router.shutdown().await.unwrap();

        // the far end hangs up: the channel is lost and unrouted
        b.driver.on_streams(|_| {
            close_streams(1);
        });
        let lost = tokio::time::timeout(Duration::from_secs(5), a.events.recv()).await.expect("lost");
        assert!(matches!(lost, Some(LinkEvent::Lost { .. })), "{lost:?}");
        assert_eq!(a.driver.hub.peers(), 0);
        for d in [&a, &b] {
            d.driver.stopped.store(true, Ordering::SeqCst);
            d.driver.rl.get().unwrap().0.wake_up();
        }
    }
}
