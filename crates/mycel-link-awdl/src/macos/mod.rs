//! The macOS implementation: Network.framework listener + browser + UDP
//! connections, bridged to Iroh's poll-based custom transport.
//!
//! Threading: every Network.framework callback runs on one serial dispatch
//! queue owned by the link. Received QUIC packets go into a bounded tokio
//! channel that `poll_recv` drains (its waker is the channel's). Sends from
//! Iroh look up the peer's current flow under a read lock and hand the
//! datagram to `nw_connection_send`, which never blocks. A small timer
//! thread sends liveness hellos, retries connections and expires dead flows.

mod ffi;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use block2::RcBlock;
use bytes::Bytes;
use mycel_crypto::SignPk;
use mycel_net::link::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use mycel_net::link::{CustomAddr, TRANSPORT_PEER_WIFI, n0_watcher, noq_udp};
use mycel_net::{Link, LinkEvent, LinkStatus, PathKind};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::wire::{self, Advert, Control};
use ffi::Nw;

/// Liveness hello on every outbound flow this often.
const HELLO_EVERY: Duration = Duration::from_secs(2);
/// A flow with nothing received for this long doesn't carry traffic.
const FLOW_TIMEOUT: Duration = Duration::from_secs(8);
/// ...and is torn down (outbound: re-resolved and reconnected) after this.
const FLOW_EXPIRE: Duration = Duration::from_secs(20);
/// Between connection attempts to one service.
const RETRY_EVERY: Duration = Duration::from_secs(3);
/// Datagrams queued in Network.framework per flow before we drop (like a
/// congested radio; QUIC's congestion control backs off).
const MAX_INFLIGHT: usize = 512;
/// Inbound flows we keep at once (each is cheap, but bound them).
const MAX_INBOUND: usize = 64;
const RECV_QUEUE: usize = 4096;
/// A failed listener or browser is recreated after this long.
const RESTART_EVERY: Duration = Duration::from_secs(5);

fn debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("MYCEL_AWDL_DEBUG").is_ok_and(|v| !v.is_empty() && v != "0"))
}

macro_rules! log {
    ($($t:tt)*) => {
        if debug() {
            eprintln!("[awdl] {}", format_args!($($t)*));
        }
    };
}

fn addr_of(pk: &SignPk) -> CustomAddr {
    CustomAddr::from_parts(TRANSPORT_PEER_WIFI, &pk.0)
}

fn parse_addr(a: &CustomAddr) -> Option<SignPk> {
    (a.id() == TRANSPORT_PEER_WIFI)
        .then(|| a.data().try_into().ok().map(SignPk))
        .flatten()
}

struct Packet {
    data: Bytes,
    from: SignPk,
}

/// A completion block shared by every send on one flow.
struct SendDone(RcBlock<dyn Fn(ffi::nw_object)>);
// The block only touches an `Arc<AtomicUsize>`; block refcounts are atomic.
unsafe impl Send for SendDone {}
unsafe impl Sync for SendDone {}

/// One UDP flow (an `nw_connection`) to or from a peer.
struct Flow {
    id: u64,
    conn: Nw,
    outbound: bool,
    peer: Mutex<Option<SignPk>>,
    ready: AtomicBool,
    closed: AtomicBool,
    created: Instant,
    last_rx: Mutex<Option<Instant>>,
    last_hello: Mutex<Option<Instant>>,
    max_datagram: AtomicUsize,
    inflight: Arc<AtomicUsize>,
    done: SendDone,
    /// Stats for the debug log: datagrams received, largest one.
    rx_count: AtomicU64,
    rx_largest: AtomicUsize,
}

impl Flow {
    fn new(id: u64, conn: Nw, outbound: bool, peer: Option<SignPk>) -> Arc<Flow> {
        let inflight = Arc::new(AtomicUsize::new(0));
        let n = inflight.clone();
        let done = SendDone(RcBlock::new(move |_err: ffi::nw_object| {
            n.fetch_sub(1, Ordering::Relaxed);
        }));
        Arc::new(Flow {
            id,
            conn,
            outbound,
            peer: Mutex::new(peer),
            ready: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            created: Instant::now(),
            last_rx: Mutex::new(None),
            last_hello: Mutex::new(None),
            max_datagram: AtomicUsize::new(0),
            inflight,
            done,
            rx_count: AtomicU64::new(0),
            rx_largest: AtomicUsize::new(0),
        })
    }

    fn alive(&self, now: Instant) -> bool {
        self.ready.load(Ordering::Acquire)
            && !self.closed.load(Ordering::Acquire)
            && self
                .last_rx
                .lock()
                .is_some_and(|t| now.duration_since(t) < FLOW_TIMEOUT)
    }

    fn cancel(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            unsafe { ffi::nw_connection_cancel(self.conn.ptr()) };
        }
    }

    /// Queue one datagram; drops it if the flow is backed up or it's too big.
    fn send(&self, bytes: &[u8]) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let max = self.max_datagram.load(Ordering::Relaxed);
        if max > 0 && bytes.len() > max {
            return; // a path-MTU probe that doesn't fit: lost, QUIC settles lower
        }
        if self.inflight.fetch_add(1, Ordering::Relaxed) >= MAX_INFLIGHT {
            self.inflight.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        let data = ffi::data_from(bytes);
        unsafe {
            ffi::nw_connection_send(
                self.conn.ptr(),
                data,
                ffi::_nw_content_context_default_message,
                true,
                &self.done.0,
            );
            ffi::dispatch_release(data);
        }
    }
}

/// A peer's Bonjour advertisement as the browser currently sees it.
struct Service {
    advert: Advert,
    endpoint: Nw,
    /// Interfaces it was seen on that aren't peer-to-peer (prohibited for our flow).
    other_ifaces: Vec<Nw>,
    /// Seen on a peer-to-peer interface (or the result has no interface info).
    eligible: bool,
    flow: Option<u64>,
    last_attempt: Option<Instant>,
}

#[derive(Default)]
struct State {
    listener: Option<Nw>,
    browser: Option<Nw>,
    listener_state: u32,
    listener_err: Option<(u32, i32)>,
    browser_state: u32,
    browser_err: Option<(u32, i32)>,
    /// A flow is waiting because Local Network access is denied.
    flow_denied: bool,
    /// When the listener / browser failed (they are recreated after a pause).
    listener_failed: Option<Instant>,
    browser_failed: Option<Instant>,
    services: HashMap<String, Service>,
    flows: HashMap<u64, Arc<Flow>>,
    /// Peers we told the node about (`Found` sent, no `Lost` since).
    reported: HashMap<SignPk, Option<String>>,
}

struct Shared {
    me: SignPk,
    any_iface: bool,
    queue: ffi::Queue,
    name: Mutex<String>,
    tx: mpsc::Sender<Packet>,
    events: Mutex<Option<mpsc::UnboundedSender<LinkEvent>>>,
    st: Mutex<State>,
    /// Peer → the flow that carries its packets right now.
    routes: RwLock<HashMap<SignPk, Arc<Flow>>>,
    next_id: AtomicU64,
    started: AtomicBool,
    stopped: AtomicBool,
}

pub struct AwdlLink {
    shared: Arc<Shared>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl AwdlLink {
    pub fn create(me: SignPk, name: &str, any_iface: bool) -> Arc<dyn Link> {
        let (tx, rx) = mpsc::channel(RECV_QUEUE);
        let shared = Arc::new(Shared {
            me,
            any_iface,
            queue: ffi::Queue::new(c"mycel.link.awdl"),
            name: Mutex::new(name.to_string()),
            tx,
            events: Mutex::new(None),
            st: Mutex::default(),
            routes: RwLock::default(),
            next_id: AtomicU64::new(1),
            started: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        });
        Arc::new(AwdlLink {
            shared,
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        })
    }
}

impl Link for AwdlLink {
    fn kind(&self) -> PathKind {
        PathKind::PeerWifi
    }

    fn transport(&self) -> Arc<dyn CustomTransport> {
        Arc::new(AwdlTransport {
            shared: self.shared.clone(),
            rx: self.rx.clone(),
        })
    }

    fn start(&self, events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
        if self.shared.started.swap(true, Ordering::AcqRel) {
            bail!("peer-to-peer Wi-Fi link already started");
        }
        *self.shared.events.lock() = Some(events);
        self.shared.start_listener();
        self.shared.start_browser();
        let weak = Arc::downgrade(&self.shared);
        std::thread::Builder::new()
            .name("mycel-awdl".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    let Some(s) = weak.upgrade() else { return };
                    if s.stopped.load(Ordering::Acquire) {
                        return;
                    }
                    s.tick();
                }
            })?;
        Ok(())
    }

    fn set_name(&self, name: &str) {
        *self.shared.name.lock() = name.to_string();
        let st = self.shared.st.lock();
        if let Some(l) = &st.listener {
            self.shared.advertise(l);
        }
    }

    fn status(&self) -> LinkStatus {
        self.shared.status()
    }

    fn stop(&self) {
        self.shared.stop();
    }
}

impl Drop for AwdlLink {
    fn drop(&mut self) {
        self.shared.stop();
    }
}

// ─────────────────────────── Network.framework side ───────────────────────────

fn udp_params() -> Nw {
    let p = unsafe {
        ffi::nw_parameters_create_secure_udp(
            ffi::_nw_parameters_configure_protocol_disable,
            ffi::_nw_parameters_configure_protocol_default_configuration,
        )
    };
    let p = Nw::owned(p).expect("nw_parameters_create_secure_udp");
    unsafe { ffi::nw_parameters_set_include_peer_to_peer(p.ptr(), true) };
    p
}

fn service_type() -> CString {
    CString::new(wire::SERVICE_TYPE).expect("no NUL")
}

impl Shared {
    fn emit(&self, ev: LinkEvent) {
        if let Some(tx) = &*self.events.lock() {
            let _ = tx.send(ev);
        }
    }

    fn advertise(&self, listener: &Nw) {
        let name = CString::new(wire::instance_name(&self.me)).expect("hex");
        let ty = service_type();
        unsafe {
            let Some(adv) = Nw::owned(ffi::nw_advertise_descriptor_create_bonjour_service(
                name.as_ptr(),
                ty.as_ptr(),
                std::ptr::null(),
            )) else {
                return;
            };
            if let Some(txt) = Nw::owned(ffi::nw_txt_record_create_dictionary()) {
                for (k, v) in wire::txt_entries(&self.me, &self.name.lock()) {
                    let k = CString::new(k).expect("static key");
                    ffi::nw_txt_record_set_key(txt.ptr(), k.as_ptr(), v.as_ptr(), v.len());
                }
                ffi::nw_advertise_descriptor_set_txt_record_object(adv.ptr(), txt.ptr());
            }
            ffi::nw_listener_set_advertise_descriptor(listener.ptr(), adv.ptr());
        }
    }

    fn start_listener(self: &Arc<Self>) {
        let params = udp_params();
        let Some(l) = Nw::owned(unsafe { ffi::nw_listener_create(params.ptr()) }) else {
            self.st.lock().listener_state = ffi::LISTENER_FAILED;
            return;
        };
        let weak = Arc::downgrade(self);
        let on_state = RcBlock::new(move |state: u32, err: ffi::nw_object| {
            let Some(s) = weak.upgrade() else { return };
            let err = ffi::error_of(err);
            log!("listener state {state} err {err:?}");
            let mut st = s.st.lock();
            st.listener_state = state;
            st.listener_err = err;
            if state == ffi::LISTENER_READY
                && let Some(l) = &st.listener
            {
                log!("listening on UDP port {}", unsafe {
                    ffi::nw_listener_get_port(l.ptr())
                });
            }
            if state == ffi::LISTENER_FAILED
                && let Some(l) = st.listener.take()
            {
                st.listener_failed = Some(Instant::now());
                unsafe { ffi::nw_listener_cancel(l.ptr()) };
            }
        });
        let weak = Arc::downgrade(self);
        let on_conn = RcBlock::new(move |conn: ffi::nw_object| {
            let Some(conn) = Nw::retained(conn) else {
                return;
            };
            match weak.upgrade() {
                Some(s) if !s.stopped.load(Ordering::Acquire) => s.accept(conn),
                _ => unsafe { ffi::nw_connection_cancel(conn.ptr()) },
            }
        });
        unsafe {
            ffi::nw_listener_set_queue(l.ptr(), self.queue.ptr());
            ffi::nw_listener_set_state_changed_handler(l.ptr(), &on_state);
            ffi::nw_listener_set_new_connection_handler(l.ptr(), &on_conn);
        }
        self.advertise(&l);
        unsafe { ffi::nw_listener_start(l.ptr()) };
        self.st.lock().listener = Some(l);
    }

    fn start_browser(self: &Arc<Self>) {
        let ty = service_type();
        let Some(desc) = Nw::owned(unsafe {
            ffi::nw_browse_descriptor_create_bonjour_service(ty.as_ptr(), std::ptr::null())
        }) else {
            self.st.lock().browser_state = ffi::BROWSER_FAILED;
            return;
        };
        unsafe { ffi::nw_browse_descriptor_set_include_txt_record(desc.ptr(), true) };
        let params =
            Nw::owned(unsafe { ffi::nw_parameters_create() }).expect("nw_parameters_create");
        unsafe { ffi::nw_parameters_set_include_peer_to_peer(params.ptr(), true) };
        let Some(b) = Nw::owned(unsafe { ffi::nw_browser_create(desc.ptr(), params.ptr()) }) else {
            self.st.lock().browser_state = ffi::BROWSER_FAILED;
            return;
        };
        let weak = Arc::downgrade(self);
        let on_state = RcBlock::new(move |state: u32, err: ffi::nw_object| {
            let Some(s) = weak.upgrade() else { return };
            let err = ffi::error_of(err);
            log!("browser state {state} err {err:?}");
            let mut st = s.st.lock();
            st.browser_state = state;
            st.browser_err = err;
            if state == ffi::BROWSER_FAILED
                && let Some(b) = st.browser.take()
            {
                st.browser_failed = Some(Instant::now());
                unsafe { ffi::nw_browser_cancel(b.ptr()) };
            }
        });
        let weak = Arc::downgrade(self);
        let on_results = RcBlock::new(
            move |old: ffi::nw_object, new: ffi::nw_object, _batch_complete: ffi::CBool| {
                if let Some(s) = weak.upgrade() {
                    s.on_browse(old, new);
                }
            },
        );
        unsafe {
            ffi::nw_browser_set_queue(b.ptr(), self.queue.ptr());
            ffi::nw_browser_set_state_changed_handler(b.ptr(), &on_state);
            ffi::nw_browser_set_browse_results_changed_handler(b.ptr(), &on_results);
            ffi::nw_browser_start(b.ptr());
        }
        self.st.lock().browser = Some(b);
    }

    /// The browser saw a service appear, change or go away.
    fn on_browse(self: &Arc<Self>, old: ffi::nw_object, new: ffi::nw_object) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let changes = unsafe { ffi::nw_browse_result_get_changes(old, new) };
        if changes & ffi::CHANGE_REMOVED != 0 && !old.is_null() {
            if let Some(name) = result_name(old) {
                log!("service gone: {name}");
                let mut st = self.st.lock();
                if let Some(svc) = st.services.remove(&name)
                    && let Some(f) = svc.flow.and_then(|id| st.flows.get(&id))
                {
                    f.cancel();
                }
            }
            self.recompute();
        }
        let update = ffi::CHANGE_ADDED
            | ffi::CHANGE_IFACE_ADDED
            | ffi::CHANGE_IFACE_REMOVED
            | ffi::CHANGE_TXT;
        if changes & update != 0 && !new.is_null() {
            self.upsert_service(new);
            self.recompute();
        }
    }

    fn upsert_service(self: &Arc<Self>, result: ffi::nw_object) {
        let Some(name) = result_name(result) else {
            return;
        };
        let advert = Nw::owned(unsafe { ffi::nw_browse_result_copy_txt_record_object(result) })
            .and_then(|txt| {
                let pk = ffi::txt_value(txt.ptr(), &cstring(wire::TXT_KEY));
                let n = ffi::txt_value(txt.ptr(), &cstring(wire::TXT_NAME));
                wire::parse_advert(pk.as_deref(), n.as_deref())
            });
        let Some(advert) = advert else {
            log!("service {name}: no usable TXT record yet");
            return;
        };
        if advert.key == self.me {
            return; // our own advertisement
        }
        let Some(endpoint) = Nw::owned(unsafe { ffi::nw_browse_result_copy_endpoint(result) })
        else {
            return;
        };
        let ifaces = ffi::interfaces_of_browse_result(result);
        let p2p = ifaces
            .iter()
            .any(|(n, _)| wire::is_peer_to_peer_interface(n));
        let eligible = self.any_iface || p2p || ifaces.is_empty();
        log!(
            "service {name}: {} {:?} on {:?} (eligible: {eligible})",
            advert.key.short(),
            advert.name,
            ifaces.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()
        );
        let other_ifaces: Vec<Nw> = ifaces
            .into_iter()
            .filter(|(n, _)| !wire::is_peer_to_peer_interface(n))
            .map(|(_, i)| i)
            .collect();
        let mut st = self.st.lock();
        let (mut flow, last_attempt) = match st.services.get(&name) {
            Some(s) => (s.flow, s.last_attempt),
            None => (None, None),
        };
        let same_key = st
            .services
            .get(&name)
            .is_none_or(|s| s.advert.key == advert.key);
        if !(same_key && eligible)
            && let Some(f) = flow.take().and_then(|id| st.flows.get(&id))
        {
            // key changed, or no longer on peer-to-peer Wi-Fi
            f.cancel();
        }
        st.services.insert(
            name.clone(),
            Service {
                advert,
                endpoint,
                other_ifaces,
                eligible,
                flow,
                last_attempt,
            },
        );
        if eligible && flow.is_none() {
            self.connect(&mut st, &name);
        }
    }

    /// Open an outbound flow to a discovered service.
    fn connect(self: &Arc<Self>, st: &mut State, name: &str) {
        let Some(svc) = st.services.get_mut(name) else {
            return;
        };
        let params = udp_params();
        if !self.any_iface {
            // Steer resolution onto peer-to-peer Wi-Fi: rule out every other
            // interface the peer is visible on (same LAN, VPN...). Prohibiting
            // the Wi-Fi *type* would also rule out AWDL, a Wi-Fi subtype.
            for i in &svc.other_ifaces {
                unsafe { ffi::nw_parameters_prohibit_interface(params.ptr(), i.ptr()) };
            }
        }
        let Some(conn) =
            Nw::owned(unsafe { ffi::nw_connection_create(svc.endpoint.ptr(), params.ptr()) })
        else {
            return;
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        svc.flow = Some(id);
        svc.last_attempt = Some(Instant::now());
        log!(
            "flow {id}: connecting to {name} ({})",
            svc.advert.key.short()
        );
        let flow = Flow::new(id, conn, true, Some(svc.advert.key));
        st.flows.insert(id, flow.clone());
        self.run_flow(&flow);
    }

    /// The listener got a new inbound flow.
    fn accept(self: &Arc<Self>, conn: Nw) {
        let mut st = self.st.lock();
        let inbound = st.flows.values().filter(|f| !f.outbound).count();
        if inbound >= MAX_INBOUND {
            unsafe { ffi::nw_connection_cancel(conn.ptr()) };
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        log!("flow {id}: inbound from {}", ffi::remote_of(conn.ptr()));
        let flow = Flow::new(id, conn, false, None);
        st.flows.insert(id, flow.clone());
        self.run_flow(&flow);
    }

    fn run_flow(self: &Arc<Self>, flow: &Arc<Flow>) {
        let (ws, wf) = (Arc::downgrade(self), Arc::downgrade(flow));
        let on_state = RcBlock::new(move |state: u32, err: ffi::nw_object| {
            let (Some(s), Some(f)) = (ws.upgrade(), wf.upgrade()) else {
                return;
            };
            s.on_flow_state(&f, state, ffi::error_of(err));
        });
        unsafe {
            ffi::nw_connection_set_queue(flow.conn.ptr(), self.queue.ptr());
            ffi::nw_connection_set_state_changed_handler(flow.conn.ptr(), &on_state);
            ffi::nw_connection_start(flow.conn.ptr());
        }
    }

    fn on_flow_state(self: &Arc<Self>, flow: &Arc<Flow>, state: u32, err: Option<(u32, i32)>) {
        log!("flow {}: state {state} err {err:?}", flow.id);
        match state {
            ffi::CONN_READY => {
                if !self.any_iface {
                    let ifaces =
                        Nw::owned(unsafe { ffi::nw_connection_copy_current_path(flow.conn.ptr()) })
                            .map(|p| ffi::interfaces_of_path(p.ptr()))
                            .unwrap_or_default();
                    if !ifaces.iter().any(|n| wire::is_peer_to_peer_interface(n)) {
                        log!(
                            "flow {}: not on peer-to-peer Wi-Fi ({ifaces:?}), closing",
                            flow.id
                        );
                        flow.cancel();
                        return;
                    }
                }
                let max = unsafe { ffi::nw_connection_get_maximum_datagram_size(flow.conn.ptr()) };
                flow.max_datagram.store(max as usize, Ordering::Relaxed);
                log!(
                    "flow {}: ready via {} (max datagram {max})",
                    flow.id,
                    ffi::remote_of(flow.conn.ptr())
                );
                flow.ready.store(true, Ordering::Release);
                self.st.lock().flow_denied = false;
                if !flow.closed.load(Ordering::Acquire) {
                    self.receive(flow);
                    if flow.outbound {
                        self.hello(flow);
                    }
                }
            }
            ffi::CONN_WAITING | ffi::CONN_PREPARING => {
                flow.ready.store(false, Ordering::Release);
                if state == ffi::CONN_WAITING {
                    let reason =
                        Nw::owned(unsafe { ffi::nw_connection_copy_current_path(flow.conn.ptr()) })
                            .map(|p| unsafe { ffi::nw_path_get_unsatisfied_reason(p.ptr()) });
                    if reason == Some(ffi::UNSATISFIED_LOCAL_NETWORK_DENIED) {
                        log!("flow {}: Local Network access denied", flow.id);
                        self.st.lock().flow_denied = true;
                    }
                }
                self.recompute();
            }
            ffi::CONN_FAILED => flow.cancel(),
            ffi::CONN_CANCELLED => {
                log!(
                    "flow {}: closed after {} datagrams in, largest {} bytes",
                    flow.id,
                    flow.rx_count.load(Ordering::Relaxed),
                    flow.rx_largest.load(Ordering::Relaxed)
                );
                flow.closed.store(true, Ordering::Release);
                flow.ready.store(false, Ordering::Release);
                {
                    let mut st = self.st.lock();
                    st.flows.remove(&flow.id);
                    for svc in st.services.values_mut() {
                        if svc.flow == Some(flow.id) {
                            svc.flow = None;
                        }
                    }
                }
                self.recompute();
            }
            _ => {}
        }
    }

    fn hello(&self, flow: &Flow) {
        *flow.last_hello.lock() = Some(Instant::now());
        flow.send(&Control::Hello(self.me).encode());
    }

    /// Keep one receive outstanding per flow (one datagram each).
    fn receive(self: &Arc<Self>, flow: &Arc<Flow>) {
        let (ws, wf) = (Arc::downgrade(self), Arc::downgrade(flow));
        let done = RcBlock::new(
            move |content: ffi::dispatch_object,
                  _ctx: ffi::nw_object,
                  _complete: ffi::CBool,
                  err: ffi::nw_object| {
                let (Some(s), Some(f)) = (ws.upgrade(), wf.upgrade()) else {
                    return;
                };
                if !content.is_null() {
                    s.on_datagram(&f, ffi::data_bytes(content));
                }
                if let Some(e) = ffi::error_of(err) {
                    log!("flow {}: receive error {e:?}", f.id);
                    return;
                }
                if !f.closed.load(Ordering::Acquire) && !s.stopped.load(Ordering::Acquire) {
                    s.receive(&f);
                }
            },
        );
        unsafe { ffi::nw_connection_receive_message(flow.conn.ptr(), &done) };
    }

    fn on_datagram(self: &Arc<Self>, flow: &Arc<Flow>, data: Vec<u8>) {
        let now = Instant::now();
        flow.rx_count.fetch_add(1, Ordering::Relaxed);
        flow.rx_largest.fetch_max(data.len(), Ordering::Relaxed);
        match Control::decode(&data) {
            Some(Control::Hello(key)) => {
                if key == self.me {
                    return;
                }
                let was_alive = flow.alive(now);
                {
                    let mut peer = flow.peer.lock();
                    if flow.outbound && *peer != Some(key) {
                        return; // the service claimed another key: ignore
                    }
                    *peer = Some(key);
                }
                *flow.last_rx.lock() = Some(now);
                flow.send(&Control::Ack(self.me).encode());
                if !was_alive {
                    log!("flow {}: hello from {}", flow.id, key.short());
                    self.recompute();
                }
            }
            Some(Control::Ack(key)) => {
                if *flow.peer.lock() != Some(key) {
                    return;
                }
                let was_alive = flow.alive(now);
                *flow.last_rx.lock() = Some(now);
                if !was_alive {
                    log!("flow {}: ack from {}", flow.id, key.short());
                    self.recompute();
                }
            }
            None => {
                let Some(from) = *flow.peer.lock() else {
                    return; // QUIC before the hello: dropped, QUIC retransmits
                };
                *flow.last_rx.lock() = Some(now);
                // A full queue drops the packet, like a congested radio.
                let _ = self.tx.try_send(Packet {
                    data: Bytes::from(data),
                    from,
                });
            }
        }
    }

    /// Re-pick each peer's flow and tell the node who appeared / vanished.
    fn recompute(&self) {
        let now = Instant::now();
        let mut st = self.st.lock();
        let mut best: HashMap<SignPk, Arc<Flow>> = HashMap::new();
        for f in st.flows.values() {
            let Some(peer) = *f.peer.lock() else { continue };
            if !f.alive(now) {
                continue;
            }
            let better = match best.get(&peer) {
                None => true,
                // prefer our own outbound flow (its key came from the
                // advertisement), then the most recently heard
                Some(b) => (f.outbound, *f.last_rx.lock()) > (b.outbound, *b.last_rx.lock()),
            };
            if better {
                best.insert(peer, f.clone());
            }
        }
        let name_of = |st: &State, peer: &SignPk| {
            st.services
                .values()
                .find(|s| s.advert.key == *peer)
                .and_then(|s| s.advert.name.clone())
        };
        // keep the last name we knew if its advertisement is gone for now
        let now_up: HashMap<SignPk, Option<String>> = best
            .keys()
            .map(|p| {
                (
                    *p,
                    name_of(&st, p).or_else(|| st.reported.get(p).cloned().flatten()),
                )
            })
            .collect();
        *self.routes.write() = best;
        for (peer, name) in &now_up {
            // new, or its name became known (an inbound-only peer we then browsed)
            if st.reported.get(peer) != Some(name) {
                log!("found {} {name:?}", peer.short());
                self.emit(LinkEvent::Found {
                    peer: *peer,
                    addr: addr_of(peer),
                    name: name.clone(),
                });
            }
        }
        for peer in st.reported.keys().filter(|p| !now_up.contains_key(p)) {
            log!("lost {}", peer.short());
            self.emit(LinkEvent::Lost {
                peer: *peer,
                addr: addr_of(peer),
            });
        }
        st.reported = now_up;
    }

    /// Timer: liveness hellos, reconnects, expiry.
    fn tick(self: &Arc<Self>) {
        let now = Instant::now();
        let mut st = self.st.lock();
        let flows: Vec<Arc<Flow>> = st.flows.values().cloned().collect();
        for f in &flows {
            if f.closed.load(Ordering::Acquire) {
                continue;
            }
            let heard = f.last_rx.lock().unwrap_or(f.created);
            if now.duration_since(heard) > FLOW_EXPIRE {
                log!(
                    "flow {}: silent for {:?}, closing",
                    f.id,
                    now.duration_since(heard)
                );
                f.cancel();
                continue;
            }
            if f.outbound
                && f.ready.load(Ordering::Acquire)
                && f.last_hello
                    .lock()
                    .is_none_or(|t| now.duration_since(t) >= HELLO_EVERY)
            {
                self.hello(f);
            }
        }
        let retry: Vec<String> = st
            .services
            .iter()
            .filter(|(_, s)| {
                s.eligible
                    && s.flow.is_none()
                    && s.last_attempt
                        .is_none_or(|t| now.duration_since(t) >= RETRY_EVERY)
            })
            .map(|(n, _)| n.clone())
            .collect();
        for name in retry {
            self.connect(&mut st, &name);
        }
        let restart_listener = st.listener.is_none()
            && st
                .listener_failed
                .take_if(|t| now.duration_since(*t) >= RESTART_EVERY)
                .is_some();
        let restart_browser = st.browser.is_none()
            && st
                .browser_failed
                .take_if(|t| now.duration_since(*t) >= RESTART_EVERY)
                .is_some();
        drop(st);
        if restart_listener && !self.stopped.load(Ordering::Acquire) {
            log!("restarting listener");
            self.start_listener();
        }
        if restart_browser && !self.stopped.load(Ordering::Acquire) {
            log!("restarting browser");
            self.start_browser();
        }
        self.recompute();
    }

    fn status(&self) -> LinkStatus {
        let st = self.st.lock();
        let peers = self.routes.read().len();
        let denied = st.flow_denied
            || [st.listener_err, st.browser_err]
                .iter()
                .any(|e| matches!(e, Some((ffi::ERR_DNS, wire::DNS_POLICY_DENIED))));
        let started = self.started.load(Ordering::Acquire);
        let stopped = self.stopped.load(Ordering::Acquire);
        let radio = self.any_iface || awdl_up();
        let ready =
            st.listener_state == ffi::LISTENER_READY && st.browser_state == ffi::BROWSER_READY;
        let failed =
            st.listener_state == ffi::LISTENER_FAILED || st.browser_state == ffi::BROWSER_FAILED;
        let detail = if stopped {
            Some("Stopped".to_string())
        } else if !started {
            Some("Not started".to_string())
        } else if denied {
            Some("Local Network permission denied (System Settings › Privacy & Security › Local Network)".to_string())
        } else if !radio {
            Some("Wi-Fi is off".to_string())
        } else if failed {
            let e = st.listener_err.or(st.browser_err);
            Some(format!(
                "Peer-to-peer Wi-Fi failed{}",
                e.map(|(d, c)| format!(" (error {d}/{c})"))
                    .unwrap_or_default()
            ))
        } else if !ready {
            Some("Starting peer-to-peer Wi-Fi…".to_string())
        } else {
            None
        };
        LinkStatus {
            kind: PathKind::PeerWifi,
            active: detail.is_none(),
            detail,
            peers,
        }
    }

    fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut st = self.st.lock();
        if let Some(l) = st.listener.take() {
            unsafe { ffi::nw_listener_cancel(l.ptr()) };
        }
        if let Some(b) = st.browser.take() {
            unsafe { ffi::nw_browser_cancel(b.ptr()) };
        }
        for f in st.flows.values() {
            f.cancel();
        }
        st.services.clear();
        self.routes.write().clear();
        for peer in std::mem::take(&mut st.reported).into_keys() {
            self.emit(LinkEvent::Lost {
                peer,
                addr: addr_of(&peer),
            });
        }
    }
}

fn cstring(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

fn result_name(r: ffi::nw_object) -> Option<String> {
    let ep = Nw::owned(unsafe { ffi::nw_browse_result_copy_endpoint(r) })?;
    if unsafe { ffi::nw_endpoint_get_type(ep.ptr()) } != ffi::ENDPOINT_BONJOUR {
        return None;
    }
    ffi::cstr(unsafe { ffi::nw_endpoint_get_bonjour_service_name(ep.ptr()) })
}

/// Is the peer-to-peer Wi-Fi interface up? (It goes down with the Wi-Fi radio.)
fn awdl_up() -> bool {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return true; // can't tell: don't claim it's off
    }
    let mut up = false;
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes();
            let flags = ifa.ifa_flags as libc::c_int;
            if name.starts_with(b"awdl")
                && flags & libc::IFF_UP != 0
                && flags & libc::IFF_RUNNING != 0
            {
                up = true;
                break;
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    up
}

// ─────────────────────────────── Iroh side ───────────────────────────────

struct AwdlTransport {
    shared: Arc<Shared>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for AwdlTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AwdlTransport")
    }
}

impl CustomTransport for AwdlTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self
            .rx
            .clone()
            .try_lock_owned()
            .map_err(|_| io::Error::other("peer-to-peer Wi-Fi link already bound"))?;
        let local = addr_of(&self.shared.me);
        Ok(Box::new(AwdlEndpoint {
            shared: self.shared.clone(),
            addrs: n0_watcher::Watchable::new(vec![local.clone()]),
            local,
            rx,
        }))
    }
}

struct AwdlEndpoint {
    shared: Arc<Shared>,
    local: CustomAddr,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<Packet>>,
}

impl std::fmt::Debug for AwdlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AwdlEndpoint")
    }
}

impl CustomEndpoint for AwdlEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(AwdlSender {
            shared: self.shared.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len();
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut packets = Vec::with_capacity(n);
        match self.rx.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => {
                return Poll::Ready(Err(io::Error::other("peer-to-peer Wi-Fi link closed")));
            }
            Poll::Ready(_) => {}
        }
        let mut count = 0;
        for p in packets {
            if bufs[count].len() < p.data.len() {
                continue;
            }
            bufs[count][..p.data.len()].copy_from_slice(&p.data);
            metas[count].len = p.data.len();
            metas[count].stride = p.data.len();
            recv_infos[count] = RecvInfo::new(addr_of(&p.from), Some(self.local.clone()));
            count += 1;
        }
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }
}

struct AwdlSender {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for AwdlSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AwdlSender")
    }
}

impl CustomSender for AwdlSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        parse_addr(addr).is_some()
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(peer) = parse_addr(dst) else {
            return Poll::Ready(Err(io::Error::other("not a peer-to-peer Wi-Fi address")));
        };
        // No flow to the peer right now: the packet is lost in the air and
        // QUIC treats it like any other loss.
        let Some(flow) = self.shared.routes.read().get(&peer).cloned() else {
            return Poll::Ready(Ok(()));
        };
        let seg = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for chunk in transmit.contents.chunks(seg) {
            flow.send(chunk);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_addr_is_the_node_key() {
        let pk = SignPk([9; 32]);
        assert_eq!(parse_addr(&addr_of(&pk)), Some(pk));
        assert_eq!(
            parse_addr(&CustomAddr::from_parts(TRANSPORT_PEER_WIFI, &[1, 2, 3])),
            None
        );
        assert_eq!(
            parse_addr(&CustomAddr::from_parts(
                mycel_net::link::TRANSPORT_BLUETOOTH,
                &pk.0
            )),
            None
        );
    }
}
