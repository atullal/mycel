//! Standard Bonjour LAN discovery on Apple platforms. DNS-SD performs multicast
//! in the system daemon; the app only uses the declared `_mycel._udp` service.
//! Advertisements are untrusted hints. QUIC still authenticates the endpoint key.
use iroh::{
    EndpointId,
    address_lookup::{
        AddressLookup, EndpointData, EndpointInfo, Error, Item, MemoryLookup, UserData,
    },
};
use iroh_mdns_address_lookup::DiscoveryEvent;
use n0_future::boxed::BoxStream;
use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString, c_char, c_void},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const SERVICE: &CStr = c"_mycel._udp";
const MAX_SERVICES: usize = 128;
const ADD: u32 = 2;
type Ref = *mut c_void;
// SDK dns_sd.h signatures. All references, callbacks and deallocation stay on
// one thread; no DNSServiceRef is accessed while another thread processes it.
#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceBrowse(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        ty: *const c_char,
        domain: *const c_char,
        cb: unsafe extern "C" fn(
            Ref,
            u32,
            u32,
            i32,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut c_void,
        ),
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceResolve(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        name: *const c_char,
        ty: *const c_char,
        domain: *const c_char,
        cb: unsafe extern "C" fn(
            Ref,
            u32,
            u32,
            i32,
            *const c_char,
            *const c_char,
            u16,
            u16,
            *const u8,
            *mut c_void,
        ),
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceGetAddrInfo(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        protocol: u32,
        host: *const c_char,
        cb: unsafe extern "C" fn(
            Ref,
            u32,
            u32,
            i32,
            *const c_char,
            *const libc::sockaddr,
            u32,
            *mut c_void,
        ),
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceRegister(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        name: *const c_char,
        ty: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port: u16,
        txt_len: u16,
        txt: *const c_void,
        cb: Option<
            unsafe extern "C" fn(
                Ref,
                u32,
                i32,
                *const c_char,
                *const c_char,
                *const c_char,
                *mut c_void,
            ),
        >,
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(r: Ref) -> i32;
    fn DNSServiceProcessResult(r: Ref) -> i32;
    fn DNSServiceRefDeallocate(r: Ref);
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceKey {
    name: String,
    ty: String,
    domain: String,
    iface: u32,
}
enum Event {
    Restart,
    Browse(ServiceKey, bool),
    Resolved(ServiceKey, String, u16, Option<UserData>),
    Address(ServiceKey, IpAddr, bool),
    Failed(ServiceKey),
}
struct Context {
    overflow: Arc<AtomicBool>,
    tx: mpsc::SyncSender<Event>,
    key: Option<ServiceKey>,
}
impl Context {
    fn send(&self, event: Event) {
        if matches!(self.tx.try_send(event), Err(mpsc::TrySendError::Full(_))) {
            self.overflow.store(true, Ordering::Release);
        }
    }
}
struct Operation {
    raw: Ref,
    _context: Box<Context>,
}
impl Drop for Operation {
    fn drop(&mut self) {
        unsafe { DNSServiceRefDeallocate(self.raw) };
    }
}
impl Operation {
    fn new(context: Context, call: impl FnOnce(*mut Ref, *mut c_void) -> i32) -> Option<Self> {
        let mut context = Box::new(context);
        let mut raw = std::ptr::null_mut();
        let err = call(&mut raw, (&mut *context as *mut Context).cast());
        if err != 0 || raw.is_null() {
            eprintln!("[mycel] native Bonjour operation failed: {err}");
            return None;
        }
        Some(Self {
            raw,
            _context: context,
        })
    }
}
// DNS-SD strings are NUL terminated by the system API, not arbitrary packet
// pointers. Still reject overlong fields before retaining remote data.
unsafe fn string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().ok()?;
    (s.len() <= 255).then(|| s.to_string())
}
unsafe extern "C" fn browse(
    _r: Ref,
    flags: u32,
    iface: u32,
    err: i32,
    name: *const c_char,
    ty: *const c_char,
    domain: *const c_char,
    ctx: *mut c_void,
) {
    if err != 0 {
        eprintln!("[mycel] native Bonjour browse failed: {err}");
        let c = unsafe { &*(ctx as *const Context) };
        c.send(Event::Restart);
        return;
    }
    let (Some(name), Some(ty), Some(domain)) =
        (unsafe { string(name) }, unsafe { string(ty) }, unsafe {
            string(domain)
        })
    else {
        return;
    };
    if name.parse::<EndpointId>().is_err() {
        return;
    }
    let c = unsafe { &*(ctx as *const Context) };
    c.send(Event::Browse(
        ServiceKey {
            name,
            ty,
            domain,
            iface,
        },
        flags & ADD != 0,
    ));
}
unsafe extern "C" fn resolved(
    _r: Ref,
    _flags: u32,
    _iface: u32,
    err: i32,
    _full: *const c_char,
    host: *const c_char,
    port: u16,
    len: u16,
    txt: *const u8,
    ctx: *mut c_void,
) {
    let c = unsafe { &*(ctx as *const Context) };
    let Some(key) = &c.key else {
        return;
    };
    if err != 0 {
        c.send(Event::Failed(key.clone()));
        return;
    }
    let Some(host) = (unsafe { string(host) }) else {
        return;
    };
    if len > 4096 || (len > 0 && txt.is_null()) {
        return;
    }
    let txt = if len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(txt, len as usize) }
    };
    c.send(Event::Resolved(
        key.clone(),
        host,
        u16::from_be(port),
        parse_txt(txt),
    ));
}
unsafe extern "C" fn address(
    _r: Ref,
    flags: u32,
    _iface: u32,
    err: i32,
    _host: *const c_char,
    addr: *const libc::sockaddr,
    _ttl: u32,
    ctx: *mut c_void,
) {
    let c = unsafe { &*(ctx as *const Context) };
    let Some(key) = &c.key else {
        return;
    };
    if err != 0 || addr.is_null() {
        c.send(Event::Failed(key.clone()));
        return;
    }
    let ip = match unsafe { (*addr).sa_family as i32 } {
        libc::AF_INET => {
            let a = unsafe { &*(addr as *const libc::sockaddr_in) };
            IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(addr as *const libc::sockaddr_in6) };
            IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr))
        }
        _ => return,
    };
    // Scoped IPv6 needs an interface-aware address type that Iroh does not
    // expose here. IPv4 and routable IPv6 still work; never publish a bad scope.
    if ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local())
    {
        return;
    }
    c.send(Event::Address(key.clone(), ip, flags & ADD != 0));
}
// Match swarm-discovery's lowercase RFC 4648 base32 key. A hex key is
// 64 bytes and exceeds Bonjour's 63-byte service-instance label limit.
fn instance_name(me: EndpointId) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(52);
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in me.as_bytes() {
        bits = (bits << 8) | u32::from(*byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(ALPHABET[((bits >> count) & 31) as usize] as char);
        }
    }
    if count > 0 {
        out.push(ALPHABET[((bits << (5 - count)) & 31) as usize] as char);
    }
    out
}
unsafe extern "C" fn registered(
    _r: Ref,
    _flags: u32,
    err: i32,
    _name: *const c_char,
    _ty: *const c_char,
    _domain: *const c_char,
    ctx: *mut c_void,
) {
    if err != 0 {
        eprintln!("[mycel] native Bonjour registration failed: {err}");
        let c = unsafe { &*(ctx as *const Context) };
        c.send(Event::Restart);
    }
}
fn parse_txt(mut txt: &[u8]) -> Option<UserData> {
    while let Some((&len, rest)) = txt.split_first() {
        let len = len as usize;
        if rest.len() < len {
            return None;
        }
        let value = &rest[..len];
        txt = &rest[len..];
        if let Some(value) = value.strip_prefix(b"user-data=") {
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
    }
    None
}
fn make_txt(data: &EndpointData) -> Vec<u8> {
    let Some(user) = data.user_data() else {
        return vec![];
    };
    let value = format!("user-data={}", user.as_ref());
    if value.len() > 255 {
        return vec![];
    }
    let mut txt = vec![value.len() as u8];
    txt.extend_from_slice(value.as_bytes());
    txt
}
#[derive(Debug)]
struct Shared {
    published: Mutex<Option<EndpointData>>,
    stopped: AtomicBool,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}
#[derive(Clone, Debug)]
pub(crate) struct NativeMdns {
    shared: Arc<Shared>,
    memory: MemoryLookup,
}
impl AddressLookup for NativeMdns {
    fn publish(&self, data: &EndpointData) {
        *self.shared.published.lock() = Some(data.clone());
    }
    fn resolve(&self, id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.memory.resolve(id)
    }
}
struct Peer {
    resolve: Option<Operation>,
    addresses: Option<Operation>,
    port: u16,
    host: Option<String>,
    user: Option<UserData>,
    ips: BTreeSet<IpAddr>,
    retry_at: Instant,
}
impl NativeMdns {
    pub(crate) fn start(
        me: EndpointId,
        bound_port: u16,
    ) -> std::io::Result<(Self, tokio::sync::mpsc::Receiver<DiscoveryEvent>)> {
        let shared = Arc::new(Shared {
            published: Mutex::new(None),
            stopped: AtomicBool::new(false),
        });
        let memory = MemoryLookup::with_provenance("native_bonjour");
        let (out, rx) = tokio::sync::mpsc::channel(1024);
        let weak = Arc::downgrade(&shared);
        let lookup = memory.clone();
        std::thread::Builder::new()
            .name("mycel.bonjour".into())
            .spawn(move || {
                let (tx, events) = mpsc::sync_channel(1024);
                let mut browser: Option<Operation> = None;
                let mut registrations = Vec::new();
                let mut last_publication: Option<EndpointData> = None;
                let mut peers: BTreeMap<ServiceKey, Peer> = BTreeMap::new();
                let mut known: BTreeMap<EndpointId, EndpointData> = BTreeMap::new();
                let mut retry = Instant::now();
                let overflow = Arc::new(AtomicBool::new(false));
                loop {
                    let Some(s) = weak.upgrade() else {
                        break;
                    };
                    if s.stopped.load(Ordering::Acquire) || out.is_closed() {
                        break;
                    }
                    let publication = s.published.lock().clone();
                    drop(s);
                    if browser.is_none() && Instant::now() >= retry {
                        browser = Operation::new(
                            Context {
                                overflow: overflow.clone(),
                                tx: tx.clone(),
                                key: None,
                            },
                            |r, c| unsafe {
                                DNSServiceBrowse(
                                    r,
                                    0,
                                    0,
                                    SERVICE.as_ptr(),
                                    c"local.".as_ptr(),
                                    browse,
                                    c,
                                )
                            },
                        );
                        retry = Instant::now() + Duration::from_secs(5);
                    }
                    if browser.is_some()
                        && (publication != last_publication
                            || registrations.is_empty() && Instant::now() >= retry)
                    {
                        registrations.clear();
                        if let Some(data) = &publication {
                            let txt = make_txt(data);
                            let name = CString::new(instance_name(me)).unwrap();
                            // Bonjour advertises this machine's hostname. Only the
                            // actual bound local socket port belongs on that host;
                            // public NAT/STUN ports in EndpointData do not.
                            if bound_port != 0 && data.ip_addrs().any(|a| !a.ip().is_loopback()) {
                                let port = bound_port;
                                if let Some(op) = Operation::new(
                                    Context {
                                        overflow: overflow.clone(),
                                        tx: tx.clone(),
                                        key: None,
                                    },
                                    |r, c| unsafe {
                                        DNSServiceRegister(
                                            r,
                                            0,
                                            0,
                                            name.as_ptr(),
                                            SERVICE.as_ptr(),
                                            c"local.".as_ptr(),
                                            std::ptr::null(),
                                            port.to_be(),
                                            txt.len() as u16,
                                            txt.as_ptr().cast(),
                                            Some(registered),
                                            c,
                                        )
                                    },
                                ) {
                                    registrations.push(op);
                                }
                            }
                        }
                        last_publication = publication;
                    }
                    for (key, p) in &mut peers {
                        if p.resolve.is_none() && Instant::now() >= p.retry_at {
                            let (Ok(n), Ok(t), Ok(d)) = (
                                CString::new(key.name.as_str()),
                                CString::new(key.ty.as_str()),
                                CString::new(key.domain.as_str()),
                            ) else {
                                continue;
                            };
                            p.resolve = Operation::new(
                                Context {
                                    overflow: overflow.clone(),
                                    tx: tx.clone(),
                                    key: Some(key.clone()),
                                },
                                |r, c| unsafe {
                                    DNSServiceResolve(
                                        r,
                                        0,
                                        key.iface,
                                        n.as_ptr(),
                                        t.as_ptr(),
                                        d.as_ptr(),
                                        resolved,
                                        c,
                                    )
                                },
                            );
                            p.retry_at = Instant::now() + Duration::from_secs(5);
                        }
                    }
                    let mut ready = Vec::new();
                    if let Some(b) = &browser {
                        ready.push(b.raw);
                    }
                    ready.extend(registrations.iter().map(|o| o.raw));
                    ready.extend(
                        peers.values().flat_map(|p| {
                            p.resolve.iter().chain(p.addresses.iter()).map(|o| o.raw)
                        }),
                    );
                    let mut fds: Vec<_> = ready
                        .iter()
                        .map(|r| libc::pollfd {
                            fd: unsafe { DNSServiceRefSockFD(*r) },
                            events: libc::POLLIN,
                            revents: 0,
                        })
                        .collect();
                    unsafe {
                        libc::poll(fds.as_mut_ptr(), fds.len() as _, 250);
                    }
                    let mut failed = BTreeSet::new();
                    for (r, fd) in ready.iter().zip(&fds) {
                        if fd.revents != 0
                            && (fd.revents & libc::POLLIN == 0
                                || unsafe { DNSServiceProcessResult(*r) } != 0)
                        {
                            failed.insert(*r as usize);
                        }
                    }
                    if browser
                        .as_ref()
                        .is_some_and(|b| failed.contains(&(b.raw as usize)))
                    {
                        browser = None;
                        peers.clear();
                    }
                    registrations.retain(|o| !failed.contains(&(o.raw as usize)));
                    for p in peers.values_mut() {
                        if p.resolve
                            .as_ref()
                            .is_some_and(|o| failed.contains(&(o.raw as usize)))
                            || p.addresses
                                .as_ref()
                                .is_some_and(|o| failed.contains(&(o.raw as usize)))
                        {
                            p.resolve = None;
                            p.addresses = None;
                            p.ips.clear();
                        }
                    }
                    if overflow.swap(false, Ordering::AcqRel) {
                        // A dropped callback may have been a removal. Rebuild a
                        // complete browser snapshot rather than retain stale peers.
                        browser = None;
                        peers.clear();
                        retry = Instant::now();
                        while events.try_recv().is_ok() {}
                    }
                    for ev in events.try_iter().take(1024) {
                        match ev {
                            Event::Restart => {
                                browser = None;
                                registrations.clear();
                                last_publication = None;
                                peers.clear();
                                retry = Instant::now() + Duration::from_secs(5);
                            }
                            Event::Browse(key, true)
                                if key.name.parse::<EndpointId>().ok() != Some(me)
                                    && peers.len() < MAX_SERVICES =>
                            {
                                peers.entry(key).or_insert(Peer {
                                    resolve: None,
                                    addresses: None,
                                    port: 0,
                                    host: None,
                                    user: None,
                                    ips: BTreeSet::new(),
                                    retry_at: Instant::now(),
                                });
                            }
                            Event::Browse(key, false) => {
                                peers.remove(&key);
                            }
                            Event::Resolved(key, host, port, user) => {
                                if let Some(p) = peers.get_mut(&key) {
                                    p.resolve = None;
                                    p.user = user;
                                    if p.host.as_deref() == Some(host.as_str())
                                        && p.port == port
                                        && p.addresses.is_some()
                                    {
                                        continue;
                                    }
                                    p.port = port;
                                    p.host = Some(host.clone());
                                    p.ips.clear();
                                    if port > 0
                                        && let Ok(host) = CString::new(host)
                                    {
                                        p.addresses = Operation::new(
                                            Context {
                                                overflow: overflow.clone(),
                                                tx: tx.clone(),
                                                key: Some(key.clone()),
                                            },
                                            |r, c| unsafe {
                                                DNSServiceGetAddrInfo(
                                                    r,
                                                    0,
                                                    key.iface,
                                                    3,
                                                    host.as_ptr(),
                                                    address,
                                                    c,
                                                )
                                            },
                                        );
                                    }
                                }
                            }
                            Event::Address(key, ip, add) => {
                                if let Some(p) = peers.get_mut(&key) {
                                    if add && p.ips.len() < 16 {
                                        p.ips.insert(ip);
                                    } else if !add {
                                        p.ips.remove(&ip);
                                    }
                                }
                            }
                            Event::Failed(key) => {
                                if let Some(p) = peers.get_mut(&key) {
                                    p.resolve = None;
                                    p.addresses = None;
                                    p.ips.clear();
                                    p.retry_at = Instant::now() + Duration::from_secs(5);
                                }
                            }
                            _ => {}
                        }
                    }
                    let mut current: BTreeMap<EndpointId, EndpointData> = BTreeMap::new();
                    for (key, p) in &peers {
                        if p.port > 0
                            && !p.ips.is_empty()
                            && let Ok(id) = key.name.parse()
                        {
                            let data = current.entry(id).or_default();
                            for ip in &p.ips {
                                data.add_ip_addrs(vec![SocketAddr::new(*ip, p.port)]);
                            }
                            data.set_user_data(p.user.clone());
                        }
                    }
                    deliver_changes(&out, &lookup, &mut known, current);
                }
            })?;
        Ok((Self { shared, memory }, rx))
    }
}
/// Delivery state advances only when the consumer received that transition.
/// Full channels retry from the same state on the next bounded poll cycle.
fn deliver_changes(
    out: &tokio::sync::mpsc::Sender<DiscoveryEvent>,
    lookup: &MemoryLookup,
    known: &mut BTreeMap<EndpointId, EndpointData>,
    current: BTreeMap<EndpointId, EndpointData>,
) {
    let removed: Vec<_> = known
        .keys()
        .filter(|id| !current.contains_key(*id))
        .copied()
        .collect();
    for id in removed {
        if out
            .try_send(DiscoveryEvent::Expired { endpoint_id: id })
            .is_ok()
        {
            lookup.remove_endpoint_info(id);
            known.remove(&id);
        }
    }
    for (id, data) in current {
        if known.get(&id) == Some(&data) {
            continue;
        }
        let info = EndpointInfo::from_parts(id, data.clone());
        if out
            .try_send(DiscoveryEvent::Discovered {
                endpoint_info: info.clone(),
                last_updated: None,
            })
            .is_ok()
        {
            lookup.set_endpoint_info(info);
            known.insert(id, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_backpressure_retries_discovery_and_expiry() {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let memory = MemoryLookup::new();
        let mut known = BTreeMap::new();
        let current = BTreeMap::from([(a, EndpointData::default()), (b, EndpointData::default())]);
        deliver_changes(&tx, &memory, &mut known, current.clone());
        assert_eq!(known.len(), 1, "undelivered discovery must remain pending");
        rx.try_recv().unwrap();
        deliver_changes(&tx, &memory, &mut known, current);
        assert_eq!(known.len(), 2);
        deliver_changes(&tx, &memory, &mut known, BTreeMap::new());
        assert_eq!(known.len(), 2, "full output cannot forget pending removals");
        rx.try_recv().unwrap();
        deliver_changes(&tx, &memory, &mut known, BTreeMap::new());
        assert_eq!(known.len(), 1);
        assert!(matches!(rx.try_recv(), Ok(DiscoveryEvent::Expired { .. })));
        deliver_changes(&tx, &memory, &mut known, BTreeMap::new());
        assert!(known.is_empty());
    }

    #[test]
    fn callback_overflow_requests_complete_resync() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let flag = Arc::new(AtomicBool::new(false));
        let context = Context {
            tx,
            overflow: flag.clone(),
            key: None,
        };
        context.send(Event::Restart);
        assert!(!flag.load(Ordering::Acquire));
        context.send(Event::Restart);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn undelivered_transient_peer_cannot_leave_a_cached_address() {
        let peer = iroh::SecretKey::generate().public();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(DiscoveryEvent::Expired { endpoint_id: peer })
            .unwrap();
        let memory = MemoryLookup::new();
        let mut known = BTreeMap::new();
        deliver_changes(
            &tx,
            &memory,
            &mut known,
            BTreeMap::from([(peer, EndpointData::default())]),
        );
        assert!(known.is_empty());
        assert!(memory.get_endpoint_info(peer).is_none());
        deliver_changes(&tx, &memory, &mut known, BTreeMap::new());
        assert!(memory.get_endpoint_info(peer).is_none());
    }

    #[test]
    fn address_callback_overflow_requests_resync() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let flag = Arc::new(AtomicBool::new(false));
        let mut context = Context {
            tx,
            overflow: flag.clone(),
            key: Some(ServiceKey {
                name: "peer".into(),
                ty: "_iroh._udp".into(),
                domain: "local.".into(),
                iface: 1,
            }),
        };
        context.send(Event::Restart);
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as _;
        addr.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 1]);
        unsafe {
            address(
                std::ptr::null_mut(),
                0,
                1,
                0,
                std::ptr::null(),
                (&addr as *const libc::sockaddr_in).cast(),
                30,
                (&mut context as *mut Context).cast(),
            );
        }
        assert!(
            flag.load(Ordering::Acquire),
            "lost address removal must trigger resync"
        );
    }

    #[test]
    fn service_instance_matches_legacy_base32_key() {
        let me = iroh::SecretKey::generate().public();
        let name = instance_name(me);
        assert_eq!(name.len(), 52);
        assert_eq!(name.parse::<EndpointId>().unwrap(), me);
    }

    /// Requires Local Network permission and a connected LAN. Explicitly run
    /// this on Apple hardware; pure parsing tests do not claim radio coverage.
    #[tokio::test]
    #[ignore = "requires an available LAN and macOS Local Network permission"]
    async fn native_bonjour_discovers_updates_and_removes_a_peer() {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        let (first, mut rx) = NativeMdns::start(a, 35490).unwrap();
        let (second, second_rx) = NativeMdns::start(b, 35491).unwrap();
        let mut data = EndpointData::from(BTreeSet::from(["192.0.2.1:35491"
            .parse::<SocketAddr>()
            .unwrap()]));
        // A published endpoint can also carry a different external NAT port.
        // It must never create a second Bonjour instance or advertise that port.
        data.add_ip_addrs(vec!["203.0.113.2:54321".parse().unwrap()]);
        data.set_user_data(Some("mycel:Native LAN test".parse().unwrap()));
        second.publish(&data);
        let legacy = iroh_mdns_address_lookup::MdnsAddressLookup::builder()
            .service_name("mycel")
            .build(b)
            .unwrap();
        legacy.publish(&data);
        let info = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = rx.recv().await {
                    if endpoint_info.endpoint_id == b {
                        break endpoint_info;
                    }
                }
            }
        })
        .await
        .expect("native Bonjour did not find peer");
        assert!(info.data.ip_addrs().all(|a| a.port() == 35491));
        assert_eq!(
            info.data.user_data().unwrap().as_ref(),
            "mycel:Native LAN test"
        );
        data.set_user_data(Some("mycel:Updated LAN test".parse().unwrap()));
        second.publish(&data);
        legacy.publish(&data);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = rx.recv().await {
                    if endpoint_info.endpoint_id == b
                        && endpoint_info
                            .data
                            .user_data()
                            .is_some_and(|u| u.as_ref() == "mycel:Updated LAN test")
                    {
                        break;
                    }
                }
            }
        })
        .await
        .expect("native Bonjour did not update peer name");
        drop(legacy);
        drop(second);
        drop(second_rx);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Expired { endpoint_id }) = rx.recv().await {
                    if endpoint_id == b {
                        break;
                    }
                }
            }
        })
        .await
        .expect("native Bonjour did not remove peer");
        drop(first);
    }

    #[test]
    fn txt_wire_schema_and_bounds() {
        let mut data = EndpointData::default();
        data.set_user_data(Some("mycel:Phone".parse().unwrap()));
        assert_eq!(parse_txt(&make_txt(&data)).unwrap().as_ref(), "mycel:Phone");
        assert!(parse_txt(&[250, b'x']).is_none());
        assert!(
            parse_txt(&[
                13, b'u', b's', b'e', b'r', b'-', b'd', b'a', b't', b'a', b'=', 255, 255, 255
            ])
            .is_none()
        );
    }
}
