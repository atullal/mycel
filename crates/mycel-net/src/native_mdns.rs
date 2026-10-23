//! Standard Bonjour LAN discovery on Apple platforms. DNS-SD performs multicast
//! in the system daemon; the app only uses the declared `_mycel._udp` service.
//! Advertisements are untrusted hints. QUIC still authenticates the endpoint key.
use iroh::{
    EndpointId,
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error, Item, MemoryLookup, UserData},
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
/// kDNSServiceFlagsNoAutoRename: on a name clash, fail rather than register
/// "<name> (2)", which no peer could parse as an endpoint id.
const NO_AUTO_RENAME: u32 = 0x8;
/// kDNSServiceErr_NameConflict.
const NAME_CONFLICT: i32 = -65548;
/// A peer that drops out of the browse results (a Wi-Fi roam, a responder
/// re-announcing) is kept this long before it expires, so a blip doesn't
/// flap Expired/Discovered and set off a burst of syncs.
const EXPIRY_GRACE: Duration = Duration::from_secs(3);
/// Our name (TXT) changing is published this long after the last change.
const TXT_DEBOUNCE: Duration = Duration::from_secs(2);
/// Losing every routable address withdraws the registration only after
/// this long, so a brief interface change isn't a goodbye.
const UNREGISTER_DELAY: Duration = Duration::from_secs(5);
/// The thread re-checks for shutdown at least this often.
const MAX_WAIT: Duration = Duration::from_secs(5);
const RR_SRV: u16 = 33;
const RR_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
/// kDNSServiceMaxDomainName.
const MAX_DOMAIN_NAME: usize = 1009;
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
        cb: unsafe extern "C" fn(Ref, u32, u32, i32, *const c_char, *const c_char, *const c_char, *mut c_void),
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceQueryRecord(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        cb: unsafe extern "C" fn(Ref, u32, u32, i32, *const c_char, u16, u16, u16, *const c_void, u32, *mut c_void),
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceConstructFullName(
        full: *mut c_char,
        service: *const c_char,
        ty: *const c_char,
        domain: *const c_char,
    ) -> i32;
    fn DNSServiceGetAddrInfo(
        r: *mut Ref,
        flags: u32,
        iface: u32,
        protocol: u32,
        host: *const c_char,
        cb: unsafe extern "C" fn(Ref, u32, u32, i32, *const c_char, *const libc::sockaddr, u32, *mut c_void),
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
        cb: Option<unsafe extern "C" fn(Ref, u32, i32, *const c_char, *const c_char, *const c_char, *mut c_void)>,
        ctx: *mut c_void,
    ) -> i32;
    fn DNSServiceUpdateRecord(
        r: Ref,
        record: *mut c_void,
        flags: u32,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
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
use crate::mdns_records::Target;
use crate::mdns_records::{parse_srv, parse_txt};
enum Event {
    Restart,
    /// Our registration failed (`true`: another responder holds our name).
    RegisterFailed(bool),
    Browse(ServiceKey, bool),
    Srv(ServiceKey, Target, bool),
    Txt(ServiceKey, Option<UserData>),
    Address(ServiceKey, Target, IpAddr, bool),
    /// A query for this peer (SRV, TXT, or one target's addresses) failed.
    Failed(ServiceKey, Option<Target>),
}
struct Context {
    overflow: Arc<AtomicBool>,
    tx: mpsc::SyncSender<Event>,
    key: Option<ServiceKey>,
    target: Option<Target>,
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
        Some(Self { raw, _context: context })
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
        (unsafe { string(name) }, unsafe { string(ty) }, unsafe { string(domain) })
    else {
        return;
    };
    if name.parse::<EndpointId>().is_err() {
        return;
    }
    let c = unsafe { &*(ctx as *const Context) };
    c.send(Event::Browse(ServiceKey { name, ty, domain, iface }, flags & ADD != 0));
}
unsafe extern "C" fn record(
    _r: Ref,
    flags: u32,
    _iface: u32,
    err: i32,
    _full: *const c_char,
    rrtype: u16,
    _rrclass: u16,
    len: u16,
    rdata: *const c_void,
    _ttl: u32,
    ctx: *mut c_void,
) {
    let c = unsafe { &*(ctx as *const Context) };
    let Some(key) = &c.key else {
        return;
    };
    if err != 0 {
        c.send(Event::Failed(key.clone(), None));
        return;
    }
    if len > 4096 || (len > 0 && rdata.is_null()) {
        return;
    }
    let rdata =
        if len == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(rdata.cast::<u8>(), len as usize) } };
    let add = flags & ADD != 0;
    match rrtype {
        RR_SRV => {
            if let Some(target) = parse_srv(rdata).filter(|(_, port)| *port > 0) {
                c.send(Event::Srv(key.clone(), target, add));
            }
        }
        RR_TXT => c.send(Event::Txt(key.clone(), if add { parse_txt(rdata) } else { None })),
        _ => {}
    }
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
    let (Some(key), Some(target)) = (&c.key, &c.target) else {
        return;
    };
    if err != 0 || addr.is_null() {
        c.send(Event::Failed(key.clone(), Some(target.clone())));
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
    if ip.is_unspecified() || ip.is_multicast() || matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local()) {
        return;
    }
    c.send(Event::Address(key.clone(), target.clone(), ip, flags & ADD != 0));
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
        let c = unsafe { &*(ctx as *const Context) };
        c.send(Event::RegisterFailed(err == NAME_CONFLICT));
    }
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
    /// Write end of the thread's wake pipe: a new publication or shutdown
    /// wakes it instead of it polling on a timer.
    wake: WakePipe,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.wake.wake();
    }
}

/// A non-blocking pipe: one byte written wakes the discovery thread's poll.
#[derive(Debug)]
struct WakePipe {
    read: std::os::fd::OwnedFd,
    write: std::os::fd::OwnedFd,
}
impl WakePipe {
    fn new() -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: pipe() just returned these two descriptors; we own them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [&read, &write] {
            let raw = fd.as_raw_fd();
            unsafe {
                libc::fcntl(raw, libc::F_SETFL, libc::fcntl(raw, libc::F_GETFL) | libc::O_NONBLOCK);
                libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        Ok(Self { read, write })
    }
    fn wake(&self) {
        use std::os::fd::AsRawFd;
        // A full pipe already has a wake-up pending.
        unsafe { libc::write(self.write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }
    fn drain(&self) {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; 64];
        while unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMdns {
    shared: Arc<Shared>,
    memory: MemoryLookup,
}
impl AddressLookup for NativeMdns {
    fn publish(&self, data: &EndpointData) {
        let mut published = self.shared.published.lock();
        if published.as_ref() != Some(data) {
            *published = Some(data.clone());
            self.shared.wake.wake();
        }
    }
    fn resolve(&self, id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.memory.resolve(id)
    }
}
/// A browsed instance and what we learned about it: its SRV records (each
/// a host and port) with their addresses, and its name from the TXT record.
struct Peer {
    srv: Option<Operation>,
    txt: Option<Operation>,
    user: Option<UserData>,
    targets: BTreeMap<Target, Addresses>,
    retry_at: Instant,
}
struct Addresses {
    op: Option<Operation>,
    ips: BTreeSet<IpAddr>,
    retry_at: Instant,
}
impl Peer {
    fn new() -> Self {
        Peer { srv: None, txt: None, user: None, targets: BTreeMap::new(), retry_at: Instant::now() }
    }
    fn ops(&self) -> impl Iterator<Item = &Operation> {
        self.srv.iter().chain(self.txt.iter()).chain(self.targets.values().flat_map(|a| a.op.iter()))
    }
}
fn full_name(key: &ServiceKey) -> Option<CString> {
    let (n, t, d) = (
        CString::new(key.name.as_str()).ok()?,
        CString::new(key.ty.as_str()).ok()?,
        CString::new(key.domain.as_str()).ok()?,
    );
    let mut buf = vec![0 as c_char; MAX_DOMAIN_NAME];
    if unsafe { DNSServiceConstructFullName(buf.as_mut_ptr(), n.as_ptr(), t.as_ptr(), d.as_ptr()) } != 0 {
        return None;
    }
    Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned())
}

/// Our own registration with the system's responder.
struct Registration {
    op: Operation,
    /// The TXT record as registered or last updated.
    txt: Vec<u8>,
}

/// What we should be advertising: our name (as TXT) if we have a socket
/// and a routable address to be reached at. Bonjour advertises this host's
/// own addresses, so the addresses themselves aren't part of it: an
/// address change alone never re-registers.
fn desired_txt(publication: Option<&EndpointData>, bound_port: u16) -> Option<Vec<u8>> {
    let data = publication?;
    (bound_port != 0 && data.ip_addrs().any(|a| !a.ip().is_loopback())).then(|| make_txt(data))
}

/// Keeps endpoints that just left `current` for [`EXPIRY_GRACE`], so they
/// don't expire on a blip. Returns when the earliest held one expires.
fn hold_departures(
    known: &BTreeMap<EndpointId, EndpointData>,
    current: &mut BTreeMap<EndpointId, EndpointData>,
    missing: &mut BTreeMap<EndpointId, Instant>,
    now: Instant,
) -> Option<Instant> {
    missing.retain(|id, _| known.contains_key(id) && !current.contains_key(id));
    let mut next = None::<Instant>;
    for (id, data) in known {
        if current.contains_key(id) {
            continue;
        }
        let since = *missing.entry(*id).or_insert(now);
        let until = since + EXPIRY_GRACE;
        if now < until {
            current.insert(*id, data.clone());
            next = Some(next.map_or(until, |n| n.min(until)));
        }
    }
    next
}

impl NativeMdns {
    pub(crate) fn start(
        me: EndpointId,
        bound_port: u16,
    ) -> std::io::Result<(Self, tokio::sync::mpsc::Receiver<DiscoveryEvent>)> {
        let wake = WakePipe::new()?;
        let wake_fd = {
            use std::os::fd::AsRawFd;
            wake.read.as_raw_fd()
        };
        let shared = Arc::new(Shared { published: Mutex::new(None), stopped: AtomicBool::new(false), wake });
        let memory = MemoryLookup::with_provenance("native_bonjour");
        let (out, rx) = tokio::sync::mpsc::channel(1024);
        let weak = Arc::downgrade(&shared);
        let lookup = memory.clone();
        std::thread::Builder::new().name("mycel.bonjour".into()).spawn(move || {
            let (tx, events) = mpsc::sync_channel(1024);
            let context = |key: Option<ServiceKey>, target: Option<Target>, overflow: &Arc<AtomicBool>| Context {
                overflow: overflow.clone(),
                tx: tx.clone(),
                key,
                target,
            };
            let name = CString::new(instance_name(me)).expect("base32 has no NUL");
            let mut browser: Option<Operation> = None;
            let mut browse_at = Instant::now();
            let mut registration: Option<Registration> = None;
            let mut register_at = Instant::now();
            let mut register_backoff = Duration::from_secs(5);
            let mut txt_due: Option<Instant> = None;
            let mut unregister_due: Option<Instant> = None;
            let mut peers: BTreeMap<ServiceKey, Peer> = BTreeMap::new();
            let mut known: BTreeMap<EndpointId, EndpointData> = BTreeMap::new();
            let mut missing: BTreeMap<EndpointId, Instant> = BTreeMap::new();
            let overflow = Arc::new(AtomicBool::new(false));
            loop {
                let Some(s) = weak.upgrade() else {
                    break;
                };
                if s.stopped.load(Ordering::Acquire) || out.is_closed() {
                    break;
                }
                s.wake.drain();
                let desired = desired_txt(s.published.lock().as_ref(), bound_port);
                drop(s);
                let now = Instant::now();

                if browser.is_none() && now >= browse_at {
                    browser = Operation::new(context(None, None, &overflow), |r, c| unsafe {
                        DNSServiceBrowse(r, 0, 0, SERVICE.as_ptr(), c"local.".as_ptr(), browse, c)
                    });
                    browse_at = now + Duration::from_secs(5);
                }

                // Our registration follows `desired`: registered once,
                // TXT updated in place (debounced), withdrawn only after
                // the addresses have been gone a while.
                match (&desired, &mut registration) {
                    (Some(txt), None) if browser.is_some() && now >= register_at => {
                        let flags = NO_AUTO_RENAME;
                        registration = Operation::new(context(None, None, &overflow), |r, c| unsafe {
                            DNSServiceRegister(
                                r,
                                flags,
                                0,
                                name.as_ptr(),
                                SERVICE.as_ptr(),
                                c"local.".as_ptr(),
                                std::ptr::null(),
                                bound_port.to_be(),
                                txt.len() as u16,
                                txt.as_ptr().cast(),
                                Some(registered),
                                c,
                            )
                        })
                        .map(|op| Registration { op, txt: txt.clone() });
                        if registration.is_none() {
                            register_at = now + register_backoff;
                        }
                        txt_due = None;
                        unregister_due = None;
                    }
                    (Some(txt), Some(reg)) => {
                        unregister_due = None;
                        if *txt == reg.txt {
                            txt_due = None;
                        } else if txt_due.is_some_and(|due| now >= due) {
                            // An empty TXT record is a single empty string.
                            let rdata: &[u8] = if txt.is_empty() { &[0] } else { txt };
                            let err = unsafe {
                                DNSServiceUpdateRecord(
                                    reg.op.raw,
                                    std::ptr::null_mut(),
                                    0,
                                    rdata.len() as u16,
                                    rdata.as_ptr().cast(),
                                    0,
                                )
                            };
                            if err == 0 {
                                reg.txt = txt.clone();
                            } else {
                                eprintln!("[mycel] native Bonjour TXT update failed: {err}");
                                registration = None;
                                register_at = now;
                            }
                            txt_due = None;
                        } else if txt_due.is_none() {
                            txt_due = Some(now + TXT_DEBOUNCE);
                        }
                    }
                    (None, Some(_)) => match unregister_due {
                        Some(due) if now >= due => {
                            registration = None;
                            unregister_due = None;
                        }
                        Some(_) => {}
                        None => unregister_due = Some(now + UNREGISTER_DELAY),
                    },
                    _ => {}
                }

                // Each peer: its SRV and TXT records (kept open, so
                // changes arrive), and each SRV target's addresses.
                for (key, p) in &mut peers {
                    if (p.srv.is_none() || p.txt.is_none()) && now >= p.retry_at {
                        if let Some(full) = full_name(key) {
                            for (slot, rrtype) in [(&mut p.srv, RR_SRV), (&mut p.txt, RR_TXT)] {
                                if slot.is_none() {
                                    *slot =
                                        Operation::new(context(Some(key.clone()), None, &overflow), |r, c| unsafe {
                                            DNSServiceQueryRecord(
                                                r,
                                                0,
                                                key.iface,
                                                full.as_ptr(),
                                                rrtype,
                                                CLASS_IN,
                                                record,
                                                c,
                                            )
                                        });
                                }
                            }
                        }
                        p.retry_at = now + Duration::from_secs(5);
                    }
                    for (target, a) in &mut p.targets {
                        if a.op.is_none() && now >= a.retry_at {
                            if let Ok(host) = CString::new(target.0.as_str()) {
                                a.op = Operation::new(
                                    context(Some(key.clone()), Some(target.clone()), &overflow),
                                    |r, c| unsafe {
                                        DNSServiceGetAddrInfo(r, 0, key.iface, 3, host.as_ptr(), address, c)
                                    },
                                );
                            }
                            a.retry_at = now + Duration::from_secs(5);
                        }
                    }
                }

                // Block until the system's responder has something for
                // us, we're woken (publication, shutdown), or the next
                // timer is due.
                let mut deadlines: Vec<Instant> = vec![now + MAX_WAIT];
                if browser.is_none() {
                    deadlines.push(browse_at);
                }
                if desired.is_some() && registration.is_none() {
                    deadlines.push(register_at);
                }
                deadlines.extend(txt_due);
                deadlines.extend(unregister_due);
                for p in peers.values() {
                    if p.srv.is_none() || p.txt.is_none() {
                        deadlines.push(p.retry_at);
                    }
                    deadlines.extend(p.targets.values().filter(|a| a.op.is_none()).map(|a| a.retry_at));
                }
                deadlines.extend(missing.values().map(|since| *since + EXPIRY_GRACE));
                let wait = deadlines.into_iter().min().unwrap_or(now).saturating_duration_since(now);

                let mut ready = Vec::new();
                if let Some(b) = &browser {
                    ready.push(b.raw);
                }
                ready.extend(registration.iter().map(|r| r.op.raw));
                ready.extend(peers.values().flat_map(|p| p.ops().map(|o| o.raw)));
                let mut fds: Vec<_> = std::iter::once(wake_fd)
                    .chain(ready.iter().map(|r| unsafe { DNSServiceRefSockFD(*r) }))
                    .map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
                    .collect();
                let ms = wait.as_millis().clamp(1, MAX_WAIT.as_millis()) as libc::c_int;
                unsafe {
                    libc::poll(fds.as_mut_ptr(), fds.len() as _, ms);
                }
                let mut failed = BTreeSet::new();
                for (r, fd) in ready.iter().zip(&fds[1..]) {
                    if fd.revents != 0
                        && (fd.revents & libc::POLLIN == 0 || unsafe { DNSServiceProcessResult(*r) } != 0)
                    {
                        failed.insert(*r as usize);
                    }
                }
                if browser.as_ref().is_some_and(|b| failed.contains(&(b.raw as usize))) {
                    browser = None;
                    peers.clear();
                }
                if registration.as_ref().is_some_and(|r| failed.contains(&(r.op.raw as usize))) {
                    registration = None;
                    register_at = Instant::now() + register_backoff;
                }
                let gone = |o: &Option<Operation>| o.as_ref().is_some_and(|o| failed.contains(&(o.raw as usize)));
                for p in peers.values_mut() {
                    if gone(&p.srv) || gone(&p.txt) {
                        p.srv = None;
                        p.txt = None;
                        p.targets.clear();
                    }
                    for a in p.targets.values_mut() {
                        if gone(&a.op) {
                            a.op = None;
                            a.ips.clear();
                        }
                    }
                }
                if overflow.swap(false, Ordering::AcqRel) {
                    // A dropped callback may have been a removal. Rebuild a
                    // complete browser snapshot rather than retain stale peers.
                    browser = None;
                    peers.clear();
                    browse_at = Instant::now();
                    while events.try_recv().is_ok() {}
                }
                for ev in events.try_iter().take(1024) {
                    match ev {
                        Event::Restart => {
                            // The browser failed: browse again shortly.
                            // Our registration is independent of it.
                            browser = None;
                            peers.clear();
                            browse_at = Instant::now() + Duration::from_secs(5);
                        }
                        Event::RegisterFailed(conflict) => {
                            registration = None;
                            if conflict {
                                // Another responder already answers for
                                // our endpoint id (the same identity on a
                                // second device, or a stale record). Keep
                                // browsing; try our name again later
                                // rather than advertise a renamed one.
                                eprintln!(
                                    "[mycel] native Bonjour: our name is taken on this network; retrying in {} s",
                                    register_backoff.as_secs()
                                );
                            } else {
                                eprintln!("[mycel] native Bonjour registration failed; retrying");
                            }
                            register_at = Instant::now() + register_backoff;
                            register_backoff = (register_backoff * 2).min(Duration::from_secs(300));
                        }
                        Event::Browse(key, true)
                            if key.name.parse::<EndpointId>().ok() != Some(me) && peers.len() < MAX_SERVICES =>
                        {
                            peers.entry(key).or_insert_with(Peer::new);
                        }
                        Event::Browse(key, false) => {
                            peers.remove(&key);
                        }
                        Event::Srv(key, target, add) => {
                            if let Some(p) = peers.get_mut(&key) {
                                if !add {
                                    p.targets.remove(&target);
                                } else if p.targets.len() < 8 {
                                    p.targets.entry(target).or_insert_with(|| Addresses {
                                        op: None,
                                        ips: BTreeSet::new(),
                                        retry_at: Instant::now(),
                                    });
                                }
                            }
                        }
                        Event::Txt(key, user) => {
                            if let Some(p) = peers.get_mut(&key) {
                                p.user = user;
                            }
                        }
                        Event::Address(key, target, ip, add) => {
                            if let Some(a) = peers.get_mut(&key).and_then(|p| p.targets.get_mut(&target)) {
                                if add && a.ips.len() < 16 {
                                    a.ips.insert(ip);
                                } else if !add {
                                    a.ips.remove(&ip);
                                }
                            }
                        }
                        Event::Failed(key, None) => {
                            if let Some(p) = peers.get_mut(&key) {
                                p.srv = None;
                                p.txt = None;
                                p.targets.clear();
                                p.retry_at = Instant::now() + Duration::from_secs(5);
                            }
                        }
                        Event::Failed(key, Some(target)) => {
                            if let Some(a) = peers.get_mut(&key).and_then(|p| p.targets.get_mut(&target)) {
                                a.op = None;
                                a.ips.clear();
                                a.retry_at = Instant::now() + Duration::from_secs(5);
                            }
                        }
                        _ => {}
                    }
                }
                if registration.is_some() {
                    register_backoff = Duration::from_secs(5);
                }
                let mut current: BTreeMap<EndpointId, EndpointData> = BTreeMap::new();
                for (key, p) in &peers {
                    let addrs: Vec<SocketAddr> = p
                        .targets
                        .iter()
                        .flat_map(|((_, port), a)| a.ips.iter().map(move |ip| SocketAddr::new(*ip, *port)))
                        .collect();
                    if !addrs.is_empty()
                        && let Ok(id) = key.name.parse()
                    {
                        let data = current.entry(id).or_default();
                        data.add_ip_addrs(addrs);
                        data.set_user_data(p.user.clone());
                    }
                }
                hold_departures(&known, &mut current, &mut missing, Instant::now());
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
    let removed: Vec<_> = known.keys().filter(|id| !current.contains_key(*id)).copied().collect();
    for id in removed {
        if out.try_send(DiscoveryEvent::Expired { endpoint_id: id }).is_ok() {
            lookup.remove_endpoint_info(id);
            known.remove(&id);
        }
    }
    for (id, data) in current {
        if known.get(&id) == Some(&data) {
            continue;
        }
        let info = EndpointInfo::from_parts(id, data.clone());
        if out.try_send(DiscoveryEvent::Discovered { endpoint_info: info.clone(), last_updated: None }).is_ok() {
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
        let context = Context { tx, overflow: flag.clone(), key: None, target: None };
        context.send(Event::Restart);
        assert!(!flag.load(Ordering::Acquire));
        context.send(Event::Restart);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn undelivered_transient_peer_cannot_leave_a_cached_address() {
        let peer = iroh::SecretKey::generate().public();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(DiscoveryEvent::Expired { endpoint_id: peer }).unwrap();
        let memory = MemoryLookup::new();
        let mut known = BTreeMap::new();
        deliver_changes(&tx, &memory, &mut known, BTreeMap::from([(peer, EndpointData::default())]));
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
            key: Some(ServiceKey { name: "peer".into(), ty: "_iroh._udp".into(), domain: "local.".into(), iface: 1 }),
            target: Some(("peer-1.local.".into(), 1)),
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
        assert!(flag.load(Ordering::Acquire), "lost address removal must trigger resync");
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
        let mut data = EndpointData::from(BTreeSet::from(["192.0.2.1:35491".parse::<SocketAddr>().unwrap()]));
        // A published endpoint can also carry a different external NAT port.
        // It must never create a second Bonjour instance or advertise that port.
        data.add_ip_addrs(vec!["203.0.113.2:54321".parse().unwrap()]);
        data.set_user_data(Some("mycel:Native LAN test".parse().unwrap()));
        // (Only native: a device runs one of native Bonjour and iroh's mDNS,
        // never both under the same name; their interop is the next test.)
        second.publish(&data);
        let info = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = rx.recv().await
                    && endpoint_info.endpoint_id == b
                {
                    break endpoint_info;
                }
            }
        })
        .await
        .expect("native Bonjour did not find peer");
        assert!(info.data.ip_addrs().all(|a| a.port() == 35491));
        assert_eq!(info.data.user_data().unwrap().as_ref(), "mycel:Native LAN test");
        data.set_user_data(Some("mycel:Updated LAN test".parse().unwrap()));
        second.publish(&data);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = rx.recv().await
                    && endpoint_info.endpoint_id == b
                    && endpoint_info.data.user_data().is_some_and(|u| u.as_ref() == "mycel:Updated LAN test")
                {
                    break;
                }
            }
        })
        .await
        .expect("native Bonjour did not update peer name");
        drop(second);
        drop(second_rx);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(DiscoveryEvent::Expired { endpoint_id }) = rx.recv().await
                    && endpoint_id == b
                {
                    break;
                }
            }
        })
        .await
        .expect("native Bonjour did not remove peer");
        drop(first);
    }

    #[test]
    fn a_departing_peer_is_held_through_a_blip_then_expires() {
        let peer = iroh::SecretKey::generate().public();
        let t0 = Instant::now();
        let known = BTreeMap::from([(peer, EndpointData::default())]);
        let mut missing = BTreeMap::new();
        // gone from the browse results: still reported for the grace period
        let mut current = BTreeMap::new();
        let next = hold_departures(&known, &mut current, &mut missing, t0);
        assert!(current.contains_key(&peer), "held, so no Expired yet");
        assert_eq!(next, Some(t0 + EXPIRY_GRACE));
        // back within the grace period: never expired, and the timer resets
        let mut current = BTreeMap::from([(peer, EndpointData::default())]);
        hold_departures(&known, &mut current, &mut missing, t0 + Duration::from_secs(1));
        assert!(missing.is_empty());
        // gone for longer than the grace period: it expires
        let mut current = BTreeMap::new();
        hold_departures(&known, &mut current, &mut missing, t0 + Duration::from_secs(2));
        let mut current = BTreeMap::new();
        let next = hold_departures(&known, &mut current, &mut missing, t0 + Duration::from_secs(2) + EXPIRY_GRACE);
        assert!(current.is_empty() && next.is_none());
    }

    #[test]
    fn registration_follows_name_and_reachability_not_addresses() {
        let mut data = EndpointData::from(BTreeSet::from(["192.0.2.1:1".parse::<SocketAddr>().unwrap()]));
        data.set_user_data(Some("mycel:Phone".parse().unwrap()));
        let txt = desired_txt(Some(&data), 4000).unwrap();
        // a new address (a Wi-Fi roam) is the same registration
        data.add_ip_addrs(vec!["198.51.100.7:9".parse().unwrap()]);
        assert_eq!(desired_txt(Some(&data), 4000), Some(txt.clone()));
        // a new name is a TXT update
        data.set_user_data(Some("mycel:Renamed".parse().unwrap()));
        assert_ne!(desired_txt(Some(&data), 4000), Some(txt));
        // nothing to advertise without a socket or a routable address
        assert!(desired_txt(Some(&data), 0).is_none());
        let lo = EndpointData::from(BTreeSet::from(["127.0.0.1:1".parse::<SocketAddr>().unwrap()]));
        assert!(desired_txt(Some(&lo), 4000).is_none());
        assert!(desired_txt(None, 4000).is_none());
    }

    /// The system's Bonjour responder (what an iPhone uses) and iroh's mDNS
    /// (Macs, Linux, Windows, Android; vendor/swarm-discovery) find each
    /// other both ways, names included. Needs a LAN and Bonjour, like the test
    /// above; run on a Mac with `--ignored`.
    #[tokio::test]
    #[ignore = "requires an available LAN and macOS Local Network permission"]
    async fn native_bonjour_and_iroh_mdns_find_each_other() {
        use n0_future::StreamExt;
        let native_id = iroh::SecretKey::generate().public();
        let iroh_id = iroh::SecretKey::generate().public();
        let (native, mut native_rx) = NativeMdns::start(native_id, 35492).unwrap();
        let mut data = EndpointData::from(BTreeSet::from(["192.0.2.1:35492".parse::<SocketAddr>().unwrap()]));
        data.set_user_data(Some("mycel:Native phone".parse().unwrap()));
        native.publish(&data);
        let legacy =
            iroh_mdns_address_lookup::MdnsAddressLookup::builder().service_name("mycel").build(iroh_id).unwrap();
        let mut legacy_data = EndpointData::from(BTreeSet::from(["192.0.2.2:35493".parse::<SocketAddr>().unwrap()]));
        // like a real laptop: its LAN socket and a NAT mapping on another port
        legacy_data.add_ip_addrs(vec!["203.0.113.9:54321".parse().unwrap()]);
        legacy_data.set_user_data(Some("mycel:Iroh laptop".parse().unwrap()));
        legacy.publish(&legacy_data);
        let mut legacy_rx = legacy.subscribe().await;
        let seen = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = native_rx.recv().await
                    && endpoint_info.endpoint_id == iroh_id
                    && endpoint_info.data.user_data().is_some_and(|u| u.as_ref() == "mycel:Iroh laptop")
                {
                    break endpoint_info;
                }
            }
        })
        .await
        .expect("native Bonjour did not find the iroh mDNS peer");
        eprintln!("native sees the iroh peer at {:?}", seen.data.ip_addrs().collect::<Vec<_>>());
        assert!(seen.data.ip_addrs().any(|a| *a == "192.0.2.2:35493".parse::<SocketAddr>().unwrap()));
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = legacy_rx.next().await
                    && endpoint_info.endpoint_id == native_id
                    && endpoint_info.data.user_data().is_some_and(|u| u.as_ref() == "mycel:Native phone")
                {
                    break;
                }
            }
        })
        .await
        .expect("iroh mDNS did not find the native Bonjour peer");
        drop(native);
    }

    #[test]
    fn srv_records_parse_into_host_and_port() {
        // priority 0, weight 0, port 35493, target "abc-35493.local."
        let mut rdata = vec![0, 0, 0, 0, 0x8a, 0xa5];
        for label in ["abc-35493", "local"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        assert_eq!(parse_srv(&rdata), Some(("abc-35493.local.".into(), 35493)));
        // a dot inside a label is escaped, not a separator
        assert_eq!(crate::mdns_records::wire_name(&[3, b'a', b'.', b'b', 0]).as_deref(), Some("a\\.b."));
        // truncated, oversized or binary labels are refused
        assert!(parse_srv(&rdata[..8]).is_none());
        assert!(crate::mdns_records::wire_name(&[64, b'a', 0]).is_none());
        assert!(crate::mdns_records::wire_name(&[1, 0x01, 0]).is_none());
        assert!(parse_srv(&[0, 0, 0, 0]).is_none());
    }

    #[test]
    fn txt_wire_schema_and_bounds() {
        let mut data = EndpointData::default();
        data.set_user_data(Some("mycel:Phone".parse().unwrap()));
        assert_eq!(parse_txt(&make_txt(&data)).unwrap().as_ref(), "mycel:Phone");
        assert!(parse_txt(&[250, b'x']).is_none());
        assert!(parse_txt(&[13, b'u', b's', b'e', b'r', b'-', b'd', b'a', b't', b'a', b'=', 255, 255, 255]).is_none());
    }
}
