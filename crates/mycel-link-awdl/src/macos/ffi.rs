//! Hand-written bindings to the parts of Network.framework (C API) and
//! libdispatch this link uses. Signatures follow the macOS SDK headers
//! (`Network/*.h`, `dispatch/*.h`); `objc2-network` is only a reserved name.
//!
//! Ownership: `*_create*` / `*_copy*` return a +1 reference (wrap with
//! [`Nw::owned`]); objects handed to our blocks are borrowed (wrap with
//! [`Nw::retained`] to keep them).
#![allow(non_camel_case_types, dead_code)]

use std::ffi::{CStr, c_char, c_void};
use std::ptr::NonNull;

use block2::Block;

pub type nw_object = *mut c_void;
pub type dispatch_object = *mut c_void;

// nw_listener_state_t
pub const LISTENER_WAITING: u32 = 1;
pub const LISTENER_READY: u32 = 2;
pub const LISTENER_FAILED: u32 = 3;
pub const LISTENER_CANCELLED: u32 = 4;
// nw_browser_state_t
pub const BROWSER_READY: u32 = 1;
pub const BROWSER_FAILED: u32 = 2;
pub const BROWSER_CANCELLED: u32 = 3;
pub const BROWSER_WAITING: u32 = 4;
// nw_connection_state_t
pub const CONN_WAITING: u32 = 1;
pub const CONN_PREPARING: u32 = 2;
pub const CONN_READY: u32 = 3;
pub const CONN_FAILED: u32 = 4;
pub const CONN_CANCELLED: u32 = 5;
// nw_browse_result_change_t
pub const CHANGE_ADDED: u64 = 0x02;
pub const CHANGE_REMOVED: u64 = 0x04;
pub const CHANGE_IFACE_ADDED: u64 = 0x08;
pub const CHANGE_IFACE_REMOVED: u64 = 0x10;
pub const CHANGE_TXT: u64 = 0x20;
// nw_endpoint_type_t
pub const ENDPOINT_BONJOUR: u32 = 3;
// nw_error_domain_t
pub const ERR_POSIX: u32 = 1;
pub const ERR_DNS: u32 = 2;
// nw_path_unsatisfied_reason_t
pub const UNSATISFIED_LOCAL_NETWORK_DENIED: u32 = 3;
// nw_txt_record_find_key_t
pub const TXT_NON_EMPTY: i32 = 4;

pub type StateBlock = Block<dyn Fn(u32, nw_object)>;
pub type ObjBlock = Block<dyn Fn(nw_object)>;
/// C `bool` (`_Bool`) in block signatures: objc2 has no `bool` encoding, and
/// a `u8` holding 0/1 is ABI-identical.
pub type CBool = u8;
pub type BrowseBlock = Block<dyn Fn(nw_object, nw_object, CBool)>;
pub type ReceiveBlock = Block<dyn Fn(dispatch_object, nw_object, CBool, nw_object)>;

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    pub fn nw_retain(obj: nw_object) -> nw_object;
    pub fn nw_release(obj: nw_object);

    pub static _nw_parameters_configure_protocol_disable: *const c_void;
    pub static _nw_parameters_configure_protocol_default_configuration: *const c_void;
    pub static _nw_content_context_default_message: nw_object;

    pub fn nw_parameters_create() -> nw_object;
    pub fn nw_parameters_create_secure_udp(
        configure_dtls: *const c_void,
        configure_udp: *const c_void,
    ) -> nw_object;
    pub fn nw_parameters_set_include_peer_to_peer(p: nw_object, include: bool);
    pub fn nw_parameters_prohibit_interface(p: nw_object, iface: nw_object);

    pub fn nw_listener_create(p: nw_object) -> nw_object;
    pub fn nw_listener_set_queue(l: nw_object, q: dispatch_object);
    pub fn nw_listener_set_state_changed_handler(l: nw_object, h: &StateBlock);
    pub fn nw_listener_set_new_connection_handler(l: nw_object, h: &ObjBlock);
    pub fn nw_listener_set_advertise_descriptor(l: nw_object, adv: nw_object);
    pub fn nw_listener_get_port(l: nw_object) -> u16;
    pub fn nw_listener_start(l: nw_object);
    pub fn nw_listener_cancel(l: nw_object);

    pub fn nw_advertise_descriptor_create_bonjour_service(
        name: *const c_char,
        ty: *const c_char,
        domain: *const c_char,
    ) -> nw_object;
    pub fn nw_advertise_descriptor_set_txt_record_object(adv: nw_object, txt: nw_object);

    pub fn nw_txt_record_create_dictionary() -> nw_object;
    pub fn nw_txt_record_set_key(
        txt: nw_object,
        key: *const c_char,
        value: *const u8,
        len: usize,
    ) -> bool;
    pub fn nw_txt_record_access_key(
        txt: nw_object,
        key: *const c_char,
        f: &Block<dyn Fn(*const c_char, i32, *const u8, usize) -> CBool + '_>,
    ) -> bool;

    pub fn nw_browse_descriptor_create_bonjour_service(
        ty: *const c_char,
        domain: *const c_char,
    ) -> nw_object;
    pub fn nw_browse_descriptor_set_include_txt_record(d: nw_object, include: bool);
    pub fn nw_browser_create(d: nw_object, p: nw_object) -> nw_object;
    pub fn nw_browser_set_queue(b: nw_object, q: dispatch_object);
    pub fn nw_browser_set_browse_results_changed_handler(b: nw_object, h: &BrowseBlock);
    pub fn nw_browser_set_state_changed_handler(b: nw_object, h: &StateBlock);
    pub fn nw_browser_start(b: nw_object);
    pub fn nw_browser_cancel(b: nw_object);

    pub fn nw_browse_result_get_changes(old: nw_object, new: nw_object) -> u64;
    pub fn nw_browse_result_copy_endpoint(r: nw_object) -> nw_object;
    pub fn nw_browse_result_copy_txt_record_object(r: nw_object) -> nw_object;
    pub fn nw_browse_result_enumerate_interfaces(
        r: nw_object,
        f: &Block<dyn Fn(nw_object) -> CBool + '_>,
    );

    pub fn nw_endpoint_get_type(e: nw_object) -> u32;
    pub fn nw_endpoint_get_bonjour_service_name(e: nw_object) -> *const c_char;
    pub fn nw_endpoint_copy_address_string(e: nw_object) -> *mut c_char;

    pub fn nw_connection_create(e: nw_object, p: nw_object) -> nw_object;
    pub fn nw_connection_copy_endpoint(c: nw_object) -> nw_object;
    pub fn nw_connection_set_queue(c: nw_object, q: dispatch_object);
    pub fn nw_connection_set_state_changed_handler(c: nw_object, h: &StateBlock);
    pub fn nw_connection_start(c: nw_object);
    pub fn nw_connection_cancel(c: nw_object);
    pub fn nw_connection_send(
        c: nw_object,
        data: dispatch_object,
        ctx: nw_object,
        complete: bool,
        done: &ObjBlock,
    );
    pub fn nw_connection_receive_message(c: nw_object, done: &ReceiveBlock);
    pub fn nw_connection_copy_current_path(c: nw_object) -> nw_object;
    pub fn nw_connection_get_maximum_datagram_size(c: nw_object) -> u32;

    pub fn nw_path_get_unsatisfied_reason(path: nw_object) -> u32;
    pub fn nw_path_enumerate_interfaces(
        path: nw_object,
        f: &Block<dyn Fn(nw_object) -> CBool + '_>,
    );
    pub fn nw_interface_get_name(iface: nw_object) -> *const c_char;

    pub fn nw_error_get_error_domain(e: nw_object) -> u32;
    pub fn nw_error_get_error_code(e: nw_object) -> i32;
}

// libdispatch lives in libSystem, linked by default.
unsafe extern "C" {
    pub fn dispatch_queue_create(label: *const c_char, attr: *mut c_void) -> dispatch_object;
    pub fn dispatch_release(obj: dispatch_object);
    pub fn dispatch_data_create(
        buf: *const c_void,
        size: usize,
        queue: dispatch_object,
        destructor: *const c_void,
    ) -> dispatch_object;
    pub fn dispatch_data_create_map(
        data: dispatch_object,
        buf: *mut *const c_void,
        size: *mut usize,
    ) -> dispatch_object;
}

/// A +1 reference to a Network.framework object. Network.framework objects
/// are reference counted atomically and safe to use from any thread.
pub struct Nw(NonNull<c_void>);

unsafe impl Send for Nw {}
unsafe impl Sync for Nw {}

impl Nw {
    /// Take ownership of a +1 reference (`create`/`copy` results).
    pub fn owned(p: nw_object) -> Option<Nw> {
        NonNull::new(p).map(Nw)
    }

    /// Retain a borrowed object (handed to a block).
    pub fn retained(p: nw_object) -> Option<Nw> {
        NonNull::new(p).map(|p| Nw(NonNull::new(unsafe { nw_retain(p.as_ptr()) }).unwrap_or(p)))
    }

    pub fn ptr(&self) -> nw_object {
        self.0.as_ptr()
    }
}

impl Clone for Nw {
    fn clone(&self) -> Nw {
        unsafe { nw_retain(self.ptr()) };
        Nw(self.0)
    }
}

impl Drop for Nw {
    fn drop(&mut self) {
        unsafe { nw_release(self.ptr()) }
    }
}

impl std::fmt::Debug for Nw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nw({:p})", self.0)
    }
}

/// A serial dispatch queue we own.
pub struct Queue(NonNull<c_void>);

unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    pub fn new(label: &CStr) -> Queue {
        let q = unsafe { dispatch_queue_create(label.as_ptr(), std::ptr::null_mut()) };
        Queue(NonNull::new(q).expect("dispatch_queue_create"))
    }

    pub fn ptr(&self) -> dispatch_object {
        self.0.as_ptr()
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe { dispatch_release(self.ptr()) }
    }
}

/// Borrowed C string → `String` (lossy), `None` for NULL.
pub fn cstr(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// Copy the bytes out of a `dispatch_data_t` (borrowed).
pub fn data_bytes(data: dispatch_object) -> Vec<u8> {
    if data.is_null() {
        return Vec::new();
    }
    let mut buf: *const c_void = std::ptr::null();
    let mut len = 0usize;
    let map = unsafe { dispatch_data_create_map(data, &mut buf, &mut len) };
    let out = if buf.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf as *const u8, len) }.to_vec()
    };
    if !map.is_null() {
        unsafe { dispatch_release(map) };
    }
    out
}

/// `dispatch_data_t` holding a copy of `bytes` (+1; release after use).
pub fn data_from(bytes: &[u8]) -> dispatch_object {
    // NULL destructor = DISPATCH_DATA_DESTRUCTOR_DEFAULT: the bytes are copied.
    unsafe {
        dispatch_data_create(
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    }
}

/// (domain, code) of an `nw_error_t`, or `None`.
pub fn error_of(e: nw_object) -> Option<(u32, i32)> {
    (!e.is_null()).then(|| unsafe { (nw_error_get_error_domain(e), nw_error_get_error_code(e)) })
}

/// Names (and retained objects) of the interfaces a browse result or path uses.
pub fn interfaces_of_browse_result(r: nw_object) -> Vec<(String, Nw)> {
    let out = std::cell::RefCell::new(Vec::new());
    let f = block2::StackBlock::new(|iface: nw_object| {
        if let (Some(name), Some(obj)) = (
            cstr(unsafe { nw_interface_get_name(iface) }),
            Nw::retained(iface),
        ) {
            out.borrow_mut().push((name, obj));
        }
        1
    });
    unsafe { nw_browse_result_enumerate_interfaces(r, &f) };
    out.into_inner()
}

pub fn interfaces_of_path(path: nw_object) -> Vec<String> {
    let out = std::cell::RefCell::new(Vec::new());
    let f = block2::StackBlock::new(|iface: nw_object| {
        if let Some(name) = cstr(unsafe { nw_interface_get_name(iface) }) {
            out.borrow_mut().push(name);
        }
        1
    });
    unsafe { nw_path_enumerate_interfaces(path, &f) };
    out.into_inner()
}

/// Value of `key` in a TXT record (borrowed), if present and non-empty.
pub fn txt_value(txt: nw_object, key: &CStr) -> Option<Vec<u8>> {
    let out = std::cell::RefCell::new(None);
    let f = block2::StackBlock::new(
        |_k: *const c_char, found: i32, value: *const u8, len: usize| {
            if found == TXT_NON_EMPTY && !value.is_null() {
                *out.borrow_mut() =
                    Some(unsafe { std::slice::from_raw_parts(value, len) }.to_vec());
            }
            1
        },
    );
    unsafe { nw_txt_record_access_key(txt, key.as_ptr(), &f) };
    out.into_inner()
}

/// The remote address of a connection, for logs.
pub fn remote_of(conn: nw_object) -> String {
    let Some(ep) = Nw::owned(unsafe { nw_connection_copy_endpoint(conn) }) else {
        return "?".into();
    };
    let s = unsafe { nw_endpoint_copy_address_string(ep.ptr()) };
    if s.is_null() {
        return cstr(unsafe { nw_endpoint_get_bonjour_service_name(ep.ptr()) })
            .unwrap_or_else(|| "?".into());
    }
    let out = cstr(s).unwrap_or_default();
    unsafe { libc::free(s as *mut c_void) };
    out
}
