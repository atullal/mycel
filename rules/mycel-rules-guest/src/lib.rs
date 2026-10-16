//! Guest SDK for Mycel rules bundles.
//!
//! App authors write plain Rust and register their entry points with [`rules!`]:
//!
//! ```ignore
//! #![no_std]
//! use mycel_rules_guest::{RuleInput, Verdict};
//!
//! fn validate(input: RuleInput) -> Verdict {
//!     if input.author_role.can_write() { Verdict::Accept } else { Verdict::reject(1) }
//! }
//!
//! mycel_rules_guest::rules!(validate = validate);
//! // or, with an action reducer `fn(RuleInput, &[u8]) -> Result<Vec<u8>, u32>`:
//! // mycel_rules_guest::rules!(validate = validate, reduce = reduce);
//! ```
//!
//! Build the crate as a `cdylib` for `wasm32-unknown-unknown`. On that target this crate
//! provides:
//! - a bump allocator (never frees: the host uses a fresh instance per call),
//! - a panic handler that executes `unreachable` (the host sees a trap → `Reject(Trap)`).
//!
//! Rules must not use floating point (`f32`/`f64`): the host rejects any module containing
//! float types or instructions.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub use mycel_rules_abi as abi;
pub use mycel_rules_abi::{Reason, RoleTag, RuleInput, StreamKind, StreamTag, Verdict};
use mycel_rules_abi::{ReduceInput, ReduceOutput};

/// Register the rules entry points and emit the ABI exports (`mycel_abi_version`,
/// `mycel_alloc`, `mycel_validate`, and optionally `mycel_reduce`).
///
/// - `validate`: `fn(RuleInput) -> Verdict`
/// - `reduce`: `fn(RuleInput, &[u8]) -> Result<Vec<u8>, u32>`, where `input.payload` is the
///   action, the slice is the current state and `Ok` is the new state.
#[macro_export]
macro_rules! rules {
    (validate = $validate:path $(, reduce = $reduce:path)? $(,)?) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn mycel_abi_version() -> i32 {
            $crate::abi::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn mycel_alloc(len: i32) -> i32 {
            $crate::__private::alloc(len)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn mycel_validate(ptr: i32, len: i32) -> i64 {
            $crate::__private::validate(ptr, len, $validate)
        }

        $(
            #[unsafe(no_mangle)]
            pub extern "C" fn mycel_reduce(ptr: i32, len: i32) -> i64 {
                $crate::__private::reduce(ptr, len, $reduce)
            }
        )?
    };
}

/// Abort the call: the host records `Reject(Reason::Trap)`.
pub fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    panic!("mycel rules trap");
}

#[doc(hidden)]
pub mod __private {
    use super::*;
    use core::alloc::Layout;

    /// # Safety contract with the host
    /// The host passes the `(ptr, len)` it obtained from `mycel_alloc(len)` after writing
    /// `len` bytes there.
    fn input<'a>(ptr: i32, len: i32) -> &'a [u8] {
        if len < 0 {
            trap()
        }
        if len == 0 {
            return &[];
        }
        // SAFETY: see above; the buffer was allocated by `alloc` and is never freed.
        unsafe { core::slice::from_raw_parts(ptr as usize as *const u8, len as usize) }
    }

    pub fn alloc(len: i32) -> i32 {
        if len < 0 {
            trap()
        }
        if len == 0 {
            return 1; // dangling, never dereferenced
        }
        let layout = Layout::from_size_align(len as usize, 1).unwrap_or_else(|_| trap());
        // SAFETY: non-zero size.
        let p = unsafe { alloc::alloc::alloc(layout) };
        if p.is_null() {
            trap()
        }
        p as usize as i32
    }

    pub fn validate(ptr: i32, len: i32, f: fn(RuleInput) -> Verdict) -> i64 {
        let input: RuleInput = abi::decode_exact(input(ptr, len)).unwrap_or_else(|| trap());
        abi::encode_validate(f(input))
    }

    pub fn reduce(ptr: i32, len: i32, f: fn(RuleInput, &[u8]) -> Result<Vec<u8>, u32>) -> i64 {
        let ReduceInput { input: rule_input, state } = abi::decode_exact(input(ptr, len)).unwrap_or_else(|| trap());
        let out = match f(rule_input, &state) {
            Ok(state) => ReduceOutput::Accept { state },
            Err(code) => ReduceOutput::Reject { code },
        };
        let bytes = abi::encode(&out);
        let packed = abi::pack_ptr_len(bytes.as_ptr() as usize as u32, bytes.len() as u32);
        core::mem::forget(bytes); // the host reads it; the instance is then dropped
        packed
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_runtime {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::Cell;

    const PAGE: usize = 65536;

    /// Bump allocator over pages obtained with `memory.grow`. Never frees; instances are
    /// discarded after every call.
    struct Bump {
        next: Cell<usize>,
        end: Cell<usize>,
    }

    // SAFETY: wasm32-unknown-unknown guests are single-threaded (threads are not enabled).
    unsafe impl Sync for Bump {}

    impl Bump {
        fn reserve(&self, layout: Layout) -> *mut u8 {
            if self.end.get() == 0 {
                // First use: the heap starts after the module's initial memory.
                let start = core::arch::wasm32::memory_size(0) * PAGE;
                self.next.set(start);
                self.end.set(start);
            }
            let start = match self.next.get().checked_add(layout.align() - 1) {
                Some(v) => v & !(layout.align() - 1),
                None => return core::ptr::null_mut(),
            };
            let Some(new_next) = start.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if new_next > self.end.get() {
                let pages = (new_next - self.end.get()).div_ceil(PAGE);
                if core::arch::wasm32::memory_grow(0, pages) == usize::MAX {
                    return core::ptr::null_mut();
                }
                self.end.set(self.end.get() + pages * PAGE);
            }
            self.next.set(new_next);
            start as *mut u8
        }
    }

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            self.reserve(layout)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // Reclaim only the most recent allocation.
            if ptr as usize + layout.size() == self.next.get() {
                self.next.set(ptr as usize);
            }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // Grow/shrink in place when `ptr` is the most recent allocation.
            if ptr as usize + layout.size() == self.next.get() {
                let Some(new_next) = (ptr as usize).checked_add(new_size) else {
                    return core::ptr::null_mut();
                };
                if new_next <= self.end.get() {
                    self.next.set(new_next);
                    return ptr;
                }
                let pages = (new_next - self.end.get()).div_ceil(PAGE);
                if core::arch::wasm32::memory_grow(0, pages) == usize::MAX {
                    return core::ptr::null_mut();
                }
                self.end.set(self.end.get() + pages * PAGE);
                self.next.set(new_next);
                return ptr;
            }
            // SAFETY: caller upholds GlobalAlloc::realloc's contract.
            let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            let new = self.reserve(new_layout);
            if !new.is_null() {
                // SAFETY: both regions are valid for min(old, new) bytes and don't overlap.
                unsafe {
                    core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                }
            }
            new
        }
    }

    #[global_allocator]
    static ALLOC: Bump = Bump { next: Cell::new(0), end: Cell::new(0) };

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        core::arch::wasm32::unreachable()
    }
}
