//! Access to the guest's linear memory.
//!
//! The guest's memory is a wasm *shared* memory, because each guest thread runs
//! in its own wasmtime store and a store-owned memory would be private to one.
//! wasmtime's only accessor is `SharedMemory::data`, returning
//! `&[UnsafeCell<u8>]`: another thread may be writing any byte right now.
//!
//! # Why this crate exists
//!
//! Guest memory is shared mutable state by construction; no Rust type describes
//! it faithfully, and wrapping every access in an atomic would be both wrong
//! (the guest's own atomics decide ordering) and ruinous. A data race in the
//! guest stays one, observed as whatever the hardware does. So the
//! host reads these bytes as an ordinary slice, isolated here so the host itself
//! keeps `#![forbid(unsafe_code)]`.
//!
//! What the host must not assume: that a value read twice is unchanged (every
//! kernel path reads a guest word once and works from the copy); that a slice
//! stays valid across a guest instruction (the borrow lives one host call).

use wasmtime::SharedMemory;

/// The guest's linear memory, viewable as bytes.
#[derive(Clone)]
pub struct GuestMemory {
    inner: SharedMemory,
}

impl GuestMemory {
    pub fn new(inner: SharedMemory) -> GuestMemory {
        GuestMemory { inner }
    }

    /// Total size in bytes. Fixed for the life of the process: gex sizes the
    /// address space up front and never grows it.
    pub fn len(&self) -> usize {
        self.inner.data_size()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The whole address space as a mutable slice. See the module comment for
    /// why this is not `unsafe`. The lifetime is tied to the borrow of `self`,
    /// in practice one host call.
    #[allow(clippy::mut_from_ref)]
    pub fn bytes(&self) -> &mut [u8] {
        let cells = self.inner.data();
        // SAFETY: `cells` is the guest's address space, which the guest may be
        // writing to from another thread. That is the point: see above. The
        // pointer is valid and the length correct for as long as the
        // `SharedMemory` lives, and this borrow cannot outlive `self`.
        unsafe { std::slice::from_raw_parts_mut(cells.as_ptr() as *mut u8, cells.len()) }
    }

    pub fn shared(&self) -> &SharedMemory {
        &self.inner
    }
}

/// Give the host back what its allocator keeps of memory the program has
/// freed (glibc's `malloc_trim`; nothing on a host with another
/// allocator). Here with the other thing the host cannot say safely: glibc
/// keeps what a thread frees in that thread's own arena, and a guest
/// process's threads each free tens of megabytes when it ends
/// (`gex_native`'s `trim_heap`).
pub fn trim_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        // SAFETY: glibc's own call, which takes each arena's lock itself and
        // may be made from any thread at any time.
        unsafe {
            malloc_trim(0);
        }
    }
}

/// Let the host process open as many files as its hard limit allows (the
/// soft limit is 1024 on most Linux hosts). A run's guest processes share
/// the host's descriptors: every file a guest has open on the host's
/// filesystem is one, and so is every translation mapped from the cache,
/// thousands in a process that loads many libraries
/// (`gex_cache`'s `artifact`). Nothing when the host says no; the limit
/// stays what it was.
pub fn raise_open_files() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        #[repr(C)]
        struct Rlimit {
            cur: u64,
            max: u64,
        }
        extern "C" {
            fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32;
            fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
        }
        #[cfg(target_os = "linux")]
        const RLIMIT_NOFILE: i32 = 7;
        #[cfg(target_os = "macos")]
        const RLIMIT_NOFILE: i32 = 8;
        // macOS refuses a soft limit above OPEN_MAX whatever the hard one
        // says (setrlimit(2)).
        #[cfg(target_os = "linux")]
        const MOST: u64 = u64::MAX;
        #[cfg(target_os = "macos")]
        const MOST: u64 = 10240;
        let mut l = Rlimit { cur: 0, max: 0 };
        // SAFETY: both calls read or write the one struct given, which is
        // the layout of `struct rlimit` on these hosts (two 64-bit limits).
        unsafe {
            if getrlimit(RLIMIT_NOFILE, &mut l) != 0 {
                return;
            }
            let want = l.max.min(MOST);
            if want > l.cur {
                l.cur = want;
                setrlimit(RLIMIT_NOFILE, &l);
            }
        }
    }
}
