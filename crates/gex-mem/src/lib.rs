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

    /// How many bytes of `[start, end)` the host has in memory now (its
    /// `mincore`): what a guest's resident size is made of, since a page
    /// the guest never touched is one the host never gave it. Counted by
    /// the host's pages, each clipped to the range. `None` where the host
    /// cannot say.
    pub fn resident(&self, start: u64, end: u64) -> Option<u64> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::ffi::c_void;
            extern "C" {
                fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> i32;
                fn sysconf(name: i32) -> i64;
            }
            #[cfg(target_os = "linux")]
            const SC_PAGESIZE: i32 = 30;
            #[cfg(target_os = "macos")]
            const SC_PAGESIZE: i32 = 29;
            // SAFETY: a read of a constant of the system's.
            let page = unsafe { sysconf(SC_PAGESIZE) };
            if page <= 0 || !(page as u64).is_power_of_two() {
                return None;
            }
            let page = page as u64;
            let cells = self.inner.data();
            let base = cells.as_ptr() as u64;
            let len = cells.len() as u64;
            let (start, end) = (start.min(len), end.min(len));
            if start >= end {
                return Some(0);
            }
            // At most this many host pages a call, for a bounded vector.
            const CHUNK: u64 = 1 << 16;
            let (lo, hi) = ((base + start) & !(page - 1), base + end);
            let mut vec = vec![0u8; CHUNK.min((hi - lo).div_ceil(page)) as usize];
            let mut n = 0;
            let mut at = lo;
            while at < hi {
                let to = hi.min(at + CHUNK * page);
                let pages = (to - at).div_ceil(page) as usize;
                // SAFETY: `[at, to)` is within the memory's own mapping (its
                // start rounded down to a host page, which holds the
                // mapping's page-aligned base), `mincore` only reads the
                // host's page tables, and `vec` has a byte for each page.
                let r = unsafe { mincore(at as *mut c_void, (to - at) as usize, vec.as_mut_ptr()) };
                if r != 0 {
                    return None;
                }
                for (i, v) in vec[..pages].iter().enumerate() {
                    if v & 1 != 0 {
                        let a = (at + i as u64 * page).max(base + start);
                        let b = (at + (i as u64 + 1) * page).min(hi);
                        n += b - a;
                    }
                }
                at = to;
            }
            Some(n)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (start, end);
            None
        }
    }

    pub fn shared(&self) -> &SharedMemory {
        &self.inner
    }

    /// The host's page size where [`Self::alias`] can make two ranges of
    /// this memory one, else `None`.
    pub fn alias_page() -> Option<u64> {
        #[cfg(target_os = "macos")]
        {
            extern "C" {
                fn sysconf(name: i32) -> i64;
            }
            const SC_PAGESIZE: i32 = 29;
            // SAFETY: a read of a constant of the system's.
            let page = unsafe { sysconf(SC_PAGESIZE) };
            (page > 0 && (page as u64).is_power_of_two()).then_some(page as u64)
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Make `[dst, dst + len)` the same memory as `[src, src + len)`: the
    /// host's pages of `src` mapped at `dst` too, so a write through either
    /// is in both at once (`mach_vm_remap`, sharing, not copying). What
    /// `dst` held is gone. Both host-page aligned, within the memory, and
    /// apart. False where it cannot be done, and nothing changed.
    ///
    /// How two `MAP_SHARED` mappings of one file in one process are one
    /// memory, as a page cache makes them on Linux (ART's JIT keeps its
    /// cache at two addresses, one writable and one not).
    pub fn alias(&self, dst: u64, src: u64, len: u64) -> bool {
        let Some(page) = Self::alias_page() else { return false };
        let size = self.len() as u64;
        let fits = |a: u64| a.is_multiple_of(page) && a.checked_add(len).is_some_and(|e| e <= size);
        if len == 0 || !len.is_multiple_of(page) || !fits(dst) || !fits(src) || (dst < src + len && src < dst + len) {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            #[allow(non_upper_case_globals)]
            extern "C" {
                static mach_task_self_: u32;
                fn mach_vm_remap(
                    target: u32,
                    address: *mut u64,
                    size: u64,
                    mask: u64,
                    flags: i32,
                    src_task: u32,
                    src_address: u64,
                    copy: i32,
                    cur: *mut i32,
                    max: *mut i32,
                    inherit: u32,
                ) -> i32;
            }
            const VM_FLAGS_FIXED: i32 = 0;
            const VM_FLAGS_OVERWRITE: i32 = 0x4000;
            const VM_INHERIT_COPY: u32 = 1;
            const RW: i32 = 3;
            let base = self.inner.data().as_ptr() as u64;
            let mut at = base + dst;
            let (mut cur, mut max) = (0i32, 0i32);
            // SAFETY: the task's own port, a constant of the process.
            let task = unsafe { mach_task_self_ };
            // SAFETY: both ranges are inside this memory's own mapping
            // (checked above) and apart; the remap replaces `dst`'s pages
            // with `src`'s in place, read and write as before (`cur`
            // checked below), and moves nothing else. The guest may be
            // using `dst` meanwhile, as it may any memory it maps over.
            let kr = unsafe { mach_vm_remap(task, &mut at, len, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, base + src, 0, &mut cur, &mut max, VM_INHERIT_COPY) };
            if kr != 0 || at != base + dst || cur & RW != RW {
                eprintln!("gex: mach_vm_remap of {len:#x} bytes from {src:#x} to {dst:#x}: {kr} at {:#x}, protection {cur}", at.wrapping_sub(base));
                return false;
            }
            true
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Make `[start, start + len)` (host-page aligned) memory of its own
    /// again, keeping what it holds: a range [`Self::alias`] made one with
    /// another is copied out, mapped anew, and copied back. What another
    /// thread writes into the range meanwhile may be lost; the kernel does
    /// this to memory being unmapped or mapped over, or to the host page
    /// around such memory.
    pub fn unalias(&self, start: u64, len: u64) -> bool {
        let Some(page) = Self::alias_page() else { return false };
        if len == 0 || !start.is_multiple_of(page) || !len.is_multiple_of(page) || start.checked_add(len).is_none_or(|e| e > self.len() as u64) {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            use std::ffi::c_void;
            extern "C" {
                fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
            }
            const PROT_RW: i32 = 1 | 2;
            const MAP_PRIVATE: i32 = 2;
            const MAP_FIXED: i32 = 0x10;
            const MAP_ANON: i32 = 0x1000;
            let (s, e) = (start as usize, (start + len) as usize);
            let keep = self.bytes()[s..e].to_vec();
            let at = self.bytes()[s..].as_mut_ptr() as *mut c_void;
            // SAFETY: `[start, start + len)` is inside this memory's own
            // mapping (checked above); fresh private pages replace it, read
            // and write as the memory's accessible part is, and the bytes
            // are put back below.
            let r = unsafe { mmap(at, len as usize, PROT_RW, MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0) };
            if r != at {
                eprintln!("gex: mapping {len:#x} bytes at {start:#x} anew failed");
                return false;
            }
            let bytes = self.bytes();
            for (i, chunk) in keep.chunks(page as usize).enumerate() {
                // A page of zeros stays untouched, and costs nothing.
                if chunk.iter().any(|&b| b != 0) {
                    let at = s + i * page as usize;
                    bytes[at..at + chunk.len()].copy_from_slice(chunk);
                }
            }
            true
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

pub mod alloc_tag;

/// Which host pages of `[addr, addr + len)` the host has ever given this
/// process (in memory, or swapped or compressed out of it), one byte each
/// in `out` (non-zero for touched), by the host's `mincore`; and the host's
/// page size. `None` where the host cannot say: the caller then takes every
/// page as touched. For a range of the process's own memory: on macOS,
/// reading a page the host never gave makes the host give it, so a fork's
/// copy that reads every page to find the non-zero ones costs all of them.
pub fn host_pages_touched(addr: usize, len: usize, out: &mut Vec<u8>) -> Option<usize> {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn mincore(addr: *const std::ffi::c_void, len: usize, vec: *mut u8) -> i32;
            fn sysconf(name: i32) -> i64;
        }
        const SC_PAGESIZE: i32 = 29;
        // In memory, paged out (swapped or compressed), or written.
        const TOUCHED: u8 = 0x1 | 0x4 | 0x20;
        // SAFETY: a read of a constant of the system's.
        let page = unsafe { sysconf(SC_PAGESIZE) };
        if page <= 0 {
            return None;
        }
        let page = page as usize;
        let lo = addr & !(page - 1);
        let hi = (addr + len).div_ceil(page) * page;
        let n = (hi - lo) / page;
        out.clear();
        out.resize(n, 0);
        // SAFETY: `mincore` reads the host's page tables for the range, which
        // is the caller's own mapped memory, and writes one byte a page into
        // `out`, which has room for each.
        if unsafe { mincore(lo as *const std::ffi::c_void, hi - lo, out.as_mut_ptr()) } != 0 {
            return None;
        }
        for b in out.iter_mut() {
            *b &= TOUCHED;
        }
        Some(page)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (addr, len, out);
        None
    }
}

/// Give the host back what its allocator keeps of memory the program has
/// freed (glibc's `malloc_trim`; nothing on a host with another
/// allocator). Here with the other thing the host cannot say safely: glibc
/// keeps what a thread frees in that thread's own arena, and a guest
/// process's threads each free tens of megabytes when it ends
/// (`gex_native`'s `trim_heap`).
pub fn trim_heap() {
    // macOS's allocator keeps what is freed too, and gives it back when
    // asked (`malloc_zone_pressure_relief`, every zone, as much as it can).
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: the system allocator's own call, which takes each zone's
        // lock, made from any thread at any time.
        unsafe {
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
    }
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

/// Hold the host's allocator to what the program uses. A run's host
/// threads compile and translate in bursts, each in its own glibc arena,
/// and glibc keeps what they free: a booting Android's arenas held 3.3 GiB
/// from the system with 0.3 to 0.6 GiB in use, and the host killed the run
/// for it. Two things: blocks of a megabyte or more are mapped of their own
/// and given back when freed (glibc raises that threshold to 32 MiB as
/// large blocks are freed, which puts the next ones in the arenas for
/// good; a fixed value stops it), and every `GEX_HEAP_TRIM` seconds (10
/// unless set; 0 for never) the arenas' free pages are given back when
/// they come to 64 MiB or more. Nothing on a host with another allocator.
pub fn tune_heap() {
    // macOS: no threshold to fix, but the same periodic giving back, when
    // a megabyte or more is free in the zones.
    #[cfg(target_os = "macos")]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let secs = std::env::var("GEX_HEAP_TRIM").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(10);
            if secs == 0 {
                return;
            }
            let _ = std::thread::Builder::new().name("gex-heap-trim".into()).spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                let z = zone_stats();
                if z.size_allocated.saturating_sub(z.size_in_use) >= 64 << 20 {
                    trim_heap();
                }
            });
        });
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            extern "C" {
                fn mallopt(param: i32, value: i32) -> i32;
            }
            const M_MMAP_THRESHOLD: i32 = -3;
            // SAFETY: glibc's own call, made before the run's threads.
            unsafe {
                mallopt(M_MMAP_THRESHOLD, 1 << 20);
            }
            let secs = std::env::var("GEX_HEAP_TRIM").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(10);
            if secs == 0 {
                return;
            }
            let _ = std::thread::Builder::new().name("gex-heap-trim".into()).spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                if mallinfo().fordblks >= 64 << 20 {
                    trim_heap();
                }
            });
        });
    }
}

/// macOS's `malloc_statistics_t`, over every zone.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct ZoneStats {
    blocks_in_use: u32,
    size_in_use: usize,
    max_size_in_use: usize,
    size_allocated: usize,
}

#[cfg(target_os = "macos")]
fn zone_stats() -> ZoneStats {
    extern "C" {
        fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut ZoneStats);
    }
    let mut z = ZoneStats::default();
    // SAFETY: the system allocator's own call, a null zone being all of
    // them; it writes the one structure given.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut z) };
    z
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[repr(C)]
struct Mallinfo2 {
    arena: usize,
    ordblks: usize,
    smblks: usize,
    hblks: usize,
    hblkhd: usize,
    usmblks: usize,
    fsmblks: usize,
    uordblks: usize,
    fordblks: usize,
    keepcost: usize,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn mallinfo() -> Mallinfo2 {
    extern "C" {
        fn mallinfo2() -> Mallinfo2;
    }
    // SAFETY: glibc's own call, which takes each arena's lock.
    unsafe { mallinfo2() }
}

/// `GEX_HEAP_STATS=<seconds>`: every so many seconds, what the host's
/// allocator holds from the system against what is in use in it (glibc's
/// `mallinfo2`), one line on standard error: to tell memory the program
/// holds from memory the allocator keeps after it was freed. Nothing on a
/// host with another allocator, or unless asked.
pub fn heap_stats_every() {
    #[cfg(target_os = "macos")]
    {
        let Some(secs) = std::env::var("GEX_HEAP_STATS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|&s| s > 0) else {
            return;
        };
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let start = std::time::Instant::now();
            let _ = std::thread::Builder::new().name("gex-heap-stats".into()).spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                let z = zone_stats();
                eprintln!(
                    "gex: heap at {}s: {} MiB from the system in the zones, {} MiB in use, {} MiB in use at most, {} blocks",
                    start.elapsed().as_secs(),
                    z.size_allocated >> 20,
                    z.size_in_use >> 20,
                    z.max_size_in_use >> 20,
                    z.blocks_in_use
                );
                let live = alloc_tag::live();
                if live.iter().any(|&b| b != 0) {
                    let parts: Vec<String> = alloc_tag::NAMES.iter().zip(live).map(|(n, b)| format!("{n} {}", b >> 20)).collect();
                    eprintln!("gex: heap by tag at {}s (MiB): {}", start.elapsed().as_secs(), parts.join(", "));
                }
            });
        });
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let Some(secs) = std::env::var("GEX_HEAP_STATS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|&s| s > 0) else {
            return;
        };
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let start = std::time::Instant::now();
            let _ = std::thread::Builder::new().name("gex-heap-stats".into()).spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                let m = mallinfo();
                eprintln!(
                    "gex: heap at {}s: {} MiB from the system in arenas, {} MiB in use, {} MiB free in them; {} MiB in {} mapped blocks",
                    start.elapsed().as_secs(),
                    m.arena >> 20,
                    m.uordblks >> 20,
                    m.fordblks >> 20,
                    m.hblkhd >> 20,
                    m.hblks
                );
                let live = alloc_tag::live();
                if live.iter().any(|&b| b != 0) {
                    let parts: Vec<String> = alloc_tag::NAMES.iter().zip(live).map(|(n, b)| format!("{n} {}", b >> 20)).collect();
                    eprintln!("gex: heap by tag at {}s (MiB): {}", start.elapsed().as_secs(), parts.join(", "));
                }
            });
        });
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
    #[cfg(target_os = "macos")]
    fn macos_max_files() -> Option<u64> {
        extern "C" {
            fn sysctlbyname(name: *const u8, oldp: *mut std::ffi::c_void, oldlenp: *mut usize, newp: *const std::ffi::c_void, newlen: usize) -> i32;
        }
        let mut v: i32 = 0;
        let mut len = std::mem::size_of::<i32>();
        // SAFETY: the name is NUL-terminated, and the kernel writes at most
        // `len` bytes into `v`, an i32 (the sysctl's type).
        let r = unsafe { sysctlbyname(b"kern.maxfilesperproc\0".as_ptr(), &mut v as *mut i32 as *mut std::ffi::c_void, &mut len, std::ptr::null(), 0) };
        (r == 0 && v > 0).then_some(v as u64)
    }
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
        // macOS's own ceiling is kern.maxfilesperproc (92160 on a current
        // Mac), and it takes a soft limit up to that: OPEN_MAX (10240),
        // which setrlimit(2) names, is only where a program built for strict
        // UNIX03 conformance is held. A whole Android boot (every guest
        // process's host files and every mapped translation) went past
        // 10240, and its guests' opens failed with the host's EMFILE.
        #[cfg(target_os = "linux")]
        let most: u64 = u64::MAX;
        #[cfg(target_os = "macos")]
        let most: u64 = macos_max_files().unwrap_or(10240);
        let mut l = Rlimit { cur: 0, max: 0 };
        // SAFETY: both calls read or write the one struct given, which is
        // the layout of `struct rlimit` on these hosts (two 64-bit limits).
        unsafe {
            if getrlimit(RLIMIT_NOFILE, &mut l) != 0 {
                return;
            }
            let want = l.max.min(most);
            if want > l.cur {
                let old = l.cur;
                l.cur = want;
                if setrlimit(RLIMIT_NOFILE, &l) != 0 && want > 10240 && old < 10240 {
                    // A host that does hold the soft limit to OPEN_MAX.
                    l.cur = 10240;
                    setrlimit(RLIMIT_NOFILE, &l);
                }
            }
        }
    }
}
