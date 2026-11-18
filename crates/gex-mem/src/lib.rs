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
}

pub mod alloc_tag;

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
