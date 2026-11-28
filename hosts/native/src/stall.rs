//! `GEX_STALL=MS`: when no guest thread has entered a system call for MS
//! milliseconds, say what every guest thread is doing -- inside a call
//! (which, for how long) or outside one (running guest code, or parked in a
//! wasm32 `memory.atomic.wait`, which is no syscall) -- and how much CPU
//! each used over the next 200 ms, which tells a busy thread from a waiting
//! one. `GEX_STALL_EVERY=MS` dumps on that period regardless.
//! `GEX_STALL_FRAME=MS` dumps when the compositor has shown no new frame
//! for MS (and again each further MS): a GUI session that boots to nothing
//! is often busy with syscalls the whole time, so only the screen says it
//! stalled. For the
//! stalls a CPU profile cannot see: a whole session idle, waiting on a
//! wakeup that comes late. Off unless set; when off, one load per syscall.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

struct Conf {
    quiet: Option<Duration>,
    every: Option<Duration>,
    frame: Option<Duration>,
}

fn conf() -> &'static Conf {
    static C: OnceLock<Conf> = OnceLock::new();
    C.get_or_init(|| {
        let ms = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok()).map(Duration::from_millis);
        Conf { quiet: ms("GEX_STALL"), every: ms("GEX_STALL_EVERY"), frame: ms("GEX_STALL_FRAME") }
    })
}

pub fn on() -> bool {
    let c = conf();
    c.quiet.is_some() || c.every.is_some() || c.frame.is_some()
}

/// Milliseconds since `START` of the compositor's latest frame.
static LAST_FRAME_MS: AtomicU64 = AtomicU64::new(0);

/// The compositor showed a frame (`GEX_STALL_FRAME`).
pub fn frame() {
    if conf().frame.is_some() {
        LAST_FRAME_MS.store(start().elapsed().as_millis() as u64, Relaxed);
    }
}

#[derive(Clone)]
struct Entry {
    tid: i32,
    pid: i32,
    /// The raw number of the call it is in, or `None` when outside one.
    inside: Option<u64>,
    /// That call's canonical number, once the kernel has decoded it.
    call: Option<u64>,
    /// Where it blocked, when asked for (`want_bt`).
    bt: Option<String>,
    since: Instant,
    last: u64,
    /// The latest call-out from a unit: target, return address; how many
    /// call-outs, and how many of them ended without the callee returning.
    co: (u64, u64),
    co_n: u64,
    co_aborts: u64,
    /// Its process's memory, its context's address there and the process's
    /// memory map, from its latest call ([`enter_at`]): where a thread that
    /// is outside a call is running, said by its PC and link register.
    place: Option<Place>,
}

#[derive(Clone)]
struct Place {
    memory: gex_mem::GuestMemory,
    ctx: u64,
    mm: gex_kernel::mem::Mm,
}

static START: OnceLock<Instant> = OnceLock::new();
/// Milliseconds since `START` of the latest syscall entry by any thread.
static LAST_ENTRY_MS: AtomicU64 = AtomicU64::new(0);
static THREADS: Mutex<Option<HashMap<u64, Entry>>> = Mutex::new(None);

thread_local! {
    static HOST_TID: u64 = gex_mem::hostthread::current();
}

fn start() -> Instant {
    *START.get_or_init(|| {
        let _ = std::thread::Builder::new().name("gex-stall".into()).spawn(watch);
        Instant::now()
    })
}

/// Guest thread `tid` of process `pid` is entering raw syscall `nr`.
pub fn enter(pid: i32, tid: i32, nr: u64) {
    let now = Instant::now();
    LAST_ENTRY_MS.store(now.duration_since(start()).as_millis() as u64, Relaxed);
    let host = HOST_TID.with(|t| *t);
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_with(HashMap::new).entry(host).or_insert(Entry { tid, pid, inside: None, call: None, bt: None, since: now, last: !0, co: (0, 0), co_n: 0, co_aborts: 0, place: None });
    e.tid = tid;
    e.pid = pid;
    e.inside = Some(nr);
    e.call = None;
    e.bt = None;
    e.since = now;
}

/// [`enter`], and where the thread's context is: its process's `memory`
/// at `ctx`, and the process's map (`mm`, asked for only when the memory
/// is not the one noted already: at its first call and after an exec).
pub fn enter_at(pid: i32, tid: i32, nr: u64, memory: &gex_mem::GuestMemory, ctx: u64, mm: impl FnOnce() -> gex_kernel::mem::Mm) {
    enter(pid, tid, nr);
    let host = HOST_TID.with(|t| *t);
    let known = {
        let g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().and_then(|m| m.get(&host)).and_then(|e| e.place.as_ref()).is_some_and(|p| p.ctx == ctx && p.memory.bytes().as_ptr() == memory.bytes().as_ptr())
    };
    if known {
        return;
    }
    let place = Place { memory: memory.clone(), ctx, mm: mm() };
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.get_or_insert_with(HashMap::new).get_mut(&host) {
        e.place = Some(place);
    }
}

/// `GEX_STALL_PEEK=x23-64:64,sp+0:32,...`: memory a running thread's dump
/// shows, each at a register (`x0`-`x30`, `sp`) plus an offset, so many
/// bytes (whole 8-byte words; at most 4096).
fn peek() -> &'static [(u8, i64, usize)] {
    static P: OnceLock<Vec<(u8, i64, usize)>> = OnceLock::new();
    P.get_or_init(|| {
        let Ok(v) = std::env::var("GEX_STALL_PEEK") else { return Vec::new() };
        v.split(',')
            .filter_map(|item| {
                let (place, len) = item.trim().split_once(':')?;
                let len: usize = len.parse().ok().filter(|&n| n > 0 && n <= 4096)?;
                let at = place.find(['+', '-']).unwrap_or(place.len());
                let (reg, off) = place.split_at(at);
                let reg = if reg == "sp" { 31 } else { reg.strip_prefix('x')?.parse::<u8>().ok().filter(|&r| r < 31)? };
                let off: i64 = if off.is_empty() { 0 } else { off.trim_start_matches('+').parse().ok()? };
                Some((reg, off, len.next_multiple_of(8)))
            })
            .collect()
    })
}

/// Where `at` is in a process: its mapping's name and the offset in it
/// (in its file where it was loaded from one).
fn where_in(mm: &gex_kernel::mem::Mm, at: u64) -> String {
    let m = mm.lock();
    match m.vma_at(at) {
        Some(v) => match &v.code {
            Some((file, off)) => format!("{file}+{:#x}", off + (at - v.start)),
            None => format!("{}+{:#x}", if v.name.is_empty() { "[anon]" } else { &v.name }, at - v.start),
        },
        None => "no mapping".to_string(),
    }
}

/// `GEX_STALL_BT=1` (with `GEX_WASM_BACKTRACE=1`): keep where each blocking
/// call was made.
pub fn want_bt() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("GEX_STALL_BT").as_deref() == Ok("1"))
}

/// The guest frames a thread blocked from (`want_bt`).
pub fn blocked(frames: String) {
    let host = HOST_TID.with(|t| *t);
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.get_or_insert_with(HashMap::new).get_mut(&host) {
        e.bt = Some(frames);
    }
}

/// The kernel has decoded the call this thread is in: its canonical number,
/// which a stall dump names (the raw number is the guest ABI's).
pub fn decoded(canonical: u64) {
    let host = HOST_TID.with(|t| *t);
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.get_or_insert_with(HashMap::new).get_mut(&host) {
        e.call = Some(canonical);
    }
}

/// The call it entered has returned; `name` is the kernel's canonical number.
pub fn exit(canonical: u64) {
    let host = HOST_TID.with(|t| *t);
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.get_or_insert_with(HashMap::new).get_mut(&host) {
        e.inside = None;
        e.since = Instant::now();
        e.last = canonical;
    }
}

/// A unit's call-out to `target`, returning to `ret`, has ended; `aborted`
/// when the callee did not return through it.
pub fn callout(target: u64, ret: u64, aborted: bool) {
    let host = HOST_TID.with(|t| *t);
    let mut g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_with(HashMap::new).entry(host).or_insert(Entry {
        tid: 0,
        pid: 0,
        inside: None,
        call: None,
        bt: None,
        since: Instant::now(),
        last: !0,
        co: (0, 0),
        co_n: 0,
        co_aborts: 0,
        place: None,
    });
    e.co = (target, ret);
    e.co_n += 1;
    e.co_aborts += aborted as u64;
}

fn dump(why: &str) {
    let snap: Vec<(u64, Entry)> = {
        let g = THREADS.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|m| m.iter().map(|(k, v)| (*k, v.clone())).collect()).unwrap_or_default()
    };
    // Threads that have exited are not listed: left out.
    let all_before = gex_mem::hostthread::threads();
    std::thread::sleep(Duration::from_millis(200));
    let all_after = gex_mem::hostthread::threads();
    // The host's other threads (compilers, the compositor, GPU) by name.
    let mut others: HashMap<String, u64> = HashMap::new();
    for (h, (name, a)) in &all_after {
        if snap.iter().any(|(g, _)| g == h) {
            continue;
        }
        let d = a.saturating_sub(all_before.get(h).map(|x| x.1).unwrap_or(0));
        if d > 0 {
            *others.entry(name.clone()).or_default() += d;
        }
    }
    let t = start().elapsed().as_secs_f64();
    let mut lines = Vec::new();
    for (h, e) in &snap {
        let (Some((_, b)), Some((name, a))) = (all_before.get(h), all_after.get(h)) else { continue };
        let state = match e.inside {
            Some(nr) => match e.call {
                Some(c) => format!("in {} (raw {nr})", gex_kernel::syscalls::syscall_name(c)),
                None => format!("in raw {nr}"),
            },
            None => format!("outside (last {})", gex_kernel::syscalls::syscall_name(e.last)),
        };
        let co = if e.co_n > 0 {
            format!("; call-outs {} ({} aborted), last to {:#x} ret {:#x}", e.co_n, e.co_aborts, e.co.0, e.co.1)
        } else {
            String::new()
        };
        let bt = match (&e.inside, &e.bt) {
            (Some(_), Some(bt)) => format!("\n      at {bt}"),
            _ => String::new(),
        };
        // Running guest code: where (its context holds the PC its last
        // safepoint or call-out wrote).
        let at = match (&e.inside, &e.place) {
            (None, Some(p)) => {
                let gm = gex_kernel::GuestMem::new(p.memory.bytes());
                let pc = gm.read_u64(p.ctx + gex_abi::ctx::PC as u64).unwrap_or(0);
                let lr = gm.read_u64(p.ctx + gex_abi::ctx::x(30) as u64).unwrap_or(0);
                // Its registers as its last safepoint left them, and what
                // `GEX_STALL_PEEK` asks to see at them.
                let regs: Vec<String> = (0u8..31).map(|i| format!("x{i}={:#x}", gm.read_u64(p.ctx + gex_abi::ctx::x(i) as u64).unwrap_or(0))).collect();
                let sp = gm.read_u64(p.ctx + gex_abi::ctx::SP as u64).unwrap_or(0);
                let mut peeks = String::new();
                for &(reg, off, len) in peek() {
                    let base = if reg == 31 { sp } else { gm.read_u64(p.ctx + gex_abi::ctx::x(reg) as u64).unwrap_or(0) };
                    let at = base.wrapping_add_signed(off);
                    let words: Vec<String> = match gm.read(at, len) {
                        Ok(b) => b.chunks(8).map(|c| {
                            let mut w = [0u8; 8];
                            w[..c.len()].copy_from_slice(c);
                            format!("{:#x}", u64::from_le_bytes(w))
                        }).collect(),
                        Err(_) => vec!["(unreadable)".to_string()],
                    };
                    peeks.push_str(&format!("\n      at {}{off:+} = {at:#x}: {}", if reg == 31 { "sp".to_string() } else { format!("x{reg}") }, words.join(" ")));
                }
                format!("\n      pc {pc:#x} ({}) lr {lr:#x} ({})\n      {} sp={sp:#x}{peeks}", where_in(&p.mm, pc), where_in(&p.mm, lr), regs.join(" "))
            }
            _ => String::new(),
        };
        lines.push((e.pid, e.tid, format!(
            "  pid {} tid {} [{} {}] {} for {} ms, cpu {} ms/200{co}{bt}{at}",
            e.pid, e.tid, h, name, state, e.since.elapsed().as_millis(), a.saturating_sub(*b)
        )));
    }
    lines.sort();
    let mut busy: Vec<_> = others.into_iter().collect();
    busy.sort_by(|a, b| b.1.cmp(&a.1));
    let busy: Vec<String> = busy.iter().map(|(n, d)| format!("{n} {d}")).collect();
    let mut out = format!("[gex-stall] {t:.3} s: {why}; other threads' cpu ms/200: {}\n", busy.join(", "));
    for (_, _, l) in lines {
        out.push_str(&l);
        out.push('\n');
    }
    eprint!("{out}");
}

fn watch() {
    let c = conf();
    let mut last_every = Instant::now();
    let mut dumped_for = u64::MAX;
    let mut frame_dumped_at = 0u64;
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let Some(st) = START.get() else { continue };
        if let Some(every) = c.every {
            if last_every.elapsed() >= every {
                last_every = Instant::now();
                dump("periodic");
            }
        }
        if let Some(q) = c.quiet {
            let last = LAST_ENTRY_MS.load(Relaxed);
            let now = st.elapsed().as_millis() as u64;
            if now.saturating_sub(last) >= q.as_millis() as u64 && dumped_for != last {
                dumped_for = last;
                dump(&format!("no syscall for {} ms", now - last));
            }
        }
        if let Some(q) = c.frame {
            let last = LAST_FRAME_MS.load(Relaxed);
            let now = st.elapsed().as_millis() as u64;
            let q = q.as_millis() as u64;
            if now.saturating_sub(last) >= q && now.saturating_sub(frame_dumped_at.max(last)) >= q {
                frame_dumped_at = now;
                dump(&format!("no frame for {} ms", now - last));
            }
        }
    }
}
