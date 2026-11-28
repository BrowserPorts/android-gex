//! Holding the whole system still, for a snapshot of it
//! (`gex_kernel::snap`).
//!
//! A hold is asked for with [`ask`]; from then every guest thread stops at
//! the next point where it is out of guest code with nothing half done:
//! a safepoint, a system call's entry or return, the end of a blocking
//! call. These are the points the cgroup freezer and job-control stops
//! already use (`freeze_point`, `freeze_wait`, `hold_then_deliver`), which
//! consult [`pending`] through `holds_any`. A thread blocked in a host wait
//! (a futex, a poll, a sleep) touches nothing of the guest's while it
//! waits and counts as still; if its wait ends during the hold, it stops
//! before it writes its result.
//!
//! [`ask`] returns when every live guest thread is held or blocked
//! ([`Hold`]), or says which count did not come to rest in time; dropping
//! the [`Hold`] lets them all go on.
//!
//! `GEX_SNAP_HOLD_AT=<seconds>`: hold the system once, that many seconds
//! into the run, say what was held, and let it go a second later. A program
//! held and let go must print what it prints when never held: the test of
//! the hold alone, before anything is saved.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static PENDING: AtomicBool = AtomicBool::new(false);
/// Guest threads in their run loop ([`Live`]).
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// Of those, held at a hook ([`park`]).
static PARKED: AtomicUsize = AtomicUsize::new(0);
/// Of those, in a host wait for a blocking call ([`Blocked`]).
static BLOCKED: AtomicUsize = AtomicUsize::new(0);

/// Host nanoseconds (since [`epoch`]) at which the current hold began, 0
/// when none is on; and all the time held before it.
static HELD_FROM: AtomicU64 = AtomicU64::new(0);
static HELD_TOTAL: AtomicU64 = AtomicU64::new(0);

fn epoch() -> Instant {
    static E: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *E.get_or_init(Instant::now)
}

fn host_ns() -> u64 {
    epoch().elapsed().as_nanos() as u64
}

/// The host time spent held, so far, the current hold included.
fn held_ns() -> u64 {
    let from = HELD_FROM.load(Ordering::Acquire);
    let now = if from != 0 { host_ns().saturating_sub(from) } else { 0 };
    HELD_TOTAL.load(Ordering::Acquire) + now
}

/// When a wait began, on a clock that stands still while the system is
/// held: a blocking call's timeout measured with it does not run out during
/// a hold, as the guest's own clocks do not move then
/// (`gex_kernel::syscalls::pause_clocks`). `Instant`'s two calls a wait
/// makes, `now` and `elapsed`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Since {
    at: Instant,
    held: u64,
}

impl Since {
    pub(crate) fn now() -> Since {
        Since { at: Instant::now(), held: held_ns() }
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.at.elapsed().saturating_sub(Duration::from_nanos(held_ns().saturating_sub(self.held)))
    }
}

/// Whether a hold is asked for: threads stop at their next hook.
pub(crate) fn pending() -> bool {
    PENDING.load(Ordering::Acquire)
}

/// The guest threads in their run loops, by their process's memory, their
/// context and their id ([`Live`]): what a snapshot writes of each.
static LIVE_AT: std::sync::Mutex<Vec<(usize, u64, i32)>> = std::sync::Mutex::new(Vec::new());

/// A guest thread in its run loop, for as long as this lives.
pub(crate) struct Live {
    at: (usize, u64, i32),
}

impl Live {
    pub(crate) fn enter(memory: Option<&gex_mem::GuestMemory>, ctx_addr: u64, tid: i32) -> Live {
        let at = (memory.map_or(0, |m| m.bytes().as_ptr() as usize), ctx_addr, tid);
        LIVE_AT.lock().unwrap_or_else(|e| e.into_inner()).push(at);
        LIVE.fetch_add(1, Ordering::AcqRel);
        Live { at }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::AcqRel);
        let mut l = LIVE_AT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = l.iter().position(|x| *x == self.at) {
            l.swap_remove(i);
        }
    }
}

/// `memory`'s live threads: context and id.
fn threads_in(memory: &gex_mem::GuestMemory) -> Vec<(u64, i32)> {
    let key = memory.bytes().as_ptr() as usize;
    let mut t: Vec<(u64, i32)> = LIVE_AT.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(m, _, _)| *m == key).map(|(_, c, t)| (*c, *t)).collect();
    t.sort();
    t
}

/// The threads a restore has still to start ([`apply`] reads them, the run
/// starts them once its process's context exists, [`start_restored`]).
static TO_START: std::sync::Mutex<Vec<gex_kernel::syscalls::ThreadState>> = std::sync::Mutex::new(Vec::new());

/// Start a restored process's threads other than its first, each at its
/// context: called once the process's context exists.
pub(crate) fn start_restored(cx: &std::sync::Arc<crate::SpawnContext>) -> anyhow::Result<()> {
    let threads = std::mem::take(&mut *TO_START.lock().unwrap_or_else(|e| e.into_inner()));
    for t in threads {
        crate::start_guest_thread(std::sync::Arc::clone(cx), t)?;
    }
    Ok(())
}

/// The threads in a host wait, by their process's memory and their
/// context: a snapshot sends each back to its call, to make it again when
/// resumed ([`Blocked`]).
static BLOCKED_AT: std::sync::Mutex<Vec<(usize, u64)>> = std::sync::Mutex::new(Vec::new());

/// A guest thread in a host wait (`perform_block`), for as long as this
/// lives: still, as far as a hold is concerned. Its registers are as it made
/// the call (no result is written until the wait ends), so a snapshot of it
/// resumes by making the call again.
pub(crate) struct Blocked {
    at: (usize, u64),
}

impl Blocked {
    pub(crate) fn enter(memory: &gex_mem::GuestMemory, ctx_addr: u64) -> Blocked {
        let at = (memory.bytes().as_ptr() as usize, ctx_addr);
        BLOCKED_AT.lock().unwrap_or_else(|e| e.into_inner()).push(at);
        BLOCKED.fetch_add(1, Ordering::AcqRel);
        Blocked { at }
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        BLOCKED.fetch_sub(1, Ordering::AcqRel);
        let mut b = BLOCKED_AT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = b.iter().position(|x| *x == self.at) {
            b.swap_remove(i);
        }
    }
}

/// The contexts of `memory`'s threads that are in a host wait.
fn blocked_in(memory: &gex_mem::GuestMemory) -> Vec<u64> {
    let key = memory.bytes().as_ptr() as usize;
    BLOCKED_AT.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(m, _)| *m == key).map(|(_, c)| *c).collect()
}

/// Stop this thread here while a hold is pending (out of guest code; the
/// caller has left the fork gate). Whether it stopped.
pub(crate) fn park() -> bool {
    if !pending() {
        return false;
    }
    PARKED.fetch_add(1, Ordering::AcqRel);
    while pending() {
        std::thread::sleep(Duration::from_millis(2));
    }
    PARKED.fetch_sub(1, Ordering::AcqRel);
    true
}

/// The system held still: every guest thread parked or blocked. Dropping it
/// lets them go.
pub(crate) struct Hold {
    pub(crate) live: usize,
    pub(crate) parked: usize,
    pub(crate) blocked: usize,
    pub(crate) took: Duration,
}

impl Drop for Hold {
    fn drop(&mut self) {
        gex_kernel::syscalls::resume_clocks();
        let from = HELD_FROM.swap(0, Ordering::AcqRel);
        if from != 0 {
            HELD_TOTAL.fetch_add(host_ns().saturating_sub(from), Ordering::AcqRel);
        }
        PENDING.store(false, Ordering::Release);
    }
}

/// Ask every guest thread to stop, and wait up to `limit` for them to.
/// `Err` says what was still moving, and lets everything go.
pub(crate) fn ask(limit: Duration) -> Result<Hold, String> {
    if PENDING.swap(true, Ordering::AcqRel) {
        return Err("a hold is already pending".into());
    }
    let started = Instant::now();
    loop {
        // Read in this order: a thread counted live but not yet parked or
        // blocked shows as moving, never the other way round.
        let live = LIVE.load(Ordering::Acquire);
        let parked = PARKED.load(Ordering::Acquire);
        let blocked = BLOCKED.load(Ordering::Acquire);
        if parked + blocked >= live && live == LIVE.load(Ordering::Acquire) {
            // No guest time passes while it is held, nor does a blocked
            // call's timeout run down ([`Since`]).
            gex_kernel::syscalls::pause_clocks();
            HELD_FROM.store(host_ns().max(1), Ordering::Release);
            return Ok(Hold { live, parked, blocked, took: started.elapsed() });
        }
        if started.elapsed() > limit {
            PENDING.store(false, Ordering::Release);
            return Err(format!("{} of {live} threads did not stop in {limit:?} ({parked} held, {blocked} blocked)", live.saturating_sub(parked + blocked)));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// `GEX_SNAP_HOLD_AT`: one hold, that many seconds in.
pub(crate) fn start_test_hold() {
    let Some(secs) = std::env::var("GEX_SNAP_HOLD_AT").ok().and_then(|v| v.parse::<f64>().ok()).filter(|s| *s >= 0.0) else {
        return;
    };
    let _ = std::thread::Builder::new().name("gex-snap-hold".into()).spawn(move || {
        std::thread::sleep(Duration::from_secs_f64(secs));
        match ask(Duration::from_secs(10)) {
            Ok(h) => {
                eprintln!("[gex] snapshot hold: {} threads still ({} held, {} blocked) in {:?}", h.live, h.parked, h.blocked, h.took);
                // `GEX_SNAP_OUT=DIR`: written there while held; and with
                // `GEX_SNAP_STOP=1` the run ends with the snapshot.
                if let Some(dir) = std::env::var_os("GEX_SNAP_OUT") {
                    match write(std::path::Path::new(&dir)) {
                        Ok(s) => eprintln!("[gex] snapshot written: {s}"),
                        Err(e) => eprintln!("[gex] snapshot not written: {e}"),
                    }
                    if std::env::var_os("GEX_SNAP_STOP").is_some() {
                        std::process::exit(0);
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
                drop(h);
                eprintln!("[gex] snapshot hold: let go");
            }
            Err(e) => eprintln!("[gex] snapshot hold refused: {e}"),
        }
    });
}

/// Mappings of gex's own that hold translation state, not the guest's:
/// a restored process starts with a fresh registry, so they are left out
/// and come back as a fresh process has them.
const RUNTIME_MAPPINGS: [&str; 2] = ["[gex dense slot map]", "[gex other-mode dispatch]"];

const MEMORY_MAGIC: &[u8; 8] = b"GEXMEM1\0";

/// The guest's part of a held process's memory, as runs of the pages that
/// are not zero: the thread contexts below `ctx::` space's end (registers
/// come back with the memory) and every mapping's parts not known to be
/// zero (`MemoryMap::dirty_parts`), as a fork copies them. Translation
/// state (the dispatch directory and caches above the contexts, the dense
/// maps, the protection table) is not written. Pages written and bytes.
pub(crate) fn write_memory(memory: &gex_mem::GuestMemory, mm: &gex_kernel::mem::MemoryMap, out: &mut impl std::io::Write) -> std::io::Result<(u64, u64)> {
    let src = memory.bytes();
    let mut regions: Vec<(u64, u64)> = vec![(0, gex_abi::CTX_LIMIT)];
    for v in mm.vmas() {
        if RUNTIME_MAPPINGS.contains(&v.name.as_str()) {
            continue;
        }
        regions.extend(mm.dirty_parts(v.start, v.end));
    }
    out.write_all(MEMORY_MAGIC)?;
    let mut sparse = crate::SparseCopy::new();
    let page = crate::SparseCopy::PAGE;
    let (mut pages, mut runs) = (0u64, Vec::<(usize, usize)>::new());
    for (a, b) in regions {
        let (a, b) = (a as usize / page * page, (b as usize).min(src.len()).next_multiple_of(page).min(src.len()));
        if a >= b {
            continue;
        }
        sparse.nonzero_pages(src, a, b, &mut |r| {
            pages += 1;
            match runs.last_mut() {
                Some(last) if last.1 == r.start => last.1 = r.end,
                _ => runs.push((r.start, r.end)),
            }
        });
    }
    let mut bytes = 0u64;
    for (a, b) in runs {
        out.write_all(&(a as u64).to_le_bytes())?;
        out.write_all(&((b - a) as u64).to_le_bytes())?;
        out.write_all(&src[a..b])?;
        bytes += (b - a) as u64;
    }
    out.write_all(&[0u8; 16])?;
    Ok((pages, bytes))
}

/// A memory [`write_memory`] wrote, into `memory` (fresh, so all zero but
/// for what its setup wrote, which the runs overwrite). Bytes read.
pub(crate) fn read_memory(memory: &gex_mem::GuestMemory, input: &mut impl std::io::Read) -> std::io::Result<u64> {
    use std::io::{Error, ErrorKind};
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MEMORY_MAGIC {
        return Err(Error::new(ErrorKind::InvalidData, "not a gex snapshot's memory"));
    }
    let dst = memory.bytes();
    let mut total = 0u64;
    loop {
        let mut head = [0u8; 16];
        input.read_exact(&mut head)?;
        let at = u64::from_le_bytes(head[..8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(head[8..].try_into().unwrap()) as usize;
        if len == 0 {
            return Ok(total);
        }
        let end = at.checked_add(len).filter(|&e| e <= dst.len()).ok_or_else(|| Error::new(ErrorKind::InvalidData, format!("a run at {at:#x} of {len} bytes past the memory's end")))?;
        input.read_exact(&mut dst[at..end])?;
        total += len as u64;
    }
}

/// Every process this host runs, for a snapshot to find (`register`).
static PROCS: std::sync::Mutex<Vec<std::sync::Weak<crate::SpawnContext>>> = std::sync::Mutex::new(Vec::new());

/// A process, from when its context is made: a snapshot writes what it
/// can still reach.
pub(crate) fn register(cx: &std::sync::Arc<crate::SpawnContext>) {
    let mut p = PROCS.lock().unwrap_or_else(|e| e.into_inner());
    p.retain(|w| w.strong_count() > 0);
    p.push(std::sync::Arc::downgrade(cx));
}

/// The head of a process's file: its section, and the version that says
/// its parent, group and session.
const PROC_HEAD: u32 = 0x5052_4f43;

/// Write every live process of the held system to `dir`: for each, its
/// memory map and identity (`proc-<pid>.bin`) and its memory
/// (`mem-<pid>.bin`), and `order` (the pids, a parent before its
/// children: the order a restore makes them in). One numbering of open
/// descriptions, pipes and the like across every process, so what two
/// processes share is written once and is one again when restored. A
/// summary, or what refused.
pub(crate) fn write(dir: &std::path::Path) -> Result<String, String> {
    use std::io::Write;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let procs: Vec<_> = PROCS.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(|w| w.upgrade()).filter(|cx| !cx.stopping.load(Ordering::Acquire)).collect();
    // Each one's ids, and its depth among them: parents first.
    let mut listed: Vec<(usize, i32, i32, i32, i32, std::sync::Arc<crate::SpawnContext>)> = Vec::new();
    for cx in procs {
        let k = cx.kernel.lock().unwrap_or_else(|e| e.into_inner());
        let pid = k.pid;
        let ppid = k.procs.ppid(pid);
        let pgid = k.procs.pgid(pid, pid).unwrap_or(pid);
        let sid = k.procs.sid(pid, pid).unwrap_or(pid);
        drop(k);
        listed.push((0, pid, ppid, pgid, sid, cx));
    }
    let parent: std::collections::HashMap<i32, i32> = listed.iter().map(|l| (l.1, l.2)).collect();
    for l in &mut listed {
        let (mut at, mut depth) = (l.2, 0);
        while let Some(&up) = parent.get(&at) {
            depth += 1;
            if depth > parent.len() {
                return Err(format!("pid {}: its parents go round", l.1));
            }
            at = up;
        }
        l.0 = depth;
    }
    listed.sort_by_key(|l| (l.0, l.1));
    if listed.iter().filter(|l| l.0 == 0).count() != 1 {
        return Err(format!("{} processes with no parent among them: a restore makes one tree", listed.iter().filter(|l| l.0 == 0).count()));
    }
    let mut ids = gex_kernel::snap::Ids::new();
    let mut said = Vec::new();
    for (_, pid, ppid, pgid, sid, cx) in &listed {
        let (pid, ppid, pgid, sid) = (*pid, *ppid, *pgid, *sid);
        let k = cx.kernel.lock().unwrap_or_else(|e| e.into_inner());
        let mut w = gex_kernel::snap::W::new();
        w.section(PROC_HEAD, 2, |w| {
            w.i32(pid);
            w.i32(ppid);
            w.i32(pgid);
            w.i32(sid);
            w.str(&k.exe_path);
            w.len_of(k.argv.len());
            for a in &k.argv {
                w.str(a);
            }
            w.len_of(k.envp.len());
            for e in &k.envp {
                w.str(e);
            }
            Ok(())
        })
        .map_err(|e| format!("pid {pid}: {e}"))?;
        let mm = k.mem.lock();
        mm.snap(&mut w).map_err(|e| format!("pid {pid}: {e}"))?;
        // Its descriptors, its signals' state (dispositions, mask, pending
        // sets, alternate stack, prctl state, auxv) and its credentials.
        k.fds.snap(&mut w, &mut ids).map_err(|e| format!("pid {pid}: {e}"))?;
        w.section(0x5349_4700, 1, |w| {
            w.bytes(&k.signals.to_bytes(true));
            w.bytes(&k.creds.save());
            Ok(())
        })
        .map_err(|e| format!("pid {pid}: {e}"))?;
        // The threads caught in a blocking call: sent back to the call when
        // resumed, to make it again.
        let blocked = blocked_in(&cx.memory);
        w.section(0x424c_4b00, 1, |w| {
            w.len_of(blocked.len());
            for c in &blocked {
                w.u64(*c);
            }
            Ok(())
        })
        .map_err(|e| format!("pid {pid}: {e}"))?;
        // Its threads: the slots their contexts are in, and each one's id,
        // context and own signal state. Its first (whose id is the pid)
        // goes on as the process's own thread.
        let threads = threads_in(&cx.memory);
        if !threads.iter().any(|&(_, t)| t == pid) {
            return Err(format!("pid {pid}: its first thread has ended"));
        }
        w.section(0x5448_5200, 1, |w| {
            k.next_ctx_slot.snap(w);
            w.len_of(threads.len());
            for &(c, tid) in &threads {
                w.u64(c);
                w.i32(tid);
                let sig = k.thread_signals.get(tid).unwrap_or_else(|| std::sync::Arc::clone(k.signals.thread()));
                sig.snap(w);
            }
            Ok(())
        })
        .map_err(|e| format!("pid {pid}: {e}"))?;
        // The guest's time, held still: a resumed run's clocks go on from it.
        w.section(0x434c_4b00, 1, |w| {
            gex_kernel::syscalls::clocks_snap(w);
            Ok(())
        })
        .map_err(|e| format!("pid {pid}: {e}"))?;
        std::fs::write(dir.join(format!("proc-{pid}.bin")), w.into_bytes()).map_err(|e| format!("pid {pid}: {e}"))?;
        let f = std::fs::File::create(dir.join(format!("mem-{pid}.bin"))).map_err(|e| format!("pid {pid}: {e}"))?;
        let mut out = std::io::BufWriter::with_capacity(1 << 20, f);
        let (pages, bytes) = write_memory(&cx.memory, &mm, &mut out).map_err(|e| format!("pid {pid}: memory: {e}"))?;
        out.flush().map_err(|e| format!("pid {pid}: memory: {e}"))?;
        said.push(format!("pid {pid}: {} mappings, {pages} pages ({} MiB)", mm.vmas().len(), bytes >> 20));
    }
    let order: String = listed.iter().map(|l| format!("{}\n", l.1)).collect();
    std::fs::write(dir.join("order"), order).map_err(|e| format!("order: {e}"))?;
    Ok(said.join("; "))
}

/// What a restore has made so far that more than one process may name: by
/// the number the snapshot gave it ([`gex_kernel::snap::Ids`], one
/// numbering across every process).
#[derive(Default)]
struct Objects {
    /// Open descriptions.
    descs: std::collections::HashMap<u32, std::sync::Arc<gex_kernel::file::OpenFile>>,
    /// signalfd descriptions: made in each process that has one, with its
    /// own signal state.
    signalfds: std::collections::HashMap<u32, (u64, String, u64, bool, bool)>,
    pipes: std::collections::HashMap<u32, std::sync::Arc<gex_kernel::pipe::Pipe>>,
    /// The run's own standard streams, by number.
    stdio: std::collections::HashMap<i32, std::sync::Arc<gex_kernel::file::OpenFile>>,
}

/// A process's file read as far as its head: pid, parent, group, session,
/// program.
struct Head {
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    exe: String,
    argv: Vec<String>,
    envp: Vec<String>,
}

fn read_head(r: &mut gex_kernel::snap::R<'_>) -> anyhow::Result<Head> {
    use anyhow::anyhow;
    let e = |e: gex_kernel::snap::Refused| anyhow!("{e}");
    let mut head = r.expect(PROC_HEAD, 2, "process").map_err(e)?;
    let (pid, ppid, pgid, sid) = (head.i32().map_err(e)?, head.i32().map_err(e)?, head.i32().map_err(e)?, head.i32().map_err(e)?);
    let exe = head.str().map_err(e)?.to_string();
    let strs = |head: &mut gex_kernel::snap::R<'_>| -> anyhow::Result<Vec<String>> {
        let n = head.len_of().map_err(e)?;
        (0..n).map(|_| Ok(head.str().map_err(e)?.to_string())).collect()
    };
    let argv = strs(&mut head)?;
    let envp = strs(&mut head)?;
    Ok(Head { pid, ppid, pgid, sid, exe, argv, envp })
}

/// The processes still to make after the run's own, in order, each its
/// file's bytes ([`apply`] reads them, [`restore_children`] makes them),
/// and what the run's own restore made that they may share.
static CHILDREN: std::sync::Mutex<(Vec<(std::path::PathBuf, Vec<u8>)>, Option<Objects>)> = std::sync::Mutex::new((Vec::new(), None));

/// The rest of a process's file, after its head, onto kernel `k` and
/// memory `memory`: its memory and map, descriptors, signals' state,
/// credentials, blocked calls, threads and (`clocks`: the first process's)
/// the guest's time. `clear`: the memory has a program's own in it (a
/// fresh one is zero already).
/// Its threads (context and id); its first, whose id is the pid, first.
fn restore_into(k: &mut gex_kernel::syscalls::Kernel, memory: &gex_mem::GuestMemory, r: &mut gex_kernel::snap::R<'_>, mem_file: &std::path::Path, objs: &mut Objects, clear: bool, clocks: bool) -> anyhow::Result<Vec<gex_kernel::syscalls::ThreadState>> {
    use anyhow::{anyhow, bail, Context};
    // What the process had cleared where it or the snapshot's has
    // anything, so what the snapshot left out as zero is zero.
    let mut mm = k.mem.lock();
    let mut clear_ranges: Vec<(u64, u64)> = vec![(0, gex_abi::CTX_LIMIT)];
    clear_ranges.extend(mm.vmas().iter().filter(|v| !RUNTIME_MAPPINGS.contains(&v.name.as_str())).map(|v| (v.start, v.end)));
    mm.unsnap(r).map_err(|e| anyhow!("{e}"))?;
    clear_ranges.extend(mm.vmas().iter().filter(|v| !RUNTIME_MAPPINGS.contains(&v.name.as_str())).map(|v| (v.start, v.end)));
    // (A fresh memory, another process's, is zero already: writing zeros
    // would only make the host give it pages.)
    let bytes = memory.bytes();
    for (a, b) in clear_ranges.into_iter().filter(|_| clear) {
        let (a, b) = (a as usize, (b as usize).min(bytes.len()));
        if a < b {
            bytes[a..b].fill(0);
        }
    }
    drop(mm);
    let f = std::fs::File::open(mem_file).with_context(|| mem_file.display().to_string())?;
    read_memory(memory, &mut std::io::BufReader::with_capacity(1 << 20, f)).with_context(|| mem_file.display().to_string())?;

    // Descriptors: the host's streams it has already; host files
    // opened again by path, at their offsets; what another process made
    // already, shared.
    let mut fds = r.expect(gex_kernel::file::SNAP_FDS, 1, "descriptors").map_err(|e| anyhow!("{e}"))?;
    k.fds.close_all();
    let mut later_signalfds: Vec<(i32, bool, u64, String, u64, bool, bool)> = Vec::new();
    let mut later_epolls: Vec<(std::sync::Arc<gex_kernel::unix::EpollSet>, Vec<u8>)> = Vec::new();
    let n = fds.len_of().map_err(|e| anyhow!("{e}"))?;
    let e = |e: gex_kernel::snap::Refused| anyhow!("{e}");
    for _ in 0..n {
        let fd = fds.i32().map_err(e)?;
        let cloexec = fds.bool().map_err(e)?;
        let id = fds.u32().map_err(e)?;
        // A signalfd's description, made later (below), named again.
        // (Each process its own description, and each descriptor in it
        // too: what reads from one is the process's pending signals
        // either way.)
        if let Some((mask, path, flags, readable, writable)) = objs.signalfds.get(&id).cloned() {
            later_signalfds.push((fd, cloexec, mask, path, flags, readable, writable));
            continue;
        }
        let file = if let Some(f) = objs.descs.get(&id) {
            std::sync::Arc::clone(f)
        } else {
            let path = fds.str().map_err(e)?.to_string();
            let flags = fds.u64().map_err(e)?;
            let offset = fds.u64().map_err(e)?;
            let readable = fds.bool().map_err(e)?;
            let writable = fds.bool().map_err(e)?;
            let kind = fds.u16().map_err(e)?;
            let inner = fds.bytes().map_err(e)?;
            let mut ir = gex_kernel::snap::R::new(inner);
            let file = match kind {
                gex_kernel::snap::KIND_STDIO => {
                    let stream = ir.u8().map_err(e)? as i32;
                    objs.stdio.get(&stream).cloned().ok_or_else(|| anyhow!("fd {fd}: this run has no standard stream {stream}"))?
                }
                gex_kernel::snap::KIND_HOST_FILE => {
                    use gex_kernel::fs::oflags;
                    let open = flags & !(oflags::O_CREAT | oflags::O_TRUNC | oflags::O_EXCL);
                    let h = k.vfs.open(&path, open, 0).map_err(|er| anyhow!("fd {fd}: {path}: {er:?}"))?;
                    let f = gex_kernel::file::OpenFile::new(h, path.clone(), flags, readable, writable);
                    f.set_offset(offset);
                    f
                }
                gex_kernel::snap::KIND_EVENTFD => {
                    let count = ir.u64().map_err(e)?;
                    let semaphore = ir.bool().map_err(e)?;
                    gex_kernel::file::OpenFile::new(std::sync::Arc::new(gex_kernel::eventfd::EventFd::new(count, semaphore)), path.clone(), flags, readable, writable)
                }
                gex_kernel::snap::KIND_TIMERFD => {
                    let t = gex_kernel::syscalls::timerfd_unsnap(k.clock, &mut ir).map_err(e)?;
                    gex_kernel::file::OpenFile::new(std::sync::Arc::new(t), path.clone(), flags, readable, writable)
                }
                gex_kernel::snap::KIND_SIGNALFD => {
                    // Made once the process's signal state is back
                    // (below): it notes itself with that state.
                    let mask = ir.u64().map_err(e)?;
                    later_signalfds.push((fd, cloexec, mask, path.clone(), flags, readable, writable));
                    objs.signalfds.insert(id, (mask, path.clone(), flags, readable, writable));
                    continue;
                }
                gex_kernel::snap::KIND_PIPE => {
                    let write = ir.bool().map_err(e)?;
                    let pid = ir.u32().map_err(e)?;
                    let pipe = if ir.bool().map_err(e)? {
                        let p = std::sync::Arc::new(gex_kernel::pipe::Pipe::unsnap(&mut ir).map_err(e)?);
                        objs.pipes.insert(pid, std::sync::Arc::clone(&p));
                        p
                    } else {
                        std::sync::Arc::clone(objs.pipes.get(&pid).ok_or_else(|| anyhow!("fd {fd}: pipe {pid} before it was written"))?)
                    };
                    // Counted in as an end, as when it was made.
                    pipe.open_end(write);
                    gex_kernel::file::OpenFile::new(std::sync::Arc::new(gex_kernel::file::PipeEnd { pipe, write }), path.clone(), flags, readable, writable)
                }
                gex_kernel::snap::KIND_EPOLL => {
                    // Its watches name descriptors by number: they are
                    // watched again once every descriptor is back.
                    let set = std::sync::Arc::new(gex_kernel::unix::EpollSet::new());
                    later_epolls.push((std::sync::Arc::clone(&set), inner.to_vec()));
                    gex_kernel::file::OpenFile::new(set, path.clone(), flags, readable, writable)
                }
                other => bail!("fd {fd} ({path}): a kind of file ({other}) this build does not restore"),
            };
            objs.descs.insert(id, std::sync::Arc::clone(&file));
            file
        };
        k.fds.install(fd, file, cloexec).map_err(|er| anyhow!("fd {fd}: {er:?}"))?;
    }

    // Signals' state and credentials.
    let mut sig = r.expect(0x5349_4700, 1, "signals").map_err(|e| anyhow!("{e}"))?;
    let s = sig.bytes().map_err(|e| anyhow!("{e}"))?;
    k.signals = gex_kernel::signal::Signals::from_bytes(s).ok_or_else(|| anyhow!("the snapshot's signal state does not read back"))?;
    k.creds.restore(sig.bytes().map_err(|e| anyhow!("{e}"))?);
    for (fd, cloexec, mask, path, flags, readable, writable) in later_signalfds {
        let h = std::sync::Arc::new(gex_kernel::signalfd::SignalFd::new(mask, &k.signals));
        let f = gex_kernel::file::OpenFile::new(h, path, flags, readable, writable);
        k.fds.install(fd, f, cloexec).map_err(|er| anyhow!("fd {fd}: {er:?}"))?;
    }
    // Every descriptor is back: the epoll sets watch theirs again.
    for (set, bytes) in later_epolls {
        let fds = std::sync::Arc::clone(&k.fds);
        let file_of = move |fd: i32| fds.get(fd).ok().map(|f| std::sync::Arc::clone(&f.handle));
        set.rewatch(&mut gex_kernel::snap::R::new(&bytes), &file_of).map_err(|e| anyhow!("{e}"))?;
    }
    // A thread caught in a blocking call makes it again: its PC back
    // on the call's instruction, its registers as it made the call.
    let mut bl = r.expect(0x424c_4b00, 1, "blocked threads").map_err(|e| anyhow!("{e}"))?;
    let n = bl.len_of().map_err(|e| anyhow!("{e}"))?;
    let mut gm = gex_kernel::GuestMem::new(memory.bytes());
    for _ in 0..n {
        let c = bl.u64().map_err(|e| anyhow!("{e}"))?;
        let pc = gm.read_u64(c + gex_abi::ctx::PC as u64).map_err(|er| anyhow!("{er:?}"))?;
        // (A translated program's: a native wasm32 one marks its
        // context instead, which is not restored.)
        gex_kernel::syscalls::restart_call(&mut gm, c, pc, false).ok_or_else(|| anyhow!("a blocked thread's context at {c:#x} cannot be written"))?;
    }
    // Its threads: the same ids and slots, and each one's own signal
    // state.
    let mut th = r.expect(0x5448_5200, 1, "threads").map_err(|e| anyhow!("{e}"))?;
    k.next_ctx_slot = std::sync::Arc::new(gex_kernel::syscalls::CtxSlots::unsnap(&mut th).map_err(|e| anyhow!("{e}"))?);
    let n = th.len_of().map_err(|e| anyhow!("{e}"))?;
    k.thread_signals.clear();
    let mut threads = Vec::new();
    for _ in 0..n {
        let c = th.u64().map_err(|e| anyhow!("{e}"))?;
        let tid = th.i32().map_err(|e| anyhow!("{e}"))?;
        let sig = std::sync::Arc::new(gex_kernel::signal::ThreadSig::unsnap(&mut th).map_err(|e| anyhow!("{e}"))?);
        let t = gex_kernel::syscalls::ThreadState { ctx_addr: c, tid };
        if tid == k.pid {
            k.signals.switch_to(std::sync::Arc::clone(&sig));
            k.ctx_addr = c;
            threads.insert(0, t);
        } else {
            k.procs.adopt_tid(k.pid, tid).map_err(|er| anyhow!("thread {tid}: {er:?}"))?;
            threads.push(t);
        }
        k.thread_signals.insert(tid, sig);
    }
    if threads.first().is_none_or(|t| t.tid != k.pid) {
        bail!("pid {}: no thread of its own in the snapshot", k.pid);
    }
    k.sig_tid = k.pid;
    k.live_threads.store(n as u32, std::sync::atomic::Ordering::Release);
    // Its time: from now the guest's clocks read what they read at the
    // snapshot, so its sleeps, timers and deadlines are where they were.
    // (One clock for the whole system: taken from the first process.)
    let mut clk = r.expect(0x434c_4b00, 1, "clocks").map_err(|e| anyhow!("{e}"))?;
    if clocks {
        gex_kernel::syscalls::clocks_unsnap(&mut clk).map_err(|e| anyhow!("{e}"))?;
    }
    Ok(threads)
}

/// A snapshot's first process, in place of the program this run just
/// placed (`gexc run --restore DIR`, given the same program): its memory,
/// memory map, descriptors, signals' state, credentials and threads, from
/// what [`write`] put in `dir`. Where its thread goes on: the saved
/// context's PC (the registers came back with the memory, whose low part
/// holds the contexts). Its other threads are started by
/// [`start_restored`] and the snapshot's other processes made by
/// [`restore_children`], once the run's context exists.
pub(crate) fn apply(store: &mut wasmtime::Store<crate::HostState>, memory: &gex_mem::GuestMemory, dir: &std::path::Path) -> anyhow::Result<u64> {
    use anyhow::{anyhow, bail, Context};
    let order = std::fs::read_to_string(dir.join("order")).with_context(|| format!("--restore {}: its order", dir.display()))?;
    let mut files = Vec::new();
    for pid in order.lines().filter(|l| !l.is_empty()) {
        let path = dir.join(format!("proc-{pid}.bin"));
        let bytes = std::fs::read(&path).with_context(|| path.display().to_string())?;
        files.push((path, bytes));
    }
    if files.is_empty() {
        bail!("--restore {}: no process", dir.display());
    }
    let (_, bytes) = files.remove(0);
    let mut r = gex_kernel::snap::R::new(&bytes);
    let head = read_head(&mut r)?;
    let (pid, exe) = (head.pid, head.exe.clone());
    let mem_file = dir.join(format!("mem-{pid}.bin"));
    let state = store.data_mut();
    let ctx_addr = state.thread.ctx_addr;
    let mut objs = Objects::default();
    state.with_kernel(|k| -> anyhow::Result<()> {
        if k.exe_path != exe {
            bail!("--restore: the snapshot is of {exe}, and this run's program is {}", k.exe_path);
        }
        if k.pid != pid {
            bail!("--restore: the snapshot's first process is {pid}, and this run's is {}", k.pid);
        }
        k.procs.adopt_process(pid, head.ppid, head.pgid, head.sid).map_err(|er| anyhow!("pid {pid}: {er:?}"))?;
        objs.stdio = k.fds.entries().into_iter().filter(|(fd, _, _)| (0..3).contains(fd)).map(|(fd, f, _)| (fd, f)).collect();
        let threads = restore_into(k, memory, &mut r, &mem_file, &mut objs, true, true)?;
        if threads[0].ctx_addr != ctx_addr {
            bail!("pid {pid}: its own thread's context is at {:#x}, and this run's at {ctx_addr:#x}", threads[0].ctx_addr);
        }
        *TO_START.lock().unwrap_or_else(|e| e.into_inner()) = threads[1..].to_vec();
        Ok(())
    })?;
    *CHILDREN.lock().unwrap_or_else(|e| e.into_inner()) = (files, Some(objs));
    // Where its thread was: the saved context's PC.
    let pc = u64::from_le_bytes(memory.bytes()[(ctx_addr + gex_abi::ctx::PC as u64) as usize..][..8].try_into().unwrap());
    eprintln!("[gex] restored pid {pid} ({exe}) from {}, at {pc:#x}", dir.display());
    Ok(pc)
}

/// The snapshot's other processes, in order (a parent before its
/// children). One of the run's own program (a fork's child that has not
/// exec'd) is made as such a child of the run's would be: the run's
/// kernel's namespace, process table and translated code, a fresh memory
/// with the run's dispatch directory and runtime mappings, then what was
/// saved of it. One of another program is made as a fork's child that
/// execs it ([`crate::exec_program`]), and what was saved of it is put in
/// place of the program's start ([`apply_exec`]). Each is restored before
/// the next is begun, so what they share is made once.
pub(crate) fn restore_children(cx: &std::sync::Arc<crate::SpawnContext>) -> anyhow::Result<()> {
    use anyhow::{anyhow, bail, Context};
    let (files, objs) = std::mem::take(&mut *CHILDREN.lock().unwrap_or_else(|e| e.into_inner()));
    let Some(objs) = objs else { return Ok(()) };
    let objs = std::sync::Arc::new(std::sync::Mutex::new(objs));
    for (path, bytes) in files {
        let mut r = gex_kernel::snap::R::new(&bytes);
        let head = read_head(&mut r).with_context(|| path.display().to_string())?;
        let pid = head.pid;
        let mem_file = path.with_file_name(format!("mem-{pid}.bin"));
        let (mut child, root_vmas, same) = {
            let k = cx.kernel.lock().unwrap_or_else(|e| e.into_inner());
            k.procs.adopt_process(pid, head.ppid, head.pgid, head.sid).map_err(|er| anyhow!("pid {pid}: {er:?}"))?;
            let vmas: Vec<(u64, u64)> = k.mem.lock().vmas().iter().filter(|v| RUNTIME_MAPPINGS.contains(&v.name.as_str())).map(|v| (v.start, v.end)).collect();
            let mut child = k.fork_kernel();
            child.pid = pid;
            child.tid = pid;
            child.forget_own_pidfds();
            (child, vmas, k.exe_path == head.exe)
        };
        if !same {
            // Another program: exec'd into, on its own host thread, and
            // restored where it would start; this waits for that.
            let proc_state = std::sync::Arc::new(crate::ProcCell::default());
            child.vfs.mount_own("/proc", std::sync::Arc::new(gex_kernel::vfs::procfs::ProcFs::new(std::sync::Arc::new(crate::KernelProcSource(std::sync::Arc::clone(&proc_state))))));
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let restore = ExecRestore { bytes, mem_file, objs: std::sync::Arc::clone(&objs), done: done_tx };
            let req = crate::ExecRequest { path: head.exe.clone(), argv: head.argv.clone(), envp: head.envp.clone() };
            let opts = crate::RunOptions { args: head.argv.clone(), env: head.envp.clone(), ..cx.opts.clone() };
            let (xlate, wayland) = (cx.xlate.clone(), cx.wayland.clone());
            crate::run_child_thread(cx, pid, None, None, cx.wayland.clone(), move || {
                EXEC_RESTORE.with(|e| *e.borrow_mut() = Some(restore));
                let ran = crate::exec_program(req, &opts, &xlate, child, proc_state, wayland).map(|(exit, _)| exit);
                // Ended before it was restored: say so to whoever waits.
                if let Some(r) = EXEC_RESTORE.with(|e| e.borrow_mut().take()) {
                    let _ = r.done.send(Err(match &ran {
                        Err(e) => format!("{e:#}"),
                        Ok(_) => "it ended before it was restored".to_string(),
                    }));
                }
                ran
            })?;
            match done_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => bail!("pid {pid} ({}): {e}", head.exe),
                Err(_) => bail!("pid {pid} ({}): its thread ended before it was restored", head.exe),
            }
            continue;
        }
        let shared = wasmtime::SharedMemory::new(&cx.engine, crate::guest_memory_type()).map_err(|e| anyhow!("creating a restored process's memory: {e}"))?;
        let mem = gex_mem::GuestMemory::new(shared);
        // The run's dispatch directory and runtime mappings: the code is
        // the run's, at the same addresses, as a fork's child has it.
        {
            let (src, dst) = (cx.memory.bytes(), mem.bytes());
            let mut copy = crate::SparseCopy::new();
            let mut ranges = vec![(gex_abi::CTX_LIMIT, gex_abi::DISPATCH_DIR_END)];
            if gex_abi::mem64() {
                ranges.push((gex_abi::DISPATCH_DIR64, gex_abi::PERM_TABLE64));
            }
            ranges.extend(root_vmas);
            for (a, b) in ranges {
                let (a, b) = (a as usize, (b as usize).min(src.len()));
                if a < b {
                    copy.copy_or_share(&cx.memory, &mem, src, dst, a, b);
                }
            }
        }
        let threads = {
            let mut o = objs.lock().unwrap_or_else(|e| e.into_inner());
            restore_into(&mut child, &mem, &mut r, &mem_file, &mut o, false, false).with_context(|| format!("pid {pid}"))?
        };
        crate::publish_vm(&child, &mem);
        child.flush_perms(&mut gex_kernel::GuestMem::new(mem.bytes()));
        let main = threads[0];
        let entry = u64::from_le_bytes(mem.bytes()[(main.ctx_addr + gex_abi::ctx::PC as u64) as usize..][..8].try_into().unwrap());
        let child_cx = crate::start_child(cx, child, mem, cx.jit_shared.clone(), std::collections::HashMap::new(), main.ctx_addr, entry)?;
        for t in &threads[1..] {
            crate::start_guest_thread(std::sync::Arc::clone(&child_cx), *t)?;
        }
        eprintln!("[gex] restored pid {pid} ({}) with {} threads, at {entry:#x}", head.exe, threads.len());
    }
    Ok(())
}

/// A process of another program than the run's, to be restored in place
/// of that program's start ([`restore_children`], [`apply_exec`]): its
/// file, its memory's file, what the restore has made so far, and whom to
/// tell when it is done.
pub(crate) struct ExecRestore {
    bytes: Vec<u8>,
    mem_file: std::path::PathBuf,
    objs: std::sync::Arc<std::sync::Mutex<Objects>>,
    done: std::sync::mpsc::Sender<Result<(), String>>,
}

thread_local! {
    /// This host thread's program is to be restored ([`apply_exec`]).
    static EXEC_RESTORE: std::cell::RefCell<Option<ExecRestore>> = const { std::cell::RefCell::new(None) };
    /// Its other threads, started once its context exists
    /// ([`start_exec_restored`]).
    static EXEC_THREADS: std::cell::RefCell<Vec<gex_kernel::syscalls::ThreadState>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Whether this host thread's program is to be restored rather than
/// started.
pub(crate) fn exec_restore_pending() -> bool {
    EXEC_RESTORE.with(|e| e.borrow().is_some())
}

/// The program this host thread has just placed, given what a snapshot
/// saved of its process instead of its start: as [`apply`] does for the
/// run's own, for a process [`restore_children`] exec'd into it. Where
/// its thread goes on.
pub(crate) fn apply_exec(store: &mut wasmtime::Store<crate::HostState>, memory: &gex_mem::GuestMemory) -> anyhow::Result<u64> {
    use anyhow::{anyhow, bail};
    let er = EXEC_RESTORE.with(|e| e.borrow_mut().take()).ok_or_else(|| anyhow!("no restore was asked of this thread"))?;
    let tell = |res: Result<(), String>| {
        let _ = er.done.send(res);
    };
    let run = (|| -> anyhow::Result<u64> {
        let mut r = gex_kernel::snap::R::new(&er.bytes);
        let head = read_head(&mut r)?;
        let state = store.data_mut();
        let ctx_addr = state.thread.ctx_addr;
        state.with_kernel(|k| -> anyhow::Result<()> {
            if k.exe_path != head.exe {
                bail!("the snapshot's pid {} is of {}, and the program placed is {}", head.pid, head.exe, k.exe_path);
            }
            let mut o = er.objs.lock().unwrap_or_else(|e| e.into_inner());
            let threads = restore_into(k, memory, &mut r, &er.mem_file, &mut o, true, false)?;
            if threads[0].ctx_addr != ctx_addr {
                bail!("pid {}: its own thread's context is at {:#x}, and the program's at {ctx_addr:#x}", head.pid, threads[0].ctx_addr);
            }
            EXEC_THREADS.with(|t| *t.borrow_mut() = threads[1..].to_vec());
            Ok(())
        })?;
        let pc = u64::from_le_bytes(memory.bytes()[(ctx_addr + gex_abi::ctx::PC as u64) as usize..][..8].try_into().unwrap());
        eprintln!("[gex] restored pid {} ({}), at {pc:#x}", head.pid, head.exe);
        Ok(pc)
    })();
    tell(run.as_ref().map(|_| ()).map_err(|e| format!("{e:#}")));
    run
}

/// Start an exec-restored process's other threads ([`apply_exec`]), once
/// its context exists.
pub(crate) fn start_exec_restored(cx: &std::sync::Arc<crate::SpawnContext>) -> anyhow::Result<()> {
    let threads = EXEC_THREADS.with(|t| std::mem::take(&mut *t.borrow_mut()));
    for t in threads {
        crate::start_guest_thread(std::sync::Arc::clone(cx), t)?;
    }
    Ok(())
}
