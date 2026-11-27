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

/// Write every live process of the held system to `dir`: for each, its
/// memory map and identity (`proc-<pid>.bin`) and its memory
/// (`mem-<pid>.bin`). A summary, or what refused.
pub(crate) fn write(dir: &std::path::Path) -> Result<String, String> {
    use std::io::Write;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let procs: Vec<_> = PROCS.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(|w| w.upgrade()).collect();
    let mut said = Vec::new();
    for cx in procs {
        if cx.stopping.load(Ordering::Acquire) {
            continue;
        }
        let k = cx.kernel.lock().unwrap_or_else(|e| e.into_inner());
        let pid = k.pid;
        let mut w = gex_kernel::snap::W::new();
        w.section(0x5052_4f43, 1, |w| {
            w.i32(pid);
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
        let mut ids = gex_kernel::snap::Ids::new();
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
        // context and own signal state. The first is the one that will
        // resume as the run's own thread; it must be in slot 0.
        let threads = threads_in(&cx.memory);
        if !threads.iter().any(|&(c, _)| c == gex_abi::ctx_addr(0)) {
            return Err(format!("pid {pid}: no thread in the first slot (its first thread has ended)"));
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
    Ok(said.join("; "))
}

/// A snapshot's process, in place of the program this run just placed
/// (`gexc run --restore DIR`, given the same program): its memory, memory
/// map, descriptors, signals' state and credentials, from what [`write`]
/// put in `dir`. Where its thread goes on: the saved context's PC (the
/// registers came back with the memory, whose low part holds the
/// contexts). One process, one thread: what stage 1 of snapshots carries.
pub(crate) fn apply(store: &mut wasmtime::Store<crate::HostState>, memory: &gex_mem::GuestMemory, dir: &std::path::Path) -> anyhow::Result<u64> {
    use anyhow::{anyhow, bail, Context};
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("--restore {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("proc-") && n.ends_with(".bin")))
        .collect();
    found.sort();
    let [proc_file] = found.as_slice() else {
        bail!("--restore {}: {} processes; a restore of one is what is done", dir.display(), found.len());
    };
    let bytes = std::fs::read(proc_file).with_context(|| proc_file.display().to_string())?;
    let mut r = gex_kernel::snap::R::new(&bytes);
    let mut head = r.expect(0x5052_4f43, 1, "process").map_err(|e| anyhow!("{e}"))?;
    let pid = head.i32().map_err(|e| anyhow!("{e}"))?;
    let exe = head.str().map_err(|e| anyhow!("{e}"))?.to_string();

    let mem_file = dir.join(format!("mem-{pid}.bin"));
    let state = store.data_mut();
    let ctx_addr = state.thread.ctx_addr;
    state.with_kernel(|k| -> anyhow::Result<()> {
        if k.exe_path != exe {
            bail!("--restore: the snapshot is of {exe}, and this run's program is {}", k.exe_path);
        }
        // The fresh program's memory cleared where it or the snapshot's has
        // anything, so what the snapshot left out as zero is zero.
        let mut mm = k.mem.lock();
        let mut clear: Vec<(u64, u64)> = vec![(0, gex_abi::CTX_LIMIT)];
        clear.extend(mm.vmas().iter().filter(|v| !RUNTIME_MAPPINGS.contains(&v.name.as_str())).map(|v| (v.start, v.end)));
        mm.unsnap(&mut r).map_err(|e| anyhow!("{e}"))?;
        clear.extend(mm.vmas().iter().filter(|v| !RUNTIME_MAPPINGS.contains(&v.name.as_str())).map(|v| (v.start, v.end)));
        let bytes = memory.bytes();
        for (a, b) in clear {
            let (a, b) = (a as usize, (b as usize).min(bytes.len()));
            if a < b {
                bytes[a..b].fill(0);
            }
        }
        drop(mm);
        let f = std::fs::File::open(&mem_file).with_context(|| mem_file.display().to_string())?;
        read_memory(memory, &mut std::io::BufReader::with_capacity(1 << 20, f)).with_context(|| mem_file.display().to_string())?;

        // Descriptors: the host's streams it has already; host files
        // opened again by path, at their offsets.
        let mut fds = r.expect(gex_kernel::file::SNAP_FDS, 1, "descriptors").map_err(|e| anyhow!("{e}"))?;
        let fresh: std::collections::HashMap<i32, std::sync::Arc<gex_kernel::file::OpenFile>> = k.fds.entries().into_iter().map(|(fd, f, _)| (fd, f)).collect();
        k.fds.close_all();
        let mut descs: Vec<std::sync::Arc<gex_kernel::file::OpenFile>> = Vec::new();
        let mut later_signalfds: Vec<(i32, bool, u64, String, u64, bool, bool)> = Vec::new();
        let mut pipes: std::collections::HashMap<u32, std::sync::Arc<gex_kernel::pipe::Pipe>> = std::collections::HashMap::new();
        let mut later_epolls: Vec<(std::sync::Arc<gex_kernel::unix::EpollSet>, Vec<u8>)> = Vec::new();
        // (Each of those its own description again, where the snapshot's
        // descriptors shared one: what reads from one is the process's
        // pending signals either way.)
        let mut signalfd_descs: std::collections::HashMap<usize, (u64, String, u64, bool, bool)> = std::collections::HashMap::new();
        let n = fds.len_of().map_err(|e| anyhow!("{e}"))?;
        let e = |e: gex_kernel::snap::Refused| anyhow!("{e}");
        for _ in 0..n {
            let fd = fds.i32().map_err(e)?;
            let cloexec = fds.bool().map_err(e)?;
            let id = fds.u32().map_err(e)? as usize;
            // A signalfd's description, made later (below), named again.
            if let Some(&(mask, ref path, flags, readable, writable)) = signalfd_descs.get(&id) {
                later_signalfds.push((fd, cloexec, mask, path.clone(), flags, readable, writable));
                continue;
            }
            let file = if id < descs.len() {
                std::sync::Arc::clone(&descs[id])
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
                        fresh.get(&stream).cloned().ok_or_else(|| anyhow!("fd {fd}: this run has no standard stream {stream}"))?
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
                        signalfd_descs.insert(descs.len(), (mask, path.clone(), flags, readable, writable));
                        descs.push(gex_kernel::file::OpenFile::new(std::sync::Arc::new(gex_kernel::eventfd::EventFd::new(0, false)), String::new(), 0, false, false));
                        continue;
                    }
                    gex_kernel::snap::KIND_PIPE => {
                        let write = ir.bool().map_err(e)?;
                        let id = ir.u32().map_err(e)?;
                        let pipe = if ir.bool().map_err(e)? {
                            let p = std::sync::Arc::new(gex_kernel::pipe::Pipe::unsnap(&mut ir).map_err(e)?);
                            pipes.insert(id, std::sync::Arc::clone(&p));
                            p
                        } else {
                            std::sync::Arc::clone(pipes.get(&id).ok_or_else(|| anyhow!("fd {fd}: pipe {id} before it was written"))?)
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
                descs.push(std::sync::Arc::clone(&file));
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
            // context instead, which stage 1 does not restore.)
            gex_kernel::syscalls::restart_call(&mut gm, c, pc, false).ok_or_else(|| anyhow!("a blocked thread's context at {c:#x} cannot be written"))?;
        }
        // Its threads: the same ids and slots, and each one's own signal
        // state; the first goes on as this run's thread, the rest are
        // started once the process's context exists.
        let mut th = r.expect(0x5448_5200, 1, "threads").map_err(|e| anyhow!("{e}"))?;
        k.next_ctx_slot = std::sync::Arc::new(gex_kernel::syscalls::CtxSlots::unsnap(&mut th).map_err(|e| anyhow!("{e}"))?);
        let n = th.len_of().map_err(|e| anyhow!("{e}"))?;
        k.thread_signals.clear();
        let mut rest = Vec::new();
        for _ in 0..n {
            let c = th.u64().map_err(|e| anyhow!("{e}"))?;
            let tid = th.i32().map_err(|e| anyhow!("{e}"))?;
            let sig = std::sync::Arc::new(gex_kernel::signal::ThreadSig::unsnap(&mut th).map_err(|e| anyhow!("{e}"))?);
            if c == gex_abi::ctx_addr(0) {
                if tid != k.pid {
                    bail!("the snapshot's first thread is {tid}, and this run's process is {}", k.pid);
                }
                k.signals.switch_to(std::sync::Arc::clone(&sig));
            } else {
                k.procs.adopt_tid(k.pid, tid).map_err(|er| anyhow!("thread {tid}: {er:?}"))?;
                rest.push(gex_kernel::syscalls::ThreadState { ctx_addr: c, tid });
            }
            k.thread_signals.insert(tid, sig);
        }
        k.sig_tid = k.pid;
        k.live_threads.store(n as u32, std::sync::atomic::Ordering::Release);
        *TO_START.lock().unwrap_or_else(|e| e.into_inner()) = rest;
        // Its time: from now the guest's clocks read what they read at the
        // snapshot, so its sleeps, timers and deadlines are where they were.
        let mut clk = r.expect(0x434c_4b00, 1, "clocks").map_err(|e| anyhow!("{e}"))?;
        gex_kernel::syscalls::clocks_unsnap(&mut clk).map_err(|e| anyhow!("{e}"))?;
        Ok(())
    })?;
    // Where its thread was: the saved context's PC.
    let pc = u64::from_le_bytes(memory.bytes()[(ctx_addr + gex_abi::ctx::PC as u64) as usize..][..8].try_into().unwrap());
    eprintln!("[gex] restored pid {pid} ({exe}) from {}, at {pc:#x}", dir.display());
    Ok(pc)
}
