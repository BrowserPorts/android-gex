//! Signals.
//!
//! Delivery works because of the tail-call design: every host call flushes the
//! guest's registers to the thread context first, so at any syscall or safepoint
//! the architectural state is complete and a handler frame can be built from it.
//! Resuming is just re-entering translated code at a different PC -- there is no
//! wasm stack to unwind.
//!
//! Returning from a handler: a libc that sets `SA_RESTORER` returns to its own
//! trampoline, which issues `rt_sigreturn`. Otherwise the return address is
//! [`SIGRETURN_TRAMPOLINE`], a reserved address with no translation, so
//! branching to it lands in the dispatch-miss handler, which restores the frame.

use crate::errno::Errno;
use crate::GuestMem;
use gex_abi::ctx;
use crate::sync::{Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

/// Signal numbers.
pub mod sig {
    pub const SIGHUP: u32 = 1;
    pub const SIGINT: u32 = 2;
    pub const SIGQUIT: u32 = 3;
    pub const SIGILL: u32 = 4;
    pub const SIGTRAP: u32 = 5;
    pub const SIGABRT: u32 = 6;
    pub const SIGBUS: u32 = 7;
    pub const SIGFPE: u32 = 8;
    pub const SIGKILL: u32 = 9;
    pub const SIGUSR1: u32 = 10;
    pub const SIGSEGV: u32 = 11;
    pub const SIGUSR2: u32 = 12;
    pub const SIGPIPE: u32 = 13;
    pub const SIGALRM: u32 = 14;
    pub const SIGTERM: u32 = 15;
    pub const SIGCHLD: u32 = 17;
    pub const SIGCONT: u32 = 18;
    pub const SIGSTOP: u32 = 19;
    pub const SIGTSTP: u32 = 20;
    pub const SIGVTALRM: u32 = 26;
    pub const SIGPROF: u32 = 27;
    pub const SIGWINCH: u32 = 28;
    pub const SIGSYS: u32 = 31;
    /// Signals 1..=64 exist; 0 is "no signal".
    pub const MAX: u32 = 64;
}

/// `sa_flags` bits.
pub mod sa {
    pub const NOCLDSTOP: u64 = 0x0000_0001;
    pub const NOCLDWAIT: u64 = 0x0000_0002;
    pub const SIGINFO: u64 = 0x0000_0004;
    pub const RESTORER: u64 = 0x0400_0000;
    pub const ONSTACK: u64 = 0x0800_0000;
    pub const RESTART: u64 = 0x1000_0000;
    pub const NODEFER: u64 = 0x4000_0000;
    pub const RESETHAND: u64 = 0x8000_0000;
}

/// `SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// Return address installed when the guest supplies no `sa_restorer`. In the
/// reserved region and deliberately without a translation, so returning to it
/// reaches the dispatch-miss handler.
pub const SIGRETURN_TRAMPOLINE: u64 = gex_abi::RESERVED_END - 16;

/// What the kernel should do when a signal has no handler.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DefaultAction {
    /// Terminate the process.
    Terminate,
    /// Terminate and note that a core would have been written.
    Core,
    /// Discard the signal.
    Ignore,
    /// Stop the process.
    Stop,
    /// Continue a stopped process.
    Continue,
}

/// The default disposition of a signal.
pub fn default_action(signal: u32) -> DefaultAction {
    match signal {
        sig::SIGCHLD | sig::SIGCONT | sig::SIGWINCH | 29 => DefaultAction::Ignore,
        sig::SIGSTOP | sig::SIGTSTP | 21 | 22 => DefaultAction::Stop,
        sig::SIGQUIT
        | sig::SIGILL
        | sig::SIGTRAP
        | sig::SIGABRT
        | sig::SIGBUS
        | sig::SIGFPE
        | sig::SIGSEGV
        | sig::SIGSYS => DefaultAction::Core,
        _ => DefaultAction::Terminate,
    }
}

/// One installed disposition.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// An alternate signal stack.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

/// What the caller should do after the kernel considered a pending signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Nothing to deliver; carry on.
    None,
    /// A handler frame is set up; resume translated code at this address.
    Resume(u64),
    /// No handler, and the default disposition ends the process.
    Terminate { signal: u32, core: bool },
}

/// Slots in a per-signal table: index 0 is unused, as in a `sigset_t`.
const NSIG: usize = sig::MAX as usize + 1;

/// One armed interval timer.
///
/// Times are absolute nanoseconds on the same clock the guest reads, because
/// a deadline compared against a clock that can be replaced per host has to
/// be in that clock's terms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Itimer {
    /// When it next fires.
    pub next: u128,
    /// What to reload on firing. Zero is a one-shot timer, which disarms.
    pub interval: u128,
}

/// No timer armed, in [`ProcSig`]'s `timer_next`.
const NO_TIMER: u64 = u64::MAX;

/// The process's part of the signal state, shared by its threads and read
/// without the kernel lock: dispositions behind
/// an `RwLock`, the process-directed pending set as one atomic word (with
/// its senders behind a `Mutex`), and the interval timers, whose earliest
/// deadline is an atomic word so asking "is one due" takes no lock.
pub struct ProcSig {
    actions: RwLock<[SigAction; NSIG]>,
    /// Process-directed signals (another process's `kill`, a timer, a
    /// child's exit): any thread that does not block one may take it. A
    /// thread's own (`tgkill`, faults) are its [`ThreadSig`]'s. Linux keeps
    /// the two sets apart the same way.
    shared: AtomicU64,
    shared_sources: Mutex<[Option<Source>; NSIG]>,
    /// The interval timers, indexed by `which`.
    timers: Mutex<[Option<Itimer>; 3]>,
    /// The POSIX timers ([`crate::ptimer`]). Taken after `timers` where
    /// both are held.
    posix: Mutex<crate::ptimer::Timers>,
    /// The earliest armed timer's deadline, clamped to `u64`; [`NO_TIMER`]
    /// when none is armed. Written under `timers`.
    timer_next: AtomicU64,
    /// Held across a [`ProcSig::collect`]'s take of the inbox and its
    /// raise, so a collect that finds the inbox empty because another is
    /// under way waits for that one's signals to be pending.
    collecting: Mutex<()>,
    /// The signal a delivery last found fatal (no handler), who sent it,
    /// and whether it was the thread's own: the death report's "sent by".
    /// Written once per process at most, just before it dies.
    fatal: Mutex<Option<(u32, Option<Source>, bool)>>,
    /// The last fault signal (SEGV, BUS, ILL, FPE) a delivery gave a
    /// handler, with its sender: a handler that re-raises it (KCrash) dies
    /// of a signal whose first sending this says. Rare, so a lock.
    handled: Mutex<Option<(u32, Option<Source>, bool)>>,
    /// The last fault signal one of this process's threads sent with
    /// `kill`, `tkill` or `tgkill`: sending thread, target (pid; 0 for a
    /// thread of this process), target thread (0 for `kill`), signal. What
    /// says which thread of a process sent its own death.
    fault_send: Mutex<Option<(i32, i32, i32, u32)>>,
    /// What the process has set with `prctl`: flags of its address space
    /// and its `signal_struct`.
    prctl: Mutex<crate::prctl::Proc>,
    /// The auxiliary vector the program was started with, zero after its
    /// end (Linux's `mm->saved_auxv`, which `PR_GET_AUXV` reads).
    saved_auxv: Mutex<[u8; crate::prctl::SAVED_AUXV_BYTES]>,
    /// A stop signal a delivery found with its default action, for the host
    /// to stop the process with ([`Signals::take_stop`]); 0 for none.
    stop: AtomicU32,
}

/// Whether a stop signal's default action stops the process
/// ([`enable_job_control`]). Otherwise `SIGSTOP` ends it and the three a
/// terminal raises do nothing, for a host that cannot hold a stopped
/// process's threads.
static JOB_CONTROL: AtomicBool = AtomicBool::new(false);

/// How many processes have a stop for their host to take
/// ([`Signals::take_stop`]), so a host's safepoint asks only when some do.
static STOPS_ASKED: AtomicU32 = AtomicU32::new(0);

/// A host that parks a stopped process's threads (the native one) turns
/// stops on: a stop signal with its default action then stops the process
/// ([`Signals::take_stop`], [`crate::proc::ProcTable::stop`]).
pub fn enable_job_control() {
    JOB_CONTROL.store(true, Ordering::Release);
}

/// Whether stops are on ([`enable_job_control`]).
pub fn job_control() -> bool {
    JOB_CONTROL.load(Ordering::Acquire)
}

/// Whether any process has a stop for its host to take.
pub fn stops_asked() -> bool {
    STOPS_ASKED.load(Ordering::Acquire) != 0
}

impl std::fmt::Debug for ProcSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcSig")
            .field("shared", &format_args!("{:#x}", self.shared.load(Ordering::Relaxed)))
            .field("timer_next", &self.timer_next.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ProcSig {
    fn with_actions(actions: [SigAction; NSIG]) -> ProcSig {
        ProcSig {
            actions: RwLock::new(actions),
            shared: AtomicU64::new(0),
            shared_sources: Mutex::new([None; NSIG]),
            timers: Mutex::new([None; 3]),
            posix: Mutex::new(crate::ptimer::Timers::default()),
            collecting: Mutex::new(()),
            timer_next: AtomicU64::new(NO_TIMER),
            fatal: Mutex::new(None),
            handled: Mutex::new(None),
            fault_send: Mutex::new(None),
            prctl: Mutex::new(crate::prctl::Proc::default()),
            saved_auxv: Mutex::new([0; crate::prctl::SAVED_AUXV_BYTES]),
            stop: AtomicU32::new(0),
        }
    }

    /// The saved auxiliary vector, all of its fixed size.
    pub fn saved_auxv(&self) -> [u8; crate::prctl::SAVED_AUXV_BYTES] {
        *self.saved_auxv.lock()
    }

    /// Keep the auxiliary vector a new program's stack was given
    /// (`create_elf_tables`): `auxv` as written there, `AT_NULL` included.
    pub fn set_saved_auxv(&self, auxv: &[u8]) {
        let mut saved = [0; crate::prctl::SAVED_AUXV_BYTES];
        let n = auxv.len().min(saved.len());
        saved[..n].copy_from_slice(&auxv[..n]);
        *self.saved_auxv.lock() = saved;
    }

    /// What the process has set with `prctl` ([`crate::prctl::Proc`]).
    pub fn prctl(&self) -> crate::prctl::Proc {
        *self.prctl.lock()
    }

    pub fn update_prctl(&self, f: impl FnOnce(&mut crate::prctl::Proc)) {
        f(&mut self.prctl.lock())
    }

    /// The signal a delivery found fatal, its sender and whether it was the
    /// thread's own ([`dispatch`]); `None` when none was.
    pub fn fatal(&self) -> Option<(u32, Option<Source>, bool)> {
        *self.fatal.lock()
    }

    /// A synchronous fault given to a handler (no sender: the instruction).
    pub fn note_fault_handled(&self, signal: u32) {
        *self.handled.lock() = Some((signal, None, true));
    }

    /// A fault signal (SEGV, BUS, ILL, FPE) one of this process's threads
    /// sent; any other is not kept.
    pub fn note_send(&self, from_tid: i32, pid: i32, tid: i32, signal: u32) {
        if matches!(signal, sig::SIGSEGV | sig::SIGBUS | sig::SIGILL | sig::SIGFPE) {
            *self.fault_send.lock() = Some((from_tid, pid, tid, signal));
        }
    }

    /// The last fault signal this process sent ([`ProcSig::note_send`]).
    pub fn fault_send(&self) -> Option<(i32, i32, i32, u32)> {
        *self.fault_send.lock()
    }

    /// The last fault signal a handler was given, and its sender.
    pub fn handled_fault(&self) -> Option<(u32, Option<Source>, bool)> {
        *self.handled.lock()
    }

    /// Mark a process-directed signal pending: whichever thread does not
    /// block it takes it.
    pub fn raise(&self, signal: u32, source: Option<Source>) {
        if signal > 0 && signal <= sig::MAX {
            self.shared_sources.lock()[signal as usize] = source;
            self.shared.fetch_or(bit(signal), Ordering::AcqRel);
        }
    }

    /// The process-directed pending set.
    pub fn shared(&self) -> u64 {
        self.shared.load(Ordering::Acquire)
    }

    pub fn action(&self, signal: u32) -> SigAction {
        self.actions.read()[(signal as usize).min(sig::MAX as usize)]
    }

    /// Whether a signal that would do something is ready for a thread whose
    /// own pending set and mask are `pending` and `blocked`, counting this
    /// process's shared set. An ignored one, or one whose default is to be
    /// ignored, does not count: see [`Signals::would_deliver`].
    pub fn would_deliver_with(&self, pending: u64, blocked: u64) -> bool {
        let mut ready = (pending | self.shared()) & !blocked;
        if ready == 0 {
            return false;
        }
        let actions = self.actions.read();
        while ready != 0 {
            let signal = ready.trailing_zeros() + 1;
            ready &= ready - 1;
            let action = actions[signal as usize];
            if action.handler == SIG_IGN {
                continue;
            }
            if action.handler == SIG_DFL && default_action(signal) == DefaultAction::Ignore {
                continue;
            }
            return true;
        }
        false
    }

    /// Interval timer `which`.
    pub fn timer(&self, which: usize) -> Option<Itimer> {
        self.timers.lock().get(which).copied().flatten()
    }

    /// Arm or disarm interval timer `which`.
    pub fn set_timer(&self, which: usize, t: Option<Itimer>) {
        let mut timers = self.timers.lock();
        if let Some(slot) = timers.get_mut(which) {
            *slot = t;
        }
        let posix = self.posix.lock();
        self.timer_next.store(earliest(&timers, &posix), Ordering::Release);
    }

    /// Work on the POSIX timers; their earliest deadline is taken again
    /// after.
    pub fn with_posix<R>(&self, f: impl FnOnce(&mut crate::ptimer::Timers) -> R) -> R {
        let timers = self.timers.lock();
        let mut posix = self.posix.lock();
        let r = f(&mut posix);
        self.timer_next.store(earliest(&timers, &posix), Ordering::Release);
        r
    }

    /// Whether POSIX timer `id`'s signal is still queued (not delivered).
    pub fn timer_queued(&self, id: i32) -> bool {
        let posix = self.posix.lock();
        let Some(t) = posix.list.iter().find(|t| t.id == id) else { return false };
        t.queued && self.timer_still_queued(t, t.overrun)
    }

    /// Whether a timer's signal is still queued to its target, and if so
    /// its siginfo made to say `overrun` (Linux's `si_overrun` is read at
    /// delivery, so a queued signal carries the overruns since queued).
    fn timer_still_queued(&self, t: &crate::ptimer::Timer, overrun: i32) -> bool {
        use crate::ptimer::Notify;
        let (signo, pending, sources) = match &t.notify {
            Notify::None => return false,
            Notify::Process(s) => (*s, self.shared(), &self.shared_sources),
            Notify::Thread(s, w) => {
                let Some(th) = w.upgrade() else { return false };
                if th.pending() & bit(*s) == 0 {
                    return false;
                }
                let mut src = th.sources.lock();
                return match &mut src[*s as usize] {
                    Some(x) if x.code == crate::ptimer::SI_TIMER && x.pid == t.id => {
                        x.uid = overrun as u32;
                        true
                    }
                    _ => false,
                };
            }
        };
        if pending & bit(signo) == 0 {
            return false;
        }
        let mut src = sources.lock();
        match &mut src[signo as usize] {
            Some(x) if x.code == crate::ptimer::SI_TIMER && x.pid == t.id => {
                x.uid = overrun as u32;
                true
            }
            _ => false,
        }
    }

    /// Whether any interval timer is armed.
    pub fn timers_armed(&self) -> bool {
        self.timer_next.load(Ordering::Acquire) != NO_TIMER
    }

    /// Whether an interval timer has expired at `now` and has yet to raise
    /// its signal.
    pub fn timer_due(&self, now: u128) -> bool {
        let next = self.timer_next.load(Ordering::Acquire);
        next != NO_TIMER && now >= next as u128
    }

    /// How long from `now` until the next interval timer fires, if one is
    /// armed.
    pub fn timer_in_ns(&self, now: u128) -> Option<u64> {
        let next = self.timer_next.load(Ordering::Acquire);
        (next != NO_TIMER).then(|| (next as u128).saturating_sub(now).min(u64::MAX as u128) as u64)
    }

    /// Fire any timer whose deadline has passed at `now`, and reload it if
    /// it repeats.
    ///
    /// `ITIMER_VIRTUAL`/`ITIMER_PROF` should count CPU time but are driven
    /// from the same wall clock as the rest.
    pub fn fire_timers(&self, now: u128) {
        if !self.timer_due(now) {
            return;
        }
        let mut timers = self.timers.lock();
        let mut posix = self.posix.lock();
        // The POSIX timers: each due one's expiries since it was last seen.
        for i in 0..posix.list.len() {
            let Some(next) = posix.list[i].next else { continue };
            if now < next {
                continue;
            }
            let t = &mut posix.list[i];
            let expiries = if t.interval == 0 { 1 } else { (now - next) / t.interval + 1 };
            t.next = (t.interval > 0).then(|| next + expiries * t.interval);
            let expiries = expiries.min(i32::MAX as u128) as i32;
            if t.queued {
                let overrun = t.overrun.saturating_add(expiries);
                if self.timer_still_queued(&posix.list[i], overrun) {
                    posix.list[i].overrun = overrun;
                    continue;
                }
                // Its last signal was delivered with what it carried.
                let t = &mut posix.list[i];
                t.overrun_last = t.overrun;
            }
            let t = &mut posix.list[i];
            t.overrun = expiries - 1;
            t.queued = !matches!(t.notify, crate::ptimer::Notify::None);
            let source = Source { code: crate::ptimer::SI_TIMER, pid: t.id, uid: t.overrun as u32, value: t.value, errno: 0 };
            match &t.notify {
                crate::ptimer::Notify::None => {}
                crate::ptimer::Notify::Process(s) => self.raise(*s, Some(source)),
                crate::ptimer::Notify::Thread(s, w) => {
                    if let Some(th) = w.upgrade() {
                        th.raise(*s, Some(source));
                    }
                }
            }
        }
        for which in 0..3 {
            let Some(timer) = timers[which] else {
                continue;
            };
            if now < timer.next {
                continue;
            }
            timers[which] = if timer.interval == 0 {
                None
            } else {
                // Skip whole missed periods rather than firing once per
                // period afterwards: a guest that was away for a second with
                // a millisecond timer does not want a thousand signals.
                let missed = (now - timer.next) / timer.interval + 1;
                Some(Itimer {
                    next: timer.next + missed * timer.interval,
                    interval: timer.interval,
                })
            };
            self.raise(
                match which {
                    1 => sig::SIGVTALRM,
                    2 => sig::SIGPROF,
                    _ => sig::SIGALRM,
                },
                None,
            );
        }
        self.timer_next.store(earliest(&timers, &posix), Ordering::Release);
    }

    /// Move signals other processes have sent this one (`pid`) into its
    /// shared pending set, with who sent each that `kill` sent. Returns what
    /// arrived.
    ///
    /// `kill` cannot reach into another process's kernel -- each has its own
    /// -- so it leaves the signal on a shared per-process word and the target
    /// picks it up here. This is what makes `timeout`, job control and every
    /// supervisor work.
    ///
    /// One step to any other collector of this process: a `kill` to its own
    /// process that finds its signal already taken by another thread's
    /// collect waits here until that collect has raised it, so the signal
    /// is pending when the `kill` returns (a `sigtimedwait` after it found
    /// nothing, one time in a few hundred, in the page).
    pub fn collect(&self, procs: &crate::proc::ProcTable, pid: i32, uid: u32) -> u64 {
        let _one = self.collecting.lock();
        let inbox = procs.take_signals(pid);
        if inbox == 0 {
            return 0;
        }
        // Each signal raised once, with its sender: raised twice, a thread
        // delivering between the two (without the kernel lock) would see it
        // pending again after taking it.
        let mut sources = [None; NSIG];
        for (signo, pid) in procs.take_kill_senders(pid, inbox) {
            if let Some(slot) = sources.get_mut(signo as usize) {
                *slot = Some(Source { code: SI_USER, pid, uid, value: 0, errno: 0 });
            }
        }
        // A child's end, with which child and how it ended.
        let mut inbox = inbox;
        if inbox & (1u64 << (sig::SIGCHLD - 1)) != 0 && sources[sig::SIGCHLD as usize].is_none() {
            sources[sig::SIGCHLD as usize] = procs.take_child_end(pid);
            // A child's stop or continue raises no SIGCHLD for a parent that
            // asked for none (`SA_NOCLDSTOP`, `do_notify_parent_cldstop`).
            if sources[sig::SIGCHLD as usize].is_some_and(|s| matches!(s.code, 5 | 6)) && self.action(sig::SIGCHLD).flags & sa::NOCLDSTOP != 0 {
                inbox &= !(1u64 << (sig::SIGCHLD - 1));
            }
        }
        for signo in 1..=64u32 {
            if inbox & (1u64 << (signo - 1)) != 0 {
                self.raise(signo, sources[signo as usize]);
            }
        }
        inbox
    }
}

fn earliest(timers: &[Option<Itimer>; 3], posix: &crate::ptimer::Timers) -> u64 {
    timers
        .iter()
        .flatten()
        .map(|t| t.next)
        .chain(posix.earliest())
        .map(|n| n.min(NO_TIMER as u128 - 1) as u64)
        .min()
        .unwrap_or(NO_TIMER)
}

/// The handler state of one thread that only that thread reads or writes:
/// its alternate stack and what the frame it is in looks like.
#[derive(Copy, Clone, Debug, Default)]
pub struct Own {
    pub alt_stack: SigAltStack,
    /// Set while a handler runs, so `rt_sigreturn` knows a frame exists.
    pub in_handler: bool,
    /// The i386 frame most recently set up was the non-rt `sigframe` (a
    /// handler without `SA_SIGINFO`), whose `sigreturn` reads a different
    /// layout. Decided where the frame is written, because the return may
    /// arrive through the host trampoline as well as through `int 0x80`.
    pub legacy_frame: bool,
    /// The mask a signal frame should record instead of the current one.
    ///
    /// `rt_sigsuspend` runs with a caller-chosen mask and must restore the old
    /// one *after* the handler returns; the frame carries the mask across. So
    /// suspend leaves the old mask here, `setup_frame` writes it into the frame,
    /// and `sigreturn` restores it -- without it the woken signal stays blocked
    /// and pending forever (`timeout` spun 2.2 million times).
    pub suspend_restore: Option<u64>,
}

/// Every thread's own signal state in a process, by tid, behind its own
/// lock: what a `tgkill` to a thread of the same process raises on,
/// whether its sender holds the kernel or not. Shared (`Arc`) between the
/// process's kernel and its host's lock-free calls; a fork's is new. A leaf
/// lock: nothing is called with it held.
#[derive(Default)]
pub struct ThreadSigs(Mutex<std::collections::HashMap<i32, Arc<ThreadSig>>>);

impl ThreadSigs {
    pub fn get(&self, tid: i32) -> Option<Arc<ThreadSig>> {
        self.0.lock().get(&tid).cloned()
    }

    pub fn contains(&self, tid: i32) -> bool {
        self.0.lock().contains_key(&tid)
    }

    pub fn insert(&self, tid: i32, t: Arc<ThreadSig>) {
        self.0.lock().insert(tid, t);
    }

    /// `tid`'s, made by `make` if it has none yet.
    pub fn get_or_insert_with(&self, tid: i32, make: impl FnOnce() -> Arc<ThreadSig>) -> Arc<ThreadSig> {
        Arc::clone(self.0.lock().entry(tid).or_insert_with(make))
    }

    pub fn remove(&self, tid: i32) {
        self.0.lock().remove(&tid);
    }

    pub fn clear(&self) {
        self.0.lock().clear();
    }

    /// The tids it holds, as it holds them now.
    pub fn tids(&self) -> Vec<i32> {
        self.0.lock().keys().copied().collect()
    }
}

/// One thread's signal state, shared (`Arc`) between the thread and whoever
/// sends it a signal or asks whether it has one ready. Its pending set and
/// mask are atomic words
/// any thread reads without a lock; only the thread itself writes the mask
/// and [`Own`].
pub struct ThreadSig {
    /// Signals raised for this thread alone (`tgkill`, faults) and not yet
    /// delivered.
    pending: AtomicU64,
    /// Signals the thread has blocked.
    blocked: AtomicU64,
    /// Who sent each pending signal, when a process did (`kill`, `tgkill`):
    /// what its siginfo reports instead of `SI_KERNEL`. `None` for one the
    /// kernel raised itself.
    sources: Mutex<[Option<Source>; NSIG]>,
    own: Mutex<Own>,
    /// Where the thread's exit writes zero and futex-wakes (what
    /// `pthread_join` waits on): `CLONE_CHILD_CLEARTID`'s word, or
    /// `set_tid_address`'s. Zero for none.
    clear_child_tid: AtomicU64,
    /// AArch64's tagged address ABI (`TIF_TAGGED_ADDR`): the thread asked,
    /// with `prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE)`, for the
    /// kernel to take tagged pointers in its system calls. Inherited on
    /// `clone` and `fork` and cleared on `execve`
    /// (Documentation/arch/arm64/tagged-address-abi.rst).
    tagged_addr: AtomicBool,
    /// What the thread has set about itself with `prctl`
    /// ([`crate::prctl::Task`]).
    prctl: Mutex<crate::prctl::Task>,
    /// Its seccomp mode, which every system call reads, and its mode and
    /// filters together ([`crate::seccomp::State`]). Inherited on `clone`
    /// and `fork`, kept across `execve`.
    seccomp_mode: AtomicU8,
    seccomp: Mutex<crate::seccomp::State>,
}

impl std::fmt::Debug for ThreadSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadSig")
            .field("pending", &format_args!("{:#x}", self.pending()))
            .field("blocked", &format_args!("{:#x}", self.blocked()))
            .finish_non_exhaustive()
    }
}

impl ThreadSig {
    /// This thread's own signal state written for a snapshot
    /// ([`crate::snap`]): pending and blocked sets, who sent each pending
    /// signal, the alternate stack and handler state, `clear_child_tid`,
    /// the tagged address ABI, `prctl`'s per-thread settings and seccomp.
    pub fn snap(&self, w: &mut crate::snap::W) {
        w.u64(self.pending());
        w.u64(self.blocked());
        let given: Vec<(usize, Source)> = self.sources.lock().iter().enumerate().filter_map(|(i, s)| s.map(|s| (i, s))).collect();
        w.len_of(given.len());
        for (i, s) in given {
            w.len_of(i);
            w.i32(s.code);
            w.i32(s.pid);
            w.u32(s.uid);
            w.u64(s.value);
            w.i32(s.errno);
        }
        {
            let own = self.own.lock();
            w.u64(own.alt_stack.sp);
            w.u32(own.alt_stack.flags);
            w.u64(own.alt_stack.size);
            w.bool(own.in_handler);
            w.bool(own.legacy_frame);
            w.opt(own.suspend_restore, |w, m| w.u64(m));
        }
        w.u64(self.clear_child_tid.load(Ordering::Acquire));
        w.bool(self.tagged_addr.load(Ordering::Acquire));
        let t = *self.prctl.lock();
        w.u64(t.timer_slack_ns);
        w.u64(t.default_timer_slack_ns);
        w.bool(t.no_new_privs);
        w.u8(t.mce);
        w.bool(t.io_flusher);
        w.u8(t.pdeathsig);
        w.u8(self.seccomp_mode());
        w.bytes(&self.seccomp.lock().to_bytes());
    }

    /// A thread's signal state as [`ThreadSig::snap`] wrote it.
    pub fn unsnap(r: &mut crate::snap::R<'_>) -> Result<ThreadSig, crate::snap::Refused> {
        let t = ThreadSig::new_thread(0);
        t.pending.store(r.u64()?, Ordering::Release);
        t.blocked.store(r.u64()?, Ordering::Release);
        let n = r.len_of()?;
        {
            let mut sources = t.sources.lock();
            for _ in 0..n {
                let i = r.len_of()?;
                let s = Source { code: r.i32()?, pid: r.i32()?, uid: r.u32()?, value: r.u64()?, errno: r.i32()? };
                *sources.get_mut(i).ok_or_else(|| crate::snap::Refused::new(format!("a sender of signal {i}, past the last")))? = Some(s);
            }
        }
        {
            let mut own = t.own.lock();
            own.alt_stack = SigAltStack { sp: r.u64()?, flags: r.u32()?, size: r.u64()? };
            own.in_handler = r.bool()?;
            own.legacy_frame = r.bool()?;
            own.suspend_restore = r.opt(|r| r.u64())?;
        }
        t.clear_child_tid.store(r.u64()?, Ordering::Release);
        t.tagged_addr.store(r.bool()?, Ordering::Release);
        {
            let mut p = t.prctl.lock();
            p.timer_slack_ns = r.u64()?;
            p.default_timer_slack_ns = r.u64()?;
            p.no_new_privs = r.bool()?;
            p.mce = r.u8()?;
            p.io_flusher = r.bool()?;
            p.pdeathsig = r.u8()?;
        }
        t.seccomp_mode.store(r.u8()?, Ordering::Release);
        let sc = r.bytes()?;
        *t.seccomp.lock() = crate::seccomp::State::from_bytes(sc).ok_or_else(|| crate::snap::Refused::new("a thread's seccomp state that does not read back"))?;
        Ok(t)
    }

    /// A new thread's: its creator's mask, nothing pending, no alternate
    /// stack (a thread sets its own), not in a handler.
    pub fn new_thread(blocked: u64) -> ThreadSig {
        ThreadSig {
            pending: AtomicU64::new(0),
            blocked: AtomicU64::new(blocked),
            sources: Mutex::new([None; NSIG]),
            own: Mutex::new(Own::default()),
            clear_child_tid: AtomicU64::new(0),
            tagged_addr: AtomicBool::new(false),
            prctl: Mutex::new(crate::prctl::Task::default()),
            seccomp_mode: AtomicU8::new(crate::seccomp::MODE_DISABLED),
            seccomp: Mutex::new(crate::seccomp::State::default()),
        }
    }

    /// Its seccomp mode (`SECCOMP_MODE_*`), without a lock.
    pub fn seccomp_mode(&self) -> u8 {
        self.seccomp_mode.load(Ordering::Acquire)
    }

    /// Its seccomp mode and filters.
    pub fn seccomp(&self) -> crate::seccomp::State {
        self.seccomp.lock().clone()
    }

    /// Set them: the thread itself, or `SECCOMP_FILTER_FLAG_TSYNC` from
    /// another of its process's threads.
    pub fn set_seccomp(&self, s: crate::seccomp::State) {
        let mode = s.mode;
        *self.seccomp.lock() = s;
        self.seccomp_mode.store(mode, Ordering::Release);
    }

    /// What the thread has set with `prctl`.
    pub fn prctl(&self) -> crate::prctl::Task {
        *self.prctl.lock()
    }

    pub fn update_prctl(&self, f: impl FnOnce(&mut crate::prctl::Task)) {
        f(&mut self.prctl.lock())
    }

    /// What a thread or a forked child this one makes starts with of the
    /// state no `ThreadSig::new_thread` argument carries: the tagged
    /// address ABI and the `prctl` settings ([`crate::prctl::Task::child`]).
    pub fn inherit(&self, creator: &ThreadSig) {
        self.set_tagged_addr(creator.tagged_addr());
        *self.prctl.lock() = creator.prctl().child();
        self.set_seccomp(creator.seccomp());
    }

    /// Whether the thread has the tagged address ABI on
    /// ([`Self::set_tagged_addr`]).
    pub fn tagged_addr(&self) -> bool {
        self.tagged_addr.load(Ordering::Acquire)
    }

    /// `PR_SET_TAGGED_ADDR_CTRL`, or what a new thread or a forked child
    /// takes from its creator.
    pub fn set_tagged_addr(&self, on: bool) {
        self.tagged_addr.store(on, Ordering::Release);
    }

    /// The word the thread's exit clears ([`Self::set_clear_child_tid`]).
    pub fn clear_child_tid(&self) -> u64 {
        self.clear_child_tid.load(Ordering::Acquire)
    }

    /// `set_tid_address`, or `CLONE_CHILD_CLEARTID` at its start: the word
    /// the thread's exit clears. Only the thread itself, or its creator
    /// before it runs, sets it.
    pub fn set_clear_child_tid(&self, addr: u64) {
        self.clear_child_tid.store(addr, Ordering::Release);
    }

    /// Mark a signal pending for this thread, sent by `source` (`None`: the
    /// kernel raised it). A standard signal does not queue, so the last
    /// sender is the one reported.
    pub fn raise(&self, signal: u32, source: Option<Source>) {
        if signal > 0 && signal <= sig::MAX {
            self.sources.lock()[signal as usize] = source;
            self.pending.fetch_or(bit(signal), Ordering::AcqRel);
        }
    }

    /// Mark a thread-directed signal pending, as sent by a process
    /// (`tgkill` to another thread).
    pub fn raise_from(&self, signal: u32, source: Source) {
        self.raise(signal, Some(source));
    }

    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    pub fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::Acquire)
    }

    /// Whether a signal that would do something is ready for this thread,
    /// counting its process's shared set ([`ProcSig::would_deliver_with`]).
    /// Takes no lock unless an unblocked signal is pending.
    pub fn ready(&self, process: &ProcSig) -> bool {
        process.would_deliver_with(self.pending(), self.blocked())
    }
}

/// The calling thread's mask and [`Own`] state, copied out to be read and
/// changed by a frame being built or unwound, and stored back when dropped.
/// Only the thread itself writes them, so the copy cannot go stale.
pub struct OwnView<'a> {
    thread: &'a ThreadSig,
    pub blocked: u64,
    pub alt_stack: SigAltStack,
    pub in_handler: bool,
    pub legacy_frame: bool,
    pub suspend_restore: Option<u64>,
}

impl Drop for OwnView<'_> {
    fn drop(&mut self) {
        self.thread.blocked.store(self.blocked, Ordering::Release);
        *self.thread.own.lock() = Own {
            alt_stack: self.alt_stack,
            in_handler: self.in_handler,
            legacy_frame: self.legacy_frame,
            suspend_restore: self.suspend_restore,
        };
    }
}

/// A process's signal state as one thread sees it: the process's
/// [`ProcSig`] and the running thread's [`ThreadSig`]. Which thread is
/// running is a pointer to swap ([`Signals::switch_to`]), not state to copy
/// in and out.
#[derive(Debug)]
pub struct Signals {
    proc: Arc<ProcSig>,
    cur: Arc<ThreadSig>,
}

impl Default for Signals {
    fn default() -> Self {
        Self::new()
    }
}

impl Signals {
    pub fn new() -> Signals {
        Signals {
            proc: Arc::new(ProcSig::with_actions([SigAction::default(); NSIG])),
            cur: Arc::new(ThreadSig::new_thread(0)),
        }
    }

    /// The process's part.
    pub fn process(&self) -> &Arc<ProcSig> {
        &self.proc
    }

    /// The running thread's part.
    pub fn thread(&self) -> &Arc<ThreadSig> {
        &self.cur
    }

    /// Make `t` the running thread's part.
    pub fn switch_to(&mut self, t: Arc<ThreadSig>) {
        self.cur = t;
    }

    /// The signal state a forked child starts with.
    ///
    /// Dispositions, the blocked mask and the alternate stack are inherited;
    /// the pending set is not, nor are the timers, and neither is a handler
    /// frame -- the child begins between instructions, not inside a handler.
    pub fn fork(&self) -> Signals {
        let cur = ThreadSig::new_thread(self.blocked());
        cur.own.lock().alt_stack = self.alt_stack();
        cur.inherit(&self.cur);
        let proc = ProcSig::with_actions(*self.proc.actions.read());
        *proc.prctl.lock() = self.proc.prctl().fork();
        // The child's address space is a copy, its saved vector with it.
        *proc.saved_auxv.lock() = self.proc.saved_auxv();
        Signals { proc: Arc::new(proc), cur: Arc::new(cur) }
    }

    /// Keep a new program's auxiliary vector ([`ProcSig::set_saved_auxv`]).
    pub fn set_saved_auxv(&self, auxv: &[u8]) {
        self.proc.set_saved_auxv(auxv);
    }

    /// The signal state after `execve`.
    ///
    /// A handler is an address in the old image, so every caught signal reverts
    /// to default -- otherwise the new program inherits the address of a handler
    /// that no longer exists (`timeout 3 sleep 30` would jump into dash's old
    /// handler). Ignored stays ignored, the blocked mask and pending signals
    /// carry over, per POSIX; the alternate stack does not -- it too pointed into
    /// the old image.
    pub fn exec(&self) {
        for action in self.proc.actions.write().iter_mut() {
            if action.handler != SIG_DFL && action.handler != SIG_IGN {
                *action = SigAction::default();
            }
        }
        // `flush_thread` -> `flush_tagged_addr_state`: the new program
        // starts without the tagged address ABI.
        self.cur.set_tagged_addr(false);
        // `exit_itimers`: the POSIX timers go (the interval timers stay).
        self.proc.with_posix(|t| t.clear());
        // A new address space ([`crate::prctl::Proc::exec`]). What the
        // thread set about itself stays.
        let after = self.proc.prctl().exec();
        *self.proc.prctl.lock() = after;
        let mut own = self.cur.own.lock();
        own.alt_stack = SigAltStack::default();
        own.in_handler = false;
        own.suspend_restore = None;
        // The word was in the old image: Linux forgets it (`mm_release`).
        self.cur.set_clear_child_tid(0);
    }

    pub fn action(&self, signal: u32) -> SigAction {
        self.proc.action(signal)
    }

    pub fn set_action(&self, signal: u32, action: SigAction) -> Result<(), Errno> {
        // SIGKILL and SIGSTOP cannot be caught or ignored.
        if signal == 0 || signal > sig::MAX || signal == sig::SIGKILL || signal == sig::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        // Nor blocked, by a handler's mask either (Linux strips them).
        let mut action = action;
        action.mask &= !(bit(sig::SIGKILL) | bit(sig::SIGSTOP));
        self.proc.actions.write()[signal as usize] = action;
        Ok(())
    }

    /// The running thread's mask.
    pub fn blocked(&self) -> u64 {
        self.cur.blocked()
    }

    /// Set the running thread's mask.
    pub fn set_blocked(&self, mask: u64) {
        self.cur.blocked.store(mask, Ordering::Release);
    }

    pub fn alt_stack(&self) -> SigAltStack {
        self.cur.own.lock().alt_stack
    }

    pub fn set_alt_stack(&self, a: SigAltStack) {
        self.cur.own.lock().alt_stack = a;
    }

    /// Whether the running thread is in a handler.
    pub fn in_handler(&self) -> bool {
        self.cur.own.lock().in_handler
    }

    /// Leave `mask` for the next frame to record (`rt_sigsuspend`); see
    /// [`Own::suspend_restore`].
    pub fn set_suspend_restore(&self, mask: Option<u64>) {
        self.cur.own.lock().suspend_restore = mask;
    }

    pub fn take_suspend_restore(&self) -> Option<u64> {
        self.cur.own.lock().suspend_restore.take()
    }

    /// The running thread's mask and handler state, to change and store
    /// back on drop.
    pub fn own(&self) -> OwnView<'_> {
        let own = *self.cur.own.lock();
        OwnView {
            thread: &self.cur,
            blocked: self.cur.blocked(),
            alt_stack: own.alt_stack,
            in_handler: own.in_handler,
            legacy_frame: own.legacy_frame,
            suspend_restore: own.suspend_restore,
        }
    }

    /// Mark a process-directed signal pending: whichever thread does not
    /// block it takes it.
    pub fn raise_shared(&self, signal: u32, source: Option<Source>) {
        self.proc.raise(signal, source);
    }

    /// Mark a signal pending, as the kernel raising it itself (`SI_KERNEL`).
    pub fn raise(&self, signal: u32) {
        self.cur.raise(signal, None);
    }

    /// Mark a signal pending, as sent by a process: `kill` (`SI_USER`) or
    /// `tkill`/`tgkill` (`SI_TKILL`). A standard signal does not queue, so the
    /// last sender is the one reported.
    pub fn raise_from(&self, signal: u32, source: Source) {
        self.cur.raise(signal, Some(source));
    }

    /// Clear `signal` as delivered or taken: the thread's own first, else
    /// the process's.
    pub fn clear_pending(&self, signal: u32) {
        let b = bit(signal);
        if self.cur.pending.fetch_and(!b, Ordering::AcqRel) & b == 0 {
            self.proc.shared.fetch_and(!b, Ordering::AcqRel);
        }
    }

    /// Take `signal` off the pending sets to deliver it, with who sent it:
    /// the thread's own first, else the process's. `None` when it is no
    /// longer pending, because another thread took it first.
    pub fn claim(&self, signal: u32) -> Option<Option<Source>> {
        let b = bit(signal);
        let i = (signal as usize).min(sig::MAX as usize);
        if self.cur.pending.fetch_and(!b, Ordering::AcqRel) & b != 0 {
            return Some(self.cur.sources.lock()[i].take());
        }
        if self.proc.shared.fetch_and(!b, Ordering::AcqRel) & b != 0 {
            return Some(self.proc.shared_sources.lock()[i].take());
        }
        None
    }

    /// A process's signal state as thread `cur` sees it: for a host that
    /// delivers to its own thread without the kernel.
    pub fn view(proc: Arc<ProcSig>, cur: Arc<ThreadSig>) -> Signals {
        Signals { proc, cur }
    }

    /// Forget who sent `signal`: a synchronous fault reports itself, whatever
    /// a process may also have sent.
    pub fn forget_source(&self, signal: u32) {
        if signal > 0 && signal <= sig::MAX {
            self.cur.sources.lock()[signal as usize] = None;
        }
    }

    /// Take who sent `signal`, as its delivery reports it.
    pub fn take_source(&self, signal: u32) -> Option<Source> {
        let i = (signal as usize).min(sig::MAX as usize);
        if self.cur.pending() & bit(signal) != 0 {
            self.cur.sources.lock()[i].take()
        } else {
            self.proc.shared_sources.lock()[i].take()
        }
    }

    /// Take the lowest-numbered pending signal in `set`, blocked or not,
    /// with who sent it ([`Signals::claim`]: the thread's own first).
    ///
    /// `sigwaitinfo` is used precisely on signals the caller has blocked, so
    /// this deliberately ignores the mask [`Signals::next_deliverable`] respects.
    /// It claims rather than clearing and then asking for the sender: cleared
    /// first, a thread-directed signal's sender was looked for on the
    /// process's set, and a `tgkill` taken by `sigtimedwait` said `SI_KERNEL`.
    pub fn claim_in(&self, set: u64) -> Option<(u32, Option<Source>)> {
        loop {
            // The thread's own before its process's, the lowest number
            // first in each (`dequeue_signal`).
            let own = self.cur.pending() & set;
            let ready = if own != 0 { own } else { self.proc.shared() & set };
            if ready == 0 {
                return None;
            }
            let signal = ready.trailing_zeros() + 1;
            // Another thread took it between the look and the claim: the
            // next one, if any.
            if let Some(source) = self.claim(signal) {
                return Some((signal, source));
            }
        }
    }

    /// Everything raised, deliverable or not. For diagnostics only.
    pub fn pending_raw(&self) -> u64 {
        self.cur.pending() | self.proc.shared()
    }

    /// Thread `t`'s pending signals with this process's shared set.
    pub fn pending_raw_for(&self, t: &ThreadSig) -> u64 {
        t.pending() | self.proc.shared()
    }

    pub fn has_pending(&self) -> bool {
        self.pending_raw() & !self.blocked() != 0
    }

    /// Whether a pending signal would actually *do* something -- a handler, or a
    /// non-`Ignore` default. `has_pending` only asks whether an unblocked bit is
    /// set, which is wrong for ending a wait: `SIGCHLD` is ignored by default and
    /// arrives on every child exit, and would otherwise interrupt a shell's wait
    /// for nothing.
    pub fn would_deliver(&self) -> bool {
        self.cur.ready(&self.proc)
    }

    /// The stop signal a delivery asked its host to stop the process with
    /// ([`dispatch`]), taken: the host stops it ([`crate::proc::ProcTable::stop`]).
    /// `None` too when a `SIGCONT` has come since and waits to be
    /// delivered: the stop is cancelled, as `prepare_signal` clears a stop
    /// pending when a `SIGCONT` is sent (a `SIGCONT` sent before the stop
    /// signal would have been delivered first, being the lower number).
    pub fn take_stop(&self) -> Option<u32> {
        let s = self.proc.stop.swap(0, Ordering::AcqRel);
        if s == 0 {
            return None;
        }
        STOPS_ASKED.fetch_sub(1, Ordering::AcqRel);
        let pending = self.cur.pending() | self.proc.shared.load(Ordering::Acquire);
        (pending & bit(sig::SIGCONT) == 0).then_some(s)
    }

    /// Whether `SIGKILL` is pending for this thread or its process: what
    /// ends a stop no other signal ends.
    pub fn kill_pending(&self) -> bool {
        (self.cur.pending() | self.proc.shared.load(Ordering::Acquire)) & bit(sig::SIGKILL) != 0
    }

    /// [`Self::would_deliver`] for a thread whose own pending set and mask
    /// are `pending` and `blocked` (with this process's dispositions and
    /// shared set).
    pub fn would_deliver_with(&self, pending: u64, blocked: u64) -> bool {
        self.proc.would_deliver_with(pending, blocked)
    }

    /// [`Self::next_deliverable`], for a trace.
    pub fn peek_deliverable(&self) -> Option<u32> {
        self.next_deliverable()
    }

    /// Whether a call of restart class `class`, its wait ended by a signal,
    /// starts again (from its instruction, as the guest made it) rather than
    /// answering `EINTR`: Linux's `-ERESTARTSYS`, `-ERESTARTNOINTR` and
    /// `-ERESTARTNOHAND` (signal(7), "Interruption of system calls"). The
    /// signal is the one about to be delivered: a handler installed with
    /// `SA_RESTART` restarts an [`Restart::SaRestart`] call, any handler ends
    /// an [`Restart::NoHandler`] one, and with no handler to run (a default
    /// that ends the process, or nothing deliverable after all) every class
    /// but [`Restart::Never`] restarts.
    pub fn restarts(&self, class: Restart) -> bool {
        if class == Restart::Never {
            return false;
        }
        if class == Restart::Always {
            return true;
        }
        let Some(signal) = self.next_deliverable() else { return true };
        let action = self.action(signal);
        if action.handler == SIG_IGN || action.handler == SIG_DFL {
            return true;
        }
        class == Restart::SaRestart && action.flags & sa::RESTART != 0
    }

    /// The lowest-numbered deliverable signal, if any.
    fn next_deliverable(&self) -> Option<u32> {
        let ready = self.pending_raw() & !self.blocked();
        if ready == 0 {
            return None;
        }
        Some(ready.trailing_zeros() + 1)
    }

    /// The running thread's signal state as bytes, for another Worker to
    /// rebuild with [`Signals::from_bytes`]: the dispositions, the mask and
    /// the alternate stack, which is what a `fork` child inherits
    /// ([`Signals::fork`]), and with `pending` the pending sets too, which
    /// an `execve` keeps. Who sent each pending signal is not kept, nor are
    /// the timers.
    pub fn to_bytes(&self, pending: bool) -> Vec<u8> {
        let mut v = Vec::with_capacity(STATE_BYTES);
        for a in self.proc.actions.read().iter() {
            for w in [a.handler, a.flags, a.restorer, a.mask] {
                v.extend_from_slice(&w.to_le_bytes());
            }
        }
        let alt = self.alt_stack();
        let (mine, shared) = if pending { (self.cur.pending(), self.proc.shared()) } else { (0, 0) };
        // The `prctl` settings and the tagged address ABI as they are: a
        // fork child's are its parent's, and an `execve` changes its own
        // ([`Signals::exec`], which the new program's kernel runs).
        let (task, proc) = (self.cur.prctl(), self.proc.prctl());
        let task = if pending { task } else { task.child() };
        let proc = if pending { proc } else { proc.fork() };
        let flags = task.flags() << 1 | self.cur.tagged_addr() as u64;
        for w in [self.blocked(), alt.sp, alt.flags as u64, alt.size, mine, shared, task.timer_slack_ns, task.default_timer_slack_ns, flags, proc.word()] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        // The saved auxiliary vector: a fork child's is its parent's, and a
        // new program's is set when its stack is built.
        v.extend_from_slice(&self.proc.saved_auxv());
        // Then seccomp, which a fork child and a new program both keep.
        v.extend_from_slice(&self.cur.seccomp().to_bytes());
        v
    }

    /// A process's signal state from [`Signals::to_bytes`], or `None` for
    /// bytes that are not one.
    pub fn from_bytes(b: &[u8]) -> Option<Signals> {
        if b.len() < STATE_BYTES {
            return None;
        }
        let seccomp = crate::seccomp::State::from_bytes(&b[STATE_BYTES..])?;
        let b = &b[..STATE_BYTES];
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        let mut actions = [SigAction::default(); NSIG];
        for (i, a) in actions.iter_mut().enumerate() {
            *a = SigAction { handler: w(i * 4), flags: w(i * 4 + 1), restorer: w(i * 4 + 2), mask: w(i * 4 + 3) };
        }
        let o = NSIG * 4;
        let cur = ThreadSig::new_thread(w(o));
        cur.own.lock().alt_stack = SigAltStack { sp: w(o + 1), flags: w(o + 2) as u32, size: w(o + 3) };
        cur.pending.store(w(o + 4), Ordering::Release);
        cur.set_tagged_addr(w(o + 8) & 1 != 0);
        *cur.prctl.lock() = crate::prctl::Task::from_words(w(o + 6), w(o + 7), w(o + 8) >> 1);
        cur.set_seccomp(seccomp);
        let proc = ProcSig::with_actions(actions);
        proc.shared.store(w(o + 5), Ordering::Release);
        *proc.prctl.lock() = crate::prctl::Proc::from_word(w(o + 9));
        proc.set_saved_auxv(&b[(o + 10) * 8..]);
        Some(Signals { proc: Arc::new(proc), cur: Arc::new(cur) })
    }
}

/// How a blocking call a signal interrupts ends ([`Signals::restarts`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Restart {
    /// `EINTR`, handler or not: a wait with a timeout the caller chose
    /// (`poll`, `select`, `epoll_wait`, `nanosleep`, a timed futex wait,
    /// `sigsuspend`). Linux restarts some of these when no handler runs, but
    /// such a signal never ends a wait here.
    #[default]
    Never,
    /// Restarted after a handler with `SA_RESTART`, and when no handler
    /// runs; `EINTR` after any other handler (`-ERESTARTSYS`): `read`,
    /// `write`, `wait4`, `accept`, an untimed futex wait.
    SaRestart,
    /// Restarted after a handler too (`-ERESTARTNOINTR`): `FUTEX_LOCK_PI`.
    Always,
}

/// The length of [`Signals::to_bytes`]: four words a disposition, then the
/// mask, the alternate stack's three, the two pending sets, and four for
/// the `prctl` settings and the tagged address ABI; then the saved
/// auxiliary vector.
const STATE_BYTES: usize = (NSIG * 4 + 10) * 8 + crate::prctl::SAVED_AUXV_BYTES;

/// A process that sent a signal, for its siginfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// `si_code`: [`SI_USER`], [`SI_TKILL`], or what `rt_sigqueueinfo`'s
    /// caller put there (`sigqueue`'s `SI_QUEUE`).
    pub code: i32,
    pub pid: i32,
    pub uid: u32,
    /// `si_value`, which `sigqueue` sends with the signal; zero otherwise.
    /// For seccomp's `SIGSYS` (`SYS_SECCOMP`) the three fields are its
    /// `_sigsys` instead ([`Source::seccomp`]).
    pub value: u64,
    /// `si_errno`: what `rt_sigqueueinfo`'s caller put there, or the data
    /// of the seccomp filter's answer.
    pub errno: i32,
}

/// `si_code` of seccomp's `SIGSYS`.
pub const SYS_SECCOMP: i32 = 1;

impl Source {
    /// `force_sig_seccomp`'s siginfo, kept in the sender's fields: the
    /// call's address in `pid` and `uid` (low and high halves), its
    /// number and architecture in `value` ([`Source::sigsys`]).
    pub fn seccomp(call_addr: u64, syscall: i32, arch: u32, errno: u32) -> Source {
        Source { code: SYS_SECCOMP, pid: call_addr as i32, uid: (call_addr >> 32) as u32, value: (arch as u64) << 32 | syscall as u32 as u64, errno: errno as i32 }
    }

    /// The call's address, number and architecture, for seccomp's
    /// `SIGSYS` ([`Source::seccomp`]).
    pub fn sigsys(&self, signal: u32) -> Option<(u64, u32, u32)> {
        (signal == sig::SIGSYS && self.code == SYS_SECCOMP).then(|| (self.pid as u32 as u64 | (self.uid as u64) << 32, self.value as u32, (self.value >> 32) as u32))
    }
}

/// `si_code` for a signal sent by `kill`.
pub const SI_USER: i32 = 0;
/// `si_code` for a signal sent by `tkill` or `tgkill`.
pub const SI_TKILL: i32 = -6;

/// Bit for a signal in a `sigset_t`. Signal 1 is bit 0.
fn bit(signal: u32) -> u64 {
    if signal == 0 || signal > 64 {
        0
    } else {
        1u64 << (signal - 1)
    }
}

/// Byte offsets inside the aarch64 signal frame the kernel builds.
///
/// The layout is `struct rt_sigframe`: a `siginfo_t` followed by a
/// `ucontext`, whose `uc_mcontext` is a `sigcontext`. Every offset here is
/// fixed ABI that libc unwinders and `longjmp` implementations read directly.
pub mod frame {
    /// `siginfo_t` occupies the first 128 bytes.
    pub const SIGINFO: usize = 0;
    pub const SIGINFO_SIZE: usize = 128;
    /// The `ucontext` follows it.
    pub const UCONTEXT: usize = SIGINFO_SIZE;
    /// Fields within the ucontext.
    pub const UC_FLAGS: usize = 0;
    pub const UC_LINK: usize = 8;
    pub const UC_STACK: usize = 16;
    pub const UC_SIGMASK: usize = 40;
    /// `uc_mcontext`, after the 128-byte signal mask.
    pub const UC_MCONTEXT: usize = 176;
    /// Fields within the `sigcontext`.
    pub const MC_FAULT_ADDRESS: usize = 0;
    pub const MC_REGS: usize = 8;
    pub const MC_SP: usize = 8 + 31 * 8;
    pub const MC_PC: usize = MC_SP + 8;
    pub const MC_PSTATE: usize = MC_PC + 8;
    /// `__reserved[4096]`: records, each a magic and its size, to one whose
    /// magic is zero. `fpsimd_context` first (FPSR, FPCR and V0-V31 after
    /// its head), then `esr_context` (the syndrome) for a fault that has
    /// one (arch/arm64/include/uapi/asm/sigcontext.h).
    /// (Aligned to sixteen bytes in the structure, which puts eight unused
    /// ones after `pstate`.)
    pub const MC_RESERVED: usize = (MC_PSTATE + 8 + 15) & !15;
    pub const RESERVED_SIZE: usize = 4096;
    pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
    pub const FPSIMD_SIZE: u32 = 16 + 32 * 16;
    pub const ESR_MAGIC: u32 = 0x4553_5201;
    pub const ESR_SIZE: u32 = 16;
    pub const SIGCONTEXT_SIZE: usize = MC_RESERVED + RESERVED_SIZE;
    pub const UCONTEXT_SIZE: usize = UC_MCONTEXT + SIGCONTEXT_SIZE;
    pub const FRAME_SIZE: usize = UCONTEXT + UCONTEXT_SIZE;
}

/// Byte offsets inside the x86-64 `struct rt_sigframe`.
///
/// The return address the handler `ret`s through comes first, then the
/// `ucontext` (whose `uc_mcontext` is a `struct sigcontext` of 23 words in
/// the architecture's fixed order), then the `siginfo`. The FP state is a
/// separate 512-byte `fxsave` area above the frame that `uc_mcontext.fpstate`
/// points to. Fixed ABI: libc's unwinders and `swapcontext` read it.
pub mod xframe {
    pub const PRETCODE: usize = 0;
    pub const UCONTEXT: usize = 8;
    pub const UC_FLAGS: usize = 0;
    pub const UC_LINK: usize = 8;
    pub const UC_STACK: usize = 16;
    pub const UC_MCONTEXT: usize = 40;
    /// `sigcontext` words: r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp,
    /// rip, eflags, then cs/gs/fs/ss packed, err, trapno, oldmask, cr2,
    /// fpstate pointer, and reserved space.
    pub const MC_R8: usize = 0;
    pub const MC_RDI: usize = 64;
    pub const MC_RSI: usize = 72;
    pub const MC_RBP: usize = 80;
    pub const MC_RBX: usize = 88;
    pub const MC_RDX: usize = 96;
    pub const MC_RAX: usize = 104;
    pub const MC_RCX: usize = 112;
    pub const MC_RSP: usize = 120;
    pub const MC_RIP: usize = 128;
    pub const MC_EFLAGS: usize = 136;
    pub const MC_CS: usize = 144;
    pub const MC_ERR: usize = 152;
    pub const MC_TRAPNO: usize = 160;
    pub const MC_OLDMASK: usize = 168;
    pub const MC_CR2: usize = 176;
    pub const MC_FPSTATE: usize = 184;
    pub const SIGCONTEXT_SIZE: usize = 256;
    pub const UC_SIGMASK: usize = UC_MCONTEXT + SIGCONTEXT_SIZE;
    pub const UCONTEXT_SIZE: usize = UC_SIGMASK + 8;
    pub const SIGINFO: usize = UCONTEXT + UCONTEXT_SIZE;
    pub const SIGINFO_SIZE: usize = 128;
    pub const FRAME_SIZE: usize = SIGINFO + SIGINFO_SIZE;
    /// The `fxsave` image.
    pub const FPSTATE_SIZE: usize = 512;
    /// The System V red zone below `rsp` a signal frame must not touch.
    pub const RED_ZONE: u64 = 128;
    /// `struct sigcontext` register order as gex GPR numbers.
    pub const GPR_ORDER: [u8; 16] = [8, 9, 10, 11, 12, 13, 14, 15, 7, 6, 5, 3, 2, 0, 1, 4];
}

/// A fault signal's name, for a line that says one was taken.
pub fn fault_name(signo: u32) -> &'static str {
    match signo {
        sig::SIGSEGV => "SIGSEGV",
        sig::SIGBUS => "SIGBUS",
        sig::SIGILL => "SIGILL",
        sig::SIGFPE => "SIGFPE",
        _ => "a fault signal",
    }
}

/// Build a handler frame for `signal` and point the context at the handler.
///
/// Returns the address to resume at. The caller has already established that
/// a handler is installed.
pub fn setup_frame(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    signal: u32,
    fault_address: u64,
    compat: bool,
) -> Result<u64, Errno> {
    build_frame(signals, m, ctx_addr, signal, fault_address, compat, Taken::Fault(None))
}

/// What a synchronous fault's frame says of it beyond its signal and
/// address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// `si_code`, where it is not the one the signal usually has
    /// ([`fault_code`]): a protection fault's `SEGV_ACCERR`.
    pub code: u32,
    /// AArch64: the exception syndrome (`ESR_EL1`), which the frame carries
    /// as an `esr_context` record for a fault that has one.
    pub esr: Option<u64>,
    /// What the context's `fault_address` holds, where it is not the
    /// address the siginfo reports.
    pub context_address: Option<u64>,
}

impl Fault {
    /// A data abort from the program, as an AArch64 processor reports it: a
    /// load's or a store's (`write`), with Linux's `si_code` for it. The
    /// syndrome is a data abort from a lower exception level's (class 0x24,
    /// a 32-bit instruction), write-not-read as it was, at the last level
    /// of the page tables (where Linux's 4 KiB pages are): a permission
    /// fault when the page is `there`, mapped for the processor with some
    /// access that is not this one, else a translation fault -- nothing
    /// mapped, or a page that allows nothing, which has no valid entry.
    /// (A page is taken to have been touched: one never touched has no
    /// entry yet either, and its first refused store is a translation
    /// fault on hardware.)
    pub fn data_abort(code: u32, write: bool, there: bool) -> Fault {
        let status = if there { 0x0f } else { 0x07 };
        Fault { code, esr: Some(0x24 << 26 | 1 << 25 | (write as u64) << 6 | status), context_address: None }
    }

    /// An instruction abort from the program: a branch to an address
    /// nothing is mapped at, or whose page may not be run. Class 0x20, and
    /// the status as a data abort's ([`Fault::data_abort`]).
    pub fn instruction_abort(code: u32, there: bool) -> Fault {
        let status = if there { 0x0f } else { 0x07 };
        Fault { code, esr: Some(0x20 << 26 | 1 << 25 | status), context_address: None }
    }

    /// A branch to an address that is no multiple of four: SIGBUS with
    /// `BUS_ADRALN`, a PC alignment fault (class 0x22). The siginfo has the
    /// address; the context's `fault_address` is 0, as `arm64_notify_die`
    /// leaves it.
    pub fn pc_alignment() -> Fault {
        Fault { code: BUS_ADRALN, esr: Some(0x22 << 26 | 1 << 25), context_address: Some(0) }
    }
}

/// [`setup_frame`] with more of the fault given ([`Fault`]).
pub fn setup_frame_fault(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    signal: u32,
    fault: Fault,
    fault_address: u64,
    compat: bool,
) -> Result<u64, Errno> {
    build_frame(signals, m, ctx_addr, signal, fault_address, compat, Taken::Fault(Some(fault)))
}

/// `si_code` for an address that is not aligned as its use needs.
pub const BUS_ADRALN: u32 = 1;
/// `BUS_ADRERR`: a nonexistent physical address, which is how a missing
/// page of a `userfaultfd` range that asked for `SIGBUS` is reported.
pub const BUS_ADRERR: u32 = 2;
/// `si_code` for a fault at an address nothing is mapped at.
pub const SEGV_MAPERR: u32 = 1;
/// `si_code` for a fault at a page whose protection refuses the access.
pub const SEGV_ACCERR: u32 = 2;

/// Whose a signal a frame is built for is, and who sent it.
#[derive(Clone, Copy, Debug)]
enum Taken {
    /// A synchronous fault, raised by the running instruction: its siginfo
    /// reports the fault (as this says, or with the signal's usual
    /// `si_code`), and whatever is pending of it is cleared once the frame
    /// is built.
    Fault(Option<Fault>),
    /// A pending signal [`Signals::claim`] already took off the pending
    /// sets, with its sender.
    Claimed(Option<Source>),
}

fn build_frame(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    signal: u32,
    fault_address: u64,
    compat: bool,
    taken: Taken,
) -> Result<u64, Errno> {
    if compat {
        return setup_frame_i386(signals, m, ctx_addr, signal, fault_address, taken);
    }
    if gex_abi::X86 {
        return setup_frame_x86(signals, m, ctx_addr, signal, fault_address, taken);
    }
    let action = signals.action(signal);
    let sp = m.read_u64(ctx_addr + ctx::SP as u64)?;

    // An `SA_ONSTACK` handler runs on the alternate stack, but only if one is
    // installed and we are not already on it.
    let mut own = signals.own();
    let base = if action.flags & sa::ONSTACK != 0 && own.alt_stack.size > 0 {
        let alt = &own.alt_stack;
        let top = alt.sp + alt.size;
        if sp > alt.sp && sp <= top {
            sp
        } else {
            top
        }
    } else {
        sp
    };

    // The frame sits below the current stack pointer, 16-byte aligned.
    let frame_addr = (base - frame::FRAME_SIZE as u64) & !0xf;
    m.zero(frame_addr, frame::FRAME_SIZE)?;

    // siginfo: si_signo, si_errno, si_code, then the fault address for the
    // synchronous signals, which is what a crash handler reads.
    write_siginfo(signals, m, frame_addr, signal, fault_address, true, taken)?;

    let uc = frame_addr + frame::UCONTEXT as u64;
    m.write_u64(uc + frame::UC_FLAGS as u64, 0)?;
    m.write_u64(uc + frame::UC_LINK as u64, 0)?;
    // uc_stack describes the stack the handler is running on.
    m.write_u64(uc + frame::UC_STACK as u64, own.alt_stack.sp)?;
    m.write_u32(uc + frame::UC_STACK as u64 + 8, own.alt_stack.flags)?;
    m.write_u64(uc + frame::UC_STACK as u64 + 16, own.alt_stack.size)?;
    // The mask to restore on return is the one in force right now.
    m.write_u64(
        uc + frame::UC_SIGMASK as u64,
        own.suspend_restore.take().unwrap_or(own.blocked),
    )?;

    // The machine context: every general register, sp, pc and pstate, taken
    // from the thread context, which a host call has already made complete.
    let mc = uc + frame::UC_MCONTEXT as u64;
    let context_address = match taken {
        Taken::Fault(Some(Fault { context_address: Some(a), .. })) => a,
        _ => fault_address,
    };
    m.write_u64(mc + frame::MC_FAULT_ADDRESS as u64, context_address)?;
    for i in 0..31u8 {
        let v = m.read_u64(ctx_addr + ctx::x(i) as u64)?;
        m.write_u64(mc + frame::MC_REGS as u64 + i as u64 * 8, v)?;
    }
    m.write_u64(mc + frame::MC_SP as u64, sp)?;
    let pc = m.read_u64(ctx_addr + ctx::PC as u64)?;
    m.write_u64(mc + frame::MC_PC as u64, pc)?;
    m.write_u64(mc + frame::MC_PSTATE as u64, read_pstate(m, ctx_addr)?)?;

    // The records: the FP and vector state the handler may use and
    // `sigreturn` restores, then the fault's syndrome. The frame was zeroed,
    // which is the record that ends them.
    let mut rec = mc + frame::MC_RESERVED as u64;
    m.write_u32(rec, frame::FPSIMD_MAGIC)?;
    m.write_u32(rec + 4, frame::FPSIMD_SIZE)?;
    m.write_u32(rec + 8, m.read_u32(ctx_addr + ctx::FPSR as u64)?)?;
    m.write_u32(rec + 12, m.read_u32(ctx_addr + ctx::FPCR as u64)?)?;
    let vregs = m.read(ctx_addr + ctx::V as u64, 32 * 16)?.to_vec();
    m.write(rec + 16, &vregs)?;
    rec += frame::FPSIMD_SIZE as u64;
    if let Taken::Fault(Some(Fault { esr: Some(esr), .. })) = taken {
        m.write_u32(rec, frame::ESR_MAGIC)?;
        m.write_u32(rec + 4, frame::ESR_SIZE)?;
        m.write_u64(rec + 8, esr)?;
    }

    // Block this signal for the duration of the handler unless asked not to,
    // plus whatever the action's mask names.
    own.blocked |= action.mask;
    if action.flags & sa::NODEFER == 0 {
        own.blocked |= bit(signal);
    }
    if let Taken::Fault(_) = taken {
        signals.clear_pending(signal);
    }
    own.in_handler = true;

    // A one-shot handler reverts before it runs, as `SA_RESETHAND` requires.
    if action.flags & sa::RESETHAND != 0 {
        let _ = signals.set_action(signal, SigAction::default());
    }

    // Hand the handler its arguments and a way back.
    m.write_u64(ctx_addr + ctx::SP as u64, frame_addr)?;
    m.write_u64(ctx_addr + ctx::x(0) as u64, signal as u64)?;
    m.write_u64(ctx_addr + ctx::x(1) as u64, frame_addr)?;
    m.write_u64(ctx_addr + ctx::x(2) as u64, uc)?;
    let ret = if action.flags & sa::RESTORER != 0 && action.restorer != 0 {
        action.restorer
    } else {
        SIGRETURN_TRAMPOLINE
    };
    m.write_u64(ctx_addr + ctx::x(30) as u64, ret)?;
    m.write_u64(ctx_addr + ctx::PC as u64, action.handler)?;
    Ok(action.handler)
}

/// The x86-64 frame builder. See [`xframe`] for the layout.
fn setup_frame_x86(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    signal: u32,
    fault_address: u64,
    taken: Taken,
) -> Result<u64, Errno> {
    let action = signals.action(signal);
    let sp = m.read_u64(ctx_addr + ctx::SP as u64)?;

    let mut own = signals.own();
    let on_alt = action.flags & sa::ONSTACK != 0 && own.alt_stack.size > 0;
    let base = if on_alt {
        let alt = &own.alt_stack;
        let top = alt.sp + alt.size;
        if sp > alt.sp && sp <= top {
            sp
        } else {
            top
        }
    } else {
        // Leave the red zone below the interrupted code's stack pointer.
        sp - xframe::RED_ZONE
    };

    // The FP state above the frame, 64-byte aligned; the frame below it so
    // that `rsp + 8` is 16-byte aligned on handler entry, as after a `call`.
    let fpstate = (base - xframe::FPSTATE_SIZE as u64) & !63;
    let frame_addr = ((fpstate - xframe::FRAME_SIZE as u64) & !0xf) - 8;
    m.zero(frame_addr, xframe::FRAME_SIZE)?;
    m.zero(fpstate, xframe::FPSTATE_SIZE)?;

    // The handler's return address: the libc restorer (glibc always sets one
    // on x86-64), else the untranslated trampoline the host recognises.
    let ret = if action.flags & sa::RESTORER != 0 && action.restorer != 0 {
        action.restorer
    } else {
        SIGRETURN_TRAMPOLINE
    };
    m.write_u64(frame_addr + xframe::PRETCODE as u64, ret)?;

    let info = frame_addr + xframe::SIGINFO as u64;
    write_siginfo(signals, m, info, signal, fault_address, true, taken)?;

    let uc = frame_addr + xframe::UCONTEXT as u64;
    m.write_u64(uc + xframe::UC_FLAGS as u64, 0)?;
    m.write_u64(uc + xframe::UC_LINK as u64, 0)?;
    m.write_u64(uc + xframe::UC_STACK as u64, own.alt_stack.sp)?;
    m.write_u32(uc + xframe::UC_STACK as u64 + 8, own.alt_stack.flags)?;
    m.write_u64(uc + xframe::UC_STACK as u64 + 16, own.alt_stack.size)?;
    let saved_mask = own.suspend_restore.take().unwrap_or(own.blocked);
    m.write_u64(uc + xframe::UC_SIGMASK as u64, saved_mask)?;

    let mc = uc + xframe::UC_MCONTEXT as u64;
    for (i, reg) in xframe::GPR_ORDER.iter().enumerate() {
        let v = m.read_u64(ctx_addr + ctx::x(*reg) as u64)?;
        m.write_u64(mc + i as u64 * 8, v)?;
    }
    let pc = m.read_u64(ctx_addr + ctx::PC as u64)?;
    m.write_u64(mc + xframe::MC_RIP as u64, pc)?;
    m.write_u64(mc + xframe::MC_EFLAGS as u64, read_rflags(m, ctx_addr)?)?;
    // cs: the interrupted code's (__USER_CS, 0x33, or __USER32_CS, 0x23,
    // for a WoW64 thread's 32-bit code), the other selectors zero.
    let cs = m.read_u32(ctx_addr + ctx::CS as u64)?;
    m.write_u64(mc + xframe::MC_CS as u64, if cs == 0 { ctx::CS_LONG as u64 } else { cs as u64 })?;
    m.write_u64(mc + xframe::MC_TRAPNO as u64, if signal == sig::SIGSEGV { 14 } else { 0 })?;
    m.write_u64(mc + xframe::MC_OLDMASK as u64, saved_mask)?;
    m.write_u64(mc + xframe::MC_CR2 as u64, fault_address)?;
    m.write_u64(mc + xframe::MC_FPSTATE as u64, fpstate)?;

    // The fxsave image: control words, MXCSR, and the sixteen xmm registers.
    m.write_u32(fpstate, m.read_u32(ctx_addr + ctx::X87_CW as u64)? & 0xffff)?;
    m.write_u32(fpstate + 24, m.read_u32(ctx_addr + ctx::MXCSR as u64)?)?;
    m.write_u32(fpstate + 28, 0xffff)?;
    for n in 0..16u8 {
        for half in 0..2u64 {
            let v = m.read_u64(ctx_addr + ctx::v(n) as u64 + half * 8)?;
            m.write_u64(fpstate + 160 + n as u64 * 16 + half * 8, v)?;
        }
    }

    own.blocked |= action.mask;
    if action.flags & sa::NODEFER == 0 {
        own.blocked |= bit(signal);
    }
    if let Taken::Fault(_) = taken {
        signals.clear_pending(signal);
    }
    own.in_handler = true;
    if action.flags & sa::RESETHAND != 0 {
        let _ = signals.set_action(signal, SigAction::default());
    }

    // rsp = frame, rdi = signo, rsi = &info, rdx = &uc, rax = 0.
    m.write_u64(ctx_addr + ctx::SP as u64, frame_addr)?;
    m.write_u64(ctx_addr + ctx::x(7) as u64, signal as u64)?;
    m.write_u64(ctx_addr + ctx::x(6) as u64, info)?;
    m.write_u64(ctx_addr + ctx::x(2) as u64, uc)?;
    m.write_u64(ctx_addr + ctx::x(0) as u64, 0)?;
    m.write_u64(ctx_addr + ctx::PC as u64, action.handler)?;
    // The handler is 64-bit code, whatever was interrupted.
    m.write_u32(ctx_addr + ctx::CS as u64, 0)?;
    Ok(action.handler)
}

/// The x86-64 `rt_sigreturn`. The handler's `ret` popped the return address,
/// so the frame starts one word below the stack pointer.
fn sigreturn_x86(signals: &Signals, m: &mut GuestMem<'_>, ctx_addr: u64) -> Result<u64, Errno> {
    let frame_addr = m.read_u64(ctx_addr + ctx::SP as u64)? - 8;
    let uc = frame_addr + xframe::UCONTEXT as u64;
    let mc = uc + xframe::UC_MCONTEXT as u64;
    for (i, reg) in xframe::GPR_ORDER.iter().enumerate() {
        let v = m.read_u64(mc + i as u64 * 8)?;
        m.write_u64(ctx_addr + ctx::x(*reg) as u64, v)?;
    }
    // Back to 64-bit or 32-bit code (a WoW64 thread's); any other selector
    // is no code segment, and the return fails (SIGSEGV).
    let cs = match m.read_u64(mc + xframe::MC_CS as u64)? as u16 as u32 {
        ctx::CS_LONG => 0,
        ctx::CS_COMPAT => ctx::CS_COMPAT,
        _ => return Err(Errno::EFAULT),
    };
    m.write_u32(ctx_addr + ctx::CS as u64, cs)?;
    let pc = m.read_u64(mc + xframe::MC_RIP as u64)?;
    m.write_u64(ctx_addr + ctx::PC as u64, pc)?;
    write_rflags(m, ctx_addr, m.read_u64(mc + xframe::MC_EFLAGS as u64)?)?;
    let fpstate = m.read_u64(mc + xframe::MC_FPSTATE as u64)?;
    if fpstate != 0 {
        if let Ok(mxcsr) = m.read_u32(fpstate + 24) {
            m.write_u32(ctx_addr + ctx::MXCSR as u64, mxcsr)?;
            for n in 0..16u8 {
                for half in 0..2u64 {
                    let v = m.read_u64(fpstate + 160 + n as u64 * 16 + half * 8)?;
                    m.write_u64(ctx_addr + ctx::v(n) as u64 + half * 8, v)?;
                }
            }
        }
    }
    let mut own = signals.own();
    own.blocked = m.read_u64(uc + xframe::UC_SIGMASK as u64)?;
    own.in_handler = false;
    Ok(pc)
}

/// The i386 signal frames (`arch/x86/ia32/ia32_signal.c`). Every field is a
/// 32-bit word; the frame sits on the 32-bit stack and the handler is entered
/// as if called, with `esp` at the return address.
///
/// `struct sigcontext_ia32` (88 bytes):
///   gs fs es ds (selector words) | edi esi ebp esp ebx edx ecx eax | trapno
///   err | eip cs eflags esp_at_signal ss | fpstate oldmask cr2
/// `struct sigframe_ia32`: pretcode sig sigcontext extramask retcode
/// `struct rt_sigframe_ia32`: pretcode sig pinfo puc siginfo(128) ucontext
///   where ucontext is uc_flags uc_link uc_stack(12) uc_mcontext(88)
///   uc_sigmask(8).
mod iframe {
    pub const SC_GS: u64 = 0;
    pub const SC_FS: u64 = 4;
    pub const SC_ES: u64 = 8;
    pub const SC_DS: u64 = 12;
    /// edi esi ebp esp ebx edx ecx eax, as context register numbers.
    pub const GPR_ORDER: [u8; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
    pub const SC_GPRS: u64 = 16;
    pub const SC_TRAPNO: u64 = 48;
    pub const SC_ERR: u64 = 52;
    pub const SC_EIP: u64 = 56;
    pub const SC_CS: u64 = 60;
    pub const SC_EFLAGS: u64 = 64;
    pub const SC_ESP_AT_SIGNAL: u64 = 68;
    pub const SC_SS: u64 = 72;
    pub const SC_FPSTATE: u64 = 76;
    pub const SC_OLDMASK: u64 = 80;
    pub const SC_CR2: u64 = 84;
    pub const SC_SIZE: u64 = 88;

    // sigframe_ia32
    pub const SF_SIG: u64 = 4;
    pub const SF_SC: u64 = 8;
    pub const SF_EXTRAMASK: u64 = SF_SC + SC_SIZE; // 96
    pub const SF_SIZE: u64 = 112;

    // rt_sigframe_ia32
    pub const RT_SIG: u64 = 4;
    pub const RT_PINFO: u64 = 8;
    pub const RT_PUC: u64 = 12;
    pub const RT_INFO: u64 = 16;
    pub const RT_UC: u64 = 144;
    pub const UC_STACK: u64 = 8;
    pub const UC_MCONTEXT: u64 = 20;
    pub const UC_SIGMASK: u64 = UC_MCONTEXT + SC_SIZE; // 108
    pub const RT_SIZE: u64 = 272;

    /// `struct _fpstate_ia32` with an fxsave image: the legacy words first,
    /// `magic` at 110, then the fxsave environment (mxcsr at 136) and the
    /// xmm registers at 272.
    pub const FPSTATE_SIZE: usize = 624;
    pub const FP_MXCSR: u64 = 136;
    pub const FP_XMM: u64 = 272;

    pub const USER32_CS: u32 = 0x23;
    pub const USER_DS: u32 = 0x2b;
    /// The TLS entry glibc's i386 port loads into %gs: GDT entry 6, RPL 3.
    pub const GS_TLS: u32 = 0x33;
}

fn setup_frame_i386(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    signal: u32,
    fault_address: u64,
    taken: Taken,
) -> Result<u64, Errno> {
    let action = signals.action(signal);
    let sp = m.read_u64(ctx_addr + ctx::sp_slot(true) as u64)? & 0xffff_ffff;
    let rt = action.flags & sa::SIGINFO != 0;
    let mut own = signals.own();
    own.legacy_frame = !rt;

    let on_alt = action.flags & sa::ONSTACK != 0 && own.alt_stack.size > 0;
    let base = if on_alt {
        let alt = &own.alt_stack;
        let top = alt.sp + alt.size;
        if sp > alt.sp && sp <= top {
            sp
        } else {
            top
        }
    } else {
        sp
    };

    // The FP image above the frame, then the frame such that `esp + 4` is
    // 16-byte aligned on handler entry, as after a `call`.
    let fpstate = (base - iframe::FPSTATE_SIZE as u64) & !63;
    let size = if rt { iframe::RT_SIZE } else { iframe::SF_SIZE };
    let frame_addr = ((fpstate - size) & !0xf) - 4;
    m.zero(frame_addr, size as usize)?;
    m.zero(fpstate, iframe::FPSTATE_SIZE)?;

    let ret = if action.flags & sa::RESTORER != 0 && action.restorer != 0 {
        action.restorer
    } else {
        SIGRETURN_TRAMPOLINE
    };
    m.write_u32(frame_addr, ret as u32)?;

    // The mask sigreturn puts back: the one a sigsuspend or pwait-style
    // call replaced for its duration, otherwise the current one.
    let saved_mask = own.suspend_restore.take().unwrap_or(own.blocked);
    let sc = if rt {
        m.write_u32(frame_addr + iframe::RT_SIG, signal)?;
        let info = frame_addr + iframe::RT_INFO;
        let uc = frame_addr + iframe::RT_UC;
        m.write_u32(frame_addr + iframe::RT_PINFO, info as u32)?;
        m.write_u32(frame_addr + iframe::RT_PUC, uc as u32)?;
        write_siginfo(signals, m, info, signal, fault_address, false, taken)?;
        m.write_u32(uc, 0)?;
        m.write_u32(uc + 4, 0)?;
        m.write_u32(uc + iframe::UC_STACK, own.alt_stack.sp as u32)?;
        m.write_u32(uc + iframe::UC_STACK + 4, own.alt_stack.flags)?;
        m.write_u32(uc + iframe::UC_STACK + 8, own.alt_stack.size as u32)?;
        m.write_u64(uc + iframe::UC_SIGMASK, saved_mask)?;
        uc + iframe::UC_MCONTEXT
    } else {
        m.write_u32(frame_addr + iframe::SF_SIG, signal)?;
        m.write_u32(frame_addr + iframe::SF_EXTRAMASK, (saved_mask >> 32) as u32)?;
        frame_addr + iframe::SF_SC
    };

    m.write_u32(sc + iframe::SC_GS, iframe::GS_TLS)?;
    m.write_u32(sc + iframe::SC_FS, 0)?;
    m.write_u32(sc + iframe::SC_ES, iframe::USER_DS)?;
    m.write_u32(sc + iframe::SC_DS, iframe::USER_DS)?;
    for (i, reg) in iframe::GPR_ORDER.iter().enumerate() {
        let v = m.read_u64(ctx_addr + ctx::x(*reg) as u64)?;
        m.write_u32(sc + iframe::SC_GPRS + i as u64 * 4, v as u32)?;
    }
    let pc = m.read_u64(ctx_addr + ctx::PC as u64)?;
    m.write_u32(sc + iframe::SC_TRAPNO, if signal == sig::SIGSEGV { 14 } else { 0 })?;
    // A wasm32 program's call that restarts after this handler
    // (`syscalls::restart_call`): said in the frame, where its sigreturn
    // finds it, however many frames nest meanwhile.
    let restart = m.read_u64(ctx_addr + ctx::x(RESTART_SLOT) as u64)? == RESTART_MARK;
    if restart {
        m.write_u64(ctx_addr + ctx::x(RESTART_SLOT) as u64, 0)?;
    }
    m.write_u32(sc + iframe::SC_ERR, if restart { RESTART_ERR } else { 0 })?;
    m.write_u32(sc + iframe::SC_EIP, pc as u32)?;
    m.write_u32(sc + iframe::SC_CS, iframe::USER32_CS)?;
    m.write_u32(sc + iframe::SC_EFLAGS, read_rflags(m, ctx_addr)? as u32)?;
    m.write_u32(sc + iframe::SC_ESP_AT_SIGNAL, sp as u32)?;
    m.write_u32(sc + iframe::SC_SS, iframe::USER_DS)?;
    m.write_u32(sc + iframe::SC_FPSTATE, fpstate as u32)?;
    m.write_u32(sc + iframe::SC_OLDMASK, saved_mask as u32)?;
    m.write_u32(sc + iframe::SC_CR2, fault_address as u32)?;

    // The FP image: x87 control word, MXCSR and the eight xmm registers.
    // (an AArch64 build's i386-ABI processes are wasm32 programs: no x87,
    // and the context has no x87 area)
    let cw = if gex_abi::X86 { m.read_u32(ctx_addr + ctx::X87_CW as u64)? & 0xffff } else { 0x37f };
    m.write_u32(fpstate, cw)?;
    m.write_u32(fpstate + iframe::FP_MXCSR, m.read_u32(ctx_addr + ctx::MXCSR as u64)?)?;
    for n in 0..8u8 {
        for half in 0..2u64 {
            let v = m.read_u64(ctx_addr + ctx::v(n) as u64 + half * 8)?;
            m.write_u64(fpstate + iframe::FP_XMM + n as u64 * 16 + half * 8, v)?;
        }
    }

    own.blocked |= action.mask;
    if action.flags & sa::NODEFER == 0 {
        own.blocked |= bit(signal);
    }
    if let Taken::Fault(_) = taken {
        signals.clear_pending(signal);
    }
    own.in_handler = true;
    if action.flags & sa::RESETHAND != 0 {
        let _ = signals.set_action(signal, SigAction::default());
    }

    if std::env::var_os("GEX_SIGTRACE").is_some() {
        eprintln!(
            "[sig] i386 frame for {signal}: rt={rt} frame=0x{frame_addr:x} sc=0x{sc:x} fpstate=0x{fpstate:x} \
             handler=0x{:x} restorer=0x{:x} flags=0x{:x} interrupted pc=0x{pc:x} esp=0x{sp:x}",
            action.handler, action.restorer, action.flags
        );
    }
    // esp = frame; eax = signo; for an rt frame edx = &info and ecx = &uc.
    m.write_u64(ctx_addr + ctx::sp_slot(true) as u64, frame_addr)?;
    m.write_u64(ctx_addr + ctx::x(0) as u64, signal as u64)?;
    if rt {
        m.write_u64(ctx_addr + ctx::x(2) as u64, frame_addr + iframe::RT_INFO)?;
        m.write_u64(ctx_addr + ctx::x(1) as u64, frame_addr + iframe::RT_UC)?;
    } else {
        m.write_u64(ctx_addr + ctx::x(2) as u64, 0)?;
        m.write_u64(ctx_addr + ctx::x(1) as u64, 0)?;
    }
    m.write_u64(ctx_addr + ctx::PC as u64, action.handler)?;
    Ok(action.handler)
}

/// The i386 `sigreturn` (legacy: the restorer popped the return address and
/// `sig`, so the frame is two words below `esp`) and `rt_sigreturn` (one
/// word below).
/// A wasm32 program's interrupted call that restarts once its handler
/// returns (`syscalls::restart_call`): the context slot that says so
/// (r8, which the i386 ABI its calls use never touches), what it holds
/// then, and how the handler's frame keeps it (its `err` field, which only
/// a fault's frame uses).
pub const RESTART_SLOT: u8 = 8;
pub const RESTART_MARK: u64 = 0x5245_5354_4152_5453;
const RESTART_ERR: u32 = 0x5253_5452;

fn sigreturn_i386(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    legacy: bool,
) -> Result<u64, Errno> {
    let esp = m.read_u64(ctx_addr + ctx::sp_slot(true) as u64)? & 0xffff_ffff;
    let (sc, mask) = if legacy {
        let frame_addr = esp - 8;
        let sc = frame_addr + iframe::SF_SC;
        let lo = m.read_u32(sc + iframe::SC_OLDMASK)? as u64;
        let hi = m.read_u32(frame_addr + iframe::SF_EXTRAMASK)? as u64;
        (sc, lo | (hi << 32))
    } else {
        let frame_addr = esp - 4;
        let uc = frame_addr + iframe::RT_UC;
        (uc + iframe::UC_MCONTEXT, m.read_u64(uc + iframe::UC_SIGMASK)?)
    };
    if std::env::var_os("GEX_SIGTRACE").is_some() {
        let words: Vec<String> = (0..8)
            .map(|i| format!("{:08x}", m.read_u32(esp - 8 + i * 4).unwrap_or(0)))
            .collect();
        eprintln!(
            "[sig] i386 sigreturn legacy={legacy} esp=0x{esp:x} sc=0x{sc:x} eip=0x{:x} words@esp-8: {}",
            m.read_u32(sc + iframe::SC_EIP).unwrap_or(0),
            words.join(" ")
        );
    }
    for (i, reg) in iframe::GPR_ORDER.iter().enumerate() {
        let v = m.read_u32(sc + iframe::SC_GPRS + i as u64 * 4)? as u64;
        m.write_u64(ctx_addr + ctx::x(*reg) as u64, v)?;
    }
    let pc = m.read_u32(sc + iframe::SC_EIP)? as u64;
    m.write_u64(ctx_addr + ctx::PC as u64, pc)?;
    if m.read_u32(sc + iframe::SC_ERR)? == RESTART_ERR {
        m.write_u64(ctx_addr + ctx::x(RESTART_SLOT) as u64, RESTART_MARK)?;
    }
    write_rflags(m, ctx_addr, m.read_u32(sc + iframe::SC_EFLAGS)? as u64)?;
    let fpstate = m.read_u32(sc + iframe::SC_FPSTATE)? as u64;
    if fpstate != 0 {
        if let Ok(mxcsr) = m.read_u32(fpstate + iframe::FP_MXCSR) {
            m.write_u32(ctx_addr + ctx::MXCSR as u64, mxcsr)?;
            for n in 0..8u8 {
                for half in 0..2u64 {
                    let v = m.read_u64(fpstate + iframe::FP_XMM + n as u64 * 16 + half * 8)?;
                    m.write_u64(ctx_addr + ctx::v(n) as u64 + half * 8, v)?;
                }
            }
        }
    }
    let mut own = signals.own();
    own.blocked = mask;
    own.in_handler = false;
    Ok(pc)
}

/// RFLAGS from the context's flag bytes: CF, PF, AF, ZF, SF, DF, OF in their
/// architectural bits, plus the always-set bit 1 and IF.
fn read_rflags(m: &GuestMem<'_>, ctx_addr: u64) -> Result<u64, Errno> {
    let f = |off: usize| -> Result<u64, Errno> {
        Ok(m.read(ctx_addr + off as u64, 1)?[0] as u64 & 1)
    };
    Ok((f(ctx::CF)?)
        | (1 << 1)
        | (f(ctx::PF)? << 2)
        | (f(ctx::AF)? << 4)
        | (f(ctx::ZF)? << 6)
        | (f(ctx::NF)? << 7)
        | (1 << 9)
        | (f(ctx::DF)? << 10)
        | (f(ctx::VF)? << 11)
        | (m.read_u32(ctx_addr + ctx::EFLAGS_SYS as u64)? & EFLAGS_AC_ID) as u64)
}

/// EFLAGS.AC (bit 18) and ID (bit 21): the system bits user code can toggle,
/// kept in `ctx::EFLAGS_SYS`, so a handler sees, and `sigreturn` restores, what
/// the interrupted code's last `popf` set.
const EFLAGS_AC_ID: u32 = 0x24_0000;

fn write_rflags(m: &mut GuestMem<'_>, ctx_addr: u64, v: u64) -> Result<(), Errno> {
    for (off, bit) in [
        (ctx::CF, 0),
        (ctx::PF, 2),
        (ctx::AF, 4),
        (ctx::ZF, 6),
        (ctx::NF, 7),
        (ctx::DF, 10),
        (ctx::VF, 11),
    ] {
        m.write(ctx_addr + off as u64, &[((v >> bit) & 1) as u8])?;
    }
    m.write_u32(ctx_addr + ctx::EFLAGS_SYS as u64, v as u32 & EFLAGS_AC_ID)?;
    Ok(())
}

/// Restore the context a handler frame captured. Returns the resume address.
/// `compat` selects the i386 frames, and `legacy` the non-rt `sigreturn`
/// form of those (a handler installed without `SA_SIGINFO`).
pub fn sigreturn(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    compat: bool,
    legacy: bool,
) -> Result<u64, Errno> {
    if compat {
        // The frame's own kind decides; the entry number is a cross-check.
        let _ = legacy;
        let kind = signals.own().legacy_frame;
        return sigreturn_i386(signals, m, ctx_addr, kind);
    }
    if gex_abi::X86 {
        return sigreturn_x86(signals, m, ctx_addr);
    }
    // The frame is at the stack pointer the handler was entered with, which
    // it is required to have preserved.
    let frame_addr = m.read_u64(ctx_addr + ctx::SP as u64)?;
    let uc = frame_addr + frame::UCONTEXT as u64;
    let mc = uc + frame::UC_MCONTEXT as u64;

    for i in 0..31u8 {
        let v = m.read_u64(mc + frame::MC_REGS as u64 + i as u64 * 8)?;
        m.write_u64(ctx_addr + ctx::x(i) as u64, v)?;
    }
    let sp = m.read_u64(mc + frame::MC_SP as u64)?;
    let pc = m.read_u64(mc + frame::MC_PC as u64)?;
    let pstate = m.read_u64(mc + frame::MC_PSTATE as u64)?;
    m.write_u64(ctx_addr + ctx::SP as u64, sp)?;
    m.write_u64(ctx_addr + ctx::PC as u64, pc)?;
    write_pstate(m, ctx_addr, pstate)?;

    // The records, as `parse_user_sigframe` reads them: each on a sixteen
    // byte boundary and within `__reserved`, to the one with no magic; the
    // FP and vector state once and whole; the syndrome passed over; any
    // other magic, or no FP state, a frame that is not one (SIGSEGV).
    let reserved = mc + frame::MC_RESERVED as u64;
    let (mut at, mut fpsimd) = (0u64, false);
    loop {
        if at + 8 > frame::RESERVED_SIZE as u64 {
            return Err(Errno::EINVAL);
        }
        let (magic, size) = (m.read_u32(reserved + at)?, m.read_u32(reserved + at + 4)? as u64);
        if magic == 0 {
            if size != 0 {
                return Err(Errno::EINVAL);
            }
            break;
        }
        if size < 8 || size % 16 != 0 || size > frame::RESERVED_SIZE as u64 - at {
            return Err(Errno::EINVAL);
        }
        match magic {
            frame::FPSIMD_MAGIC => {
                if fpsimd || size != frame::FPSIMD_SIZE as u64 {
                    return Err(Errno::EINVAL);
                }
                fpsimd = true;
                let rec = reserved + at;
                m.write_u32(ctx_addr + ctx::FPSR as u64, m.read_u32(rec + 8)?)?;
                m.write_u32(ctx_addr + ctx::FPCR as u64, m.read_u32(rec + 12)?)?;
                let vregs = m.read(rec + 16, 32 * 16)?.to_vec();
                m.write(ctx_addr + ctx::V as u64, &vregs)?;
            }
            frame::ESR_MAGIC => {}
            _ => return Err(Errno::EINVAL),
        }
        at += size;
    }
    if !fpsimd {
        return Err(Errno::EINVAL);
    }

    let mut own = signals.own();
    own.blocked = m.read_u64(uc + frame::UC_SIGMASK as u64)?;
    own.in_handler = false;
    Ok(pc)
}

/// Consider the highest-priority pending signal.
pub fn dispatch(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    ctx_addr: u64,
    compat: bool,
) -> Result<Delivery, Errno> {
    // Taken off the pending sets before anything else: another thread of the
    // process may be delivering at the same time, without the kernel lock,
    // and a process-directed signal is for one of them only.
    let (signal, source, own) = loop {
        let Some(signal) = signals.next_deliverable() else {
            return Ok(Delivery::None);
        };
        let own = signals.cur.pending() & bit(signal) != 0;
        if let Some(source) = signals.claim(signal) {
            break (signal, source, own);
        }
    };
    let action = signals.action(signal);
    if action.handler == SIG_IGN {
        return Ok(Delivery::None);
    }
    if action.handler == SIG_DFL {
        let d = match default_action(signal) {
            DefaultAction::Ignore => Delivery::None,
            // A stop, for the host to make (`do_signal_stop`): it stops the
            // process, the table telling its parent, and holds its threads
            // until a `SIGCONT` or `SIGKILL`. Whether a terminal's three are
            // discarded instead (an orphaned group's) is the table's to say.
            DefaultAction::Stop if job_control() => {
                if signals.proc.stop.swap(signal, Ordering::AcqRel) == 0 {
                    STOPS_ASKED.fetch_add(1, Ordering::AcqRel);
                }
                return Ok(Delivery::None);
            }
            // With no host to hold a stopped process: the three a terminal
            // raises do nothing, which matches a shell with no job control (a
            // `^Z` there does nothing on real hardware too), and is far better
            // than killing a backgrounded reader. `SIGSTOP` is excluded -- it
            // can't be handled, so ending the process at least does something.
            DefaultAction::Stop
                if matches!(signal, sig::SIGTSTP | 21 | 22) =>
            {
                Delivery::None
            }
            DefaultAction::Core | DefaultAction::Stop => Delivery::Terminate { signal, core: true },
            _ => Delivery::Terminate {
                signal,
                core: false,
            },
        };
        if matches!(d, Delivery::Terminate { .. }) {
            *signals.proc.fatal.lock() = Some((signal, source, own));
        }
        return Ok(d);
    }
    match build_frame(signals, m, ctx_addr, signal, 0, compat, Taken::Claimed(source)) {
        Ok(resume) => {
            if matches!(signal, sig::SIGSEGV | sig::SIGBUS | sig::SIGILL | sig::SIGFPE) {
                *signals.proc.handled.lock() = Some((signal, source, own));
            }
            Ok(Delivery::Resume(resume))
        }
        Err(e) => {
            // No frame: the signal stays pending, as it was.
            signals.cur.raise(signal, source);
            Err(e)
        }
    }
}

/// The `siginfo_t` head at `info`: signo, code, and then either the sender
/// (`si_pid`, `si_uid`) of a signal a process sent or, for the synchronous
/// faults, the fault address, which is what a crash handler reads. `wide` is
/// the 64-bit layout, where the union after the three ints is 8-aligned (at
/// 16 rather than 12). Takes the signal's [`Source`].
fn write_siginfo(
    signals: &Signals,
    m: &mut GuestMem<'_>,
    info: u64,
    signal: u32,
    fault_address: u64,
    wide: bool,
    taken: Taken,
) -> Result<(), Errno> {
    let fields = info + if wide { 16 } else { 12 };
    m.write_u32(info, signal)?;
    let source = match taken {
        Taken::Fault(_) => signals.take_source(signal),
        Taken::Claimed(source) => source,
    };
    if let Some(src) = source {
        m.write_u32(info + 4, src.errno as u32)?;
        m.write_u32(info + 8, src.code as u32)?;
        // `_sigsys`: the call's address at a pointer's width, then its
        // number and the architecture.
        if let Some((addr, nr, arch)) = src.sigsys(signal) {
            if wide {
                m.write_u64(fields, addr)?;
                m.write_u32(fields + 8, nr)?;
                m.write_u32(fields + 12, arch)?;
            } else {
                m.write_u32(fields, addr as u32)?;
                m.write_u32(fields + 4, nr)?;
                m.write_u32(fields + 8, arch)?;
            }
            return Ok(());
        }
        m.write_u32(fields, src.pid as u32)?;
        m.write_u32(fields + 4, src.uid)?;
        // `si_value` follows the sender: a pointer's width.
        if wide {
            m.write_u64(fields + 8, src.value)?;
        } else {
            m.write_u32(fields + 8, src.value as u32)?;
        }
        return Ok(());
    }
    let code = match taken {
        Taken::Fault(Some(fault)) => fault.code,
        _ => fault_code(signal),
    };
    m.write_u32(info + 8, code)?;
    if matches!(signal, sig::SIGSEGV | sig::SIGBUS | sig::SIGILL | sig::SIGFPE) {
        if wide {
            m.write_u64(fields, fault_address)?;
        } else {
            m.write_u32(fields, fault_address as u32)?;
        }
    }
    Ok(())
}

/// The `si_code` a synchronous fault reports.
fn fault_code(signal: u32) -> u32 {
    match signal {
        // SEGV_MAPERR: address not mapped to an object.
        sig::SIGSEGV => 1,
        // ILL_ILLOPC: illegal opcode.
        sig::SIGILL => 1,
        // BUS_ADRALN: invalid address alignment.
        sig::SIGBUS => 1,
        // FPE_INTDIV: integer divide by zero.
        sig::SIGFPE => 1,
        // TRAP_BRKPT: process breakpoint.
        sig::SIGTRAP => 1,
        // SI_KERNEL for everything the kernel raised itself.
        _ => 0x80,
    }
}

/// Pack the four condition flags into a PSTATE word.
fn read_pstate(m: &GuestMem<'_>, ctx_addr: u64) -> Result<u64, Errno> {
    let (n, z, c, v) = ctx::unpack_nzcv(m.read_u32(ctx_addr + ctx::NZCV as u64)?);
    // EL0t with interrupts enabled, plus NZCV in their architectural places.
    Ok(((n as u64) << 31) | ((z as u64) << 30) | ((c as u64) << 29) | ((v as u64) << 28))
}

fn write_pstate(m: &mut GuestMem<'_>, ctx_addr: u64, pstate: u64) -> Result<(), Errno> {
    m.write_u32(
        ctx_addr + ctx::NZCV as u64,
        ctx::pack_nzcv(
            (pstate >> 31) as u32,
            (pstate >> 30) as u32,
            (pstate >> 29) as u32,
            (pstate >> 28) as u32,
        ),
    )?;
    Ok(())
}

#[cfg(all(test, not(feature = "x86")))]
mod tests {
    use super::*;

    /// A thread's signal state written for a snapshot and read back: the
    /// same sets, senders, stack, flags and settings.
    #[test]
    fn a_threads_signals_come_back_from_a_snapshot() {
        let t = ThreadSig::new_thread(1 << 4);
        t.raise(10, Some(Source { code: -6, pid: 42, uid: 1000, value: 7, errno: 0 }));
        t.raise(12, None);
        t.set_clear_child_tid(0x7000_1234);
        t.own.lock().alt_stack = SigAltStack { sp: 0x9000, flags: 0, size: 0x4000 };
        t.own.lock().suspend_restore = Some(0xff);
        t.tagged_addr.store(true, Ordering::Release);
        t.prctl.lock().timer_slack_ns = 123;
        let mut w = crate::snap::W::new();
        t.snap(&mut w);
        let b = w.into_bytes();
        let mut r = crate::snap::R::new(&b);
        let back = ThreadSig::unsnap(&mut r).unwrap();
        assert!(r.done());
        assert_eq!((back.pending(), back.blocked()), (t.pending(), t.blocked()));
        assert_eq!(*back.sources.lock(), *t.sources.lock());
        assert_eq!(back.clear_child_tid(), 0x7000_1234);
        {
            let (a, b2) = (back.own.lock(), t.own.lock());
            assert_eq!((a.alt_stack.sp, a.alt_stack.size, a.suspend_restore), (b2.alt_stack.sp, b2.alt_stack.size, b2.suspend_restore));
        }
        assert!(back.tagged_addr.load(Ordering::Acquire));
        assert_eq!(*back.prctl.lock(), *t.prctl.lock());
    }

    const CTX: u64 = 0x1000;

    fn setup() -> (Vec<u8>, Signals) {
        let mut buf = vec![0u8; 0x80000];
        {
            let mut m = GuestMem::new(&mut buf);
            // A plausible stack pointer with room below it for a frame.
            m.write_u64(CTX + ctx::SP as u64, 0x40000).unwrap();
            m.write_u64(CTX + ctx::PC as u64, 0x400100).unwrap();
            for i in 0..31u8 {
                m.write_u64(CTX + ctx::x(i) as u64, 0x1000 + i as u64)
                    .unwrap();
            }
        }
        (buf, Signals::new())
    }

    #[test]
    fn state_bytes_round_trip() {
        let s = Signals::new();
        let a = SigAction { handler: 0x1234, flags: 4, restorer: 0x99, mask: 1 << 3 };
        s.set_action(sig::SIGUSR1, a).unwrap();
        s.set_action(sig::SIGPIPE, SigAction { handler: SIG_IGN, ..Default::default() }).unwrap();
        s.set_blocked(bit(sig::SIGTERM));
        s.set_alt_stack(SigAltStack { sp: 0x7000, flags: 0, size: 0x2000 });
        s.raise(sig::SIGUSR2);
        s.raise_shared(sig::SIGHUP, None);
        s.set_saved_auxv(&[6, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0]);
        // As a fork child: no pending.
        let f = Signals::from_bytes(&s.to_bytes(false)).unwrap();
        assert_eq!(f.proc.saved_auxv(), s.proc.saved_auxv());
        assert_eq!(s.fork().proc.saved_auxv()[..10], [6, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
        assert_eq!(f.action(sig::SIGUSR1).handler, 0x1234);
        assert_eq!(f.action(sig::SIGUSR1).mask, 1 << 3);
        assert_eq!(f.action(sig::SIGPIPE).handler, SIG_IGN);
        assert_eq!(f.blocked(), bit(sig::SIGTERM));
        assert_eq!(f.alt_stack().sp, 0x7000);
        assert_eq!(f.pending_raw(), 0);
        // As an execve: pending kept.
        let e = Signals::from_bytes(&s.to_bytes(true)).unwrap();
        assert_eq!(e.pending_raw(), bit(sig::SIGUSR2) | bit(sig::SIGHUP));
        assert!(Signals::from_bytes(&[0u8; 7]).is_none());
    }

    #[test]
    fn kill_and_stop_cannot_be_caught() {
        let s = Signals::new();
        assert_eq!(
            s.set_action(sig::SIGKILL, SigAction::default()).err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(
            s.set_action(sig::SIGSTOP, SigAction::default()).err(),
            Some(Errno::EINVAL)
        );
        assert!(s.set_action(sig::SIGUSR1, SigAction::default()).is_ok());
    }

    #[test]
    fn blocked_signals_stay_pending() {
        let s = Signals::new();
        s.set_blocked(bit(sig::SIGUSR1));
        s.raise(sig::SIGUSR1);
        assert!(!s.has_pending());
        s.set_blocked(0);
        assert!(s.has_pending());
    }

    #[test]
    fn an_unhandled_fatal_signal_terminates() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.raise(sig::SIGTERM);
        assert_eq!(
            dispatch(&mut s, &mut m, CTX, false).unwrap(),
            Delivery::Terminate {
                signal: sig::SIGTERM,
                core: false
            }
        );
    }

    #[test]
    fn a_fatal_delivery_keeps_its_sender() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        assert_eq!(s.process().fatal(), None);
        s.raise_from(sig::SIGSEGV, Source { code: SI_TKILL, pid: 92, uid: 0, value: 0, errno: 0 });
        assert!(matches!(dispatch(&mut s, &mut m, CTX, false).unwrap(), Delivery::Terminate { signal: sig::SIGSEGV, .. }));
        assert_eq!(s.process().fatal(), Some((sig::SIGSEGV, Some(Source { code: SI_TKILL, pid: 92, uid: 0, value: 0, errno: 0 }), true)));
    }

    #[test]
    fn an_ignored_signal_is_discarded() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.set_action(
            sig::SIGUSR1,
            SigAction {
                handler: SIG_IGN,
                ..Default::default()
            },
        )
        .unwrap();
        s.raise(sig::SIGUSR1);
        assert_eq!(dispatch(&mut s, &mut m, CTX, false).unwrap(), Delivery::None);
        assert!(!s.has_pending());
    }

    #[test]
    fn sigchld_defaults_to_ignored() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.raise(sig::SIGCHLD);
        assert_eq!(dispatch(&mut s, &mut m, CTX, false).unwrap(), Delivery::None);
    }

    #[test]
    fn a_handler_frame_round_trips_the_context() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.set_action(
            sig::SIGUSR1,
            SigAction {
                handler: 0x400500,
                ..Default::default()
            },
        )
        .unwrap();
        s.raise(sig::SIGUSR1);

        let d = dispatch(&mut s, &mut m, CTX, false).unwrap();
        assert_eq!(d, Delivery::Resume(0x400500));
        // The handler sees its arguments and a return path.
        assert_eq!(
            m.read_u64(CTX + ctx::x(0) as u64).unwrap(),
            sig::SIGUSR1 as u64
        );
        assert_eq!(
            m.read_u64(CTX + ctx::x(30) as u64).unwrap(),
            SIGRETURN_TRAMPOLINE
        );
        assert!(s.in_handler());
        // The signal is blocked while its own handler runs.
        assert_ne!(s.blocked() & bit(sig::SIGUSR1), 0);
        // The stack moved below the original.
        let handler_sp = m.read_u64(CTX + ctx::SP as u64).unwrap();
        assert!(handler_sp < 0x40000);
        assert_eq!(handler_sp % 16, 0);

        // Returning restores everything the frame captured.
        let resume = sigreturn(&mut s, &mut m, CTX, false, false).unwrap();
        assert_eq!(resume, 0x400100);
        assert_eq!(m.read_u64(CTX + ctx::SP as u64).unwrap(), 0x40000);
        assert_eq!(m.read_u64(CTX + ctx::x(5) as u64).unwrap(), 0x1005);
        assert_eq!(s.blocked(), 0);
        assert!(!s.in_handler());
    }

    /// The frame's records: the vector registers where the structure has
    /// them, restored from there (so what a handler writes there is what
    /// the program resumes with, and what it does to the registers is
    /// undone); a fault's syndrome after them; and a frame whose records
    /// are not what the kernel wrote is refused.
    #[test]
    fn a_frame_carries_the_vector_state_and_a_faults_syndrome() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        for n in 0..32u8 {
            m.write(CTX + ctx::v(n) as u64, &[n + 1; 16]).unwrap();
        }
        let handler = SigAction { handler: 0x400500, ..Default::default() };
        s.set_action(sig::SIGSEGV, handler).unwrap();
        let fault = Fault::data_abort(SEGV_ACCERR, true, true);
        assert_eq!(fault.esr, Some(0x9200_004f));
        assert_eq!(Fault::data_abort(SEGV_MAPERR, false, false).esr, Some(0x9200_0007));
        setup_frame_fault(&s, &mut m, CTX, sig::SIGSEGV, fault, 0x7000, false).unwrap();
        let frame_at = m.read_u64(CTX + ctx::SP as u64).unwrap();
        // siginfo: the code and the address.
        assert_eq!(m.read_u32(frame_at + 8).unwrap(), SEGV_ACCERR);
        assert_eq!(m.read_u64(frame_at + 16).unwrap(), 0x7000);
        // `__reserved` is 288 bytes into the context, on a sixteen-byte
        // boundary: `struct fpsimd_context`, then `struct esr_context`.
        let reserved = frame_at + frame::UCONTEXT as u64 + frame::UC_MCONTEXT as u64 + 288;
        assert_eq!(reserved % 16, 0);
        assert_eq!((m.read_u32(reserved).unwrap(), m.read_u32(reserved + 4).unwrap()), (0x4650_8001, 528));
        assert_eq!(m.read(reserved + 16 + 31 * 16, 16).unwrap(), [32u8; 16]);
        assert_eq!((m.read_u32(reserved + 528).unwrap(), m.read_u32(reserved + 532).unwrap()), (0x4553_5201, 16));
        assert_eq!(m.read_u64(reserved + 536).unwrap(), 0x9200_004f);
        assert_eq!(m.read_u64(reserved + 544).unwrap(), 0, "the end");
        // The handler uses the registers, and leaves V1 changed in the frame.
        for n in 0..32u8 {
            m.write(CTX + ctx::v(n) as u64, &[0xff; 16]).unwrap();
        }
        m.write(reserved + 16 + 16, &[0x55; 16]).unwrap();
        let saved = m.read(frame_at, frame::FRAME_SIZE).unwrap().to_vec();
        sigreturn(&s, &mut m, CTX, false, false).unwrap();
        for n in 0..32u8 {
            let want = if n == 1 { 0x55 } else { n + 1 };
            assert_eq!(m.read(CTX + ctx::v(n) as u64, 16).unwrap(), [want; 16], "v{n}");
        }
        // Not frames: no vector state, a magic no one knows, a size past
        // the end.
        for (at, word) in [(reserved, 0u32), (reserved + 528, 0x1234_5678), (reserved + 4, 8192)] {
            m.write(frame_at, &saved).unwrap();
            m.write_u64(CTX + ctx::SP as u64, frame_at).unwrap();
            m.write_u32(at, word).unwrap();
            assert_eq!(sigreturn(&s, &mut m, CTX, false, false), Err(Errno::EINVAL), "{word:#x} at {:#x}", at - reserved);
        }
    }

    #[test]
    fn flags_are_preserved_across_a_handler() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        m.write_u32(CTX + ctx::NZCV as u64, ctx::pack_nzcv(1, 0, 1, 0))
            .unwrap();
        s.set_action(
            sig::SIGUSR1,
            SigAction {
                handler: 0x400500,
                ..Default::default()
            },
        )
        .unwrap();
        s.raise(sig::SIGUSR1);
        dispatch(&mut s, &mut m, CTX, false).unwrap();
        // The handler runs with whatever flags it likes.
        m.write_u32(CTX + ctx::NZCV as u64, ctx::pack_nzcv(0, 1, 0, 0))
            .unwrap();
        sigreturn(&mut s, &mut m, CTX, false, false).unwrap();
        let (n, z, c, _) = ctx::unpack_nzcv(m.read_u32(CTX + ctx::NZCV as u64).unwrap());
        assert_eq!((n, z, c), (1, 0, 1));
    }

    #[test]
    fn the_tagged_address_abi_follows_fork_and_ends_at_exec() {
        // Documentation/arch/arm64/tagged-address-abi.rst: "thread-scoped,
        // inherited on clone() and fork() and cleared on exec()".
        let s = Signals::new();
        assert!(!s.thread().tagged_addr());
        assert!(!s.fork().thread().tagged_addr());
        s.thread().set_tagged_addr(true);
        let child = s.fork();
        assert!(child.thread().tagged_addr(), "inherited on fork");
        child.exec();
        assert!(!child.thread().tagged_addr(), "cleared on exec");
        assert!(s.thread().tagged_addr(), "the parent's is its own");
    }

    #[test]
    fn resethand_reverts_before_the_handler_runs() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.set_action(
            sig::SIGUSR1,
            SigAction {
                handler: 0x400500,
                flags: sa::RESETHAND,
                ..Default::default()
            },
        )
        .unwrap();
        s.raise(sig::SIGUSR1);
        dispatch(&mut s, &mut m, CTX, false).unwrap();
        assert_eq!(s.action(sig::SIGUSR1).handler, SIG_DFL);
    }

    #[test]
    fn an_alternate_stack_is_used_when_requested() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        s.set_alt_stack(SigAltStack {
            sp: 0x60000,
            flags: 0,
            size: 0x8000,
        });
        s.set_action(
            sig::SIGSEGV,
            SigAction {
                handler: 0x400600,
                flags: sa::ONSTACK,
                ..Default::default()
            },
        )
        .unwrap();
        s.raise(sig::SIGSEGV);
        dispatch(&mut s, &mut m, CTX, false).unwrap();
        let sp = m.read_u64(CTX + ctx::SP as u64).unwrap();
        assert!(
            sp > 0x60000 && sp <= 0x68000,
            "handler should run on the alternate stack, got {sp:#x}"
        );
    }

    #[test]
    fn the_lowest_numbered_signal_is_delivered_first() {
        let (mut buf, mut s) = setup();
        let mut m = GuestMem::new(&mut buf);
        for n in [sig::SIGUSR2, sig::SIGUSR1] {
            s.set_action(
                n,
                SigAction {
                    handler: 0x400000 + n as u64,
                    ..Default::default()
                },
            )
            .unwrap();
            s.raise(n);
        }
        assert_eq!(
            dispatch(&mut s, &mut m, CTX, false).unwrap(),
            Delivery::Resume(0x400000 + sig::SIGUSR1 as u64)
        );
    }
}
