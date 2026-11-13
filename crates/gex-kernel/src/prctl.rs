//! `prctl(2)`: what a thread and its process set and ask about themselves.
//!
//! After `prctl` in kernel/sys.c (android17-6.18), the functions it calls
//! and `cap_task_prctl` (security/commoncap.c), for the kernel Android's
//! generic configuration builds: no KSM, no checkpoint and restore, no
//! core scheduling, no Yama. The processor is the one gex reports: no SVE,
//! SME, pointer authentication, memory tagging or guarded control stack on
//! AArch64, and none that speculates past a check on either architecture.
//!
//! An option this kernel has but gex has not the machinery for is refused
//! as a kernel built without it refuses it, `EINVAL`, and says so once
//! ([`refuse`]): a call that reported success and did nothing would be
//! believed. Those are a parent-death signal, a child subreaper, seccomp,
//! `PR_SET_MM`, the saved auxiliary vector, a faulting `rdtsc`, syscall
//! user dispatch and restored timer ids.

use crate::errno::SysResult;
use crate::signal::{ProcSig, ThreadSig};
use crate::syscalls::Creds;
use crate::{Errno, GuestMem};
use std::sync::atomic::{AtomicU64, Ordering};

/// The option numbers (include/uapi/linux/prctl.h).
pub mod pr {
    pub const SET_PDEATHSIG: u64 = 1;
    pub const GET_PDEATHSIG: u64 = 2;
    pub const GET_DUMPABLE: u64 = 3;
    pub const SET_DUMPABLE: u64 = 4;
    pub const GET_UNALIGN: u64 = 5;
    pub const SET_UNALIGN: u64 = 6;
    pub const GET_KEEPCAPS: u64 = 7;
    pub const SET_KEEPCAPS: u64 = 8;
    pub const GET_FPEMU: u64 = 9;
    pub const SET_FPEMU: u64 = 10;
    pub const GET_FPEXC: u64 = 11;
    pub const SET_FPEXC: u64 = 12;
    pub const GET_TIMING: u64 = 13;
    pub const SET_TIMING: u64 = 14;
    pub const SET_NAME: u64 = 15;
    pub const GET_NAME: u64 = 16;
    pub const GET_ENDIAN: u64 = 19;
    pub const SET_ENDIAN: u64 = 20;
    pub const GET_SECCOMP: u64 = 21;
    pub const SET_SECCOMP: u64 = 22;
    pub const CAPBSET_READ: u64 = 23;
    pub const CAPBSET_DROP: u64 = 24;
    pub const GET_TSC: u64 = 25;
    pub const SET_TSC: u64 = 26;
    pub const GET_SECUREBITS: u64 = 27;
    pub const SET_SECUREBITS: u64 = 28;
    pub const SET_TIMERSLACK: u64 = 29;
    pub const GET_TIMERSLACK: u64 = 30;
    pub const TASK_PERF_EVENTS_DISABLE: u64 = 31;
    pub const TASK_PERF_EVENTS_ENABLE: u64 = 32;
    pub const MCE_KILL: u64 = 33;
    pub const MCE_KILL_GET: u64 = 34;
    pub const SET_MM: u64 = 35;
    pub const SET_CHILD_SUBREAPER: u64 = 36;
    pub const GET_CHILD_SUBREAPER: u64 = 37;
    pub const SET_NO_NEW_PRIVS: u64 = 38;
    pub const GET_NO_NEW_PRIVS: u64 = 39;
    pub const GET_TID_ADDRESS: u64 = 40;
    pub const SET_THP_DISABLE: u64 = 41;
    pub const GET_THP_DISABLE: u64 = 42;
    pub const MPX_ENABLE_MANAGEMENT: u64 = 43;
    pub const MPX_DISABLE_MANAGEMENT: u64 = 44;
    pub const SET_FP_MODE: u64 = 45;
    pub const GET_FP_MODE: u64 = 46;
    pub const CAP_AMBIENT: u64 = 47;
    pub const SVE_SET_VL: u64 = 50;
    pub const SVE_GET_VL: u64 = 51;
    pub const GET_SPECULATION_CTRL: u64 = 52;
    pub const SET_SPECULATION_CTRL: u64 = 53;
    pub const PAC_RESET_KEYS: u64 = 54;
    pub const SET_TAGGED_ADDR_CTRL: u64 = 55;
    pub const GET_TAGGED_ADDR_CTRL: u64 = 56;
    pub const SET_IO_FLUSHER: u64 = 57;
    pub const GET_IO_FLUSHER: u64 = 58;
    pub const SET_SYSCALL_USER_DISPATCH: u64 = 59;
    pub const PAC_SET_ENABLED_KEYS: u64 = 60;
    pub const PAC_GET_ENABLED_KEYS: u64 = 61;
    pub const SCHED_CORE: u64 = 62;
    pub const SME_SET_VL: u64 = 63;
    pub const SME_GET_VL: u64 = 64;
    pub const SET_MDWE: u64 = 65;
    pub const GET_MDWE: u64 = 66;
    pub const SET_MEMORY_MERGE: u64 = 67;
    pub const GET_MEMORY_MERGE: u64 = 68;
    pub const RISCV_V_SET_CONTROL: u64 = 69;
    pub const RISCV_V_GET_CONTROL: u64 = 70;
    pub const RISCV_SET_ICACHE_FLUSH_CTX: u64 = 71;
    pub const PPC_GET_DEXCR: u64 = 72;
    pub const PPC_SET_DEXCR: u64 = 73;
    pub const GET_SHADOW_STACK_STATUS: u64 = 74;
    pub const SET_SHADOW_STACK_STATUS: u64 = 75;
    pub const LOCK_SHADOW_STACK_STATUS: u64 = 76;
    pub const TIMER_CREATE_RESTORE_IDS: u64 = 77;
    pub const FUTEX_HASH: u64 = 78;
    pub const SET_VMA: u64 = 0x5356_4d41;
    pub const GET_AUXV: u64 = 0x4155_5856;

    pub const TSC_ENABLE: u64 = 1;
    pub const TSC_SIGSEGV: u64 = 2;
    pub const MCE_KILL_CLEAR: u64 = 0;
    pub const MCE_KILL_SET: u64 = 1;
    pub const MCE_KILL_LATE: u64 = 0;
    pub const MCE_KILL_EARLY: u64 = 1;
    pub const MCE_KILL_DEFAULT: u64 = 2;
    pub const CAP_AMBIENT_IS_SET: u64 = 1;
    pub const CAP_AMBIENT_RAISE: u64 = 2;
    pub const CAP_AMBIENT_LOWER: u64 = 3;
    pub const CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    pub const THP_DISABLE_EXCEPT_ADVISED: u64 = 1 << 1;
    pub const SPEC_STORE_BYPASS: u64 = 0;
    pub const SPEC_INDIRECT_BRANCH: u64 = 1;
    pub const SPEC_L1D_FLUSH: u64 = 2;
    pub const SPEC_NOT_AFFECTED: u64 = 0;
    pub const SPEC_ENABLE: u64 = 1 << 1;
    pub const SPEC_DISABLE: u64 = 1 << 2;
    pub const SPEC_FORCE_DISABLE: u64 = 1 << 3;
    pub const SPEC_DISABLE_NOEXEC: u64 = 1 << 4;
    pub const MDWE_REFUSE_EXEC_GAIN: u64 = 1 << 0;
    pub const MDWE_NO_INHERIT: u64 = 1 << 1;
    pub const SYS_DISPATCH_OFF: u64 = 0;
    pub const TIMER_CREATE_RESTORE_IDS_OFF: u64 = 0;
    pub const TIMER_CREATE_RESTORE_IDS_ON: u64 = 1;
    pub const TIMER_CREATE_RESTORE_IDS_GET: u64 = 2;
    pub const FUTEX_HASH_SET_SLOTS: u64 = 1;
    pub const FUTEX_HASH_GET_SLOTS: u64 = 2;
    pub const SET_VMA_ANON_NAME: u64 = 0;
}

/// A new task's timer slack (`init_task`'s): 50 microseconds.
pub const TIMER_SLACK_NS: u64 = 50_000;

/// `task_struct`'s `PF_MCE_PROCESS` and `PF_MCE_EARLY`, as [`Task::mce`]
/// keeps them.
const MCE_PROCESS: u8 = 1;
const MCE_EARLY: u8 = 2;

/// What a thread has set about itself: the fields of its `task_struct`
/// these options read and write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task {
    /// `PR_SET_TIMERSLACK`, and what a zero resets it to: the slack its
    /// creator had when it was made.
    pub timer_slack_ns: u64,
    pub default_timer_slack_ns: u64,
    /// `PR_SET_NO_NEW_PRIVS`: never cleared.
    pub no_new_privs: bool,
    /// `PR_MCE_KILL`'s policy.
    pub mce: u8,
    /// `PR_SET_IO_FLUSHER`.
    pub io_flusher: bool,
}

impl Default for Task {
    fn default() -> Task {
        Task { timer_slack_ns: TIMER_SLACK_NS, default_timer_slack_ns: TIMER_SLACK_NS, no_new_privs: false, mce: 0, io_flusher: false }
    }
}

impl Task {
    /// What a task this one makes starts with (`copy_process`): all of it,
    /// its default slack the creator's slack now.
    pub fn child(&self) -> Task {
        Task { default_timer_slack_ns: self.timer_slack_ns, ..*self }
    }

    /// As one word, for a state that crosses to another memory
    /// ([`crate::signal::Signals::to_bytes`]), with the slacks beside it.
    pub fn flags(&self) -> u64 {
        self.no_new_privs as u64 | (self.mce as u64) << 1 | (self.io_flusher as u64) << 3
    }

    pub fn from_words(slack: u64, default_slack: u64, flags: u64) -> Task {
        Task {
            timer_slack_ns: slack,
            default_timer_slack_ns: default_slack,
            no_new_privs: flags & 1 != 0,
            mce: (flags >> 1 & 3) as u8,
            io_flusher: flags >> 3 & 1 != 0,
        }
    }
}

/// A process's private futex hash (`mm->futex_phash`): how many slots, and
/// whether `PR_FUTEX_HASH_SET_SLOTS` chose them. Zero slots is the global
/// hash chosen for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexHash {
    pub slots: u32,
    pub custom: bool,
}

/// What a process has set: flags of its `mm_struct` and its
/// `signal_struct`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proc {
    /// `PR_SET_DUMPABLE`: 0 or 1 (`SUID_DUMP_USER`, what an `execve` that
    /// changes no id sets).
    pub dumpable: u8,
    /// `PR_SET_THP_DISABLE`: 0, 1 for all of it, or 1 with
    /// `PR_THP_DISABLE_EXCEPT_ADVISED`.
    pub thp_disable: u8,
    /// `PR_SET_MDWE`'s bits, which are never cleared.
    pub mdwe: u8,
    pub futex_hash: Option<FutexHash>,
}

impl Default for Proc {
    fn default() -> Proc {
        Proc { dumpable: 1, thp_disable: 0, mdwe: 0, futex_hash: None }
    }
}

impl Proc {
    /// What a new address space takes from this one, a `fork`'s or an
    /// `execve`'s alike (`mm_init`'s `mmf_init_legacy_flags`): the dumpable
    /// and THP flags, and write-or-execute denial unless it was set not to
    /// be inherited. The futex hash is the old address space's.
    fn new_mm(&self) -> Proc {
        let mdwe = if self.mdwe as u64 & pr::MDWE_NO_INHERIT != 0 { 0 } else { self.mdwe };
        Proc { mdwe, futex_hash: None, ..*self }
    }

    /// `PR_MDWE_REFUSE_EXEC_GAIN`.
    pub fn denies_write_exec(&self) -> bool {
        self.mdwe as u64 & pr::MDWE_REFUSE_EXEC_GAIN != 0
    }

    /// A forked child's.
    pub fn fork(&self) -> Proc {
        self.new_mm()
    }

    /// After an `execve` that changed no id: dumpable again
    /// (`begin_new_exec`).
    pub fn exec(&self) -> Proc {
        Proc { dumpable: 1, ..self.new_mm() }
    }

    /// A thread is being made in a process that has `threads` and a machine
    /// with `cpus` processors: the private hash grows to four slots a
    /// thread, sixteen at least, unless its size was chosen
    /// (`futex_hash_allocate_default`). The global hash it is capped by has
    /// 256 slots a processor, rounded up to a power of two.
    pub fn thread_made(&mut self, threads: u32, cpus: u32) {
        let current = match self.futex_hash {
            Some(h) if h.custom || h.slots == 0 => return,
            Some(h) => h.slots,
            None => 0,
        };
        let global = (256 * cpus.max(1)).next_power_of_two();
        let want = (4 * threads.min(cpus.max(1))).next_power_of_two().clamp(16, global.max(16));
        if current < want {
            self.futex_hash = Some(FutexHash { slots: want, custom: false });
        }
    }

    pub fn word(&self) -> u64 {
        let (slots, custom, set) = match self.futex_hash {
            Some(h) => (h.slots as u64, h.custom as u64, 1),
            None => (0, 0, 0),
        };
        self.dumpable as u64 | (self.thp_disable as u64) << 2 | (self.mdwe as u64) << 4 | set << 6 | custom << 7 | slots << 8
    }

    pub fn from_word(w: u64) -> Proc {
        Proc {
            dumpable: (w & 3) as u8,
            thp_disable: (w >> 2 & 3) as u8,
            mdwe: (w >> 4 & 3) as u8,
            futex_hash: (w >> 6 & 1 != 0).then_some(FutexHash { slots: (w >> 8) as u32, custom: w >> 7 & 1 != 0 }),
        }
    }
}

/// Whose `prctl` it is.
pub struct Cx<'a> {
    pub thread: &'a ThreadSig,
    pub process: &'a ProcSig,
    pub creds: &'a Creds,
    pub pid: i32,
    /// An AArch64 thread; otherwise x86's rules (x86-64, i386 and a wasm32
    /// program, which runs on i386's ABI).
    pub a64: bool,
}

/// Capabilities by number (include/uapi/linux/capability.h).
const CAP_SETPCAP: u64 = 8;
const CAP_SYS_RESOURCE: u64 = 24;
const CAP_LAST_CAP: u64 = 40;

fn cap_valid(cap: u64) -> bool {
    cap <= CAP_LAST_CAP
}

/// Say, once for each option, that it is refused for want of an
/// implementation, and refuse it: `EINVAL`, a kernel built without it.
fn refuse(cx: &Cx<'_>, bit: u32, what: &str) -> SysResult {
    static SAID: AtomicU64 = AtomicU64::new(0);
    if SAID.fetch_or(1 << bit, Ordering::AcqRel) & (1 << bit) == 0 {
        eprintln!("[gex:{}] prctl: {what} is not implemented -> EINVAL", cx.pid);
    }
    Err(Errno::EINVAL)
}

/// `put_user` of a 32-bit value.
fn put_u32(m: &mut GuestMem<'_>, at: u64, v: u32) -> SysResult {
    m.write_u32(at, v).map(|_| 0).map_err(|_| Errno::EFAULT)
}

/// `prctl(option, arg2, arg3, arg4, arg5)` for `cx`'s thread, or `None` for
/// an option answered elsewhere: the thread's name, the tagged address ABI
/// (which the caller asks [`crate::syscalls::tagged_addr_ctrl`] first), the
/// naming of mappings and gex's own options.
pub fn call(cx: &Cx<'_>, m: &mut GuestMem<'_>, a: [u64; 6]) -> Option<SysResult> {
    let [option, arg2, arg3, arg4, arg5, _] = a;
    // The option is an `int`.
    let option = option as u32 as u64;
    if matches!(option, pr::SET_NAME | pr::GET_NAME | pr::SET_VMA | crate::proc::PR_GEX_CRASH | crate::proc::PR_GEX_SHORT) {
        return None;
    }
    Some(match option {
        // -- security/commoncap.c, before any of kernel/sys.c ----------------
        pr::CAPBSET_READ => {
            if cap_valid(arg2) {
                Ok(cx.creds.bounding() >> arg2 & 1)
            } else {
                Err(Errno::EINVAL)
            }
        }
        pr::CAPBSET_DROP => {
            if !cx.creds.capable(CAP_SETPCAP) {
                Err(Errno::EPERM)
            } else if !cap_valid(arg2) {
                Err(Errno::EINVAL)
            } else {
                cx.creds.drop_bounding(arg2);
                Ok(0)
            }
        }
        pr::SET_SECUREBITS => cx.creds.set_securebits(arg2).map(|_| 0),
        pr::GET_SECUREBITS => Ok(cx.creds.securebits() as u64),
        pr::GET_KEEPCAPS => Ok(cx.creds.keep_caps() as u64),
        pr::SET_KEEPCAPS => {
            if arg2 > 1 {
                Err(Errno::EINVAL)
            } else {
                cx.creds.set_keep_caps_checked(arg2 == 1).map(|_| 0)
            }
        }
        pr::CAP_AMBIENT => {
            if arg2 == pr::CAP_AMBIENT_CLEAR_ALL {
                if arg3 | arg4 | arg5 != 0 {
                    Err(Errno::EINVAL)
                } else {
                    cx.creds.clear_ambient();
                    Ok(0)
                }
            } else if !cap_valid(arg3) || arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                match arg2 {
                    pr::CAP_AMBIENT_IS_SET => Ok(cx.creds.ambient() >> arg3 & 1),
                    pr::CAP_AMBIENT_RAISE => cx.creds.raise_ambient(arg3).map(|_| 0),
                    pr::CAP_AMBIENT_LOWER => {
                        cx.creds.lower_ambient(arg3);
                        Ok(0)
                    }
                    _ => Err(Errno::EINVAL),
                }
            }
        }

        // -- kernel/sys.c ---------------------------------------------------
        pr::SET_PDEATHSIG => {
            if arg2 > 64 {
                Err(Errno::EINVAL)
            } else if arg2 == 0 {
                // None is what every task has.
                Ok(0)
            } else {
                refuse(cx, 0, "PR_SET_PDEATHSIG (a signal when the parent dies)")
            }
        }
        pr::GET_PDEATHSIG => put_u32(m, arg2, 0),
        pr::GET_DUMPABLE => Ok(cx.process.prctl().dumpable as u64),
        pr::SET_DUMPABLE => {
            if arg2 > 1 {
                Err(Errno::EINVAL)
            } else {
                cx.process.update_prctl(|p| p.dumpable = arg2 as u8);
                Ok(0)
            }
        }
        pr::GET_TIMING => Ok(0),
        pr::SET_TIMING => {
            if arg2 == 0 {
                Ok(0)
            } else {
                Err(Errno::EINVAL)
            }
        }
        // No filter is installed, and none can be: no CONFIG_SECCOMP.
        pr::GET_SECCOMP => Ok(0),
        pr::SET_SECCOMP => refuse(cx, 1, "PR_SET_SECCOMP"),
        // The time stamp counter is x86's.
        pr::GET_TSC if !cx.a64 => put_u32(m, arg2, pr::TSC_ENABLE as u32),
        pr::SET_TSC if !cx.a64 => match arg2 {
            pr::TSC_ENABLE => Ok(0),
            pr::TSC_SIGSEGV => refuse(cx, 2, "PR_SET_TSC with PR_TSC_SIGSEGV (a faulting rdtsc)"),
            _ => Err(Errno::EINVAL),
        },
        pr::GET_TIMERSLACK => Ok(cx.thread.prctl().timer_slack_ns),
        pr::SET_TIMERSLACK => {
            cx.thread.update_prctl(|t| t.timer_slack_ns = if arg2 == 0 { t.default_timer_slack_ns } else { arg2 });
            Ok(0)
        }
        // The task has no performance events to switch.
        pr::TASK_PERF_EVENTS_DISABLE | pr::TASK_PERF_EVENTS_ENABLE => Ok(0),
        pr::MCE_KILL => {
            if arg4 | arg5 != 0 {
                return Some(Err(Errno::EINVAL));
            }
            let mce = match (arg2, arg3) {
                (pr::MCE_KILL_CLEAR, 0) => |m: u8| m & !MCE_PROCESS,
                (pr::MCE_KILL_SET, pr::MCE_KILL_EARLY) => |m: u8| m | MCE_PROCESS | MCE_EARLY,
                (pr::MCE_KILL_SET, pr::MCE_KILL_LATE) => |m: u8| (m | MCE_PROCESS) & !MCE_EARLY,
                (pr::MCE_KILL_SET, pr::MCE_KILL_DEFAULT) => |_: u8| 0,
                _ => return Some(Err(Errno::EINVAL)),
            };
            cx.thread.update_prctl(|t| t.mce = mce(t.mce));
            Ok(0)
        }
        pr::MCE_KILL_GET => {
            if arg2 | arg3 | arg4 | arg5 != 0 {
                return Some(Err(Errno::EINVAL));
            }
            let mce = cx.thread.prctl().mce;
            Ok(match (mce & MCE_PROCESS != 0, mce & MCE_EARLY != 0) {
                (false, _) => pr::MCE_KILL_DEFAULT,
                (true, true) => pr::MCE_KILL_EARLY,
                (true, false) => pr::MCE_KILL_LATE,
            })
        }
        pr::SET_MM => {
            if !cx.creds.capable(CAP_SYS_RESOURCE) {
                Err(Errno::EPERM)
            } else {
                refuse(cx, 3, "PR_SET_MM")
            }
        }
        pr::SET_CHILD_SUBREAPER => {
            if arg2 == 0 {
                Ok(0)
            } else {
                refuse(cx, 4, "PR_SET_CHILD_SUBREAPER")
            }
        }
        pr::GET_CHILD_SUBREAPER => put_u32(m, arg2, 0),
        pr::SET_NO_NEW_PRIVS => {
            if arg2 != 1 || arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                cx.thread.update_prctl(|t| t.no_new_privs = true);
                Ok(0)
            }
        }
        pr::GET_NO_NEW_PRIVS => {
            if arg2 | arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(cx.thread.prctl().no_new_privs as u64)
            }
        }
        pr::GET_THP_DISABLE => {
            if arg2 | arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(cx.process.prctl().thp_disable as u64)
            }
        }
        pr::SET_THP_DISABLE => {
            // Flags only when disabling, and only the one.
            if arg4 | arg5 != 0 || (arg2 == 0 && arg3 != 0) || arg3 & !pr::THP_DISABLE_EXCEPT_ADVISED != 0 {
                Err(Errno::EINVAL)
            } else {
                let v = if arg2 == 0 { 0 } else { 1 | arg3 as u8 };
                cx.process.update_prctl(|p| p.thp_disable = v);
                Ok(0)
            }
        }
        pr::GET_SPECULATION_CTRL => {
            if arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                spec_ctrl_get(cx.a64, arg2)
            }
        }
        pr::SET_SPECULATION_CTRL => {
            if arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                spec_ctrl_set(cx.a64, arg2, arg3)
            }
        }
        pr::SET_IO_FLUSHER => {
            if !cx.creds.capable(CAP_SYS_RESOURCE) {
                Err(Errno::EPERM)
            } else if arg3 | arg4 | arg5 != 0 || arg2 > 1 {
                Err(Errno::EINVAL)
            } else {
                cx.thread.update_prctl(|t| t.io_flusher = arg2 == 1);
                Ok(0)
            }
        }
        pr::GET_IO_FLUSHER => {
            if !cx.creds.capable(CAP_SYS_RESOURCE) {
                Err(Errno::EPERM)
            } else if arg2 | arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(cx.thread.prctl().io_flusher as u64)
            }
        }
        // x86 only (its generic entry code); off is what it is.
        pr::SET_SYSCALL_USER_DISPATCH if !cx.a64 => {
            if arg2 == pr::SYS_DISPATCH_OFF {
                if arg3 | arg4 | arg5 != 0 {
                    Err(Errno::EINVAL)
                } else {
                    Ok(0)
                }
            } else {
                refuse(cx, 5, "PR_SET_SYSCALL_USER_DISPATCH")
            }
        }
        pr::SET_MDWE => {
            let now = cx.process.prctl().mdwe as u64;
            if arg3 | arg4 | arg5 != 0
                || arg2 & !(pr::MDWE_REFUSE_EXEC_GAIN | pr::MDWE_NO_INHERIT) != 0
                || (arg2 & pr::MDWE_NO_INHERIT != 0 && arg2 & pr::MDWE_REFUSE_EXEC_GAIN == 0)
            {
                Err(Errno::EINVAL)
            } else if now != 0 && now != arg2 {
                // The flags cannot be taken back.
                Err(Errno::EPERM)
            } else {
                cx.process.update_prctl(|p| p.mdwe |= arg2 as u8);
                Ok(0)
            }
        }
        pr::GET_MDWE => {
            if arg2 | arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(cx.process.prctl().mdwe as u64)
            }
        }
        pr::GET_AUXV => {
            if arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                refuse(cx, 6, "PR_GET_AUXV")
            }
        }
        pr::TIMER_CREATE_RESTORE_IDS => {
            if arg3 | arg4 | arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                match arg2 {
                    pr::TIMER_CREATE_RESTORE_IDS_OFF | pr::TIMER_CREATE_RESTORE_IDS_GET => Ok(0),
                    pr::TIMER_CREATE_RESTORE_IDS_ON => refuse(cx, 7, "PR_TIMER_CREATE_RESTORE_IDS_ON"),
                    _ => Err(Errno::EINVAL),
                }
            }
        }
        pr::FUTEX_HASH => match arg2 {
            pr::FUTEX_HASH_SET_SLOTS => {
                let slots = arg3 as u32;
                if arg4 != 0 || slots == 1 || (slots != 0 && !slots.is_power_of_two()) {
                    Err(Errno::EINVAL)
                } else if matches!(cx.process.prctl().futex_hash, Some(h) if h.slots == 0) {
                    // The global hash, once chosen, is kept.
                    Err(Errno::EBUSY)
                } else {
                    cx.process.update_prctl(|p| p.futex_hash = Some(FutexHash { slots, custom: true }));
                    Ok(0)
                }
            }
            pr::FUTEX_HASH_GET_SLOTS => Ok(cx.process.prctl().futex_hash.map_or(0, |h| h.slots) as u64),
            _ => Err(Errno::EINVAL),
        },
        // Everything else is an option of another architecture or of a
        // feature this kernel or this processor has not: unaligned access
        // control, FP emulation and exception modes, endianness, MPX, the
        // MIPS FP mode, SVE and SME vector lengths, pointer authentication
        // keys, the shadow stack, the RISC-V and PowerPC ones, KSM, core
        // scheduling, the clear-child-tid address (checkpoint and restore),
        // Yama's ptracer, and a number no option has.
        _ => Err(Errno::EINVAL),
    })
}

/// `PR_SET_VMA` (`prctl_set_vma`): `PR_SET_VMA_ANON_NAME` names the
/// anonymous mappings of a range, or with no name takes theirs away. A name
/// is at most 79 bytes of printable ASCII without ``\`$[]``
/// (`set_anon_vma_name`, mm/madvise.c).
pub fn set_vma(mem: &crate::mem::Mm, m: &GuestMem<'_>, a: [u64; 6]) -> SysResult {
    let [_, opt, addr, size, name, _] = a;
    if opt != pr::SET_VMA_ANON_NAME {
        return Err(Errno::EINVAL);
    }
    let name = if name == 0 {
        None
    } else {
        // `strndup_user`: longer than the limit with its NUL is `EINVAL`.
        let bytes = match m.read_cstr(name, 80) {
            Err(Errno::ENAMETOOLONG) => return Err(Errno::EINVAL),
            r => r?,
        };
        if bytes.len() >= 80 || bytes.iter().any(|&c| !(0x20..0x7f).contains(&c) || b"\\`$[]".contains(&c)) {
            return Err(Errno::EINVAL);
        }
        Some(String::from_utf8(bytes).map_err(|_| Errno::EINVAL)?)
    };
    mem.lock().set_anon_name(addr, size, name.as_deref()).map(|_| 0)
}

/// `arch_prctl_spec_ctrl_get` for a processor none of the misfeatures
/// affects. AArch64 knows only the store bypass; x86 reports the L1D flush
/// as forced off when its mitigation is not in use.
fn spec_ctrl_get(a64: bool, which: u64) -> SysResult {
    match (a64, which) {
        (_, pr::SPEC_STORE_BYPASS) | (false, pr::SPEC_INDIRECT_BRANCH) => Ok(pr::SPEC_NOT_AFFECTED),
        (false, pr::SPEC_L1D_FLUSH) => Ok(pr::SPEC_FORCE_DISABLE),
        _ => Err(Errno::ENODEV),
    }
}

/// `arch_prctl_spec_ctrl_set` for the same processor. AArch64 takes any
/// setting of the store bypass and has nothing to change
/// (arch/arm64/kernel/proton-pack.c); x86 has no per-task control to set
/// (arch/x86/kernel/cpu/bugs.c).
fn spec_ctrl_set(a64: bool, which: u64, ctrl: u64) -> SysResult {
    let known = matches!(ctrl, pr::SPEC_ENABLE | pr::SPEC_DISABLE | pr::SPEC_FORCE_DISABLE | pr::SPEC_DISABLE_NOEXEC);
    match (a64, which) {
        (true, pr::SPEC_STORE_BYPASS) => {
            if known {
                Ok(0)
            } else {
                Err(Errno::ERANGE)
            }
        }
        (false, pr::SPEC_STORE_BYPASS) => Err(Errno::ENXIO),
        (false, pr::SPEC_INDIRECT_BRANCH) => match ctrl {
            pr::SPEC_ENABLE => Ok(0),
            pr::SPEC_DISABLE | pr::SPEC_FORCE_DISABLE => Err(Errno::EPERM),
            _ => Err(Errno::ERANGE),
        },
        (false, pr::SPEC_L1D_FLUSH) => Err(Errno::EPERM),
        _ => Err(Errno::ENODEV),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Signals;

    fn run(s: &Signals, creds: &Creds, a64: bool, m: &mut GuestMem<'_>, a: [u64; 5]) -> SysResult {
        let cx = Cx { thread: s.thread(), process: s.process(), creds, pid: 1, a64 };
        call(&cx, m, [a[0], a[1], a[2], a[3], a[4], 0]).expect("an option of this module's")
    }

    /// Each option as kernel/sys.c has it, for root.
    #[test]
    fn options_answer_as_the_kernel_does() {
        let mut bytes = vec![0u8; 0x2000];
        let mut m = GuestMem::new(&mut bytes);
        let s = Signals::new();
        let root = Creds::new(0, 0);
        let inval = Err(Errno::EINVAL);
        let mut p = |a: [u64; 5]| run(&s, &root, true, &mut m, a);
        // No option 0, nor one past the last, nor another architecture's.
        for o in [0, 5, 6, 9, 10, 11, 12, 17, 18, 19, 20, 25, 26, 40, 43, 44, 45, 46, 48, 49, 50, 51, 54, 59, 60, 61, 62, 63, 64, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 79, 0x5961_6d61] {
            assert_eq!(p([o, 0, 0, 0, 0]), inval, "option {o}");
            assert_eq!(p([o, 0x1000, 8, 0, 0]), inval, "option {o}");
        }
        // The option is an int: its high half is not looked at.
        assert_eq!(p([1 << 32 | pr::GET_DUMPABLE, 0, 0, 0, 0]), Ok(1));
        assert_eq!(p([pr::SET_PDEATHSIG, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_PDEATHSIG, 65, 0, 0, 0]), inval);
        assert_eq!(p([pr::GET_PDEATHSIG, 0x1ff_ffff_ffff, 0, 0, 0]), Err(Errno::EFAULT));
        assert_eq!(p([pr::GET_PDEATHSIG, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_DUMPABLE, 2, 0, 0, 0]), inval);
        assert_eq!(p([pr::SET_DUMPABLE, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_DUMPABLE, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_TIMING, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_TIMING, 1, 0, 0, 0]), inval);
        assert_eq!(p([pr::GET_SECCOMP, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_TIMERSLACK, 0, 0, 0, 0]), Ok(50_000));
        assert_eq!(p([pr::SET_TIMERSLACK, 7, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_TIMERSLACK, 0, 0, 0, 0]), Ok(7));
        assert_eq!(p([pr::SET_TIMERSLACK, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_TIMERSLACK, 0, 0, 0, 0]), Ok(50_000));
        assert_eq!(p([pr::TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::MCE_KILL_GET, 0, 0, 0, 0]), Ok(pr::MCE_KILL_DEFAULT));
        assert_eq!(p([pr::MCE_KILL_GET, 1, 0, 0, 0]), inval);
        assert_eq!(p([pr::MCE_KILL, pr::MCE_KILL_SET, pr::MCE_KILL_EARLY, 0, 0]), Ok(0));
        assert_eq!(p([pr::MCE_KILL_GET, 0, 0, 0, 0]), Ok(pr::MCE_KILL_EARLY));
        assert_eq!(p([pr::MCE_KILL, pr::MCE_KILL_SET, pr::MCE_KILL_LATE, 0, 0]), Ok(0));
        assert_eq!(p([pr::MCE_KILL_GET, 0, 0, 0, 0]), Ok(pr::MCE_KILL_LATE));
        assert_eq!(p([pr::MCE_KILL, pr::MCE_KILL_CLEAR, 1, 0, 0]), inval);
        assert_eq!(p([pr::MCE_KILL, pr::MCE_KILL_CLEAR, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::MCE_KILL_GET, 0, 0, 0, 0]), Ok(pr::MCE_KILL_DEFAULT));
        assert_eq!(p([pr::MCE_KILL, 2, 0, 0, 0]), inval);
        assert_eq!(p([pr::GET_CHILD_SUBREAPER, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_CHILD_SUBREAPER, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_NO_NEW_PRIVS, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_NO_NEW_PRIVS, 0, 0, 0, 0]), inval);
        assert_eq!(p([pr::SET_NO_NEW_PRIVS, 1, 0, 0, 1]), inval);
        assert_eq!(p([pr::SET_NO_NEW_PRIVS, 1, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_NO_NEW_PRIVS, 0, 0, 0, 0]), Ok(1));
        assert_eq!(p([pr::GET_THP_DISABLE, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_THP_DISABLE, 0, 2, 0, 0]), inval, "a flag when enabling");
        assert_eq!(p([pr::SET_THP_DISABLE, 1, 4, 0, 0]), inval);
        assert_eq!(p([pr::SET_THP_DISABLE, 1, 2, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_THP_DISABLE, 0, 0, 0, 0]), Ok(3));
        assert_eq!(p([pr::SET_THP_DISABLE, 1, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_THP_DISABLE, 0, 0, 0, 0]), Ok(1));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 1, 0, 0, 0]), Err(Errno::ENODEV));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 0, 1, 0, 0]), inval);
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 0, 0, 0, 0]), Err(Errno::ERANGE));
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 0, pr::SPEC_DISABLE, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 1, pr::SPEC_DISABLE, 0, 0]), Err(Errno::ENODEV));
        assert_eq!(p([pr::GET_IO_FLUSHER, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_IO_FLUSHER, 2, 0, 0, 0]), inval);
        assert_eq!(p([pr::SET_IO_FLUSHER, 1, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_IO_FLUSHER, 0, 0, 0, 0]), Ok(1));
        assert_eq!(p([pr::GET_MDWE, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_MDWE, 2, 0, 0, 0]), inval, "no-inherit alone");
        assert_eq!(p([pr::SET_MDWE, 4, 0, 0, 0]), inval);
        assert_eq!(p([pr::SET_MDWE, 1, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_MDWE, 1, 0, 0, 0]), Ok(0), "the same again");
        assert_eq!(p([pr::SET_MDWE, 3, 0, 0, 0]), Err(Errno::EPERM));
        assert_eq!(p([pr::SET_MDWE, 0, 0, 0, 0]), Err(Errno::EPERM), "never taken back");
        assert_eq!(p([pr::GET_MDWE, 0, 0, 0, 0]), Ok(1));
        assert_eq!(p([pr::TIMER_CREATE_RESTORE_IDS, pr::TIMER_CREATE_RESTORE_IDS_GET, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::TIMER_CREATE_RESTORE_IDS, 3, 0, 0, 0]), inval);
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_GET_SLOTS, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 1, 0, 0]), inval);
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 24, 0, 0]), inval);
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 32, 1, 0]), inval);
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 32, 0, 0]), Ok(0));
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_GET_SLOTS, 0, 0, 0]), Ok(32));
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::FUTEX_HASH, pr::FUTEX_HASH_SET_SLOTS, 32, 0, 0]), Err(Errno::EBUSY));
        assert_eq!(p([pr::FUTEX_HASH, 3, 0, 0, 0]), inval);
        // What gex has not, refused and never claimed.
        for a in [
            [pr::SET_PDEATHSIG, 9, 0, 0, 0],
            [pr::SET_SECCOMP, 1, 0, 0, 0],
            [pr::SET_MM, 1, 0, 0, 0],
            [pr::SET_CHILD_SUBREAPER, 1, 0, 0, 0],
            [pr::GET_AUXV, 0x1000, 64, 0, 0],
            [pr::TIMER_CREATE_RESTORE_IDS, pr::TIMER_CREATE_RESTORE_IDS_ON, 0, 0, 0],
        ] {
            assert_eq!(p(a), inval, "{a:?}");
        }
    }

    /// x86's own options, and AArch64's refused there.
    #[test]
    fn x86_has_the_time_stamp_counter_and_its_own_speculation_answers() {
        let mut bytes = vec![0u8; 0x2000];
        let mut m = GuestMem::new(&mut bytes);
        let s = Signals::new();
        let root = Creds::new(0, 0);
        let mut p = |a: [u64; 5]| run(&s, &root, false, &mut m, a);
        assert_eq!(p([pr::GET_TSC, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_TSC, pr::TSC_ENABLE, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_TSC, 0, 0, 0, 0]), Err(Errno::EINVAL));
        assert_eq!(p([pr::SET_TSC, pr::TSC_SIGSEGV, 0, 0, 0]), Err(Errno::EINVAL));
        assert_eq!(p([pr::SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_SYSCALL_USER_DISPATCH, 0, 1, 0, 0]), Err(Errno::EINVAL));
        assert_eq!(p([pr::SET_SYSCALL_USER_DISPATCH, 1, 0, 0, 0]), Err(Errno::EINVAL));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 1, 0, 0, 0]), Ok(0));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 2, 0, 0, 0]), Ok(pr::SPEC_FORCE_DISABLE));
        assert_eq!(p([pr::GET_SPECULATION_CTRL, 3, 0, 0, 0]), Err(Errno::ENODEV));
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 0, pr::SPEC_DISABLE, 0, 0]), Err(Errno::ENXIO));
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 1, pr::SPEC_ENABLE, 0, 0]), Ok(0));
        assert_eq!(p([pr::SET_SPECULATION_CTRL, 1, pr::SPEC_DISABLE, 0, 0]), Err(Errno::EPERM));
        assert_eq!(m.read_u32(0x1000).unwrap(), 1, "PR_TSC_ENABLE, written where asked");
    }

    #[test]
    fn a_thread_made_grows_the_futex_hash_unless_its_size_was_chosen() {
        let mut p = Proc::default();
        p.thread_made(1, 8);
        assert_eq!(p.futex_hash, Some(FutexHash { slots: 16, custom: false }));
        p.thread_made(7, 8);
        assert_eq!(p.futex_hash.unwrap().slots, 32);
        p.thread_made(2, 8);
        assert_eq!(p.futex_hash.unwrap().slots, 32, "it does not shrink");
        // No more threads count than there are processors.
        p.thread_made(100, 8);
        assert_eq!(p.futex_hash.unwrap().slots, 32);
        let mut chosen = Proc { futex_hash: Some(FutexHash { slots: 64, custom: true }), ..Proc::default() };
        chosen.thread_made(100, 64);
        assert_eq!(chosen.futex_hash.unwrap().slots, 64);
    }

    #[test]
    fn state_follows_fork_and_exec_as_the_kernel_has_it() {
        let t = Task { timer_slack_ns: 9, default_timer_slack_ns: 50_000, no_new_privs: true, mce: 3, io_flusher: true };
        assert_eq!(t.child(), Task { default_timer_slack_ns: 9, ..t });
        assert_eq!(Task::from_words(t.timer_slack_ns, t.default_timer_slack_ns, t.flags()), t);
        let p = Proc { dumpable: 0, thp_disable: 3, mdwe: 1, futex_hash: Some(FutexHash { slots: 32, custom: true }) };
        assert_eq!(p.fork(), Proc { futex_hash: None, ..p });
        assert_eq!(p.exec(), Proc { dumpable: 1, futex_hash: None, ..p });
        assert_eq!(Proc { mdwe: 3, ..p }.fork().mdwe, 0, "set not to be inherited");
        assert_eq!(Proc::from_word(p.word()), p);
        assert_eq!(Proc::from_word(Proc::default().word()), Proc::default());
    }
}
