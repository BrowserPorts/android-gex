//! How each thread is scheduled: its nice value, policy, real-time priority
//! and reset-on-fork flag, as Linux 6.18 keeps them in a `task_struct` and
//! sets and reads them (`kernel/sys.c`'s `setpriority` and `getpriority`,
//! `kernel/sched/syscalls.c`'s `sched_setscheduler` family, `sched_fork`),
//! and its I/O priority (`block/ioprio.c`'s `ioprio_set` and `ioprio_get`,
//! `blk-ioc.c`'s `set_task_ioprio` and `__copy_io`).
//!
//! Kept, not applied: gex's guest threads are the host's threads, and the
//! host schedules them as it does its own. What a thread set is what it and
//! others read back, and the rules on who may set what are Linux's, so a
//! program that sets a real-time policy as root, or lowers another
//! thread's priority, gets Linux's answer. Kept in the process table
//! ([`ProcTable::sched_of`]), since a call can name any task.
//!
//! Not here: `sched_setattr` and `sched_getattr` (unimplemented, so
//! `ENOSYS`), the timer slack a real-time policy zeroes (`prctl`'s
//! `PR_GET_TIMERSLACK` reads what was set), an I/O context shared by
//! `CLONE_IO` (each task keeps its own copy), and the SELinux checks
//! (`security_task_setnice`, `_setscheduler`, `_getscheduler`,
//! `_setioprio`, `_getioprio`), as with every other hook.

use crate::errno::Errno;
use crate::proc::ProcTable;
use crate::syscalls::{Creds, RLIM_NLIMITS};

pub const SCHED_NORMAL: u8 = 0;
pub const SCHED_FIFO: u8 = 1;
pub const SCHED_RR: u8 = 2;
pub const SCHED_BATCH: u8 = 3;
pub const SCHED_IDLE: u8 = 5;
pub const SCHED_DEADLINE: u8 = 6;
/// GKI has `CONFIG_SCHED_CLASS_EXT`; with no BPF scheduler loaded a task
/// of this policy runs as `SCHED_NORMAL` does.
pub const SCHED_EXT: u8 = 7;
/// The flag `sched_setscheduler` takes and `sched_getscheduler` gives
/// beside the policy.
pub const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;
const MIN_NICE: i32 = -20;
const MAX_NICE: i32 = 19;
/// `MAX_RT_PRIO - 1`.
const MAX_RT_PRIORITY: u32 = 99;
const CAP_SYS_ADMIN: u64 = 21;
const CAP_SYS_NICE: u64 = 23;
const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_WHO_PGRP: i32 = 2;
const IOPRIO_WHO_USER: i32 = 3;
const IOPRIO_CLASS_NONE: u32 = 0;
const IOPRIO_CLASS_RT: u32 = 1;
const IOPRIO_CLASS_BE: u32 = 2;
const IOPRIO_CLASS_IDLE: u32 = 3;
const IOPRIO_CLASS_SHIFT: u32 = 13;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;

fn rt_policy(p: u8) -> bool {
    p == SCHED_FIFO || p == SCHED_RR
}

fn valid_policy(p: i64) -> bool {
    matches!(p, 0 | 1 | 2 | 3 | 5 | 6 | 7)
}

/// One task's scheduling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sched {
    /// -20 to 19, kept whatever the policy (`static_prio`).
    pub nice: i8,
    pub policy: u8,
    /// 1 to 99 under a real-time policy, 0 otherwise.
    pub rt_priority: u8,
    pub reset_on_fork: bool,
    /// Its I/O context's priority as set (`io_context->ioprio`), 0 for
    /// none: class in bits 13 to 15, a hint in 3 to 12, a level in 0 to 2.
    pub ioprio: u16,
}

/// `IOPRIO_PRIO_CLASS`.
fn io_class(ioprio: u32) -> u32 {
    ioprio >> IOPRIO_CLASS_SHIFT & 7
}

impl Sched {
    /// As the process table keeps it: policy, priority, nice (two's
    /// complement) and the flag, a byte each, and the I/O priority above
    /// them. 0 is `SCHED_NORMAL` at nice 0 with no I/O priority set.
    pub fn word(self) -> u64 {
        self.policy as u64 | (self.rt_priority as u64) << 8 | (self.nice as u8 as u64) << 16 | (self.reset_on_fork as u64) << 24 | (self.ioprio as u64) << 32
    }

    pub fn from_word(w: u64) -> Sched {
        Sched { policy: w as u8, rt_priority: (w >> 8) as u8, nice: (w >> 16) as u8 as i8, reset_on_fork: w >> 24 & 1 != 0, ioprio: (w >> 32) as u16 }
    }

    /// What a task this one makes starts with (`sched_fork`): the same,
    /// unless it asked for its children to be reset: then a real-time or
    /// deadline policy becomes `SCHED_NORMAL` at nice 0, a negative nice
    /// becomes 0, and the flag is not passed on.
    ///
    /// The I/O priority is copied when its class is one (`__copy_io`'s
    /// `ioprio_valid`); otherwise the child has none.
    pub fn child(self) -> Sched {
        let ioprio = if (IOPRIO_CLASS_RT..=IOPRIO_CLASS_IDLE).contains(&io_class(self.ioprio as u32)) { self.ioprio } else { 0 };
        let s = if !self.reset_on_fork {
            self
        } else if rt_policy(self.policy) || self.policy == SCHED_DEADLINE {
            Sched::default()
        } else {
            Sched { nice: self.nice.max(0), reset_on_fork: false, ..self }
        };
        Sched { ioprio, ..s }
    }

    /// `__get_task_ioprio`: the I/O priority set, or for none the one the
    /// scheduling implies: idle for `SCHED_IDLE`, real-time for a
    /// real-time or deadline policy, best effort otherwise, at the level
    /// `(nice + 20) / 5`.
    fn effective_ioprio(self) -> u32 {
        if io_class(self.ioprio as u32) != IOPRIO_CLASS_NONE {
            return self.ioprio as u32;
        }
        let class = if self.policy == SCHED_IDLE {
            IOPRIO_CLASS_IDLE
        } else if rt_policy(self.policy) || self.policy == SCHED_DEADLINE {
            IOPRIO_CLASS_RT
        } else {
            IOPRIO_CLASS_BE
        };
        class << IOPRIO_CLASS_SHIFT | ((self.nice as i32 + 20) / 5) as u32
    }

    /// `/proc/<pid>/stat`'s priority (`task_prio`): `-1 - rt_priority` for
    /// a real-time policy, `20 + nice` otherwise.
    pub fn prio(self) -> i32 {
        if rt_policy(self.policy) {
            -1 - self.rt_priority as i32
        } else {
            20 + self.nice as i32
        }
    }
}

/// A task's scheduling as a thread's `/proc` files say it: the table's, or
/// the default for a task the table does not have.
pub fn of(procs: &ProcTable, tid: i32) -> Sched {
    Sched::from_word(procs.sched_of(tid).unwrap_or(0))
}

/// A thread or process `child` was made by thread `parent`: it starts with
/// [`Sched::child`] of the parent's.
pub fn inherit(procs: &ProcTable, parent: i32, child: i32) {
    let s = of(procs, parent).child();
    if s != Sched::default() {
        procs.set_sched(child, s.word());
    }
}

/// The caller of a scheduling call: its process and thread, its
/// credentials, and its process's resource limits.
pub struct Cx<'a> {
    pub procs: &'a ProcTable,
    pub pid: i32,
    pub tid: i32,
    pub creds: &'a Creds,
    pub rlimits: [[u64; 2]; RLIM_NLIMITS],
}

/// A task a call names, and what the rules ask of it.
struct Target {
    tid: i32,
    sched: Sched,
    /// Its process's real and effective uids.
    uid: u32,
    euid: u32,
    /// Its process's soft `RLIMIT_NICE` and `RLIMIT_RTPRIO`.
    rlim_nice: u64,
    rlim_rtprio: u64,
}

impl Cx<'_> {
    /// Task `id` (0: the caller), if there is one.
    fn target(&self, id: i32) -> Option<Target> {
        let tid = if id == 0 { self.tid } else { id };
        if tid <= 0 {
            return None;
        }
        let pid = self.procs.task_owner(tid)?;
        let sched = Sched::from_word(self.procs.sched_of(tid)?);
        Some(self.target_in(tid, pid, sched, None))
    }

    /// Task `tid` of process `pid`, with `creds` its process's saved
    /// credentials when the caller has them to hand.
    fn target_in(&self, tid: i32, pid: i32, sched: Sched, creds: Option<&[u8]>) -> Target {
        let (uid, euid, limits) = if pid == self.pid {
            (self.creds.ruid(), self.creds.uid(), Some(self.rlimits))
        } else {
            let saved = match creds {
                Some(c) => Some(c.to_vec()),
                None => self.procs.entries().into_iter().find(|e| e.pid == pid).map(|e| e.creds),
            };
            let (uid, euid) = saved.as_deref().map_or((u32::MAX, u32::MAX), uids_of);
            // Another process's limits, where the host has published them;
            // otherwise the defaults (0), which a process rarely raises.
            let limits = self.procs.vm(pid).ok().and_then(|vm| vm.rlimits.as_ref()?.upgrade()).map(|r| r.get());
            (uid, euid, limits)
        };
        let lim = |r: usize| limits.map_or(0, |l| l[r][0]);
        Target { tid, sched, uid, euid, rlim_nice: lim(RLIMIT_NICE), rlim_rtprio: lim(RLIMIT_RTPRIO) }
    }

    /// The tasks `setpriority` and `getpriority` name: one task, every
    /// task of a process group (0: the caller's), or every task of the
    /// processes whose real uid is `who` (0: the caller's).
    fn named(&self, which: i32, who: i32) -> Vec<Target> {
        match which {
            PRIO_PROCESS => self.target(who).into_iter().collect(),
            PRIO_PGRP => self.every(Some(who), None),
            _ => self.every(None, Some(if who != 0 { who as u32 } else { self.creds.ruid() })),
        }
    }

    /// Every task of process group `pgrp` (0: the caller's), or every task
    /// of the processes whose real uid is `uid`.
    fn every(&self, pgrp: Option<i32>, uid: Option<u32>) -> Vec<Target> {
        let entries = self.procs.entries();
        let group = pgrp.map(|g| if g != 0 { g } else { entries.iter().find(|e| e.pid == self.pid).map_or(0, |e| e.pgid) });
        let want = |e: &crate::proc::ProcEntry| -> bool {
            match (group, uid) {
                (Some(g), _) => g != 0 && e.pgid == g,
                (None, Some(u)) => (if e.pid == self.pid { self.creds.ruid() } else { uids_of(&e.creds).0 }) == u,
                (None, None) => false,
            }
        };
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| want(e)) {
            for tid in std::iter::once(e.pid).chain(e.tids.iter().copied()) {
                if let Some(w) = self.procs.sched_of(tid) {
                    out.push(self.target_in(tid, e.pid, Sched::from_word(w), Some(&e.creds)));
                }
            }
        }
        out
    }

    fn capable(&self) -> bool {
        self.creds.capable(CAP_SYS_NICE)
    }

    /// `is_nice_reduction`: going to `nice` is within the target's
    /// `RLIMIT_NICE` (whose value 20 - nice is the lowest allowed).
    fn nice_within(t: &Target, nice: i32) -> bool {
        (20 - nice) as u64 <= t.rlim_nice
    }

    /// `set_one_prio`, with `error` the answer so far.
    fn set_one_prio(&self, t: &Target, nice: i32, error: Result<(), Errno>) -> Result<(), Errno> {
        let euid = self.creds.uid();
        if !(t.uid == euid || t.euid == euid || self.capable()) {
            return Err(Errno::EPERM);
        }
        if nice < t.sched.nice as i32 && !(Self::nice_within(t, nice) || self.capable()) {
            return Err(Errno::EACCES);
        }
        let error = if error == Err(Errno::ESRCH) { Ok(()) } else { error };
        self.procs.set_sched(t.tid, Sched { nice: nice as i8, ..t.sched }.word());
        error
    }

    /// `setpriority(which, who, niceval)`.
    pub fn setpriority(&self, which: i32, who: i32, nice: i32) -> Result<u64, Errno> {
        if !(PRIO_PROCESS..=PRIO_USER).contains(&which) {
            return Err(Errno::EINVAL);
        }
        let nice = nice.clamp(MIN_NICE, MAX_NICE);
        let mut error = Err(Errno::ESRCH);
        for t in self.named(which, who) {
            error = self.set_one_prio(&t, nice, error);
        }
        error.map(|()| 0)
    }

    /// `getpriority(which, who)`: the highest priority among the tasks
    /// named, as `20 - nice` (1 to 40) so no answer looks like an error.
    pub fn getpriority(&self, which: i32, who: i32) -> Result<u64, Errno> {
        if !(PRIO_PROCESS..=PRIO_USER).contains(&which) {
            return Err(Errno::EINVAL);
        }
        self.named(which, who).iter().map(|t| (20 - t.sched.nice as i32) as u64).max().ok_or(Errno::ESRCH)
    }

    /// `sched_setscheduler(pid, policy, param)`, or `sched_setparam(pid,
    /// param)` with `policy` `None` (`SETPARAM_POLICY`). `priority` is what
    /// `param` held, read by the caller, or `Err(EFAULT)`.
    pub fn setscheduler(&self, pid: i32, policy: Option<i32>, param: u64, priority: impl FnOnce() -> Result<u32, Errno>) -> Result<u64, Errno> {
        if policy.is_some_and(|p| p < 0) {
            return Err(Errno::EINVAL);
        }
        if param == 0 || pid < 0 {
            return Err(Errno::EINVAL);
        }
        let prio = priority()?;
        let t = self.target(pid).ok_or(Errno::ESRCH)?;
        // The legacy flag beside the policy (`_sched_setscheduler`).
        let (policy, reset) = match policy {
            None => (t.sched.policy, t.sched.reset_on_fork),
            Some(p) => {
                let p = p as u32;
                let reset = p & SCHED_RESET_ON_FORK != 0;
                let p = (p & !SCHED_RESET_ON_FORK) as i64;
                if !valid_policy(p) {
                    return Err(Errno::EINVAL);
                }
                (p as u8, reset)
            }
        };
        if prio > MAX_RT_PRIORITY {
            return Err(Errno::EINVAL);
        }
        // A deadline policy needs `sched_setattr`'s parameters; here its
        // deadline is 0 (`__checkparam_dl`).
        if policy == SCHED_DEADLINE || rt_policy(policy) != (prio != 0) {
            return Err(Errno::EINVAL);
        }
        if !self.may_setscheduler(&t, policy, prio, reset) {
            return Err(Errno::EPERM);
        }
        let s = Sched { policy, rt_priority: prio as u8, reset_on_fork: reset, ..t.sched };
        self.procs.set_sched(t.tid, s.word());
        Ok(0)
    }

    /// `user_check_sched_setscheduler`: what a caller without
    /// `CAP_SYS_NICE` may do. The nice value is the target's own here
    /// (`sched_setscheduler` passes it), so the fair policies' check never
    /// refuses.
    fn may_setscheduler(&self, t: &Target, policy: u8, prio: u32, reset: bool) -> bool {
        if self.capable() {
            return true;
        }
        if rt_policy(policy) {
            if policy != t.sched.policy && t.rlim_rtprio == 0 {
                return false;
            }
            if prio > t.sched.rt_priority as u32 && prio as u64 > t.rlim_rtprio {
                return false;
            }
        }
        // `SCHED_IDLE` counts as nice 20: leaving it is a nice reduction.
        if t.sched.policy == SCHED_IDLE && policy != SCHED_IDLE && !Self::nice_within(t, t.sched.nice as i32) {
            return false;
        }
        let euid = self.creds.uid();
        if !(euid == t.euid || euid == t.uid) {
            return false;
        }
        !(t.sched.reset_on_fork && !reset)
    }

    /// `sched_getscheduler(pid)`: the policy, with the reset flag.
    pub fn getscheduler(&self, pid: i32) -> Result<u64, Errno> {
        if pid < 0 {
            return Err(Errno::EINVAL);
        }
        let t = self.target(pid).ok_or(Errno::ESRCH)?;
        Ok(t.sched.policy as u64 | if t.sched.reset_on_fork { SCHED_RESET_ON_FORK as u64 } else { 0 })
    }

    /// `sched_getparam(pid, param)`: the real-time priority, 0 under any
    /// other policy, for the caller to write.
    pub fn getparam(&self, pid: i32, param: u64) -> Result<u32, Errno> {
        if param == 0 || pid < 0 {
            return Err(Errno::EINVAL);
        }
        let t = self.target(pid).ok_or(Errno::ESRCH)?;
        Ok(if rt_policy(t.sched.policy) { t.sched.rt_priority as u32 } else { 0 })
    }
}

impl Cx<'_> {
    /// `ioprio_set(which, who, ioprio)`: the class checked first
    /// (`ioprio_check_cap`), then each task named (`set_task_ioprio`: its
    /// real uid the caller's real or effective one, or `CAP_SYS_NICE`); a
    /// group or a user's tasks stop at the first refusal. For a user, who
    /// 0 is uid 0 here, as Linux compares it.
    pub fn ioprio_set(&self, which: i32, who: i32, ioprio: i32) -> Result<u64, Errno> {
        let class = io_class(ioprio as u32);
        match class {
            IOPRIO_CLASS_RT => {
                if !self.creds.capable(CAP_SYS_ADMIN) && !self.capable() {
                    return Err(Errno::EPERM);
                }
            }
            IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => {}
            IOPRIO_CLASS_NONE if ioprio & 7 == 0 => {}
            _ => return Err(Errno::EINVAL),
        }
        let tasks = match which {
            IOPRIO_WHO_PROCESS => self.target(who).into_iter().collect(),
            IOPRIO_WHO_PGRP => self.every(Some(who), None),
            // `make_kuid` of -1 is no uid
            IOPRIO_WHO_USER if who == -1 => Vec::new(),
            IOPRIO_WHO_USER => self.every(None, Some(who as u32)),
            _ => return Err(Errno::EINVAL),
        };
        let mut ret = Err(Errno::ESRCH);
        for t in tasks {
            if t.uid != self.creds.uid() && t.uid != self.creds.ruid() && !self.capable() {
                return Err(Errno::EPERM);
            }
            // `io_context->ioprio` is an unsigned short
            self.procs.set_sched(t.tid, Sched { ioprio: ioprio as u16, ..t.sched }.word());
            ret = Ok(0);
        }
        ret
    }

    /// `ioprio_get(which, who)`: a task's priority as set (0 for none), or
    /// the best (lowest) of a group's or a user's as their scheduling
    /// implies it where none is set. For a user, who 0 is the caller's real
    /// uid.
    pub fn ioprio_get(&self, which: i32, who: i32) -> Result<u64, Errno> {
        let tasks = match which {
            IOPRIO_WHO_PROCESS => return self.target(who).map(|t| t.sched.ioprio as u64).ok_or(Errno::ESRCH),
            IOPRIO_WHO_PGRP => self.every(Some(who), None),
            IOPRIO_WHO_USER => self.every(None, Some(if who != 0 { who as u32 } else { self.creds.ruid() })),
            _ => return Err(Errno::EINVAL),
        };
        tasks.iter().map(|t| t.sched.effective_ioprio() as u64).min().ok_or(Errno::ESRCH)
    }
}

/// `sched_get_priority_max` and `_min`.
pub fn priority_bound(policy: i64, max: bool) -> Result<u64, Errno> {
    match policy {
        1 | 2 => Ok(if max { MAX_RT_PRIORITY as u64 } else { 1 }),
        0 | 3 | 5 | 6 | 7 => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

/// The real and effective uids in [`Creds::save`]'s bytes; none read as
/// nobody's.
fn uids_of(saved: &[u8]) -> (u32, u32) {
    let w = |i: usize| saved.get(i * 4..i * 4 + 4).map_or(u32::MAX, |b| u32::from_le_bytes(b.try_into().unwrap()));
    (w(0), w(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::INIT_PID;
    use crate::syscalls::default_rlimits;

    fn cx<'a>(procs: &'a ProcTable, pid: i32, tid: i32, creds: &'a Creds) -> Cx<'a> {
        Cx { procs, pid, tid, creds, rlimits: default_rlimits() }
    }

    #[test]
    fn a_word_holds_each_field() {
        let s = Sched { nice: -7, policy: SCHED_RR, rt_priority: 42, reset_on_fork: true, ioprio: 0x4006 };
        assert_eq!(Sched::from_word(s.word()), s);
        assert_eq!(Sched::default().word(), 0);
        assert_eq!(Sched { nice: 19, ..Sched::default() }.prio(), 39);
        assert_eq!(Sched { policy: SCHED_FIFO, rt_priority: 10, ..Sched::default() }.prio(), -11);
    }

    #[test]
    fn a_reset_child_loses_what_privilege_gave() {
        let rt = Sched { nice: -5, policy: SCHED_FIFO, rt_priority: 50, reset_on_fork: true, ioprio: 0 };
        assert_eq!(rt.child(), Sched::default());
        let fair = Sched { nice: -5, policy: SCHED_BATCH, rt_priority: 0, reset_on_fork: true, ioprio: 0 };
        assert_eq!(fair.child(), Sched { nice: 0, policy: SCHED_BATCH, rt_priority: 0, reset_on_fork: false, ioprio: 0 });
        let kept = Sched { nice: -5, policy: SCHED_FIFO, rt_priority: 50, reset_on_fork: false, ioprio: 0 };
        assert_eq!(kept.child(), kept);
    }

    /// Root sets a real-time policy and reads it back; a thread of another
    /// user's is out of an unprivileged caller's reach; nice goes up
    /// freely and down only within `RLIMIT_NICE`.
    #[test]
    fn the_rules_are_linuxs() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let a2 = t.new_tid(a);
        let root = Creds::new(0, 0);
        let c = cx(&t, a, a, &root);
        assert_eq!(c.setscheduler(0, Some(1), 8, || Ok(10)), Ok(0));
        assert_eq!(c.getscheduler(0), Ok(1));
        assert_eq!(c.getparam(0, 8), Ok(10));
        // the other thread is its own
        assert_eq!(c.getscheduler(a2), Ok(0));
        assert_eq!(c.setscheduler(0, Some(1), 8, || Ok(0)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(0, Some(0), 8, || Ok(1)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(0, Some(1), 8, || Ok(100)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(0, Some(4), 8, || Ok(0)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(0, Some(6), 8, || Ok(0)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(0, Some(1), 0, || Ok(5)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(-1, Some(1), 8, || Ok(5)), Err(Errno::EINVAL));
        assert_eq!(c.setscheduler(99999, Some(1), 8, || Ok(5)), Err(Errno::ESRCH));
        assert_eq!(c.setscheduler(0, Some(SCHED_RESET_ON_FORK as i32 | 2), 8, || Ok(3)), Ok(0));
        assert_eq!(c.getscheduler(0), Ok(2 | SCHED_RESET_ON_FORK as u64));
        // setparam keeps the policy and the flag
        assert_eq!(c.setscheduler(0, None, 8, || Ok(4)), Ok(0));
        assert_eq!(c.getscheduler(0), Ok(2 | SCHED_RESET_ON_FORK as u64));
        assert_eq!(c.getparam(0, 8), Ok(4));

        // an unprivileged process of uid 1000
        let b = t.spawn(INIT_PID);
        let user = Creds::new(1000, 1000);
        t.set_creds(b, &user.save());
        let u = cx(&t, b, b, &user);
        assert_eq!(u.setscheduler(0, Some(1), 8, || Ok(1)), Err(Errno::EPERM));
        assert_eq!(u.setscheduler(0, Some(3), 8, || Ok(0)), Ok(0));
        assert_eq!(u.setscheduler(0, Some(5), 8, || Ok(0)), Ok(0));
        // leaving SCHED_IDLE is a nice reduction
        assert_eq!(u.setscheduler(0, Some(0), 8, || Ok(0)), Err(Errno::EPERM));
        assert_eq!(u.setpriority(PRIO_PROCESS, 0, 5), Ok(0));
        assert_eq!(u.getpriority(PRIO_PROCESS, 0), Ok(15));
        assert_eq!(u.setpriority(PRIO_PROCESS, 0, 3), Err(Errno::EACCES));
        assert_eq!(u.setpriority(PRIO_PROCESS, 0, 100), Ok(0));
        assert_eq!(u.getpriority(PRIO_PROCESS, 0), Ok(1));
        // root's process is not its own
        t.set_creds(a, &root.save());
        assert_eq!(u.setpriority(PRIO_PROCESS, a, 10), Err(Errno::EPERM));
        assert_eq!(u.setscheduler(a, Some(0), 8, || Ok(0)), Err(Errno::EPERM));
        assert_eq!(u.getpriority(PRIO_PROCESS, a), Ok(20));
        assert_eq!(u.getpriority(PRIO_PROCESS, 99999), Err(Errno::ESRCH));
        assert_eq!(u.getpriority(3, 0), Err(Errno::EINVAL));
        // root lowers anyone's
        assert_eq!(c.setpriority(PRIO_PROCESS, b, -10), Ok(0));
        assert_eq!(u.getpriority(PRIO_PROCESS, 0), Ok(30));
        // by user: every task of uid 1000's processes
        assert_eq!(c.setpriority(PRIO_USER, 1000, 7), Ok(0));
        assert_eq!(c.getpriority(PRIO_USER, 1000), Ok(13));
        assert_eq!(c.getpriority(PRIO_USER, 4242), Err(Errno::ESRCH));
    }

    /// I/O priorities: set and read raw for one task, derived from nice
    /// and policy for a group; who may set what; a child's copy.
    #[test]
    fn io_priorities_are_linuxs() {
        let t = ProcTable::new();
        let a = t.spawn(INIT_PID);
        let root = Creds::new(0, 0);
        let c = cx(&t, a, a, &root);
        let be = |level: i32| (2 << 13 | level) as i32;
        assert_eq!(c.ioprio_get(IOPRIO_WHO_PROCESS, 0), Ok(0));
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, 0, be(6)), Ok(0));
        assert_eq!(c.ioprio_get(IOPRIO_WHO_PROCESS, 0), Ok(be(6) as u64));
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, 0, 1), Err(Errno::EINVAL), "class none at a level");
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, 0, 4 << 13), Err(Errno::EINVAL), "class 4");
        assert_eq!(c.ioprio_set(4, 0, be(0)), Err(Errno::EINVAL));
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, 99999, be(0)), Err(Errno::ESRCH));
        assert_eq!(c.ioprio_get(0, 0), Err(Errno::EINVAL));
        // a child keeps a class, not none
        assert_eq!(of(&t, a).child().ioprio, be(6) as u16);
        assert_eq!(Sched { ioprio: 8, ..Sched::default() }.child().ioprio, 0);
        // none, read for a group: best effort at (nice + 20) / 5, the best
        // (lowest) of the group's; pid 1, in the same group, is at nice 0
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, 0, 0), Ok(0));
        assert_eq!(c.setpriority(PRIO_PROCESS, 0, 10), Ok(0));
        let e = t.entries().into_iter().find(|e| e.pid == a).unwrap();
        assert!(t.entries().iter().any(|o| o.pid == INIT_PID && o.pgid == e.pgid));
        assert_eq!(c.ioprio_get(IOPRIO_WHO_PGRP, e.pgid), Ok((2 << 13 | 4) as u64));
        assert_eq!(c.setpriority(PRIO_PROCESS, INIT_PID, 15), Ok(0));
        assert_eq!(c.ioprio_get(IOPRIO_WHO_PGRP, e.pgid), Ok((2 << 13 | 6) as u64));
        // the user's: uid 1000 may not take real-time
        let b = t.spawn(INIT_PID);
        let user = Creds::new(1000, 1000);
        t.set_creds(b, &user.save());
        t.set_creds(a, &root.save());
        let u = cx(&t, b, b, &user);
        assert_eq!(u.ioprio_set(IOPRIO_WHO_PROCESS, 0, 1 << 13), Err(Errno::EPERM));
        assert_eq!(u.ioprio_set(IOPRIO_WHO_PROCESS, 0, 3 << 13), Ok(0));
        assert_eq!(u.ioprio_set(IOPRIO_WHO_PROCESS, a, be(1)), Err(Errno::EPERM));
        assert_eq!(c.ioprio_set(IOPRIO_WHO_PROCESS, b, 1 << 13 | 2), Ok(0));
        assert_eq!(u.ioprio_get(IOPRIO_WHO_PROCESS, 0), Ok((1 << 13 | 2) as u64));
        assert_eq!(u.ioprio_get(IOPRIO_WHO_USER, 0), Ok((1 << 13 | 2) as u64));
        assert_eq!(c.ioprio_set(IOPRIO_WHO_USER, -1, be(0)), Err(Errno::ESRCH));
    }

    #[test]
    fn priority_bounds_are_linuxs() {
        assert_eq!(priority_bound(1, true), Ok(99));
        assert_eq!(priority_bound(2, false), Ok(1));
        assert_eq!(priority_bound(7, true), Ok(0));
        assert_eq!(priority_bound(4, true), Err(Errno::EINVAL));
        assert_eq!(priority_bound(-1, false), Err(Errno::EINVAL));
    }
}
