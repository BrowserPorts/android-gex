//! seccomp, after `kernel/seccomp.c` and classic BPF's checks in
//! `net/core/filter.c` at android17-6.18: strict mode, and filters of
//! classic BPF that see each system call's number, architecture,
//! instruction pointer and arguments (`struct seccomp_data`) and answer
//! what becomes of it. Android needs them: minijail puts its services
//! behind filters (a failure is fatal to them) and the zygote does so for
//! every app.
//!
//! A thread's filters are a chain, newest first, shared with the threads
//! and processes made from it ([`State`]); every filter of the chain runs
//! at each call and the lowest action wins, the newest among equals.
//! Filters are kept across `execve` and never removed. What is not here:
//! `SECCOMP_FILTER_FLAG_NEW_LISTENER` (user notification, refused loudly),
//! the per-architecture cache of always-allowed calls (each filter is run
//! every time, which gives the same answers), and the audit log `LOG`
//! writes to.

use crate::errno::Errno;
use std::sync::Arc;

/// `SECCOMP_MODE_*`: what `PR_GET_SECCOMP` and `/proc/<pid>/status` say.
pub const MODE_DISABLED: u8 = 0;
pub const MODE_STRICT: u8 = 1;
pub const MODE_FILTER: u8 = 2;

/// `seccomp(2)`'s operations.
const SET_MODE_STRICT: u64 = 0;
const SET_MODE_FILTER: u64 = 1;
const GET_ACTION_AVAIL: u64 = 2;
const GET_NOTIF_SIZES: u64 = 3;

/// `SECCOMP_FILTER_FLAG_*`.
const FLAG_TSYNC: u64 = 1;
const FLAG_LOG: u64 = 2;
const FLAG_SPEC_ALLOW: u64 = 4;
const FLAG_NEW_LISTENER: u64 = 8;
const FLAG_TSYNC_ESRCH: u64 = 16;
const FLAG_WAIT_KILLABLE_RECV: u64 = 32;
const FLAG_MASK: u64 = FLAG_TSYNC | FLAG_LOG | FLAG_SPEC_ALLOW | FLAG_NEW_LISTENER | FLAG_TSYNC_ESRCH | FLAG_WAIT_KILLABLE_RECV;

/// `SECCOMP_RET_*`: a filter's answer is an action in the top sixteen
/// bits and data in the low sixteen.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_TRACE: u32 = 0x7ff0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ACTION_FULL: u32 = 0xffff_0000;
const RET_DATA: u32 = 0xffff;

/// `BPF_MAXINSNS`, and `MAX_INSNS_PER_PATH`: a chain's instructions, each
/// filter counted with four more.
const MAX_INSNS: usize = 4096;
const MAX_INSNS_PER_PATH: usize = 32768;
/// `sizeof(struct seccomp_data)`.
const DATA_LEN: u32 = 64;
/// `BPF_MEMWORDS`.
const MEMWORDS: u32 = 16;
/// `MAX_ERRNO`.
const MAX_ERRNO: u32 = 4095;

/// The architectures as the filter sees them (`AUDIT_ARCH_*`).
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;

/// A classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Classic BPF's encoding (include/uapi/linux/bpf_common.h, filter.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const MSH: u16 = 0xa0;
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;
const K: u16 = 0x00;
const X: u16 = 0x08;
const RA: u16 = 0x10;
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;

/// A filter as installed: its instructions after the checks (with
/// seccomp's rewrites), and the filter installed before it.
#[derive(Debug)]
pub struct Filter {
    insns: Vec<Insn>,
    prev: Option<Arc<Filter>>,
}

impl Filter {
    /// The filters of the chain this one heads.
    pub fn count(self: &Arc<Filter>) -> usize {
        let mut n = 0;
        let mut f = Some(self);
        while let Some(x) = f {
            n += 1;
            f = x.prev.as_ref();
        }
        n
    }

    /// Whether `old` is this chain or a part of it (`is_ancestor`).
    fn descends_from(self: &Arc<Filter>, old: &Option<Arc<Filter>>) -> bool {
        let Some(old) = old else { return true };
        let mut f = Some(self);
        while let Some(x) = f {
            if Arc::ptr_eq(x, old) {
                return true;
            }
            f = x.prev.as_ref();
        }
        false
    }
}

/// A thread's seccomp (`task->seccomp`): its mode and its filters.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub mode: u8,
    pub filter: Option<Arc<Filter>>,
}

impl State {
    /// How many filters (`Seccomp_filters` in `/proc/<pid>/status`).
    pub fn filters(&self) -> usize {
        self.filter.as_ref().map_or(0, Filter::count)
    }

    /// As bytes, for a state that crosses to another memory
    /// ([`crate::signal::Signals::to_bytes`]): the mode, the count of
    /// filters, then each, newest first, as its length and instructions.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![self.mode];
        v.extend_from_slice(&(self.filters() as u32).to_le_bytes());
        let mut f = self.filter.as_ref();
        while let Some(x) = f {
            v.extend_from_slice(&(x.insns.len() as u32).to_le_bytes());
            for i in &x.insns {
                v.extend_from_slice(&i.code.to_le_bytes());
                v.extend_from_slice(&[i.jt, i.jf]);
                v.extend_from_slice(&i.k.to_le_bytes());
            }
            f = x.prev.as_ref();
        }
        v
    }

    /// From [`State::to_bytes`]; none at all is no seccomp. `None` for
    /// bytes that are not one.
    pub fn from_bytes(b: &[u8]) -> Option<State> {
        if b.is_empty() {
            return Some(State::default());
        }
        let u32_at = |at: usize| b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()));
        let mode = b[0];
        let count = u32_at(1)? as usize;
        let mut at = 5;
        let mut lists = Vec::with_capacity(count);
        for _ in 0..count {
            let n = u32_at(at)? as usize;
            at += 4;
            let raw = b.get(at..at.checked_add(n.checked_mul(8)?)?)?;
            at += n * 8;
            lists.push(
                raw.chunks_exact(8)
                    .map(|c| Insn { code: u16::from_le_bytes([c[0], c[1]]), jt: c[2], jf: c[3], k: u32::from_le_bytes(c[4..8].try_into().unwrap()) })
                    .collect::<Vec<_>>(),
            );
        }
        if at != b.len() || mode > MODE_FILTER {
            return None;
        }
        let mut filter = None;
        for insns in lists.into_iter().rev() {
            filter = Some(Arc::new(Filter { insns, prev: filter }));
        }
        Some(State { mode, filter })
    }
}

/// What a filter sees of a call (`struct seccomp_data`).
#[derive(Clone, Copy, Debug)]
pub struct Data {
    pub nr: i32,
    pub arch: u32,
    pub ip: u64,
    pub args: [u64; 6],
}

impl Data {
    /// The 32-bit word at `off` (4-aligned, below 64), in the machine's
    /// order, as `BPF_LD | BPF_W | BPF_ABS` reads it under seccomp.
    fn word(&self, off: u32) -> u32 {
        match off {
            0 => self.nr as u32,
            4 => self.arch,
            8 => self.ip as u32,
            12 => (self.ip >> 32) as u32,
            _ => {
                let a = self.args[((off - 16) / 8) as usize];
                if off % 8 == 0 {
                    a as u32
                } else {
                    (a >> 32) as u32
                }
            }
        }
    }
}

/// `chk_code_allowed`: the codes classic BPF has at all.
fn classic_code(code: u16) -> bool {
    let class = code & 0x07;
    match class {
        LD => matches!(code & !0x07, x if [W | IMM, W | ABS, H | ABS, B | ABS, W | IND, H | IND, B | IND, W | MEM, W | LEN].contains(&x)),
        LDX => matches!(code & !0x07, x if [W | IMM, W | MEM, W | LEN, B | MSH].contains(&x)),
        ST | STX => code & !0x07 == 0,
        ALU => {
            let op = code & 0xf0;
            if op == NEG {
                code & 0x08 == 0
            } else {
                matches!(op, ADD | SUB | MUL | DIV | OR | AND | LSH | RSH | MOD | XOR)
            }
        }
        JMP => {
            let op = code & 0xf0;
            if op == JA {
                code & 0x08 == 0
            } else {
                matches!(op, JEQ | JGT | JGE | JSET)
            }
        }
        RET => matches!(code & !0x07, K | RA),
        MISC => matches!(code & !0x07, TAX | TXA),
        _ => false,
    }
}

/// `bpf_check_classic`, then `check_load_and_stores`, then
/// `seccomp_check_filter`'s list and rewrites: the filter as it will run,
/// or `EINVAL`.
pub fn check(insns: &[Insn]) -> Result<Vec<Insn>, Errno> {
    let n = insns.len();
    if n == 0 || n > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    for (pc, i) in insns.iter().enumerate() {
        if !classic_code(i.code) {
            return Err(Errno::EINVAL);
        }
        let class = i.code & 0x07;
        // An ancillary load (an offset at SKF_AD_OFF, -0x1000, or past)
        // is refused below by seccomp's own offset check.
        match class {
            ALU => {
                let op = i.code & 0xf0;
                if i.code & X == 0 && matches!(op, DIV | MOD) && i.k == 0 {
                    return Err(Errno::EINVAL);
                }
                if i.code & X == 0 && matches!(op, LSH | RSH) && i.k >= 32 {
                    return Err(Errno::EINVAL);
                }
            }
            LD | LDX if i.code & 0xe0 == MEM && i.k >= MEMWORDS => return Err(Errno::EINVAL),
            ST | STX if i.k >= MEMWORDS => return Err(Errno::EINVAL),
            JMP => {
                if i.code & 0xf0 == JA {
                    if i.k as u64 >= (n - pc - 1) as u64 {
                        return Err(Errno::EINVAL);
                    }
                } else if pc + i.jt as usize + 1 >= n || pc + i.jf as usize + 1 >= n {
                    return Err(Errno::EINVAL);
                }
            }
            _ => {}
        }
    }
    if !matches!(insns[n - 1].code, c if c == RET | K || c == RET | RA) {
        return Err(Errno::EINVAL);
    }
    loads_after_stores(insns)?;
    let mut out = Vec::with_capacity(n);
    for i in insns {
        let mut i = *i;
        match i.code {
            c if c == LD | W | ABS => {
                if i.k >= DATA_LEN || i.k & 3 != 0 {
                    return Err(Errno::EINVAL);
                }
            }
            c if c == LD | W | LEN => {
                i.code = LD | IMM;
                i.k = DATA_LEN;
            }
            c if c == LDX | W | LEN => {
                i.code = LDX | IMM;
                i.k = DATA_LEN;
            }
            c if c == RET | K || c == RET | RA => {}
            c if c & 0x07 == ALU && c & 0xf0 != MOD => {}
            c if c == LD | IMM || c == LDX | IMM || c == MISC | TAX || c == MISC | TXA => {}
            c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => {}
            c if c & 0x07 == JMP => {}
            _ => return Err(Errno::EINVAL),
        }
        out.push(i);
    }
    Ok(out)
}

/// `check_load_and_stores`: a scratch word read on some path before any
/// store to it is `EINVAL`.
fn loads_after_stores(insns: &[Insn]) -> Result<(), Errno> {
    let n = insns.len();
    let mut masks = vec![u16::MAX; n];
    let mut valid: u16 = 0;
    for pc in 0..n {
        valid &= masks[pc];
        let i = insns[pc];
        match i.code {
            c if c == ST || c == STX => valid |= 1 << i.k,
            c if c == LD | MEM || c == LDX | MEM => {
                if valid & (1 << i.k) == 0 {
                    return Err(Errno::EINVAL);
                }
            }
            c if c == JMP | JA => {
                masks[pc + 1 + i.k as usize] &= valid;
                valid = u16::MAX;
            }
            c if c & 0x07 == JMP => {
                masks[pc + 1 + i.jt as usize] &= valid;
                masks[pc + 1 + i.jf as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// One checked filter on one call: its answer. A division by a zero X
/// answers 0, as the kernel's translation of classic BPF has it.
fn run_one(insns: &[Insn], d: &Data) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; MEMWORDS as usize];
    let mut pc = 0usize;
    loop {
        let i = insns[pc];
        pc += 1;
        match i.code & 0x07 {
            LD => {
                a = match i.code & 0xe0 {
                    ABS => d.word(i.k),
                    MEM => mem[i.k as usize],
                    _ => i.k,
                }
            }
            LDX => x = if i.code & 0xe0 == MEM { mem[i.k as usize] } else { i.k },
            ST => mem[i.k as usize] = a,
            STX => mem[i.k as usize] = x,
            ALU => {
                let s = if i.code & X != 0 { x } else { i.k };
                a = match i.code & 0xf0 {
                    ADD => a.wrapping_add(s),
                    SUB => a.wrapping_sub(s),
                    MUL => a.wrapping_mul(s),
                    DIV => {
                        if s == 0 {
                            return 0;
                        }
                        a / s
                    }
                    OR => a | s,
                    AND => a & s,
                    LSH => a.wrapping_shl(s),
                    RSH => a.wrapping_shr(s),
                    NEG => a.wrapping_neg(),
                    _ => a ^ s,
                }
            }
            JMP => {
                let s = if i.code & X != 0 { x } else { i.k };
                let taken = match i.code & 0xf0 {
                    JA => {
                        pc += i.k as usize;
                        continue;
                    }
                    JEQ => a == s,
                    JGT => a > s,
                    JGE => a >= s,
                    _ => a & s != 0,
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            RET => return if i.code & RA != 0 { a } else { i.k },
            _ => {
                if i.code & 0xf8 == TXA {
                    a = x;
                } else {
                    x = a;
                }
            }
        }
    }
}

/// `ACTION_ONLY`: the action, compared as a signed number.
fn action_only(ret: u32) -> i32 {
    (ret & RET_ACTION_FULL) as i32
}

/// `seccomp_run_filters`: every filter of the chain, newest first; the
/// lowest action wins, the newest among equals.
pub fn run(filter: &Arc<Filter>, d: &Data) -> u32 {
    let mut ret = RET_ALLOW;
    let mut f = Some(filter);
    while let Some(x) = f {
        let cur = run_one(&x.insns, d);
        if action_only(cur) < action_only(ret) {
            ret = cur;
        }
        f = x.prev.as_ref();
    }
    ret
}

/// What a call becomes under a thread's filters (`__seccomp_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Made as usual (`ALLOW`, `LOG`).
    Allow,
    /// Not made; this is its result (`ERRNO`, `TRACE` and `USER_NOTIF`
    /// with nobody to hand it to).
    Fail(u32),
    /// Not made; `SIGSYS` with `SYS_SECCOMP` and this data as `si_errno`,
    /// the registers as they were.
    Trap(u32),
    /// The thread ends (by `SIGSYS`), the others go on.
    KillThread,
    /// The process ends by `SIGSYS`, with a core.
    KillProcess,
}

/// A filter's answer as what becomes of the call. `last_thread`: the
/// caller is its process's only thread, when `KILL_THREAD` ends the
/// process as `KILL_PROCESS` does.
pub fn verdict(ret: u32, last_thread: bool) -> Verdict {
    let data = ret & RET_DATA;
    match ret & RET_ACTION_FULL {
        RET_ERRNO => Verdict::Fail(data.min(MAX_ERRNO)),
        RET_TRAP => Verdict::Trap(data),
        // No tracer here, and no listener: as Linux with none.
        RET_TRACE | RET_USER_NOTIF => Verdict::Fail(Errno::ENOSYS.0 as u32),
        RET_LOG | RET_ALLOW => Verdict::Allow,
        RET_KILL_THREAD if !last_thread => Verdict::KillThread,
        // KILL_PROCESS, and anything else the kernel does not know.
        _ => Verdict::KillProcess,
    }
}

/// `__secure_computing_strict`'s four calls, by the caller's numbering:
/// `read`, `write`, `exit` and `rt_sigreturn`.
pub fn strict_allows(raw: u64, arch: u32) -> bool {
    match arch {
        AUDIT_ARCH_X86_64 => matches!(raw, 0 | 1 | 60 | 15),
        AUDIT_ARCH_I386 => matches!(raw & 0xffff_ffff, 3 | 4 | 1 | 119 | 173),
        _ => matches!(raw, 63 | 64 | 93 | 139),
    }
}

/// What installing a filter needs from the caller's world.
pub trait Threads {
    /// The calling thread's state.
    fn mine(&self) -> State;
    /// Set the calling thread's state.
    fn set_mine(&self, s: State);
    /// The process's other threads: each one's id and state.
    fn others(&self) -> Vec<(i32, State)>;
    /// Give thread `tid` this state, and `no_new_privs` if `nnp`.
    fn set_other(&self, tid: i32, s: State, nnp: bool);
    /// Whether the caller has `no_new_privs`.
    fn no_new_privs(&self) -> bool;
    /// Whether the caller has `CAP_SYS_ADMIN`.
    fn admin(&self) -> bool;
    /// Read guest memory.
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno>;
    /// Write guest memory.
    fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), Errno>;
    /// The caller's pointers are 32 bits (`struct sock_fprog`'s layout).
    fn compat(&self) -> bool;
    /// For a refusal said once.
    fn pid(&self) -> i32;
}

/// `seccomp(2)` (`do_seccomp`).
pub fn call(t: &dyn Threads, op: u64, flags: u64, uargs: u64) -> Result<u64, Errno> {
    match op {
        SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 {
                return Err(Errno::EINVAL);
            }
            set_strict(t)
        }
        SET_MODE_FILTER => set_filter(t, flags, uargs),
        GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let b = t.read(uargs, 4).map_err(|_| Errno::EFAULT)?;
            let action = u32::from_le_bytes(b[..4].try_into().unwrap());
            match action {
                RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP | RET_ERRNO | RET_USER_NOTIF | RET_TRACE | RET_LOG | RET_ALLOW => Ok(0),
                _ => Err(Errno::EOPNOTSUPP),
            }
        }
        GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            // struct seccomp_notif, seccomp_notif_resp, seccomp_data.
            let mut b = Vec::with_capacity(6);
            for v in [80u16, 24, DATA_LEN as u16] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            t.write(uargs, &b).map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `prctl(PR_SET_SECCOMP, mode, filter)`.
pub fn prctl_set(t: &dyn Threads, mode: u64, filter: u64) -> Result<u64, Errno> {
    match mode {
        1 => call(t, SET_MODE_STRICT, 0, 0),
        2 => call(t, SET_MODE_FILTER, 0, filter),
        _ => Err(Errno::EINVAL),
    }
}

fn set_strict(t: &dyn Threads) -> Result<u64, Errno> {
    let mut s = t.mine();
    if s.mode != MODE_DISABLED && s.mode != MODE_STRICT {
        return Err(Errno::EINVAL);
    }
    s.mode = MODE_STRICT;
    t.set_mine(s);
    Ok(0)
}

fn set_filter(t: &dyn Threads, flags: u64, uargs: u64) -> Result<u64, Errno> {
    if flags & !FLAG_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & FLAG_TSYNC != 0 && flags & FLAG_NEW_LISTENER != 0 && flags & FLAG_TSYNC_ESRCH == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & FLAG_WAIT_KILLABLE_RECV != 0 && flags & FLAG_NEW_LISTENER == 0 {
        return Err(Errno::EINVAL);
    }
    // `struct sock_fprog`: the length, then a pointer to the instructions.
    let (len, ptr) = if t.compat() {
        let b = t.read(uargs, 8).map_err(|_| Errno::EFAULT)?;
        (u16::from_le_bytes([b[0], b[1]]) as usize, u32::from_le_bytes(b[4..8].try_into().unwrap()) as u64)
    } else {
        let b = t.read(uargs, 16).map_err(|_| Errno::EFAULT)?;
        (u16::from_le_bytes([b[0], b[1]]) as usize, u64::from_le_bytes(b[8..16].try_into().unwrap()))
    };
    if len == 0 || len > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    if !t.no_new_privs() && !t.admin() {
        return Err(Errno::EACCES);
    }
    let raw = t.read(ptr, len * 8).map_err(|_| Errno::EFAULT)?;
    let insns: Vec<Insn> = raw
        .chunks_exact(8)
        .map(|c| Insn { code: u16::from_le_bytes([c[0], c[1]]), jt: c[2], jf: c[3], k: u32::from_le_bytes(c[4..8].try_into().unwrap()) })
        .collect();
    let insns = check(&insns)?;
    if flags & FLAG_NEW_LISTENER != 0 {
        static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[gex:{}] seccomp: SECCOMP_FILTER_FLAG_NEW_LISTENER (user notification) is not implemented -> EINVAL", t.pid());
        }
        return Err(Errno::EINVAL);
    }
    let mine = t.mine();
    if mine.mode != MODE_DISABLED && mine.mode != MODE_FILTER {
        return Err(Errno::EINVAL);
    }
    // `seccomp_attach_filter`: the whole path's length.
    let mut total = insns.len();
    let mut f = mine.filter.as_ref();
    while let Some(x) = f {
        total += x.insns.len() + 4;
        f = x.prev.as_ref();
    }
    if total > MAX_INSNS_PER_PATH {
        return Err(Errno::ENOMEM);
    }
    let others = if flags & FLAG_TSYNC != 0 {
        let others = t.others();
        // `seccomp_can_sync_threads`: every other thread has none, or a
        // part of the caller's chain.
        for (tid, s) in &others {
            let fits = s.mode == MODE_DISABLED || (s.mode == MODE_FILTER && mine.filter.as_ref().map_or(s.filter.is_none(), |m| m.descends_from(&s.filter)));
            if !fits {
                return if flags & FLAG_TSYNC_ESRCH != 0 || *tid == 0 { Err(Errno::ESRCH) } else { Ok(*tid as u64) };
            }
        }
        others
    } else {
        Vec::new()
    };
    let new = State { mode: MODE_FILTER, filter: Some(Arc::new(Filter { insns, prev: mine.filter.clone() })) };
    t.set_mine(new.clone());
    let nnp = t.no_new_privs();
    for (tid, _) in others {
        t.set_other(tid, new.clone(), nnp);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(code: u16, k: u32) -> Insn {
        Insn { code, jt: 0, jf: 0, k }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
        Insn { code, jt, jf, k }
    }

    fn data(nr: i32, arg0: u64) -> Data {
        Data { nr, arch: AUDIT_ARCH_AARCH64, ip: 0x1234_5678_9abc, args: [arg0, 0, 0, 0, 0, 0] }
    }

    /// The checks the reference makes, each one refusing.
    #[test]
    fn refuses_what_the_kernel_refuses() {
        let ret = stmt(RET | K, RET_ALLOW);
        assert_eq!(check(&[]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(LD | W | ABS, 0)]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(LD | W | ABS, 64), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(LD | W | ABS, 2), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(LD | B | ABS, 0), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(JMP | JA, 5), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[jump(JMP | JEQ | K, 0, 1, 0), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(LD | MEM, 3), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(ALU | DIV | K, 0), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(ALU | LSH | K, 32), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(ST, 16), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(ALU | MOD | K, 3), ret]), Err(Errno::EINVAL));
        assert_eq!(check(&[stmt(0xffff, 0), ret]), Err(Errno::EINVAL));
        // A store on one path but not the other.
        let half = [jump(JMP | JEQ | K, 0, 0, 1), stmt(ST, 2), stmt(LD | MEM, 2), ret];
        assert_eq!(check(&half), Err(Errno::EINVAL));
        assert!(check(&[stmt(ST, 2), jump(JMP | JEQ | K, 0, 0, 0), stmt(LD | MEM, 2), ret]).is_ok());
        assert!(check(&[ret]).is_ok());
    }

    /// Loads of each word, the arithmetic, len's rewrite, X's division by
    /// zero, and the jumps.
    #[test]
    fn runs_as_the_kernel_does() {
        let d = data(173, 0xdead_beef_0000_0007);
        let words = |off: u32| run_one(&check(&[stmt(LD | W | ABS, off), stmt(RET | RA, 0)]).unwrap(), &d);
        assert_eq!(words(0), 173);
        assert_eq!(words(4), AUDIT_ARCH_AARCH64);
        assert_eq!(words(8), 0x5678_9abc);
        assert_eq!(words(12), 0x1234);
        assert_eq!(words(16), 7);
        assert_eq!(words(20), 0xdead_beef);
        let len = check(&[stmt(LD | W | LEN, 0), stmt(ALU | ADD | K, 1), stmt(RET | RA, 0)]).unwrap();
        assert_eq!(run_one(&len, &d), 65);
        let div0 = check(&[stmt(LD | IMM, 9), stmt(LDX | IMM, 0), stmt(ALU | DIV | X, 0), stmt(RET | K, RET_ALLOW)]).unwrap();
        assert_eq!(run_one(&div0, &d), 0);
        let shift = check(&[stmt(LD | IMM, 1), stmt(LDX | IMM, 33), stmt(ALU | LSH | X, 0), stmt(RET | RA, 0)]).unwrap();
        assert_eq!(run_one(&shift, &d), 2);
        let set = check(&[stmt(LD | IMM, 6), jump(JMP | JSET | K, 4, 0, 1), stmt(RET | K, 1), stmt(RET | K, 2)]).unwrap();
        assert_eq!(run_one(&set, &d), 1);
        let neg = check(&[stmt(LD | IMM, 1), stmt(ALU | NEG, 0), stmt(MISC | TAX, 0), stmt(LD | IMM, 0), stmt(MISC | TXA, 0), stmt(RET | RA, 0)]).unwrap();
        assert_eq!(run_one(&neg, &d), u32::MAX);
    }

    /// The lowest action wins, the newest among equals; the actions'
    /// meanings.
    #[test]
    fn chains_and_verdicts() {
        let errno = |e: u32| Arc::new(Filter { insns: vec![stmt(RET | K, RET_ERRNO | e)], prev: None });
        let old = errno(6);
        let new = Arc::new(Filter { insns: vec![stmt(RET | K, RET_ERRNO | 5)], prev: Some(old.clone()) });
        assert_eq!(run(&new, &data(0, 0)), RET_ERRNO | 5);
        let allow = Arc::new(Filter { insns: vec![stmt(RET | K, RET_ALLOW)], prev: Some(new.clone()) });
        assert_eq!(run(&allow, &data(0, 0)), RET_ERRNO | 5);
        let kill = Arc::new(Filter { insns: vec![stmt(RET | K, RET_KILL_PROCESS)], prev: Some(allow.clone()) });
        assert_eq!(run(&kill, &data(0, 0)), RET_KILL_PROCESS);
        assert_eq!(kill.count(), 4);
        assert!(kill.descends_from(&Some(old.clone())));
        assert!(!old.descends_from(&Some(kill.clone())));
        assert_eq!(verdict(RET_ERRNO | 5000, true), Verdict::Fail(4095));
        assert_eq!(verdict(RET_TRACE | 1, true), Verdict::Fail(Errno::ENOSYS.0 as u32));
        assert_eq!(verdict(RET_TRAP | 9, true), Verdict::Trap(9));
        assert_eq!(verdict(RET_LOG, true), Verdict::Allow);
        assert_eq!(verdict(RET_KILL_THREAD, false), Verdict::KillThread);
        assert_eq!(verdict(RET_KILL_THREAD, true), Verdict::KillProcess);
        assert_eq!(verdict(0x0007_0000, false), Verdict::KillProcess);
    }
}
