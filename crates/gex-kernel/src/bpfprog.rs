//! `BPF_PROG_LOAD`: a BPF program checked and kept (`kernel/bpf/syscall.c`'s
//! `bpf_prog_load`, the parts of `kernel/bpf/verifier.c` that hold a
//! program's form, at android17-6.18).
//!
//! What is checked is what can be checked of a program without running
//! the kernel's verifier's simulation of it: each instruction's encoding
//! (class, operation, operand form, the fields that must be zero, shifts
//! and divisions by a constant), registers in range and the frame pointer
//! never written (`EACCES`), every jump inside the program and not into
//! the second half of a 64-bit load, the last instruction an exit or a
//! jump, every instruction reachable, no register read on any path before
//! it is written (`R%d !read_ok`, `EACCES`), the maps a 64-bit load names
//! (`EBADF` for a descriptor that is not open, `EINVAL` for one that is not
//! a map), the helpers called (those gex has; any other is said and
//! refused), GPL-only helpers only from a GPL program, the attach types the
//! kernel holds a program to. What the verifier would refuse beyond that
//! (an access out of a map value's bounds, a pointer leaked, a loop not
//! shown to end) is not refused here: the interpreter that runs a program
//! checks what it does as it does it.

use crate::bpf::Map;
use crate::errno::Errno;
use std::sync::Arc;

/// Program types (`enum bpf_prog_type`).
pub mod prog_type {
    pub const SOCKET_FILTER: u32 = 1;
    pub const KPROBE: u32 = 2;
    pub const SCHED_CLS: u32 = 3;
    pub const SCHED_ACT: u32 = 4;
    pub const TRACEPOINT: u32 = 5;
    pub const XDP: u32 = 6;
    pub const CGROUP_SKB: u32 = 8;
    pub const CGROUP_SOCK: u32 = 9;
    pub const SOCK_OPS: u32 = 13;
    pub const CGROUP_SOCK_ADDR: u32 = 18;
    pub const CGROUP_SOCKOPT: u32 = 25;
    pub const SK_LOOKUP: u32 = 30;
    pub const SK_REUSEPORT: u32 = 21;
    pub const SYSCALL: u32 = 31;
    pub const EXT: u32 = 28;
    pub const NETFILTER: u32 = 32;
    /// The last the kernel knows.
    pub const MAX: u32 = 32;
}

/// Attach types a program may be loaded expecting (`enum bpf_attach_type`).
pub mod attach {
    pub const INET_INGRESS: u32 = 0;
    pub const INET_EGRESS: u32 = 1;
    pub const INET_SOCK_CREATE: u32 = 2;
    pub const INET4_BIND: u32 = 8;
    pub const INET6_BIND: u32 = 9;
    pub const INET4_CONNECT: u32 = 10;
    pub const INET6_CONNECT: u32 = 11;
    pub const INET4_POST_BIND: u32 = 12;
    pub const INET6_POST_BIND: u32 = 13;
    pub const UDP4_SENDMSG: u32 = 14;
    pub const UDP6_SENDMSG: u32 = 15;
    pub const UDP4_RECVMSG: u32 = 19;
    pub const UDP6_RECVMSG: u32 = 20;
    pub const GETSOCKOPT: u32 = 21;
    pub const SETSOCKOPT: u32 = 22;
    pub const INET4_GETPEERNAME: u32 = 29;
    pub const INET6_GETPEERNAME: u32 = 30;
    pub const INET4_GETSOCKNAME: u32 = 31;
    pub const INET6_GETSOCKNAME: u32 = 32;
    pub const XDP_DEVMAP: u32 = 33;
    pub const INET_SOCK_RELEASE: u32 = 34;
    pub const SK_LOOKUP: u32 = 36;
    pub const SK_REUSEPORT_SELECT: u32 = 39;
    pub const SK_REUSEPORT_SELECT_OR_MIGRATE: u32 = 40;
    pub const NETFILTER: u32 = 45;
    pub const UNIX_CONNECT: u32 = 49;
    pub const UNIX_SENDMSG: u32 = 50;
    pub const UNIX_RECVMSG: u32 = 51;
    pub const UNIX_GETPEERNAME: u32 = 52;
    pub const UNIX_GETSOCKNAME: u32 = 53;
}

/// The helpers gex has: Android's networking programs' (`Connectivity/bpf`):
/// id, name, and whether only a GPL program may call it.
pub const HELPERS: &[(i32, &str, bool)] = &[
    (1, "map_lookup_elem", false),
    (2, "map_update_elem", false),
    (3, "map_delete_elem", false),
    (4, "probe_read", true),
    (5, "ktime_get_ns", false),
    (6, "trace_printk", true),
    (8, "get_smp_processor_id", false),
    (9, "skb_store_bytes", false),
    (10, "l3_csum_replace", false),
    (11, "l4_csum_replace", false),
    (14, "get_current_pid_tgid", false),
    (15, "get_current_uid_gid", false),
    (16, "get_current_comm", false),
    (23, "redirect", false),
    (26, "skb_load_bytes", false),
    (27, "get_stackid", true),
    (28, "csum_diff", false),
    (31, "skb_change_proto", false),
    (39, "skb_pull_data", false),
    (40, "csum_update", false),
    (43, "skb_change_head", false),
    (45, "probe_read_str", true),
    (46, "get_socket_cookie", false),
    (47, "get_socket_uid", false),
    (50, "skb_adjust_room", false),
    (51, "redirect_map", false),
    (59, "sock_ops_cb_flags_set", false),
    (68, "skb_load_bytes_relative", false),
    (84, "sk_lookup_tcp", false),
    (85, "sk_lookup_udp", false),
    (86, "sk_release", false),
    (95, "sk_fullsock", false),
    (107, "sk_storage_get", false),
    (108, "sk_storage_delete", false),
    (112, "probe_read_user", true),
    (114, "probe_read_user_str", true),
    (122, "get_netns_cookie", false),
    (125, "ktime_get_boot_ns", false),
    (130, "ringbuf_output", false),
    (131, "ringbuf_reserve", false),
    (132, "ringbuf_submit", false),
    (133, "ringbuf_discard", false),
    (143, "store_hdr_opt", false),
    (144, "reserve_hdr_opt", false),
    (164, "for_each_map_elem", false),
    (187, "set_retval", false),
];

/// The largest program (`BPF_COMPLEXITY_LIMIT_INSNS`).
pub const MAX_INSNS: u32 = 1_000_000;

/// One instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    pub fn decode(b: &[u8]) -> Insn {
        Insn { code: b[0], dst: b[1] & 0xf, src: b[1] >> 4, off: i16::from_le_bytes([b[2], b[3]]), imm: i32::from_le_bytes(b[4..8].try_into().unwrap()) }
    }
}

/// What a 64-bit load (`BPF_LD | BPF_IMM | BPF_DW`) loads.
#[derive(Debug, Clone)]
pub enum Imm64 {
    /// A constant.
    Value(u64),
    /// A map (`BPF_PSEUDO_MAP_FD`).
    Map(Arc<Map>),
    /// The address of a map's value at an offset (`BPF_PSEUDO_MAP_VALUE`).
    MapValue(Arc<Map>, u32),
}

/// A loaded program.
#[derive(Debug)]
pub struct Prog {
    pub id: u32,
    pub ty: u32,
    pub expected_attach: u32,
    pub name: [u8; 16],
    pub gpl: bool,
    pub insns: Vec<Insn>,
    /// The 64-bit loads, by the index of their first instruction.
    pub imm64: std::collections::BTreeMap<usize, Imm64>,
    pub uid: u32,
}

fn next_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `license_is_gpl_compatible`.
fn gpl_compatible(license: &str) -> bool {
    matches!(license, "GPL" | "GPL v2" | "GPL and additional rights" | "Dual BSD/GPL" | "Dual MIT/GPL" | "Dual MPL/GPL")
}

/// `bpf_prog_load_check_attach`, after `bpf_prog_load_fixup_attach_type`.
pub fn check_attach(ty: u32, expected: u32) -> Result<u32, Errno> {
    use attach::*;
    let expected = match (ty, expected) {
        (prog_type::CGROUP_SOCK, 0) => INET_SOCK_CREATE,
        (prog_type::SK_REUSEPORT, 0) => SK_REUSEPORT_SELECT,
        _ => expected,
    };
    let ok = match ty {
        prog_type::CGROUP_SOCK => matches!(expected, INET_SOCK_CREATE | INET_SOCK_RELEASE | INET4_POST_BIND | INET6_POST_BIND),
        prog_type::CGROUP_SOCK_ADDR => matches!(
            expected,
            INET4_BIND | INET6_BIND | INET4_CONNECT | INET6_CONNECT | UNIX_CONNECT | INET4_GETPEERNAME | INET6_GETPEERNAME | UNIX_GETPEERNAME | INET4_GETSOCKNAME | INET6_GETSOCKNAME | UNIX_GETSOCKNAME | UDP4_SENDMSG | UDP6_SENDMSG | UNIX_SENDMSG | UDP4_RECVMSG | UDP6_RECVMSG | UNIX_RECVMSG
        ),
        prog_type::CGROUP_SKB => matches!(expected, INET_INGRESS | INET_EGRESS),
        prog_type::CGROUP_SOCKOPT => matches!(expected, SETSOCKOPT | GETSOCKOPT),
        prog_type::SK_LOOKUP => expected == SK_LOOKUP,
        prog_type::SK_REUSEPORT => matches!(expected, SK_REUSEPORT_SELECT | SK_REUSEPORT_SELECT_OR_MIGRATE),
        prog_type::NETFILTER => expected == NETFILTER,
        prog_type::SYSCALL | prog_type::EXT => expected == 0,
        _ => true,
    };
    if ok { Ok(expected) } else { Err(Errno::EINVAL) }
}

/// The classes.
const LD: u8 = 0x00;
const LDX: u8 = 0x01;
const ST: u8 = 0x02;
const STX: u8 = 0x03;
const ALU: u8 = 0x04;
const JMP: u8 = 0x05;
const JMP32: u8 = 0x06;
const ALU64: u8 = 0x07;

/// How an instruction uses registers, and where it may go next.
struct Flow {
    reads: u16,
    writes: u16,
    /// After it, these registers hold nothing (a call's r1 to r5).
    clobbers: u16,
    /// Falls through to the next instruction.
    next: bool,
    /// Jumps to this instruction.
    target: Option<usize>,
    /// Takes two instructions (a 64-bit load).
    wide: bool,
}

fn bit(r: u8) -> u16 {
    1 << r
}

/// Check one instruction's form and say how it flows. `i` its index,
/// `n` the program's length.
fn form(insns: &[Insn], i: usize, ty: u32, gpl: bool) -> Result<Flow, Errno> {
    let x = insns[i];
    let n = insns.len();
    let class = x.code & 7;
    let op = x.code & 0xf0;
    let src_reg = x.code & 0x08 != 0;
    let bad = Err(Errno::EINVAL);
    if x.dst > 10 || x.src > 10 {
        return bad;
    }
    let mut f = Flow { reads: 0, writes: 0, clobbers: 0, next: true, target: None, wide: false };
    let jump = |off: i32| -> Result<usize, Errno> {
        let t = i as i64 + off as i64 + 1;
        if t < 0 || t >= n as i64 {
            return Err(Errno::EINVAL);
        }
        Ok(t as usize)
    };
    match class {
        ALU | ALU64 => {
            let wide = class == ALU64;
            match op {
                0x80 => {
                    // NEG.
                    if src_reg || x.src != 0 || x.off != 0 || x.imm != 0 {
                        return bad;
                    }
                    f.reads = bit(x.dst);
                }
                0xd0 => {
                    // END (byte swap): 16, 32 or 64 bits.
                    if x.src != 0 || x.off != 0 || !matches!(x.imm, 16 | 32 | 64) || (wide && src_reg) {
                        return bad;
                    }
                    f.reads = bit(x.dst);
                }
                0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70 | 0x90 | 0xa0 | 0xb0 | 0xc0 => {
                    let mov = op == 0xb0;
                    // `off`: 0, or 1 for a signed division (v4), or a move's
                    // sign extension width (v4).
                    let off_ok = match op {
                        0x30 | 0x90 => matches!(x.off, 0 | 1),
                        0xb0 => x.off == 0 || (src_reg && matches!(x.off, 8 | 16) || (src_reg && wide && x.off == 32)),
                        _ => x.off == 0,
                    };
                    if !off_ok {
                        return bad;
                    }
                    if src_reg {
                        if x.imm != 0 {
                            return bad;
                        }
                        f.reads = bit(x.src) | if mov { 0 } else { bit(x.dst) };
                    } else {
                        if x.src != 0 {
                            return bad;
                        }
                        if matches!(op, 0x30 | 0x90) && x.imm == 0 {
                            return bad;
                        }
                        if matches!(op, 0x60 | 0x70 | 0xc0) && (x.imm < 0 || x.imm >= if wide { 64 } else { 32 }) {
                            return bad;
                        }
                        f.reads = if mov { 0 } else { bit(x.dst) };
                    }
                }
                _ => return bad,
            }
            if x.dst == 10 {
                return Err(Errno::EACCES);
            }
            f.writes = bit(x.dst);
        }
        LD => {
            if x.code == 0x18 {
                // A 64-bit load: the next instruction holds the high half.
                let Some(y) = insns.get(i + 1) else { return bad };
                if y.code != 0 || y.dst != 0 || y.src != 0 || y.off != 0 || x.off != 0 {
                    return bad;
                }
                if x.dst == 10 {
                    return Err(Errno::EACCES);
                }
                f.writes = bit(x.dst);
                f.wide = true;
            } else if matches!(x.code, 0x20 | 0x28 | 0x30 | 0x40 | 0x48 | 0x50) {
                // The old packet loads (`BPF_ABS`, `BPF_IND`), of socket
                // filters and classifiers: from the packet in r6 into r0.
                if !matches!(ty, prog_type::SOCKET_FILTER | prog_type::SCHED_CLS | prog_type::SCHED_ACT) {
                    return bad;
                }
                let ind = x.code & 0xe0 == 0x40;
                if x.dst != 0 || x.off != 0 || (!ind && x.src != 0) {
                    return bad;
                }
                f.reads = bit(6) | if ind { bit(x.src) } else { 0 };
                f.writes = bit(0);
                f.clobbers = 0x3e;
            } else {
                return bad;
            }
        }
        LDX => {
            // Loads from memory, plain or sign-extending (v4).
            if !matches!(x.code, 0x61 | 0x69 | 0x71 | 0x79 | 0x81 | 0x89 | 0x91) || x.imm != 0 {
                return bad;
            }
            if x.dst == 10 {
                return Err(Errno::EACCES);
            }
            f.reads = bit(x.src);
            f.writes = bit(x.dst);
        }
        ST => {
            if !matches!(x.code, 0x62 | 0x6a | 0x72 | 0x7a) || x.src != 0 {
                return bad;
            }
            f.reads = bit(x.dst);
        }
        STX => {
            match x.code {
                0x63 | 0x6b | 0x73 | 0x7b => {
                    if x.imm != 0 {
                        return bad;
                    }
                    f.reads = bit(x.dst) | bit(x.src);
                }
                // Atomics: add, or, and, xor (each with fetch), xchg,
                // cmpxchg.
                0xc3 | 0xdb => {
                    const FETCH: i32 = 1;
                    let ok = matches!(x.imm, 0x00 | 0x40 | 0x50 | 0xa0) || matches!(x.imm, 0x01 | 0x41 | 0x51 | 0xa1) || x.imm == 0xe0 | FETCH || x.imm == 0xf0 | FETCH;
                    if !ok {
                        return bad;
                    }
                    f.reads = bit(x.dst) | bit(x.src);
                    if x.imm == 0xf1 {
                        f.reads |= bit(0);
                        f.writes = bit(0);
                    } else if x.imm & FETCH != 0 {
                        f.writes = bit(x.src);
                    }
                }
                _ => return bad,
            }
        }
        JMP | JMP32 => match op {
            0x00 => {
                // JA: in JMP32, `gotol` with the offset in `imm` (v4).
                if src_reg || x.dst != 0 || x.src != 0 {
                    return bad;
                }
                let off = if class == JMP32 {
                    if x.off != 0 {
                        return bad;
                    }
                    x.imm
                } else {
                    if x.imm != 0 {
                        return bad;
                    }
                    x.off as i32
                };
                f.target = Some(jump(off)?);
                f.next = false;
            }
            0x80 if class == JMP => {
                if src_reg || x.dst != 0 || x.off != 0 {
                    return bad;
                }
                match x.src {
                    0 => {
                        let Some(&(_, name, gpl_only)) = HELPERS.iter().find(|h| h.0 == x.imm) else {
                            crate::bpf::say_once(&format!("helper {} (bpf_func_id)", x.imm));
                            return bad;
                        };
                        if gpl_only && !gpl {
                            let _ = name;
                            return bad;
                        }
                    }
                    // A call of a function in the program.
                    1 => {
                        f.target = Some(jump(x.imm)?);
                    }
                    _ => {
                        crate::bpf::say_once("a call of a kernel function (kfunc)");
                        return bad;
                    }
                }
                f.writes = bit(0);
                f.clobbers = 0x3e;
            }
            0x90 if class == JMP => {
                if src_reg || x.dst != 0 || x.src != 0 || x.off != 0 || x.imm != 0 {
                    return bad;
                }
                f.reads = bit(0);
                f.next = false;
            }
            0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70 | 0xa0 | 0xb0 | 0xc0 | 0xd0 => {
                if src_reg {
                    if x.imm != 0 {
                        return bad;
                    }
                    f.reads = bit(x.dst) | bit(x.src);
                } else {
                    if x.src != 0 {
                        return bad;
                    }
                    f.reads = bit(x.dst);
                }
                f.target = Some(jump(x.off as i32)?);
            }
            _ => return bad,
        },
        _ => unreachable!(),
    }
    Ok(f)
}

/// The program's form, its reachability and its registers' use
/// (`check_cfg`, and the verifier's `!read_ok`).
fn check(insns: &[Insn], ty: u32, gpl: bool) -> Result<(), Errno> {
    let n = insns.len();
    let mut flows: Vec<Option<Flow>> = Vec::with_capacity(n);
    let mut second = vec![false; n];
    let mut i = 0;
    while i < n {
        let f = form(insns, i, ty, gpl)?;
        let wide = f.wide;
        flows.push(Some(f));
        if wide {
            second[i + 1] = true;
            flows.push(None);
            i += 2;
        } else {
            i += 1;
        }
    }
    // Into the middle of a 64-bit load, or off the end.
    for (i, f) in flows.iter().enumerate() {
        let Some(f) = f else { continue };
        if f.target.is_some_and(|t| second[t]) {
            return Err(Errno::EINVAL);
        }
        let after = i + if f.wide { 2 } else { 1 };
        if f.next && after >= n {
            return Err(Errno::EINVAL);
        }
    }
    // The functions: the program, and each a call of one in it begins.
    let mut entries = vec![0usize];
    for (i, f) in flows.iter().enumerate() {
        if let Some(f) = f {
            if insns[i].code == 0x85 && insns[i].src == 1 {
                entries.push(f.target.unwrap());
            }
        }
    }
    // What is reached, and which registers are written on every way to
    // each instruction: r1 (the context, or a function's arguments, r1 to
    // r5) and r10 at an entry.
    let mut known: Vec<Option<u16>> = vec![None; n];
    let mut work: Vec<usize> = Vec::new();
    for &e in &entries {
        let at = if e == 0 { bit(1) | bit(10) } else { 0x3e | bit(10) };
        known[e] = Some(known[e].map_or(at, |k| k & at));
        work.push(e);
    }
    while let Some(i) = work.pop() {
        let Some(f) = &flows[i] else { continue };
        let have = known[i].unwrap();
        if f.reads & !have != 0 {
            return Err(Errno::EACCES);
        }
        let after = (have & !f.clobbers) | f.writes;
        let call = insns[i].code == 0x85 && insns[i].src == 1;
        let mut go = |t: usize, k: u16| {
            let merged = known[t].map_or(k, |old| old & k);
            if known[t] != Some(merged) {
                known[t] = Some(merged);
                work.push(t);
            }
        };
        if f.next {
            go(i + if f.wide { 2 } else { 1 }, after);
        }
        if let Some(t) = f.target {
            if !call {
                go(t, have);
            }
        }
    }
    if flows.iter().enumerate().any(|(i, f)| f.is_some() && known[i].is_none()) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl Prog {
    /// Check and keep a program. `maps` gives the map a descriptor is:
    /// `Err(EBADF)` for one not open, `Err(EINVAL)` for one that is not a
    /// map.
    pub fn load(ty: u32, expected_attach: u32, raw: &[u8], license: &str, name: [u8; 16], uid: u32, maps: &dyn Fn(i32) -> Result<Arc<Map>, Errno>) -> Result<Prog, Errno> {
        if ty == 0 || ty > prog_type::MAX {
            return Err(Errno::EINVAL);
        }
        let expected = check_attach(ty, expected_attach)?;
        let gpl = gpl_compatible(license);
        let insns: Vec<Insn> = raw.chunks(8).map(Insn::decode).collect();
        check(&insns, ty, gpl)?;
        let mut imm64 = std::collections::BTreeMap::new();
        let mut i = 0;
        while i < insns.len() {
            let x = insns[i];
            if x.code == 0x18 {
                let hi = insns[i + 1].imm as u32 as u64;
                let v = match x.src {
                    0 => Imm64::Value((x.imm as u32 as u64) | hi << 32),
                    1 => Imm64::Map(maps(x.imm)?),
                    2 => {
                        let map = maps(x.imm)?;
                        let off = insns[i + 1].imm as u32;
                        if !map.direct_value() {
                            return Err(crate::btf::ENOTSUPP);
                        }
                        if off >= map.value_size() {
                            return Err(Errno::EINVAL);
                        }
                        Imm64::MapValue(map, off)
                    }
                    other => {
                        crate::bpf::say_once(&format!("a 64-bit load of pseudo kind {other}"));
                        return Err(Errno::EINVAL);
                    }
                };
                imm64.insert(i, v);
                i += 2;
            } else {
                i += 1;
            }
        }
        Ok(Prog { id: next_id(), ty, expected_attach: expected, name, gpl, insns, imm64, uid })
    }

    /// `struct bpf_prog_info`, as far as this kernel fills it.
    pub fn info(&self) -> Vec<u8> {
        let mut b = vec![0u8; 228];
        b[0..4].copy_from_slice(&self.ty.to_le_bytes());
        b[4..8].copy_from_slice(&self.id.to_le_bytes());
        // xlated_prog_len: the instructions as kept.
        b[20..24].copy_from_slice(&((self.insns.len() * 8) as u32).to_le_bytes());
        b[48..52].copy_from_slice(&self.uid.to_le_bytes());
        let maps = self.imm64.values().filter(|v| !matches!(v, Imm64::Value(_))).count() as u32;
        b[52..56].copy_from_slice(&maps.to_le_bytes());
        b[64..80].copy_from_slice(&self.name);
        b
    }
}
