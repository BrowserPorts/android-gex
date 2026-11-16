//! Running a compiled BPF program ([`crate::bpfjit`]'s operations), as the
//! kernel's interpreter and JITs run one (`kernel/bpf/core.c`,
//! `___bpf_prog_run`), for the hooks that call programs and for
//! `BPF_PROG_TEST_RUN`.
//!
//! Registers are 64 bits. A pointer is a region and an offset in it: the
//! stack of each call's frame (512 bytes), the context, the packet, a value
//! a map lookup found, a map itself. Each load and store is checked
//! against its region as it is made: the verifier proves a program's
//! accesses before it runs, which is not done here, so an access it would
//! have refused ends the program here instead (said once, with the
//! program's name). A program that runs on past a budget of operations is
//! ended the same way (the verifier proves every loop ends).
//!
//! Arithmetic is the kernel's: 32-bit operations zero the upper half,
//! division by zero gives 0 and remainder by zero leaves the dividend (as
//! the verifier patches them), a shift by a register is by its low bits.

use crate::bpf::{Map, ValueAt};
use crate::bpfjit::{EndKind, Op, Src};
use crate::bpfprog::{Imm64, Prog};
use crate::errno::Errno;
use std::sync::Arc;

/// Where regions' addresses are: region `n` at `BASE + n << 32`.
const BASE: u64 = 0xffff_8880_0000_0000;

fn addr(region: usize, off: u64) -> u64 {
    BASE + ((region as u64) << 32) + off
}

fn region_of(a: u64) -> Option<(usize, u64)> {
    let d = a.checked_sub(BASE)?;
    Some(((d >> 32) as usize, d & 0xffff_ffff))
}

/// `MAX_BPF_STACK`.
pub const STACK: usize = 512;

/// Operations a run may take before it is taken to be stuck.
const BUDGET: u64 = 1 << 26;

/// What a context field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Scalar(u64),
    /// A pointer into the packet, at this offset from its start.
    Packet(u64),
}

/// What a program runs on, by its type: the context's fields as the
/// verifier would have rewritten each access, the packet, and what the
/// helpers that ask about the context need.
pub trait Context {
    /// The field at `off`, `size` bytes; `None` for one this program may
    /// not read.
    fn load(&mut self, off: u32, size: u8) -> Option<Field>;
    /// `None` for one it may not write.
    fn store(&mut self, off: u32, size: u8, value: u64) -> Option<()>;
    /// The packet's bytes, from its data (what the old packet loads,
    /// `BPF_ABS`, count from) to its end.
    fn packet(&mut self) -> Option<&mut Vec<u8>> {
        None
    }
    /// Whether a program may write the packet's bytes (a classifier may).
    fn packet_writable(&self) -> bool {
        false
    }
    /// `bpf_get_socket_uid` and `bpf_get_socket_cookie`.
    fn socket_uid(&mut self) -> u64 {
        // `overflowuid`, for no socket.
        65534
    }
    fn socket_cookie(&mut self) -> u64 {
        0
    }
}

#[derive(Debug)]
enum Region {
    Stack(Vec<u8>),
    Ctx,
    Packet,
    Value(Arc<Map>, ValueAt),
    Map(Arc<Map>),
}

/// Why a run ended without an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// An access the verifier would have refused, at an operation.
    Access(u32, u64),
    /// Past the budget.
    Stuck,
    /// A helper this kernel does not run.
    Helper(i32),
}

struct Frame {
    func: usize,
    ret: u32,
    saved: [u64; 4],
    stack: usize,
}

struct Machine<'p, 'c> {
    prog: &'p Prog,
    regions: Vec<Region>,
    ctx: &'c mut dyn Context,
}

const PACKET: usize = 1;
const CTX: usize = 0;

impl Machine<'_, '_> {
    fn bad(op: u32, a: u64) -> Fault {
        Fault::Access(op, a)
    }

    fn read(&mut self, op: u32, a: u64, size: u8) -> Result<u64, Fault> {
        let (r, off) = region_of(a).ok_or(Self::bad(op, a))?;
        let n = size as usize;
        let get = |b: &[u8]| -> Option<u64> {
            let s = b.get(off as usize..off as usize + n)?;
            let mut w = [0u8; 8];
            w[..n].copy_from_slice(s);
            Some(u64::from_le_bytes(w))
        };
        let v = match self.regions.get(r).ok_or(Self::bad(op, a))? {
            Region::Stack(b) => get(b),
            Region::Ctx => match self.ctx.load(off as u32, size) {
                Some(Field::Scalar(v)) => Some(v),
                Some(Field::Packet(o)) => Some(addr(PACKET, o)),
                None => None,
            },
            Region::Packet => self.ctx.packet().and_then(|p| get(p)),
            Region::Value(m, at) => m.with_value(at, |v| get(v)).flatten(),
            Region::Map(_) => None,
        };
        v.ok_or(Self::bad(op, a))
    }

    fn write(&mut self, op: u32, a: u64, size: u8, v: u64) -> Result<(), Fault> {
        let (r, off) = region_of(a).ok_or(Self::bad(op, a))?;
        let n = size as usize;
        let put = |b: &mut [u8]| -> Option<()> {
            b.get_mut(off as usize..off as usize + n)?.copy_from_slice(&v.to_le_bytes()[..n]);
            Some(())
        };
        let done = match self.regions.get_mut(r).ok_or(Self::bad(op, a))? {
            Region::Stack(b) => put(b),
            Region::Ctx => self.ctx.store(off as u32, size, v),
            Region::Packet if self.ctx.packet_writable() => self.ctx.packet().and_then(|p| put(p)),
            Region::Packet => None,
            Region::Value(m, at) => m.with_value(at, |v| put(v)).flatten(),
            Region::Map(_) => None,
        };
        done.ok_or(Self::bad(op, a))
    }

    /// `len` bytes at `a`, for a helper.
    fn bytes(&mut self, op: u32, a: u64, len: usize) -> Result<Vec<u8>, Fault> {
        let mut out = Vec::with_capacity(len);
        for k in 0..len {
            out.push(self.read(op, a + k as u64, 1)? as u8);
        }
        Ok(out)
    }

    fn put_bytes(&mut self, op: u32, a: u64, b: &[u8]) -> Result<(), Fault> {
        for (k, &x) in b.iter().enumerate() {
            self.write(op, a + k as u64, 1, x as u64)?;
        }
        Ok(())
    }

    fn map_arg(&self, op: u32, a: u64) -> Result<Arc<Map>, Fault> {
        match region_of(a).and_then(|(r, off)| (off == 0).then(|| self.regions.get(r)).flatten()) {
            Some(Region::Map(m)) => Ok(Arc::clone(m)),
            _ => Err(Self::bad(op, a)),
        }
    }

    fn helper(&mut self, op: u32, id: i32, r: &[u64; 11]) -> Result<u64, Fault> {
        let err = |e: Errno| (-(e.0 as i64)) as u64;
        Ok(match id {
            // map_lookup_elem, map_update_elem, map_delete_elem.
            1 => {
                let m = self.map_arg(op, r[1])?;
                let key = self.bytes(op, r[2], m.key_size() as usize)?;
                match m.find(&key) {
                    Some(at) => {
                        self.regions.push(Region::Value(m, at));
                        addr(self.regions.len() - 1, 0)
                    }
                    None => 0,
                }
            }
            2 => {
                let m = self.map_arg(op, r[1])?;
                let key = self.bytes(op, r[2], m.key_size() as usize)?;
                let value = self.bytes(op, r[3], m.value_size() as usize)?;
                match m.update(&key, &value, r[4]) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            3 => {
                let m = self.map_arg(op, r[1])?;
                let key = self.bytes(op, r[2], m.key_size() as usize)?;
                match m.delete(&key) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            // ktime_get_ns, ktime_get_boot_ns: the monotonic clock, and
            // the boot clock (the same here: nothing is suspended).
            5 => crate::syscalls::clock_ns(crate::syscalls::system_clock, 1),
            125 => crate::syscalls::clock_ns(crate::syscalls::system_clock, 7),
            // get_smp_processor_id.
            8 => 0,
            // skb_load_bytes(skb, offset, to, len): -EFAULT and the
            // destination zeroed when the packet has not that much.
            26 => {
                let (off, to, len) = (r[2] as u32 as usize, r[3], r[4] as u32 as usize);
                let got = self.ctx.packet().and_then(|p| p.get(off..off.checked_add(len)?).map(<[u8]>::to_vec));
                match got {
                    Some(b) => {
                        self.put_bytes(op, to, &b)?;
                        0
                    }
                    None => {
                        self.put_bytes(op, to, &vec![0; len])?;
                        err(Errno::EFAULT)
                    }
                }
            }
            46 => self.ctx.socket_cookie(),
            47 => self.ctx.socket_uid(),
            other => return Err(Fault::Helper(other)),
        })
    }

    fn run(&mut self) -> Result<u64, Fault> {
        let funcs = &self.prog.image.funcs;
        let mut r = [0u64; 11];
        self.regions.push(Region::Stack(vec![0; STACK]));
        let mut stack = self.regions.len() - 1;
        r[1] = addr(CTX, 0);
        r[10] = addr(stack, STACK as u64);
        let mut frames: Vec<Frame> = Vec::new();
        let (mut func, mut pc) = (0usize, 0u32);
        let mut budget = BUDGET;
        loop {
            budget = budget.checked_sub(1).ok_or(Fault::Stuck)?;
            let at = pc;
            let o = &funcs[func].ops[pc as usize];
            pc += 1;
            let src = |r: &[u64; 11], s: Src, wide: bool| match s {
                Src::Reg(x) => r[x as usize],
                Src::Imm(i) => {
                    if wide {
                        i as i64 as u64
                    } else {
                        i as u32 as u64
                    }
                }
            };
            match o {
                Op::Alu { wide, op, signed, dst, src: s } => {
                    let d = *dst as usize;
                    let b = src(&r, *s, *wide);
                    r[d] = if *wide { alu64(*op, *signed, r[d], b) } else { alu32(*op, *signed, r[d] as u32, b as u32) as u64 };
                }
                Op::Mov { wide, dst, src: s, sx } => {
                    let b = src(&r, *s, *wide);
                    let v = match sx {
                        8 => b as u8 as i8 as i64 as u64,
                        16 => b as u16 as i16 as i64 as u64,
                        32 => b as u32 as i32 as i64 as u64,
                        _ => b,
                    };
                    r[*dst as usize] = if *wide { v } else { v as u32 as u64 };
                }
                Op::Neg { wide, dst } => {
                    let d = *dst as usize;
                    r[d] = if *wide { r[d].wrapping_neg() } else { (r[d] as u32).wrapping_neg() as u64 };
                }
                Op::End { dst, bits, kind } => {
                    let d = *dst as usize;
                    let v = r[d];
                    r[d] = match (kind, bits) {
                        (EndKind::ToLe, 16) => v as u16 as u64,
                        (EndKind::ToLe, 32) => v as u32 as u64,
                        (EndKind::ToLe, _) => v,
                        (_, 16) => (v as u16).swap_bytes() as u64,
                        (_, 32) => (v as u32).swap_bytes() as u64,
                        (_, _) => v.swap_bytes(),
                    };
                }
                Op::Imm64 { dst, value } => {
                    r[*dst as usize] = match value {
                        Imm64::Value(v) => *v,
                        Imm64::Map(m) => {
                            self.regions.push(Region::Map(Arc::clone(m)));
                            addr(self.regions.len() - 1, 0)
                        }
                        Imm64::MapValue(m, off) => {
                            self.regions.push(Region::Value(Arc::clone(m), ValueAt::Index(0)));
                            addr(self.regions.len() - 1, *off as u64)
                        }
                    };
                }
                Op::Load { size, signed, dst, src: s, off } => {
                    let a = r[*s as usize].wrapping_add(*off as i64 as u64);
                    let v = self.read(at, a, *size)?;
                    r[*dst as usize] = if *signed {
                        match size {
                            1 => v as u8 as i8 as i64 as u64,
                            2 => v as u16 as i16 as i64 as u64,
                            4 => v as u32 as i32 as i64 as u64,
                            _ => v,
                        }
                    } else {
                        v
                    };
                }
                Op::Store { size, dst, src: s, off } => {
                    let a = r[*dst as usize].wrapping_add(*off as i64 as u64);
                    let v = src(&r, *s, true);
                    self.write(at, a, *size, v)?;
                }
                Op::Atomic { size, op, dst, src: s, off } => {
                    let a = r[*dst as usize].wrapping_add(*off as i64 as u64);
                    let old = self.read(at, a, *size)?;
                    let x = r[*s as usize];
                    let mask = if *size == 8 { u64::MAX } else { u32::MAX as u64 };
                    const FETCH: i32 = 1;
                    let new = match op & !FETCH {
                        0x00 => old.wrapping_add(x),
                        0x40 => old | x,
                        0x50 => old & x,
                        0xa0 => old ^ x,
                        0xe0 => x,
                        // Compare and exchange: with r0.
                        0xf0 => {
                            if old & mask == r[0] & mask {
                                x
                            } else {
                                old
                            }
                        }
                        _ => return Err(Self::bad(at, a)),
                    } & mask;
                    self.write(at, a, *size, new)?;
                    if op & !FETCH == 0xf0 {
                        r[0] = old;
                    } else if op & FETCH != 0 {
                        r[*s as usize] = old;
                    }
                }
                Op::LoadPacket { size, ind, imm } => {
                    // Big-endian, from the packet's data; one that is not
                    // there ends the program with 0.
                    let off = (*imm as i64).wrapping_add(ind.map_or(0, |x| r[x as usize] as u32 as i32 as i64));
                    let n = *size as usize;
                    let got = (off >= 0)
                        .then(|| self.ctx.packet().and_then(|b| b.get(off as usize..off as usize + n).map(<[u8]>::to_vec)))
                        .flatten();
                    let Some(b) = got else { return Ok(0) };
                    let mut w = [0u8; 8];
                    w[8 - n..].copy_from_slice(&b);
                    r[0] = u64::from_be_bytes(w);
                    // The call it is clobbers r1 to r5.
                    for x in &mut r[1..6] {
                        *x = 0;
                    }
                }
                Op::Jump { to } => pc = *to,
                Op::Branch { wide, cond, dst, src: s, to } => {
                    let (a, b) = if *wide { (r[*dst as usize], src(&r, *s, true)) } else { (r[*dst as usize] as u32 as u64, src(&r, *s, true) as u32 as u64) };
                    let (sa, sb) = if *wide { (a as i64, b as i64) } else { (a as u32 as i32 as i64, b as u32 as i32 as i64) };
                    let taken = match cond {
                        0x10 => a == b,
                        0x20 => a > b,
                        0x30 => a >= b,
                        0x40 => a & b != 0,
                        0x50 => a != b,
                        0x60 => sa > sb,
                        0x70 => sa >= sb,
                        0xa0 => a < b,
                        0xb0 => a <= b,
                        0xc0 => sa < sb,
                        0xd0 => sa <= sb,
                        _ => return Err(Self::bad(at, 0)),
                    };
                    if taken {
                        pc = *to;
                    }
                }
                Op::Call { helper } => {
                    r[0] = self.helper(at, *helper, &r)?;
                    for x in &mut r[1..6] {
                        *x = 0;
                    }
                }
                Op::CallLocal { func: f } => {
                    frames.push(Frame { func, ret: pc, saved: [r[6], r[7], r[8], r[9]], stack });
                    self.regions.push(Region::Stack(vec![0; STACK]));
                    stack = self.regions.len() - 1;
                    r[10] = addr(stack, STACK as u64);
                    func = *f as usize;
                    pc = 0;
                }
                Op::Exit => match frames.pop() {
                    None => return Ok(r[0]),
                    Some(fr) => {
                        func = fr.func;
                        pc = fr.ret;
                        [r[6], r[7], r[8], r[9]] = fr.saved;
                        stack = fr.stack;
                        r[10] = addr(stack, STACK as u64);
                    }
                },
            }
        }
    }
}

fn alu64(op: u8, signed: bool, a: u64, b: u64) -> u64 {
    match op {
        0x00 => a.wrapping_add(b),
        0x10 => a.wrapping_sub(b),
        0x20 => a.wrapping_mul(b),
        0x30 if b == 0 => 0,
        0x30 if signed => (a as i64).wrapping_div(b as i64) as u64,
        0x30 => a / b,
        0x40 => a | b,
        0x50 => a & b,
        0x60 => a << (b & 63),
        0x70 => a >> (b & 63),
        0x90 if b == 0 => a,
        0x90 if signed => (a as i64).wrapping_rem(b as i64) as u64,
        0x90 => a % b,
        0xa0 => a ^ b,
        0xc0 => ((a as i64) >> (b & 63)) as u64,
        _ => a,
    }
}

fn alu32(op: u8, signed: bool, a: u32, b: u32) -> u32 {
    match op {
        0x00 => a.wrapping_add(b),
        0x10 => a.wrapping_sub(b),
        0x20 => a.wrapping_mul(b),
        0x30 if b == 0 => 0,
        0x30 if signed => (a as i32).wrapping_div(b as i32) as u32,
        0x30 => a / b,
        0x40 => a | b,
        0x50 => a & b,
        0x60 => a << (b & 31),
        0x70 => a >> (b & 31),
        0x90 if b == 0 => a,
        0x90 if signed => (a as i32).wrapping_rem(b as i32) as u32,
        0x90 => a % b,
        0xa0 => a ^ b,
        0xc0 => ((a as i32) >> (b & 31)) as u32,
        _ => a,
    }
}

/// Run `prog` on `ctx`: its return value, or why it has none.
pub fn run(prog: &Prog, ctx: &mut dyn Context) -> Result<u64, Fault> {
    let mut m = Machine { prog, regions: vec![Region::Ctx, Region::Packet], ctx };
    let r = m.run();
    if let Err(f) = &r {
        let name = String::from_utf8_lossy(&prog.name).trim_end_matches('\0').to_string();
        crate::bpf::note_once(&format!("program {} ({name}) ended: {f:?}", prog.id));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpfprog::{prog_type, Insn};

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn { code, dst, src, off, imm }
    }

    /// Ethernet, IPv4 10.0.0.1 to 10.0.0.2, UDP 1234 to 5678, "hi!!".
    const PKT: [u8; 46] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x0c, 0x00,
        0x00, b'h', b'i', b'!', b'!',
    ];

    fn ret(ty: u32, insns: &[Insn]) -> u32 {
        let raw: Vec<u8> = insns.iter().flat_map(|x| x.encode()).collect();
        let p = Prog::load(ty, 0, &raw, "GPL", [0; 16], 0, None, &|_| Err(Errno::EBADF)).expect("loads");
        let mut skb = crate::bpfskb::for_test(ty, &PKT, None).unwrap();
        run(&p, &mut skb).expect("runs") as u32
    }

    // Each answer is Linux 7.0's (`tests/android/src/bpfrun.c`).
    #[test]
    fn arithmetic_as_the_kernel_does_it() {
        let exit = i(0x95, 0, 0, 0, 0);
        // 100 / 0 and 100 % 0.
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, 100), i(0xb7, 1, 0, 0, 0), i(0x3f, 0, 1, 0, 0), exit]), 0);
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, 100), i(0xb7, 1, 0, 0, 0), i(0x9f, 0, 1, 0, 0), exit]), 100);
        // -1, plus 2 in 32 bits, its top half shifted in.
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, -1), i(0x04, 0, 0, 0, 2), i(0xbf, 1, 0, 0, 0), i(0x77, 1, 0, 0, 32), i(0x67, 1, 0, 0, 8), i(0x4f, 0, 1, 0, 0), exit]), 1);
        // -16 s>> 2; 1 << 65; -100 s/ 7; -100 s% 7; movsx8 of 0x80.
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, -16), i(0xc7, 0, 0, 0, 2), exit]), 0xffff_fffc);
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, 1), i(0xb7, 1, 0, 0, 65), i(0x6f, 0, 1, 0, 0), exit]), 2);
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, -100), i(0xb7, 1, 0, 0, 7), i(0x3f, 0, 1, 1, 0), exit]), 0xffff_fff2);
        assert_eq!(ret(1, &[i(0xb7, 0, 0, 0, -100), i(0xb7, 1, 0, 0, 7), i(0x9f, 0, 1, 1, 0), exit]), 0xffff_fffe);
        assert_eq!(ret(1, &[i(0xb7, 1, 0, 0, 0x80), i(0xbf, 0, 1, 8, 0), exit]), 0xffff_ff80);
    }

    #[test]
    fn packets_stacks_and_calls() {
        let exit = i(0x95, 0, 0, 0, 0);
        // The IP protocol and the UDP destination port, by the old loads.
        assert_eq!(ret(1, &[i(0xbf, 6, 1, 0, 0), i(0x30, 0, 0, 0, 9), i(0xbf, 7, 0, 0, 0), i(0x28, 0, 0, 0, 22), i(0x67, 0, 0, 0, 8), i(0x4f, 0, 7, 0, 0), exit]), 0x16_2e11);
        // Past the packet: the program ends with 0.
        assert_eq!(ret(1, &[i(0xbf, 6, 1, 0, 0), i(0xb7, 0, 0, 0, 99), i(0x30, 0, 0, 0, 1000), i(0xb7, 0, 0, 0, 55), exit]), 0);
        // A call: 20 * 2 + 1000 + 1, r6 kept across it.
        assert_eq!(
            ret(1, &[i(0xb7, 1, 0, 0, 20), i(0xb7, 6, 0, 0, 1000), i(0x85, 0, 1, 0, 3), i(0x0f, 0, 6, 0, 0), i(0x07, 0, 0, 0, 1), exit, i(0x7a, 10, 0, -8, 5), i(0xbf, 0, 1, 0, 0), i(0x27, 0, 0, 0, 2), i(0xb7, 6, 0, 0, 7), exit]),
            0x411
        );
        // An atomic add and a fetching one on the stack.
        assert_eq!(
            ret(1, &[i(0x7a, 10, 0, -8, 10), i(0xb7, 1, 0, 0, 5), i(0xdb, 10, 1, -8, 0x00), i(0xb7, 2, 0, 0, 3), i(0xdb, 10, 2, -8, 0x01), i(0x79, 0, 10, -8, 0), i(0x67, 0, 0, 0, 8), i(0x4f, 0, 2, 0, 0), exit]),
            0x120f
        );
        // len, protocol, ifindex and pkt_type of a socket filter's packet.
        let _ = prog_type::SOCKET_FILTER;
        assert_eq!(
            ret(1, &[i(0x61, 0, 1, 0, 0), i(0x61, 2, 1, 16, 0), i(0x67, 2, 0, 0, 8), i(0x4f, 0, 2, 0, 0), i(0x61, 2, 1, 40, 0), i(0x67, 2, 0, 0, 24), i(0x4f, 0, 2, 0, 0), i(0x61, 2, 1, 4, 0), i(0x67, 2, 0, 0, 28), i(0x4f, 0, 2, 0, 0), exit]),
            0x100_0820
        );
    }
}
