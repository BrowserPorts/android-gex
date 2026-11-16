//! A BPF program compiled: what this kernel runs of it.
//!
//! Android's kernels have the JIT always on (`CONFIG_BPF_JIT_ALWAYS_ON`, and
//! `net.core.bpf_jit_enable` reads 1 and takes nothing else), and Android's
//! loader refuses a program the kernel did not compile (`NetBpfLoad.cpp`:
//! "Kernel eBPF JIT failure" when `jited_prog_len` is 0). Here a program is
//! compiled at load, as `bpf_int_jit_compile` would, into gex's own form
//! rather than a CPU's: each function a list of operations decoded once,
//! with its jumps and calls resolved to operations, its 64-bit loads made
//! one operation holding the map they name, and its helper calls bound.
//! That list is what runs a program (the interpreter that runs it, and the
//! hooks that call it, are the next pieces), and its
//! encoding, sixteen bytes an operation, is the image `BPF_OBJ_GET_INFO_BY_FD`
//! reports and copies out (`jited_prog_len`, `jited_prog_insns`), with each
//! function placed at an address of its own in the kernel's range, as the
//! JIT's images are (`jited_ksyms`).

use crate::bpfprog::{Imm64, Insn};
use crate::errno::Errno;

/// The second operand of an operation: a register, or a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src {
    Reg(u8),
    Imm(i32),
}

/// One operation.
#[derive(Debug, Clone)]
pub enum Op {
    /// Arithmetic (`op` the instruction's operation, `BPF_ADD` to
    /// `BPF_ARSH`), 64 or 32 bits wide; a signed division or remainder
    /// (`off` 1, v4).
    Alu { wide: bool, op: u8, signed: bool, dst: u8, src: Src },
    /// A move, sign-extending from `sx` bits when not 0 (v4).
    Mov { wide: bool, dst: u8, src: Src, sx: u8 },
    Neg { wide: bool, dst: u8 },
    /// A byte order change of `bits`: to little-endian, to big-endian, or
    /// a swap whatever the order (`BPF_ALU64 | BPF_END`, v4).
    End { dst: u8, bits: u8, kind: EndKind },
    /// A 64-bit load: a constant, or a map or the address in its value.
    Imm64 { dst: u8, value: Imm64 },
    /// A load of `size` bytes, sign-extended or not (v4).
    Load { size: u8, signed: bool, dst: u8, src: u8, off: i16 },
    Store { size: u8, dst: u8, src: Src, off: i16 },
    /// An atomic operation (`imm`: add, or, and, xor, each perhaps with
    /// fetch, exchange, compare-and-exchange).
    Atomic { size: u8, op: i32, dst: u8, src: u8, off: i16 },
    /// The old packet loads (`BPF_ABS`, `BPF_IND`) into r0.
    LoadPacket { size: u8, ind: Option<u8>, imm: i32 },
    Jump { to: u32 },
    /// A conditional jump (`cond` the instruction's operation).
    Branch { wide: bool, cond: u8, dst: u8, src: Src, to: u32 },
    Call { helper: i32 },
    /// A call of another of the program's functions, by its number.
    CallLocal { func: u32 },
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndKind {
    ToLe,
    ToBe,
    Swap,
}

/// One function compiled.
#[derive(Debug)]
pub struct Func {
    /// Its first instruction in the program.
    pub start: usize,
    pub ops: Vec<Op>,
    /// The operation each of its instructions begins (the second half of a
    /// 64-bit load: the load's).
    pub op_of: Vec<u32>,
    /// Where its image is in the kernel's range.
    pub addr: u64,
    pub image: Vec<u8>,
}

/// A program compiled: its functions, the program's own first.
#[derive(Debug)]
pub struct Image {
    pub funcs: Vec<Func>,
}

/// The bytes an operation is in an image.
pub const OP_BYTES: usize = 16;

/// Where the next image goes: the start of the range arm64's BPF images
/// are in (`BPF_JIT_REGION_START`, the module area's), each at a multiple of
/// `BPF_PROG_CHUNK_SIZE` (64) as the program pack gives them.
fn place(len: usize) -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0xffff_8000_8000_0000);
    NEXT.fetch_add((len as u64).next_multiple_of(64).max(64), std::sync::atomic::Ordering::Relaxed)
}

fn encode(op: &Op) -> [u8; OP_BYTES] {
    let mut b = [0u8; OP_BYTES];
    let src = |b: &mut [u8; OP_BYTES], s: Src| match s {
        Src::Reg(r) => b[2] = r,
        Src::Imm(i) => {
            b[2] = 0xff;
            b[8..16].copy_from_slice(&(i as i64).to_le_bytes());
        }
    };
    match op {
        Op::Alu { wide, op, signed, dst, src: s } => {
            b[0] = 1;
            b[1] = *dst;
            src(&mut b, *s);
            b[3] = *wide as u8 | (*signed as u8) << 1;
            b[4] = *op;
        }
        Op::Mov { wide, dst, src: s, sx } => {
            b[0] = 2;
            b[1] = *dst;
            src(&mut b, *s);
            b[3] = *wide as u8;
            b[4] = *sx;
        }
        Op::Neg { wide, dst } => {
            b[0] = 3;
            b[1] = *dst;
            b[3] = *wide as u8;
        }
        Op::End { dst, bits, kind } => {
            b[0] = 4;
            b[1] = *dst;
            b[3] = *kind as u8;
            b[4] = *bits;
        }
        Op::Imm64 { dst, value } => {
            b[0] = 5;
            b[1] = *dst;
            let (kind, v) = match value {
                Imm64::Value(v) => (0, *v),
                Imm64::Map(m) => (1, m.id() as u64),
                Imm64::MapValue(m, off) => (2, m.id() as u64 | (*off as u64) << 32),
            };
            b[3] = kind;
            b[8..16].copy_from_slice(&v.to_le_bytes());
        }
        Op::Load { size, signed, dst, src: s, off } => {
            b[0] = 6;
            b[1] = *dst;
            b[2] = *s;
            b[3] = *signed as u8;
            b[4] = *size;
            b[6..8].copy_from_slice(&off.to_le_bytes());
        }
        Op::Store { size, dst, src: s, off } => {
            b[0] = 7;
            b[1] = *dst;
            src(&mut b, *s);
            b[4] = *size;
            b[6..8].copy_from_slice(&off.to_le_bytes());
        }
        Op::Atomic { size, op, dst, src: s, off } => {
            b[0] = 8;
            b[1] = *dst;
            b[2] = *s;
            b[4] = *size;
            b[6..8].copy_from_slice(&off.to_le_bytes());
            b[8..16].copy_from_slice(&(*op as i64).to_le_bytes());
        }
        Op::LoadPacket { size, ind, imm } => {
            b[0] = 9;
            b[2] = ind.unwrap_or(0xff);
            b[4] = *size;
            b[8..16].copy_from_slice(&(*imm as i64).to_le_bytes());
        }
        Op::Jump { to } => {
            b[0] = 10;
            b[8..16].copy_from_slice(&(*to as i64).to_le_bytes());
        }
        Op::Branch { wide, cond, dst, src: s, to } => {
            // The constant in 8..12, the target in 12..16.
            b[0] = 11;
            b[1] = *dst;
            match s {
                Src::Reg(r) => b[2] = *r,
                Src::Imm(i) => {
                    b[2] = 0xff;
                    b[8..12].copy_from_slice(&i.to_le_bytes());
                }
            }
            b[3] = *wide as u8;
            b[4] = *cond;
            b[12..16].copy_from_slice(&to.to_le_bytes());
        }
        Op::Call { helper } => {
            b[0] = 12;
            b[8..16].copy_from_slice(&(*helper as i64).to_le_bytes());
        }
        Op::CallLocal { func } => {
            b[0] = 13;
            b[8..16].copy_from_slice(&(*func as i64).to_le_bytes());
        }
        Op::Exit => b[0] = 14,
    }
    b
}

/// The size of a memory access (`BPF_W`, `BPF_H`, `BPF_B`, `BPF_DW`).
fn size_of(code: u8) -> u8 {
    match code & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    }
}

/// Compile a checked program (`insns` as `crate::bpfprog::check` passed
/// them, `imm64` its 64-bit loads). Its functions begin at `entries`. A
/// jump out of its function, or a function that runs on into the next, is
/// refused as `check_subprogs` refuses them (`EINVAL`).
pub fn compile(insns: &[Insn], imm64: &std::collections::BTreeMap<usize, Imm64>) -> Result<Image, Errno> {
    // The functions: the program, and each one a call in it names.
    let mut entries = vec![0usize];
    for (i, x) in insns.iter().enumerate() {
        if x.code == 0x85 && x.src == 1 {
            entries.push((i as i64 + x.imm as i64 + 1) as usize);
        }
    }
    entries.sort_unstable();
    entries.dedup();
    let n = insns.len();
    let mut funcs = Vec::with_capacity(entries.len());
    for (k, &start) in entries.iter().enumerate() {
        let end = entries.get(k + 1).copied().unwrap_or(n);
        // The last instruction an exit or a jump (`check_subprogs`): the
        // second half of a 64-bit load is never one.
        let last = insns[end - 1];
        if !matches!(last.code, 0x95 | 0x05 | 0x06) {
            return Err(Errno::EINVAL);
        }
        // Each instruction's operation.
        let mut op_of = Vec::with_capacity(end - start);
        let mut count = 0u32;
        let mut i = start;
        while i < end {
            op_of.push(count);
            if imm64.contains_key(&i) {
                op_of.push(count);
                i += 2;
            } else {
                i += 1;
            }
            count += 1;
        }
        let target = |i: usize, off: i64| -> Result<u32, Errno> {
            let t = i as i64 + off + 1;
            if t < start as i64 || t >= end as i64 {
                return Err(Errno::EINVAL);
            }
            Ok(op_of[t as usize - start])
        };
        let mut ops = Vec::with_capacity(count as usize);
        let mut i = start;
        while i < end {
            let x = insns[i];
            let class = x.code & 7;
            let op = x.code & 0xf0;
            let from_reg = x.code & 0x08 != 0;
            let src = if from_reg { Src::Reg(x.src) } else { Src::Imm(x.imm) };
            let o = match class {
                0x04 | 0x07 => {
                    let wide = class == 0x07;
                    match op {
                        0x80 => Op::Neg { wide, dst: x.dst },
                        0xd0 => Op::End {
                            dst: x.dst,
                            bits: x.imm as u8,
                            kind: match (wide, from_reg) {
                                (true, _) => EndKind::Swap,
                                (false, false) => EndKind::ToLe,
                                (false, true) => EndKind::ToBe,
                            },
                        },
                        0xb0 => Op::Mov { wide, dst: x.dst, src, sx: x.off as u8 },
                        _ => Op::Alu { wide, op, signed: x.off == 1, dst: x.dst, src },
                    }
                }
                0x00 if x.code == 0x18 => {
                    let value = imm64.get(&i).cloned().ok_or(Errno::EINVAL)?;
                    i += 1;
                    Op::Imm64 { dst: x.dst, value }
                }
                0x00 => Op::LoadPacket { size: size_of(x.code), ind: (x.code & 0xe0 == 0x40).then_some(x.src), imm: x.imm },
                0x01 => Op::Load { size: size_of(x.code), signed: x.code & 0xe0 == 0x80, dst: x.dst, src: x.src, off: x.off },
                0x02 => Op::Store { size: size_of(x.code), dst: x.dst, src: Src::Imm(x.imm), off: x.off },
                0x03 if x.code & 0xe0 == 0xc0 => Op::Atomic { size: size_of(x.code), op: x.imm, dst: x.dst, src: x.src, off: x.off },
                0x03 => Op::Store { size: size_of(x.code), dst: x.dst, src: Src::Reg(x.src), off: x.off },
                _ => match op {
                    0x00 => Op::Jump { to: target(i, if class == 0x06 { x.imm as i64 } else { x.off as i64 })? },
                    0x80 if x.src == 1 => {
                        let callee = (i as i64 + x.imm as i64 + 1) as usize;
                        Op::CallLocal { func: entries.iter().position(|&e| e == callee).ok_or(Errno::EINVAL)? as u32 }
                    }
                    0x80 => Op::Call { helper: x.imm },
                    0x90 => Op::Exit,
                    cond => Op::Branch { wide: class == 0x05, cond, dst: x.dst, src, to: target(i, x.off as i64)? },
                },
            };
            ops.push(o);
            i += 1;
        }
        let image: Vec<u8> = ops.iter().flat_map(encode).collect();
        funcs.push(Func { start, ops, op_of, addr: place(image.len()), image });
    }
    Ok(Image { funcs })
}

impl Image {
    /// The image's length, all its functions'.
    pub fn len(&self) -> usize {
        self.funcs.iter().map(|f| f.image.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Where the instruction at `insn` begins in the kernel's range: what
    /// a line's record says of where the line was compiled to.
    pub fn addr_of(&self, insn: usize) -> Option<u64> {
        let f = self.funcs.iter().rev().find(|f| f.start <= insn)?;
        let op = *f.op_of.get(insn - f.start)?;
        Some(f.addr + op as u64 * OP_BYTES as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn { code, dst, src, off, imm }
    }

    #[test]
    fn functions_operations_and_places() {
        // r0 = 1 << 32 (two instructions); call the function at 5; if r0
        // == 3 skip one; exit; [5] r0 = 3; exit.
        let insns = [
            i(0x18, 0, 0, 0, 0),
            i(0, 0, 0, 0, 1),
            i(0x85, 0, 1, 0, 2),
            i(0x15, 0, 0, 0, 3),
            i(0x95, 0, 0, 0, 0),
            i(0xb7, 0, 0, 0, 3),
            i(0x95, 0, 0, 0, 0),
        ];
        let mut imm64 = BTreeMap::new();
        imm64.insert(0, Imm64::Value(1 << 32));
        let img = compile(&insns, &imm64).unwrap();
        assert_eq!(img.funcs.len(), 2);
        let (f, g) = (&img.funcs[0], &img.funcs[1]);
        assert_eq!((f.start, f.ops.len(), g.start, g.ops.len()), (0, 4, 5, 2));
        // Both halves of the 64-bit load are its one operation.
        assert_eq!(f.op_of, vec![0, 0, 1, 2, 3]);
        assert!(matches!(f.ops[1], Op::CallLocal { func: 1 }));
        assert!(matches!(f.ops[2], Op::Branch { cond: 0x10, to: 3, src: Src::Imm(3), .. }));
        assert_eq!(img.len(), 6 * OP_BYTES);
        assert_ne!(f.addr, g.addr);
        assert_eq!(img.addr_of(3), Some(f.addr + 2 * OP_BYTES as u64));
        assert_eq!(img.addr_of(6), Some(g.addr + OP_BYTES as u64));
    }

    #[test]
    fn what_check_subprogs_refuses() {
        // A jump from the program into its function.
        let into = [i(0x85, 0, 1, 0, 2), i(0x05, 0, 0, 2, 0), i(0x95, 0, 0, 0, 0), i(0xb7, 0, 0, 0, 1), i(0x95, 0, 0, 0, 0)];
        assert_eq!(compile(&into, &BTreeMap::new()).unwrap_err(), Errno::EINVAL);
        // The program running on into its function.
        let on = [i(0x85, 0, 1, 0, 1), i(0xb7, 0, 0, 0, 0), i(0xb7, 0, 0, 0, 1), i(0x95, 0, 0, 0, 0)];
        assert_eq!(compile(&on, &BTreeMap::new()).unwrap_err(), Errno::EINVAL);
    }
}
