//! AArch64 instructions the host carries out for translated code.

use crate::{Errno, GuestMem};
use gex_abi::{ctx, pair_op};

/// One sixteen-byte atomic (`gex_abi::pair_op`) for the thread at
/// `ctx_addr`: an X-register `ldxp`, `stxp` or `casp` at `addr`, on the
/// registers `regs` names, 31 being the zero register.
///
/// Under one lock for every one of them on every thread (wasm has no
/// sixteen-byte atomic), so they are atomic against one another. That is
/// every access a sixteen-byte atomic object gets from code built for a CPU
/// with these features and no more, which is what gex reports itself as: a
/// compiler's load and store of one are exclusive pairs or a `casp`. They
/// are not atomic against an eight-byte access to either half.
///
/// The translated code has already faulted for an address that is
/// misaligned or not the guest's, so an error here means the memory went
/// away in between; the caller must not carry on as if the instruction ran.
pub fn serve_pair(m: &mut GuestMem<'_>, ctx_addr: u64, op: u32, regs: [u8; 3], addr: u64) -> Result<(), Errno> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOCK: AtomicBool = AtomicBool::new(false);
    // The monitor keeps the address as the register held it, as `ldxr`'s
    // does; memory is reached without the tag.
    let at = crate::untagged_addr(addr);
    while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        std::hint::spin_loop();
    }
    let done = pair_locked(m, ctx_addr, op, regs, addr, at);
    LOCK.store(false, Ordering::Release);
    done
}

fn pair_locked(m: &mut GuestMem<'_>, c: u64, op: u32, [r0, r1, r2]: [u8; 3], addr: u64, at: u64) -> Result<(), Errno> {
    let get = |m: &GuestMem<'_>, r: u8| if r == 31 { Ok(0) } else { m.read_u64(c + ctx::x(r) as u64) };
    let set = |m: &mut GuestMem<'_>, r: u8, v: u64| if r == 31 { Ok(()) } else { m.write_u64(c + ctx::x(r) as u64, v) };
    let (lo, hi) = (m.read_u64(at)?, m.read_u64(at + 8)?);
    match op {
        pair_op::LOAD => {
            m.write_u64(c + ctx::MON_ADDR as u64, addr)?;
            m.write_u64(c + ctx::MON_VALUE as u64, lo)?;
            m.write_u64(c + ctx::MON_VALUE_HI as u64, hi)?;
            m.write_u64(c + ctx::MON_SIZE as u64, 16)?;
            set(m, r0, lo)?;
            set(m, r1, hi)
        }
        pair_op::STORE => {
            let armed = m.read_u64(c + ctx::MON_ADDR as u64)? == addr && m.read_u64(c + ctx::MON_SIZE as u64)? == 16;
            let same = lo == m.read_u64(c + ctx::MON_VALUE as u64)? && hi == m.read_u64(c + ctx::MON_VALUE_HI as u64)?;
            let (first, second) = (get(m, r1)?, get(m, r2)?);
            if armed && same {
                m.write_u64(at, first)?;
                m.write_u64(at + 8, second)?;
            }
            // The monitor is cleared either way; the status is a W register.
            m.write_u64(c + ctx::MON_SIZE as u64, 0)?;
            set(m, r0, !(armed && same) as u64)
        }
        pair_op::CAS => {
            let next = |r: u8| if r >= 30 { 31 } else { r + 1 };
            if lo == get(m, r0)? && hi == get(m, next(r0))? {
                let (first, second) = (get(m, r1)?, get(m, next(r1))?);
                m.write_u64(at, first)?;
                m.write_u64(at + 8, second)?;
            }
            // The pair receives what was there, swapped or not.
            set(m, r0, lo)?;
            set(m, next(r0), hi)
        }
        _ => Err(Errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: u64 = 0x1000;
    const AT: u64 = 0x4000;

    fn x(m: &GuestMem<'_>, r: u8) -> u64 {
        m.read_u64(CTX + ctx::x(r) as u64).unwrap()
    }
    fn set_x(m: &mut GuestMem<'_>, r: u8, v: u64) {
        m.write_u64(CTX + ctx::x(r) as u64, v).unwrap();
    }
    fn pair(m: &GuestMem<'_>) -> (u64, u64) {
        (m.read_u64(AT).unwrap(), m.read_u64(AT + 8).unwrap())
    }
    fn set_pair(m: &mut GuestMem<'_>, lo: u64, hi: u64) {
        m.write_u64(AT, lo).unwrap();
        m.write_u64(AT + 8, hi).unwrap();
    }

    #[test]
    fn casp_swaps_only_an_equal_pair_and_always_returns_the_old_one() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        set_pair(&mut m, 1, 2);
        for (r, v) in [(0, 1), (1, 2), (2, 30), (3, 40)] {
            set_x(&mut m, r, v);
        }
        serve_pair(&mut m, CTX, pair_op::CAS, [0, 2, 31], AT).unwrap();
        assert_eq!(pair(&m), (30, 40));
        assert_eq!((x(&m, 0), x(&m, 1)), (1, 2));
        // The second half differs: nothing stored, the pair read back.
        set_x(&mut m, 0, 30);
        set_x(&mut m, 1, 41);
        serve_pair(&mut m, CTX, pair_op::CAS, [0, 2, 31], AT).unwrap();
        assert_eq!(pair(&m), (30, 40));
        assert_eq!((x(&m, 0), x(&m, 1)), (30, 40));
        // So does the first.
        set_x(&mut m, 0, 31);
        serve_pair(&mut m, CTX, pair_op::CAS, [0, 2, 31], AT).unwrap();
        assert_eq!(pair(&m), (30, 40));
        assert_eq!((x(&m, 0), x(&m, 1)), (30, 40));
    }

    /// `casp x30, xzr, x28, x29`: the register after x30 is the zero
    /// register, not the stack pointer whose slot follows x30's.
    #[test]
    fn casp_reads_and_discards_the_zero_register() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        let sp = CTX + ctx::SP as u64;
        m.write_u64(sp, 0x7000).unwrap();
        set_pair(&mut m, 5, 0);
        for (r, v) in [(30, 5), (28, 8), (29, 9)] {
            set_x(&mut m, r, v);
        }
        serve_pair(&mut m, CTX, pair_op::CAS, [30, 28, 31], AT).unwrap();
        assert_eq!(pair(&m), (8, 9));
        // The old second half, 0 then 9, goes nowhere.
        set_x(&mut m, 30, 8);
        serve_pair(&mut m, CTX, pair_op::CAS, [30, 28, 31], AT).unwrap();
        assert_eq!(pair(&m), (8, 9));
        assert_eq!(x(&m, 30), 8);
        assert_eq!(m.read_u64(sp).unwrap(), 0x7000);
    }

    #[test]
    fn an_exclusive_pair_stores_only_what_it_loaded() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        set_pair(&mut m, 1, 2);
        serve_pair(&mut m, CTX, pair_op::LOAD, [4, 5, 31], AT).unwrap();
        assert_eq!((x(&m, 4), x(&m, 5)), (1, 2));
        set_x(&mut m, 6, 10);
        set_x(&mut m, 7, 20);
        set_x(&mut m, 8, 0xdead_beef_0000_0007);
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], AT).unwrap();
        assert_eq!((pair(&m), x(&m, 8)), ((10, 20), 0));
        // The monitor was cleared: a second store fails.
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], AT).unwrap();
        assert_eq!(x(&m, 8), 1);

        // Only the second doubleword changed since the load, as when a
        // tagged pointer's count moved on under the same pointer.
        serve_pair(&mut m, CTX, pair_op::LOAD, [4, 5, 31], AT).unwrap();
        set_pair(&mut m, 10, 21);
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], AT).unwrap();
        assert_eq!((pair(&m), x(&m, 8)), ((10, 21), 1));

        // Another address, and an eight-byte monitor, are not this pair's.
        serve_pair(&mut m, CTX, pair_op::LOAD, [4, 5, 31], AT).unwrap();
        set_pair(&mut m, 3, 4);
        m.write_u64(AT + 16, 10).unwrap();
        m.write_u64(AT + 24, 21).unwrap();
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], AT + 16).unwrap();
        assert_eq!(x(&m, 8), 1);
        serve_pair(&mut m, CTX, pair_op::LOAD, [4, 5, 31], AT).unwrap();
        m.write_u64(CTX + ctx::MON_SIZE as u64, 8).unwrap();
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], AT).unwrap();
        assert_eq!((pair(&m), x(&m, 8)), ((3, 4), 1));
    }

    /// `ldxp xzr, x1, [x2]` and `stxp w0, xzr, x1, [x2]`.
    #[test]
    fn an_exclusive_pair_takes_the_zero_register() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        let sp = CTX + ctx::SP as u64;
        m.write_u64(sp, 0x7000).unwrap();
        set_pair(&mut m, 1, 2);
        serve_pair(&mut m, CTX, pair_op::LOAD, [31, 1, 31], AT).unwrap();
        assert_eq!((x(&m, 1), m.read_u64(sp).unwrap()), (2, 0x7000));
        serve_pair(&mut m, CTX, pair_op::STORE, [0, 31, 1], AT).unwrap();
        assert_eq!((pair(&m), x(&m, 0)), ((0, 2), 0));
    }

    /// The top byte of the address is a tag: the memory is the same, and
    /// the monitor compares the address as the register holds it.
    #[test]
    fn a_tagged_address_reaches_the_same_pair() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        let tagged = AT | 0xb4 << 56;
        set_pair(&mut m, 1, 2);
        serve_pair(&mut m, CTX, pair_op::LOAD, [4, 5, 31], tagged).unwrap();
        assert_eq!((x(&m, 4), x(&m, 5)), (1, 2));
        set_x(&mut m, 6, 10);
        set_x(&mut m, 7, 20);
        serve_pair(&mut m, CTX, pair_op::STORE, [8, 6, 7], tagged).unwrap();
        assert_eq!((pair(&m), x(&m, 8)), ((10, 20), 0));
    }

    #[test]
    fn memory_that_is_not_there_is_an_error() {
        let mut bytes = vec![0u8; 0x8000];
        let mut m = GuestMem::new(&mut bytes);
        assert!(serve_pair(&mut m, CTX, pair_op::CAS, [0, 2, 31], 0x10_0000).is_err());
        // And the lock was given back.
        set_pair(&mut m, 0, 0);
        serve_pair(&mut m, CTX, pair_op::CAS, [0, 2, 31], AT).unwrap();
    }
}
