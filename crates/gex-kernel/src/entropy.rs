//! Randomness that repeats, for a run that has to (off unless a host asks:
//! [`fix`]).
//!
//! A translation is of code at an address, and is kept by what it is
//! (`gex_cache`): a program whose code lands where it did last time finds
//! its translations made. glibc's loader puts a library where `mmap` says,
//! which here is the same place every run. Android's does not: bionic's
//! linker draws from `arc4random`, seeded by `getrandom`, where in a
//! reservation each library starts and how many 2 MiB of nothing come
//! before it (`ReserveWithAlignmentPadding`, linker_phdr.cpp). So every
//! process of an Android boot had its libraries somewhere new, nothing was
//! ever found made, and each process translated libc and the rest again:
//! half a minute for `sh -c true`.
//!
//! With a seed fixed, what `getrandom` and `/dev/urandom` give is a
//! function of the seed and of who asks, and nothing else:
//!
//! * a process's stream is named at its `execve`, by the program's path and
//!   how many times that path has been run before (the third `toybox` of a
//!   boot reads what the third `toybox` of the last boot read, and not what
//!   the second reads);
//! * a `fork`'s child, until it runs a program, by its parent's stream and
//!   which child of it this is;
//! * a thread's, by its process's and which of its threads to ask this is.
//!
//! No two of them are the same stream, so what programs make of the bytes
//! (names of temporary files, tokens) does not collide as it would with one
//! sequence for everybody. The bytes are no more secret than the seed: this
//! is for a test's oracle and for finding a fault twice, never for a run
//! anything trusts.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The seed; 0 while randomness is the host's own.
static SEED: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Proc {
    /// What names its stream.
    key: u64,
    /// How many of its threads have asked, and how many children it has had.
    threads: u64,
    forks: u64,
}

#[derive(Default)]
struct Table {
    procs: HashMap<i32, Proc>,
    /// How many times each program has been run.
    execs: HashMap<String, u64>,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

thread_local! {
    /// The process whose call this thread is in ([`enter`]).
    static PID: Cell<i32> = const { Cell::new(0) };
    /// This thread's stream: whose it is (a process, and the key it had
    /// when the stream began) and where it has got to.
    static MINE: Cell<(i32, u64, u64)> = const { Cell::new((0, 0, 0)) };
}

const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// FNV-1a of a path: the same number for the same program in every run
/// (std's hasher is seeded anew in each).
fn name(path: &str) -> u64 {
    path.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

fn table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    let mut t = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    f(t.get_or_insert_with(Table::default))
}

/// From now, randomness is a function of `seed` and of who asks (the
/// module's notes). For a host to call before its first program runs; a
/// seed of 0 is taken as 1.
pub fn fix(seed: u64) {
    SEED.store(seed.max(1), Ordering::Relaxed);
}

/// Whether [`fix`] has been called.
pub fn fixed() -> bool {
    SEED.load(Ordering::Relaxed) != 0
}

/// A call of process `pid` begins on this thread. A load when randomness
/// is not fixed.
pub fn enter(pid: i32) {
    if fixed() {
        PID.with(|p| p.set(pid));
    }
}

/// Process `pid` becomes the program at `path`: its stream is that
/// program's, of this many runs of it.
pub fn exec(pid: i32, path: &str) {
    let seed = SEED.load(Ordering::Relaxed);
    if seed == 0 {
        return;
    }
    table(|t| {
        let nth = t.execs.entry(path.to_string()).or_insert(0);
        let key = mix(seed ^ mix(name(path) ^ mix(*nth)));
        *nth += 1;
        t.procs.insert(pid, Proc { key, ..Proc::default() });
    });
}

/// Process `child` is a fork of `parent`: its stream is its parent's
/// child's, of this many children. (A process's number is its own until
/// a fork gives it to another, which is here.)
pub fn fork(parent: i32, child: i32) {
    let seed = SEED.load(Ordering::Relaxed);
    if seed == 0 {
        return;
    }
    table(|t| {
        let p = t.procs.entry(parent).or_insert_with(|| Proc { key: mix(seed ^ mix(parent as u64)), ..Proc::default() });
        p.forks += 1;
        let key = mix(p.key ^ mix(p.forks.wrapping_mul(GOLDEN)));
        t.procs.insert(child, Proc { key, ..Proc::default() });
    });
}

/// Fill `buf` from the calling thread's stream, when randomness is fixed;
/// whether it was.
pub(crate) fn fill(buf: &mut [u8]) -> bool {
    let seed = SEED.load(Ordering::Relaxed);
    if seed == 0 {
        return false;
    }
    let pid = PID.with(|p| p.get());
    let (whose, key, mut x) = MINE.with(|m| m.get());
    // The process's key now: a new stream when this thread has none of
    // that process's yet, or the process has run a program since.
    let fresh = table(|t| {
        let p = t.procs.entry(pid).or_insert_with(|| Proc { key: mix(seed ^ mix(pid as u64)), ..Proc::default() });
        if whose == pid && key == p.key {
            return None;
        }
        let nth = p.threads;
        p.threads += 1;
        Some((p.key, mix(p.key ^ mix(nth.wrapping_add(1).wrapping_mul(GOLDEN)))))
    });
    let key = match fresh {
        Some((k, start)) => {
            x = start;
            k
        }
        None => key,
    };
    for chunk in buf.chunks_mut(8) {
        x = x.wrapping_add(GOLDEN);
        let bytes = mix(x).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    MINE.with(|m| m.set((pid, key, x)));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, since the seed is the whole process's: a program's stream
    /// is the same for the same run of it, whoever ran before; another
    /// run of it, a fork of it and another thread of it each read their
    /// own.
    #[test]
    fn a_fixed_seed_gives_each_program_its_own_stream_again() {
        fn read(pid: i32) -> [u8; 24] {
            let mut b = [0u8; 24];
            enter(pid);
            assert!(fill(&mut b));
            b
        }
        let mut b = [0u8; 8];
        assert!(!fill(&mut b), "off until a host asks");
        fix(7);
        // The first run of a program, and what it reads next.
        exec(100, "/system/bin/toybox");
        let first = read(100);
        let more = read(100);
        assert_ne!(first, more);
        // Its fork, and another thread of it.
        fork(100, 101);
        let child = read(101);
        let thread = std::thread::spawn(|| read(100)).join().unwrap();
        assert_ne!(child, first);
        assert_ne!(thread, first);
        assert_ne!(thread, child);
        // Another program, and this one's second run.
        exec(102, "/system/bin/sh");
        let other = read(102);
        exec(103, "/system/bin/toybox");
        let second = read(103);
        assert_ne!(other, first);
        assert_ne!(second, first);
        // A fork that runs the program: the program's stream, not the fork's.
        fork(100, 104);
        exec(104, "/system/bin/sh");
        assert_ne!(read(104), other);

        // The same again from the start, the other program run first this
        // time and under other numbers: each reads what it read.
        *TABLE.lock().unwrap() = None;
        exec(7, "/system/bin/sh");
        assert_eq!(read(7), other);
        exec(8, "/system/bin/toybox");
        assert_eq!(read(8), first);
        assert_eq!(read(8), more);
        fork(8, 9);
        assert_eq!(read(9), child);
        exec(10, "/system/bin/toybox");
        assert_eq!(read(10), second);
        SEED.store(0, Ordering::Relaxed);
    }
}
