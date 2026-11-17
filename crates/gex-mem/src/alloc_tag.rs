//! A diagnostic allocator: which part of the host each live heap byte was
//! allocated by. A thread says what it is doing ([`enter`]); every block
//! carries the tag it was allocated under in a header before it, and its
//! bytes count against that tag until it is freed, whatever frees it.
//! [`live`] is what each tag holds now.
//!
//! Installed only by a gexc built with the `alloc-tags` feature
//! (`#[global_allocator]` there), since every block then costs a header of
//! at least 16 bytes. Elsewhere [`enter`] costs a thread-local write and
//! nothing counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicI64, Ordering};

/// The tags, by number.
pub const NAMES: [&str; N] = ["other", "kernel", "translate", "thread", "load", "install", "replay", "fork", "run", "fill"];

const N: usize = 10;

pub const OTHER: u8 = 0;
pub const KERNEL: u8 = 1;
pub const TRANSLATE: u8 = 2;
/// A thread's or process's store and image instance being made.
pub const THREAD: u8 = 3;
pub const LOAD: u8 = 4;
pub const INSTALL: u8 = 5;
pub const REPLAY: u8 = 6;
pub const FORK: u8 = 7;
/// Guest code running, and what it calls that nothing above names.
pub const RUN: u8 = 8;
/// A dispatch's empty slot or stale table being answered.
pub const FILL: u8 = 9;

static LIVE: [AtomicI64; N] = [const { AtomicI64::new(0) }; N];

thread_local! {
    static TAG: Cell<u8> = const { Cell::new(0) };
}

/// This thread is doing `tag`'s work until the guard goes (and then what it
/// was doing before).
pub struct Enter(u8);

pub fn enter(tag: u8) -> Enter {
    Enter(TAG.try_with(|c| c.replace(tag)).unwrap_or(0))
}

impl Drop for Enter {
    fn drop(&mut self) {
        let _ = TAG.try_with(|c| c.set(self.0));
    }
}

/// The bytes each tag's blocks hold now (0 without the allocator).
pub fn live() -> [i64; N] {
    std::array::from_fn(|i| LIVE[i].load(Ordering::Relaxed))
}

/// The allocator: the system's, each block with a header.
pub struct Tagged;

/// The header: the block's size and tag, in the 8 bytes just before it.
const HDR: usize = 16;

fn full(l: Layout) -> Option<(Layout, usize)> {
    let align = l.align().max(HDR);
    Some((Layout::from_size_align(l.size().checked_add(align)?, align).ok()?, align))
}

// SAFETY: every block is the system allocator's, `align` bytes bigger and
// returned `align` bytes in, so the header before it is inside the block;
// `dealloc` finds the same layout from the caller's.
unsafe impl GlobalAlloc for Tagged {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let Some((f, align)) = full(l) else { return std::ptr::null_mut() };
        unsafe { finish(System.alloc(f), align, l.size()) }
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let Some((f, align)) = full(l) else { return std::ptr::null_mut() };
        unsafe { finish(System.alloc_zeroed(f), align, l.size()) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let (f, align) = full(l).expect("a layout that was allocated");
        unsafe {
            let h = (p.sub(8) as *const u64).read();
            LIVE[(h & 0xff) as usize % N].fetch_sub((h >> 8) as i64, Ordering::Relaxed);
            System.dealloc(p.sub(align), f);
        }
    }
}

unsafe fn finish(base: *mut u8, align: usize, size: usize) -> *mut u8 {
    if base.is_null() {
        return base;
    }
    let tag = TAG.try_with(|c| c.get()).unwrap_or(0);
    unsafe {
        let p = base.add(align);
        (p.sub(8) as *mut u64).write(((size as u64) << 8) | tag as u64);
        LIVE[tag as usize % N].fetch_add(size as i64, Ordering::Relaxed);
        p
    }
}
