//! `userfaultfd`, as far as a program that takes its faults as `SIGBUS`
//! uses it: Android's ART, whose concurrent compacting collector
//! (`art/runtime/gc/collector/mark_compact.cc`) needs the kernel to say it
//! has `UFFD_FEATURE_SIGBUS`, and without it the image's preopted boot
//! image is thrown away and the boot class path compiled again at every
//! boot (odrefresh: "Userfaultfd GC check failed").
//!
//! What it is (`fs/userfaultfd.c`, `mm/userfaultfd.c`, at android17-6.18):
//! a descriptor, made by `userfaultfd(2)`, set up once with `UFFDIO_API`,
//! with which a range of anonymous memory is registered
//! (`UFFDIO_REGISTER`, missing mode). A page of a registered range that
//! has nothing in it is *missing*; a thread that touches one takes `SIGBUS`
//! (`BUS_ADRERR`, at the address), and the handler fills it
//! (`UFFDIO_COPY`, `UFFDIO_ZEROPAGE`) and returns, and the access is made
//! again. A system call that touches one fails with `EFAULT`.
//!
//! Which pages have nothing in them: here, a page of a registered range
//! that `MADV_DONTNEED` emptied, or that `mremap` moved away from and left
//! (`MREMAP_DONTUNMAP`), since it was registered and until it is filled.
//! ART empties its ranges so after registering them (the moving space by
//! `madvise`, the linear-alloc spaces by `mremap`). A page Linux counts
//! missing because it was never touched, or emptied before the range was
//! registered, is taken here as present: gex does not see a page's first
//! touch.
//!
//! Not here, and refused: the event and wake-up mode (a thread that reads
//! fault events from the descriptor), write-protect and minor modes,
//! `UFFDIO_MOVE`, `UFFDIO_CONTINUE`, `UFFDIO_POISON`. The features
//! `UFFDIO_API` offers are what is here: `UFFD_FEATURE_SIGBUS`.

use crate::errno::Errno;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::errno::SysResult;
use crate::GuestMem;

/// `UFFD_API`.
pub const UFFD_API: u64 = 0xaa;
/// `UFFD_FEATURE_SIGBUS`: a missing page is the toucher's `SIGBUS`.
pub const FEATURE_SIGBUS: u64 = 1 << 7;
/// What `UFFDIO_API` sets on a descriptor beside the features asked for
/// (`UFFD_FEATURE_INITIALIZED`), so that a second call fails.
const INITIALIZED: u64 = 1 << 31;
/// `userfaultfd(2)`'s flag: faults of the kernel's own accesses are not
/// handled (all this one handles anyway).
pub const USER_MODE_ONLY: u64 = 1;

/// The ioctls (`_IOWR(0xAA, n, struct ...)`).
pub const UFFDIO_API: u64 = 0xc018_aa3f;
pub const UFFDIO_REGISTER: u64 = 0xc020_aa00;
pub const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
pub const UFFDIO_WAKE: u64 = 0x8010_aa02;
pub const UFFDIO_COPY: u64 = 0xc028_aa03;
pub const UFFDIO_ZEROPAGE: u64 = 0xc020_aa04;

/// The ioctls' numbers (`_UFFDIO_*`), for the masks the kernel reports.
const NR_REGISTER: u64 = 0x00;
const NR_UNREGISTER: u64 = 0x01;
const NR_WAKE: u64 = 0x02;
const NR_COPY: u64 = 0x03;
const NR_ZEROPAGE: u64 = 0x04;
const NR_API: u64 = 0x3f;

/// `UFFDIO_REGISTER_MODE_*`.
const MODE_MISSING: u64 = 1;
const MODE_WP: u64 = 2;
const MODE_MINOR: u64 = 4;
/// `UFFDIO_COPY_MODE_DONTWAKE`, `UFFDIO_ZEROPAGE_MODE_DONTWAKE`: there is
/// nobody to wake here, so it changes nothing.
const MODE_DONTWAKE: u64 = 1;

const PAGE: u64 = crate::mem::PAGE_SIZE;

/// A set of page ranges, sorted and disjoint.
#[derive(Debug, Default, Clone)]
pub(crate) struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    pub(crate) fn add(&mut self, s: u64, e: u64) {
        if s >= e {
            return;
        }
        let (mut s, mut e) = (s, e);
        let mut out = Vec::with_capacity(self.0.len() + 1);
        for &(a, b) in &self.0 {
            if b < s || a > e {
                out.push((a, b));
            } else {
                s = s.min(a);
                e = e.max(b);
            }
        }
        out.push((s, e));
        out.sort_unstable();
        self.0 = out;
    }

    pub(crate) fn remove(&mut self, s: u64, e: u64) {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        for &(a, b) in &self.0 {
            if b <= s || a >= e {
                out.push((a, b));
                continue;
            }
            if a < s {
                out.push((a, s));
            }
            if b > e {
                out.push((e, b));
            }
        }
        self.0 = out;
    }

    pub(crate) fn contains(&self, at: u64) -> bool {
        let i = self.0.partition_point(|r| r.1 <= at);
        self.0.get(i).is_some_and(|r| r.0 <= at)
    }

    /// The parts of `[s, e)` in the set.
    pub(crate) fn within(&self, s: u64, e: u64) -> Vec<(u64, u64)> {
        self.0.iter().filter(|r| r.0 < e && r.1 > s).map(|r| (r.0.max(s), r.1.min(e))).collect()
    }

    pub(crate) fn all(&self) -> &[(u64, u64)] {
        &self.0
    }
}

/// A map's userfaultfd state: which ranges are registered, with which
/// descriptor, and which of their pages are missing.
#[derive(Debug, Default)]
pub struct UffdState {
    /// Registered ranges: start, end, the descriptor's number.
    regs: Vec<(u64, u64, u64)>,
    /// The missing pages of registered ranges.
    pub(crate) missing: Ranges,
}

impl Clone for UffdState {
    /// A fork's child: its copy of the memory is registered with nothing
    /// (no `UFFD_FEATURE_EVENT_FORK` here), and its missing pages read as
    /// the zeros they hold.
    fn clone(&self) -> UffdState {
        UffdState::default()
    }
}

impl UffdState {
    /// The descriptor `[at, at+1)` is registered with, if any.
    pub(crate) fn owner(&self, at: u64) -> Option<u64> {
        self.regs.iter().find(|r| r.0 <= at && at < r.1).map(|r| r.2)
    }

    /// Register `[s, e)` (the parts of it that are mapped) with `id`:
    /// `EBUSY` where another descriptor has any of it.
    pub(crate) fn register(&mut self, id: u64, parts: &[(u64, u64)]) -> Result<(), Errno> {
        for &(s, e) in parts {
            if self.regs.iter().any(|r| r.2 != id && r.0 < e && r.1 > s) {
                return Err(Errno::EBUSY);
            }
        }
        for &(s, e) in parts {
            self.unregister_range(id, s, e);
            self.regs.push((s, e, id));
        }
        self.regs.sort_unstable();
        Ok(())
    }

    /// `id`'s registration of `[s, e)` undone; its missing pages there are
    /// no longer missing (they read as the zeros they hold).
    pub(crate) fn unregister_range(&mut self, id: u64, s: u64, e: u64) {
        let mut out = Vec::with_capacity(self.regs.len() + 1);
        for &(a, b, who) in &self.regs {
            if who != id || b <= s || a >= e {
                out.push((a, b, who));
                continue;
            }
            self.missing.remove(a.max(s), b.min(e));
            if a < s {
                out.push((a, s, who));
            }
            if b > e {
                out.push((e, b, who));
            }
        }
        self.regs = out;
    }

    /// All of `id`'s registrations undone (its descriptor is gone).
    pub(crate) fn release(&mut self, id: u64) -> bool {
        let had = self.regs.iter().any(|r| r.2 == id);
        let mine: Vec<(u64, u64)> = self.regs.iter().filter(|r| r.2 == id).map(|r| (r.0, r.1)).collect();
        for (a, b) in mine {
            self.unregister_range(id, a, b);
        }
        had
    }

    /// `[s, e)` is no longer mapped: whatever was registered there goes.
    pub(crate) fn unmapped(&mut self, s: u64, e: u64) -> bool {
        let ids: Vec<u64> = self.regs.iter().filter(|r| r.0 < e && r.1 > s).map(|r| r.2).collect();
        for id in &ids {
            self.unregister_range(*id, s, e);
        }
        self.missing.remove(s, e);
        !ids.is_empty()
    }

    /// `[s, e)` was emptied (`MADV_DONTNEED`, or the source `mremap` left
    /// with `MREMAP_DONTUNMAP`): its registered pages are missing. Whether
    /// any were.
    pub(crate) fn emptied(&mut self, s: u64, e: u64) -> bool {
        let regs: Vec<(u64, u64)> = self.regs.iter().filter(|r| r.0 < e && r.1 > s).map(|r| (r.0.max(s), r.1.min(e))).collect();
        for &(a, b) in &regs {
            self.missing.add(a, b);
        }
        !regs.is_empty()
    }
}

/// The next descriptor's number.
fn next_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A `userfaultfd` descriptor: the map it was made in, and the features
/// `UFFDIO_API` set (0 until it has).
pub struct Uffd {
    id: u64,
    mm: crate::mem::Mm,
    features: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Uffd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "userfaultfd {}", self.id)
    }
}

impl Uffd {
    /// A descriptor for the map `mm` (the caller's, which it stays with
    /// whoever later holds it).
    pub fn new(mm: crate::mem::Mm) -> Uffd {
        Uffd { id: next_id(), mm, features: std::sync::atomic::AtomicU64::new(0) }
    }

    fn initialized(&self) -> bool {
        self.features.load(std::sync::atomic::Ordering::Acquire) != 0
    }

    /// `UFFDIO_API`: the features offered and the ioctls given back, and
    /// those asked for kept, once (`userfaultfd_api`).
    fn api(&self, m: &mut GuestMem<'_>, arg: u64) -> SysResult {
        let api = m.read_u64(arg)?;
        let features = m.read_u64(arg + 8)?;
        m.read_u64(arg + 16)?;
        let refuse = |m: &mut GuestMem<'_>, e: Errno| -> SysResult {
            m.write(arg, &[0u8; 24])?;
            Err(e)
        };
        if api != UFFD_API {
            return refuse(m, Errno::EINVAL);
        }
        const EVENT_FORK: u64 = 1 << 1;
        if features & EVENT_FORK != 0 {
            // (EPERM without CAP_SYS_PTRACE; offered by neither here.)
            return refuse(m, Errno::EINVAL);
        }
        if features & !FEATURE_SIGBUS != 0 {
            return refuse(m, Errno::EINVAL);
        }
        m.write_u64(arg + 8, FEATURE_SIGBUS)?;
        m.write_u64(arg + 16, 1 << NR_REGISTER | 1 << NR_UNREGISTER | 1 << NR_API)?;
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        if self.features.compare_exchange(0, features | INITIALIZED, AcqRel, Acquire).is_err() {
            return refuse(m, Errno::EINVAL);
        }
        Ok(0)
    }

    /// A range as `validate_range` takes it: page-aligned start and
    /// length, not empty, within the address space.
    fn range(m: &GuestMem<'_>, at: u64) -> Result<(u64, u64), Errno> {
        let start = m.read_u64(at)?;
        let len = m.read_u64(at + 8)?;
        if start % PAGE != 0 || len % PAGE != 0 || len == 0 {
            return Err(Errno::EINVAL);
        }
        let end = start.checked_add(len).ok_or(Errno::EINVAL)?;
        if start < gex_abi::guest_floor() || end > gex_abi::perm_limit() {
            return Err(Errno::EINVAL);
        }
        Ok((start, end))
    }

    /// `UFFDIO_REGISTER`, missing mode: the anonymous mappings in the range
    /// (holes passed over, none at all `EINVAL`, any other kind `EINVAL`).
    fn register(&self, m: &mut GuestMem<'_>, arg: u64) -> SysResult {
        let mode = m.read_u64(arg + 16)?;
        if mode == 0 || mode & !(MODE_MISSING | MODE_WP | MODE_MINOR) != 0 {
            return Err(Errno::EINVAL);
        }
        if mode & (MODE_WP | MODE_MINOR) != 0 {
            unimplemented("register in write-protect or minor mode");
            return Err(Errno::EINVAL);
        }
        let (start, end) = Self::range(m, arg)?;
        let mut map = self.mm.lock();
        let parts = map.anon_parts(start, end)?;
        map.uffd_mut().register(self.id, &parts)?;
        drop(map);
        // The ioctls that work on the range (`UFFD_API_RANGE_IOCTLS`, less
        // what is not here).
        m.write_u64(arg + 24, 1 << NR_WAKE | 1 << NR_COPY | 1 << NR_ZEROPAGE)?;
        Ok(0)
    }

    fn unregister(&self, m: &mut GuestMem<'_>, arg: u64) -> SysResult {
        let (start, end) = Self::range(m, arg)?;
        let mut map = self.mm.lock();
        let parts = map.anon_parts(start, end)?;
        for (s, e) in parts {
            map.uffd_mut().unregister_range(self.id, s, e);
        }
        map.uffd_changed();
        Ok(0)
    }

    /// `UFFDIO_COPY` and `UFFDIO_ZEROPAGE` (`zero`): fill the missing pages
    /// of `[dst, dst+len)` from `src`, or with zeros, page by page, each
    /// whole before it is present; `EEXIST` at the first that is not
    /// missing. The count filled goes back in the struct's last field (or
    /// the error); filled less than asked is `EAGAIN`.
    fn fill(&self, m: &mut GuestMem<'_>, arg: u64, zero: bool) -> SysResult {
        let (dst, src, len, mode, out) = if zero {
            let (dst, end) = Self::range(m, arg)?;
            (dst, 0, end - dst, m.read_u64(arg + 16)?, arg + 24)
        } else {
            let dst = m.read_u64(arg)?;
            let src = m.read_u64(arg + 8)?;
            let len = m.read_u64(arg + 16)?;
            let mode = m.read_u64(arg + 24)?;
            // The source unaligned is allowed; not the destination.
            if len == 0 || src.checked_add(len).is_none() {
                return Err(Errno::EINVAL);
            }
            Self::range_of(dst, len)?;
            (dst, src, len, mode, arg + 32)
        };
        if mode & !MODE_DONTWAKE != 0 {
            return Err(Errno::EINVAL);
        }
        let mut done = 0u64;
        let mut err = None;
        {
            let mut map = self.mm.lock();
            // The whole destination is to be this descriptor's.
            if (dst..dst + len).step_by(PAGE as usize).any(|p| map.uffd().owner(p) != Some(self.id)) {
                drop(map);
                m.write_u64(out, (-(Errno::ENOENT.0 as i64)) as u64)?;
                return Err(Errno::ENOENT);
            }
            while done < len {
                let page = dst + done;
                if !map.uffd().missing.contains(page) {
                    err = Some(Errno::EEXIST);
                    break;
                }
                // The source as the program may read it; the page written
                // as the kernel writes it (it is not the program's to
                // touch until it is present).
                let bytes = if zero {
                    vec![0u8; PAGE as usize]
                } else {
                    match m.read(src + done, PAGE as usize) {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                };
                let user = m.take_user();
                let w = m.write(page, &bytes);
                m.set_user(user);
                if let Err(e) = w {
                    err = Some(e);
                    break;
                }
                map.uffd_mut().missing.remove(page, page + PAGE);
                done += PAGE;
            }
            if done > 0 {
                map.uffd_changed();
            }
        }
        // `mfill_atomic`: what was filled, else the error.
        let said = if done > 0 { done as i64 } else { -(err.unwrap_or(Errno::EINVAL).0 as i64) };
        m.write_u64(out, said as u64)?;
        if done == 0 {
            return Err(err.unwrap_or(Errno::EINVAL));
        }
        if done < len {
            return Err(Errno::EAGAIN);
        }
        Ok(0)
    }

    fn range_of(start: u64, len: u64) -> Result<(), Errno> {
        if start % PAGE != 0 || len % PAGE != 0 || len == 0 {
            return Err(Errno::EINVAL);
        }
        let end = start.checked_add(len).ok_or(Errno::EINVAL)?;
        if start < gex_abi::guest_floor() || end > gex_abi::perm_limit() {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

impl Drop for Uffd {
    /// The descriptor's last close: what it registered is no longer.
    fn drop(&mut self) {
        let mut map = self.mm.lock();
        if map.uffd_mut().release(self.id) {
            map.uffd_changed();
        }
    }
}

fn unimplemented(what: &str) {
    static SAID: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] userfaultfd: {what} is not implemented -> EINVAL");
        said.push(what.to_string());
    }
}

impl FileHandle for Uffd {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        // Events are not made here (faults are SIGBUS): nothing to read.
        if !self.initialized() {
            return Err(Errno::EINVAL);
        }
        Err(Errno::EAGAIN)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o600, ino: self.id, mtime: 0, nlink: 1, rdev: 0, times: Default::default(), owner: None })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        false
    }

    fn ioctl(&self, m: &mut GuestMem<'_>, req: u64, arg: u64) -> Option<SysResult> {
        let req = req & 0xffff_ffff;
        if req != UFFDIO_API && !self.initialized() {
            return Some(Err(Errno::EINVAL));
        }
        Some(match req {
            UFFDIO_API => self.api(m, arg),
            UFFDIO_REGISTER => self.register(m, arg),
            UFFDIO_UNREGISTER => self.unregister(m, arg),
            // Nobody waits: a fault here is the toucher's SIGBUS.
            UFFDIO_WAKE => Self::range(m, arg).map(|_| 0),
            UFFDIO_COPY => self.fill(m, arg, false),
            UFFDIO_ZEROPAGE => self.fill(m, arg, true),
            _ => Err(Errno::EINVAL),
        })
    }
}
