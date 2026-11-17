//! `signalfd`: pending signals read from a descriptor, as an event loop
//! takes them (Android's init waits for SIGCHLD and SIGTERM this way, on
//! the epoll set it waits for everything else on).
//!
//! The descriptor holds a mask and nothing else. A read takes the signals
//! of the mask that are pending for whoever reads, the thread's own and
//! its process's, each as a `signalfd_siginfo`; it is readable while one
//! is pending for whoever asks. "Whoever" is the thread that makes the
//! call, as in Linux (`current`): a child that inherits the descriptor
//! reads its own signals from it, not its parent's. A handle is asked
//! without being told who asks, so the kernel notes the thread it runs
//! ([`enter`]) once any signalfd exists.
//!
//! As fs/signalfd.c in what a program can see.

use crate::errno::{Errno, SysResult};
use crate::signal::{Signals, Source};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `sizeof(struct signalfd_siginfo)`.
pub const SIGINFO_SIZE: usize = 128;

const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
/// `si_code` of a signal the kernel raised, and of one `sigqueue` sent.
const SI_KERNEL: i32 = 0x80;
const SI_QUEUE: i32 = -1;

/// A signalfd has been made: the kernel notes its running thread from now.
static IN_USE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The guest thread this host thread runs, as its signals see it.
    static CURRENT: RefCell<Option<Signals>> = const { RefCell::new(None) };
}

/// The kernel is running a call of the thread `signals` is the view of.
/// Costs a load until a signalfd exists.
pub fn enter(signals: &Signals) {
    if !IN_USE.load(Ordering::Relaxed) {
        return;
    }
    note(signals);
}

fn note(signals: &Signals) {
    CURRENT.with(|c| {
        let mut c = c.borrow_mut();
        let same = c.as_ref().is_some_and(|s| std::sync::Arc::ptr_eq(s.thread(), signals.thread()) && std::sync::Arc::ptr_eq(s.process(), signals.process()));
        if !same {
            *c = Some(Signals::view(std::sync::Arc::clone(signals.process()), std::sync::Arc::clone(signals.thread())));
        }
    });
}

/// Have the kernel note its running thread from now, as a signalfd makes
/// it: for a file that has to know who writes it.
pub fn note_running() {
    IN_USE.store(true, Ordering::Relaxed);
}

/// Whether the thread the kernel is running a call of belongs to process
/// `p`. `None` where the kernel has not noted one (nothing had asked it to
/// when the call began).
pub fn running_process_is(p: &std::sync::Arc<crate::signal::ProcSig>) -> Option<bool> {
    CURRENT.with(|c| c.borrow().as_ref().map(|s| std::sync::Arc::ptr_eq(s.process(), p)))
}

/// A mask as a signalfd keeps it: SIGKILL and SIGSTOP are never in it.
fn masked(mask: u64) -> u64 {
    mask & !(1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1))
}

/// A signalfd.
#[derive(Debug)]
pub struct SignalFd {
    mask: AtomicU64,
    /// Who waits on it: notified when its mask changes. A signal's arrival
    /// is the host's to notice, as it is for any wait a signal ends.
    queue: crate::wait::Queue,
}

impl SignalFd {
    /// A signalfd for `mask`, made by the thread `signals` is the view of.
    pub fn new(mask: u64, signals: &Signals) -> SignalFd {
        IN_USE.store(true, Ordering::Relaxed);
        note(signals);
        SignalFd { mask: AtomicU64::new(masked(mask)), queue: crate::wait::Queue::new() }
    }

    /// `signalfd4` on a descriptor that is one already: another mask.
    pub fn set_mask(&self, mask: u64) {
        self.mask.store(masked(mask), Ordering::Release);
        self.queue.notify();
    }

    pub fn mask(&self) -> u64 {
        self.mask.load(Ordering::Acquire)
    }
}

/// A `signalfd_siginfo` for `signal`, sent by `source` (the kernel's own
/// when `None`): its number and code, and what a signal of that code
/// carries (`signalfd_copyinfo`).
pub fn siginfo(signal: u32, source: Option<Source>) -> [u8; SIGINFO_SIZE] {
    let mut b = [0u8; SIGINFO_SIZE];
    b[..4].copy_from_slice(&signal.to_le_bytes());
    let code = source.map_or(SI_KERNEL, |s| s.code);
    b[8..12].copy_from_slice(&code.to_le_bytes());
    if let Some(s) = source {
        // ssi_pid, ssi_uid
        b[12..16].copy_from_slice(&(s.pid as u32).to_le_bytes());
        b[16..20].copy_from_slice(&s.uid.to_le_bytes());
        if signal == crate::signal::sig::SIGCHLD && (1..=6).contains(&s.code) {
            // ssi_status: how the child ended (a `CLD_*` code's exit
            // status or signal). Its times, ssi_utime and ssi_stime, are
            // not kept here and read 0.
            b[40..44].copy_from_slice(&(s.value as u32).to_le_bytes());
        } else if s.code == SI_QUEUE {
            // ssi_int, ssi_ptr: the value sent with it.
            b[44..48].copy_from_slice(&(s.value as u32).to_le_bytes());
            b[48..56].copy_from_slice(&s.value.to_le_bytes());
        }
    }
    b
}

impl FileHandle for SignalFd {
    /// As many of the mask's pending signals as the buffer holds, lowest
    /// first; `EAGAIN` with none, which a read that may wait parks on.
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if buf.len() < SIGINFO_SIZE {
            return Err(Errno::EINVAL);
        }
        let mask = self.mask();
        CURRENT.with(|c| {
            let c = c.borrow();
            let signals = c.as_ref().ok_or(Errno::EAGAIN)?;
            let mut done = 0;
            while buf.len() - done >= SIGINFO_SIZE {
                let Some((signal, source)) = signals.claim_in(mask) else { break };
                buf[done..done + SIGINFO_SIZE].copy_from_slice(&siginfo(signal, source));
                done += SIGINFO_SIZE;
            }
            if done == 0 {
                return Err(Errno::EAGAIN);
            }
            Ok(done as u64)
        })
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        // An anonymous inode, reported as eventfd's is.
        Ok(Metadata { file_type: FileType::Fifo, size: 0, mode: 0o600, ino: 0, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        let mask = self.mask();
        CURRENT.with(|c| c.borrow().as_ref().is_some_and(|s| s.pending_raw() & mask != 0))
    }

    fn poll_writable(&self) -> bool {
        false
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn as_signalfd(self: std::sync::Arc<Self>) -> Option<std::sync::Arc<SignalFd>> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGUSR1: u32 = 10;
    const SIGUSR2: u32 = 12;

    fn bit(signal: u32) -> u64 {
        1 << (signal - 1)
    }

    /// The signals of its mask that are pending for the thread that reads
    /// are read, lowest first, each with who sent it; others stay pending.
    #[test]
    fn a_read_takes_the_masks_pending_signals_of_the_reader() {
        let signals = Signals::new();
        let fd = SignalFd::new(bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGKILL), &signals);
        assert_eq!(fd.mask(), bit(SIGUSR1) | bit(SIGUSR2), "SIGKILL is in no mask");
        let mut buf = [0u8; 3 * SIGINFO_SIZE];
        assert!(!fd.poll_readable());
        assert_eq!(fd.read_at(0, &mut buf), Err(Errno::EAGAIN));
        assert_eq!(fd.read_at(0, &mut buf[..SIGINFO_SIZE - 1]), Err(Errno::EINVAL));

        signals.raise(SIGUSR2);
        signals.raise_from(SIGUSR1, Source { code: SI_QUEUE, pid: 42, uid: 7, value: 0x1_0000_0005 });
        signals.raise(15);
        assert!(fd.poll_readable());
        assert_eq!(fd.read_at(0, &mut buf), Ok(2 * SIGINFO_SIZE as u64));
        let word = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
        assert_eq!((word(0), word(8) as i32, word(12), word(16), word(44)), (SIGUSR1, SI_QUEUE, 42, 7, 5));
        assert_eq!(u64::from_le_bytes(buf[48..56].try_into().unwrap()), 0x1_0000_0005);
        assert_eq!((word(SIGINFO_SIZE), word(SIGINFO_SIZE + 8) as i32), (SIGUSR2, SI_KERNEL));
        // SIGTERM is not its to take.
        assert!(!fd.poll_readable());
        assert_eq!(signals.pending_raw(), bit(15));
        // A child's end says which child and how.
        let chld = siginfo(17, Some(Source { code: 1, pid: 99, uid: 7, value: 3 }));
        assert_eq!((word_of(&chld, 0), word_of(&chld, 8), word_of(&chld, 12), word_of(&chld, 40), word_of(&chld, 44)), (17, 1, 99, 3, 0));

        // Another thread's view on this host thread: its signals, not the
        // first's.
        let other = Signals::new();
        other.raise(SIGUSR1);
        signals.raise(SIGUSR2);
        enter(&other);
        assert_eq!(fd.read_at(0, &mut buf), Ok(SIGINFO_SIZE as u64));
        assert_eq!(word_of(&buf, 0), SIGUSR1);
        enter(&signals);
        assert_eq!(fd.read_at(0, &mut buf), Ok(SIGINFO_SIZE as u64));
        assert_eq!(word_of(&buf, 0), SIGUSR2);
    }

    fn word_of(buf: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
    }
}
