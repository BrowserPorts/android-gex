//! `timerfd`: a clock as a descriptor, for event loops (libuv arms one per
//! timer heap and lets `epoll_wait` return it).
//!
//! The object is a monotonic count of expirations. `timerfd_settime` arms it
//! with an initial delay and optional interval; a `read` returns how many
//! times it fired since the last read and clears that count. Readiness is
//! time-based -- [`poll_readable`] asks the clock -- so the handle carries its
//! own [`ClockFn`].
//!
//! A waiter parks until the next expiry ([`ready_in_ns`]); arming the timer
//! notifies its wait queue, so a waiter parked to an old expiry takes the new.
//!
//! [`poll_readable`]: crate::vfs::FileHandle::poll_readable
//! [`ready_in_ns`]: crate::vfs::FileHandle::ready_in_ns
//! [`ClockFn`]: crate::syscalls::ClockFn

use crate::errno::{Errno, SysResult};
use crate::syscalls::ClockFn;
use crate::vfs::{FileHandle, FileType, Metadata};
use std::sync::Mutex;

/// `timerfd_settime` flag: `it_value` is an absolute time on the clock rather
/// than a delay from now.
pub const TFD_TIMER_ABSTIME: u64 = 1;
/// `timerfd_settime` flag: with `TFD_TIMER_ABSTIME`, on a wall clock, a
/// read after the clock is set is `ECANCELED` (`timerfd_setup_cancel`).
pub const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
/// The flags `timerfd_settime` takes; any other is `EINVAL`.
pub const TFD_SETTIME_FLAGS: u64 = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;

/// How many times the wall clock has been set (`settimeofday`,
/// `clock_settime`): what Linux's `moffs` comparison in
/// `timerfd_clock_was_set` comes to. A timer armed to be cancelled
/// remembers the count, and is cancelled once it has moved.
static CLOCK_SETS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The queue a clock set notifies, which each timer armed to be
/// cancelled is chained to: a reader parked on one wakes to `ECANCELED`.
fn clock_set_queue() -> &'static crate::wait::Queue {
    static Q: std::sync::OnceLock<crate::wait::Queue> = std::sync::OnceLock::new();
    Q.get_or_init(crate::wait::Queue::new)
}

/// The wall clock was set: every timer armed with
/// `TFD_TIMER_CANCEL_ON_SET` is cancelled, and whoever waits on one wakes.
pub fn clock_was_set() {
    CLOCK_SETS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    clock_set_queue().notify();
}

fn clock_sets() -> u64 {
    CLOCK_SETS.load(std::sync::atomic::Ordering::SeqCst)
}

#[derive(Debug, Default, Clone, Copy)]
struct State {
    /// Absolute nanoseconds of the next expiry, or 0 when disarmed.
    next: u64,
    /// Interval in nanoseconds, or 0 for a one-shot timer.
    interval: u64,
    /// Armed with `TFD_TIMER_CANCEL_ON_SET` on a wall clock (Linux's
    /// `might_cancel`, the timer on the cancel list).
    might_cancel: bool,
    /// [`CLOCK_SETS`] when it was last armed so or last told of a set.
    seen: u64,
    /// A set it was not told of before it stopped being armed so, which it
    /// is told of if it is again (Linux's `moffs` left at `KTIME_MAX`).
    stale: bool,
}

impl State {
    /// Whether the clock was set since it was last told (`timerfd_canceled`
    /// without the telling).
    fn cancel_pending(&self) -> bool {
        self.might_cancel && (self.stale || self.seen != clock_sets())
    }

    /// [`Self::cancel_pending`], and told (`timerfd_canceled`).
    fn take_cancel(&mut self) -> bool {
        if !self.cancel_pending() {
            return false;
        }
        self.stale = false;
        self.seen = clock_sets();
        true
    }

    /// What fired is forgotten and nothing is armed again: a cancelled
    /// read's `ticks = 0; expired = 0`, the cancel bookkeeping kept.
    fn forget_expiry(&mut self, now: u64) {
        if self.next != 0 && now >= self.next {
            self.next = 0;
            self.interval = 0;
        }
    }
}

/// A `timerfd` object.
pub struct TimerFd {
    clock: ClockFn,
    /// For a CLOCK_MONOTONIC (or BOOTTIME) timer: how a reading of `clock`
    /// becomes that clock's, so an absolute `it_value` means what the guest
    /// read from `clock_gettime` on the same clock.
    map: Option<fn((u64, u32)) -> (u64, u32)>,
    /// On a wall clock (`CLOCK_REALTIME`, `CLOCK_REALTIME_ALARM`), which a
    /// clock set can cancel.
    wall: bool,
    state: Mutex<State>,
    /// Who waits on it (`crate::wait`): arming or disarming it. Its expiry
    /// is a deadline the waiter parks to ([`FileHandle::ready_in_ns`]).
    queue: crate::wait::Queue,
}

impl std::fmt::Debug for TimerFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerFd").field("state", &*self.state.lock().unwrap()).finish()
    }
}

impl TimerFd {
    pub fn new(clock: ClockFn) -> TimerFd {
        TimerFd {
            clock,
            map: None,
            wall: false,
            state: Mutex::new(State::default()),
            queue: crate::wait::Queue::new(),
        }
    }

    /// The same timer on a clock derived from `clock` by `map`.
    pub fn monotonic(mut self, map: fn((u64, u32)) -> (u64, u32)) -> TimerFd {
        self.map = Some(map);
        self
    }

    /// A timer on a wall clock, read through `map` (the guest's wall clock,
    /// which may have been set), and cancelled by a set if armed so.
    pub fn wall(mut self, map: fn((u64, u32)) -> (u64, u32)) -> TimerFd {
        self.map = Some(map);
        self.wall = true;
        self
    }

        fn now_ns(&self) -> u64 {
        let read = (self.clock)();
        let (secs, nanos) = match self.map {
            Some(map) => map(read),
            None => read,
        };
        secs.saturating_mul(1_000_000_000).saturating_add(nanos as u64)
    }

    /// How many times the timer has fired at `now` but not yet been read.
    fn expirations_at(s: &State, now: u64) -> u64 {
        if s.next == 0 || now < s.next {
            return 0;
        }
        if s.interval == 0 {
            1
        } else {
            1 + (now - s.next) / s.interval
        }
    }

    /// Arm or disarm the timer. `value` is the initial delay in nanoseconds
    /// (or an absolute time with `TFD_TIMER_ABSTIME` in `flags`), zero
    /// disarms; `interval` repeats. Returns the previous `(remaining,
    /// interval)` for `timerfd_gettime`-style old-value reporting, or
    /// `ECANCELED` when it is armed to be cancelled by a clock set and one
    /// came that it was not told of (it is armed all the same, as
    /// `timerfd_setup` leaves it).
    pub fn set(&self, value: u64, interval: u64, flags: u64) -> Result<(u64, u64), Errno> {
        let now = self.now_ns();
        let mut s = self.state.lock().unwrap();
        // timerfd_setup_cancel
        let cancel = self.wall && flags & TFD_TIMER_ABSTIME != 0 && flags & TFD_TIMER_CANCEL_ON_SET != 0;
        if cancel && !s.might_cancel {
            s.might_cancel = true;
            s.seen = clock_sets();
            crate::wait::chain(clock_set_queue().id(), self.queue.id());
        } else if !cancel && s.might_cancel {
            s.stale |= s.seen != clock_sets();
            s.might_cancel = false;
            crate::wait::unchain(clock_set_queue().id(), self.queue.id());
        }
        let prev = Self::remaining(&s, now);
        let canceled = if value == 0 {
            s.next = 0;
            s.interval = 0;
            false
        } else {
            s.next = if flags & TFD_TIMER_ABSTIME != 0 { value } else { now.saturating_add(value) };
            s.interval = interval;
            s.take_cancel()
        };
        drop(s);
        // A waiter parked to the old expiry must take the new one.
        self.queue.notify();
        if canceled {
            return Err(Errno::ECANCELED);
        }
        Ok(prev)
    }

    /// `(remaining until next expiry, interval)` for `timerfd_gettime`. A
    /// disarmed timer reads back all zeros.
    fn remaining(s: &State, now: u64) -> (u64, u64) {
        if s.next == 0 {
            (0, s.interval)
        } else if now >= s.next {
            // Already due: Linux reports the time to the *next* tick, which for
            // a periodic timer is one interval minus how far past it is.
            if s.interval == 0 {
                (0, 0)
            } else {
                (s.interval - (now - s.next) % s.interval, s.interval)
            }
        } else {
            (s.next - now, s.interval)
        }
    }

    /// The current `(remaining, interval)`, for `timerfd_gettime`.
    pub fn get(&self) -> (u64, u64) {
        let now = self.now_ns();
        Self::remaining(&self.state.lock().unwrap(), now)
    }
}

impl Drop for TimerFd {
    fn drop(&mut self) {
        if self.state.get_mut().map_or(false, |s| s.might_cancel) {
            crate::wait::unchain(clock_set_queue().id(), self.queue.id());
        }
    }
}

impl FileHandle for TimerFd {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let now = self.now_ns();
        let mut s = self.state.lock().unwrap();
        // The clock was set: whatever fired is forgotten, and the reader
        // must look at the clock again.
        if s.take_cancel() {
            s.forget_expiry(now);
            return Err(Errno::ECANCELED);
        }
        let n = Self::expirations_at(&s, now);
        if n == 0 {
            return Err(Errno::EAGAIN);
        }
        if s.interval == 0 {
            s.next = 0;
        } else {
            // Advance past every tick that has already fired, so the next read
            // counts only ticks after this one.
            s.next = s.next.saturating_add(n.saturating_mul(s.interval));
        }
        buf[..8].copy_from_slice(&n.to_le_bytes());
        Ok(8)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata {
            file_type: FileType::Fifo,
            size: 0,
            mode: 0o600,
            ino: 0,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            times: Default::default(),
            owner: None,
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        let now = self.now_ns();
        let s = self.state.lock().unwrap();
        // A set makes it readable, as Linux's `ticks++` does.
        s.cancel_pending() || Self::expirations_at(&s, now) > 0
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        // A set wakes it through the chained queue, which does not count
        // here: counted from the sets for an edge-triggered watch.
        let sets = if self.state.lock().unwrap().might_cancel { clock_sets() } else { 0 };
        Some(self.queue.wakes().wrapping_add(sets))
    }

    fn ready_in_ns(&self) -> Option<u64> {
        let now = self.now_ns();
        let s = self.state.lock().unwrap();
        (s.next != 0).then(|| s.next.saturating_sub(now))
    }

    fn available(&self) -> Option<u64> {
        Some(if self.poll_readable() { 8 } else { 0 })
    }

    fn timerfd_set(&self, value_ns: u64, interval_ns: u64, flags: u64) -> Option<Result<(u64, u64), Errno>> {
        Some(self.set(value_ns, interval_ns, flags))
    }

    fn timerfd_get(&self) -> Option<(u64, u64)> {
        Some(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // A clock the test drives by hand. `ClockFn` is a bare `fn` pointer, so the
    // "current time" lives in a thread-local the closure-free function reads:
    // thread-local, because the test harness runs these tests in parallel and
    // a shared static let one test move another's clock.
    thread_local!(static CLOCK_NS: Cell<u64> = const { Cell::new(0) });
    fn test_clock() -> (u64, u32) {
        let ns = CLOCK_NS.with(|c| c.get());
        (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
    }
    fn set_now(ns: u64) {
        CLOCK_NS.with(|c| c.set(ns));
    }
    fn read(t: &TimerFd) -> Result<u64, Errno> {
        let mut b = [0u8; 8];
        t.read_at(0, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    #[test]
    fn a_one_shot_fires_once() {
        set_now(0);
        let t = TimerFd::new(test_clock);
        t.set(100, 0, 0).unwrap(); // 100ns from now
        assert!(!t.poll_readable());
        assert_eq!(read(&t).err(), Some(Errno::EAGAIN));
        set_now(100);
        assert!(t.poll_readable());
        assert_eq!(read(&t).unwrap(), 1);
        // Cleared, and one-shot does not re-arm.
        assert!(!t.poll_readable());
        set_now(1_000_000);
        assert!(!t.poll_readable());
    }

    #[test]
    fn a_periodic_timer_counts_missed_ticks() {
        set_now(0);
        let t = TimerFd::new(test_clock);
        t.set(100, 100, 0).unwrap(); // first at 100, every 100 after
        set_now(100);
        assert_eq!(read(&t).unwrap(), 1);
        // Fall four intervals behind before reading again.
        set_now(100 + 4 * 100);
        assert!(t.poll_readable());
        assert_eq!(read(&t).unwrap(), 4);
        // And it keeps going.
        assert!(!t.poll_readable());
        set_now(100 + 5 * 100);
        assert_eq!(read(&t).unwrap(), 1);
    }

    #[test]
    fn abstime_arms_at_an_absolute_point() {
        set_now(500);
        let t = TimerFd::new(test_clock);
        t.set(1000, 0, TFD_TIMER_ABSTIME).unwrap(); // absolute 1000, i.e. 500ns from now
        assert!(!t.poll_readable());
        set_now(1000);
        assert_eq!(read(&t).unwrap(), 1);
    }

    #[test]
    fn setting_zero_disarms() {
        set_now(0);
        let t = TimerFd::new(test_clock);
        t.set(100, 0, 0).unwrap();
        t.set(0, 0, 0).unwrap(); // disarm
        set_now(1000);
        assert!(!t.poll_readable());
        assert_eq!(t.get(), (0, 0));
    }

    #[test]
    fn gettime_reports_remaining() {
        set_now(0);
        let t = TimerFd::new(test_clock);
        t.set(1000, 250, 0).unwrap();
        set_now(400);
        let (rem, int) = t.get();
        assert_eq!((rem, int), (600, 250));
    }

    #[test]
    fn a_short_read_buffer_is_einval() {
        set_now(0);
        let t = TimerFd::new(test_clock);
        t.set(1, 0, 0).unwrap();
        set_now(1);
        assert_eq!(t.read_at(0, &mut [0u8; 4]).err(), Some(Errno::EINVAL));
    }

    /// `TFD_TIMER_CANCEL_ON_SET`: a wall-clock timer armed absolute so is
    /// cancelled by a set (readable, then `ECANCELED` once, then as before,
    /// still armed); one armed relative, or on another clock, is not; and
    /// arming one again after a set it was not told of is `ECANCELED`.
    #[test]
    fn a_clock_set_cancels_a_timer_armed_to_be_cancelled() {
        let flags = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;
        set_now(1_000);
        let wall = TimerFd::new(test_clock).wall(|t| t);
        let relative = TimerFd::new(test_clock).wall(|t| t);
        let mono = TimerFd::new(test_clock).monotonic(|t| t);
        wall.set(1_000_000, 0, flags).unwrap();
        relative.set(1_000_000, 0, TFD_TIMER_CANCEL_ON_SET).unwrap();
        mono.set(1_000_000, 0, flags).unwrap();
        assert_eq!(read(&wall), Err(Errno::EAGAIN));
        assert!(!wall.poll_readable());

        clock_was_set();
        assert!(wall.poll_readable());
        assert!(!relative.poll_readable() && !mono.poll_readable());
        assert_eq!(read(&wall), Err(Errno::ECANCELED));
        assert_eq!(read(&wall), Err(Errno::EAGAIN));
        assert!(wall.get().0 > 0, "still armed");
        assert_eq!(read(&relative), Err(Errno::EAGAIN));
        assert_eq!(read(&mono), Err(Errno::EAGAIN));

        // Told of nothing, then a set: arming again says so, and arms.
        clock_was_set();
        assert_eq!(wall.set(2_000_000, 0, flags), Err(Errno::ECANCELED));
        assert!(wall.get().0 > 0);
        assert_eq!(read(&wall), Err(Errno::EAGAIN));
        // Disarming tells it nothing.
        clock_was_set();
        assert_eq!(wall.set(0, 0, flags), Ok((2_000_000 - 1_000, 0)));
        assert_eq!(read(&wall), Err(Errno::ECANCELED));
    }
}
