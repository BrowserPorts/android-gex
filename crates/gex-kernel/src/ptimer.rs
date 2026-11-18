//! POSIX timers (`timer_create`, `timer_settime`, `timer_gettime`,
//! `timer_getoverrun`, `timer_delete`), after `kernel/time/posix-timers.c`
//! at android17-6.18: a process's timers by id, each a clock, how it
//! notifies (a signal to the process or to one of its threads, or none)
//! and when it next expires. They fire with the interval timers
//! ([`crate::signal::ProcSig::fire_timers`]): a timer whose signal is still
//! queued counts the expiry as an overrun instead of queuing another, and
//! its `si_overrun` says how many. A fork's child has none, and `execve`
//! deletes them.
//!
//! Not here: timers on CPU-time clocks (refused, said once), and absolute
//! realtime timers that follow a later `clock_settime` (the deadline is
//! taken when armed).

use crate::errno::Errno;
use crate::signal::ThreadSig;
use std::sync::{Arc, Weak};

/// `CLOCK_*` ids that take timers.
pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;
pub const CLOCK_MONOTONIC_RAW: u32 = 4;
pub const CLOCK_REALTIME_COARSE: u32 = 5;
pub const CLOCK_MONOTONIC_COARSE: u32 = 6;
pub const CLOCK_BOOTTIME: u32 = 7;
pub const CLOCK_REALTIME_ALARM: u32 = 8;
pub const CLOCK_BOOTTIME_ALARM: u32 = 9;
pub const CLOCK_TAI: u32 = 11;

/// `sigev_notify`.
pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;
pub const SIGEV_THREAD: i32 = 2;
pub const SIGEV_THREAD_ID: i32 = 4;

/// `si_code` of a timer's signal.
pub const SI_TIMER: i32 = -2;

/// `TIMER_ABSTIME`.
pub const TIMER_ABSTIME: u64 = 1;

/// How a timer says it expired.
#[derive(Clone, Debug)]
pub enum Notify {
    /// Nothing is sent (`SIGEV_NONE`); `timer_gettime` still reads it.
    None,
    /// This signal to the process.
    Process(u32),
    /// This signal to one of its threads (`SIGEV_THREAD_ID`); nothing once
    /// the thread is gone.
    Thread(u32, Weak<ThreadSig>),
}

#[derive(Debug)]
pub struct Timer {
    pub id: i32,
    pub clock: u32,
    pub notify: Notify,
    /// `sigev_value`, the signal's `si_value`.
    pub value: u64,
    /// When it next expires, on the clock [`crate::signal::ProcSig::fire_timers`]
    /// is given; `None` disarmed.
    pub next: Option<u128>,
    /// Its period; 0 for one expiry.
    pub interval: u128,
    /// Expiries since its signal was queued, which the signal will carry.
    pub overrun: i32,
    /// What its last delivered signal carried (`timer_getoverrun`).
    pub overrun_last: i32,
    /// Whether its signal is queued and not yet seen delivered.
    pub queued: bool,
}

/// A process's timers.
#[derive(Debug, Default)]
pub struct Timers {
    next_id: i32,
    pub list: Vec<Timer>,
}

impl Timers {
    /// The earliest expiry of any armed timer.
    pub fn earliest(&self) -> Option<u128> {
        self.list.iter().filter_map(|t| t.next).min()
    }

    /// A new timer's id: the one after the last given (`posix_timer_add`).
    pub fn add(&mut self, clock: u32, notify: Notify, value: Option<u64>) -> i32 {
        let mut id = self.next_id;
        while self.list.iter().any(|t| t.id == id) {
            id = id.wrapping_add(1).max(0);
        }
        self.next_id = id.wrapping_add(1).max(0);
        // With no sigevent the value is the id.
        let value = value.unwrap_or(id as u64);
        self.list.push(Timer { id, clock, notify, value, next: None, interval: 0, overrun: 0, overrun_last: 0, queued: false });
        id
    }

    pub fn get_mut(&mut self, id: i32) -> Result<&mut Timer, Errno> {
        self.list.iter_mut().find(|t| t.id == id).ok_or(Errno::EINVAL)
    }

    pub fn delete(&mut self, id: i32) -> Result<(), Errno> {
        let i = self.list.iter().position(|t| t.id == id).ok_or(Errno::EINVAL)?;
        self.list.remove(i);
        Ok(())
    }

    /// `execve`: none survive.
    pub fn clear(&mut self) {
        self.list.clear();
    }
}

impl Timer {
    /// What is left until it expires and its period, at `now`, as
    /// `timer_gettime` reports them: a periodic timer behind its deadline
    /// (fired late) reports what is left of the current period.
    pub fn remaining(&self, now: u128) -> (u128, u128) {
        let left = match self.next {
            None => 0,
            Some(n) if n > now => n - now,
            Some(n) if self.interval > 0 => self.interval - (now - n) % self.interval,
            Some(_) => 0,
        };
        (left, self.interval)
    }
}

/// A `struct sigevent` as the caller laid it out: the value, the signal,
/// the notify kind and the thread id.
pub fn parse_sigevent(b: &[u8], compat: bool) -> (u64, i32, i32, i32) {
    let i32_at = |at: usize| i32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    if compat {
        (u32::from_le_bytes(b[0..4].try_into().unwrap()) as u64, i32_at(4), i32_at(8), i32_at(12))
    } else {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()), i32_at(8), i32_at(12), i32_at(16))
    }
}

/// `good_sigevent`: how a timer with this sigevent notifies, given a way to
/// find a thread of the caller's process by id; `EINVAL` for a bad one.
pub fn notify_of(signo: i32, notify: i32, tid: i32, thread: impl Fn(i32) -> Option<Arc<ThreadSig>>) -> Result<Notify, Errno> {
    let target = if notify & SIGEV_THREAD_ID != 0 {
        Some(thread(tid).ok_or(Errno::EINVAL)?)
    } else {
        None
    };
    match notify & !SIGEV_THREAD_ID {
        SIGEV_SIGNAL | SIGEV_THREAD => {
            if !(1..=64).contains(&signo) {
                return Err(Errno::EINVAL);
            }
            Ok(match target {
                Some(t) => Notify::Thread(signo as u32, Arc::downgrade(&t)),
                None => Notify::Process(signo as u32),
            })
        }
        SIGEV_NONE => Ok(Notify::None),
        _ => Err(Errno::EINVAL),
    }
}

/// A clock's answer to `timer_create` (`clockid_to_kclock` and the clock's
/// `timer_create`): `Ok` for one this kernel times, else the error.
/// `wake_alarm`: the caller has `CAP_WAKE_ALARM`.
pub fn clock_ok(clock: i32, wake_alarm: bool, pid: i32) -> Result<(), Errno> {
    if clock < 0 {
        // Another process's or thread's CPU clock.
        say_cpu(pid);
        return Err(Errno::EINVAL);
    }
    match clock as u32 {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_TAI => Ok(()),
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => {
            if wake_alarm {
                Ok(())
            } else {
                Err(Errno::EPERM)
            }
        }
        CLOCK_MONOTONIC_RAW | CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => Err(Errno::EOPNOTSUPP),
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            say_cpu(pid);
            Err(Errno::EINVAL)
        }
        _ => Err(Errno::EINVAL),
    }
}

fn say_cpu(pid: i32) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("[gex:{pid}] timer_create: timers on CPU-time clocks are not implemented -> EINVAL");
    }
}

/// `timespec64_valid` of a `(seconds, nanoseconds)` pair.
pub fn valid(sec: i64, nsec: i64) -> bool {
    sec >= 0 && (0..1_000_000_000).contains(&nsec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_on_and_a_deleted_one_is_not_given_at_once() {
        let mut t = Timers::default();
        let a = t.add(CLOCK_MONOTONIC, Notify::None, Some(5));
        let b = t.add(CLOCK_MONOTONIC, Notify::None, None);
        assert_eq!((a, b), (0, 1));
        assert_eq!(t.get_mut(b).unwrap().value, 1);
        t.delete(a).unwrap();
        assert_eq!(t.add(CLOCK_MONOTONIC, Notify::None, None), 2);
        assert_eq!(t.delete(a), Err(Errno::EINVAL));
    }

    #[test]
    fn remaining_as_gettime_reports_it() {
        let mut t = Timers::default();
        let id = t.add(CLOCK_MONOTONIC, Notify::None, None);
        let x = t.get_mut(id).unwrap();
        assert_eq!(x.remaining(100), (0, 0));
        x.next = Some(150);
        assert_eq!(x.remaining(100), (50, 0));
        assert_eq!(x.remaining(200), (0, 0));
        x.interval = 30;
        assert_eq!(x.remaining(200), (10, 30));
    }

    #[test]
    fn sigevents_are_checked_as_good_sigevent_does() {
        let none = |_| None;
        assert!(matches!(notify_of(10, SIGEV_SIGNAL, 0, none), Ok(Notify::Process(10))));
        assert!(matches!(notify_of(10, SIGEV_THREAD, 0, none), Ok(Notify::Process(10))));
        assert_eq!(notify_of(0, SIGEV_SIGNAL, 0, none).err(), Some(Errno::EINVAL));
        assert_eq!(notify_of(65, SIGEV_SIGNAL, 0, none).err(), Some(Errno::EINVAL));
        assert!(matches!(notify_of(0, SIGEV_NONE, 0, none), Ok(Notify::None)));
        assert_eq!(notify_of(10, 9, 0, none).err(), Some(Errno::EINVAL));
        assert_eq!(notify_of(10, SIGEV_THREAD_ID, 1, none).err(), Some(Errno::EINVAL));
        assert_eq!(clock_ok(99, false, 1), Err(Errno::EINVAL));
        assert_eq!(clock_ok(CLOCK_BOOTTIME_ALARM as i32, false, 1), Err(Errno::EPERM));
        assert_eq!(clock_ok(CLOCK_MONOTONIC_RAW as i32, false, 1), Err(Errno::EOPNOTSUPP));
        assert!(valid(0, 999_999_999) && !valid(0, 1_000_000_000) && !valid(-1, 0) && !valid(0, -1));
    }
}
