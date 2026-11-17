//! The kernel's log, and `/dev/kmsg`, the device a program reads it from
//! and writes to it by (character device 1:11).
//!
//! Android's init has no other log: until logd is up, everything it and
//! its first services say is a line written here. A write is one record,
//! with an optional `<N>` before its text, whose low three bits are the
//! level and the rest the facility; a reader gets one record a read, as
//! `level,sequence,microseconds,-;text`, waits for the next when there
//! is none, and is told (`EPIPE`) when the ones it had not read were
//! dropped to make room. A record whose write did not end in a newline
//! may still be continued, so it is not a reader's to have until the
//! next record is written (as Linux 7.0's device was seen to behave).
//!
//! As kernel/printk/printk.c at android17-6.18 in what `/dev/kmsg` shows
//! (`devkmsg_write`, `devkmsg_read`, `devkmsg_llseek`, `devkmsg_poll`). A
//! record below the console's level is also written to the host's standard
//! error, which is this kernel's console. Not here: the kernel's own
//! messages (this kernel logs to the host), a record's dictionary, the
//! `syslog` call, and the rate limit on writers: every write is kept.

use super::{FileHandle, Metadata};
use crate::errno::{Errno, SysResult};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// `PRINTKRB_RECORD_MAX`: the longest record a write may make.
const RECORD_MAX: usize = 1024;
/// How much text the log keeps before its oldest records go
/// (`CONFIG_LOG_BUF_SHIFT` of 18).
const KEPT: usize = 1 << 18;
/// `CONSOLE_LOGLEVEL_DEFAULT`: records of a lower level reach the console.
const CONSOLE_LEVEL: u32 = 7;
/// `default_message_loglevel`, and the facility of a record that names
/// none (`LOG_USER`): one from a program is never the kernel's.
const DEFAULT_LEVEL: u32 = 4;
const LOG_USER: u32 = 1;

struct Record {
    seq: u64,
    /// Since the log began.
    ts_ns: u64,
    facility: u32,
    level: u32,
    text: String,
    /// Written with no newline at its end, and the newest: it might be
    /// continued, and is not read yet.
    open: bool,
}

#[derive(Default)]
struct Log {
    records: VecDeque<Record>,
    /// The sequence number the next record gets.
    next: u64,
    bytes: usize,
}

struct Shared {
    log: Mutex<Log>,
    /// Readers that wait for a record.
    queue: crate::wait::Queue,
    /// When the log began, on the vfs's clock.
    began: u64,
}

fn shared() -> &'static Shared {
    static LOG: OnceLock<Shared> = OnceLock::new();
    LOG.get_or_init(|| Shared { log: Mutex::default(), queue: crate::wait::Queue::new(), began: super::tmpfs::now_ns() })
}

/// A record written to the log: `<N>` taken from its front if it has one,
/// kept, and shown on the console if its level calls for that.
fn emit(line: &[u8]) {
    let (mut level, mut facility) = (DEFAULT_LEVEL, LOG_USER);
    let mut text = line;
    if let [b'<', rest @ ..] = line {
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if rest.get(digits) == Some(&b'>') {
            // No digits is the number 0, as `simple_strtoul` has it.
            let n = rest[..digits].iter().fold(0u32, |n, d| n.wrapping_mul(10).wrapping_add((d - b'0') as u32));
            level = n & 7;
            if n >> 3 != 0 {
                facility = n >> 3;
            }
            text = &rest[digits + 1..];
        }
    }
    // The newline a record ends in is not text: it says the record is
    // whole.
    let text = String::from_utf8_lossy(text);
    let open = !text.ends_with('\n');
    let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
    if level < CONSOLE_LEVEL {
        eprintln!("[kmsg] {text}");
    }
    let s = shared();
    let mut log = s.log.lock().unwrap_or_else(|e| e.into_inner());
    // The one before it can be continued no more.
    if let Some(last) = log.records.back_mut() {
        last.open = false;
    }
    let seq = log.next;
    log.next += 1;
    log.bytes += text.len();
    log.records.push_back(Record { seq, ts_ns: super::tmpfs::now_ns().saturating_sub(s.began), facility, level, text, open });
    while log.bytes > KEPT {
        let Some(gone) = log.records.pop_front() else { break };
        log.bytes -= gone.text.len();
    }
    drop(log);
    s.queue.notify();
}

/// A record as a reader gets it (`info_print_ext_header` and
/// `msg_print_ext_body`): its facility and level, sequence number and
/// time in microseconds, then its text, with a byte that is not printable
/// (or is a backslash) written `\xNN`.
fn printed(r: &Record) -> Vec<u8> {
    let mut out = format!("{},{},{},-;", r.facility << 3 | r.level, r.seq, r.ts_ns / 1000).into_bytes();
    for &b in r.text.as_bytes() {
        if b < b' ' || b >= 127 || b == b'\\' {
            out.extend_from_slice(format!("\\x{b:02x}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out.push(b'\n');
    out
}

/// `/dev/kmsg`, open: where its reader has got to.
pub struct Kmsg {
    /// The sequence number of the next record it reads.
    seq: AtomicU64,
    node: Option<super::devices::NodeMeta>,
}

impl std::fmt::Debug for Kmsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/dev/kmsg")
    }
}

impl Kmsg {
    /// An open of the device: it reads from the oldest record kept.
    pub fn open(node: Option<super::devices::NodeMeta>) -> Arc<Kmsg> {
        let log = shared().log.lock().unwrap_or_else(|e| e.into_inner());
        let first = log.records.front().map_or(log.next, |r| r.seq);
        Arc::new(Kmsg { seq: AtomicU64::new(first), node })
    }
}

impl FileHandle for Kmsg {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        let log = shared().log.lock().unwrap_or_else(|e| e.into_inner());
        let at = self.seq.load(Ordering::Acquire);
        let first = log.records.front().map_or(log.next, |r| r.seq);
        if at < first {
            // What it had not read is gone: it is told, and goes on from
            // the oldest there is.
            self.seq.store(first, Ordering::Release);
            return Err(Errno::EPIPE);
        }
        let Some(r) = log.records.get((at - first) as usize).filter(|r| !r.open) else { return Err(Errno::EAGAIN) };
        let out = printed(r);
        // It is this reader's whether or not it fits: one too long for
        // the buffer is `EINVAL`, and passed over.
        self.seq.store(at + 1, Ordering::Release);
        if out.len() > buf.len() {
            return Err(Errno::EINVAL);
        }
        buf[..out.len()].copy_from_slice(&out);
        Ok(out.len() as u64)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        if buf.len() > RECORD_MAX {
            return Err(Errno::EINVAL);
        }
        emit(buf);
        Ok(buf.len() as u64)
    }

    /// `devkmsg_llseek`: to the oldest record (`SEEK_SET`), or past the
    /// newest (`SEEK_END`; `SEEK_DATA` too, which is past the last
    /// cleared, and nothing clears this log), with no offset. It answers
    /// 0: the device has no position a program can use.
    fn seek(&self, offset: i64, whence: u32) -> Option<SysResult> {
        const SEEK_SET: u32 = 0;
        const SEEK_END: u32 = 2;
        const SEEK_DATA: u32 = 3;
        if offset != 0 {
            return Some(Err(Errno::ESPIPE));
        }
        let log = shared().log.lock().unwrap_or_else(|e| e.into_inner());
        let first = log.records.front().map_or(log.next, |r| r.seq);
        // Past every record a reader can have: one still open is next.
        let end = log.records.back().filter(|r| r.open).map_or(log.next, |r| r.seq);
        match whence {
            SEEK_SET => self.seq.store(first, Ordering::Release),
            SEEK_DATA => self.seq.store(first, Ordering::Release),
            SEEK_END => self.seq.store(end, Ordering::Release),
            _ => return Some(Err(Errno::EINVAL)),
        }
        Some(Ok(0))
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        // A record to read, or the news that some were dropped.
        let log = shared().log.lock().unwrap_or_else(|e| e.into_inner());
        let end = log.records.back().filter(|r| r.open).map_or(log.next, |r| r.seq);
        self.seq.load(Ordering::Acquire) < end
    }

    fn wait_queue(&self) -> u32 {
        shared().queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(shared().queue.wakes())
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        match &self.node {
            Some(node) => Ok(node()),
            None => Ok(Metadata { file_type: super::FileType::CharDevice, size: 0, mode: 0o644, ino: 1, mtime: 0, nlink: 1, rdev: super::devices::makedev(1, 11), dev: 0, times: Default::default(), owner: None }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(k: &Kmsg) -> Result<String, Errno> {
        let mut buf = [0u8; 2048];
        k.read_at(0, &mut buf).map(|n| String::from_utf8(buf[..n as usize].to_vec()).unwrap())
    }

    /// The fields after a record's header, and its text.
    fn parts(record: &str) -> (u32, u64, String) {
        let (header, text) = record.split_once(';').unwrap();
        let f: Vec<&str> = header.split(',').collect();
        assert_eq!((f.len(), f[3]), (4, "-"), "{record}");
        assert!(f[2].parse::<u64>().is_ok());
        (f[0].parse().unwrap(), f[1].parse().unwrap(), text.to_string())
    }

    /// A write is a record, its `<N>` its level and facility (a
    /// program's is never the kernel's facility); a reader gets a record
    /// a read, in order, and `EAGAIN` when there is no more; one written
    /// with no newline is not read until another follows it, and one too
    /// long for the reader's buffer is lost to it (both as on Linux 7.0:
    /// tests/android/src/kmsg.c); one too long to write is refused.
    #[test]
    fn a_write_is_a_record_and_a_read_is_one() {
        // The log is one for the kernel, and tests share it: this reader
        // starts past whatever another test wrote.
        let k = Kmsg::open(None);
        let put = |line: &[u8]| assert_eq!(k.write_at(0, line), Ok(line.len() as u64));
        put(b"<6>whatever was open is closed by this\n");
        assert_eq!(k.seek(0, 2), Some(Ok(0)));
        assert_eq!(read(&k), Err(Errno::EAGAIN));
        assert!(!k.poll_readable());
        put(b"<6>init: second stage\n");
        assert!(k.poll_readable());
        put(b"no level at all");
        put(b"<27>a daemon's error");
        put(b"<x>not a level, and a \\ and a \x01");
        let (prio, seq, text) = parts(&read(&k).unwrap());
        assert_eq!((prio, text.as_str()), (LOG_USER << 3 | 6, "init: second stage\n"));
        let (prio, next, text) = parts(&read(&k).unwrap());
        assert_eq!((prio, next, text.as_str()), (LOG_USER << 3 | DEFAULT_LEVEL, seq + 1, "no level at all\n"));
        let (prio, _, text) = parts(&read(&k).unwrap());
        assert_eq!((prio, text.as_str()), (27, "a daemon's error\n"));
        // The last had no newline: not yet, and a seek to the end stays
        // before it.
        assert_eq!((read(&k), k.poll_readable()), (Err(Errno::EAGAIN), false));
        assert_eq!((k.seek(0, 2), read(&k)), (Some(Ok(0)), Err(Errno::EAGAIN)));
        put(b"<6>a longer line than the buffer\n");
        let (_, _, text) = parts(&read(&k).unwrap());
        assert_eq!(text, "<x>not a level, and a \\x5c and a \\x01\n");
        // A buffer too small for the record is EINVAL, and the record is
        // passed over.
        let mut small = [0u8; 8];
        assert_eq!(k.read_at(0, &mut small), Err(Errno::EINVAL));
        assert_eq!(read(&k), Err(Errno::EAGAIN));
        assert_eq!(k.write_at(0, &[b'a'; RECORD_MAX + 1]), Err(Errno::EINVAL));
        // Another open reads from the oldest record kept; a seek to the
        // end is past them all.
        let other = Kmsg::open(None);
        assert!(other.poll_readable());
        assert_eq!((other.seek(0, 2), other.poll_readable()), (Some(Ok(0)), false));
        assert_eq!((other.seek(1, 0), other.seek(0, 9)), (Some(Err(Errno::ESPIPE)), Some(Err(Errno::EINVAL))));
        assert_eq!(k.metadata().unwrap().rdev, super::super::devices::makedev(1, 11));
    }
}
