//! Linux error numbers, and the negative-return convention.
//!
//! The aarch64 syscall ABI reports failure by returning `-errno` in `x0`, so
//! errors are values here rather than a separate channel.

/// A Linux errno value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Errno(pub i32);

/// gex-store's failures are the kernel's errnos.
impl From<gex_store::Errno> for Errno {
    fn from(e: gex_store::Errno) -> Errno {
        Errno(e.0)
    }
}

impl Errno {
    pub const EPERM: Errno = Errno(1);
    pub const ENOENT: Errno = Errno(2);
    pub const ESRCH: Errno = Errno(3);
    pub const EINTR: Errno = Errno(4);
    pub const EIO: Errno = Errno(5);
    pub const ENXIO: Errno = Errno(6);
    pub const ENOTBLK: Errno = Errno(15);
    pub const E2BIG: Errno = Errno(7);
    pub const EBADF: Errno = Errno(9);
    /// File descriptor in bad state (a TUN descriptor with no device).
    pub const EBADFD: Errno = Errno(77);
    pub const ECHILD: Errno = Errno(10);
    pub const EAGAIN: Errno = Errno(11);
    pub const ENOEXEC: Errno = Errno(8);
    pub const ENOMEM: Errno = Errno(12);
    pub const EACCES: Errno = Errno(13);
    pub const EFAULT: Errno = Errno(14);
    pub const EBUSY: Errno = Errno(16);
    pub const EEXIST: Errno = Errno(17);
    pub const EXDEV: Errno = Errno(18);
    pub const ENODEV: Errno = Errno(19);
    pub const ENOTDIR: Errno = Errno(20);
    pub const EISDIR: Errno = Errno(21);
    pub const EINVAL: Errno = Errno(22);
    pub const ENFILE: Errno = Errno(23);
    pub const EMFILE: Errno = Errno(24);
    pub const ENOTTY: Errno = Errno(25);
    pub const EFBIG: Errno = Errno(27);
    pub const ENOSPC: Errno = Errno(28);
    pub const ESPIPE: Errno = Errno(29);
    pub const EROFS: Errno = Errno(30);
    pub const EPIPE: Errno = Errno(32);
    pub const ERANGE: Errno = Errno(34);
    pub const EDEADLK: Errno = Errno(35);
    pub const EOVERFLOW: Errno = Errno(75);
    pub const ENAMETOOLONG: Errno = Errno(36);
    pub const ENOSYS: Errno = Errno(38);
    pub const ENOTEMPTY: Errno = Errno(39);
    pub const ELOOP: Errno = Errno(40);
    /// Also `ENOATTR`: no such extended attribute.
    pub const ENODATA: Errno = Errno(61);
    pub const ETIMEDOUT: Errno = Errno(110);
    pub const EOPNOTSUPP: Errno = Errno(95);
    pub const EAFNOSUPPORT: Errno = Errno(97);
    pub const ECONNREFUSED: Errno = Errno(111);
    pub const EADDRINUSE: Errno = Errno(98);
    /// The same number as EAGAIN on Linux, and the name `flock` uses.
    pub const EWOULDBLOCK: Errno = Errno(11);
    pub const ENOTCONN: Errno = Errno(107);
    pub const EINPROGRESS: Errno = Errno(115);
    pub const EPROTONOSUPPORT: Errno = Errno(93);
    pub const ESOCKTNOSUPPORT: Errno = Errno(94);
    /// "Structure needs cleaning": a filesystem's `EFSCORRUPTED`.
    pub const EUCLEAN: Errno = Errno(117);
    pub const ENOBUFS: Errno = Errno(105);
    /// An operation called off: a `timerfd` read after the clock it is
    /// armed against was set (`TFD_TIMER_CANCEL_ON_SET`).
    pub const ECANCELED: Errno = Errno(125);
    pub const ESTALE: Errno = Errno(116);
    pub const EADDRNOTAVAIL: Errno = Errno(99);
    pub const ENETUNREACH: Errno = Errno(101);
    pub const ENOTSOCK: Errno = Errno(88);
    pub const EMSGSIZE: Errno = Errno(90);
    /// Protocol error (a membership asked of a stream socket).
    pub const EPROTO: Errno = Errno(71);
    pub const EPROTOTYPE: Errno = Errno(91);
    pub const ENOPROTOOPT: Errno = Errno(92);
    pub const ECONNRESET: Errno = Errno(104);
    pub const EISCONN: Errno = Errno(106);
    /// Only between a process and the global kernel, never a guest's: a
    /// moved socket another holder connected out (`net::op::WENT_OUT`).
    pub const EREMCHG: Errno = Errno(78);

    /// The value the guest sees in `x0`.
    pub fn as_return(self) -> u64 {
        (-(self.0 as i64)) as u64
    }

    /// Map a host I/O error onto the guest errno. The host's own number
    /// comes first: `ErrorKind` folds `EPERM` into `EACCES`.
    pub fn from_io(e: &std::io::Error) -> Errno {
        use std::io::ErrorKind::*;
        if let Some(code) = e.raw_os_error().filter(|&c| c > 0) {
            return Errno::from_host(code);
        }
        match e.kind() {
            NotFound => Errno::ENOENT,
            PermissionDenied => Errno::EACCES,
            AlreadyExists => Errno::EEXIST,
            InvalidInput => Errno::EINVAL,
            BrokenPipe => Errno::EPIPE,
            WouldBlock => Errno::EAGAIN,
            Interrupted => Errno::EINTR,
            _ => match e.raw_os_error() {
                Some(code) if code > 0 => Errno::from_host(code),
                _ => Errno::EIO,
            },
        }
    }

    /// A host's raw errno as Linux numbers it. A Linux host's passes
    /// straight through.
    #[cfg(not(target_os = "macos"))]
    pub fn from_host(code: i32) -> Errno {
        if code == 24 {
            host_out_of_descriptors();
        }
        Errno(code)
    }

    /// A host's raw errno as Linux numbers it: XNU's `sys/errno.h` against
    /// Linux's `asm-generic/errno*.h`, name for name. `ENOATTR` is Linux's
    /// `ENODATA`, and XNU's discrete `EOPNOTSUPP` (102) and `ENOTSUP` (45)
    /// are both Linux's 95. XNU's own errors with no Linux name (Mach-O,
    /// RPC, power, policy) are reported and reach the guest as `EIO`.
    #[cfg(target_os = "macos")]
    pub fn from_host(code: i32) -> Errno {
        if code == 24 {
            host_out_of_descriptors();
        }
        match macos_to_linux(code) {
            Some(v) => Errno(v),
            None => {
                eprintln!("gex: host errno {code} has no Linux errno; the guest sees EIO");
                Errno::EIO
            }
        }
    }
}

/// The host refused gex a descriptor (`EMFILE`, the same number on both
/// hosts): every guest process's host files and every translation mapped
/// from the cache are this one process's descriptors, and the guest is
/// told EMFILE for a table of its own that is nowhere near full. Said once,
/// with how many the host process holds and, where the host names them
/// (Linux's `/proc/self/fd`), how many are cached translations, when there
/// is a descriptor left to look with; at the limit there is not.
fn host_out_of_descriptors() {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    let (mut open, mut cached) = (0usize, 0usize);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            open += 1;
            if std::fs::read_link(e.path()).is_ok_and(|t| t.extension().is_some_and(|x| x == "cwasm")) {
                cached += 1;
            }
        }
    }
    let held = if open == 0 {
        "every descriptor the host allows it".to_string()
    } else if cfg!(target_os = "linux") {
        format!("{open}, {cached} of them cached translations")
    } else {
        open.to_string()
    };
    eprintln!("[gex] the host is out of descriptors (EMFILE): gex holds {held}; the guest is told EMFILE");
}

#[cfg(target_os = "macos")]
fn macos_to_linux(code: i32) -> Option<i32> {
    Some(match code {
        1 => 1, // EPERM
        2 => 2, // ENOENT
        3 => 3, // ESRCH
        4 => 4, // EINTR
        5 => 5, // EIO
        6 => 6, // ENXIO
        7 => 7, // E2BIG
        8 => 8, // ENOEXEC
        9 => 9, // EBADF
        10 => 10, // ECHILD
        11 => 35, // EDEADLK
        12 => 12, // ENOMEM
        13 => 13, // EACCES
        14 => 14, // EFAULT
        15 => 15, // ENOTBLK
        16 => 16, // EBUSY
        17 => 17, // EEXIST
        18 => 18, // EXDEV
        19 => 19, // ENODEV
        20 => 20, // ENOTDIR
        21 => 21, // EISDIR
        22 => 22, // EINVAL
        23 => 23, // ENFILE
        24 => 24, // EMFILE
        25 => 25, // ENOTTY
        26 => 26, // ETXTBSY
        27 => 27, // EFBIG
        28 => 28, // ENOSPC
        29 => 29, // ESPIPE
        30 => 30, // EROFS
        31 => 31, // EMLINK
        32 => 32, // EPIPE
        33 => 33, // EDOM
        34 => 34, // ERANGE
        35 => 11, // EAGAIN
        36 => 115, // EINPROGRESS
        37 => 114, // EALREADY
        38 => 88, // ENOTSOCK
        39 => 89, // EDESTADDRREQ
        40 => 90, // EMSGSIZE
        41 => 91, // EPROTOTYPE
        42 => 92, // ENOPROTOOPT
        43 => 93, // EPROTONOSUPPORT
        44 => 94, // ESOCKTNOSUPPORT
        45 => 95, // ENOTSUP
        46 => 96, // EPFNOSUPPORT
        47 => 97, // EAFNOSUPPORT
        48 => 98, // EADDRINUSE
        49 => 99, // EADDRNOTAVAIL
        50 => 100, // ENETDOWN
        51 => 101, // ENETUNREACH
        52 => 102, // ENETRESET
        53 => 103, // ECONNABORTED
        54 => 104, // ECONNRESET
        55 => 105, // ENOBUFS
        56 => 106, // EISCONN
        57 => 107, // ENOTCONN
        58 => 108, // ESHUTDOWN
        59 => 109, // ETOOMANYREFS
        60 => 110, // ETIMEDOUT
        61 => 111, // ECONNREFUSED
        62 => 40, // ELOOP
        63 => 36, // ENAMETOOLONG
        64 => 112, // EHOSTDOWN
        65 => 113, // EHOSTUNREACH
        66 => 39, // ENOTEMPTY
        68 => 87, // EUSERS
        69 => 122, // EDQUOT
        70 => 116, // ESTALE
        71 => 66, // EREMOTE
        77 => 37, // ENOLCK
        78 => 38, // ENOSYS
        84 => 75, // EOVERFLOW
        89 => 125, // ECANCELED
        90 => 43, // EIDRM
        91 => 42, // ENOMSG
        92 => 84, // EILSEQ
        93 => 61, // ENOATTR
        94 => 74, // EBADMSG
        95 => 72, // EMULTIHOP
        96 => 61, // ENODATA
        97 => 67, // ENOLINK
        98 => 63, // ENOSR
        99 => 60, // ENOSTR
        100 => 71, // EPROTO
        101 => 62, // ETIME
        102 => 95, // EOPNOTSUPP
        104 => 131, // ENOTRECOVERABLE
        105 => 130, // EOWNERDEAD
        _ => return None,
    })
}

/// The result of a syscall that produces a value.
pub type SysResult = Result<u64, Errno>;

/// Convert a syscall result to the `x0` the guest expects.
pub fn encode(r: SysResult) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => e.as_return(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_host_error_keeps_its_own_meaning() {
        use super::Errno;
        use std::io::Error;
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(1)), Errno::EPERM);
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(13)), Errno::EACCES);
        let not_empty = if cfg!(target_os = "macos") { 66 } else { 39 };
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(not_empty)), Errno(39));
        let again = if cfg!(target_os = "macos") { 35 } else { 11 };
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(again)), Errno::EAGAIN);
    }

    use super::*;

    #[test]
    fn errors_encode_as_negative() {
        assert_eq!(encode(Err(Errno::ENOENT)) as i64, -2);
        assert_eq!(encode(Err(Errno::ENOSYS)) as i64, -38);
        assert_eq!(encode(Ok(17)), 17);
        // A large successful return must not look like an error.
        assert_eq!(encode(Ok(0x7fff_ffff_ffff_ffff)), 0x7fff_ffff_ffff_ffff);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_errors_are_linux_numbers() {
        let io = |c| Errno::from_io(&std::io::Error::from_raw_os_error(c));
        assert_eq!(io(66), Errno::ENOTEMPTY);
        assert_eq!(io(62), Errno::ELOOP);
        assert_eq!(io(63), Errno::ENAMETOOLONG);
        assert_eq!(io(93), Errno::ENODATA);
        assert_eq!(io(102), Errno::EOPNOTSUPP);
        assert_eq!(io(45), Errno::EOPNOTSUPP);
        assert_eq!(io(35), Errno::EAGAIN);
        assert_eq!(io(78), Errno::ENOSYS);
        assert_eq!(io(88), Errno::EIO);
    }
}
