//! A process's own SELinux attributes: the files of `/proc/<pid>/attr`.
//!
//! `current` is the context the process runs as and `prev` the one it had
//! before its last `execve`. The other four are requests: `exec` the
//! context its next `execve` gives it, `fscreate`, `keycreate` and
//! `sockcreate` the contexts of the files, keys and sockets it makes. Each
//! request reads empty until it is made, and is forgotten at `execve`.
//! libselinux's `getcon`, `setcon`, `setexeccon` and `setfscreatecon` are
//! reads and writes of these files.
//!
//! As security/selinux/hooks.c at android17-6.18 (`selinux_lsm_setattr`,
//! `selinux_lsm_getattr`, `selinux_bprm_creds_for_exec`), and as Linux 7.0
//! was seen to behave with a policy loaded. Not here: what the policy
//! lets a process set (the `process` class's `setexec`, `setcurrent`,
//! `dyntransition` and the rest), which waits for the hooks; and the
//! transition an `execve` makes by the program's own label, which waits
//! for files to have labels.

use super::server::{Error, Server, SID_KERNEL};
use crate::errno::Errno;

/// The files, in the order a process's ids are kept.
pub const NAMES: [&str; 6] = ["current", "prev", "exec", "fscreate", "keycreate", "sockcreate"];
pub const CURRENT: usize = 0;
pub const PREV: usize = 1;
pub const EXEC: usize = 2;
pub const FSCREATE: usize = 3;
pub const KEYCREATE: usize = 4;
pub const SOCKCREATE: usize = 5;

/// What the first process is: the kernel's SID, and no request.
pub const INITIAL: [u32; 6] = [SID_KERNEL, SID_KERNEL, 0, 0, 0, 0];

/// A file's place among [`NAMES`].
pub fn which(name: &str) -> Option<usize> {
    NAMES.iter().position(|n| *n == name)
}

/// A file's mode: `prev` only reads.
pub fn mode(which: usize) -> u32 {
    if which == PREV {
        0o444
    } else {
        0o666
    }
}

fn errno(e: Error) -> Errno {
    match e {
        Error::Invalid => Errno::EINVAL,
        Error::Denied => Errno::EACCES,
        Error::NotPermitted => Errno::EPERM,
    }
}

/// What a file reads: the context of the SID it holds and the NUL that
/// ends it, or nothing for a request not made.
pub fn read(s: &Server, sid: u32) -> Result<Vec<u8>, Errno> {
    if sid == 0 {
        return Ok(Vec::new());
    }
    let text = s.sid_to_context(sid, false).map_err(errno)?;
    Ok([text.as_bytes(), b"\0"].concat())
}

/// A write to file `which` of a process's own: the SID it now holds, and
/// what the write returns.
///
/// Nothing, or text that starts with a NUL or a newline, takes a request
/// back. A newline at the end is not part of the context and is not
/// counted in what the write returns. `current` cannot be taken back, and
/// `prev` cannot be set. A context the policy has no words for can still
/// be asked for the files a process with `CAP_MAC_ADMIN` makes
/// (`mac_admin`): it is kept as written.
pub fn written(s: &mut Server, which: usize, value: &[u8], mac_admin: bool) -> Result<(u32, u64), Errno> {
    if !(CURRENT..=SOCKCREATE).contains(&which) || which == PREV {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut size = value.len();
    let mut sid = 0;
    if size > 0 && value[0] != 0 && value[0] != b'\n' {
        if value[size - 1] == b'\n' {
            size -= 1;
        }
        // The kernel reads it as a string: to its first NUL.
        let bytes = &value[..size];
        let text = String::from_utf8_lossy(&bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(size)]).into_owned();
        sid = match s.context_to_sid(&text) {
            Ok(sid) => sid,
            Err(Error::Invalid) if which == FSCREATE && mac_admin => s.context_to_sid_force(&text).map_err(errno)?,
            Err(e) => return Err(errno(e)),
        };
    }
    if which == CURRENT && sid == 0 {
        return Err(Errno::EINVAL);
    }
    Ok((sid, size as u64))
}

/// A process's ids after an `execve`: it is what it asked to be, or what
/// it was; what it was is `prev`; and its requests are forgotten.
pub fn exec(ids: [u32; 6]) -> [u32; 6] {
    let now = if ids[EXEC] != 0 { ids[EXEC] } else { ids[CURRENT] };
    [now, ids[CURRENT], 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    const V33: &[u8] = include_bytes!("testdata/test.33");
    const INIT: &[u8] = b"system_u:system_r:init_t:s0";
    const FILE: &[u8] = b"system_u:object_r:file_t:s0";
    const KERNEL: &[u8] = b"system_u:system_r:kernel_t:s0";

    /// Each write Linux 7.0 was given with test.33 loaded, what it
    /// returned and what the file then read (a process of kernel_t, by
    /// root and by an ordinary user alike).
    #[test]
    fn a_processs_files_take_and_read_as_a_kernels() {
        let mut s = Server::default();
        s.load(V33).unwrap();
        let mut ids = INITIAL;
        let show = |s: &Server, sid: u32| String::from_utf8(read(s, sid).unwrap()).unwrap();
        assert_eq!((show(&s, ids[CURRENT]), show(&s, ids[PREV]), show(&s, ids[EXEC])), ("system_u:system_r:kernel_t:s0\0".into(), "system_u:system_r:kernel_t:s0\0".into(), String::new()));
        fn write(s: &mut Server, ids: &mut [u32; 6], which: usize, value: &[u8]) -> (Result<u64, Errno>, String) {
            let r = written(s, which, value, false);
            if let Ok((sid, _)) = r {
                ids[which] = sid;
            }
            (r.map(|(_, n)| n), String::from_utf8(read(s, ids[which]).unwrap()).unwrap())
        }
        let init = "system_u:system_r:init_t:s0\0".to_string();
        let file = "system_u:object_r:file_t:s0\0".to_string();
        assert_eq!(write(&mut s, &mut ids, EXEC, INIT), (Ok(27), init.clone()));
        assert_eq!(write(&mut s, &mut ids, EXEC, &[INIT, b"\n"].concat()), (Ok(27), init.clone()), "the newline is not counted");
        assert_eq!(write(&mut s, &mut ids, EXEC, &[INIT, b"\0"].concat()), (Ok(28), init.clone()));
        assert_eq!(write(&mut s, &mut ids, EXEC, b"nobody:system_r:init_t:s0"), (Err(Errno::EINVAL), init.clone()));
        assert_eq!(write(&mut s, &mut ids, EXEC, b""), (Ok(0), String::new()));
        assert_eq!(write(&mut s, &mut ids, EXEC, INIT), (Ok(27), init.clone()));
        assert_eq!(write(&mut s, &mut ids, EXEC, b"\n"), (Ok(1), String::new()));
        assert_eq!(write(&mut s, &mut ids, EXEC, INIT), (Ok(27), init.clone()));
        assert_eq!(write(&mut s, &mut ids, EXEC, b"\0"), (Ok(1), String::new()));
        assert_eq!(write(&mut s, &mut ids, FSCREATE, FILE), (Ok(27), file.clone()));
        assert_eq!(write(&mut s, &mut ids, FSCREATE, b"\0"), (Ok(1), String::new()));
        assert_eq!(write(&mut s, &mut ids, SOCKCREATE, FILE), (Ok(27), file.clone()));
        assert_eq!(write(&mut s, &mut ids, SOCKCREATE, b""), (Ok(0), String::new()));
        assert_eq!(write(&mut s, &mut ids, KEYCREATE, FILE), (Ok(27), file.clone()));
        assert_eq!(write(&mut s, &mut ids, KEYCREATE, b"\n"), (Ok(1), String::new()));
        assert_eq!(write(&mut s, &mut ids, PREV, KERNEL), (Err(Errno::EOPNOTSUPP), "system_u:system_r:kernel_t:s0\0".into()));
        // An alias is written as the type it names; and nothing enforced
        // keeps a process from a file's context.
        assert_eq!(write(&mut s, &mut ids, CURRENT, b"system_u:object_r:old_file_t:s0"), (Ok(31), file.clone()));
        assert_eq!(write(&mut s, &mut ids, CURRENT, b"junk"), (Err(Errno::EINVAL), file.clone()));
        // setcon leaves prev as it was.
        assert_eq!(write(&mut s, &mut ids, CURRENT, INIT), (Ok(27), init.clone()));
        assert_eq!(show(&s, ids[PREV]), "system_u:system_r:kernel_t:s0\0");
        // From the reference, not seen: current cannot be taken back.
        assert_eq!(write(&mut s, &mut ids, CURRENT, b"").0, Err(Errno::EINVAL));
        assert_eq!(write(&mut s, &mut ids, CURRENT, b"\n").0, Err(Errno::EINVAL));
    }

    /// An `execve`: as seen, a process that had asked for nothing is what
    /// it was, with that as `prev` and `exec` empty. From the reference:
    /// one that had asked becomes what it asked, and every request is
    /// forgotten.
    #[test]
    fn an_exec_takes_the_request_and_forgets_the_rest() {
        assert_eq!(exec([30, 1, 0, 0, 0, 0]), [30, 30, 0, 0, 0, 0]);
        assert_eq!(exec([30, 1, 31, 32, 33, 34]), [31, 30, 0, 0, 0, 0]);
    }

    /// From the reference, not seen: a context the policy has no words
    /// for may be asked for a privileged process's files, and is kept as
    /// written, reading as unlabeled; for anything else, or by anyone
    /// else, it is no context.
    #[test]
    fn a_privileged_process_may_ask_for_a_context_the_policy_lacks() {
        let mut s = Server::default();
        s.load(V33).unwrap();
        let odd = b"nobody:system_r:init_t:s0";
        assert_eq!(written(&mut s, FSCREATE, odd, false), Err(Errno::EINVAL));
        assert_eq!(written(&mut s, EXEC, odd, true), Err(Errno::EINVAL));
        let (sid, n) = written(&mut s, FSCREATE, odd, true).unwrap();
        assert_eq!(n, 25);
        assert_eq!(written(&mut s, FSCREATE, odd, true), Ok((sid, 25)), "the same text, the same SID");
        assert_eq!(read(&s, sid).unwrap(), b"system_u:object_r:file_t:s0\0", "unlabeled, to who may not see it as written");
        assert_eq!(s.sid_to_context(sid, true).as_deref(), Ok("nobody:system_r:init_t:s0"));
    }

    /// Before a policy every process is "kernel", and whatever it writes
    /// is the kernel's SID.
    #[test]
    fn before_a_policy_a_process_is_the_kernel() {
        let mut s = Server::default();
        assert_eq!(read(&s, INITIAL[CURRENT]).unwrap(), b"kernel\0");
        assert_eq!(read(&s, INITIAL[EXEC]).unwrap(), b"");
        assert_eq!(written(&mut s, EXEC, b"anything", false), Ok((SID_KERNEL, 8)));
    }
}
