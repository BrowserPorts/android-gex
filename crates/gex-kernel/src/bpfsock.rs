//! Sockets as BPF sees them: each socket's cookie (`sock_gen_cookie`), and
//! the programs attached to a control group run where a socket of one of
//! its processes is made (`BPF_CGROUP_INET_SOCK_CREATE`, `struct bpf_sock`
//! as `sock_filter_is_valid_access` lets a program see it).

use crate::bpfrun::{Context, Field};
use crate::errno::Errno;
use crate::vfs::FileHandle;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// Each socket's cookie, by the socket, while it lasts.
static COOKIES: Mutex<Option<HashMap<usize, (Weak<dyn FileHandle>, u64)>>> = Mutex::new(None);

/// A socket's cookie: a number no other socket has had, given when it is
/// first asked for (`SO_COOKIE`, `bpf_get_socket_cookie`).
pub fn cookie_of(sock: &Arc<dyn FileHandle>) -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let at = Arc::as_ptr(sock) as *const () as usize;
    let mut t = COOKIES.lock().unwrap_or_else(|e| e.into_inner());
    let t = t.get_or_insert_with(HashMap::new);
    if let Some((w, c)) = t.get(&at) {
        if w.strong_count() > 0 {
            return *c;
        }
    }
    if t.len() > 1024 {
        t.retain(|_, (w, _)| w.strong_count() > 0);
    }
    let c = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    t.insert(at, (Arc::downgrade(sock), c));
    c
}

/// What a socket keeps that a program or `setsockopt` may set: its mark,
/// its priority, the interface it is bound to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SockOpts {
    pub mark: u32,
    pub priority: u32,
    pub bound_dev_if: u32,
}

/// `struct bpf_sock`'s fields.
mod off {
    pub const BOUND_DEV_IF: u32 = 0;
    pub const FAMILY: u32 = 4;
    pub const TYPE: u32 = 8;
    pub const PROTOCOL: u32 = 12;
    pub const MARK: u32 = 16;
    pub const PRIORITY: u32 = 20;
    pub const SRC_IP4: u32 = 24;
    pub const SRC_IP6: u32 = 28;
    pub const SRC_PORT: u32 = 44;
    pub const DST_PORT: u32 = 48;
    pub const DST_IP4: u32 = 52;
    pub const DST_IP6: u32 = 56;
    pub const STATE: u32 = 72;
    pub const RX_QUEUE_MAPPING: u32 = 76;
    pub const SIZE: u32 = 80;
}

/// A socket as a `cgroup/sock` program sees it.
pub struct SockCtx {
    pub attach: u32,
    pub sock: Arc<dyn FileHandle>,
    pub family: u32,
    pub ty: u32,
    pub protocol: u32,
    pub opts: SockOpts,
    /// `TCP_CLOSE`, for one just made.
    pub state: u32,
    /// The calling task's real group and user (`bpf_get_current_uid_gid`).
    pub uid_gid: u64,
}

impl Context for SockCtx {
    fn load(&mut self, off: u32, size: u8) -> Option<Field> {
        use off::*;
        // The source's address and port only after a bind, which these
        // are not; the rest any program of the kind reads.
        if (SRC_IP4..DST_PORT).contains(&off) || off >= SIZE {
            return None;
        }
        let base = off & !3;
        let v: u32 = match base {
            BOUND_DEV_IF => self.opts.bound_dev_if,
            FAMILY => self.family,
            TYPE => self.ty,
            PROTOCOL => self.protocol,
            MARK => self.opts.mark,
            PRIORITY => self.opts.priority,
            DST_PORT | DST_IP4 => 0,
            b if (DST_IP6..STATE).contains(&b) => 0,
            STATE => self.state,
            RX_QUEUE_MAPPING => u32::MAX,
            _ => return None,
        };
        // Whole, or narrower for an address or a port.
        let narrow_ok = matches!(base, DST_PORT | DST_IP4) || (DST_IP6..STATE).contains(&base);
        let within = off - base;
        if size != 4 && !(narrow_ok && matches!(size, 1 | 2) && within % size as u32 == 0) {
            return None;
        }
        let b = v.to_le_bytes();
        let mut w = [0u8; 8];
        w[..size as usize].copy_from_slice(&b[within as usize..within as usize + size as usize]);
        Some(Field::Scalar(u64::from_le_bytes(w)))
    }

    fn store(&mut self, off: u32, size: u8, value: u64) -> Option<()> {
        use crate::bpfprog::attach::*;
        if size != 4 || !matches!(self.attach, INET_SOCK_CREATE | INET_SOCK_RELEASE) {
            return None;
        }
        let v = value as u32;
        match off {
            off::BOUND_DEV_IF => self.opts.bound_dev_if = v,
            off::MARK => self.opts.mark = v,
            off::PRIORITY => self.opts.priority = v,
            _ => return None,
        }
        Some(())
    }

    fn socket_cookie(&mut self) -> u64 {
        cookie_of(&self.sock)
    }

    fn current_uid_gid(&mut self) -> u64 {
        self.uid_gid
    }

    fn socket(&mut self) -> Option<Arc<dyn FileHandle>> {
        Some(Arc::clone(&self.sock))
    }
}

/// Run the programs that run for process `pid`'s group at `attach` on
/// `ctx`, all of them (`bpf_prog_run_array_cg`): `EPERM` if any said no
/// (an even answer).
pub fn run_group(pid: i32, attach: u32, ctx: &mut dyn Context) -> Result<(), Errno> {
    let progs = {
        let t = crate::cgroup::tree();
        let g = t.group_of(pid);
        crate::cgroup::bpf_effective(&t, g, attach)
    };
    let mut allowed = true;
    for p in progs {
        match crate::bpfrun::run(&p, ctx) {
            Ok(r) if r & 1 == 1 => {}
            // (A run that ended without an answer is taken as no.)
            _ => allowed = false,
        }
    }
    if allowed { Ok(()) } else { Err(Errno::EPERM) }
}

/// A socket of `family`, `ty` and `protocol` has been made by `pid`: the
/// group's socket-creation programs see it and may refuse it (`EPERM`) or
/// set its mark, priority and interface.
#[allow(clippy::too_many_arguments)]
pub fn created(sock: &Arc<dyn FileHandle>, opts: &Mutex<SockOpts>, pid: i32, ruid: u32, rgid: u32, family: u32, ty: u32, protocol: u32) -> Result<(), Errno> {
    let attach = crate::bpfprog::attach::INET_SOCK_CREATE;
    let mut ctx = SockCtx { attach, sock: Arc::clone(sock), family, ty, protocol, opts: *opts.lock().unwrap_or_else(|e| e.into_inner()), state: 7, uid_gid: (rgid as u64) << 32 | ruid as u64 };
    run_group(pid, attach, &mut ctx)?;
    *opts.lock().unwrap_or_else(|e| e.into_inner()) = ctx.opts;
    Ok(())
}
