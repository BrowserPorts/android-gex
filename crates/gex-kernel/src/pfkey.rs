//! `AF_KEY` sockets (PF_KEY version 2, `net/key/af_key.c` at Linux 6.18,
//! built into GKI as `CONFIG_NET_KEY`).
//!
//! Android makes one and closes it straight away (`synchronizeKernelRCU`
//! in the BPF headers its network stack shares): closing it waits for an
//! RCU grace period, which is what the network statistics service wants
//! before it reads a map it has just swapped. Without the family its
//! service threw, and the system server died with it.
//!
//! A socket is made as `pfkey_create` makes one (`CAP_NET_ADMIN`, then
//! `SOCK_RAW`, then `PF_KEY_V2`) and closes as any; there is no grace
//! period to wait for here (no reader runs under RCU). No security
//! association is kept (`crate::netlink`'s `NETLINK_XFRM` has none
//! either), so nothing is ever broadcast to a socket: a read waits, or is
//! `EAGAIN`. A message sent is refused with `EOPNOTSUPP`, said once.

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::sync::Arc;

/// `AF_KEY`.
pub const AF_KEY: u64 = 15;
/// `PF_KEY_V2`.
pub const PF_KEY_V2: u64 = 2;

/// One socket.
#[derive(Debug)]
pub struct Socket {
    queue: crate::wait::Queue,
}

/// `pfkey_create`: the caller's `CAP_NET_ADMIN`, then the type, then the
/// protocol.
pub fn create(net_admin: bool, kind: u64, protocol: u64) -> Result<Arc<Socket>, Errno> {
    const SOCK_RAW: u64 = 3;
    if !net_admin {
        return Err(Errno::EPERM);
    }
    if kind != SOCK_RAW {
        return Err(Errno::ESOCKTNOSUPPORT);
    }
    if protocol != PF_KEY_V2 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(Arc::new(Socket { queue: crate::wait::Queue::new() }))
}

impl FileHandle for Socket {
    /// Nothing is ever sent to a PF_KEY socket here.
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if buf.is_empty() {
            return Ok(0);
        }
        Err(Errno::EAGAIN)
    }

    /// `pfkey_sendmsg`: a message no security association here could
    /// answer.
    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        let kind = buf.get(1).copied().unwrap_or(0);
        crate::bpf::say_once(&format!("a PF_KEY message (SADB type {kind}): security associations are not kept here"));
        Err(Errno::EOPNOTSUPP)
    }

    fn keeps_records(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        false
    }

    fn poll_in(&self) -> bool {
        false
    }

    fn poll_out(&self) -> bool {
        true
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(self.queue.wakes())
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Socket, size: 0, mode: 0o777, ino: crate::vfs::anon_ino(self as *const Self as *const u8), mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn made_as_pfkey_create_makes_one() {
        assert_eq!(create(false, 3, 2).err(), Some(Errno::EPERM));
        assert_eq!(create(false, 2, 0).err(), Some(Errno::EPERM));
        assert_eq!(create(true, 2, 2).err(), Some(Errno::ESOCKTNOSUPPORT));
        assert_eq!(create(true, 3, 0).err(), Some(Errno::EPROTONOSUPPORT));
        let s = create(true, 3, 2).unwrap();
        let mut b = [0u8; 16];
        assert_eq!(s.read_at(0, &mut b), Err(Errno::EAGAIN));
        assert_eq!(s.write_at(0, &[2, 9, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Errno::EOPNOTSUPP));
    }
}
