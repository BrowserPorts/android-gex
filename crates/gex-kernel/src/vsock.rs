//! `AF_VSOCK` stream sockets, as a guest with a virtio-vsock device has
//! them (`net/vmw_vsock/af_vsock.c` and `virtio_transport_common.c` at
//! android17-6.18), with the Android emulator as the host behind it.
//!
//! The emulator image's hardware layers reach the emulator's services this
//! way ([`crate::emuhost`]): a stream to the host (CID 2) at port 5000. The
//! emulator's vsock device (`virtio_vsock_device.cpp`) accepts a
//! connection to port 5000 at any CID it is sent to, and answers every
//! other port with a reset, so `connect` there is `ECONNRESET` (port 5001,
//! which the pipe library connects to as a kick, among them).
//!
//! What a guest sees, after the source:
//! - `socket(AF_VSOCK, SOCK_STREAM, 0 or AF_VSOCK)`; another protocol is
//!   `EPROTONOSUPPORT`. A new socket is unbound: `getsockname` gives CID and
//!   port both `-1` (`VMADDR_CID_ANY`, `VMADDR_PORT_ANY`).
//! - `connect`: an address shorter than `sockaddr_vm`, of another family or
//!   with flags other than `VMADDR_FLAG_TO_HOST` is `EINVAL`; a connected
//!   socket's is `EISCONN`, and one shut down is `EINVAL`. It binds the
//!   socket to an ephemeral port first (the kernel's one counter, from a
//!   random start above 1023), which it keeps whether or not the host
//!   accepts.
//! - A connected socket reads what the host has sent, waiting for it (or
//!   `EAGAIN`); a write is taken whole. Unconnected, both are `ENOTCONN`.
//!   After a `shutdown` in either direction the host closes the stream, as
//!   the emulator does: reads are 0 and writes `EPIPE`.
//! - `poll`: `POLLOUT` while connected and not shut down, or never
//!   connected; `POLLIN` with something to read or once shut; `POLLHUP`
//!   once shut.
//!
//! Not here, and said when asked: datagram and seqpacket sockets, a
//! connect that does not wait (`O_NONBLOCK`), `bind`, `listen` and
//! `accept`, the local CIDs (1, and the guest's own, 3), and `sendmsg` and
//! `recvmsg`.
//!
//! Off unless asked: `GEX_EMULATOR_HOST=1`. Without it `socket(AF_VSOCK)`
//! is `EAFNOSUPPORT`, as on a kernel without vsock.

use crate::emuhost::Connection;
use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const AF_VSOCK: u64 = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_PORT_ANY: u32 = u32::MAX;
const VMADDR_CID_LOCAL: u32 = 1;
/// The CID the emulator gives its guest.
const GUEST_CID: u32 = 3;
const VMADDR_FLAG_TO_HOST: u8 = 1;
const LAST_RESERVED_PORT: u32 = 1023;
/// The emulator's pipe services (`DstPort::Data`).
const DATA_PORT: u32 = 5000;
/// `sizeof(struct sockaddr_vm)`.
pub const SOCKADDR_LEN: usize = 16;

/// Whether the kernel has vsock, with the emulator behind it
/// (`GEX_EMULATOR_HOST=1`).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("GEX_EMULATOR_HOST").is_ok_and(|v| v == "1"))
}

fn say_once(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] vsock: {what} is not implemented");
        said.push(what.to_string());
    }
}

/// A refusal of something vsock does on Linux and this kernel does not.
pub fn not_here(what: &str, e: Errno) -> Errno {
    say_once(what);
    e
}

/// `sockaddr_vm` as the kernel writes it.
pub fn sockaddr(cid: u32, port: u32) -> [u8; SOCKADDR_LEN] {
    let mut a = [0u8; SOCKADDR_LEN];
    a[..2].copy_from_slice(&(AF_VSOCK as u16).to_le_bytes());
    a[4..8].copy_from_slice(&port.to_le_bytes());
    a[8..12].copy_from_slice(&cid.to_le_bytes());
    a
}

/// The next ephemeral port (`__vsock_bind_connectible`: one counter, from
/// a random start above the reserved ports).
fn ephemeral_port() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    if NEXT.load(Ordering::Relaxed) == 0 {
        let mut b = [0u8; 4];
        crate::vfs::devfs::fill_random(&mut b);
        let start = LAST_RESERVED_PORT + 1 + u32::from_le_bytes(b) % (u32::MAX - LAST_RESERVED_PORT - 1);
        let _ = NEXT.compare_exchange(0, start, Ordering::Relaxed, Ordering::Relaxed);
    }
    loop {
        let port = NEXT.fetch_add(1, Ordering::Relaxed);
        if port != VMADDR_PORT_ANY && port > LAST_RESERVED_PORT {
            return port;
        }
        let _ = NEXT.compare_exchange(port.wrapping_add(1), LAST_RESERVED_PORT + 1, Ordering::Relaxed, Ordering::Relaxed);
    }
}

#[derive(Debug)]
enum State {
    Unconnected,
    Connected { peer: (u32, u32), host: Connection },
    /// Shut down, and so closed by the host.
    Shut { peer: (u32, u32) },
}

#[derive(Debug)]
struct Inner {
    state: State,
    port: Option<u32>,
}

/// One vsock stream socket.
#[derive(Debug)]
pub struct Socket {
    inner: Mutex<Inner>,
    queue: crate::wait::Queue,
}

impl Socket {
    pub fn new() -> Arc<Socket> {
        Arc::new(Socket { inner: Mutex::new(Inner { state: State::Unconnected, port: None }), queue: crate::wait::Queue::new() })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `connect` to the address in `addr` (as many bytes as the caller gave).
    pub fn connect(&self, addr: &[u8]) -> Result<(), Errno> {
        let mut inner = self.lock();
        match inner.state {
            State::Connected { .. } => return Err(Errno::EISCONN),
            State::Shut { .. } => return Err(Errno::EINVAL),
            State::Unconnected => {}
        }
        if addr.len() < SOCKADDR_LEN || u16::from_le_bytes([addr[0], addr[1]]) as u64 != AF_VSOCK || addr[12] & !VMADDR_FLAG_TO_HOST != 0 {
            return Err(Errno::EINVAL);
        }
        let port = u32::from_le_bytes(addr[4..8].try_into().unwrap());
        let cid = u32::from_le_bytes(addr[8..12].try_into().unwrap());
        if cid == VMADDR_CID_LOCAL || cid == GUEST_CID {
            return Err(not_here("a connection within the guest (CID 1 or 3)", Errno::ENODEV));
        }
        if inner.port.is_none() {
            inner.port = Some(ephemeral_port());
        }
        if port != DATA_PORT {
            return Err(Errno::ECONNRESET);
        }
        inner.state = State::Connected { peer: (cid, port), host: Connection::new() };
        Ok(())
    }

    /// `getsockname`'s `sockaddr_vm`.
    pub fn name(&self) -> [u8; SOCKADDR_LEN] {
        sockaddr(VMADDR_CID_ANY, self.lock().port.unwrap_or(VMADDR_PORT_ANY))
    }

    /// `getpeername`'s, or `ENOTCONN`.
    pub fn peer_name(&self) -> Result<[u8; SOCKADDR_LEN], Errno> {
        match self.lock().state {
            State::Connected { peer, .. } | State::Shut { peer } => Ok(sockaddr(peer.0, peer.1)),
            State::Unconnected => Err(Errno::ENOTCONN),
        }
    }

    /// `shutdown(how)`.
    pub fn shutdown(&self, how: u64) -> SysResult {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let mut inner = self.lock();
        match inner.state {
            State::Unconnected => return Err(Errno::ENOTCONN),
            State::Connected { peer, .. } => inner.state = State::Shut { peer },
            State::Shut { .. } => {}
        }
        drop(inner);
        self.queue.notify();
        Ok(0)
    }

    /// A read, `peek` leaving what it reads.
    pub fn recv(&self, buf: &mut [u8], peek: bool) -> SysResult {
        let mut inner = self.lock();
        match &mut inner.state {
            State::Unconnected => Err(Errno::ENOTCONN),
            State::Shut { .. } => Ok(0),
            State::Connected { .. } if buf.is_empty() => Ok(0),
            State::Connected { host, .. } => {
                if host.pending() == 0 {
                    return Err(Errno::EAGAIN);
                }
                Ok(if peek { host.peek(buf) } else { host.recv(buf) } as u64)
            }
        }
    }

    /// Whether the socket is connected now (a destination given to a send
    /// is `EISCONN` then, `EOPNOTSUPP` otherwise).
    pub fn connected(&self) -> bool {
        matches!(self.lock().state, State::Connected { .. })
    }
}

impl FileHandle for Socket {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        self.recv(buf, false)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        let mut inner = self.lock();
        let answered = match &mut inner.state {
            State::Shut { .. } => return Err(Errno::EPIPE),
            State::Unconnected => return Err(Errno::ENOTCONN),
            State::Connected { host, .. } => host.send(buf),
        };
        drop(inner);
        if answered {
            self.queue.notify();
        }
        Ok(buf.len() as u64)
    }

    fn is_stream(&self) -> bool {
        true
    }

    /// Whether a read returns now: with something to read, once shut, or
    /// never connected (its `ENOTCONN`).
    fn poll_readable(&self) -> bool {
        match &self.lock().state {
            State::Connected { host, .. } => host.pending() > 0,
            _ => true,
        }
    }

    fn poll_in(&self) -> bool {
        match &self.lock().state {
            State::Connected { host, .. } => host.pending() > 0,
            State::Shut { .. } => true,
            State::Unconnected => false,
        }
    }

    fn poll_out(&self) -> bool {
        !matches!(self.lock().state, State::Shut { .. })
    }

    fn poll_hup(&self) -> bool {
        matches!(self.lock().state, State::Shut { .. })
    }

    fn available(&self) -> Option<u64> {
        match &self.lock().state {
            State::Connected { host, .. } => Some(host.pending() as u64),
            _ => Some(0),
        }
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(self.queue.wakes())
    }

    fn as_vsock(self: Arc<Self>) -> Option<Arc<Socket>> {
        Some(self)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Socket, size: 0, mode: 0o777, ino: 1, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(cid: u32, port: u32) -> Vec<u8> {
        sockaddr(cid, port).to_vec()
    }

    #[test]
    fn the_emulators_pipe_port_connects_and_others_are_reset() {
        let s = Socket::new();
        assert_eq!(&s.name()[4..12], &[0xff; 8]);
        assert_eq!(s.peer_name(), Err(Errno::ENOTCONN));
        let mut buf = [0u8; 8];
        assert_eq!(s.read_at(0, &mut buf), Err(Errno::ENOTCONN));
        assert_eq!(s.write_at(0, b"x"), Err(Errno::ENOTCONN));
        assert!(s.poll_out() && !s.poll_in());
        assert_eq!(s.connect(&addr(2, 5001)), Err(Errno::ECONNRESET));
        // The port it bound is kept.
        let port = u32::from_le_bytes(s.name()[4..8].try_into().unwrap());
        assert!(port > 1023 && port != u32::MAX);
        assert_eq!(s.connect(&addr(2, 5000)[..15]), Err(Errno::EINVAL));
        let mut bad = addr(2, 5000);
        bad[0] = 1;
        assert_eq!(s.connect(&bad), Err(Errno::EINVAL));
        let mut flagged = addr(2, 5000);
        flagged[12] = 2;
        assert_eq!(s.connect(&flagged), Err(Errno::EINVAL));
        assert_eq!(s.connect(&addr(2, 5000)), Ok(()));
        assert_eq!(u32::from_le_bytes(s.name()[4..8].try_into().unwrap()), port);
        assert_eq!(s.peer_name().unwrap(), sockaddr(2, 5000));
        assert_eq!(s.connect(&addr(2, 5000)), Err(Errno::EISCONN));

        // The sensors HAL's start, through the socket.
        assert_eq!(s.write_at(0, b"pipe:qemud:sensors\0"), Ok(19));
        assert!(!s.poll_readable());
        assert_eq!(s.read_at(0, &mut buf), Err(Errno::EAGAIN));
        assert_eq!(s.write_at(0, b"000clist-sensors"), Ok(16));
        assert!(s.poll_in());
        assert_eq!(s.recv(&mut buf[..2], true), Ok(2));
        assert_eq!(s.read_at(0, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"00010");

        assert_eq!(s.shutdown(3), Err(Errno::EINVAL));
        assert_eq!(s.shutdown(1), Ok(0));
        assert!(s.poll_hup() && s.poll_in() && !s.poll_out());
        assert_eq!(s.read_at(0, &mut buf), Ok(0));
        assert_eq!(s.write_at(0, b"x"), Err(Errno::EPIPE));
        assert_eq!(s.connect(&addr(2, 5000)), Err(Errno::EINVAL));
        assert_eq!(Socket::new().shutdown(0), Err(Errno::ENOTCONN));
    }

    #[test]
    fn ephemeral_ports_count_up_above_the_reserved_ones() {
        let a = ephemeral_port();
        let b = ephemeral_port();
        assert!(a > LAST_RESERVED_PORT && b > LAST_RESERVED_PORT && a != b);
    }
}
