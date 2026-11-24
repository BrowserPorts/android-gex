//! The goldfish pipe (`/dev/goldfish_pipe_dprctd`), as the emulator image's
//! kernel module has it (`common-modules/virtual-device`'s
//! `goldfish_pipe.c`) and the emulator answers it (`AndroidPipe.cpp`'s
//! connector), there when the kernel stands in for the emulator
//! (`GEX_EMULATOR_HOST=1`).
//!
//! The image's pipe library sends its graphics pipes (`opengles`,
//! `GLProcessPipe`, `refcount`) here; every other pipe goes over vsock
//! ([`crate::vsock`]). Each open of the misc device (a dynamic minor, the
//! first: 256) is one pipe:
//!
//! - It starts as the emulator's connector, which takes bytes up to and
//!   including a NUL, 128 at most, and gives the write the count it took
//!   (`ConnectorPipe::onGuestSend`). With the NUL it names a service:
//!   `pipe:<name>[:<args>]`. A string that does not begin `pipe:`, or a
//!   name with no service, fails the write with `EINVAL`, and so does every
//!   later write that ends a string (the name is still the first one); 128
//!   bytes with no NUL is `EIO`. A read of a connector is `EIO`.
//! - What the guest wrote past the NUL goes to the service, as the driver's
//!   loop sends the rest of a write on.
//! - The services: the host's graphics ([`Services`], which the native host
//!   gives, with its OpenGL ES), and the emulator's qemud services and
//!   `QemuMiscPipe` ([`crate::emuhost`]), which the image reaches over vsock
//!   but which the emulator answers on either.
//! - A read with nothing to read waits, or is `EAGAIN` for a non-blocking
//!   descriptor (`PIPE_ERROR_AGAIN`); a service's other errors are the
//!   driver's (`goldfish_pipe_error_convert`); a read or write that moved
//!   bytes before an error returns the count. An empty read or write is 0.
//! - `poll` says what the service says: `POLLIN`, `POLLOUT`, `POLLHUP`.
//! - The last close of a pipe closes its service.

use crate::emuhost::Connection;
use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, Metadata};
use std::sync::{Arc, Mutex, OnceLock};

/// Its misc minor: the first dynamic one (`misc_register` with
/// `MISC_DYNAMIC_MINOR`), no other dynamic misc device being here.
pub const MISC_MINOR: u32 = 256;
/// Its name (`DEVICE_NAME`).
pub const NAME: &str = "goldfish_pipe_dprctd";

/// The most the connector takes (`ConnectorPipe::kBufferSize`).
const CONNECT_MAX: usize = 128;

/// One pipe's service, at the host.
pub trait Service: Send {
    /// Bytes from the guest: how many it took, or `EIO` (the service has
    /// ended), or `EAGAIN` (none taken yet: the writer waits).
    fn send(&mut self, buf: &[u8]) -> Result<usize, Errno>;
    /// Bytes for the guest: how many, 0 for end of file, `EAGAIN` for none
    /// yet (the reader waits), or `EIO`.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Errno>;
    /// `PIPE_POLL_IN`: there is something to read.
    fn readable(&self) -> bool;
    /// Whether a read would wait (`PIPE_ERROR_AGAIN`), rather than answer
    /// or fail at once.
    fn recv_waits(&self) -> bool {
        !self.readable() && !self.hung_up()
    }
    /// `PIPE_POLL_OUT`.
    fn writable(&self) -> bool {
        true
    }
    /// `PIPE_POLL_HUP`.
    fn hung_up(&self) -> bool {
        false
    }
}

/// The services the host gives by name (the emulator's
/// `AndroidPipe::Service` registry).
pub trait Services: Send + Sync {
    /// A new pipe of the service `name`, with `args` (what followed the
    /// name's `:`, if anything); `None` if the host has no such service.
    fn open(&self, name: &str, args: Option<&str>) -> Option<Box<dyn Service>>;
}

static SERVICES: OnceLock<Box<dyn Services>> = OnceLock::new();

/// The host's services, given once.
pub fn set_services(s: Box<dyn Services>) -> bool {
    SERVICES.set(s).is_ok()
}

/// Whether the kernel has the pipe.
pub fn present() -> bool {
    crate::vsock::enabled()
}

enum State {
    /// The connection string so far.
    Connecting(Vec<u8>),
    Host(Box<dyn Service>),
    Emulator(Connection),
}

pub struct Pipe {
    state: Mutex<State>,
    queue: crate::wait::Queue,
    node: crate::vfs::devices::NodeMeta,
}

/// Open the device: a new pipe, a connector.
pub fn open(node: crate::vfs::devices::NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    if !present() {
        return Err(Errno::ENXIO);
    }
    Ok(Arc::new(Pipe { state: Mutex::new(State::Connecting(Vec::new())), queue: crate::wait::Queue::new(), node }))
}

fn say_once(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] goldfish pipe: {what}");
        said.push(what.to_string());
    }
}

/// The service a whole connection string (up to its NUL) names.
fn connect(name: &[u8]) -> Result<State, Errno> {
    let Some(rest) = name.strip_prefix(b"pipe:") else {
        return Err(Errno::EINVAL);
    };
    let text = String::from_utf8_lossy(rest).into_owned();
    let (pipe, args) = match text.split_once(':') {
        Some((p, a)) => (p.to_string(), Some(a.to_string())),
        None => (text.clone(), None),
    };
    if pipe == "qemud" || pipe == "QemuMiscPipe" {
        let mut c = Connection::new();
        let mut whole = name.to_vec();
        whole.push(0);
        c.send(&whole);
        if c.refused() {
            return Err(Errno::EINVAL);
        }
        return Ok(State::Emulator(c));
    }
    match SERVICES.get().and_then(|s| s.open(&pipe, args.as_deref())) {
        Some(s) => Ok(State::Host(s)),
        None => {
            say_once(&format!("no service for '{text}'"));
            Err(Errno::EINVAL)
        }
    }
}

impl std::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &*self.lock() {
            State::Connecting(_) => "connecting",
            State::Host(_) => "host service",
            State::Emulator(_) => "emulator service",
        };
        f.debug_struct("Pipe").field("state", &state).finish()
    }
}

impl Pipe {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl FileHandle for Pipe {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut s = self.lock();
        let r = match &mut *s {
            State::Connecting(_) => Err(Errno::EIO),
            State::Host(svc) => svc.recv(buf),
            State::Emulator(c) => match c.recv(buf) {
                0 => Err(Errno::EAGAIN),
                n => Ok(n),
            },
        };
        drop(s);
        self.queue.notify();
        r.map(|n| n as u64)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut s = self.lock();
        let mut done = 0;
        let mut err = None;
        while done < buf.len() {
            let rest = &buf[done..];
            let step = match &mut *s {
                State::Connecting(name) => {
                    // What fits, up to and with a NUL.
                    let room = CONNECT_MAX.saturating_sub(name.len());
                    let window = &rest[..rest.len().min(room)];
                    match window.iter().position(|&b| b == 0) {
                        Some(i) => {
                            name.extend_from_slice(&window[..=i]);
                            // The name is the buffer's first string.
                            let first: Vec<u8> = name.iter().copied().take_while(|&b| b != 0).collect();
                            connect(&first).map(|next| {
                                *s = next;
                                i + 1
                            })
                        }
                        // Full and no NUL: the connector gives up.
                        None if window.len() == room => Err(Errno::EIO),
                        None => {
                            name.extend_from_slice(window);
                            Ok(window.len())
                        }
                    }
                }
                State::Host(svc) => svc.send(rest),
                State::Emulator(c) => {
                    c.send(rest);
                    Ok(rest.len())
                }
            };
            match step {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        drop(s);
        self.queue.notify();
        match (done, err) {
            (0, Some(e)) => Err(e),
            (n, _) => Ok(n as u64),
        }
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok((self.node)())
    }

    fn seek(&self, _offset: i64, _whence: u32) -> Option<SysResult> {
        Some(Err(Errno::ESPIPE))
    }

    fn poll_readable(&self) -> bool {
        match &*self.lock() {
            // A read fails at once.
            State::Connecting(_) => true,
            State::Host(svc) => !svc.recv_waits(),
            State::Emulator(c) => c.pending() > 0,
        }
    }

    fn poll_in(&self) -> bool {
        match &*self.lock() {
            State::Connecting(_) => false,
            State::Host(svc) => svc.readable(),
            State::Emulator(c) => c.pending() > 0,
        }
    }

    fn poll_writable(&self) -> bool {
        match &*self.lock() {
            State::Host(svc) => svc.writable() || svc.hung_up(),
            _ => true,
        }
    }

    fn poll_out(&self) -> bool {
        match &*self.lock() {
            State::Host(svc) => svc.writable(),
            _ => true,
        }
    }

    fn poll_hup(&self) -> bool {
        matches!(&*self.lock(), State::Host(svc) if svc.hung_up())
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    /// The host renderer reads and writes graphics buffers by address
    /// while it runs what a write hands it.
    fn hands_over_on_write(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A service that echoes, as a test's host would give one.
    struct Echo(Vec<u8>);

    impl Service for Echo {
        fn send(&mut self, buf: &[u8]) -> Result<usize, Errno> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
            if self.0.is_empty() {
                return Err(Errno::EAGAIN);
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
        fn readable(&self) -> bool {
            !self.0.is_empty()
        }
    }

    struct Host;
    static OPENED: AtomicUsize = AtomicUsize::new(0);

    impl Services for Host {
        fn open(&self, name: &str, args: Option<&str>) -> Option<Box<dyn Service>> {
            (name == "echo" && args.is_none()).then(|| {
                OPENED.fetch_add(1, Ordering::SeqCst);
                Box::new(Echo(Vec::new())) as Box<dyn Service>
            })
        }
    }

    fn pipe() -> Pipe {
        let _ = set_services(Box::new(Host));
        Pipe { state: Mutex::new(State::Connecting(Vec::new())), queue: crate::wait::Queue::new(), node: Arc::new(|| Metadata { file_type: crate::vfs::FileType::CharDevice, size: 0, mode: 0o666, ino: 1, mtime: 0, nlink: 1, rdev: 10 << 8 | MISC_MINOR as u64, dev: 0, times: Default::default(), owner: None }) }
    }

    /// The connector's rules, then a service's bytes both ways.
    #[test]
    fn a_pipe_connects_as_the_emulators_connector_does() {
        let p = pipe();
        assert_eq!(p.read_at(0, &mut [0; 4]), Err(Errno::EIO));
        assert!(!p.poll_in() && p.poll_out());
        // A name in two writes, the second with bytes for the service.
        assert_eq!(p.write_at(0, b"pipe:ec"), Ok(7));
        assert_eq!(p.write_at(0, b"ho\0hello"), Ok(8));
        assert!(p.poll_in());
        let mut b = [0u8; 16];
        assert_eq!(p.read_at(0, &mut b), Ok(5));
        assert_eq!(&b[..5], b"hello");
        assert_eq!(p.read_at(0, &mut b), Err(Errno::EAGAIN));
        assert!(!p.poll_readable());
        assert_eq!(p.read_at(0, &mut []), Ok(0));
        // Refusals: not `pipe:`, a service not here, and the name stays.
        let p = pipe();
        assert_eq!(p.write_at(0, b"echo\0"), Err(Errno::EINVAL));
        assert_eq!(p.write_at(0, b"pipe:echo\0"), Err(Errno::EINVAL));
        let p = pipe();
        assert_eq!(p.write_at(0, b"pipe:nothing\0"), Err(Errno::EINVAL));
        // 128 bytes and no NUL.
        let p = pipe();
        assert_eq!(p.write_at(0, &[b'x'; 100]), Ok(100));
        assert_eq!(p.write_at(0, &[b'x'; 28]), Err(Errno::EIO));
        // A qemud service through the same connector.
        let p = pipe();
        assert_eq!(p.write_at(0, b"pipe:qemud:boot-properties\0"), Ok(27));
        assert_eq!(p.write_at(0, b"0004list"), Ok(8));
        assert_eq!(p.read_at(0, &mut b), Ok(5));
        assert_eq!(&b[..5], b"0001\0");
    }
}
