//! The Android emulator's host services, for the emulator image's hardware
//! layers: what the emulator answers on the other end of a guest's pipe.
//!
//! The image's pipe library (`libqemupipe.ranchu`,
//! `hardware/google/gfxstream`'s `guest/qemupipe/qemu_pipe_guest.cpp`)
//! reaches every service but the graphics ones over virtio-vsock: a stream
//! to the host's port 5000, then the connection string. Here the kernel is
//! that host ([`crate::vsock`]), and a [`Connection`] is one such stream's
//! host end. Its behaviour is the emulator's (`platform/hardware/google/aemu`,
//! `host-common/AndroidPipe.cpp`; `platform/external/qemu`,
//! `android-qemu2-glue/emulation/virtio_vsock_device.cpp` and
//! `android/android-emu/android/hw-sensors.cpp`):
//!
//! - A new stream is a connector. It takes bytes up to a NUL, 128 at most.
//!   `pipe:<name>[:<args>]` connects it to the service of that name, and the
//!   rest of the same bytes go to the service; `pipe:qemud:<service>[:<args>]`
//!   is a qemud service. What the connector refuses (no NUL in 128 bytes, a
//!   string that is not `pipe:`, a service that is not here) is refused
//!   silently: the vsock device drops a pipe's errors, and the stream never
//!   answers. Here a service that is not here is also said once on the
//!   host's standard error.
//! - A qemud service's messages are framed both ways by a header of four
//!   hex digits giving the length (the guest library's `qemud_channel_send`;
//!   a frame of 64 KiB or more has a 32-bit big-endian length with the top
//!   bit set instead). An empty frame, or a header that is not a length, is
//!   passed over, as the emulator's qemud does.
//! - The qemud services here: **`sensors`**, as the emulator's with a
//!   virtual device that has no sensors. `list-sensors` answers the mask of
//!   sensors (0), `wake` answers `wake`; `set-delay:`, `time:` and `set:`
//!   (of a sensor not there) are taken without an answer, as is anything
//!   else. With no sensor enabled nothing is ever reported.
//!
//! The emulator's other services (`boot-properties`, `gps`, the camera,
//! `QemuMiscPipe` and the rest) are not here.

use std::collections::VecDeque;
use std::sync::Mutex;

/// The most a connector takes before its NUL (`ConnectorPipe::kBufferSize`).
const CONNECT_MAX: usize = 128;

/// A qemud service a stream is connected to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Service {
    Sensors,
}

impl Service {
    fn find(name: &[u8]) -> Option<Service> {
        match name {
            b"sensors" => Some(Service::Sensors),
            _ => None,
        }
    }

    /// The service's answer to one message from the guest, if it gives one.
    fn message(self, msg: &[u8]) -> Option<Vec<u8>> {
        match self {
            // `_hwSensorClient_receive`, with no sensor in the AVD.
            Service::Sensors => match msg {
                b"list-sensors" => Some(b"0".to_vec()),
                b"wake" => Some(b"wake".to_vec()),
                _ => None,
            },
        }
    }
}

#[derive(Debug)]
enum State {
    /// Bytes of the connection string so far.
    Connecting(Vec<u8>),
    /// The connector refused: nothing more is taken or answered.
    Refused,
    Qemud {
        service: Service,
        /// Guest bytes not yet a whole frame.
        partial: Vec<u8>,
    },
}

/// The host's end of one stream to the emulator's pipe services.
#[derive(Debug)]
pub struct Connection {
    state: State,
    /// What the host has for the guest to read.
    out: VecDeque<u8>,
}

impl Default for Connection {
    fn default() -> Self {
        Connection::new()
    }
}

impl Connection {
    pub fn new() -> Connection {
        Connection { state: State::Connecting(Vec::new()), out: VecDeque::new() }
    }

    /// Bytes from the guest. Whether the host now has more for it to read.
    pub fn send(&mut self, buf: &[u8]) -> bool {
        let before = self.out.len();
        let rest = match &mut self.state {
            State::Refused => &[][..],
            State::Connecting(name) => {
                let room = CONNECT_MAX - name.len();
                match buf.iter().take(room).position(|&b| b == 0) {
                    None if buf.len() >= room => {
                        self.state = State::Refused;
                        &[][..]
                    }
                    None => {
                        name.extend_from_slice(buf);
                        &[][..]
                    }
                    Some(nul) => {
                        name.extend_from_slice(&buf[..nul]);
                        match connect(name) {
                            Some(service) => {
                                self.state = State::Qemud { service, partial: Vec::new() };
                                &buf[nul + 1..]
                            }
                            None => {
                                say_once(&String::from_utf8_lossy(name));
                                self.state = State::Refused;
                                &[][..]
                            }
                        }
                    }
                }
            }
            State::Qemud { .. } => buf,
        };
        if let State::Qemud { service, partial } = &mut self.state {
            partial.extend_from_slice(rest);
            for msg in frames(partial) {
                if let Some(answer) = service.message(&msg) {
                    self.out.extend(frame(&answer));
                }
            }
        }
        self.out.len() > before
    }

    /// What the host has for the guest, taken into `buf`.
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.out.len());
        for (b, o) in buf.iter_mut().zip(self.out.drain(..n)) {
            *b = o;
        }
        n
    }

    /// What `recv` would take, left where it is.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.out.len());
        for (b, o) in buf.iter_mut().zip(self.out.iter()) {
            *b = *o;
        }
        n
    }

    /// How many bytes there are to read.
    pub fn pending(&self) -> usize {
        self.out.len()
    }
}

fn say_once(name: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == name) {
        eprintln!("[gex] emulator host: no service for '{name}'; the stream will not answer");
        said.push(name.to_string());
    }
}

/// A message framed as qemud frames it.
fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = if msg.len() < 0x10000 {
        format!("{:04x}", msg.len()).into_bytes()
    } else {
        ((msg.len() as u32) | 1 << 31).to_be_bytes().to_vec()
    };
    out.extend_from_slice(msg);
    out
}

/// The whole frames at the front of `partial`, taken out of it.
fn frames(partial: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut msgs = Vec::new();
    let mut at = 0;
    while partial.len() - at >= 4 {
        let header = &partial[at..at + 4];
        let len = if header[0] & 0x80 != 0 {
            Some((u32::from_be_bytes([header[0], header[1], header[2], header[3]]) & !(1 << 31)) as usize)
        } else {
            std::str::from_utf8(header).ok().filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit())).and_then(|h| usize::from_str_radix(h, 16).ok())
        };
        match len {
            // Not a length, or nothing: passed over.
            None | Some(0) => at += 4,
            Some(n) if partial.len() - at - 4 >= n => {
                msgs.push(partial[at + 4..at + 4 + n].to_vec());
                at += 4 + n;
            }
            Some(_) => break,
        }
    }
    partial.drain(..at);
    msgs
}

/// The service a connection string names: `pipe:qemud:<service>[:<args>]`.
/// `None` for anything else (`ConnectorPipe::onGuestSend`; no service but
/// qemud's is here, and no `qemud:<name>` service of its own).
fn connect(name: &[u8]) -> Option<Service> {
    let rest = name.strip_prefix(b"pipe:")?;
    let args = rest.strip_prefix(b"qemud:")?;
    let service = args.split(|&b| b == b':').next()?;
    Service::find(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(c: &mut Connection) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let n = c.recv(&mut buf);
        buf[..n].to_vec()
    }

    /// What the emulator image's sensors HAL does at its start
    /// (`MultihalSensors::MultihalSensors`): connect, ask for the list,
    /// read the mask.
    #[test]
    fn the_sensors_service_answers_that_there_are_none() {
        let mut c = Connection::new();
        assert!(!c.send(b"pipe:qemud:sensors\0"));
        assert_eq!(c.pending(), 0);
        assert!(c.send(b"000clist-sensors"));
        // Read in two parts, as `qemud_channel_recv` does: the header, then
        // the message.
        let mut header = [0u8; 4];
        assert_eq!(c.recv(&mut header), 4);
        assert_eq!(&header, b"0001");
        assert_eq!(read_all(&mut c), b"0");
        // Taken quietly: a delay, a sensor this AVD lacks, the time.
        for m in ["set-delay:200", "set:acceleration:1", "time:123456789", "nonsense"] {
            assert!(!c.send(&frame(m.as_bytes())));
        }
        assert_eq!(read_all(&mut c), b"");
        // `wake` comes back, in one write with another message, and a frame
        // split across writes is put together.
        let both = [frame(b"wake"), frame(b"list-sensors")].concat();
        assert!(!c.send(&both[..6]));
        assert!(c.send(&both[6..]));
        assert_eq!(read_all(&mut c), b"0004wake00010");
    }

    /// The connector: bytes up to the NUL in as many writes as it takes,
    /// the rest the service's; what it refuses never answers.
    #[test]
    fn a_connector_takes_a_name_and_refused_streams_stay_silent() {
        let mut c = Connection::new();
        c.send(b"pipe:qe");
        assert!(c.send(&[&b"mud:sensors:extra\0"[..], &frame(b"list-sensors")].concat()));
        assert_eq!(read_all(&mut c), b"00010");

        for name in [&b"pipe:qemud:gps\0"[..], b"pipe:opengles\0", b"pipe:qemud\0", b"pipe:sensors\0", b"qemud:sensors\0", b"pipe:QemuMiscPipe\0"] {
            let mut c = Connection::new();
            c.send(name);
            assert!(!c.send(&frame(b"list-sensors")), "{}", String::from_utf8_lossy(name));
            assert_eq!(c.pending(), 0);
        }
        // 128 bytes with no NUL: refused, and a NUL after does not help.
        let mut c = Connection::new();
        c.send(&[b'x'; 100]);
        c.send(&[b'x'; 28]);
        assert!(!c.send(&[b"\0".as_slice(), &frame(b"list-sensors")].concat()));
    }

    #[test]
    fn frames_are_four_hex_digits_or_a_long_length() {
        assert_eq!(frame(b"abc"), b"0003abc");
        let long = vec![7u8; 0x10000];
        let f = frame(&long);
        assert_eq!(&f[..4], &[0x80, 0x01, 0x00, 0x00]);
        let mut partial = f.clone();
        assert_eq!(frames(&mut partial), vec![long]);
        // An empty frame and a header that is not one are passed over.
        let mut partial = b"0000zzzz0002hi000".to_vec();
        assert_eq!(frames(&mut partial), vec![b"hi".to_vec()]);
        assert_eq!(partial, b"000");
        let mut partial = b"00FFab".to_vec();
        assert_eq!(frames(&mut partial), Vec::<Vec<u8>>::new());
        assert_eq!(partial, b"00FFab");
    }
}
