//! The emulator's graphics pipes on the host's OpenGL ES, for the goldfish
//! pipe (`gex_kernel::goldfishpipe`): `opengles` (a render thread of
//! `gex-gfxstream`'s renderer), `GLProcessPipe` (a guest process's id) and
//! `refcount` (a color buffer's reference), as the emulator's
//! `OpenglEsPipe.cpp`, `GLProcessPipe.cpp` and `RefcountPipe.cpp` answer
//! them.
//!
//! The renderer is made at the first graphics pipe, so a guest that never
//! draws costs no EGL. Its display is `GEX_GFXSTREAM_DISPLAY`
//! (`<width>x<height>[@<dpi>]`), else `GEX_VIRTIO_GPU`'s size at 480 dpi,
//! else 1080x1920 at 480. `GEX_GFXSTREAM_FRAME=<file>` writes the frame the
//! guest last posted there as a PPM image, at most once a second. DMA
//! pointers (the mapper's pixels) are the goldfish address space's memory,
//! and the goldfish sync device's waits are the renderer's fence syncs.

use gex_gfxstream::host::compose::Frame;
use gex_gfxstream::host::{DisplaySize, Dma, Features, Renderer, Thread};
use gex_kernel::errno::Errno;
use gex_kernel::goldfishpipe::{Service, Services};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Give the kernel the graphics services, when it has the goldfish pipe.
pub fn install() {
    if gex_kernel::goldfishpipe::present() {
        gex_kernel::goldfishpipe::set_services(Box::new(Host));
        gex_kernel::goldfishsync::set_host(Box::new(SyncHost));
    }
}

/// The sync device's waits: the renderer's fence syncs.
struct SyncHost;

impl gex_kernel::goldfishsync::Host for SyncHost {
    fn wait(&self, glsync: u64, _syncthread: u64) {
        if let Some(r) = renderer() {
            Renderer::wait_fence(&r, glsync);
        }
    }
}

fn size() -> DisplaySize {
    let parse = |s: &str| -> Option<DisplaySize> {
        let (dims, dpi) = match s.split_once('@') {
            Some((d, p)) => (d, p.parse().ok()?),
            None => (s, 480),
        };
        let (w, h) = dims.split_once('x')?;
        Some(DisplaySize { width: w.parse().ok()?, height: h.parse().ok()?, dpi_x: dpi, dpi_y: dpi })
    };
    std::env::var("GEX_GFXSTREAM_DISPLAY")
        .ok()
        .and_then(|s| parse(&s))
        .or_else(|| std::env::var("GEX_VIRTIO_GPU").ok().and_then(|s| parse(&s)))
        .unwrap_or(DisplaySize { width: 1080, height: 1920, dpi_x: 480, dpi_y: 480 })
}

/// The renderer, made once; a failure is said once and every graphics pipe
/// is then refused.
fn renderer() -> Option<Arc<Mutex<Renderer>>> {
    static R: OnceLock<Option<Arc<Mutex<Renderer>>>> = OnceLock::new();
    R.get_or_init(|| match Renderer::new(Features::default(), size()) {
        Ok(mut r) => {
            r.set_dma(Box::new(AddressSpace));
            if let Some(path) = std::env::var_os("GEX_GFXSTREAM_FRAME") {
                let path = std::path::PathBuf::from(path);
                let mut last: Option<std::time::Instant> = None;
                r.set_sink(Box::new(move |f: &Frame| {
                    if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1)) {
                        return;
                    }
                    last = Some(std::time::Instant::now());
                    let mut out = format!("P6\n{} {}\n255\n", f.width, f.height).into_bytes();
                    for px in f.rgba.chunks_exact(4) {
                        out.extend_from_slice(&px[..3]);
                    }
                    if let Err(e) = std::fs::write(&path, out) {
                        eprintln!("[gex] gfxstream: the frame could not be written to {}: {e}", path.display());
                    }
                }));
            }
            Some(Arc::new(Mutex::new(r)))
        }
        Err(e) => {
            eprintln!("[gex] gfxstream: no renderer, so no graphics pipes: {e}");
            None
        }
    })
    .clone()
}

/// DMA pointers name the goldfish address space's memory.
struct AddressSpace;

impl Dma for AddressSpace {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        gex_kernel::goldfishas::read_phys(addr, buf)
    }

    fn write(&self, addr: u64, buf: &[u8]) -> bool {
        gex_kernel::goldfishas::write_phys(addr, buf)
    }
}

struct Host;

impl Services for Host {
    fn open(&self, name: &str, _args: Option<&str>) -> Option<Box<dyn Service>> {
        let r = match name {
            "opengles" | "GLProcessPipe" | "refcount" => renderer()?,
            _ => return None,
        };
        Some(match name {
            "opengles" => Box::new(OpenGles::new(r)?),
            "GLProcessPipe" => Box::new(ProcessPipe::new(r)),
            _ => Box::new(Refcount { renderer: r, handle: 0 }),
        })
    }
}

/// `EmuglPipe`: the guest's command stream to a render thread, and its
/// answers back. The stream is decoded on a host thread of its own, as
/// gfxstream's `RenderThread` is, whichever guest thread writes: its EGL
/// context is current on that one host thread, which a context must be
/// (Mesa refuses one still current on another thread with
/// EGL_BAD_ACCESS), and its end unbinds it there.
struct OpenGles {
    to: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    from: std::sync::mpsc::Receiver<(Vec<u8>, Option<String>)>,
    out: VecDeque<u8>,
    broken: Option<String>,
}

impl OpenGles {
    fn new(renderer: Arc<Mutex<Renderer>>) -> Option<OpenGles> {
        let (to, input) = std::sync::mpsc::channel::<Vec<u8>>();
        let (answers, from) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("gex-render".into())
            .stack_size(8 << 20)
            .spawn(move || {
                let mut thread = Thread::new(renderer);
                while let Ok(buf) = input.recv() {
                    let answer = thread.feed(&buf);
                    let broken = thread.broken.as_ref().map(|e| format!("{e:?}"));
                    if answers.send((answer, broken)).is_err() {
                        break;
                    }
                }
            });
        if let Err(e) = spawned {
            eprintln!("[gex] gfxstream: no host thread for a render thread: {e}");
            return None;
        }
        Some(OpenGles { to: Some(to), from, out: VecDeque::new(), broken: None })
    }
}

impl Service for OpenGles {
    fn send(&mut self, buf: &[u8]) -> Result<usize, Errno> {
        if self.broken.is_some() {
            return Err(Errno::EIO);
        }
        let reply = self.to.as_ref().and_then(|to| to.send(buf.to_vec()).ok()).and_then(|()| self.from.recv().ok());
        let Some((answer, broken)) = reply else {
            self.broken = Some("its host thread ended".into());
            eprintln!("[gex] gfxstream: a render thread's host thread ended; the pipe is closed");
            return Err(Errno::EIO);
        };
        self.out.extend(answer);
        if let Some(e) = broken {
            eprintln!("[gex] gfxstream: a render thread's stream is malformed ({e}); the pipe is closed");
            self.broken = Some(e);
        }
        Ok(buf.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.out.is_empty() {
            return Err(if self.broken.is_some() { Errno::EIO } else { Errno::EAGAIN });
        }
        let n = buf.len().min(self.out.len());
        for (b, o) in buf.iter_mut().zip(self.out.drain(..n)) {
            *b = o;
        }
        Ok(n)
    }

    fn readable(&self) -> bool {
        !self.out.is_empty()
    }

    fn hung_up(&self) -> bool {
        self.broken.is_some()
    }
}

impl Drop for OpenGles {
    /// Its host thread ends once the stream is closed, dropping the render
    /// thread there.
    fn drop(&mut self) {
        self.to = None;
    }
}

/// `GLProcessPipe`: a guest process's id, from 1, given once after its
/// confirmation; its end lets go of what the process made.
struct ProcessPipe {
    renderer: Arc<Mutex<Renderer>>,
    id: u64,
    has_data: bool,
}

impl ProcessPipe {
    fn new(renderer: Arc<Mutex<Renderer>>) -> ProcessPipe {
        static HEAD: AtomicU64 = AtomicU64::new(0);
        ProcessPipe { renderer, id: HEAD.fetch_add(1, Ordering::SeqCst) + 1, has_data: false }
    }
}

impl Service for ProcessPipe {
    /// The confirmation (100): the first buffer, taken whole.
    fn send(&mut self, buf: &[u8]) -> Result<usize, Errno> {
        self.has_data = true;
        Ok(buf.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.has_data || buf.len() < 8 {
            return Ok(0);
        }
        self.has_data = false;
        buf[..8].copy_from_slice(&self.id.to_le_bytes());
        Ok(8)
    }

    fn readable(&self) -> bool {
        true
    }
}

impl Drop for ProcessPipe {
    fn drop(&mut self) {
        self.renderer.lock().unwrap_or_else(|e| e.into_inner()).process_ended(self.id);
    }
}

/// `RefcountPipe`: a color buffer's handle, written as four bytes; its end
/// lets go of the reference.
struct Refcount {
    renderer: Arc<Mutex<Renderer>>,
    handle: u32,
}

impl Service for Refcount {
    fn send(&mut self, buf: &[u8]) -> Result<usize, Errno> {
        if buf.len() > 4 {
            return Ok(0);
        }
        if buf.len() == 4 {
            self.handle = u32::from_le_bytes(buf.try_into().unwrap());
        }
        Ok(buf.len())
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EIO)
    }

    fn readable(&self) -> bool {
        false
    }

    /// A read fails at once.
    fn recv_waits(&self) -> bool {
        false
    }
}

impl Drop for Refcount {
    fn drop(&mut self) {
        self.renderer.lock().unwrap_or_else(|e| e.into_inner()).release_color_buffer(self.handle);
    }
}
