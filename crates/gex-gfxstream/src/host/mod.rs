//! The host's side of gfxstream: what the guest's EGL and OpenGL ES ask, done
//! on the host's EGL and OpenGL ES (Mesa), after gfxstream's own host
//! (`host/RenderControl.cpp`, `FrameBuffer.cpp`, `host/gl/`).
//!
//! One [`Renderer`] for the machine holds what every guest process shares:
//! the host's display, a root context of its own (where color buffers are
//! kept, composed and read), the configs, and the objects by handle. A [`Thread`] is one `pipe:opengles` stream, a
//! guest render thread: its current context and surfaces, its process.
//!
//! What the host offers the guest is said in `GL_EXTENSIONS`
//! (`rcGetGLString`), and the guest takes its paths by it:
//! [`Features`] says which.

pub mod compose;
pub mod config;
pub mod displays;
pub mod egl;
pub mod gl;
mod gles;
pub mod yuv;
pub mod objects;
pub mod translator;

use crate::{Arg, Call};
use egl::*;
use std::ffi::c_char;
use objects::Owner;
use std::sync::{Arc, Mutex};

/// gfxstream's renderer version (`rendererVersion`).
const RENDERER_VERSION: i32 = 1;

/// The EGL the guest is shown is gfxstream's translator's
/// (`glestranslator/egl/egl_imp.cpp`), not the host's: version 1.4, and
/// its own short list of extensions, whatever the host's EGL has. (Mesa's
/// list offers `EGL_KHR_no_config_context` and `EGL_KHR_surfaceless_context`,
/// which the guest's EGL takes on trust and cannot serve: SurfaceFlinger
/// then makes a context with no config and no surface and its first
/// `eglMakeCurrent` fails.)
const TRANSLATOR_EGL_VERSION: (EGLint, EGLint) = (1, 4);
const TRANSLATOR_EGL_EXTENSIONS: &str = "EGL_KHR_image EGL_KHR_image_base EGL_KHR_gl_texture_2D_image EGL_ANDROID_recordable ";

const GL_VERSION: u32 = 0x1F02;
const GL_EXTENSIONS: u32 = 0x1F03;

/// What the host offers. The defaults are what this host does.
#[derive(Clone, Debug)]
pub struct Features {
    /// `GlesDynamicVersion`: OpenGL ES past 2 when the host has it.
    pub gles_dynamic_version: bool,
    /// `HostComposition`: the guest's composer asks the host to compose
    /// (`rcCompose`) rather than drawing the frame itself.
    pub host_composition: bool,
}

impl Default for Features {
    fn default() -> Features {
        Features { gles_dynamic_version: true, host_composition: true }
    }
}

/// The memory DMA pointers name (the goldfish address space's), by guest
/// physical address: what the emulator's `g_emugl_dma_get_host_addr` gives
/// its decoders.
pub trait Dma: Send {
    /// `buf.len()` bytes at `addr` into `buf`; false if they are not all
    /// there.
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool;
    /// `buf` to `addr`; false if the memory is not all there.
    fn write(&self, addr: u64, buf: &[u8]) -> bool;
}

/// The OpenGL ES version the host's contexts reach (`GLESDispatchMaxVersion`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaxVersion {
    Es2,
    Es30,
    Es31,
}

/// The display's size and density (`FrameBuffer`'s display config 0).
#[derive(Clone, Copy, Debug)]
pub struct DisplaySize {
    pub width: i32,
    pub height: i32,
    pub dpi_x: i32,
    pub dpi_y: i32,
}

pub struct Renderer {
    display: EGLDisplay,
    egl_version: (EGLint, EGLint),
    pub configs: config::Configs,
    features: Features,
    max_version: MaxVersion,
    /// The host's extensions, read on the root context.
    host_extensions: String,
    /// The renderer's own context and its surface: where color buffers are
    /// made, composed and read (`FrameBuffer`'s own context).
    root: EGLContext,
    root_surface: EGLSurface,
    size: DisplaySize,
    objects: objects::Objects,
    /// Render threads are numbered from 1.
    threads: u64,
    drawer: Option<compose::Drawer>,
    /// The color buffer the display shows, and how many posts there were.
    shown: u32,
    posts: u64,
    /// The displays the guest's composer made ([`displays::Displays`]).
    displays: displays::Displays,
    sink: Option<compose::Sink>,
    /// The guest's syncs (`glFenceSyncAEMU`) by handle, from 1.
    syncs: std::collections::HashMap<u64, usize>,
    next_sync: u64,
    dma: Option<Box<dyn Dma>>,
    /// Fence syncs (`EmulatedEglFenceSync`) by handle, from 1.
    fences: std::collections::HashMap<u64, Fence>,
    next_fence: u64,
}

/// A fence sync and its references: one, and one more to be let go when it
/// signals (`destroyWhenSignaled`).
struct Fence {
    egl: EGLSync,
    refs: u32,
    destroy_when_signaled: bool,
}

/// `SyncThread::get()`'s address, which the guest passes back to the sync
/// device: any number but 0.
pub const SYNC_THREAD: u64 = 1;

// The EGL handles are the driver's; the renderer's lock is what orders
// their use.
unsafe impl Send for Renderer {}

fn gl_string(name: u32) -> String {
    type GetString = unsafe extern "C" fn(u32) -> *const u8;
    let p = proc_address("glGetString");
    if p.is_null() {
        return String::new();
    }
    let f: GetString = unsafe { std::mem::transmute(p) };
    unsafe { string(f(name) as *const c_char) }.unwrap_or_default()
}

/// The host's `glGetIntegerv` of `name` on the current context (0 when it
/// has none).
fn gl_integer(name: u32) -> i32 {
    type GetIntegerv = unsafe extern "C" fn(u32, *mut i32);
    let p = proc_address("glGetIntegerv");
    if p.is_null() {
        return 0;
    }
    let f: GetIntegerv = unsafe { std::mem::transmute(p) };
    let mut v = 0;
    unsafe { f(name, &mut v) };
    v
}

/// The version an OpenGL ES version string names (`OpenGL ES 3.1 Mesa ...`).
fn max_version_of(version: &str) -> MaxVersion {
    let v = version.trim_start_matches("OpenGL ES ").split(|c: char| c == ' ' || c == '-').next().unwrap_or("");
    let mut it = v.split('.').map(|x| x.parse::<u32>().unwrap_or(0));
    match (it.next().unwrap_or(0), it.next().unwrap_or(0)) {
        (3, 0) => MaxVersion::Es30,
        (3, _) => MaxVersion::Es31,
        (m, _) if m > 3 => MaxVersion::Es31,
        _ => MaxVersion::Es2,
    }
}

/// `replaceESVersionString`: the version after "OpenGL ES " replaced.
fn replace_es_version(s: &str, version: &str) -> String {
    let Some(rest) = s.strip_prefix("OpenGL ES ") else { return s.to_string() };
    let after = rest.find(' ').map(|i| &rest[i..]).unwrap_or("");
    format!("OpenGL ES {version}{after}")
}

impl Renderer {
    /// The host's display and root context.
    pub fn new(features: Features, size: DisplaySize) -> Result<Renderer, String> {
        let (display, _, _) = egl::display()?;
        // A root context at the highest version the host gives, on a small
        // pbuffer of the first config that has one.
        let attrs = [EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE];
        let mut cfg = std::ptr::null_mut();
        let mut n = 0;
        if unsafe { eglChooseConfig(display, attrs.as_ptr(), &mut cfg, 1, &mut n) } != EGL_TRUE || n < 1 {
            return Err("no host config for the root context".into());
        }
        let pb = [EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE];
        let root_surface = unsafe { eglCreatePbufferSurface(display, cfg, pb.as_ptr()) };
        let mut root = std::ptr::null_mut();
        for v in [3, 2] {
            let ca = [EGL_CONTEXT_CLIENT_VERSION, v, EGL_NONE];
            root = unsafe { eglCreateContext(display, cfg, std::ptr::null_mut(), ca.as_ptr()) };
            if !root.is_null() {
                break;
            }
        }
        if root.is_null() || root_surface.is_null() {
            return Err(format!("no root context: {:#x}", unsafe { eglGetError() }));
        }
        unsafe { eglMakeCurrent(display, root_surface, root_surface, root) };
        let host_version = gl_string(GL_VERSION);
        let host_extensions = gl_string(GL_EXTENSIONS);
        unsafe { eglMakeCurrent(display, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        let max_version = if features.gles_dynamic_version { max_version_of(&host_version) } else { MaxVersion::Es2 };
        let configs = config::Configs::new(display, max_version > MaxVersion::Es2);
        Ok(Renderer { display, egl_version: TRANSLATOR_EGL_VERSION, configs, features, max_version, host_extensions, root, root_surface, size, objects: Default::default(), threads: 0, drawer: None, shown: 0, posts: 0, displays: Default::default(), sink: None, syncs: Default::default(), next_sync: 0, dma: None, fences: Default::default(), next_fence: 0 })
    }

    /// `rcGetGLString`'s answer for `name`: the translator's string for the
    /// thread's current context (none: empty; [`translator::gl_string`]),
    /// then for `GL_EXTENSIONS` what the host offers, and for `GL_VERSION`
    /// the version the guest may use.
    fn gl_string(&self, name: u32, current: Option<String>) -> String {
        let mut s = current.unwrap_or_default();
        if name == GL_EXTENSIONS {
            let mut add = |x: &str| {
                s.push_str(x);
                s.push(' ');
            };
            if self.features.host_composition {
                add("ANDROID_EMU_host_composition_v1");
                add("ANDROID_EMU_host_composition_v2");
            }
            add("ANDROID_EMU_sync_buffer_data");
            // The mapper reads YUV buffers back only through the YUV cache.
            add("ANDROID_EMU_YUV_Cache");
            let guest_version = if self.features.gles_dynamic_version {
                add("GL_OES_EGL_image_external_essl3");
                self.max_version
            } else {
                MaxVersion::Es2
            };
            if self.max_version > MaxVersion::Es2 {
                add("GL_OES_vertex_array_object");
            }
            if self.host_extensions.contains("GL_KHR_texture_compression_astc_ldr") {
                add("GL_KHR_texture_compression_astc_ldr");
            }
            add("ANDROID_EMU_host_side_tracing");
            add(match guest_version {
                MaxVersion::Es2 => "ANDROID_EMU_gles_max_version_2",
                MaxVersion::Es30 => "ANDROID_EMU_gles_max_version_3_0",
                MaxVersion::Es31 => "ANDROID_EMU_gles_max_version_3_1",
            });
        }
        if name == GL_VERSION {
            let v = match (self.features.gles_dynamic_version, self.max_version) {
                (false, _) | (true, MaxVersion::Es2) => "2.0",
                (true, MaxVersion::Es30) => "3.0",
                (true, MaxVersion::Es31) => "3.1",
            };
            s = replace_es_version(&s, v);
        }
        s
    }
}

/// One guest render thread: a `pipe:opengles` stream.
pub struct Thread {
    renderer: Arc<Mutex<Renderer>>,
    id: u64,
    /// What `rcMakeCurrent` made current (`RenderThreadInfoGl`'s
    /// `currContext`, `currDrawSurf`, `currReadSurf`).
    context: u32,
    draw: u32,
    read: u32,
    /// The stream's first word (`clientFlags`), not yet all read.
    flags_left: usize,
    /// Bytes of a call not yet whole.
    pending: Vec<u8>,
    /// The guest process, once `rcSetPuid` says it.
    pub puid: u64,
    /// A malformed stream stops being read.
    pub broken: Option<crate::Malformed>,
}

/// A string answer as renderControl gives one: its length with the NUL, or
/// minus that when `size` is short.
fn string_answer(s: &str, size: i32) -> (i32, Vec<u8>) {
    let len = s.len() as i32 + 1;
    if len > size {
        return (-len, Vec::new());
    }
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    (len, b)
}

fn value(a: &Arg<'_>) -> u64 {
    match a {
        Arg::Value(v) => *v,
        _ => 0,
    }
}

fn words(b: &[u8]) -> Vec<i32> {
    b.chunks_exact(4).map(|w| i32::from_le_bytes(w.try_into().unwrap())).collect()
}

impl Thread {
    pub fn new(renderer: Arc<Mutex<Renderer>>) -> Thread {
        let id = {
            let mut r = renderer.lock().unwrap_or_else(|e| e.into_inner());
            r.threads += 1;
            r.threads
        };
        Thread { renderer, id, context: 0, draw: 0, read: 0, flags_left: 4, pending: Vec::new(), puid: 0, broken: None }
    }

    /// Whose what this thread makes is.
    fn owner(&self) -> Owner {
        if self.puid != 0 {
            Owner::Process(self.puid)
        } else {
            Owner::Thread(self.id)
        }
    }

    /// The host thread feeding this stream has the stream's context current,
    /// or none: a host thread may serve more than one stream.
    fn rebind(&self) {
        let r = self.renderer.lock().unwrap_or_else(|e| e.into_inner());
        let want = r.objects.contexts.get(&self.context).map(|c| c.egl).unwrap_or(std::ptr::null_mut());
        let surf = |h: u32| r.objects.windows.get(&h).map(|w| w.surface).unwrap_or(std::ptr::null_mut());
        let (draw, read) = (surf(self.draw), surf(self.read));
        if !Binding::current(r.display).is(want, draw, read) && unsafe { eglMakeCurrent(r.display, draw, read, want) } != EGL_TRUE {
            eprintln!("[gex] gfxstream: render thread {}: its context could not be made current here: {:#x}", self.id, unsafe { eglGetError() });
        }
    }

    /// `FrameBuffer::bindContext`.
    fn make_current(&mut self, r: &mut Renderer, context: u32, draw: u32, read: u32) -> bool {
        let none = std::ptr::null_mut();
        let (mut egl, mut d, mut rd) = (none, none, none);
        if context != 0 || draw != 0 || read != 0 {
            let Some(c) = r.objects.contexts.get(&context) else { return false };
            let Some(dw) = r.objects.windows.get(&draw) else { return false };
            egl = c.egl;
            d = dw.surface;
            rd = if read != draw {
                match r.objects.windows.get(&read) {
                    Some(w) => w.surface,
                    None => return false,
                }
            } else {
                d
            };
        }
        if unsafe { eglMakeCurrent(r.display, d, rd, egl) } != EGL_TRUE {
            eprintln!("[gex] gfxstream: eglMakeCurrent failed: {:#x}", unsafe { eglGetError() });
            return false;
        }
        // The surfaces bound are told their contexts; unbinding tells the
        // ones bound before that they have none.
        let (bind_draw, bind_read) = if draw == 0 && read == 0 { (self.draw, self.read) } else { (draw, read) };
        if bind_draw != 0 && bind_read != 0 {
            if let Some(w) = r.objects.windows.get_mut(&bind_draw) {
                w.draw_context = context;
                if bind_draw == bind_read {
                    w.read_context = context;
                }
            }
            if bind_draw != bind_read {
                if let Some(w) = r.objects.windows.get_mut(&bind_read) {
                    w.read_context = context;
                }
            }
        }
        self.context = context;
        self.draw = draw;
        self.read = read;
        true
    }

    /// Bytes from the guest; what the host answers, in order.
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.broken.is_some() {
            return out;
        }
        self.rebind();
        if self.flags_left > 0 {
            let n = self.flags_left.min(data.len());
            self.flags_left -= n;
            data = &data[n..];
        }
        self.pending.extend_from_slice(data);
        let buf = std::mem::take(&mut self.pending);
        let mut at = 0;
        loop {
            match crate::next_call(&buf[at..]) {
                Ok(Some((call, len))) => {
                    if let Some(a) = self.run(&call) {
                        out.extend_from_slice(&a);
                    }
                    at += len;
                }
                Ok(None) => break,
                Err(e) => {
                    self.broken = Some(e);
                    break;
                }
            }
        }
        self.pending = buf[at..].to_vec();
        out
    }

    /// One call: its answer, if it has one.
    fn run(&mut self, call: &Call<'_>) -> Option<Vec<u8>> {
        let (_, entry) = crate::entry(call.opcode)?;
        if call.api != "renderControl" {
            return self.gles(call, entry);
        }
        let renderer = self.renderer.clone();
        let mut r = renderer.lock().unwrap_or_else(|e| e.into_inner());
        let a = &call.args;
        let v = |i: usize| value(&a[i]);
        let reply = |outs: &[&[u8]], ret: u64| Some(crate::answer(entry, call, outs, ret));
        match call.name {
            "rcGetRendererVersion" => reply(&[], RENDERER_VERSION as u64),
            "rcGetEGLVersion" => reply(&[&r.egl_version.0.to_le_bytes(), &r.egl_version.1.to_le_bytes()], 1),
            "rcQueryEGLString" => {
                let Some(mut s) = r.egl_string(value(&a[0]) as EGLenum) else { return reply(&[], 0) };
                if r.max_version > MaxVersion::Es2 && r.features.gles_dynamic_version && !s.contains("EGL_KHR_create_context") {
                    s.push_str("EGL_KHR_create_context ");
                }
                let size = match a[1] {
                    Arg::Out(n) => n as i32,
                    _ => 0,
                };
                let (ret, b) = string_answer(&s, size.min(value(&a[2]) as i32));
                reply(&[&b], ret as u32 as u64)
            }
            "rcGetGLString" | "rcGetHostExtensionsString" => {
                // The translator's string for the thread's current context,
                // if it has one (`EmulationGl::getGlString`, which asks the
                // translator's `glGetString`; `rcGetHostExtensionsString`
                // is GL_EXTENSIONS's).
                let (name, out, size) = if call.name == "rcGetGLString" { (v(0) as u32, 1, 2) } else { (GL_EXTENSIONS, 1, 0) };
                let current = r.objects.contexts.get(&self.context).map(|c| translator::gl_string(name, c.version, &gl_string, &gl_integer).unwrap_or_default());
                let s = r.gl_string(name, current);
                let room = match a[out] {
                    Arg::Out(n) => n as i32,
                    _ => 0,
                };
                let (ret, b) = string_answer(&s, room.min(v(size) as i32));
                reply(&[&b], ret as u32 as u64)
            }
            "rcGetNumConfigs" => reply(&[&(config::ATTRIBUTES.len() as u32).to_le_bytes()], r.configs.list.len() as u64),
            "rcGetConfigs" => {
                let (ret, b) = r.configs.pack(value(&a[0]) as u32);
                reply(&[&b], ret as u32 as u64)
            }
            "rcChooseConfig" => {
                let attribs = match &a[0] {
                    Arg::In(d) => words(d),
                    _ => Vec::new(),
                };
                let (max, want) = match a[2] {
                    Arg::Out(n) => ((n / 4) as usize, n > 0),
                    _ => (0, false),
                };
                let max = max.min(value(&a[3]) as usize);
                let (ret, list) = r.configs.choose(&attribs, max, want);
                let b: Vec<u8> = list.iter().flat_map(|c| c.to_le_bytes()).collect();
                reply(&[&b], ret as u32 as u64)
            }
            "rcGetFBParam" => {
                let v = match value(&a[0]) {
                    1 => r.size.width,
                    2 => r.size.height,
                    3 => r.size.dpi_x,
                    4 => r.size.dpi_y,
                    5 => 60,
                    _ => -1,
                };
                reply(&[], v as u32 as u64)
            }
            "rcSetPuid" => {
                self.puid = v(0);
                None
            }
            "rcCreateContext" => {
                let owner = self.owner();
                reply(&[], r.create_context(v(0) as u32, v(1) as u32, v(2) as u32, owner) as u64)
            }
            "rcDestroyContext" => {
                r.destroy_context(v(0) as u32);
                None
            }
            "rcCreateWindowSurface" => {
                let owner = self.owner();
                reply(&[], r.create_window(v(0) as u32, v(1) as u32, v(2) as u32, owner) as u64)
            }
            "rcDestroyWindowSurface" => {
                r.destroy_window(v(0) as u32);
                None
            }
            "rcCreateColorBuffer" => reply(&[], r.create_color_buffer(v(0) as u32, v(1) as u32, v(2) as u32) as u64),
            "rcCreateColorBufferDMA" => {
                // A framework format other than 0 (`FRAMEWORK_FORMAT_GL_COMPATIBLE`)
                // is a YUV layout converted on upload (`YUVConverter`).
                reply(&[], r.create_color_buffer_of(v(0) as u32, v(1) as u32, v(2) as u32, v(3) as u32) as u64)
            }
            // With the refcount pipe, opening and closing count nothing.
            "rcOpenColorBuffer" | "rcCloseColorBuffer" => None,
            "rcOpenColorBuffer2" => reply(&[], 0),
            "rcSetWindowColorBuffer" => {
                r.set_window_color_buffer(v(0) as u32, v(1) as u32);
                None
            }
            "rcFlushWindowColorBuffer" => reply(&[], r.flush_window(v(0) as u32) as u32 as u64),
            "rcFlushWindowColorBufferAsync" | "rcFlushWindowColorBufferAsyncWithFrameNumber" => {
                r.flush_window(v(0) as u32);
                None
            }
            "rcMakeCurrent" => {
                let ok = self.make_current(&mut r, v(0) as u32, v(1) as u32, v(2) as u32);
                reply(&[], ok as u64)
            }
            "rcMakeCurrentAsync" => {
                self.make_current(&mut r, v(0) as u32, v(1) as u32, v(2) as u32);
                None
            }
            "rcCreateClientImage" => {
                let owner = self.owner();
                reply(&[], r.create_image(v(0) as u32, v(1) as u32, v(2) as u32, owner) as u64)
            }
            "rcDestroyClientImage" => reply(&[], r.destroy_image(v(0) as u32) as u64),
            "rcCreateSyncKHR" => {
                // Some context must be current: a trivial one if not
                // (`createTrivialContext`, `bindContext`).
                if self.context == 0 {
                    let owner = self.owner();
                    let ctx = r.create_context(0, 0, objects::GLES_API_2, owner);
                    let win = r.create_window(0, 1, 1, owner);
                    self.make_current(&mut r, ctx, win, win);
                }
                let h = r.create_fence(v(3) != 0);
                let thread = if h == 0 { 0 } else { SYNC_THREAD };
                reply(&[&h.to_le_bytes(), &thread.to_le_bytes()], 0)
            }
            "rcClientWaitSyncKHR" => {
                let Some(egl) = r.fences.get(&v(0)).map(|f| f.egl) else { return reply(&[], EGL_CONDITION_SATISFIED_KHR as u64) };
                let display = r.display;
                drop(r);
                let res = sync_fns().map(|s| unsafe { (s.client_wait)(display, egl, EGL_SYNC_FLUSH_COMMANDS_BIT_KHR, v(2)) }).unwrap_or(EGL_CONDITION_SATISFIED_KHR);
                reply(&[], res as u32 as u64)
            }
            "rcWaitSyncKHR" => {
                if let (Some(f), Some(s)) = (r.fences.get(&v(0)), sync_fns()) {
                    unsafe { (s.wait)(r.display, f.egl, 0) };
                }
                None
            }
            "rcDestroySyncKHR" | "rcDestroySyncKHRAsync" => {
                r.fence_unref(v(0));
                entry.answers().then(|| crate::answer(entry, call, &[], 0))
            }
            "rcIsSyncSignaled" => {
                let signaled = match (r.fences.get(&v(0)), sync_fns()) {
                    (Some(f), Some(s)) => {
                        let mut st = 0;
                        unsafe { (s.get_attrib)(r.display, f.egl, EGL_SYNC_STATUS_KHR, &mut st) };
                        st == EGL_SIGNALED_KHR
                    }
                    // A sync not here was destroyed: signalled.
                    _ => true,
                };
                reply(&[], signaled as u64)
            }
            // One display, 0, whose only config is 0 (`mDisplayConfigs`).
            "rcGetFBDisplayConfigsCount" => reply(&[], 1),
            "rcGetFBDisplayActiveConfig" => reply(&[], 0),
            "rcGetFBDisplayConfigsParam" => {
                let p = if v(0) as i32 != 0 {
                    -1
                } else {
                    match v(1) {
                        1 => r.size.width,
                        2 => r.size.height,
                        3 => r.size.dpi_x,
                        4 => r.size.dpi_y,
                        5 => 60,
                        _ => -1,
                    }
                };
                reply(&[], p as u32 as u64)
            }
            // The displays, as gfxstream's default multi-display operations
            // keep them ([`displays`]): -1 for a display that is not there.
            "rcGetDisplayPose" => match r.displays.get(v(0) as u32) {
                Some(d) => reply(&[&d.x.to_le_bytes(), &d.y.to_le_bytes(), &d.width.to_le_bytes(), &d.height.to_le_bytes()], 0),
                None => reply(&[&[0; 4], &[0; 4], &[0; 4], &[0; 4]], u32::MAX as u64),
            },
            "rcSetDisplayPose" | "rcSetDisplayPoseDpi" => match r.displays.get_mut(v(0) as u32) {
                Some(d) => {
                    (d.x, d.y, d.width, d.height) = (v(1) as i32, v(2) as i32, v(3) as u32, v(4) as u32);
                    d.dpi = if call.name == "rcSetDisplayPoseDpi" { v(5) as u32 } else { 0 };
                    reply(&[], 0)
                }
                None => reply(&[], u32::MAX as u64),
            },
            "rcSetDisplayColorBuffer" => match r.displays.get_mut(v(0) as u32) {
                Some(d) => {
                    d.color_buffer = v(1) as u32;
                    reply(&[], 0)
                }
                None => reply(&[], u32::MAX as u64),
            },
            "rcGetDisplayColorBuffer" => match r.displays.get(v(0) as u32) {
                Some(d) => reply(&[&d.color_buffer.to_le_bytes()], 0),
                None => reply(&[&[0; 4]], u32::MAX as u64),
            },
            "rcGetColorBufferDisplay" => match r.displays.showing(v(0) as u32) {
                Some(id) => reply(&[&id.to_le_bytes()], 0),
                None => reply(&[&[0; 4]], u32::MAX as u64),
            },
            // `rcCreateDisplay` always asks for a new id.
            "rcCreateDisplay" => match r.displays.create(displays::INVALID_DISPLAY_ID) {
                Some(id) => reply(&[&id.to_le_bytes()], 0),
                None => reply(&[&displays::INVALID_DISPLAY_ID.to_le_bytes()], u32::MAX as u64),
            },
            "rcCreateDisplayById" => reply(&[], if r.displays.create(v(0) as u32).is_some() { 0 } else { u32::MAX as u64 }),
            "rcDestroyDisplay" => {
                r.displays.destroy(v(0) as u32);
                reply(&[], 0)
            }
            "rcGetDisplayColorTransform" => match r.displays.get(v(0) as u32) {
                Some(d) => {
                    let b: Vec<u8> = d.color_transform.iter().flat_map(|x| x.to_le_bytes()).collect();
                    reply(&[&b], 0)
                }
                None => reply(&[&[0; 64]], u32::MAX as u64),
            },
            "rcSetDisplayColorTransform" => {
                let m = match a[1] {
                    Arg::In(d) if d.len() >= 64 => Some(d),
                    _ => None,
                };
                match (r.displays.get_mut(v(0) as u32), m) {
                    (Some(d), Some(m)) => {
                        for (i, c) in m.chunks_exact(4).take(16).enumerate() {
                            d.color_transform[i] = f32::from_le_bytes(c.try_into().unwrap());
                        }
                        reply(&[], 0)
                    }
                    _ => reply(&[], u32::MAX as u64),
                }
            }
            "rcColorBufferCacheFlush" => reply(&[], 0),
            // `readPixelsYUVCached`: the frame as last uploaded.
            "rcReadColorBufferYUV" => {
                let len = match a[5] {
                    Arg::Out(n) => n as usize,
                    _ => 0,
                };
                let mut b = vec![0u8; len];
                match r.objects.color_buffers.get(&(v(0) as u32)) {
                    Some(c) if c.framework != 0 => {
                        let n = len.min(c.yuv.len());
                        b[..n].copy_from_slice(&c.yuv[..n]);
                    }
                    _ => eprintln!("[gex] gfxstream: rcReadColorBufferYUV of color buffer {}, which is not a YUV one", v(0)),
                }
                reply(&[&b], 0)
            }
            // Taken and not used here: the swap interval of a window, the
            // process's name, host-side tracing.
            "rcFBSetSwapInterval" | "rcSetProcessMetadata" | "rcSetTracingForPuid" => None,
            "rcFBPost" => {
                r.post(v(0) as u32);
                None
            }
            "rcCompose" | "rcComposeWithoutPost" | "rcComposeAsync" | "rcComposeAsyncWithoutPost" => {
                let buf = match &a[1] {
                    Arg::In(d) => *d,
                    _ => &[],
                };
                let done = r.compose(buf, !call.name.ends_with("WithoutPost"));
                if entry.answers() {
                    reply(&[], done as u64)
                } else {
                    None
                }
            }
            "rcBindTexture" => {
                r.bind_color_buffer(v(0) as u32, false);
                None
            }
            "rcBindRenderbuffer" => {
                r.bind_color_buffer(v(0) as u32, true);
                None
            }
            "rcUpdateColorBufferDMA" | "rcReadColorBufferDMA" => {
                let (Arg::Dma(addr), size) = (&a[7], v(8) as usize) else { return reply(&[], 0) };
                let (cb, x, y, w, h, fmt, ty) = (v(0) as u32, v(1) as i32, v(2) as i32, v(3) as i32, v(4) as i32, v(5) as u32, v(6) as u32);
                if *addr == 0 || r.dma.is_none() {
                    eprintln!("[gex] gfxstream: {} with no DMA memory at {addr:#x}", call.name);
                    return reply(&[], 0);
                }
                if call.name == "rcUpdateColorBufferDMA" {
                    let mut px = vec![0u8; size];
                    if !r.dma.as_ref().unwrap().read(*addr, &mut px) {
                        eprintln!("[gex] gfxstream: rcUpdateColorBufferDMA: {size} bytes at {addr:#x} are not all DMA memory");
                        return reply(&[], 0);
                    }
                    r.update_color_buffer(cb, x, y, w, h, fmt, ty, &px);
                } else {
                    let px = r.read_color_buffer(cb, x, y, w, h, fmt, ty, size);
                    if !r.dma.as_ref().unwrap().write(*addr, &px) {
                        eprintln!("[gex] gfxstream: rcReadColorBufferDMA: {size} bytes at {addr:#x} are not all DMA memory");
                    }
                }
                reply(&[], 0)
            }
            "rcUpdateColorBuffer" => {
                let pixels = match &a[7] {
                    Arg::In(d) => *d,
                    _ => &[],
                };
                r.update_color_buffer(v(0) as u32, v(1) as i32, v(2) as i32, v(3) as i32, v(4) as i32, v(5) as u32, v(6) as u32, pixels);
                reply(&[], 0)
            }
            "rcReadColorBuffer" => {
                let len = match a[7] {
                    Arg::Out(n) => n as usize,
                    _ => 0,
                };
                let b = r.read_color_buffer(v(0) as u32, v(1) as i32, v(2) as i32, v(3) as i32, v(4) as i32, v(5) as u32, v(6) as u32, len);
                reply(&[&b], 0)
            }
            // `rcSelectChecksumHelper`: none was offered, so none is chosen.
            "rcSelectChecksumHelper" => None,
            _ => {
                not_yet(call.name);
                // The guest waits for an answer it would get: zeros.
                if entry.answers() {
                    reply(&[], 0)
                } else {
                    None
                }
            }
        }
    }
}

impl Drop for Thread {
    /// A render thread's end: what it made with no process said goes, and
    /// nothing stays current.
    fn drop(&mut self) {
        let mut r = self.renderer.lock().unwrap_or_else(|e| e.into_inner());
        if self.context != 0 && Binding::current(r.display).context() == r.objects.contexts.get(&self.context).map(|c| c.egl).unwrap_or(std::ptr::null_mut()) {
            unsafe { eglMakeCurrent(r.display, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        r.ended(Owner::Thread(self.id));
    }
}

impl Renderer {
    /// The translator's `eglQueryString`: the vendor is the host's
    /// (`EglOsEglDisplay`'s), anything but the three names none.
    fn egl_string(&self, name: EGLenum) -> Option<String> {
        match name {
            egl::EGL_VENDOR => unsafe { string(eglQueryString(self.display, name as EGLint)) },
            egl::EGL_VERSION => Some(format!("{}.{}", TRANSLATOR_EGL_VERSION.0, TRANSLATOR_EGL_VERSION.1)),
            egl::EGL_EXTENSIONS => Some(TRANSLATOR_EGL_EXTENSIONS.into()),
            _ => None,
        }
    }

    /// `EmulatedEglFenceSync::create`: a fence on the current context, the
    /// context flushed; 0 if the host makes none.
    fn create_fence(&mut self, destroy_when_signaled: bool) -> u64 {
        let Some(f) = sync_fns() else {
            not_yet("eglCreateSyncKHR");
            return 0;
        };
        let egl = unsafe { (f.create)(self.display, EGL_SYNC_FENCE_KHR, std::ptr::null()) };
        if egl.is_null() {
            eprintln!("[gex] gfxstream: no EGL fence sync: {:#x}", unsafe { eglGetError() });
            return 0;
        }
        if let Ok(g) = gl::fns() {
            unsafe { (g.glFlush)() };
        }
        self.next_fence += 1;
        self.fences.insert(self.next_fence, Fence { egl, refs: 1 + destroy_when_signaled as u32, destroy_when_signaled });
        self.next_fence
    }

    fn fence_unref(&mut self, handle: u64) {
        let gone = match self.fences.get_mut(&handle) {
            Some(f) => {
                f.refs -= 1;
                f.refs == 0
            }
            None => false,
        };
        if gone {
            let f = self.fences.remove(&handle).unwrap();
            if let Some(s) = sync_fns() {
                unsafe { (s.destroy)(self.display, f.egl) };
            }
        }
    }

    /// The sync device's wait (`SyncThread`'s trigger-wait): until the fence
    /// signals, then the reference it kept for that let go.
    pub fn wait_fence(renderer: &Mutex<Renderer>, handle: u64) {
        let (display, egl) = {
            let r = renderer.lock().unwrap_or_else(|e| e.into_inner());
            match r.fences.get(&handle) {
                Some(f) => (r.display, f.egl),
                None => return,
            }
        };
        if let Some(s) = sync_fns() {
            unsafe { (s.client_wait)(display, egl, EGL_SYNC_FLUSH_COMMANDS_BIT_KHR, EGL_FOREVER_KHR) };
        }
        let mut r = renderer.lock().unwrap_or_else(|e| e.into_inner());
        if r.fences.get(&handle).is_some_and(|f| f.destroy_when_signaled) {
            r.fence_unref(handle);
        }
    }

    /// Where DMA pointers' memory is.
    pub fn set_dma(&mut self, dma: Box<dyn Dma>) {
        self.dma = Some(dma);
    }

    fn add_sync(&mut self, sync: *mut std::ffi::c_void) -> u64 {
        self.next_sync += 1;
        self.syncs.insert(self.next_sync, sync as usize);
        self.next_sync
    }

    /// A handle's sync, or null (which the host's GL refuses as it would a
    /// sync it never made).
    fn sync(&self, handle: u64) -> *mut std::ffi::c_void {
        self.syncs.get(&handle).copied().unwrap_or(0) as *mut _
    }

    fn remove_sync(&mut self, handle: u64) -> *mut std::ffi::c_void {
        self.syncs.remove(&handle).unwrap_or(0) as *mut _
    }

    /// A guest process's `GLProcessPipe` closed: what it made goes.
    pub fn process_ended(&mut self, puid: u64) {
        self.ended(Owner::Process(puid));
    }
}

/// A call this host does not do yet: said once each.
fn not_yet(name: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut s = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !s.iter().any(|x| x == name) {
        eprintln!("[gex] gfxstream: {name} is not done here yet");
        s.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call as the guest's encoder writes it: scalars as given, `in`
    /// pointers with their bytes, `out` pointers with their length.
    enum P<'a> {
        V(u64),
        In(&'a [u8]),
        Out(u32),
        Dma(u64),
    }

    fn encode(name: &str, params: &[P<'_>]) -> Vec<u8> {
        let (op, e) = (0..20000u32).find_map(|op| crate::entry(op).filter(|(_, e)| e.name == name).map(|(_, e)| (op, e))).unwrap();
        let mut body = Vec::new();
        for (p, spec) in params.iter().zip(e.params) {
            match (p, spec.kind) {
                (P::V(v), crate::Kind::Scalar(n)) => body.extend_from_slice(&v.to_le_bytes()[..n as usize]),
                (P::In(d), _) => {
                    body.extend_from_slice(&(d.len() as u32).to_le_bytes());
                    body.extend_from_slice(d);
                }
                (P::Out(n), _) => body.extend_from_slice(&n.to_le_bytes()),
                (P::Dma(a), crate::Kind::Dma) => body.extend_from_slice(&a.to_le_bytes()),
                _ => panic!("{name}: a parameter of the wrong kind"),
            }
        }
        let mut w = op.to_le_bytes().to_vec();
        w.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        w.extend_from_slice(&body);
        w
    }

    fn i32_at(b: &[u8], at: usize) -> i32 {
        i32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// The composer's displays (HWC3's `HostFrameComposer::onDisplayCreate`
    /// and the goldfish display finder): none until made, the primary by
    /// its id, one more numbered from 6, each pose kept.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn the_composer_makes_its_displays() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 1080, height: 1920, dpi_x: 480, dpi_y: 480 }).unwrap();
        let mut t = Thread::new(Arc::new(Mutex::new(r)));
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcGetDisplayPose", &[P::V(0), P::Out(4), P::Out(4), P::Out(4), P::Out(4)]));
        let a = t.feed(&w);
        assert_eq!(i32_at(&a, 16), -1, "no display before the composer makes one");
        assert_eq!(i32_at(&t.feed(&encode("rcCreateDisplayById", &[P::V(0)])), 0), 0);
        assert_eq!(i32_at(&t.feed(&encode("rcCreateDisplayById", &[P::V(0)])), 0), 0, "there already");
        let neg = |x: i32| P::V(x as u32 as u64);
        assert_eq!(i32_at(&t.feed(&encode("rcSetDisplayPoseDpi", &[P::V(0), neg(-1), neg(-1), P::V(1080), P::V(1920), P::V(480)])), 0), 0);
        let a = t.feed(&encode("rcGetDisplayPose", &[P::V(0), P::Out(4), P::Out(4), P::Out(4), P::Out(4)]));
        assert_eq!((i32_at(&a, 0), i32_at(&a, 4), i32_at(&a, 8), i32_at(&a, 12), i32_at(&a, 16)), (-1, -1, 1080, 1920, 0));
        // A secondary display: rcCreateDisplay gives 6.
        let a = t.feed(&encode("rcCreateDisplay", &[P::Out(4)]));
        assert_eq!((i32_at(&a, 0), i32_at(&a, 4)), (6, 0));
        assert_eq!(i32_at(&t.feed(&encode("rcSetDisplayColorBuffer", &[P::V(6), P::V(42)])), 0), 0);
        let a = t.feed(&encode("rcGetColorBufferDisplay", &[P::V(42), P::Out(4)]));
        assert_eq!((i32_at(&a, 0), i32_at(&a, 4)), (6, 0));
        assert_eq!(i32_at(&t.feed(&encode("rcDestroyDisplay", &[P::V(6)])), 0), 0);
        assert_eq!(i32_at(&t.feed(&encode("rcSetDisplayPose", &[P::V(6), P::V(0), P::V(0), P::V(1), P::V(1)])), 0), -1);
        assert!(t.broken.is_none());
    }

    /// What the guest's EGL asks first (`HostConnection`, `egl.cpp`'s
    /// `eglInitialize`), answered by the host's Mesa.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn the_guests_first_questions_are_answered() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 720, height: 1280, dpi_x: 320, dpi_y: 320 }).unwrap();
        let n_configs = r.configs.list.len();
        assert!(n_configs > 0, "no compatible host configs");
        let mut t = Thread::new(Arc::new(Mutex::new(r)));
        // The client flags, then calls, split across writes.
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcGetRendererVersion", &[]));
        w.extend(encode("rcGetEGLVersion", &[P::Out(4), P::Out(4)]));
        let a = t.feed(&w[..6]);
        assert!(a.is_empty());
        let a = t.feed(&w[6..]);
        assert_eq!(i32_at(&a, 0), 1);
        assert!(i32_at(&a, 4) >= 1 && i32_at(&a, 12) == 1, "{a:?}");
        // The configs: their count and the attribute count, then the table.
        let a = t.feed(&encode("rcGetNumConfigs", &[P::Out(4)]));
        assert_eq!((i32_at(&a, 0), i32_at(&a, 4)), (34, n_configs as i32));
        let need = ((n_configs + 1) * 34 * 4) as u32;
        let a = t.feed(&encode("rcGetConfigs", &[P::V(8), P::Out(8)]));
        assert_eq!(i32_at(&a, 8), -(need as i32));
        let a = t.feed(&encode("rcGetConfigs", &[P::V(need as u64), P::Out(need)]));
        assert_eq!(a.len() as u32, need + 4);
        assert_eq!(i32_at(&a, 0), egl::EGL_DEPTH_SIZE);
        assert_eq!(i32_at(&a, need as usize), n_configs as i32);
        // Every config has a window surface.
        for c in 0..n_configs {
            assert!(i32_at(&a, (c + 1) * 34 * 4 + 3 * 4) & egl::EGL_WINDOW_BIT != 0);
        }
        // An 8888 config chosen.
        let attrs: Vec<u8> = [egl::EGL_RED_SIZE, 8, egl::EGL_GREEN_SIZE, 8, egl::EGL_BLUE_SIZE, 8, egl::EGL_ALPHA_SIZE, 8, egl::EGL_NONE].iter().flat_map(|v| v.to_le_bytes()).collect();
        let a = t.feed(&encode("rcChooseConfig", &[P::In(&attrs), P::V(attrs.len() as u64), P::Out(16), P::V(4)]));
        let count = i32_at(&a, 16);
        assert!(count >= 1, "no 8888 config");
        // The extensions say what the host offers.
        let a = t.feed(&encode("rcGetGLString", &[P::V(GL_EXTENSIONS as u64), P::Out(4096), P::V(4096)]));
        let len = i32_at(&a, 4096) as usize;
        let s = std::str::from_utf8(&a[..len - 1]).unwrap();
        assert!(s.contains("ANDROID_EMU_host_composition_v2") && s.contains("ANDROID_EMU_gles_max_version_"), "{s}");
        assert!(!s.contains("CHECKSUM"));
        assert!(t.broken.is_none());
    }

    fn clear(r: f32, g: f32, b: f32, a: f32) {
        type ClearColor = unsafe extern "C" fn(f32, f32, f32, f32);
        type Clear = unsafe extern "C" fn(u32);
        unsafe {
            let cc: ClearColor = std::mem::transmute(egl::proc_address("glClearColor"));
            let c: Clear = std::mem::transmute(egl::proc_address("glClear"));
            cc(r, g, b, a);
            c(gl::GL_COLOR_BUFFER_BIT);
        }
    }

    fn layer(cb: u32, mode: u32, frame: [i32; 4], crop: [f32; 4], color: [u8; 4]) -> Vec<u8> {
        let mut l = Vec::new();
        for w in [cb, mode] {
            l.extend_from_slice(&w.to_le_bytes());
        }
        for w in frame {
            l.extend_from_slice(&w.to_le_bytes());
        }
        for f in crop {
            l.extend_from_slice(&f.to_le_bytes());
        }
        l.extend_from_slice(&1i32.to_le_bytes()); // HWC2_BLEND_MODE_NONE
        l.extend_from_slice(&1.0f32.to_le_bytes());
        l.extend_from_slice(&color);
        l.extend_from_slice(&0u32.to_le_bytes());
        l
    }

    /// The guest's composer (host composition v2): a solid colour over the
    /// whole target, then a 4x4 color buffer into the rectangle (2, 2) to
    /// (6, 6); posted, the display's frame has the source's first row at
    /// the rectangle's top, as gfxstream's compositor and display put it.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn layers_are_composed_and_posted() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 8, height: 8, dpi_x: 160, dpi_y: 160 }).unwrap();
        let renderer = Arc::new(Mutex::new(r));
        let frames: Arc<Mutex<Vec<(u32, u32, Vec<u8>, u64)>>> = Arc::default();
        let got = frames.clone();
        renderer.lock().unwrap().set_sink(Box::new(move |f| got.lock().unwrap().push((f.width, f.height, f.rgba.clone(), f.number))));
        let mut t = Thread::new(renderer.clone());
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcCreateColorBufferDMA", &[P::V(4), P::V(4), P::V(gl::GL_RGBA as u64), P::V(0)]));
        w.extend(encode("rcCreateColorBufferDMA", &[P::V(8), P::V(8), P::V(gl::GL_RGBA as u64), P::V(0)]));
        let a = t.feed(&w);
        let (src, target) = (i32_at(&a, 0) as u64, i32_at(&a, 4) as u64);
        let px: Vec<u8> = (0..16u8).flat_map(|i| [(i / 4) * 40, (i % 4) * 40, 0, 255]).collect();
        t.feed(&encode("rcUpdateColorBuffer", &[P::V(src), P::V(0), P::V(0), P::V(4), P::V(4), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::In(&px)]));
        let mut req = Vec::new();
        for x in [2u32, 0, target as u32, 2] {
            req.extend_from_slice(&x.to_le_bytes());
        }
        req.extend(layer(0, 3, [0, 0, 8, 8], [0.0, 0.0, 1.0, 1.0], [0, 0, 255, 255]));
        req.extend(layer(src as u32, 2, [2, 2, 6, 6], [0.0, 0.0, 4.0, 4.0], [0; 4]));
        let a = t.feed(&encode("rcCompose", &[P::V(req.len() as u64), P::In(&req)]));
        assert_eq!(i32_at(&a, 0), 1);
        let f = frames.lock().unwrap();
        assert_eq!(f.len(), 1);
        let (fw, fh, rgba, n) = &f[0];
        assert_eq!((*fw, *fh, *n), (8, 8, 1));
        let at = |x: usize, y: usize| &rgba[(y * 8 + x) * 4..(y * 8 + x) * 4 + 4];
        assert_eq!(at(0, 0), [0, 0, 255, 255]);
        assert_eq!(at(7, 7), [0, 0, 255, 255]);
        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(at(x + 2, y + 2), [y as u8 * 40, x as u8 * 40, 0, 255], "({x}, {y})");
            }
        }
        drop(f);
        // The target is held while shown: released by its pipe, it stays
        // until another frame is posted.
        let mut r = renderer.lock().unwrap();
        r.release_color_buffer(target as u32);
        assert!(r.objects.color_buffers.contains_key(&(target as u32)));
        r.post(src as u32);
        assert!(!r.objects.color_buffers.contains_key(&(target as u32)));
    }

    /// DMA memory for the tests: one region at 0x1000_0000.
    struct Region(Arc<Mutex<Vec<u8>>>);

    impl Dma for Region {
        fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
            let m = self.0.lock().unwrap();
            let Some(at) = addr.checked_sub(0x1000_0000).map(|a| a as usize) else { return false };
            match m.get(at..at + buf.len()) {
                Some(s) => {
                    buf.copy_from_slice(s);
                    true
                }
                None => false,
            }
        }
        fn write(&self, addr: u64, buf: &[u8]) -> bool {
            let mut m = self.0.lock().unwrap();
            let Some(at) = addr.checked_sub(0x1000_0000).map(|a| a as usize) else { return false };
            match m.get_mut(at..at + buf.len()) {
                Some(s) => {
                    s.copy_from_slice(buf);
                    true
                }
                None => false,
            }
        }
    }

    /// The mapper's path (`rcUpdateColorBufferDMA`, `rcReadColorBufferDMA`):
    /// pixels at a guest physical address into a color buffer and back out
    /// to another; the address alone on the wire.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn pixels_move_through_dma_memory() {
        let mut r = Renderer::new(Features::default(), DisplaySize { width: 8, height: 8, dpi_x: 160, dpi_y: 160 }).unwrap();
        let mem = Arc::new(Mutex::new(vec![0u8; 4096]));
        r.set_dma(Box::new(Region(mem.clone())));
        let mut t = Thread::new(Arc::new(Mutex::new(r)));
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcCreateColorBufferDMA", &[P::V(4), P::V(4), P::V(gl::GL_RGBA as u64), P::V(0)]));
        let cb = i32_at(&t.feed(&w), 0) as u64;
        let px: Vec<u8> = (0..64).collect();
        mem.lock().unwrap()[..64].copy_from_slice(&px);
        let up = encode("rcUpdateColorBufferDMA", &[P::V(cb), P::V(0), P::V(0), P::V(4), P::V(4), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Dma(0x1000_0000), P::V(64)]);
        assert_eq!(up.len(), 8 + 7 * 4 + 8 + 4);
        assert_eq!(i32_at(&t.feed(&up), 0), 0);
        let a = t.feed(&encode("rcReadColorBufferDMA", &[P::V(cb), P::V(0), P::V(0), P::V(4), P::V(4), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Dma(0x1000_0100), P::V(64)]));
        assert_eq!(a, [0, 0, 0, 0]);
        assert_eq!(mem.lock().unwrap()[0x100..0x140], px[..]);
        assert!(t.broken.is_none());
    }

    /// GLES 1 as its encoder sends it: a client array of vertices sent as
    /// data, a flat colour, a clear and a draw; the left half drawn.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn a_guest_draws_with_opengl_es_1() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 16, height: 16, dpi_x: 160, dpi_y: 160 }).unwrap();
        let mut t = Thread::new(Arc::new(Mutex::new(r)));
        const EGL_OPENGL_ES_BIT: i32 = 1;
        let attrs: Vec<u8> = [egl::EGL_RED_SIZE, 8, egl::EGL_GREEN_SIZE, 8, egl::EGL_BLUE_SIZE, 8, egl::EGL_RENDERABLE_TYPE, EGL_OPENGL_ES_BIT, egl::EGL_NONE].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcChooseConfig", &[P::In(&attrs), P::V(attrs.len() as u64), P::Out(4), P::V(1)]));
        let a = t.feed(&w);
        assert!(i32_at(&a, 4) >= 1, "no OpenGL ES 1 config");
        let config = i32_at(&a, 0) as u64;
        let ctx = i32_at(&t.feed(&encode("rcCreateContext", &[P::V(config), P::V(0), P::V(objects::GLES_API_CM as u64)])), 0) as u64;
        assert_ne!(ctx, 0, "no OpenGL ES 1 context");
        let win = i32_at(&t.feed(&encode("rcCreateWindowSurface", &[P::V(config), P::V(16), P::V(16)])), 0) as u64;
        let cb = i32_at(&t.feed(&encode("rcCreateColorBuffer", &[P::V(16), P::V(16), P::V(gl::GL_RGBA as u64)])), 0) as u64;
        t.feed(&encode("rcSetWindowColorBuffer", &[P::V(win), P::V(cb)]));
        assert_eq!(i32_at(&t.feed(&encode("rcMakeCurrent", &[P::V(ctx), P::V(win), P::V(win)])), 0), 1);
        const GL_VERTEX_ARRAY: u64 = 0x8074;
        let fl = |x: f32| P::V(x.to_bits() as u64);
        let quad: Vec<u8> = [-1.0f32, -1.0, 0.0, -1.0, 0.0, 1.0, -1.0, -1.0, 0.0, 1.0, -1.0, 1.0].iter().flat_map(|x| x.to_le_bytes()).collect();
        let mut w = encode("glViewport", &[P::V(0), P::V(0), P::V(16), P::V(16)]);
        w.extend(encode("glClearColor", &[fl(0.0), fl(0.0), fl(1.0), fl(1.0)]));
        w.extend(encode("glClear", &[P::V(gl::GL_COLOR_BUFFER_BIT as u64)]));
        w.extend(encode("glEnableClientState", &[P::V(GL_VERTEX_ARRAY)]));
        w.extend(encode("glVertexPointerData", &[P::V(2), P::V(gl::GL_FLOAT as u64), P::V(8), P::In(&quad), P::V(quad.len() as u64)]));
        w.extend(encode("glColor4f", &[fl(0.0), fl(1.0), fl(0.0), fl(1.0)]));
        w.extend(encode("glDrawArrays", &[P::V(gl::GL_TRIANGLES as u64), P::V(0), P::V(6)]));
        w.extend(encode("glGetError", &[]));
        assert_eq!(t.feed(&w), [0, 0, 0, 0], "a GL error");
        t.feed(&encode("rcFlushWindowColorBuffer", &[P::V(win)]));
        let px = t.feed(&encode("rcReadColorBuffer", &[P::V(cb), P::V(0), P::V(0), P::V(16), P::V(16), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Out(16 * 16 * 4)]));
        let at = |x: usize, y: usize| &px[(y * 16 + x) * 4..(y * 16 + x) * 4 + 4];
        assert_eq!(at(0, 8), [0, 255, 0, 255]);
        assert_eq!(at(15, 8), [0, 0, 255, 255]);
        assert!(t.broken.is_none());
    }

    /// The composer's frame fence: a sync made with no context current (a
    /// trivial one is bound), waited for as the sync device's host does,
    /// then signalled, waited on, destroyed; unknown handles signalled.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn fence_syncs_signal_and_go() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 8, height: 8, dpi_x: 160, dpi_y: 160 }).unwrap();
        let renderer = Arc::new(Mutex::new(r));
        let mut t = Thread::new(renderer.clone());
        let attrs: Vec<u8> = [0x3144i32, -1, egl::EGL_NONE].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcCreateSyncKHR", &[P::V(0x3144), P::In(&attrs), P::V(attrs.len() as u64), P::V(1), P::Out(8), P::Out(8)]));
        let a = t.feed(&w);
        let h = u64::from_le_bytes(a[0..8].try_into().unwrap());
        assert_ne!(h, 0);
        assert_eq!(u64::from_le_bytes(a[8..16].try_into().unwrap()), SYNC_THREAD);
        assert_ne!(t.context, 0, "a trivial context bound");
        Renderer::wait_fence(&renderer, h);
        let a = t.feed(&encode("rcIsSyncSignaled", &[P::V(h)]));
        assert_eq!(i32_at(&a, 0), 1);
        let a = t.feed(&encode("rcClientWaitSyncKHR", &[P::V(h), P::V(1), P::V(u64::MAX)]));
        assert_eq!(i32_at(&a, 0), EGL_CONDITION_SATISFIED_KHR);
        assert_eq!(i32_at(&t.feed(&encode("rcDestroySyncKHR", &[P::V(h)])), 0), 0);
        assert!(renderer.lock().unwrap().fences.is_empty());
        assert_eq!(i32_at(&t.feed(&encode("rcIsSyncSignaled", &[P::V(h)])), 0), 1);
        assert!(t.broken.is_none());
    }

    /// A camera's or decoder's buffer: YUV_420_888, uploaded whole, read
    /// back as RGB (converted) and as YUV (as it came).
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn yuv_buffers_are_converted_and_kept() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 8, height: 8, dpi_x: 160, dpi_y: 160 }).unwrap();
        let mut t = Thread::new(Arc::new(Mutex::new(r)));
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcCreateColorBufferDMA", &[P::V(4), P::V(2), P::V(gl::GL_RGBA as u64), P::V(yuv::YUV_420_888 as u64)]));
        let cb = i32_at(&t.feed(&w), 0) as u64;
        assert_ne!(cb, 0);
        let frame = [81u8, 81, 81, 81, 81, 81, 81, 81, 90, 90, 240, 240];
        let a = t.feed(&encode("rcUpdateColorBuffer", &[P::V(cb), P::V(0), P::V(0), P::V(4), P::V(2), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::In(&frame)]));
        assert_eq!(i32_at(&a, 0), 0);
        let px = t.feed(&encode("rcReadColorBuffer", &[P::V(cb), P::V(0), P::V(0), P::V(4), P::V(2), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Out(32)]));
        assert!(px.chunks_exact(4).all(|p| p == [255, 0, 0, 255]), "{px:?}");
        let back = t.feed(&encode("rcReadColorBufferYUV", &[P::V(cb), P::V(0), P::V(0), P::V(4), P::V(2), P::Out(12), P::V(12)]));
        assert_eq!(back, frame);
        assert!(t.broken.is_none());
    }

    /// A guest's OpenGL ES 2 drawing through the stream as its encoder sends
    /// it: shaders as strings, a program, a uniform of floats, a client
    /// array sent as data, a clear and a draw; then flushed and read back,
    /// the left half the uniform's colour and the right the clear colour.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn a_guest_draws_with_opengl_es() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 32, height: 32, dpi_x: 160, dpi_y: 160 }).unwrap();
        let renderer = Arc::new(Mutex::new(r));
        let mut t = Thread::new(renderer.clone());
        let attrs: Vec<u8> = [egl::EGL_RED_SIZE, 8, egl::EGL_GREEN_SIZE, 8, egl::EGL_BLUE_SIZE, 8, egl::EGL_ALPHA_SIZE, 8, egl::EGL_RENDERABLE_TYPE, egl::EGL_OPENGL_ES2_BIT, egl::EGL_NONE].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut w = 0u32.to_le_bytes().to_vec();
        w.extend(encode("rcChooseConfig", &[P::In(&attrs), P::V(attrs.len() as u64), P::Out(4), P::V(1)]));
        let config = i32_at(&t.feed(&w), 0) as u64;
        let ctx = i32_at(&t.feed(&encode("rcCreateContext", &[P::V(config), P::V(0), P::V(objects::GLES_API_2 as u64)])), 0) as u64;
        let win = i32_at(&t.feed(&encode("rcCreateWindowSurface", &[P::V(config), P::V(32), P::V(32)])), 0) as u64;
        let cb = i32_at(&t.feed(&encode("rcCreateColorBuffer", &[P::V(32), P::V(32), P::V(gl::GL_RGBA as u64)])), 0) as u64;
        t.feed(&encode("rcSetWindowColorBuffer", &[P::V(win), P::V(cb)]));
        assert_eq!(i32_at(&t.feed(&encode("rcMakeCurrent", &[P::V(ctx), P::V(win), P::V(win)])), 0), 1);
        let shader = |t: &mut Thread, kind: u32, src: &str| {
            let s = i32_at(&t.feed(&encode("glCreateShader", &[P::V(kind as u64)])), 0) as u64;
            let mut text = src.as_bytes().to_vec();
            text.push(0);
            assert!(t.feed(&encode("glShaderString", &[P::V(s), P::In(&text), P::V(text.len() as u64)])).is_empty());
            t.feed(&encode("glCompileShader", &[P::V(s)]));
            let a = t.feed(&encode("glGetShaderiv", &[P::V(s), P::V(gl::GL_COMPILE_STATUS as u64), P::Out(4)]));
            assert_eq!(i32_at(&a, 0), 1, "{src}");
            s
        };
        let vs = shader(&mut t, gl::GL_VERTEX_SHADER, "attribute vec2 pos; void main() { gl_Position = vec4(pos, 0.0, 1.0); }");
        let fs = shader(&mut t, gl::GL_FRAGMENT_SHADER, "precision mediump float; uniform vec4 color; void main() { gl_FragColor = color; }");
        let prog = i32_at(&t.feed(&encode("glCreateProgram", &[])), 0) as u64;
        let mut w = encode("glAttachShader", &[P::V(prog), P::V(vs)]);
        w.extend(encode("glAttachShader", &[P::V(prog), P::V(fs)]));
        w.extend(encode("glBindAttribLocation", &[P::V(prog), P::V(3), P::In(b"pos\0")]));
        w.extend(encode("glLinkProgram", &[P::V(prog)]));
        w.extend(encode("glGetProgramiv", &[P::V(prog), P::V(gl::GL_LINK_STATUS as u64), P::Out(4)]));
        assert_eq!(i32_at(&t.feed(&w), 0), 1);
        t.feed(&encode("glUseProgram", &[P::V(prog)]));
        let loc = i32_at(&t.feed(&encode("glGetUniformLocation", &[P::V(prog), P::In(b"color\0")])), 0);
        assert!(loc >= 0);
        let fl = |x: f32| P::V(x.to_bits() as u64);
        let mut w = encode("glUniform4f", &[P::V(loc as u32 as u64), fl(1.0), fl(0.5), fl(0.0), fl(1.0)]);
        let quad: Vec<u8> = [-1.0f32, -1.0, 0.0, -1.0, 0.0, 1.0, -1.0, -1.0, 0.0, 1.0, -1.0, 1.0].iter().flat_map(|x| x.to_le_bytes()).collect();
        w.extend(encode("glEnableVertexAttribArray", &[P::V(3)]));
        w.extend(encode("glVertexAttribPointerData", &[P::V(3), P::V(2), P::V(gl::GL_FLOAT as u64), P::V(0), P::V(8), P::In(&quad), P::V(quad.len() as u64)]));
        w.extend(encode("glViewport", &[P::V(0), P::V(0), P::V(32), P::V(32)]));
        w.extend(encode("glClearColor", &[fl(0.0), fl(0.0), fl(1.0), fl(1.0)]));
        w.extend(encode("glClear", &[P::V(gl::GL_COLOR_BUFFER_BIT as u64)]));
        w.extend(encode("glDrawArrays", &[P::V(gl::GL_TRIANGLES as u64), P::V(0), P::V(6)]));
        w.extend(encode("glGetError", &[]));
        let a = t.feed(&w);
        assert_eq!(a, [0, 0, 0, 0], "a GL error");
        assert_eq!(i32_at(&t.feed(&encode("rcFlushWindowColorBuffer", &[P::V(win)])), 0), 0);
        let px = t.feed(&encode("rcReadColorBuffer", &[P::V(cb), P::V(0), P::V(0), P::V(32), P::V(32), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Out(32 * 32 * 4)]));
        let at = |x: usize, y: usize| &px[(y * 32 + x) * 4..(y * 32 + x) * 4 + 4];
        for y in [0, 15, 31] {
            assert_eq!(at(0, y), [255, 128, 0, 255], "row {y}");
            assert_eq!(at(15, y), [255, 128, 0, 255]);
            assert_eq!(at(16, y), [0, 0, 255, 255]);
            assert_eq!(at(31, y), [0, 0, 255, 255]);
        }
        // A client image of one of the guest's textures, bound to another.
        let a = t.feed(&encode("glGenTextures", &[P::V(2), P::Out(8)]));
        let (t1, t2) = (i32_at(&a, 0) as u64, i32_at(&a, 4) as u64);
        let mut w = encode("glBindTexture", &[P::V(gl::GL_TEXTURE_2D as u64), P::V(t1)]);
        w.extend(encode("glTexImage2D", &[P::V(gl::GL_TEXTURE_2D as u64), P::V(0), P::V(gl::GL_RGBA as u64), P::V(4), P::V(4), P::V(0), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::In(&[])]));
        t.feed(&w);
        let image = i32_at(&t.feed(&encode("rcCreateClientImage", &[P::V(ctx), P::V(egl::EGL_GL_TEXTURE_2D_KHR as u64), P::V(t1)])), 0) as u64;
        assert_ne!(image, 0);
        let mut w = encode("glBindTexture", &[P::V(gl::GL_TEXTURE_2D as u64), P::V(t2)]);
        w.extend(encode("glEGLImageTargetTexture2DOES", &[P::V(gl::GL_TEXTURE_2D as u64), P::V(image)]));
        w.extend(encode("glGetError", &[]));
        assert_eq!(t.feed(&w), [0, 0, 0, 0]);
        // One never given is refused by the host's GL.
        let mut w = encode("glEGLImageTargetTexture2DOES", &[P::V(gl::GL_TEXTURE_2D as u64), P::V(image + 100)]);
        w.extend(encode("glGetError", &[]));
        assert_ne!(t.feed(&w), [0, 0, 0, 0]);
        assert_eq!(i32_at(&t.feed(&encode("rcDestroyClientImage", &[P::V(image)])), 0), 1);
        assert_eq!(i32_at(&t.feed(&encode("rcDestroyClientImage", &[P::V(image)])), 0), 0);
        assert!(t.broken.is_none());
    }

    /// A guest's frame (`egl_window_surface_t`'s path): a context, a window
    /// surface on a color buffer, made current, drawn (here by the host's
    /// GL directly, there being no GLES decoder yet), flushed into the
    /// color buffer and read back; a rectangle written into the color
    /// buffer and read back; handles from 1 and never reused while in use.
    #[test]
    #[ignore = "needs the host's Mesa EGL"]
    fn a_frame_reaches_its_color_buffer() {
        let r = Renderer::new(Features::default(), DisplaySize { width: 64, height: 64, dpi_x: 160, dpi_y: 160 }).unwrap();
        let renderer = Arc::new(Mutex::new(r));
        let mut t = Thread::new(renderer.clone());
        let mut w = 0u32.to_le_bytes().to_vec();
        let attrs: Vec<u8> = [egl::EGL_RED_SIZE, 8, egl::EGL_GREEN_SIZE, 8, egl::EGL_BLUE_SIZE, 8, egl::EGL_ALPHA_SIZE, 8, egl::EGL_RENDERABLE_TYPE, egl::EGL_OPENGL_ES2_BIT, egl::EGL_NONE].iter().flat_map(|v| v.to_le_bytes()).collect();
        w.extend(encode("rcChooseConfig", &[P::In(&attrs), P::V(attrs.len() as u64), P::Out(4), P::V(1)]));
        let a = t.feed(&w);
        assert!(i32_at(&a, 4) >= 1);
        let config = i32_at(&a, 0) as u64;
        let a = t.feed(&encode("rcCreateContext", &[P::V(config), P::V(0), P::V(objects::GLES_API_2 as u64)]));
        let ctx = i32_at(&a, 0);
        let a = t.feed(&encode("rcCreateWindowSurface", &[P::V(config), P::V(16), P::V(16)]));
        let win = i32_at(&a, 0);
        let a = t.feed(&encode("rcCreateColorBufferDMA", &[P::V(32), P::V(32), P::V(gl::GL_RGBA as u64), P::V(0)]));
        let cb = i32_at(&a, 0);
        assert_eq!((ctx, win, cb), (1, 2, 3));
        // Attaching gives the window the color buffer's size.
        assert!(t.feed(&encode("rcSetWindowColorBuffer", &[P::V(win as u64), P::V(cb as u64)])).is_empty());
        assert_eq!(renderer.lock().unwrap().objects.windows[&(win as u32)].width, 32);
        let a = t.feed(&encode("rcMakeCurrent", &[P::V(ctx as u64), P::V(win as u64), P::V(win as u64)]));
        assert_eq!(i32_at(&a, 0), 1);
        // With a context current, the GL strings are the host's own, the
        // version the one offered.
        let a = t.feed(&encode("rcGetGLString", &[P::V(gl::GL_VERSION as u64), P::Out(256), P::V(256)]));
        let v = String::from_utf8_lossy(&a[..i32_at(&a, 256) as usize - 1]).into_owned();
        assert!(v.starts_with("OpenGL ES 3.1") || v.starts_with("OpenGL ES 3.0") || v.starts_with("OpenGL ES 2.0"), "{v}");
        assert!(v.len() > "OpenGL ES 3.1".len(), "{v}");
        let a = t.feed(&encode("rcGetHostExtensionsString", &[P::V(8192), P::Out(8192)]));
        let e = String::from_utf8_lossy(&a[..i32_at(&a, 8192) as usize - 1]).into_owned();
        assert!(e.contains("GL_OES_EGL_image ") && e.contains("ANDROID_EMU_host_composition_v2"), "{e}");
        // The renderer's textures are not the guest context's.
        let cb_tex = renderer.lock().unwrap().objects.color_buffers[&(cb as u32)].tex;
        type IsTexture = unsafe extern "C" fn(u32) -> u8;
        let is_texture: IsTexture = unsafe { std::mem::transmute(egl::proc_address("glIsTexture")) };
        assert_eq!(unsafe { is_texture(cb_tex) }, 0);
        clear(1.0, 0.0, 1.0, 1.0);
        let a = t.feed(&encode("rcFlushWindowColorBuffer", &[P::V(win as u64)]));
        assert_eq!(i32_at(&a, 0), 0);
        let n = 32 * 32 * 4;
        let a = t.feed(&encode("rcReadColorBuffer", &[P::V(cb as u64), P::V(0), P::V(0), P::V(32), P::V(32), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Out(n)]));
        assert_eq!(a.len(), n as usize);
        assert!(a.chunks_exact(4).all(|p| p == [255, 0, 255, 255]), "{:?}", &a[..8]);
        // The guest's context is still current, and still draws.
        clear(0.0, 1.0, 0.0, 1.0);
        t.feed(&encode("rcFlushWindowColorBuffer", &[P::V(win as u64)]));
        // A 2x2 rectangle written at (4, 4), read back with a row around it.
        let px: Vec<u8> = (0..16).map(|i| i as u8 * 10).collect();
        let a = t.feed(&encode("rcUpdateColorBuffer", &[P::V(cb as u64), P::V(4), P::V(4), P::V(2), P::V(2), P::V(gl::GL_RGBA as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::In(&px)]));
        assert_eq!(i32_at(&a, 0), 0);
        let a = t.feed(&encode("rcReadColorBuffer", &[P::V(cb as u64), P::V(3), P::V(4), P::V(4), P::V(2), P::V(gl::GL_RGB as u64), P::V(gl::GL_UNSIGNED_BYTE as u64), P::Out(24)]));
        assert_eq!(&a[..3], [0, 255, 0]);
        assert_eq!(&a[3..9], [0, 10, 20, 40, 50, 60]);
        assert_eq!(&a[9..12], [0, 255, 0]);
        // Unbound, then gone with the thread; the color buffer with its pipe.
        let a = t.feed(&encode("rcMakeCurrent", &[P::V(0), P::V(0), P::V(0)]));
        assert_eq!(i32_at(&a, 0), 1);
        assert!(t.broken.is_none());
        drop(t);
        let mut r = renderer.lock().unwrap();
        assert!(r.objects.contexts.is_empty() && r.objects.windows.is_empty());
        assert_eq!(r.objects.color_buffers.len(), 1);
        r.release_color_buffer(cb as u32);
        assert!(r.objects.color_buffers.is_empty());
    }
}
