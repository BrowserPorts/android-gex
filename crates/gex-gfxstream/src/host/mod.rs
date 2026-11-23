//! The host's side of gfxstream: what the guest's EGL and OpenGL ES ask, done
//! on the host's EGL and OpenGL ES (Mesa), after gfxstream's own host
//! (`host/RenderControl.cpp`, `FrameBuffer.cpp`, `host/gl/`).
//!
//! One [`Renderer`] for the machine holds what every guest process shares:
//! the host's display, a root context every guest context shares with (so a
//! color buffer, a texture of the root's, is every context's), the configs,
//! and the objects by handle. A [`Thread`] is one `pipe:opengles` stream, a
//! guest render thread: its current context and surfaces, its process.
//!
//! What the host offers the guest is said in `GL_EXTENSIONS`
//! (`rcGetGLString`), and the guest takes its paths by it:
//! [`Features`] says which.

pub mod config;
pub mod egl;

use crate::{Arg, Call};
use egl::*;
use std::ffi::c_char;
use std::sync::{Arc, Mutex};

/// gfxstream's renderer version (`rendererVersion`).
const RENDERER_VERSION: i32 = 1;

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
    /// The context every guest context shares with, and its surface: where
    /// color buffers are made and drawn to (`FrameBuffer`'s own context).
    #[allow(dead_code)]
    root: EGLContext,
    #[allow(dead_code)]
    root_surface: EGLSurface,
    size: DisplaySize,
}

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
        let (display, major, minor) = egl::display()?;
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
        Ok(Renderer { display, egl_version: (major, minor), configs, features, max_version, host_extensions, root, root_surface, size })
    }

    /// `rcGetGLString`'s answer for `name`: the host's string on the
    /// thread's current context (none: empty), then for `GL_EXTENSIONS` what
    /// the host offers, and for `GL_VERSION` the version the guest may use.
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
        Thread { renderer, flags_left: 4, pending: Vec::new(), puid: 0, broken: None }
    }

    /// Bytes from the guest; what the host answers, in order.
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.broken.is_some() {
            return out;
        }
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
        let r = self.renderer.lock().unwrap_or_else(|e| e.into_inner());
        let a = &call.args;
        let reply = |outs: &[&[u8]], ret: u64| Some(crate::answer(entry, call, outs, ret));
        match call.name {
            "rcGetRendererVersion" => reply(&[], RENDERER_VERSION as u64),
            "rcGetEGLVersion" => reply(&[&r.egl_version.0.to_le_bytes(), &r.egl_version.1.to_le_bytes()], 1),
            "rcQueryEGLString" => {
                let s = unsafe { string(eglQueryString(r.display, value(&a[0]) as EGLint)) };
                let Some(mut s) = s else { return reply(&[], 0) };
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
            "rcGetGLString" => {
                let s = r.gl_string(value(&a[0]) as u32, None);
                let size = match a[1] {
                    Arg::Out(n) => n as i32,
                    _ => 0,
                };
                let (ret, b) = string_answer(&s, size.min(value(&a[2]) as i32));
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
                drop(r);
                self.puid = value(&a[0]);
                None
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
}
