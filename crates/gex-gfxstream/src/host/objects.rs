//! The renderer's objects by handle, as gfxstream's `FrameBuffer` keeps
//! them: contexts (`EmulatedEglContext`), window surfaces
//! (`EmulatedEglWindowSurface`: a host pbuffer the guest's window is drawn
//! into, copied into its color buffer at a flush) and color buffers
//! (`ColorBufferGl`: a texture of the root context's, with an EGL image of
//! it through which guest contexts reach it).
//!
//! A guest context shares objects only with the context it names, as EGL
//! has it: gfxstream shares every context with its own and keeps each
//! guest share group's names apart in its translator; here the host's EGL
//! keeps them apart, and the renderer's own objects are no guest's.
//!
//! Color buffers are counted as with the `RefCountPipe` feature, which the
//! image's allocator and EGL always use: one reference when made, none taken
//! or dropped by `rcOpenColorBuffer`/`rcCloseColorBuffer`, and the
//! `refcount` pipe's close dropping it. A window it is attached to holds it
//! too, as gfxstream's shared pointer does.

use super::egl::*;
use super::gl::{self, Fns, Format};
use super::Renderer;
use std::collections::HashMap;

/// `GLESApi`: the version a guest context was asked for.
pub const GLES_API_CM: u32 = 1;
pub const GLES_API_2: u32 = 2;
pub const GLES_API_3_0: u32 = 3;
pub const GLES_API_3_1: u32 = 4;

/// Whose an object is: a guest process's (from `rcSetPuid`), ended with
/// the process's `GLProcessPipe`; or, with no process said, the render
/// thread's that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Process(u64),
    Thread(u64),
}

pub struct Context {
    pub egl: EGLContext,
    pub version: u32,
    pub owner: Owner,
    /// Client-array data by attribute, kept until replaced
    /// (`GLESv2Decoder`'s context data).
    pub(super) arrays: HashMap<u32, super::gles::Buf>,
}

pub struct Window {
    pub surface: EGLSurface,
    config: EGLConfig,
    pub width: u32,
    pub height: u32,
    pub color_buffer: u32,
    pub draw_context: u32,
    pub read_context: u32,
    pub owner: Owner,
}

pub struct ColorBuffer {
    pub tex: u32,
    image: EGLImage,
    pub width: u32,
    pub height: u32,
    pub format: Format,
    /// The first update may respecify the texture (`m_needFormatCheck`).
    format_checked: bool,
    /// Kept for reads (`m_fbo`).
    fbo: u32,
    /// The guest's references (`ColorBufferRef::refcount`).
    pub refs: u32,
    /// The windows it is attached to, and the display while it shows it.
    holds: u32,
}

impl ColorBuffer {
    /// A window or the display takes or lets go of it.
    pub fn hold(&mut self, on: bool) {
        if on {
            self.holds += 1;
        } else {
            self.holds -= 1;
        }
    }
}

/// An image of a guest context's object (`EmulatedEglImage`).
pub struct Image {
    pub egl: EGLImage,
    pub owner: Owner,
}

#[derive(Default)]
pub struct Objects {
    next: u32,
    pub contexts: HashMap<u32, Context>,
    pub windows: HashMap<u32, Window>,
    pub color_buffers: HashMap<u32, ColorBuffer>,
    /// Numbered apart, from 1 (gfxstream gives the host image's address).
    pub images: HashMap<u32, Image>,
    next_image: u32,
}

// The handles are the driver's; the renderer's lock orders their use.
unsafe impl Send for Objects {}

impl Objects {
    /// `genHandle_locked`: the next number that is not 0 and names nothing.
    fn handle(&mut self) -> u32 {
        loop {
            self.next = self.next.wrapping_add(1);
            let h = self.next;
            if h != 0 && !self.contexts.contains_key(&h) && !self.windows.contains_key(&h) && !self.color_buffers.contains_key(&h) {
                return h;
            }
        }
    }
}

/// Bytes a pixel of `format` and `type` takes in client memory.
pub fn pixel_bytes(format: u32, ty: u32) -> u32 {
    let comps = match format {
        gl::GL_RGBA | gl::GL_BGRA_EXT => 4,
        gl::GL_RGB => 3,
        gl::GL_RG | gl::GL_LUMINANCE_ALPHA => 2,
        _ => 1,
    };
    match ty {
        gl::GL_UNSIGNED_SHORT_5_6_5 | gl::GL_UNSIGNED_SHORT_4_4_4_4 | gl::GL_UNSIGNED_SHORT_5_5_5_1 => 2,
        gl::GL_UNSIGNED_INT_2_10_10_10_REV | gl::GL_UNSIGNED_INT_24_8 => 4,
        gl::GL_FLOAT_32_UNSIGNED_INT_24_8_REV => 8,
        gl::GL_HALF_FLOAT | gl::GL_UNSIGNED_SHORT => 2 * comps,
        gl::GL_FLOAT | gl::GL_UNSIGNED_INT => 4 * comps,
        _ => comps,
    }
}

fn int(f: &Fns, name: u32) -> i32 {
    let mut v = 0;
    unsafe { (f.glGetIntegerv)(name, &mut v) };
    v
}

impl Renderer {
    fn fns(&self) -> &'static Fns {
        gl::fns().expect("the host's GLES lost an entry point it had")
    }

    /// Runs `f` with the root context current on this thread, then puts back
    /// what was (`RecursiveScopedContextBind` on the renderer's helper).
    pub(super) fn with_root<T>(&self, f: impl FnOnce(&Fns) -> T) -> Option<T> {
        let was = Binding::current(self.display);
        let switch = !was.is(self.root, self.root_surface, self.root_surface);
        if switch && unsafe { eglMakeCurrent(self.display, self.root_surface, self.root_surface, self.root) } != EGL_TRUE {
            eprintln!("[gex] gfxstream: the root context could not be made current: {:#x}", unsafe { eglGetError() });
            return None;
        }
        let r = f(self.fns());
        if switch {
            was.restore();
        }
        Some(r)
    }

    /// `rcCreateContext`: a host context of the guest's config, sharing with
    /// `share` if one is named, at the version asked; 0 if it cannot be.
    pub fn create_context(&mut self, config: u32, share: u32, version: u32, owner: Owner) -> u32 {
        let shared = if share != 0 {
            match self.objects.contexts.get(&share) {
                Some(c) => c.egl,
                None => {
                    eprintln!("[gex] gfxstream: rcCreateContext: no context {share} to share with");
                    return 0;
                }
            }
        } else {
            std::ptr::null_mut()
        };
        let handle = self.objects.handle();
        let Some(cfg) = self.configs.list.get(config as usize).map(|c| c.host) else {
            eprintln!("[gex] gfxstream: rcCreateContext: no config {config}");
            return 0;
        };
        let (major, minor) = match version {
            GLES_API_3_0 => (3, 0),
            GLES_API_3_1 => (3, 1),
            v => (v as EGLint, 0),
        };
        let attrs = [EGL_CONTEXT_CLIENT_VERSION, major, EGL_CONTEXT_MINOR_VERSION, minor, EGL_NONE];
        let egl = unsafe { eglCreateContext(self.display, cfg, shared, attrs.as_ptr()) };
        if egl.is_null() {
            eprintln!("[gex] gfxstream: rcCreateContext: the host made no OpenGL ES {major}.{minor} context: {:#x}", unsafe { eglGetError() });
            return 0;
        }
        self.objects.contexts.insert(handle, Context { egl, version, owner, arrays: HashMap::new() });
        handle
    }

    /// `rcDestroyContext`. A context current somewhere is let go by the
    /// host's EGL when it stops being current.
    pub fn destroy_context(&mut self, handle: u32) {
        if let Some(c) = self.objects.contexts.remove(&handle) {
            unsafe { eglDestroyContext(self.display, c.egl) };
        }
    }

    fn pbuffer(&self, config: EGLConfig, width: u32, height: u32) -> EGLSurface {
        let attrs = [EGL_WIDTH, width as EGLint, EGL_HEIGHT, height as EGLint, EGL_NONE];
        unsafe { eglCreatePbufferSurface(self.display, config, attrs.as_ptr()) }
    }

    /// `rcCreateWindowSurface`: a pbuffer of the config and size.
    pub fn create_window(&mut self, config: u32, width: u32, height: u32, owner: Owner) -> u32 {
        let handle = self.objects.handle();
        let Some(cfg) = self.configs.list.get(config as usize).map(|c| c.host) else {
            eprintln!("[gex] gfxstream: rcCreateWindowSurface: no config {config}");
            return 0;
        };
        let surface = self.pbuffer(cfg, width, height);
        if surface.is_null() {
            eprintln!("[gex] gfxstream: rcCreateWindowSurface: no {width}x{height} pbuffer: {:#x}", unsafe { eglGetError() });
            return 0;
        }
        self.objects.windows.insert(handle, Window { surface, config: cfg, width, height, color_buffer: 0, draw_context: 0, read_context: 0, owner });
        handle
    }

    pub fn destroy_window(&mut self, handle: u32) {
        if let Some(w) = self.objects.windows.remove(&handle) {
            self.detach(w.color_buffer);
            unsafe { eglDestroySurface(self.display, w.surface) };
        }
    }

    /// `EmulatedEglWindowSurface::resize`: a new pbuffer, made current again
    /// where the old one was current on this thread.
    fn resize(&mut self, handle: u32, width: u32, height: u32) -> bool {
        let Some(w) = self.objects.windows.get(&handle) else { return false };
        if w.width == width && w.height == height {
            return true;
        }
        let (old, config) = (w.surface, w.config);
        let was = Binding::current(self.display);
        let draw = unsafe { eglGetCurrentSurface(EGL_DRAW) };
        let read = unsafe { eglGetCurrentSurface(EGL_READ) };
        let rebind = draw == old || read == old;
        if rebind {
            unsafe { eglMakeCurrent(self.display, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        unsafe { eglDestroySurface(self.display, old) };
        let new = self.pbuffer(config, width, height);
        let w = self.objects.windows.get_mut(&handle).unwrap();
        w.surface = new;
        if new.is_null() {
            eprintln!("[gex] gfxstream: a window surface could not be made {width}x{height}: {:#x}", unsafe { eglGetError() });
            return false;
        }
        w.width = width;
        w.height = height;
        if rebind {
            let d = if draw == old { new } else { draw };
            let r = if read == old { new } else { read };
            unsafe { eglMakeCurrent(self.display, d, r, was.context()) };
        }
        true
    }

    fn detach(&mut self, cb: u32) {
        if cb == 0 {
            return;
        }
        if let Some(c) = self.objects.color_buffers.get_mut(&cb) {
            c.hold(false);
        }
        self.free_if_unused(cb);
    }

    /// `rcSetWindowColorBuffer`: the window draws into `cb` from now on, and
    /// takes its size.
    pub fn set_window_color_buffer(&mut self, window: u32, cb: u32) {
        if !self.objects.windows.contains_key(&window) {
            eprintln!("[gex] gfxstream: rcSetWindowColorBuffer: no window {window}");
            return;
        }
        let Some(c) = self.objects.color_buffers.get_mut(&cb) else {
            eprintln!("[gex] gfxstream: rcSetWindowColorBuffer: no color buffer {cb}");
            return;
        };
        c.hold(true);
        let (width, height) = (c.width, c.height);
        let w = self.objects.windows.get_mut(&window).unwrap();
        let old = std::mem::replace(&mut w.color_buffer, cb);
        self.detach(old);
        self.resize(window, width, height);
    }

    /// `rcFlushWindowColorBuffer`: what was drawn into the window copied into
    /// its color buffer, with the window's draw context; 0, or -1.
    pub fn flush_window(&mut self, window: u32) -> i32 {
        let Some(w) = self.objects.windows.get(&window) else {
            eprintln!("[gex] gfxstream: rcFlushWindowColorBuffer: no window {window}");
            return -1;
        };
        if w.color_buffer == 0 {
            return 0;
        }
        let Some(cb) = self.objects.color_buffers.get(&w.color_buffer) else { return -1 };
        if w.width == 0 || w.height == 0 || cb.width != w.width || cb.height != w.height {
            return -1;
        }
        let Some(ctx) = self.objects.contexts.get(&w.draw_context) else {
            return -1;
        };
        let was = Binding::current(self.display);
        let switch = !was.is(ctx.egl, w.surface, w.surface);
        if switch && unsafe { eglMakeCurrent(self.display, w.surface, w.surface, ctx.egl) } != EGL_TRUE {
            eprintln!("[gex] gfxstream: rcFlushWindowColorBuffer: the draw context could not be made current: {:#x}", unsafe { eglGetError() });
            return -1;
        }
        blit_from_read_buffer(self.fns(), cb, ctx.version > GLES_API_2);
        if switch {
            was.restore();
        }
        0
    }

    /// `rcCreateColorBuffer`/`rcCreateColorBufferDMA`: a texture of the
    /// root's, with one reference.
    pub fn create_color_buffer(&mut self, width: u32, height: u32, internal: u32) -> u32 {
        let handle = self.objects.handle();
        let Some(format) = gl::color_buffer_format(internal) else {
            eprintln!("[gex] gfxstream: a color buffer of format {internal:#x} cannot be made (gfxstream's host aborts here)");
            return 0;
        };
        let display = self.display;
        let root = self.root;
        let made = self.with_root(|f| unsafe {
            let unpack = int(f, gl::GL_UNPACK_ALIGNMENT);
            let bound = int(f, gl::GL_TEXTURE_BINDING_2D);
            (f.glPixelStorei)(gl::GL_UNPACK_ALIGNMENT, 1);
            let mut tex = 0;
            (f.glGenTextures)(1, &mut tex);
            (f.glBindTexture)(gl::GL_TEXTURE_2D, tex);
            (f.glTexImage2D)(gl::GL_TEXTURE_2D, 0, format.internal as i32, width as i32, height as i32, 0, format.format, format.ty, std::ptr::null());
            (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_MAG_FILTER, gl::GL_LINEAR);
            (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_MIN_FILTER, gl::GL_LINEAR);
            (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_WRAP_S, gl::GL_CLAMP_TO_EDGE);
            (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_WRAP_T, gl::GL_CLAMP_TO_EDGE);
            if internal == gl::GL_BGR10_A2_ANGLEX {
                (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_SWIZZLE_B, gl::GL_RED as i32);
                (f.glTexParameteri)(gl::GL_TEXTURE_2D, gl::GL_TEXTURE_SWIZZLE_R, gl::GL_BLUE as i32);
            }
            let image = texture_image(display, root, tex);
            (f.glBindTexture)(gl::GL_TEXTURE_2D, bound as u32);
            (f.glPixelStorei)(gl::GL_UNPACK_ALIGNMENT, unpack);
            (tex, image)
        });
        let Some((tex, image)) = made else { return 0 };
        if image.is_null() {
            eprintln!("[gex] gfxstream: no EGL image of a color buffer's texture: {:#x}", unsafe { eglGetError() });
        }
        self.objects.color_buffers.insert(handle, ColorBuffer { tex, image, width, height, format, format_checked: false, fbo: 0, refs: 1, holds: 0 });
        handle
    }

    /// The `refcount` pipe's close (`onLastColorBufferRef`, swept at once).
    pub fn release_color_buffer(&mut self, handle: u32) {
        if let Some(c) = self.objects.color_buffers.get_mut(&handle) {
            c.refs = c.refs.saturating_sub(1);
        }
        self.free_if_unused(handle);
    }

    pub(super) fn free_if_unused(&mut self, handle: u32) {
        match self.objects.color_buffers.get(&handle) {
            Some(c) if c.refs == 0 && c.holds == 0 => {}
            _ => return,
        }
        let c = self.objects.color_buffers.remove(&handle).unwrap();
        destroy_image(self.display, c.image);
        self.with_root(|f| unsafe {
            (f.glDeleteTextures)(1, &c.tex);
            if c.fbo != 0 {
                (f.glDeleteFramebuffers)(1, &c.fbo);
            }
        });
    }

    /// `rcUpdateColorBuffer`: pixels into a rectangle of it. The first
    /// update in a format or type other than the buffer's makes the buffer
    /// that format (`reformat`).
    pub fn update_color_buffer(&mut self, handle: u32, x: i32, y: i32, width: i32, height: i32, format: u32, ty: u32, pixels: &[u8]) {
        let display = self.display;
        let root = self.root;
        let Some(c) = self.objects.color_buffers.get(&handle) else {
            eprintln!("[gex] gfxstream: rcUpdateColorBuffer: no color buffer {handle}");
            return;
        };
        let need = (width.max(0) as usize) * (height.max(0) as usize) * pixel_bytes(gl::unsized_format(format), ty) as usize;
        if pixels.len() < need {
            eprintln!("[gex] gfxstream: rcUpdateColorBuffer: {} bytes for a {width}x{height} rectangle that takes {need}", pixels.len());
            return;
        }
        let reformat = !c.format_checked && (ty != c.format.ty || format != c.format.format);
        let (tex, cw, ch, old_image) = (c.tex, c.width, c.height, c.image);
        let mut new = c.format;
        if reformat {
            new = gl::color_buffer_format(format).unwrap_or_else(|| {
                eprintln!("[gex] gfxstream: a color buffer reformatted to an unknown format {format:#x}");
                Format { internal: format, format, ty, bytes: 4 }
            });
            new.ty = ty;
        }
        let image = self.with_root(|f| unsafe {
            let mut image = old_image;
            let bound = int(f, gl::GL_TEXTURE_BINDING_2D);
            if reformat {
                (f.glBindTexture)(gl::GL_TEXTURE_2D, tex);
                (f.glTexImage2D)(gl::GL_TEXTURE_2D, 0, format as i32, cw as i32, ch as i32, 0, new.format, new.ty, std::ptr::null());
                destroy_image(display, old_image);
                image = texture_image(display, root, tex);
            }
            let unpack = int(f, gl::GL_UNPACK_ALIGNMENT);
            (f.glBindTexture)(gl::GL_TEXTURE_2D, tex);
            (f.glPixelStorei)(gl::GL_UNPACK_ALIGNMENT, 1);
            (f.glTexSubImage2D)(gl::GL_TEXTURE_2D, 0, x, y, width, height, gl::unsized_format(format), ty, pixels.as_ptr().cast());
            (f.glPixelStorei)(gl::GL_UNPACK_ALIGNMENT, unpack);
            (f.glBindTexture)(gl::GL_TEXTURE_2D, bound as u32);
            (f.glFlush)();
            image
        });
        let c = self.objects.color_buffers.get_mut(&handle).unwrap();
        c.format_checked = true;
        if reformat {
            c.format = new;
            if let Some(i) = image {
                c.image = i;
            }
        }
    }

    /// `rcReadColorBuffer`: a rectangle of it, `len` bytes (what the guest's
    /// buffer holds).
    pub fn read_color_buffer(&mut self, handle: u32, x: i32, y: i32, width: i32, height: i32, format: u32, ty: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let Some(c) = self.objects.color_buffers.get(&handle) else {
            eprintln!("[gex] gfxstream: rcReadColorBuffer: no color buffer {handle}");
            return out;
        };
        let (tex, mut fbo) = (c.tex, c.fbo);
        let format = gl::unsized_format(format);
        let (w, h) = (width.max(0) as usize, height.max(0) as usize);
        self.with_root(|f| unsafe {
            if fbo == 0 {
                (f.glGenFramebuffers)(1, &mut fbo);
            }
            let bound = int(f, gl::GL_FRAMEBUFFER_BINDING);
            (f.glBindFramebuffer)(gl::GL_FRAMEBUFFER, fbo);
            (f.glFramebufferTexture2D)(gl::GL_FRAMEBUFFER, gl::GL_COLOR_ATTACHMENT0, gl::GL_TEXTURE_2D, tex, 0);
            let pack = int(f, gl::GL_PACK_ALIGNMENT);
            (f.glPixelStorei)(gl::GL_PACK_ALIGNMENT, 1);
            if format == gl::GL_RGB && ty == gl::GL_UNSIGNED_BYTE {
                // Read as RGBA and dropped to RGB (`convertRgbaToRgbPixels`).
                let mut rgba = vec![0u8; w * h * 4];
                (f.glReadPixels)(x, y, width, height, gl::GL_RGBA, ty, rgba.as_mut_ptr().cast());
                for (i, px) in rgba.chunks_exact(4).enumerate() {
                    if let Some(d) = out.get_mut(i * 3..i * 3 + 3) {
                        d.copy_from_slice(&px[..3]);
                    }
                }
            } else {
                let need = w * h * pixel_bytes(format, ty) as usize;
                let mut buf = vec![0u8; need.max(len)];
                (f.glReadPixels)(x, y, width, height, format, ty, buf.as_mut_ptr().cast());
                out.copy_from_slice(&buf[..len]);
            }
            (f.glPixelStorei)(gl::GL_PACK_ALIGNMENT, pack);
            (f.glBindFramebuffer)(gl::GL_FRAMEBUFFER, bound as u32);
        });
        if let Some(c) = self.objects.color_buffers.get_mut(&handle) {
            c.fbo = fbo;
        }
        out
    }

    /// `rcBindTexture` and `rcBindRenderbuffer`: the color buffer as the
    /// current context's bound 2D texture or renderbuffer.
    pub fn bind_color_buffer(&self, handle: u32, renderbuffer: bool) {
        let Some(c) = self.objects.color_buffers.get(&handle) else {
            eprintln!("[gex] gfxstream: binding color buffer {handle}, which is not there");
            return;
        };
        if c.image.is_null() || unsafe { eglGetCurrentContext() }.is_null() {
            return;
        }
        let f = self.fns();
        unsafe {
            if renderbuffer {
                (f.glEGLImageTargetRenderbufferStorageOES)(gl::GL_RENDERBUFFER, c.image);
            } else {
                (f.glEGLImageTargetTexture2DOES)(gl::GL_TEXTURE_2D, c.image);
            }
        }
    }

    /// `rcCreateClientImage`: an image of an object of a guest context's
    /// (`EGL_GL_TEXTURE_2D_KHR`: a texture by name), or of none; 0 if the
    /// host's EGL makes none.
    pub fn create_image(&mut self, context: u32, target: u32, buffer: u32, owner: Owner) -> u32 {
        let ctx = if context != 0 {
            match self.objects.contexts.get(&context) {
                Some(c) => c.egl,
                None => {
                    eprintln!("[gex] gfxstream: rcCreateClientImage: no context {context}");
                    return 0;
                }
            }
        } else {
            std::ptr::null_mut()
        };
        let egl = create_image(self.display, ctx, target, buffer as usize as *mut _);
        if egl.is_null() {
            eprintln!("[gex] gfxstream: rcCreateClientImage: the host made no image: {:#x}", unsafe { eglGetError() });
            return 0;
        }
        let o = &mut self.objects;
        loop {
            o.next_image = o.next_image.wrapping_add(1);
            if o.next_image != 0 && !o.images.contains_key(&o.next_image) {
                break;
            }
        }
        o.images.insert(o.next_image, Image { egl, owner });
        o.next_image
    }

    /// `rcDestroyClientImage`: whether there was one to destroy.
    pub fn destroy_image(&mut self, handle: u32) -> bool {
        match self.objects.images.remove(&handle) {
            Some(i) => destroy_image(self.display, i.egl),
            None => {
                eprintln!("[gex] gfxstream: rcDestroyClientImage: no image {handle}");
                false
            }
        }
    }

    /// The host image of a handle, or null.
    pub fn image(&self, handle: u32) -> EGLImage {
        self.objects.images.get(&handle).map(|i| i.egl).unwrap_or(std::ptr::null_mut())
    }

    /// What a render thread or a guest process made, let go when it ends
    /// (`cleanupProcGLObjects`, a render thread's context and window sets).
    pub fn ended(&mut self, owner: Owner) {
        let images: Vec<u32> = self.objects.images.iter().filter(|(_, i)| i.owner == owner).map(|(h, _)| *h).collect();
        for h in images {
            self.destroy_image(h);
        }
        let contexts: Vec<u32> = self.objects.contexts.iter().filter(|(_, c)| c.owner == owner).map(|(h, _)| *h).collect();
        let windows: Vec<u32> = self.objects.windows.iter().filter(|(_, w)| w.owner == owner).map(|(h, _)| *h).collect();
        for h in windows {
            self.destroy_window(h);
        }
        for h in contexts {
            self.destroy_context(h);
        }
    }
}

/// `ColorBufferGl::blitFromCurrentReadBuffer`: the current read buffer into
/// the color buffer, with the context current that drew it, through a
/// texture of that context's made from the color buffer's EGL image, the
/// context's bindings left as they were. A multisampled buffer is resolved
/// by a blit (OpenGL ES 3).
fn blit_from_read_buffer(f: &Fns, cb: &ColorBuffer, es3: bool) {
    if cb.image.is_null() {
        return;
    }
    unsafe {
        let tex = int(f, gl::GL_TEXTURE_BINDING_2D);
        let mut tmp = 0;
        (f.glGenTextures)(1, &mut tmp);
        (f.glBindTexture)(gl::GL_TEXTURE_2D, tmp);
        (f.glEGLImageTargetTexture2DOES)(gl::GL_TEXTURE_2D, cb.image);
        let read_binding = if es3 { gl::GL_READ_FRAMEBUFFER_BINDING } else { gl::GL_FRAMEBUFFER_BINDING };
        let read_target = if es3 { gl::GL_READ_FRAMEBUFFER } else { gl::GL_FRAMEBUFFER };
        let read = int(f, read_binding);
        if read != 0 {
            (f.glBindFramebuffer)(read_target, 0);
        }
        let samples = int(f, gl::GL_SAMPLE_BUFFERS);
        let (w, h) = (cb.width as i32, cb.height as i32);
        if es3 && samples > 0 {
            let mut fbo = 0;
            (f.glGenFramebuffers)(1, &mut fbo);
            let draw = int(f, gl::GL_DRAW_FRAMEBUFFER_BINDING);
            (f.glBindFramebuffer)(gl::GL_DRAW_FRAMEBUFFER, fbo);
            (f.glFramebufferTexture2D)(gl::GL_DRAW_FRAMEBUFFER, gl::GL_COLOR_ATTACHMENT0, gl::GL_TEXTURE_2D, tmp, 0);
            (f.glBlitFramebuffer)(0, 0, w, h, 0, 0, w, h, gl::GL_COLOR_BUFFER_BIT, gl::GL_NEAREST);
            (f.glBindFramebuffer)(gl::GL_DRAW_FRAMEBUFFER, draw as u32);
            (f.glDeleteFramebuffers)(1, &fbo);
        } else {
            (f.glCopyTexSubImage2D)(gl::GL_TEXTURE_2D, 0, 0, 0, 0, 0, w, h);
        }
        if read != 0 {
            (f.glBindFramebuffer)(read_target, read as u32);
        }
        (f.glDeleteTextures)(1, &tmp);
        (f.glBindTexture)(gl::GL_TEXTURE_2D, tex as u32);
        // Other contexts read the texture next.
        (f.glFlush)();
        // A read buffer whose format the texture's does not match leaves an
        // error the guest must not see.
        (f.glGetError)();
    }
}
