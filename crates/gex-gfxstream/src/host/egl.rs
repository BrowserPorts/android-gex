//! The host's EGL, as the renderer uses it: a surfaceless display, configs,
//! contexts sharing one root, and pbuffer surfaces. The same Mesa EGL that
//! `gex-gl` links (Homebrew's on macOS, the system's on Linux).

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::{c_char, c_void, CString};

pub type EGLDisplay = *mut c_void;
pub type EGLConfig = *mut c_void;
pub type EGLContext = *mut c_void;
pub type EGLSurface = *mut c_void;
pub type EGLint = i32;
pub type EGLenum = u32;
pub type EGLBoolean = u32;
pub type EGLImage = *mut c_void;

pub const EGL_NONE: EGLint = 0x3038;
pub const EGL_TRUE: EGLBoolean = 1;
pub const EGL_DONT_CARE: EGLint = -1;
pub const EGL_SUCCESS: EGLint = 0x3000;

pub const EGL_BUFFER_SIZE: EGLint = 0x3020;
pub const EGL_ALPHA_SIZE: EGLint = 0x3021;
pub const EGL_BLUE_SIZE: EGLint = 0x3022;
pub const EGL_GREEN_SIZE: EGLint = 0x3023;
pub const EGL_RED_SIZE: EGLint = 0x3024;
pub const EGL_DEPTH_SIZE: EGLint = 0x3025;
pub const EGL_STENCIL_SIZE: EGLint = 0x3026;
pub const EGL_CONFIG_CAVEAT: EGLint = 0x3027;
pub const EGL_CONFIG_ID: EGLint = 0x3028;
pub const EGL_LEVEL: EGLint = 0x3029;
pub const EGL_MAX_PBUFFER_HEIGHT: EGLint = 0x302A;
pub const EGL_MAX_PBUFFER_PIXELS: EGLint = 0x302B;
pub const EGL_MAX_PBUFFER_WIDTH: EGLint = 0x302C;
pub const EGL_NATIVE_RENDERABLE: EGLint = 0x302D;
pub const EGL_NATIVE_VISUAL_ID: EGLint = 0x302E;
pub const EGL_NATIVE_VISUAL_TYPE: EGLint = 0x302F;
pub const EGL_PRESERVED_RESOURCES: EGLint = 0x3030;
pub const EGL_SAMPLES: EGLint = 0x3031;
pub const EGL_SAMPLE_BUFFERS: EGLint = 0x3032;
pub const EGL_SURFACE_TYPE: EGLint = 0x3033;
pub const EGL_TRANSPARENT_TYPE: EGLint = 0x3034;
pub const EGL_TRANSPARENT_BLUE_VALUE: EGLint = 0x3035;
pub const EGL_TRANSPARENT_GREEN_VALUE: EGLint = 0x3036;
pub const EGL_TRANSPARENT_RED_VALUE: EGLint = 0x3037;
pub const EGL_BIND_TO_TEXTURE_RGB: EGLint = 0x3039;
pub const EGL_BIND_TO_TEXTURE_RGBA: EGLint = 0x303A;
pub const EGL_MIN_SWAP_INTERVAL: EGLint = 0x303B;
pub const EGL_MAX_SWAP_INTERVAL: EGLint = 0x303C;
pub const EGL_LUMINANCE_SIZE: EGLint = 0x303D;
pub const EGL_ALPHA_MASK_SIZE: EGLint = 0x303E;
pub const EGL_COLOR_BUFFER_TYPE: EGLint = 0x303F;
pub const EGL_RENDERABLE_TYPE: EGLint = 0x3040;
pub const EGL_CONFORMANT: EGLint = 0x3042;
pub const EGL_RECORDABLE_ANDROID: EGLint = 0x3142;

pub const EGL_PBUFFER_BIT: EGLint = 0x0001;
pub const EGL_WINDOW_BIT: EGLint = 0x0004;
pub const EGL_SWAP_BEHAVIOR_PRESERVED_BIT: EGLint = 0x0400;
pub const EGL_OPENGL_ES2_BIT: EGLint = 0x0004;
pub const EGL_OPENGL_ES3_BIT: EGLint = 0x0040;

pub const EGL_WIDTH: EGLint = 0x3057;
pub const EGL_HEIGHT: EGLint = 0x3056;
pub const EGL_CONTEXT_CLIENT_VERSION: EGLint = 0x3098;
pub const EGL_CONTEXT_MINOR_VERSION: EGLint = 0x30FB;
pub const EGL_OPENGL_ES_API: EGLenum = 0x30A0;
pub const EGL_VENDOR: EGLenum = 0x3053;
pub const EGL_VERSION: EGLenum = 0x3054;
pub const EGL_EXTENSIONS: EGLenum = 0x3055;
pub const EGL_PLATFORM_SURFACELESS_MESA: EGLenum = 0x31DD;
pub const EGL_DRAW: EGLint = 0x3059;
pub const EGL_READ: EGLint = 0x305A;
pub const EGL_GL_TEXTURE_2D_KHR: EGLenum = 0x30B1;

#[link(name = "EGL")]
extern "C" {
    pub fn eglGetProcAddress(name: *const c_char) -> *mut c_void;
    pub fn eglInitialize(dpy: EGLDisplay, major: *mut EGLint, minor: *mut EGLint) -> EGLBoolean;
    pub fn eglBindAPI(api: EGLenum) -> EGLBoolean;
    pub fn eglGetConfigs(dpy: EGLDisplay, configs: *mut EGLConfig, size: EGLint, num: *mut EGLint) -> EGLBoolean;
    pub fn eglChooseConfig(dpy: EGLDisplay, attrs: *const EGLint, configs: *mut EGLConfig, size: EGLint, num: *mut EGLint) -> EGLBoolean;
    pub fn eglGetConfigAttrib(dpy: EGLDisplay, config: EGLConfig, attr: EGLint, value: *mut EGLint) -> EGLBoolean;
    pub fn eglCreateContext(dpy: EGLDisplay, config: EGLConfig, share: EGLContext, attrs: *const EGLint) -> EGLContext;
    pub fn eglDestroyContext(dpy: EGLDisplay, ctx: EGLContext) -> EGLBoolean;
    pub fn eglCreatePbufferSurface(dpy: EGLDisplay, config: EGLConfig, attrs: *const EGLint) -> EGLSurface;
    pub fn eglDestroySurface(dpy: EGLDisplay, surface: EGLSurface) -> EGLBoolean;
    pub fn eglMakeCurrent(dpy: EGLDisplay, draw: EGLSurface, read: EGLSurface, ctx: EGLContext) -> EGLBoolean;
    pub fn eglQueryString(dpy: EGLDisplay, name: EGLint) -> *const c_char;
    pub fn eglGetError() -> EGLint;
    pub fn eglGetCurrentContext() -> EGLContext;
    pub fn eglGetCurrentSurface(which: EGLint) -> EGLSurface;
}

/// What is current on the calling thread, to be put back.
pub struct Binding {
    display: EGLDisplay,
    context: EGLContext,
    draw: EGLSurface,
    read: EGLSurface,
}

impl Binding {
    pub fn current(display: EGLDisplay) -> Binding {
        unsafe { Binding { display, context: eglGetCurrentContext(), draw: eglGetCurrentSurface(EGL_DRAW), read: eglGetCurrentSurface(EGL_READ) } }
    }

    pub fn is(&self, context: EGLContext, draw: EGLSurface, read: EGLSurface) -> bool {
        self.context == context && self.draw == draw && self.read == read
    }

    pub fn context(&self) -> EGLContext {
        self.context
    }

    /// Makes it current again.
    pub fn restore(&self) -> bool {
        unsafe { eglMakeCurrent(self.display, self.draw, self.read, self.context) == EGL_TRUE }
    }
}

type CreateImage = unsafe extern "C" fn(EGLDisplay, EGLContext, EGLenum, *mut c_void, *const EGLint) -> EGLImage;
type DestroyImage = unsafe extern "C" fn(EGLDisplay, EGLImage) -> EGLBoolean;

/// An image of a texture of `context`'s (`EGL_KHR_gl_texture_2D_image`).
pub fn texture_image(display: EGLDisplay, context: EGLContext, texture: u32) -> EGLImage {
    create_image(display, context, EGL_GL_TEXTURE_2D_KHR, texture as usize as *mut c_void)
}

pub type EGLSync = *mut c_void;
pub const EGL_SYNC_FENCE_KHR: EGLenum = 0x30F9;
pub const EGL_SYNC_STATUS_KHR: EGLint = 0x30F1;
pub const EGL_SIGNALED_KHR: EGLint = 0x30F2;
pub const EGL_CONDITION_SATISFIED_KHR: EGLint = 0x30F6;
pub const EGL_SYNC_FLUSH_COMMANDS_BIT_KHR: EGLint = 0x0001;
pub const EGL_FOREVER_KHR: u64 = u64::MAX;

/// `EGL_KHR_fence_sync` and `EGL_KHR_wait_sync`, found once.
pub struct SyncFns {
    pub create: unsafe extern "C" fn(EGLDisplay, EGLenum, *const EGLint) -> EGLSync,
    pub destroy: unsafe extern "C" fn(EGLDisplay, EGLSync) -> EGLBoolean,
    pub client_wait: unsafe extern "C" fn(EGLDisplay, EGLSync, EGLint, u64) -> EGLint,
    pub wait: unsafe extern "C" fn(EGLDisplay, EGLSync, EGLint) -> EGLint,
    pub get_attrib: unsafe extern "C" fn(EGLDisplay, EGLSync, EGLint, *mut EGLint) -> EGLBoolean,
}

pub fn sync_fns() -> Option<&'static SyncFns> {
    static F: std::sync::OnceLock<Option<SyncFns>> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let p = |n: &str| {
            let a = proc_address(n);
            (!a.is_null()).then_some(a)
        };
        unsafe {
            Some(SyncFns {
                create: std::mem::transmute(p("eglCreateSyncKHR")?),
                destroy: std::mem::transmute(p("eglDestroySyncKHR")?),
                client_wait: std::mem::transmute(p("eglClientWaitSyncKHR")?),
                wait: std::mem::transmute(p("eglWaitSyncKHR")?),
                get_attrib: std::mem::transmute(p("eglGetSyncAttribKHR")?),
            })
        }
    })
    .as_ref()
}

/// `eglCreateImageKHR` with no attributes.
pub fn create_image(display: EGLDisplay, context: EGLContext, target: EGLenum, buffer: *mut c_void) -> EGLImage {
    let p = proc_address("eglCreateImageKHR");
    if p.is_null() {
        return std::ptr::null_mut();
    }
    let f: CreateImage = unsafe { std::mem::transmute(p) };
    unsafe { f(display, context, target, buffer, std::ptr::null()) }
}

pub fn destroy_image(display: EGLDisplay, image: EGLImage) -> bool {
    let p = proc_address("eglDestroyImageKHR");
    if p.is_null() || image.is_null() {
        return false;
    }
    let f: DestroyImage = unsafe { std::mem::transmute(p) };
    unsafe { f(display, image) == EGL_TRUE }
}

/// An entry point by name, or null.
pub fn proc_address(name: &str) -> *mut c_void {
    let n = CString::new(name).unwrap();
    unsafe { eglGetProcAddress(n.as_ptr()) }
}

/// A C string the driver owns, as Rust's.
pub unsafe fn string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned())
}

/// The surfaceless display, initialised: its version.
pub fn display() -> Result<(EGLDisplay, EGLint, EGLint), String> {
    type GetPlatformDisplay = unsafe extern "C" fn(EGLenum, *mut c_void, *const EGLint) -> EGLDisplay;
    let p = proc_address("eglGetPlatformDisplayEXT");
    if p.is_null() {
        return Err("no eglGetPlatformDisplayEXT".into());
    }
    let get: GetPlatformDisplay = unsafe { std::mem::transmute(p) };
    let dpy = unsafe { get(EGL_PLATFORM_SURFACELESS_MESA, std::ptr::null_mut(), std::ptr::null()) };
    if dpy.is_null() {
        return Err("no EGL display".into());
    }
    let (mut major, mut minor) = (0, 0);
    if unsafe { eglInitialize(dpy, &mut major, &mut minor) } != EGL_TRUE {
        return Err(format!("eglInitialize: {:#x}", unsafe { eglGetError() }));
    }
    unsafe { eglBindAPI(EGL_OPENGL_ES_API) };
    Ok((dpy, major, minor))
}
