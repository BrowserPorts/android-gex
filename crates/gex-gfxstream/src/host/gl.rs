//! The OpenGL ES entry points the renderer itself calls (not the guest's:
//! those are the decoders'), found through `eglGetProcAddress` once.

#![allow(non_snake_case, dead_code)]

use std::ffi::c_void;
use std::sync::OnceLock;

pub const GL_TEXTURE_2D: u32 = 0x0DE1;
pub const GL_TEXTURE_BINDING_2D: u32 = 0x8069;
pub const GL_FRAMEBUFFER: u32 = 0x8D40;
pub const GL_FRAMEBUFFER_BINDING: u32 = 0x8CA6;
pub const GL_COLOR_ATTACHMENT0: u32 = 0x8CE0;
pub const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
pub const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
pub const GL_TEXTURE_WRAP_S: u32 = 0x2802;
pub const GL_TEXTURE_WRAP_T: u32 = 0x2803;
pub const GL_LINEAR: i32 = 0x2601;
pub const GL_CLAMP_TO_EDGE: i32 = 0x812F;
pub const GL_UNPACK_ALIGNMENT: u32 = 0x0CF5;
pub const GL_PACK_ALIGNMENT: u32 = 0x0D05;
pub const GL_RENDERBUFFER: u32 = 0x8D41;
pub const GL_READ_FRAMEBUFFER: u32 = 0x8CA8;
pub const GL_DRAW_FRAMEBUFFER: u32 = 0x8CA9;
pub const GL_READ_FRAMEBUFFER_BINDING: u32 = 0x8CAA;
pub const GL_DRAW_FRAMEBUFFER_BINDING: u32 = 0x8CA6;
pub const GL_SAMPLE_BUFFERS: u32 = 0x80A8;
pub const GL_COLOR_BUFFER_BIT: u32 = 0x4000;
pub const GL_NEAREST: u32 = 0x2600;

pub const GL_RGBA: u32 = 0x1908;
pub const GL_RGB: u32 = 0x1907;
pub const GL_ALPHA: u32 = 0x1906;
pub const GL_LUMINANCE: u32 = 0x1909;
pub const GL_RED: u32 = 0x1903;
pub const GL_RG: u32 = 0x8227;
pub const GL_BGRA_EXT: u32 = 0x80E1;
pub const GL_UNSIGNED_BYTE: u32 = 0x1401;
pub const GL_UNSIGNED_SHORT_5_6_5: u32 = 0x8363;
pub const GL_HALF_FLOAT: u32 = 0x140B;
pub const GL_UNSIGNED_INT_2_10_10_10_REV: u32 = 0x8368;
pub const GL_RGB565: u32 = 0x8D62;
pub const GL_RGB8: u32 = 0x8051;
pub const GL_RGBA8: u32 = 0x8058;
pub const GL_RGBA16F: u32 = 0x881A;
pub const GL_RGB10_A2: u32 = 0x8059;
pub const GL_R8: u32 = 0x8229;
pub const GL_RG8: u32 = 0x822B;
pub const GL_BLUE: u32 = 0x1905;
pub const GL_LUMINANCE_ALPHA: u32 = 0x190A;
pub const GL_UNSIGNED_SHORT_4_4_4_4: u32 = 0x8033;
pub const GL_UNSIGNED_SHORT_5_5_5_1: u32 = 0x8034;
pub const GL_TEXTURE_SWIZZLE_R: u32 = 0x8E42;
pub const GL_TEXTURE_SWIZZLE_B: u32 = 0x8E44;
pub const GL_UNSIGNED_SHORT: u32 = 0x1403;
pub const GL_UNSIGNED_INT: u32 = 0x1405;
pub const GL_FLOAT: u32 = 0x1406;
pub const GL_RGB16F: u32 = 0x881B;
pub const GL_RGBA4_OES: u32 = 0x8056;
pub const GL_RGB5_A1_OES: u32 = 0x8057;
pub const GL_UNSIGNED_INT_10_10_10_2_OES: u32 = 0x8DF6;
pub const GL_BGRA8_EXT: u32 = 0x93A1;
pub const GL_BGR10_A2_ANGLEX: u32 = 0x6AF9;
pub const GL_DEPTH_COMPONENT: u32 = 0x1902;
pub const GL_DEPTH_COMPONENT16: u32 = 0x81A5;
pub const GL_DEPTH_COMPONENT24: u32 = 0x81A6;
pub const GL_DEPTH_COMPONENT32F: u32 = 0x8CAC;
pub const GL_DEPTH_STENCIL: u32 = 0x84F9;
pub const GL_DEPTH24_STENCIL8: u32 = 0x88F0;
pub const GL_DEPTH32F_STENCIL8: u32 = 0x8CAD;
pub const GL_UNSIGNED_INT_24_8: u32 = 0x84FA;
pub const GL_FLOAT_32_UNSIGNED_INT_24_8_REV: u32 = 0x8DAD;

pub struct Fns {
    pub glGenTextures: unsafe extern "C" fn(i32, *mut u32),
    pub glDeleteTextures: unsafe extern "C" fn(i32, *const u32),
    pub glBindTexture: unsafe extern "C" fn(u32, u32),
    pub glTexParameteri: unsafe extern "C" fn(u32, u32, i32),
    pub glTexImage2D: unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void),
    pub glTexSubImage2D: unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void),
    pub glCopyTexSubImage2D: unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, i32, i32),
    pub glGenFramebuffers: unsafe extern "C" fn(i32, *mut u32),
    pub glDeleteFramebuffers: unsafe extern "C" fn(i32, *const u32),
    pub glBindFramebuffer: unsafe extern "C" fn(u32, u32),
    pub glFramebufferTexture2D: unsafe extern "C" fn(u32, u32, u32, u32, i32),
    pub glReadPixels: unsafe extern "C" fn(i32, i32, i32, i32, u32, u32, *mut c_void),
    pub glPixelStorei: unsafe extern "C" fn(u32, i32),
    pub glGetIntegerv: unsafe extern "C" fn(u32, *mut i32),
    pub glFinish: unsafe extern "C" fn(),
    pub glFlush: unsafe extern "C" fn(),
    pub glEGLImageTargetTexture2DOES: unsafe extern "C" fn(u32, *mut c_void),
    pub glEGLImageTargetRenderbufferStorageOES: unsafe extern "C" fn(u32, *mut c_void),
    pub glBlitFramebuffer: unsafe extern "C" fn(i32, i32, i32, i32, i32, i32, i32, i32, u32, u32),
    pub glGetError: unsafe extern "C" fn() -> u32,
}

/// The entry points, or the first one the host lacks.
pub fn fns() -> Result<&'static Fns, String> {
    static FNS: OnceLock<Result<Fns, String>> = OnceLock::new();
    FNS.get_or_init(|| {
        macro_rules! load {
            ($($name:ident),* $(,)?) => {
                Fns { $($name: {
                    let p = super::egl::proc_address(stringify!($name));
                    if p.is_null() {
                        return Err(format!("the host has no {}", stringify!($name)));
                    }
                    unsafe { std::mem::transmute::<*mut c_void, _>(p) }
                }),* }
            };
        }
        Ok(load!(
            glGenTextures,
            glDeleteTextures,
            glBindTexture,
            glTexParameteri,
            glTexImage2D,
            glTexSubImage2D,
            glCopyTexSubImage2D,
            glGenFramebuffers,
            glDeleteFramebuffers,
            glBindFramebuffer,
            glFramebufferTexture2D,
            glReadPixels,
            glPixelStorei,
            glGetIntegerv,
            glFinish,
            glFlush,
            glEGLImageTargetTexture2DOES,
            glEGLImageTargetRenderbufferStorageOES,
            glBlitFramebuffer,
            glGetError,
        ))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// How a color buffer of an internal format is kept (`sGetFormatParameters`):
/// the internal format given to `glTexImage2D` (as asked, but for the one
/// gfxstream rewrites), the format and type of its pixels, and their size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub internal: u32,
    pub format: u32,
    pub ty: u32,
    pub bytes: u32,
}

pub fn color_buffer_format(internal: u32) -> Option<Format> {
    let f = |format, ty, bytes| Some(Format { internal, format, ty, bytes });
    match internal {
        GL_RGB | GL_RGB8 => f(GL_RGB, GL_UNSIGNED_BYTE, 3),
        GL_RGB565 => f(GL_RGB, GL_UNSIGNED_SHORT_5_6_5, 2),
        GL_RGBA | GL_RGBA8 | GL_RGB5_A1_OES | GL_RGBA4_OES => f(GL_RGBA, GL_UNSIGNED_BYTE, 4),
        GL_UNSIGNED_INT_10_10_10_2_OES => f(GL_RGBA, GL_UNSIGNED_SHORT, 4),
        GL_RGB10_A2 => f(GL_RGBA, GL_UNSIGNED_INT_2_10_10_10_REV, 4),
        GL_RGB16F => f(GL_RGB, GL_HALF_FLOAT, 6),
        GL_RGBA16F => f(GL_RGBA, GL_HALF_FLOAT, 8),
        GL_LUMINANCE => f(GL_LUMINANCE, GL_UNSIGNED_BYTE, 1),
        GL_BGRA_EXT => f(GL_BGRA_EXT, GL_UNSIGNED_BYTE, 4),
        GL_BGR10_A2_ANGLEX => Some(Format { internal: GL_RGB10_A2, format: GL_RGBA, ty: GL_UNSIGNED_INT_2_10_10_10_REV, bytes: 4 }),
        GL_R8 | GL_RED => f(GL_RED, GL_UNSIGNED_BYTE, 1),
        GL_RG8 | GL_RG => f(GL_RG, GL_UNSIGNED_BYTE, 2),
        GL_DEPTH_COMPONENT | GL_DEPTH_COMPONENT16 => f(GL_DEPTH_COMPONENT, GL_UNSIGNED_SHORT, 2),
        GL_DEPTH_COMPONENT24 => f(GL_DEPTH_COMPONENT, GL_UNSIGNED_INT, 4),
        GL_DEPTH_COMPONENT32F => f(GL_DEPTH_COMPONENT, GL_FLOAT, 4),
        GL_DEPTH_STENCIL | GL_DEPTH24_STENCIL8 => f(GL_DEPTH_STENCIL, GL_UNSIGNED_INT_24_8, 4),
        GL_DEPTH32F_STENCIL8 => f(GL_DEPTH_STENCIL, GL_FLOAT_32_UNSIGNED_INT_24_8_REV, 8),
        _ => None,
    }
}

/// `sGetUnsizedColorBufferFormat`: the format a sized one is read and
/// written as.
pub fn unsized_format(format: u32) -> u32 {
    match format {
        GL_R8 => GL_RED,
        GL_RG8 => GL_RG,
        GL_RGB8 | GL_RGB565 | GL_RGB16F => GL_RGB,
        GL_RGBA8 | GL_RGB5_A1_OES | GL_RGBA4_OES | GL_UNSIGNED_INT_10_10_10_2_OES | GL_RGB10_A2 | GL_RGBA16F => GL_RGBA,
        GL_BGRA8_EXT | GL_BGR10_A2_ANGLEX => GL_BGRA_EXT,
        f => f,
    }
}
