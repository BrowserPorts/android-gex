//! The EGL configs the guest sees (gfxstream's `EmulatedEglConfigList`):
//! the translator's ([`super::translator`]) that can make a pbuffer and have
//! colour, numbered from 0 in the translator's order, each described by the same 34 attributes, with a window
//! surface always among its types (the guest's windows are the host's
//! pbuffers) and OpenGL ES 3 among its APIs only when the host offers the
//! guest a version past 2 (`GlesDynamicVersion`).

use super::egl::*;
use super::translator::{host_infos, Display, TConfig};

/// The attributes, in the order the guest reads them (the first five are
/// read by place: depth, stencil, renderable type, surface type, id).
pub const ATTRIBUTES: [EGLint; 34] = [
    EGL_DEPTH_SIZE,
    EGL_STENCIL_SIZE,
    EGL_RENDERABLE_TYPE,
    EGL_SURFACE_TYPE,
    EGL_CONFIG_ID,
    EGL_BUFFER_SIZE,
    EGL_ALPHA_SIZE,
    EGL_BLUE_SIZE,
    EGL_GREEN_SIZE,
    EGL_RED_SIZE,
    EGL_CONFIG_CAVEAT,
    EGL_LEVEL,
    EGL_MAX_PBUFFER_HEIGHT,
    EGL_MAX_PBUFFER_PIXELS,
    EGL_MAX_PBUFFER_WIDTH,
    EGL_NATIVE_RENDERABLE,
    EGL_NATIVE_VISUAL_ID,
    EGL_NATIVE_VISUAL_TYPE,
    EGL_PRESERVED_RESOURCES,
    EGL_SAMPLES,
    EGL_SAMPLE_BUFFERS,
    EGL_TRANSPARENT_TYPE,
    EGL_TRANSPARENT_BLUE_VALUE,
    EGL_TRANSPARENT_GREEN_VALUE,
    EGL_TRANSPARENT_RED_VALUE,
    EGL_BIND_TO_TEXTURE_RGB,
    EGL_BIND_TO_TEXTURE_RGBA,
    EGL_MIN_SWAP_INTERVAL,
    EGL_MAX_SWAP_INTERVAL,
    EGL_LUMINANCE_SIZE,
    EGL_ALPHA_MASK_SIZE,
    EGL_COLOR_BUFFER_TYPE,
    EGL_RECORDABLE_ANDROID,
    EGL_CONFORMANT,
];

pub struct Config {
    pub host: EGLConfig,
    pub values: [EGLint; ATTRIBUTES.len()],
}

impl Config {
    pub fn id(&self) -> EGLint {
        self.values[4]
    }
}

pub struct Configs {
    /// The translator's configs, which these are drawn from.
    translator: Display,
    pub list: Vec<Config>,
    /// Whether the guest may have OpenGL ES 3.
    es3: bool,
}

/// `isCompatibleHostConfig`: a pbuffer, and some red, green and blue.
fn compatible(c: &TConfig) -> bool {
    let a = |x| c.attrib(x).unwrap_or(0);
    a(EGL_SURFACE_TYPE) & EGL_PBUFFER_BIT != 0 && a(EGL_RED_SIZE) != 0 && a(EGL_GREEN_SIZE) != 0 && a(EGL_BLUE_SIZE) != 0
}

impl Configs {
    pub fn new(display: EGLDisplay, es3: bool) -> Configs {
        let translator = Display::new(&host_infos(display));
        let list = translator
            .configs
            .iter()
            .filter(|c| compatible(c))
            .map(|c| {
                let mut values = [0; ATTRIBUTES.len()];
                for (v, &a) in values.iter_mut().zip(ATTRIBUTES.iter()) {
                    *v = c.attrib(a).unwrap_or(0);
                    if a == EGL_SURFACE_TYPE {
                        *v |= EGL_WINDOW_BIT;
                    }
                    if a == EGL_RENDERABLE_TYPE && !es3 {
                        *v &= !EGL_OPENGL_ES3_BIT;
                    }
                }
                Config { host: c.host, values }
            })
            .collect();
        Configs { translator, list, es3 }
    }

    /// `packConfigs`: the attribute ids, then each config's values, as
    /// `u32`s; the count, or minus the bytes it needs if `size` is short.
    pub fn pack(&self, size: u32) -> (i32, Vec<u8>) {
        let need = (self.list.len() + 1) * ATTRIBUTES.len() * 4;
        if (size as usize) < need {
            return (-(need as i32), Vec::new());
        }
        let mut b = Vec::with_capacity(need);
        for a in ATTRIBUTES {
            b.extend_from_slice(&a.to_le_bytes());
        }
        for c in &self.list {
            for v in c.values {
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        (self.list.len() as i32, b)
    }

    /// `chooseConfig`: the guest's attributes (pairs, to `EGL_NONE`), with a
    /// surface type of 0 added when it names none, chosen by the
    /// translator; the guest's numbers of its matches, at most `max` of
    /// them (none asked for: all counted), or minus the translator's error.
    /// ES3 asked of a host that offers only 2: none.
    pub fn choose(&self, attribs: &[EGLint], max: usize, want_list: bool) -> (i32, Vec<u32>) {
        let mut a = Vec::new();
        let mut has_surface_type = false;
        for pair in attribs.chunks(2) {
            if pair[0] == EGL_NONE || pair.len() < 2 {
                break;
            }
            if pair[0] == EGL_SURFACE_TYPE {
                has_surface_type = true;
            }
            if pair[0] == EGL_RENDERABLE_TYPE && pair[1] != EGL_DONT_CARE && pair[1] & EGL_OPENGL_ES3_BIT != 0 && !self.es3 {
                return (0, Vec::new());
            }
            a.extend_from_slice(pair);
        }
        if !has_surface_type {
            a.extend_from_slice(&[EGL_SURFACE_TYPE, 0]);
        }
        a.push(EGL_NONE);
        let matched = match self.translator.choose(&a) {
            Ok(m) => m,
            Err(e) => return (-e, Vec::new()),
        };
        let mut out = Vec::new();
        let mut count = 0;
        for t in matched {
            if want_list && max > 0 && count >= max {
                break;
            }
            let c = &self.translator.configs[t];
            if !compatible(c) {
                continue;
            }
            if let Some(i) = self.list.iter().position(|x| x.id() == c.id()) {
                if want_list && out.len() < max {
                    out.push(i as u32);
                }
                count += 1;
            }
        }
        (count as i32, out)
    }
}
