//! The configs of gfxstream's EGL translator (`glestranslator/egl`:
//! `EglDisplay::initConfigurations`, `EglConfig`, `eglChooseConfig`), which
//! is the EGL `EmulatedEglConfigList` reads on the emulator's host, not the
//! host driver's own:
//!
//! - the host's configs that make pbuffers with OpenGL ES 3 and some red,
//!   green and blue (`EglOsEglDisplay::queryConfigs`), each taken with
//!   OpenGL ES 1 added to its APIs and never recordable, and kept only with
//!   at most 8 bits a colour, a depth of 24 or more, a stencil of 8 or more
//!   and at most 2 samples (`EglDisplay::addConfig`), once for each set of
//!   properties; numbered from 3 in the host's order;
//! - then two reserved configs, ids 1 and 2: the host config that best
//!   matches 8-8-8 (and then 8-8-8-8) with a depth of 16, taken again with
//!   those sizes (`addSimplePixelFormat`); only a config of 16 or 32 bits is
//!   a framebuffer target;
//! - all in `EglConfig`'s order (conformant first, caveat, buffer size,
//!   samples, depth, stencil, id);
//! - chosen as the translator's `eglChooseConfig` chooses (its defaults,
//!   its refusals, `EglConfig::chosen`, and the order the attributes asked
//!   for give).

use super::egl::*;

const EGL_SLOW_CONFIG: EGLint = 0x3050;
const EGL_NON_CONFORMANT_CONFIG: EGLint = 0x3051;
const EGL_TRANSPARENT_RGB: EGLint = 0x3052;
const EGL_MATCH_NATIVE_PIXMAP: EGLint = 0x3041;
const EGL_RGB_BUFFER: EGLint = 0x308E;
const EGL_LUMINANCE_BUFFER: EGLint = 0x308F;
const EGL_FRAMEBUFFER_TARGET_ANDROID: EGLint = 0x3147;
const EGL_OPENGL_ES_BIT: EGLint = 0x0001;
const EGL_FALSE: EGLint = 0;
const EGL_TRUE_I: EGLint = 1;
/// `EGL_BAD_ATTRIBUTE`.
pub const EGL_BAD_ATTRIBUTE: EGLint = 0x3004;
const MIN_SWAP_INTERVAL: EGLint = 1;
const MAX_SWAP_INTERVAL: EGLint = 10;

/// An `EglConfig`: its properties, and the host config it is drawn with.
#[derive(Clone, Debug)]
pub struct TConfig {
    pub host: EGLConfig,
    buffer_size: EGLint,
    red: EGLint,
    green: EGLint,
    blue: EGLint,
    alpha: EGLint,
    alpha_mask: EGLint,
    bind_rgb: EGLint,
    bind_rgba: EGLint,
    caveat: EGLint,
    id: EGLint,
    level: EGLint,
    depth: EGLint,
    max_pb_width: EGLint,
    max_pb_height: EGLint,
    max_pb_pixels: EGLint,
    max_swap: EGLint,
    min_swap: EGLint,
    native_renderable: EGLint,
    renderable: EGLint,
    native_visual_id: EGLint,
    native_visual_type: EGLint,
    sample_buffers: EGLint,
    samples: EGLint,
    stencil: EGLint,
    luminance: EGLint,
    wanted_buffer_size: EGLint,
    surface_type: EGLint,
    transparent_type: EGLint,
    trans_red: EGLint,
    trans_green: EGLint,
    trans_blue: EGLint,
    recordable: EGLint,
    framebuffer_target: EGLint,
    conformant: EGLint,
    color_buffer_type: EGLint,
    /// What the caller asked about (a choice's pattern only).
    wanted: Vec<EGLint>,
}

/// What the host says of one of its configs (`EglOS::ConfigInfo`).
#[derive(Clone, Copy, Debug, Default)]
pub struct HostInfo {
    pub red: EGLint,
    pub green: EGLint,
    pub blue: EGLint,
    pub alpha: EGLint,
    pub alpha_mask: EGLint,
    pub caveat: EGLint,
    pub depth: EGLint,
    pub level: EGLint,
    pub max_pb_width: EGLint,
    pub max_pb_height: EGLint,
    pub max_pb_pixels: EGLint,
    pub native_renderable: EGLint,
    pub renderable: EGLint,
    pub native_visual_id: EGLint,
    pub native_visual_type: EGLint,
    pub samples: EGLint,
    pub stencil: EGLint,
    pub surface_type: EGLint,
    pub transparent_type: EGLint,
    pub trans_red: EGLint,
    pub trans_green: EGLint,
    pub trans_blue: EGLint,
}

impl TConfig {
    /// The constructor `addConfig` and `addSimplePixelFormat` use: no
    /// luminance, no wanted buffer size, not a framebuffer target, sample
    /// buffers from the samples, conformant to its APIs when it has colour
    /// and is not marked otherwise.
    fn from_info(i: &HostInfo, recordable: EGLint, host: EGLConfig) -> TConfig {
        let colour = i.red + i.green + i.blue + i.alpha;
        TConfig {
            host,
            buffer_size: colour,
            red: i.red,
            green: i.green,
            blue: i.blue,
            alpha: i.alpha,
            alpha_mask: i.alpha_mask,
            bind_rgb: EGL_FALSE,
            bind_rgba: EGL_FALSE,
            caveat: i.caveat,
            id: EGL_DONT_CARE,
            level: i.level,
            depth: i.depth,
            max_pb_width: i.max_pb_width,
            max_pb_height: i.max_pb_height,
            max_pb_pixels: i.max_pb_pixels,
            max_swap: MAX_SWAP_INTERVAL,
            min_swap: MIN_SWAP_INTERVAL,
            native_renderable: i.native_renderable,
            renderable: i.renderable,
            native_visual_id: i.native_visual_id,
            native_visual_type: i.native_visual_type,
            sample_buffers: if i.samples > 0 { 1 } else { 0 },
            samples: i.samples,
            stencil: i.stencil,
            luminance: 0,
            wanted_buffer_size: EGL_DONT_CARE,
            surface_type: i.surface_type,
            transparent_type: i.transparent_type,
            trans_red: i.trans_red,
            trans_green: i.trans_green,
            trans_blue: i.trans_blue,
            recordable,
            framebuffer_target: EGL_FALSE,
            conformant: if colour > 0 && i.caveat != EGL_NON_CONFORMANT_CONFIG { i.renderable } else { 0 },
            color_buffer_type: EGL_RGB_BUFFER,
            wanted: Vec::new(),
        }
    }

    /// The copy with other colour sizes (the id not kept): a framebuffer
    /// target when its buffer is 16 or 32 bits.
    fn resized(&self, red: EGLint, green: EGLint, blue: EGLint, alpha: EGLint) -> TConfig {
        let buffer_size = red + green + blue + alpha;
        TConfig { red, green, blue, alpha, buffer_size, id: EGL_DONT_CARE, framebuffer_target: if buffer_size == 16 || buffer_size == 32 { EGL_TRUE_I } else { EGL_FALSE }, wanted: Vec::new(), ..self.clone() }
    }

    pub fn id(&self) -> EGLint {
        self.id
    }

    /// `getConfAttrib`: none for an attribute it does not keep.
    pub fn attrib(&self, a: EGLint) -> Option<EGLint> {
        Some(match a {
            EGL_BUFFER_SIZE => self.buffer_size,
            EGL_RED_SIZE => self.red,
            EGL_GREEN_SIZE => self.green,
            EGL_BLUE_SIZE => self.blue,
            EGL_LUMINANCE_SIZE => self.luminance,
            EGL_ALPHA_SIZE => self.alpha,
            EGL_ALPHA_MASK_SIZE => self.alpha_mask,
            EGL_BIND_TO_TEXTURE_RGB => self.bind_rgb,
            EGL_BIND_TO_TEXTURE_RGBA => self.bind_rgba,
            EGL_CONFIG_CAVEAT => self.caveat,
            EGL_CONFORMANT => self.conformant,
            EGL_CONFIG_ID => self.id,
            EGL_DEPTH_SIZE => self.depth,
            EGL_LEVEL => self.level,
            EGL_MAX_PBUFFER_WIDTH => self.max_pb_width,
            EGL_MAX_PBUFFER_HEIGHT => self.max_pb_height,
            EGL_MAX_PBUFFER_PIXELS => self.max_pb_pixels,
            EGL_MAX_SWAP_INTERVAL => self.max_swap,
            EGL_MIN_SWAP_INTERVAL => self.min_swap,
            EGL_NATIVE_RENDERABLE => self.native_renderable,
            EGL_NATIVE_VISUAL_ID => self.native_visual_id,
            EGL_NATIVE_VISUAL_TYPE => self.native_visual_type,
            EGL_RENDERABLE_TYPE => self.renderable,
            EGL_SAMPLE_BUFFERS => self.sample_buffers,
            EGL_SAMPLES => self.samples,
            EGL_STENCIL_SIZE => self.stencil,
            EGL_SURFACE_TYPE => self.surface_type,
            EGL_COLOR_BUFFER_TYPE => EGL_RGB_BUFFER,
            EGL_TRANSPARENT_TYPE => self.transparent_type,
            EGL_TRANSPARENT_RED_VALUE => self.trans_red,
            EGL_TRANSPARENT_GREEN_VALUE => self.trans_green,
            EGL_TRANSPARENT_BLUE_VALUE => self.trans_blue,
            EGL_RECORDABLE_ANDROID => self.recordable,
            EGL_FRAMEBUFFER_TARGET_ANDROID => self.framebuffer_target,
            _ => return None,
        })
    }

    /// `operator==`: the same properties (not the id, the native visual or
    /// the wanted buffer size).
    fn same(&self, o: &TConfig) -> bool {
        let k = |c: &TConfig| {
            [
                c.buffer_size, c.red, c.green, c.blue, c.alpha, c.alpha_mask, c.bind_rgb, c.bind_rgba, c.caveat, c.level, c.depth, c.max_pb_width, c.max_pb_height, c.max_pb_pixels, c.max_swap, c.min_swap, c.native_renderable, c.renderable, c.sample_buffers, c.samples, c.stencil, c.luminance, c.surface_type, c.transparent_type, c.trans_red, c.trans_green, c.trans_blue, c.recordable, c.framebuffer_target, c.conformant, c.color_buffer_type,
            ]
        };
        k(self) == k(o)
    }

    /// `operator<`, the list's own order.
    fn static_less(&self, o: &TConfig) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if self.conformant != o.conformant {
            return if self.conformant != 0 { Ordering::Less } else { Ordering::Greater };
        }
        (self.caveat as u32, colour_buffer_rank(self.color_buffer_type), self.buffer_size, self.sample_buffers, self.samples, self.depth, self.stencil, self.id).cmp(&(o.caveat as u32, colour_buffer_rank(o.color_buffer_type), o.buffer_size, o.sample_buffers, o.samples, o.depth, o.stencil, o.id))
    }

    /// `chosen`: whether this config meets `pattern`'s criteria.
    fn chosen(&self, p: &TConfig) -> bool {
        let dc = EGL_DONT_CARE;
        // At least.
        for (want, have) in [(p.buffer_size, self.buffer_size), (p.red, self.red), (p.green, self.green), (p.blue, self.blue), (p.alpha, self.alpha), (p.alpha_mask, self.alpha_mask), (p.depth, self.depth), (p.stencil, self.stencil), (p.luminance, self.luminance)] {
            if want != dc && want > have {
                return false;
            }
        }
        if p.wanted.contains(&EGL_BUFFER_SIZE) && p.wanted_buffer_size != dc && p.wanted_buffer_size > self.buffer_size {
            return false;
        }
        for (want, have) in [(p.sample_buffers, self.sample_buffers), (p.samples, self.samples)] {
            if want != dc && want > have {
                return false;
            }
        }
        // Exactly.
        for (want, have) in [
            (p.level, self.level),
            (p.id, self.id),
            (p.native_visual_type, self.native_visual_type),
            (p.max_swap, self.max_swap),
            (p.min_swap, self.min_swap),
            (p.trans_red, self.trans_red),
            (p.trans_green, self.trans_green),
            (p.trans_blue, self.trans_blue),
            (p.bind_rgb, self.bind_rgb),
            (p.bind_rgba, self.bind_rgba),
            (p.caveat, self.caveat),
            (p.native_renderable, self.native_renderable),
            (p.transparent_type, self.transparent_type),
        ] {
            if want != dc && want != have {
                return false;
            }
        }
        // Masks; every config is taken as able to make a window.
        if p.surface_type != dc && p.surface_type & (self.surface_type | EGL_WINDOW_BIT) != p.surface_type {
            return false;
        }
        if p.conformant != dc && p.conformant & self.conformant != p.conformant {
            return false;
        }
        if p.renderable != dc && p.renderable & self.renderable != p.renderable {
            return false;
        }
        if p.framebuffer_target != dc && p.framebuffer_target != self.framebuffer_target {
            return false;
        }
        true
    }
}

fn colour_buffer_rank(t: EGLint) -> u32 {
    match t {
        EGL_RGB_BUFFER => 0,
        EGL_LUMINANCE_BUFFER => 1,
        0x3300 => 2, // EGL_YUV_BUFFER_EXT
        _ => 3,
    }
}

/// `DynamicCompare`: the order a choice is given in, which counts the
/// colour sizes asked for (more first) before the buffer size.
fn dynamic_order(p: &TConfig, a: &TConfig, b: &TConfig) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a.conformant != b.conformant {
        return if a.conformant != 0 { Ordering::Less } else { Ordering::Greater };
    }
    if a.caveat != b.caveat {
        return (a.caveat as u32).cmp(&(b.caveat as u32));
    }
    if a.color_buffer_type != b.color_buffer_type {
        return colour_buffer_rank(a.color_buffer_type).cmp(&colour_buffer_rank(b.color_buffer_type));
    }
    let nontrivial = |v: EGLint| v != 0 && v != EGL_DONT_CARE;
    let wanted = |attr: EGLint, v: EGLint| p.wanted.contains(&attr) && nontrivial(v);
    let colour = |c: &TConfig| {
        let mut n = 0;
        if wanted(EGL_RED_SIZE, p.red) {
            n += c.red;
        }
        if wanted(EGL_GREEN_SIZE, p.green) {
            n += c.green;
        }
        if wanted(EGL_BLUE_SIZE, p.blue) {
            n += c.blue;
        }
        if wanted(EGL_LUMINANCE_SIZE, p.luminance) {
            n += c.luminance;
        }
        if wanted(EGL_ALPHA_SIZE, p.alpha) {
            n += c.alpha;
        }
        n
    };
    let (ca, cb) = (colour(a), colour(b));
    if ca != cb {
        return cb.cmp(&ca);
    }
    (a.buffer_size, a.sample_buffers, a.samples, a.depth, a.stencil, a.id).cmp(&(b.buffer_size, b.sample_buffers, b.samples, b.depth, b.stencil, b.id))
}

/// The translator's display: its configs in order.
#[derive(Debug, Default)]
pub struct Display {
    pub configs: Vec<TConfig>,
}

impl Display {
    /// `initConfigurations`, from the host's configs as `queryConfigs`
    /// finds them.
    pub fn new(host: &[(EGLConfig, HostInfo)]) -> Display {
        let mut d = Display::default();
        for (cfg, info) in host {
            // `addConfig`.
            if info.red > 8 || info.green > 8 || info.blue > 8 || info.depth < 24 || info.stencil < 8 || info.samples > 2 {
                continue;
            }
            let mut i = *info;
            i.renderable |= EGL_OPENGL_ES_BIT;
            let c = TConfig::from_info(&i, 0, *cfg);
            if !d.configs.iter().any(|x| x.same(&c)) {
                d.configs.push(c);
            }
        }
        for (n, c) in d.configs.iter_mut().enumerate() {
            c.id = n as EGLint + 1 + RESERVED.len() as EGLint;
        }
        // `addReservedConfigs`.
        for (n, &(r, g, b, a)) in RESERVED.iter().enumerate() {
            if let Some(i) = d.add_simple(r, g, b, a) {
                d.configs[i].id = n as EGLint + 1;
            }
        }
        d.sort();
        d
    }

    fn sort(&mut self) {
        self.configs.sort_by(|a, b| a.static_less(b));
    }

    /// `addSimplePixelFormat` (any number of samples): the best match with a
    /// depth of 16 taken again with these sizes, or the match itself when
    /// that is a config already there or its buffer is 16 bits.
    fn add_simple(&mut self, r: EGLint, g: EGLint, b: EGLint, a: EGLint) -> Option<usize> {
        self.sort();
        let dc = EGL_DONT_CARE;
        let info = HostInfo {
            red: r,
            green: g,
            blue: b,
            alpha: a,
            alpha_mask: dc,
            caveat: dc,
            depth: 16,
            level: dc,
            max_pb_width: dc,
            max_pb_height: dc,
            max_pb_pixels: dc,
            native_renderable: dc,
            renderable: dc,
            native_visual_id: dc,
            native_visual_type: dc,
            samples: dc,
            stencil: dc,
            surface_type: dc,
            transparent_type: dc,
            trans_red: dc,
            trans_green: dc,
            trans_blue: dc,
        };
        let pattern = TConfig::from_info(&info, dc, std::ptr::null_mut());
        let m = *self.matching(&pattern).first()?;
        if self.configs[m].buffer_size == 16 {
            return Some(m);
        }
        let c = self.configs[m].resized(r, g, b, a);
        if self.configs.iter().any(|x| x.same(&c)) {
            // Already there: the translator keeps the match.
            return Some(m);
        }
        self.configs.push(c);
        Some(self.configs.len() - 1)
    }

    /// `doChooseConfigs`: the configs meeting `pattern`, in its order.
    fn matching(&self, pattern: &TConfig) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.configs.len()).filter(|&i| self.configs[i].chosen(pattern)).collect();
        v.sort_by(|&a, &b| dynamic_order(pattern, &self.configs[a], &self.configs[b]));
        v
    }

    pub fn by_id(&self, id: EGLint) -> Option<usize> {
        self.configs.iter().position(|c| c.id == id)
    }

    /// `eglChooseConfig`: the configs (by place) for the attribute list
    /// (pairs to `EGL_NONE`), or the EGL error.
    pub fn choose(&self, attribs: &[EGLint]) -> Result<Vec<usize>, EGLint> {
        let dc = EGL_DONT_CARE;
        let mut p = TConfig::from_info(&HostInfo::default(), EGL_FALSE, std::ptr::null_mut());
        // The selection defaults.
        p.surface_type = EGL_WINDOW_BIT;
        p.renderable = EGL_OPENGL_ES_BIT;
        p.caveat = dc;
        p.native_renderable = dc;
        p.native_visual_type = dc;
        p.trans_red = dc;
        p.trans_green = dc;
        p.trans_blue = dc;
        p.transparent_type = EGL_NONE;
        p.framebuffer_target = dc;
        p.wanted_buffer_size = dc;
        p.conformant = 0;
        p.max_pb_width = 0;
        p.max_pb_height = 0;
        p.max_pb_pixels = 0;
        p.native_visual_id = 0;
        let mut config_id = None;
        let mut i = 0;
        while i + 1 < attribs.len() && attribs[i] != EGL_NONE && config_id.is_none() {
            let (a, v) = (attribs[i], attribs[i + 1]);
            i += 2;
            if a != EGL_LEVEL && a != EGL_MATCH_NATIVE_PIXMAP && v == dc {
                continue;
            }
            let bad = Err(EGL_BAD_ATTRIBUTE);
            let boolean = |v: EGLint| v == EGL_TRUE_I || v == EGL_FALSE;
            match a {
                EGL_MAX_PBUFFER_WIDTH | EGL_MAX_PBUFFER_HEIGHT | EGL_MAX_PBUFFER_PIXELS | EGL_NATIVE_VISUAL_ID => continue,
                EGL_LEVEL => {
                    if v == dc {
                        return bad;
                    }
                    p.level = v;
                }
                EGL_BUFFER_SIZE | EGL_RED_SIZE | EGL_GREEN_SIZE | EGL_BLUE_SIZE | EGL_LUMINANCE_SIZE | EGL_ALPHA_SIZE | EGL_ALPHA_MASK_SIZE | EGL_DEPTH_SIZE | EGL_MAX_SWAP_INTERVAL | EGL_MIN_SWAP_INTERVAL | EGL_SAMPLE_BUFFERS | EGL_SAMPLES | EGL_STENCIL_SIZE | EGL_CONFIG_ID => {
                    if v < 0 {
                        return bad;
                    }
                    match a {
                        EGL_BUFFER_SIZE => p.wanted_buffer_size = v,
                        EGL_RED_SIZE => p.red = v,
                        EGL_GREEN_SIZE => p.green = v,
                        EGL_BLUE_SIZE => p.blue = v,
                        EGL_LUMINANCE_SIZE => p.luminance = v,
                        EGL_ALPHA_SIZE => p.alpha = v,
                        EGL_ALPHA_MASK_SIZE => p.alpha_mask = v,
                        EGL_DEPTH_SIZE => p.depth = v,
                        EGL_SAMPLE_BUFFERS => p.sample_buffers = v,
                        EGL_SAMPLES => p.samples = v,
                        EGL_STENCIL_SIZE => p.stencil = v,
                        EGL_CONFIG_ID => config_id = Some(v),
                        // The swap intervals are checked, never kept.
                        _ => {}
                    }
                }
                EGL_BIND_TO_TEXTURE_RGB | EGL_BIND_TO_TEXTURE_RGBA => {
                    if !boolean(v) {
                        return bad;
                    }
                }
                EGL_CONFIG_CAVEAT => {
                    if v != EGL_NONE && v != EGL_SLOW_CONFIG && v != EGL_NON_CONFORMANT_CONFIG {
                        return bad;
                    }
                    p.caveat = v;
                }
                EGL_CONFORMANT => p.conformant = v,
                EGL_NATIVE_RENDERABLE => {
                    if !boolean(v) {
                        return bad;
                    }
                    p.native_renderable = v;
                }
                EGL_RENDERABLE_TYPE => p.renderable = v,
                // Taken, not counted as asked for.
                EGL_NATIVE_VISUAL_TYPE => {
                    p.native_visual_type = v;
                    continue;
                }
                EGL_SURFACE_TYPE => p.surface_type = v,
                EGL_TRANSPARENT_TYPE => {
                    if v != EGL_NONE && v != EGL_TRANSPARENT_RGB {
                        return bad;
                    }
                    p.transparent_type = v;
                }
                EGL_TRANSPARENT_RED_VALUE => p.trans_red = v,
                EGL_TRANSPARENT_GREEN_VALUE => p.trans_green = v,
                EGL_TRANSPARENT_BLUE_VALUE => p.trans_blue = v,
                EGL_COLOR_BUFFER_TYPE => {
                    if v != EGL_RGB_BUFFER && v != EGL_LUMINANCE_BUFFER {
                        return bad;
                    }
                }
                EGL_RECORDABLE_ANDROID => p.recordable = v,
                EGL_FRAMEBUFFER_TARGET_ANDROID => p.framebuffer_target = v,
                _ => return bad,
            }
            p.wanted.push(a);
        }
        if let Some(id) = config_id {
            return self.by_id(id).map(|i| vec![i]).ok_or(EGL_BAD_ATTRIBUTE);
        }
        p.buffer_size = p.red + p.green + p.blue + p.alpha;
        Ok(self.matching(&p))
    }
}

/// `kCommonCfgs`: 8-8-8 and 8-8-8-8 (565 and the multisampled ones are left
/// out there too).
const RESERVED: [(EGLint, EGLint, EGLint, EGLint); 2] = [(8, 8, 8, 0), (8, 8, 8, 8)];

/// `EglOsEglDisplay::queryConfigs`: the host's configs with pbuffers,
/// OpenGL ES 3 and colour, and what it says of each.
pub fn host_infos(dpy: EGLDisplay) -> Vec<(EGLConfig, HostInfo)> {
    let attrs = [EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_RED_SIZE, 1, EGL_GREEN_SIZE, 1, EGL_BLUE_SIZE, 1, EGL_ALPHA_SIZE, 0, EGL_NONE];
    let mut n = 0;
    unsafe { eglChooseConfig(dpy, attrs.as_ptr(), std::ptr::null_mut(), 0, &mut n) };
    let mut v = vec![std::ptr::null_mut(); n.max(0) as usize];
    if unsafe { eglChooseConfig(dpy, attrs.as_ptr(), v.as_mut_ptr(), n, &mut n) } != EGL_TRUE {
        return Vec::new();
    }
    v.truncate(n.max(0) as usize);
    let at = |c: EGLConfig, a: EGLint| {
        let mut x = 0;
        unsafe { eglGetConfigAttrib(dpy, c, a, &mut x) };
        x
    };
    v.into_iter()
        .map(|c| {
            let i = HostInfo {
                red: at(c, EGL_RED_SIZE),
                green: at(c, EGL_GREEN_SIZE),
                blue: at(c, EGL_BLUE_SIZE),
                alpha: at(c, EGL_ALPHA_SIZE),
                alpha_mask: at(c, EGL_ALPHA_MASK_SIZE),
                caveat: at(c, EGL_CONFIG_CAVEAT),
                depth: at(c, EGL_DEPTH_SIZE),
                level: at(c, EGL_LEVEL),
                max_pb_width: at(c, EGL_MAX_PBUFFER_WIDTH),
                max_pb_height: at(c, EGL_MAX_PBUFFER_HEIGHT),
                max_pb_pixels: at(c, EGL_MAX_PBUFFER_PIXELS),
                native_renderable: at(c, EGL_NATIVE_RENDERABLE),
                renderable: at(c, EGL_RENDERABLE_TYPE),
                native_visual_id: at(c, EGL_NATIVE_VISUAL_ID),
                native_visual_type: at(c, EGL_NATIVE_VISUAL_TYPE),
                samples: at(c, EGL_SAMPLES),
                stencil: at(c, EGL_STENCIL_SIZE),
                surface_type: at(c, EGL_SURFACE_TYPE),
                transparent_type: at(c, EGL_TRANSPARENT_TYPE),
                trans_red: at(c, EGL_TRANSPARENT_RED_VALUE),
                trans_green: at(c, EGL_TRANSPARENT_GREEN_VALUE),
                trans_blue: at(c, EGL_TRANSPARENT_BLUE_VALUE),
            };
            (c, i)
        })
        .collect()
}

/// The translator's OpenGL ES strings, which are what the guest is told
/// (`EmulationGl::getGlString` asks the translator's `glGetString`, not the
/// host driver's): `glestranslator`'s `GLEScontext::buildStrings`,
/// `initCapsLocked`, `GLESv2Context::initExtensionString` with
/// `InitExtensionString`, `GLEScmContext::initExtensionString`, and
/// `glGetString` in `gles_v2_imp.cpp`, for a context of `version` (one of
/// [`super::objects`]' `GLES_API_*`) on a host that is OpenGL ES
/// (`isGles2Gles`) and not a core profile. `host` is the host's own
/// `glGetString` on that context, `host_integer` its `glGetIntegerv`.
///
/// The extensions offered are only those the guest's encoder can serve:
/// offered the host's whole list, the guest's Skia found extensions whose
/// functions the encoder has not (`GL_EXT_debug_marker`, `GL_KHR_debug`,
/// ...), and SurfaceFlinger's `GrDirectContext` creation failed.
pub fn gl_string(name: u32, version: u32, host: &dyn Fn(u32) -> String, host_integer: &dyn Fn(u32) -> i32) -> Option<String> {
    const GL_VENDOR: u32 = 0x1F00;
    const GL_RENDERER: u32 = 0x1F01;
    const GL_VERSION: u32 = 0x1F02;
    const GL_EXTENSIONS: u32 = 0x1F03;
    const GL_SHADING_LANGUAGE_VERSION: u32 = 0x8B8C;
    let gles1 = version == super::objects::GLES_API_CM;
    let (major, minor) = match version {
        super::objects::GLES_API_CM => (1, 1),
        super::objects::GLES_API_2 => (2, 0),
        super::objects::GLES_API_3_0 => (3, 0),
        _ => (3, 1),
    };
    let base = |n: u32| {
        let s = host(n);
        if s.is_empty() {
            "N/A".to_string()
        } else {
            s
        }
    };
    Some(match name {
        GL_VENDOR => format!("Google ({})", base(GL_VENDOR)),
        GL_RENDERER => format!("Android Emulator OpenGL ES Translator ({})", base(GL_RENDERER)),
        GL_VERSION => {
            // `sPickVersionStringPart`, or ES-CM's.
            let part = match (major, minor) {
                (1, _) => "OpenGL ES-CM 1.1",
                (2, _) => "OpenGL ES 2.0",
                (3, 0) => "OpenGL ES 3.0",
                _ => "OpenGL ES 3.1",
            };
            format!("{part} ({})", base(GL_VERSION))
        }
        // GLES 1's comes from the host (`gles_cm_imp.cpp` passes it
        // through); GLES 2 and 3's are the translator's.
        GL_SHADING_LANGUAGE_VERSION if gles1 => host(GL_SHADING_LANGUAGE_VERSION),
        GL_SHADING_LANGUAGE_VERSION => match (major, minor) {
            (3, 0) => "OpenGL ES GLSL ES 3.00",
            (3, _) => "OpenGL ES GLSL ES 3.10",
            _ => "OpenGL ES GLSL ES 1.0.17",
        }
        .to_string(),
        GL_EXTENSIONS => {
            let caps = Caps::of(&host(GL_EXTENSIONS), &host(GL_VERSION));
            if gles1 {
                caps.gles1_extensions(host_integer)
            } else {
                caps.gles2_extensions()
            }
        }
        _ => return None,
    })
}

/// gfxstream's `Version` of a string: two or three numbers by `sscanf`
/// at its start, else 0.0 (Mesa's "OpenGL ES 3.1 Mesa ..." is 0.0).
fn version_of(s: &str) -> (u32, u32) {
    let t = s.trim_start();
    let num = |t: &str| -> Option<(u32, usize)> {
        let t2 = t.trim_start();
        let skip = t.len() - t2.len();
        let (sign, body) = match t2.as_bytes().first() {
            Some(b'+') | Some(b'-') => (1, &t2[1..]),
            _ => (0, t2),
        };
        let n = body.bytes().take_while(u8::is_ascii_digit).count();
        (n > 0).then(|| (body[..n].parse::<u32>().unwrap_or(0), skip + sign + n))
    };
    match num(t) {
        Some((major, used)) if t[used..].starts_with('.') => match num(&t[used + 1..]) {
            Some((minor, _)) => (major, minor),
            None => (0, 0),
        },
        _ => (0, 0),
    }
}

/// What `initCapsLocked` finds in the host's extensions (`getHostExtensionsString`:
/// the list with a space before and after) for the strings it builds, as
/// on a host that is OpenGL ES and not a core profile.
struct Caps {
    half_float_pixel: bool,
    nv_half_float: bool,
    packed_depth_stencil: bool,
    half_float_vertex: bool,
    standard_derivatives: bool,
    texture_npot: bool,
    rgb8_rgba8: bool,
    ovr_multiview2: bool,
    multiview_texture_multisample: bool,
    color_buffer_float: bool,
    color_buffer_half_float: bool,
    shader_framebuffer_fetch: bool,
    bgra8888: bool,
    ext_texture_buffer: bool,
    oes_texture_buffer: bool,
    draw_buffers_indexed: bool,
    clip_cull_distance: bool,
    read_format: bool,
    framebuffer_object: bool,
    matrix_palette: bool,
    vertex_blend: bool,
}

impl Caps {
    fn of(extensions: &str, gl_version: &str) -> Caps {
        let s = format!(" {} ", extensions.trim());
        let has = |x: &str| s.contains(x);
        Caps {
            half_float_pixel: has("GL_ARB_half_float_pixel ") || has("GL_OES_texture_half_float "),
            nv_half_float: has("GL_NV_half_float "),
            packed_depth_stencil: has("GL_EXT_packed_depth_stencil ") || has("GL_OES_packed_depth_stencil "),
            half_float_vertex: has("GL_ARB_half_float_vertex ") || has("GL_OES_vertex_half_float "),
            standard_derivatives: has("GL_OES_standard_derivatives "),
            texture_npot: has("GL_ARB_texture_non_power_of_two") || has("GL_OES_texture_npot"),
            rgb8_rgba8: version_of(gl_version) >= (3, 0) || has("GL_OES_rgb8_rgba8"),
            ovr_multiview2: has("GL_OVR_multiview2"),
            multiview_texture_multisample: has("GL_EXT_multiview_texture_multisample"),
            color_buffer_float: has("GL_ARB_color_buffer_float") || has("GL_EXT_color_buffer_float"),
            color_buffer_half_float: has("GL_EXT_color_buffer_half_float"),
            // On a host that is OpenGL ES only (b/203446380).
            shader_framebuffer_fetch: has("GL_EXT_shader_framebuffer_fetch"),
            bgra8888: has("GL_EXT_bgra ") || has("GL_EXT_texture_format_BGRA8888"),
            ext_texture_buffer: has("GL_EXT_texture_buffer"),
            oes_texture_buffer: has("GL_OES_texture_buffer"),
            draw_buffers_indexed: has("GL_EXT_draw_buffers_indexed"),
            clip_cull_distance: has("GL_EXT_clip_cull_distance"),
            read_format: has("GL_OES_read_format "),
            framebuffer_object: has("GL_EXT_framebuffer_object "),
            matrix_palette: has("GL_ARB_matrix_palette "),
            vertex_blend: has("GL_ARB_vertex_blend "),
        }
    }

    /// `InitExtensionString`: OpenGL ES 2 and 3's.
    fn gles2_extensions(&self) -> String {
        let mut ext = String::from(
            "GL_OES_EGL_sync GL_OES_EGL_image GL_OES_EGL_image_external GL_OES_depth24 GL_OES_depth32 \
             GL_OES_element_index_uint \
             GL_OES_texture_float GL_OES_texture_float_linear \
             GL_OES_compressed_paletted_texture GL_OES_compressed_ETC1_RGB8_texture \
             GL_OES_depth_texture ",
        );
        let mut add = |on: bool, x: &str| {
            if on {
                ext.push_str(x);
            }
        };
        add(self.half_float_pixel || self.nv_half_float, "GL_OES_texture_half_float GL_OES_texture_half_float_linear ");
        add(self.packed_depth_stencil, "GL_OES_packed_depth_stencil ");
        add(self.half_float_vertex, "GL_OES_vertex_half_float ");
        add(self.standard_derivatives, "GL_OES_standard_derivatives ");
        add(self.texture_npot, "GL_OES_texture_npot ");
        add(self.rgb8_rgba8, "GL_OES_rgb8_rgba8 ");
        add(self.ovr_multiview2, "GL_OVR_multiview2 ");
        add(self.multiview_texture_multisample, "GL_EXT_multiview_texture_multisample ");
        add(self.color_buffer_float, "GL_EXT_color_buffer_float ");
        add(self.color_buffer_half_float, "GL_EXT_color_buffer_half_float ");
        add(self.shader_framebuffer_fetch, "GL_EXT_shader_framebuffer_fetch ");
        add(self.bgra8888, "GL_EXT_texture_format_BGRA8888 GL_APPLE_texture_format_BGRA8888 ");
        add(self.ext_texture_buffer, "GL_EXT_texture_buffer ");
        add(self.oes_texture_buffer, "GL_OES_texture_buffer ");
        add(self.draw_buffers_indexed, "GL_EXT_draw_buffers_indexed ");
        add(self.clip_cull_distance, "GL_EXT_clip_cull_distance ");
        ext
    }

    /// `GLEScmContext::initExtensionString`: OpenGL ES 1's.
    fn gles1_extensions(&self, host_integer: &dyn Fn(u32) -> i32) -> String {
        let mut ext = String::from(
            "GL_OES_blend_func_separate GL_OES_blend_equation_separate GL_OES_blend_subtract \
             GL_OES_byte_coordinates GL_OES_compressed_paletted_texture GL_OES_point_size_array \
             GL_OES_point_sprite GL_OES_single_precision GL_OES_stencil_wrap GL_OES_texture_env_crossbar \
             GL_OES_texture_mirored_repeat GL_OES_EGL_image GL_OES_element_index_uint GL_OES_draw_texture \
             GL_OES_texture_cube_map GL_OES_draw_texture ",
        );
        if self.read_format {
            ext.push_str("GL_OES_read_format ");
        }
        if self.framebuffer_object {
            ext.push_str(
                "GL_OES_framebuffer_object GL_OES_depth24 GL_OES_depth32 GL_OES_fbo_render_mipmap \
                 GL_OES_rgb8_rgba8 GL_OES_stencil1 GL_OES_stencil4 GL_OES_stencil8 ",
            );
        }
        if self.packed_depth_stencil {
            ext.push_str("GL_OES_packed_depth_stencil ");
        }
        if self.bgra8888 {
            ext.push_str("GL_EXT_texture_format_BGRA8888 GL_APPLE_texture_format_BGRA8888 ");
        }
        if self.matrix_palette && self.vertex_blend {
            ext.push_str("GL_OES_matrix_palette ");
            const GL_MAX_PALETTE_MATRICES_OES: u32 = 0x8842;
            const GL_MAX_VERTEX_UNITS_OES: u32 = 0x86A4;
            if host_integer(GL_MAX_PALETTE_MATRICES_OES) >= 32 && host_integer(GL_MAX_VERTEX_UNITS_OES) >= 4 {
                ext.push_str("GL_OES_extended_matrix_palette ");
            }
        }
        ext.push_str("GL_OES_compressed_ETC1_RGB8_texture ");
        ext
    }
}

#[cfg(test)]
mod tests {

    /// A host as this Mac's Mesa answers: an OpenGL ES 3.1 driver whose
    /// extensions include ones the guest's encoder cannot serve.
    fn mesa(name: u32) -> String {
        match name {
            0x1F00 => "Mesa".into(),
            0x1F01 => "llvmpipe (LLVM 23.1.5, 128 bits)".into(),
            0x1F02 => "OpenGL ES 3.1 Mesa 26.3.0".into(),
            0x8B8C => "OpenGL ES GLSL ES 3.20".into(),
            0x1F03 => "GL_EXT_blend_minmax GL_EXT_debug_marker GL_KHR_debug GL_KHR_blend_equation_advanced \
                       GL_EXT_base_instance GL_EXT_multi_draw_indirect GL_OES_texture_half_float GL_OES_texture_half_float_linear \
                       GL_OES_packed_depth_stencil GL_OES_standard_derivatives GL_OES_texture_npot GL_OES_rgb8_rgba8 \
                       GL_EXT_color_buffer_float GL_EXT_color_buffer_half_float GL_EXT_texture_format_BGRA8888 \
                       GL_EXT_texture_buffer GL_OES_texture_buffer GL_EXT_draw_buffers_indexed GL_EXT_clip_cull_distance \
                       GL_EXT_shader_framebuffer_fetch GL_OES_vertex_half_float"
                .into(),
            _ => String::new(),
        }
    }

    #[test]
    fn the_guest_is_told_the_translators_strings_not_the_hosts() {
        use super::super::objects::{GLES_API_2, GLES_API_3_0, GLES_API_3_1, GLES_API_CM};
        let s = |name, v| gl_string(name, v, &mesa, &|_| 0).unwrap();
        assert_eq!(s(0x1F00, GLES_API_3_1), "Google (Mesa)");
        assert_eq!(s(0x1F01, GLES_API_3_1), "Android Emulator OpenGL ES Translator (llvmpipe (LLVM 23.1.5, 128 bits))");
        assert_eq!(s(0x1F02, GLES_API_3_1), "OpenGL ES 3.1 (OpenGL ES 3.1 Mesa 26.3.0)");
        assert_eq!(s(0x1F02, GLES_API_3_0), "OpenGL ES 3.0 (OpenGL ES 3.1 Mesa 26.3.0)");
        assert_eq!(s(0x1F02, GLES_API_2), "OpenGL ES 2.0 (OpenGL ES 3.1 Mesa 26.3.0)");
        assert_eq!(s(0x1F02, GLES_API_CM), "OpenGL ES-CM 1.1 (OpenGL ES 3.1 Mesa 26.3.0)");
        assert_eq!(s(0x8B8C, GLES_API_3_1), "OpenGL ES GLSL ES 3.10");
        assert_eq!(s(0x8B8C, GLES_API_3_0), "OpenGL ES GLSL ES 3.00");
        assert_eq!(s(0x8B8C, GLES_API_2), "OpenGL ES GLSL ES 1.0.17");
        assert_eq!(gl_string(0x1234, GLES_API_2, &mesa, &|_| 0), None);
        // Only what the translator offers: none of the host's debug,
        // blend-equation or multi-draw extensions.
        let ext = s(0x1F03, GLES_API_3_1);
        for x in ["GL_EXT_debug_marker", "GL_KHR_debug", "GL_KHR_blend_equation_advanced", "GL_EXT_base_instance", "GL_EXT_multi_draw_indirect", "GL_EXT_blend_minmax"] {
            assert!(!ext.contains(x), "{x} in {ext}");
        }
        assert_eq!(
            ext,
            "GL_OES_EGL_sync GL_OES_EGL_image GL_OES_EGL_image_external GL_OES_depth24 GL_OES_depth32 \
             GL_OES_element_index_uint GL_OES_texture_float GL_OES_texture_float_linear \
             GL_OES_compressed_paletted_texture GL_OES_compressed_ETC1_RGB8_texture GL_OES_depth_texture \
             GL_OES_texture_half_float GL_OES_texture_half_float_linear GL_OES_packed_depth_stencil \
             GL_OES_vertex_half_float GL_OES_standard_derivatives GL_OES_texture_npot GL_OES_rgb8_rgba8 \
             GL_EXT_color_buffer_float GL_EXT_color_buffer_half_float GL_EXT_shader_framebuffer_fetch \
             GL_EXT_texture_format_BGRA8888 GL_APPLE_texture_format_BGRA8888 GL_EXT_texture_buffer \
             GL_OES_texture_buffer GL_EXT_draw_buffers_indexed GL_EXT_clip_cull_distance "
        );
        let es1 = s(0x1F03, GLES_API_CM);
        assert!(es1.starts_with("GL_OES_blend_func_separate ") && es1.ends_with("GL_OES_compressed_ETC1_RGB8_texture "));
        assert!(es1.contains("GL_OES_packed_depth_stencil ") && !es1.contains("GL_OES_framebuffer_object"));
    }

    #[test]
    fn a_version_is_read_as_sscanf_reads_it() {
        assert_eq!(version_of("OpenGL ES 3.1 Mesa 26.3.0"), (0, 0));
        assert_eq!(version_of("4.6.0 NVIDIA 550"), (4, 6));
        assert_eq!(version_of("  3.0"), (3, 0));
        assert_eq!(version_of("3"), (0, 0));
        // Without GL_OES_rgb8_rgba8, a host whose version does not parse
        // as 3.0 or more is not taken to have it.
        let host = |n: u32| if n == 0x1F02 { "OpenGL ES 3.1 Mesa".to_string() } else { String::new() };
        assert!(!gl_string(0x1F03, super::super::objects::GLES_API_2, &host, &|_| 0).unwrap().contains("rgb8_rgba8"));
    }
    use super::*;

    fn host(r: EGLint, g: EGLint, b: EGLint, a: EGLint, depth: EGLint, stencil: EGLint) -> HostInfo {
        HostInfo { red: r, green: g, blue: b, alpha: a, depth, stencil, caveat: EGL_NONE, renderable: EGL_OPENGL_ES2_BIT | EGL_OPENGL_ES3_BIT, surface_type: EGL_PBUFFER_BIT, transparent_type: EGL_NONE, ..Default::default() }
    }

    fn cfg(n: usize) -> EGLConfig {
        n as EGLConfig
    }

    /// A host like Mesa's: 10-bit and depthless configs among the rest.
    fn mesa_like() -> Display {
        Display::new(&[
            (cfg(1), host(10, 10, 10, 2, 24, 8)),
            (cfg(2), host(8, 8, 8, 8, 0, 0)),
            (cfg(3), host(8, 8, 8, 8, 24, 8)),
            (cfg(4), host(8, 8, 8, 0, 24, 8)),
            (cfg(5), host(5, 6, 5, 0, 24, 8)),
            (cfg(6), host(8, 8, 8, 8, 24, 8)),
        ])
    }

    #[test]
    fn the_host_configs_are_filtered_and_two_reserved_added() {
        let d = mesa_like();
        // 10-bit and depthless gone, the duplicate once: 3, 4, 5 kept as
        // ids 3, 4, 5. The reserved 8-8-8 is the 888 config itself (the
        // copy would have the same properties), which becomes id 1; the
        // 8-8-8-8 copy is a framebuffer target, which the host's is not, so
        // it is a config of its own, id 2.
        let mut ids: Vec<EGLint> = d.configs.iter().map(|c| c.id).collect();
        ids.sort();
        assert_eq!(ids, [1, 2, 3, 5]);
        assert!(d.configs.iter().all(|c| c.red <= 8 && c.renderable & EGL_OPENGL_ES_BIT != 0 && c.recordable == 0));
        let one = &d.configs[d.by_id(1).unwrap()];
        assert_eq!((one.red, one.alpha, one.buffer_size, one.framebuffer_target), (8, 0, 24, EGL_FALSE));
        // 8-8-8 from the smallest buffer with 8 a colour: the 888 host config.
        assert_eq!(one.host, cfg(4));
        let two = &d.configs[d.by_id(2).unwrap()];
        assert_eq!((two.alpha, two.buffer_size, two.framebuffer_target, two.host), (8, 32, EGL_TRUE_I, cfg(3)));
    }

    #[test]
    fn surfaceflingers_choice_is_the_reserved_rgba() {
        let d = mesa_like();
        let sf = [EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_RECORDABLE_ANDROID, 1, EGL_SURFACE_TYPE, EGL_WINDOW_BIT | EGL_PBUFFER_BIT, EGL_FRAMEBUFFER_TARGET_ANDROID, 1, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE];
        let got = d.choose(&sf).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(d.configs[got[0]].id, 2);
        // Asked for 8 bits of red: more colour first, then the smaller buffer.
        let rgb = [EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_DEPTH_SIZE, 0, EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE];
        let got = d.choose(&rgb).unwrap();
        let first = &d.configs[got[0]];
        assert_eq!((first.red, first.green, first.blue), (8, 8, 8));
        // A name it does not know; a bad caveat.
        assert_eq!(d.choose(&[0x31ff, 1, EGL_NONE]), Err(EGL_BAD_ATTRIBUTE));
        assert_eq!(d.choose(&[EGL_CONFIG_CAVEAT, 7, EGL_NONE]), Err(EGL_BAD_ATTRIBUTE));
        assert_eq!(d.choose(&[EGL_CONFIG_ID, 5, EGL_NONE]).map(|v| d.configs[v[0]].id), Ok(5));
        assert_eq!(d.choose(&[EGL_CONFIG_ID, 4, EGL_NONE]), Err(EGL_BAD_ATTRIBUTE));
        assert_eq!(d.choose(&[EGL_CONFIG_ID, 40, EGL_NONE]), Err(EGL_BAD_ATTRIBUTE));
    }
}
