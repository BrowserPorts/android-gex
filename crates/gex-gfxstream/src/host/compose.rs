//! Composing and posting (gfxstream's `Hwc2`, `CompositorGl`, `TextureDraw`,
//! `FrameBuffer::compose` and `post`).
//!
//! The guest's composer (with `ANDROID_EMU_host_composition_v1`/`v2`) sends
//! a `ComposeDevice`: a target color buffer and its layers, each a color
//! buffer's crop drawn into a rectangle of the target, or a solid colour,
//! with a transform, a blend mode and an alpha. They are drawn in order
//! into the target, cleared first, by one shader on the root context, a
//! source's first row at the rectangle's top row. A post makes a color
//! buffer the display's frame, handed to the host's sink: the display draws
//! it flipped (`TextureDraw::drawImpl` at rotation 0 takes the flip-V quad),
//! so the texture's first row is the top of the screen.

use super::gl::{self, Fns};
use super::Renderer;

/// `HWC2_COMPOSITION_DEVICE` and `_SOLID_COLOR`.
const DEVICE: u32 = 2;
const SOLID_COLOR: u32 = 3;
/// `HWC2_BLEND_MODE_NONE` and `_PREMULTIPLIED`.
const BLEND_NONE: i32 = 1;
const BLEND_PREMULTIPLIED: i32 = 2;

/// One layer (`ComposeLayer`, 56 bytes).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Layer {
    pub color_buffer: u32,
    pub mode: u32,
    /// left, top, right, bottom in the target's pixels.
    pub frame: [i32; 4],
    /// left, top, right, bottom in the source's pixels.
    pub crop: [f32; 4],
    pub blend: i32,
    pub alpha: f32,
    pub color: [u8; 4],
    pub transform: u32,
}

pub const LAYER_BYTES: usize = 56;

/// What a `ComposeDevice` (version 1) or `ComposeDevice_v2` asks.
#[derive(Debug, PartialEq)]
pub struct Request {
    pub version: u32,
    pub display: u32,
    pub target: u32,
    pub layers: Vec<Layer>,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().unwrap()))
}

impl Request {
    /// The request in `buf`, or none if it is of another version or shorter
    /// than its layers.
    pub fn parse(buf: &[u8]) -> Option<Request> {
        let version = u32_at(buf, 0)?;
        let (display, target, count, at) = match version {
            1 => (0, u32_at(buf, 4)?, u32_at(buf, 8)?, 12),
            2 => (u32_at(buf, 4)?, u32_at(buf, 8)?, u32_at(buf, 12)?, 16),
            _ => return None,
        };
        let mut layers = Vec::new();
        for i in 0..count as usize {
            let l = buf.get(at + i * LAYER_BYTES..at + (i + 1) * LAYER_BYTES)?;
            let w = |o: usize| u32_at(l, o).unwrap();
            let f = |o: usize| f32::from_bits(w(o));
            layers.push(Layer {
                color_buffer: w(0),
                mode: w(4),
                frame: [w(8) as i32, w(12) as i32, w(16) as i32, w(20) as i32],
                crop: [f(24), f(28), f(32), f(36)],
                blend: w(40) as i32,
                alpha: f(44),
                color: [l[48], l[49], l[50], l[51]],
                transform: w(52),
            });
        }
        Some(Request { version, display, target, layers })
    }
}

/// A frame as the display shows it: rows from the top, RGBA.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    /// How many have been posted, this one included.
    pub number: u64,
}

pub type Sink = Box<dyn FnMut(&Frame) + Send>;

const VERTEX_SHADER: &str = "attribute vec4 position;\n\
attribute vec2 inCoord;\n\
varying vec2 outCoord;\n\
uniform vec2 translation;\n\
uniform vec2 scale;\n\
uniform vec2 coordTranslation;\n\
uniform vec2 coordScale;\n\
void main(void) {\n\
  gl_Position.xy = position.xy * scale.xy - translation.xy;\n\
  gl_Position.zw = position.zw;\n\
  outCoord = inCoord * coordScale + coordTranslation;\n\
}\n";

const FRAGMENT_SHADER: &str = "#define kComposeModeDevice 2\n\
precision mediump float;\n\
varying lowp vec2 outCoord;\n\
uniform sampler2D tex;\n\
uniform float alpha;\n\
uniform int composeMode;\n\
uniform vec4 color ;\n\
void main(void) {\n\
  if (composeMode == kComposeModeDevice) {\n\
    gl_FragColor = alpha * texture2D(tex, outCoord);\n\
  } else {\n\
    gl_FragColor = alpha * color;\n\
  }\n\
}\n";

/// Position (x, y, z) and texture coordinate (s, t) of each corner, for
/// each transform (`kVertices`).
#[rustfmt::skip]
const VERTICES: [[f32; 5]; 32] = [
    // 0 degree
    [1., -1., 0., 1., 0.], [1., 1., 0., 1., 1.], [-1., 1., 0., 0., 1.], [-1., -1., 0., 0., 0.],
    // 90 degree clock-wise
    [1., -1., 0., 1., 1.], [1., 1., 0., 0., 1.], [-1., 1., 0., 0., 0.], [-1., -1., 0., 1., 0.],
    // 180 degree clock-wise
    [1., -1., 0., 0., 1.], [1., 1., 0., 0., 0.], [-1., 1., 0., 1., 0.], [-1., -1., 0., 1., 1.],
    // 270 degree clock-wise
    [1., -1., 0., 0., 0.], [1., 1., 0., 1., 0.], [-1., 1., 0., 1., 1.], [-1., -1., 0., 0., 1.],
    // flip horizontally
    [1., -1., 0., 0., 0.], [1., 1., 0., 0., 1.], [-1., 1., 0., 1., 1.], [-1., -1., 0., 1., 0.],
    // flip vertically
    [1., -1., 0., 1., 1.], [1., 1., 0., 1., 0.], [-1., 1., 0., 0., 0.], [-1., -1., 0., 0., 1.],
    // flip horizontally, then rotate 90 degrees clock-wise
    [1., -1., 0., 0., 1.], [1., 1., 0., 1., 1.], [-1., 1., 0., 1., 0.], [-1., -1., 0., 0., 0.],
    // flip vertically, then rotate 90 degrees clock-wise
    [1., -1., 0., 1., 0.], [1., 1., 0., 0., 0.], [-1., 1., 0., 0., 1.], [-1., -1., 0., 1., 1.],
];

const INDICES: [u8; 48] = [0, 1, 2, 2, 3, 0, 4, 5, 6, 6, 7, 4, 8, 9, 10, 10, 11, 8, 12, 13, 14, 14, 15, 12, 16, 17, 18, 18, 19, 16, 20, 21, 22, 22, 23, 20, 24, 25, 26, 26, 27, 24, 28, 29, 30, 30, 31, 28];

/// Which six indices draw a transform (`HWC_TRANSFORM_*`).
fn index_shift(transform: u32) -> usize {
    6 * match transform {
        4 => 1, // ROT_90
        3 => 2, // ROT_180
        7 => 3, // ROT_270
        1 => 4, // FLIP_H
        2 => 5, // FLIP_V
        5 => 6, // FLIP_H_ROT_90
        6 => 7, // FLIP_V_ROT_90
        _ => 0,
    }
}

/// The compositor's program and buffers on the root context, and where its
/// uniforms are.
pub struct Drawer {
    program: u32,
    vertices: u32,
    indices: u32,
    fbo: u32,
    position: i32,
    in_coord: i32,
    alpha: i32,
    mode: i32,
    color: i32,
    coord_translation: i32,
    coord_scale: i32,
    scale: i32,
    translation: i32,
    tex: i32,
}

fn shader(f: &Fns, kind: u32, source: &str) -> Result<u32, String> {
    unsafe {
        let s = (f.glCreateShader)(kind);
        let p = source.as_ptr();
        let n = source.len() as i32;
        (f.glShaderSource)(s, 1, &p, &n);
        (f.glCompileShader)(s);
        let mut ok = 0;
        (f.glGetShaderiv)(s, gl::GL_COMPILE_STATUS, &mut ok);
        if ok == 0 {
            let mut log = vec![0u8; 1024];
            let mut len = 0;
            (f.glGetShaderInfoLog)(s, log.len() as i32, &mut len, log.as_mut_ptr());
            return Err(String::from_utf8_lossy(&log[..len.max(0) as usize]).into_owned());
        }
        Ok(s)
    }
}

impl Drawer {
    /// Made on the root context, which is current.
    fn new(f: &Fns) -> Result<Drawer, String> {
        unsafe {
            let vs = shader(f, gl::GL_VERTEX_SHADER, VERTEX_SHADER)?;
            let fs = shader(f, gl::GL_FRAGMENT_SHADER, FRAGMENT_SHADER)?;
            let program = (f.glCreateProgram)();
            (f.glAttachShader)(program, vs);
            (f.glAttachShader)(program, fs);
            (f.glLinkProgram)(program);
            let mut ok = 0;
            (f.glGetProgramiv)(program, gl::GL_LINK_STATUS, &mut ok);
            if ok == 0 {
                return Err("the compositor's program did not link".into());
            }
            let at = |n: &str| (f.glGetAttribLocation)(program, format!("{n}\0").as_ptr());
            let un = |n: &str| (f.glGetUniformLocation)(program, format!("{n}\0").as_ptr());
            let mut d = Drawer {
                program,
                vertices: 0,
                indices: 0,
                fbo: 0,
                position: at("position"),
                in_coord: at("inCoord"),
                alpha: un("alpha"),
                mode: un("composeMode"),
                color: un("color"),
                coord_translation: un("coordTranslation"),
                coord_scale: un("coordScale"),
                scale: un("scale"),
                translation: un("translation"),
                tex: un("tex"),
            };
            (f.glGenBuffers)(1, &mut d.vertices);
            (f.glBindBuffer)(gl::GL_ARRAY_BUFFER, d.vertices);
            (f.glBufferData)(gl::GL_ARRAY_BUFFER, std::mem::size_of_val(&VERTICES) as isize, VERTICES.as_ptr().cast(), gl::GL_STATIC_DRAW);
            (f.glGenBuffers)(1, &mut d.indices);
            (f.glBindBuffer)(gl::GL_ELEMENT_ARRAY_BUFFER, d.indices);
            (f.glBufferData)(gl::GL_ELEMENT_ARRAY_BUFFER, INDICES.len() as isize, INDICES.as_ptr().cast(), gl::GL_STATIC_DRAW);
            (f.glGenFramebuffers)(1, &mut d.fbo);
            Ok(d)
        }
    }

    /// `TextureDraw`'s state for drawing layers (its constructor's uniforms,
    /// `preDrawLayer`'s bindings).
    fn prepare(&self, f: &Fns) {
        unsafe {
            (f.glUseProgram)(self.program);
            (f.glBindBuffer)(gl::GL_ARRAY_BUFFER, self.vertices);
            (f.glBindBuffer)(gl::GL_ELEMENT_ARRAY_BUFFER, self.indices);
            (f.glEnableVertexAttribArray)(self.position as u32);
            (f.glVertexAttribPointer)(self.position as u32, 3, gl::GL_FLOAT, 0, 20, std::ptr::null());
            (f.glEnableVertexAttribArray)(self.in_coord as u32);
            (f.glVertexAttribPointer)(self.in_coord as u32, 2, gl::GL_FLOAT, 0, 20, 12 as *const _);
            (f.glUniform1f)(self.alpha, 1.0);
            (f.glUniform1i)(self.mode, DEVICE as i32);
            (f.glUniform2f)(self.translation, 0.0, 0.0);
            (f.glUniform2f)(self.scale, 1.0, 1.0);
            (f.glUniform2f)(self.coord_translation, 0.0, 0.0);
            (f.glUniform2f)(self.coord_scale, 1.0, 1.0);
            (f.glActiveTexture)(gl::GL_TEXTURE0);
            (f.glUniform1i)(self.tex, 0);
            (f.glEnable)(gl::GL_BLEND);
            (f.glBlendFunc)(gl::GL_ONE, gl::GL_ONE_MINUS_SRC_ALPHA);
        }
    }

    /// `TextureDraw::drawLayer`: a source of `cb_w` by `cb_h` (1 by 1 for a
    /// colour) into a target of `fw` by `fh`.
    fn layer(&self, f: &Fns, l: &Layer, fw: i32, fh: i32, cb_w: f32, cb_h: f32, texture: u32) {
        unsafe {
            match l.mode {
                DEVICE => (f.glBindTexture)(gl::GL_TEXTURE_2D, texture),
                SOLID_COLOR => {
                    (f.glUniform1i)(self.mode, SOLID_COLOR as i32);
                    let c = |i: usize| l.color[i] as f32 / 255.0;
                    (f.glUniform4f)(self.color, c(0), c(1), c(2), c(3));
                }
                m => {
                    eprintln!("[gex] gfxstream: a layer of composition mode {m} is not composed (gfxstream's host refuses it)");
                    return;
                }
            }
            match l.blend {
                BLEND_NONE => (f.glDisable)(gl::GL_BLEND),
                BLEND_PREMULTIPLIED => {}
                b => {
                    eprintln!("[gex] gfxstream: a layer of blend mode {b} is not composed (gfxstream's host refuses it)");
                    return;
                }
            }
            (f.glUniform1f)(self.alpha, l.alpha);
            let (fw, fh) = (fw as f64, fh as f64);
            let e = [
                1.0 - 2.0 * (fw - l.frame[0] as f64) / fw,
                1.0 - 2.0 * (fh - l.frame[1] as f64) / fh,
                1.0 - 2.0 * (fw - l.frame[2] as f64) / fw,
                1.0 - 2.0 * (fh - l.frame[3] as f64) / fh,
            ];
            let c = [l.crop[0] / cb_w, l.crop[1] / cb_h, l.crop[2] / cb_w, l.crop[3] / cb_h];
            (f.glUniform2f)(self.translation, ((-e[2] - e[0]) / 2.0) as f32, ((-e[3] - e[1]) / 2.0) as f32);
            (f.glUniform2f)(self.scale, ((e[2] - e[0]) / 2.0) as f32, ((e[1] - e[3]) / 2.0) as f32);
            (f.glUniform2f)(self.coord_translation, c[0], c[3]);
            (f.glUniform2f)(self.coord_scale, c[2] - c[0], c[1] - c[3]);
            (f.glDrawElements)(gl::GL_TRIANGLES, 6, gl::GL_UNSIGNED_BYTE, index_shift(l.transform) as *const _);
            if l.mode != DEVICE {
                (f.glUniform1i)(self.mode, DEVICE as i32);
            }
            if l.blend != BLEND_PREMULTIPLIED {
                (f.glEnable)(gl::GL_BLEND);
                (f.glBlendFunc)(gl::GL_ONE, gl::GL_ONE_MINUS_SRC_ALPHA);
            }
        }
    }
}

impl Renderer {
    /// `FrameBuffer::compose`: the layers drawn into the target, then, if
    /// asked and for display 0, the target posted. Whether it was done.
    pub fn compose(&mut self, buf: &[u8], post: bool) -> bool {
        let Some(req) = Request::parse(buf) else {
            eprintln!("[gex] gfxstream: a compose request of version {:?} or too short", u32_at(buf, 0));
            return false;
        };
        if req.display != 0 {
            eprintln!("[gex] gfxstream: composing for display {}: only display 0 is here", req.display);
            return false;
        }
        let Some(target) = self.objects.color_buffers.get(&req.target) else {
            eprintln!("[gex] gfxstream: composing into color buffer {}, which is not there", req.target);
            return false;
        };
        let (tw, th, ttex) = (target.width as i32, target.height as i32, target.tex);
        let sources: Vec<(f32, f32, u32)> = req
            .layers
            .iter()
            .map(|l| match (l.mode, self.objects.color_buffers.get(&l.color_buffer)) {
                (DEVICE, Some(c)) => (c.width as f32, c.height as f32, c.tex),
                (DEVICE, None) => {
                    eprintln!("[gex] gfxstream: a layer's color buffer {} is not there", l.color_buffer);
                    (1.0, 1.0, 0)
                }
                _ => (1.0, 1.0, 0),
            })
            .collect();
        let mut drawer = self.drawer.take();
        let done = self.with_root(|f| unsafe {
            if drawer.is_none() {
                match Drawer::new(f) {
                    Ok(d) => drawer = Some(d),
                    Err(e) => {
                        eprintln!("[gex] gfxstream: the compositor could not be made: {e}");
                        return false;
                    }
                }
            }
            let d = drawer.as_ref().unwrap();
            let mut viewport = [0i32; 4];
            (f.glGetIntegerv)(gl::GL_VIEWPORT, viewport.as_mut_ptr());
            (f.glViewport)(0, 0, tw, th);
            (f.glBindFramebuffer)(gl::GL_FRAMEBUFFER, d.fbo);
            (f.glFramebufferTexture2D)(gl::GL_FRAMEBUFFER, gl::GL_COLOR_ATTACHMENT0, gl::GL_TEXTURE_2D, ttex, 0);
            d.prepare(f);
            (f.glClear)(gl::GL_COLOR_BUFFER_BIT | gl::GL_DEPTH_BUFFER_BIT);
            for (l, &(w, h, tex)) in req.layers.iter().zip(&sources) {
                d.layer(f, l, tw, th, w, h, tex);
            }
            (f.glBindFramebuffer)(gl::GL_FRAMEBUFFER, 0);
            (f.glViewport)(viewport[0], viewport[1], viewport[2], viewport[3]);
            (f.glFlush)();
            true
        });
        self.drawer = drawer;
        if done != Some(true) {
            return false;
        }
        if post {
            self.post(req.target);
        }
        true
    }

    /// `rcFBPost`: the color buffer is the display's frame. The one shown is
    /// held until another is.
    pub fn post(&mut self, handle: u32) {
        let Some(c) = self.objects.color_buffers.get_mut(&handle) else {
            eprintln!("[gex] gfxstream: posting color buffer {handle}, which is not there");
            return;
        };
        c.hold(true);
        let (w, h) = (c.width, c.height);
        let old = std::mem::replace(&mut self.shown, handle);
        if old != 0 {
            if let Some(o) = self.objects.color_buffers.get_mut(&old) {
                o.hold(false);
            }
            self.free_if_unused(old);
        }
        self.posts += 1;
        if self.sink.is_none() {
            return;
        }
        let rgba = self.read_color_buffer(handle, 0, 0, w as i32, h as i32, gl::GL_RGBA, gl::GL_UNSIGNED_BYTE, (w * h * 4) as usize);
        let frame = Frame { width: w, height: h, rgba, number: self.posts };
        if let Some(s) = self.sink.as_mut() {
            s(&frame);
        }
    }

    /// Where posted frames go.
    pub fn set_sink(&mut self, sink: Sink) {
        self.sink = Some(sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_read_as_the_guests_composer_writes_them() {
        let mut b = Vec::new();
        for w in [2u32, 0, 7, 1] {
            b.extend_from_slice(&w.to_le_bytes());
        }
        let mut l = Vec::new();
        for w in [9u32, 2, 1, 2, 30, 40] {
            l.extend_from_slice(&w.to_le_bytes());
        }
        for f in [0.5f32, 1.0, 16.0, 17.0] {
            l.extend_from_slice(&f.to_le_bytes());
        }
        l.extend_from_slice(&2u32.to_le_bytes());
        l.extend_from_slice(&0.75f32.to_le_bytes());
        l.extend_from_slice(&[1, 2, 3, 4]);
        l.extend_from_slice(&4u32.to_le_bytes());
        assert_eq!(l.len(), LAYER_BYTES);
        b.extend_from_slice(&l);
        let r = Request::parse(&b).unwrap();
        assert_eq!((r.version, r.display, r.target), (2, 0, 7));
        assert_eq!(r.layers, vec![Layer { color_buffer: 9, mode: 2, frame: [1, 2, 30, 40], crop: [0.5, 1.0, 16.0, 17.0], blend: 2, alpha: 0.75, color: [1, 2, 3, 4], transform: 4 }]);
        assert!(Request::parse(&b[..b.len() - 1]).is_none());
        b[0] = 3;
        assert!(Request::parse(&b).is_none());
        assert_eq!(index_shift(4), 6);
        assert_eq!(index_shift(6), 42);
    }
}
