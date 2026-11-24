//! Color buffers of a YUV framework format (gfxstream's `YUVConverter`):
//! the guest uploads the whole frame in the layout `getYUVOffsets` gives
//! (Android's: luma rows aligned to 16 pixels for YV12, the rest packed),
//! and it is made RGB, as gfxstream's default shader makes it (limited
//! range, BT.601: `kFragShaderMain_2_4_3`), with each chroma sample
//! covering two by two pixels (the planes are sampled nearest). The bytes
//! as uploaded are kept for reads (`rcReadColorBufferYUV`, the YUV cache).
//!
//! YUV_420_888 is planar here, U before V: the host does not offer the
//! guest its NV21 layout (`ANDROID_EMU_YUV420_888_to_NV21`).

/// `FrameworkFormat`.
pub const YV12: u32 = 1;
pub const YUV_420_888: u32 = 2;
pub const NV12: u32 = 3;
pub const P010: u32 = 4;

/// Where a plane's samples are: its offset, the bytes a row takes, and the
/// bytes from one sample to the next in a row (2 for an interleaved plane's
/// own, or a 16-bit one's).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Plane {
    offset: usize,
    stride: usize,
    step: usize,
}

/// The planes of a frame: luma, U, V, and the bytes it all takes.
fn layout(format: u32, w: usize, h: usize) -> Option<(Plane, Plane, Plane, usize)> {
    let align = |v: usize, a: usize| (v + a - 1) & !(a - 1);
    let (y, u, v) = match format {
        YV12 => {
            let ys = align(w, 16);
            let cs = align(ys / 2, 16);
            let vo = ys * h;
            let uo = vo + cs * (h / 2);
            (Plane { offset: 0, stride: ys, step: 1 }, Plane { offset: uo, stride: cs, step: 1 }, Plane { offset: vo, stride: cs, step: 1 })
        }
        YUV_420_888 => {
            let uo = w * h;
            let vo = uo + (w / 2) * (h / 2);
            (Plane { offset: 0, stride: w, step: 1 }, Plane { offset: uo, stride: w / 2, step: 1 }, Plane { offset: vo, stride: w / 2, step: 1 })
        }
        // The chroma rows interleave U and V; their stride is in pairs.
        NV12 => {
            let uo = w * h;
            (Plane { offset: 0, stride: w, step: 1 }, Plane { offset: uo, stride: w, step: 2 }, Plane { offset: uo + 1, stride: w, step: 2 })
        }
        P010 => {
            let uo = w * h * 2;
            (Plane { offset: 0, stride: w * 2, step: 2 }, Plane { offset: uo, stride: w * 2, step: 4 }, Plane { offset: uo + 2, stride: w * 2, step: 4 })
        }
        _ => return None,
    };
    let end = |p: Plane, rows: usize, cols: usize| if rows == 0 || cols == 0 { 0 } else { p.offset + p.stride * (rows - 1) + p.step * (cols - 1) + if format == P010 { 2 } else { 1 } };
    let size = end(y, h, w).max(end(u, h / 2, w / 2)).max(end(v, h / 2, w / 2));
    Some((y, u, v, size))
}

/// The bytes a frame of the format takes (`YUVConverter::getDataSize`'s).
pub fn data_size(format: u32, w: u32, h: u32) -> Option<usize> {
    layout(format, w as usize, h as usize).map(|l| l.3)
}

fn sample(data: &[u8], p: Plane, x: usize, y: usize, ten_bit: bool) -> f64 {
    let at = p.offset + p.stride * y + p.step * x;
    if ten_bit {
        let v = u16::from_le_bytes([data.get(at).copied().unwrap_or(0), data.get(at + 1).copied().unwrap_or(0)]);
        (v >> 6) as f64 / 1023.0
    } else {
        data.get(at).copied().unwrap_or(0) as f64 / 255.0
    }
}

/// The frame as RGBA rows, from the first row.
pub fn to_rgba(format: u32, w: u32, h: u32, data: &[u8]) -> Option<Vec<u8>> {
    let (w, h) = (w as usize, h as usize);
    let (yp, up, vp, _) = layout(format, w, h)?;
    let ten = format == P010;
    let mut out = vec![0u8; w * h * 4];
    let q = |c: f64| (c.clamp(0.0, 1.0) * 255.0).round() as u8;
    for row in 0..h {
        for col in 0..w {
            let y = sample(data, yp, col, row, ten) - 0.0625;
            let u = sample(data, up, col / 2, row / 2, ten) - 0.5;
            let v = sample(data, vp, col / 2, row / 2, ten) - 0.5;
            let ys = 1.1643835616438356 * y;
            let r = ys + 1.5960267857142856 * v;
            let g = ys - 0.39176229009491365 * u - 0.8129676472377708 * v;
            let b = ys + 2.017232142857143 * u;
            let o = (row * w + col) * 4;
            out[o..o + 4].copy_from_slice(&[q(r), q(g), q(b), 255]);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_androids() {
        // YV12 4x2: luma rows of 16, chroma rows of 16; V then U.
        assert_eq!(data_size(YV12, 4, 2), Some(16 * 2 + 16 + 2));
        assert_eq!(data_size(YUV_420_888, 4, 2), Some(8 + 2 + 2));
        assert_eq!(data_size(NV12, 4, 2), Some(8 + 4));
        assert_eq!(data_size(P010, 4, 2), Some(16 + 8));
        assert_eq!(data_size(0, 4, 2), None);
    }

    #[test]
    fn black_white_and_red_are_the_shaders() {
        // I420 2x2 of one colour: Y, then U, then V.
        let rgb = |y: u8, u: u8, v: u8| to_rgba(YUV_420_888, 2, 2, &[y, y, y, y, u, v]).unwrap()[..4].to_vec();
        // The shader centres chroma at 0.5, and 128/255 is a little past
        // it: its black and white are not quite.
        assert_eq!(rgb(16, 128, 128), [1, 0, 1, 255]);
        assert_eq!(rgb(235, 128, 128), [255, 254, 255, 255]);
        assert_eq!(rgb(81, 90, 240), [255, 0, 0, 255]);
        // YV12 puts V first.
        let mut yv = vec![81u8; 16 * 2];
        yv.extend([240u8; 16]);
        yv.extend([90u8; 16]);
        assert_eq!(to_rgba(YV12, 2, 2, &yv).unwrap()[..4], [255, 0, 0, 255]);
    }
}
