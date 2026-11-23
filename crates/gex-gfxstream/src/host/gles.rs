//! The OpenGL ES decoders (gfxstream's generated `gles1_dec`/`gles2_dec` and
//! the hand-written `GLESv2Decoder`): a call is run on the host's OpenGL ES
//! with the stream's context current.
//!
//! Most calls are the host's function of the same name, called with the
//! wire's values as their C types (`calls.rs`, made by `build.rs`), every
//! pointer the call's bytes (never null, but for a `nullAllowed` one sent
//! with none), an `out` pointer a zeroed buffer as long as the guest's, its
//! bytes the answer. Calls gfxstream decodes by hand only to note them for
//! its snapshots are the same here.
//!
//! The rest have meanings of gfxstream's own, ported below: client arrays
//! sent as data (`*Data`) kept with the context until drawn, buffer
//! offsets sent for pointers (`*Offset`), shader strings, mapped buffers
//! copied each way, syncs by handle, packed name lists. GLES 1's client
//! arrays are not done yet and say so.

use super::{not_yet, Thread};
use crate::{Arg, Call, Entry};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

mod calls {
    use std::ffi::c_void;
    include!(concat!(env!("OUT_DIR"), "/calls.rs"));
}

/// Bytes kept where the host's functions may read any type from them.
pub(super) struct Buf {
    words: Vec<u64>,
    len: usize,
}

impl Buf {
    fn zeroed(len: usize) -> Buf {
        Buf { words: vec![0; len.div_ceil(8).max(1)], len }
    }

    pub(super) fn from(b: &[u8]) -> Buf {
        let mut x = Buf::zeroed(b.len());
        x.bytes_mut().copy_from_slice(b);
        x
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `words` holds at least `len` bytes.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.len) }
    }

    fn addr(&mut self) -> u64 {
        self.words.as_mut_ptr() as u64
    }
}

/// Room past an `out` buffer, in case the host writes more than the guest
/// asked for (a query whose answer has more values on this host).
const SLACK: usize = 256;

/// The host's entry point for a name, looked up once.
fn host_fn(name: &'static str) -> *mut c_void {
    static FNS: Mutex<Option<HashMap<&'static str, usize>>> = Mutex::new(None);
    let mut m = FNS.lock().unwrap_or_else(|e| e.into_inner());
    *m.get_or_insert_with(HashMap::new).entry(name).or_insert_with(|| super::egl::proc_address(name) as usize) as *mut c_void
}

/// The opcode of a name in an API.
fn opcode(api: &'static crate::Api, name: &str) -> Option<u32> {
    api.entries.iter().position(|e| e.name == name).map(|i| api.base + i as u32)
}

fn api_of(call: &Call<'_>) -> &'static crate::Api {
    if call.api == "gles1" {
        &crate::GLES1
    } else {
        &crate::GLES2
    }
}

/// Calls the host's `name` (of the call's API) with wire values.
fn forward(call: &Call<'_>, name: &'static str, v: &[u64]) -> Option<u64> {
    let op = opcode(api_of(call), name)?;
    let f = host_fn(name);
    if f.is_null() {
        not_yet(name);
        return None;
    }
    // SAFETY: `f` is the host's function of that name, whose C types the
    // generated call passes.
    let r = unsafe { calls::call(op, f, v) };
    if r.is_none() {
        not_yet(name);
    }
    r
}

fn value(a: &Arg<'_>) -> u64 {
    match a {
        Arg::Value(v) => *v,
        _ => 0,
    }
}

fn bytes<'a>(a: &Arg<'a>) -> &'a [u8] {
    match a {
        Arg::In(d) | Arg::InOut(d) => d,
        _ => &[],
    }
}

fn out_len(a: &Arg<'_>) -> usize {
    match a {
        Arg::Out(n) => *n as usize,
        _ => 0,
    }
}

/// `sUnpackVarNames`: `count` names, each ended by ';', as C strings.
fn unpack_names(count: i32, packed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = packed;
    for _ in 0..count.max(0) {
        let end = rest.iter().position(|&b| b == b';').unwrap_or(rest.len());
        let mut name = rest[..end].to_vec();
        name.push(0);
        out.push(name);
        rest = rest.get(end + 1..).unwrap_or(&[]);
    }
    out
}

const GL_MAP_READ_BIT: u32 = 0x0001;
const GL_MAP_WRITE_BIT: u32 = 0x0002;
const GL_MAP_INVALIDATE_RANGE_BIT: u32 = 0x0004;
const GL_MAP_INVALIDATE_BUFFER_BIT: u32 = 0x0008;
const GL_NUM_COMPRESSED_TEXTURE_FORMATS: u32 = 0x86A2;
const GL_COMPRESSED_TEXTURE_FORMATS: u32 = 0x86A3;
const GL_ELEMENT_ARRAY_BUFFER_BINDING: u32 = 0x8895;
const GL_MAX_VERTEX_ATTRIBS: u32 = 0x8869;
const GL_VERTEX_ATTRIB_ARRAY_ENABLED: u32 = 0x8622;
const GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING: u32 = 0x889F;

type MapRange = unsafe extern "C" fn(u32, isize, isize, u32) -> *mut c_void;
type Unmap = unsafe extern "C" fn(u32) -> u8;
type FlushRange = unsafe extern "C" fn(u32, isize, isize);
type GetIntegerv = unsafe extern "C" fn(u32, *mut i32);

fn f<T: Copy>(name: &'static str) -> Option<T> {
    let p = host_fn(name);
    if p.is_null() {
        not_yet(name);
        return None;
    }
    // SAFETY: T is the function type of `name`, as the callers name it.
    Some(unsafe { std::mem::transmute_copy(&p) })
}

fn integer(name: u32) -> i32 {
    let mut v = 0;
    if let Some(g) = f::<GetIntegerv>("glGetIntegerv") {
        unsafe { g(name, &mut v) };
    }
    v
}

/// The wire's 32-bit pointer-sized integer, as the host's.
fn word(v: u64) -> isize {
    v as u32 as i32 as isize
}

impl Thread {
    /// One OpenGL ES call: its answer, if it has one.
    pub(super) fn gles(&mut self, call: &Call<'_>, entry: &'static Entry) -> Option<Vec<u8>> {
        if let Some(a) = self.gles_by_hand(call, entry) {
            return a;
        }
        let mut v = Vec::with_capacity(call.args.len());
        let mut bufs: Vec<Buf> = Vec::new();
        let mut outs: Vec<usize> = Vec::new();
        for (p, a) in entry.params.iter().zip(&call.args) {
            match a {
                Arg::Value(x) => v.push(*x),
                Arg::In(d) if d.is_empty() && p.null_allowed => v.push(0),
                Arg::Out(0) if p.null_allowed => {
                    v.push(0);
                    outs.push(usize::MAX);
                }
                Arg::In(d) => {
                    let mut b = Buf::from(d);
                    v.push(b.addr());
                    bufs.push(b);
                }
                Arg::InOut(d) => {
                    let mut b = Buf::from(d);
                    v.push(b.addr());
                    outs.push(bufs.len());
                    bufs.push(b);
                }
                Arg::Out(n) => {
                    let mut b = Buf::zeroed(*n as usize + SLACK);
                    b.len = *n as usize;
                    v.push(b.addr());
                    outs.push(bufs.len());
                    bufs.push(b);
                }
            }
        }
        let name = entry.name;
        let fun = host_fn(name);
        let ret = if fun.is_null() {
            None
        } else {
            // SAFETY: the host's function of this call's name, given the
            // wire's values as its C types; every pointer is to a buffer
            // alive until it returns.
            unsafe { calls::call(call.opcode, fun, &v) }
        };
        let Some(ret) = ret else {
            not_yet(name);
            return entry.answers().then(|| crate::answer(entry, call, &[], 0));
        };
        if !entry.answers() {
            return None;
        }
        let empty: &[u8] = &[];
        let slices: Vec<&[u8]> = outs.iter().map(|&i| if i == usize::MAX { empty } else { bufs[i].bytes() }).collect();
        Some(crate::answer(entry, call, &slices, ret))
    }

    /// gfxstream's own calls. `None`: not one of them.
    fn gles_by_hand(&mut self, call: &Call<'_>, entry: &'static Entry) -> Option<Option<Vec<u8>>> {
        let a = &call.args;
        let v = |i: usize| value(&a[i]);
        let reply = |outs: &[&[u8]], ret: u64| Some(crate::answer(entry, call, outs, ret));
        let gles2 = call.api == "gles2";
        Some(match call.name {
            "glFinishRoundTrip" => {
                forward(call, "glFinish", &[]);
                reply(&[], 0)
            }
            "glGetCompressedTextureFormats" => {
                let count = v(0) as i32;
                let mut formats = vec![0i32; count.max(0) as usize + SLACK];
                if integer(GL_NUM_COMPRESSED_TEXTURE_FORMATS) > count {
                    eprintln!("[gex] gfxstream: glGetCompressedTextureFormats: the guest asked for fewer formats than the host has");
                } else if let Some(g) = f::<GetIntegerv>("glGetIntegerv") {
                    unsafe { g(GL_COMPRESSED_TEXTURE_FORMATS, formats.as_mut_ptr()) };
                }
                let b: Vec<u8> = formats.iter().flat_map(|x| x.to_le_bytes()).collect();
                reply(&[&b], 0)
            }
            "glShaderString" if gles2 => {
                // One string, ended by its NUL (the length is not passed).
                let mut s = bytes(&a[1]).to_vec();
                if s.last() != Some(&0) {
                    s.push(0);
                }
                let p = s.as_ptr();
                forward(call, "glShaderSource", &[v(0), 1, &p as *const _ as u64, 0]);
                None
            }
            "glVertexAttribPointerData" | "glVertexAttribIPointerDataAEMU" if gles2 => {
                let int = call.name != "glVertexAttribPointerData";
                let (data_at, index) = (if int { 4 } else { 5 }, v(0) as u32);
                let addr = self.keep_array(index, bytes(&a[data_at]));
                if int {
                    forward(call, "glVertexAttribIPointer", &[v(0), v(1), v(2), 0, addr]);
                } else {
                    forward(call, "glVertexAttribPointer", &[v(0), v(1), v(2), v(3), 0, addr]);
                }
                None
            }
            "glVertexAttribPointerOffset" => {
                forward(call, "glVertexAttribPointer", &[v(0), v(1), v(2), v(3), v(4), v(5)]);
                None
            }
            "glVertexAttribIPointerOffsetAEMU" => {
                forward(call, "glVertexAttribIPointer", &[v(0), v(1), v(2), v(3), v(4)]);
                None
            }
            "glDrawElementsData" | "glDrawElementsInstancedDataAEMU" | "glDrawRangeElementsDataAEMU" | "glDrawArraysIndirectDataAEMU" | "glDrawElementsIndirectDataAEMU" if gles2 => {
                let mut b = Buf::from(bytes(&a[match call.name {
                    "glDrawElementsData" | "glDrawElementsInstancedDataAEMU" => 3,
                    "glDrawRangeElementsDataAEMU" => 5,
                    "glDrawArraysIndirectDataAEMU" => 1,
                    _ => 2,
                }]));
                let p = b.addr();
                match call.name {
                    "glDrawElementsData" => forward(call, "glDrawElements", &[v(0), v(1), v(2), p]),
                    "glDrawElementsInstancedDataAEMU" => forward(call, "glDrawElementsInstanced", &[v(0), v(1), v(2), p, v(4)]),
                    "glDrawRangeElementsDataAEMU" => forward(call, "glDrawRangeElements", &[v(0), v(1), v(2), v(3), v(4), p]),
                    "glDrawArraysIndirectDataAEMU" => forward(call, "glDrawArraysIndirect", &[v(0), p]),
                    _ => forward(call, "glDrawElementsIndirect", &[v(0), v(1), p]),
                };
                None
            }
            "glDrawElementsOffset" => {
                forward(call, "glDrawElements", &[v(0), v(1), v(2), v(3)]);
                None
            }
            "glDrawElementsInstancedOffsetAEMU" => {
                forward(call, "glDrawElementsInstanced", &[v(0), v(1), v(2), v(3), v(4)]);
                None
            }
            "glDrawRangeElementsOffsetAEMU" => {
                forward(call, "glDrawRangeElements", &[v(0), v(1), v(2), v(3), v(4), v(5)]);
                None
            }
            "glDrawArraysIndirectOffsetAEMU" => {
                forward(call, "glDrawArraysIndirect", &[v(0), v(1)]);
                None
            }
            "glDrawElementsIndirectOffsetAEMU" => {
                forward(call, "glDrawElementsIndirect", &[v(0), v(1), v(2)]);
                None
            }
            // A buffer offset in place of the last pointer.
            "glReadPixelsOffsetAEMU" | "glTexImage2DOffsetAEMU" | "glTexSubImage2DOffsetAEMU" | "glCompressedTexImage2DOffsetAEMU" | "glCompressedTexSubImage2DOffsetAEMU" | "glTexImage3DOffsetAEMU" | "glTexSubImage3DOffsetAEMU" | "glCompressedTexImage3DOffsetAEMU" | "glCompressedTexSubImage3DOffsetAEMU" => {
                let base = call.name.trim_end_matches("OffsetAEMU");
                let base = crate::GLES2.entries.iter().find(|e| e.name == base).map(|e| e.name)?;
                let vals: Vec<u64> = a.iter().map(value).collect();
                forward(call, base, &vals);
                None
            }
            "glDrawArraysNullAEMU" | "glDrawElementsNullAEMU" | "glDrawElementsOffsetNullAEMU" | "glDrawElementsDataNullAEMU" => {
                self.null_draw(call);
                None
            }
            "glGetUniformIndicesAEMU" => {
                let names = unpack_names(v(1) as i32, bytes(&a[2]));
                let ptrs: Vec<*const u8> = names.iter().map(|n| n.as_ptr()).collect();
                let mut out = Buf::zeroed(out_len(&a[4]) + SLACK);
                out.len = out_len(&a[4]);
                forward(call, "glGetUniformIndices", &[v(0), v(1), ptrs.as_ptr() as u64, out.addr()]);
                reply(&[out.bytes()], 0)
            }
            "glTransformFeedbackVaryingsAEMU" => {
                let names = unpack_names(v(1) as i32, bytes(&a[2]));
                let ptrs: Vec<*const u8> = names.iter().map(|n| n.as_ptr()).collect();
                forward(call, "glTransformFeedbackVaryings", &[v(0), v(1), ptrs.as_ptr() as u64, v(4)]);
                None
            }
            "glCreateShaderProgramvAEMU" => {
                let mut s = bytes(&a[2]).to_vec();
                if s.last() != Some(&0) {
                    s.push(0);
                }
                let p = s.as_ptr();
                let r = forward(call, "glCreateShaderProgramv", &[v(0), 1, &p as *const _ as u64]).unwrap_or(0);
                reply(&[], r)
            }
            "glMapBufferRangeAEMU" => {
                let (target, offset, length, access) = (v(0) as u32, word(v(1)), word(v(2)), v(3) as u32);
                let mut out = vec![0u8; out_len(&a[4])];
                let copy = access & GL_MAP_READ_BIT != 0 || (access & GL_MAP_WRITE_BIT != 0 && access & (GL_MAP_INVALIDATE_RANGE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT) == 0);
                if copy {
                    if let (Some(map), Some(unmap)) = (f::<MapRange>("glMapBufferRange"), f::<Unmap>("glUnmapBuffer")) {
                        let p = unsafe { map(target, offset, length, access) };
                        if p.is_null() {
                            eprintln!("[gex] gfxstream: glMapBufferRangeAEMU: the host buffer could not be mapped");
                        } else {
                            let n = (length.max(0) as usize).min(out.len());
                            unsafe { std::ptr::copy_nonoverlapping(p as *const u8, out.as_mut_ptr(), n) };
                            unsafe { unmap(target) };
                        }
                    }
                }
                reply(&[&out], 0)
            }
            "glUnmapBufferAEMU" | "glUnmapBufferAsyncAEMU" => {
                let (target, offset, length, access) = (v(0) as u32, word(v(1)), word(v(2)), v(3) as u32);
                let guest = bytes(&a[4]);
                let mut res = 1u8;
                if access & GL_MAP_WRITE_BIT != 0 && !guest.is_empty() {
                    if let (Some(map), Some(unmap)) = (f::<MapRange>("glMapBufferRange"), f::<Unmap>("glUnmapBuffer")) {
                        let p = unsafe { map(target, offset, length, access) };
                        if p.is_null() {
                            eprintln!("[gex] gfxstream: glUnmapBufferAEMU: the host buffer could not be mapped");
                        } else {
                            let n = (length.max(0) as usize).min(guest.len());
                            unsafe { std::ptr::copy_nonoverlapping(guest.as_ptr(), p as *mut u8, n) };
                            res = unsafe { unmap(target) };
                        }
                    }
                }
                if entry.answers() {
                    reply(&[&[res]], 0)
                } else {
                    None
                }
            }
            "glFlushMappedBufferRangeAEMU" | "glFlushMappedBufferRangeAEMU2" => {
                let (target, offset, length, access) = (v(0) as u32, word(v(1)), word(v(2)), v(3) as u32);
                let guest = bytes(&a[4]);
                if !guest.is_empty() {
                    if let (Some(map), Some(flush), Some(unmap)) = (f::<MapRange>("glMapBufferRange"), f::<FlushRange>("glFlushMappedBufferRange"), f::<Unmap>("glUnmapBuffer")) {
                        let p = unsafe { map(target, offset, length, access) };
                        if p.is_null() {
                            eprintln!("[gex] gfxstream: glFlushMappedBufferRangeAEMU: the host buffer could not be mapped");
                        } else {
                            let n = (length.max(0) as usize).min(guest.len());
                            unsafe {
                                std::ptr::copy_nonoverlapping(guest.as_ptr(), p as *mut u8, n);
                                flush(target, 0, length);
                                unmap(target);
                            }
                        }
                    }
                }
                None
            }
            "glBufferDataSyncAEMU" => {
                let data = bytes(&a[2]);
                let mut b = Buf::from(data);
                let p = if data.is_empty() { 0 } else { b.addr() };
                forward(call, "glBufferData", &[v(0), v(1), p, v(3)]);
                reply(&[], 1)
            }
            "glFenceSyncAEMU" => {
                type FenceSync = unsafe extern "C" fn(u32, u32) -> *mut c_void;
                let sync = f::<FenceSync>("glFenceSync").map(|g| unsafe { g(v(0) as u32, v(1) as u32) }).unwrap_or(std::ptr::null_mut());
                let handle = if sync.is_null() { 0 } else { self.renderer().add_sync(sync) };
                reply(&[], handle)
            }
            "glClientWaitSyncAEMU" => {
                type ClientWait = unsafe extern "C" fn(*mut c_void, u32, u64) -> u32;
                let sync = self.renderer().sync(v(0));
                let r = f::<ClientWait>("glClientWaitSync").map(|g| unsafe { g(sync, v(1) as u32, v(2)) }).unwrap_or(0x911D);
                reply(&[], r as u64)
            }
            "glWaitSyncAEMU" => {
                type Wait = unsafe extern "C" fn(*mut c_void, u32, u64);
                let sync = self.renderer().sync(v(0));
                if let Some(g) = f::<Wait>("glWaitSync") {
                    unsafe { g(sync, v(1) as u32, v(2)) };
                }
                None
            }
            "glDeleteSyncAEMU" => {
                type Delete = unsafe extern "C" fn(*mut c_void);
                let sync = self.renderer().remove_sync(v(0));
                if let Some(g) = f::<Delete>("glDeleteSync") {
                    unsafe { g(sync) };
                }
                None
            }
            "glIsSyncAEMU" => {
                type IsSync = unsafe extern "C" fn(*mut c_void) -> u8;
                let sync = self.renderer().sync(v(0));
                let r = f::<IsSync>("glIsSync").map(|g| unsafe { g(sync) }).unwrap_or(0);
                reply(&[], r as u64)
            }
            "glGetSyncivAEMU" => {
                type GetSynciv = unsafe extern "C" fn(*mut c_void, u32, i32, *mut i32, *mut i32);
                let sync = self.renderer().sync(v(0));
                let (nl, nv) = (out_len(&a[3]), out_len(&a[4]));
                let mut length = vec![0i32; nl.div_ceil(4).max(1)];
                let mut values = vec![0i32; nv.div_ceil(4) + SLACK];
                if let Some(g) = f::<GetSynciv>("glGetSynciv") {
                    let lp = if nl == 0 { std::ptr::null_mut() } else { length.as_mut_ptr() };
                    unsafe { g(sync, v(1) as u32, v(2) as i32, lp, values.as_mut_ptr()) };
                }
                let lb: Vec<u8> = length.iter().flat_map(|x| x.to_le_bytes()).collect();
                let vb: Vec<u8> = values.iter().flat_map(|x| x.to_le_bytes()).collect();
                reply(&[&lb, &vb], 0)
            }
            // GLES 1's client arrays and draws from them.
            n if call.api == "gles1" && entry.custom_decoder && (n.ends_with("PointerData") || n.ends_with("PointerOffset") || n.starts_with("glDrawElements")) => {
                not_yet(n);
                None
            }
            // An EGL image by the handle `rcCreateClientImage` gave; one it
            // never gave is null, which the host's GL refuses.
            "glEGLImageTargetTexture2DOES" | "glEGLImageTargetRenderbufferStorageOES" => {
                type Target = unsafe extern "C" fn(u32, *mut c_void);
                let image = self.renderer().image(v(1) as u32);
                if let Some(g) = f::<Target>(entry.name) {
                    unsafe { g(v(0) as u32, image) };
                }
                None
            }
            _ => return None,
        })
    }

    fn renderer(&self) -> std::sync::MutexGuard<'_, super::Renderer> {
        self.renderer.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Client-array data for attribute `index` kept with the current
    /// context until replaced (`storePointerData`): its address.
    fn keep_array(&mut self, index: u32, data: &[u8]) -> u64 {
        let mut r = self.renderer();
        let ctx = self.context;
        let Some(c) = r.objects.contexts.get_mut(&ctx) else {
            return 0;
        };
        let mut b = Buf::from(data);
        let addr = b.addr();
        c.arrays.insert(index, b);
        addr
    }

    /// `glDrawArraysNullAEMU` and `glDrawElementsNullAEMU` (gfxstream's
    /// translator): no draw when every enabled attribute (and, for
    /// elements, the indices) comes from a buffer; a draw otherwise, and for
    /// arguments the draw refuses, so that the error is the draw's.
    fn null_draw(&mut self, call: &Call<'_>) {
        let a = &call.args;
        let v = |i: usize| value(&a[i]);
        let elements = call.name != "glDrawArraysNullAEMU";
        type GetAttrib = unsafe extern "C" fn(u32, u32, *mut i32);
        let mut backed = !elements || integer(GL_ELEMENT_ARRAY_BUFFER_BINDING) != 0;
        if let Some(g) = f::<GetAttrib>("glGetVertexAttribiv") {
            for i in 0..integer(GL_MAX_VERTEX_ATTRIBS).max(0) as u32 {
                let (mut on, mut buf) = (0, 0);
                unsafe {
                    g(i, GL_VERTEX_ATTRIB_ARRAY_ENABLED, &mut on);
                    g(i, GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING, &mut buf);
                }
                if on != 0 && buf == 0 {
                    backed = false;
                }
            }
        }
        let count = v(1) as i32;
        if backed && count >= 0 {
            return;
        }
        match call.name {
            "glDrawArraysNullAEMU" => forward(call, "glDrawArrays", &[v(0), v(1), v(2)]),
            "glDrawElementsDataNullAEMU" => {
                let mut b = Buf::from(bytes(&a[3]));
                let p = b.addr();
                forward(call, "glDrawElements", &[v(0), v(1), v(2), p])
            }
            _ => forward(call, "glDrawElements", &[v(0), v(1), v(2), v(3)]),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unpacked_as_gfxstream_does() {
        assert_eq!(unpack_names(2, b"a;bc;"), vec![b"a\0".to_vec(), b"bc\0".to_vec()]);
        assert_eq!(unpack_names(1, b"x"), vec![b"x\0".to_vec()]);
        assert!(unpack_names(0, b"a;").is_empty());
    }
}
