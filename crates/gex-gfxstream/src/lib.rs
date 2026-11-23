//! gfxstream's wire protocol, as Android's emulator image speaks it: the
//! guest's OpenGL ES and EGL go to the host as calls in a byte stream
//! (`pipe:opengles` on the goldfish pipe), and the host answers each call
//! that has an answer on the same stream. This crate knows the calls and
//! reads them; what each one does on the host is the caller's.
//!
//! The calls are gfxstream's own descriptions of three APIs (`spec/`):
//! renderControl (EGL's side: configs, contexts, surfaces, color buffers,
//! posting and composing frames; opcodes from 10000), OpenGL ES 1 (from
//! 1024) and OpenGL ES 2 and 3 (from 2048). `build.rs` makes their tables.
//!
//! A call on the wire (emugen's encoders, `codegen/generic-apigen/README`):
//!
//! - its opcode and its length in bytes, header included, as `u32`s;
//! - each parameter in order: a scalar as its type's size, little-endian; a
//!   pointer as a `u32` length, then that many bytes for an `in` or `inout`
//!   pointer (an `out` pointer's bytes are the answer's);
//! - then, if checksums were agreed, a checksum. Never here: the host
//!   offers none (`ANDROID_EMU_CHECKSUM_HELPER` is not in its extensions).
//!
//! The answer: each `out` and `inout` pointer's bytes in parameter order,
//! then the return value, if the call has one. A call with neither has no
//! answer, and the guest goes on without waiting.

include!(concat!(env!("OUT_DIR"), "/apis.rs"));

#[cfg(feature = "host")]
pub mod host;

/// One API's calls.
pub struct Api {
    pub name: &'static str,
    pub base: u32,
    pub entries: &'static [Entry],
}

/// One call.
pub struct Entry {
    pub name: &'static str,
    /// The return value's size in bytes, 0 for none.
    pub ret: u32,
    pub params: &'static [Param],
    /// gfxstream's host decodes it by hand (`flag custom_decoder`): its
    /// meaning is not the GL call of its name.
    pub custom_decoder: bool,
    /// Not an entry point of the API (`flag not_api`): gfxstream's own.
    pub not_api: bool,
    /// The guest's encoder never sends it (`flag unsupported`).
    pub unsupported: bool,
}

pub struct Param {
    pub name: &'static str,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A value of this many bytes.
    Scalar(u32),
    /// A pointer whose bytes go to the host.
    In,
    /// A pointer whose bytes come back.
    Out,
    /// Both.
    InOut,
}

impl Entry {
    /// Whether the guest waits for an answer.
    pub fn answers(&self) -> bool {
        self.ret != 0 || self.params.iter().any(|p| matches!(p.kind, Kind::Out | Kind::InOut))
    }
}

/// The API and call of an opcode.
pub fn entry(opcode: u32) -> Option<(&'static Api, &'static Entry)> {
    for api in [&RENDER_CONTROL, &GLES1, &GLES2] {
        if let Some(e) = opcode.checked_sub(api.base).and_then(|i| api.entries.get(i as usize)) {
            return Some((api, e));
        }
    }
    None
}

/// A parameter as the wire gave it.
#[derive(Debug, PartialEq, Eq)]
pub enum Arg<'a> {
    /// A scalar, its bytes widened to 64 bits.
    Value(u64),
    /// An `in` pointer's bytes.
    In(&'a [u8]),
    /// An `out` pointer: how many bytes the answer gives it.
    Out(u32),
    /// An `inout` pointer's bytes, which the answer gives back changed.
    InOut(&'a [u8]),
}

/// One call read off the stream.
#[derive(Debug)]
pub struct Call<'a> {
    pub opcode: u32,
    pub api: &'static str,
    pub name: &'static str,
    pub args: Vec<Arg<'a>>,
}

/// What is wrong with a stream: after it, where the next call starts is not
/// known, so the stream is not read further.
#[derive(Debug, PartialEq, Eq)]
pub enum Malformed {
    /// An opcode no API has.
    Opcode(u32),
    /// A length shorter than the header, or than the parameters it holds.
    Length { opcode: u32, len: u32 },
}

/// The first whole call in `buf`, and its length; `Ok(None)` if `buf` does
/// not yet hold a whole one.
pub fn next_call(buf: &[u8]) -> Result<Option<(Call<'_>, usize)>, Malformed> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let opcode = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let (api, e) = entry(opcode).ok_or(Malformed::Opcode(opcode))?;
    if len < 8 {
        return Err(Malformed::Length { opcode, len });
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
    let body = &buf[8..len as usize];
    let bad = || Malformed::Length { opcode, len };
    let mut at = 0usize;
    let mut take = |n: usize| -> Result<&[u8], Malformed> {
        let s = body.get(at..at + n).ok_or_else(bad)?;
        at += n;
        Ok(s)
    };
    let mut args = Vec::with_capacity(e.params.len());
    for p in e.params {
        args.push(match p.kind {
            Kind::Scalar(n) => {
                let b = take(n as usize)?;
                let mut v = [0u8; 8];
                v[..b.len()].copy_from_slice(b);
                Arg::Value(u64::from_le_bytes(v))
            }
            Kind::In | Kind::InOut | Kind::Out => {
                let n = u32::from_le_bytes(take(4)?.try_into().unwrap());
                match p.kind {
                    Kind::Out => Arg::Out(n),
                    Kind::In => Arg::In(take(n as usize)?),
                    _ => Arg::InOut(take(n as usize)?),
                }
            }
        });
    }
    Ok(Some((Call { opcode, api: api.name, name: e.name, args }, len as usize)))
}

/// A call's answer, as the guest reads it back: the `out` and `inout`
/// pointers' bytes in parameter order, each as long as the call said, then
/// the return value at its size.
pub fn answer(entry: &Entry, call: &Call<'_>, outs: &[&[u8]], ret: u64) -> Vec<u8> {
    let mut b = Vec::new();
    let mut given = outs.iter();
    for (p, a) in entry.params.iter().zip(&call.args) {
        let want = match (p.kind, a) {
            (Kind::Out, Arg::Out(n)) => *n as usize,
            (Kind::InOut, Arg::InOut(d)) => d.len(),
            _ => continue,
        };
        let data = given.next().copied().unwrap_or(&[]);
        let n = want.min(data.len());
        b.extend_from_slice(&data[..n]);
        b.resize(b.len() + (want - n), 0);
    }
    b.extend_from_slice(&ret.to_le_bytes()[..entry.ret as usize]);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_name(api: &Api, name: &str) -> (u32, &'static Entry) {
        let i = api.entries.iter().position(|e| e.name == name).unwrap_or_else(|| panic!("{name}"));
        (api.base + i as u32, &api.entries[i])
    }

    /// The opcodes the image's encoders use (`renderControl_opcodes.h`,
    /// `gl2_opcodes.h` at android-17.0.0_r1).
    #[test]
    fn opcodes_are_gfxstreams() {
        assert_eq!(by_name(&RENDER_CONTROL, "rcGetRendererVersion").0, 10000);
        assert_eq!(by_name(&RENDER_CONTROL, "rcGetDisplayColorTransform").0, 10070);
        assert_eq!(by_name(&RENDER_CONTROL, "rcSetDisplayColorTransform").0, 10071);
        assert_eq!(GLES1.base, 1024);
        assert_eq!(GLES2.base, 2048);
        assert_eq!(entry(10000).unwrap().1.name, "rcGetRendererVersion");
        assert!(entry(10072).is_none() && entry(0).is_none());
    }

    /// Every opcode the image's encoders define (`renderControl_opcodes.h`,
    /// `gl_opcodes.h`, `gl2_opcodes.h` at android-17.0.0_r1, as `opcode
    /// name` lines in the file `GEX_GFXSTREAM_OPCODES`) is the same call
    /// here, and nothing here is missing from them.
    #[test]
    #[ignore = "needs GEX_GFXSTREAM_OPCODES"]
    fn opcodes_match_the_images_encoders() {
        let path = std::env::var("GEX_GFXSTREAM_OPCODES").expect("GEX_GFXSTREAM_OPCODES");
        let text = std::fs::read_to_string(path).unwrap();
        let mut theirs = 0;
        for line in text.lines() {
            let (op, name) = line.split_once(' ').unwrap();
            let op: u32 = op.parse().unwrap();
            let got = entry(op).map(|(_, e)| e.name);
            assert_eq!(got, Some(name), "opcode {op}");
            theirs += 1;
        }
        let ours: usize = [&RENDER_CONTROL, &GLES1, &GLES2].iter().map(|a| a.entries.len()).sum();
        assert_eq!(ours, theirs);
    }

    /// rcGetEGLVersion as the image's encoder writes it: two `out` pointers
    /// of 4 bytes, an `EGLint` back.
    #[test]
    fn a_call_with_out_pointers_is_read_and_answered() {
        let (op, e) = by_name(&RENDER_CONTROL, "rcGetEGLVersion");
        let mut w = Vec::new();
        w.extend_from_slice(&op.to_le_bytes());
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&4u32.to_le_bytes());
        w.extend_from_slice(&4u32.to_le_bytes());
        assert!(next_call(&w[..15]).unwrap().is_none());
        let (call, len) = next_call(&w).unwrap().unwrap();
        assert_eq!((call.name, len), ("rcGetEGLVersion", 16));
        assert_eq!(call.args, vec![Arg::Out(4), Arg::Out(4)]);
        assert!(e.answers());
        let a = answer(e, &call, &[&1i32.to_le_bytes(), &4i32.to_le_bytes()], 1);
        assert_eq!(a, [1, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
    }

    /// The new color transform call: a `mat4x4_ptr` sent as 512 bytes.
    #[test]
    fn a_pointer_type_gex_declares_is_read() {
        let (op, _) = by_name(&RENDER_CONTROL, "rcSetDisplayColorTransform");
        let mut w = Vec::new();
        w.extend_from_slice(&op.to_le_bytes());
        w.extend_from_slice(&(8u32 + 4 + 4 + 512).to_le_bytes());
        w.extend_from_slice(&7u32.to_le_bytes());
        w.extend_from_slice(&512u32.to_le_bytes());
        w.extend_from_slice(&[0u8; 512]);
        let (call, _) = next_call(&w).unwrap().unwrap();
        assert_eq!(call.args[0], Arg::Value(7));
        assert!(matches!(call.args[1], Arg::In(d) if d.len() == 512));
    }

    /// GLES2's glClearColor: four floats, no answer; a call that claims
    /// more than it holds stops the stream.
    #[test]
    fn scalars_and_malformed_lengths() {
        let (op, e) = by_name(&GLES2, "glClearColor");
        assert!(!e.answers());
        let mut w = Vec::new();
        w.extend_from_slice(&op.to_le_bytes());
        w.extend_from_slice(&24u32.to_le_bytes());
        for f in [0.25f32, 0.5, 0.75, 1.0] {
            w.extend_from_slice(&f.to_le_bytes());
        }
        let (call, _) = next_call(&w).unwrap().unwrap();
        assert_eq!(call.args[1], Arg::Value(0.5f32.to_bits() as u64));
        w[4] = 20;
        assert_eq!(next_call(&w[..20]).unwrap_err(), Malformed::Length { opcode: op, len: 20 });
        assert_eq!(next_call(&[9, 9, 9, 9, 8, 0, 0, 0]).unwrap_err(), Malformed::Opcode(0x0909_0909));
    }
}
