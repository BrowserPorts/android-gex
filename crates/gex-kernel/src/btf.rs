//! BTF, the BPF type format (`BPF_BTF_LOAD`; `kernel/bpf/btf.c` at
//! android17-6.18, `include/uapi/linux/btf.h`): the types a BPF object
//! describes its maps and functions with. libbpf loads an object's `.BTF`
//! before anything else, and a map that names a BTF key and value type has
//! them checked against its sizes.
//!
//! What is checked here is the format as the kernel's verifier holds it:
//! the header, the two sections, the string section, each type's kind,
//! flags, extra data and name, that every type it names is there, that
//! naming does not go round in a circle, and that what needs a size has
//! one. Errors are `EINVAL`, except a version or flags the kernel does
//! not know (`ENOTSUPP`, 524) and a longer header with something in it
//! (`E2BIG`). The kernel's deeper checks of a struct's members against
//! their types' sizes and of a datasec's variables are made as far as
//! sizes go.

use crate::errno::Errno;

pub const MAGIC: u16 = 0xeb9f;
const VERSION: u8 = 1;
/// The header this kernel knows: magic, version, flags, hdr_len,
/// type_off, type_len, str_off, str_len.
const HDR_LEN: usize = 24;
/// `BTF_MAX_TYPE`, `BTF_MAX_NAME_OFFSET`.
const MAX_TYPE: u32 = 0x000f_ffff;
const MAX_NAME_OFFSET: u32 = 0x00ff_ffff;
/// `ENOTSUPP` (the kernel's own, not a user-space errno).
pub const ENOTSUPP: Errno = Errno(524);

pub mod kind {
    pub const INT: u32 = 1;
    pub const PTR: u32 = 2;
    pub const ARRAY: u32 = 3;
    pub const STRUCT: u32 = 4;
    pub const UNION: u32 = 5;
    pub const ENUM: u32 = 6;
    pub const FWD: u32 = 7;
    pub const TYPEDEF: u32 = 8;
    pub const VOLATILE: u32 = 9;
    pub const CONST: u32 = 10;
    pub const RESTRICT: u32 = 11;
    pub const FUNC: u32 = 12;
    pub const FUNC_PROTO: u32 = 13;
    pub const VAR: u32 = 14;
    pub const DATASEC: u32 = 15;
    pub const FLOAT: u32 = 16;
    pub const DECL_TAG: u32 = 17;
    pub const TYPE_TAG: u32 = 18;
    pub const ENUM64: u32 = 19;
    pub const MAX: u32 = ENUM64;
}

/// One type: its kind, flag, count, name, size-or-type, and the ids it
/// names (with what each is for).
#[derive(Debug, Clone)]
struct Type {
    kind: u32,
    kflag: bool,
    vlen: u32,
    name: String,
    /// `size` for a sized kind, `type` for a referring one.
    size_type: u32,
    /// For an array: element type, index type, count.
    array: Option<(u32, u32, u32)>,
    /// Member (or parameter, or variable) type ids.
    refs: Vec<u32>,
}

/// A loaded BTF.
#[derive(Debug)]
pub struct Btf {
    pub id: u32,
    pub data: Vec<u8>,
    /// Types by id; id 0 is `void` (`None`).
    types: Vec<Option<Type>>,
}

fn next_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// `btf_name_valid_identifier`: a C identifier.
fn identifier(s: &str) -> bool {
    let mut c = s.bytes();
    matches!(c.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_') && c.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `btf_name_valid_section`: printable, no space, not empty.
fn section_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Btf {
    /// Parse and check `data` (`btf_parse`).
    pub fn parse(data: Vec<u8>) -> Result<Btf, Errno> {
        let n = data.len();
        if n < 8 {
            return Err(Errno::EINVAL);
        }
        let hdr_len = u32_at(&data, 4) as usize;
        if n < hdr_len {
            return Err(Errno::EINVAL);
        }
        if hdr_len > HDR_LEN && data[HDR_LEN..hdr_len].iter().any(|b| *b != 0) {
            return Err(Errno::E2BIG);
        }
        if hdr_len < HDR_LEN {
            // (A shorter header than the kernel's has no sections to name.)
            return Err(Errno::EINVAL);
        }
        if u16::from_le_bytes([data[0], data[1]]) != MAGIC {
            return Err(Errno::EINVAL);
        }
        if data[2] != VERSION {
            return Err(ENOTSUPP);
        }
        if data[3] != 0 {
            return Err(ENOTSUPP);
        }
        if n == hdr_len {
            return Err(Errno::EINVAL);
        }
        let (type_off, type_len, str_off, str_len) = (u32_at(&data, 8) as usize, u32_at(&data, 12) as usize, u32_at(&data, 16) as usize, u32_at(&data, 20) as usize);
        // The sections (`btf_parse_sec_hdr`): types 4-aligned, in order,
        // within the data, not overlapping, and nothing left between or
        // after them.
        if type_off % 4 != 0 {
            return Err(Errno::EINVAL);
        }
        let body = n - hdr_len;
        let mut secs = [(type_off, type_len), (str_off, str_len)];
        secs.sort();
        let mut expected = 0usize;
        let mut total = 0usize;
        for (off, len) in secs {
            if off < expected || off.checked_add(len).is_none_or(|e| e > body) {
                return Err(Errno::EINVAL);
            }
            if off != expected && len != 0 {
                return Err(Errno::EINVAL);
            }
            total += len;
            expected = off + len;
        }
        if total != body {
            return Err(Errno::EINVAL);
        }
        // The strings: not empty, the first empty, the last ended.
        let strs = &data[hdr_len + str_off..hdr_len + str_off + str_len];
        if str_len == 0 || str_len - 1 > MAX_NAME_OFFSET as usize || strs[str_len - 1] != 0 || strs[0] != 0 {
            return Err(Errno::EINVAL);
        }
        let name_at = |off: u32| -> Result<String, Errno> {
            let off = off as usize;
            if off >= str_len {
                return Err(Errno::EINVAL);
            }
            let end = strs[off..].iter().position(|b| *b == 0).unwrap();
            Ok(String::from_utf8_lossy(&strs[off..off + end]).into_owned())
        };
        // The types.
        let tb = &data[hdr_len + type_off..hdr_len + type_off + type_len];
        let mut types: Vec<Option<Type>> = vec![None];
        let mut at = 0usize;
        while at < tb.len() {
            if tb.len() - at < 12 {
                return Err(Errno::EINVAL);
            }
            let name_off = u32_at(tb, at);
            let info = u32_at(tb, at + 4);
            let size_type = u32_at(tb, at + 8);
            at += 12;
            // `BTF_INFO_MASK`: vlen, kind, kind_flag.
            if info & !0x9f00_ffff != 0 {
                return Err(Errno::EINVAL);
            }
            let kind = (info >> 24) & 0x1f;
            let vlen = info & 0xffff;
            let kflag = info >> 31 != 0;
            if kind == 0 || kind > kind::MAX {
                return Err(Errno::EINVAL);
            }
            let name = name_at(name_off)?;
            let mut t = Type { kind, kflag, vlen, name, size_type, array: None, refs: Vec::new() };
            let extra = |each: usize| -> Result<usize, Errno> { (vlen as usize).checked_mul(each).filter(|b| *b <= tb.len() - at).ok_or(Errno::EINVAL) };
            let need = |c: bool| if c { Ok(()) } else { Err(Errno::EINVAL) };
            let sz = size_type;
            match kind {
                kind::INT => {
                    need(vlen == 0 && !kflag && tb.len() - at >= 4)?;
                    let enc = u32_at(tb, at);
                    at += 4;
                    let (encoding, offset, bits) = ((enc >> 24) & 0xf, (enc >> 16) & 0xff, enc & 0xff);
                    // (`BTF_INT_MASK`: the top four bits are nothing.)
                    need(enc & 0xf000_0000 == 0)?;
                    need(bits <= 128 && bits.div_ceil(8) <= sz && matches!(sz, 1 | 2 | 4 | 8 | 16) && offset + bits <= sz * 8)?;
                    need(matches!(encoding, 0 | 1 | 2 | 4))?;
                    need(t.name.is_empty() || identifier(&t.name))?;
                }
                kind::PTR | kind::VOLATILE | kind::CONST | kind::RESTRICT => {
                    need(vlen == 0 && !kflag && sz <= MAX_TYPE && t.name.is_empty())?;
                    t.refs.push(sz);
                }
                kind::TYPEDEF => {
                    need(vlen == 0 && !kflag && sz <= MAX_TYPE && identifier(&t.name))?;
                    t.refs.push(sz);
                }
                kind::TYPE_TAG => {
                    need(vlen == 0 && sz <= MAX_TYPE && !t.name.is_empty())?;
                    t.refs.push(sz);
                }
                kind::FWD => {
                    need(vlen == 0 && sz == 0 && identifier(&t.name))?;
                }
                kind::ARRAY => {
                    need(vlen == 0 && !kflag && sz == 0 && t.name.is_empty() && tb.len() - at >= 12)?;
                    let (elem, index, nelems) = (u32_at(tb, at), u32_at(tb, at + 4), u32_at(tb, at + 8));
                    at += 12;
                    t.array = Some((elem, index, nelems));
                    t.refs.extend([elem, index]);
                }
                kind::STRUCT | kind::UNION => {
                    need(t.name.is_empty() || identifier(&t.name))?;
                    let len = extra(12)?;
                    let mut last = 0u32;
                    for i in 0..vlen as usize {
                        let m = at + i * 12;
                        let mname = name_at(u32_at(tb, m))?;
                        need(mname.is_empty() || identifier(&mname))?;
                        let ty = u32_at(tb, m + 4);
                        let off = u32_at(tb, m + 8);
                        // With kind_flag the offset's top 8 bits are a
                        // bitfield's size.
                        let bits_off = if kflag { off & 0x00ff_ffff } else { off };
                        if kind == kind::STRUCT {
                            need(bits_off >= last)?;
                            last = bits_off;
                        }
                        need(bits_off / 8 <= sz)?;
                        t.refs.push(ty);
                    }
                    at += len;
                }
                kind::ENUM => {
                    need(matches!(sz, 1 | 2 | 4 | 8) && (t.name.is_empty() || identifier(&t.name)))?;
                    let len = extra(8)?;
                    for i in 0..vlen as usize {
                        need(identifier(&name_at(u32_at(tb, at + i * 8))?))?;
                    }
                    at += len;
                }
                kind::ENUM64 => {
                    need(matches!(sz, 1 | 2 | 4 | 8) && (t.name.is_empty() || identifier(&t.name)))?;
                    let len = extra(12)?;
                    for i in 0..vlen as usize {
                        need(identifier(&name_at(u32_at(tb, at + i * 12))?))?;
                    }
                    at += len;
                }
                kind::FUNC_PROTO => {
                    need(!kflag && t.name.is_empty())?;
                    let len = extra(8)?;
                    for i in 0..vlen as usize {
                        let pname = name_at(u32_at(tb, at + i * 8))?;
                        let ty = u32_at(tb, at + i * 8 + 4);
                        // Only the last may be `...` (no name, no type).
                        if ty == 0 {
                            need(i + 1 == vlen as usize && pname.is_empty())?;
                        } else {
                            need(pname.is_empty() || identifier(&pname))?;
                            t.refs.push(ty);
                        }
                    }
                    t.refs.push(sz);
                    at += len;
                }
                kind::FUNC => {
                    need(vlen <= 2 && !kflag && identifier(&t.name))?;
                    t.refs.push(sz);
                }
                kind::VAR => {
                    need(vlen == 0 && !kflag && identifier(&t.name) && tb.len() - at >= 4)?;
                    need(u32_at(tb, at) <= 2)?;
                    at += 4;
                    t.refs.push(sz);
                }
                kind::DATASEC => {
                    need(!kflag && section_name(&t.name) && vlen > 0 && sz > 0)?;
                    let len = extra(12)?;
                    let mut end = 0u32;
                    for i in 0..vlen as usize {
                        let m = at + i * 12;
                        let (ty, off, size) = (u32_at(tb, m), u32_at(tb, m + 4), u32_at(tb, m + 8));
                        need(ty != 0 && size != 0 && off >= end && off.checked_add(size).is_some_and(|e| e <= sz))?;
                        end = off + size;
                        t.refs.push(ty);
                    }
                    at += len;
                }
                kind::FLOAT => {
                    need(vlen == 0 && !kflag && identifier(&t.name) && matches!(sz, 2 | 4 | 8 | 12 | 16))?;
                }
                kind::DECL_TAG => {
                    need(vlen == 0 && !t.name.is_empty() && tb.len() - at >= 4)?;
                    need((u32_at(tb, at) as i32) >= -1)?;
                    at += 4;
                    t.refs.push(sz);
                }
                _ => return Err(Errno::EINVAL),
            }
            types.push(Some(t));
            if types.len() as u32 > MAX_TYPE {
                return Err(Errno::E2BIG);
            }
        }
        let btf = Btf { id: next_id(), data, types };
        btf.check_refs()?;
        Ok(btf)
    }

    /// Every id a type names is a type; what refers through names does
    /// not come back to where it began; an array's element has a size and
    /// its index is an integer.
    fn check_refs(&self) -> Result<(), Errno> {
        let n = self.types.len() as u32;
        for t in self.types.iter().flatten() {
            if t.refs.iter().any(|r| *r >= n) {
                return Err(Errno::EINVAL);
            }
        }
        for id in 1..n {
            self.resolve(id)?;
            let t = self.types[id as usize].as_ref().unwrap();
            if let Some((elem, index, _)) = t.array {
                self.size_of(elem)?;
                let idx = self.resolve(index)?;
                if !matches!(self.types[idx as usize].as_ref().map(|t| t.kind), Some(kind::INT)) {
                    return Err(Errno::EINVAL);
                }
            }
            if t.kind == kind::FUNC {
                let proto = self.types[t.size_type as usize].as_ref().ok_or(Errno::EINVAL)?;
                if proto.kind != kind::FUNC_PROTO {
                    return Err(Errno::EINVAL);
                }
            }
        }
        Ok(())
    }

    /// Through typedefs and modifiers to what they name; a circle is
    /// `EEXIST` (the kernel's "Loop detected").
    fn resolve(&self, mut id: u32) -> Result<u32, Errno> {
        for _ in 0..=self.types.len() {
            match self.types.get(id as usize) {
                None => return Err(Errno::EINVAL),
                Some(None) => return Ok(id),
                Some(Some(t)) => match t.kind {
                    kind::TYPEDEF | kind::VOLATILE | kind::CONST | kind::RESTRICT | kind::TYPE_TAG => id = t.size_type,
                    _ => return Ok(id),
                },
            }
        }
        Err(Errno::EEXIST)
    }

    /// The size of type `id` (`btf_type_id_size`); `EINVAL` for one that
    /// has none (void, a function, a forward declaration).
    pub fn size_of(&self, id: u32) -> Result<u32, Errno> {
        let r = self.resolve(id)?;
        let t = self.types.get(r as usize).and_then(|t| t.as_ref()).ok_or(Errno::EINVAL)?;
        match t.kind {
            kind::INT | kind::STRUCT | kind::UNION | kind::ENUM | kind::ENUM64 | kind::FLOAT | kind::DATASEC => Ok(t.size_type),
            kind::PTR => Ok(8),
            kind::ARRAY => {
                let (elem, _, n) = t.array.unwrap();
                self.size_of(elem)?.checked_mul(n).ok_or(Errno::EINVAL)
            }
            kind::VAR => self.size_of(t.size_type),
            _ => Err(Errno::EINVAL),
        }
    }

    /// How many types (and void).
    pub fn count(&self) -> u32 {
        self.types.len() as u32
    }

    /// Whether type `id` is a function (`btf_type_is_func`).
    pub fn is_func(&self, id: u32) -> bool {
        matches!(self.types.get(id as usize), Some(Some(t)) if t.kind == kind::FUNC)
    }

    /// Whether type `id` is a datasec (`btf_type_is_datasec`).
    pub fn is_datasec(&self, id: u32) -> bool {
        matches!(self.types.get(id as usize), Some(Some(t)) if t.kind == kind::DATASEC)
    }

    /// Whether type `id` (through typedefs and modifiers) is a 32-bit int
    /// (`btf_type_is_i32`).
    pub fn is_i32(&self, id: u32) -> bool {
        let Ok(r) = self.resolve(id) else { return false };
        matches!(self.types.get(r as usize), Some(Some(t)) if t.kind == kind::INT && t.size_type == 4)
    }
}

/// The verifier's log of a load (`btf_verifier_log_hdr`, and a line a
/// type): what a caller that asked for one is given.
pub fn log_of(data: &[u8]) -> String {
    let mut out = String::new();
    if data.len() >= HDR_LEN {
        let h = |at: usize| u32_at(data, at);
        out.push_str(&format!(
            "magic: 0x{:x}\nversion: {}\nflags: 0x{:x}\nhdr_len: {}\ntype_off: {}\ntype_len: {}\nstr_off: {}\nstr_len: {}\nbtf_total_size: {}\n",
            u16::from_le_bytes([data[0], data[1]]),
            data[2],
            data[3],
            h(4),
            h(8),
            h(12),
            h(16),
            h(20),
            data.len()
        ));
    }
    if let Ok(btf) = Btf::parse(data.to_vec()) {
        const NAMES: [&str; 20] = ["UNKN", "INT", "PTR", "ARRAY", "STRUCT", "UNION", "ENUM", "FWD", "TYPEDEF", "VOLATILE", "CONST", "RESTRICT", "FUNC", "FUNC_PROTO", "VAR", "DATASEC", "FLOAT", "DECL_TAG", "TYPE_TAG", "ENUM64"];
        for (id, t) in btf.types.iter().enumerate().skip(1) {
            let t = t.as_ref().unwrap();
            out.push_str(&format!("[{id}] {} {}\n", NAMES[t.kind as usize], if t.name.is_empty() { "(anon)" } else { &t.name }));
        }
    }
    out
}

/// A loaded BTF's descriptor.
#[derive(Debug)]
pub struct BtfFile(pub std::sync::Arc<Btf>);

impl crate::vfs::FileHandle for BtfFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(Errno::EINVAL)
    }
    fn metadata(&self) -> Result<crate::vfs::Metadata, Errno> {
        Ok(crate::vfs::Metadata { file_type: crate::vfs::FileType::Regular, size: 0, mode: 0o600, ino: self.0.id as u64, mtime: 0, nlink: 1, rdev: 0, times: Default::default(), owner: None })
    }
    fn bpf_object(&self) -> Option<crate::bpf::Object> {
        Some(crate::bpf::Object::Btf(std::sync::Arc::clone(&self.0)))
    }
}
