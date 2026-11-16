//! `bpf(2)`: maps, and the objects bpffs pins (`kernel/bpf/syscall.c`,
//! `arraymap.c`, `hashtab.c`, at android17-6.18, and what Linux 7.0 answers:
//! `tests/android/src/bpfmap.c`).
//!
//! Android's networking is built on BPF: netbpfload makes the maps and
//! loads the programs at boot and pins them in `/sys/fs/bpf`, and netd,
//! the system server and the rest open the pinned maps (`BPF_OBJ_GET`)
//! and read and write them. Here so far: the array and hash maps, their
//! element calls, pins and `BPF_OBJ_GET`, a map's description
//! (`BPF_OBJ_GET_INFO_BY_FD`), maps by id (`BPF_MAP_GET_NEXT_ID`,
//! `BPF_MAP_GET_FD_BY_ID`). Not yet, and refused as unknown: programs
//! (`BPF_PROG_LOAD` and attaching them), BTF, the other map types.

use crate::errno::Errno;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The commands.
pub mod cmd {
    pub const MAP_CREATE: u64 = 0;
    pub const MAP_LOOKUP_ELEM: u64 = 1;
    pub const MAP_UPDATE_ELEM: u64 = 2;
    pub const MAP_DELETE_ELEM: u64 = 3;
    pub const MAP_GET_NEXT_KEY: u64 = 4;
    pub const OBJ_PIN: u64 = 6;
    pub const OBJ_GET: u64 = 7;
    pub const PROG_GET_NEXT_ID: u64 = 11;
    pub const MAP_GET_NEXT_ID: u64 = 12;
    pub const MAP_GET_FD_BY_ID: u64 = 14;
    pub const OBJ_GET_INFO_BY_FD: u64 = 15;
    pub const BTF_LOAD: u64 = 18;
}

/// Map types (`enum bpf_map_type`).
pub mod map_type {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
}

/// `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST`, `BPF_F_LOCK`: an update's flags.
const ANY: u64 = 0;
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;
const F_LOCK: u64 = 4;

/// `BPF_F_RDONLY`, `BPF_F_WRONLY`: what a descriptor `BPF_OBJ_GET` gives
/// may do.
const F_RDONLY: u32 = 1 << 3;
const F_WRONLY: u32 = 1 << 4;

/// The size of `union bpf_attr` this kernel reads: what a caller's attr
/// has past it must be zero (`bpf_check_uarg_tail_zero`: `E2BIG`).
pub const ATTR_SIZE: usize = 256;

/// A key's largest size (`MAX_BPF_STACK`).
const MAX_KEY: u32 = 512;

/// What bpffs pins and `BPF_OBJ_GET` gives back.
#[derive(Clone, Debug)]
pub enum Object {
    Map(Arc<Map>),
    Btf(Arc<crate::btf::Btf>),
}

/// A map.
#[derive(Debug)]
pub struct Map {
    id: u32,
    ty: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: [u8; 16],
    /// The BTF it was made with, and its key's and value's type ids.
    btf: Option<(Arc<crate::btf::Btf>, u32, u32)>,
    data: Mutex<Data>,
}

/// A hash map's elements: in the order they were put there, and where
/// each key is in that order.
#[derive(Debug, Default)]
struct Hash {
    order: BTreeMap<u64, (Vec<u8>, Vec<u8>)>,
    at: std::collections::HashMap<Vec<u8>, u64>,
    next: u64,
}

#[derive(Debug)]
enum Data {
    /// `max_entries` values, every one there, zero until written.
    Array(Vec<u8>),
    /// Values by key, in the order they were put there (which
    /// `BPF_MAP_GET_NEXT_KEY` walks).
    Hash(Hash),
}

fn next_map_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Every map there is, by id, for `BPF_MAP_GET_NEXT_ID` and
/// `BPF_MAP_GET_FD_BY_ID`: a map is there while a descriptor or a pin
/// holds it.
static MAPS: Mutex<BTreeMap<u32, std::sync::Weak<Map>>> = Mutex::new(BTreeMap::new());

fn register(map: &Arc<Map>) {
    let mut maps = MAPS.lock().unwrap_or_else(|e| e.into_inner());
    maps.retain(|_, m| m.strong_count() > 0);
    maps.insert(map.id, Arc::downgrade(map));
}

/// The live map with the least id above `after`.
fn map_after(after: u32) -> Option<Arc<Map>> {
    let maps = MAPS.lock().unwrap_or_else(|e| e.into_inner());
    maps.range(after.saturating_add(1)..).find_map(|(_, m)| m.upgrade())
}

impl Map {
    /// `BPF_MAP_CREATE`'s checks (`map_create`, `array_map_alloc_check`,
    /// `htab_map_alloc_check`): a name of letters, digits, `_` and `.`; an
    /// array's key four bytes; no empty value or map.
    fn create(ty: u32, key_size: u32, value_size: u32, max_entries: u32, flags: u32, name: [u8; 16]) -> Result<Map, Errno> {
        let named = name.iter().take_while(|b| **b != 0);
        if !named.clone().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.') || name[15] != 0 {
            return Err(Errno::EINVAL);
        }
        if value_size == 0 || max_entries == 0 || key_size > MAX_KEY {
            return Err(Errno::EINVAL);
        }
        let data = match ty {
            map_type::ARRAY => {
                if key_size != 4 || flags != 0 {
                    unsupported_flags(flags);
                    return Err(Errno::EINVAL);
                }
                let len = (value_size as u64).checked_mul(max_entries as u64).filter(|n| *n < 1 << 32).ok_or(Errno::ENOMEM)?;
                Data::Array(vec![0; len as usize])
            }
            map_type::HASH => {
                if key_size == 0 || flags != 0 {
                    unsupported_flags(flags);
                    return Err(Errno::EINVAL);
                }
                Data::Hash(Hash::default())
            }
            other => {
                unsupported_type(other);
                return Err(Errno::EINVAL);
            }
        };
        Ok(Map { id: next_map_id(), ty, key_size, value_size, max_entries, flags, name, btf: None, data: Mutex::new(data) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Data> {
        self.data.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn index(&self, key: &[u8]) -> u32 {
        u32::from_le_bytes(key[..4].try_into().unwrap())
    }

    pub fn lookup(&self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        let vs = self.value_size as usize;
        match &*self.lock() {
            Data::Array(v) => {
                let i = self.index(key);
                if i >= self.max_entries {
                    return Err(Errno::ENOENT);
                }
                Ok(v[i as usize * vs..(i as usize + 1) * vs].to_vec())
            }
            Data::Hash(h) => h.at.get(key).map(|o| h.order[o].1.clone()).ok_or(Errno::ENOENT),
        }
    }

    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), Errno> {
        if flags & !F_LOCK > EXIST {
            return Err(Errno::EINVAL);
        }
        if flags & F_LOCK != 0 {
            // (No map here has a spin lock in its value.)
            return Err(Errno::EINVAL);
        }
        let vs = self.value_size as usize;
        let max = self.max_entries;
        match &mut *self.lock() {
            Data::Array(v) => {
                let i = self.index(key);
                if i >= max {
                    return Err(Errno::E2BIG);
                }
                // Every element of an array is there.
                if flags == NOEXIST {
                    return Err(Errno::EEXIST);
                }
                v[i as usize * vs..(i as usize + 1) * vs].copy_from_slice(value);
                Ok(())
            }
            Data::Hash(h) => {
                let there = h.at.get(key).copied();
                match (there, flags) {
                    (Some(_), NOEXIST) => Err(Errno::EEXIST),
                    (None, EXIST) => Err(Errno::ENOENT),
                    (Some(o), _) => {
                        h.order.get_mut(&o).unwrap().1 = value.to_vec();
                        Ok(())
                    }
                    (None, _) => {
                        if h.order.len() as u32 >= max {
                            return Err(Errno::E2BIG);
                        }
                        let o = h.next;
                        h.next += 1;
                        h.order.insert(o, (key.to_vec(), value.to_vec()));
                        h.at.insert(key.to_vec(), o);
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), Errno> {
        match &mut *self.lock() {
            Data::Array(_) => Err(Errno::EINVAL),
            Data::Hash(h) => {
                let o = h.at.remove(key).ok_or(Errno::ENOENT)?;
                h.order.remove(&o);
                Ok(())
            }
        }
    }

    /// The key after `key`, or the first for none (or, in a hash, for a
    /// key that is not there); `ENOENT` after the last.
    pub fn next_key(&self, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
        match &*self.lock() {
            Data::Array(_) => {
                let next = match key.map(|k| self.index(k)) {
                    Some(i) if i < self.max_entries => i + 1,
                    _ => 0,
                };
                if next >= self.max_entries {
                    return Err(Errno::ENOENT);
                }
                Ok(next.to_le_bytes().to_vec())
            }
            Data::Hash(h) => {
                let at = key.and_then(|key| h.at.get(key).copied());
                let next = match at {
                    Some(o) => h.order.range(o + 1..).next(),
                    None => h.order.iter().next(),
                };
                next.map(|(_, (k, _))| k.clone()).ok_or(Errno::ENOENT)
            }
        }
    }

    /// `struct bpf_map_info`, as far as this kernel fills it (88 bytes).
    fn info(&self) -> Vec<u8> {
        let mut b = vec![0u8; 88];
        let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(0, self.ty);
        put(4, self.id);
        put(8, self.key_size);
        put(12, self.value_size);
        put(16, self.max_entries);
        put(20, self.flags);
        b[24..40].copy_from_slice(&self.name);
        if let Some((btf, key, value)) = &self.btf {
            b[64..68].copy_from_slice(&btf.id.to_le_bytes());
            b[68..72].copy_from_slice(&key.to_le_bytes());
            b[72..76].copy_from_slice(&value.to_le_bytes());
        }
        b
    }
}

fn unsupported_type(ty: u32) {
    say_once(&format!("a map of type {ty}"));
}

fn unsupported_flags(flags: u32) {
    if flags != 0 {
        say_once(&format!("map flags {flags:#x}"));
    }
}

pub(crate) fn say_once(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] bpf: {what} is not implemented -> EINVAL");
        said.push(what.to_string());
    }
}

/// A map's descriptor: the map, and what it may do to it.
#[derive(Debug)]
pub struct MapFile {
    pub map: Arc<Map>,
    read: bool,
    write: bool,
}

impl FileHandle for MapFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(Errno::EINVAL)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o600, ino: self.map.id as u64, mtime: 0, nlink: 1, rdev: 0, times: Default::default(), owner: None })
    }
    fn bpf_object(&self) -> Option<Object> {
        Some(Object::Map(Arc::clone(&self.map)))
    }
    fn bpf_access(&self) -> Option<(bool, bool)> {
        Some((self.read, self.write))
    }
}

/// What a `bpf(2)` call needs of its caller.
pub struct Caller<'a> {
    pub fds: &'a crate::file::FdTable,
    pub ns: &'a crate::vfs::Namespace,
    /// `CAP_BPF` or `CAP_SYS_ADMIN`.
    pub capable: bool,
    /// `CAP_SYS_ADMIN`.
    pub admin: bool,
    pub uid: u32,
    pub gid: u32,
    pub umask: u32,
}

fn install(c: &Caller<'_>, obj: Object, read: bool, write: bool) -> crate::errno::SysResult {
    let (handle, name): (Arc<dyn FileHandle>, &str) = match obj {
        Object::Map(map) => (Arc::new(MapFile { map, read, write }), "anon_inode:bpf-map"),
        Object::Btf(btf) => (Arc::new(crate::btf::BtfFile(btf)), "anon_inode:btf"),
    };
    let flags = match (read, write) {
        (true, true) => crate::fs::oflags::O_RDWR,
        (true, false) => 0,
        _ => crate::fs::oflags::O_WRONLY,
    };
    let file = crate::file::OpenFile::new(handle, name.to_string(), flags, read, write);
    // Every descriptor bpf(2) makes closes at an exec (O_CLOEXEC).
    c.fds.insert(file, true)
}

/// The map a descriptor is, with whether it may be read and written.
fn map_of(c: &Caller<'_>, fd: i32) -> Result<(Arc<Map>, bool, bool), Errno> {
    let file = c.fds.get(fd)?;
    match file.handle.bpf_object() {
        Some(Object::Map(map)) => {
            let (r, w) = file.handle.bpf_access().unwrap_or((true, true));
            Ok((map, r, w))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `bpf(cmd, attr, size)`.
pub fn call(c: &Caller<'_>, m: &mut GuestMem<'_>, cmd: u64, attr: u64, size: u64) -> crate::errno::SysResult {
    // Without CAP_BPF, nothing while kernel.unprivileged_bpf_disabled is
    // set (`__sys_bpf`).
    if !c.capable && crate::vfs::procfs::bpf_sysctl::Which::UnprivDisabled.get() != 0 {
        return Err(Errno::EPERM);
    }
    let size = size as usize;
    if size > crate::mem::PAGE_SIZE as usize {
        return Err(Errno::E2BIG);
    }
    let mut a = vec![0u8; ATTR_SIZE];
    let n = size.min(ATTR_SIZE);
    if n > 0 {
        a[..n].copy_from_slice(m.read(attr, n)?);
    }
    if size > ATTR_SIZE && m.read(attr + ATTR_SIZE as u64, size - ATTR_SIZE)?.iter().any(|b| *b != 0) {
        return Err(Errno::E2BIG);
    }
    let u32_at = |at: usize| u32::from_le_bytes(a[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(a[at..at + 8].try_into().unwrap());
    // What a command does not read must be zero (`CHECK_ATTR`).
    let zero_from = |at: usize| -> Result<(), Errno> { if a[at..].iter().any(|b| *b != 0) { Err(Errno::EINVAL) } else { Ok(()) } };
    match cmd {
        cmd::MAP_CREATE => {
            // ... map_token_fd, the last field 6.18 has: 80 bytes.
            zero_from(80)?;
            let (ty, key, value, max, flags) = (u32_at(0), u32_at(4), u32_at(8), u32_at(12), u32_at(16));
            let mut name = [0u8; 16];
            name.copy_from_slice(&a[28..44]);
            if u32_at(20) != 0 || u32_at(44) != 0 || u32_at(60) != 0 || u64_at(64) != 0 {
                say_once("a map with an inner map, a device, kernel BTF or extra");
                return Err(Errno::EINVAL);
            }
            let mut map = Map::create(ty, key, value, max, flags, name)?;
            // Its key's and value's types (`map_check_btf`): the value's
            // there and the value's size, the key's too where it is named.
            let (btf_fd, key_id, value_id) = (u32_at(48), u32_at(52), u32_at(56));
            if key_id != 0 || value_id != 0 {
                if btf_fd == 0 {
                    return Err(Errno::EINVAL);
                }
                let btf = match c.fds.get(btf_fd as i32)?.handle.bpf_object() {
                    Some(Object::Btf(b)) => b,
                    _ => return Err(Errno::EINVAL),
                };
                if key_id != 0 && btf.size_of(key_id) != Ok(key) {
                    return Err(Errno::EINVAL);
                }
                if value_id == 0 || btf.size_of(value_id) != Ok(value) {
                    return Err(Errno::EINVAL);
                }
                // A key of no type only where the map says it may be
                // (`map_check_btf`): an array of one element whose value is
                // a datasec (global data); an array's key is otherwise a
                // 32-bit int (`array_map_check_btf`). A hash names its key.
                match ty {
                    map_type::ARRAY if key_id == 0 => {
                        if max != 1 || !btf.is_datasec(value_id) {
                            return Err(Errno::EINVAL);
                        }
                    }
                    map_type::ARRAY => {
                        if !btf.is_i32(key_id) {
                            return Err(Errno::EINVAL);
                        }
                    }
                    _ if key_id == 0 => return Err(Errno::EINVAL),
                    _ => {}
                }
                map.btf = Some((btf, key_id, value_id));
            }
            let map = Arc::new(map);
            register(&map);
            install(c, Object::Map(map), true, true)
        }
        cmd::MAP_LOOKUP_ELEM | cmd::MAP_UPDATE_ELEM | cmd::MAP_DELETE_ELEM | cmd::MAP_GET_NEXT_KEY => {
            zero_from(32)?;
            let (map, r, w) = map_of(c, u32_at(0) as i32)?;
            let ks = map.key_size as usize;
            let key = if u64_at(8) == 0 && cmd == cmd::MAP_GET_NEXT_KEY { None } else { Some(m.read(u64_at(8), ks)?.to_vec()) };
            match cmd {
                cmd::MAP_LOOKUP_ELEM => {
                    if !r {
                        return Err(Errno::EPERM);
                    }
                    if u64_at(24) != 0 {
                        return Err(Errno::EINVAL);
                    }
                    let v = map.lookup(key.as_deref().unwrap())?;
                    m.write(u64_at(16), &v)?;
                }
                cmd::MAP_UPDATE_ELEM => {
                    if !w {
                        return Err(Errno::EPERM);
                    }
                    let value = m.read(u64_at(16), map.value_size as usize)?.to_vec();
                    map.update(key.as_deref().unwrap(), &value, u64_at(24))?;
                }
                cmd::MAP_DELETE_ELEM => {
                    if !w {
                        return Err(Errno::EPERM);
                    }
                    map.delete(key.as_deref().unwrap())?;
                }
                _ => {
                    if !r {
                        return Err(Errno::EPERM);
                    }
                    let next = map.next_key(key.as_deref())?;
                    m.write(u64_at(16), &next)?;
                }
            }
            Ok(0)
        }
        cmd::OBJ_PIN => {
            zero_from(20)?;
            if u32_at(12) != 0 {
                return Err(Errno::EINVAL);
            }
            let path = path_at(m, u64_at(0))?;
            let file = c.fds.get(u32_at(8) as i32)?;
            let obj = file.handle.bpf_object().ok_or(Errno::EINVAL)?;
            let mode = 0o600 & !c.umask;
            c.ns.bpf_pin(&path, obj, mode, c.uid, c.gid)?;
            Ok(0)
        }
        cmd::OBJ_GET => {
            zero_from(20)?;
            let flags = u32_at(12);
            if flags & !(F_RDONLY | F_WRONLY) != 0 || flags == F_RDONLY | F_WRONLY {
                return Err(Errno::EINVAL);
            }
            let path = path_at(m, u64_at(0))?;
            let obj = c.ns.bpf_get(&path)?;
            install(c, obj, flags & F_WRONLY == 0, flags & F_RDONLY == 0)
        }
        // The objects there are, by id: root's to ask (`CAP_SYS_ADMIN`).
        cmd::PROG_GET_NEXT_ID | cmd::MAP_GET_NEXT_ID => {
            zero_from(12)?;
            if !c.admin {
                return Err(Errno::EPERM);
            }
            let next = match cmd {
                // No program is loaded here yet.
                cmd::PROG_GET_NEXT_ID => None,
                _ => map_after(u32_at(0)).map(|m| m.id),
            };
            let next = next.ok_or(Errno::ENOENT)?;
            m.write_u32(attr + 4, next)?;
            Ok(0)
        }
        cmd::MAP_GET_FD_BY_ID => {
            zero_from(12)?;
            if !c.admin {
                return Err(Errno::EPERM);
            }
            let flags = u32_at(8);
            if flags & !(F_RDONLY | F_WRONLY) != 0 || flags == F_RDONLY | F_WRONLY {
                return Err(Errno::EINVAL);
            }
            let id = u32_at(0);
            let map = map_after(id.wrapping_sub(1)).filter(|m| m.id == id).ok_or(Errno::ENOENT)?;
            install(c, Object::Map(map), flags & F_WRONLY == 0, flags & F_RDONLY == 0)
        }
        cmd::OBJ_GET_INFO_BY_FD => {
            zero_from(16)?;
            let file = c.fds.get(u32_at(0) as i32)?;
            let info = match file.handle.bpf_object() {
                Some(Object::Map(map)) => map.info(),
                Some(Object::Btf(btf)) => {
                    // `struct bpf_btf_info`: the BTF itself copied out
                    // where the caller gave room (`btf`, `btf_size`).
                    let mut i = vec![0u8; 32];
                    if u32_at(4) as usize >= 16 {
                        let to = m.read_u64(u64_at(8))?;
                        let room = m.read_u32(u64_at(8) + 8)? as usize;
                        if to != 0 {
                            m.write(to, &btf.data[..room.min(btf.data.len())])?;
                        }
                    }
                    i[8..12].copy_from_slice(&(btf.data.len() as u32).to_le_bytes());
                    i[12..16].copy_from_slice(&btf.id.to_le_bytes());
                    if u32_at(4) as usize >= 16 {
                        i[0..8].copy_from_slice(&m.read_u64(u64_at(8))?.to_le_bytes());
                    }
                    i
                }
                None => return Err(Errno::EINVAL),
            };
            let want = u32_at(4) as usize;
            let n = want.min(info.len());
            // What the caller's struct has past this kernel's must be zero.
            if want > info.len() && m.read(u64_at(8) + info.len() as u64, want - info.len())?.iter().any(|b| *b != 0) {
                return Err(Errno::E2BIG);
            }
            m.write(u64_at(8), &info[..n])?;
            m.write_u32(attr + 4, n as u32)?;
            Ok(0)
        }
        cmd::BTF_LOAD => {
            zero_from(40)?;
            if !c.capable {
                return Err(Errno::EPERM);
            }
            let (data_at, log_buf, size, log_size, log_level, flags) = (u64_at(0), u64_at(8), u32_at(16), u32_at(20), u32_at(24), u32_at(32));
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            check_log(log_buf, log_size, log_level)?;
            // `BTF_MAX_SIZE`.
            if size > 16 << 20 {
                return Err(Errno::E2BIG);
            }
            let data = m.read(data_at, size as usize)?.to_vec();
            // The log, when asked for: what does not fit is cut, and the
            // load fails for it (`ENOSPC`); its whole length is said.
            let mut full = false;
            if log_level != 0 {
                let text = crate::btf::log_of(&data);
                let room = log_size as usize - 1;
                let n = text.len().min(room);
                m.write(log_buf, &text.as_bytes()[..n])?;
                m.write(log_buf + n as u64, &[0])?;
                m.write_u32(attr + 28, text.len() as u32 + 1)?;
                full = text.len() > room;
            }
            let btf = crate::btf::Btf::parse(data)?;
            if full {
                return Err(Errno::ENOSPC);
            }
            install(c, Object::Btf(Arc::new(btf)), true, true)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// A verifier log's attributes (`bpf_vlog_init`): a buffer and a level
/// together or neither, a level of known bits, no more than `UINT_MAX >> 2`
/// of room.
fn check_log(buf: u64, size: u32, level: u32) -> Result<(), Errno> {
    const LOG_MASK: u32 = 1 | 2 | 4 | 8 | 16;
    if (buf != 0) != (size != 0) || (level != 0) != (buf != 0) || level & !LOG_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if size > u32::MAX >> 2 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn path_at(m: &GuestMem<'_>, at: u64) -> Result<String, Errno> {
    String::from_utf8(m.read_cstr(at, 4096)?).map_err(|_| Errno::EINVAL)
}
