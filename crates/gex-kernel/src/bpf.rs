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
    pub const PROG_LOAD: u64 = 5;
    pub const PROG_GET_FD_BY_ID: u64 = 13;
    pub const OBJ_PIN: u64 = 6;
    pub const OBJ_GET: u64 = 7;
    pub const PROG_GET_NEXT_ID: u64 = 11;
    pub const MAP_GET_NEXT_ID: u64 = 12;
    pub const MAP_GET_FD_BY_ID: u64 = 14;
    pub const OBJ_GET_INFO_BY_FD: u64 = 15;
    pub const BTF_LOAD: u64 = 18;
    pub const PROG_ATTACH: u64 = 8;
    pub const PROG_DETACH: u64 = 9;
    pub const PROG_QUERY: u64 = 16;
    pub const PROG_TEST_RUN: u64 = 10;
    pub const MAP_FREEZE: u64 = 22;
    pub const MAP_LOOKUP_BATCH: u64 = 24;
    pub const MAP_LOOKUP_AND_DELETE_BATCH: u64 = 25;
    pub const MAP_UPDATE_BATCH: u64 = 26;
    pub const MAP_DELETE_BATCH: u64 = 27;
}

/// Map types (`enum bpf_map_type`).
pub mod map_type {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const PERCPU_ARRAY: u32 = 6;
    pub const LRU_HASH: u32 = 9;
    pub const LPM_TRIE: u32 = 11;
    pub const SK_STORAGE: u32 = 24;
    pub const DEVMAP_HASH: u32 = 25;
    pub const RINGBUF: u32 = 27;
}

/// Map creation flags (`BPF_F_*`).
pub mod map_flag {
    pub const NO_PREALLOC: u32 = 1 << 0;
    pub const NO_COMMON_LRU: u32 = 1 << 1;
    pub const NUMA_NODE: u32 = 1 << 2;
    pub const RDONLY: u32 = 1 << 3;
    pub const WRONLY: u32 = 1 << 4;
    pub const ZERO_SEED: u32 = 1 << 6;
    pub const RDONLY_PROG: u32 = 1 << 7;
    pub const WRONLY_PROG: u32 = 1 << 8;
    pub const CLONE: u32 = 1 << 9;
    pub const MMAPABLE: u32 = 1 << 10;
    /// `BPF_F_ACCESS_MASK`.
    pub const ACCESS: u32 = RDONLY | WRONLY | RDONLY_PROG | WRONLY_PROG;
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
    Prog(Arc<crate::bpfprog::Prog>),
}

/// `__jhash_mix`.
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(4);
    *b = b.wrapping_add(*a);
}

/// `__jhash_final`.
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(14));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(11));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(25));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(16));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(4));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(14));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(24));
}

const JHASH_INITVAL: u32 = 0xdead_beef;

/// `jhash`: bytes.
fn jhash(k: &[u8], initval: u32) -> u32 {
    let mut len = k.len();
    let init = JHASH_INITVAL.wrapping_add(len as u32).wrapping_add(initval);
    let (mut a, mut b, mut c) = (init, init, init);
    let word = |at: usize| u32::from_le_bytes(k[at..at + 4].try_into().unwrap());
    let mut at = 0;
    while len > 12 {
        a = a.wrapping_add(word(at));
        b = b.wrapping_add(word(at + 4));
        c = c.wrapping_add(word(at + 8));
        jhash_mix(&mut a, &mut b, &mut c);
        len -= 12;
        at += 12;
    }
    if len == 0 {
        return c;
    }
    // The last block, a byte at a time into a, b and c.
    for i in (0..len).rev() {
        let v = (k[at + i] as u32) << ((i % 4) * 8);
        match i / 4 {
            0 => a = a.wrapping_add(v),
            1 => b = b.wrapping_add(v),
            _ => c = c.wrapping_add(v),
        }
    }
    jhash_final(&mut a, &mut b, &mut c);
    c
}

/// `jhash2`: 32-bit words.
fn jhash2(k: &[u32], initval: u32) -> u32 {
    let init = JHASH_INITVAL.wrapping_add((k.len() as u32) << 2).wrapping_add(initval);
    let (mut a, mut b, mut c) = (init, init, init);
    let mut rest = k;
    while rest.len() > 3 {
        a = a.wrapping_add(rest[0]);
        b = b.wrapping_add(rest[1]);
        c = c.wrapping_add(rest[2]);
        jhash_mix(&mut a, &mut b, &mut c);
        rest = &rest[3..];
    }
    if rest.is_empty() {
        return c;
    }
    if rest.len() == 3 {
        c = c.wrapping_add(rest[2]);
    }
    if rest.len() >= 2 {
        b = b.wrapping_add(rest[1]);
    }
    a = a.wrapping_add(rest[0]);
    jhash_final(&mut a, &mut b, &mut c);
    c
}

/// `htab_map_hash`: a key of whole words by words (`jhash_1word` and
/// `jhash_2words` come to the same), any other by bytes.
fn htab_hash(key: &[u8], hashrnd: u32) -> u32 {
    if key.len() % 4 == 0 {
        let words: Vec<u32> = key.chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect();
        jhash2(&words, hashrnd)
    } else {
        jhash(key, hashrnd)
    }
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
    /// Counted at each change a mapping would show (a mappable array's).
    changes: std::sync::atomic::AtomicU64,
    /// Frozen (`BPF_MAP_FREEZE`): no longer written through the system
    /// call or a new mapping. Changed under `writers`' lock.
    frozen: std::sync::atomic::AtomicBool,
    /// How many writable mappings there are of it (`bpf_map_write_active`),
    /// each held by a [`WriteHold`] for as long as it lasts: while any
    /// does, it cannot be frozen.
    writers: Mutex<u64>,
    /// A hash's seed for the bucket of a key (`hashrnd`): 0 with
    /// `BPF_F_ZERO_SEED`, else drawn at creation.
    hashrnd: u32,
}

/// A writable mapping of a map, for as long as the mapping lasts (and in
/// a forked child, its copy): what makes the map write-active.
#[derive(Debug)]
struct WriteHold(Arc<Map>);

impl Drop for WriteHold {
    fn drop(&mut self) {
        let mut n = self.0.writers.lock().unwrap_or_else(|e| e.into_inner());
        *n = n.saturating_sub(1);
    }
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
    /// `BPF_MAP_GET_NEXT_KEY` walks). An LRU hash keeps them in the order
    /// they were last used, and when full puts out the least recent.
    Hash(Hash),
    /// `max_entries` elements of a value for each possible CPU, each
    /// value rounded up to eight bytes, as user space reads and writes
    /// them.
    PercpuArray(Vec<u8>),
    /// Prefixes (bits of the key's data) and their values.
    Lpm(Vec<(u32, Vec<u8>, Vec<u8>)>),
    /// A value for each socket that has one, by the socket (its address,
    /// and the socket while it lasts).
    SkStorage(std::collections::HashMap<usize, (std::sync::Weak<dyn FileHandle>, Vec<u8>)>),
    /// A ring buffer ([`Ring`]).
    Ringbuf(Ring),
}

const PAGE: u64 = 4096;

/// A ring buffer as user space maps it (`struct bpf_ringbuf` from its
/// consumer page): the consumer's page (its position first, the one page
/// user space may write), the producer's (its position first), and the
/// data, mapped twice over so a record that wraps reads straight on.
#[derive(Debug)]
pub struct Ring {
    consumer: Vec<u8>,
    producer: Vec<u8>,
    data: Vec<u8>,
    /// Counted at each change, for a mapping to know it is behind.
    changes: u64,
}

impl Ring {
    fn pos(page: &[u8]) -> u64 {
        u64::from_le_bytes(page[..8].try_into().unwrap())
    }

    /// Whether there is a record not consumed (`ringbuf_avail_data_sz`).
    fn pending(&self) -> bool {
        Self::pos(&self.producer) != Self::pos(&self.consumer)
    }

    /// The mapped bytes at `offset`, from the consumer page on.
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let size = self.data.len() as u64;
        let end = (2 * PAGE + 2 * size).saturating_sub(offset).min(buf.len() as u64) as usize;
        for (i, b) in buf[..end].iter_mut().enumerate() {
            let at = offset + i as u64;
            *b = match at / PAGE {
                0 => self.consumer[at as usize],
                1 => self.producer[(at - PAGE) as usize],
                _ => self.data[((at - 2 * PAGE) % size) as usize],
            };
        }
        end
    }
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

/// Every program there is, by id.
static PROGS: Mutex<BTreeMap<u32, std::sync::Weak<crate::bpfprog::Prog>>> = Mutex::new(BTreeMap::new());

fn register_prog(p: &Arc<crate::bpfprog::Prog>) {
    let mut progs = PROGS.lock().unwrap_or_else(|e| e.into_inner());
    progs.retain(|_, m| m.strong_count() > 0);
    progs.insert(p.id, Arc::downgrade(p));
}

fn prog_after(after: u32) -> Option<Arc<crate::bpfprog::Prog>> {
    let progs = PROGS.lock().unwrap_or_else(|e| e.into_inner());
    progs.range(after.saturating_add(1)..).find_map(|(_, m)| m.upgrade())
}

/// Where a value a program found is in its map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueAt {
    /// An array's element.
    Index(u32),
    /// A hash's, by its key.
    Key(Vec<u8>),
    /// A trie's, by its prefix.
    Prefix(u32, Vec<u8>),
    /// A socket's, by the socket.
    Sock(usize),
}

/// A program's descriptor.
#[derive(Debug)]
pub struct ProgFile(pub Arc<crate::bpfprog::Prog>);

impl FileHandle for ProgFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(Errno::EINVAL)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o600, ino: self.0.id as u64, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
    fn bpf_object(&self) -> Option<Object> {
        Some(Object::Prog(Arc::clone(&self.0)))
    }
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
        // `ringbuf_map_alloc`: no key or value, a size of a power of two
        // pages, and no flag but the node's.
        if ty == map_type::RINGBUF {
            if flags & !map_flag::NUMA_NODE != 0 || key_size != 0 || value_size != 0 || !max_entries.is_power_of_two() || max_entries as u64 % PAGE != 0 {
                return Err(Errno::EINVAL);
            }
            let ring = Ring { consumer: vec![0; PAGE as usize], producer: vec![0; PAGE as usize], data: vec![0; max_entries as usize], changes: 1 };
            return Ok(Map { id: next_map_id(), ty, key_size, value_size, max_entries, flags, name, btf: None, data: Mutex::new(Data::Ringbuf(ring)), changes: std::sync::atomic::AtomicU64::new(1), frozen: Default::default(), writers: Mutex::new(0), hashrnd: 0 });
        }
        // (Socket storage has no number of entries: one a socket.)
        if value_size == 0 || (max_entries == 0) != (ty == map_type::SK_STORAGE) || key_size > MAX_KEY {
            return Err(Errno::EINVAL);
        }
        if ty == map_type::SK_STORAGE && value_size > 0xffff - 64 {
            return Err(Errno::E2BIG);
        }
        // A per-CPU value's size has a limit (`PCPU_MIN_UNIT_SIZE`).
        if ty == map_type::PERCPU_ARRAY && value_size > 32 << 10 {
            return Err(Errno::E2BIG);
        }
        use map_flag::*;
        let flags_ok = |allowed: u32| -> Result<(), Errno> {
            if flags & !allowed != 0 {
                unsupported_flags(flags & !allowed);
                return Err(Errno::EINVAL);
            }
            // (Read-only and write-only for user space at once is nothing.)
            if flags & (RDONLY | WRONLY) == RDONLY | WRONLY || flags & (RDONLY_PROG | WRONLY_PROG) == RDONLY_PROG | WRONLY_PROG {
                return Err(Errno::EINVAL);
            }
            Ok(())
        };
        let data = match ty {
            map_type::ARRAY => {
                flags_ok(NUMA_NODE | ACCESS | MMAPABLE)?;
                if key_size != 4 {
                    return Err(Errno::EINVAL);
                }
                // Each element at a multiple of its value rounded up to
                // eight bytes (`elem_size`), as a mapping of it shows; a
                // mappable array's data in whole pages.
                let len = (value_size as u64).next_multiple_of(8).checked_mul(max_entries as u64).filter(|n| *n < 1 << 32).ok_or(Errno::ENOMEM)?;
                let len = if flags & MMAPABLE != 0 { len.next_multiple_of(PAGE) } else { len };
                Data::Array(vec![0; len as usize])
            }
            map_type::PERCPU_ARRAY => {
                flags_ok(NUMA_NODE | ACCESS)?;
                if key_size != 4 {
                    return Err(Errno::EINVAL);
                }
                let each = (value_size as u64).next_multiple_of(8) * crate::cpus::count() as u64;
                let len = each.checked_mul(max_entries as u64).filter(|n| *n < 1 << 32).ok_or(Errno::ENOMEM)?;
                Data::PercpuArray(vec![0; len as usize])
            }
            map_type::HASH | map_type::LRU_HASH => {
                let lru = ty == map_type::LRU_HASH;
                flags_ok(NO_PREALLOC | NUMA_NODE | ACCESS | ZERO_SEED | if lru { NO_COMMON_LRU } else { 0 })?;
                if key_size == 0 {
                    return Err(Errno::EINVAL);
                }
                // An LRU's elements are made ahead (`htab_map_alloc_check`).
                if lru && flags & NO_PREALLOC != 0 {
                    return Err(crate::btf::ENOTSUPP);
                }
                Data::Hash(Hash::default())
            }
            map_type::LPM_TRIE => {
                // `trie_alloc`: no elements made ahead, a key of a prefix
                // length and 1 to 256 bytes of data.
                if flags & NO_PREALLOC == 0 {
                    return Err(Errno::EINVAL);
                }
                flags_ok(NO_PREALLOC | NUMA_NODE | ACCESS)?;
                if !(5..=4 + 256).contains(&key_size) {
                    return Err(Errno::EINVAL);
                }
                Data::Lpm(Vec::new())
            }
            map_type::SK_STORAGE => {
                // `bpf_local_storage_map_alloc_check` (and the BTF its key
                // and value need, which the caller checks after).
                if flags & !(NO_PREALLOC | CLONE) != 0 || flags & NO_PREALLOC == 0 || key_size != 4 {
                    return Err(Errno::EINVAL);
                }
                Data::SkStorage(std::collections::HashMap::new())
            }
            map_type::DEVMAP_HASH => {
                // `dev_map_alloc_check`: a key of four bytes, a value of an
                // ifindex or an ifindex and a program.
                if key_size != 4 || !matches!(value_size, 4 | 8) || flags & !(NUMA_NODE | RDONLY | WRONLY) != 0 || max_entries > 1 << 31 {
                    return Err(Errno::EINVAL);
                }
                Data::Hash(Hash::default())
            }
            other => {
                unsupported_type(other);
                return Err(Errno::EINVAL);
            }
        };
        // A devmap's lookup gives programs the ifindex itself, so they may
        // not write it (`dev_map_init_map`).
        let flags = if ty == map_type::DEVMAP_HASH { flags | RDONLY_PROG } else { flags };
        let hashrnd = if flags & ZERO_SEED != 0 {
            0
        } else {
            let mut b = [0u8; 4];
            crate::vfs::devfs::fill_random(&mut b);
            u32::from_le_bytes(b)
        };
        Ok(Map { id: next_map_id(), ty, key_size, value_size, max_entries, flags, name, btf: None, data: Mutex::new(data), changes: std::sync::atomic::AtomicU64::new(1), frozen: Default::default(), writers: Mutex::new(0), hashrnd })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn value_size(&self) -> u32 {
        self.value_size
    }

    /// How many bytes a value is to user space: a per-CPU map's, one for
    /// each possible CPU, each rounded up to eight bytes.
    pub fn user_value_size(&self) -> usize {
        if self.ty == map_type::PERCPU_ARRAY {
            self.value_size.next_multiple_of(8) as usize * crate::cpus::count() as usize
        } else {
            self.value_size as usize
        }
    }

    /// Whether a program may take the address of its value directly
    /// (`array_map_direct_value_addr`: an array of one element's).
    pub fn direct_value(&self) -> bool {
        self.ty == map_type::ARRAY && self.max_entries == 1
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Data> {
        self.data.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A socket's value (`bpf_fd_sk_storage_lookup_elem`).
    fn sk_lookup(&self, sock: &Arc<dyn FileHandle>) -> Result<Vec<u8>, Errno> {
        let Data::SkStorage(t) = &*self.lock() else { return Err(Errno::EINVAL) };
        let at = Arc::as_ptr(sock) as *const () as usize;
        t.get(&at).filter(|(w, _)| w.strong_count() > 0).map(|(_, v)| v.clone()).ok_or(Errno::ENOENT)
    }

    /// `bpf_local_storage_update` for a socket.
    fn sk_update(&self, sock: &Arc<dyn FileHandle>, value: &[u8], flags: u64) -> Result<(), Errno> {
        if flags & !F_LOCK > EXIST || flags & F_LOCK != 0 {
            return Err(Errno::EINVAL);
        }
        let Data::SkStorage(t) = &mut *self.lock() else { return Err(Errno::EINVAL) };
        t.retain(|_, (w, _)| w.strong_count() > 0);
        let at = Arc::as_ptr(sock) as *const () as usize;
        match (t.contains_key(&at), flags) {
            (true, NOEXIST) => Err(Errno::EEXIST),
            (false, EXIST) => Err(Errno::ENOENT),
            _ => {
                t.insert(at, (Arc::downgrade(sock), value.to_vec()));
                Ok(())
            }
        }
    }

    fn sk_delete(&self, sock: &Arc<dyn FileHandle>) -> Result<(), Errno> {
        let Data::SkStorage(t) = &mut *self.lock() else { return Err(Errno::EINVAL) };
        let at = Arc::as_ptr(sock) as *const () as usize;
        match t.remove(&at) {
            Some((w, _)) if w.strong_count() > 0 => Ok(()),
            _ => Err(Errno::ENOENT),
        }
    }

    /// `map_lookup_elem` from a program: where the value it found is, for
    /// the program to read and write in place; `None` for none. An LRU
    /// hash's lookup is a use of the element. (A program has the value
    /// of the processor it runs on: here, always the first.)
    pub fn find(&self, key: &[u8]) -> Option<ValueAt> {
        let max = self.max_entries;
        match &mut *self.lock() {
            Data::Array(_) | Data::PercpuArray(_) => {
                let i = self.index(key);
                (i < max).then_some(ValueAt::Index(i))
            }
            Data::Hash(h) => {
                let o = *h.at.get(key)?;
                if self.ty == map_type::LRU_HASH {
                    let (k, v) = h.order.remove(&o).unwrap();
                    let n = h.next;
                    h.next += 1;
                    h.order.insert(n, (k, v));
                    h.at.insert(key.to_vec(), n);
                }
                Some(ValueAt::Key(key.to_vec()))
            }
            Data::Lpm(t) => lpm_match(t, key).map(|(p, d, _)| ValueAt::Prefix(*p, d.clone())),
            Data::SkStorage(_) | Data::Ringbuf(_) => None,
        }
    }

    /// The value at `at`, given to `f` to read or write in place; `None`
    /// when it is no longer there (deleted since it was found).
    pub fn with_value<R>(&self, at: &ValueAt, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let vs = self.value_size as usize;
        match (&mut *self.lock(), at) {
            (Data::Array(v), ValueAt::Index(i)) => {
                let at = *i as usize * self.stride();
                self.changed();
                Some(f(&mut v[at..at + vs]))
            }
            (Data::PercpuArray(v), ValueAt::Index(i)) => {
                let each = self.user_value_size();
                Some(f(&mut v[*i as usize * each..*i as usize * each + vs]))
            }
            (Data::Hash(h), ValueAt::Key(k)) => {
                let o = *h.at.get(k)?;
                Some(f(&mut h.order.get_mut(&o)?.1))
            }
            (Data::Lpm(t), ValueAt::Prefix(p, d)) => t.iter_mut().find(|(q, e, _)| q == p && e == d).map(|(_, _, v)| f(v)),
            (Data::SkStorage(t), ValueAt::Sock(at)) => t.get_mut(at).filter(|(w, _)| w.strong_count() > 0).map(|(_, v)| f(v)),
            _ => None,
        }
    }

    /// Each element's key and where its value is, in the order a walk
    /// takes them (`map_for_each_callback`: arrays and hashes).
    pub fn elements(&self) -> Vec<(Vec<u8>, ValueAt)> {
        match &*self.lock() {
            Data::Array(_) | Data::PercpuArray(_) => (0..self.max_entries).map(|i| (i.to_le_bytes().to_vec(), ValueAt::Index(i))).collect(),
            Data::Hash(h) => h.order.values().map(|(k, _)| (k.clone(), ValueAt::Key(k.clone()))).collect(),
            _ => Vec::new(),
        }
    }

    /// `bpf_sk_storage_get` from a program: the socket's value, made
    /// (from `init`, or zeros) when `create` and it has none.
    pub fn sk_get(&self, sock: &Arc<dyn FileHandle>, init: Option<&[u8]>, create: bool) -> Option<ValueAt> {
        let vs = self.value_size as usize;
        let Data::SkStorage(t) = &mut *self.lock() else { return None };
        let at = Arc::as_ptr(sock) as *const () as usize;
        let there = t.get(&at).is_some_and(|(w, _)| w.strong_count() > 0);
        if !there {
            if !create {
                return None;
            }
            t.retain(|_, (w, _)| w.strong_count() > 0);
            t.insert(at, (Arc::downgrade(sock), init.map_or_else(|| vec![0; vs], <[u8]>::to_vec)));
        }
        Some(ValueAt::Sock(at))
    }

    /// `bpf_sk_storage_delete`.
    pub fn sk_delete_of(&self, sock: &Arc<dyn FileHandle>) -> Result<(), Errno> {
        self.sk_delete(sock)
    }

    pub fn key_size(&self) -> u32 {
        self.key_size
    }

    pub fn ty(&self) -> u32 {
        self.ty
    }

    /// An array's elements' spacing (`elem_size`).
    fn stride(&self) -> usize {
        (self.value_size as usize).next_multiple_of(8)
    }

    /// Something a mapping of the map shows has changed: counted, and, for
    /// a map that can be mapped, said, so that mappings are brought up to
    /// date at their processes' next system calls (`crate::locks`).
    fn is_frozen(&self) -> bool {
        self.frozen.load(std::sync::atomic::Ordering::Acquire)
    }

    fn changed(&self) {
        if self.flags & map_flag::MMAPABLE != 0 {
            self.changes.fetch_add(1, std::sync::atomic::Ordering::Release);
            crate::locks::note_written("anon_inode:bpf-map");
        }
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
                let at = i as usize * self.stride();
                Ok(v[at..at + vs].to_vec())
            }
            Data::Hash(h) => h.at.get(key).map(|o| h.order[o].1.clone()).ok_or(Errno::ENOENT),
            Data::PercpuArray(v) => {
                let i = self.index(key);
                if i >= self.max_entries {
                    return Err(Errno::ENOENT);
                }
                let each = self.user_value_size();
                Ok(v[i as usize * each..(i as usize + 1) * each].to_vec())
            }
            Data::Lpm(t) => lpm_match(t, key).map(|(_, _, v)| v.clone()).ok_or(Errno::ENOENT),
            Data::SkStorage(_) => Err(Errno::EINVAL),
            Data::Ringbuf(_) => Err(crate::btf::ENOTSUPP),
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
                let at = i as usize * self.stride();
                v[at..at + vs].copy_from_slice(value);
                self.changed();
                Ok(())
            }
            Data::SkStorage(_) => Err(Errno::EINVAL),
            Data::Ringbuf(_) => Err(crate::btf::ENOTSUPP),
            Data::PercpuArray(v) => {
                let i = self.index(key);
                if i >= max {
                    return Err(Errno::E2BIG);
                }
                if flags == NOEXIST {
                    return Err(Errno::EEXIST);
                }
                let each = self.user_value_size();
                v[i as usize * each..(i as usize + 1) * each].copy_from_slice(&value[..each]);
                Ok(())
            }
            Data::Lpm(t) => {
                // `trie_update_elem`: a prefix no longer than the data,
                // the flags as a hash's, ENOSPC when full.
                let (plen, data) = lpm_key(key);
                if plen as usize > data.len() * 8 {
                    return Err(Errno::EINVAL);
                }
                let at = t.iter().position(|(p, d, _)| *p == plen && prefix_eq(d, &data, plen));
                match (at, flags) {
                    (Some(_), NOEXIST) => Err(Errno::EEXIST),
                    (None, EXIST) => Err(Errno::ENOENT),
                    (Some(i), _) => {
                        t[i].2 = value.to_vec();
                        Ok(())
                    }
                    (None, _) => {
                        if t.len() as u32 >= max {
                            return Err(Errno::ENOSPC);
                        }
                        t.push((plen, masked(&data, plen), value.to_vec()));
                        Ok(())
                    }
                }
            }
            Data::Hash(h) if self.ty == map_type::DEVMAP_HASH => {
                // `__dev_map_hash_update_elem`: an interface there is (the
                // program, if any, the caller has made its id).
                let ifindex = u32::from_le_bytes(value[..4].try_into().unwrap());
                if flags > EXIST || ifindex == 0 {
                    return Err(Errno::EINVAL);
                }
                let there = h.at.get(key).copied();
                if there.is_some() && flags == NOEXIST {
                    return Err(Errno::EEXIST);
                }
                if !crate::netlink::iface_exists(ifindex) {
                    return Err(Errno::EINVAL);
                }
                match there {
                    Some(o) => h.order.get_mut(&o).unwrap().1 = value.to_vec(),
                    None => {
                        if h.order.len() as u32 >= max {
                            return Err(Errno::E2BIG);
                        }
                        let o = h.next;
                        h.next += 1;
                        h.order.insert(o, (key.to_vec(), value.to_vec()));
                        h.at.insert(key.to_vec(), o);
                    }
                }
                Ok(())
            }
            Data::Hash(h) => {
                let lru = self.ty == map_type::LRU_HASH;
                let there = h.at.get(key).copied();
                match (there, flags) {
                    (Some(_), NOEXIST) => Err(Errno::EEXIST),
                    (None, EXIST) => Err(Errno::ENOENT),
                    (Some(o), _) => {
                        if lru {
                            // Used now: last to go.
                            let (k, _) = h.order.remove(&o).unwrap();
                            let n = h.next;
                            h.next += 1;
                            h.order.insert(n, (k, value.to_vec()));
                            h.at.insert(key.to_vec(), n);
                        } else {
                            h.order.get_mut(&o).unwrap().1 = value.to_vec();
                        }
                        Ok(())
                    }
                    (None, _) => {
                        if h.order.len() as u32 >= max {
                            if !lru {
                                return Err(Errno::E2BIG);
                            }
                            // Full: the least recently used makes room.
                            let (&oldest, _) = h.order.iter().next().unwrap();
                            let (k, _) = h.order.remove(&oldest).unwrap();
                            h.at.remove(&k);
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
            Data::Array(_) | Data::PercpuArray(_) | Data::SkStorage(_) => Err(Errno::EINVAL),
            Data::Ringbuf(_) => Err(crate::btf::ENOTSUPP),
            Data::Lpm(t) => {
                let (plen, data) = lpm_key(key);
                let at = t.iter().position(|(p, d, _)| *p == plen && prefix_eq(d, &data, plen)).ok_or(Errno::ENOENT)?;
                t.remove(at);
                Ok(())
            }
            Data::Hash(h) => {
                let o = h.at.remove(key).ok_or(Errno::ENOENT)?;
                h.order.remove(&o);
                Ok(())
            }
        }
    }

    /// Whether the map has a hash's batch walk (`BATCH_OPS(htab)`): a
    /// hash and an LRU hash; a device hash has no batch commands.
    fn hash_batches(&self) -> bool {
        matches!(self.ty, map_type::HASH | map_type::LRU_HASH)
    }

    /// The hash's buckets (`n_buckets`: `max_entries` rounded up to a power
    /// of two).
    fn buckets(&self) -> u32 {
        self.max_entries.next_power_of_two()
    }

    /// The elements of bucket `b` of a hash, as its list holds them: the
    /// latest put there first (`hlist_nulls_add_head_rcu`).
    fn bucket(&self, b: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
        let n = self.buckets();
        match &*self.lock() {
            Data::Hash(h) => h.order.values().rev().filter(|(k, _)| htab_hash(k, self.hashrnd) & (n - 1) == b).cloned().collect(),
            _ => Vec::new(),
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
            // No walk of a socket storage (`notsupp_get_next_key`).
            Data::SkStorage(_) | Data::Ringbuf(_) => Err(crate::btf::ENOTSUPP),
            Data::PercpuArray(_) => {
                let next = match key.map(|k| self.index(k)) {
                    Some(i) if i < self.max_entries => i + 1,
                    _ => 0,
                };
                if next >= self.max_entries {
                    return Err(Errno::ENOENT);
                }
                Ok(next.to_le_bytes().to_vec())
            }
            Data::Lpm(t) => {
                // The trie's post-order: what is under a prefix before it,
                // the 0 side before the 1 side (`trie_get_next_key`); from
                // none, or from a key that is not there, the first.
                let mut sorted: Vec<&(u32, Vec<u8>, Vec<u8>)> = t.iter().collect();
                sorted.sort_by(|a, b| lpm_order(a, b));
                let at = key.and_then(|key| {
                    let (plen, data) = lpm_key(key);
                    sorted.iter().position(|(p, d, _)| *p == plen && prefix_eq(d, &data, plen))
                });
                let next = match at {
                    Some(i) => sorted.get(i + 1),
                    None => sorted.first(),
                };
                let (p, d, _) = next.ok_or(Errno::ENOENT)?;
                let mut out = p.to_le_bytes().to_vec();
                out.extend_from_slice(d);
                Ok(out)
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

    /// `struct bpf_map_info` (88 bytes): the caller's (`user`), with what
    /// the kernel says of the map put in it.
    fn info(&self, user: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 88];
        let n = user.len().min(b.len());
        b[..n].copy_from_slice(&user[..n]);
        // `btf_vmlinux_value_type_id` and `map_extra`: none here.
        b[44..48].fill(0);
        b[80..88].fill(0);
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

/// Say `what` once, as it is: something done in part.
pub(crate) fn note_once(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] bpf: {what}");
        said.push(what.to_string());
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
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o600, ino: self.map.id as u64, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
    fn bpf_object(&self) -> Option<Object> {
        Some(Object::Map(Arc::clone(&self.map)))
    }
    fn bpf_access(&self) -> Option<(bool, bool)> {
        Some((self.read, self.write))
    }

    /// `bpf_map_mmap`: only a ring buffer maps (an array that could is
    /// refused when made), shared, and of it only the consumer's page for
    /// writing (`ringbuf_map_mmap_kern`), no further than its pages.
    fn may_map(&self, offset: u64, len: u64, prot: u32, shared: bool) -> Result<(), Errno> {
        let map = &self.map;
        // An array: if it was made mappable, its data's pages
        // (`array_map_mmap`); not to be written for a map programs only
        // read.
        let writes = prot & crate::mem::prot::WRITE != 0;
        if let Data::Array(v) = &*map.lock() {
            if !shared {
                return Err(Errno::EINVAL);
            }
            if writes && map.is_frozen() {
                return Err(Errno::EPERM);
            }
            if writes && map.flags & map_flag::RDONLY_PROG != 0 {
                return Err(Errno::EACCES);
            }
            if map.flags & map_flag::MMAPABLE == 0 || offset.checked_add(len).is_none_or(|end| end > v.len() as u64) {
                return Err(Errno::EINVAL);
            }
            return Ok(());
        }
        let Data::Ringbuf(ring) = &*self.map.lock() else { return Err(crate::btf::ENOTSUPP) };
        if !shared {
            return Err(Errno::EINVAL);
        }
        if writes && map.is_frozen() {
            return Err(Errno::EPERM);
        }
        if prot & crate::mem::prot::WRITE != 0 && (offset != 0 || len != PAGE) {
            return Err(Errno::EPERM);
        }
        if offset.checked_add(len).is_none_or(|end| end > 2 * PAGE + 2 * ring.data.len() as u64) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
    /// A mapping made read-only stays so (`bpf_map_mmap`).
    fn read_only_mapping_stays(&self) -> bool {
        true
    }
    /// A writable mapping makes the map write-active until it ends; one
    /// asked of a map frozen since [`FileHandle::may_map`] is `EPERM`
    /// (`bpf_map_mmap` checks and counts under one lock).
    fn map_hold(&self, prot: u32, shared: bool) -> Result<Option<Arc<dyn std::any::Any + Send + Sync>>, Errno> {
        if !shared || prot & crate::mem::prot::WRITE == 0 {
            return Ok(None);
        }
        let mut n = self.map.writers.lock().unwrap_or_else(|e| e.into_inner());
        if self.map.is_frozen() {
            return Err(Errno::EPERM);
        }
        *n += 1;
        drop(n);
        Ok(Some(Arc::new(WriteHold(Arc::clone(&self.map)))))
    }
    fn mapped_len(&self) -> Option<u64> {
        match &*self.map.lock() {
            Data::Ringbuf(ring) => Some(2 * PAGE + 2 * ring.data.len() as u64),
            Data::Array(v) if self.map.flags & map_flag::MMAPABLE != 0 => Some(v.len() as u64),
            _ => None,
        }
    }
    fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> crate::errno::SysResult {
        match &*self.map.lock() {
            Data::Ringbuf(ring) => Ok(ring.read(offset, buf) as u64),
            Data::Array(v) if self.map.flags & map_flag::MMAPABLE != 0 => {
                let start = (offset as usize).min(v.len());
                let n = buf.len().min(v.len() - start);
                buf[..n].copy_from_slice(&v[start..start + n]);
                Ok(n as u64)
            }
            _ => Err(Errno::EINVAL),
        }
    }
    /// What a mapping writes back: the consumer's page, the one it may.
    fn write_mapped(&self, offset: u64, buf: &[u8]) -> crate::errno::SysResult {
        match &mut *self.map.lock() {
            Data::Ringbuf(ring) if offset.checked_add(buf.len() as u64).is_some_and(|end| end <= PAGE) => {
                ring.consumer[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
                ring.changes += 1;
                Ok(buf.len() as u64)
            }
            Data::Array(v) if self.map.flags & map_flag::MMAPABLE != 0 && offset.checked_add(buf.len() as u64).is_some_and(|end| end <= v.len() as u64) => {
                v[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
                self.map.changed();
                Ok(buf.len() as u64)
            }
            _ => Err(Errno::EINVAL),
        }
    }
    fn changes(&self) -> u64 {
        match &*self.map.lock() {
            Data::Ringbuf(ring) => ring.changes,
            Data::Array(_) if self.map.flags & map_flag::MMAPABLE != 0 => self.map.changes.load(std::sync::atomic::Ordering::Acquire),
            _ => 0,
        }
    }
    /// To `poll`, a ring buffer is readable while a record waits, and never
    /// writable (`ringbuf_map_poll_kern`); any other map says only
    /// `POLLERR`. (A `read` or `write` never waits: it is `EINVAL`.)
    fn poll_in(&self) -> bool {
        match &*self.map.lock() {
            Data::Ringbuf(ring) => ring.pending(),
            _ => false,
        }
    }
    fn poll_out(&self) -> bool {
        false
    }
    fn poll_err(&self) -> bool {
        !matches!(&*self.map.lock(), Data::Ringbuf(_))
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
    /// `CAP_NET_ADMIN`.
    pub net_admin: bool,
    /// `bpf_dump_raw_ok`: whether it may see kernel addresses (by
    /// `kernel.kptr_restrict` and `CAP_SYSLOG`).
    pub raw_ok: bool,
    pub uid: u32,
    pub gid: u32,
    /// The real group and user, as `bpf_get_current_uid_gid` gives them.
    pub real_uid_gid: u64,
    pub umask: u32,
}

fn install(c: &Caller<'_>, obj: Object, read: bool, write: bool) -> crate::errno::SysResult {
    // A map made read-only or write-only for user space gives no
    // descriptor that does the other (`map_get_sys_perms`).
    let (read, write) = match &obj {
        Object::Map(m) => (read && m.flags & map_flag::WRONLY == 0, write && m.flags & map_flag::RDONLY == 0),
        _ => (read, write),
    };
    let (handle, name): (Arc<dyn FileHandle>, &str) = match obj {
        Object::Map(map) => (Arc::new(MapFile { map, read, write }), "anon_inode:bpf-map"),
        Object::Btf(btf) => (Arc::new(crate::btf::BtfFile(btf)), "anon_inode:btf"),
        Object::Prog(p) => (Arc::new(ProgFile(p)), "anon_inode:bpf-prog"),
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

/// The most a test run's packet may be (`bpf_test_init` at 6.18): a page
/// less the headroom an skb keeps (`NET_SKB_PAD`, 64 on arm64, whose
/// `NET_IP_ALIGN` is 0) and the room for its shared information at the
/// end (`SKB_DATA_ALIGN(sizeof(struct skb_shared_info))`: 360 bytes with
/// GKI's Android reserves and 17 fragments, 384 aligned). (Linux 7.0 takes
/// far more.)
const TEST_MAX_DATA: u32 = 4096 - 64 - 384;

/// The program type a cgroup attach type takes (`attach_type_to_prog_type`),
/// for the cgroup hooks this kernel has; `None` for any other, said once
/// where it is one Linux has.
fn cgroup_prog_type(ty: u32) -> Option<u32> {
    use crate::bpfprog::{attach::*, prog_type};
    Some(match ty {
        INET_INGRESS | INET_EGRESS => prog_type::CGROUP_SKB,
        INET_SOCK_CREATE | INET_SOCK_RELEASE | INET4_POST_BIND | INET6_POST_BIND => prog_type::CGROUP_SOCK,
        INET4_BIND | INET6_BIND | INET4_CONNECT | INET6_CONNECT | UDP4_SENDMSG | UDP6_SENDMSG | UDP4_RECVMSG | UDP6_RECVMSG | INET4_GETPEERNAME | INET6_GETPEERNAME | INET4_GETSOCKNAME | INET6_GETSOCKNAME | UNIX_CONNECT | UNIX_SENDMSG | UNIX_RECVMSG | UNIX_GETPEERNAME | UNIX_GETSOCKNAME => prog_type::CGROUP_SOCK_ADDR,
        GETSOCKOPT | SETSOCKOPT => prog_type::CGROUP_SOCKOPT,
        other => {
            if other <= 60 {
                say_once(&format!("attaching a program at attach type {other}"));
            }
            return None;
        }
    })
}

/// The program a descriptor is, of type `ty` (`bpf_prog_get_type`):
/// `EBADF` for no descriptor, `EINVAL` for one that is not a program of it.
fn prog_of(c: &Caller<'_>, fd: i32, ty: u32) -> Result<Arc<crate::bpfprog::Prog>, Errno> {
    match c.fds.get(fd)?.handle.bpf_object() {
        Some(Object::Prog(p)) if p.ty == ty => Ok(p),
        _ => Err(Errno::EINVAL),
    }
}

/// The map a descriptor is, with whether it may be read and written.
fn map_of(c: &Caller<'_>, fd: i32) -> Result<(Arc<Map>, bool, bool), Errno> {
    let file = c.fds.get(fd)?;
    match file.handle.bpf_object() {
        Some(Object::Map(map)) => {
            // A frozen map is not the system call's to write
            // (`map_get_sys_perms`), whatever the descriptor may do.
            let (r, w) = file.handle.bpf_access().unwrap_or((true, true));
            let w = w && !map.is_frozen();
            Ok((map, r, w))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Whether `map`'s value has fields the kernel manages
/// (`map->record`, from its BTF).
fn map_has_record(map: &Map) -> bool {
    map.btf.as_ref().is_some_and(|(btf, _, value)| btf.has_special_fields(*value))
}

/// `bpf(cmd, attr, size)`.
pub fn call(c: &Caller<'_>, m: &mut GuestMem<'_>, cmd: u64, attr: u64, size: u64) -> crate::errno::SysResult {
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
            // Who may make it (`map_create`): no one without CAP_BPF while
            // `kernel.unprivileged_bpf_disabled` is set, and some types
            // only with CAP_BPF or CAP_NET_ADMIN at all. Asked after the
            // type's own check of what it is asked for, where it has one
            // (`map_alloc_check`), and before it is made.
            let allowed = (c.capable || crate::vfs::procfs::bpf_sysctl::Which::UnprivDisabled.get() == 0)
                && match ty {
                    map_type::LRU_HASH | map_type::LPM_TRIE | map_type::SK_STORAGE => c.capable,
                    map_type::DEVMAP_HASH => c.net_admin,
                    _ => true,
                };
            let checked_first = !matches!(ty, map_type::LPM_TRIE | map_type::RINGBUF);
            if !allowed && !checked_first {
                return Err(Errno::EPERM);
            }
            let mut map = Map::create(ty, key, value, max, flags, name)?;
            if !allowed {
                return Err(Errno::EPERM);
            }
            // Its key's and value's types (`map_check_btf`): the value's
            // there and the value's size, the key's too where it is named.
            let (btf_fd, key_id, value_id) = (u32_at(48), u32_at(52), u32_at(56));
            if ty == map_type::SK_STORAGE && (key_id == 0 || value_id == 0) {
                return Err(Errno::EINVAL);
            }
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
                    map_type::SK_STORAGE if !btf.is_i32(key_id) => return Err(Errno::EINVAL),
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
            // Past each command's last field (`CHECK_ATTR`): a delete's is
            // the key, a walk's the next key, the others' the flags.
            zero_from(match cmd {
                cmd::MAP_DELETE_ELEM => 16,
                cmd::MAP_GET_NEXT_KEY => 24,
                _ => 32,
            })?;
            let (map, r, w) = map_of(c, u32_at(0) as i32)?;
            let ks = map.key_size as usize;
            // A ring buffer has no elements: it is read by mapping it
            // (`ringbuf_map_lookup_elem` and its kin), after the checks
            // the system call makes of any map.
            if map.ty == map_type::RINGBUF {
                let flags = u64_at(24);
                let wants_read = matches!(cmd, cmd::MAP_LOOKUP_ELEM | cmd::MAP_GET_NEXT_KEY);
                if cmd == cmd::MAP_LOOKUP_ELEM && flags & !F_LOCK != 0 {
                    return Err(Errno::EINVAL);
                }
                if if wants_read { !r } else { !w } {
                    return Err(Errno::EPERM);
                }
                if matches!(cmd, cmd::MAP_LOOKUP_ELEM | cmd::MAP_UPDATE_ELEM) && flags & F_LOCK != 0 {
                    return Err(Errno::EINVAL);
                }
                // A key given to a map with none (`___bpf_copy_key`).
                if u64_at(8) != 0 {
                    return Err(Errno::EINVAL);
                }
                return Err(crate::btf::ENOTSUPP);
            }
            // Socket storage: the key is a socket's descriptor.
            if map.ty == map_type::SK_STORAGE && cmd != cmd::MAP_GET_NEXT_KEY {
                let fd = m.read_u32(u64_at(8))? as i32;
                let sock = c.fds.get(fd)?.handle.clone();
                if sock.metadata()?.file_type != FileType::Socket {
                    return Err(Errno::ENOTSOCK);
                }
                match cmd {
                    cmd::MAP_LOOKUP_ELEM => {
                        if !r {
                            return Err(Errno::EPERM);
                        }
                        let v = map.sk_lookup(&sock)?;
                        m.write(u64_at(16), &v)?;
                    }
                    cmd::MAP_UPDATE_ELEM => {
                        if !w {
                            return Err(Errno::EPERM);
                        }
                        let v = m.read(u64_at(16), map.value_size as usize)?.to_vec();
                        map.sk_update(&sock, &v, u64_at(24))?;
                    }
                    _ => {
                        if !w {
                            return Err(Errno::EPERM);
                        }
                        map.sk_delete(&sock)?;
                    }
                }
                return Ok(0);
            }
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
                    let mut value = m.read(u64_at(16), map.user_value_size())?.to_vec();
                    // A devmap's program, by its descriptor: an XDP program
                    // for a devmap, kept by its id (`__dev_map_alloc_node`).
                    if map.ty == map_type::DEVMAP_HASH && value.len() == 8 {
                        let fd = i32::from_le_bytes(value[4..8].try_into().unwrap());
                        let id = if fd > 0 {
                            match c.fds.get(fd).ok().and_then(|f| f.handle.bpf_object()) {
                                Some(Object::Prog(p)) if p.ty == crate::bpfprog::prog_type::XDP && p.expected_attach == crate::bpfprog::attach::XDP_DEVMAP => p.id,
                                _ => return Err(Errno::EINVAL),
                            }
                        } else {
                            0
                        };
                        value[4..8].copy_from_slice(&id.to_le_bytes());
                    }
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
        // The batch commands (`bpf_map_do_batch`): `struct { in_batch,
        // out_batch, keys, values; u32 count, map_fd; u64 elem_flags, flags }`.
        // A hash walks its buckets (`__htab_map_lookup_and_delete_batch`),
        // the others go a key at a time (`generic_map_*_batch`); a map with
        // no such command is `ENOTSUPP`.
        cmd::MAP_LOOKUP_BATCH | cmd::MAP_LOOKUP_AND_DELETE_BATCH | cmd::MAP_UPDATE_BATCH | cmd::MAP_DELETE_BATCH => {
            if size < 56 {
                return Err(Errno::EINVAL);
            }
            zero_from(56)?;
            let (map, r, w) = map_of(c, u32_at(36) as i32)?;
            let reads = matches!(cmd, cmd::MAP_LOOKUP_BATCH | cmd::MAP_LOOKUP_AND_DELETE_BATCH);
            let writes = cmd != cmd::MAP_LOOKUP_BATCH;
            if (reads && !r) || (writes && !w) {
                return Err(Errno::EPERM);
            }
            let generic = matches!(map.ty, map_type::ARRAY | map_type::PERCPU_ARRAY | map_type::LPM_TRIE);
            let has = match cmd {
                cmd::MAP_LOOKUP_BATCH | cmd::MAP_UPDATE_BATCH => map.hash_batches() || generic,
                cmd::MAP_LOOKUP_AND_DELETE_BATCH => map.hash_batches(),
                _ => map.hash_batches() || map.ty == map_type::LPM_TRIE,
            };
            if !has {
                return Err(crate::btf::ENOTSUPP);
            }
            // No map here has a spin lock for `BPF_F_LOCK` to take.
            if u64_at(40) != 0 {
                return Err(Errno::EINVAL);
            }
            let (in_batch, out_batch, keys, values) = (u64_at(0), u64_at(8), u64_at(16), u64_at(24));
            let max = u32_at(32);
            let ks = map.key_size as u64;
            let count_at = attr + 32;
            let hash_walk = map.hash_batches() && matches!(cmd, cmd::MAP_LOOKUP_BATCH | cmd::MAP_LOOKUP_AND_DELETE_BATCH);
            if hash_walk && u64_at(48) != 0 {
                return Err(Errno::EINVAL);
            }
            if max == 0 {
                return Ok(0);
            }
            m.write(count_at, &0u32.to_le_bytes())?;
            if hash_walk {
                // Whole buckets, from the one `in_batch` names; `ENOSPC` if
                // the first will not fit, `ENOENT` past the last, and the
                // bucket to go on from in `out_batch`.
                let delete = cmd == cmd::MAP_LOOKUP_AND_DELETE_BATCH;
                let vs = map.value_size as u64;
                let n = map.buckets();
                let mut batch = if in_batch != 0 { m.read_u32(in_batch)? } else { 0 };
                if batch >= n {
                    return Err(Errno::ENOENT);
                }
                let mut total = 0u32;
                let mut ret = Ok(0);
                loop {
                    let elems = map.bucket(batch);
                    let cnt = elems.len() as u32;
                    if cnt > max - total {
                        if total == 0 {
                            ret = Err(Errno::ENOSPC);
                        }
                        break;
                    }
                    if delete {
                        for (k, _) in &elems {
                            let _ = map.delete(k);
                        }
                    }
                    for (i, (k, v)) in elems.iter().enumerate() {
                        let at = (total + i as u32) as u64;
                        m.write(keys + at * ks, k)?;
                        m.write(values + at * vs, v)?;
                    }
                    total += cnt;
                    batch += 1;
                    if batch >= n {
                        ret = Err(Errno::ENOENT);
                        break;
                    }
                }
                m.write(out_batch, &batch.to_le_bytes())?;
                m.write(count_at, &total.to_le_bytes())?;
                return ret;
            }
            let vs = map.user_value_size() as u64;
            let mut cp = 0u32;
            let mut err: Result<(), Errno> = Ok(());
            match cmd {
                cmd::MAP_LOOKUP_BATCH => {
                    // Key after key from the one `in_batch` holds; the last
                    // key gone over back in `out_batch`.
                    let mut prev = if in_batch != 0 { Some(m.read(in_batch, ks as usize)?.to_vec()) } else { None };
                    while cp < max {
                        let key = match map.next_key(prev.as_deref()) {
                            Ok(k) => k,
                            Err(e) => {
                                err = Err(e);
                                break;
                            }
                        };
                        match map.lookup(&key) {
                            Ok(v) => {
                                m.write(keys + cp as u64 * ks, &key)?;
                                m.write(values + cp as u64 * vs, &v)?;
                                cp += 1;
                            }
                            Err(Errno::ENOENT) => {}
                            Err(e) => return Err(e),
                        }
                        prev = Some(key);
                    }
                    m.write(count_at, &cp.to_le_bytes())?;
                    if cp > 0 {
                        if let Some(p) = &prev {
                            m.write(out_batch, p)?;
                        }
                    }
                }
                cmd::MAP_UPDATE_BATCH => {
                    while cp < max {
                        let key = match m.read(keys + cp as u64 * ks, ks as usize) {
                            Ok(k) => k.to_vec(),
                            Err(_) => {
                                err = Err(Errno::EFAULT);
                                break;
                            }
                        };
                        let value = match m.read(values + cp as u64 * vs, vs as usize) {
                            Ok(v) => v.to_vec(),
                            Err(_) => {
                                err = Err(Errno::EFAULT);
                                break;
                            }
                        };
                        if let Err(e) = map.update(&key, &value, 0) {
                            err = Err(e);
                            break;
                        }
                        cp += 1;
                    }
                    m.write(count_at, &cp.to_le_bytes())?;
                }
                _ => {
                    while cp < max {
                        let key = match m.read(keys + cp as u64 * ks, ks as usize) {
                            Ok(k) => k.to_vec(),
                            Err(_) => {
                                err = Err(Errno::EFAULT);
                                break;
                            }
                        };
                        if let Err(e) = map.delete(&key) {
                            err = Err(e);
                            break;
                        }
                        cp += 1;
                    }
                    m.write(count_at, &cp.to_le_bytes())?;
                }
            }
            err.map(|_| 0)
        }
        // `map_freeze`: the descriptor must be able to write it, and no
        // writable mapping of it be left; frozen, the system call and new
        // mappings no longer write it (programs still may).
        cmd::MAP_FREEZE => {
            zero_from(4)?;
            let (map, _, w) = map_of(c, u32_at(0) as i32)?;
            if map_has_record(&map) {
                return Err(crate::btf::ENOTSUPP);
            }
            if !w {
                return Err(Errno::EPERM);
            }
            let n = map.writers.lock().unwrap_or_else(|e| e.into_inner());
            if *n != 0 || map.is_frozen() {
                return Err(Errno::EBUSY);
            }
            map.frozen.store(true, std::sync::atomic::Ordering::Release);
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
                cmd::PROG_GET_NEXT_ID => prog_after(u32_at(0)).map(|p| p.id),
                _ => map_after(u32_at(0)).map(|m| m.id),
            };
            let next = next.ok_or(Errno::ENOENT)?;
            m.write_u32(attr + 4, next)?;
            Ok(0)
        }
        cmd::PROG_GET_FD_BY_ID => {
            zero_from(12)?;
            if !c.admin {
                return Err(Errno::EPERM);
            }
            if u32_at(8) != 0 {
                return Err(Errno::EINVAL);
            }
            let id = u32_at(0);
            let p = prog_after(id.wrapping_sub(1)).filter(|p| p.id == id).ok_or(Errno::ENOENT)?;
            install(c, Object::Prog(p), true, true)
        }
        cmd::PROG_LOAD => prog_load(c, m, attr, &a),
        cmd::PROG_ATTACH | cmd::PROG_DETACH => {
            // ... expected_revision, the last field of both.
            zero_from(32)?;
            let (target, prog_fd, ty, flags, replace_fd, relative, revision) = (u32_at(0), u32_at(4), u32_at(8), u32_at(12), u32_at(16), u32_at(20), u64_at(24));
            let ptype = cgroup_prog_type(ty).ok_or(Errno::EINVAL)?;
            let group = |c: &Caller<'_>| -> Result<u64, Errno> { c.fds.get(target as i32)?.handle.cgroup().ok_or(Errno::EBADF) };
            if cmd == cmd::PROG_DETACH {
                let g = group(c)?;
                let prog = prog_of(c, prog_fd as i32, ptype).ok();
                return crate::cgroup::bpf_detach(g, ty, prog, revision).map(|_| 0);
            }
            use crate::cgroup::bpf_flag::*;
            if flags & !(ALLOW_OVERRIDE | ALLOW_MULTI | REPLACE | PLACED) != 0 {
                return Err(Errno::EINVAL);
            }
            if flags & PLACED != 0 || relative != 0 {
                say_once("a cgroup program placed before or after another, or by a link");
                return Err(Errno::EINVAL);
            }
            let prog = prog_of(c, prog_fd as i32, ptype)?;
            // `bpf_prog_attach_check_attach_type`. (A cgroup skb program
            // the verifier would hold to its expected type, one whose return
            // may be 2 or 3, is not told apart here.)
            match ptype {
                crate::bpfprog::prog_type::CGROUP_SKB => {
                    if !c.net_admin {
                        return Err(Errno::EPERM);
                    }
                }
                _ if prog.expected_attach != ty => return Err(Errno::EINVAL),
                _ => {}
            }
            let g = group(c)?;
            let replace = if flags & ALLOW_MULTI != 0 && flags & REPLACE != 0 { Some(prog_of(c, replace_fd as i32, ptype)?) } else { None };
            crate::cgroup::bpf_attach(g, ty, prog, replace, flags, revision)?;
            // Run where a socket is made and at getsockopt and setsockopt
            // (crate::bpfsock); the other hooks are not here yet.
            if !matches!(ty, crate::bpfprog::attach::INET_SOCK_CREATE | crate::bpfprog::attach::GETSOCKOPT | crate::bpfprog::attach::SETSOCKOPT) {
                note_once(&format!("a program attached to a cgroup at attach type {ty} is kept and runs nowhere yet"));
            }
            Ok(0)
        }
        cmd::PROG_TEST_RUN => {
            // ... batch_size, the last field.
            zero_from(76)?;
            let (prog_fd, size_in, room, data_in, data_out, repeat) = (u32_at(0), u32_at(8), u32_at(12), u64_at(16), u64_at(24), u32_at(32));
            let (ctx_size_in, ctx_size_out, ctx_in, ctx_out, flags, cpu, batch) = (u32_at(40), u32_at(44), u64_at(48), u64_at(56), u32_at(64), u32_at(68), u32_at(72));
            if (ctx_size_in != 0) != (ctx_in != 0) || (ctx_size_out != 0) != (ctx_out != 0) {
                return Err(Errno::EINVAL);
            }
            let prog = match c.fds.get(prog_fd as i32)?.handle.bpf_object() {
                Some(Object::Prog(p)) => p,
                _ => return Err(Errno::EINVAL),
            };
            use crate::bpfprog::prog_type::*;
            if !matches!(prog.ty, SOCKET_FILTER | SCHED_CLS | SCHED_ACT | CGROUP_SKB) {
                say_once(&format!("a test run of a program of type {}", prog.ty));
                return Err(crate::btf::ENOTSUPP);
            }
            // `bpf_prog_test_run_skb`: BPF_F_TEST_SKB_CHECKSUM_COMPLETE the
            // only flag; a packet in a page with the room an skb keeps.
            if flags & !1 != 0 || cpu != 0 || batch != 0 {
                return Err(Errno::EINVAL);
            }
            if flags != 0 {
                say_once("a test run with BPF_F_TEST_SKB_CHECKSUM_COMPLETE");
                return Err(Errno::EINVAL);
            }
            if size_in < 14 {
                return Err(Errno::EINVAL);
            }
            if size_in > TEST_MAX_DATA {
                return Err(Errno::EINVAL);
            }
            const CTX: usize = crate::bpfskb::off::SIZE as usize;
            let mut ctx = vec![0u8; CTX];
            let given = if ctx_in != 0 || ctx_out != 0 {
                if ctx_in != 0 {
                    let n = ctx_size_in as usize;
                    if n > CTX && m.read(ctx_in + CTX as u64, n - CTX)?.iter().any(|b| *b != 0) {
                        return Err(Errno::E2BIG);
                    }
                    ctx[..n.min(CTX)].copy_from_slice(m.read(ctx_in, n.min(CTX))?);
                }
                true
            } else {
                false
            };
            let packet = m.read(data_in, size_in as usize)?.to_vec();
            let mut skb = crate::bpfskb::for_test(prog.ty, &packet, given.then_some(&ctx[..]))?;
            skb.uid_gid = c.real_uid_gid;
            let start = crate::syscalls::clock_ns(crate::syscalls::system_clock, 1);
            let mut retval = 0u32;
            for _ in 0..repeat.max(1) {
                retval = crate::bpfrun::run(&prog, &mut skb).map_err(|_| Errno::EINVAL)? as u32;
            }
            let took = crate::syscalls::clock_ns(crate::syscalls::system_clock, 1).saturating_sub(start);
            let out = skb.after_test(&mut ctx);
            // `bpf_test_finish`.
            let size = out.len() as u32;
            let mut r = Ok(0);
            let copy = if room != 0 && size > room {
                r = Err(Errno::ENOSPC);
                room
            } else {
                size
            };
            if data_out != 0 {
                m.write(data_out, &out[..copy as usize])?;
            }
            m.write_u32(attr + 12, size)?;
            m.write_u32(attr + 4, retval)?;
            m.write_u32(attr + 36, (took / repeat.max(1) as u64) as u32)?;
            r?;
            // `bpf_ctx_finish`.
            if given && ctx_out != 0 {
                let n = CTX.min(ctx_size_out as usize);
                m.write(ctx_out, &ctx[..n])?;
                m.write_u32(attr + 44, CTX as u32)?;
                if (ctx_size_out as usize) < CTX {
                    return Err(Errno::ENOSPC);
                }
            }
            Ok(0)
        }
        cmd::PROG_QUERY => {
            if !(c.net_admin || c.admin) {
                return Err(Errno::EPERM);
            }
            // ... revision, the last field.
            zero_from(64)?;
            let (target, ty, qflags, ids_at, cnt, flags_at) = (u32_at(0), u32_at(4), u32_at(8), u64_at(16), u32_at(24), u64_at(32));
            const EFFECTIVE: u32 = 1;
            if qflags & !EFFECTIVE != 0 {
                return Err(Errno::EINVAL);
            }
            cgroup_prog_type(ty).ok_or(Errno::EINVAL)?;
            let g = c.fds.get(target as i32)?.handle.cgroup().ok_or(Errno::EBADF)?;
            let effective = qflags & EFFECTIVE != 0;
            if effective && flags_at != 0 {
                return Err(Errno::EINVAL);
            }
            let (flags, progs, revision) = crate::cgroup::bpf_query(g, ty, effective)?;
            m.write_u32(attr + 12, flags)?;
            m.write_u32(attr + 24, progs.len() as u32)?;
            if size >= 64 {
                m.write_u64(attr + 56, revision)?;
            }
            if cnt == 0 || ids_at == 0 || progs.is_empty() {
                return Ok(0);
            }
            let n = progs.len().min(cnt as usize);
            for (k, p) in progs.iter().take(n).enumerate() {
                m.write_u32(ids_at + 4 * k as u64, p.id)?;
                if flags_at != 0 {
                    m.write_u32(flags_at + 4 * k as u64, flags)?;
                }
            }
            if (cnt as usize) < progs.len() {
                return Err(Errno::ENOSPC);
            }
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
            // The caller's struct as far as it gave it: the kernel fills it
            // in, and what it does not fill stays the caller's.
            let user = m.read(u64_at(8), (u32_at(4) as usize).min(256))?.to_vec();
            let info = match file.handle.bpf_object() {
                Some(Object::Map(map)) => map.info(&user),
                Some(Object::Prog(p)) => p.info(&user, m, c.capable, c.raw_ok)?,
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

/// `BPF_PROG_LOAD` (`bpf_prog_load`), its checks in its order: the fields
/// it does not read zero, its flags, the license, the instruction count,
/// the type and what it expects to be attached to, the name, function and
/// line information against the BTF; then the program
/// ([`crate::bpfprog::Prog::load`]); then the log.
fn prog_load(c: &Caller<'_>, m: &mut GuestMem<'_>, attr: u64, a: &[u8]) -> crate::errno::SysResult {
    let u32_at = |at: usize| u32::from_le_bytes(a[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(a[at..at + 8].try_into().unwrap());
    if a[148..].iter().any(|b| *b != 0) {
        return Err(Errno::EINVAL);
    }
    let (ty, insn_cnt, insns, license_at) = (u32_at(0), u32_at(4), u64_at(8), u64_at(16));
    let (log_level, log_size, log_buf) = (u32_at(24), u32_at(28), u64_at(32));
    let flags = u32_at(44);
    // BPF_F_STRICT_ALIGNMENT, ANY_ALIGNMENT, TEST_RND_HI32,
    // TEST_STATE_FREQ, SLEEPABLE, XDP_HAS_FRAGS, XDP_DEV_BOUND_ONLY,
    // TEST_REG_INVARIANTS, TOKEN_FD.
    if flags & !0x1ff != 0 {
        return Err(Errno::EINVAL);
    }
    // Without CAP_BPF: nothing while `kernel.unprivileged_bpf_disabled`
    // is set; when it is not, Linux lets a socket filter or a cgroup skb
    // program be loaded and holds it to the verifier's unprivileged rules,
    // which are not here.
    if !c.capable {
        if crate::vfs::procfs::bpf_sysctl::Which::UnprivDisabled.get() == 0 && matches!(ty, crate::bpfprog::prog_type::SOCKET_FILTER | crate::bpfprog::prog_type::CGROUP_SKB) {
            say_once("a program loaded without CAP_BPF (the verifier's unprivileged rules)");
        }
        return Err(Errno::EPERM);
    }
    let license = String::from_utf8_lossy(&m.read_cstr(license_at, 128)?).into_owned();
    if insn_cnt == 0 || insn_cnt > crate::bpfprog::MAX_INSNS {
        return Err(Errno::E2BIG);
    }
    if u32_at(64) != 0 {
        say_once("a program offloaded to a device");
        return Err(Errno::EINVAL);
    }
    if u32_at(108) != 0 || u32_at(112) != 0 || u32_at(116) != 0 || u64_at(120) != 0 || u64_at(128) != 0 {
        say_once("a program attached by BTF id, with CO-RE relocations, or with an fd_array");
        return Err(Errno::EINVAL);
    }
    let expected = u32_at(68);
    crate::bpfprog::check_attach(ty, expected).map_err(|e| if ty == 0 || ty > crate::bpfprog::prog_type::MAX { Errno::EINVAL } else { e })?;
    let mut name = [0u8; 16];
    name.copy_from_slice(&a[48..64]);
    if !name.iter().take_while(|b| **b != 0).all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.') || name[15] != 0 {
        return Err(Errno::EINVAL);
    }
    check_log(log_buf, log_size, log_level)?;
    let raw = m.read(insns, insn_cnt as usize * 8)?.to_vec();
    // Function and line information, which name the program's BTF.
    let (btf_fd, func_rec, func_at, func_cnt, line_rec, line_at, line_cnt) = (u32_at(72), u32_at(76), u64_at(80), u32_at(88), u32_at(92), u64_at(96), u32_at(104));
    // Kept as the kernel keeps them (`bpf_func_info`'s 8 bytes a record,
    // `bpf_line_info`'s 16), with the BTF they name.
    let mut prog_btf = None;
    if func_cnt != 0 || line_cnt != 0 {
        let btf = match c.fds.get(btf_fd as i32)?.handle.bpf_object() {
            Some(Object::Btf(b)) => b,
            _ => return Err(Errno::EINVAL),
        };
        let (mut func_info, mut line_info) = (Vec::new(), Vec::new());
        if func_cnt != 0 {
            // `check_btf_func`: records of at least 8 bytes, each an
            // instruction and a function's type, the first at 0, in order.
            if !(8..=252).contains(&func_rec) || func_rec % 4 != 0 {
                return Err(Errno::EINVAL);
            }
            let mut last = None;
            for k in 0..func_cnt as u64 {
                let rec = m.read(func_at + k * func_rec as u64, func_rec as usize)?.to_vec();
                let (off, tid) = (u32::from_le_bytes(rec[0..4].try_into().unwrap()), u32::from_le_bytes(rec[4..8].try_into().unwrap()));
                if (k == 0 && off != 0) || last.is_some_and(|l| off <= l) || off >= insn_cnt || !btf.is_func(tid) || rec[8..].iter().any(|b| *b != 0) {
                    return Err(Errno::EINVAL);
                }
                last = Some(off);
                func_info.extend_from_slice(&rec[..8]);
            }
        }
        if line_cnt != 0 {
            // `check_btf_line`: records of at least 16 bytes, in order,
            // within the program, their names in the BTF's strings.
            if !(16..=252).contains(&line_rec) || line_rec % 4 != 0 {
                return Err(Errno::EINVAL);
            }
            let mut last = None;
            for k in 0..line_cnt as u64 {
                let rec = m.read(line_at + k * line_rec as u64, line_rec as usize)?.to_vec();
                let off = u32::from_le_bytes(rec[0..4].try_into().unwrap());
                if (k == 0 && off != 0) || last.is_some_and(|l| off < l) || off >= insn_cnt || rec[16..].iter().any(|b| *b != 0) {
                    return Err(Errno::EINVAL);
                }
                last = Some(off);
                line_info.extend_from_slice(&rec[..16]);
            }
        }
        prog_btf = Some(crate::bpfprog::ProgBtf { btf, func_info, line_info });
    }
    let maps = |fd: i32| -> Result<Arc<Map>, Errno> {
        match c.fds.get(fd).map_err(|_| Errno::EBADF)?.handle.bpf_object() {
            Some(Object::Map(m)) => Ok(m),
            _ => Err(Errno::EINVAL),
        }
    };
    let prog = crate::bpfprog::Prog::load(ty, expected, &raw, &license, name, c.uid, prog_btf, &maps);
    // The log, when asked for: the verifier's last line.
    if log_level != 0 {
        let text = match &prog {
            Ok(_) => format!("processed {insn_cnt} insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n"),
            Err(_) => format!("{}\nprogram refused\n", crate::bpfprog::last_reason()),
        };
        let room = log_size as usize - 1;
        let n = text.len().min(room);
        m.write(log_buf, &text.as_bytes()[..n])?;
        m.write(log_buf + n as u64, &[0])?;
        m.write_u32(attr + 140, text.len() as u32 + 1)?;
        if text.len() > room && prog.is_ok() {
            return Err(Errno::ENOSPC);
        }
    }
    let prog = Arc::new(prog?);
    register_prog(&prog);
    install(c, Object::Prog(prog), true, true)
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

/// An LPM trie's key: its prefix length and its data.
fn lpm_key(key: &[u8]) -> (u32, Vec<u8>) {
    (u32::from_le_bytes(key[..4].try_into().unwrap()), key[4..].to_vec())
}

/// The bit `i` of `data`, the most significant first.
fn bit_of(data: &[u8], i: u32) -> u8 {
    data[i as usize / 8] >> (7 - i % 8) & 1
}

/// `data` with every bit past `plen` cleared.
fn masked(data: &[u8], plen: u32) -> Vec<u8> {
    let mut out = data.to_vec();
    for i in plen..(data.len() * 8) as u32 {
        out[i as usize / 8] &= !(0x80 >> (i % 8));
    }
    out
}

/// Whether `a` and `b` agree in their first `plen` bits.
fn prefix_eq(a: &[u8], b: &[u8], plen: u32) -> bool {
    (0..plen).all(|i| bit_of(a, i) == bit_of(b, i))
}

/// The longest prefix in `t` that `key`'s data begins with, no longer
/// than `key`'s own prefix length.
fn lpm_match<'a>(t: &'a [(u32, Vec<u8>, Vec<u8>)], key: &[u8]) -> Option<&'a (u32, Vec<u8>, Vec<u8>)> {
    let (plen, data) = lpm_key(key);
    t.iter().filter(|(p, d, _)| *p <= plen && prefix_eq(d, &data, *p)).max_by_key(|(p, _, _)| *p)
}

/// The trie's post-order: a prefix after what is under it; between two
/// that part, the one on the 0 side first.
fn lpm_order(a: &&(u32, Vec<u8>, Vec<u8>), b: &&(u32, Vec<u8>, Vec<u8>)) -> std::cmp::Ordering {
    let (pa, da, _) = a;
    let (pb, db, _) = b;
    let common = (0..(*pa).min(*pb)).find(|&i| bit_of(da, i) != bit_of(db, i));
    match common {
        Some(i) => bit_of(da, i).cmp(&bit_of(db, i)),
        // One is a prefix of the other: the longer (under it) first.
        None => pb.cmp(pa),
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    /// `jhash` over bytes and `jhash2` over the same words agree, as the
    /// kernel's do (both start from the length in bytes); a key's bucket is
    /// a function of its bytes and the seed alone.
    #[test]
    fn the_two_jhashes_agree_on_words() {
        for words in [vec![0u32], vec![7, 9], vec![1, 2, 3], vec![0xdead_beef, 4, 5, 6], vec![1; 7]] {
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            for seed in [0, 1, 0x1234_5678] {
                assert_eq!(jhash(&bytes, seed), jhash2(&words, seed));
            }
        }
        assert_ne!(htab_hash(&[1, 0, 0, 0], 0), htab_hash(&[2, 0, 0, 0], 0));
        assert_eq!(jhash(&[], 5), JHASH_INITVAL.wrapping_add(5));
    }
}
