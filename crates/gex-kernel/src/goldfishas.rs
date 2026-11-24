//! The goldfish address space (`/dev/goldfish_address_space`), as the
//! emulator image's kernel module has it (`common-modules/virtual-device`'s
//! `goldfish_drivers/goldfish_address_space.c` at android17-6.18) and the
//! emulator answers it (`aemu`'s `address_space_device.cpp` and
//! `address_space_host_memory_allocator.cpp`), there when the kernel stands
//! in for the emulator (`GEX_EMULATOR_HOST=1`). The image's graphics
//! allocator keeps every buffer's memory in it, and the mapper and the host
//! renderer reach that memory by its guest physical address (DMA).
//!
//! - The device is a region of guest physical memory, an "address area".
//!   Each open is a host handle with its own blocks of the area:
//!   `ALLOCATE_BLOCK` takes `size` and gives the block's `offset` in the
//!   area and its `phys_addr` (the area's base plus the offset);
//!   `DEALLOCATE_BLOCK` gives one back by offset (`ENXIO` if this open has
//!   none there); `CLAIM_SHARED` and `UNCLAIM_SHARED` list and unlist a
//!   range of the host's shared memory as this open's (nothing is checked
//!   against the host: the driver only keeps the list). The last close gives
//!   back the open's own blocks, not the shared ones.
//! - `mmap` of the device at an offset maps the area there, shared, only
//!   within one of this open's own or claimed blocks (`EPERM` otherwise).
//!   A descriptor handed to another process (the buffer's, by binder) is the
//!   same open, so the other process maps the same blocks.
//! - `PING` hands the open's ping record to the host with its `offset`
//!   made a guest physical address, and copies the record back, the host's
//!   answer in `metadata`. The first ping of an open names the host context
//!   it is (`metadata` is the type; 0 back if the host has it, -1 if not).
//!   The host memory allocator's (type 5) commands: `ALLOCATE` (1) gives
//!   the block at `offset` host memory of `size` (0, or -1 if it has some
//!   already), `UNALLOCATE` (2) takes it away (0, or -1 if it had none);
//!   anything else answers -1. Other context types are not here, and say
//!   so. `PING_WITH_DATA` is the same with up to a page of data, which no
//!   context here reads.
//!
//! The emulator's allocator of blocks is its own (in its qemu device); this
//! one rounds a block up to whole pages and takes the lowest offset free,
//! in an area of 16 GiB at guest physical address 0x40_0000_0000. A block's
//! memory is the kernel's, zeroed when allocated; mappings of it are kept
//! as other shared mappings are, and a write to the goldfish pipe writes
//! them back first (see `graphics_memory`).

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Its misc minor: the second dynamic one, after the goldfish pipe's.
pub const MISC_MINOR: u32 = 257;
/// `GOLDFISH_ADDRESS_SPACE_DEVICE_NAME`.
pub const NAME: &str = "goldfish_address_space";

/// Where the area is in guest physical memory, and how big it is.
pub const AREA_BASE: u64 = 0x40_0000_0000;
pub const AREA_SIZE: u64 = 16 << 30;
const PAGE: u64 = 4096;

const IOC_MAGIC: u64 = b'G' as u64;
const fn iowr(nr: u64, size: u64) -> u64 {
    (3 << 30) | (size << 16) | (IOC_MAGIC << 8) | nr
}
pub const ALLOCATE_BLOCK: u64 = iowr(10, 24);
pub const DEALLOCATE_BLOCK: u64 = iowr(11, 8);
pub const PING: u64 = iowr(12, 40);
pub const CLAIM_SHARED: u64 = iowr(13, 16);
pub const UNCLAIM_SHARED: u64 = iowr(14, 8);
pub const PING_WITH_DATA: u64 = iowr(15, 56);

/// `AddressSpaceDeviceType::HostMemoryAllocator`.
const HOST_MEMORY_ALLOCATOR: u64 = 5;
/// `HostMemoryAllocatorCommand`.
const ALLOCATE: u64 = 1;
const UNALLOCATE: u64 = 2;

/// Whether the kernel has the device.
pub fn present() -> bool {
    crate::vsock::enabled()
}

/// A block's memory.
struct Block {
    size: u64,
    data: Mutex<Vec<u8>>,
    /// Whether the host memory allocator has given it host memory.
    host: Mutex<bool>,
}

/// The area: its blocks by offset.
#[derive(Default)]
struct Area {
    blocks: BTreeMap<u64, Arc<Block>>,
}

fn area() -> &'static Mutex<Area> {
    static A: OnceLock<Mutex<Area>> = OnceLock::new();
    A.get_or_init(Default::default)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Area {
    /// The lowest offset with `size` free.
    fn place(&self, size: u64) -> Option<u64> {
        let mut at = 0;
        for (&off, b) in &self.blocks {
            if off >= at + size {
                break;
            }
            at = off + b.size;
        }
        (at + size <= AREA_SIZE).then_some(at)
    }

    /// The block holding `[offset, offset + len)` and where in it.
    fn find(&self, offset: u64, len: u64) -> Option<(Arc<Block>, u64)> {
        let (&start, b) = self.blocks.range(..=offset).next_back()?;
        (offset + len <= start + b.size).then(|| (Arc::clone(b), offset - start))
    }
}

/// `len` bytes of the area at guest physical `addr`, for the host
/// renderer's DMA; false unless they are all in one block.
pub fn read_phys(addr: u64, buf: &mut [u8]) -> bool {
    let Some(off) = addr.checked_sub(AREA_BASE) else { return false };
    let Some((b, at)) = lock(area()).find(off, buf.len() as u64) else { return false };
    let d = lock(&b.data);
    buf.copy_from_slice(&d[at as usize..at as usize + buf.len()]);
    true
}

/// `buf` to the area at guest physical `addr`.
pub fn write_phys(addr: u64, buf: &[u8]) -> bool {
    let Some(off) = addr.checked_sub(AREA_BASE) else { return false };
    let Some((b, at)) = lock(area()).find(off, buf.len() as u64) else { return false };
    lock(&b.data)[at as usize..at as usize + buf.len()].copy_from_slice(buf);
    CHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    true
}

/// Moves at every write the host makes, so mappings are refreshed.
static CHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The host's handles, from 1 (`AS_COMMAND_GEN_HANDLE`).
fn gen_handle() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// What an open's first ping made it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Context {
    HostMemoryAllocator,
}

#[derive(Default)]
struct Open {
    /// Its own blocks and its claimed shared ranges, by offset and size.
    own: Vec<(u64, u64)>,
    shared: Vec<(u64, u64)>,
    context: Option<Context>,
    /// The first ping was made (and found no context).
    pinged: bool,
}

pub struct AddressSpace {
    handle: u32,
    open: Mutex<Open>,
    node: crate::vfs::devices::NodeMeta,
}

impl std::fmt::Debug for AddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressSpace").field("handle", &self.handle).finish()
    }
}

/// Open the device: a new host handle with no blocks.
pub fn open(node: crate::vfs::devices::NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    if !present() {
        return Err(Errno::ENXIO);
    }
    Ok(Arc::new(AddressSpace { handle: gen_handle(), open: Mutex::new(Open::default()), node }))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn say_once(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = lock(&SAID);
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] goldfish address space: {what}");
        said.push(what.to_string());
    }
}

impl AddressSpace {
    /// `as_ioctl`, on the request's bytes.
    fn request(&self, req: u64, k: &mut [u8]) -> Result<(), Errno> {
        match req {
            ALLOCATE_BLOCK => {
                let size = u64_at(k, 0).checked_add(PAGE - 1).ok_or(Errno::ENOMEM)? & !(PAGE - 1);
                if size == 0 {
                    return Err(Errno::EINVAL);
                }
                let mut a = lock(area());
                let off = a.place(size).ok_or(Errno::ENOMEM)?;
                a.blocks.insert(off, Arc::new(Block { size, data: Mutex::new(vec![0; size as usize]), host: Mutex::new(false) }));
                drop(a);
                lock(&self.open).own.push((off, size));
                k[0..8].copy_from_slice(&size.to_le_bytes());
                k[8..16].copy_from_slice(&off.to_le_bytes());
                k[16..24].copy_from_slice(&(AREA_BASE + off).to_le_bytes());
                Ok(())
            }
            DEALLOCATE_BLOCK => {
                let off = u64_at(k, 0);
                let mut o = lock(&self.open);
                let i = o.own.iter().position(|&(b, _)| b == off).ok_or(Errno::ENXIO)?;
                o.own.swap_remove(i);
                drop(o);
                lock(area()).blocks.remove(&off);
                Ok(())
            }
            CLAIM_SHARED => {
                lock(&self.open).shared.push((u64_at(k, 0), u64_at(k, 8)));
                Ok(())
            }
            UNCLAIM_SHARED => {
                let off = u64_at(k, 0);
                let mut o = lock(&self.open);
                let i = o.shared.iter().position(|&(b, _)| b == off).ok_or(Errno::ENXIO)?;
                o.shared.swap_remove(i);
                Ok(())
            }
            PING | PING_WITH_DATA => {
                // The offset as the host sees it: a physical address.
                let phys = u64_at(k, 0).wrapping_add(AREA_BASE);
                k[0..8].copy_from_slice(&phys.to_le_bytes());
                let size = u64_at(k, 8);
                let metadata = u64_at(k, 16);
                let answer = self.ping(phys, size, metadata);
                k[16..24].copy_from_slice(&answer.to_le_bytes());
                Ok(())
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// `AddressSpaceDeviceState::ping`: the answer in `metadata`.
    fn ping(&self, phys: u64, size: u64, metadata: u64) -> u64 {
        let mut o = lock(&self.open);
        match o.context {
            None => {
                o.pinged = true;
                if metadata == HOST_MEMORY_ALLOCATOR {
                    o.context = Some(Context::HostMemoryAllocator);
                    0
                } else {
                    say_once(&format!("no host context of type {metadata}"));
                    u64::MAX
                }
            }
            Some(Context::HostMemoryAllocator) => {
                drop(o);
                let Some(off) = phys.checked_sub(AREA_BASE) else { return u64::MAX };
                let block = lock(area()).blocks.get(&off).cloned();
                match (metadata, block) {
                    // The guest's block is the host's memory here, so
                    // allocating it marks it given.
                    (ALLOCATE, Some(b)) if size <= b.size => {
                        let mut host = lock(&b.host);
                        if *host {
                            return u64::MAX;
                        }
                        *host = true;
                        0
                    }
                    (UNALLOCATE, Some(b)) => {
                        let mut host = lock(&b.host);
                        if !*host {
                            return u64::MAX;
                        }
                        *host = false;
                        0
                    }
                    _ => u64::MAX,
                }
            }
        }
    }

    /// The ioctl, from guest memory.
    pub fn control(&self, m: &mut GuestMem<'_>, req: u64, arg: u64) -> SysResult {
        let size = match req {
            ALLOCATE_BLOCK => 24,
            DEALLOCATE_BLOCK | UNCLAIM_SHARED => 8,
            PING => 40,
            CLAIM_SHARED => 16,
            PING_WITH_DATA => 56,
            _ => return Err(Errno::ENOTTY),
        };
        let mut k = m.read(arg, size).map_err(|_| Errno::EFAULT)?.to_vec();
        if req == PING_WITH_DATA {
            // The data must fit the ping page after the record's head.
            let data_size = u64_at(&k, 40);
            if data_size > PAGE - 48 {
                return Err(Errno::EFAULT);
            }
            m.read(u64_at(&k, 48), data_size as usize).map_err(|_| Errno::EFAULT)?;
        }
        self.request(req, &mut k)?;
        let back = match req {
            // Not written back: the block and the offset.
            DEALLOCATE_BLOCK | UNCLAIM_SHARED => return Ok(0),
            _ => &k[..],
        };
        m.write(arg, back).map_err(|_| Errno::EFAULT)?;
        Ok(0)
    }
}

impl Drop for AddressSpace {
    /// `as_release`: the host handle and the open's own blocks go.
    fn drop(&mut self) {
        let own = std::mem::take(&mut lock(&self.open).own);
        let mut a = lock(area());
        for (off, _) in own {
            a.blocks.remove(&off);
        }
    }
}

impl FileHandle for AddressSpace {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok((self.node)())
    }

    /// `as_mmap`: only within one of this open's blocks, own or claimed.
    fn may_map(&self, offset: u64, len: u64, _prot: u32, _shared: bool) -> Result<(), Errno> {
        let len = len.checked_add(PAGE - 1).ok_or(Errno::EINVAL)? & !(PAGE - 1);
        let end = offset.checked_add(len).ok_or(Errno::EPERM)?;
        let o = lock(&self.open);
        let inside = |l: &[(u64, u64)]| l.iter().any(|&(b, s)| offset >= b && end <= b + s);
        if inside(&o.own) || inside(&o.shared) {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    }

    fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        match lock(area()).find(offset, buf.len() as u64) {
            Some((b, at)) => {
                buf.copy_from_slice(&lock(&b.data)[at as usize..at as usize + buf.len()]);
                Ok(buf.len() as u64)
            }
            // Shared memory the host never gave: nothing there.
            None => {
                buf.fill(0);
                Ok(buf.len() as u64)
            }
        }
    }

    fn write_mapped(&self, offset: u64, buf: &[u8]) -> SysResult {
        match lock(area()).find(offset, buf.len() as u64) {
            Some((b, at)) => {
                lock(&b.data)[at as usize..at as usize + buf.len()].copy_from_slice(buf);
                CHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(buf.len() as u64)
            }
            None => Ok(buf.len() as u64),
        }
    }

    /// A mapping is of the area at its offset, wherever that is.
    fn mapped_len(&self) -> Option<u64> {
        Some(AREA_SIZE)
    }

    fn changes(&self) -> u64 {
        CHANGES.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn graphics_memory(&self) -> bool {
        true
    }

    fn ioctl(&self, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        Some(self.control(m, request & 0xffff_ffff, arg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> AddressSpace {
        AddressSpace {
            handle: gen_handle(),
            open: Mutex::new(Open::default()),
            node: Arc::new(|| Metadata { file_type: crate::vfs::FileType::CharDevice, size: 0, mode: 0o666, ino: 1, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None }),
        }
    }

    fn alloc(d: &AddressSpace, size: u64) -> (u64, u64, u64) {
        let mut k = [0u8; 24];
        k[0..8].copy_from_slice(&size.to_le_bytes());
        d.request(ALLOCATE_BLOCK, &mut k).unwrap();
        (u64_at(&k, 0), u64_at(&k, 8), u64_at(&k, 16))
    }

    fn ping(d: &AddressSpace, offset: u64, size: u64, metadata: u64) -> (u64, u64) {
        let mut k = [0u8; 40];
        k[0..8].copy_from_slice(&offset.to_le_bytes());
        k[8..16].copy_from_slice(&size.to_le_bytes());
        k[16..24].copy_from_slice(&metadata.to_le_bytes());
        d.request(PING, &mut k).unwrap();
        (u64_at(&k, 0), u64_at(&k, 16))
    }

    /// The graphics allocator's sequence (`hostMalloc` with no shared
    /// slots): the context's type, a block, its host memory, a mapping;
    /// then the memory by physical address, and the block given back.
    #[test]
    fn a_buffer_is_allocated_as_the_allocator_does() {
        let d = dev();
        assert_eq!(ping(&d, 0, 0, HOST_MEMORY_ALLOCATOR).1, 0);
        let (size, off, phys) = alloc(&d, 5000);
        assert_eq!((size, phys), (8192, AREA_BASE + off));
        assert_eq!(ping(&d, off, size, ALLOCATE), (phys, 0));
        assert_eq!(ping(&d, off, size, ALLOCATE).1, u64::MAX);
        assert_eq!(ping(&d, off, size, 9).1, u64::MAX);
        assert_eq!(d.may_map(off, 5000, 3, true), Ok(()));
        assert_eq!(d.may_map(off + 4096, 8192, 3, true), Err(Errno::EPERM));
        assert_eq!(d.write_mapped(off + 10, b"pixels"), Ok(6));
        let mut b = [0u8; 6];
        assert!(read_phys(phys + 10, &mut b));
        assert_eq!(&b, b"pixels");
        assert!(write_phys(phys + 100, b"back"));
        let mut c = [0u8; 4];
        d.read_mapped(off + 100, &mut c).unwrap();
        assert_eq!(&c, b"back");
        assert!(!read_phys(phys + 8190, &mut b));
        // Another open has no blocks of its own.
        let e = dev();
        assert_eq!(e.may_map(off, 4096, 3, true), Err(Errno::EPERM));
        let mut k = off.to_le_bytes();
        assert_eq!(e.request(DEALLOCATE_BLOCK, &mut k), Err(Errno::ENXIO));
        assert_eq!(ping(&e, 0, 0, 7).1, u64::MAX);
        assert_eq!(d.request(DEALLOCATE_BLOCK, &mut k), Ok(()));
        assert!(!read_phys(phys, &mut b));
        // A second block takes the lowest offset free.
        let (_, off2, _) = alloc(&d, 1);
        assert!(off2 <= off);
    }
}
