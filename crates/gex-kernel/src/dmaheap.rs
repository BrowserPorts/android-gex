//! DMA-BUF heaps (`drivers/dma-buf/dma-heap.c` at Linux 6.18): character
//! devices in `/dev/dma_heap`, one a heap, each allocating dma-bufs.
//! Android's graphics allocator (minigbm's) and codecs take their buffers
//! from the `system` heap.
//!
//! GKI builds the core in. Its heaps come from modules: the emulator
//! image's is the system heap (`system_heap.ko`,
//! `drivers/dma-buf/heaps/system_heap.c`), which registers `system` and
//! `system-uncached`. This kernel loads no modules, so the two are here
//! with the emulator's hardware ([`crate::vsock::enabled`]), as its other
//! devices are; without it the core has no heaps.
//!
//! A heap's device takes one ioctl (`dma_heap_ioctl`): the command is
//! found by its number alone, any number past the last is `EINVAL`, and
//! the argument is copied in and out as far as the caller's command and
//! the kernel's both say, the rest zeroed. `DMA_HEAP_IOCTL_ALLOC` checks
//! (`dma_heap_ioctl_allocate`, `dma_heap_buffer_alloc`): no descriptor
//! given, no flags but `O_CLOEXEC` and the access mode, no heap flags, a
//! length that is not 0 once rounded up to pages. The buffer is a dma-buf
//! of that length ([`crate::drm::exported_buffer`]), zeroed, its descriptor
//! open as the flags say. Cached or not makes no difference to memory
//! that is never a device's.

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::sync::Arc;

/// The heaps' character major. Linux gives one from its dynamic range at
/// boot (`alloc_chrdev_region`); this is the one it gives here.
pub const MAJOR: u32 = 248;

/// The heaps there are, by minor, in the order the system heap adds them.
pub fn heaps() -> &'static [&'static str] {
    if crate::vsock::enabled() {
        &["system", "system-uncached"]
    } else {
        &[]
    }
}

/// `dma_heap_open`: the heap of the minor, `ENODEV` for none.
pub fn open(minor: u32, node: crate::vfs::devices::NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    let name = heaps().get(minor as usize).ok_or(Errno::ENODEV)?;
    Ok(Arc::new(Heap { name, node }))
}

/// An open heap.
pub struct Heap {
    name: &'static str,
    node: crate::vfs::devices::NodeMeta,
}

impl std::fmt::Debug for Heap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dma_heap/{}", self.name)
    }
}

/// `DMA_HEAP_IOCTL_ALLOC`: `_IOWR('H', 0, struct dma_heap_allocation_data)`.
const ALLOC: u64 = 0xc018_4800;
/// `struct dma_heap_allocation_data`: `len`, `fd`, `fd_flags`, `heap_flags`.
const ALLOC_SIZE: usize = 24;
const IOC_WRITE: u64 = 1 << 30;
const IOC_READ: u64 = 2 << 30;

impl Heap {
    /// `dma_heap_ioctl`, for a caller whose descriptors are `fds`.
    pub fn ioctl(&self, fds: &crate::file::FdTable, m: &mut GuestMem<'_>, request: u64, arg: u64) -> SysResult {
        let ucmd = request & 0xffff_ffff;
        if ucmd & 0xff >= 1 {
            return Err(Errno::EINVAL);
        }
        let size = ((ucmd >> 16) & 0x3fff) as usize;
        let in_size = if ucmd & ALLOC & IOC_WRITE != 0 { size } else { 0 };
        let out_size = if ucmd & ALLOC & IOC_READ != 0 { size } else { 0 };
        let mut k = vec![0u8; in_size.max(out_size).max(ALLOC_SIZE)];
        if in_size > 0 {
            k[..in_size].copy_from_slice(m.read(arg, in_size)?);
        }
        let r = self.allocate(fds, &mut k);
        if out_size > 0 {
            m.write(arg, &k[..out_size])?;
        }
        r
    }

    /// `dma_heap_ioctl_allocate` and `dma_heap_buffer_alloc`.
    fn allocate(&self, fds: &crate::file::FdTable, k: &mut [u8]) -> SysResult {
        use crate::fs::oflags::{ACCMODE, O_CLOEXEC, O_RDONLY};
        let len = u64::from_le_bytes(k[0..8].try_into().unwrap());
        let fd = u32::from_le_bytes(k[8..12].try_into().unwrap());
        let fd_flags = u32::from_le_bytes(k[12..16].try_into().unwrap()) as u64;
        let heap_flags = u64::from_le_bytes(k[16..24].try_into().unwrap());
        if fd != 0 {
            return Err(Errno::EINVAL);
        }
        if fd_flags & !(O_CLOEXEC | ACCMODE) != 0 || heap_flags != 0 {
            return Err(Errno::EINVAL);
        }
        // `__PAGE_ALIGN`, which wraps to 0 past the last page.
        let len = len.wrapping_add(4095) & !4095;
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        // More than the machine has (4 GiB, as `/proc/meminfo` says): the
        // pages are not there.
        if len > 4 << 30 {
            return Err(Errno::ENOMEM);
        }
        let rw = fd_flags & ACCMODE != O_RDONLY;
        let file = crate::drm::exported_buffer(len, rw);
        let new = fds.insert(file, fd_flags & O_CLOEXEC != 0)?;
        k[8..12].copy_from_slice(&(new as u32).to_le_bytes());
        Ok(0)
    }
}

impl FileHandle for Heap {
    /// No read or write: `EINVAL`, as a file without them.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    /// `nonseekable_open`.
    fn is_stream(&self) -> bool {
        true
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        let md = (self.node)();
        Ok(Metadata { file_type: FileType::CharDevice, ..md })
    }

    fn as_dma_heap(self: Arc<Self>) -> Option<Arc<Heap>> {
        Some(self)
    }
}
