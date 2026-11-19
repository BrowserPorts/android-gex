//! Sync files (`drivers/dma-buf/sync_file.c` at android17-6.18): a
//! descriptor for a set of fences, which `poll` says `POLLIN` of once they
//! have signalled, and whose `ioctl`s merge two and describe one.
//!
//! The only fences this kernel makes are a virtio-gpu CRTC's out-fences
//! ([`crate::drm`]), and that driver has no vblank: its commit sends the
//! flip at once and signals the fence before the call returns. So every
//! fence here is signalled when it is made, and a merge, which keeps only
//! fences still pending, is always Linux's private stub fence ("stub",
//! signalled at the latest of the timestamps it was given).

use crate::errno::Errno;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::errno::SysResult;
use std::sync::Arc;

/// `SYNC_IOC_MERGE`, `SYNC_IOC_FILE_INFO`, `SYNC_IOC_SET_DEADLINE`.
pub const IOC_MERGE: u64 = 0xc030_3e03;
pub const IOC_FILE_INFO: u64 = 0xc038_3e04;
pub const IOC_SET_DEADLINE: u64 = 0x4010_3e05;

/// A fence: its driver's and timeline's names, its context and number,
/// and when it signalled (CLOCK_MONOTONIC, ns).
#[derive(Clone, Debug)]
pub struct Fence {
    pub driver: String,
    pub timeline: String,
    pub context: u64,
    pub seqno: u64,
    pub timestamp_ns: u64,
}

impl Fence {
    /// `dma_fence_allocate_private_stub(timestamp)`.
    pub fn stub(timestamp_ns: u64) -> Fence {
        Fence { driver: "stub".into(), timeline: "stub".into(), context: 0, seqno: 0, timestamp_ns }
    }
}

/// `dma_fence_context_alloc(1)`: a fence context of its own, numbered
/// in the order asked (Linux's count is global, from 1; what came before
/// a context here is not what came before it there).
pub fn context_alloc() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A sync file: one fence (a merge's is one too, the stub), and the name
/// a merge gave it.
#[derive(Debug)]
pub struct SyncFile {
    pub fence: Fence,
    user_name: String,
}

impl SyncFile {
    pub fn new(fence: Fence) -> SyncFile {
        SyncFile { fence, user_name: String::new() }
    }

    /// `sync_file_get_name`, 32 bytes with its terminator.
    fn name(&self) -> String {
        let n = if self.user_name.is_empty() {
            format!("{}-{}{}-{}", self.fence.driver, self.fence.timeline, self.fence.context, self.fence.seqno as i64)
        } else {
            self.user_name.clone()
        };
        truncate(&n, 31)
    }

    /// `SYNC_IOC_MERGE` with `other` (`fd2`), named `name`: a new sync
    /// file, which the caller installs (close-on-exec) and whose number
    /// it writes to `fence`. Every fence here has signalled, so the merge
    /// is the stub at the later timestamp.
    pub fn merge(&self, other: &SyncFile, name: &str) -> SyncFile {
        let ts = self.fence.timestamp_ns.max(other.fence.timestamp_ns);
        SyncFile { fence: Fence::stub(ts), user_name: truncate(name, 31) }
    }

    /// The open file for a sync file: `anon_inode:sync_file`, read-only.
    pub fn open(self) -> Arc<crate::file::OpenFile> {
        crate::file::OpenFile::new(Arc::new(self), "anon_inode:sync_file".into(), crate::fs::oflags::O_RDONLY, true, false)
    }
}

fn truncate(s: &str, n: usize) -> String {
    let mut end = s.len().min(n);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn put_str(buf: &mut [u8], s: &str) {
    buf.fill(0);
    let b = s.as_bytes();
    let n = b.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&b[..n]);
}

impl FileHandle for SyncFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o600, ino: 1, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }

    fn fs_dev(&self) -> u64 {
        crate::vfs::anon_dev(crate::vfs::DevKey::Kind("anon_inodefs"))
    }

    fn as_syncfile(self: Arc<Self>) -> Option<Arc<SyncFile>> {
        Some(self)
    }

    /// Signalled, always: readable.
    fn poll_readable(&self) -> bool {
        true
    }

    fn poll_writable(&self) -> bool {
        false
    }

    fn ioctl(&self, m: &mut crate::GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        Some(match request & 0xffff_ffff {
            // `sync_file_ioctl_fence_info`.
            IOC_FILE_INFO => (|| {
                let mut info = m.read(arg, 56)?.to_vec();
                let flags = u32::from_le_bytes(info[36..40].try_into().unwrap());
                let num = u32::from_le_bytes(info[40..44].try_into().unwrap());
                let pad = u32::from_le_bytes(info[44..48].try_into().unwrap());
                if flags != 0 || pad != 0 {
                    return Err(Errno::EINVAL);
                }
                if num != 0 {
                    // One fence, signalled: status 1.
                    let mut f = [0u8; 80];
                    put_str(&mut f[0..32], &self.fence.timeline);
                    put_str(&mut f[32..64], &self.fence.driver);
                    f[64..68].copy_from_slice(&1i32.to_le_bytes());
                    f[72..80].copy_from_slice(&self.fence.timestamp_ns.to_le_bytes());
                    let ptr = u64::from_le_bytes(info[48..56].try_into().unwrap());
                    m.write(ptr, &f)?;
                }
                info[32..36].copy_from_slice(&1i32.to_le_bytes());
                put_str(&mut info[0..32], &self.name());
                info[40..44].copy_from_slice(&1u32.to_le_bytes());
                m.write(arg, &info)?;
                Ok(0)
            })(),
            // `dma_fence_set_deadline`: a hint, and every fence here has
            // signalled.
            IOC_SET_DEADLINE => (|| {
                let ts = m.read(arg, 16)?;
                if u64::from_le_bytes(ts[8..16].try_into().unwrap()) != 0 {
                    return Err(Errno::EINVAL);
                }
                Ok(0)
            })(),
            // A merge makes a descriptor: the syscall layer's
            // ([`crate::syscalls::FdIo::ioctl`]).
            _ => Err(Errno::ENOTTY),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_file_is_named_as_linux_names_it() {
        let f = SyncFile::new(Fence { driver: "virtio_gpu".into(), timeline: "CRTC:37-crtc-0".into(), context: 5, seqno: 1, timestamp_ns: 9 });
        assert_eq!(f.name(), "virtio_gpu-CRTC:37-crtc-05-1");
        let g = f.merge(&SyncFile::new(Fence::stub(20)), "merged");
        assert_eq!((g.name().as_str(), g.fence.driver.as_str(), g.fence.timestamp_ns), ("merged", "stub", 20));
    }
}
