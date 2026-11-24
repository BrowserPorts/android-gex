//! The goldfish sync device (`/dev/goldfish_sync`), as the emulator image's
//! kernel module has it (`common-modules/virtual-device`'s
//! `goldfish_drivers/goldfish_sync.c` at android17-6.18), there when the
//! kernel stands in for the emulator (`GEX_EMULATOR_HOST=1`). The image's
//! composer turns each frame's host sync into a release fence with it.
//!
//! - Each open is a timeline, named `goldfish_sync:<n>` (n from 1), with a
//!   fence context of its own and a count from 0.
//! - `GOLDFISH_SYNC_IOC_QUEUE_WORK` (`_IOWR('@', 0, 24 bytes)`): the
//!   host's GL sync and sync thread handles in, a close-on-exec sync file
//!   out (`fence_fd_out`), its fence the timeline's next point (driver
//!   `sw_sync`); `EFAULT` with no sync thread handle. The emulator has its
//!   sync thread wait for the GL sync and then moves the timeline on, which
//!   signals the fence; here the host waits ([`Host`]) before the ioctl
//!   returns, so the fence has signalled when the guest gets it (the work
//!   is the same, its time is not).
//! - Anything else is `ENOTTY`.

use crate::errno::{Errno, SysResult};
use crate::syncfile::{Fence, SyncFile};
use crate::vfs::{FileHandle, Metadata};
use crate::GuestMem;
use std::sync::{Arc, Mutex, OnceLock};

/// Its misc minor: the third dynamic one, after the pipe's and the address
/// space's.
pub const MISC_MINOR: u32 = 258;
/// `GOLDFISH_SYNC_DEVICE_NAME`.
pub const NAME: &str = "goldfish_sync";
/// `GOLDFISH_SYNC_IOC_QUEUE_WORK`.
pub const QUEUE_WORK: u64 = (3 << 30) | (24 << 16) | ((b'@' as u64) << 8);

/// The host's side: wait until a GL sync it made has signalled.
pub trait Host: Send + Sync {
    fn wait(&self, glsync: u64, syncthread: u64);
}

static HOST: OnceLock<Box<dyn Host>> = OnceLock::new();

/// The host's waits, given once.
pub fn set_host(h: Box<dyn Host>) -> bool {
    HOST.set(h).is_ok()
}

/// Whether the kernel has the device.
pub fn present() -> bool {
    crate::vsock::enabled()
}

pub struct Timeline {
    name: String,
    context: u64,
    seqno: Mutex<u64>,
    node: crate::vfs::devices::NodeMeta,
}

impl std::fmt::Debug for Timeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timeline").field("name", &self.name).finish()
    }
}

/// Open the device: a new timeline.
pub fn open(node: crate::vfs::devices::NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    if !present() {
        return Err(Errno::ENXIO);
    }
    static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    Ok(Arc::new(Timeline { name: format!("{NAME}:{n}"), context: crate::syncfile::context_alloc(), seqno: Mutex::new(0), node }))
}

impl Timeline {
    /// `QUEUE_WORK`'s fence, once the host's sync has signalled: the
    /// timeline moved on to it.
    pub fn queue_work(&self, glsync: u64, syncthread: u64) -> Result<SyncFile, Errno> {
        if syncthread == 0 {
            return Err(Errno::EFAULT);
        }
        match HOST.get() {
            Some(h) => h.wait(glsync, syncthread),
            None => eprintln!("[gex] goldfish sync: no host to wait for sync {glsync:#x}; signalled at once"),
        }
        let mut seq = self.seqno.lock().unwrap_or_else(|e| e.into_inner());
        *seq += 1;
        let now = crate::syscalls::clock_ns(crate::syscalls::system_clock, 1);
        Ok(SyncFile::new(Fence { driver: "sw_sync".into(), timeline: self.name.clone(), context: self.context, seqno: *seq, timestamp_ns: now }))
    }

    /// The ioctl, from guest memory, installing the fence in `fds`.
    pub fn ioctl(&self, fds: &crate::file::FdTable, m: &mut GuestMem<'_>, req: u64, arg: u64) -> SysResult {
        if req & 0xffff_ffff != QUEUE_WORK {
            return Err(Errno::ENOTTY);
        }
        let mut k = m.read(arg, 24).map_err(|_| Errno::EFAULT)?.to_vec();
        let glsync = u64::from_le_bytes(k[0..8].try_into().unwrap());
        let thread = u64::from_le_bytes(k[8..16].try_into().unwrap());
        let file = self.queue_work(glsync, thread)?;
        let fd = fds.insert(file.open(), true)?;
        k[16..20].copy_from_slice(&(fd as i32).to_le_bytes());
        if m.write(arg, &k).is_err() {
            let _ = fds.close(fd as i32);
            return Err(Errno::EFAULT);
        }
        Ok(0)
    }
}

impl FileHandle for Timeline {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok((self.node)())
    }

    fn as_goldfish_sync(self: Arc<Self>) -> Option<Arc<Timeline>> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_is_a_fence_on_the_timeline() {
        let node: crate::vfs::devices::NodeMeta = Arc::new(|| Metadata { file_type: crate::vfs::FileType::CharDevice, size: 0, mode: 0o666, ino: 1, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None });
        let t = Timeline { name: "goldfish_sync:1".into(), context: 7, seqno: Mutex::new(0), node };
        assert_eq!(t.queue_work(1, 0).err(), Some(Errno::EFAULT));
        let a = t.queue_work(1, 1).unwrap();
        let b = t.queue_work(2, 1).unwrap();
        assert_eq!((a.fence.seqno, b.fence.seqno), (1, 2));
        assert_eq!((a.fence.driver.as_str(), a.fence.timeline.as_str(), a.fence.context), ("sw_sync", "goldfish_sync:1", 7));
        assert_eq!(QUEUE_WORK, 0xc018_4000);
    }
}
