//! Block devices: the disks this kernel has, what a block device node
//! opens as, and how sysfs shows them.
//!
//! A disk ([`Disk`]) is a run of bytes with a size, read and (when it
//! allows) written at any offset. The only kind so far is the loop device
//! (crate::loopdev), which is how Android's `apexd` puts each APEX's
//! payload image where `mount` can take it.
//!
//! A node with a disk's number opens as the disk ([`open`], from
//! [`crate::vfs::devices`]): reads and writes within its size, `lseek` to
//! its end, and the block layer's ioctls (block/ioctl.c): its size in
//! bytes and in sectors, its block sizes, read-only, read-ahead, and
//! flushing, which has nothing to flush (nothing here is cached). What a
//! driver adds (the loop device's own calls) is the disk's.
//!
//! In sysfs a disk is `devices/virtual/block/<name>`, with `block/<name>`,
//! `class/block/<name>` and `dev/block/<major>:<minor>` leading to it:
//! `size` in 512-byte sectors, `ro`, `removable`, `hidden`, `diskseq`,
//! `queue/` with the block sizes, `read_ahead_kb`, `nr_requests` and
//! `scheduler` (none: there is no queue to schedule), and the driver's
//! own directory. Its events carry `DEVTYPE=disk` and `DISKSEQ`.
//!
//! Not here: partitions, the other `queue` and statistics files, and who
//! may make the calls that take `CAP_SYS_ADMIN` (any opener may).

use crate::errno::{Errno, SysResult};
use crate::vfs::devices::NodeMeta;
use crate::vfs::sysfs;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A disk.
pub trait Disk: Send + Sync + std::fmt::Debug {
    /// Its size in bytes: 0 for one with nothing behind it.
    fn size(&self) -> u64;
    fn read_only(&self) -> bool;
    /// `BLKROSET`.
    fn set_read_only(&self, ro: bool);
    /// Its logical block size.
    fn block_size(&self) -> u32 {
        512
    }
    /// Read at `offset`, which is within its size.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult;
    /// Write at `offset`, which is within its size, to a disk that is not
    /// read-only.
    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult;
    /// A node of it is opened: `ENXIO` when it cannot be now.
    fn opened(&self) -> Result<(), Errno> {
        Ok(())
    }
    /// An open of it is closed.
    fn released(&self) {}
    /// An ioctl of the driver's own; `None` for one it does not know.
    fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        let _ = (cx, m, request, arg);
        None
    }
    /// The driver's directory in the disk's sysfs directory: its name and
    /// its files' names, when there is one now.
    fn sysfs_dir(&self) -> Option<(&'static str, Vec<&'static str>)> {
        None
    }
    /// A file in that directory.
    fn sysfs_read(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }
    /// The disks it is made of, by number (`slaves/` in sysfs).
    fn slaves(&self) -> Vec<u64> {
        Vec::new()
    }
}

/// The disk numbered `dev`, when there is one.
pub fn disk(dev: u64) -> Option<Arc<dyn Disk>> {
    entry(dev).map(|e| Arc::clone(&e.disk))
}

/// The name of the disk numbered `dev`.
fn name_of(dev: u64) -> Option<String> {
    entry(dev).map(|e| e.name.clone())
}

/// Who makes an ioctl: their descriptors, which a call may name one of,
/// and whether a `long` of theirs is 32 bits.
pub struct Caller<'a> {
    pub fds: &'a crate::file::FdTable,
    pub compat: bool,
}

/// A disk as the kernel knows it.
#[derive(Debug)]
struct Entry {
    name: String,
    disk: Arc<dyn Disk>,
    /// Its place in the order disks were added and changed (`DISKSEQ`).
    diskseq: AtomicU64,
    /// `BLKRASET`, `queue/read_ahead_kb`: in 512-byte sectors.
    read_ahead: AtomicU32,
    /// `queue/nr_requests`.
    nr_requests: AtomicU32,
}

static DISKS: Mutex<BTreeMap<u64, Arc<Entry>>> = Mutex::new(BTreeMap::new());
static DISKSEQ: AtomicU64 = AtomicU64::new(0);

/// The disks a kernel starts with: made once, before anything asks about
/// one.
pub fn boot() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(crate::loopdev::boot);
}

fn entry(dev: u64) -> Option<Arc<Entry>> {
    boot();
    DISKS.lock().unwrap_or_else(|e| e.into_inner()).get(&dev).cloned()
}

/// Add a disk, numbered `dev` and named `name`. With `announce` its
/// `add` event goes out; the disks a kernel starts with are found by
/// whoever walks sysfs.
pub fn add(dev: u64, name: &str, disk: Arc<dyn Disk>, announce: bool) {
    let e = Arc::new(Entry { name: name.to_string(), disk, diskseq: AtomicU64::new(DISKSEQ.fetch_add(1, Ordering::AcqRel) + 1), read_ahead: AtomicU32::new(256), nr_requests: AtomicU32::new(128) });
    DISKS.lock().unwrap_or_else(|e| e.into_inner()).insert(dev, Arc::clone(&e));
    let device = sysfs::Device {
        subsystem: "block".to_string(),
        name: name.to_string(),
        major: crate::vfs::devices::major(dev),
        minor: crate::vfs::devices::minor(dev),
        mode: None,
        attrs: Some(e),
    };
    sysfs::add(device, announce);
}

/// Remove the disk numbered `dev`, with its `remove` event.
pub fn remove(dev: u64) {
    if let Some(e) = DISKS.lock().unwrap_or_else(|e| e.into_inner()).remove(&dev) {
        sysfs::remove("block", &e.name);
    }
}

/// The disk's medium changed (`disk_force_media_change`): a new place in
/// the order.
pub fn media_changed(dev: u64) {
    if let Some(e) = entry(dev) {
        e.diskseq.store(DISKSEQ.fetch_add(1, Ordering::AcqRel) + 1, Ordering::Release);
    }
}

/// Send the disk's `change` event.
pub fn changed(dev: u64) {
    if let Some(e) = entry(dev) {
        sysfs::event("block", &e.name, "change");
    }
}

impl sysfs::Attributes for Entry {
    fn vars(&self) -> Vec<(String, String)> {
        vec![("DEVTYPE".to_string(), "disk".to_string()), ("DISKSEQ".to_string(), self.diskseq.load(Ordering::Acquire).to_string())]
    }

    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>> {
        let files = |names: &[&str]| names.iter().map(|n| (n.to_string(), FileType::Regular)).collect::<Vec<_>>();
        match dir {
            "" => {
                let mut v = files(&["diskseq", "hidden", "removable", "ro", "size"]);
                v.push(("queue".to_string(), FileType::Directory));
                v.push(("slaves".to_string(), FileType::Directory));
                if let Some((name, _)) = self.disk.sysfs_dir() {
                    v.push((name.to_string(), FileType::Directory));
                }
                Some(v)
            }
            "queue" => Some(files(&["hw_sector_size", "logical_block_size", "nr_requests", "physical_block_size", "read_ahead_kb", "scheduler"])),
            // A link to each disk it is made of.
            "slaves" => Some(self.disk.slaves().into_iter().filter_map(name_of).map(|n| (n, FileType::Symlink)).collect()),
            other => match self.disk.sysfs_dir() {
                Some((name, names)) if name == other => Some(files(&names)),
                _ => None,
            },
        }
    }

    fn read(&self, path: &str) -> Option<(u32, String)> {
        let block = self.disk.block_size();
        Some(match path {
            "size" => (0o444, format!("{}\n", self.disk.size() / 512)),
            "ro" => (0o444, format!("{}\n", self.disk.read_only() as u32)),
            "removable" | "hidden" => (0o444, "0\n".to_string()),
            "diskseq" => (0o444, format!("{}\n", self.diskseq.load(Ordering::Acquire))),
            "queue/logical_block_size" | "queue/physical_block_size" | "queue/hw_sector_size" => (0o444, format!("{block}\n")),
            "queue/read_ahead_kb" => (0o644, format!("{}\n", self.read_ahead.load(Ordering::Acquire) / 2)),
            "queue/nr_requests" => (0o644, format!("{}\n", self.nr_requests.load(Ordering::Acquire))),
            // No queue to schedule: the one choice, chosen.
            "queue/scheduler" => (0o644, "[none] \n".to_string()),
            other => {
                let (dir, name) = other.split_once('/')?;
                let (driver, names) = self.disk.sysfs_dir()?;
                if dir != driver || !names.contains(&name) {
                    return None;
                }
                (0o444, self.disk.sysfs_read(name)?)
            }
        })
    }

    fn link(&self, path: &str) -> Option<String> {
        let name = path.strip_prefix("slaves/")?;
        self.disk.slaves().into_iter().filter_map(name_of).any(|n| n == name).then(|| format!("../../{name}"))
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<(), Errno> {
        let text = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?.trim();
        match path {
            "queue/read_ahead_kb" => {
                let kb: u32 = text.parse().map_err(|_| Errno::EINVAL)?;
                self.read_ahead.store(kb.saturating_mul(2), Ordering::Release);
                Ok(())
            }
            // At least `BLKDEV_MIN_RQ`.
            "queue/nr_requests" => {
                let n: u32 = text.parse().map_err(|_| Errno::EINVAL)?;
                self.nr_requests.store(n.max(4), Ordering::Release);
                Ok(())
            }
            // Only the one there is.
            "queue/scheduler" => {
                if text == "none" {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
            _ => Err(Errno::EACCES),
        }
    }
}

/// An open block device.
pub struct BlockFile {
    entry: Arc<Entry>,
    node: NodeMeta,
}

impl std::fmt::Debug for BlockFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockFile").field("disk", &self.entry.name).finish()
    }
}

impl Drop for BlockFile {
    fn drop(&mut self) {
        self.entry.disk.released();
    }
}

/// Open the disk numbered `dev` through the node `node` describes:
/// `ENXIO` for a number no disk has, as Linux says of one. A driver may
/// make the disk of a number that is asked for (`blk_request_module`:
/// the loop driver does).
pub fn open(dev: u64, node: NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    let entry = match entry(dev) {
        Some(e) => e,
        None => {
            crate::loopdev::probe(dev);
            entry(dev).ok_or(Errno::ENXIO)?
        }
    };
    entry.disk.opened()?;
    Ok(Arc::new(BlockFile { entry, node }))
}

impl BlockFile {
    /// The disk it is an open of.
    pub fn disk(&self) -> &Arc<dyn Disk> {
        &self.entry.disk
    }

    /// The block layer's ioctls (`blkdev_common_ioctl`), then the
    /// driver's. `None` for a request neither knows.
    pub fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        const BLKROSET: u64 = 0x125d;
        const BLKROGET: u64 = 0x125e;
        const BLKGETSIZE: u64 = 0x1260;
        const BLKFLSBUF: u64 = 0x1261;
        const BLKRASET: u64 = 0x1262;
        const BLKRAGET: u64 = 0x1263;
        const BLKFRASET: u64 = 0x1264;
        const BLKFRAGET: u64 = 0x1265;
        const BLKSSZGET: u64 = 0x1268;
        const BLKPBSZGET: u64 = 0x127b;
        const BLKGETSIZE64: u64 = 0x8008_1272;
        let disk = &self.entry.disk;
        let int = |m: &mut GuestMem<'_>, v: u32| m.write_u32(arg, v).map(|_| 0);
        // A long: 32 bits for a 32-bit caller, where a value that does
        // not fit is `EFBIG`.
        let long = |m: &mut GuestMem<'_>, v: u64| {
            if !cx.compat {
                m.write_u64(arg, v).map(|_| 0)
            } else if v > u32::MAX as u64 {
                Err(Errno::EFBIG)
            } else {
                m.write_u32(arg, v as u32).map(|_| 0)
            }
        };
        Some(match request {
            BLKGETSIZE64 => m.write_u64(arg, disk.size()).map(|_| 0),
            // In sectors.
            BLKGETSIZE => long(m, disk.size() / 512),
            BLKSSZGET | BLKPBSZGET => int(m, disk.block_size()),
            BLKROGET => int(m, disk.read_only() as u32),
            BLKROSET => m.read_u32(arg).map(|v| {
                disk.set_read_only(v != 0);
                0
            }),
            // Nothing is cached, so there is nothing to write out or drop.
            BLKFLSBUF => Ok(0),
            BLKRAGET | BLKFRAGET => long(m, self.entry.read_ahead.load(Ordering::Acquire) as u64),
            BLKRASET | BLKFRASET => {
                self.entry.read_ahead.store(arg.min(u32::MAX as u64) as u32, Ordering::Release);
                Ok(0)
            }
            _ => return disk.ioctl(cx, m, request, arg),
        })
    }
}

impl FileHandle for BlockFile {
    fn as_block(self: Arc<Self>) -> Option<Arc<BlockFile>> {
        Some(self)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let size = self.entry.disk.size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        self.entry.disk.read_at(offset, &mut buf[..n])
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        let disk = &self.entry.disk;
        if disk.read_only() {
            return Err(Errno::EPERM);
        }
        let size = disk.size();
        if offset >= size {
            return Err(Errno::ENOSPC);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        disk.write_at(offset, &buf[..n])
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok((self.node)())
    }

    fn device_size(&self) -> Option<u64> {
        Some(self.entry.disk.size())
    }
}
