//! binderfs: the filesystem the binder devices live in.
//!
//! Android mounts one at `/dev/binderfs` and links `/dev/binder`,
//! `/dev/hwbinder` and `/dev/vndbinder` into it. Every mount has those
//! three devices of its own ([`crate::binder::Context`]: a device's
//! processes talk to each other and to no other device's), a
//! `binder-control` node that makes more (`BINDER_CTL_ADD`), and a
//! `features` directory that says what the driver can do.
//!
//! As drivers/android/binderfs.c at android17-6.18 in what a program can
//! see. Not here: `binder_logs`, the driver's state as text, which
//! `stats=global` asks for (the mount is refused, and says why), and the
//! `transaction_report` feature, whose reports go over netlink.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::binder::{BinderFile, Context};
use crate::errno::{Errno, SysResult};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// `BINDERFS_MAX_MINOR`: how many devices there can be, in all mounts.
const MAX_MINOR: u32 = 1 << 20;
/// The character major the devices have. Linux allots one when the driver
/// starts; this is the one it has allotted on the kernels looked at.
const MAJOR: u64 = 235;
/// A device's inode is its minor and this.
const INODE_OFFSET: u64 = 3;
const FEATURES_INO: u64 = MAX_MINOR as u64 + INODE_OFFSET + 1;
/// `BINDER_CTL_ADD`, of a `struct binderfs_device`: a name of 256 bytes,
/// then the major and minor the new device got.
const CTL_ADD: u64 = 0xc108_6201;
const CONTROL: &str = "binder-control";
/// The devices every mount starts with (`CONFIG_ANDROID_BINDER_DEVICES`).
const DEVICES: [&str; 3] = ["binder", "hwbinder", "vndbinder"];
/// What the driver says it can do, each a file that reads `1`.
const FEATURES: [&str; 3] = ["oneway_spam_detection", "extended_error", "freeze_notification"];

/// The minors in use (`binderfs_minors`).
static MINORS: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

fn take_minor() -> Option<u32> {
    let mut used = MINORS.lock().unwrap_or_else(|e| e.into_inner());
    let free = (0..MAX_MINOR).find(|n| !used.contains(n))?;
    used.insert(free);
    Some(free)
}

fn rdev(minor: u32) -> u64 {
    let minor = minor as u64;
    (MAJOR & 0xfff) << 8 | (minor & 0xff) | (minor & !0xff) << 12
}

/// A node's minor number, and for a device its place in its mount's
/// count: held by the node's name and by every open of it, and given back
/// when the last of them goes (the inode's eviction). A device removed
/// while open still counts against its mount's `max=`.
struct Slot {
    minor: u32,
    counted: Option<Arc<AtomicU32>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        MINORS.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.minor);
        if let Some(count) = &self.counted {
            count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// A node of the root: a binder device, or `binder-control`.
struct Node {
    name: String,
    slot: Arc<Slot>,
    mode: Arc<AtomicU32>,
    /// `None` for `binder-control`.
    ctx: Option<Arc<Context>>,
}

impl Node {
    fn metadata(&self) -> Metadata {
        node_metadata(self.slot.minor, &self.mode)
    }
}

fn node_metadata(minor: u32, mode: &AtomicU32) -> Metadata {
    Metadata {
        file_type: FileType::CharDevice,
        size: 0,
        mode: mode.load(Ordering::Relaxed),
        ino: minor as u64 + INODE_OFFSET,
        mtime: 0,
        nlink: 1,
        rdev: rdev(minor),
        times: Default::default(),
    }
}

struct Inner {
    nodes: Vec<Node>,
    /// The `max=` it was mounted with: how many devices it may hold.
    max: u32,
    /// How many it holds, the removed ones that are still open among them.
    count: Arc<AtomicU32>,
    root_mode: u32,
}

impl Inner {
    /// `binderfs_binder_device_create`.
    fn add(&mut self, name: &str) -> Result<u32, Errno> {
        if self.count.load(Ordering::SeqCst) >= self.max {
            return Err(Errno::ENOSPC);
        }
        let minor = take_minor().ok_or(Errno::ENOSPC)?;
        self.count.fetch_add(1, Ordering::SeqCst);
        let slot = Arc::new(Slot { minor, counted: Some(Arc::clone(&self.count)) });
        self.nodes.push(Node { name: name.to_string(), slot, mode: Arc::new(AtomicU32::new(0o600)), ctx: Some(Context::new(name)) });
        Ok(minor)
    }
}

/// One mount of binderfs.
pub struct BinderFs {
    inner: Arc<Mutex<Inner>>,
}

impl BinderFs {
    /// A mount that may hold `max` devices, with the three it starts with.
    pub fn new(max: u32) -> Result<BinderFs, Errno> {
        let slot = Arc::new(Slot { minor: take_minor().ok_or(Errno::ENOSPC)?, counted: None });
        let control = Node { name: CONTROL.to_string(), slot, mode: Arc::new(AtomicU32::new(0o600)), ctx: None };
        let mut inner = Inner { nodes: vec![control], max, count: Arc::new(AtomicU32::new(0)), root_mode: 0o755 };
        for name in DEVICES {
            inner.add(name)?;
        }
        Ok(BinderFs { inner: Arc::new(Mutex::new(inner)) })
    }

    /// The `max=` of a mount's option string; the most there can be when
    /// it names none.
    pub fn options(data: &str) -> Result<u32, Errno> {
        let mut max = MAX_MINOR;
        for opt in data.split(',').filter(|o| !o.is_empty()) {
            match opt.split_once('=') {
                Some(("max", n)) => {
                    max = n.parse().map_err(|_| Errno::EINVAL)?;
                    if max > MAX_MINOR {
                        return Err(Errno::EINVAL);
                    }
                }
                Some(("stats", "global")) => {
                    eprintln!("[gex] binderfs: stats=global (binder_logs) is not implemented");
                    return Err(Errno::EINVAL);
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        Ok(max)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn feature(path: &str) -> Option<usize> {
    FEATURES.iter().position(|f| path.strip_prefix("features/") == Some(f))
}

fn feature_metadata(i: usize) -> Metadata {
    Metadata { file_type: FileType::Regular, size: 0, mode: 0o444, ino: FEATURES_INO + 1 + i as u64, mtime: 0, nlink: 1, rdev: 0, times: Default::default() }
}

fn features_metadata() -> Metadata {
    Metadata { mode: 0o555, ino: FEATURES_INO, ..Metadata::dir() }
}

impl FileSystem for BinderFs {
    fn fs_type(&self) -> &'static str {
        "binder"
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let inner = self.lock();
        if path.is_empty() || path == "features" {
            if super::writes(flags) {
                return Err(Errno::EISDIR);
            }
            let mut entries = vec![
                DirEntry { name: ".".into(), file_type: FileType::Directory, ino: 1 },
                DirEntry { name: "..".into(), file_type: FileType::Directory, ino: 1 },
            ];
            if path.is_empty() {
                entries.extend(inner.nodes.iter().map(|n| DirEntry { name: n.name.clone(), file_type: FileType::CharDevice, ino: n.slot.minor as u64 + INODE_OFFSET }));
                entries.push(DirEntry { name: "features".into(), file_type: FileType::Directory, ino: FEATURES_INO });
                return Ok(Arc::new(Dir { entries, metadata: Metadata { mode: inner.root_mode, ..Metadata::dir() } }));
            }
            entries.extend(FEATURES.iter().enumerate().map(|(i, f)| DirEntry { name: f.to_string(), file_type: FileType::Regular, ino: FEATURES_INO + 1 + i as u64 }));
            return Ok(Arc::new(Dir { entries, metadata: features_metadata() }));
        }
        if let Some(i) = feature(path) {
            // Read-only to everyone, its owner too: it has no write.
            if super::writes(flags) {
                return Err(Errno::EACCES);
            }
            return Ok(Arc::new(Feature(i)));
        }
        let Some(node) = inner.nodes.iter().find(|n| n.name == path) else {
            // Nothing is made here but by `binder-control`.
            return Err(if flags & crate::fs::oflags::O_CREAT != 0 && !path.contains('/') { Errno::EACCES } else { Errno::ENOENT });
        };
        let (slot, mode) = (Arc::clone(&node.slot), Arc::clone(&node.mode));
        match &node.ctx {
            Some(ctx) => Ok(Arc::new(BinderFile::open(Arc::clone(ctx)).at_node(Arc::new(move || node_metadata(slot.minor, &mode))))),
            None => Ok(Arc::new(Control { fs: Arc::clone(&self.inner), slot, mode })),
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        let inner = self.lock();
        if path.is_empty() {
            return Ok(Metadata { mode: inner.root_mode, ..Metadata::dir() });
        }
        if path == "features" {
            return Ok(features_metadata());
        }
        if let Some(i) = feature(path) {
            return Ok(feature_metadata(i));
        }
        inner.nodes.iter().find(|n| n.name == path).map(Node::metadata).ok_or(Errno::ENOENT)
    }

    /// A device goes when its name does (`binderfs_unlink`); the processes
    /// that have it open keep it. `binder-control` and what is in
    /// `features` stay.
    fn unlink(&self, path: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        if path == CONTROL || path == "features" || feature(path).is_some() {
            return Err(Errno::EPERM);
        }
        let at = inner.nodes.iter().position(|n| n.name == path).ok_or(Errno::ENOENT)?;
        inner.nodes.remove(at);
        Ok(())
    }

    fn mkdir(&self, path: &str, _mode: u32) -> Result<(), Errno> {
        self.metadata(path).map_or(Err(Errno::EPERM), |_| Err(Errno::EEXIST))
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        match self.metadata(path)?.file_type {
            FileType::Directory => Err(Errno::EPERM),
            _ => Err(Errno::ENOTDIR),
        }
    }

    /// A device may be renamed, over another too (`binderfs_rename`);
    /// `binder-control` neither moves nor is replaced.
    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        if from == CONTROL || to == CONTROL || from.contains('/') || to.contains('/') || from == "features" || to == "features" {
            return Err(Errno::EPERM);
        }
        let at = inner.nodes.iter().position(|n| n.name == from).ok_or(Errno::ENOENT)?;
        if from == to {
            return Ok(());
        }
        inner.nodes[at].name = to.to_string();
        if let Some(old) = inner.nodes.iter().enumerate().position(|(i, n)| i != at && n.name == to) {
            inner.nodes.remove(old);
        }
        Ok(())
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let mut inner = self.lock();
        if path.is_empty() {
            inner.root_mode = mode & 0o7777;
            return Ok(());
        }
        if path == "features" || feature(path).is_some() {
            return Ok(());
        }
        let node = inner.nodes.iter().find(|n| n.name == path).ok_or(Errno::ENOENT)?;
        node.mode.store(mode & 0o7777, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug)]
struct Dir {
    entries: Vec<DirEntry>,
    metadata: Metadata,
}

impl FileHandle for Dir {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EISDIR)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.metadata.clone())
    }
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Ok(self.entries.clone())
    }
}

/// A file of `features`: `1` and a newline.
#[derive(Debug)]
struct Feature(usize);

impl FileHandle for Feature {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let text = b"1\n";
        let from = (offset as usize).min(text.len());
        let n = buf.len().min(text.len() - from);
        buf[..n].copy_from_slice(&text[from..from + n]);
        Ok(n as u64)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(feature_metadata(self.0))
    }
}

/// `binder-control`, open: its one ioctl makes a device in its mount.
struct Control {
    fs: Arc<Mutex<Inner>>,
    slot: Arc<Slot>,
    mode: Arc<AtomicU32>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder-control")
    }
}

impl FileHandle for Control {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(node_metadata(self.slot.minor, &self.mode))
    }
    fn is_stream(&self) -> bool {
        true
    }
    fn ioctl(&self, m: &mut crate::GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        if request != CTL_ADD {
            return Some(Err(Errno::EINVAL));
        }
        Some((|| {
            let raw = m.read(arg, 256)?;
            // The last byte is taken as the end whatever it holds.
            let len = raw[..255].iter().position(|&b| b == 0).unwrap_or(255);
            let name = String::from_utf8_lossy(&raw[..len]).into_owned();
            let mut inner = self.fs.lock().unwrap_or_else(|e| e.into_inner());
            let minor = inner.add(&name)?;
            // The numbers are written before the name is looked up, so a
            // name that cannot be had has them all the same.
            let wrote = m.write_u32(arg + 256, MAJOR as u32).and_then(|()| m.write_u32(arg + 260, minor));
            let taken = inner.nodes[..inner.nodes.len() - 1].iter().any(|n| n.name == name) || name == "features";
            let refused = match wrote {
                Err(e) => Some(e),
                Ok(()) if name.is_empty() || name == "." || name == ".." || name.contains('/') => Some(Errno::EACCES),
                Ok(()) if taken => Some(Errno::EEXIST),
                Ok(()) => None,
            };
            match refused {
                Some(e) => {
                    inner.nodes.pop();
                    Err(e)
                }
                None => Ok(0),
            }
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount has its three devices, the control node and the features;
    /// a device can be added, renamed and removed, the control node
    /// cannot, and a mount holds no more devices than it was mounted for.
    #[test]
    fn a_mount_has_its_devices_and_makes_more_through_its_control_node() {
        assert_eq!(BinderFs::options(""), Ok(MAX_MINOR));
        assert_eq!(BinderFs::options("max=4"), Ok(4));
        assert_eq!(BinderFs::options("max=1048577"), Err(Errno::EINVAL));
        assert_eq!(BinderFs::options("stats=global"), Err(Errno::EINVAL));
        assert_eq!(BinderFs::options("mode=0755"), Err(Errno::EINVAL));
        assert!(BinderFs::new(2).is_err(), "no room for the three it starts with");

        let fs = BinderFs::new(4).unwrap();
        let names = |fs: &BinderFs| -> Vec<String> { fs.open("", 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).collect() };
        assert_eq!(names(&fs), [".", "..", "binder-control", "binder", "hwbinder", "vndbinder", "features"]);
        let md = fs.metadata("binder").unwrap();
        assert_eq!((md.file_type, md.mode), (FileType::CharDevice, 0o600));
        assert_eq!(md.rdev >> 8 & 0xfff, MAJOR);
        fs.chmod("binder", 0o666).unwrap();
        assert_eq!(fs.metadata("binder").unwrap().mode, 0o666);
        assert_eq!(fs.open("binder", 0, 0).unwrap().metadata().unwrap().mode, 0o666, "an open device is its node");

        let mut text = [0u8; 8];
        let f = fs.open("features/freeze_notification", 0, 0).unwrap();
        assert_eq!(f.read_at(0, &mut text), Ok(2));
        assert_eq!(&text[..2], b"1\n");
        assert_eq!(fs.metadata("features/transaction_report").err(), Some(Errno::ENOENT));

        // One more device, by the control node's ioctl.
        let mut bytes = vec![0u8; 0x1000];
        let mut m = crate::GuestMem::new(&mut bytes);
        let ctl = fs.open(CONTROL, 0, 0).unwrap();
        m.write(0x100, b"mine\0").unwrap();
        assert_eq!(ctl.ioctl(&mut m, CTL_ADD, 0x100), Some(Ok(0)));
        assert_eq!(m.read_u32(0x200).unwrap() as u64, MAJOR);
        assert_eq!(rdev(m.read_u32(0x204).unwrap()), fs.metadata("mine").unwrap().rdev);
        // Its name is taken, and the mount is full: one removed makes
        // room only when nothing has it open.
        assert_eq!(ctl.ioctl(&mut m, CTL_ADD, 0x100), Some(Err(Errno::ENOSPC)));
        let open = fs.open("vndbinder", 0, 0).unwrap();
        fs.unlink("vndbinder").unwrap();
        assert_eq!(ctl.ioctl(&mut m, CTL_ADD, 0x100), Some(Err(Errno::ENOSPC)));
        drop(open);
        assert_eq!(ctl.ioctl(&mut m, CTL_ADD, 0x100), Some(Err(Errno::EEXIST)));
        assert_eq!(ctl.ioctl(&mut m, 0x1234, 0x100), Some(Err(Errno::EINVAL)));

        fs.rename("mine", "yours").unwrap();
        assert_eq!(fs.rename(CONTROL, "other"), Err(Errno::EPERM));
        assert_eq!(fs.unlink(CONTROL), Err(Errno::EPERM));
        assert_eq!(fs.unlink("features/extended_error"), Err(Errno::EPERM));
        assert_eq!(names(&fs), [".", "..", "binder-control", "binder", "hwbinder", "yours", "features"]);
    }
}
