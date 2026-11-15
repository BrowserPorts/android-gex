//! A filesystem as it is mounted in one place: what it was mounted from,
//! and with which flags.
//!
//! `/proc/mounts` and `/proc/self/mountinfo` say both of every mount, and
//! programs read them: Android's `apexd` finds the APEXes that are active
//! by the block device each `/apex/<name>@<version>` is mounted from.
//! And two of the flags change what the mount allows:
//!
//! - `MS_RDONLY`: nothing in it can be changed (`EROFS`), though a device
//!   node, a FIFO or a socket in it opens for writing as anywhere, since
//!   what is written goes elsewhere.
//! - `MS_NODEV`: a device node in it does not open (`EACCES`).
//!
//! The rest are kept and shown: `nosuid` and `noexec` (nothing here runs
//! a program with a file's user, and what may be run is not asked of the
//! mount yet), and the access-time flags (no access time is kept).
//!
//! A [`Mount`] is the filesystem with these in front of it: every call is
//! the filesystem's own, but for the two refusals.

use super::{FileHandle, FileSystem, FileType, Metadata, Walked, XattrOp};
use crate::errno::Errno;
use std::sync::Arc;

/// `mount`'s flags that a mount keeps.
pub mod flag {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const SYNCHRONOUS: u64 = 16;
    pub const MANDLOCK: u64 = 64;
    pub const DIRSYNC: u64 = 128;
    pub const NOSYMFOLLOW: u64 = 256;
    pub const NOATIME: u64 = 1024;
    pub const NODIRATIME: u64 = 2048;
    pub const RELATIME: u64 = 1 << 21;
    pub const STRICTATIME: u64 = 1 << 24;
    pub const LAZYTIME: u64 = 1 << 25;
}

/// What a mount was made with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// What `mount` was given as its source: a device's path, or for a
    /// filesystem with nothing behind it whatever the caller wrote.
    pub source: String,
    pub flags: u64,
}

impl Record {
    /// The options of the mount itself, after `ro` or `rw`
    /// (`show_mnt_opts`): with no access-time flag, `relatime`, as a
    /// mount is by default.
    pub fn mount_options(&self) -> String {
        let mut out = String::new();
        for (bit, name) in [(flag::NOSUID, ",nosuid"), (flag::NODEV, ",nodev"), (flag::NOEXEC, ",noexec"), (flag::NOATIME, ",noatime"), (flag::NODIRATIME, ",nodiratime")] {
            if self.flags & bit != 0 {
                out.push_str(name);
            }
        }
        if self.flags & (flag::NOATIME | flag::STRICTATIME) == 0 {
            out.push_str(",relatime");
        }
        if self.flags & flag::NOSYMFOLLOW != 0 {
            out.push_str(",nosymfollow");
        }
        out
    }

    /// The options of what is mounted, after `ro` or `rw`
    /// (`show_sb_opts`'s part of them).
    pub fn super_options(&self) -> String {
        let mut out = String::new();
        for (bit, name) in [(flag::SYNCHRONOUS, ",sync"), (flag::DIRSYNC, ",dirsync"), (flag::MANDLOCK, ",mand"), (flag::LAZYTIME, ",lazytime")] {
            if self.flags & bit != 0 {
                out.push_str(name);
            }
        }
        out
    }

    pub fn read_only(&self) -> bool {
        self.flags & flag::RDONLY != 0
    }
}

/// A filesystem, mounted.
pub struct Mount {
    fs: Arc<dyn FileSystem>,
    source: String,
    /// Its flags, which a remount changes.
    flags: std::sync::atomic::AtomicU64,
}

/// The flags a mount keeps, of all `mount` is given.
const KEPT: u64 = flag::RDONLY | flag::NOSUID | flag::NODEV | flag::NOEXEC | flag::SYNCHRONOUS | flag::MANDLOCK | flag::DIRSYNC | flag::NOSYMFOLLOW | flag::NOATIME | flag::NODIRATIME | flag::RELATIME | flag::STRICTATIME | flag::LAZYTIME;

impl Mount {
    /// `fs` as mounted from `source` with `flags`.
    pub fn new(fs: Arc<dyn FileSystem>, source: &str, flags: u64) -> Arc<dyn FileSystem> {
        Arc::new(Mount { fs, source: source.to_string(), flags: std::sync::atomic::AtomicU64::new(flags & KEPT) })
    }

    fn record(&self) -> Record {
        Record { source: self.source.clone(), flags: self.flags.load(std::sync::atomic::Ordering::Acquire) }
    }

    /// `EROFS` when the mount is read-only.
    fn writable(&self) -> Result<(), Errno> {
        if self.record().read_only() {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    /// What an open that the mount's flags have a say in may do, before
    /// the filesystem is asked: a read-only mount opens nothing for
    /// writing but what is not a file of its own, and makes nothing; a
    /// `nodev` mount opens no device.
    fn may_open(&self, path: &str, flags: u64) -> Result<(), Errno> {
        use crate::fs::oflags;
        let record = self.record();
        let ro = record.read_only();
        let nodev = record.flags & flag::NODEV != 0;
        let changes = super::writes(flags) || flags & (oflags::O_TRUNC | oflags::O_CREAT) != 0;
        if !nodev && !(ro && changes) {
            return Ok(());
        }
        match self.fs.metadata(path) {
            Ok(md) => {
                let device = matches!(md.file_type, FileType::CharDevice | FileType::BlockDevice);
                if nodev && device {
                    return Err(Errno::EACCES);
                }
                let own = matches!(md.file_type, FileType::Regular | FileType::Directory);
                if ro && own && (super::writes(flags) || flags & oflags::O_TRUNC != 0) {
                    // A directory opened for writing is that mistake first.
                    return Err(if md.file_type == FileType::Directory { Errno::EISDIR } else { Errno::EROFS });
                }
                Ok(())
            }
            Err(Errno::ENOENT) if ro && flags & oflags::O_CREAT != 0 => Err(Errno::EROFS),
            Err(_) => Ok(()),
        }
    }
}

impl FileSystem for Mount {
    fn fs_type(&self) -> &'static str {
        self.fs.fs_type()
    }
    fn magic(&self) -> u64 {
        self.fs.magic()
    }
    fn mount_record(&self) -> Option<Record> {
        Some(self.record())
    }
    fn remount(&self, flags: u64) -> bool {
        self.flags.store(flags & KEPT, std::sync::atomic::Ordering::Release);
        true
    }
    fn show_options(&self) -> String {
        self.fs.show_options()
    }
    fn keeps_links(&self) -> bool {
        self.fs.keeps_links()
    }
    fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.may_open(path, flags)?;
        self.fs.open(path, flags, mode)
    }
    fn open_mode(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.may_open(path, flags)?;
        self.fs.open_mode(path, flags, mode)
    }
    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.fs.metadata(path)
    }
    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        self.fs.metadata_nofollow(path)
    }
    fn access(&self, path: &str, mode: u32) -> Result<(), Errno> {
        // `W_OK` of a file in a read-only mount.
        if mode & 2 != 0 && self.record().read_only() {
            self.fs.metadata(path)?;
            return Err(Errno::EROFS);
        }
        self.fs.access(path, mode)
    }
    fn read_link(&self, path: &str) -> Result<String, Errno> {
        self.fs.read_link(path)
    }
    fn walk(&self, abs: &str, follow_final: bool, mounts: &str) -> Result<Walked, Errno> {
        self.fs.walk(abs, follow_final, mounts)
    }
    fn walk_metadata(&self, abs: &str, mounts: &str) -> Result<Option<Metadata>, Errno> {
        self.fs.walk_metadata(abs, mounts)
    }
    fn unlink(&self, path: &str) -> Result<(), Errno> {
        self.writable()?;
        self.fs.unlink(path)
    }
    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        // What is there already is said first, as Linux says it.
        if self.record().read_only() {
            return Err(if self.fs.metadata_nofollow(path).is_ok() { Errno::EEXIST } else { Errno::EROFS });
        }
        self.fs.mkdir(path, mode)
    }
    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        self.writable()?;
        self.fs.rmdir(path)
    }
    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        self.writable()?;
        self.fs.rename(from, to)
    }
    fn rename2(&self, from: &str, to: &str, noreplace: bool) -> Result<(), Errno> {
        self.writable()?;
        self.fs.rename2(from, to, noreplace)
    }
    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        self.writable()?;
        self.fs.chmod(path, mode)
    }
    fn set_mtime(&self, path: &str, secs: i64) -> Result<(), Errno> {
        self.writable()?;
        self.fs.set_mtime(path, secs)
    }
    fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        self.writable()?;
        self.fs.set_times(path, atime, mtime)
    }
    fn link(&self, from: &str, to: &str) -> Result<(), Errno> {
        self.writable()?;
        self.fs.link(from, to)
    }
    fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        if self.record().read_only() {
            return Err(if self.fs.metadata_nofollow(path).is_ok() { Errno::EEXIST } else { Errno::EROFS });
        }
        self.fs.symlink(target, path)
    }
    fn mksocket(&self, path: &str) -> Result<(), Errno> {
        self.writable()?;
        self.fs.mksocket(path)
    }
    fn mknod(&self, path: &str, mode: u32, rdev: u64) -> Result<(), Errno> {
        if self.record().read_only() {
            return Err(if self.fs.metadata_nofollow(path).is_ok() { Errno::EEXIST } else { Errno::EROFS });
        }
        self.fs.mknod(path, mode, rdev)
    }
    fn watch_key(&self, path: &str) -> Result<(Option<crate::inotify::Key>, bool), Errno> {
        self.fs.watch_key(path)
    }
    fn watched_remotely(&self) -> bool {
        self.fs.watched_remotely()
    }
    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        if matches!(op, XattrOp::Set { .. } | XattrOp::Remove { .. }) {
            self.writable()?;
        }
        self.fs.xattr(path, op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::oflags;
    use crate::vfs::TmpFs;

    fn tree() -> Arc<dyn FileSystem> {
        let fs = TmpFs::new();
        fs.add_file("dir/file", b"data".to_vec());
        fs.mknod("null", 0o666, super::super::devices::makedev(1, 3)).unwrap();
        Arc::new(fs)
    }

    /// A read-only mount changes nothing, and says what Linux says.
    #[test]
    fn a_read_only_mount_changes_nothing() {
        let m = Mount::new(tree(), "tmpfs", flag::RDONLY);
        assert!(m.open("dir/file", oflags::O_RDONLY, 0).is_ok());
        assert_eq!(m.open("dir/file", oflags::O_WRONLY, 0).err(), Some(Errno::EROFS));
        assert_eq!(m.open("dir/file", oflags::O_RDONLY | oflags::O_TRUNC, 0).err(), Some(Errno::EROFS));
        assert_eq!(m.open("dir/new", oflags::O_WRONLY | oflags::O_CREAT, 0o644).err(), Some(Errno::EROFS));
        assert!(m.open("dir/file", oflags::O_RDONLY | oflags::O_CREAT, 0o644).is_ok());
        assert_eq!(m.open("dir", oflags::O_RDWR, 0).err(), Some(Errno::EISDIR));
        // A device in it is written as anywhere.
        assert!(m.open("null", oflags::O_RDWR, 0).is_ok());
        assert_eq!(m.mkdir("new", 0o755), Err(Errno::EROFS));
        assert_eq!(m.mkdir("dir", 0o755), Err(Errno::EEXIST));
        assert_eq!(m.unlink("dir/file"), Err(Errno::EROFS));
        assert_eq!(m.rmdir("dir"), Err(Errno::EROFS));
        assert_eq!(m.rename("dir/file", "dir/other"), Err(Errno::EROFS));
        assert_eq!(m.chmod("dir/file", 0o600), Err(Errno::EROFS));
        assert_eq!(m.symlink("file", "dir/link"), Err(Errno::EROFS));
        assert_eq!(m.mknod("zero", 0o666, 0x105), Err(Errno::EROFS));
        assert_eq!(m.xattr("dir/file", XattrOp::Set { name: "user.x", value: b"1", flags: 0 }), Err(Errno::EROFS));
        assert_eq!(m.access("dir/file", 2), Err(Errno::EROFS));
        assert_eq!(m.access("dir/file", 4), Ok(()));
        assert_eq!(m.metadata("dir/file").unwrap().size, 4);
        // Remounted for writing, it takes them; and read-only again, not.
        assert!(m.remount(0));
        assert!(m.open("dir/file", oflags::O_WRONLY, 0).is_ok());
        assert!(m.remount(flag::RDONLY | flag::NOSUID));
        assert_eq!(m.open("dir/file", oflags::O_WRONLY, 0).err(), Some(Errno::EROFS));
        assert_eq!(m.mount_record().unwrap(), Record { source: "tmpfs".into(), flags: flag::RDONLY | flag::NOSUID });
        // The same tree mounted for writing takes them.
        let w = Mount::new(tree(), "tmpfs", 0);
        assert!(w.open("dir/file", oflags::O_WRONLY, 0).is_ok());
        assert_eq!(w.mkdir("new", 0o755), Ok(()));
    }

    /// A `nodev` mount opens no device.
    #[test]
    fn a_nodev_mount_opens_no_device() {
        let m = Mount::new(tree(), "tmpfs", flag::NODEV);
        assert_eq!(m.open("null", oflags::O_RDONLY, 0).err(), Some(Errno::EACCES));
        assert!(m.open("dir/file", oflags::O_RDWR, 0).is_ok());
        assert!(m.metadata("null").is_ok());
    }

    /// The options as `/proc/mounts` words them.
    #[test]
    fn options_are_worded_as_linux_words_them() {
        let r = |flags| Record { source: "x".into(), flags };
        assert_eq!(r(0).mount_options(), ",relatime");
        assert_eq!(r(flag::NOSUID | flag::NODEV | flag::NOEXEC).mount_options(), ",nosuid,nodev,noexec,relatime");
        assert_eq!(r(flag::NOATIME | flag::NODEV).mount_options(), ",nodev,noatime");
        assert_eq!(r(flag::STRICTATIME).mount_options(), "");
        assert_eq!(r(flag::RDONLY | flag::DIRSYNC).super_options(), ",dirsync");
        assert_eq!(r(flag::SYNCHRONOUS | flag::LAZYTIME).super_options(), ",sync,lazytime");
    }
}
