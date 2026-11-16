//! cgroup2 (`mount -t cgroup2`): the one hierarchy of [`crate::cgroup`] as
//! kernfs shows it. Every mount is the same filesystem, as Linux's is one
//! superblock. A group is a directory, made by `mkdir` and removed by
//! `rmdir`; its files are the kernel's, each opened only the ways its mode
//! allows (`kernfs_fop_open`), and nothing else is made here (`EACCES`),
//! removed (`EPERM`) or renamed (`EPERM`). Modes and owners can be
//! changed, as Android's init and libprocessgroup change them.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::cgroup;
use crate::errno::Errno;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// The filesystem every cgroup2 mount is.
pub fn instance() -> Arc<CgroupFs> {
    static FS: OnceLock<Arc<CgroupFs>> = OnceLock::new();
    Arc::clone(FS.get_or_init(|| Arc::new(CgroupFs)))
}

#[derive(Debug)]
pub struct CgroupFs;

/// What a path is: a group, or a file of one.
enum Node {
    Group(u64),
    File(u64, &'static str),
}

fn find(path: &str) -> Result<Node, Errno> {
    let t = cgroup::tree();
    if let Some(id) = t.at(path) {
        return Ok(Node::Group(id));
    }
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let id = t.at(dir).ok_or(Errno::ENOENT)?;
    let file = cgroup::FILES.iter().find(|(n, _, not_root)| *n == name && !(id == cgroup::ROOT && *not_root)).ok_or(Errno::ENOENT)?;
    Ok(Node::File(id, file.0))
}

/// The inode numbers: a group's, and its files' after it.
fn ino(id: u64, file: Option<&str>) -> u64 {
    let k = file.and_then(|f| cgroup::FILES.iter().position(|(n, _, _)| *n == f)).map_or(0, |i| i + 1);
    (id << 6) | k as u64
}

fn metadata_of(node: &Node) -> Result<Metadata, Errno> {
    let t = cgroup::tree();
    match *node {
        Node::Group(id) => {
            let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
            Ok(Metadata { file_type: FileType::Directory, size: 0, mode: g.mode, ino: ino(id, None), mtime: 0, nlink: 2 + g.children.len() as u32, rdev: 0, times: Default::default(), owner: Some(g.owner) })
        }
        Node::File(id, name) => {
            let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
            let (mode, uid, gid) = g.files.get(name).copied().unwrap_or((cgroup::file_mode(name, id == cgroup::ROOT).unwrap_or(0), g.made_by.0, g.made_by.1));
            Ok(Metadata { file_type: FileType::Regular, size: 0, mode, ino: ino(id, Some(name)), mtime: 0, nlink: 1, rdev: 0, times: Default::default(), owner: Some((uid, gid)) })
        }
    }
}

#[derive(Debug)]
struct Dir {
    group: u64,
    entries: Vec<DirEntry>,
    metadata: Metadata,
}

impl FileHandle for Dir {
    fn cgroup(&self) -> Option<u64> {
        Some(self.group)
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(Errno::EISDIR)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.metadata.clone())
    }
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Ok(self.entries.clone())
    }
}

/// A group's file, open: what it says is made at each read from its
/// start, as a seq file's is; each write is the whole of what it takes.
#[derive(Debug)]
struct File {
    group: u64,
    name: &'static str,
    /// The change count of `cgroup.events` as this reader last read it
    /// (kernfs's `of->event`): `POLLPRI` once it has moved.
    seen: AtomicU64,
    /// A pressure file's trigger.
    pressure: Option<crate::vfs::procfs::Pressure>,
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::errno::SysResult {
        if let Some(p) = &self.pressure {
            return p.read_at(offset, buf);
        }
        if self.name == "cgroup.events" {
            self.seen.store(cgroup::events_of(self.group), Ordering::SeqCst);
        }
        let data = cgroup::read(self.group, self.name)?;
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n as u64)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> crate::errno::SysResult {
        if let Some(p) = &self.pressure {
            return p.write_at(0, buf);
        }
        let who = crate::unix::Sender::current().map(|c| cgroup::Writer { pid: c.pid, uid: c.uid });
        cgroup::write(self.group, self.name, buf, who)
    }
    fn write_keeps_position(&self) -> bool {
        true
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        metadata_of(&Node::File(self.group, self.name))
    }
    fn wait_queue(&self) -> u32 {
        match &self.pressure {
            Some(p) => p.wait_queue(),
            None if self.name == "cgroup.events" => cgroup::events_queue().id(),
            None => 0,
        }
    }
    fn wakes(&self) -> Option<u64> {
        (self.name == "cgroup.events").then(|| cgroup::events_of(self.group))
    }
    fn poll_pri(&self) -> bool {
        match &self.pressure {
            Some(p) => p.poll_pri(),
            None => self.name == "cgroup.events" && cgroup::events_of(self.group) != self.seen.load(Ordering::SeqCst),
        }
    }
}

impl FileSystem for CgroupFs {
    fn fs_type(&self) -> &'static str {
        "cgroup2"
    }

    fn magic(&self) -> u64 {
        cgroup::MAGIC
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let node = match find(path) {
            Ok(n) => n,
            // Nothing is made here.
            Err(Errno::ENOENT) if flags & crate::fs::oflags::O_CREAT != 0 => {
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                cgroup::tree().at(dir).ok_or(Errno::ENOENT)?;
                return Err(Errno::EACCES);
            }
            Err(e) => return Err(e),
        };
        if flags & crate::fs::oflags::O_CREAT != 0 && flags & crate::fs::oflags::O_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        let me = metadata_of(&node)?;
        match node {
            Node::Group(id) => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let t = cgroup::tree();
                let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
                let mut entries = vec![
                    DirEntry { name: ".".into(), file_type: FileType::Directory, ino: me.ino },
                    DirEntry { name: "..".into(), file_type: FileType::Directory, ino: ino(g.parent.unwrap_or(id), None) },
                ];
                for (name, _, not_root) in cgroup::FILES {
                    if !(id == cgroup::ROOT && *not_root) {
                        entries.push(DirEntry { name: name.to_string(), file_type: FileType::Regular, ino: ino(id, Some(name)) });
                    }
                }
                for (name, &c) in &g.children {
                    entries.push(DirEntry { name: name.clone(), file_type: FileType::Directory, ino: ino(c, None) });
                }
                Ok(Arc::new(Dir { group: id, entries, metadata: me }))
            }
            Node::File(id, name) => {
                // As its mode allows, whoever asks (`kernfs_fop_open`).
                let default = cgroup::file_mode(name, id == cgroup::ROOT).unwrap_or(0);
                if super::writes(flags) && default & 0o222 == 0 {
                    return Err(Errno::EACCES);
                }
                if flags & 3 != crate::fs::oflags::O_WRONLY && default & 0o444 == 0 {
                    return Err(Errno::EACCES);
                }
                let pressure = name.ends_with(".pressure").then(|| crate::vfs::procfs::Pressure::new(name == "irq.pressure")).filter(|_| name != "cgroup.pressure");
                Ok(Arc::new(File { group: id, name, seen: AtomicU64::new(cgroup::events_of(id)), pressure }))
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        metadata_of(&find(path)?)
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = cgroup::tree().at(dir).ok_or(Errno::ENOENT)?;
        // The maker's, unless it is root's (`cgroup_kn_set_ugid`).
        let owner = super::Maker::current().unwrap_or((0, 0));
        cgroup::mkdir(parent, name, mode, owner).map(|_| ())
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        match find(path)? {
            Node::Group(id) => cgroup::rmdir(id),
            Node::File(..) => Err(Errno::ENOTDIR),
        }
    }

    fn unlink(&self, path: &str) -> Result<(), Errno> {
        match find(path)? {
            Node::Group(_) => Err(Errno::EISDIR),
            Node::File(..) => Err(Errno::EPERM),
        }
    }

    fn rename(&self, from: &str, _to: &str) -> Result<(), Errno> {
        find(from)?;
        Err(Errno::EPERM)
    }

    fn link(&self, _from: &str, _to: &str) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn symlink(&self, _target: &str, _path: &str) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn mknod(&self, _path: &str, _mode: u32, _rdev: u64) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let node = find(path)?;
        let mut t = cgroup::tree();
        match node {
            Node::Group(id) => t.groups.get_mut(&id).ok_or(Errno::ENOENT)?.mode = mode & 0o7777,
            Node::File(id, name) => {
                let g = t.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                let made_by = g.made_by;
                let e = g.files.entry(name.to_string()).or_insert((0, made_by.0, made_by.1));
                e.0 = mode & 0o7777;
            }
        }
        Ok(())
    }

    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let node = find(path)?;
        let mut t = cgroup::tree();
        match node {
            Node::Group(id) => {
                let g = t.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                g.owner = (uid.unwrap_or(g.owner.0), gid.unwrap_or(g.owner.1));
            }
            Node::File(id, name) => {
                let g = t.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                let mode = cgroup::file_mode(name, id == cgroup::ROOT).unwrap_or(0);
                let made_by = g.made_by;
                let e = g.files.entry(name.to_string()).or_insert((mode, made_by.0, made_by.1));
                e.1 = uid.unwrap_or(e.1);
                e.2 = gid.unwrap_or(e.2);
            }
        }
        Ok(())
    }
}
