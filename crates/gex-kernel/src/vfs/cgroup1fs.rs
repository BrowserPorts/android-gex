//! A cgroup v1 hierarchy (`mount -t cgroup`, [`crate::cgroup1`]) as kernfs
//! shows it: a group a directory made by `mkdir`, its files the kernel's,
//! opened only the ways their modes allow; nothing else is made (`EACCES`),
//! removed or renamed (`EPERM`). Every mount of a hierarchy is the same.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::cgroup1;
use crate::errno::Errno;
use std::sync::Arc;

/// The filesystem hierarchy `hier` is: one for each.
pub fn instance(hier: u32) -> Arc<Cgroup1Fs> {
    static ALL: std::sync::Mutex<Vec<Arc<Cgroup1Fs>>> = std::sync::Mutex::new(Vec::new());
    let mut all = ALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(fs) = all.iter().find(|f| f.hier == hier) {
        return Arc::clone(fs);
    }
    let fs = Arc::new(Cgroup1Fs { hier });
    all.push(Arc::clone(&fs));
    fs
}

#[derive(Debug)]
pub struct Cgroup1Fs {
    hier: u32,
}

enum Node {
    Group(u64),
    File(u64, String, u32),
}

impl Cgroup1Fs {
    fn find(&self, path: &str) -> Result<Node, Errno> {
        let hs = cgroup1::hierarchies();
        let h = hs.all.iter().find(|h| h.id == self.hier).ok_or(Errno::ENODEV)?;
        if let Some(id) = h.at(path) {
            return Ok(Node::Group(id));
        }
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let id = h.at(dir).ok_or(Errno::ENOENT)?;
        let (n, mode, _) = h.files_of(id).into_iter().find(|(n, _, _)| n == name).ok_or(Errno::ENOENT)?;
        Ok(Node::File(id, n, mode))
    }

    fn metadata_of(&self, node: &Node) -> Result<Metadata, Errno> {
        let hs = cgroup1::hierarchies();
        let h = hs.all.iter().find(|h| h.id == self.hier).ok_or(Errno::ENODEV)?;
        let ino = |id: u64, k: usize| (u64::from(self.hier) << 48) | (id << 8) | k as u64;
        match node {
            Node::Group(id) => {
                let g = h.groups.get(id).ok_or(Errno::ENOENT)?;
                Ok(Metadata { file_type: FileType::Directory, size: 0, mode: g.mode, ino: ino(*id, 0), mtime: 0, nlink: 2 + g.children.len() as u32, rdev: 0, dev: 0, times: Default::default(), owner: Some(g.owner) })
            }
            Node::File(id, name, mode) => {
                let g = h.groups.get(id).ok_or(Errno::ENOENT)?;
                let k = h.files_of(*id).iter().position(|(n, _, _)| n == name).unwrap_or(0) + 1;
                let (mode, uid, gid) = g.files.get(name).copied().unwrap_or((*mode, g.made_by.0, g.made_by.1));
                Ok(Metadata { file_type: FileType::Regular, size: 0, mode, ino: ino(*id, k), mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: Some((uid, gid)) })
            }
        }
    }
}

#[derive(Debug)]
struct Dir {
    entries: Vec<DirEntry>,
    metadata: Metadata,
}

impl FileHandle for Dir {
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

#[derive(Debug)]
struct File {
    fs: Arc<Cgroup1Fs>,
    group: u64,
    name: String,
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::errno::SysResult {
        let data = cgroup1::read(self.fs.hier, self.group, &self.name)?;
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n as u64)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> crate::errno::SysResult {
        let who = crate::unix::Sender::current().map(|c| crate::cgroup::Writer { pid: c.pid, uid: c.uid });
        cgroup1::write(self.fs.hier, self.group, &self.name, buf, who)
    }
    fn write_keeps_position(&self) -> bool {
        true
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        let node = self.fs.find(&self.path())?;
        self.fs.metadata_of(&node)
    }
}

impl File {
    fn path(&self) -> String {
        let hs = cgroup1::hierarchies();
        let p = hs.all.iter().find(|h| h.id == self.fs.hier).map_or(String::new(), |h| h.path_of(self.group));
        format!("{}/{}", p.trim_start_matches('/'), self.name).trim_start_matches('/').to_string()
    }
}

impl FileSystem for Cgroup1Fs {
    fn fs_type(&self) -> &'static str {
        "cgroup"
    }

    fn magic(&self) -> u64 {
        // `CGROUP_SUPER_MAGIC`.
        0x0027_e0eb
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let node = match self.find(path) {
            Ok(n) => n,
            Err(Errno::ENOENT) if flags & crate::fs::oflags::O_CREAT != 0 => {
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                let hs = cgroup1::hierarchies();
                hs.all.iter().find(|h| h.id == self.hier).and_then(|h| h.at(dir)).ok_or(Errno::ENOENT)?;
                return Err(Errno::EACCES);
            }
            Err(e) => return Err(e),
        };
        if flags & crate::fs::oflags::O_CREAT != 0 && flags & crate::fs::oflags::O_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        let me = self.metadata_of(&node)?;
        match node {
            Node::Group(id) => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let hs = cgroup1::hierarchies();
                let h = hs.all.iter().find(|h| h.id == self.hier).ok_or(Errno::ENODEV)?;
                let g = h.groups.get(&id).ok_or(Errno::ENOENT)?;
                let mut entries = vec![DirEntry { name: ".".into(), file_type: FileType::Directory, ino: me.ino }, DirEntry { name: "..".into(), file_type: FileType::Directory, ino: me.ino }];
                for (n, _, _) in h.files_of(id) {
                    entries.push(DirEntry { name: n, file_type: FileType::Regular, ino: me.ino });
                }
                for name in g.children.keys() {
                    entries.push(DirEntry { name: name.clone(), file_type: FileType::Directory, ino: me.ino });
                }
                Ok(Arc::new(Dir { entries, metadata: me }))
            }
            Node::File(id, name, mode) => {
                if super::writes(flags) && mode & 0o222 == 0 {
                    return Err(Errno::EACCES);
                }
                if flags & 3 != crate::fs::oflags::O_WRONLY && mode & 0o444 == 0 {
                    return Err(Errno::EACCES);
                }
                Ok(Arc::new(File { fs: instance(self.hier), group: id, name }))
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.metadata_of(&self.find(path)?)
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = {
            let hs = cgroup1::hierarchies();
            hs.all.iter().find(|h| h.id == self.hier).and_then(|h| h.at(dir)).ok_or(Errno::ENOENT)?
        };
        let owner = super::Maker::current().unwrap_or((0, 0));
        cgroup1::mkdir(self.hier, parent, name, mode, owner)
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        match self.find(path)? {
            Node::Group(id) => cgroup1::rmdir(self.hier, id),
            Node::File(..) => Err(Errno::ENOTDIR),
        }
    }

    fn unlink(&self, path: &str) -> Result<(), Errno> {
        match self.find(path)? {
            Node::Group(_) => Err(Errno::EISDIR),
            Node::File(..) => Err(Errno::EPERM),
        }
    }

    fn rename(&self, from: &str, _to: &str) -> Result<(), Errno> {
        self.find(from)?;
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
        let node = self.find(path)?;
        let mut hs = cgroup1::hierarchies();
        let h = hs.all.iter_mut().find(|h| h.id == self.hier).ok_or(Errno::ENODEV)?;
        match node {
            Node::Group(id) => h.groups.get_mut(&id).ok_or(Errno::ENOENT)?.mode = mode & 0o7777,
            Node::File(id, name, _) => {
                let g = h.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                let m = g.made_by;
                g.files.entry(name).or_insert((0, m.0, m.1)).0 = mode & 0o7777;
            }
        }
        Ok(())
    }

    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let node = self.find(path)?;
        let mut hs = cgroup1::hierarchies();
        let h = hs.all.iter_mut().find(|h| h.id == self.hier).ok_or(Errno::ENODEV)?;
        match node {
            Node::Group(id) => {
                let g = h.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                g.owner = (uid.unwrap_or(g.owner.0), gid.unwrap_or(g.owner.1));
            }
            Node::File(id, name, mode) => {
                let g = h.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
                let m = g.made_by;
                let e = g.files.entry(name).or_insert((mode, m.0, m.1));
                e.1 = uid.unwrap_or(e.1);
                e.2 = gid.unwrap_or(e.2);
            }
        }
        Ok(())
    }
}
