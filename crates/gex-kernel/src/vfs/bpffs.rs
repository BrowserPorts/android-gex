//! bpffs (`mount -t bpf`, `kernel/bpf/inode.c`): directories, symbolic
//! links, and the BPF objects `BPF_OBJ_PIN` puts there, by which another
//! process gets them (`BPF_OBJ_GET`). Android mounts one at `/sys/fs/bpf`.
//!
//! As Linux 7.0 has it (`tests/android/src/bpfmap.c`): nothing else is made
//! here (an `open` with `O_CREAT` is `EACCES`), a pinned object is a
//! regular file of mode 0600 less the umask that does not open (`EIO`),
//! and `BPF_OBJ_GET` of anything but a pinned object is `EACCES`.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::bpf::Object;
use crate::errno::Errno;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// `BPF_FS_MAGIC`.
pub const MAGIC: u64 = 0xcafe_4a11;

#[derive(Debug, Clone)]
enum Kind {
    Dir,
    Link(String),
    Obj(Object),
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    ino: u64,
}

#[derive(Debug)]
struct Inner {
    /// By path from the mount's root, no leading slash; "" is the root.
    nodes: BTreeMap<String, Node>,
    next_ino: u64,
}

/// A bpffs mount.
#[derive(Debug)]
pub struct BpfFs {
    inner: Mutex<Inner>,
}

impl Default for BpfFs {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfFs {
    /// An empty one: its root a sticky directory anyone may write
    /// (`S_IFDIR | S_ISVTX | 0777`, bpffs's default `mode=`).
    pub fn new() -> BpfFs {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::new(), Node { kind: Kind::Dir, mode: 0o1777, uid: 0, gid: 0, ino: 1 });
        BpfFs { inner: Mutex::new(Inner { nodes, next_ino: 2 }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `BPF_OBJ_PIN` at `path` (from the root): its directory must be
    /// there, the name not.
    pub fn pin(&self, path: &str, obj: Object, mode: u32, uid: u32, gid: u32) -> Result<(), Errno> {
        let mut inner = self.lock();
        inner.parent_dir(path)?;
        if inner.nodes.contains_key(path) {
            return Err(Errno::EEXIST);
        }
        let ino = inner.take_ino();
        inner.nodes.insert(path.to_string(), Node { kind: Kind::Obj(obj), mode: mode & 0o7777, uid, gid, ino });
        Ok(())
    }

    /// `BPF_OBJ_GET` of `path`: the object pinned there; `EACCES` for
    /// anything else that is there.
    pub fn get(&self, path: &str) -> Result<Object, Errno> {
        match self.lock().nodes.get(path) {
            None => Err(Errno::ENOENT),
            Some(Node { kind: Kind::Obj(o), .. }) => Ok(o.clone()),
            Some(_) => Err(Errno::EACCES),
        }
    }
}

impl Inner {
    fn take_ino(&mut self) -> u64 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    /// The directory `path` would be made in must be one.
    fn parent_dir(&self, path: &str) -> Result<(), Errno> {
        let parent = path.rfind('/').map_or("", |i| &path[..i]);
        match self.nodes.get(parent) {
            Some(Node { kind: Kind::Dir, .. }) => Ok(()),
            Some(_) => Err(Errno::ENOTDIR),
            None => Err(Errno::ENOENT),
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        let n = self.nodes.get(path).ok_or(Errno::ENOENT)?;
        let (file_type, size) = match &n.kind {
            Kind::Dir => (FileType::Directory, 0),
            Kind::Link(t) => (FileType::Symlink, t.len() as u64),
            Kind::Obj(_) => (FileType::Regular, 0),
        };
        let nlink = if matches!(n.kind, Kind::Dir) { 2 } else { 1 };
        Ok(Metadata { file_type, size, mode: n.mode, ino: n.ino, mtime: 0, nlink, rdev: 0, dev: 0, times: Default::default(), owner: Some((n.uid, n.gid)) })
    }

    fn children(&self, dir: &str) -> impl Iterator<Item = (&String, &Node)> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        self.nodes.iter().filter(move |(k, _)| !k.is_empty() && k.starts_with(&prefix) && !k[prefix.len()..].contains('/'))
    }
}

/// A directory of it, open.
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

impl FileSystem for BpfFs {
    fn fs_type(&self) -> &'static str {
        "bpf"
    }

    fn magic(&self) -> u64 {
        MAGIC
    }

    fn bpf(&self) -> Option<&BpfFs> {
        Some(self)
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let inner = self.lock();
        match inner.nodes.get(path) {
            Some(Node { kind: Kind::Dir, .. }) => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let me = inner.metadata(path)?;
                let mut entries = vec![
                    DirEntry { name: ".".into(), file_type: FileType::Directory, ino: me.ino },
                    DirEntry { name: "..".into(), file_type: FileType::Directory, ino: 1 },
                ];
                for (k, n) in inner.children(path) {
                    let file_type = match n.kind {
                        Kind::Dir => FileType::Directory,
                        Kind::Link(_) => FileType::Symlink,
                        Kind::Obj(_) => FileType::Regular,
                    };
                    entries.push(DirEntry { name: k.rsplit('/').next().unwrap_or(k).to_string(), file_type, ino: n.ino });
                }
                Ok(Arc::new(Dir { entries, metadata: me }))
            }
            // A pinned object is had by BPF_OBJ_GET, not by open.
            Some(Node { kind: Kind::Obj(_), .. }) => Err(Errno::EIO),
            Some(Node { kind: Kind::Link(_), .. }) => Err(Errno::ELOOP),
            None => {
                // Nothing is made here but by bpf(2) and mkdir.
                if flags & crate::fs::oflags::O_CREAT != 0 {
                    inner.parent_dir(path)?;
                    return Err(Errno::EACCES);
                }
                Err(Errno::ENOENT)
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.lock().metadata(path)
    }

    fn read_link(&self, path: &str) -> Result<String, Errno> {
        match self.lock().nodes.get(path) {
            Some(Node { kind: Kind::Link(t), .. }) => Ok(t.clone()),
            Some(_) => Err(Errno::EINVAL),
            None => Err(Errno::ENOENT),
        }
    }

    fn keeps_links(&self) -> bool {
        true
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let mut inner = self.lock();
        if inner.nodes.contains_key(path) {
            return Err(Errno::EEXIST);
        }
        inner.parent_dir(path)?;
        let ino = inner.take_ino();
        let (uid, gid) = super::Maker::current().unwrap_or((0, 0));
        inner.nodes.insert(path.to_string(), Node { kind: Kind::Dir, mode: mode & 0o7777, uid, gid, ino });
        Ok(())
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        match inner.nodes.get(path) {
            None => return Err(Errno::ENOENT),
            Some(Node { kind: Kind::Dir, .. }) => {}
            Some(_) => return Err(Errno::ENOTDIR),
        }
        if path.is_empty() {
            return Err(Errno::EBUSY);
        }
        if inner.children(path).next().is_some() {
            return Err(Errno::ENOTEMPTY);
        }
        inner.nodes.remove(path);
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        match inner.nodes.get(path) {
            None => Err(Errno::ENOENT),
            Some(Node { kind: Kind::Dir, .. }) => Err(Errno::EISDIR),
            Some(_) => {
                inner.nodes.remove(path);
                Ok(())
            }
        }
    }

    fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        if inner.nodes.contains_key(path) {
            return Err(Errno::EEXIST);
        }
        inner.parent_dir(path)?;
        let ino = inner.take_ino();
        let (uid, gid) = super::Maker::current().unwrap_or((0, 0));
        inner.nodes.insert(path.to_string(), Node { kind: Kind::Link(target.to_string()), mode: 0o777, uid, gid, ino });
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        let mut inner = self.lock();
        let node = inner.nodes.get(from).cloned().ok_or(Errno::ENOENT)?;
        inner.parent_dir(to)?;
        if from == to {
            return Ok(());
        }
        if let Some(there) = inner.nodes.get(to) {
            match (&there.kind, &node.kind) {
                (Kind::Dir, Kind::Dir) if inner.children(to).next().is_some() => return Err(Errno::ENOTEMPTY),
                (Kind::Dir, Kind::Dir) => {}
                (Kind::Dir, _) => return Err(Errno::EISDIR),
                (_, Kind::Dir) => return Err(Errno::ENOTDIR),
                _ => {}
            }
        }
        // A directory takes what is under it along.
        let moved: Vec<String> = inner.nodes.keys().filter(|k| *k == from || k.starts_with(&format!("{from}/"))).cloned().collect();
        let mut taken = Vec::new();
        for k in moved {
            let n = inner.nodes.remove(&k).unwrap();
            taken.push((format!("{to}{}", &k[from.len()..]), n));
        }
        inner.nodes.remove(to);
        inner.nodes.extend(taken);
        Ok(())
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let mut inner = self.lock();
        let n = inner.nodes.get_mut(path).ok_or(Errno::ENOENT)?;
        n.mode = mode & 0o7777;
        Ok(())
    }

    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let mut inner = self.lock();
        let n = inner.nodes.get_mut(path).ok_or(Errno::ENOENT)?;
        if let Some(u) = uid {
            n.uid = u;
        }
        if let Some(g) = gid {
            n.gid = g;
        }
        Ok(())
    }
}
