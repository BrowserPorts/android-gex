//! selinuxfs: the filesystem a program talks to SELinux through.
//!
//! Android's init mounts it at `/sys/fs/selinux` before anything else and
//! writes the policy to its `load`; libselinux then reads `enforce`, maps
//! `status`, and asks its questions of `access` and `create`. What the
//! files hold is the security server's to say
//! ([`crate::selinux::server::Server`]); this is the tree they sit in, as
//! security/selinux/selinuxfs.c at android17-6.18 lays it out: the names,
//! their modes and inode numbers, and which of them are directories.
//!
//! Every mount is the one filesystem, as on Linux, where it has a single
//! superblock: [`SelinuxFs::of_kernel`] is over the kernel's own server.
//!
//! Not here yet, and opening them says so: `policy` (the loaded policy
//! written out again), and the kernel's own statistics under `avc` and
//! `ss`, which count a cache and a hash table this kernel does not have.
//! Nor is a file's mode held against who opens it: no file of this kernel
//! has an owner yet.

use super::devices::makedev;
use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::errno::{Errno, SysResult};
use crate::selinux::server::{self, Server, INITIAL_SID_NAMES};
use std::sync::{Arc, Mutex};

/// `SELINUX_MAGIC`.
pub const MAGIC: u64 = 0xf97c_ff8c;

/// The root's files, each with its inode number (`enum sel_inos`) and
/// mode.
const ROOT_FILES: [(&str, u64, u32); 18] = [
    ("load", 3, 0o600),
    ("enforce", 4, 0o644),
    ("context", 5, 0o666),
    ("access", 6, 0o666),
    ("create", 7, 0o666),
    ("relabel", 8, 0o666),
    ("user", 9, 0o666),
    ("policyvers", 10, 0o444),
    ("commit_pending_bools", 11, 0o200),
    ("mls", 12, 0o444),
    ("disable", 13, 0o200),
    ("member", 14, 0o666),
    ("checkreqprot", 15, 0o644),
    ("reject_unknown", 17, 0o444),
    ("deny_unknown", 18, 0o444),
    ("status", 19, 0o444),
    ("policy", 20, 0o444),
    ("validatetrans", 21, 0o222),
];
/// The root's directories and `null`, numbered in the order the
/// filesystem makes them after its files, with what `avc` and `ss` hold
/// numbered between.
const BOOLEANS_INO: u64 = 22;
const NULL_INO: u64 = 23;
const AVC_INO: u64 = 24;
const AVC_FILES: [(&str, u64, u32); 3] = [("cache_threshold", 25, 0o644), ("hash_stats", 26, 0o444), ("cache_stats", 27, 0o444)];
const SS_INO: u64 = 28;
const SS_FILES: [(&str, u64, u32); 1] = [("sidtab_hash_stats", 29, 0o444)];
const INITIAL_CONTEXTS_INO: u64 = 30;
const CLASS_INO: u64 = 31;
const POLICY_CAPABILITIES_INO: u64 = 32;
const DIRS: [(&str, u64); 6] = [
    ("booleans", BOOLEANS_INO),
    ("avc", AVC_INO),
    ("ss", SS_INO),
    ("initial_contexts", INITIAL_CONTEXTS_INO),
    ("class", CLASS_INO),
    ("policy_capabilities", POLICY_CAPABILITIES_INO),
];
/// What a file's inode number carries besides its index
/// (`SEL_*_INO_OFFSET`).
const INITCON_OFFSET: u64 = 0x0100_0000;
const BOOL_OFFSET: u64 = 0x0200_0000;
const CLASS_OFFSET: u64 = 0x0400_0000;
const POLICYCAP_OFFSET: u64 = 0x0800_0000;
/// `SEL_VEC_MAX + 1`: a class's inode numbers are this many apart, its
/// permissions' between.
const CLASS_STRIDE: u64 = 33;
/// `sizeof(struct selinux_kernel_status)`: what `status` reads.
const STATUS_LEN: usize = 20;

/// What a name is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Dir,
    /// A file that reads the server's state ([`Server::file`]).
    State,
    /// A file of the root that is more than that: by its name.
    Root(&'static str),
    /// `null`: the null device.
    Null,
    /// A file that is not here yet.
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    kind: Kind,
    ino: u64,
    mode: u32,
    /// For a directory, how many directories it holds.
    subdirs: u32,
}

impl Found {
    fn file(kind: Kind, ino: u64, mode: u32) -> Option<Found> {
        Some(Found { kind, ino, mode, subdirs: 0 })
    }

    fn dir(ino: u64, subdirs: u32) -> Option<Found> {
        Some(Found { kind: Kind::Dir, ino, mode: 0o555, subdirs })
    }

    fn file_type(&self) -> FileType {
        match self.kind {
            Kind::Dir => FileType::Directory,
            Kind::Null => FileType::CharDevice,
            _ => FileType::Regular,
        }
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            file_type: self.file_type(),
            size: 0,
            mode: self.mode,
            ino: self.ino,
            mtime: 0,
            nlink: if self.kind == Kind::Dir { 2 + self.subdirs } else { 1 },
            rdev: if self.kind == Kind::Null { makedev(1, 3) } else { 0 },
            times: Default::default(),
        }
    }
}

/// The files of the root that only read the server's state.
fn reads_state(name: &str) -> bool {
    matches!(name, "policyvers" | "mls" | "reject_unknown" | "deny_unknown")
}

/// What `path` names, as the server now stands.
fn find(s: &Server, path: &str) -> Option<Found> {
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    let classes = || s.dir("class").unwrap_or_default();
    // A class's number, and its place among the classes.
    let class = |name: &str| {
        let number = String::from_utf8(s.file(&format!("class/{name}/index"))?.1.ok()?).ok()?.parse::<u64>().ok()?;
        Some((number, classes().iter().position(|c| c == name)? as u64))
    };
    // The inode numbers the class directories are given from
    // (`sel_make_classes`): each class's, then its `perms`.
    let class_dirs_from = || ((classes().len() as u64 + 2) * CLASS_STRIDE) | CLASS_OFFSET;
    match parts.as_slice() {
        [] => Found::dir(2, DIRS.len() as u32),
        ["null"] => Found::file(Kind::Null, NULL_INO, 0o666),
        [name] => {
            if let Some(&(_, ino)) = DIRS.iter().find(|(n, _)| n == name) {
                return Found::dir(ino, if ino == CLASS_INO { classes().len() as u32 } else { 0 });
            }
            let &(name, ino, mode) = ROOT_FILES.iter().find(|(n, ..)| n == name)?;
            Found::file(if reads_state(name) { Kind::State } else { Kind::Root(name) }, ino, mode)
        }
        ["avc", name] => AVC_FILES.iter().find(|(n, ..)| n == name).and_then(|&(_, ino, mode)| Found::file(Kind::Missing, ino, mode)),
        ["ss", name] => SS_FILES.iter().find(|(n, ..)| n == name).and_then(|&(_, ino, mode)| Found::file(Kind::Missing, ino, mode)),
        ["booleans", name] => {
            let at = s.dir("booleans")?.iter().position(|b| b == name)? as u64;
            Found::file(Kind::State, at | BOOL_OFFSET, s.file(path)?.0)
        }
        ["initial_contexts", name] => {
            let sid = INITIAL_SID_NAMES.iter().position(|n| n.as_deref() == Some(*name))? as u64;
            Found::file(Kind::State, sid | INITCON_OFFSET, 0o444)
        }
        ["policy_capabilities", name] => {
            let at = s.dir("policy_capabilities")?.iter().position(|c| c == name)? as u64;
            Found::file(Kind::State, at | POLICYCAP_OFFSET, 0o444)
        }
        ["class", name] => Found::dir(class_dirs_from() + 1 + 2 * class(name)?.1, 1),
        ["class", name, "index"] => Found::file(Kind::State, (class(name)?.0 * CLASS_STRIDE) | CLASS_OFFSET, 0o444),
        ["class", name, "perms"] => Found::dir(class_dirs_from() + 2 + 2 * class(name)?.1, 0),
        ["class", name, "perms", _] => {
            let number = String::from_utf8(s.file(path)?.1.ok()?).ok()?.parse::<u64>().ok()?;
            Found::file(Kind::State, (class(name)?.0 * CLASS_STRIDE + number) | CLASS_OFFSET, 0o444)
        }
        _ => None,
    }
}

/// The names in the directory `path` is.
fn names(s: &Server, path: &str) -> Vec<String> {
    let table = |files: &[(&str, u64, u32)]| files.iter().map(|f| f.0.to_string()).collect();
    match path {
        "" => {
            let mut all: Vec<String> = table(&ROOT_FILES);
            all.push("null".to_string());
            all.extend(DIRS.iter().map(|d| d.0.to_string()));
            all
        }
        "avc" => table(&AVC_FILES),
        "ss" => table(&SS_FILES),
        _ => s.dir(path).unwrap_or_default(),
    }
}

fn errno(e: server::Error) -> Errno {
    match e {
        server::Error::Invalid => Errno::EINVAL,
        server::Error::Denied => Errno::EACCES,
        server::Error::NotPermitted => Errno::EPERM,
    }
}

/// `simple_read_from_buffer`: the part of `all` a read at `offset` gets.
fn read_from(all: &[u8], offset: u64, buf: &mut [u8]) -> SysResult {
    let from = (offset.min(all.len() as u64)) as usize;
    let n = buf.len().min(all.len() - from);
    buf[..n].copy_from_slice(&all[from..from + n]);
    Ok(n as u64)
}

/// selinuxfs, over a security server.
pub struct SelinuxFs {
    server: Arc<Mutex<Server>>,
}

impl SelinuxFs {
    /// The filesystem over a server of its own: a test's.
    pub fn new(server: Arc<Mutex<Server>>) -> SelinuxFs {
        SelinuxFs { server }
    }

    /// The filesystem every mount of it is: over the kernel's server.
    pub fn of_kernel() -> SelinuxFs {
        SelinuxFs::new(crate::selinux::kernel_server())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Server> {
        self.server.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl FileSystem for SelinuxFs {
    fn fs_type(&self) -> &'static str {
        "selinuxfs"
    }

    fn magic(&self) -> u64 {
        MAGIC
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let s = self.lock();
        let Some(found) = find(&s, path) else {
            // Nothing is made here: the directories have no way to.
            let parent = path.rsplit_once('/').map_or("", |(dir, _)| dir);
            let makes = flags & crate::fs::oflags::O_CREAT != 0 && find(&s, parent).is_some_and(|p| p.kind == Kind::Dir);
            return Err(if makes { Errno::EACCES } else { Errno::ENOENT });
        };
        let metadata = found.metadata();
        match found.kind {
            Kind::Dir => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let parent = path.rsplit_once('/').map_or("", |(dir, _)| dir);
                let parent_ino = find(&s, parent).map_or(2, |p| p.ino);
                let mut entries = vec![
                    DirEntry { name: ".".into(), file_type: FileType::Directory, ino: found.ino },
                    DirEntry { name: "..".into(), file_type: FileType::Directory, ino: parent_ino },
                ];
                for name in names(&s, path) {
                    let child = if path.is_empty() { name.clone() } else { format!("{path}/{name}") };
                    if let Some(f) = find(&s, &child) {
                        entries.push(DirEntry { name, file_type: f.file_type(), ino: f.ino });
                    }
                }
                Ok(Arc::new(Dir { entries, metadata }))
            }
            Kind::Null => super::devices::open_char(makedev(1, 3), Arc::new(move || metadata.clone())),
            Kind::Missing => {
                eprintln!("[gex] selinuxfs: {path} is not implemented");
                Err(Errno::EOPNOTSUPP)
            }
            Kind::Root("policy") => {
                eprintln!("[gex] selinuxfs: policy (the loaded policy written out) is not implemented");
                Err(Errno::EOPNOTSUPP)
            }
            Kind::State | Kind::Root(_) => {
                // What a class's files read is theirs for good; a boolean
                // is the one at its place while that one has its name.
                let fixed = match path.strip_prefix("class/") {
                    Some(_) => Some(s.file(path).ok_or(Errno::ENOENT)?.1.map_err(errno)?),
                    None => None,
                };
                let boolean = path.strip_prefix("booleans/").and_then(|name| s.dir("booleans")?.iter().position(|b| b == name));
                Ok(Arc::new(File { server: Arc::clone(&self.server), path: path.to_string(), metadata, fixed, boolean }))
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        find(&self.lock(), path).map(|f| f.metadata()).ok_or(Errno::ENOENT)
    }

    // A directory here can have nothing made in it, taken from it or
    // moved: its inode has no such operations.
    fn unlink(&self, path: &str) -> Result<(), Errno> {
        self.metadata(path).and(Err(Errno::EPERM))
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

    fn rename(&self, from: &str, _to: &str) -> Result<(), Errno> {
        self.metadata(from).and(Err(Errno::EPERM))
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

/// A file, open.
struct File {
    server: Arc<Mutex<Server>>,
    path: String,
    metadata: Metadata,
    /// What it reads, where that never changes.
    fixed: Option<Vec<u8>>,
    /// For a boolean, its place among the booleans when it was opened.
    boolean: Option<usize>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "selinuxfs:{}", self.path)
    }
}

impl File {
    fn lock(&self) -> std::sync::MutexGuard<'_, Server> {
        self.server.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The whole of what it reads now.
    fn contents(&self) -> Result<Vec<u8>, Errno> {
        if let Some(fixed) = &self.fixed {
            return Ok(fixed.clone());
        }
        let s = self.lock();
        if let Some(at) = self.boolean {
            // Another policy's boolean at its place is not it.
            let name = self.path.strip_prefix("booleans/").unwrap_or("");
            if s.dir("booleans").and_then(|b| b.get(at).cloned()).as_deref() != Some(name) {
                return Err(Errno::EINVAL);
            }
        }
        match self.path.as_str() {
            "status" => Ok(s.status().iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<u8>>()[..STATUS_LEN].to_vec()),
            // Written to, not read: a file with no way to be read.
            "load" | "commit_pending_bools" | "disable" | "validatetrans" => Err(Errno::EINVAL),
            // The answer to a question, and none has been written.
            "context" | "access" | "create" | "relabel" | "member" | "user" => Ok(Vec::new()),
            path => s.file(path).ok_or(Errno::EINVAL)?.1.map_err(errno),
        }
    }
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        read_from(&self.contents()?, offset, buf)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        eprintln!("[gex] selinuxfs: writing {} is not implemented", self.path);
        Err(Errno::EOPNOTSUPP)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.metadata.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V33: &[u8] = include_bytes!("../selinux/testdata/test.33");

    fn fs() -> (SelinuxFs, Arc<Mutex<Server>>) {
        let server = Arc::new(Mutex::new(Server::default()));
        (SelinuxFs::new(Arc::clone(&server)), server)
    }

    fn read(fs: &SelinuxFs, path: &str) -> Result<Vec<u8>, Errno> {
        let h = fs.open(path, 0, 0)?;
        let mut buf = [0u8; 256];
        let n = h.read_at(0, &mut buf)? as usize;
        Ok(buf[..n].to_vec())
    }

    fn list(fs: &SelinuxFs, path: &str) -> Vec<String> {
        let mut names: Vec<String> = fs.open(path, 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
        names.sort();
        names
    }

    /// The tree before a policy, as Linux 6.8's was listed with SELinux on
    /// and nothing loaded: the names of the root, the directories a
    /// policy fills empty, and each file's mode and number as the
    /// reference gives them.
    #[test]
    fn before_a_policy_the_tree_is_a_kernels() {
        let (fs, _) = fs();
        assert_eq!((fs.fs_type(), fs.magic()), ("selinuxfs", 0xf97c_ff8c));
        assert_eq!(
            list(&fs, "").join(" "),
            "access avc booleans checkreqprot class commit_pending_bools context create deny_unknown disable enforce initial_contexts load member mls null policy \
             policy_capabilities policyvers reject_unknown relabel ss status user validatetrans"
        );
        assert_eq!(list(&fs, "class"), Vec::<String>::new());
        assert_eq!(list(&fs, "booleans"), Vec::<String>::new());
        assert_eq!(list(&fs, "initial_contexts").join(" "), "any_socket devnull file init kernel netif netmsg node port security unlabeled");
        assert_eq!(list(&fs, "avc").join(" "), "cache_stats cache_threshold hash_stats");
        assert_eq!(list(&fs, "ss"), ["sidtab_hash_stats"]);
        assert_eq!(list(&fs, "policy_capabilities").len(), 14);
        let stat = |path: &str| fs.metadata(path).map(|m| (m.file_type, m.mode, m.ino, m.nlink));
        assert_eq!(stat(""), Ok((FileType::Directory, 0o555, 2, 8)));
        assert_eq!(stat("load"), Ok((FileType::Regular, 0o600, 3, 1)));
        assert_eq!(stat("enforce"), Ok((FileType::Regular, 0o644, 4, 1)));
        assert_eq!(stat("access"), Ok((FileType::Regular, 0o666, 6, 1)));
        assert_eq!(stat("commit_pending_bools"), Ok((FileType::Regular, 0o200, 11, 1)));
        assert_eq!(stat("validatetrans"), Ok((FileType::Regular, 0o222, 21, 1)));
        assert_eq!(stat("booleans"), Ok((FileType::Directory, 0o555, 22, 2)));
        assert_eq!(stat("null"), Ok((FileType::CharDevice, 0o666, 23, 1)));
        assert_eq!(fs.metadata("null").unwrap().rdev, makedev(1, 3));
        assert_eq!(stat("avc/cache_threshold"), Ok((FileType::Regular, 0o644, 25, 1)));
        assert_eq!(stat("ss/sidtab_hash_stats"), Ok((FileType::Regular, 0o444, 29, 1)));
        assert_eq!(stat("class"), Ok((FileType::Directory, 0o555, 31, 2)));
        assert_eq!(stat("initial_contexts/kernel"), Ok((FileType::Regular, 0o444, 0x0100_0001, 1)));
        assert_eq!(stat("policy_capabilities/open_perms"), Ok((FileType::Regular, 0o444, 0x0800_0001, 1)));
        assert_eq!((stat("nothing"), stat("class/file"), stat("booleans/x"), stat("load/x")), (Err(Errno::ENOENT), Err(Errno::ENOENT), Err(Errno::ENOENT), Err(Errno::ENOENT)));
        // What they read.
        for (path, want) in [("enforce", "0"), ("policyvers", "35"), ("mls", "0"), ("deny_unknown", "1"), ("reject_unknown", "0"), ("checkreqprot", "0")] {
            assert_eq!(read(&fs, path).as_deref(), Ok(want.as_bytes()), "{path}");
        }
        assert_eq!(read(&fs, "initial_contexts/file").as_deref(), Ok(&b"file\0"[..]));
        assert_eq!(read(&fs, "initial_contexts/init").as_deref(), Ok(&b"kernel\0"[..]));
        // The status page's words: 1 0 0 0 1.
        assert_eq!(read(&fs, "status").unwrap(), [1u32, 0, 0, 0, 1].iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
        // A read that starts part way gets the rest, and past the end
        // nothing.
        let enforce = fs.open("enforce", 0, 0).unwrap();
        let mut one = [0u8; 4];
        assert_eq!((enforce.read_at(1, &mut one), enforce.read_at(9, &mut one)), (Ok(0), Ok(0)));
        // `null` is the null device.
        let null = fs.open("null", crate::fs::oflags::O_RDWR, 0).unwrap();
        assert_eq!((null.write_at(0, b"gone"), null.read_at(0, &mut one)), (Ok(4), Ok(0)));
    }

    /// With test.33 loaded: the directories the policy fills, numbered as
    /// the reference numbers them, and the files reading what the kernel
    /// that loaded it read (the security server's tests have the rest).
    #[test]
    fn with_a_policy_its_directories_are_filled() {
        let (fs, server) = fs();
        server.lock().unwrap().load(V33).unwrap();
        let classes = list(&fs, "class");
        assert!(classes.contains(&"file".to_string()) && classes.contains(&"binder".to_string()));
        assert_eq!(fs.metadata("class").unwrap().nlink, 2 + classes.len() as u32);
        assert_eq!(list(&fs, "class/file"), ["index", "perms"]);
        assert_eq!(list(&fs, "booleans"), ["allow_stuff", "other_thing"]);
        assert_eq!((read(&fs, "mls").as_deref(), read(&fs, "class/file/index").as_deref()), (Ok(&b"1"[..]), Ok(&b"2"[..])));
        assert_eq!((read(&fs, "class/file/perms/read").as_deref(), read(&fs, "class/file/perms/open").as_deref()), (Ok(&b"1"[..]), Ok(&b"7"[..])));
        assert_eq!(read(&fs, "initial_contexts/kernel").as_deref(), Ok(&b"system_u:system_r:kernel_t:s0\0"[..]));
        assert_eq!(read(&fs, "status").unwrap(), [1u32, 2, 0, 1, 1].iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
        // file is class 2: its index's number is the class's, a
        // permission's the permission's after it.
        let ino = |path: &str| fs.metadata(path).unwrap().ino;
        assert_eq!((ino("class/file/index"), ino("class/file/perms/read"), ino("class/file/perms/open")), (0x0400_0000 | 66, 0x0400_0000 | 67, 0x0400_0000 | 73));
        // The class directories are numbered after every class's files,
        // each and then its perms, in the policy's order of them.
        let n = classes.len() as u64;
        let first = server.lock().unwrap().dir("class").unwrap()[0].clone();
        assert_eq!(ino(&format!("class/{first}")), (0x0400_0000 | (n + 2) * 33) + 1);
        assert_eq!(ino(&format!("class/{first}/perms")), (0x0400_0000 | (n + 2) * 33) + 2);
        assert_eq!(fs.metadata("class/file").unwrap().nlink, 3);
        assert_eq!(ino("booleans/other_thing") & !0xff_ffff, 0x0200_0000);
        // An open class file keeps its number; an open boolean is not the
        // boolean another policy has at its place.
        let index = fs.open("class/binder/index", 0, 0).unwrap();
        let boolean = fs.open("booleans/allow_stuff", 0, 0).unwrap();
        let mut buf = [0u8; 16];
        let was = index.read_at(0, &mut buf).unwrap();
        let was = buf[..was as usize].to_vec();
        *server.lock().unwrap() = Server::default();
        let n = index.read_at(0, &mut buf).unwrap() as usize;
        assert_eq!(buf[..n], was[..]);
        assert_eq!(boolean.read_at(0, &mut buf), Err(Errno::EINVAL));
        assert_eq!(fs.metadata("class/binder").err(), Some(Errno::ENOENT));
    }

    /// Nothing is made, removed or moved here, and what is not here yet
    /// says so.
    #[test]
    fn the_tree_is_not_a_programs_to_change() {
        let (fs, _) = fs();
        let creat = crate::fs::oflags::O_CREAT | crate::fs::oflags::O_WRONLY;
        assert_eq!(fs.open("new", creat, 0o644).err(), Some(Errno::EACCES));
        assert_eq!(fs.open("class/new", creat, 0o644).err(), Some(Errno::EACCES));
        assert_eq!(fs.open("nothing/new", creat, 0o644).err(), Some(Errno::ENOENT));
        assert_eq!(fs.open("class", crate::fs::oflags::O_WRONLY, 0).err(), Some(Errno::EISDIR));
        assert_eq!((fs.unlink("enforce"), fs.unlink("nothing")), (Err(Errno::EPERM), Err(Errno::ENOENT)));
        assert_eq!((fs.mkdir("new", 0o755), fs.mkdir("class", 0o755)), (Err(Errno::EPERM), Err(Errno::EEXIST)));
        assert_eq!((fs.rmdir("class"), fs.rmdir("enforce")), (Err(Errno::EPERM), Err(Errno::ENOTDIR)));
        assert_eq!(fs.rename("enforce", "other"), Err(Errno::EPERM));
        assert_eq!(fs.open("policy", 0, 0).err(), Some(Errno::EOPNOTSUPP));
        assert_eq!(fs.open("avc/hash_stats", 0, 0).err(), Some(Errno::EOPNOTSUPP));
    }
}
