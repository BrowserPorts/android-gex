//! The virtual filesystem: a mount table over pluggable backends.
//!
//! The [`FileSystem`] trait is the seam every backend fits into; paths are
//! resolved against the mount table by longest prefix, so a guest sees one
//! namespace regardless of which backend answers.

use crate::errno::{Errno, SysResult};
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod binderfs;
pub mod bpffs;
pub mod cgroupfs;
pub mod cgroup1fs;
pub mod devfs;
pub mod devices;
pub mod evdev;
pub mod ext4;
pub mod hostcall;
// Passthrough to the host's own filesystem; the browser gets `opfs`/`httpfs`
// instead.
#[cfg(unix)]
pub mod hostfs;
pub mod kmsg;
pub mod mounted;
pub mod oss;
pub mod peimage;
pub mod procfs;
/// The filesystem when it is not in this process's memory.
pub mod remote;
pub mod blocks;
pub mod selinuxfs;
pub mod subtree;
pub mod sysfs;
pub mod tmpfs;

pub use binderfs::BinderFs;
pub use bpffs::BpfFs;
pub use devfs::DevFs;
#[cfg(unix)]
pub use hostfs::HostFs;
pub use procfs::{ProcFs, ProcSource, SysCpuFs};
pub use remote::RemoteFs;
pub use selinuxfs::SelinuxFs;
pub use sysfs::SysFs;
pub use tmpfs::TmpFs;

/// What kind of thing a directory entry names.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl FileType {
    /// The `st_mode` type bits.
    pub fn mode_bits(self) -> u32 {
        match self {
            FileType::Regular => 0o100000,
            FileType::Directory => 0o040000,
            FileType::Symlink => 0o120000,
            FileType::CharDevice => 0o020000,
            FileType::BlockDevice => 0o060000,
            FileType::Fifo => 0o010000,
            FileType::Socket => 0o140000,
        }
    }
    /// The `d_type` byte in a `getdents64` record.
    pub fn dirent_type(self) -> u8 {
        match self {
            FileType::Fifo => 1,
            FileType::CharDevice => 2,
            FileType::Directory => 4,
            FileType::BlockDevice => 6,
            FileType::Regular => 8,
            FileType::Symlink => 10,
            FileType::Socket => 12,
        }
    }
}

/// An inode number for an object no file system holds (a pipe, a socket,
/// the host's stdio): unique among live objects, from the object's address,
/// in a range no file system's inodes reach. Programs compare (dev, ino) to
/// tell files apart -- GNU grep takes an output that matches /dev/null's for
/// /dev/null and prints nothing -- so these must not all be 1.
pub fn anon_ino(p: *const u8) -> u64 {
    (1 << 62) | (p as usize as u64 >> 3)
}

/// What a filesystem with no device behind it is numbered by
/// ([`anon_dev`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DevKey {
    /// One mounted instance, by where it is in memory.
    Instance(usize),
    /// The one filesystem of its kind: proc, sysfs, the pipes'.
    Kind(&'static str),
    /// A tree of the host's, by the host's own number for the filesystem
    /// it is on: two views of one host tree are one filesystem.
    Host(u64),
}

/// The device number of a filesystem with no device behind it
/// (`get_anon_bdev`): major 0 and a minor of its own, from 1, the same
/// one every time it is asked for. A file's `st_dev` is its filesystem's
/// number, and programs take two files of one `st_dev` and `st_ino` for
/// one file: bionic's linker takes a library it is asked for as loaded
/// already when a loaded one has both, and the libraries of two APEXes,
/// each an ext4 of its own with inodes counted from 11, would be one
/// another's if every filesystem said 0.
pub fn anon_dev(key: DevKey) -> u64 {
    static TABLE: std::sync::Mutex<Option<std::collections::HashMap<DevKey, u32>>> = std::sync::Mutex::new(None);
    let mut t = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let t = t.get_or_insert_with(Default::default);
    let next = t.len() as u32 + 1;
    devices::makedev(0, *t.entry(key).or_insert(next))
}

/// Metadata about a path, independent of any open file.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub file_type: FileType,
    pub size: u64,
    pub mode: u32,
    pub ino: u64,
    pub mtime: i64,
    /// Hard-link count, reported as `st_nlink`. A file with one name is 1; a
    /// directory is `2 + immediate subdirectories`.
    pub nlink: u32,
    /// `st_rdev`: the device a character or block device node names, in
    /// Linux's `makedev` encoding. Zero where the node does not say; `stat`
    /// then reports a character device as a pseudo-terminal (136:0).
    pub rdev: u64,
    /// The device of the host's filesystem a host file is on (its own
    /// `st_dev`), where a filesystem's files are not all on one: a host
    /// tree holds the host's other filesystems at their mount points. Zero
    /// for every other file: its `st_dev` is its filesystem's
    /// ([`FileSystem::dev`]).
    pub dev: u64,
    /// The other times and the nanoseconds, where the filesystem keeps
    /// them (the host's). All zero: every time is `mtime`, whole seconds.
    pub times: Times,
    /// Its owner, user and group, where the filesystem keeps one (a
    /// tmpfs, an ext4). `None` where it keeps none: `stat` then says the
    /// caller's own ids, as it always did, so a program that compares a
    /// file's owner with itself sees itself.
    pub owner: Option<(u32, u32)>,
}

/// `st_atim`, `st_ctim` and the nanoseconds of `st_mtim`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {
    pub mtime_ns: u32,
    pub atime: i64,
    pub atime_ns: u32,
    pub ctime: i64,
    pub ctime_ns: u32,
}

impl Metadata {
    pub fn regular(size: u64) -> Metadata {
        Metadata {
            file_type: FileType::Regular,
            size,
            mode: 0o644,
            ino: 1,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            dev: 0,
            times: Default::default(),
            owner: None,
        }
    }
    pub fn dir() -> Metadata {
        Metadata {
            file_type: FileType::Directory,
            size: 4096,
            mode: 0o755,
            ino: 1,
            mtime: 0,
            nlink: 2,
            rdev: 0,
            dev: 0,
            times: Default::default(),
            owner: None,
        }
    }
}

/// One directory entry.
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
    pub ino: u64,
}

/// An open file's backing object.
///
/// Handles are reference-counted so `dup` and `fork` can share one open-file
/// description, which is what makes a shared file offset behave correctly.
/// `POSIX_FADV_WILLNEED`.
pub const FADV_WILLNEED: u32 = 3;
/// gex's own `posix_fadvise` advice: fetch now the parts of a PE image the
/// wineserver reads when it makes an image mapping of it (its headers, the
/// export name, the version resource, the CLR and load-config headers, the
/// shared sections: server/mapping.c `get_image_params`), so that its read
/// inside a door call never waits on the network (`offset`, `len` unused).
/// A Wine client advises this before `create_mapping` (ntdll's `NtCreateSection`).
pub const FADV_GEX_IMAGE: u32 = 0x4745_0001;

/// One extended-attribute call (`getxattr` and its kin), path or handle.
/// Names are whole (`user.foo`); only the `user.` namespace is kept
/// ([`xattr_name`]). Every form answers a byte count.
#[derive(Debug)]
pub enum XattrOp<'a> {
    /// The value into `buf`, or its size when `buf` is empty; `ENODATA`
    /// for an attribute that is not there, `ERANGE` when `buf` is short.
    Get { name: &'a str, buf: &'a mut [u8] },
    /// `flags`: `XATTR_CREATE` (1, `EEXIST` if it is there) and
    /// `XATTR_REPLACE` (2, `ENODATA` if it is not).
    Set { name: &'a str, value: &'a [u8], flags: u32 },
    /// Every name, each NUL-terminated, into `buf` (or the size, as `Get`).
    List { buf: &'a mut [u8] },
    /// `ENODATA` if it is not there.
    Remove { name: &'a str },
}

/// `XATTR_CREATE` and `XATTR_REPLACE`.
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;
/// Linux's limits: a name of at most 255 bytes, a value of at most 64 KiB.
pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;

/// Check an attribute name: `ERANGE` past [`XATTR_NAME_MAX`] or empty, and
/// `EOPNOTSUPP` outside `user.` (the trusted, security and system
/// namespaces are the kernel's own, which a tmpfs here does not model).
pub fn xattr_name(name: &str) -> Result<(), Errno> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(Errno::ERANGE);
    }
    if !name.starts_with("user.") || name.len() == 5 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

/// [`xattr_name`] for a filesystem that keeps its attributes in memory, as
/// Linux's tmpfs does: the `security.` namespace is kept as well as
/// `user.` (a file's SELinux label is `security.selinux`; who may set one
/// is the system call's to say).
fn xattr_name_in_memory(name: &str) -> Result<(), Errno> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(Errno::ERANGE);
    }
    if name.strip_prefix("user.").or(name.strip_prefix("security.")).is_none_or(str::is_empty) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

/// One node's attributes, kept by a filesystem: the work every
/// [`XattrOp`] does on them.
pub fn xattr_apply(attrs: &mut std::collections::BTreeMap<String, Vec<u8>>, op: XattrOp<'_>) -> Result<usize, Errno> {
    fn out(buf: &mut [u8], bytes: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(bytes.len());
        }
        if buf.len() < bytes.len() {
            return Err(Errno::ERANGE);
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    match op {
        XattrOp::Get { name, buf } => {
            xattr_name_in_memory(name).map_err(|e| if e == Errno::EOPNOTSUPP { Errno::ENODATA } else { e })?;
            let v = attrs.get(name).ok_or(Errno::ENODATA)?;
            out(buf, v)
        }
        XattrOp::Set { name, value, flags } => {
            xattr_name_in_memory(name)?;
            if value.len() > XATTR_SIZE_MAX {
                return Err(Errno::E2BIG);
            }
            let there = attrs.contains_key(name);
            if flags & XATTR_CREATE != 0 && there {
                return Err(Errno::EEXIST);
            }
            if flags & XATTR_REPLACE != 0 && !there {
                return Err(Errno::ENODATA);
            }
            attrs.insert(name.to_string(), value.to_vec());
            Ok(0)
        }
        XattrOp::List { buf } => {
            let mut all = Vec::new();
            for k in attrs.keys() {
                all.extend_from_slice(k.as_bytes());
                all.push(0);
            }
            out(buf, &all)
        }
        XattrOp::Remove { name } => {
            xattr_name_in_memory(name).map_err(|e| if e == Errno::EOPNOTSUPP { Errno::ENODATA } else { e })?;
            attrs.remove(name).map(|_| 0).ok_or(Errno::ENODATA)
        }
    }
}

pub trait FileHandle: Send + Sync + std::fmt::Debug {
    /// Read at `offset`, returning the bytes read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult;
    /// Write at `offset`.
    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        let _ = (offset, buf);
        Err(Errno::EBADF)
    }
    /// True when a write leaves the file's position where it was: a file
    /// whose write is a command to the kernel and no contents (selinuxfs's),
    /// which is written again from the start.
    fn write_keeps_position(&self) -> bool {
        false
    }
    fn metadata(&self) -> Result<Metadata, Errno>;
    /// How many times the file's contents have changed, as the filesystem
    /// holding them counts, or 0 where it keeps no count. Two equal nonzero
    /// counts are the same contents: every change is counted before anyone
    /// can read what it wrote.
    fn changes(&self) -> u64 {
        0
    }
    /// [`FileHandle::metadata`] and [`FileHandle::changes`] together, which
    /// a filesystem in another module answers in one call.
    fn metadata_changes(&self) -> Result<(Metadata, u64), Errno> {
        Ok((self.metadata()?, self.changes()))
    }
    /// [`FileHandle::read_at`] handing `f` the bytes where they are, for a
    /// caller that copies them on (the global kernel into a process's
    /// memory) rather than into a buffer of its own first. `None` where the
    /// filesystem has them nowhere to hand over.
    fn read_with(&self, offset: u64, len: usize, f: &mut dyn FnMut(&[u8])) -> Option<SysResult> {
        let _ = (offset, len, f);
        None
    }
    /// The id this handle has in the global kernel, when it has one. `fork`
    /// hands the child an id rather than a path, because a file the parent
    /// created and unlinked (as dpkg-deb does) has no name left to reopen.
    fn remote_id(&self) -> Option<i32> {
        None
    }
    /// Where a directory opened here is now, for a descriptor that relative
    /// paths resolve through (`openat(dirfd, ...)`, `fchdir`), or `ENOENT`
    /// once it is removed. Linux resolves such a descriptor by the
    /// directory, not by its name, so it follows a rename of the directory
    /// or of any directory above it. `None` for a handle that does not
    /// follow its node: its recorded path stands.
    fn moved(&self) -> Option<Result<Moved, Errno>> {
        None
    }
    /// How many directories this handle's filesystem has renamed or removed, read
    /// without a lock: while it stays the same, a directory's path found
    /// by [`FileHandle::moved`] still stands (a working directory keeps its
    /// path this way, `FsCwd`). `None` for a filesystem that does not count.
    fn rename_epoch(&self) -> Option<u64> {
        None
    }
    /// The count of the renames of directories made through this handle's
    /// filesystem by gex itself, where [`FileHandle::rename_epoch`] cannot
    /// count every rename (a host directory: the host's own are not seen).
    /// While it stays the same, a directory's path found by
    /// [`FileHandle::moved`] stands as far as gex can tell
    /// (`FsCwd::get_call`).
    fn own_rename_epoch(&self) -> Option<u64> {
        self.rename_epoch()
    }
    /// Hold off the renames of directories on this handle's filesystem
    /// (`on`), or let them go again, for process `owner`: its rename lock,
    /// taken shared. What a lookup through a directory descriptor that kept
    /// racing renames falls back to, as Linux's walk falls back to
    /// `rename_lock` (`PathIo::call`). Whether the filesystem has one.
    fn hold_renames(&self, owner: i32, on: bool) -> bool {
        let _ = (owner, on);
        false
    }
    /// List a directory. Only directories implement this.
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Err(Errno::ENOTDIR)
    }
    /// Set the modification time of what this handle is open on. A handle
    /// onto something that keeps no times accepts it and does nothing.
    fn set_mtime(&self, _secs: i64) -> Result<(), Errno> {
        Ok(())
    }
    /// `futimens`: [`FileSystem::set_times`] on an open file.
    fn set_times(&self, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        let _ = atime;
        match mtime {
            Some((secs, _)) => self.set_mtime(secs),
            None => Ok(()),
        }
    }
    /// [`FileHandle::set_times`] with the change time given (`now`, whole
    /// seconds): for a module with no clock of its own -- the global kernel,
    /// told the time by the process that asked.
    fn set_times_now(&self, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>, now: i64) -> Result<(), Errno> {
        let _ = now;
        self.set_times(atime, mtime)
    }
    fn truncate(&self, len: u64) -> Result<(), Errno> {
        let _ = len;
        Err(Errno::EINVAL)
    }
    /// `posix_fadvise`: `advice` is `POSIX_FADV_*` or [`FADV_GEX_IMAGE`]. A
    /// file whose bytes are all here has nothing to do; a lazy one
    /// ([`tmpfs::TmpFs::add_lazy`]) fetches what is asked now, so that a later
    /// read of it waits on nothing.
    fn advise(&self, offset: u64, len: u64, advice: u32) -> Result<(), Errno> {
        let _ = (offset, len, advice);
        Ok(())
    }
    /// `fsync` and `fdatasync`: what was written through any handle on this
    /// file made durable, its size and name with it; `data_only`
    /// (`sync_file_range`): its bytes only. A file whose bytes are only in
    /// memory has nothing to do.
    fn sync(&self, data_only: bool) -> Result<(), Errno> {
        let _ = data_only;
        Ok(())
    }
    /// `fchmod` on what this handle is open on, when the handle can do it
    /// itself; `None` sends the caller to [`FileSystem::chmod`] by name.
    fn chmod(&self, mode: u32) -> Option<Result<(), Errno>> {
        let _ = mode;
        None
    }

    /// `fchown` of the open file itself, wherever its name has gone;
    /// `None` where the handle's filesystem keeps no owner, and the call
    /// is taken without effect.
    fn chown(&self, uid: Option<u32>, gid: Option<u32>) -> Option<Result<(), Errno>> {
        let _ = (uid, gid);
        None
    }

    /// The device number (`st_dev`) of an object no path leads to, which
    /// is its kind's filesystem's: the anonymous inodes' for anything
    /// that does not say (an eventfd, an epoll), the pipes' for a pipe,
    /// the sockets' for a socket. A file opened by a path has the number
    /// of the filesystem the path led to, and is not asked.
    fn fs_dev(&self) -> u64 {
        anon_dev(DevKey::Kind("anon_inodefs"))
    }

    /// An extended-attribute call on the open file itself (`fgetxattr` and
    /// its kin); `None` where the handle has no node of its own to keep
    /// them on, and the caller goes by its path.
    fn xattr(&self, op: XattrOp<'_>) -> Option<Result<usize, Errno>> {
        let _ = op;
        None
    }
    /// True when reads and writes ignore the offset, as for a terminal or
    /// pipe. Such files also report `ESPIPE` from `lseek`.
    fn is_stream(&self) -> bool {
        false
    }
    /// True when each write is a record of its own (a `SOCK_SEQPACKET`
    /// socket): a `writev` is one write of all its vectors, whatever its
    /// length, as Linux's one `sendmsg` is one record.
    fn keeps_records(&self) -> bool {
        false
    }
    /// `lseek` on a handle that keeps its own offset (a standard stream
    /// redirected from a host file: the offset is the host descriptor's).
    /// `None`: the open-file description's offset, or `ESPIPE` for a stream.
    fn seek(&self, _offset: i64, _whence: u32) -> Option<SysResult> {
        None
    }
    /// True when the file should behave like a terminal for `ioctl`.
    fn is_tty(&self) -> bool {
        false
    }
    /// Whether a blocking read with nothing to read returns 0 at once instead
    /// of waiting: a terminal in non-canonical mode with `VMIN` and `VTIME`
    /// both 0 (termios(3)'s "polling read"). A non-blocking descriptor still
    /// gets `EAGAIN`, as on Linux.
    fn empty_read_returns(&self) -> bool {
        false
    }
    /// Whether a read would return without waiting. Only streams that can be
    /// empty answer no; a file never waits. Asked *before* the read so an
    /// `O_NONBLOCK` descriptor still sees its own `EAGAIN`.
    fn poll_readable(&self) -> bool {
        true
    }

    /// How many bytes a read would return now, for `FIONREAD`. `None` means
    /// "work it out from size and offset", right for a file but no answer for
    /// a socket -- glibc's resolver sizes its datagram buffer by this.
    fn available(&self) -> Option<u64> {
        None
    }

    /// Whether a write would make progress without waiting. Only a stream
    /// that can fill up answers no.
    fn poll_writable(&self) -> bool {
        true
    }

    /// What `poll` says as `POLLIN`: that there is something to read.
    /// [`Self::poll_readable`], unless the two differ: a pseudoterminal's
    /// master whose other end has closed lets a reader through (to its
    /// `EIO`) and says `POLLHUP` alone.
    fn poll_in(&self) -> bool {
        self.poll_readable()
    }

    /// What `poll` says as `POLLOUT`: [`Self::poll_writable`], unless a
    /// write that never waits is still not something `poll` reports (a BPF
    /// map's, which is `EINVAL`).
    fn poll_out(&self) -> bool {
        self.poll_writable()
    }

    /// Whether the other end has hung up: a pipe with no writers left, a
    /// stream socket shut down in both directions (its peer closed).
    /// `poll` and `epoll` report `POLLHUP` for it whether or not it was
    /// asked for, as Linux does; a server learns that a client died this way.
    fn poll_hup(&self) -> bool {
        false
    }

    /// The wait queue a change in this handle's readiness is announced on
    /// ([`crate::wait`]): a thread waiting for it registers its wait slot
    /// there. 0 for a handle whose readiness no event changes (a file is
    /// always ready; a timer becomes ready by the clock, [`Self::ready_in_ns`]).
    fn wait_queue(&self) -> u32 {
        0
    }

    /// A count that moves at every wakeup of this handle's object (each
    /// notify of its [`Self::wait_queue`]): an edge-triggered epoll watch
    /// (`EPOLLET`) reports again when it has moved, as Linux's does at each
    /// wakeup of the file. A file or directory never wakes: always ready, it
    /// is reported once. `None` where this kernel cannot see the count (an
    /// object another kernel holds): such a watch answers as a
    /// level-triggered one.
    fn wakes(&self) -> Option<u64> {
        match self.metadata() {
            Ok(md) if matches!(md.file_type, FileType::Regular | FileType::Directory) => Some(0),
            _ => None,
        }
    }

    /// An exceptional condition to report (`POLLPRI`, with `POLLERR`, which
    /// is never masked): what `/proc/self/mountinfo` says after a mount
    /// changed.
    fn poll_pri(&self) -> bool {
        false
    }

    /// An error to report (`POLLERR`, never masked) and nothing else: a
    /// BPF map that has no readiness of its own (`bpf_map_poll`).
    fn poll_err(&self) -> bool {
        false
    }

    /// A poll or epoll wait has just reported `revents` for this handle to
    /// its caller: a condition reported once ([`Self::poll_pri`]) is spent.
    fn poll_reported(&self, revents: u16) {
        let _ = revents;
    }

    /// How long until this handle becomes ready by the clock alone (a
    /// timerfd's next expiry, a sound device draining its buffer), for a
    /// waiter to bound its park by. `None` when only an event makes it ready.
    fn ready_in_ns(&self) -> Option<u64> {
        None
    }

    /// Whether the peer has shut its sending side, so reading ends at EOF
    /// once the buffer is empty: `POLLRDHUP` / `EPOLLRDHUP`, reported only
    /// when asked for.
    fn poll_rdhup(&self) -> bool {
        false
    }

    /// This handle as a unix socket, when it is one: the syscalls that need
    /// the concrete type (descriptor passing, `listen`, `accept`) recover it
    /// from the handle, whichever process made it.
    /// The BPF object a descriptor is (a map, from `bpf(2)`), for
    /// `BPF_OBJ_PIN` and the element calls; `None` for any other.
    fn bpf_object(&self) -> Option<crate::bpf::Object> {
        None
    }

    /// The control group a cgroup2 directory is ([`crate::cgroup`]), for
    /// `BPF_PROG_ATTACH` and its kin, which name one by an open directory.
    fn cgroup(&self) -> Option<u64> {
        None
    }

    /// For a BPF object's descriptor: whether it may be read and written
    /// (`BPF_OBJ_GET` with `BPF_F_RDONLY` or `BPF_F_WRONLY`).
    fn bpf_access(&self) -> Option<(bool, bool)> {
        None
    }

    fn as_unix_socket(self: Arc<Self>) -> Option<Arc<crate::unix::UnixSocket>> {
        None
    }

    /// This handle as a unix datagram socket, when it is one.
    fn as_unix_dgram(self: Arc<Self>) -> Option<Arc<crate::unix::UnixDgram>> {
        None
    }

    /// This handle as a unix socket in the global kernel, when it is one.
    fn as_remote_unix(self: Arc<Self>) -> Option<Arc<crate::unix::RemoteUnix>> {
        None
    }

    /// This handle as an internet socket, when it is one.
    fn as_inet_socket(self: Arc<Self>) -> Option<Arc<crate::net::Socket>> {
        None
    }

    /// This handle as the device-mapper's control, when it is that.
    fn as_dm(self: Arc<Self>) -> Option<Arc<crate::dm::Control>> {
        None
    }

    /// This handle as an open block device, when it is one.
    fn as_block(self: Arc<Self>) -> Option<Arc<crate::block::BlockFile>> {
        None
    }

    /// The size of the device behind this handle, when it is a block
    /// device: where `lseek` to the end goes, which `fstat`'s size (0 for
    /// a device) does not say.
    fn device_size(&self) -> Option<u64> {
        None
    }

    /// This handle as a netlink socket, when it is one.
    /// A raw internet socket's family and protocol (`crate::xtables`).
    fn raw_socket(&self) -> Option<(crate::xtables::Family, u32)> {
        None
    }

    fn as_netlink(self: Arc<Self>) -> Option<Arc<crate::netlink::Socket>> {
        None
    }

    /// This handle as an epoll set, when it is one: `epoll_ctl` and
    /// `epoll_pwait` recover the set from the descriptor's handle, with or
    /// without the kernel.
    fn as_epoll(self: Arc<Self>) -> Option<Arc<crate::unix::EpollSet>> {
        None
    }

    /// The process a process descriptor names (`crate::pidfd`), when this
    /// handle is one.
    fn pidfd(&self) -> Option<i32> {
        None
    }

    /// This handle as an anonymous shared file (`memfd_create`), when it is
    /// one: its seals and `fallocate`.
    /// An `inotify` instance's descriptor ([`crate::inotify::Inotify`]).
    fn as_inotify(self: Arc<Self>) -> Option<Arc<crate::inotify::Inotify>> {
        None
    }
    fn as_memfd(self: Arc<Self>) -> Option<Arc<crate::unix::MemFd>> {
        None
    }
    /// A signalfd, whose mask `signalfd4` on it changes.
    fn as_signalfd(self: Arc<Self>) -> Option<Arc<crate::signalfd::SignalFd>> {
        None
    }
    /// A mount namespace, open as the file `/proc/<pid>/ns/mnt` is:
    /// what `setns` enters.
    fn as_mount_ns(self: Arc<Self>) -> Option<Arc<MountNs>> {
        None
    }
    /// An open of a binder device, whose ioctls need to know their caller
    /// and may wait ([`crate::binder::BinderFile::ioctl`]).
    fn as_binder(self: Arc<Self>) -> Option<Arc<crate::binder::BinderFile>> {
        None
    }

    /// A short description of this handle's state, for a diagnostic: the
    /// buffer behind a descriptor -- empty, full, which way it points -- that
    /// the fd number and path cannot show.
    fn debug_state(&self) -> String {
        String::new()
    }

    /// An `ioctl` this handle answers itself. `None` means "not mine" and the
    /// kernel's own handling runs. Guest memory is passed because an ioctl arg
    /// is usually a pointer to a struct the device reads or writes -- and a
    /// host device reaches the caller's buffers through it uncopied.
    /// A session has claimed this file as its controlling terminal.
    ///
    /// `TIOCSCTTY` on a *local* tty is handled at the syscall layer, which has
    /// the process table and can record the session there. A pty in the global
    /// kernel cannot be reached that way -- its state is in another module --
    /// so the syscall layer hands the session down here instead. Nothing else
    /// needs it, hence the default.
    fn claim_session(&self, _sid: i32) {}

    /// The session a terminal of the global kernel's is the controlling
    /// terminal of, 0 for none; `None` for anything that is not one.
    /// Asked before [`Self::claim_session`]: a terminal a living session
    /// has is not another's to claim.
    fn session(&self) -> Option<i32> {
        None
    }

    /// The pts number of a pseudoterminal's master: what `TIOCGPTPEER`
    /// opens the slave of. The syscall layer opens it, as only it installs
    /// descriptors. `None` for anything else.
    fn pty_peer(&self) -> Option<i32> {
        None
    }

    /// Whether another *process* is what ends a wait on this handle, rather
    /// than the host.
    ///
    /// A host with one thread per process has to know the difference. A guest
    /// waiting for a pipe, a unix socket or the far end of a pseudoterminal is
    /// waiting for a program that runs elsewhere and will say so when it gets
    /// there; a guest waiting for a keystroke, or for bytes off a socket the
    /// host owns, is waiting for the host to do something -- and a host that is
    /// inside this guest's syscall is not doing it. Answer `true` and the
    /// browser shim sleeps on the shared wake word; answer `false` and it hands
    /// the page its event loop back.
    ///
    /// Pipes and sockets are recognised by their file type. A pseudoterminal is
    /// not: it looks exactly like the terminal a person types into, and the two
    /// want opposite answers, so it says which it is here.
    fn peer_wakes(&self) -> bool {
        false
    }

    /// Whether this is a socket in the global kernel (`unix::RemoteUnix`):
    /// what a host asks of a parked thread's handle without the kernel.
    fn is_global_socket(&self) -> bool {
        false
    }

    /// Whether a read on this handle, made now, can end nobody's wait. Asked
    /// *before* the read, of a stream only (a read of anything else never
    /// ends a wait). A read ends a writer's wait by making room, and a writer
    /// parks only when there is none, so a stream that knows it has room
    /// says so here and the read is not followed by a wake of every parked
    /// Worker. `false`, "it might", is always safe.
    fn read_frees_nothing(&self) -> bool {
        false
    }

    fn ioctl(&self, m: &mut crate::GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        let _ = (m, request, arg);
        None
    }

    /// Whether a mapping of this file is the device's own memory (an OSS
    /// DMA buffer) rather than a copy of its contents: fresh zeroed pages,
    /// never read from the file or written back to it, whose place the
    /// device is told ([`FileHandle::mapped`]).
    fn maps_own_memory(&self) -> bool {
        false
    }

    /// Whether the file may be mapped so: `len` bytes (whole pages) from
    /// `offset` with protection `prot`, shared or private. A file that is
    /// a page of the kernel's lets only that page be mapped, and not for
    /// writing; one with no mapping at all is `ENODEV`.
    fn may_map(&self, offset: u64, len: u64, prot: u32, shared: bool) -> Result<(), Errno> {
        let _ = (offset, len, prot, shared);
        Ok(())
    }

    /// What a mapping of the file holds for as long as it (or a forked
    /// child's copy of it) lasts, asked after [`FileHandle::may_map`]: a
    /// BPF map counts its writable mappings so (`bpf_map_write_active`).
    /// An error refuses the mapping.
    fn map_hold(&self, prot: u32, shared: bool) -> Result<Option<Arc<dyn std::any::Any + Send + Sync>>, Errno> {
        let _ = (prot, shared);
        Ok(None)
    }

    /// Whether a mapping made without writing may be made writable later.
    /// No for a file whose mapping the kernel keeps read-only once it is
    /// (`VM_MAYWRITE` cleared at the mapping: a BPF map, selinuxfs's
    /// status page).
    fn read_only_mapping_stays(&self) -> bool {
        false
    }

    /// What a mapping of the file holds at `offset`, where that is not
    /// what `read` gives (a BPF ring buffer, which `read` refuses).
    fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        self.read_at(offset, buf)
    }

    /// What a shared mapping writes back, where that is not a `write`.
    fn write_mapped(&self, offset: u64, buf: &[u8]) -> SysResult {
        self.write_at(offset, buf)
    }

    /// How much of the file a mapping holds, for a file whose size does
    /// not say: one that reads more than its size of 0 (selinuxfs's
    /// `status`). `None`: its size.
    fn mapped_len(&self) -> Option<u64> {
        None
    }

    /// Where a mapping of the device's own memory landed, and its length.
    fn mapped(&self, start: u64, len: u64) {
        let _ = (start, len);
    }

    /// A pipe's capacity in bytes (`F_GETPIPE_SZ`). `None` for anything that
    /// is not a pipe.
    fn pipe_capacity(&self) -> Option<u64> {
        None
    }

    /// `F_SETPIPE_SZ` ([`crate::pipe::Pipe::set_capacity`]). `EBADF` for
    /// anything that is not a pipe, as Linux.
    fn set_pipe_capacity(&self, arg: u32, privileged: bool) -> SysResult {
        let _ = (arg, privileged);
        Err(Errno::EBADF)
    }

    /// How many bytes a write can take now, when bounded. `None` means it is
    /// not (file, terminal, socket). A pipe is bounded, and a blocking write
    /// larger than its free space is carried to completion by the syscall layer.
    fn write_room(&self) -> Option<u64> {
        None
    }

    /// Arm or disarm a `timerfd`, returning the previous `(remaining, interval)`
    /// in nanoseconds. `None` means this handle is not a timerfd, which the
    /// `timerfd_settime` syscall reports as `EINVAL`.
    fn timerfd_set(&self, value_ns: u64, interval_ns: u64, flags: u64) -> Option<Result<(u64, u64), Errno>> {
        let _ = (value_ns, interval_ns, flags);
        None
    }

    /// The current `(remaining, interval)` in nanoseconds of a `timerfd`, or
    /// `None` when this handle is not one.
    fn timerfd_get(&self) -> Option<(u64, u64)> {
        None
    }
}

/// A descriptor that names a file without opening it: `O_PATH`. Answers
/// `fstat`, carries its path for `*at` calls, refuses the rest. Legal on
/// things an ordinary open is not, e.g. a dangling symlink.
#[derive(Debug)]
pub struct PathHandle(pub Metadata);

impl FileHandle for PathHandle {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EBADF)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EBADF)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.0.clone())
    }
}

static SYNC_ALL: std::sync::OnceLock<fn() -> Result<(), Errno>> = std::sync::OnceLock::new();

/// Where `sync(2)` and `syncfs` go: the filesystem whose contents are kept
/// away from this memory (the global kernel's block store,
/// [`blocks::sync_all`], or a process's way to it). The first call wins;
/// without one there is nothing to flush.
pub fn set_sync_all(f: fn() -> Result<(), Errno>) {
    let _ = SYNC_ALL.set(f);
}

/// `sync(2)`: everything written made durable ([`set_sync_all`]).
pub fn sync_all() -> Result<(), Errno> {
    SYNC_ALL.get().map_or(Ok(()), |f| f())
}

static OWNER_ALIVE: std::sync::OnceLock<fn(i32) -> bool> = std::sync::OnceLock::new();

/// How a filesystem shared by several processes tells whether the process
/// holding its directory renames off is still there
/// ([`FileHandle::hold_renames`]): one that ended without letting go holds
/// nothing. The first call wins; without one every holder is.
pub fn set_owner_alive(alive: fn(i32) -> bool) {
    let _ = OWNER_ALIVE.set(alive);
}

thread_local! {
    /// The holds this thread has taken: a rename it makes itself does not
    /// wait for them. Counted by the caller of `hold_renames` (`PathIo`),
    /// on its own thread: the global kernel's thread-locals are not one per
    /// thread of the process calling it, so a remote rename carries the
    /// count with it.
    static OWN_HOLDS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// The holds the calling thread has taken ([`FileHandle::hold_renames`]).
pub fn own_holds() -> u32 {
    OWN_HOLDS.with(|h| h.get())
}

/// The calling thread took a hold (`on`) or let one go.
pub fn note_own_hold(on: bool) {
    OWN_HOLDS.with(|h| h.set(if on { h.get() + 1 } else { h.get().saturating_sub(1) }));
}

/// A filesystem's rename lock (Linux's `rename_lock`, per filesystem): the
/// count of its directories renamed or removed, read without a lock
/// ([`FileHandle::rename_epoch`]), and the lookups holding directory renames
/// off, by process ([`FileHandle::hold_renames`]). A directory rename runs
/// in [`RenameGate::rename`], which waits while another thread holds, and a
/// hold waits for a rename under way.
#[derive(Debug, Default)]
pub struct RenameGate {
    renamed: std::sync::atomic::AtomicU64,
    holds: std::sync::Mutex<std::collections::BTreeMap<i32, u32>>,
}

impl RenameGate {
    pub fn epoch(&self) -> u64 {
        self.renamed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// A directory renamed or removed.
    pub fn bump(&self) {
        self.renamed.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<i32, u32>> {
        self.holds.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// [`FileHandle::hold_renames`].
    pub fn hold(&self, owner: i32, on: bool) {
        let mut holds = self.lock();
        if on {
            *holds.entry(owner).or_insert(0) += 1;
        } else if let Some(n) = holds.get_mut(&owner) {
            *n -= 1;
            if *n == 0 {
                holds.remove(&owner);
            }
        }
    }

    /// Run `f`, a directory rename (`dir`) or another, once no thread but
    /// the caller, which holds `own`, holds directory renames off: a
    /// lookup's few calls, made after it raced renames many times over. A
    /// rename that moved a directory counts ([`RenameGate::epoch`]).
    pub fn rename<T>(&self, own: u32, dir: bool, f: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
        if !dir {
            return f();
        }
        let holds = loop {
            let mut holds = self.lock();
            if !Self::held_by_others(&mut holds, own) {
                break holds;
            }
            drop(holds);
            std::thread::yield_now();
            core::hint::spin_loop();
        };
        let r = f();
        if r.is_ok() {
            self.bump();
        }
        drop(holds);
        r
    }

    /// Whether a thread other than this one holds, a holder that has ended
    /// forgotten.
    fn held_by_others(holds: &mut std::collections::BTreeMap<i32, u32>, own: u32) -> bool {
        if holds.is_empty() {
            return false;
        }
        if let Some(alive) = OWNER_ALIVE.get() {
            holds.retain(|pid, _| alive(*pid));
        }
        let all: u32 = holds.values().sum();
        all > own
    }
}

/// Where an open directory is ([`FileHandle::moved`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The path it was opened at and the path it has now, both relative to
    /// its filesystem.
    pub was: String,
    pub now: String,
    /// How many times it has moved, renamed itself or with a directory
    /// above it: a lookup through the path that missed while this changed
    /// raced a rename, and is made again (`PathIo::call`).
    pub epoch: u64,
}

impl Moved {
    /// The absolute path the directory has now, given the absolute path it
    /// was opened at: the mount's part of that path does not change. `None`
    /// when the directory was opened through a symlink among the
    /// directories of its path (the path does not end in `was`).
    pub fn path_from(&self, opened: &str) -> Option<String> {
        if self.was == self.now {
            return Some(opened.to_string());
        }
        let mount = if self.was.is_empty() {
            opened
        } else {
            opened.strip_suffix(self.was.as_str())?.strip_suffix('/')?
        };
        Some(match (mount, self.now.as_str()) {
            ("", "") => "/".to_string(),
            (m, "") => m.to_string(),
            (m, now) => format!("{m}/{now}"),
        })
    }
}

/// A mounted filesystem.
pub trait FileSystem: Send + Sync {
    /// This filesystem as a bpffs, which `BPF_OBJ_PIN` puts objects in;
    /// `None` for any other kind.
    fn bpf(&self) -> Option<&bpffs::BpfFs> {
        None
    }

    /// Its type as `/proc/self/mountinfo` names it. tmpfs unless it says
    /// otherwise, as `statfs` answers for every one.
    fn fs_type(&self) -> &'static str {
        "tmpfs"
    }
    /// Its magic number, `statfs`'s `f_type` (include/uapi/linux/magic.h):
    /// by its type, and tmpfs's for one that names none.
    fn magic(&self) -> u64 {
        match self.fs_type() {
            "proc" => 0x9fa0,
            "sysfs" => 0x6265_6572,
            "binder" => 0x6c6f_6f70,
            _ => 0x0102_1994,
        }
    }
    /// Open a path relative to this mount's root (no leading slash).
    fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno>;
    /// [`FileSystem::open`] for a program's `open` (or the page's, which has
    /// no umask): a file O_CREAT makes gets exactly `mode`, the umask
    /// already applied, 0 making a 0000 file as on Linux. `open` itself is
    /// the kernel's own, whose created files take the filesystem's default.
    fn open_mode(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.open(path, flags, mode)
    }
    fn metadata(&self, path: &str) -> Result<Metadata, Errno>;
    /// [`FileSystem::metadata`] of a symlink itself rather than what it
    /// names (`lstat`). The default asks [`FileSystem::read_link`] first; a
    /// filesystem whose `metadata` never follows a link answers in one.
    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        if let Ok(target) = self.read_link(path) {
            return Ok(Metadata {
                file_type: FileType::Symlink,
                size: target.len() as u64,
                mode: 0o777,
                ino: 1,
                mtime: 0,
                nlink: 1,
                rdev: 0,
                dev: 0,
                times: Default::default(),
                owner: None,
            });
        }
        self.metadata(path)
    }
    /// `access(2)`: whether the caller may use `path` as `mode` asks
    /// (`R_OK` 4, `W_OK` 2, `X_OK` 1; 0 is existence). Filesystems that do
    /// not model permissions say yes to anything that exists.
    fn access(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let _ = mode;
        self.metadata(path).map(|_| ())
    }
    /// No links here: `EINVAL` for a name that is there, and the lookup's
    /// error (`ENOENT`) for one that is not. (`metadata`: the default
    /// `metadata_nofollow` asks this.)
    fn read_link(&self, path: &str) -> Result<String, Errno> {
        self.metadata(path)?;
        Err(Errno::EINVAL)
    }
    /// Absolute path `abs` with the symlinks among its directories followed
    /// (and its last component's, with `follow_final`), as far as this
    /// filesystem mounted at `/` can say: see [`walk_links`]. A filesystem
    /// whose `read_link` is a round trip (the browser's [`remote::RemoteFs`])
    /// does the whole walk in one.
    fn walk(&self, abs: &str, follow_final: bool, mounts: &str) -> Result<Walked, Errno> {
        walk_links(abs.to_string(), follow_final, mounts, &|rel| self.read_link(rel))
    }
    /// [`FileSystem::walk`] with the final link followed, and the metadata
    /// of where it ends: `None` when the walk reached one of `mounts`, which
    /// names its own. A `stat` of a path in the root, in one step: one round
    /// trip where this filesystem's calls are ([`remote::RemoteFs`]), one
    /// lock where they take one ([`TmpFs`]).
    fn walk_metadata(&self, abs: &str, mounts: &str) -> Result<Option<Metadata>, Errno> {
        let w = self.walk(abs, true, mounts)?;
        if w.at_mount {
            return Ok(None);
        }
        self.metadata(w.path.trim_start_matches('/')).map(Some)
    }
    fn unlink(&self, path: &str) -> Result<(), Errno> {
        let _ = path;
        Err(Errno::EROFS)
    }
    fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let _ = (path, mode);
        Err(Errno::EROFS)
    }
    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let _ = path;
        Err(Errno::EROFS)
    }
    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        let _ = (from, to);
        Err(Errno::EROFS)
    }
    /// `rename`, refusing (`EEXIST`) a destination that exists when
    /// `noreplace` (`RENAME_NOREPLACE`). A filesystem that can make the
    /// check and the move one step does; this default checks first.
    fn rename2(&self, from: &str, to: &str, noreplace: bool) -> Result<(), Errno> {
        if noreplace && self.metadata_nofollow(to).is_ok() {
            return Err(Errno::EEXIST);
        }
        self.rename(from, to)
    }
    /// Change a file's mode. Filesystems that do not model permissions
    /// accept it and do nothing, which is what the guest expects to see.
    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let _ = (path, mode);
        Ok(())
    }
    /// Change a file's owner (`chown`; a final symlink is the link's own):
    /// its user, its group, or both. Who may is the caller's to have
    /// checked. A filesystem that keeps no owners accepts it for a file
    /// that is there and does nothing, as it always did: tar treats a
    /// failed chown while unpacking as a failure to unpack.
    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let _ = (uid, gid);
        self.metadata_nofollow(path).map(|_| ())
    }

    /// The number of the device the filesystem is on (`s_dev`: its
    /// files' `st_dev`, and what `/proc/self/mountinfo` says of it). The
    /// block device's for one that is on one; for the rest a number of
    /// its own ([`anon_dev`]), by default this instance's.
    fn dev(&self) -> u64 {
        anon_dev(DevKey::Instance(self as *const Self as *const u8 as usize))
    }

    /// Set a file's modification time (seconds since the epoch), for
    /// `utimensat`. Filesystems that keep no times accept it and do nothing.
    fn set_mtime(&self, path: &str, secs: i64) -> Result<(), Errno> {
        let _ = (path, secs);
        Ok(())
    }
    /// `utimensat` with both times and nanoseconds (`None`: leave it). A
    /// filesystem that keeps only whole-second modification times takes
    /// what it can.
    fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        let _ = atime;
        match mtime {
            Some((secs, _)) => self.set_mtime(path, secs),
            None => Ok(()),
        }
    }

    /// A second name for the same file. `EPERM` is what Linux says for a
    /// filesystem that has no hard links, which is the honest default.
    fn link(&self, from: &str, to: &str) -> Result<(), Errno> {
        let _ = (from, to);
        Err(Errno::EPERM)
    }

    fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        let _ = (target, path);
        Err(Errno::EROFS)
    }

    /// Place a node that `stat` reports as a socket. A bound UNIX socket must
    /// exist in the filesystem too, not just the socket namespace, or
    /// `test -e /tmp/.X11-unix/X0` says no while the X server is listening.
    fn mksocket(&self, path: &str) -> Result<(), Errno> {
        let _ = path;
        Err(Errno::EROFS)
    }

    /// `mknod` of a device: a node at `path`, with `mode`'s permission
    /// bits, that opens as device number `rdev` ([`devices`]): a block
    /// device when `mode` has `S_IFBLK`'s bits (0o060000), else a
    /// character device. A filesystem that keeps no device nodes says
    /// `EPERM`, as Linux's that cannot (vfat) do.
    fn mknod(&self, path: &str, mode: u32, rdev: u64) -> Result<(), Errno> {
        let _ = (path, mode, rdev);
        Err(Errno::EPERM)
    }

    /// What an `inotify` watch on `path` watches: the inode's key and
    /// whether it is a directory. `None` for the key where this filesystem
    /// says no changes (the default: `/proc`, `/dev`); `ENOENT` for nothing
    /// there.
    fn watch_key(&self, path: &str) -> Result<(Option<crate::inotify::Key>, bool), Errno> {
        self.metadata(path).map(|m| (None, m.file_type == FileType::Directory))
    }

    /// Whether its watches are kept in another module, by path
    /// ([`crate::inotify::Remote`]): the global kernel's tree.
    fn watched_remotely(&self) -> bool {
        false
    }

    /// What this was mounted from, and with which flags, when it is a
    /// mount a program made ([`mounted::Mount`]); `None` for one the
    /// kernel or its host set up, which shows as its type, read-write.
    fn mount_record(&self) -> Option<mounted::Record> {
        None
    }

    /// `mount` with `MS_REMOUNT`: the mount's flags are now `flags`.
    /// `false` for a mount that keeps none (it is as it was).
    fn remount(&self, flags: u64) -> bool {
        let _ = flags;
        false
    }

    /// Its own options, as `/proc/mounts` shows them after the mount's:
    /// each with a comma before it (a tmpfs's `,mode=755`).
    fn show_options(&self) -> String {
        String::new()
    }

    /// Whether the namespace follows this filesystem's links to
    /// directories when it is mounted somewhere other than `/`: for one
    /// that keeps symbolic links a program makes or an image holds (tmpfs,
    /// ext4), whose targets may lead anywhere. One that resolves its own
    /// names (proc, the host's), or has no links, is not asked, a
    /// directory at a time, on every lookup under it.
    fn keeps_links(&self) -> bool {
        false
    }

    /// An extended-attribute call on `path` (the node it names: a final
    /// symlink is the link's own, the caller follows it first). A
    /// filesystem that keeps none answers `EOPNOTSUPP`, as Linux's do.
    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        let _ = (path, op);
        Err(Errno::EOPNOTSUPP)
    }
}

/// Whether open `flags` ask to write, which a directory refuses (`EISDIR`).
pub(crate) fn writes(flags: u64) -> bool {
    let acc = flags & crate::fs::oflags::ACCMODE;
    acc == crate::fs::oflags::O_WRONLY || acc == crate::fs::oflags::O_RDWR
}

/// The id of the mount at `at` (`/proc/self/mountinfo`'s first field,
/// `statx`'s `stx_mnt_id`): 1 for the root, and for another the same number
/// wherever and whenever it is asked, a forked child's table and the
/// table after other mounts come and go included.
pub fn mount_id(at: &str) -> u64 {
    if at == "/" {
        return 1;
    }
    let h = at.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    2 + h % 0x3fff_fff0
}

/// Whether absolute `abs` is `at` or below it.
fn within(abs: &str, at: &str) -> bool {
    abs.starts_with(at) && matches!(abs.as_bytes().get(at.len()), None | Some(b'/'))
}

/// The place `rest` ("" or "/a/b") below `root` ("" or "/x") in a
/// filesystem: "/x/a/b".
fn place(root: &str, rest: &str) -> String {
    format!("{root}{rest}")
}

/// What is left of the place `loc` below `root` ("" for `root` itself, else
/// "/a/b"), if it is there.
fn below<'a>(loc: &'a str, root: &str) -> Option<&'a str> {
    if root.is_empty() {
        return Some(loc);
    }
    within(loc, root).then(|| &loc[root.len()..])
}

/// A process's mount table and working directory, and its published
/// [`Namespace`]: what a caller without the kernel lock reads
/// ([`Vfs::view`]). Every lookup is the
/// namespace's (`Deref`); the three changes -- a mount, an unmount, a
/// `chdir` -- are this type's, and publish.
pub struct Vfs {
    ns: Namespace,
    view: NsCell,
    /// The mount table `ns` holds: the view's [`VfsView::mounts`] count
    /// when it was taken ([`Vfs::refresh`]).
    mounts: u64,
    /// The process's working directory while a thread with an fs_struct
    /// of its own has its directory in `ns` for its call ([`Vfs::enter_cwd`]):
    /// what a publication shows.
    held: Option<String>,
}

/// A mount namespace: the mount table every process in it sees, and how
/// many times it has changed.
///
/// Processes share one until one of them leaves for a copy of its own
/// (`unshare(CLONE_NEWNS)`), as on Linux: what a process mounts, its
/// parent, its children and its siblings all see. Each process's own
/// picture of it ([`VfsView`]) is made from this table and the process's
/// root, and made again when the count here has moved on.
///
/// The paths are the namespace's own, from the root it began with: a
/// process that has changed its root sees the mounts under that root, and
/// a mount it makes is recorded where it is in the namespace.
///
/// A namespace made as a copy of another is not wholly apart from it. A
/// mount is private unless it is made shared, and what is mounted or
/// unmounted under a shared mount happens in every namespace that has
/// that mount too ([`Propagation`]): Android's init makes `/` shared and
/// `/apex` private, and then keeps two namespaces that see each other's
/// mounts everywhere but under `/apex`.
///
/// One for a kernel's processes. A host whose processes are each a
/// kernel of their own (the page's) has one a process, as before: there
/// nothing a process mounts is seen by another.
pub struct MountNs {
    table: std::sync::Mutex<BTreeMap<String, Mounted>>,
    changes: std::sync::atomic::AtomicU64,
    id: u64,
}

/// How what is mounted and unmounted under a mount spreads to the other
/// namespaces that have the mount (`mount(2)`'s `MS_SHARED`, `MS_PRIVATE`,
/// `MS_SLAVE` and `MS_UNBINDABLE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Propagation {
    /// To every namespace that has this mount as a peer or a slave of it,
    /// and from the peers to here.
    Shared,
    /// Nowhere, and nothing comes: what a mount is until it is made
    /// otherwise.
    Private,
    /// From the peers it had to here, and nothing from here.
    Slave,
    /// As private (and not to be bound elsewhere, which nothing here does
    /// yet).
    Unbindable,
}

/// A mount in a namespace's table.
#[derive(Clone)]
struct Mounted {
    fs: Arc<dyn FileSystem>,
    /// The filesystem it shows a part of, and which part: `fs` itself and
    /// "" for a filesystem mounted whole, the source's filesystem and the
    /// directory in it for a bind mount (whose `fs` is that directory).
    /// Peers show the same filesystem; where in it a mount is made says
    /// where in each peer it goes (Linux's propagation is by dentry).
    origin: Arc<dyn FileSystem>,
    root: String,
    /// The peer group it is in, if it is shared: the mounts in the other
    /// namespaces that are this mount there.
    group: Option<u64>,
    /// The peer group it takes from without giving to, if it is a slave.
    master: Option<u64>,
}

/// Every mount namespace there is, for a mount that spreads.
static NAMESPACES: std::sync::Mutex<Vec<std::sync::Weak<MountNs>>> = std::sync::Mutex::new(Vec::new());

fn next_group() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl MountNs {
    fn new(table: BTreeMap<String, Mounted>) -> Arc<MountNs> {
        // Numbered as Linux numbers a namespace's inode, from the first
        // number it gives out after the ones it keeps for its own.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0xf000_0000);
        let ns = Arc::new(MountNs {
            table: std::sync::Mutex::new(table),
            changes: std::sync::atomic::AtomicU64::new(0),
            id: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        });
        let mut all = NAMESPACES.lock().unwrap_or_else(|e| e.into_inner());
        all.retain(|ns| ns.strong_count() > 0);
        all.push(Arc::downgrade(&ns));
        ns
    }

    /// The number `/proc/<pid>/ns/mnt` shows for it: `mnt:[n]`.
    pub fn id(&self) -> u64 {
        self.id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Mounted>> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The filesystems, by where they are mounted.
    fn filesystems(&self) -> BTreeMap<String, Arc<dyn FileSystem>> {
        self.lock().iter().map(|(at, m)| (at.clone(), Arc::clone(&m.fs))).collect()
    }

    /// The namespaces there are now.
    fn all() -> Vec<Arc<MountNs>> {
        NAMESPACES.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(std::sync::Weak::upgrade).collect()
    }

    /// The mount `at` is in, other than one at `at` itself: where it is
    /// mounted, and it.
    fn parent<'a>(table: &'a BTreeMap<String, Mounted>, at: &str) -> Option<(&'a String, &'a Mounted)> {
        table.iter().filter(|(k, _)| k.as_str() != at && (k.as_str() == "/" || within(at, k))).max_by_key(|(k, _)| k.len())
    }

    fn count(&self) {
        self.changes.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// The mount a mount at `at` would be made on: the one at `at` itself,
    /// which it covers, else the one `at` is in. With where it is, and
    /// where `at` is in the filesystem that mount shows.
    fn covering<'a>(table: &'a BTreeMap<String, Mounted>, at: &str) -> Option<(&'a String, &'a Mounted, String)> {
        let (k, m) = table.get_key_value(at).or_else(|| Self::parent(table, at))?;
        Some((k, m, place(&m.root, &at[if k == "/" { 0 } else { k.len() }..])))
    }

    /// Where the place `loc` of `origin` is in each namespace whose mount
    /// shows it and is in `group` (or, for `slaves`, takes from it): the
    /// namespace, the path there, and whether that mount is a slave.
    fn receivers(origin: &Arc<dyn FileSystem>, loc: &str, group: u64) -> Vec<(Arc<MountNs>, String, bool)> {
        let mut out = Vec::new();
        for ns in Self::all() {
            let table = ns.lock();
            for (k, m) in table.iter() {
                let slave = m.master == Some(group);
                if !(m.group == Some(group) || slave) || !Arc::ptr_eq(&m.origin, origin) {
                    continue;
                }
                // A peer that shows only a part of the filesystem has what
                // is made in that part.
                let Some(rest) = below(loc, &m.root) else { continue };
                let path = if rest.is_empty() { k.clone() } else if k == "/" { rest.to_string() } else { format!("{k}{rest}") };
                out.push((Arc::clone(&ns), path, slave));
            }
        }
        out
    }

    /// Mount `fs` at `at`, replacing what was mounted there (or, with
    /// `unless_there`, leaving it: whether it mounted). `origin` and
    /// `root` are what it shows (`fs` and "" for a filesystem mounted
    /// whole); `join`, the peer group of a bind mount's shared source,
    /// which the bind mount is in as well.
    ///
    /// A mount is made on the mount it covers, if there is one at `at`,
    /// else on the one `at` is in; when that one is shared it is made in
    /// each of its peers too, where the same place of the same filesystem
    /// is (a bind mount's peers are elsewhere than it), and in their slaves
    /// as a slave. What is made under a shared mount is shared, in a group
    /// of its own with its copies (`attach_recursive_mnt`).
    fn mount(self: &Arc<Self>, at: String, fs: Arc<dyn FileSystem>, origin: Arc<dyn FileSystem>, root: String, join: Option<u64>, unless_there: bool) -> bool {
        let spread = {
            let mut table = self.lock();
            if unless_there && table.contains_key(&at) {
                return false;
            }
            match Self::covering(&table, &at).map(|(_, m, loc)| (m.group, Arc::clone(&m.origin), loc)) {
                Some((Some(group), cover, loc)) => (group, cover, loc),
                _ => {
                    table.insert(at, Mounted { fs, origin, root, group: join, master: None });
                    self.count();
                    return true;
                }
            }
        };
        let (group, cover, loc) = spread;
        let new = join.unwrap_or_else(next_group);
        for (ns, path, slave) in Self::receivers(&cover, &loc, group) {
            let m = Mounted {
                fs: Arc::clone(&fs),
                origin: Arc::clone(&origin),
                root: root.clone(),
                group: if slave { None } else { Some(new) },
                master: if slave { Some(new) } else { None },
            };
            ns.lock().insert(path, m);
            ns.count();
        }
        true
    }

    /// Remove the mount at exactly `at`: whether there was one. Under a
    /// shared mount it goes from each peer of that mount, and each slave,
    /// where the same mount was made.
    fn unmount(self: &Arc<Self>, at: &str) -> bool {
        let (group, cover, loc, gone) = {
            let mut table = self.lock();
            let Some(gone) = table.get(at).cloned() else { return false };
            let parent = Self::parent(&table, at).map(|(k, m)| (m.group, Arc::clone(&m.origin), place(&m.root, &at[if k == "/" { 0 } else { k.len() }..])));
            match parent {
                Some((Some(group), cover, loc)) => (group, cover, loc, gone),
                _ => {
                    table.remove(at);
                    self.count();
                    return true;
                }
            }
        };
        let mut done = false;
        for (ns, path, _) in Self::receivers(&cover, &loc, group) {
            let mut table = ns.lock();
            // The same mount there: the filesystem that spread with it.
            if table.get(&path).is_some_and(|m| Arc::ptr_eq(&m.fs, &gone.fs)) {
                table.remove(&path);
                done |= Arc::ptr_eq(&ns, self) && path == at;
                drop(table);
                ns.count();
            }
        }
        if !done {
            self.lock().remove(at);
            self.count();
        }
        true
    }

    /// Change how the mount at exactly `at` spreads, and with `recursive`
    /// every mount under it: `false` where nothing is mounted at `at`.
    fn set_propagation(&self, at: &str, kind: Propagation, recursive: bool) -> bool {
        let mut table = self.lock();
        if !table.contains_key(at) {
            return false;
        }
        let which: Vec<String> = table.keys().filter(|k| k.as_str() == at || (recursive && (at == "/" || within(k, at)))).cloned().collect();
        for k in which {
            let m = table.get_mut(&k).expect("a key of the table");
            match kind {
                // A group of its own, which a copy of the namespace then
                // has too.
                Propagation::Shared => {
                    if m.group.is_none() {
                        m.group = Some(next_group());
                    }
                }
                Propagation::Private | Propagation::Unbindable => (m.group, m.master) = (None, None),
                // What it shared with, it now only takes from.
                Propagation::Slave => {
                    if let Some(group) = m.group.take() {
                        m.master = Some(group);
                    }
                }
            }
        }
        true
    }
}

/// A mount namespace as an open file (`/proc/<pid>/ns/mnt`): nothing to
/// read, a regular file whose inode is the namespace's number, and the
/// namespace for as long as it is open, whatever becomes of the processes
/// that were in it.
pub struct MountNsFile(pub Arc<MountNs>);

impl std::fmt::Debug for MountNsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mnt:[{}]", self.0.id())
    }
}

impl FileHandle for MountNsFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 0, mode: 0o444, ino: self.0.id(), mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
    fn as_mount_ns(self: Arc<Self>) -> Option<Arc<MountNs>> {
        Some(Arc::clone(&self.0))
    }
}

/// A [`Vfs`]'s namespace as other threads read it: replaced whole on every
/// change, so a reader holds one consistent table and directory for as long
/// as it likes (an `Arc`), and a lookup through it runs outside every lock.
///
/// It is the process's picture of its mount namespace ([`MountNs`]), from
/// the process's own root and with its own directory: `mount` and
/// `umount2` change the namespace's table through it, with or without the
/// kernel lock, and it follows the table, as the kernel's own copy
/// follows it ([`Vfs::refresh`]).
pub struct VfsView {
    cur: gex_atomic::rcu::Published<Arc<Namespace>>,
    /// How many times this picture's mount table has changed.
    mounts: std::sync::atomic::AtomicU64,
    /// Notified at each change: a reader of `/proc/self/mountinfo` waits
    /// on it.
    changed: crate::wait::Queue,
    /// The mount namespace this is a picture of.
    shared: std::sync::RwLock<Arc<MountNs>>,
    /// The namespace's count of changes at which `cur`'s table was made.
    seen: std::sync::atomic::AtomicU64,
    /// The mounts that are this process's alone, over the namespace's, by
    /// their paths in the namespace: its `/proc`, which is one filesystem
    /// on Linux that answers each reader about itself, and here a
    /// filesystem a process, made of that process's own state.
    own: std::sync::Mutex<BTreeMap<String, Arc<dyn FileSystem>>>,
}

impl VfsView {
    /// A picture, `ns`, of the namespace `shared` as it was at its
    /// change `seen`.
    /// Change how the mount at `at` spreads ([`Propagation`]), and with
    /// `recursive` every mount under it. `false` where nothing is mounted
    /// there. One of the process's own mounts spreads nowhere, whatever is
    /// asked.
    pub fn set_propagation(&self, at: &str, kind: Propagation, recursive: bool) -> bool {
        self.sync();
        let cur = self.cur.read(crate::sync::me() as usize, Arc::clone);
        let outer = cur.outer_path(&normalize(at, &cur.cwd)).into_owned();
        let own = self.own().contains_key(&outer);
        self.mount_ns().set_propagation(&outer, kind, recursive) || own
    }

    fn new(ns: &Namespace, shared: Arc<MountNs>, seen: u64, own: BTreeMap<String, Arc<dyn FileSystem>>) -> VfsView {
        VfsView {
            cur: gex_atomic::rcu::Published::new(Arc::new(ns.clone()), crate::file::FD_READER_SLOTS),
            mounts: std::sync::atomic::AtomicU64::new(0),
            changed: crate::wait::Queue::new(),
            shared: std::sync::RwLock::new(shared),
            seen: std::sync::atomic::AtomicU64::new(seen),
            own: std::sync::Mutex::new(own),
        }
    }

    fn own(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<dyn FileSystem>>> {
        self.own.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Mount `fs` at `at` for this process alone, over whatever the
    /// namespace has there: its own `/proc`. A fork begins with its
    /// parent's and is given its own.
    pub fn mount_own(&self, at: &str, fs: Arc<dyn FileSystem>) {
        self.sync();
        let cur = self.cur.read(crate::sync::me() as usize, Arc::clone);
        self.own().insert(cur.outer_path(&normalize(at, &cur.cwd)).into_owned(), fs);
        // The picture again, whatever the namespace's count.
        self.seen.store(u64::MAX, std::sync::atomic::Ordering::Release);
        self.sync();
    }

    /// The mount namespace this process is in.
    pub fn mount_ns(&self) -> Arc<MountNs> {
        Arc::clone(&self.shared.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Bring the picture up to date with its namespace, if another
    /// process (or this one) has changed the table since it was made: the
    /// table again, from this process's root, with its directory as it
    /// is. One load when nothing has changed.
    fn sync(&self) {
        use std::sync::atomic::Ordering::{AcqRel, Acquire, Release};
        let shared = self.mount_ns();
        if shared.changes.load(Acquire) == self.seen.load(Acquire) {
            return;
        }
        let changed = self.cur.write(|cur| {
            // The count, then the table: a table never older than the
            // count it is kept with.
            let now = shared.changes.load(Acquire);
            if now == self.seen.load(Acquire) {
                return (None, false);
            }
            let mut ns = Namespace::new();
            ns.mounts = shared.filesystems();
            ns.mounts.extend(self.own().iter().map(|(at, fs)| (at.clone(), Arc::clone(fs))));
            ns.list_others();
            // From the process's root, where that is not the namespace's.
            if cur.root != "/" && ns.chroot(&cur.root).is_err() {
                // Its root is no longer there to be found: the picture it
                // had stands.
                self.seen.store(now, Release);
                return (None, false);
            }
            ns.cwd.clone_from(&cur.cwd);
            self.seen.store(now, Release);
            (Some(Arc::new(ns)), true)
        });
        if changed {
            self.mounts.fetch_add(1, AcqRel);
            self.changed.notify();
        }
    }

    /// Leave the mount namespace for a copy of it that is this process's
    /// own (`unshare(CLONE_NEWNS)`): what it mounts from now nobody else
    /// sees, nor it what they do.
    pub fn unshare(&self) {
        self.sync();
        let mut shared = self.shared.write().unwrap_or_else(|e| e.into_inner());
        // A copy with every mount as it is there, the shared ones peers of
        // the ones they are copies of.
        let table = shared.lock().clone();
        let copy = MountNs::new(table);
        // The copy is at its first count, and the picture is of it.
        self.seen.store(0, std::sync::atomic::Ordering::Release);
        *shared = copy;
    }

    /// Enter the mount namespace `ns` (`setns`): its table, from its root,
    /// and in its root directory.
    pub fn join(&self, ns: Arc<MountNs>) {
        *self.shared.write().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&ns);
        let now = ns.changes.load(std::sync::atomic::Ordering::Acquire);
        self.cur.write(|_| {
            let mut fresh = Namespace::new();
            fresh.mounts = ns.filesystems();
            fresh.mounts.extend(self.own().iter().map(|(at, fs)| (at.clone(), Arc::clone(fs))));
            fresh.list_others();
            self.seen.store(now, std::sync::atomic::Ordering::Release);
            (Some(Arc::new(fresh)), ())
        });
        self.mounts.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.changed.notify();
    }

    /// The namespace as it stands.
    pub fn get(&self) -> Arc<Namespace> {
        self.sync();
        self.cur.read(crate::sync::me() as usize, Arc::clone)
    }

    /// Which namespace [`Self::get`] gives: it changes with each one
    /// published. A caller that keeps what `get` gave, with the epoch read
    /// before it, keeps the current namespace while this reads the same.
    pub fn epoch(&self) -> u64 {
        self.cur.epoch()
    }

    /// How many times the mount table has changed, now.
    pub fn mounts(&self) -> u64 {
        self.sync();
        self.mounts.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The wait queue notified at each change of the mount table.
    pub fn mounts_queue(&self) -> u32 {
        self.changed.id()
    }

    /// Where `at` (absolute, or relative to the published directory) is
    /// in the namespace: this process's root is not always the
    /// namespace's.
    fn outer(&self, at: &str) -> String {
        self.sync();
        let cur = self.cur.read(crate::sync::me() as usize, Arc::clone);
        cur.outer_path(&normalize(at, &cur.cwd)).into_owned()
    }

    /// Mount `fs` at `at` (absolute, or relative to the published
    /// directory), replacing what was mounted there: in the namespace,
    /// for every process in it, and wherever it spreads to.
    pub fn mount(&self, at: &str, fs: Arc<dyn FileSystem>) {
        let at = self.outer(at);
        self.mount_ns().mount(at, Arc::clone(&fs), fs, String::new(), None, false);
        self.sync();
    }

    /// Remove the mount at exactly `path` (absolute). The root mount
    /// stays: a guest that unmounts `/` has nothing left to run from.
    pub fn unmount(&self, path: &str) -> bool {
        if normalize(path, "/") == "/" {
            return false;
        }
        let at = self.outer(path);
        // One of the process's own goes for the process alone; what the
        // namespace has under it shows again.
        let gone = if self.own().remove(&at).is_some() {
            self.seen.store(u64::MAX, std::sync::atomic::Ordering::Release);
            true
        } else {
            self.mount_ns().unmount(&at)
        };
        self.sync();
        gone
    }

    /// [`Namespace::chroot`] of the namespace as published: this
    /// process's root alone, which its picture of the table is made from
    /// after this.
    pub fn chroot(&self, dir: &str) -> Result<(), Errno> {
        self.sync();
        let mut err = Ok(());
        let changed = self.cur.write(|cur| {
            let mut ns = Namespace::clone(cur);
            err = ns.chroot(dir);
            if err.is_err() {
                return (None, false);
            }
            (Some(Arc::new(ns)), true)
        });
        if changed {
            self.mounts.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.changed.notify();
        }
        err
    }

    /// A bind mount: what is at `source` (absolute) is at `target` too,
    /// and with `recursive` so is each thing mounted under it, where it
    /// is from the source. The same files, not copies. A bind of a shared
    /// mount is that mount's peer (and each copy under it its source's),
    /// and the bind spreads as any mount made at the target does.
    pub fn bind(&self, source: &str, target: &str, recursive: bool) -> Result<(), Errno> {
        let cur = self.get();
        let source = normalize(source, &cur.cwd);
        let (fs, rel) = cur.mount_of(source.clone())?;
        let root: Arc<dyn FileSystem> = if rel.is_empty() { Arc::clone(fs) } else { Arc::new(subtree::Subtree::new(Arc::clone(fs), &rel)) };
        let target = normalize(target, &cur.cwd);
        let ns = self.mount_ns();
        // The source's mount as the namespace has it (a process's own
        // mount, its /proc, is not there: bound as a filesystem of no
        // group).
        let outer = self.outer(&source);
        let table = ns.lock().clone();
        let from = MountNs::covering(&table, &outer).filter(|(_, m, _)| Arc::ptr_eq(&m.fs, fs) || Arc::ptr_eq(&m.origin, fs));
        let (origin, place_of, join) = match &from {
            Some((_, m, loc)) => (Arc::clone(&m.origin), loc.clone(), m.group),
            None => (Arc::clone(&root), String::new(), None),
        };
        // What is mounted under the source now: looked up before anything
        // is mounted, since the target may be under the source itself.
        let under: Vec<(String, Mounted)> = if recursive {
            let inside = |at: &str| at != outer && (outer == "/" || within(at, &outer));
            table.iter().filter(|(at, _)| inside(at)).map(|(at, m)| (if outer == "/" { at.clone() } else { at[outer.len()..].to_string() }, m.clone())).collect()
        } else {
            Vec::new()
        };
        let target = self.outer(&target);
        ns.mount(target.clone(), root, origin, place_of, join, false);
        for (rest, m) in under {
            ns.mount(format!("{}{rest}", target.trim_end_matches('/')), m.fs, m.origin, m.root, m.group, false);
        }
        self.sync();
        Ok(())
    }

    /// Mount `fs` at `at` unless something is mounted there already:
    /// whether it did.
    pub fn mount_unless_there(&self, at: &str, fs: impl FnOnce() -> Arc<dyn FileSystem>) -> bool {
        let at = self.outer(at);
        if self.own().contains_key(&at) || self.mount_ns().lock().contains_key(&at) {
            return false;
        }
        let fs = fs();
        let mounted = self.mount_ns().mount(at, Arc::clone(&fs), fs, String::new(), None, true);
        self.sync();
        mounted
    }
}

/// A view a copy of the table does not share: a forked child's picture of
/// the mounts, its root and its directory are its own. The mount
/// namespace the picture is of is the parent's.
struct NsCell(Arc<VfsView>);

impl Clone for Vfs {
    fn clone(&self) -> Vfs {
        // A fork's copy: the calling thread's directory is the child's.
        // The mount table as published (another thread may have mounted
        // since this copy's was taken), the directory as it is here. The
        // namespace's count is read first: the picture is no older than
        // it, so the child misses no change (at worst it looks again).
        let seen = self.view.0.seen.load(std::sync::atomic::Ordering::Acquire);
        let shared = self.view.0.mount_ns();
        let own = self.view.0.own().clone();
        let mut ns = Namespace::clone(&self.view.0.cur.read(crate::sync::me() as usize, Arc::clone));
        ns.cwd.clone_from(&self.ns.cwd);
        Vfs { view: NsCell(Arc::new(VfsView::new(&ns, shared, seen, own))), ns, mounts: 0, held: None }
    }
}

impl std::ops::Deref for Vfs {
    type Target = Namespace;
    fn deref(&self) -> &Namespace {
        &self.ns
    }
}

impl Vfs {
    pub fn new() -> Vfs {
        let ns = Namespace::new();
        let view = NsCell(Arc::new(VfsView::new(&ns, MountNs::new(BTreeMap::new()), 0, BTreeMap::new())));
        Vfs { ns, view, mounts: 0, held: None }
    }

    /// Mount `fs` at `at` for this process alone ([`VfsView::mount_own`]).
    pub fn mount_own(&mut self, at: &str, fs: Arc<dyn FileSystem>) {
        self.view.0.mount_own(at, fs);
        self.refresh();
    }

    /// Leave the mount namespace for a copy of the process's own
    /// ([`VfsView::unshare`]).
    pub fn unshare_mounts(&mut self) {
        self.view.0.unshare();
        self.refresh();
    }

    /// Enter another mount namespace ([`VfsView::join`]).
    pub fn join_mounts(&mut self, ns: Arc<MountNs>) {
        self.view.0.join(ns);
        self.mounts = u64::MAX;
        self.refresh();
        self.ns.cwd = "/".to_string();
        self.ns.root = "/".to_string();
    }

    /// The published namespace, the same view for this table's whole life.
    pub fn view(&self) -> &Arc<VfsView> {
        &self.view.0
    }

    /// The process's directory, published: the mount table stays the
    /// view's own. Every build, the single-threaded page's too, which reads
    /// its namespace the same way: a `chdir` is rare.
    fn publish(&self) {
        let cwd = self.held.as_ref().unwrap_or(&self.ns.cwd);
        self.view.0.cur.write(|cur| {
            let mut ns = Namespace::clone(cur);
            ns.cwd.clone_from(cwd);
            (Some(Arc::new(ns)), ())
        });
    }

    /// Take the published mount table if it has changed since this copy's
    /// was taken: a `mount` or `umount2` made without the kernel lock.
    pub fn refresh(&mut self) {
        let now = self.view.0.mounts();
        if now == self.mounts {
            return;
        }
        let ns = self.view.0.get();
        self.ns.mounts.clone_from(&ns.mounts);
        self.ns.others.clone_from(&ns.others);
        if self.ns.root != ns.root {
            // A `chroot`: the directory too, as it left it.
            self.ns.root.clone_from(&ns.root);
            if self.held.is_none() {
                self.ns.cwd.clone_from(&ns.cwd);
            }
        }
        self.mounts = now;
    }

    /// `chroot` to `path` ([`VfsView::chroot`]): a directory, its links
    /// followed. `path` is in the namespace as it is now; a host restoring
    /// a process gives the root it had ([`Namespace::root`]), which names
    /// the same directory while this one's root is still `/`.
    pub fn chroot(&mut self, path: &str) -> Result<(), Errno> {
        let dir = self.ns.canonical(&normalize(path, &self.ns.cwd));
        if self.ns.metadata(&dir)?.file_type != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        self.view.0.chroot(&dir)?;
        self.refresh();
        Ok(())
    }

    /// Mount `fs` at `at` ([`VfsView::mount`]).
    pub fn mount(&mut self, at: &str, fs: Arc<dyn FileSystem>) {
        self.view.0.mount(at, fs);
        self.refresh();
    }

    /// Remove the mount at exactly this path ([`VfsView::unmount`]).
    pub fn unmount(&mut self, path: &str) -> bool {
        let at = normalize(path, &self.ns.cwd);
        let gone = self.view.0.unmount(&at);
        self.refresh();
        gone
    }

    pub fn set_cwd(&mut self, path: &str) -> Result<(), Errno> {
        self.ns.set_cwd(path)?;
        self.publish();
        Ok(())
    }
    /// Whether a thread's own directory is in for its call
    /// ([`Vfs::enter_cwd`]).
    pub fn in_thread_cwd(&self) -> bool {
        self.held.is_some()
    }
    /// Make `cwd` the process's directory as it is, checked when it was
    /// set: an `execve` from a thread with an fs_struct of its own keeps
    /// that thread's directory.
    pub fn put_cwd(&mut self, cwd: String) {
        self.ns.cwd = cwd;
        self.publish();
    }
    /// Resolve against `cwd`, a thread's own fs_struct's directory, until
    /// [`Vfs::leave_cwd`]: the process's stays what is published, a `chdir`
    /// in between changing only the thread's.
    pub fn enter_cwd(&mut self, cwd: String) {
        self.held = Some(std::mem::replace(&mut self.ns.cwd, cwd));
    }

    /// Back to the process's directory; the thread's, as the call left it.
    pub fn leave_cwd(&mut self) -> String {
        match self.held.take() {
            Some(p) => std::mem::replace(&mut self.ns.cwd, p),
            None => self.ns.cwd.clone(),
        }
    }
}

/// The mount table and working directory: every path lookup.
#[derive(Clone)]
pub struct Namespace {
    /// Mount point (absolute, no trailing slash except for "/") to backend.
    mounts: BTreeMap<String, Arc<dyn FileSystem>>,
    /// The mount points other than `/`, NUL-separated: what a walk of the
    /// root filesystem stops at. Kept with `mounts`, not built per lookup.
    others: String,
    /// Current working directory, always absolute and normalised.
    pub cwd: String,
    /// Where this namespace's `/` is in the one the process started with:
    /// `/` until a `chroot` ([`Namespace::chroot`]).
    root: String,
}

impl Namespace {
    fn new() -> Namespace {
        Namespace {
            mounts: BTreeMap::new(),
            others: String::new(),
            cwd: "/".to_string(),
            root: "/".to_string(),
        }
    }

    /// Where `/` is in the namespace the process started with.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Absolute `abs` as the namespace the process started with names it:
    /// what is the same object in every process's view whatever its root
    /// (a socket's name in the table every process shares).
    pub fn outer_path<'a>(&self, abs: &'a str) -> std::borrow::Cow<'a, str> {
        if self.root == "/" || !abs.starts_with('/') {
            return std::borrow::Cow::Borrowed(abs);
        }
        std::borrow::Cow::Owned(if abs == "/" { self.root.clone() } else { format!("{}{abs}", self.root) })
    }

    /// `chroot` to `dir` (absolute, normal, its links followed, a
    /// directory): the mounts at and under it, moved up to `/`, and the
    /// filesystem it is in as the root, from it down ([`subtree::Subtree`]).
    /// A mount elsewhere is out of sight. The directory stays where it was
    /// when inside; outside, it is the new root (Linux leaves one outside
    /// where it is, a way out of the root that this namespace, which names
    /// directories by path, cannot give).
    fn chroot(&mut self, dir: &str) -> Result<(), Errno> {
        if dir == "/" {
            return Ok(());
        }
        let mut mounts = BTreeMap::new();
        for (at, fs) in &self.mounts {
            if within(at, dir) {
                let moved = if at.len() == dir.len() { "/".to_string() } else { at[dir.len()..].to_string() };
                mounts.insert(moved, fs.clone());
            }
        }
        if !mounts.contains_key("/") {
            let (fs, rel) = self.mount_of(dir.to_string())?;
            let root: Arc<dyn FileSystem> = if rel.is_empty() { fs.clone() } else { Arc::new(subtree::Subtree::new(fs.clone(), &rel)) };
            mounts.insert("/".to_string(), root);
        }
        self.mounts = mounts;
        self.list_others();
        self.cwd = if within(&self.cwd, dir) && self.cwd.len() > dir.len() { self.cwd[dir.len()..].to_string() } else { "/".to_string() };
        self.root = self.outer_path(dir).into_owned();
        Ok(())
    }

    fn list_others(&mut self) {
        let others: Vec<&str> = self.mounts.keys().map(String::as_str).filter(|m| *m != "/").collect();
        self.others = others.join("\0");
    }

    /// Every mount, parents before what is mounted under them: where,
    /// its [`FileSystem::fs_type`], and what it was mounted from and how.
    pub fn mount_table(&self) -> Vec<MountLine> {
        self.mounts
            .iter()
            .map(|(at, fs)| {
                let fs_type = fs.fs_type();
                let record = fs.mount_record().unwrap_or(mounted::Record { source: fs_type.to_string(), flags: 0 });
                MountLine { at: at.clone(), fs_type, record, fs_options: fs.show_options(), dev: fs.dev() }
            })
            .collect()
    }

    /// [`mount_id`] of the mount holding `path`, by its name: a symlink on
    /// the way into another mount is not followed (the root's, then).
    pub fn mount_id_of(&self, path: &str) -> u64 {
        self.mount_at(&normalize(path, &self.cwd)).map_or(1, |(at, _)| mount_id(at))
    }

    /// The magic number of the filesystem `path` is in, for `statfs`; the
    /// path has to name something.
    pub fn fs_magic(&self, path: &str) -> Result<u64, Errno> {
        self.metadata(path)?;
        self.resolve(path).map(|(fs, _)| fs.magic())
    }

    /// [`Namespace::fs_magic`] for an open file, by the name it was opened
    /// under; tmpfs's for one with no name in any filesystem (a pipe, a
    /// socket).
    pub fn fs_magic_of_open(&self, path: &str) -> u64 {
        self.resolve(path).map_or(0x0102_1994, |(fs, _)| fs.magic())
    }

    /// Whether something is mounted at exactly this path.
    pub fn is_mount_point(&self, path: &str) -> bool {
        self.mounts.contains_key(&normalize(path, &self.cwd))
    }

    /// What is mounted at exactly this path.
    pub fn mounted_at(&self, path: &str) -> Option<&Arc<dyn FileSystem>> {
        self.mounts.get(&normalize(path, &self.cwd))
    }

    /// Find the backend responsible for `path`, and the path relative to it.
    ///
    /// Longest prefix wins, so a `/proc` mount shadows the root mount for
    /// everything beneath it.
    fn resolve<'a>(&'a self, path: &str) -> Result<(&'a Arc<dyn FileSystem>, String), Errno> {
        let abs = normalize(path, &self.cwd);
        let abs = match self.walk(&abs, false)? {
            Some(w) if !w.at_mount => w.path,
            _ => self.through_dir_links(abs)?,
        };
        self.mount_of(abs)
    }

    /// `path` from the directory `base` (absolute), as [`normalize`] makes
    /// it but with each `..` taken from where the names before it lead:
    /// after a symbolic link to a directory it is that directory's
    /// parent, not the link's, since Linux walks a path a name at a time.
    /// What a `..` follows has to be there (`ENOENT`) and be a directory
    /// (`ENOTDIR`). For a path with a `..` in it; any other is
    /// `normalize`'s, with nothing asked.
    pub fn physical(&self, path: &str, base: &str) -> Result<String, Errno> {
        let absolute = path.starts_with('/');
        let mut at = if absolute { "/".to_string() } else { base.to_string() };
        // Whether `at` may have a link on it still: a relative path's
        // directory may (it is kept as it was named), the root not.
        let mut unfollowed = !absolute && at != "/";
        for c in path.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    if unfollowed {
                        at = self.followed(&at)?;
                        unfollowed = false;
                    }
                    at = parent_of(&at);
                }
                c => {
                    if at != "/" {
                        at.push('/');
                    }
                    at.push_str(c);
                    unfollowed = true;
                }
            }
        }
        Ok(at)
    }

    /// Absolute `abs`, which has to be a directory, with every link on it
    /// followed, the last name's too.
    fn followed(&self, abs: &str) -> Result<String, Errno> {
        let mut current = abs.to_string();
        for _ in 0..40 {
            let dirs = match self.walk(&current, false)? {
                Some(w) if !w.at_mount => w.path,
                _ => self.through_dir_links(current)?,
            };
            let (fs, rel) = self.mount_of(dirs.clone())?;
            match fs.read_link(&rel) {
                Ok(target) => current = if target.starts_with('/') { normalize(&target, "/") } else { normalize(&target, &parent_of(&dirs)) },
                Err(_) => {
                    return match fs.metadata(&rel)?.file_type {
                        FileType::Directory => Ok(dirs),
                        _ => Err(Errno::ENOTDIR),
                    };
                }
            }
        }
        Err(Errno::ELOOP)
    }

    /// Absolute `abs` with every root-filesystem symlink on it followed,
    /// the last component's too: the name Linux's `/proc/self/fd/N` shows
    /// for a file opened by `abs`. `abs` itself when the walk fails or
    /// reaches another mount (which names its own links).
    pub fn canonical(&self, abs: &str) -> String {
        match self.walk(abs, true) {
            Ok(Some(w)) if !w.at_mount => w.path,
            _ => abs.to_string(),
        }
    }

    /// Where `mount` and `umount` of absolute `abs` act: the root
    /// filesystem's links on it followed, up to another mount if it lies in
    /// one. (A mount made under a name with a link in it would be found
    /// under no name.)
    pub fn mount_target(&self, abs: &str) -> String {
        match self.walk(abs, true) {
            Ok(Some(w)) => w.path,
            _ => abs.to_string(),
        }
    }

    /// The root filesystem's [`FileSystem::walk`] of absolute `abs`, or
    /// `None` with nothing mounted at `/`.
    fn walk(&self, abs: &str, follow_final: bool) -> Result<Option<Walked>, Errno> {
        let Some(root) = self.mounts.get("/") else {
            return Ok(None);
        };
        root.walk(abs, follow_final, &self.others).map(Some)
    }

    /// `abs` fully resolved in the root filesystem, final link and all, and
    /// that filesystem with the path relative to it; `None` when the walk
    /// reached another mount, which the caller resolves the long way.
    fn resolve_final(&self, abs: &str) -> Result<Option<(&Arc<dyn FileSystem>, String)>, Errno> {
        self.resolve_walked(abs, true)
    }

    /// [`Vfs::resolve_final`], following the final link only with
    /// `follow_final`.
    fn resolve_walked(&self, abs: &str, follow_final: bool) -> Result<Option<(&Arc<dyn FileSystem>, String)>, Errno> {
        match self.walk(abs, follow_final)? {
            Some(w) if !w.at_mount => self.mount_of(w.path).map(Some),
            _ => Ok(None),
        }
    }

    /// `abs` with every symlink among its directories followed (not the
    /// final component: each caller decides about that). A filesystem here
    /// is a map of whole paths, so `/bin/sh` under a merged /usr (`/bin ->
    /// usr/bin`) names nothing until the `/bin` link is followed. The root
    /// filesystem's links, and those of a mount that keeps links
    /// ([`FileSystem::keeps_links`]: a tmpfs that is a process's `/dev`,
    /// with `fd` leading to `/proc/self/fd`); /proc and the like resolve
    /// their own names, and the walk ends at one.
    fn through_dir_links(&self, mut abs: String) -> Result<String, Errno> {
        'again: for _ in 0..40 {
            let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
            let mut prefix = String::new();
            for (i, c) in comps.iter().enumerate().take(comps.len().saturating_sub(1)) {
                prefix.push('/');
                prefix.push_str(c);
                let (at, fs) = self.mount_at(&prefix)?;
                let rel = if at == "/" {
                    prefix.trim_start_matches('/')
                } else if !fs.keeps_links() {
                    break;
                } else if prefix.len() == at.len() {
                    // The mount point itself: the mounted filesystem's root.
                    continue;
                } else {
                    &prefix[at.len() + 1..]
                };
                if let Ok(target) = fs.read_link(rel) {
                    let base = if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&prefix))
                    };
                    abs = normalize(&comps[i + 1..].join("/"), &base);
                    continue 'again;
                }
            }
            return Ok(abs);
        }
        Err(Errno::ELOOP)
    }

    /// The mount holding absolute path `abs`, and where it is mounted.
    fn mount_at<'a>(&'a self, abs: &str) -> Result<(&'a str, &'a Arc<dyn FileSystem>), Errno> {
        let mut best: Option<(&String, &Arc<dyn FileSystem>)> = None;
        for (at, fs) in &self.mounts {
            let matches = if at == "/" {
                true
            } else {
                within(abs, at)
            };
            if matches && best.map(|(b, _)| at.len() > b.len()).unwrap_or(true) {
                best = Some((at, fs));
            }
        }
        best.map(|(at, fs)| (at.as_str(), fs)).ok_or(Errno::ENOENT)
    }

    fn mount_of<'a>(&'a self, abs: String) -> Result<(&'a Arc<dyn FileSystem>, String), Errno> {
        let mut best: Option<(&String, &Arc<dyn FileSystem>)> = None;
        for (at, fs) in &self.mounts {
            let matches = if at == "/" {
                true
            } else {
                within(&abs, at)
            };
            if matches && best.map(|(b, _)| at.len() > b.len()).unwrap_or(true) {
                best = Some((at, fs));
            }
        }
        let (at, fs) = best.ok_or(Errno::ENOENT)?;
        let rel = if at == "/" {
            abs.trim_start_matches('/').to_string()
        } else {
            abs[at.len()..].trim_start_matches('/').to_string()
        };
        Ok((fs, rel))
    }

    /// Open a path, following symlinks up to a bounded depth.
    pub fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.open_with(path, |fs, rel| fs.open(rel, flags, mode)).map(|(h, _)| h)
    }

    /// [`Namespace::open`] by [`FileSystem::open_mode`]: a program's open,
    /// whose O_CREAT makes the file with exactly `mode`.
    pub fn open_mode(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.open_with(path, |fs, rel| fs.open_mode(rel, flags, mode)).map(|(h, _)| h)
    }

    /// [`Self::open_mode`], and the number of the device of the
    /// filesystem the file is in ([`FileSystem::dev`]): its `st_dev`.
    pub fn open_mode_on(&self, path: &str, flags: u64, mode: u32) -> Result<(Arc<dyn FileHandle>, u64), Errno> {
        self.open_with(path, |fs, rel| fs.open_mode(rel, flags, mode))
    }

    fn open_with(
        &self,
        path: &str,
        open: impl Fn(&Arc<dyn FileSystem>, &str) -> Result<Arc<dyn FileHandle>, Errno>,
    ) -> Result<(Arc<dyn FileHandle>, u64), Errno> {
        let mut current = normalize(path, &self.cwd);
        if let Some((fs, rel)) = self.resolve_final(&current)? {
            return open(fs, &rel).map(|h| (h, fs.dev()));
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            // O_NOFOLLOW and O_PATH are not modelled; a symlink is always
            // followed, which is what every caller here wants.
            match fs.read_link(&rel) {
                Ok(target) => {
                    current = if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        let parent = parent_of(&current);
                        normalize(&target, &parent)
                    };
                }
                Err(_) => return open(fs, &rel).map(|h| (h, fs.dev())),
            }
        }
        Err(Errno::ELOOP)
    }

    pub fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        // Borrowed when already normal, the usual case: no allocation.
        let mut current = normalize_cow(path, &self.cwd);
        // In the root, all links followed (`resolve_final`, then the
        // metadata there): one step.
        if let Some(root) = self.mounts.get("/") {
            if let Some(md) = root.walk_metadata(&current, &self.others)? {
                return Ok(md);
            }
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) => {
                    current = std::borrow::Cow::Owned(if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&current))
                    });
                }
                Err(_) => return fs.metadata(&rel),
            }
        }
        Err(Errno::ELOOP)
    }

    /// `access(2)` on `path`, following symlinks as [`Vfs::metadata`] does.
    pub fn access(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let mut current = normalize(path, &self.cwd);
        if let Some((fs, rel)) = self.resolve_final(&current)? {
            return fs.access(&rel, mode);
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) => {
                    current = if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&current))
                    };
                }
                Err(_) => return fs.access(&rel, mode),
            }
        }
        Err(Errno::ELOOP)
    }

    /// The filesystem holding what `path` names and the path in it, for an
    /// `inotify` watch: a final symlink followed unless `!follow`
    /// (`IN_DONT_FOLLOW`), as [`Vfs::access`] follows them.
    pub fn watch_target(&self, path: &str, follow: bool) -> Result<(Arc<dyn FileSystem>, String), Errno> {
        if !follow {
            let (fs, rel) = self.resolve(path)?;
            return Ok((Arc::clone(fs), rel));
        }
        let mut current = normalize(path, &self.cwd);
        if let Some((fs, rel)) = self.resolve_final(&current)? {
            return Ok((Arc::clone(fs), rel));
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) => {
                    current = if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&current))
                    };
                }
                Err(_) => return Ok((Arc::clone(fs), rel)),
            }
        }
        Err(Errno::ELOOP)
    }

    /// Metadata without following a final symlink, for `lstat`.
    pub fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.metadata_nofollow(&rel)
    }

    /// [`Self::metadata`] (`follow`) or [`Self::metadata_nofollow`], and
    /// the number of the device of the filesystem the file is in
    /// ([`FileSystem::dev`]): what `stat` says of a path.
    pub fn metadata_on(&self, path: &str, follow: bool) -> Result<(Metadata, u64), Errno> {
        // A host file's own filesystem's number where it says one
        // ([`Metadata::dev`]), by the same key the host tree's own number
        // is made from: the same number for every file on the tree's own
        // host filesystem, another across a host mount point.
        let own = |md: Metadata, fs_dev: u64| {
            let dev = if md.dev != 0 { anon_dev(DevKey::Host(md.dev)) } else { fs_dev };
            (md, dev)
        };
        if !follow {
            let (fs, rel) = self.resolve(path)?;
            return Ok(own(fs.metadata_nofollow(&rel)?, fs.dev()));
        }
        let mut current = normalize_cow(path, &self.cwd);
        // As `metadata`: in the root, one step.
        if let Some(root) = self.mounts.get("/") {
            if let Some(md) = root.walk_metadata(&current, &self.others)? {
                return Ok(own(md, root.dev()));
            }
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) => {
                    current = std::borrow::Cow::Owned(if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&current))
                    });
                }
                Err(_) => return Ok(own(fs.metadata(&rel)?, fs.dev())),
            }
        }
        Err(Errno::ELOOP)
    }

    pub fn read_link(&self, path: &str) -> Result<String, Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.read_link(&rel)
    }

    pub fn unlink(&self, path: &str) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.unlink(&rel)
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.mkdir(&rel, mode)
    }

    /// `BPF_OBJ_PIN` at `path` (its last name not followed): `EPERM`
    /// where that is not in a bpffs (`bpf_obj_do_pin`).
    pub fn bpf_pin(&self, path: &str, obj: crate::bpf::Object, mode: u32, uid: u32, gid: u32) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        let bpf = fs.bpf().ok_or(Errno::EPERM)?;
        bpf.pin(rel.trim_matches('/'), obj, mode, uid, gid)
    }

    /// `BPF_OBJ_GET` of `path` (its last name followed): the object pinned
    /// there; `EACCES` for anything else that is there.
    pub fn bpf_get(&self, path: &str) -> Result<crate::bpf::Object, Errno> {
        let abs = normalize(path, &self.cwd);
        let (fs, rel) = match self.resolve_walked(&abs, true)? {
            Some(found) => found,
            None => self.resolve(&abs)?,
        };
        match fs.bpf() {
            Some(bpf) => bpf.get(rel.trim_matches('/')),
            None => {
                fs.metadata(&rel)?;
                Err(Errno::EACCES)
            }
        }
    }

    pub fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.rmdir(&rel)
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        self.rename2(from, to, false)
    }

    /// `rename`, or with `noreplace` `RENAME_NOREPLACE`: `EEXIST` for a
    /// destination that exists, decided with the move by the filesystem.
    pub fn rename2(&self, from: &str, to: &str, noreplace: bool) -> Result<(), Errno> {
        let (fs, rel_from) = self.resolve(from)?;
        let (fs_to, rel_to) = self.resolve(to)?;
        // Crossing a mount boundary needs a copy, which Linux also refuses.
        if !Arc::ptr_eq(fs, fs_to) {
            return Err(Errno::EXDEV);
        }
        fs.rename2(&rel_from, &rel_to, noreplace)
    }

    pub fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.chmod(&rel, mode)
    }

    /// Where the file `path` names is, for whoever labels it: its
    /// filesystem's type, its path from that filesystem's root (with a
    /// leading slash) and what it is; the link itself without `follow`.
    pub fn located(&self, path: &str, follow: bool) -> Result<(&'static str, String, Metadata), Errno> {
        let abs = normalize(path, &self.cwd);
        let (fs, rel) = match self.resolve_walked(&abs, follow)? {
            Some(found) => found,
            None => self.resolve(&abs)?,
        };
        let md = if follow { fs.metadata(&rel)? } else { fs.metadata_nofollow(&rel)? };
        Ok((fs.fs_type(), format!("/{}", rel.trim_start_matches('/')), md))
    }

    /// An extended-attribute call on `path`, following a final symlink when
    /// `follow` (`getxattr`; `lgetxattr` does not).
    pub fn xattr(&self, path: &str, follow: bool, op: XattrOp<'_>) -> Result<usize, Errno> {
        let abs = normalize(path, &self.cwd);
        if let Some((fs, rel)) = self.resolve_walked(&abs, follow)? {
            return fs.xattr(&rel, op);
        }
        let (fs, rel) = self.resolve(&abs)?;
        fs.xattr(&rel, op)
    }

    /// [`FileSystem::chown`] of `path`, a final symlink followed with
    /// `follow`.
    pub fn chown(&self, path: &str, follow: bool, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let abs = normalize(path, &self.cwd);
        if let Some((fs, rel)) = self.resolve_walked(&abs, follow)? {
            return fs.chown(&rel, uid, gid);
        }
        let mut current = abs;
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) if follow => current = if target.starts_with('/') { normalize(&target, "/") } else { normalize(&target, &parent_of(&current)) },
                _ => return fs.chown(&rel, uid, gid),
            }
        }
        Err(Errno::ELOOP)
    }

    /// Set the modification time of `path`, following a final symlink when
    /// `follow` (as `utimensat` does without `AT_SYMLINK_NOFOLLOW`).
    pub fn set_mtime(&self, path: &str, secs: i64, follow: bool) -> Result<(), Errno> {
        self.set_times(path, None, Some((secs, 0)), follow)
    }

    /// Set the access and modification times of `path` (`None`: leave it),
    /// following a final symlink when `follow`.
    pub fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>, follow: bool) -> Result<(), Errno> {
        let mut current = normalize(path, &self.cwd);
        // On the root filesystem one walk names the node (the link itself
        // without `follow`), and setting its times says `ENOENT` for a
        // name that is not there.
        if let Some((fs, rel)) = self.resolve_walked(&current, follow)? {
            return fs.set_times(&rel, atime, mtime);
        }
        for _ in 0..40 {
            let (fs, rel) = self.resolve(&current)?;
            match fs.read_link(&rel) {
                Ok(target) if follow => {
                    current = if target.starts_with('/') {
                        normalize(&target, "/")
                    } else {
                        normalize(&target, &parent_of(&current))
                    };
                }
                // The link itself (AT_SYMLINK_NOFOLLOW), whether or not
                // what it names exists yet: dpkg stamps each link it unpacks
                // as `NAME.dpkg-new`, before its target has that name.
                Ok(_) => return fs.set_times(&rel, atime, mtime),
                Err(_) => {
                    fs.metadata(&rel)?;
                    return fs.set_times(&rel, atime, mtime);
                }
            }
        }
        Err(Errno::ELOOP)
    }

    /// `link`. Both names must be on one filesystem, as they must on Linux:
    /// a hard link is a second directory entry for the same inode, and an
    /// inode does not span mounts.
    pub fn link(&self, from: &str, to: &str) -> Result<(), Errno> {
        let (fs, rel_from) = self.resolve(from)?;
        let (fs_to, rel_to) = self.resolve(to)?;
        if !Arc::ptr_eq(fs, fs_to) {
            return Err(Errno::EXDEV);
        }
        fs.link(&rel_from, &rel_to)
    }

    /// Create a filesystem node for a bound UNIX socket.
    pub fn mksocket(&self, path: &str) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.mksocket(&rel)
    }

    /// Create a device node ([`FileSystem::mknod`]).
    pub fn mknod(&self, path: &str, mode: u32, rdev: u64) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.mknod(&rel, mode, rdev)
    }

    pub fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        let (fs, rel) = self.resolve(path)?;
        fs.symlink(target, &rel)
    }

    /// Resolve a path to its absolute, normalised form.
    pub fn absolute(&self, path: &str) -> String {
        normalize(path, &self.cwd)
    }

    fn set_cwd(&mut self, path: &str) -> Result<(), Errno> {
        let abs = normalize(path, &self.cwd);
        let md = self.metadata(&abs)?;
        if md.file_type != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        self.cwd = abs;
        Ok(())
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    static MAKER: std::cell::Cell<Option<(u32, u32)>> = const { std::cell::Cell::new(None) };
}

/// Whose a file made now is: the user and group of the process making
/// the call this thread is in. A filesystem that keeps owners gives what
/// it makes to them ([`Maker::current`]); the call says who it is for as
/// long as it lasts ([`Maker::enter`]), since making a file is asked of a
/// filesystem by path, with no word of who asks.
pub struct Maker(Option<(u32, u32)>);

impl Maker {
    /// From now until the value is dropped, files are made by `uid` and
    /// `gid` (the caller's filesystem ids).
    pub fn enter(uid: u32, gid: u32) -> Maker {
        Maker(MAKER.with(|m| m.replace(Some((uid, gid)))))
    }

    /// Who makes a file now; `None` when it is the kernel or its host.
    pub fn current() -> Option<(u32, u32)> {
        MAKER.with(|m| m.get())
    }
}

impl Drop for Maker {
    fn drop(&mut self) {
        MAKER.with(|m| m.set(self.0));
    }
}

/// A mount as `/proc/mounts` and `/proc/self/mountinfo` list it.
#[derive(Clone, Debug)]
pub struct MountLine {
    /// Where it is mounted.
    pub at: String,
    pub fs_type: &'static str,
    /// What it was mounted from, and its flags.
    pub record: mounted::Record,
    /// The filesystem's own options ([`FileSystem::show_options`]).
    pub fs_options: String,
    /// The number of the device it is on ([`FileSystem::dev`]).
    pub dev: u64,
}

impl MountLine {
    /// The options of what is mounted: `ro` or `rw`, the flags that are
    /// the filesystem's, `seclabel` where SELinux labels its files, and
    /// its own.
    pub fn super_options(&self) -> String {
        let label = if crate::selinux::shows_seclabel(self.fs_type) { ",seclabel" } else { "" };
        format!("{}{}{label}{}", if self.record.read_only() { "ro" } else { "rw" }, self.record.super_options(), self.fs_options)
    }

    /// The options of the mount: `ro` or `rw`, and the flags that are the
    /// mount's.
    pub fn mount_options(&self) -> String {
        format!("{}{}", if self.record.read_only() { "ro" } else { "rw" }, self.record.mount_options())
    }
}

/// Where [`walk_links`] got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    /// The absolute path reached.
    pub path: String,
    /// It stopped at another mount (`mounts`), which resolves its own names:
    /// the caller carries on from `path` there.
    pub at_mount: bool,
}

/// Follow the root filesystem's symlinks through absolute path `abs`: every
/// directory's, and the last component's too with `follow_final`. Stops,
/// with `at_mount`, at the first prefix inside one of `mounts` (absolute,
/// not `/`), whose filesystem names its own links. `read_link` takes a path
/// relative to the root. At most 40 links, as Linux.
///
/// The one walk both the per-process [`Vfs`] and the browser's global kernel
/// run, so a whole lookup there is one call rather than a round trip per
/// directory.
pub fn walk_links(
    mut abs: String,
    follow_final: bool,
    mounts: &str,
    read_link: &dyn Fn(&str) -> Result<String, Errno>,
) -> Result<Walked, Errno> {
    let under = |p: &str| mounts.split('\0').any(|m| !m.is_empty() && within(p, m));
    if !is_normal(&abs) {
        abs = normalize(&abs, "/");
    }
    'again: for _ in 0..40 {
        // Each directory's prefix is a slice of `abs` (normalised: one slash
        // before every component), so a walk that meets no link builds
        // nothing.
        let last = abs.rfind('/').unwrap_or(0);
        let mut end = 0;
        while end < last {
            end = abs[end + 1..].find('/').map_or(abs.len(), |i| end + 1 + i);
            if end > last {
                break;
            }
            let prefix = &abs[..end];
            if under(prefix) {
                return Ok(Walked { path: abs, at_mount: true });
            }
            if let Ok(target) = read_link(&prefix[1..]) {
                let base = if target.starts_with('/') {
                    normalize(&target, "/")
                } else {
                    normalize(&target, &parent_of(prefix))
                };
                abs = normalize(&abs[end + 1..], &base);
                continue 'again;
            }
        }
        if !follow_final {
            return Ok(Walked { path: abs, at_mount: false });
        }
        if under(&abs) {
            return Ok(Walked { path: abs, at_mount: true });
        }
        match read_link(abs.trim_start_matches('/')) {
            Ok(target) => {
                abs = if target.starts_with('/') {
                    normalize(&target, "/")
                } else {
                    normalize(&target, &parent_of(&abs))
                };
            }
            Err(_) => return Ok(Walked { path: abs, at_mount: false }),
        }
    }
    Err(Errno::ELOOP)
}

/// [`walk_links`] where `abs` (normalised) has no link on it, without
/// building anything: `Some(at_mount)` for the walk's answer (`abs` itself,
/// stopped at one of `mounts` or not), `None` when it meets a link (or
/// `abs` is not normal), for `walk_links` to follow. The same questions in
/// the same order, so the same answer; most lookups meet no link, and the
/// walk's copy of the path was an allocation on every one.
pub fn walk_plain(abs: &str, follow_final: bool, mounts: &str, is_link: &dyn Fn(&str) -> bool) -> Option<bool> {
    if !is_normal(abs) {
        return None;
    }
    let under = |p: &str| mounts.split('\0').any(|m| !m.is_empty() && within(p, m));
    let last = abs.rfind('/').unwrap_or(0);
    let mut end = 0;
    while end < last {
        end = abs[end + 1..].find('/').map_or(abs.len(), |i| end + 1 + i);
        if end > last {
            break;
        }
        let prefix = &abs[..end];
        if under(prefix) {
            return Some(true);
        }
        if is_link(&prefix[1..]) {
            return None;
        }
    }
    if !follow_final {
        return Some(false);
    }
    if under(abs) {
        return Some(true);
    }
    if is_link(abs.trim_start_matches('/')) {
        return None;
    }
    Some(false)
}

/// Whether `abs` is within one of `mounts` (NUL-separated, as
/// [`walk_links`] takes them).
pub fn within_any(abs: &str, mounts: &str) -> bool {
    mounts.split('\0').any(|m| !m.is_empty() && within(abs, m))
}

/// Make a path absolute and remove `.`, `..` and redundant separators.
///
/// Purely lexical, like `realpath -m`: symlinks are resolved separately, by
/// the caller, so that a loop can be bounded.
pub fn normalize(path: &str, cwd: &str) -> String {
    if is_normal(path) {
        return path.to_string();
    }
    let combined = if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in combined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// [`normalize`], borrowing `path` when it is already normal.
pub fn normalize_cow<'a>(path: &'a str, cwd: &str) -> std::borrow::Cow<'a, str> {
    if is_normal(path) {
        std::borrow::Cow::Borrowed(path)
    } else {
        std::borrow::Cow::Owned(normalize(path, cwd))
    }
}

/// Whether `path` is already what [`normalize`] makes of it: absolute, and
/// no empty, `.` or `..` component (so no doubled or trailing slash).
pub fn is_normal(path: &str) -> bool {
    let b = path.as_bytes();
    if b.first() != Some(&b'/') {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    b[1..].split(|&c| c == b'/').all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// The directory containing `path`.
pub fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// The final component of a path.
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Serialise directory entries into the `getdents64` record format.
///
/// Returns the bytes written and how many entries were consumed, so the
/// caller can resume from the right place on the next call.
pub fn encode_dirents(entries: &[DirEntry], start: usize, buf_len: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut consumed = 0;
    for (i, e) in entries.iter().enumerate().skip(start) {
        let name = e.name.as_bytes();
        // struct linux_dirent64 { u64 ino; i64 off; u16 reclen; u8 type; char name[]; }
        let reclen = (19 + name.len() + 1).div_ceil(8) * 8;
        if out.len() + reclen > buf_len {
            break;
        }
        let mut rec = vec![0u8; reclen];
        rec[0..8].copy_from_slice(&e.ino.to_le_bytes());
        rec[8..16].copy_from_slice(&((i + 1) as i64).to_le_bytes());
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = e.file_type.dirent_type();
        rec[19..19 + name.len()].copy_from_slice(name);
        out.extend_from_slice(&rec);
        consumed = i + 1 - start;
    }
    (out, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_dots_and_roots() {
        assert_eq!(normalize("/a/b/../c", "/"), "/a/c");
        assert_eq!(normalize("b/c", "/a"), "/a/b/c");
        assert_eq!(normalize("..", "/a/b"), "/a");
        assert_eq!(normalize("../../..", "/a"), "/");
        assert_eq!(normalize(".", "/a/b"), "/a/b");
        assert_eq!(normalize("//a///b//", "/"), "/a/b");
        assert_eq!(normalize("/", "/x"), "/");
        // Already normal: returned as is, whatever the cwd.
        for p in ["/", "/a", "/a/b.c/..d"] {
            assert!(is_normal(p), "{p}");
            assert_eq!(normalize(p, "/x"), p);
        }
        for p in ["", "a", "//", "/a/", "/a//b", "/a/./b", "/a/..", "/."] {
            assert!(!is_normal(p), "{p}");
        }
    }

    /// One mount table for the processes of a mount namespace, as on
    /// Linux: what a fork's copy mounts its parent sees, and the other way
    /// about, each at its next look; a process with a root of its own sees
    /// the mounts under that root, where they are from there, and what it
    /// mounts is where it is in the namespace; and a process that leaves
    /// for a namespace of its own neither shows its mounts nor sees any
    /// made after, until it enters another's.
    #[test]
    fn a_mount_is_every_process_of_the_namespaces() {
        let root = Arc::new(TmpFs::new());
        for dir in ["a", "b", "jail", "jail/in", "c", "d"] {
            root.add_dir(dir);
        }
        let mut parent = Vfs::new();
        parent.mount("/", root);
        let mut child = parent.clone();
        let fs = || Arc::new(TmpFs::new()) as Arc<dyn FileSystem>;
        // The child mounts: the parent sees it, by its view at once and
        // in its own copy at its next call.
        child.mount("/a", fs());
        assert!(child.is_mount_point("/a") && parent.view().get().is_mount_point("/a"));
        assert!(!parent.is_mount_point("/a"), "not until it looks");
        parent.refresh();
        assert!(parent.is_mount_point("/a"));
        // And the parent's the child, a fork made later too.
        parent.mount("/b", fs());
        child.refresh();
        assert!(child.is_mount_point("/b") && parent.clone().is_mount_point("/b"));
        assert!(child.unmount("/b"));
        parent.refresh();
        assert!(!parent.is_mount_point("/b"));
        assert_eq!(parent.view().mount_ns().id(), child.view().mount_ns().id());

        // A mount of a process's own (its /proc) is that process's alone,
        // a fork starting with its parent's until it is given its own.
        let mine = fs();
        mine.open("parent", crate::fs::oflags::O_CREAT | crate::fs::oflags::O_WRONLY, 0o644).unwrap();
        parent.mount_own("/d", mine);
        child.refresh();
        assert!(parent.is_mount_point("/d") && !child.is_mount_point("/d") && parent.metadata("/d/parent").is_ok());
        let mut later = parent.clone();
        assert!(later.metadata("/d/parent").is_ok(), "its parent's, to begin with");
        later.mount_own("/d", fs());
        parent.refresh();
        assert!(later.metadata("/d/parent").is_err() && parent.metadata("/d/parent").is_ok());
        assert!(parent.unmount("/d") && !parent.is_mount_point("/d") && later.is_mount_point("/d"));

        // A root of its own: the namespace's mounts under it, from it.
        let mut jailed = parent.clone();
        jailed.chroot("/jail").unwrap();
        parent.mount("/jail/in", fs());
        parent.mount("/c", fs());
        jailed.refresh();
        assert!(jailed.is_mount_point("/in") && !jailed.is_mount_point("/c") && jailed.metadata("/c").is_err());
        assert_eq!(jailed.root(), "/jail");
        // What it mounts is in the namespace where it is there.
        jailed.mount("/in", fs());
        jailed.mount("/new", fs());
        parent.refresh();
        assert!(parent.is_mount_point("/jail/new") && !parent.is_mount_point("/new"));
        assert!(jailed.unmount("/new") && !jailed.unmount("/"));
        parent.refresh();
        assert!(!parent.is_mount_point("/jail/new"));

        // A namespace of its own: a copy as it stood, then apart.
        let mut apart = parent.clone();
        apart.unshare_mounts();
        assert!(apart.is_mount_point("/a") && apart.is_mount_point("/c"));
        assert_ne!(apart.view().mount_ns().id(), parent.view().mount_ns().id());
        apart.mount("/d", fs());
        assert!(apart.unmount("/a"));
        parent.mount("/b", fs());
        parent.refresh();
        apart.refresh();
        assert!(!parent.is_mount_point("/d") && parent.is_mount_point("/a"), "the parent sees nothing of it");
        assert!(!apart.is_mount_point("/b") && apart.is_mount_point("/d"), "nor it of the parent");
        // A fork of it is in its namespace.
        let mut its_child = apart.clone();
        its_child.mount("/b", fs());
        apart.refresh();
        assert!(apart.is_mount_point("/b"));
        // And another process may enter it: its table, from its root.
        jailed.join_mounts(apart.view().mount_ns());
        assert!(jailed.is_mount_point("/d") && jailed.is_mount_point("/jail/in") && !jailed.is_mount_point("/a"));
        assert_eq!((jailed.root(), jailed.cwd.as_str()), ("/", "/"));
    }

    /// A bind mount shows what is at one place at another: the same
    /// files, with what is mounted under it only when that is asked for.
    #[test]
    fn a_bind_shows_a_directory_in_another_place() {
        let root = Arc::new(TmpFs::new());
        for dir in ["src", "src/sub", "dst", "all"] {
            root.add_dir(dir);
        }
        root.add_file("src/file", b"here".to_vec());
        let sub = Arc::new(TmpFs::new());
        sub.add_file("inner", b"deep".to_vec());
        let mut v = Vfs::new();
        v.mount("/", root);
        v.mount("/src/sub", sub);
        let read = |v: &Vfs, p: &str| {
            let h = v.open(p, 0, 0).map_err(|e| e.0)?;
            let mut b = [0u8; 16];
            let n = h.read_at(0, &mut b).map_err(|e| e.0)?;
            Ok::<_, i32>(String::from_utf8_lossy(&b[..n as usize]).into_owned())
        };
        v.view().bind("/src", "/dst", false).unwrap();
        v.refresh();
        assert!(v.is_mount_point("/dst"));
        assert_eq!(read(&v, "/dst/file").unwrap(), "here");
        assert!(read(&v, "/dst/sub/inner").is_err(), "what is mounted under it does not come unasked");
        // The same files: what is made through one is in the other.
        v.open("/dst/new", crate::fs::oflags::O_CREAT | crate::fs::oflags::O_WRONLY, 0o644).unwrap().write_at(0, b"made").unwrap();
        assert_eq!(read(&v, "/src/new").unwrap(), "made");
        v.view().bind("/src", "/all", true).unwrap();
        v.refresh();
        assert_eq!((read(&v, "/all/file").unwrap(), read(&v, "/all/sub/inner").unwrap()), ("here".to_string(), "deep".to_string()));
        assert!(v.is_mount_point("/all/sub"));
        // A whole filesystem bound is that filesystem; and nothing bound
        // from nothing.
        v.view().bind("/src/sub", "/dst", false).unwrap();
        v.refresh();
        assert_eq!(read(&v, "/dst/inner").unwrap(), "deep");
        assert!(v.unmount("/dst") && v.unmount("/all/sub") && v.unmount("/all"));
        assert_eq!(read(&v, "/src/file").unwrap(), "here");
    }

    /// What is mounted under a shared mount is mounted in every namespace
    /// that has that mount, and unmounted from them all; under a private
    /// one it is the namespace's own; a slave takes and does not give
    /// (the reference's rules: Documentation/filesystems/sharedsubtree.rst).
    #[test]
    fn a_mount_under_a_shared_mount_spreads() {
        let fs = || Arc::new(TmpFs::new()) as Arc<dyn FileSystem>;
        let mut one = Vfs::new();
        one.mount("/", fs());
        one.mount("/s", fs());
        one.mount("/p", fs());
        assert!(one.view().set_propagation("/s", Propagation::Shared, false));
        assert!(!one.view().set_propagation("/nothing", Propagation::Shared, false));
        let mut two = one.clone();
        two.unshare_mounts();
        let look = |a: &mut Vfs, b: &mut Vfs| {
            a.refresh();
            b.refresh();
        };
        // Under the shared mount: both; under the private ones: its own.
        two.mount("/s/x", fs());
        two.mount("/p/x", fs());
        two.mount("/y", fs());
        look(&mut one, &mut two);
        assert!(one.is_mount_point("/s/x") && !one.is_mount_point("/p/x") && !one.is_mount_point("/y"));
        one.mount("/s/z", fs());
        look(&mut one, &mut two);
        assert!(two.is_mount_point("/s/z"));
        // What spread is shared in its turn, and an unmount spreads as the
        // mount did.
        one.mount("/s/x/deep", fs());
        look(&mut one, &mut two);
        assert!(two.is_mount_point("/s/x/deep"));
        assert!(two.unmount("/s/z"));
        look(&mut one, &mut two);
        assert!(!one.is_mount_point("/s/z") && one.is_mount_point("/s/x"));
        // A third namespace, a copy of the second, is a peer too.
        let mut three = two.clone();
        three.unshare_mounts();
        three.mount("/s/w", fs());
        look(&mut one, &mut two);
        assert!(one.is_mount_point("/s/w") && two.is_mount_point("/s/w"));
        // A slave takes what its peers mount and gives nothing.
        assert!(two.view().set_propagation("/s", Propagation::Slave, false));
        one.mount("/s/from-one", fs());
        two.mount("/s/from-two", fs());
        look(&mut one, &mut two);
        three.refresh();
        assert!(two.is_mount_point("/s/from-one") && !one.is_mount_point("/s/from-two") && !three.is_mount_point("/s/from-two"));
        // Private again: nothing comes or goes.
        assert!(two.view().set_propagation("/s", Propagation::Private, false));
        one.mount("/s/later", fs());
        look(&mut one, &mut two);
        assert!(!two.is_mount_point("/s/later"));
        // Everything shared, as Android's init makes it, but one mount
        // made private after: the namespaces meet everywhere but there.
        let mut init = Vfs::new();
        init.mount("/", fs());
        init.mount("/apex", fs());
        assert!(init.view().set_propagation("/", Propagation::Shared, true));
        assert!(init.view().set_propagation("/apex", Propagation::Private, false));
        let mut other = init.clone();
        other.unshare_mounts();
        other.mount("/data", fs());
        other.mount("/apex/com.android.art", fs());
        init.mount("/apex/com.android.runtime", fs());
        look(&mut init, &mut other);
        assert!(init.is_mount_point("/data") && !init.is_mount_point("/apex/com.android.art") && !other.is_mount_point("/apex/com.android.runtime"));
    }

    /// `chroot`: the root a directory of the old one's filesystem, its
    /// mounts under it moved up, the rest out of sight; absolute links and
    /// `..` resolve inside it; a socket's name is the outer path; a second
    /// chroot nests; a fork's copy keeps it.
    #[test]
    fn chroot_resolves_inside_the_new_root() {
        let root = Arc::new(TmpFs::new());
        root.add_dir("srv");
        root.add_dir("srv/jail");
        root.add_dir("srv/jail/etc");
        root.add_dir("srv/jail/inner");
        root.add_dir("srv/jail/proc");
        root.add_file("srv/jail/etc/f", b"inside".to_vec());
        root.add_file("srv/jail/inner/g", b"deeper".to_vec());
        root.add_dir("etc");
        root.add_file("etc/f", b"outside".to_vec());
        root.symlink("/etc", "srv/jail/link").unwrap();
        let mut v = Vfs::new();
        v.mount("/", root);
        let proc_fs = Arc::new(TmpFs::new());
        proc_fs.add_file("version", b"p".to_vec());
        v.mount("/srv/jail/proc", proc_fs);
        v.mount("/elsewhere", Arc::new(TmpFs::new()));
        v.set_cwd("/srv/jail/inner").unwrap();
        let read = |v: &Vfs, p: &str| {
            let h = v.open(p, 0, 0).map_err(|e| e.0)?;
            let mut b = [0u8; 16];
            let n = h.read_at(0, &mut b).map_err(|e| e.0)?;
            Ok::<_, i32>(String::from_utf8_lossy(&b[..n as usize]).into_owned())
        };
        assert_eq!(read(&v, "/etc/f").unwrap(), "outside");
        assert_eq!(v.chroot("/srv/jail/etc/f").err(), Some(Errno::ENOTDIR));
        v.chroot("/srv/jail").unwrap();
        assert_eq!(v.root(), "/srv/jail");
        assert_eq!(v.cwd, "/inner");
        for p in ["/etc/f", "/link/f", "/../../etc/f", "/inner/../etc/f"] {
            assert_eq!(read(&v, p).unwrap(), "inside", "{p}");
        }
        assert_eq!(read(&v, "/proc/version").unwrap(), "p");
        assert!(v.metadata("/elsewhere").is_err());
        assert!(v.metadata("/srv").is_err());
        assert_eq!(v.read_link("/link").unwrap(), "/etc");
        assert_eq!(v.outer_path("/run/s"), "/srv/jail/run/s");
        assert_eq!(v.outer_path("\0abstract"), "\0abstract");
        let child = v.clone();
        assert_eq!(read(&child, "/etc/f").unwrap(), "inside");
        assert_eq!(child.root(), "/srv/jail");
        v.chroot("/inner").unwrap();
        assert_eq!(v.root(), "/srv/jail/inner");
        assert_eq!(v.cwd, "/");
        assert_eq!(read(&v, "/g").unwrap(), "deeper");
        // The published view has it too.
        assert_eq!(v.view().get().root(), "/srv/jail/inner");
    }

    #[test]
    fn tmpfs_walks_under_one_lock_as_walk_links_does() {
        let fs = TmpFs::new();
        fs.add_dir("usr");
        fs.add_dir("usr/bin");
        fs.add_file("usr/bin/dash", vec![]);
        fs.symlink("usr/bin", "bin").unwrap();
        fs.symlink("dash", "usr/bin/sh").unwrap();
        let w = |p: &str, f: bool| fs.walk(p, f, "/proc").unwrap();
        assert_eq!(w("/bin/sh", false), Walked { path: "/usr/bin/sh".into(), at_mount: false });
        assert_eq!(w("/bin/sh", true), Walked { path: "/usr/bin/dash".into(), at_mount: false });
        assert_eq!(w("/proc/1/exe", true), Walked { path: "/proc/1/exe".into(), at_mount: true });
        assert_eq!(w("//bin/./sh", true), Walked { path: "/usr/bin/dash".into(), at_mount: false });
    }

    /// TmpFs's one-lock `walk_metadata` answers as a walk and then a
    /// metadata do (the trait's own `walk_metadata`).
    #[test]
    fn tmpfs_walk_metadata_is_walk_then_metadata() {
        let fs = TmpFs::new();
        fs.add_dir("usr");
        fs.add_dir("usr/bin");
        fs.add_file("usr/bin/dash", vec![1, 2, 3]);
        fs.symlink("usr/bin", "bin").unwrap();
        fs.symlink("dash", "usr/bin/sh").unwrap();
        fs.symlink("nowhere", "usr/dangling").unwrap();
        fs.symlink("/proc/self", "self").unwrap();
        let mounts = "/proc\0/w";
        for p in ["/", "/usr", "/usr/bin", "/usr/bin/dash", "/usr/bin/sh", "/bin", "/bin/sh", "/bin/dash", "/usr/dangling",
                  "/usr/missing", "/missing/x", "/proc", "/proc/1", "/w", "/w/x", "/self", "/self/exe", "//usr/./bin/sh",
                  "/usr/bin/dash/x"] {
            let fast = fs.walk_metadata(p, mounts);
            let slow = fs.walk(p, true, mounts).and_then(|w| {
                if w.at_mount { Ok(None) } else { fs.metadata(w.path.trim_start_matches('/')).map(Some) }
            });
            assert_eq!(fast.map(|m| m.map(|m| (m.file_type, m.size, m.ino))), slow.map(|m| m.map(|m| (m.file_type, m.size, m.ino))), "{p}");
        }
    }

    #[test]
    fn parent_and_basename() {
        assert_eq!(parent_of("/a/b/c"), "/a/b");
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(basename("/a/b/c"), "c");
        assert_eq!(basename("c"), "c");
    }

    #[test]
    fn longest_mount_prefix_wins() {
        let mut vfs = Vfs::new();
        vfs.mount("/", Arc::new(TmpFs::new()));
        vfs.mount("/proc", Arc::new(TmpFs::new()));
        let (_, rel) = vfs.resolve("/proc/self/maps").unwrap();
        assert_eq!(rel, "self/maps");
        let (_, rel) = vfs.resolve("/etc/passwd").unwrap();
        assert_eq!(rel, "etc/passwd");
        // A path that merely starts with the same letters is not inside it.
        let (_, rel) = vfs.resolve("/procession").unwrap();
        assert_eq!(rel, "procession");
    }

    #[test]
    fn directory_symlinks_are_followed() {
        // A merged /usr: /bin -> usr/bin, /lib -> /usr/lib (absolute).
        let mut vfs = Vfs::new();
        let root = Arc::new(TmpFs::new());
        root.add_file("usr/bin/dash", b"sh".to_vec());
        root.add_file("usr/lib/ld.so", b"ld".to_vec());
        vfs.mount("/", root);
        vfs.symlink("usr/bin", "/bin").unwrap();
        vfs.symlink("/usr/lib", "/lib").unwrap();
        vfs.symlink("dash", "/usr/bin/sh").unwrap();
        assert_eq!(vfs.resolve("/bin/dash").unwrap().1, "usr/bin/dash");
        assert_eq!(vfs.resolve("/lib/ld.so").unwrap().1, "usr/lib/ld.so");
        // The final component is left to the caller.
        assert_eq!(vfs.resolve("/bin").unwrap().1, "bin");
        assert_eq!(vfs.read_link("/bin/sh").unwrap(), "dash");
        assert!(vfs.metadata("/bin/sh").is_ok());
        assert!(vfs.metadata("/bin/../lib/ld.so").is_ok());
    }

    /// A `..` is the parent of where the names before it lead, not of
    /// the last name written.
    #[test]
    fn dotdot_is_taken_from_where_a_link_leads() {
        let mut vfs = Vfs::new();
        let root = Arc::new(TmpFs::new());
        root.add_file("real/sub/deep", b"deep".to_vec());
        root.add_file("real/inside", b"in".to_vec());
        root.add_file("top", b"top".to_vec());
        vfs.mount("/", root);
        let other = Arc::new(TmpFs::new());
        other.add_file("far/there", b"other".to_vec());
        vfs.mount("/mnt", other);
        vfs.symlink("real/sub", "/down").unwrap();
        vfs.symlink("/mnt/far", "/across").unwrap();
        vfs.symlink("/real", "/mnt/back").unwrap();
        let p = |path: &str, base: &str| vfs.physical(path, base);
        assert_eq!(p("/down/../inside", "/").unwrap(), "/real/inside");
        assert_eq!(p("down/../inside", "/").unwrap(), "/real/inside");
        assert_eq!(p("/real/sub/../inside", "/").unwrap(), "/real/inside");
        assert_eq!(p("/across/../far/there", "/").unwrap(), "/mnt/far/there");
        assert_eq!(p("/mnt/back/../top", "/").unwrap(), "/top");
        assert_eq!(p("/down/../../top", "/").unwrap(), "/top");
        // From a directory that was named through a link.
        assert_eq!(p("../inside", "/down").unwrap(), "/real/inside");
        assert_eq!(p("..", "/down").unwrap(), "/real");
        assert_eq!(p("../..", "/real/sub").unwrap(), "/");
        // The root's parent is the root.
        assert_eq!(p("/../../top", "/").unwrap(), "/top");
        assert_eq!(p("..", "/").unwrap(), "/");
        // What a `..` follows has to be a directory that is there.
        assert_eq!(p("/nothing/../top", "/"), Err(Errno::ENOENT));
        assert_eq!(p("/top/../real", "/"), Err(Errno::ENOTDIR));
        assert_eq!(p("/real/inside/..", "/"), Err(Errno::ENOTDIR));
        // With no `..` it asks nothing.
        assert_eq!(p("/nothing/./at//all", "/").unwrap(), "/nothing/at/all");
    }

    /// A mounted tmpfs's links to directories are followed too, wherever
    /// they lead: within it, by an absolute name, and into another mount.
    #[test]
    fn a_mounts_directory_links_are_followed() {
        let mut vfs = Vfs::new();
        let root = Arc::new(TmpFs::new());
        root.add_file("data/file", b"root's".to_vec());
        vfs.mount("/", root);
        let dev = Arc::new(TmpFs::new());
        dev.add_file("real/inside", b"in".to_vec());
        vfs.mount("/dev", dev);
        let other = Arc::new(TmpFs::new());
        other.add_file("sub/there", b"other".to_vec());
        vfs.mount("/other", other);
        vfs.symlink("real", "/dev/rel").unwrap();
        vfs.symlink("/dev/real", "/dev/abs").unwrap();
        vfs.symlink("/data", "/dev/out").unwrap();
        vfs.symlink("/other/sub", "/dev/across").unwrap();
        vfs.symlink("../data", "/dev/up").unwrap();
        vfs.symlink("rel", "/dev/twice").unwrap();
        assert_eq!(vfs.resolve("/dev/rel/inside").unwrap().1, "real/inside");
        assert_eq!(vfs.resolve("/dev/abs/inside").unwrap().1, "real/inside");
        assert_eq!(vfs.resolve("/dev/twice/inside").unwrap().1, "real/inside");
        assert_eq!(vfs.resolve("/dev/out/file").unwrap().1, "data/file");
        assert_eq!(vfs.resolve("/dev/up/file").unwrap().1, "data/file");
        assert_eq!(vfs.resolve("/dev/across/there").unwrap().1, "sub/there");
        assert!(vfs.metadata("/dev/twice/inside").is_ok());
        assert!(vfs.metadata("/dev/across/there").is_ok());
        assert_eq!(vfs.metadata("/dev/rel/nothing").err(), Some(Errno::ENOENT));
        // The final name is still the caller's to follow or not.
        assert_eq!(vfs.resolve("/dev/rel").unwrap().1, "rel");
        assert_eq!(vfs.read_link("/dev/twice").unwrap(), "rel");
        // A loop ends.
        vfs.symlink("b", "/dev/a").unwrap();
        vfs.symlink("a", "/dev/b").unwrap();
        assert_eq!(vfs.metadata("/dev/a/x").err(), Some(Errno::ELOOP));
    }

    #[test]
    fn dirents_encode_and_stop_at_the_buffer() {
        let entries = vec![
            DirEntry {
                name: ".".into(),
                file_type: FileType::Directory,
                ino: 1,
            },
            DirEntry {
                name: "file".into(),
                file_type: FileType::Regular,
                ino: 2,
            },
        ];
        let (buf, n) = encode_dirents(&entries, 0, 4096);
        assert_eq!(n, 2);
        // Each record is 8-byte aligned and self-describing.
        let reclen = u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize;
        assert_eq!(reclen % 8, 0);
        assert_eq!(buf[18], FileType::Directory.dirent_type());
        assert_eq!(&buf[19..20], b".");
        // A buffer that fits nothing consumes nothing.
        let (buf, n) = encode_dirents(&entries, 0, 8);
        assert!(buf.is_empty());
        assert_eq!(n, 0);
    }

    #[test]
    fn one_lookup_answers_eisdir_enoent_and_a_links_own_times() {
        use crate::fs::oflags::{O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
        let fs = Arc::new(tmpfs::TmpFs::new());
        fs.add_dir("d");
        fs.add_file("d/f", b"x".to_vec());
        fs.symlink("gone", "d/dangling").unwrap();
        let mut vfs = Vfs::new();
        vfs.mount("/", fs.clone());
        // A directory opens for reading only, with or without O_CREAT.
        assert!(vfs.open("/d", O_RDONLY, 0).is_ok());
        assert_eq!(vfs.open("/d", O_WRONLY, 0).unwrap_err(), Errno::EISDIR);
        assert_eq!(vfs.open("/d", O_RDWR | O_CREAT, 0o644).unwrap_err(), Errno::EISDIR);
        // Times on a missing name: ENOENT, following or not.
        let t = Some((5, 0));
        assert_eq!(vfs.set_times("/d/nope", t, t, true), Err(Errno::ENOENT));
        assert_eq!(vfs.set_times("/d/nope", t, t, false), Err(Errno::ENOENT));
        // A dangling link's own times are set; through it there is nothing.
        assert_eq!(vfs.set_times("/d/dangling", t, t, false), Ok(()));
        assert_eq!(vfs.set_times("/d/dangling", t, t, true), Err(Errno::ENOENT));
        assert_eq!(vfs.set_times("/d/f", t, Some((7, 0)), true), Ok(()));
        assert_eq!(vfs.metadata("/d/f").unwrap().mtime, 7);
        // fchmod by handle: the name it was opened under.
        let h = vfs.open("/d/f", O_RDWR, 0).unwrap();
        assert_eq!(h.chmod(0o600), Some(Ok(())));
        assert_eq!(vfs.metadata("/d/f").unwrap().mode & 0o7777, 0o600);
    }

    #[test]
    fn walk_links_follows_dirs_final_and_stops_at_mounts() {
        let links = |rel: &str| match rel {
            "bin" => Ok("usr/bin".to_string()),
            "usr/bin/sh" => Ok("dash".to_string()),
            "loop" => Ok("/loop".to_string()),
            "var/run" => Ok("/run".to_string()),
            _ => Err(Errno::EINVAL),
        };
        let w = |p: &str, f: bool| walk_links(p.to_string(), f, "/proc\0/run", &links);
        assert_eq!(w("/bin/sh", false).unwrap(), Walked { path: "/usr/bin/sh".into(), at_mount: false });
        assert_eq!(w("/bin/sh", true).unwrap(), Walked { path: "/usr/bin/dash".into(), at_mount: false });
        assert_eq!(w("/proc/self/exe", true).unwrap(), Walked { path: "/proc/self/exe".into(), at_mount: true });
        assert_eq!(w("/var/run/x/y", false).unwrap(), Walked { path: "/run/x/y".into(), at_mount: true });
        assert_eq!(w("/run", true).unwrap(), Walked { path: "/run".into(), at_mount: true });
        assert_eq!(w("/loop", true), Err(Errno::ELOOP));
        assert_eq!(w("/", true).unwrap(), Walked { path: "/".into(), at_mount: false });
    }

    /// `walk_plain` answers as `walk_links` wherever it answers, and hands
    /// every path with a link on it (or not normal) to `walk_links`.
    #[test]
    fn walk_plain_answers_as_walk_links_or_not_at_all() {
        let links = |rel: &str| match rel {
            "bin" => Ok("usr/bin".to_string()),
            "usr/bin/sh" => Ok("dash".to_string()),
            "var/run" => Ok("/run".to_string()),
            "proc2" => Ok("/proc".to_string()),
            _ => Err(Errno::EINVAL),
        };
        let mounts = "/proc\0/run\0/w";
        let paths = [
            "/", "/usr", "/usr/bin", "/usr/bin/dash", "/usr/bin/sh", "/bin", "/bin/sh", "/var/run", "/var/run/x",
            "/proc", "/proc/self/exe", "/procession/x", "/run", "/w", "/w/a/b", "/tmp/missing.txt", "/a/b/c/d/e/f",
            "/proc2/x", "/usr//bin", "/usr/./bin", "/usr/../bin/sh", "relative",
        ];
        let mut answered = 0;
        for p in paths {
            for f in [false, true] {
                let plain = walk_plain(p, f, mounts, &|rel| links(rel).is_ok());
                if let Some(at_mount) = plain {
                    answered += 1;
                    assert_eq!(Ok(Walked { path: p.to_string(), at_mount }), walk_links(p.to_string(), f, mounts, &links), "{p} {f}");
                } else {
                    // a link on the path (a directory's, or the last's when
                    // followed), or a path to normalise first
                    let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
                    let upto = if f { comps.len() } else { comps.len().saturating_sub(1) };
                    let link = (1..=upto).any(|n| links(&comps[..n].join("/")).is_ok());
                    assert!(!is_normal(p) || link, "{p} {f}: no answer, with no link on it");
                }
            }
        }
        assert!(answered > 20, "{answered}");
    }
}
