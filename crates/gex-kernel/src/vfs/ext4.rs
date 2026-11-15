//! ext4, read-only: the filesystem an Android APEX's payload is, and a
//! system image's partitions are.
//!
//! `apexd` mounts each APEX's `apex_payload.img` (through a loop device)
//! at `/apex/<name>`: an ext4 made by `mke2fs` with 4096-byte blocks,
//! 256-byte inodes, extents, no journal and no checksums, holding the
//! module's programs and libraries with their SELinux labels. This reads
//! such an image, and the others `mke2fs` makes, as fs/ext4 does
//! (android17-6.18), with the layouts of fs/ext4/ext4.h:
//!
//! - the superblock, and from it the block size, the groups and their
//!   descriptors (32 bytes, or 64 with the `64bit` feature), each group's
//!   inode table
//! - an inode: its mode, owner, size, times (with the extra epoch bits and
//!   nanoseconds), link count, device number
//! - a file's blocks, by its extent tree or (without the `extents` flag)
//!   its block map with one, two and three levels of indirection; a hole
//!   and an extent not yet written read as zeros
//! - a directory's entries, a block at a time (an indexed directory's
//!   index blocks are empty entries to this, as they are meant to be)
//! - a symbolic link's target, in the inode when it is short
//! - extended attributes, in the inode and in its attribute block: a
//!   file's SELinux label is `security.selinux`
//!
//! Nothing is written: every change is `EROFS`. An image is refused
//! (`EINVAL`, and a line on the host's standard error saying why) when it
//! has a feature this does not read: a journal that needs replaying,
//! inline data, encryption, case-folded names, attributes in inodes of
//! their own, `meta_bg`, multiple-mount protection, compression.
//!
//! Not as Linux: no checksum is verified (`metadata_csum`, the group
//! descriptors'); a file's owner is read but no file of this kernel
//! reports one yet; and FIFOs, sockets and block device nodes are there
//! to `stat` but do not open.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata, Times, XattrOp};
use crate::errno::{Errno, SysResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;
const EXTENT_MAGIC: u16 = 0xf30a;
const XATTR_MAGIC: u32 = 0xea02_0000;

const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// What of the incompatible features this reads. `csum_seed` only moves
/// the seed of checksums that are not verified here; `largedir` allows a
/// directory more blocks and index levels, which reading its blocks in
/// order does not care about.
const INCOMPAT_READ: u32 = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED | INCOMPAT_LARGEDIR;

const EXTENTS_FL: u32 = 0x8_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;

const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;
const S_IFLNK: u16 = 0o120000;
const S_IFREG: u16 = 0o100000;
const S_IFBLK: u16 = 0o060000;
const S_IFDIR: u16 = 0o040000;
const S_IFCHR: u16 = 0o020000;
const S_IFIFO: u16 = 0o010000;

/// Say once per kind that an image has something not read here.
fn unimplemented(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] ext4: {what} is not implemented");
        said.push(what.to_string());
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// An inode, as much of it as is used.
#[derive(Debug)]
struct Inode {
    ino: u32,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    links: u16,
    flags: u32,
    /// `i_block`: the root of the extent tree, the block map, a short
    /// link's target, or a device's number.
    block: [u8; 60],
    /// The block its other attributes are in, 0 for none.
    file_acl: u64,
    /// `i_blocks`, in 512-byte units.
    blocks: u64,
    mtime: (i64, u32),
    atime: (i64, u32),
    ctime: (i64, u32),
    /// The attributes kept in the inode, after its fixed fields: the
    /// bytes from their magic number on (empty when there are none).
    inline_attrs: Vec<u8>,
}

impl Inode {
    fn kind(&self) -> u16 {
        self.mode & S_IFMT
    }

    fn file_type(&self) -> FileType {
        match self.kind() {
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            S_IFCHR | S_IFBLK => FileType::CharDevice,
            S_IFIFO => FileType::Fifo,
            S_IFSOCK => FileType::Socket,
            _ => FileType::Regular,
        }
    }

    /// A device node's number, in `makedev`'s encoding: the old 16-bit
    /// form in the first word of `i_block` when that is not zero, else the
    /// new form in the second (`ext4_iget`).
    fn rdev(&self) -> u64 {
        if !matches!(self.kind(), S_IFCHR | S_IFBLK) {
            return 0;
        }
        let old = le32(&self.block, 0);
        if old != 0 {
            super::devices::makedev(old >> 8 & 0xff, old & 0xff)
        } else {
            // `new_decode_dev`'s layout is `makedev`'s.
            le32(&self.block, 4) as u64
        }
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            file_type: self.file_type(),
            size: self.size,
            mode: (self.mode & 0o7777) as u32,
            ino: self.ino as u64,
            mtime: self.mtime.0,
            nlink: self.links as u32,
            rdev: self.rdev(),
            times: Times { mtime_ns: self.mtime.1, atime: self.atime.0, atime_ns: self.atime.1, ctime: self.ctime.0, ctime_ns: self.ctime.1 },
        }
    }
}

/// A run of a file's blocks: `len` from logical block `first`, at `start`
/// on the device, or (`written` false) not yet written and read as zeros.
#[derive(Clone, Copy, Debug)]
struct Extent {
    first: u64,
    len: u64,
    start: u64,
    written: bool,
}

/// A directory entry: its name, inode, and type as the entry says it (0
/// where the filesystem's entries do not).
#[derive(Clone, Debug)]
struct Entry {
    name: String,
    ino: u32,
    kind: u8,
}

/// An ext4 filesystem on `dev`.
pub struct Ext4 {
    dev: Arc<dyn FileHandle>,
    block_size: u64,
    blocks_count: u64,
    inodes_count: u32,
    inodes_per_group: u32,
    inode_size: usize,
    incompat: u32,
    /// Each group's inode table's first block.
    inode_tables: Vec<u64>,
    /// Inodes and directories read so far: nothing here changes.
    inodes: Mutex<HashMap<u32, Arc<Inode>>>,
    dirs: Mutex<HashMap<u32, Arc<Vec<Entry>>>>,
}

impl std::fmt::Debug for Ext4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ext4").field("block_size", &self.block_size).field("blocks", &self.blocks_count).field("inodes", &self.inodes_count).finish()
    }
}

/// `EUCLEAN`, ext4's `EFSCORRUPTED`: the image is not as an ext4 is.
fn corrupt() -> Errno {
    Errno::EUCLEAN
}

impl Ext4 {
    /// The filesystem on `dev`, for a read-only mount. `EINVAL` when it is
    /// not an ext4 (or ext2, ext3) this can read.
    pub fn new(dev: Arc<dyn FileHandle>) -> Result<Ext4, Errno> {
        let mut sb = [0u8; 1024];
        read_exact(&dev, 1024, &mut sb).map_err(|_| Errno::EINVAL)?;
        if le16(&sb, 0x38) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let incompat = le32(&sb, 0x60);
        let refuse = |what: &str| {
            unimplemented(what);
            Err(Errno::EINVAL)
        };
        if incompat & INCOMPAT_RECOVER != 0 {
            return refuse("a journal that needs replaying");
        }
        if incompat & !INCOMPAT_READ != 0 {
            let names = [(0x1, "compression"), (0x8, "a journal device"), (0x10, "meta_bg"), (0x100, "multiple-mount protection"), (0x400, "attributes in inodes of their own"), (0x1000, "dirdata"), (0x8000, "inline data"), (0x1_0000, "encryption"), (0x2_0000, "case-folded names")];
            let named: Vec<&str> = names.iter().filter(|(bit, _)| incompat & bit != 0).map(|(_, n)| *n).collect();
            return refuse(&format!("an image with {} (incompatible features {:#x})", if named.is_empty() { "features unknown here".to_string() } else { named.join(", ") }, incompat & !INCOMPAT_READ));
        }
        let log_block_size = le32(&sb, 0x18);
        if log_block_size > 6 {
            return Err(Errno::EINVAL);
        }
        let block_size = 1024u64 << log_block_size;
        let wide = incompat & INCOMPAT_64BIT != 0;
        let blocks_count = le32(&sb, 0x04) as u64 | if wide { (le32(&sb, 0x150) as u64) << 32 } else { 0 };
        let first_data_block = le32(&sb, 0x14) as u64;
        let blocks_per_group = le32(&sb, 0x20) as u64;
        let inodes_per_group = le32(&sb, 0x28);
        let inodes_count = le32(&sb, 0x00);
        // Revision 0 has 128-byte inodes and says nothing of it.
        let inode_size = if le32(&sb, 0x4c) == 0 { 128 } else { le16(&sb, 0x58) as usize };
        let desc_size = if wide { le16(&sb, 0xfe) as usize } else { 32 };
        if blocks_per_group == 0 || inodes_per_group == 0 || inode_size < 128 || inode_size as u64 > block_size || !inode_size.is_power_of_two() || blocks_count <= first_data_block || (wide && (desc_size < 64 || !desc_size.is_power_of_two())) {
            return Err(Errno::EINVAL);
        }
        let groups = (blocks_count - first_data_block).div_ceil(blocks_per_group);
        if groups > 1 << 24 || groups * inodes_per_group as u64 != inodes_count as u64 {
            return Err(Errno::EINVAL);
        }
        // The descriptors follow the superblock's block.
        let mut table = vec![0u8; groups as usize * desc_size];
        read_exact(&dev, (first_data_block + 1) * block_size, &mut table).map_err(|_| Errno::EINVAL)?;
        let mut inode_tables = Vec::with_capacity(groups as usize);
        for g in 0..groups as usize {
            let d = &table[g * desc_size..(g + 1) * desc_size];
            let at = le32(d, 0x08) as u64 | if desc_size >= 64 { (le32(d, 0x28) as u64) << 32 } else { 0 };
            if at == 0 || at >= blocks_count {
                return Err(Errno::EINVAL);
            }
            inode_tables.push(at);
        }
        let fs = Ext4 { dev, block_size, blocks_count, inodes_count, inodes_per_group, inode_size, incompat, inode_tables, inodes: Mutex::new(HashMap::new()), dirs: Mutex::new(HashMap::new()) };
        // The root has to be a directory.
        if fs.inode(ROOT_INO).map_err(|_| Errno::EINVAL)?.kind() != S_IFDIR {
            return Err(Errno::EINVAL);
        }
        Ok(fs)
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>, Errno> {
        if block == 0 || block >= self.blocks_count {
            return Err(corrupt());
        }
        let mut buf = vec![0u8; self.block_size as usize];
        read_exact(&self.dev, block * self.block_size, &mut buf)?;
        Ok(buf)
    }

    fn inode(&self, ino: u32) -> Result<Arc<Inode>, Errno> {
        if ino == 0 || ino > self.inodes_count {
            return Err(corrupt());
        }
        if let Some(i) = self.inodes.lock().unwrap_or_else(|e| e.into_inner()).get(&ino) {
            return Ok(Arc::clone(i));
        }
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as u64;
        let mut raw = vec![0u8; self.inode_size];
        read_exact(&self.dev, self.inode_tables[group] * self.block_size + index * self.inode_size as u64, &mut raw)?;
        // The fields past the first 128 bytes, as far as the inode says
        // it has them.
        let extra = if self.inode_size > 128 { le16(&raw, 0x80) as usize } else { 0 };
        if 128 + extra > self.inode_size {
            return Err(corrupt());
        }
        // A time: 32 signed bits of seconds, and where the inode has the
        // extra word, two more bits of epoch and thirty of nanoseconds.
        let time = |at: usize, extra_at: usize| {
            let secs = le32(&raw, at) as i32 as i64;
            if 128 + extra >= extra_at + 4 {
                let e = le32(&raw, extra_at);
                (secs + (((e & 3) as i64) << 32), e >> 2)
            } else {
                (secs, 0)
            }
        };
        let attrs_at = 128 + extra;
        let inline_attrs = if self.inode_size > 128 && attrs_at + 4 <= self.inode_size && le32(&raw, attrs_at) == XATTR_MAGIC { raw[attrs_at..].to_vec() } else { Vec::new() };
        let mut block = [0u8; 60];
        block.copy_from_slice(&raw[0x28..0x28 + 60]);
        let inode = Arc::new(Inode {
            ino,
            mode: le16(&raw, 0x00),
            uid: le16(&raw, 0x02) as u32 | (le16(&raw, 0x78) as u32) << 16,
            gid: le16(&raw, 0x18) as u32 | (le16(&raw, 0x7a) as u32) << 16,
            size: le32(&raw, 0x04) as u64 | (le32(&raw, 0x6c) as u64) << 32,
            links: le16(&raw, 0x1a),
            flags: le32(&raw, 0x20),
            block,
            file_acl: le32(&raw, 0x68) as u64 | (le16(&raw, 0x76) as u64) << 32,
            blocks: le32(&raw, 0x1c) as u64 | (le16(&raw, 0x74) as u64) << 32,
            mtime: time(0x10, 0x88),
            atime: time(0x08, 0x8c),
            ctime: time(0x0c, 0x84),
            inline_attrs,
        });
        if inode.flags & INLINE_DATA_FL != 0 {
            unimplemented("inline data");
            return Err(Errno::EOPNOTSUPP);
        }
        self.inodes.lock().unwrap_or_else(|e| e.into_inner()).insert(ino, Arc::clone(&inode));
        Ok(inode)
    }

    /// Every extent of a file with an extent tree, in order.
    fn extents(&self, inode: &Inode) -> Result<Vec<Extent>, Errno> {
        let mut out = Vec::new();
        self.extent_node(&inode.block, 0, &mut out)?;
        Ok(out)
    }

    /// One node of an extent tree (`node`: the 60 bytes in the inode, or a
    /// block): its extents if it is a leaf, else its children's.
    fn extent_node(&self, node: &[u8], level: u32, out: &mut Vec<Extent>) -> Result<(), Errno> {
        if le16(node, 0) != EXTENT_MAGIC || level > 5 {
            return Err(corrupt());
        }
        let entries = le16(node, 2) as usize;
        let depth = le16(node, 6);
        if 12 + entries * 12 > node.len() {
            return Err(corrupt());
        }
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if depth == 0 {
                let len = le16(e, 4) as u64;
                // A length past 32768 is an extent allocated and not yet
                // written.
                let (len, written) = if len > 32768 { (len - 32768, false) } else { (len, true) };
                out.push(Extent { first: le32(e, 0) as u64, len, start: le32(e, 8) as u64 | (le16(e, 6) as u64) << 32, written });
            } else {
                let child = le32(e, 4) as u64 | (le16(e, 8) as u64) << 32;
                self.extent_node(&self.read_block(child)?, level + 1, out)?;
            }
        }
        Ok(())
    }

    /// Where logical block `block` of a file without an extent tree is,
    /// by its block map: twelve blocks named in the inode, then through
    /// one, two and three blocks of block numbers. `None` for a hole.
    fn mapped(&self, inode: &Inode, block: u64) -> Result<Option<u64>, Errno> {
        let per = self.block_size / 4;
        let direct = |at: usize| le32(&inode.block, at * 4) as u64;
        let (mut at, path): (u64, Vec<u64>) = if block < 12 {
            (direct(block as usize), Vec::new())
        } else if block - 12 < per {
            (direct(12), vec![block - 12])
        } else if block - 12 - per < per * per {
            let b = block - 12 - per;
            (direct(13), vec![b / per, b % per])
        } else if block - 12 - per - per * per < per * per * per {
            let b = block - 12 - per - per * per;
            (direct(14), vec![b / (per * per), b / per % per, b % per])
        } else {
            return Err(Errno::EFBIG);
        };
        for index in path {
            if at == 0 {
                return Ok(None);
            }
            at = le32(&self.read_block(at)?, index as usize * 4) as u64;
        }
        Ok((at != 0).then_some(at))
    }

    /// Read a file's bytes from `offset`: its blocks where it has them,
    /// zeros in a hole, nothing past its size.
    fn read_file(&self, inode: &Inode, extents: Option<&[Extent]>, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        if offset >= inode.size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(inode.size - offset) as usize;
        let bs = self.block_size;
        let mut done = 0;
        while done < want {
            let pos = offset + done as u64;
            let (block, within) = (pos / bs, pos % bs);
            // As far as this block, or (in an extent) the run of them, goes.
            let (start, run) = match extents {
                Some(extents) => match extents.iter().find(|e| block >= e.first && block < e.first + e.len) {
                    Some(e) => (e.written.then(|| e.start + (block - e.first)), e.first + e.len - block),
                    None => (None, 1),
                },
                None => (self.mapped(inode, block)?, 1),
            };
            let n = ((run * bs - within) as usize).min(want - done);
            match start {
                Some(start) => {
                    if start + run > self.blocks_count {
                        return Err(corrupt());
                    }
                    read_exact(&self.dev, start * bs + within, &mut buf[done..done + n])?;
                }
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(want)
    }

    /// The whole of a file that is metadata: a directory, a long link.
    fn contents(&self, inode: &Inode) -> Result<Vec<u8>, Errno> {
        // A directory of more than this is not one anybody made.
        if inode.size > 1 << 30 {
            return Err(Errno::EFBIG);
        }
        let extents = if inode.flags & EXTENTS_FL != 0 { Some(self.extents(inode)?) } else { None };
        let mut buf = vec![0u8; inode.size as usize];
        self.read_file(inode, extents.as_deref(), 0, &mut buf)?;
        Ok(buf)
    }

    /// A directory's entries, in the order they are in it.
    fn entries(&self, dir: &Inode) -> Result<Arc<Vec<Entry>>, Errno> {
        if dir.kind() != S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        if let Some(e) = self.dirs.lock().unwrap_or_else(|e| e.into_inner()).get(&dir.ino) {
            return Ok(Arc::clone(e));
        }
        let data = self.contents(dir)?;
        let bs = self.block_size as usize;
        let typed = self.incompat & INCOMPAT_FILETYPE != 0;
        let mut out = Vec::new();
        for block in data.chunks(bs) {
            let mut at = 0;
            while at + 8 <= block.len() {
                let ino = le32(block, at);
                let rec_len = match le16(block, at + 4) as usize {
                    // A 64 KiB block's whole length does not fit the field.
                    0 | 0xffff if bs == 65536 => 65536,
                    n => n,
                };
                // With types in the entries a name's length is a byte and
                // the type the next; without, the length is both.
                let (name_len, kind) = if typed { (block[at + 6] as usize, block[at + 7]) } else { (le16(block, at + 6) as usize, 0) };
                if rec_len < 8 || rec_len % 4 != 0 || at + rec_len > block.len() || 8 + name_len > rec_len {
                    return Err(corrupt());
                }
                if ino != 0 && name_len != 0 {
                    out.push(Entry { name: String::from_utf8_lossy(&block[at + 8..at + 8 + name_len]).into_owned(), ino, kind });
                }
                at += rec_len;
            }
        }
        let out = Arc::new(out);
        self.dirs.lock().unwrap_or_else(|e| e.into_inner()).insert(dir.ino, Arc::clone(&out));
        Ok(out)
    }

    /// The inode `path` names, from the root. A link among its
    /// directories is not followed: the namespace follows those before
    /// it asks ([`FileSystem::keeps_links`]), so one here is `ENOTDIR`.
    fn find(&self, path: &str) -> Result<Arc<Inode>, Errno> {
        let mut at = self.inode(ROOT_INO)?;
        for name in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            let entries = self.entries(&at)?;
            let entry = entries.iter().find(|e| e.name == name).ok_or(Errno::ENOENT)?;
            at = self.inode(entry.ino)?;
        }
        Ok(at)
    }

    /// A link's target: in the inode itself when the link has no blocks
    /// of its own (`ext4_inode_is_fast_symlink`), else its contents.
    fn target(&self, inode: &Inode) -> Result<String, Errno> {
        let attr_blocks = if inode.file_acl != 0 { self.block_size / 512 } else { 0 };
        let bytes = if inode.blocks == attr_blocks {
            if inode.size as usize > inode.block.len() {
                return Err(corrupt());
            }
            inode.block[..inode.size as usize].to_vec()
        } else {
            if inode.size > self.block_size {
                return Err(corrupt());
            }
            self.contents(inode)?
        };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// A file's extended attributes, by their whole names: those in the
    /// inode, then those in its attribute block.
    fn attrs(&self, inode: &Inode) -> Result<Vec<(String, Vec<u8>)>, Errno> {
        let mut out = Vec::new();
        if !inode.inline_attrs.is_empty() {
            // Entries after the magic number; a value's place is counted
            // from the first entry.
            attr_entries(&inode.inline_attrs, 4, 4, &mut out)?;
        }
        if inode.file_acl != 0 {
            let block = self.read_block(inode.file_acl)?;
            if le32(&block, 0) != XATTR_MAGIC {
                return Err(corrupt());
            }
            // Entries after a 32-byte header; a value's place is counted
            // from the block's start.
            attr_entries(&block, 32, 0, &mut out)?;
        }
        Ok(out)
    }
}

/// The attribute entries in `area` from `at`, each a 16-byte header and
/// its name, ended by four zero bytes; a value is at its offset from
/// `values`. The name's first part is a number (`ext4_xattr_handler`).
fn attr_entries(area: &[u8], mut at: usize, values: usize, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), Errno> {
    while at + 4 <= area.len() && le32(area, at) != 0 {
        if at + 16 > area.len() {
            return Err(corrupt());
        }
        let name_len = area[at] as usize;
        let prefix = match area[at + 1] {
            1 => "user.",
            2 => "system.posix_acl_access",
            3 => "system.posix_acl_default",
            4 => "trusted.",
            6 => "security.",
            7 => "system.",
            8 => "system.richacl",
            _ => return Err(corrupt()),
        };
        let value_at = values + le16(area, at + 2) as usize;
        let value_inode = le32(area, at + 4);
        let size = le32(area, at + 8) as usize;
        if at + 16 + name_len > area.len() || value_inode != 0 || value_at + size > area.len() {
            return Err(corrupt());
        }
        let name = format!("{prefix}{}", String::from_utf8_lossy(&area[at + 16..at + 16 + name_len]));
        out.push((name, area[value_at..value_at + size].to_vec()));
        at += (16 + name_len + 3) & !3;
    }
    Ok(())
}

/// Fill `buf` from `dev` at `offset`: `EIO` when the device ends first.
fn read_exact(dev: &Arc<dyn FileHandle>, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
    let mut done = 0;
    while done < buf.len() {
        match dev.read_at(offset + done as u64, &mut buf[done..])? {
            0 => return Err(Errno::EIO),
            n => done += n as usize,
        }
    }
    Ok(())
}

/// An open regular file.
struct File {
    fs: Arc<Ext4>,
    inode: Arc<Inode>,
    extents: Option<Vec<Extent>>,
}

/// An open directory.
struct Dir {
    inode: Arc<Inode>,
    entries: Vec<DirEntry>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ext4::File").field("ino", &self.inode.ino).finish()
    }
}

impl std::fmt::Debug for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ext4::Dir").field("ino", &self.inode.ino).finish()
    }
}

/// An attribute call on a file here: read and list, never change.
fn xattr(fs: &Ext4, inode: &Inode, op: XattrOp<'_>) -> Result<usize, Errno> {
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
            let attrs = fs.attrs(inode)?;
            let (_, value) = attrs.iter().find(|(n, _)| n == name).ok_or(Errno::ENODATA)?;
            out(buf, value)
        }
        XattrOp::List { buf } => {
            let mut names = Vec::new();
            for (name, _) in fs.attrs(inode)? {
                names.extend_from_slice(name.as_bytes());
                names.push(0);
            }
            out(buf, &names)
        }
        XattrOp::Set { .. } | XattrOp::Remove { .. } => Err(Errno::EROFS),
    }
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        self.fs.read_file(&self.inode, self.extents.as_deref(), offset, buf).map(|n| n as u64)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EBADF)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.inode.metadata())
    }

    fn xattr(&self, op: XattrOp<'_>) -> Option<Result<usize, Errno>> {
        Some(xattr(&self.fs, &self.inode, op))
    }
}

impl FileHandle for Dir {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EISDIR)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.inode.metadata())
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Ok(self.entries.clone())
    }
}

/// A mounted ext4: the filesystem, shared with its open files.
pub struct Ext4Fs(Arc<Ext4>);

impl Ext4Fs {
    /// Mount the ext4 on `dev`, read-only.
    pub fn new(dev: Arc<dyn FileHandle>) -> Result<Ext4Fs, Errno> {
        Ok(Ext4Fs(Arc::new(Ext4::new(dev)?)))
    }

    /// A file's owner, its user and group: read here, though `stat`
    /// does not say a file's owner yet.
    pub fn owner(&self, path: &str) -> Result<(u32, u32), Errno> {
        let i = self.0.find(path)?;
        Ok((i.uid, i.gid))
    }
}

impl FileSystem for Ext4Fs {
    fn fs_type(&self) -> &'static str {
        "ext4"
    }

    fn magic(&self) -> u64 {
        MAGIC as u64
    }

    fn keeps_links(&self) -> bool {
        true
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let fs = &self.0;
        let inode = match fs.find(path) {
            Ok(i) => i,
            // Nothing is made here.
            Err(Errno::ENOENT) if flags & crate::fs::oflags::O_CREAT != 0 => return Err(Errno::EROFS),
            Err(e) => return Err(e),
        };
        match inode.kind() {
            S_IFDIR => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let mut entries = Vec::new();
                for e in fs.entries(&inode)?.iter() {
                    // The type the entry gives, or the inode's where
                    // entries give none.
                    let file_type = match e.kind {
                        1 => FileType::Regular,
                        2 => FileType::Directory,
                        3 | 4 => FileType::CharDevice,
                        5 => FileType::Fifo,
                        6 => FileType::Socket,
                        7 => FileType::Symlink,
                        _ => fs.inode(e.ino)?.file_type(),
                    };
                    entries.push(DirEntry { name: e.name.clone(), file_type, ino: e.ino as u64 });
                }
                Ok(Arc::new(Dir { inode, entries }))
            }
            S_IFREG => {
                if super::writes(flags) || flags & crate::fs::oflags::O_TRUNC != 0 {
                    return Err(Errno::EROFS);
                }
                let extents = if inode.flags & EXTENTS_FL != 0 { Some(fs.extents(&inode)?) } else { None };
                Ok(Arc::new(File { fs: Arc::clone(fs), inode, extents }))
            }
            // The namespace follows a link before it opens.
            S_IFLNK => Err(Errno::ELOOP),
            // A character device is the one its number names, as a node
            // in any filesystem is.
            S_IFCHR => {
                let md = inode.metadata();
                super::devices::open_char(md.rdev, Arc::new(move || md.clone()))
            }
            _ => {
                unimplemented("opening a FIFO, a socket or a block device in an ext4");
                Err(Errno::ENXIO)
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        Ok(self.0.find(path)?.metadata())
    }

    fn read_link(&self, path: &str) -> Result<String, Errno> {
        let inode = self.0.find(path)?;
        if inode.kind() != S_IFLNK {
            return Err(Errno::EINVAL);
        }
        self.0.target(&inode)
    }

    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        xattr(&self.0, &*self.0.find(path)?, op)
    }

    fn chmod(&self, path: &str, _mode: u32) -> Result<(), Errno> {
        self.0.find(path).and(Err(Errno::EROFS))
    }

    fn set_mtime(&self, path: &str, _secs: i64) -> Result<(), Errno> {
        self.0.find(path).and(Err(Errno::EROFS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An image in memory, as the device.
    #[derive(Debug)]
    struct Image(Vec<u8>);

    impl FileHandle for Image {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
            let at = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - at);
            buf[..n].copy_from_slice(&self.0[at..at + n]);
            Ok(n as u64)
        }
        fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
            Err(Errno::EBADF)
        }
        fn metadata(&self) -> Result<Metadata, Errno> {
            Ok(Metadata::regular(self.0.len() as u64))
        }
    }

    const APEX: &[u8] = include_bytes!("testdata/ext4/apex.img");
    const APEX_LISTING: &str = include_str!("testdata/ext4/apex.txt");

    fn apex() -> Ext4Fs {
        Ext4Fs::new(Arc::new(Image(APEX.to_vec()))).unwrap()
    }

    fn fnv(data: &[u8]) -> u64 {
        data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ *b as u64).wrapping_mul(0x100_0000_01b3))
    }

    fn read_all(fs: &Ext4Fs, path: &str) -> Vec<u8> {
        let f = fs.open(path, 0, 0).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 5000];
        loop {
            let n = f.read_at(out.len() as u64, &mut buf).unwrap() as usize;
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    fn attrs_of(fs: &Ext4Fs, path: &str) -> String {
        let mut names = vec![0u8; 4096];
        let n = fs.xattr(path, XattrOp::List { buf: &mut names }).unwrap();
        let mut all: Vec<String> = names[..n]
            .split(|b| *b == 0)
            .filter(|n| !n.is_empty())
            .map(|name| {
                let name = std::str::from_utf8(name).unwrap();
                let mut value = vec![0u8; 4096];
                let n = fs.xattr(path, XattrOp::Get { name, buf: &mut value }).unwrap();
                format!("{name}={}", value[..n].iter().map(|b| format!("{b:02x}")).collect::<String>())
            })
            .collect();
        all.sort();
        if all.is_empty() { "-".to_string() } else { all.join(",") }
    }

    /// Every file of the image is as Linux 7.0's ext4 showed it mounted
    /// (`tests/android/oracle/ext4-fixture.sh`): its type, mode, owner,
    /// size, link count, time, target or device number, contents and
    /// attributes; and a directory lists what Linux listed in it.
    #[test]
    fn an_image_is_what_linux_reads_it_as() {
        let fs = apex();
        let mut seen = 0;
        let mut listed: HashMap<String, Vec<String>> = HashMap::new();
        for line in APEX_LISTING.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            let (path, kind) = (if f[0] == "." { "" } else { f[0] }, f[1]);
            let md = fs.metadata(path).unwrap();
            let want_type = match kind {
                "f" => FileType::Regular,
                "d" => FileType::Directory,
                "l" => FileType::Symlink,
                "c" | "b" => FileType::CharDevice,
                "p" => FileType::Fifo,
                _ => FileType::Socket,
            };
            assert_eq!(md.file_type, want_type, "{path}");
            assert_eq!(format!("{:o}", md.mode), f[2], "{path}");
            let (uid, gid) = fs.owner(path).unwrap();
            assert_eq!((uid.to_string().as_str(), gid.to_string().as_str()), (f[3], f[4]), "{path}");
            assert_eq!(md.size.to_string(), f[5], "{path}");
            assert_eq!(md.nlink.to_string(), f[6], "{path}");
            assert_eq!(md.mtime.to_string(), f[7], "{path}");
            match kind {
                "l" => assert_eq!(fs.read_link(path).unwrap(), f[8], "{path}"),
                "c" | "b" => assert_eq!(format!("{}:{}", super::super::devices::major(md.rdev), super::super::devices::minor(md.rdev)), f[8], "{path}"),
                "f" => assert_eq!(format!("{:016x}", fnv(&read_all(&fs, path))), f[9], "{path}"),
                _ => {}
            }
            assert_eq!(attrs_of(&fs, path), f[10], "{path}");
            if !path.is_empty() {
                let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
                listed.entry(dir.to_string()).or_default().push(name.to_string());
            }
            seen += 1;
        }
        assert!(seen > 170);
        for (dir, mut names) in listed {
            let mut got: Vec<String> = fs.open(&dir, 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
            got.sort();
            names.sort();
            assert_eq!(got, names, "{dir}");
        }
    }

    /// Reads at any place: within a block, across blocks, in a hole, at
    /// and past the end.
    #[test]
    fn a_file_reads_from_anywhere() {
        let fs = apex();
        let whole = read_all(&fs, "lib64/libfixture.so");
        assert_eq!(whole.len(), 36393);
        let f = fs.open("lib64/libfixture.so", 0, 0).unwrap();
        for (at, len) in [(0usize, 10usize), (4090, 20), (4096, 4096), (8191, 2), (36390, 100), (20000, 16393)] {
            let mut buf = vec![0xaau8; len];
            let n = f.read_at(at as u64, &mut buf).unwrap() as usize;
            assert_eq!(n, len.min(whole.len() - at), "{at}");
            assert_eq!(&buf[..n], &whole[at..at + n], "{at}");
        }
        assert_eq!(f.read_at(36393, &mut [0u8; 8]), Ok(0));
        assert_eq!(f.read_at(1 << 40, &mut [0u8; 8]), Ok(0));
        // A file with holes: its data where it wrote it, zeros between
        // and after.
        let holes = read_all(&fs, "lib64/holes");
        assert_eq!(holes.len(), 40000);
        assert_eq!(&holes[..5], b"start");
        assert_eq!(&holes[5 * 4096..5 * 4096 + 6], b"middle");
        assert!(holes[5..5 * 4096].iter().all(|b| *b == 0) && holes[5 * 4096 + 6..].iter().all(|b| *b == 0));
        // Two names, one file.
        assert_eq!(fs.metadata("bin/tool").unwrap().ino, fs.metadata("bin/tool2").unwrap().ino);
        // A directory's own entries are there for a listing.
        let names: Vec<String> = fs.open("bin", 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&".".to_string()) && names.contains(&"..".to_string()));
    }

    /// Nothing changes, and what is not there is said the usual ways.
    #[test]
    fn nothing_is_written_and_errors_are_linuxs() {
        let fs = apex();
        let rw = crate::fs::oflags::O_RDWR;
        assert_eq!(fs.open("bin/tool", rw, 0).err(), Some(Errno::EROFS));
        assert_eq!(fs.open("bin/new", crate::fs::oflags::O_CREAT | 1, 0o644).err(), Some(Errno::EROFS));
        assert_eq!(fs.open("bin/nothing", 0, 0).err(), Some(Errno::ENOENT));
        assert_eq!(fs.open("bin/tool/x", 0, 0).err(), Some(Errno::ENOTDIR));
        assert_eq!(fs.open("bin", rw, 0).err(), Some(Errno::EISDIR));
        assert_eq!(fs.mkdir("bin/dir", 0o755), Err(Errno::EROFS));
        assert_eq!(fs.unlink("bin/tool"), Err(Errno::EROFS));
        assert_eq!(fs.rename("bin/tool", "bin/other"), Err(Errno::EROFS));
        assert_eq!(fs.chmod("bin/tool", 0o700), Err(Errno::EROFS));
        assert_eq!(fs.read_link("bin/tool"), Err(Errno::EINVAL));
        assert_eq!(fs.read_link("bin/nothing"), Err(Errno::ENOENT));
        assert_eq!(fs.xattr("bin/tool", XattrOp::Set { name: "user.x", value: b"1", flags: 0 }), Err(Errno::EROFS));
        assert_eq!(fs.xattr("bin/tool", XattrOp::Remove { name: "user.comment" }), Err(Errno::EROFS));
        assert_eq!(fs.xattr("bin/tool", XattrOp::Get { name: "user.nothing", buf: &mut [0u8; 8] }), Err(Errno::ENODATA));
        assert_eq!(fs.xattr("bin/tool", XattrOp::Get { name: "user.comment", buf: &mut [0u8; 2] }), Err(Errno::ERANGE));
        assert_eq!(fs.xattr("bin/tool", XattrOp::Get { name: "user.comment", buf: &mut [] }), Ok(9));
        // A character device in it is the device.
        let null = fs.open("etc/null", 0, 0).unwrap();
        assert_eq!(null.read_at(0, &mut [0u8; 4]), Ok(0));
        assert_eq!((fs.fs_type(), fs.magic()), ("ext4", 0xef53));
    }

    /// What is not an ext4, or one this cannot read, is refused.
    #[test]
    fn what_is_not_an_ext4_is_refused() {
        let new = |image: Vec<u8>| Ext4Fs::new(Arc::new(Image(image))).err();
        assert_eq!(new(vec![0u8; 8192]), Some(Errno::EINVAL));
        assert_eq!(new(vec![0u8; 100]), Some(Errno::EINVAL));
        // A feature it does not read: inline data.
        let mut image = APEX.to_vec();
        image[1024 + 0x61] |= 0x80;
        assert_eq!(new(image), Some(Errno::EINVAL));
        // A journal to replay.
        let mut image = APEX.to_vec();
        image[1024 + 0x60] |= 0x04;
        assert_eq!(new(image), Some(Errno::EINVAL));
        // An inode table outside the image.
        let mut image = APEX.to_vec();
        image[4096 + 8..4096 + 12].copy_from_slice(&0xffff_ff00u32.to_le_bytes());
        assert_eq!(new(image), Some(Errno::EINVAL));
    }
}
