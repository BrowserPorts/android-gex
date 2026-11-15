//! Loop devices: a file as a disk (drivers/block/loop.c, android17-6.18).
//!
//! Android's `apexd` gives each APEX's payload, an ext4 image stored in
//! the `.apex` file, a loop device over the file at the payload's offset
//! and length, and mounts that. It asks `/dev/loop-control` for a free
//! device, opens `/dev/block/loop<n>` (which `ueventd` makes from the
//! device's event), and configures it with `LOOP_CONFIGURE`.
//!
//! - `/dev/loop-control` (10:237): `LOOP_CTL_GET_FREE` answers the lowest
//!   device with no file behind it, adding one when all have;
//!   `LOOP_CTL_ADD` adds the device of a number (`EEXIST`), or with -1
//!   the next; `LOOP_CTL_REMOVE` takes one away that is unbound and not
//!   open (`EBUSY`, `ENODEV`).
//! - `/dev/loop<n>` (7:n), sixteen to start with as Android's kernel is
//!   configured, and any other the moment a node of its number is opened: `LOOP_CONFIGURE` (a descriptor, a block size, and a
//!   `loop_info64`'s offset, size limit, flags and name), or `LOOP_SET_FD`
//!   and then `LOOP_SET_STATUS64`; `LOOP_GET_STATUS64`;
//!   `LOOP_SET_BLOCK_SIZE`; `LOOP_SET_CAPACITY`; `LOOP_SET_DIRECT_IO`
//!   (taken: nothing here is cached either way); `LOOP_CLR_FD`, which
//!   takes the file away at the last close, as does a device configured
//!   to clear itself. The file must be a regular file or a block device.
//!   The device is read-only when asked, or when the file or the device
//!   was not opened for writing.
//! - Its size is the file's from the offset, no more than the limit, in
//!   whole 512-byte sectors.
//! - sysfs: `loop/backing_file`, `offset`, `sizelimit`, `autoclear`,
//!   `partscan`, `dio`, there while a file is behind it. A `change` event
//!   when one is put there and when it is taken away.
//!
//! Not here: partitions (`LO_FLAGS_PARTSCAN` is kept and reported, and
//! nothing is scanned), `LOOP_CHANGE_FD`, and the old `LOOP_SET_STATUS`
//! and `LOOP_GET_STATUS` with their 32-bit structure, which are refused
//! out loud.

use crate::block::{self, Caller, Disk};
use crate::errno::{Errno, SysResult};
use crate::vfs::devices::makedev;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const LOOP_MAJOR: u32 = 7;
/// `CONFIG_BLK_DEV_LOOP_MIN_COUNT` of Android's kernel.
const AT_BOOT: u32 = 16;

const LOOP_SET_FD: u64 = 0x4c00;
const LOOP_CLR_FD: u64 = 0x4c01;
const LOOP_SET_STATUS: u64 = 0x4c02;
const LOOP_GET_STATUS: u64 = 0x4c03;
const LOOP_SET_STATUS64: u64 = 0x4c04;
const LOOP_GET_STATUS64: u64 = 0x4c05;
const LOOP_CHANGE_FD: u64 = 0x4c06;
const LOOP_SET_CAPACITY: u64 = 0x4c07;
const LOOP_SET_DIRECT_IO: u64 = 0x4c08;
const LOOP_SET_BLOCK_SIZE: u64 = 0x4c09;
const LOOP_CONFIGURE: u64 = 0x4c0a;
const LOOP_CTL_ADD: u64 = 0x4c80;
const LOOP_CTL_REMOVE: u64 = 0x4c81;
const LOOP_CTL_GET_FREE: u64 = 0x4c82;

const READ_ONLY: u32 = 1;
const AUTOCLEAR: u32 = 4;
const PARTSCAN: u32 = 8;
const DIRECT_IO: u32 = 16;
/// The size of `struct loop_info64`, and where its fields are.
const INFO_SIZE: usize = 232;

/// Say once per kind that a program asked for something not done here.
fn unimplemented(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] loop: {what} is not implemented");
        said.push(what.to_string());
    }
}

/// What is behind a bound device.
#[derive(Debug)]
struct Backing {
    file: Arc<dyn FileHandle>,
    /// The file's name as it was opened (`loop/backing_file`).
    path: String,
    /// Its device and inode numbers, for `LOOP_GET_STATUS64`.
    ino: u64,
    offset: u64,
    sizelimit: u64,
    /// `lo_file_name`: 64 bytes, the last a NUL.
    name: [u8; 64],
}

#[derive(Debug, Default)]
struct State {
    backing: Option<Backing>,
    flags: u32,
    block_size: u32,
    /// The device's size in bytes, as last set from the file's.
    size: u64,
    /// How many opens of the device there are.
    openers: u32,
    /// `LOOP_CLR_FD` was asked with another open of it: gone at the last
    /// close, and not to be opened meanwhile (`Lo_rundown`).
    rundown: bool,
}

impl State {
    /// `Lo_bound`: a file is behind it, and it has not been asked to let
    /// go of it.
    fn bound(&self) -> bool {
        self.backing.is_some() && !self.rundown
    }
}

/// A loop device.
#[derive(Debug)]
pub struct Loop {
    number: u32,
    state: Mutex<State>,
}

static LOOPS: Mutex<BTreeMap<u32, Arc<Loop>>> = Mutex::new(BTreeMap::new());

fn dev(number: u32) -> u64 {
    makedev(LOOP_MAJOR, number)
}

/// Add loop device `number` (`loop_add`).
fn add(loops: &mut BTreeMap<u32, Arc<Loop>>, number: u32, announce: bool) {
    let lo = Arc::new(Loop { number, state: Mutex::new(State { block_size: 512, ..State::default() }) });
    loops.insert(number, Arc::clone(&lo));
    block::add(dev(number), &format!("loop{number}"), lo, announce);
}

/// The devices a kernel starts with. Called once, by the block layer.
pub fn boot() {
    let mut loops = LOOPS.lock().unwrap_or_else(|e| e.into_inner());
    for number in 0..AT_BOOT {
        add(&mut loops, number, false);
    }
}

/// `loop_probe`: a node with a loop device's number is opened and there
/// is no such device: there is now.
pub fn probe(dev: u64) {
    if crate::vfs::devices::major(dev) != LOOP_MAJOR {
        return;
    }
    let number = crate::vfs::devices::minor(dev);
    let mut loops = LOOPS.lock().unwrap_or_else(|e| e.into_inner());
    if !loops.contains_key(&number) {
        add(&mut loops, number, true);
    }
}

impl Loop {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `lo_calculate_size`: the file's size from the offset, no more than
    /// the limit, in whole sectors.
    fn calculate(file: &Arc<dyn FileHandle>, offset: u64, sizelimit: u64) -> u64 {
        let whole = file.device_size().or_else(|| file.metadata().ok().map(|m| m.size)).unwrap_or(0);
        let mut size = whole.saturating_sub(offset);
        if sizelimit > 0 && sizelimit < size {
            size = sizelimit;
        }
        size & !511
    }

    /// `loop_set_status_from_info`: the offset, limit and name of a
    /// `loop_info64`, which may ask for no encryption.
    fn info(info: &[u8]) -> Result<(u64, u64, [u8; 64]), Errno> {
        let u64_at = |at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap());
        let u32_at = |at: usize| u32::from_le_bytes(info[at..at + 4].try_into().unwrap());
        let (offset, sizelimit, encrypt_type, key_size) = (u64_at(24), u64_at(32), u32_at(44), u32_at(48));
        if key_size > 32 || encrypt_type != 0 {
            return Err(Errno::EINVAL);
        }
        if offset > i64::MAX as u64 || sizelimit > i64::MAX as u64 {
            return Err(Errno::EOVERFLOW);
        }
        let mut name = [0u8; 64];
        name.copy_from_slice(&info[56..120]);
        name[63] = 0;
        Ok((offset, sizelimit, name))
    }

    /// `loop_configure`: put the file of descriptor `fd` behind the
    /// device, as `info` says (all zeros for `LOOP_SET_FD`) and with
    /// `block_size`, 0 for the usual 512.
    fn configure(&self, cx: &Caller<'_>, fd: u32, block_size: u32, info: &[u8]) -> SysResult {
        let file = cx.fds.get(fd as i32).map_err(|_| Errno::EBADF)?;
        if !file.readable {
            return Err(Errno::EINVAL);
        }
        let mut st = self.state();
        if st.backing.is_some() {
            return Err(Errno::EBUSY);
        }
        // A regular file, or a block device (another loop device's is
        // not this one: `EBADF`).
        let md = file.handle.metadata()?;
        if let Some(other) = Arc::clone(&file.handle).as_block() {
            if md.rdev == dev(self.number) {
                return Err(Errno::EBADF);
            }
            if other.disk().size() == 0 && md.rdev >> 8 & 0xfff == LOOP_MAJOR as u64 {
                return Err(Errno::EINVAL);
            }
        } else if md.file_type != FileType::Regular {
            return Err(Errno::EINVAL);
        }
        let flags = u32::from_le_bytes(info[52..56].try_into().unwrap());
        if flags & !(READ_ONLY | AUTOCLEAR | PARTSCAN | DIRECT_IO) != 0 {
            return Err(Errno::EINVAL);
        }
        let (offset, sizelimit, name) = Loop::info(info)?;
        let block_size = if block_size == 0 { 512 } else { block_size };
        if !(512..=4096).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(Errno::EINVAL);
        }
        // Read-only when asked, or when the file cannot be written.
        st.flags = flags | if file.writable { 0 } else { READ_ONLY };
        st.block_size = block_size;
        st.size = Loop::calculate(&file.handle, offset, sizelimit);
        st.backing = Some(Backing { file: Arc::clone(&file.handle), path: file.path.clone(), ino: md.ino, offset, sizelimit, name });
        drop(st);
        block::media_changed(dev(self.number));
        block::changed(dev(self.number));
        Ok(0)
    }

    /// `__loop_clr_fd`: the file taken away.
    fn clear(&self, st: &mut State) {
        st.backing = None;
        st.flags = 0;
        st.block_size = 512;
        st.size = 0;
        st.rundown = false;
    }

    /// `LOOP_SET_STATUS64`.
    fn set_status(&self, info: &[u8]) -> SysResult {
        let mut st = self.state();
        if !st.bound() {
            return Err(Errno::ENXIO);
        }
        let (offset, sizelimit, name) = Loop::info(info)?;
        let flags = u32::from_le_bytes(info[52..56].try_into().unwrap());
        // It may set these two flags and clear the first.
        st.flags = (st.flags & !AUTOCLEAR) | (flags & (AUTOCLEAR | PARTSCAN));
        let b = st.backing.as_mut().unwrap();
        (b.offset, b.sizelimit, b.name) = (offset, sizelimit, name);
        let size = Loop::calculate(&b.file, offset, sizelimit);
        st.size = size;
        Ok(0)
    }

    /// `LOOP_GET_STATUS64`: the `loop_info64` of a bound device.
    fn status(&self) -> Result<[u8; INFO_SIZE], Errno> {
        let st = self.state();
        if !st.bound() {
            return Err(Errno::ENXIO);
        }
        let b = st.backing.as_ref().ok_or(Errno::ENXIO)?;
        let mut info = [0u8; INFO_SIZE];
        // lo_device is the device the file is on, which no file here
        // says; lo_rdevice is the file's own number when it is a device.
        info[8..16].copy_from_slice(&b.ino.to_le_bytes());
        info[16..24].copy_from_slice(&b.file.metadata().map_or(0, |m| m.rdev).to_le_bytes());
        info[24..32].copy_from_slice(&b.offset.to_le_bytes());
        info[32..40].copy_from_slice(&b.sizelimit.to_le_bytes());
        info[40..44].copy_from_slice(&self.number.to_le_bytes());
        info[52..56].copy_from_slice(&st.flags.to_le_bytes());
        info[56..120].copy_from_slice(&b.name);
        Ok(info)
    }
}

impl Disk for Loop {
    fn size(&self) -> u64 {
        self.state().size
    }

    fn read_only(&self) -> bool {
        self.state().flags & READ_ONLY != 0
    }

    fn set_read_only(&self, ro: bool) {
        let mut st = self.state();
        st.flags = if ro { st.flags | READ_ONLY } else { st.flags & !READ_ONLY };
    }

    fn block_size(&self) -> u32 {
        self.state().block_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let (file, at) = {
            let st = self.state();
            let b = st.backing.as_ref().ok_or(Errno::EIO)?;
            (Arc::clone(&b.file), b.offset + offset)
        };
        // All of what was asked, which is within the device: the file may
        // answer in pieces, and what it has not got reads as zeros.
        let mut done = 0;
        while done < buf.len() {
            match file.read_at(at + done as u64, &mut buf[done..])? {
                0 => {
                    buf[done..].fill(0);
                    break;
                }
                n => done += n as usize,
            }
        }
        Ok(buf.len() as u64)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        let (file, at) = {
            let st = self.state();
            let b = st.backing.as_ref().ok_or(Errno::EIO)?;
            (Arc::clone(&b.file), b.offset + offset)
        };
        let mut done = 0;
        while done < buf.len() {
            match file.write_at(at + done as u64, &buf[done..])? {
                0 => return Err(Errno::EIO),
                n => done += n as usize,
            }
        }
        Ok(buf.len() as u64)
    }

    fn opened(&self) -> Result<(), Errno> {
        let mut st = self.state();
        if st.rundown {
            return Err(Errno::ENXIO);
        }
        st.openers += 1;
        Ok(())
    }

    /// `lo_release`: at the last close, a device that clears itself, or
    /// was asked to be cleared, loses its file.
    fn released(&self) {
        let mut st = self.state();
        st.openers = st.openers.saturating_sub(1);
        if st.openers == 0 && st.backing.is_some() && (st.flags & AUTOCLEAR != 0 || st.rundown) {
            self.clear(&mut st);
            drop(st);
            block::media_changed(dev(self.number));
            block::changed(dev(self.number));
        }
    }

    fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        Some(match request {
            LOOP_SET_FD => self.configure(cx, arg as u32, 0, &[0u8; INFO_SIZE]),
            LOOP_CONFIGURE => (|| {
                // struct loop_config: fd, block_size, the info, and eight
                // words that must be there to read.
                let config = m.read(arg, 8 + INFO_SIZE + 64)?.to_vec();
                let fd = u32::from_le_bytes(config[0..4].try_into().unwrap());
                let block_size = u32::from_le_bytes(config[4..8].try_into().unwrap());
                self.configure(cx, fd, block_size, &config[8..8 + INFO_SIZE])
            })(),
            LOOP_SET_STATUS64 => (|| {
                let info = m.read(arg, INFO_SIZE)?.to_vec();
                self.set_status(&info)
            })(),
            LOOP_GET_STATUS64 => (|| {
                let info = self.status()?;
                m.write(arg, &info)?;
                Ok(0)
            })(),
            // The file is gone at the last close of the device, which is
            // not before this descriptor's.
            LOOP_CLR_FD => {
                let mut st = self.state();
                if !st.bound() {
                    Err(Errno::ENXIO)
                } else {
                    st.flags |= AUTOCLEAR;
                    if st.openers == 1 {
                        st.rundown = true;
                    }
                    Ok(0)
                }
            }
            LOOP_SET_BLOCK_SIZE => {
                let mut st = self.state();
                if !st.bound() {
                    Err(Errno::ENXIO)
                } else if !(512..=4096).contains(&arg) || !arg.is_power_of_two() {
                    Err(Errno::EINVAL)
                } else {
                    st.block_size = arg as u32;
                    Ok(0)
                }
            }
            // The file's size again.
            LOOP_SET_CAPACITY => {
                let mut st = self.state();
                match st.backing.as_ref().filter(|_| st.bound()).map(|b| Loop::calculate(&b.file, b.offset, b.sizelimit)) {
                    None => Err(Errno::ENXIO),
                    Some(size) => {
                        st.size = size;
                        Ok(0)
                    }
                }
            }
            // Nothing is cached with or without it.
            LOOP_SET_DIRECT_IO => {
                let mut st = self.state();
                if !st.bound() {
                    Err(Errno::ENXIO)
                } else {
                    st.flags = if arg != 0 { st.flags | DIRECT_IO } else { st.flags & !DIRECT_IO };
                    Ok(0)
                }
            }
            LOOP_SET_STATUS | LOOP_GET_STATUS | LOOP_CHANGE_FD => {
                unimplemented(&format!("ioctl {request:#x}"));
                Err(Errno::ENOTTY)
            }
            _ => return None,
        })
    }

    fn sysfs_dir(&self) -> Option<(&'static str, Vec<&'static str>)> {
        self.state().backing.as_ref().map(|_| ("loop", vec!["autoclear", "backing_file", "dio", "offset", "partscan", "sizelimit"]))
    }

    fn sysfs_read(&self, name: &str) -> Option<String> {
        let st = self.state();
        let b = st.backing.as_ref()?;
        let flag = |f: u32| format!("{}\n", (st.flags & f != 0) as u32);
        Some(match name {
            "backing_file" => format!("{}\n", b.path),
            "offset" => format!("{}\n", b.offset),
            "sizelimit" => format!("{}\n", b.sizelimit),
            "autoclear" => flag(AUTOCLEAR),
            "partscan" => flag(PARTSCAN),
            "dio" => flag(DIRECT_IO),
            _ => return None,
        })
    }
}

/// `/dev/loop-control`.
pub struct Control {
    node: Option<crate::vfs::devices::NodeMeta>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("loop::Control")
    }
}

impl Control {
    pub fn open(node: Option<crate::vfs::devices::NodeMeta>) -> Arc<dyn FileHandle> {
        Arc::new(Control { node })
    }
}

impl FileHandle for Control {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(match &self.node {
            Some(node) => node(),
            None => Metadata { file_type: FileType::CharDevice, size: 0, mode: 0o660, ino: crate::vfs::anon_ino(self as *const Self as *const u8), mtime: 0, nlink: 1, rdev: makedev(10, 237), times: Default::default(), owner: None },
        })
    }

    fn ioctl(&self, _m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        // The devices a kernel starts with are there before any is asked
        // for.
        block::boot();
        let mut loops = LOOPS.lock().unwrap_or_else(|e| e.into_inner());
        let number = arg as u32 as i32;
        Some(match request {
            LOOP_CTL_GET_FREE => {
                let free = loops.values().find(|lo| lo.state().backing.is_none()).map(|lo| lo.number);
                Ok(match free {
                    Some(n) => n,
                    None => {
                        let n = (0..).find(|n| !loops.contains_key(n)).unwrap();
                        add(&mut loops, n, true);
                        n
                    }
                } as u64)
            }
            LOOP_CTL_ADD => {
                if number >= 0 && loops.contains_key(&(number as u32)) {
                    Err(Errno::EEXIST)
                } else if number >= 1 << 20 {
                    // More than a minor number holds.
                    Err(Errno::EINVAL)
                } else {
                    let n = if number < 0 { (0..).find(|n| !loops.contains_key(n)).unwrap() } else { number as u32 };
                    add(&mut loops, n, true);
                    Ok(n as u64)
                }
            }
            LOOP_CTL_REMOVE => {
                if number < 0 {
                    Err(Errno::EINVAL)
                } else {
                    match loops.get(&(number as u32)) {
                        None => Err(Errno::ENODEV),
                        Some(lo) => {
                            let busy = {
                                let st = lo.state();
                                st.backing.is_some() || st.openers > 0
                            };
                            if busy {
                                Err(Errno::EBUSY)
                            } else {
                                loops.remove(&(number as u32));
                                block::remove(dev(number as u32));
                                Ok(0)
                            }
                        }
                    }
                }
            }
            _ => return None,
        })
    }
}
