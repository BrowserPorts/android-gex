//! Character devices by number: what a device node opens as, wherever the
//! node is. Android's init makes its own `/dev` in a tmpfs, `/dev/null`
//! and the rest with `mknod`, and a node there has to be the device its
//! number says.
//!
//! The numbers are Linux's (Documentation/admin-guide/devices.txt). Here
//! so far: the memory devices 1:3 (null), 1:5 (zero), 1:7 (full), 1:8 and
//! 1:9 (random, urandom) and 1:11 (kmsg, the kernel's log: [`super::kmsg`]),
//! the terminals 5:0 and 5:1 (tty, console), 10:237, the loop devices'
//! control (crate::loopdev), and 10:236, the device-mapper's (crate::dm). Any other number opens as `ENXIO`,
//! as a number no driver has does: 5:2 among them, the pseudoterminal
//! multiplexer, which the kernel opens by its path.
//!
//! A block device node opens as the disk of its number (crate::block).

use super::{FileHandle, Metadata};
use crate::errno::Errno;
use std::sync::Arc;

/// A node's metadata as it now is: what `fstat` of the device opened
/// through it says, the node's mode and inode with the device's number.
pub type NodeMeta = Arc<dyn Fn() -> Metadata + Send + Sync>;

/// A device number as `mknod` takes it and `stat` gives it (the kernel's
/// `new_encode_dev`).
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    (major & 0xfff) << 8 | (minor & 0xff) | (minor & !0xff) << 12
}

pub fn major(dev: u64) -> u32 {
    (dev >> 8 & 0xfff) as u32
}

pub fn minor(dev: u64) -> u32 {
    (dev & 0xff | dev >> 12 & 0xfff00) as u32
}

/// Open character device `dev` through the node `node` describes.
/// `flags` are the open's, which a device may refuse.
pub fn open_char(dev: u64, node: NodeMeta, flags: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    // The hardware generator's, which opens for reading alone.
    if major(dev) == 10 && minor(dev) == crate::hwrng::MISC_MINOR {
        return crate::hwrng::open(flags, node);
    }
    // The emulator's address space, a new host handle each open.
    if major(dev) == 10 && minor(dev) == crate::goldfishas::MISC_MINOR && crate::goldfishas::present() {
        return crate::goldfishas::open(node);
    }
    // The emulator's sync device, a new timeline each open.
    if major(dev) == 10 && minor(dev) == crate::goldfishsync::MISC_MINOR && crate::goldfishsync::present() {
        return crate::goldfishsync::open(node);
    }
    // The emulator's goldfish pipe, a new pipe each open.
    if major(dev) == 10 && minor(dev) == crate::goldfishpipe::MISC_MINOR && crate::goldfishpipe::present() {
        return crate::goldfishpipe::open(node);
    }
    // A DMA-BUF heap's.
    if major(dev) == crate::dmaheap::MAJOR {
        return crate::dmaheap::open(minor(dev), node);
    }
    // An hvc minor its driver registered with no port behind it:
    // `hvc_install` finds no console for the index.
    if super::devfs::has_hvc() && major(dev) == super::devfs::HVC_MAJOR && minor(dev) < super::devfs::HVC_MINORS {
        return super::devfs::open_numbered(dev, node).ok_or(Errno::ENODEV);
    }
    super::devfs::open_numbered(dev, node).ok_or(Errno::ENXIO)
}

/// Open block device `dev` through the node `node` describes.
pub fn open_block(dev: u64, node: NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    crate::block::open(dev, node)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node in a tmpfs opens as the device of its number, which says of
    /// itself what the node says; a number nobody has does not open.
    #[test]
    fn a_node_opens_as_the_device_of_its_number() {
        use crate::vfs::{FileSystem, FileType, TmpFs};
        let fs = TmpFs::new();
        fs.mknod("zero", 0o640, makedev(1, 5)).unwrap();
        assert_eq!(fs.mknod("zero", 0o640, makedev(1, 5)), Err(Errno::EEXIST));
        assert_eq!(fs.mknod("no/dir", 0o640, makedev(1, 5)), Err(Errno::ENOENT));
        let md = fs.metadata("zero").unwrap();
        assert_eq!((md.file_type, md.mode, md.rdev), (FileType::CharDevice, 0o640, makedev(1, 5)));
        let zero = fs.open("zero", 0, 0).unwrap();
        let mut buf = [7u8; 8];
        assert_eq!(zero.read_at(0, &mut buf), Ok(8));
        assert_eq!(buf, [0; 8]);
        // The open device is its node: its number, its inode, and its mode
        // as it now is.
        let open = zero.metadata().unwrap();
        assert_eq!((open.file_type, open.mode, open.rdev, open.ino), (FileType::CharDevice, 0o640, makedev(1, 5), md.ino));
        fs.chmod("zero", 0o600).unwrap();
        assert_eq!(zero.metadata().unwrap().mode, 0o600);
        // Removed, it still works, and says what it last was.
        fs.unlink("zero").unwrap();
        assert_eq!(fs.metadata("zero").err(), Some(Errno::ENOENT));
        assert_eq!(zero.read_at(0, &mut buf), Ok(8));
        assert_eq!(zero.metadata().unwrap().rdev, makedev(1, 5));

        fs.mknod("full", 0o666, makedev(1, 7)).unwrap();
        assert_eq!(fs.open("full", 1, 0).unwrap().write_at(0, b"x"), Err(Errno::ENOSPC));
        fs.mknod("nothing", 0o666, makedev(240, 77)).unwrap();
        assert_eq!(fs.metadata("nothing").unwrap().rdev, makedev(240, 77));
        assert_eq!(fs.open("nothing", 0, 0).err(), Some(Errno::ENXIO));
    }

    #[test]
    fn a_device_number_is_its_major_and_minor() {
        assert_eq!(makedev(1, 3), 0x103);
        assert_eq!((major(0x103), minor(0x103)), (1, 3));
        let big = makedev(235, 0x12345);
        assert_eq!((major(big), minor(big)), (235, 0x12345));
    }
}
