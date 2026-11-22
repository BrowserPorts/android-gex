//! The hardware random number generator's character device
//! (`drivers/char/hw_random/core.c` at Linux 6.18): misc 10:183, named
//! `hw_random` (its node `hwrng`; Android's ueventd makes it as
//! `/dev/hw_random`, after the device's name). Android's `prng_seeder`
//! reads it to seed the generator it serves, and without it hangs for
//! good.
//!
//! The core is always there. A generator behind it is the emulator's
//! (`virtio_rng.0`, `drivers/char/hw_random/virtio-rng.c`), there when the
//! kernel has the emulator's hardware ([`crate::vsock::enabled`]), as the
//! hvc consoles are. Its bytes are the kernel's randomness
//! ([`crate::vfs::devfs`]'s, the fixed stream when a run is made to
//! repeat). QEMU feeds a virtio-rng from the host's urandom as fast as it
//! is asked, so a read here has what it asks for at once, blocking or not.
//! Without a generator, a read is `ENODEV` and `rng_current` says `none`.
//!
//! The device's attributes are `rng_current`, `rng_available`,
//! `rng_selected` and `rng_quality`. With one generator, choosing it or
//! `none` (`rng_current`) and its quality (`rng_quality`) are kept as the
//! core keeps them.

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::sync::{Arc, Mutex};

/// `HWRNG_MINOR`.
pub const MISC_MINOR: u32 = 183;

/// The one generator there can be.
const NAME: &str = "virtio_rng.0";

/// The core's state: the generator in use (`current_rng`), whether a
/// program chose it (`cur_rng_set_by_user`), and its quality.
struct Core {
    current: bool,
    by_user: bool,
    quality: u16,
}

fn core() -> &'static Mutex<Core> {
    static CORE: std::sync::OnceLock<Mutex<Core>> = std::sync::OnceLock::new();
    // `hwrng_register`: a generator that gives no quality has 1024, and
    // the first one registered is used.
    CORE.get_or_init(|| Mutex::new(Core { current: present(), by_user: false, quality: 1024 }))
}

fn lock() -> std::sync::MutexGuard<'static, Core> {
    core().lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether the emulator's generator is there.
fn present() -> bool {
    crate::vsock::enabled()
}

/// `rng_dev_open`: for reading alone, else `EINVAL`.
pub fn open(flags: u64, node: crate::vfs::devices::NodeMeta) -> Result<Arc<dyn FileHandle>, Errno> {
    use crate::fs::oflags;
    if flags & oflags::ACCMODE != oflags::O_RDONLY {
        return Err(Errno::EINVAL);
    }
    Ok(Arc::new(Rng { node }))
}

/// An open `/dev/hw_random`.
pub struct Rng {
    node: crate::vfs::devices::NodeMeta,
}

impl std::fmt::Debug for Rng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("hw_random")
    }
}

impl FileHandle for Rng {
    /// `rng_dev_read`: what is asked for, from the generator in use, or
    /// `ENODEV` with none.
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if buf.is_empty() {
            return Ok(0);
        }
        if !lock().current {
            return Err(Errno::ENODEV);
        }
        crate::vfs::devfs::fill_random(buf);
        Ok(buf.len() as u64)
    }

    /// Opened for reading only: never reached.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EBADF)
    }

    /// `noop_llseek`: the position is 0, and stays (a read does not move
    /// it).
    fn seek(&self, _offset: i64, _whence: u32) -> Option<SysResult> {
        Some(Ok(0))
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok((self.node)())
    }
}

/// The misc device's attributes in sysfs.
#[derive(Debug)]
pub struct Attrs;

impl crate::vfs::sysfs::Attributes for Attrs {
    fn vars(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// `rng_miscdev`'s `nodename`.
    fn devname(&self) -> Option<String> {
        Some("hwrng".to_string())
    }

    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>> {
        dir.is_empty().then(|| ["rng_available", "rng_current", "rng_quality", "rng_selected"].iter().map(|n| (n.to_string(), FileType::Regular)).collect())
    }

    fn read(&self, path: &str) -> Option<(u32, String)> {
        self.read_result(path).and_then(Result::ok)
    }

    fn read_result(&self, path: &str) -> Option<Result<(u32, String), Errno>> {
        let c = lock();
        let text = match path {
            "rng_current" => format!("{}\n", if c.current { NAME } else { "none" }),
            "rng_available" => {
                if present() {
                    format!("{NAME} none\n")
                } else {
                    "none\n".to_string()
                }
            }
            "rng_selected" => format!("{}\n", c.by_user as u8),
            "rng_quality" => {
                if !c.current {
                    return Some(Err(Errno::ENODEV));
                }
                format!("{}\n", c.quality)
            }
            _ => return None,
        };
        let mode = if matches!(path, "rng_current" | "rng_quality") { 0o644 } else { 0o444 };
        Some(Ok((mode, text)))
    }

    /// `rng_quality` cannot be read with no generator in use, and is
    /// written to all the same.
    fn refused_mode(&self, path: &str) -> u32 {
        if path == "rng_quality" { 0o644 } else { 0o444 }
    }

    /// `rng_current_store` and `rng_quality_store`.
    fn write(&self, path: &str, data: &[u8]) -> Result<(), Errno> {
        let text = String::from_utf8_lossy(data);
        // `sysfs_streq`: one newline at the end does not count.
        let value = text.strip_suffix('\n').unwrap_or(&text);
        let mut c = lock();
        match path {
            "rng_current" => {
                if value.is_empty() {
                    // `enable_best_rng`: the best there is, and the choice
                    // is the core's again.
                    c.current = present();
                    c.by_user = false;
                } else if value == "none" {
                    c.by_user = true;
                    c.current = false;
                } else if present() && value == NAME {
                    c.current = true;
                    c.by_user = true;
                }
                // A name no generator has: nothing changes, and the write
                // is taken whole.
                Ok(())
            }
            "rng_quality" => {
                if data.len() < 2 {
                    return Err(Errno::EINVAL);
                }
                let quality = parse_u16(value.trim_end()).filter(|q| *q <= 1024).ok_or(Errno::EINVAL)?;
                if !c.current {
                    return Err(Errno::ENODEV);
                }
                c.quality = quality;
                // `enable_best_rng`, with one generator: the one in use
                // stays, and unless a program chose it the choice is the
                // core's.
                if !c.by_user {
                    c.current = present();
                }
                Ok(())
            }
            _ => Err(Errno::EACCES),
        }
    }
}

/// `kstrtou16(buf, 0, ..)`: decimal, `0x` hexadecimal or `0` octal.
fn parse_u16(s: &str) -> Option<u16> {
    let s = s.strip_prefix('+').unwrap_or(s);
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u16::from_str_radix(h, 16).ok();
    }
    if s.len() > 1 && s.starts_with('0') {
        return u16::from_str_radix(&s[1..], 8).ok();
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quality_is_read_as_kstrtou16_reads_one() {
        assert_eq!(parse_u16("1024"), Some(1024));
        assert_eq!(parse_u16("0x400"), Some(1024));
        assert_eq!(parse_u16("0100"), Some(64));
        assert_eq!(parse_u16("+7"), Some(7));
        assert_eq!(parse_u16("70000"), None);
        assert_eq!(parse_u16("x"), None);
    }
}
