//! sysfs: the kernel's devices as a tree of files, which `mount -t sysfs`
//! mounts.
//!
//! Android's `ueventd` makes `/dev` from it. At its start it walks
//! `/sys/class`, `/sys/block` and `/sys/devices` and writes `add` to every
//! `uevent` file it finds; the kernel answers each write with the device's
//! event on the uevent socket (crate::netlink), and for each event with a
//! device number ueventd makes the node, with the owner and mode its rules
//! give. udev does the same.
//!
//! The devices are the ones this kernel opens by number
//! ([`super::devices`]): the character devices it always has, and the
//! disks of the block layer (crate::block), which come and go
//! ([`add`], [`remove`]) with their events. Each as Linux 7.0 shows it:
//!
//! - `devices/virtual/<subsystem>/<name>/`: `dev` (`major:minor`),
//!   `uevent` (the device's variables; a write of an action broadcasts an
//!   event, as `kobject_synth_uevent` has it), `subsystem` (a link to its
//!   class)
//! - `class/<subsystem>/<name>` and `dev/char/<major>:<minor>` (a disk's
//!   `dev/block/<major>:<minor>` and `block/<name>`): links to the device
//! - a device's other files and directories, which its driver gives
//!   ([`Attributes`]): a disk's `size`, `queue/read_ahead_kb` and the rest
//! - `devices/system/cpu`: the processors ([`super::SysCpuFs`])
//! - `kernel/uevent_seqnum`: the number of the last event
//! - `fs/selinux` and `fs/cgroup`: where those filesystems are mounted
//!
//! Not here: a device's `power` directory (there is no power management
//! to report), buses, modules, firmware, and every attribute of a driver
//! this kernel does not have.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::errno::{Errno, SysResult};
use std::sync::{Arc, Mutex, OnceLock};

/// What a device's driver adds to its directory and its events.
pub trait Attributes: Send + Sync + std::fmt::Debug {
    /// More of its variables, after `DEVNAME`: a disk's `DEVTYPE` and
    /// `DISKSEQ`.
    fn vars(&self) -> Vec<(String, String)>;
    /// What is in directory `dir` of the device's own (`""`: beside
    /// `dev` and `uevent`); `None` for a directory it has not.
    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>>;
    /// The mode and text of the file at `path` in the device's directory.
    fn read(&self, path: &str) -> Option<(u32, String)>;
    /// [`Self::read`], for a file that is there but whose read fails now
    /// (the error its `show` gives).
    fn read_result(&self, path: &str) -> Option<Result<(u32, String), Errno>> {
        self.read(path).map(Ok)
    }
    /// A write, whole, to that file.
    fn write(&self, path: &str, data: &[u8]) -> Result<(), Errno>;
    /// Where the link at `path` leads, when there is one there.
    fn link(&self, path: &str) -> Option<String> {
        let _ = path;
        None
    }
    /// `DEVNAME`, where its node is not named as it is (`dri/card0`).
    fn devname(&self) -> Option<String> {
        None
    }
}

/// A device whose node is named otherwise than it is (`DEVNAME`), with no
/// files of its own.
#[derive(Debug)]
struct Nodename(&'static str);

impl Attributes for Nodename {
    fn vars(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>> {
        dir.is_empty().then(Vec::new)
    }
    fn read(&self, _path: &str) -> Option<(u32, String)> {
        None
    }
    fn write(&self, _path: &str, _data: &[u8]) -> Result<(), Errno> {
        Err(Errno::EOPNOTSUPP)
    }
    fn devname(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// A DRM minor's (`drm_sysfs.c`): its node under `dri/`, and
/// `DEVTYPE=drm_minor`; no mode of its own.
#[derive(Debug)]
struct DrmMinor(&'static str);

impl Attributes for DrmMinor {
    fn vars(&self) -> Vec<(String, String)> {
        vec![("DEVTYPE".to_string(), "drm_minor".to_string())]
    }
    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>> {
        dir.is_empty().then(Vec::new)
    }
    fn read(&self, _path: &str) -> Option<(u32, String)> {
        None
    }
    fn write(&self, _path: &str, _data: &[u8]) -> Result<(), Errno> {
        Err(Errno::EACCES)
    }
    fn devname(&self) -> Option<String> {
        Some(format!("dri/{}", self.0))
    }
}

/// A device as the device model has it.
#[derive(Clone, Debug)]
pub struct Device {
    pub subsystem: String,
    pub name: String,
    pub major: u32,
    pub minor: u32,
    /// `DEVMODE`: the mode its driver asks for its node, when it asks.
    pub mode: Option<u32>,
    pub attrs: Option<Arc<dyn Attributes>>,
}

impl Device {
    /// Its path among the devices, as an event names it.
    fn devpath(&self) -> String {
        format!("/devices/virtual/{}/{}", self.subsystem, self.name)
    }

    fn is_block(&self) -> bool {
        self.subsystem == "block"
    }

    /// A network interface: no device number (`net/core/net-sysfs.c`).
    fn is_net(&self) -> bool {
        self.subsystem == "net"
    }

    /// Its own variables (`dev_uevent`), in the kernel's order.
    fn vars(&self) -> Vec<(String, String)> {
        // An interface's are its driver's alone (`netdev_uevent`).
        if self.is_net() {
            return self.attrs.as_ref().map(|a| a.vars()).unwrap_or_default();
        }
        let devname = self.attrs.as_ref().and_then(|a| a.devname()).unwrap_or_else(|| self.name.clone());
        let mut v = vec![("MAJOR".to_string(), self.major.to_string()), ("MINOR".to_string(), self.minor.to_string()), ("DEVNAME".to_string(), devname)];
        if let Some(mode) = self.mode {
            v.push(("DEVMODE".to_string(), format!("{mode:04o}")));
        }
        if let Some(attrs) = &self.attrs {
            v.extend(attrs.vars());
        }
        v
    }
}

/// A network interface's attributes (`net-sysfs.c`), as an interface of
/// this kernel's has them: its index and link, type, flags, MTU and
/// address, and the state of a link that is always up.
#[derive(Debug)]
struct NetAttrs {
    index: u32,
    name: String,
}

impl NetAttrs {
    /// `net_class_attrs` (`net/core/net-sysfs.c`) and a TUN device's group
    /// (`tun_flags`, `owner`, `group`).
    const FILES: [&'static str; 24] = [
        "addr_assign_type", "addr_len", "address", "broadcast", "carrier", "carrier_changes", "carrier_down_count", "carrier_up_count", "dev_id", "dev_port", "dormant", "duplex", "flags", "ifalias", "ifindex", "iflink", "link_mode", "mtu", "name_assign_type", "netdev_group", "operstate", "proto_down", "testing", "tx_queue_len",
    ];
    const MORE: [&'static str; 2] = ["type", "speed"];
    const TUN: [&'static str; 3] = ["tun_flags", "owner", "group"];

    fn dev(&self) -> Option<crate::netdev::NetDev> {
        crate::netdev::by_index(self.index)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
    }
}

impl Attributes for NetAttrs {
    fn vars(&self) -> Vec<(String, String)> {
        vec![("INTERFACE".to_string(), self.name.clone()), ("IFINDEX".to_string(), self.index.to_string())]
    }
    fn list(&self, dir: &str) -> Option<Vec<(String, FileType)>> {
        if !dir.is_empty() {
            return None;
        }
        let tun = self.dev().is_some_and(|d| d.tun.is_some());
        let mut v: Vec<(String, FileType)> = Self::FILES.iter().chain(Self::MORE.iter()).map(|f| (f.to_string(), FileType::Regular)).collect();
        if tun {
            v.extend(Self::TUN.iter().map(|f| (f.to_string(), FileType::Regular)));
        }
        Some(v)
    }
    fn read(&self, path: &str) -> Option<(u32, String)> {
        self.read_result(path).and_then(|r| r.ok())
    }
    /// The files `netdev_show` refuses (`EINVAL`) while the device is not
    /// running (its carrier, speed, duplex, dormant and testing), and
    /// `name_assign_type` for a name the kernel gave without saying how.
    fn read_result(&self, path: &str) -> Option<Result<(u32, String), Errno>> {
        let d = self.dev()?;
        let running = d.running();
        let text = match path {
            "addr_assign_type" => d.addr_assign_type.to_string(),
            "addr_len" => d.addr.len().to_string(),
            "address" => Self::hex(&d.addr),
            "broadcast" => Self::hex(&d.broadcast),
            "carrier" | "speed" | "duplex" | "dormant" | "testing" if !running => return Some(Err(Errno::EINVAL)),
            "carrier" => (d.carrier as u8).to_string(),
            "speed" if d.tun.is_some() => "10000".to_string(),
            "duplex" if d.tun.is_some() => "full".to_string(),
            // No ethtool link settings for lo and eth0 here.
            "speed" | "duplex" => return Some(Err(Errno::EINVAL)),
            "dormant" | "testing" => "0".to_string(),
            "carrier_changes" => (d.carrier_up + d.carrier_down).to_string(),
            "carrier_up_count" => d.carrier_up.to_string(),
            "carrier_down_count" => d.carrier_down.to_string(),
            "dev_id" => "0x0".to_string(),
            "dev_port" | "link_mode" | "netdev_group" | "proto_down" => "0".to_string(),
            "flags" => format!("{:#x}", d.flags),
            "ifalias" => return Some(Ok((0o644, String::new()))),
            "ifindex" | "iflink" => d.index.to_string(),
            "mtu" => d.mtu.to_string(),
            // NET_NAME_UNKNOWN: a name nobody said the origin of.
            "name_assign_type" if d.tun.is_some() => return Some(Err(Errno::EINVAL)),
            "name_assign_type" => "0".to_string(),
            "operstate" => d.operstate_text().to_string(),
            "tx_queue_len" => d.txqlen.to_string(),
            "type" => d.kind.to_string(),
            "tun_flags" | "owner" | "group" => {
                let t = d.tun.as_ref()?;
                match path {
                    "tun_flags" => format!("{:#x}", t.flags & (crate::tun::TUN_FEATURES | crate::tun::IFF_PERSIST | crate::tun::IFF_TUN | crate::tun::IFF_TAP)),
                    "owner" => t.owner.map_or("-1".to_string(), |o| o.to_string()),
                    _ => t.group.map_or("-1".to_string(), |g| g.to_string()),
                }
            }
            _ => return None,
        };
        let rw = matches!(path, "flags" | "mtu" | "tx_queue_len" | "ifalias" | "netdev_group" | "proto_down" | "carrier" | "gro_flush_timeout");
        Some(Ok((if rw { 0o644 } else { 0o444 }, format!("{text}\n"))))
    }
    fn write(&self, _path: &str, _data: &[u8]) -> Result<(), Errno> {
        crate::bpf::say_once("a write to a network device's sysfs attribute (not here)");
        Err(Errno::EOPNOTSUPP)
    }
}

/// A network device comes (`netdev_register_kobject`): its directory, and
/// its `add` uevent (`INTERFACE`, `IFINDEX`).
pub fn add_net(name: &str, index: u32) {
    add(Device { subsystem: "net".to_string(), name: name.to_string(), major: 0, minor: 0, mode: None, attrs: Some(Arc::new(NetAttrs { index, name: name.to_string() })) }, true);
}

/// The devices there are, in the order they came.
fn registry() -> &'static Mutex<Vec<Arc<Device>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Arc<Device>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // The character devices this kernel always has, with the modes
        // Linux's drivers give them (drivers/char/mem.c,
        // drivers/tty/tty_io.c, drivers/block/loop.c).
        let chars: [(&str, &str, u32, u32, Option<u32>); 12] = [
            ("mem", "null", 1, 3, Some(0o666)),
            ("mem", "zero", 1, 5, Some(0o666)),
            ("mem", "full", 1, 7, Some(0o666)),
            ("mem", "random", 1, 8, Some(0o666)),
            ("mem", "urandom", 1, 9, Some(0o666)),
            ("mem", "kmsg", 1, 11, Some(0o644)),
            ("tty", "tty", 5, 0, Some(0o666)),
            ("tty", "console", 5, 1, None),
            ("tty", "ptmx", 5, 2, Some(0o666)),
            ("misc", "loop-control", 10, 237, None),
            ("misc", "device-mapper", 10, 236, None),
            ("misc", "tun", 10, crate::tun::MISC_MINOR, None),
        ];
        // TUN's misc device names its node `net/tun` (`tun_miscdev`'s
        // `nodename`); Android's ueventd makes it as `/dev/tun` all the same.
        let attrs_of = |n: &str| -> Option<Arc<dyn Attributes>> { (n == "tun").then(|| Arc::new(Nodename("net/tun")) as Arc<dyn Attributes>) };
        let mut all: Vec<Arc<Device>> = chars.iter().map(|(s, n, major, minor, mode)| Arc::new(Device { subsystem: s.to_string(), name: n.to_string(), major: *major, minor: *minor, mode: *mode, attrs: attrs_of(n) })).collect();
        // The emulator's consoles, when the kernel has them: every minor
        // of `hvc_console`'s driver, in `devices/virtual/tty` (no parent),
        // as `tty_register_driver` adds them without `TTY_DRIVER_DYNAMIC_DEV`.
        if super::devfs::has_hvc() {
            for n in 0..super::devfs::HVC_MINORS {
                all.push(Arc::new(Device { subsystem: "tty".to_string(), name: format!("hvc{n}"), major: super::devfs::HVC_MAJOR, minor: n, mode: None, attrs: None }));
            }
        }
        // A virtio-gpu's minors, when there is one ([`crate::drm`]): the
        // render node first, as `drm_dev_register` adds them.
        for (name, minor) in crate::drm::minors() {
            all.push(Arc::new(Device { subsystem: "drm".to_string(), name: name.to_string(), major: crate::drm::MAJOR, minor: *minor, mode: None, attrs: Some(Arc::new(DrmMinor(name))) }));
        }
        // The network interfaces (`net/core/net-sysfs.c`): no device
        // number, and their own attributes.
        for d in crate::netdev::all() {
            all.push(Arc::new(Device { subsystem: "net".to_string(), name: d.name.clone(), major: 0, minor: 0, mode: None, attrs: Some(Arc::new(NetAttrs { index: d.index, name: d.name })) }));
        }
        Mutex::new(all)
    })
}

/// Every device, the disks a kernel starts with among them.
fn devices() -> Vec<Arc<Device>> {
    crate::block::boot();
    registry().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A device comes: it is in the tree, and with `announce` its `add` event
/// goes out (the devices there from the start are found by a walk).
pub fn add(device: Device, announce: bool) {
    let device = Arc::new(device);
    registry().lock().unwrap_or_else(|e| e.into_inner()).push(Arc::clone(&device));
    if announce {
        crate::netlink::uevent("add", &device.devpath(), &device.subsystem, &device.vars());
    }
}

/// A device goes, with its `remove` event.
pub fn remove(subsystem: &str, name: &str) {
    let gone = {
        let mut all = registry().lock().unwrap_or_else(|e| e.into_inner());
        all.iter().position(|d| d.subsystem == subsystem && d.name == name).map(|i| all.remove(i))
    };
    if let Some(device) = gone {
        crate::netlink::uevent("remove", &device.devpath(), &device.subsystem, &device.vars());
    }
}

/// An event of the kernel's own about a device: `change`, when a disk's
/// medium does.
pub fn event(subsystem: &str, name: &str, action: &str) {
    let found = registry().lock().unwrap_or_else(|e| e.into_inner()).iter().find(|d| d.subsystem == subsystem && d.name == name).cloned();
    if let Some(device) = found {
        crate::netlink::uevent(action, &device.devpath(), &device.subsystem, &device.vars());
    }
}

fn subsystems() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for d in devices() {
        if !v.contains(&d.subsystem) {
            v.push(d.subsystem.clone());
        }
    }
    v
}

fn device(subsystem: &str, name: &str) -> Option<Arc<Device>> {
    devices().into_iter().find(|d| d.subsystem == subsystem && d.name == name)
}

/// What a path in the tree is.
enum Node {
    /// A directory and what it holds.
    Dir(Vec<(String, FileType)>),
    /// A link and where it leads.
    Link(String),
    /// A file that is only read: its mode and text.
    Text(u32, String),
    /// A device's `uevent` file.
    Uevent(Arc<Device>),
    /// A file of a device's driver, at its path in the device's
    /// directory: its mode and text.
    Attr(Arc<Device>, String, u32, String),
    /// A file of a device's driver whose read fails now: its mode and the
    /// error (a network device's `carrier` while it is down).
    Refused(u32, Errno),
}

/// An open attribute whose read fails ([`Node::Refused`]).
#[derive(Debug)]
struct RefusedFile(Errno);

impl FileHandle for RefusedFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(self.0)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EACCES)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: 4096, mode: 0o444, ino: 1, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
}

fn dirs<S: AsRef<str>>(names: &[S]) -> Node {
    Node::Dir(names.iter().map(|n| (n.as_ref().to_string(), FileType::Directory)).collect())
}

/// `major:minor`, as `dev` reads and the links by number are named.
fn number(d: &Device) -> String {
    format!("{}:{}", d.major, d.minor)
}

fn node(path: &str) -> Option<Node> {
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    let links = |keep: &dyn Fn(&Device) -> bool, name: &dyn Fn(&Device) -> String| Node::Dir(devices().iter().filter(|d| keep(d)).map(|d| (name(d), FileType::Symlink)).collect());
    Some(match parts.as_slice() {
        [] => dirs(&["block", "bus", "class", "dev", "devices", "fs", "kernel", "module"]),
        ["bus"] | ["module"] | ["fs", "selinux"] | ["fs", "cgroup"] => dirs::<&str>(&[]),
        ["block"] => links(&|d| d.is_block(), &|d| d.name.clone()),
        ["block", n] => Node::Link(format!("..{}", device("block", n)?.devpath())),
        ["class"] => dirs(&subsystems()),
        ["class", s] if subsystems().iter().any(|x| x == s) => links(&|d| d.subsystem == *s, &|d| d.name.clone()),
        ["class", s, n] => Node::Link(format!("../..{}", device(s, n)?.devpath())),
        ["dev"] => dirs(&["block", "char"]),
        ["dev", kind @ ("block" | "char")] => links(&|d| !d.is_net() && d.is_block() == (*kind == "block"), &number),
        ["dev", kind @ ("block" | "char"), n] => Node::Link(format!("../..{}", devices().iter().find(|d| d.is_block() == (*kind == "block") && number(d) == *n)?.devpath())),
        ["devices"] => dirs(&["system", "virtual"]),
        ["devices", "system"] => dirs(&["cpu"]),
        ["devices", "virtual"] => dirs(&subsystems()),
        ["devices", "virtual", s] if subsystems().iter().any(|x| x == s) => Node::Dir(devices().iter().filter(|d| d.subsystem == *s).map(|d| (d.name.clone(), FileType::Directory)).collect()),
        ["devices", "virtual", s, n] => {
            let d = device(s, n)?;
            let mut entries = vec![("dev".to_string(), FileType::Regular), ("subsystem".to_string(), FileType::Symlink), ("uevent".to_string(), FileType::Regular)];
            if d.is_net() {
                entries.remove(0);
            }
            if let Some(more) = d.attrs.as_ref().and_then(|a| a.list("")) {
                entries.extend(more);
            }
            Node::Dir(entries)
        }
        ["devices", "virtual", s, n, "dev"] => Node::Text(0o444, format!("{}\n", number(&*device(s, n).filter(|d| !d.is_net())?))),
        ["devices", "virtual", s, n, "subsystem"] => Node::Link(format!("../../../../class/{}", device(s, n)?.subsystem)),
        ["devices", "virtual", s, n, "uevent"] => Node::Uevent(device(s, n)?),
        // Whatever else is under a device is its driver's.
        ["devices", "virtual", s, n, rest @ ..] => {
            let d = device(s, n)?;
            let attrs = d.attrs.clone()?;
            let rest = rest.join("/");
            if let Some(target) = attrs.link(&rest) {
                return Some(Node::Link(target));
            }
            match attrs.read_result(&rest) {
                Some(Ok((mode, text))) => Node::Attr(d, rest, mode, text),
                Some(Err(e)) => Node::Refused(if rest == "carrier" { 0o644 } else { 0o444 }, e),
                None => Node::Dir(attrs.list(&rest)?),
            }
        }
        ["fs"] => dirs(&["cgroup", "selinux"]),
        ["kernel"] => Node::Dir(vec![("uevent_seqnum".to_string(), FileType::Regular)]),
        ["kernel", "uevent_seqnum"] => Node::Text(0o444, format!("{}\n", crate::netlink::uevent_seqnum())),
        _ => return None,
    })
}

/// `path` with the links among its directories followed, and its last
/// name's too with `follow_final`: a class's entry is a link to the
/// device's directory, and a path through it (`class/mem/null/dev`) is a
/// path to the device's file. The namespace follows only the root
/// filesystem's links, so the ones here are followed here. `ELOOP` for
/// links without end, which this tree has none of.
fn resolve(path: &str, follow_final: bool) -> Result<String, Errno> {
    let mut todo: Vec<String> = path.split('/').filter(|c| !c.is_empty()).rev().map(str::to_string).collect();
    let mut done: Vec<String> = Vec::new();
    let mut followed = 0;
    while let Some(c) = todo.pop() {
        match c.as_str() {
            "." => continue,
            ".." => {
                done.pop();
                continue;
            }
            _ => {}
        }
        done.push(c);
        if todo.is_empty() && !follow_final {
            break;
        }
        if let Some(Node::Link(target)) = node(&done.join("/")) {
            followed += 1;
            if followed > 40 {
                return Err(Errno::ELOOP);
            }
            // Its target is from the directory the link is in.
            done.pop();
            todo.extend(target.split('/').filter(|c| !c.is_empty()).rev().map(str::to_string));
        }
    }
    Ok(done.join("/"))
}

/// The processors' subtree, which is [`super::SysCpuFs`]'s.
fn cpu(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("devices/system/cpu")?;
    (rest.is_empty() || rest.starts_with('/')).then(|| rest.trim_start_matches('/'))
}

/// A number for a path: every file and directory its own, since a walk of
/// the tree (`fts`, which `restorecon -R` uses) takes two directories with
/// one number for a loop.
fn ino(path: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    (h >> 16) | (1 << 47)
}

fn file_meta(path: &str, file_type: FileType, mode: u32, size: u64, nlink: u32) -> Metadata {
    Metadata { file_type, size, mode, ino: ino(path), mtime: 0, nlink, rdev: 0, dev: 0, times: Default::default(), owner: None }
}

/// What an action written to a `uevent` file asks for
/// (`kobject_action_type`, `kobject_action_args`): the action, and the
/// variables it adds: `SYNTH_UUID`, 0 when the write gave none, and a
/// `SYNTH_ARG_` for each `KEY=VALUE` after it. `EINVAL` for anything else.
fn synthetic(text: &[u8]) -> Result<(String, Vec<(String, String)>), Errno> {
    const ACTIONS: [&str; 8] = ["add", "remove", "change", "move", "online", "offline", "bind", "unbind"];
    let text = match text.last() {
        Some(b'\n' | 0) => &text[..text.len() - 1],
        _ => text,
    };
    let text = std::str::from_utf8(text).map_err(|_| Errno::EINVAL)?;
    let (action, args) = match text.split_once(' ') {
        Some((a, rest)) => (a, Some(rest)),
        None => (text, None),
    };
    if !ACTIONS.contains(&action) {
        return Err(Errno::EINVAL);
    }
    let Some(args) = args else {
        return Ok((action.to_string(), vec![("SYNTH_UUID".to_string(), "0".to_string())]));
    };
    // A UUID first: 36 characters, hexadecimal but for its four hyphens.
    let bytes = args.as_bytes();
    let uuid_ok = bytes.len() >= 36 && bytes[..36].iter().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { *b == b'-' } else { b.is_ascii_hexdigit() });
    if !uuid_ok {
        return Err(Errno::EINVAL);
    }
    let mut vars = vec![("SYNTH_UUID".to_string(), args[..36].to_string())];
    let mut rest = &args[36..];
    while !rest.is_empty() {
        // A space, a key, an equals sign, a value: letters and digits.
        let pair = rest.strip_prefix(' ').ok_or(Errno::EINVAL)?;
        let end = pair.find(' ').unwrap_or(pair.len());
        let (key, value) = pair[..end].split_once('=').ok_or(Errno::EINVAL)?;
        let word = |w: &str| !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric());
        if !word(key) || !word(value) {
            return Err(Errno::EINVAL);
        }
        vars.push((format!("SYNTH_ARG_{key}"), value.to_string()));
        rest = &pair[end..];
    }
    Ok((action.to_string(), vars))
}

/// sysfs.
pub struct SysFs;

/// An open directory.
#[derive(Debug)]
struct Dir {
    path: String,
    entries: Vec<DirEntry>,
}

impl FileHandle for Dir {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EISDIR)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        SysFs.metadata(&self.path)
    }
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Ok(self.entries.clone())
    }
}

/// What a write to an open file does.
#[derive(Debug)]
enum Writes {
    /// Nothing: the file is only read.
    No,
    /// A device's `uevent` file: an action, for its event.
    Uevent(Arc<Device>),
    /// A file of a device's driver, at this path in its directory.
    Attr(Arc<Device>, String),
}

/// An open file: its text as it was at the open, and what a write does.
#[derive(Debug)]
struct File {
    path: String,
    text: String,
    writes: Writes,
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let data = self.text.as_bytes();
        let at = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - at);
        buf[..n].copy_from_slice(&data[at..at + n]);
        Ok(n as u64)
    }

    /// A write, taken whole. To a `uevent` file it is an action: the
    /// device's event goes out to whoever listens (`uevent_store`).
    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        // Nothing written is nothing asked (`kernfs_fop_write_iter`).
        if buf.is_empty() && !matches!(self.writes, Writes::No) {
            return Ok(0);
        }
        match &self.writes {
            Writes::No => return Err(Errno::EACCES),
            Writes::Uevent(d) => {
                let (action, mut vars) = synthetic(buf)?;
                vars.extend(d.vars());
                crate::netlink::uevent(&action, &d.devpath(), &d.subsystem, &vars);
            }
            Writes::Attr(d, path) => d.attrs.as_ref().ok_or(Errno::EACCES)?.write(path, buf)?,
        }
        Ok(buf.len() as u64)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        SysFs.metadata(&self.path)
    }
}

impl FileSystem for SysFs {
    fn fs_type(&self) -> &'static str {
        "sysfs"
    }

    /// One number, whichever mount is asked: every mount is the one filesystem.
    fn dev(&self) -> u64 {
        super::anon_dev(super::DevKey::Kind("sysfs"))
    }

    fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        let path = &resolve(path, true)?;
        if let Some(rest) = cpu(path) {
            return super::SysCpuFs.open(rest, flags, mode);
        }
        let Some(found) = node(path) else {
            // A file cannot be made here: `EACCES`, in a directory there is.
            let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
            let creating = flags & crate::fs::oflags::O_CREAT != 0 && matches!(node(parent), Some(Node::Dir(_)));
            return Err(if creating { Errno::EACCES } else { Errno::ENOENT });
        };
        match found {
            Node::Dir(names) => {
                if super::writes(flags) {
                    return Err(Errno::EISDIR);
                }
                let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
                let mut entries = vec![
                    DirEntry { name: ".".to_string(), file_type: FileType::Directory, ino: ino(path) },
                    DirEntry { name: "..".to_string(), file_type: FileType::Directory, ino: ino(parent) },
                ];
                let child = |name: &str| if path.is_empty() { name.to_string() } else { format!("{path}/{name}") };
                entries.extend(names.into_iter().map(|(name, file_type)| DirEntry { ino: ino(&child(&name)), name, file_type }));
                Ok(Arc::new(Dir { path: path.to_string(), entries }))
            }
            // Followed above.
            Node::Link(_) => Err(Errno::ELOOP),
            Node::Text(_, text) => {
                if super::writes(flags) {
                    return Err(Errno::EACCES);
                }
                Ok(Arc::new(File { path: path.to_string(), text, writes: Writes::No }))
            }
            Node::Uevent(d) => {
                let text = d.vars().iter().map(|(k, v)| format!("{k}={v}\n")).collect();
                Ok(Arc::new(File { path: path.to_string(), text, writes: Writes::Uevent(d) }))
            }
            Node::Refused(_, e) => Ok(Arc::new(RefusedFile(e))),
            Node::Attr(d, rest, mode, text) => {
                // One with no write bit is only read.
                if super::writes(flags) && mode & 0o200 == 0 {
                    return Err(Errno::EACCES);
                }
                Ok(Arc::new(File { path: path.to_string(), text, writes: if mode & 0o200 != 0 { Writes::Attr(d, rest) } else { Writes::No } }))
            }
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.metadata_nofollow(&resolve(path, true)?)
    }

    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        let path = &resolve(path, false)?;
        if let Some(rest) = cpu(path) {
            let mut md = super::SysCpuFs.metadata(rest)?;
            md.ino = ino(path);
            return Ok(md);
        }
        Ok(match node(path).ok_or(Errno::ENOENT)? {
            Node::Dir(names) => {
                let subdirs = names.iter().filter(|(_, t)| *t == FileType::Directory).count() as u32;
                file_meta(path, FileType::Directory, if path.is_empty() { 0o555 } else { 0o755 }, 0, 2 + subdirs)
            }
            Node::Link(target) => file_meta(path, FileType::Symlink, 0o777, target.len() as u64, 1),
            Node::Text(mode, _) | Node::Attr(_, _, mode, _) | Node::Refused(mode, _) => file_meta(path, FileType::Regular, mode, 4096, 1),
            Node::Uevent(_) => file_meta(path, FileType::Regular, 0o644, 4096, 1),
        })
    }

    fn read_link(&self, path: &str) -> Result<String, Errno> {
        let path = &resolve(path, false)?;
        if let Some(rest) = cpu(path) {
            return super::SysCpuFs.read_link(rest);
        }
        match node(path).ok_or(Errno::ENOENT)? {
            Node::Link(target) => Ok(target),
            _ => Err(Errno::EINVAL),
        }
    }

    // Nothing is made or removed here by a program: Linux says EPERM.
    fn unlink(&self, path: &str) -> Result<(), Errno> {
        self.metadata_nofollow(path).and(Err(Errno::EPERM))
    }
    fn mkdir(&self, _path: &str, _mode: u32) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }
    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        self.metadata_nofollow(path).and(Err(Errno::EPERM))
    }
    fn rename(&self, from: &str, _to: &str) -> Result<(), Errno> {
        self.metadata_nofollow(from).and(Err(Errno::EPERM))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &str) -> String {
        let f = SysFs.open(path, 0, 0).unwrap();
        let mut buf = [0u8; 256];
        let n = f.read_at(0, &mut buf).unwrap() as usize;
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn names(path: &str) -> Vec<String> {
        let mut v: Vec<String> = SysFs.open(path, 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
        v.sort();
        v
    }

    /// A device as Linux 7.0 shows `/dev/null`'s: its directory, its
    /// number, its variables, and the links that lead to it.
    #[test]
    fn a_device_is_where_linux_has_it() {
        assert_eq!(names("devices/virtual/mem/null"), ["dev", "subsystem", "uevent"]);
        assert_eq!(read("devices/virtual/mem/null/dev"), "1:3\n");
        assert_eq!(read("devices/virtual/mem/null/uevent"), "MAJOR=1\nMINOR=3\nDEVNAME=null\nDEVMODE=0666\n");
        assert_eq!(read("devices/virtual/mem/kmsg/uevent"), "MAJOR=1\nMINOR=11\nDEVNAME=kmsg\nDEVMODE=0644\n");
        assert_eq!(read("devices/virtual/tty/console/uevent"), "MAJOR=5\nMINOR=1\nDEVNAME=console\n");
        assert_eq!(SysFs.read_link("devices/virtual/mem/null/subsystem").unwrap(), "../../../../class/mem");
        assert_eq!(SysFs.read_link("class/mem/null").unwrap(), "../../devices/virtual/mem/null");
        assert_eq!(SysFs.read_link("dev/char/1:3").unwrap(), "../../devices/virtual/mem/null");
        assert_eq!(SysFs.read_link("dev/char/5:2").unwrap(), "../../devices/virtual/tty/ptmx");
        assert_eq!(names("class"), ["block", "mem", "misc", "net", "tty"]);
        // A network interface as Linux 7.0 shows `lo`: a class link to its
        // directory, its index and type, and an event of its name and
        // index alone; no device number.
        assert_eq!(names("class/net"), ["eth0", "lo"]);
        assert_eq!(SysFs.read_link("class/net/lo").unwrap(), "../../devices/virtual/net/lo");
        assert_eq!(read("class/net/lo/ifindex"), "1\n");
        assert_eq!(read("class/net/lo/type"), "772\n");
        assert_eq!(read("class/net/lo/address"), "00:00:00:00:00:00\n");
        assert_eq!(read("devices/virtual/net/lo/uevent"), "INTERFACE=lo\nIFINDEX=1\n");
        assert!(!names("devices/virtual/net/lo").iter().any(|n| n == "dev"));
        assert_eq!(names("class/tty"), ["console", "ptmx", "tty"]);
        assert_eq!(names(""), ["block", "bus", "class", "dev", "devices", "fs", "kernel", "module"]);
        let md = SysFs.metadata("devices/virtual/mem/null/uevent").unwrap();
        assert_eq!((md.mode, md.size), (0o644, 4096));
        assert_eq!(SysFs.metadata("devices/virtual/mem/null/dev").unwrap().mode, 0o444);
        assert_eq!(SysFs.metadata("").unwrap().mode, 0o555);
        assert_eq!(SysFs.metadata_nofollow("class/mem/null").unwrap().file_type, FileType::Symlink);
        // Through the links: a class's entry is the device's directory.
        assert_eq!(SysFs.metadata("class/mem/null").unwrap().file_type, FileType::Directory);
        assert_eq!(SysFs.metadata("class/mem/null").unwrap().ino, SysFs.metadata("devices/virtual/mem/null").unwrap().ino);
        assert_eq!(read("class/mem/null/dev"), "1:3\n");
        assert_eq!(read("class/mem/null/subsystem/zero/uevent"), "MAJOR=1\nMINOR=5\nDEVNAME=zero\nDEVMODE=0666\n");
        assert_eq!(names("dev/char/5:0"), ["dev", "subsystem", "uevent"]);
        assert_eq!(SysFs.read_link("class/mem/null/subsystem").unwrap(), "../../../../class/mem");
        assert_eq!(SysFs.metadata("class/mem/null/nothing").err(), Some(Errno::ENOENT));
        assert_eq!(read("devices/virtual/../virtual/./mem/null/dev"), "1:3\n");
        assert_eq!(SysFs.metadata("devices/virtual/mem/nothing").err(), Some(Errno::ENOENT));
        assert_eq!(SysFs.read_link("devices/virtual/mem/null").err(), Some(Errno::EINVAL));
        assert_eq!(SysFs.mkdir("fs/new", 0o755), Err(Errno::EPERM));
        assert_eq!(SysFs.open("fs/new", crate::fs::oflags::O_CREAT | 1, 0o644).err(), Some(Errno::EACCES));
        assert_eq!(SysFs.open("nothing/new", crate::fs::oflags::O_CREAT | 1, 0o644).err(), Some(Errno::ENOENT));
        // The processors are under it.
        assert_eq!(read("devices/system/cpu/online").trim_end().chars().next(), Some('0'));
    }

    /// The disks a kernel starts with are in the tree: sixteen loop
    /// devices, each with what the block layer says of it, and the loop
    /// devices' control among the miscellaneous devices.
    #[test]
    fn the_first_disks_are_there() {
        let disks = names("block");
        for n in 0..16 {
            assert!(disks.contains(&format!("loop{n}")), "{n}");
        }
        assert_eq!(SysFs.read_link("block/loop3").unwrap(), "../devices/virtual/block/loop3");
        assert_eq!(SysFs.read_link("class/block/loop3").unwrap(), "../../devices/virtual/block/loop3");
        assert_eq!(SysFs.read_link("dev/block/7:3").unwrap(), "../../devices/virtual/block/loop3");
        assert_eq!(read("block/loop3/dev"), "7:3\n");
        assert_eq!(read("block/loop3/size"), "0\n");
        assert_eq!(read("block/loop3/ro"), "0\n");
        assert_eq!(read("block/loop3/queue/logical_block_size"), "512\n");
        assert_eq!(read("block/loop3/queue/read_ahead_kb"), "128\n");
        assert!(read("block/loop3/uevent").starts_with("MAJOR=7\nMINOR=3\nDEVNAME=loop3\nDEVTYPE=disk\nDISKSEQ="));
        assert_eq!(SysFs.metadata("block/loop3/loop").err(), Some(Errno::ENOENT));
        assert_eq!(SysFs.metadata("block/loop3/queue/read_ahead_kb").unwrap().mode, 0o644);
        assert_eq!(SysFs.open("block/loop3/size", 1, 0).err(), Some(Errno::EACCES));
        assert_eq!(read("class/misc/loop-control/uevent"), "MAJOR=10\nMINOR=237\nDEVNAME=loop-control\n");
        assert_eq!(SysFs.read_link("dev/char/10:237").unwrap(), "../../devices/virtual/misc/loop-control");
    }

    /// Every directory has a number of its own, and says how many
    /// directories it holds.
    #[test]
    fn directories_are_told_apart() {
        let mut seen = std::collections::HashSet::new();
        let mut todo = vec![String::new()];
        while let Some(dir) = todo.pop() {
            let md = SysFs.metadata(&dir).unwrap();
            assert!(seen.insert(md.ino), "{dir}");
            let entries = SysFs.open(&dir, 0, 0).unwrap().read_dir().unwrap();
            let subdirs: Vec<_> = entries.iter().filter(|e| e.file_type == FileType::Directory && e.name != "." && e.name != "..").collect();
            if !dir.starts_with("devices/system/cpu") {
                assert_eq!(md.nlink as usize, 2 + subdirs.len(), "{dir}");
            }
            for e in subdirs {
                todo.push(if dir.is_empty() { e.name.clone() } else { format!("{dir}/{}", e.name) });
            }
        }
        assert!(seen.len() > 20);
    }

    /// What a write to a `uevent` file may be, as Linux 7.0 took and
    /// refused them.
    #[test]
    fn an_action_is_read_as_the_kernel_reads_it() {
        let none = vec![("SYNTH_UUID".to_string(), "0".to_string())];
        assert_eq!(synthetic(b"add"), Ok(("add".to_string(), none.clone())));
        assert_eq!(synthetic(b"change\n"), Ok(("change".to_string(), none)));
        assert_eq!(synthetic(b"bogus"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"ad"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b""), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"\n"), Err(Errno::EINVAL));
        let (action, vars) = synthetic(b"add 01234567-89ab-cdef-0123-456789abcdef A=1 B=2").unwrap();
        assert_eq!(action, "add");
        assert_eq!(vars, [("SYNTH_UUID", "01234567-89ab-cdef-0123-456789abcdef"), ("SYNTH_ARG_A", "1"), ("SYNTH_ARG_B", "2")].map(|(k, v)| (k.to_string(), v.to_string())));
        assert_eq!(synthetic(b"add 01234567-89ab-cdef-0123-456789abcdef").unwrap().1.len(), 1);
        assert_eq!(synthetic(b"add 0123"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"add 01234567x89ab-cdef-0123-456789abcdef"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"add 01234567-89ab-cdef-0123-456789abcdef A"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"add 01234567-89ab-cdef-0123-456789abcdef A=b-c"), Err(Errno::EINVAL));
        assert_eq!(synthetic(b"add 01234567-89ab-cdef-0123-456789abcdef  A=1"), Err(Errno::EINVAL));
    }
}
