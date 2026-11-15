//! The device-mapper: block devices made of pieces of other block devices
//! (drivers/md/dm-ioctl.c and dm.c, as Linux 7.0's behave).
//!
//! Android makes its partitions with it (fs_mgr), and `apexd` a device
//! for every APEX: a name first, and for an APEX that is not part of the
//! system image a table that checks its payload.
//!
//! `/dev/device-mapper` (10:236) takes every request as a `struct
//! dm_ioctl`, 312 bytes, with whatever goes with it after:
//!
//! - `DM_VERSION`: the interface is 4.50.0; a request for another major
//!   version is `EINVAL`.
//! - `DM_DEV_CREATE`: a device by name, and uuid if given: a number
//!   (252:n), with no disk behind it until it is given a table (its node
//!   is `ENXIO` and sysfs has nothing of it). `EBUSY` for a name or uuid
//!   in use; `EINVAL` for a name that is empty or has a slash.
//! - `DM_DEV_STATUS`, by name or by uuid (`ENXIO` for neither): its
//!   number, how many have it open, and its flags: suspended, read-only,
//!   a table in use, a table waiting.
//! - `DM_TABLE_LOAD`: a table that waits: targets end to end from sector
//!   0 (`EINVAL` for a gap, or for none). At the first the disk appears,
//!   as `dm-<n>`, with its `add` event.
//! - `DM_DEV_SUSPEND`: with the flag, suspended; without, resumed, and
//!   the waiting table is the device's from then: its size is the
//!   table's. A `change` event tells of it.
//! - `DM_TABLE_CLEAR`, `DM_TABLE_STATUS` (the table read back, or each
//!   target's status), `DM_TABLE_DEPS` (the devices it is made of),
//!   `DM_LIST_DEVICES`, `DM_LIST_VERSIONS`, `DM_GET_TARGET_VERSION`,
//!   `DM_DEV_RENAME`, `DM_REMOVE_ALL`.
//! - `DM_DEV_REMOVE`: `EBUSY` while it is open, unless the removal is
//!   asked to wait for the last close.
//!
//! The targets: `linear` (`<device> <sector>`: a run of another block
//! device, named by number or by path), `zero` (reads zeros, takes
//! writes), `error` (fails both).
//!
//! sysfs: `block/dm-<n>/dm/name`, `uuid`, `suspended`, and `slaves/` with
//! a link to each device the table is made of.
//!
//! Not here, and refused out loud: `verity` and every other target,
//! `DM_DEV_WAIT`, `DM_TARGET_MSG`, `DM_DEV_SET_GEOMETRY`,
//! `DM_DEV_ARM_POLL`. A suspended device still reads and writes, where
//! Linux holds its I/O until it is resumed.

use crate::block::{self, Disk};
use crate::errno::{Errno, SysResult};
use crate::vfs::devices::{major, makedev, minor};
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The block major the device-mapper has (dynamic on Linux: this is what
/// Linux 7.0 gives it).
const DM_MAJOR: u32 = 252;
/// `sizeof(struct dm_ioctl)`, and where its fields are.
const HEADER: usize = 312;
const NAME_AT: usize = 48;
const UUID_AT: usize = 176;
const VERSION: [u32; 3] = [4, 50, 0];

mod flag {
    pub const READONLY: u32 = 1 << 0;
    pub const SUSPEND: u32 = 1 << 1;
    pub const PERSISTENT_DEV: u32 = 1 << 3;
    pub const STATUS_TABLE: u32 = 1 << 4;
    pub const ACTIVE_PRESENT: u32 = 1 << 5;
    pub const INACTIVE_PRESENT: u32 = 1 << 6;
    pub const BUFFER_FULL: u32 = 1 << 8;
    pub const QUERY_INACTIVE_TABLE: u32 = 1 << 12;
    pub const UEVENT_GENERATED: u32 = 1 << 13;
    pub const UUID: u32 = 1 << 14;
    pub const SECURE_DATA: u32 = 1 << 15;
    pub const DATA_OUT: u32 = 1 << 16;
    pub const DEFERRED_REMOVE: u32 = 1 << 17;
    pub const INTERNAL_SUSPEND: u32 = 1 << 18;
}

/// Say once per kind that a program asked for something not done here.
fn unimplemented(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] device-mapper: {what} is not implemented");
        said.push(what.to_string());
    }
}

/// What a target does with its sectors.
#[derive(Clone, Debug)]
enum Kind {
    /// A run of `disk` (numbered `dev`) from sector `offset`.
    Linear { disk: Arc<dyn Disk>, dev: u64, offset: u64 },
    Zero,
    Error,
}

#[derive(Clone, Debug)]
struct Target {
    /// Its first sector in the device, and how many.
    start: u64,
    len: u64,
    kind: Kind,
}

impl Target {
    fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Linear { .. } => "linear",
            Kind::Zero => "zero",
            Kind::Error => "error",
        }
    }

    /// Its words as a table has them (`STATUSTYPE_TABLE`).
    fn words(&self) -> String {
        match &self.kind {
            Kind::Linear { dev, offset, .. } => format!("{}:{} {offset}", major(*dev), minor(*dev)),
            _ => String::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Table {
    targets: Vec<Target>,
    read_only: bool,
}

impl Table {
    fn sectors(&self) -> u64 {
        self.targets.last().map_or(0, |t| t.start + t.len)
    }

    /// The devices it is made of, each once.
    fn deps(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for t in &self.targets {
            if let Kind::Linear { dev, .. } = t.kind {
                if !out.contains(&dev) {
                    out.push(dev);
                }
            }
        }
        out
    }
}

#[derive(Debug, Default)]
struct State {
    name: String,
    uuid: String,
    active: Option<Table>,
    inactive: Option<Table>,
    suspended: bool,
    openers: u32,
    /// Its disk is there: it has had a table.
    added: bool,
    /// Asked to be removed while open: gone at the last close.
    deferred: bool,
    /// How many events it has had (none are raised here: no target has
    /// any to raise).
    event_nr: u32,
}

/// A mapped device.
#[derive(Debug)]
pub struct Mapped {
    minor: u32,
    state: Mutex<State>,
}

static DEVICES: Mutex<BTreeMap<u32, Arc<Mapped>>> = Mutex::new(BTreeMap::new());

impl Mapped {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn dev(&self) -> u64 {
        makedev(DM_MAJOR, self.minor)
    }

    /// The target sector `sector` of the device is in, in the table in
    /// use.
    fn target(&self, sector: u64) -> Option<Target> {
        self.state().active.as_ref()?.targets.iter().find(|t| sector >= t.start && sector < t.start + t.len).cloned()
    }

    /// Read or write through the targets, a target's run at a time.
    fn io(&self, mut offset: u64, len: usize, mut each: impl FnMut(&Target, u64, std::ops::Range<usize>) -> Result<(), Errno>) -> SysResult {
        let mut done = 0;
        while done < len {
            let t = self.target(offset / 512).ok_or(Errno::EIO)?;
            let within = offset - t.start * 512;
            let n = ((t.len * 512 - within) as usize).min(len - done);
            each(&t, within, done..done + n)?;
            done += n;
            offset += n as u64;
        }
        Ok(len as u64)
    }
}

impl Disk for Mapped {
    fn size(&self) -> u64 {
        self.state().active.as_ref().map_or(0, |t| t.sectors() * 512)
    }

    fn read_only(&self) -> bool {
        self.state().active.as_ref().is_some_and(|t| t.read_only)
    }

    fn set_read_only(&self, ro: bool) {
        if let Some(t) = self.state().active.as_mut() {
            t.read_only = ro;
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let len = buf.len();
        self.io(offset, len, |t, within, range| match &t.kind {
            Kind::Linear { disk, offset, .. } => {
                // All of it: what the device under it has not got reads
                // as an error, as a read past a disk's end does.
                let mut at = 0;
                let part = &mut buf[range];
                while at < part.len() {
                    match disk.read_at(offset * 512 + within + at as u64, &mut part[at..])? {
                        0 => return Err(Errno::EIO),
                        n => at += n as usize,
                    }
                }
                Ok(())
            }
            Kind::Zero => {
                buf[range].fill(0);
                Ok(())
            }
            Kind::Error => Err(Errno::EIO),
        })
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> SysResult {
        self.io(offset, buf.len(), |t, within, range| match &t.kind {
            Kind::Linear { disk, offset, .. } => {
                if disk.read_only() {
                    return Err(Errno::EIO);
                }
                let mut at = 0;
                let part = &buf[range];
                while at < part.len() {
                    match disk.write_at(offset * 512 + within + at as u64, &part[at..])? {
                        0 => return Err(Errno::EIO),
                        n => at += n as usize,
                    }
                }
                Ok(())
            }
            Kind::Zero => Ok(()),
            Kind::Error => Err(Errno::EIO),
        })
    }

    fn opened(&self) -> Result<(), Errno> {
        self.state().openers += 1;
        Ok(())
    }

    fn released(&self) {
        let gone = {
            let mut st = self.state();
            st.openers = st.openers.saturating_sub(1);
            st.openers == 0 && st.deferred
        };
        if gone {
            let mut devices = DEVICES.lock().unwrap_or_else(|e| e.into_inner());
            devices.remove(&self.minor);
            drop(devices);
            block::remove(self.dev());
        }
    }

    fn sysfs_dir(&self) -> Option<(&'static str, Vec<&'static str>)> {
        Some(("dm", vec!["name", "suspended", "uuid"]))
    }

    fn sysfs_read(&self, name: &str) -> Option<String> {
        let st = self.state();
        Some(match name {
            "name" => format!("{}\n", st.name),
            "uuid" => format!("{}\n", st.uuid),
            "suspended" => format!("{}\n", st.suspended as u32),
            _ => return None,
        })
    }

    fn slaves(&self) -> Vec<u64> {
        self.state().active.as_ref().map(Table::deps).unwrap_or_default()
    }
}

/// A request as it came: the header's fields, and the bytes after it.
struct Request<'a> {
    flags: u32,
    target_count: u32,
    dev: u64,
    name: String,
    uuid: String,
    /// Everything from the request's start (`data_start` counts from
    /// there).
    all: &'a [u8],
    data_start: usize,
}

/// What a request answers with, beyond the device's status.
#[derive(Default)]
struct Answer {
    /// The device the status is of.
    device: Option<Arc<Mapped>>,
    /// Flags the request sets in its answer.
    set: u32,
    /// What goes after the header.
    data: Option<Vec<u8>>,
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The device a request names: by its name, or with none by its uuid.
/// `ENXIO` for one that is not there.
fn find(devices: &BTreeMap<u32, Arc<Mapped>>, r: &Request<'_>) -> Result<Arc<Mapped>, Errno> {
    if r.name.is_empty() && r.uuid.is_empty() {
        return Err(Errno::ENXIO);
    }
    devices
        .values()
        .find(|d| {
            let st = d.state();
            if r.name.is_empty() { st.uuid == r.uuid } else { st.name == r.name }
        })
        .cloned()
        .ok_or(Errno::ENXIO)
}

/// `check_name`: not empty, and no slash.
fn check_name(name: &str) -> Result<(), Errno> {
    if name.is_empty() || name.contains('/') {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The targets there are, with their versions.
const TARGETS: [(&str, [u32; 3]); 3] = [("error", [1, 7, 0]), ("linear", [1, 5, 0]), ("zero", [1, 2, 0])];

/// `struct dm_target_versions` for each of `targets`, one after another.
fn versions(targets: &[(&str, [u32; 3])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (name, version)) in targets.iter().enumerate() {
        let len = (16 + name.len() + 1 + 7) & !7;
        let next = if i + 1 == targets.len() { 0 } else { len as u32 };
        let at = out.len();
        out.extend_from_slice(&next.to_le_bytes());
        for v in version {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.resize(at + len, 0);
    }
    out
}

/// How a device named in a table is found: its number from its path.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<u64, Errno>;

/// A table from a `DM_TABLE_LOAD`: `count` `struct dm_target_spec`, each
/// with its words after it and the next at `next` bytes from its start.
fn parse_table(r: &Request<'_>, resolve: Resolve<'_>) -> Result<Table, Errno> {
    if r.target_count == 0 {
        return Err(Errno::EINVAL);
    }
    let mut targets: Vec<Target> = Vec::new();
    let mut at = r.data_start;
    for _ in 0..r.target_count {
        let spec = r.all.get(at..at + 40).ok_or(Errno::EINVAL)?;
        let start = u64::from_le_bytes(spec[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(spec[8..16].try_into().unwrap());
        let next = u32::from_le_bytes(spec[20..24].try_into().unwrap()) as usize;
        let kind = cstr(&spec[24..40]);
        let words = cstr(&r.all[at + 40..]);
        // End to end, from sector 0.
        if start != targets.last().map_or(0, |t| t.start + t.len) || len == 0 {
            return Err(Errno::EINVAL);
        }
        let args: Vec<&str> = words.split_ascii_whitespace().collect();
        let kind = match kind.as_str() {
            "linear" => {
                let [device, offset] = args[..] else {
                    return Err(Errno::EINVAL);
                };
                let offset: u64 = offset.parse().map_err(|_| Errno::EINVAL)?;
                // By number, or by the path of its node.
                let dev = match device.split_once(':').and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?))) {
                    Some((a, b)) => makedev(a, b),
                    None => resolve(device)?,
                };
                let disk = block::disk(dev).ok_or(Errno::ENXIO)?;
                Kind::Linear { disk, dev, offset }
            }
            "zero" => {
                if !args.is_empty() {
                    return Err(Errno::EINVAL);
                }
                Kind::Zero
            }
            "error" => Kind::Error,
            other => {
                unimplemented(&format!("the {other} target"));
                return Err(Errno::EINVAL);
            }
        };
        targets.push(Target { start, len, kind });
        at += next;
    }
    Ok(Table { targets, read_only: r.flags & flag::READONLY != 0 })
}

/// A table as `DM_TABLE_STATUS` gives it: a `struct dm_target_spec` and
/// a string for each target, `next` counted from the start of them all.
/// The string is the target's words with `words`, else its status.
fn table_status(table: &Table, words: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for t in &table.targets {
        let text = if words { t.words() } else { String::new() };
        let at = out.len();
        let end = (at + 40 + text.len() + 1 + 7) & !7;
        out.extend_from_slice(&t.start.to_le_bytes());
        out.extend_from_slice(&t.len.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&(end as u32).to_le_bytes());
        let mut kind = [0u8; 16];
        kind[..t.type_name().len()].copy_from_slice(t.type_name().as_bytes());
        out.extend_from_slice(&kind);
        out.extend_from_slice(text.as_bytes());
        out.resize(end, 0);
    }
    out
}

/// One request (`ctl_ioctl`'s commands).
fn handle(cmd: u64, r: &Request<'_>, resolve: Resolve<'_>) -> Result<Answer, Errno> {
    let mut devices = DEVICES.lock().unwrap_or_else(|e| e.into_inner());
    let mut answer = Answer::default();
    match cmd {
        // DM_VERSION
        0 => {}
        // DM_REMOVE_ALL: every device nobody has open.
        1 => {
            let idle: Vec<u32> = devices.values().filter(|d| d.state().openers == 0).map(|d| d.minor).collect();
            for m in idle {
                if let Some(d) = devices.remove(&m) {
                    if d.state().added {
                        block::remove(d.dev());
                    }
                }
            }
        }
        // DM_LIST_DEVICES: a `struct dm_name_list` each, with after its
        // name the event number and whether it has a uuid, and the uuid.
        2 => {
            let mut out = Vec::new();
            let all: Vec<&Arc<Mapped>> = devices.values().collect();
            if all.is_empty() {
                out.extend_from_slice(&[0u8; 16]);
            }
            for (i, d) in all.iter().enumerate() {
                let st = d.state();
                let at = out.len();
                out.extend_from_slice(&d.dev().to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(st.name.as_bytes());
                out.push(0);
                out.resize((out.len() + 7) & !7, 0);
                out.extend_from_slice(&st.event_nr.to_le_bytes());
                out.extend_from_slice(&(if st.uuid.is_empty() { 2u32 } else { 1 }).to_le_bytes());
                if !st.uuid.is_empty() {
                    out.extend_from_slice(st.uuid.as_bytes());
                    out.push(0);
                }
                out.resize((out.len() + 7) & !7, 0);
                if i + 1 != all.len() {
                    let next = (out.len() - at) as u32;
                    out[at + 8..at + 12].copy_from_slice(&next.to_le_bytes());
                }
            }
            answer.data = Some(out);
        }
        // DM_DEV_CREATE
        3 => {
            check_name(&r.name)?;
            let taken = devices.values().any(|d| {
                let st = d.state();
                st.name == r.name || (!r.uuid.is_empty() && st.uuid == r.uuid)
            });
            if taken {
                return Err(Errno::EBUSY);
            }
            let number = if r.flags & flag::PERSISTENT_DEV != 0 {
                let m = minor(r.dev);
                if devices.contains_key(&m) {
                    return Err(Errno::EBUSY);
                }
                m
            } else {
                (0..).find(|m| !devices.contains_key(m)).unwrap()
            };
            let d = Arc::new(Mapped { minor: number, state: Mutex::new(State { name: r.name.clone(), uuid: r.uuid.clone(), ..State::default() }) });
            devices.insert(number, Arc::clone(&d));
            answer.device = Some(d);
        }
        // DM_DEV_REMOVE
        4 => {
            let d = find(&devices, r)?;
            let (open, added) = {
                let st = d.state();
                (st.openers > 0, st.added)
            };
            if open {
                if r.flags & flag::DEFERRED_REMOVE == 0 {
                    return Err(Errno::EBUSY);
                }
                d.state().deferred = true;
                answer.set |= flag::DEFERRED_REMOVE;
                answer.device = Some(d);
            } else {
                devices.remove(&d.minor);
                if added {
                    drop(devices);
                    block::remove(d.dev());
                    answer.set |= flag::UEVENT_GENERATED;
                }
            }
        }
        // DM_DEV_RENAME: the new name (or with the flag, a uuid for a
        // device that has none) is the string after the header.
        5 => {
            let d = find(&devices, r)?;
            let new = cstr(r.all.get(r.data_start..).ok_or(Errno::EINVAL)?);
            let uuid = r.flags & flag::UUID != 0;
            if !uuid {
                check_name(&new)?;
            }
            let taken = devices.values().any(|o| {
                let st = o.state();
                if uuid { st.uuid == new } else { st.name == new }
            });
            if taken || new.is_empty() {
                return Err(if new.is_empty() { Errno::EINVAL } else { Errno::EBUSY });
            }
            {
                let mut st = d.state();
                if uuid {
                    if !st.uuid.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    st.uuid = new;
                } else {
                    st.name = new;
                }
            }
            if d.state().added {
                block::changed(d.dev());
                answer.set |= flag::UEVENT_GENERATED;
            }
            answer.device = Some(d);
        }
        // DM_DEV_SUSPEND: with the flag suspend; without, resume, and
        // the waiting table is in use from now.
        6 => {
            let d = find(&devices, r)?;
            let changed = {
                let mut st = d.state();
                if r.flags & flag::SUSPEND != 0 {
                    st.suspended = true;
                    false
                } else {
                    st.suspended = false;
                    if let Some(t) = st.inactive.take() {
                        st.active = Some(t);
                    }
                    st.added
                }
            };
            if changed {
                block::changed(d.dev());
                answer.set |= flag::UEVENT_GENERATED;
            }
            answer.device = Some(d);
        }
        // DM_DEV_STATUS
        7 => answer.device = Some(find(&devices, r)?),
        // DM_TABLE_LOAD: the table waits; the disk is there from the
        // first.
        9 => {
            let d = find(&devices, r)?;
            let table = parse_table(r, resolve)?;
            let first = {
                let mut st = d.state();
                st.inactive = Some(table);
                !std::mem::replace(&mut st.added, true)
            };
            if first {
                block::add(d.dev(), &format!("dm-{}", d.minor), Arc::clone(&d) as Arc<dyn Disk>, true);
            }
            answer.device = Some(d);
        }
        // DM_TABLE_CLEAR
        10 => {
            let d = find(&devices, r)?;
            d.state().inactive = None;
            answer.device = Some(d);
        }
        // DM_TABLE_DEPS: `struct dm_target_deps`.
        11 | 12 => {
            let d = find(&devices, r)?;
            let table = {
                let st = d.state();
                if r.flags & flag::QUERY_INACTIVE_TABLE != 0 { st.inactive.clone() } else { st.active.clone() }
            }
            .unwrap_or_default();
            answer.data = Some(if cmd == 11 {
                let deps = table.deps();
                let mut out = (deps.len() as u32).to_le_bytes().to_vec();
                out.extend_from_slice(&0u32.to_le_bytes());
                for dev in deps {
                    out.extend_from_slice(&dev.to_le_bytes());
                }
                out
            } else {
                table_status(&table, r.flags & flag::STATUS_TABLE != 0)
            });
            answer.device = Some(d);
        }
        // DM_LIST_VERSIONS
        13 => answer.data = Some(versions(&TARGETS)),
        // DM_GET_TARGET_VERSION: of the target the name field names.
        17 => {
            let t = TARGETS.iter().find(|(n, _)| *n == r.name).ok_or(Errno::EINVAL)?;
            answer.data = Some(versions(&[*t]));
        }
        // DM_DEV_WAIT, DM_TARGET_MSG, DM_DEV_SET_GEOMETRY, DM_DEV_ARM_POLL
        8 | 14 | 15 | 16 => {
            unimplemented(&format!("request {cmd}"));
            return Err(Errno::EOPNOTSUPP);
        }
        _ => return Err(Errno::ENOTTY),
    }
    Ok(answer)
}

/// `/dev/device-mapper`.
pub struct Control {
    node: Option<crate::vfs::devices::NodeMeta>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("dm::Control")
    }
}

impl Control {
    pub fn open(node: Option<crate::vfs::devices::NodeMeta>) -> Arc<dyn FileHandle> {
        Arc::new(Control { node })
    }

    /// A request: `_IOWR(0xfd, command, struct dm_ioctl)` with the
    /// structure, and what goes with it, at `arg`. The answer is written
    /// over it: the interface's version, the device's status, and after
    /// the header whatever the command gives, as far as there is room
    /// (the rest lost, and said to be, with `DM_BUFFER_FULL_FLAG`).
    pub fn ioctl(&self, m: &mut GuestMem<'_>, request: u64, arg: u64, resolve: Resolve<'_>) -> SysResult {
        if request >> 8 & 0xff != 0xfd {
            return Err(Errno::ENOTTY);
        }
        let cmd = request & 0xff;
        let header = m.read(arg, HEADER)?.to_vec();
        let u32_at = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
        let (version, data_size, data_start) = ([u32_at(0), u32_at(4), u32_at(8)], u32_at(12) as usize, u32_at(16) as usize);
        // Its major version, and no newer a minor.
        if version[0] != VERSION[0] || version[1] > VERSION[1] {
            return Err(Errno::EINVAL);
        }
        // Room for the header (but for the padding at its end), and not
        // more than anybody sends.
        if data_size < HEADER - 7 || data_size > 16 << 20 {
            return Err(Errno::EINVAL);
        }
        let all = m.read(arg, data_size)?.to_vec();
        let r = Request {
            flags: u32_at(28) & !(flag::BUFFER_FULL | flag::UEVENT_GENERATED | flag::SECURE_DATA | flag::DATA_OUT),
            target_count: u32_at(20),
            dev: u64::from_le_bytes(header[40..48].try_into().unwrap()),
            name: cstr(&header[NAME_AT..NAME_AT + 128]),
            uuid: cstr(&header[UUID_AT..UUID_AT + 129]),
            all: &all,
            data_start: data_start.min(all.len()),
        };
        let answer = handle(cmd, &r, resolve)?;

        // The answer: the header again, with the version, and of the
        // device its number, opens, events, targets, flags and names.
        let mut out = header;
        for (i, v) in VERSION.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut flags = r.flags | answer.set;
        if let Some(d) = &answer.device {
            let st = d.state();
            flags &= !(flag::SUSPEND | flag::READONLY | flag::ACTIVE_PRESENT | flag::INACTIVE_PRESENT | flag::INTERNAL_SUSPEND);
            let shown = if r.flags & flag::QUERY_INACTIVE_TABLE != 0 { st.inactive.as_ref() } else { st.active.as_ref() };
            if st.suspended {
                flags |= flag::SUSPEND;
            }
            if st.active.is_some() {
                flags |= flag::ACTIVE_PRESENT;
            }
            if st.inactive.is_some() {
                flags |= flag::INACTIVE_PRESENT;
            }
            if shown.is_some_and(|t| t.read_only) {
                flags |= flag::READONLY;
            }
            out[20..24].copy_from_slice(&(shown.map_or(0, |t| t.targets.len()) as u32).to_le_bytes());
            out[24..28].copy_from_slice(&(st.openers as i32).to_le_bytes());
            out[32..36].copy_from_slice(&st.event_nr.to_le_bytes());
            out[40..48].copy_from_slice(&d.dev().to_le_bytes());
            out[NAME_AT..NAME_AT + 128].fill(0);
            out[NAME_AT..NAME_AT + st.name.len().min(127)].copy_from_slice(&st.name.as_bytes()[..st.name.len().min(127)]);
            out[UUID_AT..UUID_AT + 129].fill(0);
            out[UUID_AT..UUID_AT + st.uuid.len().min(128)].copy_from_slice(&st.uuid.as_bytes()[..st.uuid.len().min(128)]);
        }
        // What goes after the header, where the request left room.
        let mut used = HEADER;
        if let Some(data) = &answer.data {
            if HEADER + data.len() <= data_size {
                m.write(arg + HEADER as u64, data)?;
                used += data.len();
            } else {
                flags |= flag::BUFFER_FULL;
            }
            out[16..20].copy_from_slice(&(HEADER as u32).to_le_bytes());
        }
        out[12..16].copy_from_slice(&(used as u32).to_le_bytes());
        out[28..32].copy_from_slice(&flags.to_le_bytes());
        // As much of the header as the request had room for.
        m.write(arg, &out[..HEADER.min(data_size)])?;
        Ok(0)
    }
}

impl FileHandle for Control {
    fn as_dm(self: Arc<Self>) -> Option<Arc<Control>> {
        Some(self)
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(match &self.node {
            Some(node) => node(),
            None => Metadata { file_type: FileType::CharDevice, size: 0, mode: 0o600, ino: crate::vfs::anon_ino(self as *const Self as *const u8), mtime: 0, nlink: 1, rdev: makedev(10, 236), times: Default::default(), owner: None },
        })
    }
}
