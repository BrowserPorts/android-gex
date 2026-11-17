//! cgroup v1 (`kernel/cgroup/cgroup-v1.c` at android17-6.18): hierarchies
//! a controller, or a set of them, is bound to by `mount -t cgroup`, as
//! Android mounts cpuset at `/dev/cpuset` (`noprefix,cpuset_v2_mode`), cpu
//! at `/dev/cpuctl` and blkio at `/dev/blkio`; and a named hierarchy with
//! no controller (`none,name=…`).
//!
//! Membership is a thread's (`tasks`; `cgroup.procs` moves a process's
//! every thread), one group in each hierarchy, a new process's and a new
//! thread's those of its process. The controllers' files are GKI's
//! (`cpuset_v1` with `CPUSETS_V1`; the cpu controller's legacy files with
//! `CFS_BANDWIDTH` and `UCLAMP_TASK_GROUP`, Android's
//! `uclamp.latency_sensitive` among them; blkio's with throttling and I/O
//! priority, no BFQ): each takes what Linux takes and reads back what was
//! written. **Kept and not applied**: this kernel schedules nothing itself
//! (a guest thread is a host thread) and has no block I/O to throttle,
//! which is said once.

use crate::errno::Errno;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

/// The controllers this kernel has (`/proc/cgroups`), in their order.
pub const CONTROLLERS: &[&str] = &["cpuset", "cpu", "blkio"];

/// A controller's files (without its prefix), their modes, and whether
/// only the root has one.
fn controller_files(c: &str) -> &'static [(&'static str, u32, bool)] {
    match c {
        "cpuset" => &[
            ("cpus", 0o644, false),
            ("mems", 0o644, false),
            ("effective_cpus", 0o444, false),
            ("effective_mems", 0o444, false),
            ("cpu_exclusive", 0o644, false),
            ("mem_exclusive", 0o644, false),
            ("mem_hardwall", 0o644, false),
            ("sched_load_balance", 0o644, false),
            ("sched_relax_domain_level", 0o644, false),
            ("memory_migrate", 0o644, false),
            ("memory_pressure", 0o444, false),
            ("memory_spread_page", 0o644, false),
            ("memory_spread_slab", 0o644, false),
            ("memory_pressure_enabled", 0o644, true),
        ],
        "cpu" => &[
            ("shares", 0o644, false),
            ("idle", 0o644, false),
            ("cfs_period_us", 0o644, false),
            ("cfs_quota_us", 0o644, false),
            ("cfs_burst_us", 0o644, false),
            ("stat", 0o444, false),
            ("stat.local", 0o444, false),
            ("uclamp.min", 0o644, false),
            ("uclamp.max", 0o644, false),
            ("uclamp.latency_sensitive", 0o644, false),
        ],
        "blkio" => &[
            ("reset_stats", 0o200, false),
            ("prio.class", 0o644, false),
            ("throttle.read_bps_device", 0o644, false),
            ("throttle.write_bps_device", 0o644, false),
            ("throttle.read_iops_device", 0o644, false),
            ("throttle.write_iops_device", 0o644, false),
            ("throttle.io_service_bytes", 0o444, false),
            ("throttle.io_service_bytes_recursive", 0o444, false),
            ("throttle.io_serviced", 0o444, false),
            ("throttle.io_serviced_recursive", 0o444, false),
        ],
        _ => &[],
    }
}

/// Every hierarchy's core files, and the root's alone.
const CORE: &[(&str, u32, bool)] = &[
    ("cgroup.procs", 0o644, false),
    ("tasks", 0o644, false),
    ("notify_on_release", 0o644, false),
    ("cgroup.clone_children", 0o644, false),
    ("release_agent", 0o644, true),
    ("cgroup.sane_behavior", 0o444, true),
];

#[derive(Debug)]
pub struct Group {
    pub parent: Option<u64>,
    pub name: String,
    pub children: BTreeMap<String, u64>,
    pub mode: u32,
    pub owner: (u32, u32),
    pub made_by: (u32, u32),
    pub files: HashMap<String, (u32, u32, u32)>,
    /// The controllers' settings, as written (by file name, unprefixed).
    pub values: HashMap<&'static str, String>,
    pub notify_on_release: bool,
    pub clone_children: bool,
}

#[derive(Debug)]
pub struct Hierarchy {
    pub id: u32,
    pub controllers: Vec<&'static str>,
    pub name: Option<String>,
    pub noprefix: bool,
    pub release_agent: String,
    pub groups: BTreeMap<u64, Group>,
    /// Each thread's group.
    pub tasks: HashMap<i32, u64>,
    next: u64,
}

pub const ROOT: u64 = 1;

impl Hierarchy {
    pub fn at(&self, path: &str) -> Option<u64> {
        let mut id = ROOT;
        for name in path.split('/').filter(|s| !s.is_empty()) {
            id = *self.groups.get(&id)?.children.get(name)?;
        }
        Some(id)
    }

    pub fn path_of(&self, id: u64) -> String {
        let mut names = Vec::new();
        let mut at = Some(id);
        while let Some(g) = at.and_then(|i| self.groups.get(&i)) {
            if g.parent.is_some() {
                names.push(g.name.clone());
            }
            at = g.parent;
        }
        names.reverse();
        format!("/{}", names.join("/"))
    }

    /// A file's name as this hierarchy shows it, from a controller's.
    fn shown(&self, controller: &str, file: &str) -> String {
        if self.noprefix { file.to_string() } else { format!("{controller}.{file}") }
    }

    /// The files group `id` has: name, mode, and its controller and the
    /// controller's name for it (`None` for a core file).
    pub fn files_of(&self, id: u64) -> Vec<(String, u32, Option<(&'static str, &'static str)>)> {
        let root = id == ROOT;
        let mut out: Vec<(String, u32, Option<(&'static str, &'static str)>)> = CORE.iter().filter(|(_, _, r)| !*r || root).map(|(n, m, _)| (n.to_string(), *m, None)).collect();
        for &c in &self.controllers {
            for (f, m, r) in controller_files(c) {
                if !*r || root {
                    out.push((self.shown(c, f), *m, Some((c, *f))));
                }
            }
        }
        out
    }

    pub fn group_of(&self, tid: i32) -> u64 {
        self.tasks.get(&tid).copied().unwrap_or(ROOT)
    }
}

#[derive(Debug, Default)]
pub struct Hierarchies {
    pub all: Vec<Hierarchy>,
}

static ALL: OnceLock<Mutex<Hierarchies>> = OnceLock::new();

pub fn hierarchies() -> std::sync::MutexGuard<'static, Hierarchies> {
    ALL.get_or_init(|| Mutex::new(Hierarchies::default())).lock().unwrap_or_else(|e| e.into_inner())
}

fn said() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| eprintln!("[gex] cgroup v1: the controllers' settings are kept and not applied: this kernel schedules nothing and throttles no I/O"));
}

/// The CPUs there are, as a list (`0-3`).
fn all_cpus() -> String {
    let n = crate::cpus::count().max(1);
    if n == 1 { "0".into() } else { format!("0-{}", n - 1) }
}

/// A CPU or memory-node list (`0-2,5`): its members, or `None` for one
/// that does not read as one, or names one past `max`.
fn parse_list(s: &str, max: u32) -> Option<Vec<u32>> {
    let s = s.trim();
    let mut out = Vec::new();
    if s.is_empty() {
        return Some(out);
    }
    for part in s.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim().parse::<u32>().ok()?, b.trim().parse::<u32>().ok()?),
            None => {
                let v = part.trim().parse::<u32>().ok()?;
                (v, v)
            }
        };
        if a > b || b >= max {
            return None;
        }
        out.extend(a..=b);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

fn show_list(v: &[u32]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let mut j = i;
        while j + 1 < v.len() && v[j + 1] == v[j] + 1 {
            j += 1;
        }
        out.push(if i == j { v[i].to_string() } else { format!("{}-{}", v[i], v[j]) });
        i = j + 1;
    }
    out.join(",")
}

/// A controller's setting's value when nothing was written to it.
fn default_of(h: &Hierarchy, id: u64, c: &str, f: &str) -> String {
    match (c, f) {
        // The root's are the machine's; a new group's are empty (copied
        // from its parent's with `cgroup.clone_children`).
        ("cpuset", "cpus") => {
            if id == ROOT { all_cpus() } else { String::new() }
        }
        ("cpuset", "mems") => {
            if id == ROOT { "0".into() } else { String::new() }
        }
        ("cpuset", "effective_cpus") => effective(h, id, "cpus"),
        ("cpuset", "effective_mems") => effective(h, id, "mems"),
        ("cpuset", "sched_load_balance") => "1".into(),
        ("cpuset", "sched_relax_domain_level") => "-1".into(),
        ("cpuset", "cpu_exclusive") => if id == ROOT { "1".into() } else { "0".into() },
        ("cpuset", "mem_exclusive") => if id == ROOT { "1".into() } else { "0".into() },
        ("cpu", "shares") => "1024".into(),
        ("cpu", "cfs_period_us") => "100000".into(),
        ("cpu", "cfs_quota_us") => "-1".into(),
        ("cpu", "uclamp.min") => "0.00".into(),
        ("cpu", "uclamp.max") => "max".into(),
        ("cpu", "stat") => "nr_periods 0\nnr_throttled 0\nthrottled_time 0\nnr_bursts 0\nburst_time 0".into(),
        ("cpu", "stat.local") => "throttled_time 0".into(),
        ("blkio", "prio.class") => "no-change".into(),
        ("blkio", f) if f.starts_with("throttle.io_") => "Total 0".into(),
        ("blkio", f) if f.starts_with("throttle.") => String::new(),
        _ => "0".into(),
    }
}

fn value(h: &Hierarchy, id: u64, c: &str, f: &'static str) -> String {
    h.groups.get(&id).and_then(|g| g.values.get(f).cloned()).unwrap_or_else(|| default_of(h, id, c, f))
}

/// A cpuset's effective CPUs or nodes in `cpuset_v2_mode` (which Android
/// asks for): its own, or its parent's where it has none.
fn effective(h: &Hierarchy, id: u64, what: &'static str) -> String {
    let mut at = Some(id);
    while let Some(i) = at {
        let v = value(h, i, "cpuset", what);
        if !v.is_empty() {
            return v;
        }
        at = h.groups.get(&i).and_then(|g| g.parent);
    }
    String::new()
}

/// `mount -t cgroup` with `options`: the hierarchy it is, made or found.
pub fn mount(options: &str) -> Result<u32, Errno> {
    let mut wanted: Vec<&'static str> = Vec::new();
    let (mut name, mut none, mut noprefix, mut all) = (None, false, false, false);
    let mut release_agent = String::new();
    for o in options.split(',').map(str::trim).filter(|o| !o.is_empty()) {
        match o {
            "none" => none = true,
            "all" => all = true,
            "noprefix" => noprefix = true,
            // (Kept by cpusets in this mode: an empty one takes its
            // parent's, `effective`.)
            "cpuset_v2_mode" | "xattr" | "clone_children" => {}
            _ if o.starts_with("name=") => name = Some(o[5..].to_string()),
            _ if o.starts_with("release_agent=") => release_agent = o[14..].to_string(),
            c => match CONTROLLERS.iter().find(|x| **x == c) {
                Some(x) => wanted.push(x),
                None => return Err(Errno::ENOENT),
            },
        }
    }
    if all || (wanted.is_empty() && !none) {
        if none {
            return Err(Errno::EINVAL);
        }
        wanted = CONTROLLERS.to_vec();
    }
    if none && !wanted.is_empty() {
        return Err(Errno::EINVAL);
    }
    // No controller and no name is nothing; noprefix only for cpuset alone.
    if wanted.is_empty() && name.is_none() {
        return Err(Errno::EINVAL);
    }
    if noprefix && wanted != ["cpuset"] {
        return Err(Errno::EINVAL);
    }
    wanted.sort_by_key(|c| CONTROLLERS.iter().position(|x| x == c));
    let mut hs = hierarchies();
    // The same set, or the same name: that hierarchy again.
    if let Some(h) = hs.all.iter().find(|h| (name.is_some() && h.name == name) || (!wanted.is_empty() && h.controllers == wanted && name.is_none())) {
        if h.controllers != wanted || h.name != name {
            return Err(Errno::EBUSY);
        }
        return Ok(h.id);
    }
    // A controller is bound to one hierarchy at a time.
    if hs.all.iter().any(|h| h.controllers.iter().any(|c| wanted.contains(c))) {
        return Err(Errno::EBUSY);
    }
    if !wanted.is_empty() {
        said();
    }
    let id = hs.all.iter().map(|h| h.id).max().unwrap_or(0) + 1;
    let mut groups = BTreeMap::new();
    groups.insert(
        ROOT,
        Group { parent: None, name: String::new(), children: BTreeMap::new(), mode: 0o555, owner: (0, 0), made_by: (0, 0), files: HashMap::new(), values: HashMap::new(), notify_on_release: false, clone_children: false },
    );
    hs.all.push(Hierarchy { id, controllers: wanted, name, noprefix, release_agent, groups, tasks: HashMap::new(), next: ROOT + 1 });
    Ok(id)
}

pub fn mkdir(hier: u32, parent: u64, name: &str, mode: u32, owner: (u32, u32)) -> Result<(), Errno> {
    if name.contains('\n') {
        return Err(Errno::EINVAL);
    }
    let mut hs = hierarchies();
    let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
    let p = h.groups.get(&parent).ok_or(Errno::ENOENT)?;
    if p.children.contains_key(name) || h.files_of(parent).iter().any(|(n, _, _)| n == name) {
        return Err(Errno::EEXIST);
    }
    // `cgroup.clone_children`: a new cpuset takes its parent's CPUs and
    // nodes.
    let mut values = HashMap::new();
    if p.clone_children && h.controllers.contains(&"cpuset") {
        values.insert("cpus", value(h, parent, "cpuset", "cpus"));
        values.insert("mems", value(h, parent, "cpuset", "mems"));
    }
    let id = h.next;
    h.next += 1;
    h.groups.insert(id, Group { parent: Some(parent), name: name.to_string(), children: BTreeMap::new(), mode: mode & 0o7777, owner, made_by: owner, files: HashMap::new(), values, notify_on_release: false, clone_children: false });
    h.groups.get_mut(&parent).unwrap().children.insert(name.to_string(), id);
    Ok(())
}

pub fn rmdir(hier: u32, id: u64) -> Result<(), Errno> {
    let mut hs = hierarchies();
    let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
    let g = h.groups.get(&id).ok_or(Errno::ENOENT)?;
    let Some(parent) = g.parent else { return Err(Errno::EBUSY) };
    if !g.children.is_empty() || h.tasks.values().any(|&t| t == id) {
        return Err(Errno::EBUSY);
    }
    let name = g.name.clone();
    h.groups.remove(&id);
    h.groups.get_mut(&parent).unwrap().children.remove(&name);
    Ok(())
}

/// The contents of file `name` of group `id`.
pub fn read(hier: u32, id: u64, name: &str) -> Result<Vec<u8>, Errno> {
    let hs = hierarchies();
    let h = hs.all.iter().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
    let g = h.groups.get(&id).ok_or(Errno::ENODEV)?;
    let line = |s: String| format!("{s}\n");
    let text = match name {
        "tasks" => {
            let mut v: Vec<i32> = h.tasks.iter().filter(|(_, &g)| g == id).map(|(&t, _)| t).collect();
            v.sort_unstable();
            v.iter().map(|t| format!("{t}\n")).collect()
        }
        "cgroup.procs" => {
            let procs = crate::cgroup::procs_of_threads(h.tasks.iter().filter(|(_, &g)| g == id).map(|(&t, _)| t));
            procs.iter().map(|p| format!("{p}\n")).collect()
        }
        "notify_on_release" => line((g.notify_on_release as u8).to_string()),
        "cgroup.clone_children" => line((g.clone_children as u8).to_string()),
        "release_agent" => line(h.release_agent.clone()),
        "cgroup.sane_behavior" => line("0".into()),
        _ => {
            let (_, _, ctl) = h.files_of(id).into_iter().find(|(n, _, _)| n == name).ok_or(Errno::ENOENT)?;
            let (c, f) = ctl.ok_or(Errno::EINVAL)?;
            line(value(h, id, c, f))
        }
    };
    Ok(text.into_bytes())
}

/// A write to file `name` of group `id`, by `who`.
pub fn write(hier: u32, id: u64, name: &str, buf: &[u8], who: Option<crate::cgroup::Writer>) -> Result<u64, Errno> {
    let n = buf.len() as u64;
    let s = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?.trim().to_string();
    let int = || -> Result<i64, Errno> { s.parse::<i64>().map_err(|_| Errno::EINVAL) };
    match name {
        "tasks" | "cgroup.procs" => {
            let v = int()?;
            if v < 0 {
                return Err(Errno::EINVAL);
            }
            let tid = if v == 0 { who.map(|w| w.pid).ok_or(Errno::ESRCH)? } else { v as i32 };
            let threads = crate::cgroup::threads_for_move(tid, name == "cgroup.procs").ok_or(Errno::ESRCH)?;
            let mut hs = hierarchies();
            let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
            if !h.groups.contains_key(&id) {
                return Err(Errno::ENODEV);
            }
            // A cpuset with no CPUs or nodes to run on, even its parent's
            // (`cpuset_can_attach`).
            if h.controllers.contains(&"cpuset") && (effective(h, id, "cpus").is_empty() || effective(h, id, "mems").is_empty()) {
                return Err(Errno::ENOSPC);
            }
            for t in threads {
                h.tasks.insert(t, id);
            }
            Ok(n)
        }
        "notify_on_release" | "cgroup.clone_children" => {
            // `kstrtoull`: any number, set by any but 0.
            let v = s.parse::<u64>().map_err(|_| Errno::EINVAL)? != 0;
            let mut hs = hierarchies();
            let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
            let g = h.groups.get_mut(&id).ok_or(Errno::ENODEV)?;
            if name == "notify_on_release" {
                g.notify_on_release = v;
            } else {
                g.clone_children = v;
            }
            Ok(n)
        }
        "release_agent" => {
            let mut hs = hierarchies();
            let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
            h.release_agent = s;
            Ok(n)
        }
        _ => {
            let mut hs = hierarchies();
            let h = hs.all.iter_mut().find(|h| h.id == hier).ok_or(Errno::ENODEV)?;
            let (_, mode, ctl) = h.files_of(id).into_iter().find(|(f, _, _)| f == name).ok_or(Errno::ENOENT)?;
            let (c, f) = ctl.ok_or(Errno::EINVAL)?;
            if mode & 0o222 == 0 {
                return Err(Errno::EACCES);
            }
            let stored = check(h, id, c, f, &s)?;
            if let Some(v) = stored {
                h.groups.get_mut(&id).ok_or(Errno::ENODEV)?.values.insert(f, v);
            }
            Ok(n)
        }
    }
}

/// What a write of `s` to a controller's file sets it to, or why not
/// (`None`: taken, nothing kept).
fn check(h: &Hierarchy, id: u64, c: &str, f: &'static str, s: &str) -> Result<Option<String>, Errno> {
    let num = || s.parse::<i64>().map_err(|_| Errno::EINVAL);
    match (c, f) {
        ("cpuset", "cpus" | "mems") => {
            // The root's are the machine's (`EACCES`); a group's within its
            // parent's.
            if id == ROOT {
                return Err(Errno::EACCES);
            }
            let max = if f == "cpus" { crate::cpus::count().max(1) as u32 } else { 1 };
            let v = parse_list(s, max).ok_or(Errno::EINVAL)?;
            let parent = h.groups.get(&id).and_then(|g| g.parent).unwrap_or(ROOT);
            let within = parse_list(&effective(h, parent, f), max).unwrap_or_default();
            if v.iter().any(|x| !within.contains(x)) {
                return Err(Errno::EINVAL);
            }
            Ok(Some(show_list(&v)))
        }
        ("cpuset", "cpu_exclusive" | "mem_exclusive" | "mem_hardwall" | "sched_load_balance" | "memory_migrate" | "memory_spread_page" | "memory_spread_slab" | "memory_pressure_enabled") => match num()? {
            0 | 1 => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        ("cpuset", "sched_relax_domain_level") => match num()? {
            -1..=5 => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        // `cpu_shares_write_u64`: within 2 and 262144.
        ("cpu", "shares") => Ok(Some(num()?.clamp(2, 262_144).to_string())),
        ("cpu", "idle") => match num()? {
            0 | 1 => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        ("cpu", "cfs_period_us") => match num()? {
            1000..=1_000_000 => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        ("cpu", "cfs_quota_us") => match num()? {
            -1 => Ok(Some("-1".into())),
            1000.. => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        ("cpu", "cfs_burst_us") => match num()? {
            0.. => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        // `capacity_from_percent`: "max", or a percentage of up to two
        // places, no more than 100.
        ("cpu", "uclamp.min" | "uclamp.max") => {
            if s == "max" {
                return Ok(Some("max".into()));
            }
            let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
            let w = whole.parse::<u64>().map_err(|_| Errno::EINVAL)?;
            if frac.len() > 2 || !frac.chars().all(|c| c.is_ascii_digit()) {
                return Err(Errno::EINVAL);
            }
            let fr = format!("{frac:0<2}").parse::<u64>().unwrap_or(0);
            if w > 100 || (w == 100 && fr > 0) {
                return Err(Errno::ERANGE);
            }
            Ok(Some(format!("{w}.{fr:02}")))
        }
        ("cpu", "uclamp.latency_sensitive") => match num()? {
            0 | 1 => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        ("blkio", "reset_stats") => Ok(None),
        ("blkio", "prio.class") => match s {
            "no-change" | "promote-to-rt" | "restrict-to-be" | "idle" | "none-to-rt" => Ok(Some(s.to_string())),
            _ => Err(Errno::EINVAL),
        },
        // A device's limit: "MAJ:MIN value", for a disk this kernel has.
        ("blkio", _) => {
            let (dev, _) = s.split_once(' ').ok_or(Errno::EINVAL)?;
            let (maj, min) = dev.split_once(':').ok_or(Errno::EINVAL)?;
            let (maj, min) = (maj.parse::<u32>().map_err(|_| Errno::EINVAL)?, min.parse::<u32>().map_err(|_| Errno::EINVAL)?);
            if crate::block::disk(crate::vfs::devices::makedev(maj, min)).is_none() {
                return Err(Errno::ENODEV);
            }
            Ok(Some(s.to_string()))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The lines `/proc/<pid>/cgroup` has for the v1 hierarchies of thread
/// `tid`: the most recently made first.
pub fn proc_lines(tid: i32) -> String {
    let hs = hierarchies();
    let mut out = String::new();
    for h in hs.all.iter().rev() {
        let mut names: Vec<String> = h.controllers.iter().map(|c| c.to_string()).collect();
        if let Some(n) = &h.name {
            names.push(format!("name={n}"));
        }
        out.push_str(&format!("{}:{}:{}\n", h.id, names.join(","), h.path_of(h.group_of(tid))));
    }
    out
}

/// `/proc/cgroups`.
pub fn proc_cgroups() -> Vec<u8> {
    let hs = hierarchies();
    let v2 = crate::cgroup::tree().groups.len();
    let mut out = String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
    for c in CONTROLLERS {
        let (hier, n) = hs.all.iter().find(|h| h.controllers.contains(c)).map_or((0, v2), |h| (h.id, h.groups.len()));
        out.push_str(&format!("{c}\t{hier}\t{n}\t1\n"));
    }
    out.into_bytes()
}

/// Membership as threads come and go: a new process's threads in its
/// parent's groups, a new thread in its process's, an ended one out.
pub fn fork(ppid: i32, pid: i32) {
    let mut hs = hierarchies();
    for h in hs.all.iter_mut() {
        let g = h.group_of(ppid);
        h.tasks.insert(pid, g);
    }
}

pub fn thread_start(pid: i32, tid: i32) {
    fork(pid, tid);
}

pub fn thread_end(tid: i32) {
    let mut hs = hierarchies();
    for h in hs.all.iter_mut() {
        h.tasks.remove(&tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The controllers' files as Android uses them, held to 6.18's
    /// source (the oracle binds these controllers to version 2 and cannot
    /// mount them here).
    #[test]
    fn the_controllers_as_android_uses_them() {
        let s = |v: Result<Vec<u8>, Errno>| String::from_utf8(v.unwrap()).unwrap();
        // cpuset, as Android mounts it: no prefix.
        let cs = mount("cpuset,noprefix,cpuset_v2_mode").unwrap();
        assert_eq!(mount("cpuset,noprefix"), Ok(cs), "the same set is the same hierarchy");
        assert_eq!(mount("cpu,noprefix"), Err(Errno::EINVAL), "noprefix is cpuset's alone");
        assert_eq!(mount("cpuset,cpu"), Err(Errno::EBUSY), "cpuset is bound already");
        assert_eq!(mount("memory"), Err(Errno::ENOENT));
        let n = crate::cpus::count().max(1);
        assert_eq!(s(read(cs, ROOT, "cpus")), format!("{}\n", all_cpus()));
        assert_eq!(write(cs, ROOT, "cpus", b"0", None), Err(Errno::EACCES));
        mkdir(cs, ROOT, "foreground", 0o755, (0, 0)).unwrap();
        let fg = hierarchies().all.iter().find(|h| h.id == cs).unwrap().at("foreground").unwrap();
        // A new group's own are empty; in v2 mode its effective are its parent's.
        assert_eq!(s(read(cs, fg, "cpus")), "\n");
        assert_eq!(s(read(cs, fg, "effective_cpus")), format!("{}\n", all_cpus()));
        assert_eq!(write(cs, fg, "cpus", format!("{n}").as_bytes(), None), Err(Errno::EINVAL), "past the CPUs there are");
        assert_eq!(write(cs, fg, "cpus", b"0\n", None), Ok(2));
        assert_eq!(s(read(cs, fg, "cpus")), "0\n");
        assert_eq!(write(cs, fg, "mems", b"0", None), Ok(1));
        assert_eq!(write(cs, fg, "mems", b"1", None), Err(Errno::EINVAL));
        assert_eq!(write(cs, fg, "sched_load_balance", b"2", None), Err(Errno::EINVAL));
        assert!(read(cs, ROOT, "memory_pressure_enabled").is_ok());
        assert_eq!(read(cs, fg, "memory_pressure_enabled"), Err(Errno::ENOENT), "the root's alone");
        // cpu: its legacy files, prefixed.
        let cpu = mount("cpu").unwrap();
        mkdir(cpu, ROOT, "nnapi-hal", 0o755, (0, 0)).unwrap();
        let nn = hierarchies().all.iter().find(|h| h.id == cpu).unwrap().at("nnapi-hal").unwrap();
        assert_eq!(write(cpu, nn, "cpu.uclamp.min", b"1", None), Ok(1));
        assert_eq!(s(read(cpu, nn, "cpu.uclamp.min")), "1.00\n");
        assert_eq!(s(read(cpu, nn, "cpu.uclamp.max")), "max\n");
        assert_eq!(write(cpu, nn, "cpu.uclamp.min", b"100.5", None), Err(Errno::ERANGE));
        assert_eq!(write(cpu, nn, "cpu.uclamp.min", b"1.234", None), Err(Errno::EINVAL));
        assert_eq!(write(cpu, nn, "cpu.uclamp.latency_sensitive", b"1", None), Ok(1));
        assert_eq!(write(cpu, nn, "cpu.shares", b"1", None), Ok(1));
        assert_eq!(s(read(cpu, nn, "cpu.shares")), "2\n", "at least 2");
        assert_eq!(read(cpu, nn, "cpu.rt_runtime_us"), Err(Errno::ENOENT), "no RT_GROUP_SCHED");
        // blkio: I/O priority and throttling, no BFQ.
        let bl = mount("blkio").unwrap();
        assert_eq!(write(bl, ROOT, "blkio.prio.class", b"restrict-to-be", None), Ok(14));
        assert_eq!(write(bl, ROOT, "blkio.prio.class", b"fast", None), Err(Errno::EINVAL));
        assert_eq!(write(bl, ROOT, "blkio.weight", b"1000", None), Err(Errno::ENOENT));
        assert_eq!(write(bl, ROOT, "blkio.bfq.weight", b"10", None), Err(Errno::ENOENT));
        let pc = String::from_utf8(proc_cgroups()).unwrap();
        assert!(pc.starts_with("#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t"), "{pc}");
    }

    #[test]
    fn lists_as_cpusets_read_them() {
        assert_eq!(parse_list("0-2,5", 8), Some(vec![0, 1, 2, 5]));
        assert_eq!(parse_list("", 8), Some(vec![]));
        assert_eq!(parse_list("3-1", 8), None);
        assert_eq!(parse_list("9", 8), None);
        assert_eq!(show_list(&[0, 1, 2, 5, 7, 8]), "0-2,5,7-8");
    }
}
