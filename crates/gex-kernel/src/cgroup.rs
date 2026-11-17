//! cgroup v2 (`kernel/cgroup/cgroup.c` at android17-6.18): the one
//! hierarchy of control groups, which processes are in which, and what
//! each group's core files say and take. Android mounts it at
//! `/sys/fs/cgroup`; libprocessgroup puts each app's processes in a group
//! of their own, kills them by it (`cgroup.kill`) and waits for it to
//! empty (`cgroup.events`); netd attaches its BPF programs to its root.
//!
//! No controller is bound to it (GKI's Android binds cpu, cpuset and blkio
//! to version 1 hierarchies and the memory controller here only when it is
//! there to activate, which it is not): `cgroup.controllers` is empty and a
//! controller cannot be enabled. What is here is the core: groups made and
//! removed, membership by process (all of a process's threads in its
//! group, as a domain group has them), the limits on depth and
//! descendants, `cgroup.events` and the wakeup at each change, `cgroup.kill`,
//! `cpu.stat`'s time, and pressure-stall information, which here is always
//! none (`crate::vfs::procfs`). Freezing (`cgroup.freeze` 1) and threaded
//! groups are refused loudly. One hierarchy for every process of this host
//! (as the process table is); a page's processes, each a kernel of its
//! own, do not share it.

use crate::errno::Errno;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// `CGROUP2_SUPER_MAGIC`.
pub const MAGIC: u64 = 0x6367_7270;

/// The root's id.
pub const ROOT: u64 = 1;

/// A file of a group: name, mode, and whether only a group that is not
/// the root has it (`CFTYPE_NOT_ON_ROOT`). In the order `cgroup_base_files`
/// and the pressure files are made.
pub const FILES: &[(&str, u32, bool)] = &[
    ("cgroup.type", 0o644, true),
    ("cgroup.procs", 0o644, false),
    ("cgroup.threads", 0o644, false),
    ("cgroup.controllers", 0o444, false),
    ("cgroup.subtree_control", 0o644, false),
    ("cgroup.events", 0o444, true),
    ("cgroup.max.descendants", 0o644, false),
    ("cgroup.max.depth", 0o644, false),
    ("cgroup.stat", 0o444, false),
    ("cgroup.stat.local", 0o444, true),
    ("cgroup.freeze", 0o644, true),
    ("cgroup.kill", 0o200, true),
    ("cpu.stat", 0o444, false),
    ("cpu.stat.local", 0o444, false),
    ("io.pressure", 0o644, false),
    ("memory.pressure", 0o644, false),
    ("cpu.pressure", 0o644, false),
    // GKI is built with `IRQ_TIME_ACCOUNTING`.
    ("irq.pressure", 0o644, false),
    ("cgroup.pressure", 0o644, false),
];

/// Whether `name` is a file a group has, the root or another.
pub fn file_mode(name: &str, root: bool) -> Option<u32> {
    FILES.iter().find(|(n, _, not_root)| *n == name && !(root && *not_root)).map(|(_, m, _)| *m)
}

/// "max", as the limits keep it (`INT_MAX`).
const MAX: i32 = i32::MAX;

#[derive(Debug)]
pub struct Group {
    pub id: u64,
    pub parent: Option<u64>,
    pub name: String,
    pub children: BTreeMap<String, u64>,
    pub max_depth: i32,
    pub max_descendants: i32,
    /// `cgroup.pressure`: whether pressure is accounted here.
    pub pressure: bool,
    /// The directory's mode and owner, and each file's that was changed.
    pub mode: u32,
    pub owner: (u32, u32),
    /// Who made it: its files are theirs until changed.
    pub made_by: (u32, u32),
    pub files: HashMap<String, (u32, u32, u32)>,
    /// Counted at each change of `cgroup.events` (`cgroup_file_notify`).
    pub events: u64,
    /// The processor time of processes that ended in it (nanoseconds).
    pub gone_ns: u64,
    /// BPF programs attached here, by attach type, with the flags they
    /// were attached with and the count of changes (`revisions`, from 1).
    pub bpf: BTreeMap<u32, Vec<Attached>>,
    pub bpf_flags: BTreeMap<u32, u32>,
    pub bpf_revision: BTreeMap<u32, u64>,
}

/// A BPF program attached to a group, and the flags it was attached with.
#[derive(Debug, Clone)]
pub struct Attached {
    pub prog: Arc<crate::bpfprog::Prog>,
    pub flags: u32,
}

#[derive(Debug)]
pub struct Tree {
    pub groups: BTreeMap<u64, Group>,
    /// Each process's group.
    members: HashMap<i32, u64>,
    /// Each thread (but a process's first) and its process.
    threads: HashMap<i32, i32>,
    next: u64,
}

impl Tree {
    fn new() -> Tree {
        let mut groups = BTreeMap::new();
        groups.insert(ROOT, Group::new(ROOT, None, String::new(), 0o755, (0, 0)));
        Tree { groups, members: HashMap::new(), threads: HashMap::new(), next: ROOT + 1 }
    }

    /// The group at `path` (names from the root, "" for it).
    pub fn at(&self, path: &str) -> Option<u64> {
        let mut id = ROOT;
        for name in path.split('/').filter(|s| !s.is_empty()) {
            id = *self.groups.get(&id)?.children.get(name)?;
        }
        Some(id)
    }

    /// A group's path from the root, "/" for it.
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

    /// Whether `id` is `anc` or under it.
    pub fn under(&self, id: u64, anc: u64) -> bool {
        let mut at = Some(id);
        while let Some(i) = at {
            if i == anc {
                return true;
            }
            at = self.groups.get(&i).and_then(|g| g.parent);
        }
        false
    }

    fn descendants(&self, id: u64) -> usize {
        self.groups.get(&id).map_or(0, |g| g.children.values().map(|c| 1 + self.descendants(*c)).sum())
    }

    /// Whether a process is in `id` or under it (`cgroup_is_populated`).
    pub fn populated(&self, id: u64) -> bool {
        self.members.values().any(|&g| self.under(g, id))
    }

    /// The processes in `id` itself.
    pub fn procs(&self, id: u64) -> Vec<i32> {
        let mut v: Vec<i32> = self.members.iter().filter(|(_, &g)| g == id).map(|(&p, _)| p).collect();
        v.sort_unstable();
        v
    }

    /// The processes in `id` or under it.
    pub fn procs_under(&self, id: u64) -> Vec<i32> {
        let mut v: Vec<i32> = self.members.iter().filter(|(_, &g)| self.under(g, id)).map(|(&p, _)| p).collect();
        v.sort_unstable();
        v
    }

    /// Their threads: each process's first, then its others.
    pub fn threads(&self, id: u64) -> Vec<i32> {
        let mut out = Vec::new();
        for p in self.procs(id) {
            out.push(p);
            let mut more: Vec<i32> = self.threads.iter().filter(|(_, &q)| q == p).map(|(&t, _)| t).collect();
            more.sort_unstable();
            out.extend(more);
        }
        out
    }

    pub fn group_of(&self, pid: i32) -> u64 {
        let pid = self.threads.get(&pid).copied().unwrap_or(pid);
        self.members.get(&pid).copied().unwrap_or(ROOT)
    }

    /// Run `change`, and tell each group whose populated state it changed
    /// (`cgroup_update_populated`).
    fn changing(&mut self, change: impl FnOnce(&mut Tree)) {
        let before: Vec<(u64, bool)> = self.groups.keys().map(|&g| (g, self.populated(g))).collect();
        change(self);
        let mut told = false;
        for (g, was) in before {
            if self.groups.contains_key(&g) && self.populated(g) != was {
                if let Some(gr) = self.groups.get_mut(&g) {
                    gr.events += 1;
                    told = true;
                }
            }
        }
        if told {
            events_queue().notify();
        }
    }
}

impl Group {
    fn new(id: u64, parent: Option<u64>, name: String, mode: u32, owner: (u32, u32)) -> Group {
        Group {
            id,
            parent,
            name,
            children: BTreeMap::new(),
            max_depth: MAX,
            max_descendants: MAX,
            pressure: true,
            mode,
            owner,
            made_by: owner,
            files: HashMap::new(),
            events: 0,
            gone_ns: 0,
            bpf: BTreeMap::new(),
            bpf_flags: BTreeMap::new(),
            bpf_revision: BTreeMap::new(),
        }
    }
}

static TREE: OnceLock<Mutex<Tree>> = OnceLock::new();

/// The hierarchy, locked.
pub fn tree() -> std::sync::MutexGuard<'static, Tree> {
    TREE.get_or_init(|| Mutex::new(Tree::new())).lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a change of a group's `cgroup.events` is announced.
pub fn events_queue() -> &'static crate::wait::Queue {
    static Q: OnceLock<crate::wait::Queue> = OnceLock::new();
    Q.get_or_init(crate::wait::Queue::new)
}

/// The process table, for `cgroup.kill` and the processor time of the
/// processes in a group: the first kernel's ([`set_procs`]).
static PROCS: OnceLock<Weak<crate::proc::ProcTable>> = OnceLock::new();

pub fn set_procs(procs: &Arc<crate::proc::ProcTable>) {
    if PROCS.set(Arc::downgrade(procs)).is_ok() {
        // The first process, which no fork made: in the root.
        tree().members.entry(crate::proc::INIT_PID).or_insert(ROOT);
    }
}

// -- membership, as the process table changes ------------------------------

/// A process made by a fork: in its parent's group, in each hierarchy.
pub fn fork(ppid: i32, pid: i32) {
    {
        let mut t = tree();
        let g = t.group_of(ppid);
        t.changing(|t| {
            t.members.insert(pid, g);
        });
    }
    crate::cgroup1::fork(ppid, pid);
}

/// A thread made in a process.
pub fn thread_start(pid: i32, tid: i32) {
    tree().threads.insert(tid, pid);
    crate::cgroup1::thread_start(pid, tid);
}

pub fn thread_end(tid: i32) {
    tree().threads.remove(&tid);
    crate::cgroup1::thread_end(tid);
}

/// The processes the threads `tids` are of, each once, in order.
pub fn procs_of_threads(tids: impl Iterator<Item = i32>) -> Vec<i32> {
    let t = tree();
    let mut v: Vec<i32> = tids.map(|x| t.threads.get(&x).copied().unwrap_or(x)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// The threads a write of `tid` to a v1 group's `tasks` (one) or
/// `cgroup.procs` (its process's every one) moves; `None` for no such
/// task.
pub fn threads_for_move(tid: i32, whole: bool) -> Option<Vec<i32>> {
    let procs = PROCS.get().and_then(Weak::upgrade)?;
    let pid = procs.task_owner(tid).filter(|&p| procs.alive(p))?;
    if !whole {
        return Some(vec![tid]);
    }
    let t = tree();
    let mut v = vec![pid];
    v.extend(t.threads.iter().filter(|(_, &p)| p == pid).map(|(&x, _)| x));
    Some(v)
}

/// A process has ended (`cgroup_exit`): out of its group, its time kept
/// there.
pub fn exit(pid: i32, cpu_ns: u64) {
    let tids: Vec<i32> = {
        let t = tree();
        std::iter::once(pid).chain(t.threads.iter().filter(|(_, &p)| p == pid).map(|(&x, _)| x)).collect()
    };
    for x in tids {
        crate::cgroup1::thread_end(x);
    }
    let mut t = tree();
    t.changing(|t| {
        if let Some(g) = t.members.remove(&pid) {
            if let Some(gr) = t.groups.get_mut(&g) {
                gr.gone_ns += cpu_ns;
            }
        }
        t.threads.retain(|_, p| *p != pid);
    });
}

/// `/proc/<pid>/cgroup`: a line for each version 1 hierarchy, then the
/// version 2 one's.
pub fn proc_file(pid: i32) -> Vec<u8> {
    let v1 = crate::cgroup1::proc_lines(pid);
    let t = tree();
    format!("{v1}0::{}\n", t.path_of(t.group_of(pid))).into_bytes()
}

// -- groups made and removed ------------------------------------------------

/// `cgroup_mkdir` of `name` in group `parent`, owned by `owner` (the
/// maker's, as `cgroup_kn_set_ugid` gives it unless it is root's).
pub fn mkdir(parent: u64, name: &str, mode: u32, owner: (u32, u32)) -> Result<u64, Errno> {
    if name.contains('\n') {
        return Err(Errno::EINVAL);
    }
    let mut t = tree();
    let root = parent == ROOT;
    let p = t.groups.get(&parent).ok_or(Errno::ENOENT)?;
    if p.children.contains_key(name) || file_mode(name, root).is_some() {
        return Err(Errno::EEXIST);
    }
    // `cgroup_check_hierarchy_limits`: each ancestor's depth and number of
    // descendants.
    let mut at = Some(parent);
    let mut below = 1u32;
    while let Some(a) = at {
        let g = &t.groups[&a];
        if below > g.max_depth as u32 || t.descendants(a) >= g.max_descendants as usize {
            return Err(Errno::EAGAIN);
        }
        below += 1;
        at = g.parent;
    }
    let id = t.next;
    t.next += 1;
    t.groups.insert(id, Group::new(id, Some(parent), name.to_string(), mode & 0o7777, owner));
    t.groups.get_mut(&parent).unwrap().children.insert(name.to_string(), id);
    Ok(id)
}

/// `cgroup_rmdir`: not while a process is in it or it has groups under it.
pub fn rmdir(id: u64) -> Result<(), Errno> {
    let mut t = tree();
    let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
    let Some(parent) = g.parent else { return Err(Errno::EBUSY) };
    if !g.children.is_empty() || t.populated(id) {
        return Err(Errno::EBUSY);
    }
    let name = g.name.clone();
    t.groups.remove(&id);
    t.groups.get_mut(&parent).unwrap().children.remove(&name);
    Ok(())
}

// -- what the files say -----------------------------------------------------

fn limit(v: i32) -> String {
    if v == MAX { "max\n".into() } else { format!("{v}\n") }
}

/// A group's processes' processor time, those still running and those
/// that ended in it, in nanoseconds: what `cpu.stat` counts.
fn cpu_ns(t: &Tree, id: u64) -> u64 {
    let gone: u64 = t.groups.iter().filter(|(&g, _)| t.under(g, id)).map(|(_, g)| g.gone_ns).sum();
    let live = PROCS.get().and_then(Weak::upgrade).map_or(0, |procs| t.procs_under(id).iter().map(|&p| procs.cpu_ns_of(p)).sum());
    gone + live
}

/// The contents of `name` in group `id`.
pub fn read(id: u64, name: &str) -> Result<Vec<u8>, Errno> {
    let t = tree();
    let g = t.groups.get(&id).ok_or(Errno::ENODEV)?;
    let text = match name {
        "cgroup.type" => "domain\n".to_string(),
        "cgroup.procs" => t.procs(id).iter().map(|p| format!("{p}\n")).collect(),
        "cgroup.threads" => t.threads(id).iter().map(|p| format!("{p}\n")).collect(),
        // No controller: nothing, not even the line's end.
        "cgroup.controllers" | "cgroup.subtree_control" => String::new(),
        "cgroup.events" => format!("populated {}\nfrozen 0\n", t.populated(id) as u8),
        "cgroup.max.descendants" => limit(g.max_descendants),
        "cgroup.max.depth" => limit(g.max_depth),
        "cgroup.stat" => format!("nr_descendants {}\nnr_dying_descendants 0\n", t.descendants(id)),
        "cgroup.stat.local" => "frozen_usec 0\n".to_string(),
        "cgroup.freeze" => "0\n".to_string(),
        "cpu.stat" => {
            // All of it counted as the user's: this kernel does not part
            // a guest thread's time into user and system.
            let us = cpu_ns(&t, id) / 1000;
            format!("usage_usec {us}\nuser_usec {us}\nsystem_usec 0\nnice_usec 0\n")
        }
        // Only with the cpu controller.
        "cpu.stat.local" => String::new(),
        "cgroup.pressure" => format!("{}\n", g.pressure as u8),
        _ => return Err(Errno::EINVAL),
    };
    Ok(text.into_bytes())
}

/// The value a write gives (`kstrtoint` of the text stripped of space).
fn int(buf: &[u8]) -> Result<i64, Errno> {
    let s = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = if let Some(h) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i64::from_str_radix(h, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<i64>()
    }
    .map_err(|e| if matches!(e.kind(), std::num::IntErrorKind::PosOverflow) { Errno::ERANGE } else { Errno::EINVAL })?;
    if digits.is_empty() {
        return Err(Errno::EINVAL);
    }
    let v = if neg { -v } else { v };
    if v > i32::MAX as i64 || v < i32::MIN as i64 {
        return Err(Errno::ERANGE);
    }
    Ok(v)
}

/// Who writes: the process, and its user, as the system call that writes
/// says ([`crate::unix::Sender`]).
#[derive(Debug, Clone, Copy)]
pub struct Writer {
    pub pid: i32,
    pub uid: u32,
}

/// A write of `buf` to `name` in group `id`, whole (a group's files take
/// one write at a time from their start). The number of bytes taken.
pub fn write(id: u64, name: &str, buf: &[u8], who: Option<Writer>) -> Result<u64, Errno> {
    let n = buf.len() as u64;
    match name {
        "cgroup.procs" | "cgroup.threads" => {
            let pid = int(buf)?;
            if pid < 0 {
                return Err(Errno::EINVAL);
            }
            let pid = if pid == 0 { who.map(|w| w.pid).ok_or(Errno::ESRCH)? } else { pid as i32 };
            let procs = PROCS.get().and_then(Weak::upgrade).ok_or(Errno::ESRCH)?;
            let owner = procs.task_owner(pid).filter(|&p| procs.alive(p)).ok_or(Errno::ESRCH)?;
            let mut t = tree();
            if !t.groups.contains_key(&id) {
                return Err(Errno::ENODEV);
            }
            if name == "cgroup.threads" {
                // A thread alone moves only within its domain: every
                // group here is a domain of its own.
                return if t.group_of(pid) == id { Ok(n) } else { Err(Errno::EOPNOTSUPP) };
            }
            t.changing(|t| {
                t.members.insert(owner, id);
            });
            Ok(n)
        }
        "cgroup.subtree_control" => {
            // Each word a controller to enable or disable, and there is none.
            let s = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
            if s.split_whitespace().next().is_some() {
                return Err(Errno::EINVAL);
            }
            Ok(n)
        }
        "cgroup.type" => {
            if std::str::from_utf8(buf).map(str::trim) != Ok("threaded") {
                return Err(Errno::EINVAL);
            }
            crate::bpf::say_once("a threaded cgroup (cgroup.type)");
            Err(Errno::EOPNOTSUPP)
        }
        "cgroup.max.depth" | "cgroup.max.descendants" => {
            let s = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?.trim();
            let v = if s == "max" { MAX as i64 } else { int(buf)? };
            if v < 0 {
                return Err(Errno::ERANGE);
            }
            let mut t = tree();
            let g = t.groups.get_mut(&id).ok_or(Errno::ENODEV)?;
            if name == "cgroup.max.depth" {
                g.max_depth = v as i32;
            } else {
                g.max_descendants = v as i32;
            }
            Ok(n)
        }
        "cgroup.freeze" => {
            let v = int(buf)?;
            if !(0..=1).contains(&v) {
                return Err(Errno::ERANGE);
            }
            if v == 1 {
                crate::bpf::say_once("freezing a cgroup (cgroup.freeze)");
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(n)
        }
        "cgroup.kill" => {
            if int(buf)? != 1 {
                return Err(Errno::ERANGE);
            }
            // Each sent as `send_sig` sends it: from the writer.
            let victims = tree().procs_under(id);
            if let Some(procs) = PROCS.get().and_then(Weak::upgrade) {
                for p in victims {
                    let _ = procs.kill(who.map_or(0, |w| w.pid), p, 9);
                }
            }
            Ok(n)
        }
        "cgroup.pressure" => {
            let s = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?.trim();
            let on = match s {
                "1" | "y" | "Y" | "on" => true,
                "0" | "n" | "N" | "off" => false,
                _ => return Err(Errno::EINVAL),
            };
            let mut t = tree();
            t.groups.get_mut(&id).ok_or(Errno::ENODEV)?.pressure = on;
            Ok(n)
        }
        _ => Err(Errno::EINVAL),
    }
}

// -- BPF programs attached (`kernel/bpf/cgroup.c`) --------------------------

pub mod bpf_flag {
    pub const ALLOW_OVERRIDE: u32 = 1;
    pub const ALLOW_MULTI: u32 = 2;
    pub const REPLACE: u32 = 4;
    /// `BPF_F_BEFORE`, `AFTER`, `ID`, `LINK`, `PREORDER`: placing among
    /// the others by a relative, which nothing here does yet.
    pub const PLACED: u32 = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 13) | (1 << 6);
}

/// `BPF_CGROUP_MAX_PROGS`.
const MAX_PROGS: usize = 64;

/// `__cgroup_bpf_attach`.
pub fn bpf_attach(id: u64, ty: u32, prog: Arc<crate::bpfprog::Prog>, replace: Option<Arc<crate::bpfprog::Prog>>, flags: u32, revision: u64) -> Result<(), Errno> {
    use bpf_flag::*;
    let saved = flags & (ALLOW_OVERRIDE | ALLOW_MULTI);
    if (flags & ALLOW_OVERRIDE != 0 && flags & ALLOW_MULTI != 0) || (flags & REPLACE != 0 && flags & ALLOW_MULTI == 0) {
        return Err(Errno::EINVAL);
    }
    if replace.is_some() != (flags & REPLACE != 0) {
        return Err(Errno::EINVAL);
    }
    let mut t = tree();
    let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
    if revision != 0 && revision != g.bpf_revision.get(&ty).copied().unwrap_or(1) {
        return Err(Errno::ESTALE);
    }
    // `hierarchy_allows_attach`: the nearest ancestor with a program lets
    // its descendants have their own only when it said so.
    let mut at = g.parent;
    while let Some(p) = at {
        let pg = &t.groups[&p];
        let pf = pg.bpf_flags.get(&ty).copied().unwrap_or(0);
        if pf & ALLOW_MULTI != 0 {
            break;
        }
        if pg.bpf.get(&ty).is_some_and(|v| !v.is_empty()) {
            if pf & ALLOW_OVERRIDE == 0 {
                return Err(Errno::EPERM);
            }
            break;
        }
        at = pg.parent;
    }
    let g = t.groups.get_mut(&id).unwrap();
    let list = g.bpf.entry(ty).or_default();
    if !list.is_empty() && g.bpf_flags.get(&ty).copied().unwrap_or(0) != saved {
        return Err(Errno::EPERM);
    }
    if list.len() >= MAX_PROGS {
        return Err(Errno::E2BIG);
    }
    // `find_attach_entry`: the one there for a single program; for several,
    // not the same program twice, and the one being replaced.
    let slot = if flags & ALLOW_MULTI == 0 {
        (!list.is_empty()).then_some(0)
    } else {
        if list.iter().any(|a| Arc::ptr_eq(&a.prog, &prog) && !replace.as_ref().is_some_and(|r| Arc::ptr_eq(r, &prog))) {
            return Err(Errno::EINVAL);
        }
        match &replace {
            Some(r) => Some(list.iter().position(|a| Arc::ptr_eq(&a.prog, r)).ok_or(Errno::ENOENT)?),
            None => None,
        }
    };
    match slot {
        Some(i) => list[i] = Attached { prog, flags },
        None => list.push(Attached { prog, flags }),
    }
    g.bpf_flags.insert(ty, saved);
    *g.bpf_revision.entry(ty).or_insert(1) += 1;
    Ok(())
}

/// `__cgroup_bpf_detach`.
pub fn bpf_detach(id: u64, ty: u32, prog: Option<Arc<crate::bpfprog::Prog>>, revision: u64) -> Result<(), Errno> {
    let mut t = tree();
    let g = t.groups.get_mut(&id).ok_or(Errno::ENOENT)?;
    if revision != 0 && revision != g.bpf_revision.get(&ty).copied().unwrap_or(1) {
        return Err(Errno::ESTALE);
    }
    let multi = g.bpf_flags.get(&ty).copied().unwrap_or(0) & bpf_flag::ALLOW_MULTI != 0;
    let list = g.bpf.entry(ty).or_default();
    let at = if !multi {
        if list.is_empty() {
            return Err(Errno::ENOENT);
        }
        0
    } else {
        let p = prog.ok_or(Errno::EINVAL)?;
        list.iter().position(|a| Arc::ptr_eq(&a.prog, &p)).ok_or(Errno::ENOENT)?
    };
    list.remove(at);
    if list.is_empty() {
        g.bpf_flags.remove(&ty);
    }
    *g.bpf_revision.entry(ty).or_insert(1) += 1;
    Ok(())
}

/// The programs that run for group `id` at `ty`, in the order they run
/// (`compute_effective_progs`): its own, then each ancestor's while it and
/// those below it allow several.
pub fn bpf_effective(t: &Tree, id: u64, ty: u32) -> Vec<Arc<crate::bpfprog::Prog>> {
    let mut out = Vec::new();
    let mut at = Some(id);
    while let Some(i) = at {
        let g = &t.groups[&i];
        if out.is_empty() || g.bpf_flags.get(&ty).copied().unwrap_or(0) & bpf_flag::ALLOW_MULTI != 0 {
            out.extend(g.bpf.get(&ty).into_iter().flatten().map(|a| Arc::clone(&a.prog)));
        }
        at = g.parent;
    }
    out
}

/// `__cgroup_bpf_query`'s answer: the flags, the programs (attached, or
/// those that run), and the revision.
pub fn bpf_query(id: u64, ty: u32, effective: bool) -> Result<(u32, Vec<Arc<crate::bpfprog::Prog>>, u64), Errno> {
    let t = tree();
    let g = t.groups.get(&id).ok_or(Errno::ENOENT)?;
    if effective {
        return Ok((0, bpf_effective(&t, id, ty), 0));
    }
    let progs = g.bpf.get(&ty).into_iter().flatten().map(|a| Arc::clone(&a.prog)).collect();
    Ok((g.bpf_flags.get(&ty).copied().unwrap_or(0), progs, g.bpf_revision.get(&ty).copied().unwrap_or(1)))
}

/// How many times group `id`'s `cgroup.events` has changed.
pub fn events_of(id: u64) -> u64 {
    tree().groups.get(&id).map_or(0, |g| g.events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_as_kstrtoint_reads_them() {
        assert_eq!(int(b"12\n"), Ok(12));
        assert_eq!(int(b" 0x10 "), Ok(16));
        assert_eq!(int(b"010"), Ok(8));
        assert_eq!(int(b"-1"), Ok(-1));
        assert_eq!(int(b"abc"), Err(Errno::EINVAL));
        assert_eq!(int(b""), Err(Errno::EINVAL));
        assert_eq!(int(b"99999999999"), Err(Errno::ERANGE));
    }
}
