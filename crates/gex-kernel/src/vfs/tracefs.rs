//! tracefs (`mount -t tracefs`, `/sys/kernel/tracing`): the kernel's
//! tracing files as Android's GKI android17-6.18 arm64 kernel has them
//! (fs/tracefs/inode.c, event_inode.c; kernel/trace/trace.c,
//! trace_events.c, trace_output.c, ring_buffer.c at that tag). The spec
//! this follows, with the source lines for each answer, is
//! tracefs-spec.md in the oracle's drafts.
//!
//! What Android uses: libcutils writes every `ATRACE_*` to `trace_marker`
//! (it logs and gives up tracing for the process when it cannot open it);
//! init mounts it with `gid=3012`, makes the `bootreceiver` instance and
//! writes its buffer size, options and an event's `enable`; atrace.rc
//! chmods and chowns hundreds of its files. Here:
//!
//! - one tree, as Linux's one superblock: every mount is the same files,
//!   and a mount's `uid=`/`gid=` give every file that owner (clearing what
//!   `chown` set), `mode=` the root's mode;
//! - the root's files and `instances/` with Linux's modes and owners
//!   (resolved as `set_tracefs_inode_owner` does), `chmod` and `chown`
//!   kept; nothing made, removed or renamed but instances (`EPERM`,
//!   `EACCES` for a new name);
//! - a ring buffer a trace array: `trace_marker` and `trace_marker_raw`
//!   record into it as `tracing_mark_write` does (the cap, the newline,
//!   `EBADF` with tracing off, `EINVAL` with markers off, the top level's
//!   copies to instances), `trace` shows it with Linux's header and lines,
//!   `trace_pipe` consumes it, and the sizes, clock, options and cpumask
//!   answer as Linux's;
//! - `events/` with the events whose formats the spec gives (ftrace's
//!   print and raw_data, sched's switch, wakeups and exit, power's
//!   frequency and idle, error_report_end), their `enable`, `id`,
//!   `format`, `filter`, `trigger` and `hist`, `set_event` and
//!   `available_events`. This kernel has no tracepoints: an enabled event
//!   is kept enabled and never recorded, and that is said once.
//!
//! Not here, and refused loudly: `per_cpu/cpuN/trace_pipe_raw` (the binary
//! pages perfetto reads), filter and trigger expressions, kprobe, uprobe,
//! dynamic and synthetic event definitions. Every entry is recorded as CPU
//! 0's, the one CPU `getcpu` names here.

use super::{DirEntry, FileHandle, FileSystem, FileType, Metadata};
use crate::errno::{Errno, SysResult};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// `TRACEFS_MAGIC`.
const MAGIC: u64 = 0x7472_6163;
/// `EVENTFS_FILE_INODE_INO`: every eventfs file's inode number.
const EVENTFS_FILE_INO: u64 = 19_680_823;
/// A sub-buffer's data (4 KiB pages less its header) and the most one
/// event may take of it (`ring_buffer_max_event_size`).
const SUBBUF_DATA: u64 = 4080;
/// `TRACE_BUF_SIZE_DEFAULT`, per CPU.
const DEFAULT_BYTES: u64 = 1_441_792;
/// `TRACE_MARKER_MAX_SIZE`.
const MARKER_MAX: usize = 4096;
/// A print entry's header and the two bytes `write_marker_to_buffer` adds.
const PRINT_META: usize = 18;
/// The entry types with fixed ids.
const TRACE_PRINT: u32 = 5;
const TRACE_RAW_DATA: u32 = 19;
/// `__TRACE_LAST_TYPE`: where dynamic event ids start.
const FIRST_EVENT_ID: u32 = 21;

const CLOCKS: [&str; 9] = ["local", "global", "counter", "uptime", "perf", "mono", "mono_raw", "boot", "tai"];

/// The core options in bit order (`trace.h`), for this configuration.
const OPTIONS: [&str; 28] = [
    "print-parent",
    "sym-offset",
    "sym-addr",
    "verbose",
    "raw",
    "hex",
    "bin",
    "block",
    "fields",
    "trace_printk",
    "annotate",
    "userstacktrace",
    "sym-userobj",
    "printk-msg-only",
    "context-info",
    "latency-format",
    "record-cmd",
    "record-tgid",
    "overwrite",
    "disable_on_free",
    "irq-info",
    "markers",
    "event-fork",
    "trace_printk_dest",
    "copy_trace_marker",
    "pause-on-trace",
    "hash-ptr",
    "stacktrace",
];
const O_TRACE_PRINTK: u32 = 9;
const O_PRINTK_MSG_ONLY: u32 = 13;
const O_CONTEXT_INFO: u32 = 14;
const O_RECORD_CMD: u32 = 16;
const O_RECORD_TGID: u32 = 17;
const O_OVERWRITE: u32 = 18;
const O_DISABLE_ON_FREE: u32 = 19;
const O_IRQ_INFO: u32 = 20;
const O_MARKERS: u32 = 21;
const O_EVENT_FORK: u32 = 22;
const O_TRACE_PRINTK_DEST: u32 = 23;
const O_COPY_TRACE_MARKER: u32 = 24;
const O_VERBOSE: u32 = 3;
/// `TRACE_DEFAULT_FLAGS`.
const TOP_DEFAULT: u32 = 1 | 1 << O_TRACE_PRINTK | 1 << 10 | 1 << O_CONTEXT_INFO | 1 << O_RECORD_CMD | 1 << O_OVERWRITE | 1 << O_IRQ_INFO | 1 << O_MARKERS | 1 << O_TRACE_PRINTK_DEST | 1 << O_COPY_TRACE_MARKER | 1 << 26;
/// `ZEROED_TRACE_FLAGS`: cleared in a new instance.
const ZEROED: u32 = 1 << O_EVENT_FORK | 1 << O_TRACE_PRINTK_DEST | 1 << O_COPY_TRACE_MARKER;
/// `TOP_LEVEL_TRACE_FLAGS`: no `options/` file in an instance.
const TOP_ONLY: u32 = 1 << O_TRACE_PRINTK | 1 << O_PRINTK_MSG_ONLY | 1 << O_RECORD_CMD;
/// The nop tracer's options.
const NOP_OPTIONS: [&str; 2] = ["test_nop_accept", "test_nop_refuse"];

/// `README` for this configuration (trace.c's `readme_msg`).
const README: &str = include_str!("tracefs_readme.txt");

/// An event's field: type, name, offset, size, signed.
type Field = (&'static str, &'static str, u32, u32, u32);

/// An event of the defined set.
struct Event {
    system: &'static str,
    name: &'static str,
    fields: &'static [Field],
    print_fmt: &'static str,
    /// Its id, when fixed (ftrace's entries); else one from 21 in table order.
    fixed_id: Option<u32>,
}

impl Event {
    /// ftrace's entries are formats only: no `enable` or `filter`, and an
    /// `id` and `trigger` only for print (`TRACE_EVENT_FL_IGNORE_ENABLE`).
    fn internal(&self) -> bool {
        self.system == "ftrace"
    }
    fn files(&self) -> &'static [&'static str] {
        match (self.internal(), self.name) {
            (true, "print") => &["trigger", "format", "id", "hist"],
            (true, _) => &["format", "hist"],
            (false, _) => &["enable", "filter", "trigger", "format", "id", "hist"],
        }
    }
}

const SWITCH_FMT: &str = r#""prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d", REC->prev_comm, REC->prev_pid, REC->prev_prio, (REC->prev_state & ((((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) - 1)) ? __print_flags(REC->prev_state & ((((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) - 1), "|", { 0x00000001, "S" }, { 0x00000002, "D" }, { 0x00000004, "T" }, { 0x00000008, "t" }, { 0x00000010, "X" }, { 0x00000020, "Z" }, { 0x00000040, "P" }, { 0x00000080, "I" }) : "R", REC->prev_state & (((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) ? "+" : "", REC->next_comm, REC->next_pid, REC->next_prio"#;
const WAKEUP_FIELDS: &[Field] = &[("char", "comm[16]", 8, 16, 0), ("pid_t", "pid", 24, 4, 1), ("int", "prio", 28, 4, 1), ("int", "target_cpu", 32, 4, 1)];
const WAKEUP_FMT: &str = r#""comm=%s pid=%d prio=%d target_cpu=%03d", REC->comm, REC->pid, REC->prio, REC->target_cpu"#;
const CPU_FIELDS: &[Field] = &[("u32", "state", 8, 4, 0), ("u32", "cpu_id", 12, 4, 0)];
const CPU_FMT: &str = r#""state=%lu cpu_id=%lu", (unsigned long)REC->state, (unsigned long)REC->cpu_id"#;

const EVENTS: &[Event] = &[
    Event {
        system: "ftrace",
        name: "print",
        fields: &[("unsigned long", "ip", 8, 8, 0), ("char", "buf[]", 16, 0, 0)],
        print_fmt: r#""%ps: %s", (void *)REC->ip, REC->buf"#,
        fixed_id: Some(TRACE_PRINT),
    },
    Event {
        system: "ftrace",
        name: "raw_data",
        fields: &[("unsigned int", "id", 8, 4, 0), ("char", "buf[]", 12, 0, 0)],
        print_fmt: r#""id:%04x %08x", REC->id, (int)REC->buf[0]"#,
        fixed_id: Some(TRACE_RAW_DATA),
    },
    Event {
        system: "sched",
        name: "sched_switch",
        fields: &[
            ("char", "prev_comm[16]", 8, 16, 0),
            ("pid_t", "prev_pid", 24, 4, 1),
            ("int", "prev_prio", 28, 4, 1),
            ("long", "prev_state", 32, 8, 1),
            ("char", "next_comm[16]", 40, 16, 0),
            ("pid_t", "next_pid", 56, 4, 1),
            ("int", "next_prio", 60, 4, 1),
        ],
        print_fmt: SWITCH_FMT,
        fixed_id: None,
    },
    Event { system: "sched", name: "sched_waking", fields: WAKEUP_FIELDS, print_fmt: WAKEUP_FMT, fixed_id: None },
    Event { system: "sched", name: "sched_wakeup", fields: WAKEUP_FIELDS, print_fmt: WAKEUP_FMT, fixed_id: None },
    Event { system: "sched", name: "sched_wakeup_new", fields: WAKEUP_FIELDS, print_fmt: WAKEUP_FMT, fixed_id: None },
    Event {
        system: "sched",
        name: "sched_process_exit",
        fields: &[("char", "comm[16]", 8, 16, 0), ("pid_t", "pid", 24, 4, 1), ("int", "prio", 28, 4, 1), ("bool", "group_dead", 32, 1, 0)],
        print_fmt: r#""comm=%s pid=%d prio=%d group_dead=%s", REC->comm, REC->pid, REC->prio, REC->group_dead ? "true" : "false""#,
        fixed_id: None,
    },
    Event { system: "power", name: "cpu_frequency", fields: CPU_FIELDS, print_fmt: CPU_FMT, fixed_id: None },
    Event { system: "power", name: "cpu_idle", fields: CPU_FIELDS, print_fmt: CPU_FMT, fixed_id: None },
    Event {
        system: "error_report",
        name: "error_report_end",
        fields: &[("enum error_detector", "error_detector", 8, 4, 0), ("unsigned long", "id", 16, 8, 0)],
        print_fmt: r#""[%s] %lx", __print_symbolic(REC->error_detector, { 0, "kfence" }, { 1, "kasan" }, { 2, "warning" }), REC->id"#,
        fixed_id: None,
    },
];

/// Each event's id: its fixed one, or the next from 21.
fn event_id(i: usize) -> u32 {
    EVENTS[i].fixed_id.unwrap_or_else(|| FIRST_EVENT_ID + EVENTS[..i].iter().filter(|e| e.fixed_id.is_none()).count() as u32)
}

fn event_index(system: &str, name: &str) -> Option<usize> {
    EVENTS.iter().position(|e| e.system == system && e.name == name)
}

fn systems() -> Vec<&'static str> {
    let mut v: Vec<&str> = Vec::new();
    for e in EVENTS {
        if !v.contains(&e.system) {
            v.push(e.system);
        }
    }
    v
}

fn cpus() -> u32 {
    crate::cpus::count().max(1) as u32
}

/// What a trace array's buffer holds.
#[derive(Clone)]
enum Payload {
    Print(Vec<u8>),
    Raw(u32, Vec<u8>),
}

#[derive(Clone)]
struct Entry {
    ts_ns: u64,
    pid: i32,
    cpu: u32,
    /// `common_preempt_count` (the low nibble is the preempt depth).
    preempt: u8,
    payload: Payload,
}

impl Entry {
    /// What it takes of the buffer: its 4-byte event header and its body,
    /// rounded to 4 as the ring buffer stores it.
    fn bytes(&self) -> u64 {
        let body = match &self.payload {
            Payload::Print(b) => 16 + b.len() + 1,
            Payload::Raw(_, b) => 12 + b.len(),
        };
        4 + (body as u64).next_multiple_of(4)
    }
}

/// A trace array: the top level's, or an instance's.
struct Array {
    buffer: VecDeque<Entry>,
    used: u64,
    /// Entries ever recorded, and those dropped to make room.
    written: u64,
    overrun: u64,
    on: bool,
    /// The top level's buffer is minimal until first used (`ring_buf_size`).
    expanded: bool,
    /// Each CPU's sub-buffer pages.
    pages: Vec<u64>,
    /// `buffer_subbuf_size_kb`'s order.
    subbuf_order: u32,
    percent: u64,
    clock: usize,
    flags: u32,
    nop_flags: u32,
    cpumask: u64,
    enabled: BTreeSet<usize>,
    pids: BTreeSet<u64>,
    notrace_pids: BTreeSet<u64>,
    /// Files open that hold the array (rmdir is `EBUSY` while any is).
    refs: usize,
    /// `trace_pipe` readers: the whole array's, and each CPU's.
    pipe_all: bool,
    pipe_cpus: u64,
    /// Its `events/` tree's default owner (`ei->attr`).
    events_owner: (u32, u32),
}

impl Array {
    fn new(flags: u32, expanded: bool, events_owner: (u32, u32)) -> Array {
        let pages = if expanded { DEFAULT_BYTES.div_ceil(SUBBUF_DATA).max(2) } else { 2 };
        Array {
            buffer: VecDeque::new(),
            used: 0,
            written: 0,
            overrun: 0,
            on: true,
            expanded,
            pages: vec![pages; cpus() as usize],
            subbuf_order: 0,
            percent: 50,
            clock: 0,
            flags,
            nop_flags: 0,
            cpumask: if cpus() >= 64 { u64::MAX } else { (1 << cpus()) - 1 },
            enabled: BTreeSet::new(),
            pids: BTreeSet::new(),
            notrace_pids: BTreeSet::new(),
            refs: 0,
            pipe_all: false,
            pipe_cpus: 0,
            events_owner,
        }
    }

    fn flag(&self, bit: u32) -> bool {
        self.flags & (1 << bit) != 0
    }

    /// The bytes one CPU's buffer holds.
    fn capacity(&self) -> u64 {
        self.pages[0] * self.subbuf_data()
    }

    fn subbuf_data(&self) -> u64 {
        (4096 << self.subbuf_order) - 16
    }

    /// `ring_buffer_max_event_size`.
    fn max_event(&self) -> usize {
        (self.subbuf_data() - 8) as usize
    }

    fn expand(&mut self) {
        if !self.expanded {
            self.expanded = true;
            let pages = DEFAULT_BYTES.div_ceil(SUBBUF_DATA).max(2);
            self.pages.iter_mut().for_each(|p| *p = pages);
        }
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.used = 0;
        self.written = 0;
        self.overrun = 0;
    }

    /// Drop the oldest entries until `extra` more bytes fit.
    fn make_room(&mut self, extra: u64) -> bool {
        let cap = self.capacity();
        if extra > cap {
            return false;
        }
        while self.used + extra > cap {
            if !self.flag(O_OVERWRITE) {
                return false;
            }
            let Some(e) = self.buffer.pop_front() else { return false };
            self.used -= e.bytes();
            self.overrun += 1;
        }
        true
    }

    /// `ring_buffer_lock_reserve` and commit: `EBADF` when recording is off
    /// for the writer or the buffer is full with overwrite off.
    fn record(&mut self, e: Entry) -> Result<(), Errno> {
        if !self.on || self.cpumask & (1 << e.cpu) == 0 {
            return Err(Errno::EBADF);
        }
        let n = e.bytes();
        if !self.make_room(n) {
            return Err(Errno::EBADF);
        }
        self.used += n;
        self.written += 1;
        self.buffer.push_back(e);
        Ok(())
    }

    fn kb(&self, cpu: usize) -> u64 {
        self.pages[cpu] * self.subbuf_data() / 1024
    }

    /// `buffer_size_kb` of the whole array.
    fn size_text(&self) -> String {
        if self.pages.iter().any(|&p| p != self.pages[0]) {
            return "X\n".into();
        }
        if self.expanded {
            format!("{}\n", self.kb(0))
        } else {
            format!("{} (expanded: {})\n", self.kb(0), DEFAULT_BYTES / 1024)
        }
    }

    fn resize(&mut self, kb: u64, cpu: Option<usize>) {
        let pages = (kb * 1024).div_ceil(self.subbuf_data()).max(2);
        match cpu {
            Some(c) => self.pages[c] = pages,
            None => self.pages.iter_mut().for_each(|p| *p = pages),
        }
        self.expanded = true;
        let cap = self.capacity();
        while self.used > cap {
            let Some(e) = self.buffer.pop_front() else { break };
            self.used -= e.bytes();
        }
    }
}

/// A node's own mode and owner, where `chmod` or `chown` set them.
#[derive(Clone, Copy, Default)]
struct Attr {
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

struct State {
    /// "" the top level; else the instance's name.
    arrays: BTreeMap<String, Array>,
    attrs: HashMap<String, Attr>,
    root_mode: u32,
    root_owner: (u32, u32),
    /// The last mount's options, as `/proc/mounts` shows them.
    shown: String,
    inodes: HashMap<String, u64>,
    next_ino: u64,
    cmdlines_size: u64,
    thresh_us: u64,
    /// Whether "enabled but never emitted" has been said.
    said_enabled: bool,
}

fn state() -> MutexGuard<'static, State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| {
        let mut arrays = BTreeMap::new();
        arrays.insert(String::new(), Array::new(TOP_DEFAULT, false, (0, 0)));
        Mutex::new(State {
            arrays,
            attrs: HashMap::new(),
            root_mode: 0o700,
            root_owner: (0, 0),
            shown: String::new(),
            inodes: HashMap::new(),
            next_ino: 2,
            cmdlines_size: 6552,
            thresh_us: 0,
            said_enabled: false,
        })
    })
    .lock()
    .unwrap_or_else(|e| e.into_inner())
}

/// Woken when an array's buffer or recording changes (`trace_pipe`).
fn queue() -> &'static crate::wait::Queue {
    static Q: OnceLock<crate::wait::Queue> = OnceLock::new();
    Q.get_or_init(crate::wait::Queue::new)
}

/// What a path within the tree is.
#[derive(Clone, Debug, PartialEq)]
enum Node {
    Root,
    Instances,
    /// An array's directory (an instance's; the top level's is `Root`).
    ArrayDir(String),
    /// A file of an array: its name.
    File(String, &'static str),
    OptionsDir(String),
    /// An option file: core (by bit) or nop's (by index + 32).
    Option(String, u32),
    PerCpu(String),
    CpuDir(String, u32),
    CpuFile(String, u32, &'static str),
    Events(String),
    EventsFile(String, &'static str),
    System(String, &'static str),
    SystemFile(String, &'static str, &'static str),
    EventDir(String, usize),
    EventFile(String, usize, &'static str),
}

/// The files of an array's directory, top level or instance.
const ARRAY_FILES: &[(&str, u32)] = &[
    ("set_event", 0o640),
    ("set_event_pid", 0o640),
    ("set_event_notrace_pid", 0o640),
    ("available_tracers", 0o440),
    ("current_tracer", 0o640),
    ("tracing_cpumask", 0o640),
    ("trace_options", 0o640),
    ("trace", 0o640),
    ("trace_pipe", 0o440),
    ("buffer_size_kb", 0o640),
    ("buffer_total_size_kb", 0o440),
    ("free_buffer", 0o200),
    ("trace_marker", 0o220),
    ("trace_marker_raw", 0o220),
    ("trace_clock", 0o640),
    ("tracing_on", 0o640),
    ("timestamp_mode", 0o440),
    ("buffer_percent", 0o640),
    ("buffer_subbuf_size_kb", 0o640),
    ("error_log", 0o640),
];
/// The top level's files besides.
const TOP_FILES: &[(&str, u32)] = &[
    ("available_events", 0o440),
    ("tracing_thresh", 0o640),
    ("README", 0o440),
    ("saved_cmdlines", 0o440),
    ("saved_cmdlines_size", 0o640),
    ("saved_tgids", 0o440),
    ("printk_formats", 0o440),
    ("dynamic_events", 0o640),
    ("kprobe_events", 0o640),
    ("kprobe_profile", 0o440),
    ("uprobe_events", 0o640),
    ("uprobe_profile", 0o440),
    ("synthetic_events", 0o640),
];
const CPU_FILES: &[(&str, u32)] = &[("trace_pipe", 0o440), ("trace", 0o640), ("trace_pipe_raw", 0o440), ("stats", 0o440), ("buffer_size_kb", 0o640)];
const EVENTS_FILES: &[(&str, u32)] = &[("enable", 0o640), ("header_page", 0o440), ("header_event", 0o440)];
const EVENT_FILE_MODES: &[(&str, u32)] = &[("enable", 0o640), ("filter", 0o640), ("trigger", 0o640), ("format", 0o440), ("id", 0o440), ("hist", 0o440)];

fn lookup(list: &[(&'static str, u32)], name: &str) -> Option<(&'static str, u32)> {
    list.iter().find(|(n, _)| *n == name).copied()
}

/// The options an array's `options/` has: the core ones (in an instance,
/// not the top-level-only ones) and nop's.
fn option_files(top: bool) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> = OPTIONS.iter().enumerate().filter(|(i, _)| top || TOP_ONLY & (1 << i) == 0).map(|(i, n)| (n.to_string(), i as u32)).collect();
    v.extend(NOP_OPTIONS.iter().enumerate().map(|(i, n)| (n.to_string(), 32 + i as u32)));
    v
}

fn find(path: &str) -> Result<Node, Errno> {
    let s = state();
    find_in(&s, path)
}

fn find_in(s: &State, path: &str) -> Result<Node, Errno> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Ok(Node::Root);
    }
    let (array, rest) = if parts[0] == "instances" {
        if parts.len() == 1 {
            return Ok(Node::Instances);
        }
        if !s.arrays.contains_key(parts[1]) || parts[1].is_empty() {
            return Err(Errno::ENOENT);
        }
        if parts.len() == 2 {
            return Ok(Node::ArrayDir(parts[1].to_string()));
        }
        (parts[1].to_string(), &parts[2..])
    } else {
        (String::new(), &parts[..])
    };
    let top = array.is_empty();
    match rest {
        [f] => {
            if let Some((n, _)) = lookup(ARRAY_FILES, f).or_else(|| if top { lookup(TOP_FILES, f) } else { None }) {
                return Ok(Node::File(array, n));
            }
            match *f {
                "options" => Ok(Node::OptionsDir(array)),
                "per_cpu" => Ok(Node::PerCpu(array)),
                "events" => Ok(Node::Events(array)),
                _ => Err(Errno::ENOENT),
            }
        }
        ["options", o] => option_files(top).into_iter().find(|(n, _)| n == o).map(|(_, b)| Node::Option(array, b)).ok_or(Errno::ENOENT),
        ["per_cpu", c, more @ ..] => {
            let n: u32 = c.strip_prefix("cpu").and_then(|d| d.parse().ok()).filter(|&n| n < cpus()).ok_or(Errno::ENOENT)?;
            match more {
                [] => Ok(Node::CpuDir(array, n)),
                [f] => lookup(CPU_FILES, f).map(|(f, _)| Node::CpuFile(array, n, f)).ok_or(Errno::ENOENT),
                _ => Err(Errno::ENOENT),
            }
        }
        ["events", more @ ..] => {
            let systems = systems();
            match more {
                [] => Ok(Node::Events(array)),
                [f] => {
                    if let Some((f, _)) = lookup(EVENTS_FILES, f) {
                        return Ok(Node::EventsFile(array, f));
                    }
                    systems.into_iter().find(|s| s == f).map(|s| Node::System(array, s)).ok_or(Errno::ENOENT)
                }
                [sys, f] => {
                    let sys = systems.into_iter().find(|s| s == sys).ok_or(Errno::ENOENT)?;
                    if sys != "ftrace" {
                        if let Some(f) = ["enable", "filter"].into_iter().find(|n| n == f) {
                            return Ok(Node::SystemFile(array, sys, f));
                        }
                    }
                    event_index(sys, f).map(|i| Node::EventDir(array, i)).ok_or(Errno::ENOENT)
                }
                [sys, ev, f] => {
                    let i = event_index(sys, ev).ok_or(Errno::ENOENT)?;
                    EVENTS[i].files().iter().find(|n| *n == f).map(|n| Node::EventFile(array, i, n)).ok_or(Errno::ENOENT)
                }
                _ => Err(Errno::ENOENT),
            }
        }
        _ => Err(Errno::ENOENT),
    }
}

impl Node {
    fn is_dir(&self) -> bool {
        matches!(self, Node::Root | Node::Instances | Node::ArrayDir(_) | Node::OptionsDir(_) | Node::PerCpu(_) | Node::CpuDir(..) | Node::Events(_) | Node::System(..) | Node::EventDir(..))
    }

    /// Whether it is under `events/` (eventfs: its own owners and inodes).
    fn eventfs(&self) -> bool {
        matches!(self, Node::Events(_) | Node::EventsFile(..) | Node::System(..) | Node::SystemFile(..) | Node::EventDir(..) | Node::EventFile(..))
    }

    fn array(&self) -> Option<&str> {
        match self {
            Node::Root | Node::Instances => None,
            Node::ArrayDir(a)
            | Node::File(a, _)
            | Node::OptionsDir(a)
            | Node::Option(a, _)
            | Node::PerCpu(a)
            | Node::CpuDir(a, _)
            | Node::CpuFile(a, ..)
            | Node::Events(a)
            | Node::EventsFile(a, _)
            | Node::System(a, _)
            | Node::SystemFile(a, ..)
            | Node::EventDir(a, _)
            | Node::EventFile(a, ..) => Some(a),
        }
    }

    /// The mode it is made with.
    fn default_mode(&self) -> u32 {
        match self {
            Node::Root => 0o700,
            Node::Events(_) | Node::System(..) | Node::EventDir(..) => 0o755,
            Node::Instances | Node::ArrayDir(_) | Node::OptionsDir(_) | Node::PerCpu(_) | Node::CpuDir(..) => 0o750,
            Node::File(_, f) => lookup(ARRAY_FILES, f).or_else(|| lookup(TOP_FILES, f)).map_or(0o440, |(_, m)| m),
            Node::Option(..) => 0o640,
            Node::CpuFile(_, _, f) => lookup(CPU_FILES, f).map_or(0o440, |(_, m)| m),
            Node::EventsFile(_, f) => lookup(EVENTS_FILES, f).map_or(0o440, |(_, m)| m),
            Node::SystemFile(..) => 0o640,
            Node::EventFile(_, _, f) => lookup(EVENT_FILE_MODES, f).map_or(0o440, |(_, m)| m),
        }
    }
}

/// A path in canonical form, for attributes and inode numbers.
fn key(path: &str) -> String {
    path.split('/').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("/")
}

fn metadata_in(s: &mut State, path: &str, node: &Node) -> Metadata {
    let k = key(path);
    let attr = s.attrs.get(&k).copied().unwrap_or_default();
    let mode = if *node == Node::Root { s.root_mode } else { attr.mode.unwrap_or_else(|| node.default_mode()) };
    // Owners (`set_tracefs_inode_owner`): the root's are its own; an
    // eventfs node's its tree's default unless set on it; any other's
    // `instances/`'s (an instance's file) when that was chowned, else the
    // root's, unless set on it.
    let (duid, dgid) = if *node == Node::Root {
        s.root_owner
    } else if node.eventfs() {
        let a = node.array().unwrap_or("");
        s.arrays.get(a).map_or(s.root_owner, |arr| arr.events_owner)
    } else {
        let inst = s.attrs.get("instances").copied().unwrap_or_default();
        let under_instance = node.array().is_some_and(|a| !a.is_empty());
        let uid = if under_instance { inst.uid.unwrap_or(s.root_owner.0) } else { s.root_owner.0 };
        let gid = if under_instance { inst.gid.unwrap_or(s.root_owner.1) } else { s.root_owner.1 };
        (uid, gid)
    };
    let owner = (attr.uid.unwrap_or(duid), attr.gid.unwrap_or(dgid));
    let dir = node.is_dir();
    let ino = if !dir && node.eventfs() {
        EVENTFS_FILE_INO
    } else {
        let next = s.next_ino;
        let ino = *s.inodes.entry(k).or_insert(next);
        if ino == next {
            s.next_ino += 1;
        }
        ino
    };
    Metadata {
        file_type: if dir { FileType::Directory } else { FileType::Regular },
        size: 0,
        mode,
        ino,
        mtime: 0,
        nlink: if dir && !node.eventfs() { 2 } else { 1 },
        rdev: 0,
        dev: 0,
        times: Default::default(),
        owner: Some(owner),
    }
}

/// The entries of a directory node.
fn entries_in(s: &State, node: &Node) -> Vec<(String, bool)> {
    let mut v: Vec<(String, bool)> = Vec::new();
    let files = |v: &mut Vec<(String, bool)>, list: &[(&str, u32)]| v.extend(list.iter().map(|(n, _)| (n.to_string(), false)));
    match node {
        Node::Root | Node::ArrayDir(_) => {
            let top = *node == Node::Root;
            files(&mut v, ARRAY_FILES);
            if top {
                files(&mut v, TOP_FILES);
                v.push(("instances".into(), true));
            }
            v.extend(["options", "per_cpu", "events"].iter().map(|n| (n.to_string(), true)));
        }
        Node::Instances => v.extend(s.arrays.keys().filter(|k| !k.is_empty()).map(|k| (k.clone(), true))),
        Node::OptionsDir(a) => v.extend(option_files(a.is_empty()).into_iter().map(|(n, _)| (n, false))),
        Node::PerCpu(_) => v.extend((0..cpus()).map(|c| (format!("cpu{c}"), true))),
        Node::CpuDir(..) => files(&mut v, CPU_FILES),
        Node::Events(_) => {
            files(&mut v, EVENTS_FILES);
            v.extend(systems().into_iter().map(|s| (s.to_string(), true)));
        }
        Node::System(_, sys) => {
            if *sys != "ftrace" {
                v.extend(["filter", "enable"].iter().map(|n| (n.to_string(), false)));
            }
            v.extend(EVENTS.iter().filter(|e| e.system == *sys).map(|e| (e.name.to_string(), true)));
        }
        Node::EventDir(_, i) => v.extend(EVENTS[*i].files().iter().map(|n| (n.to_string(), false))),
        _ => {}
    }
    v
}

/// `kstrtoul_from_user(.., 10, ..)`: decimal, one trailing newline.
fn parse_u64(buf: &[u8]) -> Result<u64, Errno> {
    let t = std::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
    let t = t.strip_suffix('\n').unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Errno::EINVAL);
    }
    t.parse::<u64>().map_err(|_| Errno::ERANGE)
}

/// The writer's pid (`current->pid`), as the kernel's record names it.
fn writer() -> i32 {
    crate::unix::Sender::current().map_or(0, |c| c.pid)
}

/// The array's clock, in nanoseconds (`counter` counts entries).
fn now(clock: usize) -> u64 {
    let c = crate::syscalls::system_clock;
    match CLOCKS[clock] {
        "boot" => crate::syscalls::clock_ns(c, 7),
        "mono_raw" => crate::syscalls::clock_ns(c, 4),
        "tai" => crate::syscalls::clock_ns(c, 11),
        // jiffies at GKI's 250 Hz.
        "uptime" => crate::syscalls::clock_ns(c, 1) / 4_000_000,
        _ => crate::syscalls::clock_ns(c, 1),
    }
}

/// One entry as a line of `trace` (`trace_print_context` and the entry's
/// own output).
fn line(arr: &Array, e: &Entry) -> String {
    let mut out = String::new();
    if arr.flag(O_CONTEXT_INFO) {
        let comm = if e.pid == 0 { "<idle>" } else { "<...>" };
        out.push_str(&format!("{comm:>16}-{:<7} ", e.pid));
        if arr.flag(O_RECORD_TGID) {
            out.push_str("(-------) ");
        }
        out.push_str(&format!("[{:03}] ", e.cpu));
        if arr.flag(O_IRQ_INFO) {
            let depth = e.preempt & 0xf;
            let migrate = e.preempt >> 4;
            let hex = |n: u8| if n == 0 { '.' } else { char::from_digit(n as u32, 16).unwrap_or('.') };
            out.push_str(&format!("...{}{} ", hex(depth), hex(migrate)));
        }
        if matches!(CLOCKS[arr.clock], "counter" | "uptime") {
            out.push_str(&format!("{:12}: ", e.ts_ns));
        } else {
            let us = e.ts_ns / 1000;
            out.push_str(&format!("{:5}.{:06}: ", us / 1_000_000, us % 1_000_000));
        }
    }
    match &e.payload {
        Payload::Print(b) => {
            let text = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
            out.push_str("tracing_mark_write: ");
            out.push_str(&String::from_utf8_lossy(text));
        }
        Payload::Raw(id, b) => {
            out.push_str(&format!("# {id:x} buf:"));
            let padded = (8 + b.len()).next_multiple_of(4) - 8;
            for i in 0..padded {
                out.push_str(&format!(" {:02x}", b.get(i).copied().unwrap_or(0)));
            }
            out.push('\n');
        }
    }
    out
}

/// `trace`'s text: the header, then every entry (of `cpu` alone, if given).
fn trace_text(arr: &Array, cpu: Option<u32>) -> String {
    let mut out = String::from("# tracer: nop\n#\n");
    if arr.flag(O_CONTEXT_INFO) && !arr.flag(O_VERBOSE) {
        out.push_str(&format!("# entries-in-buffer/entries-written: {}/{}   #P:{}\n#\n", arr.buffer.len(), arr.buffer.len() as u64 + arr.overrun, cpus()));
        let tgid = arr.flag(O_RECORD_TGID);
        if arr.flag(O_IRQ_INFO) {
            let pad = if tgid { "          " } else { "" };
            for l in [
                "                                _-----=> irqs-off/BH-disabled",
                "                               / _----=> need-resched",
                "                              | / _---=> hardirq/softirq",
                "                              || / _--=> preempt-depth",
                "                              ||| / _-=> migrate-disable",
                "                              |||| /     delay",
            ] {
                out.push_str(&format!("#{pad}{}\n", &l[1..]));
            }
            if tgid {
                out.push_str("#           TASK-PID       TGID    CPU#  |||||  TIMESTAMP  FUNCTION\n#              | |           |       |   |||||     |         |\n");
            } else {
                out.push_str("#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION\n#              | |         |   |||||     |         |\n");
            }
        } else if tgid {
            out.push_str("#           TASK-PID       TGID    CPU#     TIMESTAMP  FUNCTION\n#              | |           |       |         |         |\n");
        } else {
            out.push_str("#           TASK-PID     CPU#     TIMESTAMP  FUNCTION\n#              | |         |         |         |\n");
        }
    }
    for e in arr.buffer.iter().filter(|e| cpu.is_none_or(|c| c == e.cpu)) {
        out.push_str(&line(arr, e));
    }
    out
}

/// `trace_clock`'s text.
fn clock_text(arr: &Array) -> String {
    let names: Vec<String> = CLOCKS.iter().enumerate().map(|(i, n)| if i == arr.clock { format!("[{n}]") } else { n.to_string() }).collect();
    format!("{}\n", names.join(" "))
}

fn options_text(arr: &Array) -> String {
    let mut out = String::new();
    for (i, n) in OPTIONS.iter().enumerate() {
        out.push_str(if arr.flags & (1 << i) != 0 { "" } else { "no" });
        out.push_str(n);
        out.push('\n');
    }
    for (i, n) in NOP_OPTIONS.iter().enumerate() {
        out.push_str(if arr.nop_flags & (1 << i) != 0 { "" } else { "no" });
        out.push_str(n);
        out.push('\n');
    }
    out
}

/// `%*pb` of the cpumask: hex, a comma every 32 bits.
fn cpumask_text(arr: &Array) -> String {
    let n = cpus();
    let words = n.div_ceil(32);
    let mut parts = Vec::new();
    for w in (0..words).rev() {
        let bits = (arr.cpumask >> (w * 32)) & 0xffff_ffff;
        let width = if w == words - 1 { (n - w * 32).div_ceil(4) as usize } else { 8 };
        parts.push(format!("{bits:0width$x}"));
    }
    format!("{}\n", parts.join(","))
}

fn stats_text(arr: &Array, cpu: u32) -> String {
    let mine: Vec<&Entry> = arr.buffer.iter().filter(|e| e.cpu == cpu).collect();
    let bytes: u64 = mine.iter().map(|e| e.bytes()).sum();
    let ts = |ns: u64| {
        let us = ns / 1000;
        format!("{:5}.{:06}", us / 1_000_000, us % 1_000_000)
    };
    let oldest = mine.first().map_or(0, |e| e.ts_ns);
    format!(
        "entries: {}\noverrun: {}\ncommit overrun: 0\nbytes: {}\noldest event ts: {}\nnow ts: {}\ndropped events: 0\nread events: 0\n",
        mine.len(),
        if cpu == 0 { arr.overrun } else { 0 },
        bytes,
        ts(oldest),
        ts(now(arr.clock))
    )
}

fn format_text(i: usize) -> String {
    let e = &EVENTS[i];
    let mut out = format!("name: {}\nID: {}\nformat:\n", e.name, event_id(i));
    for (t, n, o, s, sg) in [
        ("unsigned short", "common_type", 0, 2, 0),
        ("unsigned char", "common_flags", 2, 1, 0),
        ("unsigned char", "common_preempt_count", 3, 1, 0),
        ("int", "common_pid", 4, 4, 1),
    ]
    .into_iter()
    .chain(e.fields.iter().copied())
    {
        out.push_str(&format!("\tfield:{t} {n};\toffset:{o};\tsize:{s};\tsigned:{sg};\n"));
        if n == "common_pid" {
            out.push('\n');
        }
    }
    out.push_str(&format!("\nprint fmt: {}\n", e.print_fmt));
    out
}

const HEADER_PAGE: &str = "\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n\tfield: local_t commit;\toffset:8;\tsize:8;\tsigned:1;\n\tfield: int overwrite;\toffset:8;\tsize:1;\tsigned:1;\n\tfield: char data;\toffset:16;\tsize:4080;\tsigned:0;\n";
const HEADER_EVENT: &str = "# compressed entry header\n\ttype_len    :    5 bits\n\ttime_delta  :   27 bits\n\tarray       :   32 bits\n\n\tpadding     : type == 29\n\ttime_extend : type == 30\n\ttime_stamp : type == 31\n\tdata max type_len  == 28\n";
const SYSTEM_FILTER: &str = "### global filter ###\n# Use this to set filters for multiple events.\n# Only events with the given fields will be affected.\n# If no events are modified, an error message will be displayed here\n";
const TRIGGERS: &str = "# Available triggers:\n# traceon traceoff stacktrace enable_event disable_event enable_hist disable_hist hist\n";

/// The enableable events a system file or `events/enable` covers.
fn scope(system: Option<&str>) -> Vec<usize> {
    (0..EVENTS.len()).filter(|&i| !EVENTS[i].internal() && system.is_none_or(|s| EVENTS[i].system == s)).collect()
}

fn enable_char(arr: &Array, system: Option<&str>) -> &'static str {
    let s = scope(system);
    let on = s.iter().filter(|i| arr.enabled.contains(i)).count();
    match (s.len(), on) {
        (0, _) => "?\n",
        (_, 0) => "0\n",
        (n, m) if n == m => "1\n",
        _ => "X\n",
    }
}

fn set_enabled(s: &mut State, array: &str, events: &[usize], on: bool) -> Result<(), Errno> {
    let arr = s.arrays.get_mut(array).ok_or(Errno::ENODEV)?;
    arr.expand();
    for &i in events {
        if on {
            arr.enabled.insert(i);
        } else {
            arr.enabled.remove(&i);
        }
    }
    if on && !s.said_enabled {
        s.said_enabled = true;
        eprintln!("[gex] tracefs: events enabled (first {}:{}); this kernel has no tracepoints, and records none", EVENTS[events[0]].system, EVENTS[events[0]].name);
    }
    Ok(())
}

/// `set_event`'s token: `[!]spec`, which events it names.
fn match_events(spec: &str) -> Vec<usize> {
    let spec = spec.split(":mod:").next().unwrap_or(spec);
    let (sys, ev) = match spec.split_once(':') {
        Some((s, e)) => (Some(s).filter(|s| !s.is_empty() && *s != "*"), Some(e).filter(|e| !e.is_empty() && *e != "*")),
        None => (None, None),
    };
    scope(None)
        .into_iter()
        .filter(|&i| {
            let e = &EVENTS[i];
            if spec.contains(':') {
                sys.is_none_or(|s| s == e.system) && ev.is_none_or(|n| n == e.name)
            } else {
                spec == e.system || spec == e.name
            }
        })
        .collect()
}

/// Records a marker into `array` (`write_marker_to_buffer`): the bytes
/// taken from the writer.
fn write_marker(arr: &mut Array, bytes: &[u8], pid: i32) -> Result<usize, Errno> {
    let mut cnt = bytes.len().min(MARKER_MAX);
    if cnt + PRINT_META > arr.max_event() {
        cnt = arr.max_event() - PRINT_META;
    }
    let mut text = bytes[..cnt].to_vec();
    if text.last() != Some(&b'\n') {
        text.push(b'\n');
    }
    let ts = now(arr.clock);
    arr.record(Entry { ts_ns: ts, pid, cpu: 0, preempt: 1, payload: Payload::Print(text) })?;
    Ok(cnt)
}

fn write_raw(arr: &mut Array, bytes: &[u8], pid: i32) -> Result<usize, Errno> {
    if bytes.len() + 8 > arr.max_event() {
        return Err(Errno::EINVAL);
    }
    let id = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]));
    let ts = now(arr.clock);
    arr.record(Entry { ts_ns: ts, pid, cpu: 0, preempt: 1, payload: Payload::Raw(id, bytes[4..].to_vec()) })?;
    Ok(bytes.len())
}

/// `set_tracer_flag`: `EINVAL` for what may not change.
fn set_flag(s: &mut State, array: &str, bit: u32, on: bool) -> Result<(), Errno> {
    let arr = s.arrays.get_mut(array).ok_or(Errno::ENODEV)?;
    if bit >= 32 {
        // nop's: test_nop_refuse is refused.
        if bit == 33 {
            return Err(Errno::EINVAL);
        }
        if on {
            arr.nop_flags |= 1 << (bit - 32);
        } else {
            arr.nop_flags &= !(1 << (bit - 32));
        }
        return Ok(());
    }
    // trace_printk's output has to go somewhere: the array that has it
    // cannot let it go (the top level, unless an instance took it).
    if bit == O_TRACE_PRINTK_DEST && !on && arr.flag(bit) {
        return Err(Errno::EINVAL);
    }
    if on {
        arr.flags |= 1 << bit;
    } else {
        arr.flags &= !(1 << bit);
    }
    if bit == O_TRACE_PRINTK_DEST && on {
        for (k, other) in s.arrays.iter_mut() {
            if k != array {
                other.flags &= !(1 << O_TRACE_PRINTK_DEST);
            }
        }
    }
    Ok(())
}

/// A handle's hold on its array (`trace_array_get`), let go at close.
#[derive(Debug)]
struct Hold(Option<String>);

impl Drop for Hold {
    fn drop(&mut self) {
        if let Some(a) = &self.0 {
            if let Some(arr) = state().arrays.get_mut(a) {
                arr.refs = arr.refs.saturating_sub(1);
            }
        }
    }
}

#[derive(Debug)]
struct Dir {
    entries: Vec<DirEntry>,
    meta: Metadata,
}

impl FileHandle for Dir {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EISDIR)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.meta.clone())
    }
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        Ok(self.entries.clone())
    }
}

/// An open file of the tree.
#[derive(Debug)]
struct File {
    path: String,
    node: Node,
    /// `trace`'s text, made at the first read and read from after (a
    /// seq_file's iteration over what the buffer held then).
    snapshot: Mutex<Option<Vec<u8>>>,
    /// `trace_pipe`: something was read (an empty buffer with tracing
    /// off is then the end).
    read_any: std::sync::atomic::AtomicBool,
    _hold: Hold,
}

fn text_at(text: &[u8], offset: u64, buf: &mut [u8]) -> SysResult {
    let start = (offset as usize).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    Ok(n as u64)
}

impl File {
    fn array(&self) -> &str {
        self.node.array().unwrap_or("")
    }

    /// What a read gives, as text, for the files whose whole text is made
    /// at each read.
    fn text(&self, s: &mut State) -> Result<String, Errno> {
        let a = self.array().to_string();
        let arr = s.arrays.get(&a).ok_or(Errno::ENODEV)?;
        Ok(match &self.node {
            Node::File(_, f) => match *f {
                "tracing_on" => format!("{}\n", arr.on as u8),
                "buffer_size_kb" => arr.size_text(),
                "buffer_total_size_kb" => {
                    let total: u64 = (0..arr.pages.len()).map(|c| arr.pages[c] * arr.subbuf_data() >> 10).sum();
                    if arr.expanded {
                        format!("{total}\n")
                    } else {
                        format!("{total} (expanded: {})\n", cpus() as u64 * (DEFAULT_BYTES >> 10))
                    }
                }
                "buffer_subbuf_size_kb" => format!("{}\n", 4u64 << arr.subbuf_order),
                "buffer_percent" => format!("{}\n", arr.percent),
                "trace_clock" => clock_text(arr),
                "timestamp_mode" => "[delta] absolute\n".into(),
                "available_tracers" | "current_tracer" => "nop\n".into(),
                "tracing_cpumask" => cpumask_text(arr),
                "trace_options" => options_text(arr),
                "set_event" => arr.enabled.iter().map(|&i| format!("{}:{}\n", EVENTS[i].system, EVENTS[i].name)).collect(),
                "set_event_pid" => arr.pids.iter().map(|p| format!("{p}\n")).collect(),
                "set_event_notrace_pid" => arr.notrace_pids.iter().map(|p| format!("{p}\n")).collect(),
                "available_events" => scope(None).into_iter().map(|i| format!("{}:{}\n", EVENTS[i].system, EVENTS[i].name)).collect(),
                "saved_cmdlines_size" => format!("{}\n", s.cmdlines_size),
                "tracing_thresh" => format!("{}\n", s.thresh_us),
                "README" => README.into(),
                "error_log" | "saved_cmdlines" | "saved_tgids" | "printk_formats" | "dynamic_events" | "kprobe_events" | "kprobe_profile" | "uprobe_events" | "uprobe_profile" | "synthetic_events" => String::new(),
                _ => return Err(Errno::EINVAL),
            },
            Node::Option(_, b) if *b >= 32 => format!("{}\n", (arr.nop_flags >> (b - 32)) & 1),
            Node::Option(_, b) => format!("{}\n", (arr.flags >> b) & 1),
            Node::CpuFile(_, c, f) => match *f {
                "buffer_size_kb" => format!("{}\n", arr.kb(*c as usize)),
                "stats" => stats_text(arr, *c),
                _ => return Err(Errno::EINVAL),
            },
            Node::EventsFile(_, f) => match *f {
                "enable" => enable_char(arr, None).into(),
                "header_page" => HEADER_PAGE.into(),
                "header_event" => HEADER_EVENT.into(),
                _ => return Err(Errno::EINVAL),
            },
            Node::SystemFile(_, sys, f) => match *f {
                "enable" => enable_char(arr, Some(sys)).into(),
                _ => SYSTEM_FILTER.into(),
            },
            Node::EventFile(_, i, f) => match *f {
                "enable" => format!("{}\n", arr.enabled.contains(i) as u8),
                "filter" => "none\n".into(),
                "trigger" => TRIGGERS.into(),
                "format" => format_text(*i),
                "id" => format!("{}\n", event_id(*i)),
                "hist" => String::new(),
                _ => return Err(Errno::EINVAL),
            },
            _ => return Err(Errno::EINVAL),
        })
    }

    /// `trace_pipe`'s read: whole lines of what is there, consumed.
    fn read_pipe(&self, cpu: Option<u32>, buf: &mut [u8]) -> SysResult {
        let mut s = state();
        let arr = s.arrays.get_mut(self.array()).ok_or(Errno::ENODEV)?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(pos) = arr.buffer.iter().position(|e| cpu.is_none_or(|c| c == e.cpu)) else { break };
            let l = line(arr, &arr.buffer[pos]);
            if !out.is_empty() && out.len() + l.len() > buf.len() {
                break;
            }
            let l = if l.len() > buf.len() { "[LINE TOO BIG]\n".to_string() } else { l };
            if out.len() + l.len() > buf.len() {
                break;
            }
            out.extend_from_slice(l.as_bytes());
            if let Some(e) = arr.buffer.remove(pos) {
                arr.used -= e.bytes();
            }
        }
        if out.is_empty() {
            let ended = self.read_any.load(std::sync::atomic::Ordering::Relaxed) && !arr.on;
            return if ended { Ok(0) } else { Err(Errno::EAGAIN) };
        }
        self.read_any.store(true, std::sync::atomic::Ordering::Relaxed);
        buf[..out.len()].copy_from_slice(&out);
        Ok(out.len() as u64)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let mut s = state();
        let a = self.node.array().unwrap_or("").to_string();
        let Some(arr) = s.arrays.get_mut(&a) else { return };
        match &self.node {
            Node::File(_, "trace_pipe") => arr.pipe_all = false,
            Node::CpuFile(_, c, "trace_pipe") => arr.pipe_cpus &= !(1 << c),
            // `free_buffer`'s close: off, if so asked, and as small as it goes.
            Node::File(_, "free_buffer") => {
                if arr.flag(O_DISABLE_ON_FREE) {
                    arr.on = false;
                }
                arr.resize(0, None);
                queue().notify();
            }
            _ => {}
        }
    }
}

impl FileHandle for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        match &self.node {
            Node::File(_, "trace") | Node::CpuFile(_, _, "trace") => {
                let mut snap = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
                if snap.is_none() || offset == 0 {
                    let s = state();
                    let arr = s.arrays.get(self.array()).ok_or(Errno::ENODEV)?;
                    let cpu = if let Node::CpuFile(_, c, _) = self.node { Some(c) } else { None };
                    *snap = Some(trace_text(arr, cpu).into_bytes());
                }
                text_at(snap.as_deref().unwrap_or_default(), offset, buf)
            }
            Node::File(_, "trace_pipe") => self.read_pipe(None, buf),
            Node::CpuFile(_, c, "trace_pipe") => self.read_pipe(Some(*c), buf),
            Node::File(_, "trace_marker" | "trace_marker_raw" | "free_buffer") => Err(Errno::EINVAL),
            Node::File(_, "tracing_cpumask") => {
                let text = self.text(&mut state())?;
                if offset == 0 && buf.len() <= text.len() {
                    return Err(Errno::EINVAL);
                }
                text_at(text.as_bytes(), offset, buf)
            }
            Node::EventsFile(_, "header_page" | "header_event") if offset != 0 => Ok(0),
            _ => {
                let text = self.text(&mut state())?;
                text_at(text.as_bytes(), offset, buf)
            }
        }
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        let mut s = state();
        let a = self.array().to_string();
        let cnt = buf.len() as u64;
        let pid = writer();
        match &self.node {
            Node::File(_, f) => match *f {
                "trace_marker" | "trace_marker_raw" => {
                    let raw = *f == "trace_marker_raw";
                    let arr = s.arrays.get(&a).ok_or(Errno::ENODEV)?;
                    if !arr.flag(O_MARKERS) {
                        return Err(Errno::EINVAL);
                    }
                    if raw && (buf.len() < 4 || buf.len() > MARKER_MAX) {
                        return Err(Errno::EINVAL);
                    }
                    // The top level's goes to every array that copies it.
                    let targets: Vec<String> = if a.is_empty() {
                        s.arrays.iter().filter(|(_, x)| x.flag(O_COPY_TRACE_MARKER)).map(|(k, _)| k.clone()).collect()
                    } else {
                        vec![a.clone()]
                    };
                    let mut written: Result<usize, Errno> = Err(Errno::ENODEV);
                    for t in targets {
                        let arr = s.arrays.get_mut(&t).ok_or(Errno::ENODEV)?;
                        written = if raw { write_raw(arr, buf, pid) } else { write_marker(arr, buf, pid) };
                        if written.is_err() {
                            break;
                        }
                    }
                    queue().notify();
                    written.map(|n| n as u64)
                }
                "tracing_on" => {
                    let v = parse_u64(buf)?;
                    s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.on = v != 0;
                    queue().notify();
                    Ok(cnt)
                }
                "trace" | "error_log" | "free_buffer" => Ok(cnt),
                "buffer_size_kb" => {
                    let kb = parse_u64(buf)?;
                    if kb == 0 {
                        return Err(Errno::EINVAL);
                    }
                    s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.resize(kb, None);
                    Ok(cnt)
                }
                "buffer_subbuf_size_kb" => {
                    let kb = parse_u64(buf)?;
                    let pages = (kb * 1024).div_ceil(4096);
                    let order = if pages == 0 { 32 } else { 64 - (pages - 1).leading_zeros() };
                    if order > 7 {
                        return Err(Errno::EINVAL);
                    }
                    let arr = s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?;
                    arr.subbuf_order = order;
                    arr.clear();
                    Ok(cnt)
                }
                "buffer_percent" => {
                    let v = parse_u64(buf)?;
                    if v > 100 {
                        return Err(Errno::EINVAL);
                    }
                    s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.percent = v;
                    Ok(cnt)
                }
                "trace_clock" => {
                    if buf.len() >= 64 {
                        return Err(Errno::EINVAL);
                    }
                    let name = String::from_utf8_lossy(buf);
                    let i = CLOCKS.iter().position(|c| *c == name.trim()).ok_or(Errno::EINVAL)?;
                    let arr = s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?;
                    arr.clock = i;
                    arr.clear();
                    Ok(cnt)
                }
                "current_tracer" => {
                    let name = String::from_utf8_lossy(&buf[..buf.len().min(100)]).trim().to_string();
                    if name != "nop" {
                        return Err(Errno::EINVAL);
                    }
                    let arr = s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?;
                    if arr.pipe_all || arr.pipe_cpus != 0 {
                        return Err(Errno::EBUSY);
                    }
                    arr.expand();
                    Ok(cnt)
                }
                "tracing_cpumask" => {
                    if buf.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    let t: String = String::from_utf8_lossy(buf).trim().chars().filter(|c| *c != ',').collect();
                    let mask = u64::from_str_radix(&t, 16).map_err(|_| Errno::EINVAL)?;
                    s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.cpumask = mask;
                    Ok(cnt)
                }
                "trace_options" => {
                    if buf.len() >= 64 {
                        return Err(Errno::EINVAL);
                    }
                    let t = String::from_utf8_lossy(buf).trim().to_string();
                    let (on, name) = match t.strip_prefix("no") {
                        Some(n) if OPTIONS.contains(&n) || NOP_OPTIONS.contains(&n) => (false, n.to_string()),
                        _ => (true, t),
                    };
                    let bit = OPTIONS.iter().position(|o| *o == name).map(|b| b as u32).or_else(|| NOP_OPTIONS.iter().position(|o| *o == name).map(|b| 32 + b as u32)).ok_or(Errno::EINVAL)?;
                    set_flag(&mut s, &a, bit, on)?;
                    Ok(cnt)
                }
                "set_event" => {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.expand();
                    // One whitespace-delimited token a write.
                    let skip = buf.iter().take_while(|b| b.is_ascii_whitespace()).count();
                    let len = buf[skip..].iter().take_while(|b| !b.is_ascii_whitespace()).count();
                    if len == 0 {
                        return Ok(cnt);
                    }
                    if len > 127 {
                        return Err(Errno::EINVAL);
                    }
                    let tok = String::from_utf8_lossy(&buf[skip..skip + len]).to_string();
                    let (on, spec) = match tok.strip_prefix('!') {
                        Some(r) => (false, r.to_string()),
                        None => (true, tok),
                    };
                    let events = match_events(&spec);
                    if events.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    set_enabled(&mut s, &a, &events, on)?;
                    Ok(((skip + len + 1).min(buf.len())) as u64)
                }
                "set_event_pid" | "set_event_notrace_pid" => {
                    let text = String::from_utf8_lossy(buf);
                    let mut pids = Vec::new();
                    for t in text.split_ascii_whitespace() {
                        let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                            u64::from_str_radix(h, 16)
                        } else if t.len() > 1 && t.starts_with('0') {
                            u64::from_str_radix(&t[1..], 8)
                        } else {
                            t.parse()
                        };
                        pids.push(v.map_err(|_| Errno::EINVAL)?);
                    }
                    let arr = s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?;
                    arr.expand();
                    let list = if *f == "set_event_pid" { &mut arr.pids } else { &mut arr.notrace_pids };
                    list.extend(pids);
                    Ok(cnt)
                }
                "saved_cmdlines_size" => {
                    let n = parse_u64(buf)?;
                    if n == 0 || n > 32768 {
                        return Err(Errno::EINVAL);
                    }
                    // A power-of-two run of pages holding the map and n slots.
                    let need = 131_096 + 20 * n;
                    let bytes = need.div_ceil(4096).next_power_of_two() * 4096;
                    s.cmdlines_size = (bytes - 131_096) / 20;
                    Ok(cnt)
                }
                "tracing_thresh" => {
                    s.thresh_us = parse_u64(buf)?;
                    Ok(cnt)
                }
                "dynamic_events" | "kprobe_events" | "uprobe_events" | "synthetic_events" => {
                    if buf.iter().all(|b| b.is_ascii_whitespace()) {
                        return Ok(cnt);
                    }
                    eprintln!("[gex] tracefs: {f}: defining events is not implemented -> EINVAL ({})", String::from_utf8_lossy(buf).trim());
                    Err(Errno::EINVAL)
                }
                _ => Err(Errno::EINVAL),
            },
            Node::Option(_, b) => {
                let v = parse_u64(buf)?;
                if v > 1 {
                    return Err(Errno::EINVAL);
                }
                set_flag(&mut s, &a, *b, v == 1)?;
                Ok(cnt)
            }
            Node::CpuFile(_, c, "buffer_size_kb") => {
                let kb = parse_u64(buf)?;
                if kb == 0 {
                    return Err(Errno::EINVAL);
                }
                s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.resize(kb, Some(*c as usize));
                Ok(cnt)
            }
            Node::CpuFile(_, _, "trace") => Ok(cnt),
            Node::EventsFile(_, "enable") | Node::SystemFile(_, _, "enable") | Node::EventFile(_, _, "enable") => {
                let events = match &self.node {
                    Node::SystemFile(_, sys, _) => scope(Some(sys)),
                    Node::EventFile(_, i, _) => vec![*i],
                    _ => scope(None),
                };
                s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?.expand();
                let v = parse_u64(buf)?;
                if v > 1 {
                    return Err(Errno::EINVAL);
                }
                set_enabled(&mut s, &a, &events, v == 1)?;
                Ok(cnt)
            }
            Node::SystemFile(_, _, "filter") | Node::EventFile(_, _, "filter" | "trigger") => {
                if buf.len() >= 4096 {
                    return Err(Errno::EINVAL);
                }
                let t = String::from_utf8_lossy(buf);
                let t = t.trim();
                if t.is_empty() || t == "0" {
                    return Ok(cnt);
                }
                eprintln!("[gex] tracefs: {}: filters and triggers are not implemented -> EINVAL ({t})", self.path);
                Err(Errno::EINVAL)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_keeps_position(&self) -> bool {
        true
    }

    fn is_stream(&self) -> bool {
        matches!(&self.node, Node::File(_, "trace_pipe" | "trace_marker" | "trace_marker_raw") | Node::CpuFile(_, _, "trace_pipe"))
    }

    /// The markers are `stream_open`ed, the pipes `nonseekable_open`ed.
    fn refuses_positioned_io(&self) -> bool {
        self.is_stream()
    }

    fn poll_readable(&self) -> bool {
        match &self.node {
            Node::File(_, "trace_pipe") | Node::CpuFile(_, _, "trace_pipe") => {
                let s = state();
                let Some(arr) = s.arrays.get(self.array()) else { return true };
                let cpu = if let Node::CpuFile(_, c, _) = self.node { Some(c) } else { None };
                arr.flag(7) || arr.buffer.iter().any(|e| cpu.is_none_or(|c| c == e.cpu)) || (self.read_any.load(std::sync::atomic::Ordering::Relaxed) && !arr.on)
            }
            _ => true,
        }
    }

    fn wait_queue(&self) -> u32 {
        queue().id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(queue().wakes())
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        let mut s = state();
        Ok(metadata_in(&mut s, &self.path, &self.node))
    }
}

/// The filesystem every tracefs mount is.
pub fn instance() -> Arc<TraceFs> {
    static FS: OnceLock<Arc<TraceFs>> = OnceLock::new();
    Arc::clone(FS.get_or_init(|| Arc::new(TraceFs)))
}

#[derive(Debug)]
pub struct TraceFs;

/// A mount's options (`tracefs_parse_param`, `tracefs_apply_options`):
/// `uid=`, `gid=` (every file's owner, what `chown` set cleared) and
/// `mode=` (the root's), anything else `EINVAL`. Every mount is a
/// remount of the one tree.
pub fn mount(options: &str) -> Result<(), Errno> {
    let (mut uid, mut gid, mut mode) = (None, None, None);
    for o in options.split(',').filter(|o| !o.is_empty()) {
        let (k, v) = o.split_once('=').ok_or(Errno::EINVAL)?;
        match k {
            "uid" => uid = Some(v.parse::<u32>().map_err(|_| Errno::EINVAL)?),
            "gid" => gid = Some(v.parse::<u32>().map_err(|_| Errno::EINVAL)?),
            "mode" => mode = Some(u32::from_str_radix(v, 8).map_err(|_| Errno::EINVAL)? & 0o7777),
            _ => return Err(Errno::EINVAL),
        }
    }
    let mut s = state();
    if let Some(m) = mode {
        s.root_mode = m;
    }
    if uid.is_some() || gid.is_some() {
        if let Some(u) = uid {
            s.root_owner.0 = u;
        }
        if let Some(g) = gid {
            s.root_owner.1 = g;
        }
        for a in s.attrs.values_mut() {
            if uid.is_some() {
                a.uid = None;
            }
            if gid.is_some() {
                a.gid = None;
            }
        }
        let owner = s.root_owner;
        for arr in s.arrays.values_mut() {
            arr.events_owner = owner;
        }
    }
    let mut shown = String::new();
    if let Some(u) = uid.filter(|&u| u != 0) {
        shown.push_str(&format!(",uid={u}"));
    }
    if let Some(g) = gid.filter(|&g| g != 0) {
        shown.push_str(&format!(",gid={g}"));
    }
    if let Some(m) = mode.filter(|&m| m != 0o700) {
        shown.push_str(&format!(",mode={m:o}"));
    }
    s.shown = shown;
    Ok(())
}

/// May the caller open `meta` so: root may anything; others by its mode.
fn may(meta: &Metadata, flags: u64) -> bool {
    let Some((uid, gid)) = super::Maker::current() else { return true };
    if uid == 0 {
        return true;
    }
    let (ouid, ogid) = meta.owner.unwrap_or((0, 0));
    let bits = if uid == ouid { meta.mode >> 6 } else if gid == ogid { meta.mode >> 3 } else { meta.mode } & 7;
    let acc = flags & crate::fs::oflags::ACCMODE;
    let read = acc != crate::fs::oflags::O_WRONLY;
    let write = acc != crate::fs::oflags::O_RDONLY;
    (!read || bits & 4 != 0) && (!write || bits & 2 != 0)
}

impl FileSystem for TraceFs {
    fn fs_type(&self) -> &'static str {
        "tracefs"
    }

    fn magic(&self) -> u64 {
        MAGIC
    }

    fn dev(&self) -> u64 {
        super::anon_dev(super::DevKey::Kind("tracefs"))
    }

    fn show_options(&self) -> String {
        state().shown.clone()
    }

    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        use crate::fs::oflags;
        let mut s = state();
        let node = match find_in(&s, path) {
            Ok(n) => n,
            Err(Errno::ENOENT) if flags & oflags::O_CREAT != 0 => {
                // Nothing is made here: a new name in a directory that is
                // there is `EACCES`.
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                return Err(if find_in(&s, dir).is_ok_and(|n| n.is_dir()) { Errno::EACCES } else { Errno::ENOENT });
            }
            Err(e) => return Err(e),
        };
        if flags & oflags::O_CREAT != 0 && flags & oflags::O_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        let meta = metadata_in(&mut s, path, &node);
        if !may(&meta, flags) {
            return Err(Errno::EACCES);
        }
        let write = super::writes(flags);
        if node.is_dir() {
            if write {
                return Err(Errno::EISDIR);
            }
            let mut entries = vec![DirEntry { name: ".".into(), file_type: FileType::Directory, ino: meta.ino }, DirEntry { name: "..".into(), file_type: FileType::Directory, ino: 1 }];
            for (name, dir) in entries_in(&s, &node) {
                let child = if key(path).is_empty() { name.clone() } else { format!("{}/{name}", key(path)) };
                let ino = find_in(&s, &child).map(|n| metadata_in(&mut s, &child, &n).ino).unwrap_or(0);
                entries.push(DirEntry { name, file_type: if dir { FileType::Directory } else { FileType::Regular }, ino });
            }
            return Ok(Arc::new(Dir { entries, meta }));
        }
        let a = node.array().unwrap_or("").to_string();
        let trunc = write && flags & oflags::O_TRUNC != 0;
        {
            let arr = s.arrays.get_mut(&a).ok_or(Errno::ENODEV)?;
            match &node {
                Node::CpuFile(_, _, "trace_pipe_raw") => {
                    eprintln!("[gex] tracefs: per_cpu/cpuN/trace_pipe_raw (the buffer's raw pages) is not implemented -> EOPNOTSUPP");
                    return Err(Errno::EOPNOTSUPP);
                }
                Node::File(_, "trace_pipe") => {
                    if arr.pipe_all || arr.pipe_cpus != 0 {
                        return Err(Errno::EBUSY);
                    }
                    arr.pipe_all = true;
                }
                Node::CpuFile(_, c, "trace_pipe") => {
                    if arr.pipe_all || arr.pipe_cpus & (1 << c) != 0 {
                        return Err(Errno::EBUSY);
                    }
                    arr.pipe_cpus |= 1 << c;
                }
                Node::File(_, "trace") if trunc => arr.clear(),
                Node::CpuFile(_, c, "trace") if trunc => {
                    let c = *c;
                    arr.buffer.retain(|e| e.cpu != c);
                    arr.used = arr.buffer.iter().map(|e| e.bytes()).sum();
                }
                Node::File(_, "set_event") if trunc => arr.enabled.clear(),
                Node::File(_, "set_event_pid") if trunc => arr.pids.clear(),
                Node::File(_, "set_event_notrace_pid") if trunc => arr.notrace_pids.clear(),
                _ => {}
            }
            // Every open of the array's files holds it, but the options'
            // and an event's format and id.
            let holds = !matches!(&node, Node::Option(..) | Node::EventFile(_, _, "format" | "id"));
            if holds {
                arr.refs += 1;
            }
            let hold = Hold(holds.then(|| a.clone()));
            return Ok(Arc::new(File {
                path: key(path),
                node,
                snapshot: Mutex::new(None),
                read_any: std::sync::atomic::AtomicBool::new(false),
                _hold: hold,
            }));
        }
    }

    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        let mut s = state();
        let node = find_in(&s, path)?;
        Ok(metadata_in(&mut s, path, &node))
    }

    /// Only `instances/` makes directories: a trace array of the name.
    fn mkdir(&self, path: &str, _mode: u32) -> Result<(), Errno> {
        let mut s = state();
        let k = key(path);
        let (dir, name) = k.rsplit_once('/').unwrap_or(("", &k));
        if find_in(&s, &k).is_ok() {
            return Err(Errno::EEXIST);
        }
        if dir != "instances" {
            find_in(&s, dir)?;
            return Err(Errno::EPERM);
        }
        // The new array starts from the top level's options, less those
        // an instance does not inherit; its events' owner is its
        // directory's.
        let top = s.arrays.get("").map_or(TOP_DEFAULT, |t| t.flags);
        let meta = metadata_in(&mut s, "instances", &Node::Instances);
        let owner = meta.owner.unwrap_or((0, 0));
        s.arrays.insert(name.to_string(), Array::new(top & !ZEROED, true, owner));
        Ok(())
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let mut s = state();
        let k = key(path);
        match find_in(&s, &k)? {
            Node::ArrayDir(name) => {
                let arr = s.arrays.get(&name).ok_or(Errno::ENODEV)?;
                if arr.refs > 0 || arr.pipe_all || arr.pipe_cpus != 0 {
                    return Err(Errno::EBUSY);
                }
                s.arrays.remove(&name);
                let prefix = format!("instances/{name}");
                s.attrs.retain(|p, _| p != &prefix && !p.starts_with(&format!("{prefix}/")));
                s.inodes.retain(|p, _| p != &prefix && !p.starts_with(&format!("{prefix}/")));
                Ok(())
            }
            n if n.is_dir() => Err(Errno::EPERM),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn unlink(&self, path: &str) -> Result<(), Errno> {
        if find(path)?.is_dir() {
            return Err(Errno::EISDIR);
        }
        Err(Errno::EPERM)
    }

    fn rename(&self, from: &str, _to: &str) -> Result<(), Errno> {
        find(from)?;
        Err(Errno::EPERM)
    }

    fn link(&self, _from: &str, _to: &str) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn symlink(&self, _target: &str, _path: &str) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn mknod(&self, _path: &str, _mode: u32, _rdev: u64) -> Result<(), Errno> {
        Err(Errno::EPERM)
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let mut s = state();
        let node = find_in(&s, path)?;
        if node == Node::Root {
            s.root_mode = mode & 0o7777;
            return Ok(());
        }
        s.attrs.entry(key(path)).or_default().mode = Some(mode & 0o7777);
        Ok(())
    }

    fn chown(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let mut s = state();
        let node = find_in(&s, path)?;
        if node == Node::Root {
            if let Some(u) = uid {
                s.root_owner.0 = u;
            }
            if let Some(g) = gid {
                s.root_owner.1 = g;
            }
            return Ok(());
        }
        let a = s.attrs.entry(key(path)).or_default();
        if uid.is_some() {
            a.uid = uid;
        }
        if gid.is_some() {
            a.gid = gid;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> Arc<TraceFs> {
        instance()
    }

    fn read_all(h: &Arc<dyn FileHandle>) -> String {
        let mut buf = vec![0u8; 1 << 16];
        let n = h.read_at(0, &mut buf).unwrap() as usize;
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    fn open(path: &str, flags: u64) -> Arc<dyn FileHandle> {
        fs().open(path, flags, 0).unwrap()
    }

    /// The top level's options at boot are the 30 lines Linux shows, and
    /// a new instance's leave out what an instance does not inherit.
    #[test]
    fn options_read_as_linux_lists_them() {
        let arr = Array::new(TOP_DEFAULT, false, (0, 0));
        let text = options_text(&arr);
        assert_eq!(text.lines().count(), 30);
        assert!(text.starts_with("print-parent\nnosym-offset\n"));
        assert!(text.contains("\ncopy_trace_marker\nnopause-on-trace\nhash-ptr\nnostacktrace\nnotest_nop_accept\nnotest_nop_refuse\n"));
        let inst = Array::new(TOP_DEFAULT & !ZEROED, true, (0, 0));
        assert!(options_text(&inst).contains("\nnotrace_printk_dest\nnocopy_trace_marker\n"));
        assert_eq!(option_files(false).len(), 27);
    }

    /// Buffer sizes as `buffer_size_kb` reads them: minimal at first, 1410
    /// once expanded, 7 for a kilobyte, `EINVAL` for none.
    #[test]
    fn buffer_sizes_round_as_the_ring_buffer() {
        let mut arr = Array::new(TOP_DEFAULT, false, (0, 0));
        assert_eq!(arr.size_text(), "7 (expanded: 1408)\n");
        arr.expand();
        assert_eq!(arr.size_text(), "1410\n");
        arr.resize(1, None);
        assert_eq!(arr.size_text(), "7\n");
        arr.resize(8, None);
        assert_eq!(arr.size_text(), "11\n");
        arr.resize(4096, None);
        assert_eq!(arr.size_text(), "4099\n");
    }

    /// A marker: the count taken, a newline added once, the cap, EBADF off.
    #[test]
    fn markers_record_as_tracing_mark_write() {
        let mut arr = Array::new(TOP_DEFAULT & !ZEROED, true, (0, 0));
        assert_eq!(write_marker(&mut arr, b"B|7|x", 7), Ok(5));
        assert_eq!(write_marker(&mut arr, b"E|7\n", 7), Ok(4));
        assert_eq!(write_marker(&mut arr, &[b'x'; 5000], 7), Ok(4054));
        let text = trace_text(&arr, None);
        assert!(text.contains("# entries-in-buffer/entries-written: 3/3   #P:"), "{text}");
        assert!(text.contains("           <...>-7       [000] ...1. "), "{text}");
        assert!(text.contains(": tracing_mark_write: B|7|x\n"));
        assert!(text.contains(": tracing_mark_write: E|7\n") && !text.contains("E|7\n\n"));
        arr.on = false;
        assert_eq!(write_marker(&mut arr, b"x", 7), Err(Errno::EBADF));
    }

    /// A full buffer drops its oldest with overwrite on, refuses with it off.
    #[test]
    fn a_full_buffer_overwrites_or_refuses() {
        let mut arr = Array::new(TOP_DEFAULT & !ZEROED, true, (0, 0));
        arr.resize(1, None);
        let cap = arr.capacity();
        let mut n = 0u64;
        while arr.used + 64 <= cap {
            write_marker(&mut arr, &[b'y'; 40], 1).unwrap();
            n += 1;
        }
        write_marker(&mut arr, &[b'y'; 40], 1).unwrap();
        assert!(arr.overrun > 0 && arr.buffer.len() as u64 <= n);
        arr.flags &= !(1 << O_OVERWRITE);
        while arr.used + 64 <= cap {
            write_marker(&mut arr, &[b'y'; 40], 1).unwrap();
        }
        assert_eq!(write_marker(&mut arr, &[b'y'; 40], 1), Err(Errno::EBADF));
    }

    /// The tree: an instance made and removed, its files, `EBUSY` while
    /// one is open, `set_event`, the formats' ids.
    #[test]
    fn an_instance_has_its_own_files() {
        let f = fs();
        f.mkdir("instances/unit", 0o700).unwrap();
        assert_eq!(f.mkdir("instances/unit", 0o700), Err(Errno::EEXIST));
        assert_eq!(f.mkdir("events/foo", 0o755), Err(Errno::EPERM));
        assert_eq!(f.metadata("instances/unit").unwrap().mode, 0o750);
        assert_eq!(f.metadata("instances/unit/trace_marker").unwrap().mode, 0o220);
        assert_eq!(f.metadata("instances/unit/README").err(), Some(Errno::ENOENT));
        assert_eq!(f.metadata("instances/unit/options/record-cmd").err(), Some(Errno::ENOENT));
        let on = open("instances/unit/tracing_on", crate::fs::oflags::O_RDONLY);
        assert_eq!(read_all(&on), "1\n");
        assert_eq!(f.rmdir("instances/unit"), Err(Errno::EBUSY));
        drop(on);
        let se = open("instances/unit/set_event", crate::fs::oflags::O_WRONLY);
        assert_eq!(se.write_at(0, b"nosuch"), Err(Errno::EINVAL));
        assert_eq!(se.write_at(0, b"power:\n"), Ok(7));
        drop(se);
        let se = open("instances/unit/set_event", crate::fs::oflags::O_RDONLY);
        assert_eq!(read_all(&se), "power:cpu_frequency\npower:cpu_idle\n");
        drop(se);
        assert_eq!(read_all(&open("instances/unit/events/power/enable", crate::fs::oflags::O_RDONLY)), "1\n");
        assert_eq!(read_all(&open("instances/unit/events/enable", crate::fs::oflags::O_RDONLY)), "X\n");
        assert_eq!(read_all(&open("instances/unit/events/ftrace/print/id", crate::fs::oflags::O_RDONLY)), "5\n");
        let fmt = read_all(&open("instances/unit/events/sched/sched_switch/format", crate::fs::oflags::O_RDONLY));
        assert!(fmt.starts_with(&format!("name: sched_switch\nID: {}\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n", event_id(2))), "{fmt}");
        assert!(fmt.contains("\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n"));
        f.rmdir("instances/unit").unwrap();
        assert_eq!(f.metadata("instances/unit").err(), Some(Errno::ENOENT));
    }
}
