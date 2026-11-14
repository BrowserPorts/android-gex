//! Binder: Android's inter-process call, as `/dev/binder` serves it.
//!
//! A process opens the device, maps a buffer of it, and talks to it with
//! one ioctl, `BINDER_WRITE_READ`: commands written (`BC_*`), returns read
//! (`BR_*`). A call names a *node* another process owns, by a *handle* the
//! caller holds on it; its bytes are copied into the target's mapped
//! buffer, the objects in them (nodes, handles, descriptors) made the
//! target's own, and a thread of the target reads it as `BR_TRANSACTION`.
//! Its reply goes back to the thread that waits for it.
//!
//! This follows the Android common kernel's driver (drivers/android/
//! binder.c at android17-6.18) in what a program can see: the protocol of
//! include/uapi/linux/android/binder.h, the order work is queued and
//! returned in, the reference counts a node's owner is told of, and what
//! is told when a process dies or is frozen. It is written for this
//! kernel, not ported: the driver's state is one table under one lock
//! ([`Driver`]), a thread that would sleep in the driver parks in the host
//! instead and makes its call again ([`Outcome::Wait`]), and a call's
//! bytes are held here until the target reads them, when they are written
//! into its memory by its own thread.
//!
//! The devices are binderfs's ([`crate::vfs::BinderFs`]): each mount has
//! its own, each device its own context manager.
//!
//! A node that asks for its callers' security contexts gets what the
//! kernel's security module says of them ([`Caller::secctx`]); with no
//! module, as now, a call to such a node fails as Linux's does.
//!
//! Not here: the reports of failed calls over netlink, a feature binderfs
//! here does not say it has. A node's scheduling priority is taken and has
//! no effect: there is no scheduler here to hand it to. The table lives in this process's memory, so a host
//! whose guest processes do not share it (the page's) has no binder yet.

use crate::errno::{Errno, SysResult};
use crate::file::{FdTable, OpenFile};
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// include/uapi/linux/android/binder.h, for a 64-bit program.
#[allow(dead_code)]
mod abi {
    pub const PROTOCOL_VERSION: i32 = 8;

    // ioctls ('b').
    pub const WRITE_READ: u64 = 0xc030_6201;
    pub const SET_IDLE_TIMEOUT: u64 = 0x4008_6203;
    pub const SET_MAX_THREADS: u64 = 0x4004_6205;
    pub const SET_IDLE_PRIORITY: u64 = 0x4004_6206;
    pub const SET_CONTEXT_MGR: u64 = 0x4004_6207;
    pub const THREAD_EXIT: u64 = 0x4004_6208;
    pub const VERSION: u64 = 0xc004_6209;
    pub const GET_NODE_DEBUG_INFO: u64 = 0xc018_620b;
    pub const GET_NODE_INFO_FOR_REF: u64 = 0xc018_620c;
    pub const SET_CONTEXT_MGR_EXT: u64 = 0x4018_620d;
    pub const FREEZE: u64 = 0x400c_620e;
    pub const GET_FROZEN_INFO: u64 = 0xc00c_620f;
    pub const ENABLE_ONEWAY_SPAM_DETECTION: u64 = 0x4004_6210;
    pub const GET_EXTENDED_ERROR: u64 = 0xc00c_6211;

    // Commands ('c').
    pub const BC_TRANSACTION: u32 = 0x4040_6300;
    pub const BC_REPLY: u32 = 0x4040_6301;
    pub const BC_FREE_BUFFER: u32 = 0x4008_6303;
    pub const BC_INCREFS: u32 = 0x4004_6304;
    pub const BC_ACQUIRE: u32 = 0x4004_6305;
    pub const BC_RELEASE: u32 = 0x4004_6306;
    pub const BC_DECREFS: u32 = 0x4004_6307;
    pub const BC_INCREFS_DONE: u32 = 0x4010_6308;
    pub const BC_ACQUIRE_DONE: u32 = 0x4010_6309;
    pub const BC_REGISTER_LOOPER: u32 = 0x0000_630b;
    pub const BC_ENTER_LOOPER: u32 = 0x0000_630c;
    pub const BC_EXIT_LOOPER: u32 = 0x0000_630d;
    pub const BC_REQUEST_DEATH_NOTIFICATION: u32 = 0x400c_630e;
    pub const BC_CLEAR_DEATH_NOTIFICATION: u32 = 0x400c_630f;
    pub const BC_DEAD_BINDER_DONE: u32 = 0x4008_6310;
    pub const BC_TRANSACTION_SG: u32 = 0x4048_6311;
    pub const BC_REPLY_SG: u32 = 0x4048_6312;
    pub const BC_REQUEST_FREEZE_NOTIFICATION: u32 = 0x400c_6313;
    pub const BC_CLEAR_FREEZE_NOTIFICATION: u32 = 0x400c_6314;
    pub const BC_FREEZE_NOTIFICATION_DONE: u32 = 0x4008_6315;

    // Returns ('r').
    pub const BR_OK: u32 = 0x0000_7201;
    pub const BR_TRANSACTION: u32 = 0x8040_7202;
    /// With a `binder_transaction_data_secctx`: the call, then where the
    /// sender's security context lies.
    pub const BR_TRANSACTION_SEC_CTX: u32 = 0x8048_7202;
    pub const BR_REPLY: u32 = 0x8040_7203;
    pub const BR_DEAD_REPLY: u32 = 0x0000_7205;
    pub const BR_TRANSACTION_COMPLETE: u32 = 0x0000_7206;
    pub const BR_INCREFS: u32 = 0x8010_7207;
    pub const BR_ACQUIRE: u32 = 0x8010_7208;
    pub const BR_RELEASE: u32 = 0x8010_7209;
    pub const BR_DECREFS: u32 = 0x8010_720a;
    pub const BR_NOOP: u32 = 0x0000_720c;
    pub const BR_SPAWN_LOOPER: u32 = 0x0000_720d;
    pub const BR_DEAD_BINDER: u32 = 0x8008_720f;
    pub const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8008_7210;
    pub const BR_FAILED_REPLY: u32 = 0x0000_7211;
    pub const BR_FROZEN_REPLY: u32 = 0x0000_7212;
    pub const BR_ONEWAY_SPAM_SUSPECT: u32 = 0x0000_7213;
    pub const BR_TRANSACTION_PENDING_FROZEN: u32 = 0x0000_7214;
    pub const BR_FROZEN_BINDER: u32 = 0x8010_7215;
    pub const BR_CLEAR_FREEZE_NOTIFICATION_DONE: u32 = 0x8008_7216;

    // Objects.
    pub const TYPE_BINDER: u32 = 0x7362_2a85;
    pub const TYPE_WEAK_BINDER: u32 = 0x7762_2a85;
    pub const TYPE_HANDLE: u32 = 0x7368_2a85;
    pub const TYPE_WEAK_HANDLE: u32 = 0x7768_2a85;
    pub const TYPE_FD: u32 = 0x6664_2a85;
    pub const TYPE_FDA: u32 = 0x6664_6185;
    pub const TYPE_PTR: u32 = 0x7074_2a85;
    /// `sizeof(struct flat_binder_object)`, and of `binder_fd_object`.
    pub const OBJECT_SIZE: usize = 24;
    /// `sizeof(struct binder_buffer_object)`: type, flags, buffer, length,
    /// parent, parent_offset.
    pub const PTR_SIZE: usize = 40;
    /// `sizeof(struct binder_fd_array_object)`: type, pad, num_fds, parent,
    /// parent_offset.
    pub const FDA_SIZE: usize = 32;
    pub const BUFFER_FLAG_HAS_PARENT: u32 = 0x01;

    pub const TF_ONE_WAY: u32 = 0x01;
    pub const TF_ACCEPT_FDS: u32 = 0x10;
    pub const TF_UPDATE_TXN: u32 = 0x40;
    pub const FLAT_BINDER_FLAG_ACCEPTS_FDS: u32 = 0x100;
    pub const FLAT_BINDER_FLAG_TXN_SECURITY_CTX: u32 = 0x1000;

    // A thread's looper state.
    pub const LOOPER_REGISTERED: u32 = 0x01;
    pub const LOOPER_ENTERED: u32 = 0x02;
    pub const LOOPER_EXITED: u32 = 0x04;
    pub const LOOPER_INVALID: u32 = 0x08;

    /// `sizeof(struct binder_transaction_data)`.
    pub const TR_SIZE: usize = 64;
}
use abi::*;

/// Who is making an ioctl.
pub struct Caller<'a> {
    pub pid: i32,
    pub tid: i32,
    pub euid: u32,
    /// Its descriptors: a descriptor in a call is read from the sender's
    /// table, and one that arrives is put in the receiver's.
    pub fds: &'a FdTable,
    /// The device was opened `O_NONBLOCK`.
    pub nonblock: bool,
    /// The clock a wait's time limit is measured on.
    pub clock: crate::syscalls::ClockFn,
    /// Its security context as the kernel's security module names it, the
    /// terminating NUL included (`security_secid_to_secctx`); `None` when
    /// there is no module to name one.
    pub secctx: Option<&'a [u8]>,
}

fn nanos(clock: crate::syscalls::ClockFn) -> u128 {
    let (secs, nanos) = clock();
    secs as u128 * 1_000_000_000 + nanos as u128
}

/// What an ioctl came to.
pub enum Outcome {
    Done(SysResult),
    /// A read with nothing to return: what it wrote is done and recorded
    /// in the caller's `binder_write_read`; the thread waits until the
    /// handle is readable, then makes the call again.
    Wait(Arc<dyn FileHandle>),
}

/// The driver: every device's processes under one lock (the kernel's
/// `binder_procs`; a process is frozen through any device, for its opens
/// of them all).
struct Driver {
    st: Mutex<State>,
    /// Notified whenever work is queued for anyone.
    queue: crate::wait::Queue,
}

fn driver() -> &'static Driver {
    static DRIVER: std::sync::OnceLock<Driver> = std::sync::OnceLock::new();
    DRIVER.get_or_init(|| Driver { st: Mutex::new(State::default()), queue: crate::wait::Queue::new() })
}

fn lock() -> std::sync::MutexGuard<'static, State> {
    driver().st.lock().unwrap_or_else(|e| e.into_inner())
}

/// One binder device (`struct binder_context`): a name, and a context
/// manager of its own.
pub struct Context {
    name: String,
    id: u64,
}

impl Context {
    pub fn new(name: &str) -> Arc<Context> {
        let mut st = lock();
        let id = st.id();
        st.ctxs.insert(id, Ctx::default());
        Arc::new(Context { name: name.to_string(), id })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        lock().ctxs.remove(&self.id);
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder context {}", self.name)
    }
}

/// A device's context manager: its node, and the euid that may be one.
#[derive(Default)]
struct Ctx {
    mgr: Option<u64>,
    mgr_uid: Option<u32>,
}

#[derive(Default)]
struct State {
    procs: HashMap<u64, Proc>,
    nodes: HashMap<u64, Node>,
    txns: HashMap<u64, Txn>,
    ctxs: HashMap<u64, Ctx>,
    freezes: HashMap<u64, Freeze>,
    next_id: u64,
}

#[derive(Default)]
struct Proc {
    /// Its device.
    ctx: u64,
    pid: i32,
    euid: u32,
    /// Its security context, as its first use of the device found it.
    secctx: Option<Vec<u8>>,
    dead: bool,
    /// `BINDER_FREEZE`: no call reaches it, and what arrived since.
    is_frozen: bool,
    sync_recv: bool,
    async_recv: bool,
    /// Calls and replies queued for it or in its threads' hands
    /// (`outstanding_txns`).
    outstanding: i64,
    spam_detection: bool,
    /// One sender has been named for filling the one-way space, and it has
    /// not come free since (`oneway_spam_detected`).
    spam_detected: bool,
    threads: HashMap<i32, Thread>,
    todo: VecDeque<Work>,
    /// Threads waiting for the process's work, first to wait first.
    waiting: VecDeque<i32>,
    refs: BTreeMap<u32, Ref>,
    ref_of_node: HashMap<u64, u32>,
    node_of_ptr: HashMap<u64, u64>,
    /// Its mapping of the device, and what is allocated of it.
    map: Option<(u64, u64)>,
    buffers: BTreeMap<u64, Buffer>,
    free_async: u64,
    max_threads: u32,
    requested_threads: u32,
    requested_threads_started: u32,
    /// Deaths told and not yet answered with `BC_DEAD_BINDER_DONE`.
    delivered_death: Vec<Death>,
    /// Freezes told and not yet answered with `BC_FREEZE_NOTIFICATION_DONE`.
    delivered_freeze: Vec<u64>,
}

struct Thread {
    todo: VecDeque<Work>,
    /// Work in `todo` that the thread is to return to its program for (a
    /// deferred item, such as a waiting call's completion, is not).
    process_todo: bool,
    looper: u32,
    /// Its first ioctl returns without waiting.
    need_return: bool,
    /// The call it is in: one it made and waits on, or one it is serving.
    stack: Option<u64>,
    /// `binder_extended_error`: id, command, param.
    ee: (u32, u32, i32),
    /// A `BINDER_FREEZE` of its that waits for a process's calls to drain:
    /// the process, and when the wait is over.
    freezing: Option<(u64, u128)>,
}

impl Default for Thread {
    fn default() -> Thread {
        Thread { todo: VecDeque::new(), process_todo: false, looper: 0, need_return: true, stack: None, ee: (0, BR_OK, 0), freezing: None }
    }
}

/// A request to hear of a node's process being frozen and thawed
/// (`struct binder_ref_freeze`).
struct Freeze {
    /// The process that asked.
    proc: u64,
    cookie: u64,
    is_frozen: bool,
    /// Told and not yet answered.
    sent: bool,
    /// To be queued again when the answer comes.
    resend: bool,
    /// Taken back: its work is now the telling of that
    /// (`BINDER_WORK_CLEAR_FREEZE_NOTIFICATION`).
    clear: bool,
    /// On a list: queued to be read, or told and unanswered.
    listed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Death {
    id: u64,
    cookie: u64,
    /// `BINDER_WORK_DEAD_BINDER_AND_CLEAR`: cleared while its telling was
    /// queued or unanswered.
    clear: bool,
}

#[derive(Debug)]
enum Work {
    Txn(u64),
    Complete,
    /// A one-way call's completion when its target is frozen
    /// (`BINDER_WORK_TRANSACTION_PENDING`).
    Pending,
    /// A one-way call's completion when its sender is filling the
    /// target's one-way space.
    SpamSuspect,
    Freeze(u64),
    /// A return code alone (`return_error`, `reply_error`).
    Error(u32),
    Node(u64),
    DeadBinder(Death),
    ClearDeathDone(u64),
}

struct Node {
    /// Its process; `None` once that has died.
    owner: Option<u64>,
    ptr: u64,
    cookie: u64,
    accept_fds: bool,
    /// Its calls carry their senders' security contexts
    /// (`FLAT_BINDER_FLAG_TXN_SECURITY_CTX`).
    sec_ctx: bool,
    internal_strong: u32,
    local_strong: u32,
    local_weak: u32,
    has_strong: bool,
    pending_strong: bool,
    has_weak: bool,
    pending_weak: bool,
    has_async: bool,
    async_todo: VecDeque<Work>,
    /// The references to it: process and handle.
    refs: Vec<(u64, u32)>,
    /// Its work is on a list (`!list_empty(&node->work.entry)`).
    queued: bool,
}

struct Ref {
    node: u64,
    strong: u32,
    weak: u32,
    death: Option<Death>,
    freeze: Option<u64>,
}

/// A range of a process's mapping.
#[derive(Default)]
struct Buffer {
    size: u64,
    free: bool,
    /// Who sent what it holds.
    pid: i32,
    spam_suspect: bool,
    allow_user_free: bool,
    /// The call whose bytes it holds, until that is done with.
    txn: Option<u64>,
    target_node: Option<u64>,
    is_async: bool,
    /// The objects in it, as the receiver has them: what freeing it lets go.
    objects: Vec<Object>,
}

impl Buffer {
    fn free(size: u64) -> Buffer {
        Buffer { size, free: true, ..Buffer::default() }
    }
}

#[derive(Clone, Copy)]
enum Object {
    /// A node of the receiver's: pointer, and whether strong.
    Binder(u64, bool),
    Handle(u32, bool),
    /// A descriptor of the receiver's that came in an array: closed when
    /// the buffer is given back.
    ArrayFd(i32),
}

struct Txn {
    /// The thread that waits for its reply.
    from: Option<(u64, i32)>,
    from_parent: Option<u64>,
    to_proc: Option<u64>,
    to_thread: Option<i32>,
    to_parent: Option<u64>,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: u32,
    is_reply: bool,
    /// Where the sender's security context lies in the target's mapping,
    /// for a node that asked for it.
    security_ctx: Option<u64>,
    /// Counted in its target's `outstanding`.
    counted: bool,
    /// Where its bytes go in the target's mapping.
    buffer: Option<u64>,
    target_node: Option<u64>,
    /// The bytes, until the target reads the call: data padded to eight,
    /// then the offsets.
    bytes: Vec<u8>,
    data_size: u64,
    offsets_size: u64,
    /// Descriptors to put in the receiver's table: where each number goes
    /// in `bytes`, the open file, and whether it came in an array.
    fds: Vec<(usize, Arc<OpenFile>, bool)>,
}

/// Where a call's scatter-gather buffers go, and what may be fixed up next
/// (`sg_buf_offset`, `last_fixup_obj_off`, `last_fixup_min_off`).
struct Sg {
    /// The buffer's address in the target, and where its data, its
    /// offsets and its extra buffers begin and end.
    base: u64,
    data_size: u64,
    offsets: usize,
    count: usize,
    at: u64,
    end: u64,
    /// The buffer object last fixed up in (0: none yet), and the least
    /// offset in it the next fix-up may have.
    last_obj: u64,
    last_min: u64,
    /// Each buffer object's address in the sender, by its offset.
    sender: HashMap<u64, u64>,
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

/// The size of the object at `at` in a call's data, if a whole one of a
/// known type is there (`binder_get_object`).
fn object_size(bytes: &[u8], data_size: u64, at: u64) -> Option<usize> {
    if at % 4 != 0 || at.checked_add(4).is_none_or(|end| end > data_size) {
        return None;
    }
    let size = match u32_at(bytes, at as usize) {
        TYPE_BINDER | TYPE_WEAK_BINDER | TYPE_HANDLE | TYPE_WEAK_HANDLE | TYPE_FD => OBJECT_SIZE,
        TYPE_PTR => PTR_SIZE,
        TYPE_FDA => FDA_SIZE,
        _ => return None,
    };
    (at + size as u64 <= data_size).then_some(size)
}

impl Sg {
    /// The buffer object the `index`th offset names, among the `valid`
    /// ones already translated: its offset, its address in the target and
    /// its length (`binder_validate_ptr`).
    fn parent(&self, bytes: &[u8], index: u64, valid: usize) -> Option<(u64, u64, u64)> {
        if index >= valid as u64 {
            return None;
        }
        let at = u64_at(bytes, self.offsets + index as usize * 8);
        let size = object_size(bytes, self.data_size, at)?;
        let a = at as usize;
        (size == PTR_SIZE && u32_at(bytes, a) == TYPE_PTR).then(|| (at, u64_at(bytes, a + 8), u64_at(bytes, a + 16)))
    }

    /// Whether a fix-up at `offset` in the buffer object at `obj` is in
    /// order: fix-ups go by rising offset, in the object last fixed up in
    /// or one of its parents (`binder_validate_fixup`).
    fn may_fix(&self, bytes: &[u8], obj: u64, offset: u64) -> bool {
        let (mut last, mut min) = (self.last_obj, self.last_min);
        if last == 0 {
            return false;
        }
        while last != obj {
            if object_size(bytes, self.data_size, last) != Some(PTR_SIZE) {
                return false;
            }
            let a = last as usize;
            if u32_at(bytes, a + 4) & BUFFER_FLAG_HAS_PARENT == 0 {
                return false;
            }
            min = u64_at(bytes, a + 32).wrapping_add(8);
            let parent = u64_at(bytes, a + 24);
            if parent >= self.count as u64 {
                return false;
            }
            last = u64_at(bytes, self.offsets + parent as usize * 8);
        }
        offset >= min
    }
}

/// A `binder_transaction_data` as a command carries it.
#[derive(Clone, Copy)]
struct TrData {
    target: u64,
    code: u32,
    flags: u32,
    data_size: u64,
    offsets_size: u64,
    buffer: u64,
    offsets: u64,
}

/// A call that cannot be made: the return its sender reads, and the errno
/// its extended error names.
struct Fail(u32, Errno);

/// A protocol error: a reply with no call, a call out of turn.
const EPROTO: Errno = Errno(71);

fn align8(n: u64) -> u64 {
    (n + 7) & !7
}

/// Say once per kind that a program asked for something not done here.
fn unimplemented(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] binder: {what} is not implemented");
        said.push(what.to_string());
    }
}

impl State {
    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// The context manager's node on `proc`'s device.
    fn mgr_of(&self, proc: u64) -> Option<u64> {
        self.procs.get(&proc).and_then(|p| self.ctxs.get(&p.ctx)).and_then(|c| c.mgr)
    }

    fn is_mgr(&self, node: u64) -> bool {
        self.ctxs.values().any(|c| c.mgr == Some(node))
    }

    /// A call is queued for `proc` (`outstanding_txns`).
    fn count(&mut self, txn: u64, proc: u64) {
        if let (Some(t), Some(p)) = (self.txns.get_mut(&txn), self.procs.get_mut(&proc)) {
            t.counted = true;
            p.outstanding += 1;
        }
    }

    fn thread(&mut self, proc: u64, tid: i32) -> &mut Thread {
        self.procs.get_mut(&proc).expect("a binder process").threads.entry(tid).or_default()
    }

    /// `binder_enqueue_thread_work`: work the thread returns for.
    fn to_thread(&mut self, proc: u64, tid: i32, w: Work) {
        let t = self.thread(proc, tid);
        t.todo.push_back(w);
        t.process_todo = true;
    }

    /// The thread's work if it loops for the process, else the process's
    /// (how a death or its clearing is queued).
    fn to_looper_or_proc(&mut self, proc: u64, tid: i32, w: Work) {
        if self.thread(proc, tid).looper & (LOOPER_REGISTERED | LOOPER_ENTERED) != 0 {
            self.to_thread(proc, tid, w);
        } else if let Some(p) = self.procs.get_mut(&proc) {
            p.todo.push_back(w);
        }
    }

    // -- nodes and references (binder_inc_node_nilocked and friends) --------

    fn new_node(&mut self, proc: u64, ptr: u64, cookie: u64, flags: u32) -> u64 {
        let id = self.id();
        self.nodes.insert(
            id,
            Node {
                owner: Some(proc),
                ptr,
                cookie,
                accept_fds: flags & FLAT_BINDER_FLAG_ACCEPTS_FDS != 0,
                sec_ctx: flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX != 0,
                internal_strong: 0,
                local_strong: 0,
                local_weak: 0,
                has_strong: false,
                pending_strong: false,
                has_weak: false,
                pending_weak: false,
                has_async: false,
                async_todo: VecDeque::new(),
                refs: Vec::new(),
                queued: false,
            },
        );
        self.procs.get_mut(&proc).expect("a binder process").node_of_ptr.insert(ptr, id);
        id
    }

    /// Take a node's work off whichever list it is on.
    fn dequeue_node_work(&mut self, node: u64) {
        let Some(owner) = self.nodes.get(&node).and_then(|n| n.owner) else { return };
        if let Some(p) = self.procs.get_mut(&owner) {
            p.todo.retain(|w| !matches!(w, Work::Node(n) if *n == node));
            for t in p.threads.values_mut() {
                t.todo.retain(|w| !matches!(w, Work::Node(n) if *n == node));
            }
        }
        if let Some(n) = self.nodes.get_mut(&node) {
            n.queued = false;
        }
    }

    /// `binder_inc_node_nilocked`. `target` is the thread whose list the
    /// node's work may be put on (the sender's, while a call is made).
    fn inc_node(&mut self, node: u64, strong: bool, internal: bool, target: Option<(u64, i32)>) -> Result<(), Errno> {
        let is_mgr = self.is_mgr(node);
        let n = self.nodes.get_mut(&node).ok_or(Errno::EINVAL)?;
        if strong {
            if internal {
                if target.is_none() && n.internal_strong == 0 && !(is_mgr && n.has_strong) {
                    return Err(Errno::EINVAL);
                }
                n.internal_strong += 1;
            } else {
                n.local_strong += 1;
            }
            if !n.has_strong {
                if let Some((proc, tid)) = target {
                    self.dequeue_node_work(node);
                    // Deferred: the thread does not return for it alone.
                    self.thread(proc, tid).todo.push_back(Work::Node(node));
                    self.nodes.get_mut(&node).expect("the node").queued = true;
                }
            }
        } else {
            if !internal {
                n.local_weak += 1;
            }
            if !n.has_weak && !n.queued {
                let (proc, tid) = target.ok_or(Errno::EINVAL)?;
                n.queued = true;
                self.thread(proc, tid).todo.push_back(Work::Node(node));
            }
        }
        Ok(())
    }

    /// `binder_dec_node_nilocked`; the node goes when nothing holds it.
    fn dec_node(&mut self, node: u64, strong: bool, internal: bool) {
        let Some(n) = self.nodes.get_mut(&node) else { return };
        if strong {
            if internal {
                n.internal_strong = n.internal_strong.saturating_sub(1);
            } else {
                n.local_strong = n.local_strong.saturating_sub(1);
            }
            if n.local_strong != 0 || n.internal_strong != 0 {
                return;
            }
        } else {
            if !internal {
                n.local_weak = n.local_weak.saturating_sub(1);
            }
            if n.local_weak != 0 || !n.refs.is_empty() {
                return;
            }
        }
        match n.owner {
            Some(owner) if n.has_strong || n.has_weak => {
                if !n.queued {
                    n.queued = true;
                    if let Some(p) = self.procs.get_mut(&owner) {
                        p.todo.push_back(Work::Node(node));
                    }
                }
            }
            _ => {
                if n.refs.is_empty() && n.local_strong == 0 && n.local_weak == 0 {
                    self.free_node(node);
                }
            }
        }
    }

    fn free_node(&mut self, node: u64) {
        self.dequeue_node_work(node);
        if let Some(n) = self.nodes.remove(&node) {
            if let Some(p) = n.owner.and_then(|o| self.procs.get_mut(&o)) {
                if p.node_of_ptr.get(&n.ptr) == Some(&node) {
                    p.node_of_ptr.remove(&n.ptr);
                }
            }
        }
    }

    /// The process's handle on `node`, made if it has none
    /// (`binder_get_ref_for_node_olocked`): the lowest number free, from 1,
    /// or 0 for the context manager's node.
    fn ref_for_node(&mut self, proc: u64, node: u64) -> u32 {
        let is_mgr = self.is_mgr(node);
        let p = self.procs.get_mut(&proc).expect("a binder process");
        if let Some(&h) = p.ref_of_node.get(&node) {
            return h;
        }
        let mut h = if is_mgr { 0 } else { 1 };
        for &used in p.refs.keys() {
            if used > h {
                break;
            }
            if used == h {
                h += 1;
            }
        }
        p.refs.insert(h, Ref { node, strong: 0, weak: 0, death: None, freeze: None });
        p.ref_of_node.insert(node, h);
        if let Some(n) = self.nodes.get_mut(&node) {
            n.refs.push((proc, h));
        }
        h
    }

    /// `binder_inc_ref_olocked`.
    fn inc_ref(&mut self, proc: u64, handle: u32, strong: bool, target: Option<(u64, i32)>) -> Result<(), Errno> {
        let (node, first) = {
            let r = self.procs.get(&proc).and_then(|p| p.refs.get(&handle)).ok_or(Errno::EINVAL)?;
            (r.node, if strong { r.strong == 0 } else { r.weak == 0 })
        };
        if first {
            self.inc_node(node, strong, true, target)?;
        }
        let r = self.procs.get_mut(&proc).and_then(|p| p.refs.get_mut(&handle)).ok_or(Errno::EINVAL)?;
        if strong {
            r.strong += 1;
        } else {
            r.weak += 1;
        }
        Ok(())
    }

    /// `binder_dec_ref_olocked`: the reference goes with its last count.
    fn dec_ref(&mut self, proc: u64, handle: u32, strong: bool) -> Result<(), Errno> {
        let r = self.procs.get_mut(&proc).and_then(|p| p.refs.get_mut(&handle)).ok_or(Errno::EINVAL)?;
        let node = r.node;
        if strong {
            if r.strong == 0 {
                return Err(Errno::EINVAL);
            }
            r.strong -= 1;
            if r.strong == 0 {
                self.dec_node(node, true, true);
            }
        } else {
            if r.weak == 0 {
                return Err(Errno::EINVAL);
            }
            r.weak -= 1;
        }
        let gone = self.procs.get(&proc).and_then(|p| p.refs.get(&handle)).is_some_and(|r| r.strong == 0 && r.weak == 0);
        if gone {
            self.cleanup_ref(proc, handle);
        }
        Ok(())
    }

    /// `binder_cleanup_ref_olocked`.
    fn cleanup_ref(&mut self, proc: u64, handle: u32) {
        let Some(p) = self.procs.get_mut(&proc) else { return };
        let Some(r) = p.refs.remove(&handle) else { return };
        p.ref_of_node.remove(&r.node);
        if let Some(d) = r.death {
            // Its telling, if queued, is not made.
            p.todo.retain(|w| !matches!(w, Work::DeadBinder(x) if x.id == d.id));
            for t in p.threads.values_mut() {
                t.todo.retain(|w| !matches!(w, Work::DeadBinder(x) if x.id == d.id));
            }
        }
        if let Some(f) = r.freeze {
            p.todo.retain(|w| !matches!(w, Work::Freeze(x) if *x == f));
            p.delivered_freeze.retain(|&x| x != f);
            self.freezes.remove(&f);
        }
        if r.strong > 0 {
            self.dec_node(r.node, true, true);
        }
        if let Some(n) = self.nodes.get_mut(&r.node) {
            n.refs.retain(|&x| x != (proc, handle));
        }
        self.dec_node(r.node, false, true);
    }

    // -- the buffer a process mapped (binder_alloc) --------------------------

    /// A range of `proc`'s mapping for a call of `size` bytes: the smallest
    /// free one that holds it.
    fn alloc(&mut self, proc: u64, size: u64, is_async: bool, sender: i32) -> Result<u64, Fail> {
        let p = self.procs.get_mut(&proc).ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
        if p.map.is_none() {
            return Err(Fail(BR_DEAD_REPLY, Errno::ESRCH));
        }
        // No two buffers share an address.
        let size = align8(size).max(8);
        if is_async && p.free_async < size {
            return Err(Fail(BR_FAILED_REPLY, Errno::ENOSPC));
        }
        let best = p.buffers.iter().filter(|(_, b)| b.free && b.size >= size).min_by_key(|(_, b)| b.size).map(|(&at, b)| (at, b.size));
        let (at, have) = best.ok_or(Fail(BR_FAILED_REPLY, Errno::ENOSPC))?;
        if have > size {
            p.buffers.insert(at + size, Buffer::free(have - size));
        }
        p.buffers.insert(at, Buffer { size, is_async, pid: sender, ..Buffer::default() });
        if is_async {
            p.free_async -= size;
            // With less than a fifth of the one-way space left, a sender
            // that holds more than fifty buffers or half of it is named,
            // once (`debug_low_async_space_locked`).
            let whole = p.map.map_or(0, |(_, len)| len);
            if p.free_async >= whole / 10 {
                p.spam_detected = false;
            } else {
                let mine = p.buffers.values().filter(|b| !b.free && b.is_async && b.pid == sender);
                let (count, total) = mine.fold((0u64, 0u64), |(n, sum), b| (n + 1, sum + b.size));
                if (count > 50 || total > whole / 4) && !p.spam_detected {
                    p.spam_detected = true;
                    p.buffers.get_mut(&at).expect("the buffer").spam_suspect = true;
                }
            }
        }
        Ok(at)
    }

    /// Give a range back, joined to the free ranges beside it.
    fn release(&mut self, proc: u64, at: u64) {
        let Some(p) = self.procs.get_mut(&proc) else { return };
        let Some(b) = p.buffers.get_mut(&at) else { return };
        if b.is_async {
            p.free_async += b.size;
        }
        *b = Buffer::free(b.size);
        let mut start = at;
        if let Some((&before, prev)) = p.buffers.range(..at).next_back() {
            if prev.free && before + prev.size == at {
                start = before;
            }
        }
        let mut size = p.buffers.remove(&at).map_or(0, |b| b.size);
        if start != at {
            size += p.buffers.remove(&start).map_or(0, |b| b.size);
        }
        if let Some(next) = p.buffers.get(&(start + size)).filter(|n| n.free).map(|n| n.size) {
            p.buffers.remove(&(start + size));
            size += next;
        }
        p.buffers.insert(start, Buffer::free(size));
    }

    /// `binder_free_buf`: the buffer's call is done with, the next one-way
    /// call to its node may go, and what its objects held is let go.
    fn free_buffer(&mut self, proc: u64, at: u64) {
        let Some(b) = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&at)) else { return };
        let (txn, node, is_async, objects) = (b.txn.take(), b.target_node, b.is_async, std::mem::take(&mut b.objects));
        if let Some(t) = txn.and_then(|t| self.txns.get_mut(&t)) {
            t.buffer = None;
        }
        if let (true, Some(node)) = (is_async, node) {
            let next = self.nodes.get_mut(&node).and_then(|n| {
                let w = n.async_todo.pop_front();
                if w.is_none() {
                    n.has_async = false;
                }
                w
            });
            if let (Some(w), Some(p)) = (next, self.procs.get_mut(&proc)) {
                p.todo.push_back(w);
            }
        }
        self.release_objects(proc, &objects);
        self.release(proc, at);
    }

    /// `binder_transaction_buffer_release`, for objects as the receiver
    /// has them.
    fn release_objects(&mut self, proc: u64, objects: &[Object]) {
        for o in objects {
            match *o {
                Object::Binder(ptr, strong) => {
                    if let Some(&node) = self.procs.get(&proc).and_then(|p| p.node_of_ptr.get(&ptr)) {
                        self.dec_node(node, strong, false);
                    }
                }
                Object::Handle(h, strong) => {
                    let _ = self.dec_ref(proc, h, strong);
                }
                // The receiver's to close, when it frees the buffer.
                Object::ArrayFd(_) => {}
            }
        }
    }

    // -- calls (binder_transaction) ------------------------------------------

    /// A thread of `proc` waiting for the process's work, taken off the
    /// list (`binder_select_thread_ilocked`).
    fn select_thread(&mut self, proc: u64) -> Option<i32> {
        self.procs.get_mut(&proc)?.waiting.pop_front()
    }

    /// `binder_proc_transaction`: the call to a thread that waits, else to
    /// the process's work, else (a one-way call behind another to the same
    /// node) to the node's own. A frozen process takes no call that waits
    /// for a reply; a one-way call is kept for it, and `true` says so.
    fn proc_transaction(&mut self, txn: u64, proc: u64, thread: Option<i32>) -> Result<bool, Fail> {
        let (node, flags) = {
            let t = &self.txns[&txn];
            (t.target_node, t.flags)
        };
        let oneway = flags & TF_ONE_WAY != 0;
        let mut pending_async = false;
        if oneway {
            if let Some(n) = node.and_then(|n| self.nodes.get_mut(&n)) {
                if n.has_async {
                    pending_async = true;
                } else {
                    n.has_async = true;
                }
            }
        }
        let mut frozen = false;
        if let Some(p) = self.procs.get_mut(&proc).filter(|p| p.is_frozen) {
            frozen = true;
            p.sync_recv |= !oneway;
            p.async_recv |= oneway;
        }
        let dead = self.procs.get(&proc).is_none_or(|p| p.dead || thread.is_some_and(|t| !p.threads.contains_key(&t)));
        if (frozen && !oneway) || dead {
            return Err(Fail(if frozen { BR_FROZEN_REPLY } else { BR_DEAD_REPLY }, Errno(0)));
        }
        let thread = match thread {
            None if !pending_async => self.select_thread(proc),
            t => t,
        };
        match thread {
            Some(tid) => self.to_thread(proc, tid, Work::Txn(txn)),
            None if !pending_async => self.procs.get_mut(&proc).expect("the target").todo.push_back(Work::Txn(txn)),
            None => {
                if frozen && flags & TF_UPDATE_TXN != 0 {
                    self.supersede(txn, proc);
                }
                if let Some(n) = node.and_then(|n| self.nodes.get_mut(&n)) {
                    n.async_todo.push_back(Work::Txn(txn));
                }
            }
        }
        self.count(txn, proc);
        Ok(oneway && frozen)
    }

    /// `TF_UPDATE_TXN`: a one-way call to a frozen process takes the place
    /// of one from the same sender, to the same node, with the same code
    /// and flags, that still waits behind it
    /// (`binder_find_outdated_transaction_ilocked`).
    fn supersede(&mut self, new: u64, proc: u64) {
        let (node, code, flags, pid) = {
            let t = &self.txns[&new];
            (t.target_node, t.code, t.flags, t.sender_pid)
        };
        let Some(n) = node.and_then(|n| self.nodes.get_mut(&n)) else { return };
        let txns = &self.txns;
        let same = |w: &Work| match w {
            Work::Txn(id) => txns.get(id).is_some_and(|o| o.to_proc == Some(proc) && o.code == code && o.flags == flags && o.sender_pid == pid),
            _ => false,
        };
        let Some(i) = n.async_todo.iter().position(same) else { return };
        let Some(Work::Txn(old)) = n.async_todo.remove(i) else { return };
        let buffer = self.txns.get(&old).and_then(|t| t.buffer);
        self.drop_txn(old);
        if let Some(at) = buffer {
            let objects = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&at)).map(|b| std::mem::take(&mut b.objects)).unwrap_or_default();
            self.release_objects(proc, &objects);
            self.release(proc, at);
        }
    }

    /// `binder_send_failed_reply`: the thread that waits on `txn` reads
    /// `code` in place of a reply; a call it was itself serving goes on
    /// waiting.
    fn send_failed_reply(&mut self, mut txn: u64, code: u32) {
        loop {
            let Some(t) = self.txns.get(&txn) else { return };
            let (from, parent) = (t.from, t.from_parent);
            if let Some((proc, tid)) = from {
                if self.procs.get(&proc).is_some_and(|p| p.threads.contains_key(&tid)) {
                    // binder_pop_transaction_ilocked
                    self.thread(proc, tid).stack = parent;
                    self.to_thread(proc, tid, Work::Error(code));
                    self.drop_txn(txn);
                    return;
                }
            }
            self.drop_txn(txn);
            match parent {
                Some(p) => txn = p,
                None => return,
            }
        }
    }

    /// A call is done with (`binder_free_transaction`).
    fn drop_txn(&mut self, txn: u64) {
        if let Some(t) = self.txns.remove(&txn) {
            if let (true, Some(p)) = (t.counted, t.to_proc.and_then(|p| self.procs.get_mut(&p))) {
                p.outstanding -= 1;
            }
            if let (Some(proc), Some(at)) = (t.to_proc, t.buffer) {
                if let Some(b) = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&at)) {
                    b.txn = None;
                }
            }
        }
    }

    /// One object of a call, made the target's (`binder_translate_binder`,
    /// `_handle`, `_fd`). `at` is where it lies in `bytes`.
    #[allow(clippy::too_many_arguments)]
    fn translate(
        &mut self,
        cx: &Caller<'_>,
        proc: u64,
        target: u64,
        m: &GuestMem<'_>,
        bytes: &mut [u8],
        at: usize,
        // How many objects before this one are translated.
        valid: usize,
        allows_fds: bool,
        sg: &mut Sg,
        objects: &mut Vec<Object>,
        fds: &mut Vec<(usize, Arc<OpenFile>, bool)>,
    ) -> Result<(), Fail> {
        let bad = |e| Fail(BR_FAILED_REPLY, e);
        let kind = u32_at(bytes, at);
        let put = |b: &mut [u8], kind: u32, value: u64, cookie: u64| {
            b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            b[at + 16..at + 24].copy_from_slice(&cookie.to_le_bytes());
        };
        match kind {
            TYPE_BINDER | TYPE_WEAK_BINDER => {
                let strong = kind == TYPE_BINDER;
                let (flags, ptr, cookie) = (u32_at(bytes, at + 4), u64_at(bytes, at + 8), u64_at(bytes, at + 16));
                let node = match self.procs[&proc].node_of_ptr.get(&ptr) {
                    Some(&n) => n,
                    None => self.new_node(proc, ptr, cookie, flags),
                };
                if self.nodes[&node].cookie != cookie {
                    return Err(bad(Errno::EINVAL));
                }
                let h = self.ref_for_node(target, node);
                self.inc_ref(target, h, strong, Some((proc, cx.tid))).map_err(bad)?;
                put(bytes, if strong { TYPE_HANDLE } else { TYPE_WEAK_HANDLE }, h as u64, 0);
                objects.push(Object::Handle(h, strong));
            }
            TYPE_HANDLE | TYPE_WEAK_HANDLE => {
                let strong = kind == TYPE_HANDLE;
                let h = u32_at(bytes, at + 8);
                let r = self.procs[&proc].refs.get(&h).ok_or(bad(Errno::EINVAL))?;
                if strong && r.strong == 0 {
                    return Err(bad(Errno::EINVAL));
                }
                let node = r.node;
                if self.nodes[&node].owner == Some(target) {
                    // The target's own node: its pointer and cookie again.
                    let (ptr, cookie) = (self.nodes[&node].ptr, self.nodes[&node].cookie);
                    self.inc_node(node, strong, false, None).map_err(bad)?;
                    put(bytes, if strong { TYPE_BINDER } else { TYPE_WEAK_BINDER }, ptr, cookie);
                    objects.push(Object::Binder(ptr, strong));
                } else {
                    let th = self.ref_for_node(target, node);
                    self.inc_ref(target, th, strong, None).map_err(bad)?;
                    put(bytes, kind, th as u64, 0);
                    objects.push(Object::Handle(th, strong));
                }
            }
            TYPE_FD => {
                if !allows_fds {
                    return Err(bad(Errno::EPERM));
                }
                let fd = u32_at(bytes, at + 8) as i32;
                let file = cx.fds.get(fd).map_err(|_| bad(Errno::EBADF))?;
                bytes[at + 8..at + 16].fill(0);
                fds.push((at + 8, file, false));
            }
            // A buffer of the sender's, carried in the call's extra space
            // (`BC_TRANSACTION_SG`): the object's pointer becomes the
            // target's, and so does the pointer to it in its parent
            // buffer, if it says it has one.
            TYPE_PTR => {
                let (flags, from, length) = (u32_at(bytes, at + 4), u64_at(bytes, at + 8), u64_at(bytes, at + 16));
                let (parent, parent_offset) = (u64_at(bytes, at + 24), u64_at(bytes, at + 32));
                if length > sg.end - sg.at {
                    return Err(bad(Errno::EINVAL));
                }
                // A buffer of no bytes is read from nowhere.
                if length != 0 {
                    let from_bytes = m.read(from, length as usize).map_err(|_| bad(Errno::EFAULT))?;
                    bytes[sg.at as usize..(sg.at + length) as usize].copy_from_slice(from_bytes);
                }
                let to = sg.base + sg.at;
                bytes[at + 8..at + 16].copy_from_slice(&to.to_le_bytes());
                sg.at += align8(length);
                if flags & BUFFER_FLAG_HAS_PARENT != 0 {
                    let (obj, start, len) = sg.parent(bytes, parent, valid).ok_or(bad(Errno::EINVAL))?;
                    if !sg.may_fix(bytes, obj, parent_offset) || len < 8 || parent_offset > len - 8 {
                        return Err(bad(Errno::EINVAL));
                    }
                    let fix = (start - sg.base + parent_offset) as usize;
                    bytes[fix..fix + 8].copy_from_slice(&to.to_le_bytes());
                }
                sg.sender.insert(at as u64, from);
                (sg.last_obj, sg.last_min) = (at as u64, 0);
            }
            // Descriptors in a buffer that went before: each becomes one
            // of the target's, where it lay.
            TYPE_FDA => {
                let (count, parent, parent_offset) = (u64_at(bytes, at + 8), u64_at(bytes, at + 16), u64_at(bytes, at + 24));
                let (obj, start, len) = sg.parent(bytes, parent, valid).ok_or(bad(Errno::EINVAL))?;
                if !sg.may_fix(bytes, obj, parent_offset) {
                    return Err(bad(Errno::EINVAL));
                }
                if count != 0 {
                    let size = count.checked_mul(4).ok_or(bad(Errno::EINVAL))?;
                    if size > len || parent_offset > len - size {
                        return Err(bad(Errno::EINVAL));
                    }
                    let to = start - sg.base + parent_offset;
                    let from = sg.sender.get(&obj).copied().ok_or(bad(Errno::EINVAL))?.wrapping_add(parent_offset);
                    if to % 4 != 0 || from % 4 != 0 {
                        return Err(bad(Errno::EINVAL));
                    }
                    for i in 0..count {
                        let fd = m.read_u32(from.wrapping_add(i * 4)).map_err(|_| bad(Errno::EINVAL))? as i32;
                        if !allows_fds {
                            return Err(bad(Errno::EPERM));
                        }
                        let file = cx.fds.get(fd).map_err(|_| bad(Errno::EBADF))?;
                        fds.push(((to + i * 4) as usize, file, true));
                    }
                }
                (sg.last_obj, sg.last_min) = (obj, parent_offset.wrapping_add(count.wrapping_mul(4)));
            }
            _ => return Err(bad(Errno::EINVAL)),
        }
        Ok(())
    }

    /// `binder_transaction`: a call (`BC_TRANSACTION`) or a reply to one.
    fn transaction(&mut self, cx: &Caller<'_>, m: &GuestMem<'_>, proc: u64, tr: TrData, reply: bool, extra: u64) {
        let tid = cx.tid;
        let in_reply_to = if reply { self.thread(proc, tid).stack } else { None };
        match self.transaction_inner(cx, m, proc, tr, reply, extra, in_reply_to) {
            Ok(()) => {}
            Err(Fail(code, errno)) => {
                let id = self.next_id as u32;
                self.thread(proc, tid).ee = (id, code, -errno.0);
                match in_reply_to {
                    // The replier is told its reply is done with; the one
                    // that waited for it reads the failure.
                    Some(t) => {
                        self.to_thread(proc, tid, Work::Error(BR_TRANSACTION_COMPLETE));
                        self.send_failed_reply(t, code);
                    }
                    None => self.to_thread(proc, tid, Work::Error(code)),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transaction_inner(&mut self, cx: &Caller<'_>, m: &GuestMem<'_>, proc: u64, tr: TrData, reply: bool, extra: u64, in_reply_to: Option<u64>) -> Result<(), Fail> {
        let tid = cx.tid;
        let failed = |e| Fail(BR_FAILED_REPLY, e);
        let oneway = tr.flags & TF_ONE_WAY != 0;
        let (target_proc, target_thread, target_node);
        if reply {
            let t = in_reply_to.ok_or(failed(EPROTO))?;
            let (to, from, parent) = {
                let x = self.txns.get(&t).ok_or(failed(EPROTO))?;
                ((x.to_proc, x.to_thread), x.from, x.to_parent)
            };
            if to != (Some(proc), Some(tid)) {
                return Err(failed(EPROTO));
            }
            self.thread(proc, tid).stack = parent;
            // The thread that waits, if it is still there and still on
            // this call.
            let (fp, ft) = from.ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
            let waits = self.procs.get(&fp).and_then(|p| p.threads.get(&ft)).ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
            if waits.stack != Some(t) {
                return Err(failed(EPROTO));
            }
            (target_proc, target_thread, target_node) = (fp, Some(ft), None);
        } else {
            let node = if tr.target as u32 != 0 {
                let r = self.procs[&proc].refs.get(&(tr.target as u32)).filter(|r| r.strong > 0).ok_or(failed(Errno::EINVAL))?;
                r.node
            } else {
                let n = self.mgr_of(proc).ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
                if self.nodes[&n].owner == Some(proc) {
                    return Err(failed(Errno::EINVAL));
                }
                n
            };
            let owner = self.nodes[&node].owner.ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
            let me = self.thread(proc, tid);
            if !oneway && matches!(me.todo.front(), Some(Work::Txn(_))) {
                // A new call while one waits on this thread's list.
                return Err(failed(EPROTO));
            }
            // A thread of the target that waits on a call this one is
            // serving takes the new call: it is called back.
            let mut back = None;
            if !oneway {
                let mut at = me.stack;
                if at.is_some_and(|t| self.txns.get(&t).is_some_and(|x| x.to_thread != Some(tid) || x.to_proc != Some(proc))) {
                    return Err(failed(EPROTO));
                }
                while let Some(x) = at.and_then(|t| self.txns.get(&t)) {
                    if let Some((fp, ft)) = x.from.filter(|f| f.0 == owner) {
                        back = Some((fp, ft).1);
                        break;
                    }
                    at = x.from_parent;
                }
            }
            (target_proc, target_thread, target_node) = (owner, back, Some(node));
        }

        // Room in the target's buffer, then the bytes and the offsets of
        // its objects, from the sender; the buffers its objects point to
        // follow them (`extra`).
        if tr.offsets_size % 8 != 0 || extra % 8 != 0 {
            return Err(failed(Errno::EINVAL));
        }
        // The sender's security context, for a node that asked for it, at
        // the end of the extra space. With no security module there is
        // none to give, and the call fails.
        let secctx = match target_node.filter(|n| self.nodes[n].sec_ctx) {
            Some(_) => Some(self.procs[&proc].secctx.clone().ok_or(failed(Errno(95)))?),
            None => None,
        };
        let ctx_len = secctx.as_ref().map_or(0, |c| align8(c.len() as u64));
        let data_len = align8(tr.data_size);
        let total = data_len.checked_add(tr.offsets_size).and_then(|n| n.checked_add(extra)).and_then(|n| n.checked_add(ctx_len)).ok_or(failed(Errno::EINVAL))?;
        let buffer = self.alloc(target_proc, total, !reply && oneway, cx.pid)?;
        let security_ctx = secctx.as_ref().map(|_| buffer + total - ctx_len);
        let allows_fds = match in_reply_to {
            Some(t) => self.txns[&t].flags & TF_ACCEPT_FDS != 0,
            None => target_node.is_some_and(|n| self.nodes[&n].accept_fds),
        };
        let (mut objects, mut fds) = (Vec::new(), Vec::new());
        let mut bytes = vec![0u8; total as usize];
        if let Some(c) = &secctx {
            bytes[(total - ctx_len) as usize..][..c.len()].copy_from_slice(c);
        }
        let filled: Result<(), Fail> = (|| {
            let fault = |_| failed(Errno::EFAULT);
            bytes[..tr.data_size as usize].copy_from_slice(m.read(tr.buffer, tr.data_size as usize).map_err(fault)?);
            bytes[data_len as usize..(data_len + tr.offsets_size) as usize].copy_from_slice(m.read(tr.offsets, tr.offsets_size as usize).map_err(fault)?);
            let count = (tr.offsets_size / 8) as usize;
            let mut sg = Sg {
                base: buffer,
                data_size: tr.data_size,
                offsets: data_len as usize,
                count,
                at: data_len + tr.offsets_size,
                end: total - ctx_len,
                last_obj: 0,
                last_min: 0,
                sender: HashMap::new(),
            };
            let mut least = 0u64;
            for i in 0..count {
                let at = u64_at(&bytes, data_len as usize + i * 8);
                // In order, whole, and inside the data.
                let size = object_size(&bytes, tr.data_size, at).filter(|_| at >= least).ok_or(failed(Errno::EINVAL))?;
                least = at + size as u64;
                self.translate(cx, proc, target_proc, m, &mut bytes, at as usize, i, allows_fds, &mut sg, &mut objects, &mut fds)?;
            }
            Ok(())
        })();
        if let Err(f) = filled {
            // What was made the target's is let go again.
            self.release_objects(target_proc, &objects);
            self.release(target_proc, buffer);
            return Err(f);
        }
        if let Some(b) = self.procs.get_mut(&target_proc).and_then(|p| p.buffers.get_mut(&buffer)) {
            b.target_node = target_node;
            b.objects = objects;
        }

        let id = self.id();
        let txn = Txn {
            from: (!reply && !oneway).then_some((proc, tid)),
            from_parent: None,
            to_proc: Some(target_proc),
            to_thread: target_thread,
            to_parent: None,
            code: tr.code,
            flags: tr.flags,
            sender_pid: cx.pid,
            sender_euid: self.procs[&proc].euid,
            is_reply: reply,
            security_ctx,
            counted: false,
            buffer: Some(buffer),
            target_node,
            bytes,
            data_size: tr.data_size,
            offsets_size: tr.offsets_size,
            fds,
        };
        self.txns.insert(id, txn);
        if let Some(b) = self.procs.get_mut(&target_proc).and_then(|p| p.buffers.get_mut(&buffer)) {
            b.txn = Some(id);
        }

        if reply {
            let t = in_reply_to.expect("a reply's call");
            self.to_thread(proc, tid, Work::Complete);
            let tt = target_thread.expect("the thread that waits");
            // binder_pop_transaction_ilocked: the waiter's call is over.
            let parent = self.txns[&t].from_parent;
            self.thread(target_proc, tt).stack = parent;
            self.to_thread(target_proc, tt, Work::Txn(id));
            self.count(id, target_proc);
            self.drop_txn(t);
        } else if !oneway {
            // The completion waits with the caller: it returns when the
            // reply does.
            let me = self.thread(proc, tid);
            me.todo.push_back(Work::Complete);
            let parent = me.stack;
            me.stack = Some(id);
            self.txns.get_mut(&id).expect("the call").from_parent = parent;
            if let Err(f) = self.proc_transaction(id, target_proc, target_thread) {
                // This call's completion comes off again, and no other's.
                let me = self.thread(proc, tid);
                me.stack = parent;
                if matches!(me.todo.back(), Some(Work::Complete)) {
                    me.todo.pop_back();
                }
                self.abandon(id);
                return Err(f);
            }
        } else {
            let suspect = self.procs.get(&target_proc).and_then(|p| p.buffers.get(&buffer)).is_some_and(|b| b.spam_suspect);
            match self.proc_transaction(id, target_proc, None) {
                // Kept for a frozen target: its sender is told so.
                Ok(true) => self.to_thread(proc, tid, Work::Pending),
                Ok(false) => self.to_thread(proc, tid, if suspect { Work::SpamSuspect } else { Work::Complete }),
                Err(f) => {
                    self.abandon(id);
                    return Err(f);
                }
            }
        }
        Ok(())
    }

    /// A call that was built and could not be queued: its buffer and what
    /// its objects held go back.
    fn abandon(&mut self, txn: u64) {
        let Some((proc, buffer)) = self.txns.get(&txn).map(|t| (t.to_proc, t.buffer)) else { return };
        self.drop_txn(txn);
        if let (Some(proc), Some(at)) = (proc, buffer) {
            self.free_buffer(proc, at);
        }
    }

    // -- what a thread writes (binder_thread_write) --------------------------

    fn write(&mut self, cx: &Caller<'_>, m: &GuestMem<'_>, proc: u64, buf: u64, size: u64, consumed: &mut u64) -> Result<(), Errno> {
        let tid = cx.tid;
        while *consumed < size {
            let at = buf + *consumed;
            let cmd = m.read_u32(at)?;
            let arg = at + 4;
            let len = (cmd >> 16 & 0x3fff) as u64;
            if *consumed + 4 + len > size {
                return Err(Errno::EINVAL);
            }
            match cmd {
                BC_INCREFS | BC_ACQUIRE | BC_RELEASE | BC_DECREFS => {
                    let handle = m.read_u32(arg)?;
                    let strong = matches!(cmd, BC_ACQUIRE | BC_RELEASE);
                    let up = matches!(cmd, BC_INCREFS | BC_ACQUIRE);
                    // Handle 0 is the context manager's node, which a
                    // process may take a reference to unasked.
                    if handle == 0 && up && !self.procs[&proc].refs.contains_key(&0) {
                        if let Some(mgr) = self.mgr_of(proc) {
                            self.ref_for_node(proc, mgr);
                        }
                    }
                    let _ = if up { self.inc_ref(proc, handle, strong, None) } else { self.dec_ref(proc, handle, strong) };
                }
                BC_INCREFS_DONE | BC_ACQUIRE_DONE => {
                    let (ptr, cookie) = (m.read_u64(arg)?, m.read_u64(arg + 8)?);
                    let strong = cmd == BC_ACQUIRE_DONE;
                    if let Some(&node) = self.procs[&proc].node_of_ptr.get(&ptr) {
                        let n = self.nodes.get_mut(&node).expect("the node");
                        let same = n.cookie == cookie;
                        let pending = if strong { &mut n.pending_strong } else { &mut n.pending_weak };
                        if same && *pending {
                            *pending = false;
                            self.dec_node(node, strong, false);
                        }
                    }
                }
                BC_FREE_BUFFER => {
                    let ptr = m.read_u64(arg)?;
                    if let Some(b) = self.procs[&proc].buffers.get(&ptr).filter(|b| !b.free && b.allow_user_free) {
                        // The descriptors of its arrays go with it, and
                        // the thread goes back to its program for that.
                        let fds: Vec<i32> = b.objects.iter().filter_map(|o| if let Object::ArrayFd(fd) = o { Some(*fd) } else { None }).collect();
                        for &fd in &fds {
                            let _ = cx.fds.close(fd);
                        }
                        if !fds.is_empty() {
                            self.thread(proc, tid).need_return = true;
                        }
                        self.free_buffer(proc, ptr);
                    }
                }
                BC_TRANSACTION | BC_REPLY | BC_TRANSACTION_SG | BC_REPLY_SG => {
                    let b = m.read(arg, len as usize)?;
                    let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
                    let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let tr = TrData { target: u64_at(0), code: u32_at(16), flags: u32_at(20), data_size: u64_at(32), offsets_size: u64_at(40), buffer: u64_at(48), offsets: u64_at(56) };
                    let extra = if len as usize > TR_SIZE { u64_at(64) } else { 0 };
                    self.transaction(cx, m, proc, tr, matches!(cmd, BC_REPLY | BC_REPLY_SG), extra);
                }
                BC_REGISTER_LOOPER => {
                    let p = self.procs.get_mut(&proc).expect("a binder process");
                    let entered = p.threads.get(&tid).is_some_and(|t| t.looper & LOOPER_ENTERED != 0);
                    let mut invalid = entered;
                    if !entered {
                        if p.requested_threads == 0 {
                            invalid = true;
                        } else {
                            p.requested_threads -= 1;
                            p.requested_threads_started += 1;
                        }
                    }
                    let t = self.thread(proc, tid);
                    t.looper |= LOOPER_REGISTERED | if invalid { LOOPER_INVALID } else { 0 };
                }
                BC_ENTER_LOOPER => {
                    let t = self.thread(proc, tid);
                    if t.looper & LOOPER_REGISTERED != 0 {
                        t.looper |= LOOPER_INVALID;
                    }
                    t.looper |= LOOPER_ENTERED;
                }
                BC_EXIT_LOOPER => self.thread(proc, tid).looper |= LOOPER_EXITED,
                BC_REQUEST_DEATH_NOTIFICATION | BC_CLEAR_DEATH_NOTIFICATION => {
                    let (handle, cookie) = (m.read_u32(arg)?, m.read_u64(arg + 4)?);
                    self.death_command(proc, tid, handle, cookie, cmd == BC_REQUEST_DEATH_NOTIFICATION);
                }
                BC_DEAD_BINDER_DONE => {
                    let cookie = m.read_u64(arg)?;
                    let p = self.procs.get_mut(&proc).expect("a binder process");
                    if let Some(i) = p.delivered_death.iter().position(|d| d.cookie == cookie) {
                        let d = p.delivered_death.remove(i);
                        if d.clear {
                            self.to_looper_or_proc(proc, tid, Work::ClearDeathDone(d.cookie));
                        }
                    }
                }
                BC_REQUEST_FREEZE_NOTIFICATION | BC_CLEAR_FREEZE_NOTIFICATION => {
                    let (handle, cookie) = (m.read_u32(arg)?, m.read_u64(arg + 4)?);
                    self.freeze_command(proc, handle, cookie, cmd == BC_REQUEST_FREEZE_NOTIFICATION)?;
                }
                BC_FREEZE_NOTIFICATION_DONE => {
                    let cookie = m.read_u64(arg)?;
                    self.freeze_done(proc, cookie)?;
                }
                _ => {
                    unimplemented(&format!("command {cmd:#x}"));
                    return Err(Errno::EINVAL);
                }
            }
            *consumed += 4 + len;
        }
        Ok(())
    }

    /// `BC_REQUEST_DEATH_NOTIFICATION` and `BC_CLEAR_DEATH_NOTIFICATION`.
    fn death_command(&mut self, proc: u64, tid: i32, handle: u32, cookie: u64, request: bool) {
        let id = self.id();
        let Some(r) = self.procs.get_mut(&proc).and_then(|p| p.refs.get_mut(&handle)) else { return };
        let node = r.node;
        if request {
            if r.death.is_some() {
                return;
            }
            let d = Death { id, cookie, clear: false };
            r.death = Some(d);
            // Dead already: told at once.
            if self.nodes.get(&node).is_none_or(|n| n.owner.is_none()) {
                self.to_looper_or_proc(proc, tid, Work::DeadBinder(d));
            }
        } else {
            let Some(d) = r.death.filter(|d| d.cookie == cookie) else { return };
            r.death = None;
            // Its telling is queued or unanswered: that one clears it.
            let p = self.procs.get_mut(&proc).expect("a binder process");
            let mut marked = false;
            let mut mark = |w: &mut Work| {
                if let Work::DeadBinder(x) = w {
                    if x.id == d.id {
                        x.clear = true;
                        marked = true;
                    }
                }
            };
            p.todo.iter_mut().for_each(&mut mark);
            p.threads.values_mut().for_each(|t| t.todo.iter_mut().for_each(&mut mark));
            for x in p.delivered_death.iter_mut().filter(|x| x.id == d.id) {
                x.clear = true;
                marked = true;
            }
            if !marked {
                self.to_looper_or_proc(proc, tid, Work::ClearDeathDone(cookie));
            }
        }
    }

    // -- freezing ---------------------------------------------------------------

    /// `BC_REQUEST_FREEZE_NOTIFICATION` and `BC_CLEAR_FREEZE_NOTIFICATION`.
    /// One asked for is told at once how the node's process stands.
    fn freeze_command(&mut self, proc: u64, handle: u32, cookie: u64, request: bool) -> Result<(), Errno> {
        let id = self.id();
        let r = self.procs.get_mut(&proc).and_then(|p| p.refs.get_mut(&handle)).ok_or(Errno::EINVAL)?;
        if request {
            if r.freeze.is_some() {
                return Err(Errno::EINVAL);
            }
            r.freeze = Some(id);
            let owner = self.nodes.get(&r.node).and_then(|n| n.owner);
            let mut f = Freeze { proc, cookie, is_frozen: false, sent: false, resend: false, clear: false, listed: false };
            if let Some(owner) = owner {
                f.is_frozen = self.procs.get(&owner).is_some_and(|p| p.is_frozen);
                f.listed = true;
                self.procs.get_mut(&proc).expect("a binder process").todo.push_back(Work::Freeze(id));
            }
            self.freezes.insert(id, f);
        } else {
            let id = r.freeze.ok_or(Errno::EINVAL)?;
            let f = self.freezes.get_mut(&id).ok_or(Errno::EINVAL)?;
            if f.cookie != cookie {
                return Err(Errno::EINVAL);
            }
            r.freeze = None;
            // Its work becomes the telling that it is cleared: queued now
            // if it is on no list, read as that if it waits to be read,
            // and queued when the answer comes if it is told and
            // unanswered.
            f.clear = true;
            if !f.listed {
                f.listed = true;
                self.procs.get_mut(&proc).expect("a binder process").todo.push_back(Work::Freeze(id));
            } else if f.sent {
                f.resend = true;
            }
        }
        Ok(())
    }

    /// `BC_FREEZE_NOTIFICATION_DONE`.
    fn freeze_done(&mut self, proc: u64, cookie: u64) -> Result<(), Errno> {
        let p = self.procs.get_mut(&proc).expect("a binder process");
        let at = p.delivered_freeze.iter().position(|id| self.freezes.get(id).is_some_and(|f| f.cookie == cookie)).ok_or(Errno::EINVAL)?;
        let id = p.delivered_freeze.remove(at);
        let f = self.freezes.get_mut(&id).expect("the request");
        f.listed = false;
        f.sent = false;
        if f.resend {
            f.resend = false;
            f.listed = true;
            p.todo.push_back(Work::Freeze(id));
        }
        Ok(())
    }

    /// `binder_add_freeze_work`: everyone that asked to hear of a node of
    /// `proc` is told it is frozen, or thawed.
    fn add_freeze_work(&mut self, proc: u64, is_frozen: bool) {
        let refs: Vec<(u64, u32)> = self.nodes.values().filter(|n| n.owner == Some(proc)).flat_map(|n| n.refs.iter().copied()).collect();
        for (rp, h) in refs {
            let Some(id) = self.procs.get(&rp).and_then(|p| p.refs.get(&h)).and_then(|r| r.freeze) else { continue };
            let Some(f) = self.freezes.get_mut(&id) else { continue };
            if !f.listed {
                f.is_frozen = is_frozen;
                f.listed = true;
                if let Some(p) = self.procs.get_mut(&rp) {
                    p.todo.push_back(Work::Freeze(id));
                }
            } else {
                if f.sent && f.is_frozen != is_frozen {
                    f.resend = true;
                }
                f.is_frozen = is_frozen;
            }
        }
    }

    /// Calls are queued for the process or in its threads' hands
    /// (`binder_txns_pending_ilocked`).
    fn txns_pending(&self, proc: u64) -> bool {
        self.procs.get(&proc).is_some_and(|p| p.outstanding > 0 || p.threads.values().any(|t| t.stack.is_some()))
    }

    // -- what a thread reads (binder_thread_read) ----------------------------

    /// Whether a read by this thread has something to return
    /// (`binder_has_work`).
    fn has_work(&self, proc: u64, tid: i32) -> bool {
        let Some(p) = self.procs.get(&proc) else { return true };
        let Some(t) = p.threads.get(&tid) else { return true };
        let for_proc = t.stack.is_none() && t.todo.is_empty();
        t.process_todo || t.need_return || (for_proc && !p.todo.is_empty())
    }

    /// Fill `out` (at most `cap` bytes) with returns. `None` when there is
    /// nothing and the thread is to wait.
    fn read(&mut self, cx: &Caller<'_>, m: &mut GuestMem<'_>, proc: u64, cap: usize, first: bool) -> Result<Option<Vec<u8>>, Errno> {
        let tid = cx.tid;
        let mut out: Vec<u8> = Vec::new();
        if first {
            out.extend_from_slice(&BR_NOOP.to_le_bytes());
        }
        let for_proc = {
            let t = self.thread(proc, tid);
            t.stack.is_none() && t.todo.is_empty()
        };
        if !self.has_work(proc, tid) {
            if cx.nonblock {
                return Err(Errno::EAGAIN);
            }
            // Waiting: for the process's work too, if this thread may take
            // it.
            let p = self.procs.get_mut(&proc).expect("a binder process");
            if for_proc && !p.waiting.contains(&tid) {
                p.waiting.push_back(tid);
            }
            return Ok(None);
        }
        if let Some(p) = self.procs.get_mut(&proc) {
            p.waiting.retain(|&t| t != tid);
        }
        loop {
            let from_thread = !self.thread(proc, tid).todo.is_empty();
            let p = self.procs.get_mut(&proc).expect("a binder process");
            if !from_thread && !(for_proc && !p.todo.is_empty()) {
                break;
            }
            // Room for the largest return, a call with its security
            // context's place.
            if cap - out.len().min(cap) < TR_SIZE + 8 + 4 {
                break;
            }
            let w = if from_thread {
                let t = p.threads.get_mut(&tid).expect("the thread");
                let w = t.todo.pop_front().expect("its work");
                if t.todo.is_empty() {
                    t.process_todo = false;
                }
                w
            } else {
                p.todo.pop_front().expect("the process's work")
            };
            match w {
                Work::Complete => out.extend_from_slice(&BR_TRANSACTION_COMPLETE.to_le_bytes()),
                Work::Pending => out.extend_from_slice(&BR_TRANSACTION_PENDING_FROZEN.to_le_bytes()),
                Work::SpamSuspect => {
                    // Said only to a process that asked to be told.
                    let asked = self.procs.get(&proc).is_some_and(|p| p.spam_detection);
                    out.extend_from_slice(&if asked { BR_ONEWAY_SPAM_SUSPECT } else { BR_TRANSACTION_COMPLETE }.to_le_bytes());
                }
                Work::Freeze(id) => {
                    let Some(f) = self.freezes.get_mut(&id) else { continue };
                    if f.clear {
                        out.extend_from_slice(&BR_CLEAR_FREEZE_NOTIFICATION_DONE.to_le_bytes());
                        out.extend_from_slice(&f.cookie.to_le_bytes());
                        self.freezes.remove(&id);
                    } else {
                        // struct binder_frozen_state_info
                        out.extend_from_slice(&BR_FROZEN_BINDER.to_le_bytes());
                        out.extend_from_slice(&f.cookie.to_le_bytes());
                        out.extend_from_slice(&(f.is_frozen as u32).to_le_bytes());
                        out.extend_from_slice(&0u32.to_le_bytes());
                        f.sent = true;
                        self.procs.get_mut(&proc).expect("a binder process").delivered_freeze.push(id);
                        // As a death: it may cause calls.
                        break;
                    }
                }
                Work::Error(code) => out.extend_from_slice(&code.to_le_bytes()),
                Work::Node(node) => self.read_node(proc, node, &mut out),
                Work::DeadBinder(d) => {
                    out.extend_from_slice(&BR_DEAD_BINDER.to_le_bytes());
                    out.extend_from_slice(&d.cookie.to_le_bytes());
                    self.procs.get_mut(&proc).expect("a binder process").delivered_death.push(d);
                    // A death may cause calls: returned at once.
                    break;
                }
                Work::ClearDeathDone(cookie) => {
                    out.extend_from_slice(&BR_CLEAR_DEATH_NOTIFICATION_DONE.to_le_bytes());
                    out.extend_from_slice(&cookie.to_le_bytes());
                }
                Work::Txn(id) => {
                    if self.read_txn(cx, m, proc, id, &mut out) {
                        break;
                    }
                }
            }
        }
        // Another looper, when none waits and the process allows more.
        let p = self.procs.get_mut(&proc).expect("a binder process");
        let looper = p.threads.get(&tid).map_or(0, |t| t.looper);
        if first && p.requested_threads == 0 && p.waiting.is_empty() && p.requested_threads_started < p.max_threads && looper & (LOOPER_REGISTERED | LOOPER_ENTERED) != 0 {
            p.requested_threads += 1;
            out[..4].copy_from_slice(&BR_SPAWN_LOOPER.to_le_bytes());
        }
        Ok(Some(out))
    }

    /// A node's work: its owner is told of the references it gained or
    /// lost (`BINDER_WORK_NODE`).
    fn read_node(&mut self, proc: u64, node: u64, out: &mut Vec<u8>) {
        let Some(n) = self.nodes.get_mut(&node) else { return };
        n.queued = false;
        let strong = n.internal_strong != 0 || n.local_strong != 0;
        let weak = !n.refs.is_empty() || n.local_weak != 0 || strong;
        let (had_strong, had_weak) = (n.has_strong, n.has_weak);
        let (ptr, cookie) = (n.ptr, n.cookie);
        if weak && !had_weak {
            n.has_weak = true;
            n.pending_weak = true;
            n.local_weak += 1;
        }
        if strong && !had_strong {
            n.has_strong = true;
            n.pending_strong = true;
            n.local_strong += 1;
        }
        if !strong && had_strong {
            n.has_strong = false;
        }
        if !weak && had_weak {
            n.has_weak = false;
        }
        if !weak && !strong {
            self.free_node(node);
        }
        let _ = proc;
        let mut put = |code: u32| {
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&ptr.to_le_bytes());
            out.extend_from_slice(&cookie.to_le_bytes());
        };
        if weak && !had_weak {
            put(BR_INCREFS);
        }
        if strong && !had_strong {
            put(BR_ACQUIRE);
        }
        if !strong && had_strong {
            put(BR_RELEASE);
        }
        if !weak && had_weak {
            put(BR_DECREFS);
        }
    }

    /// A call or a reply reaches its thread: its bytes are written into
    /// the thread's process's mapping, its descriptors made that
    /// process's, and it is returned. `true` when one was returned, which
    /// ends the read.
    fn read_txn(&mut self, cx: &Caller<'_>, m: &mut GuestMem<'_>, proc: u64, id: u64, out: &mut Vec<u8>) -> bool {
        let tid = cx.tid;
        let Some(t) = self.txns.get_mut(&id) else { return false };
        let Some(buffer) = t.buffer else {
            self.drop_txn(id);
            return false;
        };
        // The descriptors, each close-on-exec; then the bytes, which the
        // kernel writes whatever the mapping allows the program.
        let mut installed = Vec::new();
        let mut ok = true;
        let mut in_arrays = Vec::new();
        for (at, file, array) in std::mem::take(&mut t.fds) {
            match cx.fds.insert(file, true) {
                Ok(fd) => {
                    t.bytes[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes());
                    installed.push(fd as i32);
                    if array {
                        in_arrays.push(Object::ArrayFd(fd as i32));
                    }
                }
                Err(_) => ok = false,
            }
        }
        let user = m.take_user();
        ok = ok && m.write(buffer, &t.bytes).is_ok();
        m.set_user(user);
        let (is_reply, oneway, node) = (t.is_reply, t.flags & TF_ONE_WAY != 0, t.target_node);
        if !ok {
            for fd in installed {
                let _ = cx.fds.close(fd);
            }
            let from_waits = t.from.is_some();
            if is_reply {
                // The reply could not be delivered: the caller reads that.
                self.drop_txn(id);
                self.free_buffer(proc, buffer);
                out.extend_from_slice(&BR_FAILED_REPLY.to_le_bytes());
                return true;
            }
            if from_waits {
                self.send_failed_reply(id, BR_FAILED_REPLY);
            } else {
                self.drop_txn(id);
            }
            self.free_buffer(proc, buffer);
            return false;
        }
        let t = self.txns.get_mut(&id).expect("the call");
        t.bytes = Vec::new();
        let (target_ptr, cookie) = match node.and_then(|n| self.nodes.get(&n)) {
            Some(n) => (n.ptr, n.cookie),
            None => (0, 0),
        };
        let t = &self.txns[&id];
        let sender_pid = if t.from.is_some() { t.sender_pid } else { 0 };
        let security_ctx = t.security_ctx;
        let code = if is_reply {
            BR_REPLY
        } else if security_ctx.is_some() {
            BR_TRANSACTION_SEC_CTX
        } else {
            BR_TRANSACTION
        };
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&target_ptr.to_le_bytes());
        out.extend_from_slice(&cookie.to_le_bytes());
        out.extend_from_slice(&t.code.to_le_bytes());
        out.extend_from_slice(&t.flags.to_le_bytes());
        out.extend_from_slice(&sender_pid.to_le_bytes());
        out.extend_from_slice(&t.sender_euid.to_le_bytes());
        out.extend_from_slice(&t.data_size.to_le_bytes());
        out.extend_from_slice(&t.offsets_size.to_le_bytes());
        out.extend_from_slice(&buffer.to_le_bytes());
        out.extend_from_slice(&(buffer + align8(t.data_size)).to_le_bytes());
        if let Some(at) = security_ctx {
            out.extend_from_slice(&at.to_le_bytes());
        }
        if let Some(b) = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&buffer)) {
            b.allow_user_free = true;
            b.objects.extend(in_arrays);
        }
        if !is_reply && !oneway {
            // The thread is in the call until it replies.
            let parent = self.thread(proc, tid).stack;
            let t = self.txns.get_mut(&id).expect("the call");
            t.to_parent = parent;
            t.to_thread = Some(tid);
            self.thread(proc, tid).stack = Some(id);
        } else {
            self.drop_txn(id);
        }
        true
    }

    // -- endings --------------------------------------------------------------

    /// `binder_thread_release`: the calls the thread was in go on without
    /// it, and one it was serving fails for its caller.
    fn thread_release(&mut self, proc: u64, tid: i32) {
        let Some(thread) = self.procs.get_mut(&proc).and_then(|p| p.threads.remove(&tid)) else { return };
        if let Some(p) = self.procs.get_mut(&proc) {
            p.waiting.retain(|&t| t != tid);
        }
        let mut at = thread.stack;
        let send_reply = at.filter(|t| self.txns.get(t).is_some_and(|x| x.to_thread == Some(tid) && x.to_proc == Some(proc)));
        while let Some(id) = at {
            let Some(t) = self.txns.get_mut(&id) else { break };
            if t.to_thread == Some(tid) && t.to_proc == Some(proc) {
                if std::mem::take(&mut t.counted) {
                    if let Some(p) = self.procs.get_mut(&proc) {
                        p.outstanding -= 1;
                    }
                }
                let t = self.txns.get_mut(&id).expect("the call");
                t.to_proc = None;
                t.to_thread = None;
                t.buffer = None;
                at = t.to_parent;
            } else if t.from == Some((proc, tid)) {
                t.from = None;
                at = t.from_parent;
            } else {
                break;
            }
        }
        if let Some(t) = send_reply {
            self.send_failed_reply(t, BR_DEAD_REPLY);
        }
        self.release_work(thread.todo);
    }

    /// `binder_release_work`: queued work that will not be read. A call
    /// that waits for a reply fails for its caller.
    fn release_work(&mut self, list: VecDeque<Work>) {
        for w in list {
            if let Work::Txn(id) = w {
                let waits = self.txns.get(&id).is_some_and(|t| t.target_node.is_some() && t.flags & TF_ONE_WAY == 0);
                if waits {
                    self.send_failed_reply(id, BR_DEAD_REPLY);
                } else {
                    self.drop_txn(id);
                }
            }
        }
    }

    /// `binder_deferred_release`: the process's last descriptor on the
    /// device is closed.
    fn proc_release(&mut self, proc: u64) {
        let Some(p) = self.procs.get_mut(&proc) else { return };
        p.dead = true;
        let tids: Vec<i32> = p.threads.keys().copied().collect();
        let ctx = p.ctx;
        if self.mgr_of(proc).is_some_and(|n| self.nodes.get(&n).is_some_and(|n| n.owner == Some(proc))) {
            if let Some(c) = self.ctxs.get_mut(&ctx) {
                c.mgr = None;
            }
        }
        for tid in tids {
            self.thread_release(proc, tid);
        }
        // Its nodes die: those that hold handles on them are told, if they
        // asked to be.
        let nodes: Vec<u64> = self.nodes.iter().filter(|(_, n)| n.owner == Some(proc)).map(|(&id, _)| id).collect();
        for node in nodes {
            let n = self.nodes.get_mut(&node).expect("the node");
            n.owner = None;
            n.queued = false;
            let (waiting, refs) = (std::mem::take(&mut n.async_todo), n.refs.clone());
            self.release_work(waiting);
            if refs.is_empty() {
                self.nodes.remove(&node);
                continue;
            }
            for (rp, h) in refs {
                let Some(d) = self.procs.get(&rp).and_then(|p| p.refs.get(&h)).and_then(|r| r.death) else { continue };
                if let Some(p) = self.procs.get_mut(&rp) {
                    p.todo.push_back(Work::DeadBinder(d));
                }
            }
        }
        // Its handles go, and their nodes' owners are told.
        let handles: Vec<u32> = self.procs.get(&proc).map(|p| p.refs.keys().copied().collect()).unwrap_or_default();
        for h in handles {
            self.cleanup_ref(proc, h);
        }
        let Some(mut p) = self.procs.remove(&proc) else { return };
        self.freezes.retain(|_, f| f.proc != proc);
        self.release_work(std::mem::take(&mut p.todo));
        // Calls whose bytes lay in its buffers have nowhere to be read.
        for b in p.buffers.values() {
            if let Some(t) = b.txn.and_then(|t| self.txns.get_mut(&t)) {
                t.buffer = None;
            }
        }
    }
}

/// An open of a binder device (`struct binder_proc`): the process that
/// first uses it is its process.
pub struct BinderFile {
    ctx: Arc<Context>,
    id: u64,
    /// What `fstat` says: its node's metadata, where it has a node.
    node: Option<Arc<dyn Fn() -> Metadata + Send + Sync>>,
}

impl std::fmt::Debug for BinderFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder {} #{}", self.ctx.name, self.id)
    }
}

impl BinderFile {
    pub fn open(ctx: Arc<Context>) -> BinderFile {
        let mut st = lock();
        let id = st.id();
        st.procs.insert(id, Proc { ctx: ctx.id, ..Proc::default() });
        drop(st);
        BinderFile { ctx, id, node: None }
    }

    /// The open is of a node with this metadata.
    pub fn at_node(mut self, metadata: Arc<dyn Fn() -> Metadata + Send + Sync>) -> BinderFile {
        self.node = Some(metadata);
        self
    }

    /// One ioctl by `cx`'s thread.
    pub fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Outcome {
        let mut st = lock();
        let p = st.procs.get_mut(&self.id).expect("this open's process");
        // The process is whoever used the device first; another (a child
        // that inherited the descriptor) may not use it.
        if p.pid == 0 {
            (p.pid, p.euid) = (cx.pid, cx.euid);
            p.secctx = cx.secctx.map(<[u8]>::to_vec);
        } else if p.pid != cx.pid {
            return Outcome::Done(Err(Errno::EINVAL));
        }
        st.thread(self.id, cx.tid);
        let out = self.ioctl_locked(&mut st, cx, m, request, arg);
        // Its first ioctl is over (`looper_need_return`).
        if let Some(t) = st.procs.get_mut(&self.id).and_then(|p| p.threads.get_mut(&cx.tid)) {
            t.need_return = false;
        }
        drop(st);
        driver().queue.notify();
        out
    }

    /// The wait of an ioctl of `tid`'s ([`Outcome::Wait`]) ended without
    /// the call being made again (a signal): a process it was freezing is
    /// not frozen, as when the driver's own wait is interrupted.
    pub fn interrupted(&self, tid: i32) {
        let mut st = lock();
        let waited = st.procs.get_mut(&self.id).and_then(|p| p.threads.get_mut(&tid)).and_then(|t| t.freezing.take());
        if let Some(p) = waited.and_then(|(target, _)| st.procs.get_mut(&target)) {
            p.is_frozen = false;
        }
    }

    fn ioctl_locked(&self, st: &mut State, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Outcome {
        let proc = self.id;
        let done = |r: Result<(), Errno>| Outcome::Done(r.map(|()| 0));
        let words = |m: &GuestMem<'_>, n: usize| -> Result<Vec<u32>, Errno> {
            let b = m.read(arg, n * 4)?;
            Ok((0..n).map(|i| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())).collect())
        };
        match request {
            VERSION => done(m.write_u32(arg, PROTOCOL_VERSION as u32)),
            SET_MAX_THREADS => done(m.read_u32(arg).map(|n| st.procs.get_mut(&proc).expect("this process").max_threads = n)),
            SET_CONTEXT_MGR | SET_CONTEXT_MGR_EXT => {
                let flags = if request == SET_CONTEXT_MGR_EXT {
                    match m.read_u32(arg + 4) {
                        Ok(f) => f,
                        Err(e) => return Outcome::Done(Err(e)),
                    }
                } else {
                    0
                };
                let c = st.ctxs.get_mut(&self.ctx.id).expect("this device");
                if c.mgr.is_some() {
                    return Outcome::Done(Err(Errno::EBUSY));
                }
                // Whoever was first is the only one that may be again.
                match c.mgr_uid {
                    Some(uid) if uid != cx.euid => return Outcome::Done(Err(Errno::EPERM)),
                    _ => c.mgr_uid = Some(cx.euid),
                }
                let node = st.new_node(proc, 0, 0, flags);
                let n = st.nodes.get_mut(&node).expect("the node");
                n.local_weak += 1;
                n.local_strong += 1;
                n.has_strong = true;
                n.has_weak = true;
                st.ctxs.get_mut(&self.ctx.id).expect("this device").mgr = Some(node);
                Outcome::Done(Ok(0))
            }
            THREAD_EXIT => {
                st.thread_release(proc, cx.tid);
                Outcome::Done(Ok(0))
            }
            GET_NODE_INFO_FOR_REF => {
                // {handle, strong_count, weak_count, reserved x3}: the
                // context manager's question about a handle it holds.
                let w = match words(m, 6) {
                    Ok(w) => w,
                    Err(e) => return Outcome::Done(Err(e)),
                };
                if w[1..].iter().any(|&x| x != 0) {
                    return Outcome::Done(Err(Errno::EINVAL));
                }
                if st.mgr_of(proc).is_none_or(|n| st.nodes[&n].owner != Some(proc)) {
                    return Outcome::Done(Err(Errno::EPERM));
                }
                let Some(node) = st.procs[&proc].refs.get(&w[0]).map(|r| r.node) else { return Outcome::Done(Err(Errno::EINVAL)) };
                let n = &st.nodes[&node];
                let (strong, weak) = (n.local_strong + n.internal_strong, n.local_weak);
                done(m.write_u32(arg + 4, strong).and_then(|()| m.write_u32(arg + 8, weak)))
            }
            GET_NODE_DEBUG_INFO => {
                // {ptr, cookie, has_strong_ref, has_weak_ref}: the process's
                // node next after `ptr`, or zeros after the last.
                let after = match m.read_u64(arg) {
                    Ok(p) => p,
                    Err(e) => return Outcome::Done(Err(e)),
                };
                let next = st.procs[&proc].node_of_ptr.iter().filter(|(&ptr, _)| ptr > after).min_by_key(|(&ptr, _)| ptr).map(|(_, &n)| n);
                let mut out = [0u8; 24];
                if let Some(n) = next.and_then(|n| st.nodes.get(&n)) {
                    out[..8].copy_from_slice(&n.ptr.to_le_bytes());
                    out[8..16].copy_from_slice(&n.cookie.to_le_bytes());
                    out[16..20].copy_from_slice(&(n.has_strong as u32).to_le_bytes());
                    out[20..].copy_from_slice(&(n.has_weak as u32).to_le_bytes());
                }
                done(m.write(arg, &out))
            }
            FREEZE => match words(m, 3) {
                // {pid, enable, timeout_ms}
                Ok(w) => self.freeze(st, cx, w[0] as i32, w[1] != 0, w[2]),
                Err(e) => Outcome::Done(Err(e)),
            },
            GET_FROZEN_INFO => {
                // {pid, sync_recv, async_recv}: what reached the process's
                // opens while frozen; bit 1 of the first, that calls are
                // still in hand.
                let pid = match m.read_u32(arg) {
                    Ok(p) => p as i32,
                    Err(e) => return Outcome::Done(Err(e)),
                };
                let of: Vec<u64> = st.procs.iter().filter(|(_, p)| pid != 0 && p.pid == pid).map(|(&id, _)| id).collect();
                if of.is_empty() {
                    return Outcome::Done(Err(Errno::EINVAL));
                }
                let (mut sync, mut asynch) = (0u32, 0u32);
                for id in of {
                    let p = &st.procs[&id];
                    sync |= p.sync_recv as u32 | (st.txns_pending(id) as u32) << 1;
                    asynch |= p.async_recv as u32;
                }
                done(m.write_u32(arg + 4, sync).and_then(|()| m.write_u32(arg + 8, asynch)))
            }
            ENABLE_ONEWAY_SPAM_DETECTION => done(m.read_u32(arg).map(|on| st.procs.get_mut(&proc).expect("this process").spam_detection = on != 0)),
            GET_EXTENDED_ERROR => {
                let t = st.thread(proc, cx.tid);
                let ee = std::mem::replace(&mut t.ee, (0, BR_OK, 0));
                done(m.write_u32(arg, ee.0).and_then(|()| m.write_u32(arg + 4, ee.1)).and_then(|()| m.write_u32(arg + 8, ee.2 as u32)))
            }
            WRITE_READ => self.write_read(st, cx, m, arg),
            // Named in the header and done by no driver.
            SET_IDLE_TIMEOUT | SET_IDLE_PRIORITY => Outcome::Done(Err(Errno::EINVAL)),
            _ => {
                unimplemented(&format!("ioctl {request:#x}"));
                Outcome::Done(Err(Errno::EINVAL))
            }
        }
    }

    /// `BINDER_FREEZE`: every open of a device by process `pid`, newest
    /// first, is frozen or thawed. One being frozen takes no new call from
    /// then; with a time limit, the calls it has are waited for that long,
    /// and if any is still in hand it is not frozen and the answer is
    /// `EAGAIN`.
    fn freeze(&self, st: &mut State, cx: &Caller<'_>, pid: i32, enable: bool, timeout_ms: u32) -> Outcome {
        let resume = st.thread(self.id, cx.tid).freezing.take();
        let mut targets: Vec<u64> = st.procs.iter().filter(|(_, p)| pid != 0 && p.pid == pid && !p.dead).map(|(&id, _)| id).collect();
        targets.sort_unstable_by(|a, b| b.cmp(a));
        if targets.is_empty() && resume.is_none() {
            return Outcome::Done(Err(Errno::EINVAL));
        }
        for target in targets {
            // The call made again after a wait goes on from the process it
            // waited for.
            let mut deadline = None;
            match resume {
                Some((at, _)) if target > at => continue,
                Some((at, d)) if target == at => deadline = Some(d),
                _ => {}
            }
            let p = st.procs.get_mut(&target).expect("the process");
            if !enable {
                (p.sync_recv, p.async_recv, p.is_frozen) = (false, false, false);
                st.add_freeze_work(target, false);
                continue;
            }
            if deadline.is_none() {
                (p.sync_recv, p.async_recv, p.is_frozen) = (false, false, true);
                if timeout_ms > 0 {
                    deadline = Some(nanos(cx.clock) + timeout_ms as u128 * 1_000_000);
                }
            }
            if let Some(d) = deadline {
                if p.outstanding > 0 && nanos(cx.clock) < d {
                    st.thread(self.id, cx.tid).freezing = Some((target, d));
                    return Outcome::Wait(Arc::new(FreezeWaiter { proc: target, deadline: d, clock: cx.clock }));
                }
            }
            if st.txns_pending(target) {
                st.procs.get_mut(&target).expect("the process").is_frozen = false;
                return Outcome::Done(Err(Errno::EAGAIN));
            }
            st.add_freeze_work(target, true);
        }
        Outcome::Done(Ok(0))
    }

    /// `binder_ioctl_write_read`.
    fn write_read(&self, st: &mut State, cx: &Caller<'_>, m: &mut GuestMem<'_>, arg: u64) -> Outcome {
        let proc = self.id;
        let bwr = match m.read(arg, 48) {
            Ok(b) => {
                let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
                [w(0), w(1), w(2), w(3), w(4), w(5)]
            }
            Err(e) => return Outcome::Done(Err(e)),
        };
        let [write_size, mut write_consumed, write_buffer, read_size, mut read_consumed, read_buffer] = bwr;
        let put = |m: &mut GuestMem<'_>, w: u64, r: u64| m.write_u64(arg + 8, w).and_then(|()| m.write_u64(arg + 32, r));
        if write_size > 0 {
            if let Err(e) = st.write(cx, m, proc, write_buffer, write_size, &mut write_consumed) {
                let _ = put(m, write_consumed, 0);
                return Outcome::Done(Err(e));
            }
        }
        if read_size > 0 {
            match st.read(cx, m, proc, (read_size - read_consumed.min(read_size)) as usize, read_consumed == 0) {
                Ok(Some(out)) => {
                    if let Err(e) = m.write(read_buffer + read_consumed, &out) {
                        let _ = put(m, write_consumed, read_consumed);
                        return Outcome::Done(Err(e));
                    }
                    read_consumed += out.len() as u64;
                }
                Ok(None) => {
                    // What was written is recorded, so that the call made
                    // again writes none of it twice.
                    if let Err(e) = put(m, write_consumed, read_consumed) {
                        return Outcome::Done(Err(e));
                    }
                    return Outcome::Wait(Arc::new(Waiter { proc, tid: cx.tid }));
                }
                Err(e) => {
                    let _ = put(m, write_consumed, read_consumed);
                    return Outcome::Done(Err(e));
                }
            }
        }
        Outcome::Done(put(m, write_consumed, read_consumed).map(|()| 0))
    }
}

impl Drop for BinderFile {
    fn drop(&mut self) {
        lock().proc_release(self.id);
        driver().queue.notify();
    }
}

fn device_metadata() -> Metadata {
    Metadata { file_type: FileType::CharDevice, size: 0, mode: 0o600, ino: 1, mtime: 0, nlink: 1, rdev: 0, times: Default::default() }
}

impl FileHandle for BinderFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(self.node.as_ref().map_or_else(device_metadata, |node| node()))
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn as_binder(self: Arc<Self>) -> Option<Arc<BinderFile>> {
        Some(self)
    }

    /// The device's buffer: the process's mapping of it (`binder_mmap`),
    /// whose pages the kernel fills as calls arrive.
    fn maps_own_memory(&self) -> bool {
        true
    }

    fn mapped(&self, start: u64, len: u64) {
        let mut st = lock();
        if let Some(p) = st.procs.get_mut(&self.id) {
            if p.map.is_none() {
                // No more than 4 MiB of a mapping is the driver's.
                let len = len.min(4 << 20);
                p.map = Some((start, len));
                p.free_async = len / 2;
                p.buffers.insert(start, Buffer::free(len));
            }
        }
    }

    /// Readable when any of the process's threads has work
    /// (`binder_poll`, which asks for the polling thread alone).
    fn poll_readable(&self) -> bool {
        lock().procs.get(&self.id).is_some_and(|p| !p.todo.is_empty() || p.threads.values().any(|t| t.process_todo))
    }

    fn wait_queue(&self) -> u32 {
        driver().queue.id()
    }
}

/// What a thread that waits in a read is parked on: readable when that
/// thread's read would return.
struct Waiter {
    proc: u64,
    tid: i32,
}

impl std::fmt::Debug for Waiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder wait {}.{}", self.proc, self.tid)
    }
}

impl FileHandle for Waiter {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(device_metadata())
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        lock().has_work(self.proc, self.tid)
    }

    fn wait_queue(&self) -> u32 {
        driver().queue.id()
    }
}

/// What a thread that freezes a process with a time limit is parked on:
/// readable when the process has no call left, or the time is up. Nothing
/// notifies at the time, so the host that parks on this asks again as
/// time passes (the native host's waits are in slices).
struct FreezeWaiter {
    proc: u64,
    deadline: u128,
    clock: crate::syscalls::ClockFn,
}

impl std::fmt::Debug for FreezeWaiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder freeze of {}", self.proc)
    }
}

impl FileHandle for FreezeWaiter {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(device_metadata())
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        nanos(self.clock) >= self.deadline || lock().procs.get(&self.proc).is_none_or(|p| p.outstanding <= 0)
    }

    fn wait_queue(&self) -> u32 {
        driver().queue.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One memory two "processes" share for the test: each has its own
    /// descriptor table, device mapping and scratch for its ioctls.
    struct Side {
        file: BinderFile,
        fds: FdTable,
        pid: i32,
        /// Where its `binder_write_read`, commands and returns go.
        at: u64,
    }

    impl Side {
        fn new(ctx: &Arc<Context>, pid: i32, at: u64, map: u64) -> Side {
            let file = BinderFile::open(Arc::clone(ctx));
            file.mapped(map, 0x1000);
            Side { file, fds: FdTable::new(), pid, at }
        }

        fn ioctl(&self, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Outcome {
            let cx = Caller { pid: self.pid, tid: self.pid, euid: 1000, fds: &self.fds, nonblock: false, clock: || (0, 0), secctx: None };
            self.file.ioctl(&cx, m, request, arg)
        }

        /// Write `cmds` and read: the returns, or `None` when the read
        /// would wait.
        fn write_read(&self, m: &mut GuestMem<'_>, cmds: &[u8], read: bool) -> Option<Vec<u8>> {
            let (bwr, wbuf, rbuf) = (self.at, self.at + 0x100, self.at + 0x400);
            m.write(wbuf, cmds).unwrap();
            for (i, v) in [cmds.len() as u64, 0, wbuf, if read { 256 } else { 0 }, 0, rbuf].into_iter().enumerate() {
                m.write_u64(bwr + 8 * i as u64, v).unwrap();
            }
            match self.ioctl(m, WRITE_READ, bwr) {
                Outcome::Done(r) => {
                    assert_eq!(r, Ok(0));
                    assert_eq!(m.read_u64(bwr + 8).unwrap(), cmds.len() as u64, "all of it written");
                    let n = m.read_u64(bwr + 32).unwrap() as usize;
                    Some(m.read(rbuf, n).unwrap().to_vec())
                }
                Outcome::Wait(w) => {
                    // What was written is recorded, and nothing is ready.
                    assert_eq!(m.read_u64(bwr + 8).unwrap(), cmds.len() as u64);
                    assert!(!w.poll_readable());
                    None
                }
            }
        }
    }

    fn words(b: &[u8]) -> Vec<u32> {
        b.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
    }

    /// A call's command: `cmd`, then its `binder_transaction_data`.
    fn call(cmd: u32, handle: u32, code: u32, flags: u32, data: u64, size: u64) -> Vec<u8> {
        let mut b = cmd.to_le_bytes().to_vec();
        for v in [handle as u64, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&code.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        for v in [0u64, size, 0, data, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    }

    /// A call and its reply between two processes, as each reads them; a
    /// call with no manager; and what the manager is told when the caller's
    /// node dies.
    #[test]
    fn a_call_is_read_replied_to_and_its_caller_mourned() {
        let ctx = Context::new("unit-test");
        let mut bytes = vec![0u8; 0x10000];
        let mut m = GuestMem::new(&mut bytes);
        let mgr = Side::new(&ctx, 10, 0x1000, 0x8000);
        let cli = Side::new(&ctx, 20, 0x2000, 0x9000);

        // The protocol's version, for both; no manager yet.
        assert!(matches!(cli.ioctl(&mut m, VERSION, 0x3000), Outcome::Done(Ok(0))));
        assert_eq!(m.read_u32(0x3000).unwrap(), 8);
        m.write(0x3100, b"ping\0").unwrap();
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 1, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_DEAD_REPLY]);

        // One manager, and no second.
        assert!(matches!(mgr.ioctl(&mut m, SET_CONTEXT_MGR, 0), Outcome::Done(Ok(0))));
        assert!(matches!(cli.ioctl(&mut m, SET_CONTEXT_MGR, 0), Outcome::Done(Err(Errno::EBUSY))));
        assert_eq!(mgr.write_read(&mut m, &BC_ENTER_LOOPER.to_le_bytes(), false), Some(vec![]));
        // Nothing to read yet: the manager waits.
        assert_eq!(mgr.write_read(&mut m, &[], true), None);

        // The call: the caller waits for its reply; the manager reads it,
        // from the caller, its bytes in its own mapping.
        assert_eq!(cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 7, 0, 0x3100, 5), true), None);
        let r = mgr.write_read(&mut m, &[], true).unwrap();
        let w = words(&r);
        assert_eq!((w[0], w[1]), (BR_NOOP, BR_TRANSACTION));
        let field = |i: usize| u64::from_le_bytes(r[8 + i * 8..16 + i * 8].try_into().unwrap());
        assert_eq!((field(0), field(1)), (0, 0), "the manager's node");
        assert_eq!((w[6], w[7], w[8] as i32, w[9]), (7, 0, 20, 1000), "code, flags, sender pid and euid");
        assert_eq!((field(4), field(5), field(6)), (5, 0, 0x8000), "five bytes at the start of the mapping");
        assert_eq!(m.read(0x8000, 5).unwrap(), b"ping\0");

        // The reply, with the buffer given back: complete for the manager,
        // and the caller's wait ends with its completion and the reply.
        m.write(0x3200, b"pong\0").unwrap();
        let mut cmds = BC_FREE_BUFFER.to_le_bytes().to_vec();
        cmds.extend_from_slice(&0x8000u64.to_le_bytes());
        cmds.extend_from_slice(&call(BC_REPLY, 0, 0, 0, 0x3200, 5));
        let r = mgr.write_read(&mut m, &cmds, true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_TRANSACTION_COMPLETE]);
        let r = cli.write_read(&mut m, &[], true).unwrap();
        let w = words(&r);
        assert_eq!((w[0], w[1], w[2]), (BR_NOOP, BR_TRANSACTION_COMPLETE, BR_REPLY));
        assert_eq!(m.read(0x9000, 5).unwrap(), b"pong\0");

        // A handle nobody gave the caller.
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 9, 1, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_FAILED_REPLY]);

        // The manager dies: a call to it is a dead reply.
        drop(mgr);
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 1, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_DEAD_REPLY]);
    }

    /// A frozen process: whoever asked is told, a call that waits is
    /// refused and a one-way call kept, and a process with a call in hand
    /// is frozen only once it is done with it.
    #[test]
    fn a_frozen_process_takes_no_call_and_who_asked_is_told() {
        let ctx = Context::new("unit-freeze");
        let mut bytes = vec![0u8; 0x10000];
        let mut m = GuestMem::new(&mut bytes);
        let mgr = Side::new(&ctx, 11, 0x1000, 0x8000);
        let cli = Side::new(&ctx, 21, 0x2000, 0x9000);
        assert!(matches!(mgr.ioctl(&mut m, SET_CONTEXT_MGR, 0), Outcome::Done(Ok(0))));
        assert_eq!(mgr.write_read(&mut m, &BC_ENTER_LOOPER.to_le_bytes(), false), Some(vec![]));
        let with = |cmd: u32, handle: Option<u32>, cookie: u64| {
            let mut b = cmd.to_le_bytes().to_vec();
            if let Some(h) = handle {
                b.extend_from_slice(&h.to_le_bytes());
            }
            b.extend_from_slice(&cookie.to_le_bytes());
            b
        };
        let freeze = |m: &mut GuestMem<'_>, enable: u32, timeout: u32| {
            for (i, v) in [11u32, enable, timeout].into_iter().enumerate() {
                m.write_u32(0x3000 + 4 * i as u64, v).unwrap();
            }
            cli.ioctl(m, FREEZE, 0x3000)
        };
        let told = |frozen: u32| vec![BR_NOOP, BR_FROZEN_BINDER, 0x55, 0, frozen, 0];
        let done = with(BC_FREEZE_NOTIFICATION_DONE, None, 0x55);

        // Asked for: told at once how the manager stands.
        let mut cmds = BC_INCREFS.to_le_bytes().to_vec();
        cmds.extend_from_slice(&0u32.to_le_bytes());
        cmds.extend_from_slice(&with(BC_REQUEST_FREEZE_NOTIFICATION, Some(0), 0x55));
        assert_eq!(words(&cli.write_read(&mut m, &cmds, true).unwrap()), told(0));
        // Asked twice, or answered for a cookie nobody was told: refused.
        m.write(0x2100, &with(BC_REQUEST_FREEZE_NOTIFICATION, Some(0), 0x56)).unwrap();
        for (i, v) in [16u64, 0, 0x2100, 0, 0, 0].into_iter().enumerate() {
            m.write_u64(0x2000 + 8 * i as u64, v).unwrap();
        }
        assert!(matches!(cli.ioctl(&mut m, WRITE_READ, 0x2000), Outcome::Done(Err(Errno::EINVAL))));
        assert_eq!(m.read_u64(0x2008).unwrap(), 0, "none of it consumed");

        // Frozen: told again only when the first telling is answered.
        assert!(matches!(freeze(&mut m, 1, 0), Outcome::Done(Ok(0))));
        assert_eq!(cli.write_read(&mut m, &[], true), None);
        assert_eq!(words(&cli.write_read(&mut m, &done, true).unwrap()), told(1));
        // A call that waits is refused; a one-way call is kept.
        m.write(0x3100, b"ping\0").unwrap();
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 1, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_FROZEN_REPLY]);
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 2, TF_ONE_WAY, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_TRANSACTION_PENDING_FROZEN]);
        m.write_u32(0x3000, 11).unwrap();
        assert!(matches!(cli.ioctl(&mut m, GET_FROZEN_INFO, 0x3000), Outcome::Done(Ok(0))));
        assert_eq!((m.read_u32(0x3004).unwrap(), m.read_u32(0x3008).unwrap()), (3, 1), "both kinds arrived, and one is in hand");

        // Thawed: told, and the call that was kept is read.
        assert!(matches!(freeze(&mut m, 0, 0), Outcome::Done(Ok(0))));
        assert_eq!(words(&cli.write_read(&mut m, &done, true).unwrap()), told(0));
        let r = mgr.write_read(&mut m, &[], true).unwrap();
        assert_eq!(words(&r)[..2], [BR_NOOP, BR_TRANSACTION]);
        let mut cmds = done.clone();
        cmds.extend_from_slice(&with(BC_CLEAR_FREEZE_NOTIFICATION, Some(0), 0x55));
        assert_eq!(words(&cli.write_read(&mut m, &cmds, true).unwrap()), [BR_NOOP, BR_CLEAR_FREEZE_NOTIFICATION_DONE, 0x55, 0]);

        // A call in the manager's hands: not frozen at once, and frozen
        // within a time limit when the reply is made within it.
        assert_eq!(cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 7, 0, 0x3100, 5), true), None);
        let r = mgr.write_read(&mut m, &[], true).unwrap();
        assert_eq!(words(&r)[..2], [BR_NOOP, BR_TRANSACTION]);
        assert!(matches!(freeze(&mut m, 1, 0), Outcome::Done(Err(Errno::EAGAIN))));
        let Outcome::Wait(wait) = freeze(&mut m, 1, 1000) else { panic!("the freeze waits") };
        assert!(!wait.poll_readable());
        let r = mgr.write_read(&mut m, &call(BC_REPLY, 0, 0, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_TRANSACTION_COMPLETE]);
        // The reply is the caller's to read; the manager has none in hand.
        assert!(wait.poll_readable());
        let r = cli.write_read(&mut m, &[], true).unwrap();
        assert_eq!(words(&r)[..3], [BR_NOOP, BR_TRANSACTION_COMPLETE, BR_REPLY]);
        assert!(matches!(freeze(&mut m, 1, 1000), Outcome::Done(Ok(0))));
        let r = cli.write_read(&mut m, &call(BC_TRANSACTION, 0, 1, 0, 0x3100, 5), true).unwrap();
        assert_eq!(words(&r), [BR_NOOP, BR_FROZEN_REPLY]);
    }

    /// The buffer a process mapped is given out smallest fit first, in
    /// whole words, and what is freed joins what is free beside it.
    #[test]
    fn the_mapped_buffer_is_shared_out_and_joined_again() {
        let mut st = State::default();
        st.procs.insert(1, Proc::default());
        let whole = Buffer::free(0x100);
        let p = st.procs.get_mut(&1).unwrap();
        p.map = Some((0x4000, 0x100));
        p.free_async = 0x80;
        p.buffers.insert(0x4000, whole);
        let a = st.alloc(1, 5, false, 9).ok().unwrap();
        let b = st.alloc(1, 0, false, 9).ok().unwrap();
        let c = st.alloc(1, 0x40, true, 9).ok().unwrap();
        assert_eq!((a, b, c), (0x4000, 0x4008, 0x4010));
        // One-way calls may fill half the buffer, and no more.
        assert!(st.alloc(1, 0x48, true, 9).is_err());
        assert!(st.alloc(1, 0x1000, false, 9).is_err());
        // With a tenth of the buffer left for one-way calls, the sender
        // that holds more than a quarter of it is named, and named once.
        assert!(!st.procs[&1].buffers[&c].spam_suspect);
        let d = st.alloc(1, 0x30, true, 9).ok().unwrap();
        assert!(st.procs[&1].buffers[&d].spam_suspect);
        st.release(1, d);
        let d = st.alloc(1, 0x30, true, 9).ok().unwrap();
        assert!(!st.procs[&1].buffers[&d].spam_suspect);
        st.release(1, d);
        st.release(1, b);
        st.release(1, a);
        // The two freed ranges are one, and the smallest that fits is used.
        assert_eq!(st.alloc(1, 0x10, false, 9).ok().unwrap(), 0x4000);
        st.release(1, 0x4000);
        st.release(1, c);
        let p = &st.procs[&1];
        assert_eq!(p.buffers.len(), 1);
        assert!(p.buffers[&0x4000].free && p.buffers[&0x4000].size == 0x100 && p.free_async == 0x80);
    }
}
