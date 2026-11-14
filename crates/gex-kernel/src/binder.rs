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
//! is told when a process dies. It is written for this kernel, not ported:
//! the driver's state is one table under one lock ([`Context`]), a thread
//! that would sleep in the driver parks in the host instead and makes its
//! call again ([`Outcome::Wait`]), and a call's bytes are held here until
//! the target reads them, when they are written into its memory by its own
//! thread.
//!
//! Not here, and refused where asked for: scatter-gather buffers and
//! descriptor arrays (`BINDER_TYPE_PTR`, `BINDER_TYPE_FDA`, which hwbinder
//! uses), freezing, security contexts, priorities, and the debug queries.
//! The table lives in this process's memory, so a host whose guest
//! processes do not share it (the page's) has no binder yet.

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
    pub const SET_MAX_THREADS: u64 = 0x4004_6205;
    pub const SET_CONTEXT_MGR: u64 = 0x4004_6207;
    pub const THREAD_EXIT: u64 = 0x4004_6208;
    pub const VERSION: u64 = 0xc004_6209;
    pub const GET_NODE_INFO_FOR_REF: u64 = 0xc018_620c;
    pub const SET_CONTEXT_MGR_EXT: u64 = 0x4018_620d;
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

    // Returns ('r').
    pub const BR_OK: u32 = 0x0000_7201;
    pub const BR_TRANSACTION: u32 = 0x8040_7202;
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

    pub const TF_ONE_WAY: u32 = 0x01;
    pub const TF_ACCEPT_FDS: u32 = 0x10;
    pub const FLAT_BINDER_FLAG_ACCEPTS_FDS: u32 = 0x100;

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
}

/// What an ioctl came to.
pub enum Outcome {
    Done(SysResult),
    /// A read with nothing to return: what it wrote is done and recorded
    /// in the caller's `binder_write_read`; the thread waits until the
    /// handle is readable, then makes the call again.
    Wait(Arc<dyn FileHandle>),
}

/// One binder device's state (`struct binder_context` and everything that
/// hangs off the processes that opened it), under one lock.
pub struct Context {
    name: &'static str,
    st: Mutex<State>,
    /// Notified whenever work is queued for anyone.
    queue: crate::wait::Queue,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder context {}", self.name)
    }
}

/// The device named `name` (`binder`, `hwbinder`, `vndbinder`): one for
/// the machine.
pub fn context(name: &'static str) -> Arc<Context> {
    static ALL: Mutex<Vec<Arc<Context>>> = Mutex::new(Vec::new());
    let mut all = ALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = all.iter().find(|c| c.name == name) {
        return Arc::clone(c);
    }
    let c = Arc::new(Context { name, st: Mutex::new(State::default()), queue: crate::wait::Queue::new() });
    all.push(Arc::clone(&c));
    c
}

#[derive(Default)]
struct State {
    procs: HashMap<u64, Proc>,
    nodes: HashMap<u64, Node>,
    txns: HashMap<u64, Txn>,
    /// The context manager's node, and the euid that may be one.
    mgr: Option<u64>,
    mgr_uid: Option<u32>,
    next_id: u64,
}

#[derive(Default)]
struct Proc {
    pid: i32,
    euid: u32,
    dead: bool,
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
}

impl Default for Thread {
    fn default() -> Thread {
        Thread { todo: VecDeque::new(), process_todo: false, looper: 0, need_return: true, stack: None, ee: (0, BR_OK, 0) }
    }
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
}

/// A range of a process's mapping.
struct Buffer {
    size: u64,
    free: bool,
    allow_user_free: bool,
    /// The call whose bytes it holds, until that is done with.
    txn: Option<u64>,
    target_node: Option<u64>,
    is_async: bool,
    /// The objects in it, as the receiver has them: what freeing it lets go.
    objects: Vec<Object>,
}

#[derive(Clone, Copy)]
enum Object {
    /// A node of the receiver's: pointer, and whether strong.
    Binder(u64, bool),
    Handle(u32, bool),
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
    /// Where its bytes go in the target's mapping.
    buffer: Option<u64>,
    target_node: Option<u64>,
    /// The bytes, until the target reads the call: data padded to eight,
    /// then the offsets.
    bytes: Vec<u8>,
    data_size: u64,
    offsets_size: u64,
    /// Descriptors to put in the receiver's table: where each number goes
    /// in `bytes`, and the open file.
    fds: Vec<(usize, Arc<OpenFile>)>,
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
        let is_mgr = self.mgr == Some(node);
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
        let is_mgr = self.mgr == Some(node);
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
        p.refs.insert(h, Ref { node, strong: 0, weak: 0, death: None });
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
    fn alloc(&mut self, proc: u64, size: u64, is_async: bool) -> Result<u64, Fail> {
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
            p.buffers.insert(at + size, Buffer { size: have - size, free: true, allow_user_free: false, txn: None, target_node: None, is_async: false, objects: Vec::new() });
        }
        p.buffers.insert(at, Buffer { size, free: false, allow_user_free: false, txn: None, target_node: None, is_async, objects: Vec::new() });
        if is_async {
            p.free_async -= size;
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
        *b = Buffer { size: b.size, free: true, allow_user_free: false, txn: None, target_node: None, is_async: false, objects: Vec::new() };
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
        p.buffers.insert(start, Buffer { size, free: true, allow_user_free: false, txn: None, target_node: None, is_async: false, objects: Vec::new() });
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
    /// node) to the node's own.
    fn proc_transaction(&mut self, txn: u64, proc: u64, thread: Option<i32>) -> Result<(), Fail> {
        let (node, oneway) = {
            let t = &self.txns[&txn];
            (t.target_node, t.flags & TF_ONE_WAY != 0)
        };
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
        let dead = self.procs.get(&proc).is_none_or(|p| p.dead || thread.is_some_and(|t| !p.threads.contains_key(&t)));
        if dead {
            return Err(Fail(BR_DEAD_REPLY, Errno::ESRCH));
        }
        let thread = match thread {
            None if !pending_async => self.select_thread(proc),
            t => t,
        };
        match thread {
            Some(tid) => self.to_thread(proc, tid, Work::Txn(txn)),
            None if !pending_async => self.procs.get_mut(&proc).expect("the target").todo.push_back(Work::Txn(txn)),
            None => {
                if let Some(n) = node.and_then(|n| self.nodes.get_mut(&n)) {
                    n.async_todo.push_back(Work::Txn(txn));
                }
            }
        }
        Ok(())
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
        bytes: &mut [u8],
        at: usize,
        allows_fds: bool,
        objects: &mut Vec<Object>,
        fds: &mut Vec<(usize, Arc<OpenFile>)>,
    ) -> Result<(), Fail> {
        let bad = |e| Fail(BR_FAILED_REPLY, e);
        let u32_at = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |b: &[u8], i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
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
                fds.push((at + 8, file));
            }
            TYPE_PTR | TYPE_FDA => {
                unimplemented("a scatter-gather buffer or a descriptor array in a call (BINDER_TYPE_PTR, BINDER_TYPE_FDA)");
                return Err(bad(Errno::EINVAL));
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
                let n = self.mgr.ok_or(Fail(BR_DEAD_REPLY, Errno::ESRCH))?;
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

        // The bytes and the offsets of its objects, from the sender.
        if tr.offsets_size % 8 != 0 || extra % 8 != 0 {
            return Err(failed(Errno::EINVAL));
        }
        let data_len = align8(tr.data_size);
        let total = data_len.checked_add(tr.offsets_size).and_then(|n| n.checked_add(extra)).ok_or(failed(Errno::EINVAL))?;
        let mut bytes = vec![0u8; (data_len + tr.offsets_size) as usize];
        let fault = |_| failed(Errno::EFAULT);
        bytes[..tr.data_size as usize].copy_from_slice(m.read(tr.buffer, tr.data_size as usize).map_err(fault)?);
        bytes[data_len as usize..].copy_from_slice(m.read(tr.offsets, tr.offsets_size as usize).map_err(fault)?);
        let buffer = self.alloc(target_proc, total, !reply && oneway)?;

        let allows_fds = match in_reply_to {
            Some(t) => self.txns[&t].flags & TF_ACCEPT_FDS != 0,
            None => target_node.is_some_and(|n| self.nodes[&n].accept_fds),
        };
        let (mut objects, mut fds) = (Vec::new(), Vec::new());
        let mut least = 0u64;
        let mut failure = None;
        for i in 0..(tr.offsets_size / 8) as usize {
            let o = data_len as usize + i * 8;
            let at = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
            // In order, whole, and inside the data.
            if at < least || at % 4 != 0 || at.checked_add(OBJECT_SIZE as u64).is_none_or(|end| end > tr.data_size) {
                failure = Some(failed(Errno::EINVAL));
                break;
            }
            least = at + OBJECT_SIZE as u64;
            if let Err(f) = self.translate(cx, proc, target_proc, &mut bytes, at as usize, allows_fds, &mut objects, &mut fds) {
                failure = Some(f);
                break;
            }
        }
        if let Some(f) = failure {
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
                let me = self.thread(proc, tid);
                me.stack = parent;
                me.todo.retain(|w| !matches!(w, Work::Complete));
                self.abandon(id);
                return Err(f);
            }
        } else {
            self.to_thread(proc, tid, Work::Complete);
            if let Err(f) = self.proc_transaction(id, target_proc, None) {
                let me = self.thread(proc, tid);
                me.todo.retain(|w| !matches!(w, Work::Complete));
                self.abandon(id);
                return Err(f);
            }
        }
        Ok(())
    }

    /// A call that was built and could not be queued: its buffer and what
    /// its objects held go back.
    fn abandon(&mut self, txn: u64) {
        if let Some(t) = self.txns.remove(&txn) {
            if let (Some(proc), Some(at)) = (t.to_proc, t.buffer) {
                if let Some(b) = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&at)) {
                    b.txn = None;
                }
                self.free_buffer(proc, at);
            }
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
                        if let Some(mgr) = self.mgr {
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
                    if self.procs[&proc].buffers.get(&ptr).is_some_and(|b| !b.free && b.allow_user_free) {
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
            if cap - out.len().min(cap) < TR_SIZE + 4 {
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
            self.txns.remove(&id);
            return false;
        };
        // The descriptors, each close-on-exec; then the bytes, which the
        // kernel writes whatever the mapping allows the program.
        let mut installed = Vec::new();
        let mut ok = true;
        for (at, file) in std::mem::take(&mut t.fds) {
            match cx.fds.insert(file, true) {
                Ok(fd) => {
                    t.bytes[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes());
                    installed.push(fd as i32);
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
                self.txns.remove(&id);
                self.free_buffer(proc, buffer);
                out.extend_from_slice(&BR_FAILED_REPLY.to_le_bytes());
                return true;
            }
            if from_waits {
                self.send_failed_reply(id, BR_FAILED_REPLY);
            } else {
                self.txns.remove(&id);
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
        let code = if is_reply { BR_REPLY } else { BR_TRANSACTION };
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
        if let Some(b) = self.procs.get_mut(&proc).and_then(|p| p.buffers.get_mut(&buffer)) {
            b.allow_user_free = true;
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
                    self.txns.remove(&id);
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
        if self.mgr.is_some_and(|n| self.nodes.get(&n).is_some_and(|n| n.owner == Some(proc))) {
            self.mgr = None;
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
}

impl std::fmt::Debug for BinderFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binder {} #{}", self.ctx.name, self.id)
    }
}

impl BinderFile {
    pub fn open(ctx: Arc<Context>) -> BinderFile {
        let mut st = ctx.st.lock().unwrap_or_else(|e| e.into_inner());
        let id = st.id();
        st.procs.insert(id, Proc::default());
        drop(st);
        BinderFile { ctx, id }
    }

    /// One ioctl by `cx`'s thread.
    pub fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Outcome {
        let mut st = self.ctx.st.lock().unwrap_or_else(|e| e.into_inner());
        let p = st.procs.get_mut(&self.id).expect("this open's process");
        // The process is whoever used the device first; another (a child
        // that inherited the descriptor) may not use it.
        if p.pid == 0 {
            (p.pid, p.euid) = (cx.pid, cx.euid);
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
        self.ctx.queue.notify();
        out
    }

    fn ioctl_locked(&self, st: &mut State, cx: &Caller<'_>, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Outcome {
        let proc = self.id;
        let done = |r: Result<(), Errno>| Outcome::Done(r.map(|()| 0));
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
                if st.mgr.is_some() {
                    return Outcome::Done(Err(Errno::EBUSY));
                }
                // Whoever was first is the only one that may be again.
                match st.mgr_uid {
                    Some(uid) if uid != cx.euid => return Outcome::Done(Err(Errno::EPERM)),
                    _ => st.mgr_uid = Some(cx.euid),
                }
                let node = st.new_node(proc, 0, 0, flags);
                let n = st.nodes.get_mut(&node).expect("the node");
                n.local_weak += 1;
                n.local_strong += 1;
                n.has_strong = true;
                n.has_weak = true;
                st.mgr = Some(node);
                Outcome::Done(Ok(0))
            }
            THREAD_EXIT => {
                st.thread_release(proc, cx.tid);
                Outcome::Done(Ok(0))
            }
            GET_NODE_INFO_FOR_REF => {
                // {handle, strong_count, weak_count, reserved x3}: the
                // context manager's question about a handle it holds.
                let read = (|| {
                    let b = m.read(arg, 24)?;
                    let w = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
                    Ok::<_, Errno>([w(0), w(1), w(2), w(3), w(4), w(5)])
                })();
                let w = match read {
                    Ok(w) => w,
                    Err(e) => return Outcome::Done(Err(e)),
                };
                if w[1..].iter().any(|&x| x != 0) {
                    return Outcome::Done(Err(Errno::EINVAL));
                }
                if st.mgr.is_none_or(|n| st.nodes[&n].owner != Some(proc)) {
                    return Outcome::Done(Err(Errno::EPERM));
                }
                let Some(node) = st.procs[&proc].refs.get(&w[0]).map(|r| r.node) else { return Outcome::Done(Err(Errno::EINVAL)) };
                let n = &st.nodes[&node];
                let (strong, weak) = (n.local_strong + n.internal_strong, n.local_weak);
                done(m.write_u32(arg + 4, strong).and_then(|()| m.write_u32(arg + 8, weak)))
            }
            ENABLE_ONEWAY_SPAM_DETECTION => done(m.read_u32(arg).map(|_| ())),
            GET_EXTENDED_ERROR => {
                let t = st.thread(proc, cx.tid);
                let ee = std::mem::replace(&mut t.ee, (0, BR_OK, 0));
                done(m.write_u32(arg, ee.0).and_then(|()| m.write_u32(arg + 4, ee.1)).and_then(|()| m.write_u32(arg + 8, ee.2 as u32)))
            }
            WRITE_READ => self.write_read(st, cx, m, arg),
            _ => {
                unimplemented(&format!("ioctl {request:#x}"));
                Outcome::Done(Err(Errno::EINVAL))
            }
        }
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
                    return Outcome::Wait(Arc::new(Waiter { ctx: Arc::clone(&self.ctx), proc, tid: cx.tid }));
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
        let mut st = self.ctx.st.lock().unwrap_or_else(|e| e.into_inner());
        st.proc_release(self.id);
        drop(st);
        self.ctx.queue.notify();
    }
}

fn device_metadata() -> Metadata {
    Metadata { file_type: FileType::CharDevice, size: 0, mode: 0o666, ino: 1, mtime: 0, nlink: 1, rdev: 10 << 8, times: Default::default() }
}

impl FileHandle for BinderFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(device_metadata())
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
        let mut st = self.ctx.st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = st.procs.get_mut(&self.id) {
            if p.map.is_none() {
                p.map = Some((start, len));
                p.free_async = len / 2;
                p.buffers.insert(start, Buffer { size: len, free: true, allow_user_free: false, txn: None, target_node: None, is_async: false, objects: Vec::new() });
            }
        }
    }

    /// Readable when any of the process's threads has work
    /// (`binder_poll`, which asks for the polling thread alone).
    fn poll_readable(&self) -> bool {
        let st = self.ctx.st.lock().unwrap_or_else(|e| e.into_inner());
        st.procs.get(&self.id).is_some_and(|p| !p.todo.is_empty() || p.threads.values().any(|t| t.process_todo))
    }

    fn wait_queue(&self) -> u32 {
        self.ctx.queue.id()
    }
}

/// What a thread that waits in a read is parked on: readable when that
/// thread's read would return.
struct Waiter {
    ctx: Arc<Context>,
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
        self.ctx.st.lock().unwrap_or_else(|e| e.into_inner()).has_work(self.proc, self.tid)
    }

    fn wait_queue(&self) -> u32 {
        self.ctx.queue.id()
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
            let cx = Caller { pid: self.pid, tid: self.pid, euid: 1000, fds: &self.fds, nonblock: false };
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
        let name: &'static str = "unit-test";
        let ctx = context(name);
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

    /// The buffer a process mapped is given out smallest fit first, in
    /// whole words, and what is freed joins what is free beside it.
    #[test]
    fn the_mapped_buffer_is_shared_out_and_joined_again() {
        let mut st = State::default();
        st.procs.insert(1, Proc::default());
        let whole = Buffer { size: 0x100, free: true, allow_user_free: false, txn: None, target_node: None, is_async: false, objects: Vec::new() };
        let p = st.procs.get_mut(&1).unwrap();
        p.map = Some((0x4000, 0x100));
        p.free_async = 0x80;
        p.buffers.insert(0x4000, whole);
        let a = st.alloc(1, 5, false).ok().unwrap();
        let b = st.alloc(1, 0, false).ok().unwrap();
        let c = st.alloc(1, 0x40, true).ok().unwrap();
        assert_eq!((a, b, c), (0x4000, 0x4008, 0x4010));
        // One-way calls may fill half the buffer, and no more.
        assert!(st.alloc(1, 0x48, true).is_err());
        assert!(st.alloc(1, 0x1000, false).is_err());
        st.release(1, b);
        st.release(1, a);
        // The two freed ranges are one, and the smallest that fits is used.
        assert_eq!(st.alloc(1, 0x10, false).ok().unwrap(), 0x4000);
        st.release(1, 0x4000);
        st.release(1, c);
        let p = &st.procs[&1];
        assert_eq!(p.buffers.len(), 1);
        assert!(p.buffers[&0x4000].free && p.buffers[&0x4000].size == 0x100 && p.free_async == 0x80);
    }
}
