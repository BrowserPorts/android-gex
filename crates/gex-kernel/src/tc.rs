//! Traffic control over `NETLINK_ROUTE`: queueing disciplines and
//! classifiers as Android uses them, after net/sched at Android's
//! android17-6.18 (sch_api.c, sch_ingress.c, sch_generic.c, cls_api.c,
//! cls_bpf.c; the spec, with the source line for each answer, is
//! tc-spec.md in the oracle's drafts).
//!
//! netd sends `RTM_DELQDISC` of `clsact` for every interface at its start
//! (an `ENOENT` on a fresh kernel, which it ignores); netd's route
//! controller adds and removes `clsact` as interfaces join physical and
//! local networks; clat and tethering attach BPF classifiers to its
//! ingress and egress blocks (libtcutils). Here:
//!
//! - every device's root is its default qdisc (`noqueue`, or `pfifo_fast`
//!   for a TUN device: [`crate::netdev::NetDev::qdisc`]), there from its
//!   first up, and cannot be replaced (refused loudly);
//! - its ingress slot holds `clsact` or `ingress`, made, changed, deleted
//!   and asked about as `tc_modify_qdisc` and `tc_get_qdisc` do, every
//!   check in their order and with their errno;
//! - `clsact`'s two blocks and `ingress`'s one hold chains of classifiers
//!   by priority and protocol; kind `bpf`, a `BPF_PROG_TYPE_SCHED_CLS`
//!   program by descriptor, direct action or not, added, deleted, asked
//!   about and dumped as `cls_api.c` and `cls_bpf.c` do;
//! - dumps, and notifications to `RTNLGRP_TC` (to the asker too with
//!   `NLM_F_ECHO`).
//!
//! No packet passes a device here, so no classifier ever runs: a program
//! is attached and kept, and that is all. Not here, and refused loudly:
//! other classifier kinds (`matchall`, `u32`, ...), actions, classic BPF,
//! shared blocks, root qdiscs other than the default, statistics other
//! than zeros.

use crate::errno::Errno;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
/// `RTNLGRP_TC`.
const RTNLGRP_TC: u32 = 4;

const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ECHO: u16 = 0x8;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

const TC_H_ROOT: u32 = 0xFFFF_FFFF;
const TC_H_INGRESS: u32 = 0xFFFF_FFF1;
const TC_H_MAJ: u32 = 0xFFFF_0000;
const INGRESS_HANDLE: u32 = 0xFFFF_0000;
const TC_H_MIN_INGRESS: u32 = 0xFFF2;
const TC_H_MIN_EGRESS: u32 = 0xFFF3;
/// `TCM_IFINDEX_MAGIC_BLOCK`.
const MAGIC_BLOCK: u32 = 0xFFFF_FFFF;
/// `TC_ACT_EXT_VAL_MASK`: the highest chain index.
const CHAIN_MAX: u32 = 0x0FFF_FFFF;
/// `BPF_PROG_TYPE_SCHED_CLS`.
const SCHED_CLS: u32 = 3;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_STATS: u16 = 3;
const TCA_STATS2: u16 = 7;
const TCA_CHAIN: u16 = 11;
const TCA_HW_OFFLOAD: u16 = 12;
const TCA_INGRESS_BLOCK: u16 = 13;
const TCA_EGRESS_BLOCK: u16 = 14;
const TCA_STATS_BASIC: u16 = 1;
const TCA_STATS_QUEUE: u16 = 3;

const TCA_BPF_ACT: u16 = 1;
const TCA_BPF_POLICE: u16 = 2;
const TCA_BPF_CLASSID: u16 = 3;
const TCA_BPF_OPS_LEN: u16 = 4;
const TCA_BPF_OPS: u16 = 5;
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAGS_GEN: u16 = 9;
const TCA_BPF_TAG: u16 = 10;
const TCA_BPF_ID: u16 = 11;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;
const TCA_CLS_FLAGS_SKIP_HW: u32 = 1;
const TCA_CLS_FLAGS_SKIP_SW: u32 = 2;
const TCA_CLS_FLAGS_NOT_IN_HW: u32 = 8;

/// The qdisc kinds GKI's configuration builds, which this kernel knows of
/// (only the defaults, `clsact` and `ingress` it has).
const QDISC_KINDS: &[&str] = &[
    "pfifo_fast", "pfifo", "bfifo", "pfifo_head_drop", "mq", "noqueue", "htb", "prio", "multiq", "sfq", "tbf", "netem", "codel", "fq_codel", "fq", "ingress", "clsact",
];
/// The classifier kinds it builds (only `bpf` here).
const CLS_KINDS: &[&str] = &["basic", "fw", "u32", "flow", "cgroup", "bpf", "matchall"];

/// A BPF classifier.
#[derive(Clone)]
struct Filter {
    handle: u32,
    prog: Arc<crate::bpfprog::Prog>,
    /// `TCA_BPF_NAME` as given (dumped to its first NUL).
    name: Option<Vec<u8>>,
    direct: bool,
    gen_flags: u32,
    classid: u32,
}

/// A classifier instance of one priority and protocol (`tcf_proto`).
#[derive(Clone)]
struct Tp {
    /// `TC_H_MAJ` of `tcm_info`, as kept.
    prio: u32,
    protocol: u16,
    kind: String,
    /// Newest first (`list_add_rcu`).
    filters: Vec<Filter>,
}

#[derive(Clone, Default)]
struct Block {
    /// The parent of the last `RTM_NEWTFILTER` on it, which its dumps say.
    classid: u32,
    /// Chains by index, each its classifiers by ascending priority. A
    /// chain is there while it holds one.
    chains: BTreeMap<u32, Vec<Tp>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IngressKind {
    Ingress,
    Clsact,
}

impl IngressKind {
    fn name(self) -> &'static str {
        match self {
            IngressKind::Ingress => "ingress",
            IngressKind::Clsact => "clsact",
        }
    }
}

#[derive(Clone)]
struct Ingress {
    kind: IngressKind,
    /// `clsact`'s ingress and egress blocks; `ingress` has the first.
    blocks: [Block; 2],
}

#[derive(Default)]
struct DevTc {
    /// `dev->ingress_queue`: made by the first `RTM_NEWQDISC` with the
    /// ingress parent, kept after its qdisc goes.
    queue: bool,
    ingress: Option<Ingress>,
}

fn state() -> MutexGuard<'static, HashMap<u32, DevTc>> {
    static S: OnceLock<Mutex<HashMap<u32, DevTc>>> = OnceLock::new();
    S.get_or_init(Mutex::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// A device's qdiscs and classifiers go with it (`dev_shutdown`), and no
/// notification says so.
pub fn forget(index: u32) {
    state().remove(&index);
}

thread_local! {
    /// The programs the `TCA_BPF_FD`s of the datagram being sent name, as
    /// the sender's descriptors resolved them ([`Progs::enter`]).
    static PROGS: std::cell::RefCell<Vec<(i32, Result<Arc<crate::bpfprog::Prog>, Errno>)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The programs a datagram's classifier requests name, resolved in the
/// sender's descriptor table while it is sent: a netlink request is
/// answered in the socket, which has none.
pub struct Progs(Vec<(i32, Result<Arc<crate::bpfprog::Prog>, Errno>)>);

impl Progs {
    pub fn enter(progs: Vec<(i32, Result<Arc<crate::bpfprog::Prog>, Errno>)>) -> Progs {
        Progs(PROGS.with(|p| std::mem::replace(&mut *p.borrow_mut(), progs)))
    }
}

impl Drop for Progs {
    fn drop(&mut self) {
        let old = std::mem::take(&mut self.0);
        PROGS.with(|p| *p.borrow_mut() = old);
    }
}

/// The descriptors the `RTM_NEWTFILTER`s of a datagram name as programs,
/// each as `fd` names it (`bpf_prog_get_type_dev`): `EBADF` for none,
/// `EINVAL` for one that is not a `BPF_PROG_TYPE_SCHED_CLS` program.
pub fn progs_named(data: &[u8], file: &dyn Fn(i32) -> Result<Arc<crate::file::OpenFile>, Errno>) -> Vec<(i32, Result<Arc<crate::bpfprog::Prog>, Errno>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= data.len() {
        let len = u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
        if len < 16 || at + len > data.len() {
            break;
        }
        let kind = u16::from_le_bytes(data[at + 4..at + 6].try_into().unwrap());
        if kind == RTM_NEWTFILTER && len >= 36 {
            for (t, v) in attrs(&data[at + 36..at + len]) {
                if t == TCA_OPTIONS {
                    for (t, v) in attrs(v) {
                        if t == TCA_BPF_FD && v.len() >= 4 {
                            let fd = i32::from_le_bytes(v[..4].try_into().unwrap());
                            let p = file(fd).and_then(|f| match f.handle.bpf_object() {
                                Some(crate::bpf::Object::Prog(p)) if p.ty == SCHED_CLS => Ok(p),
                                _ => Err(Errno::EINVAL),
                            });
                            out.push((fd, p));
                        }
                    }
                }
            }
        }
        at += (len + 3) & !3;
    }
    out
}

fn prog_for(fd: i32) -> Result<Arc<crate::bpfprog::Prog>, Errno> {
    PROGS.with(|p| p.borrow().iter().find(|(f, _)| *f == fd).map(|(_, r)| r.clone())).unwrap_or(Err(Errno::EBADF))
}

/// A netlink message's attributes, as `(type, payload)` (`NLA_TYPE_MASK`).
fn attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_le_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_le_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            break;
        }
        v.push((ty, &b[4..len]));
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    v
}

fn put(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn message(kind: u16, flags: u16, seq: u32, portid: u32, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + body.len());
    m.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    m.extend_from_slice(&kind.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&portid.to_le_bytes());
    m.extend_from_slice(body);
    while m.len() % 4 != 0 {
        m.push(0);
    }
    m
}

fn tcmsg(ifindex: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&ifindex.to_le_bytes());
    b.extend_from_slice(&handle.to_le_bytes());
    b.extend_from_slice(&parent.to_le_bytes());
    b.extend_from_slice(&info.to_le_bytes());
    b
}

/// A request's `TCA_*` attributes, checked as `rtm_tca_policy` checks
/// them (liberally: unknown ones ignored).
struct Req<'a> {
    flags: u16,
    seq: u32,
    portid: u32,
    ifindex: u32,
    handle: u32,
    parent: u32,
    info: u32,
    kind: Option<&'a [u8]>,
    options: Option<&'a [u8]>,
    chain: Option<u32>,
    ingress_block: Option<u32>,
    egress_block: Option<u32>,
}

fn parse(req: &[u8], portid: u32) -> Result<Req<'_>, Errno> {
    if req.len() < 36 {
        return Err(Errno::EINVAL);
    }
    let u = |at: usize| u32::from_le_bytes(req[at..at + 4].try_into().unwrap());
    let mut r = Req {
        flags: u16::from_le_bytes(req[6..8].try_into().unwrap()),
        seq: u(8),
        portid,
        ifindex: u(20),
        handle: u(24),
        parent: u(28),
        info: u(32),
        kind: None,
        options: None,
        chain: None,
        ingress_block: None,
        egress_block: None,
    };
    let u32_of = |v: &[u8]| if v.len() < 4 { Err(Errno::ERANGE) } else { Ok(u32::from_le_bytes(v[..4].try_into().unwrap())) };
    for (t, v) in attrs(&req[36..]) {
        match t {
            TCA_KIND => {
                if v.is_empty() {
                    return Err(Errno::ERANGE);
                }
                r.kind = Some(v.strip_suffix(&[0]).unwrap_or(v));
            }
            TCA_OPTIONS => r.options = Some(v),
            TCA_CHAIN => r.chain = Some(u32_of(v)?),
            TCA_INGRESS_BLOCK => r.ingress_block = Some(u32_of(v)?),
            TCA_EGRESS_BLOCK => r.egress_block = Some(u32_of(v)?),
            _ => {}
        }
    }
    Ok(r)
}

/// What a request answers: messages for the asker before its
/// acknowledgement, or an error.
pub type Answer = Result<Vec<u8>, Errno>;

/// A request of one of the six types (`rtnetlink_rcv_msg`'s dispatch to
/// sch_api.c and cls_api.c): `None` for a dump, whose messages and end
/// the caller sends, as for every dump.
pub fn request(req: &[u8], net_admin: bool, portid: u32) -> Answer {
    let kind = u16::from_le_bytes(req[4..6].try_into().unwrap());
    // `nlmsg_len(nlh) < sizeof(struct rtgenmsg)`: nothing done, success.
    if req.len() < 17 {
        return Ok(Vec::new());
    }
    if matches!(kind, RTM_NEWQDISC | RTM_DELQDISC | RTM_NEWTFILTER | RTM_DELTFILTER) && !net_admin {
        return Err(Errno::EPERM);
    }
    let r = parse(req, portid)?;
    match kind {
        RTM_NEWQDISC => modify_qdisc(&r),
        RTM_DELQDISC | RTM_GETQDISC => get_qdisc(&r, kind == RTM_DELQDISC),
        RTM_NEWTFILTER => new_tfilter(&r),
        RTM_DELTFILTER => del_tfilter(&r),
        RTM_GETTFILTER => get_tfilter(&r),
        _ => Err(Errno::EOPNOTSUPP),
    }
}

/// A dump's messages (`tc_dump_qdisc`, `tc_dump_tfilter`).
pub fn dump(req: &[u8], seq: u32, portid: u32) -> Result<Vec<u8>, Errno> {
    let kind = u16::from_le_bytes(req[4..6].try_into().unwrap());
    if kind == RTM_GETTFILTER {
        // A request too short, a device not there, no block: nothing.
        let Ok(r) = parse(req, portid) else { return Ok(Vec::new()) };
        return Ok(dump_filters(&r, seq));
    }
    if req.len() >= 36 {
        parse(req, portid)?;
    }
    let mut out = Vec::new();
    let s = state();
    for d in crate::netdev::all() {
        if d.qdisc != "noop" {
            out.extend(message(RTM_NEWQDISC, NLM_F_MULTI, seq, portid, &fill_root(d.index, d.qdisc, TC_H_ROOT)));
        }
        if let Some(ing) = s.get(&d.index).and_then(|t| t.ingress.as_ref()) {
            out.extend(message(RTM_NEWQDISC, NLM_F_MULTI, seq, portid, &fill_ingress(d.index, ing.kind, TC_H_INGRESS, 1)));
        }
    }
    Ok(out)
}

/// Is `flags` the request's for a dump.
pub fn is_dump(req: &[u8]) -> bool {
    let flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    flags & NLM_F_DUMP == NLM_F_DUMP
}

/// The statistics every qdisc message ends with, all zero here
/// (`gnet_stats_start_copy_compat`): `TCA_STATS2` with the basic and queue
/// counters, then `TCA_STATS`.
fn stats(b: &mut Vec<u8>) {
    let mut s2 = Vec::new();
    put(&mut s2, TCA_STATS_BASIC, &[0; 16]);
    put(&mut s2, TCA_STATS_QUEUE, &[0; 20]);
    put(b, TCA_STATS2, &s2);
    put(b, TCA_STATS, &[0; 40]);
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// A device's default root (`tc_fill_qdisc`): handle 0, refcount 2.
fn fill_root(ifindex: u32, kind: &str, parent: u32) -> Vec<u8> {
    let mut b = tcmsg(ifindex, 0, parent, 2);
    put(&mut b, TCA_KIND, &cstr(kind));
    if kind == "pfifo_fast" {
        // `struct tc_prio_qopt`: three bands and the priority map.
        let mut o = 3i32.to_le_bytes().to_vec();
        o.extend_from_slice(&[1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]);
        put(&mut b, TCA_OPTIONS, &o);
    }
    put(&mut b, TCA_HW_OFFLOAD, &[0]);
    stats(&mut b);
    b
}

/// An ingress or clsact qdisc: handle `ffff:`, an empty options nest.
fn fill_ingress(ifindex: u32, kind: IngressKind, parent: u32, refcnt: u32) -> Vec<u8> {
    let mut b = tcmsg(ifindex, INGRESS_HANDLE, parent, refcnt);
    put(&mut b, TCA_KIND, &cstr(kind.name()));
    put(&mut b, TCA_OPTIONS, &[]);
    put(&mut b, TCA_HW_OFFLOAD, &[0]);
    stats(&mut b);
    b
}

/// What a qdisc lookup finds.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Q {
    /// The builtin placeholder: a root before the device was first up, an
    /// empty ingress slot. Never dumped or notified.
    Noop,
    Root(&'static str),
    Ingress(IngressKind),
}

impl Q {
    fn handle(self) -> u32 {
        match self {
            Q::Ingress(_) => INGRESS_HANDLE,
            _ => 0,
        }
    }
    fn kind(self) -> &'static str {
        match self {
            Q::Noop => "noop",
            Q::Root(k) => k,
            Q::Ingress(k) => k.name(),
        }
    }
}

fn root_of(dev: &crate::netdev::NetDev) -> Q {
    if dev.qdisc == "noop" {
        Q::Noop
    } else {
        Q::Root(dev.qdisc)
    }
}

/// `qdisc_lookup`: by handle, none for 0; only the ingress qdisc has one.
fn lookup(t: Option<&DevTc>, handle: u32) -> Option<Q> {
    if handle == 0 {
        return None;
    }
    let ing = t.and_then(|t| t.ingress.as_ref())?;
    (handle == INGRESS_HANDLE).then_some(Q::Ingress(ing.kind))
}

fn kind_is(k: Option<&[u8]>, name: &str) -> bool {
    k.is_none_or(|k| k == name.as_bytes())
}

/// To the group, and to the asker with `NLM_F_ECHO` (its copy among its
/// answers).
fn notify(r: &Req<'_>, msgs: Vec<u8>, echo_to: &mut Vec<u8>) {
    if r.flags & NLM_F_ECHO != 0 {
        echo_to.extend_from_slice(&msgs);
    }
    crate::netlink::route_notify(msgs, RTNLGRP_TC);
}

/// `tc_modify_qdisc`.
fn modify_qdisc(r: &Req<'_>) -> Answer {
    let dev = crate::netdev::by_index(r.ifindex).ok_or(Errno::ENODEV)?;
    let mut s = state();
    let clid = r.parent;
    let mut q: Option<Q>;
    if clid != 0 {
        if clid == TC_H_ROOT {
            q = Some(root_of(&dev));
        } else if clid == TC_H_INGRESS {
            let t = s.entry(r.ifindex).or_default();
            t.queue = true;
            q = Some(t.ingress.as_ref().map_or(Q::Noop, |i| Q::Ingress(i.kind)));
        } else {
            match lookup(s.get(&r.ifindex), clid & TC_H_MAJ) {
                None => return Err(Errno::ENOENT),
                Some(Q::Ingress(_)) => return Err(Errno::EOPNOTSUPP),
                Some(_) => return Err(Errno::EOPNOTSUPP),
            }
        }
        // "It may be default qdisc, ignore it."
        if q.is_some_and(|q| q.handle() == 0) {
            q = None;
        }
        let mut create = false;
        let mut skip_create_check = false;
        if q.is_none() || r.handle == 0 || q.is_some_and(|q| q.handle() != r.handle) {
            if r.handle != 0 {
                if q.is_some() && r.flags & NLM_F_REPLACE == 0 {
                    return Err(Errno::EEXIST);
                }
                if r.handle & 0xFFFF != 0 {
                    return Err(Errno::EINVAL);
                }
                match lookup(s.get(&r.ifindex), r.handle) {
                    None => create = true,
                    Some(found) => {
                        let parent = if matches!(found, Q::Ingress(_)) { TC_H_INGRESS } else { TC_H_ROOT };
                        if parent != r.parent {
                            return Err(Errno::EINVAL);
                        }
                        if r.flags & NLM_F_EXCL != 0 {
                            return Err(Errno::EEXIST);
                        }
                        if !kind_is(r.kind, found.kind()) {
                            return Err(Errno::EINVAL);
                        }
                        // Ingress and clsact cannot be grafted.
                        return Err(Errno::EINVAL);
                    }
                }
            } else if q.is_none() {
                create = true;
            } else if r.kind.is_some_and(|k| k != q.unwrap().kind().as_bytes()) {
                let f = r.flags;
                if (f & NLM_F_CREATE != 0 && f & NLM_F_REPLACE != 0) || (f & NLM_F_CREATE != 0 && f & NLM_F_EXCL != 0) {
                    create = true;
                } else if f & (NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL) == 0 {
                    create = true;
                    skip_create_check = true;
                }
            }
        }
        if create {
            if !skip_create_check && r.flags & NLM_F_CREATE == 0 {
                return Err(Errno::ENOENT);
            }
            return create_qdisc(&mut s, r, clid);
        }
    } else {
        if r.handle == 0 {
            return Err(Errno::EINVAL);
        }
        q = lookup(s.get(&r.ifindex), r.handle);
    }
    // A change.
    let Some(q) = q else { return Err(Errno::ENOENT) };
    if r.flags & NLM_F_EXCL != 0 {
        return Err(Errno::EEXIST);
    }
    if !kind_is(r.kind, q.kind()) {
        return Err(Errno::EINVAL);
    }
    if r.options.is_some() {
        // No `->change` for ingress or clsact.
        return Err(Errno::EINVAL);
    }
    let Q::Ingress(k) = q else { return Err(Errno::EINVAL) };
    let mut echo = Vec::new();
    notify(r, message(RTM_NEWQDISC, 0, r.seq, r.portid, &fill_ingress(r.ifindex, k, clid, 1)), &mut echo);
    Ok(echo)
}

/// `qdisc_create` and its graft, for the ingress slot (and the refusals
/// for the root, which keeps its default).
fn create_qdisc(s: &mut HashMap<u32, DevTc>, r: &Req<'_>, clid: u32) -> Answer {
    let name = r.kind.map(|k| String::from_utf8_lossy(k).into_owned());
    let Some(name) = name.filter(|n| QDISC_KINDS.contains(&n.as_str())) else { return Err(Errno::ENOENT) };
    let kind = match name.as_str() {
        "clsact" => Some(IngressKind::Clsact),
        "ingress" => Some(IngressKind::Ingress),
        _ => None,
    };
    if clid == TC_H_INGRESS && kind.is_none() {
        return Err(Errno::EINVAL);
    }
    for b in [r.ingress_block, r.egress_block].into_iter().flatten() {
        if b == 0 {
            return Err(Errno::EINVAL);
        }
    }
    if r.egress_block.is_some() && kind == Some(IngressKind::Ingress) || (r.ingress_block.is_some() || r.egress_block.is_some()) && kind.is_none() {
        return Err(Errno::EOPNOTSUPP);
    }
    let Some(kind) = kind else {
        crate::bpf::say_once(&format!("a root qdisc of kind {name} (only a device's default)"));
        return Err(Errno::EOPNOTSUPP);
    };
    // `clsact_init`/`ingress_init`: only under the ingress parent.
    if clid != TC_H_INGRESS {
        return Err(Errno::EOPNOTSUPP);
    }
    if r.ingress_block.is_some() || r.egress_block.is_some() {
        crate::bpf::say_once("shared tc blocks (TCA_INGRESS_BLOCK, TCA_EGRESS_BLOCK)");
        return Err(Errno::EOPNOTSUPP);
    }
    let t = s.entry(r.ifindex).or_default();
    let old = t.ingress.replace(Ingress { kind, blocks: [Block::default(), Block::default()] });
    // One datagram: the old occupant's deletion, the new one's arrival
    // (`NLM_F_REPLACE`: the slot held something, if only the placeholder).
    let mut msgs = Vec::new();
    if let Some(o) = old {
        msgs.extend(message(RTM_DELQDISC, 0, r.seq, r.portid, &fill_ingress(r.ifindex, o.kind, clid, 0)));
    }
    msgs.extend(message(RTM_NEWQDISC, NLM_F_REPLACE, r.seq, r.portid, &fill_ingress(r.ifindex, kind, clid, 1)));
    let mut echo = Vec::new();
    notify(r, msgs, &mut echo);
    Ok(echo)
}

/// `tc_get_qdisc`, for `RTM_DELQDISC` (`del`) and `RTM_GETQDISC`.
fn get_qdisc(r: &Req<'_>, del: bool) -> Answer {
    let dev = crate::netdev::by_index(r.ifindex).ok_or(Errno::ENODEV)?;
    let mut s = state();
    let clid = r.parent;
    let q = if clid != 0 {
        let q = if clid != TC_H_ROOT && clid & TC_H_MAJ != INGRESS_HANDLE {
            // A class of a classful qdisc: none here.
            return Err(Errno::ENOENT);
        } else if clid & TC_H_MAJ == INGRESS_HANDLE {
            s.get(&r.ifindex).filter(|t| t.queue).map(|t| t.ingress.as_ref().map_or(Q::Noop, |i| Q::Ingress(i.kind)))
        } else {
            Some(root_of(&dev))
        };
        let Some(q) = q else { return Err(Errno::ENOENT) };
        if r.handle != 0 && q.handle() != r.handle {
            return Err(Errno::EINVAL);
        }
        q
    } else {
        lookup(s.get(&r.ifindex), r.handle).ok_or(Errno::ENOENT)?
    };
    if !kind_is(r.kind, q.kind()) {
        return Err(Errno::EINVAL);
    }
    let mut echo = Vec::new();
    if del {
        if clid == 0 {
            return Err(Errno::EINVAL);
        }
        if q.handle() == 0 {
            return Err(Errno::ENOENT);
        }
        let Q::Ingress(k) = q else { return Err(Errno::ENOENT) };
        if let Some(t) = s.get_mut(&r.ifindex) {
            t.ingress = None;
        }
        notify(r, message(RTM_DELQDISC, 0, r.seq, r.portid, &fill_ingress(r.ifindex, k, clid, 0)), &mut echo);
        return Ok(echo);
    }
    // A get answers the group, and the asker only with `NLM_F_ECHO`.
    let body = match q {
        Q::Noop => return Ok(echo),
        Q::Root(k) => fill_root(r.ifindex, k, clid),
        Q::Ingress(k) => fill_ingress(r.ifindex, k, clid, 1),
    };
    notify(r, message(RTM_NEWQDISC, 0, r.seq, r.portid, &body), &mut echo);
    Ok(echo)
}

/// `__tcf_qdisc_find` and the class and block lookups: the block a
/// filter request's parent names, with its index in the ingress qdisc.
fn block_of<'a>(s: &'a mut HashMap<u32, DevTc>, r: &Req<'_>) -> Result<&'a mut Block, Errno> {
    if r.ifindex == MAGIC_BLOCK {
        return Err(Errno::EINVAL);
    }
    let dev = crate::netdev::by_index(r.ifindex).ok_or(Errno::ENODEV)?;
    let ing = if r.parent == 0 {
        // The root: no class operations (noop, noqueue, pfifo_fast).
        let _ = root_of(&dev);
        return Err(Errno::EINVAL);
    } else {
        s.get_mut(&r.ifindex).and_then(|t| t.ingress.as_mut()).filter(|_| r.parent & TC_H_MAJ == INGRESS_HANDLE).ok_or(Errno::EINVAL)?
    };
    if r.kind.is_some_and(|k| k.len() > 15) {
        return Err(Errno::EINVAL);
    }
    let min = r.parent & 0xFFFF;
    let i = match ing.kind {
        IngressKind::Clsact => match min {
            0 => return Err(Errno::EINVAL),
            TC_H_MIN_INGRESS => 0,
            TC_H_MIN_EGRESS => 1,
            _ => return Err(Errno::ENOENT),
        },
        IngressKind::Ingress => 0,
    };
    Ok(&mut ing.blocks[i])
}

/// A filter message (`tcf_fill_node`): the header alone for `None`.
fn fill_filter(ifindex: u32, parent: u32, tp: &Tp, chain: u32, f: Option<&Filter>) -> Vec<u8> {
    let mut b = tcmsg(ifindex, f.map_or(0, |f| f.handle), parent, tp.prio | tp.protocol as u32);
    put(&mut b, TCA_KIND, &cstr(&tp.kind));
    put(&mut b, TCA_CHAIN, &chain.to_le_bytes());
    if let Some(f) = f {
        let mut o = Vec::new();
        if f.classid != 0 {
            put(&mut o, TCA_BPF_CLASSID, &f.classid.to_le_bytes());
        }
        if let Some(n) = &f.name {
            let end = n.iter().position(|&c| c == 0).unwrap_or(n.len());
            let mut v = n[..end].to_vec();
            v.push(0);
            put(&mut o, TCA_BPF_NAME, &v);
        }
        put(&mut o, TCA_BPF_ID, &f.prog.id.to_le_bytes());
        put(&mut o, TCA_BPF_TAG, &f.prog.tag);
        if f.direct {
            put(&mut o, TCA_BPF_FLAGS, &TCA_BPF_FLAG_ACT_DIRECT.to_le_bytes());
        }
        put(&mut o, TCA_BPF_FLAGS_GEN, &f.gen_flags.to_le_bytes());
        put(&mut b, TCA_OPTIONS, &o);
    }
    b
}

fn chain_of(r: &Req<'_>) -> Result<u32, Errno> {
    let c = r.chain.unwrap_or(0);
    if c > CHAIN_MAX {
        return Err(Errno::EINVAL);
    }
    Ok(c)
}

/// `tc_new_tfilter` and `cls_bpf_change`.
fn new_tfilter(r: &Req<'_>) -> Answer {
    let mut prio = r.info & TC_H_MAJ;
    let protocol = (r.info & 0xFFFF) as u16;
    let auto = prio == 0;
    if auto && r.flags & NLM_F_CREATE == 0 {
        return Err(Errno::ENOENT);
    }
    let mut s = state();
    let block = block_of(&mut s, r)?;
    let chain_index = chain_of(r)?;
    block.classid = r.parent;
    let chain = block.chains.entry(chain_index).or_default();
    let existing = if auto { None } else { chain.iter().position(|tp| tp.prio == prio) };
    if let Some(i) = existing {
        if protocol != 0 && chain[i].protocol != protocol {
            if chain.is_empty() {
                block.chains.remove(&chain_index);
            }
            return Err(Errno::EINVAL);
        }
    }
    let created = existing.is_none();
    let i = match existing {
        Some(i) => i,
        None => {
            let fail = |block: &mut Block, e: Errno| {
                if block.chains.get(&chain_index).is_some_and(|c| c.is_empty()) {
                    block.chains.remove(&chain_index);
                }
                Err(e)
            };
            let Some(kind) = r.kind.filter(|_| protocol != 0) else { return fail(block, Errno::EINVAL) };
            if r.flags & NLM_F_CREATE == 0 {
                return fail(block, Errno::ENOENT);
            }
            let chain = block.chains.entry(chain_index).or_default();
            if auto {
                // `tcf_auto_prio`: under the lowest there is, else 0xC000.
                prio = chain.first().map_or(0xC000_0000, |tp| tp.prio.wrapping_sub(1) & TC_H_MAJ);
            }
            let name = String::from_utf8_lossy(kind).into_owned();
            if !CLS_KINDS.contains(&name.as_str()) {
                return fail(block, Errno::ENOENT);
            }
            if name != "bpf" {
                crate::bpf::say_once(&format!("tc classifiers of kind {name} (only bpf)"));
                return fail(block, Errno::EOPNOTSUPP);
            }
            let at = chain.partition_point(|tp| tp.prio < prio);
            chain.insert(at, Tp { prio, protocol, kind: name, filters: Vec::new() });
            at
        }
    };
    let chain = block.chains.get_mut(&chain_index).expect("made above");
    let undo = |chain: &mut Vec<Tp>| {
        if created {
            chain.remove(i);
        }
    };
    if r.kind.is_some_and(|k| k != chain[i].kind.as_bytes()) {
        undo(chain);
        return Err(Errno::EINVAL);
    }
    let found = (r.handle != 0).then(|| chain[i].filters.iter().position(|f| f.handle == r.handle)).flatten();
    if found.is_none() && r.flags & NLM_F_CREATE == 0 {
        undo(chain);
        return Err(Errno::ENOENT);
    }
    if found.is_some() && r.flags & NLM_F_EXCL != 0 {
        undo(chain);
        return Err(Errno::EEXIST);
    }
    let f = match bpf_change(r, &chain[i], found) {
        Ok(f) => f,
        Err(e) => {
            undo(chain);
            if chain.is_empty() {
                block.chains.remove(&chain_index);
            }
            return Err(e);
        }
    };
    let tp = &mut chain[i];
    match found {
        Some(at) => tp.filters[at] = f.clone(),
        None => tp.filters.insert(0, f.clone()),
    }
    let body = fill_filter(r.ifindex, r.parent, tp, chain_index, Some(&f));
    let mut echo = Vec::new();
    notify(r, message(RTM_NEWTFILTER, r.flags, r.seq, r.portid, &body), &mut echo);
    Ok(echo)
}

/// `cls_bpf_change`: the classifier the options make.
fn bpf_change(r: &Req<'_>, tp: &Tp, found: Option<usize>) -> Result<Filter, Errno> {
    let Some(opts) = r.options else { return Err(Errno::EINVAL) };
    let (mut fd, mut name, mut flags, mut gen, mut classid, mut ops, mut acts) = (None, None, 0u32, 0u32, 0u32, false, false);
    let u32_of = |v: &[u8]| if v.len() < 4 { Err(Errno::ERANGE) } else { Ok(u32::from_le_bytes(v[..4].try_into().unwrap())) };
    for (t, v) in attrs(opts) {
        match t {
            TCA_BPF_FD => fd = Some(u32_of(v)? as i32),
            TCA_BPF_NAME => {
                // `NLA_NUL_STRING` of at most 256.
                let end = v.iter().take(257).position(|&c| c == 0).ok_or(Errno::EINVAL)?;
                if end > 256 {
                    return Err(Errno::ERANGE);
                }
                name = Some(v.to_vec());
            }
            TCA_BPF_FLAGS => flags = u32_of(v)?,
            TCA_BPF_FLAGS_GEN => gen = u32_of(v)?,
            TCA_BPF_CLASSID => classid = u32_of(v)?,
            TCA_BPF_OPS | TCA_BPF_OPS_LEN => ops = true,
            TCA_BPF_ACT | TCA_BPF_POLICE => acts = true,
            _ => {}
        }
    }
    let handle = match found {
        Some(at) => tp.filters[at].handle,
        None if r.handle != 0 => r.handle,
        None => (1..).find(|h| !tp.filters.iter().any(|f| f.handle == *h)).unwrap_or(1),
    };
    if ops == fd.is_some() {
        return Err(Errno::EINVAL);
    }
    if acts {
        crate::bpf::say_once("tc actions on a bpf classifier");
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & !TCA_BPF_FLAG_ACT_DIRECT != 0 {
        return Err(Errno::EINVAL);
    }
    if gen & !(TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW) != 0 || gen & (TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW) == TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW {
        return Err(Errno::EINVAL);
    }
    let Some(fd) = fd else {
        crate::bpf::say_once("classic BPF (TCA_BPF_OPS) tc classifiers");
        return Err(Errno::EOPNOTSUPP);
    };
    let prog = prog_for(fd)?;
    // No device here offloads: skipping software leaves nowhere to run.
    if gen & TCA_CLS_FLAGS_SKIP_SW != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(Filter { handle, prog, name, direct: flags & TCA_BPF_FLAG_ACT_DIRECT != 0, gen_flags: gen | TCA_CLS_FLAGS_NOT_IN_HW, classid })
}

/// `tc_del_tfilter`.
fn del_tfilter(r: &Req<'_>) -> Answer {
    let prio = r.info & TC_H_MAJ;
    let protocol = (r.info & 0xFFFF) as u16;
    if prio == 0 && (protocol != 0 || r.handle != 0 || r.kind.is_some()) {
        return Err(Errno::ENOENT);
    }
    let mut s = state();
    let block = block_of(&mut s, r)?;
    let chain_index = chain_of(r)?;
    let Some(chain) = block.chains.get_mut(&chain_index) else {
        return if prio == 0 { Ok(Vec::new()) } else { Err(Errno::ENOENT) };
    };
    let mut echo = Vec::new();
    if prio == 0 {
        // The whole chain: a header message a classifier instance.
        let mut msgs = Vec::new();
        for tp in chain.iter() {
            msgs.extend(message(RTM_DELTFILTER, r.flags, r.seq, r.portid, &fill_filter(r.ifindex, r.parent, tp, chain_index, None)));
        }
        block.chains.remove(&chain_index);
        if !msgs.is_empty() {
            notify(r, msgs, &mut echo);
        }
        return Ok(echo);
    }
    let i = chain.iter().position(|tp| tp.prio == prio).ok_or(Errno::ENOENT)?;
    if protocol != 0 && chain[i].protocol != protocol {
        return Err(Errno::EINVAL);
    }
    if r.kind.is_some_and(|k| k != chain[i].kind.as_bytes()) {
        return Err(Errno::EINVAL);
    }
    if r.handle == 0 {
        let tp = chain.remove(i);
        let body = fill_filter(r.ifindex, r.parent, &tp, chain_index, None);
        if chain.is_empty() {
            block.chains.remove(&chain_index);
        }
        notify(r, message(RTM_DELTFILTER, r.flags, r.seq, r.portid, &body), &mut echo);
        return Ok(echo);
    }
    let at = chain[i].filters.iter().position(|f| f.handle == r.handle).ok_or(Errno::ENOENT)?;
    let body = fill_filter(r.ifindex, r.parent, &chain[i], chain_index, Some(&chain[i].filters[at]));
    chain[i].filters.remove(at);
    if chain[i].filters.is_empty() {
        chain.remove(i);
    }
    if chain.is_empty() {
        block.chains.remove(&chain_index);
    }
    notify(r, message(RTM_DELTFILTER, r.flags, r.seq, r.portid, &body), &mut echo);
    Ok(echo)
}

/// `tc_get_tfilter`: the filter, to the asker alone.
fn get_tfilter(r: &Req<'_>) -> Answer {
    let prio = r.info & TC_H_MAJ;
    let protocol = (r.info & 0xFFFF) as u16;
    if prio == 0 {
        return Err(Errno::ENOENT);
    }
    let mut s = state();
    let block = block_of(&mut s, r)?;
    let chain_index = chain_of(r)?;
    let chain = block.chains.get(&chain_index).ok_or(Errno::EINVAL)?;
    let tp = chain.iter().find(|tp| tp.prio == prio && (protocol == 0 || tp.protocol == protocol)).ok_or(Errno::ENOENT)?;
    if r.kind.is_some_and(|k| k != tp.kind.as_bytes()) {
        return Err(Errno::EINVAL);
    }
    let f = tp.filters.iter().find(|f| f.handle == r.handle && r.handle != 0).ok_or(Errno::ENOENT)?;
    Ok(message(RTM_NEWTFILTER, r.flags, r.seq, r.portid, &fill_filter(r.ifindex, r.parent, tp, chain_index, Some(f))))
}

/// `tc_dump_tfilter`: a block's classifiers, each instance's header and
/// then its programs, newest first.
fn dump_filters(r: &Req<'_>, seq: u32) -> Vec<u8> {
    let mut s = state();
    let Ok(block) = block_of(&mut s, r) else { return Vec::new() };
    let prio = r.info & TC_H_MAJ;
    let protocol = (r.info & 0xFFFF) as u16;
    let mut out = Vec::new();
    for (&c, chain) in &block.chains {
        if r.chain.is_some_and(|w| w != c) {
            continue;
        }
        for tp in chain.iter().filter(|tp| (prio == 0 || tp.prio == prio) && (protocol == 0 || tp.protocol == protocol)) {
            out.extend(message(RTM_NEWTFILTER, NLM_F_MULTI, seq, r.portid, &fill_filter(r.ifindex, block.classid, tp, c, None)));
            for f in &tp.filters {
                out.extend(message(RTM_NEWTFILTER, NLM_F_MULTI, seq, r.portid, &fill_filter(r.ifindex, block.classid, tp, c, Some(f))));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: u16, flags: u16, ifindex: u32, handle: u32, parent: u32, info: u32, attrs_: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = tcmsg(ifindex, handle, parent, info);
        for (t, v) in attrs_ {
            put(&mut b, *t, v);
        }
        message(kind, 0x1 | 0x4 | flags, 7, 0, &b)
    }

    /// Android's clsact requests as tcutils sends them, in the order its
    /// own test makes them: add, add again (EEXIST), replace (a change),
    /// delete, delete again (EINVAL: the ingress queue is there now).
    #[test]
    fn clsact_as_tcutils_asks() {
        let lo = crate::netdev::by_name("lo").expect("lo").index;
        forget(lo);
        let kind = vec![(TCA_KIND, b"clsact\0".to_vec())];
        let del = req(RTM_DELQDISC, 0, lo, INGRESS_HANDLE, TC_H_INGRESS, 0, &kind);
        assert_eq!(request(&del, true, 1).err(), Some(Errno::ENOENT), "no ingress queue yet");
        let add = req(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, lo, INGRESS_HANDLE, TC_H_INGRESS, 0, &kind);
        assert_eq!(request(&add, false, 1).err(), Some(Errno::EPERM));
        assert!(request(&add, true, 1).is_ok());
        assert_eq!(request(&add, true, 1).err(), Some(Errno::EEXIST));
        let replace = req(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, lo, INGRESS_HANDLE, TC_H_INGRESS, 0, &kind);
        assert!(request(&replace, true, 1).is_ok());
        assert!(request(&del, true, 1).is_ok());
        assert_eq!(request(&del, true, 1).err(), Some(Errno::EINVAL), "the queue stays");
        assert_eq!(request(&req(RTM_NEWQDISC, NLM_F_CREATE, 9999, 0, TC_H_INGRESS, 0, &kind), true, 1).err(), Some(Errno::ENODEV));
        assert_eq!(request(&req(RTM_NEWQDISC, NLM_F_CREATE, lo, 0, TC_H_INGRESS, 0, &[(TCA_KIND, b"pfifo\0".to_vec())]), true, 1).err(), Some(Errno::EINVAL));
        assert_eq!(request(&req(RTM_NEWQDISC, NLM_F_CREATE, lo, 0, TC_H_INGRESS, 0, &[(TCA_KIND, b"nosuch\0".to_vec())]), true, 1).err(), Some(Errno::ENOENT));
        assert_eq!(request(&req(RTM_NEWQDISC, NLM_F_CREATE, lo, 0, TC_H_ROOT, 0, &kind), true, 1).err(), Some(Errno::EOPNOTSUPP));
        forget(lo);
    }

    /// A message's size as Linux makes it: clsact's is 152 bytes, with
    /// zero statistics.
    #[test]
    fn qdisc_messages_are_linuxs_size() {
        assert_eq!(16 + fill_ingress(1, IngressKind::Clsact, TC_H_INGRESS, 1).len(), 152);
        assert_eq!(16 + fill_root(1, "noqueue", TC_H_ROOT).len(), 148);
        assert_eq!(16 + fill_root(1, "pfifo_fast", TC_H_ROOT).len(), 176);
    }

    /// Filter requests on a clsact with none: the parent is needed, a
    /// chain not there is ENOENT to delete and EINVAL to get.
    #[test]
    fn filters_need_a_parent_and_a_chain() {
        let d = crate::netdev::by_name("dummy0").expect("dummy0").index;
        forget(d);
        let info = (17 << 16) | 0x0300;
        let delf = req(RTM_DELTFILTER, 0, d, 0, 0xFFFF_FFF2, info, &[]);
        assert_eq!(request(&delf, true, 1).err(), Some(Errno::EINVAL), "no clsact");
        let kind = vec![(TCA_KIND, b"clsact\0".to_vec())];
        request(&req(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, d, INGRESS_HANDLE, TC_H_INGRESS, 0, &kind), true, 1).unwrap();
        assert_eq!(request(&delf, true, 1).err(), Some(Errno::ENOENT));
        let getf = req(RTM_GETTFILTER, 0, d, 1, 0xFFFF_FFF2, info, &[]);
        assert_eq!(request(&getf, true, 1).err(), Some(Errno::EINVAL));
        assert_eq!(request(&req(RTM_DELTFILTER, 0, d, 0, 0xFFFF_FFF2, 0, &[]), true, 1).err(), None, "flushing an empty chain");
        assert_eq!(request(&req(RTM_DELTFILTER, 0, d, 0, 0xFFFF_FFF2, 0x0300, &[]), true, 1).err(), Some(Errno::ENOENT));
        let bpf = vec![(TCA_KIND, b"bpf\0".to_vec())];
        assert_eq!(request(&req(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, d, 0, 0xFFFF_FFF1, info, &bpf), true, 1).err(), Some(Errno::ENOENT), "clsact's minor");
        assert_eq!(request(&req(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, d, 0, 0xFFFF_FFF2, 17 << 16, &bpf), true, 1).err(), Some(Errno::EINVAL), "no protocol");
        assert_eq!(request(&req(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, d, 0, 0xFFFF_FFF2, info, &[(TCA_KIND, b"nosuch\0".to_vec())]), true, 1).err(), Some(Errno::ENOENT));
        assert_eq!(request(&req(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, d, 0, 0xFFFF_FFF2, info, &bpf), true, 1).err(), Some(Errno::EINVAL), "no options");
        let mut fd = Vec::new();
        put(&mut fd, TCA_BPF_FD, &99i32.to_le_bytes());
        assert_eq!(request(&req(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, d, 0, 0xFFFF_FFF2, info, &[(TCA_KIND, b"bpf\0".to_vec()), (TCA_OPTIONS, fd)]), true, 1).err(), Some(Errno::EBADF));
        assert!(dump_filters(&parse(&req(RTM_GETTFILTER, NLM_F_DUMP, d, 0, 0xFFFF_FFF2, 0, &[]), 1).unwrap(), 7).is_empty(), "nothing left behind");
        forget(d);
    }
}
