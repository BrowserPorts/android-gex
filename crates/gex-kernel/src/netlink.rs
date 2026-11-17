//! `AF_NETLINK` sockets: `NETLINK_ROUTE` and `NETLINK_KOBJECT_UEVENT`.
//!
//! A netlink socket ([`Socket`]) has a port and may listen to groups; a
//! datagram goes to a port, to a group, or to the kernel. Binding, naming,
//! the buffers' sizes, credentials, acknowledgements and what a listener
//! that falls behind is told are as `net/netlink/af_netlink.c` has them
//! (Linux 6.18), checked by `tests/android/src/uevent.c` on Linux 7.0.
//!
//! `NETLINK_KOBJECT_UEVENT` is where device events are broadcast (group
//! 1): Android's `ueventd` opens it before anything else and aborts
//! without it, and udev's monitor listens to it. The kernel's own events
//! are its devices' ([`uevent`], which sysfs calls); a process with
//! `CAP_SYS_ADMIN` can have a uevent broadcast too, as
//! `lib/kobject_uevent.c` lets it.
//!
//! `NETLINK_ROUTE` answers the dumps that list the machine's network
//! interfaces and their addresses, and nothing else.
//!
//! musl's `if_nameindex`, `if_nametoindex` and `getifaddrs` read them (its
//! `__rtnetlink_enumerate`): an `RTM_GETLINK` dump, then an `RTM_GETADDR`
//! one. With no route socket every one failed, `if_nameindex` with
//! `ENOBUFS`, and Wine's nsi (the table behind `GetAdaptersAddresses`,
//! `GetIfTable` and the rest of iphlpapi) logged
//! `if_nameindex failed, errno 105` and knew no interface at all -- not even
//! the loopback one every Windows machine has.
//!
//! The machine here has two: `lo` (127.0.0.1/8) and `eth0` (10.0.2.15/24,
//! the address QEMU's user network gives a guest). The guest's network is
//! the kernel's own in both modes (crate::net): it answers DNS with
//! synthetic addresses and hands each connection to the host by name -- a
//! host TCP socket natively, a Wisp stream in a page -- so the guest never
//! sees the host's interfaces or addresses, natively either. `eth0` is that
//! network's interface, the address a connected socket reports
//! (`getsockname`, [`local_for`]). IPv4 only, as that network is. glibc's `getaddrinfo` (`AI_ADDRCONFIG`)
//! reads the same dump and counts a non-loopback IPv4 address as "IPv4 is
//! there", so `eth0` keeps its A lookups, and with no IPv6 address it now
//! asks for no AAAA either.
//!
//! A request is answered as it is written: the dump, as one datagram ended by
//! `NLMSG_DONE`, waits for the next read. Any other request gets
//! `NLMSG_ERROR` with `EOPNOTSUPP` (when it asked for an acknowledgement or a
//! dump); nothing on this socket changes anything.

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x10000;
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const IFA_F_PERMANENT: u8 = 0x80;

/// One interface: its index, name, type, flags, MTU, hardware address, and
/// its IPv4 address with prefix length.
struct Iface {
    index: u32,
    name: &'static str,
    kind: u16,
    flags: u32,
    mtu: u32,
    mac: [u8; 6],
    addr: [u8; 4],
    prefix: u8,
}

/// The interfaces' names, in index order.
pub fn interface_names() -> Vec<&'static str> {
    IFACES.iter().map(|i| i.name).collect()
}

/// An interface's MTU, by name.
pub fn interface_mtu(name: &str) -> Option<u32> {
    IFACES.iter().find(|i| i.name == name).map(|i| i.mtu)
}

/// eth0's address: where a connected socket says it is (`getsockname`).
pub const ETH0_ADDR: [u8; 4] = [10, 0, 2, 15];

/// The address a socket connected to `peer` (host order) has: lo's for a
/// loopback peer, eth0's for any other. What `getsockname` reports for a
/// connected socket not bound to an address of its own.
pub fn local_for(peer: u32) -> u32 {
    if peer >> 24 == 127 {
        0x7f00_0001
    } else {
        u32::from_be_bytes(ETH0_ADDR)
    }
}

/// Whether there is a network interface of index `index`
/// (`dev_get_by_index`).
pub fn iface_exists(index: u32) -> bool {
    IFACES.iter().any(|i| i.index == index)
}

const IFACES: [Iface; 2] = [
    Iface {
        index: 1,
        name: "lo",
        kind: ARPHRD_LOOPBACK,
        flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
        mtu: 65536,
        mac: [0; 6],
        addr: [127, 0, 0, 1],
        prefix: 8,
    },
    Iface {
        index: 2,
        name: "eth0",
        kind: ARPHRD_ETHER,
        flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP,
        mtu: 1500,
        mac: [0x02, 0, 0, 0, 0, 0x01],
        addr: ETH0_ADDR,
        prefix: 24,
    },
];

/// Appends a `struct nlmsghdr` and `body`, padded to 4 bytes.
fn message(out: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, body: &[u8]) {
    let len = 16 + body.len();
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // from the kernel
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Appends a `struct rtattr` holding `data`, padded to 4 bytes.
fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// `RTM_NEWLINK` for each interface: `struct ifinfomsg` and its attributes.
fn links(out: &mut Vec<u8>, seq: u32) {
    for i in &IFACES {
        let mut b = vec![AF_UNSPEC, 0];
        b.extend_from_slice(&i.kind.to_le_bytes());
        b.extend_from_slice(&(i.index as i32).to_le_bytes());
        b.extend_from_slice(&i.flags.to_le_bytes());
        b.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // ifi_change
        attr(&mut b, IFLA_IFNAME, &cstr(i.name));
        attr(&mut b, IFLA_MTU, &i.mtu.to_le_bytes());
        attr(&mut b, IFLA_ADDRESS, &i.mac);
        let bcast = if i.kind == ARPHRD_ETHER { [0xff; 6] } else { [0; 6] };
        attr(&mut b, IFLA_BROADCAST, &bcast);
        message(out, RTM_NEWLINK, NLM_F_MULTI, seq, &b);
    }
}

/// `RTM_NEWADDR` for each interface's address: `struct ifaddrmsg` and its
/// attributes.
fn addrs(out: &mut Vec<u8>, seq: u32) {
    for i in &IFACES {
        let scope = if i.flags & IFF_LOOPBACK != 0 { RT_SCOPE_HOST } else { RT_SCOPE_UNIVERSE };
        let mut b = vec![AF_INET, i.prefix, IFA_F_PERMANENT, scope];
        b.extend_from_slice(&i.index.to_le_bytes());
        attr(&mut b, IFA_ADDRESS, &i.addr);
        attr(&mut b, IFA_LOCAL, &i.addr);
        if i.flags & IFF_BROADCAST != 0 {
            let host = u32::MAX >> i.prefix;
            let bcast = (u32::from_be_bytes(i.addr) | host).to_be_bytes();
            attr(&mut b, IFA_BROADCAST, &bcast);
        }
        attr(&mut b, IFA_LABEL, &cstr(i.name));
        message(out, RTM_NEWADDR, NLM_F_MULTI, seq, &b);
    }
}

/// The reply to one request (`nlmsghdr` + body), if it is owed one.
fn route_answer(req: &[u8], net_admin: bool) -> Option<Vec<u8>> {
    let kind = u16::from_le_bytes(req[4..6].try_into().unwrap());
    let flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    // rtgenmsg / ifinfomsg / ifaddrmsg all start with the family.
    let family = req.get(16).copied().unwrap_or(AF_UNSPEC);
    let mut out = Vec::new();
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    // A change, refused or done (`rtnetlink_rcv_msg`: anything but a GET
    // takes CAP_NET_ADMIN), acknowledged when asked; an error is always
    // said, with the request after it.
    let change = |r: Result<(), Errno>| change_reply(req, r);
    let ifindex = |name: &str| IFACES.iter().find(|i| i.name == name).map(|i| i.index);
    match kind {
        crate::fibrules::RTM_NEWRULE | crate::fibrules::RTM_DELRULE if !net_admin => return change(Err(Errno::EPERM)),
        crate::fibrules::RTM_NEWRULE => {
            const NLM_F_EXCL: u16 = 0x200;
            return change(crate::fibrules::add(family, flags & NLM_F_EXCL != 0, &req[16..], &ifindex));
        }
        crate::fibrules::RTM_DELRULE => return change(crate::fibrules::delete(family, &req[16..], &ifindex)),
        crate::fibrules::RTM_GETRULE if dump => {
            for b in crate::fibrules::dump(family, &ifindex) {
                message(&mut out, crate::fibrules::RTM_NEWRULE, NLM_F_MULTI, seq, &b);
            }
        }
        RTM_GETLINK if dump => links(&mut out, seq),
        // No IPv6 addresses: a dump for AF_INET6 is only its end.
        RTM_GETADDR if dump && (family == AF_UNSPEC || family == AF_INET) => addrs(&mut out, seq),
        RTM_GETADDR if dump => {}
        _ => {
            if flags & (NLM_F_ACK | NLM_F_DUMP) == 0 {
                return None;
            }
            let mut b = (-(Errno::EOPNOTSUPP.0 as i32)).to_le_bytes().to_vec();
            b.extend_from_slice(&req[..16]);
            message(&mut out, NLMSG_ERROR, 0, seq, &b);
            return Some(out);
        }
    }
    message(&mut out, NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_le_bytes());
    Some(out)
}

/// `NETLINK_ROUTE`.
pub const NETLINK_ROUTE: u32 = 0;
/// `NETLINK_KOBJECT_UEVENT`: the device events `ueventd` and udev listen to.
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
/// `NETLINK_XFRM`: IPsec's security associations and policies
/// ([`xfrm_answer`]).
pub const NETLINK_XFRM: u32 = 6;

/// The reply a change is owed: an acknowledgement when asked for one
/// (the request's header after it), or its error, which is always said
/// (the whole request after it).
fn change_reply(req: &[u8], r: Result<(), Errno>) -> Option<Vec<u8>> {
    let flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    let mut out = Vec::new();
    match r {
        Ok(()) if flags & NLM_F_ACK == 0 => return None,
        Ok(()) => {
            let mut b = 0i32.to_le_bytes().to_vec();
            b.extend_from_slice(&req[..16]);
            message(&mut out, NLMSG_ERROR, NLM_F_CAPPED, seq, &b);
        }
        Err(e) => {
            let mut b = (-(e.0 as i32)).to_le_bytes().to_vec();
            b.extend_from_slice(req);
            message(&mut out, NLMSG_ERROR, 0, seq, &b);
        }
    }
    Some(out)
}

/// `xfrm_user_rcv_msg` for what Android's netd asks at its start
/// (`XfrmController::Init`): every message takes CAP_NET_ADMIN; the
/// databases are flushed (`xfrm_flush_sa`, `xfrm_flush_policy`: an empty
/// one flushed is no error) and dumped. Nothing adds to them here yet, so
/// they are empty, and anything else is refused, said once.
fn xfrm_answer(req: &[u8], net_admin: bool) -> Option<Vec<u8>> {
    const MSG_BASE: u16 = 0x10;
    const MSG_MAX: u16 = 0x28;
    const GETSA: u16 = 0x12;
    const GETPOLICY: u16 = 0x15;
    const FLUSHSA: u16 = 0x1c;
    const FLUSHPOLICY: u16 = 0x1d;
    const GETSADINFO: u16 = 0x23;
    let kind = u16::from_le_bytes(req[4..6].try_into().unwrap());
    let flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    if !(MSG_BASE..=MSG_MAX).contains(&kind) {
        return change_reply(req, Err(Errno::EINVAL));
    }
    if !net_admin {
        return change_reply(req, Err(Errno::EPERM));
    }
    match kind {
        // `xfrm_usersa_flush`: one byte, the protocol.
        FLUSHSA if req.len() < 17 => change_reply(req, Err(Errno::EINVAL)),
        FLUSHSA | FLUSHPOLICY => change_reply(req, Ok(())),
        GETSA | GETPOLICY if flags & NLM_F_DUMP == NLM_F_DUMP => {
            let mut out = Vec::new();
            message(&mut out, NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_le_bytes());
            Some(out)
        }
        GETSA | GETPOLICY => change_reply(req, Err(Errno::ESRCH)),
        // `xfrm_get_sadinfo`: how many SAs (none) and the hash's buckets,
        // as a namespace starts it (8) and at most (1M).
        GETSADINFO => {
            const NEWSADINFO: u16 = 0x22;
            const XFRMA_SAD_CNT: u16 = 1;
            const XFRMA_SAD_HINFO: u16 = 2;
            let mut b = 0u32.to_le_bytes().to_vec();
            attr(&mut b, XFRMA_SAD_CNT, &0u32.to_le_bytes());
            let mut h = 8u32.to_le_bytes().to_vec();
            h.extend_from_slice(&(1u32 << 20).to_le_bytes());
            attr(&mut b, XFRMA_SAD_HINFO, &h);
            let mut out = Vec::new();
            message(&mut out, NEWSADINFO, 0, seq, &b);
            Some(out)
        }
        _ => {
            crate::bpf::say_once(&format!("xfrm message {kind:#x} (IPsec: only flushing and empty dumps here)"));
            change_reply(req, Err(Errno::EOPNOTSUPP))
        }
    }
}
/// `SOL_NETLINK`.
pub const SOL_NETLINK: u64 = 270;

/// `SOCK_MIN_RCVBUF` and `SOCK_MIN_SNDBUF`.
const MIN_RCVBUF: u32 = 2304;
const MIN_SNDBUF: u32 = 4608;

/// `net.core.rmem_default`, `rmem_max`, `wmem_default` and `wmem_max`:
/// what a socket's buffers start as, and the most `SO_RCVBUF` and
/// `SO_SNDBUF` give without `CAP_NET_ADMIN`. They start as Linux 6.18's
/// and are set through `/proc/sys/net/core` (Android's `init.rc` sets
/// both maxima to 262144).
pub mod sysctl {
    use std::sync::atomic::{AtomicU32, Ordering};

    static VALUES: [AtomicU32; 4] = [AtomicU32::new(212_992), AtomicU32::new(4 << 20), AtomicU32::new(212_992), AtomicU32::new(4 << 20)];
    pub const NAMES: [&str; 4] = ["rmem_default", "rmem_max", "wmem_default", "wmem_max"];

    pub fn get(name: &str) -> Option<u32> {
        NAMES.iter().position(|n| *n == name).map(|i| VALUES[i].load(Ordering::Acquire))
    }

    /// Set one: no less than the least a buffer of its kind may be
    /// (`EINVAL` below it, as the kernel's table has their minima).
    pub fn set(name: &str, value: u32) -> Result<(), crate::errno::Errno> {
        let i = NAMES.iter().position(|n| *n == name).ok_or(crate::errno::Errno::ENOENT)?;
        let least = if name.starts_with('r') { super::MIN_RCVBUF } else { super::MIN_SNDBUF };
        if value < least || value > i32::MAX as u32 {
            return Err(crate::errno::Errno::EINVAL);
        }
        VALUES[i].store(value, Ordering::Release);
        Ok(())
    }
}
/// `UEVENT_BUFFER_SIZE`: the most a uevent sent from userspace may be, its
/// sequence number included.
const UEVENT_BUFFER_SIZE: usize = 2048;
const NLMSG_MIN_TYPE: u16 = 0x10;
const NLM_F_CAPPED: u16 = 0x100;

/// Who makes a call on a socket: what a message carries of its sender, and
/// what the sender may do.
#[derive(Clone, Copy, Debug)]
pub struct Sender {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    /// `CAP_NET_ADMIN`: to send to another socket or to a group, and to
    /// force a buffer's size.
    pub net_admin: bool,
    /// `CAP_SYS_ADMIN`: to have the kernel broadcast a uevent.
    pub sys_admin: bool,
}

/// A datagram waiting on a socket.
#[derive(Debug)]
struct Datagram {
    data: Vec<u8>,
    /// The sender's port: 0 for the kernel.
    from: u32,
    /// The group it was sent to, from 1; 0 for one sent to the socket alone.
    group: u32,
    /// The sender's `struct ucred`.
    cred: (i32, u32, u32),
}

/// A datagram as `recvmsg` gives it.
#[derive(Debug)]
pub struct Received {
    /// As much of it as there was room for.
    pub data: Vec<u8>,
    /// Its whole length (`MSG_TRUNC`).
    pub whole: usize,
    /// `nl_pid` and `nl_groups` of its `sockaddr_nl`.
    pub from: u32,
    pub groups: u32,
    /// For `SCM_CREDENTIALS`.
    pub cred: (i32, u32, u32),
}

#[derive(Debug)]
struct State {
    portid: u32,
    bound: bool,
    /// The groups it listens to, group 1 the lowest bit.
    groups: u32,
    dst_portid: u32,
    dst_group: u32,
    connected: bool,
    rcvbuf: u32,
    sndbuf: u32,
    passcred: bool,
    /// `NETLINK_NO_ENOBUFS`, `NETLINK_CAP_ACK`.
    no_enobufs: bool,
    cap_ack: bool,
    /// A datagram was dropped for want of room, and none is taken until
    /// the queue has been read empty.
    congested: bool,
    /// The error the next receive reports (`sk_err`).
    err: Option<Errno>,
    /// What the queue counts against `rcvbuf` (`sk_rmem_alloc`).
    queued: u32,
    inbox: VecDeque<Datagram>,
}

/// A netlink socket, of either protocol this kernel has.
///
/// A socket is known by its port (`nl_pid`), unique among its protocol's:
/// the caller's process id when it is bound with none, or a negative number
/// when that is taken. It may listen to groups; a message is sent to a port,
/// to a group, or (port 0) to the kernel, which answers a route socket's
/// dumps and takes a uevent socket's messages for broadcasting.
///
/// Not as Linux: a `write` is sent as the process that made the socket,
/// where Linux's is the writer's (the calls with an address are the
/// caller's); a send to a socket whose buffer is full is `EAGAIN` where a
/// blocking sender would wait.
#[derive(Debug)]
pub struct Socket {
    protocol: u32,
    /// `SOCK_RAW` or `SOCK_DGRAM`, as it was asked for: they are the same.
    kind: u32,
    opener: Sender,
    state: Mutex<State>,
    /// Who waits on it (`crate::wait`): a datagram arrives, or an error.
    queue: crate::wait::Queue,
}

/// Every socket there is, for finding one by its port and the listeners of
/// a group. Locked before any socket's state, never after.
static TABLE: Mutex<Vec<std::sync::Weak<Socket>>> = Mutex::new(Vec::new());

/// The number the next uevent carries (`/sys/kernel/uevent_seqnum`).
static UEVENT_SEQNUM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Say once per kind that a program asked for something not done here.
fn unimplemented(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        eprintln!("[gex] netlink: {what} is not implemented");
        said.push(what.to_string());
    }
}

/// What a datagram of `len` bytes counts against a receive buffer. Linux
/// counts the whole allocation behind it (`skb->truesize`): the data, to a
/// cache line, with the 320 bytes of shared info after it, in a buffer of
/// 704 bytes when it fits one (the cache small heads come from, as an
/// arm64 Android kernel is built) and else rounded up to one of the
/// allocator's sizes; and the 256 of the `sk_buff` itself. On Linux 7.0 a
/// listener's smallest buffer holds two short events and its usual one 166
/// of 600 bytes, as it does by this.
fn truesize(len: usize) -> u32 {
    const SMALL_HEAD: usize = 704;
    let head = ((len + 63) & !63) + 320;
    let head = if head <= SMALL_HEAD { SMALL_HEAD } else { head.next_power_of_two() };
    (head + 256) as u32
}

impl State {
    /// Take a datagram if there is room (`netlink_broadcast_deliver`,
    /// `netlink_attachskb`): when the queue is empty, or when it and what
    /// is queued come to no more than the buffer; and never while the
    /// socket has been losing them.
    fn take(&mut self, d: Datagram) -> bool {
        let cost = truesize(d.data.len());
        if self.congested || (self.queued != 0 && self.queued + cost > self.rcvbuf) {
            return false;
        }
        self.queued += cost;
        self.inbox.push_back(d);
        true
    }
}

/// `netlink_group_mask`.
fn group_mask(group: u32) -> u32 {
    if group == 0 { 0 } else { 1 << (group - 1) }
}

/// `ffs`: the lowest group in a mask, from 1; 0 for none.
fn lowest_group(mask: u32) -> u32 {
    if mask == 0 { 0 } else { mask.trailing_zeros() + 1 }
}

fn sockets(protocol: u32) -> Vec<Arc<Socket>> {
    let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    table.iter().filter_map(|w| w.upgrade()).filter(|s| s.protocol == protocol).collect()
}

/// `netlink_broadcast`: to every socket of the protocol listening to
/// `group`, but the sender and the one at port `except` (which is sent it
/// alone). A listener with no room loses it, and learns that it did
/// (`ENOBUFS` at its next receive) unless it asked not to.
fn broadcast(protocol: u32, sender: Option<&Socket>, d: &Datagram, except: u32, group: u32) {
    for s in sockets(protocol) {
        if sender.is_some_and(|x| std::ptr::eq(x, &*s)) {
            continue;
        }
        let mut st = s.state();
        if st.portid == except || st.groups & group_mask(group) == 0 {
            continue;
        }
        if !st.take(Datagram { data: d.data.clone(), from: d.from, group: d.group, cred: d.cred }) {
            Socket::overrun(&mut st);
        }
        drop(st);
        s.queue.notify();
    }
}

impl Socket {
    /// `socket(AF_NETLINK, kind, protocol)`, made by `opener`.
    pub fn new(protocol: u32, kind: u32, opener: Sender) -> Arc<Socket> {
        let s = Arc::new(Socket {
            protocol,
            kind,
            opener,
            state: Mutex::new(State {
                portid: 0,
                bound: false,
                groups: 0,
                dst_portid: 0,
                dst_group: 0,
                connected: false,
                rcvbuf: sysctl::get("rmem_default").unwrap(),
                sndbuf: sysctl::get("wmem_default").unwrap(),
                passcred: false,
                no_enobufs: false,
                cap_ack: false,
                congested: false,
                err: None,
                queued: 0,
                inbox: VecDeque::new(),
            }),
            queue: crate::wait::Queue::new(),
        });
        let mut table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
        table.retain(|w| w.strong_count() != 0);
        table.push(Arc::downgrade(&s));
        s
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    /// `SO_TYPE`.
    pub fn kind(&self) -> u32 {
        self.kind
    }

    /// `netlink_overrun`.
    fn overrun(st: &mut State) {
        if !st.no_enobufs && !st.congested {
            st.congested = true;
            st.err = Some(Errno::ENOBUFS);
        }
    }

    /// Give the socket a port if it has none: `nl_pid`, or with 0 the
    /// caller's process id, or a negative number when that is another
    /// socket's (`netlink_autobind`).
    fn insert(&self, tgid: i32, nl_pid: u32) -> Result<(), Errno> {
        let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
        if self.state().bound {
            return Ok(());
        }
        let taken = |portid: u32| {
            table.iter().filter_map(|w| w.upgrade()).any(|s| {
                s.protocol == self.protocol && !std::ptr::eq(&*s, self) && {
                    let st = s.state();
                    st.bound && st.portid == portid
                }
            })
        };
        let portid = if nl_pid != 0 {
            if taken(nl_pid) {
                return Err(Errno::EADDRINUSE);
            }
            nl_pid
        } else if !taken(tgid as u32) {
            tgid as u32
        } else {
            // Somewhere in [i32::MIN, -4097], and down from there.
            let mut r = [0u8; 4];
            crate::vfs::devfs::fill_random(&mut r);
            let span = (-4096i64 - i32::MIN as i64) as u32;
            let mut rover = i32::MIN.wrapping_add((u32::from_le_bytes(r) % span) as i32);
            while taken(rover as u32) {
                rover = if rover == i32::MIN { -4097 } else { rover - 1 };
            }
            rover as u32
        };
        let mut st = self.state();
        st.portid = portid;
        st.bound = true;
        Ok(())
    }

    /// `bind` to a `sockaddr_nl`'s `nl_pid` and `nl_groups`, by a process.
    /// Either protocol here lets anyone listen to its groups.
    pub fn bind(&self, tgid: i32, nl_pid: u32, groups: u32) -> Result<(), Errno> {
        {
            let st = self.state();
            if st.bound && nl_pid != st.portid {
                return Err(Errno::EINVAL);
            }
        }
        self.insert(tgid, nl_pid)?;
        self.state().groups = groups;
        Ok(())
    }

    /// `connect` to a `sockaddr_nl`: where a send with no address goes.
    /// To anything but the kernel only with `CAP_NET_ADMIN`.
    pub fn connect(&self, who: Sender, nl_pid: u32, groups: u32) -> Result<(), Errno> {
        if (groups != 0 || nl_pid != 0) && !who.net_admin {
            return Err(Errno::EPERM);
        }
        self.insert(who.pid, 0)?;
        let mut st = self.state();
        st.connected = true;
        st.dst_portid = nl_pid;
        st.dst_group = lowest_group(groups);
        Ok(())
    }

    /// `connect` to `AF_UNSPEC`: to nothing again.
    pub fn disconnect(&self) {
        let mut st = self.state();
        st.connected = false;
        st.dst_portid = 0;
        st.dst_group = 0;
    }

    /// `getsockname`: `nl_pid` and `nl_groups`.
    pub fn name(&self) -> (u32, u32) {
        let st = self.state();
        (st.portid, st.groups)
    }

    /// `getpeername`: where it is connected to, as an address.
    pub fn peer(&self) -> (u32, u32) {
        let st = self.state();
        (st.dst_portid, group_mask(st.dst_group))
    }

    /// `SO_RCVBUF` (and `SO_RCVBUFFORCE` with `force`, the caller having
    /// been found able): twice what is asked, as Linux keeps it, and what
    /// is asked no more than `rmem_max` unless forced.
    pub fn set_rcvbuf(&self, val: i32, force: bool) {
        let val = if force { val.max(0) as u32 } else { (val as u32).min(sysctl::get("rmem_max").unwrap()) };
        self.state().rcvbuf = (val.min(i32::MAX as u32 / 2) * 2).max(MIN_RCVBUF);
    }

    /// `SO_SNDBUF` and `SO_SNDBUFFORCE`, likewise.
    pub fn set_sndbuf(&self, val: i32, force: bool) {
        let val = if force { val.max(0) as u32 } else { (val as u32).min(sysctl::get("wmem_max").unwrap()) };
        self.state().sndbuf = (val.min(i32::MAX as u32 / 2) * 2).max(MIN_SNDBUF);
    }

    pub fn rcvbuf(&self) -> u32 {
        self.state().rcvbuf
    }

    pub fn sndbuf(&self) -> u32 {
        self.state().sndbuf
    }

    pub fn set_passcred(&self, on: bool) {
        self.state().passcred = on;
    }

    pub fn passcred(&self) -> bool {
        self.state().passcred
    }

    /// `setsockopt(SOL_NETLINK)`.
    pub fn set_option(&self, name: u64, val: u32) -> Result<(), Errno> {
        const NETLINK_ADD_MEMBERSHIP: u64 = 1;
        const NETLINK_DROP_MEMBERSHIP: u64 = 2;
        match name {
            NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                if val == 0 || val > 32 {
                    return Err(Errno::EINVAL);
                }
                let mut st = self.state();
                if name == NETLINK_ADD_MEMBERSHIP {
                    st.groups |= group_mask(val);
                } else {
                    st.groups &= !group_mask(val);
                }
                Ok(())
            }
            option::NO_ENOBUFS => {
                let mut st = self.state();
                st.no_enobufs = val != 0;
                if val != 0 {
                    st.congested = false;
                }
                Ok(())
            }
            option::CAP_ACK => {
                self.state().cap_ack = val != 0;
                Ok(())
            }
            option::PKTINFO | option::BROADCAST_ERROR | option::LISTEN_ALL_NSID | option::EXT_ACK | option::GET_STRICT_CHK => {
                unimplemented(&format!("socket option {name}"));
                Err(Errno::ENOPROTOOPT)
            }
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    /// `getsockopt(SOL_NETLINK)` of an option that is a flag.
    pub fn option(&self, name: u64) -> Result<u32, Errno> {
        match name {
            option::NO_ENOBUFS => Ok(self.state().no_enobufs as u32),
            option::CAP_ACK => Ok(self.state().cap_ack as u32),
            // Never set, since setting them is refused.
            option::PKTINFO | option::BROADCAST_ERROR | option::LISTEN_ALL_NSID | option::EXT_ACK | option::GET_STRICT_CHK => Ok(0),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    /// A datagram from the kernel to this socket alone: lost, and said to
    /// be, when there is no room.
    fn from_kernel(&self, data: Vec<u8>) {
        let mut st = self.state();
        if !st.take(Datagram { data, from: 0, group: 0, cred: (0, 0, 0) }) {
            Socket::overrun(&mut st);
        }
        drop(st);
        self.queue.notify();
    }

    /// `netlink_ack`: the `NLMSG_ERROR` message that answers request `req`
    /// (its header and all) with `err`, 0 for success. A failed request
    /// comes back whole unless the socket asked for the header alone.
    fn ack(&self, req: &[u8], err: i32) {
        let (portid, cap) = {
            let st = self.state();
            (st.portid, st.cap_ack)
        };
        let whole = err != 0 && !cap;
        let mut body = err.to_le_bytes().to_vec();
        body.extend_from_slice(&req[..16]);
        if whole {
            body.extend_from_slice(&req[16..]);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
        let mut out = Vec::new();
        out.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
        out.extend_from_slice(&(if whole { 0 } else { NLM_F_CAPPED }).to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&portid.to_le_bytes());
        out.extend_from_slice(&body);
        self.from_kernel(out);
    }

    /// What the kernel does with a datagram sent to it (`netlink_rcv_skb`):
    /// each message in it that is whole. `named` when the send gave an
    /// address.
    fn to_kernel(&self, who: Sender, named: bool, data: &[u8]) {
        match self.protocol {
            NETLINK_ROUTE | NETLINK_XFRM => {
                // A request is answered; the answers to one datagram are
                // one datagram.
                let mut at = 0;
                let mut out = Vec::new();
                while at + 16 <= data.len() {
                    let len = u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
                    if len < 16 || at + len > data.len() {
                        break;
                    }
                    let flags = u16::from_le_bytes(data[at + 6..at + 8].try_into().unwrap());
                    if flags & NLM_F_REQUEST != 0 {
                        let answer = if self.protocol == NETLINK_XFRM { xfrm_answer } else { route_answer };
                        if let Some(r) = answer(&data[at..at + len], who.net_admin) {
                            out.extend_from_slice(&r);
                        }
                    }
                    at += (len + 3) & !3;
                }
                if !out.is_empty() {
                    // Each answer names the socket it answers
                    // (`nlmsg_pid`, as `netlink_ack` and the dumps fill
                    // it): iproute2 skips a message that names another.
                    let portid = self.state().portid;
                    let mut at = 0;
                    while at + 16 <= out.len() {
                        let len = u32::from_le_bytes(out[at..at + 4].try_into().unwrap()) as usize;
                        out[at + 12..at + 16].copy_from_slice(&portid.to_le_bytes());
                        at += (len.max(16) + 3) & !3;
                    }
                    self.from_kernel(out);
                }
            }
            _ => {
                let mut at = 0;
                while at + 16 <= data.len() {
                    let len = u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
                    if len < 16 || at + len > data.len() {
                        break;
                    }
                    let kind = u16::from_le_bytes(data[at + 4..at + 6].try_into().unwrap());
                    let flags = u16::from_le_bytes(data[at + 6..at + 8].try_into().unwrap());
                    let mut err = 0;
                    if flags & NLM_F_REQUEST != 0 && kind >= NLMSG_MIN_TYPE {
                        // `uevent_net_rcv_skb`: only one who may, and (with
                        // no address given) only on a socket made by one
                        // who might.
                        if !(who.sys_admin && (named || self.opener.sys_admin)) {
                            err = -(Errno::EPERM.0 as i32);
                        } else {
                            err = uevent_from_user(who, &data[at..]);
                        }
                    }
                    if flags & NLM_F_ACK != 0 || err != 0 {
                        self.ack(&data[at..at + len], err);
                    }
                    at += (len + 3) & !3;
                }
            }
        }
    }

    /// `sendmsg`: `data` from `who`, to `dest` (`nl_pid`, `nl_groups`) or
    /// with none to where the socket is connected: the kernel, unless it
    /// was connected elsewhere.
    pub fn send(&self, who: Sender, dest: Option<(u32, u32)>, data: &[u8]) -> SysResult {
        if data.is_empty() {
            return Err(Errno::ENODATA);
        }
        let (dst_portid, dst_group) = match dest {
            Some((pid, groups)) => {
                let group = lowest_group(groups);
                if (group != 0 || pid != 0) && !who.net_admin {
                    return Err(Errno::EPERM);
                }
                (pid, group)
            }
            None => {
                let st = self.state();
                (st.dst_portid, st.dst_group)
            }
        };
        self.insert(who.pid, 0)?;
        let (portid, sndbuf) = {
            let st = self.state();
            (st.portid, st.sndbuf)
        };
        if data.len() as u64 > sndbuf.saturating_sub(32) as u64 {
            return Err(Errno::EMSGSIZE);
        }
        let d = Datagram { data: data.to_vec(), from: portid, group: dst_group, cred: (who.pid, who.uid, who.gid) };
        if dst_group != 0 {
            broadcast(self.protocol, Some(self), &d, dst_portid, dst_group);
        }
        if dst_portid == 0 {
            self.to_kernel(who, dest.is_some(), data);
            return Ok(data.len() as u64);
        }
        // To the socket at that port, unless it is connected to another.
        let to = sockets(self.protocol)
            .into_iter()
            .find(|s| {
                let st = s.state();
                st.bound && st.portid == dst_portid
            })
            .ok_or(Errno::ECONNREFUSED)?;
        let mut st = to.state();
        if st.connected && st.dst_portid != portid {
            return Err(Errno::ECONNREFUSED);
        }
        if !st.take(d) {
            return Err(Errno::EAGAIN);
        }
        drop(st);
        to.queue.notify();
        Ok(data.len() as u64)
    }

    /// `recvmsg` into `room` bytes: the error the socket has waiting, else
    /// its next datagram, cut to the room there is. `EAGAIN` with neither.
    pub fn recv(&self, room: usize, peek: bool) -> Result<Received, Errno> {
        let mut st = self.state();
        if let Some(e) = st.err.take() {
            return Err(e);
        }
        let Some(d) = st.inbox.front() else {
            return Err(Errno::EAGAIN);
        };
        let n = d.data.len().min(room);
        let r = Received { data: d.data[..n].to_vec(), whole: d.data.len(), from: d.from, groups: group_mask(d.group), cred: d.cred };
        if !peek {
            st.queued = st.queued.saturating_sub(truesize(r.whole));
            st.inbox.pop_front();
            if st.inbox.is_empty() {
                st.congested = false;
            }
        }
        Ok(r)
    }
}

/// The number of the last uevent (`/sys/kernel/uevent_seqnum`).
pub fn uevent_seqnum() -> u64 {
    UEVENT_SEQNUM.load(std::sync::atomic::Ordering::Acquire)
}

/// A device's event, from the kernel (`kobject_uevent_env`): to group 1
/// from port 0, as root's. `action@devpath`, then `ACTION`, `DEVPATH`,
/// `SUBSYSTEM`, the variables given, and the event's number, each ended
/// by a NUL.
pub fn uevent(action: &str, devpath: &str, subsystem: &str, vars: &[(String, String)]) {
    let seq = UEVENT_SEQNUM.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
    let mut data = format!("{action}@{devpath}\0ACTION={action}\0DEVPATH={devpath}\0SUBSYSTEM={subsystem}\0").into_bytes();
    for (k, v) in vars {
        data.extend_from_slice(format!("{k}={v}\0").as_bytes());
    }
    data.extend_from_slice(format!("SEQNUM={seq}\0").as_bytes());
    broadcast(NETLINK_KOBJECT_UEVENT, None, &Datagram { data, from: 0, group: 1, cred: (0, 0, 0) }, 0, 1);
}

/// `uevent_net_broadcast`: a uevent sent by a process, given the next
/// sequence number and sent to group 1 as the kernel's own are, from port 0
/// with the sender's credentials. `rest` is the datagram from the request's
/// header on. A negative errno, or 0.
fn uevent_from_user(who: Sender, rest: &[u8]) -> i32 {
    let seq = UEVENT_SEQNUM.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
    let mut tail = format!("SEQNUM={seq}").into_bytes();
    tail.push(0);
    if rest.len() + tail.len() > UEVENT_BUFFER_SIZE {
        return -(Errno::EINVAL.0 as i32);
    }
    let mut data = rest[16..].to_vec();
    data.extend_from_slice(&tail);
    broadcast(NETLINK_KOBJECT_UEVENT, None, &Datagram { data, from: 0, group: 1, cred: (who.pid, who.uid, who.gid) }, 0, 1);
    0
}

/// The `SOL_NETLINK` options that are flags.
pub mod option {
    pub const PKTINFO: u64 = 3;
    pub const BROADCAST_ERROR: u64 = 4;
    pub const NO_ENOBUFS: u64 = 5;
    pub const LISTEN_ALL_NSID: u64 = 8;
    pub const LIST_MEMBERSHIPS: u64 = 9;
    pub const CAP_ACK: u64 = 10;
    pub const EXT_ACK: u64 = 11;
    pub const GET_STRICT_CHK: u64 = 12;
}

impl FileHandle for Socket {
    /// A socket is in the sockets' filesystem.
    fn fs_dev(&self) -> u64 {
        crate::vfs::anon_dev(crate::vfs::DevKey::Kind("sockfs"))
    }

    fn as_netlink(self: Arc<Self>) -> Option<Arc<Socket>> {
        Some(self)
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        let r = self.recv(buf.len(), false)?;
        buf[..r.data.len()].copy_from_slice(&r.data);
        Ok(r.data.len() as u64)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        self.send(self.opener, None, buf)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata {
            file_type: FileType::Socket,
            size: 0,
            mode: 0o777,
            ino: crate::vfs::anon_ino(self as *const Self as *const u8),
            mtime: 0,
            nlink: 1,
            rdev: 0,
            times: Default::default(),
            owner: None,
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn poll_readable(&self) -> bool {
        let st = self.state();
        !st.inbox.is_empty() || st.err.is_some()
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(self.queue.wakes())
    }

    fn poll_writable(&self) -> bool {
        true
    }

    fn available(&self) -> Option<u64> {
        Some(self.state().inbox.front().map_or(0, |d| d.data.len() as u64))
    }
}

/// The interface requests asked of any socket (`struct ifreq`): by name
/// (`SIOCGIFINDEX`, the flags, MTU, hardware and IPv4 addresses) or by index
/// (`SIOCGIFNAME`). musl's and glibc's `if_nametoindex` and `if_indextoname`
/// are these, and Wine's nsi asks the flags, MTU and hardware address of
/// each interface `if_nameindex` gave it.
pub mod ioctl {
    pub const SIOCGIFNAME: u64 = 0x8910;
    pub const SIOCGIFFLAGS: u64 = 0x8913;
    pub const SIOCGIFADDR: u64 = 0x8915;
    pub const SIOCGIFBRDADDR: u64 = 0x8919;
    pub const SIOCGIFNETMASK: u64 = 0x891b;
    pub const SIOCGIFMTU: u64 = 0x8921;
    pub const SIOCGIFHWADDR: u64 = 0x8927;
    pub const SIOCGIFINDEX: u64 = 0x8933;
}

/// Whether `req` is one of [`ioctl`]'s.
pub fn is_iface_ioctl(req: u64) -> bool {
    use ioctl::*;
    matches!(req, SIOCGIFNAME | SIOCGIFFLAGS | SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK | SIOCGIFMTU | SIOCGIFHWADDR | SIOCGIFINDEX)
}

/// Answers one of [`ioctl`]'s in `ifr`, the first 32 bytes of a `struct
/// ifreq` (the name, then the union's first 16 bytes: the same on 32- and
/// 64-bit guests). `ENODEV` for an interface that is not here.
pub fn iface_ioctl(req: u64, ifr: &mut [u8; 32]) -> Result<(), Errno> {
    use ioctl::*;
    let iface = if req == SIOCGIFNAME {
        let index = i32::from_le_bytes(ifr[16..20].try_into().unwrap());
        IFACES.iter().find(|i| i.index as i32 == index)
    } else {
        let name = ifr[..16].split(|&b| b == 0).next().unwrap_or(&[]);
        IFACES.iter().find(|i| i.name.as_bytes() == name)
    };
    let i = iface.ok_or(Errno::ENODEV)?;
    let inet = |ifr: &mut [u8; 32], a: [u8; 4]| {
        ifr[16..32].fill(0);
        ifr[16..18].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        ifr[20..24].copy_from_slice(&a);
    };
    let mask = (u32::MAX << (32 - i.prefix as u32)).to_be_bytes();
    match req {
        SIOCGIFNAME => {
            ifr[..16].fill(0);
            ifr[..i.name.len()].copy_from_slice(i.name.as_bytes());
        }
        SIOCGIFINDEX => ifr[16..20].copy_from_slice(&(i.index as i32).to_le_bytes()),
        // ifr_flags is a short: the low 16 bits (IFF_LOWER_UP is not among them).
        SIOCGIFFLAGS => ifr[16..18].copy_from_slice(&(i.flags as u16).to_le_bytes()),
        SIOCGIFMTU => ifr[16..20].copy_from_slice(&(i.mtu as i32).to_le_bytes()),
        SIOCGIFHWADDR => {
            ifr[16..32].fill(0);
            ifr[16..18].copy_from_slice(&i.kind.to_le_bytes());
            ifr[18..24].copy_from_slice(&i.mac);
        }
        SIOCGIFADDR => inet(ifr, i.addr),
        SIOCGIFNETMASK => inet(ifr, mask),
        SIOCGIFBRDADDR => {
            if i.flags & IFF_BROADCAST == 0 {
                return Err(Errno::EINVAL);
            }
            let b = u32::from_be_bytes(i.addr) | !u32::from_be_bytes(mask);
            inet(ifr, b.to_be_bytes());
        }
        _ => return Err(Errno::ENOTTY),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: u16, flags: u16, seq: u32, family: u8) -> Vec<u8> {
        let mut v = Vec::new();
        message(&mut v, kind, flags, seq, &[family, 0, 0, 0]);
        v
    }

    /// (type, seq, body) of each message in a datagram.
    fn parse(d: &[u8]) -> Vec<(u16, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 16 <= d.len() {
            let len = u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize;
            let kind = u16::from_le_bytes(d[at + 4..at + 6].try_into().unwrap());
            let seq = u32::from_le_bytes(d[at + 8..at + 12].try_into().unwrap());
            out.push((kind, seq, d[at + 16..at + len].to_vec()));
            at += (len + 3) & !3;
        }
        out
    }

    /// The rtattrs after a fixed header of `skip` bytes, as (type, data).
    fn attrs(body: &[u8], skip: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = skip;
        while at + 4 <= body.len() {
            let len = u16::from_le_bytes(body[at..at + 2].try_into().unwrap()) as usize;
            let kind = u16::from_le_bytes(body[at + 2..at + 4].try_into().unwrap());
            out.push((kind, body[at + 4..at + len].to_vec()));
            at += (len + 3) & !3;
        }
        out
    }

    fn route() -> Arc<Socket> {
        Socket::new(NETLINK_ROUTE, 3, user(100))
    }

    fn user(pid: i32) -> Sender {
        Sender { pid, uid: 1000, gid: 1000, net_admin: false, sys_admin: false }
    }

    fn root(pid: i32) -> Sender {
        Sender { pid, uid: 0, gid: 0, net_admin: true, sys_admin: true }
    }

    fn reply(s: &Socket) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        let n = s.read_at(0, &mut buf).unwrap() as usize;
        buf.truncate(n);
        buf
    }

    /// What musl's `if_nameindex` does: a link dump, then an address dump;
    /// it wants every interface by index and name, and each dump's end.
    #[test]
    fn a_link_dump_names_lo_and_eth0() {
        let s = route();
        assert!(!s.poll_readable());
        let req = request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 7, AF_UNSPEC);
        assert_eq!(s.write_at(0, &req).unwrap(), req.len() as u64);
        assert!(s.poll_readable());
        let msgs = parse(&reply(&s));
        assert_eq!(msgs.len(), 3);
        assert!(msgs.iter().all(|m| m.1 == 7));
        assert_eq!(msgs[2].0, NLMSG_DONE);
        let names: Vec<(i32, Vec<u8>)> = msgs[..2]
            .iter()
            .map(|(k, _, b)| {
                assert_eq!(*k, RTM_NEWLINK);
                let index = i32::from_le_bytes(b[4..8].try_into().unwrap());
                let name = attrs(b, 16).into_iter().find(|a| a.0 == IFLA_IFNAME).unwrap().1;
                (index, name)
            })
            .collect();
        assert_eq!(names, vec![(1, b"lo\0".to_vec()), (2, b"eth0\0".to_vec())]);
        assert!(!s.poll_readable());
        assert_eq!(s.read_at(0, &mut [0u8; 64]).err(), Some(Errno::EAGAIN));
    }

    #[test]
    fn an_address_dump_has_the_ipv4_addresses_and_no_ipv6() {
        let s = route();
        s.write_at(0, &request(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 2, AF_UNSPEC)).unwrap();
        let msgs = parse(&reply(&s));
        assert_eq!(msgs.len(), 3);
        let got: Vec<(u8, u8, u32, Vec<u8>)> = msgs[..2]
            .iter()
            .map(|(k, _, b)| {
                assert_eq!(*k, RTM_NEWADDR);
                let local = attrs(b, 8).into_iter().find(|a| a.0 == IFA_LOCAL).unwrap().1;
                (b[0], b[1], u32::from_le_bytes(b[4..8].try_into().unwrap()), local)
            })
            .collect();
        assert_eq!(got, vec![(AF_INET, 8, 1, vec![127, 0, 0, 1]), (AF_INET, 24, 2, vec![10, 0, 2, 15])]);
        s.write_at(0, &request(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 3, 10)).unwrap();
        let msgs = parse(&reply(&s));
        assert_eq!(msgs.iter().map(|m| m.0).collect::<Vec<_>>(), vec![NLMSG_DONE]);
    }

    #[test]
    fn anything_else_is_refused_when_it_wants_an_answer() {
        let s = route();
        s.write_at(0, &request(24, NLM_F_REQUEST | NLM_F_ACK, 9, AF_INET)).unwrap();
        let msgs = parse(&reply(&s));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, NLMSG_ERROR);
        assert_eq!(i32::from_le_bytes(msgs[0].2[..4].try_into().unwrap()), -(Errno::EOPNOTSUPP.0 as i32));
        s.write_at(0, &request(24, NLM_F_REQUEST, 10, AF_INET)).unwrap();
        assert!(!s.poll_readable());
    }

    fn ifr(name: &str) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r
    }

    #[test]
    fn interface_ioctls_answer_by_name_and_index() {
        let mut r = ifr("eth0");
        iface_ioctl(ioctl::SIOCGIFINDEX, &mut r).unwrap();
        assert_eq!(i32::from_le_bytes(r[16..20].try_into().unwrap()), 2);
        let mut r = [0u8; 32];
        r[16..20].copy_from_slice(&1i32.to_le_bytes());
        iface_ioctl(ioctl::SIOCGIFNAME, &mut r).unwrap();
        assert_eq!(&r[..3], b"lo\0");
        let mut r = ifr("lo");
        iface_ioctl(ioctl::SIOCGIFFLAGS, &mut r).unwrap();
        assert_ne!(u16::from_le_bytes(r[16..18].try_into().unwrap()) as u32 & IFF_LOOPBACK, 0);
        let mut r = ifr("eth0");
        iface_ioctl(ioctl::SIOCGIFADDR, &mut r).unwrap();
        assert_eq!(&r[20..24], &[10, 0, 2, 15]);
        iface_ioctl(ioctl::SIOCGIFNETMASK, &mut r).unwrap();
        assert_eq!(&r[20..24], &[255, 255, 255, 0]);
        iface_ioctl(ioctl::SIOCGIFBRDADDR, &mut r).unwrap();
        assert_eq!(&r[20..24], &[10, 0, 2, 255]);
        let mut r = ifr("eth0");
        iface_ioctl(ioctl::SIOCGIFHWADDR, &mut r).unwrap();
        assert_eq!(u16::from_le_bytes(r[16..18].try_into().unwrap()), ARPHRD_ETHER);
        assert_eq!(&r[18..24], &[2, 0, 0, 0, 0, 1]);
        let mut r = ifr("lo");
        iface_ioctl(ioctl::SIOCGIFMTU, &mut r).unwrap();
        assert_eq!(i32::from_le_bytes(r[16..20].try_into().unwrap()), 65536);
        assert_eq!(iface_ioctl(ioctl::SIOCGIFINDEX, &mut ifr("wlan0")).err(), Some(Errno::ENODEV));
    }

    #[test]
    fn a_connected_socket_is_on_lo_or_eth0() {
        assert_eq!(local_for(0x7f00_0001), 0x7f00_0001);
        assert_eq!(local_for(0x7f12_3456), 0x7f00_0001);
        assert_eq!(local_for(0xf000_0001).to_be_bytes(), ETH0_ADDR);
    }

    fn uevent(who: Sender) -> Arc<Socket> {
        Socket::new(NETLINK_KOBJECT_UEVENT, 2, who)
    }

    /// A request for the kernel to broadcast `text` as a uevent.
    fn broadcast_request(text: &str, flags: u16, seq: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((16 + text.len() + 1) as u32).to_le_bytes());
        v.extend_from_slice(&NLMSG_MIN_TYPE.to_le_bytes());
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&seq.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(text.as_bytes());
        v.push(0);
        v
    }

    /// Bound with no port a socket has its process's id; the process's
    /// second, a negative number; a port in use is refused, and a bound
    /// socket binds again only to its own. Ports are a protocol's.
    #[test]
    fn a_socket_is_bound_to_its_process_or_elsewhere() {
        let a = uevent(user(7001));
        assert_eq!(a.name(), (0, 0));
        a.bind(7001, 0, 0xffff_ffff).unwrap();
        assert_eq!(a.name(), (7001, 0xffff_ffff));
        assert_eq!(a.bind(7001, 0, 1), Err(Errno::EINVAL));
        a.bind(7001, 7001, 1).unwrap();
        assert_eq!(a.name(), (7001, 1));
        let b = uevent(user(7001));
        assert_eq!(b.bind(7001, 7001, 0), Err(Errno::EADDRINUSE));
        b.bind(7001, 0, 0).unwrap();
        assert!((b.name().0 as i32) <= -4097);
        let r = route();
        r.bind(7001, 0, 0).unwrap();
        assert_eq!(r.name().0, 7001);
        // A port is free again when its socket is gone.
        drop(a);
        let c = uevent(user(7001));
        c.bind(7001, 0, 0).unwrap();
        assert_eq!(c.name().0, 7001);
    }

    /// `SO_RCVBUF` as ueventd uses it: asked for 16 MiB it gets twice the
    /// system's limit, and forced, twice what it asked.
    #[test]
    fn a_receive_buffer_is_twice_what_was_asked_within_the_limit() {
        let s = uevent(root(7002));
        assert_eq!(s.rcvbuf(), 212_992);
        s.set_rcvbuf(16 << 20, false);
        assert_eq!(s.rcvbuf(), 8 << 20);
        s.set_rcvbuf(16 << 20, true);
        assert_eq!(s.rcvbuf(), 32 << 20);
        s.set_rcvbuf(1, false);
        assert_eq!(s.rcvbuf(), 2304);
        s.set_sndbuf(1, false);
        assert_eq!(s.sndbuf(), 4608);
    }

    /// Root's request has the kernel broadcast its payload to group 1,
    /// numbered, from port 0, as root's; and it is acknowledged when it
    /// asks to be.
    #[test]
    fn root_has_the_kernel_broadcast_a_uevent() {
        let listener = uevent(user(7003));
        listener.bind(7003, 0, 1).unwrap();
        let deaf = uevent(user(7004));
        deaf.bind(7004, 0, 0).unwrap();
        let sender = uevent(root(7005));
        let text = "gextest@/devices/unit-7003";
        let req = broadcast_request(text, NLM_F_REQUEST | NLM_F_ACK, 41);
        assert_eq!(sender.send(root(7005), None, &req), Ok(req.len() as u64));
        // Other tests' requests are broadcast to this listener too.
        let got = loop {
            let r = listener.recv(4096, false).unwrap();
            if r.data.starts_with(text.as_bytes()) {
                break r;
            }
        };
        assert_eq!((got.from, got.groups, got.cred), (0, 1, (7005, 0, 0)));
        let tail = &got.data[text.len() + 1..];
        assert!(tail.starts_with(b"SEQNUM=") && tail.ends_with(&[0]));
        assert!(std::str::from_utf8(&tail[7..tail.len() - 1]).unwrap().parse::<u64>().unwrap() > 0);
        assert_eq!(deaf.recv(4096, false).err(), Some(Errno::EAGAIN));
        // The acknowledgement: no error, the request's header alone.
        let ack = sender.recv(4096, false).unwrap();
        assert_eq!((ack.from, ack.groups, ack.cred), (0, 0, (0, 0, 0)));
        assert_eq!(ack.data.len(), 36);
        assert_eq!(u16::from_le_bytes(ack.data[4..6].try_into().unwrap()), NLMSG_ERROR);
        assert_eq!(u16::from_le_bytes(ack.data[6..8].try_into().unwrap()), NLM_F_CAPPED);
        assert_eq!(u32::from_le_bytes(ack.data[12..16].try_into().unwrap()), 7005);
        assert_eq!(i32::from_le_bytes(ack.data[16..20].try_into().unwrap()), 0);
        assert_eq!(&ack.data[20..36], &req[..16]);
    }

    /// An ordinary process's request is refused and returned whole (its
    /// header alone when the socket asked for that); it may not send to a
    /// socket or a group at all.
    #[test]
    fn an_ordinary_process_may_only_listen() {
        let s = uevent(user(7006));
        let req = broadcast_request("gextest@/devices/unit-7006", NLM_F_REQUEST, 7);
        assert_eq!(s.send(user(7006), None, &req), Ok(req.len() as u64));
        let r = s.recv(4096, false).unwrap();
        assert_eq!(i32::from_le_bytes(r.data[16..20].try_into().unwrap()), -1);
        assert_eq!(r.data.len(), 20 + ((req.len() + 3) & !3));
        assert_eq!(&r.data[20..20 + req.len()], &req[..]);
        s.set_option(option::CAP_ACK, 1).unwrap();
        s.send(user(7006), None, &req).unwrap();
        assert_eq!(s.recv(4096, false).unwrap().data.len(), 36);
        assert_eq!(s.send(user(7006), Some((1, 0)), b"x"), Err(Errno::EPERM));
        assert_eq!(s.send(user(7006), Some((0, 1)), b"x"), Err(Errno::EPERM));
        assert_eq!(s.connect(user(7006), 0, 1), Err(Errno::EPERM));
        assert_eq!(s.send(user(7006), None, b""), Err(Errno::ENODATA));
        // Root sends to a socket by its port, and to none there is not.
        let other = uevent(root(7007));
        assert_eq!(other.send(root(7007), Some((7006, 0)), b"hello"), Ok(5));
        let r = s.recv(3, true).unwrap();
        assert_eq!((&r.data[..], r.whole, r.from, r.groups, r.cred), (&b"hel"[..], 5, 7007, 0, (7007, 0, 0)));
        assert_eq!(s.recv(16, false).unwrap().data, b"hello");
        assert_eq!(other.send(root(7007), Some((0x7fff_ff00, 0)), b"hello"), Err(Errno::ECONNREFUSED));
    }

    /// A listener with no room loses events and is told so once, before
    /// what it has; then it hears again.
    #[test]
    fn a_listener_that_falls_behind_is_told_once() {
        let listener = uevent(user(7008));
        listener.bind(7008, 0, 1).unwrap();
        listener.set_rcvbuf(1, false);
        let sender = uevent(root(7009));
        let req = broadcast_request("gextest@/devices/unit-7008", NLM_F_REQUEST, 1);
        for _ in 0..64 {
            sender.send(root(7009), None, &req).unwrap();
        }
        assert!(listener.poll_readable());
        assert_eq!(listener.recv(4096, false).err(), Some(Errno::ENOBUFS));
        // Two, as on Linux: the first because the queue was empty, the
        // second because two still fit.
        let mut kept = 0;
        while listener.recv(4096, false).is_ok() {
            kept += 1;
        }
        assert_eq!(kept, 2);
        assert!(!listener.poll_readable());
        sender.send(root(7009), None, &req).unwrap();
        assert!(listener.recv(4096, false).is_ok());
        // One that asked not to be told is not.
        listener.set_option(option::NO_ENOBUFS, 1).unwrap();
        for _ in 0..64 {
            sender.send(root(7009), None, &req).unwrap();
        }
        assert!(listener.recv(4096, false).is_ok());
    }
}
