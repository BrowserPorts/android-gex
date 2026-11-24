//! `NETLINK_SOCK_DIAG` (`net/core/sock_diag.c`, `net/ipv4/inet_diag.c`,
//! `tcp_diag.c`, `udp_diag.c` at android17-6.18) for this kernel's inet
//! sockets: what Android's netd and system server ask of it (dumps of TCP
//! and UDP sockets by family and state, with netd's bytecode filters;
//! exact lookups for a connection's owner).
//!
//! - Types: `SOCK_DIAG_BY_FAMILY` (20) dumps or looks up; `SOCK_DESTROY`
//!   (21) is refused loudly here (the abort of a socket is not done yet);
//!   `TCPDIAG_GETSOCK`'s old form is refused loudly; any other type from
//!   16 is `EINVAL`. A payload under two bytes or a family past `AF_MAX`
//!   is `EINVAL`, a family other than IPv4 and IPv6 `ENOENT`, an inet
//!   request under 56 bytes `EINVAL`.
//! - A dump (`NLM_F_DUMP`, either bit) checks its bytecode first
//!   (`inet_diag_bc_audit`: `EINVAL`, `EPERM` for a mark condition without
//!   `CAP_NET_ADMIN`), then gives each socket of the family, protocol and
//!   states that passes the port filters and the bytecode, in datagrams of
//!   at most a page's worth, and `NLMSG_DONE` in a datagram of its own: an
//!   unknown protocol is `NLMSG_DONE` carrying `-ENOENT`. TCP gives its
//!   listeners, then (state bit 13) bound sockets never connected, then its
//!   connections; UDP its bound sockets.
//! - An exact lookup ignores the states and the bytecode: TCP by local
//!   (`src`) and remote (`dst`) ends, UDP with them the other way round (as
//!   Linux has them "for historical reasons"); `ENOENT` for none, a cookie
//!   that is not the socket's `ENOENT` (TCP) or `ESTALE` (UDP).
//! - Each socket: `inet_diag_msg` as the guest sees it (its addresses as
//!   `getsockname` and `getpeername` give them, its cookie `SO_COOKIE`'s,
//!   its owner, its inode `socket:[N]`'s), then the attributes in the
//!   kernel's order: shutdown, [TOS], [TCLASS], [v6only], [mark, to one
//!   with `CAP_NET_ADMIN`], [class id], cgroup id, socket options, [memory],
//!   [TCP: info, congestion control].
//!
//! The connections are the host's: their timers, queues, `tcp_info` and
//! the host stack's own states (SYN_RECV, TIME_WAIT, a closing orphan) are
//! not seen here. Those fields are 0 (`tcp_info` but its state), a
//! connection the host closed is CLOSE_WAIT, congestion control "cubic".

use crate::errno::Errno;
use crate::net::DiagView;
use std::sync::Arc;

pub const NETLINK_SOCK_DIAG: u32 = 4;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const TCPDIAG_GETSOCK: u16 = 18;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CAPPED: u16 = 0x100;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_MAX: u8 = 46;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_UDPLITE: u8 = 136;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSE: u8 = 7;
const TCP_SYN_RECV: u8 = 3;
const TCP_NEW_SYN_RECV: u8 = 12;
const TCP_BOUND_INACTIVE: u8 = 13;
const NOCOOKIE: u32 = !0;

/// Reply attributes (`INET_DIAG_*`).
mod at {
    pub const MEMINFO: u16 = 1;
    pub const INFO: u16 = 2;
    pub const CONG: u16 = 4;
    pub const TOS: u16 = 5;
    pub const TCLASS: u16 = 6;
    pub const SKMEMINFO: u16 = 7;
    pub const SHUTDOWN: u16 = 8;
    pub const SKV6ONLY: u16 = 11;
    pub const MARK: u16 = 15;
    pub const CLASS_ID: u16 = 17;
    pub const CGROUP_ID: u16 = 21;
    pub const SOCKOPT: u16 = 22;
}

/// `sizeof(struct tcp_info)`.
const TCP_INFO_LEN: usize = 280;

/// Who asks: whether they may see marks and test them (`CAP_NET_ADMIN`,
/// of both the socket's opener and the caller).
#[derive(Clone, Copy, Debug)]
pub struct Asker {
    pub net_admin: bool,
}

/// A socket of this kernel as sock_diag sees it.
struct Entry {
    view: DiagView,
    cookie: u64,
}

fn entries() -> Vec<(Arc<crate::net::Socket>, Entry)> {
    crate::net::live()
        .into_iter()
        .map(|s| {
            let handle: Arc<dyn crate::vfs::FileHandle> = s.clone();
            let cookie = crate::bpfsock::cookie_of(&handle);
            let view = s.diag_view();
            (s, Entry { view, cookie })
        })
        .collect()
}

/// An address as its family's `inet_diag_sockid` holds it: IPv4 in the
/// first word (the rest zero), IPv6 as `getsockname` writes it.
fn addr16(v6: bool, a: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    if v6 {
        b.copy_from_slice(&crate::net::build_sockaddr6(a, 0)[8..24]);
    } else {
        b[..4].copy_from_slice(&a.to_be_bytes());
    }
    b
}

fn put_attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn message(kind: u16, flags: u16, seq: u32, portid: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&portid.to_le_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// `netlink_ack`: an error with the whole request, or success with its
/// header alone.
fn ack(req: &[u8], err: i32, portid: u32) -> Vec<u8> {
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    let mut b = err.to_le_bytes().to_vec();
    if err == 0 {
        b.extend_from_slice(&req[..16]);
        message(NLMSG_ERROR, NLM_F_CAPPED, seq, portid, &b)
    } else {
        b.extend_from_slice(req);
        message(NLMSG_ERROR, 0, seq, portid, &b)
    }
}

/// `inet_sk_diag_fill` (and `inet_diag_msg_attrs_fill`): the message for
/// one socket.
fn fill(e: &Entry, ext: u8, asker: Asker, kind: u16, flags: u16, seq: u32, portid: u32) -> Vec<u8> {
    let v = &e.view;
    let mut b = vec![0u8; 72];
    b[0] = if v.v6 { AF_INET6 } else { AF_INET };
    b[1] = v.state;
    b[4..6].copy_from_slice(&v.local.1.to_be_bytes());
    b[6..8].copy_from_slice(&v.peer.1.to_be_bytes());
    b[8..24].copy_from_slice(&addr16(v.v6, v.local.0));
    b[24..40].copy_from_slice(&addr16(v.v6, v.peer.0));
    b[40..44].copy_from_slice(&v.opts.bound_dev_if.to_le_bytes());
    b[44..48].copy_from_slice(&(e.cookie as u32).to_le_bytes());
    b[48..52].copy_from_slice(&((e.cookie >> 32) as u32).to_le_bytes());
    b[64..68].copy_from_slice(&v.uid.to_le_bytes());
    b[68..72].copy_from_slice(&(v.ino as u32).to_le_bytes());
    // A connection the host has closed has had its peer's FIN.
    let shutdown: u8 = if v.state == 8 { 1 } else { 0 };
    put_attr(&mut b, at::SHUTDOWN, &[shutdown]);
    if ext & 0x10 != 0 {
        put_attr(&mut b, at::TOS, &[0]);
    }
    if v.v6 && ext & 0x20 != 0 {
        put_attr(&mut b, at::TCLASS, &[0]);
    }
    if v.v6 && (v.state == TCP_LISTEN || v.state == TCP_CLOSE) {
        put_attr(&mut b, at::SKV6ONLY, &[v.v6only as u8]);
    }
    if asker.net_admin {
        put_attr(&mut b, at::MARK, &v.opts.mark.to_le_bytes());
    }
    if ext & 0x20 != 0 {
        // No net_cls group here: its priority.
        put_attr(&mut b, at::CLASS_ID, &v.opts.priority.to_le_bytes());
    }
    put_attr(&mut b, at::CGROUP_ID, &v.cgroup.to_le_bytes());
    // Untouched options: multicast loop (and for IPv4 multicast all),
    // and a connection socket's mark.
    let mut sockopt = 0x10u8;
    if !v.v6 {
        sockopt |= 0x40;
    }
    if v.tcp {
        sockopt |= 0x02;
    }
    put_attr(&mut b, at::SOCKOPT, &[sockopt, 0]);
    if ext & 0x01 != 0 {
        put_attr(&mut b, at::MEMINFO, &[0u8; 16]);
    }
    if ext & 0x40 != 0 {
        put_attr(&mut b, at::SKMEMINFO, &[0u8; 36]);
    }
    // A connection socket's own (not a UDP one, nor TCP's bound-inactive).
    if v.tcp && (v.hashed || v.listening) {
        if ext & 0x02 != 0 {
            let mut info = [0u8; TCP_INFO_LEN];
            info[0] = v.state;
            put_attr(&mut b, at::INFO, &info);
        }
        if ext & 0x08 != 0 {
            put_attr(&mut b, at::CONG, b"cubic\0");
        }
    }
    message(kind, flags, seq, portid, &b)
}

// -- bytecode ----------------------------------------------------------------

const BC_NOP: u8 = 0;
const BC_JMP: u8 = 1;
const BC_S_GE: u8 = 2;
const BC_S_LE: u8 = 3;
const BC_D_GE: u8 = 4;
const BC_D_LE: u8 = 5;
const BC_AUTO: u8 = 6;
const BC_S_COND: u8 = 7;
const BC_D_COND: u8 = 8;
const BC_DEV_COND: u8 = 9;
const BC_MARK_COND: u8 = 10;
const BC_S_EQ: u8 = 11;
const BC_D_EQ: u8 = 12;
const BC_CGROUP_COND: u8 = 13;

fn op_at(bc: &[u8], at: usize) -> (u8, usize, usize) {
    (bc[at], bc[at + 1] as usize, u16::from_le_bytes([bc[at + 2], bc[at + 3]]) as usize)
}

/// `valid_cc`: from the start, steps of `yes` land on `cc` bytes from the
/// end.
fn valid_cc(bc: &[u8], len: usize, cc: usize) -> bool {
    let mut at = 0;
    let mut left = len;
    while left > 0 {
        let yes = bc[at + 1] as usize;
        if cc > left {
            return false;
        }
        if cc == left {
            return true;
        }
        if yes < 4 || yes & 3 != 0 {
            return false;
        }
        left = left.saturating_sub(yes);
        at += yes;
    }
    false
}

/// `inet_diag_bc_audit`: `len` is signed there, so a last `yes` that runs
/// past the end leaves it below zero, which is no program.
fn audit(bc: &[u8], asker: Asker) -> Result<(), Errno> {
    let total = bc.len();
    let mut len = total as isize;
    let mut at = 0;
    while len > 0 {
        let left = len as usize;
        if left < 4 {
            return Err(Errno::EINVAL);
        }
        let (code, yes, no) = op_at(bc, at);
        let mut min_len = 4;
        match code {
            BC_S_COND | BC_D_COND => {
                min_len += 8;
                if left < min_len {
                    return Err(Errno::EINVAL);
                }
                let family = bc[at + 4];
                let prefix = bc[at + 5] as usize;
                let addr_len = match family {
                    0 => 0,
                    AF_INET => 4,
                    AF_INET6 => 16,
                    _ => return Err(Errno::EINVAL),
                };
                min_len += addr_len;
                if left < min_len || prefix > 8 * addr_len {
                    return Err(Errno::EINVAL);
                }
            }
            BC_DEV_COND | BC_S_EQ | BC_S_GE | BC_S_LE | BC_D_EQ | BC_D_GE | BC_D_LE => {
                min_len += 4;
                if left < min_len {
                    return Err(Errno::EINVAL);
                }
            }
            BC_MARK_COND => {
                if !asker.net_admin {
                    return Err(Errno::EPERM);
                }
                min_len += 8;
                if left < min_len {
                    return Err(Errno::EINVAL);
                }
            }
            BC_CGROUP_COND => {
                min_len += 8;
                if left < min_len {
                    return Err(Errno::EINVAL);
                }
            }
            BC_AUTO | BC_JMP | BC_NOP => {}
            _ => return Err(Errno::EINVAL),
        }
        if code != BC_NOP {
            if no < min_len || no > left + 4 || no & 3 != 0 {
                return Err(Errno::EINVAL);
            }
            if no < left && !valid_cc(bc, total, left - no) {
                return Err(Errno::EINVAL);
            }
        }
        if yes < min_len || yes > left + 4 || yes & 3 != 0 {
            return Err(Errno::EINVAL);
        }
        at += yes;
        len -= yes as isize;
    }
    if len == 0 { Ok(()) } else { Err(Errno::EINVAL) }
}

/// `bitstring_match`: the first `bits` bits of two addresses.
fn prefix_match(a: &[u8], b: &[u8], bits: usize) -> bool {
    let whole = bits / 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// `inet_diag_bc_run` over one socket: whether it is taken.
fn run(bc: &[u8], e: &Entry) -> bool {
    let v = &e.view;
    let family = if v.v6 { AF_INET6 } else { AF_INET };
    let (saddr, daddr): (Vec<u8>, Vec<u8>) = if v.v6 {
        (addr16(true, v.local.0).to_vec(), addr16(true, v.peer.0).to_vec())
    } else {
        (v.local.0.to_be_bytes().to_vec(), v.peer.0.to_be_bytes().to_vec())
    };
    let (sport, dport) = (v.local.1 as u32, v.peer.1 as u32);
    let mut len = bc.len() as isize;
    let mut at = 0usize;
    while len > 0 {
        let (code, yes, no) = op_at(bc, at);
        let ok = match code {
            BC_NOP => true,
            BC_JMP => false,
            BC_S_EQ | BC_S_GE | BC_S_LE | BC_D_EQ | BC_D_GE | BC_D_LE => {
                let want = u16::from_le_bytes([bc[at + 6], bc[at + 7]]) as u32;
                match code {
                    BC_S_EQ => sport == want,
                    BC_S_GE => sport >= want,
                    BC_S_LE => sport <= want,
                    BC_D_EQ => dport == want,
                    BC_D_GE => dport >= want,
                    _ => dport <= want,
                }
            }
            // Ports bound by the kernel (`SOCK_BINDPORT_LOCK` unset): none
            // here is told apart.
            BC_AUTO => false,
            BC_S_COND | BC_D_COND => {
                let cf = bc[at + 4];
                let prefix = bc[at + 5] as usize;
                let port = i32::from_le_bytes(bc[at + 8..at + 12].try_into().unwrap());
                let addr = &bc[at + 12..];
                let (mine, myport) = if code == BC_S_COND { (&saddr, sport) } else { (&daddr, dport) };
                if port != -1 && port as u32 != myport {
                    false
                } else if cf != 0 && cf != family {
                    // An IPv4 condition on an IPv6 socket: its mapped address.
                    cf == AF_INET && family == AF_INET6 && mine[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && prefix_match(&mine[12..], addr, prefix)
                } else {
                    prefix == 0 || prefix_match(mine, addr, prefix)
                }
            }
            BC_DEV_COND => u32::from_le_bytes(bc[at + 4..at + 8].try_into().unwrap()) == v.opts.bound_dev_if,
            BC_MARK_COND => {
                let mark = u32::from_le_bytes(bc[at + 4..at + 8].try_into().unwrap());
                let mask = u32::from_le_bytes(bc[at + 8..at + 12].try_into().unwrap());
                v.opts.mark & mask == mark
            }
            BC_CGROUP_COND => u64::from_le_bytes(bc[at + 4..at + 12].try_into().unwrap()) == v.cgroup,
            _ => false,
        };
        let step = if ok { yes } else { no };
        len -= step as isize;
        at += step;
    }
    len == 0
}

// -- requests ----------------------------------------------------------------

/// The request's attributes after its 56 bytes: the bytecode and the
/// protocol (`inet_diag_parse_attrs`: a protocol of other than four bytes
/// is `EINVAL`).
fn parse_attrs(p: &[u8]) -> Result<(Option<&[u8]>, Option<u8>), Errno> {
    let mut bc = None;
    let mut proto = None;
    let mut at = 56;
    while at + 4 <= p.len() {
        let len = u16::from_le_bytes([p[at], p[at + 1]]) as usize;
        if len < 4 || at + len > p.len() {
            break;
        }
        let ty = u16::from_le_bytes([p[at + 2], p[at + 3]]) & 0x3fff;
        let data = &p[at + 4..at + len];
        match ty {
            1 => bc = Some(data),
            3 => {
                if data.len() != 4 {
                    return Err(Errno::EINVAL);
                }
                proto = Some(u32::from_le_bytes(data.try_into().unwrap()).min(255) as u8);
            }
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Ok((bc, proto))
}

/// A request from user space: the datagrams that answer it, in order.
pub fn answer(req: &[u8], asker: Asker, portid: u32) -> Vec<Vec<u8>> {
    let kind = u16::from_le_bytes(req[4..6].try_into().unwrap());
    let flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    let wants_ack = flags & NLM_F_ACK != 0;
    let fail = |e: Errno| vec![ack(req, -(e.0 as i32), portid)];
    // Not a request, or a control message: only an asked-for ack.
    if flags & NLM_F_REQUEST == 0 || kind < 0x10 {
        return if wants_ack { vec![ack(req, 0, portid)] } else { Vec::new() };
    }
    let p = &req[16..];
    match kind {
        TCPDIAG_GETSOCK => {
            crate::bpf::say_once("sock_diag's old TCPDIAG_GETSOCK request");
            return fail(Errno::EOPNOTSUPP);
        }
        SOCK_DIAG_BY_FAMILY | SOCK_DESTROY => {}
        _ => return fail(Errno::EINVAL),
    }
    if p.len() < 2 {
        return fail(Errno::EINVAL);
    }
    let family = p[0];
    if family >= AF_MAX {
        return fail(Errno::EINVAL);
    }
    if family != AF_INET && family != AF_INET6 {
        return fail(Errno::ENOENT);
    }
    if p.len() < 56 {
        return fail(Errno::EINVAL);
    }
    let (ext, states) = (p[2], u32::from_le_bytes(p[4..8].try_into().unwrap()));
    let id = &p[8..56];
    let sport = u16::from_be_bytes([id[0], id[1]]);
    let dport = u16::from_be_bytes([id[2], id[3]]);
    let cookie = (u32::from_le_bytes(id[40..44].try_into().unwrap()), u32::from_le_bytes(id[44..48].try_into().unwrap()));
    let dump = kind == SOCK_DIAG_BY_FAMILY && flags & NLM_F_DUMP != 0;
    let (bc, proto_attr) = match parse_attrs(p) {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    let proto = proto_attr.unwrap_or(p[1]);
    let v6 = family == AF_INET6;
    if dump {
        if let Some(bc) = bc {
            if let Err(e) = audit(bc, asker) {
                return fail(e);
            }
        }
        let done = |status: i32| message(NLMSG_DONE, NLM_F_MULTI, seq, portid, &status.to_le_bytes());
        if proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_UDPLITE {
            return vec![done(-(Errno::ENOENT.0 as i32))];
        }
        let mut states = states;
        if states & (1 << TCP_SYN_RECV) != 0 {
            states |= 1 << TCP_NEW_SYN_RECV;
        }
        let all = entries();
        let mine: Vec<&Entry> = all.iter().map(|(_, e)| e).filter(|e| e.view.v6 == v6).collect();
        let passes = |e: &Entry| bc.is_none_or(|bc| run(bc, e));
        let mut picked: Vec<&Entry> = Vec::new();
        if proto == IPPROTO_TCP {
            if states & (1 << TCP_LISTEN) != 0 && dport == 0 {
                picked.extend(mine.iter().filter(|e| e.view.tcp && e.view.listening && (sport == 0 || sport == e.view.local.1) && passes(e)));
            }
            if states & (1 << TCP_BOUND_INACTIVE) != 0 {
                picked.extend(mine.iter().filter(|e| e.view.tcp && !e.view.hashed && e.view.state == TCP_CLOSE && e.view.local.1 != 0 && passes(e)));
            }
            if states & !(1 << TCP_LISTEN) != 0 {
                picked.extend(mine.iter().filter(|e| {
                    let v = &e.view;
                    v.tcp && v.hashed && !v.listening && states & (1 << v.state) != 0 && (sport == 0 || sport == v.local.1) && (dport == 0 || dport == v.peer.1) && passes(e)
                }));
            }
        } else if proto == IPPROTO_UDP {
            picked.extend(mine.iter().filter(|e| {
                let v = &e.view;
                !v.tcp && v.hashed && states & (1 << v.state) != 0 && (sport == 0 || sport == v.local.1) && (dport == 0 || dport == v.peer.1) && passes(e)
            }));
        }
        // Datagrams of at most a page's worth of messages, then DONE alone.
        const GOODSIZE: usize = 4096 - 320;
        let mut out = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        for e in picked {
            let m = fill(e, ext, asker, SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, seq, portid);
            if !cur.is_empty() && cur.len() + m.len() > GOODSIZE {
                out.push(std::mem::take(&mut cur));
            }
            cur.extend_from_slice(&m);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out.push(done(0));
        return out;
    }
    // An exact lookup (or a destroy): no handler for the protocol is ENOENT.
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_UDPLITE {
        return fail(Errno::ENOENT);
    }
    let src = &id[4..20];
    let dst = &id[20..36];
    let dif = u32::from_le_bytes(id[36..40].try_into().unwrap());
    let all = entries();
    // The address an entry has as `id` holds it for the request's family:
    // an IPv6 request naming two mapped addresses looks in IPv4's tables.
    let mapped = |a: &[u8]| a[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    let v4_lookup = !v6 || (proto == IPPROTO_TCP || kind == SOCK_DESTROY) && mapped(src) && mapped(dst);
    let as_v4 = |a: &[u8]| -> u32 { if v6 { u32::from_be_bytes(a[12..16].try_into().unwrap()) } else { u32::from_be_bytes(a[..4].try_into().unwrap()) } };
    let same = |e: &Entry, addr: u32, want: &[u8]| -> bool {
        if v4_lookup {
            addr == as_v4(want)
        } else {
            e.view.v6 && addr16(true, addr) == want[..16]
        }
    };
    let dev_ok = |e: &Entry| e.view.opts.bound_dev_if == 0 || e.view.opts.bound_dev_if == dif;
    let tcp = proto == IPPROTO_TCP;
    // TCP: src the local end, dst the remote. UDP's lookup has them the
    // other way round; its destroy does not.
    let (local_a, local_p, remote_a, remote_p) = if tcp || kind == SOCK_DESTROY { (src, sport, dst, dport) } else { (dst, dport, src, sport) };
    let family_ok = |e: &Entry| if v4_lookup { true } else { e.view.v6 };
    let found = if tcp {
        all.iter()
            .map(|(_, e)| e)
            .find(|e| {
                let v = &e.view;
                v.tcp && v.hashed && !v.listening && family_ok(e) && v.local.1 == local_p && v.peer.1 == remote_p && same(e, v.local.0, local_a) && same(e, v.peer.0, remote_a) && dev_ok(e)
            })
            .or_else(|| {
                all.iter().map(|(_, e)| e).find(|e| {
                    let v = &e.view;
                    v.tcp && v.listening && family_ok(e) && v.local.1 == local_p && (v.local.0 == 0 || same(e, v.local.0, local_a)) && dev_ok(e)
                })
            })
    } else if proto == IPPROTO_UDP {
        // The best of the bound sockets on the port: a connected one to
        // the remote end before one bound to any.
        let score = |e: &Entry| -> Option<u32> {
            let v = &e.view;
            if v.tcp || !v.hashed || !family_ok(e) || v.local.1 != local_p || !dev_ok(e) {
                return None;
            }
            let mut s = 1;
            if v.local.0 != 0 {
                if !same(e, v.local.0, local_a) {
                    return None;
                }
                s += 4;
            }
            if v.state == 1 {
                if v.peer.1 != remote_p || !same(e, v.peer.0, remote_a) {
                    return None;
                }
                s += 4;
            }
            Some(s)
        };
        all.iter().map(|(_, e)| e).filter_map(|e| score(e).map(|s| (s, e))).max_by_key(|(s, _)| *s).map(|(_, e)| e)
    } else {
        None
    };
    let Some(e) = found else { return fail(Errno::ENOENT) };
    if cookie != (NOCOOKIE, NOCOOKIE) && (cookie.0 as u64 | (cookie.1 as u64) << 32) != e.cookie {
        return fail(if tcp || kind == SOCK_DESTROY { Errno::ENOENT } else { Errno::ESTALE });
    }
    if kind == SOCK_DESTROY {
        if !asker.net_admin {
            return fail(Errno::EPERM);
        }
        crate::bpf::say_once("SOCK_DESTROY (aborting a socket)");
        return fail(Errno::EOPNOTSUPP);
    }
    let mut out = vec![fill(e, ext, asker, SOCK_DIAG_BY_FAMILY, 0, seq, portid)];
    if wants_ack {
        out.push(ack(req, 0, portid));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netds_programs_pass_the_audit() {
        let admin = Asker { net_admin: true };
        // R1: one S_COND on an IPv4 /32: yes = its length, no = past it.
        let mut r1 = vec![BC_S_COND, 16, 20, 0, AF_INET, 32, 0, 0];
        r1.extend_from_slice(&(-1i32).to_le_bytes());
        r1.extend_from_slice(&[10, 0, 2, 15]);
        assert_eq!(audit(&r1, admin), Ok(()));
        // R2: MARK_COND, MARK_COND, JMP.
        let mut r2 = vec![BC_MARK_COND, 12, 32, 0];
        r2.extend_from_slice(&100u32.to_le_bytes());
        r2.extend_from_slice(&0xffffu32.to_le_bytes());
        r2.extend_from_slice(&[BC_MARK_COND, 12, 16, 0]);
        r2.extend_from_slice(&(1u32 << 16).to_le_bytes());
        r2.extend_from_slice(&(1u32 << 16).to_le_bytes());
        r2.extend_from_slice(&[BC_JMP, 4, 8, 0]);
        assert_eq!(audit(&r2, admin), Ok(()));
        assert_eq!(audit(&r2, Asker { net_admin: false }), Err(Errno::EPERM));
        // Bad: an unknown op, a jump past the end, a short condition.
        assert_eq!(audit(&[99, 4, 8, 0], admin), Err(Errno::EINVAL));
        assert_eq!(audit(&[BC_NOP, 8, 8, 0], admin), Err(Errno::EINVAL));
        assert_eq!(audit(&[BC_S_COND, 8, 12, 0, AF_INET, 0, 0, 0], admin), Err(Errno::EINVAL));
    }

    fn entry(local: (u32, u16), peer: (u32, u16), mark: u32) -> Entry {
        Entry {
            view: DiagView { tcp: true, v6: false, v6only: false, state: 1, listening: false, hashed: true, local, peer, ino: 9, uid: 10001, cgroup: 1, opts: crate::bpfsock::SockOpts { mark, priority: 0, bound_dev_if: 0 } },
            cookie: 42,
        }
    }

    #[test]
    fn netds_programs_choose_as_the_kernel_does() {
        let mut r1 = vec![BC_S_COND, 16, 20, 0, AF_INET, 32, 0, 0];
        r1.extend_from_slice(&(-1i32).to_le_bytes());
        r1.extend_from_slice(&[10, 0, 2, 15]);
        assert!(run(&r1, &entry((0x0a00_020f, 4000), (0x0808_0808, 443), 0)));
        assert!(!run(&r1, &entry((0x0a00_0210, 4000), (0x0808_0808, 443), 0)));
        // Accept iff (mark & 0xffff) == 100 and the permission bit unset.
        let mut r2 = vec![BC_MARK_COND, 12, 32, 0];
        r2.extend_from_slice(&100u32.to_le_bytes());
        r2.extend_from_slice(&0xffffu32.to_le_bytes());
        r2.extend_from_slice(&[BC_MARK_COND, 12, 16, 0]);
        r2.extend_from_slice(&(1u32 << 16).to_le_bytes());
        r2.extend_from_slice(&(1u32 << 16).to_le_bytes());
        r2.extend_from_slice(&[BC_JMP, 4, 8, 0]);
        assert!(run(&r2, &entry((0, 1), (0, 2), 100)));
        assert!(!run(&r2, &entry((0, 1), (0, 2), 100 | 1 << 16)));
        assert!(!run(&r2, &entry((0, 1), (0, 2), 101)));
    }

    #[test]
    fn a_socket_fills_as_the_kernel_lays_it_out() {
        let e = entry((0x7f00_0001, 4000), (0x7f00_0001, 5000), 7);
        let m = fill(&e, 0, Asker { net_admin: true }, 20, NLM_F_MULTI, 3, 9);
        // 16 + 72 + shutdown 8 + mark 8 + cgroup 12 + sockopt 8.
        assert_eq!(m.len(), 124);
        assert_eq!(&m[16 + 4..16 + 6], &4000u16.to_be_bytes());
        assert_eq!(&m[16 + 8..16 + 12], &[127, 0, 0, 1]);
        assert_eq!(&m[16 + 44..16 + 48], &42u32.to_le_bytes());
        assert_eq!(fill(&e, 0, Asker { net_admin: false }, 20, NLM_F_MULTI, 3, 9).len(), 116);
        assert_eq!(fill(&e, 0x02, Asker { net_admin: true }, 20, NLM_F_MULTI, 3, 9).len(), 124 + 284);
    }
}
