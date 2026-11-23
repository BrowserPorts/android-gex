//! Routes over `NETLINK_ROUTE` (`RTM_NEWROUTE`, `RTM_DELROUTE`,
//! `RTM_GETROUTE` dumps), IPv4 and IPv6, as Linux 6.18 keeps and answers
//! them (net/ipv4/fib_frontend.c, fib_semantics.c, fib_trie.c;
//! net/ipv6/route.c, ip6_fib.c). Kept, checked, dumped and announced; no
//! packet is routed by them (the guest's network is the host's, by
//! connection). Android's netd builds a table of routes for every network
//! and flushes one by dumping it and sending each route back to be
//! deleted.
//!
//! Each family has its tables, made when first named and kept for good
//! (IPv6's main and local from the start, IPv4's with its first address).
//! A route's checks are Linux's, in its order: the request's parse, then
//! `fib_create_info`/`ip6_route_info_create` (types and scopes, metrics,
//! the device, a gateway found through the tables), then the insertion's
//! rules (`NLM_F_EXCL`, `CREATE`, `REPLACE`, `APPEND`; IPv4 keys on
//! table, prefix, tos and priority, IPv6 on prefix and metric, with
//! same-metric gateway routes as one multipath group). A delete matches
//! as `fib_table_delete` and `ip6_route_del` do. A dump comes in each
//! family's order (tables by `id & 255`, newest first within one; IPv4 by
//! address, longest prefix first; IPv6 by the radix tree's post-order) and
//! layout (`fib_dump_info`, `rt6_fill_node`). Changes go to
//! `RTNLGRP_IPV4_ROUTE` and `RTNLGRP_IPV6_ROUTE`.
//!
//! The kernel's own routes follow the devices: an IPv4 address gives its
//! local route, and on a device that is up its prefix and broadcast routes
//! (`fib_add_ifaddr`); a device that is up gives IPv6's multicast route.
//! A device going down takes its routes with it (IPv4 silently, IPv6 each
//! announced).
//!
//! Not here, and said when asked: nexthop objects, multipath requests,
//! source-specific IPv6 routes in the dump order (they are kept), single
//! lookups (`RTM_GETROUTE` without a dump), strict-checked dumps. IPv6
//! addresses are not kept yet, so no IPv6 local or prefix route is made
//! for one, and a gateway or source address is never one of the machine's.
//! A gateway's route is looked for in the route's table, then local, main
//! and default (IPv4) or main (IPv6): Linux's rules, before any are added.

use crate::errno::Errno;
use crate::netdev;
use std::sync::Mutex;

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_PREF: u16 = 20;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_NH_ID: u16 = 30;
const RTA_FLOWLABEL: u16 = 31;
const RTA_DEL_REASON: u16 = 32;

const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BROADCAST: u8 = 3;
const RTN_ANYCAST: u8 = 4;
const RTN_MULTICAST: u8 = 5;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTN_THROW: u8 = 9;
const RTN_MAX: u8 = 11;

const SCOPE_UNIVERSE: u8 = 0;
const SCOPE_LINK: u8 = 253;
const SCOPE_HOST: u8 = 254;
const SCOPE_NOWHERE: u8 = 255;

const RTPROT_KERNEL: u8 = 2;
const RTPROT_BOOT: u8 = 3;

const TABLE_DEFAULT: u32 = 253;
const TABLE_MAIN: u32 = 254;
const TABLE_LOCAL: u32 = 255;

const RTNH_F_DEAD: u32 = 1;
const RTNH_F_PERVASIVE: u32 = 2;
const RTNH_F_ONLINK: u32 = 4;
const RTNH_F_LINKDOWN: u32 = 0x10;
const RTM_F_CLONED: u32 = 0x200;
const RTM_F_PREFIX: u32 = 0x800;

const NLM_F_MULTI: u16 = 0x2;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;

/// `RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE`.
const GROUP_V4: u32 = 7;
const GROUP_V6: u32 = 11;

/// `RTAX_MAX`, and the metrics' places.
const RTAX_MAX: usize = 17;
const RTAX_MTU: usize = 2;
const RTAX_HOPLIMIT: usize = 10;
const RTAX_ADVMSS: usize = 8;
const RTAX_FEATURES: usize = 12;
const RTAX_CC_ALGO: usize = 16;

/// IPv6's default metric for a route a program adds (`IP6_RT_PRIO_USER`),
/// and the kernel's own (`IP6_RT_PRIO_ADDRCONF`).
const PRIO_USER: u32 = 1024;
const PRIO_ADDRCONF: u32 = 256;

/// One route.
#[derive(Clone, Debug, PartialEq)]
struct Route {
    family: u8,
    table: u32,
    /// The prefix, its host bits clear: four bytes used for IPv4.
    dst: [u8; 16],
    dst_len: u8,
    /// IPv6's source prefix (`CONFIG_IPV6_SUBTREES`).
    src: [u8; 16],
    src_len: u8,
    tos: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    priority: u32,
    prefsrc: Option<[u8; 16]>,
    /// The device, 0 for none.
    oif: u32,
    gateway: Option<[u8; 16]>,
    /// Private metrics, `RTAX_*` by place (0 unused), when given.
    metrics: Option<[u32; RTAX_MAX + 1]>,
    /// `RTNH_F_ONLINK`.
    onlink: bool,
    /// IPv6's router preference (`RTF_PREF`).
    pref: u8,
    /// IPv6: a reject route by its device (loopback promotion); its
    /// device is loopback.
    reject: bool,
    /// IPv6: the multipath group it is in, 0 for none.
    group: u64,
}

struct Rib {
    v4: Vec<Route>,
    v6: Vec<Route>,
    /// The tables made, family and id, in the order made.
    tables: Vec<(u8, u32)>,
    next_group: u64,
}

static RIB: Mutex<Option<Rib>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Rib) -> R) -> R {
    let mut r = RIB.lock().unwrap_or_else(|e| e.into_inner());
    let rib = r.get_or_insert_with(|| {
        let mut rib = Rib { v4: Vec::new(), v6: Vec::new(), tables: Vec::new(), next_group: 1 };
        // IPv6's main and local tables are the namespace's from its start
        // (`fib6_tables_init`).
        rib.make_table(AF_INET6, TABLE_MAIN);
        rib.make_table(AF_INET6, TABLE_LOCAL);
        for d in netdev::all() {
            rib.device_routes(&d, false);
        }
        rib
    });
    f(rib)
}

impl Rib {
    fn has_table(&self, family: u8, id: u32) -> bool {
        self.tables.contains(&(family, id))
    }

    /// `fib_new_table` / `fib6_new_table`: made if missing. IPv4's local
    /// table, while no rule was added, brings main first.
    fn make_table(&mut self, family: u8, id: u32) {
        let id = if id == 0 { TABLE_MAIN } else { id };
        if family == AF_INET && id == TABLE_LOCAL && !self.has_table(AF_INET, TABLE_MAIN) {
            self.tables.push((AF_INET, TABLE_MAIN));
        }
        if !self.has_table(family, id) {
            self.tables.push((family, id));
        }
    }

    /// The kernel's own routes for a device as it now is: IPv4's for its
    /// address (`fib_add_ifaddr`), IPv6's multicast route when it is up
    /// (`addrconf_add_mroute`). Announced with `announce`.
    fn device_routes(&mut self, d: &netdev::NetDev, announce: bool) {
        let up = d.running();
        let loopback = d.flags & netdev::IFF_LOOPBACK != 0;
        if let Some((addr, len)) = d.inet {
            self.make_table(AF_INET, TABLE_LOCAL);
            let a = u32::from_be_bytes(addr);
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            let kernel = |dst: u32, dst_len: u8, table: u32, kind: u8, scope: u8| Route {
                family: AF_INET,
                table,
                dst: v4(dst),
                dst_len,
                src: [0; 16],
                src_len: 0,
                tos: 0,
                protocol: RTPROT_KERNEL,
                scope,
                kind,
                priority: 0,
                prefsrc: Some(v4(a)),
                oif: d.index,
                gateway: None,
                metrics: None,
                onlink: false,
                pref: 0,
                reject: false,
                group: 0,
            };
            let mut add = vec![kernel(a, 32, TABLE_LOCAL, RTN_LOCAL, SCOPE_HOST)];
            if up {
                let prefix = a & mask;
                // Not 0.0.0.0/8, and not an address that is its own /32.
                if prefix >> 24 != 0 && !(a == prefix && len == 32) {
                    if loopback {
                        add.push(kernel(prefix, len, TABLE_LOCAL, RTN_LOCAL, SCOPE_HOST));
                    } else {
                        add.push(kernel(prefix, len, TABLE_MAIN, RTN_UNICAST, SCOPE_LINK));
                    }
                    if len < 31 {
                        add.push(kernel(prefix | !mask, 32, TABLE_LOCAL, RTN_BROADCAST, SCOPE_LINK));
                    }
                }
            }
            for r in add {
                // `CREATE|APPEND`: one already there is left as it is.
                if !self.v4.iter().any(|x| same_route(x, &r)) {
                    let flags = self.insert_v4(r.clone(), true);
                    if announce {
                        notify(RTM_NEWROUTE, flags, 0, 0, &r, &[]);
                    }
                }
            }
        }
        // IPv6 state needs an MTU of 1280 or more.
        if up && !loopback && d.mtu >= 1280 {
            let r = Route {
                family: AF_INET6,
                table: TABLE_LOCAL,
                dst: { let mut a = [0u8; 16]; a[0] = 0xff; a },
                dst_len: 8,
                src: [0; 16],
                src_len: 0,
                tos: 0,
                protocol: RTPROT_KERNEL,
                scope: SCOPE_UNIVERSE,
                kind: RTN_MULTICAST,
                priority: PRIO_ADDRCONF,
                prefsrc: None,
                oif: d.index,
                gateway: None,
                metrics: None,
                onlink: false,
                pref: 0,
                reject: false,
                group: 0,
            };
            if !self.v6.iter().any(|x| same_route(x, &r)) {
                let had = self.v6.iter().any(|x| x.table == r.table && x.dst == r.dst && x.dst_len == r.dst_len && x.priority == r.priority);
                self.v6.push(r.clone());
                if announce {
                    notify(RTM_NEWROUTE, if had { NLM_F_CREATE } else { NLM_F_CREATE | NLM_F_EXCL }, 0, 0, &r, &[]);
                }
            }
        }
    }

    /// IPv4's insertion of a route that is new to its key group: before
    /// the group's first (or after its last with `append`). The
    /// notification's flags (R3.5).
    fn insert_v4(&mut self, r: Route, append: bool) -> u16 {
        let key = |x: &Route| x.table == r.table && x.dst == r.dst && x.dst_len == r.dst_len && x.tos == r.tos && x.priority == r.priority;
        let first = self.v4.iter().position(key);
        let mut flags = NLM_F_EXCL | NLM_F_CREATE;
        match first {
            None => self.v4.push(r),
            Some(i) => {
                flags &= !NLM_F_EXCL;
                if append {
                    let last = self.v4.iter().rposition(key).unwrap_or(i);
                    self.v4.insert(last + 1, r);
                    flags |= NLM_F_APPEND;
                } else {
                    self.v4.insert(i, r);
                }
            }
        }
        flags
    }
}

/// Whether two routes are the same one (`fib_find_info` and `nh_comp`, or
/// IPv6's `rt6_duplicate_nexthop` within one prefix and metric).
fn same_route(a: &Route, b: &Route) -> bool {
    let metrics = |m: &Option<[u32; RTAX_MAX + 1]>| m.unwrap_or([0; RTAX_MAX + 1]);
    a.family == b.family
        && a.table == b.table
        && a.dst == b.dst
        && a.dst_len == b.dst_len
        && a.src == b.src
        && a.src_len == b.src_len
        && a.tos == b.tos
        && a.priority == b.priority
        && a.kind == b.kind
        && a.protocol == b.protocol
        && a.scope == b.scope
        && a.prefsrc == b.prefsrc
        && a.oif == b.oif
        && a.gateway == b.gateway
        && a.onlink == b.onlink
        && metrics(&a.metrics) == metrics(&b.metrics)
}

fn v4(a: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&a.to_be_bytes());
    out
}

fn v4_of(a: &[u8; 16]) -> u32 {
    u32::from_be_bytes(a[..4].try_into().unwrap())
}

/// The attributes of a message, by kind (the last of a kind wins), with
/// the nested and byte-order bits taken off.
fn attrs(data: &[u8]) -> Vec<(u16, &[u8])> {
    netdev::attrs_of(data)
}

fn get<'a>(tb: &[(u16, &'a [u8])], k: u16) -> Option<&'a [u8]> {
    tb.iter().rev().find(|(t, _)| *t == k).map(|(_, d)| *d)
}

fn u32_at(d: &[u8]) -> u32 {
    u32::from_le_bytes(d[..4].try_into().unwrap())
}

/// The request's `struct rtmsg`.
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
}

fn rtmsg(body: &[u8]) -> Result<RtMsg, Errno> {
    if body.len() < 12 {
        return Err(Errno::EINVAL);
    }
    Ok(RtMsg { family: body[0], dst_len: body[1], src_len: body[2], tos: body[3], table: body[4], protocol: body[5], scope: body[6], kind: body[7], flags: u32::from_le_bytes(body[8..12].try_into().unwrap()) })
}

/// `ip_metrics_convert`: the nested metrics, checked and clamped.
fn parse_metrics(data: &[u8]) -> Result<[u32; RTAX_MAX + 1], Errno> {
    let mut m = [0u32; RTAX_MAX + 1];
    for (k, d) in attrs(data) {
        let k = k as usize;
        if k == 0 {
            continue;
        }
        if k > RTAX_MAX {
            return Err(Errno::EINVAL);
        }
        if k == RTAX_CC_ALGO {
            crate::bpf::say_once("a route's congestion control algorithm (RTAX_CC_ALGO)");
            return Err(Errno::EINVAL);
        }
        if d.len() != 4 {
            return Err(Errno::EINVAL);
        }
        let mut v = u32_at(d);
        match k {
            RTAX_ADVMSS => v = v.min(65495),
            RTAX_MTU => v = v.min(65520),
            RTAX_HOPLIMIT => v = v.min(255),
            RTAX_FEATURES if v & !0x1f != 0 => return Err(Errno::EINVAL),
            _ => {}
        }
        m[k] = v;
    }
    Ok(m)
}

/// The attribute policy's length checks (`rtm_ipv4_policy`,
/// `rtm_ipv6_policy`): `ERANGE` for one too short, `EINVAL` for the strict
/// types from `RTA_NH_ID`.
fn policy(family: u8, tb: &[(u16, &[u8])]) -> Result<(), Errno> {
    for (k, d) in tb {
        let need = match (*k, family) {
            (RTA_GATEWAY | RTA_PREFSRC, AF_INET6) => 16,
            (RTA_DST | RTA_SRC | RTA_GATEWAY | RTA_PREFSRC, _) => 4,
            (RTA_OIF | 3 | RTA_PRIORITY | 11 | 25 | 16 | RTA_TABLE, _) => 4,
            (23, AF_INET6) => 4,
            (RTA_MULTIPATH, _) => 8,
            (RTA_ENCAP_TYPE | 28 | 29, _) => 2,
            (RTA_PREF, AF_INET6) | (27, _) => 1,
            (RTA_METRICS | RTA_ENCAP, _) if !d.is_empty() => 4,
            (RTA_NH_ID, _) => {
                if d.len() != 4 {
                    return Err(Errno::EINVAL);
                }
                0
            }
            (RTA_FLOWLABEL, AF_INET6) if d.len() != 4 => return Err(Errno::EINVAL),
            (RTA_FLOWLABEL, AF_INET) | (RTA_DEL_REASON, _) => return Err(Errno::EINVAL),
            _ => 0,
        };
        // IPv4's addresses are u32s; IPv6's DST and SRC have no policy.
        let need = if family == AF_INET6 && matches!(*k, RTA_DST | RTA_SRC) { 0 } else { need };
        if d.len() < need {
            return Err(Errno::ERANGE);
        }
    }
    Ok(())
}

fn mask(addr: &mut [u8; 16], len: u8) {
    for i in len as usize..128 {
        addr[i / 8] &= !(0x80 >> (i % 8));
    }
}

/// Whether `addr` is in `dst`/`len`.
fn covers(dst: &[u8; 16], len: u8, addr: &[u8; 16]) -> bool {
    (0..len as usize).all(|i| (dst[i / 8] ^ addr[i / 8]) & (0x80 >> (i % 8)) == 0)
}

/// What a lookup of a gateway found.
enum Found {
    Route(Route),
    /// An error route's: its errno, or `None` for `throw` (go on).
    Error(Option<Errno>),
    Miss,
}

/// `fib_table_lookup` of `addr` in one IPv4 table: the longest prefix
/// whose route has at least scope `scope` and, with `oif`, that device.
fn lookup_v4(rib: &Rib, table: u32, addr: u32, scope: u8, oif: u32) -> Found {
    let a = v4(addr);
    let mut cands: Vec<&Route> = rib.v4.iter().filter(|r| r.table == table && covers(&r.dst, r.dst_len, &a)).collect();
    cands.sort_by(|x, y| y.dst_len.cmp(&x.dst_len));
    for r in cands {
        let error = match r.kind {
            RTN_UNREACHABLE => Some(Some(Errno::EHOSTUNREACH)),
            RTN_PROHIBIT => Some(Some(Errno::EACCES)),
            RTN_BLACKHOLE => Some(Some(Errno::EINVAL)),
            RTN_THROW => Some(None),
            _ => None,
        };
        if let Some(e) = error {
            return Found::Error(e);
        }
        if r.scope < scope || (oif != 0 && r.oif != oif) {
            continue;
        }
        return Found::Route(r.clone());
    }
    Found::Miss
}

/// IPv4's gateway check (`fib_check_nh_v4_gw`, no `ONLINK`): the route
/// that reaches `gw`, in `table` first, then as the rules Linux starts
/// with would find it (local, main, default).
fn resolve_v4_gw(rib: &Rib, table: u32, gw: u32, scope: u8, oif: u32) -> Result<Route, Errno> {
    let scope = scope.saturating_add(1).max(SCOPE_LINK);
    if table != 0 && table != TABLE_MAIN && rib.has_table(AF_INET, table) {
        if let Found::Route(r) = lookup_v4(rib, table, gw, scope, oif) {
            return Ok(r);
        }
    }
    for t in [TABLE_LOCAL, TABLE_MAIN, TABLE_DEFAULT] {
        match lookup_v4(rib, t, gw, scope, oif) {
            Found::Route(r) => return Ok(r),
            Found::Error(Some(e)) => return Err(e),
            Found::Error(None) | Found::Miss => {}
        }
    }
    Err(Errno::ENETUNREACH)
}

/// `inet_addr_type_table` of `addr` in the local table (main as local):
/// the type of the route there that covers it, else unicast.
fn addr_type_v4(rib: &Rib, addr: u32) -> u8 {
    match lookup_v4(rib, TABLE_LOCAL, addr, 0, 0) {
        Found::Route(r) => r.kind,
        _ => RTN_UNICAST,
    }
}

/// The device's state, for a route's checks.
fn device(oif: u32) -> Option<netdev::NetDev> {
    netdev::by_index(oif)
}

/// `RTM_NEWROUTE` for IPv4 (`inet_rtm_newroute`).
fn add_v4(m: &RtMsg, nl_flags: u16, tb: &[(u16, &[u8])], portid: u32, seq: u32) -> Result<(), Errno> {
    let r = parse_v4(m, tb, true)?;
    with(|rib| {
        rib.make_table(AF_INET, r.table);
        let mut r = r;
        check_v4(rib, &mut r, m.flags, tb)?;
        // `fib_table_insert`.
        let key = |x: &Route| x.table == r.table && x.dst == r.dst && x.dst_len == r.dst_len && x.tos == r.tos && x.priority == r.priority;
        let first = rib.v4.iter().position(key);
        if let Some(i) = first {
            if nl_flags & NLM_F_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if nl_flags & NLM_F_REPLACE != 0 {
                let exact = rib.v4.iter().position(|x| key(x) && same_route(x, &r));
                match exact {
                    Some(j) if j == i => return Ok(()),
                    Some(_) => return Err(Errno::EEXIST),
                    None => {
                        rib.v4[i] = r.clone();
                        notify(RTM_NEWROUTE, NLM_F_REPLACE, portid, seq, &r, &[]);
                        return Ok(());
                    }
                }
            }
            if rib.v4.iter().any(|x| key(x) && same_route(x, &r)) {
                return Err(Errno::EEXIST);
            }
        }
        if nl_flags & NLM_F_CREATE == 0 {
            return Err(Errno::ENOENT);
        }
        let flags = rib.insert_v4(r.clone(), nl_flags & NLM_F_APPEND != 0);
        notify(RTM_NEWROUTE, flags, portid, seq, &r, &[]);
        Ok(())
    })
}

/// `rtm_to_fib_config`: a route as an IPv4 request describes it.
fn parse_v4(m: &RtMsg, tb: &[(u16, &[u8])], adding: bool) -> Result<Route, Errno> {
    policy(AF_INET, tb)?;
    if m.tos & 3 != 0 || m.kind > RTN_MAX {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_ENCAP_TYPE).is_some() {
        return Err(Errno::EOPNOTSUPP);
    }
    if m.dst_len > 32 {
        return Err(Errno::EINVAL);
    }
    let dst = get(tb, RTA_DST).map(|d| u32::from_be_bytes(d[..4].try_into().unwrap())).unwrap_or(0);
    if m.dst_len < 32 && dst.checked_shl(m.dst_len as u32).unwrap_or(0) != 0 {
        return Err(Errno::EINVAL);
    }
    let nh_id = get(tb, RTA_NH_ID).is_some();
    if nh_id && (get(tb, RTA_OIF).is_some() || get(tb, RTA_GATEWAY).is_some() || get(tb, RTA_ENCAP).is_some() || get(tb, RTA_MULTIPATH).is_some()) {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_GATEWAY).is_some() && get(tb, RTA_VIA).is_some() {
        return Err(Errno::EINVAL);
    }
    let mut gateway = get(tb, RTA_GATEWAY).map(|d| u32::from_be_bytes(d[..4].try_into().unwrap())).filter(|g| *g != 0).map(v4);
    if let Some(via) = get(tb, RTA_VIA) {
        if via.len() < 2 {
            return Err(Errno::EINVAL);
        }
        match (u16::from_le_bytes([via[0], via[1]]) as u8, via.len() - 2) {
            (AF_INET, 4) => gateway = Some(v4(u32::from_be_bytes(via[2..6].try_into().unwrap()))).filter(|g| v4_of(g) != 0),
            (AF_INET6, 16) => {
                crate::bpf::say_once("an IPv4 route by an IPv6 gateway (RTA_VIA)");
                return Err(Errno::EOPNOTSUPP);
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    let table = get(tb, RTA_TABLE).map(u32_at).unwrap_or(m.table as u32);
    let table = if table == 0 { TABLE_MAIN } else { table };
    if nh_id {
        // No nexthop objects are kept: none exists.
        return Err(Errno::EINVAL);
    }
    let _ = adding;
    Ok(Route {
        family: AF_INET,
        table,
        dst: v4(dst),
        dst_len: m.dst_len,
        src: [0; 16],
        src_len: 0,
        tos: m.tos,
        protocol: m.protocol,
        scope: m.scope,
        kind: m.kind,
        priority: get(tb, RTA_PRIORITY).map(u32_at).unwrap_or(0),
        prefsrc: get(tb, RTA_PREFSRC).map(|d| v4(u32::from_be_bytes(d[..4].try_into().unwrap()))).filter(|a| v4_of(a) != 0),
        oif: get(tb, RTA_OIF).map(u32_at).unwrap_or(0),
        gateway,
        metrics: None,
        onlink: m.flags & RTNH_F_ONLINK != 0,
        pref: 0,
        reject: false,
        group: 0,
    })
}

/// `fib_create_info` and `fib_check_nh`.
fn check_v4(rib: &Rib, r: &mut Route, rtm_flags: u32, tb: &[(u16, &[u8])]) -> Result<(), Errno> {
    // The least scope a type takes (`fib_props`).
    let min_scope = match r.kind {
        RTN_UNICAST | RTN_MULTICAST | RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_THROW => SCOPE_UNIVERSE,
        RTN_LOCAL => SCOPE_HOST,
        RTN_BROADCAST | RTN_ANYCAST => SCOPE_LINK,
        _ => SCOPE_NOWHERE,
    };
    if min_scope > r.scope || rtm_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN) != 0 {
        return Err(Errno::EINVAL);
    }
    if let Some(d) = get(tb, RTA_METRICS) {
        r.metrics = Some(parse_metrics(d)?);
    }
    if get(tb, RTA_MULTIPATH).is_some() {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_ENCAP).is_some() {
        return Err(Errno::EOPNOTSUPP);
    }
    let error_type = matches!(r.kind, RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_THROW | 10 | 11);
    if error_type {
        if r.gateway.is_some() || r.oif != 0 || get(tb, RTA_GATEWAY).is_some() {
            return Err(Errno::EINVAL);
        }
        return Ok(());
    }
    if !matches!(r.kind, RTN_UNICAST | RTN_LOCAL | RTN_BROADCAST | RTN_ANYCAST | RTN_MULTICAST) || r.scope > SCOPE_HOST {
        return Err(Errno::EINVAL);
    }
    if r.scope == SCOPE_HOST {
        if r.gateway.is_some() {
            return Err(Errno::EINVAL);
        }
        device(r.oif).ok_or(Errno::ENODEV)?;
    } else if let Some(gw) = r.gateway {
        let gw = v4_of(&gw);
        if r.onlink {
            if r.scope >= SCOPE_LINK {
                return Err(Errno::EINVAL);
            }
            let d = device(r.oif).filter(|d| d.mtu >= 68).ok_or(Errno::ENODEV)?;
            if !d.running() {
                return Err(Errno::ENETDOWN);
            }
            let bad = gw >> 24 == 0 || gw == u32::MAX || gw >> 28 == 0xe;
            if bad || addr_type_v4(rib, gw) != RTN_UNICAST {
                return Err(Errno::EINVAL);
            }
        } else {
            let found = resolve_v4_gw(rib, r.table, gw, r.scope, r.oif)?;
            if !matches!(found.kind, RTN_UNICAST | RTN_LOCAL) {
                return Err(Errno::EINVAL);
            }
            let d = device(found.oif).ok_or(Errno::EINVAL)?;
            if !d.running() {
                return Err(Errno::ENETDOWN);
            }
            r.oif = found.oif;
        }
    } else {
        if rtm_flags & (RTNH_F_ONLINK | RTNH_F_PERVASIVE) != 0 {
            return Err(Errno::EINVAL);
        }
        let d = device(r.oif).filter(|d| d.mtu >= 68).ok_or(Errno::ENODEV)?;
        if !d.running() {
            return Err(Errno::ENETDOWN);
        }
    }
    // `fib_valid_prefsrc`.
    if let Some(p) = r.prefsrc {
        let local = (r.kind == RTN_LOCAL && p == r.dst) || addr_type_v4(rib, v4_of(&p)) == RTN_LOCAL;
        if !local {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// `RTM_DELROUTE` for IPv4 (`inet_rtm_delroute`, `fib_table_delete`).
fn del_v4(m: &RtMsg, tb: &[(u16, &[u8])], portid: u32, seq: u32) -> Result<(), Errno> {
    let want = parse_v4(m, tb, false)?;
    let req_metrics = get(tb, RTA_METRICS);
    with(|rib| {
        if !rib.has_table(AF_INET, want.table) {
            return Err(Errno::ESRCH);
        }
        // In dump order within the key: priority ascending, then the
        // group's order.
        let mut idx: Vec<usize> = (0..rib.v4.len()).filter(|&i| {
            let x = &rib.v4[i];
            x.table == want.table && x.dst == want.dst && x.dst_len == want.dst_len && x.tos == want.tos
        }).collect();
        idx.sort_by_key(|&i| rib.v4[i].priority);
        let nh = want.oif != 0 || want.gateway.is_some();
        let found = idx.into_iter().find(|&i| {
            let x = &rib.v4[i];
            (want.kind == 0 || want.kind == x.kind)
                && (want.scope == SCOPE_NOWHERE || want.scope == x.scope)
                && (want.prefsrc.is_none() || want.prefsrc == x.prefsrc)
                && (want.protocol == 0 || want.protocol == x.protocol)
                && (want.priority == 0 || want.priority == x.priority)
                && (!nh || ((want.oif == 0 || want.oif == x.oif) && (want.gateway.is_none() || want.gateway == x.gateway)))
                && metrics_match(req_metrics, &x.metrics)
        });
        let i = found.ok_or(Errno::ESRCH)?;
        let gone = rib.v4.remove(i);
        notify(RTM_DELROUTE, 0, portid, seq, &gone, &[]);
        Ok(())
    })
}

/// `fib_metrics_match`: each metric the request gives equals the route's.
fn metrics_match(req: Option<&[u8]>, have: &Option<[u32; RTAX_MAX + 1]>) -> bool {
    let Some(req) = req else { return true };
    let have = have.unwrap_or([0; RTAX_MAX + 1]);
    attrs(req).into_iter().all(|(k, d)| {
        let k = k as usize;
        k == 0 || (k <= RTAX_MAX && d.len() == 4 && have[k] == u32_at(d))
    })
}

/// `rtm_to_fib6_config`.
fn parse_v6(m: &RtMsg, tb: &[(u16, &[u8])]) -> Result<Route, Errno> {
    policy(AF_INET6, tb)?;
    if m.tos != 0 || get(tb, RTA_FLOWLABEL).is_some() {
        return Err(Errno::EINVAL);
    }
    let nh_id = get(tb, RTA_NH_ID).is_some();
    if nh_id && (get(tb, RTA_GATEWAY).is_some() || get(tb, RTA_OIF).is_some() || get(tb, RTA_MULTIPATH).is_some() || get(tb, RTA_ENCAP).is_some()) {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_VIA).is_some() {
        return Err(Errno::EINVAL);
    }
    let prefix = |k: u16, len: u8| -> Result<[u8; 16], Errno> {
        let mut a = [0u8; 16];
        if let Some(d) = get(tb, k) {
            let n = (len as usize).div_ceil(8);
            if d.len() < n || n > 16 {
                return Err(Errno::EINVAL);
            }
            a[..n].copy_from_slice(&d[..n]);
        }
        Ok(a)
    };
    let dst = prefix(RTA_DST, m.dst_len.min(128))?;
    let src = prefix(RTA_SRC, m.src_len.min(128))?;
    if get(tb, RTA_ENCAP_TYPE).is_some() {
        return Err(Errno::EOPNOTSUPP);
    }
    let pref = match get(tb, RTA_PREF).map(|d| d[0]) {
        Some(3) => 3,
        Some(1) => 1,
        _ => 0,
    };
    let gateway = get(tb, RTA_GATEWAY).map(|d| <[u8; 16]>::try_from(&d[..16]).unwrap());
    Ok(Route {
        family: AF_INET6,
        table: get(tb, RTA_TABLE).map(u32_at).unwrap_or(m.table as u32),
        dst,
        dst_len: m.dst_len,
        src,
        src_len: m.src_len,
        tos: 0,
        protocol: m.protocol,
        scope: SCOPE_UNIVERSE,
        kind: m.kind,
        priority: get(tb, RTA_PRIORITY).map(u32_at).unwrap_or(0),
        prefsrc: get(tb, RTA_PREFSRC).map(|d| <[u8; 16]>::try_from(&d[..16]).unwrap()).filter(|a| *a != [0; 16]),
        oif: get(tb, RTA_OIF).map(u32_at).unwrap_or(0),
        gateway,
        metrics: None,
        onlink: m.flags & RTNH_F_ONLINK != 0,
        pref,
        reject: false,
        group: 0,
    })
}

fn is_reject(kind: u8) -> bool {
    matches!(kind, RTN_UNREACHABLE | RTN_BLACKHOLE | RTN_PROHIBIT | RTN_THROW)
}

/// IPv6 lookup of `addr` in one table: the longest prefix's first route
/// (metric order), with `oif` on that device.
fn lookup_v6(rib: &Rib, table: u32, addr: &[u8; 16], oif: u32) -> Option<Route> {
    let mut cands: Vec<&Route> = rib.v6.iter().filter(|r| r.table == table && r.src_len == 0 && covers(&r.dst, r.dst_len, addr) && (oif == 0 || r.oif == oif)).collect();
    cands.sort_by(|x, y| y.dst_len.cmp(&x.dst_len).then(x.priority.cmp(&y.priority)));
    cands.first().map(|r| (*r).clone())
}

/// `RTM_NEWROUTE` for IPv6 (`inet6_rtm_newroute`, `ip6_route_add`).
fn add_v6(m: &RtMsg, nl_flags: u16, tb: &[(u16, &[u8])], portid: u32, seq: u32) -> Result<(), Errno> {
    let mut r = parse_v6(m, tb)?;
    if r.priority == 0 {
        r.priority = PRIO_USER;
    }
    // `fib6_config_validate`.
    if m.flags & RTM_F_CLONED != 0 || r.kind > RTN_MAX || r.dst_len > 128 || r.src_len > 128 {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_NH_ID).is_some() && r.src_len != 0 {
        return Err(Errno::EINVAL);
    }
    with(|rib| {
        // `ip6_route_info_create`: the table first, whatever follows.
        let table = if r.table == 0 { TABLE_MAIN } else { r.table };
        rib.make_table(AF_INET6, table);
        r.table = table;
        if let Some(d) = get(tb, RTA_METRICS) {
            r.metrics = Some(parse_metrics(d)?);
        }
        if r.protocol == 0 {
            r.protocol = RTPROT_BOOT;
        }
        if r.kind == 0 {
            r.kind = RTN_UNICAST;
        }
        mask(&mut r.dst, r.dst_len);
        mask(&mut r.src, r.src_len);
        if get(tb, RTA_NH_ID).is_some() {
            return Err(Errno::EINVAL);
        }
        if get(tb, RTA_MULTIPATH).is_some() {
            crate::bpf::say_once("an IPv6 multipath route request (RTA_MULTIPATH)");
            return Err(Errno::EOPNOTSUPP);
        }
        check_v6(rib, &mut r, m.flags, tb)?;
        insert_v6(rib, r, nl_flags, portid, seq)
    })
}

/// `fib6_nh_init` and `ip6_validate_gw`.
fn check_v6(rib: &Rib, r: &mut Route, rtm_flags: u32, tb: &[(u16, &[u8])]) -> Result<(), Errno> {
    let mut dev = None;
    if r.oif != 0 {
        dev = Some(device(r.oif).filter(|d| d.mtu >= 1280).ok_or(Errno::ENODEV)?);
    }
    if rtm_flags & RTNH_F_ONLINK != 0 {
        let d = dev.as_ref().ok_or(Errno::ENODEV)?;
        if !d.running() {
            return Err(Errno::ENETDOWN);
        }
    }
    if is_reject(r.kind) {
        // The device is loopback, whatever was asked; a gateway is dropped.
        r.oif = 1;
        r.gateway = None;
        r.reject = true;
        return Ok(());
    }
    if let Some(gw) = r.gateway {
        let link_local = gw[0] == 0xfe && gw[1] & 0xc0 == 0x80;
        if !link_local {
            let unspecified = gw == [0; 16];
            if unspecified || gw[0] == 0xff {
                return Err(Errno::EINVAL);
            }
            if rtm_flags & RTNH_F_ONLINK == 0 {
                // In the route's table, then main.
                let in_table = if r.table != 0 { lookup_v6(rib, r.table, &gw, r.oif).filter(|f| !f.reject && !is_reject(f.kind) && f.gateway.is_none() && (r.oif == 0 || f.oif == r.oif)) } else { None };
                let found = in_table.or_else(|| lookup_v6(rib, TABLE_MAIN, &gw, 0).filter(|f| !f.reject && !is_reject(f.kind) && f.gateway.is_none())).ok_or(Errno::EHOSTUNREACH)?;
                if r.oif != 0 && found.oif != r.oif {
                    return Err(Errno::EHOSTUNREACH);
                }
                if dev.is_none() {
                    r.oif = found.oif;
                    dev = device(found.oif);
                }
            }
        }
        let d = dev.as_ref().ok_or(Errno::EINVAL)?;
        if d.flags & netdev::IFF_LOOPBACK != 0 {
            return Err(Errno::EINVAL);
        }
    }
    let d = dev.ok_or(Errno::ENODEV)?;
    if !d.running() && !matches!(r.kind, RTN_LOCAL | RTN_ANYCAST) {
        return Err(Errno::ENETDOWN);
    }
    // Loopback promotion: a route through loopback that is not ::1's.
    let loopback = { let mut a = [0u8; 16]; a[15] = 1; a };
    if d.flags & netdev::IFF_LOOPBACK != 0 && !(r.dst == loopback && r.dst_len == 128) && !matches!(r.kind, RTN_LOCAL | RTN_ANYCAST) {
        r.reject = true;
    }
    // No IPv6 address is kept here, so none is a valid source.
    if r.prefsrc.is_some() {
        return Err(Errno::EINVAL);
    }
    let _ = tb;
    Ok(())
}

/// Whether an IPv6 route may share a multipath group (`rt6_qualify_for_ecmp`).
fn ecmp(r: &Route) -> bool {
    r.gateway.is_some() && r.protocol != RTPROT_KERNEL
}

/// `fib6_add_rt2node`.
fn insert_v6(rib: &mut Rib, mut r: Route, nl_flags: u16, portid: u32, seq: u32) -> Result<(), Errno> {
    let node = |x: &Route| x.table == r.table && x.dst == r.dst && x.dst_len == r.dst_len && x.src == r.src && x.src_len == r.src_len;
    let any_node = rib.v6.iter().any(node);
    if !any_node && nl_flags & NLM_F_CREATE == 0 && nl_flags & NLM_F_REPLACE != 0 {
        return Err(Errno::ENOENT);
    }
    let same_metric: Vec<usize> = (0..rib.v6.len()).filter(|&i| node(&rib.v6[i]) && rib.v6[i].priority == r.priority).collect();
    let mut flags = NLM_F_EXCL | NLM_F_CREATE;
    if !same_metric.is_empty() {
        if nl_flags & NLM_F_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        flags &= !NLM_F_EXCL;
        if nl_flags & NLM_F_REPLACE != 0 {
            let target = same_metric.iter().copied().find(|&i| ecmp(&rib.v6[i]) == ecmp(&r)).unwrap_or(same_metric[0]);
            let old_group = rib.v6[target].group;
            rib.v6[target] = r.clone();
            if old_group != 0 && ecmp(&r) {
                // Its siblings go with it.
                let mut i = 0;
                while i < rib.v6.len() {
                    if i != target && rib.v6[i].group == old_group {
                        rib.v6.remove(i);
                        continue;
                    }
                    i += 1;
                }
            }
            if let Some(t) = rib.v6.iter_mut().find(|x| **x == r) {
                t.group = 0;
            }
            notify(RTM_NEWROUTE, NLM_F_REPLACE, portid, seq, &r, &[]);
            return Ok(());
        }
        for &i in &same_metric {
            let x = &rib.v6[i];
            if x.oif == r.oif && x.gateway == r.gateway {
                return Err(Errno::EEXIST);
            }
        }
        // A gateway route beside another: a multipath group.
        if ecmp(&r) {
            if let Some(&i) = same_metric.iter().find(|&&i| ecmp(&rib.v6[i])) {
                if rib.v6[i].group == 0 {
                    rib.v6[i].group = rib.next_group;
                    rib.next_group += 1;
                }
                r.group = rib.v6[i].group;
            }
        }
    } else if nl_flags & NLM_F_REPLACE != 0 && nl_flags & NLM_F_CREATE == 0 {
        return Err(Errno::ENOENT);
    }
    if nl_flags & NLM_F_APPEND != 0 {
        flags |= NLM_F_APPEND;
    }
    rib.v6.push(r.clone());
    let members: Vec<Route> = if r.group != 0 { rib.v6.iter().filter(|x| x.group == r.group).cloned().collect() } else { Vec::new() };
    notify(RTM_NEWROUTE, flags, portid, seq, &r, &members);
    Ok(())
}

/// `RTM_DELROUTE` for IPv6 (`ip6_route_del`).
fn del_v6(m: &RtMsg, tb: &[(u16, &[u8])], portid: u32, seq: u32) -> Result<(), Errno> {
    let mut want = parse_v6(m, tb)?;
    if get(tb, RTA_NH_ID).is_some() {
        return Err(Errno::EINVAL);
    }
    if get(tb, RTA_MULTIPATH).is_some() {
        crate::bpf::say_once("an IPv6 multipath route delete (RTA_MULTIPATH)");
        return Err(Errno::EOPNOTSUPP);
    }
    mask(&mut want.dst, want.dst_len);
    mask(&mut want.src, want.src_len);
    let table = if want.table == 0 { TABLE_MAIN } else { want.table };
    with(|rib| {
        if !rib.has_table(AF_INET6, table) || m.flags & RTM_F_CLONED != 0 {
            return Err(Errno::ESRCH);
        }
        let i = rib
            .v6
            .iter()
            .position(|x| {
                x.table == table
                    && x.dst == want.dst
                    && x.dst_len == want.dst_len
                    && x.src == want.src
                    && x.src_len == want.src_len
                    && (want.priority == 0 || want.priority == x.priority)
                    && (want.protocol == 0 || want.protocol == x.protocol)
                    && (want.oif == 0 || want.oif == x.oif)
                    && (want.gateway.is_none() || want.gateway == x.gateway)
            })
            .ok_or(Errno::ESRCH)?;
        let group = rib.v6[i].group;
        if want.gateway.is_some() || group == 0 {
            let gone = rib.v6.remove(i);
            if group != 0 {
                let left: Vec<usize> = (0..rib.v6.len()).filter(|&j| rib.v6[j].group == group).collect();
                if left.len() == 1 {
                    rib.v6[left[0]].group = 0;
                }
            }
            notify(RTM_DELROUTE, 0, portid, seq, &Route { group: 0, ..gone }, &[]);
        } else {
            let members: Vec<Route> = rib.v6.iter().filter(|x| x.group == group).cloned().collect();
            notify(RTM_DELROUTE, 0, portid, seq, &members[0], &members);
            rib.v6.retain(|x| x.group != group);
        }
        Ok(())
    })
}

/// The request `req` (its header and `struct rtmsg`), by the socket
/// `portid`: a change, refused or done.
pub fn change(kind: u16, req: &[u8], portid: u32) -> Result<(), Errno> {
    let nl_flags = u16::from_le_bytes(req[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(req[8..12].try_into().unwrap());
    let body = &req[16..];
    // Less than a family's byte: nothing is done (`rtnetlink_rcv_msg`).
    if body.is_empty() {
        return Ok(());
    }
    let m = rtmsg(body)?;
    let tb = attrs(&body[12..]);
    match (kind, m.family) {
        (RTM_NEWROUTE, AF_INET) => add_v4(&m, nl_flags, &tb, portid, seq),
        (RTM_DELROUTE, AF_INET) => del_v4(&m, &tb, portid, seq),
        (RTM_NEWROUTE, AF_INET6) => add_v6(&m, nl_flags, &tb, portid, seq),
        (RTM_DELROUTE, AF_INET6) => del_v6(&m, &tb, portid, seq),
        _ => Err(Errno::EOPNOTSUPP),
    }
}

/// A route as a dump and a notification give it (`fib_dump_info`,
/// `rt6_fill_node`), its `struct rtmsg` and attributes; `members` for an
/// IPv6 multipath group, this route first.
fn fill(r: &Route, members: &[Route]) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    let table8 = if r.table < 256 { r.table as u8 } else { 252 };
    let mut flags = 0u32;
    if r.family == AF_INET {
        if r.onlink {
            flags |= RTNH_F_ONLINK;
        }
        if r.oif != 0 && device(r.oif).is_some_and(|d| !d.carrier) && r.scope != SCOPE_HOST {
            flags |= RTNH_F_LINKDOWN;
        }
        b.extend_from_slice(&[AF_INET, r.dst_len, 0, r.tos, table8, r.protocol, r.scope, r.kind]);
        b.extend_from_slice(&flags.to_le_bytes());
        attr(&mut b, RTA_TABLE, &r.table.to_le_bytes());
        if r.dst_len != 0 {
            attr(&mut b, RTA_DST, &r.dst[..4]);
        }
        if r.priority != 0 {
            attr(&mut b, RTA_PRIORITY, &r.priority.to_le_bytes());
        }
        metrics_attr(&mut b, &r.metrics);
        if let Some(p) = r.prefsrc {
            attr(&mut b, RTA_PREFSRC, &p[..4]);
        }
        if let Some(g) = r.gateway {
            attr(&mut b, RTA_GATEWAY, &g[..4]);
        }
        if r.oif != 0 {
            attr(&mut b, RTA_OIF, &r.oif.to_le_bytes());
        }
        return b;
    }
    if members.len() < 2 {
        if r.onlink {
            flags |= RTNH_F_ONLINK;
        }
        if !r.reject && !matches!(r.kind, RTN_LOCAL | RTN_ANYCAST) && device(r.oif).is_some_and(|d| !d.carrier) {
            flags |= RTNH_F_LINKDOWN;
        }
    }
    b.extend_from_slice(&[AF_INET6, r.dst_len, r.src_len, 0, table8, r.protocol, SCOPE_UNIVERSE, r.kind]);
    b.extend_from_slice(&flags.to_le_bytes());
    attr(&mut b, RTA_TABLE, &r.table.to_le_bytes());
    if r.dst_len != 0 {
        attr(&mut b, RTA_DST, &r.dst);
    }
    if r.src_len != 0 {
        attr(&mut b, RTA_SRC, &r.src);
    }
    if let Some(p) = r.prefsrc {
        attr(&mut b, RTA_PREFSRC, &p);
    }
    metrics_attr(&mut b, &r.metrics);
    attr(&mut b, RTA_PRIORITY, &r.priority.to_le_bytes());
    if members.len() >= 2 {
        let mut mp = Vec::new();
        for x in members {
            let mut nh = Vec::new();
            attr(&mut nh, RTA_GATEWAY, &x.gateway.unwrap_or([0; 16]));
            let mut nh_flags = 0u8;
            if x.onlink {
                nh_flags |= RTNH_F_ONLINK as u8;
            }
            mp.extend_from_slice(&((8 + nh.len()) as u16).to_le_bytes());
            mp.push(nh_flags);
            mp.push(0);
            mp.extend_from_slice(&(x.oif as i32).to_le_bytes());
            mp.extend_from_slice(&nh);
        }
        attr(&mut b, RTA_MULTIPATH, &mp);
    } else {
        if let Some(g) = r.gateway {
            attr(&mut b, RTA_GATEWAY, &g);
        }
        if r.oif != 0 {
            attr(&mut b, RTA_OIF, &r.oif.to_le_bytes());
        }
    }
    attr(&mut b, RTA_CACHEINFO, &[0u8; 32]);
    attr(&mut b, RTA_PREF, &[r.pref]);
    b
}

fn metrics_attr(b: &mut Vec<u8>, m: &Option<[u32; RTAX_MAX + 1]>) {
    let Some(m) = m else { return };
    if m.iter().all(|&v| v == 0) {
        return;
    }
    let mut n = Vec::new();
    for (k, &v) in m.iter().enumerate().skip(1) {
        if v != 0 {
            attr(&mut n, k as u16, &v.to_le_bytes());
        }
    }
    attr(b, RTA_METRICS, &n);
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn header(kind: u16, flags: u16, seq: u32, portid: u32, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    msg.extend_from_slice(&kind.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&portid.to_le_bytes());
    msg.extend_from_slice(body);
    msg
}

/// A change to the family's route group.
fn notify(kind: u16, flags: u16, portid: u32, seq: u32, r: &Route, members: &[Route]) {
    let body = fill(r, members);
    let group = if r.family == AF_INET { GROUP_V4 } else { GROUP_V6 };
    crate::netlink::route_notify(header(kind, flags, seq, portid, &body), group);
}

/// The order a family's tables are dumped in: by `id & 255`, the newest
/// first within one.
fn table_order(rib: &Rib, family: u8) -> Vec<u32> {
    let mut t: Vec<(usize, u32)> = rib.tables.iter().enumerate().filter(|(_, (f, _))| *f == family).map(|(i, (_, id))| (i, *id)).collect();
    t.sort_by(|a, b| (a.1 & 255).cmp(&(b.1 & 255)).then(b.0.cmp(&a.0)));
    t.into_iter().map(|(_, id)| id).collect()
}

/// IPv6's radix order of two prefixes (`fib6_walk`, post-order): at the
/// first bit they differ, 0 first; one within the other, the longer first.
fn radix(a: &[u8; 16], la: u8, b: &[u8; 16], lb: u8) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for i in 0..la.min(lb) as usize {
        let (x, y) = (a[i / 8] & (0x80 >> (i % 8)) != 0, b[i / 8] & (0x80 >> (i % 8)) != 0);
        if x != y {
            return if x { Ordering::Greater } else { Ordering::Less };
        }
    }
    lb.cmp(&la)
}

/// The routes of a family, in its dump's order, multipath groups once.
fn dump_family(rib: &Rib, family: u8) -> Vec<(Route, Vec<Route>)> {
    let mut out = Vec::new();
    for table in table_order(rib, family) {
        if family == AF_INET {
            let mut rs: Vec<&Route> = rib.v4.iter().filter(|r| r.table == table).collect();
            rs.sort_by(|a, b| v4_of(&a.dst).cmp(&v4_of(&b.dst)).then(b.dst_len.cmp(&a.dst_len)).then(b.tos.cmp(&a.tos)).then(a.priority.cmp(&b.priority)));
            out.extend(rs.into_iter().map(|r| (r.clone(), Vec::new())));
        } else {
            let mut rs: Vec<&Route> = rib.v6.iter().filter(|r| r.table == table).collect();
            rs.sort_by(|a, b| radix(&a.dst, a.dst_len, &b.dst, b.dst_len).then(radix(&a.src, a.src_len, &b.src, b.src_len)).then(a.priority.cmp(&b.priority)));
            let mut seen = Vec::new();
            for r in rs {
                if r.group != 0 {
                    if seen.contains(&r.group) {
                        continue;
                    }
                    seen.push(r.group);
                    let members: Vec<Route> = rib.v6.iter().filter(|x| x.group == r.group).cloned().collect();
                    out.push((r.clone(), members));
                } else {
                    out.push((r.clone(), Vec::new()));
                }
            }
        }
    }
    out
}

/// `RTM_GETROUTE` with `NLM_F_DUMP`, without strict checking: the
/// messages (`NLMSG_DONE` is the caller's). An IPv4 request for prefix
/// routes alone dumps nothing, as does an IPv6 one (none come from a
/// router's announcement here).
pub fn dump(req: &[u8], seq: u32) -> Vec<u8> {
    let body = &req[16..];
    let family = body.first().copied().unwrap_or(0);
    let prefix_only = body.len() >= 12 && u32::from_le_bytes(body[8..12].try_into().unwrap()) & RTM_F_PREFIX != 0;
    let mut out = Vec::new();
    with(|rib| {
        for f in [AF_INET, AF_INET6] {
            if (family != 0 && family != f) || prefix_only {
                continue;
            }
            for (r, members) in dump_family(rib, f) {
                out.extend_from_slice(&header(RTM_NEWROUTE, NLM_F_MULTI, seq, 0, &fill(&r, &members)));
            }
        }
    });
    out
}

/// A device's state changed (`fib_netdev_event`, `addrconf_notify`): up,
/// its kernel routes made; down or gone, every route through it goes
/// (IPv4 without a word, but for its local routes while it is only down;
/// IPv6 each announced).
pub fn device_changed(index: u32) {
    let dev = netdev::by_index(index);
    with(|rib| {
        let running = dev.as_ref().is_some_and(|d| d.running());
        if !running {
            let gone = dev.is_none();
            rib.v4.retain(|r| r.oif != index || (!gone && r.scope == SCOPE_HOST));
            let (keep, drop): (Vec<Route>, Vec<Route>) = std::mem::take(&mut rib.v6).into_iter().partition(|r| r.oif != index);
            rib.v6 = keep;
            for r in drop {
                notify(RTM_DELROUTE, 0, 0, 0, &Route { group: 0, ..r }, &[]);
            }
        }
        if let Some(d) = dev {
            rib.device_routes(&d, true);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_dumps_in_the_radix_trees_order() {
        let p = |s: &[u8], len: u8| {
            let mut a = [0u8; 16];
            a[..s.len()].copy_from_slice(s);
            (a, len)
        };
        let mut v = vec![p(&[0xff], 8), p(&[0xfe, 0x80], 64), p(&[0x20, 0x01, 0x0d, 0xb8], 32), p(&[0x20, 0x01, 0x0d, 0xb8, 0, 1], 48), p(&[], 0), { let mut a = [0u8; 16]; a[15] = 1; (a, 128) }];
        v.sort_by(|a, b| radix(&a.0, a.1, &b.0, b.1));
        let lens: Vec<u8> = v.iter().map(|x| x.1).collect();
        assert_eq!(lens, [128, 48, 32, 64, 8, 0]);
    }

    #[test]
    fn metrics_are_checked_and_clamped() {
        let mut m = Vec::new();
        attr(&mut m, RTAX_MTU as u16, &70000u32.to_le_bytes());
        assert_eq!(parse_metrics(&m).unwrap()[RTAX_MTU], 65520);
        let mut bad = Vec::new();
        attr(&mut bad, 18, &1u32.to_le_bytes());
        assert_eq!(parse_metrics(&bad), Err(Errno::EINVAL));
        let mut short = Vec::new();
        attr(&mut short, RTAX_MTU as u16, &[1, 0]);
        assert_eq!(parse_metrics(&short), Err(Errno::EINVAL));
    }
}
