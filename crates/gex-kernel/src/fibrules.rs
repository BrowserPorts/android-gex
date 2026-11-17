//! Policy routing rules (`ip rule`: `net/core/fib_rules.c`,
//! `net/ipv4/fib_rules.c`, `net/ipv6/fib6_rules.c` at android17-6.18), as
//! `NETLINK_ROUTE`'s `RTM_NEWRULE`, `RTM_DELRULE` and `RTM_GETRULE` keep
//! them: what Android's netd makes at its start (`RouteController::Init`:
//! every rule but those at priority 0 flushed, then its own) and fails
//! without.
//!
//! The rules are kept, in each family's list as the kernel orders them,
//! and dumped as `fib_nl_fill_rule` fills them; they are not applied: this
//! kernel's internet sockets are the host's, and nothing here routes.

use crate::errno::Errno;
use std::sync::Mutex;

pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Attributes (`FRA_*`).
const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FLOW: u16 = 11;
const FRA_TUN_ID: u16 = 12;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_L3MDEV: u16 = 19;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;
const FRA_IP_PROTO: u16 = 22;
const FRA_SPORT_RANGE: u16 = 23;
const FRA_DPORT_RANGE: u16 = 24;

// Actions (`FR_ACT_*`).
const FR_ACT_TO_TBL: u8 = 1;
const FR_ACT_GOTO: u8 = 2;
const FR_ACT_MAX: u8 = 8;

// Flags (`FIB_RULE_*`).
const FIB_RULE_IIF_DETACHED: u32 = 0x8;
const FIB_RULE_OIF_DETACHED: u32 = 0x10;
const FIB_RULE_UNRESOLVED: u32 = 0x4;

const RT_TABLE_COMPAT: u32 = 252;
const RT_TABLE_DEFAULT: u32 = 253;
const RT_TABLE_MAIN: u32 = 254;
const RT_TABLE_LOCAL: u32 = 255;
const RTPROT_KERNEL: u8 = 2;
const IFNAMSIZ: usize = 16;

/// One rule (`struct fib_rule` with its family's part).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Rule {
    pref: u32,
    table: u32,
    action: u8,
    flags: u32,
    proto: u8,
    iifname: String,
    oifname: String,
    mark: u32,
    mark_mask: u32,
    target: u32,
    tun_id: u64,
    suppress_prefixlen: i32,
    suppress_ifgroup: i32,
    l3mdev: u8,
    /// `None`: unset (`fib_kuid_range_unset`).
    uid_range: Option<(u32, u32)>,
    ip_proto: u8,
    sport: Option<(u16, u16)>,
    dport: Option<(u16, u16)>,
    // The family's: prefixes, TOS, IPv4's realm.
    dst_len: u8,
    src_len: u8,
    tos: u8,
    dst: Vec<u8>,
    src: Vec<u8>,
    flow: u32,
}

struct Rules {
    v4: Vec<Rule>,
    v6: Vec<Rule>,
    /// IPv4's tables there are (`fib_get_table`): main and local, and any
    /// made empty for a rule that named none (`fib_empty_table`).
    v4_tables: Vec<u32>,
}

static RULES: Mutex<Option<Rules>> = Mutex::new(None);

/// A family's rules as the kernel starts them (`fib4_rules_init`,
/// `fib6_rules_net_init`: `fib_default_rule_add`).
fn defaults(family: u8) -> Vec<Rule> {
    let rule = |pref, table| Rule { pref, table, action: FR_ACT_TO_TBL, proto: RTPROT_KERNEL, suppress_prefixlen: -1, suppress_ifgroup: -1, ..Default::default() };
    match family {
        AF_INET => vec![rule(0, RT_TABLE_LOCAL), rule(0x7ffe, RT_TABLE_MAIN), rule(0x7fff, RT_TABLE_DEFAULT)],
        _ => vec![rule(0, RT_TABLE_LOCAL), rule(0x7ffe, RT_TABLE_MAIN)],
    }
}

fn with_rules<R>(family: u8, f: impl FnOnce(&mut Vec<Rule>) -> R) -> R {
    let mut g = RULES.lock().unwrap_or_else(|e| e.into_inner());
    let r = g.get_or_insert_with(|| Rules { v4: defaults(AF_INET), v6: defaults(AF_INET6), v4_tables: vec![RT_TABLE_MAIN, RT_TABLE_LOCAL] });
    f(if family == AF_INET { &mut r.v4 } else { &mut r.v6 })
}

/// IPv4's next empty table (`fib_empty_table`: the lowest id with none),
/// made.
fn empty_table() -> Result<u32, Errno> {
    let mut g = RULES.lock().unwrap_or_else(|e| e.into_inner());
    let r = g.get_or_insert_with(|| Rules { v4: defaults(AF_INET), v6: defaults(AF_INET6), v4_tables: vec![RT_TABLE_MAIN, RT_TABLE_LOCAL] });
    let id = (1..=u32::MAX).find(|id| !r.v4_tables.contains(id)).ok_or(Errno::ENOBUFS)?;
    r.v4_tables.push(id);
    Ok(id)
}

/// Attributes by type (the last of each, as `nla_parse` keeps it).
fn attrs(b: &[u8]) -> Result<[Option<&[u8]>; 32], Errno> {
    let mut tb: [Option<&[u8]>; 32] = [None; 32];
    let mut at = 0;
    while at + 4 <= b.len() {
        let len = u16::from_le_bytes([b[at], b[at + 1]]) as usize;
        let kind = u16::from_le_bytes([b[at + 2], b[at + 3]]) & 0x3fff;
        if len < 4 || at + len > b.len() {
            break;
        }
        if (kind as usize) < tb.len() {
            tb[kind as usize] = Some(&b[at + 4..at + len]);
        }
        at += (len + 3) & !3;
    }
    Ok(tb)
}

fn u32_of(a: &[u8]) -> Result<u32, Errno> {
    a.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or(Errno::EINVAL)
}

fn name_of(a: &[u8]) -> String {
    let n = a.iter().position(|&c| c == 0).unwrap_or(a.len()).min(IFNAMSIZ - 1);
    String::from_utf8_lossy(&a[..n]).into_owned()
}

/// `fib_nl2rule` with the family's `configure`: a rule from a request's
/// `fib_rule_hdr` and attributes, and whether it named its priority.
fn from_request(family: u8, hdr: &[u8], tb: &[Option<&[u8]>; 32], ifindex: &dyn Fn(&str) -> Option<u32>) -> Result<(Rule, bool), Errno> {
    let addr_len = if family == AF_INET { 4 } else { 16 };
    let (dst_len, src_len, tos, table8, action, flags) = (hdr[1], hdr[2], hdr[3], hdr[4], hdr[7], u32::from_le_bytes(hdr[8..12].try_into().unwrap()));
    if action > FR_ACT_MAX {
        return Err(Errno::EINVAL);
    }
    let max_len = (addr_len * 8) as u8;
    if dst_len > max_len || src_len > max_len {
        return Err(Errno::EINVAL);
    }
    let mut r = Rule { action, flags: flags & !(FIB_RULE_IIF_DETACHED | FIB_RULE_OIF_DETACHED | FIB_RULE_UNRESOLVED), dst_len, src_len, tos, ..Default::default() };
    // A prefix's address where its length is given (`fib4_rule_configure`).
    if src_len > 0 {
        let a = tb[FRA_SRC as usize].filter(|a| a.len() >= addr_len).ok_or(Errno::EINVAL)?;
        r.src = a[..addr_len].to_vec();
    }
    if dst_len > 0 {
        let a = tb[FRA_DST as usize].filter(|a| a.len() >= addr_len).ok_or(Errno::EINVAL)?;
        r.dst = a[..addr_len].to_vec();
    }
    let user_priority = tb[FRA_PRIORITY as usize].is_some();
    r.pref = match tb[FRA_PRIORITY as usize] {
        Some(a) => u32_of(a)?,
        None => 0,
    };
    r.proto = tb[FRA_PROTOCOL as usize].and_then(|a| a.first().copied()).unwrap_or(0);
    if let Some(a) = tb[FRA_IIFNAME as usize] {
        r.iifname = name_of(a);
        if ifindex(&r.iifname).is_none() {
            r.flags |= FIB_RULE_IIF_DETACHED;
        }
    }
    if let Some(a) = tb[FRA_OIFNAME as usize] {
        r.oifname = name_of(a);
        if ifindex(&r.oifname).is_none() {
            r.flags |= FIB_RULE_OIF_DETACHED;
        }
    }
    if let Some(a) = tb[FRA_FWMARK as usize] {
        r.mark = u32_of(a)?;
        // Compatibility: a non-zero mark compares every bit.
        if r.mark != 0 {
            r.mark_mask = u32::MAX;
        }
    }
    if let Some(a) = tb[FRA_FWMASK as usize] {
        r.mark_mask = u32_of(a)?;
    }
    if let Some(a) = tb[FRA_TUN_ID as usize] {
        r.tun_id = a.get(..8).map(|b| u64::from_be_bytes(b.try_into().unwrap())).ok_or(Errno::EINVAL)?;
    }
    if let Some(a) = tb[FRA_L3MDEV as usize] {
        r.l3mdev = *a.first().ok_or(Errno::EINVAL)?;
        if r.l3mdev != 1 {
            return Err(Errno::EINVAL);
        }
    }
    r.table = match tb[FRA_TABLE as usize] {
        Some(a) => u32_of(a)?,
        None => table8 as u32,
    };
    r.suppress_prefixlen = match tb[FRA_SUPPRESS_PREFIXLEN as usize] {
        Some(a) => u32_of(a)? as i32,
        None => -1,
    };
    r.suppress_ifgroup = match tb[FRA_SUPPRESS_IFGROUP as usize] {
        Some(a) => u32_of(a)? as i32,
        None => -1,
    };
    match tb[FRA_GOTO as usize] {
        Some(a) => {
            if action != FR_ACT_GOTO {
                return Err(Errno::EINVAL);
            }
            r.target = u32_of(a)?;
            // Backward jumps are refused (no loops).
            if r.target <= r.pref {
                return Err(Errno::EINVAL);
            }
        }
        None if action == FR_ACT_GOTO => return Err(Errno::EINVAL),
        None => {}
    }
    if r.l3mdev != 0 && r.table != 0 {
        return Err(Errno::EINVAL);
    }
    if let Some(a) = tb[FRA_UID_RANGE as usize] {
        let (s, e) = (u32_of(a)?, u32_of(a.get(4..).ok_or(Errno::EINVAL)?)?);
        // Unset (-1 both) or backwards is no range.
        if s == u32::MAX || e == u32::MAX || s > e {
            return Err(Errno::EINVAL);
        }
        r.uid_range = Some((s, e));
    }
    if let Some(a) = tb[FRA_IP_PROTO as usize] {
        r.ip_proto = *a.first().ok_or(Errno::EINVAL)?;
    }
    let range = |a: &[u8]| -> Result<(u16, u16), Errno> {
        let (s, e) = (a.get(..2).ok_or(Errno::EINVAL)?, a.get(2..4).ok_or(Errno::EINVAL)?);
        let (s, e) = (u16::from_le_bytes([s[0], s[1]]), u16::from_le_bytes([e[0], e[1]]));
        // `fib_rule_port_range_valid`.
        if s == 0 || e == 0 || s > e {
            return Err(Errno::EINVAL);
        }
        Ok((s, e))
    };
    if let Some(a) = tb[FRA_SPORT_RANGE as usize] {
        r.sport = Some(range(a)?);
    }
    if let Some(a) = tb[FRA_DPORT_RANGE as usize] {
        r.dport = Some(range(a)?);
    }
    if family == AF_INET {
        if let Some(a) = tb[FRA_FLOW as usize] {
            r.flow = u32_of(a)?;
        }
    }
    Ok((r, user_priority))
}

/// `rule_find`: the first rule matching what a delete names.
fn finds(r: &Rule, want: &Rule, user_priority: bool) -> bool {
    !((want.action != 0 && r.action != want.action)
        || (want.table != 0 && r.table != want.table)
        || (user_priority && r.pref != want.pref)
        || (!want.iifname.is_empty() && r.iifname != want.iifname)
        || (!want.oifname.is_empty() && r.oifname != want.oifname)
        || (want.mark != 0 && r.mark != want.mark)
        || (want.suppress_ifgroup != -1 && r.suppress_ifgroup != want.suppress_ifgroup)
        || (want.suppress_prefixlen != -1 && r.suppress_prefixlen != want.suppress_prefixlen)
        || (want.mark_mask != 0 && r.mark_mask != want.mark_mask)
        || (want.tun_id != 0 && r.tun_id != want.tun_id)
        || (want.l3mdev != 0 && r.l3mdev != want.l3mdev)
        || (want.uid_range.is_some() && r.uid_range != want.uid_range)
        || (want.ip_proto != 0 && r.ip_proto != want.ip_proto)
        || (want.sport.is_some() && r.sport != want.sport)
        || (want.dport.is_some() && r.dport != want.dport)
        // The family's `compare`.
        || (want.src_len != 0 && (r.src_len != want.src_len || r.src != want.src))
        || (want.dst_len != 0 && (r.dst_len != want.dst_len || r.dst != want.dst))
        || (want.tos != 0 && r.tos != want.tos)
        || (want.flow != 0 && r.flow != want.flow))
}

/// `fib_default_rule_pref`: one below the second rule's, where the first
/// is not the only one and the second's is not 0.
fn default_pref(rules: &[Rule]) -> u32 {
    match rules.get(1) {
        Some(r) if r.pref != 0 => r.pref - 1,
        _ => 0,
    }
}

/// A new rule (`fib_nl_newrule`).
pub fn add(family: u8, excl: bool, body: &[u8], ifindex: &dyn Fn(&str) -> Option<u32>) -> Result<(), Errno> {
    if family != AF_INET && family != AF_INET6 {
        return Err(Errno::EAFNOSUPPORT);
    }
    if body.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let tb = attrs(&body[12..])?;
    let (mut rule, user_priority) = from_request(family, &body[..12], &tb, ifindex)?;
    // The family's `configure`, which only a new rule passes through.
    if family == AF_INET && rule.tos & !0x1e != 0 {
        return Err(Errno::EINVAL);
    }
    if rule.action == FR_ACT_TO_TBL && rule.table == 0 && rule.l3mdev == 0 {
        // IPv6 wants a table named; IPv4 makes an empty one.
        if family != AF_INET {
            return Err(Errno::EINVAL);
        }
        rule.table = empty_table()?;
    }
    with_rules(family, |rules| {
        if !user_priority {
            rule.pref = default_pref(rules);
        }
        // `rule_exists`: the very same rule.
        if excl && rules.iter().any(|r| *r == rule) {
            return Err(Errno::EEXIST);
        }
        let at = rules.iter().position(|r| r.pref > rule.pref).unwrap_or(rules.len());
        rules.insert(at, rule);
        Ok(())
    })
}

/// A rule taken away (`fib_nl_delrule`).
pub fn delete(family: u8, body: &[u8], ifindex: &dyn Fn(&str) -> Option<u32>) -> Result<(), Errno> {
    if family != AF_INET && family != AF_INET6 {
        return Err(Errno::EAFNOSUPPORT);
    }
    if body.len() < 12 {
        return Err(Errno::EINVAL);
    }
    let tb = attrs(&body[12..])?;
    let (want, user_priority) = from_request(family, &body[..12], &tb, ifindex)?;
    with_rules(family, |rules| {
        let i = rules.iter().position(|r| finds(r, &want, user_priority)).ok_or(Errno::ENOENT)?;
        rules.remove(i);
        Ok(())
    })
}

/// The bodies (`fib_rule_hdr` and attributes) of a dump of `family`'s rules
/// (`AF_UNSPEC`: both), as `fib_nl_fill_rule` fills them.
pub fn dump(family: u8, ifindex: &dyn Fn(&str) -> Option<u32>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for f in [AF_INET, AF_INET6] {
        if family != 0 && family != f {
            continue;
        }
        with_rules(f, |rules| {
            for r in rules.iter() {
                // A goto whose target no rule has is unresolved.
                let resolved = r.action != FR_ACT_GOTO || rules.iter().any(|t| t.pref == r.target);
                out.push(fill(f, r, resolved, ifindex));
            }
        });
    }
    out
}

fn put(b: &mut Vec<u8>, kind: u16, data: &[u8]) {
    b.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    b.extend_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(data);
    while b.len() % 4 != 0 {
        b.push(0);
    }
}

fn fill(family: u8, r: &Rule, resolved: bool, ifindex: &dyn Fn(&str) -> Option<u32>) -> Vec<u8> {
    let mut flags = r.flags;
    if !resolved {
        flags |= FIB_RULE_UNRESOLVED;
    }
    if !r.iifname.is_empty() && ifindex(&r.iifname).is_none() {
        flags |= FIB_RULE_IIF_DETACHED;
    }
    if !r.oifname.is_empty() && ifindex(&r.oifname).is_none() {
        flags |= FIB_RULE_OIF_DETACHED;
    }
    let table8 = if r.table < 256 { r.table as u8 } else { RT_TABLE_COMPAT as u8 };
    let mut b = vec![family, r.dst_len, r.src_len, r.tos, table8, 0, 0, r.action];
    b.extend_from_slice(&flags.to_le_bytes());
    put(&mut b, FRA_TABLE, &r.table.to_le_bytes());
    put(&mut b, FRA_SUPPRESS_PREFIXLEN, &(r.suppress_prefixlen as u32).to_le_bytes());
    put(&mut b, FRA_PROTOCOL, &[r.proto]);
    let cstr = |s: &str| {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    };
    if !r.iifname.is_empty() {
        put(&mut b, FRA_IIFNAME, &cstr(&r.iifname));
    }
    if !r.oifname.is_empty() {
        put(&mut b, FRA_OIFNAME, &cstr(&r.oifname));
    }
    if r.pref != 0 {
        put(&mut b, FRA_PRIORITY, &r.pref.to_le_bytes());
    }
    if r.mark != 0 {
        put(&mut b, FRA_FWMARK, &r.mark.to_le_bytes());
    }
    if r.mark_mask != 0 || r.mark != 0 {
        put(&mut b, FRA_FWMASK, &r.mark_mask.to_le_bytes());
    }
    if r.target != 0 {
        put(&mut b, FRA_GOTO, &r.target.to_le_bytes());
    }
    if r.tun_id != 0 {
        put(&mut b, FRA_TUN_ID, &r.tun_id.to_be_bytes());
    }
    if r.suppress_ifgroup != -1 {
        put(&mut b, FRA_SUPPRESS_IFGROUP, &(r.suppress_ifgroup as u32).to_le_bytes());
    }
    if r.l3mdev != 0 {
        put(&mut b, FRA_L3MDEV, &[r.l3mdev]);
    }
    if let Some((s, e)) = r.uid_range {
        let mut v = s.to_le_bytes().to_vec();
        v.extend_from_slice(&e.to_le_bytes());
        put(&mut b, FRA_UID_RANGE, &v);
    }
    for (kind, range) in [(FRA_SPORT_RANGE, r.sport), (FRA_DPORT_RANGE, r.dport)] {
        if let Some((s, e)) = range {
            let mut v = s.to_le_bytes().to_vec();
            v.extend_from_slice(&e.to_le_bytes());
            put(&mut b, kind, &v);
        }
    }
    if r.ip_proto != 0 {
        put(&mut b, FRA_IP_PROTO, &[r.ip_proto]);
    }
    // The family's `fill`.
    if r.dst_len != 0 {
        put(&mut b, FRA_DST, &r.dst);
    }
    if r.src_len != 0 {
        put(&mut b, FRA_SRC, &r.src);
    }
    if family == AF_INET && r.flow != 0 {
        put(&mut b, FRA_FLOW, &r.flow.to_le_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule as netd's `modifyIpRule` asks: priority, table, mark and
    /// mask; added after the rules of its priority, found again by what it
    /// named, and refused twice with NLM_F_EXCL.
    #[test]
    fn rules_are_kept_in_the_kernels_order() {
        let none = |_: &str| None;
        let mut body = vec![AF_INET6, 0, 0, 0, 0, 0, 0, FR_ACT_TO_TBL, 0, 0, 0, 0];
        put(&mut body, FRA_PRIORITY, &11000u32.to_le_bytes());
        put(&mut body, FRA_TABLE, &97u32.to_le_bytes());
        put(&mut body, FRA_FWMARK, &0x10063u32.to_le_bytes());
        put(&mut body, FRA_FWMASK, &0x1ffffu32.to_le_bytes());
        add(AF_INET6, true, &body, &none).unwrap();
        assert_eq!(add(AF_INET6, true, &body, &none), Err(Errno::EEXIST));
        let rules = dump(AF_INET6, &none);
        let prefs: Vec<u32> = with_rules(AF_INET6, |r| r.iter().map(|r| r.pref).collect());
        assert_eq!(prefs, vec![0, 11000, 0x7ffe]);
        assert_eq!(rules.len(), 3);
        delete(AF_INET6, &body, &none).unwrap();
        assert_eq!(delete(AF_INET6, &body, &none), Err(Errno::ENOENT));
    }
}
